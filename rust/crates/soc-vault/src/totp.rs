//! TOTP (RFC 6238 over RFC 4226 HOTP).
//!
//! Two front ends share one core:
//! * [`generate`] understands what a Bitwarden login's `totp` field may hold —
//!   a bare Base32 secret, an `otpauth://` URI, or a Steam secret — and is what
//!   panel auto-login uses.
//! * [`totp`] / [`verify`] / [`provision_uri`] / [`generate_secret`] serve the
//!   kiosk lock, where the wall itself is the verifier.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1; // audit-allow: SHA-1 required by RFC 6238 / Bitwarden protocol
use sha2::{Sha256, Sha512};
use soc_core::CredSource;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use crate::error::VaultError;
use crate::fsutil::write_private_atomic;
use crate::session::Session;
use crate::vault::Vault;

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The folder that groups the wall's own TOTP secrets in the vault.
pub const VAULT_TOTP_FOLDER: &str = "SOC Wall Auth";

/// The HMAC hash behind a code. SHA-1 is the RFC default and what every
/// authenticator app actually uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// Parse `sha1` / `sha256` / `sha512`, any case.
    pub fn parse(name: &str) -> Option<Algorithm> {
        match name.to_ascii_uppercase().as_str() {
            "SHA1" => Some(Algorithm::Sha1),
            "SHA256" => Some(Algorithm::Sha256),
            "SHA512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    fn hmac(self, key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
        fn run<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
            let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length"); // audit-allow: infallible, HMAC accepts any key length
            mac.update(msg);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        match self {
            Algorithm::Sha1 => run::<Hmac<Sha1>>(key, msg),
            Algorithm::Sha256 => run::<Hmac<Sha256>>(key, msg),
            Algorithm::Sha512 => run::<Hmac<Sha512>>(key, msg),
        }
    }
}

fn bad(msg: impl Into<String>) -> VaultError {
    VaultError::Totp(msg.into())
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Tolerant RFC 4648 Base32 decode: operators paste these from phones and QR
/// codes, so case, whitespace and missing padding are all accepted. The error
/// never echoes the input — it is a secret.
fn b32_decode(secret: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let cleaned: Zeroizing<Vec<u8>> = Zeroizing::new(
        secret.bytes().filter(|b| !b.is_ascii_whitespace()).map(|b| b.to_ascii_uppercase()).collect::<Vec<u8>>(),
    );
    let body_len = cleaned.iter().rposition(|&b| b != b'=').map_or(0, |i| i + 1);
    let body = &cleaned[..body_len]; // audit-allow: bounds-checked above (rposition index + 1 <= len)
    if body.is_empty() || matches!(body.len() % 8, 1 | 3 | 6) {
        return Err(bad("TOTP secret is not valid Base32"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() * 5 / 8));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &ch in body {
        let value = B32_ALPHABET.iter().position(|&a| a == ch).ok_or_else(|| bad("TOTP secret is not valid Base32"))?;
        let Ok(value) = u32::try_from(value) else { return Err(bad("TOTP secret is not valid Base32")) };
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let Ok(byte) = u8::try_from(acc >> bits) else { return Err(bad("TOTP secret is not valid Base32")) };
            out.push(byte);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn b32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((acc >> bits) & 31) as usize] as char); // audit-allow: lossless, masked to 5 bits so the index is < 32
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((acc << (5 - bits)) & 31) as usize] as char); // audit-allow: lossless, masked to 5 bits so the index is < 32
    }
    out
}

/// RFC 4226 dynamic truncation of HMAC(key, counter).
fn hotp(key: &[u8], counter: u64, algorithm: Algorithm) -> u32 {
    let digest = algorithm.hmac(key, &counter.to_be_bytes());
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    u32::from_be_bytes([digest[offset], digest[offset + 1], digest[offset + 2], digest[offset + 3]]) & 0x7fff_ffff
}

fn decimal(binary: u32, digits: u32) -> String {
    format!("{:0width$}", u64::from(binary) % 10u64.pow(digits), width = usize::try_from(digits).unwrap_or(10))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() && hex(bytes[i + 1]).is_some() && hex(bytes[i + 2]).is_some() => {
                out.push(
                    u8::try_from(hex(bytes[i + 1]).unwrap_or(0) * 16 + hex(bytes[i + 2]).unwrap_or(0)).unwrap_or(b'%'),
                );
                i += 2;
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// First non-blank value of `key` in a query string.
fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (percent_decode(k) == key && !v.is_empty()).then(|| percent_decode(v))
    })
}

struct Spec {
    secret: Zeroizing<String>,
    digits: u32,
    period: u64,
    algorithm: Algorithm,
    steam: bool,
}

/// Parse a login's `totp` field. `digits` and `period` come from a vault item
/// that a compromised server or a shared item can set, so both are
/// range-checked before any arithmetic touches them.
fn parse_spec(value: &str) -> Result<Spec, VaultError> {
    let raw = value.trim();
    if raw.is_empty() {
        return Err(bad("empty TOTP secret"));
    }
    let mut spec = Spec {
        secret: Zeroizing::new(raw.to_string()),
        digits: 6,
        period: 30,
        algorithm: Algorithm::Sha1,
        steam: false,
    };
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("steam://") {
        spec.steam = true;
        spec.secret = Zeroizing::new(raw["steam://".len()..].to_string());
    } else if lower.starts_with("otpauth://") {
        let after = &raw["otpauth://".len()..];
        let after = after.split('#').next().unwrap_or("");
        let (authority_and_path, query) = after.split_once('?').unwrap_or((after, ""));
        let authority = authority_and_path.split('/').next().unwrap_or("");
        spec.steam = authority.eq_ignore_ascii_case("steam");
        spec.secret = Zeroizing::new(query_value(query, "secret").ok_or_else(|| bad("otpauth URI has no secret"))?);
        if let Some(d) = query_value(query, "digits") {
            let d: i64 = d.trim().parse().map_err(|_| bad("TOTP digits is not an integer"))?; // audit-allow: parse error is deliberately not echoed (value may be part of a secret URI)
            spec.digits = u32::try_from(d)
                .ok()
                .filter(|d| (1..=10).contains(d))
                .ok_or_else(|| bad("TOTP digits out of range"))?;
        }
        if let Some(p) = query_value(query, "period") {
            let p: i64 = p.trim().parse().map_err(|_| bad("TOTP period is not an integer"))?; // audit-allow: parse error is deliberately not echoed (value may be part of a secret URI)
            spec.period = u64::try_from(p).ok().filter(|&p| p >= 1).ok_or_else(|| bad("TOTP period out of range"))?;
        }
        if let Some(a) = query_value(query, "algorithm") {
            if a.eq_ignore_ascii_case("steam") {
                spec.steam = true;
            } else if let Some(algorithm) = Algorithm::parse(&a) {
                spec.algorithm = algorithm;
            }
        }
    }
    Ok(spec)
}

/// The code for a Bitwarden login `totp` value at `unix_time`.
///
/// Accepts a bare Base32 secret, an `otpauth://` URI, or a Steam secret
/// (`steam://` prefix, `otpauth://steam/...`, or `algorithm=steam`). Defaults:
/// 6 digits, 30 s period, SHA-1.
pub fn generate(totp_value: &str, unix_time: u64) -> Result<String, VaultError> {
    let spec = parse_spec(totp_value)?;
    let key = b32_decode(&spec.secret)?;
    let mut binary = hotp(&key, unix_time / spec.period, spec.algorithm);
    if spec.steam {
        let Ok(base) = u32::try_from(STEAM_ALPHABET.len()) else { return Err(bad("Steam alphabet too long")) };
        return (0..5)
            .map(|_| {
                let ch = usize::try_from(binary % base)
                    .ok()
                    .and_then(|i| STEAM_ALPHABET.get(i))
                    .map(|&b| char::from(b))
                    .ok_or_else(|| bad("Steam alphabet index out of range"))?;
                binary /= base;
                Ok(ch)
            })
            .collect();
    }
    Ok(decimal(binary, spec.digits))
}

/// [`generate`] at the current time.
pub fn generate_now(totp_value: &str) -> Result<String, VaultError> {
    generate(totp_value, unix_now())
}

/// RFC 6238 code for a Base32 secret. `step` is the time-step in seconds
/// (30 is the RFC default); `digits` must be 6..=10.
pub fn totp(
    secret_b32: &str,
    unix_time: u64,
    step: u64,
    digits: u32,
    algorithm: Algorithm,
) -> Result<String, VaultError> {
    if !(6..=10).contains(&digits) {
        return Err(bad("digits must be 6..10"));
    }
    if step == 0 {
        return Err(bad("TOTP period out of range"));
    }
    let key = b32_decode(secret_b32)?;
    Ok(decimal(hotp(&key, unix_time / step, algorithm), digits))
}

/// Verification parameters; the defaults are what authenticator apps assume.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Number of time-steps accepted either side of now (clock skew).
    pub window: u32,
    pub step: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions { window: 1, step: 30, digits: 6, algorithm: Algorithm::Sha1 }
    }
}

/// Verify `code` against `secret_b32`, returning the matched time-step.
///
/// The caller should remember the returned step and refuse a code whose step
/// is not greater than the last accepted one: RFC 6238 §5.2 requires a code to
/// be single-use, and without that a shoulder-surfed code stays valid for the
/// whole window.
///
/// Every candidate in the window is compared, in constant time, so neither the
/// position of a wrong digit nor which step matched shows up in the timing.
pub fn verify_step(secret_b32: &str, code: &str, unix_time: u64, opts: VerifyOptions) -> Option<u64> {
    let digits = usize::try_from(opts.digits).unwrap_or(usize::MAX);
    if code.is_empty() || code.len() > digits || !code.bytes().all(|b| b.is_ascii_digit()) || opts.step == 0 {
        return None;
    }
    let padded = format!("{code:0>digits$}");
    let now_step = unix_time / opts.step;
    let mut matched = None;
    for offset in -i64::from(opts.window)..=i64::from(opts.window) {
        let Some(step) = now_step.checked_add_signed(offset) else { continue };
        let Ok(candidate) = totp(secret_b32, step.saturating_mul(opts.step), opts.step, opts.digits, opts.algorithm)
        else {
            return None;
        };
        if bool::from(candidate.as_bytes().ct_eq(padded.as_bytes())) {
            matched = Some(step);
        }
    }
    matched
}

/// Verify a 6-digit SHA-1 code with ±`window` steps of 30 s.
pub fn verify(secret_b32: &str, code: &str, unix_time: u64, window: u32) -> bool {
    verify_step(secret_b32, code, unix_time, VerifyOptions { window, ..VerifyOptions::default() }).is_some()
}

fn percent_encode(text: &str, keep: &[u8], space_as_plus: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || keep.contains(&b) {
            out.push(b as char);
        } else if b == b' ' && space_as_plus {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// An `otpauth://totp/...` URI for a QR code — what a phone authenticator
/// scans to enrol the wall's secret. `:` and `@` stay unescaped in the label so
/// it reads `Issuer:user@host`, as authenticator apps expect.
pub fn provision_uri(
    secret_b32: &str,
    label: &str,
    issuer: &str,
    step: u64,
    digits: u32,
    algorithm: Algorithm,
) -> String {
    let secret = secret_b32.replace(' ', "").to_ascii_uppercase();
    let secret = secret.trim_end_matches('=');
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm={}&digits={digits}&period={step}",
        percent_encode(&format!("{issuer}:{label}"), b":/@", false),
        percent_encode(secret, b"", true),
        percent_encode(issuer, b"", true),
        algorithm.name(),
    )
}

/// A fresh random secret, unpadded Base32. 20 bytes is the standard
/// authenticator seed length; fewer than 16 (128 bits) is refused.
pub fn generate_secret(num_bytes: usize) -> Result<Zeroizing<String>, VaultError> {
    if num_bytes < 16 {
        return Err(bad("TOTP secret must be at least 16 bytes (128 bits)"));
    }
    let mut raw = Zeroizing::new(vec![0u8; num_bytes]);
    random_bytes(&mut raw)?;
    Ok(Zeroizing::new(b32_encode(&raw)))
}

/// Read a stored Base32 secret (one line); `None` when absent or empty.
pub fn load(path: &Path) -> Option<Zeroizing<String>> {
    let text = Zeroizing::new(std::fs::read_to_string(path).ok()?);
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| Zeroizing::new(trimmed.to_string()))
}

/// Store a secret at `path`, mode 0600, atomically.
pub fn save(path: &Path, secret_b32: &str) -> Result<(), VaultError> {
    let line = Zeroizing::new(format!("{}\n", secret_b32.trim()));
    write_private_atomic(path, line.as_bytes()).map_err(|e| VaultError::io("cannot store the TOTP secret", &e))
}

/// Remove a stored secret; a missing file is not an error.
pub fn clear(path: &Path) {
    let _ = std::fs::remove_file(path); // audit-allow: best-effort: a missing file is not an error
}

/// Which of the wall's own TOTP secrets is meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpKind {
    /// Gates the settings window.
    Settings,
    /// Gates input to the wall.
    PanelLock,
}

impl TotpKind {
    /// Parse `settings` / `panellock`.
    pub fn parse(kind: &str) -> Result<TotpKind, VaultError> {
        match kind {
            "settings" => Ok(TotpKind::Settings),
            "panellock" => Ok(TotpKind::PanelLock),
            other => Err(bad(format!("unknown TOTP kind: {other:?}; expected one of [settings, panellock]"))),
        }
    }

    /// The vault item (a secure note) that holds this secret.
    pub fn vault_item(self) -> &'static str {
        match self {
            TotpKind::Settings => "SOC Settings TOTP",
            TotpKind::PanelLock => "SOC Panel Lock TOTP",
        }
    }
}

/// Read the secret from the vault item's Notes. `None` on empty, missing or
/// any vault error, so the caller falls back to the local file — a lock prompt
/// must not fail just because Vaultwarden hiccuped.
pub fn load_vault(vault: Option<&dyn CredSource>, kind: TotpKind) -> Option<Zeroizing<String>> {
    let note = Zeroizing::new(vault?.notes(kind.vault_item()).ok()?);
    let trimmed = note.trim();
    (!trimmed.is_empty()).then(|| Zeroizing::new(trimmed.to_string()))
}

/// Store the secret as a secure note in the vault (created if absent), then
/// drop the cached copy so the next read sees the new value.
pub fn save_vault(
    session: &Session,
    vault: Option<&Vault>,
    kind: TotpKind,
    secret_b32: &str,
) -> Result<(), VaultError> {
    session.upsert_secure_note(kind.vault_item(), secret_b32.trim(), Some(VAULT_TOTP_FOLDER))?;
    if let Some(v) = vault {
        v.invalidate(Some(kind.vault_item()));
    }
    Ok(())
}

/// Delete the vault item. `Ok(true)` when something was deleted, `Ok(false)`
/// when it was already absent; transport and auth failures are errors.
pub fn clear_vault(session: &Session, vault: Option<&Vault>, kind: TotpKind) -> Result<bool, VaultError> {
    let deleted = session.delete(kind.vault_item())?;
    if let Some(v) = vault {
        v.invalidate(Some(kind.vault_item()));
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use soc_core::creds::StaticCreds;

    /// Base32 of ASCII "12345678901234567890" — the RFC 6238 SHA-1 seed.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    /// The RFC's 32- and 64-byte seeds for SHA-256 / SHA-512.
    const RFC_SECRET_256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
    const RFC_SECRET_512: &str =
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";

    /// RFC 6238 Appendix B: (time, SHA-1, SHA-256, SHA-512), 8 digits.
    const RFC_VECTORS: &[(u64, &str, &str, &str)] = &[
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn base32_matches_the_standard_vector() {
        assert_eq!(b32_encode(b"12345678901234567890"), RFC_SECRET);
        assert_eq!(b32_decode(RFC_SECRET).unwrap().as_slice(), b"12345678901234567890");
        assert_eq!(b32_decode(RFC_SECRET_256).unwrap().len(), 32);
        assert_eq!(b32_decode(RFC_SECRET_512).unwrap().len(), 64);
        for n in 1..40usize {
            let raw: Vec<u8> = (0..n as u8).collect();
            assert_eq!(b32_decode(&b32_encode(&raw)).unwrap().as_slice(), raw.as_slice());
        }
        for bad in ["", "   ", "A", "ABC", "ABCDEF", "GEZD1NBV", "GE=ZD", "ÄÖÜ"] {
            assert!(b32_decode(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rfc6238_appendix_b_all_three_hashes() {
        for &(t, sha1, sha256, sha512) in RFC_VECTORS {
            assert_eq!(totp(RFC_SECRET, t, 30, 8, Algorithm::Sha1).unwrap(), sha1);
            assert_eq!(totp(RFC_SECRET_256, t, 30, 8, Algorithm::Sha256).unwrap(), sha256);
            assert_eq!(totp(RFC_SECRET_512, t, 30, 8, Algorithm::Sha512).unwrap(), sha512);
            // The 6-digit code is the last six of the 8-digit one.
            assert_eq!(totp(RFC_SECRET, t, 30, 6, Algorithm::Sha1).unwrap(), sha1[2..]);
            // The Bitwarden front end agrees, via otpauth URIs.
            let uri = |secret: &str, alg: &str| format!("otpauth://totp/L?secret={secret}&digits=8&algorithm={alg}");
            assert_eq!(generate(&uri(RFC_SECRET, "SHA1"), t).unwrap(), sha1);
            assert_eq!(generate(&uri(RFC_SECRET_256, "sha256"), t).unwrap(), sha256);
            assert_eq!(generate(&uri(RFC_SECRET_512, "SHA512"), t).unwrap(), sha512);
        }
    }

    // The remaining expectations were produced by the Python litebw.generate_totp.
    #[test]
    fn bare_secret_defaults_and_normalisation() {
        assert_eq!(generate(RFC_SECRET, 59).unwrap(), "287082");
        let spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(generate(spaced, 59).unwrap(), "287082");
        assert_eq!(totp(spaced, 59, 30, 8, Algorithm::Sha1).unwrap(), "94287082");
        assert_eq!(generate(&format!("  {RFC_SECRET}\n"), 59).unwrap(), "287082");
    }

    #[test]
    fn otpauth_uri_parameters() {
        let uri = format!("otpauth://totp/L?secret={RFC_SECRET}&period=30");
        assert_eq!(generate(&uri, 59).unwrap(), "287082");
        let uri = format!("otpauth://totp/L?secret={RFC_SECRET}&period=60&digits=7");
        assert_eq!(generate(&uri, 1111111109).unwrap(), "9360094");
        // Percent-escapes and '+' in the query, an escaped label, extra parameters.
        let uri = "otpauth://totp/SOC%20Wall:a@b?issuer=x+y&secret=gezd%20gnbv+gy3tqojqgezdgnbvgy3tqojq";
        assert_eq!(generate(uri, 59).unwrap(), "287082");
        // An unknown algorithm falls back to SHA-1, as Bitwarden does.
        let uri = format!("otpauth://totp/L?secret={RFC_SECRET}&algorithm=MD5");
        assert_eq!(generate(&uri, 59).unwrap(), "287082");
        // A fragment is not part of the query.
        let uri = format!("OTPAUTH://totp/L?secret={RFC_SECRET}#digits=8");
        assert_eq!(generate(&uri, 59).unwrap(), "287082");
    }

    #[test]
    fn steam_codes() {
        assert_eq!(generate(&format!("steam://{RFC_SECRET}"), 59).unwrap(), "PV9M4");
        assert_eq!(generate(&format!("otpauth://steam/L?secret={RFC_SECRET}"), 59).unwrap(), "PV9M4");
        assert_eq!(generate(&format!("otpauth://totp/L?secret={RFC_SECRET}&algorithm=steam"), 59).unwrap(), "PV9M4");
        assert_eq!(generate(&format!("otpauth://steam/L?secret={RFC_SECRET}"), 1111111109).unwrap(), "PY4YB");
    }

    #[test]
    fn empty_and_secretless_inputs_are_errors() {
        assert!(matches!(generate("", 59), Err(VaultError::Totp(_))));
        assert!(matches!(generate("   ", 59), Err(VaultError::Totp(_))));
        assert!(matches!(generate("otpauth://totp/L?digits=6", 59), Err(VaultError::Totp(_))));
        assert!(matches!(generate("otpauth://totp/L?secret=", 59), Err(VaultError::Totp(_))));
        assert!(matches!(generate("not base32 !!!", 59), Err(VaultError::Totp(_))));
    }

    #[test]
    fn hostile_digits_and_period_are_rejected_before_any_arithmetic() {
        for tail in [
            "digits=100000000",
            "digits=0",
            "digits=-1",
            "digits=abc",
            "digits=11",
            "period=0",
            "period=-5",
            "period=xyz",
        ] {
            let uri = format!("otpauth://totp/L?secret={RFC_SECRET}&{tail}");
            assert!(matches!(generate(&uri, 59), Err(VaultError::Totp(_))), "accepted {tail}");
        }
        assert!(totp(RFC_SECRET, 59, 0, 6, Algorithm::Sha1).is_err());
        assert!(totp(RFC_SECRET, 59, 30, 5, Algorithm::Sha1).is_err());
        assert!(totp(RFC_SECRET, 59, 30, 11, Algorithm::Sha1).is_err());
        // Ten digits is the widest code a 31-bit truncation can fill.
        assert_eq!(totp(RFC_SECRET, 59, 30, 10, Algorithm::Sha1).unwrap().len(), 10);
    }

    #[test]
    fn errors_never_echo_the_secret() {
        let err = generate("SUPERSECRET-NOT-BASE32-!!", 59).unwrap_err().to_string();
        assert!(!err.contains("SUPERSECRET"));
    }

    #[test]
    fn verify_accepts_the_window_and_nothing_else() {
        let base = 1111111111;
        let code = totp(RFC_SECRET, base, 30, 6, Algorithm::Sha1).unwrap();
        assert!(verify(RFC_SECRET, &code, base, 0));
        assert!(verify(RFC_SECRET, &code, base + 25, 1));
        assert!(verify(RFC_SECRET, &code, base - 25, 1));
        assert!(!verify(RFC_SECRET, &code, base + 90, 1));
        assert!(!verify(RFC_SECRET, &code, base + 30, 0));
        // The matched step lets the caller enforce single use.
        let opts = VerifyOptions::default();
        assert_eq!(verify_step(RFC_SECRET, &code, base, opts), Some(base / 30));
        assert_eq!(verify_step(RFC_SECRET, &code, base + 30, opts), Some(base / 30));
        // Near the epoch the window must not underflow.
        let early = totp(RFC_SECRET, 5, 30, 6, Algorithm::Sha1).unwrap();
        assert_eq!(verify_step(RFC_SECRET, &early, 5, opts), Some(0));
    }

    #[test]
    fn verify_rejects_garbage_without_panicking() {
        for junk in ["abcdef", "", "000000", "1234567", "12 456", "１２３４５６", "²³¹²³¹", "-12345", "+12345"]
        {
            assert!(!verify(RFC_SECRET, junk, 1111111111, 1), "accepted {junk:?}");
        }
        assert!(!verify("not base32!", "123456", 1111111111, 1));
    }

    #[test]
    fn short_codes_are_zero_padded_like_a_keypad_would_drop_leading_zeros() {
        // 07081804 at t=1111111109 -> six digits "081804"; typed without the zero.
        assert_eq!(totp(RFC_SECRET, 1111111109, 30, 6, Algorithm::Sha1).unwrap(), "081804");
        assert!(verify(RFC_SECRET, "81804", 1111111109, 0));
    }

    #[test]
    fn provisioning_uri_matches_python() {
        assert_eq!(
            provision_uri("ABCDEFGHIJKLMNOP", "kiosk@soc.local", "SOC Wall", 30, 6, Algorithm::Sha1),
            "otpauth://totp/SOC%20Wall:kiosk@soc.local?secret=ABCDEFGHIJKLMNOP&issuer=SOC+Wall&algorithm=SHA1&digits=6&period=30"
        );
        assert_eq!(
            provision_uri("abcd efgh ijkl mnop==", "a b/c?d&é", "Ünï & Co", 60, 8, Algorithm::Sha256),
            "otpauth://totp/%C3%9Cn%C3%AF%20%26%20Co:a%20b/c%3Fd%26%C3%A9?secret=ABCDEFGHIJKLMNOP&issuer=%C3%9Cn%C3%AF+%26+Co&algorithm=SHA256&digits=8&period=60"
        );
    }

    #[test]
    fn generated_secrets_are_unique_valid_and_long_enough() {
        let a = generate_secret(20).unwrap();
        let b = generate_secret(20).unwrap();
        assert_ne!(a.as_str(), b.as_str());
        assert_eq!(a.len(), 32);
        assert_eq!(b32_decode(&a).unwrap().len(), 20);
        assert!(generate_secret(15).is_err());
        // A generated secret works end to end.
        let code = generate(&a, 1_700_000_000).unwrap();
        assert!(verify(&a, &code, 1_700_000_000, 0));
    }

    #[test]
    fn file_store_roundtrip_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = TestDir::new("totp");
        let p = d.path().join("config.totp");
        assert!(load(&p).is_none());
        save(&p, "  ABCDEFGHIJKLMNOP \n").unwrap();
        assert_eq!(load(&p).unwrap().as_str(), "ABCDEFGHIJKLMNOP");
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        // Overwriting a file that had drifted to a wider mode tightens it again.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        save(&p, "QRSTUVWXYZ234567").unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        clear(&p);
        assert!(load(&p).is_none());
        clear(&p);
    }

    #[test]
    fn vault_item_names() {
        assert_eq!(TotpKind::parse("settings").unwrap().vault_item(), "SOC Settings TOTP");
        assert_eq!(TotpKind::parse("panellock").unwrap().vault_item(), "SOC Panel Lock TOTP");
        assert!(TotpKind::parse("frobnitz").is_err());
    }

    #[test]
    fn load_vault_reads_trimmed_notes_and_degrades_to_none() {
        let mut creds = StaticCreds::default();
        creds.notes.insert("SOC Settings TOTP".into(), "JBSWY3DPEHPK3PXP".into());
        creds.notes.insert("SOC Panel Lock TOTP".into(), "  ABCD2345  \n".into());
        assert_eq!(load_vault(Some(&creds), TotpKind::Settings).unwrap().as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(load_vault(Some(&creds), TotpKind::PanelLock).unwrap().as_str(), "ABCD2345");
        assert!(load_vault(Some(&StaticCreds::default()), TotpKind::Settings).is_none());
        assert!(load_vault(None, TotpKind::Settings).is_none());

        struct Boom;
        impl CredSource for Boom {
            fn creds(&self, _: &str) -> Result<soc_core::Login, soc_core::CredError> {
                Err(soc_core::CredError::Other("x".into()))
            }
            fn notes(&self, _: &str) -> Result<String, soc_core::CredError> {
                Err(soc_core::CredError::Unavailable("vault hiccup".into()))
            }
            fn code(&self, _: &str) -> Result<String, soc_core::CredError> {
                Err(soc_core::CredError::Other("x".into()))
            }
        }
        assert!(load_vault(Some(&Boom), TotpKind::PanelLock).is_none());
    }
}
