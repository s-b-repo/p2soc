//! RFC 6238 TOTP for the settings gate and the kiosk lock: 6 digits, SHA-1,
//! 30-second steps, accepted one step either side of now — exactly what the
//! Python wall accepted, and what every authenticator app produces.
//!
//! Verification reports *which* time-step matched so the caller can refuse a
//! code that was already used (see [`crate::authstate::AuthState`]): on a
//! video wall a code is typed in plain sight, and without that it would stay
//! valid for up to 90 seconds.

use crate::error::{Result, StateError};
use crate::fsio;
use crate::pin::ct_eq;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1; // audit-allow: SHA-1 required by RFC 6238
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Time-step length in seconds.
pub const STEP_SECS: u64 = 30;
/// Code length.
pub const DIGITS: usize = 6;
/// Steps accepted either side of the current one (clock skew, slow typing).
pub const WINDOW: i64 = 1;
/// The account label shown in the authenticator app.
pub const DEFAULT_LABEL: &str = "kiosk@soc.local";
/// Issuer for the settings-gate secret.
pub const ISSUER_SETTINGS: &str = "SOC Wall — Settings";
/// Issuer for the kiosk-lock secret.
pub const ISSUER_PANEL_LOCK: &str = "SOC Wall — Panel lock";

const SECRET_BYTES: usize = 20;
/// Shortest secret accepted for enrolment (80 bits, the common app minimum).
const MIN_SECRET_BYTES: usize = 10;
const MAX_TOTP_FILE_BYTES: u64 = 1024;
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Tolerant base32 decode: mixed case, embedded whitespace and missing
/// padding are all fine (operators paste these from phones). `None` for
/// anything that is not base32.
pub(crate) fn decode_secret(secret: &str) -> Option<Zeroizing<Vec<u8>>> {
    let compact: Zeroizing<String> =
        Zeroizing::new(secret.chars().filter(|c| !c.is_whitespace()).map(|c| c.to_ascii_uppercase()).collect());
    let body = compact.trim_end_matches('=');
    if body.is_empty() || matches!(body.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() * 5 / 8));
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in body.bytes() {
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// The base32 digit for the low five bits of `value`.
fn b32_char(value: u32) -> char {
    let index = usize::try_from(value & 31).unwrap_or(0); // audit-allow: infallible, value & 31 always fits usize
    char::from(B32.get(index).copied().unwrap_or(b'A')) // audit-allow: infallible, B32 has 32 entries and index < 32
}

fn encode_secret(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(b32_char(acc >> bits));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(b32_char(acc << (5 - bits)));
    }
    out
}

/// RFC 4226 HOTP with dynamic truncation, as a zero-padded decimal string.
fn hotp(key: &[u8], counter: u64) -> Option<Zeroizing<String>> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let bin = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
    Some(Zeroizing::new(format!("{:0width$}", bin % 1_000_000, width = DIGITS)))
}

/// The code an authenticator shows for `secret_b32` at `unix_time`.
pub fn code_at(secret_b32: &str, unix_time: u64) -> Option<Zeroizing<String>> {
    hotp(&decode_secret(secret_b32)?, unix_time / STEP_SECS)
}

/// Verify `code`, returning the time-step it belongs to.
///
/// Every step in the window is computed and compared in constant time, so
/// neither a wrong digit's position nor which step matched shows in the
/// timing. A short all-digit code is left-padded with zeros, as the Python
/// verifier did. A secret that is not base32 never verifies.
pub fn verify_step(secret_b32: &str, code: &str, unix_time: u64) -> Option<u64> {
    if code.is_empty() || code.len() > DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let key = decode_secret(secret_b32)?;
    let padded = Zeroizing::new(format!("{code:0>width$}", width = DIGITS));
    let now_step = unix_time / STEP_SECS;
    let mut matched = None;
    for offset in -WINDOW..=WINDOW {
        let Some(step) = now_step.checked_add_signed(offset) else {
            continue;
        };
        let candidate = hotp(&key, step)?;
        if ct_eq(candidate.as_bytes(), padded.as_bytes()) {
            matched = Some(step);
        }
    }
    matched
}

/// A fresh 160-bit secret, base32 without padding — the standard
/// authenticator seed.
pub fn generate_secret() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
    getrandom::fill(bytes.as_mut()).map_err(|_| StateError::Random)?; // audit-allow: getrandom errno is not actionable; StateError::Random is the typed form
    Ok(encode_secret(bytes.as_ref()))
}

fn percent_encode(text: &str, keep: &[u8], space_as_plus: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || keep.contains(&b) {
            out.push(char::from(b));
        } else if b == b' ' && space_as_plus {
            out.push('+');
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The `otpauth://totp/...` URI an authenticator app enrols from (as a QR code
/// or pasted). `:` and `@` stay literal in the label so it reads
/// `Issuer:account@host`, the shape the apps expect.
pub fn provision_uri(secret_b32: &str, label: &str, issuer: &str) -> String {
    let secret = secret_b32.replace(' ', "").to_ascii_uppercase();
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        percent_encode(&format!("{issuer}:{label}"), b":/@", false),
        percent_encode(secret.trim_end_matches('='), b"", true),
        percent_encode(issuer, b"", true),
    )
}

/// One enrolled-secret file (`config.totp`, `panellock.totp`): the base32
/// secret on a single line, mode 0600.
#[derive(Debug, Clone)]
pub struct TotpFile {
    path: PathBuf,
}

impl TotpFile {
    pub fn new(path: impl Into<PathBuf>) -> TotpFile {
        TotpFile { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a secret is enrolled (an unreadable file still counts, so the
    /// gate stays shut).
    pub fn is_set(&self) -> bool {
        fsio::exists(&self.path)
    }

    /// The stored secret, or `None` when absent, empty or unreadable.
    pub fn load(&self) -> Option<Zeroizing<String>> {
        let bytes = fsio::read_capped(&self.path, MAX_TOTP_FILE_BYTES).ok()??;
        let text = std::str::from_utf8(&bytes).ok()?.trim();
        (!text.is_empty()).then(|| Zeroizing::new(text.to_string()))
    }

    /// Store `secret_b32`. A secret that would never verify is refused here
    /// rather than discovered at the lock screen.
    pub fn save(&self, secret_b32: &str) -> Result<()> {
        let secret = secret_b32.trim();
        match decode_secret(secret) {
            None => return Err(StateError::InvalidSecret("it is not base32")),
            Some(key) if key.len() < MIN_SECRET_BYTES => return Err(StateError::InvalidSecret("it is too short")),
            Some(_) => {}
        }
        let line = Zeroizing::new(format!("{secret}\n"));
        fsio::write_atomic(&self.path, line.as_bytes())
    }

    pub fn clear(&self) -> Result<()> {
        fsio::remove(&self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// The RFC 6238 appendix B key (`12345678901234567890`), base32.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_sha1_vectors() {
        // Appendix B lists 8-digit codes; ours are their last six digits.
        for (time, code) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code_at(RFC_SECRET, time).unwrap().as_str(), code, "t={time}");
        }
    }

    #[test]
    fn window_is_one_step_either_side() {
        let now = 1_700_000_015;
        let step = now / STEP_SECS;
        for (offset, ok) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let at = now.checked_add_signed(offset * 30).unwrap();
            let code = code_at(RFC_SECRET, at).unwrap();
            let want = ok.then(|| step.checked_add_signed(offset).unwrap());
            assert_eq!(verify_step(RFC_SECRET, &code, now), want, "offset {offset}");
        }
    }

    #[test]
    fn code_shape_is_enforced() {
        let now = 1_234_567_890;
        assert_eq!(code_at(RFC_SECRET, now).unwrap().as_str(), "005924");
        assert!(verify_step(RFC_SECRET, "005924", now).is_some());
        assert!(verify_step(RFC_SECRET, "5924", now).is_some(), "short codes are zero-padded");
        for bad in ["", "0059240", "00592a", " 05924", "٠٠٥٩٢٤"] {
            assert!(verify_step(RFC_SECRET, bad, now).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn secrets_decode_tolerantly_and_fail_closed() {
        let spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(&**decode_secret(spaced).unwrap(), b"12345678901234567890");
        assert_eq!(&**decode_secret("MFRGG===").unwrap(), b"abc");
        assert_eq!(&**decode_secret("MFRGG").unwrap(), b"abc");
        for bad in ["", "   ", "not base32 !!", "M", "MFR", "MFRGGZ", "MF=RGG", "MFRGG1"] {
            assert!(decode_secret(bad).is_none(), "{bad:?}");
            assert!(verify_step(bad, "123456", 0).is_none());
        }
    }

    #[test]
    fn generated_secrets_round_trip() {
        let a = generate_secret().unwrap();
        let b = generate_secret().unwrap();
        assert_ne!(*a, *b);
        assert_eq!(a.len(), 32);
        assert_eq!(decode_secret(&a).unwrap().len(), SECRET_BYTES);
        assert_eq!(*encode_secret(b"abc"), "MFRGG");
        assert_eq!(*encode_secret(b"12345678901234567890"), RFC_SECRET);
        let now = 1_700_000_000;
        assert!(verify_step(&a, &code_at(&a, now).unwrap(), now).is_some());
    }

    #[test]
    fn file_store_is_owner_only_and_validates() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let file = TotpFile::new(dir.path().join("panellock.totp"));
        assert!(!file.is_set() && file.load().is_none());
        file.save(&format!("  {RFC_SECRET}  ")).unwrap();
        assert!(file.is_set());
        assert_eq!(file.load().unwrap().as_str(), RFC_SECRET);
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), format!("{RFC_SECRET}\n"));
        assert_eq!(std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(matches!(file.save("not base32 !!"), Err(StateError::InvalidSecret(_))));
        assert!(matches!(file.save("MFRGG"), Err(StateError::InvalidSecret(_))));
        assert_eq!(file.load().unwrap().as_str(), RFC_SECRET, "a refused save leaves the old secret");
        file.clear().unwrap();
        assert!(!file.is_set());
    }

    #[test]
    fn provisioning_uri_shape() {
        let uri = provision_uri("jbsw y3dp ehpk 3pxp==", DEFAULT_LABEL, "SOC Wall");
        assert_eq!(
            uri,
            "otpauth://totp/SOC%20Wall:kiosk@soc.local?secret=JBSWY3DPEHPK3PXP&issuer=SOC+Wall&algorithm=SHA1&\
             digits=6&period=30"
        );
    }
}
