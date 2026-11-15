//! Encoding / crypto helpers (port of `crypto.py`).
//!
//! * [`urlencode_body`] is byte-exact with the iNode `URLEncoder::Encode`
//!   (classic form-urlencoded: `[A-Za-z0-9]` verbatim, space -> `+`, everything
//!   else -> `%XX`), prefixed `request=`.
//! * [`hotp`] is RFC 4226 HOTP/HMAC-SHA1 over an 8-byte big-endian counter, used
//!   by the SPA knock.
//! * RSA password mode ([`rsa_encrypt_password_b64`]) is a firmware variant
//!   (`H3C_USER_RSAKEY`): `base64(RSA_PKCS1v15_encrypt(pubkey, password))`. It is
//!   used only when the operator supplies the gateway's RSA public key; the
//!   standard V7 path sends the password cleartext inside TLS.

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha1::Sha1; // audit-allow: SHA-1 is mandated by RFC 4226 HOTP, the SPA wire format
use zeroize::Zeroizing;

use crate::error::{InodeError, Result};

/// `request=` + `URLEncoder::Encode(xml)`. Only ASCII letters/digits are kept
/// verbatim; a space becomes `+` (not `%20`); every other byte, including
/// `-._~<>/@%` and any non-ASCII UTF-8 byte, becomes `%XX` (uppercase hex).
pub fn urlencode_body(xml: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(crate::constants::V7_FORM_KEY.len() + xml.len() * 3));
    out.push_str(crate::constants::V7_FORM_KEY);
    for byte in xml.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(byte as char),
            b' ' => out.push('+'),
            other => {
                out.push('%');
                out.push(hex_upper(other >> 4));
                out.push(hex_upper(other & 0x0F));
            }
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// Best-effort `<private>` base64 telemetry blob. Empty by default (the gateway
/// accepts it); a minimal, clearly-delimited blob is emitted only when `host`
/// or `extra` is supplied.
pub fn make_private_blob(host: &str, os_name: &str, extra: &[u8]) -> String {
    if host.is_empty() && extra.is_empty() {
        return String::new();
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(host.as_bytes());
    payload.push(0);
    payload.extend_from_slice(os_name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(extra);
    base64::engine::general_purpose::STANDARD.encode(payload)
}

// --------------------------------------------------------------------------
// SPA HOTP (RFC 4226)
// --------------------------------------------------------------------------
/// RFC 4226 Appendix A doubling table.
const DOUBLE: [u32; 10] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];

/// RFC 4226 `calcChecksum` (Luhn mod-10 over the low `digits` digits).
fn luhn_checksum(mut num: u64, digits: u32) -> u32 {
    let mut total: u32 = 0;
    let mut dbl = true;
    for _ in 0..digits {
        let d = (num % 10) as usize;
        num /= 10;
        let mut v = d as u32;
        if dbl {
            v = DOUBLE.get(d).copied().unwrap_or(0);
        }
        total += v;
        dbl = !dbl;
    }
    let result = total % 10;
    if result > 0 { 10 - result } else { 0 }
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> Result<[u8; 20]> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|e| InodeError::Config(format!("HMAC key could not be initialised: {e}")))?;
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 20];
    for (dst, src) in buf.iter_mut().zip(out.iter()) {
        *dst = *src;
    }
    Ok(buf)
}

fn pow10(digits: u32) -> u64 {
    10u64.checked_pow(digits).unwrap_or(1_000_000_000)
}

/// RFC 4226 HOTP/HMAC-SHA1. `counter` is the random `pktID` (sent in clear);
/// `key` is the per-client SDP key. With `add_checksum` a Luhn digit is appended
/// (a `digits+1` string) — how the SPA knock fills its 6-byte field with
/// `digits=5`.
pub fn hotp(key: &[u8], counter: u64, digits: u32, add_checksum: bool) -> Result<String> {
    let mac = hmac_sha1(key, &counter.to_be_bytes())?;
    let at = |i: usize| mac.get(i).copied().unwrap_or(0);
    let off = (at(19) & 0x0F) as usize;
    let binc = ((u64::from(at(off) & 0x7F)) << 24)
        | (u64::from(at(off + 1)) << 16)
        | (u64::from(at(off + 2)) << 8)
        | u64::from(at(off + 3));
    let mut otp = binc % pow10(digits);
    if add_checksum {
        otp = otp * 10 + u64::from(luhn_checksum(otp, digits));
        Ok(zfill(otp, (digits + 1) as usize))
    } else {
        Ok(zfill(otp, digits as usize))
    }
}

/// The SPA password field is `nbytes` wide (6). The recovered call is
/// `digits=5, addChecksum=1` -> a 6-char string filling it exactly; shorter
/// strings pad with NUL (`sprintf` semantics).
pub fn hotp_bytes(key: &[u8], counter: u64, nbytes: usize, digits: u32, add_checksum: bool) -> Result<Vec<u8>> {
    let s = hotp(key, counter, digits, add_checksum)?;
    let mut buf = vec![0u8; nbytes];
    for (dst, src) in buf.iter_mut().zip(s.bytes()) {
        *dst = src;
    }
    Ok(buf)
}

fn zfill(value: u64, width: usize) -> String {
    let s = value.to_string();
    if s.len() >= width {
        s
    } else {
        let mut out = String::with_capacity(width);
        for _ in 0..(width - s.len()) {
            out.push('0');
        }
        out.push_str(&s);
        out
    }
}

/// `base64(RSA_PKCS1v15_encrypt(pubkey, password))` — the `H3C_USER_RSAKEY`
/// firmware variant. The public key may be PEM or DER, in either SubjectPublicKeyInfo
/// (`BEGIN PUBLIC KEY`) or PKCS#1 (`BEGIN RSA PUBLIC KEY`) form, matching the
/// vendored client's `load_pem_public_key` / `load_der_public_key` fallback.
///
/// Only public-key encryption is performed here; no private-key operation (and
/// thus no exposure to the RSA decryption timing sidechannel) ever runs.
pub fn rsa_encrypt_password_b64(pubkey_pem_or_der: &[u8], password: &str) -> Result<String> {
    let key = parse_rsa_public_key(pubkey_pem_or_der)?;
    let mut rng = rand_core::OsRng;
    let ciphertext = key
        .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|e| InodeError::Config(format!("RSA password encryption failed: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
}

/// Parse an RSA public key, trying the four realistic encodings in the same
/// order the vendored Python does (PEM first, then DER; SPKI before PKCS#1).
/// Each attempt's parse error is deliberately discarded in favour of the next
/// encoding; a single descriptive error is returned only once all four fail.
fn parse_rsa_public_key(data: &[u8]) -> Result<RsaPublicKey> {
    let from_pem = std::str::from_utf8(data).ok().filter(|text| text.contains("-----BEGIN")).and_then(|text| {
        RsaPublicKey::from_public_key_pem(text).ok().or_else(|| RsaPublicKey::from_pkcs1_pem(text).ok())
    });
    from_pem
        .or_else(|| RsaPublicKey::from_public_key_der(data).ok())
        .or_else(|| RsaPublicKey::from_pkcs1_der(data).ok())
        .ok_or_else(|| {
            InodeError::Config("could not parse the RSA public key (tried SPKI and PKCS#1, PEM and DER)".into())
        })
}
