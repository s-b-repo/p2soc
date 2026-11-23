//! The operator's one-time PIN: generation and the `pin.hash` verifier.
//!
//! `pin.hash` is `"<salt_hex>$<sha256(salt | pin) hex>"`. It lets setup check a
//! typed PIN without running the KDF. The format is fixed by boxes in the
//! field; it is a fast hash, so it protects the PIN no better than the 0700
//! directory it lives in — the seal's strength is `host.key`, not the PIN.

use crate::error::Result;
use crate::rng;
use ctutils::CtEq;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// NIST SP 800-63B memorized-authenticator floor. Enforced when a PIN is
/// CHOSEN, never when a legacy seal migrates: earlier releases allowed 4-digit
/// PINs and such a box must not be locked out.
pub const MIN_PIN_LEN: usize = 6;

/// Digits in a generated PIN unless the caller asks for more.
pub const DEFAULT_PIN_DIGITS: usize = 8;

/// A fresh, uniformly random numeric PIN, never shorter than [`MIN_PIN_LEN`].
pub fn gen_pin(digits: usize) -> Result<Zeroizing<String>> {
    let want = digits.max(MIN_PIN_LEN);
    let mut pin = Zeroizing::new(String::with_capacity(want));
    let mut pool = Zeroizing::new([0u8; 32]);
    while pin.len() < want {
        rng::fill(pool.as_mut())?;
        // Rejection sampling: 250 is the largest multiple of 10 below 256, so
        // every digit is equally likely (no modulo bias).
        for &b in pool.iter().filter(|&&b| b < 250) {
            if pin.len() < want {
                pin.push(char::from(b'0' + b % 10));
            }
        }
    }
    Ok(pin)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}"); // audit-allow: fmt::Write into a String is infallible
        s
    })
}

/// Decode hex the way Python's `bytes.fromhex` does: either case, ASCII
/// whitespace ignored.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks_exact(2)
        .map(|pair| {
            let &[hi, lo] = pair else { return None };
            let hi = char::from(hi).to_digit(16)?;
            let lo = char::from(lo).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

fn digest_hex(salt: &[u8], pin: &[u8]) -> Zeroizing<String> {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    Zeroizing::new(hex(&h.finalize()))
}

/// The contents of `pin.hash` for `pin` under a fresh `salt`.
pub(crate) fn hash_line(salt: &[u8; 16], pin: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut line = Zeroizing::new(Vec::with_capacity(32 + 1 + 64));
    line.extend_from_slice(hex(salt).as_bytes());
    line.push(b'$');
    line.extend_from_slice(digest_hex(salt, pin).as_bytes());
    line
}

/// True if `pin` matches the contents of a `pin.hash` file. The digest
/// comparison is constant-time; anything malformed is simply "no".
pub(crate) fn matches_hash_line(line: &[u8], pin: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(line) else { return false };
    let Some((salt_hex, want)) = text.split_once('$') else { return false };
    let Some(salt) = unhex(salt_hex) else { return false };
    let got = digest_hex(&salt, pin);
    // Lengths are public (a SHA-256 hex digest is always 64 characters).
    got.len() == want.len() && bool::from(got.as_bytes().ct_eq(want.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pins_are_numeric_and_floored() {
        let p = gen_pin(DEFAULT_PIN_DIGITS).unwrap();
        assert_eq!(p.len(), 8);
        assert!(p.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(gen_pin(6).unwrap().len(), 6);
        assert_eq!(gen_pin(2).unwrap().len(), MIN_PIN_LEN);
        assert_eq!(gen_pin(40).unwrap().len(), 40);
        assert_ne!(*gen_pin(16).unwrap(), *gen_pin(16).unwrap());
    }

    #[test]
    fn every_digit_appears() {
        let p = gen_pin(2000).unwrap();
        for d in b'0'..=b'9' {
            assert!(p.bytes().any(|b| b == d), "digit {} never generated", char::from(d));
        }
    }

    #[test]
    fn hash_line_matches_the_python_format() {
        // hashlib.sha256(bytes(range(16)) + b"12345678").hexdigest()
        let salt: [u8; 16] = core::array::from_fn(|i| i as u8);
        let line = hash_line(&salt, b"12345678");
        assert_eq!(
            std::str::from_utf8(&line).unwrap(),
            "000102030405060708090a0b0c0d0e0f$227f81661c2958a647fd2d50b4c59c00e38d65cacef6354368c0e826a80e7d63"
        );
    }

    #[test]
    fn verifies_only_the_right_pin() {
        let line = hash_line(&[3u8; 16], b"204617");
        assert!(matches_hash_line(&line, b"204617"));
        assert!(!matches_hash_line(&line, b"204618"));
        assert!(!matches_hash_line(&line, b""));
    }

    #[test]
    fn malformed_hash_files_never_match() {
        for bad in [&b""[..], b"nodollar", b"zz$00", b"0$00", b"\xff\xfe$00", b"00$"] {
            assert!(!matches_hash_line(bad, b"12345678"), "{bad:?}");
        }
        // A truncated digest must not match on a prefix.
        let line = hash_line(&[3u8; 16], b"204617");
        assert!(!matches_hash_line(&line[..line.len() - 1], b"204617"));
    }
}
