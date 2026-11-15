//! PIN hash files (`config.pin`, `panellock.pin`).
//!
//! Two line formats are understood:
//!
//! * legacy — `<salt_hex>$<sha256_hex(salt || pin)>`, what every existing wall
//!   has on disk. One SHA-256 over a short numeric PIN is fast to brute-force
//!   for anyone who can read the file, so it is only ever *read*;
//! * `v2$pbkdf2-sha256$<iterations>$<salt_hex>$<key_hex>` — what a newly set
//!   PIN is stored as. The version tag leaves room for a later scheme.
//!
//! A PIN has little entropy, so no hash makes a stolen file safe; the stretch
//! only raises the cost per guess. The file's real protection is its 0600 mode
//! inside the 0700 state directory.

use crate::error::{Result, StateError};
use crate::fsio;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// PBKDF2 rounds for a newly set PIN: about a quarter of a second on a Pi 4,
/// which is also paid by every unlock attempt on the GTK thread.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 210_000;
/// Bounds on the iteration count a file may ask for. The upper one stops a
/// planted file from freezing the wall for minutes per attempt.
pub const MIN_PBKDF2_ITERATIONS: u32 = 1_000;
pub const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
/// Longest PIN/code that is hashed at all.
pub const MAX_CODE_LEN: usize = 128;

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const MAX_PIN_FILE_BYTES: u64 = 1024;
const V2_PREFIX: &str = "v2$";
const V2_KDF: &str = "pbkdf2-sha256";

/// How a stored PIN is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinFormat {
    /// One salted SHA-256 (written by the Python wall). Worth re-setting.
    LegacySha256,
    Pbkdf2Sha256 {
        iterations: u32,
    },
}

/// Compare two byte strings without an early exit, so the time taken does not
/// depend on where they first differ. Lengths are not secret here (both sides
/// are fixed-width digests or codes).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn legacy_digest_hex(salt: &[u8], pin: &str) -> Zeroizing<String> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(pin.as_bytes());
    Zeroizing::new(hex_encode(&hasher.finalize()))
}

fn pbkdf2_key(salt: &[u8], pin: &str, iterations: u32) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<Sha256>(pin.as_bytes(), salt, iterations, key.as_mut());
    key
}

/// A legacy line for `pin` — the exact construction the Python wall used.
pub fn legacy_line(salt: &[u8], pin: &str) -> String {
    format!("{}${}", hex_encode(salt), *legacy_digest_hex(salt, pin))
}

fn v2_line(salt: &[u8], pin: &str, iterations: u32) -> String {
    format!("{V2_PREFIX}{V2_KDF}${iterations}${}${}", hex_encode(salt), hex_encode(&*pbkdf2_key(salt, pin, iterations)))
}

struct V2<'a> {
    iterations: u32,
    salt: Vec<u8>,
    key: &'a str,
}

fn parse_v2(rest: &str) -> Option<V2<'_>> {
    let mut fields = rest.split('$');
    let (Some(V2_KDF), Some(iterations), Some(salt), Some(key), None) =
        (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    let iterations = iterations.parse::<u32>().ok()?;
    if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
        return None;
    }
    Some(V2 { iterations, salt: hex_decode(salt)?, key })
}

/// The format of a stored line, if it is one this crate can verify.
pub fn line_format(line: &str) -> Option<PinFormat> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix(V2_PREFIX) {
        return parse_v2(rest).map(|v| PinFormat::Pbkdf2Sha256 { iterations: v.iterations });
    }
    let (salt, digest) = line.split_once('$')?;
    (hex_decode(salt).is_some() && digest.len() == 2 * KEY_LEN).then_some(PinFormat::LegacySha256)
}

/// Verify `pin` against a stored line, in constant time. Anything malformed
/// fails closed.
pub fn verify_line(line: &str, pin: &str) -> bool {
    if pin.is_empty() || pin.len() > MAX_CODE_LEN {
        return false;
    }
    let line = line.trim();
    if let Some(rest) = line.strip_prefix(V2_PREFIX) {
        let Some(v2) = parse_v2(rest) else {
            return false;
        };
        let key = pbkdf2_key(&v2.salt, pin, v2.iterations);
        return ct_eq(hex_encode(&*key).as_bytes(), v2.key.as_bytes());
    }
    let Some((salt, digest)) = line.split_once('$') else {
        return false;
    };
    // An empty salt is refused: it would verify a bare, unsalted digest.
    let Some(salt) = hex_decode(salt) else {
        return false;
    };
    ct_eq(legacy_digest_hex(&salt, pin).as_bytes(), digest.as_bytes())
}

/// Why a PIN cannot be stored, if it cannot.
fn check_new_pin(pin: &str) -> Result<()> {
    if pin.is_empty() {
        return Err(StateError::InvalidPin("it is empty"));
    }
    if pin.len() > MAX_CODE_LEN {
        return Err(StateError::InvalidPin("it is too long"));
    }
    // The gates trim what is typed, so padding could never be entered again.
    if pin.trim() != pin || pin.chars().any(char::is_control) {
        return Err(StateError::InvalidPin("it contains whitespace padding or control characters"));
    }
    Ok(())
}

/// One PIN hash file.
#[derive(Debug, Clone)]
pub struct PinFile {
    path: PathBuf,
    iterations: u32,
}

impl PinFile {
    pub fn new(path: impl Into<PathBuf>) -> PinFile {
        PinFile { path: path.into(), iterations: DEFAULT_PBKDF2_ITERATIONS }
    }

    /// Override the stretch for newly set PINs (clamped to the accepted
    /// range). Exists so tests do not pay the production cost.
    pub fn with_iterations(mut self, iterations: u32) -> PinFile {
        self.iterations = iterations.clamp(MIN_PBKDF2_ITERATIONS, MAX_PBKDF2_ITERATIONS);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a PIN is enrolled. A file that exists but cannot be read or
    /// parsed still counts: the gate then stays shut instead of opening.
    pub fn is_set(&self) -> bool {
        fsio::exists(&self.path)
    }

    fn read_line(&self) -> Option<Zeroizing<String>> {
        let bytes = fsio::read_capped(&self.path, MAX_PIN_FILE_BYTES).ok()??;
        std::str::from_utf8(&bytes).ok().map(|s| Zeroizing::new(s.to_string()))
    }

    /// How the enrolled PIN is hashed (`None`: not set, or unreadable).
    pub fn format(&self) -> Option<PinFormat> {
        line_format(&self.read_line()?)
    }

    /// Store a salted, stretched hash of `pin`. The PIN itself is never
    /// written. Unlike the Python `set_pin`, an empty PIN is an error rather
    /// than a silent [`clear`](Self::clear).
    pub fn set(&self, pin: &str) -> Result<()> {
        check_new_pin(pin)?;
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| StateError::Random)?; // audit-allow: getrandom errno is not actionable; StateError::Random is the typed form
        fsio::write_atomic(&self.path, v2_line(&salt, pin, self.iterations).as_bytes())
    }

    pub fn clear(&self) -> Result<()> {
        fsio::remove(&self.path)
    }

    /// Whether `pin` is the enrolled PIN. No PIN, an unreadable file or a
    /// malformed one all answer `false`.
    pub fn verify(&self, pin: &str) -> bool {
        self.read_line().is_some_and(|line| verify_line(&line, pin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    fn file(dir: &TempDir) -> PinFile {
        PinFile::new(dir.path().join("config.pin")).with_iterations(MIN_PBKDF2_ITERATIONS)
    }

    #[test]
    fn roundtrip_stores_only_a_stretched_digest() {
        let dir = TempDir::new();
        let pin = file(&dir);
        assert!(!pin.is_set());
        assert!(!pin.verify("4242"));
        pin.set("4242").unwrap();
        assert!(pin.is_set());
        assert!(pin.verify("4242"));
        assert!(!pin.verify("0000"));
        assert!(!pin.verify(""));
        let raw = std::fs::read_to_string(pin.path()).unwrap();
        assert!(raw.starts_with("v2$pbkdf2-sha256$1000$") && !raw.contains("4242"));
        assert_eq!(std::fs::metadata(pin.path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(pin.format(), Some(PinFormat::Pbkdf2Sha256 { iterations: 1000 }));
        pin.clear().unwrap();
        assert!(!pin.is_set());
        pin.clear().unwrap();
    }

    #[test]
    fn two_sets_of_the_same_pin_use_different_salts() {
        let dir = TempDir::new();
        let pin = file(&dir);
        pin.set("864213").unwrap();
        let first = std::fs::read_to_string(pin.path()).unwrap();
        pin.set("864213").unwrap();
        assert_ne!(first, std::fs::read_to_string(pin.path()).unwrap());
    }

    #[test]
    fn legacy_lines_still_verify() {
        // sha256(bytes.fromhex("00ff") + b"2468").hexdigest()
        let line = legacy_line(&[0x00, 0xff], "2468");
        assert_eq!(line_format(&line), Some(PinFormat::LegacySha256));
        assert!(verify_line(&line, "2468"));
        assert!(verify_line(&format!("  {line}\n"), "2468"));
        assert!(!verify_line(&line, "2469"));
        assert_eq!(line, "00ff$9de2ca431dac465afa39447a11634439bdbd19ed6fe691320c3420860f032c9f");
        // The digest is compared as the lowercase hex the writer produced.
        assert!(!verify_line(&line.to_uppercase(), "2468"));
    }

    #[test]
    fn malformed_lines_fail_closed() {
        let unsalted = legacy_line(&[], "1234");
        for bad in
            ["", "$", "00$é", "zz$00", unsalted.as_str(), "v2$", "v2$pbkdf2-sha256$1000$00$", "v2$scrypt$1000$00$00"]
        {
            assert!(!verify_line(bad, "1234"), "{bad:?}");
        }
        // An iteration count outside the accepted range is not even attempted.
        let salt = [7u8; 16];
        let huge = format!("v2$pbkdf2-sha256$4000000000${}${}", hex_encode(&salt), "00".repeat(32));
        assert!(!verify_line(&huge, "1234"));
        assert_eq!(line_format(&huge), None);
        assert!(!verify_line(&v2_line(&salt, "1234", 1), "1234"));
    }

    #[test]
    fn a_corrupt_file_is_enrolled_but_never_verifies() {
        let dir = TempDir::new();
        let pin = file(&dir);
        std::fs::write(pin.path(), "00$\u{e9}").unwrap();
        assert!(pin.is_set());
        assert!(!pin.verify("1234"));
        assert_eq!(pin.format(), None);
    }

    #[test]
    fn unusable_pins_are_refused() {
        let dir = TempDir::new();
        let pin = file(&dir);
        for bad in ["", " 1234", "1234 ", "12\n34", &"9".repeat(MAX_CODE_LEN + 1)] {
            assert!(matches!(pin.set(bad), Err(StateError::InvalidPin(_))), "{bad:?}");
        }
        assert!(!pin.is_set());
        assert!(!verify_line(&legacy_line(&[1], &"9".repeat(MAX_CODE_LEN + 1)), &"9".repeat(MAX_CODE_LEN + 1)));
    }

    #[test]
    fn pbkdf2_matches_the_reference_vector() {
        // hashlib.pbkdf2_hmac("sha256", b"864213", bytes(range(16)), 1000).hex()
        let salt: Vec<u8> = (0u8..16).collect();
        let line = v2_line(&salt, "864213", 1000);
        assert!(verify_line(&line, "864213"));
        assert_eq!(
            line,
            "v2$pbkdf2-sha256$1000$000102030405060708090a0b0c0d0e0f$\
             468f265306ba6f9344111de44f1e2c741e665288007796405569881975b58917"
        );
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }
}
