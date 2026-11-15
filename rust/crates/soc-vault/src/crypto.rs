//! Bitwarden client-side cryptography: master-key derivation, the stretched
//! key that protects the account key, and type-2 EncStrings
//! (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC).
//!
//! Everything a server sends is treated as hostile until its MAC verifies:
//! unauthenticated EncString types are refused outright, and KDF parameters
//! (which arrive unauthenticated from `prelogin`) are range-checked in both
//! directions before any work is done.

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::VaultError;

type HmacSha256 = Hmac<Sha256>;

const BLOCK: usize = 16;
const KEY_LEN: usize = 32;
const MAC_LEN: usize = 32;

/// Fill `buf` from the OS CSPRNG.
pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf).map_err(|_| VaultError::Crypto("the OS random source is unavailable".into())) // audit-allow: getrandom error carries nothing actionable
}

/// Standard base64 with padding, as Bitwarden writes it.
pub(crate) fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>, VaultError> {
    B64.decode(text).map_err(|_| VaultError::Crypto("bad EncString base64".into())) // audit-allow: decode error is deliberately opaque: never reveal where a MAC-less EncString was malformed
}

/// The key-derivation function an account uses, as announced by `prelogin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2-HMAC-SHA256, salt = lower-cased email.
    Pbkdf2 { iterations: u32 },
    /// Argon2id v1.3, salt = SHA-256(lower-cased email); memory in MiB.
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

impl Kdf {
    /// The accepted ranges are Bitwarden's own. The lower bounds matter as
    /// much as the upper ones: `prelogin` is unauthenticated, so a
    /// man-in-the-middle that announces one PBKDF2 round would otherwise be
    /// handed a master-password hash it can brute-force offline.
    pub const PBKDF2_ITERATIONS: std::ops::RangeInclusive<u32> = 5_000..=2_000_000;
    pub const ARGON2_ITERATIONS: std::ops::RangeInclusive<u32> = 2..=10;
    pub const ARGON2_MEMORY_MIB: std::ops::RangeInclusive<u32> = 16..=1024;
    pub const ARGON2_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=16;

    /// Build from the raw `prelogin` numbers, refusing anything out of range
    /// instead of clamping it (a clamped value derives the wrong key and only
    /// surfaces later as a baffling "wrong password").
    pub fn from_prelogin(kind: u64, iterations: u64, memory_mib: u64, parallelism: u64) -> Result<Kdf, VaultError> {
        fn within(name: &str, value: u64, range: &std::ops::RangeInclusive<u32>) -> Result<u32, VaultError> {
            u32::try_from(value).ok().filter(|v| range.contains(v)).ok_or_else(|| {
                VaultError::Kdf(format!(
                    "the vault announced {name}={value}, outside the accepted range {}..={} — refusing to derive a key",
                    range.start(),
                    range.end()
                ))
            })
        }
        match kind {
            0 => Ok(Kdf::Pbkdf2 { iterations: within("kdfIterations", iterations, &Self::PBKDF2_ITERATIONS)? }),
            1 => Ok(Kdf::Argon2id {
                iterations: within("kdfIterations", iterations, &Self::ARGON2_ITERATIONS)?,
                memory_mib: within("kdfMemory", memory_mib, &Self::ARGON2_MEMORY_MIB)?,
                parallelism: within("kdfParallelism", parallelism, &Self::ARGON2_PARALLELISM)?,
            }),
            other => Err(VaultError::Kdf(format!("unsupported KDF type {other} (only PBKDF2 and Argon2id)"))),
        }
    }
}

/// The 32-byte master key. Never leaves this process; wiped on drop.
pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    /// Derive the master key from the password. The email is lower-cased and
    /// trimmed first, exactly as the official clients do.
    pub fn derive(password: &str, email: &str, kdf: Kdf) -> Result<MasterKey, VaultError> {
        let email = normalize_email(email);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        match kdf {
            Kdf::Pbkdf2 { iterations } => {
                pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), email.as_bytes(), iterations, key.as_mut_slice());
            }
            Kdf::Argon2id { iterations, memory_mib, parallelism } => {
                let salt = Sha256::digest(email.as_bytes());
                let params =
                    argon2::Params::new(memory_mib.saturating_mul(1024), iterations, parallelism, Some(KEY_LEN))
                        .map_err(|e| VaultError::Kdf(format!("invalid Argon2id parameters: {e}")))?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), &salt, key.as_mut_slice())
                    .map_err(|e| VaultError::Kdf(format!("Argon2id key derivation failed ({e}) — out of memory?")))?;
            }
        }
        Ok(MasterKey(key))
    }

    /// The authentication hash sent to `/identity/connect/token`:
    /// base64(PBKDF2-SHA256(master_key, password, 1 round)). Password-equivalent
    /// for login, so it is wiped on drop too.
    pub fn password_hash(&self, password: &str) -> Zeroizing<String> {
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha256>(self.0.as_slice(), password.as_bytes(), 1, out.as_mut_slice());
        Zeroizing::new(b64(out.as_slice()))
    }

    /// The stretched key (HKDF-Expand-SHA256 with info `enc` / `mac`) that
    /// wraps the account key. One HMAC block each, so no HKDF crate is needed.
    pub fn stretch(&self) -> SymKey {
        SymKey { enc: self.expand(b"enc"), mac: self.expand(b"mac") }
    }

    fn expand(&self, info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_slice()).expect("HMAC accepts any key length"); // audit-allow: infallible, HMAC accepts any key length
        mac.update(info);
        mac.update(&[1]);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        out.copy_from_slice(&mac.finalize().into_bytes());
        out
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Lower-case and trim an account email (it is the KDF salt and the login name).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// A 64-byte Bitwarden symmetric key: 32 bytes AES-256 + 32 bytes HMAC-SHA256.
#[derive(Clone)]
pub struct SymKey {
    enc: Zeroizing<[u8; KEY_LEN]>,
    mac: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymKey(<redacted>)")
    }
}

impl SymKey {
    /// Split a 64-byte `enc || mac` key.
    pub fn from_bytes(bytes: &[u8]) -> Result<SymKey, VaultError> {
        if bytes.len() != 2 * KEY_LEN {
            return Err(VaultError::Crypto("symmetric key is not 64 bytes".into()));
        }
        let mut enc = Zeroizing::new([0u8; KEY_LEN]);
        let mut mac = Zeroizing::new([0u8; KEY_LEN]);
        enc.copy_from_slice(&bytes[..KEY_LEN]); // audit-allow: bounds-checked above (len == 2 * KEY_LEN)
        mac.copy_from_slice(&bytes[KEY_LEN..]); // audit-allow: bounds-checked above (len == 2 * KEY_LEN)
        Ok(SymKey { enc, mac })
    }

    /// A fresh random key (a new account's key).
    pub fn random() -> Result<SymKey, VaultError> {
        let mut raw = Zeroizing::new([0u8; 2 * KEY_LEN]);
        random_bytes(raw.as_mut_slice())?;
        SymKey::from_bytes(raw.as_slice())
    }

    /// `enc || mac`, for wrapping under another key.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 2 * KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; 2 * KEY_LEN]);
        out[..KEY_LEN].copy_from_slice(self.enc.as_slice());
        out[KEY_LEN..].copy_from_slice(self.mac.as_slice());
        out
    }

    fn tag(&self, iv: &[u8], ciphertext: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(self.mac.as_slice()).expect("HMAC accepts any key length"); // audit-allow: infallible, HMAC accepts any key length
        mac.update(iv);
        mac.update(ciphertext);
        mac
    }

    /// Encrypt to a type-2 EncString under a fresh random IV.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, VaultError> {
        let mut iv = [0u8; BLOCK];
        random_bytes(&mut iv)?;
        Ok(self.encrypt_with_iv(plaintext, &iv))
    }

    /// Encrypt a string field.
    pub fn encrypt_str(&self, plaintext: &str) -> Result<String, VaultError> {
        self.encrypt(plaintext.as_bytes())
    }

    pub(crate) fn encrypt_with_iv(&self, plaintext: &[u8], iv: &[u8; BLOCK]) -> String {
        let mut buf = Zeroizing::new(vec![0u8; plaintext.len() + BLOCK - plaintext.len() % BLOCK]);
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ciphertext = cbc::Encryptor::<Aes256>::new_from_slices(self.enc.as_slice(), iv)
            .expect("32-byte key and 16-byte IV") // audit-allow: infallible, key is 32 bytes and IV 16 by construction
            .encrypt_padded::<Pkcs7>(buf.as_mut_slice(), plaintext.len())
            .expect("buffer holds the padded plaintext"); // audit-allow: infallible, buffer is sized to the padded plaintext
        let tag = self.tag(iv, ciphertext).finalize().into_bytes();
        format!("2.{}|{}|{}", b64(iv), b64(ciphertext), b64(&tag))
    }

    /// Decrypt a type-2 EncString. The MAC is verified first, in constant
    /// time, and nothing is decrypted unless it matches. Every other type —
    /// including the MAC-less type 0 and bare, prefix-less values — is
    /// refused: accepting them would let a hostile server inject or forge
    /// fields without knowing any key.
    pub fn decrypt(&self, enc_string: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let (kind, body) = enc_string
            .split_once('.')
            .ok_or_else(|| VaultError::Crypto("malformed EncString (no type prefix)".into()))?;
        match kind {
            "2" => {}
            "0" => return Err(VaultError::Crypto("refusing an EncString without a MAC (type 0)".into())),
            _ => return Err(VaultError::Crypto("unsupported EncString type (only type 2 is accepted)".into())),
        }
        let mut parts = body.split('|');
        let (Some(iv), Some(ciphertext), Some(tag), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(VaultError::Crypto("malformed EncString".into()));
        };
        let (iv, ciphertext, tag) = (unb64(iv)?, unb64(ciphertext)?, unb64(tag)?);
        if iv.len() != BLOCK || tag.len() != MAC_LEN || ciphertext.is_empty() || ciphertext.len() % BLOCK != 0 {
            return Err(VaultError::Crypto("malformed EncString".into()));
        }
        self.tag(&iv, &ciphertext)
            .verify_slice(&tag)
            .map_err(|_| VaultError::Crypto("MAC mismatch (wrong key or tampered data)".into()))?; // audit-allow: verify_slice error is opaque by design (no crypto oracle)
        let mut buf = Zeroizing::new(ciphertext);
        let len = cbc::Decryptor::<Aes256>::new_from_slices(self.enc.as_slice(), &iv)
            .expect("32-byte key and 16-byte IV") // audit-allow: infallible, key is 32 bytes and IV 16 by construction
            .decrypt_padded::<Pkcs7>(buf.as_mut_slice())
            .map_err(|_| VaultError::Crypto("bad PKCS7 padding".into()))? // audit-allow: unpad error is opaque by design (no padding oracle)
            .len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt a text field. The plaintext is authenticated but need not be
    /// valid UTF-8 (another client may have stored binary), so it is decoded
    /// lossily rather than failing the whole item.
    pub fn decrypt_str(&self, enc_string: &str) -> Result<Zeroizing<String>, VaultError> {
        let bytes = self.decrypt(enc_string)?;
        Ok(Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    /// ek = 00..1f, mk = 20..3f — the key the Python vectors below were made with.
    fn kat_key() -> SymKey {
        let raw: Vec<u8> = (0u8..64).collect();
        SymKey::from_bytes(&raw).unwrap()
    }

    // Vectors generated by the Python reference:
    //   litebw.derive_master_key / master_password_hash / vaultseed._hkdf_expand
    #[test]
    fn pbkdf2_master_key_matches_python() {
        let kdf = Kdf::Pbkdf2 { iterations: 100_000 };
        let mk = MasterKey::derive("correct horse", "Alice@Example.com", kdf).unwrap();
        assert_eq!(hex(mk.bytes()), "9c8e752452573e5788af5ad052befcd22400fb16e23c520e290387c3898a53d3");
        // The salt is case-insensitive and whitespace-insensitive.
        let lower = MasterKey::derive("correct horse", " alice@example.com ", kdf).unwrap();
        assert_eq!(mk.bytes(), lower.bytes());
        assert_eq!(mk.password_hash("correct horse").as_str(), "Aiw8x5jv7lQuxEjeSzdNU3/OwTpeSIqnNkiQn1w7fjw=");
    }

    #[test]
    fn pbkdf2_unicode_password_matches_python() {
        let mk = MasterKey::derive("pässwörd ✓", "User@X.com", Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
        assert_eq!(hex(mk.bytes()), "825dbedbfb1909818b9a5b463e85d3bd5ab0af298d9a0b57153a412c214059b9");
        assert_eq!(mk.password_hash("pässwörd ✓").as_str(), "d2GG85vq0halQlJWQdOqEQKg0IP6jCLVpPzYR/c2nxE=");
    }

    #[test]
    fn stretched_key_matches_python() {
        let mk = MasterKey::derive("correct horse", "alice@example.com", Kdf::Pbkdf2 { iterations: 100_000 }).unwrap();
        let stretched = mk.stretch().to_bytes();
        assert_eq!(hex(&stretched[..32]), "0d9c684c8163227ffca62df107b7a6ee71bb0575c933fa63f3c50ea58ec852ea");
        assert_eq!(hex(&stretched[32..]), "65d4286979d610ca784e704c0a2f41745546943e96a64838dd2f71e8822c587b");
    }

    #[test]
    fn argon2id_master_key_matches_python() {
        // memory is MiB on the wire and KiB in the primitive: an off-by-1024
        // silently derives a wrong key, so the exact digest is pinned.
        let kdf = Kdf::Argon2id { iterations: 3, memory_mib: 16, parallelism: 4 };
        let mk = MasterKey::derive("correct horse", "Alice@Example.com", kdf).unwrap();
        assert_eq!(hex(mk.bytes()), "4d09931e776160f6b61c3ff70a80400f39260a9328c771d4a9620926d522374d");
        assert_eq!(mk.password_hash("correct horse").as_str(), "XIdJEAjXo79xc80vZgLYqUmkv1KKjNyczctudpD4jmw=");

        let kdf = Kdf::Argon2id { iterations: 2, memory_mib: 19, parallelism: 1 };
        let mk = MasterKey::derive("pässwörd ✓", "user@x.com", kdf).unwrap();
        assert_eq!(hex(mk.bytes()), "b6f2fc6a67c3fb865e8e0463e6e3a9b055447b451520b29dfa47a79ef7a85847");
    }

    #[test]
    fn prelogin_parameters_are_range_checked_both_ways() {
        assert_eq!(Kdf::from_prelogin(0, 600_000, 0, 0).unwrap(), Kdf::Pbkdf2 { iterations: 600_000 });
        assert_eq!(
            Kdf::from_prelogin(1, 3, 64, 4).unwrap(),
            Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 }
        );
        // Downgrade: one round would leak a brute-forceable hash to a MITM.
        assert!(matches!(Kdf::from_prelogin(0, 1, 0, 0), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(0, 4_999, 0, 0), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(1, 1, 64, 4), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(1, 3, 8, 4), Err(VaultError::Kdf(_))));
        // Denial of service: billions of rounds / terabytes of memory.
        assert!(matches!(Kdf::from_prelogin(0, 2_000_000_000, 0, 0), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(0, u64::MAX, 0, 0), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(1, 9_999_999_999, 64, 4), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(1, 3, 8_000_000, 4), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(1, 3, 64, 9_999), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(1, 3, 64, 0), Err(VaultError::Kdf(_))));
        assert!(matches!(Kdf::from_prelogin(7, 1000, 0, 0), Err(VaultError::Kdf(_))));
    }

    // (plaintext hex, EncString) produced by Python with ek/mk = kat_key(), iv = 64..73.
    const ENC_KATS: &[(&str, &str)] = &[
        ("", "2.ZGVmZ2hpamtsbW5vcHFycw==|95X26IAv0VGgIaQRUNSraQ==|w5/bRz27QXlnr7nU2sVc5I8DnbaRD3W7MftHgXRtU1s="),
        ("61", "2.ZGVmZ2hpamtsbW5vcHFycw==|6ky0TfMi0CNQYOW5GRA/zg==|DCwj6MLIxi1qBW53RgcFmQcK68upd9rZbjvBVXl2zWY="),
        (
            "787878787878787878787878787878",
            "2.ZGVmZ2hpamtsbW5vcHFycw==|hEvrV6Y+XhadMXnQ0svfFA==|+5Ez4WKTckanqoscIr5X2dNB9LgPNOYmhOb1KdyBysQ=",
        ),
        (
            "30313233343536373839616263646566",
            "2.ZGVmZ2hpamtsbW5vcHFycw==|4P4UkdfMCB7arNmPR/WI00V6Prr4Om4LwTn8vhcf6PQ=|sP9ac2S7KDGF1ttgqnUoenPMOCsGiQYD7rmzKCuZQ+s=",
        ),
        (
            "68c3a96c6c6f2077c3b6726c64",
            "2.ZGVmZ2hpamtsbW5vcHFycw==|VL4W3BojNIxX66xefF+1xw==|1ns7m+PNpBBuNvfAbVq6nqlr4FvjZWd35M7N8DJLSY0=",
        ),
        (
            "fffe0041",
            "2.ZGVmZ2hpamtsbW5vcHFycw==|rVBCqZQHBO3NL1zj+aYthA==|Fcf3aQFBOJE17o+zrprDL+P3HzoGYbco4rVHe5HhU7k=",
        ),
    ];

    #[test]
    fn encstring_decrypt_and_encrypt_match_python() {
        let key = kat_key();
        let iv: [u8; 16] = std::array::from_fn(|i| 100 + i as u8);
        for (plain_hex, enc) in ENC_KATS {
            let plain = unhex(plain_hex);
            assert_eq!(key.decrypt(enc).unwrap().as_slice(), plain.as_slice(), "decrypt {plain_hex}");
            assert_eq!(&key.encrypt_with_iv(&plain, &iv), enc, "encrypt {plain_hex}");
        }
    }

    #[test]
    fn decrypts_a_python_encstring_with_a_random_iv() {
        let enc = "2.B2TmAb/mt2okhiRiMNMJrA==|WRhhV7KEKeujPXAAh0XqwEU39OjwXbft3M+RQd0R9v0=|aZYI9nC3JT7dkEXECIqdusHuE5LSjwfseJHcsFkdrgg=";
        assert_eq!(kat_key().decrypt_str(enc).unwrap().as_str(), "s3cr3t-pässword");
    }

    #[test]
    fn account_key_unwraps_under_the_stretched_master_key() {
        // tok["Key"] as Python built it: the 64 bytes 40..7f under the stretched key.
        let protected = "2.AAECAwQFBgcICQoLDA0ODw==|dw0F3MnAIEuiAT3TnmMif0nfwfbFgTgyTtjDoSeoK90Nncr1LxMu9U5diSTIs+v3KJ1E4Qtnz0HupiV+wW/RphrRERFXeCKjupHp5FI53P8=|hUGacQLnCMF+sTSsW1Ya66u9Gnu8EtT+UJPG1UfF8eo=";
        let mk = MasterKey::derive("correct horse", "alice@example.com", Kdf::Pbkdf2 { iterations: 100_000 }).unwrap();
        let sym = mk.stretch().decrypt(protected).unwrap();
        let want: Vec<u8> = (64u8..128).collect();
        assert_eq!(sym.as_slice(), want.as_slice());
        assert!(SymKey::from_bytes(&sym).is_ok());
    }

    #[test]
    fn roundtrips_edge_lengths_with_random_ivs() {
        let key = SymKey::random().unwrap();
        for plain in ["", "a", "xxxxxxxxxxxxxxx", "0123456789abcdef", "0123456789abcdef!", "ünïcödé · 日本語 · key"]
        {
            let enc = key.encrypt_str(plain).unwrap();
            assert!(enc.starts_with("2."));
            assert_eq!(key.decrypt_str(&enc).unwrap().as_str(), plain);
        }
        // Two encryptions of the same plaintext never share an IV.
        assert_ne!(key.encrypt(b"same").unwrap(), key.encrypt(b"same").unwrap());
    }

    #[test]
    fn non_utf8_plaintext_decodes_lossily() {
        let out = kat_key().decrypt_str(ENC_KATS[5].1).unwrap();
        assert!(out.contains('A'));
    }

    #[test]
    fn tampering_and_wrong_keys_are_rejected_before_decryption() {
        let key = kat_key();
        let enc = ENC_KATS[4].1;
        let (head, mac) = enc.rsplit_once('|').unwrap();
        // Clobbered MAC.
        let zero_mac = format!("{head}|{}", b64(&[0u8; 32]));
        assert!(matches!(key.decrypt(&zero_mac), Err(VaultError::Crypto(m)) if m.contains("MAC")));
        // Flipped ciphertext bit under the original MAC.
        let (iv, ct) = head.split_once('|').unwrap();
        let mut raw = unb64(ct).unwrap();
        raw[0] ^= 1;
        let flipped = format!("{iv}|{}|{mac}", b64(&raw));
        assert!(matches!(key.decrypt(&flipped), Err(VaultError::Crypto(m)) if m.contains("MAC")));
        // Wrong key.
        assert!(matches!(SymKey::random().unwrap().decrypt(enc), Err(VaultError::Crypto(m)) if m.contains("MAC")));
        // Truncated MAC.
        let short = format!("{head}|{}", b64(&[0u8; 16]));
        assert!(key.decrypt(&short).is_err());
    }

    #[test]
    fn mac_valid_but_badly_padded_plaintext_fails_closed() {
        // One raw block whose last byte is not a PKCS7 pad length.
        let key = kat_key();
        let iv = [7u8; 16];
        for last in [0x00u8, 0x11] {
            let mut block = [0x41u8; 16];
            block[15] = last;
            // Encrypt the raw block without padding: CBC of a single block.
            use aes::cipher::{BlockCipherEncrypt, KeyInit as _};
            let mut x: [u8; 16] = std::array::from_fn(|i| block[i] ^ iv[i]);
            aes::Aes256::new_from_slice(key.enc.as_slice()).unwrap().encrypt_block((&mut x).into());
            let tag = key.tag(&iv, &x).finalize().into_bytes();
            let enc = format!("2.{}|{}|{}", b64(&iv), b64(&x), b64(&tag));
            assert!(matches!(key.decrypt(&enc), Err(VaultError::Crypto(m)) if m.contains("padding")));
        }
    }

    #[test]
    fn unauthenticated_and_malformed_encstrings_are_refused() {
        let key = kat_key();
        let b16 = b64(&[0u8; 16]);
        let cases = [
            "plain text smuggled by the server".to_string(),
            "no-dot-at-all".to_string(),
            "2.onlyone".to_string(),
            format!("2.{b16}|{b16}"),
            format!("2.{}", ["AAAA"; 4].join("|")),
            "2.not-base64!!!|also!!!|nope!!!".to_string(),
            // Type 0 has no MAC at all: must never be decrypted.
            format!("0.{b16}|{b16}"),
            format!("0.{b16}|"),
            // Type 1 is AES-128 and obsolete; a type-2-shaped body does not make it valid.
            ENC_KATS[1].1.replacen("2.", "1.", 1),
            ENC_KATS[1].1.replacen("2.", "999.", 1),
            // Empty and non-block-aligned ciphertexts.
            format!("2.{b16}||{}", b64(&[0u8; 32])),
            format!("2.{b16}|{}|{}", b64(&[0u8; 7]), b64(&[0u8; 32])),
            String::new(),
        ];
        for bad in cases {
            assert!(matches!(key.decrypt(&bad), Err(VaultError::Crypto(_))), "accepted {bad:?}");
        }
    }

    #[test]
    fn debug_output_never_shows_key_material() {
        let key = kat_key();
        assert_eq!(format!("{key:?}"), "SymKey(<redacted>)");
        let mk = MasterKey::derive("pw", "a@b.c", Kdf::Pbkdf2 { iterations: 5000 }).unwrap();
        assert_eq!(format!("{mk:?}"), "MasterKey(<redacted>)");
    }
}
