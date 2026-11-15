//! The sealed-blob formats.
//!
//! v2 (current, self-describing):  `MAGIC(2) | ALGO(1) | salt(16) | nonce(12) | ct+tag`
//! legacy (earlier releases):      `salt(16) | nonce(12) | ct+tag`, scrypt N=2^14
//!
//! Both are AES-256-GCM with no associated data. Legacy blobs are read-only:
//! nothing new is ever sealed that way.

use crate::error::{Result, SealError};
use crate::kdf::{self, Algo, Cost};
use crate::rng;
use aes_gcm::aead::AeadInOut;
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::{Aes256Gcm, KeyInit};
use zeroize::Zeroizing;

pub(crate) const MAGIC: &[u8; 2] = b"PS";
const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;
/// magic + algo + salt + nonce
pub(crate) const V2_HEADER: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;
/// salt + nonce
const LEGACY_HEADER: usize = SALT_LEN + NONCE_LEN;

/// AES-256-GCM encrypt; returns `ciphertext | tag`.
pub(crate) fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, InOutBuf::from(out.as_mut_slice()))
        .map_err(|_| SealError::Format)?; // audit-allow: aead::Error is opaque by design
    out.extend_from_slice(&tag);
    Ok(out)
}

/// AES-256-GCM decrypt of `ciphertext | tag`; `None` when authentication fails.
/// The tag is checked before any plaintext is produced, and the plaintext only
/// ever lives in the returned zeroizing buffer.
pub(crate) fn aead_open(key: &[u8; 32], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().ok()?;
    let split = sealed.len().checked_sub(TAG_LEN)?;
    let (ciphertext, tag) = sealed.split_at_checked(split)?;
    let tag: &[u8; TAG_LEN] = tag.try_into().ok()?;
    let cipher = Aes256Gcm::new(key.into());
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    cipher.decrypt_inout_detached(nonce.into(), aad, InOutBuf::from(plain.as_mut_slice()), tag.into()).ok()?;
    Some(plain)
}

/// True if `blob` carries the v2 header. A legacy blob starts with a random
/// salt, so about 1 in 8 million of them look like this by chance — which is
/// why [`open_either`] falls back to the legacy reader when v2 fails.
pub(crate) fn is_v2(blob: &[u8]) -> bool {
    blob.len() >= V2_HEADER && blob.starts_with(MAGIC) && Algo::from_id(blob[MAGIC.len()]).is_some()
}

/// Seal `plaintext` as a v2 blob under a key derived from `material`.
pub(crate) fn seal(material: &[u8], plaintext: &[u8], algo: Algo, cost: Cost) -> Result<Vec<u8>> {
    let salt: [u8; SALT_LEN] = rng::array()?;
    let nonce: [u8; NONCE_LEN] = rng::array()?;
    let key = kdf::derive(material, &salt, algo, cost)?;
    let sealed = aead_seal(&key, &nonce, &[], plaintext)?;
    let mut blob = Vec::with_capacity(V2_HEADER + sealed.len());
    blob.extend_from_slice(MAGIC);
    blob.push(algo.id());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Open a v2 blob.
pub(crate) fn open(material: &[u8], blob: &[u8], cost: Cost) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < V2_HEADER || !blob.starts_with(MAGIC) {
        return Err(SealError::Format);
    }
    let algo = blob.get(MAGIC.len()).copied().and_then(Algo::from_id).ok_or(SealError::Format)?;
    let body = blob.get(MAGIC.len() + 1..).ok_or(SealError::Format)?;
    let (salt, rest) = body.split_at_checked(SALT_LEN).ok_or(SealError::Format)?;
    let (nonce, sealed) = rest.split_at_checked(NONCE_LEN).ok_or(SealError::Format)?;
    let key = kdf::derive(material, salt, algo, cost)?;
    aead_open(&key, nonce, &[], sealed).ok_or(SealError::WrongHostOrCorrupt)
}

/// Open a pre-v2 blob.
pub(crate) fn open_legacy(material: &[u8], blob: &[u8], cost: Cost) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < LEGACY_HEADER {
        return Err(SealError::Format);
    }
    let (salt, rest) = blob.split_at_checked(SALT_LEN).ok_or(SealError::Format)?;
    let (nonce, sealed) = rest.split_at_checked(NONCE_LEN).ok_or(SealError::Format)?;
    let key = kdf::derive(material, salt, Algo::LegacyScrypt, cost)?;
    aead_open(&key, nonce, &[], sealed).ok_or(SealError::WrongHostOrCorrupt)
}

/// Open one sealed blob of either format, returning `(plaintext, was_legacy)`.
///
/// The decision is made per blob, never per seal: an interrupted migration
/// leaves a v2 `pin.enc` beside a legacy `master.enc`, and that state has to
/// unseal. `v2_material` is `None` when there is no usable `host.key`;
/// `no_key` then says why.
pub(crate) fn open_either(
    blob: &[u8],
    v2_material: Option<&[u8]>,
    no_key: impl FnOnce() -> SealError,
    legacy_material: &[u8],
    cost: Cost,
) -> Result<(Zeroizing<Vec<u8>>, bool)> {
    if !is_v2(blob) {
        return open_legacy(legacy_material, blob, cost).map(|p| (p, true));
    }
    let v2 = match v2_material {
        Some(material) => open(material, blob, cost),
        None => Err(no_key()),
    };
    match v2 {
        Ok(plain) => Ok((plain, false)),
        // A legacy salt that happens to look like a v2 header.
        Err(v2_err) => open_legacy(legacy_material, blob, cost).map(|p| (p, true)).map_err(|_| v2_err), // audit-allow: the v2 error is the more informative one; the legacy fallback error is discarded on purpose
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: Cost = Cost::TEST;

    #[test]
    fn v2_round_trip_and_layout() {
        for algo in [Algo::Scrypt, Algo::Pbkdf2] {
            let blob = seal(b"material", b"plaintext", algo, C).unwrap();
            assert_eq!(&blob[..2], b"PS");
            assert_eq!(blob[2], algo.id());
            assert_eq!(blob.len(), 2 + 1 + 16 + 12 + b"plaintext".len() + 16);
            assert!(is_v2(&blob));
            assert_eq!(open(b"material", &blob, C).unwrap().as_slice(), b"plaintext");
        }
    }

    #[test]
    fn wrong_material_or_any_flipped_bit_is_rejected() {
        let blob = seal(b"material", b"plaintext", Algo::Scrypt, C).unwrap();
        assert!(matches!(open(b"other", &blob, C), Err(SealError::WrongHostOrCorrupt)));
        for i in 3..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            assert!(open(b"material", &bad, C).is_err(), "byte {i}");
        }
    }

    #[test]
    fn short_or_unlabelled_blobs_are_a_format_error() {
        assert!(matches!(open(b"m", b"PS\x01short", C), Err(SealError::Format)));
        assert!(matches!(open(b"m", &[0u8; 40], C), Err(SealError::Format)));
        // "PS" + the internal legacy id is not a storable algorithm.
        let mut blob = seal(b"m", b"p", Algo::Scrypt, C).unwrap();
        blob[2] = 0;
        assert!(!is_v2(&blob));
        assert!(matches!(open(b"m", &blob, C), Err(SealError::Format)));
        assert!(matches!(open_legacy(b"m", &[0u8; 27], C), Err(SealError::Format)));
        // header only, no room for a tag
        let whole = seal(b"m", b"p", Algo::Scrypt, C).unwrap();
        assert!(matches!(open(b"m", &whole[..V2_HEADER], C), Err(SealError::WrongHostOrCorrupt)));
    }

    #[test]
    fn open_either_prefers_v2_and_reports_the_v2_error() {
        let blob = seal(b"v2", b"plain", Algo::Scrypt, C).unwrap();
        let (plain, legacy) = open_either(&blob, Some(b"v2"), || SealError::HostKeyMissing, b"legacy", C).unwrap();
        assert_eq!((plain.as_slice(), legacy), (&b"plain"[..], false));
        // No host.key: the reason is what the operator sees, not "corrupt".
        let err = open_either(&blob, None, || SealError::HostKeyCorrupt, b"legacy", C).unwrap_err();
        assert!(matches!(err, SealError::HostKeyCorrupt));
        // Wrong v2 key and not legacy either: the v2 verdict is what surfaces.
        let err = open_either(&blob, Some(b"other"), || SealError::HostKeyMissing, b"legacy", C).unwrap_err();
        assert!(matches!(err, SealError::WrongHostOrCorrupt));
    }

    #[test]
    fn empty_plaintext_and_aad_are_authenticated() {
        let key = [7u8; 32];
        let nonce = [9u8; NONCE_LEN];
        let sealed = aead_seal(&key, &nonce, b"aad", b"").unwrap();
        assert_eq!(sealed.len(), TAG_LEN);
        assert!(aead_open(&key, &nonce, b"aad", &sealed).unwrap().is_empty());
        assert!(aead_open(&key, &nonce, b"other", &sealed).is_none());
        assert!(aead_open(&key, &nonce, b"aad", &sealed[..TAG_LEN - 1]).is_none());
    }
}
