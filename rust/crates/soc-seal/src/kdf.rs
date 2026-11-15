//! Key derivation for sealed blobs.
//!
//! The KDF id travels in each blob, so a blob always opens with the algorithm
//! it was sealed under regardless of the current `SOC_FIPS_KDF` setting. The
//! parameters are part of the on-disk format: changing any of them orphans
//! every box in the field.

use crate::error::{Result, SealError};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The KDF a blob was sealed under (the blob's ALGO byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algo {
    /// Unlabelled pre-v2 data: scrypt N=2^14. Never written, never on disk as
    /// an id.
    LegacyScrypt,
    /// RFC 7914 scrypt N=2^17, r=8, p=1 (~128 MiB) — the memory-hard default.
    Scrypt,
    /// NIST SP 800-132 PBKDF2-HMAC-SHA256, 600 000 iterations, for FIPS 140
    /// deployments (scrypt is not an approved KDF).
    Pbkdf2,
}

impl Algo {
    pub(crate) const SCRYPT_ID: u8 = 1;
    pub(crate) const PBKDF2_ID: u8 = 2;

    /// The id stored in a v2 blob, for the two algorithms that are ever stored.
    pub(crate) fn from_id(id: u8) -> Option<Algo> {
        match id {
            Algo::SCRYPT_ID => Some(Algo::Scrypt),
            Algo::PBKDF2_ID => Some(Algo::Pbkdf2),
            _ => None,
        }
    }

    pub(crate) fn id(self) -> u8 {
        match self {
            Algo::LegacyScrypt => 0,
            Algo::Scrypt => Algo::SCRYPT_ID,
            Algo::Pbkdf2 => Algo::PBKDF2_ID,
        }
    }
}

/// Work factors. Production values are fixed by the on-disk format; the unit
/// tests swap in tiny ones so the suite does not spend 128 MiB per derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cost {
    scrypt_log_n: u8,
    legacy_scrypt_log_n: u8,
    pbkdf2_iters: u32,
}

impl Cost {
    pub(crate) const PRODUCTION: Cost = Cost { scrypt_log_n: 17, legacy_scrypt_log_n: 14, pbkdf2_iters: 600_000 };
    /// Distinct per algorithm, so a test that confuses two of them still fails.
    #[cfg(test)]
    pub(crate) const TEST: Cost = Cost { scrypt_log_n: 5, legacy_scrypt_log_n: 4, pbkdf2_iters: 7 };
}

const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

pub(crate) type Key = Zeroizing<[u8; 32]>;

/// Derive a 256-bit key from `material` and `salt`.
pub(crate) fn derive(material: &[u8], salt: &[u8], algo: Algo, cost: Cost) -> Result<Key> {
    #[cfg(test)]
    counter::bump();
    let mut key: Key = Zeroizing::new([0u8; 32]);
    match algo {
        Algo::Pbkdf2 => pbkdf2::pbkdf2_hmac::<Sha256>(material, salt, cost.pbkdf2_iters, key.as_mut()),
        Algo::Scrypt => scrypt(material, salt, cost.scrypt_log_n, key.as_mut())?,
        Algo::LegacyScrypt => scrypt(material, salt, cost.legacy_scrypt_log_n, key.as_mut())?,
    }
    Ok(key)
}

fn scrypt(material: &[u8], salt: &[u8], log_n: u8, out: &mut [u8]) -> Result<()> {
    let params = scrypt::Params::new(log_n, SCRYPT_R, SCRYPT_P).map_err(|_| SealError::Kdf("bad scrypt parameters"))?; // audit-allow: scrypt::errors::InvalidParams has no detail
    // scrypt allocates 128·r·N bytes and an allocation failure there aborts the
    // process. Ask for the same amount first so a box under memory pressure
    // gets a typed error (and the operator the right hint) instead.
    let working_set = 128usize
        .checked_mul(usize::try_from(SCRYPT_R).map_err(|_| SealError::Kdf("scrypt r does not fit usize"))?) // audit-allow: u32 to usize error has no detail
        .and_then(|b| b.checked_shl(u32::from(log_n)))
        .ok_or(SealError::Kdf("scrypt working set too large"))?;
    let mut probe: Vec<u8> = Vec::new();
    probe.try_reserve_exact(working_set).map_err(|_| SealError::Kdf("cannot allocate the scrypt working set"))?; // audit-allow: TryReserveError detail is replaced by the operator hint
    drop(probe);
    scrypt::scrypt(material, salt, &params, out).map_err(|_| SealError::Kdf("bad scrypt output length")) // audit-allow: InvalidOutputLen has no detail
}

/// Per-thread count of derivations, so a test can prove a path ran no KDF.
#[cfg(test)]
pub(crate) mod counter {
    use std::cell::Cell;

    thread_local! {
        static RUNS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn bump() {
        RUNS.with(|r| r.set(r.get() + 1));
    }

    pub(crate) fn get() -> usize {
        RUNS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_cost_is_the_on_disk_format() {
        // A security control and a compatibility contract: guard both against
        // an accidental edit.
        assert_eq!(Cost::PRODUCTION, Cost { scrypt_log_n: 17, legacy_scrypt_log_n: 14, pbkdf2_iters: 600_000 });
        assert_eq!((SCRYPT_R, SCRYPT_P), (8, 1));
    }

    #[test]
    fn algo_ids_round_trip_and_legacy_is_never_stored() {
        assert_eq!(Algo::from_id(Algo::Scrypt.id()), Some(Algo::Scrypt));
        assert_eq!(Algo::from_id(Algo::Pbkdf2.id()), Some(Algo::Pbkdf2));
        assert_eq!(Algo::from_id(Algo::LegacyScrypt.id()), None);
        assert_eq!(Algo::from_id(3), None);
    }

    #[test]
    fn kdfs_match_pythons_hashlib() {
        // hashlib.scrypt(b"pw", salt=b"salt", n=16, r=8, p=1, dklen=32)
        let mut out = [0u8; 32];
        scrypt(b"pw", b"salt", 4, &mut out).unwrap();
        assert_eq!(hex(&out), "c5d06c368e4a07b8a98e9a06773fcf4a639bb03b909af99f94497747f828184e");
        // hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 7, dklen=32)
        let key = derive(b"pw", b"salt", Algo::Pbkdf2, Cost::TEST).unwrap();
        assert_eq!(hex(key.as_ref()), "3481192acabf2e80238e6b58fd055e314be72eb94f9c3eda05fc16e766ba7ac4");
    }

    #[test]
    fn algorithms_and_costs_derive_different_keys() {
        let c = Cost::TEST;
        let a = derive(b"m", b"0123456789abcdef", Algo::Scrypt, c).unwrap();
        let b = derive(b"m", b"0123456789abcdef", Algo::LegacyScrypt, c).unwrap();
        let p = derive(b"m", b"0123456789abcdef", Algo::Pbkdf2, c).unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*a, *p);
        assert_eq!(*a, *derive(b"m", b"0123456789abcdef", Algo::Scrypt, c).unwrap());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
