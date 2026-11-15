//! On-disk compatibility with the Python release, at the REAL KDF cost.
//!
//! `tests/fixtures/` was written by `kiosk-host/host/secretstore.py` itself
//! (see `fixtures/generate.py`). A box sealed by Python must unseal here with
//! no operator action: same file names, magic and ALGO bytes, KDF parameters,
//! key material layout, legacy format and migration.
//!
//! Each derivation here is the production one (scrypt N=2^17 is ~128 MiB), so
//! the tests take a lock and run one at a time.

use soc_seal::{SealError, SecretStore};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

const MACHINE_ID: &str = "fixture-host-0001";
const MASTER: &str = "Fixture-Master ✓ not-a-real-secret";
const PIN: &str = "135790";
const LEGACY_PIN: &str = "4321";

/// One 128 MiB derivation at a time: the suite must fit a 1 GB machine.
static HEAVY: Mutex<()> = Mutex::new(());

fn heavy() -> std::sync::MutexGuard<'static, ()> {
    HEAVY.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A private, writable copy of one fixture seal, removed on drop.
struct Copy(PathBuf);

impl Copy {
    fn of(fixture: &str) -> Copy {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("soc-seal-compat-{fixture}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(fixture);
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = dir.join(entry.file_name());
            fs::copy(entry.path(), &target).unwrap();
            // A git checkout does not keep the 0600 the seal was written with.
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Copy(dir)
    }

    fn store(&self) -> SecretStore {
        SecretStore::new(&self.0).with_machine_id(MACHINE_ID)
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> =
            fs::read_dir(&self.0).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        names
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.0.join(name)).unwrap()
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

#[test]
fn python_v2_scrypt_seal_unseals() {
    let _one_at_a_time = heavy();
    let seal = Copy::of("v2-scrypt");
    let before = seal.names();
    let store = seal.store();
    assert_eq!(&seal.read("master.enc")[..3], b"PS\x01");
    assert!(store.is_sealed());
    assert_eq!(store.unseal().unwrap().as_str(), MASTER);
    assert!(store.verify_pin(PIN));
    assert!(!store.verify_pin("135791"));
    assert_eq!(seal.names(), before, "reading a v2 seal writes nothing");
}

#[test]
fn python_v2_pbkdf2_seal_unseals_whatever_the_current_kdf_setting() {
    let _one_at_a_time = heavy();
    let seal = Copy::of("v2-pbkdf2");
    assert_eq!(&seal.read("master.enc")[..3], b"PS\x02");
    // The KDF comes from the blob's ALGO byte, not from the current setting.
    assert_eq!(seal.store().with_fips_kdf(false).unseal().unwrap().as_str(), MASTER);
    assert!(seal.store().verify_pin(PIN));
}

#[test]
fn python_legacy_seal_unseals_even_where_it_cannot_be_migrated() {
    let _one_at_a_time = heavy();
    let seal = Copy::of("legacy");
    let store = seal.store();
    assert!(store.is_sealed(), "a legacy seal has no host.key and is still sealed");
    if is_root() {
        return; // root ignores directory modes; the --ignored tests cover migration
    }
    fs::set_permissions(&seal.0, fs::Permissions::from_mode(0o500)).unwrap();
    let got = store.unseal();
    fs::set_permissions(&seal.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(got.unwrap().as_str(), MASTER);
    assert_eq!(seal.names(), ["master.enc", "pin.enc", "pin.hash"], "left exactly as it was");
    assert!(store.verify_pin(LEGACY_PIN));
}

#[test]
fn python_interrupted_migration_state_unseals() {
    // Python died after committing host.key and a v2 pin.enc: master.enc is
    // still legacy. The format is chosen per blob, so this opens as it is.
    let _one_at_a_time = heavy();
    let seal = Copy::of("mid-migration");
    let before = seal.names();
    assert_eq!(before, ["host.key", "master.enc", "master.enc.tmp", "pin.enc", "pin.hash"]);
    assert_eq!(&seal.read("pin.enc")[..3], b"PS\x01");
    let store = seal.store();
    assert!(store.is_sealed());
    if is_root() {
        return; // root ignores directory modes; the --ignored tests cover the resume
    }
    fs::set_permissions(&seal.0, fs::Permissions::from_mode(0o500)).unwrap();
    let got = store.unseal();
    fs::set_permissions(&seal.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(got.unwrap().as_str(), MASTER);
    assert_eq!(seal.names(), before);
    assert!(store.verify_pin(LEGACY_PIN));
}

// The full migrations below each run the 128 MiB KDF four or more times, which
// is slow in an unoptimised build; the same logic runs in the unit tests at
// test cost. Run them with:
// `cargo test -p soc-seal --test python_compat -- --ignored`.

#[test]
#[ignore = "real-cost migration: several 128 MiB KDF runs"]
fn python_legacy_seal_migrates_in_place_with_the_same_pin() {
    let _one_at_a_time = heavy();
    let seal = Copy::of("legacy");
    let store = seal.store();
    let pin_hash = seal.read("pin.hash");
    assert_eq!(store.unseal().unwrap().as_str(), MASTER);
    assert_eq!(seal.names(), ["host.key", "master.enc", "pin.enc", "pin.hash"]);
    assert_eq!(seal.read("host.key").len(), 32);
    assert_eq!(&seal.read("pin.enc")[..3], b"PS\x01");
    assert_eq!(&seal.read("master.enc")[..3], b"PS\x01");
    assert_eq!(seal.read("pin.hash"), pin_hash, "the PIN did not change");
    assert!(store.verify_pin(LEGACY_PIN), "a 4-digit PIN from an earlier release still works");
    for name in seal.names() {
        let mode = fs::metadata(seal.0.join(&name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{name}");
    }
    // And it is now a v2 seal that needs its host.key. (That it opens was
    // proven before the legacy blobs were given up.)
    fs::remove_file(seal.0.join("host.key")).unwrap();
    assert!(!store.is_sealed());
    assert!(matches!(store.unseal(), Err(SealError::HostKeyMissing)));
}

#[test]
#[ignore = "real-cost migration: several 128 MiB KDF runs"]
fn python_migration_cut_off_mid_way_is_resumed() {
    // The v2 replacement for master.enc is stranded as master.enc.tmp: the
    // next unseal finishes the job with the host.key already in place.
    let _one_at_a_time = heavy();
    let seal = Copy::of("mid-migration");
    assert_eq!(seal.names(), ["host.key", "master.enc", "master.enc.tmp", "pin.enc", "pin.hash"]);
    let host_key = seal.read("host.key");
    let store = seal.store();
    assert!(store.is_sealed());
    assert_eq!(store.unseal().unwrap().as_str(), MASTER);
    assert_eq!(seal.names(), ["host.key", "master.enc", "pin.enc", "pin.hash"]);
    assert_eq!(seal.read("host.key"), host_key, "the key the v2 pin.enc depends on was kept");
    assert_eq!(&seal.read("master.enc")[..3], b"PS\x01");
    assert!(store.verify_pin(LEGACY_PIN));
}

/// The other direction: a seal written here opens in the Python release.
/// Needs `python3` with `cryptography` and the repo's `kiosk-host/` next to
/// `rust/`, so it only runs on request.
#[test]
#[ignore = "needs python3 + cryptography and the Python sources"]
fn rust_seal_unseals_in_python() {
    let _one_at_a_time = heavy();
    let kiosk_host = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../kiosk-host");
    assert!(kiosk_host.join("host/secretstore.py").is_file(), "Python sources not found");
    for fips in [false, true] {
        let seal = Copy::of("ticket"); // any directory will do: it is re-sealed
        fs::remove_file(seal.0.join("soc-unseal.ticket")).unwrap();
        seal.store().with_fips_kdf(fips).seal(MASTER, PIN).unwrap();
        let code = "import sys; from host import secretstore as ss; d = sys.argv[1]; \
                    assert ss.is_sealed(d); assert ss.verify_pin(sys.argv[2], d); print(ss.unseal(d))";
        let out = std::process::Command::new("python3")
            .args(["-c", code])
            .arg(&seal.0)
            .arg(PIN)
            .current_dir(&kiosk_host)
            .env("SOC_MACHINE_ID", MACHINE_ID)
            .env("SOC_UNSEAL_CACHE_TTL", "0")
            .env_remove("SOC_SECRET_BACKEND")
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'), MASTER, "fips={fips}");
    }
}
