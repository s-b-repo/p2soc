//! Unit tests for the seal, its legacy migration and the session ticket.
//!
//! These run with tiny KDF work factors; `tests/python_compat.rs` exercises the
//! real ones against blobs written by the Python release.

use super::*;
use crate::fsio::testdir::TestDir;
use crate::kdf::{self, counter};
use std::os::unix::fs::PermissionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MID: &str = "host-A";
const MASTER: &str = "Legacy-Master!";
const PIN: &str = "12345678";

impl SecretStore {
    fn for_test(dir: &Path) -> SecretStore {
        SecretStore::for_unit_tests(dir).with_lock_wait(Duration::from_secs(30))
    }

    /// A session ticket in `dir`, without the tmpfs requirement.
    fn with_test_ticket(mut self, dir: &Path) -> SecretStore {
        let mut cfg = TicketCfg::new(ticket::DEFAULT_TTL, None);
        cfg.trusted_dir = Some(dir.to_path_buf());
        cfg.boot_id = Some(b"boot-1".to_vec());
        self.ticket = Some(cfg);
        self
    }

    fn ticket_cfg(&mut self) -> &mut TicketCfg {
        self.ticket.as_mut().expect("test store has a ticket")
    }

    /// Die (unwind, with no cleanup) just before rename number `commits`.
    fn cut_power_after(mut self, commits: usize) -> SecretStore {
        let done = AtomicUsize::new(0);
        self.faults.before_rename = Some(Arc::new(move |_| {
            if done.load(Ordering::SeqCst) == commits {
                resume_unwind(Box::new("power cut"));
            }
            done.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));
        self
    }

    fn with_stage_error(mut self, kind: io::ErrorKind) -> SecretStore {
        self.faults.stage_error = Some(kind);
        self
    }
}

fn power_cut<T>(f: impl FnOnce() -> T) {
    assert!(catch_unwind(AssertUnwindSafe(f)).is_err(), "the power cut never happened");
}

fn legacy_blob(material: &[u8], plaintext: &[u8], salt: Option<[u8; 16]>) -> Vec<u8> {
    let salt = salt.unwrap_or_else(|| rng::array().unwrap());
    let nonce: [u8; 12] = rng::array().unwrap();
    let key = kdf::derive(material, &salt, Algo::LegacyScrypt, Cost::TEST).unwrap();
    [&salt[..], &nonce[..], &blob::aead_seal(&key, &nonce, &[], plaintext).unwrap()].concat()
}

/// Lay down a pre-v2 seal by hand: salt|nonce|ct blobs keyed by the machine-id
/// alone, and no host.key.
fn write_legacy_seal(dir: &Path, pin: &str, salt: Option<[u8; 16]>) {
    fs::create_dir_all(dir).unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    let files: [(&str, Vec<u8>); 3] = [
        (PIN_HASH_FILE, pin::hash_line(&rng::array().unwrap(), pin.as_bytes()).to_vec()),
        (PIN_FILE, legacy_blob(MID.as_bytes(), pin.as_bytes(), salt)),
        (MASTER_FILE, legacy_blob(format!("{MID}{pin}").as_bytes(), MASTER.as_bytes(), salt)),
    ];
    for (name, data) in files {
        fs::write(dir.join(name), data).unwrap();
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn legacy(label: &str) -> (TestDir, SecretStore) {
    let d = TestDir::new(label);
    write_legacy_seal(d.path(), PIN, None);
    let store = SecretStore::for_test(d.path());
    (d, store)
}

fn sealed_v2(label: &str) -> (TestDir, SecretStore) {
    let d = TestDir::new(label);
    let store = SecretStore::for_test(d.path());
    store.seal(MASTER, PIN).unwrap();
    (d, store)
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> =
        fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names
}

fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    names(dir).into_iter().map(|n| (n.clone(), fs::read(dir.join(n)).unwrap())).collect()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn is_v2(dir: &Path, name: &str) -> bool {
    blob::is_v2(&fs::read(dir.join(name)).unwrap())
}

fn assert_fully_migrated(dir: &Path) {
    assert_eq!(names(dir), ["host.key", "master.enc", "pin.enc", "pin.hash"]);
    assert_eq!(fs::read(dir.join("host.key")).unwrap().len(), 32);
    assert!(is_v2(dir, "pin.enc") && is_v2(dir, "master.enc"));
}

fn unsealed(store: &SecretStore) -> String {
    store.unseal().unwrap().to_string()
}

// --- sealing ------------------------------------------------------------- //

#[test]
fn seal_unseal_round_trip() {
    let d = TestDir::new("rt");
    let store = SecretStore::for_test(d.path());
    assert!(!store.is_sealed());
    let pin = pin::gen_pin(8).unwrap();
    store.seal("Master-PW!", &pin).unwrap();
    assert!(store.is_sealed());
    assert_eq!(unsealed(&store), "Master-PW!");
    assert!(store.verify_pin(&pin));
    assert!(!store.verify_pin("00000000") || *pin == "00000000");
    assert!(!store.verify_pin(""));
}

#[test]
fn seal_rejects_a_short_pin_and_accepts_one_at_the_floor() {
    let d = TestDir::new("shortpin");
    let store = SecretStore::for_test(d.path());
    assert!(matches!(store.seal("master", "123"), Err(SealError::Invalid(_))));
    assert!(!store.is_sealed());
    store.seal("master", &"1".repeat(MIN_PIN_LEN)).unwrap();
    assert_eq!(unsealed(&store), "master");
    // The floor counts characters, as the Python release did.
    store.seal("master", "pïn→ok").unwrap();
}

#[test]
fn seal_refuses_empty_input() {
    let d = TestDir::new("empty");
    let store = SecretStore::for_test(d.path());
    assert!(matches!(store.seal("", "123456"), Err(SealError::Invalid(_))));
    assert!(matches!(store.seal("m", ""), Err(SealError::Invalid(_))));
    assert_eq!(names(d.path()), [] as [&str; 0]);
}

#[test]
fn files_are_0600_dir_is_0700_and_nothing_is_plaintext() {
    let d = TestDir::new("modes");
    let sd = d.join("etc/soc/secret");
    let store = SecretStore::for_test(&sd);
    store.seal("PlAiNtExT-secret", PIN).unwrap();
    assert_eq!(mode(&sd), 0o700);
    assert_eq!(names(&sd), ["host.key", "master.enc", "pin.enc", "pin.hash"], "no tmp files left");
    for (name, data) in snapshot(&sd) {
        assert_eq!(mode(&sd.join(&name)), 0o600, "{name}");
        assert!(!data.windows(16).any(|w| w == b"PlAiNtExT-secret"), "{name}");
        assert!(!data.windows(PIN.len()).any(|w| w == PIN.as_bytes()), "{name}");
    }
}

#[test]
fn seal_tightens_an_existing_loose_directory() {
    let d = TestDir::new("loose");
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
    SecretStore::for_test(d.path()).seal(MASTER, PIN).unwrap();
    assert_eq!(mode(d.path()), 0o700);
}

#[test]
fn seal_is_bound_to_the_host() {
    let (d, _) = sealed_v2("bind");
    let elsewhere = SecretStore::for_test(d.path()).with_machine_id("host-B");
    assert!(matches!(elsewhere.unseal(), Err(SealError::WrongHostOrCorrupt)));
}

#[test]
fn unseal_with_nothing_sealed_says_so() {
    let d = TestDir::new("none");
    assert!(matches!(SecretStore::for_test(d.path()).unseal(), Err(SealError::NotSealed(_))));
    assert!(matches!(SecretStore::for_test(&d.join("absent")).unseal(), Err(SealError::NotSealed(_))));
}

#[test]
fn is_sealed_requires_every_file() {
    // A half-written seal must read as NOT sealed, so the operator re-seals
    // instead of booting into an unrecoverable state.
    let (d, store) = sealed_v2("complete");
    for name in ["pin.enc", "pin.hash", "master.enc"] {
        fs::remove_file(d.join(name)).unwrap();
        assert!(!store.is_sealed(), "without {name}");
        store.seal(MASTER, PIN).unwrap();
        assert!(store.is_sealed());
    }
}

#[test]
fn reseal_replaces_master_pin_and_host_key() {
    let d = TestDir::new("reseal");
    let store = SecretStore::for_test(d.path());
    store.seal("old-pw", "11111111").unwrap();
    let first_key = fs::read(d.join("host.key")).unwrap();
    store.seal("new-pw", "22222222").unwrap();
    assert_eq!(unsealed(&store), "new-pw");
    assert!(store.verify_pin("22222222") && !store.verify_pin("11111111"));
    let second_key = fs::read(d.join("host.key")).unwrap();
    assert_eq!(first_key.len(), 32);
    assert_ne!(first_key, second_key, "the host key rotates on every seal");
}

#[test]
fn fips_mode_seals_with_pbkdf2_and_the_blob_says_so() {
    let d = TestDir::new("fips");
    let fips = SecretStore::for_test(d.path()).with_fips_kdf(true);
    fips.seal("fips-master", "123456").unwrap();
    assert_eq!(fs::read(d.join("master.enc")).unwrap()[..3], [b'P', b'S', Algo::PBKDF2_ID]);
    assert_eq!(fs::read(d.join("pin.enc")).unwrap()[2], Algo::PBKDF2_ID);
    assert_eq!(unsealed(&fips), "fips-master");
    // The KDF comes from the blob, not from the current setting.
    assert_eq!(unsealed(&SecretStore::for_test(d.path())), "fips-master");
}

#[test]
fn default_kdf_is_scrypt() {
    let (d, _) = sealed_v2("scrypt");
    assert_eq!(fs::read(d.join("master.enc")).unwrap()[..3], [b'P', b'S', Algo::SCRYPT_ID]);
}

#[test]
fn corrupt_blobs_are_rejected() {
    let (d, store) = sealed_v2("corrupt");
    fs::write(d.join("master.enc"), [0u8; 40]).unwrap();
    assert!(store.unseal().is_err());
    fs::write(d.join("master.enc"), b"short").unwrap();
    assert!(matches!(store.unseal(), Err(SealError::Format)));
}

#[test]
fn host_key_is_required() {
    // The seal binds to the 0600 host.key, not just the world-readable
    // machine-id: without it the seal reads as not sealed AND fails to open.
    let (d, store) = sealed_v2("hostkey");
    fs::remove_file(d.join("host.key")).unwrap();
    assert!(!store.is_sealed());
    assert!(matches!(store.unseal(), Err(SealError::HostKeyMissing)));
    fs::write(d.join("host.key"), [1u8; 31]).unwrap();
    assert!(matches!(store.unseal(), Err(SealError::HostKeyCorrupt)));
    fs::write(d.join("host.key"), [1u8; 32]).unwrap();
    assert!(matches!(store.unseal(), Err(SealError::WrongHostOrCorrupt)));
}

#[test]
fn machine_id_alone_cannot_unseal() {
    // Threat model: the attacker has the blobs and the (public) machine-id,
    // but not host.key.
    let (src, _) = sealed_v2("stolen-src");
    let stolen = TestDir::new("stolen");
    for name in ["master.enc", "pin.enc", "pin.hash"] {
        fs::copy(src.join(name), stolen.join(name)).unwrap();
    }
    let thief = SecretStore::for_test(stolen.path());
    assert!(!thief.is_sealed());
    assert!(matches!(thief.unseal(), Err(SealError::HostKeyMissing)));
}

#[test]
fn errors_and_debug_output_never_contain_secrets() {
    let d = TestDir::new("leak");
    let store = SecretStore::for_test(d.path());
    let shown = format!("{:?}", store.seal("SuperSecretMaster", "123"));
    assert!(!shown.contains("SuperSecretMaster") && !shown.contains("123"));
    store.seal("SuperSecretMaster", "77553311").unwrap();
    let shown = format!("{store:?}");
    assert!(!shown.contains("SuperSecretMaster") && !shown.contains("77553311"));
    fs::write(d.join("master.enc"), b"PS\x01").unwrap();
    let err = store.unseal().unwrap_err();
    assert!(!format!("{err} {err:?}").contains("77553311"));
}

#[test]
fn a_contended_lock_refuses_to_seal_rather_than_interleave() {
    let (d, store) = sealed_v2("busy");
    let before = snapshot(d.path());
    let held = DirLock::acquire(d.path(), Duration::ZERO);
    assert!(held.held());
    let impatient = store.clone().with_lock_wait(Duration::from_millis(60));
    assert!(matches!(impatient.seal("other", "87654321"), Err(SealError::Busy)));
    assert_eq!(snapshot(d.path()), before);
    drop(held);
    impatient.seal("other", "87654321").unwrap();
    assert_eq!(unsealed(&store), "other");
}

#[test]
fn a_torn_write_is_caught_before_the_old_seal_is_replaced() {
    for victim in ["host.key", "pin.hash", "pin.enc", "master.enc"] {
        let (d, store) = sealed_v2("torn-seal");
        let before = snapshot(d.path());
        let mut flaky = store.clone();
        flaky.faults.torn_file = Some(victim);
        assert!(matches!(flaky.seal("new-master", "87654321"), Err(SealError::Verify)), "{victim}");
        assert_eq!(snapshot(d.path()), before, "{victim}");
        assert_eq!(unsealed(&store), MASTER);
    }
}

#[test]
fn a_failed_stage_leaves_the_old_seal_and_no_tmp_files() {
    let (d, store) = sealed_v2("stagefail");
    let before = snapshot(d.path());
    let read_only = store.clone().with_stage_error(io::ErrorKind::ReadOnlyFilesystem);
    assert!(matches!(read_only.seal("new-master", "87654321"), Err(SealError::Io { .. })));
    assert_eq!(snapshot(d.path()), before);
}

// --- a re-seal interrupted between its renames ---------------------------- //

#[test]
fn power_cut_before_the_first_rename_keeps_the_old_seal() {
    let (d, store) = sealed_v2("cut0");
    power_cut(|| store.clone().cut_power_after(0).seal("new-master", "87654321"));
    assert!(names(d.path()).iter().any(|n| n.ends_with(".tmp")), "really died part-way");
    assert_eq!(unsealed(&store), MASTER);
    assert!(store.verify_pin(PIN));
}

#[test]
fn power_cut_mid_reseal_is_finished_by_the_next_unseal() {
    // After the first rename the old blobs are bound to a host.key that is
    // gone; only rolling the staged files forward can recover.
    for commits in 1..=3 {
        let (d, store) = sealed_v2("cut-reseal");
        power_cut(|| store.clone().cut_power_after(commits).seal("new-master", "87654321"));
        assert!(store.is_sealed());
        assert_eq!(unsealed(&store), "new-master", "after {commits} renames");
        assert!(store.verify_pin("87654321") && !store.verify_pin(PIN), "after {commits} renames");
        assert_fully_migrated(d.path());
        assert_eq!(unsealed(&store), "new-master");
    }
}

#[test]
fn power_cut_mid_reseal_over_a_legacy_seal_does_not_mix_the_two() {
    // Without the roll-forward the legacy blobs still open, to the OLD master,
    // beside the NEW pin.hash.
    for commits in 1..=3 {
        let (d, store) = legacy("cut-legacy");
        power_cut(|| store.clone().cut_power_after(commits).seal("new-master", "87654321"));
        assert_eq!(unsealed(&store), "new-master", "after {commits} renames");
        assert!(store.verify_pin("87654321"));
        assert_fully_migrated(d.path());
    }
}

#[test]
fn an_interrupted_reseal_on_a_read_only_box_costs_no_kdf_to_look_at() {
    if rustix::process::geteuid().is_root() {
        return; // root ignores directory modes
    }
    let (d, store) = sealed_v2("cut-ro");
    power_cut(|| store.clone().cut_power_after(1).seal("new-master", "87654321"));
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let runs = counter::get();
    let got = store.unseal();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    // Cannot be repaired here, and says so honestly rather than hanging on to
    // the staged files' KDF on every boot: one failed open of pin.enc, plus
    // the legacy fallback.
    assert!(matches!(got, Err(SealError::WrongHostOrCorrupt)));
    assert_eq!(counter::get() - runs, 2);
    assert_eq!(unsealed(&store), "new-master", "writable again: finished");
}

#[test]
fn staged_junk_is_never_rolled_forward() {
    let (d, store) = sealed_v2("junk");
    let foreign = TestDir::new("junk-src");
    SecretStore::for_test(foreign.path()).seal("someone-else", "99999999").unwrap();
    // Well-formed blobs from another seal, and plain garbage.
    fs::copy(foreign.join("master.enc"), d.join("master.enc.tmp")).unwrap();
    fs::write(d.join("pin.enc.tmp"), b"junk from an earlier power cut").unwrap();
    let before = snapshot(d.path());
    assert_eq!(unsealed(&store), MASTER);
    assert_eq!(snapshot(d.path()), before);
}

// --- reading a legacy seal ------------------------------------------------ //

#[test]
fn legacy_seal_is_sealed_without_a_host_key() {
    let (d, store) = legacy("l-sealed");
    assert!(!d.join("host.key").exists());
    assert!(store.is_sealed());
    fs::remove_file(d.join("pin.enc")).unwrap();
    assert!(!store.is_sealed());
}

#[test]
fn legacy_seal_unseals() {
    let (_d, store) = legacy("l-unseal");
    assert_eq!(unsealed(&store), MASTER);
}

#[test]
fn legacy_seal_on_the_wrong_machine_fails_and_changes_nothing() {
    let (d, store) = legacy("l-wrong");
    let before = snapshot(d.path());
    assert!(store.with_machine_id("host-B").unseal().is_err());
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn legacy_salt_that_looks_like_a_v2_header_still_unseals() {
    // About 1 legacy blob in 8 million opens with the v2 magic and a valid
    // ALGO byte. That box must not be locked out.
    let d = TestDir::new("l-collide");
    let mut salt = [7u8; 16];
    salt[..3].copy_from_slice(&[b'P', b'S', Algo::SCRYPT_ID]);
    write_legacy_seal(d.path(), PIN, Some(salt));
    let store = SecretStore::for_test(d.path());
    assert!(!store.is_sealed(), "indistinguishable from a v2 seal missing its key until opened");
    assert_eq!(unsealed(&store), MASTER);
    assert_fully_migrated(d.path());
}

// --- migrating ------------------------------------------------------------ //

#[test]
fn unseal_migrates_with_the_same_pin_and_no_prompt() {
    let (d, store) = legacy("m-basic");
    let pin_hash = fs::read(d.join("pin.hash")).unwrap();
    assert_eq!(unsealed(&store), MASTER);
    assert_fully_migrated(d.path());
    for name in SEAL_FILES {
        assert_eq!(mode(&d.join(name)), 0o600, "{name}");
    }
    assert_eq!(fs::read(d.join("pin.hash")).unwrap(), pin_hash);
    assert!(store.verify_pin(PIN));
    assert!(store.is_sealed());
    assert_eq!(unsealed(&store), MASTER, "and reads back as a plain v2 seal");
}

#[test]
fn migration_closes_the_machine_id_only_hole() {
    let (d, store) = legacy("m-hole");
    store.unseal().unwrap();
    fs::remove_file(d.join("host.key")).unwrap();
    assert!(!store.is_sealed());
    assert!(matches!(store.unseal(), Err(SealError::HostKeyMissing)));
}

#[test]
fn migrated_blobs_use_the_configured_kdf() {
    let (d, store) = legacy("m-kdf");
    store.unseal().unwrap();
    assert_eq!(fs::read(d.join("master.enc")).unwrap()[2], Algo::SCRYPT_ID);

    let (d, store) = legacy("m-fips");
    let fips = store.with_fips_kdf(true);
    assert_eq!(unsealed(&fips), MASTER);
    assert_eq!(fs::read(d.join("pin.enc")).unwrap()[2], Algo::PBKDF2_ID);
    assert_eq!(fs::read(d.join("master.enc")).unwrap()[2], Algo::PBKDF2_ID);
    assert_eq!(unsealed(&fips), MASTER);
}

#[test]
fn pin_below_the_new_floor_still_migrates() {
    // Earlier releases generated 4-digit PINs; seal() now refuses those. A box
    // already using one must migrate anyway, keeping its PIN.
    let d = TestDir::new("m-shortpin");
    write_legacy_seal(d.path(), "1234", None);
    let store = SecretStore::for_test(d.path());
    assert_eq!(unsealed(&store), MASTER);
    assert_fully_migrated(d.path());
    assert!(store.verify_pin("1234"));
    assert_eq!(unsealed(&store), MASTER);
}

#[test]
fn migration_keeps_who_can_read_the_seal_but_no_extra_bits() {
    // Whichever of the wall or the root VPN supervisor migrates, the seal's
    // readers must not change, or one would lock the other out.
    let (d, store) = legacy("m-mode");
    fs::set_permissions(d.join("master.enc"), fs::Permissions::from_mode(0o640)).unwrap();
    store.unseal().unwrap();
    for name in ["host.key", "pin.enc", "master.enc"] {
        assert_eq!(mode(&d.join(name)), 0o640, "{name}");
    }

    let (d, store) = legacy("m-mode-x");
    fs::set_permissions(d.join("master.enc"), fs::Permissions::from_mode(0o775)).unwrap();
    store.unseal().unwrap();
    assert_eq!(mode(&d.join("host.key")), 0o644, "no write/execute bits copied onto a key");
}

#[test]
fn stale_tmp_files_are_ignored_and_swept() {
    let (d, store) = legacy("m-stale");
    for name in ["host.key.tmp", "pin.enc.tmp", "pin.hash.tmp", "master.enc.tmp"] {
        fs::write(d.join(name), b"junk from an earlier power cut").unwrap();
    }
    assert_eq!(unsealed(&store), MASTER);
    assert_fully_migrated(d.path());
}

#[test]
fn seal_over_a_legacy_seal_replaces_it() {
    let (d, store) = legacy("m-reseal");
    store.seal("new-master", "87654321").unwrap();
    assert_fully_migrated(d.path());
    assert_eq!(unsealed(&store), "new-master");
    assert!(store.verify_pin("87654321"));
}

// --- a crash mid-migration must leave a state that still unseals ----------- //

#[test]
fn power_cut_mid_migration_still_unseals() {
    for (commits, pin_is_v2) in [(0, false), (1, false), (2, true)] {
        let (d, store) = legacy("m-cut");
        power_cut(|| store.clone().cut_power_after(commits).unseal());
        assert_eq!(is_v2(d.path(), "pin.enc"), pin_is_v2, "after {commits} renames");
        assert!(!is_v2(d.path(), "master.enc"), "the sentinel goes last");
        assert!(store.is_sealed());
        assert!(store.verify_pin(PIN));
        assert_eq!(unsealed(&store), MASTER, "still boots, and resumes");
        assert_fully_migrated(d.path());
        assert_eq!(unsealed(&store), MASTER);
    }
}

#[test]
fn resume_reuses_the_host_key_a_v2_blob_may_depend_on() {
    let (d, store) = legacy("m-resume");
    power_cut(|| store.clone().cut_power_after(2).unseal());
    let key = fs::read(d.join("host.key")).unwrap();
    assert_eq!(unsealed(&store), MASTER);
    assert_eq!(fs::read(d.join("host.key")).unwrap(), key);
}

#[test]
fn repeated_power_cuts_never_lock_the_box_out() {
    let (d, store) = legacy("m-cuts");
    for commits in [2, 1, 0, 1] {
        let _ = catch_unwind(AssertUnwindSafe(|| store.clone().cut_power_after(commits).unseal()));
        assert!(store.is_sealed());
    }
    assert_eq!(unsealed(&store), MASTER);
    assert_fully_migrated(d.path());
}

// --- concurrent boots: the wall and the VPN supervisor race for the seal ---- //

#[test]
fn concurrent_unseals_migrate_exactly_one_consistent_seal() {
    let (d, store) = legacy("m-race");
    let got: Vec<String> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4).map(|_| scope.spawn(|| unsealed(&store))).collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    assert_eq!(got, [MASTER; 4]);
    assert_fully_migrated(d.path());
    assert_eq!(unsealed(&store), MASTER);
}

#[test]
fn blocked_by_a_peer_still_unseals_and_defers_migration() {
    let (d, store) = legacy("m-blocked");
    let peer = DirLock::acquire(d.path(), Duration::ZERO);
    assert!(peer.held());
    assert_eq!(unsealed(&store.clone().with_lock_wait(Duration::from_millis(60))), MASTER);
    assert!(!d.join("host.key").exists());
    drop(peer);
    assert_eq!(unsealed(&store), MASTER, "the peer went away: migrate now");
    assert_fully_migrated(d.path());
}

// --- a directory that cannot be written still unseals, with only a warning -- //

#[test]
fn unwritable_dir_returns_the_master_without_paying_for_a_migration() {
    if rustix::process::geteuid().is_root() {
        return; // root ignores directory modes
    }
    let (d, store) = legacy("m-ro");
    let before = snapshot(d.path());
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let kdf_runs = counter::get();
    let got = store.unseal();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(got.unwrap().as_str(), MASTER);
    assert_eq!(snapshot(d.path()), before);
    // A read-only box re-enters this in every process: only the two legacy
    // derivations, never the migration's four.
    assert_eq!(counter::get() - kdf_runs, 2);
}

#[test]
fn files_that_cannot_be_staged_cost_no_kdf_and_change_nothing() {
    // Read-only filesystem, or an owner this process may not give files to.
    for kind in [io::ErrorKind::ReadOnlyFilesystem, io::ErrorKind::PermissionDenied] {
        let (d, store) = legacy("m-nostage");
        let before = snapshot(d.path());
        let blocked = store.with_stage_error(kind);
        let kdf_runs = counter::get();
        assert_eq!(unsealed(&blocked), MASTER);
        assert_eq!(counter::get() - kdf_runs, 2, "refused before any migration KDF");
        assert_eq!(snapshot(d.path()), before);
    }
}

#[test]
fn a_failed_migration_is_not_retried_by_the_same_process() {
    let (d, store) = legacy("m-skip");
    let blocked = store.clone().with_stage_error(io::ErrorKind::ReadOnlyFilesystem);
    assert_eq!(unsealed(&blocked), MASTER);
    // The obstacle is gone, but this process has given up on that directory.
    assert_eq!(unsealed(&store), MASTER);
    assert!(!d.join("host.key").exists());
    skip_set().remove(d.path()); // as a restart would
    assert_eq!(unsealed(&store), MASTER);
    assert_fully_migrated(d.path());
}

#[test]
fn commit_failure_returns_the_master_and_stays_unsealable() {
    let (d, store) = legacy("m-enospc");
    let mut full = store.clone();
    full.faults.before_rename = Some(Arc::new(|_| Err(io::Error::from(io::ErrorKind::StorageFull))));
    assert_eq!(unsealed(&full), MASTER);
    assert!(!names(d.path()).iter().any(|n| n.ends_with(".tmp")));
    skip_set().remove(d.path());
    assert_eq!(unsealed(&store), MASTER);
    assert_fully_migrated(d.path());
}

#[test]
fn staged_file_torn_on_the_card_is_never_committed() {
    // The legacy blobs are the only copy until the commit: a bad write has to
    // be caught while they still exist.
    for victim in ["host.key", "pin.enc", "master.enc"] {
        let (d, store) = legacy("m-torn");
        let before = snapshot(d.path());
        let mut flaky = store.clone();
        flaky.faults.torn_file = Some(victim);
        assert_eq!(unsealed(&flaky), MASTER, "{victim}");
        assert_eq!(snapshot(d.path()), before, "{victim}");
    }
}

#[test]
fn unreadable_seal_is_a_typed_error() {
    if rustix::process::geteuid().is_root() {
        return; // root ignores file modes
    }
    // e.g. sealed as root, unsealed as the kiosk user.
    let (d, store) = legacy("m-unreadable");
    fs::set_permissions(d.join("master.enc"), fs::Permissions::from_mode(0o000)).unwrap();
    assert!(matches!(store.unseal(), Err(SealError::Io { .. })));
}

#[test]
fn oversized_files_are_refused_not_truncated() {
    let (d, store) = sealed_v2("big");
    let mut key = fs::read(d.join("host.key")).unwrap();
    key.resize(MAX_SEAL_FILE + 1, 0);
    fs::write(d.join("host.key"), key).unwrap();
    assert!(matches!(store.unseal(), Err(SealError::Io { .. })));
}

#[test]
fn a_longer_host_key_is_used_whole() {
    // Only the first 32 bytes are ever written, but the Python release keyed
    // the seal with whatever the file held; so must we.
    let (d, store) = sealed_v2("longkey");
    let mut key = fs::read(d.join("host.key")).unwrap();
    key.push(b'\n');
    fs::write(d.join("host.key"), key).unwrap();
    assert!(matches!(store.unseal(), Err(SealError::WrongHostOrCorrupt)));
}

// --- the session ticket that keeps repeat unseals cheap -------------------- //

fn ticketed_v2(label: &str) -> (TestDir, TestDir, SecretStore) {
    let d = TestDir::new(label);
    let run = TestDir::new("run");
    let store = SecretStore::for_test(d.path()).with_test_ticket(run.path());
    store.seal(MASTER, PIN).unwrap();
    (d, run, store)
}

/// KDF runs spent by one unseal.
fn kdf_cost(store: &SecretStore) -> usize {
    let before = counter::get();
    assert_eq!(unsealed(store), MASTER);
    counter::get() - before
}

#[test]
fn repeat_unseal_runs_no_kdf() {
    let (_d, _run, store) = ticketed_v2("t-repeat");
    assert_eq!(kdf_cost(&store), 2);
    for _ in 0..5 {
        assert_eq!(kdf_cost(&store), 0);
    }
}

#[test]
fn ticket_is_private_and_holds_no_plaintext() {
    let (_d, run, store) = ticketed_v2("t-private");
    store.unseal().unwrap();
    let path = run.join(ticket::FILE);
    assert_eq!(mode(&path), 0o600);
    let raw = fs::read(path).unwrap();
    assert!(!raw.windows(MASTER.len()).any(|w| w == MASTER.as_bytes()));
    assert!(!raw.windows(PIN.len()).any(|w| w == PIN.as_bytes()));
}

#[test]
fn migration_leaves_a_ticket_too() {
    let d = TestDir::new("t-migrate");
    let run = TestDir::new("run");
    write_legacy_seal(d.path(), PIN, None);
    let store = SecretStore::for_test(d.path()).with_test_ticket(run.path());
    assert_eq!(kdf_cost(&store), 6, "2 legacy opens, 2 new blobs, 2 proofs");
    assert_eq!(kdf_cost(&store), 0);
}

#[test]
fn unmigrated_legacy_seal_writes_no_ticket() {
    let d = TestDir::new("t-legacy");
    let run = TestDir::new("run");
    write_legacy_seal(d.path(), PIN, None);
    let store = SecretStore::for_test(d.path()).with_test_ticket(run.path()).with_lock_wait(Duration::ZERO);
    let _peer = DirLock::acquire(d.path(), Duration::ZERO);
    assert_eq!(unsealed(&store), MASTER);
    assert!(!run.join(ticket::FILE).exists());
}

#[test]
fn reseal_invalidates_the_ticket() {
    let (_d, run, store) = ticketed_v2("t-reseal");
    store.unseal().unwrap();
    store.seal("rotated-master", "87654321").unwrap();
    assert!(!run.join(ticket::FILE).exists());
    assert_eq!(unsealed(&store), "rotated-master");
}

#[test]
fn reseal_by_another_user_invalidates_the_ticket() {
    // Another uid's re-seal cannot unlink this uid's ticket; the binding to
    // the sealed bytes has to do it.
    let (d, run, store) = ticketed_v2("t-foreign");
    store.unseal().unwrap();
    SecretStore::for_test(d.path()).seal("rotated-master", "87654321").unwrap();
    assert!(run.join(ticket::FILE).exists());
    assert_eq!(unsealed(&store), "rotated-master");
}

#[test]
fn ticket_does_not_outlive_host_key_or_survive_a_corrupted_seal() {
    let (d, _run, store) = ticketed_v2("t-key");
    store.unseal().unwrap();
    fs::remove_file(d.join("host.key")).unwrap();
    assert!(matches!(store.unseal(), Err(SealError::HostKeyMissing)));

    let (d, _run, store) = ticketed_v2("t-corrupt");
    store.unseal().unwrap();
    let mut blob = fs::read(d.join("master.enc")).unwrap();
    blob.push(0);
    fs::write(d.join("master.enc"), blob).unwrap();
    assert!(store.unseal().is_err());
}

#[test]
fn ticket_does_not_cross_machines() {
    let (_d, _run, store) = ticketed_v2("t-machine");
    store.unseal().unwrap();
    assert!(store.with_machine_id("host-B").unseal().is_err());
}

#[test]
fn ticket_does_not_survive_a_reboot() {
    let (_d, _run, mut store) = ticketed_v2("t-boot");
    store.unseal().unwrap();
    store.ticket_cfg().boot_id = Some(b"another-boot".to_vec());
    assert_eq!(kdf_cost(&store), 2);
}

#[test]
fn expired_ticket_is_a_miss() {
    let (_d, _run, mut store) = ticketed_v2("t-expired");
    store.unseal().unwrap();
    store.ticket_cfg().clock_advance = ticket::DEFAULT_TTL + 1;
    assert_eq!(kdf_cost(&store), 2);
}

#[test]
fn damaged_ticket_falls_back_to_the_seal() {
    for garbage in [&b""[..], b"short", &[0xff; 64]] {
        let (_d, run, store) = ticketed_v2("t-damaged");
        store.unseal().unwrap();
        fs::write(run.join(ticket::FILE), garbage).unwrap();
        assert_eq!(kdf_cost(&store), 2);
        assert_eq!(kdf_cost(&store), 0, "and a good one is written back");
    }
}

#[test]
fn tampered_expiry_is_rejected() {
    let (_d, run, store) = ticketed_v2("t-tamper");
    store.unseal().unwrap();
    let path = run.join(ticket::FILE);
    let mut raw = fs::read(&path).unwrap();
    // Still inside the window, so only authentication can reject it.
    let later = u64::from_be_bytes(raw[..8].try_into().unwrap()) - 60;
    raw[..8].copy_from_slice(&later.to_be_bytes());
    fs::write(&path, raw).unwrap();
    assert_eq!(kdf_cost(&store), 2);
}

#[test]
fn ttl_zero_disables_the_ticket() {
    let d = TestDir::new("t-off");
    let store = SecretStore::for_test(d.path()).with_ticket_cache(0, Some(d.join("run")));
    assert!(store.ticket.is_none());
    store.seal(MASTER, PIN).unwrap();
    assert_eq!(kdf_cost(&store), 2);
    assert_eq!(kdf_cost(&store), 2);
}

#[test]
fn an_unusable_runtime_dir_still_unseals() {
    let (_d, run, store) = ticketed_v2("t-nodir");
    fs::set_permissions(run.path(), fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(unsealed(&store), MASTER);
    fs::set_permissions(run.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(kdf_cost(&store), 2, "a group-readable directory is not used");
    assert!(!run.join(ticket::FILE).exists());
}

#[test]
fn real_runtime_dir_is_used_only_when_it_is_tmpfs() {
    // The production path, with no test bypass: a ticket appears only if the
    // directory really is RAM-backed.
    let d = TestDir::new("t-real");
    let run = TestDir::new("run-real");
    let store = SecretStore::for_test(d.path()).with_ticket_cache(60, Some(run.path().to_path_buf()));
    store.seal(MASTER, PIN).unwrap();
    assert_eq!(unsealed(&store), MASTER);
    let on_ram = RuntimeDir::open(run.path(), true).is_some();
    // A ticket in /run/user/<uid> (the fallback) is fine too; one in a disk
    // directory never is.
    if !on_ram {
        assert!(!run.join(ticket::FILE).exists());
    }
    if let Some(rd) = RuntimeDir::locate(Some(run.path())) {
        rd.discard();
    }
}

#[test]
fn keyring_is_tried_first_and_the_sealed_files_are_the_fallback() {
    use crate::secret_tool::testutil::fake_secret_tool;
    let (_d, store) = sealed_v2("keyring");
    let tools = TestDir::new("keyring-tool");
    let keyring = Keyring::new(SecretTool::at(fake_secret_tool(tools.path())));
    let store = store.with_keyring(Some(keyring));
    assert_eq!(unsealed(&store), MASTER, "no entry: sealed files");
    fs::write(tools.join("value"), "from-the-keyring").unwrap();
    assert_eq!(unsealed(&store), "from-the-keyring");
    assert_eq!(store.unseal_sealed().unwrap().as_str(), MASTER);
    let broken = store.with_keyring(Some(Keyring::new(SecretTool::absent())));
    assert_eq!(unsealed(&broken), MASTER);
}

// --- compatibility with the Python release's session ticket ---------------- //

#[test]
fn python_written_ticket_opens_and_is_bound_like_ours() {
    // tests/fixtures/ticket was written by host/secretstore.py for the
    // v2-scrypt fixture, with the boot id and clock pinned (see generate.py).
    // No KDF is involved: the ticket key comes straight from host.key.
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let read = |name: &str| fs::read(fixtures.join(name)).unwrap();
    let (host_key, pin_blob, master_blob) =
        (read("v2-scrypt/host.key"), read("v2-scrypt/pin.enc"), read("v2-scrypt/master.enc"));
    let raw = read("ticket/soc-unseal.ticket");
    let binding = |boot_id: &'static [u8]| ticket::Binding {
        host_key: &host_key,
        machine_id: b"fixture-host-0001",
        boot_id,
        pin_blob: &pin_blob,
        master_blob: &master_blob,
    };
    let now = 2_000_000_000;
    let before = counter::get();
    let master = ticket::unwrap(&binding(b"fixture-boot-id"), &raw, now, ticket::DEFAULT_TTL).unwrap();
    assert_eq!(std::str::from_utf8(&master).unwrap(), "Fixture-Master ✓ not-a-real-secret");
    assert_eq!(counter::get(), before);
    assert_eq!(u64::from_be_bytes(raw[..8].try_into().unwrap()), now + ticket::DEFAULT_TTL);
    assert!(ticket::unwrap(&binding(b"another-boot"), &raw, now, ticket::DEFAULT_TTL).is_none());
    assert!(
        ticket::unwrap(&binding(b"fixture-boot-id"), &raw, now + ticket::DEFAULT_TTL, ticket::DEFAULT_TTL).is_none()
    );
}
