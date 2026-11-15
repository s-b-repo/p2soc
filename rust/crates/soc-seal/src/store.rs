//! Host-bound, PIN-sealed storage for the vault master password.
//!
//! There is no plaintext master password on disk. It is sealed with
//! AES-256-GCM under a key derived from THREE factors:
//!
//!   1. a 256-bit random *host key* (`host.key`, 0600),
//!   2. this host's machine-id, and
//!   3. a one-time PIN that setup generates and shows the operator once.
//!
//! So the wall can boot unattended, the PIN is itself sealed under a key
//! derived from (host key + machine-id). Net effect:
//!
//!   * nothing on disk is the plaintext master password;
//!   * the seal's strength does not rest on the machine-id, which is
//!     world-readable — the binding secret is `host.key`;
//!   * the sealed files are useless if copied to another machine, or copied
//!     without `host.key` (key derivation changes, GCM authentication fails);
//!   * the PIN is needed to re-seal and to authorise destructive setup steps.
//!
//! Files (directory 0700, files 0600):
//!
//! ```text
//! host.key     32 random bytes — the per-host binding secret
//! master.enc   v2 blob, key = KDF(context | host_key | machine_id | pin)
//! pin.enc      v2 blob, key = KDF(context | host_key | machine_id)
//! pin.hash     "<salt_hex>$<sha256(salt | pin)>" — lets setup verify the PIN
//! ```
//!
//! Earlier releases wrote legacy blobs keyed by the machine-id alone, with no
//! `host.key`. [`SecretStore::unseal`] still reads those and migrates them in
//! place — same PIN, no prompt. If the directory cannot be written the master
//! is still returned and the box stays on the legacy format until it can be.

use crate::blob;
use crate::error::{Result, SealError};
use crate::fsio::{self, DirLock, LockState, MAX_SEAL_FILE, Owner};
use crate::kdf::{Algo, Cost};
use crate::log;
use crate::machine;
use crate::pin::{self, MIN_PIN_LEN};
use crate::rng;
use crate::secret_tool::{Keyring, SecretTool};
use crate::ticket::{self, RuntimeDir};
use ctutils::CtEq;
use rustix::fs::Access;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Where the seal lives unless `$SOC_SECRET_DIR` says otherwise.
pub const DEFAULT_SECRET_DIR: &str = "/etc/soc-display/secret";

const HOST_KEY_FILE: &str = "host.key";
const PIN_HASH_FILE: &str = "pin.hash";
const PIN_FILE: &str = "pin.enc";
const MASTER_FILE: &str = "master.enc";
const HOST_KEY_LEN: usize = 32;

/// Commit order matters: `host.key` is needed to *derive* the seal, and
/// `master.enc` is the [`SecretStore::is_sealed`] sentinel — so `host.key` is
/// committed first and `master.enc` last.
const SEAL_FILES: [&str; 4] = [HOST_KEY_FILE, PIN_HASH_FILE, PIN_FILE, MASTER_FILE];
const CORE_SEAL_FILES: [&str; 3] = [PIN_HASH_FILE, PIN_FILE, MASTER_FILE];

/// Domain-separation label (NIST SP 800-108 "context"), bound into the KDF
/// input so this seal's keys can never collide with any other use of the same
/// inputs. The version suffix lets the format evolve without ambiguity.
const KDF_CONTEXT: &[u8] = b"p2soc-seal/v2";

/// How long to wait for another process holding the seal lock. Long enough
/// for a concurrent unseal or migration on a loaded Pi; on expiry a reader
/// carries on unlocked, so a stuck peer can never block a boot.
const LOCK_WAIT: Duration = Duration::from_secs(20);

/// Secret dirs this process already failed to migrate: a migration costs four
/// 128 MiB KDF runs, so a box that cannot complete it must not pay again on
/// every unseal. Cleared by a restart, which is when whatever blocked it may
/// have been fixed.
static MIGRATION_SKIP: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

fn skip_set() -> std::sync::MutexGuard<'static, BTreeSet<PathBuf>> {
    MIGRATION_SKIP.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
type RenameHook = std::sync::Arc<dyn Fn(&str) -> io::Result<()> + Send + Sync>;

/// Fault-injection seams. Inert outside the unit tests.
#[derive(Clone, Default)]
struct Faults {
    #[cfg(test)]
    before_rename: Option<RenameHook>,
    #[cfg(test)]
    stage_error: Option<io::ErrorKind>,
    #[cfg(test)]
    torn_file: Option<&'static str>,
}

impl Faults {
    fn before_rename(
        &self,
        _name: &str, // read only by the cfg(test) fault hook
    ) -> io::Result<()> {
        #[cfg(test)]
        if let Some(hook) = &self.before_rename {
            return hook(_name);
        }
        Ok(())
    }

    fn before_stage(&self) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self.stage_error {
            return Err(io::Error::new(kind, "injected staging failure"));
        }
        Ok(())
    }

    /// What reaches the card for `name`: the data, unless a test tears it.
    fn landing<'a>(&self, _name: &str, data: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        #[cfg(test)]
        if self.torn_file == Some(_name) {
            let mut torn = data.to_vec();
            if let Some(last) = torn.last_mut() {
                *last ^= 0xff;
            }
            return std::borrow::Cow::Owned(torn);
        }
        std::borrow::Cow::Borrowed(data)
    }
}

#[derive(Clone, Debug)]
struct TicketCfg {
    ttl: u64,
    xdg_runtime_dir: Option<PathBuf>,
    /// A directory to use without the tmpfs requirement, and stand-ins for the
    /// boot id and the clock: test builds only.
    #[cfg(test)]
    trusted_dir: Option<PathBuf>,
    #[cfg(test)]
    boot_id: Option<Vec<u8>>,
    #[cfg(test)]
    clock_advance: u64,
}

impl TicketCfg {
    fn new(ttl: u64, xdg_runtime_dir: Option<PathBuf>) -> TicketCfg {
        TicketCfg {
            ttl,
            xdg_runtime_dir,
            #[cfg(test)]
            trusted_dir: None,
            #[cfg(test)]
            boot_id: None,
            #[cfg(test)]
            clock_advance: 0,
        }
    }

    fn runtime_dir(&self) -> Option<RuntimeDir> {
        #[cfg(test)]
        if let Some(dir) = &self.trusted_dir {
            return RuntimeDir::open(dir, false);
        }
        RuntimeDir::locate(self.xdg_runtime_dir.as_deref())
    }

    fn boot_id(&self) -> Option<Vec<u8>> {
        #[cfg(test)]
        if let Some(id) = &self.boot_id {
            return Some(id.clone());
        }
        ticket::boot_id()
    }

    fn now(&self) -> u64 {
        #[cfg(test)]
        return ticket::now() + self.clock_advance;
        #[cfg(not(test))]
        ticket::now()
    }
}

/// What a completed migration left on disk (for the session ticket).
struct Migrated {
    host_key: Zeroizing<Vec<u8>>,
    pin_blob: Vec<u8>,
    master_blob: Vec<u8>,
}

/// One secret directory and how to treat it.
///
/// [`SecretStore::new`] reads nothing from the environment (tests, and callers
/// that want explicit control); [`SecretStore::from_env`] applies the
/// operator's `SOC_*` settings.
#[derive(Clone)]
pub struct SecretStore {
    dir: PathBuf,
    machine_id: Option<String>,
    fips_kdf: bool,
    keyring: Option<Keyring>,
    ticket: Option<TicketCfg>,
    lock_wait: Duration,
    cost: Cost,
    faults: Faults,
}

impl std::fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStore")
            .field("dir", &self.dir)
            .field("machine_id_override", &self.machine_id.is_some())
            .field("fips_kdf", &self.fips_kdf)
            .field("keyring", &self.keyring.is_some())
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

fn concat(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    // Sized up front: key material must not be left behind by a reallocation.
    let mut out = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// The non-PIN key material: context label, host key (the real secret) and
/// machine-id (binds the seal to this physical host; not trusted for secrecy).
fn binding_material(host_key: &[u8], machine_id: &[u8]) -> Zeroizing<Vec<u8>> {
    concat(&[KDF_CONTEXT, b"\0", host_key, b"\0", machine_id])
}

fn with_pin(binding: &[u8], pin: &[u8]) -> Zeroizing<Vec<u8>> {
    concat(&[binding, b"\0", pin])
}

fn into_text(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(not_text) => {
            not_text.into_bytes().zeroize();
            Err(SealError::NotText)
        }
    }
}

impl SecretStore {
    /// A store over `dir` with the defaults and nothing taken from the
    /// environment: scrypt KDF, this host's real machine-id, no session
    /// ticket, no keyring.
    pub fn new(dir: impl Into<PathBuf>) -> SecretStore {
        SecretStore {
            dir: dir.into(),
            machine_id: None,
            fips_kdf: false,
            keyring: None,
            ticket: None,
            lock_wait: LOCK_WAIT,
            cost: Cost::PRODUCTION,
            faults: Faults::default(),
        }
    }

    /// The store the operator configured: `$SOC_SECRET_DIR`,
    /// `$SOC_MACHINE_ID`, `SOC_FIPS_KDF=1`, `$SOC_UNSEAL_CACHE_TTL`
    /// (+ `$XDG_RUNTIME_DIR`) and `SOC_SECRET_BACKEND=libsecret`.
    pub fn from_env() -> SecretStore {
        SecretStore::from_env_in(None)
    }

    /// [`SecretStore::from_env`] with an explicit directory taking precedence
    /// over `$SOC_SECRET_DIR` (the seal helper's `--dir`).
    pub fn from_env_in(dir: Option<PathBuf>) -> SecretStore {
        let dir = dir
            .filter(|d| !d.as_os_str().is_empty())
            .or_else(|| std::env::var_os("SOC_SECRET_DIR").filter(|d| !d.is_empty()).map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SECRET_DIR));
        let ttl = soc_core::env::env_int(
            "SOC_UNSEAL_CACHE_TTL",
            i64::try_from(ticket::DEFAULT_TTL).unwrap_or(i64::MAX),
            Some(0),
            None,
        );
        let mut store = SecretStore::new(dir)
            .with_fips_kdf(std::env::var_os("SOC_FIPS_KDF").is_some_and(|v| v == "1"))
            .with_ticket_cache(u64::try_from(ttl).unwrap_or(0), std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from));
        store.machine_id = soc_core::env::env_str("SOC_MACHINE_ID");
        if std::env::var_os("SOC_SECRET_BACKEND").is_some_and(|v| v == "libsecret") {
            store.keyring = Some(Keyring::new(SecretTool::locate()));
        }
        store
    }

    /// Use `id` instead of this host's machine-id (simulating another host).
    pub fn with_machine_id(mut self, id: impl Into<String>) -> SecretStore {
        self.machine_id = Some(id.into());
        self
    }

    /// Seal new blobs with PBKDF2-HMAC-SHA256 (FIPS 140) instead of scrypt.
    /// Existing blobs always open with the KDF recorded in them.
    pub fn with_fips_kdf(mut self, on: bool) -> SecretStore {
        self.fips_kdf = on;
        self
    }

    /// Serve repeat unseals from a tmpfs session ticket for `ttl_secs`
    /// (0 disables). `xdg_runtime_dir` is the first place tried for it.
    pub fn with_ticket_cache(mut self, ttl_secs: u64, xdg_runtime_dir: Option<PathBuf>) -> SecretStore {
        self.ticket = (ttl_secs > 0).then(|| TicketCfg::new(ttl_secs, xdg_runtime_dir));
        self
    }

    /// Try the login keyring before the sealed files (see [`Keyring`]).
    pub fn with_keyring(mut self, keyring: Option<Keyring>) -> SecretStore {
        self.keyring = keyring;
        self
    }

    /// How long to wait for another process holding the seal lock.
    pub fn with_lock_wait(mut self, wait: Duration) -> SecretStore {
        self.lock_wait = wait;
        self
    }

    /// The secret directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn machine_id(&self) -> Result<Vec<u8>> {
        machine::machine_id(self.machine_id.as_deref())
    }

    fn active_algo(&self) -> Algo {
        if self.fips_kdf { Algo::Pbkdf2 } else { Algo::Scrypt }
    }

    fn read(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.path(name);
        match fsio::read_bounded(&path, MAX_SEAL_FILE) {
            Ok(data) => Ok(data),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(SealError::NotSealed(path)),
            // e.g. sealed as root but unsealing as the kiosk user.
            Err(source) => Err(SealError::Io { path, source }),
        }
    }

    /// Read the per-host binding secret. Its absence is fatal for a v2 seal:
    /// without it the key cannot be derived, which is the whole point.
    fn read_host_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let key = self.read(HOST_KEY_FILE).map_err(|e| match e {
            SealError::NotSealed(_) => SealError::HostKeyMissing,
            other => other,
        })?;
        if key.len() < HOST_KEY_LEN {
            return Err(SealError::HostKeyCorrupt);
        }
        Ok(key)
    }

    /// True only when a *complete* seal is present. Requiring every file (not
    /// just `master.enc`) means a half-written seal reads as "not sealed", so
    /// the operator re-seals instead of booting into an unrecoverable state.
    ///
    /// `host.key` is required only by v2 blobs: a v2 seal copied without it
    /// reads as not sealed, while a legacy seal, which never had one, stays
    /// sealed.
    pub fn is_sealed(&self) -> bool {
        if !CORE_SEAL_FILES.iter().all(|f| self.path(f).exists()) {
            return false;
        }
        if self.path(HOST_KEY_FILE).exists() {
            return true;
        }
        ![PIN_FILE, MASTER_FILE].iter().any(|f| self.read(f).is_ok_and(|b| blob::is_v2(&b)))
    }

    /// True if `pin` matches the sealed PIN (constant-time, via `pin.hash`).
    pub fn verify_pin(&self, pin: &str) -> bool {
        self.read(PIN_HASH_FILE).is_ok_and(|line| pin::matches_hash_line(&line, pin.as_bytes()))
    }

    /// Create the secret directory private from the start, without changing
    /// the mode of any parent it has to create.
    fn ensure_dir(&self) -> Result<()> {
        let io_err = |source| SealError::Io { path: self.dir.clone(), source };
        if let Some(parent) = self.dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(io_err)?;
        }
        match fs::DirBuilder::new().mode(0o700).create(&self.dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && self.dir.is_dir() => {}
            Err(e) => return Err(io_err(e)),
        }
        if let Err(e) = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)) {
            log::warn(format_args!("cannot make {} private (0700): {e}", self.dir.display()));
        }
        Ok(())
    }

    /// Who new seal files should belong to: root writing into a directory it
    /// does not own (first-run setup under sudo, the pkexec seal helper, into
    /// the kiosk-owned secret dir) must not leave files the wall cannot read.
    fn dir_owner(&self) -> Result<Option<Owner>> {
        if !rustix::process::geteuid().is_root() {
            return Ok(None);
        }
        let meta = fs::metadata(&self.dir).map_err(|source| SealError::Io { path: self.dir.clone(), source })?;
        Ok(Some(Owner::of(&meta)))
    }

    /// Prove a blob opens — with a key derived afresh, so a KDF that did not
    /// reproduce (bad RAM on the Pi) is caught while the old seal still exists.
    fn verify_opens(&self, material: &[u8], sealed: &[u8], plaintext: &[u8]) -> Result<()> {
        let opened = blob::open(material, sealed, self.cost).map_err(|_| SealError::Verify)?; // audit-allow: any open failure is "verify failed"; crypto detail is deliberately not surfaced
        if opened.len() == plaintext.len() && bool::from(opened.as_slice().ct_eq(plaintext)) {
            Ok(())
        } else {
            Err(SealError::Verify)
        }
    }

    /// Stage every file, check what actually landed on the card, then rename
    /// them into place in order. Returns how many renames happened when the
    /// commit itself failed part-way.
    fn stage_and_commit(
        &self,
        files: &[(&str, &[u8])],
        owner: Option<Owner>,
        mode: u32,
    ) -> std::result::Result<(), (usize, SealError)> {
        let names: Vec<&str> = files.iter().map(|(name, _)| *name).collect();
        let staged = (|| {
            for (name, data) in files {
                let path = self.path(name);
                self.faults
                    .before_stage()
                    .and_then(|()| fsio::stage(&path, &self.faults.landing(name, data), owner, mode))
                    .map_err(|source| SealError::Io { path, source })?;
            }
            for (name, data) in files {
                let tmp = fsio::tmp_path(&self.path(name));
                let landed =
                    fsio::read_bounded(&tmp, MAX_SEAL_FILE).map_err(|source| SealError::Io { path: tmp, source })?;
                if landed.len() != data.len() || !bool::from(landed.as_slice().ct_eq(data)) {
                    return Err(SealError::Verify);
                }
            }
            Ok(())
        })();
        if let Err(e) = staged {
            fsio::discard_tmp(&self.dir, &names);
            return Err((0, e));
        }
        fsio::commit(&self.dir, &names, &|name| self.faults.before_rename(name))
            .map_err(|(done, source)| (done, SealError::Io { path: self.path(names[done]), source }))
    }

    /// Seal the master password and PIN under this host, replacing any prior
    /// seal with a fresh `host.key`.
    ///
    /// The new blobs are proven to open before anything on disk is touched,
    /// every file is staged (`*.tmp`, fsync'd) and read back, and only then
    /// renamed into place with `master.enc` — the [`SecretStore::is_sealed`]
    /// sentinel — last. An interrupted first seal therefore reads as "not
    /// sealed", and an interrupted re-seal is finished by the next unseal
    /// (see `finish_interrupted_seal`).
    pub fn seal(&self, master: &str, pin: &str) -> Result<()> {
        if master.is_empty() {
            return Err(SealError::Invalid("refusing to seal an empty master password"));
        }
        if pin.is_empty() {
            return Err(SealError::Invalid("refusing to seal an empty PIN"));
        }
        if pin.chars().count() < MIN_PIN_LEN {
            return Err(SealError::Invalid(
                "PIN too short: need at least 6 characters (NIST SP 800-63B memorized-authenticator floor)",
            ));
        }
        let machine_id = self.machine_id()?;
        self.ensure_dir()?;

        // A fresh host key per (re-)seal: the 256-bit binding secret.
        let mut host_key = Zeroizing::new([0u8; HOST_KEY_LEN]);
        rng::fill(host_key.as_mut())?;
        let binding = binding_material(host_key.as_ref(), &machine_id);
        let master_material = with_pin(&binding, pin.as_bytes());
        let algo = self.active_algo();
        let master_blob = blob::seal(&master_material, master.as_bytes(), algo, self.cost)?;
        let pin_blob = blob::seal(&binding, pin.as_bytes(), algo, self.cost)?;
        self.verify_opens(&binding, &pin_blob, pin.as_bytes())?;
        self.verify_opens(&master_material, &master_blob, master.as_bytes())?;
        let pin_hash = pin::hash_line(&rng::array()?, pin.as_bytes());
        let owner = self.dir_owner()?;

        let lock = DirLock::acquire(&self.dir, self.lock_wait);
        match lock.state() {
            LockState::Held => {}
            // Two writers interleaving their renames can pair one's host.key
            // with the other's blobs, which nothing can ever open again.
            LockState::Contended => return Err(SealError::Busy),
            LockState::Unavailable => {
                log::warn(format_args!("sealing {} without the seal lock (no flock here)", self.dir.display()));
            }
        }
        let files: [(&str, &[u8]); 4] = [
            (HOST_KEY_FILE, host_key.as_ref()),
            (PIN_HASH_FILE, &pin_hash),
            (PIN_FILE, &pin_blob),
            (MASTER_FILE, &master_blob),
        ];
        let committed = self.stage_and_commit(&files, owner, 0o600);
        drop(lock);
        match committed {
            Ok(()) => {}
            // Nothing was renamed: the previous seal is intact, tidy up.
            Err((0, e)) => {
                fsio::discard_tmp(&self.dir, &SEAL_FILES);
                return Err(e);
            }
            // Part-way: the staged files are the only way forward, so they are
            // left for the next unseal to finish with.
            Err((_, e)) => return Err(e),
        }
        self.ticket_discard();
        Ok(())
    }

    /// Recover the master password (host.key + machine-id, no PIN prompt —
    /// unattended). Fails if nothing is sealed, on the wrong host, without
    /// `host.key`, or if the files are corrupt. A legacy seal is read and
    /// migrated on the way through.
    ///
    /// With a keyring configured ([`SecretStore::with_keyring`]) that is
    /// tried first; if it has no entry a warning is logged and the sealed
    /// files are used, which remain the on-disk source of truth.
    pub fn unseal(&self) -> Result<Zeroizing<String>> {
        if let Some(keyring) = &self.keyring {
            match keyring.load() {
                Ok(Some(master)) => return Ok(master),
                Ok(None) => log::warn("SOC_SECRET_BACKEND=libsecret but no entry found — falling back to sealed file"),
                Err(e) => log::warn(format_args!("keyring unseal failed: {e} — falling back to sealed file")),
            }
        }
        self.unseal_sealed()
    }

    /// [`SecretStore::unseal`] from the sealed files only (ticket included).
    pub(crate) fn unseal_sealed(&self) -> Result<Zeroizing<String>> {
        let machine_id = self.machine_id();
        let known_id = machine_id.as_deref().ok();
        if let Some(master) = self.ticket_load(known_id) {
            return Ok(master);
        }
        let lock = DirLock::acquire(&self.dir, self.lock_wait);
        // A peer may have finished while we waited.
        if let Some(master) = self.ticket_load(known_id) {
            return Ok(master);
        }
        if lock.held() {
            self.finish_interrupted_seal(known_id);
        }
        self.unseal_files(lock.held(), machine_id.as_deref())
    }

    /// The expensive path: decrypt the sealed files, migrating if they are
    /// legacy.
    fn unseal_files(
        &self,
        locked: bool,
        machine_id: std::result::Result<&[u8], &SealError>,
    ) -> Result<Zeroizing<String>> {
        // Blobs BEFORE host.key. Writers commit host.key first, so any v2 blob
        // seen here guarantees its key is visible below, even with no lock
        // against a concurrent migration.
        let pin_blob = self.read(PIN_FILE)?;
        let master_blob = self.read(MASTER_FILE)?;
        let (host_key, mut key_err) = match self.read_host_key() {
            Ok(key) => (Some(key), None),
            Err(e) => (None, Some(e)),
        };
        let machine_id = machine_id.map_err(|_| SealError::NoMachineId)?; // audit-allow: the only failure is a missing machine-id
        let binding = host_key.as_ref().map(|key| binding_material(key, machine_id));

        let (pin, pin_legacy) = blob::open_either(
            &pin_blob,
            binding.as_ref().map(|b| b.as_slice()),
            || key_err.take().unwrap_or(SealError::HostKeyMissing),
            machine_id,
            self.cost,
        )?;
        let master_material = binding.as_ref().map(|b| with_pin(b, &pin));
        let legacy_master_material = concat(&[machine_id, &pin]);
        let (master, master_legacy) = blob::open_either(
            &master_blob,
            master_material.as_ref().map(|m| m.as_slice()),
            || key_err.take().unwrap_or(SealError::HostKeyMissing),
            &legacy_master_material,
            self.cost,
        )?;

        if pin_legacy || master_legacy {
            let existing_key = host_key.as_ref().map(|k| k.as_slice());
            if let Some(m) = self.migrate_legacy(&pin, &master, existing_key, locked, machine_id) {
                self.ticket_save(&m.host_key, machine_id, &m.pin_blob, &m.master_blob, &master);
            }
        } else if let Some(key) = &host_key {
            self.ticket_save(key, machine_id, &pin_blob, &master_blob, &master);
        }
        into_text(master)
    }

    /// Finish a seal or migration that died between its renames.
    ///
    /// A re-seal rotates `host.key`, so once that first rename has happened
    /// the old v2 blobs can no longer be opened, and until the last one has,
    /// the directory holds a mix of two seals: it does not unseal, or (over a
    /// legacy seal) it unseals to the old master beside the new `pin.hash`.
    /// But every file of the new seal was staged and fsync'd before the first
    /// rename, so the missing pieces are still there as `*.tmp`. If they open
    /// under the `host.key` now in place they are the rest of that seal:
    /// rename them in. Anything else (junk from an unrelated crash) fails that
    /// test and is left alone.
    ///
    /// Costs nothing unless staged blobs exist. Caller holds the seal lock.
    /// True if the directory was repaired.
    fn finish_interrupted_seal(&self, machine_id: Option<&[u8]>) -> bool {
        let Some(machine_id) = machine_id else { return false };
        // host.key still staged: no rename happened, nothing to finish.
        if fsio::tmp_path(&self.path(HOST_KEY_FILE)).exists() {
            return false;
        }
        let staged = |name: &str| fsio::read_bounded(&fsio::tmp_path(&self.path(name)), MAX_SEAL_FILE).ok();
        let (staged_pin, staged_master) = (staged(PIN_FILE), staged(MASTER_FILE));
        if staged_pin.is_none() && staged_master.is_none() {
            return false;
        }
        // Nothing can be renamed on a read-only box: do not pay for the KDF.
        if rustix::fs::access(&self.dir, Access::WRITE_OK | Access::EXEC_OK).is_err() {
            return false;
        }
        let Ok(host_key) = self.read_host_key() else { return false };
        let candidate =
            |staged: Option<Zeroizing<Vec<u8>>>, name: &str| staged.map_or_else(|| self.read(name).ok(), Some);
        let pin_staged = staged_pin.is_some();
        let (Some(pin_blob), Some(master_blob)) =
            (candidate(staged_pin, PIN_FILE), candidate(staged_master, MASTER_FILE))
        else {
            return false;
        };
        let binding = binding_material(&host_key, machine_id);
        let Ok(pin) = blob::open(&binding, &pin_blob, self.cost) else { return false };
        if blob::open(&with_pin(&binding, &pin), &master_blob, self.cost).is_err() {
            return false;
        }
        let mut pending: Vec<&str> = Vec::new();
        if staged(PIN_HASH_FILE).is_some_and(|line| pin::matches_hash_line(&line, &pin)) {
            pending.push(PIN_HASH_FILE);
        }
        if pin_staged {
            pending.push(PIN_FILE);
        }
        pending.push(MASTER_FILE);
        if fsio::commit(&self.dir, &pending, &|name| self.faults.before_rename(name)).is_err() {
            return false;
        }
        fsio::discard_tmp(&self.dir, &SEAL_FILES);
        log::info(format_args!("completed an interrupted re-seal in {}", self.dir.display()));
        true
    }

    /// Re-seal an opened legacy seal as v2, same PIN, with no prompt.
    /// NEVER fails the caller: it already holds the master and a boot must not
    /// fail over an upgrade, so every failure is a logged warning and the box
    /// stays legacy.
    ///
    /// Crash safety. Everything is staged and verified first, then committed
    /// in this order, each rename durable before the next:
    ///
    /// ```text
    /// legacy state                      unseals: both blobs legacy
    /// 1. host.key                       unseals: both blobs legacy
    /// 2. pin.enc   (v2)                 unseals: v2 PIN, legacy master
    /// 3. master.enc (v2), the sentinel  unseals: fully v2
    /// ```
    ///
    /// Every intermediate state unseals because the format is chosen per
    /// blob, and the next unseal resumes the migration. That resume MUST
    /// reuse the `host.key` already on disk: a v2 `pin.enc` may depend on it,
    /// so rotating here could strand the PIN. `pin.hash` is untouched, since
    /// the PIN does not change.
    fn migrate_legacy(
        &self,
        pin: &[u8],
        master: &[u8],
        host_key: Option<&[u8]>,
        locked: bool,
        machine_id: &[u8],
    ) -> Option<Migrated> {
        let dir = self.dir.display();
        if !locked {
            log::info(format_args!("not migrating legacy seal in {dir}: another process holds the seal lock"));
            return None;
        }
        if skip_set().contains(&self.dir) {
            return None;
        }
        match self.try_migrate(pin, master, host_key, machine_id) {
            Ok(migrated) => {
                // Leftovers from any earlier interrupted run.
                fsio::discard_tmp(&self.dir, &SEAL_FILES);
                log::info(format_args!("migrated the legacy seal in {dir} to the host.key format"));
                Some(migrated)
            }
            Err(e) => {
                skip_set().insert(self.dir.clone());
                log::warn(format_args!(
                    "could not migrate the legacy seal in {dir} ({e}) — still using it; will retry on the next start"
                ));
                None
            }
        }
    }

    fn try_migrate(&self, pin: &[u8], master: &[u8], host_key: Option<&[u8]>, machine_id: &[u8]) -> Result<Migrated> {
        let io_err = |path: PathBuf| move |source: io::Error| SealError::Io { path, source };
        // Everything that can refuse comes before any KDF: on a read-only or
        // wrongly-owned box this runs in every new process.
        rustix::fs::access(&self.dir, Access::WRITE_OK | Access::EXEC_OK)
            .map_err(|e| io_err(self.dir.clone())(e.into()))?;
        // New files copy master.enc's owner and read bits so migrating can
        // never change who can read the seal: this runs as whichever of the
        // wall or the (root) VPN supervisor gets there first. Write, execute
        // and special bits are not copied — nobody needs them on a key.
        let master_path = self.path(MASTER_FILE);
        let like = fs::metadata(&master_path).map_err(io_err(master_path.clone()))?;
        let (owner, mode) = (Owner::of(&like), like.mode() & 0o644);
        if mode & 0o004 != 0 {
            log::warn(format_args!(
                "{} is world-readable; the migrated seal keeps that so no reader is locked out — \
                 tighten the secret dir to 0700 and its files to 0600",
                master_path.display()
            ));
        }
        self.faults
            .before_stage()
            .and_then(|()| fsio::stage(&master_path, &[], Some(owner), mode))
            .map_err(io_err(master_path.clone()))?;
        fsio::discard_tmp(&self.dir, &[MASTER_FILE]);

        let fresh_key = host_key.is_none();
        let mut key = Zeroizing::new(vec![0u8; HOST_KEY_LEN]);
        match host_key {
            Some(existing) => {
                key.clear();
                key.extend_from_slice(existing);
            }
            None => rng::fill(&mut key)?,
        }
        let binding = binding_material(&key, machine_id);
        let master_material = with_pin(&binding, pin);
        let algo = self.active_algo();
        let pin_blob = blob::seal(&binding, pin, algo, self.cost)?;
        let master_blob = blob::seal(&master_material, master, algo, self.cost)?;
        // The legacy blobs are about to be gone for good: prove the new ones
        // open before giving them up.
        self.verify_opens(&binding, &pin_blob, pin)?;
        self.verify_opens(&master_material, &master_blob, master)?;

        let mut files: Vec<(&str, &[u8])> = Vec::with_capacity(3);
        if fresh_key {
            files.push((HOST_KEY_FILE, &key));
        }
        files.push((PIN_FILE, &pin_blob));
        files.push((MASTER_FILE, &master_blob));
        if let Err((_, e)) = self.stage_and_commit(&files, Some(owner), mode) {
            // Whatever was renamed is a state that unseals; the rest is noise.
            fsio::discard_tmp(&self.dir, &SEAL_FILES);
            return Err(e);
        }
        Ok(Migrated { host_key: key, pin_blob, master_blob })
    }

    fn ticket_load(&self, machine_id: Option<&[u8]>) -> Option<Zeroizing<String>> {
        let cfg = self.ticket.as_ref()?;
        let raw = cfg.runtime_dir()?.read()?;
        let host_key = self.read_host_key().ok()?;
        let pin_blob = self.read(PIN_FILE).ok()?;
        let master_blob = self.read(MASTER_FILE).ok()?;
        let boot_id = cfg.boot_id()?;
        let binding = ticket::Binding {
            host_key: &host_key,
            machine_id: machine_id?,
            boot_id: &boot_id,
            pin_blob: &pin_blob,
            master_blob: &master_blob,
        };
        into_text(ticket::unwrap(&binding, &raw, cfg.now(), cfg.ttl)?).ok()
    }

    /// A cache must never fail an unseal: every problem here is just "no
    /// ticket".
    fn ticket_save(&self, host_key: &[u8], machine_id: &[u8], pin_blob: &[u8], master_blob: &[u8], master: &[u8]) {
        let Some(cfg) = &self.ticket else { return };
        let Some(dir) = cfg.runtime_dir() else { return };
        let Some(boot_id) = cfg.boot_id() else { return };
        let binding = ticket::Binding { host_key, machine_id, boot_id: &boot_id, pin_blob, master_blob };
        if let Some(raw) = ticket::wrap(&binding, master, cfg.now().saturating_add(cfg.ttl)) {
            let _ = dir.write(&raw); // audit-allow: best-effort cache write; a miss only costs a KDF
        }
    }

    fn ticket_discard(&self) {
        if let Some(dir) = self.ticket.as_ref().and_then(TicketCfg::runtime_dir) {
            dir.discard();
        }
    }
}

#[cfg(test)]
impl SecretStore {
    /// A hermetic store for the other modules' unit tests: fixed machine-id
    /// and tiny KDF work factors.
    pub(crate) fn for_unit_tests(dir: &Path) -> SecretStore {
        let mut store = SecretStore::new(dir).with_machine_id("host-A");
        store.cost = Cost::TEST;
        store
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
