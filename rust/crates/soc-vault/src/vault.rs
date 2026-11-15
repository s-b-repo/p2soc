//! The credential facade the rest of the wall talks to: a backend plus a
//! short-TTL, RAM-only cache.
//!
//! Credentials are never written to disk by this process. Cached entries are
//! wiped when they expire, are invalidated or the vault is dropped.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use soc_core::{CredError, CredSource, LOG_TAG, Login};
use zeroize::Zeroizing;

use crate::backend::{Backend, VaultEnv, make_backend, require_notes};
use crate::error::VaultError;
use crate::master::MasterSource;
use crate::session::Session;

/// Cache behaviour.
#[derive(Debug, Clone, Copy)]
pub struct VaultOptions {
    /// How long a fetched credential is served from RAM.
    pub ttl: Duration,
    /// When non-zero, a credential that worked within this window is served
    /// again if the backend is *unreachable* — so a Vaultwarden restart does
    /// not log a live panel out. Zero (the default) disables it.
    pub stale_ttl: Duration,
}

impl Default for VaultOptions {
    fn default() -> Self {
        VaultOptions { ttl: Duration::from_secs(30), stale_ttl: Duration::ZERO }
    }
}

type Clock = dyn Fn() -> Instant + Send + Sync;

#[derive(Default)]
struct Cache {
    fresh: HashMap<String, (Instant, Login)>,
    last_good: HashMap<String, (Instant, Login)>,
    /// Items already announced as served stale, to log once per outage.
    stale_logged: HashSet<String>,
    /// Bumped by every invalidation. A fetch that started before one must not
    /// cache what it got: the answer may predate the change that caused it.
    generation: u64,
}

/// The vault facade.
pub struct Vault {
    backend: Box<dyn Backend>,
    opts: VaultOptions,
    cache: Mutex<Cache>,
    ready: AtomicBool,
    clock: Box<Clock>,
}

impl Vault {
    pub fn new(backend: Box<dyn Backend>, opts: VaultOptions) -> Vault {
        Vault {
            backend,
            opts,
            cache: Mutex::new(Cache::default()),
            ready: AtomicBool::new(false),
            clock: Box::new(Instant::now),
        }
    }

    /// The vault this process's environment describes (`$SOC_VAULT_BACKEND`,
    /// `$SOC_CRED_TTL`, ...), with the master password supplied by `master`.
    pub fn from_env(master: Arc<dyn MasterSource>) -> Result<Vault, VaultError> {
        Vault::from_settings(&VaultEnv::from_process(), master)
    }

    /// As [`Vault::from_env`], from an already gathered environment.
    pub fn from_settings(env: &VaultEnv, master: Arc<dyn MasterSource>) -> Result<Vault, VaultError> {
        let opts = VaultOptions { ttl: env.cred_ttl, stale_ttl: env.stale_ttl };
        Ok(Vault::new(make_backend(env, master)?, opts))
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: impl Fn() -> Instant + Send + Sync + 'static) -> Vault {
        self.clock = Box::new(clock);
        self
    }

    fn lock(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Unlock + initial sync. Call once at startup. In interactive mode with
    /// no master this returns [`VaultError::Locked`]: show the Unlock dialog
    /// and call [`Vault::unlock_with`].
    pub fn open(&self) -> Result<(), VaultError> {
        self.backend.unlock()?;
        self.backend.sync()?;
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Open with a master the operator typed, then sync. The master stays in
    /// RAM only. Errors say whether the password or the server was the
    /// problem, so the dialog can re-prompt sensibly.
    pub fn unlock_with(&self, master: &str) -> Result<(), VaultError> {
        self.backend.unlock_with(master)?;
        self.backend.sync()?;
        self.invalidate(None);
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Drop expired entries so nothing outlives its TTL in RAM and the maps
    /// cannot grow without bound over a 24/7 run.
    fn evict_expired(&self, cache: &mut Cache, now: Instant) {
        let (ttl, stale) = (self.opts.ttl, self.opts.stale_ttl);
        cache.fresh.retain(|_, (at, _)| now.saturating_duration_since(*at) < ttl);
        cache.last_good.retain(|_, (at, _)| now.saturating_duration_since(*at) < stale);
    }

    /// True if a fresh credential is cached (no backend call needed).
    pub fn cached(&self, item: &str) -> bool {
        let mut cache = self.lock();
        self.evict_expired(&mut cache, (self.clock)());
        cache.fresh.contains_key(item)
    }

    /// Username + password of `item`, from the cache when fresh.
    pub fn creds(&self, item: &str) -> Result<Login, VaultError> {
        let generation = {
            let mut cache = self.lock();
            self.evict_expired(&mut cache, (self.clock)());
            if let Some((_, login)) = cache.fresh.get(item) {
                return Ok(login.clone());
            }
            cache.generation
        };
        // Fetch outside the lock: the backend may block on the network, and a
        // duplicate fetch of one item is harmless.
        match self.backend.get(item) {
            Ok(login) => {
                let now = (self.clock)();
                let mut cache = self.lock();
                if cache.generation == generation {
                    cache.fresh.insert(item.to_string(), (now, login.clone()));
                    if !self.opts.stale_ttl.is_zero() {
                        cache.last_good.insert(item.to_string(), (now, login.clone()));
                    }
                }
                cache.stale_logged.remove(item);
                Ok(login)
            }
            // Only an availability failure may fall back to the last-good
            // copy. "Not found" or "rejected" means the credential was
            // removed or revoked, and serving the old one would undo that.
            Err(e) if e.is_transient() && !self.opts.stale_ttl.is_zero() => {
                let mut cache = self.lock();
                self.evict_expired(&mut cache, (self.clock)());
                match cache.last_good.get(item).map(|(_, login)| login.clone()) {
                    Some(login) => {
                        if cache.stale_logged.insert(item.to_string()) {
                            eprintln!(
                                "{LOG_TAG} vault: serving last-good creds for '{item}' (backend unreachable, within \
                                 SOC_CRED_STALE_TTL)"
                            );
                        }
                        Ok(login)
                    }
                    None => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Fetch many items in parallel (off the UI thread) so each panel's first
    /// login is served from cache. Duplicates and empty names are skipped;
    /// per-item failures are passed to `log`, never raised. Returns how many
    /// items were fetched.
    pub fn prewarm(&self, items: &[&str], log: Option<&(dyn Fn(&str) + Sync)>) -> usize {
        let mut unique: Vec<&str> = Vec::new();
        for item in items.iter().filter(|i| !i.is_empty()) {
            if !unique.contains(item) {
                unique.push(item);
            }
        }
        let (next, fetched) = (AtomicUsize::new(0), AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..unique.len().min(4) {
                scope.spawn(|| {
                    while let Some(item) = unique.get(next.fetch_add(1, Ordering::SeqCst)) {
                        match self.creds(item) {
                            Ok(_) => {
                                fetched.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(e) => {
                                if let Some(log) = log {
                                    log(&format!("prewarm '{item}': {e}"));
                                }
                            }
                        }
                    }
                });
            }
        });
        fetched.into_inner()
    }

    /// The item's Notes field (not cached — read once, at connect).
    pub fn notes(&self, item: &str) -> Result<Zeroizing<String>, VaultError> {
        self.backend.notes(item)
    }

    /// The item's Notes, failing with an actionable message when blank.
    pub fn notes_required(&self, item: &str, purpose: &str) -> Result<Zeroizing<String>, VaultError> {
        require_notes(self.backend.notes(item)?, item, purpose)
    }

    /// A current TOTP code for the item.
    pub fn code(&self, item: &str) -> Result<String, VaultError> {
        self.backend.code(item)
    }

    /// Re-read the backend and forget every cached credential.
    pub fn resync(&self) -> Result<(), VaultError> {
        self.invalidate(None);
        self.backend.sync()
    }

    /// Forget one item's cached credential, or all of them.
    pub fn invalidate(&self, item: Option<&str>) {
        let mut cache = self.lock();
        cache.generation += 1;
        match item {
            Some(item) => {
                cache.fresh.remove(item);
                cache.last_good.remove(item);
                cache.stale_logged.remove(item);
            }
            None => {
                cache.fresh.clear();
                cache.last_good.clear();
                cache.stale_logged.clear();
            }
        }
    }

    /// Delete a vault item and drop every cached copy of it. Returns false —
    /// and logs — if there was nothing to delete or the backend failed, so the
    /// UI can show one "delete failed" toast.
    pub fn delete(&self, item: &str) -> bool {
        match self.backend.delete(item) {
            Ok(deleted) => {
                if deleted {
                    self.invalidate(Some(item));
                }
                deleted
            }
            Err(e) => {
                eprintln!("{LOG_TAG} vault: delete of '{item}' failed: {e}");
                false
            }
        }
    }

    /// Names of every item in the named folder; empty on failure or an
    /// unknown folder so the UI can render an empty group.
    pub fn list_by_folder(&self, folder: &str) -> Vec<String> {
        self.backend.list_by_folder(folder).unwrap_or_else(|e| {
            eprintln!("{LOG_TAG} vault: listing folder '{folder}' failed: {e}");
            Vec::new()
        })
    }

    /// A session that can write items (native backend only).
    pub fn session(&self) -> Result<Arc<Session>, VaultError> {
        self.backend.session()
    }
}

impl CredSource for Vault {
    fn creds(&self, item: &str) -> Result<Login, CredError> {
        Vault::creds(self, item).map_err(CredError::from)
    }

    fn notes(&self, item: &str) -> Result<String, CredError> {
        Vault::notes(self, item).map(|notes| notes.as_str().to_owned()).map_err(CredError::from)
    }

    fn code(&self, item: &str) -> Result<String, CredError> {
        Vault::code(self, item).map_err(CredError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Condvar;

    /// In-memory backend with switches for the failure modes under test.
    #[derive(Default)]
    struct FakeBackend {
        data: Mutex<HashMap<String, (String, String)>>,
        folders: HashMap<String, Vec<String>>,
        gets: AtomicUsize,
        fail: Mutex<Option<VaultError>>,
        /// When armed, `get` parks until released (to stage races).
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    }

    impl FakeBackend {
        fn with(items: &[(&str, &str, &str)]) -> FakeBackend {
            let data = items.iter().map(|(n, u, p)| (n.to_string(), (u.to_string(), p.to_string()))).collect();
            FakeBackend { data: Mutex::new(data), ..FakeBackend::default() }
        }
    }

    impl Backend for Arc<FakeBackend> {
        fn unlock(&self) -> Result<(), VaultError> {
            Ok(())
        }
        fn sync(&self) -> Result<(), VaultError> {
            Ok(())
        }
        fn get(&self, item: &str) -> Result<Login, VaultError> {
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e);
            }
            let found = self.data.lock().unwrap().get(item).cloned();
            // Counted only once the answer is in hand, so a test that waits on
            // this counter knows the value was read before it changes the data.
            self.gets.fetch_add(1, Ordering::SeqCst);
            if let Some((lock, cv)) = self.gate.as_deref() {
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = cv.wait(open).unwrap();
                }
            }
            found.map(|(u, p)| Login::new(u, p)).ok_or_else(|| VaultError::NotFound(format!("no vault item '{item}'")))
        }
        fn notes(&self, item: &str) -> Result<Zeroizing<String>, VaultError> {
            Ok(Zeroizing::new(if item == "WG" { "[Interface]\nPrivateKey=SECRET".to_string() } else { String::new() }))
        }
        fn code(&self, item: &str) -> Result<String, VaultError> {
            if item == "A" { Ok("123456".into()) } else { Err(VaultError::NotFound("no TOTP".into())) }
        }
        fn delete(&self, item: &str) -> Result<bool, VaultError> {
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e);
            }
            Ok(self.data.lock().unwrap().remove(item).is_some())
        }
        fn list_by_folder(&self, folder: &str) -> Result<Vec<String>, VaultError> {
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e);
            }
            Ok(self.folders.get(folder).cloned().unwrap_or_default())
        }
    }

    fn vault(backend: &Arc<FakeBackend>, opts: VaultOptions) -> Vault {
        Vault::new(Box::new(Arc::clone(backend)), opts)
    }

    /// A clock the test advances by hand.
    fn manual_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync + 'static) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let handle = Arc::clone(&now);
        (now, move || *handle.lock().unwrap())
    }

    fn advance(clock: &Arc<Mutex<Instant>>, by: Duration) {
        *clock.lock().unwrap() += by;
    }

    #[test]
    fn creds_are_fetched_once_then_served_from_cache() {
        let be = Arc::new(FakeBackend::with(&[("Item 1", "u1", "s3cr3t")]));
        let v = vault(&be, VaultOptions::default());
        assert!(!v.ready());
        v.open().unwrap();
        assert!(v.ready());
        assert!(!v.cached("Item 1"));
        let c = v.creds("Item 1").unwrap();
        assert_eq!((c.username.as_str(), c.password.as_str()), ("u1", "s3cr3t"));
        assert!(v.cached("Item 1"));
        assert_eq!(v.creds("Item 1").unwrap().password, "s3cr3t");
        assert_eq!(be.gets.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_missing_item_is_not_found_and_not_cached() {
        let be = Arc::new(FakeBackend::default());
        let v = vault(&be, VaultOptions::default());
        assert!(matches!(v.creds("nope"), Err(VaultError::NotFound(_))));
        assert!(!v.cached("nope"));
        assert!(matches!(CredSource::creds(&v, "nope"), Err(CredError::NotFound(_))));
    }

    #[test]
    fn expired_entries_are_evicted_and_refetched() {
        let be = Arc::new(FakeBackend::with(&[("stale", "u", "p"), ("fresh", "u", "p")]));
        let (clock, now) = manual_clock();
        let v = vault(&be, VaultOptions { ttl: Duration::from_secs(30), ..VaultOptions::default() }).with_clock(now);
        v.creds("stale").unwrap();
        advance(&clock, Duration::from_secs(20));
        v.creds("fresh").unwrap();
        advance(&clock, Duration::from_secs(15));
        // Touching any item sweeps every expired one out of RAM.
        assert!(v.cached("fresh"));
        assert!(!v.lock().fresh.contains_key("stale"));
        assert!(!v.cached("stale"));
        v.creds("stale").unwrap();
        assert_eq!(be.gets.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn prewarm_dedups_skips_empties_and_logs_failures() {
        let be = Arc::new(FakeBackend::with(&[("A", "ua", "pa"), ("B", "ub", "pb")]));
        let v = vault(&be, VaultOptions { ttl: Duration::from_secs(60), ..VaultOptions::default() });
        let logged = Mutex::new(Vec::new());
        let log = |line: &str| logged.lock().unwrap().push(line.to_string());
        assert_eq!(v.prewarm(&["A", "B", "A", "", "missing"], Some(&log)), 2);
        assert!(v.cached("A") && v.cached("B"));
        assert_eq!(be.gets.load(Ordering::SeqCst), 3);
        assert_eq!(*logged.lock().unwrap(), ["prewarm 'missing': no vault item 'missing'"]);
        assert_eq!(v.prewarm(&[], None), 0);
        assert_eq!(v.prewarm(&["missing"], None), 0);
    }

    #[test]
    fn concurrent_readers_are_race_free() {
        let be = Arc::new(FakeBackend::with(&[("B", "ub", "pb")]));
        let v = vault(&be, VaultOptions::default());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| assert_eq!(v.creds("B").unwrap().username, "ub"));
            }
        });
    }

    #[test]
    fn a_fetch_that_raced_an_invalidation_is_not_cached() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let be =
            Arc::new(FakeBackend { gate: Some(Arc::clone(&gate)), ..FakeBackend::with(&[("X", "u", "old-password")]) });
        let v = vault(&be, VaultOptions::default());
        std::thread::scope(|scope| {
            // The reader picks up the old password, then parks inside the backend.
            let reader = scope.spawn(|| v.creds("X").unwrap().password.clone());
            while be.gets.load(Ordering::SeqCst) == 0 {
                std::thread::yield_now();
            }
            // Meanwhile the operator rotates the credential and invalidates.
            be.data.lock().unwrap().insert("X".into(), ("u".into(), "new-password".into()));
            v.invalidate(Some("X"));
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
            assert_eq!(reader.join().unwrap(), "old-password");
        });
        assert!(!v.cached("X"), "the pre-invalidation answer must not be cached");
        assert_eq!(v.creds("X").unwrap().password, "new-password");
    }

    #[test]
    fn invalidate_and_resync_forget_cached_creds() {
        let be = Arc::new(FakeBackend::with(&[("A", "u", "p"), ("B", "u", "p")]));
        let v = vault(&be, VaultOptions::default());
        v.creds("A").unwrap();
        v.creds("B").unwrap();
        v.invalidate(Some("A"));
        assert!(!v.cached("A") && v.cached("B"));
        v.invalidate(None);
        assert!(!v.cached("B"));
        v.creds("B").unwrap();
        v.resync().unwrap();
        assert!(!v.cached("B"));
    }

    #[test]
    fn delete_drops_the_cached_copy_and_never_raises() {
        let be = Arc::new(FakeBackend::with(&[("foo", "u", "p")]));
        let v = vault(&be, VaultOptions { stale_ttl: Duration::from_secs(300), ..VaultOptions::default() });
        v.creds("foo").unwrap();
        assert!(v.cached("foo"));
        assert!(v.delete("foo"));
        assert!(!v.cached("foo"));
        assert!(v.lock().last_good.is_empty());
        assert!(!v.delete("foo"), "idempotent: gone the second time");
        *be.fail.lock().unwrap() = Some(VaultError::Backend("subprocess fell over".into()));
        assert!(!v.delete("anything"));
    }

    #[test]
    fn list_by_folder_degrades_to_empty() {
        let mut be = FakeBackend::default();
        be.folders.insert("SOC Wall Auth".into(), vec!["SOC Settings TOTP".into(), "SOC Panel Lock TOTP".into()]);
        let be = Arc::new(be);
        let v = vault(&be, VaultOptions::default());
        assert_eq!(v.list_by_folder("SOC Wall Auth"), ["SOC Settings TOTP", "SOC Panel Lock TOTP"]);
        assert!(v.list_by_folder("does-not-exist").is_empty());
        *be.fail.lock().unwrap() = Some(VaultError::Unreachable("down".into()));
        assert!(v.list_by_folder("SOC Wall Auth").is_empty());
    }

    #[test]
    fn stale_serve_covers_outages_only_and_only_when_enabled() {
        let be = Arc::new(FakeBackend::with(&[("X", "u", "p")]));
        let (clock, now) = manual_clock();
        let opts = VaultOptions { ttl: Duration::from_secs(30), stale_ttl: Duration::from_secs(300) };
        let v = vault(&be, opts).with_clock(now);
        v.creds("X").unwrap();
        advance(&clock, Duration::from_secs(60));

        // Outage: the last-good copy bridges it.
        *be.fail.lock().unwrap() = Some(VaultError::Unreachable("vault down".into()));
        assert_eq!(v.creds("X").unwrap().password, "p");
        assert!(!v.cached("X"), "a stale answer is never promoted to fresh");
        assert!(matches!(v.creds("never-seen"), Err(VaultError::Unreachable(_))));

        // Revocation: "not found" / "rejected" must NOT be papered over.
        *be.fail.lock().unwrap() = Some(VaultError::NotFound("gone".into()));
        assert!(matches!(v.creds("X"), Err(VaultError::NotFound(_))));
        *be.fail.lock().unwrap() = Some(VaultError::LoginRejected("no".into()));
        assert!(matches!(v.creds("X"), Err(VaultError::LoginRejected(_))));

        // Past the stale window the outage surfaces.
        *be.fail.lock().unwrap() = Some(VaultError::Unreachable("vault down".into()));
        advance(&clock, Duration::from_secs(300));
        assert!(matches!(v.creds("X"), Err(VaultError::Unreachable(_))));
        assert!(v.lock().last_good.is_empty(), "expired last-good copies leave RAM");

        // Disabled (the default): no last-good copy is even kept.
        let be = Arc::new(FakeBackend::with(&[("X", "u", "p")]));
        let (clock, now) = manual_clock();
        let v = vault(&be, VaultOptions::default()).with_clock(now);
        v.creds("X").unwrap();
        assert!(v.lock().last_good.is_empty());
        advance(&clock, Duration::from_secs(60));
        *be.fail.lock().unwrap() = Some(VaultError::Unreachable("vault down".into()));
        assert!(v.creds("X").is_err());
    }

    #[test]
    fn notes_codes_and_the_cred_source_boundary() {
        let be = Arc::new(FakeBackend::with(&[("A", "u", "p")]));
        let v = vault(&be, VaultOptions::default());
        assert!(v.notes("WG").unwrap().contains("PrivateKey=SECRET"));
        assert!(v.notes_required("WG", "the VPN").is_ok());
        let err = v.notes_required("empty", "the VPN").unwrap_err();
        assert!(err.to_string().contains("empty Notes field for the VPN"));
        assert_eq!(v.code("A").unwrap(), "123456");

        let source: &dyn CredSource = &v;
        assert_eq!(source.creds("A").unwrap().password, "p");
        assert_eq!(source.notes("empty").unwrap(), "");
        assert_eq!(source.code("A").unwrap(), "123456");
        assert!(matches!(source.code("B"), Err(CredError::NotFound(_))));
        assert!(matches!(v.unlock_with("x"), Err(VaultError::Config(_))));
        assert!(matches!(v.session(), Err(VaultError::Config(_))));
    }

    #[test]
    fn end_to_end_against_a_fake_vaultwarden() {
        use crate::master::FixedMaster;
        use crate::testutil::{FakeVaultwarden, TEST_EMAIL, TEST_MASTER, test_options};
        let fake = FakeVaultwarden::start();
        fake.state().add_login("SOC Panel 1", "alice", "hunter2");
        let env = VaultEnv {
            email: Some(TEST_EMAIL.into()),
            url: Some(fake.url().to_string()),
            session: test_options(),
            ..VaultEnv::default()
        };
        let v = Vault::from_settings(&env, Arc::new(FixedMaster::new(TEST_MASTER))).unwrap();
        v.open().unwrap();
        assert_eq!(v.prewarm(&["SOC Panel 1", "absent"], None), 1);
        assert_eq!(v.creds("SOC Panel 1").unwrap().password, "hunter2");
        // The editor writes through the same session; no second login.
        let session = v.session().unwrap();
        crate::totp::save_vault(&session, Some(&v), crate::totp::TotpKind::Settings, " JBSWY3DPEHPK3PXP \n").unwrap();
        v.resync().unwrap();
        let source: &dyn CredSource = &v;
        assert_eq!(
            crate::totp::load_vault(Some(source), crate::totp::TotpKind::Settings).unwrap().as_str(),
            "JBSWY3DPEHPK3PXP"
        );
        assert_eq!(v.list_by_folder(crate::totp::VAULT_TOTP_FOLDER), ["SOC Settings TOTP"]);
        assert!(crate::totp::clear_vault(&session, Some(&v), crate::totp::TotpKind::Settings).unwrap());
        assert!(!crate::totp::clear_vault(&session, Some(&v), crate::totp::TotpKind::Settings).unwrap());
        assert!(v.delete("SOC Panel 1"));
        assert!(v.creds("SOC Panel 1").is_err());
        assert_eq!(fake.password_logins(), 1);
    }
}
