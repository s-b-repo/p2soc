//! The kiosk lock: the state behind the input-swallowing overlay.
//!
//! The overlay itself is GTK and lives elsewhere; this is everything it needs
//! to decide. A code unlocks if it is the panel-lock PIN, a current TOTP code,
//! or the host's sealed setup PIN (the admin override, so a forgotten
//! credential never strands the wall).
//!
//! Differences from the Python locker, all deliberate:
//!
//! * the back-off is checked inside [`KioskLock::try_unlock`], not by greying
//!   out widgets, and it is persisted;
//! * a TOTP code unlocks once;
//! * the engaged state is recorded on disk, so restarting the wall process
//!   (or power-cycling the board) no longer removes the lock;
//! * a corrupt TOTP secret is skipped instead of aborting the whole attempt
//!   before the PIN and the admin override were tried.

use crate::auth::{Enrollment, Match, Method, enroll};
use crate::authstate::{Budget, Schedule};
use crate::error::Result;
use crate::fsio;
use crate::pin::PinFile;
use crate::totp::{self, TotpFile};
use std::path::{Path, PathBuf};

/// Credentials that live outside the state directory, supplied per call.
#[derive(Clone, Copy, Default)]
pub struct LockSources<'a> {
    /// The panel-lock TOTP secret from the vault — pass it only when the
    /// vault is already open (never trigger an unlock from the GTK thread).
    /// When present it replaces the local TOTP file, so a stale on-disk
    /// secret cannot outlast a rotation.
    pub vault_totp: Option<&'a str>,
    /// Verifier for the host's sealed setup PIN; `None` when the host is not
    /// sealed. It may be slow (it runs a memory-hard KDF).
    pub admin_pin: Option<&'a dyn Fn(&str) -> bool>,
}

/// The lock's credential files: `panellock.pin`, `panellock.totp`, the attempt
/// budget and the "engaged" marker.
#[derive(Debug)]
pub struct LockStore {
    pin: PinFile,
    totp: TotpFile,
    budget: Budget,
    marker: PathBuf,
}

impl LockStore {
    pub fn new(state_dir: &Path) -> LockStore {
        LockStore {
            pin: PinFile::new(state_dir.join("panellock.pin")),
            totp: TotpFile::new(state_dir.join("panellock.totp")),
            budget: Budget::new(state_dir, "lock", Schedule::Lock),
            marker: state_dir.join("panellock.engaged"),
        }
    }

    /// Use a cheaper PIN stretch for newly set PINs (tests).
    pub fn with_pin_iterations(mut self, iterations: u32) -> LockStore {
        self.pin = self.pin.with_iterations(iterations);
        self
    }

    pub fn pin(&self) -> &PinFile {
        &self.pin
    }

    pub fn totp(&self) -> &TotpFile {
        &self.totp
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Generate and store a new panel-lock TOTP secret.
    pub fn enroll_totp(&self) -> Result<Enrollment> {
        enroll(&self.totp, totp::ISSUER_PANEL_LOCK)
    }

    /// One line for the Security tab.
    pub fn status_text(&self) -> String {
        let pin = if self.pin.is_set() { "PIN: SET ✓" } else { "PIN: (none)" };
        let totp = if self.totp.is_set() { "TOTP: SET ✓" } else { "TOTP: (none)" };
        format!("{pin}  ·  {totp}")
    }

    /// Whether anything at all could unlock: a lock nothing can open is
    /// refused, and one anything can open would be decoration.
    pub fn has_credential(&self, sources: &LockSources<'_>) -> bool {
        self.pin.is_set() || self.totp.is_set() || sources.vault_totp.is_some() || sources.admin_pin.is_some()
    }

    fn check_local(&self, code: &str, sources: &LockSources<'_>, now: u64) -> Option<Match> {
        if let Some(secret) = self.totp.load() {
            if let Some(step) = totp::verify_step(&secret, code, now) {
                return Some(Match::Timed(Method::Totp, step));
            }
        }
        self.check_static(code, sources)
    }

    fn check_static(&self, code: &str, sources: &LockSources<'_>) -> Option<Match> {
        if self.pin.verify(code) {
            return Some(Match::Static(Method::Pin));
        }
        sources.admin_pin.is_some_and(|verify| verify(code)).then_some(Match::Static(Method::AdminPin))
    }

    /// TOTP first (vault secret if there is a usable one, else the local
    /// file), then the panel PIN, then the admin override.
    fn check(&self, code: &str, sources: &LockSources<'_>, now: u64) -> Option<Match> {
        if code.is_empty() {
            return None;
        }
        match sources.vault_totp.map(str::trim).filter(|s| totp::decode_secret(s).is_some()) {
            // A vault that is closed, empty or holds garbage falls all the way
            // back to the local files, so the lock keeps working offline.
            None => self.check_local(code, sources, now),
            Some(secret) => match totp::verify_step(secret, code, now) {
                Some(step) => Some(Match::Timed(Method::VaultTotp, step)),
                None => self.check_static(code, sources),
            },
        }
    }
}

/// Which credentials the unlock card should ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockHint {
    PinOrTotp,
    Totp,
    Pin,
    /// Only the host's sealed setup PIN can unlock.
    AdminPin,
}

impl LockHint {
    pub fn text(self) -> &'static str {
        match self {
            LockHint::PinOrTotp => "Enter your PIN or a 6-digit authenticator code.",
            LockHint::Totp => "Enter the 6-digit code from your authenticator app.",
            LockHint::Pin => "Enter your PIN.",
            LockHint::AdminPin => "Enter the host setup PIN to unlock.",
        }
    }
}

/// What a lock request did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockRequest {
    /// Show the overlay now.
    Engaged,
    /// Already locked: just re-present the overlay.
    AlreadyLocked,
    /// Refused: no credential is enrolled. Tell the operator to set one.
    NoCredential,
}

/// Text for the advisory shown when a lock request is refused.
pub const NO_CREDENTIAL_ADVICE: &str = "No panel-lock credential is enrolled, so the lock would be decorative.\nSet \
                                        a panel-lock PIN first: ⚙ Settings → Security.";

/// What became of one unlock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockOutcome {
    /// Take the overlay down.
    Unlocked(Method),
    /// Wrong code; `wait` > 0 means input is locked for that many seconds.
    Incorrect { fails: u32, wait: u64 },
    /// A valid TOTP code that was already used; wait for the next one.
    Replayed,
    /// Still locked out; nothing was checked.
    Throttled { wait: u64 },
    /// The wall is not locked.
    NotLocked,
}

impl UnlockOutcome {
    /// The line for the unlock card ("" when there is nothing to say).
    pub fn message(self) -> String {
        match self {
            UnlockOutcome::Unlocked(_) | UnlockOutcome::NotLocked => String::new(),
            UnlockOutcome::Incorrect { wait: 0, .. } => "Incorrect".to_string(),
            UnlockOutcome::Incorrect { fails, wait } => format!("Incorrect — locked for {wait}s ({fails} attempts)"),
            UnlockOutcome::Replayed => "That code was already used — wait for the next one".to_string(),
            UnlockOutcome::Throttled { wait } => format!("Locked — try again in {wait}s"),
        }
    }
}

/// What [`KioskLock::restore`] found at start-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restore {
    NotEngaged,
    /// The wall was locked when it went down: raise the overlay again.
    Engaged,
    /// As above, but nothing can currently unlock it (for example the only
    /// credential is a vault TOTP and the vault is not open yet). The lock
    /// stays engaged; an administrator can clear it with
    /// [`KioskLock::force_unlock`].
    EngagedWithoutCredential,
}

/// How the overlay should treat a key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    /// Escape: swallowed — there is no "close to bypass".
    Swallow,
    /// Enter: try the typed code.
    Submit,
    /// Anything else goes to the entry.
    Forward,
}

/// The lock itself. One per wall; calling [`lock`](Self::lock) while locked
/// does not stack.
#[derive(Debug)]
pub struct KioskLock {
    store: LockStore,
    locked: bool,
}

impl KioskLock {
    pub fn new(state_dir: &Path) -> KioskLock {
        KioskLock::with_store(LockStore::new(state_dir))
    }

    pub fn with_store(store: LockStore) -> KioskLock {
        KioskLock { store, locked: false }
    }

    pub fn store(&self) -> &LockStore {
        &self.store
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Re-engage a lock that was up when the process last stopped. Call once
    /// at start-up, before the wall accepts input.
    pub fn restore(&mut self, sources: &LockSources<'_>) -> Restore {
        if !fsio::exists(&self.store.marker) {
            return Restore::NotEngaged;
        }
        self.locked = true;
        if self.store.has_credential(sources) { Restore::Engaged } else { Restore::EngagedWithoutCredential }
    }

    /// Engage the lock. Fails closed: with nothing enrolled it refuses, since
    /// an overlay any keypress dismisses is worse than none.
    pub fn lock(&mut self, sources: &LockSources<'_>, now: u64) -> LockRequest {
        if self.locked {
            return LockRequest::AlreadyLocked;
        }
        if !self.store.has_credential(sources) {
            return LockRequest::NoCredential;
        }
        self.locked = true;
        // Best effort: an unwritable state directory must not stop the lock
        // itself, it only costs the restart persistence.
        let _ = fsio::write_atomic(&self.store.marker, format!("{now}\n").as_bytes()); // audit-allow: best-effort, see comment above
        LockRequest::Engaged
    }

    /// Which credentials to ask for on the unlock card.
    pub fn hint(&self, sources: &LockSources<'_>) -> LockHint {
        let has_totp = self.store.totp.is_set() || sources.vault_totp.is_some();
        match (self.store.pin.is_set(), has_totp) {
            (true, true) => LockHint::PinOrTotp,
            (false, true) => LockHint::Totp,
            (true, false) => LockHint::Pin,
            (false, false) => LockHint::AdminPin,
        }
    }

    /// Seconds until the next attempt is allowed.
    pub fn remaining(&self, now: u64) -> u64 {
        self.store.budget.remaining(now)
    }

    /// Try to unlock with `code` (surrounding whitespace ignored). May block
    /// for the PIN stretch and the admin verifier; nothing here touches GTK,
    /// so it can run on a worker.
    pub fn try_unlock(&mut self, code: &str, sources: &LockSources<'_>, now: u64) -> UnlockOutcome {
        if !self.locked {
            return UnlockOutcome::NotLocked;
        }
        let code = code.trim();
        let store = &self.store;
        let outcome = store.budget.transact(|state, schedule| {
            let wait = state.remaining(now);
            if wait > 0 {
                return UnlockOutcome::Throttled { wait };
            }
            match store.check(code, sources, now) {
                Some(Match::Static(method)) => {
                    state.passed();
                    UnlockOutcome::Unlocked(method)
                }
                Some(Match::Timed(method, step)) => {
                    if state.accept_totp_step(step, now) {
                        state.passed();
                        UnlockOutcome::Unlocked(method)
                    } else {
                        UnlockOutcome::Replayed
                    }
                }
                None => {
                    let wait = state.failed(schedule, now);
                    UnlockOutcome::Incorrect { fails: state.fails, wait }
                }
            }
        });
        if matches!(outcome, UnlockOutcome::Unlocked(_)) {
            self.release();
        }
        outcome
    }

    /// Drop the lock without a code — the administrator's emergency clear
    /// (reachable over SSH, never from the glass).
    pub fn force_unlock(&mut self) {
        self.release();
    }

    fn release(&mut self) {
        self.locked = false;
        let _ = fsio::remove(&self.store.marker); // audit-allow: best-effort; a stale marker only re-locks, and unlock must not fail
    }

    /// Escape never closes the lock; Enter submits.
    pub fn key_action(is_escape: bool, is_enter: bool) -> KeyAction {
        if is_escape {
            KeyAction::Swallow
        } else if is_enter {
            KeyAction::Submit
        } else {
            KeyAction::Forward
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::MIN_PBKDF2_ITERATIONS;
    use crate::testutil::TempDir;

    const T0: u64 = 1_700_000_000;
    const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    const VAULT_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const NONE: LockSources<'static> = LockSources { vault_totp: None, admin_pin: None };

    fn store(dir: &TempDir) -> LockStore {
        LockStore::new(dir.path()).with_pin_iterations(MIN_PBKDF2_ITERATIONS)
    }

    fn lock(dir: &TempDir) -> KioskLock {
        KioskLock::with_store(store(dir))
    }

    fn code(secret: &str, now: u64) -> String {
        totp::code_at(secret, now).unwrap().to_string()
    }

    /// A lock that is engaged, with a PIN enrolled.
    fn locked_with_pin(dir: &TempDir, pin: &str) -> KioskLock {
        let mut k = lock(dir);
        k.store().pin().set(pin).unwrap();
        assert_eq!(k.lock(&NONE, T0), LockRequest::Engaged);
        k
    }

    #[test]
    fn pin_store_roundtrip_in_its_own_file() {
        let dir = TempDir::new();
        let s = store(&dir);
        assert!(!s.pin().is_set());
        s.pin().set("2468").unwrap();
        assert!(s.pin().is_set() && s.pin().verify("2468") && !s.pin().verify("0000"));
        // panellock.pin is not the settings gate's config.pin: the desk PIN
        // and the admin PIN are meant to differ.
        assert!(dir.path().join("panellock.pin").exists());
        assert!(!dir.path().join("config.pin").exists());
        let raw = std::fs::read_to_string(s.pin().path()).unwrap();
        assert!(!raw.contains("2468") && raw.contains('$'));
        s.pin().clear().unwrap();
        assert!(!s.pin().is_set());
    }

    #[test]
    fn totp_store_set_clear_load() {
        let dir = TempDir::new();
        let s = store(&dir);
        assert!(!s.totp().is_set() && s.totp().load().is_none());
        s.totp().save(SECRET).unwrap();
        assert_eq!(s.totp().load().unwrap().as_str(), SECRET);
        s.totp().clear().unwrap();
        assert!(!s.totp().is_set() && s.totp().load().is_none());
        assert_eq!(s.status_text(), "PIN: (none)  ·  TOTP: (none)");
    }

    #[test]
    fn refuses_to_lock_with_nothing_enrolled() {
        let dir = TempDir::new();
        let mut k = lock(&dir);
        assert_eq!(k.lock(&NONE, T0), LockRequest::NoCredential);
        assert!(!k.is_locked());
        assert_eq!(k.try_unlock("2468", &NONE, T0), UnlockOutcome::NotLocked);
        assert!(NO_CREDENTIAL_ADVICE.contains("decorative"));
    }

    #[test]
    fn locking_twice_does_not_stack() {
        let dir = TempDir::new();
        let mut k = locked_with_pin(&dir, "2468");
        assert_eq!(k.lock(&NONE, T0), LockRequest::AlreadyLocked);
        assert!(k.is_locked());
    }

    #[test]
    fn pin_unlocks_and_wrong_or_empty_codes_do_not() {
        let dir = TempDir::new();
        let mut k = locked_with_pin(&dir, "2468");
        assert_eq!(k.hint(&NONE), LockHint::Pin);
        assert_eq!(k.try_unlock("9999", &NONE, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        assert_eq!(k.try_unlock("  ", &NONE, T0), UnlockOutcome::Incorrect { fails: 2, wait: 0 });
        assert!(k.is_locked());
        assert_eq!(k.try_unlock(" 2468 ", &NONE, T0), UnlockOutcome::Unlocked(Method::Pin));
        assert!(!k.is_locked());
    }

    #[test]
    fn totp_unlocks_once() {
        let dir = TempDir::new();
        let mut k = lock(&dir);
        k.store().totp().save(SECRET).unwrap();
        assert_eq!(k.lock(&NONE, T0), LockRequest::Engaged);
        assert_eq!(k.hint(&NONE), LockHint::Totp);
        assert_eq!(k.try_unlock("000000", &NONE, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        let good = code(SECRET, T0);
        assert_eq!(k.try_unlock(&good, &NONE, T0), UnlockOutcome::Unlocked(Method::Totp));
        // Someone watched the code being typed and re-locks/unlocks with it.
        assert_eq!(k.lock(&NONE, T0 + 5), LockRequest::Engaged);
        assert_eq!(k.try_unlock(&good, &NONE, T0 + 5), UnlockOutcome::Replayed);
        assert!(k.is_locked());
    }

    #[test]
    fn either_credential_unlocks_when_both_are_enrolled() {
        let dir = TempDir::new();
        let mut k = locked_with_pin(&dir, "8642");
        k.store().totp().save(SECRET).unwrap();
        assert_eq!(k.hint(&NONE), LockHint::PinOrTotp);
        assert_eq!(k.try_unlock("9999", &NONE, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        assert_eq!(k.try_unlock(&code(SECRET, T0), &NONE, T0), UnlockOutcome::Unlocked(Method::Totp));
        k.lock(&NONE, T0);
        assert_eq!(k.try_unlock("8642", &NONE, T0), UnlockOutcome::Unlocked(Method::Pin));
    }

    #[test]
    fn the_sealed_setup_pin_is_an_admin_override() {
        let dir = TempDir::new();
        let admin = |code: &str| code == "77553311";
        let sources = LockSources { vault_totp: None, admin_pin: Some(&admin) };
        let mut k = lock(&dir);
        assert!(k.store().has_credential(&sources), "a host seal is a real credential");
        assert_eq!(k.lock(&sources, T0), LockRequest::Engaged);
        assert_eq!(k.hint(&sources), LockHint::AdminPin);
        assert_eq!(k.try_unlock("1", &sources, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        assert_eq!(k.try_unlock("77553311", &sources, T0), UnlockOutcome::Unlocked(Method::AdminPin));
    }

    #[test]
    fn a_vault_secret_replaces_the_local_totp_file() {
        let dir = TempDir::new();
        let mut k = locked_with_pin(&dir, "8642");
        k.store().totp().save(SECRET).unwrap();
        let vault = LockSources { vault_totp: Some(VAULT_SECRET), admin_pin: None };
        // The stale local secret no longer unlocks...
        assert_eq!(k.try_unlock(&code(SECRET, T0), &vault, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        // ...the vault's does, and so does the file-backed PIN.
        assert_eq!(k.try_unlock(&code(VAULT_SECRET, T0), &vault, T0), UnlockOutcome::Unlocked(Method::VaultTotp));
        k.lock(&vault, T0);
        assert_eq!(k.try_unlock("8642", &vault, T0), UnlockOutcome::Unlocked(Method::Pin));
    }

    #[test]
    fn a_malformed_vault_secret_falls_back_to_the_local_files() {
        let dir = TempDir::new();
        let mut k = lock(&dir);
        k.store().totp().save(SECRET).unwrap();
        let vault = LockSources { vault_totp: Some("not base32 !!"), admin_pin: None };
        k.lock(&vault, T0);
        assert_eq!(k.try_unlock(&code(SECRET, T0), &vault, T0), UnlockOutcome::Unlocked(Method::Totp));
    }

    #[test]
    fn a_vault_only_wall_can_lock_and_unlock() {
        let dir = TempDir::new();
        let mut k = lock(&dir);
        let vault = LockSources { vault_totp: Some(VAULT_SECRET), admin_pin: None };
        assert_eq!(k.lock(&NONE, T0), LockRequest::NoCredential);
        assert_eq!(k.lock(&vault, T0), LockRequest::Engaged);
        assert_eq!(k.hint(&vault), LockHint::Totp);
        assert_eq!(k.try_unlock(&code(VAULT_SECRET, T0), &vault, T0), UnlockOutcome::Unlocked(Method::VaultTotp));
    }

    #[test]
    fn a_corrupt_totp_file_does_not_block_the_pin() {
        // The Python verifier raised on the bad secret before it ever looked
        // at the PIN, leaving a numeric PIN unable to unlock.
        let dir = TempDir::new();
        let mut k = locked_with_pin(&dir, "8642");
        std::fs::write(k.store().totp().path(), "not base32 !!\n").unwrap();
        assert_eq!(k.try_unlock("123456", &NONE, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        assert_eq!(k.try_unlock("8642", &NONE, T0), UnlockOutcome::Unlocked(Method::Pin));
    }

    #[test]
    fn wrong_codes_lock_the_input_and_the_lockout_is_enforced_here() {
        let dir = TempDir::new();
        let mut k = locked_with_pin(&dir, "8642");
        assert_eq!(k.try_unlock("1", &NONE, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        assert_eq!(k.try_unlock("2", &NONE, T0), UnlockOutcome::Incorrect { fails: 2, wait: 0 });
        let third = k.try_unlock("3", &NONE, T0);
        assert_eq!(third, UnlockOutcome::Incorrect { fails: 3, wait: 5 });
        assert_eq!(third.message(), "Incorrect — locked for 5s (3 attempts)");
        // Hammering Enter during the lockout neither verifies nor counts.
        for _ in 0..5 {
            assert_eq!(k.try_unlock("8642", &NONE, T0 + 1), UnlockOutcome::Throttled { wait: 4 });
        }
        assert_eq!(k.remaining(T0 + 1), 4);
        assert_eq!(k.try_unlock("4", &NONE, T0 + 5), UnlockOutcome::Incorrect { fails: 4, wait: 10 });
        assert_eq!(k.try_unlock("8642", &NONE, T0 + 14), UnlockOutcome::Throttled { wait: 1 });
        assert_eq!(k.try_unlock("8642", &NONE, T0 + 15), UnlockOutcome::Unlocked(Method::Pin));
    }

    #[test]
    fn the_lock_and_its_back_off_survive_a_restart() {
        let dir = TempDir::new();
        let mut k = locked_with_pin(&dir, "8642");
        for guess in ["1", "2", "3"] {
            k.try_unlock(guess, &NONE, T0);
        }
        drop(k);

        let mut restarted = lock(&dir);
        assert!(!restarted.is_locked());
        assert_eq!(restarted.restore(&NONE), Restore::Engaged);
        assert!(restarted.is_locked());
        assert_eq!(restarted.try_unlock("8642", &NONE, T0 + 1), UnlockOutcome::Throttled { wait: 4 });
        assert_eq!(restarted.try_unlock("8642", &NONE, T0 + 6), UnlockOutcome::Unlocked(Method::Pin));
        drop(restarted);
        assert_eq!(lock(&dir).restore(&NONE), Restore::NotEngaged, "an unlock clears the marker");
    }

    #[test]
    fn a_restored_lock_without_a_credential_stays_shut_until_forced() {
        let dir = TempDir::new();
        let vault = LockSources { vault_totp: Some(VAULT_SECRET), admin_pin: None };
        let mut k = lock(&dir);
        k.lock(&vault, T0);
        drop(k);

        // After the restart the vault is not open yet.
        let mut restarted = lock(&dir);
        assert_eq!(restarted.restore(&NONE), Restore::EngagedWithoutCredential);
        assert_eq!(restarted.try_unlock("123456", &NONE, T0), UnlockOutcome::Incorrect { fails: 1, wait: 0 });
        assert!(restarted.is_locked());
        // Once it is, its code works; or an administrator clears the lock.
        assert_eq!(
            restarted.try_unlock(&code(VAULT_SECRET, T0), &vault, T0),
            UnlockOutcome::Unlocked(Method::VaultTotp)
        );
        restarted.lock(&vault, T0);
        restarted.force_unlock();
        assert!(!restarted.is_locked());
        assert_eq!(lock(&dir).restore(&NONE), Restore::NotEngaged);
    }

    #[test]
    fn enrolment_and_keys() {
        let dir = TempDir::new();
        let s = store(&dir);
        let enrolled = s.enroll_totp().unwrap();
        assert!(enrolled.uri.starts_with("otpauth://totp/SOC%20Wall%20%E2%80%94%20Panel%20lock:kiosk@soc.local?"));
        assert_eq!(s.status_text(), "PIN: (none)  ·  TOTP: SET ✓");
        assert_eq!(KioskLock::key_action(true, false), KeyAction::Swallow);
        assert_eq!(KioskLock::key_action(false, true), KeyAction::Submit);
        assert_eq!(KioskLock::key_action(false, false), KeyAction::Forward);
        assert_eq!(LockHint::Pin.text(), "Enter your PIN.");
    }
}
