//! Failed-attempt back-off and TOTP replay state, persisted.
//!
//! The Python wall kept its counters in process memory, so restarting the
//! wall (or power-cycling the board) handed out a fresh set of free guesses.
//! Here each budget lives in a small state file and is consulted *inside* the
//! verification call, so neither a restart, a reopened window nor a second
//! prompt gets around it.
//!
//! Deadlines are wall-clock seconds because they have to outlive the process.
//! Two guards keep a clock step from hurting: a lockout never reports more
//! than [`MAX_COOLDOWN_SECS`] remaining, and a remembered TOTP step that lies
//! in the future (the clock went backwards) is forgotten rather than locking
//! every later code out.

use crate::error::Result;
use crate::fsio;
use crate::totp;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// No lockout ever lasts longer than this.
pub const MAX_COOLDOWN_SECS: u64 = 60;
/// Wrong codes that cost nothing (typos).
pub const FREE_ATTEMPTS: u32 = 2;
/// A failure streak is forgotten after this long without another failure.
/// Waiting it out yields two guesses per quarter of an hour, far fewer than
/// the one a minute the capped back-off already allows.
pub const IDLE_RESET_SECS: u64 = 15 * 60;

const MAX_STATE_BYTES: u64 = 512;

/// How the cooldown grows with consecutive failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    /// The settings gate and its re-auth prompts: 5 s doubling to 60 s.
    Gate,
    /// The kiosk lock: 5 s more per failure, up to 60 s.
    Lock,
}

impl Schedule {
    /// The cooldown started by the `fails`-th consecutive failure (0: none).
    pub fn cooldown(self, fails: u32) -> u64 {
        if fails <= FREE_ATTEMPTS {
            return 0;
        }
        let over = u64::from(fails - FREE_ATTEMPTS);
        let secs = match self {
            Schedule::Gate => 5 * (1u64 << (over - 1).min(4)),
            Schedule::Lock => 5 * over,
        };
        secs.min(MAX_COOLDOWN_SECS)
    }
}

/// One budget's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthState {
    /// Consecutive failures.
    pub fails: u32,
    /// Unix time the current lockout ends (0: none).
    pub until: u64,
    /// Unix time of the latest failure.
    pub last_fail: u64,
    /// The newest TOTP time-step that was accepted.
    pub totp_step: u64,
}

impl AuthState {
    /// Seconds left on the lockout.
    pub fn remaining(&self, now: u64) -> u64 {
        self.until.saturating_sub(now).min(MAX_COOLDOWN_SECS)
    }

    /// Record a wrong code; returns the cooldown it started (0 if none).
    pub fn failed(&mut self, schedule: Schedule, now: u64) -> u64 {
        if self.remaining(now) == 0 && now.saturating_sub(self.last_fail) > IDLE_RESET_SECS {
            self.fails = 0;
        }
        self.fails = self.fails.saturating_add(1);
        self.last_fail = now;
        let cooldown = schedule.cooldown(self.fails);
        if cooldown > 0 {
            self.until = now.saturating_add(cooldown);
        }
        cooldown
    }

    /// Record a correct code.
    pub fn passed(&mut self) {
        self.fails = 0;
        self.until = 0;
    }

    /// Consume a TOTP time-step: `false` when that step (or a later one) was
    /// already used, i.e. the code is a replay.
    pub fn accept_totp_step(&mut self, step: u64, now: u64) -> bool {
        let newest_possible = (now / totp::STEP_SECS).saturating_add(totp::WINDOW.unsigned_abs());
        if self.totp_step > newest_possible {
            self.totp_step = 0;
        }
        if step <= self.totp_step {
            return false;
        }
        self.totp_step = step;
        true
    }

    fn to_json(self) -> String {
        json!({"fails": self.fails, "until": self.until, "last_fail": self.last_fail, "totp_step": self.totp_step})
            .to_string()
    }

    fn from_json(bytes: &[u8]) -> Option<AuthState> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        let field = |key: &str| value.get(key).and_then(Value::as_u64);
        Some(AuthState {
            fails: u32::try_from(field("fails")?).ok()?,
            until: field("until")?,
            last_fail: field("last_fail")?,
            totp_step: field("totp_step")?,
        })
    }
}

struct Cached {
    state: AuthState,
    /// The last save failed, so the file is behind this copy.
    unsaved: bool,
}

/// A persisted attempt budget. Create one per secret and keep it for the life
/// of the process; every prompt that guards the same secret shares it.
pub struct Budget {
    path: PathBuf,
    schedule: Schedule,
    cached: Mutex<Cached>,
}

impl std::fmt::Debug for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget").field("path", &self.path).field("schedule", &self.schedule).finish()
    }
}

impl Budget {
    /// The budget `name` under `state_dir` (stored as `auth-<name>.state`).
    pub fn new(state_dir: &Path, name: &str, schedule: Schedule) -> Budget {
        Budget {
            path: state_dir.join(format!("auth-{name}.state")),
            schedule,
            cached: Mutex::new(Cached { state: AuthState::default(), unsaved: false }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schedule(&self) -> Schedule {
        self.schedule
    }

    fn load(&self) -> AuthState {
        match fsio::read_capped(&self.path, MAX_STATE_BYTES) {
            Ok(None) => AuthState::default(),
            Ok(Some(bytes)) => AuthState::from_json(&bytes).unwrap_or(Self::distrusted()),
            Err(_) => Self::distrusted(), // audit-allow: an unreadable state file fails closed (distrusted)
        }
    }

    /// What an unreadable state file is taken to mean: the free attempts are
    /// already spent, so the next wrong code starts a cooldown. `last_fail` is
    /// a far-future sentinel so the idle-reset in [`AuthState::failed`] cannot
    /// mistake the distrusted state for an ancient one and hand the free
    /// attempts back — corrupting or deleting the file must never reset the
    /// back-off. The first real failure overwrites it with the true time.
    fn distrusted() -> AuthState {
        AuthState { fails: FREE_ATTEMPTS, last_fail: u64::MAX, ..AuthState::default() }
    }

    fn save(&self, state: AuthState) -> Result<()> {
        fsio::write_atomic(&self.path, state.to_json().as_bytes())
    }

    /// Run `f` on the current state under the budget's lock and persist what
    /// it leaves behind. The whole check-verify-record sequence of an attempt
    /// goes through here, which is what makes it atomic.
    pub(crate) fn transact<R>(&self, f: impl FnOnce(&mut AuthState, Schedule) -> R) -> R {
        let mut cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        // The file is the shared truth (another window's budget object may
        // have written it); the cached copy only stands in while the state
        // directory is unwritable, so a full disk cannot switch the back-off
        // off.
        let mut state = if cached.unsaved { cached.state } else { self.load() };
        let before = state;
        let out = f(&mut state, self.schedule);
        if state != before || cached.unsaved {
            cached.unsaved = self.save(state).is_err();
        }
        cached.state = state;
        out
    }

    /// Seconds until another attempt is allowed (0: now).
    pub fn remaining(&self, now: u64) -> u64 {
        self.transact(|state, _| state.remaining(now))
    }

    /// Record a wrong code; returns the cooldown it started (0 if none).
    pub fn failed(&self, now: u64) -> u64 {
        self.transact(|state, schedule| state.failed(schedule, now))
    }

    /// Record a correct code.
    pub fn passed(&self) {
        self.transact(|state, _| state.passed());
    }

    /// Consecutive failures so far.
    pub fn fails(&self) -> u32 {
        self.transact(|state, _| state.fails)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    const T0: u64 = 1_700_000_000;

    #[test]
    fn gate_schedule_and_cap() {
        let mut t = AuthState::default();
        let got: Vec<u64> = (0..9).map(|_| t.failed(Schedule::Gate, T0)).collect();
        assert_eq!(got, [0, 0, 5, 10, 20, 40, 60, 60, 60]);
        assert!(t.remaining(T0) > 0);
        t.passed();
        assert_eq!(t.remaining(T0), 0);
        assert_eq!(t.failed(Schedule::Gate, T0), 0);
    }

    #[test]
    fn lock_schedule_grows_linearly_to_the_cap() {
        let got: Vec<u64> = (1..=15).map(|n| Schedule::Lock.cooldown(n)).collect();
        assert_eq!(got, [0, 0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 60]);
        assert_eq!(Schedule::Lock.cooldown(u32::MAX), 60);
        assert_eq!(Schedule::Gate.cooldown(u32::MAX), 60);
    }

    #[test]
    fn remaining_counts_down_and_is_capped_against_clock_steps() {
        let mut t = AuthState::default();
        for _ in 0..3 {
            t.failed(Schedule::Gate, T0);
        }
        assert_eq!(t.remaining(T0), 5);
        assert_eq!(t.remaining(T0 + 4), 1);
        assert_eq!(t.remaining(T0 + 5), 0);
        // The clock jumped back a year: still at most the cap.
        assert_eq!(t.remaining(T0 - 31_536_000), MAX_COOLDOWN_SECS);
    }

    #[test]
    fn a_streak_is_forgotten_only_after_a_long_quiet_spell() {
        let mut t = AuthState::default();
        for _ in 0..4 {
            t.failed(Schedule::Gate, T0);
        }
        assert_eq!(t.failed(Schedule::Gate, T0 + IDLE_RESET_SECS), 20, "not yet idle long enough");
        assert_eq!(t.failed(Schedule::Gate, T0 + 3 * IDLE_RESET_SECS), 0, "streak forgotten");
        assert_eq!(t.fails, 1);
    }

    #[test]
    fn totp_steps_are_single_use() {
        let mut t = AuthState::default();
        let step = T0 / 30;
        assert!(t.accept_totp_step(step, T0));
        assert!(!t.accept_totp_step(step, T0), "same code again");
        assert!(!t.accept_totp_step(step - 1, T0), "an older code");
        assert!(t.accept_totp_step(step + 1, T0));
        t.passed();
        assert!(!t.accept_totp_step(step + 1, T0), "a pass does not reopen the step");
    }

    #[test]
    fn a_remembered_step_from_the_future_is_dropped() {
        let mut t = AuthState { totp_step: T0 / 30 + 1_000_000, ..AuthState::default() };
        assert!(t.accept_totp_step(T0 / 30, T0));
        assert_eq!(t.totp_step, T0 / 30);
    }

    #[test]
    fn the_budget_survives_a_restart() {
        let dir = TempDir::new();
        let first = Budget::new(dir.path(), "gate", Schedule::Gate);
        assert_eq!(first.remaining(T0), 0);
        assert_eq!([first.failed(T0), first.failed(T0), first.failed(T0)], [0, 0, 5]);
        drop(first);

        let reopened = Budget::new(dir.path(), "gate", Schedule::Gate);
        assert_eq!(reopened.remaining(T0 + 1), 4);
        assert_eq!(reopened.fails(), 3);
        assert_eq!(reopened.failed(T0 + 6), 10);
        reopened.passed();
        assert_eq!(Budget::new(dir.path(), "gate", Schedule::Gate).fails(), 0);
    }

    #[test]
    fn two_objects_for_one_secret_share_the_budget() {
        let dir = TempDir::new();
        let a = Budget::new(dir.path(), "gate", Schedule::Gate);
        let b = Budget::new(dir.path(), "gate", Schedule::Gate);
        a.failed(T0);
        b.failed(T0);
        assert_eq!(a.failed(T0), 5);
        assert_eq!(b.remaining(T0), 5);
        b.passed();
        assert_eq!(a.fails(), 0);
    }

    #[test]
    fn budgets_are_separate_per_name() {
        let dir = TempDir::new();
        let gate = Budget::new(dir.path(), "gate", Schedule::Gate);
        let os = Budget::new(dir.path(), "os", Schedule::Gate);
        for _ in 0..3 {
            gate.failed(T0);
        }
        assert_eq!(os.remaining(T0), 0);
        assert_eq!(os.fails(), 0);
    }

    #[test]
    fn a_corrupt_state_file_spends_the_free_attempts() {
        let dir = TempDir::new();
        let budget = Budget::new(dir.path(), "lock", Schedule::Lock);
        std::fs::write(budget.path(), b"{not json").unwrap();
        assert_eq!(budget.remaining(T0), 0);
        assert_eq!(budget.failed(T0), 5);
    }

    #[test]
    fn an_unwritable_state_dir_does_not_disable_the_back_off() {
        let dir = TempDir::new();
        // The "directory" is a file, so nothing can be written under it.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"").unwrap();
        let budget = Budget::new(&blocker, "gate", Schedule::Gate);
        // Unreadable state already counts as the free attempts being spent...
        assert_eq!(budget.failed(T0), 5);
        // ...and the streak is carried in memory although no save succeeds.
        assert_eq!(budget.failed(T0), 10);
        assert_eq!(budget.remaining(T0), 10);
        assert_eq!(budget.fails(), 4);
    }
}
