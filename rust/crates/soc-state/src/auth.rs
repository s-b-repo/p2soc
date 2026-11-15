//! The settings gate: the PIN or TOTP code that opens the settings window and
//! confirms every destructive action inside it.
//!
//! One [`SettingsAuth::attempt`] call checks the back-off, verifies the code
//! and records the outcome under a single lock. The Python window checked the
//! back-off when a prompt *opened* and verified when it was answered, so a
//! prompt left open rode through a lockout; there is no such gap here.

use crate::authstate::{Budget, Schedule};
use crate::error::Result;
use crate::pin::PinFile;
use crate::totp::{self, TotpFile};
use std::path::Path;
use zeroize::Zeroizing;

/// Which credential a code matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Pin,
    Totp,
    /// The kiosk lock's TOTP secret held in the vault.
    VaultTotp,
    /// The host's sealed setup PIN (the lock's admin override).
    AdminPin,
}

/// What became of one code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    Granted(Method),
    /// Wrong. `cooldown` is the lockout this failure started (0: none yet).
    Rejected {
        cooldown: u64,
    },
    /// A valid TOTP code that was already used. Not counted as a failure:
    /// the operator simply waits for the next code.
    Replayed,
    /// Too many wrong codes; nothing was checked. Try again in `wait` seconds.
    Throttled {
        wait: u64,
    },
    /// No PIN and no TOTP is enrolled, so nothing can match.
    NotEnrolled,
}

impl AuthOutcome {
    pub fn granted(self) -> bool {
        matches!(self, AuthOutcome::Granted(_))
    }
}

/// A freshly enrolled TOTP secret, to show once.
pub struct Enrollment {
    pub secret: Zeroizing<String>,
    /// The `otpauth://` URI for the authenticator app (it embeds the secret).
    pub uri: String,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Enrollment(<redacted>)")
    }
}

pub(crate) enum Match {
    Static(Method),
    Timed(Method, u64),
}

/// The settings credentials under one state directory:
/// `config.pin`, `config.totp` and their shared attempt budget.
#[derive(Debug)]
pub struct SettingsAuth {
    pin: PinFile,
    totp: TotpFile,
    budget: Budget,
}

impl SettingsAuth {
    pub fn new(state_dir: &Path) -> SettingsAuth {
        SettingsAuth {
            pin: PinFile::new(state_dir.join("config.pin")),
            totp: TotpFile::new(state_dir.join("config.totp")),
            budget: Budget::new(state_dir, "gate", Schedule::Gate),
        }
    }

    /// Use a cheaper PIN stretch for newly set PINs (tests).
    pub fn with_pin_iterations(mut self, iterations: u32) -> SettingsAuth {
        self.pin = self.pin.with_iterations(iterations);
        self
    }

    pub fn pin(&self) -> &PinFile {
        &self.pin
    }

    pub fn totp(&self) -> &TotpFile {
        &self.totp
    }

    /// The gate's attempt budget (for showing the remaining lockout).
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Whether any settings credential is enrolled — if so, the window is
    /// gated and destructive actions re-authenticate.
    pub fn reauth_required(&self) -> bool {
        self.pin.is_set() || self.totp.is_set()
    }

    /// Seconds until the next attempt is allowed.
    pub fn remaining(&self, now: u64) -> u64 {
        self.budget.remaining(now)
    }

    /// PIN first, then TOTP. A corrupt PIN file or TOTP secret matches
    /// nothing.
    fn check(&self, code: &str, now: u64) -> Option<Match> {
        if code.is_empty() {
            return None;
        }
        if self.pin.verify(code) {
            return Some(Match::Static(Method::Pin));
        }
        let secret = self.totp.load()?;
        totp::verify_step(&secret, code, now).map(|step| Match::Timed(Method::Totp, step))
    }

    /// Try `code` (surrounding whitespace ignored) against the settings PIN
    /// and TOTP. This is the only way to verify a code: it always goes through
    /// the back-off. May take a few hundred milliseconds (the PIN stretch).
    pub fn attempt(&self, code: &str, now: u64) -> AuthOutcome {
        let code = code.trim();
        self.budget.transact(|state, schedule| {
            let wait = state.remaining(now);
            if wait > 0 {
                return AuthOutcome::Throttled { wait };
            }
            if !self.reauth_required() {
                return AuthOutcome::NotEnrolled;
            }
            match self.check(code, now) {
                Some(Match::Static(method)) => {
                    state.passed();
                    AuthOutcome::Granted(method)
                }
                Some(Match::Timed(method, step)) => {
                    if state.accept_totp_step(step, now) {
                        state.passed();
                        AuthOutcome::Granted(method)
                    } else {
                        AuthOutcome::Replayed
                    }
                }
                None => AuthOutcome::Rejected { cooldown: state.failed(schedule, now) },
            }
        })
    }

    /// Generate and store a new settings TOTP secret, replacing any old one.
    pub fn enroll_totp(&self) -> Result<Enrollment> {
        enroll(&self.totp, totp::ISSUER_SETTINGS)
    }
}

/// Mint a secret into `file` and build its provisioning URI.
pub(crate) fn enroll(file: &TotpFile, issuer: &str) -> Result<Enrollment> {
    let secret = totp::generate_secret()?;
    file.save(&secret)?;
    let uri = totp::provision_uri(&secret, totp::DEFAULT_LABEL, issuer);
    Ok(Enrollment { secret, uri })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::MIN_PBKDF2_ITERATIONS;
    use crate::testutil::TempDir;

    const T0: u64 = 1_700_000_000;
    const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    fn auth(dir: &TempDir) -> SettingsAuth {
        SettingsAuth::new(dir.path()).with_pin_iterations(MIN_PBKDF2_ITERATIONS)
    }

    fn code(now: u64) -> String {
        totp::code_at(SECRET, now).unwrap().to_string()
    }

    #[test]
    fn nothing_enrolled_means_nothing_matches() {
        let dir = TempDir::new();
        let a = auth(&dir);
        assert!(!a.reauth_required());
        assert_eq!(a.attempt("321987", T0), AuthOutcome::NotEnrolled);
        assert_eq!(a.attempt("", T0), AuthOutcome::NotEnrolled);
        assert_eq!(a.budget().fails(), 0, "not counted: there is nothing to guess");
    }

    #[test]
    fn pin_is_accepted_and_wrong_or_empty_codes_are_not() {
        let dir = TempDir::new();
        let a = auth(&dir);
        a.pin().set("321987").unwrap();
        assert!(a.reauth_required());
        assert_eq!(a.attempt("321987", T0), AuthOutcome::Granted(Method::Pin));
        assert_eq!(a.attempt("  321987\n", T0), AuthOutcome::Granted(Method::Pin));
        assert_eq!(a.attempt("wrong0", T0), AuthOutcome::Rejected { cooldown: 0 });
        assert_eq!(a.attempt("   ", T0), AuthOutcome::Rejected { cooldown: 0 });
    }

    #[test]
    fn totp_is_accepted_once_per_step() {
        let dir = TempDir::new();
        let a = auth(&dir);
        a.totp().save(SECRET).unwrap();
        assert!(a.reauth_required());
        assert_eq!(a.attempt("000000", T0), AuthOutcome::Rejected { cooldown: 0 });
        assert_eq!(a.attempt(&code(T0), T0), AuthOutcome::Granted(Method::Totp));
        // Shoulder-surfed and typed again within the window: refused, and the
        // refusal does not eat into the operator's attempts.
        assert_eq!(a.attempt(&code(T0), T0 + 10), AuthOutcome::Replayed);
        assert_eq!(a.attempt(&code(T0), T0 + 31), AuthOutcome::Replayed);
        assert_eq!(a.budget().fails(), 0);
        assert_eq!(a.attempt(&code(T0 + 30), T0 + 31), AuthOutcome::Granted(Method::Totp));
    }

    #[test]
    fn replay_protection_survives_a_restart() {
        let dir = TempDir::new();
        let first = auth(&dir);
        first.totp().save(SECRET).unwrap();
        assert!(first.attempt(&code(T0), T0).granted());
        drop(first);
        assert_eq!(auth(&dir).attempt(&code(T0), T0 + 5), AuthOutcome::Replayed);
    }

    #[test]
    fn either_credential_opens_the_gate_when_both_are_enrolled() {
        let dir = TempDir::new();
        let a = auth(&dir);
        a.pin().set("864213").unwrap();
        a.totp().save(SECRET).unwrap();
        assert_eq!(a.attempt("864213", T0), AuthOutcome::Granted(Method::Pin));
        assert_eq!(a.attempt(&code(T0), T0), AuthOutcome::Granted(Method::Totp));
        assert_eq!(a.attempt("999999", T0), AuthOutcome::Rejected { cooldown: 0 });
    }

    #[test]
    fn corrupt_credentials_fail_closed() {
        let dir = TempDir::new();
        let a = auth(&dir);
        std::fs::write(a.totp().path(), "not base32 !!\n").unwrap();
        std::fs::write(a.pin().path(), "00$\u{e9}").unwrap();
        assert!(a.reauth_required(), "the gate stays shut");
        assert_eq!(a.attempt("123456", T0), AuthOutcome::Rejected { cooldown: 0 });
        assert_eq!(a.attempt("1234", T0), AuthOutcome::Rejected { cooldown: 0 });
    }

    #[test]
    fn wrong_codes_back_off_and_even_the_right_code_must_wait() {
        let dir = TempDir::new();
        let a = auth(&dir);
        a.pin().set("864213").unwrap();
        assert_eq!(a.attempt("0000", T0), AuthOutcome::Rejected { cooldown: 0 });
        assert_eq!(a.attempt("0000", T0), AuthOutcome::Rejected { cooldown: 0 });
        assert_eq!(a.attempt("0000", T0), AuthOutcome::Rejected { cooldown: 5 });
        assert_eq!(a.remaining(T0), 5);
        assert_eq!(a.attempt("864213", T0 + 1), AuthOutcome::Throttled { wait: 4 });
        assert_eq!(a.attempt("0000", T0 + 1), AuthOutcome::Throttled { wait: 4 });
        assert_eq!(a.budget().fails(), 3, "a throttled try is not verified, so not counted");
        assert_eq!(a.attempt("0000", T0 + 5), AuthOutcome::Rejected { cooldown: 10 });
        assert_eq!(a.attempt("864213", T0 + 15), AuthOutcome::Granted(Method::Pin));
        assert_eq!(a.attempt("0000", T0 + 15), AuthOutcome::Rejected { cooldown: 0 }, "a pass resets the streak");
    }

    #[test]
    fn reopening_the_window_or_restarting_does_not_reset_the_back_off() {
        let dir = TempDir::new();
        let window = auth(&dir);
        window.pin().set("864213").unwrap();
        for _ in 0..3 {
            window.attempt("0000", T0);
        }
        drop(window);
        // main builds a new window (and after a restart, a new process) each time.
        let again = auth(&dir);
        assert_eq!(again.remaining(T0), 5);
        assert_eq!(again.attempt("864213", T0), AuthOutcome::Throttled { wait: 5 });
    }

    #[test]
    fn a_second_prompt_shares_the_budget_with_the_first() {
        let dir = TempDir::new();
        let (page, reauth) = (auth(&dir), auth(&dir));
        page.pin().set("864213").unwrap();
        page.attempt("1", T0);
        reauth.attempt("2", T0);
        assert_eq!(page.attempt("3", T0), AuthOutcome::Rejected { cooldown: 5 });
        // The prompt that was already open cannot be used to keep guessing.
        assert_eq!(reauth.attempt("864213", T0), AuthOutcome::Throttled { wait: 5 });
    }

    #[test]
    fn enrolment_writes_a_working_secret() {
        let dir = TempDir::new();
        let a = auth(&dir);
        let enrolled = a.enroll_totp().unwrap();
        assert!(enrolled.uri.starts_with("otpauth://totp/SOC%20Wall%20%E2%80%94%20Settings:kiosk@soc.local?secret="));
        assert_eq!(a.totp().load().unwrap().as_str(), enrolled.secret.as_str());
        let now_code = totp::code_at(&enrolled.secret, T0).unwrap();
        assert_eq!(a.attempt(&now_code, T0), AuthOutcome::Granted(Method::Totp));
        a.totp().clear().unwrap();
        assert!(!a.reauth_required());
    }
}
