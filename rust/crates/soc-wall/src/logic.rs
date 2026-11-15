//! Engine-independent wall logic: the self-healing backoff of a panel, its
//! auto-login budget and small boot helpers. No GTK here,
//! so every decision the wall makes unattended is unit-tested.

use std::time::{Duration, Instant};

/// Seconds before the first load-failure retry.
pub const RETRY_INITIAL: u32 = 5;
/// Ceiling of the load-failure retry backoff.
pub const RETRY_MAX: u32 = 120;
/// A load must stay up this long before the backoff resets.
pub const PANEL_STABLE_SEC: f64 = 30.0;
/// Proxy auth attempts before giving up (a bad password must not hammer the
/// proxy and lock the account out).
pub const PROXY_AUTH_MAX_ATTEMPTS: u32 = 3;
/// Unattended: wait after a rejected proxy password, doubling up to the max.
pub const PROXY_RETRY_INITIAL: u32 = 300;
pub const PROXY_RETRY_MAX: u32 = 3600;
/// Real fill+submit attempts before the "please sign in" prompt.
pub const MAX_LOGIN_ATTEMPTS: u32 = 3;
/// Consecutive structural misses (form not fillable) before we stop
/// re-injecting and prompt instead.
pub const MAX_LOGIN_MISSES: u32 = 10;
/// Failures in a row after which an outage looks permanent (a config/URL
/// problem rather than a blip).
pub const PERSISTENT_FAILURES: u32 = 10;
/// ... or this long since the first failure of the streak.
pub const PERSISTENT_AFTER: Duration = Duration::from_secs(1800);

/// Retry backoff + continuous-failure tracking for one panel.
///
/// The retry *cadence* never stops (capped at [`RETRY_MAX`], forever); the
/// failure streak only switches the status card to clearer "this looks
/// permanent" wording.
#[derive(Debug, Clone)]
pub struct Healing {
    retry_delay: u32,
    loaded_at: Option<Instant>,
    consec_fail: u32,
    first_fail_at: Option<Instant>,
}

impl Default for Healing {
    fn default() -> Self {
        Healing { retry_delay: RETRY_INITIAL, loaded_at: None, consec_fail: 0, first_fail_at: None }
    }
}

impl Healing {
    /// Failures in the current streak.
    pub fn failures(&self) -> u32 {
        self.consec_fail
    }

    /// The delay the next retry will use.
    pub fn retry_delay(&self) -> u32 {
        self.retry_delay
    }

    /// Record one failure. Returns `(delay for this retry, looks permanent)`
    /// and doubles the delay for the next one.
    pub fn fail(&mut self, now: Instant) -> (u32, bool) {
        let first = *self.first_fail_at.get_or_insert(now);
        self.consec_fail = self.consec_fail.saturating_add(1);
        let persistent =
            self.consec_fail >= PERSISTENT_FAILURES || now.saturating_duration_since(first) >= PERSISTENT_AFTER;
        let delay = self.retry_delay;
        self.retry_delay = self.retry_delay.saturating_mul(2).min(RETRY_MAX);
        (delay, persistent)
    }

    /// A load finished cleanly. The backoff (and the failure streak) reset
    /// only once the *previous* load had stayed up for `stable_sec`: a
    /// renderer that loads and then OOM-crashes within seconds keeps climbing
    /// toward the cap instead of pinning a tight reload loop.
    pub fn finished(&mut self, now: Instant, stable_sec: f64) {
        if let Some(prev) = self.loaded_at {
            if now.saturating_duration_since(prev).as_secs_f64() >= stable_sec {
                self.reset_backoff();
            }
        }
        self.loaded_at = Some(now);
    }

    /// Forget the backoff and the streak (after a reconfigure or a recycle).
    pub fn reset_backoff(&mut self) {
        self.retry_delay = RETRY_INITIAL;
        self.consec_fail = 0;
        self.first_fail_at = None;
    }

    /// Only the retry delay (a deliberate recycle is not a fresh start for
    /// the failure streak).
    pub fn reset_delay(&mut self) {
        self.retry_delay = RETRY_INITIAL;
    }
}

/// What to do when the page asks to be logged in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStep {
    /// An injection is already in flight; ignore the duplicate request.
    Busy,
    /// Wrong/expired credentials: the attempt budget is spent — ask a person.
    PromptFailed,
    /// The page cannot be filled (wrong selectors): stop re-injecting.
    PromptUnfillable,
    /// Fetch credentials and inject.
    Inject,
}

/// The auto-login budget of one panel.
///
/// A real fill+submit that does not log in is counted against
/// [`MAX_LOGIN_ATTEMPTS`] — retrying a wrong password locks accounts. A
/// structural miss (the login function was not there yet, fields not found,
/// origin gate refused) is transient and only counts toward the much larger
/// [`MAX_LOGIN_MISSES`].
#[derive(Debug, Clone, Default)]
pub struct LoginBudget {
    attempts: u32,
    misses: u32,
    inflight: bool,
}

impl LoginBudget {
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn misses(&self) -> u32 {
        self.misses
    }

    pub fn exhausted(&self) -> bool {
        self.attempts >= MAX_LOGIN_ATTEMPTS || self.misses >= MAX_LOGIN_MISSES
    }

    /// A fresh page (or a confirmed login) gets a fresh budget.
    pub fn reset(&mut self) {
        *self = LoginBudget::default();
    }

    /// Decide what to do with a login request. On [`LoginStep::Inject`] the
    /// budget is marked in-flight until [`LoginBudget::result`] is called.
    pub fn next_step(&mut self) -> LoginStep {
        if self.inflight {
            LoginStep::Busy
        } else if self.attempts >= MAX_LOGIN_ATTEMPTS {
            LoginStep::PromptFailed
        } else if self.misses >= MAX_LOGIN_MISSES {
            LoginStep::PromptUnfillable
        } else {
            self.inflight = true;
            LoginStep::Inject
        }
    }

    /// The injection never happened (no credentials): release the guard.
    pub fn abort(&mut self) {
        self.inflight = false;
    }

    /// Record what the injected login did: `true` when it filled and
    /// submitted a form.
    pub fn result(&mut self, submitted: bool) {
        self.inflight = false;
        if submitted {
            self.attempts = self.attempts.saturating_add(1);
            self.misses = 0;
        } else {
            self.misses = self.misses.saturating_add(1);
        }
    }
}

/// Proxy-auth attempt tracking for one panel.
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    attempts: u32,
    retry_delay: u32,
}

impl Default for ProxyAuth {
    fn default() -> Self {
        ProxyAuth { attempts: 0, retry_delay: PROXY_RETRY_INITIAL }
    }
}

impl ProxyAuth {
    /// Count a challenge. `false` once the budget is spent (stop answering).
    pub fn challenge(&mut self) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        self.attempts <= PROXY_AUTH_MAX_ATTEMPTS
    }

    /// Unattended give-up: clear the budget and return how long to wait
    /// before the panel tries again (doubling, capped).
    pub fn hold(&mut self) -> u32 {
        self.attempts = 0;
        let delay = self.retry_delay;
        self.retry_delay = self.retry_delay.saturating_mul(2).min(PROXY_RETRY_MAX);
        delay
    }

    /// A finished load means the proxy accepted the credentials.
    pub fn accepted(&mut self) {
        *self = ProxyAuth::default();
    }
}

/// Capped exponential backoff for the unattended vault retry (attempt >= 1):
/// 3 s, 6 s, 12 s ... up to a minute.
pub fn vault_retry_delay(attempt: u32) -> Duration {
    let secs = 3.0 * 2f64.powi(i32::try_from(attempt.saturating_sub(1).min(16)).unwrap_or(16));
    Duration::from_secs_f64(secs.min(60.0))
}

/// Split a `host:port` readiness probe. `None` when malformed.
pub fn parse_probe(probe: &str) -> Option<(String, u16)> {
    let (host, port) = probe.trim().rsplit_once(':')?;
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    Some((host.to_string(), port))
}

/// The catch-all reason: right when someone has just typed a password.
pub const MASTER_REJECTED: &str = "Master password rejected — check it and try again.";

/// Turn a raw vault error into a short, operator-actionable reason for the
/// unlock prompt. A reachability fault and a credential rejection get
/// different guidance — otherwise the operator re-types a correct password
/// forever against a dead URL with no clue which of the two is wrong.
pub fn classify_unlock_error(message: &str, url: &str) -> String {
    let low = message.to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| low.contains(n));
    if has(&[
        "reach",
        "refused",
        "timed out",
        "timeout",
        "connection",
        "resolve",
        "name or service",
        "unreachable",
        "no route",
        "network is",
        "dns",
    ]) {
        let at = if url.is_empty() { String::new() } else { format!(" at {url}") };
        return format!(
            "Could not reach Vaultwarden{at} — check the server is running and the URL/account in Setup, then try \
             again."
        );
    }
    if has(&["429", "too many"]) {
        return "Vaultwarden is rate-limiting logins (too many attempts) — wait about a minute, then enter the \
                master once and try again."
            .into();
    }
    if has(&["no vault email", "set soc_vault_email"]) || (low.contains("email") && low.contains("no ")) {
        return "No vault account email is configured — the wall's environment was not loaded. Check that \
                /etc/soc-display/soc.env is readable and SOC_VAULT_EMAIL is set, then relaunch."
            .into();
    }
    if has(&["no vault master", "vault is locked"]) {
        return "This host has no sealed vault master password — provision it with Setup (the master is sealed \
                host-bound)."
            .into();
    }
    MASTER_REJECTED.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn backoff_doubles_to_the_cap() {
        let t0 = Instant::now();
        let mut h = Healing::default();
        let delays: Vec<u32> = (0..7).map(|_| h.fail(t0).0).collect();
        assert_eq!(delays, vec![5, 10, 20, 40, 80, 120, 120]);
    }

    #[test]
    fn failure_looks_permanent_after_ten_or_half_an_hour() {
        let t0 = Instant::now();
        let mut h = Healing::default();
        for _ in 0..9 {
            assert!(!h.fail(t0).1);
        }
        assert!(h.fail(t0).1, "tenth failure in a row");

        let mut h = Healing::default();
        assert!(!h.fail(t0).1);
        assert!(h.fail(t0 + secs(1800)).1, "still failing 30 minutes later");
    }

    #[test]
    fn backoff_resets_only_after_a_stable_load() {
        let t0 = Instant::now();
        let mut h = Healing::default();
        h.fail(t0);
        h.fail(t0);
        assert_eq!(h.retry_delay(), 20);

        // First-ever finished load just stamps the time.
        h.finished(t0 + secs(1), 30.0);
        assert_eq!(h.retry_delay(), 20);
        // A reload 5 s later (crash loop) does not reset anything.
        h.finished(t0 + secs(6), 30.0);
        assert_eq!((h.retry_delay(), h.failures()), (20, 2));
        // One that follows 30 s of uptime does.
        h.finished(t0 + secs(40), 30.0);
        assert_eq!((h.retry_delay(), h.failures()), (RETRY_INITIAL, 0));
    }

    #[test]
    fn wrong_password_spends_the_small_budget() {
        let mut b = LoginBudget::default();
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            assert_eq!(b.next_step(), LoginStep::Inject);
            b.result(true);
        }
        assert_eq!(b.next_step(), LoginStep::PromptFailed);
        assert!(b.exhausted());
    }

    #[test]
    fn transient_misses_do_not_spend_real_attempts() {
        let mut b = LoginBudget::default();
        for _ in 0..(MAX_LOGIN_MISSES - 1) {
            assert_eq!(b.next_step(), LoginStep::Inject);
            b.result(false);
        }
        assert_eq!(b.attempts(), 0);
        // A real submit clears the miss streak.
        assert_eq!(b.next_step(), LoginStep::Inject);
        b.result(true);
        assert_eq!((b.attempts(), b.misses()), (1, 0));

        for _ in 0..MAX_LOGIN_MISSES {
            assert_eq!(b.next_step(), LoginStep::Inject);
            b.result(false);
        }
        assert_eq!(b.next_step(), LoginStep::PromptUnfillable);
    }

    #[test]
    fn overlapping_login_requests_are_serialised() {
        let mut b = LoginBudget::default();
        assert_eq!(b.next_step(), LoginStep::Inject);
        assert_eq!(b.next_step(), LoginStep::Busy);
        b.abort();
        assert_eq!(b.next_step(), LoginStep::Inject);
    }

    #[test]
    fn proxy_auth_gives_up_then_holds_longer_each_time() {
        let mut p = ProxyAuth::default();
        assert!(p.challenge() && p.challenge() && p.challenge());
        assert!(!p.challenge());
        assert_eq!(p.hold(), 300);
        assert!(p.challenge(), "budget is fresh after a hold");
        assert_eq!(p.hold(), 600);
        for _ in 0..10 {
            p.hold();
        }
        assert_eq!(p.hold(), PROXY_RETRY_MAX);
        p.accepted();
        assert_eq!(p.hold(), 300);
    }

    #[test]
    fn vault_retry_backoff() {
        let s: Vec<u64> = (1..=7).map(|a| vault_retry_delay(a).as_secs()).collect();
        assert_eq!(s, vec![3, 6, 12, 24, 48, 60, 60]);
        assert_eq!(vault_retry_delay(0).as_secs(), 3);
        assert_eq!(vault_retry_delay(u32::MAX).as_secs(), 60);
    }

    #[test]
    fn probes() {
        assert_eq!(parse_probe("10.50.0.5:443"), Some(("10.50.0.5".into(), 443)));
        assert_eq!(parse_probe(" [fd00::1]:8443 "), Some(("fd00::1".into(), 8443)));
        for bad in ["", "host", "host:", ":443", "host:0", "host:99999", "host:4x"] {
            assert_eq!(parse_probe(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn unlock_errors_get_distinct_guidance() {
        let url = "http://127.0.0.1:8222";
        assert!(
            classify_unlock_error("Connection refused (os error 111)", url)
                .contains("Could not reach Vaultwarden at http")
        );
        assert!(classify_unlock_error("request timed out", "").starts_with("Could not reach Vaultwarden —"));
        assert!(classify_unlock_error("HTTP 429 Too Many Requests", url).contains("rate-limiting"));
        assert!(classify_unlock_error("no vault email configured", url).contains("SOC_VAULT_EMAIL"));
        assert!(classify_unlock_error("vault is locked", url).contains("no sealed vault master"));
        assert_eq!(classify_unlock_error("invalid_grant", url), MASTER_REJECTED);
        assert_eq!(classify_unlock_error("", url), MASTER_REJECTED);
    }
}
