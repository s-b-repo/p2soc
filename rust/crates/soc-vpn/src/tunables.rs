//! The `SOC_VPN_*` environment tunables, parsed once.
//!
//! Reading the environment is confined to [`Tunables::from_env`]; everything
//! else takes a `Tunables` value, so tests set timings directly.

use soc_core::env::{parse_bool, parse_float};

/// Longest a waiting loop goes without a watchdog heartbeat.
pub const TICK: f64 = 5.0;

#[derive(Debug, Clone, PartialEq)]
pub struct Tunables {
    /// `SOC_VPN_BACKOFF_INITIAL` — first reconnect delay after a drop.
    pub backoff_initial: f64,
    /// `SOC_VPN_BACKOFF_MAX` — reconnect delay ceiling.
    pub backoff_max: f64,
    /// `SOC_VPN_AUTH_RETRY_DELAY` — hold after rejected credentials.
    pub auth_delay: f64,
    /// `SOC_VPN_CERT_RETRY_DELAY` — hold after a certificate failure.
    pub cert_delay: f64,
    /// `SOC_VPN_CONNECT_TIMEOUT` — restart a client showing no tunnel after
    /// this long; 0 disables.
    pub connect_timeout: f64,
    /// `SOC_READY_TIMEOUT` — how long one attempt waits for the vault.
    pub ready_timeout: f64,
    /// `SOC_VPN_STALL_SECS` — a supervisor silent for this long is wedged.
    pub stall_secs: f64,
    /// `SOC_VPN_STATUS_INTERVAL` — seconds between `STATUS=` probe rounds.
    pub status_interval: f64,
    /// `SOC_VPN_DRY_RUN=1` — resolve and print the command, connect nothing.
    pub dry_run: bool,
    /// `SOC_VPN_OTP_ARGV=1` — pass the one-time code as `--otp=` on argv (the
    /// legacy behaviour) instead of through the pinentry helper. Needed only
    /// with a third-party pinentry that cannot answer a token request.
    pub otp_on_argv: bool,
    /// Half of systemd's `WatchdogSec` (0 when there is no watchdog).
    pub watchdog_interval: f64,
    /// Heartbeat granularity of long waits.
    pub tick: f64,
    /// How often a running client is polled.
    pub poll: f64,
    /// SIGTERM-to-SIGKILL grace for a client being stopped.
    pub term_grace: f64,
    /// Pause between the two tries at a one-time code.
    pub otp_retry_wait: f64,
    /// Gap between supervisor starts, so N vault unseals do not land at once.
    pub start_stagger: f64,
}

impl Default for Tunables {
    fn default() -> Self {
        Tunables {
            backoff_initial: 5.0,
            backoff_max: 60.0,
            auth_delay: 300.0,
            cert_delay: 300.0,
            connect_timeout: 300.0,
            ready_timeout: 120.0,
            stall_secs: 300.0,
            status_interval: 30.0,
            dry_run: false,
            otp_on_argv: false,
            watchdog_interval: 0.0,
            tick: TICK,
            poll: 1.0,
            term_grace: 10.0,
            otp_retry_wait: 2.0,
            start_stagger: 0.4,
        }
    }
}

impl Tunables {
    /// Parse from a variable lookup. Garbage falls back to the default and
    /// out-of-range values clamp: a typo must never crash the VPN at boot.
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Tunables {
        let float =
            |name: &str, default: f64, lo: f64, hi: Option<f64>| parse_float(get(name), name, default, Some(lo), hi);
        let d = Tunables::default();
        Tunables {
            backoff_initial: float("SOC_VPN_BACKOFF_INITIAL", d.backoff_initial, 0.1, Some(3600.0)),
            backoff_max: float("SOC_VPN_BACKOFF_MAX", d.backoff_max, 0.1, Some(3600.0)),
            // Floors of 1s: at 0 a fast-failing login would respawn in a tight
            // loop — a CPU spin and exactly the rapid retry that locks accounts.
            auth_delay: float("SOC_VPN_AUTH_RETRY_DELAY", d.auth_delay, 1.0, None),
            cert_delay: float("SOC_VPN_CERT_RETRY_DELAY", d.cert_delay, 1.0, None),
            connect_timeout: float("SOC_VPN_CONNECT_TIMEOUT", d.connect_timeout, 0.0, Some(3600.0)),
            ready_timeout: float("SOC_READY_TIMEOUT", d.ready_timeout, 0.0, Some(3600.0)),
            stall_secs: float("SOC_VPN_STALL_SECS", d.stall_secs, 60.0, Some(3600.0)),
            status_interval: float("SOC_VPN_STATUS_INTERVAL", d.status_interval, 5.0, Some(3600.0)),
            dry_run: get("SOC_VPN_DRY_RUN").as_deref() == Some("1"),
            otp_on_argv: parse_bool(get("SOC_VPN_OTP_ARGV"), "SOC_VPN_OTP_ARGV", false),
            watchdog_interval: crate::notify::watchdog_interval(
                get("WATCHDOG_USEC").as_deref(),
                get("WATCHDOG_PID").as_deref(),
                std::process::id(),
            ),
            ..d
        }
    }

    pub fn from_env() -> Tunables {
        Tunables::from_lookup(&|name| std::env::var(name).ok())
    }

    /// The retry delay while the vault (or a one-time code) is unavailable:
    /// slower than a network backoff, never longer than the auth hold.
    pub fn slow_retry(&self) -> f64 {
        self.auth_delay.min(60.0)
    }

    /// How long a tunnel must stay up before a drop resets the backoff. It has
    /// to outlive the longest delay we would otherwise impose: resetting any
    /// sooner lets a link that survives a few seconds per try reconnect at the
    /// floor forever.
    pub fn stable_after(&self) -> f64 {
        self.backoff_max.max(60.0)
    }

    /// Heartbeat granularity: never longer than the watchdog's own interval.
    pub fn heartbeat(&self) -> f64 {
        if self.watchdog_interval > 0.0 { self.tick.min(self.watchdog_interval) } else { self.tick }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn from(pairs: &[(&str, &str)]) -> Tunables {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Tunables::from_lookup(&|name| map.get(name).cloned())
    }

    #[test]
    fn defaults_match_the_documented_values() {
        let t = from(&[]);
        assert_eq!((t.backoff_initial, t.backoff_max), (5.0, 60.0));
        assert_eq!((t.auth_delay, t.cert_delay), (300.0, 300.0));
        assert_eq!((t.connect_timeout, t.ready_timeout), (300.0, 120.0));
        assert_eq!((t.stall_secs, t.status_interval), (300.0, 30.0));
        assert!(!t.dry_run && !t.otp_on_argv);
        assert_eq!(t.slow_retry(), 60.0);
        assert_eq!(t.stable_after(), 60.0);
        assert_eq!(t.heartbeat(), 5.0);
    }

    #[test]
    fn a_zero_retry_delay_is_clamped_so_a_bad_password_cannot_spin() {
        let t = from(&[("SOC_VPN_AUTH_RETRY_DELAY", "0"), ("SOC_VPN_CERT_RETRY_DELAY", "0")]);
        assert!(t.auth_delay >= 1.0 && t.cert_delay >= 1.0 && t.slow_retry() >= 1.0);
    }

    #[test]
    fn garbage_and_out_of_range_values_fall_back_or_clamp() {
        let t = from(&[
            ("SOC_VPN_BACKOFF_INITIAL", "abc"),
            ("SOC_VPN_BACKOFF_MAX", "999999"),
            ("SOC_VPN_STALL_SECS", "1"),
            ("SOC_VPN_STATUS_INTERVAL", "0"),
            ("SOC_VPN_CONNECT_TIMEOUT", "0"),
        ]);
        assert_eq!(t.backoff_initial, 5.0);
        assert_eq!(t.backoff_max, 3600.0);
        assert_eq!(t.stall_secs, 60.0);
        assert_eq!(t.status_interval, 5.0);
        assert_eq!(t.connect_timeout, 0.0);
        assert_eq!(t.stable_after(), 3600.0);
    }

    #[test]
    fn dry_run_needs_exactly_one() {
        assert!(from(&[("SOC_VPN_DRY_RUN", "1")]).dry_run);
        assert!(!from(&[("SOC_VPN_DRY_RUN", "true")]).dry_run);
    }

    #[test]
    fn the_heartbeat_never_outwaits_the_watchdog() {
        let pid = std::process::id().to_string();
        let t = from(&[("WATCHDOG_USEC", "4000000"), ("WATCHDOG_PID", &pid)]);
        assert_eq!(t.watchdog_interval, 2.0);
        assert_eq!(t.heartbeat(), 2.0);
    }
}
