//! Time and cancellation, behind a trait so the reconnect policy is tested
//! against a virtual clock instead of real sleeps.

use crate::lock;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A cancellation flag that also wakes every thread waiting on it, so a stop
/// request ends a five-minute lockout hold at once.
#[derive(Clone, Default)]
pub struct StopFlag(Arc<(Mutex<bool>, Condvar)>);

impl StopFlag {
    pub fn new() -> StopFlag {
        StopFlag::default()
    }

    pub fn set(&self) {
        *lock(&self.0.0) = true;
        self.0.1.notify_all();
    }

    pub fn is_set(&self) -> bool {
        *lock(&self.0.0)
    }

    /// Block for up to `timeout`; true once the flag is set.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let guard = lock(&self.0.0);
        match self.0.1.wait_timeout_while(guard, timeout, |set| !*set) {
            Ok((guard, _)) => *guard,
            Err(poisoned) => *poisoned.into_inner().0,
        }
    }
}

/// Seconds as a `Duration`; negative, NaN and absurd values clamp instead of
/// panicking.
pub fn secs(seconds: f64) -> Duration {
    if seconds.is_nan() || seconds <= 0.0 {
        return Duration::ZERO;
    }
    Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX)
}

/// The supervisor's view of time. All values are seconds.
pub trait Clock: Send + Sync {
    /// Monotonic time since an arbitrary origin.
    fn now(&self) -> f64;
    /// Wall-clock seconds since the Unix epoch (WireGuard handshake ages).
    fn unix_time(&self) -> f64;
    /// Wait up to `seconds`, returning early — and true — once `stop` is set.
    fn wait(&self, stop: &StopFlag, seconds: f64) -> bool;
    /// Wait `seconds` regardless of any stop request (grace periods).
    fn sleep(&self, seconds: f64);
}

/// The real clock.
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock { origin: Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }

    fn unix_time(&self) -> f64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }

    fn wait(&self, stop: &StopFlag, seconds: f64) -> bool {
        stop.wait_timeout(secs(seconds))
    }

    fn sleep(&self, seconds: f64) {
        std::thread::sleep(secs(seconds));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_flag_ends_a_long_wait_at_once() {
        let stop = StopFlag::new();
        let waiter = stop.clone();
        let t = std::thread::spawn(move || waiter.wait_timeout(Duration::from_secs(30)));
        stop.set();
        assert!(t.join().unwrap());
        assert!(stop.is_set());
    }

    #[test]
    fn an_unset_flag_times_out() {
        assert!(!StopFlag::new().wait_timeout(Duration::from_millis(5)));
    }

    #[test]
    fn hostile_durations_clamp() {
        assert_eq!(secs(-1.0), Duration::ZERO);
        assert_eq!(secs(f64::NAN), Duration::ZERO);
        assert_eq!(secs(f64::INFINITY), Duration::MAX);
        assert_eq!(secs(1.5), Duration::from_millis(1500));
    }
}
