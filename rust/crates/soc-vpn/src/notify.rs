//! The systemd notify protocol: `READY=1`, `STATUS=…` and `WATCHDOG=1`
//! datagrams to `$NOTIFY_SOCKET`.

use crate::clock::Clock;
use crate::lock;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::{Arc, Mutex};

/// The first message: the service is up even while tunnels still connect.
pub const READY: &str = "READY=1\nSTATUS=starting";
pub const WATCHDOG: &str = "WATCHDOG=1";

/// Where notify messages go.
pub trait Notifier: Send + Sync {
    /// Best effort: a lost status line must never take a tunnel down.
    fn notify(&self, state: &str);
}

/// Discards everything (outside systemd, and in dry runs).
pub struct NullNotifier;

impl Notifier for NullNotifier {
    fn notify(&self, _state: &str) {} // audit-allow: no-op by design
}

/// Sends to a `$NOTIFY_SOCKET`-style address; a no-op without one.
pub struct SdNotifier {
    addr: Option<String>,
}

impl SdNotifier {
    /// `addr` is a socket path, or `@name` for the abstract namespace.
    pub fn new(addr: Option<String>) -> SdNotifier {
        SdNotifier { addr: addr.filter(|a| !a.is_empty()) }
    }

    pub fn from_env() -> SdNotifier {
        SdNotifier::new(std::env::var("NOTIFY_SOCKET").ok())
    }

    fn send(&self, state: &str) -> std::io::Result<()> {
        let Some(addr) = &self.addr else {
            return Ok(());
        };
        let socket = UnixDatagram::unbound()?;
        match addr.strip_prefix('@') {
            Some(name) => socket.send_to_addr(state.as_bytes(), &SocketAddr::from_abstract_name(name)?)?,
            None => socket.send_to(state.as_bytes(), addr)?,
        };
        Ok(())
    }
}

impl Notifier for SdNotifier {
    fn notify(&self, state: &str) {
        let _ = self.send(state); // audit-allow: best-effort, a lost notify must not take the tunnel down
    }
}

/// A `STATUS=` line. The text is flattened to one line: notify messages are
/// newline-separated assignments, so a config value carrying `\nMAINPID=1`
/// would otherwise be read by systemd as a second field.
pub fn status(text: &str) -> String {
    let flat: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    format!("STATUS={flat}")
}

/// The heartbeat interval in seconds — half of `WatchdogSec` — or 0 when
/// systemd armed no watchdog for this process.
pub fn watchdog_interval(usec: Option<&str>, watchdog_pid: Option<&str>, own_pid: u32) -> f64 {
    // WATCHDOG_PID names the process the watchdog was armed for; when it is
    // someone else we merely inherited the variables.
    if let Some(pid) = watchdog_pid.map(str::trim).filter(|p| !p.is_empty()) {
        if pid.parse::<u32>().ok() != Some(own_pid) {
            return 0.0;
        }
    }
    match usec {
        Some(u) if !u.is_empty() && u.bytes().all(|b| b.is_ascii_digit()) => {
            u.parse::<f64>().map(|v| v / 1e6 / 2.0).unwrap_or(0.0)
        }
        _ => 0.0,
    }
}

/// Heartbeat bookkeeping. `ping` is cheap to call often.
///
/// `beat` records the last ping whether or not it reached systemd. A
/// supervisor run by the manager has `notify` off: if every thread could pet
/// systemd, one healthy thread would hide a wedged sibling. The manager reads
/// `beat` instead, and only the service loop sends `WATCHDOG=1`, and only
/// while every supervisor is beating.
pub struct Watchdog {
    interval: f64,
    notify: bool,
    clock: Arc<dyn Clock>,
    notifier: Arc<dyn Notifier>,
    /// (last beat, last `WATCHDOG=1` sent)
    times: Mutex<(f64, Option<f64>)>,
}

impl Watchdog {
    pub fn new(interval: f64, notify: bool, clock: Arc<dyn Clock>, notifier: Arc<dyn Notifier>) -> Watchdog {
        let now = clock.now();
        Watchdog { interval, notify, clock, notifier, times: Mutex::new((now, None)) }
    }

    pub fn interval(&self) -> f64 {
        self.interval
    }

    /// Monotonic time of the last ping.
    pub fn beat(&self) -> f64 {
        lock(&self.times).0
    }

    pub fn ping(&self) {
        let now = self.clock.now();
        let due = {
            let mut times = lock(&self.times);
            times.0 = now;
            let due = self.notify && self.interval > 0.0 && times.1.is_none_or(|last| now - last >= self.interval);
            if due {
                times.1 = Some(now);
            }
            due
        };
        if due {
            self.notifier.notify(WATCHDOG);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeClock, RecNotifier, TempDir};

    #[test]
    fn datagram_reaches_a_path_socket() {
        let dir = TempDir::new("notify");
        let path = dir.path().join("notify.sock");
        let server = UnixDatagram::bind(&path).unwrap();
        server.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        SdNotifier::new(Some(path.display().to_string())).notify("READY=1\nSTATUS=test");
        let mut buf = [0u8; 256];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=test");
    }

    #[test]
    fn datagram_reaches_an_abstract_socket() {
        let name = format!("soc-vpn-test-{}-{:?}", std::process::id(), std::thread::current().id());
        let addr = SocketAddr::from_abstract_name(&name).unwrap();
        let server = UnixDatagram::bind_addr(&addr).unwrap();
        server.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        SdNotifier::new(Some(format!("@{name}"))).notify(WATCHDOG);
        let mut buf = [0u8; 64];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
    }

    #[test]
    fn no_socket_and_a_dead_socket_are_silent() {
        SdNotifier::new(None).notify(WATCHDOG);
        SdNotifier::new(Some(String::new())).notify(WATCHDOG);
        SdNotifier::new(Some("/nonexistent/dir/notify.sock".into())).notify(WATCHDOG);
    }

    #[test]
    fn status_cannot_smuggle_a_second_field() {
        assert_eq!(status("connecting to gw (attempt 2)"), "STATUS=connecting to gw (attempt 2)");
        assert_eq!(status("x\nMAINPID=1"), "STATUS=x MAINPID=1");
    }

    #[test]
    fn interval_is_half_of_watchdog_sec() {
        assert_eq!(watchdog_interval(Some("90000000"), None, 7), 45.0);
        assert_eq!(watchdog_interval(None, None, 7), 0.0);
        assert_eq!(watchdog_interval(Some(""), None, 7), 0.0);
        assert_eq!(watchdog_interval(Some("12x"), None, 7), 0.0);
        assert_eq!(watchdog_interval(Some("-5"), None, 7), 0.0);
    }

    #[test]
    fn a_watchdog_armed_for_another_process_is_not_ours() {
        assert_eq!(watchdog_interval(Some("90000000"), Some("7"), 7), 45.0);
        assert_eq!(watchdog_interval(Some("90000000"), Some("8"), 7), 0.0);
        assert_eq!(watchdog_interval(Some("90000000"), Some("junk"), 7), 0.0);
    }

    #[test]
    fn pings_are_rate_limited_to_the_interval() {
        let clock = Arc::new(FakeClock::default());
        let rec = Arc::new(RecNotifier::default());
        let wd = Watchdog::new(45.0, true, clock.clone(), rec.clone());
        wd.ping();
        wd.ping();
        clock.advance(44.0);
        wd.ping();
        assert_eq!(rec.sent(), vec![WATCHDOG]);
        clock.advance(1.0);
        wd.ping();
        assert_eq!(rec.sent().len(), 2);
        assert_eq!(wd.beat(), 45.0);
    }

    #[test]
    fn a_managed_watchdog_beats_but_never_pets_systemd() {
        let clock = Arc::new(FakeClock::default());
        let rec = Arc::new(RecNotifier::default());
        let wd = Watchdog::new(1.0, false, clock.clone(), rec.clone());
        clock.advance(10.0);
        wd.ping();
        assert_eq!(wd.beat(), 10.0);
        assert!(rec.sent().is_empty());
    }

    #[test]
    fn no_watchdog_means_no_pings() {
        let rec = Arc::new(RecNotifier::default());
        let wd = Watchdog::new(0.0, true, Arc::new(FakeClock::default()), rec.clone());
        wd.ping();
        assert!(rec.sent().is_empty());
    }
}
