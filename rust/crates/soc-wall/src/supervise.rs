//! `soc-wall supervise`: keep the wall running.
//!
//! Runs the wall as a child process, restarts it with backoff when it exits,
//! and kills it when its heartbeat goes quiet (a hung main loop is otherwise
//! indistinguishable from a healthy wall showing a frozen picture). This is
//! what makes the wall self-healing on inits without a service manager, and
//! it is the single entry point session scripts need.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// The wall's exit code for "an operator has to act" (do not restart).
pub const EXIT_OPERATOR: i32 = 2;

/// Parse a `KEY=value` environment file.
///
/// The file is read as *data*: no command substitution, no variable
/// expansion, nothing is executed (sourcing it in a shell would make a
/// writable env file a code-execution primitive). Supported: blank lines,
/// `#` comments, an optional `export ` prefix, and single- or double-quoted
/// values. Lines that are not assignments, or whose key is not a valid
/// identifier, are skipped.
pub fn parse_env_file(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let valid = key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            continue;
        }
        let value = value.trim();
        let unquoted = [('"', '"'), ('\'', '\'')]
            .into_iter()
            .find_map(|(open, close)| value.strip_prefix(open).and_then(|v| v.strip_suffix(close)));
        let value = match unquoted {
            Some(inner) => inner.to_string(),
            // Unquoted: an inline ` # comment` ends the value.
            None => value.split(" #").next().unwrap_or("").trim_end().to_string(),
        };
        if value.contains('\0') {
            continue;
        }
        out.push((key.to_string(), value));
    }
    out
}

/// Supervisor tunables.
#[derive(Debug, Clone)]
pub struct Policy {
    /// How often the heartbeat is checked.
    pub tick: Duration,
    /// No heartbeat change for this long: the wall is hung.
    pub stale: Duration,
    /// No first heartbeat for this long after start: hung during boot.
    pub startup: Duration,
    /// Nobody is at this box: never hand over to an operator.
    pub unattended: bool,
    /// Try native Wayland first and fall back to XWayland if it keeps dying.
    pub wayland_auto: bool,
}

impl Policy {
    pub fn from_env() -> Policy {
        let secs = |name: &str, default: i64| {
            Duration::from_secs(
                u64::try_from(soc_core::env::env_int(name, default, Some(1), Some(86_400))).unwrap_or(1),
            )
        };
        Policy {
            tick: secs("SOC_WATCHDOG_TICK", 10),
            stale: secs("SOC_HEARTBEAT_STALE", 120),
            startup: secs("SOC_HEARTBEAT_STARTUP", 600),
            unattended: soc_core::env::env_bool("SOC_UNATTENDED", false),
            wayland_auto: std::env::var("SOC_WAYLAND_BACKEND").is_ok_and(|v| v == "auto"),
        }
    }
}

/// Heartbeat watchdog: decides when a silent wall counts as hung.
#[derive(Debug, Default)]
pub struct BeatWatch {
    last: Option<SystemTime>,
    quiet: Duration,
}

impl BeatWatch {
    /// Feed the heartbeat file's current mtime after a tick of `elapsed`.
    /// Returns true when the wall should be killed.
    pub fn tick(&mut self, mtime: Option<SystemTime>, elapsed: Duration, policy: &Policy) -> bool {
        if mtime.is_some() && mtime != self.last {
            self.last = mtime;
            self.quiet = Duration::ZERO;
            return false;
        }
        self.quiet += elapsed;
        let limit = if self.last.is_some() { policy.stale } else { policy.startup };
        self.quiet >= limit
    }
}

/// What to do after the wall exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Start it again after this long.
    Restart(Duration),
    /// Stop supervising: an operator has to act.
    Operator,
}

/// Restart backoff + the Wayland fallback.
#[derive(Debug)]
pub struct Restarts {
    delay: Duration,
    native_fails: u32,
    /// Set once native Wayland failed twice: run under XWayland instead.
    pub force_x11: bool,
}

impl Default for Restarts {
    fn default() -> Self {
        Restarts { delay: Duration::from_secs(3), native_fails: 0, force_x11: false }
    }
}

impl Restarts {
    /// Decide what follows an exit with `code` after `ran`. `on_wayland`:
    /// the child was started on native Wayland.
    pub fn after_exit(&mut self, code: Option<i32>, ran: Duration, on_wayland: bool, policy: &Policy) -> Next {
        if code == Some(EXIT_OPERATOR) {
            // Unattended there is nobody to act: keep trying, slowly.
            return if policy.unattended { Next::Restart(Duration::from_secs(60)) } else { Next::Operator };
        }
        if policy.wayland_auto && on_wayland && !self.force_x11 && ran < Duration::from_secs(8) {
            self.native_fails += 1;
            if self.native_fails >= 2 {
                self.force_x11 = true;
            }
        }
        // A wall that stayed up for a minute earned a quick restart; one that
        // keeps dying backs off so it cannot spin the CPU.
        self.delay = if ran >= Duration::from_secs(60) {
            Duration::from_secs(3)
        } else {
            (self.delay * 2).min(Duration::from_secs(30))
        };
        Next::Restart(self.delay)
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Sleep in short steps so a termination signal is noticed promptly.
fn sleep_unless(stop: &AtomicBool, total: Duration) {
    let end = Instant::now() + total;
    while !stop.load(Ordering::Relaxed) {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        std::thread::sleep(left.min(Duration::from_millis(200)));
    }
}

/// Ask the child to stop, then insist.
fn stop_child(child: &mut Child) {
    let pid = child.id() as libc::pid_t;
    // SIGTERM first: the wall tears its panels (and Chromium children) down.
    let _ = Command::new("kill").args(["-TERM", &pid.to_string()]).status(); // audit-allow: best-effort, SIGTERM is followed by a bounded wait then kill
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill(); // audit-allow: best-effort, child may already be dead
    let _ = child.wait(); // audit-allow: best-effort, reaping an already-killed child
}

/// Run one wall process to completion (or until it hangs / we are stopped).
fn run_once(
    command: &mut Command,
    heartbeat: &Path,
    policy: &Policy,
    stop: &AtomicBool,
    log: &dyn Fn(&str),
) -> Option<i32> {
    let _ = std::fs::remove_file(heartbeat); // audit-allow: best-effort, heartbeat file may not exist
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            log(&format!("cannot start the wall: {e}"));
            return Some(1);
        }
    };
    let mut watch = BeatWatch::default();
    loop {
        let tick_start = Instant::now();
        sleep_unless(stop, policy.tick);
        if stop.load(Ordering::Relaxed) {
            stop_child(&mut child);
            return None;
        }
        match child.try_wait() {
            Ok(Some(status)) => return status.code().or(Some(1)),
            Ok(None) => {}
            Err(e) => {
                log(&format!("lost track of the wall process: {e}"));
                return Some(1);
            }
        }
        if watch.tick(mtime(heartbeat), tick_start.elapsed(), policy) {
            log(&format!("wall {} silent for too long (main loop hung?); killing it", child.id()));
            stop_child(&mut child);
            return Some(1);
        }
    }
}

/// Supervise the wall until a termination signal or an operator-action exit.
/// `make_command(force_x11)` builds the child command for each start.
pub fn supervise(
    make_command: &dyn Fn(bool) -> Command,
    heartbeat: &Path,
    policy: &Policy,
    stop: Arc<AtomicBool>,
    log: &dyn Fn(&str),
) -> i32 {
    let mut restarts = Restarts::default();
    while !stop.load(Ordering::Relaxed) {
        let mut command = make_command(restarts.force_x11);
        let on_wayland = command.get_envs().any(|(k, v)| k == "GDK_BACKEND" && v.is_some_and(|v| v == "wayland"))
            || (!restarts.force_x11 && std::env::var("GDK_BACKEND").is_ok_and(|v| v == "wayland"));
        log("starting the wall");
        let started = Instant::now();
        let Some(code) = run_once(&mut command, heartbeat, policy, &stop, log) else {
            break;
        };
        let was_forced = restarts.force_x11;
        match restarts.after_exit(Some(code), started.elapsed(), on_wayland, policy) {
            Next::Operator => {
                log("the wall needs an operator (exit code 2); not restarting");
                return EXIT_OPERATOR;
            }
            Next::Restart(delay) => {
                if restarts.force_x11 && !was_forced {
                    log("native Wayland failed to start twice — switching to XWayland for this session");
                }
                log(&format!("wall exited ({code}); restarting in {}s", delay.as_secs()));
                sleep_unless(&stop, delay);
            }
        }
    }
    0
}

/// Where the env file lives: `$SOC_ENV_FILE`, else the system default.
pub fn env_file() -> PathBuf {
    std::env::var_os("SOC_ENV_FILE")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("/etc/soc-display/soc.env"), PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            tick: Duration::from_secs(10),
            stale: Duration::from_secs(120),
            startup: Duration::from_secs(600),
            unattended: false,
            wayland_auto: true,
        }
    }

    #[test]
    fn env_file_is_data_not_code() {
        let parsed = parse_env_file(
            "# comment\n\nSOC_VAULT_URL=http://127.0.0.1:8222\nexport SOC_VAULT_EMAIL=\"wall@example.com\"\n\
             SOC_ITEM='SOC Wall Config'\nSOC_N=5 # five\nEVIL=$(rm -rf /)\nBACKTICK=`id`\n1BAD=x\nnot an assignment\n\
             SPACED = padded \nEMPTY=\n",
        );
        let get = |k: &str| parsed.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());
        assert_eq!(get("SOC_VAULT_URL"), Some("http://127.0.0.1:8222"));
        assert_eq!(get("SOC_VAULT_EMAIL"), Some("wall@example.com"));
        assert_eq!(get("SOC_ITEM"), Some("SOC Wall Config"));
        assert_eq!(get("SOC_N"), Some("5"));
        assert_eq!(get("SPACED"), Some("padded"));
        assert_eq!(get("EMPTY"), Some(""));
        // Shell syntax is kept as literal text — never run.
        assert_eq!(get("EVIL"), Some("$(rm -rf /)"));
        assert_eq!(get("BACKTICK"), Some("`id`"));
        assert_eq!(get("1BAD"), None);
        assert_eq!(parsed.len(), 8);
    }

    #[test]
    fn heartbeat_startup_grace_then_stale_limit() {
        let p = policy();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let tick = Duration::from_secs(10);

        let mut w = BeatWatch::default();
        // No first beat: allowed the long start-up window.
        for _ in 0..59 {
            assert!(!w.tick(None, tick, &p));
        }
        assert!(w.tick(None, tick, &p), "600 s without a first beat");

        let mut w = BeatWatch::default();
        assert!(!w.tick(Some(t0), tick, &p));
        for _ in 0..11 {
            assert!(!w.tick(Some(t0), tick, &p));
        }
        assert!(w.tick(Some(t0), tick, &p), "120 s without a change");

        // A fresh beat resets the count.
        let mut w = BeatWatch::default();
        w.tick(Some(t0), tick, &p);
        for _ in 0..11 {
            w.tick(Some(t0), tick, &p);
        }
        assert!(!w.tick(Some(t0 + Duration::from_secs(1)), tick, &p));
        assert!(!w.tick(Some(t0 + Duration::from_secs(1)), tick, &p));
    }

    #[test]
    fn restart_backoff_and_reset() {
        let p = policy();
        let mut r = Restarts::default();
        let quick = Duration::from_secs(20);
        let delays: Vec<u64> = (0..5)
            .map(|_| match r.after_exit(Some(1), quick, false, &p) {
                Next::Restart(d) => d.as_secs(),
                Next::Operator => unreachable!(),
            })
            .collect();
        assert_eq!(delays, vec![6, 12, 24, 30, 30]);
        assert_eq!(r.after_exit(Some(1), Duration::from_secs(61), false, &p), Next::Restart(Duration::from_secs(3)));
    }

    #[test]
    fn operator_exit_stops_unless_unattended() {
        let mut p = policy();
        let mut r = Restarts::default();
        assert_eq!(r.after_exit(Some(2), Duration::from_secs(5), false, &p), Next::Operator);
        p.unattended = true;
        assert_eq!(r.after_exit(Some(2), Duration::from_secs(5), false, &p), Next::Restart(Duration::from_secs(60)));
    }

    #[test]
    fn wayland_falls_back_after_two_quick_deaths() {
        let p = policy();
        let mut r = Restarts::default();
        r.after_exit(Some(1), Duration::from_secs(2), true, &p);
        assert!(!r.force_x11);
        r.after_exit(Some(1), Duration::from_secs(2), true, &p);
        assert!(r.force_x11);

        // Slow deaths, X11 sessions and a fixed backend never trigger it.
        let mut r = Restarts::default();
        for _ in 0..5 {
            r.after_exit(Some(1), Duration::from_secs(30), true, &p);
            r.after_exit(Some(1), Duration::from_secs(2), false, &p);
        }
        assert!(!r.force_x11);
        let fixed = Policy { wayland_auto: false, ..policy() };
        let mut r = Restarts::default();
        for _ in 0..5 {
            r.after_exit(Some(1), Duration::from_secs(2), true, &fixed);
        }
        assert!(!r.force_x11);
    }

    #[test]
    fn supervises_a_real_child_and_stops_on_request() {
        let dir = std::env::temp_dir().join(format!("soc-supervise-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let heartbeat = dir.join("heartbeat.json");
        let stop = Arc::new(AtomicBool::new(false));
        let p = Policy { tick: Duration::from_millis(50), ..policy() };

        // Exit code 2 hands over to the operator.
        let code = supervise(
            &|_| {
                let mut c = Command::new("sh");
                c.args(["-c", "exit 2"]);
                c
            },
            &heartbeat,
            &p,
            stop.clone(),
            &|_| {},
        );
        assert_eq!(code, EXIT_OPERATOR);

        // A long-running child is stopped (and reaped) when we are told to stop.
        let stopper = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            stopper.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let code = supervise(
            &|_| {
                let mut c = Command::new("sleep");
                c.arg("30");
                c
            },
            &heartbeat,
            &p,
            stop,
            &|_| {},
        );
        assert_eq!(code, 0);
        assert!(started.elapsed() < Duration::from_secs(10), "the child was not stopped promptly");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_silent_child_is_killed() {
        let dir = std::env::temp_dir().join(format!("soc-supervise-hung-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let heartbeat = dir.join("heartbeat.json");
        let p = Policy {
            tick: Duration::from_millis(40),
            startup: Duration::from_millis(200),
            stale: Duration::from_millis(200),
            ..policy()
        };
        let stop = AtomicBool::new(false);
        let logs = std::cell::RefCell::new(Vec::new());
        let started = Instant::now();
        let mut command = Command::new("sleep");
        command.arg("30");
        let code = run_once(&mut command, &heartbeat, &p, &stop, &|m| logs.borrow_mut().push(m.to_string()));
        assert_eq!(code, Some(1));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(logs.borrow().iter().any(|l| l.contains("silent for too long")), "{:?}", logs.borrow());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
