//! Child processes: spawning, reading output, stopping.
//!
//! Rules that hold for every child started here:
//!  * no shell — an explicit argv through `Command`;
//!  * its own process group, so stopping it can reach helpers it forked (a
//!    bash wrapper cannot run its TERM trap until its foreground pipeline
//!    ends; signalling only the leader would orphan the real client);
//!  * every descriptor we own is close-on-exec; the child sees only
//!    `/dev/null` and one output pipe;
//!  * the group is only ever signalled while its leader is still unreaped,
//!    which pins the group id against reuse;
//!  * it is always reaped.

use crate::clock::Clock;
use crate::driver::redact_argv;
use crate::lock;
use crate::sys;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// A child writing without newlines cannot grow our memory past this.
pub const MAX_LINE: usize = 64 * 1024;

/// Variables no VPN client is given: the vault master (up-scripts and pppd
/// inherit the client's environment), secrets meant for a different child,
/// and the notify socket (only the service itself reports to systemd).
pub const CHILD_ENV_DROP: [&str; 7] = [
    "SOC_VAULT_PASSWORD",
    "SOC_VPN_PASSWORD",
    "SOC_VPN_OTP",
    "H3C_SVPN_PASSWORD",
    "NOTIFY_SOCKET",
    "WATCHDOG_USEC",
    "WATCHDOG_PID",
];

/// What to run. `Debug` never shows a secret: environment values are omitted
/// and secret-bearing arguments masked.
#[derive(Default)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    /// Secrets handed to the child through its environment. Wiped on drop.
    pub env: Vec<(String, Zeroizing<String>)>,
    /// Inherited variables the child must not see.
    pub env_remove: Vec<String>,
}

impl CommandSpec {
    pub fn new(argv: Vec<String>) -> CommandSpec {
        CommandSpec { argv, env: Vec::new(), env_remove: CHILD_ENV_DROP.iter().map(|s| s.to_string()).collect() }
    }

    pub fn secret_env(&mut self, name: &str, value: &str) {
        self.env.push((name.to_string(), Zeroizing::new(value.to_string())));
    }
}

impl std::fmt::Debug for CommandSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("CommandSpec").field("argv", &redact_argv(&self.argv)).field("secret_env", &names).finish()
    }
}

/// A running (or finished) child and its process group.
pub trait ChildProc: Send + Sync {
    fn pid(&self) -> u32;
    /// Whether the child has exited. Never reaps.
    fn exited(&self) -> bool;
    /// Collect the exit status once the child has exited: the exit code, or
    /// the negated signal number. `None` while it is still running.
    fn reap(&self) -> Option<i32>;
    /// Signal the child's whole process group. A no-op once reaped.
    fn signal_group(&self, signal: i32);
    /// Whether the group still has live members besides the leader; `None`
    /// when that cannot be determined.
    fn group_has_members(&self) -> Option<bool>;
}

/// A source of output lines that can be told to stop.
pub trait LineSource: Send {
    /// The next line without its newline; `None` at end of output, or once
    /// `done` is set and what was already written has been drained.
    fn next_line(&mut self, done: &AtomicBool) -> Option<String>;
}

/// A freshly started child and its merged stdout+stderr.
pub struct Spawned {
    pub child: Arc<dyn ChildProc>,
    pub output: Box<dyn LineSource>,
}

/// Process creation, injectable so the reconnect policy is tested without
/// starting a VPN client.
pub trait Spawner: Send + Sync {
    /// Start a long-lived client.
    fn spawn(&self, spec: &CommandSpec) -> io::Result<Spawned>;
    /// Run a short command to completion: `(exit code, combined output)`.
    fn oneshot(&self, argv: &[String], timeout: f64) -> (i32, String);
    /// Whether `program` (a `$PATH` name or a path) can be executed.
    fn executable(&self, program: &str) -> bool;
}

// --- output ---------------------------------------------------------------------

/// Splits a byte stream into lines, bounding the length of any one line.
#[derive(Default)]
pub struct LineSplitter {
    tail: Vec<u8>,
    lines: VecDeque<Vec<u8>>,
}

impl LineSplitter {
    pub fn push(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            if byte == b'\n' {
                self.lines.push_back(std::mem::take(&mut self.tail));
            } else {
                self.tail.push(byte);
                if self.tail.len() >= MAX_LINE {
                    self.lines.push_back(std::mem::take(&mut self.tail));
                }
            }
        }
    }

    /// The unterminated remainder becomes a final line.
    pub fn finish(&mut self) {
        if !self.tail.is_empty() {
            self.lines.push_back(std::mem::take(&mut self.tail));
        }
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.lines.pop_front()
    }
}

/// How long a reader keeps draining after it was told to stop. Long enough to
/// collect what a client wrote just before exiting — the line that says *why*
/// it exited — short enough that a helper still holding the pipe cannot keep
/// the reader alive.
const DRAIN_GRACE: Duration = Duration::from_millis(500);
const READ_POLL_MS: i32 = 200;

/// Line reader over a child's output pipe.
///
/// It polls instead of blocking in `read`, so `done` can end it even while a
/// grandchild holds the write end open. Bytes are decoded with replacement:
/// gateway text is not always UTF-8, and a reader that died on the first bad
/// byte would leave the child blocked on a full pipe with the tunnel
/// apparently up.
pub struct PipeLines {
    pipe: File,
    splitter: LineSplitter,
    finished: bool,
}

impl PipeLines {
    pub fn new(pipe: File) -> PipeLines {
        PipeLines { pipe, splitter: LineSplitter::default(), finished: false }
    }

    fn fill(&mut self, done: &AtomicBool) {
        let mut buf = [0u8; 8192];
        let mut drain_until: Option<Instant> = None;
        while self.splitter.lines.is_empty() {
            let stopping = done.load(Ordering::Relaxed);
            if stopping {
                let until = *drain_until.get_or_insert_with(|| Instant::now() + DRAIN_GRACE);
                if Instant::now() >= until {
                    break;
                }
            }
            match sys::poll_readable(self.pipe.as_fd(), if stopping { 0 } else { READ_POLL_MS }) {
                Ok(true) => {}
                Ok(false) if stopping => break,
                Ok(false) => continue,
                Err(_) => break, // audit-allow: poll failure ends the drain, lines read so far are kept
            }
            match self.pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(chunk) = buf.get(..n) {
                        self.splitter.push(chunk);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break, // audit-allow: read failure ends the drain, lines read so far are kept
            }
        }
        if self.splitter.lines.is_empty() {
            self.splitter.finish();
            self.finished = true;
        }
    }
}

impl LineSource for PipeLines {
    fn next_line(&mut self, done: &AtomicBool) -> Option<String> {
        if self.splitter.lines.is_empty() && !self.finished {
            self.fill(done);
        }
        self.splitter.pop().map(|raw| String::from_utf8_lossy(&raw).into_owned())
    }
}

// --- children -------------------------------------------------------------------

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| -status.signal().unwrap_or(1))
}

/// A real child process, leader of its own process group.
pub struct OsChild {
    pid: u32,
    /// The handle, and the exit code once reaped.
    inner: Mutex<(Child, Option<i32>)>,
}

impl OsChild {
    fn new(child: Child) -> OsChild {
        OsChild { pid: child.id(), inner: Mutex::new((child, None)) }
    }
}

impl ChildProc for OsChild {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn exited(&self) -> bool {
        if lock(&self.inner).1.is_some() {
            return true;
        }
        // An error means the child is not ours to wait for (something reaped
        // it behind our back); fall back to asking whether the pid is alive.
        sys::has_exited(self.pid).unwrap_or_else(|_| sys::pid_state(self.pid) != sys::PidState::Alive)
    }

    fn reap(&self) -> Option<i32> {
        let mut inner = lock(&self.inner);
        if inner.1.is_none() {
            match inner.0.try_wait() {
                Ok(Some(status)) => inner.1 = Some(exit_code(status)),
                Ok(None) => {}
                Err(_) => inner.1 = Some(-1), // audit-allow: wait failure is reported as the -1 failure status
            }
        }
        inner.1
    }

    fn signal_group(&self, signal: i32) {
        // Held across the kill so a concurrent reap cannot free the pid
        // between the check and the signal.
        let inner = lock(&self.inner);
        if inner.1.is_none() {
            let _ = sys::kill_group(self.pid, signal); // audit-allow: best-effort, the group may already be gone
        }
    }

    fn group_has_members(&self) -> Option<bool> {
        if lock(&self.inner).1.is_some() {
            return Some(false);
        }
        group_members(self.pid).map(|n| n > 0)
    }
}

/// Live members of process group `pgid` other than its leader, from `/proc`.
fn group_members(pgid: u32) -> Option<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if pid == pgid {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // "pid (comm) state ppid pgrp ..." — comm may itself contain ')'.
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.split_ascii_whitespace();
        let (state, group) = (fields.next(), fields.nth(1));
        if state != Some("Z") && group.and_then(|g| g.parse::<u32>().ok()) == Some(pgid) {
            count += 1;
        }
    }
    Some(count)
}

fn wait_exit(child: &dyn ChildProc, seconds: f64, clock: &dyn Clock) -> bool {
    let deadline = clock.now() + seconds;
    loop {
        if child.exited() {
            return true;
        }
        if clock.now() >= deadline {
            return false;
        }
        clock.sleep(0.05);
    }
}

/// SIGTERM the child's group so the client tears down routes and DNS, then
/// escalate to SIGKILL after `grace`. Returns whether the child is gone.
/// `binary` only names it in the log — never the argv, which may carry a
/// one-time code.
pub fn terminate(child: &dyn ChildProc, grace: f64, clock: &dyn Clock, log: &dyn Fn(&str), binary: &str) -> bool {
    if child.exited() {
        return true;
    }
    child.signal_group(sys::SIGTERM);
    if wait_exit(child, grace, clock) {
        return true;
    }
    log(&format!("{binary} did not exit within {grace:.0}s; killing"));
    child.signal_group(sys::SIGKILL);
    if wait_exit(child, 5.0, clock) {
        return true;
    }
    log(&format!("{binary} survived SIGKILL (stuck in the kernel?); it will be retried before the next attempt"));
    false
}

/// Clear whatever a finished attempt left in its process group, then reap the
/// leader. A straggler holds the tunnel and our output pipe, and would fight
/// the next attempt. Must be called while the leader is still unreaped.
pub fn reap_group(child: &dyn ChildProc, grace: f64, clock: &dyn Clock) -> Option<i32> {
    if !child.exited() {
        return None;
    }
    if child.group_has_members() != Some(false) {
        child.signal_group(sys::SIGTERM);
        let deadline = clock.now() + grace;
        while child.group_has_members() != Some(false) && clock.now() < deadline {
            clock.sleep(0.1);
        }
        if child.group_has_members() != Some(false) {
            child.signal_group(sys::SIGKILL);
        }
    }
    child.reap()
}

// --- the real spawner -----------------------------------------------------------

/// Starts real processes.
pub struct SystemSpawner;

fn base_command(argv: &[String]) -> io::Result<(Command, File)> {
    let Some((program, args)) = argv.split_first() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command"));
    };
    let (read_end, write_end) = sys::pipe()?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::from(write_end.try_clone()?))
        .stdout(Stdio::from(write_end))
        .process_group(0);
    for name in CHILD_ENV_DROP {
        cmd.env_remove(name);
    }
    Ok((cmd, File::from(read_end)))
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

/// Output kept from a one-shot command; the rest is discarded.
const ONESHOT_OUTPUT_CAP: usize = 64 * 1024;

fn run_oneshot(argv: &[String], timeout: f64) -> io::Result<(i32, String)> {
    let (mut cmd, mut pipe) = base_command(argv)?;
    let spawned = cmd.spawn();
    // The Command holds the pipe's write ends; EOF needs them closed.
    drop(cmd);
    let child = OsChild::new(spawned?);
    let deadline = Instant::now() + crate::clock::secs(timeout);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut exited_at: Option<Instant> = None;
    let mut timed_out = false;
    loop {
        if exited_at.is_none() && child.exited() {
            exited_at = Some(Instant::now());
        }
        // The command is done but something it started still holds the pipe.
        if exited_at.is_some_and(|t| t.elapsed() > DRAIN_GRACE) {
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        match sys::poll_readable(pipe.as_fd(), 50) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(_) => break, // audit-allow: poll failure ends output collection
        }
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n.min(ONESHOT_OUTPUT_CAP.saturating_sub(out.len()))]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break, // audit-allow: read failure ends output collection
        }
    }
    while !timed_out && !child.exited() {
        if Instant::now() >= deadline {
            timed_out = true;
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if timed_out {
        // The whole group: wg-quick is a shell script, and killing only the
        // shell would orphan the helper that is actually stuck.
        child.signal_group(sys::SIGKILL);
        let give_up = Instant::now() + Duration::from_secs(5);
        while !child.exited() && Instant::now() < give_up {
            std::thread::sleep(Duration::from_millis(10));
        }
        child.reap();
        return Ok((1, format!("timed out after {timeout:.0}s")));
    }
    let code = child.reap().unwrap_or(1);
    Ok((code, String::from_utf8_lossy(&out).trim().to_string()))
}

impl Spawner for SystemSpawner {
    fn spawn(&self, spec: &CommandSpec) -> io::Result<Spawned> {
        let (mut cmd, pipe) = base_command(&spec.argv)?;
        for name in &spec.env_remove {
            cmd.env_remove(name);
        }
        for (name, value) in &spec.env {
            cmd.env(name, value.as_str());
        }
        let spawned = cmd.spawn();
        drop(cmd);
        Ok(Spawned { child: Arc::new(OsChild::new(spawned?)), output: Box::new(PipeLines::new(pipe)) })
    }

    fn oneshot(&self, argv: &[String], timeout: f64) -> (i32, String) {
        run_oneshot(argv, timeout).unwrap_or_else(|e| (1, e.to_string()))
    }

    fn executable(&self, program: &str) -> bool {
        if program.contains('/') {
            return is_executable(Path::new(program));
        }
        std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|dir| is_executable(&dir.join(program))))
    }
}

// --- helper threads -------------------------------------------------------------

/// A helper thread that can be joined with a time limit, so a thread stuck on
/// something we do not control can never wedge the supervisor waiting for it.
pub struct Worker {
    handle: Option<JoinHandle<()>>,
    finished: Receiver<()>,
}

impl Worker {
    pub fn spawn(name: &str, body: impl FnOnce() + Send + 'static) -> io::Result<Worker> {
        let (tx, finished) = channel::<()>();
        let handle = std::thread::Builder::new().name(name.to_string()).spawn(move || {
            // Dropped when the thread ends — normally or by unwinding — which
            // is what the receiver observes.
            let _signal = tx; // audit-allow: drop guard, must live until the body ends
            body();
        })?;
        Ok(Worker { handle: Some(handle), finished })
    }

    /// Whether the thread has ended.
    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Wait up to `timeout` for the thread to end; true if it did.
    pub fn join_timeout(&mut self, timeout: Duration) -> bool {
        if matches!(self.finished.recv_timeout(timeout), Err(RecvTimeoutError::Timeout)) {
            return false;
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join(); // audit-allow: best-effort, a panicked helper only needs to be gone
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::testing::TempDir;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn sh(script: &str) -> CommandSpec {
        CommandSpec::new(argv(&["sh", "-c", script]))
    }

    fn collect(mut src: Box<dyn LineSource>) -> Vec<String> {
        let done = AtomicBool::new(false);
        std::iter::from_fn(|| src.next_line(&done)).collect()
    }

    fn alive(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| s.rsplit_once(')').map(|(_, rest)| !rest.trim_start().starts_with('Z')))
            .unwrap_or(false)
    }

    fn wait_for_pid(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(pid) = std::fs::read_to_string(path).ok().and_then(|s| s.trim().parse().ok()) {
                return pid;
            }
            assert!(Instant::now() < deadline, "{} never appeared", path.display());
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(8);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn splitter_handles_partial_and_oversized_lines() {
        let mut s = LineSplitter::default();
        s.push(b"one\ntw");
        s.push(b"o\n\nthree");
        assert_eq!(s.pop().unwrap(), b"one");
        assert_eq!(s.pop().unwrap(), b"two");
        assert_eq!(s.pop().unwrap(), b"");
        assert!(s.pop().is_none());
        s.finish();
        assert_eq!(s.pop().unwrap(), b"three");
        s.push(&vec![b'x'; MAX_LINE + 10]);
        assert_eq!(s.pop().unwrap().len(), MAX_LINE);
        assert!(s.pop().is_none());
    }

    #[test]
    fn debug_never_shows_a_secret() {
        let mut spec = CommandSpec::new(argv(&["openfortivpn", "gw:443", "--otp=123456", "--spa-key", "deadbeef"]));
        spec.secret_env("SOC_VPN_PASSWORD", "hunter2");
        let shown = format!("{spec:?}");
        assert!(shown.contains("SOC_VPN_PASSWORD") && shown.contains("gw:443"));
        assert!(!shown.contains("hunter2") && !shown.contains("123456") && !shown.contains("deadbeef"), "{shown}");
    }

    #[test]
    fn stdout_and_stderr_arrive_merged_and_the_exit_code_is_kept() {
        let spawned = SystemSpawner.spawn(&sh("echo out; echo err >&2; exit 3")).unwrap();
        let mut lines = collect(spawned.output);
        lines.sort();
        assert_eq!(lines, ["err", "out"]);
        wait_until("exit", || spawned.child.exited());
        assert_eq!(spawned.child.reap(), Some(3));
        assert_eq!(spawned.child.reap(), Some(3));
    }

    #[test]
    fn a_signalled_child_reports_the_negated_signal() {
        let spawned = SystemSpawner.spawn(&CommandSpec::new(argv(&["sleep", "30"]))).unwrap();
        assert!(!spawned.child.exited());
        assert_eq!(spawned.child.reap(), None);
        assert!(terminate(&*spawned.child, 5.0, &SystemClock::new(), &|_| {}, "sleep"));
        assert_eq!(spawned.child.reap(), Some(-sys::SIGTERM));
    }

    #[test]
    fn the_child_gets_its_secret_through_the_environment_only() {
        let mut spec = sh("echo \"pw=[$SOC_VPN_PASSWORD] dropped=[${SOC_STALE:-}]\"");
        spec.secret_env("SOC_VPN_PASSWORD", "hunter2");
        spec.env_remove.push("SOC_STALE".into());
        assert!(!spec.argv.iter().any(|a| a.contains("hunter2")));
        let spawned = SystemSpawner.spawn(&spec).unwrap();
        assert_eq!(collect(spawned.output), ["pw=[hunter2] dropped=[]"]);
        wait_until("exit", || spawned.child.exited());
        spawned.child.reap();
    }

    #[test]
    fn the_reader_survives_non_utf8_output_and_keeps_draining() {
        // 200 KB is well past the 64 KB pipe buffer: a reader that died on the
        // bad byte would leave the child blocked on write.
        let spawned = SystemSpawner
            .spawn(&sh(r"printf 'bad \377\376 bytes\n'; head -c 200000 /dev/zero | tr '\0' x; printf '\nTunnel is up and running\n'"))
            .unwrap();
        let lines = collect(spawned.output);
        assert!(lines[0].starts_with("bad ") && lines[0].ends_with(" bytes"));
        assert_eq!(lines.last().unwrap(), "Tunnel is up and running");
        wait_until("exit", || spawned.child.exited());
        assert_eq!(spawned.child.reap(), Some(0));
    }

    #[test]
    fn the_last_line_before_exit_is_not_lost_when_told_to_stop() {
        // The line that explains an exit is written just before it. A reader
        // that quits the moment it is told to would drop it, and an
        // authentication failure would be retried like a network drop.
        let spawned = SystemSpawner.spawn(&sh("echo 'ERROR:  Could not authenticate to gateway.'; exit 1")).unwrap();
        wait_until("exit", || spawned.child.exited());
        let done = AtomicBool::new(true);
        let mut src = spawned.output;
        assert_eq!(src.next_line(&done).as_deref(), Some("ERROR:  Could not authenticate to gateway."));
        assert_eq!(src.next_line(&done), None);
        spawned.child.reap();
    }

    #[test]
    fn a_reader_told_to_stop_returns_while_a_grandchild_holds_the_pipe() {
        let tmp = TempDir::new("proc");
        let pidfile = tmp.path().join("pid");
        let spawned =
            SystemSpawner.spawn(&sh(&format!("setsid sleep 30 & echo $! > {}; exit 0", pidfile.display()))).unwrap();
        let escaped = wait_for_pid(&pidfile);
        wait_until("exit", || spawned.child.exited());
        let done = AtomicBool::new(true);
        let started = Instant::now();
        let mut src = spawned.output;
        while src.next_line(&done).is_some() {}
        assert!(started.elapsed() < Duration::from_secs(3));
        spawned.child.reap();
        let _ = std::process::Command::new("kill").args(["-9", &escaped.to_string()]).status();
    }

    #[test]
    fn a_leftover_helper_in_the_group_is_cleared_before_the_leader_is_reaped() {
        let tmp = TempDir::new("proc");
        let pidfile = tmp.path().join("pid");
        let spawned = SystemSpawner.spawn(&sh(&format!("sleep 30 & echo $! > {}; exit 0", pidfile.display()))).unwrap();
        let helper = wait_for_pid(&pidfile);
        wait_until("exit", || spawned.child.exited());
        assert_eq!(spawned.child.group_has_members(), Some(true));
        assert_eq!(reap_group(&*spawned.child, 2.0, &SystemClock::new()), Some(0));
        wait_until("helper gone", || !alive(helper));
        // Once reaped the group is never signalled again.
        assert_eq!(spawned.child.group_has_members(), Some(false));
        spawned.child.signal_group(sys::SIGKILL);
    }

    #[test]
    fn term_reaches_the_foreground_pipeline_of_a_bash_wrapper() {
        // svpn-connect.sh shape: bash cannot run its TERM trap until the
        // foreground pipeline ends, so signalling bash alone orphans the
        // backend with the tunnel still up.
        let tmp = TempDir::new("proc");
        let pidfile = tmp.path().join("pid");
        let script = tmp.path().join("wrapper.sh");
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env bash\ntrap 'exit 0' EXIT INT TERM\nsh -c 'echo $$ > {}; exec sleep 30' | cat\n",
                pidfile.display()
            ),
        )
        .unwrap();
        let spawned = SystemSpawner.spawn(&CommandSpec::new(argv(&["bash", &script.display().to_string()]))).unwrap();
        let backend = wait_for_pid(&pidfile);
        let clock = SystemClock::new();
        assert!(terminate(&*spawned.child, 4.0, &clock, &|_| {}, "wrapper"));
        reap_group(&*spawned.child, 2.0, &clock);
        wait_until("backend gone", || !alive(backend));
    }

    #[test]
    fn an_unkillable_child_is_reported_without_its_argv() {
        struct Stuck;
        impl ChildProc for Stuck {
            fn pid(&self) -> u32 {
                4_194_305
            }
            fn exited(&self) -> bool {
                false
            }
            fn reap(&self) -> Option<i32> {
                None
            }
            fn signal_group(&self, _signal: i32) {}
            fn group_has_members(&self) -> Option<bool> {
                None
            }
        }
        let clock = crate::testing::FakeClock::default();
        let logs = Mutex::new(Vec::new());
        assert!(!terminate(&Stuck, 0.0, &clock, &|m| logs.lock().unwrap().push(m.to_string()), "openfortivpn"));
        let logs = logs.into_inner().unwrap();
        assert!(logs.iter().any(|m| m.contains("SIGKILL")));
        assert!(!logs.iter().any(|m| m.contains("--otp")));
        assert_eq!(reap_group(&Stuck, 2.0, &clock), None);
    }

    #[test]
    fn oneshot_returns_code_and_output() {
        assert_eq!(SystemSpawner.oneshot(&argv(&["sh", "-c", "echo hi; echo there >&2; exit 4"]), 10.0).0, 4);
        let (rc, out) = SystemSpawner.oneshot(&argv(&["sh", "-c", r"printf 'bad \377 byte\n'"]), 10.0);
        assert_eq!(rc, 0);
        assert!(out.contains("byte"));
        let (rc, out) = SystemSpawner.oneshot(&argv(&["/nonexistent/program"]), 10.0);
        assert_eq!(rc, 1);
        assert!(!out.is_empty());
        assert_eq!(SystemSpawner.oneshot(&[], 1.0).0, 1);
    }

    #[test]
    fn oneshot_timeout_kills_the_whole_group() {
        let tmp = TempDir::new("proc");
        let pidfile = tmp.path().join("pid");
        let started = Instant::now();
        let (rc, out) = SystemSpawner
            .oneshot(&argv(&["sh", "-c", &format!("sleep 30 & echo $! > {}; wait", pidfile.display())]), 0.3);
        assert_eq!(rc, 1);
        assert!(out.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
        let helper = wait_for_pid(&pidfile);
        wait_until("helper gone", || !alive(helper));
    }

    #[test]
    fn oneshot_does_not_wait_for_a_daemon_that_kept_the_pipe() {
        let started = Instant::now();
        let (rc, out) = SystemSpawner.oneshot(&argv(&["sh", "-c", "sleep 3 & echo started"]), 20.0);
        assert_eq!((rc, out.as_str()), (0, "started"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn oneshot_children_do_not_inherit_the_vault_master() {
        // Asserted on the command itself rather than by mutating our env.
        let (cmd, _pipe) = base_command(&argv(&["true"])).unwrap();
        let removed: Vec<_> =
            cmd.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_string_lossy().into_owned()).collect();
        for name in CHILD_ENV_DROP {
            assert!(removed.iter().any(|r| r == name), "{name} is passed on");
        }
    }

    #[test]
    fn executables_are_found_by_path_and_by_name() {
        assert!(SystemSpawner.executable("sh"));
        assert!(SystemSpawner.executable("/bin/sh"));
        assert!(!SystemSpawner.executable("/etc/hostname"));
        assert!(!SystemSpawner.executable("definitely-not-a-real-program-xyz"));
        assert!(!SystemSpawner.executable("/nonexistent/x"));
    }

    #[test]
    fn flapping_does_not_accumulate_descriptors() {
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let run = || {
            let spawned = SystemSpawner.spawn(&CommandSpec::new(argv(&["true"]))).unwrap();
            collect(spawned.output);
            wait_until("exit", || spawned.child.exited());
            spawned.child.reap();
        };
        run();
        let before = count();
        for _ in 0..15 {
            run();
        }
        // Other tests open descriptors concurrently; a leak would be 15+.
        assert!(count() < before + 10, "descriptors leaked");
    }

    #[test]
    fn worker_join_is_bounded() {
        let gate = Arc::new(crate::clock::StopFlag::new());
        let g = gate.clone();
        let mut w = Worker::spawn("test-worker", move || {
            g.wait_timeout(Duration::from_secs(30));
        })
        .unwrap();
        assert!(!w.join_timeout(Duration::from_millis(20)));
        assert!(!w.is_finished());
        gate.set();
        assert!(w.join_timeout(Duration::from_secs(5)));
        assert!(w.is_finished());
    }
}
