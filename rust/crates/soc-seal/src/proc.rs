//! Run a helper program with a secret on its stdin and a hard deadline.
//!
//! Secrets travel on stdin or stdout, never argv (argv is world-readable in
//! /proc). Captured output lands in one pre-sized buffer that is wiped on
//! drop, so a secret is not left behind in reallocated memory.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Larger than any password or master; small enough that writing it to a pipe
/// (64 KiB by default) can never block on a child that does not read.
const MAX_STDIN: usize = 16 * 1024;
const POLL: Duration = Duration::from_millis(10);
/// How long to wait for output after the child has exited (a grandchild may
/// still hold the pipe open; it must not be able to hang us).
const DRAIN_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(crate) enum RunError {
    /// The program does not exist.
    NotFound,
    /// It ran past its deadline and was killed.
    TimedOut,
    /// It printed more than the caller allowed for.
    TooMuchOutput,
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::NotFound => f.write_str("program not found"),
            RunError::TimedOut => f.write_str("timed out"),
            RunError::TooMuchOutput => f.write_str("unexpectedly large output"),
            RunError::Io(e) => write!(f, "{e}"),
        }
    }
}

pub(crate) struct Finished {
    /// True only for a clean exit with status 0.
    pub success: bool,
    pub stdout: Zeroizing<Vec<u8>>,
    /// At most a few KiB, for error messages. Helpers do not echo secrets.
    pub stderr: Vec<u8>,
}

impl std::fmt::Debug for Finished {
    /// Captured output may be a secret: say how much there was, not what.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Finished")
            .field("success", &self.success)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}

/// Read up to `cap` bytes into one allocation; `None` if there was more.
pub(crate) fn read_capped(mut src: impl Read, cap: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; cap.saturating_add(1)]);
    let mut filled = 0;
    while filled < buf.len() {
        let Some(room) = buf.get_mut(filled..) else { break };
        match src.read(room) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break, // audit-allow: a failed read ends the capture; the exit status decides the outcome
        }
    }
    if filled > cap {
        return None;
    }
    buf.truncate(filled);
    Some(buf)
}

/// Run `program args…`, feed it `stdin`, and collect up to `stdout_cap` bytes
/// of output, killing it at `timeout`.
pub(crate) fn run<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    stdin: Option<&[u8]>,
    timeout: Duration,
    stdout_cap: usize,
) -> Result<Finished, RunError> {
    if stdin.is_some_and(|s| s.len() > MAX_STDIN) {
        return Err(RunError::Io(io::Error::new(io::ErrorKind::InvalidInput, "input too large")));
    }
    let mut busy_retries = 0;
    let mut child = loop {
        let spawned = Command::new(program)
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        match spawned {
            Ok(child) => break child,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(RunError::NotFound),
            // ETXTBSY: some other thread forked while the program file was
            // still open for writing (an upgrade in progress). It passes.
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && busy_retries < 100 => {
                busy_retries += 1;
                std::thread::sleep(POLL);
            }
            Err(e) => return Err(RunError::Io(e)),
        }
    };

    let (out_tx, out_rx) = mpsc::channel();
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || {
            let _ = out_tx.send(read_capped(out, stdout_cap)); // audit-allow: receiver gone means run() already returned
        });
    }
    let (err_tx, err_rx) = mpsc::channel();
    if let Some(err) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = err_tx.send(read_capped(err, 4096).map(|b| b.to_vec()).unwrap_or_default()); // audit-allow: receiver gone means run() already returned; stderr is diagnostic only
        });
    }
    if let (Some(mut pipe), Some(data)) = (child.stdin.take(), stdin) {
        // A child that exits without reading gives EPIPE; its exit status is
        // what matters, not this write. Dropping the pipe sends EOF.
        let _ = pipe.write_all(data); // audit-allow: EPIPE from a child that never reads is expected; exit status is what matters
    }

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill(); // audit-allow: best-effort teardown; the child may already be gone
                let _ = child.wait(); // audit-allow: best-effort reap after kill
                return Err(RunError::TimedOut);
            }
            Ok(None) => std::thread::sleep(POLL),
            Err(e) => {
                let _ = child.kill(); // audit-allow: best-effort teardown; the try_wait error is returned
                let _ = child.wait(); // audit-allow: best-effort reap after kill
                return Err(RunError::Io(e));
            }
        }
    };
    let stdout = match out_rx.recv_timeout(DRAIN_GRACE) {
        Ok(Some(buf)) => buf,
        Ok(None) => return Err(RunError::TooMuchOutput),
        Err(_) => return Err(RunError::TimedOut), // audit-allow: recv_timeout fails only on timeout or a dead reader thread; both mean no output in time
    };
    let stderr = err_rx.recv_timeout(DRAIN_GRACE).unwrap_or_default(); // audit-allow: default is the intended fallback (stderr is diagnostic only)
    Ok(Finished { success: status.success(), stdout, stderr })
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Find `name` in the directories of a `$PATH`-style list.
pub(crate) fn find_in(name: &str, path_var: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path_var).filter(|dir| dir.is_absolute()).map(|dir| dir.join(name)).find(|p| is_executable(p))
}

/// Find `name` in the system's own binary directories only. Used for the
/// programs an authentication decision rests on (`su`, `pamtester`): a
/// look-alike earlier on `$PATH` must be able neither to see the operator's
/// password nor to answer for the real one.
pub(crate) fn find_trusted(name: &str) -> Option<PathBuf> {
    const DIRS: [&str; 6] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/run/wrappers/bin", "/usr/local/bin"];
    DIRS.iter().map(|dir| Path::new(dir).join(name)).find(|p| is_executable(p))
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// Drop an executable `/bin/sh` script into `dir`.
    pub(crate) fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::script;
    use super::*;
    use crate::fsio::testdir::TestDir;

    const T: Duration = Duration::from_secs(10);

    #[test]
    fn feeds_stdin_and_captures_stdout() {
        let d = TestDir::new("proc");
        let echo = script(d.path(), "echo", r#"printf 'arg=%s in=' "$1"; cat"#);
        let done = run(&echo, &["x"], Some(b"secret"), T, 256).unwrap();
        assert!(done.success);
        assert_eq!(done.stdout.as_slice(), b"arg=x in=secret");
    }

    #[test]
    fn reports_failure_status_and_stderr() {
        let d = TestDir::new("procfail");
        let fail = script(d.path(), "fail", "echo nope >&2; exit 3");
        let done = run::<&str>(&fail, &[], None, T, 16).unwrap();
        assert!(!done.success);
        assert_eq!(done.stderr, b"nope\n");
    }

    #[test]
    fn kills_a_helper_that_overruns_its_deadline() {
        let d = TestDir::new("proctime");
        let slow = script(d.path(), "slow", "exec sleep 30");
        let started = Instant::now();
        let err = run::<&str>(&slow, &[], Some(b"x"), Duration::from_millis(150), 16).unwrap_err();
        assert!(matches!(err, RunError::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn missing_program_and_oversized_output_are_typed() {
        let d = TestDir::new("procmiss");
        assert!(matches!(run::<&str>(&d.join("absent"), &[], None, T, 16), Err(RunError::NotFound)));
        let loud = script(d.path(), "loud", "printf 0123456789");
        assert!(matches!(run::<&str>(&loud, &[], None, T, 4), Err(RunError::TooMuchOutput)));
        assert_eq!(run::<&str>(&loud, &[], None, T, 10).unwrap().stdout.as_slice(), b"0123456789");
    }

    #[test]
    fn a_helper_that_ignores_stdin_does_not_hang_or_fail() {
        let d = TestDir::new("procpipe");
        let deaf = script(d.path(), "deaf", "exit 0");
        assert!(run::<&str>(&deaf, &[], Some(&[b'x'; MAX_STDIN]), T, 16).unwrap().success);
        assert!(run::<&str>(&deaf, &[], Some(&[b'x'; MAX_STDIN + 1]), T, 16).is_err());
    }

    #[test]
    fn path_search_skips_relative_dirs_and_non_executables() {
        let d = TestDir::new("which");
        script(d.path(), "tool", "exit 0");
        std::fs::write(d.join("data"), b"").unwrap();
        let path_var = std::env::join_paths([Path::new("relative"), d.path()]).unwrap();
        assert_eq!(find_in("tool", &path_var), Some(d.join("tool")));
        assert_eq!(find_in("data", &path_var), None);
        assert_eq!(find_in("absent", &path_var), None);
    }
}
