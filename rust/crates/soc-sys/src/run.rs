//! Running external commands.
//!
//! Everything in this crate that needs another program goes through a
//! [`Runner`], so the decision logic is testable with a scripted fake and the
//! real implementation is the single place a process is spawned: an explicit
//! argv (never a shell), no stdin, bounded output and a hard timeout.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// What a finished command produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit status; `None` when the process was killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Something that can run a command to completion.
pub trait Runner {
    /// Run `argv` (program first) and wait at most `timeout`. A timeout is an
    /// `Err` of kind [`io::ErrorKind::TimedOut`]; the child is killed.
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<Output>;
}

/// The real thing: `std::process::Command`, no shell.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

/// Output kept per stream; the rest is drained and dropped so a chatty child
/// can neither block on a full pipe nor grow our memory.
const OUTPUT_CAP: usize = 256 * 1024;

fn drain(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let room = OUTPUT_CAP.saturating_sub(kept.len());
            kept.extend_from_slice(&chunk[..n.min(room)]);
        }
        let _ = tx.send(String::from_utf8_lossy(&kept).into_owned()); // audit-allow: best-effort, the receiver may have timed out and gone
    });
    rx
}

impl Runner for SystemRunner {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<Output> {
        let (program, args) =
            argv.split_first().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let out = child.stdout.take().map(drain);
        let err = child.stderr.take().map(drain);
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill(); // audit-allow: best-effort, the child may already be gone
                let _ = child.wait(); // audit-allow: best-effort reap after kill
                return Err(io::Error::new(io::ErrorKind::TimedOut, format!("{program} timed out")));
            }
            thread::sleep(Duration::from_millis(10));
        };
        // A grandchild can keep the pipe open after the child exits; do not
        // wait for it longer than a moment.
        let collect = |rx: Option<mpsc::Receiver<String>>| {
            rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(1)).ok()).unwrap_or_default() // audit-allow: default is the intended fallback (no output)
        };
        Ok(Output { code: status.code(), stdout: collect(out), stderr: collect(err) })
    }
}

/// Build an owned argv from string literals.
pub fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::cell::RefCell;

    /// A scripted runner: records every argv and answers from a closure.
    pub struct FakeRunner<F: Fn(&[String]) -> io::Result<Output>> {
        pub calls: RefCell<Vec<Vec<String>>>,
        answer: F,
    }

    impl<F: Fn(&[String]) -> io::Result<Output>> FakeRunner<F> {
        pub fn new(answer: F) -> Self {
            FakeRunner { calls: RefCell::new(Vec::new()), answer }
        }
    }

    impl<F: Fn(&[String]) -> io::Result<Output>> Runner for FakeRunner<F> {
        fn run(&self, argv: &[String], _timeout: Duration) -> io::Result<Output> {
            self.calls.borrow_mut().push(argv.to_vec());
            (self.answer)(argv)
        }
    }

    pub fn exit(code: i32, stdout: &str) -> io::Result<Output> {
        Ok(Output { code: Some(code), stdout: stdout.to_string(), stderr: String::new() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_without_a_shell_and_captures_both_streams() {
        let out = SystemRunner.run(&argv(&["/bin/echo", "a b", "$HOME", ";", "id"]), Duration::from_secs(5)).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout, "a b $HOME ; id\n");
        assert_eq!(out.stderr, "");
    }

    #[test]
    fn reports_exit_status_and_missing_programs() {
        let out = SystemRunner.run(&argv(&["/bin/false"]), Duration::from_secs(5)).unwrap();
        assert_eq!(out.code, Some(1));
        assert!(SystemRunner.run(&argv(&["/nonexistent/program"]), Duration::from_secs(1)).is_err());
        assert!(SystemRunner.run(&[], Duration::from_secs(1)).is_err());
    }

    #[test]
    fn a_hung_child_is_killed_at_the_deadline() {
        let started = Instant::now();
        let err = SystemRunner.run(&argv(&["/bin/sleep", "30"]), Duration::from_millis(150)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
