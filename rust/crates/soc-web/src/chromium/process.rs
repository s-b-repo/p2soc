//! The browser process, behind a small trait so the supervision logic can be
//! exercised without starting a real Chromium.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running browser.
pub trait Browser: Send {
    fn pid(&self) -> u32;
    /// `Some(code)` once the process has exited (`-1` when killed by a signal).
    fn exited(&mut self) -> Option<i32>;
    /// Ask it to shut down (SIGTERM), so it can flush cookies to disk.
    fn terminate(&mut self);
    /// Kill it outright.
    fn kill(&mut self);
}

/// Starts browsers. The real one is [`SystemLauncher`]; tests supply a fake.
pub trait Launcher: Send + Sync {
    /// Start `argv[0]` with the rest as arguments.
    fn launch(&self, argv: &[String]) -> std::io::Result<Box<dyn Browser>>;
}

/// Spawns the browser as a child process with its output discarded.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLauncher;

impl Launcher for SystemLauncher {
    fn launch(&self, argv: &[String]) -> std::io::Result<Box<dyn Browser>> {
        let (program, args) = argv.split_first().ok_or_else(|| std::io::Error::other("empty command line"))?;
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Box::new(ChildBrowser(child)))
    }
}

struct ChildBrowser(Child);

impl Browser for ChildBrowser {
    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn exited(&mut self) -> Option<i32> {
        match self.0.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1)),
            Ok(None) => None,
            // The child cannot be waited on any more: it is gone for our purposes.
            Err(_) => Some(-1), // audit-allow: an unwaitable child is treated as gone, as documented above
        }
    }

    fn terminate(&mut self) {
        if self.exited().is_none() && !send_signal(self.0.id(), "TERM") {
            let _ = self.0.kill(); // audit-allow: best-effort, the child may already be dead
        }
    }

    fn kill(&mut self) {
        let _ = self.0.kill(); // audit-allow: best-effort, the child may already be dead
    }
}

/// Deliver a signal through `kill(1)`: the workspace forbids `unsafe`, and the
/// standard library can only SIGKILL its own children. The pid is a number, so
/// nothing configurable reaches this command line; an absolute path keeps
/// `$PATH` out of it.
fn send_signal(pid: u32, signal: &str) -> bool {
    ["/bin/kill", "/usr/bin/kill"].iter().any(|kill| {
        Command::new(kill)
            .arg(format!("-{signal}"))
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Terminate the browser and actually wait for it, escalating to a kill, so a
/// shutdown never orphans a half-dead process holding the profile lock.
pub fn reap(browser: &mut dyn Browser, grace: Duration) {
    if browser.exited().is_some() {
        return;
    }
    browser.terminate();
    if wait_exit(browser, grace) {
        return;
    }
    browser.kill();
    wait_exit(browser, Duration::from_secs(2));
}

fn wait_exit(browser: &mut dyn Browser, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if browser.exited().is_some() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The pid recorded in a profile's `SingletonLock` (a symlink named
/// `<host>-<pid>`), if that process really runs this profile.
///
/// The check is an exact `--user-data-dir=<profile>` argument, not a substring
/// of the command line: `/wd/chromium/a` is a prefix of `/wd/chromium/ab`, and
/// a recycled pid must never get a healthy sibling panel killed.
pub fn orphan_pid(profile: &Path, proc_root: &Path) -> Option<u32> {
    let lock = std::fs::read_link(profile.join("SingletonLock")).ok()?;
    let pid: u32 = lock.to_str()?.rsplit_once('-')?.1.parse().ok()?;
    let cmdline = std::fs::read(proc_root.join(pid.to_string()).join("cmdline")).ok()?;
    let wanted = format!("--user-data-dir={}", profile.to_str()?);
    cmdline.split(|b| *b == 0).any(|arg| arg == wanted.as_bytes()).then_some(pid)
}

/// Clear a Chromium left behind by a host that died without stopping it. It
/// would still hold the profile's singleton lock, so every new launch would
/// hand off to it and exit at once: the panel would respawn forever around a
/// window nothing drives. Returns the pid that was signalled, if any.
pub fn reap_orphan(profile: &Path) -> Option<u32> {
    let proc_root = Path::new("/proc");
    let pid = orphan_pid(profile, proc_root)?;
    if pid == std::process::id() {
        return None;
    }
    send_signal(pid, "TERM");
    let gone = |pid: u32| !proc_root.join(pid.to_string()).exists();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !gone(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !gone(pid) {
        send_signal(pid, "KILL");
    }
    Some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stubborn {
        terminated: bool,
        killed: bool,
        obeys_term: bool,
    }

    impl Browser for Stubborn {
        fn pid(&self) -> u32 {
            1
        }
        fn exited(&mut self) -> Option<i32> {
            (self.killed || (self.terminated && self.obeys_term)).then_some(0)
        }
        fn terminate(&mut self) {
            self.terminated = true;
        }
        fn kill(&mut self) {
            self.killed = true;
        }
    }

    #[test]
    fn reap_terminates_then_escalates() {
        let mut polite = Stubborn { terminated: false, killed: false, obeys_term: true };
        reap(&mut polite, Duration::from_millis(50));
        assert!(polite.terminated && !polite.killed);

        let mut stubborn = Stubborn { terminated: false, killed: false, obeys_term: false };
        reap(&mut stubborn, Duration::from_millis(50));
        assert!(stubborn.terminated && stubborn.killed);
    }

    #[test]
    fn system_launcher_runs_and_reaps_a_child() {
        let mut child = SystemLauncher.launch(&["/bin/sleep".into(), "30".into()]).unwrap();
        assert!(child.exited().is_none());
        assert!(child.pid() > 0);
        reap(child.as_mut(), Duration::from_secs(5));
        assert!(child.exited().is_some());
        assert!(SystemLauncher.launch(&[]).is_err());
        assert!(SystemLauncher.launch(&["/nonexistent/soc-web-test-binary".into()]).is_err());
    }

    #[test]
    fn orphan_needs_an_exact_profile_argument() {
        let root = std::env::temp_dir().join(format!("soc-web-orphan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let profile = root.join("chromium").join("a");
        let proc_root = root.join("proc");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(proc_root.join("4242")).unwrap();
        // No lock at all.
        assert_eq!(orphan_pid(&profile, &proc_root), None);
        std::os::unix::fs::symlink("kiosk-host-4242", profile.join("SingletonLock")).unwrap();

        let cmdline = |profile_arg: &str| {
            let text = format!("/usr/lib/chromium/chromium\0--app=x\0--user-data-dir={profile_arg}\0--no-first-run\0");
            std::fs::write(proc_root.join("4242").join("cmdline"), text).unwrap();
        };
        cmdline(profile.to_str().unwrap());
        assert_eq!(orphan_pid(&profile, &proc_root), Some(4242));
        // A sibling panel whose profile path merely starts the same is not ours.
        cmdline(&format!("{}b", profile.display()));
        assert_eq!(orphan_pid(&profile, &proc_root), None);
        // A recycled pid running something else entirely.
        std::fs::write(proc_root.join("4242").join("cmdline"), "/bin/bash\0").unwrap();
        assert_eq!(orphan_pid(&profile, &proc_root), None);
        // A stale lock whose process is gone.
        std::fs::remove_dir_all(proc_root.join("4242")).unwrap();
        assert_eq!(orphan_pid(&profile, &proc_root), None);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
