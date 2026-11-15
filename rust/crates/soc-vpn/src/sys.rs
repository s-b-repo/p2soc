//! Process-control syscalls, through `rustix`'s safe wrappers so the crate
//! carries no `unsafe` of its own. Kept in one module so the few
//! platform-specific calls the supervisor needs are easy to review.

use rustix::event::{PollFd, PollFlags};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};

// Raw signal numbers at this module's boundary: the `ChildProc` trait and its
// test mocks speak in plain integers, and rustix's typed `Signal` is used only
// inside the syscall wrappers below.
pub(crate) const SIGTERM: i32 = libc::SIGTERM;
pub(crate) const SIGKILL: i32 = libc::SIGKILL;

/// What a signal-0 probe says about a pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidState {
    Alive,
    Dead,
    /// No permission to ask, or not a usable pid: leave it alone.
    Unknown,
}

/// Signal a whole process group. Refuses group ids 0 and 1: group 0 is our
/// own and 1 is init's.
pub(crate) fn kill_group(pgid: u32, signal: i32) -> io::Result<()> {
    let pid = match i32::try_from(pgid).ok().filter(|p| *p > 1).and_then(Pid::from_raw) {
        Some(pid) => pid,
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "refusing to signal process group <= 1")),
    };
    let signal = Signal::from_named_raw(signal)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a valid signal number"))?;
    rustix::process::kill_process_group(pid, signal).map_err(Into::into)
}

/// Whether `pid` names a live process (a signal-0 existence + permission test).
pub(crate) fn pid_state(pid: u32) -> PidState {
    let Some(pid) = i32::try_from(pid).ok().filter(|p| *p > 0).and_then(Pid::from_raw) else {
        return PidState::Unknown;
    };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => PidState::Alive,
        Err(e) if e == rustix::io::Errno::SRCH => PidState::Dead,
        Err(_) => PidState::Unknown, // audit-allow: any other errno (EPERM, ...) is genuinely unknown
    }
}

/// Whether our child `pid` has exited, *without reaping it*. An unreaped
/// child keeps its pid — and so its process-group id — reserved, which is
/// what makes signalling that group safe from pid reuse. `WNOWAIT` leaves the
/// zombie in place; `WNOHANG` returns `None` while it is still running.
pub(crate) fn has_exited(pid: u32) -> io::Result<bool> {
    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a usable pid"));
    };
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    Ok(rustix::process::waitid(WaitId::Pid(pid), options)?.is_some())
}

/// Wait up to `timeout_ms` for `fd` to become readable (or hang up). A
/// negative timeout blocks indefinitely.
pub(crate) fn poll_readable(fd: BorrowedFd<'_>, timeout_ms: i32) -> io::Result<bool> {
    let mut fds = [PollFd::from_borrowed_fd(fd, PollFlags::IN)];
    let timeout = (timeout_ms >= 0).then(|| rustix::event::Timespec {
        tv_sec: i64::from(timeout_ms) / 1000,
        tv_nsec: (i64::from(timeout_ms) % 1000) * 1_000_000,
    });
    match rustix::event::poll(&mut fds, timeout.as_ref()) {
        Ok(ready) => Ok(ready > 0),
        Err(rustix::io::Errno::INTR) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// A close-on-exec pipe `(read, write)`.
pub(crate) fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(Into::into)
}

/// Forbid core dumps for this process and its children. systemd's watchdog
/// ends a wedged unit with SIGABRT, which would have systemd-coredump write
/// this process's memory — decrypted vault credentials included — to disk.
pub(crate) fn disable_core_dumps() -> io::Result<()> {
    let limit = rustix::process::Rlimit { current: Some(0), maximum: Some(0) };
    rustix::process::setrlimit(rustix::process::Resource::Core, limit).map_err(Into::into)
}

/// The effective user id.
pub(crate) fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn group_ids_zero_and_one_are_refused() {
        assert!(kill_group(0, 0).is_err());
        assert!(kill_group(1, 0).is_err());
        assert!(kill_group(u32::MAX, 0).is_err());
    }

    #[test]
    fn pid_states() {
        assert_eq!(pid_state(std::process::id()), PidState::Alive);
        assert_eq!(pid_state(0), PidState::Unknown);
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert_eq!(pid_state(pid), PidState::Dead);
    }

    #[test]
    fn exit_is_observed_without_reaping() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !has_exited(pid).unwrap() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Still a zombie, so its pid is pinned and it can be reaped normally.
        assert_eq!(pid_state(pid), PidState::Alive);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn pipe_and_poll() {
        let (r, w) = pipe().unwrap();
        let mut reader = std::fs::File::from(r);
        let mut writer = std::fs::File::from(w);
        assert!(!poll_readable(std::os::fd::AsFd::as_fd(&reader), 0).unwrap());
        writer.write_all(b"x").unwrap();
        assert!(poll_readable(std::os::fd::AsFd::as_fd(&reader), 1000).unwrap());
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).unwrap();
        drop(writer);
        // Hang-up counts as readable: the next read returns EOF.
        assert!(poll_readable(std::os::fd::AsFd::as_fd(&reader), 1000).unwrap());
    }
}
