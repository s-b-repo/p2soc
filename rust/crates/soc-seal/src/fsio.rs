//! File plumbing for the secret directory: bounded reads, staged (tmp + fsync
//! + rename) writes, and the advisory lock that serialises writers.

use rustix::fs::{FlockOperation, OFlags};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Upper bound on any file in the secret directory. Real ones are under 1 KiB;
/// the bound stops a planted or corrupt file from being slurped into memory.
pub(crate) const MAX_SEAL_FILE: usize = 1 << 20;

fn flag(f: OFlags) -> i32 {
    i32::from_ne_bytes(f.bits().to_ne_bytes())
}

/// Read a whole regular file of at most `max` bytes into a buffer that is
/// wiped on drop. Oversized files are an error, never silently truncated: a
/// truncated `host.key` or blob would derive the wrong key.
pub(crate) fn read_bounded(path: &Path, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    // O_NONBLOCK: a FIFO planted under a seal file name must not hang the boot.
    let file = OpenOptions::new().read(true).custom_flags(flag(OFlags::NONBLOCK)).open(path)?;
    read_file_bounded(file, max)
}

pub(crate) fn read_file_bounded(mut file: File, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    let too_large = || io::Error::new(io::ErrorKind::InvalidData, "file is larger than any sealed secret");
    let size = usize::try_from(meta.len()).map_err(|_| too_large())?; // audit-allow: TryFromIntError carries nothing beyond "too large"
    if size > max {
        return Err(too_large());
    }
    // One allocation of the final size (+1 to notice a file that grew), so the
    // contents are never left behind in a reallocated buffer.
    let mut buf = Zeroizing::new(vec![0u8; size + 1]);
    let mut filled = 0;
    loop {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
        if filled == buf.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file changed while it was being read"));
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Who a staged file should belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    pub uid: u32,
    pub gid: u32,
}

impl Owner {
    pub(crate) fn of(meta: &fs::Metadata) -> Owner {
        Owner { uid: meta.uid(), gid: meta.gid() }
    }
}

pub(crate) fn tmp_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".tmp");
    PathBuf::from(os)
}

/// Write `data` to `<path>.tmp`, fsync'd, and return the tmp path. The caller
/// renames it into place once every file of the seal is staged, so an
/// interrupted seal never leaves a torn file under `path`.
///
/// The tmp file is always a fresh inode (stale one unlinked, then
/// `O_EXCL | O_NOFOLLOW`): a leftover from a crashed run, or a symlink planted
/// under that name, can neither receive the secret nor lend it its mode.
/// `owner` not being settable is an error, not a shrug — a seal its readers
/// cannot open is a lockout.
pub(crate) fn stage(path: &Path, data: &[u8], owner: Option<Owner>, mode: u32) -> io::Result<PathBuf> {
    let tmp = tmp_path(path);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file =
        OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(flag(OFlags::NOFOLLOW)).open(&tmp)?;
    let written = (|| {
        if let Some(o) = owner {
            std::os::unix::fs::fchown(&file, Some(o.uid), Some(o.gid))?;
        }
        file.set_permissions(Permissions::from_mode(mode))?;
        file.write_all(data)?;
        file.sync_all()
    })();
    match written {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = fs::remove_file(&tmp); // audit-allow: best-effort cleanup; the write error is returned
            Err(e)
        }
    }
}

/// Make completed renames durable, in order: without this a power cut can
/// persist a later rename and lose an earlier one. Best effort — some
/// filesystems cannot fsync a directory.
pub(crate) fn fsync_dir(dir: &Path) {
    let Ok(d) = File::open(dir) else { return };
    let _ = d.sync_all(); // audit-allow: best-effort; some filesystems cannot fsync a directory
}

/// Rename staged `names` into place, in order, each durable before the next.
/// On failure, also says how many renames had already happened: after the
/// first one the directory is part-way between two seals. `before_rename` is
/// a fault-injection seam (production passes a no-op).
pub(crate) fn commit(
    dir: &Path,
    names: &[&str],
    before_rename: &dyn Fn(&str) -> io::Result<()>,
) -> std::result::Result<(), (usize, io::Error)> {
    for (done, name) in names.iter().enumerate() {
        let path = dir.join(name);
        before_rename(name).and_then(|()| fs::rename(tmp_path(&path), &path)).map_err(|e| (done, e))?;
        fsync_dir(dir);
    }
    Ok(())
}

/// Remove staged leftovers; missing ones are fine.
pub(crate) fn discard_tmp(dir: &Path, names: &[&str]) {
    for name in names {
        let _ = fs::remove_file(tmp_path(&dir.join(name))); // audit-allow: best-effort; a missing leftover is fine
    }
}

/// What became of an attempt to take the seal lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockState {
    Held,
    /// Another process held it for the whole wait.
    Contended,
    /// The directory cannot be opened or the filesystem has no `flock`.
    Unavailable,
}

/// Exclusive advisory lock on the secret directory, released on drop.
///
/// Commits touch several files, and two writers interleaving them could pair
/// one's `host.key` with the other's blobs — permanently unreadable — and at
/// boot the wall and the VPN supervisor can both reach a legacy seal at once.
/// Held by every writer, and around the expensive unseal path too, so N
/// waiters on the 1 GB Pi run the 128 MiB KDF one at a time and then hit the
/// fresh ticket.
///
/// `flock()` on the directory itself: no lock file to leave behind, works for
/// any process that can open the directory (read-only included), excludes
/// across threads because each call opens its own description, and dies with
/// its holder, so a crash cannot wedge the next boot.
pub(crate) struct DirLock {
    state: LockState,
    _dir: Option<File>,
}

impl DirLock {
    pub(crate) fn acquire(dir: &Path, wait: Duration) -> DirLock {
        let unavailable = DirLock { state: LockState::Unavailable, _dir: None };
        let Ok(handle) = OpenOptions::new().read(true).custom_flags(flag(OFlags::DIRECTORY)).open(dir) else {
            return unavailable;
        };
        let deadline = Instant::now() + wait;
        loop {
            match rustix::fs::flock(&handle, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return DirLock { state: LockState::Held, _dir: Some(handle) },
                Err(e) if e == rustix::io::Errno::WOULDBLOCK || e == rustix::io::Errno::INTR => {
                    if Instant::now() >= deadline {
                        return DirLock { state: LockState::Contended, _dir: None };
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return unavailable, // audit-allow: any flock failure means "lock unavailable", reported via LockState
            }
        }
    }

    pub(crate) fn state(&self) -> LockState {
        self.state
    }

    pub(crate) fn held(&self) -> bool {
        self.state == LockState::Held
    }
}

#[cfg(test)]
pub(crate) mod testdir {
    //! Crate-local scratch directories for tests: unique per call, removed on
    //! drop, never shared between tests.

    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new(label: &str) -> TestDir {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("soc-seal-{label}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            TestDir(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        pub(crate) fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            // A test may have left a directory read-only on purpose.
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdir::TestDir;
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn stage_writes_a_private_tmp_file_and_commit_renames_it() {
        let d = TestDir::new("stage");
        let target = d.join("master.enc");
        let tmp = stage(&target, b"blob", None, 0o600).unwrap();
        assert_eq!(tmp, d.join("master.enc.tmp"));
        assert_eq!(mode(&tmp), 0o600);
        assert!(!target.exists());
        commit(d.path(), &["master.enc"], &|_| Ok(())).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"blob");
        assert!(!tmp.exists());
    }

    #[test]
    fn stage_replaces_a_stale_tmp_and_never_writes_through_a_symlink() {
        let d = TestDir::new("stale");
        let target = d.join("pin.enc");
        let victim = d.join("victim");
        fs::write(&victim, b"untouched").unwrap();
        fs::set_permissions(&victim, Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&victim, tmp_path(&target)).unwrap();
        let tmp = stage(&target, b"secret", None, 0o600).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert!(!fs::symlink_metadata(&tmp).unwrap().file_type().is_symlink());
        assert_eq!(mode(&tmp), 0o600);
        assert_eq!(fs::read(&tmp).unwrap(), b"secret");
    }

    #[test]
    fn stage_honours_the_requested_mode_and_cleans_up_on_failure() {
        let d = TestDir::new("mode");
        let tmp = stage(&d.join("a"), b"x", None, 0o640).unwrap();
        assert_eq!(mode(&tmp), 0o640);
        if rustix::process::geteuid().is_root() {
            return;
        }
        // Giving the file to root is not something an ordinary user may do.
        let err = stage(&d.join("b"), b"x", Some(Owner { uid: 0, gid: 0 }), 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(!d.join("b.tmp").exists());
    }

    #[test]
    fn read_bounded_refuses_oversized_and_non_regular_files() {
        let d = TestDir::new("read");
        fs::write(d.join("ok"), b"12345").unwrap();
        assert_eq!(read_bounded(&d.join("ok"), 5).unwrap().as_slice(), b"12345");
        assert_eq!(read_bounded(&d.join("ok"), 4).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(read_bounded(d.path(), 64).is_err());
        assert_eq!(read_bounded(&d.join("absent"), 64).unwrap_err().kind(), io::ErrorKind::NotFound);
        fs::write(d.join("empty"), b"").unwrap();
        assert!(read_bounded(&d.join("empty"), 64).unwrap().is_empty());
    }

    #[test]
    fn lock_excludes_a_second_holder_and_is_released_on_drop() {
        let d = TestDir::new("lock");
        let first = DirLock::acquire(d.path(), Duration::ZERO);
        assert!(first.held());
        let second = DirLock::acquire(d.path(), Duration::from_millis(60));
        assert_eq!(second.state(), LockState::Contended);
        drop(first);
        assert!(DirLock::acquire(d.path(), Duration::ZERO).held());
    }

    #[test]
    fn lock_on_a_missing_directory_is_unavailable_not_an_error() {
        let d = TestDir::new("nolock");
        assert_eq!(DirLock::acquire(&d.join("absent"), Duration::ZERO).state(), LockState::Unavailable);
    }
}
