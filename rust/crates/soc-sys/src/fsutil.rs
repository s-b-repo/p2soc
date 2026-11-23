//! Filesystem primitives shared by the crate.
//!
//! Every state file the wall writes goes through [`write_atomic`]: a reader
//! must see the old document or the new one, never a torn one, and a planted
//! symlink must never redirect the write. Reads of files that other parties
//! can influence are size-capped and refuse anything but a regular file.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Take an exclusive advisory lock without following an existing link or FIFO.
/// Keep the returned file open for the whole operation.
pub fn exclusive_lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "lock must be a regular file"));
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    Ok(file)
}

/// A fully written, fsynced temp file waiting to be renamed over its target.
/// Dropping it without [`Staged::commit`] removes the temp file, so a failure
/// part-way through a multi-file update leaves the previous files intact.
#[derive(Debug)]
pub struct Staged {
    tmp: PathBuf,
    dest: PathBuf,
    committed: bool,
}

impl Staged {
    /// Rename the staged file over its destination and flush the directory
    /// entry, so the swap survives a power cut.
    pub fn commit(mut self) -> io::Result<()> {
        fs::rename(&self.tmp, &self.dest)?;
        self.committed = true;
        if let Some(dir) = self.dest.parent() {
            // Best effort: some filesystems refuse to fsync a directory.
            let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
            let _ = File::open(dir).and_then(|d| d.sync_all()); // audit-allow: best-effort, some filesystems refuse a directory fsync
        }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.tmp); // audit-allow: best-effort cleanup of an abandoned temp file
        }
    }
}

/// Write `data` to a private temp file beside `dest` (same directory, so the
/// later rename can never cross filesystems) and fsync it.
///
/// The temp file is always created with `O_EXCL | O_NOFOLLOW`: a pre-planted
/// file or symlink is never written through. A leftover from a crashed run
/// (same pid after a reboot) is unlinked and the create retried under a new
/// name, so a power cut can never block later writes. `mode` is applied with
/// `fchmod`, so the umask does not decide who can read the result.
pub fn stage(dest: &Path, data: &[u8], mode: u32) -> io::Result<Staged> {
    let dir = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let base = dest.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let mut attempt = 0;
    let (tmp, mut file) = loop {
        let mut name = OsString::from(".");
        name.push(base);
        name.push(format!(".{}.{}.tmp", std::process::id(), TMP_SEQ.fetch_add(1, Ordering::Relaxed)));
        let tmp = dir.join(name);
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode & 0o7777)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp);
        match opened {
            Ok(file) => break (tmp, file),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 3 => {
                attempt += 1;
                let _ = fs::remove_file(&tmp); // audit-allow: best-effort, the create is retried under a new name
            }
            Err(e) => return Err(e),
        }
    };
    let staged = Staged { tmp, dest: dest.to_path_buf(), committed: false };
    file.set_permissions(Permissions::from_mode(mode & 0o7777))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(staged)
}

/// Atomically replace `dest` with `data` (temp file + fsync + rename).
pub fn write_atomic(dest: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    stage(dest, data, mode)?.commit()
}

/// `mkdir -p` with an explicit mode for every directory it creates.
pub fn ensure_dir(dir: &Path, mode: u32) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(mode).create(dir)
}

/// Open `path` only if it is a regular file, without following a final
/// symlink and without blocking on a FIFO. A drift check or a state read must
/// not hang on (or be redirected by) something planted in its way.
pub fn open_regular(path: &Path) -> io::Result<File> {
    let file =
        OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
    }
    Ok(file)
}

/// Read at most `cap` bytes of a text file; a larger file is an error rather
/// than an unbounded allocation.
pub fn read_capped(path: &Path, cap: u64) -> io::Result<String> {
    let mut buf = Vec::new();
    File::open(path)?.take(cap.saturating_add(1)).read_to_end(&mut buf)?;
    if u64::try_from(buf.len()).map_or(true, |n| n > cap) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("larger than {cap} bytes")));
    }
    String::from_utf8(buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("not valid UTF-8 ({})", e.utf8_error())))
}

/// The first `cap` bytes of a file, lossily decoded — for `/proc` entries,
/// which are small, may hold arbitrary bytes and can vanish mid-read.
pub fn read_prefix_lossy(path: &Path, cap: u64) -> Option<String> {
    let mut buf = Vec::new();
    File::open(path).ok()?.take(cap).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Make `path` absolute against `cwd` and normalise it lexically (`.`, `..`
/// and repeated separators removed) without touching the filesystem.
pub fn abspath(path: &Path, cwd: &Path) -> PathBuf {
    let joined = if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::RootDir => out.push("/"),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                // `/..` is `/`: never pop the root.
                if out.parent().is_some() {
                    out.pop();
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    if out.as_os_str().is_empty() { PathBuf::from("/") } else { out }
}

/// The effective user id.
pub fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Whether the effective user may write to (create entries in) `path`. Uses
/// the EFFECTIVE ids (`AT_EACCESS`), matching how the wall runs under a
/// service account.
pub fn access_writable(path: &Path) -> bool {
    rustix::fs::accessat(rustix::fs::CWD, path, rustix::fs::Access::WRITE_OK, rustix::fs::AtFlags::EACCESS).is_ok()
}

/// True if the effective user can create a file in `dir`: it exists and is
/// writable, or its nearest existing ancestor is. A probe-create would have
/// side effects, so this only asks the kernel.
pub fn dir_writable(dir: &Path) -> bool {
    let mut p = dir;
    while !p.as_os_str().is_empty() && !p.exists() {
        match p.parent() {
            Some(parent) => p = parent,
            None => break,
        }
    }
    access_writable(if p.as_os_str().is_empty() { Path::new(".") } else { p })
}

/// One `/etc/passwd` entry (the fields the wall needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}

/// Look an account up in a passwd-format file by name or uid. Local accounts
/// only — the kiosk's users are created by the installer in `/etc/passwd`.
pub fn passwd_lookup(passwd: &Path, matches: impl Fn(&PasswdEntry) -> bool) -> Option<PasswdEntry> {
    let text = read_capped(passwd, 4 << 20).ok()?;
    text.lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            let home = f.nth(2)?;
            Some(PasswdEntry { name: name.to_string(), uid, home: PathBuf::from(home) })
        })
        .find(|e| matches(e))
}

/// The system account database.
pub const PASSWD: &str = "/etc/passwd";

/// Expand a leading `~` or `~user` the way a shell would. `home` is the
/// caller's home directory; other users are looked up in `passwd`. Anything
/// that cannot be resolved is returned unchanged.
pub fn expand_user(path: &str, home: Option<&Path>, passwd: &Path) -> String {
    let Some(rest) = path.strip_prefix('~') else {
        return path.to_string();
    };
    let (user, tail) = rest.find('/').and_then(|i| rest.split_at_checked(i)).unwrap_or((rest, ""));
    let base = if user.is_empty() {
        home.map(Path::to_path_buf).or_else(|| passwd_lookup(passwd, |e| e.uid == euid()).map(|e| e.home))
    } else {
        passwd_lookup(passwd, |e| e.name == user).map(|e| e.home)
    };
    let Some(base) = base else {
        return path.to_string();
    };
    let base = base.to_string_lossy();
    let expanded = format!("{}{tail}", base.trim_end_matches('/'));
    if expanded.is_empty() { "/".to_string() } else { expanded }
}

/// First executable named `name` on a `PATH`-style list.
pub fn which(name: &str, path_var: &str) -> Option<PathBuf> {
    path_var
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| Path::new(d).join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::symlink;

    #[test]
    fn atomic_write_sets_mode_and_leaves_no_temp() {
        let t = TempDir::new("fsutil-atomic");
        let dest = t.path().join("state.json");
        write_atomic(&dest, b"one", 0o600).unwrap();
        write_atomic(&dest, b"two", 0o640).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"two");
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(t.names(), vec!["state.json"]);
    }

    #[test]
    fn a_dropped_stage_removes_its_temp_and_keeps_the_old_file() {
        let t = TempDir::new("fsutil-stage");
        let dest = t.path().join("f");
        write_atomic(&dest, b"old", 0o644).unwrap();
        drop(stage(&dest, b"new", 0o644).unwrap());
        assert_eq!(fs::read(&dest).unwrap(), b"old");
        assert_eq!(t.names(), vec!["f"]);
    }

    #[test]
    fn leftovers_from_a_crashed_run_do_not_block_the_write() {
        let t = TempDir::new("fsutil-stale");
        let dest = t.path().join("state");
        // Plant temp files (one of them a symlink to a victim) under the very
        // names the next attempts will use.
        let victim = t.write("victim", "precious");
        let next = TMP_SEQ.load(Ordering::Relaxed);
        let stale = |seq: u64| t.path().join(format!(".state.{}.{seq}.tmp", std::process::id()));
        fs::write(stale(next), b"stale").unwrap();
        symlink(&victim, stale(next + 1)).unwrap();
        write_atomic(&dest, b"fresh", 0o600).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"fresh");
        assert_eq!(fs::read(&victim).unwrap(), b"precious", "a planted link is unlinked, never written through");
    }

    #[test]
    fn atomic_write_replaces_a_symlink_instead_of_writing_through_it() {
        let t = TempDir::new("fsutil-symlink");
        let victim = t.path().join("victim");
        fs::write(&victim, b"precious").unwrap();
        let dest = t.path().join("state");
        symlink(&victim, &dest).unwrap();
        write_atomic(&dest, b"data", 0o600).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert!(fs::symlink_metadata(&dest).unwrap().is_file());
    }

    #[test]
    fn open_regular_refuses_symlinks_fifos_and_directories() {
        let t = TempDir::new("fsutil-regular");
        let real = t.path().join("real");
        fs::write(&real, b"x").unwrap();
        let link = t.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(open_regular(&real).is_ok());
        assert!(open_regular(&link).is_err());
        assert!(open_regular(t.path()).is_err());
    }

    #[test]
    fn read_capped_rejects_oversized_files() {
        let t = TempDir::new("fsutil-cap");
        let f = t.path().join("big");
        fs::write(&f, vec![b'a'; 100]).unwrap();
        assert!(read_capped(&f, 99).is_err());
        assert_eq!(read_capped(&f, 100).unwrap().len(), 100);
    }

    #[test]
    fn abspath_is_lexical() {
        let cwd = Path::new("/work/dir");
        assert_eq!(abspath(Path::new("a/../b/./c"), cwd), Path::new("/work/dir/b/c"));
        assert_eq!(abspath(Path::new("/x//y/../z/"), cwd), Path::new("/x/z"));
        assert_eq!(abspath(Path::new("../../../.."), cwd), Path::new("/"));
        assert_eq!(abspath(Path::new(""), cwd), Path::new("/work/dir"));
    }

    #[test]
    fn dir_writable_walks_up_to_the_nearest_existing_ancestor() {
        let t = TempDir::new("fsutil-writable");
        assert!(dir_writable(&t.path().join("not/yet/created")));
        let ro = t.path().join("ro");
        fs::create_dir(&ro).unwrap();
        fs::set_permissions(&ro, Permissions::from_mode(0o555)).unwrap();
        // root ignores permission bits, so only assert the refusal when unprivileged
        if euid() != 0 {
            assert!(!dir_writable(&ro.join("child")));
        }
        fs::set_permissions(&ro, Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn tilde_expansion() {
        let t = TempDir::new("fsutil-passwd");
        let passwd = t.path().join("passwd");
        fs::write(&passwd, "root:x:0:0:root:/root:/bin/sh\nsoc:x:1001:1001::/home/soc/:/bin/sh\nbroken\n").unwrap();
        let home = Path::new("/home/me");
        assert_eq!(expand_user("~/keys/id", Some(home), &passwd), "/home/me/keys/id");
        assert_eq!(expand_user("~", Some(home), &passwd), "/home/me");
        assert_eq!(expand_user("~soc/kh", Some(home), &passwd), "/home/soc/kh");
        assert_eq!(expand_user("~nobody-here/kh", Some(home), &passwd), "~nobody-here/kh");
        assert_eq!(expand_user("/abs/~x", Some(home), &passwd), "/abs/~x");
        assert!(passwd_lookup(&passwd, |e| e.name == "soc").is_some());
        assert!(passwd_lookup(&passwd, |e| e.name == "broken").is_none());
    }

    #[test]
    fn which_finds_only_executables() {
        let t = TempDir::new("fsutil-which");
        let tool = t.path().join("tool");
        fs::write(&tool, "#!/bin/sh\n").unwrap();
        let path_var = format!("/nonexistent:{}", t.path().display());
        assert_eq!(which("tool", &path_var), None);
        fs::set_permissions(&tool, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(which("tool", &path_var), Some(tool));
    }
}
