//! State-directory files: owner-only, written atomically, never read or
//! written through a symlink.
//!
//! Every state file is tiny and security-relevant (a PIN hash, a TOTP secret,
//! the back-off counters), so one small set of primitives serves them all:
//!
//! * writes go to a fresh `O_EXCL` temp file in the same directory, are
//!   fsynced and then renamed over the target — a power cut leaves either the
//!   old file or the new one, never a truncated one, and a symlink planted at
//!   the target is replaced rather than followed;
//! * reads open with `O_NOFOLLOW | O_NONBLOCK` and check the *opened* file is
//!   a regular file of bounded size, so a FIFO cannot hang the GTK thread and
//!   there is no check-then-open race.

use crate::error::{Result, StateError};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Where state lives: `$SOC_STATE_DIR`, else `$XDG_CONFIG_HOME/soc-wall`, else
/// `~/.config/soc-wall`. Empty variables count as unset.
pub fn resolve_state_dir(soc_state_dir: Option<&str>, xdg_config_home: Option<&str>, home: Option<&str>) -> PathBuf {
    let set = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(PathBuf::from);
    if let Some(dir) = set(soc_state_dir) {
        return dir;
    }
    let config =
        set(xdg_config_home).unwrap_or_else(|| set(home).unwrap_or_else(|| PathBuf::from("/")).join(".config"));
    config.join("soc-wall")
}

/// [`resolve_state_dir`] over the process environment.
pub fn state_dir_from_env() -> PathBuf {
    let var = |name: &str| std::env::var(name).ok();
    resolve_state_dir(var("SOC_STATE_DIR").as_deref(), var("XDG_CONFIG_HOME").as_deref(), var("HOME").as_deref())
}

/// Create the state directory owner-only (0700), and tighten one that already
/// exists with group/other access: the files inside name internal hosts and
/// hold the lock's secrets.
pub fn ensure_state_dir(dir: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| StateError::io(dir, e))?;
    let meta = fs::metadata(dir).map_err(|e| StateError::io(dir, e))?;
    if !meta.is_dir() {
        return Err(StateError::NotRegular { path: dir.to_path_buf() });
    }
    if meta.permissions().mode() & 0o077 != 0 {
        // Best effort: a directory we do not own (an admin-provided mount)
        // cannot be tightened, and the 0600 files still protect themselves.
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)); // audit-allow: best-effort, see comment above
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fsync a directory so a rename inside it survives a power cut. Best effort:
/// some filesystems refuse to sync a directory handle.
fn sync_dir(dir: &Path) {
    let Ok(handle) = File::open(dir) else { return };
    let _ = handle.sync_all(); // audit-allow: best-effort; some filesystems refuse to sync a directory
}

fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

/// Replace `path` with `data` (mode 0600), atomically and durably.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(StateError::InvalidInput(format!("{}: not a file path", path.display())));
    };
    ensure_state_dir(dir)?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| StateError::Random)?; // audit-allow: getrandom errno is not actionable; StateError::Random is the typed form
    let tmp = dir.join(format!(".{}.{}.tmp", name.to_string_lossy(), hex(&nonce)));
    let written = write_new(&tmp, data).and_then(|()| fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp); // audit-allow: best-effort cleanup; the write error is returned
        return Err(StateError::io(path, e));
    }
    sync_dir(dir);
    Ok(())
}

/// Create `path` with `data` (mode 0600), failing if anything is already
/// there — for files that must never overwrite (config/overrides export).
pub fn write_exclusive(path: &Path, data: &[u8]) -> Result<()> {
    write_new(path, data).map_err(|e| StateError::io(path, e))
}

fn read_opened(mut file: File, path: &Path, cap: u64) -> Result<Zeroizing<Vec<u8>>> {
    let meta = file.metadata().map_err(|e| StateError::io(path, e))?;
    if !meta.is_file() {
        return Err(StateError::NotRegular { path: path.to_path_buf() });
    }
    let too_large = || StateError::TooLarge { path: path.to_path_buf(), limit: cap };
    if meta.len() > cap {
        return Err(too_large());
    }
    let mut buf = Zeroizing::new(Vec::new());
    (&mut file).take(cap.saturating_add(1)).read_to_end(&mut buf).map_err(|e| StateError::io(path, e))?;
    if !u64::try_from(buf.len()).is_ok_and(|n| n <= cap) {
        return Err(too_large());
    }
    Ok(buf)
}

/// Read a state file of at most `cap` bytes; `Ok(None)` when it does not
/// exist. A symlink at `path` is an error, not a redirect.
pub(crate) fn read_capped(path: &Path, cap: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let opened =
        OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path);
    match opened {
        Ok(file) => read_opened(file, path, cap).map(Some),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Err(StateError::NotRegular { path: path.to_path_buf() }),
        Err(e) => Err(StateError::io(path, e)),
    }
}

/// Read a file the operator picked (config/overrides import): symlinks are
/// followed, but the opened file must still be a regular one within `cap`.
pub fn read_user_file(path: &Path, cap: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| StateError::io(path, e))?;
    read_opened(file, path, cap)
}

/// Whether anything exists at `path` — a dangling symlink counts, so a
/// credential file that cannot be read still reads as "enrolled" and the gate
/// stays shut.
pub(crate) fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Remove a state file; a missing one is fine.
pub(crate) fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StateError::io(path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::symlink;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn state_dir_resolution() {
        assert_eq!(resolve_state_dir(Some("/s"), Some("/x"), Some("/h")), PathBuf::from("/s"));
        assert_eq!(resolve_state_dir(Some(""), Some("/x"), Some("/h")), PathBuf::from("/x/soc-wall"));
        assert_eq!(resolve_state_dir(None, None, Some("/h")), PathBuf::from("/h/.config/soc-wall"));
        assert_eq!(resolve_state_dir(None, Some(""), None), PathBuf::from("/.config/soc-wall"));
    }

    #[test]
    fn atomic_write_is_owner_only_and_leaves_no_temp_file() {
        let tmp = TempDir::new();
        let dir = tmp.path().join("state");
        let file = dir.join("f.json");
        write_atomic(&file, b"one").unwrap();
        write_atomic(&file, b"two").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"two");
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn an_existing_loose_directory_is_tightened() {
        let tmp = TempDir::new();
        let dir = tmp.path().join("loose");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_state_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn a_symlink_at_the_target_is_replaced_not_followed() {
        let tmp = TempDir::new();
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        let link = tmp.path().join("config.pin");
        symlink(&victim, &link).unwrap();

        assert!(matches!(read_capped(&link, 64), Err(StateError::NotRegular { .. })));
        write_atomic(&link, b"new").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert!(fs::symlink_metadata(&link).unwrap().is_file());
        assert_eq!(&**read_capped(&link, 64).unwrap().unwrap(), b"new");
    }

    #[test]
    fn reads_are_bounded_and_refuse_non_files() {
        let tmp = TempDir::new();
        assert!(read_capped(&tmp.path().join("missing"), 8).unwrap().is_none());
        let big = tmp.path().join("big");
        fs::write(&big, [b'x'; 9]).unwrap();
        assert!(matches!(read_capped(&big, 8), Err(StateError::TooLarge { .. })));
        assert!(matches!(read_capped(tmp.path(), 8), Err(StateError::NotRegular { .. })));
        assert!(matches!(read_user_file(tmp.path(), 8), Err(StateError::NotRegular { .. })));
    }

    #[test]
    fn a_dangling_symlink_still_counts_as_present() {
        let tmp = TempDir::new();
        let link = tmp.path().join("config.pin");
        symlink(tmp.path().join("nowhere"), &link).unwrap();
        assert!(exists(&link));
        remove(&link).unwrap();
        assert!(!exists(&link));
        remove(&link).unwrap();
    }
}
