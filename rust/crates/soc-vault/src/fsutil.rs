//! Private, atomic file writes shared by the config file, the TOTP store, the
//! dev vault and the backup writer.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::crypto::random_bytes;

/// A sibling temp path that an attacker cannot predict. `create_new` below
/// would refuse a planted file or symlink anyway; the random suffix just keeps
/// a stale leftover from blocking the next write.
fn temp_sibling(path: &Path) -> io::Result<PathBuf> {
    let mut suffix = [0u8; 8];
    random_bytes(&mut suffix).map_err(|e| io::Error::other(e.to_string()))?;
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(); // audit-allow: default is the intended fallback (path without a file name)
    Ok(path.with_file_name(format!(".{name}.{}.{hex}.tmp", std::process::id())))
}

/// Write `data` to `path` with mode 0600, atomically: the bytes land in a
/// fresh sibling file (`O_EXCL`, so a pre-planted symlink or a wider-mode
/// leftover is never written through), are fsynced, then renamed over `path`.
pub(crate) fn write_private_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = temp_sibling(path)?;
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp); // audit-allow: best-effort cleanup; the write error is what gets returned
    }
    result
}

/// `mkdir -p` with mode 0700 on every directory this call creates, and on the
/// leaf even when it already existed.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    // Best effort, as a directory we do not own cannot be re-moded.
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)); // audit-allow: best-effort: a directory we do not own cannot be re-moded
    Ok(())
}

#[cfg(test)]
pub(crate) mod testdir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(0);

    /// A unique scratch directory under the system temp dir, removed on drop.
    /// Tests take paths as arguments, so nothing here touches process env.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new(tag: &str) -> TestDir {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("soc-vault-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create test dir");
            TestDir(dir)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdir::TestDir;
    use super::*;

    #[test]
    fn writes_0600_and_replaces_atomically() {
        let d = TestDir::new("fsutil");
        let p = d.path().join("f");
        write_private_atomic(&p, b"one").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_private_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let leftovers: Vec<_> = fs::read_dir(d.path()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(leftovers.len(), 1, "temp file left behind: {leftovers:?}");
    }

    #[test]
    fn private_dir_is_0700() {
        let d = TestDir::new("fsutil-dir");
        let p = d.path().join("a/b");
        create_private_dir(&p).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o700);
    }
}
