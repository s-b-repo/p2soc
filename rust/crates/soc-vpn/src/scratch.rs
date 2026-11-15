//! Transient key material: a vault-provided `.ovpn` / `.conf` and the OpenVPN
//! management socket.
//!
//! Each supervisor owns one `0700` directory, `soc-vpn/vpn-<pid>-<n>`, under
//! the runtime dir. Per-supervisor rather than per-process because
//! supervisors are threads: with one shared name two OpenVPN entries would
//! overwrite each other's keys, and one's password could reach the other's
//! openvpn. Files are `0600`, created exclusively, and removed on every exit
//! path; what a SIGKILLed process leaves behind is swept at the next start.

use crate::sys;
pub use crate::sys::PidState;
use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// One supervisor's private runtime directory and what it currently holds.
pub struct Scratch {
    root: PathBuf,
    dir: PathBuf,
    instance: u32,
    materialized: Option<PathBuf>,
    mgmt: Option<PathBuf>,
}

/// Create `path` as a directory only we can enter, or verify that an existing
/// one already is. Anything else — a symlink, another owner — is an error:
/// falling back to a broader directory would put keys where others can read
/// them.
fn private_dir(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::other(format!("{} is not a directory", path.display())));
    }
    if meta.uid() != sys::euid() {
        return Err(io::Error::other(format!("{} is owned by another user", path.display())));
    }
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(path, Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl Scratch {
    /// `base` is the runtime dir (`$XDG_RUNTIME_DIR` or `/run`). Nothing is
    /// created until a file is needed.
    pub fn new(base: &Path, pid: u32, instance: u32) -> Scratch {
        let root = base.join("soc-vpn");
        let dir = root.join(format!("vpn-{pid}-{instance}"));
        Scratch { root, dir, instance, materialized: None, mgmt: None }
    }

    /// The shared `soc-vpn` directory (swept for orphans at start).
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn materialized(&self) -> Option<&Path> {
        self.materialized.as_deref()
    }

    fn ensure(&self) -> io::Result<()> {
        private_dir(&self.root)?;
        private_dir(&self.dir)
    }

    /// Write `content` (a private key, usually) to `<dir>/<name>` with mode
    /// `0600` and remember it for cleanup. A trailing newline is added when
    /// missing.
    pub fn write_secret(&mut self, name: &str, content: &str) -> io::Result<PathBuf> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid config file name"));
        }
        self.cleanup_materialized();
        self.ensure()?;
        let path = self.dir.join(name);
        // Tracked before the first byte lands: a torn write still holds key
        // material that must be removed.
        self.materialized = Some(path.clone());
        let written = (|| {
            let _ = fs::remove_file(&path); // audit-allow: best-effort cleanup
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            file.write_all(content.as_bytes())?;
            if !content.ends_with('\n') {
                file.write_all(b"\n")?;
            }
            file.flush()
        })();
        match written {
            Ok(()) => Ok(path),
            Err(e) => {
                self.cleanup_materialized();
                Err(e)
            }
        }
    }

    /// Where the management socket of this supervisor's openvpn would live.
    pub fn mgmt_preview(&self) -> PathBuf {
        self.dir.join(format!("openvpn-{}.sock", self.instance))
    }

    /// Reserve the management socket path for a new attempt: the directory
    /// exists, any stale socket is gone, and the path is tracked for cleanup.
    /// The OpenVPN password transits this socket, hence the private directory.
    pub fn mgmt_path(&mut self) -> io::Result<PathBuf> {
        self.ensure()?;
        let path = self.mgmt_preview();
        let _ = fs::remove_file(&path); // audit-allow: best-effort cleanup
        self.mgmt = Some(path.clone());
        Ok(path)
    }

    fn drop_dir(&self) {
        // Fails while the directory still holds the other artifact; fine.
        let _ = fs::remove_dir(&self.dir); // audit-allow: best-effort cleanup
    }

    /// Remove the materialized config. Idempotent; a file already gone is fine.
    pub fn cleanup_materialized(&mut self) {
        if let Some(path) = self.materialized.take() {
            let _ = fs::remove_file(path); // audit-allow: best-effort cleanup
            self.drop_dir();
        }
    }

    /// Remove the management socket left by the last attempt.
    pub fn cleanup_mgmt(&mut self) {
        if let Some(path) = self.mgmt.take() {
            let _ = fs::remove_file(path); // audit-allow: best-effort cleanup
            self.drop_dir();
        }
    }

    pub fn cleanup(&mut self) {
        self.cleanup_materialized();
        self.cleanup_mgmt();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// The pid an entry of the `soc-vpn` directory belongs to, and whether it is
/// a per-supervisor directory (`vpn-<pid>-<n>`) or one of the flat files
/// older versions left behind (`openvpn-<pid>.sock` / `.ovpn`).
fn orphan_owner(name: &str) -> Option<(u32, bool)> {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = name.strip_prefix("vpn-") {
        let (pid, instance) = rest.split_once('-')?;
        return (digits(pid) && digits(instance)).then(|| pid.parse().ok()).flatten().map(|p| (p, true));
    }
    let rest = name.strip_prefix("openvpn-")?;
    let pid = rest.strip_suffix(".sock").or_else(|| rest.strip_suffix(".ovpn"))?;
    digits(pid).then(|| pid.parse().ok()).flatten().map(|p| (p, false))
}

/// Clear what a crashed or SIGKILLed supervisor left under `root`, including
/// its materialized keys. No cleanup code runs on SIGKILL, on OOM or when
/// systemd's watchdog aborts the unit, so this is the only cleanup those
/// exits get. Everything is pid-scoped: an entry whose pid is neither ours
/// nor a live process is an orphan. Best effort; never follows a symlink.
pub fn sweep_orphans(root: &Path, own_pid: u32, pid_state: &dyn Fn(u32) -> PidState) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some((pid, is_dir)) = name.to_str().and_then(orphan_owner) else {
            continue;
        };
        if pid == own_pid || pid_state(pid) != PidState::Dead {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if is_dir {
            if !meta.file_type().is_dir() {
                continue;
            }
            // An unreadable directory has nothing we can remove.
            for file in fs::read_dir(&path).into_iter().flatten().flatten() {
                let _ = fs::remove_file(file.path()); // audit-allow: best-effort cleanup
            }
            let _ = fs::remove_dir(&path); // audit-allow: best-effort cleanup
        } else {
            let _ = fs::remove_file(&path); // audit-allow: best-effort cleanup
        }
    }
}

/// [`sweep_orphans`] against the real process table.
pub fn sweep(root: &Path) {
    sweep_orphans(root, std::process::id(), &sys::pid_state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempDir;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o777
    }

    fn files_under(path: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(path) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    out.extend(files_under(&e.path()));
                } else {
                    out.push(e.path());
                }
            }
        }
        out
    }

    #[test]
    fn secret_is_0600_in_a_0700_dir_and_removed_with_it() {
        let tmp = TempDir::new("scratch");
        let mut s = Scratch::new(tmp.path(), 4242, 1);
        let path = s.write_secret("wg0.conf", "[Interface]\nPrivateKey=SECRET").unwrap();
        assert_eq!(path, tmp.path().join("soc-vpn/vpn-4242-1/wg0.conf"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "[Interface]\nPrivateKey=SECRET\n");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(s.dir()), 0o700);
        assert_eq!(mode(s.root()), 0o700);
        s.cleanup_materialized();
        assert!(!path.exists() && !s.dir().exists());
        assert!(s.materialized().is_none());
        s.cleanup_materialized();
    }

    #[test]
    fn cleanup_tolerates_a_file_already_gone() {
        let tmp = TempDir::new("scratch");
        let mut s = Scratch::new(tmp.path(), 1, 1);
        let path = s.write_secret("a.ovpn", "k").unwrap();
        fs::remove_file(&path).unwrap();
        s.cleanup();
        assert!(s.materialized().is_none());
    }

    #[test]
    fn dropping_the_scratch_removes_everything() {
        let tmp = TempDir::new("scratch");
        {
            let mut s = Scratch::new(tmp.path(), 1, 7);
            s.write_secret("openvpn-7.ovpn", "PRIVATE KEY").unwrap();
            let sock = s.mgmt_path().unwrap();
            fs::write(&sock, "").unwrap();
        }
        assert!(files_under(tmp.path()).is_empty());
        assert!(!tmp.path().join("soc-vpn/vpn-1-7").exists());
    }

    #[test]
    fn two_supervisors_share_no_key_or_socket() {
        let tmp = TempDir::new("scratch");
        let mut a = Scratch::new(tmp.path(), 9, 1);
        let mut b = Scratch::new(tmp.path(), 9, 2);
        let pa = a.write_secret("openvpn-1.ovpn", "KEY-A").unwrap();
        let pb = b.write_secret("openvpn-2.ovpn", "KEY-B").unwrap();
        assert_ne!(pa, pb);
        assert_ne!(a.mgmt_preview(), b.mgmt_preview());
        b.cleanup();
        assert_eq!(fs::read_to_string(&pa).unwrap(), "KEY-A\n");
    }

    #[test]
    fn a_preexisting_loose_file_is_replaced_not_reused() {
        let tmp = TempDir::new("scratch");
        let mut s = Scratch::new(tmp.path(), 1, 1);
        s.write_secret("wg0.conf", "old").unwrap();
        fs::set_permissions(s.dir().join("wg0.conf"), Permissions::from_mode(0o644)).unwrap();
        let path = s.write_secret("wg0.conf", "new").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    }

    #[test]
    fn a_symlinked_runtime_dir_is_refused() {
        let tmp = TempDir::new("scratch");
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, tmp.path().join("soc-vpn")).unwrap();
        let mut s = Scratch::new(tmp.path(), 1, 1);
        assert!(s.write_secret("wg0.conf", "PrivateKey=K").is_err());
        assert!(s.mgmt_path().is_err());
        assert!(files_under(&elsewhere).is_empty());
        assert!(s.materialized().is_none());
    }

    #[test]
    fn a_failed_write_leaves_no_partial_key() {
        let tmp = TempDir::new("scratch");
        let mut s = Scratch::new(tmp.path(), 1, 1);
        // A directory squatting on the file name makes the exclusive create fail.
        fs::create_dir_all(s.dir().join("wg0.conf")).unwrap();
        assert!(s.write_secret("wg0.conf", "PrivateKey=K").is_err());
        assert!(s.materialized().is_none());
        assert!(files_under(tmp.path()).is_empty());
    }

    #[test]
    fn file_names_cannot_escape_the_directory() {
        let tmp = TempDir::new("scratch");
        let mut s = Scratch::new(tmp.path(), 1, 1);
        for bad in ["", "..", "../x.conf", "a/b.conf"] {
            assert!(s.write_secret(bad, "k").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_loosened_directory_is_tightened() {
        let tmp = TempDir::new("scratch");
        let root = tmp.path().join("soc-vpn");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, Permissions::from_mode(0o755)).unwrap();
        let mut s = Scratch::new(tmp.path(), 1, 1);
        s.write_secret("x.ovpn", "k").unwrap();
        assert_eq!(mode(&root), 0o700);
    }

    #[test]
    fn orphan_names() {
        assert_eq!(orphan_owner("vpn-123-4"), Some((123, true)));
        assert_eq!(orphan_owner("openvpn-77.sock"), Some((77, false)));
        assert_eq!(orphan_owner("openvpn-77.ovpn"), Some((77, false)));
        for other in ["unrelated.txt", "vpn-12", "vpn-a-1", "vpn-1-b", "openvpn-.sock", "openvpn-1.conf", "xvpn-1-1"] {
            assert_eq!(orphan_owner(other), None, "{other}");
        }
    }

    #[test]
    fn sweep_clears_only_what_a_dead_supervisor_left() {
        let tmp = TempDir::new("sweep");
        let d = tmp.path();
        let (dead, live, unknown, own) = (111u32, 222u32, 333u32, 444u32);
        let state = |pid: u32| match pid {
            111 => PidState::Dead,
            222 => PidState::Alive,
            _ => PidState::Unknown,
        };
        for pid in [dead, live, unknown, own] {
            let dir = d.join(format!("vpn-{pid}-1"));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("wg0.conf"), "PrivateKey=SECRET\n").unwrap();
        }
        fs::write(d.join(format!("openvpn-{dead}.ovpn")), "PRIVATE KEY\n").unwrap();
        fs::write(d.join(format!("openvpn-{dead}.sock")), "").unwrap();
        fs::write(d.join("unrelated.txt"), "keep\n").unwrap();

        sweep_orphans(d, own, &state);

        let mut left: Vec<String> =
            fs::read_dir(d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["unrelated.txt", "vpn-222-1", "vpn-333-1", "vpn-444-1"]);
        assert!(d.join("vpn-222-1/wg0.conf").exists());
    }

    #[test]
    fn sweep_never_follows_a_symlink() {
        let tmp = TempDir::new("sweep");
        let victim = tmp.path().join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("keep.txt"), "x").unwrap();
        let root = tmp.path().join("soc-vpn");
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&victim, root.join("vpn-111-1")).unwrap();
        sweep_orphans(&root, 1, &|_| PidState::Dead);
        assert!(victim.join("keep.txt").exists());
    }

    #[test]
    fn sweep_of_a_missing_directory_is_a_no_op() {
        sweep_orphans(Path::new("/nonexistent/soc-vpn"), 1, &|_| PidState::Dead);
    }
}
