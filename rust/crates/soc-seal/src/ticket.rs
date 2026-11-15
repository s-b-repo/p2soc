//! The session ticket: makes repeat unseals cheap, across processes.
//!
//! A full unseal runs the KDF twice (~128 MiB each on the 1 GB Pi) and happens
//! far more often than once per boot. After the first, the master is served
//! from a per-uid ticket on tmpfs: the master wrapped under a key derived from
//! `host.key`, bound to this boot, to the exact sealed bytes and to an
//! authenticated expiry.
//!
//! Security: the ticket key is derived from `host.key` + machine-id, the same
//! inputs as the seal, so reading a ticket proves nothing beyond what reading
//! the seal already gives. Skipping the slow KDF gives nothing away either:
//! `host.key` is 256 random bits, and anyone holding it can run the KDF
//! themselves. A re-seal, a reboot, a removed `host.key` or a different
//! machine-id all turn the ticket into a harmless miss, and every failure here
//! falls back to the sealed files. It is ciphertext, never the plaintext
//! master, and it never reaches the disk.
//!
//! Layout: `expires(8, BE) | nonce(12) | AES-256-GCM(master, aad = expires)`.

use crate::blob::{self, NONCE_LEN, TAG_LEN};
use crate::fsio;
use crate::rng;
use hmac::{Hmac, KeyInit, Mac};
use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const FILE: &str = "soc-unseal.ticket";
const CONTEXT: &[u8] = b"p2soc-unseal-ticket/v1";
/// Default lifetime in seconds; `SOC_UNSEAL_CACHE_TTL` overrides, 0 disables.
pub(crate) const DEFAULT_TTL: u64 = 3600;
const MAX_BYTES: usize = 64 * 1024;
const EXPIRY_LEN: usize = 8;

const TMPFS_MAGIC: i128 = 0x0102_1994;
const RAMFS_MAGIC: i128 = 0x8584_58f6;

/// Everything a ticket is bound to. Change any of it and the ticket is a miss.
pub(crate) struct Binding<'a> {
    pub host_key: &'a [u8],
    pub machine_id: &'a [u8],
    pub boot_id: &'a [u8],
    pub pin_blob: &'a [u8],
    pub master_blob: &'a [u8],
}

impl Binding<'_> {
    fn key(&self) -> Option<Zeroizing<[u8; 32]>> {
        // Length-prefixed, so no two different tuples hash alike.
        let mut bound = Sha256::new();
        for part in [self.machine_id, self.boot_id, self.pin_blob, self.master_blob] {
            bound.update(u64::try_from(part.len()).ok()?.to_be_bytes());
            bound.update(part);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(self.host_key).ok()?;
        mac.update(CONTEXT);
        mac.update(&bound.finalize());
        Some(Zeroizing::new(mac.finalize().into_bytes().into()))
    }
}

/// Wrap `master` in a ticket valid until `expires` (Unix seconds).
pub(crate) fn wrap(binding: &Binding<'_>, master: &[u8], expires: u64) -> Option<Vec<u8>> {
    let key = binding.key()?;
    let nonce: [u8; NONCE_LEN] = rng::array().ok()?;
    let aad = expires.to_be_bytes();
    let sealed = blob::aead_seal(&key, &nonce, &aad, master).ok()?;
    let mut raw = Vec::with_capacity(EXPIRY_LEN + NONCE_LEN + sealed.len());
    raw.extend_from_slice(&aad);
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&sealed);
    Some(raw)
}

/// The master from a ticket, or `None` on any kind of miss: expired, issued
/// further ahead than a ticket can be (a tampered expiry), or not
/// authenticating under `binding`.
pub(crate) fn unwrap(binding: &Binding<'_>, raw: &[u8], now: u64, ttl: u64) -> Option<Zeroizing<Vec<u8>>> {
    if raw.len() < EXPIRY_LEN + NONCE_LEN + TAG_LEN {
        return None;
    }
    let (aad, rest) = raw.split_at_checked(EXPIRY_LEN)?;
    let (nonce, sealed) = rest.split_at_checked(NONCE_LEN)?;
    let expires = u64::from_be_bytes(aad.try_into().ok()?);
    if !(now < expires && expires <= now.saturating_add(ttl)) {
        return None;
    }
    blob::aead_open(&*binding.key()?, nonce, aad, sealed)
}

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// This boot's id; a ticket from another boot never opens.
pub(crate) fn boot_id() -> Option<Vec<u8>> {
    let raw = std::fs::read("/proc/sys/kernel/random/boot_id").ok()?;
    let id = raw.trim_ascii();
    (!id.is_empty()).then(|| id.to_vec())
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A private, RAM-backed directory for this uid, held open.
///
/// Every check is made on the opened descriptor and every file is reached
/// relative to it, so the directory that was vetted is the directory that is
/// used: nothing can be swapped in between the check and the write.
pub(crate) struct RuntimeDir {
    dir: File,
}

impl RuntimeDir {
    /// Open `path` if it is a real directory (not a symlink), owned by this
    /// uid, closed to group and other and — unless `require_ram` is off, which
    /// only tests do — on tmpfs/ramfs. The filesystem type comes from
    /// `fstatfs` on the descriptor rather than from matching the path against
    /// the mount table, which `..` or an intermediate symlink can fool.
    pub(crate) fn open(path: &Path, require_ram: bool) -> Option<RuntimeDir> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let dir = File::from(rustix::fs::open(path, flags, Mode::empty()).ok()?);
        let meta = dir.metadata().ok()?;
        if !meta.is_dir() || meta.uid() != euid() || meta.mode() & 0o077 != 0 {
            return None;
        }
        if require_ram {
            let fs_type = i128::from(rustix::fs::fstatfs(&dir).ok()?.f_type) & 0xffff_ffff;
            if fs_type != TMPFS_MAGIC && fs_type != RAMFS_MAGIC {
                return None;
            }
        }
        Some(RuntimeDir { dir })
    }

    /// The first usable candidate: `$XDG_RUNTIME_DIR`, `/run/user/<uid>`, and
    /// for root (whose services get no runtime dir) `/run/soc-display`. There
    /// is deliberately no fallback to a disk directory: no ticket at all then.
    pub(crate) fn locate(xdg_runtime_dir: Option<&Path>) -> Option<RuntimeDir> {
        let uid = euid();
        if let Some(found) = xdg_runtime_dir.and_then(|p| RuntimeDir::open(p, true)) {
            return Some(found);
        }
        if let Some(found) = RuntimeDir::open(Path::new(&format!("/run/user/{uid}")), true) {
            return Some(found);
        }
        if uid != 0 {
            return None;
        }
        let root_dir = Path::new("/run/soc-display");
        let _ = rustix::fs::mkdir(root_dir, Mode::RWXU); // audit-allow: best-effort; EEXIST is normal and open() below validates
        RuntimeDir::open(root_dir, true)
    }

    /// The raw ticket, if there is a plausible one.
    pub(crate) fn read(&self) -> Option<Vec<u8>> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let file = File::from(rustix::fs::openat(&self.dir, FILE, flags, Mode::empty()).ok()?);
        if file.metadata().ok()?.uid() != euid() {
            return None;
        }
        fsio::read_file_bounded(file, MAX_BYTES).ok().map(|raw| raw.to_vec())
    }

    /// Replace the ticket atomically (tmp + rename), 0600.
    pub(crate) fn write(&self, raw: &[u8]) -> io::Result<()> {
        let tmp = format!("{FILE}.{}.tmp", std::process::id());
        let _ = rustix::fs::unlinkat(&self.dir, &tmp, AtFlags::empty()); // audit-allow: best-effort removal of a stale tmp
        let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut file = File::from(rustix::fs::openat(&self.dir, &tmp, flags, Mode::RUSR | Mode::WUSR)?);
        let moved = file
            .write_all(raw)
            .and_then(|()| rustix::fs::renameat(&self.dir, &tmp, &self.dir, FILE).map_err(io::Error::from));
        if moved.is_err() {
            let _ = rustix::fs::unlinkat(&self.dir, &tmp, AtFlags::empty()); // audit-allow: best-effort cleanup; the write error is returned
        }
        moved
    }

    pub(crate) fn discard(&self) {
        let _ = rustix::fs::unlinkat(&self.dir, FILE, AtFlags::empty()); // audit-allow: best-effort discard of a cache entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsio::testdir::TestDir;
    use std::os::unix::fs::PermissionsExt;

    fn binding<'a>(boot: &'a [u8], master_blob: &'a [u8]) -> Binding<'a> {
        Binding { host_key: &[7u8; 32], machine_id: b"host-A", boot_id: boot, pin_blob: b"pin-blob", master_blob }
    }

    #[test]
    fn round_trips_within_its_lifetime() {
        let b = binding(b"boot-1", b"master-blob");
        let raw = wrap(&b, b"Master-PW!", 1_000 + 60).unwrap();
        assert_eq!(unwrap(&b, &raw, 1_000, 60).unwrap().as_slice(), b"Master-PW!");
        assert_eq!(unwrap(&b, &raw, 1_059, 60).unwrap().as_slice(), b"Master-PW!");
        assert!(!raw.windows(10).any(|w| w == b"Master-PW!"));
    }

    #[test]
    fn expired_or_too_far_ahead_is_a_miss() {
        let b = binding(b"boot-1", b"master-blob");
        let raw = wrap(&b, b"m", 1_060).unwrap();
        assert!(unwrap(&b, &raw, 1_060, 60).is_none(), "expired exactly now");
        assert!(unwrap(&b, &raw, 2_000, 60).is_none(), "long expired");
        // An expiry no ticket issued with this TTL could carry.
        assert!(unwrap(&b, &raw, 900, 60).is_none());
    }

    #[test]
    fn tampered_expiry_is_rejected_by_authentication() {
        let b = binding(b"boot-1", b"master-blob");
        let mut raw = wrap(&b, b"m", 1_060).unwrap();
        raw[..8].copy_from_slice(&1_090u64.to_be_bytes());
        // Plausible on the clock (now < expires <= now + ttl), but not what was sealed.
        assert!(unwrap(&b, &raw, 1_050, 60).is_none());
    }

    #[test]
    fn bound_to_boot_machine_host_key_and_sealed_bytes() {
        let b = binding(b"boot-1", b"master-blob");
        let raw = wrap(&b, b"m", 1_060).unwrap();
        assert!(unwrap(&binding(b"boot-2", b"master-blob"), &raw, 1_000, 60).is_none());
        assert!(unwrap(&binding(b"boot-1", b"master-blob\0"), &raw, 1_000, 60).is_none());
        let other_host = Binding { machine_id: b"host-B", ..binding(b"boot-1", b"master-blob") };
        assert!(unwrap(&other_host, &raw, 1_000, 60).is_none());
        let other_key = Binding { host_key: &[8u8; 32], ..binding(b"boot-1", b"master-blob") };
        assert!(unwrap(&other_key, &raw, 1_000, 60).is_none());
        // Moving a byte between two bound parts must change the key.
        let shifted = Binding { pin_blob: b"pin-blobm", master_blob: b"aster-blob", ..binding(b"boot-1", b"") };
        assert!(unwrap(&shifted, &raw, 1_000, 60).is_none());
    }

    #[test]
    fn garbage_is_a_miss_not_a_panic() {
        let b = binding(b"boot-1", b"master-blob");
        for garbage in [&b""[..], b"short", &[0xff; 64], &[0u8; 35]] {
            assert!(unwrap(&b, garbage, 1_000, 60).is_none());
        }
    }

    #[test]
    fn runtime_dir_must_be_private_and_a_real_directory() {
        let d = TestDir::new("rt");
        let private = d.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(RuntimeDir::open(&private, false).is_some());

        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(RuntimeDir::open(&private, false).is_none(), "group-readable");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();

        let link = d.join("link");
        std::os::unix::fs::symlink(&private, &link).unwrap();
        assert!(RuntimeDir::open(&link, false).is_none(), "through a symlink");
        std::fs::write(d.join("file"), b"").unwrap();
        assert!(RuntimeDir::open(&d.join("file"), false).is_none(), "not a directory");
        assert!(RuntimeDir::open(&d.join("absent"), false).is_none());
    }

    #[test]
    fn ticket_is_never_placed_on_a_disk_filesystem() {
        // The verdict comes from the filesystem the directory is really on.
        let d = TestDir::new("ram");
        let fs_type = i128::from(rustix::fs::statfs(d.path()).unwrap().f_type) & 0xffff_ffff;
        let on_ram = fs_type == TMPFS_MAGIC || fs_type == RAMFS_MAGIC;
        assert_eq!(RuntimeDir::open(d.path(), true).is_some(), on_ram);
        // The crate's own source tree is on a disk (or at least not ours to
        // cache in): a private directory there is still refused.
        let on_disk = Path::new(env!("CARGO_MANIFEST_DIR"));
        let disk_type = i128::from(rustix::fs::statfs(on_disk).unwrap().f_type) & 0xffff_ffff;
        if disk_type != TMPFS_MAGIC && disk_type != RAMFS_MAGIC {
            assert!(RuntimeDir::locate(Some(on_disk)).is_none_or(|rd| rd.dir.metadata().unwrap().mode() & 0o077 == 0));
            assert!(RuntimeDir::open(on_disk, true).is_none());
        }
    }

    #[test]
    fn file_is_private_replaced_atomically_and_not_read_through_a_symlink() {
        let d = TestDir::new("rtfile");
        let rd = RuntimeDir::open(d.path(), false).unwrap();
        assert!(rd.read().is_none());
        rd.write(b"first").unwrap();
        rd.write(b"second").unwrap();
        assert_eq!(rd.read().unwrap(), b"second");
        let mode = std::fs::metadata(d.join(FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1, "no tmp left behind");

        rd.discard();
        assert!(rd.read().is_none());
        std::fs::write(d.join("elsewhere"), b"planted").unwrap();
        std::os::unix::fs::symlink(d.join("elsewhere"), d.join(FILE)).unwrap();
        assert!(rd.read().is_none());
    }
}
