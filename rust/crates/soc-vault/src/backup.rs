//! Portable, passphrase-encrypted backup of the Vaultwarden data dir.
//!
//! A backup exists so the vault can be restored on **different hardware**
//! after an SD-card failure. The host-bound seal cannot travel, so a backup is
//! encrypted under an operator passphrase kept off the box.
//!
//! On-disk format (one file), identical to the Python implementation's:
//!
//! ```text
//! "PSBK" | ALGO(1) | salt(16) | nonce(12) | AES-256-GCM(gzip(tar(src_dir)))
//! ```
//!
//! `ALGO` 1 is scrypt (N=2^17, r=8, p=1), 2 is PBKDF2-HMAC-SHA256 (600k, the
//! FIPS-approved option). Backups from earlier releases have no ALGO byte
//! (scrypt N=2^14) and stay restorable: a backup is the disaster-recovery
//! path, the one thing that must still open years later.
//!
//! The archive is built in memory — a kiosk vault is a handful of logins — and
//! both directions are size-capped so a huge or hostile input cannot exhaust
//! a 1 GB board.

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use crate::error::VaultError;
use crate::fsutil::write_private_atomic;

const MAGIC: &[u8; 4] = b"PSBK";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER: usize = MAGIC.len() + 1 + SALT_LEN + NONCE_LEN;
const LEGACY_HEADER: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;

/// NIST SP 800-63B floor for a user-chosen secret.
pub const MIN_PASSPHRASE: usize = 8;
/// Largest encrypted backup that is written or read (256 MiB).
pub const MAX_BLOB: u64 = 256 * 1024 * 1024;
/// Largest total of file contents a restore will write (512 MiB).
pub const MAX_RESTORED: u64 = 512 * 1024 * 1024;

const ALGO_LEGACY_SCRYPT: u8 = 0; // unlabelled legacy data; never written
const ALGO_SCRYPT: u8 = 1;
const ALGO_PBKDF2: u8 = 2;
const PBKDF2_ITERATIONS: u32 = 600_000;

/// The KDF a new backup is protected with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupKdf {
    /// scrypt — memory-hard, the default.
    Scrypt,
    /// PBKDF2-HMAC-SHA256 — for FIPS 140 deployments (`SOC_FIPS_KDF=1`).
    Pbkdf2,
}

impl BackupKdf {
    fn id(self) -> u8 {
        match self {
            BackupKdf::Scrypt => ALGO_SCRYPT,
            BackupKdf::Pbkdf2 => ALGO_PBKDF2,
        }
    }
}

type Key = Zeroizing<[u8; 32]>;
type KdfFn = dyn Fn(&[u8], &[u8], u8) -> Result<Key, VaultError>;

fn err(msg: impl Into<String>) -> VaultError {
    VaultError::Backup(msg.into())
}

/// Derive the 32-byte key for algorithm id `algo`.
fn derive_key(passphrase: &[u8], salt: &[u8], algo: u8) -> Result<Key, VaultError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let log_n = match algo {
        ALGO_PBKDF2 => {
            pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ITERATIONS, key.as_mut_slice());
            return Ok(key);
        }
        ALGO_SCRYPT => 17,
        ALGO_LEGACY_SCRYPT => 14,
        other => return Err(err(format!("unknown KDF algorithm id {other} in backup"))),
    };
    let params = scrypt::Params::new(log_n, 8, 1).map_err(|e| err(format!("invalid scrypt parameters: {e}")))?;
    scrypt::scrypt(passphrase, salt, &params, key.as_mut_slice())
        .map_err(|e| err(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// The size limits and KDF in force; tests substitute small / cheap ones.
struct Engine<'a> {
    kdf: &'a KdfFn,
    max_blob: u64,
    max_restored: u64,
}

const REAL: Engine<'static> = Engine { kdf: &derive_key, max_blob: MAX_BLOB, max_restored: MAX_RESTORED };

/// A writer that refuses to grow past `limit`, so an oversized vault fails
/// with a clear message instead of exhausting memory.
struct Capped {
    buf: Vec<u8>,
    limit: u64,
}

impl Write for Capped {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let total = u64::try_from(self.buf.len().saturating_add(data.len())).unwrap_or(u64::MAX);
        if total > self.limit {
            return Err(io::Error::other("backup size limit exceeded"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn append_tree<W: Write>(builder: &mut tar::Builder<W>, fs_path: &Path, arc_path: &Path) -> Result<(), VaultError> {
    let io_err = |e: io::Error| match e.kind() {
        io::ErrorKind::PermissionDenied => VaultError::Io(format!("permission denied reading {}", fs_path.display())),
        _ => err(format!("cannot archive {}: {e}", fs_path.display())),
    };
    let meta = fs::symlink_metadata(fs_path).map_err(io_err)?;
    let kind = meta.file_type();
    if kind.is_dir() {
        builder.append_dir(arc_path, fs_path).map_err(io_err)?;
        let mut children: Vec<_> = fs::read_dir(fs_path).map_err(io_err)?.collect::<Result<_, _>>().map_err(io_err)?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            append_tree(builder, &child.path(), &arc_path.join(child.file_name()))?;
        }
        Ok(())
    } else if kind.is_file() {
        builder.append_path_with_name(fs_path, arc_path).map_err(io_err)
    } else {
        // Restore refuses links and special files, so archiving one would
        // produce a backup that can never be restored. Fail now, loudly.
        Err(err(format!(
            "backup source contains a symlink or special file ({}) — a backup must be self-contained; remove it or \
             back that file up separately",
            fs_path.display()
        )))
    }
}

fn tar_gz(src_dir: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if !fs::metadata(src_dir).is_ok_and(|m| m.is_dir()) {
        return Err(err(format!("backup source is not a directory: {}", src_dir.display())));
    }
    // Resolve the directory itself (the data dir may be reached through a
    // symlink); links *inside* it are refused by append_tree.
    let root = fs::canonicalize(src_dir).map_err(|e| err(format!("cannot open {}: {e}", src_dir.display())))?;
    let top = root.file_name().map_or_else(|| PathBuf::from("data"), PathBuf::from);
    let too_big = || {
        err(format!(
            "the vault is too large for an in-memory backup (over {limit} bytes compressed) — back it up out-of-band"
        ))
    };
    let mut builder = tar::Builder::new(GzEncoder::new(Capped { buf: Vec::new(), limit }, Compression::new(6)));
    builder.follow_symlinks(false);
    let mut written = append_tree(&mut builder, &root, &top);
    if matches!(&written, Err(VaultError::Backup(m)) if m.contains("size limit")) {
        written = Err(too_big());
    }
    let finished = builder.into_inner().and_then(GzEncoder::finish);
    written?;
    Ok(Zeroizing::new(finished.map_err(|_| too_big())?.buf)) // audit-allow: the only failure source is the Capped writer limit, which too_big() reports
}

fn check_passphrase(passphrase: &str) -> Result<(), VaultError> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err(err(format!(
            "backup passphrase too short: need at least {MIN_PASSPHRASE} characters (NIST SP 800-63B)"
        )));
    }
    Ok(())
}

fn cipher(key: &Key) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key.as_slice()).expect("32-byte key") // audit-allow: infallible, Key is [u8; 32]
}

impl Engine<'_> {
    fn make(&self, src_dir: &Path, passphrase: &str, kdf: BackupKdf) -> Result<Vec<u8>, VaultError> {
        check_passphrase(passphrase)?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut salt)?;
        random_bytes(&mut nonce)?;
        // Restore refuses a blob over the cap, so never produce one.
        let budget = self.max_blob.saturating_sub(u64::try_from(HEADER + TAG_LEN).unwrap_or(u64::MAX));
        let mut body = std::mem::take(&mut *tar_gz(src_dir, budget)?);
        let key = (self.kdf)(passphrase.as_bytes(), &salt, kdf.id())?;
        cipher(&key).encrypt_in_place(&nonce.into(), b"", &mut body).map_err(|_| err("encryption failed"))?; // audit-allow: AEAD error is opaque by design
        let mut blob = Vec::with_capacity(HEADER + body.len());
        blob.extend_from_slice(MAGIC);
        blob.push(kdf.id());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.append(&mut body);
        Ok(blob)
    }

    fn open(&self, blob: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if blob.len() < LEGACY_HEADER || blob.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(err("not a p2soc backup file (bad magic) or truncated"));
        }
        let off = MAGIC.len();
        // A legacy backup has its random salt where the ALGO byte sits, so a
        // plausible ALGO value proves nothing: try that reading, then the
        // legacy one. The GCM tag decides which was right.
        let mut readings = Vec::new();
        if let Some(&algo) = blob.get(off).filter(|a| matches!(**a, ALGO_SCRYPT | ALGO_PBKDF2))
            && blob.len() >= HEADER
        {
            readings.push((algo, off + 1));
        }
        readings.push((ALGO_LEGACY_SCRYPT, off));
        for (algo, at) in readings {
            let Some((salt, rest)) = blob.get(at..).and_then(|tail| tail.split_at_checked(SALT_LEN)) else { continue };
            let Some((nonce, ciphertext)) = rest.split_at_checked(NONCE_LEN) else { continue };
            let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(nonce) else { continue };
            let key = (self.kdf)(passphrase.as_bytes(), salt, algo)?;
            let mut plain = Zeroizing::new(ciphertext.to_vec());
            if cipher(&key).decrypt_in_place(&nonce.into(), b"", &mut *plain).is_ok() {
                return Ok(plain);
            }
        }
        Err(err("could not decrypt backup — wrong passphrase or the file is corrupt/tampered"))
    }

    fn write(&self, src_dir: &Path, out_path: &Path, passphrase: &str, kdf: BackupKdf) -> Result<(), VaultError> {
        let blob = self.make(src_dir, passphrase, kdf)?;
        write_private_atomic(out_path, &blob).map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied => {
                VaultError::Io(format!("permission denied writing {}", out_path.display()))
            }
            _ => err(format!("cannot write backup {}: {e}", out_path.display())),
        })
    }

    fn restore(&self, in_path: &Path, dest_dir: &Path, passphrase: &str) -> Result<(), VaultError> {
        // Reject an oversized blob BEFORE reading it into memory.
        let size =
            fs::metadata(in_path).map_err(|e| err(format!("cannot read backup {}: {e}", in_path.display())))?.len();
        if size > self.max_blob {
            return Err(err(format!(
                "backup file too large ({size} bytes > {} cap) — refusing to load it into memory",
                self.max_blob
            )));
        }
        let mut blob = Vec::new();
        fs::File::open(in_path)
            .and_then(|f| f.take(self.max_blob + 1).read_to_end(&mut blob))
            .map_err(|e| err(format!("cannot read backup {}: {e}", in_path.display())))?;
        if u64::try_from(blob.len()).unwrap_or(u64::MAX) > self.max_blob {
            return Err(err("backup file too large — refusing to load it into memory"));
        }
        let inner = self.open(&blob, passphrase)?;
        drop(blob);
        // Validate the whole archive before a single byte is written.
        let plan = inspect(&inner, self.max_restored)?;

        let dest = normalized(dest_dir);
        let sibling = |suffix: String| {
            let mut name = dest.file_name().map(|n| n.to_os_string()).unwrap_or_default(); // audit-allow: default is the intended fallback (destination without a file name)
            name.push(suffix);
            dest.with_file_name(name)
        };
        let staging = sibling(format!(".restore.{}.tmp", std::process::id()));
        let backout = sibling(format!(".bak.{}", std::process::id()));
        let fs_err = |what: &str, e: io::Error| match e.kind() {
            io::ErrorKind::PermissionDenied => VaultError::Io(format!("permission denied: {what}: {e}")),
            _ => err(format!("{what}: {e}")),
        };
        if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|e| fs_err("cannot create the restore parent directory", e))?;
        }
        // Stage ADJACENT to the destination: same filesystem, so the final
        // rename is atomic, and a failed extract only ever dirties the
        // throwaway directory.
        let _ = fs::remove_dir_all(&staging); // audit-allow: best-effort cleanup of scratch directory
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .map_err(|e| fs_err("cannot create the staging directory", e))?;
        let outcome = extract(&inner, &staging, &plan, self.max_restored).and_then(|()| {
            if !dest.exists() {
                return fs::rename(&staging, &dest).map_err(|e| fs_err("cannot move the restored data into place", e));
            }
            fs::rename(&dest, &backout).map_err(|e| fs_err("cannot move the existing data aside", e))?;
            if let Err(e) = fs::rename(&staging, &dest) {
                // Put the original back. If even that fails, the original is
                // still intact under the backout name — say where, and never
                // delete it.
                return Err(match fs::rename(&backout, &dest) {
                    Ok(()) => fs_err("cannot move the restored data into place (the existing data was kept)", e),
                    Err(e) => err(format!(
                        "restore failed mid-swap ({e}): the previous data is preserved at {} — move it back to {} by hand",
                        backout.display(),
                        dest.display()
                    )),
                });
            }
            let _ = fs::remove_dir_all(&backout); // audit-allow: best-effort: the backout copy is a leftover once the swap succeeded
            Ok(())
        });
        let _ = fs::remove_dir_all(&staging); // audit-allow: best-effort cleanup of scratch directory
        outcome
    }
}

/// `dest_dir` without trailing slashes (so its sibling names are well formed).
fn normalized(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let trimmed = text.trim_end_matches('/');
    PathBuf::from(if trimmed.is_empty() { text.as_ref() } else { trimmed })
}

/// What `inspect` learned about a validated archive.
struct Plan {
    /// The single top-level directory every member lives under, if there is
    /// one. It is the data dir itself and is stripped on extraction, so the
    /// backup is restored AS the destination rather than nested inside it.
    strip: Option<PathBuf>,
}

/// A member's path as safe relative components, or an error for anything
/// that could escape the destination.
fn safe_relative(path: &Path) -> Result<PathBuf, VaultError> {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            _ => return Err(err(format!("path traversal in archive member: {:?}", path.display().to_string()))),
        }
    }
    Ok(out)
}

fn open_archive(inner: &[u8]) -> tar::Archive<GzDecoder<&[u8]>> {
    tar::Archive::new(GzDecoder::new(inner))
}

fn corrupt(e: io::Error) -> VaultError {
    err(format!("the backup archive is corrupt: {e}"))
}

/// First pass: every member must be a plain file or directory with a path
/// inside the destination, and the declared total must fit the cap.
fn inspect(inner: &[u8], max_bytes: u64) -> Result<Plan, VaultError> {
    let mut archive = open_archive(inner);
    let mut total = 0u64;
    let mut tops: Vec<PathBuf> = Vec::new();
    let mut file_at_top = false;
    for entry in archive.entries().map_err(corrupt)? {
        let entry = entry.map_err(corrupt)?;
        let path = entry.path().map_err(corrupt)?.into_owned();
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(err(format!("refusing unsafe archive member: {:?}", path.display().to_string())));
        }
        let relative = safe_relative(&path)?;
        let mut parts = relative.components();
        let Some(first) = parts.next() else { continue };
        if parts.next().is_none() && kind.is_file() {
            file_at_top = true;
        }
        let first = PathBuf::from(first.as_os_str());
        if !tops.contains(&first) {
            tops.push(first);
        }
        total = total.saturating_add(entry.header().size().map_err(corrupt)?);
        if total > max_bytes {
            return Err(err(format!("decompressed backup too large (over {max_bytes} bytes) — refusing to extract")));
        }
    }
    let strip = (tops.len() == 1 && !file_at_top).then(|| tops.remove(0));
    Ok(Plan { strip })
}

/// Second pass: write the validated members under `staging`.
///
/// Modes come from the archive with setuid/setgid/sticky and group/other
/// write stripped; ownership is restored when the caller may (as `tar` does
/// for root) and silently left alone otherwise.
fn extract(inner: &[u8], staging: &Path, plan: &Plan, max_bytes: u64) -> Result<(), VaultError> {
    let io_err = |what: &Path, e: io::Error| match e.kind() {
        io::ErrorKind::PermissionDenied => VaultError::Io(format!("permission denied restoring {}", what.display())),
        _ => err(format!("cannot restore {}: {e}", what.display())),
    };
    let mut archive = open_archive(inner);
    let mut written = 0u64;
    // Directory modes are applied last, so a read-only directory in the
    // archive cannot block the files that belong inside it.
    let mut dirs: Vec<(PathBuf, u32, u64, u64)> = Vec::new();
    for entry in archive.entries().map_err(corrupt)? {
        let mut entry = entry.map_err(corrupt)?;
        let mut relative = safe_relative(&entry.path().map_err(corrupt)?)?;
        if let Some(top) = &plan.strip {
            relative = relative.strip_prefix(top).map(Path::to_path_buf).unwrap_or(relative);
        }
        let target = staging.join(&relative);
        let header = entry.header();
        let mode = header.mode().unwrap_or(0o600);
        let (uid, gid) = (header.uid().unwrap_or(u64::MAX), header.gid().unwrap_or(u64::MAX));
        if header.entry_type().is_dir() {
            fs::create_dir_all(&target).map_err(|e| io_err(&target, e))?;
            dirs.push((target, mode, uid, gid));
            continue;
        }
        if !header.entry_type().is_file() {
            return Err(err("refusing unsafe archive member"));
        }
        let mtime = header.mtime().ok();
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .map_err(|e| io_err(&target, e))?;
        // The header's size was vetted in the first pass, but count the bytes
        // actually produced: a gzip stream can lie about nothing here, yet the
        // cap is cheap to enforce where the bytes land.
        let copied =
            io::copy(&mut (&mut entry).take(max_bytes - written + 1), &mut file).map_err(|e| io_err(&target, e))?;
        written += copied;
        if written > max_bytes {
            return Err(err(format!("decompressed backup too large (over {max_bytes} bytes) — refusing to extract")));
        }
        fs::set_permissions(&target, fs::Permissions::from_mode((mode & 0o755) | 0o600))
            .map_err(|e| io_err(&target, e))?;
        if let Some(secs) = mtime {
            let _ = file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)); // audit-allow: best-effort: mtime is cosmetic
        }
        chown_best_effort(&target, uid, gid);
    }
    for (dir, mode, uid, gid) in dirs.into_iter().rev() {
        fs::set_permissions(&dir, fs::Permissions::from_mode((mode & 0o755) | 0o700)).map_err(|e| io_err(&dir, e))?;
        chown_best_effort(&dir, uid, gid);
    }
    Ok(())
}

fn chown_best_effort(path: &Path, uid: u64, gid: u64) {
    if let (Ok(uid), Ok(gid)) = (u32::try_from(uid), u32::try_from(gid)) {
        // Fails with EPERM for anyone but root, which is exactly right: an
        // unprivileged restore simply owns what it restored.
        let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid)); // audit-allow: best-effort: EPERM for non-root is expected
    }
}

/// Return an encrypted backup blob of `src_dir`.
pub fn make_backup(src_dir: &Path, passphrase: &str, kdf: BackupKdf) -> Result<Vec<u8>, VaultError> {
    REAL.make(src_dir, passphrase, kdf)
}

/// Decrypt a backup blob and return the inner gzip-tar bytes.
pub fn open_backup(blob: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    REAL.open(blob, passphrase)
}

/// Write an encrypted backup of `src_dir` to `out_path` (0600, atomic).
pub fn write_backup(src_dir: &Path, out_path: &Path, passphrase: &str, kdf: BackupKdf) -> Result<(), VaultError> {
    REAL.write(src_dir, out_path, passphrase, kdf)
}

/// Decrypt `in_path` and restore it AS `dest_dir`, atomically.
///
/// The archive is validated in full, extracted into a staging directory next
/// to `dest_dir`, and only then swapped in; the previous `dest_dir` is
/// replaced wholesale (the right semantics for a data-dir restore) and is
/// left untouched if anything fails first.
pub fn restore_backup(in_path: &Path, dest_dir: &Path, passphrase: &str) -> Result<(), VaultError> {
    REAL.restore(in_path, dest_dir, passphrase)
}

// --------------------------------------------------------------------------- //
// CLI (`vault-backup backup|restore`)
// --------------------------------------------------------------------------- //

const USAGE: &str = "usage: vault-backup {backup [out.bak] [--fips] | restore <in.bak> [dest]}\n\
The passphrase comes from $SOC_BACKUP_PASSPHRASE, standard input, or a prompt — never the command line.\n\
The data dir is $SOC_VAULT_DATA_DIR (default /var/lib/vaultwarden).\n";

/// What the backup CLI reads from its surroundings.
pub struct BackupCli<'a> {
    /// The Vaultwarden data dir (`$SOC_VAULT_DATA_DIR`).
    pub data_dir: PathBuf,
    /// Use PBKDF2 even without `--fips` (`SOC_FIPS_KDF=1`).
    pub fips: bool,
    /// Supplies the passphrase; the flag asks for a confirmation prompt.
    pub passphrase: &'a dyn Fn(bool) -> Result<Zeroizing<String>, VaultError>,
    /// Seconds since the epoch, for the default output name.
    pub now: u64,
}

/// `YYYYmmdd-HHMMSS` in UTC, for a default file name.
fn timestamp(unix: u64) -> String {
    let (days, secs) = (unix / 86_400, unix % 86_400);
    // Civil-from-days (Howard Hinnant's algorithm), valid for the whole u64 range we see.
    let z = days as i64 + 719_468; // audit-allow: lossless, days = unix / 86_400 < 2^48
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}-{:02}{:02}{:02}", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// Read a passphrase without echo from the controlling terminal. Echo is
/// switched off with `stty` (no terminal ioctls from here); if that cannot be
/// done the prompt is refused rather than showing the passphrase on screen.
fn prompt_hidden(prompt: &str) -> Result<Zeroizing<String>, VaultError> {
    use std::process::{Command, Stdio};
    let open_tty = || fs::OpenOptions::new().read(true).write(true).open("/dev/tty");
    let stty = |arg: &str| {
        open_tty()
            .and_then(|tty| {
                Command::new("stty").arg(arg).stdin(tty).stdout(Stdio::null()).stderr(Stdio::null()).status()
            })
            .is_ok_and(|s| s.success())
    };
    let mut tty = open_tty()
        .map_err(|_| err("no terminal to prompt on — set SOC_BACKUP_PASSPHRASE or pipe the passphrase on stdin"))?; // audit-allow: the fallback message supersedes the OS error and tells the operator what to do instead
    if !stty("-echo") {
        return Err(err("cannot disable terminal echo — set SOC_BACKUP_PASSPHRASE or pipe the passphrase on stdin"));
    }
    let _ = tty.write_all(prompt.as_bytes()); // audit-allow: best-effort: a prompt that cannot be shown surfaces as a read failure next
    let line = read_line(&tty);
    stty("echo");
    let _ = tty.write_all(b"\n"); // audit-allow: best-effort cosmetic newline after the hidden prompt
    line.map_err(|e| err(format!("cannot read the passphrase: {e}")))
}

/// Read one line, byte by byte, into a buffer that is wiped on drop and
/// pre-sized so a normal passphrase never leaves a copy behind in a
/// reallocated (and un-wiped) heap block. The line ending is dropped.
fn read_line(mut reader: impl Read) -> io::Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new(Vec::with_capacity(1024));
    let mut byte = [0u8; 1];
    while reader.read(&mut byte)? == 1 && byte != *b"\n" {
        raw.extend_from_slice(&byte);
    }
    let mut line = Zeroizing::new(String::with_capacity(raw.len()));
    line.push_str(&String::from_utf8_lossy(&raw));
    Ok(strip_newline(line))
}

fn strip_newline(mut line: Zeroizing<String>) -> Zeroizing<String> {
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    line
}

/// The passphrase from `$SOC_BACKUP_PASSPHRASE`, else the first line of a
/// piped stdin, else a hidden prompt (asked twice when `confirm`).
pub fn passphrase_from_env_or_prompt(confirm: bool) -> Result<Zeroizing<String>, VaultError> {
    if let Some(value) = soc_core::env::env_str("SOC_BACKUP_PASSPHRASE") {
        return Ok(Zeroizing::new(value));
    }
    if !io::stdin().is_terminal() {
        return read_line(io::stdin().lock()).map_err(|e| err(format!("cannot read the passphrase: {e}")));
    }
    let first = prompt_hidden("Backup passphrase: ")?;
    if confirm && *prompt_hidden("Confirm passphrase: ")? != *first {
        return Err(err("passphrases did not match"));
    }
    Ok(first)
}

/// Turn a permission failure into an actionable line: the Vaultwarden data
/// dir is root-owned, so a desktop operator running this directly hits EACCES.
fn permission_remedy(op: &str, detail: &str) -> String {
    format!(
        "error: {op} failed: {detail}\n  The Vaultwarden data dir is owned by root, so this must run with\n  \
         privilege. Re-run with sudo, preserving the passphrase via STDIN/env\n  (never on argv), e.g.:\n    \
         SOC_BACKUP_PASSPHRASE=… sudo -E soc-wall vault-backup {op} …\n  or pick a destination/source your user can \
         read+write."
    )
}

/// The backup CLI with its surroundings injected. `args` are the words after
/// the subcommand name: `backup [out.bak] [--fips]` or `restore <in.bak> [dest]`.
pub fn backup_cli_with(args: &[String], cli: &BackupCli<'_>, out: &mut dyn Write, errw: &mut dyn Write) -> i32 {
    let usage = |errw: &mut dyn Write| {
        let _ = errw.write_all(USAGE.as_bytes()); // audit-allow: best-effort: diagnostics writer failure (closed pipe) is unreportable
        2
    };
    let Some((op, rest)) = args.split_first() else { return usage(errw) };
    let result = match op.as_str() {
        "backup" => {
            let mut target = None;
            let mut fips = cli.fips;
            for arg in rest {
                match arg.as_str() {
                    "--fips" => fips = true,
                    flag if flag.starts_with('-') => return usage(errw),
                    path => target = Some(PathBuf::from(path)),
                }
            }
            let target = target.unwrap_or_else(|| PathBuf::from(format!("vaultwarden-{}.bak", timestamp(cli.now))));
            let kdf = if fips { BackupKdf::Pbkdf2 } else { BackupKdf::Scrypt };
            (cli.passphrase)(true)
                .and_then(|pass| write_backup(&cli.data_dir, &target, &pass, kdf))
                .map(|()| format!("wrote encrypted backup -> {}", target.display()))
        }
        "restore" => {
            let Some(source) = rest.first().filter(|a| !a.starts_with('-')) else { return usage(errw) };
            let dest = rest.get(1).map_or_else(|| cli.data_dir.clone(), PathBuf::from);
            (cli.passphrase)(false)
                .and_then(|pass| restore_backup(Path::new(source), &dest, &pass))
                .map(|()| format!("restored {source} -> {}", dest.display()))
        }
        _ => return usage(errw),
    };
    match result {
        Ok(line) => {
            let _ = writeln!(out, "{line}"); // audit-allow: best-effort: output writer failure (closed pipe) is unreportable
            0
        }
        Err(VaultError::Io(detail)) if detail.contains("permission denied") => {
            let _ = writeln!(errw, "{}", permission_remedy(op, &detail)); // audit-allow: best-effort: diagnostics writer failure (closed pipe) is unreportable
            1
        }
        Err(e) => {
            let _ = writeln!(errw, "error: {e}"); // audit-allow: best-effort: diagnostics writer failure (closed pipe) is unreportable
            1
        }
    }
}

/// The backup CLI against the real environment, stdout and stderr.
pub fn backup_cli_main(args: &[String]) -> i32 {
    let cli = BackupCli {
        data_dir: soc_core::env::env_str("SOC_VAULT_DATA_DIR")
            .map_or_else(|| PathBuf::from("/var/lib/vaultwarden"), PathBuf::from),
        fips: std::env::var("SOC_FIPS_KDF").is_ok_and(|v| v == "1"),
        passphrase: &passphrase_from_env_or_prompt,
        now: crate::totp::unix_now(),
    };
    backup_cli_with(args, &cli, &mut io::stdout(), &mut io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use base64::Engine as _;
    use sha2::Digest;
    use std::sync::Mutex;

    const PASS: &str = "correct horse battery";

    /// Real scrypt needs 128 MiB per derivation; run those tests one at a time.
    static HEAVY_KDF: Mutex<()> = Mutex::new(());

    /// A stand-in KDF for the container-logic tests: instant, still keyed on
    /// passphrase, salt and algorithm.
    fn cheap_kdf(passphrase: &[u8], salt: &[u8], algo: u8) -> Result<Key, VaultError> {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&Sha256::new().chain_update(passphrase).chain_update(salt).chain_update([algo]).finalize());
        Ok(key)
    }

    const FAST: Engine<'static> = Engine { kdf: &cheap_kdf, max_blob: MAX_BLOB, max_restored: MAX_RESTORED };

    fn make_vault(dir: &TestDir) -> PathBuf {
        let d = dir.path().join("vaultwarden");
        fs::create_dir_all(d.join("attachments")).unwrap();
        fs::write(d.join("db.sqlite3"), b"SQLite format 3\x00secret-vault-bytes").unwrap();
        fs::write(d.join("rsa_key.pem"), "-----BEGIN KEY-----\nxxxx\n").unwrap();
        fs::write(d.join("attachments/a.bin"), [1u8, 2, 3]).unwrap();
        fs::set_permissions(d.join("db.sqlite3"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn siblings(dir: &TestDir) -> Vec<String> {
        let mut names: Vec<String> =
            fs::read_dir(dir.path()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    /// A gzip-tar built by hand, for hostile-archive tests.
    fn archive(build: impl FnOnce(&mut tar::Builder<GzEncoder<Vec<u8>>>)) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        build(&mut builder);
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn file_header(size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header
    }

    /// Wrap an arbitrary inner archive in a valid encrypted container.
    fn seal(inner: &[u8]) -> Vec<u8> {
        let (salt, nonce) = ([9u8; SALT_LEN], [8u8; NONCE_LEN]);
        let key = cheap_kdf(PASS.as_bytes(), &salt, ALGO_SCRYPT).unwrap();
        let mut body = inner.to_vec();
        cipher(&key).encrypt_in_place(&nonce.into(), b"", &mut body).unwrap();
        [&MAGIC[..], &[ALGO_SCRYPT], &salt, &nonce, &body].concat()
    }

    // --- container ---------------------------------------------------------- //

    #[test]
    fn roundtrip_restores_the_data_dir_as_the_destination() {
        let dir = TestDir::new("backup-roundtrip");
        let src = make_vault(&dir);
        let out = dir.path().join("vault.bak");
        FAST.write(&src, &out, PASS, BackupKdf::Scrypt).unwrap();
        assert_eq!(mode(&out), 0o600);
        let blob = fs::read(&out).unwrap();
        assert!(!blob.windows(18).any(|w| w == b"secret-vault-bytes"), "the backup must be encrypted");
        assert_eq!(&blob[..5], b"PSBK\x01");

        let dest = dir.path().join("restored");
        FAST.restore(&out, &dest, PASS).unwrap();
        // The data dir's own contents land directly in the destination —
        // restoring over /var/lib/vaultwarden must yield a working data dir.
        assert_eq!(fs::read(dest.join("db.sqlite3")).unwrap(), b"SQLite format 3\x00secret-vault-bytes");
        assert_eq!(fs::read(dest.join("attachments/a.bin")).unwrap(), [1, 2, 3]);
        assert!(!dest.join("vaultwarden").exists());
        // Modes survive, so a 0700 data dir does not come back world-readable.
        assert_eq!(mode(&dest), 0o700);
        assert_eq!(mode(&dest.join("db.sqlite3")), 0o640);
        assert_eq!(siblings(&dir), ["restored", "vault.bak", "vaultwarden"]);
    }

    #[test]
    fn restore_replaces_an_existing_destination_wholesale() {
        let dir = TestDir::new("backup-replace");
        let src = make_vault(&dir);
        let out = dir.path().join("vault.bak");
        FAST.write(&src, &out, PASS, BackupKdf::Scrypt).unwrap();
        let dest = dir.path().join("live");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("STALE"), "old").unwrap();
        // A trailing slash on the destination is tolerated.
        FAST.restore(&out, Path::new(&format!("{}/", dest.display())), PASS).unwrap();
        assert!(!dest.join("STALE").exists());
        assert!(dest.join("db.sqlite3").exists());
        assert_eq!(siblings(&dir), ["live", "vault.bak", "vaultwarden"]);
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_detected() {
        let dir = TestDir::new("backup-tamper");
        let src = make_vault(&dir);
        let blob = FAST.make(&src, "right-passphrase", BackupKdf::Scrypt).unwrap();
        assert!(FAST.open(&blob, "right-passphrase").is_ok());
        assert!(
            matches!(FAST.open(&blob, "wrong-passphrase"), Err(VaultError::Backup(m)) if m.contains("wrong passphrase"))
        );
        for index in [HEADER, blob.len() / 2, blob.len() - 1, MAGIC.len() + 3, MAGIC.len() + 1 + SALT_LEN] {
            let mut bad = blob.clone();
            bad[index] ^= 0xff;
            assert!(FAST.open(&bad, "right-passphrase").is_err(), "flip at {index} went unnoticed");
        }
        assert!(FAST.open(&blob[..blob.len() - 1], "right-passphrase").is_err());
    }

    #[test]
    fn short_passphrases_and_bad_containers_are_rejected() {
        let dir = TestDir::new("backup-reject");
        let src = make_vault(&dir);
        assert!(
            matches!(FAST.make(&src, "short", BackupKdf::Scrypt), Err(VaultError::Backup(m)) if m.contains("too short"))
        );
        assert!(FAST.make(&src, "", BackupKdf::Scrypt).is_err());
        assert!(FAST.make(&src, "ñandúñan", BackupKdf::Scrypt).is_ok(), "length counts characters, not bytes");
        let mut junk = b"NOTPS".to_vec();
        junk.extend_from_slice(&[0; 40]);
        assert!(matches!(FAST.open(&junk, PASS), Err(VaultError::Backup(m)) if m.contains("bad magic")));
        assert!(FAST.open(b"PSBK", PASS).is_err());
        assert!(FAST.open(b"", PASS).is_err());
        assert!(
            matches!(FAST.make(&src.join("db.sqlite3"), PASS, BackupKdf::Scrypt), Err(VaultError::Backup(m)) if m.contains("not a directory"))
        );
        assert!(FAST.make(&dir.path().join("absent"), PASS, BackupKdf::Scrypt).is_err());
    }

    #[test]
    fn the_kdf_choice_is_recorded_in_the_blob() {
        let dir = TestDir::new("backup-algo");
        let src = make_vault(&dir);
        let fips = FAST.make(&src, PASS, BackupKdf::Pbkdf2).unwrap();
        assert_eq!(fips[MAGIC.len()], ALGO_PBKDF2);
        // Self-describing: opens with no hint about which KDF made it.
        let inner = FAST.open(&fips, PASS).unwrap();
        let mut names = Vec::new();
        for entry in open_archive(&inner).entries().unwrap() {
            names.push(entry.unwrap().path().unwrap().display().to_string());
        }
        assert!(names.iter().any(|n| n.ends_with("db.sqlite3")), "{names:?}");
        assert!(names.iter().all(|n| n.starts_with("vaultwarden")), "{names:?}");
    }

    #[test]
    fn a_legacy_blob_whose_salt_looks_like_an_algo_byte_still_opens() {
        let inner = archive(|b| b.append_data(&mut file_header(2), "data/f", &b"hi"[..]).unwrap());
        for first_salt_byte in [ALGO_SCRYPT, ALGO_PBKDF2, 0x7f] {
            let mut salt = [5u8; SALT_LEN];
            salt[0] = first_salt_byte;
            let nonce = [6u8; NONCE_LEN];
            let key = cheap_kdf(PASS.as_bytes(), &salt, ALGO_LEGACY_SCRYPT).unwrap();
            let mut body = inner.clone();
            cipher(&key).encrypt_in_place(&nonce.into(), b"", &mut body).unwrap();
            let blob = [&MAGIC[..], &salt, &nonce, &body].concat();
            assert_eq!(FAST.open(&blob, PASS).unwrap().as_slice(), inner.as_slice());
        }
    }

    // --- size caps ---------------------------------------------------------- //

    #[test]
    fn oversized_inputs_are_refused_in_both_directions() {
        let dir = TestDir::new("backup-caps");
        let src = make_vault(&dir);
        let out = dir.path().join("vault.bak");
        FAST.write(&src, &out, PASS, BackupKdf::Scrypt).unwrap();
        let dest = dir.path().join("restored");

        let tiny_blob = Engine { max_blob: 1, ..FAST };
        assert!(matches!(tiny_blob.restore(&out, &dest, PASS), Err(VaultError::Backup(m)) if m.contains("too large")));
        // The decompressed cap is enforced after decrypt, before anything is written.
        let tiny_inner = Engine { max_restored: 1, ..FAST };
        assert!(matches!(tiny_inner.restore(&out, &dest, PASS), Err(VaultError::Backup(m)) if m.contains("too large")));
        assert!(!dest.exists());
        assert_eq!(siblings(&dir), ["vault.bak", "vaultwarden"]);

        // A backup that could never be restored is never written.
        let small = Engine { max_blob: 64, ..FAST };
        let refused = small.write(&src, &dir.path().join("big.bak"), PASS, BackupKdf::Scrypt);
        assert!(matches!(refused, Err(VaultError::Backup(m)) if m.contains("too large")));
        assert!(!dir.path().join("big.bak").exists());
    }

    #[test]
    fn a_compression_bomb_cannot_fill_the_disk() {
        let dir = TestDir::new("backup-bomb");
        // 4 MiB of zeros compresses to a few KiB.
        let zeros = vec![0u8; 4 * 1024 * 1024];
        let inner =
            archive(|b| b.append_data(&mut file_header(zeros.len() as u64), "data/zeros", zeros.as_slice()).unwrap());
        assert!(inner.len() < 64 * 1024);
        let blob_path = dir.path().join("bomb.bak");
        fs::write(&blob_path, seal(&inner)).unwrap();
        let capped = Engine { max_restored: 1024 * 1024, ..FAST };
        let dest = dir.path().join("restored");
        assert!(
            matches!(capped.restore(&blob_path, &dest, PASS), Err(VaultError::Backup(m)) if m.contains("too large"))
        );
        assert_eq!(siblings(&dir), ["bomb.bak"]);
    }

    // --- hostile archives --------------------------------------------------- //

    fn restore_inner(dir: &TestDir, inner: &[u8]) -> Result<(), VaultError> {
        let blob_path = dir.path().join("evil.bak");
        fs::write(&blob_path, seal(inner)).unwrap();
        FAST.restore(&blob_path, &dir.path().join("out"), PASS)
    }

    #[test]
    fn path_traversal_members_are_refused() {
        // The tar crate refuses to *write* `..` paths, so forge the header bytes.
        let traversal = archive(|b| {
            let mut header = file_header(5);
            let name = b"../escape.txt";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            b.append(&header, &b"pwned"[..]).unwrap();
        });
        let absolute = archive(|b| {
            let mut header = file_header(5);
            let name = b"/tmp/soc-vault-absolute-escape";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            b.append(&header, &b"pwned"[..]).unwrap();
        });
        for (label, inner) in [("dot-dot", traversal), ("absolute", absolute)] {
            let dir = TestDir::new("backup-traversal");
            let outcome = restore_inner(&dir, &inner);
            assert!(
                matches!(&outcome, Err(VaultError::Backup(m)) if m.contains("path traversal")),
                "{label}: {outcome:?}"
            );
            assert_eq!(siblings(&dir), ["evil.bak"], "{label}");
            assert!(!dir.path().parent().unwrap().join("escape.txt").exists());
        }
        assert!(!Path::new("/tmp/soc-vault-absolute-escape").exists());
    }

    #[test]
    fn links_and_special_files_are_refused_before_anything_is_written() {
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
        ] {
            let dir = TestDir::new("backup-links");
            let inner = archive(|b| {
                b.append_data(&mut file_header(2), "data/ok", &b"ok"[..]).unwrap();
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(kind);
                header.set_size(0);
                header.set_path("data/link").unwrap();
                header.set_link_name("/etc/passwd").unwrap();
                header.set_cksum();
                b.append(&header, io::empty()).unwrap();
            });
            let outcome = restore_inner(&dir, &inner);
            assert!(
                matches!(&outcome, Err(VaultError::Backup(m)) if m.contains("unsafe archive member")),
                "{kind:?}: {outcome:?}"
            );
            assert_eq!(siblings(&dir), ["evil.bak"], "{kind:?}: the good member must not have been extracted");
        }
    }

    #[test]
    fn setuid_and_world_writable_bits_are_stripped() {
        let dir = TestDir::new("backup-modes");
        let inner = archive(|b| {
            let mut header = file_header(2);
            header.set_mode(0o6777);
            b.append_data(&mut header, "data/suid", &b"hi"[..]).unwrap();
        });
        restore_inner(&dir, &inner).unwrap();
        assert_eq!(mode(&dir.path().join("out/suid")), 0o755);
    }

    #[test]
    fn a_multi_rooted_archive_is_extracted_as_is() {
        let dir = TestDir::new("backup-multiroot");
        let inner = archive(|b| {
            b.append_data(&mut file_header(1), "a/one", &b"1"[..]).unwrap();
            b.append_data(&mut file_header(1), "b/two", &b"2"[..]).unwrap();
        });
        restore_inner(&dir, &inner).unwrap();
        assert_eq!(fs::read(dir.path().join("out/a/one")).unwrap(), b"1");
        assert_eq!(fs::read(dir.path().join("out/b/two")).unwrap(), b"2");
        // A lone top-level *file* is not a directory to strip.
        let dir = TestDir::new("backup-lonefile");
        let inner = archive(|b| b.append_data(&mut file_header(1), "single", &b"1"[..]).unwrap());
        restore_inner(&dir, &inner).unwrap();
        assert_eq!(fs::read(dir.path().join("out/single")).unwrap(), b"1");
    }

    #[test]
    fn a_failed_restore_leaves_the_existing_destination_untouched() {
        let dir = TestDir::new("backup-rollback");
        let dest = dir.path().join("out");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("PRE_EXISTING"), "keep me").unwrap();
        // Valid container, garbage archive: the failure happens at extraction time.
        let corrupt_inner = b"this is not a gzip stream".to_vec();
        assert!(matches!(restore_inner(&dir, &corrupt_inner), Err(VaultError::Backup(m)) if m.contains("corrupt")));
        // Same for a member that is refused, and for a wrong passphrase.
        let evil = archive(|b| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_path("data/link").unwrap();
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            b.append(&header, io::empty()).unwrap();
        });
        assert!(restore_inner(&dir, &evil).is_err());
        assert!(FAST.restore(&dir.path().join("evil.bak"), &dest, "not the passphrase").is_err());
        assert_eq!(fs::read_to_string(dest.join("PRE_EXISTING")).unwrap(), "keep me");
        assert_eq!(siblings(&dir), ["evil.bak", "out"], "no staging or backout directory may be left behind");
    }

    #[test]
    fn a_source_with_a_symlink_fails_at_backup_time_not_at_restore_time() {
        let dir = TestDir::new("backup-symlink-src");
        let src = make_vault(&dir);
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
        let outcome = FAST.make(&src, PASS, BackupKdf::Scrypt);
        assert!(matches!(&outcome, Err(VaultError::Backup(m)) if m.contains("symlink")), "{outcome:?}");
        // The data dir itself may be reached through a symlink.
        fs::remove_file(src.join("link")).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&src, &alias).unwrap();
        let blob = FAST.make(&alias, PASS, BackupKdf::Scrypt).unwrap();
        assert!(FAST.open(&blob, PASS).is_ok());
    }

    #[test]
    fn a_missing_backup_file_is_reported() {
        let dir = TestDir::new("backup-missing");
        let outcome = FAST.restore(&dir.path().join("absent.bak"), &dir.path().join("out"), PASS);
        assert!(matches!(outcome, Err(VaultError::Backup(m)) if m.contains("cannot read backup")));
    }

    // --- compatibility with the Python implementation -------------------------- //

    // Blobs written by the Python host.backup.make_backup for a directory
    //   vaultwarden/{db.sqlite3 (0640), attachments/a.bin}
    // under the passphrase "correct horse battery".
    const PY_SCRYPT: &str = "UFNCSwFdhud85aa4gtCdyiB72bnEUciEIjpfpfet5iUwuUKScy7VVJACseDHzK9QH9ev/iB/cyX8cqqG37eQO/Hfl3D5K5CpGm0s/ln+Q9Nai9V2RT8UGKHRAp30SiK3TcV9mD6lws81HrkybGBRr91EgJ6csQKfKxs+V/p8ZbHjcLxIc8izQrRDXHCp0PFGeTrVw0jXRgUVjwc+gNUMqxI2fAhU/DGLac/7pVzaEgNjN50fMB1l6XzvpM00ilUpUCtJL0dOXosBBTyCG+UAjPQzbrd5xVvpP/ja2XHJ/OAPJUA+MKKsEM3zaxe4pZk/KljNIjRSQwvQPwO14/+RUVhIwW+YTtyTbtKyYx4X3YWE3PePFzcGJm5oSLTBN5EQleWBgoTZC9j+rhRzzCBDeELapywYPfRiMscyL0nyDyuwTpbsiF9/TiXTMipA6id9w2VmyfrFVBmCKJFH7oaWaE4Q5G/ksk/ZbM32ValTCpzyVETZrXmZjzh5em7kxCbKrkMudjA=";
    const PY_FIPS: &str = "UFNCSwK3FdvVXkEZczEl+rK8ZU36EKhzggx90DbRWtR2Ba2lj5YwcuOsG5aY0ImNEelCYTV8eoExMeQ0RuDm8Kt4ieAENlveDlcBrvNrHnt0eUHXNP8lRPGoRUwtcm8D1RgNNo5cnv8/aGgzoSfsE2MnslVU77IxILV5tkriqRredPz0SJTCRPAjSZCBe1POoy426xUsR75ZXpHiaHjmcFcsAnzuS6tToiEO2nfQhfIuvCeK2nzHL+KrejqCWGk2p/aNTm4dF6XMkZLD/F7U83mwFygRapNvygR8C+BTeqgMwD7UalciGKx5kLNnPyHFKjtgbiiO6mWEbUq5AyIeOJP1XbhjDanRTFXS8RUhmD4GCBnUYbNVKd4UIlV97w4k1pFZ02WzeppQ4FcFQa660Z3JTrC0JDKjFumdP2SEZhCW/B3kZOY93W0BjI4xFGFldEL/VzqZAeb6j9N8Qvbm98aJBrz2tzEkkzgMmkfvb4R9/iQdjuFdyE/TIW8r0gpmK74Le6c=";
    // The pre-ALGO-byte layout (MAGIC | salt 00..0f | nonce 00..0b | ct), scrypt N=2^14.
    const PY_LEGACY: &str = "UFNCSwABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgtfLiWcs7DLiKPTMiUi1d4KzaB1ljUMgUaOknbA8gU6BRvu669beAhULtEYNkNhnC0OD21BHkDF8re5dRy6AwXN+OqwXOBi5JrEb+OQb2OJ6oyCcd/f/ivS3Wz31OXWFF1rooTE0RYB8uQD88B3S02W3Zp+PSuJrodaCAy4aERtldjUl3umaDFLgF5YjQzGR5y6+NnFauCuLJkQJ0LxZwvEKJtQgx1sIjS8DPAM2pUYRLhTaGC+d5cwtWXtPMuOcTq0ducx4uCfaFBN/GDLKl9leKUJHLSBEwsm+U+hRbywL16p8p4gGAhUhwMaOFQ6GCVBRXT05O+qCf2TSYjr7oOpHuy59P+GhuPLq8jxMcXuwlX/AoVFdoeQQzkG4v1iLRQY2pKZynJK6CHhSI73Ipj3BILKHo2GdFSgALMMHigqpXkXVrpFseJy1L5yu7Gp45D9qkJ2roT9+OLXRmTBN5SELBOLpA==";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn key_derivation_matches_python_for_every_algorithm() {
        let _serial = HEAVY_KDF.lock().unwrap_or_else(|p| p.into_inner());
        let salt: Vec<u8> = (0u8..16).collect();
        // secretstore._kdf(b"correct horse battery", bytes(range(16)), algo)
        let expect = [
            (ALGO_LEGACY_SCRYPT, "e96ec6ba8c63a23698220f37c7fc042925d430c7feadec9ceb04af03cabb9f2f"),
            (ALGO_PBKDF2, "bb06c8c0b1dd5bfd4e40f4e297a2d0e64da7ef94b4b8ec20989021c8b41536ad"),
            (ALGO_SCRYPT, "af5ecdbec02ddf047a3df2b4942e217b0b69c80fd3276e1923abbe0d1c80ea89"),
        ];
        for (algo, want) in expect {
            assert_eq!(hex(derive_key(PASS.as_bytes(), &salt, algo).unwrap().as_slice()), want, "algo {algo}");
        }
        assert!(derive_key(PASS.as_bytes(), &salt, 9).is_err());
    }

    #[test]
    fn python_made_backups_restore_including_the_legacy_layout() {
        let _serial = HEAVY_KDF.lock().unwrap_or_else(|p| p.into_inner());
        for (label, fixture) in [("scrypt", PY_SCRYPT), ("fips", PY_FIPS), ("legacy", PY_LEGACY)] {
            let dir = TestDir::new("backup-python");
            let blob = base64::engine::general_purpose::STANDARD.decode(fixture).unwrap();
            let path = dir.path().join("python.bak");
            fs::write(&path, &blob).unwrap();
            let dest = dir.path().join("restored");
            restore_backup(&path, &dest, PASS).unwrap_or_else(|e| panic!("{label}: {e}"));
            // Python's tarfile writes PAX headers (float mtimes); they must parse.
            assert_eq!(fs::read(dest.join("db.sqlite3")).unwrap(), b"SQLite format 3\x00secret-vault-bytes", "{label}");
            assert_eq!(fs::read(dest.join("attachments/a.bin")).unwrap(), [1, 2, 3], "{label}");
            assert_eq!(mode(&dest.join("db.sqlite3")), 0o640, "{label}");
            if label == "legacy" {
                assert!(matches!(open_backup(&blob, "wrong passphrase!"), Err(VaultError::Backup(_))));
            }
        }
    }

    #[test]
    fn real_kdf_roundtrip_in_fips_mode() {
        let dir = TestDir::new("backup-real");
        let src = make_vault(&dir);
        let out = dir.path().join("vault.bak");
        write_backup(&src, &out, "fips-passphrase!", BackupKdf::Pbkdf2).unwrap();
        let dest = dir.path().join("restored");
        restore_backup(&out, &dest, "fips-passphrase!").unwrap();
        assert_eq!(fs::read(dest.join("rsa_key.pem")).unwrap(), b"-----BEGIN KEY-----\nxxxx\n");
    }

    // --- CLI ------------------------------------------------------------------ //

    fn run_cli(dir: &TestDir, args: &[&str], pass: &'static str) -> (i32, String, String) {
        let passphrase = move |_confirm: bool| Ok(Zeroizing::new(pass.to_string()));
        let cli = BackupCli {
            data_dir: dir.path().join("vaultwarden"),
            fips: true,
            passphrase: &passphrase,
            now: 1_794_507_607,
        };
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let (mut out, mut errw) = (Vec::new(), Vec::new());
        let code = backup_cli_with(&args, &cli, &mut out, &mut errw);
        (code, String::from_utf8(out).unwrap(), String::from_utf8(errw).unwrap())
    }

    #[test]
    fn cli_backs_up_and_restores() {
        let dir = TestDir::new("backup-cli");
        make_vault(&dir);
        let bak = dir.path().join("out.bak");
        let bak_arg = bak.to_str().unwrap();
        let (code, out, errw) = run_cli(&dir, &["backup", bak_arg], "fips-passphrase!");
        assert_eq!((code, errw.as_str()), (0, ""));
        assert_eq!(out, format!("wrote encrypted backup -> {bak_arg}\n"));
        assert_eq!(fs::read(&bak).unwrap()[MAGIC.len()], ALGO_PBKDF2, "SOC_FIPS_KDF=1 selects PBKDF2 without --fips");

        let dest = dir.path().join("restored");
        let (code, out, _) = run_cli(&dir, &["restore", bak_arg, dest.to_str().unwrap()], "fips-passphrase!");
        assert_eq!(code, 0);
        assert!(out.starts_with("restored ") && dest.join("db.sqlite3").exists());

        // The destination defaults to the data dir itself.
        fs::write(dir.path().join("vaultwarden/STRAY"), "x").unwrap();
        let (code, _, _) = run_cli(&dir, &["restore", bak_arg], "fips-passphrase!");
        assert_eq!(code, 0);
        assert!(!dir.path().join("vaultwarden/STRAY").exists());
        assert!(dir.path().join("vaultwarden/db.sqlite3").exists());
    }

    #[test]
    fn cli_errors_and_usage() {
        let dir = TestDir::new("backup-cli-errors");
        make_vault(&dir);
        let bak = dir.path().join("out.bak");
        let (code, out, errw) = run_cli(&dir, &["backup", bak.to_str().unwrap()], "short");
        assert_eq!((code, out.as_str()), (1, ""));
        assert!(errw.starts_with("error: backup passphrase too short"));
        for bad in [&[][..], &["frobnicate"], &["restore"], &["backup", "--bogus"], &["restore", "--x"]] {
            let (code, out, errw) = run_cli(&dir, bad, "whatever-pass");
            assert_eq!((code, out.as_str()), (2, ""), "{bad:?}");
            assert!(errw.starts_with("usage:"));
        }
        let (code, _, errw) = run_cli(&dir, &["restore", "/nonexistent/x.bak", "/tmp/unused-dest"], "whatever-pass");
        assert_eq!(code, 1);
        assert!(errw.contains("cannot read backup"));
        assert!(permission_remedy("backup", "permission denied reading /var/lib/vaultwarden").contains("sudo -E"));
    }

    #[test]
    fn default_output_name_is_timestamped() {
        assert_eq!(timestamp(0), "19700101-000000");
        assert_eq!(timestamp(951_782_400), "20000229-000000");
        assert_eq!(timestamp(1_794_507_607), "20261112-182007");
        assert_eq!(timestamp(4_102_444_799), "20991231-235959");
    }
}
