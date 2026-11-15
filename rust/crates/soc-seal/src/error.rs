//! The crate's typed errors. No variant ever carries secret material: only
//! paths, OS errors and fixed text, so every error is safe to log.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why sealing or unsealing failed.
#[derive(Debug)]
pub enum SealError {
    /// The caller's input was refused (empty master, PIN below the floor).
    Invalid(&'static str),
    /// A sealed file is absent: nothing has been sealed here.
    NotSealed(PathBuf),
    /// A sealed file exists but could not be read or written.
    Io { path: PathBuf, source: io::Error },
    /// `host.key` is absent, so no v2 seal can be derived.
    HostKeyMissing,
    /// `host.key` is shorter than a key.
    HostKeyCorrupt,
    /// No machine-id could be found on this host.
    NoMachineId,
    /// A blob is too short or not in a known format.
    Format,
    /// Authentication failed: wrong host, wrong `host.key`, or corrupt files.
    WrongHostOrCorrupt,
    /// The KDF could not run (memory pressure on a 1 GB Pi, not a wrong key).
    Kdf(&'static str),
    /// Another process held the seal lock for the whole wait.
    Busy,
    /// A freshly written seal did not read back; nothing was committed.
    Verify,
    /// The OS random source failed.
    Random,
    /// The unsealed bytes are not text.
    NotText,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Invalid(why) => f.write_str(why),
            SealError::NotSealed(path) => {
                write!(f, "sealed secret not found: {} (run first-run setup)", path.display())
            }
            SealError::Io { path, source } => write!(f, "cannot access sealed secret {}: {source}", path.display()),
            SealError::HostKeyMissing => f.write_str(
                "host.key missing — the seal is bound to a per-host key that is not present \
                 (copied without it, or never sealed); re-run first-run setup to re-seal",
            ),
            SealError::HostKeyCorrupt => {
                f.write_str("host.key is truncated/corrupt — re-run first-run setup to re-seal")
            }
            SealError::NoMachineId => f.write_str(
                "no machine-id (/etc/machine-id missing or empty) — set SOC_MACHINE_ID, or run \
                 `systemd-machine-id-setup`",
            ),
            SealError::Format => {
                f.write_str("sealed blob is too short / not in the expected format — re-run first-run setup to re-seal")
            }
            SealError::WrongHostOrCorrupt => f.write_str(
                "could not unseal — wrong machine (the secret is bound to the host it was sealed on) \
                 or the files are corrupt; re-run first-run setup to re-seal",
            ),
            SealError::Kdf(why) => write!(f, "key derivation failed ({why}) — out of memory?"),
            SealError::Busy => f.write_str("another process is holding the seal lock — try again"),
            SealError::Verify => f.write_str("the new seal did not read back correctly; the previous seal was kept"),
            SealError::Random => f.write_str("the OS random source is unavailable"),
            SealError::NotText => f.write_str("the unsealed secret is not valid UTF-8 text — the seal is corrupt"),
        }
    }
}

impl std::error::Error for SealError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SealError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, SealError>;
