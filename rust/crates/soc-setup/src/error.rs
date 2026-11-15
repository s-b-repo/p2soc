//! The crate's typed error. Messages never contain a master password or PIN.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why a setup operation failed.
#[derive(Debug)]
pub enum SetupError {
    /// A file operation failed.
    Io { what: String, path: PathBuf, source: io::Error },
    /// Input that cannot be used (bad flag, malformed value).
    Invalid(String),
    /// A seal / secret-store step failed; carries the operator-facing text.
    Seal(SealMasterError),
    /// A vault operation failed.
    Vault(String),
}

impl SetupError {
    pub fn io(what: impl Into<String>, path: impl Into<PathBuf>, source: io::Error) -> SetupError {
        SetupError::Io { what: what.into(), path: path.into(), source }
    }
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetupError::Io { what, path, source } => write!(f, "{what} {}: {source}", path.display()),
            SetupError::Invalid(why) => f.write_str(why),
            SetupError::Seal(e) => e.fmt(f),
            SetupError::Vault(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for SetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SetupError::Io { source, .. } => Some(source),
            SetupError::Seal(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SealMasterError> for SetupError {
    fn from(e: SealMasterError) -> SetupError {
        SetupError::Seal(e)
    }
}

/// A seal / store step failed (bad input, locked wallet, ...). The message is
/// what both the CLI and the GUI show the operator (`SealMasterError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealMasterError(pub String);

impl fmt::Display for SealMasterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SealMasterError {}

pub type Result<T> = std::result::Result<T, SetupError>;

/// A fallible step whose error is the human-facing reason, shown verbatim to the operator.
pub type TextResult<T> = std::result::Result<T, String>; // audit-allow: String is the human-facing reason/display text
