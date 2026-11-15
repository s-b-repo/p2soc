//! The crate's error type.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why a state operation failed. Messages never contain a PIN, a TOTP secret
/// or a code.
#[derive(Debug)]
pub enum StateError {
    /// The filesystem refused.
    Io { path: PathBuf, source: io::Error },
    /// The path is a symlink, a FIFO, a directory — anything but a plain file.
    /// State files are never read through one.
    NotRegular { path: PathBuf },
    /// The file is larger than anything this crate writes.
    TooLarge { path: PathBuf, limit: u64 },
    /// The file exists but does not hold what it should.
    Corrupt { path: PathBuf, reason: String },
    /// The OS random source is unavailable.
    Random,
    /// A new PIN was refused (the reason is safe to show).
    InvalidPin(&'static str),
    /// A TOTP secret was refused.
    InvalidSecret(&'static str),
    /// A value handed in by the caller was refused.
    InvalidInput(String),
    /// The result would not pass config validation; every finding is listed.
    Invalid(Vec<String>),
}

impl StateError {
    pub(crate) fn io(path: &std::path::Path, source: io::Error) -> StateError {
        StateError::Io { path: path.to_path_buf(), source }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            StateError::NotRegular { path } => write!(f, "{}: not a regular file", path.display()),
            StateError::TooLarge { path, limit } => {
                write!(f, "{}: larger than the {limit}-byte limit", path.display())
            }
            StateError::Corrupt { path, reason } => write!(f, "{}: {reason}", path.display()),
            StateError::Random => f.write_str("the OS random source is unavailable"),
            StateError::InvalidPin(why) => write!(f, "PIN rejected: {why}"),
            StateError::InvalidSecret(why) => write!(f, "TOTP secret rejected: {why}"),
            StateError::InvalidInput(why) => f.write_str(why),
            StateError::Invalid(problems) => f.write_str(&problems.join("; ")),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StateError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, StateError>;
