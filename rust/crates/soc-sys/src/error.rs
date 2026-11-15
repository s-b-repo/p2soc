//! The crate error type.

use soc_core::guard::GuardError;
use std::fmt;
use std::io;

/// Why a system-layer operation failed. Messages are safe to log: they name
/// paths and settings, never secret material.
#[derive(Debug)]
pub enum SysError {
    /// A filesystem or process operation failed; `what` says which.
    Io { what: String, source: io::Error },
    /// A config value failed an input guard (option injection, bad port, ...).
    Guard(GuardError),
    /// Input that could not be understood (malformed manifest, bad framing).
    Invalid(String),
    /// A deliberate refusal: doing it would weaken a security property.
    Refused(String),
    /// An enabled tunnel with a jump host but nothing to forward — a
    /// misconfiguration, distinct from "no tunnel intended".
    NoForwards,
    /// A command-line mistake.
    Usage(String),
}

impl SysError {
    /// Wrap an I/O error with what was being attempted.
    pub fn io(what: impl Into<String>, source: io::Error) -> SysError {
        SysError::Io { what: what.into(), source }
    }

    /// The process exit status the equivalent script used for this failure.
    pub fn exit_code(&self) -> i32 {
        match self {
            SysError::NoForwards | SysError::Usage(_) => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SysError::Io { what, source } => write!(f, "{what}: {source}"),
            SysError::Guard(e) => e.fmt(f),
            SysError::Invalid(m) | SysError::Refused(m) | SysError::Usage(m) => f.write_str(m),
            SysError::NoForwards => f.write_str(
                "tunnel.enabled=true and jump_host is set, but NO panels use mode: tunnel and \
                 tunnel.extra_forwards is empty, so there is nothing for autossh to forward. Either \
                 disable the tunnel section, or give a panel mode: tunnel / add an extra_forward.",
            ),
        }
    }
}

impl std::error::Error for SysError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SysError::Io { source, .. } => Some(source),
            SysError::Guard(e) => Some(e),
            _ => None,
        }
    }
}

impl From<GuardError> for SysError {
    fn from(e: GuardError) -> SysError {
        SysError::Guard(e)
    }
}

/// The crate result type.
pub type Result<T> = std::result::Result<T, SysError>;
