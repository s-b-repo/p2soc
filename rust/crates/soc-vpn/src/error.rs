//! The crate's error type. No variant ever carries secret material.

use soc_core::CredError;
use soc_core::guard::GuardError;
use std::fmt;

/// Why a connection attempt could not be started.
#[derive(Debug)]
pub enum VpnError {
    /// A config value failed the argv guards at connect time.
    Guard(GuardError),
    /// The vault could not produce a secret.
    Cred(CredError),
    /// A filesystem or process operation failed.
    Io { what: &'static str, source: std::io::Error },
    /// The previous client could not be killed; a second one would fight it
    /// over the same routes and tunnel device.
    Busy,
    /// A one-time code is required but the vault produced none.
    OtpUnavailable,
    /// The vault item has no password; a blank login would only count
    /// against the account's lockout threshold.
    BlankPassword,
}

impl fmt::Display for VpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VpnError::Guard(e) => write!(f, "{e}"),
            VpnError::Cred(e) => write!(f, "{e}"),
            VpnError::Io { what, source } => write!(f, "{what}: {source}"),
            VpnError::Busy => f.write_str("previous child is still running"),
            VpnError::OtpUnavailable => f.write_str("no one-time code available"),
            VpnError::BlankPassword => f.write_str("the vault item has no password"),
        }
    }
}

impl std::error::Error for VpnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VpnError::Guard(e) => Some(e),
            VpnError::Cred(e) => Some(e),
            VpnError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<GuardError> for VpnError {
    fn from(e: GuardError) -> Self {
        VpnError::Guard(e)
    }
}

impl From<CredError> for VpnError {
    fn from(e: CredError) -> Self {
        VpnError::Cred(e)
    }
}

impl VpnError {
    pub(crate) fn io(what: &'static str, source: std::io::Error) -> VpnError {
        VpnError::Io { what, source }
    }
}
