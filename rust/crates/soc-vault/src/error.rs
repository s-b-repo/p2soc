//! The crate's single error type. Messages are written for the operator at the
//! glass and never contain secret material (passwords, tokens, key bytes).

use soc_core::CredError;

/// Why a vault operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Missing or invalid settings (URL, email, backend name).
    Config(String),
    /// The server could not be reached (DNS, TCP, TLS, timeout).
    Unreachable(String),
    /// The server answered with a non-success status.
    Http { status: u16, message: String },
    /// The password grant was refused. Vaultwarden gives one answer for "no
    /// such account" and "wrong password", so the two cannot be told apart.
    LoginRejected(String),
    /// Interactive mode and no master password yet: the host should show its
    /// Unlock dialog and call `unlock_with`, not treat this as a misconfig.
    Locked(String),
    /// No master password is available from the configured source.
    NoMaster(String),
    /// The vault answered but has no such item / field.
    NotFound(String),
    /// An EncString was malformed, unauthenticated or failed its MAC.
    Crypto(String),
    /// The announced KDF is unsupported or outside the accepted range.
    Kdf(String),
    /// A response was oversized, not JSON, or not shaped as expected.
    Protocol(String),
    /// The server refuses registrations.
    SignupsDisabled(String),
    /// The account exists but this master password does not open it.
    WrongMaster(String),
    /// A TOTP secret could not be parsed.
    Totp(String),
    /// A local file operation failed.
    Io(String),
    /// A helper process (the legacy `rbw` CLI) failed.
    Backend(String),
    /// Backup / restore failure.
    Backup(String),
    /// A write would overwrite a different item of the same name.
    Conflict(String),
}

impl VaultError {
    /// The HTTP status carried by this error, if any.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            VaultError::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// True when the failure says nothing about the item itself — the vault
    /// was unreachable or overloaded — so a last-good credential may be served.
    pub fn is_transient(&self) -> bool {
        match self {
            VaultError::Unreachable(_) | VaultError::Backend(_) => true,
            VaultError::Http { status, .. } => *status >= 500 || matches!(*status, 408 | 429),
            _ => false,
        }
    }

    pub(crate) fn io(what: &str, e: &std::io::Error) -> VaultError {
        VaultError::Io(format!("{what}: {e}"))
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Http { message, .. } => f.write_str(message),
            VaultError::Config(m)
            | VaultError::Unreachable(m)
            | VaultError::LoginRejected(m)
            | VaultError::Locked(m)
            | VaultError::NoMaster(m)
            | VaultError::NotFound(m)
            | VaultError::Crypto(m)
            | VaultError::Kdf(m)
            | VaultError::Protocol(m)
            | VaultError::SignupsDisabled(m)
            | VaultError::WrongMaster(m)
            | VaultError::Totp(m)
            | VaultError::Io(m)
            | VaultError::Backend(m)
            | VaultError::Backup(m)
            | VaultError::Conflict(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<VaultError> for CredError {
    fn from(e: VaultError) -> CredError {
        let msg = e.to_string();
        match e {
            VaultError::NotFound(_) => CredError::NotFound(msg),
            VaultError::Locked(_) | VaultError::NoMaster(_) => CredError::Unavailable(msg),
            ref other if other.is_transient() => CredError::Unavailable(msg),
            _ => CredError::Other(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_onto_the_credential_boundary() {
        assert!(matches!(CredError::from(VaultError::NotFound("x".into())), CredError::NotFound(_)));
        assert!(matches!(CredError::from(VaultError::Locked("x".into())), CredError::Unavailable(_)));
        assert!(matches!(CredError::from(VaultError::Unreachable("x".into())), CredError::Unavailable(_)));
        let e = VaultError::Http { status: 503, message: "x".into() };
        assert!(matches!(CredError::from(e), CredError::Unavailable(_)));
        let e = VaultError::Http { status: 400, message: "x".into() };
        assert!(matches!(CredError::from(e), CredError::Other(_)));
        assert!(matches!(CredError::from(VaultError::Crypto("x".into())), CredError::Other(_)));
    }

    #[test]
    fn only_availability_failures_are_transient() {
        assert!(VaultError::Unreachable("x".into()).is_transient());
        assert!(VaultError::Http { status: 502, message: String::new() }.is_transient());
        assert!(VaultError::Http { status: 429, message: String::new() }.is_transient());
        assert!(!VaultError::Http { status: 401, message: String::new() }.is_transient());
        assert!(!VaultError::NotFound("x".into()).is_transient());
        assert!(!VaultError::LoginRejected("x".into()).is_transient());
    }
}
