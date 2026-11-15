//! The one typed error for the whole backend. No `anyhow`.
//!
//! Display strings carry the substrings the VPN supervisor classifies on
//! (`crates/soc-vpn/src/event.rs`): auth failures say "authentication failed",
//! certificate failures say "certificate pin mismatch" / "certificate verify
//! failed", and transport drops surface the OS text ("Connection refused" /
//! "Connection reset"). Keep these words stable.

use std::fmt;

/// Every fallible operation in this crate returns `Result<T, InodeError>`.
#[derive(Debug)]
pub enum InodeError {
    /// Socket/OS error; its Display carries "Connection refused" etc. verbatim.
    Io(std::io::Error),
    /// TLS setup or verification; contains "certificate verify failed" /
    /// "certificate pin mismatch" where applicable.
    Tls(String),
    /// Malformed HTTP response from the gateway.
    Http(String),
    /// Authentication was rejected; Display starts with "authentication failed".
    Auth(String),
    /// A malformed XML / frame / netconfig payload.
    Protocol(String),
    /// A bad or missing configuration value (before any I/O).
    Config(String),
    /// Tunnel data-plane failure (netconfig missing, socket closed, ...).
    Tunnel(String),
    /// A firmware variant we deliberately do not implement (SM2 national-crypto
    /// suite, legacy V3 handshake, ...). The optional RSA password mode *is*
    /// supported — see `crypto::rsa_encrypt_password_b64`.
    Unsupported(String),
}

impl fmt::Display for InodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InodeError::Io(e) => write!(f, "connection error: {e}"),
            InodeError::Tls(m) => write!(f, "TLS error: {m}"),
            InodeError::Http(m) => write!(f, "HTTP error: {m}"),
            InodeError::Auth(m) => write!(f, "{m}"),
            InodeError::Protocol(m) => write!(f, "protocol error: {m}"),
            InodeError::Config(m) => write!(f, "configuration error: {m}"),
            InodeError::Tunnel(m) => write!(f, "tunnel error: {m}"),
            InodeError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for InodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InodeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for InodeError {
    fn from(e: std::io::Error) -> Self {
        InodeError::Io(e)
    }
}

impl InodeError {
    /// Construct an auth failure whose Display begins "authentication failed".
    pub fn auth_failed(detail: impl AsRef<str>) -> InodeError {
        InodeError::Auth(format!("authentication failed: {}", detail.as_ref()))
    }
}

pub type Result<T> = std::result::Result<T, InodeError>;
