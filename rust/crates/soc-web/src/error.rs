//! The crate's error type.

use std::path::PathBuf;

/// Why a web-layer operation failed. Messages are safe to log: they never
/// carry a credential, and URLs are masked before they get here.
#[derive(Debug)]
pub enum Error {
    /// A filesystem step failed (`what` names the step and the path).
    Io { what: String, source: std::io::Error },
    /// A configured value was refused before it could reach argv or disk.
    Refused(String),
    /// No Chromium binary on `$PATH`.
    NoBrowser,
    /// A path that must be a private directory is something else (a symlink,
    /// a file) — refusing it beats writing session tokens through it.
    UnsafePath(PathBuf),
    /// The DevTools connection failed.
    Cdp(crate::chromium::CdpError),
}

impl Error {
    pub(crate) fn io(what: impl Into<String>, source: std::io::Error) -> Error {
        Error::Io { what: what.into(), source }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io { what, source } => write!(f, "{what}: {source}"),
            Error::Refused(msg) => f.write_str(msg),
            Error::NoBrowser => f.write_str("no chromium binary found"),
            Error::UnsafePath(p) => write!(f, "{} is not a private directory (symlink or file?)", p.display()),
            Error::Cdp(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Cdp(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::chromium::CdpError> for Error {
    fn from(e: crate::chromium::CdpError) -> Error {
        Error::Cdp(e)
    }
}
