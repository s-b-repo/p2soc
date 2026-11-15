//! The credential boundary. Everything that needs a secret (panel auto-login,
//! proxy auth, the VPN supervisor) asks a [`CredSource`]; only the vault crate
//! implements it for real. Secrets are wiped from memory when dropped.

use zeroize::Zeroize;

/// A username/password pair fetched just-in-time. Wiped on drop; `Debug`
/// never prints the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Login {
    pub username: String,
    pub password: String,
}

impl Login {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Login {
        Login { username: username.into(), password: password.into() }
    }
}

impl Drop for Login {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login").field("username", &self.username).field("password", &"<redacted>").finish()
    }
}

/// Why a secret could not be produced. Messages never contain secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredError {
    /// The vault is locked or unreachable (worth retrying later).
    Unavailable(String),
    /// The vault answered but has no such item / field.
    NotFound(String),
    /// Anything else.
    Other(String),
}

impl std::fmt::Display for CredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredError::Unavailable(m) | CredError::NotFound(m) | CredError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CredError {}

/// A source of vault-held secrets, addressed by item name.
pub trait CredSource: Send + Sync {
    /// Username + password of a login item.
    fn creds(&self, item: &str) -> Result<Login, CredError>;
    /// The item's notes (`""` when it has none).
    fn notes(&self, item: &str) -> Result<String, CredError>;
    /// A current TOTP code for the item.
    fn code(&self, item: &str) -> Result<String, CredError>;
}

/// A fixed in-memory source, for tests and dry runs.
#[derive(Default)]
pub struct StaticCreds {
    pub logins: std::collections::HashMap<String, (String, String)>,
    pub notes: std::collections::HashMap<String, String>,
    pub codes: std::collections::HashMap<String, String>,
}

impl CredSource for StaticCreds {
    fn creds(&self, item: &str) -> Result<Login, CredError> {
        self.logins
            .get(item)
            .map(|(u, p)| Login::new(u.as_str(), p.as_str()))
            .ok_or_else(|| CredError::NotFound(format!("no vault item named {item:?}")))
    }

    fn notes(&self, item: &str) -> Result<String, CredError> {
        Ok(self.notes.get(item).cloned().unwrap_or_default()) // audit-allow: absent note reads as empty; default is the intended fallback
    }

    fn code(&self, item: &str) -> Result<String, CredError> {
        self.codes.get(item).cloned().ok_or_else(|| CredError::NotFound(format!("no TOTP on vault item {item:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_password() {
        let l = Login::new("alice", "hunter2");
        let shown = format!("{l:?}");
        assert!(shown.contains("alice"));
        assert!(!shown.contains("hunter2"));
    }

    #[test]
    fn static_source() {
        let mut s = StaticCreds::default();
        s.logins.insert("SOC Panel 1".into(), ("u".into(), "p".into()));
        assert_eq!(s.creds("SOC Panel 1").unwrap().password, "p");
        assert!(matches!(s.creds("nope"), Err(CredError::NotFound(_))));
        assert_eq!(s.notes("nope").unwrap(), "");
    }
}
