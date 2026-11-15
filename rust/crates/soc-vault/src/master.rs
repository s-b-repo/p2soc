//! Where the vault master password comes from.
//!
//! The sealed, host-bound store lives in another crate; this crate only asks a
//! [`MasterSource`] so it never depends on how the secret is kept. The binary
//! wires the sealed store in; the CLI and dev runs can fall back to
//! [`EnvMaster`].

use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use crate::error::VaultError;

/// A provider of the master password.
///
/// Return `Err(VaultError::NoMaster(..))` (or an empty string) when no master
/// is available *yet* — in interactive mode that turns into the "please
/// unlock" signal rather than a failure. Any other error is surfaced as-is.
pub trait MasterSource: Send + Sync {
    fn master(&self) -> Result<Zeroizing<String>, VaultError>;
}

impl<F> MasterSource for F
where
    F: Fn() -> Result<Zeroizing<String>, VaultError> + Send + Sync,
{
    fn master(&self) -> Result<Zeroizing<String>, VaultError> {
        self()
    }
}

/// A master password read from an environment variable — development and
/// seeding only. Anything in the environment is readable by every process of
/// the same user (`/proc/<pid>/environ`), so a production wall uses the sealed
/// store instead, and this source says so the first time it yields a value.
pub struct EnvMaster {
    var: String,
    warned: AtomicBool,
}

impl EnvMaster {
    /// The variable the Python host used.
    pub const DEFAULT_VAR: &'static str = "SOC_VAULT_PASSWORD";

    pub fn new() -> EnvMaster {
        EnvMaster::with_var(Self::DEFAULT_VAR)
    }

    pub fn with_var(var: &str) -> EnvMaster {
        EnvMaster { var: var.to_string(), warned: AtomicBool::new(false) }
    }
}

impl Default for EnvMaster {
    fn default() -> Self {
        EnvMaster::new()
    }
}

impl MasterSource for EnvMaster {
    fn master(&self) -> Result<Zeroizing<String>, VaultError> {
        match std::env::var(&self.var) {
            Ok(v) if !v.is_empty() => {
                if !self.warned.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "{} vault: ${} from the environment is DEV/seeding only; production uses the sealed store",
                        soc_core::LOG_TAG,
                        self.var
                    );
                }
                Ok(Zeroizing::new(v))
            }
            _ => Err(VaultError::NoMaster(format!("no vault master password (host not sealed and no ${})", self.var))),
        }
    }
}

/// A master password held in memory, e.g. one the operator just typed.
pub struct FixedMaster(Zeroizing<String>);

impl FixedMaster {
    pub fn new(master: impl Into<String>) -> FixedMaster {
        FixedMaster(Zeroizing::new(master.into()))
    }
}

impl std::fmt::Debug for FixedMaster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FixedMaster(<redacted>)")
    }
}

impl MasterSource for FixedMaster {
    fn master(&self) -> Result<Zeroizing<String>, VaultError> {
        Ok(self.0.clone())
    }
}

/// A source that never has a master (an unsealed, interactive wall).
pub struct NoMaster;

impl MasterSource for NoMaster {
    fn master(&self) -> Result<Zeroizing<String>, VaultError> {
        Err(VaultError::NoMaster("no vault master password is configured".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closures_and_fixed_values_are_sources() {
        let from_closure = || Ok(Zeroizing::new("typed".to_string()));
        assert_eq!(from_closure.master().unwrap().as_str(), "typed");
        let fixed = FixedMaster::new("hunter2");
        assert_eq!(fixed.master().unwrap().as_str(), "hunter2");
        assert!(!format!("{fixed:?}").contains("hunter2"));
        assert!(matches!(NoMaster.master(), Err(VaultError::NoMaster(_))));
    }

    #[test]
    fn unset_env_variable_is_no_master() {
        let src = EnvMaster::with_var("SOC_VAULT_TEST_VARIABLE_THAT_IS_NEVER_SET");
        assert!(matches!(src.master(), Err(VaultError::NoMaster(_))));
    }
}
