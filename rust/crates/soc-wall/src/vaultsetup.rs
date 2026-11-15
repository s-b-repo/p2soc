//! Shared construction of the sealed master password and the vault, used by
//! both the wall boot path and the headless subcommands (`vpn`, `vault`).
//!
//! The master password is produced by the sealed host-bound store
//! (`soc-seal`); this is the one place that bridges it to the vault's
//! `MasterSource` trait, so neither crate has to know about the other.

use soc_seal::MasterResolver;
use soc_vault::{Vault, VaultEnv, VaultError};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Adapts the sealed-store master resolver to the vault's `MasterSource`.
pub struct SealedMaster(pub MasterResolver);

impl soc_vault::MasterSource for SealedMaster {
    fn master(&self) -> Result<Zeroizing<String>, VaultError> {
        self.0.get_master().ok_or_else(|| VaultError::NoMaster("no vault master password is available".into()))
    }
}

/// Setup failures carry the human-facing reason text shown to the operator.
pub type SetupResult<T> = Result<T, String>; // audit-allow: String is the human-facing reason/display text

/// Build the sealed master resolver from the environment.
pub fn resolver() -> SetupResult<MasterResolver> {
    MasterResolver::from_env().map_err(|e| e.to_string())
}

/// Build a vault whose master comes from the sealed store. Does not open it.
pub fn build_vault(env: &VaultEnv) -> SetupResult<(Arc<Vault>, MasterResolver)> {
    let resolver = resolver()?;
    let master = Arc::new(SealedMaster(MasterResolver::from_env().map_err(|e| e.to_string())?));
    let vault = Vault::from_settings(env, master).map_err(|e| e.to_string())?;
    Ok((Arc::new(vault), resolver))
}

/// Build and open a vault for a headless tool, retrying briefly: a tool
/// started at boot may race Vaultwarden coming up. On a persistent failure
/// the vault is still returned (its callers retry and can recover once the
/// server answers), with the reason logged.
pub fn open_vault(env: &VaultEnv, attempts: u32, log: &dyn Fn(&str)) -> SetupResult<Arc<Vault>> {
    let (vault, _) = build_vault(env)?;
    for attempt in 1..=attempts.max(1) {
        match vault.open() {
            Ok(()) => return Ok(vault),
            Err(e) if attempt < attempts => {
                log(&format!("vault not ready (attempt {attempt}): {e}; retrying"));
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
            Err(e) => {
                log(&format!("vault did not open: {e}; continuing — callers will retry"));
                return Ok(vault);
            }
        }
    }
    Ok(vault)
}
