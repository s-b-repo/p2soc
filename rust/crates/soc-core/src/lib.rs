//! p2soc shared core: the wall's configuration model, its collect-everything
//! validation, the input guards and the non-secret argv builders.
//!
//! Pure data and string handling — no GUI, no network, no unsafe.

pub mod creds;
pub mod dict;
pub mod emit;
pub mod env;
pub mod guard;
pub mod load;
pub mod model;
pub mod url;
pub mod validate;
pub mod vpnargs;

pub use creds::{CredError, CredSource, Login};
pub use dict::{Dict, DictExt};
pub use model::{
    Backend, Config, DisplayCfg, Engine, Geometry, KeepAlive, KeepAliveStrategy, Layout, Mode, Panel, ProxyCfg,
    SecurityCfg, VpnKind, compute_geometry,
};

/// The vault backend selected when `$SOC_VAULT_BACKEND` is unset.
pub const DEFAULT_VAULT_BACKEND: &str = "native";

/// An upper bound on concurrently supervised VPNs: each costs a vault unseal
/// and a sync at boot, so a pasted list of hundreds is an error, not a thrash.
pub const MAX_VPNS: usize = 8;

/// The tag every log line carries.
pub const LOG_TAG: &str = "[soc-kiosk]";

pub use load::{ConfigError, load, load_str};
