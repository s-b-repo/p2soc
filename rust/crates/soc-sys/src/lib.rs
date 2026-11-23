//! p2soc system layer: everything the wall needs from the host that is not a
//! browser, a vault or a VPN.
//!
//! - [`paths`] — where config, secret and state files live, and the
//!   read/write precedence between system, user and checkout locations.
//! - [`perf`] / [`watchdog`] — hardware profile and the memory watchdog's
//!   decision logic.
//! - [`heartbeat`], [`manifest`], [`health`], [`complexity`] — liveness,
//!   deploy-integrity, readiness and PIN/password policy checks.
//! - [`sysaction`] — the only privileged command lines the wall may run.
//! - [`tunnel`], [`pinhost`], [`wmrules`], [`session`] — the autossh argv, the
//!   jump-host key pin, window-manager placement rules and session facts.
//! - [`tarpit`] — the scanner-deception HTTP tarpit.
//!
//! No GUI and no async runtime. External programs are only ever run through
//! [`run::Runner`] with an explicit argv — never a shell.

pub mod complexity;
pub mod error;
pub mod fsutil;
pub mod health;
pub mod heartbeat;
pub mod jsonfmt;
pub mod manifest;
pub mod paths;
pub mod perf;
pub mod pinhost;
pub mod run;
pub mod session;
pub mod sha256;
pub mod sysaction;
pub mod tarpit;
pub mod tunnel;
pub mod update;
pub mod watchdog;
pub mod wmrules;

#[cfg(test)]
pub(crate) mod testutil;

pub use error::{Result, SysError};
pub use paths::configpaths_cli;
pub use tarpit::tarpit_main;
pub use tunnel::tunnel_args;
