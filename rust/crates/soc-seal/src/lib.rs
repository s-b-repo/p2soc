//! p2soc sealed secrets: everything between the wall and the vault's master
//! password.
//!
//! * [`SecretStore`] — the host-bound, PIN-sealed master password on disk
//!   (AES-256-GCM; `host.key` + machine-id + PIN), byte-compatible with the
//!   Python release including its legacy format and in-place migration.
//! * [`MasterResolver`] — where the master comes from at run time: the seal,
//!   the freedesktop Secret Service, or (dev only) the environment.
//! * [`ospass`] — checking an operator's OS password through `su` /
//!   `pamtester`, without linking libpam.
//! * [`pinentry`] and [`cli`] — the Assuan pinentry and the pkexec seal
//!   helper, as functions for the binary's subcommands.
//!
//! Secrets are held in [`zeroize::Zeroizing`] buffers, travel to helper
//! programs on stdin only, and never appear in an error, a log line or a
//! `Debug` rendering.
#![forbid(unsafe_code)]

mod blob;
pub mod cli;
mod error;
mod fsio;
mod kdf;
mod log;
mod machine;
mod master;
pub mod ospass;
mod pin;
pub mod pinentry;
mod proc;
mod rng;
mod secret_tool;
mod store;
mod ticket;

pub use error::SealError;
pub use master::{MasterResolver, MasterSource, MasterSourceError, default_attrs, parse_attrs};
pub use pin::{DEFAULT_PIN_DIGITS, MIN_PIN_LEN, gen_pin};
pub use secret_tool::{Attrs, Keyring, SecretTool, SecretToolError};
pub use store::{DEFAULT_SECRET_DIR, SecretStore};
