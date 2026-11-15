//! p2soc vault layer: a native Vaultwarden/Bitwarden client and everything
//! built on it.
//!
//! * [`Vault`] — the facade the wall uses: a backend plus a short-TTL,
//!   RAM-only credential cache. It implements [`soc_core::CredSource`].
//! * [`Session`] — an authenticated server session: read items, and write
//!   them (the credential editor, TOTP enrolment, setup-time seeding).
//! * [`crypto`] — master-key derivation and type-2 EncStrings.
//! * [`totp`] — RFC 6238 codes, for panel logins and for the kiosk lock.
//! * [`register`] — create / verify the kiosk's Vaultwarden account.
//! * [`backup`] — passphrase-encrypted backup of the Vaultwarden data dir.
//! * [`cli`] — the `litebw` command line, mountable as a subcommand.
//!
//! The master password is never stored by this crate and never read from a
//! plaintext file: it arrives through a [`MasterSource`] the binary supplies.
//!
//! Cargo features (all on by default): `tls` (https vault URLs via rustls),
//! `register` (account creation; pulls in `rsa`) and `backup`.

pub mod backend;
#[cfg(feature = "backup")]
pub mod backup;
pub mod cli;
pub mod config;
pub mod crypto;
mod error;
mod fsutil;
mod http;
pub mod master;
#[cfg(feature = "register")]
pub mod register;
pub mod session;
pub mod totp;
mod vault;

#[cfg(test)]
mod testutil;

pub use backend::{
    Backend, BackendKind, DevFileBackend, NativeBackend, NativeConfig, RbwBackend, VaultEnv, make_backend,
    require_notes,
};
#[cfg(feature = "backup")]
pub use backup::backup_cli_main;
pub use cli::{CliContext, cli_main, cli_main_with};
pub use error::VaultError;
pub use http::{HttpOptions, MAX_RESPONSE_BYTES};
pub use master::{EnvMaster, FixedMaster, MasterSource, NoMaster};
pub use session::{Cipher, LoginRecord, LoginSpec, LoginSummary, Session, SessionOptions, Upsert};
pub use vault::{Vault, VaultOptions};
