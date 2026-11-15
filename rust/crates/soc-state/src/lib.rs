//! p2soc on-screen settings state — everything behind the settings window and
//! the kiosk lock that is not a widget.
//!
//! * [`overrides`] — `overrides.json`, the durable record of edits made at the
//!   glass, and [`merge`], which lays it over a loaded config at boot. The file
//!   is untrusted input: every value is re-validated and the merged config is
//!   proven to still pass the loader.
//! * [`auth`] / [`locker`] — the settings gate and the kiosk lock: PIN and TOTP
//!   enrolment, verification, replay protection and a persisted back-off.
//! * [`forms`], [`session`], [`apply`], [`plan`] — the settings form as plain
//!   data: what to save, what to refuse, and the typed list of actions the GUI
//!   has to perform.
//!
//! No GTK, no network, no `unsafe`. Paths, clocks and environment values are
//! arguments; the few functions that read the process environment are thin
//! wrappers named `*_from_env`.

pub mod apply;
pub mod auth;
pub mod authstate;
pub mod error;
pub mod forms;
pub mod fsio;
pub mod limits;
pub mod locker;
pub mod merge;
pub mod overrides;
pub mod pin;
pub mod plan;
pub mod policy;
pub mod session;
pub mod totp;
pub mod yamlio;

mod sanitize;
#[cfg(test)]
pub(crate) mod testutil;

pub use apply::{ApplyError, ApplyForm, DisplayForm, PanelForm, Prepared, SectionForm, VpnForms, prepare_apply};
pub use auth::{AuthOutcome, Enrollment, Method, SettingsAuth};
pub use authstate::{Budget, Schedule};
pub use error::StateError;
pub use fsio::{ensure_state_dir, resolve_state_dir, state_dir_from_env};
pub use locker::{KioskLock, LockHint, LockRequest, LockSources, LockStore, Restore, UnlockOutcome};
pub use merge::{Merged, apply_overrides};
pub use overrides::Overrides;
pub use plan::{Action, ApplyReport, Changes, DisplayChange, HostCaps, PanelChange, Plan, plan_apply};
pub use session::PanelSession;
pub use yamlio::{export_to_dir, export_yaml, import_config};

/// Seconds since the Unix epoch. The one place this crate reads the clock:
/// everything else takes `now` as an argument so it can be tested.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
