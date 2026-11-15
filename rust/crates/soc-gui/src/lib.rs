//! p2soc standalone desktop tools (GTK3), each launched as a `soc-wall`
//! subcommand: the launcher/control-center menu, the graphical setup wizard,
//! the credentials & security center, the appearance (theme) editor, the
//! fail-safe error dialog, and a best-effort system-tray icon.
//!
//! These do not depend on the running wall; they share only its palette
//! (`style`) and the ported logic crates.

pub mod appearance;
pub mod credcenter;
pub mod errdialog;
pub mod menu;
pub mod setupwiz;
pub mod style;
