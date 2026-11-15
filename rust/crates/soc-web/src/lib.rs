//! p2soc web layer: everything about showing and logging in to dashboards
//! that does not need a GUI toolkit.
//!
//! * [`inject`] — the login bootstrap, the just-in-time credential call, the
//!   calibration snippets.
//! * [`websecurity`] / [`siteguard`] — the navigation allowlist and tracker
//!   blocklist both engines enforce.
//! * [`loginmemory`] — which vault item logs which origin in.
//! * [`style`] — the wall stylesheet and the per-panel status cards.
//! * [`chromium`] — the Chromium engine, driven over the DevTools Protocol.
//!
//! The GTK/WebKit window code lives in the binary crate and calls into this
//! one; nothing here links GTK, so all of it is testable headless.

pub mod chromium;
pub mod error;
pub mod inject;
pub mod loginmemory;
pub mod pyjson;
pub mod siteguard;
pub mod style;
pub mod websecurity;

pub use chromium::{ChromiumOptions, ChromiumPanel, PanelEvent, PanelHooks, PanelStatus};
pub use error::Error;
pub use loginmemory::LoginMemory;
pub use siteguard::AllowList;
pub use style::{Palette, StatusCard, Tokens};
pub use websecurity::SecurityData;
