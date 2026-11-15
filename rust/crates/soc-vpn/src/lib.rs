//! p2soc VPN supervision.
//!
//! One [`Supervisor`] keeps one tunnel connected: it runs the VPN client as a
//! child, classifies its output, reconnects with exponential backoff and holds
//! for a long time after an authentication or certificate failure (hammering a
//! gateway with a rejected password locks the account). A [`VpnManager`] fans
//! a `vpns:` list out to one supervisor thread per entry and owns the routing
//! policy across them; [`supervisor_main`] is the service entry point that
//! speaks the systemd notify protocol.
//!
//! The layering is deliberate: classification, backoff, argv assembly, notify
//! formatting and status parsing are pure; the clock, the process spawner, the
//! network prober and the notify socket are injected, so the policy is tested
//! without sleeping or starting a real VPN client.
//!
//! Secrets never reach argv, a log line, an error message or `Debug` output:
//! the Fortinet password and one-time code travel through the pinentry helper
//! ([`pinentry_main`]) fed from the child's environment, the OpenVPN login is
//! answered over a management socket in a private directory, and the iNode
//! password is passed in the child's environment.

pub mod backoff;
pub mod clock;
pub mod driver;
pub mod entry;
pub mod error;
pub mod event;
pub mod manager;
pub mod mgmt;
pub mod notify;
pub mod overlay;
pub mod pinentry;
pub mod proc;
pub mod scratch;
pub mod status;
pub mod supervisor;
mod sys;
#[cfg(test)]
pub(crate) mod testing;
pub mod tunables;

pub use backoff::Backoff;
pub use clock::{Clock, StopFlag, SystemClock};
pub use driver::{Paths, Programs};
pub use entry::{ServiceConfig, args_main, run_service, supervisor_main, vpn_incomplete};
pub use error::VpnError;
pub use event::{Event, classify};
pub use manager::{VpnManager, aggregate_state};
pub use notify::{Notifier, NullNotifier, SdNotifier, Watchdog};
pub use pinentry::{PINENTRY_NAME, is_pinentry_argv0, pinentry_main};
pub use proc::{ChildProc, CommandSpec, Spawner, SystemSpawner};
pub use status::{NetProber, Probe, Prober, VpnState, vpn_name, vpn_state};
pub use supervisor::{Deps, Handle, Role, Supervisor, VaultAccess};
pub use tunables::Tunables;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Where a log line goes. The service prefixes and tags lines; this crate only
/// produces the message.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// Lock a mutex, ignoring poisoning: every value guarded here stays valid if
/// a holder panicked, and a supervisor must keep running (and cleaning up)
/// after a sibling thread died.
pub(crate) fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A child's output line made safe to log: control characters (a gateway can
/// put terminal escapes into text the client echoes) become `?`.
pub(crate) fn printable(line: &str) -> String {
    line.chars().map(|c| if c != '\t' && c.is_control() { '?' } else { c }).collect()
}
