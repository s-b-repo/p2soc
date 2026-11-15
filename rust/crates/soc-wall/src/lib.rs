//! p2soc wall host: the GTK/WebKit video wall plus the headless tools that
//! ship in the same binary.

pub mod cli;
pub mod dispatch;
#[cfg(feature = "gui")]
pub mod gui;
pub mod logic;
pub mod supervise;
pub mod vaultsetup;
