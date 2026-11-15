//! One-line diagnostics on stderr, tagged like the rest of the wall. Callers
//! pass only fixed text, paths and error values — never secret material.

use std::fmt::Display;

pub(crate) fn warn(msg: impl Display) {
    eprintln!("{} warning: {msg}", soc_core::LOG_TAG);
}

pub(crate) fn info(msg: impl Display) {
    eprintln!("{} {msg}", soc_core::LOG_TAG);
}
