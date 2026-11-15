//! Standalone pinentry helper for `openfortivpn --pinentry=`.
//!
//! openfortivpn executes the helper with no arguments, so it cannot be handed
//! a subcommand of the main binary; this is the same code as a tiny program.
//! (The main binary can instead be symlinked as `soc-vpn-pinentry` and call
//! [`soc_vpn::pinentry_main`] when [`soc_vpn::is_pinentry_argv0`] matches.)

fn main() {
    std::process::exit(soc_vpn::pinentry_main());
}
