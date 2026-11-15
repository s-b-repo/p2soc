//! Any byte string may arrive as a wall config (a file, or a vault note an
//! attacker with vault write access controls). Loading must never panic, and
//! whatever loads must survive a round trip through the emitter.
#![no_main]

use libfuzzer_sys::fuzz_target;
use soc_core::emit::to_yaml;
use soc_core::load::{Overrides, load_str_with};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let overrides = Overrides::default();
    let Ok(conf) = load_str_with(text, "<fuzz>", &overrides) else {
        return;
    };
    for p in &conf.panels {
        // Derived values must be computable for every accepted panel.
        let _ = (p.effective_url(), p.wmclass(), p.configured(), p.tunnel_local_port());
        let g = p.geometry.expect("every loaded panel has a geometry");
        assert!(g.w >= 1 && g.h >= 1, "non-positive cell {g:?}");
    }
    for vpn in &conf.vpns {
        // The argv builders re-run the guards; they may refuse, never panic.
        let _ = soc_core::vpnargs::openfortivpn_args(vpn);
        let _ = soc_core::vpnargs::openvpn_args(vpn);
        let _ = soc_core::vpnargs::inode_extra_args(vpn);
        let _ = soc_core::vpnargs::inode_gateway(vpn);
    }
    let yaml = to_yaml(&conf);
    let again = load_str_with(&yaml, "<fuzz-roundtrip>", &overrides)
        .unwrap_or_else(|e| panic!("emitted config does not load: {e}\n--- input ---\n{text}\n--- emitted ---\n{yaml}"));
    assert_eq!(conf.panels, again.panels, "panels changed in a round trip");
    assert_eq!(conf.display, again.display);
    assert_eq!(conf.proxy, again.proxy);
    assert_eq!(conf.security, again.security);
});
