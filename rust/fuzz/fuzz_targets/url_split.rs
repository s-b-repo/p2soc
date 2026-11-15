//! The URL splitter backs every "is this URL safe to load / send credentials
//! to" decision. It must never panic, and what it accepts as a panel URL must
//! really be a credential-free http(s) URL with a host.
#![no_main]

use libfuzzer_sys::fuzz_target;
use soc_core::guard::{url_for_msg, valid_http_url};
use soc_core::url::Url;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let parsed = Url::split(text);
    if let Ok(u) = &parsed {
        let _ = (u.origin(), u.port_or_default());
        if let Some(host) = &u.host {
            assert!(!host.is_empty());
            assert!(!host.contains('@'), "userinfo leaked into the host: {host:?}");
        }
    }
    if valid_http_url(text, false) {
        let u = parsed.expect("an accepted URL must split");
        assert!(matches!(u.scheme.as_str(), "http" | "https"));
        assert!(u.host.is_some());
        assert!(u.userinfo.is_none(), "accepted a URL with credentials");
        assert!(!text.trim().chars().any(|c| c.is_whitespace() || c.is_control()));
    }
    // The message form must never show the userinfo it exists to hide.
    let shown = url_for_msg(text);
    if let Ok(Url { userinfo: Some(secret), .. }) = Url::split(text) {
        let visible = text.replacen(&format!("{secret}@"), "", 1);
        if secret.len() >= 4 && !visible.contains(&secret) && !secret.contains(['\\', '\'']) {
            assert!(!shown.contains(&secret), "userinfo {secret:?} leaked into {shown:?}");
        }
    }
});
