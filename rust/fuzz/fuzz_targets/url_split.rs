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
    // The message form must never panic on arbitrary input — that is what we
    // fuzz here. Whether it correctly *redacts* the userinfo is a deterministic
    // property with an exact expected output, asserted in targeted unit tests
    // (soc-core `guard::tests::url_message_masks_credentials`). We deliberately
    // do NOT substring-match the fuzzer's bytes for the credential: a credential
    // byte sequence can legitimately reappear in the path/query (which must stay
    // visible), and the `***` mask abuts the `@host` it keeps, so both produce
    // substring "hits" that are coincidences, not leaks.
    let _ = url_for_msg(text);
});
