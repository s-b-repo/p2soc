//! The argv guards are the last line between a config value and a root-run
//! child process (ssh, openfortivpn). Whatever they accept must be a single
//! token that cannot be read as an option.
#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use soc_core::guard::{
    gateway_hostport, has_ctrl_or_space, panel_forward, safe_forward, safe_host, safe_word, split_host_port,
};

fn single_token(s: &str) {
    assert!(!s.is_empty());
    assert!(!s.starts_with('-'), "option-looking token accepted: {s:?}");
    assert!(!has_ctrl_or_space(s), "token with whitespace/control accepted: {s:?}");
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(host) = safe_host(text, "host") {
        single_token(&host);
    }
    if let Ok(word) = safe_word(text, "word") {
        assert!(!word.starts_with('-') && !word.contains('\n') && !word.contains('\r'));
    }
    if let Ok(fwd) = safe_forward(text) {
        single_token(&fwd);
        assert_eq!(fwd, text);
    }
    let _ = split_host_port(text, &json!(443));

    let vpn = json!({"gateway": text, "port": 443});
    if let Ok(hp) = gateway_hostport(vpn.as_object().unwrap()) {
        single_token(&hp);
    }
    let tunnel = json!({"local_port": 19000, "remote_host": text, "remote_port": 443});
    if let Ok(spec) = panel_forward(tunnel.as_object().unwrap()) {
        single_token(&spec);
        assert!(spec.starts_with("127.0.0.1:19000:"), "{spec:?}");
    }
    let tunnel = json!({"local_port": Value::String(text.into()), "remote_host": "h", "remote_port": 1});
    let _ = panel_forward(tunnel.as_object().unwrap());
});
