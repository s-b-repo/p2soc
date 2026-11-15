//! VPN settings held in a vault item's Notes (`config_from_vault`).
//!
//! * Fortinet / iNode: a `KEY=VALUE` block overlaid onto the entry in memory.
//! * WireGuard (non-owner of the default route): the `.conf` is scrubbed of
//!   catch-all routes before it is ever written to disk.

use serde_json::Value;
use soc_core::Dict;
use soc_core::guard::{safe_host, safe_port_str, safe_word};
use std::net::IpAddr;

/// Keys an operator may set in a vault Notes block. A strict allowlist, so a
/// note cannot smuggle an arbitrary setting past the on-screen review.
pub const NOTES_KEYS: [&str; 12] = [
    "ca_file",
    "domain",
    "gateway",
    "half_internet_routes",
    "insecure",
    "otp_from_vault",
    "port",
    "ready_probe",
    "realm",
    "set_dns",
    "set_routes",
    "trusted_cert",
];

const NOTES_BOOLS: [&str; 5] = ["insecure", "set_routes", "set_dns", "half_internet_routes", "otp_from_vault"];

/// A key is echoed in a warning only when it looks like a setting name. A
/// note is free text: the left side of a stray `=` may be half a base64
/// secret or a pasted `password: hunter2 = old` line.
fn loggable_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 32 && key.chars().all(|c| c.is_ascii_lowercase() || c == '_')
}

/// Parse a Notes `KEY=VALUE` block. Blank lines and `#` comments are ignored.
/// A key outside the allowlist, or a value failing the argv guards, is refused
/// loudly and the configured value stands: load-time validation never saw
/// these, and a note holding `gateway=--pppd-plugin=…` must not reach a root
/// process's argv. Values are never echoed, since a note may hold secrets.
pub fn parse_vpn_notes(notes: &str, log: &dyn Fn(&str)) -> Dict {
    let mut out = Dict::new();
    for line in notes.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let Some((key, value)) = s.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if !NOTES_KEYS.contains(&key.as_str()) {
            if loggable_key(&key) {
                log(&format!(
                    "WARNING vault VPN notes: unknown key '{key}' ignored (allowed: {})",
                    NOTES_KEYS.join(", ")
                ));
            } else {
                log("WARNING vault VPN notes: a line with an unrecognised key was ignored");
            }
            continue;
        }
        let parsed = if key == "port" {
            safe_port_str(value, &key).map(Value::from).ok()
        } else if key == "gateway" {
            safe_host(value, &key).map(Value::from).ok()
        } else if NOTES_BOOLS.contains(&key.as_str()) {
            match value.to_lowercase().as_str() {
                "true" | "yes" | "1" => Some(Value::Bool(true)),
                "false" | "no" | "0" => Some(Value::Bool(false)),
                _ => None,
            }
        } else {
            safe_word(value, &key).map(Value::from).ok()
        };
        match parsed {
            Some(v) => {
                out.insert(key, v);
            }
            // Not the guard's message: it quotes the value.
            None => log(&format!("WARNING vault VPN notes: invalid value for {key} refused")),
        }
    }
    out
}

/// True for a prefix that captures (half of) the whole address space, however
/// it is spelled: `0.0.0.0/0`, `::/0`, `::0/0`, `10.0.0.1/0` — and the
/// `0.0.0.0/1` + `128.0.0.0/1` pair wg-quick users employ to override the
/// default route without replacing it.
pub fn is_catch_all(cidr: &str) -> bool {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return false;
    };
    if addr.parse::<IpAddr>().is_err() || prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    prefix.parse::<u32>().is_ok_and(|len| len <= 1)
}

/// Remove catch-all `AllowedIPs` entries from a WireGuard config, returning
/// the scrubbed text and how many entries were dropped.
///
/// Lines are read the way `wg` itself reads them — all whitespace removed,
/// cut at `#`, key case-insensitive — so `Allowed IPs = 0.0.0.0/0 # all`
/// cannot slip past a guard that parses more strictly than the tool it
/// protects. A line left with no entries is dropped entirely.
pub fn strip_catch_all(conf: &str) -> (String, usize) {
    let mut out = String::with_capacity(conf.len());
    let mut dropped = 0;
    for line in conf.split_inclusive('\n') {
        let normal: String =
            line.chars().take_while(|c| *c != '#').filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
        if let Some(rhs) = normal.strip_prefix("allowedips=") {
            let cidrs: Vec<&str> = rhs.split(',').filter(|c| !c.is_empty()).collect();
            let kept: Vec<&str> = cidrs.iter().copied().filter(|c| !is_catch_all(c)).collect();
            if kept.len() != cidrs.len() {
                dropped += cidrs.len() - kept.len();
                if !kept.is_empty() {
                    out.push_str(&format!("AllowedIPs = {}\n", kept.join(", ")));
                }
                continue;
            }
        }
        out.push_str(line);
    }
    (out, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    fn parse(notes: &str) -> (Dict, Vec<String>) {
        let logs = Mutex::new(Vec::new());
        let out = parse_vpn_notes(notes, &|m| logs.lock().unwrap().push(m.to_string()));
        (out, logs.into_inner().unwrap())
    }

    #[test]
    fn overlay_is_typed_and_allowlisted() {
        let (kv, logs) = parse(&format!(
            "# the production HQ fortigate\ngateway = vpn.hq.acme.com\nport=443\nrealm = staff\n\
             trusted_cert={}\nset_routes = true\nbogus_field = nope\n",
            "a".repeat(64)
        ));
        assert_eq!(kv.get("gateway"), Some(&json!("vpn.hq.acme.com")));
        assert_eq!(kv.get("port"), Some(&json!(443)));
        assert_eq!(kv.get("realm"), Some(&json!("staff")));
        assert_eq!(kv.get("set_routes"), Some(&json!(true)));
        assert_eq!(kv.get("trusted_cert"), Some(&json!("a".repeat(64))));
        assert!(!kv.contains_key("bogus_field"));
        assert!(logs.iter().any(|m| m.contains("unknown key 'bogus_field'")));
    }

    #[test]
    fn overlay_refuses_argv_injection_without_echoing_values() {
        let (kv, logs) = parse(
            "gateway=--pppd-plugin=/tmp/evil.so\nport=99999\nrealm=-x\ntrusted_cert=--secret-looking\n\
             insecure=maybe\nunknown=sekrit\ndomain=1\nset_dns=no\n",
        );
        assert_eq!(kv.len(), 2);
        assert_eq!(kv.get("domain"), Some(&json!("1")));
        assert_eq!(kv.get("set_dns"), Some(&json!(false)));
        let all = logs.join("\n");
        assert!(!all.contains("evil.so") && !all.contains("sekrit") && !all.contains("secret-looking"));
    }

    #[test]
    fn a_secret_left_of_an_equals_sign_is_never_logged() {
        let (kv, logs) = parse("QWxhZGRpbjpvcGVuIHNlc2FtZQ==\npass: Hunter2 = old\n");
        assert!(kv.is_empty());
        let all = logs.join("\n").to_lowercase();
        assert!(!all.contains("qwxhzgrpbjpvcgvuihnlc2ftzq") && !all.contains("hunter2"), "{all}");
        assert_eq!(logs.len(), 2);
    }

    #[test]
    fn quotes_and_case_are_tolerated() {
        let (kv, _) = parse("Gateway = \"gw.example\"\nOTP_FROM_VAULT='Yes'\nno equals sign here\n");
        assert_eq!(kv.get("gateway"), Some(&json!("gw.example")));
        assert_eq!(kv.get("otp_from_vault"), Some(&json!(true)));
        assert_eq!(kv.len(), 2);
    }

    #[test]
    fn every_spelling_of_a_catch_all_is_recognised() {
        for cidr in
            ["0.0.0.0/0", "::/0", "::0/0", "0::/0", "0:0::/0", "10.0.0.1/0", "0.0.0.0/1", "128.0.0.0/1", "8000::/1"]
        {
            assert!(is_catch_all(cidr), "{cidr}");
        }
        for cidr in ["10.50.0.0/16", "0.0.0.0/2", "fd00::/8", "10.0.0.1", "junk/0", "10.0.0.0/x", "10.0.0.0/"] {
            assert!(!is_catch_all(cidr), "{cidr}");
        }
    }

    #[test]
    fn catch_all_is_stripped_and_the_rest_kept() {
        let conf = "[Interface]\nPrivateKey=K\n[Peer]\nAllowedIPs = ::0/0, 10.50.0.0/16\nEndpoint = h:1\n";
        let (out, dropped) = strip_catch_all(conf);
        assert_eq!(dropped, 1);
        assert_eq!(out, "[Interface]\nPrivateKey=K\n[Peer]\nAllowedIPs = 10.50.0.0/16\nEndpoint = h:1\n");
    }

    #[test]
    fn a_line_left_empty_is_dropped() {
        let (out, dropped) = strip_catch_all("[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n");
        assert_eq!((out.as_str(), dropped), ("[Peer]\n", 2));
    }

    #[test]
    fn the_guard_reads_lines_the_way_wg_does() {
        // Each of these is a catch-all to `wg`; a stricter parser let them by.
        for line in [
            "AllowedIPs = 0.0.0.0/0 # everything",
            "Allowed IPs = 0.0.0.0/0",
            "ALLOWEDIPS=0.0.0.0/0",
            "\tallowedips\t=\t0.0.0.0 / 0",
            "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1",
        ] {
            let (out, dropped) = strip_catch_all(&format!("[Peer]\n{line}\n"));
            assert!(dropped >= 1, "{line}");
            assert_eq!(out, "[Peer]\n", "{line}");
        }
    }

    #[test]
    fn a_scoped_config_is_returned_untouched() {
        let conf = "[Peer]\n# AllowedIPs = 0.0.0.0/0\nAllowedIPs = 10.0.0.0/8, 192.168.1.0/24";
        assert_eq!(strip_catch_all(conf), (conf.to_string(), 0));
    }
}
