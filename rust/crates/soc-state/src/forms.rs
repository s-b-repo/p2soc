//! Turning flat settings-form values into the minimal dictionaries that are
//! saved as overrides, and checking them before anything is written.
//!
//! A form is a [`Dict`] of widget values keyed by field name (strings from
//! entries, bools from checkboxes, integers from spinners).

use crate::limits::{
    MAX_PATH_LEN, MAX_VAULT_ITEM_LEN, MAX_VPN_CONFIG_LEN, MAX_VPN_DOMAIN_LEN, MAX_VPN_GATEWAY_LEN, MAX_VPN_NAME_LEN,
    MAX_VPN_REALM_LEN, sanitize_len,
};
use crate::merge::merge_form;
use crate::sanitize::loader_problems;
use serde_json::{Value, json};
use soc_core::dict::{text, truthy};
use soc_core::guard::{VALID_HOST_KEY_CHECKING, safe_forward, safe_host, safe_word_value};
use soc_core::{Dict, DictExt};

/// VPN text fields and the longest value each may hold.
const VPN_TEXT_KEYS: [(&str, usize); 16] = [
    ("name", MAX_VPN_NAME_LEN),
    ("gateway", MAX_VPN_GATEWAY_LEN),
    ("vault_item", MAX_VAULT_ITEM_LEN),
    ("config", MAX_VPN_CONFIG_LEN),
    ("domain", MAX_VPN_DOMAIN_LEN),
    ("realm", MAX_VPN_REALM_LEN),
    ("trusted_cert", MAX_VPN_REALM_LEN),
    ("ready_probe", MAX_VPN_GATEWAY_LEN + 6),
    ("ca_file", MAX_PATH_LEN),
    ("client_cert", MAX_PATH_LEN),
    ("client_key", MAX_PATH_LEN),
    ("spa_key", MAX_VPN_REALM_LEN),
    ("spa_aid", MAX_VPN_REALM_LEN),
    ("spa_ports", MAX_VPN_REALM_LEN),
    ("mac", MAX_VPN_REALM_LEN),
    ("language", MAX_VPN_REALM_LEN),
];
const VPN_FLAG_KEYS: [&str; 3] = ["ead", "insecure", "config_from_vault"];
const VPN_INT_KEYS: [&str; 4] = ["port", "health_check_interval", "spa_knock_port", "captcha_retries"];

/// A form field as trimmed text (`""` for an unset one).
fn field_text(form: &Dict, key: &str) -> String {
    form.get(key).filter(|v| truthy(v)).map(|v| text(v).trim().to_string()).unwrap_or_default() // audit-allow: default is the intended fallback
}

fn field_set(form: &Dict, key: &str) -> bool {
    form.get(key).is_some_and(truthy)
}

/// A clean VPN entry from flat form values: always `enabled` + `type`, only
/// non-empty strings, positive integers, and flags that are on.
///
/// `split_tunnel` is the exception among the flags: the driver treats an
/// absent key as ON, so an explicit `false` is kept — dropping it is what once
/// made split tunnelling impossible to turn off at the glass.
pub fn vpn_form_to_dict(form: &Dict) -> Dict {
    let mut out = Dict::new();
    out.insert("enabled".into(), json!(field_set(form, "enabled")));
    let kind = field_text(form, "type");
    out.insert("type".into(), json!(if kind.is_empty() { "fortinet".to_string() } else { kind }));
    for (key, max) in VPN_TEXT_KEYS {
        let value = sanitize_len(&field_text(form, key), max);
        if !value.is_empty() {
            out.insert(key.into(), json!(value));
        }
    }
    for key in VPN_FLAG_KEYS {
        if field_set(form, key) {
            out.insert(key.into(), json!(true));
        }
    }
    if let Some(split) = form.get("split_tunnel") {
        out.insert("split_tunnel".into(), json!(truthy(split)));
    }
    for key in VPN_INT_KEYS {
        let n = form.int(key);
        if n > 0 {
            out.insert(key.into(), json!(n));
        }
    }
    out
}

fn split_list(raw: Option<&Value>, separators: &[char]) -> Vec<String> {
    let items: Vec<String> = match raw {
        Some(Value::String(s)) => s.split(separators).map(|part| part.trim().to_string()).collect(),
        Some(Value::Array(a)) => a.iter().map(text).collect(),
        _ => Vec::new(),
    };
    items.into_iter().filter(|item| !item.is_empty()).collect()
}

/// A clean proxy override from form values: empty strings dropped,
/// `ignore_hosts` (comma- or newline-separated) as a list.
pub fn proxy_form_to_dict(form: &Dict) -> Dict {
    let mut out = Dict::new();
    out.insert("enabled".into(), json!(field_set(form, "enabled")));
    for key in ["url", "vault_item"] {
        let value = field_text(form, key);
        if !value.is_empty() {
            out.insert(key.into(), json!(value));
        }
    }
    let hosts = split_list(form.get("ignore_hosts"), &[',', '\n']);
    if !hosts.is_empty() {
        out.insert("ignore_hosts".into(), json!(hosts));
    }
    out
}

/// A clean tunnel section from form values. `extra_forwards` is one entry per
/// line; `host_key_checking` is kept only when it is a value the loader
/// accepts — `no` is deliberately not one.
pub fn tunnel_form_to_dict(form: &Dict) -> Dict {
    let mut out = Dict::new();
    out.insert("enabled".into(), json!(form.get("enabled").is_none_or(truthy)));
    for key in ["jump_host", "identity", "known_hosts"] {
        let value = field_text(form, key);
        if !value.is_empty() {
            out.insert(key.into(), json!(value));
        }
    }
    let checking = field_text(form, "host_key_checking").to_lowercase();
    if VALID_HOST_KEY_CHECKING.contains(&checking.as_str()) {
        out.insert("host_key_checking".into(), json!(checking));
    }
    let forwards = split_list(form.get("extra_forwards"), &['\n', '\r']);
    if !forwards.is_empty() {
        out.insert("extra_forwards".into(), json!(forwards));
    }
    out
}

/// The `*_form_to_dict` helpers drop empty values to keep overrides minimal,
/// and overrides merge key by key — so a field the operator blanked, or a flag
/// they unticked, would silently keep its old value after a restart (unticking
/// "skip TLS verify" would not stick). Re-add exactly those keys: `false` for
/// a flag, `null` ("remove it", see [`merge_form`]) for anything else.
pub fn mark_cleared(out: &mut Dict, form: &Dict, before: &Dict) {
    for key in form.keys() {
        if out.contains_key(key) {
            continue;
        }
        match before.get(key) {
            Some(Value::Bool(true)) => out.insert(key.clone(), json!(false)),
            Some(value) if truthy(value) => out.insert(key.clone(), Value::Null),
            _ => None,
        };
    }
}

/// One live VPN section of the form.
#[derive(Debug, Clone, PartialEq)]
pub struct VpnEdit {
    /// Position in the VPN tab (names a VPN that was left unnamed).
    pub index: usize,
    /// The section's current values.
    pub form: Dict,
    /// Its values when the window opened; `None` for a VPN added here.
    pub base_form: Option<Dict>,
    /// The whole VPN as loaded (`{}` for a new one).
    pub before: Dict,
}

/// What one VPN section amounts to.
#[derive(Debug, Clone, PartialEq)]
pub struct VpnResult {
    /// The override entry to save.
    pub saved: Dict,
    /// The whole VPN after the edit (what the host applies).
    pub merged: Dict,
    pub edited: bool,
}

/// Work out the override entry and the resulting VPN for one section.
pub fn collect_vpn(edit: &VpnEdit) -> VpnResult {
    let mut saved = vpn_form_to_dict(&edit.form);
    let name = saved.text("name");
    let name = if name.is_empty() { format!("vpn-{}", edit.index + 1) } else { name };
    saved.insert("name".into(), json!(name));
    mark_cleared(&mut saved, &edit.form, &edit.before);
    let mut merged = edit.before.clone();
    merge_form(&mut merged, &saved);
    let old_name = edit.before.text("name");
    if !old_name.is_empty() && old_name != name {
        // Renamed: at boot the old entry is dropped, so nothing is left to
        // merge over and the advanced fields have to travel with it.
        saved = merged.clone();
    }
    VpnResult { saved, merged, edited: edit.base_form.as_ref() != Some(&edit.form) }
}

/// Run the loader's validators over what is about to be saved, so a bad value
/// is refused at the form instead of surfacing as a wall that no longer
/// boots. Only the sections passed in are checked: an old quirk elsewhere
/// must not block an unrelated edit.
pub fn form_problems(
    vpns_merged: Option<&[Dict]>,
    proxy_form: Option<&Dict>,
    tunnel_form: Option<&Dict>,
    any_tunnel_panel: bool,
) -> Vec<String> {
    let mut problems = Vec::new();
    if let Some(vpns) = vpns_merged {
        problems.extend(loader_problems(&json!({"vpns": vpns})));
    }
    if let Some(form) = proxy_form {
        problems.extend(loader_problems(&json!({"proxy": proxy_form_to_dict(form)})));
    }
    if let Some(form) = tunnel_form {
        let tunnel = tunnel_form_to_dict(form);
        let jump_host = tunnel.text("jump_host");
        if !jump_host.is_empty() {
            if let Err(e) = safe_host(&jump_host, "tunnel.jump_host") {
                problems.push(e.0);
            }
        }
        for key in ["identity", "known_hosts"] {
            if let Err(e) = safe_word_value(tunnel.get(key), &format!("tunnel.{key}")) {
                problems.push(e.0);
            }
        }
        if tunnel.truthy("enabled") && jump_host.is_empty() && any_tunnel_panel {
            problems.push("panels use mode 'tunnel' but no jump host is set".to_string());
        }
        for entry in tunnel.strings("extra_forwards") {
            if let Err(e) = safe_forward(&entry) {
                problems.push(e.0);
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(v: Value) -> Dict {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn split_tunnel_false_is_kept() {
        assert_eq!(vpn_form_to_dict(&d(json!({"split_tunnel": false})))["split_tunnel"], json!(false));
        assert_eq!(vpn_form_to_dict(&d(json!({"split_tunnel": true})))["split_tunnel"], json!(true));
        assert!(!vpn_form_to_dict(&Dict::new()).contains_key("split_tunnel"));
    }

    #[test]
    fn split_tunnel_off_survives_the_boot_merge() {
        // Why the False matters: the driver treats an absent key as ON.
        let mut vpn = d(json!({"type": "inode", "split_tunnel": true}));
        let saved = vpn_form_to_dict(&d(json!({"type": "inode", "split_tunnel": false})));
        merge_form(&mut vpn, &saved);
        assert_eq!(vpn["split_tunnel"], json!(false));
    }

    #[test]
    fn vpn_form_defaults_and_coercions() {
        assert_eq!(Value::Object(vpn_form_to_dict(&Dict::new())), json!({"enabled": false, "type": "fortinet"}));
        let out = vpn_form_to_dict(&d(json!({
            "enabled": true, "type": "openvpn", "gateway": "  gw  ", "port": "443", "health_check_interval": -3,
            "ead": true, "insecure": false, "realm": "", "captcha_retries": 2.9, "spa_knock_port": "x",
        })));
        assert_eq!(
            Value::Object(out),
            json!({"enabled": true, "type": "openvpn", "gateway": "gw", "ead": true, "port": 443, "captcha_retries": 2})
        );
    }

    #[test]
    fn over_long_vpn_text_is_cut_to_the_field_limit() {
        let out = vpn_form_to_dict(&d(json!({"name": "n".repeat(500), "realm": "r".repeat(500)})));
        assert_eq!(out.text("name").len(), MAX_VPN_NAME_LEN);
        assert_eq!(out.text("realm").len(), MAX_VPN_REALM_LEN);
    }

    #[test]
    fn proxy_form_splits_the_bypass_list() {
        let out = proxy_form_to_dict(&d(json!({
            "enabled": true, "url": " http://p.test:3128 ", "vault_item": "", "ignore_hosts": "x.test, y.test\nz.test,,",
        })));
        assert_eq!(
            Value::Object(out),
            json!({"enabled": true, "url": "http://p.test:3128", "ignore_hosts": ["x.test", "y.test", "z.test"]})
        );
        assert_eq!(Value::Object(proxy_form_to_dict(&Dict::new())), json!({"enabled": false}));
    }

    #[test]
    fn tunnel_form_cannot_turn_host_key_checking_off() {
        assert!(!tunnel_form_to_dict(&d(json!({"host_key_checking": "no"}))).contains_key("host_key_checking"));
        let out = tunnel_form_to_dict(&d(json!({
            "enabled": false, "host_key_checking": " Accept-New ", "extra_forwards": "8080:web.test:80\n\n 9:db.test:5 ",
        })));
        assert_eq!(
            Value::Object(out),
            json!({"enabled": false, "host_key_checking": "accept-new", "extra_forwards": ["8080:web.test:80", "9:db.test:5"]})
        );
        assert_eq!(Value::Object(tunnel_form_to_dict(&Dict::new())), json!({"enabled": true}));
    }

    #[test]
    fn cleared_fields_and_unticked_flags_are_marked() {
        let form = d(json!({"insecure": false, "realm": "", "gateway": "gw.test", "domain": ""}));
        let before = d(json!({"insecure": true, "realm": "corp", "gateway": "gw.test", "set_routes": true}));
        let mut out = vpn_form_to_dict(&form);
        mark_cleared(&mut out, &form, &before);
        assert_eq!(out["insecure"], json!(false));
        assert_eq!(out["realm"], Value::Null);
        assert!(!out.contains_key("domain"), "was never set, nothing to clear");
        assert!(!out.contains_key("set_routes"), "not on the form, left alone");

        let mut vpn = before.clone();
        merge_form(&mut vpn, &out);
        assert_eq!(vpn["insecure"], json!(false), "TLS verification really came back");
        assert!(!vpn.contains_key("realm"));
        assert_eq!(vpn["set_routes"], json!(true));
    }

    #[test]
    fn a_renamed_vpn_carries_its_advanced_fields() {
        let before =
            d(json!({"name": "hq", "enabled": true, "type": "inode", "gateway": "gw.test", "set_routes": true}));
        let form = d(json!({"name": "hq2", "enabled": true, "type": "inode", "gateway": "gw.test"}));
        let out = collect_vpn(&VpnEdit { index: 0, form: form.clone(), base_form: Some(form.clone()), before });
        assert_eq!(out.saved["set_routes"], json!(true));
        assert_eq!(out.saved, out.merged);
        assert!(!out.edited);

        let unnamed = collect_vpn(&VpnEdit { index: 2, form: Dict::new(), base_form: None, before: Dict::new() });
        assert_eq!(unnamed.saved["name"], json!("vpn-3"));
        assert!(unnamed.edited, "a VPN added here is always a change");
    }

    #[test]
    fn invalid_sections_are_reported_before_anything_is_saved() {
        let bad_vpn =
            [d(json!({"name": "hq", "enabled": true, "type": "fortinet", "gateway": "bad host", "vault_item": "v"}))];
        assert!(form_problems(Some(&bad_vpn), None, None, false).iter().any(|p| p.contains("gateway")));
        let ok_vpn = [d(json!({"name": "hq", "enabled": false}))];
        assert!(form_problems(Some(&ok_vpn), None, None, false).is_empty());

        let creds = d(json!({"enabled": true, "url": "http://u:p@proxy.test:3128"}));
        assert!(form_problems(None, Some(&creds), None, false).iter().any(|p| p.contains("credentials")));

        let forward = d(json!({"enabled": true, "jump_host": "ops@jump", "extra_forwards": "-D 1080"}));
        assert_eq!(form_problems(None, None, Some(&forward), false).len(), 1);
        let inject = d(json!({"enabled": true, "jump_host": "-oProxyCommand=x"}));
        assert!(form_problems(None, None, Some(&inject), false)[0].contains("option injection"));

        let blank = d(json!({"enabled": true, "jump_host": ""}));
        assert!(form_problems(None, None, Some(&blank), false).is_empty());
        assert_eq!(form_problems(None, None, Some(&blank), true), ["panels use mode 'tunnel' but no jump host is set"]);
        assert!(form_problems(None, None, None, true).is_empty(), "untouched sections are not checked");
    }
}
