//! Serialising a [`Config`] back to YAML — used to push on-screen edits into
//! the vault config note (the source of truth). The output round-trips through
//! [`crate::load::load_str`]; defaults stay implicit so files remain small.

use crate::dict::{Dict, DictExt};
use crate::model::{Config, KeepAliveStrategy, Mode, Panel};
use serde_json::{Value, json};

fn strs(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

/// True when a one-entry list can be written as a legacy `vpn: {}` block: its
/// only added keys are the load-time defaults (name `vpn`, no default route).
fn vpn_is_plain_single(vpn: &Dict) -> bool {
    !vpn.truthy("default_route") && matches!(vpn.text("name").as_str(), "" | "vpn")
}

/// A VPN entry ready for YAML: a load-time-default `name` and a falsy
/// `default_route` are dropped from the single-block form so legacy files stay
/// stable; the list form keeps each entry's identity.
fn vpn_emit(vpn: &Dict, with_name: bool) -> Value {
    let mut out = vpn.clone();
    if !with_name {
        out.shift_remove("name");
    }
    if !out.truthy("default_route") {
        out.shift_remove("default_route");
    }
    Value::Object(out)
}

fn panel_value(p: &Panel) -> Value {
    let mut pd = Dict::new();
    pd.insert("id".into(), json!(p.id));
    pd.insert("engine".into(), json!(p.engine.as_str()));
    pd.insert("grid".into(), json!([p.grid.0, p.grid.1]));
    pd.insert("mode".into(), json!(p.mode.as_str()));
    match p.mode {
        Mode::Tunnel => {
            pd.insert("tunnel".into(), Value::Object(p.tunnel.clone().unwrap_or_default())); // audit-allow: default is the intended fallback
            pd.insert("path".into(), json!(p.path));
            pd.insert("scheme".into(), json!(p.scheme));
        }
        Mode::Direct => {
            pd.insert("url".into(), json!(p.url.clone().unwrap_or_default())); // audit-allow: default is the intended fallback
        }
    }
    if !p.vault_item.is_empty() {
        pd.insert("vault_item".into(), json!(p.vault_item));
    }
    if !p.selectors.is_empty() {
        pd.insert("selectors".into(), Value::Object(p.selectors.clone()));
    }
    if !p.login_marker.is_empty() {
        pd.insert("login_marker".into(), json!(p.login_marker));
    }
    let k = &p.keepalive;
    let mut ka = Dict::new();
    ka.insert("strategy".into(), json!(k.strategy.as_str()));
    if k.strategy != KeepAliveStrategy::None {
        ka.insert("intervalSec".into(), json!(k.interval_sec));
    }
    if let Some(url) = k.url.as_deref().filter(|u| !u.is_empty()) {
        ka.insert("url".into(), json!(url));
    }
    if let Some(target) = k.target.as_deref().filter(|t| !t.is_empty()) {
        ka.insert("target".into(), json!(target));
    }
    pd.insert("keepalive".into(), Value::Object(ka));
    if !p.proxy {
        pd.insert("proxy".into(), json!(false));
    }
    if !p.title.is_empty() {
        pd.insert("title".into(), json!(p.title));
    }
    if p.allow_insecure {
        pd.insert("allow_insecure".into(), json!(true));
    }
    if p.allow_media {
        pd.insert("allow_media".into(), json!(true));
    }
    if !p.tenant.is_empty() {
        pd.insert("tenant".into(), json!(p.tenant));
    }
    if !p.login_zones.is_empty() {
        pd.insert("login_zones".into(), Value::Object(p.login_zones.clone()));
    }
    if !p.persist {
        pd.insert("persist".into(), json!(false));
    }
    if let Some(ua) = p.user_agent.as_deref().filter(|u| !u.is_empty()) {
        pd.insert("user_agent".into(), json!(ua));
    }
    if !p.allow.is_empty() {
        pd.insert("allow".into(), strs(&p.allow));
    }
    if !p.block_trackers {
        pd.insert("block_trackers".into(), json!(false));
    }
    if !p.unblock.is_empty() {
        pd.insert("unblock".into(), strs(&p.unblock));
    }
    Value::Object(pd)
}

/// The config as an ordered document (the shape [`to_yaml`] writes).
pub fn to_value(conf: &Config) -> Value {
    let d = &conf.display;
    let mut display = Dict::new();
    display.insert("auto".into(), json!(d.auto));
    display.insert("width".into(), json!(d.width));
    display.insert("height".into(), json!(d.height));
    display.insert("cols".into(), json!(d.cols));
    display.insert("rows".into(), json!(d.rows));
    display.insert("gap".into(), json!(d.gap));
    display.insert("layout".into(), json!(d.layout.as_str()));
    if !d.fullscreen {
        display.insert("fullscreen".into(), json!(false));
    }

    let mut out = Dict::new();
    out.insert("display".into(), Value::Object(display));
    out.insert("panels".into(), Value::Array(conf.panels.iter().map(panel_value).collect()));
    if !conf.tunnel.is_empty() {
        out.insert("tunnel".into(), Value::Object(conf.tunnel.clone()));
    }
    match conf.vpns.as_slice() {
        [] => {}
        [only] if vpn_is_plain_single(only) => {
            out.insert("vpn".into(), vpn_emit(only, false));
        }
        many => {
            out.insert("vpns".into(), Value::Array(many.iter().map(|v| vpn_emit(v, true)).collect()));
        }
    }

    let sec = &conf.security;
    let mut sd = Dict::new();
    if !sec.nav_allowlist {
        sd.insert("nav_allowlist".into(), json!(false));
    }
    if !sec.block_trackers {
        sd.insert("block_trackers".into(), json!(false));
    }
    if !sec.allow.is_empty() {
        sd.insert("allow".into(), strs(&sec.allow));
    }
    if !sec.sso_allow.is_empty() {
        sd.insert("sso_allow".into(), strs(&sec.sso_allow));
    }
    if !sd.is_empty() {
        out.insert("security".into(), Value::Object(sd));
    }

    let pr = &conf.proxy;
    let mut proxy = Dict::new();
    proxy.insert("enabled".into(), json!(pr.enabled));
    // Written even when disabled: switching the proxy off for a while must not
    // erase its settings from the config note.
    if pr.enabled || !pr.url.is_empty() {
        proxy.insert("url".into(), json!(pr.url));
    }
    if !pr.vault_item.is_empty() {
        proxy.insert("vault_item".into(), json!(pr.vault_item));
    }
    if !pr.ignore_hosts.is_empty() {
        proxy.insert("ignore_hosts".into(), strs(&pr.ignore_hosts));
    }
    out.insert("proxy".into(), Value::Object(proxy));
    Value::Object(out)
}

/// Serialise a loaded config to YAML.
pub fn to_yaml(conf: &Config) -> String {
    // Serialising a tree of plain maps/strings/numbers cannot fail.
    serde_yaml_ng::to_string(&to_value(conf)).unwrap_or_default() // audit-allow: serialising plain maps/strings cannot fail
}
