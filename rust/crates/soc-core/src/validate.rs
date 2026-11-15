//! Collect-everything validation of a raw wall config.
//!
//! Nothing here returns early on the first problem: every finding is appended
//! to [`Findings`], so one edit round fixes the whole file. Unknown keys are
//! warnings, not errors — they catch typos like `vault_iten:` without taking
//! the wall down.

use crate::MAX_VPNS;
use crate::dict::{Dict, DictExt, as_bool, as_int, quote, repr, text, truthy};
use crate::guard::{
    VALID_HOST_KEY_CHECKING, has_ctrl, has_ctrl_or_space, host_key_checking, safe_extra_args, safe_forward, safe_host,
    safe_remote_host, safe_word_value, split_host_port, url_for_msg, valid_http_url,
};
use crate::model::{DisplayCfg, Engine, KeepAliveStrategy, Layout, Mode, VpnKind};
use crate::url::Url;
use serde_json::Value;

/// Same bound the on-screen config applies to the tenant field.
pub const MAX_TENANT_LEN: usize = 100;
/// Sanity bounds: beyond these a value is a typo, not a display.
pub const MAX_PIXELS: i64 = 65_535;
pub const MAX_GRID: i64 = 64;

pub(crate) const TOP_KEYS: &[&str] = &["display", "panels", "tunnel", "vpn", "vpns", "proxy", "security"];
const DISPLAY_KEYS: &[&str] = &["auto", "width", "height", "cols", "rows", "gap", "layout", "fullscreen"];
const LOGIN_ZONE_KEYS: &[&str] = &["x_pct", "y_pct"];
const LOGIN_ZONES_KEYS: &[&str] = &["user", "pass", "submit"];
const PANEL_KEYS: &[&str] = &[
    "id",
    "engine",
    "grid",
    "mode",
    "url",
    "tunnel",
    "path",
    "scheme",
    "vault_item",
    "selectors",
    "login_marker",
    "keepalive",
    "proxy",
    "title",
    "allow_insecure",
    "allow_media",
    "tenant",
    "login_zones",
    "persist",
    "user_agent",
    "allow",
    "block_trackers",
    "unblock",
    "insecure_tls",
];
const SECURITY_KEYS: &[&str] = &["nav_allowlist", "allow", "block_trackers", "sso_allow"];
const PROXY_KEYS: &[&str] = &["enabled", "url", "vault_item", "ignore_hosts"];
const TUNNEL_PANEL_KEYS: &[&str] = &["local_port", "remote_host", "remote_port"];
const KEEPALIVE_KEYS: &[&str] = &["strategy", "intervalSec", "url", "target"];
const TUNNEL_KEYS: &[&str] =
    &["enabled", "jump_host", "identity", "extra_forwards", "host_key_checking", "known_hosts"];
const VPN_KEYS: &[&str] = &[
    "name",
    "default_route",
    "enabled",
    "type",
    "config",
    "config_from_vault",
    "gateway",
    "port",
    "vault_item",
    "trusted_cert",
    "ca_file",
    "realm",
    "set_routes",
    "set_dns",
    "half_internet_routes",
    "persistent",
    "otp_from_vault",
    "ready_probe",
    "extra_args",
    "health_check_interval",
    "health_check_failures",
    "domain",
    "insecure",
    "interface",
    "ead",
    "spa_key",
    "spa_aid",
    "spa_ports",
    "spa_knock_port",
    "split_tunnel",
    "client_cert",
    "client_key",
    "captcha_retries",
    "mac",
    "language",
];
/// Free-text VPN values that end up as their own argv token.
const VPN_ARGV_WORDS: &[&str] = &[
    "realm",
    "domain",
    "trusted_cert",
    "ca_file",
    "client_cert",
    "client_key",
    "mac",
    "language",
    "spa_key",
    "spa_aid",
    "spa_ports",
];
const VALID_PROXY_SCHEMES: &[&str] = &["http", "https", "socks", "socks4", "socks5"];

/// Problems (fatal) and warnings (logged) found so far.
#[derive(Debug, Default)]
pub struct Findings {
    pub errs: Vec<String>,
    pub warns: Vec<String>,
}

impl Findings {
    fn err(&mut self, msg: impl Into<String>) {
        self.errs.push(msg.into());
    }
    fn warn(&mut self, msg: impl Into<String>) {
        self.warns.push(msg.into());
    }
}

fn list_names(names: &[&str]) -> String {
    let mut v: Vec<&str> = names.to_vec();
    v.sort_unstable();
    format!("[{}]", v.iter().map(|n| quote(n)).collect::<Vec<_>>().join(", "))
}

fn unknown_keys(d: &Dict, known: &[&str], place: &str, f: &mut Findings) {
    let mut extra: Vec<&String> = d.keys().filter(|k| !known.contains(&k.as_str())).collect();
    extra.sort_unstable();
    for k in extra {
        f.warn(format!("{place}: unknown key '{k}' (typo?) — it is ignored"));
    }
}

/// `Some(msg)` unless `v` is a real boolean.
fn bool_err(d: &Dict, key: &str, place: &str) -> Option<String> {
    let v = d.get(key)?;
    as_bool(v).is_none().then(|| format!("{place}{key}: must be true or false, got {}", repr(v)))
}

fn is_port(v: &Value) -> bool {
    as_int(v).is_some_and(|p| (1..=65535).contains(&p))
}

fn domain_list(v: &Value, place: &str, f: &mut Findings) {
    let ok = v.as_array().is_some_and(|a| a.iter().all(|x| x.as_str().is_some_and(|s| !s.trim().is_empty())));
    if !ok {
        f.err(format!("{place}: must be a list of non-empty domain strings, got {}", repr(v)));
    }
}

pub(crate) fn security(sec: &Value, f: &mut Findings) {
    let Some(sec) = sec.as_object() else {
        f.err("security: must be a mapping");
        return;
    };
    unknown_keys(sec, SECURITY_KEYS, "security", f);
    for k in ["nav_allowlist", "block_trackers"] {
        if let Some(e) = bool_err(sec, k, "security.") {
            f.err(e);
        }
    }
    for k in ["allow", "sso_allow"] {
        if let Some(v) = sec.get(k) {
            domain_list(v, &format!("security.{k}"), f);
        }
    }
}

pub(crate) fn display(d: &Dict, f: &mut Findings) {
    unknown_keys(d, DISPLAY_KEYS, "display", f);
    for (k, max) in [("width", MAX_PIXELS), ("height", MAX_PIXELS), ("cols", MAX_GRID), ("rows", MAX_GRID)] {
        if let Some(v) = d.get(k) {
            if !as_int(v).is_some_and(|n| (1..=max).contains(&n)) {
                f.err(format!("display.{k}: must be a positive integer (at most {max}), got {}", repr(v)));
            }
        }
    }
    if let Some(v) = d.get("gap") {
        if !as_int(v).is_some_and(|n| (0..=MAX_PIXELS).contains(&n)) {
            f.err(format!("display.gap: must be an integer >= 0, got {}", repr(v)));
        }
    }
    if let Some(v) = d.get("layout") {
        if v.as_str().and_then(Layout::parse).is_none() {
            f.err(format!("display.layout: must be one of {}, got {}", list_names(&Layout::names()), repr(v)));
        }
    }
    if let Some(e) = bool_err(d, "fullscreen", "display.") {
        f.err(e);
    }
}

fn login_zones(lz: &Value, place: &str, f: &mut Findings) {
    let Some(lz) = lz.as_object() else {
        f.err(format!("{place}: login_zones must be a mapping with optional 'user', 'pass', 'submit' entries"));
        return;
    };
    let mut extra: Vec<&str> = lz.keys().map(String::as_str).filter(|k| !LOGIN_ZONES_KEYS.contains(k)).collect();
    if !extra.is_empty() {
        extra.sort_unstable();
        f.err(format!(
            "{place}: unknown login_zones key(s) {}; valid: {}",
            list_names(&extra),
            list_names(LOGIN_ZONES_KEYS)
        ));
    }
    for (k, z) in lz {
        let Some(z) = z.as_object() else {
            f.err(format!("{place}: login_zones.{k} must be a mapping with x_pct + y_pct, got {}", repr(z)));
            continue;
        };
        unknown_keys(z, LOGIN_ZONE_KEYS, &format!("{place}.login_zones.{k}"), f);
        let missing: Vec<&str> = LOGIN_ZONE_KEYS.iter().copied().filter(|a| !z.contains_key(*a)).collect();
        if !missing.is_empty() {
            f.err(format!("{place}: login_zones.{k} missing {}", list_names(&missing)));
            continue;
        }
        for axis in LOGIN_ZONE_KEYS {
            let v = &z[*axis];
            let ok = matches!(v, Value::Number(n) if n.as_f64().is_some_and(|x| (0.0..=1.0).contains(&x)));
            if !ok {
                f.err(format!("{place}: login_zones.{k}.{axis} must be a 0.0..1.0 ratio, got {}", repr(v)));
            }
        }
    }
}

fn is_panel_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn panel(i: usize, raw: &Value, disp: &DisplayCfg, f: &mut Findings) {
    let n = i + 1;
    let Some(p) = raw.as_object() else {
        f.err(format!("panel #{n}: must be a mapping"));
        return;
    };
    let pid = match p.get("id") {
        Some(v) if truthy(v) => text(v),
        _ => format!("#{n}"),
    };
    let place = format!("panel {pid}");
    unknown_keys(p, PANEL_KEYS, &place, f);

    // A panel id is substituted verbatim into the window manager's rc.xml (as
    // a window class / title), so it must not be able to break out of an XML
    // attribute.
    match p.get("id") {
        Some(v) if truthy(v) => {
            if !is_panel_id(&text(v)) {
                f.err(format!(
                    "panel #{n}: id {} must match [A-Za-z0-9_-]+ (it is substituted into the WM rc.xml: no \
                     spaces/markup)",
                    repr(v)
                ));
            }
        }
        _ => f.err(format!("panel #{n}: missing required key 'id'")),
    }

    if let Some(v) = p.get("engine") {
        if v.as_str().and_then(Engine::parse).is_none() {
            f.err(format!("{place}: engine must be one of {}, got {}", list_names(&Engine::names()), repr(v)));
        }
    }

    if let Some(v) = p.get("grid") {
        match grid_cell(v) {
            Some((col, row)) => {
                if col >= i64::from(disp.cols) || row >= i64::from(disp.rows) || col < 0 || row < 0 {
                    f.err(format!(
                        "{place}: grid [{col}, {row}] is outside the {}x{} grid (0-based)",
                        disp.cols, disp.rows
                    ));
                }
            }
            None => f.err(format!("{place}: grid must be [col, row] integers, got {}", repr(v))),
        }
    }

    match p.get("mode").map(|v| v.as_str().and_then(Mode::parse).ok_or(v)) {
        Some(Err(v)) => {
            f.err(format!("{place}: mode must be one of {}, got {}", list_names(&Mode::names()), repr(v)));
        }
        None | Some(Ok(Mode::Direct)) => panel_direct(p, &place, f),
        Some(Ok(Mode::Tunnel)) => panel_tunnel(p, &place, f),
    }

    if let Some(v) = p.get("scheme") {
        if !matches!(v.as_str(), Some("http" | "https")) {
            f.err(format!("{place}: scheme must be http or https, got {}", repr(v)));
        }
    }

    let prefix = format!("{place}: ");
    for k in ["proxy", "allow_insecure", "allow_media", "persist", "block_trackers", "insecure_tls"] {
        if let Some(e) = bool_err(p, k, &prefix) {
            f.err(e);
        }
    }
    if let (Some(a), Some(b)) = (p.get("insecure_tls").and_then(as_bool), p.get("allow_insecure").and_then(as_bool)) {
        if a != b {
            f.err(format!(
                "{place}: insecure_tls and allow_insecure both set to conflicting values (they are aliases — set \
                 only one)"
            ));
        }
    }

    match p.get("tenant") {
        None | Some(Value::Null) => {}
        Some(Value::String(t)) if !has_ctrl(t) && t.trim().chars().count() <= MAX_TENANT_LEN => {}
        Some(v) => f.err(format!(
            "{place}: tenant must be a single-line string of at most {MAX_TENANT_LEN} characters, got {}",
            repr(v)
        )),
    }

    if let Some(lz) = p.get("login_zones").filter(|v| !v.is_null()) {
        login_zones(lz, &place, f);
    }
    for k in ["allow", "unblock"] {
        if let Some(v) = p.get(k) {
            domain_list(v, &format!("{place}: {k}"), f);
        }
    }
    match p.get("user_agent") {
        None | Some(Value::Null) => {}
        // A control character here would be a header-injection primitive.
        Some(Value::String(ua)) if !ua.trim().is_empty() && !has_ctrl(ua) => {}
        Some(v) => {
            f.err(format!("{place}: user_agent must be a non-empty single-line string (or omit it), got {}", repr(v)))
        }
    }

    // Auto-login is optional: a panel with a vault_item logs itself in (and
    // then needs selectors); one without is display-only.
    let sel = p.get("selectors").filter(|v| !v.is_null());
    if p.truthy("vault_item") {
        match sel.and_then(Value::as_object) {
            None => f.err(format!(
                "{place}: has a vault_item but no 'selectors:' mapping (user, pass) needed to inject the login"
            )),
            Some(sel) => {
                for (k, human) in [("user", "username"), ("pass", "password")] {
                    if !sel.truthy(k) {
                        f.err(format!(
                            "{place}: selectors.{k} is required for auto-login (CSS selector of the {human} field)"
                        ));
                    }
                }
                if !p.truthy("login_marker") && !sel.truthy("pass") {
                    f.err(format!("{place}: needs a login_marker (or at least selectors.pass)"));
                }
            }
        }
    } else if sel.is_some_and(|s| !s.is_object()) {
        f.err(format!("{place}: selectors must be a mapping (or omit it for a display-only panel)"));
    }

    match p.get("keepalive").filter(|v| truthy(v)) {
        None => {}
        Some(Value::Object(ka)) => keepalive(ka, &place, f),
        Some(_) => f.err(format!("{place}: keepalive must be a mapping")),
    }
}

/// `[col, row]` as integers, if that is what `v` is.
pub(crate) fn grid_cell(v: &Value) -> Option<(i64, i64)> {
    match v.as_array()?.as_slice() {
        [c, r] => Some((as_int(c)?, as_int(r)?)),
        _ => None,
    }
}

fn panel_direct(p: &Dict, place: &str, f: &mut Findings) {
    let url = p.text("url");
    if url.is_empty() {
        // Allowed: an unconfigured tile, set later from the on-screen config.
        f.warn(format!(
            "{place}: no url yet — shows a 'not configured' card until you set it (on-screen config, or edit \
             panels.yaml)"
        ));
    } else if !valid_http_url(&url, false) {
        f.err(format!(
            "{place}: url must be a valid http:// or https:// URL with a host and no embedded credentials, got {}",
            url_for_msg(&url)
        ));
    }
}

fn panel_tunnel(p: &Dict, place: &str, f: &mut Findings) {
    let Some(t) = p.dict("tunnel") else {
        f.err(format!("{place}: mode 'tunnel' requires a 'tunnel:' mapping (local_port, remote_host, remote_port)"));
        return;
    };
    unknown_keys(t, TUNNEL_PANEL_KEYS, &format!("{place}.tunnel"), f);
    let lp = t.get("local_port").unwrap_or(&Value::Null);
    if !is_port(lp) {
        f.err(format!("{place}: tunnel.local_port must be a port number (1-65535), got {}", repr(lp)));
    }
    if t.truthy("remote_host") {
        if let Err(e) = safe_remote_host(&t.text("remote_host")) {
            f.err(format!("{place}: {e}"));
        }
    } else {
        f.err(format!("{place}: tunnel.remote_host is required"));
    }
    match t.get("remote_port") {
        Some(rp) if !is_port(rp) => {
            f.err(format!("{place}: tunnel.remote_port must be a port number (1-65535), got {}", repr(rp)));
        }
        Some(_) => {}
        None => f.warn(format!("{place}: tunnel.remote_port is not set (the tunnel will refuse to start)")),
    }
    // `path` is concatenated straight into the effective URL
    // (scheme://127.0.0.1:port + path). Without a leading slash a value like
    // "@evil.com/dash" turns 127.0.0.1:port into userinfo and redirects the
    // panel — and any injected credentials — to an attacker's host.
    if let Some(path) = p.get("path") {
        let ok = path.as_str().is_some_and(|s| s.starts_with('/') && !has_ctrl_or_space(s));
        if !ok {
            f.err(format!(
                "{place}: tunnel path must be a string starting with '/' (no whitespace), got {}",
                repr(path)
            ));
        }
    }
}

fn keepalive(ka: &Dict, place: &str, f: &mut Findings) {
    unknown_keys(ka, KEEPALIVE_KEYS, &format!("{place}.keepalive"), f);
    let strategy = match ka.get("strategy") {
        None => Some(KeepAliveStrategy::None),
        Some(v) => v.as_str().and_then(KeepAliveStrategy::parse),
    };
    if strategy.is_none() {
        f.err(format!(
            "{place}: keepalive.strategy must be one of {}, got {}",
            list_names(&KeepAliveStrategy::names()),
            repr(&ka["strategy"])
        ));
    }
    if let Some(v) = ka.get("intervalSec") {
        if !as_int(v).is_some_and(|n| (1..=i64::from(u32::MAX)).contains(&n)) {
            f.err(format!("{place}: keepalive.intervalSec must be a positive integer"));
        }
    }
    if strategy == Some(KeepAliveStrategy::Xhr) && !ka.truthy("url") {
        f.warn(format!("{place}: keepalive strategy 'xhr' without a 'url' does nothing"));
    }
    if strategy == Some(KeepAliveStrategy::Click) && !ka.truthy("target") {
        f.warn(format!("{place}: keepalive strategy 'click' without a 'target' does nothing"));
    }
}

/// Checks that span panels and sections: unique ids, cells and tunnel ports,
/// layout/engine compatibility, and the `tunnel:` section itself.
pub(crate) fn cross(raw: &Dict, layout: Layout, panels: &[Value], f: &mut Findings) {
    let dicts: Vec<&Dict> = panels.iter().filter_map(Value::as_object).collect();

    let ids: Vec<String> = dicts.iter().filter(|p| p.truthy("id")).map(|p| p.text("id")).collect();
    let mut dups: Vec<&String> = ids.iter().filter(|i| ids.iter().filter(|j| j == i).count() > 1).collect();
    dups.sort_unstable();
    dups.dedup();
    for dup in dups {
        f.err(format!("panel id '{dup}' is used more than once — ids must be unique"));
    }

    let mut cells: Vec<((i64, i64), Vec<String>)> = Vec::new();
    for p in &dicts {
        let Some(cell) = p.get("grid").and_then(grid_cell) else {
            continue;
        };
        let who = if p.truthy("id") { p.text("id") } else { "?".to_string() };
        match cells.iter_mut().find(|(c, _)| *c == cell) {
            Some((_, list)) => list.push(who),
            None => cells.push((cell, vec![who])),
        }
    }
    cells.sort_by_key(|(c, _)| *c);
    for ((col, row), who) in &cells {
        if who.len() > 1 {
            f.err(format!("panels {} share grid cell [{col}, {row}] — each panel needs its own cell", who.join(", ")));
        }
    }

    let ports: Vec<i64> =
        dicts.iter().filter_map(|p| p.dict("tunnel")).filter_map(|t| t.get("local_port").and_then(as_int)).collect();
    let mut dup_ports: Vec<i64> =
        ports.iter().copied().filter(|x| ports.iter().filter(|y| *y == x).count() > 1).collect();
    dup_ports.sort_unstable();
    dup_ports.dedup();
    for dup in dup_ports {
        f.err(format!("tunnel local_port {dup} is used by more than one panel"));
    }

    if layout == Layout::Single {
        let chromium: Vec<String> = dicts
            .iter()
            .filter(|p| p.get("engine").and_then(Value::as_str) == Some("chromium"))
            .map(|p| if p.truthy("id") { p.text("id") } else { "?".into() })
            .collect();
        if !chromium.is_empty() {
            f.err(format!(
                "display.layout 'single' cannot host chromium panels ({}) — Chromium runs in its own OS window. Use \
                 engine: webkit for them, or layout: windows",
                chromium.join(", ")
            ));
        }
    }

    let empty = Dict::new();
    let tun = match raw.get("tunnel") {
        Some(v) if truthy(v) => match v.as_object() {
            Some(t) => t,
            None => {
                f.err("tunnel: must be a mapping");
                return;
            }
        },
        _ => &empty,
    };
    unknown_keys(tun, TUNNEL_KEYS, "tunnel", f);
    let any_tunnel = dicts.iter().any(|p| p.get("mode").and_then(Value::as_str) == Some("tunnel"));
    let enabled = tun.flag("enabled", true);
    if any_tunnel && enabled && !tun.truthy("jump_host") {
        f.err("tunnel: panels use mode 'tunnel' but tunnel.jump_host is not set");
    }
    if any_tunnel && !enabled {
        f.warn("tunnel: panels use mode 'tunnel' but tunnel.enabled is false — their local ports will never come up");
    }
    if enabled {
        tunnel_argv(tun, f);
    }
}

/// Everything the tunnel argv builder emits. A bad `extra_forwards` entry or
/// host-key setting is a warning, not an error: the builder refuses it (or
/// fails closed), so the tunnel stays safe and the wall itself still comes up.
fn tunnel_argv(tun: &Dict, f: &mut Findings) {
    if tun.truthy("jump_host") {
        if let Err(e) = safe_host(&tun.text("jump_host"), "tunnel.jump_host") {
            f.err(e.0);
        }
    }
    for k in ["identity", "known_hosts"] {
        if let Err(e) = safe_word_value(tun.get(k), &format!("tunnel.{k}")) {
            f.err(e.0);
        }
    }
    match tun.get("extra_forwards").filter(|v| truthy(v)) {
        None => {}
        Some(Value::Array(forwards)) => {
            for entry in forwards {
                if let Err(e) = safe_forward(&text(entry)) {
                    f.warn(format!("tunnel: {e} (the tunnel will refuse to start)"));
                }
            }
        }
        Some(other) => f.err(format!("tunnel.extra_forwards: must be a list, got {}", repr(other))),
    }

    let effective = host_key_checking(tun);
    match tun.get("host_key_checking") {
        Some(raw) if !raw.is_null() && text(raw).trim().to_ascii_lowercase() != effective => {
            f.warn(format!(
                "tunnel.host_key_checking: {} is not one of {}; using strict 'yes'",
                repr(raw),
                list_names(&VALID_HOST_KEY_CHECKING)
            ));
        }
        _ if effective != "yes" && tun.text("known_hosts").is_empty() => {
            f.warn(format!(
                "tunnel.host_key_checking: '{effective}' needs an explicit tunnel.known_hosts (the tunnel will \
                 refuse to start)"
            ));
        }
        _ => {}
    }
}

pub(crate) fn proxy(proxy: &Value, f: &mut Findings) {
    let Some(proxy) = proxy.as_object() else {
        f.err("proxy: must be a mapping");
        return;
    };
    unknown_keys(proxy, PROXY_KEYS, "proxy", f);
    if !proxy.truthy("enabled") {
        return;
    }
    let url = proxy.text("url");
    if url.is_empty() {
        f.err("proxy: enabled but 'url' is not set (want scheme://host:port)");
    } else if has_ctrl_or_space(&url) {
        f.err("proxy.url: must not contain whitespace or control characters");
    } else {
        let parts = Url::split(&url).ok();
        let scheme = parts.as_ref().map(|u| u.scheme.as_str()).unwrap_or("");
        if !VALID_PROXY_SCHEMES.contains(&scheme) {
            f.err(format!(
                "proxy.url: scheme must be one of {}, got {}",
                list_names(VALID_PROXY_SCHEMES),
                url_for_msg(&url)
            ));
        } else if parts.as_ref().is_none_or(|u| u.host.is_none()) {
            f.err(format!("proxy.url: missing host, got {}", url_for_msg(&url)));
        } else if parts.as_ref().is_none_or(|u| u.port.is_none()) {
            f.err(format!("proxy.url: missing port — want scheme://host:port, got {}", url_for_msg(&url)));
        }
        if parts.as_ref().is_some_and(|u| u.userinfo.is_some()) || (parts.is_none() && url.contains('@')) {
            f.err(
                "proxy.url: must not embed credentials (user:pass@...). Put them in a vault login and set \
                 proxy.vault_item — they are then injected in memory and never stored",
            );
        }
        if scheme.starts_with("socks") && proxy.truthy("vault_item") {
            f.warn(
                "proxy: SOCKS with vault_item — browsers have little/no SOCKS auth support; an authenticating proxy \
                 normally needs to be http://",
            );
        }
    }
    if let Some(ih) = proxy.get("ignore_hosts") {
        if !ih.as_array().is_some_and(|a| a.iter().all(Value::is_string)) {
            f.err("proxy.ignore_hosts: must be a list of hostnames/patterns");
        }
    }
}

/// The `vpn:` / `vpns:` sections resolved to one list. `Err` carries a value
/// that is not a list at all, for [`vpns`] to report.
///
/// * `vpns:` present -> used verbatim (a stray `vpn:` is ignored, with a
///   warning, so the list form always wins);
/// * else `vpn:` present -> wrapped as a one-entry list (every legacy
///   single-VPN config keeps working unchanged);
/// * else -> empty.
///
/// Each mapping entry gets a stable non-empty `name`: an explicit one is kept,
/// otherwise the first becomes `vpn` and the rest `vpn2`..`vpnN`.
pub(crate) fn normalize_vpns(raw: &Dict, f: &mut Findings) -> Result<Vec<Value>, Value> {
    let set = |k: &str| raw.get(k).filter(|v| !v.is_null());
    let mut entries: Vec<Value> = match (set("vpns"), set("vpn")) {
        (Some(list), stray) => {
            if stray.is_some() {
                f.warn(
                    "config: both 'vpn:' and 'vpns:' are set — using 'vpns:' (the list) and ignoring the stray \
                     'vpn:' block",
                );
            }
            match list.as_array() {
                Some(a) => a.clone(),
                None => return Err(list.clone()),
            }
        }
        (None, Some(single)) => vec![single.clone()],
        (None, None) => return Ok(Vec::new()),
    };
    for (i, e) in entries.iter_mut().enumerate() {
        if let Some(d) = e.as_object_mut() {
            if d.text("name").is_empty() {
                let name = if i == 0 { "vpn".to_string() } else { format!("vpn{}", i + 1) };
                d.insert("name".into(), Value::String(name));
            }
        }
    }
    Ok(entries)
}

/// A VPN `name` is the identity key used everywhere downstream (supervisor
/// key, log tag, status row, unit instance), so it must stay a clean token.
pub fn is_vpn_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Validate the whole VPN list: the cap, unique names, at most one
/// default-route owner, plus every per-entry problem. `legacy` means the list
/// came from a single `vpn:` block, so messages say `vpn.port`, not
/// `vpns[0] 'vpn'.port`.
pub(crate) fn vpns(list: &Result<Vec<Value>, Value>, legacy: bool, f: &mut Findings) {
    let Ok(list) = list else {
        f.err("vpns: must be a list of VPN mappings");
        return;
    };
    if list.len() > MAX_VPNS {
        f.err(format!("vpns: at most {MAX_VPNS} VPNs supported; got {} — remove some", list.len()));
    }
    let mut seen: Vec<String> = Vec::new();
    let mut dup_names: Vec<String> = Vec::new();
    let mut route_owners: Vec<String> = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let mut label = if legacy { "vpn".to_string() } else { format!("vpns[{i}]") };
        if let Some(d) = entry.as_object() {
            let name = d.text("name");
            if !name.is_empty() && !legacy {
                label = format!("vpns[{i}] {}", quote(&name));
            }
            if name.is_empty() {
                f.err(format!(
                    "{label}: 'name' is required and must be non-empty (it is the identity key used for the \
                     supervisor, status pill and logs)"
                ));
            } else if !is_vpn_name(&name) {
                f.err(format!(
                    "{label}: 'name' must start alphanumeric and contain only letters/digits/'.'/'_'/'-' (no \
                     spaces or slashes), got {}",
                    quote(&name)
                ));
            } else {
                let key = name.to_lowercase();
                if seen.contains(&key) {
                    if !dup_names.contains(&name) {
                        dup_names.push(name.clone());
                    }
                } else {
                    seen.push(key);
                }
            }
            if d.truthy("default_route") {
                route_owners.push(if name.is_empty() { label.clone() } else { name });
            }
        }
        vpn(entry, &label, f);
    }
    if !dup_names.is_empty() {
        f.err(format!(
            "vpns: duplicate VPN name(s) — each must be unique: {}",
            dup_names.iter().map(|n| quote(n)).collect::<Vec<_>>().join(", ")
        ));
    }
    if route_owners.len() > 1 {
        f.err(format!(
            "vpns: at most one VPN may set 'default_route: true' (the full-tunnel owner); these claim it: {}",
            route_owners.join(", ")
        ));
    }
}

/// A cert pin openfortivpn accepts: a SHA-256 (64 hex) or SHA-1 (40 hex)
/// digest, case-insensitive.
pub fn is_cert_pin(cert: &str) -> bool {
    matches!(cert.len(), 40 | 64) && cert.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_ipv4(h: &str) -> bool {
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            (1..=3).contains(&p.len())
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

fn is_hostname(h: &str) -> bool {
    let h = h.strip_suffix('.').unwrap_or(h);
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn is_ipv6(h: &str) -> bool {
    let (addr, zone) = match h.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (h, None),
    };
    addr.matches(':').count() >= 2
        && addr.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
        && zone.is_none_or(|z| {
            !z.is_empty() && z.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// True if `host` is a plausible gateway hostname or IP address. This is an
/// early, clear error — not a security boundary (the value is only ever passed
/// as a single argv token, guarded separately).
pub fn is_gateway_host(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() || h.chars().any(char::is_whitespace) {
        return false;
    }
    let h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(h);
    is_ipv4(h) || is_hostname(h) || is_ipv6(h)
}

fn probe_ok(probe: &str) -> bool {
    match probe.rsplit_once(':') {
        Some((host, port)) => {
            !host.is_empty()
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
        }
        None => false,
    }
}

/// Check `vpn.gateway` with the same parser the argv builders use, so load
/// accepts exactly what connect can format. `config_from_vault` may supply the
/// gateway from the vault item's notes, in which case it is only checked at
/// connect time.
fn gateway(vpn: &Dict, label: &str, kind: VpnKind, f: &mut Findings) {
    if !vpn.truthy("gateway") {
        if !vpn.truthy("config_from_vault") {
            f.err(format!(
                "{label}: type '{kind}' but 'gateway' is not set (or set config_from_vault: true to load it from \
                 the vault item)"
            ));
        }
        return;
    }
    let gw = &vpn["gateway"];
    let host = split_host_port(&text(gw), &Value::from(443)).and_then(|(h, _)| safe_host(&h, "gateway host"));
    match host {
        Err(e) => {
            f.err(format!("{label}.gateway: not a valid hostname or IP address ({e}), got {}", repr(gw)));
        }
        Ok(h) if !is_gateway_host(&h) => {
            f.err(format!("{label}.gateway: not a valid hostname or IP address, got {}", repr(gw)));
        }
        Ok(_) => {}
    }
}

fn vpn_port(vpn: &Dict, label: &str, f: &mut Findings) {
    if let Some(p) = vpn.get("port") {
        if !is_port(p) {
            f.err(format!("{label}.port: must be a port number (1-65535), got {}", repr(p)));
        }
    }
}

/// Validate one VPN entry; `label` prefixes every message so list errors point
/// at the right row.
fn vpn(entry: &Value, label: &str, f: &mut Findings) {
    let Some(vpn) = entry.as_object() else {
        f.err(format!("{label}: must be a mapping"));
        return;
    };
    unknown_keys(vpn, VPN_KEYS, label, f);
    let dotted = format!("{label}.");
    if let Some(e) = bool_err(vpn, "default_route", &dotted) {
        f.err(e);
    }
    if !vpn.truthy("enabled") {
        return;
    }

    let kind = match vpn.get("type").filter(|v| truthy(v)) {
        None => VpnKind::Fortinet,
        Some(v) => VpnKind::parse(&text(v).to_ascii_lowercase()).unwrap_or_else(|| {
            f.err(format!("{label}.type: must be one of {}, got {}", list_names(&VpnKind::names()), repr(v)));
            VpnKind::Fortinet
        }),
    };

    for k in ["persistent", "health_check_interval", "health_check_failures"] {
        if let Some(v) = vpn.get(k) {
            if !as_int(v).is_some_and(|n| n >= 0) {
                f.err(format!("{label}.{k}: must be an integer >= 0, got {}", repr(v)));
            }
        }
    }
    let probe = vpn.text("ready_probe");
    if !probe.is_empty() && !probe_ok(&probe) {
        f.err(format!("{label}.ready_probe: want 'host:port', got {}", quote(&probe)));
    }
    if vpn.truthy("health_check_interval") && probe.is_empty() && kind != VpnKind::Wireguard {
        f.err(format!(
            "{label}.health_check_interval is set but {label}.ready_probe is empty — the health check needs a \
             host:port to probe"
        ));
    }
    // Report at load what the argv builders would otherwise only refuse at
    // connect time, when the failure is just a supervisor log line.
    for k in VPN_ARGV_WORDS {
        if let Err(e) = safe_word_value(vpn.get(*k), &format!("{label}.{k}")) {
            f.err(e.0);
        }
    }
    if let Err(e) = safe_extra_args(vpn.get("extra_args")) {
        f.err(format!("{label}: {e}"));
    }

    let from_vault = vpn.truthy("config_from_vault");
    let has_item = vpn.truthy("vault_item");
    match kind {
        VpnKind::Fortinet => {
            gateway(vpn, label, kind, f);
            if !has_item {
                f.err(format!(
                    "{label}: type 'fortinet' but 'vault_item' is not set (the vault login holding the FortiGate \
                     credentials)"
                ));
            }
            vpn_port(vpn, label, f);
            let cert = vpn.text("trusted_cert");
            if !cert.is_empty() && !is_cert_pin(&cert) {
                f.err(format!(
                    "{label}.trusted_cert: expected a sha256 (64-char) or sha1 (40-char) hex digest, got {} chars",
                    cert.chars().count()
                ));
            }
            if cert.is_empty() && !vpn.truthy("ca_file") {
                f.warn(format!(
                    "{label}: no trusted_cert / ca_file pinned — the connection relies on system CAs; if the \
                     gateway uses a self-signed cert the VPN will refuse to connect (see docs/CONFIGURATION.md to \
                     pin it)"
                ));
            }
        }
        VpnKind::Openvpn => {
            if from_vault && !has_item {
                f.err(format!(
                    "{label}: openvpn with config_from_vault needs 'vault_item' (its Notes hold the .ovpn profile)"
                ));
            } else if !from_vault && !vpn.truthy("config") {
                f.err(format!(
                    "{label}: type 'openvpn' requires 'config' (path to the .ovpn profile), or config_from_vault: \
                     true"
                ));
            }
            if !from_vault && !has_item {
                f.warn(format!(
                    "{label}: openvpn with no vault_item — assuming certificate-only auth (the .ovpn must carry \
                     the client cert/key). Set vault_item for a username/password login."
                ));
            }
        }
        VpnKind::Wireguard => {
            if from_vault && !has_item {
                f.err(format!(
                    "{label}: wireguard with config_from_vault needs 'vault_item' (its Notes hold the .conf — keys \
                     included)"
                ));
            } else if !from_vault && !vpn.truthy("config") {
                f.err(format!(
                    "{label}: type 'wireguard' requires 'config' (a .conf path or an interface name under \
                     /etc/wireguard), or config_from_vault: true"
                ));
            }
            if has_item && !from_vault {
                f.warn(format!(
                    "{label}: wireguard ignores vault_item unless config_from_vault is set — otherwise its keys \
                     live in the .conf file (0600)"
                ));
            }
        }
        VpnKind::Inode => inode(vpn, label, f),
    }
}

fn inode(vpn: &Dict, label: &str, f: &mut Findings) {
    let dotted = format!("{label}.");
    gateway(vpn, label, VpnKind::Inode, f);
    if !vpn.truthy("vault_item") {
        f.err(format!(
            "{label}: type 'inode' but 'vault_item' is not set (the vault login holding the SSL-VPN username + \
             password)"
        ));
    }
    vpn_port(vpn, label, f);
    for k in ["insecure", "ead", "split_tunnel"] {
        if let Some(e) = bool_err(vpn, k, &dotted) {
            f.err(e);
        }
    }
    let cert = vpn.text("trusted_cert");
    let pinned = !cert.is_empty();
    let insecure = vpn.truthy("insecure");
    if pinned && !is_cert_pin(&cert.replace([':', ' '], "")) {
        f.warn(format!(
            "{label}.trusted_cert: does not look like a sha256/sha1 cert pin (expected 64- or 40-hex digits, \
             ':'-separated ok) — it will only fail at connect time if wrong, got {}",
            quote(&cert)
        ));
    }
    if !pinned && !insecure {
        f.warn(format!(
            "{label}: iNode with no trusted_cert pin and insecure not set — a self-signed gateway will fail TLS. \
             Pin its sha256 in {label}.trusted_cert (the AA:BB:.. --pin-sha256 form), or set insecure: true \
             (trusted LAN only)"
        ));
    }
    if let Some(v) = vpn.get("captcha_retries") {
        if !as_int(v).is_some_and(|n| n >= 0) {
            f.err(format!("{label}.captcha_retries: must be an integer >= 0, got {}", repr(v)));
        }
    }
    if let Some(v) = vpn.get("spa_knock_port") {
        if !is_port(v) {
            f.err(format!("{label}.spa_knock_port: must be a port (1-65535), got {}", repr(v)));
        }
    }
    if vpn.truthy("spa_key") && !pinned && !insecure {
        f.warn(format!(
            "{label}: SDP/SPA without cert pin or insecure — the knock may open the port, but TLS verification \
             will still fail on a self-signed gateway. Add trusted_cert or set insecure: true."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_host_shapes() {
        for ok in ["vpn.example.com", "gw", "10.0.0.1", "fd00::1", "[fd00::1]", "fe80::1%eth0", "host.example."] {
            assert!(is_gateway_host(ok), "{ok}");
        }
        for bad in ["", "a b", "-gw", "gw-", "exa$mple.com", "a..b", "1::2::zz", "http://x", "a;b"] {
            assert!(!is_gateway_host(bad), "{bad}");
        }
    }

    #[test]
    fn cert_pins() {
        assert!(is_cert_pin(&"a".repeat(64)));
        assert!(is_cert_pin(&"A1".repeat(20)));
        assert!(!is_cert_pin(&"a".repeat(63)));
        assert!(!is_cert_pin(&"g".repeat(64)));
    }

    #[test]
    fn probes() {
        assert!(probe_ok("10.50.0.5:443"));
        assert!(probe_ok("[fd00::1]:443"));
        for bad in ["host", "host:", ":443", "host:0", "host:70000", "host:4x"] {
            assert!(!probe_ok(bad), "{bad}");
        }
    }

    #[test]
    fn vpn_names() {
        assert!(is_vpn_name("site-a.1"));
        for bad in ["", "-a", "a b", "a/b", ".a", "a\n"] {
            assert!(!is_vpn_name(bad), "{bad:?}");
        }
    }
}
