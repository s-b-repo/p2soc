//! Laying `overrides.json` over a loaded config at boot.
//!
//! The overrides file sits in the wall user's state directory, outside the
//! vault and outside config validation — and its content ends up in the
//! running config, in the vault config note (write-back) and from there in the
//! VPN and tunnel command lines. So it is treated as hostile input:
//!
//! * every field is type-checked, length-bounded and re-validated with the
//!   same guards the loader uses, and a bad field is skipped, not coerced;
//! * VPN and tunnel entries may only set keys the settings form can produce;
//! * the merged config is finally run back through the loader
//!   ([`apply_overrides`]); if it does not validate, the sections are applied
//!   one at a time and the offending ones dropped.
//!
//! The result is therefore always a config the loader would have accepted.

use crate::limits::{
    MAX_FORM_GRID, MAX_FORM_PIXELS, MAX_HOST_LEN, MAX_LIST_ITEMS, MAX_MARKER_LEN, MAX_PATH_LEN, MAX_SELECTOR_LEN,
    MAX_TITLE_LEN, MAX_URL_LEN, MAX_VAULT_ITEM_LEN, MAX_VPN_CONFIG_LEN, MIN_FORM_PIXELS,
};
use crate::overrides::{
    KEY_ADDED_PANELS, KEY_DISPLAY, KEY_PROXY, KEY_REMOVED_PANELS, KEY_TUNNEL, KEY_VPN, KEY_VPNS, KEY_VPNS_REMOVED,
    Overrides, is_reserved,
};
use crate::sanitize::{
    clean_str, clean_str_or_null, config_problems, grid_cell, in_grid, is_panel_id, loader_problems,
};
use crate::session::blank_panel;
use serde_json::{Value, json};
use soc_core::dict::as_int;
use soc_core::guard::{
    VALID_HOST_KEY_CHECKING, has_ctrl, has_ctrl_or_space, safe_forward, safe_host, safe_word, valid_http_url,
};
use soc_core::validate::{MAX_PIXELS, MAX_TENANT_LEN, is_vpn_name};
use soc_core::{
    Config, Dict, DictExt, DisplayCfg, Engine, KeepAliveStrategy, Layout, MAX_VPNS, Mode, Panel, ProxyCfg,
    compute_geometry,
};

/// Every key a VPN entry may carry — the loader's list. An override entry
/// can set these and nothing else.
pub(crate) const VPN_KEYS: &[&str] = &[
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

/// A config with its overrides applied.
#[derive(Debug, Clone, PartialEq)]
pub struct Merged {
    pub config: Config,
    /// What was ignored and why (for the log). Never contains a secret.
    pub warnings: Vec<String>,
    /// The merge as a whole did not validate, so sections were applied one by
    /// one and at least one was dropped.
    pub degraded: bool,
}

type Warnings = Vec<String>;

/// Merge a saved form section over a loaded one, keeping advanced keys the
/// form does not show. A `null` value removes the key.
pub fn merge_form(target: &mut Dict, saved: &Dict) {
    for (key, value) in saved {
        if value.is_null() {
            target.shift_remove(key);
        } else {
            target.insert(key.clone(), value.clone());
        }
    }
}

// ---- display ---------------------------------------------------------------

/// Apply a saved display override. Out-of-range values are ignored, so a bad
/// override cannot wreck the layout.
pub fn apply_display_override(display: &mut DisplayCfg, overrides: &Overrides) {
    let Some(o) = overrides.get(KEY_DISPLAY).and_then(Value::as_object) else {
        return;
    };
    if let Some(layout) = o.get("layout").and_then(Value::as_str).and_then(Layout::parse) {
        display.layout = layout;
    }
    let int_in = |key: &str, lo: i64, hi: i64| o.get(key).and_then(as_int).filter(|n| (lo..=hi).contains(n));
    if let Some(gap) = int_in("gap", 0, MAX_PIXELS).and_then(|n| i32::try_from(n).ok()) {
        display.gap = gap;
    }
    if let Some(Value::Bool(auto)) = o.get("auto") {
        display.auto = *auto;
    }
    if let Some(Value::Bool(fullscreen)) = o.get("fullscreen") {
        display.fullscreen = *fullscreen;
    }
    if let Some(cols) = int_in("cols", 1, MAX_FORM_GRID).and_then(|n| u32::try_from(n).ok()) {
        display.cols = cols;
    }
    if let Some(rows) = int_in("rows", 1, MAX_FORM_GRID).and_then(|n| u32::try_from(n).ok()) {
        display.rows = rows;
    }
    if let Some(width) = int_in("width", MIN_FORM_PIXELS, MAX_FORM_PIXELS).and_then(|n| i32::try_from(n).ok()) {
        display.width = width;
    }
    if let Some(height) = int_in("height", MIN_FORM_PIXELS, MAX_FORM_PIXELS).and_then(|n| i32::try_from(n).ok()) {
        display.height = height;
    }
}

// ---- VPNs ------------------------------------------------------------------

/// Reduce one saved VPN entry to what an override may legitimately say.
///
/// `extra_args` is pass-through argv for a root-run VPN client and the form
/// cannot edit it, so it is only accepted when it repeats, verbatim, the
/// `extra_args` of a VPN in the source config (which is what a rename at the
/// glass saves).
fn clean_vpn_entry(entry: &Dict, source_args: &[Value], warnings: &mut Warnings) -> Dict {
    let name = entry.text("name");
    let mut out = Dict::new();
    for (key, value) in entry {
        let keep = if !VPN_KEYS.contains(&key.as_str()) {
            false
        } else if key == "extra_args" {
            value.is_null() || source_args.contains(value)
        } else {
            match value {
                Value::Null | Value::Bool(_) | Value::Number(_) => true,
                Value::String(s) => !has_ctrl(s) && s.chars().count() <= MAX_VPN_CONFIG_LEN,
                Value::Array(_) | Value::Object(_) => false,
            }
        };
        if keep {
            out.insert(key.clone(), value.clone());
        } else {
            warnings.push(format!("overrides: VPN '{name}': ignoring '{key}' (not something the settings form saves)"));
        }
    }
    out
}

fn string_list(v: Option<&Value>) -> Vec<&str> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default() // audit-allow: default is the intended fallback
}

/// The multi-VPN boot merge. Each `_vpns` entry is merged by name into the
/// loaded VPN (advanced fields the form does not show are kept); unmatched
/// entries are appended; VPNs removed or renamed at the glass
/// (`_vpns_removed`) are dropped first, or a by-name merge would bring them
/// back from the source config.
pub fn apply_vpns_override(vpns: &mut Vec<Dict>, overrides: &Overrides) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(saved) = overrides.get(KEY_VPNS).and_then(Value::as_array) else {
        return warnings;
    };
    let source_args: Vec<Value> = vpns.iter().filter_map(|v| v.get("extra_args")).cloned().collect();
    let removed = string_list(overrides.get(KEY_VPNS_REMOVED));
    vpns.retain(|v| !removed.contains(&v.text("name").as_str()));
    for entry in saved.iter().filter_map(Value::as_object) {
        let name = entry.text("name");
        if !entry.get("name").is_some_and(Value::is_string) || !is_vpn_name(&name) {
            warnings.push("overrides: ignoring a VPN entry without a usable name".to_string());
            continue;
        }
        let clean = clean_vpn_entry(entry, &source_args, &mut warnings);
        // Resolve the length before the mutable `find` borrow begins, so the
        // "list full" arm can consult it without a second borrow.
        let full = vpns.len() >= MAX_VPNS;
        match vpns.iter_mut().find(|v| v.text("name") == name) {
            Some(existing) => merge_form(existing, &clean),
            None if full => {
                warnings.push(format!("overrides: ignoring VPN '{name}' (at most {MAX_VPNS} VPNs)"));
            }
            None => {
                let mut fresh = Dict::new();
                merge_form(&mut fresh, &clean);
                vpns.push(fresh);
            }
        }
    }
    warnings
}

/// The legacy single-VPN override (`_vpn`), merged onto `vpn`.
pub fn apply_vpn_override(vpn: &mut Dict, overrides: &Overrides) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(saved) = overrides.get(KEY_VPN).and_then(Value::as_object) {
        let source_args: Vec<Value> = vpn.get("extra_args").cloned().into_iter().collect();
        merge_form(vpn, &clean_vpn_entry(saved, &source_args, &mut warnings));
    }
    warnings
}

/// Lay the on-screen VPN edits over the loaded config: the `_vpns` list when
/// there is one, else the legacy `_vpn` entry onto the first VPN.
pub fn merge_vpn_overrides(conf: &mut Config, overrides: &Overrides) -> Vec<String> {
    if overrides.get(KEY_VPNS).is_some() {
        return apply_vpns_override(&mut conf.vpns, overrides);
    }
    if !overrides.get(KEY_VPN).is_some_and(|v| v.as_object().is_some_and(|o| !o.is_empty())) {
        return Vec::new();
    }
    if conf.vpns.is_empty() {
        // A VPN first created at the glass by a wall that only knew `_vpn`.
        let mut first = Dict::new();
        first.insert("name".into(), json!("vpn"));
        conf.vpns.push(first);
    }
    let Some(first) = conf.vpns.first_mut() else {
        return Vec::new();
    };
    apply_vpn_override(first, overrides)
}

// ---- proxy -----------------------------------------------------------------

/// Merge a saved proxy override onto the loaded [`ProxyCfg`]. A URL the
/// loader would refuse leaves the whole proxy section as loaded.
pub fn apply_proxy_override(proxy: &mut ProxyCfg, overrides: &Overrides) -> Vec<String> {
    let Some(o) = overrides.get(KEY_PROXY).and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut next = proxy.clone();
    if let Some(Value::Bool(enabled)) = o.get("enabled") {
        next.enabled = *enabled;
    }
    if let Some(url) = o.get("url").and_then(|v| clean_str_or_null(v, MAX_URL_LEN)) {
        next.url = url;
    }
    if let Some(item) = o.get("vault_item").and_then(|v| clean_str_or_null(v, MAX_VAULT_ITEM_LEN)) {
        next.vault_item = item;
    }
    match o.get("ignore_hosts") {
        None => {}
        Some(Value::Null) => next.ignore_hosts.clear(),
        Some(Value::Array(items)) if items.len() <= MAX_LIST_ITEMS => {
            let hosts: Option<Vec<String>> = items
                .iter()
                .map(|h| h.as_str().filter(|s| !has_ctrl_or_space(s) && s.len() <= MAX_HOST_LEN).map(str::to_string))
                .collect();
            if let Some(hosts) = hosts {
                next.ignore_hosts = hosts.into_iter().filter(|h| !h.is_empty()).collect();
            }
        }
        Some(_) => {}
    }
    // The loader only inspects an enabled proxy; check the URL as if it were
    // on, so a bad one cannot lie in wait for the next "enable".
    if !next.url.is_empty() || next.enabled {
        let probe = json!({"proxy": {
            "enabled": true, "url": next.url, "vault_item": next.vault_item, "ignore_hosts": next.ignore_hosts,
        }});
        if let Some(problem) = loader_problems(&probe).into_iter().next() {
            return vec![format!("overrides: proxy settings ignored ({problem})")];
        }
    }
    *proxy = next;
    Vec::new()
}

// ---- tunnel ----------------------------------------------------------------

fn clean_tunnel_value(key: &str, value: &Value) -> bool {
    if value.is_null() {
        return key != "enabled";
    }
    match key {
        "enabled" => value.is_boolean(),
        "jump_host" => clean_str(value, MAX_HOST_LEN + 65).is_some_and(|s| safe_host(&s, "tunnel.jump_host").is_ok()),
        "identity" | "known_hosts" => clean_str(value, MAX_PATH_LEN).is_some_and(|s| safe_word(&s, key).is_ok()),
        "host_key_checking" => value.as_str().is_some_and(|s| VALID_HOST_KEY_CHECKING.contains(&s)),
        "extra_forwards" => value.as_array().is_some_and(|a| {
            a.len() <= MAX_LIST_ITEMS && a.iter().all(|f| f.as_str().is_some_and(|s| safe_forward(s).is_ok()))
        }),
        _ => false,
    }
}

/// Merge a saved tunnel override onto the loaded `tunnel:` section. These
/// values become `ssh` arguments, so each is re-checked with the argv guards;
/// host-key checking can only be set to a value the loader accepts (`no` is
/// not one).
pub fn apply_tunnel_override(tunnel: &mut Dict, overrides: &Overrides) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(o) = overrides.get(KEY_TUNNEL).and_then(Value::as_object) else {
        return warnings;
    };
    let mut clean = Dict::new();
    for (key, value) in o {
        if clean_tunnel_value(key, value) {
            clean.insert(key.clone(), value.clone());
        } else {
            warnings.push(format!("overrides: tunnel: ignoring '{key}' (not a value the settings form saves)"));
        }
    }
    merge_form(tunnel, &clean);
    warnings
}

// ---- panels ----------------------------------------------------------------

/// Replay panels added and removed at the glass, so they survive a restart on
/// a wall whose config lives in `panels.yaml` rather than the vault note.
pub fn apply_panel_additions(panels: &mut Vec<Panel>, display: &DisplayCfg, overrides: &Overrides) -> Vec<String> {
    let mut warnings = Vec::new();
    let removed = string_list(overrides.get(KEY_REMOVED_PANELS));
    panels.retain(|p| !removed.contains(&p.id.as_str()));
    let dim = |n: u32| usize::try_from(n).unwrap_or(usize::MAX);
    let capacity = dim(display.cols).saturating_mul(dim(display.rows));
    let added = overrides.get(KEY_ADDED_PANELS).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default(); // audit-allow: default is the intended fallback
    for entry in added {
        let id = entry.get("id").and_then(Value::as_str).unwrap_or_default(); // audit-allow: default is the intended fallback
        let cell = entry.get("grid").and_then(grid_cell);
        let usable = is_panel_id(id) && !is_reserved(id) && !panels.iter().any(|p| p.id == id);
        match cell {
            Some(cell) if usable && panels.len() < capacity => panels.push(blank_panel(id, cell)),
            _ => warnings.push("overrides: ignoring an added panel (bad id or grid, duplicate, or grid full)".into()),
        }
    }
    warnings
}

fn apply_panel_fields(p: &mut Panel, o: &Dict, layout: Layout, warnings: &mut Warnings) {
    let mut skip = |field: &str| warnings.push(format!("overrides: panel {}: ignoring '{field}'", p.id));
    let before = (p.vault_item.clone(), p.selectors.clone(), p.login_marker.clone());

    match o.get("url") {
        None => {}
        Some(Value::Null) => p.url = None,
        Some(Value::String(url)) if url.trim().chars().count() <= MAX_URL_LEN && valid_http_url(url, true) => {
            let url = url.trim();
            if url.is_empty() {
                p.url = None;
            } else {
                p.url = Some(url.to_string());
                // A set URL implies a direct panel.
                p.mode = Mode::Direct;
            }
        }
        Some(_) => skip("url"),
    }
    if let Some(v) = o.get("title") {
        match clean_str(v, MAX_TITLE_LEN) {
            Some(title) => p.title = title,
            None => skip("title"),
        }
    }
    if let Some(v) = o.get("vault_item") {
        match clean_str_or_null(v, MAX_VAULT_ITEM_LEN) {
            Some(item) => p.vault_item = item,
            None => skip("vault_item"),
        }
    }
    match o.get("engine").map(|v| v.as_str().and_then(Engine::parse)) {
        None => {}
        // Chromium runs in its own OS window; the single-window layout
        // cannot host it and the loader refuses the combination.
        Some(Some(engine)) if !(engine == Engine::Chromium && layout == Layout::Single) => p.engine = engine,
        Some(_) => skip("engine"),
    }
    if let Some(Value::Object(sel)) = o.get("selectors") {
        p.selectors = sel
            .iter()
            .filter(|(key, _)| is_panel_id(key))
            .filter_map(|(key, v)| {
                clean_str(v, MAX_SELECTOR_LEN).filter(|s| !s.is_empty()).map(|s| (key.clone(), json!(s)))
            })
            .collect();
    }
    if let Some(v) = o.get("login_marker") {
        match clean_str_or_null(v, MAX_MARKER_LEN) {
            Some(marker) if marker.is_empty() => p.login_marker = p.selectors.text("pass"),
            Some(marker) => p.login_marker = marker,
            None => skip("login_marker"),
        }
    }
    if let Some(Value::Bool(b)) = o.get("allow_insecure") {
        p.allow_insecure = *b;
    }
    if let Some(Value::Bool(b)) = o.get("allow_media") {
        p.allow_media = *b;
    }
    if let Some(Value::Bool(b)) = o.get("proxy") {
        p.proxy = *b;
    }
    if let Some(ka) = o.get("keepalive").and_then(Value::as_object) {
        if let Some(strategy) = ka.get("strategy").and_then(Value::as_str).and_then(KeepAliveStrategy::parse) {
            p.keepalive.strategy = strategy;
        }
        // Same floor as the loader.
        if let Some(secs) =
            ka.get("intervalSec").and_then(as_int).and_then(|n| u32::try_from(n).ok()).filter(|n| *n >= 1)
        {
            p.keepalive.interval_sec = secs;
        }
    }
    if let Some(Value::String(tenant)) = o.get("tenant") {
        if !has_ctrl(tenant) && tenant.trim().chars().count() <= MAX_TENANT_LEN {
            p.tenant = tenant.trim().to_string();
        } else {
            skip("tenant");
        }
    }
    if let Some(v) = o.get("login_zones") {
        match crate::sanitize::login_zones(v) {
            Some(zones) => p.login_zones = zones,
            None => skip("login_zones"),
        }
    }
    // Auto-login needs the user and password selectors; the loader refuses a
    // vault item without them, so the login settings move together or not at
    // all.
    if !p.vault_item.is_empty() && !(p.selectors.truthy("user") && p.selectors.truthy("pass")) {
        (p.vault_item, p.selectors, p.login_marker) = before;
        skip("vault_item/selectors (auto-login needs the user and password selectors)");
    }
}

fn cells_ok(panels: &[Panel], display: &DisplayCfg) -> bool {
    panels.iter().all(|p| in_grid(display, p.grid))
        && panels.iter().enumerate().all(|(i, p)| panels[..i].iter().all(|q| q.grid != p.grid))
}

/// Apply saved grid moves as one set: a swap is only valid as a whole. If the
/// set leaves a panel off the grid or two in one cell, none of it is applied.
fn apply_grid_moves(panels: &mut [Panel], display: &DisplayCfg, overrides: &Overrides, warnings: &mut Warnings) {
    let original: Vec<(u32, u32)> = panels.iter().map(|p| p.grid).collect();
    let mut moved = false;
    for p in panels.iter_mut() {
        if let Some(cell) = overrides.panel(&p.id).and_then(|o| o.get("grid")).and_then(grid_cell) {
            moved |= cell != p.grid;
            p.grid = cell;
        }
    }
    if moved && !cells_ok(panels, display) {
        for (p, cell) in panels.iter_mut().zip(original) {
            p.grid = cell;
        }
        warnings.push("overrides: ignoring saved panel positions (off the grid, or two panels in one cell)".into());
    }
}

/// Merge the saved per-panel settings onto the panels: additions/removals,
/// then each panel's fields, then grid moves.
pub fn apply_overrides_to_panels(panels: &mut Vec<Panel>, display: &DisplayCfg, overrides: &Overrides) -> Vec<String> {
    let loaded: Vec<String> = panels.iter().map(|p| p.id.clone()).collect();
    let mut warnings = apply_panel_additions(panels, display, overrides);
    for p in panels.iter_mut() {
        if let Some(o) = overrides.panel(&p.id) {
            apply_panel_fields(p, o, display.layout, &mut warnings);
        }
    }
    apply_grid_moves(panels, display, overrides, &mut warnings);
    // A panel added at the glass must not cost the wall a loaded one: if it
    // ended up off the grid or on a taken cell, it is the one that goes.
    for i in (0..panels.len()).rev() {
        let p = &panels[i];
        let clash = !in_grid(display, p.grid) || panels.iter().enumerate().any(|(j, q)| j != i && q.grid == p.grid);
        if clash && !loaded.contains(&p.id) {
            warnings.push(format!("overrides: ignoring added panel {} (its grid cell is not free)", p.id));
            panels.remove(i);
        }
    }
    warnings
}

// ---- the whole merge -------------------------------------------------------

pub(crate) fn refresh_geometry(conf: &mut Config) {
    for p in &mut conf.panels {
        p.geometry = Some(compute_geometry(&conf.display, p.grid));
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Display,
    Vpns,
    Proxy,
    Tunnel,
    Panels,
}

impl Stage {
    const ALL: [Stage; 5] = [Stage::Display, Stage::Vpns, Stage::Proxy, Stage::Tunnel, Stage::Panels];

    fn name(self) -> &'static str {
        match self {
            Stage::Display => "display",
            Stage::Vpns => "VPN",
            Stage::Proxy => "proxy",
            Stage::Tunnel => "tunnel",
            Stage::Panels => "panel",
        }
    }

    fn apply(self, conf: &mut Config, overrides: &Overrides) -> Vec<String> {
        match self {
            Stage::Display => {
                apply_display_override(&mut conf.display, overrides);
                Vec::new()
            }
            Stage::Vpns => merge_vpn_overrides(conf, overrides),
            Stage::Proxy => apply_proxy_override(&mut conf.proxy, overrides),
            Stage::Tunnel => apply_tunnel_override(&mut conf.tunnel, overrides),
            Stage::Panels => {
                let display = conf.display.clone();
                apply_overrides_to_panels(&mut conf.panels, &display, overrides)
            }
        }
    }
}

/// Apply everything saved from the on-screen settings to a loaded config.
///
/// `base` must be a config the loader produced. The result always validates:
/// if the full merge would not, each section is tried on its own and the ones
/// that break validation are left as loaded (and named in `warnings`).
pub fn apply_overrides(base: &Config, overrides: &Overrides) -> Merged {
    let mut warnings = Vec::new();
    let mut full = base.clone();
    for stage in Stage::ALL {
        warnings.extend(stage.apply(&mut full, overrides));
    }
    refresh_geometry(&mut full);
    let problems = config_problems(&full);
    if problems.is_empty() {
        return Merged { config: full, warnings, degraded: false };
    }

    let mut config = base.clone();
    if !config_problems(&config).is_empty() {
        warnings.push("overrides: ignored entirely (the loaded config does not validate on its own)".to_string());
        return Merged { config, warnings, degraded: true };
    }
    for stage in Stage::ALL {
        let mut candidate = config.clone();
        stage.apply(&mut candidate, overrides);
        match config_problems(&candidate).into_iter().next() {
            None => config = candidate,
            Some(problem) => warnings.push(format!("overrides: {} settings ignored ({problem})", stage.name())),
        }
    }
    refresh_geometry(&mut config);
    Merged { config, warnings, degraded: true }
}
