//! Applying a set of changes to the running wall, as a plan.
//!
//! [`plan_apply`] is pure: given the current config and the changes from the
//! settings window it returns the config to run with from now on, plus an
//! ordered list of [`Action`]s. The GUI layer holds the webviews and the
//! privileges; all it has to do is execute the actions in order.
//!
//! A plan is only produced if the resulting config validates. The Python host
//! applied first and found out at the next boot.

use crate::limits::{MAX_FORM_GRID, MAX_FORM_PIXELS, MIN_FORM_PIXELS};
use crate::merge::{merge_form, refresh_geometry};
use crate::overrides::{Overrides, is_reserved};
use crate::sanitize::{self, config_problems, in_grid, is_panel_id};
use serde_json::Value;
use soc_core::dict::as_int;
use soc_core::guard::valid_http_url;
use soc_core::validate::MAX_PIXELS;
use soc_core::{Config, Dict, DictExt, DisplayCfg, Engine, KeepAliveStrategy, Layout, Mode, Panel, ProxyCfg};

/// What the host can do right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCaps {
    /// The single-window wall (one grid of webviews) is up. `false` in the
    /// one-window-per-panel layout, where the window manager places panels
    /// from rules written at session start, so adding a panel or changing the
    /// display needs a restart.
    pub single_wall: bool,
    /// The wall may restart the VPN and tunnel services (passwordless sudo).
    pub can_restart_services: bool,
}

/// One thing the GUI must do, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Create a view for this panel and attach it.
    AddPanel {
        panel: Box<Panel>,
    },
    /// Stop the panel's view and take it off the wall.
    RemovePanel {
        id: String,
    },
    /// Set the grid's row and column spacing.
    SetGap {
        gap: i32,
    },
    /// Resize the wall window and re-fit it to the screen.
    ResizeWindow {
        width: i32,
        height: i32,
    },
    SetFullscreen {
        fullscreen: bool,
    },
    /// Detach and re-attach every view at its panel's (new) grid cell. The
    /// views are the live webviews: no reload.
    ReflowGrid,
    /// Update the panel's displayed title.
    SetTitle {
        panel: String,
        title: String,
    },
    /// Load this URL in the panel (also re-triggers auto-login).
    SetUrl {
        panel: String,
        url: String,
    },
    /// Re-run login injection on the panel with its current settings.
    Reinject {
        panel: String,
    },
    /// Restart the VPN supervisor so it re-reads the config.
    RestartVpn,
    /// Restart the SSH tunnel service.
    RestartTunnel,
    /// Write the config back to the vault note (the source of truth).
    PushConfigToVault,
    /// Soft-restart the wall. Always last.
    RestartWall,
}

/// What the plan amounts to, for the operator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Things that only take effect after a restart nobody has done yet.
    pub pending_restarts: Vec<String>,
    /// Things that took effect immediately.
    pub applied_live: Vec<String>,
    /// The wall restarts itself at the end of this apply.
    pub self_restart: bool,
    /// Parts of the request that were refused, and why (for the log).
    pub skipped: Vec<String>,
}

/// The outcome of [`plan_apply`].
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// The config to run with (and to write back) once the actions are done.
    pub config: Config,
    pub actions: Vec<Action>,
    pub report: ApplyReport,
}

/// Edits to one existing panel. `None` leaves a field alone.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PanelChange {
    pub id: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub vault_item: Option<String>,
    pub engine: Option<Engine>,
    pub selectors: Option<Dict>,
    pub login_marker: Option<String>,
    pub allow_insecure: Option<bool>,
    pub allow_media: Option<bool>,
    pub proxy: Option<bool>,
    pub keepalive: Option<(KeepAliveStrategy, u32)>,
    pub tenant: Option<String>,
    pub grid: Option<(u32, u32)>,
}

/// Edits to the display section. `None` leaves a field alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisplayChange {
    pub layout: Option<Layout>,
    pub gap: Option<i32>,
    pub cols: Option<u32>,
    pub rows: Option<u32>,
    pub auto: Option<bool>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub fullscreen: Option<bool>,
}

impl DisplayChange {
    /// Read a `_display` mapping, keeping only values the boot merge would
    /// also accept (so nothing is applied live that a restart would undo).
    pub fn from_dict(d: &Dict) -> DisplayChange {
        let int_in = |key: &str, lo: i64, hi: i64| d.get(key).and_then(as_int).filter(|n| (lo..=hi).contains(n));
        let flag = |key: &str| d.get(key).and_then(Value::as_bool);
        DisplayChange {
            layout: d.get("layout").and_then(Value::as_str).and_then(Layout::parse),
            gap: int_in("gap", 0, MAX_PIXELS).and_then(|n| i32::try_from(n).ok()),
            cols: int_in("cols", 1, MAX_FORM_GRID).and_then(|n| u32::try_from(n).ok()),
            rows: int_in("rows", 1, MAX_FORM_GRID).and_then(|n| u32::try_from(n).ok()),
            auto: flag("auto"),
            width: int_in("width", MIN_FORM_PIXELS, MAX_FORM_PIXELS).and_then(|n| i32::try_from(n).ok()),
            height: int_in("height", MIN_FORM_PIXELS, MAX_FORM_PIXELS).and_then(|n| i32::try_from(n).ok()),
            fullscreen: flag("fullscreen"),
        }
    }

    fn apply_to(&self, d: &mut DisplayCfg) {
        d.layout = self.layout.unwrap_or(d.layout);
        d.gap = self.gap.unwrap_or(d.gap);
        d.cols = self.cols.unwrap_or(d.cols);
        d.rows = self.rows.unwrap_or(d.rows);
        d.auto = self.auto.unwrap_or(d.auto);
        d.width = self.width.unwrap_or(d.width);
        d.height = self.height.unwrap_or(d.height);
        d.fullscreen = self.fullscreen.unwrap_or(d.fullscreen);
    }
}

/// Everything one Apply asks of the host.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Changes {
    pub panels: Vec<PanelChange>,
    pub add_panels: Vec<Panel>,
    pub remove_panels: Vec<String>,
    pub display: Option<DisplayChange>,
    /// The whole VPN list after the edit.
    pub vpns: Option<Vec<Dict>>,
    /// Legacy single-VPN edit: replaces the first VPN.
    pub vpn: Option<Dict>,
    /// The proxy override (missing keys mean "unset").
    pub proxy: Option<Dict>,
    /// The tunnel override, merged over the loaded section.
    pub tunnel: Option<Dict>,
}

impl Changes {
    /// Read the dictionary shape the Python window handed its host:
    /// `{<panel id>: {url, title, vault_item}, "_display": {..}, "_vpns": [..],
    /// "_vpn": {..}, "_proxy": {..}, "_tunnel": {..}, "_remove_panel": [..]}`.
    /// Malformed parts are dropped. (`_add_panel` needs whole panels and has
    /// no dictionary form; use [`Changes::add_panels`].)
    pub fn from_dict(d: &Dict) -> Changes {
        let section = |key: &str| d.get(key).and_then(Value::as_object).cloned();
        let text = |o: &Dict, key: &str| o.get(key).and_then(Value::as_str).map(str::to_string);
        Changes {
            panels: d
                .iter()
                .filter(|(id, _)| !id.starts_with('_'))
                .filter_map(|(id, v)| v.as_object().map(|o| (id, o)))
                .map(|(id, o)| PanelChange {
                    id: id.clone(),
                    url: text(o, "url"),
                    title: text(o, "title"),
                    vault_item: text(o, "vault_item"),
                    ..PanelChange::default()
                })
                .collect(),
            add_panels: Vec::new(),
            remove_panels: d
                .get("_remove_panel")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default(), // audit-allow: default is the intended fallback
            display: section("_display").map(|o| DisplayChange::from_dict(&o)),
            vpns: d
                .get("_vpns")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_object).cloned().collect()),
            vpn: section("_vpn"),
            proxy: section("_proxy"),
            tunnel: section("_tunnel"),
        }
    }
}

/// The first empty `(col, row)` in reading order, or `None` when the grid is
/// full.
pub fn free_cell(conf: &Config) -> Option<(u32, u32)> {
    let d = &conf.display;
    (0..d.rows)
        .flat_map(|row| (0..d.cols).map(move |col| (col, row)))
        .find(|cell| conf.panels.iter().all(|p| p.grid != *cell))
}

/// The first port at or above `base` that no view is using for remote
/// debugging. Ports stay with their views, so a removal can leave a hole.
pub fn first_free_port(base: u16, used: &[u16]) -> Option<u16> {
    (base..=u16::MAX).find(|port| !used.contains(port))
}

fn plan_additions(
    config: &mut Config,
    changes: &Changes,
    host: &HostCaps,
    plan: &mut Vec<Action>,
    report: &mut ApplyReport,
) {
    if changes.add_panels.is_empty() {
        return;
    }
    if !host.single_wall {
        report.pending_restarts.push("soc-wall (new panels appear on next boot)".to_string());
        return;
    }
    for wanted in &changes.add_panels {
        let id = &wanted.id;
        let url = wanted.url.as_deref().unwrap_or("");
        let refusal = if !is_panel_id(id) || is_reserved(id) {
            Some("not a usable panel id")
        } else if config.panel(id).is_some() {
            Some("a panel with this id already exists")
        } else if !valid_http_url(url, true) {
            Some("not a valid http(s) URL")
        } else if wanted.engine == Engine::Chromium {
            Some("the single-window layout cannot host chromium panels")
        } else if !in_grid(&config.display, wanted.grid) || config.panels.iter().any(|p| p.grid == wanted.grid) {
            Some("its grid cell is off the grid or taken")
        } else {
            None
        };
        if let Some(why) = refusal {
            report.skipped.push(format!("[{id}] add panel failed: {why}"));
            continue;
        }
        let mut panel = wanted.clone();
        panel.url = wanted.url.as_ref().map(|u| u.trim().to_string()).filter(|u| !u.is_empty());
        config.panels.push(panel.clone());
        plan.push(Action::AddPanel { panel: Box::new(panel) });
    }
}

fn plan_display(
    config: &mut Config,
    change: &DisplayChange,
    host: &HostCaps,
    plan: &mut Vec<Action>,
    report: &mut ApplyReport,
) {
    let before = config.display.clone();
    change.apply_to(&mut config.display);
    let after = config.display.clone();
    if !host.single_wall {
        if after != before {
            report.pending_restarts.push("soc-wall (display changes apply on next boot)".to_string());
        }
        return;
    }
    if after.gap != before.gap {
        plan.push(Action::SetGap { gap: after.gap });
    }
    if after.layout != before.layout {
        // A layout swap is a different windowing model; only a restart does it.
        report.self_restart = true;
        return;
    }
    let mut live = Vec::new();
    if (after.width, after.height) != (before.width, before.height) {
        plan.push(Action::ResizeWindow { width: after.width, height: after.height });
        live.extend([("height", after.height != before.height), ("width", after.width != before.width)]);
    }
    if after.fullscreen != before.fullscreen {
        plan.push(Action::SetFullscreen { fullscreen: after.fullscreen });
        live.push(("fullscreen", true));
    }
    if (after.cols, after.rows) != (before.cols, before.rows) {
        plan.push(Action::ReflowGrid);
        live.extend([("cols", after.cols != before.cols), ("rows", after.rows != before.rows)]);
    }
    let mut names: Vec<String> =
        live.into_iter().filter(|(_, changed)| *changed).map(|(name, _)| name.to_string()).collect();
    names.sort_unstable();
    report.applied_live.extend(names);
}

fn plan_panel(p: &mut Panel, ch: &PanelChange, plan: &mut Vec<Action>, report: &mut ApplyReport) -> bool {
    if let Some(title) = ch.title.as_ref().filter(|t| **t != p.title) {
        p.title = title.clone();
        plan.push(Action::SetTitle { panel: p.id.clone(), title: title.clone() });
    }
    let vault_changed = ch.vault_item.as_ref().is_some_and(|v| *v != p.vault_item);
    if let Some(item) = ch.vault_item.as_ref().filter(|_| vault_changed) {
        p.vault_item = item.clone();
    }
    let mut deferred = Vec::new();
    if let Some(selectors) = ch.selectors.as_ref().filter(|s| **s != p.selectors) {
        p.selectors = selectors.clone();
    }
    if let Some(marker) = &ch.login_marker {
        p.login_marker = if marker.is_empty() { p.selectors.text("pass") } else { marker.clone() };
    }
    if let Some(tenant) = &ch.tenant {
        p.tenant = tenant.clone();
    }
    if let Some(engine) = ch.engine.filter(|e| *e != p.engine) {
        p.engine = engine;
        deferred.push("engine");
    }
    for (name, wanted, slot) in [
        ("allow_insecure", ch.allow_insecure, &mut p.allow_insecure),
        ("allow_media", ch.allow_media, &mut p.allow_media),
        ("proxy", ch.proxy, &mut p.proxy),
    ] {
        if let Some(value) = wanted.filter(|v| *v != *slot) {
            *slot = value;
            deferred.push(name);
        }
    }
    if let Some((strategy, interval)) = ch.keepalive.filter(|k| *k != (p.keepalive.strategy, p.keepalive.interval_sec))
    {
        p.keepalive.strategy = strategy;
        p.keepalive.interval_sec = interval;
        deferred.push("keepalive");
    }
    if !deferred.is_empty() {
        report.pending_restarts.push(format!("soc-wall (panel {}: {} apply on next boot)", p.id, deferred.join(", ")));
    }

    let current = p.url.clone().unwrap_or_default(); // audit-allow: default is the intended fallback
    match ch.url.as_deref().map(str::trim).filter(|u| *u != current) {
        Some(url) if !valid_http_url(url, true) => {
            report.skipped.push(format!("[{}] url ignored: not a valid http(s) URL", p.id));
        }
        Some(url) => {
            p.url = (!url.is_empty()).then(|| url.to_string());
            if !url.is_empty() {
                // A set URL implies a direct panel (the boot merge agrees).
                p.mode = Mode::Direct;
            }
            plan.push(Action::SetUrl { panel: p.id.clone(), url: url.to_string() });
        }
        // The vault item changed but the URL did not: reload to log in again.
        None if vault_changed => plan.push(Action::SetUrl { panel: p.id.clone(), url: current }),
        None => {}
    }
    match ch.grid.filter(|g| *g != p.grid) {
        Some(cell) => {
            p.grid = cell;
            true
        }
        None => false,
    }
}

/// Work out how to apply `changes` to the running wall.
///
/// Returns the new config and the actions that realise it, or — if the result
/// would not validate — every problem found, in which case nothing may be
/// saved or applied.
pub fn plan_apply(conf: &Config, changes: &Changes, host: &HostCaps) -> Result<Plan, Vec<String>> {
    let mut config = conf.clone();
    let mut actions = Vec::new();
    let mut report = ApplyReport::default();

    // The display goes first so new panels and moves are judged against the
    // grid they will actually live in.
    let mut display_actions = Vec::new();
    if let Some(change) = &changes.display {
        plan_display(&mut config, change, host, &mut display_actions, &mut report);
    }
    for id in &changes.remove_panels {
        if config.panel(id).is_some() {
            config.panels.retain(|p| p.id != *id);
            actions.push(Action::RemovePanel { id: id.clone() });
        } else {
            report.skipped.push(format!("[{id}] panel not found for removal"));
        }
    }
    let mut moved = false;
    let mut panel_actions = Vec::new();
    for ch in &changes.panels {
        match config.panels.iter_mut().find(|p| p.id == ch.id) {
            Some(p) => moved |= plan_panel(p, ch, &mut panel_actions, &mut report),
            // A panel added in this same Apply arrives whole in `add_panels`.
            None if changes.add_panels.iter().any(|p| p.id == ch.id) => {}
            None => report.skipped.push(format!("[{}] no such panel", ch.id)),
        }
    }
    plan_additions(&mut config, changes, host, &mut actions, &mut report);
    actions.append(&mut display_actions);
    if moved {
        if !host.single_wall {
            report.pending_restarts.push("soc-wall (panel positions apply on next boot)".to_string());
        } else if !report.self_restart && !actions.contains(&Action::ReflowGrid) {
            actions.push(Action::ReflowGrid);
            report.applied_live.push("panel positions".to_string());
        }
    }

    // One supervisor unit runs every VPN, so either form of the edit is one
    // restart.
    if changes.vpns.is_some() || changes.vpn.is_some() {
        if let Some(vpns) = &changes.vpns {
            config.vpns = vpns.clone();
        } else if let Some(vpn) = &changes.vpn {
            match config.vpns.first_mut() {
                Some(first) => *first = vpn.clone(),
                None => config.vpns.push(vpn.clone()),
            }
        }
        if host.can_restart_services {
            actions.push(Action::RestartVpn);
            report.applied_live.push("forti-vpn".to_string());
        } else {
            report.pending_restarts.push("forti-vpn".to_string());
        }
    }
    if let Some(proxy) = &changes.proxy {
        // The browsers read the proxy when a view is created, so this takes
        // effect next boot; updating the config keeps the write-back current.
        config.proxy = ProxyCfg {
            enabled: proxy.truthy("enabled"),
            url: proxy.text("url"),
            vault_item: proxy.text("vault_item"),
            ignore_hosts: proxy.strings("ignore_hosts").into_iter().filter(|h| !h.is_empty()).collect(),
        };
        report.pending_restarts.push("soc-wall (proxy applies on next boot)".to_string());
    }
    if let Some(tunnel) = &changes.tunnel {
        // A merge, so advanced keys the form does not show survive.
        merge_form(&mut config.tunnel, tunnel);
        if host.can_restart_services {
            actions.push(Action::RestartTunnel);
        } else {
            report.pending_restarts.push("autossh-tunnel".to_string());
        }
    }
    actions.append(&mut panel_actions);

    refresh_geometry(&mut config);
    let orphans: Vec<&str> =
        config.panels.iter().filter(|p| !in_grid(&config.display, p.grid)).map(|p| p.id.as_str()).collect();
    if !orphans.is_empty() {
        return Err(vec![format!(
            "the {}x{} grid would orphan {} — move or remove those panels first",
            config.display.cols,
            config.display.rows,
            orphans.join(", ")
        )]);
    }
    let problems = config_problems(&config);
    if !problems.is_empty() {
        return Err(problems);
    }

    actions.push(Action::PushConfigToVault);
    if report.self_restart {
        // A restart re-creates everything from the saved state; live display
        // nudges before it would only flicker.
        actions
            .retain(|a| !matches!(a, Action::ResizeWindow { .. } | Action::SetFullscreen { .. } | Action::ReflowGrid));
        report
            .applied_live
            .retain(|name| !matches!(name.as_str(), "width" | "height" | "fullscreen" | "cols" | "rows"));
        actions.push(Action::RestartWall);
    }
    Ok(Plan { config, actions, report })
}

/// The outcome of a login-zone calibration (or of clearing one).
#[derive(Debug, Clone, PartialEq)]
pub struct ZonesPlan {
    pub config: Config,
    /// Save these so the calibration survives a restart.
    pub overrides: Overrides,
    pub actions: Vec<Action>,
    /// Whether the panel had zones before (for the "nothing to clear" toast).
    pub had_zones: bool,
}

/// Record freshly calibrated login zones for `panel_id`: validate them, put
/// them on the panel and in its overrides entry (keeping its other fields),
/// and re-inject so they are used straight away. An empty mapping clears the
/// zones — written as an explicit empty override, because zones from the
/// source config would otherwise return at boot.
pub fn plan_login_zones(
    conf: &Config,
    overrides: &Overrides,
    panel_id: &str,
    zones: &Value,
) -> Result<ZonesPlan, Vec<String>> {
    let Some(zones) = sanitize::login_zones(zones) else {
        return Err(vec![format!(
            "panel {panel_id}: login zones must be user/pass/submit entries with x_pct + y_pct in 0..1"
        )]);
    };
    let mut config = conf.clone();
    let Some(panel) = config.panels.iter_mut().find(|p| p.id == panel_id) else {
        return Err(vec![format!("no panel with id {panel_id:?}")]);
    };
    let mut overrides = overrides.clone();
    let entry = overrides.panel_entry(panel_id).map_err(|e| vec![e.to_string()])?;
    let had_zones = !panel.login_zones.is_empty() || entry.dict("login_zones").is_some_and(|z| !z.is_empty());
    entry.insert("login_zones".into(), Value::Object(zones.clone()));
    panel.login_zones = zones;
    Ok(ZonesPlan { config, overrides, actions: vec![Action::Reinject { panel: panel_id.to_string() }], had_zones })
}

/// Whether the config can be written back to the vault note right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteBack {
    /// The prerequisites are met; the upload may run (it can still fail).
    Ready,
    /// `overrides.json` is the only record; the stale note wins at next boot.
    Deferred(String),
}

impl WriteBack {
    /// The cheap checks before a write-back is started.
    pub fn precheck(backend: &str, item: &str, vault_url: &str, vault_email: &str, master_sealed: bool) -> WriteBack {
        let deferred = |why: &str| WriteBack::Deferred(why.to_string());
        if !matches!(backend, "rbw" | "litebw" | "native") {
            deferred("this vault backend has no config note")
        } else if item.is_empty() {
            deferred("SOC_CONFIG_VAULT_ITEM is empty")
        } else if vault_url.is_empty() {
            deferred("SOC_VAULT_URL is empty")
        } else if vault_email.is_empty() {
            deferred("SOC_VAULT_EMAIL is empty")
        } else if !master_sealed {
            deferred("master password is not host-sealed")
        } else {
            WriteBack::Ready
        }
    }
}

/// The line the settings window shows after an Apply, and whether it is an
/// error. It tells the truth about what happened: restarts still pending, or
/// a vault note that could not be written (which the next boot's stale note
/// would silently win over).
pub fn report_message(report: &ApplyReport, write_back: &WriteBack) -> (String, bool) {
    let mut bits = vec!["Saved ✓ — overrides.json updated".to_string()];
    if !report.applied_live.is_empty() {
        bits.push(format!("applied live ✓ ({} — no restart)", report.applied_live.join(", ")));
    }
    if report.self_restart {
        bits.push("restarting wall to apply layout change".to_string());
    }
    if !report.pending_restarts.is_empty() {
        bits.push(format!("⚠ PENDING restart: {}", report.pending_restarts.join(", ")));
    }
    let deferred = match write_back {
        WriteBack::Ready => {
            bits.push("vault note write-back scheduled".to_string());
            false
        }
        WriteBack::Deferred(why) => {
            bits.push(format!(
                "⚠ vault config-note NOT written ({why}) — your changes will be lost at the next boot unless you fix \
                 this. Local overrides remain in effect for now."
            ));
            true
        }
    };
    (bits.join("  ·  "), !report.pending_restarts.is_empty() || deferred)
}
