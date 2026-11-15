//! The Apply button, minus the button: from the form's values to what gets
//! saved and what the host has to do.
//!
//! [`prepare_apply`] checks everything first and writes nothing. Only when it
//! returns `Ok` does the GUI (after any re-authentication the result asks
//! for) save [`Prepared::overrides`] and execute [`Prepared::plan`]. A refused
//! Apply therefore leaves both the file and the wall untouched.

use crate::forms::{
    VpnEdit, VpnResult, collect_vpn, form_problems, mark_cleared, proxy_form_to_dict, tunnel_form_to_dict,
};
use crate::limits::{MAX_MARKER_LEN, MAX_SELECTOR_LEN, MAX_TITLE_LEN, MAX_URL_LEN, MAX_VAULT_ITEM_LEN, sanitize_len};
use crate::overrides::{
    KEY_ADDED_PANELS, KEY_DISPLAY, KEY_PROXY, KEY_REMOVED_PANELS, KEY_TUNNEL, KEY_VPN, KEY_VPNS, KEY_VPNS_REMOVED,
    Overrides,
};
use crate::plan::{Changes, DisplayChange, HostCaps, PanelChange, Plan, plan_apply};
use crate::session::PanelSession;
use serde_json::{Value, json};
use soc_core::guard::{has_ctrl, valid_http_url};
use soc_core::validate::MAX_TENANT_LEN;
use soc_core::{Config, Dict, DictExt, Engine, KeepAliveStrategy, Mode, Panel};
use std::collections::BTreeSet;

/// One row of the Panels tab, as typed.
#[derive(Debug, Clone, PartialEq)]
pub struct PanelForm {
    pub id: String,
    pub url: String,
    pub title: String,
    pub vault_item: String,
    /// `webkit` or `chromium`.
    pub engine: String,
    pub selector_user: String,
    pub selector_pass: String,
    pub selector_submit: String,
    pub login_marker: String,
    pub allow_insecure: bool,
    pub allow_media: bool,
    pub proxy: bool,
    pub keepalive_strategy: String,
    pub keepalive_interval: i64,
    pub tenant: String,
}

impl PanelForm {
    /// The row a panel starts out with.
    pub fn from_panel(p: &Panel) -> PanelForm {
        PanelForm {
            id: p.id.clone(),
            url: p.url.clone().unwrap_or_default(), // audit-allow: default is the intended fallback
            title: p.title.clone(),
            vault_item: p.vault_item.clone(),
            engine: p.engine.as_str().to_string(),
            selector_user: p.selectors.text("user"),
            selector_pass: p.selectors.text("pass"),
            selector_submit: p.selectors.text("submit"),
            login_marker: p.login_marker.clone(),
            allow_insecure: p.allow_insecure,
            allow_media: p.allow_media,
            proxy: p.proxy,
            keepalive_strategy: p.keepalive.strategy.as_str().to_string(),
            keepalive_interval: i64::from(p.keepalive.interval_sec),
            tenant: p.tenant.clone(),
        }
    }

    fn texts(&self) -> [&str; 8] {
        [
            &self.url,
            &self.title,
            &self.vault_item,
            &self.selector_user,
            &self.selector_pass,
            &self.selector_submit,
            &self.login_marker,
            &self.tenant,
        ]
    }
}

/// The Display tab's values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayForm {
    pub layout: String,
    pub gap: i64,
    pub cols: i64,
    pub rows: i64,
    pub auto: bool,
    pub width: i64,
    pub height: i64,
    pub fullscreen: bool,
}

impl DisplayForm {
    fn to_dict(&self) -> Dict {
        let layout = if self.layout.is_empty() { "auto" } else { self.layout.as_str() };
        let value = json!({
            "layout": layout, "gap": self.gap, "cols": self.cols, "rows": self.rows, "auto": self.auto,
            "width": self.width, "height": self.height, "fullscreen": self.fullscreen,
        });
        value.as_object().cloned().unwrap_or_default() // audit-allow: infallible, json! of an object literal
    }
}

/// The VPN tab's state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VpnForms {
    /// The sections still on the tab.
    pub rows: Vec<VpnEdit>,
    /// A VPN was removed since the last save.
    pub removed_any: bool,
    /// Names of the VPNs the window opened with — the ones a removal or a
    /// rename has to record as gone.
    pub names_open: Vec<String>,
}

/// A proxy or tunnel tab: its values now and when the window opened. Equal
/// means untouched, and an untouched section is neither saved nor restarted.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SectionForm {
    pub form: Dict,
    pub base: Dict,
}

/// Everything on the form. `None` for a tab that was never opened.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApplyForm {
    pub rows: Vec<PanelForm>,
    pub display: Option<DisplayForm>,
    pub vpns: Option<VpnForms>,
    pub proxy: Option<SectionForm>,
    pub tunnel: Option<SectionForm>,
}

/// Why an Apply was refused. Nothing was changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// These panels' URLs are not plain http(s) URLs.
    BadUrls(Vec<String>),
    /// The values would produce a config the wall cannot load.
    Problems(Vec<String>),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::BadUrls(ids) => {
                write!(f, "only http:// or https:// URLs are allowed (check: {})", ids.join(", "))
            }
            ApplyError::Problems(problems) => {
                let shown: Vec<&str> = problems.iter().take(3).map(String::as_str).collect();
                write!(f, "Not saved — {}", shown.join("; "))
            }
        }
    }
}

impl std::error::Error for ApplyError {}

/// A checked Apply, ready to be carried out.
#[derive(Debug, Clone, PartialEq)]
pub struct Prepared {
    /// Save this first.
    pub overrides: Overrides,
    /// What was asked of the host (also in `plan`, kept for logging).
    pub changes: Changes,
    /// Then execute this.
    pub plan: Plan,
    /// Network sections this Apply edits ("VPN", "proxy", "tunnel"). If any
    /// are listed and a settings credential is enrolled, re-authenticate
    /// before saving.
    pub reauth: Vec<&'static str>,
}

fn row_change(row: &PanelForm, grid: Option<(u32, u32)>) -> (PanelChange, Dict) {
    let url = sanitize_len(&row.url, MAX_URL_LEN);
    let title = sanitize_len(&row.title, MAX_TITLE_LEN);
    let vault_item = sanitize_len(&row.vault_item, MAX_VAULT_ITEM_LEN);
    let engine = Engine::parse(&row.engine).unwrap_or(Engine::Webkit);
    let mut selectors = Dict::new();
    for (key, value) in [("user", &row.selector_user), ("pass", &row.selector_pass), ("submit", &row.selector_submit)] {
        let value = sanitize_len(value, MAX_SELECTOR_LEN);
        if !value.is_empty() {
            selectors.insert(key.into(), json!(value));
        }
    }
    let marker = sanitize_len(&row.login_marker, MAX_MARKER_LEN);
    let strategy = KeepAliveStrategy::parse(&row.keepalive_strategy).unwrap_or(KeepAliveStrategy::None);
    let interval = u32::try_from(row.keepalive_interval).unwrap_or(0).max(1);
    let tenant = sanitize_len(&row.tenant, MAX_TENANT_LEN);

    let saved = json!({
        "url": url, "title": title, "vault_item": vault_item, "engine": engine.as_str(), "selectors": selectors,
        "login_marker": marker, "allow_insecure": row.allow_insecure, "allow_media": row.allow_media,
        "proxy": row.proxy, "keepalive": {"strategy": strategy.as_str(), "intervalSec": interval}, "tenant": tenant,
    });
    let change = PanelChange {
        id: row.id.clone(),
        url: Some(url),
        title: Some(title),
        vault_item: Some(vault_item),
        engine: Some(engine),
        selectors: Some(selectors),
        login_marker: Some(marker),
        allow_insecure: Some(row.allow_insecure),
        allow_media: Some(row.allow_media),
        proxy: Some(row.proxy),
        keepalive: Some((strategy, interval)),
        tenant: Some(tenant),
        grid,
    };
    (change, saved.as_object().cloned().unwrap_or_default()) // audit-allow: infallible, json! of an object literal
}

/// A session panel with its row's values laid on: what "add panel" hands the
/// host.
fn new_panel(panel: &Panel, change: &PanelChange, cell: (u32, u32)) -> Panel {
    let mut p = panel.clone();
    p.grid = cell;
    p.title = change.title.clone().unwrap_or_default(); // audit-allow: default is the intended fallback
    p.vault_item = change.vault_item.clone().unwrap_or_default(); // audit-allow: default is the intended fallback
    p.engine = change.engine.unwrap_or(p.engine);
    p.selectors = change.selectors.clone().unwrap_or_default(); // audit-allow: default is the intended fallback
    let marker = change.login_marker.clone().unwrap_or_default(); // audit-allow: default is the intended fallback
    p.login_marker = if marker.is_empty() { p.selectors.text("pass") } else { marker };
    p.allow_insecure = change.allow_insecure.unwrap_or(p.allow_insecure);
    p.allow_media = change.allow_media.unwrap_or(p.allow_media);
    p.proxy = change.proxy.unwrap_or(p.proxy);
    if let Some((strategy, interval)) = change.keepalive {
        p.keepalive.strategy = strategy;
        p.keepalive.interval_sec = interval;
    }
    p.tenant = change.tenant.clone().unwrap_or_default(); // audit-allow: default is the intended fallback
    let url = change.url.clone().unwrap_or_default(); // audit-allow: default is the intended fallback
    if !url.is_empty() {
        p.mode = Mode::Direct;
        p.url = Some(url);
    } else if p.mode == Mode::Direct {
        p.url = None;
    }
    p
}

fn string_set(v: Option<&Value>) -> BTreeSet<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default() // audit-allow: default is the intended fallback
}

/// Record every row in the overrides and in the changes; record additions and
/// removals so they outlive a restart (an override keyed by id alone would
/// not).
fn merge_panels(
    session: &PanelSession,
    rows: &[PanelForm],
    changes: &mut Changes,
    overrides: &mut Overrides,
) -> Result<(), ApplyError> {
    for row in rows {
        let Some(panel) = session.panels().iter().find(|p| p.id == row.id) else {
            continue;
        };
        let cell = session.grid_of(&row.id).unwrap_or(panel.grid);
        // Only a moved panel saves its grid: a saved grid would otherwise
        // outrank later edits to the source config.
        let moved = (cell != panel.grid).then_some(cell);
        let (change, saved) = row_change(row, moved);
        let entry = overrides.panel_entry(&row.id).map_err(|e| ApplyError::Problems(vec![e.to_string()]))?;
        entry.extend(saved);
        if let Some((col, row_n)) = moved {
            entry.insert("grid".into(), json!([col, row_n]));
        }
        if session.is_added(&row.id) {
            changes.add_panels.push(new_panel(panel, &change, cell));
        } else {
            changes.panels.push(change);
        }
    }

    let removed = session.removed();
    if session.added().is_empty() && removed.is_empty() {
        return Ok(());
    }
    let new: BTreeSet<&str> = session.added().iter().map(String::as_str).collect();
    let dict = overrides.as_dict_mut();
    for id in removed {
        dict.shift_remove(id);
    }
    let mut added_list: Vec<Value> = dict
        .get(KEY_ADDED_PANELS)
        .and_then(Value::as_array)
        .map(|a| {
            let gone = |e: &&Value| {
                e.get("id").and_then(Value::as_str).is_some_and(|id| !removed.contains(id) && !new.contains(id))
            };
            a.iter().filter(|e| e.is_object()).filter(gone).cloned().collect()
        })
        .unwrap_or_default(); // audit-allow: default is the intended fallback
    for id in session.added() {
        if let Some((col, row)) = session.grid_of(id) {
            added_list.push(json!({"id": id, "grid": [col, row]}));
        }
    }
    dict.insert(KEY_ADDED_PANELS.into(), Value::Array(added_list));
    let mut gone = string_set(dict.get(KEY_REMOVED_PANELS));
    gone.extend(removed.iter().cloned());
    gone.retain(|id| !new.contains(id.as_str()));
    dict.insert(KEY_REMOVED_PANELS.into(), json!(gone));
    changes.remove_panels = removed.iter().cloned().collect();
    Ok(())
}

/// Check the whole form and work out what Apply would do.
///
/// `conf` is the running config, `session` the Panels tab's state, `overrides`
/// the file as it is on disk *now* (load it right before calling: calibration
/// can have saved meanwhile). Nothing is written.
pub fn prepare_apply(
    conf: &Config,
    session: &PanelSession,
    form: &ApplyForm,
    overrides: &Overrides,
    host: &HostCaps,
) -> Result<Prepared, ApplyError> {
    let bad: Vec<String> = form
        .rows
        .iter()
        .filter(|r| !valid_http_url(&r.url, true) || r.url.trim().chars().count() > MAX_URL_LEN)
        .map(|r| r.id.clone())
        .collect();
    if !bad.is_empty() {
        return Err(ApplyError::BadUrls(bad));
    }
    let multiline: Vec<String> = form
        .rows
        .iter()
        .filter(|r| r.texts().iter().any(|t| has_ctrl(t.trim())))
        .map(|r| format!("panel {}: a field contains control characters", r.id))
        .collect();
    if !multiline.is_empty() {
        return Err(ApplyError::Problems(multiline));
    }

    let vpn_results: Option<Vec<VpnResult>> = form.vpns.as_ref().map(|v| v.rows.iter().map(collect_vpn).collect());
    let vpn_edited = vpn_results.as_ref().is_some_and(|rows| rows.iter().any(|r| r.edited));
    let vpn_changed = vpn_edited || form.vpns.as_ref().is_some_and(|v| v.removed_any);
    let merged: Option<Vec<Dict>> =
        vpn_results.as_ref().filter(|_| vpn_changed).map(|rows| rows.iter().map(|r| r.merged.clone()).collect());
    let proxy_form = form.proxy.as_ref().filter(|s| s.form != s.base).map(|s| &s.form);
    let tunnel_form = form.tunnel.as_ref().filter(|s| s.form != s.base).map(|s| &s.form);
    let any_tunnel_panel = session.panels().iter().any(|p| p.mode == Mode::Tunnel);
    let problems = form_problems(merged.as_deref(), proxy_form, tunnel_form, any_tunnel_panel);
    if !problems.is_empty() {
        return Err(ApplyError::Problems(problems));
    }
    let reauth: Vec<&'static str> =
        [("VPN", vpn_edited), ("proxy", proxy_form.is_some()), ("tunnel", tunnel_form.is_some())]
            .into_iter()
            .filter(|(_, touched)| *touched)
            .map(|(name, _)| name)
            .collect();

    let mut changes = Changes::default();
    let mut overrides = overrides.clone();
    merge_panels(session, &form.rows, &mut changes, &mut overrides)?;
    let dict = overrides.as_dict_mut();

    if let Some(display) = &form.display {
        let saved = display.to_dict();
        changes.display = Some(DisplayChange::from_dict(&saved));
        dict.insert(KEY_DISPLAY.into(), Value::Object(saved));
    }
    // VPN, proxy and tunnel are only sent when they changed: the host restarts
    // a service for each, and a URL edit must not bounce the VPN.
    if let (Some(results), Some(merged), Some(vpns)) = (&vpn_results, merged, &form.vpns) {
        let saved: Vec<Value> = results.iter().map(|r| Value::Object(r.saved.clone())).collect();
        let names: BTreeSet<String> = merged.iter().map(|m| m.text("name")).collect();
        let mut gone = string_set(dict.get(KEY_VPNS_REMOVED));
        gone.extend(vpns.names_open.iter().cloned());
        gone.retain(|name| !names.contains(name));
        dict.insert(KEY_VPNS_REMOVED.into(), json!(gone));
        // Back-compat: the first entry under the legacy key.
        dict.insert(KEY_VPN.into(), saved.first().cloned().unwrap_or_else(|| json!({})));
        dict.insert(KEY_VPNS.into(), Value::Array(saved));
        changes.vpns = Some(merged);
    }
    if let Some(form) = proxy_form {
        let p = &conf.proxy;
        let before = json!({"url": p.url, "vault_item": p.vault_item, "ignore_hosts": p.ignore_hosts});
        let mut saved = proxy_form_to_dict(form);
        mark_cleared(&mut saved, form, before.as_object().unwrap_or(&Dict::new()));
        dict.insert(KEY_PROXY.into(), Value::Object(saved.clone()));
        changes.proxy = Some(saved);
    }
    if let Some(form) = tunnel_form {
        let mut saved = tunnel_form_to_dict(form);
        mark_cleared(&mut saved, form, &conf.tunnel);
        dict.insert(KEY_TUNNEL.into(), Value::Object(saved.clone()));
        changes.tunnel = Some(saved);
    }

    let plan = plan_apply(conf, &changes, host).map_err(ApplyError::Problems)?;
    Ok(Prepared { overrides, changes, plan, reauth })
}
