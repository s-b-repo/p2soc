//! The Panels tab: one editable card per tile, plus add / remove / move.
//!
//! The list itself lives in a [`soc_state::PanelSession`] (which tile was
//! added, removed or moved this session); this file owns the widgets and
//! turns them into [`PanelForm`]s for `prepare_apply`.

use super::logic::zones_markup;
use super::widgets::{button, check, combo, combo_text, entry, hbox, label, scrolled, spin, spin_int, vbox, wd};
use super::{Win, bind, on_click};
use gtk::prelude::*;
use serde_json::json;
use soc_core::{DictExt, Panel};
use soc_state::PanelForm;
use std::rc::Rc;

/// The keep-alive strategies in the order the drop-down lists them.
const STRATEGIES: [&str; 4] = ["none", "click", "reload", "xhr"];

/// One panel's widgets.
pub struct Row {
    pub id: String,
    frame: gtk::Frame,
    url: gtk::Entry,
    title: gtk::Entry,
    vault: gtk::Entry,
    tenant: gtk::Entry,
    user: gtk::Entry,
    pass: gtk::Entry,
    submit: gtk::Entry,
    marker: gtk::Entry,
    engine: gtk::ComboBoxText,
    allow_insecure: gtk::CheckButton,
    allow_media: gtk::CheckButton,
    proxy: gtk::CheckButton,
    ka_strat: gtk::ComboBoxText,
    ka_int: gtk::SpinButton,
}

impl Row {
    /// The values on screen, as `prepare_apply` takes them.
    fn form(&self) -> PanelForm {
        PanelForm {
            id: self.id.clone(),
            url: self.url.text().to_string(),
            title: self.title.text().to_string(),
            vault_item: self.vault.text().to_string(),
            engine: combo_text(&self.engine, "webkit"),
            selector_user: self.user.text().to_string(),
            selector_pass: self.pass.text().to_string(),
            selector_submit: self.submit.text().to_string(),
            login_marker: self.marker.text().to_string(),
            allow_insecure: self.allow_insecure.is_active(),
            allow_media: self.allow_media.is_active(),
            proxy: self.proxy.is_active(),
            keepalive_strategy: combo_text(&self.ka_strat, "none"),
            keepalive_interval: spin_int(&self.ka_int),
            tenant: self.tenant.text().to_string(),
        }
    }
}

/// The tab's widgets.
#[derive(Default)]
pub struct PanelsTab {
    list: Option<gtk::Box>,
    rows: Vec<Row>,
}

/// Build the tab.
pub fn build(win: &Rc<Win>) -> gtk::Widget {
    let outer = vbox(10, 8);
    let list = vbox(10, 0);
    win.panels.borrow_mut().list = Some(list.clone());
    outer.pack_start(&list, true, true, 0);
    rebuild(win);
    let add = button("＋ Add Panel", Some("soc-config-primary"));
    on_click(&add, win, add_panel);
    outer.pack_start(&add, false, false, 0);
    let page = scrolled(&outer);
    page.set_min_content_height(340);
    page.upcast()
}

/// Rebuild every card from the session (the first build, and after Import).
pub fn rebuild(win: &Rc<Win>) {
    let Some(list) = win.panels.borrow().list.clone() else { return };
    for row in win.panels.borrow_mut().rows.drain(..) {
        list.remove(&row.frame);
    }
    let panels: Vec<Panel> = win.session.borrow().panels().to_vec();
    for p in &panels {
        let row = panel_card(win, p);
        list.pack_start(&row.frame, false, false, 0);
        win.panels.borrow_mut().rows.push(row);
    }
    list.show_all();
}

/// The forms of the panels in session order.
pub fn forms(win: &Win) -> Vec<PanelForm> {
    let tab = win.panels.borrow();
    win.session.borrow().panels().iter().filter_map(|p| tab.rows.iter().find(|r| r.id == p.id)).map(Row::form).collect()
}

/// Add a blank panel in the first free grid cell. A panel outside the grid
/// would fail validation when the config is next loaded, so a full grid
/// refuses instead.
fn add_panel(win: &Rc<Win>) {
    let (cols, rows) = win.grid_size();
    let panel = win.session.borrow_mut().add_panel(cols, rows).cloned();
    let Some(panel) = panel else {
        return win.msg("The grid is full — raise cols/rows on the Display tab first.", true);
    };
    let row = panel_card(win, &panel);
    if let Some(list) = win.panels.borrow().list.as_ref() {
        list.pack_start(&row.frame, false, false, 0);
        list.show_all();
    }
    win.panels.borrow_mut().rows.push(row);
}

/// Remove a panel from the list; the next Apply drops it from the wall.
fn remove_panel(win: &Rc<Win>, id: &str) {
    if win.auth.reauth_required() && !win.require_reauth(&format!("removal of panel '{id}'")) {
        return;
    }
    win.session.borrow_mut().remove_panel(id);
    let mut tab = win.panels.borrow_mut();
    if let Some(pos) = tab.rows.iter().position(|r| r.id == id) {
        let row = tab.rows.remove(pos);
        if let Some(list) = tab.list.as_ref() {
            list.remove(&row.frame);
        }
    }
}

/// Move a panel up (-1) or down (+1): swaps cells with its neighbour. Typed
/// but unapplied edits in the other cards survive.
fn move_panel(win: &Rc<Win>, id: &str, direction: i32) {
    if !win.session.borrow_mut().move_panel(id, direction) {
        return;
    }
    let order: Vec<String> = win.session.borrow().panels().iter().map(|p| p.id.clone()).collect();
    let mut tab = win.panels.borrow_mut();
    tab.rows.sort_by_key(|r| order.iter().position(|o| *o == r.id).unwrap_or(usize::MAX));
    if let Some(list) = tab.list.as_ref() {
        for (i, row) in tab.rows.iter().enumerate() {
            list.reorder_child(&row.frame, i32::try_from(i).unwrap_or(i32::MAX));
        }
    }
}

fn zones_status(zones: &soc_core::Dict) -> String {
    zones_markup(zones)
}

fn panel_card(win: &Rc<Win>, p: &Panel) -> Row {
    let frame = gtk::Frame::new(Some(&format!("  {}  ", p.display_name())));
    let inner = vbox(6, 8);

    let title = entry(&p.title, "title");
    title.set_width_chars(12);
    title.set_hexpand(false);
    let url = entry(p.url.as_deref().unwrap_or(""), "https://host/…  (blank = not configured)");
    url.set_input_purpose(gtk::InputPurpose::Url);
    {
        let cb = bind(win, |w| w.apply());
        url.connect_activate(move |_| cb());
    }
    let vault = entry(&p.vault_item, "vault item");
    vault.set_width_chars(13);
    vault.set_hexpand(false);
    let engine = combo(&["webkit", "chromium"], p.engine.as_str());
    let tenant = entry(&p.tenant, "tenant (optional)");
    tenant.set_width_chars(16);
    tenant.set_hexpand(false);

    let g = gtk::Grid::new();
    g.set_column_spacing(8);
    g.set_row_spacing(4);
    let cells: [(&str, gtk::Widget); 5] = [
        ("title", wd(&title)),
        ("URL", wd(&url)),
        ("vault login", wd(&vault)),
        ("engine", wd(&engine)),
        ("tenant", wd(&tenant)),
    ];
    for (col, (name, w)) in cells.iter().enumerate() {
        let col = i32::try_from(col).unwrap_or(0);
        g.attach(&label(name, Some("soc-config-sub")), col, 0, 1, 1);
        g.attach(w, col, 1, 1, 1);
    }
    inner.pack_start(&g, false, false, 0);

    let exp = gtk::Expander::new(Some("Advanced — selectors + per-panel toggles (apply on restart)"));
    let adv = vbox(6, 6);
    let sel_row = hbox(6);
    let mk = |key: &str, hint: &str| {
        let e = entry(&p.selectors.text(key), hint);
        e.set_width_chars(13);
        sel_row.pack_start(&e, true, true, 0);
        e
    };
    let (user, pass, submit) = (mk("user", "user CSS"), mk("pass", "pass CSS"), mk("submit", "submit CSS"));
    let marker = entry(&p.login_marker, "login marker");
    marker.set_width_chars(13);
    sel_row.pack_start(&marker, true, true, 0);
    adv.pack_start(&sel_row, false, false, 0);

    let toggles = hbox(12);
    let allow_insecure = check("allow self-signed TLS", p.allow_insecure);
    allow_insecure.set_tooltip_text(Some(
        "Accept self-signed certs on this panel only (trusted LAN). Off by default — system CAs are enforced.",
    ));
    let allow_media = check("allow media (WebGL/audio/video)", p.allow_media);
    allow_media
        .set_tooltip_text(Some("Re-enables WebGL/WebAudio/<video>. Off by default to save RAM/GPU on 1 GB boards."));
    let proxy = check("use global proxy (if any)", p.proxy);
    proxy.set_tooltip_text(Some("Off = this panel ALWAYS hits the URL directly, bypassing the corporate proxy."));
    for c in [&allow_insecure, &allow_media, &proxy] {
        toggles.pack_start(c, false, false, 0);
    }
    adv.pack_start(&toggles, false, false, 0);

    let ka = hbox(6);
    let ka_strat = combo(&STRATEGIES, p.keepalive.strategy.as_str());
    let ka_int = spin(1, 86_400, 30, i64::from(p.keepalive.interval_sec));
    ka.pack_start(&label("keepalive:", None), false, false, 0);
    ka.pack_start(&ka_strat, false, false, 0);
    ka.pack_start(&label("every (sec):", None), false, false, 0);
    ka.pack_start(&ka_int, false, false, 0);
    adv.pack_start(&ka, false, false, 0);

    // Click-zone calibration: the last-resort login fallback when the CSS
    // selectors AND the text-pattern heuristic both miss.
    let cz = hbox(6);
    let zones = label("", Some("soc-config-sub"));
    zones.set_hexpand(true);
    zones.set_markup(&zones_status(&p.login_zones));
    let calibrate = button("Calibrate login zones", None);
    calibrate.set_tooltip_text(Some(
        "Overlay a crosshair on the panel; click the username, password and submit elements. Ratios are stored, so \
         a resize keeps them accurate.",
    ));
    let clear = button("Clear zones", Some("destructive-action"));
    clear.set_tooltip_text(Some(
        "Drop the saved zones from this panel. The wall falls back to selectors + text-pattern heuristics.",
    ));
    {
        let (id, zones) = (p.id.clone(), zones.clone());
        on_click(&calibrate, win, move |w| calibrate_panel(w, &id, &zones));
    }
    {
        let (id, zones) = (p.id.clone(), zones.clone());
        on_click(&clear, win, move |w| clear_zones(w, &id, &zones));
    }
    cz.pack_start(&zones, true, true, 0);
    cz.pack_start(&calibrate, false, false, 0);
    cz.pack_start(&clear, false, false, 0);
    adv.pack_start(&cz, false, false, 0);
    exp.add(&adv);
    inner.pack_start(&exp, false, false, 0);

    let buttons = hbox(4);
    buttons.set_halign(gtk::Align::End);
    let load = button("▶ Load now", None);
    load.set_tooltip_text(Some("Preview this URL on the wall right now, without saving"));
    {
        let (id, url) = (p.id.clone(), url.clone());
        on_click(&load, win, move |w| preview_url(w, &id, &url));
    }
    let up = button("↑ Up", None);
    let down = button("↓ Down", None);
    let remove = button("✕ Remove", Some("destructive-action"));
    for (btn, dir) in [(&up, -1), (&down, 1)] {
        let id = p.id.clone();
        on_click(btn, win, move |w| move_panel(w, &id, dir));
    }
    {
        let id = p.id.clone();
        on_click(&remove, win, move |w| remove_panel(w, &id));
    }
    for b in [&load, &up, &down, &remove] {
        buttons.pack_start(b, false, false, 0);
    }
    inner.pack_start(&buttons, false, false, 0);
    frame.add(&inner);

    Row {
        id: p.id.clone(),
        frame,
        url,
        title,
        vault,
        tenant,
        user,
        pass,
        submit,
        marker,
        engine,
        allow_insecure,
        allow_media,
        proxy,
        ka_strat,
        ka_int,
    }
}

/// Repoint the panel on the wall at the typed URL without saving it.
fn preview_url(win: &Rc<Win>, id: &str, url: &gtk::Entry) {
    let text = url.text().to_string();
    let text = text.trim();
    if !soc_core::guard::valid_http_url(text, false) {
        return win.msg("only http:// or https:// URLs can be loaded", true);
    }
    if (win.ctx.set_panel_url)(id, text) {
        win.msg(&format!("{id}: loading {text} (not saved — press Apply to keep it)"), false);
    } else {
        win.msg(&format!("{id}: not on the wall yet — Apply first"), true);
    }
}

/// Per-panel Calibrate button. The host persists the zones; this reflects
/// them when the operator finishes.
fn calibrate_panel(win: &Rc<Win>, id: &str, status: &gtk::Label) {
    let Some(calibrate) = win.ctx.calibrate.clone() else {
        return win.alert(
            "Calibrate unavailable",
            "Calibrate is unavailable in this session: the wall was not launched with a calibrate-capable host.",
            true,
        );
    };
    win.toast(&format!("{id}: click USER → PASS → SUBMIT on the panel (Esc cancels)"));
    let (weak, status, id) = (Rc::downgrade(win), status.clone(), id.to_string());
    calibrate(
        &id.clone(),
        Box::new(move |zones| {
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            match zones {
                None => win.toast(&format!("{id}: calibration cancelled / timed out")),
                Some(zones) => {
                    let dict = zones.as_object().cloned().unwrap_or_else(soc_core::Dict::new);
                    status.set_markup(&zones_status(&dict));
                    win.toast(&format!("{id}: calibrated ✓ ({} zones)", dict.len()));
                }
            }
        }),
    );
}

/// Clear the panel's zones. Gated by re-auth, like Remove VPN. Written as an
/// explicit empty override: zones from the source config would otherwise
/// return at boot.
fn clear_zones(win: &Rc<Win>, id: &str, status: &gtk::Label) {
    if !win.require_reauth(&format!("clearing login zones on '{id}'")) {
        return;
    }
    match (win.ctx.set_login_zones)(id, &json!({})) {
        Ok(had) => {
            status.set_markup(&zones_status(&soc_core::Dict::new()));
            win.toast(&if had { format!("{id}: login zones cleared") } else { format!("{id}: no zones to clear") });
        }
        Err(e) => win.alert(
            "Save failed",
            &format!("Could not save settings: {e}\n\nCheck that {} is writable.", win.ctx.state_dir.display()),
            true,
        ),
    }
}
