//! The VPN tab: one collapsible section per VPN, add / remove / edit.
//!
//! Each section is a flat form ([`soc_core::Dict`] of widget values) that
//! `soc_state::forms::collect_vpn` turns into the override entry and the
//! merged VPN. A removed section keeps its slot (dead) so the other sections'
//! indices stay put.

use super::logic::{default_vpn_item, next_vpn_name, vpn_header_markup};
use super::widgets::{
    button, check, combo, combo_text, entry, form_grid, frame, hbox, label, note, scrolled, secret_entry, spin,
    spin_int, vbox, wd,
};
use super::{Win, creds, on_click};
use gtk::prelude::*;
use serde_json::{Value, json};
use soc_core::{Dict, DictExt};
use soc_state::VpnForms;
use soc_state::forms::VpnEdit;
use std::rc::Rc;

const TYPES: [&str; 4] = ["fortinet", "openvpn", "wireguard", "inode"];

/// One VPN section's widgets.
struct VpnW {
    enabled: gtk::CheckButton,
    kind: gtk::ComboBoxText,
    name: gtk::Entry,
    gateway: gtk::Entry,
    port: gtk::SpinButton,
    vault_item: gtk::Entry,
    config: gtk::Entry,
    domain: gtk::Entry,
    realm: gtk::Entry,
    trusted_cert: gtk::Entry,
    ready_probe: gtk::Entry,
    insecure: gtk::CheckButton,
    config_from_vault: gtk::CheckButton,
    ead: gtk::CheckButton,
    split_tunnel: gtk::CheckButton,
    ca_file: gtk::Entry,
    client_cert: gtk::Entry,
    client_key: gtk::Entry,
    spa_key: gtk::Entry,
    spa_aid: gtk::Entry,
    spa_ports: gtk::Entry,
    spa_knock_port: gtk::SpinButton,
    captcha_retries: gtk::SpinButton,
    mac: gtk::Entry,
    language: gtk::Entry,
    user: gtk::Entry,
    pass: gtk::Entry,
}

impl VpnW {
    /// Flat values of the section.
    fn form(&self) -> Dict {
        let text = |e: &gtk::Entry| json!(e.text().to_string());
        let mut f = Dict::new();
        let mut put = |k: &str, v: Value| {
            f.insert(k.to_string(), v);
        };
        put("name", text(&self.name));
        put("enabled", json!(self.enabled.is_active()));
        put("type", json!(combo_text(&self.kind, "fortinet")));
        put("gateway", text(&self.gateway));
        put("port", json!(spin_int(&self.port)));
        put("vault_item", text(&self.vault_item));
        put("config", text(&self.config));
        put("domain", text(&self.domain));
        put("realm", text(&self.realm));
        put("trusted_cert", text(&self.trusted_cert));
        put("ready_probe", text(&self.ready_probe));
        put("insecure", json!(self.insecure.is_active()));
        put("config_from_vault", json!(self.config_from_vault.is_active()));
        put("ead", json!(self.ead.is_active()));
        put("split_tunnel", json!(self.split_tunnel.is_active()));
        put("ca_file", text(&self.ca_file));
        put("client_cert", text(&self.client_cert));
        put("client_key", text(&self.client_key));
        put("spa_key", text(&self.spa_key));
        put("spa_aid", text(&self.spa_aid));
        put("spa_ports", text(&self.spa_ports));
        put("spa_knock_port", json!(spin_int(&self.spa_knock_port)));
        put("captcha_retries", json!(spin_int(&self.captcha_retries)));
        put("mac", text(&self.mac));
        put("language", text(&self.language));
        f
    }
}

struct VpnRow {
    alive: bool,
    w: VpnW,
    expander: gtk::Expander,
    /// The form as loaded or last saved; `None` for a VPN added here.
    base: Option<Dict>,
    /// The whole VPN as loaded or last saved (`{}` for a new one).
    before: Dict,
}

/// The tab's state.
pub struct VpnTab {
    list: gtk::Box,
    rows: Vec<VpnRow>,
    /// A VPN was removed since the last save.
    dirty: bool,
    /// VPN names when the window opened.
    names_open: Vec<String>,
}

impl VpnTab {
    /// The live VPNs as last loaded or saved.
    pub fn entries(&self) -> Vec<Dict> {
        self.rows.iter().filter(|r| r.alive).map(|r| r.before.clone()).collect()
    }

    /// The tab as `prepare_apply` takes it.
    pub fn forms(&self) -> VpnForms {
        VpnForms {
            rows: self
                .rows
                .iter()
                .enumerate()
                .filter(|(_, r)| r.alive)
                .map(|(index, r)| VpnEdit {
                    index,
                    form: r.w.form(),
                    base_form: r.base.clone(),
                    before: r.before.clone(),
                })
                .collect(),
            removed_any: self.dirty,
            names_open: self.names_open.clone(),
        }
    }

    /// Apply saved the VPN list (`merged`, in section order): what is on screen
    /// is the new baseline.
    pub fn saved(&mut self, merged: Option<&[Dict]>) {
        let Some(merged) = merged else { return };
        for (row, vpn) in self.rows.iter_mut().filter(|r| r.alive).zip(merged) {
            row.base = Some(row.w.form());
            row.before = vpn.clone();
        }
        self.dirty = false;
    }
}

pub fn build(win: &Rc<Win>) -> gtk::Widget {
    let outer = vbox(10, 12);
    outer.pack_start(
        &note(
            "Supervised VPNs. Credentials live in the vault: save them here, or on the Credentials tab for each VPN's \
             vault item. Apply pushes the config into the vault and restarts the VPN service(s).",
        ),
        false,
        false,
        0,
    );
    let header = hbox(8);
    let add = button("+ Add VPN", None);
    add.set_tooltip_text(Some(
        "Add a new VPN section. It starts disabled: fill in the name, gateway and vault item, then enable it.",
    ));
    on_click(&add, win, add_vpn);
    header.pack_end(&add, false, false, 0);
    outer.pack_start(&header, false, false, 0);

    let list = vbox(8, 0);
    outer.pack_start(&list, false, false, 0);
    let names_open: Vec<String> =
        win.ctx.config.vpns.iter().map(|v| v.text("name")).filter(|n| !n.is_empty()).collect();
    *win.vpn.borrow_mut() = Some(VpnTab { list: list.clone(), rows: Vec::new(), dirty: false, names_open });
    let vpns = win.conf.borrow().vpns.clone();
    for (idx, v) in vpns.iter().enumerate() {
        let row = section(win, v, idx, false);
        list.pack_start(&row.expander, false, false, 0);
        // the rest would sprawl on small displays
        row.expander.set_expanded(idx == 0);
        if let Some(tab) = win.vpn.borrow_mut().as_mut() {
            tab.rows.push(row);
        }
    }
    scrolled(&outer).upcast()
}

/// `+ Add VPN`: append a blank, disabled section.
fn add_vpn(win: &Rc<Win>) {
    let (live, used, slots) = {
        let tab = win.vpn.borrow();
        let Some(tab) = tab.as_ref() else { return };
        let live: Vec<&VpnRow> = tab.rows.iter().filter(|r| r.alive).collect();
        let used: Vec<String> = live.iter().map(|r| r.w.name.text().to_string()).collect();
        (live.len(), used, tab.rows.len())
    };
    if live >= soc_core::MAX_VPNS {
        return win.msg(&format!("At most {} VPNs are supported.", soc_core::MAX_VPNS), true);
    }
    let name = next_vpn_name(&used, slots);
    let mut v = Dict::new();
    v.insert("name".into(), json!(name));
    v.insert("enabled".into(), json!(false));
    v.insert("type".into(), json!("fortinet"));
    let row = section(win, &v, slots, true);
    row.expander.set_expanded(true);
    if let Some(tab) = win.vpn.borrow_mut().as_mut() {
        tab.list.pack_start(&row.expander, false, false, 0);
        tab.rows.push(row);
        tab.list.show_all();
    }
}

/// Remove this VPN: re-auth, then confirm, then drop the section (the next
/// Apply drops it from the config). Its vault item is intentionally NOT
/// deleted: the Credentials tab does that, with its own re-auth.
fn remove_vpn(win: &Rc<Win>, idx: usize) {
    let name = {
        let tab = win.vpn.borrow();
        let Some(row) = tab.as_ref().and_then(|t| t.rows.get(idx)).filter(|r| r.alive) else { return };
        let n = row.w.name.text().trim().to_string();
        if n.is_empty() { format!("vpn-{}", idx + 1) } else { n }
    };
    if !win.require_reauth(&format!("removal of VPN '{name}'")) {
        return;
    }
    if !win.ask(
        &format!("Remove VPN '{name}'?"),
        &format!(
            "VPN '{name}' will be removed from the config on the next Apply. The vault credential item is NOT \
             deleted by this action — use the Credentials tab for that."
        ),
    ) {
        return;
    }
    // One supervisor unit runs every VPN and Apply restarts it on the new
    // list; what can go wrong is that it may not be allowed to, so say so now.
    if !(win.ctx.caps)().can_restart_services {
        win.alert(
            "VPN supervisor still running",
            &format!(
                "Could not stop the supervisor for VPN '{name}': no NOPASSWD sudo for systemctl, so forti-vpn must be \
                 restarted by hand after Apply."
            ),
            true,
        );
    }
    if let Some(tab) = win.vpn.borrow_mut().as_mut() {
        if let Some(row) = tab.rows.get_mut(idx) {
            row.alive = false;
            row.base = None;
            tab.list.remove(&row.expander);
            tab.dirty = true;
        }
    }
}

/// Save the section's inline credentials to its vault item (defaulting that
/// to `SOC VPN <name>`), then scrub the password entry whatever happened.
fn save_inline(win: &Rc<Win>, idx: usize) {
    let grabbed = {
        let tab = win.vpn.borrow();
        tab.as_ref().and_then(|t| t.rows.get(idx)).map(|r| {
            let w = &r.w;
            let pass = super::widgets::secret_text(&w.pass);
            w.pass.set_text("");
            (super::widgets::secret_text(&w.user), pass, w.vault_item.clone(), w.name.text().to_string())
        })
    };
    let Some((user, pass, item_entry, vpn_name)) = grabbed else { return };
    if user.is_empty() && pass.is_empty() {
        return win.alert(
            "Nothing to save",
            "Set a username AND a password before saving inline VPN credentials.",
            true,
        );
    }
    if win.auth.reauth_required() && !win.require_reauth("saving VPN credentials") {
        return;
    }
    let item = default_vpn_item(&item_entry.text(), &vpn_name, idx);
    item_entry.set_text(&item);
    creds::write_login(win, &item, user, pass, None, |win, msg, ok| {
        if ok {
            win.alert(
                "Vault save succeeded",
                &format!("{msg}\n\nThe wall will pick up the new credential on the next login attempt."),
                false,
            );
        } else {
            win.alert("Vault save failed", &msg, true);
        }
    });
}

/// Build the collapsible section for VPN `v` in slot `idx`.
fn section(win: &Rc<Win>, v: &Dict, idx: usize, is_new: bool) -> VpnRow {
    let default_name = {
        let n = v.text("name");
        if n.is_empty() { format!("vpn-{}", idx + 1) } else { n }
    };
    let kind_now = {
        let t = v.text("type");
        if t.is_empty() { "fortinet".to_string() } else { t }
    };
    let header = gtk::Label::new(None);
    header.set_markup(&vpn_header_markup(&default_name, idx, &kind_now));
    header.set_xalign(0.0);
    let expander = gtk::Expander::new(None);
    expander.set_label_widget(Some(&header));
    expander.set_resize_toplevel(true);

    let int_or = |key: &str, default: i64| if v.contains_key(key) { v.int(key) } else { default };
    let w = VpnW {
        enabled: check("VPN enabled", v.truthy("enabled")),
        kind: combo(&TYPES, &kind_now),
        name: entry(&default_name, "name (top-bar pill label)"),
        gateway: entry(&v.text("gateway"), "gateway host (fortinet / inode)"),
        port: spin(0, 65_535, 1, int_or("port", 443)),
        vault_item: entry(&v.text("vault_item"), "vault login (auto-named 'SOC VPN <name>' if blank)"),
        config: entry(&v.text("config"), ".ovpn/.conf path, or the iNode client dir"),
        domain: entry(&v.text("domain"), "auth domain (inode)"),
        realm: entry(&v.text("realm"), "realm (fortinet)"),
        trusted_cert: entry(&v.text("trusted_cert"), "gateway cert sha256 pin"),
        ready_probe: entry(&v.text("ready_probe"), "host:port reachable only over the VPN"),
        insecure: check("skip TLS verify (inode — trusted LAN only)", v.truthy("insecure")),
        config_from_vault: check(
            "config from the vault item's Notes (openvpn / wireguard)",
            v.truthy("config_from_vault"),
        ),
        ead: check("send EAD host-check ack after login (--ead)", v.truthy("ead")),
        split_tunnel: check("split tunnel — only route gateway subnets (--split-tunnel)", v.flag("split_tunnel", true)),
        ca_file: entry(&v.text("ca_file"), "custom CA bundle path (--cafile)"),
        client_cert: entry(&v.text("client_cert"), "mutual-TLS client cert PEM (--client-cert)"),
        client_key: entry(&v.text("client_key"), "mutual-TLS client key PEM (--client-key)"),
        spa_key: entry(&v.text("spa_key"), "SPA/HOTP key hex (--spa-key, for SDP)"),
        spa_aid: entry(&v.text("spa_aid"), "SPA client AID hex (--spa-aid)"),
        spa_ports: entry(&v.text("spa_ports"), "comma-sep knock ports (--spa-ports)"),
        spa_knock_port: spin(0, 65_535, 1, int_or("spa_knock_port", 0)),
        captcha_retries: spin(0, 200, 1, int_or("captcha_retries", 40)),
        mac: entry(&v.text("mac"), "override MAC sent to gateway (--mac)"),
        language: entry(&v.text("language"), "auth language: cn | en (--language)"),
        user: entry("", "VPN username (saved to the vault item; never read back)"),
        pass: secret_entry("VPN password (write-only)"),
    };
    // a shared secret, at the glass
    w.spa_key.set_visibility(false);

    // The header follows the name and type live.
    {
        let (name, kind, header) = (w.name.clone(), w.kind.clone(), header.clone());
        let refresh = move || {
            header.set_markup(&vpn_header_markup(&name.text(), idx, &combo_text(&kind, "")));
        };
        let again = refresh.clone();
        w.name.connect_changed(move |_| refresh());
        w.kind.connect_changed(move |_| again());
    }

    let boxv = vbox(6, 8);
    boxv.pack_start(&w.enabled, false, false, 0);
    boxv.pack_start(
        &form_grid(&[
            ("name", wd(&w.name)),
            ("type", wd(&w.kind)),
            ("gateway", wd(&w.gateway)),
            ("port", wd(&w.port)),
            ("vault login", wd(&w.vault_item)),
            ("config", wd(&w.config)),
            ("domain", wd(&w.domain)),
            ("realm", wd(&w.realm)),
            ("trusted_cert", wd(&w.trusted_cert)),
            ("ready_probe", wd(&w.ready_probe)),
        ]),
        false,
        false,
        0,
    );
    boxv.pack_start(&w.insecure, false, false, 0);
    boxv.pack_start(&w.config_from_vault, false, false, 0);
    boxv.pack_start(
        &label("iNode (H3C SSL VPN) — gateway login + tunnel flags", Some("soc-config-sub")),
        false,
        false,
        8,
    );
    boxv.pack_start(&w.ead, false, false, 0);
    boxv.pack_start(&w.split_tunnel, false, false, 0);
    boxv.pack_start(
        &form_grid(&[
            ("CA file", wd(&w.ca_file)),
            ("client cert", wd(&w.client_cert)),
            ("client key", wd(&w.client_key)),
            ("SPA key", wd(&w.spa_key)),
            ("SPA AID", wd(&w.spa_aid)),
            ("SPA ports", wd(&w.spa_ports)),
            ("SPA knock port", wd(&w.spa_knock_port)),
            ("CAPTCHA retries", wd(&w.captcha_retries)),
            ("MAC", wd(&w.mac)),
            ("language", wd(&w.language)),
        ]),
        false,
        false,
        0,
    );

    // Inline credentials write straight to the vault item; they are never read
    // back (no re-display of stored secrets here).
    let cred_box = vbox(4, 6);
    cred_box.pack_start(&w.user, false, false, 0);
    cred_box.pack_start(&w.pass, false, false, 0);
    let save = button("Save inline creds to vault", None);
    save.set_tooltip_text(Some(
        "Writes to the vault item named in 'vault login'; auto-names it 'SOC VPN <name>' if blank.",
    ));
    on_click(&save, win, move |win| save_inline(win, idx));
    cred_box.pack_start(&save, false, false, 0);
    boxv.pack_start(&frame("inline credentials → vault", &cred_box), false, false, 0);

    let remove = button("Remove this VPN", Some("destructive-action"));
    remove.set_tooltip_text(Some(
        "Removes the section from the config (next Apply drops it). The vault credential item is left alone.",
    ));
    on_click(&remove, win, move |win| remove_vpn(win, idx));
    boxv.pack_start(&remove, false, false, 0);
    expander.add(&boxv);

    let base = (!is_new).then(|| w.form());
    let before = if is_new { Dict::new() } else { v.clone() };
    VpnRow { alive: true, w, expander, base, before }
}
