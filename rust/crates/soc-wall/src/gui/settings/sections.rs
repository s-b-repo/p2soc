//! The Display, Proxy and Tunnel tabs: flat forms that become
//! `soc_state::DisplayForm` / `SectionForm`.

use super::Win;
use super::widgets::{check, combo, combo_text, entry, form_grid, note, scrolled, spin, spin_int, vbox, wd};
use gtk::prelude::*;
use serde_json::json;
use soc_core::guard::VALID_HOST_KEY_CHECKING;
use soc_core::{Dict, DictExt, Layout};
use soc_state::{DisplayForm, SectionForm};
use std::rc::Rc;

// ---- display -----------------------------------------------------------------

/// The Display tab's widgets.
pub struct DisplayTab {
    layout: gtk::ComboBoxText,
    gap: gtk::SpinButton,
    cols: gtk::SpinButton,
    rows: gtk::SpinButton,
    auto: gtk::CheckButton,
    width: gtk::SpinButton,
    height: gtk::SpinButton,
    fullscreen: gtk::CheckButton,
}

impl DisplayTab {
    /// `(cols, rows)` as currently typed.
    pub fn grid_size(&self) -> (u32, u32) {
        (
            u32::try_from(spin_int(&self.cols)).unwrap_or(1).max(1),
            u32::try_from(spin_int(&self.rows)).unwrap_or(1).max(1),
        )
    }

    pub fn form(&self) -> DisplayForm {
        DisplayForm {
            layout: combo_text(&self.layout, "auto"),
            gap: spin_int(&self.gap),
            cols: spin_int(&self.cols),
            rows: spin_int(&self.rows),
            auto: self.auto.is_active(),
            width: spin_int(&self.width),
            height: spin_int(&self.height),
            fullscreen: self.fullscreen.is_active(),
        }
    }
}

pub fn build_display(win: &Rc<Win>) -> gtk::Widget {
    let d = win.conf.borrow().display.clone();
    let boxv = vbox(10, 12);
    boxv.pack_start(
        &note(
            "Layout, spacing, grid size and resolution. Gap applies live; layout, grid size and resolution take \
             effect on the next restart.",
        ),
        false,
        false,
        0,
    );
    let layouts = [Layout::Auto.as_str(), Layout::Windows.as_str(), Layout::Single.as_str()];
    let tab = DisplayTab {
        layout: combo(&layouts, d.layout.as_str()),
        gap: spin(0, 64, 1, i64::from(d.gap)),
        cols: spin(1, 8, 1, i64::from(d.cols)),
        rows: spin(1, 8, 1, i64::from(d.rows)),
        auto: check("auto-detect from the screen", d.auto),
        width: spin(320, 16_384, 16, i64::from(d.width)),
        height: spin(320, 16_384, 16, i64::from(d.height)),
        fullscreen: check("fullscreen on start  (off = open as a windowed desktop app)", d.fullscreen),
    };
    // width/height are only read when auto is off, so the UI follows suit
    let manual = !tab.auto.is_active();
    tab.width.set_sensitive(manual);
    tab.height.set_sensitive(manual);
    {
        let (w, h) = (tab.width.clone(), tab.height.clone());
        tab.auto.connect_toggled(move |b| {
            w.set_sensitive(!b.is_active());
            h.set_sensitive(!b.is_active());
        });
    }
    boxv.pack_start(
        &form_grid(&[
            ("layout", wd(&tab.layout)),
            ("gap (px)", wd(&tab.gap)),
            ("cols", wd(&tab.cols)),
            ("rows", wd(&tab.rows)),
            ("resolution", wd(&tab.auto)),
            ("width", wd(&tab.width)),
            ("height", wd(&tab.height)),
            ("window", wd(&tab.fullscreen)),
        ]),
        false,
        false,
        0,
    );
    *win.display.borrow_mut() = Some(tab);
    boxv.upcast()
}

// ---- proxy -------------------------------------------------------------------

/// The Proxy tab's widgets and the form values it opened with.
pub struct ProxyTab {
    enabled: gtk::CheckButton,
    url: gtk::Entry,
    vault_item: gtk::Entry,
    ignore_hosts: gtk::Entry,
    base: Dict,
}

impl ProxyTab {
    fn values(&self) -> Dict {
        let mut form = Dict::new();
        form.insert("enabled".into(), json!(self.enabled.is_active()));
        form.insert("url".into(), json!(self.url.text().to_string()));
        form.insert("vault_item".into(), json!(self.vault_item.text().to_string()));
        form.insert("ignore_hosts".into(), json!(self.ignore_hosts.text().to_string()));
        form
    }

    pub fn section(&self) -> SectionForm {
        SectionForm { form: self.values(), base: self.base.clone() }
    }

    /// Apply saved the section: what is on screen is the new baseline.
    pub fn saved(&mut self, changed: bool) {
        if changed {
            self.base = self.values();
        }
    }
}

pub fn build_proxy(win: &Rc<Win>) -> gtk::Widget {
    let p = win.conf.borrow().proxy.clone();
    let boxv = vbox(10, 12);
    boxv.pack_start(
        &note(
            "Outbound HTTP(S)/SOCKS proxy for the panel browsers. Credentials live in the vault (set username + \
             password on the Credentials tab for this proxy's vault item). Changes apply on the next restart.",
        ),
        false,
        false,
        0,
    );
    let mut tab = ProxyTab {
        enabled: check("Proxy enabled", p.enabled),
        url: entry(&p.url, "http://host:port  (no embedded user:pass)"),
        vault_item: entry(&p.vault_item, "vault login holding the proxy creds (optional)"),
        ignore_hosts: entry(&p.ignore_hosts.join(", "), "host1, host2  (loopback is always bypassed)"),
        base: Dict::new(),
    };
    tab.url.set_input_purpose(gtk::InputPurpose::Url);
    boxv.pack_start(&tab.enabled, false, false, 0);
    boxv.pack_start(
        &form_grid(&[
            ("url", wd(&tab.url)),
            ("vault login", wd(&tab.vault_item)),
            ("ignore hosts", wd(&tab.ignore_hosts)),
        ]),
        false,
        false,
        0,
    );
    tab.base = tab.values();
    *win.proxy.borrow_mut() = Some(tab);
    boxv.upcast()
}

// ---- tunnel ------------------------------------------------------------------

/// The Tunnel tab's widgets and the form values it opened with.
pub struct TunnelTab {
    enabled: gtk::CheckButton,
    jump_host: gtk::Entry,
    identity: gtk::Entry,
    known_hosts: gtk::Entry,
    host_key_checking: gtk::ComboBoxText,
    forwards: gtk::TextView,
    base: Dict,
}

impl TunnelTab {
    fn values(&self) -> Dict {
        let mut form = Dict::new();
        form.insert("enabled".into(), json!(self.enabled.is_active()));
        form.insert("jump_host".into(), json!(self.jump_host.text().to_string()));
        form.insert("identity".into(), json!(self.identity.text().to_string()));
        form.insert("known_hosts".into(), json!(self.known_hosts.text().to_string()));
        form.insert("host_key_checking".into(), json!(combo_text(&self.host_key_checking, "yes")));
        let text = self.forwards.buffer().map_or_else(String::new, |b| {
            let (start, end) = b.bounds();
            b.text(&start, &end, false).map_or_else(String::new, |t| t.to_string())
        });
        form.insert("extra_forwards".into(), json!(text));
        form
    }

    pub fn section(&self) -> SectionForm {
        SectionForm { form: self.values(), base: self.base.clone() }
    }

    pub fn saved(&mut self, changed: bool) {
        if changed {
            self.base = self.values();
        }
    }
}

pub fn build_tunnel(win: &Rc<Win>) -> gtk::Widget {
    let t = win.conf.borrow().tunnel.clone();
    let boxv = vbox(10, 12);
    boxv.pack_start(
        &note(
            "SSH jump host used by panels in 'tunnel' mode. The SSH key sits in the host's filesystem (the jump host \
             trusts its public half). Apply pushes the change and restarts autossh-tunnel.",
        ),
        false,
        false,
        0,
    );
    let current = t.text("host_key_checking");
    let current = VALID_HOST_KEY_CHECKING.into_iter().find(|ok| *ok == current).unwrap_or("yes");
    let tab = TunnelTab {
        enabled: check("Tunnel enabled", t.flag("enabled", true)),
        jump_host: entry(&t.text("jump_host"), "user@host  (the SSH jump box)"),
        identity: entry(&t.text("identity"), "private key path on the wall"),
        known_hosts: entry(&t.text("known_hosts"), "known_hosts file pinning the jump box's key"),
        host_key_checking: combo(&VALID_HOST_KEY_CHECKING, current),
        forwards: gtk::TextView::new(),
        base: Dict::new(),
    };
    boxv.pack_start(&tab.enabled, false, false, 0);
    boxv.pack_start(
        &form_grid(&[
            ("jump host", wd(&tab.jump_host)),
            ("identity (key)", wd(&tab.identity)),
            ("known_hosts", wd(&tab.known_hosts)),
            ("host key check", wd(&tab.host_key_checking)),
        ]),
        false,
        false,
        0,
    );
    boxv.pack_start(&note("extra forwards  (one per line, bindaddr:port:host:port)"), false, false, 0);
    tab.forwards.set_monospace(true);
    tab.forwards.set_wrap_mode(gtk::WrapMode::None);
    if let Some(buffer) = tab.forwards.buffer() {
        buffer.set_text(&t.strings("extra_forwards").join("\n"));
    }
    let sw = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
    sw.set_min_content_height(70);
    sw.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    sw.add(&tab.forwards);
    boxv.pack_start(&sw, false, false, 0);
    let mut tab = tab;
    tab.base = tab.values();
    *win.tunnel.borrow_mut() = Some(tab);
    scrolled(&boxv).upcast()
}
