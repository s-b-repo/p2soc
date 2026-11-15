//! The on-screen Settings window (port of `configwin.py`).
//!
//! A floating, non-modal, always-on-top utility window with nine tabs: Panels,
//! Credentials, Display, VPN, Proxy, Tunnel, Actions, Security and Status.
//! Tabs other than Panels are built the first time they are looked at (the box
//! has 1 GB of RAM and the window is rarely opened). When a settings PIN or
//! TOTP is enrolled the window opens on a gate page first.
//!
//! The window knows nothing of the host: everything it needs arrives in a
//! [`SettingsContext`]. All the logic that is not a widget lives in
//! `soc-state` (what to save, what to refuse, which actions to perform); this
//! file only collects the form, calls it and shows the answer. Every vault,
//! PAM or network call runs on a worker thread and comes back through
//! [`widgets::in_worker`], so the main loop never waits on I/O.

mod actions;
mod creds;
mod dialogs;
pub mod logic;
mod panels;
mod sections;
mod security;
mod vpn;
mod widgets;

use gtk::prelude::*;
use serde_json::Value;
use soc_core::{Config, CredSource, Dict};
use soc_state::apply::ApplyError;
use soc_state::locker::LockStore;
use soc_state::{
    ApplyForm, AuthOutcome, Budget, Changes, HostCaps, Overrides, PanelSession, Schedule, SettingsAuth,
    plan::ApplyReport, plan::WriteBack, policy, prepare_apply, unix_now,
};
use soc_vault::{Session, SessionOptions, Vault};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
pub use widgets::UiResult;
use widgets::{button, hbox, in_worker, label, set_status, vbox};
use zeroize::Zeroizing;

/// How the calibration overlay reports back: `Some(zones)` when the operator
/// finished, `None` when it was cancelled or timed out. Called on the GTK
/// thread. The host persists the zones itself.
pub type CalibrateDone = Box<dyn FnOnce(Option<Value>)>;

/// Starts the click-zone calibration overlay on a panel.
pub type CalibrateFn = Rc<dyn Fn(&str, CalibrateDone)>;

/// Repoints a panel live: `(panel id, url)`, `false` for an unknown panel or a bad URL.
pub type SetUrlFn = Rc<dyn Fn(&str, &str) -> bool>;

/// Persists login zones: `(panel id, zones)`; says whether the panel had zones before.
pub type SetZonesFn = Rc<dyn Fn(&str, &Value) -> UiResult<bool>>;

/// The vault, as far as the Credentials tab and the config write-back need it.
pub struct VaultAccess {
    pub vault: Arc<Vault>,
    pub url: String,
    pub email: String,
    pub backend: String,
    /// The vault item holding the wall config note (`SOC_CONFIG_VAULT_ITEM`).
    pub config_item: String,
    /// The master password is host-sealed (so the wall can unseal it itself).
    pub sealed: bool,
    /// Unseals the host-bound master (slow: run it off the GTK thread).
    pub sealed_master: Arc<dyn Fn() -> Option<Zeroizing<String>> + Send + Sync>,
}

impl VaultAccess {
    /// Whether the config could be written back to the vault note right now.
    pub fn write_back(&self) -> WriteBack {
        WriteBack::precheck(&self.backend, &self.config_item, &self.url, &self.email, self.sealed)
    }

    /// A session that can write items. Blocking: call it from a worker. The
    /// vault's own session is used when it has one; otherwise the host-sealed
    /// master (or, when nothing is sealed, `typed_master`) logs in afresh.
    pub fn write_session(&self, typed_master: &str) -> UiResult<Arc<Session>> {
        let vault_session = self.vault.session();
        if vault_session.is_ok() {
            return vault_session.map_err(|e| e.to_string());
        }
        let master = if self.sealed { (self.sealed_master)() } else { None };
        let master = master.unwrap_or_else(|| Zeroizing::new(typed_master.to_string()));
        if self.email.is_empty() || master.is_empty() {
            return Err(
                "need the vault email + master password to write: set SOC_VAULT_EMAIL via setup, and seal the \
                        master (setup first-run) or type it on the Credentials tab"
                    .to_string(),
            );
        }
        Session::login(&self.url, &self.email, &master, &SessionOptions::from_env())
            .map(Arc::new)
            .map_err(|e| e.to_string())
    }
}

/// Everything the window needs from its host.
pub struct SettingsContext {
    /// The live config when the window opens.
    pub config: Config,
    /// Where `overrides.json`, the PIN/TOTP files and the lockout budgets live.
    pub state_dir: PathBuf,
    /// What the host can do right now (single wall, may restart services).
    pub caps: Rc<dyn Fn() -> HostCaps>,
    /// Apply saved changes to the running wall.
    pub apply: Rc<dyn Fn(&Changes) -> ApplyReport>,
    /// Reload every panel in place; returns how many.
    pub reload_panels: Rc<dyn Fn() -> usize>,
    /// Soft-restart the wall.
    pub restart_wall: Rc<dyn Fn()>,
    /// Restart the VPN supervisor.
    pub reconnect_vpn: Rc<dyn Fn()>,
    /// Repoint a panel live without saving (`false`: unknown panel / bad URL).
    pub set_panel_url: SetUrlFn,
    /// Ids of panels whose auto-login burnt its retries (stale selectors).
    pub login_stats: Rc<dyn Fn() -> Vec<String>>,
    /// Write the running config back to the vault note; says whether the
    /// upload was started or deferred.
    pub push_config_to_vault: Rc<dyn Fn() -> WriteBack>,
    /// Persist new (or, when empty, cleared) login zones for a panel; returns
    /// whether the panel had zones before.
    pub set_login_zones: SetZonesFn,
    /// Start calibration; `None` hides the capability (the button explains).
    pub calibrate: Option<CalibrateFn>,
    /// Engage the kiosk lock (closes this window first).
    pub lock_wall: Option<Rc<dyn Fn()>>,
    /// Open the live VPN-log viewer.
    pub show_vpn_log: Option<Rc<dyn Fn()>>,
    /// Reads items (cached, any backend).
    pub creds: Arc<dyn CredSource>,
    /// Writes and deletes items; `None` disables those controls.
    pub vault: Option<Arc<VaultAccess>>,
    /// `SOC_ONSCREEN_CONFIG` allows the window at all.
    pub onscreen_enabled: bool,
    /// `SOC_CONFIG_REQUIRE_PIN`.
    pub require_pin: bool,
    /// Called once when the window is destroyed.
    pub on_close: Rc<dyn Fn()>,
}

struct Gate {
    entry: gtk::Entry,
    err: gtk::Label,
    button: gtk::Button,
}

type TabBuilder = fn(&Rc<Win>) -> gtk::Widget;

/// The window's shared state. Widgets of tabs not built yet stay `None`, and
/// Apply skips those sections.
pub(crate) struct Win {
    pub ctx: SettingsContext,
    pub window: gtk::Window,
    stack: gtk::Stack,
    gate: Gate,
    pub auth: Arc<SettingsAuth>,
    pub lock: Arc<LockStore>,
    pub os_budget: Budget,
    unlocked: Cell<bool>,
    pub closed: Cell<bool>,
    disabled: bool,
    pub conf: RefCell<Config>,
    pub session: RefCell<PanelSession>,
    form_msg: RefCell<Option<gtk::Label>>,
    lazy: RefCell<HashMap<u32, TabBuilder>>,
    form_page: RefCell<Option<gtk::Widget>>,
    pub panels: RefCell<panels::PanelsTab>,
    pub display: RefCell<Option<sections::DisplayTab>>,
    pub vpn: RefCell<Option<vpn::VpnTab>>,
    pub proxy: RefCell<Option<sections::ProxyTab>>,
    pub tunnel: RefCell<Option<sections::TunnelTab>>,
    pub cred: RefCell<Option<creds::CredTab>>,
}

/// A callback holding only a weak reference to the window.
pub(crate) fn bind(win: &Rc<Win>, f: impl Fn(&Rc<Win>) + 'static) -> impl Fn() + 'static {
    let weak = Rc::downgrade(win);
    move || {
        if let Some(w) = weak.upgrade() {
            f(&w);
        }
    }
}

/// Connect a button to a window method.
pub(crate) fn on_click(btn: &gtk::Button, win: &Rc<Win>, f: impl Fn(&Rc<Win>) + 'static) {
    let cb = bind(win, f);
    btn.connect_clicked(move |_| cb());
}

/// The single Settings window.
#[derive(Clone)]
pub struct SettingsWindow {
    win: Rc<Win>,
}

impl SettingsWindow {
    /// Build and show the window.
    pub fn open(ctx: SettingsContext) -> SettingsWindow {
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_title("SOC wall — settings");
        let auth = Arc::new(SettingsAuth::new(&ctx.state_dir));
        let lock = Arc::new(LockStore::new(&ctx.state_dir));
        let disabled = !ctx.onscreen_enabled;
        let unlocked = !disabled && policy::gate_unlocked(ctx.require_pin, auth.reauth_required());
        let gate = Gate {
            entry: gtk::Entry::new(),
            err: label("", Some("soc-config-error")),
            button: button("Unlock", Some("soc-config-primary")),
        };
        let win = Rc::new(Win {
            os_budget: Budget::new(&ctx.state_dir, "os", Schedule::Gate),
            session: RefCell::new(PanelSession::new(&ctx.config.panels)),
            conf: RefCell::new(ctx.config.clone()),
            ctx,
            window,
            stack: gtk::Stack::new(),
            gate,
            auth,
            lock,
            unlocked: Cell::new(unlocked),
            closed: Cell::new(false),
            disabled,
            form_msg: RefCell::default(),
            lazy: RefCell::default(),
            form_page: RefCell::default(),
            panels: RefCell::default(),
            display: RefCell::default(),
            vpn: RefCell::default(),
            proxy: RefCell::default(),
            tunnel: RefCell::default(),
            cred: RefCell::default(),
        });
        win.build();
        SettingsWindow { win }
    }

    /// Bring the window to the front.
    pub fn present(&self) {
        self.win.window.present();
    }

    /// Close the window (runs the close callback).
    pub fn close(&self) {
        self.win.window.close();
    }
}

impl Win {
    fn build(self: &Rc<Self>) {
        let w = &self.window;
        w.set_keep_above(true);
        // Floating, always-on-top, NOT modal: a stray click on a panel behind a
        // modal grab is read by some WMs as a dismiss, and calibration needs
        // clicks to reach the panels while this stays open.
        w.set_modal(false);
        w.set_type_hint(gdk::WindowTypeHint::Utility);
        w.set_skip_taskbar_hint(true);
        w.set_skip_pager_hint(true);
        w.set_deletable(true);
        w.set_position(gtk::WindowPosition::Center);
        w.set_default_size(820, 600);
        w.set_resizable(true);
        w.style_context().add_class("soc-config");
        {
            let weak = Rc::downgrade(self);
            w.connect_destroy(move |_| {
                if let Some(win) = weak.upgrade() {
                    win.closed.set(true);
                    (win.ctx.on_close)();
                }
            });
        }
        w.connect_key_press_event(|win, event| {
            if event.keyval() == gdk::keys::constants::Escape {
                win.close();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });

        self.stack.set_transition_type(gtk::StackTransitionType::None);
        w.add(&self.stack);
        self.stack.add_named(&self.build_gate_page(), "gate");
        // The form is only built once the gate has opened: nothing behind it
        // exists for a passer-by to reach, and a locked window costs no RAM.
        if self.unlocked.get() {
            self.enter_form();
        } else {
            self.stack.set_visible_child_name("gate");
        }
        // show_all() reverts a Stack to its first child until it is mapped, so
        // re-assert the intended page once the window actually appears.
        let weak = Rc::downgrade(self);
        w.connect_map(move |_| {
            if let Some(win) = weak.upgrade() {
                win.stack.set_visible_child_name(if win.unlocked.get() { "form" } else { "gate" });
            }
        });
        w.show_all();
    }

    // ---- the gate --------------------------------------------------------------

    /// Why no code can open the gate, or `""`.
    fn gate_hint(&self) -> &'static str {
        policy::gate_block(self.ctx.onscreen_enabled, self.ctx.require_pin, self.auth.reauth_required())
            .map_or("", |b| b.message())
    }

    fn build_gate_page(self: &Rc<Self>) -> gtk::Widget {
        let boxv = vbox(14, 28);
        boxv.pack_start(&label("🔒  Enter PIN", Some("soc-config-title")), false, false, 0);
        let g = &self.gate;
        g.entry.set_visibility(false);
        g.entry.set_input_purpose(gtk::InputPurpose::Digits);
        g.entry.set_alignment(0.5);
        g.entry.set_placeholder_text(Some("PIN or TOTP code"));
        let cb = bind(self, Win::try_unlock);
        g.entry.connect_activate(move |_| cb());
        on_click(&g.button, self, Win::try_unlock);
        let close = button("Close", None);
        {
            let w = self.window.clone();
            close.connect_clicked(move |_| w.close());
        }
        for w in [wd(&g.entry), wd(&g.err), wd(&g.button), wd(&close)] {
            boxv.pack_start(&w, false, false, 0);
        }
        let hint = self.gate_hint();
        if !hint.is_empty() {
            g.err.set_text(hint);
            g.entry.set_sensitive(false);
            g.button.set_sensitive(false);
        } else {
            let wait = self.auth.remaining(unix_now());
            if wait > 0 {
                self.hold_gate(wait);
            }
        }
        boxv.upcast()
    }

    /// Disable the PIN input for `wait` seconds (the back-off).
    fn hold_gate(self: &Rc<Self>, wait: u64) {
        let g = &self.gate;
        g.err.set_text(&format!("Too many wrong attempts — locked for {wait}s"));
        g.entry.set_sensitive(false);
        g.button.set_sensitive(false);
        let weak = Rc::downgrade(self);
        glib::timeout_add_seconds_local_once(u32::try_from(wait).unwrap_or(60).max(1), move || {
            if let Some(win) = weak.upgrade() {
                win.gate.entry.set_sensitive(true);
                win.gate.button.set_sensitive(true);
                win.gate.err.set_text("");
            }
        });
    }

    fn try_unlock(self: &Rc<Self>) {
        if self.disabled || !self.gate.entry.is_sensitive() {
            return;
        }
        let code = widgets::secret_text(&self.gate.entry);
        self.gate.entry.set_text("");
        self.gate.button.set_sensitive(false);
        let auth = self.auth.clone();
        let weak = Rc::downgrade(self);
        // The PIN stretch takes a few hundred ms: off the GTK thread.
        in_worker(
            move || auth.attempt(&code, unix_now()),
            move |outcome| {
                let Some(win) = weak.upgrade() else { return };
                win.gate.button.set_sensitive(true);
                match outcome {
                    Ok(AuthOutcome::Granted(_)) => {
                        win.gate.err.set_text("");
                        win.enter_form();
                    }
                    Ok(AuthOutcome::Rejected { cooldown }) if cooldown > 0 => win.hold_gate(cooldown),
                    Ok(AuthOutcome::Throttled { wait }) => win.hold_gate(wait),
                    Ok(AuthOutcome::Replayed) => {
                        win.gate.err.set_text("That code was already used — wait for the next one");
                    }
                    Ok(AuthOutcome::NotEnrolled) => {
                        let hint = win.gate_hint();
                        win.gate.err.set_text(if hint.is_empty() { "No PIN or TOTP is enrolled" } else { hint });
                    }
                    Ok(AuthOutcome::Rejected { .. }) => win.gate.err.set_text("Incorrect PIN"),
                    Err(e) => win.gate.err.set_text(&e),
                }
            },
        );
    }

    fn enter_form(self: &Rc<Self>) {
        self.unlocked.set(true);
        if self.form_page.borrow().is_none() {
            let page = self.build_form_page();
            self.stack.add_named(&page, "form");
            page.show_all();
            *self.form_page.borrow_mut() = Some(page);
        }
        self.stack.set_visible_child_name("form");
    }

    // ---- the tabbed form -------------------------------------------------------

    fn build_form_page(self: &Rc<Self>) -> gtk::Widget {
        let outer = vbox(10, 16);
        outer.pack_start(&label("SOC wall — settings", Some("soc-config-title")), false, false, 0);

        let msg = label("", Some("soc-config-ok"));
        *self.form_msg.borrow_mut() = Some(msg.clone());

        let nb = gtk::Notebook::new();
        nb.append_page(&panels::build(self), Some(&gtk::Label::new(Some("Panels"))));
        let tabs: [(&str, TabBuilder); 8] = [
            ("Credentials", creds::build),
            ("Display", sections::build_display),
            ("VPN", vpn::build),
            ("Proxy", sections::build_proxy),
            ("Tunnel", sections::build_tunnel),
            ("Actions", actions::build_actions),
            ("Security", security::build),
            ("Status", actions::build_status),
        ];
        for (title, build) in tabs {
            let holder = gtk::Box::new(gtk::Orientation::Vertical, 0);
            let num = nb.append_page(&holder, Some(&gtk::Label::new(Some(title))));
            self.lazy.borrow_mut().insert(num, build);
        }
        {
            let weak = Rc::downgrade(self);
            nb.connect_switch_page(move |_, page, num| {
                let Some(win) = weak.upgrade() else { return };
                let Some(build) = win.lazy.borrow_mut().remove(&num) else { return };
                if let Some(holder) = page.downcast_ref::<gtk::Box>() {
                    holder.pack_start(&build(&win), true, true, 0);
                    holder.show_all();
                }
            });
        }
        outer.pack_start(&nb, true, true, 0);
        outer.pack_start(&msg, false, false, 0);

        let io_row = hbox(6);
        let export = button("⬇ Export YAML", None);
        export.set_tooltip_text(Some("Save the effective config as a YAML file in the wall user's home directory"));
        on_click(&export, self, Win::export_yaml);
        let import = button("⬆ Import YAML", None);
        import.set_tooltip_text(Some("Load the panels from a validated config file"));
        on_click(&import, self, Win::import_yaml);
        io_row.pack_start(&export, false, false, 0);
        io_row.pack_start(&import, false, false, 0);
        outer.pack_start(&io_row, false, false, 0);

        let foot = hbox(8);
        foot.set_halign(gtk::Align::End);
        let close = button("Close", None);
        {
            let w = self.window.clone();
            close.connect_clicked(move |_| w.close());
        }
        let apply = button("Apply", Some("soc-config-primary"));
        on_click(&apply, self, Win::apply);
        foot.pack_start(&close, false, false, 0);
        foot.pack_start(&apply, false, false, 0);
        outer.pack_start(&foot, false, false, 4);
        outer.upcast()
    }

    // ---- messages and prompts -----------------------------------------------------

    /// The status line under the tabs.
    pub fn msg(&self, text: &str, error: bool) {
        if let Some(l) = self.form_msg.borrow().as_ref() {
            set_status(l, text, error);
        }
    }

    /// A lightweight non-modal message. NOT for anything an operator MUST see:
    /// use [`Win::alert`] for auth failures, vault errors and the like.
    pub fn toast(&self, text: &str) {
        if let Some(l) = self.form_msg.borrow().as_ref() {
            l.set_text(text);
        }
        if let Some(cred) = self.cred.borrow().as_ref() {
            cred.msg.set_text(text);
        }
    }

    pub fn alert(&self, title: &str, msg: &str, error: bool) {
        dialogs::alert(&self.window, title, msg, error);
    }

    pub fn ask(&self, text: &str, detail: &str) -> bool {
        dialogs::ask(&self.window, text, detail)
    }

    /// Modal PIN/TOTP prompt before a destructive action. True only after the
    /// operator types a code matching the settings PIN or TOTP. Fail-closed
    /// when nothing is enrolled: callers that should still work on an
    /// un-enrolled wall check `auth.reauth_required()` first. Wrong codes
    /// share the gate's back-off.
    pub fn require_reauth(&self, what: &str) -> bool {
        if !self.auth.reauth_required() {
            self.alert(
                "No PIN or TOTP enrolled",
                &format!("Destructive actions need a credential. Enrol a PIN or TOTP on the Security tab first, then retry {what}."),
                false,
            );
            return false;
        }
        let wait = self.auth.remaining(unix_now());
        if wait > 0 {
            self.alert("Too many wrong attempts", &format!("Wait {wait} s before trying again."), false);
            return false;
        }
        let Some(code) = dialogs::prompt_code(&self.window, what) else { return false };
        match self.auth.attempt(&code, unix_now()) {
            AuthOutcome::Granted(_) => true,
            AuthOutcome::Rejected { cooldown } if cooldown > 0 => {
                self.toast(&format!("wrong code — locked for {cooldown}s"));
                false
            }
            AuthOutcome::Throttled { wait } => {
                self.toast(&format!("too many wrong codes — wait {wait}s"));
                false
            }
            AuthOutcome::Replayed => {
                self.toast("that code was already used — wait for the next one");
                false
            }
            AuthOutcome::Rejected { .. } | AuthOutcome::NotEnrolled => {
                self.toast("wrong code");
                false
            }
        }
    }

    /// `(cols, rows)`: the Display tab's values if it was built, else the
    /// config's.
    pub fn grid_size(&self) -> (u32, u32) {
        if let Some(d) = self.display.borrow().as_ref() {
            return d.grid_size();
        }
        let conf = self.conf.borrow();
        (conf.display.cols, conf.display.rows)
    }

    /// The VPN entries as the window knows them (live rows once the tab is built).
    pub fn vpn_entries(&self) -> Vec<Dict> {
        match self.vpn.borrow().as_ref() {
            Some(tab) => tab.entries(),
            None => self.conf.borrow().vpns.clone(),
        }
    }

    /// What Apply would write back to the vault note.
    pub fn write_back(&self) -> WriteBack {
        self.ctx
            .vault
            .as_ref()
            .map_or_else(|| WriteBack::Deferred("no vault is attached".to_string()), |v| v.write_back())
    }

    // ---- export / import --------------------------------------------------------

    /// Dump the effective config to a timestamped YAML file in the wall user's
    /// home: 0600, never overwriting, no credentials (item names only).
    fn export_yaml(self: &Rc<Self>) {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_absolute()) else {
            return self.msg("Export failed: HOME is not set", true);
        };
        let overrides = match Overrides::load(&self.ctx.state_dir) {
            Ok(o) => o,
            Err(e) => return self.msg(&format!("Export failed: {e}"), true),
        };
        let stamp = glib::DateTime::now_local()
            .ok()
            .and_then(|t| t.format("%Y%m%d-%H%M%S").ok())
            .map_or_else(|| unix_now().to_string(), |s| s.to_string());
        match soc_state::export_to_dir(&self.conf.borrow(), &overrides, &home, &stamp) {
            Ok(path) => self.msg(&format!("Exported to {}", path.display()), false),
            Err(e) => self.msg(&format!("Export failed: {e}"), true),
        }
    }

    /// Replace the panel list from a config file, through the full loader so
    /// nothing unvalidated reaches the wall. Takes effect on Apply. Re-auths
    /// BEFORE the chooser: it replaces every panel, and a file chooser browses
    /// (and can rename or delete in) the filesystem from the glass.
    fn import_yaml(self: &Rc<Self>) {
        if self.auth.reauth_required() && !self.require_reauth("importing panels") {
            return;
        }
        let Some(path) = dialogs::choose_yaml(&self.window) else { return };
        let conf = match soc_state::import_config(&path) {
            Ok(c) => c,
            Err(e) => return self.msg(&format!("Import failed: {e}"), true),
        };
        if conf.panels.is_empty() {
            return self.msg("No panels found in file", true);
        }
        let count = conf.panels.len();
        self.session.borrow_mut().import(conf.panels);
        panels::rebuild(self);
        let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        self.msg(&format!("Imported {count} panels from {name} — press Apply to keep them"), false);
    }

    // ---- apply --------------------------------------------------------------------

    fn collect_form(&self) -> ApplyForm {
        ApplyForm {
            rows: panels::forms(self),
            display: self.display.borrow().as_ref().map(sections::DisplayTab::form),
            vpns: self.vpn.borrow().as_ref().map(vpn::VpnTab::forms),
            proxy: self.proxy.borrow().as_ref().map(sections::ProxyTab::section),
            tunnel: self.tunnel.borrow().as_ref().map(sections::TunnelTab::section),
        }
    }

    fn prepare(&self, overrides: &Overrides) -> Result<soc_state::Prepared, ApplyError> {
        let form = self.collect_form();
        let caps = (self.ctx.caps)();
        let conf = self.conf.borrow();
        prepare_apply(&conf, &self.session.borrow(), &form, overrides, &caps)
    }

    fn load_overrides(&self) -> Option<Overrides> {
        match Overrides::load(&self.ctx.state_dir) {
            Ok(o) => Some(o),
            Err(e) => {
                // Never overwrite a file we could not read: every saved setting would be lost.
                self.msg(&format!("could not read the saved settings: {e} — nothing was changed"), true);
                None
            }
        }
    }

    /// Validate the form, save `overrides.json`, then apply to the wall.
    fn apply(self: &Rc<Self>) {
        if !policy::may_save(
            self.ctx.onscreen_enabled,
            self.unlocked.get(),
            self.ctx.require_pin,
            self.auth.reauth_required(),
        ) {
            return self.msg(
                "Not saved — this wall requires a Settings PIN or TOTP and none is enrolled. Enrol one on the \
                 Security tab first.",
                true,
            );
        }
        let Some(overrides) = self.load_overrides() else { return };
        let mut prepared = match self.prepare(&overrides) {
            Ok(p) => p,
            Err(e) => return self.msg(&e.to_string(), true),
        };
        // All prompts come before anything is written: they spin the main loop
        // and calibration can save meanwhile. A failed re-auth leaves the file
        // and the wall untouched.
        if !prepared.reauth.is_empty() && self.auth.reauth_required() {
            let what = format!("changing the {} settings", prepared.reauth.join(" / "));
            if !self.require_reauth(&what) {
                return self.msg("Not saved — re-authentication failed, nothing was changed.", true);
            }
            let Some(fresh) = self.load_overrides() else { return };
            prepared = match self.prepare(&fresh) {
                Ok(p) => p,
                Err(e) => return self.msg(&e.to_string(), true),
            };
        }
        if let Err(e) = prepared.overrides.save(&self.ctx.state_dir) {
            return self.msg(
                &format!(
                    "could not save settings: {e} — check that {} is writable (disk space / permissions)",
                    self.ctx.state_dir.display()
                ),
                true,
            );
        }
        // Saved: what is on screen is now the baseline.
        self.session.borrow_mut().commit();
        *self.conf.borrow_mut() = prepared.plan.config.clone();
        if let Some(tab) = self.vpn.borrow_mut().as_mut() {
            tab.saved(prepared.changes.vpns.as_deref());
        }
        if let Some(tab) = self.proxy.borrow_mut().as_mut() {
            tab.saved(prepared.changes.proxy.is_some());
        }
        if let Some(tab) = self.tunnel.borrow_mut().as_mut() {
            tab.saved(prepared.changes.tunnel.is_some());
        }
        let report = (self.ctx.apply)(&prepared.changes);
        let (text, error) = soc_state::plan::report_message(&report, &self.write_back());
        self.msg(&text, error);
    }
}

fn wd<T: IsA<gtk::Widget>>(w: &T) -> gtk::Widget {
    w.clone().upcast()
}
