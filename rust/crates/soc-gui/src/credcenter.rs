//! The credentials & security control center (`soc-wall credcenter`): the
//! sidebar-nav "SOC Wall Settings" window.
//!
//! A left rail (`gtk::StackSidebar`) switches a `gtk::Stack` between two panes:
//!
//! * **Credentials** — resolve the Vaultwarden master (sealed / secret-service
//!   / typed, with a reveal toggle), list the vault logins, and create / edit /
//!   delete one. The editor has a TOTP field with a Generate button and a live
//!   authenticator-code preview that ticks every second.
//! * **Security** — set / clear the panel-lock PIN (with the complexity policy
//!   shown as you type) and enable / disable the panel-lock TOTP, with its
//!   `otpauth://` setup URI and the base32 secret.
//!
//! When a panel-lock PIN or TOTP is enrolled, a gate card is shown first and
//! the sidebar stays hidden until the code is accepted.
//!
//! # Threading
//!
//! Nothing that touches the vault, the seal, the OS-password helpers or a
//! credential file runs on the GTK thread. [`offload`] runs a closure on a
//! worker thread and hands the result back over a std channel that a
//! `glib::timeout_add_local` poll drains on the GTK thread (the `Rc` widget
//! graph is not `Send`, so `MainContext::invoke` is not an option). Secrets
//! cross that channel only as `Zeroizing` values; the master password and PINs
//! live in RAM only and are never logged or put on argv.
//!
//! # Simplifications
//!
//! No QR image is drawn (there is no QR encoder in the dependency set): the
//! setup URI and the base32 secret are shown as selectable text, which every
//! authenticator app accepts as a manual entry.

use crate::style;
use glib::ControlFlow;
use gtk::prelude::*;
use serde_json::{Map, Value};
use soc_seal::ospass::{OsPassword, operator_user};
use soc_seal::{MasterResolver, MasterSource as SealSource};
use soc_state::overrides::KEY_PROXY;
use soc_state::{LockStore, Overrides};
use soc_sys::complexity::{Policy, SecretKind};
use soc_vault::register::{DEFAULT_ACCOUNT_NAME, Registered, ensure_account};
use soc_vault::totp::{Algorithm, generate as totp_generate, generate_secret, provision_uri};
use soc_vault::{LoginSpec, LoginSummary, Session, SessionOptions, VaultEnv, VaultError};
use std::cell::{Cell, RefCell};
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// TOTP step in seconds (the authenticator default).
const TOTP_PERIOD: u64 = 30;
/// How long one OS-password check keeps the destructive actions open.
const OS_GATE_WINDOW: Duration = Duration::from_secs(120);
/// Where the local Vaultwarden listens when nothing is configured.
const DEFAULT_VAULT_URL: &str = "http://127.0.0.1:8222";
/// The otpauth issuer the panel-lock secret is enrolled under.
const ISSUER_LOGIN: &str = "SOC Wall";
/// Bytes of entropy in a generated TOTP secret (160 bits, the usual seed).
const TOTP_SECRET_BYTES: usize = 20;

// ---------------------------------------------------------------------------
// Pure helpers (no GTK): everything here is unit-tested.
// ---------------------------------------------------------------------------

/// A failure shown to the operator inline. Never carries secret material.
#[derive(Debug)]
struct Failure(String);

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<VaultError> for Failure {
    fn from(e: VaultError) -> Failure {
        Failure(e.to_string())
    }
}

impl From<soc_state::StateError> for Failure {
    fn from(e: soc_state::StateError) -> Failure {
        Failure(e.to_string())
    }
}

/// What the live-code preview shows for a TOTP field's current text.
#[derive(Debug, PartialEq, Eq)]
enum LiveCode {
    /// Nothing typed yet.
    Empty,
    /// The current code.
    Code(String),
    /// The text is not a usable secret.
    Invalid,
}

/// The live code for `secret` (bare base32, an `otpauth://` URI or a Steam
/// secret) at `now`.
fn live_code(secret: &str, now: u64) -> LiveCode {
    let secret = secret.trim();
    if secret.is_empty() {
        return LiveCode::Empty;
    }
    match totp_generate(secret, now) {
        Ok(code) => LiveCode::Code(code),
        Err(_) => LiveCode::Invalid, // audit-allow: an unusable secret is shown as "invalid", the error text adds nothing
    }
}

/// Seconds until the current code rolls over.
fn seconds_left(now: u64) -> u64 {
    TOTP_PERIOD - now % TOTP_PERIOD
}

/// A six-digit code as `123 456` for reading aloud; anything else unchanged.
fn format_code(code: &str) -> String {
    match (code.len(), code.get(..3), code.get(3..)) {
        (6, Some(head), Some(tail)) => format!("{head} {tail}"),
        _ => code.to_string(),
    }
}

/// Pango markup for a live-code label.
fn code_markup(code: &LiveCode, now: u64) -> String {
    match code {
        LiveCode::Empty => "<span font_family=\"monospace\" size=\"x-large\">------</span>".to_string(),
        LiveCode::Invalid => "<span size=\"large\">invalid secret</span>".to_string(),
        LiveCode::Code(c) => format!(
            "<span font_family=\"monospace\" size=\"x-large\" weight=\"bold\">{}</span>  <span size=\"small\">{}s</span>",
            glib::markup_escape_text(&format_code(c)),
            seconds_left(now)
        ),
    }
}

/// The `otpauth://` URI for a TOTP field: a value that already is one is kept,
/// a bare secret is wrapped (6 digits, 30 s, SHA-1).
fn setup_uri(secret: &str, label: &str, issuer: &str) -> String {
    let secret = secret.trim();
    if secret.to_ascii_lowercase().starts_with("otpauth://") {
        return secret.to_string();
    }
    provision_uri(secret, label, issuer, TOTP_PERIOD, 6, Algorithm::Sha1)
}

/// Whether an OS-password check passed recently enough to still count.
fn gate_open(until: Option<Instant>, now: Instant) -> bool {
    until.is_some_and(|t| now < t)
}

/// A short name for where the master came from.
fn describe_master(source: SealSource, sealed: bool, found: bool) -> String {
    let name = if sealed {
        "sealed (host-bound)"
    } else {
        match source {
            SealSource::SecretService => "secret-service",
            SealSource::Env => "environment (development only)",
            SealSource::Auto => "secret-service / environment",
            SealSource::Sealed => "sealed (nothing sealed yet)",
        }
    };
    if found { format!("Master source: {name}") } else { format!("Master source: {name} — none available, type it") }
}

/// The gate prompt for what is enrolled.
fn gate_hint(pin: bool, totp: bool) -> &'static str {
    match (pin, totp) {
        (true, true) => "Enter the panel-lock PIN or a 6-digit authenticator code.",
        (false, true) => "Enter the 6-digit code from your authenticator app.",
        _ => "Enter the panel-lock PIN.",
    }
}

/// The complexity feedback shown under the new-PIN field.
fn pin_hint(policy: &Policy, pin: &str) -> String {
    if pin.is_empty() {
        let rule = policy.rule(SecretKind::Pin);
        return if rule.numeric_only {
            format!("At least {} digits, digits only.", rule.min_len)
        } else {
            format!("At least {} characters.", rule.min_len)
        };
    }
    let result = policy.check(pin, SecretKind::Pin);
    if result.ok { "Meets the PIN policy.".to_string() } else { result.summary() }
}

/// The verdict on a panel-lock gate attempt.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Granted,
    Denied { cooldown: u64 },
    Throttled { wait: u64 },
    NothingEnrolled,
}

/// Check `code` against the panel-lock PIN and TOTP under the persisted
/// back-off. Runs a PBKDF2 stretch: call it from a worker.
fn check_panel_lock(store: &LockStore, code: &str, now: u64) -> Verdict {
    if !store.pin().is_set() && !store.totp().is_set() {
        return Verdict::NothingEnrolled;
    }
    let wait = store.budget().remaining(now);
    if wait > 0 {
        return Verdict::Throttled { wait };
    }
    let code = code.trim();
    let ok = !code.is_empty()
        && (store.pin().verify(code)
            || store.totp().load().is_some_and(|s| soc_state::totp::verify_step(&s, code, now).is_some()));
    if ok {
        store.budget().passed();
        Verdict::Granted
    } else {
        Verdict::Denied { cooldown: store.budget().failed(now) }
    }
}

/// Record `item` as the proxy's vault login in the overrides, keeping every
/// other saved proxy key.
fn set_proxy_item(overrides: &mut Overrides, item: &str) {
    let mut section: Map<String, Value> =
        overrides.get(KEY_PROXY).and_then(Value::as_object).cloned().unwrap_or_else(Map::new);
    section.insert("vault_item".to_string(), Value::String(item.to_string()));
    overrides.as_dict_mut().insert(KEY_PROXY.to_string(), Value::Object(section));
}

/// `0` when there is no usable (seconds) wait.
fn wait_secs(wait: u64) -> u32 {
    u32::try_from(wait.clamp(1, 3600)).unwrap_or(60) // audit-allow: default is the intended fallback (clamped, cannot fail)
}

// ---------------------------------------------------------------------------
// Off-thread plumbing.
// ---------------------------------------------------------------------------

/// Run `job` on a worker thread and call `done` on the GTK thread with the
/// result (`None` if the worker could not start or died).
fn offload<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static, done: impl FnOnce(Option<T>) + 'static) {
    let (tx, rx) = mpsc::channel::<T>();
    let spawned = std::thread::Builder::new().name("credcenter-io".to_string()).spawn(move || {
        if tx.send(job()).is_err() {
            eprintln!("credcenter: the window closed before a result was delivered");
        }
    });
    if let Err(e) = spawned {
        eprintln!("credcenter: cannot start a worker thread: {e}");
    }
    let mut done = Some(done);
    glib::timeout_add_local(Duration::from_millis(30), move || match rx.try_recv() {
        Ok(value) => {
            if let Some(d) = done.take() {
                d(Some(value));
            }
            ControlFlow::Break
        }
        Err(mpsc::TryRecvError::Empty) => ControlFlow::Continue,
        Err(mpsc::TryRecvError::Disconnected) => {
            if let Some(d) = done.take() {
                d(None);
            }
            ControlFlow::Break
        }
    });
}

// ---------------------------------------------------------------------------
// Widgets.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Tone {
    Dim,
    Ok,
    Bad,
}

fn set_status(label: &gtk::Label, text: &str, tone: Tone) {
    label.set_text(text);
    let ctx = label.style_context();
    for class in ["soc-config-sub", "soc-config-ok", "soc-config-error"] {
        ctx.remove_class(class);
    }
    ctx.add_class(match tone {
        Tone::Dim => "soc-config-sub",
        Tone::Ok => "soc-config-ok",
        Tone::Bad => "soc-config-error",
    });
}

fn make_label(text: &str, class: Option<&str>) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_xalign(0.0);
    label.set_line_wrap(true);
    if let Some(class) = class {
        label.style_context().add_class(class);
    }
    label
}

fn make_button(text: &str, class: Option<&str>) -> gtk::Button {
    let button = gtk::Button::with_label(text);
    if let Some(class) = class {
        button.style_context().add_class(class);
    }
    button
}

fn make_entry(secret: bool, placeholder: &str) -> gtk::Entry {
    let entry = gtk::Entry::new();
    entry.set_placeholder_text(Some(placeholder));
    entry.set_hexpand(true);
    if secret {
        entry.set_visibility(false);
        entry.set_input_purpose(gtk::InputPurpose::Password);
    }
    entry
}

fn field_row(caption: &str, widget: &impl IsA<gtk::Widget>) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let label = make_label(caption, None);
    label.set_size_request(120, -1);
    label.set_valign(gtk::Align::Center);
    row.pack_start(&label, false, false, 0);
    row.pack_start(widget, true, true, 0);
    row
}

fn section(title: &str) -> (gtk::Frame, gtk::Box) {
    let frame = gtk::Frame::new(Some(title));
    let inner = gtk::Box::new(gtk::Orientation::Vertical, 8);
    inner.set_border_width(12);
    frame.add(&inner);
    (frame, inner)
}

fn page_box() -> gtk::Box {
    let page = gtk::Box::new(gtk::Orientation::Vertical, 12);
    page.set_border_width(18);
    page
}

fn scrolled(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    let sc = gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).build();
    sc.add(child);
    sc
}

fn on_click(button: &gtk::Button, ui: &Rc<Ui>, action: fn(&Rc<Ui>)) {
    let weak = Rc::downgrade(ui);
    button.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            action(&ui);
        }
    });
}

fn on_activate(entry: &gtk::Entry, ui: &Rc<Ui>, action: fn(&Rc<Ui>)) {
    let weak = Rc::downgrade(ui);
    entry.connect_activate(move |_| {
        if let Some(ui) = weak.upgrade() {
            action(&ui);
        }
    });
}

/// A secret read out of a widget straight into a wiping buffer.
fn secret_text(entry: &gtk::Entry) -> Zeroizing<String> {
    Zeroizing::new(entry.text().to_string())
}

// ---------------------------------------------------------------------------
// The window state.
// ---------------------------------------------------------------------------

struct Ui {
    win: gtk::Window,
    state_dir: PathBuf,
    policy: Policy,
    vault_url: String,
    vault_email: String,
    session_opts: SessionOptions,
    // RAM-only secrets and caches.
    master: RefCell<Option<Zeroizing<String>>>,
    session: RefCell<Option<Arc<Session>>>,
    logins: RefCell<Vec<LoginSummary>>,
    editing: RefCell<Option<String>>,
    editing_notes: RefCell<Zeroizing<String>>,
    panel_totp: RefCell<Option<Zeroizing<String>>>,
    os_gate_until: Cell<Option<Instant>>,
    suppress_select: Cell<bool>,
    // Shell.
    top: gtk::Stack,
    stack: gtk::Stack,
    gate_entry: gtk::Entry,
    gate_btn: gtk::Button,
    gate_msg: gtk::Label,
    // Credentials pane.
    source_lbl: gtk::Label,
    master_entry: gtk::Entry,
    master_toggle: gtk::ToggleButton,
    unlock_btn: gtk::Button,
    create_btn: gtk::Button,
    main_box: gtk::Box,
    list: gtk::ListBox,
    cred_status: gtk::Label,
    f_name: gtk::Entry,
    f_user: gtk::Entry,
    f_pass: gtk::Entry,
    f_pass_toggle: gtk::ToggleButton,
    f_totp: gtk::Entry,
    f_uri: gtk::Entry,
    code_lbl: gtk::Label,
    save_btn: gtk::Button,
    delete_btn: gtk::Button,
    proxy_btn: gtk::Button,
    // Security pane.
    pin_status: gtk::Label,
    totp_status: gtk::Label,
    pin_entry: gtk::Entry,
    pin_confirm: gtk::Entry,
    pin_hint_lbl: gtk::Label,
    totp_uri: gtk::Entry,
    totp_secret: gtk::Entry,
    sec_code_lbl: gtk::Label,
    sec_status: gtk::Label,
}

/// What the Security pane reads from the lock store.
struct SecState {
    pin: bool,
    totp: bool,
    secret: Option<Zeroizing<String>>,
}

fn read_sec_state(dir: &Path) -> SecState {
    let store = LockStore::new(dir);
    SecState { pin: store.pin().is_set(), totp: store.totp().is_set(), secret: store.totp().load() }
}

// ---------------------------------------------------------------------------
// Build.
// ---------------------------------------------------------------------------

fn build(state_dir: PathBuf, enrolled: bool) -> Rc<Ui> {
    let env = VaultEnv::from_process();
    let (email, url, _pinentry) = env.resolved();
    let vault_url = if url.trim().is_empty() { DEFAULT_VAULT_URL.to_string() } else { url };

    let win = gtk::Window::new(gtk::WindowType::Toplevel);
    win.set_title("SOC Wall · Settings");
    win.set_default_size(980, 640);
    win.set_position(gtk::WindowPosition::Center);
    win.style_context().add_class("soc-config");

    // --- gate -------------------------------------------------------------
    let gate_page = gtk::Box::new(gtk::Orientation::Vertical, 10);
    gate_page.set_halign(gtk::Align::Center);
    gate_page.set_valign(gtk::Align::Center);
    gate_page.set_size_request(380, -1);
    let gate_title = make_label("Settings locked", Some("soc-config-title"));
    let (has_pin, has_totp) = {
        let store = LockStore::new(&state_dir);
        (store.pin().is_set(), store.totp().is_set())
    };
    let gate_hint_lbl = make_label(gate_hint(has_pin, has_totp), Some("soc-config-sub"));
    let gate_entry = make_entry(true, "PIN or 6-digit code");
    gate_entry.set_input_purpose(gtk::InputPurpose::Pin);
    let gate_msg = make_label("", Some("soc-config-error"));
    let gate_btn = make_button("Unlock", Some("soc-config-primary"));
    gate_page.pack_start(&gate_title, false, false, 0);
    gate_page.pack_start(&gate_hint_lbl, false, false, 0);
    gate_page.pack_start(&gate_entry, false, false, 0);
    gate_page.pack_start(&gate_msg, false, false, 0);
    gate_page.pack_start(&gate_btn, false, false, 0);

    // --- credentials pane -------------------------------------------------
    let cred = page_box();
    cred.pack_start(&make_label("Vault credentials", Some("soc-config-title")), false, false, 0);
    cred.pack_start(
        &make_label(
            "Logins the wall reads from Vaultwarden. The master password stays in memory and is never written. \
             Viewing or changing a login asks for the operator's OS password.",
            Some("soc-config-sub"),
        ),
        false,
        false,
        0,
    );

    let (master_frame, master_box) = section("Vault master");
    let source_lbl = make_label("Master source: resolving…", Some("soc-config-sub"));
    let master_entry = make_entry(true, "vault master password");
    let master_toggle = gtk::ToggleButton::with_label("Show");
    let unlock_btn = make_button("Unlock vault", Some("soc-config-primary"));
    let create_btn = make_button("Create account…", None);
    create_btn.set_no_show_all(true);
    let master_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    master_row.pack_start(&master_entry, true, true, 0);
    master_row.pack_start(&master_toggle, false, false, 0);
    master_row.pack_start(&unlock_btn, false, false, 0);
    master_row.pack_start(&create_btn, false, false, 0);
    master_box.pack_start(&source_lbl, false, false, 0);
    master_box.pack_start(&master_row, false, false, 0);
    cred.pack_start(&master_frame, false, false, 0);

    let main_box = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    main_box.set_no_show_all(true);
    let left = gtk::Box::new(gtk::Orientation::Vertical, 8);
    left.set_size_request(280, -1);
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Single);
    let placeholder = make_label("No vault logins yet — use Add login to create one.", Some("soc-config-sub"));
    placeholder.set_margin_top(24);
    placeholder.set_margin_bottom(24);
    placeholder.show();
    list.set_placeholder(Some(&placeholder));
    let list_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(320)
        .vexpand(true)
        .build();
    list_scroll.add(&list);
    let add_btn = make_button("Add login", None);
    let refresh_btn = make_button("Refresh", None);
    let list_btns = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    list_btns.pack_start(&add_btn, false, false, 0);
    list_btns.pack_start(&refresh_btn, false, false, 0);
    left.pack_start(&list_scroll, true, true, 0);
    left.pack_start(&list_btns, false, false, 0);

    let (editor_frame, editor) = section("Login");
    let f_name = make_entry(false, "login name (e.g. Wazuh)");
    let f_user = make_entry(false, "username");
    let f_pass = make_entry(true, "password");
    let f_pass_toggle = gtk::ToggleButton::with_label("Show");
    let pass_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    pass_row.pack_start(&f_pass, true, true, 0);
    pass_row.pack_start(&f_pass_toggle, false, false, 0);
    let f_totp = make_entry(false, "base32 secret (optional)");
    let gen_btn = make_button("Generate", None);
    let uri_btn = make_button("Setup URI", None);
    let totp_row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    totp_row.pack_start(&f_totp, true, true, 0);
    totp_row.pack_start(&gen_btn, false, false, 0);
    totp_row.pack_start(&uri_btn, false, false, 0);
    let code_lbl = make_label("", Some("soc-config-tag"));
    let f_uri = make_entry(false, "https://host/login (optional)");
    let save_btn = make_button("Save", Some("soc-config-primary"));
    let delete_btn = make_button("Delete", Some("destructive-action"));
    delete_btn.set_sensitive(false);
    let proxy_btn = make_button("Use as proxy login", None);
    proxy_btn.set_sensitive(false);
    let action_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    action_row.pack_start(&save_btn, false, false, 0);
    action_row.pack_start(&delete_btn, false, false, 0);
    action_row.pack_start(&proxy_btn, false, false, 0);
    editor.pack_start(&field_row("Name", &f_name), false, false, 0);
    editor.pack_start(&field_row("Username", &f_user), false, false, 0);
    editor.pack_start(&field_row("Password", &pass_row), false, false, 0);
    editor.pack_start(&field_row("TOTP secret", &totp_row), false, false, 0);
    editor.pack_start(&field_row("Live code", &code_lbl), false, false, 0);
    editor.pack_start(&field_row("URI", &f_uri), false, false, 0);
    editor.pack_start(&action_row, false, false, 0);
    main_box.pack_start(&left, false, false, 0);
    main_box.pack_start(&editor_frame, true, true, 0);
    cred.pack_start(&main_box, true, true, 0);
    let cred_status = make_label("", Some("soc-config-sub"));
    cred.pack_start(&cred_status, false, false, 0);

    // --- security pane ----------------------------------------------------
    let sec = page_box();
    sec.pack_start(&make_label("Panel lock", Some("soc-config-title")), false, false, 0);
    sec.pack_start(
        &make_label(
            "Protect the wall and this window with a PIN and/or a phone authenticator (TOTP). Either unlocks; \
             enrol at least one to lock the wall.",
            Some("soc-config-sub"),
        ),
        false,
        false,
        0,
    );
    let (pin_frame, pin_box) = section("PIN");
    let pin_status = make_label("", Some("soc-config-sub"));
    let pin_entry = make_entry(true, "new PIN");
    pin_entry.set_input_purpose(gtk::InputPurpose::Pin);
    let pin_confirm = make_entry(true, "confirm PIN");
    pin_confirm.set_input_purpose(gtk::InputPurpose::Pin);
    let policy = Policy::load(&state_dir.join("policy.json"));
    let pin_hint_lbl = make_label(&pin_hint(&policy, ""), Some("soc-config-sub"));
    let set_pin_btn = make_button("Set / change PIN", Some("soc-config-primary"));
    let clear_pin_btn = make_button("Clear PIN", Some("destructive-action"));
    let pin_btns = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    pin_btns.pack_start(&set_pin_btn, false, false, 0);
    pin_btns.pack_start(&clear_pin_btn, false, false, 0);
    pin_box.pack_start(&pin_status, false, false, 0);
    pin_box.pack_start(&field_row("New PIN", &pin_entry), false, false, 0);
    pin_box.pack_start(&field_row("Confirm", &pin_confirm), false, false, 0);
    pin_box.pack_start(&pin_hint_lbl, false, false, 0);
    pin_box.pack_start(&pin_btns, false, false, 0);
    sec.pack_start(&pin_frame, false, false, 0);

    let (totp_frame, totp_box) = section("Authenticator (TOTP)");
    let totp_status = make_label("", Some("soc-config-sub"));
    let totp_uri = make_entry(false, "otpauth:// setup URI appears here when enabling");
    totp_uri.set_editable(false);
    let totp_secret = make_entry(false, "base32 secret appears here when enabling");
    totp_secret.set_editable(false);
    let sec_code_lbl = make_label("", Some("soc-config-tag"));
    let enable_btn = make_button("Enable TOTP", Some("soc-config-primary"));
    let disable_btn = make_button("Disable TOTP", Some("destructive-action"));
    let totp_btns = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    totp_btns.pack_start(&enable_btn, false, false, 0);
    totp_btns.pack_start(&disable_btn, false, false, 0);
    totp_box.pack_start(&totp_status, false, false, 0);
    totp_box.pack_start(&field_row("Setup URI", &totp_uri), false, false, 0);
    totp_box.pack_start(&field_row("Secret", &totp_secret), false, false, 0);
    totp_box.pack_start(&field_row("Live code", &sec_code_lbl), false, false, 0);
    totp_box.pack_start(
        &make_label(
            "No QR image is drawn: paste the setup URI, or type the secret, into your authenticator app.",
            Some("soc-config-sub"),
        ),
        false,
        false,
        0,
    );
    totp_box.pack_start(&totp_btns, false, false, 0);
    sec.pack_start(&totp_frame, false, false, 0);
    let sec_status = make_label("", Some("soc-config-sub"));
    sec.pack_start(&sec_status, false, false, 0);

    // --- shell ------------------------------------------------------------
    let stack = gtk::Stack::new();
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);
    stack.set_hexpand(true);
    stack.add_titled(&scrolled(&cred), "credentials", "Credentials");
    stack.add_titled(&scrolled(&sec), "security", "Security");
    let sidebar = gtk::StackSidebar::new();
    sidebar.set_stack(&stack);
    sidebar.set_size_request(190, -1);
    let body = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    body.pack_start(&sidebar, false, false, 0);
    body.pack_start(&gtk::Separator::new(gtk::Orientation::Vertical), false, false, 0);
    body.pack_start(&stack, true, true, 0);

    let top = gtk::Stack::new();
    top.add_named(&gate_page, "gate");
    top.add_named(&body, "body");
    top.set_visible_child_name(if enrolled { "gate" } else { "body" });
    win.add(&top);

    let ui = Rc::new(Ui {
        win,
        state_dir,
        policy,
        vault_url,
        vault_email: email,
        session_opts: env.session.clone(),
        master: RefCell::new(None),
        session: RefCell::new(None),
        logins: RefCell::new(Vec::new()),
        editing: RefCell::new(None),
        editing_notes: RefCell::new(Zeroizing::new(String::new())),
        panel_totp: RefCell::new(None),
        os_gate_until: Cell::new(None),
        suppress_select: Cell::new(false),
        top,
        stack,
        gate_entry,
        gate_btn,
        gate_msg,
        source_lbl,
        master_entry,
        master_toggle,
        unlock_btn,
        create_btn,
        main_box,
        list,
        cred_status,
        f_name,
        f_user,
        f_pass,
        f_pass_toggle,
        f_totp,
        f_uri,
        code_lbl,
        save_btn,
        delete_btn,
        proxy_btn,
        pin_status,
        totp_status,
        pin_entry,
        pin_confirm,
        pin_hint_lbl,
        totp_uri,
        totp_secret,
        sec_code_lbl,
        sec_status,
    });

    // --- wiring -----------------------------------------------------------
    on_click(&ui.gate_btn, &ui, gate_submit);
    on_activate(&ui.gate_entry, &ui, gate_submit);
    on_click(&ui.unlock_btn, &ui, unlock_clicked);
    on_activate(&ui.master_entry, &ui, unlock_clicked);
    on_click(&ui.create_btn, &ui, create_account_clicked);
    on_click(&add_btn, &ui, new_login);
    on_click(&refresh_btn, &ui, reload_logins);
    on_click(&gen_btn, &ui, generate_totp_clicked);
    on_click(&uri_btn, &ui, show_uri_clicked);
    on_click(&ui.save_btn, &ui, save_clicked);
    on_click(&ui.delete_btn, &ui, delete_clicked);
    on_click(&ui.proxy_btn, &ui, proxy_clicked);
    on_click(&set_pin_btn, &ui, set_pin_clicked);
    on_click(&clear_pin_btn, &ui, clear_pin_clicked);
    on_click(&enable_btn, &ui, enable_totp_clicked);
    on_click(&disable_btn, &ui, disable_totp_clicked);

    let master_entry = ui.master_entry.clone();
    ui.master_toggle.connect_toggled(move |t| {
        master_entry.set_visibility(t.is_active());
        t.set_label(if t.is_active() { "Hide" } else { "Show" });
    });
    let pass_entry = ui.f_pass.clone();
    ui.f_pass_toggle.connect_toggled(move |t| {
        pass_entry.set_visibility(t.is_active());
        t.set_label(if t.is_active() { "Hide" } else { "Show" });
    });
    let weak = Rc::downgrade(&ui);
    ui.f_totp.connect_changed(move |_| {
        if let Some(ui) = weak.upgrade() {
            tick(&ui);
        }
    });
    let weak = Rc::downgrade(&ui);
    ui.pin_entry.connect_changed(move |e| {
        if let Some(ui) = weak.upgrade() {
            ui.pin_hint_lbl.set_text(&pin_hint(&ui.policy, e.text().as_str()));
        }
    });
    let weak = Rc::downgrade(&ui);
    ui.list.connect_row_selected(move |_, row| {
        if let (Some(ui), Some(row)) = (weak.upgrade(), row) {
            login_selected(&ui, row.index());
        }
    });
    let weak = Rc::downgrade(&ui);
    ui.stack.connect_visible_child_name_notify(move |s| {
        if let Some(ui) = weak.upgrade() {
            if s.visible_child_name().as_deref() == Some("security") {
                refresh_security(&ui);
            }
        }
    });
    let weak = Rc::downgrade(&ui);
    ui.win.connect_destroy(move |_| {
        if let Some(ui) = weak.upgrade() {
            ui.master.borrow_mut().take();
            ui.session.borrow_mut().take();
            ui.panel_totp.borrow_mut().take();
        }
        gtk::main_quit();
    });

    // One ticker drives both live-code labels.
    let weak = Rc::downgrade(&ui);
    glib::timeout_add_seconds_local(1, move || match weak.upgrade() {
        Some(ui) => {
            tick(&ui);
            ControlFlow::Continue
        }
        None => ControlFlow::Break,
    });

    new_login(&ui);
    ui
}

// ---------------------------------------------------------------------------
// Live codes.
// ---------------------------------------------------------------------------

fn tick(ui: &Rc<Ui>) {
    let now = soc_state::unix_now();
    let typed = secret_text(&ui.f_totp);
    ui.code_lbl.set_markup(&code_markup(&live_code(&typed, now), now));
    let panel = ui.panel_totp.borrow();
    let live = match panel.as_ref() {
        Some(secret) => live_code(secret, now),
        None => LiveCode::Empty,
    };
    ui.sec_code_lbl.set_markup(&code_markup(&live, now));
}

// ---------------------------------------------------------------------------
// Dialogs (non-blocking: no nested main loops).
// ---------------------------------------------------------------------------

type Action = Box<dyn FnOnce(&Rc<Ui>)>; // audit-allow: one-shot UI continuation, heterogeneous closures

fn confirm(ui: &Rc<Ui>, text: &str, detail: &str, on_yes: impl FnOnce(&Rc<Ui>) + 'static) {
    let dialog = gtk::MessageDialog::builder()
        .transient_for(&ui.win)
        .modal(true)
        .message_type(gtk::MessageType::Question)
        .buttons(gtk::ButtonsType::OkCancel)
        .text(text)
        .secondary_text(detail)
        .build();
    dialog.style_context().add_class("soc-config");
    let pending: RefCell<Option<Action>> = RefCell::new(Some(Box::new(on_yes)));
    let weak = Rc::downgrade(ui);
    dialog.connect_response(move |d, response| {
        d.close();
        if response == gtk::ResponseType::Ok {
            if let (Some(ui), Some(action)) = (weak.upgrade(), pending.borrow_mut().take()) {
                action(&ui);
            }
        }
    });
    dialog.show_all();
}

/// Run `then` once the operator's OS password has been verified (or was
/// verified within the last [`OS_GATE_WINDOW`]). A wrong password is reported
/// inside the dialog and never panics; the check runs off the GTK thread.
fn os_gate(ui: &Rc<Ui>, reason: &str, on_cancel: impl Fn(&Rc<Ui>) + 'static, then: impl FnOnce(&Rc<Ui>) + 'static) {
    if gate_open(ui.os_gate_until.get(), Instant::now()) {
        then(ui);
        return;
    }
    let dialog = gtk::Dialog::builder().title("Operator password").transient_for(&ui.win).modal(true).build();
    dialog.style_context().add_class("soc-config");
    dialog.add_button("Cancel", gtk::ResponseType::Cancel);
    let verify_btn = dialog.add_button("Verify", gtk::ResponseType::Ok);
    verify_btn.style_context().add_class("soc-config-primary");
    let area = dialog.content_area();
    area.set_spacing(8);
    area.set_border_width(14);
    area.pack_start(&make_label(&format!("Enter the operator's OS password to {reason}."), None), false, false, 0);
    let entry = make_entry(true, "OS password");
    let focus = entry.clone();
    let msg = make_label("", Some("soc-config-error"));
    area.pack_start(&entry, false, false, 0);
    area.pack_start(&msg, false, false, 0);
    let dlg = dialog.clone();
    entry.connect_activate(move |_| dlg.response(gtk::ResponseType::Ok));

    let pending: Rc<RefCell<Option<Action>>> = Rc::new(RefCell::new(Some(Box::new(then))));
    let weak = Rc::downgrade(ui);
    let on_cancel = Rc::new(on_cancel);
    dialog.connect_response(move |d, response| {
        let Some(ui) = weak.upgrade() else {
            d.close();
            return;
        };
        if response != gtk::ResponseType::Ok {
            d.close();
            on_cancel(&ui);
            return;
        }
        let password = secret_text(&entry);
        if password.is_empty() {
            set_status(&msg, "Enter the password.", Tone::Bad);
            return;
        }
        entry.set_sensitive(false);
        verify_btn.set_sensitive(false);
        set_status(&msg, "Checking…", Tone::Dim);
        let (d, entry, msg, verify_btn, pending, weak) =
            (d.clone(), entry.clone(), msg.clone(), verify_btn.clone(), Rc::clone(&pending), weak.clone());
        offload(
            move || {
                let user = operator_user();
                OsPassword::system().check(&user, &password).map_err(|e| Failure(e.to_string()))
            },
            move |result| {
                let Some(ui) = weak.upgrade() else { return };
                match result {
                    Some(Ok(true)) => {
                        ui.os_gate_until.set(Some(Instant::now() + OS_GATE_WINDOW));
                        d.close();
                        if let Some(action) = pending.borrow_mut().take() {
                            action(&ui);
                        }
                    }
                    other => {
                        let text = match other {
                            Some(Ok(_)) => "Incorrect password.".to_string(),
                            Some(Err(e)) => e.to_string(),
                            None => "The password check could not run.".to_string(),
                        };
                        entry.set_text("");
                        entry.set_sensitive(true);
                        verify_btn.set_sensitive(true);
                        entry.grab_focus();
                        set_status(&msg, &text, Tone::Bad);
                    }
                }
            },
        );
    });
    dialog.show_all();
    focus.grab_focus();
}

fn show_uri_dialog(ui: &Rc<Ui>, title: &str, hint: &str, uri: &str, secret: Option<&str>) {
    let dialog = gtk::Dialog::builder().title(title).transient_for(&ui.win).modal(true).build();
    dialog.style_context().add_class("soc-config");
    dialog.add_button("Close", gtk::ResponseType::Close);
    let area = dialog.content_area();
    area.set_spacing(8);
    area.set_border_width(14);
    area.pack_start(&make_label(hint, Some("soc-config-sub")), false, false, 0);
    let uri_entry = gtk::Entry::new();
    uri_entry.set_text(uri);
    uri_entry.set_editable(false);
    uri_entry.set_width_chars(60);
    area.pack_start(&uri_entry, false, false, 0);
    if let Some(secret) = secret {
        let secret_entry = gtk::Entry::new();
        secret_entry.set_text(secret);
        secret_entry.set_editable(false);
        area.pack_start(&field_row("Secret", &secret_entry), false, false, 0);
    }
    area.pack_start(
        &make_label("No QR image is drawn; paste the URI or type the secret into the authenticator app.", None),
        false,
        false,
        0,
    );
    dialog.connect_response(|d, _| d.close());
    dialog.show_all();
}

// ---------------------------------------------------------------------------
// Panel-lock gate.
// ---------------------------------------------------------------------------

fn gate_submit(ui: &Rc<Ui>) {
    let code = secret_text(&ui.gate_entry);
    ui.gate_entry.set_sensitive(false);
    ui.gate_btn.set_sensitive(false);
    set_status(&ui.gate_msg, "Checking…", Tone::Dim);
    let dir = ui.state_dir.clone();
    let weak = Rc::downgrade(ui);
    offload(
        move || check_panel_lock(&LockStore::new(&dir), &code, soc_state::unix_now()),
        move |verdict| {
            let Some(ui) = weak.upgrade() else { return };
            ui.gate_entry.set_text("");
            match verdict {
                Some(Verdict::Granted) | Some(Verdict::NothingEnrolled) => {
                    ui.top.set_visible_child_name("body");
                    begin_session(&ui);
                }
                Some(Verdict::Throttled { wait }) | Some(Verdict::Denied { cooldown: wait }) if wait > 0 => {
                    set_status(&ui.gate_msg, &format!("Too many attempts — locked for {wait}s"), Tone::Bad);
                    let weak = Rc::downgrade(&ui);
                    glib::timeout_add_seconds_local_once(wait_secs(wait), move || {
                        if let Some(ui) = weak.upgrade() {
                            rearm_gate(&ui);
                        }
                    });
                }
                Some(Verdict::Denied { .. }) => {
                    set_status(&ui.gate_msg, "Incorrect — try again", Tone::Bad);
                    rearm_gate(&ui);
                }
                Some(Verdict::Throttled { .. }) | None => {
                    set_status(&ui.gate_msg, "The check could not run — try again", Tone::Bad);
                    rearm_gate(&ui);
                }
            }
        },
    );
}

fn rearm_gate(ui: &Rc<Ui>) {
    ui.gate_entry.set_sensitive(true);
    ui.gate_btn.set_sensitive(true);
    ui.gate_entry.grab_focus();
}

// ---------------------------------------------------------------------------
// Credentials: master resolution and vault jobs.
// ---------------------------------------------------------------------------

struct Resolved {
    label: String,
    master: Option<Zeroizing<String>>,
}

fn resolve_master() -> Resolved {
    match MasterResolver::from_env() {
        Ok(resolver) => {
            let sealed = resolver.store().is_sealed();
            let master = resolver.get_master();
            Resolved { label: describe_master(resolver.source(), sealed, master.is_some()), master }
        }
        Err(e) => Resolved { label: format!("Master source: {e}"), master: None },
    }
}

/// After the gate (or straight away when nothing is enrolled): pick the
/// Credentials pane and try the sealed / secret-service master.
fn begin_session(ui: &Rc<Ui>) {
    ui.stack.set_visible_child_name("credentials");
    set_status(&ui.cred_status, "resolving the vault master…", Tone::Dim);
    let weak = Rc::downgrade(ui);
    offload(resolve_master, move |resolved| {
        let Some(ui) = weak.upgrade() else { return };
        let Some(resolved) = resolved else {
            set_status(&ui.cred_status, "could not resolve the vault master", Tone::Bad);
            return;
        };
        ui.source_lbl.set_text(&resolved.label);
        match resolved.master {
            Some(master) => {
                ui.master_entry.set_text(&master);
                set_status(&ui.cred_status, "unlocking the vault…", Tone::Dim);
                unlock_with(&ui, master);
            }
            None => set_status(&ui.cred_status, "no sealed master available — enter it to unlock", Tone::Dim),
        }
    });
}

/// Whether a failed call means the cached session is no longer good.
fn auth_failure(e: &VaultError) -> bool {
    matches!(e, VaultError::LoginRejected(_)) || e.http_status() == Some(401)
}

/// Run `op` against the vault session on a worker. A cached session is reused;
/// with `fresh` (or none cached) the master logs in first.
fn vault_job<R: Send + 'static>(
    ui: &Rc<Ui>,
    fresh: bool,
    op: impl FnOnce(&Session) -> Result<R, VaultError> + Send + 'static,
    done: impl FnOnce(&Rc<Ui>, Result<R, VaultError>) + 'static,
) {
    let master = ui.master.borrow().clone();
    let Some(master) = master else {
        set_status(&ui.cred_status, "unlock the vault first", Tone::Bad);
        return;
    };
    let cached = if fresh { None } else { ui.session.borrow().clone() };
    let (url, email, opts) = (ui.vault_url.clone(), ui.vault_email.clone(), ui.session_opts.clone());
    let weak = Rc::downgrade(ui);
    offload(
        move || -> (Option<Arc<Session>>, Result<R, VaultError>) {
            let (session, logged_in) = match cached {
                Some(s) => (s, false),
                None => match Session::login(&url, &email, &master, &opts) {
                    Ok(s) => (Arc::new(s), true),
                    Err(e) => return (None, Err(e)),
                },
            };
            let out = op(&session);
            (logged_in.then_some(session), out)
        },
        move |result| {
            let Some(ui) = weak.upgrade() else { return };
            match result {
                Some((new_session, out)) => {
                    if let Some(s) = new_session {
                        *ui.session.borrow_mut() = Some(s);
                    }
                    if out.as_ref().err().is_some_and(auth_failure) {
                        ui.session.borrow_mut().take();
                    }
                    done(&ui, out);
                }
                None => done(&ui, Err(VaultError::Backend("the worker thread failed".to_string()))),
            }
        },
    );
}

fn unlock_clicked(ui: &Rc<Ui>) {
    let master = secret_text(&ui.master_entry);
    if master.is_empty() {
        set_status(&ui.cred_status, "enter the vault master password", Tone::Bad);
        return;
    }
    set_status(&ui.cred_status, "unlocking the vault…", Tone::Dim);
    unlock_with(ui, master);
}

fn unlock_with(ui: &Rc<Ui>, master: Zeroizing<String>) {
    *ui.master.borrow_mut() = Some(master);
    ui.session.borrow_mut().take();
    ui.unlock_btn.set_sensitive(false);
    ui.create_btn.hide();
    if ui.vault_email.trim().is_empty() {
        ui.unlock_btn.set_sensitive(true);
        set_status(&ui.cred_status, "no vault email set (SOC_VAULT_EMAIL) — cannot manage logins", Tone::Bad);
        return;
    }
    vault_job(
        ui,
        true,
        |session| session.list_logins(),
        |ui, result| {
            ui.unlock_btn.set_sensitive(true);
            match result {
                Ok(rows) => {
                    ui.main_box.set_no_show_all(false);
                    ui.main_box.show_all();
                    populate(ui, rows);
                }
                Err(VaultError::LoginRejected(_)) => {
                    ui.master.borrow_mut().take();
                    ui.create_btn.set_no_show_all(false);
                    ui.create_btn.show();
                    set_status(
                        &ui.cred_status,
                        "The vault rejected this master, or no account exists for the vault email yet. Re-enter the \
                         master, or create the account with it.",
                        Tone::Bad,
                    );
                }
                Err(e) => {
                    ui.master.borrow_mut().take();
                    set_status(&ui.cred_status, &format!("could not open the vault: {e}"), Tone::Bad);
                }
            }
        },
    );
}

fn create_account_clicked(ui: &Rc<Ui>) {
    let master = secret_text(&ui.master_entry);
    if master.is_empty() {
        set_status(&ui.cred_status, "type the master password the new account should use", Tone::Bad);
        return;
    }
    let detail = format!(
        "This registers {} on {} with the password typed above as its master. Keep that password: it cannot be \
         recovered.",
        ui.vault_email, ui.vault_url
    );
    confirm(ui, "Create the Vaultwarden account?", &detail, move |ui| {
        set_status(&ui.cred_status, "creating the account (generating keys, this takes a moment)…", Tone::Dim);
        ui.create_btn.set_sensitive(false);
        let (url, email, opts) = (ui.vault_url.clone(), ui.vault_email.clone(), ui.session_opts.clone());
        let weak = Rc::downgrade(ui);
        let for_unlock = master.clone();
        offload(
            move || ensure_account(&url, &email, &master, DEFAULT_ACCOUNT_NAME, &opts),
            move |result| {
                let Some(ui) = weak.upgrade() else { return };
                ui.create_btn.set_sensitive(true);
                match result {
                    Some(Ok(registered)) => {
                        let what = if registered == Registered::Created { "account created" } else { "account exists" };
                        set_status(&ui.cred_status, &format!("{what} — unlocking…"), Tone::Ok);
                        unlock_with(&ui, for_unlock);
                    }
                    Some(Err(e)) => {
                        set_status(&ui.cred_status, &format!("could not create the account: {e}"), Tone::Bad)
                    }
                    None => set_status(&ui.cred_status, "the account creation could not run", Tone::Bad),
                }
            },
        );
    });
}

fn populate(ui: &Rc<Ui>, rows: Vec<LoginSummary>) {
    ui.suppress_select.set(true);
    for child in ui.list.children() {
        ui.list.remove(&child);
    }
    for rec in &rows {
        let row = gtk::ListBoxRow::new();
        let line = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        line.set_border_width(6);
        let text = gtk::Box::new(gtk::Orientation::Vertical, 1);
        let name = make_label(&rec.name, None);
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        name.set_max_width_chars(28);
        name.set_markup(&format!("<b>{}</b>", glib::markup_escape_text(&rec.name)));
        let user = make_label(if rec.username.is_empty() { "—" } else { &rec.username }, Some("soc-config-sub"));
        user.set_ellipsize(gtk::pango::EllipsizeMode::End);
        user.set_max_width_chars(28);
        text.pack_start(&name, false, false, 0);
        text.pack_start(&user, false, false, 0);
        line.pack_start(&text, true, true, 0);
        if rec.has_totp {
            line.pack_start(&make_label("TOTP", Some("soc-config-tag")), false, false, 0);
        }
        row.add(&line);
        ui.list.add(&row);
    }
    ui.list.show_all();
    ui.suppress_select.set(false);
    let n = rows.len();
    *ui.logins.borrow_mut() = rows;
    set_status(&ui.cred_status, &format!("{n} login{} in the vault", if n == 1 { "" } else { "s" }), Tone::Dim);
}

fn reload_logins(ui: &Rc<Ui>) {
    set_status(&ui.cred_status, "loading logins…", Tone::Dim);
    vault_job(
        ui,
        false,
        |session| session.list_logins(),
        |ui, result| match result {
            Ok(rows) => populate(ui, rows),
            Err(e) => set_status(&ui.cred_status, &format!("could not list logins: {e}"), Tone::Bad),
        },
    );
}

fn new_login(ui: &Rc<Ui>) {
    *ui.editing.borrow_mut() = None;
    *ui.editing_notes.borrow_mut() = Zeroizing::new(String::new());
    for entry in [&ui.f_name, &ui.f_user, &ui.f_pass, &ui.f_totp, &ui.f_uri] {
        entry.set_text("");
    }
    ui.suppress_select.set(true);
    ui.list.unselect_all();
    ui.suppress_select.set(false);
    ui.delete_btn.set_sensitive(false);
    ui.proxy_btn.set_sensitive(false);
    tick(ui);
    set_status(&ui.cred_status, "new login — fill the form and Save", Tone::Dim);
}

fn login_selected(ui: &Rc<Ui>, index: i32) {
    if ui.suppress_select.get() {
        return;
    }
    let name = usize::try_from(index).ok().and_then(|i| ui.logins.borrow().get(i).map(|r| r.name.clone()));
    let Some(name) = name else { return };
    let shown = name.clone();
    os_gate(
        ui,
        &format!("view '{shown}'"),
        |ui| {
            ui.suppress_select.set(true);
            ui.list.unselect_all();
            ui.suppress_select.set(false);
        },
        move |ui| {
            set_status(&ui.cred_status, &format!("loading '{name}'…"), Tone::Dim);
            let wanted = name.clone();
            vault_job(
                ui,
                false,
                move |session| session.get_login(&wanted),
                move |ui, result| match result {
                    Ok(Some(rec)) => {
                        *ui.editing.borrow_mut() = Some(rec.name.clone());
                        *ui.editing_notes.borrow_mut() = rec.notes.clone();
                        ui.f_name.set_text(&rec.name);
                        ui.f_user.set_text(&rec.username);
                        ui.f_pass.set_text(&rec.password);
                        ui.f_totp.set_text(&rec.totp);
                        ui.f_uri.set_text(&rec.uri);
                        ui.delete_btn.set_sensitive(true);
                        ui.proxy_btn.set_sensitive(true);
                        tick(ui);
                        set_status(&ui.cred_status, &format!("editing '{}'", rec.name), Tone::Dim);
                    }
                    Ok(None) => set_status(&ui.cred_status, "login not found", Tone::Bad),
                    Err(e) => set_status(&ui.cred_status, &format!("could not load '{name}': {e}"), Tone::Bad),
                },
            );
        },
    );
}

fn save_clicked(ui: &Rc<Ui>) {
    let name = ui.f_name.text().trim().to_string();
    if name.is_empty() {
        set_status(&ui.cred_status, "a login needs a name", Tone::Bad);
        return;
    }
    let totp = Zeroizing::new(ui.f_totp.text().trim().to_string());
    if live_code(&totp, soc_state::unix_now()) == LiveCode::Invalid {
        set_status(&ui.cred_status, "the TOTP secret is not valid base32 / otpauth", Tone::Bad);
        return;
    }
    let editing = ui.editing.borrow().clone();
    let clash = editing.is_none() && ui.logins.borrow().iter().any(|r| r.name == name);
    if clash {
        let detail = "Saving will overwrite its username, password and TOTP. Select it from the list to edit instead.";
        confirm(ui, &format!("A login named '{name}' already exists."), detail, do_save);
    } else {
        do_save(ui);
    }
}

fn do_save(ui: &Rc<Ui>) {
    let name = ui.f_name.text().trim().to_string();
    let user = secret_text(&ui.f_user);
    let password = secret_text(&ui.f_pass);
    let totp = Zeroizing::new(ui.f_totp.text().trim().to_string());
    let uri = Zeroizing::new(ui.f_uri.text().trim().to_string());
    let notes = ui.editing_notes.borrow().clone();
    let rename_from = ui.editing.borrow().clone().filter(|old| *old != name);
    set_status(&ui.cred_status, &format!("saving '{name}'…"), Tone::Dim);
    ui.save_btn.set_sensitive(false);
    let job_name = name.clone();
    vault_job(
        ui,
        false,
        move |session| {
            let spec = LoginSpec {
                name: &job_name,
                username: &user,
                password: &password,
                notes: (!notes.is_empty()).then_some(notes.as_str()),
                uri: (!uri.is_empty()).then_some(uri.as_str()),
                totp: (!totp.is_empty()).then_some(totp.as_str()),
                rename_from: rename_from.as_deref(),
            };
            session.upsert_login(&spec)
        },
        move |ui, result| {
            ui.save_btn.set_sensitive(true);
            match result {
                Ok(action) => {
                    *ui.editing.borrow_mut() = Some(name.clone());
                    ui.delete_btn.set_sensitive(true);
                    ui.proxy_btn.set_sensitive(true);
                    set_status(&ui.cred_status, &format!("{} '{name}'", action.as_str()), Tone::Ok);
                    reload_logins(ui);
                }
                Err(e) => set_status(&ui.cred_status, &format!("could not save '{name}': {e}"), Tone::Bad),
            }
        },
    );
}

fn delete_clicked(ui: &Rc<Ui>) {
    let name = ui.editing.borrow().clone().unwrap_or_else(|| ui.f_name.text().trim().to_string());
    if name.is_empty() {
        return;
    }
    let shown = name.clone();
    confirm(ui, &format!("Delete '{shown}'?"), "This removes the login from Vaultwarden. It cannot be undone.", {
        move |ui| {
            let reason = format!("delete '{name}'");
            os_gate(
                ui,
                &reason,
                |_| {},
                move |ui| {
                    set_status(&ui.cred_status, &format!("deleting '{name}'…"), Tone::Dim);
                    let wanted = name.clone();
                    vault_job(
                        ui,
                        false,
                        move |session| session.delete_login(&wanted),
                        move |ui, result| match result {
                            Ok(true) => {
                                new_login(ui);
                                set_status(&ui.cred_status, &format!("deleted '{name}'"), Tone::Ok);
                                reload_logins(ui);
                            }
                            Ok(false) => set_status(&ui.cred_status, &format!("no login named '{name}'"), Tone::Bad),
                            Err(e) => {
                                set_status(&ui.cred_status, &format!("could not delete '{name}': {e}"), Tone::Bad)
                            }
                        },
                    );
                },
            );
        }
    });
}

fn generate_totp_clicked(ui: &Rc<Ui>) {
    let existing = !ui.f_totp.text().trim().is_empty();
    if existing {
        confirm(
            ui,
            "Replace the existing TOTP secret?",
            "The current authenticator enrolment stops working once you Save.",
            fill_new_totp,
        );
    } else {
        fill_new_totp(ui);
    }
}

fn fill_new_totp(ui: &Rc<Ui>) {
    match generate_secret(TOTP_SECRET_BYTES) {
        Ok(secret) => {
            ui.f_totp.set_text(&secret);
            tick(ui);
            set_status(&ui.cred_status, "generated a new TOTP secret — Save to store it", Tone::Dim);
        }
        Err(e) => set_status(&ui.cred_status, &format!("could not generate a secret: {e}"), Tone::Bad),
    }
}

fn show_uri_clicked(ui: &Rc<Ui>) {
    let typed = secret_text(&ui.f_totp);
    let secret = typed.trim();
    if secret.is_empty() {
        set_status(&ui.cred_status, "no TOTP secret to build a URI from", Tone::Bad);
        return;
    }
    if live_code(secret, soc_state::unix_now()) == LiveCode::Invalid {
        set_status(&ui.cred_status, "the TOTP secret is not valid base32 / otpauth", Tone::Bad);
        return;
    }
    let name = {
        let typed_name = ui.f_name.text();
        if typed_name.trim().is_empty() { "login".to_string() } else { typed_name.trim().to_string() }
    };
    let uri = setup_uri(secret, &name, ISSUER_LOGIN);
    let bare = (!secret.to_ascii_lowercase().starts_with("otpauth://")).then_some(secret);
    show_uri_dialog(ui, "TOTP setup URI", &format!("Add '{name}' to a phone authenticator:"), &uri, bare);
}

fn proxy_clicked(ui: &Rc<Ui>) {
    let Some(name) = ui.editing.borrow().clone() else {
        set_status(&ui.cred_status, "select or save a login first", Tone::Bad);
        return;
    };
    set_status(&ui.cred_status, &format!("setting '{name}' as the proxy login…"), Tone::Dim);
    let dir = ui.state_dir.clone();
    let item = name.clone();
    let weak = Rc::downgrade(ui);
    offload(
        move || -> Result<(), Failure> {
            let mut overrides = Overrides::load(&dir)?;
            set_proxy_item(&mut overrides, &item);
            overrides.save(&dir)?;
            Ok(())
        },
        move |result| {
            let Some(ui) = weak.upgrade() else { return };
            match result {
                Some(Ok(())) => set_status(
                    &ui.cred_status,
                    &format!("'{name}' is now the proxy login (applies when the wall next loads its settings)"),
                    Tone::Ok,
                ),
                Some(Err(e)) => set_status(&ui.cred_status, &format!("could not save the proxy login: {e}"), Tone::Bad),
                None => set_status(&ui.cred_status, "the proxy setting could not run", Tone::Bad),
            }
        },
    );
}

// ---------------------------------------------------------------------------
// Security pane.
// ---------------------------------------------------------------------------

fn enrolled_text(on: bool) -> &'static str {
    if on { "● enrolled" } else { "○ not enrolled" }
}

fn apply_sec_state(ui: &Rc<Ui>, state: SecState) {
    set_status(&ui.pin_status, enrolled_text(state.pin), if state.pin { Tone::Ok } else { Tone::Dim });
    set_status(&ui.totp_status, enrolled_text(state.totp), if state.totp { Tone::Ok } else { Tone::Dim });
    *ui.panel_totp.borrow_mut() = state.secret;
    tick(ui);
}

fn refresh_security(ui: &Rc<Ui>) {
    let dir = ui.state_dir.clone();
    let weak = Rc::downgrade(ui);
    offload(
        move || read_sec_state(&dir),
        move |state| {
            if let (Some(ui), Some(state)) = (weak.upgrade(), state) {
                apply_sec_state(&ui, state);
            }
        },
    );
}

fn sec_report(ui: &Rc<Ui>, text: &str, tone: Tone) {
    set_status(&ui.sec_status, text, tone);
}

fn set_pin_clicked(ui: &Rc<Ui>) {
    let pin = secret_text(&ui.pin_entry);
    let confirm_pin = secret_text(&ui.pin_confirm);
    if pin.is_empty() {
        sec_report(ui, "enter a PIN", Tone::Bad);
        return;
    }
    if *pin != *confirm_pin {
        sec_report(ui, "the two PINs do not match", Tone::Bad);
        return;
    }
    let verdict = ui.policy.check(&pin, SecretKind::Pin);
    if !verdict.ok {
        sec_report(ui, &format!("PIN refused: {}", verdict.summary()), Tone::Bad);
        return;
    }
    sec_report(ui, "saving the PIN…", Tone::Dim);
    let dir = ui.state_dir.clone();
    let weak = Rc::downgrade(ui);
    offload(
        move || -> Result<SecState, Failure> {
            LockStore::new(&dir).pin().set(&pin)?;
            Ok(read_sec_state(&dir))
        },
        move |result| {
            let Some(ui) = weak.upgrade() else { return };
            match result {
                Some(Ok(state)) => {
                    ui.pin_entry.set_text("");
                    ui.pin_confirm.set_text("");
                    sec_report(&ui, "PIN saved", Tone::Ok);
                    apply_sec_state(&ui, state);
                }
                Some(Err(e)) => sec_report(&ui, &format!("could not save the PIN: {e}"), Tone::Bad),
                None => sec_report(&ui, "the PIN could not be saved", Tone::Bad),
            }
        },
    );
}

/// Clear one lock credential (after an OS-password check and a confirmation).
fn clear_credential(
    ui: &Rc<Ui>,
    what: &'static str,
    detail: &'static str,
    clear: fn(&LockStore) -> Result<(), Failure>,
) {
    confirm(ui, &format!("{what}?"), detail, move |ui| {
        os_gate(
            ui,
            &what.to_lowercase(),
            |_| {},
            move |ui| {
                let dir = ui.state_dir.clone();
                let weak = Rc::downgrade(ui);
                offload(
                    move || -> Result<SecState, Failure> {
                        clear(&LockStore::new(&dir))?;
                        Ok(read_sec_state(&dir))
                    },
                    move |result| {
                        let Some(ui) = weak.upgrade() else { return };
                        match result {
                            Some(Ok(state)) => {
                                ui.totp_uri.set_text("");
                                ui.totp_secret.set_text("");
                                sec_report(&ui, &format!("{what}: done"), Tone::Ok);
                                apply_sec_state(&ui, state);
                            }
                            Some(Err(e)) => sec_report(&ui, &format!("{what} failed: {e}"), Tone::Bad),
                            None => sec_report(&ui, &format!("{what} could not run"), Tone::Bad),
                        }
                    },
                );
            },
        );
    });
}

fn clear_pin_clicked(ui: &Rc<Ui>) {
    clear_credential(ui, "Clear the panel-lock PIN", "The wall will no longer need this PIN to unlock.", |store| {
        store.pin().clear().map_err(Failure::from)
    });
}

fn disable_totp_clicked(ui: &Rc<Ui>) {
    clear_credential(
        ui,
        "Disable the authenticator",
        "You will need a fresh setup URI to enrol again. This cannot be undone.",
        |store| store.totp().clear().map_err(Failure::from),
    );
}

fn enable_totp_clicked(ui: &Rc<Ui>) {
    let enrolled = ui.totp_status.text().starts_with('●');
    if enrolled {
        confirm(
            ui,
            "Replace the authenticator secret?",
            "A new secret is generated and the old one stops working: every enrolled phone must re-scan the new \
             setup URI.",
            |ui| os_gate(ui, "replace the authenticator", |_| {}, enrol_totp),
        );
    } else {
        enrol_totp(ui);
    }
}

fn enrol_totp(ui: &Rc<Ui>) {
    sec_report(ui, "generating the authenticator secret…", Tone::Dim);
    let dir = ui.state_dir.clone();
    let weak = Rc::downgrade(ui);
    offload(
        move || -> Result<(String, Zeroizing<String>, SecState), Failure> {
            let enrollment = LockStore::new(&dir).enroll_totp()?;
            let state = read_sec_state(&dir);
            Ok((enrollment.uri.clone(), enrollment.secret.clone(), state))
        },
        move |result| {
            let Some(ui) = weak.upgrade() else { return };
            match result {
                Some(Ok((uri, secret, state))) => {
                    ui.totp_uri.set_text(&uri);
                    ui.totp_secret.set_text(&secret);
                    sec_report(&ui, "TOTP enabled — add the setup URI or secret to your authenticator app", Tone::Ok);
                    apply_sec_state(&ui, state);
                }
                Some(Err(e)) => sec_report(&ui, &format!("could not enable TOTP: {e}"), Tone::Bad),
                None => sec_report(&ui, "TOTP could not be enabled", Tone::Bad),
            }
        },
    );
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

/// Show the credentials & security control center and run its main loop.
/// Returns the process exit code (`1` when there is no display).
pub fn run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("usage: soc-wall credcenter\n\nThe credentials & security control center (needs a display).");
        return 0;
    }
    if !style::init() {
        eprintln!("[soc-wall] credcenter: no graphical display ($DISPLAY / $WAYLAND_DISPLAY unset)");
        return 1;
    }
    let state_dir = soc_state::state_dir_from_env();
    let enrolled = {
        let store = LockStore::new(&state_dir);
        store.pin().is_set() || store.totp().is_set()
    };
    let ui = build(state_dir, enrolled);
    ui.win.show_all();
    if enrolled {
        ui.gate_entry.grab_focus();
    } else {
        begin_session(&ui);
    }
    gtk::main();
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// RFC 6238 SHA-1 seed ("12345678901234567890").
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> TempDir {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "credcenter-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn live_code_matches_the_rfc_vector() {
        assert_eq!(live_code(RFC_SECRET, 59), LiveCode::Code("287082".to_string()));
        assert_eq!(live_code("  ", 59), LiveCode::Empty);
        assert_eq!(live_code("not base32 !!", 59), LiveCode::Invalid);
    }

    #[test]
    fn ticker_formatting() {
        assert_eq!(format_code("287082"), "287 082");
        assert_eq!(format_code("12345"), "12345");
        assert_eq!(seconds_left(0), 30);
        assert_eq!(seconds_left(59), 1);
        assert_eq!(seconds_left(60), 30);
        let markup = code_markup(&LiveCode::Code("287082".into()), 59);
        assert!(markup.contains("287 082"));
        assert!(markup.contains("1s"));
        assert!(code_markup(&LiveCode::Empty, 0).contains("------"));
        assert!(code_markup(&LiveCode::Invalid, 0).contains("invalid"));
    }

    #[test]
    fn setup_uri_wraps_a_bare_secret_and_keeps_a_uri() {
        let uri = setup_uri(RFC_SECRET, "wazuh", "SOC Wall");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains(&format!("secret={RFC_SECRET}")));
        assert!(uri.contains("issuer=SOC+Wall") || uri.contains("issuer=SOC%20Wall"));
        let given = "otpauth://totp/x?secret=ABC";
        assert_eq!(setup_uri(&format!(" {given} "), "n", "i"), given);
    }

    #[test]
    fn os_gate_window() {
        let now = Instant::now();
        assert!(!gate_open(None, now));
        assert!(gate_open(Some(now + Duration::from_secs(5)), now));
        assert!(!gate_open(Some(now), now));
    }

    #[test]
    fn master_description_and_hints() {
        assert!(describe_master(SealSource::Auto, true, true).contains("sealed"));
        assert!(describe_master(SealSource::SecretService, false, false).contains("type it"));
        assert!(gate_hint(true, true).contains("PIN or"));
        assert!(gate_hint(false, true).contains("authenticator"));
        let policy = Policy::default();
        assert!(pin_hint(&policy, "").contains("digits"));
        assert!(pin_hint(&policy, "4821").contains("Meets"));
        assert!(pin_hint(&policy, "12").contains("at least"));
    }

    #[test]
    fn proxy_item_keeps_other_keys() {
        let mut o = Overrides::default();
        o.as_dict_mut().insert(KEY_PROXY.to_string(), serde_json::json!({"url": "http://p.test:3128"}));
        set_proxy_item(&mut o, "Corp proxy");
        let section = o.get(KEY_PROXY).and_then(Value::as_object).unwrap();
        assert_eq!(section.get("vault_item").and_then(Value::as_str), Some("Corp proxy"));
        assert_eq!(section.get("url").and_then(Value::as_str), Some("http://p.test:3128"));
        let mut empty = Overrides::default();
        set_proxy_item(&mut empty, "x");
        assert!(empty.get(KEY_PROXY).is_some());
    }

    #[test]
    fn panel_lock_gate_verdicts() {
        let dir = TempDir::new();
        let store = LockStore::new(&dir.0).with_pin_iterations(soc_state::pin::MIN_PBKDF2_ITERATIONS);
        assert_eq!(check_panel_lock(&store, "1", 1000), Verdict::NothingEnrolled);
        store.pin().set("4821").unwrap();
        assert_eq!(check_panel_lock(&store, " 4821 ", 1000), Verdict::Granted);
        assert!(matches!(check_panel_lock(&store, "0000", 1000), Verdict::Denied { .. }));
        assert!(matches!(check_panel_lock(&store, "", 5000), Verdict::Denied { .. } | Verdict::Throttled { .. }));
    }

    #[test]
    fn panel_lock_totp_unlocks() {
        let dir = TempDir::new();
        let store = LockStore::new(&dir.0);
        let enrollment = store.enroll_totp().unwrap();
        let now = 1_700_000_000;
        let code = soc_state::totp::code_at(&enrollment.secret, now).unwrap();
        assert_eq!(check_panel_lock(&store, &code, now), Verdict::Granted);
    }

    #[test]
    fn wait_is_clamped() {
        assert_eq!(wait_secs(0), 1);
        assert_eq!(wait_secs(7), 7);
        assert_eq!(wait_secs(u64::MAX), 3600);
    }
}
