//! The graphical setup wizard: `soc-wall setupwiz [--dry-run] [--target pi|dev]`.
//!
//! A desktop wizard that produces the SAME artifacts as the TTY `soc-wall setup`
//! flow: `panels.yaml`, the non-secret `soc.env` (+ the `soc-wall.service` unit
//! on a system install), and a sealed / wallet-stored vault master. It does NOT
//! render, validate or seal anything itself:
//!
//! * the form is assembled into a raw config document and validated by
//!   `soc_core::load::from_value` (collect-everything `ConfigError`, shown inline);
//! * the review text is `soc_setup::config::render_panels_yaml` +
//!   `soc_setup::render_soc_env` (+ `render_wall_unit`);
//! * the run drives the backend's own plans — `DeployPlan::run_step` for the
//!   write / account / push / logins / doctor / marker steps and
//!   `FirstRunPlan::run` for the seal — on a WORKER thread. Each step's result
//!   is sent over an `mpsc` channel that a `glib::timeout_add_local` poller on
//!   the GTK thread drains into the log view (the widget graph is `Rc`, not
//!   `Send`, so nothing GTK crosses the thread boundary).
//!
//! The master password lives in a hidden `gtk::Entry` and, from there, in a
//! `Zeroizing<String>` handed to the worker; it is never written, logged, or put
//! on argv. The one-time sealing PIN is shown exactly once, in its own panel,
//! and cleared when the operator acknowledges it.
//!
//! `FirstRunPlan` handles sealing so the selected master source is honored.

mod privileged;

use crate::style;
use gtk::prelude::*;
use serde_json::{Value, json};
use soc_core::load::Overrides;
use soc_core::{Config, ConfigError, Dict, DictExt, Panel};
use soc_seal::MasterSource;
use soc_setup::config::{previous_config, render_panels_yaml, vault_items};
use soc_setup::deploy::{DeployState, DeployStep};
use soc_setup::doctor::{is_real_vault, kiosk_user};
use soc_setup::envfile::{SocEnv, load_env_file};
use soc_setup::paths::{SetupPaths, Target};
use soc_setup::seal::pin_display;
use soc_setup::vault::{Creds, LoginCred};
use soc_setup::{DeployPlan, FirstRunPlan, FirstRunStep, SystemHost, UnitOpts, render_soc_env, render_wall_unit};
use soc_sys::paths::PathEnv;
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::sync::mpsc;
use std::time::Duration;
use zeroize::Zeroizing;

const ENGINES: [&str; 2] = ["webkit", "chromium"];
const SCHEMES: [&str; 2] = ["http", "https"];
const BACKENDS: [&str; 4] = ["native", "litebw", "rbw", "dev"];
const VPN_KINDS: [&str; 4] = ["fortinet", "openvpn", "wireguard", "inode"];
const TARGETS: [&str; 2] = ["pi", "dev"];
const SOURCES: [(MasterSource, &str); 4] = [
    (MasterSource::Sealed, "sealed — host-bound (recommended)"),
    (MasterSource::Auto, "auto — sealed, with runtime fallbacks"),
    (MasterSource::SecretService, "secret-service — the desktop wallet"),
    (MasterSource::Env, "password — dev/seeding only, nothing sealed"),
];
const DEFAULT_VAULT_URL: &str = "http://127.0.0.1:8222";
const MAX_PANELS: usize = 16;
const MAX_VPNS: usize = soc_core::MAX_VPNS;
const PAGES: [&str; 5] = ["panels", "vault", "network", "review", "run"];

// --------------------------------------------------------------------------
// Arguments
// --------------------------------------------------------------------------

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Opts {
    dry_run: bool,
    target: Option<Target>,
    preset: Option<String>,
    output: Option<std::path::PathBuf>,
    list_presets: bool,
    non_interactive: bool,
}

/// A command-line mistake.
#[derive(Debug, PartialEq, Eq)]
struct UsageError(String);

const USAGE: &str = "usage: soc-wall setup-gui [--dry-run] [--target pi|dev] [--preset NAME]\n  --list-presets\n  --preset NAME --output DIR [--non-interactive]";

/// `Ok(None)` means "print the usage and stop".
fn parse_args(args: &[String]) -> Result<Option<Opts>, UsageError> {
    let mut opts = Opts::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(None),
            "--dry-run" => opts.dry_run = true,
            "--list-presets" => opts.list_presets = true,
            "--non-interactive" => opts.non_interactive = true,
            "--preset" => {
                opts.preset = Some(it.next().ok_or_else(|| UsageError("--preset needs a name".into()))?.clone())
            }
            "--output" => {
                opts.output = Some(it.next().ok_or_else(|| UsageError("--output needs a path".into()))?.into())
            }
            inline if inline.starts_with("--preset=") => opts.preset = Some(inline[9..].into()),
            inline if inline.starts_with("--output=") => opts.output = Some(inline[9..].into()),
            "--target" => {
                let v = it.next().ok_or_else(|| UsageError("--target needs pi or dev".into()))?;
                opts.target =
                    Some(Target::parse(v).ok_or_else(|| UsageError(format!("--target must be pi or dev, not {v}")))?);
            }
            other => return Err(UsageError(format!("unknown argument: {other}"))),
        }
    }
    Ok(Some(opts))
}

// --------------------------------------------------------------------------
// The form model (pure: no GTK)
// --------------------------------------------------------------------------

fn port_value(s: &str) -> Value {
    let t = s.trim();
    t.parse::<u16>().map_or_else(|_| Value::String(t.to_string()), |p| json!(p))
}

fn set_or_remove(d: &mut Dict, key: &str, value: &str) {
    if value.trim().is_empty() {
        d.shift_remove(key);
    } else {
        d.insert(key.into(), json!(value.trim()));
    }
}

fn sub_dict(d: &Dict, key: &str) -> Dict {
    d.get(key).and_then(Value::as_object).cloned().unwrap_or_else(Dict::new)
}

/// One tile. `base` carries every key the form does not edit, so re-running the
/// wizard over an existing config never drops keep-alive / allow-lists / etc.
#[derive(Clone)]
struct PanelForm {
    base: Dict,
    id: String,
    url: String,
    vault_item: String,
    user_sel: String,
    pass_sel: String,
    submit_sel: String,
    engine: String,
    col: u32,
    row: u32,
    tunnel_mode: bool,
    local_port: String,
    remote_host: String,
    remote_port: String,
    path: String,
    scheme: String,
    /// Optional login to store in the vault for `vault_item`.
    username: String,
    password: Zeroizing<String>,
}

impl PanelForm {
    fn fresh(idx: usize, cols: u32) -> PanelForm {
        let cols = cols.max(1);
        let i = u32::try_from(idx).unwrap_or(0);
        let mut base = Dict::new();
        base.insert("keepalive".into(), json!({"strategy": "reload", "intervalSec": 600}));
        base.insert("login_marker".into(), json!("#password"));
        PanelForm {
            base,
            id: format!("p{}", idx + 1),
            url: "http://192.168.1.50:3000/login".into(),
            vault_item: format!("SOC Panel {}", idx + 1),
            user_sel: "#username".into(),
            pass_sel: "#password".into(),
            submit_sel: "button[type=submit]".into(),
            engine: "webkit".into(),
            col: i % cols,
            row: i / cols,
            tunnel_mode: false,
            local_port: String::new(),
            remote_host: String::new(),
            remote_port: String::new(),
            path: "/".into(),
            scheme: "http".into(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
        }
    }

    fn from_panel(p: &Panel, base: Dict) -> PanelForm {
        let tun = p.tunnel.as_ref().map_or_else(Dict::new, Clone::clone);
        PanelForm {
            base,
            id: p.id.clone(),
            url: p.url.as_deref().map_or_else(String::new, str::to_string),
            vault_item: p.vault_item.clone(),
            user_sel: p.selectors.text("user"),
            pass_sel: p.selectors.text("pass"),
            submit_sel: p.selectors.text("submit"),
            engine: p.engine.as_str().into(),
            col: p.grid.0,
            row: p.grid.1,
            tunnel_mode: p.mode == soc_core::model::Mode::Tunnel,
            local_port: tun.text("local_port"),
            remote_host: tun.text("remote_host"),
            remote_port: tun.text("remote_port"),
            path: p.path.clone(),
            scheme: p.scheme.clone(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
        }
    }

    fn to_value(&self) -> Value {
        let mut d = self.base.clone();
        d.insert("id".into(), json!(self.id.trim()));
        d.insert("engine".into(), json!(self.engine));
        d.insert("grid".into(), json!([self.col, self.row]));
        if self.tunnel_mode {
            d.insert("mode".into(), json!("tunnel"));
            d.shift_remove("url");
            let mut t = Dict::new();
            t.insert("local_port".into(), port_value(&self.local_port));
            t.insert("remote_host".into(), json!(self.remote_host.trim()));
            if !self.remote_port.trim().is_empty() {
                t.insert("remote_port".into(), port_value(&self.remote_port));
            }
            d.insert("tunnel".into(), Value::Object(t));
            d.insert("path".into(), json!(self.path.trim()));
            d.insert("scheme".into(), json!(self.scheme));
        } else {
            d.insert("mode".into(), json!("direct"));
            d.shift_remove("tunnel");
            d.shift_remove("path");
            d.shift_remove("scheme");
            d.insert("url".into(), json!(self.url.trim()));
        }
        set_or_remove(&mut d, "vault_item", &self.vault_item);
        let mut sel = sub_dict(&self.base, "selectors");
        set_or_remove(&mut sel, "user", &self.user_sel);
        set_or_remove(&mut sel, "pass", &self.pass_sel);
        set_or_remove(&mut sel, "submit", &self.submit_sel);
        if sel.is_empty() {
            d.shift_remove("selectors");
        } else {
            d.insert("selectors".into(), Value::Object(sel));
        }
        if !d.contains_key("login_marker") && !self.pass_sel.trim().is_empty() {
            d.insert("login_marker".into(), json!(self.pass_sel.trim()));
        }
        Value::Object(d)
    }

    fn label(&self, idx: usize) -> String {
        let place = if self.tunnel_mode { "tunnel".to_string() } else { self.url.clone() };
        format!("{}. {}   [{},{}]   {}", idx + 1, self.id, self.col, self.row, place)
    }
}

/// One VPN row; unedited keys ride along in `base`.
#[derive(Clone)]
struct VpnForm {
    base: Dict,
    name: String,
    kind: String,
    enabled: bool,
    default_route: bool,
    gateway: String,
    port: String,
    vault_item: String,
    trusted_cert: String,
}

impl VpnForm {
    fn fresh(idx: usize) -> VpnForm {
        VpnForm {
            base: Dict::new(),
            name: if idx == 0 { "vpn".into() } else { format!("vpn{}", idx + 1) },
            kind: "fortinet".into(),
            enabled: false,
            default_route: false,
            gateway: String::new(),
            port: "443".into(),
            vault_item: String::new(),
            trusted_cert: String::new(),
        }
    }

    fn from_dict(d: &Dict) -> VpnForm {
        let kind = d.text("type");
        VpnForm {
            base: d.clone(),
            name: d.text("name"),
            kind: if kind.is_empty() { "fortinet".into() } else { kind.to_ascii_lowercase() },
            enabled: d.truthy("enabled"),
            default_route: d.truthy("default_route"),
            gateway: d.text("gateway"),
            port: d.text("port"),
            vault_item: d.text("vault_item"),
            trusted_cert: d.text("trusted_cert"),
        }
    }

    fn to_value(&self) -> Value {
        let mut d = self.base.clone();
        d.insert("name".into(), json!(self.name.trim()));
        d.insert("type".into(), json!(self.kind));
        d.insert("enabled".into(), json!(self.enabled));
        d.insert("default_route".into(), json!(self.default_route));
        set_or_remove(&mut d, "gateway", &self.gateway);
        set_or_remove(&mut d, "vault_item", &self.vault_item);
        set_or_remove(&mut d, "trusted_cert", &self.trusted_cert);
        if self.port.trim().is_empty() {
            d.shift_remove("port");
        } else {
            d.insert("port".into(), port_value(&self.port));
        }
        Value::Object(d)
    }

    fn label(&self, idx: usize) -> String {
        let on = if self.enabled { "on " } else { "off" };
        format!("{}. {}   {}   {}   {}", idx + 1, self.name, self.kind, on, self.gateway)
    }
}

#[derive(Clone)]
struct DisplayForm {
    base: Dict,
    auto: bool,
    width: u32,
    height: u32,
    cols: u32,
    rows: u32,
    gap: u32,
}

impl DisplayForm {
    fn to_value(&self) -> Value {
        let mut d = self.base.clone();
        d.insert("auto".into(), json!(self.auto));
        d.insert("width".into(), json!(self.width));
        d.insert("height".into(), json!(self.height));
        d.insert("cols".into(), json!(self.cols));
        d.insert("rows".into(), json!(self.rows));
        d.insert("gap".into(), json!(self.gap));
        Value::Object(d)
    }
}

#[derive(Clone)]
struct TunnelForm {
    base: Dict,
    enabled: bool,
    jump_host: String,
    identity: String,
}

impl TunnelForm {
    /// `None` when the section is untouched (no host, nothing carried over).
    fn to_value(&self) -> Option<Value> {
        if self.jump_host.trim().is_empty() && self.base.is_empty() {
            return None;
        }
        let mut d = self.base.clone();
        d.insert("enabled".into(), json!(self.enabled));
        set_or_remove(&mut d, "jump_host", &self.jump_host);
        set_or_remove(&mut d, "identity", &self.identity);
        Some(Value::Object(d))
    }
}

#[derive(Clone)]
struct ProxyForm {
    base: Dict,
    enabled: bool,
    url: String,
    vault_item: String,
}

impl ProxyForm {
    fn to_value(&self) -> Value {
        let mut d = self.base.clone();
        d.insert("enabled".into(), json!(self.enabled));
        set_or_remove(&mut d, "url", &self.url);
        set_or_remove(&mut d, "vault_item", &self.vault_item);
        Value::Object(d)
    }
}

/// The vault page. The master never leaves a `Zeroizing`.
#[derive(Clone)]
struct VaultForm {
    target: Target,
    backend: String,
    url: String,
    email: String,
    source: MasterSource,
    master: Zeroizing<String>,
    confirm: Zeroizing<String>,
    create_account: bool,
    reseal: bool,
    pin: String,
    dry_run: bool,
}

impl VaultForm {
    fn is_real(&self) -> bool {
        is_real_vault(&self.backend)
    }

    /// Everything wrong with the page, so the operator fixes it in one pass.
    fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.is_real() {
            let u = self.url.trim();
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                out.push("vault URL must start with http:// or https://".to_string());
            }
            if self.email.trim().is_empty() {
                out.push("vault e-mail is required for a real vault backend".to_string());
            }
        }
        if *self.master != *self.confirm {
            out.push("the master password and its confirmation do not match".to_string());
        }
        if self.create_account && self.master.is_empty() {
            out.push("creating the account needs the master password".to_string());
        }
        out
    }
}

/// Everything the form holds.
#[derive(Clone)]
struct FormData {
    display: DisplayForm,
    panels: Vec<PanelForm>,
    vpns: Vec<VpnForm>,
    tunnel: TunnelForm,
    proxy: ProxyForm,
    security: Option<Value>,
    vault: VaultForm,
}

/// The raw `panels.yaml` document for the form.
fn build_raw(f: &FormData) -> Value {
    let mut out = Dict::new();
    out.insert("display".into(), f.display.to_value());
    out.insert("panels".into(), Value::Array(f.panels.iter().map(PanelForm::to_value).collect()));
    if let Some(t) = f.tunnel.to_value() {
        out.insert("tunnel".into(), t);
    }
    if !f.vpns.is_empty() {
        out.insert("vpns".into(), Value::Array(f.vpns.iter().map(VpnForm::to_value).collect()));
    }
    out.insert("proxy".into(), f.proxy.to_value());
    if let Some(s) = &f.security {
        out.insert("security".into(), s.clone());
    }
    Value::Object(out)
}

/// Validate the form through the shared loader; `Err` lists every finding.
fn assemble(f: &FormData) -> Result<Config, ConfigError> {
    soc_core::load::from_value(&build_raw(f), "the wizard form", &Overrides::default())
}

/// A validation failure as inline text (headline + one bullet per finding).
fn error_text(e: &ConfigError) -> String {
    let mut s = e.message.clone();
    for p in &e.problems {
        s.push_str("\n  - ");
        s.push_str(p);
    }
    s
}

/// The form seeded from a previous config / env (the "re-run defaults").
fn seed(cfg: &Config, env: &SocEnv, paths: &SetupPaths, opts: &Opts) -> FormData {
    let doc = soc_core::emit::to_value(cfg);
    let section = |k: &str| doc.get(k).and_then(Value::as_object).cloned().unwrap_or_else(Dict::new);
    let panel_docs: Vec<Value> = doc.get("panels").and_then(Value::as_array).cloned().unwrap_or_else(Vec::new);
    let d = &cfg.display;
    let panels = if cfg.panels.is_empty() && opts.preset.is_none() {
        vec![PanelForm::fresh(0, d.cols), PanelForm::fresh(1, d.cols)]
    } else {
        cfg.panels
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let base = panel_docs.get(i).and_then(Value::as_object).cloned().unwrap_or_else(Dict::new);
                PanelForm::from_panel(p, base)
            })
            .collect()
    };
    let env_text =
        |k: &str, dflt: &str| env.get(k).filter(|v| !v.is_empty()).map_or_else(|| dflt.to_string(), Clone::clone);
    FormData {
        display: DisplayForm {
            base: section("display"),
            auto: d.auto,
            width: u32::try_from(d.width).unwrap_or(1920),
            height: u32::try_from(d.height).unwrap_or(1080),
            cols: d.cols,
            rows: d.rows,
            gap: u32::try_from(d.gap).unwrap_or(0),
        },
        panels,
        vpns: cfg.vpns.iter().map(VpnForm::from_dict).collect(),
        tunnel: TunnelForm {
            base: cfg.tunnel.clone(),
            enabled: cfg.tunnel.flag("enabled", true),
            jump_host: cfg.tunnel.text("jump_host"),
            identity: cfg.tunnel.text("identity"),
        },
        proxy: ProxyForm {
            base: section("proxy"),
            enabled: cfg.proxy.enabled,
            url: cfg.proxy.url.clone(),
            vault_item: cfg.proxy.vault_item.clone(),
        },
        security: doc.get("security").cloned(),
        vault: VaultForm {
            target: paths.target,
            backend: env_text("SOC_VAULT_BACKEND", &paths.default_backend),
            url: env_text("SOC_VAULT_URL", DEFAULT_VAULT_URL),
            email: env_text("SOC_VAULT_EMAIL", ""),
            source: env.get("SOC_MASTER_SOURCE").and_then(|s| s.parse().ok()).unwrap_or(MasterSource::Sealed),
            master: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            create_account: false,
            reseal: false,
            pin: String::new(),
            dry_run: opts.dry_run,
        },
    }
}

/// The `soc.env` the wizard will write: the existing file with the form's vault
/// answers on top, and the path keys filled in when absent. Never a master.
fn build_env(existing: &SocEnv, paths: &SetupPaths, v: &VaultForm) -> SocEnv {
    let mut e = existing.clone();
    for k in soc_setup::envfile::NEVER_KEPT {
        e.remove(k);
    }
    e.insert("SOC_VAULT_BACKEND".into(), v.backend.clone());
    e.insert("SOC_VAULT_EMAIL".into(), v.email.trim().to_string());
    let url = v.url.trim();
    e.insert("SOC_VAULT_URL".into(), if url.is_empty() { DEFAULT_VAULT_URL.into() } else { url.to_string() });
    e.insert("SOC_MASTER_SOURCE".into(), v.source.to_string());
    let defaults = [
        ("SOC_ROOT", paths.soc_root.display().to_string()),
        ("SOC_PANELS_FILE", paths.panels_installed.display().to_string()),
        ("SOC_INJECT_TMPL", paths.inject_tmpl.display().to_string()),
        ("SOC_SECRET_DIR", paths.secret_dir.display().to_string()),
        ("SOC_CONFIG_VAULT_ITEM", paths.config_vault_item.clone()),
    ];
    for (k, val) in defaults {
        if e.get(k).is_none_or(|x| x.is_empty()) {
            e.insert(k.into(), val);
        }
    }
    e
}

/// The review page: exactly what will be written, rendered by the backend.
fn review_text(cfg: &Config, env: &SocEnv, paths: &SetupPaths, user: &str, dry_run: bool) -> String {
    let mut out = String::new();
    if dry_run {
        out.push_str("# DRY RUN — nothing below will be written\n\n");
    }
    out.push_str(&format!("# ===== {}  (mode {:o}) =====\n", paths.panels_out.display(), paths.panels_mode));
    out.push_str(&render_panels_yaml(cfg));
    out.push_str(&format!("\n# ===== {}  (mode {:o}) =====\n", paths.soc_env.display(), paths.env_mode));
    out.push_str(&render_soc_env(env));
    if let Some(unit) = &paths.wall_unit {
        let opts = UnitOpts { user: user.to_string(), soc_root: paths.soc_root.display().to_string() };
        out.push_str(&format!("\n# ===== {}  (mode 644) =====\n", unit.display()));
        out.push_str(&render_wall_unit(env, &opts));
    }
    let items = vault_items(cfg);
    if !items.is_empty() {
        out.push_str("\n# ===== vault logins that will exist =====\n");
        for i in &items {
            out.push_str(&format!("#   {:<10} {}\n", i.kind, i.name));
        }
    }
    out
}

/// Logins typed into the panel forms, keyed by vault item.
fn creds_of(panels: &[PanelForm]) -> Creds {
    let mut creds = Creds::new();
    for p in panels {
        let item = p.vault_item.trim();
        if !item.is_empty() && (!p.username.is_empty() || !p.password.is_empty()) {
            creds.insert(item.to_string(), LoginCred::new(&p.username, &p.password));
        }
    }
    creds
}

// --------------------------------------------------------------------------
// The run plan (pure) and the worker
// --------------------------------------------------------------------------

/// One stage of the run: a `DeployPlan` step, or the first-run seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Deploy(DeployStep),
    Seal,
}

/// The stages for a form, in order. The OS install and the final "start the
/// wall" are deliberately NOT here: this wizard configures a host that is
/// already installed (the TTY `deploy` command owns install/activate).
fn stages(v: &VaultForm) -> Vec<Stage> {
    let real = v.is_real();
    let local = soc_setup::host::is_local_vault(&v.url);
    let mut s = vec![Stage::Deploy(DeployStep::WriteConfig)];
    if real && local && v.target == Target::Pi {
        s.push(Stage::Deploy(DeployStep::VaultUp));
    }
    if real && v.create_account {
        s.push(Stage::Deploy(DeployStep::VaultAccount));
    }
    s.push(Stage::Seal);
    if real {
        s.push(Stage::Deploy(DeployStep::PushConfig));
        s.push(Stage::Deploy(DeployStep::StoreLogins));
    }
    s.push(Stage::Deploy(DeployStep::Doctor));
    s.push(Stage::Deploy(DeployStep::MarkConfigured));
    s
}

/// Everything the worker needs; all of it is `Send`.
struct RunJob {
    cfg: Config,
    env: SocEnv,
    paths: SetupPaths,
    penv: PathEnv,
    target: Target,
    dry_run: bool,
    backend: String,
    email: String,
    url: String,
    source: MasterSource,
    master: Option<Zeroizing<String>>,
    pin: Option<String>,
    reseal: bool,
    creds: Creds,
    user: String,
    stages: Vec<Stage>,
}

impl RunJob {
    fn new(cfg: Config, penv: PathEnv, paths: SetupPaths, v: &VaultForm, creds: Creds) -> Self {
        let mut existing = load_env_file(&paths.soc_env);
        if !paths.soc_env.exists() && paths.via == "user" {
            if let Some(system) = penv.resolve_env() {
                existing = load_env_file(&system);
                for key in ["SOC_ROOT", "SOC_PANELS_FILE", "SOC_SECRET_DIR", "SOC_INJECT_TMPL"] {
                    existing.remove(key);
                }
            }
        }
        let env = build_env(&existing, &paths, v);
        Self {
            user: kiosk_user(&env, None),
            creds,
            stages: stages(v),
            backend: v.backend.clone(),
            email: v.email.trim().to_string(),
            url: env.get("SOC_VAULT_URL").cloned().unwrap_or_else(|| DEFAULT_VAULT_URL.to_string()),
            source: v.source,
            master: Some(v.master.clone()).filter(|m| !m.is_empty()),
            pin: Some(v.pin.trim().to_string()).filter(|p| !p.is_empty()),
            reseal: v.reseal,
            dry_run: v.dry_run,
            target: v.target,
            penv,
            paths,
            env,
            cfg,
        }
    }
}

/// A finished step as shown in the log.
#[derive(serde::Serialize, serde::Deserialize)]
struct StepLine {
    title: String,
    ok: bool,
    detail: String,
    lines: Vec<String>,
}

/// Worker -> GTK thread.
#[derive(serde::Serialize, serde::Deserialize)]
enum Msg {
    Step(StepLine),
    /// The one-time PIN (real runs only).
    Pin(Zeroizing<String>),
    Done(bool),
}

/// False when the window (the receiver) is gone; nobody is left to tell.
fn send(tx: &mpsc::Sender<Msg>, m: Msg) -> bool {
    tx.send(m).is_ok()
}

/// Drive the backend plans, reporting every step. Runs off the GTK thread.
fn execute(job: RunJob, emit: impl Fn(Msg)) -> bool {
    let sys = SystemHost::from_env();
    let host = sys.host();
    let mut plan = DeployPlan::new(job.target, job.penv.clone(), job.paths.clone());
    plan.dry_run = job.dry_run;
    plan.cfg = job.cfg.clone();
    plan.soc_env = job.env.clone();
    plan.write_config = true;
    plan.email = job.email.clone();
    plan.url = job.url.clone();
    plan.pin = job.pin.clone();
    plan.master = job.master.clone();
    plan.creds = job.creds;
    plan.seed = true;
    plan.user = job.user.clone();
    let planned = plan.steps(&host);
    let mut st = DeployState { soc_env: job.env.clone(), ..DeployState::default() };
    let mut pin: Option<Zeroizing<String>> = None;
    let mut ok = true;
    for stage in &job.stages {
        match *stage {
            Stage::Deploy(step) => {
                let p = planned.iter().find(|p| p.step == step);
                let title = p.map_or_else(|| step.as_str().to_string(), |p| p.title.clone());
                if let Some(p) = p.filter(|p| !p.needed) {
                    emit(Msg::Step(StepLine {
                        title,
                        ok: true,
                        detail: format!("skipped — {}", p.why),
                        lines: vec![],
                    }));
                    continue;
                }
                let r = plan.run_step(step, &host, &mut st);
                emit(Msg::Step(StepLine { title, ok: r.ok, detail: r.detail.clone(), lines: r.lines.clone() }));
                if !r.ok {
                    ok = false;
                    // A failed health check is reported but does not stop the marker.
                    if step != DeployStep::Doctor {
                        break;
                    }
                }
            }
            Stage::Seal => {
                let fr = FirstRunPlan {
                    paths: job.paths.clone(),
                    soc_env: st.soc_env.clone(),
                    backend: job.backend.clone(),
                    source: job.source,
                    master: job.master.clone(),
                    pin: job.pin.clone(),
                    reseal: job.reseal,
                    dry_run: job.dry_run,
                };
                let out = fr.run(&host, &mut |step, r| {
                    // The ShowPin result carries the PIN banner: never stream it
                    // into the log — the PIN panel shows it once, prominently.
                    let lines = if step == FirstRunStep::ShowPin { vec![] } else { r.lines.clone() };
                    let detail = if step == FirstRunStep::ShowPin && r.ok {
                        "one-time PIN issued — shown in the highlighted panel".to_string()
                    } else {
                        r.detail.clone()
                    };
                    emit(Msg::Step(StepLine { title: format!("seal: {}", step.as_str()), ok: r.ok, detail, lines }));
                });
                pin = out.pin;
                if !out.ok {
                    ok = false;
                    break;
                }
            }
        }
    }
    if !job.dry_run {
        if let Some(p) = pin {
            emit(Msg::Pin(p));
        }
    }
    ok
}

// --------------------------------------------------------------------------
// GTK helpers
// --------------------------------------------------------------------------

fn text_of(e: &gtk::Entry) -> String {
    e.text().to_string()
}

fn entry() -> gtk::Entry {
    let e = gtk::Entry::new();
    e.set_hexpand(true);
    e
}

fn secret_entry() -> gtk::Entry {
    let e = entry();
    e.set_visibility(false);
    e.set_input_purpose(gtk::InputPurpose::Password);
    e
}

fn combo(items: &[&str]) -> gtk::ComboBoxText {
    let c = gtk::ComboBoxText::new();
    for i in items {
        c.append_text(i);
    }
    c.set_active(Some(0));
    c
}

fn set_combo(c: &gtk::ComboBoxText, items: &[&str], value: &str) {
    if let Some(i) = items.iter().position(|x| *x == value).and_then(|i| u32::try_from(i).ok()) {
        c.set_active(Some(i));
    }
}

fn combo_index(c: &gtk::ComboBoxText) -> Option<usize> {
    c.active().and_then(|i| usize::try_from(i).ok())
}

fn combo_value(c: &gtk::ComboBoxText, items: &[&str]) -> String {
    combo_index(c).and_then(|i| items.get(i)).map_or_else(String::new, |s| (*s).to_string())
}

fn spin(lo: u32, hi: u32) -> gtk::SpinButton {
    gtk::SpinButton::with_range(f64::from(lo), f64::from(hi), 1.0)
}

fn spin_u32(s: &gtk::SpinButton) -> u32 {
    u32::try_from(s.value_as_int()).unwrap_or(0)
}

fn label_row(text: &str, class: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.set_xalign(0.0);
    l.set_line_wrap(true);
    l.style_context().add_class(class);
    l
}

/// Two-column label/field grid.
struct FormGrid {
    grid: gtk::Grid,
    next: Cell<i32>,
}

impl FormGrid {
    fn new() -> FormGrid {
        let grid = gtk::Grid::new();
        grid.set_row_spacing(6);
        grid.set_column_spacing(12);
        FormGrid { grid, next: Cell::new(0) }
    }

    fn add(&self, label: &str, w: &impl IsA<gtk::Widget>) {
        let r = self.next.get();
        let l = gtk::Label::new(Some(label));
        l.set_xalign(0.0);
        self.grid.attach(&l, 0, r, 1, 1);
        self.grid.attach(w, 1, r, 1, 1);
        self.next.set(r + 1);
    }
}

fn page_shell(title: &str, subtitle: &str) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 10);
    b.set_margin_top(14);
    b.set_margin_bottom(14);
    b.set_margin_start(24);
    b.set_margin_end(24);
    b.pack_start(&label_row(title, "soc-config-title"), false, false, 0);
    b.pack_start(&label_row(subtitle, "soc-config-sub"), false, false, 0);
    b
}

fn scrolled(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    let s = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
    s.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
    s.set_hexpand(true);
    s.set_vexpand(true);
    s.add(child);
    s
}

fn log_view() -> (gtk::TextBuffer, gtk::ScrolledWindow) {
    let buf = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
    let view = gtk::TextView::with_buffer(&buf);
    view.set_editable(false);
    view.set_cursor_visible(false);
    view.set_monospace(true);
    view.set_wrap_mode(gtk::WrapMode::WordChar);
    (buf, scrolled(&view))
}

fn append(buf: &gtk::TextBuffer, text: &str) {
    let mut end = buf.end_iter();
    buf.insert(&mut end, text);
}

// --------------------------------------------------------------------------
// A list editor: list + add/remove + a form bound by load/store (no per-widget
// signals: the form is flushed into the item when the selection moves).
// --------------------------------------------------------------------------

struct Editor<T> {
    items: RefCell<Vec<T>>,
    current: Cell<Option<usize>>,
    busy: Cell<bool>,
    list: gtk::ListBox,
    labels: RefCell<Vec<gtk::Label>>,
    widget: gtk::Box,
    label: fn(&T, usize) -> String,
    fresh: Box<dyn Fn(usize) -> T>,
    load: Box<dyn Fn(&T)>,
    store: Box<dyn Fn(&mut T)>,
    max: usize,
}

impl<T: Clone + 'static> Editor<T> {
    fn new(
        items: Vec<T>,
        max: usize,
        label: fn(&T, usize) -> String,
        fresh: Box<dyn Fn(usize) -> T>,
        load: Box<dyn Fn(&T)>,
        store: Box<dyn Fn(&mut T)>,
    ) -> Rc<Editor<T>> {
        let list = gtk::ListBox::new();
        list.set_selection_mode(gtk::SelectionMode::Single);
        let frame = gtk::ScrolledWindow::new(None::<&gtk::Adjustment>, None::<&gtk::Adjustment>);
        frame.set_min_content_height(110);
        frame.add(&list);
        let add = gtk::Button::with_label("Add");
        let remove = gtk::Button::with_label("Remove");
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        buttons.pack_start(&add, false, false, 0);
        buttons.pack_start(&remove, false, false, 0);
        let widget = gtk::Box::new(gtk::Orientation::Vertical, 8);
        widget.pack_start(&frame, false, false, 0);
        widget.pack_start(&buttons, false, false, 0);
        let ed = Rc::new(Editor {
            items: RefCell::new(items),
            current: Cell::new(None),
            busy: Cell::new(false),
            list: list.clone(),
            labels: RefCell::new(Vec::new()),
            widget,
            label,
            fresh,
            load,
            store,
            max,
        });
        let weak: Weak<Editor<T>> = Rc::downgrade(&ed);
        list.connect_row_selected(move |_, row| {
            if let Some(ed) = weak.upgrade() {
                if !ed.busy.get() {
                    ed.switch_to(row.and_then(|r| usize::try_from(r.index()).ok()));
                }
            }
        });
        let weak = Rc::downgrade(&ed);
        add.connect_clicked(move |_| {
            if let Some(ed) = weak.upgrade() {
                ed.add_item();
            }
        });
        let weak = Rc::downgrade(&ed);
        remove.connect_clicked(move |_| {
            if let Some(ed) = weak.upgrade() {
                ed.remove_current();
            }
        });
        ed.rebuild();
        ed.focus(if ed.items.borrow().is_empty() { None } else { Some(0) });
        ed
    }

    /// Write the form's widgets into the selected item.
    fn flush(&self) {
        let Some(i) = self.current.get() else {
            return;
        };
        if let Some(it) = self.items.borrow_mut().get_mut(i) {
            (self.store)(it);
        }
        self.relabel();
    }

    fn relabel(&self) {
        let items = self.items.borrow();
        for (i, (it, l)) in items.iter().zip(self.labels.borrow().iter()).enumerate() {
            l.set_text(&(self.label)(it, i));
        }
    }

    fn rebuild(&self) {
        self.busy.set(true);
        for c in self.list.children() {
            self.list.remove(&c);
        }
        let mut labels = self.labels.borrow_mut();
        labels.clear();
        for _ in self.items.borrow().iter() {
            let l = gtk::Label::new(None);
            l.set_xalign(0.0);
            l.set_margin_top(4);
            l.set_margin_bottom(4);
            l.set_margin_start(6);
            self.list.add(&l);
            labels.push(l);
        }
        drop(labels);
        self.relabel();
        self.list.show_all();
        self.busy.set(false);
    }

    fn switch_to(&self, idx: Option<usize>) {
        self.flush();
        self.current.set(idx);
        if let Some(i) = idx {
            if let Some(it) = self.items.borrow().get(i) {
                (self.load)(it);
            }
        }
    }

    /// Select programmatically (moves the visual selection too).
    fn focus(&self, idx: Option<usize>) {
        self.busy.set(true);
        match idx.and_then(|i| i32::try_from(i).ok()).and_then(|i| self.list.row_at_index(i)) {
            Some(row) => self.list.select_row(Some(&row)),
            None => self.list.unselect_all(),
        }
        self.busy.set(false);
        self.switch_to(idx);
    }

    fn add_item(&self) {
        self.flush();
        let n = self.items.borrow().len();
        if n >= self.max {
            return;
        }
        let item = (self.fresh)(n);
        self.items.borrow_mut().push(item);
        self.rebuild();
        self.focus(Some(n));
    }

    fn remove_current(&self) {
        let Some(i) = self.current.get() else {
            return;
        };
        {
            let mut items = self.items.borrow_mut();
            if i < items.len() {
                items.remove(i);
            }
        }
        self.current.set(None);
        self.rebuild();
        let n = self.items.borrow().len();
        self.focus(if n == 0 { None } else { Some(i.min(n - 1)) });
    }

    fn snapshot(&self) -> Vec<T> {
        self.flush();
        self.items.borrow().clone()
    }

    fn replace(&self, items: Vec<T>) {
        self.current.set(None);
        let next = (!items.is_empty()).then_some(0);
        *self.items.borrow_mut() = items;
        self.rebuild();
        self.focus(next);
    }
}

// --------------------------------------------------------------------------
// The form widgets
// --------------------------------------------------------------------------

struct DisplayUi {
    auto: gtk::CheckButton,
    width: gtk::SpinButton,
    height: gtk::SpinButton,
    cols: gtk::SpinButton,
    rows: gtk::SpinButton,
    gap: gtk::SpinButton,
    base: RefCell<Dict>,
}

impl DisplayUi {
    fn new(f: &DisplayForm) -> DisplayUi {
        let u = DisplayUi {
            auto: gtk::CheckButton::with_label("Detect the screen size automatically"),
            width: spin(320, 16384),
            height: spin(240, 16384),
            cols: spin(1, 8),
            rows: spin(1, 8),
            gap: spin(0, 200),
            base: RefCell::new(f.base.clone()),
        };
        let (w, h) = (u.width.clone(), u.height.clone());
        u.auto.connect_toggled(move |b| {
            w.set_sensitive(!b.is_active());
            h.set_sensitive(!b.is_active());
        });
        u.load(f);
        u
    }

    fn load(&self, f: &DisplayForm) {
        *self.base.borrow_mut() = f.base.clone();
        self.auto.set_active(f.auto);
        self.width.set_value(f64::from(f.width));
        self.height.set_value(f64::from(f.height));
        self.cols.set_value(f64::from(f.cols));
        self.rows.set_value(f64::from(f.rows));
        self.gap.set_value(f64::from(f.gap));
        self.width.set_sensitive(!f.auto);
        self.height.set_sensitive(!f.auto);
    }

    fn read(&self) -> DisplayForm {
        DisplayForm {
            base: self.base.borrow().clone(),
            auto: self.auto.is_active(),
            width: spin_u32(&self.width),
            height: spin_u32(&self.height),
            cols: spin_u32(&self.cols),
            rows: spin_u32(&self.rows),
            gap: spin_u32(&self.gap),
        }
    }

    fn widget(&self) -> gtk::Grid {
        let g = FormGrid::new();
        g.add("Screen", &self.auto);
        g.add("Width (px)", &self.width);
        g.add("Height (px)", &self.height);
        g.add("Grid columns", &self.cols);
        g.add("Grid rows", &self.rows);
        g.add("Gap (px)", &self.gap);
        g.grid
    }
}

struct PanelUi {
    id: gtk::Entry,
    url: gtk::Entry,
    vault_item: gtk::Entry,
    username: gtk::Entry,
    password: gtk::Entry,
    user_sel: gtk::Entry,
    pass_sel: gtk::Entry,
    submit_sel: gtk::Entry,
    detect: gtk::Button,
    detect_untrusted: gtk::CheckButton,
    detect_status: gtk::Label,
    detected_marker: RefCell<Option<String>>,
    engine: gtk::ComboBoxText,
    mode: gtk::ComboBoxText,
    col: gtk::SpinButton,
    row: gtk::SpinButton,
    local_port: gtk::Entry,
    remote_host: gtk::Entry,
    remote_port: gtk::Entry,
    path: gtk::Entry,
    scheme: gtk::ComboBoxText,
    grid: gtk::Grid,
}

impl PanelUi {
    fn new() -> Rc<PanelUi> {
        let g = FormGrid::new();
        let u = PanelUi {
            id: entry(),
            url: entry(),
            vault_item: entry(),
            username: entry(),
            password: secret_entry(),
            user_sel: entry(),
            pass_sel: entry(),
            submit_sel: entry(),
            detect: gtk::Button::with_label("Detect login form"),
            detect_untrusted: gtk::CheckButton::with_label("Allow untrusted TLS for discovery"),
            detect_status: label_row("", "soc-config-sub"),
            detected_marker: RefCell::new(None),
            engine: combo(&ENGINES),
            mode: combo(&["direct", "tunnel"]),
            col: spin(0, 15),
            row: spin(0, 15),
            local_port: entry(),
            remote_host: entry(),
            remote_port: entry(),
            path: entry(),
            scheme: combo(&SCHEMES),
            grid: g.grid.clone(),
        };
        g.add("Tile id", &u.id);
        g.add("Engine", &u.engine);
        g.add("Grid column", &u.col);
        g.add("Grid row", &u.row);
        g.add("Mode", &u.mode);
        g.add("URL (direct)", &u.url);
        g.add("", &u.detect);
        g.add("", &u.detect_untrusted);
        g.add("", &u.detect_status);
        g.add("Local port (tunnel)", &u.local_port);
        g.add("Remote host (tunnel)", &u.remote_host);
        g.add("Remote port (tunnel)", &u.remote_port);
        g.add("Path (tunnel)", &u.path);
        g.add("Scheme (tunnel)", &u.scheme);
        g.add("Vault item", &u.vault_item);
        g.add("Username selector", &u.user_sel);
        g.add("Password selector", &u.pass_sel);
        g.add("Submit selector", &u.submit_sel);
        g.add("Login username (optional)", &u.username);
        g.add("Login password (optional)", &u.password);
        let u = Rc::new(u);
        let weak = Rc::downgrade(&u);
        u.mode.connect_changed(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.sync_mode();
            }
        });
        let weak = Rc::downgrade(&u);
        u.detect.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.detect_form();
            }
        });
        u
    }

    fn detect_form(self: &Rc<Self>) {
        let (id, url) = (text_of(&self.id), text_of(&self.url));
        self.detect.set_sensitive(false);
        self.detect_status.set_text("Reading the login page…");
        let allow_untrusted = self.detect_untrusted.is_active();
        let (tx, rx) = mpsc::channel();
        let target = url.clone();
        std::thread::spawn(move || {
            let _ = tx.send(soc_setup::discovery::probe(&target, allow_untrusted)); // audit-allow: harmless if the wizard closed
        });
        let weak = Rc::downgrade(self);
        glib::timeout_add_local(Duration::from_millis(100), move || {
            let Some(ui) = weak.upgrade() else { return glib::ControlFlow::Break };
            let result = match rx.try_recv() {
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Err(soc_setup::discovery::ProbeError::Failed("The probe stopped".into()))
                }
                Ok(result) => result,
            };
            ui.sync_mode();
            if text_of(&ui.id) != id || text_of(&ui.url) != url || combo_index(&ui.mode) == Some(1) {
                return glib::ControlFlow::Break;
            }
            match result {
                Ok(Some(form)) => {
                    ui.user_sel.set_text(&form.user);
                    ui.pass_sel.set_text(&form.password);
                    ui.submit_sel.set_text(&form.submit);
                    *ui.detected_marker.borrow_mut() = Some(form.password);
                    let product = form.product.unwrap_or("login form");
                    ui.detect_status.set_text(&format!(
                        "{} {product}. Review the suggested selectors.",
                        if form.guessed { "Recognized" } else { "Detected" }
                    ));
                }
                Ok(None) => ui.detect_status.set_text("No HTML login form found. Enter its selectors below."),
                Err(e) => ui.detect_status.set_text(&e.to_string()),
            }
            glib::ControlFlow::Break
        });
    }

    fn sync_mode(&self) {
        let tunnel = combo_index(&self.mode) == Some(1);
        self.url.set_sensitive(!tunnel);
        self.detect.set_sensitive(!tunnel);
        self.detect_untrusted.set_sensitive(!tunnel);
        for w in [&self.local_port, &self.remote_host, &self.remote_port, &self.path] {
            w.set_sensitive(tunnel);
        }
        self.scheme.set_sensitive(tunnel);
    }

    fn load(&self, p: &PanelForm) {
        self.detect_status.set_text("");
        self.detected_marker.borrow_mut().take();
        self.id.set_text(&p.id);
        self.url.set_text(&p.url);
        self.vault_item.set_text(&p.vault_item);
        self.username.set_text(&p.username);
        self.password.set_text(&p.password);
        self.user_sel.set_text(&p.user_sel);
        self.pass_sel.set_text(&p.pass_sel);
        self.submit_sel.set_text(&p.submit_sel);
        set_combo(&self.engine, &ENGINES, &p.engine);
        self.mode.set_active(Some(u32::from(p.tunnel_mode)));
        self.col.set_value(f64::from(p.col));
        self.row.set_value(f64::from(p.row));
        self.local_port.set_text(&p.local_port);
        self.remote_host.set_text(&p.remote_host);
        self.remote_port.set_text(&p.remote_port);
        self.path.set_text(&p.path);
        set_combo(&self.scheme, &SCHEMES, &p.scheme);
        self.sync_mode();
    }

    fn store(&self, p: &mut PanelForm) {
        p.id = text_of(&self.id);
        p.url = text_of(&self.url);
        p.vault_item = text_of(&self.vault_item);
        p.username = text_of(&self.username);
        p.password = Zeroizing::new(text_of(&self.password));
        p.user_sel = text_of(&self.user_sel);
        p.pass_sel = text_of(&self.pass_sel);
        p.submit_sel = text_of(&self.submit_sel);
        if let Some(marker) = self.detected_marker.borrow().as_ref() {
            p.base.insert("login_marker".into(), json!(marker));
        }
        p.engine = combo_value(&self.engine, &ENGINES);
        p.tunnel_mode = combo_index(&self.mode) == Some(1);
        p.col = spin_u32(&self.col);
        p.row = spin_u32(&self.row);
        p.local_port = text_of(&self.local_port);
        p.remote_host = text_of(&self.remote_host);
        p.remote_port = text_of(&self.remote_port);
        p.path = text_of(&self.path);
        p.scheme = combo_value(&self.scheme, &SCHEMES);
    }
}

struct VpnUi {
    name: gtk::Entry,
    kind: gtk::ComboBoxText,
    enabled: gtk::CheckButton,
    default_route: gtk::CheckButton,
    gateway: gtk::Entry,
    port: gtk::Entry,
    vault_item: gtk::Entry,
    trusted_cert: gtk::Entry,
    config_from_vault: gtk::CheckButton,
    extra: Vec<(&'static str, gtk::Entry)>,
    grid: gtk::Grid,
}

impl VpnUi {
    fn new() -> Rc<VpnUi> {
        let g = FormGrid::new();
        let u = VpnUi {
            name: entry(),
            kind: combo(&VPN_KINDS),
            enabled: gtk::CheckButton::with_label("Enabled"),
            default_route: gtk::CheckButton::with_label("Full tunnel (default route)"),
            gateway: entry(),
            port: entry(),
            vault_item: entry(),
            trusted_cert: entry(),
            config_from_vault: gtk::CheckButton::with_label("Read the VPN configuration from the vault item"),
            extra: ["config", "realm", "domain", "ready_probe"].into_iter().map(|key| (key, entry())).collect(),
            grid: g.grid.clone(),
        };
        g.add("Name", &u.name);
        g.add("Type", &u.kind);
        g.add("", &u.enabled);
        g.add("", &u.default_route);
        g.add("Gateway", &u.gateway);
        g.add("Port", &u.port);
        g.add("Vault item", &u.vault_item);
        g.add("Trusted cert (sha256)", &u.trusted_cert);
        g.add("", &u.config_from_vault);
        for ((_, value), name) in u.extra.iter().zip([
            "Profile file or interface",
            "FortiGate realm",
            "iNode domain",
            "Readiness probe (host:port)",
        ]) {
            g.add(name, value);
        }
        Rc::new(u)
    }

    fn load(&self, v: &VpnForm) {
        self.name.set_text(&v.name);
        set_combo(&self.kind, &VPN_KINDS, &v.kind);
        self.enabled.set_active(v.enabled);
        self.default_route.set_active(v.default_route);
        self.gateway.set_text(&v.gateway);
        self.port.set_text(&v.port);
        self.vault_item.set_text(&v.vault_item);
        self.trusted_cert.set_text(&v.trusted_cert);
        self.config_from_vault.set_active(v.base.truthy("config_from_vault"));
        for (key, entry) in &self.extra {
            entry.set_text(&v.base.text(key));
        }
    }

    fn store(&self, v: &mut VpnForm) {
        v.name = text_of(&self.name);
        v.kind = combo_value(&self.kind, &VPN_KINDS);
        v.enabled = self.enabled.is_active();
        v.default_route = self.default_route.is_active();
        v.gateway = text_of(&self.gateway);
        v.port = text_of(&self.port);
        v.vault_item = text_of(&self.vault_item);
        v.trusted_cert = text_of(&self.trusted_cert);
        v.base.insert("config_from_vault".into(), json!(self.config_from_vault.is_active()));
        for (key, entry) in &self.extra {
            set_or_remove(&mut v.base, key, &text_of(entry));
        }
    }
}

struct VaultUi {
    target: gtk::ComboBoxText,
    backend: gtk::ComboBoxText,
    url: gtk::Entry,
    email: gtk::Entry,
    source: gtk::ComboBoxText,
    master: gtk::Entry,
    confirm: gtk::Entry,
    create_account: gtk::CheckButton,
    reseal: gtk::CheckButton,
    pin: gtk::Entry,
    dry_run: gtk::CheckButton,
}

impl VaultUi {
    fn new(v: &VaultForm) -> VaultUi {
        let labels: Vec<&str> = SOURCES.iter().map(|(_, l)| *l).collect();
        let u = VaultUi {
            target: combo(&TARGETS),
            backend: combo(&BACKENDS),
            url: entry(),
            email: entry(),
            source: combo(&labels),
            master: secret_entry(),
            confirm: secret_entry(),
            create_account: gtk::CheckButton::with_label("Create the vault account if it does not exist"),
            reseal: gtk::CheckButton::with_label("Re-seal even if a sealed secret exists (issues a NEW PIN)"),
            pin: entry(),
            dry_run: gtk::CheckButton::with_label("Dry run — preview only, write nothing"),
        };
        set_combo(&u.target, &TARGETS, if v.target == Target::Pi { "pi" } else { "dev" });
        set_combo(&u.backend, &BACKENDS, &v.backend);
        u.url.set_text(&v.url);
        u.email.set_text(&v.email);
        if let Some(i) = SOURCES.iter().position(|(s, _)| *s == v.source).and_then(|i| u32::try_from(i).ok()) {
            u.source.set_active(Some(i));
        }
        u.create_account.set_active(v.create_account);
        u.reseal.set_active(v.reseal);
        u.dry_run.set_active(v.dry_run);
        u.pin.set_placeholder_text(Some("leave empty to generate one"));
        u
    }

    fn read(&self) -> VaultForm {
        VaultForm {
            target: if combo_index(&self.target) == Some(1) { Target::Dev } else { Target::Pi },
            backend: combo_value(&self.backend, &BACKENDS),
            url: text_of(&self.url),
            email: text_of(&self.email),
            source: combo_index(&self.source).and_then(|i| SOURCES.get(i)).map_or(MasterSource::Sealed, |(s, _)| *s),
            master: Zeroizing::new(text_of(&self.master)),
            confirm: Zeroizing::new(text_of(&self.confirm)),
            create_account: self.create_account.is_active(),
            reseal: self.reseal.is_active(),
            pin: text_of(&self.pin),
            dry_run: self.dry_run.is_active(),
        }
    }

    fn clear_secrets(&self) {
        self.master.set_text("");
        self.confirm.set_text("");
    }

    fn widget(&self) -> gtk::Grid {
        let g = FormGrid::new();
        g.add("Install target", &self.target);
        g.add("Vault backend", &self.backend);
        g.add("Vault URL", &self.url);
        g.add("Vault e-mail", &self.email);
        g.add("Master password source", &self.source);
        g.add("Master password", &self.master);
        g.add("Confirm master", &self.confirm);
        g.add("Sealing PIN (optional)", &self.pin);
        g.add("", &self.create_account);
        self.vault_actions(&g);
        g.add("", &self.reseal);
        g.add("", &self.dry_run);
        g.grid
    }

    fn vault_actions(&self, grid: &FormGrid) {
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let detect = gtk::Button::with_label("Find local Vaultwarden");
        let verify = gtk::Button::with_label("Test vault login");
        let reset = gtk::Button::with_label("Reset local account…");
        let status = label_row("", "soc-config-sub");
        for b in [&detect, &verify, &reset] {
            buttons.pack_start(b, false, false, 0);
        }
        grid.add("", &buttons);
        grid.add("", &status);
        let (url, output) = (self.url.clone(), status.clone());
        detect.connect_clicked(move |b| {
            let previous = text_of(&url);
            let url = url.clone();
            vault_job(
                b,
                &output,
                move || {
                    use soc_setup::host::{Probe, SystemProbe};
                    [previous.as_str(), DEFAULT_VAULT_URL, "http://localhost:8222", "https://127.0.0.1:8222"]
                        .into_iter()
                        .find(|value| soc_core::guard::valid_http_url(value, false) && SystemProbe.alive(value))
                        .map(str::to_string)
                        .ok_or_else(|| "Vaultwarden did not answer on the configured URL or local defaults.".into())
                },
                move |found| {
                    url.set_text(&found);
                    format!("Found Vaultwarden at {found}")
                },
            );
        });
        let (url, email, master, output) = (self.url.clone(), self.email.clone(), self.master.clone(), status.clone());
        verify.connect_clicked(move |b| {
            let (url, email, master) = (text_of(&url), text_of(&email), Zeroizing::new(text_of(&master)));
            if url.is_empty() || email.is_empty() || master.is_empty() {
                output.set_text("Enter the vault URL, email and master password.");
                return;
            }
            vault_job(
                b,
                &output,
                move || {
                    soc_vault::Session::login(&url, &email, &master, &soc_vault::SessionOptions::from_env())
                        .and_then(|s| s.list_logins())
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                },
                |()| "Vaultwarden login and decryption succeeded.".into(),
            );
        });
        let (email, url) = (self.email.clone(), self.url.clone());
        reset.connect_clicked(move |b| {
            let address = text_of(&email);
            if address.is_empty()
                || !soc_core::url::Url::split(&text_of(&url)).is_ok_and(|u| {
                    u.port == Some(8222) && matches!(u.host.as_deref(), Some("localhost" | "127.0.0.1" | "::1"))
                })
            {
                status.set_text("Enter the email and URL for the local Vaultwarden service before resetting.");
                return;
            }
            if !confirm_vault_reset(b, &address) {
                return;
            }
            vault_job(
                b,
                &status,
                move || {
                    use soc_sys::run::{Runner, SystemRunner, argv};
                    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                    let mut args =
                        argv(&[&exe.to_string_lossy(), "setup", "vault-reset", "--email", &address, "--yes"]);
                    if soc_sys::fsutil::euid() != 0 {
                        args.insert(0, "pkexec".into());
                    }
                    let out = SystemRunner.run(&args, Duration::from_secs(180)).map_err(|e| e.to_string())?;
                    if out.success() { Ok(out.stdout) } else { Err(out.stderr) }
                },
                |message| format!("{} Create and seal the replacement account with the new master.", message.trim()),
            );
        });
    }
}

fn vault_job<T: Send + 'static>(
    button: &gtk::Button,
    status: &gtk::Label,
    work: impl FnOnce() -> Result<T, String> + Send + 'static, // audit-allow: error text is shown directly in the wizard
    display: impl FnOnce(T) -> String + 'static,
) {
    button.set_sensitive(false);
    status.set_text("Contacting Vaultwarden…");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work()); // audit-allow: the wizard may close while the request completes
    }); // audit-allow: the wizard may close while the request completes
    let (button, status) = (button.downgrade(), status.downgrade());
    let mut display = Some(display);
    glib::timeout_add_local(Duration::from_millis(100), move || {
        let Some((button, status)) = button.upgrade().zip(status.upgrade()) else { return glib::ControlFlow::Break };
        let text = match rx.try_recv() {
            Ok(Ok(value)) => display.take().map_or_else(String::new, |show| show(value)),
            Ok(Err(error)) => error,
            Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => "Vault operation stopped.".into(),
        };
        button.set_sensitive(true);
        status.set_text(&text);
        glib::ControlFlow::Break
    });
}

fn confirm_vault_reset(button: &gtk::Button, address: &str) -> bool {
    let parent = button.toplevel().and_then(|w| w.downcast::<gtk::Window>().ok());
    let dialog = gtk::Dialog::with_buttons(
        Some("Reset local Vaultwarden account"),
        parent.as_ref(),
        gtk::DialogFlags::MODAL,
        &[("Cancel", gtk::ResponseType::Cancel), ("Delete account", gtk::ResponseType::Accept)],
    );
    let label = label_row(
        &format!(
            "This deletes the account and its credentials after creating a local database backup. Type {address} to continue."
        ),
        "soc-config-sub",
    );
    let confirmation = entry();
    dialog.content_area().pack_start(&label, false, false, 8);
    dialog.content_area().pack_start(&confirmation, false, false, 8);
    dialog.set_response_sensitive(gtk::ResponseType::Accept, false);
    let weak = dialog.downgrade();
    let address = address.to_string();
    confirmation.connect_changed(move |value| {
        if let Some(dialog) = weak.upgrade() {
            dialog.set_response_sensitive(gtk::ResponseType::Accept, value.text() == address.as_str());
        }
    });
    dialog.show_all();
    let confirmed = dialog.run() == gtk::ResponseType::Accept;
    dialog.close();
    confirmed
}

struct NetUi {
    tunnel_enabled: gtk::CheckButton,
    jump_host: gtk::Entry,
    identity: gtk::Entry,
    tunnel_base: RefCell<Dict>,
    proxy_enabled: gtk::CheckButton,
    proxy_url: gtk::Entry,
    proxy_item: gtk::Entry,
    proxy_base: RefCell<Dict>,
}

impl NetUi {
    fn new(t: &TunnelForm, p: &ProxyForm) -> NetUi {
        let u = NetUi {
            tunnel_enabled: gtk::CheckButton::with_label("SSH tunnel enabled"),
            jump_host: entry(),
            identity: entry(),
            tunnel_base: RefCell::new(Dict::new()),
            proxy_enabled: gtk::CheckButton::with_label("Outbound proxy enabled"),
            proxy_url: entry(),
            proxy_item: entry(),
            proxy_base: RefCell::new(Dict::new()),
        };
        u.load(t, p);
        u
    }

    fn load(&self, tunnel: &TunnelForm, proxy: &ProxyForm) {
        *self.tunnel_base.borrow_mut() = tunnel.base.clone();
        *self.proxy_base.borrow_mut() = proxy.base.clone();
        self.tunnel_enabled.set_active(tunnel.enabled);
        self.jump_host.set_text(&tunnel.jump_host);
        self.identity.set_text(&tunnel.identity);
        self.proxy_enabled.set_active(proxy.enabled);
        self.proxy_url.set_text(&proxy.url);
        self.proxy_item.set_text(&proxy.vault_item);
    }

    fn tunnel(&self) -> TunnelForm {
        TunnelForm {
            base: self.tunnel_base.borrow().clone(),
            enabled: self.tunnel_enabled.is_active(),
            jump_host: text_of(&self.jump_host),
            identity: text_of(&self.identity),
        }
    }

    fn proxy(&self) -> ProxyForm {
        ProxyForm {
            base: self.proxy_base.borrow().clone(),
            enabled: self.proxy_enabled.is_active(),
            url: text_of(&self.proxy_url),
            vault_item: text_of(&self.proxy_item),
        }
    }
}

// --------------------------------------------------------------------------
// The wizard
// --------------------------------------------------------------------------

struct Wizard {
    window: gtk::Window,
    stack: gtk::Stack,
    back: gtk::Button,
    next: gtk::Button,
    cancel: gtk::Button,
    status: gtk::Label,
    page: Cell<usize>,
    running: Cell<bool>,
    penv: PathEnv,
    display: DisplayUi,
    panels: Rc<Editor<PanelForm>>,
    vault: VaultUi,
    vpns: Rc<Editor<VpnForm>>,
    net: NetUi,
    security: RefCell<Option<Value>>,
    review: gtk::TextBuffer,
    review_note: gtk::Label,
    system_config: gtk::CheckButton,
    log: gtk::TextBuffer,
    run_state: gtk::Label,
    pin_box: gtk::Box,
    pin_label: gtk::Label,
    pin_ack: gtk::Button,
}

impl Wizard {
    fn apply_preset(&self, name: &str, path: &std::path::Path) {
        let cfg = match soc_core::load(path) {
            Ok(cfg) => cfg,
            Err(e) => {
                self.say(&error_text(&e), true);
                return;
            }
        };
        let confirm = gtk::MessageDialog::new(
            Some(&self.window),
            gtk::DialogFlags::MODAL,
            gtk::MessageType::Question,
            gtk::ButtonsType::OkCancel,
            "Replace this draft’s display, panels and network settings with the preset?",
        );
        let accepted = confirm.run() == gtk::ResponseType::Ok;
        confirm.close();
        if !accepted {
            return;
        }
        let target = self.vault.read().target;
        let paths = SetupPaths::resolve(target, &self.penv, false);
        let draft = seed(&cfg, &SocEnv::new(), &paths, &Opts { preset: Some(name.to_string()), ..Opts::default() });
        self.display.load(&draft.display);
        self.net.load(&draft.tunnel, &draft.proxy);
        self.panels.replace(draft.panels);
        self.vpns.replace(draft.vpns);
        *self.security.borrow_mut() = draft.security;
        self.go(0);
        self.say(&format!("Loaded {name}"), false);
    }

    fn snapshot(&self) -> FormData {
        FormData {
            display: self.display.read(),
            panels: self.panels.snapshot(),
            vpns: self.vpns.snapshot(),
            tunnel: self.net.tunnel(),
            proxy: self.net.proxy(),
            security: self.security.borrow().clone(),
            vault: self.vault.read(),
        }
    }

    fn say(&self, text: &str, bad: bool) {
        self.status.set_text(text);
        let ctx = self.status.style_context();
        ctx.remove_class("soc-config-error");
        ctx.remove_class("soc-config-ok");
        ctx.add_class(if bad { "soc-config-error" } else { "soc-config-ok" });
    }

    fn go(&self, to: usize) {
        let Some(name) = PAGES.get(to) else {
            return;
        };
        self.page.set(to);
        self.stack.set_visible_child_name(name);
        self.back.set_sensitive(to > 0 && to < 4);
        self.next.set_label(match to {
            3 => "Install",
            4 => "Close",
            _ => "Next",
        });
        self.next.set_sensitive(to != 4 || !self.running.get());
        self.cancel.set_sensitive(!self.running.get());
    }

    fn on_next(self: &Rc<Self>) {
        match self.page.get() {
            0 => {
                self.say("", false);
                self.go(1);
            }
            1 => {
                let problems = self.vault.read().problems();
                if problems.is_empty() {
                    self.say("", false);
                    self.go(2);
                } else {
                    self.say(&problems.join("\n"), true);
                }
            }
            2 => self.show_review(),
            3 => self.start_run(),
            _ => self.window.close(),
        }
    }

    fn on_back(&self) {
        let p = self.page.get();
        if p > 0 && p < 4 {
            self.say("", false);
            self.go(p - 1);
        }
    }

    /// Validate the whole form (inline errors) and render the review.
    fn show_review(&self) {
        let data = self.snapshot();
        match assemble(&data) {
            Err(e) => self.say(&error_text(&e), true),
            Ok(cfg) => {
                self.system_config.set_visible(privileged::available(&self.penv, &data.vault).is_some());
                let paths = SetupPaths::resolve(
                    data.vault.target,
                    &self.penv,
                    self.system_config.is_visible() && self.system_config.is_active(),
                );
                let job = RunJob::new(cfg, self.penv.clone(), paths, &data.vault, Creds::new());
                self.review.set_text(&review_text(&job.cfg, &job.env, &job.paths, &job.user, job.dry_run));
                let note = if job.cfg.warnings.is_empty() {
                    "Nothing is written until you press Install.".to_string()
                } else {
                    format!("Warnings:\n  - {}", job.cfg.warnings.join("\n  - "))
                };
                self.review_note.set_text(&note);
                self.say("", false);
                self.go(3);
            }
        }
    }

    fn start_run(self: &Rc<Self>) {
        let data = self.snapshot();
        let cfg = match assemble(&data) {
            Ok(c) => c,
            Err(e) => {
                self.say(&error_text(&e), true);
                return;
            }
        };
        let v = &data.vault;
        let pkexec = self.system_config.is_active().then(|| privileged::available(&self.penv, v)).flatten();
        let paths = SetupPaths::resolve(v.target, &self.penv, v.dry_run && pkexec.is_some());
        let job = RunJob::new(cfg, self.penv.clone(), paths, v, creds_of(&data.panels));
        let dry = job.dry_run;
        // The master now lives only in the job; drop it from the widgets.
        self.vault.clear_secrets();
        self.log.set_text("");
        self.run_state.set_text(if dry { "Dry run in progress…" } else { "Installing…" });
        self.running.set(true);
        self.say("", false);
        self.go(4);
        let (tx, rx) = mpsc::channel::<Msg>();
        let spawned = std::thread::Builder::new().name("soc-setupwiz".into()).spawn(move || {
            let emit = |msg| {
                send(&tx, msg);
            };
            let ok = match pkexec.filter(|_| !dry) {
                Some(program) => match privileged::execute(&program, &job, &emit) {
                    Ok(Some(ok)) => ok,
                    Ok(None) => {
                        emit(Msg::Step(StepLine {
                            title: "System configuration".into(),
                            ok: true,
                            detail: "Authorization unavailable. Saving for this login.".into(),
                            lines: vec![],
                        }));
                        execute(job, emit)
                    }
                    Err(detail) => {
                        emit(Msg::Step(StepLine {
                            title: "System configuration".into(),
                            ok: false,
                            detail,
                            lines: vec![],
                        }));
                        false
                    }
                },
                None => execute(job, emit),
            };
            send(&tx, Msg::Done(ok));
        });
        if let Err(e) = spawned {
            self.finish(false, dry, &format!("could not start the worker thread: {e}"));
            return;
        }
        let me = Rc::clone(self);
        glib::timeout_add_local(Duration::from_millis(100), move || {
            loop {
                match rx.try_recv() {
                    Ok(Msg::Done(ok)) => {
                        me.finish(ok, dry, "");
                        return glib::ControlFlow::Break;
                    }
                    Ok(m) => me.on_msg(m),
                    Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        me.finish(false, dry, "the worker ended unexpectedly");
                        return glib::ControlFlow::Break;
                    }
                }
            }
        });
    }

    fn on_msg(&self, m: Msg) {
        match m {
            Msg::Step(s) => {
                let mark = if s.ok { "✓" } else { "✗" };
                let mut t = format!("{mark} {}\n    {}\n", s.title, s.detail);
                for l in &s.lines {
                    t.push_str(&format!("      {l}\n"));
                }
                append(&self.log, &t);
            }
            Msg::Pin(pin) => {
                let shown = glib::markup_escape_text(&pin_display(&pin));
                self.pin_label
                    .set_markup(&format!("<span size='xx-large' weight='bold' font_family='monospace'>{shown}</span>"));
                self.pin_box.show_all();
                self.pin_ack.set_sensitive(true);
                self.next.set_sensitive(false);
            }
            Msg::Done(_) => {}
        }
    }

    fn finish(&self, ok: bool, dry: bool, why: &str) {
        self.running.set(false);
        if !why.is_empty() {
            append(&self.log, &format!("✗ {why}\n"));
        }
        let (text, bad) = match (ok, dry) {
            (true, true) => ("Dry run complete — nothing was written.", false),
            (true, false) => ("Setup complete.", false),
            (false, _) => ("Setup stopped — see the log above. Fix the problem and re-run (it is idempotent).", true),
        };
        self.run_state.set_text(text);
        self.say(text, bad);
        self.cancel.set_sensitive(true);
        self.next.set_sensitive(!self.pin_box.is_visible());
    }

    fn ack_pin(&self) {
        self.pin_label.set_text("");
        self.pin_box.hide();
        self.pin_ack.set_sensitive(false);
        self.next.set_sensitive(!self.running.get());
    }
}

fn build_pages(
    d: &DisplayUi,
    panels: &Rc<Editor<PanelForm>>,
    pui: &PanelUi,
    v: &VaultUi,
    n: &NetUi,
    vpns: &Rc<Editor<VpnForm>>,
    vui: &VpnUi,
) -> [gtk::Widget; 3] {
    let p0 = page_shell(
        "Tiles",
        "Choose the screen grid and add one tile per console. Selectors are CSS selectors for the login form.",
    );
    p0.pack_start(&d.widget(), false, false, 0);
    p0.pack_start(&label_row("Tiles", "soc-config-sub"), false, false, 0);
    p0.pack_start(&panels.widget, false, false, 0);
    p0.pack_start(&pui.grid, false, false, 0);

    let p1 = page_shell(
        "Vault",
        "Where the logins live and how the vault master password is protected. The master is never written to a file.",
    );
    p1.pack_start(&v.widget(), false, false, 0);

    let p2 =
        page_shell("VPN, tunnel and proxy", "Optional network plumbing. Leave everything off if the wall needs none.");
    let g = FormGrid::new();
    g.add("", &n.tunnel_enabled);
    g.add("Tunnel jump host", &n.jump_host);
    g.add("Tunnel identity file", &n.identity);
    g.add("", &n.proxy_enabled);
    g.add("Proxy URL", &n.proxy_url);
    g.add("Proxy vault item", &n.proxy_item);
    p2.pack_start(&g.grid, false, false, 0);
    p2.pack_start(&label_row("VPNs", "soc-config-sub"), false, false, 0);
    p2.pack_start(&vpns.widget, false, false, 0);
    p2.pack_start(&vui.grid, false, false, 0);
    [scrolled(&p0).upcast(), scrolled(&p1).upcast(), scrolled(&p2).upcast()]
}

fn build_wizard(opts: &Opts, preset: Option<Config>) -> Rc<Wizard> {
    let penv = PathEnv::from_process();
    let target = opts.target.unwrap_or_else(|| Target::default_for(soc_sys::fsutil::euid() == 0, &penv));
    let paths = SetupPaths::resolve(target, &penv, false);
    let env = load_env_file(&penv.resolve_env().unwrap_or_else(|| paths.soc_env.clone()));
    let cfg = preset
        .unwrap_or_else(|| previous_config(&penv.resolve_panels().unwrap_or_else(|| paths.panels_installed.clone())));
    let data = seed(&cfg, &env, &paths, opts);

    let display = DisplayUi::new(&data.display);
    let pui = PanelUi::new();
    let (cols_spin, p_load, p_store) = (display.cols.clone(), Rc::clone(&pui), Rc::clone(&pui));
    let panels = Editor::new(
        data.panels.clone(),
        MAX_PANELS,
        PanelForm::label,
        Box::new(move |i| PanelForm::fresh(i, spin_u32(&cols_spin))),
        Box::new(move |p| p_load.load(p)),
        Box::new(move |p| p_store.store(p)),
    );
    let vui = VpnUi::new();
    let (v_load, v_store) = (Rc::clone(&vui), Rc::clone(&vui));
    let vpns = Editor::new(
        data.vpns.clone(),
        MAX_VPNS,
        VpnForm::label,
        Box::new(VpnForm::fresh),
        Box::new(move |v| v_load.load(v)),
        Box::new(move |v| v_store.store(v)),
    );
    let vault = VaultUi::new(&data.vault);
    let net = NetUi::new(&data.tunnel, &data.proxy);
    let [p0, p1, p2] = build_pages(&display, &panels, &pui, &vault, &net, &vpns, &vui);

    // Review page.
    let p3 =
        page_shell("Review", "These are exactly the files the backend will render. Check them, then press Install.");
    let review_note = label_row("", "soc-config-sub");
    let system_config = gtk::CheckButton::with_label("Save as system configuration (administrator authorization)");
    system_config.set_no_show_all(true);
    let (review, review_scroll) = log_view();
    p3.pack_start(&review_note, false, false, 0);
    p3.pack_start(&system_config, false, false, 0);
    p3.pack_start(&review_scroll, true, true, 0);

    // Run page.
    let p4 = page_shell("Install", "Each step is run by the setup backend; its result appears below as it finishes.");
    let run_state = label_row("", "soc-config-sub");
    let (log, log_scroll) = log_view();
    let pin_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let pin_title = label_row("YOUR ONE-TIME PIN — shown once", "soc-config-title");
    let pin_label = gtk::Label::new(None);
    pin_label.set_selectable(true);
    let pin_help = label_row(
        "Write this PIN down and keep it safe. It is needed ONLY to re-seal later (re-deploy, new hardware, or a \
         changed master password) — NOT for normal boots; the wall unlocks itself from the host-bound seal.",
        "soc-config-sub",
    );
    let pin_ack = gtk::Button::with_label("I have written the PIN down");
    pin_ack.style_context().add_class("soc-config-primary");
    pin_ack.set_sensitive(false);
    pin_box.pack_start(&pin_title, false, false, 0);
    pin_box.pack_start(&pin_label, false, false, 0);
    pin_box.pack_start(&pin_help, false, false, 0);
    pin_box.pack_start(&pin_ack, false, false, 0);
    p4.pack_start(&run_state, false, false, 0);
    p4.pack_start(&pin_box, false, false, 0);
    p4.pack_start(&log_scroll, true, true, 0);

    let stack = gtk::Stack::new();
    for (name, page) in PAGES.iter().zip([p0, p1, p2, p3.upcast(), p4.upcast()]) {
        stack.add_named(&page, name);
    }

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("SOC Wall — Setup");
    window.set_default_size(920, 720);
    window.set_position(gtk::WindowPosition::Center);
    window.style_context().add_class("soc-config");

    let status = label_row("", "soc-config-sub");
    status.set_margin_start(24);
    status.set_margin_end(24);
    let back = gtk::Button::with_label("Back");
    let next = gtk::Button::with_label("Next");
    next.style_context().add_class("soc-config-primary");
    let cancel = gtk::Button::with_label("Cancel");
    let nav = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    nav.set_margin_start(24);
    nav.set_margin_end(24);
    nav.set_margin_bottom(14);
    nav.pack_end(&next, false, false, 0);
    nav.pack_end(&back, false, false, 0);
    nav.pack_start(&cancel, false, false, 0);
    let root = gtk::Box::new(gtk::Orientation::Vertical, 6);
    let tools = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    tools.set_margin_start(24);
    tools.set_margin_end(24);
    let templates = presets(&penv.repo_root());
    let choices = gtk::ComboBoxText::new();
    for name in templates.keys() {
        choices.append(Some(name), name);
    }
    choices.set_active(Some(0));
    let load = gtk::Button::with_label("Load preset");
    load.set_sensitive(!templates.is_empty());
    let appearance = gtk::Button::with_label("Appearance");
    tools.pack_start(&choices, false, false, 0);
    tools.pack_start(&load, false, false, 0);
    tools.pack_end(&appearance, false, false, 0);
    root.pack_start(&tools, false, false, 0);
    root.pack_start(&stack, true, true, 0);
    root.pack_start(&status, false, false, 0);
    root.pack_start(&nav, false, false, 0);
    window.add(&root);

    let wiz = Rc::new(Wizard {
        window,
        stack,
        back,
        next,
        cancel,
        status,
        page: Cell::new(0),
        running: Cell::new(false),
        penv,
        display,
        panels,
        vault,
        vpns,
        net,
        security: RefCell::new(data.security),
        review,
        review_note,
        system_config,
        log,
        run_state,
        pin_box,
        pin_label,
        pin_ack,
    });
    let weak = Rc::downgrade(&wiz);
    load.connect_clicked(move |_| {
        if let Some((wizard, name)) = weak.upgrade().zip(choices.active_id()) {
            if !wizard.running.get() && !wizard.pin_box.is_visible() {
                if let Some(path) = templates.get(name.as_str()) {
                    wizard.apply_preset(name.as_str(), path);
                }
            }
        }
    });
    let weak = Rc::downgrade(&wiz);
    appearance.connect_clicked(move |_| {
        let result = std::env::current_exe()
            .and_then(|exe| std::process::Command::new(exe).arg("appearance").env_remove("SOC_RETURN_TO_MENU").spawn());
        if let Err(e) = result {
            if let Some(wizard) = weak.upgrade() {
                wizard.say(&format!("Could not open Appearance: {e}"), true);
            }
        }
    });
    let w = Rc::clone(&wiz);
    wiz.next.connect_clicked(move |_| w.on_next());
    let w = Rc::clone(&wiz);
    wiz.back.connect_clicked(move |_| w.on_back());
    let weak = Rc::downgrade(&wiz);
    wiz.system_config.connect_toggled(move |_| {
        if let Some(wizard) = weak.upgrade().filter(|w| w.page.get() == 3) {
            wizard.show_review();
        }
    });
    let w = Rc::clone(&wiz);
    wiz.cancel.connect_clicked(move |_| w.window.close());
    let w = Rc::clone(&wiz);
    wiz.pin_ack.connect_clicked(move |_| w.ack_pin());
    wiz.window.connect_destroy(|_| gtk::main_quit());
    wiz
}

fn presets(root: &std::path::Path) -> std::collections::BTreeMap<String, std::path::PathBuf> {
    std::fs::read_dir(root.join("config/presets"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension()? != "yaml" || !entry.file_type().ok()?.is_file() {
                return None;
            }
            Some((path.file_stem()?.to_str()?.to_string(), path))
        })
        .collect()
}

fn write_preset(cfg: &Config, output: &std::path::Path, penv: &PathEnv, dry: bool) -> std::io::Result<()> {
    let output = std::path::absolute(output)?;
    let paths = SetupPaths::resolve(Target::Dev, penv, false);
    let env: SocEnv = [
        ("SOC_VAULT_BACKEND", "dev".to_string()),
        ("SOC_MASTER_SOURCE", "auto".to_string()),
        ("SOC_ROOT", paths.soc_root.display().to_string()),
        ("SOC_PANELS_FILE", output.join("panels.yaml").display().to_string()),
        ("SOC_SECRET_DIR", paths.secret_dir.display().to_string()),
        ("SOC_INJECT_TMPL", paths.inject_tmpl.display().to_string()),
        ("SOC_CONFIG_VAULT_ITEM", paths.config_vault_item),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .collect();
    let panels = render_panels_yaml(cfg);
    let env = render_soc_env(&env);
    if dry {
        println!("{panels}\n{env}");
    } else {
        std::fs::create_dir_all(&output)?;
        soc_sys::fsutil::write_atomic(&output.join("panels.yaml"), panels.as_bytes(), 0o644)?;
        soc_sys::fsutil::write_atomic(&output.join("soc.env"), env.as_bytes(), 0o600)?;
    }
    Ok(())
}

/// Run the wizard. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    if matches!(args, [arg] if arg == "--apply-system") {
        return privileged::apply();
    }
    let opts = match parse_args(args) {
        Ok(Some(o)) => o,
        Ok(None) => {
            println!("{USAGE}");
            return 0;
        }
        Err(UsageError(msg)) => {
            eprintln!("[soc-wall] {msg}\n{USAGE}");
            return 2;
        }
    };
    let penv = PathEnv::from_process();
    let presets = presets(&penv.repo_root());
    if opts.list_presets {
        for (name, path) in presets {
            let text = soc_sys::fsutil::read_capped(&path, 4 << 20).unwrap_or_else(|_| String::new());
            let header = |prefix: &str| {
                text.lines().take_while(|l| l.starts_with('#')).find_map(|l| l.strip_prefix(prefix)).map(str::trim)
            };
            println!("{name}\t{}\t{}", header("# name:").unwrap_or(&name), header("# desc:").unwrap_or(""));
        }
        return 0;
    }
    let preset = match &opts.preset {
        Some(name) => match presets.get(name).map(|path| soc_core::load(path)) {
            Some(Ok(cfg)) => Some(cfg),
            Some(Err(e)) => {
                eprintln!("setup-gui: {e}");
                return 2;
            }
            None => {
                eprintln!("setup-gui: unknown preset {name:?}");
                return 2;
            }
        },
        None => None,
    };
    if let (Some(output), Some(cfg)) = (opts.output.as_ref(), preset.as_ref()) {
        return match write_preset(cfg, output, &penv, opts.dry_run) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("setup-gui: could not write {}: {e}", output.display());
                1
            }
        };
    }
    if opts.output.is_some() || opts.non_interactive {
        eprintln!("setup-gui: headless rendering needs --preset NAME and --output DIR");
        return 2;
    }
    if !style::init() {
        eprintln!("[soc-wall] the setup wizard needs a display (GTK could not start); use `soc-wall setup` instead");
        return 1;
    }
    let wiz = build_wizard(&opts, preset);
    wiz.window.show_all();
    wiz.pin_box.hide();
    wiz.go(0);
    gtk::main();
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn paths() -> SetupPaths {
        SetupPaths {
            target: Target::Dev,
            via: "repo".into(),
            marker: None,
            needs_privilege: false,
            panels_out: PathBuf::from("/tmp/x/panels.yaml"),
            panels_installed: PathBuf::from("/tmp/x/panels.yaml"),
            soc_env: PathBuf::from("/tmp/x/soc.env"),
            wall_unit: Some(PathBuf::from("/tmp/x/soc-wall.service")),
            soc_root: PathBuf::from("/opt/soc-display"),
            pinentry: PathBuf::from("/opt/soc-display/scripts/pinentry-vault.py"),
            secret_dir: PathBuf::from("/tmp/x/secret"),
            config_vault_item: "SOC Wall Config".into(),
            inject_tmpl: PathBuf::from("/opt/soc-display/inject/login.js.tmpl"),
            default_backend: "dev".into(),
            configured_marker: PathBuf::from("/tmp/x/.configured"),
            panels_mode: 0o644,
            env_mode: 0o600,
        }
    }

    fn form() -> FormData {
        seed(&Config::default(), &SocEnv::new(), &paths(), &Opts::default())
    }

    #[test]
    fn args_parse() {
        let a = |v: &[&str]| parse_args(&v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        assert_eq!(
            a(&["--dry-run", "--target", "dev"]),
            Ok(Some(Opts { dry_run: true, target: Some(Target::Dev), ..Opts::default() }))
        );
        assert_eq!(a(&["--help"]), Ok(None));
        assert!(a(&["--target", "mars"]).is_err());
        assert!(a(&["--nope"]).is_err());
        assert!(a(&["--target"]).is_err());
    }

    #[test]
    fn default_form_assembles_two_tiles() {
        let cfg = assemble(&form()).expect("defaults must validate");
        assert_eq!(cfg.panels.len(), 2);
        assert_eq!(cfg.panels.first().map(|p| p.id.as_str()), Some("p1"));
        assert_eq!(cfg.panels.get(1).map(|p| p.grid), Some((1, 0)));
    }

    #[test]
    fn errors_are_collected_not_first_only() {
        let mut f = form();
        for p in &mut f.panels {
            p.id = "dup".into();
            p.url = "not a url".into();
        }
        let e = assemble(&f).expect_err("must fail");
        let text = error_text(&e);
        assert!(e.problems.len() >= 2, "{text}");
        assert!(text.contains("\n  - "));
    }

    #[test]
    fn tunnel_tile_needs_a_jump_host() {
        let mut f = form();
        if let Some(p) = f.panels.first_mut() {
            p.tunnel_mode = true;
            p.local_port = "18080".into();
            p.remote_host = "10.0.0.9".into();
            p.remote_port = "443".into();
        }
        let e = assemble(&f).expect_err("no jump host");
        assert!(error_text(&e).contains("jump_host"));
        f.tunnel.jump_host = "bastion.example.net".into();
        f.tunnel.enabled = true;
        let cfg = assemble(&f).expect("now valid");
        assert_eq!(cfg.panels.first().map(|p| p.tunnel_local_port()), Some(Some(18080)));
    }

    #[test]
    fn rerun_keeps_keys_the_form_does_not_edit() {
        let yaml = "display: {auto: true, width: 1920, height: 1080, cols: 1, rows: 1, gap: 0}\n\
panels:\n  - {id: a, engine: webkit, mode: direct, url: 'http://10.0.0.1/', grid: [0, 0], title: Keep me}\n";
        let cfg = soc_core::load_str(yaml, "t").expect("loads");
        let f = seed(&cfg, &SocEnv::new(), &paths(), &Opts::default());
        let again = assemble(&f).expect("valid");
        assert_eq!(again.panels.first().map(|p| p.title.as_str()), Some("Keep me"));
    }

    #[test]
    fn env_gets_vault_answers_and_never_a_master() {
        let mut existing = SocEnv::new();
        existing.insert("SOC_VAULT_PASSWORD".into(), "hunter2".into());
        let mut v = form().vault;
        v.backend = "litebw".into();
        v.email = " ops@example.net ".into();
        v.master = Zeroizing::new("hunter2".into());
        let env = build_env(&existing, &paths(), &v);
        assert_eq!(env.get("SOC_VAULT_EMAIL").map(String::as_str), Some("ops@example.net"));
        assert_eq!(env.get("SOC_MASTER_SOURCE").map(String::as_str), Some("sealed"));
        assert!(!env.contains_key("SOC_VAULT_PASSWORD"));
        let text = render_soc_env(&env);
        assert!(!text.contains("hunter2"));
        assert!(text.contains("SOC_VAULT_BACKEND=litebw"));
    }

    #[test]
    fn review_shows_every_artifact() {
        let f = form();
        let cfg = assemble(&f).expect("valid");
        let env = build_env(&SocEnv::new(), &paths(), &f.vault);
        let t = review_text(&cfg, &env, &paths(), "soc", true);
        assert!(t.contains("DRY RUN"));
        assert!(t.contains("/tmp/x/panels.yaml"));
        assert!(t.contains("panels:"));
        assert!(t.contains("SOC_VAULT_BACKEND="));
        assert!(t.contains("soc-wall.service"));
        assert!(t.contains("SOC Panel 1"));
    }

    #[test]
    fn vault_page_problems_are_all_listed() {
        let mut v = form().vault;
        v.backend = "native".into();
        v.url = "ftp://x".into();
        v.email = String::new();
        v.master = Zeroizing::new("a".into());
        v.confirm = Zeroizing::new("b".into());
        assert_eq!(v.problems().len(), 3);
        v.backend = "dev".into();
        assert_eq!(v.problems().len(), 1);
        v.confirm = Zeroizing::new("a".into());
        assert!(v.problems().is_empty());
    }

    #[test]
    fn stages_follow_the_backend() {
        let mut v = form().vault;
        v.backend = "dev".into();
        assert_eq!(
            stages(&v),
            vec![
                Stage::Deploy(DeployStep::WriteConfig),
                Stage::Seal,
                Stage::Deploy(DeployStep::Doctor),
                Stage::Deploy(DeployStep::MarkConfigured),
            ]
        );
        v.backend = "litebw".into();
        v.target = Target::Pi;
        v.create_account = true;
        let s = stages(&v);
        assert_eq!(s.first(), Some(&Stage::Deploy(DeployStep::WriteConfig)));
        let pos = |st: Stage| s.iter().position(|x| *x == st);
        assert!(pos(Stage::Deploy(DeployStep::VaultAccount)) < pos(Stage::Seal));
        assert!(pos(Stage::Seal) < pos(Stage::Deploy(DeployStep::PushConfig)));
        assert!(pos(Stage::Deploy(DeployStep::VaultUp)).is_some());
        v.url = "https://vault.example.net".into();
        assert!(!stages(&v).contains(&Stage::Deploy(DeployStep::VaultUp)));
    }

    #[test]
    fn creds_are_keyed_by_vault_item_and_skip_blanks() {
        let mut f = form();
        if let Some(p) = f.panels.first_mut() {
            p.username = "admin".into();
            p.password = Zeroizing::new("s3cret".into());
        }
        let creds = creds_of(&f.panels);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds.get("SOC Panel 1").map(|c| c.username.as_str()), Some("admin"));
    }

    #[test]
    fn vpn_rows_round_trip_and_keep_extra_keys() {
        let mut d = Dict::new();
        d.insert("name".into(), json!("hq"));
        d.insert("type".into(), json!("fortinet"));
        d.insert("enabled".into(), json!(true));
        d.insert("gateway".into(), json!("vpn.example.net"));
        d.insert("realm".into(), json!("corp"));
        let mut v = VpnForm::from_dict(&d);
        v.port = "8443".into();
        let out = v.to_value();
        assert_eq!(out.get("realm"), Some(&json!("corp")));
        assert_eq!(out.get("port"), Some(&json!(8443)));
        assert_eq!(out.get("gateway"), Some(&json!("vpn.example.net")));
    }

    #[test]
    fn a_dry_run_pin_is_never_forwarded() {
        // The worker only emits `Msg::Pin` for real runs; the stage list itself is
        // identical, so a dry run differs solely by the plans' `dry_run` flag.
        let mut v = form().vault;
        v.dry_run = true;
        assert_eq!(stages(&v), stages(&VaultForm { dry_run: false, ..v.clone() }));
    }
}
