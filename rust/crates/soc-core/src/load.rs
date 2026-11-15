//! Loading a wall config: YAML text -> validated [`Config`].
//!
//! The same path serves the on-disk `panels.yaml` and the config kept in a
//! vault secure note ([`load_str`]). A broken config yields one
//! [`ConfigError`] listing every problem at once.

use crate::dict::{Dict, DictExt, as_bool, as_int, text, truthy};
use crate::env::parse_bool;
use crate::model::{
    Config, DisplayCfg, Engine, KeepAlive, KeepAliveStrategy, Layout, Mode, Panel, ProxyCfg, SecurityCfg,
    compute_geometry,
};
use crate::validate::{self, Findings};
use serde_json::Value;
use std::path::Path;

/// A config larger than this is a mistake (or an attack on the 1 GB board).
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The config is unusable. `problems` lists every validation finding; it is
/// empty for a structural failure (missing file, invalid YAML).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub message: String,
    pub problems: Vec<String>,
}

impl ConfigError {
    fn new(message: String) -> ConfigError {
        ConfigError { message, problems: Vec::new() }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigError {}

/// Boot-time overrides of the security master toggles
/// (`SOC_NAV_ALLOWLIST` / `SOC_BLOCK_TRACKERS`). Raw strings; garbage falls
/// back to the configured (safe) value.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub nav_allowlist: Option<String>,
    pub block_trackers: Option<String>,
}

impl Overrides {
    pub fn from_env() -> Overrides {
        Overrides {
            nav_allowlist: std::env::var("SOC_NAV_ALLOWLIST").ok(),
            block_trackers: std::env::var("SOC_BLOCK_TRACKERS").ok(),
        }
    }
}

/// Convert parsed YAML into the JSON value model the validators work on.
/// Non-string keys are stringified; non-finite floats (which JSON cannot
/// carry) become null so the validators reject them as "not a number".
fn to_json(y: serde_yaml_ng::Value) -> Value {
    use serde_yaml_ng::Value as Y;
    match y {
        Y::Null => Value::Null,
        Y::Bool(b) => Value::Bool(b),
        Y::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                Value::from(u)
            } else {
                n.as_f64().and_then(serde_json::Number::from_f64).map_or(Value::Null, Value::Number)
            }
        }
        Y::String(s) => Value::String(s),
        Y::Sequence(seq) => Value::Array(seq.into_iter().map(to_json).collect()),
        Y::Mapping(map) => {
            let mut out = Dict::new();
            for (k, v) in map {
                let key = match k {
                    Y::String(s) => s,
                    other => text(&to_json(other)),
                };
                out.insert(key, to_json(v));
            }
            Value::Object(out)
        }
        Y::Tagged(tagged) => to_json(tagged.value),
    }
}

/// Result of [`parse_yaml`]: the raw document or the parser's message.
pub type YamlResult = Result<Value, String>; // audit-allow: public API consumed by soc-wall as a plain message

/// Parse YAML text into the raw JSON-model document.
pub fn parse_yaml(text: &str) -> YamlResult {
    serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text).map(to_json).map_err(|e| e.to_string())
}

/// Load and validate the config file at `path`, applying the environment's
/// security overrides.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    load_with(path, &Overrides::from_env())
}

/// [`load`] with explicit overrides.
pub fn load_with(path: &Path, overrides: &Overrides) -> Result<Config, ConfigError> {
    let shown = path.display().to_string();
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            ConfigError::new(format!("config file not found: {shown} (set SOC_PANELS_FILE or run setup)"))
        }
        _ => ConfigError::new(format!("cannot read {shown}: {e}")),
    })?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(format!(
            "{shown} is {} bytes — larger than the {MAX_CONFIG_BYTES}-byte limit for a wall config",
            meta.len()
        )));
    }
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::new(format!("cannot read {shown}: {e}")))?;
    load_str_with(&text, &shown, overrides)
}

/// Parse + validate a config from YAML text — used when the wall config lives
/// in a vault secure note instead of an on-disk file.
pub fn load_str(text: &str, source: &str) -> Result<Config, ConfigError> {
    load_str_with(text, source, &Overrides::from_env())
}

/// [`load_str`] with explicit overrides.
pub fn load_str_with(text: &str, source: &str, overrides: &Overrides) -> Result<Config, ConfigError> {
    if !u64::try_from(text.len()).is_ok_and(|n| n <= MAX_CONFIG_BYTES) {
        return Err(ConfigError::new(format!("{source} is larger than the {MAX_CONFIG_BYTES}-byte limit")));
    }
    let raw = parse_yaml(text).map_err(|e| ConfigError::new(format!("{source} is not valid YAML: {e}")))?;
    from_value(&raw, source, overrides)
}

/// A section that may be absent or empty: unset -> `{}`.
fn section<'a>(raw: &'a Dict, key: &str, empty: &'a Value) -> &'a Value {
    match raw.get(key) {
        Some(v) if truthy(v) => v,
        _ => empty,
    }
}

fn int_or(d: &Dict, key: &str, default: i64) -> i64 {
    d.get(key).and_then(as_int).filter(|n| *n != 0).unwrap_or(default)
}

/// Narrow a validated integer; out-of-range falls back to `default`.
fn narrow_i32(v: i64, default: i32) -> i32 {
    i32::try_from(v).unwrap_or(default)
}

fn narrow_u32(v: i64, default: u32) -> u32 {
    u32::try_from(v).unwrap_or(default)
}

fn strings(d: &Dict, key: &str) -> Vec<String> {
    d.strings(key)
}

/// Validate an already-parsed document and build the [`Config`].
pub fn from_value(raw: &Value, source: &str, overrides: &Overrides) -> Result<Config, ConfigError> {
    let Some(raw) = raw.as_object() else {
        return Err(ConfigError::new(format!(
            "{source}: top level must be a mapping with display/panels/tunnel/vpn sections"
        )));
    };
    let mut f = Findings::default();
    let empty = Value::Object(Dict::new());

    let mut extra: Vec<&String> = raw.keys().filter(|k| !validate::TOP_KEYS.contains(&k.as_str())).collect();
    extra.sort_unstable();
    for k in extra {
        f.warns.push(format!("{source}: unknown key '{k}' (typo?) — it is ignored"));
    }

    let Some(d) = section(raw, "display", &empty).as_object() else {
        return Err(ConfigError::new(format!("{source}: display must be a mapping")));
    };
    validate::display(d, &mut f);
    // Only trust the display block when it validated: later checks (grid
    // bounds, geometry) must run against sane numbers.
    let disp = if f.errs.is_empty() {
        let defaults = DisplayCfg::default();
        DisplayCfg {
            auto: d.flag("auto", true),
            width: narrow_i32(int_or(d, "width", i64::from(defaults.width)), defaults.width),
            height: narrow_i32(int_or(d, "height", i64::from(defaults.height)), defaults.height),
            cols: narrow_u32(int_or(d, "cols", i64::from(defaults.cols)), defaults.cols),
            rows: narrow_u32(int_or(d, "rows", i64::from(defaults.rows)), defaults.rows),
            gap: narrow_i32(d.get("gap").and_then(as_int).unwrap_or(0), 0),
            layout: d.get("layout").and_then(Value::as_str).and_then(Layout::parse).unwrap_or(Layout::Auto),
            fullscreen: d.flag("fullscreen", true),
        }
    } else {
        DisplayCfg::default()
    };

    let no_panels: Vec<Value> = Vec::new();
    let panels_raw: &Vec<Value> = match raw.get("panels").filter(|v| truthy(v)) {
        None => &no_panels,
        Some(Value::Array(a)) => a,
        Some(_) => {
            f.errs.push("panels: must be a list".into());
            &no_panels
        }
    };
    for (i, p) in panels_raw.iter().enumerate() {
        validate::panel(i, p, &disp, &mut f);
    }
    validate::cross(raw, disp.layout, panels_raw, &mut f);
    let vpns_norm = validate::normalize_vpns(raw, &mut f);
    let legacy = raw.get("vpns").is_none_or(Value::is_null);
    validate::vpns(&vpns_norm, legacy, &mut f);
    validate::proxy(section(raw, "proxy", &empty), &mut f);
    validate::security(section(raw, "security", &empty), &mut f);

    if !f.errs.is_empty() {
        return Err(ConfigError {
            message: format!("{source} has {} problem(s):\n  - {}", f.errs.len(), f.errs.join("\n  - ")),
            problems: f.errs,
        });
    }

    let panels = panels_raw.iter().filter_map(Value::as_object).map(|p| build_panel(p, &disp)).collect();

    let pr = section(raw, "proxy", &empty).as_object().cloned().unwrap_or_default(); // audit-allow: default is the intended fallback
    let proxy = ProxyCfg {
        enabled: pr.truthy("enabled"),
        url: pr.text("url"),
        vault_item: pr.text("vault_item"),
        ignore_hosts: strings(&pr, "ignore_hosts"),
    };

    let sc = section(raw, "security", &empty).as_object().cloned().unwrap_or_default(); // audit-allow: default is the intended fallback
    let security = SecurityCfg {
        nav_allowlist: parse_bool(overrides.nav_allowlist.clone(), "SOC_NAV_ALLOWLIST", sc.flag("nav_allowlist", true)),
        allow: strings(&sc, "allow"),
        block_trackers: parse_bool(
            overrides.block_trackers.clone(),
            "SOC_BLOCK_TRACKERS",
            sc.flag("block_trackers", true),
        ),
        sso_allow: strings(&sc, "sso_allow"),
    };

    Ok(Config {
        display: disp,
        panels,
        tunnel: section(raw, "tunnel", &empty).as_object().cloned().unwrap_or_default(), // audit-allow: default is the intended fallback
        vpns: vpns_norm.unwrap_or_default().into_iter().filter_map(|v| v.as_object().cloned()).collect(), // audit-allow: default is the intended fallback
        proxy,
        security,
        warnings: f.warns,
    })
}

fn opt_text(d: &Dict, key: &str) -> Option<String> {
    d.get(key).filter(|v| truthy(v)).map(text)
}

/// Build one panel from a mapping that already passed validation.
fn build_panel(p: &Dict, disp: &DisplayCfg) -> Panel {
    let selectors = p.dict("selectors").cloned().unwrap_or_default(); // audit-allow: default is the intended fallback
    let grid = p
        .get("grid")
        .and_then(validate::grid_cell)
        .map_or((0, 0), |(c, r)| (u32::try_from(c).unwrap_or(0), u32::try_from(r).unwrap_or(0)));
    let ka = p.dict("keepalive").cloned().unwrap_or_default(); // audit-allow: default is the intended fallback
    let allow_insecure = p.get("allow_insecure").or_else(|| p.get("insecure_tls")).and_then(as_bool).unwrap_or(false);
    let mut panel = Panel {
        id: p.text("id"),
        engine: p.get("engine").and_then(Value::as_str).and_then(Engine::parse).unwrap_or(Engine::Webkit),
        grid,
        mode: p.get("mode").and_then(Value::as_str).and_then(Mode::parse).unwrap_or(Mode::Direct),
        vault_item: p.get("vault_item").filter(|v| truthy(v)).map(text).unwrap_or_default(), // audit-allow: default is the intended fallback
        login_marker: match p.get("login_marker").filter(|v| !v.is_null()) {
            Some(v) => text(v),
            None => selectors.get("pass").map(text).unwrap_or_default(), // audit-allow: default is the intended fallback
        },
        selectors,
        keepalive: KeepAlive {
            strategy: ka
                .get("strategy")
                .and_then(Value::as_str)
                .and_then(KeepAliveStrategy::parse)
                .unwrap_or(KeepAliveStrategy::None),
            interval_sec: ka.get("intervalSec").and_then(as_int).and_then(|n| u32::try_from(n).ok()).unwrap_or(600),
            url: opt_text(&ka, "url"),
            target: opt_text(&ka, "target"),
        },
        url: p.get("url").filter(|v| !v.is_null()).map(|v| text(v).trim().to_string()),
        tunnel: p.dict("tunnel").cloned(),
        path: p.get("path").and_then(Value::as_str).unwrap_or("/").to_string(),
        scheme: p.get("scheme").and_then(Value::as_str).unwrap_or("http").to_string(),
        proxy: p.flag("proxy", true),
        title: p.get("title").filter(|v| truthy(v)).map(text).unwrap_or_default(), // audit-allow: default is the intended fallback
        allow_insecure,
        allow_media: p.flag("allow_media", false),
        tenant: p.text("tenant"),
        persist: p.flag("persist", true),
        user_agent: opt_text(p, "user_agent"),
        allow: strings(p, "allow"),
        block_trackers: p.flag("block_trackers", true),
        unblock: strings(p, "unblock"),
        login_zones: p.dict("login_zones").cloned().unwrap_or_default(), // audit-allow: default is the intended fallback
        geometry: None,
    };
    panel.geometry = Some(compute_geometry(disp, panel.grid));
    panel
}
