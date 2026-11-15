//! Honest, cheap, time-boxed health state for the launcher (and SSH/tests).
//!
//! The single source of truth for "is the wall actually ready to launch?",
//! split so the UI never waits on the network:
//!
//! - the **sync** part ([`sync_state`], [`is_installed`]) only looks at local
//!   files and is instant;
//! - the **probe** part ([`probe_state`]) opens sockets with a hard per-facet
//!   timeout and belongs on a background thread.
//!
//! Unknown always degrades to neutral/amber — never a false green, never a
//! hang. No secret appears in any field: only the vault note *name* and a
//! `host:port` are carried, never URL userinfo, a password or an email.

use crate::fsutil::{passwd_lookup, read_capped};
use crate::paths::{Candidate, Kind, PathEnv};
use serde_json::{Value, json};
use soc_core::guard::host_port;
use soc_core::url::Url;
use soc_core::vpnargs::{vpn_interface, vpn_kind, wireguard_target};
use soc_core::{Config, Dict, DictExt, VpnKind};
use std::collections::BTreeMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Hard ceiling for any single network probe. A loopback vault answers in
/// under a millisecond; this only bites a mis-set remote URL, off-thread.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// Where the kernel lists network interfaces.
pub const SYS_NET: &str = "/sys/class/net";

/// Parse `KEY=VALUE` env-file text: comments and lines without `=` are
/// skipped, one layer of matching quotes is removed. Values are data — no
/// shell expansion is ever performed.
pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let mut value = value.trim();
        for quote in ['"', '\''] {
            if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
                value = &value[1..value.len() - 1];
                break;
            }
        }
        out.insert(key.trim().to_string(), value.to_string());
    }
    out
}

/// [`parse_env`] of a file; empty when it is missing or unreadable.
pub fn load_env_file(path: &Path) -> BTreeMap<String, String> {
    read_capped(path, 1 << 20).map(|text| parse_env(&text)).unwrap_or_default() // audit-allow: default is the intended fallback (empty env)
}

/// The keys of `soc.env` the health state reads.
pub const HEALTH_ENV_KEYS: [&str; 3] = ["SOC_CONFIG_VAULT_ITEM", "SOC_VAULT_URL", "SOC_VAULT_BACKEND"];

/// The effective env: file values overlaid by the process environment, so an
/// explicitly exported `SOC_*` wins — the wall reads it that way too.
pub fn effective_env(
    mut file_env: BTreeMap<String, String>,
    process: impl Fn(&str) -> Option<String>,
) -> BTreeMap<String, String> {
    for key in HEALTH_ENV_KEYS {
        if let Some(v) = process(key).filter(|v| !v.is_empty()) {
            file_env.insert(key.to_string(), v);
        }
    }
    file_env
}

/// `host:port` of `SOC_VAULT_URL` (IPv6 bracketed), defaulting the port by
/// scheme. `None` when absent or unparseable. Never includes userinfo.
pub fn vault_hostport(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let with_scheme = if url.contains("://") { url.to_string() } else { format!("http://{url}") };
    let parts = Url::split(&with_scheme).ok()?;
    let host = parts.host?;
    let default = if parts.scheme == "https" { 443 } else { 80 };
    Some(host_port(&host, parts.port.filter(|p| *p != 0).unwrap_or(default)))
}

/// The non-secret subset of a VPN entry the probe needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnProbe {
    pub enabled: bool,
    pub kind: VpnKind,
    /// Explicit interface override (`""` = per-backend default).
    pub interface: String,
    /// The backend's config path / wg interface name.
    pub config: String,
    /// `host:port` behind the VPN whose reachability proves it is up.
    pub ready_probe: String,
}

impl VpnProbe {
    pub fn from_entry(vpn: &Dict) -> VpnProbe {
        VpnProbe {
            enabled: vpn.truthy("enabled"),
            kind: vpn_kind(vpn),
            interface: vpn_interface(vpn),
            config: wireguard_target(vpn),
            ready_probe: vpn.text("ready_probe"),
        }
    }
}

/// The coarse configuration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overall {
    Unconfigured,
    Invalid,
    Configured,
}

impl Overall {
    pub const fn as_str(self) -> &'static str {
        match self {
            Overall::Unconfigured => "unconfigured",
            Overall::Invalid => "invalid",
            Overall::Configured => "configured",
        }
    }
}

/// The outcome of trying to load the resolved config.
#[derive(Debug, Clone, Copy)]
pub enum ConfigLoad<'a> {
    /// Not attempted — the count is deferred, which is not a failure.
    Deferred,
    /// The config was rejected; the message is shown (first line only).
    Invalid(&'a str),
    Loaded(&'a Config),
}

/// The instantly available state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub configured: bool,
    pub panels_path: Option<PathBuf>,
    /// Which precedence tier the config came from (`none` when unresolved).
    pub panels_tier: String,
    pub panels_count: Option<usize>,
    /// `None` = not checked yet.
    pub panels_valid: Option<bool>,
    pub config_error: Option<String>,
    /// Name of the vault note holding the config (never its contents).
    pub vault_note: Option<String>,
    pub vault_url_hostport: Option<String>,
    pub vpn_configured: bool,
    /// The representative enabled VPN to probe.
    pub vpn: Option<VpnProbe>,
    pub overall_sync: Overall,
}

/// Build the sync state from already-resolved inputs. Opens no socket.
pub fn sync_state(panels: Option<&Candidate>, load: ConfigLoad<'_>, env: &BTreeMap<String, String>) -> SyncState {
    let configured = panels.is_some_and(|c| c.path.exists());
    let mut state = SyncState {
        configured,
        panels_path: panels.map(|c| c.path.clone()),
        panels_tier: panels.map_or_else(|| "none".to_string(), |c| c.label.clone()),
        panels_count: None,
        panels_valid: None,
        config_error: None,
        vault_note: env.get("SOC_CONFIG_VAULT_ITEM").filter(|v| !v.is_empty()).cloned(),
        vault_url_hostport: vault_hostport(env.get("SOC_VAULT_URL").map_or("", String::as_str)),
        vpn_configured: false,
        vpn: None,
        overall_sync: Overall::Unconfigured,
    };
    if configured {
        match load {
            ConfigLoad::Deferred => {}
            ConfigLoad::Invalid(message) => {
                state.panels_valid = Some(false);
                // First line only: never a multi-line dump in a status label.
                let first = message.lines().next().unwrap_or("").trim();
                state.config_error =
                    Some(if first.is_empty() { "invalid config".to_string() } else { first.to_string() });
            }
            ConfigLoad::Loaded(conf) => {
                state.panels_count = Some(conf.panels.len());
                state.panels_valid = Some(true);
                // One cheap probe for the launcher dot: prefer an enabled VPN
                // with a ready_probe (the accurate signal), else the first.
                let enabled: Vec<&Dict> = conf.enabled_vpns().collect();
                state.vpn_configured = !enabled.is_empty();
                let pick = enabled.iter().find(|v| !v.text("ready_probe").is_empty()).or(enabled.first());
                state.vpn = pick.map(|v| VpnProbe::from_entry(v));
            }
        }
        state.overall_sync = if state.panels_valid == Some(false) { Overall::Invalid } else { Overall::Configured };
    }
    state
}

/// Resolve, load and summarise the wall's config for this process: the
/// convenience entry point behind the launcher and `--json`.
pub fn sync_state_for(paths: &PathEnv, process_env: impl Fn(&str) -> Option<String>) -> SyncState {
    let panels = paths.resolve_read(Kind::Panels);
    let file_env = paths.resolve_env().map(|p| load_env_file(&p)).unwrap_or_default(); // audit-allow: default is the intended fallback (empty env)
    let env = effective_env(file_env, process_env);
    let loaded = panels.as_ref().filter(|c| c.path.exists()).map(|c| soc_core::load(&c.path));
    let load = match &loaded {
        None => ConfigLoad::Deferred,
        Some(Ok(conf)) => ConfigLoad::Loaded(conf),
        Some(Err(e)) => ConfigLoad::Invalid(&e.message),
    };
    sync_state(panels.as_ref(), load, &env)
}

/// Whether the wall is installed on this machine, and the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub installed: bool,
    pub etc_present: bool,
    pub opt_present: bool,
    pub units_present: bool,
    pub kiosk_user: bool,
    /// The strongest signal present (for tooltips / debugging).
    pub reason: String,
}

/// Inputs of [`is_installed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallProbe {
    /// The filesystem root to look under (`/`; a fixture tree in tests).
    pub fs_root: PathBuf,
    /// `$SOC_KIOSK_USER` (default `soc`).
    pub kiosk_user: String,
    /// `$SOC_FORCE_INSTALLED` — `0`/`1` forces the answer (dev/verify).
    pub force: Option<String>,
}

impl InstallProbe {
    pub fn from_process() -> InstallProbe {
        InstallProbe {
            fs_root: PathBuf::from("/"),
            kiosk_user: std::env::var("SOC_KIOSK_USER").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "soc".into()),
            force: std::env::var("SOC_FORCE_INSTALLED").ok(),
        }
    }
}

/// Probe the literal paths the installer writes — never `$SOC_ROOT`, so a dev
/// checkout does not read as installed. The stamp is the authoritative
/// signal; `/opt` tree + units is the fallback for an older install.
pub fn is_installed(probe: &InstallProbe) -> Installed {
    let at = |rel: &str| probe.fs_root.join(rel);
    let stamp = at("etc/soc-display/.installed").exists();
    let etc_present = at("etc/soc-display").is_dir();
    let opt_present = at("opt/soc-display").is_dir();
    let units_present =
        at("etc/systemd/system/soc-wall.service").exists() || at("usr/lib/systemd/system/soc-wall.service").exists();
    let kiosk_user = passwd_lookup(&at("etc/passwd"), |e| e.name == probe.kiosk_user).is_some();

    let mut installed = stamp || (opt_present && units_present);
    let mut reason = match (stamp, opt_present, units_present) {
        (true, _, _) => "install stamp",
        (false, true, true) => "/opt tree + units",
        (false, true, false) => "/opt tree only",
        (false, false, true) => "units only",
        (false, false, false) => "no install signals",
    }
    .to_string();
    if let Some(force @ ("0" | "1")) = probe.force.as_deref() {
        installed = force == "1";
        reason = format!("forced ({force})");
    }
    Installed { installed, etc_present, opt_present, units_present, kiosk_user, reason }
}

/// Split `host:port` / `[v6]:port` / `v6:port`; `None` when unparseable.
fn split_probe(hostport: &str) -> Option<(&str, u16)> {
    let hostport = hostport.trim();
    let (host, port) = match hostport.strip_prefix('[') {
        Some(rest) => {
            let (host, tail) = rest.split_once(']')?;
            (host, tail.strip_prefix(':')?)
        }
        None => hostport.rsplit_once(':')?,
    };
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((host, port.parse().ok().filter(|p| *p != 0)?))
}

/// One bounded TCP connect. `Some(true)` reachable, `Some(false)` refused or
/// timed out, `None` unparseable or unresolvable (unknown, not "down").
pub fn tcp_ok(hostport: &str, timeout: Duration) -> Option<bool> {
    let (host, port) = split_probe(hostport)?;
    let addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
    if addrs.is_empty() {
        return None;
    }
    // The budget covers all addresses together, so a multi-homed name cannot
    // multiply the wait.
    let deadline = Instant::now() + timeout;
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        if TcpStream::connect_timeout(&addr, left).is_ok() {
            return Some(true);
        }
    }
    Some(false)
}

/// The state of a VPN as far as the fast probe can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    Online,
    Offline,
    NotConfigured,
}

impl VpnState {
    pub const fn as_str(self) -> &'static str {
        match self {
            VpnState::Online => "online",
            VpnState::Offline => "offline",
            VpnState::NotConfigured => "not_configured",
        }
    }
}

/// The interface a VPN entry is expected to bring up.
pub fn expected_iface(vpn: &VpnProbe) -> String {
    if !vpn.interface.is_empty() {
        return vpn.interface.clone();
    }
    match vpn.kind {
        VpnKind::Wireguard => {
            let base = vpn.config.rsplit('/').next().unwrap_or("");
            let name = base.strip_suffix(".conf").unwrap_or(base);
            if name.is_empty() { "wg0".to_string() } else { name.to_string() }
        }
        VpnKind::Openvpn => "tun0".to_string(),
        VpnKind::Fortinet | VpnKind::Inode => "ppp0".to_string(),
    }
}

/// Whether a network interface exists. The name comes from config, so it is
/// vetted as an interface name first — it must not be able to walk out of
/// `/sys/class/net` and turn any directory into "VPN online".
pub fn iface_up(sys_net: &Path, iface: &str) -> bool {
    let valid = !iface.is_empty()
        && iface.len() <= 15
        && iface != "."
        && iface != ".."
        && iface.bytes().all(|b| b.is_ascii_graphic() && b != b'/');
    valid && sys_net.join(iface).is_dir()
}

/// The VPN state under our own short timeout. The trustworthy signal is the
/// `ready_probe` connect; interface presence (instant, but it can be up with
/// a dead route) is the last resort. `None` = could not tell.
pub fn vpn_state_fast(vpn: &VpnProbe, timeout: Duration, sys_net: &Path) -> Option<VpnState> {
    if !vpn.enabled {
        return Some(VpnState::NotConfigured);
    }
    let probe = vpn.ready_probe.trim();
    if !probe.is_empty() {
        return tcp_ok(probe, timeout).map(|ok| if ok { VpnState::Online } else { VpnState::Offline });
    }
    Some(if iface_up(sys_net, &expected_iface(vpn)) { VpnState::Online } else { VpnState::Offline })
}

/// The slow facets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeState {
    /// `None` = no (or an unresolvable) vault URL.
    pub vault_reachable: Option<bool>,
    pub vpn_state: Option<VpnState>,
}

/// Probe vault reachability and VPN state. Thread-only: each facet blocks for
/// at most its timeout.
pub fn probe_state(sync: &SyncState, vault_timeout: Duration, vpn_timeout: Duration, sys_net: &Path) -> ProbeState {
    let vault_reachable = sync.vault_url_hostport.as_deref().and_then(|hp| tcp_ok(hp, vault_timeout));
    let vpn_state = if sync.vpn_configured {
        sync.vpn.as_ref().and_then(|vpn| vpn_state_fast(vpn, vpn_timeout, sys_net))
    } else if sync.panels_valid == Some(true) {
        Some(VpnState::NotConfigured)
    } else {
        // Either genuinely not configured, or we could not tell.
        None
    };
    ProbeState { vault_reachable, vpn_state }
}

/// The header dot colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Green,
    Amber,
    Red,
    Neutral,
}

impl Level {
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::Green => "green",
            Level::Amber => "amber",
            Level::Red => "red",
            Level::Neutral => "neutral",
        }
    }
}

/// The single colour/label mapping. Precedence: red (config invalid / VPN
/// down) > amber (unconfigured / vault unreachable or unknown / VPN unknown)
/// > green. Before the probe returns the dot is neutral.
pub fn dot_for(sync: &SyncState, probe: Option<&ProbeState>) -> (Level, &'static str) {
    if sync.panels_valid == Some(false) {
        return (Level::Red, "config invalid");
    }
    if probe.is_some_and(|p| p.vpn_state == Some(VpnState::Offline)) {
        return (Level::Red, "vpn down");
    }
    if sync.overall_sync == Overall::Unconfigured {
        return (Level::Amber, "not configured");
    }
    let Some(probe) = probe else {
        return (Level::Neutral, "checking…");
    };
    let has_vault_url = sync.vault_url_hostport.is_some();
    match probe.vault_reachable {
        Some(false) => return (Level::Amber, "vault locked"),
        None if has_vault_url => return (Level::Amber, "vault unknown"),
        _ => {}
    }
    if sync.vpn_configured && !matches!(probe.vpn_state, Some(VpnState::Online | VpnState::NotConfigured)) {
        return (Level::Amber, "vpn unknown");
    }
    (Level::Green, "secure")
}

/// How bad the worst finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Pass,
    Warn,
    Fail,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Pass => "pass",
            Severity::Warn => "warn",
            Severity::Fail => "fail",
        }
    }
}

/// Sync + probe merged, with the single worst cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullCheck {
    pub sync: SyncState,
    pub probe: ProbeState,
    pub overall: Severity,
    pub first_cause: Option<String>,
}

/// Merge the two halves. Fail = config invalid / VPN offline; warn =
/// unconfigured / vault unreachable / VPN unknown / vault note not set.
pub fn full_check(sync: SyncState, probe: ProbeState) -> FullCheck {
    let (overall, first_cause) = if sync.panels_valid == Some(false) {
        let why = sync.config_error.as_deref().filter(|e| !e.is_empty()).unwrap_or("see panels.yaml");
        (Severity::Fail, Some(format!("config invalid: {why}")))
    } else if probe.vpn_state == Some(VpnState::Offline) {
        (Severity::Fail, Some("VPN down".to_string()))
    } else if sync.overall_sync == Overall::Unconfigured {
        (Severity::Warn, Some("not configured — run Setup".to_string()))
    } else if sync.vault_url_hostport.is_some() && probe.vault_reachable != Some(true) {
        (Severity::Warn, Some("vault unreachable".to_string()))
    } else if sync.vpn_configured && probe.vpn_state != Some(VpnState::Online) {
        (Severity::Warn, Some("VPN state unknown".to_string()))
    } else if sync.vault_note.is_none() {
        (Severity::Warn, Some("vault config note not set (using panels.yaml fallback)".to_string()))
    } else {
        (Severity::Pass, None)
    };
    FullCheck { sync, probe, overall, first_cause }
}

fn sync_json(s: &SyncState) -> Value {
    json!({
        "configured": s.configured,
        "panels_path": s.panels_path.as_ref().map(|p| p.display().to_string()),
        "panels_tier": s.panels_tier,
        "panels_count": s.panels_count,
        "panels_valid": s.panels_valid,
        "config_error": s.config_error,
        "vault_note": s.vault_note,
        "vault_url_hostport": s.vault_url_hostport,
        "vpn_configured": s.vpn_configured,
        "vpn": s.vpn.as_ref().map(|v| json!({
            "enabled": v.enabled,
            "type": v.kind.as_str(),
            "interface": v.interface,
            "config": v.config,
            "ready_probe": v.ready_probe,
        })),
        "overall_sync": s.overall_sync.as_str(),
    })
}

impl FullCheck {
    /// The flat document `--json` prints.
    pub fn to_json(&self) -> Value {
        let mut doc = sync_json(&self.sync);
        if let Some(map) = doc.as_object_mut() {
            map.insert("vault_reachable".into(), json!(self.probe.vault_reachable));
            map.insert("vpn_state".into(), json!(self.probe.vpn_state.map(VpnState::as_str)));
            map.insert("overall".into(), json!(self.overall.as_str()));
            map.insert("first_cause".into(), json!(self.first_cause));
        }
        doc
    }
}

/// `health [--json | --check]` — the health state for SSH and tests.
/// `--json` runs the bounded probe inline; the default prints the sync state
/// and the pre-probe dot.
pub fn health_main(args: &[String]) -> i32 {
    let sync = sync_state_for(&PathEnv::from_process(), |k| std::env::var(k).ok());
    match args.first().map(String::as_str) {
        Some("--check") => {
            println!("health ok");
            0
        }
        Some("--json") => {
            let probe = probe_state(&sync, PROBE_TIMEOUT, PROBE_TIMEOUT, Path::new(SYS_NET));
            println!("{}", full_check(sync, probe).to_json());
            0
        }
        None => {
            let (level, label) = dot_for(&sync, None);
            let doc = json!({"sync": sync_json(&sync), "dot": [level.as_str(), label]});
            println!("{doc:#}");
            0
        }
        Some(other) => {
            eprintln!("health: unrecognized argument: {other}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Tier;
    use crate::testutil::{TempDir, dict, wall_basic};
    use std::net::TcpListener;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    fn candidate(path: &Path) -> Candidate {
        Candidate { path: path.to_path_buf(), tier: Tier::Etc, label: "/etc/soc-display".into() }
    }

    fn vpn(v: Value) -> VpnProbe {
        VpnProbe::from_entry(&dict(v))
    }

    /// A configured, valid sync state with the given vault URL / VPN.
    fn configured(vault: Option<&str>, vpn_configured: bool) -> SyncState {
        SyncState {
            configured: true,
            panels_path: Some("/etc/soc-display/panels.yaml".into()),
            panels_tier: "/etc/soc-display".into(),
            panels_count: Some(4),
            panels_valid: Some(true),
            config_error: None,
            vault_note: Some("SOC Wall Config".into()),
            vault_url_hostport: vault.map(str::to_string),
            vpn_configured,
            vpn: None,
            overall_sync: Overall::Configured,
        }
    }

    fn probe(vault: Option<bool>, vpn: Option<VpnState>) -> ProbeState {
        ProbeState { vault_reachable: vault, vpn_state: vpn }
    }

    #[test]
    fn env_file_parsing() {
        let parsed = parse_env(
            "# comment\n\nSOC_VAULT_URL = \"http://127.0.0.1:8222\"\nA='x y'\nB=\"unterminated\nnoequals\nC=a=b\nD=$(id)\n",
        );
        assert_eq!(parsed["SOC_VAULT_URL"], "http://127.0.0.1:8222");
        assert_eq!(parsed["A"], "x y");
        assert_eq!(parsed["B"], "\"unterminated");
        assert_eq!(parsed["C"], "a=b");
        assert_eq!(parsed["D"], "$(id)", "values are data, never evaluated");
        assert!(!parsed.contains_key("noequals"));
        assert!(load_env_file(Path::new("/nonexistent/soc.env")).is_empty());
    }

    /// The env file is 0640 root:soc and a service may run as another user:
    /// "exists but unreadable" must behave like "absent", never abort the
    /// caller (the guard the shell entry scripts needed `-r` for).
    #[test]
    fn an_unreadable_env_file_is_treated_as_absent() {
        use std::os::unix::fs::PermissionsExt;
        let t = TempDir::new("health-envguard");
        let file = t.write("soc.env", "SOC_VAULT_URL=http://127.0.0.1:8222\n");
        assert_eq!(load_env_file(&file).len(), 1);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        if crate::fsutil::euid() != 0 {
            assert!(load_env_file(&file).is_empty());
        }
        assert!(load_env_file(t.path()).is_empty(), "a directory in its place is not fatal either");
    }

    #[test]
    fn exported_values_win_over_the_file() {
        let file = env(&[("SOC_VAULT_URL", "http://file:1"), ("OTHER", "kept")]);
        let merged = effective_env(file, |k| match k {
            "SOC_VAULT_URL" => Some("http://exported:2".into()),
            "SOC_CONFIG_VAULT_ITEM" => Some(String::new()),
            "OTHER" => Some("ignored".into()),
            _ => None,
        });
        assert_eq!(merged["SOC_VAULT_URL"], "http://exported:2");
        assert_eq!(merged["OTHER"], "kept");
        assert!(!merged.contains_key("SOC_CONFIG_VAULT_ITEM"));
    }

    #[test]
    fn vault_hostport_never_leaks_userinfo() {
        assert_eq!(vault_hostport("http://127.0.0.1:8222").as_deref(), Some("127.0.0.1:8222"));
        assert_eq!(vault_hostport("https://Vault.Example").as_deref(), Some("vault.example:443"));
        assert_eq!(vault_hostport("vault.lan").as_deref(), Some("vault.lan:80"));
        assert_eq!(vault_hostport("vault.lan:9000/path").as_deref(), Some("vault.lan:9000"));
        assert_eq!(vault_hostport("https://user:hunter2@vault.lan/").as_deref(), Some("vault.lan:443"));
        assert_eq!(vault_hostport("http://[fd00::1]:8222").as_deref(), Some("[fd00::1]:8222"));
        for bad in ["", "   ", "http://", "http://h:99999", "http://h:x", "http://[::1"] {
            assert_eq!(vault_hostport(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn unconfigured_when_nothing_resolves() {
        let s = sync_state(None, ConfigLoad::Deferred, &env(&[]));
        assert!(!s.configured);
        assert_eq!((s.panels_tier.as_str(), s.overall_sync), ("none", Overall::Unconfigured));
        assert_eq!(dot_for(&s, None), (Level::Amber, "not configured"));
        // A resolved path that has since vanished is unconfigured too.
        let gone = candidate(Path::new("/nonexistent/panels.yaml"));
        assert!(!sync_state(Some(&gone), ConfigLoad::Deferred, &env(&[])).configured);
    }

    #[test]
    fn loaded_config_is_summarised_without_secrets() {
        let t = TempDir::new("health-sync");
        let path = t.write("panels.yaml", "x");
        let mut conf = wall_basic();
        conf.vpns = vec![
            dict(json!({"name": "off", "enabled": false, "ready_probe": "10.0.0.1:443"})),
            dict(json!({"name": "a", "enabled": true, "type": "wireguard", "config": "/etc/wireguard/wg7.conf"})),
            dict(json!({"name": "b", "enabled": true, "ready_probe": " 10.9.9.9:443 ", "vault_item": "VPN login"})),
        ];
        let e = env(&[
            ("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config"),
            ("SOC_VAULT_URL", "http://u:hunter2secret@127.0.0.1:8222"),
        ]);
        let s = sync_state(Some(&candidate(&path)), ConfigLoad::Loaded(&conf), &e);
        assert!(s.configured && s.vpn_configured);
        assert_eq!((s.panels_count, s.panels_valid, s.overall_sync), (Some(4), Some(true), Overall::Configured));
        assert_eq!(s.vault_note.as_deref(), Some("SOC Wall Config"));
        assert_eq!(s.vault_url_hostport.as_deref(), Some("127.0.0.1:8222"));
        // The enabled entry with a ready_probe is the representative one.
        assert_eq!(s.vpn.as_ref().unwrap().ready_probe, "10.9.9.9:443");
        let shown = full_check(s, probe(Some(true), Some(VpnState::Online))).to_json().to_string();
        assert!(!shown.contains("hunter2secret") && !shown.contains("VPN login"), "{shown}");
    }

    #[test]
    fn invalid_config_reports_only_the_first_line() {
        let t = TempDir::new("health-invalid");
        let path = t.write("panels.yaml", "x");
        let s = sync_state(
            Some(&candidate(&path)),
            ConfigLoad::Invalid("panels.yaml has 2 problem(s):\n  - a\n  - b"),
            &env(&[]),
        );
        assert_eq!(s.panels_valid, Some(false));
        assert_eq!(s.config_error.as_deref(), Some("panels.yaml has 2 problem(s):"));
        assert_eq!(s.overall_sync, Overall::Invalid);
        assert_eq!(dot_for(&s, None), (Level::Red, "config invalid"));
        let check = full_check(s, probe(None, None));
        assert_eq!(check.overall, Severity::Fail);
        assert_eq!(check.first_cause.as_deref(), Some("config invalid: panels.yaml has 2 problem(s):"));
    }

    #[test]
    fn sync_state_for_resolves_loads_and_reads_the_env_file() {
        let t = TempDir::new("health-for");
        let etc = t.path().join("etc");
        t.write("etc/panels.yaml", &crate::testutil::fixture("wall-basic.yaml"));
        t.write("etc/soc.env", "SOC_CONFIG_VAULT_ITEM=\"Wall Config\"\nSOC_VAULT_URL=http://127.0.0.1:8222\n");
        let paths = PathEnv {
            cwd: t.path().to_path_buf(),
            home: t.path().join("home"),
            xdg_config_home: None,
            etc_dir: Some(etc.display().to_string()),
            root: Some(t.path().join("repo").display().to_string()),
            default_root: t.path().join("repo"),
            panels_file: None,
            env_file: None,
            secret_dir: None,
            webdata_dir: None,
            state_dir: None,
            force_etc: None,
            allow_pkexec: None,
        };
        let s = sync_state_for(&paths, |_| None);
        assert_eq!((s.panels_count, s.panels_valid), (Some(4), Some(true)), "{:?}", s.config_error);
        assert_eq!(s.vault_note.as_deref(), Some("Wall Config"));
        assert_eq!(s.vault_url_hostport.as_deref(), Some("127.0.0.1:8222"));
        t.write("etc/panels.yaml", "panels: [{id: 'bad id'}]\n");
        let bad = sync_state_for(&paths, |_| None);
        assert_eq!(bad.panels_valid, Some(false));
        assert!(bad.config_error.is_some_and(|e| !e.contains('\n')));
    }

    #[test]
    fn installed_signals() {
        let t = TempDir::new("health-installed");
        let probe = |force: Option<&str>| InstallProbe {
            fs_root: t.path().to_path_buf(),
            kiosk_user: "soc".into(),
            force: force.map(str::to_string),
        };
        let none = is_installed(&probe(None));
        assert_eq!((none.installed, none.reason.as_str(), none.kiosk_user), (false, "no install signals", false));

        std::fs::create_dir_all(t.path().join("opt/soc-display")).unwrap();
        assert_eq!(is_installed(&probe(None)).reason, "/opt tree only");
        t.write("usr/lib/systemd/system/soc-wall.service", "[Unit]\n");
        let both = is_installed(&probe(None));
        assert!(both.installed && both.opt_present && both.units_present && !both.etc_present);
        assert_eq!(both.reason, "/opt tree + units");

        t.write("etc/soc-display/.installed", "");
        t.write("etc/passwd", "root:x:0:0::/root:/bin/sh\nsoc:x:1001:1001::/home/soc:/bin/sh\n");
        let stamped = is_installed(&probe(None));
        assert!(stamped.installed && stamped.etc_present && stamped.kiosk_user);
        assert_eq!(stamped.reason, "install stamp");

        let forced_off = is_installed(&probe(Some("0")));
        assert_eq!((forced_off.installed, forced_off.reason.as_str()), (false, "forced (0)"));
        assert!(is_installed(&probe(Some("1"))).installed);
        assert_eq!(is_installed(&probe(Some("yes"))).reason, "install stamp", "only 0/1 force");
    }

    #[test]
    fn tcp_probe_distinguishes_up_down_and_unknown() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(tcp_ok(&format!("127.0.0.1:{port}"), PROBE_TIMEOUT), Some(true));
        drop(listener);
        assert_eq!(tcp_ok(&format!("127.0.0.1:{port}"), PROBE_TIMEOUT), Some(false));
        for unknown in ["", "nohost", ":80", "host:", "host:http", "host:0", "host:70000", "[::1]", "[::1]80"] {
            assert_eq!(tcp_ok(unknown, PROBE_TIMEOUT), None, "{unknown:?}");
        }
    }

    #[test]
    fn probe_targets_accept_bracketed_ipv6() {
        assert_eq!(split_probe("[fd00::1]:443"), Some(("fd00::1", 443)));
        assert_eq!(split_probe("::1:8222"), Some(("::1", 8222)));
        assert_eq!(split_probe(" gw.lan:10443 "), Some(("gw.lan", 10443)));
    }

    #[test]
    fn expected_interface_per_backend() {
        assert_eq!(expected_iface(&vpn(json!({"enabled": true}))), "ppp0");
        assert_eq!(expected_iface(&vpn(json!({"type": "openvpn"}))), "tun0");
        assert_eq!(expected_iface(&vpn(json!({"type": "wireguard", "config": "/etc/wireguard/wg7.conf"}))), "wg7");
        assert_eq!(expected_iface(&vpn(json!({"type": "wireguard", "config": "office"}))), "office");
        assert_eq!(expected_iface(&vpn(json!({"type": "wireguard"}))), "wg0");
        assert_eq!(expected_iface(&vpn(json!({"type": "openvpn", "interface": "tun5"}))), "tun5");
    }

    #[test]
    fn interface_names_cannot_escape_sys_class_net() {
        let t = TempDir::new("health-iface");
        std::fs::create_dir_all(t.path().join("net/ppp0")).unwrap();
        std::fs::create_dir_all(t.path().join("elsewhere")).unwrap();
        let net = t.path().join("net");
        assert!(iface_up(&net, "ppp0"));
        assert!(!iface_up(&net, "tun0"));
        for evil in ["", ".", "..", "../elsewhere", "ppp0/../ppp0", "/etc", "a-name-longer-than-ifnamsiz", "pp p0"] {
            assert!(!iface_up(&net, evil), "{evil:?}");
        }
    }

    #[test]
    fn vpn_state_uses_the_probe_then_the_interface() {
        let t = TempDir::new("health-vpn");
        std::fs::create_dir_all(t.path().join("tun0")).unwrap();
        let fast = |v: Value| vpn_state_fast(&vpn(v), PROBE_TIMEOUT, t.path());
        assert_eq!(fast(json!({"enabled": false})), Some(VpnState::NotConfigured));
        assert_eq!(fast(json!({"enabled": true, "type": "openvpn"})), Some(VpnState::Online));
        assert_eq!(fast(json!({"enabled": true})), Some(VpnState::Offline), "no ppp0");
        assert_eq!(fast(json!({"enabled": true, "ready_probe": "garbage"})), None);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        assert_eq!(fast(json!({"enabled": true, "ready_probe": target})), Some(VpnState::Online));
        drop(listener);
        assert_eq!(fast(json!({"enabled": true, "ready_probe": target})), Some(VpnState::Offline));
    }

    #[test]
    fn probe_state_facets() {
        let net = Path::new("/nonexistent");
        let p = probe_state(&configured(None, false), PROBE_TIMEOUT, PROBE_TIMEOUT, net);
        assert_eq!(p, probe(None, Some(VpnState::NotConfigured)));
        // VPN configured but no carried block: unknown, never a second parse.
        assert_eq!(probe_state(&configured(None, true), PROBE_TIMEOUT, PROBE_TIMEOUT, net).vpn_state, None);
        let mut deferred = configured(None, false);
        deferred.panels_valid = None;
        assert_eq!(probe_state(&deferred, PROBE_TIMEOUT, PROBE_TIMEOUT, net).vpn_state, None);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let hp = listener.local_addr().unwrap().to_string();
        let up = probe_state(&configured(Some(&hp), false), PROBE_TIMEOUT, PROBE_TIMEOUT, net);
        assert_eq!(up.vault_reachable, Some(true));
    }

    #[test]
    fn dot_precedence() {
        let vault = Some("127.0.0.1:8222");
        let s = configured(vault, false);
        assert_eq!(dot_for(&s, None), (Level::Neutral, "checking…"));
        assert_eq!(dot_for(&s, Some(&probe(Some(true), Some(VpnState::NotConfigured)))), (Level::Green, "secure"));
        assert_eq!(dot_for(&s, Some(&probe(Some(false), None))), (Level::Amber, "vault locked"));
        assert_eq!(dot_for(&s, Some(&probe(None, None))), (Level::Amber, "vault unknown"));
        // No vault URL at all is acceptable.
        assert_eq!(dot_for(&configured(None, false), Some(&probe(None, None))), (Level::Green, "secure"));

        let with_vpn = configured(vault, true);
        assert_eq!(dot_for(&with_vpn, Some(&probe(Some(true), Some(VpnState::Offline)))), (Level::Red, "vpn down"));
        assert_eq!(dot_for(&with_vpn, Some(&probe(Some(true), None))), (Level::Amber, "vpn unknown"));
        assert_eq!(dot_for(&with_vpn, Some(&probe(Some(true), Some(VpnState::Online)))), (Level::Green, "secure"));
        // VPN down outranks a locked vault.
        assert_eq!(dot_for(&with_vpn, Some(&probe(Some(false), Some(VpnState::Offline)))), (Level::Red, "vpn down"));
    }

    #[test]
    fn full_check_names_the_single_worst_cause() {
        let vault = Some("127.0.0.1:8222");
        let ok = probe(Some(true), Some(VpnState::Online));
        let pass = full_check(configured(vault, true), ok);
        assert_eq!((pass.overall, pass.first_cause.as_deref()), (Severity::Pass, None));

        let cause = |s: SyncState, p: ProbeState| {
            let c = full_check(s, p);
            (c.overall, c.first_cause.unwrap_or_default())
        };
        assert_eq!(
            cause(configured(vault, true), probe(Some(true), Some(VpnState::Offline))),
            (Severity::Fail, "VPN down".into())
        );
        assert_eq!(
            cause(configured(vault, false), probe(Some(false), None)),
            (Severity::Warn, "vault unreachable".into())
        );
        assert_eq!(
            cause(configured(vault, true), probe(Some(true), None)),
            (Severity::Warn, "VPN state unknown".into())
        );
        let mut no_note = configured(vault, false);
        no_note.vault_note = None;
        assert_eq!(cause(no_note, ok).1, "vault config note not set (using panels.yaml fallback)");
        let unconfigured = sync_state(None, ConfigLoad::Deferred, &env(&[]));
        assert_eq!(cause(unconfigured, probe(None, None)), (Severity::Warn, "not configured — run Setup".into()));
    }

    #[test]
    fn json_document_has_the_reference_keys() {
        let doc = full_check(configured(Some("127.0.0.1:8222"), false), probe(Some(true), None)).to_json();
        let keys: Vec<&str> = doc.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "configured",
                "panels_path",
                "panels_tier",
                "panels_count",
                "panels_valid",
                "config_error",
                "vault_note",
                "vault_url_hostport",
                "vpn_configured",
                "vpn",
                "overall_sync",
                "vault_reachable",
                "vpn_state",
                "overall",
                "first_cause"
            ]
        );
        assert_eq!(doc["overall_sync"], "configured");
        assert_eq!(doc["vpn_state"], Value::Null);
    }
}
