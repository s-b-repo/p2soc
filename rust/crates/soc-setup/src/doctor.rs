//! `doctor`: diagnose an install. Each check is a small function from the
//! gathered inputs and the [`Host`] to a [`CheckResult`]; [`Doctor::run`] runs
//! them in the original order and aggregates.

use crate::check::{CheckResult, Report};
use crate::envfile::{SocEnv, load_env_file};
use crate::error::TextResult;
use crate::host::{Host, Probe};
use crate::paths::{SetupPaths, Target};
use crate::util::CMD_TIMEOUT;
use soc_core::vpnargs::{inode_script, vpn_kind};
use soc_core::{Config, DictExt, model::Mode, model::VpnKind};
use soc_sys::paths::{Kind, PathEnv};
use soc_sys::run::argv;
use std::path::{Path, PathBuf};

/// What the legacy Python venv must import (kept for boxes still running the
/// Python host; the Rust host has no such dependency, see `Doctor::check_venv`).
pub const VENV_PROBE: &str = "import yaml, websocket, gi\n\
gi.require_version('Gtk','3.0')\n\
from gi.repository import Gtk\n\
ok=False\n\
for v in ('4.1','4.0'):\n\
  try:\n\
    gi.require_version('WebKit2', v); from gi.repository import WebKit2; ok=True; break\n\
  except Exception: pass\n\
assert ok, 'WebKit2 typelib missing'\n\
print('ok')\n";

const SUDOERS_DROPIN: &str = "/etc/sudoers.d/soc-wall-restart";

/// Everything `doctor` reads, gathered once so the checks stay pure.
#[derive(Debug, Clone)]
pub struct DoctorInputs {
    pub target: Target,
    /// The write locations (`soc_env` is the permission-checked file).
    pub paths: SetupPaths,
    /// The `soc.env` the wall actually reads, and why.
    pub env_read: (PathBuf, String),
    /// The `panels.yaml` the wall actually reads, and why.
    pub panels_read: (PathBuf, String),
    pub soc_env: SocEnv,
    /// The parsed config, or the load error text.
    pub config: TextResult<Config>,
    /// `$SOC_KIOSK_USER` of the running process.
    pub process_kiosk_user: Option<String>,
    /// The checkout, for the venv fallback.
    pub repo_root: PathBuf,
}

impl DoctorInputs {
    /// Gather the inputs from the machine, resolving what the wall reads with
    /// the shared resolver (so a write/read mismatch surfaces).
    pub fn load(target: Target, penv: &PathEnv, paths: SetupPaths) -> DoctorInputs {
        let env_read = penv
            .resolve_read(Kind::Env)
            .map_or((paths.soc_env.clone(), "write target".to_string()), |c| (c.path, c.label));
        let panels_read = penv
            .resolve_read(Kind::Panels)
            .map_or((paths.panels_installed.clone(), "write target".to_string()), |c| (c.path, c.label));
        let config = soc_core::load(&panels_read.0).map_err(|e| e.to_string());
        DoctorInputs {
            target,
            soc_env: load_env_file(&env_read.0),
            env_read,
            panels_read,
            config,
            process_kiosk_user: std::env::var("SOC_KIOSK_USER").ok().filter(|v| !v.is_empty()),
            repo_root: penv.repo_root(),
            paths,
        }
    }
}

/// The doctor.
#[derive(Debug, Clone)]
pub struct Doctor {
    pub inputs: DoctorInputs,
    /// Probe the legacy Python venv (the first check). Off for a pure-Rust host.
    pub check_venv: bool,
}

impl Doctor {
    pub fn new(inputs: DoctorInputs) -> Doctor {
        Doctor { inputs, check_venv: true }
    }

    /// Run every check and aggregate.
    pub fn run(&self, host: &Host<'_>) -> Report {
        let i = &self.inputs;
        let mut rep = Report::default();
        rep.header.push(format!(
            "   target {}   soc.env {} ({})",
            i.target.as_str(),
            i.env_read.0.display(),
            i.env_read.1
        ));
        rep.header.push(format!("   panels {} ({})", i.panels_read.0.display(), i.panels_read.1));
        // If the write target differs from what the wall reads, say so loudly.
        if i.panels_read.0 != i.paths.panels_installed {
            rep.header.push(format!(
                "  ! the wall reads {} but the wizard would write {} — run `soc-wall configpaths --explain`",
                i.panels_read.0.display(),
                i.paths.panels_installed.display()
            ));
        }
        if self.check_venv {
            rep.push(check_venv(i, host));
        }
        let backend =
            i.soc_env.get("SOC_VAULT_BACKEND").map_or(i.paths.default_backend.as_str(), String::as_str).to_string();
        rep.push(check_litebw(&backend, host.probe));
        if backend == "rbw" {
            rep.push(check_rbw(host.probe));
        }
        let session = i.soc_env.get("SOC_SESSION").map_or("auto", String::as_str);
        rep.push(check_display(session, host.probe));
        for r in check_config(i, host.probe) {
            rep.push(r);
        }
        if is_real_vault(&backend) {
            let url = i.soc_env.get("SOC_VAULT_URL").map_or("http://127.0.0.1:8222", String::as_str);
            rep.push(check_vault_reachable(url, host.probe));
            rep.push(check_master_source(&i.soc_env, host));
            let item = i.soc_env.get("SOC_CONFIG_VAULT_ITEM").map_or("SOC Wall Config", String::as_str);
            rep.push(CheckResult::ok("config source", format!("vault note '{item}' (local file fallback)")));
        }
        if let Some(r) = check_env_perms(&i.paths.soc_env, host.probe) {
            rep.push(r);
        }
        for r in check_units(host) {
            rep.push(r);
        }
        if host.probe.have("sudo") {
            rep.push(check_sudoers(i, host));
        }
        if fresh_box(i, host.probe) {
            rep.notes
                .push("  ! this box is not fully installed yet (missing users and/or /opt/soc-display)".to_string());
            rep.notes.push(format!(
                "   run: {} provision  (full install: users + packages + deploy + vault + seal)",
                crate::CLI
            ));
            rep.notes.push(format!("   or:  {} provision --dry-run   (preview, changes nothing)", crate::CLI));
        }
        rep
    }
}

/// `rbw`, `litebw` and the native client are real vault backends; `dev` is not.
pub fn is_real_vault(backend: &str) -> bool {
    matches!(backend, "rbw" | "litebw" | "native")
}

/// The kiosk account named by `soc.env`, the process env, or `soc`.
pub fn kiosk_user(env: &SocEnv, process: Option<&str>) -> String {
    env.get("SOC_KIOSK_USER")
        .filter(|v| !v.is_empty())
        .cloned()
        .or_else(|| process.map(str::to_string))
        .unwrap_or_else(|| "soc".to_string())
}

/// True when the kiosk/desktop/service users or `/opt/soc-display` are missing:
/// `repair` only patches an existing install, so the operator is steered to the
/// full install.
pub fn fresh_box(i: &DoctorInputs, probe: &dyn Probe) -> bool {
    let k = kiosk_user(&i.soc_env, None);
    let no_users = ![k.as_str(), "socwall", "socsvc"].iter().any(|u| probe.user_exists(u));
    no_users || !probe.is_dir(Path::new("/opt/soc-display"))
}

pub fn check_venv(i: &DoctorInputs, host: &Host<'_>) -> CheckResult {
    let name = "venv + Python deps";
    let in_root = i.paths.soc_root.join(".venv/bin/python");
    let py = if host.probe.exists(&in_root) { in_root } else { i.repo_root.join(".venv/bin/python") };
    probe_venv(name, &py, host)
}

/// Run the import probe under `py`.
pub fn probe_venv(name: &str, py: &Path, host: &Host<'_>) -> CheckResult {
    let args = vec![py.display().to_string(), "-c".to_string(), VENV_PROBE.to_string()];
    match host.runner.run(&args, CMD_TIMEOUT) {
        Err(e) => CheckResult::fail(name, format!("venv python not runnable ({e})"), "run: setup.py repair"),
        Ok(out) if out.success() && out.stdout.contains("ok") => {
            CheckResult::ok(name, "venv + gi/WebKit2/yaml/websocket import")
        }
        Ok(out) => CheckResult::fail(
            name,
            out.stderr.trim().lines().last().unwrap_or("import error").to_string(),
            "run: setup.py repair  (recreates venv --system-site-packages + deps)",
        ),
    }
}

pub fn check_litebw(backend: &str, probe: &dyn Probe) -> CheckResult {
    let name = "litebw (Vaultwarden client)";
    if probe.have("litebw") {
        return CheckResult::ok(name, "on PATH");
    }
    let fix = "deployed to /usr/local/bin/litebw by install.sh";
    if backend == "litebw" {
        CheckResult::fail(name, "not installed", fix)
    } else {
        CheckResult::warn(name, "not installed", fix)
    }
}

pub fn check_rbw(probe: &dyn Probe) -> CheckResult {
    let name = "rbw (Vaultwarden CLI)";
    if probe.have("rbw") {
        CheckResult::ok(name, "on PATH")
    } else {
        CheckResult::fail(name, "not installed", "cargo install rbw  (or your package manager)")
    }
}

pub fn check_display(session: &str, probe: &dyn Probe) -> CheckResult {
    let name = format!("display stack (SOC_SESSION={session})");
    let wl = probe.have("cage") || probe.have("labwc");
    let x = probe.have("Xorg") || probe.have("X") || probe.have("Xlibre");
    match session {
        "wayland" | "xwayland" if wl => CheckResult::ok(name, "compositor present"),
        "wayland" | "xwayland" => CheckResult::fail(name, "no Wayland compositor", "install labwc or cage"),
        "xorg" | "xlibre" | "x11" if x => CheckResult::ok(name, "X server present"),
        "xorg" | "xlibre" | "x11" => CheckResult::fail(name, "no X server", "install xorg/xlibre + xinit + openbox"),
        _ if wl || x => CheckResult::ok(name, format!("available (wayland={} x11={})", py_bool(wl), py_bool(x))),
        _ => CheckResult::fail(name, "no display stack", "install labwc/cage or xorg"),
    }
}

fn py_bool(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

/// `panels.yaml parses`, the per-VPN client checks and the tunnel checks.
pub fn check_config(i: &DoctorInputs, probe: &dyn Probe) -> Vec<CheckResult> {
    let name = "panels.yaml parses";
    let conf = match &i.config {
        Ok(c) => c,
        Err(e) => {
            return vec![CheckResult::fail(name, e.clone(), "fix the config / run the wizard: setup.py")];
        }
    };
    let mut out = Vec::new();
    let warnings =
        if conf.warnings.is_empty() { String::new() } else { format!(", {} warning(s)", conf.warnings.len()) };
    out.push(CheckResult::ok(name, format!("{} panels{warnings}", conf.panels.len())));
    // Every VPN, not just the primary: a missing client for the 3rd is caught.
    for vpn in conf.enabled_vpns() {
        let kind = vpn_kind(vpn);
        let nm = Some(vpn.text("name")).filter(|n| !n.is_empty()).unwrap_or_else(|| "vpn".to_string());
        if kind == VpnKind::Inode {
            let home = std::env::var_os("HOME").map(PathBuf::from);
            let script = inode_script(vpn, &i.paths.soc_root, home.as_deref());
            let label = format!("iNode client (svpn-connect.sh) [{nm}]");
            out.push(if probe.is_exec_file(&script) {
                CheckResult::ok(label, script.display().to_string())
            } else {
                CheckResult::fail(
                    label,
                    format!("missing/not executable: {}", script.display()),
                    "ship vendor/iNode-VPN-Client or set vpn.config",
                )
            });
            let label = format!("tesseract (iNode login CAPTCHA) [{nm}]");
            out.push(if probe.have("tesseract") {
                CheckResult::ok(label, "on PATH")
            } else {
                CheckResult::warn(
                    label,
                    "not installed",
                    "install tesseract-ocr — the gateway CAPTCHA cannot be auto-solved without it",
                )
            });
        } else {
            let need = match kind {
                VpnKind::Openvpn => "openvpn",
                VpnKind::Wireguard => "wg-quick",
                _ => "openfortivpn",
            };
            let label = format!("VPN client ({kind}) [{nm}]");
            out.push(if probe.have(need) {
                CheckResult::ok(label, format!("{need} present"))
            } else {
                CheckResult::fail(label, format!("{need} not installed"), format!("install {need} (setup.py repair)"))
            });
        }
    }
    // autossh tunnel: the binary + the restricted key (when panels are tunneled).
    if conf.panels.iter().any(|p| p.mode == Mode::Tunnel) && conf.tunnel.flag("enabled", true) {
        out.push(if probe.have("autossh") {
            CheckResult::ok("autossh (SSH jump-host tunnel)", "on PATH")
        } else {
            CheckResult::fail(
                "autossh (SSH jump-host tunnel)",
                "not installed",
                "install autossh (setup.py repair / install.sh)",
            )
        });
        let ident = conf.tunnel.text("identity");
        let present = !ident.is_empty() && probe.exists(Path::new(&probe.expand_user(&ident)));
        out.push(if present {
            CheckResult::ok("tunnel identity key", ident)
        } else {
            CheckResult::fail(
                "tunnel identity key",
                format!("missing: {}", if ident.is_empty() { "(unset)" } else { ident.as_str() }),
                "setup.py repair  (generates a restricted ed25519 key)",
            )
        });
    }
    out
}

pub fn check_vault_reachable(url: &str, probe: &dyn Probe) -> CheckResult {
    let name = "Vaultwarden reachable";
    if probe.alive(url) {
        CheckResult::ok(name, url)
    } else {
        CheckResult::warn(name, format!("{url} not answering /alive"), "start it: systemctl start vaultwarden")
    }
}

/// The vault master source: never a plaintext `.env`, ever.
pub fn check_master_source(env: &SocEnv, host: &Host<'_>) -> CheckResult {
    let name = "vault master password source";
    let sec = env.get("SOC_SECRET_DIR").filter(|v| !v.is_empty()).map_or("/etc/soc-display/secret", String::as_str);
    let sec_path = Path::new(sec);
    let active = env.get("SOC_MASTER_SOURCE").map_or("auto", String::as_str);
    // A plaintext master in soc.env is a FAIL regardless of source.
    if env.get("SOC_VAULT_PASSWORD").is_some_and(|v| !v.is_empty()) {
        return CheckResult::fail(
            name,
            "plaintext SOC_VAULT_PASSWORD present in soc.env",
            "remove that line, then: setup.py first-run",
        );
    }
    let sources = host.seal.available_sources(sec_path);
    let avail = if sources.is_empty() { "(none)".to_string() } else { sources.join(", ") };
    let sealed = host.seal.is_sealed(sec_path);
    // secret-service: explicit choice, or auto with a wallet but no seal.
    let want_ss = active == "secret-service" || (active == "auto" && host.seal.have_secret_tool() && !sealed);
    if want_ss {
        if !host.seal.have_secret_tool() {
            return CheckResult::fail(
                name,
                "source=secret-service but secret-tool not on PATH",
                "install libsecret-tools / libsecret, or: setup.py first-run",
            );
        }
        return if host.seal.secret_service_get().is_some() {
            CheckResult::ok(name, format!("secret-service: item found (source={active}; avail: {avail})"))
        } else {
            CheckResult::warn(
                name,
                format!("secret-service: no item / wallet locked (avail: {avail})"),
                "secret-tool store service soc-wall account vault-master  (and unlock the wallet)",
            )
        };
    }
    // sealed (default for unattended) — explicit or auto.
    if sealed {
        return match host.seal.unseal(sec_path) {
            Ok(_) => CheckResult::ok(name, format!("sealed + unseals on this host ({sec}; source={active})")),
            Err(e) => CheckResult::fail(
                name,
                format!("sealed but cannot unseal ({e}) — machine-id changed?"),
                "re-run: setup.py first-run  (re-seal with your PIN)",
            ),
        };
    }
    CheckResult::fail(
        name,
        format!("no master source ready (source={active}; avail: {avail})"),
        "run: setup.py first-run  (choose sealed or secret-service)",
    )
}

/// `soc.env` is non-secret (the master is sealed separately) and 0644 so the
/// desktop/kiosk user can source it; the ceiling allows 0644.
pub fn check_env_perms(soc_env: &Path, probe: &dyn Probe) -> Option<CheckResult> {
    let mode = probe.mode(soc_env)?;
    let name = format!("perms {}", soc_env.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()); // audit-allow: a path with no file name shows as empty
    let shown = format!("0o{mode:o}");
    Some(if mode <= 0o644 {
        CheckResult::ok(name, shown)
    } else {
        CheckResult::warn(name, shown, format!("chmod 644 {}", soc_env.display()))
    })
}

/// systemd units, when systemd is running.
pub fn check_units(host: &Host<'_>) -> Vec<CheckResult> {
    if !host.probe.systemd_running() {
        return Vec::new();
    }
    ["vaultwarden", "forti-vpn", "autossh-tunnel"]
        .iter()
        .map(|u| {
            let state = host
                .runner
                .run(&argv(&["systemctl", "is-active", u]), CMD_TIMEOUT)
                .map(|o| o.stdout.trim().to_string())
                .ok() // audit-allow: a missing systemctl is reported as state "unknown"
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown".to_string());
            let name = format!("unit {u}");
            if state == "active" {
                CheckResult::ok(name, state)
            } else {
                CheckResult::warn(name, state, format!("systemctl status {u}"))
            }
        })
        .collect()
}

/// The sudoers drop-in that lets the unprivileged kiosk user restart the
/// tunnel units. Reports presence and, when testable, whether the rule
/// actually resolves for the kiosk user.
pub fn check_sudoers(i: &DoctorInputs, host: &Host<'_>) -> CheckResult {
    let name = "reconnect sudoers rule";
    let dropin = SUDOERS_DROPIN;
    if !host.probe.exists(Path::new(dropin)) {
        return CheckResult::warn(
            name,
            format!("{dropin} not present"),
            "install.sh installs it (visudo-validated); the reconnect button falls back to a PENDING-restart message without it",
        );
    }
    let kiosk = kiosk_user(&i.soc_env, i.process_kiosk_user.as_deref());
    let mut probe = argv(&["sudo", "-n", "-l", "/usr/bin/systemctl", "restart", "forti-vpn.service"]);
    // As root, probe THROUGH the kiosk user so the rule is tested, not root's
    // blanket privileges.
    if host.probe.is_root() && host.probe.current_user() != kiosk {
        let exists = host.runner.run(&argv(&["id", "-u", &kiosk]), CMD_TIMEOUT).is_ok_and(|o| o.success());
        if !exists {
            return CheckResult::ok(name, format!("{dropin} present (kiosk user '{kiosk}' not created yet)"));
        }
        probe = argv(&["sudo", "-u", &kiosk, "-n", "-l", "/usr/bin/systemctl", "restart", "forti-vpn.service"]);
    }
    match host.runner.run(&probe, CMD_TIMEOUT) {
        Err(e) => CheckResult::warn(name, format!("present but probe failed ({e})"), ""),
        Ok(o) if o.success() => CheckResult::ok(name, format!("{dropin} present; sudo -n systemctl restart works")),
        Ok(_) => CheckResult::warn(
            name,
            format!("{dropin} present but `sudo -n systemctl restart` denied for '{kiosk}'"),
            "visudo -c /etc/sudoers.d/soc-wall-restart; check the user field matches your kiosk user",
        ),
    }
}
