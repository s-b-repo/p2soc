//! `repair`: fix what doctor flags. Every action is a small function that
//! records the command lines it ran (or, in a dry run, would run) and returns
//! a [`CheckResult`]; nothing prompts — the operator's yes/no answers are
//! [`RepairOpts`] flags (all on by default, like the wizard's default answers).

use crate::check::{CheckResult, Report};
use crate::doctor::{is_real_vault, kiosk_user, probe_venv};
use crate::envfile::{SocEnv, load_env_file};
use crate::error::TextResult;
use crate::host::Host;
use crate::paths::{SetupPaths, Target};
use soc_core::{Config, DictExt, model::Mode};
use soc_sys::fsutil;
use soc_sys::run::argv;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

/// Package managers `install.sh --deps-only` understands.
const PACKAGE_MANAGERS: [&str; 6] = ["apt-get", "dnf", "pacman", "zypper", "apk", "xbps-install"];
/// pip / package installs can take a while on a Pi.
const LONG: Duration = Duration::from_secs(1800);

/// The operator's answers and switches.
#[derive(Debug, Clone)]
pub struct RepairOpts {
    /// Recreate the venv when its probe fails.
    pub venv: bool,
    /// Run `install.sh --deps-only` for missing OS packages.
    pub packages: bool,
    /// Generate the restricted tunnel key when it is missing.
    pub tunnel_key: bool,
    pub dry_run: bool,
    /// The installer, run from the release checkout.
    pub install_sh: String,
}

impl Default for RepairOpts {
    fn default() -> RepairOpts {
        RepairOpts { venv: true, packages: true, tunnel_key: true, dry_run: false, install_sh: "./install.sh".into() }
    }
}

/// Everything `repair` reads.
#[derive(Debug, Clone)]
pub struct RepairInputs {
    pub target: Target,
    pub paths: SetupPaths,
    /// The `soc.env` at the write target.
    pub soc_env: SocEnv,
    /// The config at the write target, or why it did not load.
    pub config: TextResult<Config>,
}

impl RepairInputs {
    pub fn load(target: Target, paths: SetupPaths) -> RepairInputs {
        RepairInputs {
            target,
            soc_env: load_env_file(&paths.soc_env),
            config: soc_core::load(&paths.panels_installed).map_err(|e| e.to_string()),
            paths,
        }
    }
}

/// What a repair run did.
#[derive(Debug, Clone, Default)]
pub struct RepairOutcome {
    pub report: Report,
    /// Every command line run, or that would run in a dry run.
    pub cmds: Vec<Vec<String>>,
}

/// The repairer.
#[derive(Debug, Clone)]
pub struct Repair {
    pub inputs: RepairInputs,
    pub opts: RepairOpts,
}

struct Ctx<'a, 'h> {
    host: &'a Host<'h>,
    dry: bool,
    cmds: Vec<Vec<String>>,
}

impl Ctx<'_, '_> {
    /// Record `cmd`, and run it unless this is a dry run. `None` in a dry run.
    fn exec(&mut self, cmd: Vec<String>, timeout: Duration) -> Option<TextResult<i32>> {
        self.cmds.push(cmd.clone());
        if self.dry {
            return None;
        }
        Some(match self.host.runner.run(&cmd, timeout) {
            Ok(o) => Ok(o.code.unwrap_or(-1)),
            Err(e) => Err(e.to_string()),
        })
    }

    fn sudo(&self, mut cmd: Vec<String>) -> Vec<String> {
        if !self.host.probe.is_root() {
            cmd.insert(0, "sudo".into());
        }
        cmd
    }
}

fn verdict(name: &str, what: &str, rc: Option<TextResult<i32>>) -> CheckResult {
    match rc {
        None => CheckResult::ok(name, format!("[dry-run] would run: {what}")),
        Some(Ok(0)) => CheckResult::ok(name, what.to_string()),
        Some(Ok(rc)) => CheckResult::warn(name, format!("`{what}` exited {rc}"), "see the command output above"),
        Some(Err(e)) => CheckResult::warn(name, format!("`{what}` could not run: {e}"), ""),
    }
}

impl Repair {
    pub fn new(inputs: RepairInputs) -> Repair {
        Repair { inputs, opts: RepairOpts::default() }
    }

    pub fn run(&self, host: &Host<'_>) -> RepairOutcome {
        let mut cx = Ctx { host, dry: self.opts.dry_run, cmds: Vec::new() };
        let mut rep = Report::default();
        rep.header.push("   Fixes what doctor flags. Some steps need root/network.".to_string());
        for r in self.venv(&mut cx).into_iter().chain(self.packages(&mut cx)).chain(self.litebw(&cx)) {
            rep.push(r);
        }
        for r in self.secret_dir(&mut cx) {
            rep.push(r);
        }
        if let Some(r) = self.env_perms(&cx) {
            rep.push(r);
        }
        for r in self.tunnel_key(&mut cx) {
            rep.push(r);
        }
        rep.notes.push(format!("   re-run `{} doctor` to confirm.", crate::CLI));
        if self.fresh_box(host) {
            rep.notes.push(format!(
                "   this looks like a fresh box — a full install needs `{} provision` (users + packages + deploy + \
                 vault + seal), not just repair.",
                crate::CLI
            ));
        }
        RepairOutcome { report: rep, cmds: cx.cmds }
    }

    fn fresh_box(&self, host: &Host<'_>) -> bool {
        let k = kiosk_user(&self.inputs.soc_env, None);
        !host.probe.is_dir(Path::new("/opt/soc-display"))
            || ![k.as_str(), "socwall", "socsvc"].iter().any(|u| host.probe.user_exists(u))
    }

    /// 1) venv + python deps (legacy Python host).
    fn venv(&self, cx: &mut Ctx<'_, '_>) -> Vec<CheckResult> {
        let root = &self.inputs.paths.soc_root;
        let venv = root.join(".venv");
        let py = venv.join("bin").join("python");
        let name = "venv + Python deps";
        if probe_venv(name, &py, cx.host).status == crate::check::Status::Ok || !self.opts.venv {
            return Vec::new();
        }
        let py_s = py.display().to_string();
        let steps: Vec<(Vec<String>, &str)> = vec![
            (
                vec![
                    "python3".into(),
                    "-m".into(),
                    "venv".into(),
                    "--system-site-packages".into(),
                    venv.display().to_string(),
                ],
                "create the venv",
            ),
            (
                vec![
                    py_s.clone(),
                    "-m".into(),
                    "pip".into(),
                    "install".into(),
                    "-q".into(),
                    "--upgrade".into(),
                    "pip".into(),
                ],
                "upgrade pip",
            ),
            (
                vec![
                    py_s.clone(),
                    "-m".into(),
                    "pip".into(),
                    "install".into(),
                    "-q".into(),
                    "PyYAML".into(),
                    "websocket-client".into(),
                ],
                "install PyYAML + websocket-client",
            ),
            // cryptography is a Rust extension: wheel-only so repair never starts a
            // rustc+cc sdist build that OOM-kills the 1 GB Pi.
            (
                vec![
                    py_s,
                    "-m".into(),
                    "pip".into(),
                    "install".into(),
                    "-q".into(),
                    "--only-binary=:all:".into(),
                    "cryptography".into(),
                ],
                "install cryptography (wheel only)",
            ),
        ];
        steps
            .into_iter()
            .map(|(cmd, what)| {
                let rc = cx.exec(cmd, LONG);
                verdict(&format!("venv: {what}"), &venv.display().to_string(), rc)
            })
            .collect()
    }

    /// 2) OS packages via the installer's deps-only mode.
    fn packages(&self, cx: &mut Ctx<'_, '_>) -> Vec<CheckResult> {
        if !PACKAGE_MANAGERS.iter().any(|p| cx.host.probe.have(p)) || !self.opts.packages {
            return Vec::new();
        }
        let cmd = cx.sudo(vec![self.opts.install_sh.clone(), "--deps-only".into()]);
        let what = cmd.join(" ");
        let rc = cx.exec(cmd, LONG);
        vec![verdict("OS packages", &what, rc)]
    }

    /// 3) litebw needs no compile; install.sh puts the launcher on PATH.
    fn litebw(&self, cx: &Ctx<'_, '_>) -> Vec<CheckResult> {
        if cx.host.probe.have("litebw") {
            return Vec::new();
        }
        vec![CheckResult::warn("litebw", "litebw is not on PATH", "install.sh deploys it to /usr/local/bin/litebw")]
    }

    /// 3b) sealed-secret dir + the client's pinentry.
    fn secret_dir(&self, cx: &mut Ctx<'_, '_>) -> Vec<CheckResult> {
        let i = &self.inputs;
        let backend = i.soc_env.get("SOC_VAULT_BACKEND").map_or(i.paths.default_backend.as_str(), String::as_str);
        if !is_real_vault(backend) {
            return Vec::new();
        }
        let sd = &i.paths.secret_dir;
        let mut out = Vec::new();
        if cx.dry {
            out.push(CheckResult::ok("secret dir", format!("[dry-run] would create {} (0700)", sd.display())));
        } else {
            let made =
                fsutil::ensure_dir(sd, 0o700).and_then(|()| fs::set_permissions(sd, fs::Permissions::from_mode(0o700)));
            out.push(match made {
                Ok(()) => CheckResult::ok("secret dir", format!("secret dir {} (0700)", sd.display())),
                Err(e) => CheckResult::warn("secret dir", format!("could not create {}: {e}", sd.display()), ""),
            });
        }
        if cx.host.probe.have(backend) {
            let cmd = vec![
                backend.to_string(),
                "config".into(),
                "set".into(),
                "pinentry".into(),
                i.paths.pinentry.display().to_string(),
            ];
            let rc = cx.exec(cmd, Duration::from_secs(30));
            out.push(verdict(&format!("{backend} pinentry"), "pinentry -> pinentry-vault.sh", rc));
        }
        out
    }

    /// Step 4: soc.env 0644 (non-secret) so the desktop/kiosk user can source it;
    /// 0640 would re-break desktop-mode vault unlock.
    fn env_perms(&self, cx: &Ctx<'_, '_>) -> Option<CheckResult> {
        let f = &self.inputs.paths.soc_env;
        if !cx.host.probe.exists(f) {
            return None;
        }
        let name = "perms soc.env";
        if !cx.host.probe.is_root() && self.inputs.target == Target::Pi {
            return Some(CheckResult::warn(name, format!("(need root to chmod {})", f.display()), ""));
        }
        if cx.dry {
            return Some(CheckResult::ok(name, format!("[dry-run] would chmod 644 {}", f.display())));
        }
        Some(match fs::set_permissions(f, fs::Permissions::from_mode(0o644)) {
            Ok(()) => CheckResult::ok(
                name,
                format!("chmod 644 {}", f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()), // audit-allow: a path with no file name shows as empty
            ),
            Err(e) => CheckResult::warn(name, format!("could not chmod {}: {e}", f.display()), ""),
        })
    }

    /// 5) the restricted tunnel key.
    fn tunnel_key(&self, cx: &mut Ctx<'_, '_>) -> Vec<CheckResult> {
        let name = "tunnel key";
        let conf = match &self.inputs.config {
            Ok(c) => c,
            Err(e) => return vec![CheckResult::ok(name, format!("(skipping tunnel-key step: {e})"))],
        };
        let ident = conf.tunnel.text("identity");
        let tunneled = conf.panels.iter().any(|p| p.mode == Mode::Tunnel) && conf.tunnel.flag("enabled", true);
        if !tunneled || ident.is_empty() || !self.opts.tunnel_key {
            return Vec::new();
        }
        let ident = cx.host.probe.expand_user(&ident);
        if cx.host.probe.exists(Path::new(&ident)) {
            return Vec::new();
        }
        if !cx.dry {
            if let Some(dir) = Path::new(&ident).parent() {
                if let Err(e) = fsutil::ensure_dir(dir, 0o700) {
                    return vec![CheckResult::warn(name, format!("could not create {}: {e}", dir.display()), "")];
                }
            }
        }
        let cmd = argv(&["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "soc-wall-tunnel", "-f", &ident]);
        let rc = cx.exec(cmd, Duration::from_secs(60));
        let mut out = vec![verdict(name, &format!("generate {ident}"), rc)];
        if !cx.dry {
            let _ = fs::set_permissions(&ident, fs::Permissions::from_mode(0o600)); // audit-allow: best effort, as in the original; ssh-keygen already writes 0600
        }
        let jump = conf.tunnel.text("jump_host");
        let jump = if jump.is_empty() { "<jump-host>".to_string() } else { jump };
        out.push(CheckResult::ok(
            "tunnel key authorization",
            format!(
                "add the public key to {jump}'s authorized_keys with a restriction, e.g.: \
                 restrict,permitopen=\"HOST:PORT\",command=\"/usr/sbin/nologin\" $(cat {ident}.pub)"
            ),
        ));
        out
    }
}
