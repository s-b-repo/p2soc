//! The end-to-end deploy as a plan of typed steps:
//! install -> write config -> vault up -> account -> seal -> push config ->
//! store logins -> doctor -> mark configured -> activate.
//!
//! Inputs are arguments (master, logins, e-mail, ...); a step that cannot run
//! without one it was not given reports why instead of guessing. Every step is
//! dry-run aware: it records the commands it would run and changes nothing.

use crate::check::Report;
use crate::config::{render_panels_yaml, vault_items};
use crate::doctor::{Doctor, DoctorInputs, is_real_vault, kiosk_user};
use crate::envfile::{SocEnv, load_env_file, render_soc_env};
use crate::error::TextResult;
use crate::host::Host;
use crate::paths::{SetupPaths, Target, drop_marker, mark_configured, write_file};
use crate::seal::{SealRequest, already_sealed, seal_master};
use crate::step::StepResult;
use crate::unit::{UnitOpts, render_wall_unit};
use crate::vault::{Creds, LoginJob, ensure_account, push_config_to_vault, write_logins};
use soc_core::{Config, DictExt, Mode};
use soc_seal::MasterSource;
use soc_sys::paths::PathEnv;
use soc_sys::run::argv;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PACKAGE_MANAGERS: [&str; 6] = ["apt-get", "dnf", "pacman", "zypper", "apk", "xbps-install"];
const INSTALL_TIMEOUT: Duration = Duration::from_secs(3600);
const CMD: Duration = Duration::from_secs(60);

/// One step of the deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployStep {
    InstallOs,
    WriteConfig,
    VaultUp,
    VaultAccount,
    Seal,
    PushConfig,
    StoreLogins,
    Doctor,
    MarkConfigured,
    Activate,
}

impl DeployStep {
    pub const ALL: [DeployStep; 10] = [
        DeployStep::InstallOs,
        DeployStep::WriteConfig,
        DeployStep::VaultUp,
        DeployStep::VaultAccount,
        DeployStep::Seal,
        DeployStep::PushConfig,
        DeployStep::StoreLogins,
        DeployStep::Doctor,
        DeployStep::MarkConfigured,
        DeployStep::Activate,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            DeployStep::InstallOs => "install",
            DeployStep::WriteConfig => "write_config",
            DeployStep::VaultUp => "vault_running",
            DeployStep::VaultAccount => "vault_account",
            DeployStep::Seal => "seal",
            DeployStep::PushConfig => "push_config",
            DeployStep::StoreLogins => "vault_seed",
            DeployStep::Doctor => "doctor",
            DeployStep::MarkConfigured => "mark_configured",
            DeployStep::Activate => "activate",
        }
    }
}

/// A step in the plan with whether it will do anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    pub step: DeployStep,
    pub title: String,
    /// False when the step will be a no-op (and `why` says why).
    pub needed: bool,
    pub why: String,
}

/// The deploy inputs.
pub struct DeployPlan {
    pub target: Target,
    pub penv: PathEnv,
    pub paths: SetupPaths,
    pub dry_run: bool,
    /// Force a full OS reinstall even when already installed.
    pub fresh: bool,
    /// Never wait for a human: needs root, a real vault account and a master.
    pub unattended: bool,
    /// `INSTALL_MODE` for install.sh (`auto|kiosk|desktop`).
    pub mode: Option<String>,
    pub install_sh: String,
    pub email: String,
    pub url: String,
    pub pin: Option<String>,
    /// The vault master. Never serialised, wiped on drop.
    pub master: Option<Zeroizing<String>>,
    /// Logins to write (`--creds-fd` in the Python tool).
    pub creds: Creds,
    /// Seed an empty placeholder for every configured login that is missing.
    pub seed: bool,
    pub soc_env: SocEnv,
    pub cfg: Config,
    /// An explicitly supplied, validated YAML document. Preserve its comments and keys.
    pub config_source: Option<String>,
    /// Render and write `soc.env` / the unit (and `panels.yaml` unless
    /// `keep_panels`). Off when the files were installed by other means.
    pub write_config: bool,
    /// `panels.yaml` is final: install nothing over it, push it as written.
    pub keep_panels: bool,
    /// Include the legacy Python-venv probe in the closing doctor run.
    pub check_venv: bool,
    pub user: String,
    /// How long to wait for the vault to answer `/alive`.
    pub vault_wait: Duration,
    /// The manifest `install.sh` records the resolved mode in.
    pub install_manifest: PathBuf,
}

impl DeployPlan {
    /// A plan with the Python tool's defaults.
    pub fn new(target: Target, penv: PathEnv, paths: SetupPaths) -> DeployPlan {
        let soc_env = load_env_file(&paths.soc_env);
        let install_manifest = penv.etc_dir().join(".install-manifest");
        let cfg = crate::config::previous_config(&paths.panels_installed);
        DeployPlan {
            target,
            penv,
            paths,
            dry_run: false,
            fresh: false,
            unattended: false,
            mode: None,
            install_sh: "./install.sh".into(),
            email: String::new(),
            url: "http://127.0.0.1:8222".into(),
            pin: None,
            master: None,
            creds: Creds::new(),
            seed: true,
            soc_env,
            cfg,
            config_source: None,
            write_config: false,
            keep_panels: false,
            check_venv: false,
            user: "soc".into(),
            vault_wait: Duration::from_secs(20),
            install_manifest,
        }
    }

    fn backend(&self) -> String {
        self.soc_env
            .get("SOC_VAULT_BACKEND")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| self.paths.default_backend.clone())
    }

    fn is_vault(&self) -> bool {
        is_real_vault(&self.backend())
    }

    /// Whether the OS install already happened: the stamp, or a venv + config.
    fn installed(&self, host: &Host<'_>) -> bool {
        host.probe.exists(&self.paths.install_stamp())
            || (host.probe.exists(&self.paths.soc_root.join(".venv"))
                && host.probe.exists(&self.paths.panels_installed))
    }

    /// Refuse an unattended deploy that would have to guess.
    pub fn validate(&self, host: &Host<'_>) -> TextResult<()> {
        if !self.unattended {
            return Ok(());
        }
        if !host.probe.is_root() {
            return Err("deploy --unattended needs root".into());
        }
        if self.master.as_ref().is_none_or(|m| m.is_empty()) {
            return Err("deploy --unattended needs the vault master on stdin / --master-fd (never argv)".into());
        }
        if self.email.is_empty() || self.email == "kiosk@soc.local" {
            return Err("deploy --unattended needs a real vault account: pass --email".into());
        }
        Ok(())
    }

    /// The plan: every step, with whether it will do anything.
    pub fn steps(&self, host: &Host<'_>) -> Vec<PlannedStep> {
        let vault = self.is_vault();
        let has_master = self.master.as_ref().is_some_and(|m| !m.is_empty());
        let has_pm = PACKAGE_MANAGERS.iter().any(|p| host.probe.have(p));
        let installed = self.installed(host);
        DeployStep::ALL
            .iter()
            .map(|&step| {
                let (title, needed, why): (&str, bool, &str) = match step {
                    DeployStep::InstallOs if !has_pm => {
                        ("install OS packages + services (install.sh)", false, "no known package manager")
                    }
                    DeployStep::InstallOs if self.fresh || !installed => {
                        ("install OS packages + services (install.sh)", true, "")
                    }
                    DeployStep::InstallOs => (
                        "install OS packages + services (install.sh)",
                        false,
                        "already installed; use --fresh to force",
                    ),
                    DeployStep::WriteConfig => (
                        "render + write panels.yaml / soc.env / wall unit",
                        self.write_config,
                        "files already in place",
                    ),
                    DeployStep::VaultUp => {
                        ("start Vaultwarden and wait for /alive", vault, "dev vault backend; no server needed")
                    }
                    DeployStep::VaultAccount => (
                        "ensure the Vaultwarden account exists",
                        vault && has_master && !self.email.is_empty(),
                        "needs a vault backend, a master and an e-mail",
                    ),
                    DeployStep::Seal => (
                        "seal the master password host-bound",
                        vault && has_master,
                        "needs a vault backend and a master",
                    ),
                    DeployStep::PushConfig => (
                        "push the wall config into the vault",
                        vault && !self.cfg.panels.is_empty(),
                        "dev backend or no panels",
                    ),
                    DeployStep::StoreLogins => (
                        "store the panel logins in the vault",
                        vault && has_master && !self.cfg.panels.is_empty() && (self.seed || !self.creds.is_empty()),
                        "needs a vault backend, a master and panels",
                    ),
                    DeployStep::Doctor => ("health check (doctor)", true, ""),
                    DeployStep::MarkConfigured => ("mark the host configured", true, ""),
                    DeployStep::Activate => ("start the wall", self.target == Target::Pi, "dev target"),
                };
                PlannedStep { step, title: title.into(), needed, why: if needed { String::new() } else { why.into() } }
            })
            .collect()
    }

    fn sudo(&self, host: &Host<'_>, mut cmd: Vec<String>) -> Vec<String> {
        if !host.probe.is_root() {
            cmd.insert(0, "sudo".into());
        }
        cmd
    }

    fn master_str(&self) -> &str {
        self.master.as_ref().map_or("", |m| m.as_str())
    }

    /// Run one step.
    pub fn run_step(&self, step: DeployStep, host: &Host<'_>, st: &mut DeployState) -> StepResult {
        match step {
            DeployStep::InstallOs => self.install(host, st),
            DeployStep::WriteConfig => self.write_config_step(st),
            DeployStep::VaultUp => self.vault_up(host, st),
            DeployStep::VaultAccount => {
                if self.master_str().is_empty() {
                    return StepResult::ok("no master provided — skipping account create/verify");
                }
                ensure_account(host, &self.url, &self.email, self.master_str(), self.dry_run)
            }
            DeployStep::Seal => self.seal(host, st),
            DeployStep::PushConfig => {
                let raw = if self.dry_run { None } else { std::fs::read_to_string(&self.paths.panels_installed).ok() }; // audit-allow: no file just means the config is rendered instead
                let m = Some(self.master_str()).filter(|m| !m.is_empty());
                push_config_to_vault(
                    host,
                    &st.soc_env,
                    &self.paths.config_vault_item,
                    &self.cfg,
                    raw.as_deref(),
                    m,
                    self.dry_run,
                )
            }
            DeployStep::StoreLogins => {
                let items = vault_items(&self.cfg);
                if items.is_empty() || !self.is_vault() {
                    return StepResult::ok("no panel logins to seed");
                }
                if self.master_str().is_empty() {
                    return StepResult::ok("no master provided — skipping login storage");
                }
                let url =
                    st.soc_env.get("SOC_VAULT_URL").filter(|v| !v.is_empty()).map_or(self.url.as_str(), String::as_str);
                let email = st
                    .soc_env
                    .get("SOC_VAULT_EMAIL")
                    .filter(|v| !v.is_empty())
                    .map_or(self.email.as_str(), String::as_str);
                write_logins(
                    host,
                    &LoginJob {
                        url,
                        email,
                        master: self.master_str(),
                        items: &items,
                        creds: &self.creds,
                        placeholders: self.seed,
                        dry: self.dry_run,
                    },
                )
            }
            DeployStep::Doctor => {
                let inputs = DoctorInputs::load(self.target, &self.penv, self.paths.clone());
                let mut doctor = Doctor::new(inputs);
                doctor.check_venv = self.check_venv;
                let report = doctor.run(host);
                let (fails, warns) = (report.fails(), report.warns());
                st.doctor = Some(report);
                if self.dry_run {
                    // Nothing was changed, so the findings describe the box BEFORE the deploy.
                    StepResult::ok(format!("[dry-run] current state: {fails} problem(s), {warns} warning(s)"))
                } else if fails == 0 {
                    StepResult::ok(format!("all good ({warns} warning(s))"))
                } else {
                    StepResult::failed(format!("{fails} problem(s), {warns} warning(s)"))
                }
            }
            DeployStep::MarkConfigured => match mark_configured(&self.paths, self.dry_run) {
                Ok(()) if self.dry_run => {
                    StepResult::ok(format!("would mark configured: {}", self.paths.configured_marker.display()))
                }
                Ok(()) => {
                    let mut result =
                        StepResult::changed(format!("marked configured: {}", self.paths.configured_marker.display()));
                    self.sync_network_units(host, &mut result);
                    result
                }
                Err(e) => StepResult::failed(e.to_string()),
            },
            DeployStep::Activate => self.activate(host),
        }
    }

    fn sync_network_units(&self, host: &Host<'_>, result: &mut StepResult) {
        if self.target != Target::Pi
            || self.paths.via == "user"
            || !host.probe.is_root()
            || !host.probe.systemd_running()
            || !self.installed(host)
        {
            return;
        }
        let tunnel = self.cfg.tunnel.flag("enabled", true) && self.cfg.panels.iter().any(|p| p.mode == Mode::Tunnel);
        let vpn = self.cfg.enabled_vpns().any(|v| !soc_vpn::vpn_incomplete(v));
        for (unit, enabled) in [("autossh-tunnel.service", tunnel), ("forti-vpn.service", vpn)] {
            let verb = if enabled { "enable" } else { "disable" };
            let cmd = argv(&["systemctl", "--no-block", verb, "--now", unit]);
            match host.runner.run(&cmd, CMD) {
                Ok(output) if output.success() => {}
                Ok(output) => result.lines.push(format!("Could not {verb} {unit}: {}", output.stderr.trim())),
                Err(error) => result.lines.push(format!("Could not {verb} {unit}: {error}")),
            }
            result.cmds.push(cmd);
        }
    }

    fn install(&self, host: &Host<'_>, st: &mut DeployState) -> StepResult {
        let planned = self.steps(host).into_iter().find(|p| p.step == DeployStep::InstallOs);
        let Some(_) = planned.filter(|p| p.needed) else {
            return StepResult::ok("skipped the OS install (already installed, or no package manager)");
        };
        let mut cmd = vec![self.install_sh.clone()];
        if self.fresh {
            cmd.push("--fresh".into());
        }
        if let Some(mode) = self.mode.as_deref().filter(|m| !m.is_empty()) {
            cmd.splice(0..0, [String::from("env"), format!("INSTALL_MODE={mode}")]);
        }
        let cmd = self.sudo(host, cmd);
        let shown = cmd.join(" ");
        if self.dry_run {
            // install.sh has no --dry-run and mutates the host: print, never run it.
            return StepResult::ok(format!("[dry-run] would run: {shown}")).with_cmds(vec![cmd]);
        }
        match host.runner.run(&cmd, INSTALL_TIMEOUT) {
            Ok(o) if o.success() => {
                st.install_changed = true;
                let mut installed = load_env_file(&self.paths.soc_env);
                installed.append(&mut st.soc_env);
                st.soc_env = installed;
                StepResult::changed("OS packages + units installed").with_cmds(vec![cmd])
            }
            Ok(o) => StepResult::failed(format!(
                "install.sh failed (rc={}) — fix the error, then re-run (it is idempotent)",
                o.code.map_or("signal".to_string(), |c| c.to_string())
            ))
            .with_cmds(vec![cmd]),
            Err(e) => StepResult::failed(format!("install.sh could not run: {e}")).with_cmds(vec![cmd]),
        }
    }

    fn write_config_step(&self, st: &mut DeployState) -> StepResult {
        let mut env = st.soc_env.clone();
        env.extend(self.soc_env.clone());
        if self.unattended {
            env.insert("SOC_UNATTENDED".to_string(), "1".to_string());
        }
        let mut res = StepResult::ok(format!("config written to {}", self.paths.panels_out.display()));
        let write = |path: &std::path::Path, text: &str, mode: u32, res: &mut StepResult| -> TextResult<()> {
            if self.dry_run {
                res.lines.push(format!("[dry-run] would write {} (mode {mode:o})", path.display()));
                return Ok(());
            }
            let at = write_file(&self.penv, path, text, mode).map_err(|e| e.to_string())?;
            res.lines.push(format!("wrote {}  ({mode:o})", at.display()));
            Ok(())
        };
        let outcome = (|| {
            if !self.keep_panels {
                let panels = self.config_source.clone().unwrap_or_else(|| render_panels_yaml(&self.cfg));
                write(&self.paths.panels_out, &panels, self.paths.panels_mode, &mut res)?;
            }
            write(&self.paths.soc_env, &render_soc_env(&env), self.paths.env_mode, &mut res)?;
            if let Some(unit) = &self.paths.wall_unit {
                let opts = UnitOpts {
                    user: kiosk_user(&env, Some(&self.user)),
                    soc_root: self.paths.soc_root.display().to_string(),
                };
                write(unit, &render_wall_unit(&env, &opts), 0o644, &mut res)?;
            }
            drop_marker(&self.paths, self.dry_run).map_err(|e| e.to_string())?;
            Ok::<(), String>(())
        })();
        if let Err(e) = outcome {
            return StepResult::failed(e);
        }
        if !self.dry_run {
            res.changed = true;
            st.soc_env = env;
        }
        res
    }

    fn vault_up(&self, host: &Host<'_>, st: &DeployState) -> StepResult {
        let url = st.soc_env.get("SOC_VAULT_URL").filter(|v| !v.is_empty()).map_or(self.url.as_str(), String::as_str);
        if !self.is_vault() {
            return StepResult::ok("dev vault backend; no Vaultwarden server needed");
        }
        if !crate::host::is_local_vault(url) {
            return if self.dry_run || host.probe.alive(url) {
                StepResult::ok(format!("using external Vaultwarden at {url}"))
            } else {
                StepResult::failed(format!("external Vaultwarden is not responding at {url}/alive"))
            };
        }
        if self.dry_run {
            return StepResult::ok(format!("would start Vaultwarden ({url})"))
                .with_cmds(vec![self.sudo(host, argv(&["systemctl", "start", "vaultwarden"]))]);
        }
        if host.probe.alive(url) {
            return StepResult::ok(format!("Vaultwarden answering at {url}"));
        }
        if !host.probe.systemd_running() {
            return StepResult::ok("no systemd — start Vaultwarden via your init manager");
        }
        let cmd = self.sudo(host, argv(&["systemctl", "start", "vaultwarden"]));
        let started = host.runner.run(&cmd, CMD);
        let deadline = Instant::now() + self.vault_wait;
        loop {
            if host.probe.alive(url) {
                return StepResult::changed(format!("Vaultwarden answering at {url}")).with_cmds(vec![cmd]);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        // Fail CLOSED: a vault that never answered means account/seal fail too.
        let why = match started {
            Ok(o) if o.success() => String::new(),
            Ok(o) => format!(" (systemctl start exited {})", o.code.map_or("signal".to_string(), |c| c.to_string())),
            Err(e) => format!(" (systemctl start failed: {e})"),
        };
        StepResult::failed(format!("{url}/alive not answering{why} — the vault is not up; account create + seal will fail and the wall will be dark"))
            .with_cmds(vec![cmd])
    }

    fn seal(&self, host: &Host<'_>, st: &mut DeployState) -> StepResult {
        let master = self.master_str();
        if master.is_empty() {
            return StepResult::ok("no master provided — skipping the seal");
        }
        let sd = st
            .soc_env
            .get("SOC_SECRET_DIR")
            .filter(|v| !v.is_empty())
            .map_or_else(|| self.paths.secret_dir.clone(), PathBuf::from);
        if !self.dry_run && already_sealed(host, master, &sd) {
            return StepResult::ok("master already sealed on this host");
        }
        let req = SealRequest {
            master,
            source: MasterSource::Auto,
            pin: self.pin.as_deref(),
            paths: &self.paths,
            soc_env: &st.soc_env,
            backend: &self.backend(),
            dry: self.dry_run,
        };
        match seal_master(&req, host) {
            Ok(out) => {
                st.pin = out.pin;
                let mut r = if self.dry_run {
                    StepResult::ok("would seal the master host-bound")
                } else {
                    StepResult::changed("master sealed host-bound")
                };
                r.lines = out.actions;
                // The PIN is surfaced through `DeployState::pin`, never the detail line.
                r
            }
            Err(e) => StepResult::failed(e.to_string()),
        }
    }

    /// Bring the wall up now, so a deployment ends with a running wall.
    fn activate(&self, host: &Host<'_>) -> StepResult {
        if self.dry_run {
            return StepResult::ok("would start the wall");
        }
        if !host.probe.systemd_running() {
            return StepResult::ok("no systemd — start the wall via your init manager");
        }
        let mode = std::fs::read_to_string(&self.install_manifest)
            .ok() // audit-allow: no manifest means the requested mode stands
            .and_then(|t| {
                t.lines().find_map(|l| {
                    let parts: Vec<&str> = l.split('|').collect();
                    (parts.first() == Some(&"META") && parts.get(1) == Some(&"install_mode"))
                        .then(|| parts.get(2).map(|s| (*s).to_string()))
                        .flatten()
                })
            })
            .or_else(|| self.mode.clone())
            .unwrap_or_else(|| "kiosk".into());
        if mode != "kiosk" {
            return StepResult::ok("desktop mode — start the wall from the app menu");
        }
        let dm = host
            .runner
            .run(&argv(&["systemctl", "is-active", "display-manager.service"]), CMD)
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_default(); // audit-allow: an unanswerable probe means "not active"
        if dm == "active" {
            // A running desktop holds the display: only a reboot hands it over cleanly.
            let cmd = argv(&["shutdown", "-r", "+1", "SOC wall: rebooting into the kiosk"]);
            return match host.runner.run(&cmd, CMD) {
                Ok(result) if result.success() => {
                    StepResult::changed("rebooting in 1 minute to hand the display to the wall")
                }
                _ => StepResult::failed("could not schedule the reboot to start the wall"),
            }
            .with_cmds(vec![cmd]);
        }
        let cmd = argv(&["systemctl", "restart", "getty@tty1.service"]);
        match host.runner.run(&cmd, CMD) {
            Ok(result) if result.success() => StepResult::changed("wall starting on tty1"),
            _ => StepResult::failed("could not restart tty1 to start the wall"),
        }
        .with_cmds(vec![cmd])
    }

    /// Run the whole plan, reporting each step as it finishes. Stops at the
    /// first hard failure; a failed doctor is reported in the exit code but does
    /// not stop the marker/activation (as in the Python tool). A vault failure
    /// AFTER a real install disables the wall session, so the box does not boot
    /// into a session that cannot unseal.
    pub fn run(&self, host: &Host<'_>, report: &mut dyn FnMut(DeployStep, &StepResult)) -> DeployOutcome {
        let mut st = DeployState { soc_env: self.soc_env.clone(), ..DeployState::default() };
        let mut out = DeployOutcome { ok: true, ..DeployOutcome::default() };
        if let Err(why) = self.validate(host) {
            out.ok = false;
            out.error = Some(why);
            return out;
        }
        for p in self.steps(host) {
            if !p.needed {
                let r = StepResult::ok(format!("skipped — {}", p.why));
                report(p.step, &r);
                out.results.push((p.step, r));
                continue;
            }
            let mut r = self.run_step(p.step, host, &mut st);
            if !r.ok && p.step == DeployStep::Doctor {
                out.ok = false;
                report(p.step, &r);
                out.results.push((p.step, r));
                continue;
            }
            if !r.ok {
                let vault_step =
                    matches!(p.step, DeployStep::VaultAccount | DeployStep::Seal | DeployStep::StoreLogins);
                if vault_step && st.install_changed && !self.dry_run {
                    let cmd = argv(&["systemctl", "disable", "soc-wall.service"]);
                    let _ = host.runner.run(&cmd, CMD); // audit-allow: the failing step is already being reported
                    r.detail = format!(
                        "PARTIAL INSTALL: deploy succeeded but the vault could not be finished ({}). The wall \
                         session was left DISABLED so the box won't boot into a dead wall. Do NOT reboot yet — \
                         re-run deploy with the master to seal it, which re-enables boot.",
                        r.detail
                    );
                    r.cmds.push(cmd);
                }
                report(p.step, &r);
                out.results.push((p.step, r));
                out.ok = false;
                break;
            }
            report(p.step, &r);
            out.results.push((p.step, r));
        }
        out.pin = st.pin;
        out.doctor = st.doctor;
        out
    }
}

/// State carried between steps.
#[derive(Default)]
pub struct DeployState {
    /// The `soc.env` as of now (updated once the config is written).
    pub soc_env: SocEnv,
    /// The one-time PIN of a seal made (or previewed) in this run.
    pub pin: Option<Zeroizing<String>>,
    pub install_changed: bool,
    pub doctor: Option<Report>,
}

/// What a whole deploy produced.
#[derive(Default)]
pub struct DeployOutcome {
    pub ok: bool,
    /// Why the plan was refused before any step ran.
    pub error: Option<String>,
    pub pin: Option<Zeroizing<String>>,
    pub doctor: Option<Report>,
    pub results: Vec<(DeployStep, StepResult)>,
}

impl DeployOutcome {
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.ok)
    }
}
