//! `setup <cmd>`: the non-interactive CLI. Inputs come from flags, the
//! environment and stdin (never argv for a secret). Returns the exit code.

use crate::deploy::{DeployPlan, DeployState, DeployStep};
use crate::doctor::{Doctor, DoctorInputs};
use crate::envfile::{SocEnv, load_env_file, parse_env_file, render_soc_env};
use crate::error::TextResult;
use crate::firstrun::FirstRunPlan;
use crate::host::{Probe, SystemHost};
use crate::paths::{SetupPaths, Target};
use crate::repair::{Repair, RepairInputs};
use crate::seal::pin_banner;
use crate::step::StepResult;
use crate::unit::{UnitOpts, render_wall_unit};
use crate::vault::{Creds, LoginCred};
use soc_seal::MasterSource;
use soc_sys::paths::PathEnv;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, IsTerminal, Read};
use std::path::Path;
use std::process::Command;
use zeroize::{Zeroize, Zeroizing};

const USAGE: &str = "usage: soc-wall setup <command> [flags]
  menu | wizard | firstboot | install | wizard-gui | creds
  provision | create-users | vault-register | vault-seed | vault-reset | seal | write-config | reinstall | uninstall
  render-env   [--env-file F] [--set K=V]...            print soc.env (input: file, stdin KEY=VALUE, --set)
  render-unit  [--env-file F] [--set K=V]... [--user U] [--soc-root P]
  doctor       [--target pi|dev] [--no-venv]
  repair       [--target pi|dev] [--dry-run] [--no-venv] [--no-packages] [--no-tunnel-key]
  first-run    [--target T] [--source auto|sealed|secret-service|env] [--pin P] [--reseal] [--dry-run] [--master-fd N]
  deploy       [--target T] [--dry-run] [--fresh] [--unattended] [--write-config] [--email E] [--url U]
               [--mode M] [--pin P] [--config FILE] [--master-fd N] [--creds-fd N] [--no-seed]";

/// Parsed flags: `--k v`, `--k=v` and bare switches.
pub(crate) struct Flags {
    vals: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
}

impl Flags {
    pub(crate) fn parse(args: &[String], valued: &[&str], bare: &[&str]) -> TextResult<Flags> {
        let mut f = Flags { vals: BTreeMap::new(), switches: Vec::new() };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let (key, inline) = match a.split_once('=') {
                Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
                _ => (a.clone(), None),
            };
            if bare.contains(&key.as_str()) {
                if inline.is_some() {
                    return Err(format!("{key} does not take a value"));
                }
                f.switches.push(key);
            } else if valued.contains(&key.as_str()) {
                let v = match inline {
                    Some(v) => v,
                    None => it
                        .next()
                        .filter(|v| !v.starts_with("--"))
                        .cloned()
                        .ok_or_else(|| format!("{key} needs a value"))?,
                };
                f.vals.entry(key).or_default().push(v);
            } else {
                return Err(format!("unrecognized argument: {a}"));
            }
        }
        Ok(f)
    }

    pub(crate) fn has(&self, k: &str) -> bool {
        self.switches.iter().any(|s| s == k)
    }

    pub(crate) fn one(&self, k: &str) -> Option<&str> {
        self.vals.get(k).and_then(|v| v.last()).map(String::as_str)
    }

    fn all(&self, k: &str) -> &[String] {
        self.vals.get(k).map_or(&[], Vec::as_slice)
    }
}

/// Entry point: `args` excludes the program name and `setup` itself.
pub fn setup_cli_main(args: &[String]) -> i32 {
    let Some((cmd, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return 2;
    };
    let run = match cmd.as_str() {
        "render-env" => render(rest, false),
        "render-unit" => render(rest, true),
        "doctor" => doctor(rest),
        "repair" => repair(rest),
        "first-run" | "seal" => first_run(rest, cmd == "seal"),
        "deploy" | "provision" => deploy(rest, cmd == "provision"),
        "write-config" => provision_step(rest, DeployStep::WriteConfig),
        "vault-register" => provision_step(rest, DeployStep::VaultAccount),
        "vault-seed" => provision_step(rest, DeployStep::StoreLogins),
        "vault-reset" => crate::reset::run(rest),
        "creds" => credentials(rest),
        "create-users" => create_users(rest),
        "wizard" | "firstboot" | "install" => crate::wizard::run(cmd, rest),
        "menu" => crate::wizard::menu(rest),
        "uninstall" => system_install(false, rest),
        "reinstall" => crate::reinstall::run(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            return 0;
        }
        arg if arg.starts_with("--") => crate::wizard::run("wizard", args),
        other => Err(format!("unknown command: {other}\n{USAGE}")),
    };
    match run {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("setup {cmd}: {msg}");
            2
        }
    }
}

pub(crate) fn target_of(f: &Flags, penv: &PathEnv, host: &SystemHost) -> TextResult<Target> {
    match f.one("--target") {
        Some(t) => Target::parse(t).ok_or_else(|| format!("--target must be pi or dev, not {t}")),
        None => Ok(Target::default_for(host.probe.is_root(), penv)),
    }
}

fn input_fd(fd: &str, flag: &str) -> TextResult<File> {
    let number = fd.parse::<u32>().map_err(|e| format!("{flag} needs an open file descriptor: {e}"))?;
    File::open(format!("/proc/self/fd/{number}")).map_err(|e| format!("cannot read {flag} {number}: {e}"))
}

pub(crate) fn read_line_secret(input: impl BufRead) -> TextResult<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::with_capacity(4097));
    input.take(4097).read_line(&mut line).map_err(|e| format!("cannot read the master: {e}"))?;
    if line.len() > 4096 {
        return Err("vault master is too long".into());
    }
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}

pub(crate) fn read_master(f: &Flags) -> TextResult<Option<Zeroizing<String>>> {
    match f.one("--master-fd") {
        Some(fd) if f.has("--master-stdin") => Err(format!("choose either --master-fd {fd} or --master-stdin")),
        Some(fd) => read_line_secret(BufReader::new(input_fd(fd, "--master-fd")?)).map(Some),
        None if f.has("--master-stdin") => read_line_secret(std::io::stdin().lock()).map(Some),
        None => Ok(None),
    }
}

fn env_input(f: &Flags) -> TextResult<SocEnv> {
    let mut env = match f.one("--env-file") {
        Some(p) => load_env_file(std::path::Path::new(p)),
        None if f.one("--env-file").is_none() && !f.all("--set").is_empty() => SocEnv::new(),
        None => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text).map_err(|e| format!("cannot read stdin: {e}"))?;
            parse_env_file(&text)
        }
    };
    for kv in f.all("--set") {
        let (k, v) = kv.split_once('=').ok_or_else(|| format!("--set wants KEY=VALUE, got {kv}"))?;
        env.insert(k.to_string(), v.to_string());
    }
    Ok(env)
}

fn render(args: &[String], unit: bool) -> TextResult<i32> {
    let f = Flags::parse(args, &["--env-file", "--set", "--user", "--soc-root"], &[])?;
    let env = env_input(&f)?;
    if unit {
        let mut o = UnitOpts::default();
        if let Some(u) = f.one("--user") {
            o.user = u.into();
        }
        if let Some(r) = f.one("--soc-root") {
            o.soc_root = r.into();
        }
        print!("{}", render_wall_unit(&env, &o));
    } else {
        print!("{}", render_soc_env(&env));
    }
    Ok(0)
}

fn doctor(args: &[String]) -> TextResult<i32> {
    let f = Flags::parse(args, &["--target"], &["--no-venv", "--venv"])?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = target_of(&f, &penv, &sys)?;
    let paths = SetupPaths::resolve(target, &penv, false);
    let mut d = Doctor::new(DoctorInputs::load(target, &penv, paths));
    d.check_venv = f.has("--venv") && !f.has("--no-venv");
    let rep = d.run(&sys.host());
    print!("{}", rep.render());
    Ok(rep.exit_code())
}

fn repair(args: &[String]) -> TextResult<i32> {
    let f =
        Flags::parse(args, &["--target"], &["--dry-run", "--no-venv", "--venv", "--no-packages", "--no-tunnel-key"])?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = target_of(&f, &penv, &sys)?;
    let paths = SetupPaths::resolve(target, &penv, false);
    let mut r = Repair::new(RepairInputs::load(target, paths));
    r.opts.dry_run = f.has("--dry-run");
    r.opts.venv = f.has("--venv") && !f.has("--no-venv");
    r.opts.install_sh = penv.repo_root().join("install.sh").display().to_string();
    r.opts.packages = !f.has("--no-packages");
    r.opts.tunnel_key = !f.has("--no-tunnel-key");
    let out = r.run(&sys.host());
    print!("{}", out.report.render());
    Ok(0)
}

fn first_run(args: &[String], force_seal: bool) -> TextResult<i32> {
    let f = Flags::parse(
        args,
        &["--target", "--source", "--pin", "--master-fd"],
        &["--reseal", "--dry-run", "--master-stdin"],
    )?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = target_of(&f, &penv, &sys)?;
    let paths = SetupPaths::resolve(target, &penv, false);
    let soc_env = load_env_file(&paths.soc_env);
    let source = match f.one("--source") {
        Some(s) => s.parse::<MasterSource>().map_err(|e| e.to_string())?,
        None if force_seal => MasterSource::Sealed,
        None => soc_env.get("SOC_MASTER_SOURCE").and_then(|s| s.parse().ok()).unwrap_or(MasterSource::Auto),
    };
    let backend = if force_seal {
        "native".into()
    } else {
        soc_env.get("SOC_VAULT_BACKEND").cloned().unwrap_or_else(|| paths.default_backend.clone())
    };
    let mut master = read_master(&f)?;
    if master.is_none() && !f.has("--dry-run") && std::io::stdin().is_terminal() {
        let dir = soc_env.get("SOC_SECRET_DIR").filter(|s| !s.is_empty()).map_or(paths.secret_dir.as_path(), Path::new);
        let needed = crate::doctor::is_real_vault(&backend)
            && source != MasterSource::Env
            && !soc_env.get("SOC_VAULT_PASSWORD").is_some_and(|v| !v.is_empty())
            && (f.has("--reseal") || source == MasterSource::SecretService || !sys.host().seal.is_sealed(dir));
        if needed {
            master = Some(crate::wizard::ask_secret("Vault master password")?);
        }
    } else if force_seal && master.is_none() && !f.has("--dry-run") {
        master = Some(read_line_secret(std::io::stdin().lock())?);
    }
    if f.has("--dry-run") && master.is_none() && crate::doctor::is_real_vault(&backend) {
        master = Some(Zeroizing::new("dry-run".into()));
    }
    let plan = FirstRunPlan {
        master,
        pin: f.one("--pin").map(str::to_string),
        reseal: f.has("--reseal"),
        dry_run: f.has("--dry-run"),
        paths,
        soc_env,
        backend,
        source,
    };
    let out = plan.run(&sys.host(), &mut |step, r| {
        println!("  {} {}: {}", if r.ok { "✓" } else { "✗" }, step.as_str(), r.detail);
        for l in &r.lines {
            println!("      {l}");
        }
    });
    Ok(out.exit_code())
}

fn read_creds(mut reader: impl Read) -> TextResult<Creds> {
    const LIMIT: u64 = 1 << 20;
    let mut text = Zeroizing::new(String::new());
    reader.by_ref().take(LIMIT + 1).read_to_string(&mut text).map_err(|e| format!("cannot read credentials: {e}"))?;
    if text.len() as u64 > LIMIT {
        return Err("credential input exceeds 1 MiB".into());
    }
    let mut obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&text).map_err(|e| format!("credentials must be a JSON object of item -> login: {e}"))?;
    let mut out = Creds::new();
    for (name, login) in &mut obj {
        let s = |k: &str| login.get(k).and_then(|x| x.as_str()).unwrap_or_default(); // audit-allow: a missing field is an empty credential, as before
        out.insert(name.clone(), LoginCred::new(s("username"), s("password")));
        if let Some(serde_json::Value::String(mut password)) = login.as_object_mut().and_then(|m| m.remove("password"))
        {
            password.zeroize();
        }
    }
    Ok(out)
}

fn deploy_inputs(args: &[String], unattended: bool) -> TextResult<(Flags, DeployPlan, SystemHost)> {
    let f = Flags::parse(
        args,
        &["--target", "--email", "--url", "--mode", "--pin", "--config", "--master-fd", "--creds-fd", "--creds-file"],
        &[
            "--dry-run",
            "--fresh",
            "--unattended",
            "--write-config",
            "--master-stdin",
            "--seed",
            "--no-seed",
            "--clean",
            "--yes",
        ],
    )?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = if unattended && f.one("--target").is_none() { Target::Pi } else { target_of(&f, &penv, &sys)? };
    let paths = SetupPaths::resolve(target, &penv, false);
    let install = penv.repo_root().join("install.sh");
    let mut plan = DeployPlan::new(target, penv, paths);
    plan.install_sh = install.display().to_string();
    plan.dry_run = f.has("--dry-run");
    plan.fresh = f.has("--fresh");
    plan.unattended = f.has("--unattended");
    plan.write_config = f.has("--write-config") || plan.unattended || f.one("--config").is_some();
    plan.seed = !f.has("--no-seed");
    plan.mode = f.one("--mode").map(str::to_string);
    if plan.mode.as_deref().is_some_and(|m| !matches!(m, "auto" | "kiosk" | "desktop")) {
        return Err("--mode must be auto, kiosk or desktop".into());
    }
    if let Some(config) = f.one("--config") {
        let text = soc_sys::fsutil::read_capped(Path::new(config), 4 << 20)
            .map_err(|e| format!("cannot read {config}: {e}"))?;
        plan.cfg = soc_core::load::load_str(&text, config).map_err(|e| e.to_string())?;
        plan.config_source = Some(text);
    } else if !plan.unattended {
        plan.soc_env.entry("SOC_ROOT".into()).or_insert_with(|| plan.paths.soc_root.display().to_string());
    } else {
        plan.keep_panels = true;
        let installed = &plan.paths.panels_installed;
        let fallback = plan.penv.repo_root().join("config/panels.yaml");
        let source = if installed.exists() { installed } else { &fallback };
        plan.cfg = soc_core::load(source).map_err(|e| e.to_string())?;
        if !installed.exists() {
            plan.config_source = Some(soc_sys::fsutil::read_capped(source, 4 << 20).map_err(|e| e.to_string())?);
            plan.keep_panels = false;
        }
    }
    for (key, path) in [
        ("SOC_ROOT", &plan.paths.soc_root),
        ("SOC_PANELS_FILE", &plan.paths.panels_installed),
        ("SOC_SECRET_DIR", &plan.paths.secret_dir),
        ("SOC_INJECT_TMPL", &plan.paths.inject_tmpl),
    ] {
        if !plan.soc_env.get(key).is_some_and(|v| !v.is_empty()) {
            plan.soc_env.insert(key.into(), path.display().to_string());
        }
    }
    plan.soc_env.entry("SOC_VAULT_BACKEND".into()).or_insert_with(|| plan.paths.default_backend.clone());
    plan.pin = f.one("--pin").map(str::to_string);
    if let Some(u) = f.one("--url") {
        plan.url = u.into();
        plan.soc_env.insert("SOC_VAULT_URL".into(), u.into());
    } else if let Some(u) = plan.soc_env.get("SOC_VAULT_URL").filter(|s| !s.is_empty()) {
        plan.url.clone_from(u);
    }
    plan.email = f
        .one("--email")
        .map(str::to_string)
        .or_else(|| plan.soc_env.get("SOC_VAULT_EMAIL").cloned())
        .unwrap_or_default(); // audit-allow: no email means empty, checked just below
    if !plan.email.is_empty() {
        plan.soc_env.insert("SOC_VAULT_EMAIL".into(), plan.email.clone());
    }
    plan.master = read_master(&f)?;
    plan.creds = match (f.one("--creds-fd"), f.one("--creds-file")) {
        (Some(_), Some(_)) => return Err("choose either --creds-fd or --creds-file".into()),
        (Some(fd), None) => read_creds(input_fd(fd, "--creds-fd")?)?,
        (None, Some(p)) => read_creds(File::open(p).map_err(|e| format!("cannot read {p}: {e}"))?)?,
        (None, None) => Creds::new(),
    };
    Ok((f, plan, sys))
}

pub(crate) fn show_step(step: &str, r: &StepResult) {
    println!("  {} {}: {}", if r.ok { "✓" } else { "✗" }, step, r.detail);
    for line in &r.lines {
        println!("      {line}");
    }
}

fn deploy(args: &[String], provision: bool) -> TextResult<i32> {
    let (flags, mut plan, sys) = deploy_inputs(args, provision)?;
    if (provision || plan.target == Target::Pi) && !plan.dry_run && !sys.probe.is_root() {
        return Err("system deployment needs root; use sudo or --dry-run".into());
    }
    if provision {
        plan.write_config = true;
    }
    let interactive =
        !provision && !plan.unattended && !plan.dry_run && !flags.has("--yes") && std::io::stdin().is_terminal();
    let host = sys.host();
    if flags.has("--clean") {
        plan.validate(&host)?;
        if !clean_state(&plan, flags.has("--yes"))? {
            return Ok(1);
        }
        plan.write_config = true;
        plan.keep_panels = false;
    }
    if interactive {
        crate::wizard::configure_deploy(&mut plan)?;
    }
    let out = plan.run(&host, &mut |step, r| show_step(step.as_str(), r));
    if let Some(e) = &out.error {
        eprintln!("deploy: {e}");
    }
    if let Some(pin) = &out.pin {
        for l in pin_banner(pin) {
            println!("{l}");
        }
    }
    Ok(out.exit_code())
}

fn clean_state(plan: &DeployPlan, yes: bool) -> TextResult<bool> {
    use std::io::Write;
    let state = if plan.target == Target::Dev {
        plan.penv.repo_root().join("dev/run/state")
    } else {
        Path::new("/var/lib/soc-wall").to_path_buf()
    };
    let files = [&plan.paths.panels_out, &plan.paths.soc_env, &plan.paths.configured_marker];
    let directories = [&plan.paths.secret_dir, &state];
    let marker = plan.penv.active_marker();
    let files = files.into_iter().chain([&marker]);
    for path in files.clone().chain(directories) {
        println!("{} {}", if plan.dry_run { "Would reset" } else { "Reset" }, path.display());
    }
    if plan.dry_run {
        return Ok(true);
    }
    if !yes {
        print!("Remove generated state and sealed secrets? [y/N] ");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).map_err(|e| e.to_string())?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Ok(false);
        }
    }
    let accept_absent = |path: &Path, result: std::io::Result<()>| match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    };
    for file in files {
        if file == &plan.paths.panels_out && file.symlink_metadata().is_ok_and(|m| m.is_file()) {
            crate::envfile::backup(file);
        }
        accept_absent(file, std::fs::remove_file(file))?;
    }
    for dir in directories {
        if dir.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
            accept_absent(dir, std::fs::remove_file(dir))?;
        } else {
            accept_absent(dir, std::fs::remove_dir_all(dir))?;
        }
    }
    Ok(true)
}

fn provision_step(args: &[String], step: DeployStep) -> TextResult<i32> {
    let (_, mut plan, sys) = deploy_inputs(args, false)?;
    let host = sys.host();
    if step == DeployStep::VaultAccount && plan.email.is_empty() {
        return Err("vault-register needs --email".into());
    }
    if matches!(step, DeployStep::VaultAccount | DeployStep::StoreLogins) && plan.master.is_none() {
        plan.master = if plan.dry_run {
            Some(Zeroizing::new("dry-run".into()))
        } else {
            crate::vault::resolve_master(&host, &plan.soc_env)
        };
        if plan.master.is_none() {
            plan.master = Some(crate::wizard::ask_secret("Vault master password")?);
        }
    }
    let mut state = DeployState { soc_env: plan.soc_env.clone(), ..DeployState::default() };
    let result = plan.run_step(step, &host, &mut state);
    show_step(step.as_str(), &result);
    Ok(i32::from(!result.ok))
}

fn credentials(args: &[String]) -> TextResult<i32> {
    let (_, mut plan, sys) = deploy_inputs(args, false)?;
    if plan.creds.is_empty()
        && !plan.dry_run
        && std::io::stdin().is_terminal()
        && plan.soc_env.get("SOC_VAULT_BACKEND").is_some_and(|b| crate::doctor::is_real_vault(b))
    {
        crate::wizard::collect_logins(&mut plan)?;
    }
    let result = crate::vault::store_credentials(
        &sys.host(),
        &plan.soc_env,
        &plan.cfg,
        plan.master.as_deref().map(String::as_str),
        &plan.creds,
        plan.dry_run,
    );
    show_step("creds", &result);
    Ok(i32::from(!result.ok))
}

fn create_users(args: &[String]) -> TextResult<i32> {
    let flags = Flags::parse(args, &["--target", "--mode"], &["--dry-run"])?;
    let script = PathEnv::from_process().repo_root().join("install.sh");
    if flags.has("--dry-run") {
        println!("would run {} --users-only (kiosk, desktop, service and updater accounts)", script.display());
        return Ok(0);
    }
    if soc_sys::fsutil::euid() != 0 {
        return Err("create-users needs root (or --dry-run)".into());
    }
    Command::new(&script)
        .arg("--users-only")
        .status()
        .map(|s| s.code().unwrap_or(1))
        .map_err(|e| format!("could not run {}: {e}", script.display()))
}

pub(crate) fn system_install(install: bool, args: &[String]) -> TextResult<i32> {
    let f = Flags::parse(args, &["--mode"], &["--dry-run", "--fresh", "--purge", "--yes"])?;
    let path = PathEnv::from_process().repo_root().join(if install { "install.sh" } else { "uninstall.sh" });
    let mut command = if soc_sys::fsutil::euid() == 0 {
        Command::new(&path)
    } else {
        let mut cmd = Command::new("sudo");
        cmd.arg(&path);
        cmd
    };
    if install {
        if f.has("--fresh") {
            command.arg("--fresh");
        }
        if let Some(mode) = f.one("--mode") {
            if !matches!(mode, "auto" | "kiosk" | "desktop") {
                return Err("--mode must be auto, kiosk or desktop".into());
            }
            command.env("INSTALL_MODE", mode);
        }
    } else {
        if f.has("--purge") {
            command.arg("--purge");
        }
        if f.has("--yes") {
            command.arg("--force");
        }
    }
    if f.has("--dry-run") {
        println!("would run {command:?}");
        return Ok(0);
    }
    command.status().map(|s| s.code().unwrap_or(1)).map_err(|e| format!("could not run {}: {e}", path.display()))
}
