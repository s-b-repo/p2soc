//! `setup <cmd>`: the non-interactive CLI. Inputs come from flags, the
//! environment and stdin (never argv for a secret). Returns the exit code.

use crate::deploy::DeployPlan;
use crate::doctor::{Doctor, DoctorInputs};
use crate::envfile::{SocEnv, load_env_file, parse_env_file, render_soc_env};
use crate::error::TextResult;
use crate::firstrun::FirstRunPlan;
use crate::host::SystemHost;
use crate::paths::{SetupPaths, Target};
use crate::repair::{Repair, RepairInputs};
use crate::seal::pin_banner;
use crate::unit::{UnitOpts, render_wall_unit};
use crate::vault::{Creds, LoginCred};
use soc_seal::MasterSource;
use soc_sys::paths::PathEnv;
use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

const USAGE: &str = "usage: setup <render-env|render-unit|doctor|repair|first-run|deploy> [flags]
  render-env   [--env-file F] [--set K=V]...            print soc.env (input: file, stdin KEY=VALUE, --set)
  render-unit  [--env-file F] [--set K=V]... [--user U] [--soc-root P]
  doctor       [--target pi|dev] [--no-venv]
  repair       [--target pi|dev] [--dry-run] [--no-venv] [--no-packages] [--no-tunnel-key]
  first-run    [--target T] [--source auto|sealed|secret-service|env] [--pin P] [--reseal] [--dry-run] [--master-stdin]
  deploy       [--target T] [--dry-run] [--fresh] [--unattended] [--write-config] [--email E] [--url U]
               [--mode M] [--pin P] [--master-stdin] [--creds-file F.json] [--no-seed]";

/// Parsed flags: `--k v`, `--k=v` and bare switches.
struct Flags {
    vals: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], valued: &[&str], bare: &[&str]) -> TextResult<Flags> {
        let mut f = Flags { vals: BTreeMap::new(), switches: Vec::new() };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let (key, inline) = match a.split_once('=') {
                Some((k, v)) if k.starts_with("--") => (k.to_string(), Some(v.to_string())),
                _ => (a.clone(), None),
            };
            if bare.contains(&key.as_str()) {
                f.switches.push(key);
            } else if valued.contains(&key.as_str()) {
                let v = match inline {
                    Some(v) => v,
                    None => it.next().cloned().ok_or_else(|| format!("{key} needs a value"))?,
                };
                f.vals.entry(key).or_default().push(v);
            } else {
                return Err(format!("unrecognized argument: {a}"));
            }
        }
        Ok(f)
    }

    fn has(&self, k: &str) -> bool {
        self.switches.iter().any(|s| s == k)
    }

    fn one(&self, k: &str) -> Option<&str> {
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
        "first-run" => first_run(rest),
        "deploy" => deploy(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            return 0;
        }
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

fn target_of(f: &Flags, penv: &PathEnv, host: &SystemHost) -> TextResult<Target> {
    match f.one("--target") {
        Some(t) => Target::parse(t).ok_or_else(|| format!("--target must be pi or dev, not {t}")),
        None => Ok(Target::default_for(host.probe_is_root(), penv)),
    }
}

impl SystemHost {
    fn probe_is_root(&self) -> bool {
        use crate::host::Probe;
        self.probe.is_root()
    }
}

fn read_master() -> TextResult<Zeroizing<String>> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| format!("cannot read the master from stdin: {e}"))?;
    let t = line.trim_end_matches(['\n', '\r']).to_string();
    line.clear();
    Ok(Zeroizing::new(t))
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
    let f = Flags::parse(args, &["--target"], &["--no-venv"])?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = target_of(&f, &penv, &sys)?;
    let paths = SetupPaths::resolve(target, &penv, false);
    let mut d = Doctor::new(DoctorInputs::load(target, &penv, paths));
    d.check_venv = !f.has("--no-venv");
    let rep = d.run(&sys.host());
    print!("{}", rep.render());
    Ok(rep.exit_code())
}

fn repair(args: &[String]) -> TextResult<i32> {
    let f = Flags::parse(args, &["--target"], &["--dry-run", "--no-venv", "--no-packages", "--no-tunnel-key"])?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = target_of(&f, &penv, &sys)?;
    let paths = SetupPaths::resolve(target, &penv, false);
    let mut r = Repair::new(RepairInputs::load(target, paths));
    r.opts.dry_run = f.has("--dry-run");
    r.opts.venv = !f.has("--no-venv");
    r.opts.packages = !f.has("--no-packages");
    r.opts.tunnel_key = !f.has("--no-tunnel-key");
    let out = r.run(&sys.host());
    print!("{}", out.report.render());
    Ok(0)
}

fn first_run(args: &[String]) -> TextResult<i32> {
    let f = Flags::parse(args, &["--target", "--source", "--pin"], &["--reseal", "--dry-run", "--master-stdin"])?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = target_of(&f, &penv, &sys)?;
    let paths = SetupPaths::resolve(target, &penv, false);
    let soc_env = load_env_file(&paths.soc_env);
    let source = match f.one("--source") {
        Some(s) => s.parse::<MasterSource>().map_err(|e| e.to_string())?,
        None => soc_env.get("SOC_MASTER_SOURCE").and_then(|s| s.parse().ok()).unwrap_or(MasterSource::Auto),
    };
    let backend = soc_env.get("SOC_VAULT_BACKEND").cloned().unwrap_or_else(|| paths.default_backend.clone());
    let plan = FirstRunPlan {
        master: if f.has("--master-stdin") { Some(read_master()?) } else { None },
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

fn read_creds(path: &str) -> TextResult<Creds> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let obj = v.as_object().ok_or("the creds file must be a JSON object of item -> login")?;
    let mut out = Creds::new();
    for (name, login) in obj {
        let s = |k: &str| login.get(k).and_then(|x| x.as_str()).unwrap_or_default(); // audit-allow: a missing field is an empty credential, as before
        out.insert(name.clone(), LoginCred::new(s("username"), s("password")));
    }
    Ok(out)
}

fn deploy(args: &[String]) -> TextResult<i32> {
    let f = Flags::parse(
        args,
        &["--target", "--email", "--url", "--mode", "--pin", "--creds-file"],
        &["--dry-run", "--fresh", "--unattended", "--write-config", "--master-stdin", "--no-seed"],
    )?;
    let (penv, sys) = (PathEnv::from_process(), SystemHost::from_env());
    let target = target_of(&f, &penv, &sys)?;
    let paths = SetupPaths::resolve(target, &penv, false);
    let mut plan = DeployPlan::new(target, penv, paths);
    plan.dry_run = f.has("--dry-run");
    plan.fresh = f.has("--fresh");
    plan.unattended = f.has("--unattended");
    plan.write_config = f.has("--write-config");
    plan.seed = !f.has("--no-seed");
    plan.mode = f.one("--mode").map(str::to_string);
    plan.pin = f.one("--pin").map(str::to_string);
    if let Some(u) = f.one("--url") {
        plan.url = u.into();
    }
    plan.email = f
        .one("--email")
        .map(str::to_string)
        .or_else(|| plan.soc_env.get("SOC_VAULT_EMAIL").cloned())
        .unwrap_or_default(); // audit-allow: no email means empty, checked just below
    if !plan.email.is_empty() {
        plan.soc_env.insert("SOC_VAULT_EMAIL".into(), plan.email.clone());
    }
    if f.has("--master-stdin") {
        plan.master = Some(read_master()?);
    }
    if let Some(p) = f.one("--creds-file") {
        plan.creds = read_creds(p)?;
    }
    let host = sys.host();
    let out = plan.run(&host, &mut |step, r| {
        println!("  {} {}: {}", if r.ok { "✓" } else { "✗" }, step.as_str(), r.detail);
        for l in &r.lines {
            println!("      {l}");
        }
    });
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
