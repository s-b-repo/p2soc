//! The autossh argument list for the persistent jump-host tunnel.
//!
//! Every panel with `mode: tunnel` gets an `-L` local forward, so a remote
//! dashboard becomes `http://127.0.0.1:<local_port>/...`. Every value is
//! vetted by the guards in `soc_core::guard` first: anything starting with
//! `-` could be read as an ssh option, and a value holding a newline would
//! inject a whole extra argument into the one-per-line output.
//!
//! Host-key policy: verification is strict (`yes`) by default. The weaker
//! `accept-new` (trust on first use) is only emitted together with an
//! explicit `known_hosts` file — otherwise ssh would record first-use keys in
//! a default file nobody controls, a silent MITM window — and the builder
//! refuses to produce a tunnel at all rather than weaken verification.

use crate::error::{Result, SysError};
use crate::fsutil::{self, expand_user};
use serde_json::Value;
use soc_core::dict::{as_bool, repr, text, truthy};
use soc_core::guard::{
    has_ctrl, has_ctrl_or_space, host_key_checking, panel_forward, safe_forward, safe_host, safe_word_value,
};
use soc_core::{Config, Mode};
use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where `pin-jump-host` records the jump host's key on first start.
pub const PINNED_KNOWN_HOSTS: &str = "/etc/soc-display/keys/known_hosts";

/// The process-level inputs of the builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelEnv {
    /// For expanding `~` in key paths.
    pub home: Option<PathBuf>,
    /// The account database, for `~user`.
    pub passwd: PathBuf,
    /// The pinned known-hosts file, when it exists.
    pub pinned_known_hosts: Option<PathBuf>,
}

impl TunnelEnv {
    pub fn from_process() -> TunnelEnv {
        let pinned = Path::new(PINNED_KNOWN_HOSTS);
        TunnelEnv {
            home: std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from),
            passwd: PathBuf::from(fsutil::PASSWD),
            pinned_known_hosts: pinned.exists().then(|| pinned.to_path_buf()),
        }
    }
}

/// The outcome of building the tunnel arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelPlan {
    /// The autossh arguments; empty means "no tunnel intended" (idle).
    pub args: Vec<String>,
    /// Panels whose forward was skipped, for the journal.
    pub warnings: Vec<String>,
}

fn key_path(tunnel: &soc_core::Dict, key: &str, env: &TunnelEnv) -> Result<String> {
    let what = format!("tunnel.{key}");
    let word = safe_word_value(tunnel.get(key), &what)?;
    let path = expand_user(&word, env.home.as_deref(), &env.passwd);
    if has_ctrl(&path) {
        return Err(SysError::Refused(format!("{what} contains control characters")));
    }
    Ok(path)
}

/// Build the autossh arguments from the `tunnel:` section and the panels.
///
/// - A disabled section, or one with no `jump_host`, is a legitimate no-op:
///   empty arguments.
/// - One malformed panel forward is skipped with a warning — it must not take
///   down the other panels' forwards, and a bad `-L` is one ssh rejects and
///   autossh retries forever.
/// - A bad `extra_forwards` entry, an enabled tunnel with nothing to forward,
///   or a weakened host-key mode without a pinned `known_hosts` are errors:
///   the tunnel refuses to start.
pub fn tunnel_plan(conf: &Config, env: &TunnelEnv) -> Result<TunnelPlan> {
    let t = &conf.tunnel;
    let enabled = t.get("enabled").is_none_or(|v| as_bool(v).unwrap_or_else(|| truthy(v)));
    let jump_raw = t.get("jump_host").filter(|v| truthy(v));
    let Some(jump_raw) = jump_raw.filter(|_| enabled) else {
        return Ok(TunnelPlan::default());
    };
    let jump = safe_host(&text(jump_raw), "tunnel.jump_host")?;

    let mut plan = TunnelPlan::default();
    let mut forwards = Vec::new();
    for p in &conf.panels {
        let Some(section) = p.tunnel.as_ref().filter(|s| p.mode == Mode::Tunnel && !s.is_empty()) else {
            continue;
        };
        match panel_forward(section) {
            Ok(spec) => forwards.push(spec),
            Err(e) => plan.warnings.push(format!(
                "tunnel-args: skipping panel {}: malformed tunnel section ({e})",
                soc_core::dict::quote(&p.id)
            )),
        }
    }
    match t.get("extra_forwards") {
        Some(Value::Array(entries)) => {
            for entry in entries {
                forwards.push(safe_forward(&text(entry))?);
            }
        }
        Some(other) if truthy(other) => {
            return Err(SysError::Invalid(format!("tunnel.extra_forwards must be a list, got {}", repr(other))));
        }
        _ => {}
    }
    // An ENABLED tunnel with a jump host but zero forwards is a
    // misconfiguration, not a no-op: the operator meant to tunnel something.
    if forwards.is_empty() {
        return Err(SysError::NoForwards);
    }

    let hkc = host_key_checking(t);
    let mut known = key_path(t, "known_hosts", env)?;
    if known.is_empty() {
        if let Some(pinned) = &env.pinned_known_hosts {
            known = pinned.to_string_lossy().into_owned();
        }
    }
    if hkc != "yes" && known.is_empty() {
        return Err(SysError::Refused(format!(
            "host_key_checking={} requires an explicit 'known_hosts' path (set tunnel.known_hosts) so \
             first-connect keys are pinned to a controlled file; refusing to weaken host-key verification \
             without it.",
            t.get("host_key_checking").map_or_else(|| "None".to_string(), repr)
        )));
    }
    // ssh parses an `-o` value like a config line: whitespace would split the
    // path into several files, a quote would change how it is read.
    if has_ctrl_or_space(&known) || known.contains('"') {
        return Err(SysError::Refused(
            "tunnel.known_hosts must not contain whitespace or quotes (ssh would read it as several files)".into(),
        ));
    }

    let mut args: Vec<String> = [
        "-M",
        "0",
        "-N",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "ExitOnForwardFailure=yes",
    ]
    .map(String::from)
    .to_vec();
    args.extend(["-o".to_string(), format!("StrictHostKeyChecking={hkc}"), "-o".into(), "BatchMode=yes".into()]);
    if !known.is_empty() {
        args.extend(["-o".to_string(), format!("UserKnownHostsFile={known}")]);
    }
    let identity = key_path(t, "identity", env)?;
    if !identity.is_empty() {
        args.extend(["-i".to_string(), identity]);
    }
    for forward in forwards {
        args.extend(["-L".to_string(), forward]);
    }
    args.push(jump);
    plan.args = args;
    Ok(plan)
}

/// The autossh arguments for `conf` on this machine. Skipped-panel warnings
/// go to stderr (the journal). Empty means "no tunnel intended".
pub fn tunnel_args(conf: &Config) -> Result<Vec<String>> {
    let plan = tunnel_plan(conf, &TunnelEnv::from_process())?;
    for warning in &plan.warnings {
        eprintln!("{warning}");
    }
    Ok(plan.args)
}

/// One argument per line (nothing at all for an empty list). Refuses an
/// argument that holds a line break: it would become two arguments.
pub fn render_lines(args: &[String]) -> Result<String> {
    if args.iter().any(|a| a.contains(['\n', '\r'])) {
        return Err(SysError::Refused("a tunnel argument contains a line break".into()));
    }
    Ok(if args.is_empty() { String::new() } else { format!("{}\n", args.join("\n")) })
}

/// `tunnel-args`: print the argument list, one per line. Exit status 0 (also
/// for "no tunnel"), 2 for an enabled tunnel with nothing to forward, 1 for
/// any other refusal.
pub fn tunnel_args_main(conf: &Config) -> i32 {
    match tunnel_args(conf).and_then(|args| render_lines(&args)) {
        Ok(lines) => {
            print!("{lines}");
            0
        }
        Err(e) => {
            eprintln!("tunnel-args: {e}");
            e.exit_code()
        }
    }
}

/// What the tunnel service should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelAction {
    /// Nothing to run. The service idles instead of exiting, so
    /// `Restart=always` does not churn on a config that cannot be fixed by
    /// retrying. `fatal` distinguishes a broken config from "no tunnels".
    Idle { fatal: bool, reason: String },
    /// Exec autossh with these arguments.
    Run(Vec<String>),
}

/// Decide the service's action from the config (or the reason it could not
/// be loaded). A failure is loud and idles — it must never look identical to
/// "no tunnels configured".
pub fn tunnel_action(conf: std::result::Result<&Config, &str>, env: &TunnelEnv) -> (TunnelAction, Vec<String>) {
    let fatal = |why: &str| TunnelAction::Idle {
        fatal: true,
        reason: format!("FATAL: {why}; idling so Restart does not churn — fix config and restart"),
    };
    let conf = match conf {
        Ok(conf) => conf,
        Err(why) => return (fatal(why), Vec::new()),
    };
    match tunnel_plan(conf, env) {
        Err(e) => (fatal(&e.to_string()), Vec::new()),
        Ok(plan) if plan.args.is_empty() => {
            (TunnelAction::Idle { fatal: false, reason: "no tunnels configured; idling".into() }, plan.warnings)
        }
        Ok(plan) => (TunnelAction::Run(plan.args), plan.warnings),
    }
}

/// The `autossh` invocation. `-M 0` plus ServerAlive (in the arguments)
/// provides liveness; a 30 s gate keeps autossh's tight-respawn protection so
/// a flapping link cannot hot-loop. Both knobs — and any other `AUTOSSH_*`
/// setting — stay overridable from `soc.env`; nothing else from that file is
/// passed on to ssh.
pub fn autossh_command(args: &[String], file_env: &BTreeMap<String, String>) -> Command {
    let mut cmd = Command::new("autossh");
    cmd.args(args);
    for (key, default) in [("AUTOSSH_GATETIME", "30"), ("AUTOSSH_POLL", "30")] {
        if std::env::var_os(key).is_none_or(|v| v.is_empty()) {
            cmd.env(key, default);
        }
    }
    for (key, value) in file_env.iter().filter(|(k, _)| k.starts_with("AUTOSSH_")) {
        cmd.env(key, value);
    }
    cmd
}

/// A loaded config, or the reason it could not be loaded.
pub type ConfLoad<'a> = std::result::Result<&'a Config, &'a str>; // audit-allow: the &str error is the config-load reason text, printed as-is

/// The tunnel service entry point: build the arguments and replace this
/// process with autossh, or idle forever when there is nothing (valid) to
/// run. Only returns if autossh itself cannot be started.
pub fn autossh_service_main(conf: ConfLoad<'_>, file_env: &BTreeMap<String, String>) -> i32 {
    let (action, warnings) = tunnel_action(conf, &TunnelEnv::from_process());
    for warning in &warnings {
        eprintln!("{warning}");
    }
    match action {
        TunnelAction::Idle { reason, .. } => {
            eprintln!("[autossh-tunnel] {reason}");
            loop {
                std::thread::park();
            }
        }
        TunnelAction::Run(args) => {
            eprintln!("[autossh-tunnel] autossh {}", args.join(" "));
            let err = autossh_command(&args, file_env).exec();
            eprintln!("[autossh-tunnel] cannot start autossh: {err}");
            127
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, config, fixture, tunnel_panel, wall_basic, wall_notunnel, wall_rich};
    use serde_json::json;
    use soc_core::DisplayCfg;

    fn env() -> TunnelEnv {
        TunnelEnv { home: Some("/home/soc".into()), passwd: "/nonexistent/passwd".into(), pinned_known_hosts: None }
    }

    /// One tunnel panel behind `u@jump`, plus extra `tunnel:` keys.
    fn wall(extra: Value) -> Config {
        let d = DisplayCfg::default();
        let mut tunnel = json!({"enabled": true, "jump_host": "u@jump"});
        tunnel.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap());
        config(d.clone(), vec![tunnel_panel(&d, "p1", (0, 0), 19101, "10.0.0.5", 8443)], tunnel)
    }

    fn args(extra: Value) -> Vec<String> {
        tunnel_plan(&wall(extra), &env()).unwrap().args
    }

    fn has(args: &[String], needle: &str) -> bool {
        args.iter().any(|a| a == needle)
    }

    fn lines(conf: &Config) -> String {
        render_lines(&tunnel_plan(conf, &env()).unwrap().args).unwrap()
    }

    #[test]
    fn output_is_identical_to_the_python_script() {
        assert_eq!(lines(&wall_basic()), fixture("basic.tunnel-args.txt"));
        assert_eq!(lines(&wall_rich()), fixture("rich.tunnel-args.txt"));
        assert_eq!(lines(&wall_notunnel()), fixture("notunnel.tunnel-args.txt"));
    }

    #[test]
    fn output_from_the_loaded_yaml_is_identical_too() {
        for name in ["basic", "rich", "notunnel"] {
            let conf = soc_core::load_str(&fixture(&format!("wall-{name}.yaml")), name).unwrap();
            assert_eq!(lines(&conf), fixture(&format!("{name}.tunnel-args.txt")), "{name}");
        }
    }

    #[test]
    fn default_is_strict_host_key_checking() {
        let a = args(json!({}));
        assert!(has(&a, "StrictHostKeyChecking=yes"));
        assert!(!a.iter().any(|x| x.starts_with("UserKnownHostsFile=")));
        assert_eq!(a.last().unwrap(), "u@jump");
    }

    #[test]
    fn accept_new_is_an_explicit_opt_in_with_a_pinned_file() {
        let a = args(json!({"host_key_checking": "accept-new", "known_hosts": "/etc/soc-display/keys/known_hosts"}));
        assert!(has(&a, "StrictHostKeyChecking=accept-new"));
        assert!(has(&a, "UserKnownHostsFile=/etc/soc-display/keys/known_hosts"));
    }

    #[test]
    fn accept_new_without_known_hosts_refuses_to_start() {
        let err = tunnel_plan(&wall(json!({"host_key_checking": "accept-new"})), &env()).unwrap_err();
        assert!(
            matches!(&err, SysError::Refused(m) if m.starts_with("host_key_checking='accept-new' requires")),
            "{err}"
        );
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn accept_new_may_rely_on_the_file_pinned_at_first_start() {
        let pinned = TunnelEnv { pinned_known_hosts: Some(PINNED_KNOWN_HOSTS.into()), ..env() };
        let a = tunnel_plan(&wall(json!({"host_key_checking": "accept-new"})), &pinned).unwrap().args;
        assert!(has(&a, "StrictHostKeyChecking=accept-new"));
        assert!(has(&a, &format!("UserKnownHostsFile={PINNED_KNOWN_HOSTS}")));
        // an explicit file still wins over the pinned one
        let a = tunnel_plan(&wall(json!({"known_hosts": "/my/kh"})), &pinned).unwrap().args;
        assert!(has(&a, "UserKnownHostsFile=/my/kh"));
    }

    #[test]
    fn unknown_value_falls_back_to_strict() {
        for bogus in [json!("no"), json!(false), json!("off"), json!("accept_new")] {
            let a = args(json!({"host_key_checking": bogus}));
            assert!(has(&a, "StrictHostKeyChecking=yes"), "{bogus}");
            assert!(!a.iter().any(|x| x == "StrictHostKeyChecking=no"));
        }
    }

    #[test]
    fn extra_forward_is_emitted_after_its_own_flag() {
        let spec = "127.0.0.1:19200:10.0.0.9:443";
        let a = args(json!({"extra_forwards": [spec]}));
        let at = a.iter().position(|x| x == spec).unwrap();
        assert_eq!(a[at - 1], "-L");
    }

    #[test]
    fn a_bad_extra_forward_stops_the_tunnel() {
        for bad in [
            "-D 1080",
            "-L 127.0.0.1:1:h:2",
            "127.0.0.1:19200:10.0.0.9:443 -oProxyCommand=evil",
            "127.0.0.1: 19200:10.0.0.9:443",
            "  127.0.0.1:19200:10.0.0.9:443",
            "127.0.0.1:19200:10.0.0.9",
            "127.0.0.1:notaport:10.0.0.9:443",
            "",
        ] {
            let err = tunnel_plan(&wall(json!({"extra_forwards": [bad]})), &env()).unwrap_err();
            assert!(matches!(err, SysError::Guard(_)), "{bad:?}: {err}");
        }
        for not_a_list in [json!("8080:h:80"), json!({"a": 1}), json!(8080)] {
            let err = tunnel_plan(&wall(json!({"extra_forwards": not_a_list})), &env()).unwrap_err();
            assert!(matches!(err, SysError::Invalid(_)), "{err}");
        }
        assert!(tunnel_plan(&wall(json!({"extra_forwards": null})), &env()).is_ok());
    }

    #[test]
    fn option_injection_through_the_jump_host_or_key_paths_is_refused() {
        for bad in ["-oProxyCommand=evil", "u@jump -oProxyCommand=evil", "u@jump\n-D\n1080"] {
            assert!(tunnel_plan(&wall(json!({"jump_host": bad})), &env()).is_err(), "{bad:?}");
        }
        for (key, bad) in [
            ("identity", "-oProxyCommand=evil"),
            ("identity", "/k\n-D"),
            ("identity", "/k\u{1}"),
            ("known_hosts", "-x"),
            ("known_hosts", "/pinned /tmp/attacker"),
            ("known_hosts", "/kh\"x"),
            ("known_hosts", "/kh\tx"),
        ] {
            assert!(tunnel_plan(&wall(json!({key: bad})), &env()).is_err(), "{key}={bad:?}");
        }
    }

    #[test]
    fn disabled_or_jumpless_tunnel_is_a_silent_no_op() {
        for section in [
            json!({"enabled": false, "jump_host": "u@jump"}),
            json!({"enabled": "no", "jump_host": "u@jump"}),
            json!({"enabled": null, "jump_host": "u@jump"}),
            json!({"enabled": true}),
            json!({"enabled": true, "jump_host": ""}),
            json!({}),
        ] {
            let d = DisplayCfg::default();
            let conf = config(d.clone(), vec![tunnel_panel(&d, "p1", (0, 0), 1, "h", 2)], section.clone());
            assert_eq!(tunnel_plan(&conf, &env()).unwrap(), TunnelPlan::default(), "{section}");
        }
        assert_eq!(render_lines(&[]).unwrap(), "");
    }

    #[test]
    fn an_enabled_tunnel_with_nothing_to_forward_is_a_distinct_error() {
        let conf = config(DisplayCfg::default(), vec![], json!({"jump_host": "u@jump"}));
        let err = tunnel_plan(&conf, &env()).unwrap_err();
        assert!(matches!(err, SysError::NoForwards));
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("nothing for autossh to forward"));
    }

    #[test]
    fn one_malformed_panel_is_skipped_not_fatal() {
        let d = DisplayCfg::default();
        let mut bad = tunnel_panel(&d, "broken", (1, 0), 19102, "h:80", 443);
        let good = tunnel_panel(&d, "ok", (0, 0), 19101, "10.0.0.5", 8443);
        let conf = config(d.clone(), vec![bad.clone(), good.clone()], json!({"jump_host": "u@jump"}));
        let plan = tunnel_plan(&conf, &env()).unwrap();
        assert!(has(&plan.args, "127.0.0.1:19101:10.0.0.5:8443"));
        assert_eq!(plan.args.iter().filter(|a| *a == "-L").count(), 1);
        assert_eq!(plan.warnings.len(), 1);
        assert!(plan.warnings[0].starts_with("tunnel-args: skipping panel 'broken': malformed tunnel section ("));
        // a direct panel that still carries a tunnel block is ignored
        bad.mode = Mode::Direct;
        let conf = config(d, vec![bad, good], json!({"jump_host": "u@jump"}));
        assert!(tunnel_plan(&conf, &env()).unwrap().warnings.is_empty());
    }

    #[test]
    fn tilde_paths_are_expanded() {
        let t = TempDir::new("tunnel-passwd");
        let passwd = t.write("passwd", "tun:x:1002:1002::/var/lib/tun:/bin/sh\n");
        let e = TunnelEnv { passwd, ..env() };
        let conf = wall(json!({"identity": "~/k", "known_hosts": "~tun/kh"}));
        let a = tunnel_plan(&conf, &e).unwrap().args;
        assert!(has(&a, "/home/soc/k") && has(&a, "UserKnownHostsFile=/var/lib/tun/kh"), "{a:?}");
    }

    #[test]
    fn line_output_refuses_embedded_line_breaks() {
        assert!(render_lines(&["-L".into(), "a\nb".into()]).is_err());
        assert_eq!(render_lines(&["-N".into(), "h".into()]).unwrap(), "-N\nh\n");
    }

    #[test]
    fn service_runs_idles_or_fails_loudly() {
        let (action, _) = tunnel_action(Ok(&wall_basic()), &env());
        assert!(matches!(&action, TunnelAction::Run(a) if a.last().unwrap() == "tunneluser@jump.example.net"));
        let (action, _) = tunnel_action(Ok(&wall_notunnel()), &env());
        assert_eq!(action, TunnelAction::Idle { fatal: false, reason: "no tunnels configured; idling".into() });
        let (action, _) = tunnel_action(Err("panels.yaml is not valid YAML"), &env());
        assert!(matches!(&action, TunnelAction::Idle { fatal: true, reason } if reason.contains("not valid YAML")));
        let (action, _) = tunnel_action(Ok(&wall(json!({"host_key_checking": "accept-new"}))), &env());
        assert!(matches!(action, TunnelAction::Idle { fatal: true, .. }));
    }

    #[test]
    fn autossh_command_defaults_and_overrides() {
        let file_env: BTreeMap<String, String> =
            [("AUTOSSH_POLL", "60"), ("AUTOSSH_DEBUG", "1"), ("SOC_VAULT_URL", "http://127.0.0.1:8222")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        let cmd = autossh_command(&["-N".into(), "u@jump".into()], &file_env);
        assert_eq!(cmd.get_program(), "autossh");
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["-N", "u@jump"]);
        let envs: BTreeMap<_, _> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned())))
            .collect();
        assert_eq!(envs["AUTOSSH_POLL"].as_deref(), Some("60"));
        assert_eq!(envs["AUTOSSH_DEBUG"].as_deref(), Some("1"));
        assert!(!envs.contains_key("SOC_VAULT_URL"), "unrelated settings are not handed to ssh");
        // The gate default applies unless the caller's environment already set one.
        if std::env::var_os("AUTOSSH_GATETIME").is_none() {
            assert_eq!(envs["AUTOSSH_GATETIME"].as_deref(), Some("30"));
        }
    }
}
