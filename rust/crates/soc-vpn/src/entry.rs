//! Service entry points: the supervisor service itself and the argv
//! inspection helper.
//!
//! One unit, N supervisors: the service reads the config's VPN list and fans
//! it out to a [`VpnManager`]. It reports to systemd over the notify socket —
//! `READY=1` at once (the service is up even while tunnels still connect),
//! `STATUS=` for tunnel state, and `WATCHDOG=1` heartbeats that are withheld
//! as soon as any supervisor stops making progress.

use crate::clock::{Clock, StopFlag};
use crate::driver::{self, Paths};
use crate::manager::{VpnManager, aggregate_state};
use crate::notify::{self, Watchdog};
use crate::status::{VpnState, vpn_name};
use crate::supervisor::{Deps, VaultAccess};
use crate::tunables::Tunables;
use crate::{Log, sys};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use soc_core::guard::GuardError;
use soc_core::vpnargs::{openfortivpn_args, vpn_kind};
use soc_core::{Config, Dict, DictExt, VpnKind};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Loads and validates the wall config.
pub type Loader<'a> = &'a dyn Fn(&Path) -> Result<Config, String>; // audit-allow: display glue, the message is only printed

/// One-time vault session setup (device registration and the like), run only
/// when some VPN needs the vault. It is handed a heartbeat callback to call
/// between slow steps: the watchdog is already armed by then.
pub type Prepare = Box<dyn FnOnce(&dyn Fn()) + Send>;

const USAGE: &str = "usage: vpn [--dry-run] [--name <vpn>] [--config <panels.yaml>]";

/// The command line was not understood; displays as the usage text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageError;

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(USAGE)
    }
}

/// Everything the service reads from its arguments and environment.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceConfig {
    /// `$SOC_PANELS_FILE` / `--config`.
    pub panels: PathBuf,
    /// `$SOC_VPN_NAME` / `--name`: run only this entry (a `forti-vpn@<name>`
    /// instance). Empty runs them all.
    pub only: String,
    pub tunables: Tunables,
    pub paths: Paths,
}

impl ServiceConfig {
    /// Arguments override the environment. An unknown argument is an error
    /// (the usage text).
    pub fn from_lookup(
        args: &[String],
        get: &dyn Fn(&str) -> Option<String>,
        exe: Option<&Path>,
        cwd: &Path,
    ) -> Result<ServiceConfig, UsageError> {
        let mut cfg = ServiceConfig {
            panels: PathBuf::from(
                get("SOC_PANELS_FILE").filter(|v| !v.is_empty()).unwrap_or_else(|| "config/panels.yaml".into()),
            ),
            only: get("SOC_VPN_NAME")
                .unwrap_or_default() // audit-allow: default is the intended fallback (no name filter)
                .trim()
                .to_string(),
            tunables: Tunables::from_lookup(get),
            paths: Paths::from_lookup(get, exe, cwd),
        };
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let (flag, inline) = match arg.split_once('=') {
                Some((flag, value)) => (flag, Some(value.to_string())),
                None => (arg.as_str(), None),
            };
            let mut value = || inline.clone().or_else(|| args.next().cloned()).ok_or(UsageError);
            match flag {
                "--dry-run" => cfg.tunables.dry_run = true,
                "--name" => cfg.only = value()?.trim().to_string(),
                "--config" => cfg.panels = PathBuf::from(value()?),
                _ => return Err(UsageError),
            }
        }
        Ok(cfg)
    }

    pub fn from_env(args: &[String]) -> Result<ServiceConfig, UsageError> {
        let exe = std::env::current_exe().ok();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        ServiceConfig::from_lookup(args, &|name| std::env::var(name).ok(), exe.as_deref(), &cwd)
    }
}

/// A per-type completeness gate (validation already reported the details).
/// True means the entry is enabled but cannot connect. With
/// `config_from_vault` the gateway may arrive in the vault Notes overlay.
pub fn vpn_incomplete(vpn: &Dict) -> bool {
    let from_vault = vpn.truthy("config_from_vault");
    // Text, not truthiness: an item or host may be named "no" or "off".
    let has = |key: &str| !vpn.text(key).is_empty();
    match vpn_kind(vpn) {
        VpnKind::Fortinet | VpnKind::Inode => !has("vault_item") || (!from_vault && !has("gateway")),
        VpnKind::Openvpn | VpnKind::Wireguard => {
            if from_vault {
                !has("vault_item")
            } else {
                !has("config")
            }
        }
    }
}

/// What the service loop needs from the set of supervisors.
pub trait Fleet {
    /// Names of supervisors that stopped making progress.
    fn stalled(&self) -> Vec<String>;
    /// Per-name tunnel state; `on_each` runs between probes.
    fn states(&self, on_each: &mut dyn FnMut()) -> Vec<(String, VpnState)>;
}

impl Fleet for VpnManager {
    fn stalled(&self) -> Vec<String> {
        VpnManager::stalled(self)
    }

    fn states(&self, on_each: &mut dyn FnMut()) -> Vec<(String, VpnState)> {
        VpnManager::states(self, on_each)
    }
}

/// The unit's single `WATCHDOG=1` source. It pets systemd only while every
/// supervisor is making progress: a thread cannot be killed from inside the
/// process, so withholding the ping is the only way a wedged one gets
/// recovered — by systemd restarting the unit. Runs until `stop` is set.
///
/// The ping and the `STATUS=` poll run on separate clocks: each poll is a TCP
/// connect per ready probe, and nothing needs that at heartbeat cadence.
pub fn supervise(fleet: &dyn Fleet, stop: &StopFlag, watchdog: &Watchdog, deps: &Deps, tun: &Tunables) {
    let wait = tun.heartbeat();
    let mut last_status = String::new();
    let mut reported: Vec<String> = Vec::new();
    let mut next_status = f64::NEG_INFINITY;
    while !stop.is_set() {
        let stalled = fleet.stalled();
        if stalled != reported {
            reported.clone_from(&stalled);
            if stalled.is_empty() {
                (deps.log)("all VPN supervisors are making progress again");
            } else {
                let names = stalled.join(", ");
                (deps.log)(&format!(
                    "ERROR no progress from VPN supervisor(s): {names} — withholding the watchdog so systemd \
                     restarts the unit"
                ));
                deps.notifier.notify(&notify::status(&format!("wedged: {names}")));
                last_status.clear();
            }
        }
        if stalled.is_empty() {
            watchdog.ping();
        }
        if deps.clock.now() >= next_status {
            // Pet between probes as well, so no batch size can starve the
            // heartbeat — while still honouring a stall.
            let states = fleet.states(&mut || {
                if fleet.stalled().is_empty() {
                    watchdog.ping();
                }
            });
            next_status = deps.clock.now() + tun.status_interval;
            let overall = aggregate_state(states.iter().map(|(_, state)| *state));
            let detail: Vec<String> = states.iter().map(|(name, state)| format!("{name}={state}")).collect();
            let status = notify::status(&format!("{overall}: {}", detail.join(", ")));
            if status != last_status && stalled.is_empty() {
                deps.notifier.notify(&status);
                last_status = status;
            }
        }
        deps.clock.wait(stop, wait);
    }
}

/// Stay alive without churning systemd restarts, for what a restart cannot
/// fix. Never waits longer than the watchdog interval.
fn idle(stop: &StopFlag, watchdog: &Watchdog, clock: &dyn Clock) -> i32 {
    let wait = if watchdog.interval() > 0.0 { watchdog.interval().min(60.0) } else { 60.0 };
    while !stop.is_set() {
        watchdog.ping();
        clock.wait(stop, wait);
    }
    0
}

/// The service body, with every outside dependency passed in.
pub fn run_service(
    cfg: &ServiceConfig,
    deps: Deps,
    stop: &StopFlag,
    load: Loader<'_>,
    prepare: Option<Prepare>,
) -> i32 {
    let log = deps.log.clone();
    let status = |text: &str| deps.notifier.notify(&notify::status(text));
    deps.notifier.notify(notify::READY);
    // Armed by READY=1, so it covers the setup below too.
    let watchdog = Watchdog::new(cfg.tunables.watchdog_interval, true, deps.clock.clone(), deps.notifier.clone());

    let conf = match load(&cfg.panels) {
        Ok(conf) => conf,
        Err(e) => {
            log(&format!("FATAL: {e}"));
            log("fix the config, then: systemctl restart forti-vpn");
            status("config error — see journal");
            return idle(stop, &watchdog, &*deps.clock);
        }
    };
    for warning in &conf.warnings {
        log(&format!("WARNING {warning}"));
    }

    let enabled: Vec<&Dict> = conf.enabled_vpns().collect();
    if enabled.is_empty() {
        log("no VPN enabled in config; idling");
        status("disabled in panels.yaml");
        return idle(stop, &watchdog, &*deps.clock);
    }

    // Only runnable entries reach the manager, so a bad one never thrashes.
    let mut runnable: Vec<Dict> = Vec::new();
    let mut need_vault = false;
    for (idx, vpn) in enabled.iter().enumerate() {
        let (name, kind) = (vpn_name(vpn, idx), vpn_kind(vpn));
        if vpn_incomplete(vpn) {
            log(&format!("[vpn:{name}] config incomplete for type '{kind}'; skipping (see warnings above)"));
            continue;
        }
        log(&format!("[vpn:{name}] type: {kind}"));
        if kind == VpnKind::Fortinet && vpn.int("persistent") > 0 {
            log(&format!(
                "[vpn:{name}] NOTE persistent > 0: openfortivpn reconnects in-process; the supervisor only adds \
                 health checks + crash restarts. Set persistent: 0 for the classified backoff."
            ));
        }
        need_vault |= driver::needs_creds(kind, vpn) || vpn.truthy("config_from_vault");
        runnable.push((*vpn).clone());
    }
    if runnable.is_empty() {
        log("no runnable VPN (all enabled entries are incomplete); idling");
        status("incomplete vpn config — see journal");
        return idle(stop, &watchdog, &*deps.clock);
    }

    if let Some(prepare) = prepare.filter(|_| need_vault) {
        prepare(&|| watchdog.ping());
    }

    let manager = VpnManager::new(&runnable, &cfg.only, deps.clone(), cfg.tunables.clone(), cfg.paths.clone());
    if !cfg.only.is_empty() && manager.count() == 0 {
        log(&format!("FATAL: no runnable VPN named '{}' in config", cfg.only));
        status(&format!("no VPN named {}", cfg.only));
        return idle(stop, &watchdog, &*deps.clock);
    }

    log(&format!("starting {} VPN supervisor(s): {}", manager.count(), manager.names().join(", ")));
    manager.start();

    // Dry run: each supervisor resolves its login, prints its command and
    // returns. Wait for them, then exit instead of supervising forever.
    if cfg.tunables.dry_run {
        manager.join(cfg.tunables.ready_timeout.max(1.0) + 5.0);
        manager.stop(20.0);
        return 0;
    }

    supervise(&manager, stop, &watchdog, &deps, &cfg.tunables);

    manager.stop(20.0);
    log("all VPNs stopped");
    status("stopped");
    0
}

fn signal_name(signal: i32) -> &'static str {
    match signal {
        SIGTERM => "SIGTERM",
        SIGINT => "SIGINT",
        SIGHUP => "SIGHUP",
        _ => "a signal",
    }
}

/// Turn SIGTERM / SIGINT / SIGHUP into a stop request. The handler itself
/// only writes to a pipe; the logging and the wake-up happen on an ordinary
/// thread, where they are safe.
fn install_signals(stop: &StopFlag, log: &Log) -> std::io::Result<()> {
    let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP])?;
    let (stop, log) = (stop.clone(), log.clone());
    std::thread::Builder::new().name("signals".into()).spawn(move || {
        for signal in signals.forever() {
            log(&format!("received {}; shutting down all VPNs", signal_name(signal)));
            stop.set();
        }
    })?;
    Ok(())
}

/// The VPN service: `soc-wall vpn [--dry-run] [--name <vpn>] [--config
/// <file>]`, run by `forti-vpn.service` / `soc-vpn.service` and their
/// `@<name>` templates. Returns the process exit code.
pub fn supervisor_main(args: &[String], vault: VaultAccess, prepare: Option<Prepare>) -> i32 {
    let cfg = match ServiceConfig::from_env(args) {
        Ok(cfg) => cfg,
        Err(usage) => {
            let _ = writeln!(std::io::stderr(), "{usage}"); // audit-allow: best-effort, stderr may be gone
            return 2;
        }
    };
    // A lost journal stream must not take a tunnel down: never panic on it.
    let log: Log = Arc::new(|msg: &str| {
        let _ = writeln!(std::io::stderr(), "[forti-vpn] {msg}"); // audit-allow: best-effort, a lost journal stream must not panic
    });
    if let Err(e) = sys::disable_core_dumps() {
        log(&format!("WARNING could not disable core dumps: {e}"));
    }
    let stop = StopFlag::new();
    if let Err(e) = install_signals(&stop, &log) {
        log(&format!("FATAL: could not install signal handlers: {e}"));
        return 1;
    }
    let deps = Deps::system(vault, log);
    run_service(&cfg, deps, &stop, &|path| soc_core::load(path).map_err(|e| e.to_string()), prepare)
}

/// The non-secret openfortivpn arguments of the primary VPN, one per line;
/// nothing when it is disabled or has no gateway.
pub fn args_lines(conf: &Config) -> Result<Vec<String>, GuardError> {
    match conf.vpn() {
        Some(vpn) if vpn.truthy("enabled") => openfortivpn_args(vpn),
        _ => Ok(Vec::new()),
    }
}

/// `soc-wall vpn-args [--config <file>]`: print the non-secret openfortivpn
/// argument list, for inspection and debugging. The live connection adds the
/// username and feeds the password through the pinentry helper.
pub fn args_main(args: &[String]) -> i32 {
    let cfg = match ServiceConfig::from_env(args) {
        Ok(cfg) => cfg,
        Err(UsageError) => {
            let _ = writeln!(std::io::stderr(), "usage: vpn-args [--config <panels.yaml>]"); // audit-allow: best-effort
            return 2;
        }
    };
    let lines = soc_core::load(&cfg.panels)
        .map_err(|e| e.to_string())
        .and_then(|conf| args_lines(&conf).map_err(|e| e.to_string()));
    match lines {
        Ok(lines) => {
            let mut out = std::io::stdout().lock();
            for line in lines {
                let _ = writeln!(out, "{line}"); // audit-allow: best-effort, a closed stdout (EPIPE) ends the listing
            }
            0
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}"); // audit-allow: best-effort
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Harness, Script, dict};
    use serde_json::json;
    use std::cell::Cell;
    use std::collections::HashMap;

    fn config_from(pairs: &[(&str, &str)], args: &[&str]) -> Result<ServiceConfig, UsageError> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        ServiceConfig::from_lookup(
            &args,
            &|name| map.get(name).cloned(),
            Some(Path::new("/usr/bin/soc-wall")),
            Path::new("/cwd"),
        )
    }

    #[test]
    fn service_config_from_environment_and_arguments() {
        let cfg = config_from(&[], &[]).unwrap();
        assert_eq!(cfg.panels, Path::new("config/panels.yaml"));
        assert!(cfg.only.is_empty() && !cfg.tunables.dry_run);
        let cfg = config_from(
            &[("SOC_PANELS_FILE", "/etc/soc-display/panels.yaml"), ("SOC_VPN_NAME", " hq "), ("SOC_VPN_DRY_RUN", "1")],
            &[],
        )
        .unwrap();
        assert_eq!(cfg.panels, Path::new("/etc/soc-display/panels.yaml"));
        assert_eq!(cfg.only, "hq");
        assert!(cfg.tunables.dry_run);
        let cfg = config_from(&[("SOC_VPN_NAME", "hq")], &["--name", "dr", "--config=/x.yaml", "--dry-run"]).unwrap();
        assert_eq!((cfg.only.as_str(), cfg.panels.as_path(), cfg.tunables.dry_run), ("dr", Path::new("/x.yaml"), true));
        assert!(config_from(&[], &["--bogus"]).is_err());
        assert!(config_from(&[], &["--name"]).is_err());
    }

    #[test]
    fn completeness_gate() {
        let incomplete = |v| vpn_incomplete(&dict(v));
        // A gateway held only in the vault must not get the entry skipped
        // before the overlay can run.
        assert!(!incomplete(json!({"type": "fortinet", "vault_item": "I", "config_from_vault": true})));
        assert!(incomplete(json!({"type": "fortinet", "vault_item": "I"})));
        assert!(incomplete(json!({"type": "inode", "config_from_vault": true})));
        assert!(!incomplete(json!({"type": "inode", "vault_item": "I", "gateway": "g"})));
        assert!(incomplete(json!({"type": "openvpn"})));
        assert!(!incomplete(json!({"type": "openvpn", "config": "/x.ovpn"})));
        assert!(incomplete(json!({"type": "wireguard", "config_from_vault": true})));
        assert!(!incomplete(json!({"type": "wireguard", "config_from_vault": true, "vault_item": "W"})));
        // A vault item may be named like a YAML boolean.
        assert!(!incomplete(json!({"type": "fortinet", "vault_item": "off", "gateway": "no"})));
    }

    struct FakeFleet {
        stalled: Vec<String>,
        polls: Cell<usize>,
    }

    impl Fleet for FakeFleet {
        fn stalled(&self) -> Vec<String> {
            self.stalled.clone()
        }

        fn states(&self, on_each: &mut dyn FnMut()) -> Vec<(String, VpnState)> {
            self.polls.set(self.polls.get() + 1);
            on_each();
            vec![("a".into(), VpnState::Online), ("b".into(), VpnState::Connecting)]
        }
    }

    /// Run the service loop for `ticks` passes under a 90s watchdog.
    fn notifications(stalled: &[&str], ticks: usize) -> (Vec<String>, Vec<String>, usize) {
        let mut h = Harness::new();
        h.tun.watchdog_interval = 45.0;
        let fleet = FakeFleet { stalled: stalled.iter().map(|s| s.to_string()).collect(), polls: Cell::new(0) };
        let stop = StopFlag::new();
        h.clock.stop_after_waits(ticks, &stop);
        let deps = h.deps();
        let watchdog = Watchdog::new(45.0, true, deps.clock.clone(), deps.notifier.clone());
        supervise(&fleet, &stop, &watchdog, &deps, &h.tun);
        (h.notifier.sent(), h.logs(), fleet.polls.get())
    }

    #[test]
    fn the_watchdog_flows_while_every_supervisor_is_healthy() {
        let (sent, _, _) = notifications(&[], 5);
        assert!(sent.iter().any(|m| m == "WATCHDOG=1"));
        assert!(sent.iter().any(|m| m == "STATUS=offline: a=online, b=connecting"));
    }

    #[test]
    fn the_watchdog_is_withheld_while_a_supervisor_is_wedged() {
        let (sent, logs, _) = notifications(&["hq"], 5);
        assert!(!sent.iter().any(|m| m == "WATCHDOG=1"));
        assert_eq!(sent, ["STATUS=wedged: hq"]);
        assert_eq!(logs.iter().filter(|m| m.contains("hq")).count(), 1, "a stall is reported once, not per tick");
    }

    #[test]
    fn the_between_probes_callback_honours_a_stall() {
        let (sent, _, polls) = notifications(&["hq"], 1);
        assert_eq!(polls, 1);
        assert!(!sent.iter().any(|m| m == "WATCHDOG=1"));
    }

    #[test]
    fn status_probes_run_on_their_own_slower_clock() {
        // Five 5s heartbeats fit inside one 30s status interval.
        let (sent, _, polls) = notifications(&[], 5);
        assert_eq!(polls, 1);
        assert_eq!(sent.iter().filter(|m| m.starts_with("STATUS=")).count(), 1);
    }

    #[test]
    fn idle_never_outwaits_the_watchdog() {
        let h = Harness::new();
        let stop = StopFlag::new();
        h.clock.stop_after_waits(1, &stop);
        let watchdog = Watchdog::new(15.0, true, h.clock.clone(), h.notifier.clone());
        assert_eq!(idle(&stop, &watchdog, &*h.clock), 0);
        assert_eq!(h.clock.waits(), [15.0]);
        assert_eq!(h.notifier.sent(), ["WATCHDOG=1"]);
    }

    fn conf(vpns: serde_json::Value) -> Config {
        Config { vpns: vpns.as_array().unwrap().iter().map(|v| dict(v.clone())).collect(), ..Config::default() }
    }

    fn service(h: &Harness, only: &str) -> ServiceConfig {
        ServiceConfig {
            panels: PathBuf::from("/panels.yaml"),
            only: only.into(),
            tunables: h.tun.clone(),
            paths: h.paths.clone(),
        }
    }

    /// Run the service with a canned config until its first idle/supervise wait.
    fn run(h: &Harness, only: &str, loaded: Result<Config, String>) -> i32 {
        let stop = StopFlag::new();
        h.clock.stop_after_waits(1, &stop);
        run_service(&service(h, only), h.deps(), &stop, &move |_| loaded.clone(), None)
    }

    #[test]
    fn ready_is_sent_first_and_a_config_error_idles() {
        let h = Harness::new();
        assert_eq!(run(&h, "", Err("panels.yaml: vpn.gateway is missing".into())), 0);
        assert_eq!(h.notifier.sent(), ["READY=1\nSTATUS=starting", "STATUS=config error — see journal"]);
        assert!(h.logs().iter().any(|m| m == "FATAL: panels.yaml: vpn.gateway is missing"));
        assert!(h.spawner.spawned().is_empty());
    }

    #[test]
    fn no_enabled_or_no_runnable_vpn_idles_with_a_status() {
        let h = Harness::new();
        run(&h, "", Ok(conf(json!([{"name": "a", "enabled": false, "gateway": "g", "vault_item": "V"}]))));
        assert!(h.notifier.sent().iter().any(|m| m == "STATUS=disabled in panels.yaml"));

        let h = Harness::new();
        run(&h, "", Ok(conf(json!([{"name": "a", "enabled": true, "type": "openvpn"}]))));
        assert!(h.notifier.sent().iter().any(|m| m == "STATUS=incomplete vpn config — see journal"));
        assert!(
            h.logs().iter().any(|m| m == "[vpn:a] config incomplete for type 'openvpn'; skipping (see warnings above)")
        );

        let h = Harness::new();
        run(&h, "nope", Ok(conf(json!([{"name": "a", "enabled": true, "type": "openvpn", "config": "/x.ovpn"}]))));
        assert!(h.notifier.sent().iter().any(|m| m == "STATUS=no VPN named nope"));
        assert!(h.spawner.spawned().is_empty());
    }

    #[test]
    fn the_service_starts_supervises_and_stops() {
        let h = Harness::new();
        h.spawner.push(Script::hang(&["Initialization Sequence Completed"]));
        let mut loaded = conf(json!([{"name": "a", "enabled": true, "type": "openvpn", "config": "/x.ovpn"}]));
        loaded.warnings.push("vpn.a: unknown key 'colour'".into());
        let stop = StopFlag::new();
        let (svc, deps) = (service(&h, ""), h.deps());
        let (stop2, loaded2) = (stop.clone(), loaded.clone());
        let service = std::thread::spawn(move || run_service(&svc, deps, &stop2, &move |_| Ok(loaded2.clone()), None));
        h.wait_for_log("[vpn:a] tunnel established");
        stop.set();
        assert_eq!(service.join().unwrap(), 0);
        let logs = h.logs();
        assert!(logs.iter().any(|m| m == "WARNING vpn.a: unknown key 'colour'"));
        assert!(logs.iter().any(|m| m == "starting 1 VPN supervisor(s): a"));
        assert!(logs.iter().any(|m| m == "[vpn:a] stopped"));
        assert_eq!(logs.last().unwrap(), "all VPNs stopped");
        assert_eq!(h.notifier.sent().last().unwrap(), "STATUS=stopped");
        assert!(h.spawner.all_children_gone());
    }

    #[test]
    fn prepare_runs_only_when_a_vpn_needs_the_vault() {
        for (vpn, expected) in [
            (json!({"name": "a", "enabled": true, "type": "openvpn", "config": "/x.ovpn"}), false),
            (json!({"name": "a", "enabled": true, "gateway": "g", "vault_item": "V"}), true),
        ] {
            let mut h = Harness::new();
            h.tun.dry_run = true;
            h.vault.add_login("V", "alice", "pw");
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = ran.clone();
            let prepare: Prepare = Box::new(move |beat| {
                beat();
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            });
            let loaded = conf(json!([vpn]));
            let code =
                run_service(&service(&h, ""), h.deps(), &StopFlag::new(), &move |_| Ok(loaded.clone()), Some(prepare));
            assert_eq!(code, 0);
            assert_eq!(ran.load(std::sync::atomic::Ordering::Relaxed), expected);
            assert!(h.logs().iter().any(|m| m.contains("DRY RUN — would run:")), "{:?}", h.logs());
            assert!(h.spawner.spawned().is_empty());
        }
    }

    #[test]
    fn args_lines_only_for_an_enabled_primary_vpn() {
        let on = conf(json!([{"enabled": true, "gateway": "gw.example", "port": 10443, "realm": "soc"}]));
        assert_eq!(args_lines(&on).unwrap(), ["gw.example:10443", "--realm=soc"]);
        let off = conf(json!([{"enabled": false, "gateway": "gw.example"}]));
        assert!(args_lines(&off).unwrap().is_empty());
        assert!(args_lines(&Config::default()).unwrap().is_empty());
        assert!(args_lines(&conf(json!([{"enabled": true, "gateway": "-x"}]))).is_err());
    }

    #[test]
    fn signal_names() {
        assert_eq!(signal_name(SIGTERM), "SIGTERM");
        assert_eq!(signal_name(SIGHUP), "SIGHUP");
        assert_eq!(signal_name(0), "a signal");
    }
}
