//! Supervise N independent VPN connections concurrently.
//!
//! Each enabled entry gets its own [`Supervisor`] on its own thread; the
//! manager owns only the lifecycle and the routing policy across them:
//!
//!  * split-tunnel by default — each VPN installs only its own routes;
//!  * at most one default-route owner. Every other VPN is *coerced*
//!    split-tunnel, so two VPNs can never both silently grab `0.0.0.0/0`;
//!  * a single VPN owns its route implicitly and keeps its own config.
//!
//! WireGuard is the sharp edge: wg-quick installs whatever its `.conf`
//! declares. A vault-sourced `.conf` of a non-owner is scrubbed of catch-all
//! routes before it is written (see [`crate::overlay::strip_catch_all`]); a
//! `.conf` already on disk is the operator's to scope.

use crate::driver::Paths;
use crate::proc::Worker;
use crate::status::{VpnState, vpn_state};
use crate::supervisor::{Deps, Handle, Role, Supervisor};
use crate::tunables::Tunables;
use crate::{Log, lock};
use serde_json::Value;
use soc_core::vpnargs::vpn_kind;
use soc_core::{Dict, DictExt, VpnKind};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Per-probe timeout on the status path. The service polls every VPN under
/// the systemd watchdog; a black-holed probe must not be able to starve the
/// heartbeat. A live tunnel's probe connects far inside this.
const STATUS_PROBE_TIMEOUT: f64 = 0.5;

/// The identity key of an entry. Config normalisation fills `name` for every
/// parsed entry; the fallback only covers a hand-built list.
pub fn name_of(entry: &Dict, idx: usize) -> String {
    let name = entry.text("name");
    if !name.is_empty() {
        name
    } else if idx == 0 {
        "vpn".into()
    } else {
        format!("vpn{}", idx + 1)
    }
}

/// Force a VPN that does not own the default route to split-tunnel, using
/// each backend's own lever:
///
///  * fortinet — `set_routes` and `half_internet_routes` off, so the gateway
///    cannot push a default route;
///  * openvpn — `set_routes` off (`--route-nopull`);
///  * inode — `split_tunnel` on, so a gateway requesting redirect-all cannot
///    capture the default route;
///  * wireguard — nothing in the entry can be changed; the operator is told
///    to scope `AllowedIPs`, and a vault-sourced `.conf` is scrubbed later.
pub fn coerce_split_tunnel(entry: &mut Dict, log: &dyn Fn(&str)) {
    let name = match entry.text("name") {
        name if name.is_empty() => "?".to_string(),
        name => name,
    };
    match vpn_kind(entry) {
        VpnKind::Fortinet => {
            if entry.truthy("set_routes") || entry.truthy("half_internet_routes") {
                log(&format!("[vpn:{name}] not the default-route owner — forcing split-tunnel (--set-routes=0)"));
            }
            entry.insert("set_routes".into(), Value::Bool(false));
            entry.insert("half_internet_routes".into(), Value::Bool(false));
        }
        VpnKind::Openvpn => {
            if entry.flag("set_routes", true) {
                log(&format!("[vpn:{name}] not the default-route owner — forcing split-tunnel (--route-nopull)"));
            }
            entry.insert("set_routes".into(), Value::Bool(false));
        }
        VpnKind::Wireguard => {
            log(&format!(
                "[vpn:{name}] WireGuard and NOT the default-route owner: its .conf MUST scope AllowedIPs (never \
                 0.0.0.0/0 or ::/0). The wall cannot rewrite an on-disk .conf — a catch-all here would hijack the \
                 default route from the owner."
            ));
        }
        VpnKind::Inode => {
            if !entry.flag("split_tunnel", true) {
                log(&format!("[vpn:{name}] not the default-route owner — forcing split-tunnel (--split-tunnel)"));
            }
            entry.insert("split_tunnel".into(), Value::Bool(true));
        }
    }
}

/// One entry the manager will run.
#[derive(Debug, Clone, PartialEq)]
pub struct Planned {
    pub name: String,
    /// A private copy, already coerced when not the owner.
    pub entry: Dict,
    pub owner: bool,
}

/// Decide the routing policy across the whole list and return the entries to
/// run. `only` restricts the result to one entry (a `forti-vpn@<name>`
/// instance) *after* the policy was decided, so that instance does not
/// mistake itself for the single VPN that owns the default route.
pub fn plan(vpns: &[Dict], only: &str, log: &dyn Fn(&str)) -> Vec<Planned> {
    let enabled: Vec<(usize, &Dict)> = vpns.iter().enumerate().filter(|(_, e)| e.truthy("enabled")).collect();
    let claims: Vec<String> =
        enabled.iter().filter(|(_, e)| e.truthy("default_route")).map(|(i, e)| name_of(e, *i)).collect();
    let owner = match claims.as_slice() {
        [one] => Some(one.clone()),
        [] => match enabled.as_slice() {
            // Exactly one VPN: nothing to fight over, so it keeps its own
            // full-tunnel config.
            [only] => Some(name_of(only.1, only.0)),
            _ => None,
        },
        many => {
            // Validation should have rejected this; refuse rather than let
            // two fight over the route.
            log(&format!(
                "ERROR multiple VPNs claim default_route ({}) — refusing all of them the default route; every \
                 VPN runs split-tunnel until exactly one owns it",
                many.join(", ")
            ));
            None
        }
    };
    // A single VPN's journal stays as quiet as it always was.
    if enabled.len() > 1 {
        match &owner {
            Some(name) => {
                log(&format!("routing: '{name}' owns the default route (full-tunnel); all other VPNs are split-tunnel"))
            }
            None => {
                log("routing: split-tunnel — no default-route owner; each VPN installs only its own routes (mark one \
                 default_route:true for catch-all traffic)")
            }
        }
    }
    let only = only.trim();
    let mut out = Vec::new();
    for (idx, entry) in enabled {
        let name = name_of(entry, idx);
        if !only.is_empty() && name != only {
            continue;
        }
        let mut entry = entry.clone();
        entry.insert("name".into(), Value::String(name.clone()));
        let is_owner = owner.as_deref() == Some(name.as_str());
        if !is_owner {
            coerce_split_tunnel(&mut entry, log);
        }
        out.push(Planned { name, entry, owner: is_owner });
    }
    out
}

/// Collapse per-VPN states to one for the indicator's main label: no enabled
/// entries → not configured; all online → online; otherwise offline.
/// `Connecting` counts as not online — the per-name breakdown shows it, but
/// the indicator has no amber state for the aggregate.
pub fn aggregate_state(states: impl IntoIterator<Item = VpnState>) -> VpnState {
    let mut any = false;
    for state in states {
        match state {
            VpnState::NotConfigured => {}
            VpnState::Online => any = true,
            VpnState::Offline | VpnState::Connecting => return VpnState::Offline,
        }
    }
    if any { VpnState::Online } else { VpnState::NotConfigured }
}

/// The growing delay between relaunches of a supervisor that died
/// unexpectedly. It stops a deterministically crashing entry from hot-looping
/// on a 1 GB board. There is deliberately no cap on the number of tries: the
/// wall runs unattended, so giving up would mean offline until someone
/// restarts it.
#[derive(Debug, Clone, PartialEq)]
pub struct Relaunch {
    delay: f64,
    crashes: u32,
}

impl Relaunch {
    const FIRST: f64 = 5.0;
    const MAX: f64 = 60.0;
    /// A run that lasted this long was healthy; its crash starts afresh.
    const STABLE: f64 = 600.0;
    /// The crash count at which to shout.
    const SHOUT: u32 = 3;

    pub fn new() -> Relaunch {
        Relaunch { delay: Relaunch::FIRST, crashes: 0 }
    }

    /// Record a crash of a run that lasted `ran_for` seconds; returns the
    /// delay before the relaunch, the crash count and whether to shout.
    pub fn crashed(&mut self, ran_for: f64) -> (f64, u32, bool) {
        if ran_for >= Relaunch::STABLE {
            *self = Relaunch::new();
        }
        self.crashes += 1;
        let delay = self.delay;
        self.delay = (self.delay * 2.0).min(Relaunch::MAX);
        (delay, self.crashes, self.crashes == Relaunch::SHOUT)
    }
}

impl Default for Relaunch {
    fn default() -> Self {
        Relaunch::new()
    }
}

/// Run a supervisor, relaunching it after any unexpected death for as long
/// as the manager runs. Never resurrects a VPN whose stop was requested. One
/// entry's crash loop stays inside its thread, so its siblings keep their
/// tunnels.
fn supervised_run(mut sup: Supervisor, deps: &Deps) {
    let handle = sup.handle();
    let mut relaunch = Relaunch::new();
    while !handle.is_stopping() {
        let started = deps.clock.now();
        match catch_unwind(AssertUnwindSafe(|| sup.run())) {
            Ok(_) => return,
            Err(panic) => {
                let what = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".into());
                (deps.log)(&format!("supervisor crashed: {what}"));
            }
        }
        if handle.is_stopping() {
            return;
        }
        let (delay, crashes, shout) = relaunch.crashed(deps.clock.now() - started);
        if shout {
            (deps.log)(&format!(
                "supervisor has crashed {crashes} times running — this VPN is down and will keep retrying every \
                 {:.0}s at most (see the journal above for the cause)",
                Relaunch::MAX
            ));
        }
        (deps.log)(&format!("relaunching supervisor in {delay:.0}s (crash {crashes})"));
        sup.sleep(delay);
    }
}

struct Running {
    name: String,
    handle: Handle,
    worker: Worker,
}

/// Owns one supervisor thread per enabled entry.
pub struct VpnManager {
    planned: Vec<Planned>,
    deps: Deps,
    tun: Tunables,
    paths: Paths,
    running: Mutex<Vec<Running>>,
}

impl VpnManager {
    /// `vpns` is the whole configured list; disabled entries are skipped.
    pub fn new(vpns: &[Dict], only: &str, deps: Deps, tun: Tunables, paths: Paths) -> VpnManager {
        let planned = plan(vpns, only, &*deps.log);
        VpnManager { planned, deps, tun, paths, running: Mutex::new(Vec::new()) }
    }

    /// The entries the manager runs, in config order.
    pub fn planned(&self) -> &[Planned] {
        &self.planned
    }

    pub fn names(&self) -> Vec<String> {
        self.planned.iter().map(|p| p.name.clone()).collect()
    }

    pub fn count(&self) -> usize {
        self.planned.len()
    }

    /// Start one supervisor thread per entry, slightly staggered so N vault
    /// unseals do not land at once. Idempotent.
    pub fn start(&self) {
        if !lock(&self.running).is_empty() {
            return;
        }
        if self.planned.is_empty() {
            (self.deps.log)("no enabled VPNs to start");
            return;
        }
        for planned in &self.planned {
            let name = planned.name.clone();
            let tag = format!("[vpn:{name}]");
            let outer = self.deps.log.clone();
            // Every line is attributable to its VPN; the log viewer filters
            // on this tag.
            let tagged: Log = Arc::new(
                move |msg: &str| {
                    if msg.starts_with(&tag) { outer(msg) } else { outer(&format!("{tag} {msg}")) }
                },
            );
            let deps = Deps { log: tagged, ..self.deps.clone() };
            let sup = Supervisor::new(
                planned.entry.clone(),
                Role::managed(!planned.owner),
                deps.clone(),
                self.tun.clone(),
                self.paths.clone(),
            );
            let handle = sup.handle();
            match Worker::spawn(&format!("vpn:{name}"), move || supervised_run(sup, &deps)) {
                Ok(worker) => lock(&self.running).push(Running { name, handle, worker }),
                Err(e) => (self.deps.log)(&format!("[vpn:{name}] ERROR could not start its supervisor thread: {e}")),
            }
            self.deps.clock.sleep(self.tun.start_stagger);
        }
    }

    /// Tear every supervisor down: signal stop, SIGTERM each client, join.
    /// The default grace (20s) leaves room inside systemd's stop timeout for a
    /// wedged supervisor's forced cleanup; past that systemd kills us and the
    /// keys wait for the next start's orphan sweep.
    pub fn stop(&self, grace: f64) {
        let mut running = std::mem::take(&mut *lock(&self.running));
        for r in &running {
            r.handle.stop();
            // Signal only: waiting per client here would delay the SIGTERM to
            // every other. Each thread does the escalation for its own.
            r.handle.signal_child();
        }
        let deadline = std::time::Instant::now() + crate::clock::secs(grace);
        for r in &mut running {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if !r.worker.join_timeout(left.max(Duration::from_millis(1))) {
                (self.deps.log)(&format!(
                    "WARNING vpn '{}' supervisor did not stop within the grace period; cleaning up for it",
                    r.name
                ));
                // The process exit would kill the thread before its own
                // teardown ran, leaving the key on disk and the client orphaned.
                r.handle.force_cleanup(2.0);
            }
        }
    }

    /// Wait for every supervisor thread to end (dry runs); true if all did.
    pub fn join(&self, timeout: f64) -> bool {
        let deadline = std::time::Instant::now() + crate::clock::secs(timeout);
        let mut running = lock(&self.running);
        let mut all = true;
        for r in running.iter_mut() {
            all &= r.worker.join_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
        }
        all
    }

    /// Per-name state, computed from the entry each supervisor actually runs
    /// (after coercion and any vault overlay, so `ready_probe` is the live
    /// one). `on_each` runs between probes so the caller can keep the
    /// watchdog fed however many probes stall.
    pub fn states(&self, on_each: &mut dyn FnMut()) -> Vec<(String, VpnState)> {
        let live: Vec<(String, Dict)> =
            lock(&self.running).iter().map(|r| (r.name.clone(), r.handle.entry())).collect();
        let mut out = Vec::with_capacity(self.planned.len());
        for planned in &self.planned {
            let entry = live.iter().find(|(name, _)| *name == planned.name).map(|(_, e)| e).unwrap_or(&planned.entry);
            out.push((planned.name.clone(), vpn_state(entry, STATUS_PROBE_TIMEOUT, &*self.deps.prober)));
            on_each();
        }
        out
    }

    /// Names of supervisors the unit must be restarted to recover: the thread
    /// died, or it has not beaten within `SOC_VPN_STALL_SECS`. A thread cannot
    /// be killed from inside the process, so all the caller can do is withhold
    /// the systemd watchdog. A stopping supervisor is not stalled.
    pub fn stalled(&self) -> Vec<String> {
        let now = self.deps.clock.now();
        lock(&self.running)
            .iter()
            .filter(|r| !r.handle.is_stopping())
            .filter(|r| r.worker.is_finished() || now - r.handle.beat() > self.tun.stall_secs)
            .map(|r| r.name.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::ChildProc;
    use crate::testing::{FakeSpawner, Harness, Script, dict};
    use serde_json::json;

    fn quiet(_: &str) {}

    fn entries(v: Value) -> Vec<Dict> {
        v.as_array().unwrap().iter().map(|e| dict(e.clone())).collect()
    }

    fn two_fortinet() -> Vec<Dict> {
        entries(json!([
            {"name": "hq", "enabled": true, "gateway": "a.example", "vault_item": "A", "default_route": true},
            {"name": "dr", "enabled": true, "gateway": "b.example", "vault_item": "B", "config_from_vault": true},
        ]))
    }

    #[test]
    fn only_enabled_entries_are_planned_and_named() {
        let vpns = entries(json!([
            {"name": "a", "enabled": true, "type": "openvpn", "config": "/a.ovpn"},
            {"name": "b", "enabled": false, "type": "openvpn", "config": "/b.ovpn"},
            {"enabled": true, "type": "openvpn", "config": "/c.ovpn"},
        ]));
        let names: Vec<String> = plan(&vpns, "", &quiet).into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["a", "vpn3"]);
        assert_eq!(name_of(&dict(json!({})), 0), "vpn");
    }

    #[test]
    fn a_single_vpn_keeps_full_tunnel_as_the_implicit_owner() {
        let vpns = entries(json!([{"name": "solo", "enabled": true, "gateway": "g", "vault_item": "V",
                                   "set_routes": true, "half_internet_routes": true}]));
        let planned = plan(&vpns, "", &|m| panic!("a single VPN must stay quiet, got {m:?}"));
        assert!(planned[0].owner);
        assert_eq!(planned[0].entry.get("set_routes"), Some(&json!(true)));
        assert_eq!(planned[0].entry.get("half_internet_routes"), Some(&json!(true)));
    }

    #[test]
    fn the_explicit_owner_keeps_its_route_and_others_are_split() {
        let vpns = entries(json!([
            {"name": "hq", "enabled": true, "gateway": "a", "vault_item": "A", "default_route": true, "set_routes": true},
            {"name": "ovpn", "enabled": true, "type": "openvpn", "config": "/x.ovpn"},
            {"name": "forti2", "enabled": true, "gateway": "b", "vault_item": "B", "set_routes": true,
             "half_internet_routes": true},
            {"name": "lab", "enabled": true, "type": "inode", "gateway": "g", "vault_item": "I", "split_tunnel": false},
        ]));
        let planned = plan(&vpns, "", &quiet);
        assert!(planned[0].owner && planned[0].entry.get("set_routes") == Some(&json!(true)));
        assert!(!planned[1].owner && planned[1].entry.get("set_routes") == Some(&json!(false)));
        assert_eq!(planned[2].entry.get("set_routes"), Some(&json!(false)));
        assert_eq!(planned[2].entry.get("half_internet_routes"), Some(&json!(false)));
        assert_eq!(planned[3].entry.get("split_tunnel"), Some(&json!(true)));
    }

    #[test]
    fn two_default_route_claims_grant_none() {
        let vpns = entries(json!([
            {"name": "a", "enabled": true, "gateway": "a", "vault_item": "A", "default_route": true, "set_routes": true},
            {"name": "b", "enabled": true, "gateway": "b", "vault_item": "B", "default_route": true, "set_routes": true},
        ]));
        let logs = Mutex::new(Vec::new());
        let planned = plan(&vpns, "", &|m| logs.lock().unwrap().push(m.to_string()));
        assert!(planned.iter().all(|p| !p.owner && p.entry.get("set_routes") == Some(&json!(false))));
        assert!(logs.into_inner().unwrap().iter().any(|m| m.contains("multiple VPNs claim default_route (a, b)")));
    }

    #[test]
    fn no_owner_among_several_means_all_split() {
        let vpns = entries(json!([
            {"name": "a", "enabled": true, "gateway": "a", "vault_item": "A", "set_routes": true},
            {"name": "w", "enabled": true, "type": "wireguard", "config": "wg0"},
        ]));
        let logs = Mutex::new(Vec::new());
        let planned = plan(&vpns, "", &|m| logs.lock().unwrap().push(m.to_string()));
        assert!(planned.iter().all(|p| !p.owner));
        let logs = logs.into_inner().unwrap();
        assert!(logs.iter().any(|m| m.contains("routing: split-tunnel")));
        assert!(logs.iter().any(|m| m.contains("[vpn:w] WireGuard and NOT the default-route owner")));
    }

    #[test]
    fn planning_never_mutates_the_callers_entries() {
        let vpns = two_fortinet();
        let before = vpns.clone();
        plan(&vpns, "", &quiet);
        assert_eq!(vpns, before);
    }

    #[test]
    fn a_template_instance_runs_one_vpn_but_keeps_the_routing_policy() {
        // forti-vpn@dr sees one entry; it must not take itself for the
        // implicit route owner.
        let planned = plan(&two_fortinet(), "dr", &quiet);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].name, "dr");
        assert!(!planned[0].owner);
        assert_eq!(planned[0].entry.get("set_routes"), Some(&json!(false)));
        assert!(plan(&two_fortinet(), "nope", &quiet).is_empty());
    }

    #[test]
    fn aggregate() {
        use VpnState::*;
        assert_eq!(aggregate_state([]), NotConfigured);
        assert_eq!(aggregate_state([NotConfigured]), NotConfigured);
        assert_eq!(aggregate_state([Online, Online]), Online);
        assert_eq!(aggregate_state([Online, NotConfigured]), Online);
        assert_eq!(aggregate_state([Online, Offline]), Offline);
        assert_eq!(aggregate_state([Online, Connecting]), Offline);
    }

    #[test]
    fn a_crashing_supervisor_is_never_abandoned() {
        let mut r = Relaunch::new();
        let seen: Vec<(f64, u32, bool)> = (0..7).map(|_| r.crashed(1.0)).collect();
        let delays: Vec<f64> = seen.iter().map(|s| s.0).collect();
        assert_eq!(delays, [5.0, 10.0, 20.0, 40.0, 60.0, 60.0, 60.0]);
        let shouts: Vec<u32> = seen.iter().filter(|s| s.2).map(|s| s.1).collect();
        assert_eq!(shouts, [3]);
    }

    #[test]
    fn a_crash_after_a_long_healthy_run_starts_the_backoff_again() {
        let mut r = Relaunch::new();
        r.crashed(1.0);
        r.crashed(1.0);
        assert_eq!(r.crashed(600.0), (5.0, 1, false));
    }

    fn manager(h: &Harness, vpns: Value) -> VpnManager {
        VpnManager::new(&entries(vpns), "", h.deps(), h.tun.clone(), h.paths.clone())
    }

    #[test]
    fn supervisors_run_tagged_and_stop_cleanly() {
        let h = Harness::new();
        h.spawner.push(Script::hang(&["Initialization Sequence Completed"]));
        let mgr = manager(&h, json!([{"name": "a", "enabled": true, "type": "openvpn", "config": "/x.ovpn"}]));
        assert_eq!(mgr.names(), ["a"]);
        mgr.start();
        mgr.start();
        h.wait_for_log("tunnel established");
        assert!(h.logs().iter().all(|m| m.starts_with("[vpn:a] ")), "{:?}", h.logs());
        assert!(mgr.stalled().is_empty());
        mgr.stop(5.0);
        assert!(h.logs().iter().any(|m| m == "[vpn:a] stopped"));
        assert_eq!(h.spawner.spawned().len(), 1);
        assert!(h.spawner.all_children_gone());
    }

    #[test]
    fn managed_supervisors_cannot_pet_systemd() {
        // N+1 independent pingers would let any one healthy thread hide a
        // wedged sibling.
        let mut h = Harness::new();
        h.tun.watchdog_interval = 1.0;
        h.spawner.push(Script::hang(&["Initialization Sequence Completed"]));
        let mgr = manager(&h, json!([{"name": "a", "enabled": true, "type": "openvpn", "config": "/x.ovpn"}]));
        mgr.start();
        h.wait_for_log("tunnel established");
        mgr.stop(5.0);
        assert!(!h.notifier.sent().iter().any(|m| m == "WATCHDOG=1"));
    }

    #[test]
    fn a_stale_heartbeat_or_a_dead_thread_is_a_stall_but_stopping_is_not() {
        let mut h = Harness::new();
        h.tun.connect_timeout = 0.0;
        h.spawner.push(Script::hang(&[]));
        let mgr = manager(&h, json!([{"name": "hq", "enabled": true, "type": "openvpn", "config": "/x.ovpn"}]));
        mgr.start();
        h.wait_for_log("connecting OpenVPN");
        assert!(mgr.stalled().is_empty());
        // The supervisor keeps beating on the virtual clock, so "stale" is
        // judged against a threshold nothing can meet.
        let strict = VpnManager { tun: Tunables { stall_secs: -1.0, ..h.tun.clone() }, ..manager(&h, json!([])) };
        *lock(&strict.running) = std::mem::take(&mut *lock(&mgr.running));
        assert_eq!(strict.stalled(), ["hq"]);
        lock(&strict.running)[0].handle.stop();
        assert!(strict.stalled().is_empty(), "a stopping supervisor is not stalled");
        strict.stop(5.0);
    }

    #[test]
    fn states_use_the_entry_the_supervisor_actually_runs() {
        let h = Harness::new();
        h.prober.set_tcp(crate::status::Probe::Ok);
        let mgr = manager(
            &h,
            json!([{"name": "a", "enabled": true, "type": "openvpn", "config": "/x.ovpn", "ready_probe": "10.0.0.1:443"},
                   {"name": "b", "enabled": true, "type": "openvpn", "config": "/y.ovpn"}]),
        );
        let mut between = 0;
        let states = mgr.states(&mut || between += 1);
        assert_eq!(states, [("a".to_string(), VpnState::Online), ("b".to_string(), VpnState::Offline)]);
        assert_eq!(between, 2);
        assert_eq!(aggregate_state(states.into_iter().map(|(_, s)| s)), VpnState::Offline);
    }

    #[test]
    fn stop_cleans_up_for_a_wedged_supervisor() {
        // Its thread dies with the process, so its own teardown never runs:
        // the key would stay on disk and the client would be orphaned.
        let h = Harness::new();
        let sup = h.supervisor(json!({"type": "openvpn", "config": "/x.ovpn"}));
        let handle = sup.handle();
        let key = crate::supervisor::test_access::write_secret(&handle, "wg0.conf", "PrivateKey=K");
        let child = FakeSpawner::stuck_child();
        crate::supervisor::test_access::set_child(&handle, child.clone());
        let gate = crate::clock::StopFlag::new();
        let wedged = gate.clone();
        let worker = Worker::spawn("wedged", move || {
            let _keep = sup;
            wedged.wait_timeout(Duration::from_secs(30));
        })
        .unwrap();
        let mgr = manager(&h, json!([]));
        lock(&mgr.running).push(Running { name: "w".into(), handle, worker });
        mgr.stop(0.05);
        assert!(!key.exists());
        assert!(child.exited());
        assert!(h.logs().iter().any(|m| m.contains("did not stop within the grace period")));
        gate.set();
    }
}
