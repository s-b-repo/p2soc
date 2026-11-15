//! The reconnect policy, driven by scripted clients on a virtual clock: no
//! real sleeping, no real VPN client.

use super::*;
use crate::testing::{Harness, Script};
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;

const UP: &str = "INFO:   Tunnel is up and running.";
const CLOSED: &str = "INFO:   Closed connection to gateway.";
const AUTH: &str = "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.";
const CERT: &str = "ERROR:  Gateway certificate validation failed.";
const OVPN_UP: &str = "Initialization Sequence Completed";

fn fortinet() -> Value {
    json!({"enabled": true, "type": "fortinet", "gateway": "gw.example", "port": 443, "vault_item": "VPN"})
}

/// An OpenVPN entry with no vault item: the path with no credentials at all.
fn ovpn() -> Value {
    json!({"enabled": true, "type": "openvpn", "config": "/x.ovpn"})
}

fn harness() -> Harness {
    let h = Harness::new();
    h.vault.add_login("VPN", "alice", "hunter2");
    h
}

fn statuses(h: &Harness) -> Vec<String> {
    h.notifier.sent().into_iter().filter_map(|m| m.strip_prefix("STATUS=").map(str::to_string)).collect()
}

fn spawn_times(h: &Harness) -> Vec<f64> {
    h.spawner.spawned().iter().map(|s| s.at).collect()
}

// --- the verdict ----------------------------------------------------------------

#[test]
fn verdict_ranks_failures() {
    let mut s = AttemptState::default();
    assert_eq!(verdict(&s, 100.0, 60.0), Verdict::Dropped { stable: false, closed: false });
    s.saw.down = true;
    assert_eq!(verdict(&s, 100.0, 60.0), Verdict::Dropped { stable: false, closed: true });
    s.saw.cert = true;
    assert_eq!(verdict(&s, 100.0, 60.0), Verdict::CertFailed);
    s.saw.auth = true;
    assert_eq!(verdict(&s, 100.0, 60.0), Verdict::AuthFailed);
    s.mgmt_unreachable = true;
    assert_eq!(verdict(&s, 100.0, 60.0), Verdict::MgmtUnreachable);
}

#[test]
fn verdict_counts_a_tunnel_as_stable_only_past_the_threshold() {
    let up_at = |t| AttemptState { tunnel_up: true, up_since: Some(t), ..AttemptState::default() };
    assert_eq!(verdict(&up_at(50.0), 100.0, 60.0), Verdict::Dropped { stable: false, closed: false });
    assert_eq!(verdict(&up_at(40.0), 100.0, 60.0), Verdict::Dropped { stable: true, closed: false });
}

// --- backoff ----------------------------------------------------------------------

#[test]
fn a_short_lived_tunnel_does_not_reset_the_backoff() {
    // Reset at the floor, a link that survived 10s per try reconnected at the
    // floor forever: the backoff never climbed.
    let h = Harness::new();
    for _ in 0..3 {
        h.spawner.push(Script::new(&[OVPN_UP], 10.0, 1));
    }
    let mut sup = h.supervisor(ovpn());
    assert_eq!(h.run(&mut sup), 0);
    assert_eq!(
        h.logged("reconnecting in"),
        [
            "openvpn exited (1); reconnecting in 5s",
            "openvpn exited (1); reconnecting in 10s",
            "openvpn exited (1); reconnecting in 20s"
        ]
    );
    assert_eq!(spawn_times(&h), [0.0, 15.0, 35.0]);
    assert!(h.spawner.all_children_gone());
}

#[test]
fn a_stable_tunnel_does_reset_the_backoff() {
    let h = Harness::new();
    for up_for in [10.0, 10.0, 600.0, 10.0] {
        h.spawner.push(Script::new(&[OVPN_UP], up_for, 0));
    }
    let mut sup = h.supervisor(ovpn());
    h.run(&mut sup);
    let delays: Vec<String> =
        h.logged("reconnecting in").iter().map(|m| m.rsplit(' ').next().unwrap().to_string()).collect();
    assert_eq!(delays, ["5s", "10s", "5s", "10s"]);
}

#[test]
fn a_reported_drop_reads_connection_closed() {
    let h = harness();
    h.spawner.push(Script::new(&["INFO:   Connecting to gateway...", UP, CLOSED], 0.0, 1));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    assert_eq!(h.logged("reconnecting in"), ["connection closed; reconnecting in 5s"]);
    assert_eq!(
        statuses(&h)[..4],
        [
            "connecting to gw.example (attempt 1)",
            "connecting to gateway",
            "connected: tunnel is up",
            "disconnected; reconnecting in 5s"
        ]
    );
    assert_eq!(statuses(&h).last().unwrap(), "stopped");
    assert!(h.logs().iter().any(|m| m == "connecting to gw.example as 'alice' (attempt 1)"));
    assert!(h.logs().iter().any(|m| m == "tunnel established"));
    assert!(h.logs().iter().any(|m| m == &format!("[openfortivpn] {UP}")));
}

#[test]
fn progress_lines_never_count_as_a_drop() {
    let h = harness();
    h.spawner.push(Script::new(&["INFO:   Connecting to gateway..."], 0.0, 0));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    assert_eq!(h.logged("reconnecting in"), ["openfortivpn exited (0); reconnecting in 5s"]);
}

// --- lockout protection -------------------------------------------------------------

#[test]
fn a_rejected_login_holds_long_and_resyncs_the_vault() {
    let h = harness();
    h.spawner.push(Script::new(&[AUTH], 0.0, 1));
    h.spawner.push(Script::new(&[UP, CLOSED], 0.0, 0));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    // (The exit is noticed on the next 1s poll, hence the tolerance.)
    let times = spawn_times(&h);
    assert!((300.0..=301.0).contains(&(times[1] - times[0])), "{times:?}");
    assert!(statuses(&h).contains(&"authentication failed; fix the vault credentials (long backoff)".to_string()));
    assert!(h.logs().iter().any(|m| m == "AUTHENTICATION FAILED (fortinet, exit 1)."));
    assert!(h.logs().iter().any(|m| m == "  * check the username/password in vault item 'VPN'"));
    assert!(
        h.logs()
            .iter()
            .any(|m| m == "  NOT retrying for 300s — rapid retries with a bad password can LOCK the account")
    );
    // The fix may be a rotated secret: one re-sync, after the hold.
    assert_eq!(h.vault.refreshes.load(Ordering::Relaxed), 1);
    // The hold is not a network backoff: the next drop still starts at the floor.
    assert_eq!(h.logged("reconnecting in"), ["connection closed; reconnecting in 5s"]);
}

#[test]
fn a_certificate_failure_holds_long_without_touching_the_vault() {
    let mut h = harness();
    h.tun.cert_delay = 120.0;
    h.spawner.push(Script::new(&[CERT], 0.0, 1));
    h.spawner.push(Script::new(&[], 0.0, 0));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    let times = spawn_times(&h);
    assert!((120.0..=121.0).contains(&(times[1] - times[0])), "{times:?}");
    assert!(statuses(&h).contains(&"certificate validation failed (long backoff)".to_string()));
    assert!(h.logs().iter().any(|m| m == "CERTIFICATE VALIDATION FAILED (fortinet, exit 1)."));
    assert!(h.logs().iter().any(|m| m.contains("copy the sha256 digest")));
    assert_eq!(h.vault.refreshes.load(Ordering::Relaxed), 0);
}

#[test]
fn a_client_that_keeps_running_after_a_rejected_login_is_stopped() {
    // openfortivpn --persistent and openvpn auth-retry would otherwise resend
    // the rejected password on their own schedule, behind the hold's back.
    let h = harness();
    h.spawner.push(Script::hang(&[AUTH]));
    h.spawner.push(Script::new(&[], 0.0, 0));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    assert_eq!(h.spawner.children()[0].signals(), [sys::SIGTERM]);
    assert_eq!(h.logged("still running").len(), 1);
    assert!(h.logs().iter().any(|m| m == "AUTHENTICATION FAILED (fortinet, exit -15)."));
    let times = spawn_times(&h);
    assert!(times[1] - times[0] >= 300.0, "{times:?}");
}

#[test]
fn a_missing_one_time_code_never_becomes_a_blank_login() {
    let h = harness();
    let mut vpn = fortinet();
    vpn["otp_from_vault"] = json!(true);
    let mut sup = h.supervisor(vpn);
    h.clock.stop_after_waits(10, &sup.handle().stop_flag());
    sup.run();
    assert!(h.spawner.spawned().is_empty());
    assert_eq!(h.logged("WARNING OTP fetch from vault item 'VPN' failed").len(), 2);
    assert_eq!(h.logged("not attempting a blank-OTP login").len(), 1);
    assert!(statuses(&h).contains(&"could not retrieve OTP from vault item VPN".to_string()));
    // A secret added since the last sync must be found on the next try.
    assert_eq!(h.vault.refreshes.load(Ordering::Relaxed), 1);
    // The slow path, not the lockout hold: 2s between tries, then 60s.
    assert_eq!(h.clock.waits()[..3], [2.0, 5.0, 5.0]);
}

#[test]
fn a_vault_item_without_a_password_never_becomes_a_blank_login() {
    let h = Harness::new();
    h.vault.add_login("VPN", "alice", "");
    for vpn in [
        fortinet(),
        json!({"type": "inode", "gateway": "g", "vault_item": "VPN"}),
        json!({"type": "openvpn", "config": "/x.ovpn", "vault_item": "VPN"}),
    ] {
        let mut sup = h.supervisor(vpn);
        h.clock.stop_after_waits(h.clock.waits().len() + 3, &sup.handle().stop_flag());
        sup.run();
    }
    assert!(h.spawner.spawned().is_empty());
    assert_eq!(h.logged("has no password — not attempting a blank login").len(), 3);
}

// --- secrets ------------------------------------------------------------------------

#[test]
fn the_password_reaches_the_client_through_its_environment_only() {
    let h = harness();
    h.spawner.push(Script::new(&[UP], 0.0, 0));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    let spawn = &h.spawner.spawned()[0];
    assert_eq!(spawn.argv, ["openfortivpn", "gw.example:443", "-u", "alice", "--pinentry=/x/pinentry"]);
    assert_eq!(spawn.env, [("SOC_VPN_PASSWORD".to_string(), "hunter2".to_string())]);
    for dropped in ["SOC_VAULT_PASSWORD", "NOTIFY_SOCKET", "H3C_SVPN_PASSWORD", "SOC_VPN_OTP"] {
        assert!(spawn.env_remove.iter().any(|n| n == dropped), "{dropped} is passed on");
    }
    assert!(!spawn.debug.contains("hunter2"));
    assert!(!h.logs().join("\n").contains("hunter2"));
    assert!(!h.notifier.sent().join("\n").contains("hunter2"));
}

#[test]
fn the_one_time_code_goes_through_the_pinentry_not_argv() {
    let h = harness();
    h.vault.add_code("VPN", " 123456\n");
    h.spawner.push(Script::new(&[UP], 0.0, 0));
    let mut vpn = fortinet();
    vpn["otp_from_vault"] = json!(true);
    let mut sup = h.supervisor(vpn);
    h.run(&mut sup);
    let spawn = &h.spawner.spawned()[0];
    assert!(!spawn.argv.join(" ").contains("123456"), "{:?}", spawn.argv);
    assert!(spawn.env.contains(&("SOC_VPN_OTP".to_string(), "123456".to_string())));
    assert!(!h.logs().join("\n").contains("123456") && !spawn.debug.contains("123456"));
}

#[test]
fn the_legacy_otp_flag_is_opt_in_and_still_never_logged() {
    let mut h = harness();
    h.tun.otp_on_argv = true;
    h.vault.add_code("VPN", "123456");
    h.spawner.push(Script::new(&[UP], 0.0, 0));
    let mut vpn = fortinet();
    vpn["otp_from_vault"] = json!(true);
    let mut sup = h.supervisor(vpn);
    h.run(&mut sup);
    let spawn = &h.spawner.spawned()[0];
    assert_eq!(spawn.argv.last().unwrap(), "--otp=123456");
    assert!(!spawn.env.iter().any(|(name, _)| name == "SOC_VPN_OTP"));
    assert!(!h.logs().join("\n").contains("123456") && !spawn.debug.contains("123456"));
}

#[test]
fn the_inode_password_travels_in_the_environment() {
    let h = harness();
    h.spawner.push(Script::new(&["tunnel up: ip=10.0.0.2 mask=255.255.255.0", "[+] disconnecting..."], 0.0, 0));
    let mut sup = h
        .supervisor(json!({"type": "inode", "gateway": "g", "port": 3000, "config": "/c", "vault_item": "VPN",
                                      "domain": "system", "spa_key": "deadbeef"}));
    h.run(&mut sup);
    let spawn = &h.spawner.spawned()[0];
    assert_eq!(spawn.argv[..4], ["/c/svpn-connect.sh", "g:3000", "alice", "system"]);
    assert_eq!(spawn.env, [("H3C_SVPN_PASSWORD".to_string(), "hunter2".to_string())]);
    assert!(!spawn.debug.contains("deadbeef"));
    assert!(h.logs().iter().any(|m| m == "connecting iNode SSL-VPN (g) as 'alice' (attempt 1)"));
    assert_eq!(h.logged("reconnecting in"), ["connection closed; reconnecting in 5s"]);
}

#[test]
fn client_output_cannot_smuggle_terminal_escapes_into_the_journal() {
    let h = Harness::new();
    h.spawner.push(Script::new(&["AUTH_FAILED,\u{1b}[2Jowned\r", "   "], 0.0, 1));
    let mut sup = h.supervisor(ovpn());
    h.run(&mut sup);
    assert!(h.logs().iter().any(|m| m == "[openvpn] AUTH_FAILED,?[2Jowned"));
    assert!(!h.logs().iter().any(|m| m == "[openvpn]    "), "blank lines are not logged");
    assert!(h.logs().iter().any(|m| m == "AUTHENTICATION FAILED (openvpn, exit 1)."));
}

#[test]
fn a_hostile_vault_username_is_refused_before_any_login() {
    let h = Harness::new();
    h.vault.add_login("VPN", "al\nice", "pw");
    let mut sup = h.supervisor(fortinet());
    h.clock.stop_after_waits(1, &sup.handle().stop_flag());
    sup.run();
    assert!(h.spawner.spawned().is_empty());
    assert_eq!(h.logged("ERROR could not start openfortivpn: the vault username contains control characters").len(), 1);
    assert!(!h.logs().iter().any(|m| m.contains('\n')));
}

#[test]
fn an_empty_username_is_warned_about() {
    let h = Harness::new();
    h.vault.add_login("VPN", "", "pw");
    h.spawner.push(Script::new(&[], 0.0, 1));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    assert_eq!(h.logged("WARNING vault item 'VPN' has no username").len(), 2);
    assert_eq!(h.spawner.spawned().len(), 1);
}

// --- guards at connect time -----------------------------------------------------------

#[test]
fn an_option_looking_gateway_never_reaches_argv() {
    let h = harness();
    let mut vpn = fortinet();
    vpn["gateway"] = json!("--pppd-plugin=/tmp/evil.so");
    let mut sup = h.supervisor(vpn);
    h.clock.stop_after_waits(1, &sup.handle().stop_flag());
    sup.run();
    assert!(h.spawner.spawned().is_empty());
    assert_eq!(h.logged("ERROR could not start openfortivpn:").len(), 1);
    assert!(h.logged("ERROR could not start openfortivpn:")[0].contains("option injection"));
}

#[test]
fn no_new_login_once_a_stop_was_requested() {
    // The vault can take a while; a stop that arrives meanwhile must not be
    // followed by a fresh connection attempt.
    struct StoppingVault(Mutex<Option<StopFlag>>);
    impl CredSource for StoppingVault {
        fn creds(&self, _item: &str) -> Result<Login, CredError> {
            if let Some(stop) = &*lock(&self.0) {
                stop.set();
            }
            Ok(Login::new("alice", "pw"))
        }
        fn notes(&self, _item: &str) -> Result<String, CredError> {
            Ok(String::new())
        }
        fn code(&self, _item: &str) -> Result<String, CredError> {
            Err(CredError::NotFound("none".into()))
        }
    }
    let h = Harness::new();
    h.spawner.push(Script::hang(&[UP]));
    let vault = Arc::new(StoppingVault(Mutex::new(None)));
    let mut deps = h.deps();
    deps.vault = VaultAccess::new(vault.clone());
    let mut sup =
        Supervisor::new(crate::testing::dict(fortinet()), Role::standalone(), deps, h.tun.clone(), h.paths.clone());
    *lock(&vault.0) = Some(sup.handle().stop_flag());
    assert_eq!(sup.run(), 0);
    assert!(h.spawner.spawned().is_empty());
    assert_eq!(h.logs().last().unwrap(), "stopped");
}

#[test]
fn no_second_client_beside_one_that_cannot_be_killed() {
    struct Stuck;
    impl ChildProc for Stuck {
        fn pid(&self) -> u32 {
            4_194_305
        }
        fn exited(&self) -> bool {
            false
        }
        fn reap(&self) -> Option<i32> {
            None
        }
        fn signal_group(&self, _signal: i32) {}
        fn group_has_members(&self) -> Option<bool> {
            None
        }
    }
    let h = Harness::new();
    h.spawner.push(Script::new(&[OVPN_UP], 0.0, 0));
    let mut sup = h.supervisor(ovpn());
    sup.lingering = Some(Arc::new(Stuck));
    h.clock.stop_after_waits(3, &sup.handle().stop_flag());
    sup.run();
    assert!(h.spawner.spawned().is_empty(), "two clients would fight over the same routes and device");
    assert!(!h.logged("ERROR could not start openvpn: previous child is still running").is_empty());
    assert!(!h.logged("survived SIGKILL").is_empty());
}

// --- the vault ------------------------------------------------------------------------

#[test]
fn a_vault_outage_backs_off_instead_of_hammering_it() {
    let mut h = harness();
    h.tun.ready_timeout = 3600.0;
    h.vault.outage.store(usize::MAX, Ordering::Relaxed);
    let mut sup = h.supervisor(fortinet());
    // 3s, 6s, 12s, 24s and 48s of waiting, in heartbeat-sized pieces.
    h.clock.stop_after_waits(1 + 2 + 3 + 5 + 10, &sup.handle().stop_flag());
    sup.run();
    let delays: Vec<String> = h
        .logged("vault not ready (down); retrying in")
        .iter()
        .map(|m| m.split(' ').nth(6).unwrap().to_string())
        .collect();
    assert_eq!(delays, ["3s", "6s", "12s", "24s", "48s"]);
    assert!(statuses(&h).contains(&"waiting for the credentials vault".to_string()));
    assert!(h.spawner.spawned().is_empty());
}

#[test]
fn a_vault_that_recovers_is_used_and_its_backoff_starts_over() {
    let h = harness();
    h.vault.outage.store(2, Ordering::Relaxed);
    h.spawner.push(Script::new(&[UP], 0.0, 0));
    let mut sup = h.supervisor(fortinet());
    h.run(&mut sup);
    assert_eq!(h.logged("vault not ready").len(), 2);
    assert_eq!(h.spawner.spawned().len(), 1);
    assert_eq!(sup.vault_retry.next_delay(), 3.0);
}

#[test]
fn a_vault_outage_past_the_deadline_keeps_retrying_on_the_slow_path() {
    let mut h = harness();
    h.tun.ready_timeout = 10.0;
    h.vault.outage.store(usize::MAX, Ordering::Relaxed);
    let mut sup = h.supervisor(fortinet());
    h.clock.stop_after_waits(40, &sup.handle().stop_flag());
    sup.run();
    assert!(!h.logged("ERROR vault/creds not ready within 10s: down").is_empty());
    assert!(statuses(&h).contains(&"vault unavailable; retrying".to_string()));
    assert!(h.spawner.spawned().is_empty());
}

// --- hung attempts and health checks ----------------------------------------------------

#[test]
fn a_client_that_never_comes_up_is_restarted() {
    // Health checks only start once up, so a client hung before that was
    // waited on forever.
    let h = Harness::new();
    h.spawner.push(Script::hang(&["OpenVPN 2.6 starting"]));
    let mut sup = h.supervisor(ovpn());
    h.run(&mut sup);
    assert_eq!(h.logged("no tunnel after 300s; restarting openvpn").len(), 1);
    assert!(statuses(&h).contains(&"connect timed out; reconnecting".to_string()));
    assert_eq!(h.spawner.children()[0].signals(), [sys::SIGTERM]);
    assert!(h.spawner.all_children_gone());
}

#[test]
fn the_connect_timeout_spares_a_tunnel_whose_up_line_was_missed() {
    // A client whose log wording changed must not be killed for never saying "up".
    let h = Harness::new();
    h.prober.set_iface("tun0", true);
    h.spawner.push(Script::hang(&["some new wording"]));
    let mut sup = h.supervisor(ovpn());
    h.clock.stop_after_waits(400, &sup.handle().stop_flag());
    sup.run();
    assert!(h.logged("no tunnel after").is_empty());
    assert_eq!(h.spawner.spawned().len(), 1);
}

#[test]
fn a_zero_connect_timeout_disables_the_check() {
    let mut h = Harness::new();
    h.tun.connect_timeout = 0.0;
    h.spawner.push(Script::hang(&[]));
    let mut sup = h.supervisor(ovpn());
    h.clock.stop_after_waits(400, &sup.handle().stop_flag());
    sup.run();
    assert!(h.logged("no tunnel after").is_empty());
}

#[test]
fn a_stale_tunnel_is_restarted_after_enough_failed_health_checks() {
    let h = harness();
    h.prober.queue_tcp(&[Probe::Refused, Probe::Timeout, Probe::Ok]);
    h.spawner.push(Script::hang(&[UP]));
    let mut vpn = fortinet();
    vpn["ready_probe"] = json!("10.0.0.1:443");
    vpn["health_check_interval"] = json!(30);
    let mut sup = h.supervisor(vpn);
    h.run(&mut sup);
    let counts: Vec<String> = h
        .logged("health check: 10.0.0.1:443 unreachable")
        .iter()
        .map(|m| m.rsplit(' ').next().unwrap().to_string())
        .collect();
    // A good check in between starts the count over.
    assert_eq!(counts, ["(1/3)", "(2/3)", "(1/3)", "(2/3)", "(3/3)"]);
    assert_eq!(h.logged("health check failed — tunnel looks dead; restarting openfortivpn").len(), 1);
    assert!(statuses(&h).contains(&"health check failed; reconnecting".to_string()));
    assert_eq!(h.spawner.children()[0].signals(), [sys::SIGTERM]);
}

#[test]
fn health_checks_wait_for_the_tunnel_and_need_a_probe() {
    let h = Harness::new();
    h.spawner.push(Script::hang(&[]));
    let mut vpn = ovpn();
    vpn["ready_probe"] = json!("10.0.0.1:443");
    vpn["health_check_interval"] = json!(30);
    let mut sup = h.supervisor(vpn);
    h.clock.stop_after_waits(200, &sup.handle().stop_flag());
    sup.run();
    assert_eq!(h.prober.probes.load(Ordering::Relaxed), 0, "probed before the tunnel was up");
}

// --- config from the vault --------------------------------------------------------------

#[test]
fn a_gateway_held_only_in_the_vault_reaches_the_real_argv() {
    let h = Harness::new();
    h.vault.add_login("I", "alice", "pw");
    h.vault.add_notes("I", "# hq\ngateway = vpn.hq.example\nport=8443\nrealm=staff\nbogus_field = nope\n");
    h.spawner.push(Script::new(&[UP], 0.0, 0));
    let mut sup = h.supervisor(json!({"type": "fortinet", "vault_item": "I", "config_from_vault": true}));
    h.run(&mut sup);
    assert_eq!(h.spawner.spawned()[0].argv[..3], ["openfortivpn", "vpn.hq.example:8443", "--realm=staff"]);
    assert_eq!(h.logged("overlaid VPN field(s)"), ["overlaid VPN field(s) gateway, port, realm from vault item 'I'"]);
    assert!(h.files_on_disk().is_empty(), "an overlay must never touch disk");
    assert_eq!(sup.handle().entry().get("gateway"), Some(&json!("vpn.hq.example")));
    assert!(!sup.entry().contains_key("bogus_field"));
}

#[test]
fn a_vault_note_cannot_undo_the_split_tunnel_coercion() {
    // The overlay arrives after the routing policy was applied: a non-owner's
    // note could otherwise grab the default route from the owner.
    let h = Harness::new();
    h.vault.add_login("B", "bob", "pw");
    h.vault.add_notes("B", "set_routes=true\nhalf_internet_routes=true\nrealm=x\n");
    h.spawner.push(Script::new(&[UP], 0.0, 0));
    let entry = json!({"name": "dr", "type": "fortinet", "gateway": "b.example", "vault_item": "B",
                       "config_from_vault": true, "set_routes": false, "half_internet_routes": false});
    let mut sup = h.supervisor_as(entry, Role::managed(true));
    h.run(&mut sup);
    let argv = &h.spawner.spawned()[0].argv;
    assert!(argv.contains(&"--set-routes=0".to_string()) && argv.contains(&"--half-internet-routes=0".to_string()));
    assert!(argv.contains(&"--realm=x".to_string()));
}

#[test]
fn an_insecure_overlay_is_called_out() {
    let h = Harness::new();
    h.vault.add_notes("I", "insecure=true\n");
    let mut sup = h.supervisor(json!({"type": "inode", "gateway": "g", "vault_item": "I", "config_from_vault": true}));
    assert!(sup.materialize_config());
    assert_eq!(h.logged("turns OFF gateway certificate verification").len(), 1);
}

#[test]
fn an_unusable_vault_config_is_retried_rather_than_idled_on() {
    // Past the ready timeout this used to idle forever: an outage became
    // permanent, with the service looking healthy.
    let mut h = Harness::new();
    h.tun.ready_timeout = 0.0;
    h.vault.add_login("I", "alice", "pw");
    h.vault.add_notes("I", "gateway=vpn.hq.example\n");
    h.vault.outage.store(3, Ordering::Relaxed);
    h.spawner.push(Script::new(&[UP], 0.0, 0));
    let mut sup = h.supervisor(json!({"type": "fortinet", "vault_item": "I", "config_from_vault": true}));
    h.run(&mut sup);
    assert_eq!(h.logged("ERROR reading VPN config from vault item 'I': down").len(), 1);
    assert!(statuses(&h).contains(&"waiting for the vault (VPN config)".to_string()));
    assert!(statuses(&h).contains(&"could not load VPN config from the vault; retrying".to_string()));
    assert_eq!(h.spawner.spawned().len(), 1);
    // The 60s slow path sat between the failure and the retry.
    assert!(h.spawner.spawned()[0].at >= 60.0);
}

#[test]
fn empty_or_unusable_notes_are_reported() {
    let h = Harness::new();
    h.vault.add_notes("E", "  \n");
    h.vault.add_notes("J", "just some prose\nunknown=1\n");
    let mut sup = h.supervisor(json!({"type": "fortinet", "vault_item": "E", "config_from_vault": true}));
    assert!(!sup.materialize_config());
    assert_eq!(h.logged("ERROR vault item 'E' has no Notes content (the VPN config)").len(), 1);
    let mut sup = h.supervisor(json!({"type": "inode", "vault_item": "J", "config_from_vault": true}));
    assert!(!sup.materialize_config());
    assert_eq!(h.logged("ERROR vault item 'J' Notes had no usable KEY=VALUE lines for this inode VPN").len(), 1);
}

#[test]
fn an_openvpn_profile_from_the_vault_is_private_and_removed() {
    let h = Harness::new();
    h.vault.add_notes("O", "client\n<key>\nPRIVATE KEY\n</key>");
    let mut sup = h.supervisor(json!({"type": "openvpn", "vault_item": "O", "config_from_vault": true}));
    assert!(sup.materialize_config());
    let path = PathBuf::from(sup.entry().text("config"));
    assert!(path.starts_with(h.runtime_dir().join("soc-vpn")));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "client\n<key>\nPRIVATE KEY\n</key>\n");
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777, 0o700);
    assert!(!h.logs().join("\n").contains("PRIVATE KEY"));
    sup.teardown();
    assert!(h.files_on_disk().is_empty());
    assert!(!path.parent().unwrap().exists());
    sup.teardown();
}

#[test]
fn two_openvpn_supervisors_share_no_key() {
    let h = Harness::new();
    h.vault.add_notes("A", "KEY-A");
    h.vault.add_notes("B", "KEY-B");
    let mut a = h.supervisor(json!({"type": "openvpn", "vault_item": "A", "config_from_vault": true}));
    let mut b = h.supervisor(json!({"type": "openvpn", "vault_item": "B", "config_from_vault": true}));
    assert!(a.materialize_config() && b.materialize_config());
    let (pa, pb) = (a.entry().text("config"), b.entry().text("config"));
    assert_ne!(pa, pb);
    drop(b);
    assert_eq!(std::fs::read_to_string(&pa).unwrap(), "KEY-A\n");
    drop(a);
    assert!(h.files_on_disk().is_empty(), "dropping a supervisor removes its keys");
}

#[test]
fn a_non_owner_wireguard_conf_is_scrubbed_before_it_is_written() {
    let h = Harness::new();
    let conf = "[Interface]\nPrivateKey=K\n[Peer]\nAllowed IPs = 0.0.0.0/0, 10.50.0.0/16 # all\n";
    h.vault.add_notes("W", conf);
    let vpn = json!({"name": "w", "type": "wireguard", "config": "wg0", "vault_item": "W", "config_from_vault": true});
    let mut sup = h.supervisor_as(vpn.clone(), Role::managed(true));
    assert!(sup.materialize_config());
    let path = sup.entry().text("config");
    assert!(path.ends_with("/wg0.conf"));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[Interface]\nPrivateKey=K\n[Peer]\nAllowedIPs = 10.50.0.0/16\n"
    );
    assert_eq!(h.logged("REFUSED a catch-all AllowedIPs").len(), 1);
    drop(sup);

    // The route owner keeps its config verbatim.
    let mut owner = h.supervisor_as(vpn, Role::managed(false));
    assert!(owner.materialize_config());
    assert_eq!(std::fs::read_to_string(owner.entry().text("config")).unwrap(), conf);
}

#[test]
fn a_wireguard_name_that_is_no_interface_is_refused() {
    let h = Harness::new();
    h.vault.add_notes("W", "[Interface]\nPrivateKey=K\n");
    let mut sup =
        h.supervisor(json!({"type": "wireguard", "config": "-x", "vault_item": "W", "config_from_vault": true}));
    assert!(!sup.materialize_config());
    assert!(h.files_on_disk().is_empty());
}

#[test]
fn an_unwritable_runtime_dir_fails_closed() {
    let h = Harness::new();
    h.vault.add_notes("O", "PRIVATE KEY");
    std::fs::write(h.runtime_dir().join("soc-vpn"), "not a directory").unwrap();
    let mut sup = h.supervisor(json!({"type": "openvpn", "vault_item": "O", "config_from_vault": true}));
    assert!(!sup.materialize_config());
    assert_eq!(h.logged("ERROR writing VPN config:").len(), 1);
    assert_eq!(h.files_on_disk(), [h.runtime_dir().join("soc-vpn")]);
}

// --- OpenVPN management socket ----------------------------------------------------------

#[test]
fn an_unreachable_management_socket_gets_the_long_backoff() {
    // openvpn starts held and can never authenticate: a setup fault, not a
    // network drop to retry every few seconds.
    let h = harness();
    h.spawner.push(Script::hang(&[]));
    h.spawner.push(Script::new(&[], 0.0, 0));
    let mut sup = h.supervisor(json!({"type": "openvpn", "config": "/x.ovpn", "vault_item": "VPN"}));
    h.run(&mut sup);
    let first = &h.spawner.spawned()[0];
    let socket = &first.argv[4];
    assert_eq!(first.argv[..4], ["openvpn", "--config", "/x.ovpn", "--management"]);
    assert_eq!(first.argv[5..], ["unix", "--management-query-passwords", "--management-hold"]);
    assert!(socket.starts_with(&h.runtime_dir().join("soc-vpn").display().to_string()) && socket.ends_with(".sock"));
    assert!(first.env.is_empty(), "the OpenVPN login never enters the environment");
    assert!(h.logs().iter().any(|m| m == "OPENVPN MANAGEMENT SOCKET UNREACHABLE (openvpn, exit -15)."));
    assert!(statuses(&h).contains(&"OpenVPN management socket unreachable; backing off".to_string()));
    assert!(statuses(&h).contains(&"OpenVPN management socket unreachable (long backoff)".to_string()));
    let times = spawn_times(&h);
    assert!(times[1] - times[0] >= 300.0, "{times:?}");
    assert!(!h.logs().join("\n").contains("hunter2"));
    assert!(h.files_on_disk().is_empty());
}

/// Stand in for openvpn's management side: listen on the socket named in
/// the argv and play `script` to whoever connects.
fn fake_management(h: &Harness, script: &'static [&'static str]) -> Arc<Mutex<Vec<String>>> {
    use std::io::{BufRead, BufReader, Write};
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    h.spawner.on_spawn(move |argv| {
        let listener = std::os::unix::net::UnixListener::bind(&argv[4]).expect("bind the management socket");
        let sink = sink.clone();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("the supervisor connects");
            let mut reader = BufReader::new(conn.try_clone().expect("clone"));
            for step in script {
                match step.strip_prefix("expect ") {
                    Some(_) => {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        lock(&sink).push(line);
                    }
                    None => {
                        let _ = writeln!(conn, "{step}");
                    }
                }
            }
            // Hold the connection open until the supervisor hangs up.
            let mut rest = String::new();
            while reader.read_line(&mut rest).unwrap_or(0) > 0 {
                lock(&sink).push(std::mem::take(&mut rest));
            }
        });
    });
    received
}

fn ovpn_with_login() -> (Harness, Value) {
    let mut h = Harness::new();
    // The exchange happens in real time; keep the virtual connect timeout out of it.
    h.tun.connect_timeout = 0.0;
    h.vault.add_login("VPN", "alice", "pass word\"quoted");
    (h, json!({"type": "openvpn", "config": "/x.ovpn", "vault_item": "VPN"}))
}

#[test]
fn the_openvpn_login_is_answered_over_the_management_socket() {
    let (h, vpn) = ovpn_with_login();
    let received = fake_management(
        &h,
        &[
            ">HOLD:Waiting for hold release:0",
            "expect hold release",
            ">PASSWORD:Need 'Auth' username/password",
            "expect username",
            "expect password",
        ],
    );
    h.spawner.push(Script::hang(&[OVPN_UP]));
    let mut sup = h.supervisor(vpn);
    let handle = sup.handle();
    let runner = std::thread::spawn(move || sup.run());
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    while lock(&received).len() < 3 {
        assert!(std::time::Instant::now() < give_up, "the login never arrived");
        std::thread::sleep(Duration::from_millis(2));
    }
    handle.stop();
    assert_eq!(runner.join().unwrap(), 0);
    assert_eq!(
        lock(&received)[..3],
        ["hold release\n", "username \"Auth\" \"alice\"\n", "password \"Auth\" \"pass word\\\"quoted\"\n"]
    );
    let spawn = &h.spawner.spawned()[0];
    assert!(spawn.env.is_empty() && !spawn.argv.join(" ").contains("pass word"));
    assert!(!h.logs().join("\n").contains("pass word"));
    assert!(h.files_on_disk().is_empty(), "the management socket outlived the supervisor");
    assert!(h.logged("MANAGEMENT SOCKET UNREACHABLE").is_empty());
}

#[test]
fn a_login_rejected_over_the_management_socket_is_not_retried() {
    // With `auth-retry interact` openvpn asks again at once; answering would
    // resend the rejected password with no pause at all.
    let (h, vpn) = ovpn_with_login();
    let received = fake_management(
        &h,
        &[
            "expect hold release",
            ">PASSWORD:Need 'Auth' username/password",
            "expect username",
            "expect password",
            ">PASSWORD:Verification Failed: 'Auth'",
            ">PASSWORD:Need 'Auth' username/password",
        ],
    );
    h.spawner.push(Script::hang(&[]));
    let mut sup = h.supervisor(vpn);
    h.run(&mut sup);
    assert_eq!(h.spawner.children()[0].signals(), [sys::SIGTERM], "the client was left to retry by itself");
    assert!(h.logs().iter().any(|m| m == "AUTHENTICATION FAILED (openvpn, exit -15)."));
    assert!(statuses(&h).contains(&"authentication failed; fix the vault credentials (long backoff)".to_string()));
    // The hold ran its course before the next (here: refused) start.
    assert!(h.clock.now() >= 300.0);
    let received = lock(&received).clone();
    assert_eq!(received.len(), 3, "the login was sent more than once: {received:?}");
}

#[test]
fn an_openvpn_that_restarts_itself_is_stopped_instead_of_left_on_hold() {
    // After its own restart openvpn waits for another hold release that never
    // came: the tunnel stayed down while the supervisor believed it was up.
    let (h, vpn) = ovpn_with_login();
    fake_management(
        &h,
        &[">HOLD:Waiting for hold release:0", "expect hold release", ">HOLD:Waiting for hold release:5"],
    );
    h.spawner.push(Script::hang(&[OVPN_UP]));
    let mut sup = h.supervisor(vpn);
    h.run(&mut sup);
    assert_eq!(h.spawner.children()[0].signals(), [sys::SIGTERM]);
    assert_eq!(h.logged("openvpn restarted by itself").len(), 1);
    assert_eq!(h.logged("reconnecting in"), ["connection closed; reconnecting in 5s"]);
}

// --- dry run ----------------------------------------------------------------------------

fn dry() -> Harness {
    let mut h = harness();
    h.tun.dry_run = true;
    h
}

#[test]
fn dry_run_prints_the_command_and_starts_nothing() {
    let h = dry();
    assert_eq!(h.supervisor(fortinet()).run(), 0);
    assert_eq!(
        h.logs(),
        [
            "DRY RUN — would run: openfortivpn gw.example:443 -u alice --pinentry=/x/pinentry",
            "resolved user='alice'; password fed via /x/pinentry (not shown)"
        ]
    );
    assert!(h.spawner.spawned().is_empty() && h.spawner.oneshots().is_empty());
    assert!(h.notifier.sent().is_empty());
}

#[test]
fn dry_run_works_without_the_binary_and_masks_the_spa_key() {
    let h = dry();
    h.spawner.set_missing("/c/svpn-connect.sh");
    let mut sup = h.supervisor(json!({"type": "inode", "gateway": "g", "config": "/c", "vault_item": "VPN",
                                      "spa_key": "deadbeef"}));
    assert_eq!(sup.run(), 0);
    assert!(h.logs()[0].starts_with("DRY RUN — would run: /c/svpn-connect.sh g:443 alice -- "));
    assert!(h.logs()[0].contains("--spa-key <redacted>"));
    assert!(!h.logs().join("\n").contains("deadbeef"));
    assert_eq!(h.logs()[1], "resolved user='alice'; password fed via $H3C_SVPN_PASSWORD (not shown)");
}

#[test]
fn dry_run_can_check_a_gateway_that_only_the_vault_holds() {
    let h = dry();
    h.vault.add_notes("VPN", "gateway=vpn.hq.example\n");
    let mut sup = h.supervisor(json!({"type": "fortinet", "vault_item": "VPN", "config_from_vault": true}));
    assert_eq!(sup.run(), 0);
    assert!(h.logs().iter().any(|m| m.contains("would run: openfortivpn vpn.hq.example:443")));
}

#[test]
fn dry_run_reports_an_unloadable_overlay() {
    let h = dry();
    let mut sup = h.supervisor(json!({"type": "fortinet", "vault_item": "VPN", "config_from_vault": true}));
    assert_eq!(sup.run(), 0);
    assert_eq!(h.logs().last().unwrap(), "DRY RUN — could not load the VPN config from the vault");
}

#[test]
fn dry_run_reports_a_rejected_config_instead_of_looping() {
    let h = dry();
    let mut vpn = fortinet();
    vpn["realm"] = json!("-x");
    assert_eq!(h.supervisor(vpn).run(), 0);
    assert!(h.logs()[0].starts_with("DRY RUN — config rejected: vpn.realm"));
}

#[test]
fn dry_run_writes_no_openvpn_keys_and_creates_no_directory() {
    let h = dry();
    h.vault.add_notes("VPN", "PRIVATE KEY");
    let mut sup =
        h.supervisor(json!({"type": "openvpn", "config": "/x.ovpn", "vault_item": "VPN", "config_from_vault": true}));
    assert_eq!(sup.run(), 0);
    assert!(h.logs()[0].starts_with("DRY RUN — would run: openvpn --config /x.ovpn --management "));
    assert_eq!(h.logs()[1], "resolved user='alice'; password injected over the management socket (not shown)");
    assert!(std::fs::read_dir(h.runtime_dir()).unwrap().next().is_none(), "a config check left litter behind");
}

#[test]
fn dry_run_for_wireguard() {
    let h = dry();
    assert_eq!(h.supervisor(json!({"type": "wireguard", "config": "wg0"})).run(), 0);
    assert_eq!(h.logs(), ["DRY RUN — would run: wg-quick up wg0"]);
}

// --- start and stop -----------------------------------------------------------------------

#[test]
fn a_missing_binary_idles_with_a_status_instead_of_thrashing() {
    let mut h = harness();
    h.tun.watchdog_interval = 15.0;
    h.spawner.set_missing("openfortivpn");
    let mut sup = h.supervisor(fortinet());
    h.clock.stop_after_waits(2, &sup.handle().stop_flag());
    assert_eq!(sup.run(), 0);
    assert!(h.logs()[0].starts_with("FATAL: openfortivpn not found / not executable"));
    assert_eq!(statuses(&h), ["openfortivpn is not available"]);
    // Idle never waits longer than the watchdog interval.
    assert_eq!(h.clock.waits(), [15.0, 15.0]);
    assert!(h.notifier.sent().contains(&"WATCHDOG=1".to_string()));
}

#[test]
fn stop_terminates_the_client_and_reports_stopped() {
    let h = harness();
    h.spawner.push(Script::hang(&[UP]));
    let mut sup = h.supervisor(fortinet());
    let handle = sup.handle();
    let runner = std::thread::spawn(move || sup.run());
    h.wait_for_log("tunnel established");
    handle.stop();
    handle.signal_child();
    assert_eq!(runner.join().unwrap(), 0);
    let child = &h.spawner.children()[0];
    assert!(child.signals().contains(&sys::SIGTERM));
    assert!(h.spawner.all_children_gone(), "the client was not reaped");
    assert_eq!(h.logs().last().unwrap(), "stopped");
    assert_eq!(statuses(&h).last().unwrap(), "stopped");
    assert!(h.logged("reconnecting").is_empty());
}

#[test]
fn start_sweeps_what_a_killed_supervisor_left_behind() {
    let h = Harness::new();
    let mut dead = std::process::Command::new("true").spawn().unwrap();
    let pid = dead.id();
    dead.wait().unwrap();
    let root = h.runtime_dir().join("soc-vpn");
    std::fs::create_dir_all(root.join(format!("vpn-{pid}-1"))).unwrap();
    std::fs::write(root.join(format!("vpn-{pid}-1/wg0.conf")), "PrivateKey=SECRET\n").unwrap();
    std::fs::write(root.join(format!("openvpn-{pid}.ovpn")), "PRIVATE KEY\n").unwrap();
    h.spawner.push(Script::new(&[OVPN_UP], 0.0, 0));
    // A file-based profile: the sweep must not depend on using vault config.
    let mut sup = h.supervisor(ovpn());
    h.run(&mut sup);
    assert!(h.files_on_disk().is_empty());
}

#[test]
fn the_heartbeat_keeps_going_through_a_long_hold() {
    let h = harness();
    h.spawner.push(Script::new(&[AUTH], 0.0, 1));
    let mut sup = h.supervisor(fortinet());
    let handle = sup.handle();
    h.clock.stop_after_waits(30, &handle.stop_flag());
    sup.run();
    // Stopped mid-hold: the last beat is recent, not from before the hold.
    assert!(h.clock.now() - handle.beat() <= 5.0);
    assert!(h.clock.waits().iter().all(|w| *w <= 5.0));
}

// --- WireGuard ----------------------------------------------------------------------------

/// A fake `wg` / `wg-quick`: tracks whether the interface is up.
fn wireguard(h: &Harness, initially_up: bool, handshake: &'static str, down_rc: i32) {
    let mut up = initially_up;
    h.spawner.on_oneshot(move |argv| {
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        match args.as_slice() {
            ["wg", "show", _] => (if up { 0 } else { 1 }, String::new()),
            ["wg", "show", _, "latest-handshakes"] => (0, handshake.to_string()),
            ["wg-quick", "up", _] => {
                up = true;
                (0, String::new())
            }
            ["wg-quick", "down", _] => {
                if down_rc == 0 {
                    up = false;
                }
                (down_rc, "boom".to_string())
            }
            ["ip", "link", "delete", "dev", _] => {
                up = false;
                (0, String::new())
            }
            other => panic!("unexpected command {other:?}"),
        }
    });
}

fn wg_vpn() -> Value {
    json!({"type": "wireguard", "config": "wg0", "health_check_interval": 1, "health_check_failures": 1})
}

#[test]
fn wg_quick_up_alone_does_not_reset_the_backoff() {
    // `wg-quick up` succeeds without contacting the peer, so a dead peer used
    // to cycle the interface forever with no backoff at all.
    let h = Harness::new();
    wireguard(&h, false, "peerkey\t0", 0);
    let mut sup = h.supervisor(wg_vpn());
    h.clock.stop_after_waits(5, &sup.handle().stop_flag());
    assert_eq!(sup.run(), 0);
    assert_eq!(
        h.logged("reconnecting WireGuard in"),
        ["reconnecting WireGuard in 5s", "reconnecting WireGuard in 10s"]
    );
    assert_eq!(h.logged("WireGuard health check failed (1/1)").len(), 2);
    assert!(statuses(&h).contains(&"connecting WireGuard wg0".to_string()));
    assert!(statuses(&h).contains(&"connected: WireGuard up".to_string()));
    assert_eq!(statuses(&h).last().unwrap(), "stopped");
    // Teardown takes the interface down on the way out.
    assert_eq!(h.spawner.oneshots().last().unwrap(), &["wg-quick", "down", "wg0"]);
}

#[test]
fn a_healthy_wireguard_check_resets_the_backoff() {
    let h = Harness::new();
    wireguard(&h, false, "peerkey\t1700000000", 0);
    let mut sup = h.supervisor(wg_vpn());
    sup.backoff.next_delay();
    sup.backoff.next_delay();
    h.clock.stop_after_waits(3, &sup.handle().stop_flag());
    sup.run();
    assert!(h.logged("health check failed").is_empty());
    assert_eq!(sup.backoff.next_delay(), 5.0);
}

#[test]
fn a_ready_probe_replaces_the_handshake_check() {
    let h = Harness::new();
    h.prober.set_tcp(Probe::Ok);
    wireguard(&h, false, "peerkey\t0", 0);
    let mut vpn = wg_vpn();
    vpn["ready_probe"] = json!("10.9.0.1:443");
    let mut sup = h.supervisor(vpn);
    h.clock.stop_after_waits(3, &sup.handle().stop_flag());
    sup.run();
    assert!(h.logged("health check failed").is_empty());
    assert!(!h.spawner.oneshots().iter().any(|c| c.contains(&"latest-handshakes".to_string())));
}

#[test]
fn an_interface_left_up_by_a_crash_is_cycled_once() {
    let h = Harness::new();
    wireguard(&h, true, "peerkey\t1700000000", 0);
    let mut sup = h.supervisor(wg_vpn());
    h.clock.stop_after_waits(3, &sup.handle().stop_flag());
    sup.run();
    assert_eq!(h.logged("already up at start — cycling once").len(), 1);
    let ups = h.spawner.oneshots().iter().filter(|c| c[..2] == ["wg-quick", "up"]).count();
    assert_eq!(ups, 1);
}

#[test]
fn a_failed_down_is_followed_by_removing_the_device() {
    let h = Harness::new();
    wireguard(&h, false, "peerkey\t0", 1);
    let mut sup = h.supervisor(wg_vpn());
    h.clock.stop_after_waits(2, &sup.handle().stop_flag());
    sup.run();
    assert_eq!(h.logged("wg-quick down failed (rc 1): boom; force-removing wg0").len(), 1);
    assert!(h.spawner.oneshots().contains(&["ip", "link", "delete", "dev", "wg0"].map(String::from).to_vec()));
}

#[test]
fn a_failing_wg_quick_up_backs_off() {
    let h = Harness::new();
    h.spawner.on_oneshot(|argv| {
        if argv[0] == "wg-quick" && argv[1] == "up" { (1, "no such\ndevice".into()) } else { (1, String::new()) }
    });
    let mut sup = h.supervisor(wg_vpn());
    h.clock.stop_after_waits(3, &sup.handle().stop_flag());
    sup.run();
    assert_eq!(h.logged("wg-quick up failed").len(), 2);
    assert_eq!(h.logged("wg-quick up failed")[0], "wg-quick up failed (rc 1): no such | device; retrying in 5s");
    assert!(h.logged("wg-quick up failed")[1].ends_with("retrying in 10s"));
    assert!(statuses(&h).contains(&"wg-quick up failed; retrying".to_string()));
}

#[test]
fn a_wireguard_key_from_the_vault_survives_until_after_down() {
    let h = Harness::new();
    h.vault.add_notes("W", "[Interface]\nPrivateKey=K\n");
    let runtime = h.runtime_dir().to_path_buf();
    let seen_at_down = Arc::new(Mutex::new(Vec::new()));
    let seen = seen_at_down.clone();
    h.spawner.on_oneshot(move |argv| {
        if argv[0] == "wg-quick" && argv[1] == "down" {
            // wg-quick reads the .conf to take the interface down.
            lock(&seen).push(std::path::Path::new(&argv[2]).exists());
            assert!(argv[2].starts_with(&runtime.display().to_string()));
        }
        (if argv[0] == "wg" { 1 } else { 0 }, String::new())
    });
    let mut sup =
        h.supervisor(json!({"type": "wireguard", "config": "wg0", "vault_item": "W", "config_from_vault": true}));
    h.clock.stop_after_waits(2, &sup.handle().stop_flag());
    sup.run();
    assert_eq!(lock(&seen_at_down).last(), Some(&true));
    assert!(h.files_on_disk().is_empty(), "the key outlived the supervisor");
    assert!(!h.logs().join("\n").contains("PrivateKey"));
}

#[test]
fn missing_wireguard_tools_idle_with_a_status() {
    let h = Harness::new();
    h.spawner.set_missing("wg-quick");
    let mut sup = h.supervisor(wg_vpn());
    h.clock.stop_after_waits(1, &sup.handle().stop_flag());
    assert_eq!(sup.run(), 0);
    assert_eq!(statuses(&h), ["wg-quick is not installed"]);
    assert!(h.spawner.oneshots().is_empty());
}
