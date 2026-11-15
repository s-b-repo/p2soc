//! Doctor, repair, seal, vault and the first-run / deploy plans, against fakes.

use common::*;
use soc_seal::MasterSource;
use soc_setup::config::vault_items;
use soc_setup::deploy::{DeployPlan, DeployStep};
use soc_setup::doctor::{Doctor, DoctorInputs};
use soc_setup::envfile::load_env_file;
use soc_setup::firstrun::{FirstRunPlan, FirstRunStep};
use soc_setup::paths::{Target, drop_marker, is_configured, mark_configured};
use soc_setup::repair::{Repair, RepairInputs};
use soc_setup::seal::{SealRequest, pin_banner, pin_display, seal_master};
use soc_setup::vault::{Creds, LoginCred, LoginJob, push_config_to_vault, store_credentials, write_logins};
use soc_setup::{Status, render_soc_env};
use soc_sys::run::argv;
use std::path::PathBuf;
use zeroize::Zeroizing;

mod common;

fn doctor_inputs(dir: &TempDir, soc_env: &[(&str, &str)], panels: Option<&str>) -> DoctorInputs {
    let paths = paths_in(dir);
    let config = match panels {
        Some(y) => soc_core::load_str(y, "t").map_err(|e| e.to_string()),
        None => Err("no config".into()),
    };
    DoctorInputs {
        target: Target::Pi,
        env_read: (paths.soc_env.clone(), "test".into()),
        panels_read: (paths.panels_installed.clone(), "test".into()),
        soc_env: env(soc_env),
        config,
        process_kiosk_user: None,
        repo_root: dir.0.clone(),
        paths,
    }
}

fn doctor(inputs: DoctorInputs, rig: &Rig) -> soc_setup::Report {
    let mut d = Doctor::new(inputs);
    d.check_venv = false;
    d.run(&rig.host())
}

#[test]
fn doctor_flags_missing_pieces_and_exits_nonzero() {
    let dir = TempDir::new("doc1");
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "litebw")], None), &rig);
    assert_eq!(rep.find("litebw (Vaultwarden client)").unwrap().status, Status::Fail);
    assert_eq!(rep.find("display stack (SOC_SESSION=auto)").unwrap().detail, "no display stack");
    assert_eq!(rep.find("panels.yaml parses").unwrap().status, Status::Fail);
    assert_eq!(rep.find("Vaultwarden reachable").unwrap().status, Status::Warn);
    assert_eq!(rep.find("vault master password source").unwrap().status, Status::Fail);
    assert_eq!(rep.exit_code(), 1);
    assert!(rep.summary().contains("run: soc-wall setup repair"));
    assert!(rep.notes.iter().any(|n| n.contains("not fully installed")));
}

#[test]
fn doctor_all_good_on_a_healthy_box() {
    let dir = TempDir::new("doc2");
    let mut probe = FakeProbe::with_bins(&["litebw", "labwc", "sudo"]);
    probe.alive = true;
    probe.users.insert("soc".into());
    probe.dirs.insert("/opt/soc-display".into());
    let rig = Rig::new(probe);
    *rig.seal.sealed.borrow_mut() = Some(("m".into(), "1".into()));
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "litebw")], Some(PANELS)), &rig);
    assert_eq!(rep.find("panels.yaml parses").unwrap().detail, "2 panels");
    assert!(rep.find("vault master password source").unwrap().detail.starts_with("sealed + unseals on this host"));
    // sudo present but no drop-in: a warning, not a failure.
    assert_eq!(rep.find("reconnect sudoers rule").unwrap().status, Status::Warn);
    assert_eq!(rep.fails(), 0, "{}", rep.render());
    assert_eq!(rep.exit_code(), 0);
    assert!(rep.notes.is_empty());
}

#[test]
fn doctor_refuses_a_plaintext_master_and_reports_unseal_failure() {
    let dir = TempDir::new("doc3");
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "litebw"), ("SOC_VAULT_PASSWORD", "x")], None), &rig);
    assert_eq!(
        rep.find("vault master password source").unwrap().detail,
        "plaintext SOC_VAULT_PASSWORD present in soc.env"
    );
    let mut rig = Rig::new(FakeProbe::with_bins(&[]));
    rig.seal.unseal_error = Some("auth failed".into());
    *rig.seal.sealed.borrow_mut() = Some(("m".into(), "1".into()));
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "litebw")], None), &rig);
    assert!(
        rep.find("vault master password source").unwrap().detail.contains("sealed but cannot unseal (auth failed)")
    );
}

#[test]
fn doctor_checks_every_vpn_and_the_tunnel() {
    let dir = TempDir::new("doc4");
    let yaml = "display: {auto: true}
panels:
  - {id: t1, engine: webkit, mode: tunnel, grid: [0, 0], tunnel: {local_port: 8443, remote_host: 10.0.0.5, remote_port: 443}}
tunnel: {enabled: true, jump_host: jump.example.net, identity: '~/.ssh/soc_tunnel'}
vpns:
  - {name: a, type: fortinet, enabled: true, gateway: g1.example.net, vault_item: V1}
  - {name: b, type: openvpn, enabled: true, config: /etc/openvpn/b.ovpn, vault_item: V2}
  - {name: c, type: wireguard, enabled: false}
";
    let rig = Rig::new(FakeProbe::with_bins(&["openvpn"]));
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "dev")], Some(yaml)), &rig);
    assert_eq!(rep.find("VPN client (fortinet) [a]").unwrap().detail, "openfortivpn not installed");
    assert_eq!(rep.find("VPN client (openvpn) [b]").unwrap().status, Status::Ok);
    assert!(rep.find("VPN client (wireguard) [c]").is_none(), "disabled VPNs are not checked");
    assert_eq!(rep.find("autossh (SSH jump-host tunnel)").unwrap().status, Status::Fail);
    assert_eq!(rep.find("tunnel identity key").unwrap().detail, "missing: ~/.ssh/soc_tunnel");
    assert!(rep.find("Vaultwarden reachable").is_none(), "dev backend has no vault checks");
}

#[test]
fn doctor_env_perms_and_units() {
    let dir = TempDir::new("doc5");
    let mut probe = FakeProbe::with_bins(&["litebw", "labwc", "systemctl"]);
    probe.systemd = true;
    probe.modes.insert(dir.join("soc.env"), 0o666);
    let mut rig = Rig::new(probe);
    rig.runner = FakeRunner::new(|a| {
        Ok(out(0, if a.last().map(String::as_str) == Some("vaultwarden") { "active\n" } else { "inactive\n" }))
    });
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "dev")], None), &rig);
    let p = rep.find("perms soc.env").unwrap();
    assert_eq!((p.status, p.detail.as_str()), (Status::Warn, "0o666"));
    assert!(p.fix.starts_with("chmod 644 "));
    assert_eq!(rep.find("unit vaultwarden").unwrap().status, Status::Ok);
    assert_eq!(rep.find("unit forti-vpn").unwrap().detail, "inactive");
}

#[test]
fn doctor_sudoers_probes_through_the_kiosk_user_as_root() {
    let dir = TempDir::new("doc6");
    let mut probe = FakeProbe::with_bins(&["sudo", "litebw", "labwc"]);
    probe.root = true;
    probe.user = "root".into();
    probe.paths.insert("/etc/sudoers.d/soc-wall-restart".into());
    let mut rig = Rig::new(probe);
    rig.runner = FakeRunner::new(|a| Ok(out(i32::from(a.first().map(String::as_str) == Some("id")), "")));
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "dev")], None), &rig);
    assert!(rep.find("reconnect sudoers rule").unwrap().detail.contains("kiosk user 'soc' not created yet"));
    let mut rig = Rig::new(FakeProbe { root: true, user: "root".into(), ..FakeProbe::with_bins(&["sudo"]) });
    rig.probe.paths.insert("/etc/sudoers.d/soc-wall-restart".into());
    let rep = doctor(doctor_inputs(&dir, &[("SOC_VAULT_BACKEND", "dev")], None), &rig);
    assert!(rep.find("reconnect sudoers rule").unwrap().detail.contains("sudo -n systemctl restart works"));
    assert!(
        rig.runner
            .joined()
            .iter()
            .any(|c| c.starts_with("sudo -u soc -n -l /usr/bin/systemctl restart forti-vpn.service"))
    );
}

#[test]
fn repair_records_commands_and_is_dry_run_safe() {
    let dir = TempDir::new("rep1");
    let paths = paths_in(&dir);
    std::fs::write(&paths.soc_env, "SOC_VAULT_BACKEND=litebw\n").unwrap();
    let mut rig = Rig::new(FakeProbe::with_bins(&["apt-get", "litebw"]));
    rig.runner = FakeRunner::new(|_| Ok(out(1, ""))); // venv probe fails
    let mut r = Repair::new(RepairInputs::load(Target::Pi, paths.clone()));
    r.opts.dry_run = true;
    let res = r.run(&rig.host());
    let cmds: Vec<String> = res.cmds.iter().map(|c| c.join(" ")).collect();
    assert!(cmds.iter().any(|c| c.starts_with("python3 -m venv --system-site-packages")));
    assert!(cmds.iter().any(|c| c.contains("--only-binary=:all: cryptography")));
    assert!(cmds.contains(&"sudo ./install.sh --deps-only".to_string()));
    assert!(cmds.iter().any(|c| c.starts_with("litebw config set pinentry ")));
    assert!(!paths.secret_dir.exists(), "dry run creates nothing");
    // Only the venv probe actually ran.
    assert_eq!(rig.runner.calls.borrow().len(), 1);
    assert!(res.report.notes.iter().any(|n| n.contains("fresh box")));
}

#[test]
fn repair_creates_the_secret_dir_0700_and_the_tunnel_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("rep2");
    let mut paths = paths_in(&dir);
    paths.panels_installed = dir.join("p.yaml");
    std::fs::write(&paths.soc_env, "SOC_VAULT_BACKEND=litebw\n").unwrap();
    let key = dir.join("keys/tunnel");
    let yaml = format!(
        "display: {{auto: true}}\npanels:\n  - {{id: t1, engine: webkit, mode: tunnel, grid: [0, 0], tunnel: {{local_port: 8443, remote_host: 10.0.0.5, remote_port: 443}}}}\ntunnel: {{enabled: true, jump_host: j.example.net, identity: '{}'}}\n",
        key.display()
    );
    std::fs::write(&paths.panels_installed, yaml).unwrap();
    let mut probe = FakeProbe::with_bins(&[]);
    probe.root = true;
    probe.paths.insert(paths.soc_env.clone());
    let rig = Rig::new(probe);
    let mut r = Repair::new(RepairInputs::load(Target::Pi, paths.clone()));
    r.opts.venv = false;
    let res = r.run(&rig.host());
    assert_eq!(std::fs::metadata(&paths.secret_dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(res.cmds.iter().any(|c| c[0] == "ssh-keygen" && c.contains(&key.display().to_string())));
    assert!(res.report.find("tunnel key authorization").unwrap().detail.contains("j.example.net"));
    assert_eq!(std::fs::metadata(&paths.soc_env).unwrap().permissions().mode() & 0o777, 0o644);
}

fn req<'a>(
    master: &'a str,
    source: MasterSource,
    paths: &'a soc_setup::paths::SetupPaths,
    env: &'a soc_setup::SocEnv,
    dry: bool,
) -> SealRequest<'a> {
    SealRequest { master, source, pin: None, paths, soc_env: env, backend: "dev", dry }
}

#[test]
fn seal_auto_seals_records_auto_and_scrubs_plaintext() {
    let dir = TempDir::new("seal1");
    let paths = paths_in(&dir);
    std::fs::write(
        &paths.soc_env,
        "SOC_VAULT_BACKEND=rbw\nSOC_VAULT_PASSWORD=plain\nSOC_PINENTRY=/x/pinentry-soc.sh\n",
    )
    .unwrap();
    let soc_env = load_env_file(&paths.soc_env);
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    let mut rq = req("M-pw", MasterSource::Auto, &paths, &soc_env, false);
    rq.backend = "rbw";
    let out = seal_master(&rq, &rig.host()).unwrap();
    assert_eq!(out.pin.as_deref().map(String::as_str), Some("12345678"));
    assert_eq!(rig.seal.sealed.borrow().as_ref().unwrap().0, "M-pw");
    let after = std::fs::read_to_string(&paths.soc_env).unwrap();
    assert!(!after.contains("SOC_VAULT_PASSWORD") && after.contains("SOC_MASTER_SOURCE=auto"));
    assert!(after.contains(&format!("SOC_PINENTRY={}", paths.pinentry.display())));
    assert!(!after.contains("M-pw") && !after.contains("plain"));
}

#[test]
fn seal_dry_run_previews_the_pin_and_changes_nothing() {
    let dir = TempDir::new("seal2");
    let paths = paths_in(&dir);
    let soc_env = env(&[]);
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    let mut rq = req("M", MasterSource::Sealed, &paths, &soc_env, true);
    rq.pin = Some("987654");
    let out = seal_master(&rq, &rig.host()).unwrap();
    assert_eq!(out.pin.as_deref().map(String::as_str), Some("987654"));
    assert!(rig.seal.sealed.borrow().is_none());
}

#[test]
fn seal_refuses_empty_master_and_missing_secret_tool() {
    let dir = TempDir::new("seal3");
    let paths = paths_in(&dir);
    let soc_env = env(&[]);
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    let e = seal_master(&req("", MasterSource::Sealed, &paths, &soc_env, false), &rig.host()).unwrap_err();
    assert_eq!(e.0, "no master password entered — nothing sealed");
    let e = seal_master(&req("m", MasterSource::SecretService, &paths, &soc_env, false), &rig.host()).unwrap_err();
    assert!(e.0.starts_with("secret-tool (libsecret) is not on PATH"));
}

#[test]
fn seal_secret_service_stores_verifies_and_records() {
    let dir = TempDir::new("seal4");
    let paths = paths_in(&dir);
    std::fs::write(&paths.soc_env, "SOC_VAULT_BACKEND=litebw\n").unwrap();
    let soc_env = load_env_file(&paths.soc_env);
    let mut rig = Rig::new(FakeProbe::with_bins(&["litebw"]));
    rig.seal.secret_tool = true;
    let mut rq = req("wallet-pw", MasterSource::SecretService, &paths, &soc_env, false);
    rq.backend = "litebw";
    let out = seal_master(&rq, &rig.host()).unwrap();
    assert!(out.pin.is_none());
    assert_eq!(rig.seal.wallet.borrow().as_deref(), Some("wallet-pw"));
    assert!(std::fs::read_to_string(&paths.soc_env).unwrap().contains("SOC_MASTER_SOURCE=secret-service"));
    assert!(rig.runner.joined().iter().any(|c| c.starts_with("litebw config set pinentry")));
}

#[test]
fn env_source_only_records_the_choice() {
    let dir = TempDir::new("seal5");
    let paths = paths_in(&dir);
    std::fs::write(&paths.soc_env, "A=1\n").unwrap();
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    let soc_env = env(&[]);
    let out = seal_master(&req("", MasterSource::Env, &paths, &soc_env, false), &rig.host()).unwrap();
    assert!(out.pin.is_none());
    assert_eq!(std::fs::read_to_string(&paths.soc_env).unwrap(), "A=1\nSOC_MASTER_SOURCE=env\n");
}

#[test]
fn pin_is_shown_spaced() {
    assert_eq!(pin_display("12345"), "1  2  3  4  5");
    let b = pin_banner("1234");
    assert_eq!(b[0], "YOUR ONE-TIME PIN");
    assert_eq!(b[2], "        1  2  3  4");
}

#[test]
fn real_seal_round_trips_through_soc_seal() {
    use soc_setup::host::{RealSeal, SealBackend};
    let dir = TempDir::new("real");
    let s = RealSeal { machine_id: Some("test-host".into()), secret_tool: soc_seal::SecretTool::absent() };
    let sd = dir.join("secret");
    assert!(!s.is_sealed(&sd));
    s.seal(&sd, "M-pw", "123456").unwrap();
    assert!(s.is_sealed(&sd));
    assert_eq!(s.unseal(&sd).unwrap().as_str(), "M-pw");
    assert!(s.available_sources(&sd).contains(&"sealed".to_string()));
    assert_eq!(s.gen_pin().unwrap().len(), 8);
}

fn items() -> Vec<soc_setup::config::VaultItem> {
    vault_items(&soc_core::load_str(PANELS, "t").unwrap())
}

fn job<'a>(items: &'a [soc_setup::config::VaultItem], creds: &'a Creds, placeholders: bool, dry: bool) -> LoginJob<'a> {
    LoginJob { url: "http://v", email: "a@b.c", master: "m", items, creds, placeholders, dry }
}

#[test]
fn reseeding_never_blanks_an_existing_login() {
    let rig = Rig::new(FakeProbe::default());
    rig.vault.log.borrow_mut().existing = vec!["SOC Panel 1".into()];
    let it = items();
    let res = write_logins(&rig.host(), &job(&it, &Creds::new(), true, false));
    assert!(res.ok);
    let log = rig.vault.log.borrow();
    assert_eq!(log.connects, 1, "one session for the whole run");
    assert_eq!(log.writes.len(), 1);
    assert_eq!(log.writes[0].0, "SOC Panel 2");
    assert_eq!((log.writes[0].1.as_str(), log.writes[0].2.as_str()), ("", ""));
    assert_eq!(log.writes[0].3.as_deref(), Some("http://10.0.0.2/"));
}

#[test]
fn supplied_creds_overwrite_even_an_existing_item() {
    let rig = Rig::new(FakeProbe::default());
    rig.vault.log.borrow_mut().existing = vec!["SOC Panel 1".into()];
    let mut creds = Creds::new();
    creds.insert("SOC Panel 1".into(), LoginCred::new("u", "p"));
    let it = items();
    let res = write_logins(&rig.host(), &job(&it, &creds, false, false));
    assert!(res.ok && res.changed);
    let log = rig.vault.log.borrow();
    assert_eq!(log.writes.len(), 1);
    assert_eq!((log.writes[0].1.as_str(), log.writes[0].2.as_str()), ("u", "p"));
}

#[test]
fn dry_run_and_total_failure_are_reported() {
    let rig = Rig::new(FakeProbe::default());
    let it = items();
    let res = write_logins(&rig.host(), &job(&it, &Creds::new(), true, true));
    assert!(res.ok && res.detail.starts_with("would seed: SOC Panel 1"));
    assert_eq!(rig.vault.log.borrow().connects, 0, "no network in a dry run");
    let mut rig = Rig::new(FakeProbe::default());
    rig.vault.fail_connect = Some("login rejected".into());
    let res = write_logins(&rig.host(), &job(&it, &Creds::new(), true, false));
    assert!(!res.ok);
    assert_eq!(res.detail, "seeded 0/2 — login rejected");
}

#[test]
fn store_credentials_gates_on_backend_and_master() {
    let rig = Rig::new(FakeProbe::default());
    let cfg = soc_core::load_str(PANELS, "t").unwrap();
    let dev = env(&[("SOC_VAULT_BACKEND", "dev")]);
    assert!(store_credentials(&rig.host(), &dev, &cfg, Some("m"), &Creds::new(), false).detail.contains("'dev'"));
    let real = env(&[("SOC_VAULT_BACKEND", "litebw"), ("SOC_VAULT_URL", "http://v"), ("SOC_VAULT_EMAIL", "a@b.c")]);
    let r = store_credentials(&rig.host(), &real, &cfg, None, &Creds::new(), false);
    assert!(r.detail.starts_with("need the Vaultwarden URL"), "not sealed -> no placeholder master");
    assert_eq!(rig.vault.log.borrow().connects, 0);
    *rig.seal.sealed.borrow_mut() = Some(("sealed-m".into(), "1".into()));
    let mut creds = Creds::new();
    creds.insert("SOC Panel 2".into(), LoginCred::new("u2", "p2"));
    let r = store_credentials(&rig.host(), &real, &cfg, None, &creds, false);
    assert!(r.ok);
    let log = rig.vault.log.borrow();
    assert_eq!(log.writes.len(), 1, "items without an entry are skipped, never blanked");
}

#[test]
fn push_config_writes_the_note_into_the_config_item() {
    let rig = Rig::new(FakeProbe::default());
    let cfg = soc_core::load_str(PANELS, "t").unwrap();
    let e = env(&[("SOC_VAULT_BACKEND", "litebw"), ("SOC_VAULT_URL", "http://v"), ("SOC_VAULT_EMAIL", "a@b.c")]);
    let r = push_config_to_vault(&rig.host(), &e, "Default Item", &cfg, Some("raw: yaml\n"), Some("m"), false);
    assert!(r.ok && r.detail.contains("config note 'Default Item' (10 bytes)"), "{}", r.detail);
    let log = rig.vault.log.borrow();
    assert_eq!(log.writes[0].4.as_deref(), Some("raw: yaml\n"));
    drop(log);
    let none = soc_core::Config::default();
    assert_eq!(
        push_config_to_vault(&rig.host(), &e, "x", &none, None, Some("m"), false).detail,
        "no panels configured — nothing to push."
    );
}

fn first_run_plan(dir: &TempDir, soc_env_text: &str, source: MasterSource) -> FirstRunPlan {
    let paths = paths_in(dir);
    std::fs::write(&paths.soc_env, soc_env_text).unwrap();
    FirstRunPlan {
        soc_env: load_env_file(&paths.soc_env),
        backend: "litebw".into(),
        source,
        master: Some(Zeroizing::new("M-pw".into())),
        pin: None,
        reseal: false,
        dry_run: false,
        paths,
    }
}

#[test]
fn first_run_seals_and_surfaces_the_pin_once() {
    let dir = TempDir::new("fr1");
    let plan = first_run_plan(&dir, "SOC_VAULT_BACKEND=litebw\n", MasterSource::Auto);
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    assert_eq!(plan.steps(&rig.host()), vec![FirstRunStep::Preflight, FirstRunStep::Seal, FirstRunStep::ShowPin]);
    let mut shown = Vec::new();
    let out = plan.run(&rig.host(), &mut |s, r| shown.push((s, r.lines.clone())));
    assert!(out.ok);
    assert_eq!(out.pin.as_deref().map(String::as_str), Some("12345678"));
    let pin_lines = &shown.iter().find(|(s, _)| *s == FirstRunStep::ShowPin).unwrap().1;
    assert!(pin_lines.contains(&"        1  2  3  4  5  6  7  8".to_string()));
    assert_eq!(rig.seal.sealed.borrow().as_ref().unwrap().0, "M-pw");
}

#[test]
fn first_run_keeps_an_existing_seal_unless_resealing() {
    let dir = TempDir::new("fr2");
    let mut plan = first_run_plan(&dir, "SOC_VAULT_BACKEND=litebw\n", MasterSource::Sealed);
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    *rig.seal.sealed.borrow_mut() = Some(("old".into(), "1".into()));
    assert_eq!(plan.steps(&rig.host()), vec![FirstRunStep::Preflight, FirstRunStep::KeepExisting]);
    let out = plan.run(&rig.host(), &mut |_, _| {});
    assert!(out.ok && out.pin.is_none());
    assert_eq!(rig.seal.sealed.borrow().as_ref().unwrap().0, "old", "kept, not replaced");
    assert!(std::fs::read_to_string(&plan.paths.soc_env).unwrap().contains("SOC_MASTER_SOURCE=sealed"));
    plan.reseal = true;
    assert!(plan.steps(&rig.host()).contains(&FirstRunStep::Seal));
}

#[test]
fn first_run_dev_backend_needs_nothing_but_plaintext_is_sealed_anyway() {
    let dir = TempDir::new("fr3");
    let mut plan = first_run_plan(&dir, "SOC_VAULT_BACKEND=dev\n", MasterSource::Auto);
    plan.backend = "dev".into();
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    assert_eq!(plan.steps(&rig.host()), vec![FirstRunStep::Preflight]);
    let dir2 = TempDir::new("fr4");
    let mut plan = first_run_plan(&dir2, "SOC_VAULT_BACKEND=dev\nSOC_VAULT_PASSWORD=plain-pw\n", MasterSource::Auto);
    plan.backend = "dev".into();
    plan.master = None;
    let out = plan.run(&rig.host(), &mut |_, _| {});
    assert!(out.ok);
    assert_eq!(rig.seal.sealed.borrow().as_ref().unwrap().0, "plain-pw");
    assert!(!std::fs::read_to_string(&plan.paths.soc_env).unwrap().contains("SOC_VAULT_PASSWORD"));
}

#[test]
fn first_run_fails_without_a_master() {
    let dir = TempDir::new("fr5");
    let mut plan = first_run_plan(&dir, "SOC_VAULT_BACKEND=litebw\n", MasterSource::Sealed);
    plan.master = None;
    let rig = Rig::new(FakeProbe::with_bins(&[]));
    let out = plan.run(&rig.host(), &mut |_, _| {});
    assert!(!out.ok);
    assert_eq!(out.exit_code(), 1);
    assert!(rig.seal.sealed.borrow().is_none());
}

fn deploy_plan(dir: &TempDir, backend: &str) -> DeployPlan {
    let paths = paths_in(dir);
    std::fs::write(&paths.soc_env, format!("SOC_VAULT_BACKEND={backend}\nSOC_VAULT_URL=http://v\n")).unwrap();
    std::fs::write(&paths.panels_installed, PANELS).unwrap();
    let mut p = DeployPlan::new(Target::Pi, penv_in(dir), paths);
    p.email = "ops@soc.example".into();
    p.vault_wait = std::time::Duration::ZERO;
    p
}

fn deploy_rig() -> Rig {
    let mut probe = FakeProbe::with_bins(&["apt-get", "systemctl", "litebw", "labwc"]);
    probe.systemd = true;
    probe.root = true;
    probe.alive = true;
    probe.users.insert("soc".into());
    probe.dirs.insert("/opt/soc-display".into());
    Rig::new(probe)
}

#[test]
fn deploy_skips_install_when_stamped_and_fresh_forces_it() {
    let dir = TempDir::new("dp1");
    let mut plan = deploy_plan(&dir, "litebw");
    let rig = deploy_rig();
    let mut rig_stamped = deploy_rig();
    rig_stamped.probe.paths.insert(plan.paths.install_stamp());
    let step =
        |p: &DeployPlan, r: &Rig| p.steps(&r.host()).into_iter().find(|s| s.step == DeployStep::InstallOs).unwrap();
    assert!(step(&plan, &rig).needed);
    assert!(!step(&plan, &rig_stamped).needed);
    plan.fresh = true;
    assert!(step(&plan, &rig_stamped).needed);
    plan.dry_run = true;
    let mut st = soc_setup::deploy::DeployState::default();
    let r = plan.run_step(DeployStep::InstallOs, &rig_stamped.host(), &mut st);
    assert_eq!(r.cmds, vec![argv(&["./install.sh", "--fresh"])]);
    assert!(rig_stamped.runner.calls.borrow().is_empty(), "a dry run never shells the installer");
}

#[test]
fn unattended_deploy_refuses_to_guess() {
    let dir = TempDir::new("dp2");
    let mut plan = deploy_plan(&dir, "litebw");
    plan.unattended = true;
    let rig = deploy_rig();
    assert!(plan.validate(&rig.host()).unwrap_err().contains("master"));
    plan.master = Some(Zeroizing::new("m".into()));
    plan.email = "kiosk@soc.local".into();
    assert!(plan.validate(&rig.host()).unwrap_err().contains("--email"));
    plan.email = "ops@soc.example".into();
    assert!(plan.validate(&rig.host()).is_ok());
    let mut rig = deploy_rig();
    rig.probe.root = false;
    assert_eq!(plan.validate(&rig.host()).unwrap_err(), "deploy --unattended needs root");
    let out = plan.run(&rig.host(), &mut |_, _| panic!("no step may run"));
    assert!(!out.ok && out.error.is_some());
}

#[test]
fn full_deploy_runs_every_step_in_order() {
    let dir = TempDir::new("dp3");
    let mut plan = deploy_plan(&dir, "litebw");
    plan.master = Some(Zeroizing::new("M-pw".into()));
    plan.write_config = true;
    plan.soc_env =
        env(&[("SOC_VAULT_BACKEND", "litebw"), ("SOC_VAULT_URL", "http://v"), ("SOC_VAULT_EMAIL", "ops@soc.example")]);
    let rig = deploy_rig();
    *rig.seal.sealed.borrow_mut() = None;
    let mut order = Vec::new();
    let out = plan.run(&rig.host(), &mut |s, r| order.push((s, r.ok)));
    let ids: Vec<DeployStep> = order.iter().map(|(s, _)| *s).collect();
    assert_eq!(ids, DeployStep::ALL.to_vec());
    assert!(out.ok, "{:?}", out.results.iter().map(|(s, r)| (s.as_str(), r.detail.clone())).collect::<Vec<_>>());
    assert!(is_configured(&plan.paths));
    assert_eq!(out.pin.as_deref().map(String::as_str), Some("12345678"));
    assert!(std::fs::read_to_string(&plan.paths.soc_env).unwrap().contains("SOC_MASTER_SOURCE=auto"));
    assert!(plan.paths.wall_unit.as_ref().unwrap().exists());
    let log = rig.vault.log.borrow();
    // config note + 2 placeholder logins
    assert_eq!(log.writes.iter().filter(|w| w.4.is_some()).count(), 1);
    assert_eq!(log.writes.iter().filter(|w| w.4.is_none()).count(), 2);
    let calls = rig.runner.joined();
    assert!(calls.contains(&"systemctl restart getty@tty1.service".to_string()));
    // the install stamp is absent, so install.sh ran first
    assert_eq!(calls[0], "./install.sh");
}

#[test]
fn deploy_failure_after_install_disables_the_session_and_stops() {
    let dir = TempDir::new("dp4");
    let mut plan = deploy_plan(&dir, "litebw");
    plan.master = Some(Zeroizing::new("M".into()));
    let mut rig = deploy_rig();
    rig.vault.account = Some(Err("account exists, wrong master".into()));
    let mut seen = Vec::new();
    let out = plan.run(&rig.host(), &mut |s, _| seen.push(s));
    assert!(!out.ok);
    assert_eq!(*seen.last().unwrap(), DeployStep::VaultAccount, "stops at the first hard failure");
    assert!(!seen.contains(&DeployStep::Seal));
    let last = &out.results.last().unwrap().1;
    assert!(last.detail.starts_with("PARTIAL INSTALL"), "{}", last.detail);
    assert!(rig.runner.joined().contains(&"systemctl disable soc-wall.service".to_string()));
    assert!(!is_configured(&plan.paths));
}

#[test]
fn deploy_dry_run_changes_nothing() {
    let dir = TempDir::new("dp5");
    let mut plan = deploy_plan(&dir, "litebw");
    plan.master = Some(Zeroizing::new("M".into()));
    plan.dry_run = true;
    plan.write_config = true;
    let rig = deploy_rig();
    let out = plan.run(&rig.host(), &mut |_, _| {});
    assert!(out.ok);
    assert!(rig.seal.sealed.borrow().is_none());
    assert_eq!(rig.vault.log.borrow().connects, 0);
    assert!(!is_configured(&plan.paths));
    assert!(!plan.paths.wall_unit.as_ref().unwrap().exists());
    assert_eq!(out.pin.as_deref().map(String::as_str), Some("12345678"), "the PIN is previewed");
    assert!(rig.runner.joined().iter().all(|c| c.starts_with("systemctl is-active")), "{:?}", rig.runner.joined());
}

#[test]
fn deploy_dev_backend_skips_the_vault_steps() {
    let dir = TempDir::new("dp6");
    let plan = deploy_plan(&dir, "dev");
    let rig = deploy_rig();
    let steps = plan.steps(&rig.host());
    for s in [
        DeployStep::VaultUp,
        DeployStep::VaultAccount,
        DeployStep::Seal,
        DeployStep::PushConfig,
        DeployStep::StoreLogins,
    ] {
        assert!(!steps.iter().find(|p| p.step == s).unwrap().needed, "{s:?}");
    }
}

#[test]
fn configured_marker_roundtrip_and_user_marker() {
    let dir = TempDir::new("mk");
    let mut paths = paths_in(&dir);
    assert!(!is_configured(&paths));
    mark_configured(&paths, true).unwrap();
    assert!(!is_configured(&paths), "dry run writes nothing");
    mark_configured(&paths, false).unwrap();
    assert!(is_configured(&paths));
    paths.marker = Some(dir.join("sub/active"));
    drop_marker(&paths, false).unwrap();
    let body = std::fs::read_to_string(dir.join("sub/active")).unwrap();
    assert!(body.starts_with(&format!("{}\n# activated ", paths.panels_out.display())));
}

#[test]
fn old_env_can_be_rerendered_with_defaults() {
    let out = render_soc_env(&env(&[("SOC_VAULT_EMAIL", "a@b.c")]));
    assert!(out.contains("SOC_VAULT_EMAIL=a@b.c") && out.contains("SOC_ROOT=/opt/soc-display"));
    let _: PathBuf = PathBuf::new();
}
