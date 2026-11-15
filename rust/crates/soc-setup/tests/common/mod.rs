#![allow(dead_code)]
//! Fakes and fixtures shared by the integration tests.

use soc_setup::host::{Account, Host, Probe, SealBackend, VaultConnect, VaultWriter, Wrote};
use soc_setup::paths::{SetupPaths, Target};
use soc_sys::paths::PathEnv;
use soc_sys::run::{Output, Runner};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "soc-setup-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    pub fn join(&self, s: &str) -> PathBuf {
        self.0.join(s)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
pub struct FakeProbe {
    pub bins: BTreeSet<String>,
    pub paths: BTreeSet<PathBuf>,
    pub dirs: BTreeSet<PathBuf>,
    pub execs: BTreeSet<PathBuf>,
    pub modes: BTreeMap<PathBuf, u32>,
    pub alive: bool,
    pub systemd: bool,
    pub root: bool,
    pub user: String,
    pub users: BTreeSet<String>,
}

impl FakeProbe {
    pub fn with_bins(bins: &[&str]) -> FakeProbe {
        FakeProbe {
            bins: bins.iter().map(|s| (*s).to_string()).collect(),
            user: "tester".into(),
            ..FakeProbe::default()
        }
    }
}

impl Probe for FakeProbe {
    fn have(&self, bin: &str) -> bool {
        self.bins.contains(bin)
    }
    fn exists(&self, p: &Path) -> bool {
        self.paths.contains(p) || self.dirs.contains(p) || self.execs.contains(p)
    }
    fn is_dir(&self, p: &Path) -> bool {
        self.dirs.contains(p)
    }
    fn is_exec_file(&self, p: &Path) -> bool {
        self.execs.contains(p)
    }
    fn mode(&self, p: &Path) -> Option<u32> {
        self.modes.get(p).copied()
    }
    fn alive(&self, _: &str) -> bool {
        self.alive
    }
    fn systemd_running(&self) -> bool {
        self.systemd
    }
    fn is_root(&self) -> bool {
        self.root
    }
    fn current_user(&self) -> String {
        self.user.clone()
    }
    fn user_exists(&self, n: &str) -> bool {
        self.users.contains(n)
    }
    fn expand_user(&self, p: &str) -> String {
        p.replacen('~', "/home/tester", 1)
    }
}

type Answer = Box<dyn Fn(&[String]) -> io::Result<Output>>;

pub struct FakeRunner {
    pub calls: RefCell<Vec<Vec<String>>>,
    pub answer: Answer,
}

impl FakeRunner {
    pub fn ok() -> FakeRunner {
        FakeRunner::new(|_| Ok(out(0, "")))
    }
    pub fn new(f: impl Fn(&[String]) -> io::Result<Output> + 'static) -> FakeRunner {
        FakeRunner { calls: RefCell::new(Vec::new()), answer: Box::new(f) }
    }
    pub fn joined(&self) -> Vec<String> {
        self.calls.borrow().iter().map(|c| c.join(" ")).collect()
    }
}

impl Runner for FakeRunner {
    fn run(&self, argv: &[String], _: Duration) -> io::Result<Output> {
        self.calls.borrow_mut().push(argv.to_vec());
        (self.answer)(argv)
    }
}

pub fn out(code: i32, stdout: &str) -> Output {
    Output { code: Some(code), stdout: stdout.into(), stderr: String::new() }
}

#[derive(Default)]
pub struct FakeSeal {
    pub sealed: RefCell<Option<(String, String)>>,
    pub secret_tool: bool,
    pub wallet: RefCell<Option<String>>,
    pub sources: Vec<String>,
    pub unseal_error: Option<String>,
}

impl SealBackend for FakeSeal {
    fn is_sealed(&self, _: &Path) -> bool {
        self.sealed.borrow().is_some()
    }
    fn seal(&self, _: &Path, master: &str, pin: &str) -> Result<(), String> {
        *self.sealed.borrow_mut() = Some((master.into(), pin.into()));
        Ok(())
    }
    fn unseal(&self, _: &Path) -> Result<Zeroizing<String>, String> {
        if let Some(e) = &self.unseal_error {
            return Err(e.clone());
        }
        self.sealed.borrow().as_ref().map(|(m, _)| Zeroizing::new(m.clone())).ok_or_else(|| "not sealed".into())
    }
    fn available_sources(&self, _: &Path) -> Vec<String> {
        self.sources.clone()
    }
    fn have_secret_tool(&self) -> bool {
        self.secret_tool
    }
    fn secret_service_get(&self) -> Option<Zeroizing<String>> {
        self.wallet.borrow().clone().map(Zeroizing::new)
    }
    fn secret_service_store(&self, m: &str) -> Result<(), String> {
        *self.wallet.borrow_mut() = Some(m.into());
        Ok(())
    }
    fn gen_pin(&self) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new("12345678".into()))
    }
}

/// (name, username, password, uri, notes)
pub type Write = (String, String, String, Option<String>, Option<String>);

#[derive(Default)]
pub struct VaultLog {
    pub connects: u32,
    pub writes: Vec<Write>,
    pub existing: Vec<String>,
}

#[derive(Default)]
pub struct FakeVault {
    pub log: std::rc::Rc<RefCell<VaultLog>>,
    pub fail_connect: Option<String>,
    pub account: Option<Result<Account, String>>,
}

struct W(std::rc::Rc<RefCell<VaultLog>>);

impl VaultWriter for W {
    fn login_names(&self) -> Result<Vec<String>, String> {
        Ok(self.0.borrow().existing.clone())
    }
    fn upsert_login(&self, n: &str, u: &str, p: &str, uri: Option<&str>, notes: Option<&str>) -> Result<Wrote, String> {
        self.0.borrow_mut().writes.push((n.into(), u.into(), p.into(), uri.map(Into::into), notes.map(Into::into)));
        Ok(Wrote::Created)
    }
}

impl VaultConnect for FakeVault {
    fn connect(&self, _: &str, _: &str, _: &str) -> Result<Box<dyn VaultWriter>, String> {
        if let Some(e) = &self.fail_connect {
            return Err(e.clone());
        }
        self.log.borrow_mut().connects += 1;
        Ok(Box::new(W(self.log.clone())))
    }
    fn ensure_account(&self, _: &str, _: &str, _: &str) -> Result<Account, String> {
        self.account.clone().unwrap_or(Ok(Account::Exists))
    }
}

pub struct Rig {
    pub probe: FakeProbe,
    pub runner: FakeRunner,
    pub seal: FakeSeal,
    pub vault: FakeVault,
}

impl Rig {
    pub fn new(probe: FakeProbe) -> Rig {
        Rig { probe, runner: FakeRunner::ok(), seal: FakeSeal::default(), vault: FakeVault::default() }
    }
    pub fn host(&self) -> Host<'_> {
        Host { runner: &self.runner, probe: &self.probe, seal: &self.seal, vault: &self.vault }
    }
}

pub fn paths_in(dir: &TempDir) -> SetupPaths {
    SetupPaths {
        target: Target::Pi,
        via: "etc".into(),
        marker: None,
        needs_privilege: false,
        panels_out: dir.join("panels.yaml"),
        panels_installed: dir.join("panels.yaml"),
        soc_env: dir.join("soc.env"),
        wall_unit: Some(dir.join("soc-wall.service")),
        soc_root: PathBuf::from("/opt/soc-display"),
        pinentry: PathBuf::from("/opt/soc-display/scripts/pinentry-vault.py"),
        secret_dir: dir.join("secret"),
        config_vault_item: "SOC Wall Config".into(),
        inject_tmpl: PathBuf::from("/opt/soc-display/inject/login.js.tmpl"),
        default_backend: "litebw".into(),
        configured_marker: dir.join(".configured"),
        panels_mode: 0o644,
        env_mode: 0o600,
    }
}

pub fn penv_in(dir: &TempDir) -> PathEnv {
    PathEnv {
        cwd: dir.0.clone(),
        home: dir.0.clone(),
        xdg_config_home: None,
        etc_dir: Some(dir.0.display().to_string()),
        root: None,
        default_root: dir.0.clone(),
        panels_file: None,
        env_file: None,
        secret_dir: None,
        webdata_dir: None,
        state_dir: None,
        force_etc: None,
        allow_pkexec: None,
    }
}

pub fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

pub const PANELS: &str = "display: {auto: true, width: 1920, height: 1080, cols: 2, rows: 1, gap: 0}
panels:
  - {id: p1, engine: webkit, mode: direct, url: 'http://10.0.0.1/login', vault_item: 'SOC Panel 1', selectors: {user: '#u', pass: '#p'}, grid: [0, 0]}
  - {id: p2, engine: webkit, mode: direct, url: 'http://10.0.0.2/', vault_item: 'SOC Panel 2', selectors: {user: '#u', pass: '#p'}, grid: [1, 0]}
";
