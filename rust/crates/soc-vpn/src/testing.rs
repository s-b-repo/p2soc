//! Test doubles: a virtual clock, scripted VPN clients, a programmable vault.

use crate::clock::{Clock, StopFlag};
use crate::driver::{Paths, Programs};
use crate::notify::Notifier;
use crate::proc::{ChildProc, CommandSpec, LineSource, Spawned, Spawner};
use crate::status::{Probe, Prober};
use crate::supervisor::{Deps, Role, Supervisor, VaultAccess};
use crate::tunables::Tunables;
use crate::{Log, lock};
use serde_json::Value;
use soc_core::{CredError, CredSource, Dict, Login};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) fn dict(v: Value) -> Dict {
    v.as_object().cloned().expect("a JSON object")
}

/// Fixed paths for argv assertions.
pub(crate) fn paths() -> Paths {
    Paths {
        pinentry: PathBuf::from("/x/pinentry"),
        root: PathBuf::from("/opt/soc"),
        home: None,
        runtime_base: PathBuf::from("/run"),
        programs: Programs::default(),
        inode_native: None,
    }
}

/// A private temp directory, removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> TempDir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!("soc-vpn-{tag}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        TempDir(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A clock that only moves when someone waits on it.
///
/// Time stands still while a scripted client's output is still being read
/// (`busy`), so "the tunnel came up at T" is exact rather than a race between
/// the reader thread and the loop advancing the clock.
#[derive(Default)]
pub(crate) struct FakeClock {
    now: Mutex<f64>,
    waits: Mutex<Vec<f64>>,
    stop_after: Mutex<Option<(usize, StopFlag)>>,
    busy: AtomicUsize,
}

impl FakeClock {
    pub(crate) fn advance(&self, seconds: f64) {
        *lock(&self.now) += seconds;
    }

    /// Every interruptible wait so far.
    pub(crate) fn waits(&self) -> Vec<f64> {
        lock(&self.waits).clone()
    }

    /// Set `stop` once `count` waits have happened.
    pub(crate) fn stop_after_waits(&self, count: usize, stop: &StopFlag) {
        *lock(&self.stop_after) = Some((count, stop.clone()));
    }

    fn settle(&self) {
        let give_up = Instant::now() + Duration::from_secs(5);
        while self.busy.load(Ordering::SeqCst) > 0 && Instant::now() < give_up {
            std::thread::sleep(Duration::from_micros(50));
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> f64 {
        *lock(&self.now)
    }

    fn unix_time(&self) -> f64 {
        1_700_000_000.0 + self.now()
    }

    fn wait(&self, stop: &StopFlag, seconds: f64) -> bool {
        self.settle();
        // A breath of real time, so loops on other threads are not starved.
        std::thread::sleep(Duration::from_micros(100));
        if stop.is_set() {
            return true;
        }
        self.advance(seconds);
        let count = {
            let mut waits = lock(&self.waits);
            waits.push(seconds);
            waits.len()
        };
        if let Some((limit, flag)) = &*lock(&self.stop_after) {
            if count >= *limit {
                flag.set();
            }
        }
        stop.is_set()
    }

    fn sleep(&self, seconds: f64) {
        self.advance(seconds);
    }
}

/// Records every notify message.
#[derive(Default)]
pub(crate) struct RecNotifier(Mutex<Vec<String>>);

impl RecNotifier {
    pub(crate) fn sent(&self) -> Vec<String> {
        lock(&self.0).clone()
    }
}

impl Notifier for RecNotifier {
    fn notify(&self, state: &str) {
        lock(&self.0).push(state.to_string());
    }
}

/// A prober with canned answers.
pub(crate) struct FakeProber {
    tcp: Mutex<VecDeque<Probe>>,
    fallback: Mutex<Probe>,
    ifaces: Mutex<HashMap<String, bool>>,
    pub(crate) probes: AtomicUsize,
}

impl Default for FakeProber {
    fn default() -> Self {
        FakeProber {
            tcp: Mutex::new(VecDeque::new()),
            fallback: Mutex::new(Probe::Refused),
            ifaces: Mutex::new(HashMap::new()),
            probes: AtomicUsize::new(0),
        }
    }
}

impl FakeProber {
    /// The answer to every probe from now on.
    pub(crate) fn set_tcp(&self, result: Probe) {
        *lock(&self.fallback) = result;
    }

    /// Answers for the next probes, before falling back to `set_tcp`.
    pub(crate) fn queue_tcp(&self, results: &[Probe]) {
        lock(&self.tcp).extend(results.iter().copied());
    }

    pub(crate) fn set_iface(&self, name: &str, up: bool) {
        lock(&self.ifaces).insert(name.to_string(), up);
    }
}

impl Prober for FakeProber {
    fn tcp(&self, _hostport: &str, _timeout: f64) -> Probe {
        self.probes.fetch_add(1, Ordering::Relaxed);
        lock(&self.tcp).pop_front().unwrap_or(*lock(&self.fallback))
    }

    fn iface_up(&self, iface: &str) -> bool {
        lock(&self.ifaces).get(iface).copied().unwrap_or(false)
    }
}

/// A vault whose outages can be scripted.
#[derive(Default)]
pub(crate) struct FakeVault {
    logins: Mutex<HashMap<String, (String, String)>>,
    notes: Mutex<HashMap<String, String>>,
    codes: Mutex<HashMap<String, String>>,
    /// How many upcoming calls fail before the vault answers.
    pub(crate) outage: AtomicUsize,
    pub(crate) calls: AtomicUsize,
    pub(crate) refreshes: AtomicUsize,
}

impl FakeVault {
    pub(crate) fn add_login(&self, item: &str, user: &str, password: &str) {
        lock(&self.logins).insert(item.into(), (user.into(), password.into()));
    }

    pub(crate) fn add_notes(&self, item: &str, notes: &str) {
        lock(&self.notes).insert(item.into(), notes.into());
    }

    pub(crate) fn add_code(&self, item: &str, code: &str) {
        lock(&self.codes).insert(item.into(), code.into());
    }

    fn check(&self) -> Result<(), CredError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let left = self.outage.load(Ordering::Relaxed);
        if left > 0 {
            if left != usize::MAX {
                self.outage.store(left - 1, Ordering::Relaxed);
            }
            return Err(CredError::Unavailable("down".into()));
        }
        Ok(())
    }
}

impl CredSource for FakeVault {
    fn creds(&self, item: &str) -> Result<Login, CredError> {
        self.check()?;
        lock(&self.logins)
            .get(item)
            .map(|(u, p)| Login::new(u.as_str(), p.as_str()))
            .ok_or_else(|| CredError::NotFound(format!("no vault item named '{item}'")))
    }

    fn notes(&self, item: &str) -> Result<String, CredError> {
        self.check()?;
        Ok(lock(&self.notes).get(item).cloned().unwrap_or_default())
    }

    fn code(&self, item: &str) -> Result<String, CredError> {
        lock(&self.codes)
            .get(item)
            .cloned()
            .ok_or_else(|| CredError::NotFound(format!("no TOTP on vault item '{item}'")))
    }
}

/// One scripted client run.
pub(crate) struct Script {
    lines: Vec<String>,
    exit: i32,
    /// Virtual seconds the client stays alive after printing its lines.
    up_for: f64,
}

impl Script {
    /// Prints `lines`, then exits with `exit` after `up_for` virtual seconds.
    pub(crate) fn new(lines: &[&str], up_for: f64, exit: i32) -> Script {
        Script { lines: lines.iter().map(|l| l.to_string()).collect(), exit, up_for }
    }

    /// Prints `lines`, then runs until it is signalled.
    pub(crate) fn hang(lines: &[&str]) -> Script {
        Script::new(lines, f64::INFINITY, 0)
    }
}

pub(crate) struct FakeChild {
    pid: u32,
    clock: Arc<FakeClock>,
    exit: i32,
    up_for: f64,
    /// Virtual time its output was fully read.
    drained_at: Mutex<Option<f64>>,
    signals: Mutex<Vec<i32>>,
    reaped: AtomicBool,
}

impl FakeChild {
    pub(crate) fn signals(&self) -> Vec<i32> {
        lock(&self.signals).clone()
    }
}

impl ChildProc for FakeChild {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn exited(&self) -> bool {
        if !lock(&self.signals).is_empty() {
            return true;
        }
        lock(&self.drained_at).is_some_and(|at| self.clock.now() >= at + self.up_for)
    }

    fn reap(&self) -> Option<i32> {
        if !self.exited() {
            return None;
        }
        self.reaped.store(true, Ordering::Relaxed);
        Some(lock(&self.signals).first().map(|s| -s).unwrap_or(self.exit))
    }

    fn signal_group(&self, signal: i32) {
        lock(&self.signals).push(signal);
    }

    fn group_has_members(&self) -> Option<bool> {
        Some(false)
    }
}

struct FakeLines {
    lines: VecDeque<String>,
    child: Arc<FakeChild>,
    released: bool,
}

impl FakeLines {
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            *lock(&self.child.drained_at) = Some(self.child.clock.now());
            self.child.clock.busy.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl LineSource for FakeLines {
    fn next_line(&mut self, _done: &AtomicBool) -> Option<String> {
        let line = self.lines.pop_front();
        if line.is_none() {
            self.release();
        }
        line
    }
}

impl Drop for FakeLines {
    fn drop(&mut self) {
        self.release();
    }
}

/// What the supervisor asked to be started.
#[derive(Debug, Clone)]
pub(crate) struct SpawnRecord {
    /// Virtual time of the spawn.
    pub(crate) at: f64,
    pub(crate) argv: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) env_remove: Vec<String>,
    /// The spec's `Debug` rendering.
    pub(crate) debug: String,
}

type OneshotFn = Box<dyn FnMut(&[String]) -> (i32, String) + Send>;
type SpawnHook = Box<dyn FnMut(&[String]) + Send>;

/// Hands out scripted clients instead of starting processes.
pub(crate) struct FakeSpawner {
    clock: Arc<FakeClock>,
    scripts: Mutex<VecDeque<Script>>,
    spawned: Mutex<Vec<SpawnRecord>>,
    children: Mutex<Vec<Arc<FakeChild>>>,
    oneshots: Mutex<Vec<Vec<String>>>,
    oneshot_reply: Mutex<OneshotFn>,
    missing: Mutex<Vec<String>>,
    when_exhausted: Mutex<Option<StopFlag>>,
    on_spawn: Mutex<Option<SpawnHook>>,
}

impl FakeSpawner {
    fn new(clock: Arc<FakeClock>) -> FakeSpawner {
        FakeSpawner {
            clock,
            scripts: Mutex::new(VecDeque::new()),
            spawned: Mutex::new(Vec::new()),
            children: Mutex::new(Vec::new()),
            oneshots: Mutex::new(Vec::new()),
            oneshot_reply: Mutex::new(Box::new(|_| (0, String::new()))),
            missing: Mutex::new(Vec::new()),
            when_exhausted: Mutex::new(None),
            on_spawn: Mutex::new(None),
        }
    }

    /// Run `hook` with the argv of every client as it is started.
    pub(crate) fn on_spawn(&self, hook: impl FnMut(&[String]) + Send + 'static) {
        *lock(&self.on_spawn) = Some(Box::new(hook));
    }

    pub(crate) fn push(&self, script: Script) {
        lock(&self.scripts).push_back(script);
    }

    /// Once the scripts run out, the next spawn fails and sets `stop`.
    pub(crate) fn stop_when_exhausted(&self, stop: StopFlag) {
        *lock(&self.when_exhausted) = Some(stop);
    }

    pub(crate) fn spawned(&self) -> Vec<SpawnRecord> {
        lock(&self.spawned).clone()
    }

    pub(crate) fn children(&self) -> Vec<Arc<FakeChild>> {
        lock(&self.children).clone()
    }

    /// Every started client has exited and been reaped.
    pub(crate) fn all_children_gone(&self) -> bool {
        lock(&self.children).iter().all(|c| c.reaped.load(Ordering::Relaxed))
    }

    pub(crate) fn oneshots(&self) -> Vec<Vec<String>> {
        lock(&self.oneshots).clone()
    }

    pub(crate) fn on_oneshot(&self, reply: impl FnMut(&[String]) -> (i32, String) + Send + 'static) {
        *lock(&self.oneshot_reply) = Box::new(reply);
    }

    pub(crate) fn set_missing(&self, program: &str) {
        lock(&self.missing).push(program.to_string());
    }

    fn child(clock: Arc<FakeClock>, script: &Script) -> Arc<FakeChild> {
        static NEXT_PID: AtomicU32 = AtomicU32::new(5_000_000);
        Arc::new(FakeChild {
            pid: NEXT_PID.fetch_add(1, Ordering::Relaxed),
            clock,
            exit: script.exit,
            up_for: script.up_for,
            drained_at: Mutex::new(None),
            signals: Mutex::new(Vec::new()),
            reaped: AtomicBool::new(false),
        })
    }

    /// A client that runs until signalled, not started through a spawn.
    pub(crate) fn stuck_child() -> Arc<FakeChild> {
        let child = FakeSpawner::child(Arc::new(FakeClock::default()), &Script::hang(&[]));
        *lock(&child.drained_at) = Some(0.0);
        child
    }
}

impl Spawner for FakeSpawner {
    fn spawn(&self, spec: &CommandSpec) -> std::io::Result<Spawned> {
        let Some(script) = lock(&self.scripts).pop_front() else {
            if let Some(stop) = &*lock(&self.when_exhausted) {
                stop.set();
            }
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no more scripted clients"));
        };
        lock(&self.spawned).push(SpawnRecord {
            at: self.clock.now(),
            argv: spec.argv.clone(),
            env: spec.env.iter().map(|(k, v)| (k.clone(), v.to_string())).collect(),
            env_remove: spec.env_remove.clone(),
            debug: format!("{spec:?}"),
        });
        if let Some(hook) = &mut *lock(&self.on_spawn) {
            hook(&spec.argv);
        }
        let child = FakeSpawner::child(self.clock.clone(), &script);
        lock(&self.children).push(child.clone());
        self.clock.busy.fetch_add(1, Ordering::SeqCst);
        let output = FakeLines { lines: script.lines.into(), child: child.clone(), released: false };
        Ok(Spawned { child, output: Box::new(output) })
    }

    fn oneshot(&self, argv: &[String], _timeout: f64) -> (i32, String) {
        lock(&self.oneshots).push(argv.to_vec());
        (lock(&self.oneshot_reply))(argv)
    }

    fn executable(&self, program: &str) -> bool {
        !lock(&self.missing).iter().any(|m| m == program)
    }
}

/// Everything a supervisor needs, faked, plus a view of what it did.
pub(crate) struct Harness {
    pub(crate) clock: Arc<FakeClock>,
    pub(crate) spawner: Arc<FakeSpawner>,
    pub(crate) prober: Arc<FakeProber>,
    pub(crate) notifier: Arc<RecNotifier>,
    pub(crate) vault: Arc<FakeVault>,
    pub(crate) tun: Tunables,
    pub(crate) paths: Paths,
    logs: Arc<Mutex<Vec<String>>>,
    tmp: TempDir,
}

impl Harness {
    pub(crate) fn new() -> Harness {
        let clock = Arc::new(FakeClock::default());
        let tmp = TempDir::new("harness");
        Harness {
            spawner: Arc::new(FakeSpawner::new(clock.clone())),
            clock,
            prober: Arc::new(FakeProber::default()),
            notifier: Arc::new(RecNotifier::default()),
            vault: Arc::new(FakeVault::default()),
            tun: Tunables { start_stagger: 0.0, ..Tunables::default() },
            paths: Paths { runtime_base: tmp.path().to_path_buf(), ..paths() },
            logs: Arc::new(Mutex::new(Vec::new())),
            tmp,
        }
    }

    /// The runtime directory handed to supervisors.
    pub(crate) fn runtime_dir(&self) -> &Path {
        self.tmp.path()
    }

    pub(crate) fn deps(&self) -> Deps {
        let logs = self.logs.clone();
        let log: Log = Arc::new(move |msg: &str| lock(&logs).push(msg.to_string()));
        let vault = self.vault.clone();
        Deps {
            vault: VaultAccess {
                creds: self.vault.clone(),
                refresh: Some(Arc::new(move || {
                    vault.refreshes.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })),
            },
            spawner: self.spawner.clone(),
            prober: self.prober.clone(),
            clock: self.clock.clone(),
            notifier: self.notifier.clone(),
            log,
        }
    }

    pub(crate) fn supervisor(&self, vpn: Value) -> Supervisor {
        self.supervisor_as(vpn, Role::standalone())
    }

    pub(crate) fn supervisor_as(&self, vpn: Value, role: Role) -> Supervisor {
        Supervisor::new(dict(vpn), role, self.deps(), self.tun.clone(), self.paths.clone())
    }

    /// Run a supervisor until its scripted clients run out.
    pub(crate) fn run(&self, sup: &mut Supervisor) -> i32 {
        self.spawner.stop_when_exhausted(sup.handle().stop_flag());
        sup.run()
    }

    pub(crate) fn logs(&self) -> Vec<String> {
        lock(&self.logs).clone()
    }

    /// The log lines containing `needle`.
    pub(crate) fn logged(&self, needle: &str) -> Vec<String> {
        self.logs().into_iter().filter(|m| m.contains(needle)).collect()
    }

    pub(crate) fn wait_for_log(&self, needle: &str) {
        let give_up = Instant::now() + Duration::from_secs(10);
        while self.logged(needle).is_empty() {
            assert!(Instant::now() < give_up, "never logged {needle:?}; got {:?}", self.logs());
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Every regular file under the runtime directory.
    pub(crate) fn files_on_disk(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                if entry.path().is_dir() { walk(&entry.path(), out) } else { out.push(entry.path()) }
            }
        }
        let mut out = Vec::new();
        walk(self.tmp.path(), &mut out);
        out
    }
}
