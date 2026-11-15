//! The supervisor: keeps one VPN connected.
//!
//! Instead of running the client once and letting systemd churn through
//! restarts, the supervisor runs it as a child and owns the reconnect policy:
//!
//!  * the client's output goes to the journal and is classified;
//!  * a network drop reconnects with exponential backoff;
//!  * an authentication failure holds for a long time (hammering a gateway
//!    with a rejected password locks the account), and so does a certificate
//!    failure (retrying cannot fix a wrong pin);
//!  * credentials are re-read from the vault, and a one-time code fetched,
//!    before every attempt;
//!  * `vpn.ready_probe` is probed while the tunnel is up, and a connection
//!    that went stale is restarted.

use crate::backoff::Backoff;
use crate::clock::{Clock, StopFlag, SystemClock};
use crate::driver::{self, Paths};
use crate::error::VpnError;
use crate::event::{Event, Seen, classify};
use crate::manager::coerce_split_tunnel;
use crate::mgmt;
use crate::notify::{self, Notifier, SdNotifier, Watchdog};
use crate::overlay::{parse_vpn_notes, strip_catch_all};
use crate::pinentry::{OTP_ENV, PASSWORD_ENV};
use crate::proc::{self, ChildProc, CommandSpec, LineSource, Spawner, SystemSpawner, Worker};
use crate::scratch::{self, Scratch};
use crate::status::{NetProber, Probe, Prober, expected_iface};
use crate::tunables::Tunables;
use crate::{Log, lock, printable, sys};
use soc_core::guard::{GuardError, has_ctrl_or_space};
use soc_core::vpnargs::{vpn_kind, wireguard_target};
use soc_core::{CredError, CredSource, Dict, DictExt, Login, VpnKind};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

/// Supervisors are threads sharing one pid, so anything pid-scoped would be
/// shared by every VPN in the unit: this count keeps their keys and sockets
/// apart.
static INSTANCES: AtomicU32 = AtomicU32::new(1);

/// How long a client that printed an authentication failure may keep running
/// before it is stopped, in polls. A client normally exits by itself right
/// after; one that does not is about to retry the rejected password on its
/// own schedule.
const AUTH_EXIT_POLLS: u32 = 5;

/// Re-synchronise the vault with its server.
pub type Refresh = Arc<dyn Fn() -> Result<(), CredError> + Send + Sync>;

/// How the supervisor reaches the vault.
#[derive(Clone)]
pub struct VaultAccess {
    pub creds: Arc<dyn CredSource>,
    /// Called after a rejected login and after a missing one-time code: the
    /// fix may be a rotated password or a newly added TOTP secret, which a
    /// vault serving from a snapshot would otherwise never see.
    pub refresh: Option<Refresh>,
}

impl VaultAccess {
    pub fn new(creds: Arc<dyn CredSource>) -> VaultAccess {
        VaultAccess { creds, refresh: None }
    }
}

/// Everything the supervisor does to the outside world, injectable.
#[derive(Clone)]
pub struct Deps {
    pub vault: VaultAccess,
    pub spawner: Arc<dyn Spawner>,
    pub prober: Arc<dyn Prober>,
    pub clock: Arc<dyn Clock>,
    pub notifier: Arc<dyn Notifier>,
    pub log: Log,
}

impl Deps {
    /// The real thing: real processes, real time, `$NOTIFY_SOCKET`.
    pub fn system(vault: VaultAccess, log: Log) -> Deps {
        Deps {
            vault,
            spawner: Arc::new(SystemSpawner),
            prober: Arc::new(NetProber),
            clock: Arc::new(SystemClock::new()),
            notifier: Arc::new(SdNotifier::from_env()),
            log,
        }
    }
}

/// A supervisor's place among its siblings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Role {
    /// Another VPN owns the default route: this one must stay split-tunnel,
    /// whatever its vault-held config says.
    pub non_owner: bool,
    /// Whether this supervisor sends `WATCHDOG=1` itself. Off under a
    /// manager, which pets systemd only while every supervisor is beating.
    pub pets_watchdog: bool,
}

impl Role {
    /// The only supervisor of the process.
    pub const fn standalone() -> Role {
        Role { non_owner: false, pets_watchdog: true }
    }

    /// One of a manager's supervisors.
    pub const fn managed(non_owner: bool) -> Role {
        Role { non_owner, pets_watchdog: false }
    }
}

/// What one attempt's helper threads observed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AttemptState {
    pub tunnel_up: bool,
    /// Monotonic time the tunnel last reported up.
    pub up_since: Option<f64>,
    pub saw: Seen,
    /// The OpenVPN management socket never became reachable.
    pub mgmt_unreachable: bool,
    /// A helper thread wants the client stopped.
    pub abort: bool,
}

/// How angrily to come back after an attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    MgmtUnreachable,
    AuthFailed,
    CertFailed,
    /// An ordinary drop. `stable`: the tunnel lasted long enough to count as
    /// a real connection, so the backoff starts over. `closed`: the client
    /// reported the drop itself.
    Dropped {
        stable: bool,
        closed: bool,
    },
}

/// Classify a finished attempt. Order matters: an unreachable management
/// socket and a rejected login both outrank whatever else was printed.
pub fn verdict(state: &AttemptState, now: f64, stable_after: f64) -> Verdict {
    if state.mgmt_unreachable {
        Verdict::MgmtUnreachable
    } else if state.saw.auth {
        Verdict::AuthFailed
    } else if state.saw.cert {
        Verdict::CertFailed
    } else {
        Verdict::Dropped { stable: state.up_since.is_some_and(|t| now - t >= stable_after), closed: state.saw.down }
    }
}

struct Shared {
    stop: StopFlag,
    watchdog: Watchdog,
    child: Mutex<Option<Arc<dyn ChildProc>>>,
    scratch: Mutex<Scratch>,
    /// The entry as it currently stands (after any vault overlay).
    view: Mutex<Dict>,
}

/// A handle on a running supervisor, for the thread that manages it.
#[derive(Clone)]
pub struct Handle {
    shared: Arc<Shared>,
    clock: Arc<dyn Clock>,
    log: Log,
    binary: &'static str,
}

impl Handle {
    /// Ask the supervisor to stop. Ends every wait at once.
    pub fn stop(&self) {
        self.shared.stop.set();
    }

    pub fn stop_flag(&self) -> StopFlag {
        self.shared.stop.clone()
    }

    pub fn is_stopping(&self) -> bool {
        self.shared.stop.is_set()
    }

    /// Monotonic time of the supervisor's last heartbeat.
    pub fn beat(&self) -> f64 {
        self.shared.watchdog.beat()
    }

    /// SIGTERM the current client's process group without waiting for it.
    pub fn signal_child(&self) {
        let child = lock(&self.shared.child).clone();
        if let Some(child) = child {
            child.signal_group(sys::SIGTERM);
        }
    }

    /// Do a wedged supervisor's teardown for it: remove its key material,
    /// then stop and reap its client. Key material first — removing it cannot
    /// hang, while a stuck client can use up the whole stop timeout.
    pub fn force_cleanup(&self, grace: f64) {
        lock(&self.shared.scratch).cleanup();
        let child = lock(&self.shared.child).clone();
        if let Some(child) = child {
            proc::terminate(&*child, grace, &*self.clock, &*self.log, self.binary);
            proc::reap_group(&*child, 1.0, &*self.clock);
        }
    }

    /// The entry as the supervisor currently sees it.
    pub fn entry(&self) -> Dict {
        lock(&self.shared.view).clone()
    }
}

struct Attempt {
    child: Arc<dyn ChildProc>,
    done: Arc<AtomicBool>,
    state: Arc<Mutex<AttemptState>>,
    reader: Option<Worker>,
    mgmt: Option<Worker>,
}

/// Turns one attempt's output lines into state, journal lines and status.
struct LineSink {
    kind: VpnKind,
    binary: &'static str,
    state: Arc<Mutex<AttemptState>>,
    clock: Arc<dyn Clock>,
    notifier: Arc<dyn Notifier>,
    log: Log,
}

impl LineSink {
    fn on_line(&self, raw: &str) {
        let line = raw.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            return;
        }
        (self.log)(&format!("[{}] {}", self.binary, printable(line)));
        match classify(self.kind, line) {
            Some(Event::Up) => {
                {
                    let mut state = lock(&self.state);
                    state.tunnel_up = true;
                    // The backoff is reset later, and only if it stays up.
                    state.up_since = Some(self.clock.now());
                }
                (self.log)("tunnel established");
                self.notifier.notify(&notify::status("connected: tunnel is up"));
            }
            // Progress for the wall only: it must never count as a drop.
            Some(Event::Connecting) => self.notifier.notify(&notify::status("connecting to gateway")),
            Some(event) => lock(&self.state).saw.record(event),
            None => {}
        }
    }
}

/// Runs teardown on every way out of a supervise loop, unwinding included.
struct Teardown<'a>(&'a mut Supervisor);

impl Drop for Teardown<'_> {
    fn drop(&mut self) {
        self.0.teardown();
    }
}

/// Keeps one VPN entry connected. See the module docs.
pub struct Supervisor {
    vpn: Dict,
    kind: VpnKind,
    role: Role,
    deps: Deps,
    tun: Tunables,
    paths: Paths,
    shared: Arc<Shared>,
    backoff: Backoff,
    /// Each failed vault unlock re-runs a key derivation plus a login;
    /// retried at a fixed short interval, a vault outage would pin the board.
    vault_retry: Backoff,
    instance: u32,
    attempt: Option<Attempt>,
    /// A client that survived SIGKILL; no new one starts beside it.
    lingering: Option<Arc<dyn ChildProc>>,
}

impl Supervisor {
    pub fn new(vpn: Dict, role: Role, deps: Deps, tun: Tunables, paths: Paths) -> Supervisor {
        let instance = INSTANCES.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(Shared {
            stop: StopFlag::new(),
            watchdog: Watchdog::new(
                tun.watchdog_interval,
                role.pets_watchdog,
                deps.clock.clone(),
                deps.notifier.clone(),
            ),
            child: Mutex::new(None),
            scratch: Mutex::new(Scratch::new(&paths.runtime_base, std::process::id(), instance)),
            view: Mutex::new(vpn.clone()),
        });
        Supervisor {
            kind: vpn_kind(&vpn),
            vpn,
            role,
            backoff: Backoff::new(tun.backoff_initial, tun.backoff_max),
            vault_retry: Backoff::new(3.0, 60.0),
            deps,
            tun,
            paths,
            shared,
            instance,
            attempt: None,
            lingering: None,
        }
    }

    pub fn handle(&self) -> Handle {
        Handle {
            shared: self.shared.clone(),
            clock: self.deps.clock.clone(),
            log: self.deps.log.clone(),
            binary: self.binary(),
        }
    }

    /// The entry as it currently stands (after any vault overlay).
    pub fn entry(&self) -> &Dict {
        &self.vpn
    }

    fn binary(&self) -> &'static str {
        driver::binary(self.kind)
    }

    fn log(&self, msg: &str) {
        (self.deps.log)(msg);
    }

    fn status(&self, text: &str) {
        self.deps.notifier.notify(&notify::status(text));
    }

    fn now(&self) -> f64 {
        self.deps.clock.now()
    }

    fn stopping(&self) -> bool {
        self.shared.stop.is_set()
    }

    fn ping(&self) {
        self.shared.watchdog.ping();
    }

    fn item(&self) -> String {
        self.vpn.text("vault_item")
    }

    /// Interruptible sleep that keeps the heartbeat going.
    pub fn sleep(&self, seconds: f64) {
        let deadline = self.now() + seconds;
        let tick = self.tun.heartbeat();
        while !self.stopping() {
            let left = deadline - self.now();
            if left <= 0.0 {
                break;
            }
            self.ping();
            self.deps.clock.wait(&self.shared.stop, tick.min(left));
        }
    }

    /// Stay alive without churning systemd restarts. Reserved for what a
    /// restart cannot fix (the reason was already logged and put in STATUS):
    /// anything that can heal retries on a slow path instead.
    pub fn idle(&self) -> i32 {
        let interval = self.shared.watchdog.interval();
        let wait = if interval > 0.0 { interval.min(60.0) } else { 60.0 };
        while !self.stopping() {
            self.ping();
            self.deps.clock.wait(&self.shared.stop, wait);
        }
        0
    }

    /// Supervise until stopped. Key material, the client and its helper
    /// threads are cleaned up on every way out.
    pub fn run(&mut self) -> i32 {
        if driver::is_interface(self.kind) { self.run_interface() } else { self.run_process() }
    }

    // --- credentials ------------------------------------------------------------

    /// Fetch the login, riding out a vault that is not ready yet (it may
    /// still be starting at boot). `None` when stopped or past `timeout`.
    fn resolve_creds(&mut self, timeout: f64) -> Option<Login> {
        let item = self.item();
        let deadline = self.now() + timeout;
        while !self.stopping() {
            self.ping();
            match self.deps.vault.creds.creds(&item) {
                Ok(login) => {
                    self.vault_retry.reset();
                    if login.username.is_empty() {
                        self.log(&format!("WARNING vault item '{item}' has no username"));
                    }
                    return Some(login);
                }
                Err(e) => {
                    if self.now() > deadline {
                        self.log(&format!("ERROR vault/creds not ready within {timeout:.0}s: {e}"));
                        return None;
                    }
                    let delay = self.vault_retry.next_delay();
                    self.log(&format!("vault not ready ({e}); retrying in {delay:.0}s ..."));
                    self.status("waiting for the credentials vault");
                    self.sleep(delay);
                }
            }
        }
        None
    }

    fn refresh_vault(&self) {
        let Some(refresh) = &self.deps.vault.refresh else {
            return;
        };
        self.ping();
        if let Err(e) = refresh() {
            self.log(&format!("could not re-sync the vault ({e}); it will be re-opened"));
        }
    }

    /// The single-use code, with one short retry: a transient fetch failure
    /// should not spend a doomed blank-code login. Empty only after every try
    /// failed.
    fn otp_code(&self) -> Zeroizing<String> {
        let item = self.item();
        for attempt in 0..2 {
            match self.deps.vault.creds.code(&item) {
                Ok(code) => {
                    let code = Zeroizing::new(code);
                    let trimmed = code.trim();
                    if !trimmed.is_empty() && !has_ctrl_or_space(trimmed) {
                        return Zeroizing::new(trimmed.to_string());
                    }
                    self.log(&format!("WARNING vault item '{item}' produced an unusable one-time code"));
                }
                Err(e) => self.log(&format!("WARNING OTP fetch from vault item '{item}' failed: {e}")),
            }
            if attempt == 0 && !self.stopping() {
                self.ping();
                self.deps.clock.wait(&self.shared.stop, self.tun.otp_retry_wait);
            }
        }
        Zeroizing::new(String::new())
    }

    // --- VPN config from the vault ----------------------------------------------

    /// With `config_from_vault`, hydrate the config from the vault item's
    /// Notes. Fortinet / iNode: a `KEY=VALUE` block overlaid in memory, never
    /// written to disk. OpenVPN / WireGuard: a whole profile, written `0600`
    /// into this supervisor's private directory. False when it cannot be done.
    fn materialize_config(&mut self) -> bool {
        if !self.vpn.truthy("config_from_vault") {
            return true;
        }
        let item = self.item();
        let deadline = self.now() + self.tun.ready_timeout;
        let content = loop {
            self.ping();
            match self.deps.vault.creds.notes(&item) {
                Ok(notes) => {
                    self.vault_retry.reset();
                    break Zeroizing::new(notes);
                }
                Err(e) => {
                    if self.stopping() || self.now() > deadline {
                        self.log(&format!("ERROR reading VPN config from vault item '{item}': {e}"));
                        return false;
                    }
                    let delay = self.vault_retry.next_delay();
                    self.log(&format!("vault not ready for VPN config ({e}); retrying in {delay:.0}s"));
                    self.status("waiting for the vault (VPN config)");
                    self.sleep(delay);
                }
            }
        };
        if content.trim().is_empty() {
            self.log(&format!("ERROR vault item '{item}' has no Notes content (the VPN config)"));
            return false;
        }
        match self.kind {
            VpnKind::Fortinet | VpnKind::Inode => self.overlay_notes(&item, &content),
            VpnKind::Wireguard | VpnKind::Openvpn => self.write_profile(&item, &content),
        }
    }

    fn overlay_notes(&mut self, item: &str, notes: &str) -> bool {
        let kv = parse_vpn_notes(notes, &*self.deps.log);
        if kv.is_empty() {
            self.log(&format!(
                "ERROR vault item '{item}' Notes had no usable KEY=VALUE lines for this {} VPN",
                self.kind
            ));
            return false;
        }
        let mut keys: Vec<&str> = kv.keys().map(String::as_str).collect();
        keys.sort_unstable();
        self.log(&format!("overlaid VPN field(s) {} from vault item '{item}'", keys.join(", ")));
        if kv.get("insecure").is_some_and(|v| v == &serde_json::Value::Bool(true)) {
            self.log(&format!(
                "WARNING vault item '{item}' turns OFF gateway certificate verification (insecure=true)"
            ));
        }
        for (key, value) in kv {
            self.vpn.insert(key, value);
        }
        if self.role.non_owner {
            // The overlay arrived after the routing policy was applied: a
            // non-owner's note must not take the default route back.
            coerce_split_tunnel(&mut self.vpn, &*self.deps.log);
        }
        true
    }

    fn write_profile(&mut self, item: &str, content: &str) -> bool {
        let (name, body) = if self.kind == VpnKind::Wireguard {
            let iface = match driver::wireguard_iface(&self.vpn) {
                iface if iface.is_empty() => "wg0".to_string(),
                iface => iface,
            };
            if !driver::valid_iface(&iface) {
                self.log("ERROR vpn.config does not name a valid WireGuard interface");
                return false;
            }
            let mut body = Zeroizing::new(content.to_string());
            if self.role.non_owner {
                // Scrubbed before it is written: wg-quick obeys the file
                // verbatim, so the unstripped config never exists on disk.
                let (scrubbed, dropped) = strip_catch_all(content);
                if dropped > 0 {
                    self.log(
                        "REFUSED a catch-all AllowedIPs (0.0.0.0/0 or ::/0) in a non-owner WireGuard .conf — \
                         stripping it so it cannot hijack the default route. Scope AllowedIPs to the panel subnets.",
                    );
                }
                body = Zeroizing::new(scrubbed);
            }
            (format!("{iface}.conf"), body)
        } else {
            (format!("openvpn-{}.ovpn", self.instance), Zeroizing::new(content.to_string()))
        };
        let written = lock(&self.shared.scratch).write_secret(&name, &body);
        match written {
            Ok(path) => {
                self.log(&format!("materialized VPN config from vault item '{item}' -> {} (0600)", path.display()));
                self.vpn.insert("config".into(), path.display().to_string().into());
                true
            }
            Err(e) => {
                self.log(&format!("ERROR writing VPN config: {e}"));
                false
            }
        }
    }

    /// Materialize the vault-held config, retrying on the slow path until it
    /// works or we are stopped. A vault outage, or an item an operator has yet
    /// to fix, must heal by itself: nobody is there to restart the service.
    fn await_config(&mut self) {
        while !self.stopping() {
            if self.materialize_config() {
                *lock(&self.shared.view) = self.vpn.clone();
                return;
            }
            lock(&self.shared.scratch).cleanup_materialized();
            self.status("could not load VPN config from the vault; retrying");
            self.sleep(self.tun.slow_retry());
        }
    }

    // --- one attempt (process drivers) ------------------------------------------

    fn mgmt_thread(
        &self,
        path: PathBuf,
        login: Login,
        child: Arc<dyn ChildProc>,
        att: (Arc<AtomicBool>, Arc<Mutex<AttemptState>>),
    ) -> impl FnOnce() + Send + 'static + use<> {
        let (done, state) = att;
        let stop = self.shared.stop.clone();
        let clock = self.deps.clock.clone();
        let notifier = self.deps.notifier.clone();
        let log = self.deps.log.clone();
        move || {
            // The path is reused by the next attempt, so a thread outliving
            // its openvpn must stand down rather than serve its successor.
            let gone = || done.load(Ordering::Relaxed) || stop.is_set() || child.exited();
            let deadline = clock.now() + 30.0;
            let mut stream = None;
            while clock.now() < deadline && !gone() {
                // A refused connect only means openvpn is not listening yet: retry until the deadline.
                stream = UnixStream::connect(&path).ok();
                if stream.is_some() {
                    break;
                }
                clock.wait(&stop, 0.3);
            }
            let Some(stream) = stream else {
                if gone() {
                    return;
                }
                // openvpn sits held and will never proceed until released over
                // the socket we could not reach. A setup fault, not a network
                // drop: flag it so the long backoff applies.
                {
                    let mut state = lock(&state);
                    state.mgmt_unreachable = true;
                    state.saw.down = true;
                    state.abort = true;
                }
                log("ERROR could not reach the OpenVPN management socket — the child started --management-hold \
                     and cannot authenticate; check that openvpn created the socket (selinux/apparmor, runtime dir \
                     perms). Terminating the held child and backing off.");
                notifier.notify(&notify::status("OpenVPN management socket unreachable; backing off"));
                return;
            };
            match mgmt::serve(&stream, &login, &gone) {
                mgmt::End::AuthFailed => {
                    let mut state = lock(&state);
                    state.saw.auth = true;
                    state.abort = true;
                }
                mgmt::End::Restarted => {
                    {
                        let mut state = lock(&state);
                        state.saw.down = true;
                        state.abort = true;
                    }
                    log("openvpn restarted by itself and is waiting to be released; stopping it so the supervisor \
                         reconnects on its own schedule");
                }
                mgmt::End::Closed | mgmt::End::Cancelled => {}
            }
        }
    }

    /// Build the command for one attempt. The login is consumed here; the
    /// OpenVPN one is handed back for the management thread.
    fn command(&mut self, creds: Option<Login>) -> Result<(CommandSpec, Option<(PathBuf, Login)>), VpnError> {
        let mut spec = CommandSpec::new(Vec::new());
        if let Some(login) = &creds {
            if login.password.is_empty() {
                return Err(VpnError::BlankPassword);
            }
        }
        match (self.kind, creds) {
            (VpnKind::Fortinet, Some(login)) => {
                let mut otp = Zeroizing::new(String::new());
                if self.vpn.truthy("otp_from_vault") {
                    otp = self.otp_code();
                    if otp.is_empty() {
                        // We know we have no code to send: starting the client
                        // would be a guaranteed failed login.
                        return Err(VpnError::OtpUnavailable);
                    }
                }
                let on_argv = self.tun.otp_on_argv && !otp.is_empty();
                spec.argv =
                    driver::fortinet_cmd(&self.vpn, &self.paths, &login.username, on_argv.then_some(otp.as_str()))?;
                spec.secret_env(PASSWORD_ENV, &login.password);
                if !otp.is_empty() && !on_argv {
                    spec.secret_env(OTP_ENV, &otp);
                }
                Ok((spec, None))
            }
            (VpnKind::Inode, Some(login)) => {
                spec.argv = driver::inode_cmd(&self.vpn, &self.paths, &login.username)?;
                spec.secret_env("H3C_SVPN_PASSWORD", &login.password);
                Ok((spec, None))
            }
            (VpnKind::Openvpn, Some(login)) => {
                let socket =
                    lock(&self.shared.scratch).mgmt_path().map_err(|e| VpnError::io("management socket", e))?;
                spec.argv = driver::openvpn_cmd(&self.vpn, &self.paths, Some(&socket))?;
                Ok((spec, Some((socket, login))))
            }
            (VpnKind::Openvpn, None) => {
                spec.argv = driver::openvpn_cmd(&self.vpn, &self.paths, None)?;
                Ok((spec, None))
            }
            (VpnKind::Fortinet | VpnKind::Inode, None) => Err(VpnError::BlankPassword),
            (VpnKind::Wireguard, _) => Err(VpnError::Guard(GuardError("WireGuard has no client process".into()))),
        }
    }

    fn spawn(&mut self, creds: Option<Login>) -> Result<(), VpnError> {
        // Retire the previous attempt first, so a late line from it cannot
        // land in this one.
        self.retire_attempt();
        if let Some(old) = self.lingering.take() {
            if !proc::terminate(&*old, self.tun.term_grace, &*self.deps.clock, &*self.deps.log, self.binary()) {
                // Two clients would fight over the same routes and device.
                self.lingering = Some(old);
                return Err(VpnError::Busy);
            }
            old.reap();
        }
        let (spec, mgmt) = self.command(creds)?;
        let spawned = self.deps.spawner.spawn(&spec).map_err(|e| VpnError::io("spawn", e));
        drop(spec);
        let spawned = spawned?;
        let child = spawned.child;
        let done = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(AttemptState::default()));
        *lock(&self.shared.child) = Some(child.clone());

        let sink = LineSink {
            kind: self.kind,
            binary: self.binary(),
            state: state.clone(),
            clock: self.deps.clock.clone(),
            notifier: self.deps.notifier.clone(),
            log: self.deps.log.clone(),
        };
        let (mut output, reader_done) = (spawned.output, done.clone());
        // The reader must keep draining whatever a line does: a dead reader
        // leaves the child blocked on a full pipe with the tunnel apparently up.
        let reader = Worker::spawn("vpn-reader", move || {
            while let Some(line) = LineSource::next_line(&mut *output, &reader_done) {
                sink.on_line(&line);
            }
        });
        let mgmt = mgmt.map(|(path, login)| {
            Worker::spawn("vpn-mgmt", self.mgmt_thread(path, login, child.clone(), (done.clone(), state.clone())))
        });
        let mut attempt = Attempt { child, done, state, reader: None, mgmt: None };
        let mut failed = None;
        match reader {
            Ok(worker) => attempt.reader = Some(worker),
            Err(e) => failed = Some(e),
        }
        match mgmt {
            Some(Ok(worker)) => attempt.mgmt = Some(worker),
            Some(Err(e)) => failed = Some(e),
            None => {}
        }
        self.attempt = Some(attempt);
        if let Some(e) = failed {
            // Without its helper threads the client would hang unread or
            // unauthenticated; stop it and report the attempt as not started.
            self.terminate_current();
            self.retire_attempt();
            return Err(VpnError::io("helper thread", e));
        }
        Ok(())
    }

    fn terminate_current(&self) {
        if let Some(attempt) = &self.attempt {
            proc::terminate(&*attempt.child, self.tun.term_grace, &*self.deps.clock, &*self.deps.log, self.binary());
        }
    }

    /// End the finished attempt: clear its process group, reap the client,
    /// stop its helper threads. Bounded — the threads are told to stop and
    /// given a moment, never waited on indefinitely, so a held pipe cannot
    /// wedge the supervisor; and a fast connect/drop flap cannot accumulate
    /// threads, descriptors or tunnel helpers.
    fn retire_attempt(&mut self) -> (AttemptState, i32) {
        let Some(mut attempt) = self.attempt.take() else {
            return (AttemptState::default(), -1);
        };
        attempt.done.store(true, Ordering::Relaxed);
        let rc = proc::reap_group(&*attempt.child, 2.0, &*self.deps.clock);
        for (name, worker) in [("reader thread", attempt.reader.as_mut()), ("mgmt thread", attempt.mgmt.as_mut())] {
            if worker.is_some_and(|w| !w.join_timeout(Duration::from_secs(2))) {
                self.log(&format!("WARNING {name} still running after its attempt ended"));
            }
        }
        *lock(&self.shared.child) = None;
        if rc.is_none() {
            self.lingering = Some(attempt.child.clone());
        }
        let state = lock(&attempt.state).clone();
        (state, rc.unwrap_or(-1))
    }

    /// Evidence of a live tunnel that does not rest on log classification, so
    /// a client whose wording changed is not killed for never saying "up".
    fn looks_connected(&self) -> bool {
        let probe = self.vpn.text("ready_probe");
        if !probe.is_empty() {
            return self.deps.prober.tcp(&probe, 3.0) == Probe::Ok;
        }
        self.deps.prober.iface_up(&expected_iface(&self.vpn))
    }

    /// Wait for the client to exit; meanwhile heartbeat and health-check.
    fn watch_child(&mut self) {
        let Some(attempt) = &self.attempt else {
            return;
        };
        let (child, state) = (attempt.child.clone(), attempt.state.clone());
        let binary = self.binary();
        let mut connect_by = (self.tun.connect_timeout > 0.0).then(|| self.now() + self.tun.connect_timeout);
        let interval = self.vpn.int("health_check_interval").max(0) as f64; // audit-allow: lossless, seconds far below 2^53
        let threshold = match self.vpn.int("health_check_failures") {
            n if n > 0 => n,
            _ => 3,
        };
        let probe = self.vpn.text("ready_probe");
        let mut next_check = (interval > 0.0 && !probe.is_empty()).then(|| self.now() + interval);
        let mut failures = 0;
        let mut auth_polls = 0;
        while !child.exited() {
            if self.stopping() {
                self.terminate_current();
                break;
            }
            self.ping();
            let seen = lock(&state).clone();
            if seen.abort {
                self.terminate_current();
                break;
            }
            if seen.saw.auth {
                auth_polls += 1;
                if auth_polls > AUTH_EXIT_POLLS {
                    // Left running it would retry by itself (openfortivpn
                    // --persistent, openvpn auth-retry) with the password the
                    // gateway just rejected.
                    self.log(&format!(
                        "{binary} reported an authentication failure but is still running; stopping it so the \
                         lockout hold applies"
                    ));
                    self.terminate_current();
                    break;
                }
            }
            if connect_by.is_some_and(|by| !seen.tunnel_up && self.now() >= by) {
                // Health checks only run once up, so a client hung before that
                // (a stalled gateway, a passphrase prompt nobody answers) would
                // otherwise be waited on forever.
                connect_by = None;
                if !self.looks_connected() {
                    self.log(&format!("no tunnel after {:.0}s; restarting {binary}", self.tun.connect_timeout));
                    self.status("connect timed out; reconnecting");
                    self.terminate_current();
                    break;
                }
            }
            if next_check.is_some_and(|at| seen.tunnel_up && self.now() >= at) {
                next_check = Some(self.now() + interval);
                if self.deps.prober.tcp(&probe, 3.0) == Probe::Ok {
                    failures = 0;
                } else {
                    failures += 1;
                    self.log(&format!("health check: {probe} unreachable ({failures}/{threshold})"));
                    if failures >= threshold {
                        self.log(&format!("health check failed — tunnel looks dead; restarting {binary}"));
                        self.status("health check failed; reconnecting");
                        self.terminate_current();
                        break;
                    }
                }
            }
            self.deps.clock.wait(&self.shared.stop, self.tun.poll);
        }
    }

    // --- target description and dry run -----------------------------------------

    fn target(&self) -> String {
        match self.kind {
            VpnKind::Fortinet => format!("to {}", self.vpn.text("gateway")),
            VpnKind::Openvpn => format!("OpenVPN ({})", self.vpn.text("config")),
            VpnKind::Inode => format!("iNode SSL-VPN ({})", self.vpn.text("gateway")),
            VpnKind::Wireguard => format!("WireGuard ({})", wireguard_target(&self.vpn)),
        }
    }

    fn dry_print(&self, creds: Option<&Login>) {
        let user = creds.map(|c| c.username.as_str()).unwrap_or("<user>");
        let built = match self.kind {
            VpnKind::Fortinet => {
                let otp = (self.tun.otp_on_argv && self.vpn.truthy("otp_from_vault")).then_some("<otp>");
                driver::fortinet_cmd(&self.vpn, &self.paths, user, otp)
            }
            VpnKind::Inode => driver::inode_cmd(&self.vpn, &self.paths, user),
            VpnKind::Openvpn => {
                let socket = creds.map(|_| lock(&self.shared.scratch).mgmt_preview());
                driver::openvpn_cmd(&self.vpn, &self.paths, socket.as_deref())
            }
            VpnKind::Wireguard => driver::wireguard_up(&self.vpn, &self.paths),
        };
        let cmd = match built {
            Ok(cmd) => cmd,
            Err(e) => {
                self.log(&format!("DRY RUN — config rejected: {e}"));
                return;
            }
        };
        self.log(&format!("DRY RUN — would run: {}", driver::redact_argv(&cmd).join(" ")));
        let user = printable(user);
        match self.kind {
            VpnKind::Fortinet => {
                self.log(&format!(
                    "resolved user='{user}'; password fed via {} (not shown)",
                    self.paths.pinentry.display()
                ));
            }
            VpnKind::Inode => {
                self.log(&format!("resolved user='{user}'; password fed via $H3C_SVPN_PASSWORD (not shown)"))
            }
            VpnKind::Openvpn if creds.is_some() => {
                self.log(&format!("resolved user='{user}'; password injected over the management socket (not shown)"));
            }
            _ => {}
        }
    }

    // --- the loop (process drivers) ---------------------------------------------

    fn run_process(&mut self) -> i32 {
        let needs = driver::needs_creds(self.kind, &self.vpn);
        // A dry run is a config check: it must work without the binary.
        if self.tun.dry_run {
            // A Notes overlay stays in memory and may hold the gateway the
            // command needs; an .ovpn would put keys on disk just for a check.
            if matches!(self.kind, VpnKind::Fortinet | VpnKind::Inode) && !self.materialize_config() {
                self.log("DRY RUN — could not load the VPN config from the vault");
                return 0;
            }
            let creds = if needs { self.resolve_creds(self.tun.ready_timeout) } else { None };
            self.dry_print(creds.as_ref());
            return 0;
        }

        let program = driver::resolve_binary(self.kind, &self.vpn, &self.paths);
        if !self.deps.spawner.executable(&program) {
            self.log(&format!(
                "FATAL: {program} not found / not executable — install it (or fix vpn.config) and restart the VPN \
                 service"
            ));
            self.status(&format!("{} is not available", program.rsplit('/').next().unwrap_or(&program)));
            return self.idle();
        }

        let root = lock(&self.shared.scratch).root().to_path_buf();
        scratch::sweep(&root);
        // From here on a 0600 profile (private keys) may sit in the runtime dir.
        let guard = Teardown(self);
        guard.0.await_config();
        guard.0.run_loop()
    }

    fn run_loop(&mut self) -> i32 {
        let target = self.target();
        let needs = driver::needs_creds(self.kind, &self.vpn);
        let slow_retry = self.tun.slow_retry();
        let mut attempt = 0u64;

        while !self.stopping() {
            let mut creds = None;
            if needs {
                creds = self.resolve_creds(self.tun.ready_timeout);
                if creds.is_none() {
                    if self.stopping() {
                        break;
                    }
                    // Vault outage: keep the service alive, retry on the slow path.
                    self.status("vault unavailable; retrying");
                    self.sleep(slow_retry);
                    continue;
                }
            }
            // The vault may have taken a while: no new login once a stop was
            // requested.
            if self.stopping() {
                break;
            }

            attempt += 1;
            let who = creds.as_ref().map(|c| format!(" as '{}'", printable(&c.username))).unwrap_or_default(); // audit-allow: default is the intended fallback (no username suffix)
            self.log(&format!("connecting {target}{who} (attempt {attempt})"));
            self.status(&format!("connecting {target} (attempt {attempt})"));
            match self.spawn(creds) {
                Ok(()) => {}
                Err(VpnError::OtpUnavailable) => {
                    // No client was started. A transient fetch fault, not a
                    // rejected credential: take the slow vault path rather
                    // than the long lockout hold.
                    let item = self.item();
                    self.log(&format!(
                        "could not retrieve the OTP from vault item '{item}' — not attempting a blank-OTP login; \
                         retrying shortly"
                    ));
                    self.status(&format!("could not retrieve OTP from vault item {item}"));
                    self.sleep(slow_retry);
                    self.refresh_vault();
                    continue;
                }
                Err(VpnError::BlankPassword) => {
                    let item = self.item();
                    self.log(&format!(
                        "vault item '{item}' has no password — not attempting a blank login; retrying shortly"
                    ));
                    self.status(&format!("vault item {item} has no password"));
                    self.sleep(slow_retry);
                    self.refresh_vault();
                    continue;
                }
                Err(e) => {
                    self.log(&format!("ERROR could not start {}: {e}", self.binary()));
                    let delay = self.backoff.next_delay();
                    self.sleep(delay);
                    continue;
                }
            }

            self.watch_child();
            let (state, rc) = self.retire_attempt();
            if self.stopping() {
                break;
            }
            self.after_attempt(&state, rc);
        }

        self.terminate_current();
        self.log("stopped");
        self.status("stopped");
        0
    }

    /// The client is gone — decide how angrily to come back.
    fn after_attempt(&mut self, state: &AttemptState, rc: i32) {
        let (kind, bar) = (self.kind, "=".repeat(70));
        match verdict(state, self.now(), self.tun.stable_after()) {
            Verdict::MgmtUnreachable => {
                // Authentication was never even attempted: a setup fault, so
                // do not spin on the same broken path with a short delay.
                self.log(&bar);
                self.log(&format!("OPENVPN MANAGEMENT SOCKET UNREACHABLE ({kind}, exit {rc})."));
                self.log(
                    "  openvpn could not be authenticated because its management socket never came up; verify \
                     openvpn can create the socket (runtime dir perms, selinux/apparmor).",
                );
                self.log(&format!("  Backing off {:.0}s before retrying.", self.tun.auth_delay));
                self.log(&bar);
                self.status("OpenVPN management socket unreachable (long backoff)");
                self.sleep(self.tun.auth_delay);
            }
            Verdict::AuthFailed => {
                self.log(&bar);
                self.log(&format!("AUTHENTICATION FAILED ({kind}, exit {rc})."));
                self.log(&format!("  * check the username/password in vault item '{}'", self.item()));
                if kind == VpnKind::Fortinet {
                    self.log(
                        "  * check vpn.realm and that SSL-VPN tunnel mode is enabled for this user/group on the \
                         FortiGate",
                    );
                    if self.vpn.truthy("otp_from_vault") {
                        self.log("  * OTP was attached — verify the TOTP secret in the vault item");
                    }
                }
                self.log(&format!(
                    "  NOT retrying for {:.0}s — rapid retries with a bad password can LOCK the account",
                    self.tun.auth_delay
                ));
                self.log(&bar);
                self.status("authentication failed; fix the vault credentials (long backoff)");
                self.sleep(self.tun.auth_delay);
                // The fix may be a rotated secret.
                self.refresh_vault();
            }
            Verdict::CertFailed => {
                self.log(&bar);
                self.log(&format!("CERTIFICATE VALIDATION FAILED ({kind}, exit {rc})."));
                if kind == VpnKind::Fortinet {
                    self.log(
                        "  Pin the gateway cert: copy the sha256 digest from the message above into \
                         vpn.trusted_cert, or set vpn.ca_file.",
                    );
                } else {
                    self.log(
                        "  The server certificate did not verify. Check the ca/cert/key in the .ovpn profile and \
                         the system clock.",
                    );
                }
                self.log("  Retrying cannot succeed until the config is fixed.");
                self.log(&bar);
                self.status("certificate validation failed (long backoff)");
                self.sleep(self.tun.cert_delay);
            }
            Verdict::Dropped { stable, closed } => {
                if stable {
                    self.backoff.reset();
                }
                let delay = self.backoff.next_delay();
                let why =
                    if closed { "connection closed".to_string() } else { format!("{} exited ({rc})", self.binary()) };
                self.log(&format!("{why}; reconnecting in {delay:.0}s"));
                self.status(&format!("disconnected; reconnecting in {delay:.0}s"));
                self.sleep(delay);
            }
        }
    }

    /// Release everything a supervise loop may hold. Idempotent.
    pub fn teardown(&mut self) {
        if driver::is_interface(self.kind) {
            // `down` first: wg-quick reads the .conf to take the interface down.
            match driver::wireguard_down(&self.vpn, &self.paths) {
                Ok(down) => {
                    self.oneshot(&down);
                }
                Err(e) => self.log(&format!("WARNING cannot take the interface down: {e}")),
            }
            lock(&self.shared.scratch).cleanup();
            return;
        }
        // Key material first: removing it cannot hang, while a stuck client
        // can use up all of systemd's stop timeout.
        lock(&self.shared.scratch).cleanup();
        self.terminate_current();
        self.retire_attempt();
        if let Some(old) = self.lingering.take() {
            if proc::terminate(&*old, 2.0, &*self.deps.clock, &*self.deps.log, self.binary()) {
                old.reap();
            } else {
                self.lingering = Some(old);
            }
        }
    }

    // --- the loop (interface driver: WireGuard) ---------------------------------

    fn oneshot(&self, argv: &[String]) -> (i32, String) {
        // Each step may legitimately take a minute: beat on both sides.
        self.ping();
        let (rc, out) = self.deps.spawner.oneshot(argv, 60.0);
        self.ping();
        (rc, printable(&out.replace('\n', " | ")))
    }

    fn wg(&self, args: &[&str]) -> (i32, String) {
        let mut argv = vec![self.paths.programs.wg.clone()];
        argv.extend(args.iter().map(|a| a.to_string()));
        self.ping();
        let result = self.deps.spawner.oneshot(&argv, 60.0);
        self.ping();
        result
    }

    fn wg_is_up(&self, iface: &str) -> bool {
        self.wg(&["show", iface]).0 == 0
    }

    /// Whether any peer completed a handshake within the last three minutes.
    fn wg_handshake_ok(&self, iface: &str) -> bool {
        let (rc, out) = self.wg(&["show", iface, "latest-handshakes"]);
        if rc != 0 {
            return false;
        }
        let now = self.deps.clock.unix_time();
        out.lines().any(|line| {
            let stamp = line.split_whitespace().next_back().and_then(|last| last.parse::<u64>().ok());
            stamp.is_some_and(|ts| ts > 0 && now - (ts as f64) < 180.0) // audit-allow: lossless, unix seconds far below 2^53
        })
    }

    fn run_interface(&mut self) -> i32 {
        if self.tun.dry_run {
            self.dry_print(None);
            return 0;
        }
        let program = self.paths.programs.wg_quick.clone();
        if !self.deps.spawner.executable(&program) {
            self.log(&format!("FATAL: {program} not found — install wireguard-tools and restart the VPN service"));
            self.status("wg-quick is not installed");
            return self.idle();
        }
        let root = lock(&self.shared.scratch).root().to_path_buf();
        scratch::sweep(&root);
        // A materialized .conf holds a private key: teardown on every way out,
        // so a crash cannot leave the key on disk or the interface installed.
        let guard = Teardown(self);
        guard.0.await_config();
        guard.0.run_interface_loop()
    }

    fn run_interface_loop(&mut self) -> i32 {
        let probe = self.vpn.text("ready_probe");
        let interval = match self.vpn.int("health_check_interval") {
            n if n > 0 => n as f64, // audit-allow: lossless, seconds far below 2^53
            _ => 30.0,
        };
        let threshold = match self.vpn.int("health_check_failures") {
            n if n > 0 => n,
            _ => 3,
        };
        let iface = driver::wireguard_iface(&self.vpn);
        let commands = driver::wireguard_up(&self.vpn, &self.paths)
            .and_then(|up| Ok((up, driver::wireguard_down(&self.vpn, &self.paths)?)));
        let (up, down) = match commands {
            Ok(pair) if driver::valid_iface(&iface) => pair,
            Ok(_) => {
                self.log("FATAL: vpn.config does not name a valid WireGuard interface");
                self.status("invalid WireGuard config");
                return self.idle();
            }
            Err(e) => {
                self.log(&format!("FATAL: {e}"));
                self.status("invalid WireGuard config");
                return self.idle();
            }
        };
        let target = wireguard_target(&self.vpn);
        let tick = self.tun.heartbeat();

        let mut first = true;
        while !self.stopping() {
            if !self.wg_is_up(&iface) {
                self.log(&format!("bringing up WireGuard ({target})"));
                self.status(&format!("connecting WireGuard {iface}"));
                let (rc, out) = self.oneshot(&up);
                if rc != 0 {
                    let delay = self.backoff.next_delay();
                    self.log(&format!("wg-quick up failed (rc {rc}): {out}; retrying in {delay:.0}s"));
                    self.status("wg-quick up failed; retrying");
                    self.sleep(delay);
                    continue;
                }
                self.log("WireGuard interface up");
                self.status("connected: WireGuard up");
            } else if first {
                // A previous run left the interface up (its teardown never
                // ran). Cycle it once so fresh keys and routes are asserted
                // instead of trusting a stale interface.
                first = false;
                self.log(&format!(
                    "WireGuard {iface} already up at start — cycling once to reassert fresh keys/routes"
                ));
                self.oneshot(&down);
                continue;
            }
            first = false;
            let mut failures = 0;
            let mut next_check = self.now() + interval;
            while !self.stopping() {
                self.ping();
                if self.now() >= next_check {
                    next_check = self.now() + interval;
                    let healthy = if probe.is_empty() {
                        self.wg_handshake_ok(&iface)
                    } else {
                        self.deps.prober.tcp(&probe, 3.0) == Probe::Ok
                    };
                    if healthy {
                        failures = 0;
                        // Here, not at `wg-quick up`: that succeeds without
                        // ever reaching the peer, so it proves nothing.
                        self.backoff.reset();
                    } else {
                        failures += 1;
                        self.log(&format!("WireGuard health check failed ({failures}/{threshold})"));
                        if failures >= threshold {
                            self.log("cycling the WireGuard interface");
                            self.status("health check failed; reconnecting");
                            let (rc, out) = self.oneshot(&down);
                            if rc != 0 && self.wg_is_up(&iface) {
                                // The next `wg-quick up` would refuse an
                                // interface that still exists.
                                self.log(&format!("wg-quick down failed (rc {rc}): {out}; force-removing {iface}"));
                                let ip = self.paths.programs.ip.clone();
                                self.oneshot(&[ip, "link".into(), "delete".into(), "dev".into(), iface.clone()]);
                            }
                            break;
                        }
                    }
                }
                let left = (next_check - self.now()).max(0.0);
                self.deps.clock.wait(&self.shared.stop, tick.min(left));
            }
            if self.stopping() {
                break;
            }
            let delay = self.backoff.next_delay();
            self.log(&format!("reconnecting WireGuard in {delay:.0}s"));
            self.sleep(delay);
        }
        self.log("stopped");
        self.status("stopped");
        0
    }
}

/// Back doors for tests that need to stage a supervisor mid-flight.
#[cfg(test)]
pub(crate) mod test_access {
    use super::*;

    pub(crate) fn write_secret(handle: &Handle, name: &str, content: &str) -> PathBuf {
        lock(&handle.shared.scratch).write_secret(name, content).expect("write secret")
    }

    pub(crate) fn set_child(handle: &Handle, child: Arc<dyn ChildProc>) {
        *lock(&handle.shared.child) = Some(child);
    }
}

#[cfg(test)]
mod tests;
