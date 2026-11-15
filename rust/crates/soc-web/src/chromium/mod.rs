//! The Chromium engine: one `chromium --app` window per panel, driven over the
//! Chrome DevTools Protocol from a control thread.
//!
//! The thread
//!
//! * starts Chromium on a dark placeholder page and attaches DevTools;
//! * installs the credential-free bootstrap, the tracker block, the download
//!   ban and the navigation gate, and only then navigates to the panel's URL;
//! * polls the page and, when it asks for a login *on the panel's own origin*,
//!   fetches credentials just-in-time and evaluates the guarded `socLogin`
//!   call;
//! * answers the proxy's auth challenges from the vault;
//! * restarts Chromium with a doubling backoff when it dies, and parks the
//!   panel after too many straight failures (on an unattended wall a park is
//!   only a long pause).
//!
//! The websocket belongs to that thread alone. Other threads talk to it
//! through [`ChromiumPanel`]'s methods, which only queue commands; state comes
//! back through the [`PanelEvent`] callback.
//!
//! DevTools exposure: Chromium is asked for an ephemeral port
//! (`--remote-debugging-port=0`) and reports it in a file inside the 0700
//! profile directory, so the port is neither guessable from the config nor
//! squattable before launch, and the endpoint the host connects to is one its
//! own browser bound. No `--remote-allow-origins` is passed, so no page script
//! can reach the debugger. A local process of the same user can still talk to
//! the port — closing that needs `--remote-debugging-pipe`.

mod argv;
mod cdp;
mod process;
mod session;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use soc_core::guard::{url_for_msg, valid_http_url};
use soc_core::{CredSource, Dict, Engine, Login, Mode, Panel, ProxyCfg, SecurityCfg};

pub use argv::{
    ACTIVE_PORT_FILE, LaunchEnv, LaunchSpec, UNCONFIGURED_URL, chromium_argv, find_chromium, hwaccel_enabled,
    hwaccel_flags, ozone_platform, prepare_profile, private_dir, profile_dir, proxy_flags,
};
pub use cdp::{CdpError, Endpoint};
pub use process::{Browser, Launcher, SystemLauncher};
pub use session::{MAX_LOGIN_ATTEMPTS, PROXY_AUTH_MAX_ATTEMPTS};

use crate::error::Error;
use crate::inject::{self, Calibration};
use crate::loginmemory::LoginMemory;
use crate::siteguard::{self, AllowList};
use crate::style::StatusCard;
use crate::websecurity::SecurityData;
use session::{Attach, Guard, LoginState, PageState, PanelCtx, ProxyAuth, Session};

/// A still-alive process whose poll fails this many times in a row has an
/// unusable session: re-attach rather than evaluating against it forever.
const MAX_POLL_FAILURES: u32 = 2;
/// Longest stretch the control thread goes without looking at its commands.
const COMMAND_SLICE: Duration = Duration::from_millis(500);

/// The control loop's clocks. The defaults are the production values; tests
/// shrink them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timing {
    /// First restart delay; doubled up to `respawn_max` after each failure.
    pub respawn_initial: Duration,
    pub respawn_max: Duration,
    /// The backoff resets only after a browser has survived this long.
    pub respawn_stable: Duration,
    /// Hard ceiling on one DevTools round-trip.
    pub rpc_timeout: Duration,
    /// Poll period while a page is loading, logging in or failing.
    pub poll_interval: Duration,
    /// Poll period once a page is loaded with nothing pending. Navigations
    /// and crashes cut it short by themselves.
    pub poll_settled: Duration,
    /// How long a parked panel waits before trying again (unattended only).
    pub park_retry: Duration,
    /// How long a new browser gets to open its DevTools endpoint.
    pub attach_timeout: Duration,
    pub attach_poll: Duration,
    /// Fast event pumping after the first navigation, for proxy challenges.
    pub proxy_auth_window: Duration,
    pub calibrate_timeout: Duration,
    /// How long a browser gets to exit after SIGTERM before it is killed.
    pub reap_grace: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        let s = Duration::from_secs;
        Timing {
            respawn_initial: s(5),
            respawn_max: s(60),
            respawn_stable: s(30),
            rpc_timeout: s(30),
            poll_interval: s(2),
            poll_settled: s(15),
            park_retry: s(600),
            attach_timeout: s(20),
            attach_poll: Duration::from_millis(250),
            proxy_auth_window: s(20),
            calibrate_timeout: s(300),
            reap_grace: s(5),
        }
    }
}

/// What a panel is doing, for its status card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelStatus {
    /// No URL configured: the tile shows the dark placeholder.
    Unconfigured,
    /// A browser is up and the page is loading.
    Connecting,
    /// The top document finished loading over http(s).
    Online,
    /// The browser's error page is showing. `retry_in` is set when the host
    /// re-navigates by itself (unattended walls).
    Offline {
        retry_in: Option<Duration>,
    },
    /// The browser died or could not be driven; it restarts after `retry_in`.
    Recovering {
        reason: String,
        retry_in: Duration,
    },
    /// Too many straight failures. Re-armed by `set_url` / `reload`, or by
    /// itself after `retry_in` on an unattended wall.
    Parked {
        reason: String,
        retry_in: Option<Duration>,
    },
    /// The proxy rejected the vault's credentials.
    ProxyAuthFailed,
    Stopped,
}

impl PanelStatus {
    /// The card to show over the panel in this state (`None`: show the page).
    pub fn card(&self, panel_name: &str) -> Option<StatusCard> {
        let secs = |d: &Duration| d.as_secs().max(1);
        Some(match self {
            PanelStatus::Online | PanelStatus::Stopped => return None,
            PanelStatus::Unconfigured => StatusCard::unconfigured(panel_name),
            PanelStatus::Connecting => StatusCard::connecting(panel_name),
            PanelStatus::Offline { retry_in: Some(d) } => {
                StatusCard::offline(panel_name, "the page failed to load", secs(d))
            }
            PanelStatus::Offline { retry_in: None } => {
                StatusCard::new(panel_name, "offline: the page failed to load", true, false)
            }
            PanelStatus::Recovering { reason, retry_in } => StatusCard::recovering(panel_name, reason, secs(retry_in)),
            PanelStatus::Parked { reason, retry_in: Some(d) } => StatusCard::new(
                panel_name,
                format!("stopped after repeated failures ({reason})\nretrying in {}s", secs(d)),
                true,
                false,
            ),
            PanelStatus::Parked { reason, retry_in: None } => StatusCard::new(
                panel_name,
                format!("stopped after repeated failures ({reason})\nset a URL in Settings to retry"),
                true,
                false,
            ),
            PanelStatus::ProxyAuthFailed => StatusCard::proxy_auth_failed(panel_name),
        })
    }
}

/// What the engine reports. Delivered on the panel's control thread: a GUI
/// must hand the event to its own main loop before touching widgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanelEvent {
    /// A journal line, already prefixed with `[panel-id]`. Never contains a
    /// credential or a URL path.
    Log(String),
    /// The panel's state changed.
    Status(PanelStatus),
    /// The page reported a successful login on the panel's own origin.
    LoginSucceeded,
    /// Auto-login gave up; the in-page prompt asks a human to sign in.
    SignInNeeded,
    /// A document navigation off the allowlist was refused (scheme + host).
    NavBlocked(String),
}

/// Receives [`PanelEvent`]s (on the panel's control thread).
pub type EventFn = Arc<dyn Fn(PanelEvent) + Send + Sync>;
/// Produces a panel's login just-in-time; `None` when there is none.
pub type LoginFn = Arc<dyn Fn(&Panel) -> Option<Login> + Send + Sync>;
/// Produces the proxy's login just-in-time.
pub type ProxyLoginFn = Arc<dyn Fn() -> Option<Login> + Send + Sync>;

/// Callbacks a panel needs from its host.
#[derive(Clone)]
pub struct PanelHooks {
    pub on_event: EventFn,
    /// Credentials for a panel's login page. `None` shows the "no saved
    /// login" prompt instead.
    pub login: LoginFn,
    /// Credentials for the proxy (`proxy.vault_item`).
    pub proxy_login: Option<ProxyLoginFn>,
}

impl PanelHooks {
    /// Hooks backed by the vault.
    ///
    /// A panel logs in with its own `vault_item`, or — when it has none —
    /// with the item [`LoginMemory`] remembers for its configured origin. A
    /// panel that has its own item registers its origin at once, so other
    /// panels pointed at the same site can reuse it.
    pub fn from_vault(
        creds: Arc<dyn CredSource>,
        memory: Option<Arc<LoginMemory>>,
        proxy_vault_item: &str,
        on_event: EventFn,
    ) -> PanelHooks {
        let login: LoginFn = {
            let (creds, on_event) = (creds.clone(), on_event.clone());
            Arc::new(move |panel: &Panel| {
                let url = panel.effective_url();
                let item = if panel.vault_item.is_empty() {
                    memory.as_ref().map(|m| m.vault_item_for(&url)).unwrap_or_default() // audit-allow: default is the intended fallback (no memory -> "")
                } else {
                    panel.vault_item.clone()
                };
                if item.is_empty() {
                    return None;
                }
                if let Some(memory) = memory.as_ref().filter(|_| !panel.vault_item.is_empty()) {
                    if let Err(e) = memory.remember(&url, &item) {
                        on_event(PanelEvent::Log(format!("[{}] login memory: {e}", panel.id)));
                    }
                }
                match creds.creds(&item) {
                    Ok(login) => Some(login),
                    Err(e) => {
                        on_event(PanelEvent::Log(format!("[{}] vault: {e}", panel.id)));
                        None
                    }
                }
            })
        };
        let proxy_login = (!proxy_vault_item.is_empty()).then(|| {
            let (creds, item) = (creds, proxy_vault_item.to_string());
            Arc::new(move || creds.creds(&item).ok()) as ProxyLoginFn
        });
        PanelHooks { on_event, login, proxy_login }
    }
}

/// Everything about the machine and the wall a panel needs besides its own
/// configuration.
#[derive(Clone)]
pub struct ChromiumOptions {
    /// The Chromium binary; `None` searches `$PATH` at each launch.
    pub binary: Option<PathBuf>,
    /// A fixed DevTools port. `None` (the default) lets Chromium pick one and
    /// reads it back from the private profile directory.
    pub cdp_port: Option<u16>,
    /// The private web-data base (profiles live in `<base>/chromium/<id>`).
    pub webdata_dir: PathBuf,
    /// The per-user runtime directory (`$XDG_RUNTIME_DIR`), for the profiles
    /// of `persist: false` panels.
    pub runtime_dir: Option<PathBuf>,
    pub launch: LaunchEnv,
    /// Nobody is at this box: retry forever instead of waiting for a human.
    pub unattended: bool,
    /// Straight launch/attach failures before the panel parks.
    pub max_respawns: u32,
    pub proxy: Option<ProxyCfg>,
    pub security: SecurityCfg,
    pub data: Arc<SecurityData>,
    pub timing: Timing,
    pub launcher: Arc<dyn Launcher>,
}

impl ChromiumOptions {
    /// Safe defaults around a web-data directory.
    pub fn new(webdata_dir: impl Into<PathBuf>) -> ChromiumOptions {
        ChromiumOptions {
            binary: None,
            cdp_port: None,
            webdata_dir: webdata_dir.into(),
            runtime_dir: None,
            launch: LaunchEnv::default(),
            unattended: false,
            max_respawns: 20,
            proxy: None,
            security: SecurityCfg::default(),
            data: Arc::new(SecurityData::embedded()),
            timing: Timing::default(),
            launcher: Arc::new(SystemLauncher),
        }
    }

    /// [`new`](Self::new) plus what the environment says: `$PATH`,
    /// `$XDG_RUNTIME_DIR`, `$SOC_MAX_RESPAWNS`, the `$SOC_CHROMIUM_*`
    /// variables and the security data overrides. `low_memory`, `arm_gpu` and
    /// `unattended` come from the caller's hardware / deployment probe.
    pub fn from_env(
        webdata_dir: impl Into<PathBuf>,
        low_memory: bool,
        arm_gpu: bool,
        unattended: bool,
    ) -> ChromiumOptions {
        let mut opts = ChromiumOptions::new(webdata_dir);
        opts.binary = soc_core::env::env_str("PATH").and_then(|p| find_chromium(&p));
        opts.runtime_dir = soc_core::env::env_str("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|p| p.is_absolute());
        opts.launch = LaunchEnv::from_env(low_memory, arm_gpu);
        opts.unattended = unattended;
        opts.max_respawns = u32::try_from(soc_core::env::env_int("SOC_MAX_RESPAWNS", 20, Some(1), Some(100_000)))
            .unwrap_or(opts.max_respawns);
        opts.data = Arc::new(SecurityData::global().clone());
        opts
    }
}

/// A restart delay that doubles up to a ceiling.
#[derive(Debug, Clone)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    delay: Duration,
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Backoff {
        Backoff { initial, max, delay: initial }
    }

    /// The delay to wait now; the next one is twice as long.
    pub fn next_delay(&mut self) -> Duration {
        let now = self.delay;
        self.delay = (self.delay * 2).min(self.max);
        now
    }

    pub fn reset(&mut self) {
        self.delay = self.initial;
    }
}

type CalibrateDone = Box<dyn FnOnce(Option<Dict>) + Send>;

enum Cmd {
    Stop,
    /// Restart the browser now; `rearm` also clears a park and the backoff.
    Restart {
        rearm: bool,
    },
    Reload,
    Calibrate(CalibrateDone),
}

struct Shared {
    panel: Mutex<Panel>,
    cancel: Arc<AtomicBool>,
    page_ok: AtomicBool,
    parked: AtomicBool,
    pid: AtomicU32,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One Chromium-rendered panel.
pub struct ChromiumPanel {
    shared: Arc<Shared>,
    opts: ChromiumOptions,
    hooks: PanelHooks,
    running: Mutex<Option<(Sender<Cmd>, JoinHandle<()>)>>,
}

impl ChromiumPanel {
    pub fn new(panel: Panel, opts: ChromiumOptions, hooks: PanelHooks) -> ChromiumPanel {
        let shared = Arc::new(Shared {
            panel: Mutex::new(panel),
            cancel: Arc::new(AtomicBool::new(false)),
            page_ok: AtomicBool::new(false),
            parked: AtomicBool::new(false),
            pid: AtomicU32::new(0),
        });
        ChromiumPanel { shared, opts, hooks, running: Mutex::new(None) }
    }

    /// Start the control thread (a no-op while it is running).
    pub fn start(&self) {
        let mut running = lock(&self.running);
        if running.is_some() {
            return;
        }
        self.shared.cancel.store(false, Ordering::Relaxed);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = Worker::new(self.shared.clone(), self.opts.clone(), self.hooks.clone(), rx);
        let name = format!("soc-chromium-{}", lock(&self.shared.panel).id);
        match std::thread::Builder::new().name(name).spawn(move || worker.run()) {
            Ok(handle) => *running = Some((tx, handle)),
            Err(e) => (self.hooks.on_event)(PanelEvent::Log(format!("chromium control thread: {e}"))),
        }
    }

    /// Stop the control thread and the browser, and wait for both. Chromium
    /// gets a moment to exit cleanly (it flushes cookies) before it is killed.
    pub fn stop(&self) {
        let Some((tx, handle)) = lock(&self.running).take() else {
            return;
        };
        self.shared.cancel.store(true, Ordering::Relaxed);
        let _ = tx.send(Cmd::Stop); // audit-allow: best-effort, a dead worker needs no stop
        let _ = handle.join(); // audit-allow: best-effort, a panicked worker has nothing left to clean
    }

    fn send(&self, cmd: Cmd) -> Result<(), Cmd> {
        match lock(&self.running).as_ref() {
            Some((tx, _)) => tx.send(cmd).map_err(|e| e.0),
            None => Err(cmd),
        }
    }

    /// Navigate back to the panel's URL (also un-parks a parked panel and
    /// gives a held proxy login a fresh chance).
    pub fn reload(&self) {
        let _ = self.send(Cmd::Reload); // audit-allow: best-effort, no running worker means nothing to signal
    }

    /// Restart the browser process, e.g. to reclaim memory. It comes back on
    /// the current URL within a few seconds.
    pub fn recycle(&self) {
        (self.hooks.on_event)(PanelEvent::Log(format!("[{}] recycling chromium", lock(&self.shared.panel).id)));
        let _ = self.send(Cmd::Restart { rearm: false }); // audit-allow: best-effort, no running worker means nothing to signal
    }

    /// Pick up a re-rendered bootstrap (new login zones, say). A script added
    /// to a live session cannot be replaced, so this restarts the browser.
    pub fn reinject(&self) {
        let _ = self.send(Cmd::Restart { rearm: false }); // audit-allow: best-effort, no running worker means nothing to signal
    }

    /// Repoint the panel (from the on-screen config). An empty string clears
    /// it. Anything but a plain http(s) URL is refused and changes nothing —
    /// in particular it does not re-arm a parked panel.
    pub fn set_url(&self, url: &str) -> Result<(), Error> {
        let url = url.trim();
        let id = lock(&self.shared.panel).id.clone();
        if !url.is_empty() && !valid_http_url(url, false) {
            let msg = format!("[{id}] refusing non-http(s) URL: {}", url_for_msg(url));
            (self.hooks.on_event)(PanelEvent::Log(msg.clone()));
            return Err(Error::Refused(msg));
        }
        {
            let mut panel = lock(&self.shared.panel);
            panel.url = (!url.is_empty()).then(|| url.to_string());
            if !url.is_empty() {
                panel.mode = Mode::Direct;
            }
        }
        let shown = if url.is_empty() { "(cleared)".to_string() } else { session::loggable_url(url) };
        (self.hooks.on_event)(PanelEvent::Log(format!("[{id}] reconfigured -> {shown}; restarting chromium")));
        self.shared.parked.store(false, Ordering::Relaxed);
        let _ = self.send(Cmd::Restart { rearm: true }); // audit-allow: best-effort, no running worker means nothing to signal
        Ok(())
    }

    /// Change the panel's configuration in place (login zones after a
    /// calibration, a title). Follow with [`reinject`](Self::reinject) when
    /// the change affects the injected script.
    pub fn update_panel<R>(&self, change: impl FnOnce(&mut Panel) -> R) -> R {
        change(&mut lock(&self.shared.panel))
    }

    /// A snapshot of the panel's configuration.
    pub fn panel(&self) -> Panel {
        lock(&self.shared.panel).clone()
    }

    /// Overlay the three-click calibration. `on_done` receives the captured
    /// zones, or `None` on cancel / timeout / a lost session. It is called on
    /// the control thread (or on the caller's, if the panel is not running).
    pub fn calibrate(&self, on_done: impl FnOnce(Option<Dict>) + Send + 'static) {
        if let Err(Cmd::Calibrate(on_done)) = self.send(Cmd::Calibrate(Box::new(on_done))) {
            on_done(None);
        }
    }

    /// True while the panel's page is loaded without error. Cheap; meant for
    /// a heartbeat.
    pub fn loaded_ok(&self) -> bool {
        self.shared.page_ok.load(Ordering::Relaxed)
    }

    pub fn is_parked(&self) -> bool {
        self.shared.parked.load(Ordering::Relaxed)
    }

    /// The browser process, for memory accounting (its renderers are its
    /// children).
    pub fn pid(&self) -> Option<u32> {
        Some(self.shared.pid.load(Ordering::Relaxed)).filter(|pid| *pid != 0)
    }
}

impl Drop for ChromiumPanel {
    fn drop(&mut self) {
        self.stop();
    }
}

// --------------------------------------------------------------------------- //
// Control thread
// --------------------------------------------------------------------------- //

struct Calib {
    src: String,
    on_done: CalibrateDone,
    injected: bool,
    deadline: Instant,
}

struct Worker {
    shared: Arc<Shared>,
    opts: ChromiumOptions,
    hooks: PanelHooks,
    rx: Receiver<Cmd>,
    id: String,
    browser: Option<Box<dyn Browser>>,
    session: Option<Session>,
    ctx: Option<PanelCtx>,
    profile: Option<PathBuf>,
    /// The ephemeral profile was emptied for this run already.
    wiped: bool,
    login: LoginState,
    backoff: Backoff,
    spawn_time: Instant,
    fail_streak: u32,
    parked: bool,
    park_until: Instant,
    poll_failures: u32,
    /// Unattended retry of a page stuck on the browser's error page.
    reload_delay: Duration,
    reload_at: Option<Instant>,
    calib: Option<Calib>,
    renderer_crashed: bool,
    last_status: Option<PanelStatus>,
}

impl Worker {
    fn new(shared: Arc<Shared>, opts: ChromiumOptions, hooks: PanelHooks, rx: Receiver<Cmd>) -> Worker {
        let id = lock(&shared.panel).id.clone();
        let backoff = Backoff::new(opts.timing.respawn_initial, opts.timing.respawn_max);
        let reload_delay = opts.timing.respawn_initial;
        Worker {
            shared,
            opts,
            hooks,
            rx,
            id,
            browser: None,
            session: None,
            ctx: None,
            profile: None,
            wiped: false,
            login: LoginState::default(),
            backoff,
            spawn_time: Instant::now(),
            fail_streak: 0,
            parked: false,
            park_until: Instant::now(),
            poll_failures: 0,
            reload_delay,
            reload_at: None,
            calib: None,
            renderer_crashed: false,
            last_status: None,
        }
    }

    fn log(&self, msg: impl AsRef<str>) {
        (self.hooks.on_event)(PanelEvent::Log(format!("[{}] {}", self.id, msg.as_ref())));
    }

    fn status(&mut self, status: PanelStatus) {
        if self.last_status.as_ref() != Some(&status) {
            self.last_status = Some(status.clone());
            (self.hooks.on_event)(PanelEvent::Status(status));
        }
    }

    fn set_page_ok(&self, ok: bool) {
        self.shared.page_ok.store(ok, Ordering::Relaxed);
    }

    fn stopping(&self) -> bool {
        self.shared.cancel.load(Ordering::Relaxed)
    }

    // ---- commands ------------------------------------------------------- //

    /// Apply one command. Returns `true` for a stop.
    fn handle(&mut self, cmd: Cmd) -> bool {
        match cmd {
            Cmd::Stop => return true,
            Cmd::Restart { rearm } => {
                if rearm {
                    self.unpark();
                }
                if self.browser.is_some() {
                    self.reap();
                }
            }
            Cmd::Reload => {
                if self.parked {
                    self.unpark();
                }
                let target = self.ctx.as_ref().and_then(|c| c.target.clone());
                if let (Some(session), Some(url)) = (self.session.as_mut(), target) {
                    session.guard.proxy_reset();
                    self.reload_at = None;
                    if let Err(e) = session.navigate(&url) {
                        self.log(format!("reload: {e}"));
                    }
                }
            }
            Cmd::Calibrate(on_done) => self.start_calibrate(on_done),
        }
        false
    }

    /// Apply queued commands without waiting. `Some(true)` = stop,
    /// `Some(false)` = something changed, `None` = nothing queued.
    fn drain(&mut self) -> Option<bool> {
        let mut changed = None;
        loop {
            match self.rx.try_recv() {
                Ok(cmd) => {
                    if self.handle(cmd) {
                        return Some(true);
                    }
                    changed = Some(false);
                }
                Err(TryRecvError::Empty) => return if self.stopping() { Some(true) } else { changed },
                Err(TryRecvError::Disconnected) => return Some(true),
            }
        }
    }

    /// Sleep for `delay`, waking at once for a command. Returns `true` for a
    /// stop; any other command ends the wait early so the loop can act on it.
    fn wait(&mut self, delay: Duration) -> bool {
        let deadline = Instant::now() + delay;
        loop {
            if self.stopping() {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match self.rx.recv_timeout(left.min(COMMAND_SLICE)) {
                Ok(cmd) => return self.handle(cmd),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return true,
            }
        }
    }

    // ---- lifecycle ------------------------------------------------------ //

    fn build_ctx(&self, panel: &Panel) -> PanelCtx {
        let sink = self.hooks.on_event.clone();
        let bootstrap =
            inject::bootstrap_with_origin(panel, Engine::Chromium, &mut |m| sink(PanelEvent::Log(m.to_string())));
        let security = &self.opts.security;
        let allowlist =
            siteguard::nav_gate_enabled(security).then(|| AllowList::build(panel, security, &self.opts.data));
        for entry in allowlist.iter().flat_map(AllowList::rejected) {
            self.log(format!("ignoring allowlist entry {entry:?}: not a host name"));
        }
        let blocked_urls = if siteguard::trackers_enabled(panel, security) {
            siteguard::chromium_blocked_urls(panel, &self.opts.data)
        } else {
            Vec::new()
        };
        let target = Some(panel.effective_url()).filter(|u| !u.is_empty());
        PanelCtx {
            bootstrap,
            origin: inject::allowed_origin(panel),
            target,
            allowlist,
            blocked_urls,
            proxy_auth: self.proxy_for(panel).is_some_and(|p| !p.vault_item.is_empty()),
            unattended: self.opts.unattended,
            panel: panel.clone(),
        }
    }

    /// The proxy this panel goes through, if any.
    fn proxy_for(&self, panel: &Panel) -> Option<&ProxyCfg> {
        self.opts.proxy.as_ref().filter(|p| p.enabled && panel.proxy)
    }

    fn spawn(&mut self) -> Result<(), Error> {
        let panel = lock(&self.shared.panel).clone();
        self.ctx = Some(self.build_ctx(&panel));
        // A fresh process gets a fresh login budget.
        self.login = LoginState::default();
        self.reload_at = None;
        let (profile, ephemeral) = profile_dir(&panel, &self.opts.webdata_dir, self.opts.runtime_dir.as_deref())?;
        if profile.starts_with(&self.opts.webdata_dir) {
            // The web-data base holds every panel's session tokens.
            private_dir(&self.opts.webdata_dir)?;
        }
        if let Some(pid) = process::reap_orphan(&profile) {
            self.log(format!("killed orphaned chromium (pid {pid})"));
        }
        for note in prepare_profile(&profile, ephemeral && !self.wiped)? {
            self.log(note);
        }
        self.wiped = true;
        let binary = self
            .opts
            .binary
            .clone()
            .or_else(|| soc_core::env::env_str("PATH").and_then(|p| find_chromium(&p)))
            .ok_or(Error::NoBrowser)?;
        let argv = chromium_argv(&LaunchSpec {
            panel: &panel,
            binary: &binary,
            profile_dir: &profile,
            cdp_port: self.opts.cdp_port.unwrap_or(0),
            proxy: self.opts.proxy.as_ref(),
            env: &self.opts.launch,
        })?;
        if self.opts.launch.no_sandbox {
            self.log("WARNING: chromium sandbox disabled (SOC_CHROMIUM_NO_SANDBOX) — development only");
        }
        let port = self.opts.cdp_port.map_or("auto".to_string(), |p| p.to_string());
        self.log(format!("chromium spawning (CDP :{port}, ozone {})", self.opts.launch.ozone));
        let browser = self.opts.launcher.launch(&argv).map_err(|e| Error::io("start chromium", e))?;
        self.shared.pid.store(browser.pid(), Ordering::Relaxed);
        self.browser = Some(browser);
        self.profile = Some(profile);
        self.status(if panel.effective_url().is_empty() { PanelStatus::Unconfigured } else { PanelStatus::Connecting });
        Ok(())
    }

    /// Wait for the browser's page endpoint to come up.
    fn find_endpoint(&mut self) -> Result<Endpoint, CdpError> {
        let deadline = Instant::now() + self.opts.timing.attach_timeout;
        let mut last = CdpError::Discovery("the browser has not opened its DevTools port".into());
        loop {
            if self.stopping() {
                return Err(CdpError::Stopped);
            }
            if self.browser.as_mut().is_none_or(|b| b.exited().is_some()) {
                return Err(CdpError::Discovery("chromium exited before DevTools came up".into()));
            }
            let port = self.opts.cdp_port.or_else(|| self.profile.as_deref().and_then(cdp::read_active_port));
            if let Some(port) = port {
                match cdp::discover(port) {
                    Ok(endpoint) => return Ok(endpoint),
                    // Whatever answered is not our browser; do not keep asking it.
                    Err(e @ CdpError::NotLoopback(_)) => return Err(e),
                    Err(e) => last = e,
                }
            }
            if Instant::now() >= deadline {
                return Err(last);
            }
            std::thread::sleep(self.opts.timing.attach_poll);
        }
    }

    fn attach(&mut self, mode: Attach) -> Result<(), CdpError> {
        self.session = None;
        let endpoint = self.find_endpoint()?;
        let Some(ctx) = self.ctx.as_ref() else {
            return Err(CdpError::Discovery("panel context missing".into()));
        };
        let proxy = match self.proxy_for(&ctx.panel) {
            Some(cfg) if ctx.proxy_auth => {
                Some(ProxyAuth::new(&cfg.url, &cfg.vault_item, self.hooks.proxy_login.clone(), self.opts.unattended))
            }
            _ => None,
        };
        let guard = Guard::new(&self.id, ctx.allowlist.clone(), proxy, self.hooks.on_event.clone());
        let session = Session::attach(&endpoint, ctx, guard, mode, &self.opts.timing, self.shared.cancel.clone())?;
        self.session = Some(session);
        self.log("chromium CDP attached + bootstrap installed");
        Ok(())
    }

    /// Terminate the browser, wait for it, and forget it.
    fn reap(&mut self) {
        self.finish_calibrate(None);
        self.session = None;
        if let Some(mut browser) = self.browser.take() {
            process::reap(browser.as_mut(), self.opts.timing.reap_grace);
        }
        self.shared.pid.store(0, Ordering::Relaxed);
        self.set_page_ok(false);
    }

    fn unpark(&mut self) {
        self.parked = false;
        self.fail_streak = 0;
        self.backoff.reset();
        self.shared.parked.store(false, Ordering::Relaxed);
    }

    /// Stop restarting a permanently-broken panel, so it cannot churn RAM,
    /// CPU and the SD card forever.
    fn park(&mut self, why: &str) {
        self.parked = true;
        self.shared.parked.store(true, Ordering::Relaxed);
        self.set_page_ok(false);
        self.park_until = Instant::now() + self.opts.timing.park_retry;
        let retry = self.opts.unattended.then_some(self.opts.timing.park_retry);
        let then = match retry {
            Some(d) => format!("retrying in {}s", d.as_secs()),
            None => "not respawning until reconfigured (set a URL in Settings)".to_string(),
        };
        self.log(format!("chromium parked after {} consecutive failures ({why}); {then}", self.fail_streak));
        self.status(PanelStatus::Parked { reason: why.to_string(), retry_in: retry });
    }

    /// Count one failed launch/attach, then back off (or park). Returns
    /// `true` for a stop.
    fn spawn_failed(&mut self, why: &str) -> bool {
        self.fail_streak += 1;
        if self.fail_streak >= self.opts.max_respawns {
            self.log(format!("{why} ({}/{})", self.fail_streak, self.opts.max_respawns));
            self.park(why);
            return false;
        }
        let delay = self.backoff.next_delay();
        self.log(format!("{why}; retrying in {}s ({}/{})", delay.as_secs(), self.fail_streak, self.opts.max_respawns));
        self.status(PanelStatus::Recovering { reason: why.to_string(), retry_in: delay });
        self.wait(delay)
    }

    fn run(mut self) {
        while !self.step() {}
        self.reap();
        self.status(PanelStatus::Stopped);
    }

    /// One turn of the control loop. Returns `true` to stop.
    fn step(&mut self) -> bool {
        if self.drain() == Some(true) {
            return true;
        }
        if self.parked {
            if self.opts.unattended && Instant::now() >= self.park_until {
                self.log("chromium park expired; trying again");
                self.unpark();
            } else {
                return self.wait(self.opts.timing.poll_interval);
            }
        }

        // (Re)start and (re)attach when the process is missing or dead.
        let exit = self.browser.as_mut().and_then(|b| b.exited());
        if let Some(code) = exit {
            self.reap();
            let delay = self.backoff.next_delay();
            self.log(format!("chromium exited ({code}); restarting in {}s", delay.as_secs()));
            self.status(PanelStatus::Recovering { reason: format!("exited ({code})"), retry_in: delay });
            // Back at the top afterwards: a command may have changed the plan.
            return self.wait(delay);
        }
        if self.browser.is_none() {
            if let Err(e) = self.spawn() {
                return self.spawn_failed(&format!("chromium spawn failed: {e}"));
            }
            if let Err(e) = self.attach(Attach::Fresh) {
                if e == CdpError::Stopped {
                    return true;
                }
                // A live process that cannot be driven is useless.
                self.log(format!("chromium CDP setup failed: {e}"));
                self.reap();
                return self.spawn_failed("chromium attach failed");
            }
            self.spawn_time = Instant::now();
            self.poll_failures = 0;
        }

        match self.poll_once() {
            Ok(settled) => {
                self.poll_failures = 0;
                // Clear the backoff only once the browser has survived a
                // while: one that attaches, polls once and dies must keep
                // climbing toward the maximum delay.
                if self.spawn_time.elapsed() >= self.opts.timing.respawn_stable {
                    self.backoff.reset();
                    self.fail_streak = 0;
                }
                let timing = &self.opts.timing;
                self.idle(if settled { timing.poll_settled } else { timing.poll_interval })
            }
            Err(CdpError::Stopped) => true,
            Err(e) => self.poll_failed(e),
        }
    }

    fn poll_failed(&mut self, e: CdpError) -> bool {
        self.set_page_ok(false);
        if std::mem::take(&mut self.renderer_crashed) {
            // The page is gone for good; only a new process brings it back —
            // after a backoff, so a page that crashes on load cannot spin.
            self.reap();
            let delay = self.backoff.next_delay();
            self.log(format!("renderer crashed; restarting chromium in {}s", delay.as_secs()));
            self.status(PanelStatus::Recovering { reason: "crashed".into(), retry_in: delay });
            return self.wait(delay);
        }
        if self.browser.as_mut().is_none_or(|b| b.exited().is_some()) {
            // The process died; the next turn restarts it.
            return false;
        }
        self.poll_failures += 1;
        let lost = self.session.as_ref().is_none_or(|s| !s.is_alive());
        if !lost && self.poll_failures < MAX_POLL_FAILURES {
            // Transient (a momentary navigation context drop): just retry.
            self.log(format!("chromium poll: {e}"));
            return self.idle(self.opts.timing.poll_interval);
        }
        let why = if lost { "socket lost".to_string() } else { format!("poll {} fails", self.poll_failures) };
        self.log(format!("chromium CDP session unusable ({why}): {e}; reattaching"));
        self.finish_calibrate(None);
        self.session = None;
        self.poll_failures = 0;
        match self.attach(Attach::Resume) {
            Ok(()) => {
                self.spawn_time = Instant::now();
                false
            }
            Err(CdpError::Stopped) => true,
            Err(e) => {
                self.reap();
                let delay = self.backoff.next_delay();
                self.log(format!("chromium reattach failed ({e}); respawning in {}s", delay.as_secs()));
                self.status(PanelStatus::Recovering { reason: "lost the browser".into(), retry_in: delay });
                self.wait(delay)
            }
        }
    }

    /// One poll of the page and everything that follows from it. Returns
    /// whether the page is settled (the next poll can wait).
    fn poll_once(&mut self) -> Result<bool, CdpError> {
        let closed = || CdpError::Closed("no session".into());
        let st = self.session.as_mut().ok_or_else(closed)?.poll()?;
        let (crashed, proxy_held) = {
            let guard = &mut self.session.as_mut().ok_or_else(closed)?.guard;
            (std::mem::take(&mut guard.crashed), guard.proxy_held())
        };
        if crashed {
            self.renderer_crashed = true;
            return Err(CdpError::Closed("renderer crashed".into()));
        }
        let unconfigured = self.ctx.as_ref().is_none_or(|c| c.target.is_none());
        // An error page is chrome-error:, an unconfigured tile is data: —
        // neither counts as loaded.
        self.set_page_ok(st.ready);
        if st.error_page {
            self.retry_error_page()?;
        } else {
            self.reload_delay = self.opts.timing.respawn_initial;
            self.reload_at = None;
        }
        self.status(if proxy_held {
            PanelStatus::ProxyAuthFailed
        } else if st.error_page {
            PanelStatus::Offline { retry_in: self.opts.unattended.then_some(self.reload_delay) }
        } else if st.ready {
            PanelStatus::Online
        } else if unconfigured {
            PanelStatus::Unconfigured
        } else {
            PanelStatus::Connecting
        });

        if let (Some(session), Some(ctx)) = (self.session.as_mut(), self.ctx.as_ref()) {
            if session.handle_login(&st, ctx, &mut self.login, &self.hooks.login, Instant::now())? {
                (self.hooks.on_event)(PanelEvent::LoginSucceeded);
            }
        }
        self.calibrate_step()?;
        Ok(self.settled(&st, unconfigured))
    }

    /// Nothing is pending on this page, so the next poll can wait. Before
    /// login and on anything unfinished the loop stays on the short interval.
    fn settled(&self, st: &PageState, unconfigured: bool) -> bool {
        if st.need_login || st.logged_in || st.error_page || self.calib.is_some() {
            return false;
        }
        st.ready || unconfigured
    }

    /// Unattended: a panel that failed to load sits on the error page with a
    /// healthy process, so nothing restarts it, and a tunnel or VPN that comes
    /// up late would never be noticed. Re-navigate on a capped backoff.
    fn retry_error_page(&mut self) -> Result<(), CdpError> {
        if !self.opts.unattended {
            return Ok(());
        }
        let now = Instant::now();
        match self.reload_at {
            None => self.reload_at = Some(now + self.reload_delay),
            Some(at) if now >= at => {
                self.reload_delay = (self.reload_delay * 2).min(self.opts.timing.respawn_max);
                self.reload_at = Some(now + self.reload_delay);
                self.log("retrying failed load");
                let target = self.ctx.as_ref().and_then(|c| c.target.clone());
                if let (Some(session), Some(url)) = (self.session.as_mut(), target) {
                    session.navigate(&url)?;
                }
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Pump events until the next poll is due. An event wakes the read at
    /// once, so a paused navigation is released as soon as it arrives. Only a
    /// settled page waits longer than one poll interval, and a navigation, a
    /// crash or a calibration request cuts that back to one. Returns `true`
    /// for a stop.
    fn idle(&mut self, delay: Duration) -> bool {
        let start = Instant::now();
        let mut deadline = start + delay;
        let interval = self.opts.timing.poll_interval;
        loop {
            match self.drain() {
                Some(true) => return true,
                // A command changed something: poll again right away.
                Some(false) => return false,
                None => {}
            }
            let calibrating = self.calib.is_some();
            let Some(session) = self.session.as_mut() else {
                return self.wait(deadline.saturating_duration_since(Instant::now()));
            };
            if session.guard.activity || calibrating {
                deadline = deadline.min(start + interval);
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            match session.pump(deadline.min(now + COMMAND_SLICE)) {
                Ok(_) => {}
                Err(CdpError::Stopped) => return true,
                Err(e) => {
                    // The socket died mid-pump: the next poll's watchdog
                    // re-attaches or restarts. Do not spin here.
                    self.log(format!("chromium nav pump: {e}"));
                    return self.wait(deadline.saturating_duration_since(Instant::now()).min(interval));
                }
            }
            if self.browser.as_mut().is_some_and(|b| b.exited().is_some()) {
                return false;
            }
        }
    }

    // ---- click-zone calibration ----------------------------------------- //

    fn start_calibrate(&mut self, on_done: CalibrateDone) {
        if self.calib.is_some() {
            self.log("calibrate already in progress");
            on_done(None);
        } else if self.session.is_none() {
            self.log("calibrate: no CDP session — is the panel still loading?");
            on_done(None);
        } else {
            match inject::calibrate_js() {
                Ok(src) => {
                    let deadline = Instant::now() + self.opts.timing.calibrate_timeout;
                    self.calib = Some(Calib { src: src.into_owned(), on_done, injected: false, deadline });
                }
                Err(e) => {
                    self.log(format!("calibrate template missing: {e}"));
                    on_done(None);
                }
            }
        }
    }

    fn finish_calibrate(&mut self, zones: Option<Dict>) {
        if let Some(calib) = self.calib.take() {
            (calib.on_done)(zones);
        }
    }

    /// Advance a pending calibration by one poll.
    fn calibrate_step(&mut self) -> Result<(), CdpError> {
        let (Some(calib), Some(session)) = (self.calib.as_mut(), self.session.as_mut()) else {
            return Ok(());
        };
        if !calib.injected {
            calib.injected = true;
            session.evaluate(&calib.src)?;
            self.log("calibrate: overlay injected, awaiting 3 clicks");
            return Ok(());
        }
        if Instant::now() > calib.deadline {
            session.evaluate(inject::CALIBRATE_ABORT_JS)?;
            self.log("calibrate: timed out");
            self.finish_calibrate(None);
            return Ok(());
        }
        let value = session.evaluate(inject::CALIBRATE_POLL_JS)?;
        let Some(raw) = value.as_str().filter(|s| !s.is_empty()) else {
            return Ok(());
        };
        session.evaluate(inject::CALIBRATE_CLEAR_JS)?;
        let outcome = Calibration::parse(raw);
        (self.hooks.on_event)(PanelEvent::Log(outcome.log_line(&self.id)));
        self.finish_calibrate(outcome.zones());
        Ok(())
    }
}
