//! The wall orchestrator: builds one view per panel (WebKit widgets, Chromium
//! processes), shows them staggered, and runs the periodic duties of a 24/7
//! wall — memory watchdog, theme sync — until told to stop.

use super::panel::{Profile, WallServices, WebKitPanel};
use super::services::{Log, Services};
use super::settings::{SettingsContext, SettingsWindow, VaultAccess};
use super::style;
use super::wall::{PillState, WallActions, WallWindow};
use gtk::prelude::*;
use soc_brand as branding;
use soc_core::{Backend, Config, CredSource, Engine, Layout, Panel, compute_geometry};
use soc_sys::watchdog::{MemWatch, MemWatchCfg, PanelMem, Verdict};
use soc_web::{ChromiumOptions, ChromiumPanel, LoginMemory, PanelEvent, PanelHooks, SecurityData};
use std::cell::{Cell, RefCell};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Everything resolved from the environment before the wall is built.
#[derive(Clone)]
pub struct HostOptions {
    pub profile: Profile,
    /// The machine probe behind `profile` (Chromium needs more of it).
    pub machine: soc_sys::perf::Profile,
    /// Pause between showing consecutive panels (smooths the RAM spike).
    pub stagger: Duration,
    /// A normal desktop window instead of taking over the screen.
    pub windowed: bool,
    /// `SOC_LAYOUT` override from the session script.
    pub layout: Option<Layout>,
    /// First DevTools port for Chromium panels; `None` picks a free one.
    pub cdp_base: Option<u16>,
    pub branding: branding::Locations,
    /// Where the kiosk-lock PIN/TOTP enrolment lives.
    pub state_dir: std::path::PathBuf,
}

type ChromiumSink = Rc<dyn Fn(&str, PanelEvent)>;

enum View {
    Webkit(WebKitPanel),
    Chromium { panel: Box<ChromiumPanel>, id: String },
}

impl View {
    fn id(&self) -> String {
        match self {
            View::Webkit(p) => p.panel().id,
            View::Chromium { id, .. } => id.clone(),
        }
    }

    fn loaded_ok(&self) -> bool {
        match self {
            View::Webkit(p) => p.loaded_ok(),
            View::Chromium { panel, .. } => panel.loaded_ok(),
        }
    }

    fn show(&self) {
        match self {
            View::Webkit(p) => p.show(),
            View::Chromium { panel, .. } => panel.start(),
        }
    }

    fn recycle(&self) {
        match self {
            View::Webkit(p) => p.recycle(),
            View::Chromium { panel, .. } => panel.recycle(),
        }
    }

    fn reload(&self) {
        match self {
            View::Webkit(p) => p.load(),
            View::Chromium { panel, .. } => panel.reload(),
        }
    }

    fn stop(&self) {
        match self {
            View::Webkit(p) => p.stop(),
            View::Chromium { panel, .. } => panel.stop(),
        }
    }

    /// Renderer memory in KiB, when it can be measured.
    fn rss_kb(&self, table: &soc_sys::perf::ProcTable) -> Option<u64> {
        match self {
            View::Webkit(p) => p.mem_rss_kb(),
            View::Chromium { panel, .. } => {
                let proc_root = Path::new("/proc");
                soc_sys::perf::proc_tree_rss_kb(panel.pid()?, table, |pid| soc_sys::perf::proc_rss_kb(proc_root, pid))
            }
        }
    }
}

thread_local! {
    /// Where Chromium panel events land once marshalled to the main thread.
    static CHROMIUM_SINK: RefCell<Option<ChromiumSink>> = const { RefCell::new(None) };
}

struct Inner {
    conf: RefCell<Config>,
    opts: HostOptions,
    services: Rc<Services>,
    creds: Arc<dyn CredSource>,
    memory: Arc<LoginMemory>,
    data: Arc<SecurityData>,
    log: Log,
    views: RefCell<Vec<View>>,
    wall: RefCell<Option<WallWindow>>,
    /// Repeating sources only (they never remove themselves).
    timers: RefCell<Vec<glib::SourceId>>,
    memwatch: RefCell<Option<MemWatch>>,
    stopping: Cell<bool>,
    theme_seen: Cell<Option<SystemTime>>,
    actions: RefCell<WallActions>,
    /// The single live VPN-log viewer window, when open.
    vpn_log: RefCell<Option<super::vpnlog::VpnLogViewer>>,
    /// The kiosk-lock state machine (authoritative locked state) and its window.
    locker: Rc<RefCell<soc_state::KioskLock>>,
    lock_overlay: RefCell<Option<super::lock::LockOverlay>>,
    /// The sealed-store admin-PIN override, if a verifier was installed.
    admin_pin: RefCell<Option<AdminPin>>,
    /// The single live Settings window, when open.
    settings: RefCell<Option<SettingsWindow>>,
    /// What the Settings window may do with the vault, once the boot path has one.
    vault_access: RefCell<Option<Arc<VaultAccess>>>,
    /// Opens the Settings window (`None` when `SOC_ONSCREEN_CONFIG` is off).
    on_config: RefCell<Option<Rc<dyn Fn()>>>,
    /// Whether the wall may restart the VPN / tunnel units; probed once off
    /// the main thread (`sudo -n` can take seconds).
    can_restart: Cell<Option<bool>>,
    /// A soft restart is already scheduled.
    restarting: Cell<bool>,
}

/// A sealed-store admin-PIN check (the kiosk-lock override).
pub type AdminPin = Rc<dyn Fn(&str) -> bool>;

/// The running wall.
#[derive(Clone)]
pub struct Host {
    inner: Rc<Inner>,
}

/// Which display server GTK actually connected to.
pub fn detect_backend() -> Backend {
    let wayland = gdk::Display::default().is_some_and(|d| d.type_().name().contains("Wayland"));
    if wayland { Backend::Wayland } else { Backend::X11 }
}

/// Size of the primary monitor, if it can be read.
pub fn detect_resolution() -> Option<(i32, i32)> {
    let display = gdk::Display::default()?;
    let geometry = display.primary_monitor().or_else(|| display.monitor(0))?.geometry();
    (geometry.width() > 0 && geometry.height() > 0).then(|| (geometry.width(), geometry.height()))
}

impl Host {
    pub fn new(
        conf: Config,
        opts: HostOptions,
        creds: Arc<dyn CredSource>,
        memory: Arc<LoginMemory>,
        data: Arc<SecurityData>,
        trackers_env: bool,
        log: Log,
    ) -> Host {
        let services = Services::new(
            creds.clone(),
            memory.clone(),
            conf.security.clone(),
            data.clone(),
            trackers_env,
            &conf.proxy.vault_item,
            log.clone(),
        );
        let theme_seen = opts.branding.marker_mtime();
        let opts_state_dir = opts.state_dir.clone();
        Host {
            inner: Rc::new(Inner {
                conf: RefCell::new(conf),
                opts,
                services,
                creds,
                memory,
                data,
                log,
                views: RefCell::default(),
                wall: RefCell::default(),
                timers: RefCell::default(),
                memwatch: RefCell::default(),
                stopping: Cell::new(false),
                theme_seen: Cell::new(theme_seen),
                actions: RefCell::default(),
                vpn_log: RefCell::default(),
                locker: Rc::new(RefCell::new(soc_state::KioskLock::new(&opts_state_dir))),
                lock_overlay: RefCell::default(),
                admin_pin: RefCell::default(),
                settings: RefCell::default(),
                vault_access: RefCell::default(),
                on_config: RefCell::default(),
                can_restart: Cell::new(None),
                restarting: Cell::new(false),
            }),
        }
    }

    fn log(&self, msg: &str) {
        (self.inner.log)(msg);
    }

    /// Toolbar / hotkey actions (config window, lock, VPN). Set before
    /// [`Host::build_and_show`].
    pub fn set_actions(&self, actions: WallActions) {
        *self.inner.actions.borrow_mut() = actions;
    }

    pub fn config(&self) -> Config {
        self.inner.conf.borrow().clone()
    }

    pub fn wall(&self) -> Option<WallWindow> {
        self.inner.wall.borrow().clone()
    }

    /// `(panels showing a page, panels total)`.
    pub fn panel_counts(&self) -> (u64, u64) {
        let views = self.inner.views.borrow();
        (
            u64::try_from(views.iter().filter(|v| v.loaded_ok()).count()).unwrap_or(u64::MAX),
            u64::try_from(views.len()).unwrap_or(u64::MAX),
        )
    }

    fn keep(&self, source: glib::SourceId) {
        self.inner.timers.borrow_mut().push(source);
    }

    /// A repeating main-loop duty that holds only a weak reference to the
    /// host (so the host can be dropped) and ends when it is gone.
    fn every(&self, period: Duration, duty: impl Fn(&Host) + 'static) {
        let weak = Rc::downgrade(&self.inner);
        self.keep(glib::timeout_add_local(period, move || match weak.upgrade() {
            Some(inner) if !inner.stopping.get() => {
                duty(&Host { inner });
                glib::ControlFlow::Continue
            }
            // Keep the source alive until shutdown removes it: a source that
            // ended by itself must not be removed a second time.
            _ => glib::ControlFlow::Continue,
        }));
    }

    /// `display.auto`: recompute the grid from the real screen size.
    fn autosize(&self) {
        let mut conf = self.inner.conf.borrow_mut();
        if !conf.display.auto {
            return;
        }
        let Some((w, h)) = detect_resolution() else {
            return;
        };
        if (conf.display.width, conf.display.height) != (w, h) {
            self.log(&format!(
                "display auto-detect: {w}x{h} (config said {}x{})",
                conf.display.width, conf.display.height
            ));
            conf.display.width = w;
            conf.display.height = h;
            let display = conf.display.clone();
            for p in &mut conf.panels {
                p.geometry = Some(compute_geometry(&display, p.grid));
            }
        }
    }

    /// Build every view and show the wall.
    pub fn build_and_show(&self) {
        let inner = &self.inner;
        let backend = detect_backend();
        let layout = inner.opts.layout.unwrap_or_else(|| inner.conf.borrow().resolve_layout(backend));
        self.log(&format!("backend={backend} layout={layout}"));
        self.autosize();

        let weak = Rc::downgrade(inner);
        CHROMIUM_SINK.with(|sink| {
            *sink.borrow_mut() = Some(Rc::new(move |id: &str, event: PanelEvent| {
                if let Some(inner) = weak.upgrade() {
                    Host { inner }.on_chromium_event(id, event);
                }
            }));
        });

        let conf = inner.conf.borrow().clone();
        // The gear button and Ctrl+Shift+C: the host's own Settings window
        // unless the boot path supplied one, and none at all when
        // `SOC_ONSCREEN_CONFIG` turns the on-screen settings off.
        let mut actions = inner.actions.borrow().clone();
        if actions.on_config.is_none() && soc_state::policy::onscreen_config_enabled_from_env() {
            let weak = Rc::downgrade(inner);
            actions.on_config = Some(Rc::new(move || {
                if let Some(inner) = weak.upgrade() {
                    Host { inner }.open_settings();
                }
            }) as Rc<dyn Fn()>);
        }
        *inner.on_config.borrow_mut() = actions.on_config.clone();
        self.probe_service_caps();
        if layout == Layout::Single {
            // Build the runtime toolbar actions from the host's own methods,
            // keeping any externally supplied ones (e.g. config/lock) that the
            // boot path set.
            let destroy = {
                let weak = Rc::downgrade(inner);
                Rc::new(move || {
                    if let Some(inner) = weak.upgrade() {
                        Host { inner }.shutdown();
                    }
                }) as Rc<dyn Fn()>
            };
            let on_vpn = actions.on_vpn.clone().or_else(|| {
                let weak = Rc::downgrade(inner);
                Some(Rc::new(move || {
                    if let Some(inner) = weak.upgrade() {
                        Host { inner }.reconnect_vpn();
                    }
                }) as Rc<dyn Fn()>)
            });
            let on_show_vpn_log = actions.on_show_vpn_log.clone().or_else(|| {
                let weak = Rc::downgrade(inner);
                Some(Rc::new(move || {
                    if let Some(inner) = weak.upgrade() {
                        Host { inner }.open_vpn_log();
                    }
                }) as Rc<dyn Fn()>)
            });
            let on_lock = actions.on_lock.clone().or_else(|| {
                let weak = Rc::downgrade(inner);
                Some(Rc::new(move || {
                    if let Some(inner) = weak.upgrade() {
                        Host { inner }.lock_wall();
                    }
                }) as Rc<dyn Fn()>)
            });
            let wall_actions =
                WallActions { on_destroy: Some(destroy), on_vpn, on_show_vpn_log, on_lock, ..actions.clone() };
            let log = inner.log.clone();
            let wall = WallWindow::new(&conf, inner.opts.windowed, wall_actions, Rc::new(move |m: &str| log(m)));
            *inner.wall.borrow_mut() = Some(wall);
        }

        let mut delay = Duration::ZERO;
        for (index, panel) in conf.panels.iter().enumerate() {
            let view = self.make_view(panel, index, actions.on_config.clone());
            inner.views.borrow_mut().push(view);
            let weak = Rc::downgrade(inner);
            let id = panel.id.clone();
            glib::timeout_add_local_once(delay, move || {
                let Some(inner) = weak.upgrade().filter(|i| !i.stopping.get()) else {
                    return;
                };
                if let Some(view) = inner.views.borrow().iter().find(|v| v.id() == id) {
                    view.show();
                }
            });
            delay += inner.opts.stagger;
        }
        if let Some(wall) = inner.wall.borrow().as_ref() {
            wall.show();
        }
        self.start_mem_watch();
        self.every(Duration::from_secs(15), Host::check_theme);
    }

    fn make_view(&self, panel: &Panel, index: usize, on_config: Option<Rc<dyn Fn()>>) -> View {
        let inner = &self.inner;
        let conf = inner.conf.borrow();
        if panel.engine == Engine::Chromium {
            let machine = &inner.opts.machine;
            let mut opts = ChromiumOptions::from_env(
                inner.opts.profile.webdata_dir.clone(),
                machine.low_memory,
                machine.chromium_gpu,
                machine.unattended,
            );
            opts.cdp_port = inner.opts.cdp_base.and_then(|base| base.checked_add(u16::try_from(index).ok()?));
            opts.proxy = conf.proxy.enabled.then(|| conf.proxy.clone());
            opts.security = conf.security.clone();
            opts.data = inner.data.clone();
            let id = panel.id.clone();
            let event_id = id.clone();
            let on_event: Arc<dyn Fn(PanelEvent) + Send + Sync> = Arc::new(move |event| {
                let id = event_id.clone();
                // Events arrive on the panel's control thread; hand them to
                // the main loop.
                glib::MainContext::default().invoke(move || {
                    let sink = CHROMIUM_SINK.with(|s| s.borrow().clone());
                    if let Some(sink) = sink {
                        sink(&id, event);
                    }
                });
            });
            let hooks = PanelHooks::from_vault(
                inner.creds.clone(),
                Some(inner.memory.clone()),
                &conf.proxy.vault_item,
                on_event,
            );
            return View::Chromium { panel: Box::new(ChromiumPanel::new(panel.clone(), opts, hooks)), id };
        }
        let embedded = inner.wall.borrow().is_some();
        let services: Rc<dyn WallServices> = inner.services.clone();
        let view = WebKitPanel::new(
            panel.clone(),
            services,
            conf.proxy.clone(),
            inner.opts.profile.clone(),
            embedded,
            on_config,
        );
        if let Some(wall) = inner.wall.borrow().as_ref() {
            wall.attach(panel, &view.widget());
        }
        View::Webkit(view)
    }

    fn on_chromium_event(&self, id: &str, event: PanelEvent) {
        match event {
            PanelEvent::Log(line) => self.log(&format!("[{id}] {line}")),
            PanelEvent::Status(status) => self.log(&format!("[{id}] chromium: {status:?}")),
            PanelEvent::LoginSucceeded => {
                if let Some(panel) = self.inner.conf.borrow().panel(id) {
                    self.inner.services.login_succeeded(panel);
                }
            }
            PanelEvent::SignInNeeded => self.log(&format!("[{id}] sign-in needed (auto-login could not complete)")),
            PanelEvent::NavBlocked(target) => self.log(&format!("[{id}] refused off-allowlist nav -> {target}")),
        }
    }

    // ---- periodic duties -----------------------------------------------------

    /// On a 1 GB board a single leaking dashboard can OOM the box: under
    /// sustained pressure recycle the heaviest panel.
    fn start_mem_watch(&self) {
        if soc_sys::perf::mem_available_mb(Path::new("/proc")).is_none() {
            return; // no /proc: nothing to watch
        }
        let cfg = MemWatchCfg::from_env();
        self.log(&format!(
            "memory watchdog on: recycle a panel when MemAvailable < {} MB (every {}s)",
            cfg.min_avail_mb,
            cfg.check_every.as_secs()
        ));
        let period = cfg.check_every;
        *self.inner.memwatch.borrow_mut() = Some(MemWatch::new(cfg));
        self.every(period, Host::check_memory);
    }

    fn check_memory(&self) {
        let inner = &self.inner;
        let proc_root = Path::new("/proc");
        let avail = soc_sys::perf::mem_available_mb(proc_root);
        let views = inner.views.borrow();
        let table = soc_sys::perf::proc_table(proc_root);
        let ids: Vec<String> = views.iter().map(View::id).collect();
        let rss: Vec<Option<u64>> = views.iter().map(|v| v.rss_kb(&table)).collect();
        let mem: Vec<PanelMem<'_>> =
            ids.iter().zip(&rss).map(|(id, rss_kb)| PanelMem { id, rss_kb: *rss_kb }).collect();
        let mut guard = inner.memwatch.borrow_mut();
        let Some(watch) = guard.as_mut() else {
            return;
        };
        let now = Instant::now();
        if let Verdict::Recycle { index } = watch.sample(avail, now, &mem) {
            self.log(&format!(
                "[mem] MemAvailable {} MB < {} MB — recycling panel {}",
                avail.unwrap_or(0),
                watch.cfg().min_avail_mb,
                ids[index]
            ));
            views[index].recycle();
            watch.recycled(now);
        }
    }

    /// Repaint when another process (the appearance editor) saved a theme.
    fn check_theme(&self) {
        let seen = self.inner.opts.branding.marker_mtime();
        if seen.is_some() && seen != self.inner.theme_seen.get() {
            self.inner.theme_seen.set(seen);
            style::apply_css(&style::tokens_from_colors(&self.inner.opts.branding.load().colors));
            self.log("theme changed — wall repainted");
        }
    }

    // ---- operations ----------------------------------------------------------

    /// Install the sealed-store admin-PIN override, so a forgotten panel-lock
    /// credential never strands the operator. Called by the boot path when a
    /// sealed master is present.
    pub fn set_admin_pin(&self, verify: AdminPin) {
        *self.inner.admin_pin.borrow_mut() = Some(verify);
    }

    /// Build the live unlock inputs (fresh vault TOTP + the admin override).
    fn lock_inputs(&self) -> super::lock::LockInputs {
        let creds = self.inner.creds.clone();
        let vault_totp =
            Rc::new(move || soc_vault::totp::load_vault(Some(&*creds), soc_vault::totp::TotpKind::PanelLock))
                as Rc<dyn Fn() -> Option<zeroize::Zeroizing<String>>>;
        let admin = self.inner.admin_pin.borrow().clone();
        let admin_pin = admin.unwrap_or_else(|| Rc::new(|_: &str| false) as AdminPin);
        super::lock::LockInputs { vault_totp, admin_pin }
    }

    /// Engage the kiosk lock (toolbar button / Ctrl+Alt+L). A no-op while
    /// already locked; shows an advisory when nothing is enrolled to unlock.
    pub fn lock_wall(&self) {
        if let Some(existing) = self.inner.lock_overlay.borrow().as_ref() {
            existing.dismiss();
        }
        let on_unlock = {
            let weak = Rc::downgrade(&self.inner);
            Rc::new(move || {
                if let Some(inner) = weak.upgrade() {
                    inner.lock_overlay.borrow_mut().take();
                    (inner.log)("wall unlocked");
                }
            }) as Rc<dyn Fn()>
        };
        match super::lock::LockOverlay::engage(self.inner.locker.clone(), self.lock_inputs(), on_unlock) {
            Some(overlay) => {
                self.log("wall locked");
                *self.inner.lock_overlay.borrow_mut() = Some(overlay);
            }
            None => super::lock::advise_no_credential(),
        }
    }

    /// Open (or re-present) the single VPN-log viewer window.
    pub fn open_vpn_log(&self) {
        if let Some(existing) = self.inner.vpn_log.borrow().as_ref() {
            existing.present();
            return;
        }
        let names: Vec<String> = self
            .inner
            .conf
            .borrow()
            .enabled_vpns()
            .map(|v| soc_vpn::vpn_name(v, 0))
            .filter(|n| !n.is_empty())
            .collect();
        let reconnect = {
            let weak = Rc::downgrade(&self.inner);
            Rc::new(move || {
                if let Some(inner) = weak.upgrade() {
                    Host { inner }.reconnect_vpn();
                }
            }) as Rc<dyn Fn()>
        };
        let on_close = {
            let weak = Rc::downgrade(&self.inner);
            Rc::new(move || {
                if let Some(inner) = weak.upgrade() {
                    inner.vpn_log.borrow_mut().take();
                }
            }) as Rc<dyn Fn()>
        };
        let viewer = super::vpnlog::VpnLogViewer::open(&names, reconnect, on_close);
        *self.inner.vpn_log.borrow_mut() = Some(viewer);
    }

    /// Restart the VPN supervisor unit (the toolbar pill / log Reconnect),
    /// off the main thread so a slow `systemctl` never freezes the wall. The
    /// result lands back on the GTK loop via a channel the main thread owns.
    pub fn reconnect_vpn(&self) {
        self.set_vpn_status(PillState::Connecting, "VPN: restarting…", None);
        let log = self.inner.log.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>(); // audit-allow: one-shot channel; the error is display text, logged in the worker
        std::thread::spawn(move || {
            let euid = soc_sys::fsutil::euid();
            let result = soc_sys::sysaction::privileged_systemctl(
                &soc_sys::run::SystemRunner,
                euid,
                soc_sys::sysaction::Verb::Restart,
                soc_sys::sysaction::Unit::FortiVpn,
            );
            log(&match &result {
                Ok(_) => "VPN restart requested".to_string(),
                Err(e) => format!("VPN restart failed: {e}"),
            });
            let _ = tx.send(result.map(|_| ())); // audit-allow: best-effort, the main thread may be gone
        });
        // Poll the one-shot result on the main thread and settle the pill.
        let weak = Rc::downgrade(&self.inner);
        glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
            let outcome = match rx.try_recv() {
                Ok(outcome) => outcome,
                Err(std::sync::mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return glib::ControlFlow::Break,
            };
            if let Some(inner) = weak.upgrade() {
                let (state, label) = match outcome {
                    Ok(()) => (PillState::Checking, "VPN: reconnecting…"),
                    Err(_) => (PillState::Offline, "VPN: restart failed"), // audit-allow: detail logged in the worker; only the pill state is needed
                };
                Host { inner }.set_vpn_status(state, label, None);
            }
            glib::ControlFlow::Break
        });
    }

    /// Update the VPN pills (`name` as in [`WallWindow::set_vpn_status`]).
    pub fn set_vpn_status(&self, state: PillState, label: &str, name: Option<&str>) {
        if let Some(wall) = self.inner.wall.borrow().as_ref() {
            wall.set_vpn_status(state, label, name);
        }
    }

    /// Reload every panel; returns how many.
    pub fn reload_all(&self) -> usize {
        let views = self.inner.views.borrow();
        views.iter().for_each(View::reload);
        views.len()
    }

    /// Repoint a WebKit panel live. Returns false for an unknown panel.
    pub fn set_panel_url(&self, id: &str, url: &str) -> bool {
        let views = self.inner.views.borrow();
        match views.iter().find(|v| v.id() == id) {
            Some(View::Webkit(p)) => {
                p.set_url(url);
                true
            }
            Some(View::Chromium { panel, .. }) => panel.set_url(url).is_ok(),
            None => false,
        }
    }

    // ---- on-screen settings --------------------------------------------------

    /// Give the Settings window what it needs for vault writes and the config
    /// write-back. Called by the boot path once the vault exists.
    pub fn set_vault_access(&self, access: VaultAccess) {
        *self.inner.vault_access.borrow_mut() = Some(Arc::new(access));
    }

    /// What the host can do right now.
    pub fn caps(&self) -> soc_state::HostCaps {
        soc_state::HostCaps {
            single_wall: self.inner.wall.borrow().is_some(),
            can_restart_services: self.inner.can_restart.get().unwrap_or(false),
        }
    }

    /// Probe once, off the main thread, whether `systemctl` may be used
    /// without a password prompt; the answer lands in a one-shot channel the
    /// main loop polls.
    fn probe_service_caps(&self) {
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        std::thread::spawn(move || {
            let ok = soc_sys::sysaction::can_systemctl(&soc_sys::run::SystemRunner, soc_sys::fsutil::euid());
            if tx.send(ok).is_err() {
                // the host is gone; nobody needs the answer
            }
        });
        let weak = Rc::downgrade(&self.inner);
        glib::timeout_add_local(Duration::from_millis(250), move || match rx.try_recv() {
            Ok(ok) => {
                if let Some(inner) = weak.upgrade() {
                    inner.can_restart.set(Some(ok));
                }
                glib::ControlFlow::Break
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
        });
    }

    /// A closure that reaches the host again without keeping it alive.
    fn weak_host(&self) -> impl Fn() -> Option<Host> + Clone + 'static {
        let weak = Rc::downgrade(&self.inner);
        move || weak.upgrade().map(|inner| Host { inner })
    }

    /// Open (or re-present) the single Settings window.
    pub fn open_settings(&self) {
        if let Some(existing) = self.inner.settings.borrow().as_ref() {
            existing.present();
            return;
        }
        let window = SettingsWindow::open(self.settings_context());
        *self.inner.settings.borrow_mut() = Some(window);
    }

    fn settings_context(&self) -> SettingsContext {
        let host = self.weak_host();
        let (h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12) = (
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
            host.clone(),
        );
        let state_dir = self.inner.opts.state_dir.clone();
        SettingsContext {
            config: self.config(),
            state_dir,
            caps: Rc::new(move || {
                h1().map_or(soc_state::HostCaps { single_wall: false, can_restart_services: false }, |h| h.caps())
            }),
            apply: Rc::new(move |changes| h2().map(|h| h.apply_changes(changes)).unwrap_or_default()), // audit-allow: a vanished host has nothing to report
            reload_panels: Rc::new(move || h3().map_or(0, |h| h.reload_all())),
            restart_wall: Rc::new(move || {
                if let Some(h) = h4() {
                    h.restart_wall();
                }
            }),
            reconnect_vpn: Rc::new(move || {
                if let Some(h) = h5() {
                    h.reconnect_vpn();
                }
            }),
            set_panel_url: Rc::new(move |id, url| h6().is_some_and(|h| h.set_panel_url(id, url))),
            login_stats: Rc::new(move || h7().map_or_else(Vec::new, |h| h.stale_login_panels())),
            push_config_to_vault: Rc::new(move || {
                h8().map_or_else(
                    || soc_state::plan::WriteBack::Deferred("the wall is shutting down".to_string()),
                    |h| h.push_config_to_vault(),
                )
            }),
            set_login_zones: Rc::new(move |id, zones| match h9() {
                Some(h) => h.set_login_zones(id, zones),
                None => Err("the wall is shutting down".to_string()),
            }),
            // No click-zone calibrator exists in the Rust wall yet: the button explains.
            calibrate: None,
            lock_wall: Some(Rc::new(move || {
                if let Some(h) = h10() {
                    h.lock_wall();
                }
            })),
            show_vpn_log: Some(Rc::new(move || {
                if let Some(h) = h11() {
                    h.open_vpn_log();
                }
            })),
            creds: self.inner.creds.clone(),
            vault: self.inner.vault_access.borrow().clone(),
            onscreen_enabled: soc_state::policy::onscreen_config_enabled_from_env(),
            require_pin: soc_state::policy::require_pin_from_env(),
            on_close: Rc::new(move || {
                if let Some(h) = h12() {
                    h.inner.settings.borrow_mut().take();
                }
            }),
        }
    }

    /// Panels whose auto-login burnt its retries without success (the
    /// selectors are probably stale).
    pub fn stale_login_panels(&self) -> Vec<String> {
        self.inner
            .views
            .borrow()
            .iter()
            .filter_map(|v| match v {
                View::Webkit(p) if p.login_attempts() >= 2 => Some(p.panel().id),
                _ => None,
            })
            .collect()
    }

    /// Persist new (or, when empty, cleared) login zones for a panel and
    /// re-inject so they are used straight away. Returns whether it had zones.
    pub fn set_login_zones(&self, id: &str, zones: &serde_json::Value) -> super::settings::UiResult<bool> {
        let dir = &self.inner.opts.state_dir;
        let overrides = soc_state::Overrides::load(dir).map_err(|e| e.to_string())?;
        let conf = self.inner.conf.borrow().clone();
        let plan = soc_state::plan::plan_login_zones(&conf, &overrides, id, zones).map_err(|p| p.join("; "))?;
        plan.overrides.save(dir).map_err(|e| e.to_string())?;
        let new_zones = plan.config.panel(id).map(|p| p.login_zones.clone()).unwrap_or_default(); // audit-allow: no such panel means nothing to repaint
        *self.inner.conf.borrow_mut() = plan.config;
        if let Some(View::Webkit(view)) = self.inner.views.borrow().iter().find(|v| v.id() == id) {
            view.update_panel(|p| p.login_zones = new_zones);
        }
        for action in &plan.actions {
            if let soc_state::Action::Reinject { panel } = action {
                if let Some(View::Webkit(view)) = self.inner.views.borrow().iter().find(|v| v.id() == *panel) {
                    view.reinject();
                }
            }
        }
        Ok(plan.had_zones)
    }

    /// Apply saved settings to the running wall: plan them
    /// (`soc_state::plan_apply`), then perform each action in order. Mirrors
    /// the Python `apply_config`.
    pub fn apply_changes(&self, changes: &soc_state::Changes) -> soc_state::ApplyReport {
        let conf = self.inner.conf.borrow().clone();
        let plan = match soc_state::plan_apply(&conf, changes, &self.caps()) {
            Ok(plan) => plan,
            Err(problems) => {
                for p in &problems {
                    self.log(&format!("settings apply refused: {p}"));
                }
                return soc_state::ApplyReport { skipped: problems, ..soc_state::ApplyReport::default() };
            }
        };
        for line in &plan.report.skipped {
            self.log(line);
        }
        *self.inner.conf.borrow_mut() = plan.config.clone();
        self.sync_view_panels(&plan.config);
        for action in &plan.actions {
            self.run_action(action, &plan.config);
        }
        plan.report
    }

    /// Hand each WebKit view the login-relevant fields of its panel's new
    /// config (they take effect on the next load / re-inject).
    fn sync_view_panels(&self, conf: &Config) {
        for view in self.inner.views.borrow().iter() {
            let View::Webkit(p) = view else { continue };
            let Some(new) = conf.panel(&p.panel().id) else { continue };
            p.update_panel(|old| {
                old.title.clone_from(&new.title);
                old.vault_item.clone_from(&new.vault_item);
                old.selectors.clone_from(&new.selectors);
                old.login_marker.clone_from(&new.login_marker);
                old.tenant.clone_from(&new.tenant);
                old.grid = new.grid;
            });
        }
    }

    fn run_action(&self, action: &soc_state::Action, conf: &Config) {
        use soc_state::Action;
        let wall = self.inner.wall.borrow().clone();
        match action {
            Action::AddPanel { panel } => self.add_panel_live(panel),
            Action::RemovePanel { id } => self.remove_panel_live(id),
            Action::SetGap { gap } => wall.iter().for_each(|w| w.set_gap(*gap)),
            Action::ResizeWindow { width, height } => wall.iter().for_each(|w| w.resize(*width, *height)),
            Action::SetFullscreen { fullscreen } => wall.iter().for_each(|w| w.set_fullscreen(*fullscreen)),
            Action::ReflowGrid => wall.iter().for_each(|w| w.reflow(&conf.panels)),
            Action::SetTitle { .. } => {} // already synced by sync_view_panels
            Action::SetUrl { panel, url } => {
                if !self.set_panel_url(panel, url) {
                    self.log(&format!("[{panel}] set url: no such panel on the wall"));
                }
            }
            Action::Reinject { panel } => {
                if let Some(View::Webkit(view)) = self.inner.views.borrow().iter().find(|v| v.id() == *panel) {
                    view.reinject();
                }
            }
            Action::RestartVpn => self.reconnect_vpn(),
            Action::RestartTunnel => self.restart_tunnel(),
            Action::PushConfigToVault => {
                self.push_config_to_vault();
            }
            Action::RestartWall => self.restart_wall(),
        }
    }

    /// Create and attach a new panel at runtime, without a restart.
    fn add_panel_live(&self, panel: &Panel) {
        let index = self.inner.views.borrow().len();
        let on_config = self.inner.on_config.borrow().clone();
        let view = self.make_view(panel, index, on_config);
        self.inner.views.borrow_mut().push(view);
        let weak = Rc::downgrade(&self.inner);
        let id = panel.id.clone();
        glib::idle_add_local_once(move || {
            let Some(inner) = weak.upgrade().filter(|i| !i.stopping.get()) else {
                return;
            };
            if let Some(view) = inner.views.borrow().iter().find(|v| v.id() == id) {
                view.show();
            }
        });
        self.log(&format!("[{}] panel added live", panel.id));
    }

    /// Stop a panel and take it off the wall at runtime.
    fn remove_panel_live(&self, id: &str) {
        let view = {
            let mut views = self.inner.views.borrow_mut();
            views.iter().position(|v| v.id() == id).map(|i| views.remove(i))
        };
        let Some(view) = view else {
            return self.log(&format!("[{id}] panel not found for removal"));
        };
        view.stop();
        if let Some(wall) = self.inner.wall.borrow().as_ref() {
            wall.detach(id);
        }
        self.log(&format!("[{id}] panel removed live"));
    }

    /// Restart the SSH tunnel unit off the main thread (best effort: it
    /// needs privilege).
    fn restart_tunnel(&self) {
        let log = self.inner.log.clone();
        std::thread::spawn(move || {
            let result = soc_sys::sysaction::privileged_systemctl(
                &soc_sys::run::SystemRunner,
                soc_sys::fsutil::euid(),
                soc_sys::sysaction::Verb::Restart,
                soc_sys::sysaction::Unit::AutosshTunnel,
            );
            log(&match result {
                Ok(_) => "tunnel config changed — restarted autossh-tunnel".to_string(),
                Err(e) => format!("tunnel restart not permitted from the wall ({e})"),
            });
        });
    }

    /// Write the running config back to the vault note (the source of truth),
    /// so it does not drift from the on-screen edits. The cheap checks happen
    /// here; the upload runs on a worker and logs its outcome. When it cannot
    /// run, `overrides.json` is the only record and the stale note wins at the
    /// next boot — the caller says so.
    pub fn push_config_to_vault(&self) -> soc_state::plan::WriteBack {
        let Some(access) = self.inner.vault_access.borrow().clone() else {
            return soc_state::plan::WriteBack::Deferred("no vault is attached".to_string());
        };
        let precheck = access.write_back();
        if let soc_state::plan::WriteBack::Deferred(why) = &precheck {
            self.log(&format!("config write-back deferred: {why}"));
            return precheck;
        }
        let yaml = soc_core::emit::to_yaml(&self.inner.conf.borrow());
        let log = self.inner.log.clone();
        std::thread::spawn(move || {
            let spec = soc_vault::LoginSpec { name: &access.config_item, notes: Some(&yaml), ..Default::default() };
            let outcome = access.write_session("").and_then(|s| s.upsert_login(&spec).map_err(|e| e.to_string()));
            log(&match outcome {
                Ok(_) => format!("config written back to vault note '{}'", access.config_item),
                Err(e) => format!("config write-back failed (local overrides kept): {e}"),
            });
        });
        precheck
    }

    /// Soft restart with the current config, after 500 ms so the GUI can paint
    /// first. Under systemd (or the wall's own supervisor) exiting cleanly is
    /// enough to be respawned; run bare, nobody would do that, so re-exec.
    pub fn restart_wall(&self) {
        if self.inner.restarting.replace(true) {
            return;
        }
        self.log("restart_wall: restarting in 0.5 s");
        let host = self.weak_host();
        glib::timeout_add_local_once(Duration::from_millis(500), move || {
            let Some(host) = host() else { return };
            if std::env::var_os("INVOCATION_ID").is_some() {
                return host.shutdown();
            }
            host.log("restart_wall: re-execing");
            for view in host.inner.views.borrow().iter() {
                view.stop();
            }
            use std::os::unix::process::CommandExt;
            let exe = std::env::current_exe();
            let replaced = exe.map(|exe| {
                let mut command = std::process::Command::new(exe); // audit-allow: re-exec of our own binary with our own argv
                command.args(std::env::args_os().skip(1)).exec()
            });
            match replaced {
                Ok(e) | Err(e) => host.log(&format!("restart_wall: re-exec failed ({e}); exiting instead")),
            }
            host.shutdown();
        });
    }

    /// True once [`Host::shutdown`] ran.
    pub fn stopping(&self) -> bool {
        self.inner.stopping.get()
    }

    /// Stop everything and leave the main loop. Idempotent, and it always
    /// reaches `main_quit`: a shutdown that stalled would hang
    /// `systemctl stop` until the kill timeout and orphan Chromium children.
    pub fn shutdown(&self) {
        let inner = &self.inner;
        if inner.stopping.replace(true) {
            return;
        }
        self.log("shutting down ...");
        for source in inner.timers.borrow_mut().drain(..) {
            source.remove();
        }
        CHROMIUM_SINK.with(|sink| sink.borrow_mut().take());
        if let Some(viewer) = inner.vpn_log.borrow_mut().take() {
            viewer.close();
        }
        let settings = inner.settings.borrow_mut().take();
        if let Some(window) = settings {
            window.close();
        }
        let views = std::mem::take(&mut *inner.views.borrow_mut());
        for view in &views {
            view.stop();
        }
        if gtk::main_level() > 0 {
            gtk::main_quit();
        }
    }
}
