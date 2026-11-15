//! One WebKit panel: a `WebKitWebView` either in its own top-level window
//! (layout `windows` — the window manager's rules place it into its cell) or
//! embedded into the shared wall window (layout `single`).
//!
//! Login is injected natively: a credential-free bootstrap user script detects
//! the login page and posts to the `socCreds` message handler; the host
//! answers by evaluating the login call with credentials fetched just-in-time
//! from the vault. Credentials never traverse the network or a page-context
//! fetch, and there is no broker or open port.
//!
//! Self-healing for 24/7 operation: a crashed web process is reloaded, a
//! failed load retries with backoff, and a status card covers the view
//! whenever the page is not live so a dark cell always says why.

use super::ffi::{self, Filter, FilterStore};
use super::style::{self, PanelFrame};
use crate::logic::{Healing, LoginBudget, LoginStep, ProxyAuth};
use gtk::prelude::*;
use javascriptcore::ValueExt;
use soc_core::guard::{url_for_msg, valid_http_url};
use soc_core::{Login, Mode, Panel, ProxyCfg};
pub use soc_sys::perf::HwAccel;
use soc_sys::perf::log_repeat;
use soc_web::inject::LoginRearm;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::time::Instant;
use webkit2gtk::{
    AuthenticationRequestExt, CacheModel, CookieAcceptPolicy, CookieManagerExt, CookiePersistentStorage, Credential,
    CredentialPersistence, DownloadExt, HardwareAccelerationPolicy, LoadEvent, MemoryPressureSettings,
    NavigationPolicyDecision, NavigationPolicyDecisionExt, NetworkError, NetworkProxyMode, NetworkProxySettings,
    PolicyDecisionExt, PolicyDecisionType, SettingsExt, TLSErrorsPolicy, URIRequestExt, UserContentInjectedFrames,
    UserContentManager, UserContentManagerExt, UserScript, UserScriptInjectionTime, WebContext, WebContextExt, WebView,
    WebViewExt, WebsiteDataManager, WebsiteDataManagerExt,
};
use zeroize::Zeroizing;

/// The hardware/session profile, resolved once at start-up.
#[derive(Debug, Clone)]
pub struct Profile {
    /// A small board (~1 GB): trade caches for headroom.
    pub low_memory: bool,
    pub hwaccel: HwAccel,
    /// Nobody is at this box: never wait for a person, retry forever.
    pub unattended: bool,
    /// Per web/network-process memory cap on small boards (MB).
    pub mem_limit_mb: u32,
    /// How long a load must stay up before the retry backoff resets.
    pub stable_sec: f64,
    /// Private 0700 root for web data (session tokens live here).
    pub webdata_dir: PathBuf,
}

/// The tracker rule set for one panel.
pub struct TrackerRules {
    /// Distinguishes rule-set variants (a panel may unblock some hosts), so
    /// each variant is compiled once.
    pub key: String,
    /// WebKit content-blocker JSON.
    pub json: String,
}

/// What a panel needs from the rest of the wall. The host implements this on
/// top of the vault, the injection templates and the security policy; keeping
/// it a trait keeps secrets and policy out of the widget code.
/// A top-level navigation predicate over the target URI (true = allowed).
pub type NavGate = Box<dyn Fn(&str) -> bool>;

pub trait WallServices {
    fn log(&self, msg: &str);
    /// The credential-free bootstrap script for this panel (carries the
    /// origin gate, so the login function refuses to fill an off-origin page).
    fn bootstrap_js(&self, panel: &Panel) -> String;
    /// The top-level navigation gate: `None` when gating is disabled, else a
    /// predicate over the target URI (true = allowed).
    fn nav_gate(&self, panel: &Panel) -> Option<NavGate>;
    /// Tracker rules to enforce on this panel, if any.
    fn tracker_rules(&self, panel: &Panel) -> Option<TrackerRules>;
    /// Whether a page at `page_uri` may be handed this panel's credentials.
    /// Checked on the host — never left to script the page could replace —
    /// and before the vault is even asked.
    fn may_login(&self, panel: &Panel, page_uri: &str) -> bool;
    /// Credentials for this panel's current page, fetched just-in-time.
    fn login_for(&self, panel: &Panel) -> Option<Login>;
    /// The JS that fills + submits the login form with `login`, wrapped so it
    /// only runs while the page is still on the panel's own origin. `None`
    /// when the panel has no origin to pin the credentials to.
    fn login_js(&self, panel: &Panel, login: &Login) -> Option<Zeroizing<String>>;
    /// JS showing an in-page "please sign in" prompt.
    fn prompt_js(&self, message: &str) -> String;
    /// JS removing that prompt.
    fn prompt_clear_js(&self) -> String;
    /// The page reported a successful login.
    fn login_succeeded(&self, panel: &Panel);
    /// Proxy credentials, fetched just-in-time.
    fn proxy_login(&self) -> Option<Login>;
    /// PIDs of this process's live web-content children.
    fn web_process_pids(&self) -> BTreeSet<u32>;
    /// Resident set size of a process in KiB.
    fn proc_rss_kb(&self, pid: u32) -> Option<u64>;
}

thread_local! {
    /// One memory-pressure policy for every process (`None` = engine default).
    static MEM_PRESSURE: RefCell<Option<Option<MemoryPressureSettings>>> = const { RefCell::new(None) };
    static NETWORK_CAPPED: Cell<bool> = const { Cell::new(false) };
    static PROXY_LOGGED: Cell<bool> = const { Cell::new(false) };
    static FILTERS: RefCell<FilterCache> = RefCell::new(FilterCache::default());
    /// Every live web process we have claimed: pid -> panel id.
    static WEB_PIDS: RefCell<HashMap<u32, String>> = RefCell::new(HashMap::new());
}

type FilterWaiter = Box<dyn FnOnce(&Filter)>;

#[derive(Default)]
struct FilterCache {
    store: Option<Rc<FilterStore>>,
    ready: HashMap<String, Filter>,
    waiting: HashMap<String, Vec<FilterWaiter>>,
}

/// Create a private directory (0700), tightening one that pre-existed.
fn private_dir(path: &Path) {
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path); // audit-allow: best-effort, set_permissions below and later use surface real failures
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)); // audit-allow: best-effort, directory may be on a filesystem without modes
}

/// The memory limit + GC thresholds for small boards — the biggest RAM lever
/// on a 1 GB Pi. Built once so every process gets the same policy.
fn memory_pressure(profile: &Profile) -> Option<MemoryPressureSettings> {
    MEM_PRESSURE.with(|slot| {
        slot.borrow_mut()
            .get_or_insert_with(|| {
                if !profile.low_memory {
                    return None;
                }
                let mut mps = MemoryPressureSettings::new();
                mps.set_memory_limit(profile.mem_limit_mb.clamp(16, 4096));
                // Strict before conservative: each setter asserts the pair
                // stays ordered, and the default strict (0.5) would refuse a
                // conservative of 0.5.
                mps.set_strict_threshold(0.65);
                mps.set_conservative_threshold(0.50);
                mps.set_poll_interval(30.0);
                Some(mps)
            })
            .clone()
    })
}

/// Hand `on_ready` the compiled tracker filter for `rules`, compiling it (once
/// per variant, asynchronously) if needed. Best-effort: without a store the
/// panel simply renders unfiltered.
fn with_tracker_filter(rules: TrackerRules, profile: &Profile, svc: &Rc<dyn WallServices>, on_ready: FilterWaiter) {
    let pending = FILTERS.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(filter) = cache.ready.get(&rules.key) {
            return Err(Some((on_ready, filter.clone())));
        }
        if cache.store.is_none() {
            let dir = profile.webdata_dir.join("filter-store");
            private_dir(&profile.webdata_dir);
            private_dir(&dir);
            cache.store = FilterStore::new(&dir).map(Rc::new);
        }
        let Some(store) = cache.store.clone() else {
            return Err(None);
        };
        let first = !cache.waiting.contains_key(&rules.key);
        cache.waiting.entry(rules.key.clone()).or_default().push(on_ready);
        Ok(first.then_some(store))
    });
    let store = match pending {
        Err(Some((on_ready, filter))) => return on_ready(&filter),
        Err(None) => return svc.log("tracker filter store unavailable; trackers are not blocked"),
        Ok(None) => return, // a compile for this variant is already running
        Ok(Some(store)) => store,
    };
    let key = rules.key.clone();
    let svc = svc.clone();
    let ident = if key.is_empty() { "soc-trackers".to_string() } else { format!("soc-trackers-{key}") };
    store.save(&ident.clone(), &rules.json, move |result| {
        let waiters = FILTERS.with(|cache| {
            let mut cache = cache.borrow_mut();
            cache.ready.extend(result.as_ref().ok().map(|f| (key.clone(), f.clone()))); // Err is reported below
            cache.waiting.remove(&key).unwrap_or_default() // audit-allow: default (no waiters) is the intended fallback
        });
        match result {
            Ok(filter) => waiters.into_iter().for_each(|w| w(&filter)),
            Err(e) => svc.log(&format!("tracker filter compile failed ({ident}): {e}")),
        }
    });
}

#[derive(Default)]
struct State {
    healing: Healing,
    login: LoginBudget,
    rearm: LoginRearm,
    proxy_auth: ProxyAuth,
    retry: Option<glib::SourceId>,
    /// `stop()` ran: ignore late callbacks.
    stopped: bool,
    /// We killed the renderer on purpose (not a crash).
    recycling: bool,
    ever_loaded: bool,
    load_failed: bool,
    /// The last load finished without error.
    page_ok: bool,
}

struct Inner {
    panel: RefCell<Panel>,
    svc: Rc<dyn WallServices>,
    proxy: ProxyCfg,
    profile: Profile,
    webview: WebView,
    ucm: UserContentManager,
    context: WebContext,
    frame: PanelFrame,
    window: Option<gtk::Window>,
    nav_gate: Option<NavGate>,
    st: RefCell<State>,
    handlers: RefCell<Vec<glib::SignalHandlerId>>,
}

/// A WebKit-rendered wall panel.
#[derive(Clone)]
pub struct WebKitPanel {
    inner: Rc<Inner>,
}

fn panel_data_dir(profile: &Profile, panel: &Panel) -> PathBuf {
    private_dir(&profile.webdata_dir);
    let dir = profile.webdata_dir.join(format!("wk-{}", panel.id));
    private_dir(&dir);
    dir
}

/// A private, per-panel web context backed by its own data manager, so each
/// panel persists cookies and storage independently (profile isolation: one
/// panel's session is not readable by another) and sessions survive a wall
/// restart. `persist: false` panels are ephemeral.
fn context_for(panel: &Panel, proxy: &ProxyCfg, profile: &Profile, svc: &Rc<dyn WallServices>) -> WebContext {
    let mps = memory_pressure(profile);
    // The static setter caps the NETWORK processes and must run before the
    // first data manager exists; web processes are capped per context below.
    if let Some(mps) = &mps {
        if !NETWORK_CAPPED.replace(true) {
            WebsiteDataManager::set_memory_pressure_settings(&mut mps.clone());
        }
    }
    let data_dir = panel.persist.then(|| panel_data_dir(profile, panel));
    let dm = match &data_dir {
        Some(dir) => WebsiteDataManager::builder()
            .base_data_directory(dir.to_string_lossy().as_ref())
            .base_cache_directory(dir.join("cache").to_string_lossy().as_ref())
            .build(),
        None => WebsiteDataManager::new_ephemeral(),
    };
    let mut builder = WebContext::builder().website_data_manager(&dm);
    if let Some(mps) = &mps {
        builder = builder.memory_pressure_settings(mps);
    }
    let ctx = builder.build();

    if proxy.enabled {
        if panel.proxy {
            let ignore = proxy.effective_ignore_hosts();
            let ignore_refs: Vec<&str> = ignore.iter().map(String::as_str).collect();
            let mut settings = NetworkProxySettings::new(Some(&proxy.url), &ignore_refs);
            dm.set_network_proxy_settings(NetworkProxyMode::Custom, Some(&mut settings));
            if !PROXY_LOGGED.replace(true) {
                svc.log(&format!("proxy: webkit panels -> {} (bypass: {})", proxy.url, ignore.join(", ")));
            }
        } else {
            dm.set_network_proxy_settings(NetworkProxyMode::NoProxy, None);
        }
    }
    if panel.allow_insecure {
        dm.set_tls_errors_policy(TLSErrorsPolicy::Ignore);
        svc.log(&format!(
            "[{}] TLS verification DISABLED for this panel (allow_insecure: self-signed cert accepted)",
            panel.id
        ));
    }
    // Persistent cookie store (survives a restart) + refuse third-party cookie
    // writes, which complements the tracker blocklist.
    if let Some(cookies) = dm.cookie_manager() {
        if let Some(dir) = &data_dir {
            cookies
                .set_persistent_storage(&dir.join("cookies.sqlite").to_string_lossy(), CookiePersistentStorage::Sqlite);
        }
        cookies.set_accept_policy(CookieAcceptPolicy::NoThirdParty);
    }
    // No page / back-forward cache: right for a wall that shows one page per
    // view, and a big saving on 1 GB boards.
    if profile.low_memory {
        ctx.set_cache_model(CacheModel::DocumentViewer);
    }
    ctx
}

/// Attack-surface reduction applied to every view in one place, so no code
/// path can skip a control. None of these are features a dashboard needs.
fn harden_settings(webview: &WebView, panel: &Panel, profile: &Profile) {
    let Some(s) = WebViewExt::settings(webview) else {
        return;
    };
    s.set_enable_developer_extras(false);
    s.set_enable_back_forward_navigation_gestures(false);
    s.set_enable_page_cache(false);
    // IndexedDB: SPA dashboards keep session state there; it lives under the
    // per-panel private data directory.
    s.set_enable_html5_database(true);
    s.set_enable_offline_web_application_cache(false);
    // file:// can neither read other files nor reach other origins.
    s.set_allow_file_access_from_file_urls(false);
    s.set_allow_universal_access_from_file_urls(false);
    s.set_allow_top_navigation_to_data_urls(false);
    s.set_allow_modal_dialogs(false);
    s.set_enable_dns_prefetching(false);
    s.set_javascript_can_open_windows_automatically(false);
    if let Some(ua) = panel.user_agent.as_deref().filter(|ua| !ua.is_empty()) {
        s.set_user_agent(Some(ua));
    }
    // WebGL / WebAudio / media pin RAM + GPU; off unless the panel asks.
    if !panel.allow_media {
        s.set_enable_webgl(false);
        s.set_enable_webaudio(false);
        s.set_enable_media(false);
        s.set_enable_media_stream(false);
        s.set_enable_mediasource(false);
        s.set_enable_encrypted_media(false);
        s.set_enable_webrtc(false);
    }
    match profile.hwaccel {
        HwAccel::Always => s.set_hardware_acceleration_policy(HardwareAccelerationPolicy::Always),
        HwAccel::Never => s.set_hardware_acceleration_policy(HardwareAccelerationPolicy::Never),
        HwAccel::OnDemand => s.set_hardware_acceleration_policy(HardwareAccelerationPolicy::OnDemand),
        HwAccel::Default => {}
    }
}

fn bootstrap_script(svc: &Rc<dyn WallServices>, panel: &Panel) -> UserScript {
    UserScript::new(
        &svc.bootstrap_js(panel),
        UserContentInjectedFrames::TopFrame,
        UserScriptInjectionTime::Start,
        &[],
        &[],
    )
}

impl WebKitPanel {
    /// Build the panel. `embedded` panels have no window of their own (the
    /// wall window hosts their widget). `on_config` opens the on-screen
    /// config (Ctrl+Shift+C) for a standalone window.
    pub fn new(
        panel: Panel,
        svc: Rc<dyn WallServices>,
        proxy: ProxyCfg,
        profile: Profile,
        embedded: bool,
        on_config: Option<Rc<dyn Fn()>>,
    ) -> WebKitPanel {
        let ucm = UserContentManager::new();
        ucm.register_script_message_handler("socCreds");
        ucm.add_script(&bootstrap_script(&svc, &panel));

        let context = context_for(&panel, &proxy, &profile, &svc);
        let webview = WebView::builder().web_context(&context).user_content_manager(&ucm).build();
        harden_settings(&webview, &panel, &profile);
        // Match the wall background so navigations never flash white.
        style::background().parse::<gdk::RGBA>().iter().for_each(|bg| webview.set_background_color(bg)); // unparsable keeps default
        let frame = PanelFrame::new(panel.display_name(), &webview);

        let window = (!embedded).then(|| {
            let win = gtk::Window::new(gtk::WindowType::Toplevel);
            let class = panel.wmclass();
            // X11 window managers place by WM_CLASS; Wayland compositors by
            // title, so keep both equal and stable.
            ffi::set_wmclass(&win, &class);
            win.set_title(&class);
            if let Some(g) = panel.geometry {
                win.set_default_size(g.w, g.h);
            }
            win.set_decorated(true);
            win.add(frame.widget());
            win
        });

        let nav_gate = svc.nav_gate(&panel);
        if nav_gate.is_none() {
            svc.log(&format!(
                "[{}] nav allowlist DISABLED (SOC_NAV_ALLOWLIST / security.nav_allowlist) — top-level navigation \
                 is not gated",
                panel.id
            ));
        }
        let this = WebKitPanel {
            inner: Rc::new(Inner {
                panel: RefCell::new(panel),
                svc,
                proxy,
                profile,
                webview,
                ucm,
                context,
                frame,
                window,
                nav_gate,
                st: RefCell::new(State::default()),
                handlers: RefCell::new(Vec::new()),
            }),
        };
        this.connect_signals(on_config);
        this.install_tracker_block();
        this
    }

    fn weak(&self) -> Weak<Inner> {
        Rc::downgrade(&self.inner)
    }

    fn connect_signals(&self, on_config: Option<Rc<dyn Fn()>>) {
        let inner = &self.inner;
        let wv = &inner.webview;
        let mut ids = Vec::new();
        // Each handler holds a weak reference: the view must not keep its own
        // panel alive through its signal closures.
        macro_rules! with_panel {
            ($weak:ident, $default:expr, |$p:ident| $body:expr) => {
                match $weak.upgrade() {
                    Some(inner) => {
                        let $p = WebKitPanel { inner };
                        $body
                    }
                    None => $default,
                }
            };
        }

        let weak = self.weak();
        ids.push(wv.connect_web_process_terminated(move |_, reason| {
            with_panel!(weak, (), |p| p.on_terminated(&format!("{reason:?}").to_lowercase()))
        }));
        let weak = self.weak();
        ids.push(wv.connect_load_failed(move |_, _event, uri, error| {
            with_panel!(weak, false, |p| p.on_load_failed(uri, error))
        }));
        let weak = self.weak();
        ids.push(wv.connect_load_changed(move |_, event| with_panel!(weak, (), |p| p.on_load_changed(event))));
        let weak = self.weak();
        ids.push(wv.connect_authenticate(move |_, request| with_panel!(weak, false, |p| p.on_authenticate(request))));
        let weak = self.weak();
        ids.push(wv.connect_decide_policy(move |_, decision, kind| {
            with_panel!(weak, false, |p| p.on_decide_policy(decision, kind))
        }));
        *inner.handlers.borrow_mut() = ids;

        // A wall never saves a file: refuse every download (neutralises
        // drive-by file drops).
        let weak = self.weak();
        inner.context.connect_download_started(move |_, download| {
            download.cancel();
            if let Some(inner) = weak.upgrade() {
                inner.svc.log(&format!("[{}] download refused (downloads disabled)", inner.panel.borrow().id));
            }
        });

        let weak = self.weak();
        inner.ucm.connect_script_message_received(Some("socCreds"), move |_, message| {
            let reason = message.js_value().map(|v| v.to_string()).unwrap_or_default(); // audit-allow: default is the intended fallback
            with_panel!(weak, (), |p| if reason == "loggedin" { p.on_logged_in() } else { p.do_login() })
        });

        if let Some(win) = &inner.window {
            let weak = self.weak();
            win.connect_destroy(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.svc.log(&format!("[{}] window closed", inner.panel.borrow().id));
                }
            });
            if let Some(on_config) = on_config {
                win.connect_key_press_event(move |_, event| {
                    let mods = event.state();
                    let combo = mods.contains(gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::SHIFT_MASK);
                    if combo && matches!(event.keyval(), gdk::keys::constants::c | gdk::keys::constants::C) {
                        on_config();
                        return glib::Propagation::Stop;
                    }
                    glib::Propagation::Proceed
                });
            }
        }
    }

    fn id(&self) -> String {
        self.inner.panel.borrow().id.clone()
    }

    fn log(&self, msg: &str) {
        self.inner.svc.log(&format!("[{}] {msg}", self.id()));
    }

    /// A snapshot of the panel's configuration.
    pub fn panel(&self) -> Panel {
        self.inner.panel.borrow().clone()
    }

    /// The embeddable widget (used by the wall window in single layout).
    pub fn widget(&self) -> gtk::Widget {
        self.inner.frame.widget().clone().upcast()
    }

    /// How many auto-login attempts this panel has used.
    pub fn login_attempts(&self) -> u32 {
        self.inner.st.borrow().login.attempts()
    }

    /// True if this panel's page finished loading without error.
    pub fn loaded_ok(&self) -> bool {
        self.inner.st.borrow().page_ok
    }

    // ---- renderer security -------------------------------------------------

    /// Refuse top-level navigation outside the panel's allowlist (own origin,
    /// its SSO/redirect domains, configured extras). New windows are always
    /// refused — a wall panel never opens one. Returning true means "handled".
    fn on_decide_policy(&self, decision: &webkit2gtk::PolicyDecision, kind: PolicyDecisionType) -> bool {
        match kind {
            PolicyDecisionType::NewWindowAction => {
                decision.ignore();
                true
            }
            PolicyDecisionType::NavigationAction => {
                let Some(gate) = &self.inner.nav_gate else {
                    return false;
                };
                let uri = decision
                    .downcast_ref::<NavigationPolicyDecision>()
                    .and_then(|d| d.navigation_action())
                    .and_then(|action| action.request())
                    .and_then(|request| request.uri());
                match uri {
                    Some(uri) if gate(&uri) => false,
                    Some(uri) => {
                        decision.ignore();
                        self.log(&format!("refused off-allowlist nav -> {}", url_for_msg(&uri)));
                        true
                    }
                    // A navigation we cannot inspect is anomalous: for a
                    // fail-closed guard, refuse it rather than let the
                    // engine's default-allow apply.
                    None => {
                        decision.ignore();
                        self.log("nav-policy: navigation without a readable target refused (fail-closed)");
                        true
                    }
                }
            }
            _ => false,
        }
    }

    fn install_tracker_block(&self) {
        let panel = self.inner.panel.borrow().clone();
        let Some(rules) = self.inner.svc.tracker_rules(&panel) else {
            return;
        };
        let weak = self.weak();
        with_tracker_filter(
            rules,
            &self.inner.profile,
            &self.inner.svc,
            Box::new(move |filter| {
                if let Some(inner) = weak.upgrade() {
                    filter.add_to(&inner.ucm);
                }
            }),
        );
    }

    // ---- lifecycle ---------------------------------------------------------

    /// Show the panel (and its window, when it has one) and start loading.
    pub fn show(&self) {
        if let Some(win) = &self.inner.window {
            win.show_all();
            // Best-effort placement when no window-manager rules are active
            // (a plain nested X server); a real WM's placement overrides it.
            if let Some(g) = self.inner.panel.borrow().geometry {
                win.move_(g.x, g.y);
                win.resize(g.w.max(1), g.h.max(1));
            }
        }
        self.load();
    }

    /// (Re)load the panel's effective URL.
    pub fn load(&self) {
        let inner = &self.inner;
        if inner.st.borrow().stopped {
            return;
        }
        let url = inner.panel.borrow().effective_url();
        if url.is_empty() {
            inner.frame.update("not configured — open ⚙ or press Ctrl+Shift+C to set this panel's URL", false, false);
            return;
        }
        // Defence in depth: only a valid http(s) URL ever reaches the engine.
        if !valid_http_url(&url, false) {
            self.log(&format!("refusing non-http(s) URL: {}", url_for_msg(&url)));
            inner.frame.update("rejected: only http:// or https:// URLs are allowed", true, false);
            return;
        }
        let failures = {
            let mut st = inner.st.borrow_mut();
            // A fresh page gets a fresh login budget.
            st.login.reset();
            st.healing.failures()
        };
        if !inner.st.borrow().ever_loaded {
            inner.frame.update("connecting…", false, true);
        }
        inner.webview.load_uri(&url);
        self.note_web_process();
        if log_repeat(u64::from(failures)) {
            self.log(&format!("webkit loading {}", url_for_msg(&url)));
        }
    }

    /// Work out which web process is this panel's. WebKit has no API for it
    /// and the process carries nothing naming its panel. What does hold: it is
    /// launched on the main thread inside `load_uri` (first load, or after a
    /// crash) and on the way to load-committed (cross-site process swap). So
    /// a child nobody has claimed yet, seen at those moments, is ours. Two
    /// panels swapping in the same instant could trade pids; the only cost is
    /// recycling the other one of those two.
    fn note_web_process(&self) {
        let live = self.inner.svc.web_process_pids();
        let id = self.id();
        WEB_PIDS.with(|pids| {
            let mut pids = pids.borrow_mut();
            pids.retain(|pid, _| live.contains(pid));
            for pid in live {
                pids.entry(pid).or_insert_with(|| id.clone());
            }
        });
    }

    /// RSS (KiB) of this panel's web process, or `None` when it has none
    /// right now (crashed, or not loaded yet): nothing there to reclaim.
    pub fn mem_rss_kb(&self) -> Option<u64> {
        let id = self.id();
        let mine: Vec<u32> = WEB_PIDS
            .with(|pids| pids.borrow().iter().filter(|(_, owner)| **owner == id).map(|(pid, _)| *pid).collect());
        let live = self.inner.svc.web_process_pids();
        let rss: Vec<u64> = mine
            .into_iter()
            .filter(|pid| live.contains(pid))
            .filter_map(|pid| self.inner.svc.proc_rss_kb(pid))
            .collect();
        (!rss.is_empty()).then(|| rss.iter().sum())
    }

    /// Actually reclaim a leaking renderer: a plain reload does not free a
    /// leaked web process; killing it does. Cookies and storage stay, so the
    /// session survives.
    pub fn recycle(&self) {
        let inner = &self.inner;
        if inner.st.borrow().stopped {
            return;
        }
        self.log("recycling webkit (terminate web process) to reclaim memory");
        inner.context.clear_cache();
        self.cancel_retry();
        {
            let mut st = inner.st.borrow_mut();
            st.recycling = true; // on_terminated: this is not a crash
            st.healing.reset_delay();
            st.load_failed = false;
        }
        inner.webview.terminate_web_process();
        self.load();
    }

    /// Re-render the bootstrap (after new login zones, say) and reload onto
    /// it: a user script is fixed once added.
    pub fn reinject(&self) {
        let inner = &self.inner;
        inner.ucm.remove_all_scripts();
        inner.ucm.add_script(&bootstrap_script(&inner.svc, &inner.panel.borrow()));
        self.load();
    }

    /// Repoint this panel live (from the on-screen config).
    pub fn set_url(&self, url: &str) {
        let url = url.trim();
        if !url.is_empty() && !valid_http_url(url, false) {
            self.log(&format!("refusing non-http(s) URL: {}", url_for_msg(url)));
            self.inner.frame.update("rejected: only http:// or https:// URLs are allowed", true, false);
            return;
        }
        {
            let mut panel = self.inner.panel.borrow_mut();
            panel.url = (!url.is_empty()).then(|| url.to_string());
            if !url.is_empty() {
                panel.mode = Mode::Direct;
            }
        }
        self.cancel_retry(); // drop any stale retry on the old URL
        {
            let mut st = self.inner.st.borrow_mut();
            st.healing.reset_backoff();
            st.load_failed = false;
            st.ever_loaded = false;
            st.page_ok = false;
        }
        self.log(&format!(
            "reconfigured -> {}",
            if url.is_empty() { "(cleared)".to_string() } else { url_for_msg(url) }
        ));
        self.load();
    }

    /// Replace the panel's configuration (title, vault item, selectors...)
    /// without touching the loaded page; call [`Self::reinject`] to apply.
    pub fn update_panel(&self, apply: impl FnOnce(&mut Panel)) {
        apply(&mut self.inner.panel.borrow_mut());
    }

    // ---- self-healing ------------------------------------------------------

    /// Record a failure, put up the right card and schedule the retry.
    fn fail(&self, what_log: &str, card: impl FnOnce(u32) -> String) {
        let inner = &self.inner;
        let (delay, persistent, failures) = {
            let mut st = inner.st.borrow_mut();
            st.load_failed = true; // keep the card through the error page's FINISHED
            st.page_ok = false;
            let (delay, persistent) = st.healing.fail(Instant::now());
            (delay, persistent, st.healing.failures())
        };
        if log_repeat(u64::from(failures)) {
            self.log(&format!("{what_log}; retrying in {delay}s"));
        }
        let message = if persistent {
            format!("unreachable {failures}x — verify URL/tunnel (Ctrl+Shift+C)\nstill retrying every {delay}s")
        } else {
            card(delay)
        };
        inner.frame.update(&message, true, false);
        self.schedule_retry(delay);
    }

    fn on_terminated(&self, why: &str) {
        {
            let mut st = self.inner.st.borrow_mut();
            if st.stopped {
                return;
            }
            st.page_ok = false;
            if std::mem::take(&mut st.recycling) {
                return; // our own recycle(): it reloads by itself
            }
        }
        // The same exponential backoff as a load failure: on a small board a
        // terminated web process is usually the memory-pressure killer, and a
        // fixed quick reload of a heavy page would crash-loop and starve the
        // other panels.
        self.fail(&format!("web process terminated ({why})"), |delay| {
            format!("renderer {why} — recovering in {delay}s")
        });
    }

    fn on_load_failed(&self, uri: &str, error: &glib::Error) -> bool {
        if self.inner.st.borrow().stopped {
            return false;
        }
        // CANCELLED fires on perfectly normal in-page navigation.
        if error.matches(NetworkError::Cancelled) {
            return false;
        }
        let reason = error.message().to_string();
        self.fail(&format!("load failed: {reason} ({})", url_for_msg(uri)), |delay| {
            format!("offline: {reason}\nretrying in {delay}s")
        });
        // Handled: our status card is the error UI, so WebKit must not load
        // its own (white) error page.
        true
    }

    fn on_load_changed(&self, event: LoadEvent) {
        let inner = &self.inner;
        match event {
            // A new navigation starts clean; the failure flag is set later
            // only if this load fails.
            LoadEvent::Started => {
                let mut st = inner.st.borrow_mut();
                st.load_failed = false;
                st.page_ok = false;
            }
            // A cross-site load may have swapped the web process.
            LoadEvent::Committed => self.note_web_process(),
            LoadEvent::Finished => {
                {
                    let mut st = inner.st.borrow_mut();
                    // WebKit emits FINISHED even for a failed load; keep the
                    // offline card, a retry is pending.
                    if st.load_failed || st.stopped {
                        return;
                    }
                    st.page_ok = true;
                    st.recycling = false; // a stale flag would swallow a real crash
                    st.healing.finished(Instant::now(), inner.profile.stable_sec);
                    st.ever_loaded = true;
                    // A finished load means the proxy accepted the credentials.
                    st.proxy_auth.accepted();
                }
                inner.frame.clear();
            }
            _ => {}
        }
    }

    /// Remove any pending retry so a stale one cannot fire after a
    /// reconfigure / recycle / stop and stack retries on the old URL.
    fn cancel_retry(&self) {
        if let Some(source) = self.inner.st.borrow_mut().retry.take() {
            source.remove();
        }
    }

    fn schedule_retry(&self, delay: u32) {
        let mut st = self.inner.st.borrow_mut();
        if st.retry.is_some() || st.stopped {
            return;
        }
        let weak = self.weak();
        st.retry = Some(glib::timeout_add_seconds_local(delay.max(1), move || {
            if let Some(inner) = weak.upgrade() {
                // Forget the source id first: it is consumed by returning Break.
                inner.st.borrow_mut().retry = None;
                WebKitPanel { inner }.load();
            }
            glib::ControlFlow::Break
        }));
    }

    // ---- proxy auth --------------------------------------------------------

    /// Answer the proxy's 407 challenge with vault credentials. Site-level
    /// auth (401) is left to the page — panels log in via injection instead.
    fn on_authenticate(&self, request: &webkit2gtk::AuthenticationRequest) -> bool {
        if !request.is_for_proxy() {
            return false;
        }
        let inner = &self.inner;
        let target = format!("{}:{}", request.host().unwrap_or_default(), request.port()); // audit-allow: default is the intended fallback
        if inner.proxy.vault_item.is_empty() {
            self.log(&format!("proxy {target} demands authentication but proxy.vault_item is not set — cancelling"));
            request.cancel();
            return true;
        }
        if !inner.st.borrow_mut().proxy_auth.challenge() {
            self.log(&format!(
                "proxy {target} rejected the credentials from vault item '{}' repeatedly — giving up. Check the \
                 username/password in the vault.",
                inner.proxy.vault_item
            ));
            inner.frame.update("proxy authentication failed — check the vault login for the proxy", true, false);
            request.cancel();
            if inner.profile.unattended {
                // The password may get fixed in the vault with nobody here to
                // reload the panel: try again, slowly enough not to lock the
                // account out.
                let delay = inner.st.borrow_mut().proxy_auth.hold();
                self.cancel_retry();
                self.schedule_retry(delay);
            }
            return true;
        }
        let Some(login) = inner.svc.proxy_login() else {
            self.log(&format!(
                "proxy {target}: could not fetch credentials (vault item '{}') — cancelling",
                inner.proxy.vault_item
            ));
            request.cancel();
            return true;
        };
        let mut credential = Credential::new(&login.username, &login.password, CredentialPersistence::ForSession);
        ffi::authenticate(request, &mut credential);
        true
    }

    // ---- login -------------------------------------------------------------

    /// The login form went away — we are in.
    fn on_logged_in(&self) {
        {
            let mut st = self.inner.st.borrow_mut();
            st.login.reset();
            st.rearm.reset();
        }
        self.evaluate(&self.inner.svc.prompt_clear_js(), None);
        let panel = self.inner.panel.borrow().clone();
        self.inner.svc.login_succeeded(&panel);
    }

    fn do_login(&self) {
        let inner = &self.inner;
        let step = {
            let mut st = inner.st.borrow_mut();
            if st.stopped {
                return;
            }
            // Unattended: a spent budget refills after a (doubling) wait
            // instead of parking the panel on its login page forever.
            if inner.profile.unattended && st.login.exhausted() && st.rearm.due(Instant::now()) {
                st.login.reset();
                drop(st);
                self.log("login budget re-armed (unattended)");
                inner.st.borrow_mut().login.next_step()
            } else {
                st.login.next_step()
            }
        };
        let prompt = |msg: &str| self.evaluate(&inner.svc.prompt_js(msg), None);
        match step {
            LoginStep::Busy => {}
            LoginStep::PromptFailed => {
                prompt("Auto-login failed — please sign in here, or open Settings (⚙ top bar) to fix the saved login.")
            }
            LoginStep::PromptUnfillable => prompt(
                "Sign-in needed — couldn't auto-fill this page. Log in here, or open Settings (⚙ top bar) to fix the \
                 saved login selectors.",
            ),
            LoginStep::Inject => {
                let panel = inner.panel.borrow().clone();
                let page = inner.webview.uri().map(|u| u.to_string()).unwrap_or_default(); // audit-allow: default is the intended fallback
                // A redirect may have taken the top frame elsewhere (an SSO
                // tenant, an error page): the credentials stay in the vault.
                if !inner.svc.may_login(&panel, &page) {
                    inner.st.borrow_mut().login.result(false);
                    self.log(&format!("login withheld: page is off the panel's origin ({})", url_for_msg(&page)));
                    return;
                }
                let Some(login) = inner.svc.login_for(&panel) else {
                    inner.st.borrow_mut().login.abort();
                    prompt(
                        "Sign-in needed — no saved login for this page. Open Settings (⚙ top bar) to add one, or \
                         just log in here.",
                    );
                    return;
                };
                let Some(js) = inner.svc.login_js(&panel, &login) else {
                    inner.st.borrow_mut().login.result(false);
                    return;
                };
                drop(login);
                // Inject first, then count by what the login call actually
                // did: true only when it filled + submitted a form.
                let weak = self.weak();
                self.evaluate(
                    &js,
                    Some(Box::new(move |value| {
                        let Some(inner) = weak.upgrade() else {
                            return;
                        };
                        let submitted = value.is_some_and(|v| v.to_boolean());
                        let (attempts, misses) = {
                            let mut st = inner.st.borrow_mut();
                            st.login.result(submitted);
                            (st.login.attempts(), st.login.misses())
                        };
                        let p = WebKitPanel { inner };
                        if submitted {
                            p.log(&format!("injected login (attempt {attempts})"));
                        } else {
                            p.log(&format!(
                                "login injection miss (retriable {misses}/{})",
                                crate::logic::MAX_LOGIN_MISSES
                            ));
                        }
                    })),
                );
            }
        }
    }

    /// Evaluate JS in the view. With a callback, it receives the result (or
    /// `None` on any evaluation error) — failures are observed, never
    /// silently swallowed.
    fn evaluate(&self, js: &str, on_result: Option<Box<dyn FnOnce(Option<javascriptcore::Value>)>>) {
        let weak = self.weak();
        self.inner.webview.evaluate_javascript(js, None, None, gio::Cancellable::NONE, move |result| {
            let value = match result {
                Ok(v) => Some(v),
                Err(e) => {
                    if let Some(inner) = weak.upgrade() {
                        inner.svc.log(&format!("[{}] evaluate_javascript failed: {e}", inner.panel.borrow().id));
                    }
                    None
                }
            };
            if let Some(callback) = on_result {
                callback(value);
            }
        });
    }

    /// Tear down so web processes and timers do not leak. Idempotent.
    pub fn stop(&self) {
        let inner = &self.inner;
        {
            let mut st = inner.st.borrow_mut();
            if st.stopped {
                return;
            }
            st.stopped = true;
            st.page_ok = false;
        }
        self.cancel_retry();
        for id in inner.handlers.borrow_mut().drain(..) {
            inner.webview.disconnect(id);
        }
        inner.webview.terminate_web_process();
        let id = self.id();
        WEB_PIDS.with(|pids| pids.borrow_mut().retain(|_, owner| *owner != id));
        if let Some(win) = &inner.window {
            win.close();
        }
        self.log("webkit panel stopped");
    }
}
