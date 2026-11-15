//! One attached DevTools session for a panel: install the bootstrap and the
//! guards, navigate, then answer what the page and the network ask for.
//!
//! Everything here runs on the panel's control thread, which alone owns the
//! websocket.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use soc_core::url::Url;
use soc_core::{Login, Panel};
use zeroize::Zeroizing;

use super::cdp::{Cdp, CdpError, Endpoint, EventHandler, Outbox};
use super::{PanelEvent, Timing};
use crate::inject::{self, LoginRearm};
use crate::pyjson;
use crate::siteguard::AllowList;

/// Auto-login attempts per page before a human is asked.
pub const MAX_LOGIN_ATTEMPTS: u32 = 3;
/// Wrong answers to one proxy challenge before the proxy is left alone.
pub const PROXY_AUTH_MAX_ATTEMPTS: u32 = 3;
/// Answers within [`PROXY_BURST_WINDOW`] that mean something is looping.
const PROXY_BURST_MAX: usize = 20;
const PROXY_BURST_WINDOW: Duration = Duration::from_secs(30);
const PROXY_HOLD_INITIAL: Duration = Duration::from_secs(300);
const PROXY_HOLD_MAX: Duration = Duration::from_secs(3600);
const MAX_ANSWERED: usize = 512;

/// One round-trip for everything the loop needs to know about the page. The
/// origin is read from the unforgeable `window.location`, so the page cannot
/// misreport where it is.
pub(crate) const POLL_JS: &str = "(function(){var s=window.__SOC||{};\
return {n:!!s.needLogin,l:!!s.justLoggedIn,\
r:document.readyState==='complete'&&/^https?:$/.test(location.protocol),\
e:location.protocol==='chrome-error:',o:window.location.origin};})()";

const PROMPT_FAILED: &str =
    "Auto-login failed — please sign in here, or open Settings (⚙ top bar) to fix the saved login.";
const PROMPT_NO_LOGIN: &str =
    "Sign-in needed — no saved login for this page. Open Settings (⚙ top bar) to add one, or log in here.";
const PROMPT_FOREIGN: &str =
    "Sign-in needed — this is not the panel's configured site, so the saved login was not used. Log in here.";

pub(crate) use super::{EventFn as EventSink, LoginFn, ProxyLoginFn};

/// What a panel's session is built from; recomputed whenever the panel's URL
/// changes.
pub(crate) struct PanelCtx {
    pub panel: Panel,
    pub bootstrap: String,
    /// The only origin credentials are released to; `""` = never.
    pub origin: String,
    /// The panel's URL, or `None` for an unconfigured tile.
    pub target: Option<String>,
    /// `None` when the navigation gate is switched off.
    pub allowlist: Option<AllowList>,
    pub blocked_urls: Vec<String>,
    /// The panel goes through a proxy that wants vault credentials.
    pub proxy_auth: bool,
    pub unattended: bool,
}

/// How the session came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attach {
    /// A fresh browser sitting on the placeholder: navigate it.
    Fresh,
    /// The socket to a running page was lost: re-arm, keep the page.
    Resume,
}

// --------------------------------------------------------------------------- //
// Proxy authentication
// --------------------------------------------------------------------------- //

/// State for answering the proxy's `407` from the vault.
pub(crate) struct ProxyAuth {
    /// The configured proxy authority, for checking who is asking.
    host: Option<String>,
    port: Option<u16>,
    vault_item: String,
    login: Option<ProxyLoginFn>,
    /// Request ids already answered: a second challenge for one of them means
    /// the proxy rejected what the vault holds.
    answered: HashSet<String>,
    rejections: u32,
    recent: VecDeque<Instant>,
    held_until: Option<Instant>,
    held: bool,
    next_hold: Duration,
    /// On an unattended wall a hold expires (the password may get fixed in
    /// the vault with nobody there to restart anything).
    rearm: bool,
    misses: u32,
}

impl ProxyAuth {
    pub fn new(proxy_url: &str, vault_item: &str, login: Option<ProxyLoginFn>, unattended: bool) -> ProxyAuth {
        let parts = Url::split(proxy_url.trim()).ok();
        ProxyAuth {
            host: parts.as_ref().and_then(|p| p.host.clone()),
            port: parts.as_ref().and_then(|p| p.port),
            vault_item: vault_item.to_string(),
            login,
            answered: HashSet::new(),
            rejections: 0,
            recent: VecDeque::new(),
            held_until: None,
            held: false,
            next_hold: PROXY_HOLD_INITIAL,
            rearm: unattended,
            misses: 0,
        }
    }

    /// Whether the challenge comes from the configured proxy. Only a parsed
    /// mismatch refuses: an origin this cannot read is left to Chromium's own
    /// `source: Proxy` classification.
    fn is_our_proxy(&self, challenge_origin: &str) -> bool {
        let (Some(host), Some(theirs)) = (self.host.as_deref(), authority_of(challenge_origin)) else {
            return true;
        };
        theirs.0.eq_ignore_ascii_case(host) && (theirs.1.is_none() || self.port.is_none() || theirs.1 == self.port)
    }

    /// Forget a hold and its history (a new browser, or an operator reload).
    pub fn reset(&mut self) {
        self.answered.clear();
        self.recent.clear();
        self.rejections = 0;
        self.held = false;
        self.held_until = None;
        self.next_hold = PROXY_HOLD_INITIAL;
    }

    pub fn is_held(&self) -> bool {
        self.held
    }
}

/// `(host, port)` of `scheme://host:port` or a bare `host:port`.
fn authority_of(origin: &str) -> Option<(String, Option<u16>)> {
    let text = origin.trim();
    let with_scheme = if text.contains("://") { text.to_string() } else { format!("x://{text}") };
    let parts = Url::split(&with_scheme).ok()?;
    Some((parts.host?, parts.port))
}

enum AuthVerdict {
    Provide(Login),
    Cancel,
}

// --------------------------------------------------------------------------- //
// Event handling
// --------------------------------------------------------------------------- //

/// The persistent event handler: navigation gate, proxy auth, activity flags.
pub(crate) struct Guard {
    id: String,
    allowlist: Option<AllowList>,
    proxy: Option<ProxyAuth>,
    sink: EventSink,
    /// A new top-level document or SPA route appeared since the last poll
    /// (it may be a login page): the settled poll must not wait.
    pub activity: bool,
    pub crashed: bool,
    last_fetch: Instant,
}

impl Guard {
    pub fn new(id: &str, allowlist: Option<AllowList>, proxy: Option<ProxyAuth>, sink: EventSink) -> Guard {
        Guard {
            id: id.to_string(),
            allowlist,
            proxy,
            sink,
            activity: false,
            crashed: false,
            last_fetch: Instant::now(),
        }
    }

    fn log(&self, msg: impl AsRef<str>) {
        (self.sink)(PanelEvent::Log(format!("[{}] {}", self.id, msg.as_ref())));
    }

    /// Whether proxy authentication has been given up on (for now).
    pub fn proxy_held(&self) -> bool {
        self.proxy.as_ref().is_some_and(ProxyAuth::is_held)
    }

    /// Give the proxy a fresh chance (an operator asked for a reload).
    pub fn proxy_reset(&mut self) {
        if let Some(proxy) = self.proxy.as_mut() {
            proxy.reset();
        }
    }

    /// True if a paused request is a document navigation to a host off the
    /// allowlist. Only `Document` requests are gated; sub-resources pass.
    /// Sub-frame documents are gated too: erring toward refusing an
    /// off-allowlist frame is the safer choice on a wall.
    fn nav_blocked(&self, params: &Value) -> bool {
        match &self.allowlist {
            Some(list) if params["resourceType"] == "Document" => {
                !list.nav_allowed(params["request"]["url"].as_str().unwrap_or_default()) // audit-allow: default is the intended fallback (no url -> allowed, as before)
            }
            _ => false,
        }
    }

    fn on_request_paused(&mut self, params: &Value, out: &mut Outbox) {
        let Some(rid) = params["requestId"].as_str() else {
            return;
        };
        if self.nav_blocked(params) {
            out.push("Fetch.failRequest", &json!({"requestId": rid, "errorReason": "BlockedByClient"}));
            let url = params["request"]["url"].as_str().unwrap_or_default(); // audit-allow: default is the intended fallback (missing url -> "")
            self.log(format!("refused off-allowlist nav -> {}", loggable_url(url)));
            (self.sink)(PanelEvent::NavBlocked(loggable_url(url)));
        } else {
            out.push("Fetch.continueRequest", &json!({"requestId": rid}));
        }
    }

    fn on_auth_required(&mut self, params: &Value, out: &mut Outbox) {
        let Some(rid) = params["requestId"].as_str() else {
            return;
        };
        let challenge = &params["authChallenge"];
        let respond = |out: &mut Outbox, response: &str| {
            out.push(
                "Fetch.continueWithAuth",
                &json!({"requestId": rid, "authChallengeResponse": {"response": response}}),
            );
        };
        if challenge["source"] != "Proxy" {
            // Site-level auth is not ours to answer (panels log in by injection).
            respond(out, "Default");
            return;
        }
        let origin = challenge["origin"].as_str().unwrap_or_default(); // audit-allow: default is the intended fallback (missing origin -> "")
        match self.proxy_verdict(rid, origin) {
            AuthVerdict::Cancel => respond(out, "CancelAuth"),
            AuthVerdict::Provide(login) => {
                // Serialised by hand into a buffer that is wiped after
                // sending, instead of through an intermediate JSON tree.
                let mut body = Zeroizing::new(String::with_capacity(160));
                body.push_str("{\"requestId\":");
                pyjson::write_str(&mut body, rid);
                body.push_str(",\"authChallengeResponse\":{\"response\":\"ProvideCredentials\",\"username\":");
                pyjson::write_str(&mut body, &login.username);
                body.push_str(",\"password\":");
                pyjson::write_str(&mut body, &login.password);
                body.push_str("}}");
                out.push_raw("Fetch.continueWithAuth", body);
            }
        }
    }

    fn proxy_verdict(&mut self, rid: &str, origin: &str) -> AuthVerdict {
        let now = Instant::now();
        let Some(proxy) = self.proxy.as_mut() else {
            return AuthVerdict::Cancel;
        };
        if proxy.held {
            match proxy.held_until {
                Some(until) if now >= until => {
                    let next = proxy.next_hold;
                    proxy.reset();
                    proxy.next_hold = next;
                }
                _ => return AuthVerdict::Cancel,
            }
        }
        if !proxy.is_our_proxy(origin) {
            let shown = loggable_url(origin);
            self.log(format!("proxy auth challenge from {shown}, not the configured proxy — not answered"));
            return AuthVerdict::Cancel;
        }
        if proxy.answered.contains(rid) {
            proxy.rejections += 1;
        }
        while proxy.recent.front().is_some_and(|t| now.duration_since(*t) > PROXY_BURST_WINDOW) {
            proxy.recent.pop_front();
        }
        let rejected = proxy.rejections >= PROXY_AUTH_MAX_ATTEMPTS;
        if rejected || proxy.recent.len() >= PROXY_BURST_MAX || proxy.login.is_none() {
            // Stop answering: hammering the proxy with a wrong password locks
            // the account.
            proxy.held = true;
            proxy.held_until = proxy.rearm.then(|| now + proxy.next_hold);
            let retry = proxy.rearm.then_some(proxy.next_hold);
            proxy.next_hold = (proxy.next_hold * 2).min(PROXY_HOLD_MAX);
            let item = proxy.vault_item.clone();
            let why = if rejected { "rejected the credentials from" } else { "kept challenging despite" };
            let then = match retry {
                Some(d) => format!("holding off for {}s", d.as_secs()),
                None => "giving up".to_string(),
            };
            self.log(format!("proxy {why} vault item '{item}' — {then}. Check the username/password in the vault."));
            return AuthVerdict::Cancel;
        }
        let Some(login) = proxy.login.as_ref().and_then(|fetch| fetch()) else {
            proxy.misses += 1;
            let (n, item) = (proxy.misses, proxy.vault_item.clone());
            if n <= 5 || n % 30 == 0 {
                self.log(format!("proxy auth: could not fetch credentials (vault item '{item}')"));
            }
            return AuthVerdict::Cancel;
        };
        if proxy.answered.len() >= MAX_ANSWERED {
            proxy.answered.clear();
        }
        let first = proxy.answered.is_empty();
        proxy.answered.insert(rid.to_string());
        proxy.recent.push_back(now);
        proxy.misses = 0;
        if first {
            let item = proxy.vault_item.clone();
            self.log(format!("proxy auth answered (vault item '{item}')"));
        }
        AuthVerdict::Provide(login)
    }
}

impl EventHandler for Guard {
    fn on_event(&mut self, method: &str, params: &Value, out: &mut Outbox) {
        match method {
            "Fetch.requestPaused" => {
                self.last_fetch = Instant::now();
                self.on_request_paused(params, out);
            }
            "Fetch.authRequired" => {
                self.last_fetch = Instant::now();
                self.on_auth_required(params, out);
            }
            // A sub-frame navigating must not cancel a top-level one's flag.
            "Page.frameNavigated" => self.activity |= params["frame"]["parentId"].as_str().is_none_or(str::is_empty),
            "Page.navigatedWithinDocument" => self.activity = true,
            "Inspector.targetCrashed" => {
                self.activity = true;
                self.crashed = true;
            }
            _ => {}
        }
    }
}

/// A URL reduced to what is safe and useful in the journal: scheme and
/// authority (no userinfo), without the path or query — those can carry
/// session tokens, and the journal outlives the session.
pub(crate) fn loggable_url(url: &str) -> String {
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).take(120).collect::<String>();
    match Url::split(url.trim()) {
        Ok(parts) => match parts.host {
            Some(host) => {
                let port = parts.port.map(|p| format!(":{p}")).unwrap_or_default(); // audit-allow: default is the intended fallback (no port)
                let host = if host.contains(':') { format!("[{host}]") } else { host };
                clean(&format!("{}://{host}{port}/…", parts.scheme))
            }
            None => clean(&format!("{}:…", parts.scheme)),
        },
        Err(_) => "(unparsable url)".to_string(), // audit-allow: the parse error may echo the url, which must stay out of the journal
    }
}

// --------------------------------------------------------------------------- //
// Login state
// --------------------------------------------------------------------------- //

/// Auto-login bookkeeping that outlives a re-attach (but not a new browser).
#[derive(Default)]
pub(crate) struct LoginState {
    pub attempts: u32,
    pub rearm: LoginRearm,
    /// The last foreign origin a login was withheld from (logged once each).
    withheld_on: Option<String>,
}

/// What one poll saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PageState {
    pub need_login: bool,
    pub logged_in: bool,
    /// The top document finished loading over http(s).
    pub ready: bool,
    /// The browser's own error page is showing.
    pub error_page: bool,
    pub origin: String,
}

impl PageState {
    fn from_value(v: &Value) -> PageState {
        let flag = |k: &str| v[k].as_bool().unwrap_or(false);
        PageState {
            need_login: flag("n"),
            logged_in: flag("l"),
            ready: flag("r"),
            error_page: flag("e"),
            origin: v["o"].as_str().unwrap_or_default().to_string(), // audit-allow: default is the intended fallback (missing field -> "")
        }
    }
}

// --------------------------------------------------------------------------- //
// Session
// --------------------------------------------------------------------------- //

pub(crate) struct Session {
    cdp: Cdp,
    pub guard: Guard,
    rpc_timeout: Duration,
}

impl Session {
    /// Connect and arm everything, in an order that leaves no gap: the
    /// bootstrap, the tracker block, the download ban and the navigation /
    /// proxy-auth interception are all in place before the panel's URL is
    /// requested for the first time.
    pub fn attach(
        endpoint: &Endpoint,
        ctx: &PanelCtx,
        guard: Guard,
        mode: Attach,
        timing: &Timing,
        cancel: Arc<AtomicBool>,
    ) -> Result<Session, CdpError> {
        let cdp = Cdp::connect(endpoint, cancel)?;
        let mut session = Session { cdp, guard, rpc_timeout: timing.rpc_timeout };
        session.arm(ctx, mode, timing)?;
        Ok(session)
    }

    fn rpc(&mut self, method: &str, params: Value) -> Result<Value, CdpError> {
        self.cdp.rpc(method, &params, self.rpc_timeout, &mut self.guard)
    }

    fn eval(&mut self, expression: &str) -> Result<Value, CdpError> {
        self.cdp.evaluate(expression, self.rpc_timeout, &mut self.guard)
    }

    /// Run a guard that may be missing from a given Chromium build: a refusal
    /// from the browser is logged and tolerated, a dead socket is not.
    fn optional(&mut self, what: &str, method: &str, params: Value) -> Result<bool, CdpError> {
        match self.rpc(method, params) {
            Ok(_) => Ok(true),
            Err(CdpError::Remote(e)) => {
                self.guard.log(format!("{what} setup failed: {e}"));
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    fn arm(&mut self, ctx: &PanelCtx, mode: Attach, timing: &Timing) -> Result<(), CdpError> {
        self.rpc("Page.enable", json!({}))?;
        // No Runtime.enable: evaluate does not need it, and with it every
        // console.log of a chatty page is serialised to this thread.
        // Inspector.enable only buys the crash event; the poll catches a dead
        // renderer anyway.
        match self.rpc("Inspector.enable", json!({})) {
            Ok(_) | Err(CdpError::Remote(_)) => {}
            Err(e) => return Err(e),
        }
        self.rpc("Page.addScriptToEvaluateOnNewDocument", json!({"source": ctx.bootstrap}))?;
        if mode == Attach::Resume {
            // The page that is already showing lost nothing (the bootstrap is
            // idempotent), but make sure it has it.
            self.eval(&ctx.bootstrap)?;
        }

        if !ctx.blocked_urls.is_empty() {
            // The Network domain keeps a copy of every response body for a
            // debugger that might ask (100+ MB per panel). Nothing here ever
            // reads one, so the buffers are sized to zero.
            let enabled = self.optional(
                "tracker block",
                "Network.enable",
                json!({"maxTotalBufferSize": 0, "maxResourceBufferSize": 0}),
            )?;
            if enabled && self.optional("tracker block", "Network.setBlockedURLs", json!({"urls": ctx.blocked_urls}))? {
                self.guard.log(format!("chromium tracker block on ({} patterns)", ctx.blocked_urls.len()));
            }
        }
        // A wall never needs to save a file; this also stops drive-by drops.
        self.optional("download-deny", "Page.setDownloadBehavior", json!({"behavior": "deny"}))?;

        // A fresh browser behind an authenticating proxy: every request is
        // intercepted while the proxy session is being established, so the
        // first 407 is answered here and never reaches Chromium's native
        // credentials dialog.
        let auth_window = ctx.proxy_auth && mode == Attach::Fresh && ctx.target.is_some();
        if auth_window {
            self.rpc("Fetch.enable", json!({"handleAuthRequests": true}))?;
        } else {
            self.arm_document_gate(ctx)?;
        }
        if mode == Attach::Fresh {
            if let Some(url) = ctx.target.as_deref() {
                // Not awaited: the reply only comes once the (paused)
                // navigation has been let through by the handler above.
                self.cdp.send_nowait("Page.navigate", &json!({"url": url}))?;
            }
        }
        if auth_window {
            self.proxy_auth_window(timing)?;
            self.arm_document_gate(ctx)?;
        }
        Ok(())
    }

    /// The steady-state interception: only document requests are paused, so
    /// sub-resources pay no latency. It carries the navigation allowlist and
    /// keeps auth handling on, so a late proxy re-challenge on a navigation is
    /// still answered (hence it is armed for a proxied panel even with the
    /// allowlist switched off — the handler then lets every document through).
    /// If it cannot be armed the attach fails: a wall that silently runs
    /// without its navigation guard is worse than a panel that retries.
    fn arm_document_gate(&mut self, ctx: &PanelCtx) -> Result<(), CdpError> {
        if ctx.allowlist.is_none() && !ctx.proxy_auth {
            return Ok(());
        }
        self.rpc(
            "Fetch.enable",
            json!({"handleAuthRequests": true, "patterns": [{"requestStage": "Request", "resourceType": "Document"}]}),
        )?;
        if let Some(list) = &ctx.allowlist {
            self.guard.log(format!("chromium nav allowlist on ({} domains)", list.len()));
        }
        Ok(())
    }

    /// Pump events quickly for a short while after the first navigation so the
    /// proxy's challenges are answered; Chromium caches the proxy session
    /// afterwards. Ends early once requests stop being paused.
    fn proxy_auth_window(&mut self, timing: &Timing) -> Result<(), CdpError> {
        let start = Instant::now();
        self.guard.last_fetch = start;
        let deadline = start + timing.proxy_auth_window;
        let quiet = timing.proxy_auth_window / 10;
        while Instant::now() < deadline {
            self.cdp.pump((Instant::now() + Duration::from_millis(250)).min(deadline), &mut self.guard)?;
            if self.guard.proxy_held() {
                break;
            }
            if start.elapsed() > quiet + quiet / 2 && self.guard.last_fetch.elapsed() > quiet {
                break;
            }
        }
        Ok(())
    }

    pub fn is_alive(&self) -> bool {
        self.cdp.is_alive()
    }

    /// Ask the page where it is and what it needs.
    pub fn poll(&mut self) -> Result<PageState, CdpError> {
        self.guard.activity = false;
        self.eval(POLL_JS).map(|v| PageState::from_value(&v))
    }

    /// Go (back) to `url`.
    pub fn navigate(&mut self, url: &str) -> Result<(), CdpError> {
        self.cdp.send_nowait("Page.navigate", &json!({"url": url}))
    }

    /// Wait for events until `until`; returns early after each one.
    pub fn pump(&mut self, until: Instant) -> Result<bool, CdpError> {
        self.cdp.pump(until, &mut self.guard)
    }

    pub fn evaluate(&mut self, expression: &str) -> Result<Value, CdpError> {
        self.eval(expression)
    }

    /// Act on a poll: acknowledge a completed login, and answer a login
    /// request — with credentials only when the page is on the panel's own
    /// origin, and only inside an evaluation that re-checks that origin.
    ///
    /// Returns `true` when the page reported a successful login.
    pub fn handle_login(
        &mut self,
        st: &PageState,
        ctx: &PanelCtx,
        login: &mut LoginState,
        fetch: &LoginFn,
        now: Instant,
    ) -> Result<bool, CdpError> {
        // `needLogin` / `justLoggedIn` are page-controlled flags; they only
        // mean something on the panel's own site.
        let home = !ctx.origin.is_empty() && st.origin == ctx.origin;
        let mut succeeded = false;
        if st.logged_in {
            self.eval("window.__SOC.justLoggedIn=false")?;
            if home {
                login.attempts = 0;
                login.rearm.reset();
                login.withheld_on = None;
                self.eval(inject::prompt_clear_call())?;
                succeeded = true;
            }
        }
        if !st.need_login {
            return Ok(succeeded);
        }
        if !home {
            if login.withheld_on.as_deref() != Some(st.origin.as_str()) {
                login.withheld_on = Some(st.origin.clone());
                self.guard.log(format!(
                    "login requested on {} — not the panel's origin, credentials withheld",
                    loggable_url(&st.origin)
                ));
            }
            self.eval(&inject::prompt_call(PROMPT_FOREIGN))?;
            return Ok(succeeded);
        }
        login.attempts += 1;
        if login.attempts > MAX_LOGIN_ATTEMPTS && ctx.unattended && login.rearm.due(now) {
            self.guard.log("login budget re-armed (unattended)");
            login.attempts = 1;
        }
        if login.attempts > MAX_LOGIN_ATTEMPTS {
            if login.attempts == MAX_LOGIN_ATTEMPTS + 1 {
                (self.guard.sink)(PanelEvent::SignInNeeded);
            }
            // Keep the counter from growing without bound on a stuck page.
            login.attempts = MAX_LOGIN_ATTEMPTS + 2;
            self.eval(&inject::prompt_call(PROMPT_FAILED))?;
            return Ok(succeeded);
        }
        let call = fetch(&ctx.panel).and_then(|creds| inject::guarded_login_call(&ctx.origin, &creds));
        match call {
            Some(call) => {
                self.eval(&call)?;
                self.guard.log(format!("injected login (chromium, attempt {})", login.attempts));
            }
            None => {
                self.eval(&inject::prompt_call(PROMPT_NO_LOGIN))?;
            }
        }
        Ok(succeeded)
    }
}
