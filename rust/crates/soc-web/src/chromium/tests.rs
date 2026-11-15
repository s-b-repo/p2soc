//! The engine against the in-process fake DevTools server: no real Chromium,
//! no display, loopback only.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use soc_core::{Engine, Geometry, Login, Panel, ProxyCfg, SecurityCfg};

use super::cdp::{self, Cdp, CdpError, Endpoint, EventHandler, NoEvents, Outbox};
use super::fake::FakeDevTools;
use super::session::{Attach, Guard, LoginState, PageState, PanelCtx, ProxyAuth, Session};
use super::*;
use crate::inject;
use crate::websecurity::SecurityData;

const ORIGIN: &str = "https://dash.example.com";

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn fast() -> Timing {
    Timing {
        respawn_initial: ms(20),
        respawn_max: ms(80),
        respawn_stable: Duration::from_secs(60),
        rpc_timeout: Duration::from_secs(3),
        poll_interval: ms(15),
        poll_settled: ms(30),
        park_retry: Duration::from_secs(60),
        attach_timeout: Duration::from_secs(3),
        attach_poll: ms(5),
        proxy_auth_window: ms(300),
        calibrate_timeout: Duration::from_secs(5),
        reap_grace: ms(200),
    }
}

fn dash() -> Panel {
    let mut p = Panel::new("a");
    p.engine = Engine::Chromium;
    p.url = Some("https://dash.example.com/overview?token=s3cret".into());
    p.vault_item = "Dash".into();
    p.selectors = json!({"user": "#u", "pass": "#p", "submit": "#s"}).as_object().cloned().unwrap();
    p.geometry = Some(Geometry { x: 0, y: 0, w: 960, h: 540 });
    p
}

type Events = Arc<Mutex<Vec<PanelEvent>>>;

fn collector() -> (Events, EventFn) {
    let events: Events = Arc::default();
    let sink = events.clone();
    (events, Arc::new(move |e| sink.lock().unwrap().push(e)))
}

fn logs(events: &Events) -> Vec<String> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| if let PanelEvent::Log(m) = e { Some(m.clone()) } else { None })
        .collect()
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(ms(5));
    }
}

fn ctx_for(panel: &Panel, security: &SecurityCfg, proxy_auth: bool) -> PanelCtx {
    let data = SecurityData::embedded();
    PanelCtx {
        bootstrap: inject::render_bootstrap(inject::DEFAULT_TEMPLATE, panel, Engine::Chromium),
        origin: inject::allowed_origin(panel),
        target: Some(panel.effective_url()).filter(|u| !u.is_empty()),
        allowlist: crate::siteguard::nav_gate_enabled(security).then(|| AllowList::build(panel, security, &data)),
        blocked_urls: crate::siteguard::chromium_blocked_urls(panel, &data),
        proxy_auth,
        unattended: false,
        panel: panel.clone(),
    }
}

fn endpoint(fake: &FakeDevTools) -> Endpoint {
    cdp::discover(fake.port).unwrap()
}

fn no_cancel() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

fn attach(fake: &FakeDevTools, ctx: &PanelCtx, proxy: Option<ProxyAuth>, mode: Attach) -> (Session, Events) {
    let (events, sink) = collector();
    let guard = Guard::new(&ctx.panel.id, ctx.allowlist.clone(), proxy, sink);
    let session = Session::attach(&endpoint(fake), ctx, guard, mode, &fast(), no_cancel()).unwrap();
    (session, events)
}

/// A vault stand-in that counts how often it is asked.
fn vault(user: &str, pass: &str) -> (Arc<AtomicU32>, LoginFn) {
    let asked = Arc::new(AtomicU32::new(0));
    let (count, user, pass) = (asked.clone(), user.to_string(), pass.to_string());
    let fetch: LoginFn = Arc::new(move |_panel: &Panel| {
        count.fetch_add(1, Ordering::Relaxed);
        Some(Login::new(user.as_str(), pass.as_str()))
    });
    (asked, fetch)
}

fn proxy_vault() -> (Arc<AtomicU32>, ProxyLoginFn) {
    let asked = Arc::new(AtomicU32::new(0));
    let count = asked.clone();
    let fetch: ProxyLoginFn = Arc::new(move || {
        count.fetch_add(1, Ordering::Relaxed);
        Some(Login::new("svc-proxy", "pr0xy\"pw"))
    });
    (asked, fetch)
}

/// One round trip, so everything sent before it has been processed by the
/// fake — and the first navigation, paused by the gate, has been released.
fn settle(session: &mut Session) {
    session.poll().unwrap();
}

fn position(methods: &[String], method: &str) -> usize {
    methods.iter().position(|m| m == method).unwrap_or_else(|| panic!("{method} was never sent: {methods:?}"))
}

fn page(need: bool, logged_in: bool, origin: &str) -> PageState {
    PageState { need_login: need, logged_in, ready: true, error_page: false, origin: origin.to_string() }
}

// --------------------------------------------------------------------------- //
// Transport
// --------------------------------------------------------------------------- //

#[test]
fn discovery_picks_the_page_target() {
    let fake = FakeDevTools::start();
    let ep = endpoint(&fake);
    assert_eq!(ep.port, fake.port);
    assert_eq!(ep.path, "/devtools/page/FAKE0123456789ABCDEF");
}

#[test]
fn discovery_refuses_an_endpoint_that_is_not_loopback() {
    for hostile in [
        "ws://attacker.example:9222/devtools/page/X".to_string(),
        "ws://127.0.0.1:1/devtools/page/X".to_string(),
        "wss://127.0.0.1/devtools/page/X".to_string(),
    ] {
        let fake = FakeDevTools::start();
        fake.advertise(&hostile);
        assert!(matches!(cdp::discover(fake.port), Err(CdpError::NotLoopback(_))), "{hostile}");
        assert_eq!(fake.connections(), 0, "no websocket may be opened");
    }
}

#[test]
fn discovery_fails_cleanly_on_a_closed_port() {
    // Port 1 (tcpmux) is never handed out as an ephemeral port, so no
    // parallel test's server can appear on it.
    assert!(matches!(cdp::discover(1), Err(CdpError::Discovery(_))));
}

#[test]
fn rpc_returns_the_matching_result_and_surfaces_remote_errors() {
    let fake = FakeDevTools::start();
    fake.set_page(json!({"n": true, "o": ORIGIN}));
    let mut cdp = Cdp::connect(&endpoint(&fake), no_cancel()).unwrap();
    assert_eq!(cdp.rpc("Page.enable", &json!({}), ms(2000), &mut NoEvents).unwrap(), json!({}));
    let value = cdp.evaluate(super::session::POLL_JS, ms(2000), &mut NoEvents).unwrap();
    assert_eq!(value["o"], ORIGIN);
    fake.fail_method("Inspector.enable");
    let err = cdp.rpc("Inspector.enable", &json!({}), ms(2000), &mut NoEvents).unwrap_err();
    assert!(matches!(&err, CdpError::Remote(m) if m.contains("wasn't found")), "{err:?}");
    assert!(cdp.is_alive(), "a refused command does not kill the session");
}

#[test]
fn rpc_times_out_under_an_event_flood() {
    // A flood of unsolicited events keeps every read returning early; the
    // overall deadline must still fire instead of wedging the control loop.
    let fake = FakeDevTools::start();
    let mut cdp = Cdp::connect(&endpoint(&fake), no_cancel()).unwrap();
    fake.silence_method("Page.enable");
    fake.flood(true);
    let started = Instant::now();
    let err = cdp.rpc("Page.enable", &json!({}), ms(200), &mut NoEvents).unwrap_err();
    assert_eq!(err, CdpError::Timeout("Page.enable".into()));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn rpc_times_out_when_the_browser_goes_silent() {
    let fake = FakeDevTools::start();
    let mut cdp = Cdp::connect(&endpoint(&fake), no_cancel()).unwrap();
    fake.silence_method("Page.enable");
    let err = cdp.rpc("Page.enable", &json!({}), ms(150), &mut NoEvents).unwrap_err();
    assert!(matches!(err, CdpError::Timeout(_)));
    // The late session is still usable for the next call.
    assert!(cdp.rpc("Page.disable", &json!({}), ms(2000), &mut NoEvents).is_ok());
}

#[test]
fn a_stop_request_interrupts_a_pending_call() {
    let fake = FakeDevTools::start();
    let cancel = no_cancel();
    let mut cdp = Cdp::connect(&endpoint(&fake), cancel.clone()).unwrap();
    fake.silence_method("Page.enable");
    cancel.store(true, Ordering::Relaxed);
    let started = Instant::now();
    assert_eq!(cdp.rpc("Page.enable", &json!({}), Duration::from_secs(30), &mut NoEvents), Err(CdpError::Stopped));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_closed_socket_is_fatal_not_a_timeout() {
    let fake = FakeDevTools::start();
    let mut cdp = Cdp::connect(&endpoint(&fake), no_cancel()).unwrap();
    fake.drop_connection();
    let err = cdp.pump(Instant::now() + Duration::from_secs(3), &mut NoEvents).unwrap_err();
    assert!(matches!(err, CdpError::Closed(_)) && err.is_fatal());
    assert!(!cdp.is_alive());
    assert!(matches!(cdp.send_nowait("Page.enable", &json!({})), Err(CdpError::Closed(_))));
}

// --------------------------------------------------------------------------- //
// Attach: bootstrap + guards
// --------------------------------------------------------------------------- //

#[test]
fn bootstrap_and_guards_are_in_place_before_the_first_navigation() {
    let fake = FakeDevTools::start();
    let panel = dash();
    let ctx = ctx_for(&panel, &SecurityCfg::default(), false);
    let (mut session, events) = attach(&fake, &ctx, None, Attach::Fresh);
    // The gate pauses the panel's own first navigation and lets it through.
    settle(&mut session);
    fake.wait_for("navigation released", |r| r.iter().any(|(m, _)| m == "Fetch.continueRequest"));
    assert_eq!(fake.calls("Fetch.continueRequest"), vec![json!({"requestId": "nav-1"})]);

    let methods: Vec<String> = fake.methods().into_iter().filter(|m| m != "Runtime.evaluate").collect();
    let script = fake.calls("Page.addScriptToEvaluateOnNewDocument");
    assert_eq!(script.len(), 1);
    assert_eq!(
        script[0]["source"],
        json!(inject::render_bootstrap(inject::DEFAULT_TEMPLATE, &panel, Engine::Chromium))
    );
    assert!(script[0]["source"].as_str().unwrap().contains("allowedOrigin: \"https://dash.example.com\""));

    let navigate = position(&methods, "Page.navigate");
    for guard in [
        "Page.enable",
        "Page.addScriptToEvaluateOnNewDocument",
        "Network.enable",
        "Network.setBlockedURLs",
        "Page.setDownloadBehavior",
        "Fetch.enable",
    ] {
        assert!(position(&methods, guard) < navigate, "{guard} must precede the navigation: {methods:?}");
    }
    assert_eq!(fake.calls("Page.navigate"), vec![json!({"url": panel.effective_url()})]);
    assert_eq!(fake.calls("Network.enable"), vec![json!({"maxTotalBufferSize": 0, "maxResourceBufferSize": 0})]);
    assert!(
        fake.calls("Network.setBlockedURLs")[0]["urls"].as_array().unwrap().contains(&json!("*://doubleclick.net/*"))
    );
    assert_eq!(fake.calls("Page.setDownloadBehavior"), vec![json!({"behavior": "deny"})]);
    assert_eq!(
        fake.calls("Fetch.enable"),
        vec![
            json!({"handleAuthRequests": true, "patterns": [{"requestStage": "Request", "resourceType": "Document"}]})
        ]
    );
    // No Runtime.enable (console floods), and nothing but the poll is
    // evaluated: the placeholder page never gets the bootstrap run on it.
    assert!(!methods.iter().any(|m| m == "Runtime.enable"));
    assert_eq!(fake.evaluated(), vec![super::session::POLL_JS.to_string()]);
    assert!(logs(&events).iter().any(|l| l.contains("nav allowlist on")));
}

#[test]
fn resume_rearms_the_running_page_without_navigating() {
    let fake = FakeDevTools::start();
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (_session, _) = attach(&fake, &ctx, None, Attach::Resume);
    let methods = fake.methods();
    assert!(!methods.iter().any(|m| m == "Page.navigate"));
    assert_eq!(fake.evaluated(), vec![ctx.bootstrap.clone()], "the live document gets the (idempotent) bootstrap");
    assert!(methods.iter().any(|m| m == "Fetch.enable"));
}

#[test]
fn toggles_switch_individual_guards_off() {
    let fake = FakeDevTools::start();
    let mut panel = dash();
    panel.block_trackers = false;
    let mut ctx = ctx_for(&panel, &SecurityCfg { nav_allowlist: false, ..SecurityCfg::default() }, false);
    ctx.blocked_urls.clear();
    let (mut session, _) = attach(&fake, &ctx, None, Attach::Fresh);
    settle(&mut session);
    let methods = fake.methods();
    for off in ["Network.enable", "Network.setBlockedURLs", "Fetch.enable"] {
        assert!(!methods.iter().any(|m| m == off), "{off} should not be sent");
    }
    // Downloads stay denied and the page still loads.
    assert!(methods.iter().any(|m| m == "Page.setDownloadBehavior"));
    assert!(methods.iter().any(|m| m == "Page.navigate"));
}

#[test]
fn an_unconfigured_tile_stays_on_the_placeholder() {
    let fake = FakeDevTools::start();
    let ctx = ctx_for(&Panel::new("empty"), &SecurityCfg::default(), false);
    assert_eq!(ctx.target, None);
    let (mut session, _) = attach(&fake, &ctx, None, Attach::Fresh);
    settle(&mut session);
    assert!(!fake.methods().iter().any(|m| m == "Page.navigate"));
}

#[test]
fn a_navigation_gate_that_cannot_be_armed_fails_the_attach() {
    let fake = FakeDevTools::start();
    fake.fail_method("Fetch.enable");
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (_, sink) = collector();
    let guard = Guard::new("a", ctx.allowlist.clone(), None, sink);
    let result = Session::attach(&endpoint(&fake), &ctx, guard, Attach::Fresh, &fast(), no_cancel());
    assert!(matches!(result.err(), Some(CdpError::Remote(_))));
    assert!(!fake.methods().iter().any(|m| m == "Page.navigate"), "nothing may load unguarded");
}

#[test]
fn a_missing_optional_guard_degrades_with_a_log_line() {
    let fake = FakeDevTools::start();
    fake.fail_method("Network.setBlockedURLs");
    fake.fail_method("Inspector.enable");
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (mut session, events) = attach(&fake, &ctx, None, Attach::Fresh);
    settle(&mut session);
    assert!(logs(&events).iter().any(|l| l.contains("tracker block setup failed")));
    assert!(fake.methods().iter().any(|m| m == "Page.navigate"));
}

// --------------------------------------------------------------------------- //
// Login
// --------------------------------------------------------------------------- //

#[test]
fn login_round_trip() {
    let fake = FakeDevTools::start();
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (mut session, events) = attach(&fake, &ctx, None, Attach::Fresh);
    let (asked, fetch) = vault("alice", "p\"w</script>\u{2028}\\");
    let mut login = LoginState::default();

    // The page (through the real poll) says it is on its login form.
    fake.set_page(json!({"n": true, "l": false, "r": true, "e": false, "o": ORIGIN}));
    let st = session.poll().unwrap();
    assert_eq!(st, page(true, false, ORIGIN));
    fake.clear();
    assert!(!session.handle_login(&st, &ctx, &mut login, &fetch, Instant::now()).unwrap());
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    let expected = inject::guarded_login_call(ORIGIN, &Login::new("alice", "p\"w</script>\u{2028}\\")).unwrap();
    assert_eq!(fake.evaluated(), vec![expected.to_string()]);
    // The credentials travel as one JSON-escaped argument inside the origin check.
    let sent = &fake.evaluated()[0];
    assert!(sent.starts_with("if(window.location.origin===\"https://dash.example.com\"){try{window.socLogin"));
    assert!(sent.is_ascii() && !sent.contains("</script>"));
    assert_eq!(login.attempts, 1);
    // The journal names the attempt, never the credentials.
    let lines = logs(&events);
    assert!(lines.iter().any(|l| l == "[a] injected login (chromium, attempt 1)"));
    assert!(!lines.iter().any(|l| l.contains("alice") || l.contains("p\"w")));

    // The page reports success: the budget resets and the prompt is cleared.
    fake.clear();
    assert!(session.handle_login(&page(false, true, ORIGIN), &ctx, &mut login, &fetch, Instant::now()).unwrap());
    assert_eq!(login.attempts, 0);
    assert_eq!(
        fake.evaluated(),
        vec!["window.__SOC.justLoggedIn=false".to_string(), inject::prompt_clear_call().to_string()]
    );
    assert_eq!(asked.load(Ordering::Relaxed), 1);
}

#[test]
fn credentials_are_withheld_from_a_foreign_origin() {
    // The top frame ended up on an allow-listed but attacker-controllable SSO
    // tenant whose script raises needLogin (and may have replaced socLogin).
    let fake = FakeDevTools::start();
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (mut session, events) = attach(&fake, &ctx, None, Attach::Fresh);
    let (asked, fetch) = vault("alice", "hunter2");
    let mut login = LoginState::default();
    fake.clear();
    for origin in
        ["https://evil.auth0.com", "https://dash.example.com.evil.example", "http://dash.example.com", "null", ""]
    {
        let done = session.handle_login(&page(true, true, origin), &ctx, &mut login, &fetch, Instant::now()).unwrap();
        assert!(!done, "a foreign page cannot report a login as successful");
    }
    assert_eq!(asked.load(Ordering::Relaxed), 0, "the vault must not even be asked");
    assert_eq!(login.attempts, 0);
    let evaluated = fake.evaluated();
    assert!(!evaluated.iter().any(|e| e.contains("socLogin") || e.contains("hunter2")), "{evaluated:?}");
    assert!(evaluated.iter().any(|e| e.contains("socPrompt") && e.contains("not the panel's configured site")));
    let withheld: Vec<_> = logs(&events).into_iter().filter(|l| l.contains("credentials withheld")).collect();
    assert_eq!(withheld.len(), 5, "one line per foreign origin: {withheld:?}");
}

#[test]
fn a_panel_without_an_origin_never_gets_credentials() {
    let fake = FakeDevTools::start();
    let mut ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    ctx.origin = String::new();
    let (mut session, _) = attach(&fake, &ctx, None, Attach::Fresh);
    let (asked, fetch) = vault("alice", "hunter2");
    fake.clear();
    session.handle_login(&page(true, false, ""), &ctx, &mut LoginState::default(), &fetch, Instant::now()).unwrap();
    session.handle_login(&page(true, false, ORIGIN), &ctx, &mut LoginState::default(), &fetch, Instant::now()).unwrap();
    assert_eq!(asked.load(Ordering::Relaxed), 0);
    assert!(!fake.evaluated().iter().any(|e| e.contains("socLogin")));
}

#[test]
fn login_budget_runs_out_then_rearms_only_unattended() {
    let fake = FakeDevTools::start();
    let mut ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (mut session, events) = attach(&fake, &ctx, None, Attach::Fresh);
    let (asked, fetch) = vault("alice", "hunter2");
    let mut login = LoginState::default();
    let t0 = Instant::now();
    let need = page(true, false, ORIGIN);
    for _ in 0..MAX_LOGIN_ATTEMPTS + 3 {
        session.handle_login(&need, &ctx, &mut login, &fetch, t0).unwrap();
    }
    assert_eq!(asked.load(Ordering::Relaxed), MAX_LOGIN_ATTEMPTS, "only the budgeted attempts reach the vault");
    assert!(fake.evaluated().iter().any(|e| e.contains("Auto-login failed")));
    let asks = events.lock().unwrap().iter().filter(|e| **e == PanelEvent::SignInNeeded).count();
    assert_eq!(asks, 1, "the host is told once");

    // Attended: waiting changes nothing.
    session.handle_login(&need, &ctx, &mut login, &fetch, t0 + Duration::from_secs(7200)).unwrap();
    assert_eq!(asked.load(Ordering::Relaxed), MAX_LOGIN_ATTEMPTS);

    // Unattended: the first spent poll starts the wait, a later one refills.
    ctx.unattended = true;
    session.handle_login(&need, &ctx, &mut login, &fetch, t0).unwrap();
    session.handle_login(&need, &ctx, &mut login, &fetch, t0 + Duration::from_secs(299)).unwrap();
    assert_eq!(asked.load(Ordering::Relaxed), MAX_LOGIN_ATTEMPTS);
    session.handle_login(&need, &ctx, &mut login, &fetch, t0 + Duration::from_secs(301)).unwrap();
    assert_eq!(asked.load(Ordering::Relaxed), MAX_LOGIN_ATTEMPTS + 1);
    assert!(logs(&events).iter().any(|l| l.contains("login budget re-armed")));
}

#[test]
fn no_saved_login_shows_the_prompt() {
    let fake = FakeDevTools::start();
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (mut session, _) = attach(&fake, &ctx, None, Attach::Fresh);
    let none: LoginFn = Arc::new(|_panel: &Panel| None);
    fake.clear();
    session.handle_login(&page(true, false, ORIGIN), &ctx, &mut LoginState::default(), &none, Instant::now()).unwrap();
    let evaluated = fake.evaluated();
    assert_eq!(evaluated.len(), 1);
    assert!(evaluated[0].contains("socPrompt") && evaluated[0].contains("no saved login"));
}

// --------------------------------------------------------------------------- //
// Navigation gate
// --------------------------------------------------------------------------- //

fn paused(rid: &str, url: &str, kind: &str) -> Value {
    json!({"requestId": rid, "resourceType": kind, "request": {"url": url}})
}

#[test]
fn off_allowlist_navigation_is_blocked() {
    let fake = FakeDevTools::start();
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), false);
    let (mut session, events) = attach(&fake, &ctx, None, Attach::Fresh);
    settle(&mut session);
    fake.wait_for("navigation released", |r| r.iter().any(|(m, _)| m == "Fetch.continueRequest"));
    fake.clear();
    fake.push_event("Fetch.requestPaused", paused("evil", "https://evil.example/steal?session=abc123", "Document"));
    fake.push_event("Fetch.requestPaused", paused("own", "https://dash.example.com/next", "Document"));
    fake.push_event("Fetch.requestPaused", paused("sso", "https://accounts.google.com/o/oauth2", "Document"));
    fake.push_event("Fetch.requestPaused", paused("cdn", "https://cdn.other.net/lib.js", "Script"));
    fake.push_event("Fetch.requestPaused", paused("file", "file:///etc/passwd", "Document"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while fake.methods().len() < 5 {
        assert!(Instant::now() < deadline, "only {:?} answered", fake.methods());
        session.pump(Instant::now() + ms(20)).unwrap();
    }
    assert_eq!(
        fake.calls("Fetch.failRequest"),
        vec![
            json!({"requestId": "evil", "errorReason": "BlockedByClient"}),
            json!({"requestId": "file", "errorReason": "BlockedByClient"}),
        ]
    );
    // Own origin, bundled SSO and an off-allowlist sub-resource all continue.
    assert_eq!(
        fake.calls("Fetch.continueRequest"),
        vec![json!({"requestId": "own"}), json!({"requestId": "sso"}), json!({"requestId": "cdn"})]
    );
    let events = events.lock().unwrap();
    assert!(events.contains(&PanelEvent::NavBlocked("https://evil.example/…".into())));
    // The refused URL's path and query (which may hold a token) are not journalled.
    assert!(!events.iter().any(|e| matches!(e, PanelEvent::Log(l) if l.contains("abc123") || l.contains("steal"))));
}

#[test]
fn navigation_events_wake_a_settled_poll() {
    let (_, sink) = collector();
    let mut guard = Guard::new("a", None, None, sink);
    let mut out = Outbox::default();
    guard.on_event("Page.frameNavigated", &json!({"frame": {"id": "M"}}), &mut out);
    assert!(guard.activity);
    // A sub-frame navigating afterwards must not cancel the wake-up.
    guard.on_event("Page.frameNavigated", &json!({"frame": {"id": "C", "parentId": "M"}}), &mut out);
    assert!(guard.activity);
    guard.activity = false;
    guard.on_event("Page.frameNavigated", &json!({"frame": {"id": "C", "parentId": "M"}}), &mut out);
    assert!(!guard.activity);
    guard.on_event("Inspector.targetCrashed", &json!({}), &mut out);
    assert!(guard.activity && guard.crashed);
    // With the gate off, a paused document simply continues.
    guard.on_event("Fetch.requestPaused", &paused("r1", "https://evil.example/", "Document"), &mut out);
    assert_eq!(out.drain(), vec![("Fetch.continueRequest", json!({"requestId": "r1"}))]);
}

// --------------------------------------------------------------------------- //
// Proxy authentication
// --------------------------------------------------------------------------- //

fn proxy_auth(login: Option<ProxyLoginFn>) -> ProxyAuth {
    ProxyAuth::new("http://proxy.corp:3128", "SOC Proxy", login, false)
}

fn challenge(rid: &str, source: &str, origin: &str) -> Value {
    json!({"requestId": rid, "authChallenge": {"source": source, "origin": origin, "scheme": "basic", "realm": "r"}})
}

#[test]
fn proxy_challenge_is_answered_from_the_vault() {
    let fake = FakeDevTools::start();
    fake.proxy(true, false);
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), true);
    let (asked, fetch) = proxy_vault();
    let (_session, events) = attach(&fake, &ctx, Some(proxy_auth(Some(fetch))), Attach::Fresh);

    let answers = fake.calls("Fetch.continueWithAuth");
    assert_eq!(
        answers,
        vec![json!({"requestId": "nav-1", "authChallengeResponse": {
            "response": "ProvideCredentials", "username": "svc-proxy", "password": "pr0xy\"pw"}})]
    );
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    // All requests are intercepted for the auth window, then only documents.
    let enables = fake.calls("Fetch.enable");
    assert_eq!(enables[0], json!({"handleAuthRequests": true}));
    assert_eq!(enables[1]["patterns"], json!([{"requestStage": "Request", "resourceType": "Document"}]));
    let methods = fake.methods();
    assert!(position(&methods, "Fetch.enable") < position(&methods, "Page.navigate"));
    // The journal names the vault item, never the password.
    let lines = logs(&events);
    assert!(lines.iter().any(|l| l.contains("proxy auth answered (vault item 'SOC Proxy')")));
    assert!(!lines.iter().any(|l| l.contains("pr0xy")));
}

#[test]
fn rejected_proxy_credentials_are_held_after_three_answers() {
    let fake = FakeDevTools::start();
    fake.proxy(true, true);
    let ctx = ctx_for(&dash(), &SecurityCfg::default(), true);
    let (asked, fetch) = proxy_vault();
    let (mut session, events) = attach(&fake, &ctx, Some(proxy_auth(Some(fetch))), Attach::Fresh);

    let responses: Vec<String> = fake
        .calls("Fetch.continueWithAuth")
        .iter()
        .map(|p| p["authChallengeResponse"]["response"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(responses, ["ProvideCredentials", "ProvideCredentials", "ProvideCredentials", "CancelAuth"]);
    assert_eq!(asked.load(Ordering::Relaxed), PROXY_AUTH_MAX_ATTEMPTS);
    assert!(session.guard.proxy_held());
    assert!(logs(&events).iter().any(|l| l.contains("rejected the credentials") && l.contains("giving up")));

    // A later challenge is cancelled without touching the vault or the proxy again.
    fake.clear();
    fake.push_event("Fetch.authRequired", challenge("late", "Proxy", "http://proxy.corp:3128"));
    while fake.calls("Fetch.continueWithAuth").is_empty() {
        session.pump(Instant::now() + ms(20)).unwrap();
    }
    assert_eq!(
        fake.calls("Fetch.continueWithAuth"),
        vec![json!({"requestId": "late", "authChallengeResponse": {"response": "CancelAuth"}})]
    );
    assert_eq!(asked.load(Ordering::Relaxed), PROXY_AUTH_MAX_ATTEMPTS);

    // An operator-requested reload gives the (possibly corrected) vault entry a new chance.
    session.guard.proxy_reset();
    assert!(!session.guard.proxy_held());
}

fn auth_response(guard: &mut Guard, params: &Value) -> Value {
    let mut out = Outbox::default();
    guard.on_event("Fetch.authRequired", params, &mut out);
    let mut sent = out.drain();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "Fetch.continueWithAuth");
    sent.remove(0).1["authChallengeResponse"].take()
}

#[test]
fn only_the_configured_proxy_is_answered() {
    let (asked, fetch) = proxy_vault();
    let (events, sink) = collector();
    let mut guard = Guard::new("a", None, Some(proxy_auth(Some(fetch))), sink);
    // A site's own HTTP auth is not ours to answer.
    assert_eq!(
        auth_response(&mut guard, &challenge("s", "Server", "https://dash.example.com")),
        json!({"response": "Default"})
    );
    // A "proxy" challenge naming another authority gets nothing.
    for foreign in ["http://evil.example:3128", "http://proxy.corp:9999", "evil.example:3128"] {
        assert_eq!(auth_response(&mut guard, &challenge("f", "Proxy", foreign)), json!({"response": "CancelAuth"}));
    }
    assert_eq!(asked.load(Ordering::Relaxed), 0);
    assert!(logs(&events).iter().any(|l| l.contains("not the configured proxy")));
    // The configured one, in the spellings a browser may report it.
    for (i, ours) in ["http://proxy.corp:3128", "proxy.corp:3128", "http://PROXY.corp:3128/"].iter().enumerate() {
        let response = auth_response(&mut guard, &challenge(&format!("ok{i}"), "Proxy", ours));
        assert_eq!(response["response"], "ProvideCredentials", "{ours}");
        assert_eq!(response["username"], "svc-proxy");
    }
    assert_eq!(asked.load(Ordering::Relaxed), 3);
    assert!(!guard.proxy_held(), "distinct requests challenged once each are not rejections");
}

#[test]
fn proxy_auth_without_usable_credentials_cancels() {
    let (_, sink) = collector();
    // The vault has no answer right now (locked): cancel, but do not give up.
    let locked: ProxyLoginFn = Arc::new(|| None);
    let mut guard = Guard::new("a", None, Some(proxy_auth(Some(locked))), sink.clone());
    let response = auth_response(&mut guard, &challenge("r", "Proxy", "http://proxy.corp:3128"));
    assert_eq!(response, json!({"response": "CancelAuth"}));
    assert!(!guard.proxy_held());
    // No credential source at all: held from the first challenge.
    let mut guard = Guard::new("a", None, Some(proxy_auth(None)), sink.clone());
    assert_eq!(auth_response(&mut guard, &challenge("r", "Proxy", "http://proxy.corp:3128"))["response"], "CancelAuth");
    assert!(guard.proxy_held());
    // A panel that is not behind an authenticating proxy never answers.
    let mut guard = Guard::new("a", None, None, sink);
    assert_eq!(auth_response(&mut guard, &challenge("r", "Proxy", "http://proxy.corp:3128"))["response"], "CancelAuth");
}

// --------------------------------------------------------------------------- //
// The panel: process supervision around the session
// --------------------------------------------------------------------------- //

#[derive(Default)]
struct FakeLauncher {
    fail: AtomicBool,
    launches: AtomicU32,
    argv: Mutex<Vec<Vec<String>>>,
    alive: Mutex<Vec<Arc<AtomicBool>>>,
}

struct FakeBrowser(Arc<AtomicBool>);

impl Browser for FakeBrowser {
    fn pid(&self) -> u32 {
        4242
    }
    fn exited(&mut self) -> Option<i32> {
        (!self.0.load(Ordering::Relaxed)).then_some(0)
    }
    fn terminate(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
    fn kill(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

impl Launcher for FakeLauncher {
    fn launch(&self, argv: &[String]) -> std::io::Result<Box<dyn Browser>> {
        self.launches.fetch_add(1, Ordering::Relaxed);
        self.argv.lock().unwrap().push(argv.to_vec());
        if self.fail.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("no chromium here"));
        }
        let alive = Arc::new(AtomicBool::new(true));
        self.alive.lock().unwrap().push(alive.clone());
        Ok(Box::new(FakeBrowser(alive)))
    }
}

struct Rig {
    panel: ChromiumPanel,
    launcher: Arc<FakeLauncher>,
    events: Events,
    asked: Arc<AtomicU32>,
    dir: PathBuf,
}

impl Rig {
    fn new(tag: &str, panel: Panel, port: Option<u16>, tweak: impl FnOnce(&mut ChromiumOptions)) -> Rig {
        let dir = std::env::temp_dir().join(format!("soc-web-panel-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let launcher = Arc::new(FakeLauncher::default());
        let mut opts = ChromiumOptions::new(dir.join("webdata"));
        opts.binary = Some(PathBuf::from("/usr/bin/chromium"));
        opts.cdp_port = port;
        opts.timing = fast();
        opts.launcher = launcher.clone();
        tweak(&mut opts);
        let (events, on_event) = collector();
        let (asked, login) = vault("alice", "hunter2");
        let hooks = PanelHooks { on_event, login, proxy_login: None };
        Rig { panel: ChromiumPanel::new(panel, opts, hooks), launcher, events, asked, dir }
    }

    fn statuses(&self) -> Vec<PanelStatus> {
        let events = self.events.lock().unwrap();
        events.iter().filter_map(|e| if let PanelEvent::Status(s) = e { Some(s.clone()) } else { None }).collect()
    }

    fn launches(&self) -> u32 {
        self.launcher.launches.load(Ordering::Relaxed)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.panel.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn panel_loads_logs_in_and_stops() {
    let fake = FakeDevTools::start();
    let rig = Rig::new("e2e", dash(), Some(fake.port), |_| {});
    rig.panel.start();
    rig.panel.start(); // idempotent
    fake.wait_for("first navigation", |r| r.iter().any(|(m, _)| m == "Page.navigate"));
    assert!(rig.statuses().contains(&PanelStatus::Connecting));
    assert_eq!(rig.panel.pid(), Some(4242));
    assert!(!rig.panel.loaded_ok());

    // The browser was started on the placeholder with the fixed test port.
    let argv = rig.launcher.argv.lock().unwrap()[0].clone();
    assert!(argv.contains(&format!("--remote-debugging-port={}", fake.port)));
    assert!(argv.contains(&format!("--app={UNCONFIGURED_URL}")));
    assert!(!argv.iter().any(|a| a.contains("s3cret") || a.contains("hunter2")));
    assert!(argv.iter().any(|a| a.starts_with("--user-data-dir=") && a.ends_with("/webdata/chromium/a")));
    // Every level down to the profile is private to this user.
    use std::os::unix::fs::PermissionsExt;
    for dir in ["webdata", "webdata/chromium", "webdata/chromium/a"] {
        let mode = std::fs::metadata(rig.dir.join(dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{dir}");
    }

    fake.set_page(json!({"n": false, "l": false, "r": true, "e": false, "o": ORIGIN}));
    wait_until("online", || rig.panel.loaded_ok() && rig.statuses().contains(&PanelStatus::Online));

    // The session expires: the page asks, the host answers once per poll.
    fake.set_page(json!({"n": true, "l": false, "r": true, "e": false, "o": ORIGIN}));
    wait_until("login injected", || {
        fake.evaluated().iter().any(|e| e.contains("window.socLogin({\"user\": \"alice\""))
    });
    fake.set_page(json!({"n": false, "l": true, "r": true, "e": false, "o": ORIGIN}));
    wait_until("login acknowledged", || rig.events.lock().unwrap().contains(&PanelEvent::LoginSucceeded));
    assert!(rig.asked.load(Ordering::Relaxed) >= 1);

    // The error page is reported as offline.
    fake.set_page(json!({"n": false, "l": false, "r": false, "e": true, "o": "null"}));
    wait_until("offline", || rig.statuses().contains(&PanelStatus::Offline { retry_in: None }));
    assert!(!rig.panel.loaded_ok());

    rig.panel.stop();
    assert_eq!(rig.statuses().last(), Some(&PanelStatus::Stopped));
    assert!(!rig.launcher.alive.lock().unwrap()[0].load(Ordering::Relaxed), "the browser must be terminated");
    assert_eq!(rig.panel.pid(), None);
    assert_eq!(rig.launches(), 1);
    // Nothing secret reached the journal.
    assert!(!logs(&rig.events).iter().any(|l| l.contains("hunter2") || l.contains("s3cret")));
}

#[test]
fn panel_parks_after_max_respawns_and_set_url_rearms_it() {
    let rig = Rig::new("park", dash(), Some(1), |o| o.max_respawns = 3);
    rig.launcher.fail.store(true, Ordering::Relaxed);
    rig.panel.start();
    wait_until("park", || rig.panel.is_parked());
    assert_eq!(rig.launches(), 3, "exactly max_respawns attempts");
    std::thread::sleep(ms(150));
    assert_eq!(rig.launches(), 3, "a parked panel must not keep respawning");
    assert!(logs(&rig.events).iter().any(|l| l.contains("parked after 3 consecutive failures")));
    assert!(matches!(rig.statuses().last(), Some(PanelStatus::Parked { retry_in: None, .. })));
    // The delays grew while it was failing.
    let delays: Vec<Duration> = rig
        .statuses()
        .iter()
        .filter_map(|s| if let PanelStatus::Recovering { retry_in, .. } = s { Some(*retry_in) } else { None })
        .collect();
    assert_eq!(delays, [ms(20), ms(40)]);

    // A bad URL is refused and must not silently re-arm the panel.
    assert!(matches!(rig.panel.set_url("file:///etc/passwd"), Err(Error::Refused(_))));
    assert!(rig.panel.set_url("http://user:hunter2@10.0.0.1/").is_err());
    assert!(rig.panel.is_parked());
    assert!(logs(&rig.events).iter().any(|l| l.contains("refusing non-http")));
    assert!(!logs(&rig.events).iter().any(|l| l.contains("hunter2")));
    assert_eq!(rig.launches(), 3);

    // A good one clears the park and the failure streak.
    rig.panel.set_url("http://10.0.0.1:9999/new").unwrap();
    assert_eq!(rig.panel.panel().url.as_deref(), Some("http://10.0.0.1:9999/new"));
    wait_until("respawn after set_url", || rig.launches() > 3);
    wait_until("park again", || rig.launches() == 6 && rig.panel.is_parked());
}

#[test]
fn attach_failure_backs_off_instead_of_spinning() {
    // The browser starts but its DevTools endpoint never comes up.
    let rig = Rig::new("attach", dash(), Some(1), |o| {
        o.timing.attach_timeout = ms(30);
        o.max_respawns = 4;
    });
    rig.panel.start();
    wait_until("park", || rig.panel.is_parked());
    assert_eq!(rig.launches(), 4);
    let delays: Vec<Duration> = rig
        .statuses()
        .iter()
        .filter_map(|s| if let PanelStatus::Recovering { retry_in, .. } = s { Some(*retry_in) } else { None })
        .collect();
    assert_eq!(delays, [ms(20), ms(40), ms(80)], "the delay doubles up to the cap");
    // Each browser that could not be driven was reaped.
    assert!(rig.launcher.alive.lock().unwrap().iter().all(|a| !a.load(Ordering::Relaxed)));
}

#[test]
fn panel_reattaches_after_a_lost_socket() {
    let fake = FakeDevTools::start();
    let rig = Rig::new("reattach", dash(), Some(fake.port), |_| {});
    fake.set_page(json!({"n": false, "l": false, "r": true, "e": false, "o": ORIGIN}));
    rig.panel.start();
    wait_until("online", || rig.panel.loaded_ok());
    fake.drop_connection();
    wait_until("second session", || {
        fake.connections() == 2 && fake.calls("Page.addScriptToEvaluateOnNewDocument").len() == 2
    });
    wait_until("online again", || rig.panel.loaded_ok());
    assert_eq!(fake.calls("Page.navigate").len(), 1, "the running page is kept, not reloaded");
    assert_eq!(rig.launches(), 1, "the browser was not restarted");
    assert!(logs(&rig.events).iter().any(|l| l.contains("reattaching")));
}

#[test]
fn a_dead_browser_is_restarted_and_reload_renavigates() {
    let fake = FakeDevTools::start();
    let rig = Rig::new("restart", dash(), Some(fake.port), |_| {});
    fake.set_page(json!({"n": false, "l": false, "r": true, "e": false, "o": ORIGIN}));
    rig.panel.start();
    wait_until("online", || rig.panel.loaded_ok());

    rig.panel.reload();
    wait_until("reload", || fake.calls("Page.navigate").len() == 2);
    assert_eq!(rig.launches(), 1);

    // The process dies underneath us.
    rig.launcher.alive.lock().unwrap()[0].store(false, Ordering::Relaxed);
    wait_until("restart", || rig.launches() == 2 && rig.panel.loaded_ok());
    assert!(
        rig.statuses().iter().any(|s| matches!(s, PanelStatus::Recovering { reason, .. } if reason.contains("exited")))
    );

    // A commanded recycle restarts without waiting out a backoff.
    rig.panel.recycle();
    wait_until("recycle", || rig.launches() == 3 && rig.panel.loaded_ok());
}

#[test]
fn a_crashed_renderer_restarts_the_browser_after_a_backoff() {
    let fake = FakeDevTools::start();
    let rig = Rig::new("crash", dash(), Some(fake.port), |_| {});
    fake.set_page(json!({"n": false, "l": false, "r": true, "e": false, "o": ORIGIN}));
    rig.panel.start();
    wait_until("online", || rig.panel.loaded_ok());
    fake.push_event("Inspector.targetCrashed", json!({}));
    wait_until("restart", || rig.launches() == 2 && rig.panel.loaded_ok());
    let crashed = PanelStatus::Recovering { reason: "crashed".into(), retry_in: ms(20) };
    assert!(rig.statuses().contains(&crashed), "{:?}", rig.statuses());
    assert!(!rig.launcher.alive.lock().unwrap()[0].load(Ordering::Relaxed), "the crashed browser was reaped");
}

#[test]
fn unattended_wall_never_gives_up() {
    // A park is only a long pause ...
    let rig = Rig::new("unattended-park", dash(), Some(1), |o| {
        o.unattended = true;
        o.max_respawns = 2;
        o.timing.park_retry = ms(60);
    });
    rig.launcher.fail.store(true, Ordering::Relaxed);
    rig.panel.start();
    wait_until("park", || rig.panel.is_parked());
    assert!(rig.statuses().iter().any(|s| matches!(s, PanelStatus::Parked { retry_in: Some(d), .. } if *d == ms(60))));
    wait_until("park expiry", || rig.launches() >= 4);
    assert!(logs(&rig.events).iter().any(|l| l.contains("park expired")));
    drop(rig);

    // ... and a page stuck on the error page is re-requested on a growing delay.
    let fake = FakeDevTools::start();
    let rig = Rig::new("unattended-reload", dash(), Some(fake.port), |o| o.unattended = true);
    fake.set_page(json!({"n": false, "l": false, "r": false, "e": true, "o": "null"}));
    rig.panel.start();
    wait_until("re-navigation", || fake.calls("Page.navigate").len() >= 3);
    let offline: Vec<Duration> = rig
        .statuses()
        .iter()
        .filter_map(|s| if let PanelStatus::Offline { retry_in } = s { *retry_in } else { None })
        .collect();
    assert_eq!(&offline[..2], [ms(20), ms(40)], "{offline:?}");
    assert!(!rig.panel.loaded_ok());
    assert_eq!(rig.launches(), 1, "the healthy browser is kept");
}

#[test]
fn calibration_runs_on_the_control_thread() {
    let fake = FakeDevTools::start();
    let rig = Rig::new("calib", dash(), Some(fake.port), |_| {});
    // Not running yet: the request is answered at once.
    let early: Arc<Mutex<Option<Option<soc_core::Dict>>>> = Arc::default();
    let slot = early.clone();
    rig.panel.calibrate(move |zones| *slot.lock().unwrap() = Some(zones));
    assert_eq!(*early.lock().unwrap(), Some(None));

    fake.set_page(json!({"n": false, "l": false, "r": true, "e": false, "o": ORIGIN, "calibrate": ""}));
    rig.panel.start();
    wait_until("online", || rig.panel.loaded_ok());
    let result: Arc<Mutex<Option<Option<soc_core::Dict>>>> = Arc::default();
    let slot = result.clone();
    rig.panel.calibrate(move |zones| *slot.lock().unwrap() = Some(zones));
    wait_until("overlay injected", || fake.evaluated().iter().any(|e| e == inject::DEFAULT_CALIBRATE));
    assert!(result.lock().unwrap().is_none(), "still waiting for the operator's clicks");
    fake.set_page(json!({
        "n": false, "l": false, "r": true, "e": false, "o": ORIGIN,
        "calibrate": "{\"user\":{\"x_pct\":0.5,\"y_pct\":0.4},\"pass\":{\"x_pct\":0.5,\"y_pct\":0.5}}",
    }));
    wait_until("zones", || result.lock().unwrap().is_some());
    let zones = result.lock().unwrap().clone().unwrap().unwrap();
    assert_eq!(zones.get("user"), Some(&json!({"x_pct": 0.5, "y_pct": 0.4})));
    assert!(fake.evaluated().iter().any(|e| e == inject::CALIBRATE_CLEAR_JS));
    assert!(logs(&rig.events).iter().any(|l| l == "[a] calibrate: captured [pass, user]"));
}

#[test]
fn hooks_from_the_vault_resolve_and_remember_logins() {
    let dir = std::env::temp_dir().join(format!("soc-web-hooks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let memory = Arc::new(LoginMemory::new(&dir));
    let mut creds = soc_core::creds::StaticCreds::default();
    creds.logins.insert("Dash".into(), ("alice".into(), "hunter2".into()));
    creds.logins.insert("SOC Proxy".into(), ("svc".into(), "pw".into()));
    let (events, on_event) = collector();
    let hooks = PanelHooks::from_vault(Arc::new(creds), Some(memory.clone()), "SOC Proxy", on_event);

    // A panel with its own item logs in and registers its origin ...
    let login = (hooks.login)(&dash()).unwrap();
    assert_eq!((login.username.as_str(), login.password.as_str()), ("alice", "hunter2"));
    assert_eq!(memory.vault_item_for("https://dash.example.com/elsewhere"), "Dash");
    // ... so a display-only panel pointed at the same origin reuses it,
    let mut other = Panel::new("b");
    other.url = Some("https://dash.example.com/other".into());
    assert!((hooks.login)(&other).is_some());
    // while one at an unknown origin gets nothing.
    other.url = Some("https://unknown.example/".into());
    assert!((hooks.login)(&other).is_none());
    // A missing vault item is logged, not fatal.
    let mut missing = dash();
    missing.vault_item = "Nope".into();
    assert!((hooks.login)(&missing).is_none());
    assert!(logs(&events).iter().any(|l| l.starts_with("[a] vault:")));
    assert_eq!(hooks.proxy_login.as_ref().and_then(|f| f()).map(|l| l.username.clone()), Some("svc".into()));
    assert!(
        PanelHooks::from_vault(Arc::new(soc_core::creds::StaticCreds::default()), None, "", hooks.on_event.clone())
            .proxy_login
            .is_none()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn status_cards_for_every_state() {
    let s = Duration::from_secs;
    assert_eq!(PanelStatus::Online.card("p"), None);
    assert_eq!(PanelStatus::Stopped.card("p"), None);
    assert!(PanelStatus::Connecting.card("p").unwrap().busy);
    assert!(!PanelStatus::Unconfigured.card("p").unwrap().error);
    let card = PanelStatus::Recovering { reason: "exited (11)".into(), retry_in: s(10) }.card("p").unwrap();
    assert_eq!(card.message, "renderer exited (11) — recovering in 10s");
    assert!(PanelStatus::Offline { retry_in: Some(s(5)) }.card("p").unwrap().message.contains("retrying in 5s"));
    assert!(PanelStatus::Offline { retry_in: None }.card("p").unwrap().error);
    assert!(PanelStatus::Parked { reason: "x".into(), retry_in: None }.card("p").unwrap().message.contains("Settings"));
    assert!(
        PanelStatus::Parked { reason: "x".into(), retry_in: Some(s(600)) }.card("p").unwrap().message.contains("600s")
    );
    assert!(PanelStatus::ProxyAuthFailed.card("p").unwrap().message.contains("proxy authentication failed"));
}

#[test]
fn backoff_doubles_to_the_cap_and_resets() {
    let mut b = Backoff::new(ms(5000), ms(60_000));
    let seen: Vec<u64> = (0..6).map(|_| b.next_delay().as_secs()).collect();
    assert_eq!(seen, [5, 10, 20, 40, 60, 60]);
    b.reset();
    assert_eq!(b.next_delay(), ms(5000));
}

#[test]
fn proxied_panel_keeps_credentials_off_argv_and_out_of_the_url() {
    let fake = FakeDevTools::start();
    fake.proxy(true, false);
    let proxy = ProxyCfg {
        enabled: true,
        url: "http://proxy.corp:3128".into(),
        vault_item: "SOC Proxy".into(),
        ignore_hosts: vec![],
    };
    let (asked, fetch) = proxy_vault();
    let mut rig = Rig::new("proxy", dash(), Some(fake.port), |o| o.proxy = Some(proxy));
    rig.panel.hooks.proxy_login = Some(fetch);
    rig.panel.start();
    fake.wait_for("proxy answer", |r| r.iter().any(|(m, _)| m == "Fetch.continueWithAuth"));
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    let argv = rig.launcher.argv.lock().unwrap()[0].clone();
    assert!(argv.contains(&"--proxy-server=http://proxy.corp:3128".to_string()));
    assert!(!argv.iter().any(|a| a.contains("pr0xy") || a.contains("svc-proxy") || a.contains("SOC Proxy")));
    rig.panel.stop();
    assert!(!logs(&rig.events).iter().any(|l| l.contains("pr0xy")));
}
