//! The JavaScript injected into each panel.
//!
//! * [`bootstrap_js`] — the credential-free login / keep-alive bootstrap,
//!   rendered from `inject/login.js.tmpl`. Byte-identical to the Python
//!   renderer for the same panel (see `tests/parity.rs`).
//! * [`login_call`] / [`guarded_login_call`] — the just-in-time `socLogin(...)`
//!   call that carries real credentials.
//! * [`prompt_call`], the calibration snippets and [`LoginRearm`].
//!
//! Every value is substituted as a JSON literal, so a selector containing
//! quotes cannot break out of its string.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;
use soc_core::url::Url;
use soc_core::{Dict, Engine, Login, Panel};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::pyjson;

/// The login bootstrap template shipped with the wall.
pub const DEFAULT_TEMPLATE: &str = include_str!("../../../../inject/login.js.tmpl");

/// The click-zone calibration overlay shipped with the wall.
pub const DEFAULT_CALIBRATE: &str = include_str!("../../../../inject/calibrate.js.tmpl");

/// Environment variable that relocates the login template (and, beside it,
/// `calibrate.js.tmpl`).
pub const TEMPLATE_ENV: &str = "SOC_INJECT_TMPL";

const CALIBRATE_BASENAME: &str = "calibrate.js.tmpl";

/// Minimal idempotent bootstrap used when an overriding template cannot be
/// read. It installs `window.__SOC` with `needLogin:false`, so no auto-login
/// fires: a wall that renders without logging in beats a dark one.
pub const FALLBACK_BOOTSTRAP: &str = "(function(){if(window.__SOC&&window.__SOC.installed)return;\
window.__SOC={installed:true,needLogin:false,justLoggedIn:false,lastLogin:0};})();";

/// The overlay leaves its result in this page global as a JSON string.
pub const CALIBRATE_POLL_JS: &str = "window.__SOC_CALIBRATE_RESULT||''";
pub const CALIBRATE_CLEAR_JS: &str = "window.__SOC_CALIBRATE_RESULT=null;";
pub const CALIBRATE_ABORT_JS: &str = "try{document.getElementById('__soc_calibrate').remove();}\
catch(e){}window.__SOC_CALIBRATE_ACTIVE=false;window.__SOC_CALIBRATE_RESULT=null;";

const ZONE_KEYS: [&str; 3] = ["user", "pass", "submit"];

// --------------------------------------------------------------------------- //
// Templates
// --------------------------------------------------------------------------- //

/// The bootstrap template: the embedded one, or the file `override_path`
/// names. A set-but-unreadable override is an error — the caller decides how
/// to degrade (see [`template`]).
pub fn load_template(override_path: Option<&Path>) -> Result<Cow<'static, str>, Error> {
    match override_path {
        None => Ok(Cow::Borrowed(DEFAULT_TEMPLATE)),
        Some(path) => std::fs::read_to_string(path)
            .map(Cow::Owned)
            .map_err(|e| Error::io(format!("login bootstrap template {}", path.display()), e)),
    }
}

/// The calibration overlay: embedded, or `calibrate.js.tmpl` beside the
/// overriding login template (so one variable relocates both).
pub fn load_calibrate(override_path: Option<&Path>) -> Result<Cow<'static, str>, Error> {
    match override_path {
        None => Ok(Cow::Borrowed(DEFAULT_CALIBRATE)),
        Some(path) => {
            let beside = path.parent().unwrap_or(Path::new("")).join(CALIBRATE_BASENAME);
            std::fs::read_to_string(&beside)
                .map(Cow::Owned)
                .map_err(|e| Error::io(format!("calibrate template {}", beside.display()), e))
        }
    }
}

fn override_path() -> Option<PathBuf> {
    soc_core::env::env_str(TEMPLATE_ENV).map(PathBuf::from)
}

/// The process-wide bootstrap template, honouring `$SOC_INJECT_TMPL`. Read
/// once. An unreadable override is reported loudly and replaced by
/// [`FALLBACK_BOOTSTRAP`]: panels then render without auto-login instead of
/// the wall going dark.
pub fn template() -> &'static str {
    static TEMPLATE: OnceLock<String> = OnceLock::new();
    TEMPLATE.get_or_init(|| match load_template(override_path().as_deref()) {
        Ok(t) => t.into_owned(),
        Err(e) => {
            eprintln!("[soc-inject] {e} ({TEMPLATE_ENV}); panels render WITHOUT auto-login");
            FALLBACK_BOOTSTRAP.to_string()
        }
    })
}

/// The calibration overlay, honouring `$SOC_INJECT_TMPL`. Read on each use
/// (calibration is rare); a missing override file is reported to the operator.
pub fn calibrate_js() -> Result<Cow<'static, str>, Error> {
    load_calibrate(override_path().as_deref())
}

// --------------------------------------------------------------------------- //
// Origin gate
// --------------------------------------------------------------------------- //

/// Browser-style origin (`scheme://host[:port]`, default ports omitted) of a
/// panel's effective URL — what the template compares `location.origin` to.
/// `""` when none can be derived (not http(s), no host, malformed).
///
/// Deliberately the same derivation as the Python wall, because the value is
/// rendered into the shared template. Two inherited defects follow from that
/// and are pinned by tests rather than fixed silently: an IPv6 host is not
/// re-bracketed and an IDN host is not punycoded, so such panels never match
/// `location.origin` and auto-login stays off for them (fail closed).
pub fn panel_origin(url: &str) -> String {
    // Python's urlsplit drops leading C0/space and embedded tab/CR/LF.
    let cleaned: String =
        url.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect();
    let Ok(parts) = Url::split(&cleaned) else {
        return String::new();
    };
    if !matches!(parts.scheme.as_str(), "http" | "https") {
        return String::new();
    }
    let Some(host) = parts.host.as_deref() else {
        return String::new();
    };
    if parts.netloc.contains('[') && !crate::siteguard::is_ipv6_literal(host) {
        return String::new();
    }
    let host = host.to_lowercase();
    let default = if parts.scheme == "https" { 443 } else { 80 };
    match parts.port {
        Some(port) if port != 0 && port != default => format!("{}://{host}:{port}", parts.scheme),
        _ => format!("{}://{host}", parts.scheme),
    }
}

/// The origin credentials may be released to for `panel`; `""` when the panel
/// has none.
pub fn allowed_origin(panel: &Panel) -> String {
    panel_origin(&panel.effective_url())
}

// --------------------------------------------------------------------------- //
// Bootstrap
// --------------------------------------------------------------------------- //

/// The panel's login zones reduced to the known keys with in-range numeric
/// ratios. Config validation already rejects bad zones, but zones are also
/// changed at runtime (calibration, a hand-edited override) and are rendered
/// straight into page JS, so they are filtered again here.
pub fn safe_zones(raw: &Dict) -> Dict {
    let mut zones = Dict::new();
    for key in ZONE_KEYS {
        let Some(zone) = raw.get(key).and_then(Value::as_object) else {
            continue;
        };
        let ratio = |axis: &str| match zone.get(axis) {
            Some(Value::Number(n)) => n.as_f64().filter(|f| (0.0..=1.0).contains(f)),
            _ => None,
        };
        if let (Some(x), Some(y)) = (ratio("x_pct"), ratio("y_pct")) {
            let mut entry = Dict::new();
            entry.insert("x_pct".into(), Value::from(x));
            entry.insert("y_pct".into(), Value::from(y));
            zones.insert(key.into(), Value::Object(entry));
        }
    }
    zones
}

fn keepalive_json(panel: &Panel) -> String {
    let ka = &panel.keepalive;
    let mut map = Dict::new();
    map.insert("strategy".into(), Value::from(ka.strategy.as_str()));
    map.insert("intervalSec".into(), Value::from(ka.interval_sec));
    for (key, value) in [("url", &ka.url), ("target", &ka.target)] {
        if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
            map.insert(key.into(), Value::from(v));
        }
    }
    pyjson::dumps(&Value::Object(map))
}

/// Render `template` for `panel`. Pure: no environment, no I/O.
///
/// The tokens are replaced one after another over the evolving text, exactly
/// as the Python renderer does. (That means a configured value that itself
/// contains `{{KEEPALIVE_JSON}}` or `{{LOGIN_ZONES_JSON}}` is expanded a second
/// time; a single-pass substitution would be more robust, but must change in
/// both renderers together.)
pub fn render_bootstrap(template: &str, panel: &Panel, engine: Engine) -> String {
    let empty = Value::String(String::new());
    let selector = |key: &str| pyjson::dumps(panel.selectors.get(key).unwrap_or(&empty));
    let string = |s: &str| pyjson::dumps(&Value::from(s));
    let replacements = [
        ("\"{{PANEL_ID}}\"", string(&panel.id)),
        ("\"{{MODE}}\"", string(engine.as_str())),
        ("\"{{USER_SEL}}\"", selector("user")),
        ("\"{{PASS_SEL}}\"", selector("pass")),
        ("\"{{SUBMIT_SEL}}\"", selector("submit")),
        ("\"{{LOGIN_MARKER}}\"", string(&panel.login_marker)),
        ("\"{{ALLOWED_ORIGIN}}\"", string(&allowed_origin(panel))),
        ("{{KEEPALIVE_JSON}}", keepalive_json(panel)),
        ("{{LOGIN_ZONES_JSON}}", pyjson::dumps(&Value::Object(safe_zones(&panel.login_zones)))),
    ];
    let mut js = template.to_string();
    for (token, value) in &replacements {
        js = js.replace(token, value);
    }
    js
}

/// The bootstrap for `panel`, from the process-wide [`template`].
pub fn bootstrap_js(panel: &Panel, engine: Engine) -> String {
    render_bootstrap(template(), panel, engine)
}

/// [`bootstrap_js`], warning through `log` when no origin gate could be
/// derived. Such a panel renders `allowedOrigin: ""`, which the template reads
/// as "no gate" — so the host must not release credentials to it at all (the
/// Chromium engine in this crate refuses; see [`guarded_login_call`]).
pub fn bootstrap_with_origin(panel: &Panel, engine: Engine, log: &mut dyn FnMut(&str)) -> String {
    if allowed_origin(panel).is_empty() {
        log(&format!("[{}] no allowed-origin for credential gate (url not http(s)); auto-login is withheld", panel.id));
    }
    bootstrap_js(panel, engine)
}

// --------------------------------------------------------------------------- //
// Just-in-time calls
// --------------------------------------------------------------------------- //

/// The `socLogin({...})` call carrying real credentials. The result is wiped
/// when dropped; never log it.
///
/// Identical to the Python call except that `<`, `>` and `&` inside a value
/// are written as `\u00XX` escapes, so the text is inert in a `<script>`
/// context too. JS decodes both spellings to the same string.
pub fn login_call(login: &Login) -> Zeroizing<String> {
    let mut js = Zeroizing::new(String::with_capacity(96 + login.username.len() + login.password.len()));
    js.push_str("try{window.socLogin && window.socLogin({\"user\": ");
    pyjson::write_js_str(&mut js, &login.username);
    js.push_str(", \"pass\": ");
    pyjson::write_js_str(&mut js, &login.password);
    js.push_str("});}catch(e){}");
    js
}

/// [`login_call`] wrapped in a host-authored origin check, or `None` when
/// `origin` is empty (a panel without a derivable origin gets no credentials).
///
/// The template's own gate lives inside `window.socLogin`, which is an
/// ordinary page-writable property: a page the top frame was redirected to
/// can replace it and raise `needLogin`, and would then be handed the
/// credentials as arguments. `window` and `location` are unforgeable, so
/// testing `window.location.origin` in the same evaluation — before the
/// credentials are even parsed as an argument list by the page's function —
/// closes that hole without touching the shared template.
pub fn guarded_login_call(origin: &str, login: &Login) -> Option<Zeroizing<String>> {
    if origin.is_empty() {
        return None;
    }
    let call = login_call(login);
    let mut js = Zeroizing::new(String::with_capacity(call.len() + origin.len() + 48));
    js.push_str("if(window.location.origin===");
    pyjson::write_js_str(&mut js, origin);
    js.push_str("){");
    js.push_str(&call);
    js.push('}');
    Some(js)
}

/// JS that shows the in-page "sign-in needed" popup.
pub fn prompt_call(msg: &str) -> String {
    let mut js = String::from("try{window.socPrompt && window.socPrompt(");
    pyjson::write_js_str(&mut js, msg);
    js.push_str(");}catch(e){}");
    js
}

/// JS that removes the popup again.
pub fn prompt_clear_call() -> &'static str {
    "try{window.socPromptClear && window.socPromptClear();}catch(e){}"
}

// --------------------------------------------------------------------------- //
// Calibration result
// --------------------------------------------------------------------------- //

/// What the calibration overlay reported.
#[derive(Debug, Clone, PartialEq)]
pub enum Calibration {
    /// The zones the operator clicked (only well-formed ones are kept, so the
    /// saved override stays schema-conformant).
    Captured(Dict),
    Cancelled,
    Malformed,
}

impl Calibration {
    /// Parse the overlay's JSON result.
    pub fn parse(raw: &str) -> Calibration {
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            return Calibration::Malformed;
        };
        let Some(obj) = value.as_object() else {
            return Calibration::Cancelled;
        };
        if obj.get("cancelled").is_some_and(soc_core::dict::truthy) {
            return Calibration::Cancelled;
        }
        Calibration::Captured(safe_zones(obj))
    }

    /// The zones to save, if any were captured.
    pub fn zones(self) -> Option<Dict> {
        match self {
            Calibration::Captured(zones) => Some(zones),
            _ => None,
        }
    }

    /// The journal line for this outcome.
    pub fn log_line(&self, panel_id: &str) -> String {
        match self {
            Calibration::Captured(zones) => {
                let mut keys: Vec<&str> = zones.keys().map(String::as_str).collect();
                keys.sort_unstable();
                format!("[{panel_id}] calibrate: captured [{}]", keys.join(", "))
            }
            Calibration::Cancelled => format!("[{panel_id}] calibrate: cancelled"),
            Calibration::Malformed => format!("[{panel_id}] calibrate: malformed result"),
        }
    }
}

// --------------------------------------------------------------------------- //
// Login budget re-arm
// --------------------------------------------------------------------------- //

/// When a panel's auto-login budget runs out it stops and asks a human to sign
/// in. On an unattended wall that is a dead end, so the budget refills after a
/// backoff that doubles up to `maximum`: slow enough not to lock the account,
/// but never giving up.
///
/// [`due`](Self::due) is called from wherever the panel notices the budget is
/// spent; the first call starts the wait. The clock is passed in, so this is
/// pure and shared by both engines.
#[derive(Debug, Clone)]
pub struct LoginRearm {
    initial: Duration,
    maximum: Duration,
    delay: Duration,
    since: Option<Instant>,
}

impl Default for LoginRearm {
    fn default() -> Self {
        LoginRearm::new(Duration::from_secs(300), Duration::from_secs(3600))
    }
}

impl LoginRearm {
    pub fn new(initial: Duration, maximum: Duration) -> LoginRearm {
        LoginRearm { initial, maximum, delay: initial, since: None }
    }

    /// True once the current wait has elapsed (and doubles the next one).
    pub fn due(&mut self, now: Instant) -> bool {
        let Some(since) = self.since else {
            self.since = Some(now);
            return false;
        };
        if now.saturating_duration_since(since) < self.delay {
            return false;
        }
        self.since = None;
        self.delay = (self.delay * 2).min(self.maximum);
        true
    }

    /// A login worked: the next failure starts from the short wait again.
    pub fn reset(&mut self) {
        self.delay = self.initial;
        self.since = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use soc_core::{KeepAliveStrategy, Mode};

    fn dict(v: Value) -> Dict {
        v.as_object().cloned().unwrap()
    }

    fn panel() -> Panel {
        let mut p = Panel::new("p1");
        p.url = Some("http://10.0.0.1:3000/login".into());
        p.vault_item = "Item 1".into();
        p.selectors = dict(json!({"user": "#u", "pass": "input[name=\"pw\"]", "submit": ".go"}));
        p.login_marker = "#u".into();
        p.keepalive.strategy = KeepAliveStrategy::Reload;
        p.keepalive.interval_sec = 42;
        p
    }

    #[test]
    fn every_placeholder_is_filled_and_escaped() {
        let js = render_bootstrap(DEFAULT_TEMPLATE, &panel(), Engine::Webkit);
        // The only braces-pairs left are the ones in the header comment.
        let body = &js[js.find("(function ()").unwrap()..];
        assert!(!body.contains("{{"), "unfilled placeholder in the script body");
        assert!(js.contains("id:          \"p1\""));
        assert!(js.contains("\"reload\"") && js.contains("\"intervalSec\": 42"));
        assert!(js.contains(r#"input[name=\"pw\"]"#), "quotes in a selector must be JSON-escaped");
        assert!(js.contains("allowedOrigin: \"http://10.0.0.1:3000\""));
        assert!(js.contains("loginZones: {}"));
    }

    #[test]
    fn origin_gate_is_empty_for_an_unresolved_tunnel() {
        let mut p = panel();
        p.mode = Mode::Tunnel;
        p.tunnel = Some(Dict::new());
        let mut logs = Vec::new();
        let js = render_bootstrap(DEFAULT_TEMPLATE, &p, Engine::Chromium);
        assert!(js.contains("allowedOrigin: \"\""));
        let _ = bootstrap_with_origin(&p, Engine::Chromium, &mut |m| logs.push(m.to_string()));
        assert!(logs.iter().any(|m| m.contains("no allowed-origin")));
        // A resolvable panel does not warn.
        logs.clear();
        let _ = bootstrap_with_origin(&panel(), Engine::Webkit, &mut |m| logs.push(m.to_string()));
        assert!(logs.is_empty());
    }

    #[test]
    fn panel_origin_matches_location_origin() {
        for (url, want) in [
            ("http://10.0.0.1:3000/login", "http://10.0.0.1:3000"),
            ("http://127.0.0.1:19103/app", "http://127.0.0.1:19103"),
            ("https://app.example.com/x", "https://app.example.com"),
            ("https://app.example.com:443/x", "https://app.example.com"),
            ("http://h:80/x", "http://h"),
            ("https://h:8443/", "https://h:8443"),
            ("https://soc.example/path?q=1", "https://soc.example"),
            ("", ""),
            ("ftp://x/y", ""),
            ("file:///etc/passwd", ""),
            ("javascript:1", ""),
            ("data:text/html,x", ""),
            ("http://h:99999/", ""),
            ("http://[not-an-ip]/", ""),
        ] {
            assert_eq!(panel_origin(url), want, "{url:?}");
        }
    }

    #[test]
    fn zones_are_filtered_before_rendering() {
        let zones = dict(json!({
            "user": {"x_pct": 0.5, "y_pct": 0.5},
            "pass": {"x_pct": "nope", "y_pct": 0.5},
            "submit": {"x_pct": 1.5, "y_pct": 0.5},
            "hackme": {"x_pct": 0.5, "y_pct": 0.5},
        }));
        let safe = safe_zones(&zones);
        assert_eq!(safe.keys().collect::<Vec<_>>(), vec!["user"]);
        // Booleans are not numbers, and extra keys inside a zone are dropped.
        let odd = dict(json!({"user": {"x_pct": true, "y_pct": 0.1}, "pass": {"x_pct": 0, "y_pct": 1, "z": "x"}}));
        assert_eq!(pyjson::dumps(&Value::Object(safe_zones(&odd))), r#"{"pass": {"x_pct": 0.0, "y_pct": 1.0}}"#);

        let mut p = panel();
        p.login_zones = zones;
        let js = render_bootstrap(DEFAULT_TEMPLATE, &p, Engine::Webkit);
        assert!(js.contains(r#"loginZones: {"user": {"x_pct": 0.5, "y_pct": 0.5}}"#));
    }

    #[test]
    fn login_call_escapes_every_breakout() {
        let hostile = Login::new("a\"b</script>", "p\\x\u{2028}';alert(1)//\n&");
        let call = login_call(&hostile);
        assert!(call.starts_with("try{window.socLogin && window.socLogin({\"user\": \""));
        assert!(call.ends_with("});}catch(e){}"));
        assert!(call.is_ascii());
        assert!(!call.contains("</script>") && !call.contains('\n') && !call.contains('<'));
        // The argument is still one well-formed JSON object holding the values.
        let start = call.find('{').unwrap() + 1;
        let payload = &call[call[start..].find('{').unwrap() + start..call.rfind("});").unwrap() + 1];
        let parsed: Value = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed, json!({"user": "a\"b</script>", "pass": "p\\x\u{2028}';alert(1)//\n&"}));
    }

    #[test]
    fn guarded_call_needs_an_origin() {
        let login = Login::new("u", "p");
        assert!(guarded_login_call("", &login).is_none());
        let js = guarded_login_call("https://dash.example.com", &login).unwrap();
        assert_eq!(
            js.as_str(),
            "if(window.location.origin===\"https://dash.example.com\"){try{window.socLogin && \
             window.socLogin({\"user\": \"u\", \"pass\": \"p\"});}catch(e){}}"
        );
    }

    #[test]
    fn prompt_calls() {
        let c = prompt_call("say \"hi\"");
        assert!(c.contains("window.socPrompt") && c.contains(r#"\"hi\""#));
        assert!(prompt_clear_call().contains("socPromptClear"));
    }

    #[test]
    fn calibration_results() {
        let ok =
            Calibration::parse(r#"{"user":{"x_pct":0.5,"y_pct":0.4},"submit":{"x_pct":0.55,"y_pct":0.6},"junk":1}"#);
        assert_eq!(ok.log_line("z"), "[z] calibrate: captured [submit, user]");
        let zones = ok.zones().unwrap();
        assert_eq!(zones.get("user"), Some(&json!({"x_pct": 0.5, "y_pct": 0.4})));
        assert!(!zones.contains_key("junk"));

        assert_eq!(Calibration::parse(r#"{"cancelled":true}"#), Calibration::Cancelled);
        assert_eq!(Calibration::parse("[1]"), Calibration::Cancelled);
        assert_eq!(Calibration::parse("not json"), Calibration::Malformed);
        assert_eq!(Calibration::parse("not json").zones(), None);
        // A zone the overlay could not have produced is not persisted.
        let bad = Calibration::parse(r#"{"user":{"x_pct":7,"y_pct":0.4}}"#);
        assert_eq!(bad, Calibration::Captured(Dict::new()));
    }

    #[test]
    fn calibrate_template_ships_with_three_steps() {
        for needle in ["\"user\"", "\"pass\"", "\"submit\"", "__SOC_CALIBRATE_RESULT", "Escape", "cursor:crosshair"] {
            assert!(DEFAULT_CALIBRATE.contains(needle), "{needle} missing from calibrate.js.tmpl");
        }
    }

    #[test]
    fn template_override_and_fallback() {
        assert_eq!(load_template(None).unwrap(), DEFAULT_TEMPLATE);
        assert_eq!(load_calibrate(None).unwrap(), DEFAULT_CALIBRATE);
        let dir = std::env::temp_dir().join(format!("soc-web-inject-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tmpl = dir.join("custom.js.tmpl");
        std::fs::write(&tmpl, "id=\"{{PANEL_ID}}\";").unwrap();
        let text = load_template(Some(&tmpl)).unwrap();
        assert_eq!(render_bootstrap(&text, &panel(), Engine::Webkit), "id=\"p1\";");
        // calibrate.js.tmpl is looked up beside the override, and its absence is an error.
        assert!(load_calibrate(Some(&tmpl)).is_err());
        std::fs::write(dir.join("calibrate.js.tmpl"), "overlay").unwrap();
        assert_eq!(load_calibrate(Some(&tmpl)).unwrap(), "overlay");
        assert!(load_template(Some(&dir.join("missing.tmpl"))).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        // The fallback installs the guard object and adds no placeholder.
        assert!(FALLBACK_BOOTSTRAP.contains("needLogin:false") && !FALLBACK_BOOTSTRAP.contains("{{"));
    }

    #[test]
    fn rearm_doubles_and_resets() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut r = LoginRearm::new(s(300), s(1000));
        assert!(!r.due(t0), "the first call only starts the wait");
        assert!(!r.due(t0 + s(299)));
        assert!(r.due(t0 + s(300)));
        // Next wait is 600 s, measured from its own first call.
        assert!(!r.due(t0 + s(400)));
        assert!(!r.due(t0 + s(999)));
        assert!(r.due(t0 + s(1000)));
        // ... then capped at the maximum.
        assert!(!r.due(t0 + s(2000)));
        assert!(!r.due(t0 + s(2999)));
        assert!(r.due(t0 + s(3000)));
        r.reset();
        assert!(!r.due(t0 + s(4000)));
        assert!(r.due(t0 + s(4300)));
    }
}
