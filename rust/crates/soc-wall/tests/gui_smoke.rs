//! End-to-end check of the WebKit panel against a real engine: a local fake
//! dashboard with a login form, a bootstrap that asks the host for
//! credentials, and the host injecting them. Needs a display (CI runs it
//! under Xvfb); without one it is skipped.
#![cfg(feature = "gui")]

use gtk::prelude::*;
use soc_core::{Login, Panel, ProxyCfg};
use soc_wall::gui::panel::{HwAccel, Profile, TrackerRules, WallServices, WebKitPanel};
use soc_wall::gui::style;
use soc_wall::gui::wall::{PillState, WallActions, WallWindow};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

const LOGIN_PAGE: &str = "<!doctype html><title>login</title><form method=post action=/session>\
<input id=u name=u><input id=p name=p type=password><button id=go type=submit>go</button></form>\
<a id=away href='http://198.51.100.7/'>away</a>";
const DASHBOARD: &str = "<!doctype html><title>dash</title><h1 id=ok>dashboard</h1>\
<script>setTimeout(function(){ location.href = 'http://198.51.100.7/exfil'; }, 300);</script>";

/// What the fake dashboard server saw.
#[derive(Default)]
struct Seen {
    posted: Vec<String>,
    paths: Vec<String>,
}

fn serve(stream: TcpStream, seen: &Arc<Mutex<Seen>>) {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or("").to_string());
    let mut length = 0usize;
    let mut cookie = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("cookie:") {
            cookie = line;
        }
    }
    let mut body = vec![0u8; length.min(4096)];
    let _ = reader.read_exact(&mut body);
    seen.lock().unwrap().paths.push(format!("{method} {path}"));
    let (status, extra, page) = match (method, path.as_str()) {
        ("POST", "/session") => {
            seen.lock().unwrap().posted.push(String::from_utf8_lossy(&body).into_owned());
            ("303 See Other", "Location: /\r\nSet-Cookie: sid=1; Path=/\r\n", "")
        }
        ("GET", "/") if cookie.contains("sid=1") => ("200 OK", "", DASHBOARD),
        ("GET", "/") => ("200 OK", "", LOGIN_PAGE),
        _ => ("404 Not Found", "", "nope"),
    };
    let mut stream = reader.into_inner();
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{page}",
        page.len()
    );
}

fn start_server() -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let shared = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let shared = shared.clone();
            std::thread::spawn(move || serve(stream, &shared));
        }
    });
    (port, seen)
}

/// A minimal stand-in for the real injection template: same protocol
/// (`socCreds` messages, a `socLogin` function returning whether it submitted).
const BOOTSTRAP: &str = "(function(){\
  function post(m){ window.webkit.messageHandlers.socCreds.postMessage(m); }\
  window.socLogin = function(c){\
    var u = document.querySelector('#u'), p = document.querySelector('#p');\
    if (!u || !p) return false;\
    u.value = c.user; p.value = c.pass; document.querySelector('#go').click(); return true; };\
  document.addEventListener('DOMContentLoaded', function(){\
    post(document.querySelector('#p') ? 'login' : 'loggedin'); });\
})();";

#[derive(Default)]
struct Fake {
    port: Cell<u16>,
    logs: RefCell<Vec<String>>,
    logged_in: Cell<bool>,
    login_requests: Cell<u32>,
}

impl WallServices for Fake {
    fn log(&self, msg: &str) {
        self.logs.borrow_mut().push(msg.to_string());
    }
    fn bootstrap_js(&self, _panel: &Panel) -> String {
        BOOTSTRAP.to_string()
    }
    fn nav_gate(&self, _panel: &Panel) -> Option<Box<dyn Fn(&str) -> bool>> {
        let own = format!("http://127.0.0.1:{}/", self.port.get());
        Some(Box::new(move |uri| uri.starts_with(&own) || uri.starts_with("about:")))
    }
    fn tracker_rules(&self, _panel: &Panel) -> Option<TrackerRules> {
        Some(TrackerRules {
            key: String::new(),
            json: r#"[{"trigger":{"url-filter":"tracker\\.example"},"action":{"type":"block"}}]"#.into(),
        })
    }
    fn login_for(&self, _panel: &Panel) -> Option<Login> {
        self.login_requests.set(self.login_requests.get() + 1);
        Some(Login::new("operator", "s3cr3t&=pw"))
    }
    fn may_login(&self, _panel: &Panel, page_uri: &str) -> bool {
        page_uri.starts_with(&format!("http://127.0.0.1:{}/", self.port.get()))
    }
    fn login_js(&self, _panel: &Panel, login: &Login) -> Option<Zeroizing<String>> {
        let creds = serde_json::json!({"user": login.username, "pass": login.password});
        Some(Zeroizing::new(format!("window.socLogin({creds})")))
    }
    fn prompt_js(&self, _message: &str) -> String {
        "void 0".into()
    }
    fn prompt_clear_js(&self) -> String {
        "void 0".into()
    }
    fn login_succeeded(&self, _panel: &Panel) {
        self.logged_in.set(true);
    }
    fn proxy_login(&self) -> Option<Login> {
        None
    }
    fn web_process_pids(&self) -> BTreeSet<u32> {
        BTreeSet::new()
    }
    fn proc_rss_kb(&self, _pid: u32) -> Option<u64> {
        None
    }
}

/// Turn the main loop until `done` holds or the deadline passes.
fn pump_until(deadline: Duration, done: impl Fn() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        while gtk::events_pending() {
            gtk::main_iteration();
        }
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done()
}

#[test]
fn webkit_panel_logs_in_and_gates_navigation() {
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("no display: skipping the GUI smoke test");
        return;
    }
    if gtk::init().is_err() {
        eprintln!("GTK could not initialise: skipping the GUI smoke test");
        return;
    }
    let (port, seen) = start_server();
    let webdata = std::env::temp_dir().join(format!("soc-wall-smoke-{}", std::process::id()));
    let fake = Rc::new(Fake::default());
    fake.port.set(port);
    let services: Rc<dyn WallServices> = fake.clone();

    let mut conf = soc_core::load::load_str_with(
        &format!("display: {{cols: 1, rows: 1}}\npanels:\n  - id: p1\n    url: http://127.0.0.1:{port}/\n"),
        "<smoke>",
        &soc_core::load::Overrides::default(),
    )
    .unwrap();
    let panel_cfg = conf.panels.remove(0);
    conf.panels.push(panel_cfg.clone());

    style::apply_css(&style::tokens_from_colors(&Default::default()));
    let profile = Profile {
        low_memory: true,
        hwaccel: HwAccel::Never,
        unattended: true,
        mem_limit_mb: 256,
        stable_sec: 30.0,
        webdata_dir: webdata.clone(),
    };
    let logs: Rc<RefCell<Vec<String>>> = Rc::default();
    let wall = {
        let logs = logs.clone();
        WallWindow::new(&conf, true, WallActions::default(), Rc::new(move |m: &str| logs.borrow_mut().push(m.into())))
    };
    let panel = WebKitPanel::new(panel_cfg.clone(), services, ProxyCfg::default(), profile, true, None);
    wall.attach(&panel_cfg, &panel.widget());
    wall.show();
    wall.set_vpn_status(PillState::Online, "VPN up", None);
    panel.show();

    let logged_in = pump_until(Duration::from_secs(60), || fake.logged_in.get());
    let dump = || format!("panel log: {:#?}\nserver saw: {:#?}", fake.logs.borrow(), seen.lock().unwrap().paths);
    assert!(logged_in, "the panel never reported a login\n{}", dump());

    // The credentials reached the page's own form, exactly once, URL-encoded
    // by the browser (never mangled by the injection).
    let posted = seen.lock().unwrap().posted.clone();
    assert_eq!(posted, vec!["u=operator&p=s3cr3t%26%3Dpw".to_string()], "{}", dump());
    assert_eq!(fake.login_requests.get(), 1);
    assert!(fake.logs.borrow().iter().any(|l| l.contains("injected login (attempt 1)")), "{}", dump());

    // The dashboard then tries to navigate the top frame off-origin: refused.
    let refused = pump_until(Duration::from_secs(20), || {
        fake.logs.borrow().iter().any(|l| l.contains("refused off-allowlist nav"))
    });
    assert!(refused, "the off-allowlist navigation was not refused\n{}", dump());
    assert!(panel.loaded_ok(), "the dashboard should still be showing\n{}", dump());

    // Web data is private to the wall user.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&webdata).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "web-data root must be 0700");

    panel.stop();
    panel.stop(); // idempotent
    wall.window().close();
    pump_until(Duration::from_millis(300), || false);
    let _ = std::fs::remove_dir_all(&webdata);
}
