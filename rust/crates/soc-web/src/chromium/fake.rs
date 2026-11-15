//! An in-process stand-in for Chromium's DevTools server: an HTTP target list
//! and one page websocket on a loopback port. It records every command and
//! behaves like the real thing where the host's logic depends on it — above
//! all, a navigation paused by `Fetch` is held until the client lets it go.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tungstenite::Message;

#[derive(Default)]
struct State {
    received: Vec<(String, Value)>,
    /// What the poll expression evaluates to.
    page: Value,
    /// Events to push on the next loop turn.
    events: VecDeque<Value>,
    /// Methods answered with an error.
    failing: HashSet<String>,
    /// Methods never answered (a wedged browser).
    silent: HashSet<String>,
    /// Stream unsolicited events non-stop.
    flood: bool,
    /// Advertise this websocket URL instead of the real one.
    advertise: Option<String>,
    /// Challenge every navigation as the proxy would.
    proxy_challenge: bool,
    /// Re-challenge after credentials were provided (wrong password).
    proxy_rejects: bool,
    fetch_on: bool,
    /// `Page.navigate` calls whose reply waits for the paused request.
    held_navigations: Vec<(u64, String)>,
    nav_seq: u32,
    drop_now: bool,
    connections: u32,
}

/// The fake server. Dropping it shuts it down.
pub struct FakeDevTools {
    pub port: u16,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
}

impl FakeDevTools {
    pub fn start() -> FakeDevTools {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(State { page: json!({}), ..State::default() }));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_state, thread_stop) = (state.clone(), stop.clone());
        std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (state, stop) = (thread_state.clone(), thread_stop.clone());
                        std::thread::spawn(move || serve(stream, port, &state, &stop));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(2)),
                }
            }
        });
        FakeDevTools { port, state, stop }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// Set what the page reports to the poll (`n`, `l`, `r`, `e`, `o`).
    pub fn set_page(&self, page: Value) {
        self.state().page = page;
    }

    pub fn push_event(&self, method: &str, params: Value) {
        self.state().events.push_back(json!({"method": method, "params": params}));
    }

    pub fn fail_method(&self, method: &str) {
        self.state().failing.insert(method.to_string());
    }

    pub fn silence_method(&self, method: &str) {
        self.state().silent.insert(method.to_string());
    }

    pub fn flood(&self, on: bool) {
        self.state().flood = on;
    }

    pub fn advertise(&self, ws_url: &str) {
        self.state().advertise = Some(ws_url.to_string());
    }

    pub fn proxy(&self, challenge: bool, rejects: bool) {
        let mut s = self.state();
        s.proxy_challenge = challenge;
        s.proxy_rejects = rejects;
    }

    /// Close the page websocket from the server side.
    pub fn drop_connection(&self) {
        self.state().drop_now = true;
    }

    pub fn connections(&self) -> u32 {
        self.state().connections
    }

    pub fn clear(&self) {
        self.state().received.clear();
    }

    pub fn methods(&self) -> Vec<String> {
        self.state().received.iter().map(|(m, _)| m.clone()).collect()
    }

    /// The params of every received `method` command.
    pub fn calls(&self, method: &str) -> Vec<Value> {
        self.state().received.iter().filter(|(m, _)| m == method).map(|(_, p)| p.clone()).collect()
    }

    /// Every expression the client asked the page to evaluate.
    pub fn evaluated(&self) -> Vec<String> {
        self.calls("Runtime.evaluate")
            .iter()
            .map(|p| p["expression"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// Wait until `done` holds for the recorded commands.
    pub fn wait_for(&self, what: &str, done: impl Fn(&[(String, Value)]) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if done(&self.state().received) {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}; saw {:?}", self.methods());
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for FakeDevTools {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(mut stream: TcpStream, port: u16, state: &Mutex<State>, stop: &AtomicBool) {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut head = [0u8; 16];
    let Ok(n) = stream.peek(&mut head) else {
        return;
    };
    if head[..n].starts_with(b"GET /json") {
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        let url = state
            .lock()
            .unwrap()
            .advertise
            .clone()
            .unwrap_or_else(|| format!("ws://127.0.0.1:{port}/devtools/page/FAKE0123456789ABCDEF"));
        let body = json!([
            {"type": "background_page", "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/BG")},
            {"type": "page", "url": "data:text/html,", "webSocketDebuggerUrl": url},
        ])
        .to_string();
        // Like Chromium, answer with a length and keep the connection open.
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.flush();
        std::thread::sleep(Duration::from_millis(50));
        return;
    }
    let Ok(mut ws) = tungstenite::accept(stream) else {
        return;
    };
    state.lock().unwrap().connections += 1;
    ws.get_ref().set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    let send = |ws: &mut tungstenite::WebSocket<TcpStream>, v: Value| ws.send(Message::text(v.to_string())).is_ok();
    while !stop.load(Ordering::Relaxed) {
        let (pending, flood, drop_now) = {
            let mut s = state.lock().unwrap();
            (s.events.drain(..).collect::<Vec<_>>(), s.flood, std::mem::take(&mut s.drop_now))
        };
        if drop_now {
            let _ = ws.close(None);
            let _ = ws.flush();
            return;
        }
        for event in pending {
            if !send(&mut ws, event) {
                return;
            }
        }
        if flood && !send(&mut ws, json!({"method": "Runtime.consoleAPICalled", "params": {}})) {
            return;
        }
        let msg = match ws.read() {
            Ok(Message::Text(text)) => serde_json::from_str::<Value>(text.as_str()).unwrap(),
            Ok(Message::Close(_)) => return,
            Ok(_) => continue,
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
            {
                continue;
            }
            Err(_) => return,
        };
        for reply in react(&msg, state) {
            if !send(&mut ws, reply) {
                return;
            }
        }
    }
}

fn proxy_challenge(rid: &str) -> Value {
    json!({"method": "Fetch.authRequired", "params": {
        "requestId": rid,
        "request": {"url": "https://dash.example.com/overview"},
        "resourceType": "Document",
        "authChallenge": {"source": "Proxy", "origin": "http://proxy.corp:3128", "scheme": "basic", "realm": "corp"},
    }})
}

/// Record one command and produce the messages a browser would send back.
fn react(msg: &Value, state: &Mutex<State>) -> Vec<Value> {
    let mut s = state.lock().unwrap();
    let id = msg["id"].as_u64().unwrap();
    let method = msg["method"].as_str().unwrap().to_string();
    let params = msg["params"].clone();
    s.received.push((method.clone(), params.clone()));
    if s.silent.contains(&method) {
        return Vec::new();
    }
    if s.failing.contains(&method) {
        return vec![json!({"id": id, "error": {"code": -32601, "message": format!("'{method}' wasn't found")}})];
    }
    let ok = |result: Value| json!({"id": id, "result": result});
    // Release the navigation a paused request belongs to.
    let release = |s: &mut State, rid: &str, error: Option<&str>| -> Vec<Value> {
        let Some(at) = s.held_navigations.iter().position(|(_, held)| held == rid) else {
            return Vec::new();
        };
        let (nav_id, _) = s.held_navigations.remove(at);
        let mut result = json!({"frameId": "MAIN", "loaderId": "L1"});
        if let Some(error) = error {
            result["errorText"] = json!(error);
        }
        vec![
            json!({"id": nav_id, "result": result}),
            json!({"method": "Page.frameNavigated", "params": {"frame": {"id": "MAIN", "url": "x"}}}),
        ]
    };
    match method.as_str() {
        "Fetch.enable" => {
            s.fetch_on = true;
            vec![ok(json!({}))]
        }
        "Fetch.disable" => {
            s.fetch_on = false;
            vec![ok(json!({}))]
        }
        "Page.navigate" if s.fetch_on => {
            s.nav_seq += 1;
            let rid = format!("nav-{}", s.nav_seq);
            s.held_navigations.push((id, rid.clone()));
            if s.proxy_challenge {
                vec![proxy_challenge(&rid)]
            } else {
                vec![json!({"method": "Fetch.requestPaused", "params": {
                    "requestId": rid, "resourceType": "Document", "request": {"url": params["url"]},
                }})]
            }
        }
        "Fetch.continueRequest" => {
            let rid = params["requestId"].as_str().unwrap_or_default().to_string();
            let mut out = vec![ok(json!({}))];
            out.extend(release(&mut s, &rid, None));
            out
        }
        "Fetch.failRequest" => {
            let rid = params["requestId"].as_str().unwrap_or_default().to_string();
            let mut out = vec![ok(json!({}))];
            out.extend(release(&mut s, &rid, Some("net::ERR_BLOCKED_BY_CLIENT")));
            out
        }
        "Fetch.continueWithAuth" => {
            let rid = params["requestId"].as_str().unwrap_or_default().to_string();
            let mut out = vec![ok(json!({}))];
            let provided = params["authChallengeResponse"]["response"] == "ProvideCredentials";
            if provided && s.proxy_rejects {
                out.push(proxy_challenge(&rid));
            } else {
                let error = (!provided).then_some("net::ERR_PROXY_AUTH_REQUESTED");
                out.extend(release(&mut s, &rid, error));
            }
            out
        }
        "Runtime.evaluate" => {
            let expression = params["expression"].as_str().unwrap_or_default();
            if expression.starts_with("(function(){var s=window.__SOC||{};") {
                vec![ok(json!({"result": {"type": "object", "value": s.page}}))]
            } else if expression == crate::inject::CALIBRATE_POLL_JS {
                vec![ok(json!({"result": {"type": "string", "value": s.page["calibrate"]}}))]
            } else {
                vec![ok(json!({"result": {"type": "undefined"}}))]
            }
        }
        _ => vec![ok(json!({}))],
    }
}
