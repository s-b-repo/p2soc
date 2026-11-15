//! Test doubles: a tiny in-process HTTP server on 127.0.0.1 and, on top of it,
//! a fake Vaultwarden that behaves like the real one for the flows this crate
//! drives (prelogin, password and refresh grants, cipher and folder CRUD).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::crypto::{Kdf, MasterKey, SymKey};
use crate::http::HttpOptions;
use crate::session::SessionOptions;

#[derive(Debug, Clone)]
pub(crate) struct MockRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Vec<u8>,
}

impl MockRequest {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// Decoded `application/x-www-form-urlencoded` fields.
    pub(crate) fn form(&self) -> HashMap<String, String> {
        fn decode(text: &str) -> String {
            let bytes = text.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'+' => out.push(b' '),
                    b'%' if i + 2 < bytes.len() => {
                        out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap_or(b'?'));
                        i += 2;
                    }
                    other => out.push(other),
                }
                i += 1;
            }
            String::from_utf8_lossy(&out).into_owned()
        }
        String::from_utf8_lossy(&self.body)
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (decode(k), decode(v)))
            .collect()
    }
}

pub(crate) struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Send this many zero bytes instead of `body` (oversize tests).
    filler: Option<u64>,
}

impl MockResponse {
    pub(crate) fn json(status: u16, value: &Value) -> MockResponse {
        MockResponse::text(status, &value.to_string()).with_header("Content-Type", "application/json")
    }

    pub(crate) fn text(status: u16, body: &str) -> MockResponse {
        MockResponse { status, headers: Vec::new(), body: body.as_bytes().to_vec(), filler: None }
    }

    pub(crate) fn raw_with_length(status: u16, length: u64) -> MockResponse {
        MockResponse { status, headers: Vec::new(), body: Vec::new(), filler: Some(length) }
    }

    pub(crate) fn with_header(mut self, name: &str, value: &str) -> MockResponse {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

type Handler = dyn Fn(&MockRequest) -> MockResponse + Send + Sync;

pub(crate) struct MockServer {
    pub(crate) url: String,
    requests: Arc<Mutex<Vec<MockRequest>>>,
    stop: Arc<AtomicBool>,
    addr: std::net::SocketAddr,
    thread: Option<JoinHandle<()>>,
}

fn read_request(stream: &mut TcpStream) -> Option<MockRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: HashMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(MockRequest { method, path, headers, body })
}

fn write_response(stream: &mut TcpStream, response: &MockResponse) {
    let length = response.filler.unwrap_or(response.body.len() as u64);
    let mut head = format!("HTTP/1.1 {} X\r\nContent-Length: {length}\r\nConnection: close\r\n", response.status);
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    // The client may hang up early (oversize tests); that is not a failure.
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    match response.filler {
        None => {
            let _ = stream.write_all(&response.body);
        }
        Some(mut left) => {
            let zeros = [0u8; 64 * 1024];
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                if stream.write_all(&zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
        }
    }
    let _ = stream.flush();
}

impl MockServer {
    pub(crate) fn start(handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let (log, stopping) = (Arc::clone(&requests), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream else { continue };
                let (handler, log) = (Arc::clone(&handler), Arc::clone(&log));
                // One thread per connection so a deliberately slow handler
                // cannot hold up the next test request or the shutdown.
                std::thread::spawn(move || {
                    if let Some(request) = read_request(&mut stream) {
                        log.lock().unwrap().push(request.clone());
                        write_response(&mut stream, &handler(&request));
                    }
                });
            }
        });
        MockServer { url: format!("http://{addr}"), requests, stop, addr, thread: Some(thread) }
    }

    pub(crate) fn requests(&self) -> Vec<MockRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// `METHOD path` of every request so far, in order.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.requests().iter().map(|r| format!("{} {}", r.method, r.path)).collect()
    }

    pub(crate) fn clear(&self) {
        self.requests.lock().unwrap().clear();
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A base URL nothing listens on. A fresh loopback *address* per call rather
/// than a just-freed port: tests run in parallel, and a freed port can be
/// handed to another test's listener before the "dead" connection is made.
pub(crate) fn dead_url() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed) + std::process::id();
    format!("http://127.{}.{}.{}:9", 64 + (n >> 16) % 60, (n >> 8) & 0xff, 1 + (n & 0xff) % 250)
}

/// Session options that keep tests quick.
pub(crate) fn test_options() -> SessionOptions {
    SessionOptions {
        http: HttpOptions { timeout: Duration::from_secs(10), ..HttpOptions::default() },
        ..SessionOptions::default()
    }
}

pub(crate) const TEST_EMAIL: &str = "kiosk@soc.local";
pub(crate) const TEST_MASTER: &str = "correct horse battery staple";
pub(crate) const TEST_USER_ID: &str = "11111111-2222-3333-4444-555555555555";

/// Mutable state of the fake server, shared with the test.
pub(crate) struct FakeState {
    pub(crate) kdf: Value,
    pub(crate) account_key: SymKey,
    master_hash: String,
    protected_key: String,
    pub(crate) ciphers: Vec<Value>,
    pub(crate) folders: Vec<Value>,
    /// Access tokens the API currently accepts.
    pub(crate) valid_tokens: Vec<String>,
    pub(crate) refresh_token: String,
    /// When false the refresh grant is refused.
    pub(crate) refresh_works: bool,
    /// When set, every API call answers with this status.
    pub(crate) api_failure: Option<u16>,
    /// When set, the password grant answers 400 with a two-factor challenge.
    pub(crate) require_two_factor: bool,
    issued: u32,
    next_id: u32,
}

impl FakeState {
    fn issue_token(&mut self) -> String {
        self.issued += 1;
        let part = |v: Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let token = format!(
            "{}.{}.sig{}",
            part(json!({"alg": "RS256"})),
            part(json!({"sub": TEST_USER_ID, "n": self.issued})),
            self.issued
        );
        self.valid_tokens = vec![token.clone()];
        token
    }

    /// Invalidate every access token, as a server restart or expiry would.
    pub(crate) fn expire_tokens(&mut self) {
        self.valid_tokens.clear();
    }

    /// Add a login cipher encrypted under the account key; returns its id.
    pub(crate) fn add_login(&mut self, name: &str, username: &str, password: &str) -> String {
        let key = self.account_key.clone();
        let enc = |s: &str| key.encrypt_str(s).unwrap();
        self.next_id += 1;
        let id = format!("cipher-{}", self.next_id);
        self.ciphers.push(json!({
            "id": id, "type": 1, "name": enc(name), "notes": null, "folderId": null, "favorite": false,
            "organizationId": null, "deletedDate": null,
            "login": {"username": enc(username), "password": enc(password), "totp": null, "uris": null},
        }));
        id
    }

    pub(crate) fn cipher_mut(&mut self, id: &str) -> &mut Value {
        self.ciphers.iter_mut().find(|c| c["id"] == id).expect("cipher id")
    }

    pub(crate) fn enc(&self, text: &str) -> String {
        self.account_key.encrypt_str(text).unwrap()
    }

    pub(crate) fn add_folder(&mut self, name: &str) -> String {
        self.next_id += 1;
        let id = format!("folder-{}", self.next_id);
        let name = self.enc(name);
        self.folders.push(json!({"id": id, "name": name}));
        id
    }
}

pub(crate) struct FakeVaultwarden {
    pub(crate) server: MockServer,
    pub(crate) state: Arc<Mutex<FakeState>>,
}

fn fake_handle(state: &Mutex<FakeState>, req: &MockRequest) -> MockResponse {
    let mut s = state.lock().unwrap();
    let bad_login = || {
        MockResponse::json(
            400,
            &json!({"error": "invalid_grant", "error_description": "invalid_username_or_password",
                "ErrorModel": {"Message": "Username or password is incorrect. Try again", "Object": "error"}}),
        )
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/identity/accounts/prelogin") => return MockResponse::json(200, &s.kdf),
        ("POST", "/identity/connect/token") => {
            let form = req.form();
            return match form.get("grant_type").map(String::as_str) {
                Some("password") => {
                    if form.get("username").map(String::as_str) != Some(TEST_EMAIL)
                        || form.get("password") != Some(&s.master_hash)
                    {
                        return bad_login();
                    }
                    if s.require_two_factor {
                        return MockResponse::json(
                            400,
                            &json!({"error": "invalid_grant", "error_description": "Two factor required.",
                                "TwoFactorProviders": [0], "TwoFactorProviders2": {"0": null}}),
                        );
                    }
                    let token = s.issue_token();
                    MockResponse::json(
                        200,
                        &json!({"access_token": token, "expires_in": 7200, "token_type": "Bearer",
                            "refresh_token": s.refresh_token, "Key": s.protected_key, "Kdf": 0}),
                    )
                }
                Some("refresh_token") => {
                    if !s.refresh_works || form.get("refresh_token") != Some(&s.refresh_token) {
                        return MockResponse::json(401, &json!({"error": "invalid_grant"}));
                    }
                    let token = s.issue_token();
                    MockResponse::json(200, &json!({"access_token": token, "expires_in": 7200}))
                }
                _ => MockResponse::json(400, &json!({"error": "unsupported_grant_type"})),
            };
        }
        _ => {}
    }
    let token = req.header("authorization").and_then(|h| h.strip_prefix("Bearer ")).unwrap_or("");
    if !s.valid_tokens.iter().any(|t| t == token) {
        return MockResponse::text(401, "");
    }
    if let Some(status) = s.api_failure {
        return MockResponse::json(status, &json!({"message": "simulated failure"}));
    }
    let cipher_id = req.path.strip_prefix("/api/ciphers/").map(str::to_string);
    match (req.method.as_str(), req.path.as_str(), cipher_id) {
        ("GET", "/api/ciphers", _) => MockResponse::json(200, &json!({"data": s.ciphers, "object": "list"})),
        ("GET", "/api/folders", _) => MockResponse::json(200, &json!({"data": s.folders, "object": "list"})),
        ("POST", "/api/folders", _) => {
            s.next_id += 1;
            let folder = json!({"id": format!("folder-{}", s.next_id), "name": req.json()["name"]});
            s.folders.push(folder.clone());
            MockResponse::json(200, &folder)
        }
        ("POST", "/api/ciphers", _) => {
            // Current Vaultwarden rejects a write that does not name its user.
            let mut body = req.json();
            if body["encryptedFor"] != TEST_USER_ID {
                return MockResponse::json(422, &json!({"message": "missing encryptedFor"}));
            }
            s.next_id += 1;
            body["id"] = json!(format!("cipher-{}", s.next_id));
            s.ciphers.push(body.clone());
            MockResponse::json(200, &body)
        }
        ("PUT", _, Some(id)) => {
            let mut body = req.json();
            body["id"] = json!(id);
            match s.ciphers.iter_mut().find(|c| c["id"] == id.as_str()) {
                Some(slot) => {
                    *slot = body.clone();
                    MockResponse::json(200, &body)
                }
                None => MockResponse::json(404, &json!({"message": "Cipher doesn't exist"})),
            }
        }
        ("DELETE", _, Some(id)) => {
            let before = s.ciphers.len();
            s.ciphers.retain(|c| c["id"] != id.as_str());
            if s.ciphers.len() == before {
                MockResponse::json(404, &json!({"message": "Cipher doesn't exist"}))
            } else {
                MockResponse::text(200, "")
            }
        }
        _ => MockResponse::json(404, &json!({"message": "Not Found"})),
    }
}

impl FakeVaultwarden {
    /// A fake with one account ([`TEST_EMAIL`] / [`TEST_MASTER`]) on PBKDF2 at
    /// the minimum accepted cost, so debug-build tests stay fast.
    pub(crate) fn start() -> FakeVaultwarden {
        Self::start_with_kdf(Kdf::Pbkdf2 { iterations: 5000 }, json!({"kdf": 0, "kdfIterations": 5000}))
    }

    pub(crate) fn start_with_kdf(kdf: Kdf, prelogin: Value) -> FakeVaultwarden {
        let master_key = MasterKey::derive(TEST_MASTER, TEST_EMAIL, kdf).unwrap();
        let account_key = SymKey::random().unwrap();
        let state = Arc::new(Mutex::new(FakeState {
            kdf: prelogin,
            master_hash: master_key.password_hash(TEST_MASTER).to_string(),
            protected_key: master_key.stretch().encrypt(account_key.to_bytes().as_slice()).unwrap(),
            account_key,
            ciphers: Vec::new(),
            folders: Vec::new(),
            valid_tokens: Vec::new(),
            refresh_token: "refresh-token-1".to_string(),
            refresh_works: true,
            api_failure: None,
            require_two_factor: false,
            issued: 0,
            next_id: 0,
        }));
        let shared = Arc::clone(&state);
        let server = MockServer::start(move |req| fake_handle(&shared, req));
        FakeVaultwarden { server, state }
    }

    pub(crate) fn url(&self) -> &str {
        &self.server.url
    }

    pub(crate) fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    /// How many times a full password login happened.
    pub(crate) fn password_logins(&self) -> usize {
        self.server
            .requests()
            .iter()
            .filter(|r| {
                r.path == "/identity/connect/token"
                    && r.form().get("grant_type").map(String::as_str) == Some("password")
            })
            .count()
    }

    pub(crate) fn count(&self, call: &str) -> usize {
        self.server.calls().iter().filter(|c| c.as_str() == call).count()
    }
}
