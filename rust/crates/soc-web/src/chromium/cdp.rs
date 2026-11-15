//! A minimal Chrome DevTools Protocol client: blocking websocket, one thread.
//!
//! The connection only ever goes to `127.0.0.1`. The websocket URL a DevTools
//! server advertises is treated as untrusted text — it is checked to be a
//! loopback page endpoint on the expected port, and then only its *path* is
//! used; the socket itself is opened to the loopback address by this code.
//! Otherwise whatever answers on the port could redirect the host — and the
//! credentials it injects — to a machine of its choosing.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use soc_core::url::Url;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};
use zeroize::Zeroizing;

use super::argv::ACTIVE_PORT_FILE;
use crate::pyjson;

/// Longest single blocking read, so a stop request is noticed promptly.
const SLICE: Duration = Duration::from_millis(250);
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// The host only ever reads small results; a renderer must not be able to
/// make it buffer more.
const MAX_MESSAGE: usize = 8 << 20;
const MAX_HTTP_BODY: u64 = 1 << 20;
/// Fire-and-forget command ids awaiting their (ignored) reply.
const MAX_NOREPLY: usize = 4096;

/// Why a DevTools operation failed. Never contains an evaluated expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpError {
    /// No page endpoint could be found on the port.
    Discovery(String),
    /// The advertised endpoint is not a loopback page endpoint on our port.
    NotLoopback(String),
    /// The socket is closed or broken; the session must be re-attached.
    Closed(String),
    /// No reply within the deadline (a wedged browser or an event flood).
    Timeout(String),
    /// The browser answered the command with an error.
    Remote(String),
    /// A stop was requested while waiting.
    Stopped,
}

impl CdpError {
    /// True when the connection itself is unusable.
    pub fn is_fatal(&self) -> bool {
        matches!(self, CdpError::Closed(_) | CdpError::Stopped)
    }
}

impl std::fmt::Display for CdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CdpError::Discovery(m) => write!(f, "could not attach CDP ({m})"),
            CdpError::NotLoopback(m) => write!(f, "refusing DevTools endpoint: {m}"),
            CdpError::Closed(m) => write!(f, "CDP socket closed: {m}"),
            CdpError::Timeout(m) => write!(f, "CDP rpc {m} timed out"),
            CdpError::Remote(m) => write!(f, "CDP error: {m}"),
            CdpError::Stopped => f.write_str("stopped"),
        }
    }
}

impl std::error::Error for CdpError {}

/// A validated page endpoint: `ws://127.0.0.1:<port><path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub port: u16,
    /// `/devtools/page/<id>`.
    pub path: String,
}

impl Endpoint {
    /// Validate an advertised `webSocketDebuggerUrl` against the port it was
    /// discovered on.
    pub fn from_ws_url(url: &str, port: u16) -> Result<Endpoint, CdpError> {
        let refuse = |why: &str| CdpError::NotLoopback(format!("{why} ({} chars)", url.len()));
        let parts = Url::split(url).map_err(|_| refuse("malformed websocket url"))?; // audit-allow: the parse error may echo the url; refuse() reports only its length
        if parts.scheme != "ws" {
            return Err(refuse("not a plain ws:// url"));
        }
        if parts.userinfo.is_some() {
            return Err(refuse("url carries userinfo"));
        }
        if !matches!(parts.host.as_deref(), Some("127.0.0.1" | "localhost" | "::1")) {
            return Err(refuse("host is not loopback"));
        }
        if parts.port_or_default() != Some(port) {
            return Err(refuse("port differs from the DevTools port"));
        }
        let id = parts.rest.strip_prefix("/devtools/page/").ok_or_else(|| refuse("not a page endpoint"))?;
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(refuse("unexpected characters in the target id"));
        }
        Ok(Endpoint { port, path: parts.rest })
    }
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// The port in a profile's `DevToolsActivePort` file, once Chromium wrote it.
/// The profile directory is private to this user, so the port read here was
/// bound by the browser this host started — not by a squatter.
pub fn read_active_port(profile: &Path) -> Option<u16> {
    let text = std::fs::read_to_string(profile.join(ACTIVE_PORT_FILE)).ok()?;
    text.lines().next()?.trim().parse::<u16>().ok().filter(|p| *p != 0)
}

/// Whether `len` bytes exceed [`MAX_HTTP_BODY`] (a length that does not fit
/// `u64` certainly does).
fn over_body_cap(len: usize) -> bool {
    !u64::try_from(len).is_ok_and(|n| n <= MAX_HTTP_BODY)
}

/// `GET http://127.0.0.1:<port><path>` and parse the body as JSON.
fn http_get_json(port: u16, path: &str) -> Result<Value, CdpError> {
    let fail = |what: &str, e: &dyn std::fmt::Display| CdpError::Discovery(format!(":{port} {what}: {e}"));
    let mut stream = TcpStream::connect_timeout(&loopback(port), HTTP_TIMEOUT).map_err(|e| fail("connect", &e))?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT)).map_err(|e| fail("socket", &e))?;
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).map_err(|e| fail("socket", &e))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|e| fail("send", &e))?;
    // The server may keep the connection open, so stop at Content-Length
    // rather than waiting for EOF.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let (body_start, body_len) = loop {
        if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..split]).into_owned(); // audit-allow: bounds-checked, split came from raw.windows(4).position
            let status = head.lines().next().unwrap_or_default(); // audit-allow: default is the intended fallback, an empty status fails the 200 check
            if status.split_whitespace().nth(1) != Some("200") {
                return Err(fail("status", &status.chars().take(60).collect::<String>()));
            }
            let length = head.lines().skip(1).find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
            });
            break (split + 4, length);
        }
        if raw.len() > 16 * 1024 {
            return Err(fail("read", &"oversized HTTP header"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(fail("read", &"connection closed before the HTTP header")),
            Ok(n) => raw.extend_from_slice(chunk.get(..n).ok_or_else(|| fail("read", &"invalid read length"))?),
            Err(e) => return Err(fail("read", &e)),
        }
    };
    let wanted = body_len.map(|len| body_start + len);
    if wanted.is_some_and(over_body_cap) {
        return Err(fail("read", &"oversized target list"));
    }
    while wanted.is_none_or(|w| raw.len() < w) {
        if over_body_cap(raw.len()) {
            return Err(fail("read", &"oversized target list"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(chunk.get(..n).ok_or_else(|| fail("read", &"invalid read length"))?),
            Err(e) => return Err(fail("read", &e)),
        }
    }
    let body = &raw[body_start..wanted.unwrap_or(raw.len()).min(raw.len())];
    serde_json::from_slice(body).map_err(|e| fail("target list", &e))
}

/// Find the page target's endpoint on `port`.
pub fn discover(port: u16) -> Result<Endpoint, CdpError> {
    let targets = http_get_json(port, "/json/list")?;
    let pages = targets.as_array().map_or(&[][..], Vec::as_slice).iter().filter(|t| t["type"] == "page");
    let mut last = CdpError::Discovery(format!(":{port} lists no page target"));
    for target in pages {
        match target["webSocketDebuggerUrl"].as_str() {
            Some(url) => match Endpoint::from_ws_url(url, port) {
                Ok(endpoint) => return Ok(endpoint),
                Err(e) => last = e,
            },
            None => last = CdpError::Discovery(format!(":{port} page target is already being debugged")),
        }
    }
    Err(last)
}

/// A command queued by an event handler. `params` is JSON object text and is
/// wiped after sending (it may hold proxy credentials).
pub struct Command {
    pub method: &'static str,
    pub params: Zeroizing<String>,
}

/// Commands an [`EventHandler`] wants sent in response to an event. Handlers
/// run inside a receive loop, so they queue instead of sending and waiting.
#[derive(Default)]
pub struct Outbox(Vec<Command>);

impl Outbox {
    pub fn push(&mut self, method: &'static str, params: &Value) {
        self.0.push(Command { method, params: Zeroizing::new(params.to_string()) });
    }

    /// Queue pre-serialised params (for text that must not be copied around).
    pub fn push_raw(&mut self, method: &'static str, params: Zeroizing<String>) {
        self.0.push(Command { method, params });
    }

    #[cfg(test)]
    pub(crate) fn drain(&mut self) -> Vec<(&'static str, Value)> {
        self.0.drain(..).map(|c| (c.method, serde_json::from_str(&c.params).unwrap())).collect()
    }
}

/// Receives protocol events as they arrive — including while a command's
/// reply is awaited, because the reply can depend on answering one (a paused
/// navigation holds up `Page.navigate`).
pub trait EventHandler {
    fn on_event(&mut self, method: &str, params: &Value, out: &mut Outbox);
}

/// A handler that ignores everything.
#[cfg(test)]
pub struct NoEvents;

#[cfg(test)]
impl EventHandler for NoEvents {
    fn on_event(&mut self, _method: &str, _params: &Value, _out: &mut Outbox) {}
}

/// One attached DevTools session. Owned by a single thread.
pub struct Cdp {
    ws: WebSocket<TcpStream>,
    next_id: u64,
    noreply: HashSet<u64>,
    cancel: Arc<AtomicBool>,
    alive: bool,
}

impl Cdp {
    /// Open the websocket to a validated endpoint. `cancel` aborts any wait.
    pub fn connect(endpoint: &Endpoint, cancel: Arc<AtomicBool>) -> Result<Cdp, CdpError> {
        let closed = |what: &str, e: &dyn std::fmt::Display| CdpError::Closed(format!("{what}: {e}"));
        let stream = TcpStream::connect_timeout(&loopback(endpoint.port), HANDSHAKE_TIMEOUT)
            .map_err(|e| closed("connect", &e))?;
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| closed("socket", &e))?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(|e| closed("socket", &e))?;
        let _ = stream.set_nodelay(true); // audit-allow: best-effort latency tweak
        // No Origin header is sent: Chromium then needs no allow-listed origin
        // at all, which keeps every browser-based client out.
        let url = format!("ws://127.0.0.1:{}{}", endpoint.port, endpoint.path);
        let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
        let (ws, _response) = tungstenite::client::client_with_config(url, stream, Some(config))
            .map_err(|e| closed("websocket handshake", &e))?;
        Ok(Cdp { ws, next_id: 0, noreply: HashSet::new(), cancel, alive: true })
    }

    /// False once the socket has failed; the session must then be dropped.
    pub fn is_alive(&self) -> bool {
        self.alive
    }

    fn dead(&mut self, what: &str, e: &dyn std::fmt::Display) -> CdpError {
        self.alive = false;
        CdpError::Closed(format!("{what}: {e}"))
    }

    /// Send one command; returns its id. `params` must be JSON object text.
    fn send(&mut self, method: &str, params: &str, want_reply: bool) -> Result<u64, CdpError> {
        if !self.alive {
            return Err(CdpError::Closed("socket already closed".into()));
        }
        self.next_id += 1;
        let id = self.next_id;
        let mut frame = Zeroizing::new(String::with_capacity(params.len() + method.len() + 40));
        frame.push_str("{\"id\":");
        frame.push_str(&id.to_string());
        frame.push_str(",\"method\":");
        pyjson::write_str(&mut frame, method);
        frame.push_str(",\"params\":");
        frame.push_str(params);
        frame.push('}');
        // Hand the buffer over without copying, so no second plaintext copy of
        // an injected credential is left behind in this process.
        let text = std::mem::take(&mut *frame);
        if let Err(e) = self.ws.send(Message::text(text)) {
            return Err(self.dead("send", &e));
        }
        if !want_reply {
            if self.noreply.len() >= MAX_NOREPLY {
                self.noreply.clear();
            }
            self.noreply.insert(id);
        }
        Ok(id)
    }

    /// Send a command whose reply is not awaited.
    pub fn send_nowait(&mut self, method: &str, params: &Value) -> Result<(), CdpError> {
        self.send(method, &params.to_string(), false).map(|_| ())
    }

    /// Read one message, waiting at most `wait`. `Ok(None)` on a quiet socket.
    fn read_message(&mut self, wait: Duration) -> Result<Option<Value>, CdpError> {
        let wait = wait.clamp(Duration::from_millis(1), SLICE);
        if let Err(e) = self.ws.get_ref().set_read_timeout(Some(wait)) {
            return Err(self.dead("socket", &e));
        }
        match self.ws.read() {
            Ok(Message::Text(text)) => match serde_json::from_str::<Value>(text.as_str()) {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(self.dead("malformed message", &e)),
            },
            Ok(Message::Close(_)) => Err(self.dead("recv", &"closed by the browser")),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
            {
                Ok(None)
            }
            Err(e) => Err(self.dead("recv", &e)),
        }
    }

    /// Route one incoming non-reply message to the handler and send whatever
    /// it queued.
    fn dispatch(&mut self, msg: &Value, handler: &mut dyn EventHandler) -> Result<(), CdpError> {
        let Some(method) = msg["method"].as_str() else {
            return Ok(());
        };
        let mut out = Outbox::default();
        handler.on_event(method, &msg["params"], &mut out);
        for command in out.0 {
            self.send(command.method, &command.params, false)?;
        }
        Ok(())
    }

    /// Send a command and wait for its result, dispatching events meanwhile.
    ///
    /// The overall deadline holds even under a flood of unsolicited events
    /// (which keep every read returning early), and a browser that stops
    /// sending altogether hits the same deadline — either way the caller gets
    /// an error instead of a wedged control loop.
    pub fn rpc(
        &mut self,
        method: &str,
        params: &Value,
        timeout: Duration,
        handler: &mut dyn EventHandler,
    ) -> Result<Value, CdpError> {
        self.rpc_raw(method, &params.to_string(), timeout, handler)
    }

    fn rpc_raw(
        &mut self,
        method: &str,
        params: &str,
        timeout: Duration,
        handler: &mut dyn EventHandler,
    ) -> Result<Value, CdpError> {
        let id = self.send(method, params, true)?;
        let deadline = Instant::now() + timeout;
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(CdpError::Stopped);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(CdpError::Timeout(method.to_string()));
            }
            let Some(mut msg) = self.read_message(left)? else {
                continue;
            };
            match msg["id"].as_u64() {
                Some(reply) if reply == id => {
                    if let Some(error) = msg.get("error") {
                        let text = error["message"].as_str().unwrap_or("unspecified");
                        return Err(CdpError::Remote(format!(
                            "{method}: {}",
                            text.chars().take(200).collect::<String>()
                        )));
                    }
                    return Ok(msg["result"].take());
                }
                // A fire-and-forget reply, or one to a call that timed out.
                Some(other) => {
                    self.noreply.remove(&other);
                }
                None => self.dispatch(&msg, handler)?,
            }
        }
    }

    /// Process incoming events until `until`, the first event, or a stop —
    /// whichever comes first. Returns whether an event was handled.
    pub fn pump(&mut self, until: Instant, handler: &mut dyn EventHandler) -> Result<bool, CdpError> {
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(CdpError::Stopped);
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            let Some(msg) = self.read_message(left)? else {
                continue;
            };
            match msg["id"].as_u64() {
                Some(id) => {
                    self.noreply.remove(&id);
                }
                None => {
                    self.dispatch(&msg, handler)?;
                    return Ok(true);
                }
            }
        }
    }

    /// Evaluate `expression` in the page and return its value. The expression
    /// is wiped from this process's buffers after sending; a script error in
    /// the page yields `Null`, like any other valueless result.
    pub fn evaluate(
        &mut self,
        expression: &str,
        timeout: Duration,
        handler: &mut dyn EventHandler,
    ) -> Result<Value, CdpError> {
        let mut params = Zeroizing::new(String::with_capacity(expression.len() + 64));
        params.push_str("{\"expression\":");
        pyjson::write_str(&mut params, expression);
        params.push_str(",\"returnByValue\":true,\"awaitPromise\":false}");
        let mut result = self.rpc_raw("Runtime.evaluate", &params, timeout, handler)?;
        Ok(result["result"]["value"].take())
    }

    /// Close the socket (best effort).
    pub fn close(&mut self) {
        if self.alive {
            self.alive = false;
            let _ = self.ws.close(None); // audit-allow: best-effort close on drop
            let _ = self.ws.flush(); // audit-allow: best-effort close on drop
        }
        let _ = self.ws.get_ref().shutdown(std::net::Shutdown::Both); // audit-allow: best-effort, peer may be gone
    }
}

impl Drop for Cdp {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_page_endpoints_are_accepted() {
        let ok = Endpoint::from_ws_url("ws://127.0.0.1:9222/devtools/page/8A1B-2c3d", 9222).unwrap();
        assert_eq!(ok, Endpoint { port: 9222, path: "/devtools/page/8A1B-2c3d".into() });
        assert!(Endpoint::from_ws_url("ws://localhost:9222/devtools/page/ABC", 9222).is_ok());
        assert!(Endpoint::from_ws_url("ws://[::1]:9222/devtools/page/ABC", 9222).is_ok());
        for bad in [
            "ws://attacker.example:9222/devtools/page/ABC",
            "ws://10.0.0.5:9222/devtools/page/ABC",
            "ws://127.0.0.1.attacker.example:9222/devtools/page/ABC",
            "ws://127.0.0.1@attacker.example:9222/devtools/page/ABC",
            "ws://attacker.example@127.0.0.1:9222/devtools/page/ABC",
            "ws://127.0.0.1:9223/devtools/page/ABC",
            "ws://127.0.0.1/devtools/page/ABC",
            "wss://127.0.0.1:9222/devtools/page/ABC",
            "http://127.0.0.1:9222/devtools/page/ABC",
            "ws://127.0.0.1:9222/devtools/browser/ABC",
            "ws://127.0.0.1:9222/devtools/page/",
            "ws://127.0.0.1:9222/devtools/page/../../json",
            "ws://127.0.0.1:9222/devtools/page/ABC?x=1",
            "ws://127.0.0.1:9222/devtools/page/A\r\nHost: evil",
            "ws://2130706433:9222/devtools/page/ABC",
            "",
        ] {
            assert!(
                matches!(Endpoint::from_ws_url(bad, 9222), Err(CdpError::NotLoopback(_))),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn refusals_do_not_echo_the_url() {
        let err = Endpoint::from_ws_url("ws://attacker.example/devtools/page/\u{1b}[31mX", 1).unwrap_err();
        assert!(!err.to_string().contains("attacker") && !err.to_string().contains('\u{1b}'));
    }

    #[test]
    fn active_port_file() {
        let dir = std::env::temp_dir().join(format!("soc-web-port-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_active_port(&dir), None);
        std::fs::write(dir.join(ACTIVE_PORT_FILE), "41873\n/devtools/browser/abc\n").unwrap();
        assert_eq!(read_active_port(&dir), Some(41873));
        for junk in ["", "0\n", "99999\n", "port\n"] {
            std::fs::write(dir.join(ACTIVE_PORT_FILE), junk).unwrap();
            assert_eq!(read_active_port(&dir), None, "{junk:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
