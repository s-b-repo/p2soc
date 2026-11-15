//! Scanner-deception tarpit: a tiny HTTP server for port 80.
//!
//! A passing port scanner that asks for `admin.php`, `wp-login.php`, `.env`
//! and the like gets `200 OK` with plausible-looking junk (4–32 KiB) after a
//! 0.5–2 s drip; everything else gets a 404. The goal is to make automated
//! scanners waste real time and false-positive triage, without exposing
//! anything real. Off unless `SOC_TARPIT_ENABLE=1`.
//!
//! This is the one component that talks to arbitrary hosts, so every
//! resource a peer can consume is bounded:
//!
//! - **connections/threads** — a hard cap on open connections, enforced at
//!   accept time before any thread exists; over the cap the socket is closed;
//! - **time** — one deadline for the whole request head (a client trickling
//!   bytes cannot reset it), a bounded drip, and a deadline for the response;
//! - **memory** — a 4 KiB request head, a capped body, small thread stacks,
//!   and LRU-bounded per-source tables;
//! - **log volume** — per-request refusals are rate-limited, because the
//!   journal lives on an SD card and its size must not be attacker-driven.
//!
//! Standard library sockets and threads only; no async runtime.
//!
//! Signals: `SIGHUP` re-reads the paths file, `SIGUSR1` logs the top sources
//! and the worker usage, `SIGTERM`/`SIGINT` exit cleanly.

mod config;
mod junk;
mod lru;
mod paths;

pub use config::TarpitConfig;
pub use junk::{BodyKind, Rng, http_date, junk_body, mime_for, plausibility_headers};
pub use lru::{HitCounter, Lru, RateLimiter};
pub use paths::PathSet;

use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The request line and headers must fit in this; nothing more is ever read.
pub const MAX_HEAD: usize = 4096;
/// Stack of a connection thread (the request head and body live on the heap).
const CONN_STACK: usize = 128 * 1024;
/// At most this many refusal log lines per [`NOISY_WINDOW`].
const NOISY_LINES: u32 = 20;
const NOISY_WINDOW: Duration = Duration::from_secs(10);
/// Longest request path copied into a log line.
const LOG_PATH_MAX: usize = 256;

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic in one connection thread must not wedge every other one.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// Whole seconds since the Unix epoch.
fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// One JSON log line: `{"ts": ..., "event": ..., <fields>}`.
pub fn log_line(event: &str, fields: Value) -> String {
    let mut rec = serde_json::Map::new();
    rec.insert("ts".into(), json!((unix_now() * 1000.0).round() / 1000.0));
    rec.insert("event".into(), json!(event));
    if let Value::Object(extra) = fields {
        rec.extend(extra);
    }
    Value::Object(rec).to_string()
}

/// Write a log line to stderr (the journal). Lossy on a full pipe: logging
/// must never block or fail a request.
fn stderr_sink(line: &str) {
    let _ = writeln!(io::stderr().lock(), "{line}"); // audit-allow: best-effort, logging must never block or fail a request
}

fn clip(s: &str) -> &str {
    match s.char_indices().nth(LOG_PATH_MAX) {
        Some((end, _)) => s.get(..end).unwrap_or(s),
        None => s,
    }
}

/// Rate limit for log lines a remote peer can trigger at will.
#[derive(Debug)]
struct LogGate {
    window_start: Instant,
    lines: u32,
    suppressed: u64,
}

impl LogGate {
    fn new(now: Instant) -> LogGate {
        LogGate { window_start: now, lines: 0, suppressed: 0 }
    }

    /// `Some(n)` if a line may be written now (`n` lines were dropped since
    /// the last one), `None` to drop this one.
    fn admit(&mut self, now: Instant) -> Option<u64> {
        if now.saturating_duration_since(self.window_start) >= NOISY_WINDOW {
            self.window_start = now;
            self.lines = 0;
        }
        if self.lines >= NOISY_LINES {
            self.suppressed += 1;
            return None;
        }
        self.lines += 1;
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// The request line of an HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The target without its query string.
    pub path: String,
}

/// Parse the request line out of a request head. `None` for anything that is
/// not `METHOD target [HTTP/x.y]` — such a peer gets no answer at all.
pub fn parse_request(head: &[u8]) -> Option<Request> {
    let line = head.split(|b| *b == b'\n').next()?;
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_ascii_whitespace();
    let (method, target) = (parts.next()?, parts.next()?);
    let version = parts.next();
    let method_ok = method.len() <= 16 && method.bytes().all(|b| b.is_ascii_uppercase());
    if !method_ok || parts.next().is_some() || version.is_some_and(|v| !v.starts_with("HTTP/")) {
        return None;
    }
    let path = target.split('?').next().unwrap_or(target);
    Some(Request { method: method.to_string(), path: path.to_string() })
}

fn head_complete(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.windows(2).any(|w| w == b"\n\n")
}

/// Read a request head, bounded in size ([`MAX_HEAD`]) and in *total* time
/// (`deadline`). A per-read timeout would let a client hold a thread forever
/// by sending one byte at a time.
fn read_head(stream: &mut TcpStream, deadline: Instant) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; MAX_HEAD];
    let mut len = 0;
    while !head_complete(buf.get(..len)?) {
        let left = deadline.saturating_duration_since(Instant::now());
        if len == buf.len() || left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return None;
        }
        match stream.read(buf.get_mut(len..)?) {
            // The peer finished sending: answer if a full line arrived.
            Ok(0) => return buf.get(..len).filter(|head| head.contains(&b'\n')).map(<[u8]>::to_vec),
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None, // audit-allow: a failed read drops the connection unanswered
        }
    }
    buf.truncate(len);
    Some(buf)
}

/// `write_all` with one deadline for the whole buffer, so a peer that reads
/// a byte at a time cannot pin the thread.
fn write_all_by(stream: &mut TcpStream, mut data: &[u8], deadline: Instant) -> io::Result<()> {
    while !data.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        stream.set_write_timeout(Some(left))?;
        match stream.write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = data.get(n..).unwrap_or(&[]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn response_head(status: &str, now_secs: u64, headers: &[(&str, String)]) -> Vec<u8> {
    // No `Server` header: nothing here should fingerprint the implementation.
    let mut head = format!("HTTP/1.1 {status}\r\nDate: {}\r\n", http_date(now_secs));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    head.into_bytes()
}

/// The key a source is rate-limited under: its address, with an IPv4-mapped
/// address unwrapped and an IPv6 address reduced to its /64 — one host
/// controls a whole /64, so per-address buckets would never fill.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let [a, b, c, d, ..] = v6.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// A reserved worker slot, released on drop.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One open connection's share of the connection cap, released on drop —
/// including when its thread could not be spawned.
struct ConnGuard(Arc<Tarpit>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::AcqRel);
    }
}

type LogSink = Box<dyn Fn(&str) + Send + Sync>;

/// The tarpit's shared state.
pub struct Tarpit {
    cfg: TarpitConfig,
    paths: RwLock<Arc<PathSet>>,
    limiter: Mutex<RateLimiter<IpAddr>>,
    hits: Mutex<HitCounter<IpAddr>>,
    busy: AtomicUsize,
    conns: AtomicUsize,
    gate: Mutex<LogGate>,
    sink: LogSink,
}

impl Tarpit {
    /// A tarpit logging to stderr.
    pub fn new(cfg: TarpitConfig) -> Tarpit {
        Tarpit::with_sink(cfg, Box::new(stderr_sink))
    }

    /// A tarpit handing its log lines to `sink`.
    pub fn with_sink(cfg: TarpitConfig, sink: LogSink) -> Tarpit {
        Tarpit {
            paths: RwLock::new(Arc::new(PathSet::builtin())),
            limiter: Mutex::new(RateLimiter::new(cfg.burst, cfg.window, cfg.hit_cap)),
            hits: Mutex::new(HitCounter::new(cfg.hit_cap)),
            busy: AtomicUsize::new(0),
            conns: AtomicUsize::new(0),
            gate: Mutex::new(LogGate::new(Instant::now())),
            sink,
            cfg,
        }
    }

    pub fn cfg(&self) -> &TarpitConfig {
        &self.cfg
    }

    /// Matched requests being answered right now.
    pub fn busy(&self) -> usize {
        self.busy.load(Ordering::Acquire)
    }

    /// Connections currently open.
    pub fn open_connections(&self) -> usize {
        self.conns.load(Ordering::Acquire)
    }

    fn log(&self, event: &str, fields: Value) {
        (self.sink)(&log_line(event, fields));
    }

    /// Log an event a peer can trigger at will, within the log budget.
    fn log_noisy(&self, event: &str, mut fields: Value) {
        let Some(suppressed) = locked(&self.gate).admit(Instant::now()) else {
            return;
        };
        if suppressed > 0 {
            if let Some(map) = fields.as_object_mut() {
                map.insert("suppressed".into(), json!(suppressed));
            }
        }
        self.log(event, fields);
    }

    /// The live path set.
    pub fn paths(&self) -> Arc<PathSet> {
        Arc::clone(&self.paths.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// (Re)load the paths file. On failure the live set is left untouched: a
    /// misconfigured file must not change what the tarpit answers.
    pub fn reload_paths(&self) {
        let file = &self.cfg.paths_file;
        match paths::load(file) {
            Ok((set, file_seen)) => {
                let (exact, prefix) = set.counts();
                *self.paths.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(set);
                self.log(
                    "paths_reloaded",
                    json!({"path": file.display().to_string(), "file_seen": file_seen, "exact": exact, "prefix": prefix}),
                );
            }
            Err(e) => {
                self.log("paths_reload_failed", json!({"path": file.display().to_string(), "err": e.to_string()}));
            }
        }
    }

    /// Log the top-20 sources by hit count and the current worker usage.
    pub fn dump_hits(&self) {
        let top: Vec<Value> = locked(&self.hits)
            .top(20)
            .into_iter()
            .map(|(ip, hits)| json!({"ip": ip.to_string(), "hits": hits}))
            .collect();
        self.log(
            "metrics_dump",
            json!({
                "busy": self.busy(),
                "workers_max": self.cfg.max_workers,
                "conns": self.open_connections(),
                "conns_max": self.cfg.max_conns,
                "top": top,
            }),
        );
    }

    fn acquire_slot(&self) -> Option<Slot<'_>> {
        let mut seen = self.busy.load(Ordering::Acquire);
        while seen < self.cfg.max_workers {
            match self.busy.compare_exchange_weak(seen, seen + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Slot(&self.busy)),
                Err(now) => seen = now,
            }
        }
        None
    }

    fn send(stream: &mut TcpStream, head: &[u8], body: &[u8], timeout: Duration) {
        let deadline = Instant::now() + timeout;
        if write_all_by(stream, head, deadline).is_ok() {
            let _ = write_all_by(stream, body, deadline); // audit-allow: best-effort, the peer may have hung up
        }
        let _ = stream.shutdown(Shutdown::Both); // audit-allow: best-effort, the peer may already be gone
    }

    /// Serve one connection: read one request, answer (or not), close.
    fn handle(&self, mut stream: TcpStream, peer: SocketAddr) {
        let timeout = self.cfg.conn_timeout;
        let Some(req) = read_head(&mut stream, Instant::now() + timeout).as_deref().and_then(parse_request) else {
            return;
        };
        let ip = peer.ip().to_canonical();
        let now_secs = unix_secs();
        let zero_length = [("Content-Length", "0".to_string())];

        if !matches!(req.method.as_str(), "GET" | "HEAD" | "POST" | "PUT") {
            Tarpit::send(&mut stream, &response_head("501 Not Implemented", now_secs, &zero_length), b"", timeout);
            return;
        }
        if !self.paths().matches(&req.path) {
            Tarpit::send(&mut stream, &response_head("404 Not Found", now_secs, &zero_length), b"", timeout);
            return;
        }
        let who = || json!({"ip": ip.to_string(), "path": clip(&req.path)});

        // Reserve a worker slot. At the cap the socket is dropped silently —
        // a 503 would tell a flooder its strategy is working.
        let Some(_slot) = self.acquire_slot() else {
            let mut fields = who();
            fields["busy"] = json!(self.cfg.max_workers);
            self.log_noisy("dropped_at_cap", fields);
            return;
        };
        if !locked(&self.limiter).allow(source_key(ip)) {
            // No reply at all: a bot waiting on a response times out, which
            // costs it far more than reading a 429.
            self.log_noisy("rate_limited", who());
            return;
        }
        locked(&self.hits).bump(ip);

        // Drip — eat real scanner wall-clock. Bounded by `drip_max`.
        let mut rng = Rng::new();
        let drip = rng.uniform(self.cfg.drip_min.as_secs_f64(), self.cfg.drip_max.as_secs_f64()).max(0.0);
        thread::sleep(Duration::from_secs_f64(drip));

        let (content_type, kind) = mime_for(&req.path);
        let body = junk_body(kind, rng.range_len(4 * 1024, 32 * 1024), &mut rng);
        let mut headers = vec![("Content-Type", content_type.to_string()), ("Content-Length", body.len().to_string())];
        headers.extend(plausibility_headers(&req.path, &ip.to_string(), now_secs, &mut rng));
        // HEAD: the headers (with the real Content-Length) but no body.
        let sent_body: &[u8] = if req.method == "HEAD" { b"" } else { &body };
        Tarpit::send(&mut stream, &response_head("200 OK", now_secs, &headers), sent_body, timeout);
        self.log(
            "served",
            json!({
                "ip": ip.to_string(),
                "method": req.method,
                "path": clip(&req.path),
                "status": 200,
                "bytes": body.len(),
                "drip_s": (drip * 1000.0).round() / 1000.0,
            }),
        );
    }

    /// Accept connections until `stop` is set (checked after each accept).
    /// Each accepted connection gets a short-lived thread, up to the
    /// connection cap; beyond it the socket is closed at once.
    pub fn serve(self: &Arc<Self>, listener: &TcpListener, stop: &AtomicBool) {
        loop {
            let accepted = listener.accept();
            if stop.load(Ordering::Acquire) {
                return;
            }
            let Ok((stream, peer)) = accepted else {
                // A transient accept failure (e.g. out of file descriptors):
                // back off instead of spinning, then retry.
                thread::sleep(Duration::from_millis(50));
                continue;
            };
            if self.conns.fetch_add(1, Ordering::AcqRel) >= self.cfg.max_conns {
                self.conns.fetch_sub(1, Ordering::AcqRel);
                self.log_noisy("dropped_at_conn_cap", json!({"ip": peer.ip().to_canonical().to_string()}));
                continue;
            }
            let guard = ConnGuard(Arc::clone(self));
            let spawned = thread::Builder::new().name("tarpit-conn".into()).stack_size(CONN_STACK).spawn(move || {
                let guard = guard;
                guard.0.handle(stream, peer);
            });
            if let Err(e) = spawned {
                // The closure (socket and guard) was dropped with the error.
                self.log_noisy("spawn_failed", json!({"err": e.to_string()}));
            }
        }
    }
}

/// A tarpit serving on a background thread (tests, embedding).
pub struct Running {
    pub addr: SocketAddr,
    pub tarpit: Arc<Tarpit>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Running {
    /// Serve `tarpit` on `listener` in the background.
    pub fn start(tarpit: Arc<Tarpit>, listener: TcpListener) -> io::Result<Running> {
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let (t, s) = (Arc::clone(&tarpit), Arc::clone(&stop));
        let thread = thread::Builder::new().name("tarpit-accept".into()).spawn(move || t.serve(&listener, &s))?;
        Ok(Running { addr, tarpit, stop, thread: Some(thread) })
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake the blocking accept so the loop sees the flag.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1)); // audit-allow: best-effort wake-up of the accept loop
        if let Some(thread) = self.thread.take() {
            let _ = thread.join(); // audit-allow: best-effort, a panicked accept thread has nothing left to report
        }
    }
}

/// Bind the listening socket. An IPv6 literal selects an IPv6 socket;
/// anything else is IPv4, so existing deployments stay IPv4.
pub fn bind(host: &str, port: u16) -> io::Result<TcpListener> {
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => (host, port) // audit-allow: not an IP literal, so resolve it as a host name
            .to_socket_addrs()?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no IPv4 address for host"))?,
    };
    TcpListener::bind(addr)
}

/// The flags a signal sets. signal-hook installs an async-signal-safe handler
/// that only stores to these atomics; the watcher thread does the real work.
#[derive(Default)]
struct SignalFlags {
    hup: Arc<AtomicBool>,
    usr1: Arc<AtomicBool>,
    term: Arc<AtomicBool>,
}

impl SignalFlags {
    /// Register the handlers. Must run before the bind, so an early SIGHUP is
    /// never fatal. Returns the registrations' guard errors, if any.
    fn install(&self) -> std::io::Result<()> {
        use signal_hook::flag::register;
        register(signal_hook::consts::SIGHUP, Arc::clone(&self.hup))?;
        register(signal_hook::consts::SIGUSR1, Arc::clone(&self.usr1))?;
        for term in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
            register(term, Arc::clone(&self.term))?;
        }
        Ok(())
    }
}

fn watch_signals(tarpit: &Tarpit, flags: &SignalFlags) {
    loop {
        thread::sleep(Duration::from_millis(250));
        if flags.hup.swap(false, Ordering::AcqRel) {
            tarpit.reload_paths();
        }
        if flags.usr1.swap(false, Ordering::AcqRel) {
            tarpit.dump_hits();
        }
        if flags.term.load(Ordering::Acquire) {
            std::process::exit(0);
        }
    }
}

fn say(msg: &str) {
    let _ = writeln!(io::stderr().lock(), "[tarpit] {msg}"); // audit-allow: best-effort, a closed stderr is not actionable
}

/// [`tarpit_main`] with an explicit environment lookup.
pub fn tarpit_main_with(args: &[String], get: impl Fn(&str) -> Option<String>) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        say("usage: tarpit   (configured through SOC_TARPIT_* — see the unit file)");
        return 0;
    }
    // Refuse to start unless explicitly opted in — defence in depth against
    // an operator who installed the unit but did not mean to expose port 80.
    if get("SOC_TARPIT_ENABLE").as_deref() != Some("1") {
        say("SOC_TARPIT_ENABLE=1 not set — exiting.");
        return 0;
    }
    let cfg = TarpitConfig::from_lookup(get);
    let tarpit = Arc::new(Tarpit::new(cfg.clone()));
    tarpit.reload_paths();
    // Handlers go in before the bind, so an early SIGHUP is never fatal.
    let signals = SignalFlags::default();
    if signals.install().is_err() {
        say("cannot install signal handlers");
        return 1;
    }
    let listener = match bind(&cfg.host, cfg.port) {
        Ok(listener) => listener,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            say(&format!("cannot bind {}:{} (needs CAP_NET_BIND_SERVICE for port <1024)", cfg.host, cfg.port));
            return 1;
        }
        Err(e) => {
            say(&format!("bind failed: {e}"));
            return 1;
        }
    };
    let family = if listener.local_addr().is_ok_and(|a| a.is_ipv6()) { "inet6" } else { "inet" };
    tarpit.log(
        "listening",
        json!({
            "host": cfg.host,
            "port": cfg.port,
            "family": family,
            "burst": cfg.burst,
            "window": cfg.window.as_secs_f64(),
            "drip_min": cfg.drip_min.as_secs_f64(),
            "drip_max": cfg.drip_max.as_secs_f64(),
            "workers_max": cfg.max_workers,
            "conns_max": cfg.max_conns,
            "conn_timeout": cfg.conn_timeout.as_secs_f64(),
            "paths_file": cfg.paths_file.display().to_string(),
        }),
    );
    let watched = Arc::clone(&tarpit);
    if thread::Builder::new().name("tarpit-signals".into()).spawn(move || watch_signals(&watched, &signals)).is_err() {
        say("cannot start the signal watcher");
        return 1;
    }
    tarpit.serve(&listener, &AtomicBool::new(false));
    0
}

/// The `tarpit` entry point. Returns 0 when not enabled, 1 when the socket
/// cannot be bound; otherwise serves until terminated.
pub fn tarpit_main(args: &[String]) -> i32 {
    tarpit_main_with(args, |name| std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    type Logs = Arc<Mutex<Vec<String>>>;

    /// A config for loopback tests: no drip, short timeouts.
    fn quick() -> TarpitConfig {
        TarpitConfig {
            host: "127.0.0.1".into(),
            port: 0,
            drip_min: Duration::ZERO,
            drip_max: Duration::ZERO,
            conn_timeout: Duration::from_millis(1500),
            paths_file: "/nonexistent/tarpit-paths.list".into(),
            ..TarpitConfig::default()
        }
    }

    fn tarpit(cfg: TarpitConfig) -> (Arc<Tarpit>, Logs) {
        let logs: Logs = Arc::default();
        let sink = Arc::clone(&logs);
        (Arc::new(Tarpit::with_sink(cfg, Box::new(move |line| locked(&sink).push(line.to_string())))), logs)
    }

    fn start(cfg: TarpitConfig) -> (Running, Logs) {
        let (t, logs) = tarpit(cfg);
        let running = Running::start(t, bind("127.0.0.1", 0).unwrap()).unwrap();
        (running, logs)
    }

    fn connect(addr: SocketAddr) -> TcpStream {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream
    }

    /// Everything the server sends before closing (empty = dropped silently).
    fn read_all(mut stream: TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        // A reset counts as "closed without an answer", same as a clean EOF.
        let _ = stream.read_to_end(&mut out);
        out
    }

    fn request(addr: SocketAddr, raw: &str) -> Vec<u8> {
        let mut stream = connect(addr);
        // A server that has already closed the socket may fail the write.
        let _ = stream.write_all(raw.as_bytes());
        read_all(stream)
    }

    fn get(addr: SocketAddr, path: &str) -> Vec<u8> {
        request(addr, &format!("GET {path} HTTP/1.1\r\nHost: wall\r\nUser-Agent: scanner\r\n\r\n"))
    }

    fn split(response: &[u8]) -> (String, Vec<u8>) {
        let at = response.windows(4).position(|w| w == b"\r\n\r\n").expect("a complete response head");
        (String::from_utf8(response[..at].to_vec()).unwrap(), response[at + 4..].to_vec())
    }

    fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines()
            .skip(1)
            .find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v))
    }

    fn events(logs: &Logs, event: &str) -> Vec<Value> {
        locked(logs)
            .iter()
            .map(|l| serde_json::from_str::<Value>(l).expect("every log line is JSON"))
            .filter(|v| v["event"] == event)
            .collect()
    }

    /// Poll until `cond` holds (connection threads finish asynchronously).
    fn eventually(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn request_line_parsing() {
        let req = |raw: &str| parse_request(raw.as_bytes());
        assert_eq!(
            req("GET /admin.php?x=1&y=2 HTTP/1.1\r\nHost: h\r\n\r\n"),
            Some(Request { method: "GET".into(), path: "/admin.php".into() })
        );
        assert_eq!(req("HEAD /.env HTTP/1.0\n\n").unwrap().method, "HEAD");
        assert_eq!(req("GET /old-style\r\n").unwrap().path, "/old-style");
        for bad in
            ["", "\r\n\r\n", "GET\r\n", "get / HTTP/1.1", "GET / FTP/1.0", "GET / HTTP/1.1 extra", "G3T / HTTP/1.1"]
        {
            assert_eq!(req(bad), None, "{bad:?}");
        }
        assert_eq!(req(&format!("{} / HTTP/1.1", "A".repeat(17))), None);
        assert!(parse_request(b"GET /\xff\xfe HTTP/1.1\r\n\r\n").is_some(), "non-UTF-8 targets do not panic");
    }

    #[test]
    fn log_lines_are_single_json_objects() {
        let line = log_line("served", json!({"ip": "1.2.3.4", "path": "/x\n\"injected\": true", "status": 200}));
        assert!(!line.contains('\n'), "a hostile path cannot add a log line");
        let rec: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(rec["event"], "served");
        assert_eq!(rec["ip"], "1.2.3.4");
        assert_eq!(rec["status"], 200);
        assert!(rec["ts"].as_f64().is_some_and(|ts| ts > 1.0e9));
        assert!(line.starts_with("{\"ts\":"));
        assert_eq!(clip(&"é".repeat(LOG_PATH_MAX + 50)).chars().count(), LOG_PATH_MAX);
    }

    #[test]
    fn noisy_log_lines_are_budgeted() {
        let t0 = Instant::now();
        let mut gate = LogGate::new(t0);
        let admitted = (0..1000).filter(|_| gate.admit(t0).is_some()).count();
        assert_eq!(admitted, NOISY_LINES as usize);
        // the next window reports how many were dropped, then starts clean
        assert_eq!(gate.admit(t0 + NOISY_WINDOW), Some(1000 - u64::from(NOISY_LINES)));
        assert_eq!(gate.admit(t0 + NOISY_WINDOW), Some(0));
    }

    #[test]
    fn sources_are_keyed_by_address_or_ipv6_prefix() {
        let key = |s: &str| source_key(s.parse().unwrap());
        assert_eq!(key("192.0.2.7"), key("::ffff:192.0.2.7"));
        assert_ne!(key("192.0.2.7"), key("192.0.2.8"));
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:bbbb::2"), "one /64 is one source");
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
    }

    #[test]
    fn bind_picks_the_address_family_from_the_host() {
        assert!(bind("127.0.0.1", 0).unwrap().local_addr().unwrap().is_ipv4());
        assert!(bind("0.0.0.0", 0).unwrap().local_addr().unwrap().is_ipv4());
        // IPv6 may be disabled on a build host; when it binds it must be v6.
        if let Ok(listener) = bind("::1", 0) {
            assert!(listener.local_addr().unwrap().is_ipv6());
        }
    }

    /// Each connection is a thread, and the unit caps tasks: the default
    /// connection budget has to fit, or the kernel would refuse threads
    /// before our own cap is reached.
    #[test]
    fn default_connection_budget_fits_the_units_task_limit() {
        let unit = include_str!("../../../../../systemd/soc-tarpit.service");
        let tasks_max: usize =
            unit.lines().find_map(|l| l.strip_prefix("TasksMax=")).expect("TasksMax in the unit").parse().unwrap();
        // + the accept loop, the signal watcher and the main thread
        assert!(TarpitConfig::default().max_conns + 3 <= tasks_max, "{tasks_max}");
        assert!(unit.contains("Environment=SOC_TARPIT_ENABLE=0"), "the unit ships disabled");
    }

    #[test]
    fn not_enabled_means_exit_zero_without_binding() {
        assert_eq!(tarpit_main_with(&[], |_| None), 0);
        assert_eq!(tarpit_main_with(&[], |k| (k == "SOC_TARPIT_ENABLE").then(|| "0".to_string())), 0);
        assert_eq!(tarpit_main_with(&["--help".into()], |_| Some("1".into())), 0);
    }

    #[test]
    fn paths_reload_picks_up_the_file_and_survives_a_bad_one() {
        let t = TempDir::new("tarpit-reload");
        let file = t.write("paths.list", "# comment\n/private/data\n/secrets/* \n\n");
        let (tp, logs) = tarpit(TarpitConfig { paths_file: file.clone(), ..quick() });
        assert!(!tp.paths().matches("/private/data"));
        tp.reload_paths();
        assert!(tp.paths().matches("/private/data") && tp.paths().matches("/secrets/anything"));
        assert!(tp.paths().matches("/admin.php"), "built-in defaults survive");
        let reloaded = &events(&logs, "paths_reloaded")[0];
        assert_eq!(reloaded["file_seen"], true);
        assert_eq!(reloaded["path"], file.display().to_string());

        // An unusable file leaves the live set untouched.
        std::fs::write(&file, [0xff, 0xfe]).unwrap();
        tp.reload_paths();
        assert!(tp.paths().matches("/private/data"));
        assert_eq!(events(&logs, "paths_reload_failed").len(), 1);
        if crate::fsutil::euid() != 0 {
            std::fs::write(&file, "/should-not-load\n").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
            tp.reload_paths();
            assert!(!tp.paths().matches("/should-not-load") && tp.paths().matches("/private/data"));
            assert_eq!(events(&logs, "paths_reload_failed").len(), 2);
        }

        // A missing file restores the defaults; that is not an error.
        std::fs::remove_file(&file).unwrap();
        tp.reload_paths();
        assert!(tp.paths().matches("/admin.php") && !tp.paths().matches("/private/data"));
        assert_eq!(events(&logs, "paths_reloaded").last().unwrap()["file_seen"], false);
    }

    #[test]
    fn worker_slots_are_released() {
        let (tp, _) = tarpit(TarpitConfig { max_workers: 4, ..quick() });
        let held: Vec<_> = (0..4).map(|_| tp.acquire_slot()).collect();
        assert!(held.iter().all(Option::is_some));
        assert!(tp.acquire_slot().is_none(), "pool exhausted");
        assert_eq!(tp.busy(), 4);
        drop(held);
        assert_eq!(tp.busy(), 0);
        assert!(tp.acquire_slot().is_some());
    }

    #[test]
    fn metrics_dump_lists_the_top_sources() {
        let (tp, logs) = tarpit(quick());
        for i in 1..=30u8 {
            for _ in 0..i {
                locked(&tp.hits).bump(IpAddr::from([203, 0, 113, i]));
            }
        }
        tp.dump_hits();
        let dump = &events(&logs, "metrics_dump")[0];
        let top = dump["top"].as_array().unwrap();
        assert_eq!(top.len(), 20);
        assert_eq!(top[0], json!({"ip": "203.0.113.30", "hits": 30}));
        let hits: Vec<u64> = top.iter().map(|e| e["hits"].as_u64().unwrap()).collect();
        assert!(hits.windows(2).all(|w| w[0] >= w[1]));
        assert_eq!((dump["busy"].as_u64(), dump["workers_max"].as_u64()), (Some(0), Some(64)));
    }

    #[test]
    fn a_scanner_target_gets_plausible_junk() {
        let (srv, logs) = start(quick());
        let (head, body) = split(&get(srv.addr, "/admin.php"));
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert_eq!(header(&head, "Content-Type"), Some("text/html; charset=utf-8"));
        assert_eq!(header(&head, "Content-Length"), Some(body.len().to_string().as_str()));
        assert!((4096..=64 * 1024).contains(&body.len()), "{}", body.len());
        assert!(body.starts_with(b"<!doctype html"));
        assert!(header(&head, "ETag").is_some_and(|e| e.starts_with("W/\"")));
        assert!(header(&head, "Last-Modified").is_some_and(|d| d.ends_with(" GMT")));
        assert!(header(&head, "Date").is_some_and(|d| d.ends_with(" GMT")));
        assert_eq!(header(&head, "Cache-Control"), Some("no-store, no-cache, must-revalidate"));
        assert_eq!(header(&head, "Connection"), Some("close"));
        assert_eq!(header(&head, "Server"), None, "no implementation fingerprint");

        eventually("the served log line", || !events(&logs, "served").is_empty());
        let served = &events(&logs, "served")[0];
        assert_eq!(served["ip"], "127.0.0.1");
        assert_eq!(served["path"], "/admin.php");
        assert_eq!(served["method"], "GET");
        assert_eq!(served["bytes"], body.len());
    }

    #[test]
    fn the_query_string_is_ignored_and_the_type_fits_the_path() {
        let (srv, _) = start(quick());
        let (head, body) = split(&get(srv.addr, "/.env?debug=1"));
        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(header(&head, "Content-Type"), Some("text/plain; charset=utf-8"));
        assert!(body.contains(&b'='));
        let (head, body) = split(&get(srv.addr, "/api/v1/users"));
        assert_eq!(header(&head, "Content-Type"), Some("application/json"));
        assert!(serde_json::from_slice::<Value>(&body).is_ok());
    }

    #[test]
    fn head_gets_the_headers_without_the_body() {
        let (srv, _) = start(quick());
        let (head, body) = split(&request(srv.addr, "HEAD /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert!(header(&head, "Content-Length").unwrap().parse::<usize>().unwrap() >= 4096);
        assert!(body.is_empty());
    }

    #[test]
    fn post_and_put_are_tarpitted_like_get() {
        let (srv, _) = start(quick());
        for method in ["POST", "PUT"] {
            let raw = format!("{method} /wp-login.php HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
            assert!(request(srv.addr, &raw).starts_with(b"HTTP/1.1 200 OK"), "{method}");
        }
    }

    #[test]
    fn everything_else_is_a_bare_404() {
        let (srv, logs) = start(quick());
        for path in ["/", "/index.html", "/healthz", "/login"] {
            let (head, body) = split(&get(srv.addr, path));
            assert!(head.starts_with("HTTP/1.1 404 Not Found\r\n"), "{path}: {head}");
            assert_eq!(header(&head, "Content-Length"), Some("0"));
            assert_eq!(header(&head, "Connection"), Some("close"));
            assert!(body.is_empty());
        }
        assert!(events(&logs, "served").is_empty());
    }

    #[test]
    fn other_methods_get_a_bodyless_501() {
        let (srv, _) = start(quick());
        let (head, body) = split(&request(srv.addr, "DELETE /admin.php HTTP/1.1\r\n\r\n"));
        assert!(head.starts_with("HTTP/1.1 501 Not Implemented\r\n"), "{head}");
        assert!(body.is_empty());
    }

    #[test]
    fn garbage_is_dropped_without_an_answer() {
        let (srv, _) = start(quick());
        for raw in ["\r\n\r\n", "not http at all\r\n\r\n", "GET / SMTP\r\n\r\n", "\u{1}\u{2}\u{3}\n\n"] {
            assert!(request(srv.addr, raw).is_empty(), "{raw:?}");
        }
    }

    #[test]
    fn a_source_over_its_budget_gets_silence() {
        let (srv, logs) = start(TarpitConfig { burst: 2, window: Duration::from_secs(60), ..quick() });
        assert!(get(srv.addr, "/admin.php").starts_with(b"HTTP/1.1 200"));
        assert!(get(srv.addr, "/.env").starts_with(b"HTTP/1.1 200"));
        assert!(get(srv.addr, "/admin.php").is_empty(), "third hit: no reply at all");
        // a 404 costs nothing and is not rate limited
        assert!(get(srv.addr, "/").starts_with(b"HTTP/1.1 404"));
        eventually("the rate_limited log line", || !events(&logs, "rate_limited").is_empty());
        assert_eq!(events(&logs, "rate_limited")[0]["path"], "/admin.php");
        eventually("slots to be released", || srv.tarpit.busy() == 0);
    }

    #[test]
    fn the_drip_delays_the_answer() {
        let drip = Duration::from_millis(300);
        let (srv, _) = start(TarpitConfig { drip_min: drip, drip_max: drip, ..quick() });
        let started = Instant::now();
        assert!(get(srv.addr, "/admin.php").starts_with(b"HTTP/1.1 200"));
        assert!(started.elapsed() >= drip, "{:?}", started.elapsed());
    }

    #[test]
    fn a_trickling_client_is_cut_off_at_the_total_deadline() {
        let timeout = Duration::from_millis(400);
        let (srv, _) = start(TarpitConfig { conn_timeout: timeout, ..quick() });
        let mut stream = connect(srv.addr);
        stream.write_all(b"GET /admin.php HTTP/1.1\r\n").unwrap();
        eventually("the connection to be counted", || srv.tarpit.open_connections() == 1);
        let started = Instant::now();
        // One header byte every 100 ms: each read succeeds, so a per-read
        // timeout would never fire.
        let cut_off = (0..100).any(|_| {
            thread::sleep(Duration::from_millis(100));
            stream.write_all(b"X").is_err() || srv.tarpit.open_connections() == 0
        });
        assert!(cut_off, "the slow client was never disconnected");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(read_all(stream).is_empty(), "and it got no answer");
    }

    #[test]
    fn a_silent_client_is_dropped_too() {
        let (srv, _) = start(TarpitConfig { conn_timeout: Duration::from_millis(300), ..quick() });
        let started = Instant::now();
        assert!(read_all(connect(srv.addr)).is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn an_oversized_request_head_is_dropped() {
        let (srv, _) = start(quick());
        let mut stream = connect(srv.addr);
        let mut raw = b"GET /admin.php HTTP/1.1\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", 400).flatten());
        // The server may reset the connection once it has seen enough.
        let _ = stream.write_all(&raw);
        assert!(read_all(stream).is_empty());
        eventually("the connection to be released", || srv.tarpit.open_connections() == 0);
    }

    #[test]
    fn connections_beyond_the_cap_are_closed_at_once() {
        let (srv, logs) = start(TarpitConfig { max_conns: 2, conn_timeout: Duration::from_secs(4), ..quick() });
        // Two idle connections occupy the whole budget (each holds a thread).
        let idle = [connect(srv.addr), connect(srv.addr)];
        eventually("both connections to be counted", || srv.tarpit.open_connections() == 2);
        let started = Instant::now();
        assert!(get(srv.addr, "/admin.php").is_empty(), "the third connection gets nothing");
        assert!(started.elapsed() < Duration::from_secs(3), "and is not made to wait for a thread");
        assert_eq!(srv.tarpit.open_connections(), 2);
        assert_eq!(events(&logs, "dropped_at_conn_cap").len(), 1);
        // Freed capacity is usable again.
        drop(idle);
        eventually("the idle connections to be released", || srv.tarpit.open_connections() == 0);
        assert!(get(srv.addr, "/admin.php").starts_with(b"HTTP/1.1 200"));
    }

    #[test]
    fn matched_requests_beyond_the_worker_cap_are_dropped() {
        let drip = Duration::from_millis(1500);
        let (srv, logs) = start(TarpitConfig { max_workers: 1, drip_min: drip, drip_max: drip, ..quick() });
        let addr = srv.addr;
        let first = thread::spawn(move || get(addr, "/admin.php"));
        eventually("the first request to take the only slot", || srv.tarpit.busy() == 1);
        assert!(get(srv.addr, "/.env").is_empty(), "no slot: dropped silently");
        assert!(get(srv.addr, "/").starts_with(b"HTTP/1.1 404"), "unmatched paths need no slot");
        assert!(first.join().unwrap().starts_with(b"HTTP/1.1 200"));
        assert_eq!(events(&logs, "dropped_at_cap")[0]["path"], "/.env");
        eventually("the slot to be released", || srv.tarpit.busy() == 0);
    }

    #[test]
    fn many_parallel_clients_are_all_answered_and_all_released() {
        let (srv, _) = start(TarpitConfig { burst: 1000, ..quick() });
        let addr = srv.addr;
        let clients: Vec<_> = (0..24)
            .map(|i| thread::spawn(move || get(addr, if i % 2 == 0 { "/admin.php" } else { "/nothing-here" })))
            .collect();
        for (i, client) in clients.into_iter().enumerate() {
            let want: &[u8] = if i % 2 == 0 { b"HTTP/1.1 200" } else { b"HTTP/1.1 404" };
            assert!(client.join().unwrap().starts_with(want), "client {i}");
        }
        eventually("every connection to be released", || srv.tarpit.open_connections() == 0);
        assert_eq!(srv.tarpit.busy(), 0);
    }
}
