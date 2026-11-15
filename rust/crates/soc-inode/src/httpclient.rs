//! A tiny HTTP/1.1 client over an already-connected TLS stream (port of
//! `httpclient.py`).
//!
//! We can't use a generic HTTP library because the protocol needs full control
//! of header order and cookie strings, a custom `NET_EXTEND` verb that then
//! switches the same socket to a raw binary frame stream, and a long-lived
//! connection across many requests. This implements just enough: request
//! writing, response parsing (status line, headers, Content-Length AND chunked),
//! a flat cookie jar and redirect classification, with the hard caps from
//! `constants`.

use std::collections::BTreeMap;
use std::io::Write;

use crate::constants as c;
use crate::error::{InodeError, Result};
use crate::transport::TlsStream;

/// Which cookies to attach to a request.
pub enum Cookies<'a> {
    /// No `Cookie` header.
    None,
    /// The whole jar.
    All,
    /// A literal cookie string.
    Literal(String),
    /// Only these jar entries, in this order.
    Named(&'a [&'a str]),
}

/// A parsed HTTP response.
#[derive(Debug, Clone, Default)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub raw_status_line: String,
}

impl Response {
    /// First header value matching `name` (case-insensitive), or `default`.
    pub fn header<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        let nl = name.to_ascii_lowercase();
        self.headers.iter().find(|(k, _)| k.to_ascii_lowercase() == nl).map(|(_, v)| v.as_str()).unwrap_or(default)
    }

    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        let nl = name.to_ascii_lowercase();
        self.headers.iter().filter(|(k, _)| k.to_ascii_lowercase() == nl).map(|(_, v)| v.as_str()).collect()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn is_success(&self) -> bool {
        self.status == 200
    }

    pub fn is_redirect(&self) -> bool {
        c::REDIRECT_MIN <= self.status && self.status <= c::REDIRECT_MAX
    }
}

/// A minimal cookie store: name -> value, last-write-wins. The gateway uses a
/// flat namespace (svpnginfo / svpnvldid / svpnuid / vldID / domainId).
#[derive(Debug, Default)]
pub struct CookieJar {
    jar: BTreeMap<String, String>,
}

impl CookieJar {
    pub fn update_from_response(&mut self, resp: &Response) {
        for sc in resp.headers_all("Set-Cookie") {
            let first = sc.split(';').next().unwrap_or("").trim();
            if let Some((name, val)) = first.split_once('=') {
                self.jar.insert(name.trim().to_string(), val.trim().to_string());
            }
        }
    }

    pub fn set(&mut self, name: &str, value: &str) {
        self.jar.insert(name.to_string(), value.to_string());
    }

    pub fn get(&self, name: &str) -> String {
        self.jar.get(name).cloned().unwrap_or_else(String::new)
    }

    /// `name=value; ...` for all cookies (insertion-independent, sorted order).
    pub fn header_value_all(&self) -> String {
        self.jar.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("; ")
    }

    /// `name=value; ...` for the named cookies that are present, in order.
    pub fn header_value_named(&self, names: &[&str]) -> String {
        names.iter().filter_map(|n| self.jar.get(*n).map(|v| format!("{n}={v}"))).collect::<Vec<_>>().join("; ")
    }
}

/// A request's extra header lines (after Cookie, before Content-Type).
pub type Headers<'a> = &'a [(&'a str, &'a str)];

/// HTTP/1.1 over a connected TLS stream.
pub struct Connection {
    pub stream: TlsStream,
    pub host: String,
    pub port: u16,
    pub cookies: CookieJar,
    buf: Vec<u8>,
}

impl Connection {
    pub fn new(stream: TlsStream, host: &str, port: u16) -> Connection {
        Connection { stream, host: host.to_string(), port, cookies: CookieJar::default(), buf: Vec::new() }
    }

    // -- low level ---------------------------------------------------------
    fn recv_some(&mut self) -> Result<()> {
        let mut tmp = [0u8; 65536];
        let n = std::io::Read::read(&mut self.stream, &mut tmp).map_err(InodeError::Io)?;
        if n == 0 {
            return Err(InodeError::Http("connection closed by peer".into()));
        }
        self.buf.extend_from_slice(tmp.get(..n).unwrap_or(&[]));
        Ok(())
    }

    fn read_until(&mut self, marker: &[u8], cap: usize) -> Result<Vec<u8>> {
        loop {
            if let Some(idx) = find_subslice(&self.buf, marker) {
                let end = idx + marker.len();
                let out: Vec<u8> = self.buf.drain(..end).collect();
                return Ok(out);
            }
            if self.buf.len() > cap {
                return Err(InodeError::Http(format!(
                    "line/marker not found within {cap} bytes (hostile or non-HTTP response)"
                )));
            }
            self.recv_some()?;
        }
    }

    fn read_exact_n(&mut self, n: usize) -> Result<Vec<u8>> {
        if n > c::MAX_BODY_BYTES {
            return Err(InodeError::Http(format!("declared body size {n} exceeds cap {}", c::MAX_BODY_BYTES)));
        }
        while self.buf.len() < n {
            self.recv_some()?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// Return (and clear) any bytes already read past the HTTP response — needed
    /// when the socket switches to raw framing after `NET_EXTEND`.
    pub fn take_buffered(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Consume the connection, returning the raw TLS stream (for the tunnel pump
    /// after the `NET_EXTEND` upgrade). Any still-buffered bytes are dropped, so
    /// callers must `take_buffered` first.
    pub fn into_stream(self) -> TlsStream {
        self.stream
    }

    // -- requests ----------------------------------------------------------
    /// Send a request. When `read_response` is false (the `NET_EXTEND` upgrade)
    /// nothing is read back and `Ok(None)` is returned.
    #[allow(clippy::too_many_arguments)] // audit-allow: a faithful HTTP/1.1 request writer; the argument set mirrors the Python signature (method/path/headers/body/ua/cookies/host/read)
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers<'_>,
        body: &[u8],
        ua: &str,
        cookies: Cookies<'_>,
        host_header: Option<&str>,
        read_response: bool,
    ) -> Result<Option<Response>> {
        let mut host = host_header.unwrap_or(&self.host).to_string();
        if self.port != 80 && self.port != 443 {
            host = format!("{host}:{}", self.port);
        }
        let mut lines: Vec<String> = vec![
            format!("{method} {path} {}", c::HTTP_VERSION),
            format!("Host: {host}"),
            format!("User-Agent: {ua}"),
            "Connection: Keep-Alive".to_string(),
        ];
        let cookie_str = match cookies {
            Cookies::None => String::new(),
            Cookies::All => self.cookies.header_value_all(),
            Cookies::Literal(s) => s,
            Cookies::Named(names) => self.cookies.header_value_named(names),
        };
        if !cookie_str.is_empty() {
            lines.push(format!("Cookie: {cookie_str}"));
        }
        for (k, v) in headers {
            lines.push(format!("{k}: {v}"));
        }
        if !body.is_empty() {
            lines.push(format!("Content-Type: {}", c::FORM_CONTENT_TYPE));
            lines.push(format!("Content-Length: {}", body.len()));
        }
        let mut raw = lines.join("\r\n").into_bytes();
        raw.extend_from_slice(b"\r\n\r\n");
        raw.extend_from_slice(body);
        Write::write_all(&mut self.stream, &raw).map_err(InodeError::Io)?;
        Write::flush(&mut self.stream).map_err(InodeError::Io)?;
        if !read_response {
            return Ok(None);
        }
        let resp = self.read_response()?;
        self.cookies.update_from_response(&resp);
        Ok(Some(resp))
    }

    pub fn get(&mut self, path: &str, ua: &str, cookies: Cookies<'_>, headers: Headers<'_>) -> Result<Response> {
        self.request("GET", path, headers, b"", ua, cookies, None, true)?
            .ok_or_else(|| InodeError::Http("no response".into()))
    }

    pub fn post(
        &mut self,
        path: &str,
        body: &[u8],
        ua: &str,
        cookies: Cookies<'_>,
        headers: Headers<'_>,
    ) -> Result<Response> {
        self.request("POST", path, headers, body, ua, cookies, None, true)?
            .ok_or_else(|| InodeError::Http("no response".into()))
    }

    // -- response parsing --------------------------------------------------
    fn read_response(&mut self) -> Result<Response> {
        let head_bytes = self.read_until(b"\r\n\r\n", c::MAX_HEADER_BYTES)?;
        let head = String::from_utf8_lossy(&head_bytes);
        let mut it = head.split("\r\n");
        let status_line = it.next().unwrap_or("").to_string();
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        let code = parts.get(1).and_then(|s| s.parse::<u16>().ok());
        let Some(status) = code else {
            return Err(InodeError::Http(format!("bad status line: {status_line:?}")));
        };
        let reason = parts.get(2).copied().unwrap_or("").to_string();
        let mut headers: Vec<(String, String)> = Vec::new();
        for hl in it {
            if hl.is_empty() {
                continue;
            }
            if let Some((k, v)) = hl.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let mut resp = Response { status, reason, headers, body: Vec::new(), raw_status_line: status_line };

        let te = resp.header("Transfer-Encoding", "").to_ascii_lowercase();
        let body = if te.contains("chunked") {
            self.read_chunked()?
        } else {
            let cl = resp.header("Content-Length", "").to_string();
            match cl.trim().parse::<usize>().ok() {
                Some(n) => self.read_exact_n(n)?,
                None => Vec::new(),
            }
        };
        resp.body = body;
        Ok(resp)
    }

    fn read_chunked(&mut self) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let mut chunks = 0usize;
        loop {
            chunks += 1;
            if chunks > c::MAX_CHUNKS {
                return Err(InodeError::Http("too many chunks (hostile response)".into()));
            }
            let size_line = self.read_until(b"\r\n", c::MAX_HEADER_BYTES)?;
            let line = String::from_utf8_lossy(&size_line);
            let token = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(token, 16)
                .map_err(|e| InodeError::Http(format!("bad chunk size {token:?}: {e}")))?;
            if size == 0 {
                let mut trailers = 0usize;
                loop {
                    let l = self.read_until(b"\r\n", c::MAX_HEADER_BYTES)?;
                    if l == b"\r\n" {
                        break;
                    }
                    trailers += 1;
                    if trailers > c::MAX_TRAILER_LINES {
                        return Err(InodeError::Http("too many trailer lines (hostile response)".into()));
                    }
                }
                break;
            }
            let chunk = self.read_exact_n(size)?;
            out.extend_from_slice(&chunk);
            if out.len() > c::MAX_BODY_BYTES {
                return Err(InodeError::Http("chunked body exceeds size cap".into()));
            }
            self.read_exact_n(2)?; // CRLF after chunk (Vec dropped)
        }
        Ok(out)
    }
}

/// Find the first index of `needle` in `haystack`.
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
