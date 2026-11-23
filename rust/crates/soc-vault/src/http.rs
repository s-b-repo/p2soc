//! The one place that talks HTTP. Blocking `ureq`, no async runtime.
//!
//! Hardening that the transport owns:
//! * redirects are never followed, so a bearer token or master-password hash
//!   can never be replayed to wherever a `Location` header points;
//! * cleartext `http://` is only allowed to loopback unless explicitly opted in;
//! * TLS verifies against the system trust store (rustls, no OpenSSL);
//! * one overall deadline per request and a hard cap on every body, success or
//!   error, so a hostile endpoint can neither stall nor OOM a 1 GB board;
//! * server-supplied text is sanitised before it reaches an error message.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use soc_core::url::Url;
use zeroize::Zeroizing;

use crate::error::VaultError;

/// Cap on one response body. A real personal vault's `/api/ciphers` is far
/// below this; the ceiling stops a compromised endpoint streaming gigabytes.
pub const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// Error bodies are only ever summarised, so they get a much smaller cap.
const MAX_ERROR_BYTES: u64 = 64 * 1024;

/// Transport settings.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Overall deadline for one request, connect to last body byte.
    pub timeout: Duration,
    /// Permit `http://` to a non-loopback host. Off by default: the login
    /// request carries a password-equivalent hash and every later one a
    /// bearer token.
    pub allow_cleartext_remote: bool,
    /// A PEM bundle to trust instead of the system store (`$SSL_CERT_FILE`).
    pub ca_file: Option<PathBuf>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        HttpOptions { timeout: Duration::from_secs(20), allow_cleartext_remote: false, ca_file: None }
    }
}

impl HttpOptions {
    /// Settings from the process environment: `$SOC_VAULT_TIMEOUT` (seconds),
    /// `$SOC_VAULT_ALLOW_HTTP` and `$SSL_CERT_FILE`.
    pub fn from_env() -> HttpOptions {
        HttpOptions {
            timeout: Duration::from_secs_f64(soc_core::env::env_float(
                "SOC_VAULT_TIMEOUT",
                20.0,
                Some(1.0),
                Some(300.0),
            )),
            allow_cleartext_remote: soc_core::env::env_bool("SOC_VAULT_ALLOW_HTTP", false),
            ca_file: soc_core::env::env_str("SSL_CERT_FILE").map(PathBuf::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

/// A request body. `Form` values may be secret; the encoded body is wiped
/// after sending.
#[derive(Clone, Copy)]
pub(crate) enum Payload<'a> {
    None,
    Json(&'a Value),
    Form(&'a [(&'a str, &'a str)]),
}

/// A response with any status. Bodies are wiped on drop: the token response
/// carries bearer and refresh tokens.
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl Reply {
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub(crate) struct Http {
    agent: ureq::Agent,
    base: String,
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// TLS settings for an https vault: verify against the system trust store
/// (or the given bundle) with the rustls + ring provider. No OpenSSL, and no
/// bundled root set — a private CA installed on the box is honoured exactly as
/// the Python client honoured it.
#[cfg(feature = "tls")]
pub(crate) mod tls {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};

    use crate::error::VaultError;

    /// Where distributions keep their CA bundle, most common first.
    const CA_BUNDLES: [&str; 5] = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];

    fn load_roots(ca_file: Option<&Path>) -> Result<Vec<Certificate<'static>>, VaultError> {
        let candidates: Vec<PathBuf> = match ca_file {
            Some(explicit) => vec![explicit.to_path_buf()],
            None => CA_BUNDLES.iter().map(PathBuf::from).collect(),
        };
        for path in &candidates {
            let Ok(pem) = std::fs::read(path) else { continue };
            let certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(&pem)
                .filter_map(|item| match item {
                    Ok(PemItem::Certificate(cert)) => Some(cert),
                    _ => None,
                })
                .collect();
            if !certs.is_empty() {
                return Ok(certs);
            }
        }
        Err(VaultError::Config(
            "no usable CA certificate bundle found for an https vault (install ca-certificates or set SSL_CERT_FILE)"
                .into(),
        ))
    }

    pub(crate) fn config(ca_file: Option<&Path>) -> Result<TlsConfig, VaultError> {
        Ok(TlsConfig::builder()
            .root_certs(RootCerts::Specific(Arc::new(load_roots(ca_file)?)))
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build())
    }
}

/// `application/x-www-form-urlencoded`, the way Python's `urlencode` does it.
fn form_encode(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    fn push(out: &mut String, text: &str) {
        for b in text.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
                b' ' => out.push('+'),
                other => out.push_str(&format!("%{other:02X}")),
            }
        }
    }
    let mut out = Zeroizing::new(String::new());
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        push(&mut out, key);
        out.push('=');
        push(&mut out, value);
    }
    out
}

/// Keep server- or network-supplied text printable and short: it ends up in
/// logs and on the wall, and must not be able to forge log lines.
pub(crate) fn sanitize(text: &str) -> String {
    let cleaned: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The human-readable part of a Bitwarden/Vaultwarden error body.
pub(crate) fn error_detail(body: &[u8]) -> String {
    let Ok(json) = serde_json::from_slice::<Value>(body) else {
        return sanitize(&String::from_utf8_lossy(body));
    };
    let text = |v: Option<&Value>| v.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let model = json.get("ErrorModel").or_else(|| json.get("errorModel"));
    let mut detail = text(json.get("message"))
        .or_else(|| text(json.get("Message")))
        .or_else(|| text(model.and_then(|m| m.get("Message").or_else(|| m.get("message")))))
        .or_else(|| text(json.get("error_description")))
        .or_else(|| text(json.get("error")))
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    // Validation failures put the useful sentence one level down.
    let validation = json.get("validationErrors").or_else(|| json.get("ValidationErrors")).and_then(Value::as_object);
    if let Some(first) = validation.and_then(|v| v.values().next()).and_then(Value::as_array) {
        for line in first.iter().filter_map(Value::as_str) {
            detail.push_str(": ");
            detail.push_str(line);
        }
    }
    sanitize(&detail)
}

impl Http {
    /// Validate `base_url` and build an agent for it.
    pub(crate) fn new(base_url: &str, opts: &HttpOptions) -> Result<Http, VaultError> {
        let trimmed = base_url.trim().trim_end_matches('/');
        let bad = |why: &str| VaultError::Config(format!("invalid Vaultwarden URL: {why}"));
        let url = Url::split(trimmed).map_err(|e| bad(&e.to_string()))?;
        let https = match url.scheme.as_str() {
            "https" => true,
            "http" => false,
            _ => return Err(bad("it must start with http:// or https://")),
        };
        let host = url.host.as_deref().ok_or_else(|| bad("it has no host"))?;
        if url.userinfo.is_some() {
            return Err(bad("credentials must not be embedded in it"));
        }
        if url.rest.contains(['?', '#']) || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(bad("it must be a plain base URL"));
        }
        let loopback = is_loopback(host);
        if !https && !loopback && !opts.allow_cleartext_remote {
            return Err(VaultError::Config(format!(
                "refusing to send vault credentials to {trimmed} over cleartext http — use https, or set \
                 SOC_VAULT_ALLOW_HTTP=1 if the network path is trusted"
            )));
        }

        let mut config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .https_only(https)
            .timeout_global(Some(opts.timeout))
            .user_agent("soc-vault");
        if loopback {
            // A local vault must never be routed through an environment proxy.
            config = config.proxy(None);
        }
        #[cfg(feature = "tls")]
        if https {
            config = config.tls_config(tls::config(opts.ca_file.as_deref())?);
        }
        #[cfg(not(feature = "tls"))]
        if https {
            return Err(VaultError::Config(
                "this build has no TLS support, so an https:// vault URL cannot be used (rebuild with the `tls` feature)"
                    .into(),
            ));
        }
        Ok(Http { agent: config.build().new_agent(), base: trimmed.to_string() })
    }

    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    /// Send one request and return the reply whatever its status. Only
    /// transport failures and oversized bodies are errors here.
    pub(crate) fn send(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        payload: Payload<'_>,
    ) -> Result<Reply, VaultError> {
        let url = format!("{}{path}", self.base);
        let auth = bearer.map(|token| Zeroizing::new(format!("Bearer {token}")));
        let result = match method {
            Method::Get | Method::Delete => {
                let mut req = if method == Method::Get { self.agent.get(&url) } else { self.agent.delete(&url) };
                if let Some(value) = &auth {
                    req = req.header("Authorization", value.as_str());
                }
                req.call()
            }
            Method::Post | Method::Put => {
                let mut req = if method == Method::Post { self.agent.post(&url) } else { self.agent.put(&url) };
                if let Some(value) = &auth {
                    req = req.header("Authorization", value.as_str());
                }
                match payload {
                    Payload::None => req.send_empty(),
                    Payload::Json(value) => {
                        let body = Zeroizing::new(serde_json::to_vec(value).map_err(|e| {
                            VaultError::Protocol(format!("{} {url}: cannot encode the request: {e}", method.name()))
                        })?);
                        req.content_type("application/json").send(body.as_slice())
                    }
                    Payload::Form(pairs) => {
                        let body = form_encode(pairs);
                        req.content_type("application/x-www-form-urlencoded").send(body.as_bytes())
                    }
                }
            }
        };
        let response = result.map_err(|e| self.transport_error(method, &url, &e))?;
        let status = response.status().as_u16();
        let limit = if (200..300).contains(&status) { MAX_RESPONSE_BYTES } else { MAX_ERROR_BYTES };
        match response.into_body().into_with_config().limit(limit).read_to_vec() {
            Ok(body) => Ok(Reply { status, body: Zeroizing::new(body) }),
            // An oversized *error* body is not worth failing differently for:
            // the status alone is the answer.
            Err(ureq::Error::BodyExceedsLimit(_)) if limit == MAX_ERROR_BYTES => {
                Ok(Reply { status, body: Zeroizing::new(Vec::new()) })
            }
            Err(e) => Err(self.transport_error(method, &url, &e)),
        }
    }

    /// Send and require a 2xx; anything else becomes [`VaultError::Http`].
    pub(crate) fn request(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        payload: Payload<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let reply = self.send(method, path, bearer, payload)?;
        if reply.is_success() { Ok(reply.body) } else { Err(self.status_error(method, path, &reply)) }
    }

    pub(crate) fn status_error(&self, method: Method, path: &str, reply: &Reply) -> VaultError {
        let mut message = format!("{} {}{path} -> HTTP {}", method.name(), self.base, reply.status);
        let detail = if (300..400).contains(&reply.status) {
            "the server answered with a redirect, which is never followed (point the vault URL at the final address)"
                .to_string()
        } else {
            error_detail(&reply.body)
        };
        if !detail.is_empty() {
            message.push_str(": ");
            message.push_str(&detail);
        }
        VaultError::Http { status: reply.status, message }
    }

    fn transport_error(&self, method: Method, url: &str, e: &ureq::Error) -> VaultError {
        match e {
            ureq::Error::BodyExceedsLimit(_) => VaultError::Protocol(format!(
                "{} {url}: vault response exceeds {MAX_RESPONSE_BYTES} bytes",
                method.name()
            )),
            other => VaultError::Unreachable(format!(
                "could not reach Vaultwarden at {}: {}",
                self.base,
                sanitize(&other.to_string())
            )),
        }
    }
}

/// Parse a JSON body; an empty one is `{}` (Vaultwarden answers some writes
/// with no content).
pub(crate) fn parse_json(body: &[u8], what: &str) -> Result<Value, VaultError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    serde_json::from_slice(body)
        .map_err(|_| VaultError::Protocol(format!("{what}: the vault did not answer with JSON"))) // audit-allow: serde error text can quote response content; deliberately not echoed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{MockResponse, MockServer};

    fn opts() -> HttpOptions {
        HttpOptions { timeout: Duration::from_secs(5), ..HttpOptions::default() }
    }

    #[test]
    fn url_validation() {
        for good in ["http://127.0.0.1:8222", "http://localhost:8222/", "http://[::1]:8222", "http://127.0.0.1/vault/"]
        {
            assert!(Http::new(good, &opts()).is_ok(), "rejected {good}");
        }
        for bad in [
            "",
            "127.0.0.1:8222",
            "ftp://127.0.0.1",
            "http://",
            "http://user:pass@127.0.0.1:8222",
            "http://127.0.0.1:8222/?x=1",
            "http://127.0.0.1:8222/#frag",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:8222/a b",
        ] {
            assert!(matches!(Http::new(bad, &opts()), Err(VaultError::Config(_))), "accepted {bad:?}");
        }
        assert_eq!(Http::new("http://127.0.0.1:8222///", &opts()).unwrap().base(), "http://127.0.0.1:8222");
    }

    #[test]
    fn cleartext_to_a_remote_host_needs_an_explicit_opt_in() {
        let err = Http::new("http://vault.example.com", &opts()).err().unwrap();
        assert!(matches!(&err, VaultError::Config(m) if m.contains("cleartext")));
        assert!(matches!(Http::new("http://192.168.1.10:8222", &opts()), Err(VaultError::Config(_))));
        let allow = HttpOptions { allow_cleartext_remote: true, ..opts() };
        assert!(Http::new("http://vault.example.com", &allow).is_ok());
    }

    /// Real TLS handshakes against an in-process rustls server: the client must
    /// accept a chain to a trusted CA and refuse everything else.
    #[cfg(feature = "tls")]
    mod tls {
        use super::*;
        use std::sync::Arc;

        #[test]
        fn https_needs_a_ca_bundle_and_takes_an_explicit_one() {
            let missing = HttpOptions { ca_file: Some(PathBuf::from("/nonexistent/ca.pem")), ..opts() };
            assert!(
                matches!(Http::new("https://vault.example.com", &missing), Err(VaultError::Config(m)) if m.contains("CA"))
            );
        }

        // A throwaway P-256 test CA, a leaf it signed for 127.0.0.1 / localhost, and
        // an unrelated CA. Generated with openssl for these tests only.
        const TEST_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBnzCCAUWgAwIBAgIUPa0+VVjoAzIqw17Pny26/drEQUUwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRc29jLXZhdWx0IHRlc3QgQ0EwIBcNMjYxMTEzMTEwNTI5WhgP
MjEyNjEwMjAxMTA1MjlaMBwxGjAYBgNVBAMMEXNvYy12YXVsdCB0ZXN0IENBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWx1/5pFW7mbSyZVZta8137p74ZG9cv30
YuMLIllp1GWKyR6x5LqFI7zvLXZgswSXY+2tfFmzPCukKQ+hk4u5yqNjMGEwHQYD
VR0OBBYEFLNkDdfdVoBgZgKHIwYT5BxVnhbkMB8GA1UdIwQYMBaAFLNkDdfdVoBg
ZgKHIwYT5BxVnhbkMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoG
CCqGSM49BAMCA0gAMEUCIQCm0quu419+35sjSgZkQIq85rrfvSqd6DSs93mboJnf
ZQIgQVKs4Z+UhjINQMai/zqT/EVbxCMngt1E8W5XDvKG7oA=
-----END CERTIFICATE-----
";
        const TEST_LEAF: &str = "-----BEGIN CERTIFICATE-----
MIIBxzCCAW2gAwIBAgIUdo2TgrzILCq3vAOcSJcnCMnUwekwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRc29jLXZhdWx0IHRlc3QgQ0EwIBcNMjYxMTEzMTEwNTI5WhgP
MjEyNjEwMjAxMTA1MjlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABOYYTZd845VhpQCw93egL2teVQ7nxYZOsCX/iDZgL7O7
FISVdDcoi6qKRdTzfqIXi/+se2qablpWm7YFo4rzedejgZIwgY8wGgYDVR0RBBMw
EYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBRRw6tOxrgcws6GOoWw5Egj
zKt/UzAfBgNVHSMEGDAWgBSzZA3X3VaAYGYChyMGE+QcVZ4W5DAKBggqhkjOPQQD
AgNIADBFAiAq6mRSGD0jLvpggfWgT1OwTdHTg/YHa6U2I0W1Mm4uyAIhALDIxKCp
7Uc2OcTl7Ks3glypjgFGg1XVU75ZA+nPtcqe
-----END CERTIFICATE-----
";
        /// The leaf's PKCS#8 key, base64 DER. It protects nothing: only these tests trust `TEST_CA`.
        const TEST_LEAF_KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8h/6Cl5DEOQX2cNta34FV7H0fgmB2AAzvyXvhA7YeTihRANCAATmGE2XfOOVYaUAsPd3oC9rXlUO58WGTrAl/4g2YC+zuxSElXQ3KIuqikXU836iF4v/rHtqmm5aVpu2BaOK83nX";
        const OTHER_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBhzCCAS2gAwIBAgIUFg4IQrsimN6XLIuoszyNyv+hUf4wCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNc29tZSBvdGhlciBDQTAgFw0yNjExMTMxMTA1MzBaGA8yMTI2
MTAyMDExMDUzMFowGDEWMBQGA1UEAwwNc29tZSBvdGhlciBDQTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABD0+R9VMKtBa6baU3dQ5kOx9WMqrqxWAV3kep92Kxf+z
ROM2DCKpVD1D0rNXme/eOchvovtFkoobXV3JiTPnFLCjUzBRMB0GA1UdDgQWBBTh
tHTyLW7G1NKoGetHuuULUfiDQDAfBgNVHSMEGDAWgBThtHTyLW7G1NKoGetHuuUL
UfiDQDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBABZrYffkX7
huftD8hHA2byfamYAlKQVdn+bLKiaQBmAiEA4UwaX29ZQFyBUZw2rlMpq10XLjkF
J6pZjr3WP2hGGl4=
-----END CERTIFICATE-----
";

        /// A one-response-per-connection HTTPS server presenting `TEST_LEAF`.
        struct TlsServer {
            addr: std::net::SocketAddr,
            stop: Arc<std::sync::atomic::AtomicBool>,
            thread: Option<std::thread::JoinHandle<()>>,
        }

        impl TlsServer {
            fn start(bind: &str) -> TlsServer {
                use rustls::pki_types::pem::PemObject;
                use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
                use std::io::{Read, Write};
                use std::sync::atomic::Ordering;
                let certs = vec![CertificateDer::from_pem_slice(TEST_LEAF.as_bytes()).unwrap()];
                let key_der =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, TEST_LEAF_KEY_DER).unwrap();
                let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
                let config =
                    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                        .with_safe_default_protocol_versions()
                        .unwrap()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .unwrap();
                let config = Arc::new(config);
                let listener = std::net::TcpListener::bind(bind).unwrap();
                let addr = listener.local_addr().unwrap();
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stopping = Arc::clone(&stop);
                let thread = std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        if stopping.load(Ordering::SeqCst) {
                            break;
                        }
                        let Ok(stream) = stream else { continue };
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let conn = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                        let mut tls = rustls::StreamOwned::new(conn, stream);
                        let mut seen = Vec::new();
                        let mut chunk = [0u8; 1024];
                        // A client that rejects our certificate aborts here; that is the point of the test.
                        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                            match tls.read(&mut chunk) {
                                Ok(n) if n > 0 => seen.extend_from_slice(&chunk[..n]),
                                _ => break,
                            }
                        }
                        if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                            let _ = tls.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"tls\":true}",
                            );
                            tls.conn.send_close_notify();
                            let _ = tls.flush();
                        }
                    }
                });
                TlsServer { addr, stop, thread: Some(thread) }
            }
        }

        impl Drop for TlsServer {
            fn drop(&mut self) {
                self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = std::net::TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
        }

        fn with_ca(dir: &crate::fsutil::testdir::TestDir, pem: &str) -> HttpOptions {
            let path = dir.path().join("ca.pem");
            std::fs::write(&path, pem).unwrap();
            HttpOptions { ca_file: Some(path), ..opts() }
        }

        #[test]
        fn https_works_against_a_certificate_from_a_trusted_ca() {
            let dir = crate::fsutil::testdir::TestDir::new("tls-ok");
            let server = TlsServer::start("127.0.0.1:0");
            let http = Http::new(&format!("https://{}", server.addr), &with_ca(&dir, TEST_CA)).unwrap();
            let body = http.request(Method::Get, "/api/ciphers", Some("tok"), Payload::None).unwrap();
            assert_eq!(parse_json(&body, "tls").unwrap(), serde_json::json!({"tls": true}));
        }

        #[test]
        fn https_rejects_an_untrusted_issuer() {
            let dir = crate::fsutil::testdir::TestDir::new("tls-untrusted");
            let server = TlsServer::start("127.0.0.1:0");
            let http = Http::new(&format!("https://{}", server.addr), &with_ca(&dir, OTHER_CA)).unwrap();
            let e = http.request(Method::Get, "/api/ciphers", Some("tok"), Payload::None).unwrap_err();
            assert!(matches!(e, VaultError::Unreachable(_)), "{e:?}");
        }

        #[test]
        fn https_rejects_a_certificate_for_another_host() {
            // The leaf is valid for 127.0.0.1 only; the same server reached as 127.0.0.2 must fail.
            let dir = crate::fsutil::testdir::TestDir::new("tls-hostname");
            let server = TlsServer::start("127.0.0.2:0");
            let http = Http::new(&format!("https://{}", server.addr), &with_ca(&dir, TEST_CA)).unwrap();
            let e = http.request(Method::Get, "/api/ciphers", Some("tok"), Payload::None).unwrap_err();
            assert!(matches!(e, VaultError::Unreachable(_)), "{e:?}");
        }

        #[test]
        fn https_never_downgrades_to_plain_http() {
            // An https URL pointed at a plain-HTTP listener must fail, not fall back.
            let dir = crate::fsutil::testdir::TestDir::new("tls-plain");
            let plain = MockServer::start(|_| MockResponse::text(200, "{}"));
            let url = plain.url.replace("http://", "https://");
            let http = Http::new(&url, &with_ca(&dir, TEST_CA)).unwrap();
            let e = http.request(Method::Get, "/x", Some("tok"), Payload::None).unwrap_err();
            assert!(matches!(e, VaultError::Unreachable(_)), "{e:?}");
            assert!(plain.requests().iter().all(|r| r.header("authorization").is_none()));
        }
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn https_is_refused_by_a_build_without_tls() {
        assert!(
            matches!(Http::new("https://vault.example.com", &opts()), Err(VaultError::Config(m)) if m.contains("TLS"))
        );
    }

    #[test]
    fn form_encoding_matches_urlencode() {
        let encoded = form_encode(&[("scope", "api offline_access"), ("password", "a+b/c=="), ("u", "é@x.com")]);
        assert_eq!(encoded.as_str(), "scope=api+offline_access&password=a%2Bb%2Fc%3D%3D&u=%C3%A9%40x.com");
    }

    #[test]
    fn json_and_form_requests_reach_the_server_intact() {
        let server = MockServer::start(|req| {
            let echo = serde_json::json!({
                "method": req.method, "path": req.path,
                "type": req.header("content-type"), "auth": req.header("authorization"),
                "body": String::from_utf8_lossy(&req.body),
            });
            MockResponse::json(200, &echo)
        });
        let http = Http::new(&server.url, &opts()).unwrap();

        let body =
            http.request(Method::Post, "/a", None, Payload::Json(&serde_json::json!({"email": "a@b.c"}))).unwrap();
        let seen = parse_json(&body, "echo").unwrap();
        assert_eq!(seen["method"], "POST");
        assert_eq!(seen["path"], "/a");
        assert_eq!(seen["type"], "application/json");
        assert_eq!(seen["body"], "{\"email\":\"a@b.c\"}");
        assert_eq!(seen["auth"], Value::Null);

        let body = http.request(Method::Put, "/b", Some("tok"), Payload::Form(&[("k", "v w")])).unwrap();
        let seen = parse_json(&body, "echo").unwrap();
        assert_eq!(seen["method"], "PUT");
        assert_eq!(seen["type"], "application/x-www-form-urlencoded");
        assert_eq!(seen["body"], "k=v+w");
        assert_eq!(seen["auth"], "Bearer tok");

        let body = http.request(Method::Delete, "/c", Some("tok"), Payload::None).unwrap();
        assert_eq!(parse_json(&body, "echo").unwrap()["method"], "DELETE");
        let body = http.request(Method::Get, "/d", None, Payload::None).unwrap();
        assert_eq!(parse_json(&body, "echo").unwrap()["method"], "GET");
    }

    #[test]
    fn error_statuses_carry_a_sanitised_server_message() {
        let server = MockServer::start(|req| match req.path.as_str() {
            "/vw" => MockResponse::json(
                400,
                &serde_json::json!({"error": "invalid_grant", "error_description": "x",
                    "ErrorModel": {"Message": "Username or password is incorrect. Try again"}}),
            ),
            "/msg" => MockResponse::json(
                400,
                &serde_json::json!({"message": "Registration not allowed or user already exists"}),
            ),
            "/validation" => MockResponse::json(
                400,
                &serde_json::json!({"message": "The model state is invalid.", "validationErrors": {"": ["Email is taken"]}}),
            ),
            "/html" => MockResponse::text(502, "<html>\r\nBad\x1b[31m Gateway\n</html>"),
            "/forge" => MockResponse::text(500, &format!("a\n[soc-kiosk] fake line {}", "x".repeat(500))),
            "/empty" => MockResponse::text(401, ""),
            _ => MockResponse::text(404, "nope"),
        });
        let http = Http::new(&server.url, &opts()).unwrap();
        let fail = |path: &str| http.request(Method::Get, path, None, Payload::None).unwrap_err();

        let e = fail("/vw");
        assert_eq!(e.http_status(), Some(400));
        assert!(e.to_string().ends_with("/vw -> HTTP 400: Username or password is incorrect. Try again"), "{e}");
        assert!(fail("/msg").to_string().contains("Registration not allowed or user already exists"));
        assert!(fail("/validation").to_string().contains("The model state is invalid.: Email is taken"));

        let html = fail("/html").to_string();
        assert!(html.contains("HTTP 502") && html.contains("Bad") && !html.contains('\n') && !html.contains('\x1b'));
        let forged = fail("/forge").to_string();
        assert!(!forged.contains('\n') && forged.len() < 400);
        assert_eq!(fail("/empty").http_status(), Some(401));
        assert!(fail("/empty").to_string().ends_with("-> HTTP 401"));
    }

    #[test]
    fn redirects_are_reported_not_followed() {
        let target = MockServer::start(|_| MockResponse::text(200, "{\"leaked\": true}"));
        let location = format!("{}/steal", target.url);
        let server = MockServer::start(move |_| MockResponse::text(302, "").with_header("Location", &location));
        let http = Http::new(&server.url, &opts()).unwrap();
        let e = http.request(Method::Get, "/api/ciphers", Some("secret-token"), Payload::None).unwrap_err();
        assert_eq!(e.http_status(), Some(302));
        assert!(e.to_string().contains("redirect"));
        assert!(target.requests().is_empty(), "the redirect target must never be contacted");
    }

    #[test]
    fn oversized_and_non_json_bodies_are_protocol_errors() {
        let server = MockServer::start(|req| match req.path.as_str() {
            "/big" => MockResponse::raw_with_length(200, MAX_RESPONSE_BYTES + 1),
            "/big-error" => MockResponse::raw_with_length(500, MAX_ERROR_BYTES + 1),
            _ => MockResponse::text(200, "<html>captive portal</html>"),
        });
        let http = Http::new(&server.url, &opts()).unwrap();
        let e = http.request(Method::Get, "/big", None, Payload::None).unwrap_err();
        assert!(matches!(&e, VaultError::Protocol(m) if m.contains("exceeds")), "{e:?}");
        let e = http.request(Method::Get, "/big-error", None, Payload::None).unwrap_err();
        assert_eq!(e.http_status(), Some(500));
        let body = http.request(Method::Get, "/html", None, Payload::None).unwrap();
        assert!(matches!(parse_json(&body, "GET /html"), Err(VaultError::Protocol(_))));
        assert_eq!(parse_json(b"  \n", "x").unwrap(), serde_json::json!({}));
    }

    #[test]
    fn a_dead_port_is_unreachable_and_a_stalled_server_times_out() {
        let dead = crate::testutil::dead_url();
        let http = Http::new(&dead, &opts()).unwrap();
        let e = http.request(Method::Get, "/x", None, Payload::None).unwrap_err();
        assert!(matches!(&e, VaultError::Unreachable(m) if m.contains("could not reach Vaultwarden")), "{e:?}");
        assert!(e.is_transient());

        let stalled = MockServer::start(|_| {
            std::thread::sleep(Duration::from_secs(4));
            MockResponse::text(200, "{}")
        });
        let quick = HttpOptions { timeout: Duration::from_millis(300), ..HttpOptions::default() };
        let http = Http::new(&stalled.url, &quick).unwrap();
        let started = std::time::Instant::now();
        let e = http.request(Method::Get, "/x", None, Payload::None).unwrap_err();
        assert!(matches!(e, VaultError::Unreachable(_)));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
