//! RAW TLS over `std::net::TcpStream` with rustls (port of `transport.py`).
//!
//! This is deliberately NOT an HTTP library: after the `NET_EXTEND` upgrade the
//! same socket carries binary frames, so we need ownership of the byte stream.
//!
//! Trust options mirror the Python client: full verification (system roots or a
//! `--cafile` bundle), a SHA-256 certificate pin (the secure way to trust a
//! self-signed gateway — implemented as a rustls `ServerCertVerifier` with a
//! constant-time compare), `--insecure` (accept any cert), an optional client
//! certificate for mutual TLS and an SNI override. GM/SM2 (CNTLS) is out of
//! scope and noted as a limitation.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{InodeError, Result};

/// TLS settings for one connection.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub verify: bool,
    pub cafile: Option<String>,
    /// SHA-256 cert pin (hex, colons/spaces optional). Overrides CA/hostname.
    pub pin_sha256: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub server_hostname: Option<String>,
    /// "1.0" / "1.2" / None. rustls has no TLS<1.2, so "1.0" is treated as 1.2.
    pub min_tls: Option<String>,
    pub timeout: Duration,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            verify: true,
            cafile: None,
            pin_sha256: None,
            client_cert: None,
            client_key: None,
            server_hostname: None,
            min_tls: None,
            timeout: Duration::from_secs(30),
        }
    }
}

/// An owned TLS byte stream. Implements `Read`/`Write` for the HTTP client and
/// exposes the raw fd so the tunnel pump can `poll` it.
pub struct TlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
}

impl TlsStream {
    pub fn raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }

    /// The underlying TCP socket, for `poll`-based readiness checks.
    pub fn get_ref(&self) -> &TcpStream {
        self.inner.get_ref()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.inner.get_ref().set_read_timeout(dur)?;
        Ok(())
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.inner.get_ref().set_write_timeout(dur)?;
        Ok(())
    }

    /// Best-effort half-close, used to break the pump out of a blocking read.
    pub fn shutdown(&self) {
        drop(self.inner.get_ref().shutdown(Shutdown::Both));
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// --------------------------------------------------------------------------
// certificate verifiers (pin / insecure)
// --------------------------------------------------------------------------
/// Accepts any certificate whose SHA-256 matches the pin (constant-time). This
/// is the correct way to trust a self-signed gateway whose CN does not match.
#[derive(Debug)]
struct PinVerifier {
    provider: Arc<CryptoProvider>,
    pin: Vec<u8>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let got = Sha256::digest(end_entity.as_ref());
        let matches = got.len() == self.pin.len() && bool::from(got.as_slice().ct_eq(self.pin.as_slice()));
        if matches {
            Ok(ServerCertVerified::assertion())
        } else {
            let want = hex_lower(&self.pin);
            let peer = hex_lower(got.as_slice());
            Err(rustls::Error::General(format!("certificate pin mismatch: peer={peer} expected={want}")))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Accepts ANY certificate (the `--insecure` escape hatch; prefer a pin).
#[derive(Debug)]
struct InsecureVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

// --------------------------------------------------------------------------
// config building / connect
// --------------------------------------------------------------------------
fn build_client_config(cfg: &TlsConfig) -> Result<ClientConfig> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| InodeError::Tls(format!("TLS provider setup failed: {e}")))?;

    // Verifier: pin > insecure > full verification.
    let builder = if let Some(pin) = cfg.pin_sha256.as_deref().filter(|p| !p.is_empty()) {
        let verifier = Arc::new(PinVerifier { provider: Arc::clone(&provider), pin: parse_pin(pin)? });
        builder.dangerous().with_custom_certificate_verifier(verifier)
    } else if !cfg.verify {
        let verifier = Arc::new(InsecureVerifier { provider: Arc::clone(&provider) });
        builder.dangerous().with_custom_certificate_verifier(verifier)
    } else {
        builder.with_root_certificates(load_roots(cfg.cafile.as_deref())?)
    };

    // Optional client certificate for mutual TLS.
    let config = match cfg.client_cert.as_deref().filter(|p| !p.is_empty()) {
        Some(cert_path) => {
            let (certs, key) = load_client_auth(cert_path, cfg.client_key.as_deref())?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| InodeError::Tls(format!("client certificate rejected: {e}")))?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(config)
}

fn load_roots(cafile: Option<&str>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    match cafile {
        Some(path) => {
            let mut added = 0usize;
            for item in CertificateDer::pem_file_iter(path)
                .map_err(|e| InodeError::Tls(format!("could not read CA bundle {path}: {e}")))?
            {
                let cert = item.map_err(|e| InodeError::Tls(format!("bad certificate in {path}: {e}")))?;
                if roots.add(cert).is_ok() {
                    added += 1;
                }
            }
            if added == 0 {
                return Err(InodeError::Tls(format!("no usable certificates in CA bundle {path}")));
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                drop(roots.add(cert));
            }
            if roots.is_empty() {
                return Err(InodeError::Tls(
                    "no system trust roots found (install ca-certificates, use --cafile or --pin-sha256)".into(),
                ));
            }
        }
    }
    Ok(roots)
}

fn load_client_auth(
    cert_path: &str,
    key_path: Option<&str>,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut certs = Vec::new();
    for item in CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| InodeError::Tls(format!("could not read client cert {cert_path}: {e}")))?
    {
        certs.push(item.map_err(|e| InodeError::Tls(format!("bad client cert in {cert_path}: {e}")))?);
    }
    if certs.is_empty() {
        return Err(InodeError::Tls(format!("no certificate found in {cert_path}")));
    }
    // The key is in a separate file, or in the cert file itself.
    let key_src = key_path.filter(|p| !p.is_empty()).unwrap_or(cert_path);
    let key = PrivateKeyDer::from_pem_file(key_src)
        .map_err(|e| InodeError::Tls(format!("could not read client key {key_src}: {e}")))?;
    Ok((certs, key))
}

/// Open a fresh TLS connection to `host:port`.
pub fn tls_connect(host: &str, port: u16, cfg: &TlsConfig) -> Result<TlsStream> {
    let config = build_client_config(cfg)?;
    let sni = cfg.server_hostname.clone().unwrap_or_else(|| host.to_string());
    let server_name = ServerName::try_from(sni.clone())
        .map_err(|e| InodeError::Config(format!("invalid SNI/host {sni:?}: {e}")))?
        .to_owned();

    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| InodeError::Config(format!("could not resolve {host}:{port}")))?;
    let tcp = TcpStream::connect_timeout(&addr, cfg.timeout)?;
    tcp.set_read_timeout(Some(cfg.timeout))?;
    tcp.set_write_timeout(Some(cfg.timeout))?;
    tcp.set_nodelay(true)?;

    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| InodeError::Tls(format!("TLS setup failed: {e}")))?;
    // Drive the handshake now so a pin/verify error surfaces at connect time.
    let mut tcp_mut = tcp;
    while conn.is_handshaking() {
        match conn.complete_io(&mut tcp_mut) {
            Ok(_) => {}
            Err(e) => return Err(map_handshake_err(e)),
        }
    }
    Ok(TlsStream { inner: StreamOwned::new(conn, tcp_mut) })
}

/// Keep certificate-trust failures saying "certificate ..." (so the supervisor
/// classifies them as a cert error) while letting raw socket errors keep their
/// OS text ("Connection refused" / "Connection reset").
fn map_handshake_err(e: io::Error) -> InodeError {
    let text = e.to_string();
    let low = text.to_ascii_lowercase();
    if low.contains("pin mismatch") {
        InodeError::Tls(text)
    } else if low.contains("certificate") || low.contains("invalid peer cert") || low.contains("unknownissuer") {
        InodeError::Tls(format!("certificate verify failed: {text}"))
    } else {
        InodeError::Io(e)
    }
}

/// Decode a SHA-256 pin: strip `:`/spaces, require 32 bytes of hex.
fn parse_pin(pin: &str) -> Result<Vec<u8>> {
    let cleaned: String = pin.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if cleaned.len() != 64 {
        return Err(InodeError::Config(format!("--pin-sha256 must be 64 hex chars (got {})", cleaned.len())));
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(32);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_val(bytes.get(i).copied().unwrap_or(0))?;
        let lo = hex_val(bytes.get(i + 1).copied().unwrap_or(0))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(InodeError::Config("--pin-sha256 contains a non-hex character".into())),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0F));
    }
    s
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}
