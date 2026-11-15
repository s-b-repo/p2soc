//! End-to-end session orchestration (port of `session.py`) and the in-process
//! library API the VPN supervisor drives.
//!
//! [`Client::authenticate`] runs: optional SPA knock -> TLS -> index.cgi ->
//! follow redirects -> gatewayinfo -> optional domain list -> captcha login loop
//! -> challenge/2FA loop -> optional EAD host-check, returning a [`Session`].
//! [`Session::open_tunnel`] performs the NET_EXTEND upgrade and reads the network
//! config; [`Tunnel::run`](crate::tunnel::Tunnel::run) then pumps packets.

use std::io::{Read, Write};
use std::rc::Rc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::constants as c;
use crate::crypto;
use crate::error::{InodeError, Result};
use crate::httpclient::{Connection, Cookies};
use crate::protocol::{self, ChallengeXml, GatewayInfo, LoginResult, LoginXml};
use crate::spa::SpaConfig;
use crate::transport::{self, TlsConfig, TlsStream};
use crate::tunnel::{self, NetworkConfig, Tunnel};

/// Interaction hooks (overridable for non-interactive / test use).
pub trait Prompter {
    /// Prompt for a CAPTCHA answer (the image has already been rendered).
    fn captcha(&self, image: &[u8]) -> String;
    /// Prompt for a challenge/2FA code (SMS / PROMPTPWD / CHANGEPWD).
    fn challenge_code(&self, ctype: &str, message: &str) -> String;
}

/// The default interactive prompter: reads from the terminal.
pub struct StdinPrompter;

impl Prompter for StdinPrompter {
    #[allow(unused_variables)] // audit-allow: the session renders `image` before calling the prompter, so it is unused here
    fn captcha(&self, image: &[u8]) -> String {
        eprint!("[captcha] enter the code shown above: ");
        drop(std::io::stderr().flush());
        read_line()
    }

    fn challenge_code(&self, ctype: &str, message: &str) -> String {
        eprintln!("[challenge:{ctype}] {message}");
        eprint!("Code: ");
        drop(std::io::stderr().flush());
        read_line()
    }
}

fn read_line() -> String {
    let mut s = String::new();
    match std::io::stdin().read_line(&mut s) {
        Ok(_) => s.trim().to_string(),
        Err(e) => {
            drop(e);
            String::new()
        }
    }
}

type Logger = Rc<dyn Fn(&str)>;

/// Everything needed to open a session: identity, password and the TLS / SPA /
/// EAD / split-tunnel options.
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    /// Wiped on drop; never logged or placed in argv.
    pub password: Zeroizing<String>,
    /// For a CHANGEPWD challenge.
    pub new_password: Zeroizing<String>,
    /// When set, the login/challenge passwords are RSA-PKCS1v15-encrypted with
    /// this public key (PEM or DER) instead of sent cleartext-in-TLS — the
    /// `H3C_USER_RSAKEY` firmware variant. `None` is the standard V7 path.
    pub rsa_pubkey: Option<Vec<u8>>,
    pub language: String,
    pub mac: String,
    pub tls: TlsConfig,
    pub private_blob: String,
    pub zero_trust: Option<SpaConfig>,
    pub spa_knock_port: u16,
    pub ead: bool,
    pub split_tunnel: bool,
    pub keepalive_max_miss: u32,
    pub auto_captcha: bool,
    pub captcha_retries: u32,
    pub show_captcha: bool,
    /// An explicit CAPTCHA answer, if known up front.
    pub vld_code: String,
}

impl ClientConfig {
    pub fn new(host: &str, port: u16, username: &str, password: Zeroizing<String>) -> ClientConfig {
        ClientConfig {
            host: host.to_string(),
            port,
            username: username.to_string(),
            domain: String::new(),
            password,
            new_password: Zeroizing::new(String::new()),
            rsa_pubkey: None,
            language: "cn".to_string(),
            mac: String::new(),
            tls: TlsConfig::default(),
            private_blob: String::new(),
            zero_trust: None,
            spa_knock_port: c::SPA_KNOCK_PORT_GW,
            ead: false,
            split_tunnel: false,
            keepalive_max_miss: c::DEFAULT_KEEPALIVE_MAX_MISS,
            auto_captcha: true,
            captcha_retries: 8,
            show_captcha: true,
            vld_code: String::new(),
        }
    }
}

/// The authentication driver.
pub struct Client {
    config: ClientConfig,
    prompter: Rc<dyn Prompter>,
    log: Logger,
}

impl Client {
    pub fn new(config: ClientConfig) -> Client {
        Client { config, prompter: Rc::new(StdinPrompter), log: Rc::new(|_m: &str| {}) }
    }

    /// Replace the interactive prompter (captcha / challenge entry).
    pub fn with_prompter(mut self, prompter: Rc<dyn Prompter>) -> Client {
        self.prompter = prompter;
        self
    }

    /// Install a log sink for progress lines (the supervisor classifies these).
    pub fn with_logger<F: Fn(&str) + 'static>(mut self, f: F) -> Client {
        self.log = Rc::new(f);
        self
    }

    fn full_user(&self) -> String {
        if !self.config.domain.is_empty() && !self.config.username.contains('@') {
            format!("{}@{}", self.config.username, self.config.domain)
        } else {
            self.config.username.clone()
        }
    }

    fn private_blob(&self) -> String {
        if self.config.private_blob.is_empty() {
            crypto::make_private_blob("", c::OS_FIELD, &[])
        } else {
            self.config.private_blob.clone()
        }
    }

    /// Encode a password for the wire: RSA-PKCS1v15 + base64 when the gateway's
    /// public key is configured (`H3C_USER_RSAKEY` variant), else cleartext —
    /// which is still protected by the enclosing TLS session (standard V7 path).
    fn encode_password(&self, pw: &str) -> Result<Zeroizing<String>> {
        match &self.config.rsa_pubkey {
            Some(key) => Ok(Zeroizing::new(crypto::rsa_encrypt_password_b64(key, pw)?)),
            None => Ok(Zeroizing::new(pw.to_string())),
        }
    }

    /// Run the full authentication flow.
    pub fn authenticate(&mut self) -> Result<Session> {
        if let Some(zt) = &self.config.zero_trust {
            (self.log)("SPA: sending Zero-Trust knock");
            spa_knock(&self.config.host, zt, self.config.spa_knock_port)?;
        }
        let stream = transport::tls_connect(&self.config.host, self.config.port, &self.config.tls)?;
        (self.log)(&format!("TLS connected to {}:{}", self.config.host, self.config.port));
        let mut conn = Connection::new(stream, &self.config.host, self.config.port);

        // 1) index.cgi + follow redirects, detect version, get gatewayinfo.
        let mut resp = conn.get(c::PATH_INDEX, c::UA_V7, Cookies::None, &[])?;
        if !resp.header("Server", "").contains(c::VERSION_SENTINEL) {
            (self.log)("warning: gateway looks like legacy V3 (no SSLVPN-Gateway/7.0); this client implements V7");
        }
        let mut saw_domainlist = false;
        let mut hops = 0;
        while resp.is_redirect() && hops < 10 {
            let loc = resp.header("Location", "").to_string();
            if loc.contains("getdomainlist") {
                saw_domainlist = true;
            }
            resp = conn.get(&path_of(&loc), c::UA_V7, Cookies::All, &[])?;
            hops += 1;
        }
        if !resp.is_success() {
            return Err(InodeError::auth_failed(format!("index.cgi returned {} {}", resp.status, resp.reason)));
        }
        let text = resp.text();
        let gw = if text.contains('<') { protocol::parse_gatewayinfo(&text)? } else { GatewayInfo::default() };
        let mut login_url = gw.login_url.clone();

        // 2) domain list (if advertised / redirected).
        if saw_domainlist || !self.config.domain.is_empty() {
            let cookie = format!("{}{}{}", c::DOMAIN_COOKIE_PREFIX, "0", c::DOMAIN_COOKIE_SUFFIX);
            let dl_path = format!("{}?type=getdomainlist", c::PATH_INDEX);
            match conn.get(&dl_path, c::UA_V7, Cookies::Literal(cookie), &[]) {
                Ok(dresp) => {
                    let body = dresp.text();
                    if dresp.is_success() && body.contains("<domain") {
                        let domains = protocol::parse_domainlist(&body)?;
                        if let Some(chosen) = pick_domain(&domains, &self.config.domain) {
                            (self.log)(&format!("domain: {} -> {}", chosen.name, chosen.url));
                            if !chosen.url.is_empty() {
                                login_url = chosen.url.clone();
                            }
                        }
                    }
                }
                Err(e) => (self.log)(&format!("domain list skipped: {e}")),
            }
        }

        // 3+4) CAPTCHA + login.
        let result = if gw.support_vldimg {
            self.captcha_login_loop(&mut conn, &gw, &login_url)?
        } else {
            self.login_once(&mut conn, &login_url, &self.config.vld_code)?
        };

        // 5) challenge / 2FA loop.
        let result = self.run_challenge_loop(&mut conn, &gw, result)?;
        if !result.is_success() {
            let msg = if result.message.is_empty() { &result.reply_message } else { &result.message };
            return Err(InodeError::auth_failed(format!("result={:?} msg={msg}", result.result)));
        }
        let svpnginfo = conn.cookies.get(c::SESSION_COOKIE);
        if svpnginfo.is_empty() {
            (self.log)("warning: no svpnginfo cookie after login");
        }
        (self.log)("authentication OK");

        // 6) optional EAD host-check ack.
        if self.config.ead {
            let referer = format!("https://{}{}", self.config.host, path_of(&gw.login_url));
            match conn.post(
                &path_of(&gw.challenge_url),
                b"hostcheckresult=&ActXisIns=1",
                c::UA_V7,
                Cookies::All,
                &[("Referer", referer.as_str())],
            ) {
                Ok(_) => {}
                Err(e) => drop(e),
            }
        }

        Ok(Session {
            conn,
            gateway: gw,
            svpnginfo,
            host: self.config.host.clone(),
            port: self.config.port,
            tls: self.config.tls.clone(),
            zero_trust: self.config.zero_trust.clone(),
            spa_knock_port: self.config.spa_knock_port,
            keepalive_max_miss: self.config.keepalive_max_miss,
            log: Rc::clone(&self.log),
        })
    }

    fn login_once(&self, conn: &mut Connection, login_url: &str, vld_code: &str) -> Result<LoginResult> {
        let user = self.full_user();
        let private = self.private_blob();
        let password = self.encode_password(self.config.password.as_str())?;
        let mut args = LoginXml::new(&user, password.as_str());
        args.vld_code = vld_code;
        args.language = &self.config.language;
        args.mac = &self.config.mac;
        args.private = &private;
        let xml = protocol::build_login_xml(&args);
        let body = crypto::urlencode_body(&xml);
        let resp = conn.post(&path_of(login_url), body.as_bytes(), c::UA_V7, Cookies::All, &[])?;
        protocol::parse_login_result(&resp.text())
    }

    fn show_captcha(&self, image: &[u8]) {
        match crate::captcha::decode_bmp(image) {
            Ok(bmp) => eprintln!("[captcha] image:\n{}", crate::captcha::render_ansi(&bmp.rows, 96)),
            Err(e) => drop(e),
        }
    }

    fn captcha_login_loop(&self, conn: &mut Connection, gw: &GatewayInfo, login_url: &str) -> Result<LoginResult> {
        let preset = self.config.vld_code.clone();
        let retries = self.config.captcha_retries.max(1);
        let mut result: Option<LoginResult> = None;
        for attempt in 0..retries {
            let img = conn.get(&path_of(&gw.vldimg_url), c::UA_V7, Cookies::All, &[("Accept", "*/*")])?;
            if self.config.show_captcha {
                self.show_captcha(&img.body);
            }
            let code = if !preset.is_empty() {
                preset.clone()
            } else if self.config.auto_captcha {
                match crate::captcha::solve(&img.body, 4) {
                    Some(c) if !c.is_empty() => {
                        (self.log)(&format!("[captcha] OCR solved (try {}/{retries}): {c}", attempt + 1));
                        c
                    }
                    _ => {
                        if crate::captcha::have_solver() {
                            (self.log)(&format!(
                                "[captcha] try {}/{retries}: low-confidence read, refetching",
                                attempt + 1
                            ));
                            continue;
                        }
                        (self.log)("[captcha] no OCR (tesseract missing); manual entry.");
                        self.prompter.captcha(&img.body)
                    }
                }
            } else {
                self.prompter.captcha(&img.body)
            };

            let r = self.login_once(conn, login_url, &code)?;
            if !is_verify_error(&r) {
                return Ok(r);
            }
            (self.log)(&format!("[captcha] rejected: {:?}", r.reply_message));
            let fixed = !preset.is_empty();
            result = Some(r);
            if fixed {
                break;
            }
        }
        result.ok_or_else(|| {
            InodeError::auth_failed(
                "could not solve the CAPTCHA within the allotted attempts (use manual entry or raise --captcha-retries)",
            )
        })
    }

    fn run_challenge_loop(
        &self,
        conn: &mut Connection,
        gw: &GatewayInfo,
        mut result: LoginResult,
    ) -> Result<LoginResult> {
        let mut guard = 0;
        while result.is_challenge() && guard < 10 {
            guard += 1;
            let ctype = if result.ctype.is_empty() { "SMS".to_string() } else { result.ctype.clone() };
            (self.log)(&format!("challenge: type={ctype} msg={:?}", result.message));
            let user = self.full_user();
            let private = self.private_blob();
            let referer = format!("https://{}{}", self.config.host, path_of(&gw.login_url));

            let new_pw: Zeroizing<String>;
            let code: String;
            let xml = if ctype == c::RESULT_CHANGEPWD {
                let prompt = if result.message.is_empty() { "enter new password" } else { result.message.as_str() };
                new_pw = if self.config.new_password.is_empty() {
                    Zeroizing::new(self.prompter.challenge_code(&ctype, prompt))
                } else {
                    self.config.new_password.clone()
                };
                let enc_pw = self.encode_password(self.config.password.as_str())?;
                let enc_new = self.encode_password(new_pw.as_str())?;
                let mut c = ChallengeXml::new(&user, &ctype, "");
                c.language = &self.config.language;
                c.password = Some(enc_pw.as_str());
                c.new_password = Some(enc_new.as_str());
                c.vld_code = &self.config.vld_code;
                c.mac = &self.config.mac;
                c.private = &private;
                protocol::build_challenge_xml(&c)
            } else {
                let prompt =
                    if result.message.is_empty() { result.reply_message.as_str() } else { result.message.as_str() };
                code = self.prompter.challenge_code(&ctype, prompt);
                let enc_pw: Option<Zeroizing<String>> =
                    if ctype == "SMS-IMC" { Some(self.encode_password(self.config.password.as_str())?) } else { None };
                let mut c = ChallengeXml::new(&user, &ctype, &code);
                c.language = &self.config.language;
                c.password = enc_pw.as_deref().map(String::as_str);
                c.vld_code = &self.config.vld_code;
                c.mac = &self.config.mac;
                c.private = &private;
                protocol::build_challenge_xml(&c)
            };
            let body = crypto::urlencode_body(&xml);
            let resp = conn.post(
                &path_of(&gw.challenge_url),
                body.as_bytes(),
                c::UA_V7,
                Cookies::All,
                &[("Referer", referer.as_str())],
            )?;
            result = protocol::parse_login_result(&resp.text())?;
        }
        Ok(result)
    }
}

/// An authenticated session: the live control connection plus the gateway info
/// and session cookie needed to open the tunnel.
pub struct Session {
    conn: Connection,
    gateway: GatewayInfo,
    svpnginfo: String,
    host: String,
    port: u16,
    tls: TlsConfig,
    zero_trust: Option<SpaConfig>,
    spa_knock_port: u16,
    keepalive_max_miss: u32,
    log: Logger,
}

impl Session {
    pub fn gateway(&self) -> &GatewayInfo {
        &self.gateway
    }

    pub fn session_cookie(&self) -> &str {
        &self.svpnginfo
    }

    /// Perform the NET_EXTEND upgrade on a fresh TLS socket, read the network
    /// config, and return the ready-to-run tunnel.
    pub fn open_tunnel(&mut self) -> Result<(Tunnel, NetworkConfig)> {
        if let Some(zt) = &self.zero_trust {
            spa_knock(&self.host, zt, self.spa_knock_port)?;
        }
        let stream = transport::tls_connect(&self.host, self.port, &self.tls)?;
        (self.log)("tunnel: TLS connected, sending NET_EXTEND");
        let mut tconn = Connection::new(stream, &self.host, self.port);
        let cookie = format!("{}={}", c::SESSION_COOKIE, self.svpnginfo);
        tconn.request(c::TUNNEL_VERB, "/", &[], b"", c::UA_V7, Cookies::Literal(cookie), None, false)?;

        let (leftover, pre_cfg) = read_tunnel_preamble(&mut tconn)?;
        let stream = tconn.into_stream();
        let mut tun = Tunnel::new(stream, &leftover, self.keepalive_max_miss)?;
        let cfg = match pre_cfg {
            Some(cfg) => cfg,
            None => tun
                .wait_netconfig(Duration::from_secs(20))?
                .ok_or_else(|| InodeError::Tunnel("did not receive a valid network-config frame".into()))?,
        };
        if !cfg.is_valid() {
            return Err(InodeError::Tunnel("did not receive a valid network-config frame".into()));
        }
        if cfg.keepalive_time > 0 {
            tun.set_keepalive_interval(u64::try_from(cfg.keepalive_time).unwrap_or(c::DEFAULT_KEEPALIVE_INTERVAL));
        }
        (self.log)(&format!(
            "tunnel up: ip={} mask={} gw={} dns={} routes={} keepalive={}s",
            cfg.ipaddress,
            cfg.subnetmask,
            cfg.gateway,
            cfg.dns.join(","),
            cfg.routes.len(),
            tun.keepalive_interval_secs(),
        ));
        Ok((tun, cfg))
    }

    /// Best-effort logout (GET logout.cgi).
    pub fn logout(&mut self) {
        match self.conn.get(&path_of(&self.gateway.logout_url), c::UA_V7, Cookies::All, &[]) {
            Ok(_) => (self.log)("logged out"),
            Err(e) => drop(e),
        }
    }
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------
fn spa_knock(host: &str, cfg: &SpaConfig, port: u16) -> Result<()> {
    crate::spa::send_knock(host, cfg, port, None)?;
    Ok(())
}

fn is_verify_error(result: &LoginResult) -> bool {
    result.reply_message.to_ascii_lowercase().contains("verify code")
}

fn pick_domain<'a>(domains: &'a [protocol::Domain], hint: &str) -> Option<&'a protocol::Domain> {
    if domains.is_empty() {
        return None;
    }
    if !hint.is_empty() {
        if let Some(d) = domains.iter().find(|d| d.name.eq_ignore_ascii_case(hint)) {
            return Some(d);
        }
    }
    domains.first()
}

fn path_of(url: &str) -> String {
    if url.is_empty() {
        return "/".to_string();
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.splitn(4, '/').nth(3).map(|p| format!("/{p}")).unwrap_or_else(|| "/".to_string());
    }
    if url.starts_with('/') { url.to_string() } else { format!("/{url}") }
}

fn read_append(stream: &mut TlsStream, buf: &mut Vec<u8>) -> Result<usize> {
    let mut tmp = [0u8; 65536];
    match Read::read(stream, &mut tmp) {
        Ok(0) => Ok(0),
        Ok(n) => {
            buf.extend_from_slice(tmp.get(..n).unwrap_or(&[]));
            Ok(n)
        }
        Err(e) if tunnel::is_retry(&e) => Ok(0),
        Err(e) => Err(InodeError::Io(e)),
    }
}

fn http_content_length(head: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim().eq_ignore_ascii_case("content-length") {
            return v.trim().parse::<usize>().ok();
        }
    }
    None
}

/// Consume an optional `HTTP/1.x` preamble after NET_EXTEND, returning the
/// leftover raw-frame bytes and a network config if it was carried in the HTTP
/// headers/body (the live gateway returns it in the headers with
/// `Content-Length: 0`).
fn read_tunnel_preamble(tconn: &mut Connection) -> Result<(Vec<u8>, Option<NetworkConfig>)> {
    let mut buf = tconn.take_buffered();
    let t0 = Instant::now();
    while buf.is_empty() && t0.elapsed() < Duration::from_secs(10) {
        if !tunnel::poll_readable(&tconn.stream, Duration::from_secs(10))? {
            break;
        }
        if read_append(&mut tconn.stream, &mut buf)? == 0 {
            break;
        }
    }
    if buf.get(..5) != Some(b"HTTP/") {
        return Ok((buf, None)); // raw frame stream
    }
    while crate::httpclient::find_subslice(&buf, b"\r\n\r\n").is_none() && t0.elapsed() < Duration::from_secs(15) {
        if buf.len() > c::MAX_HEADER_BYTES {
            return Err(InodeError::Tunnel("tunnel preamble header block exceeds size cap".into()));
        }
        if !tunnel::poll_readable(&tconn.stream, Duration::from_secs(10))? {
            break;
        }
        if read_append(&mut tconn.stream, &mut buf)? == 0 {
            break;
        }
    }
    let split = crate::httpclient::find_subslice(&buf, b"\r\n\r\n");
    let (head, mut rest) = match split {
        Some(i) => (buf.get(..i).unwrap_or(&[]).to_vec(), buf.get(i + 4..).unwrap_or(&[]).to_vec()),
        None => (buf.clone(), Vec::new()),
    };
    let mut netcfg = None;
    if crate::httpclient::find_subslice(&head, b"IPADDRESS").is_some() {
        netcfg = Some(tunnel::parse_netconfig(&head));
    } else if let Some(cl) = http_content_length(&head) {
        if cl > c::MAX_BODY_BYTES {
            return Err(InodeError::Tunnel(format!("tunnel preamble Content-Length {cl} exceeds cap")));
        }
        while rest.len() < cl && t0.elapsed() < Duration::from_secs(20) {
            if !tunnel::poll_readable(&tconn.stream, Duration::from_secs(10))? {
                break;
            }
            if read_append(&mut tconn.stream, &mut rest)? == 0 {
                break;
            }
        }
        let body = rest.get(..cl.min(rest.len())).unwrap_or(&[]).to_vec();
        rest = rest.get(cl.min(rest.len())..).unwrap_or(&[]).to_vec();
        if crate::httpclient::find_subslice(&body, b"IPADDRESS").is_some() {
            netcfg = Some(tunnel::parse_netconfig(&body));
        }
    }
    Ok((rest, netcfg))
}
