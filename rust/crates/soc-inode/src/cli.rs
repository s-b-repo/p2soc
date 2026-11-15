//! Command-line entry (port of `cli.py` + `svpn-connect.sh`'s interface).
//!
//! [`connect_main`] accepts exactly the argv the VPN supervisor already builds
//! for the iNode backend (soc-core `vpnargs::inode_extra_args` +
//! soc-vpn `driver::inode_cmd`):
//! ```text
//!   [--auth-only] <gateway[:port]> <user> [domain] [-- <backend flags>]
//! ```
//! The password comes from `$H3C_SVPN_PASSWORD` or an interactive prompt, never
//! argv. Classification lines are written to stderr so the supervisor's existing
//! substring classifier drives reconnect/notify unchanged.

use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use zeroize::Zeroizing;

use crate::constants as c;
use crate::error::InodeError;
use crate::session::{Client, ClientConfig};
use crate::spa::SpaConfig;
use crate::transport::TlsConfig;
use crate::tunnel::Event;
use crate::vnic::{self, VirtualNIC};

const USAGE: &str = "usage: svpn-connect [--auth-only] <gateway[:port]> <user> [domain] [-- <backend flags>]\n\
     password: $H3C_SVPN_PASSWORD or prompted";

/// Run the connect flow. Returns a process exit code (0 ok; 2 auth/connection;
/// 3 tunnel setup; 4 needs root).
pub fn connect_main(args: &[String]) -> i32 {
    // Split head (positionals) from the backend flags after "--".
    let sep = args.iter().position(|a| a == "--");
    let head: &[String] = match sep {
        Some(i) => args.get(..i).unwrap_or(&[]),
        None => args,
    };
    let tail: &[String] = match sep {
        Some(i) => args.get(i + 1..).unwrap_or(&[]),
        None => &[],
    };

    let mut hi = 0usize;
    let mut auth_only = false;
    while let Some(tok) = head.get(hi) {
        match tok.as_str() {
            "--auth-only" => {
                auth_only = true;
                hi += 1;
            }
            "-h" | "--help" => {
                eprintln!("{USAGE}");
                return 0;
            }
            _ => break,
        }
    }
    let Some(gateway) = head.get(hi) else {
        eprintln!("[x] missing gateway\n{USAGE}");
        return 2;
    };
    let Some(user) = head.get(hi + 1) else {
        eprintln!("[x] missing user\n{USAGE}");
        return 2;
    };
    let domain = match head.get(hi + 2) {
        Some(d) => d.clone(),
        None => String::new(),
    };

    let (host, port) = split_host(gateway, c::DEFAULT_PORT);

    // Backend flags.
    let mut tls = TlsConfig::default();
    let mut mac = String::new();
    let mut language = "cn".to_string();
    let mut captcha_retries: u32 = 8;
    let mut vld_code = String::new();
    let mut ead = false;
    let mut split_tunnel = false;
    let mut auto_captcha = true;
    let mut show_captcha = true;
    let mut no_tunnel = auth_only;
    let mut ifname = c::IFNAME_TEMPLATE.to_string();
    let mut spa_key = String::new();
    let mut spa_aid = String::new();
    let mut spa_ports = String::new();
    let mut spa_knock_port: u16 = c::SPA_KNOCK_PORT_GW;
    let mut rsa_pubkey_path = String::new();

    let mut i = 0usize;
    while i < tail.len() {
        let flag = tail.get(i).map(String::as_str).unwrap_or("");
        i += 1;
        match flag {
            "--insecure" => tls.verify = false,
            "--pin-sha256" => tls.pin_sha256 = take(tail, &mut i),
            "--cafile" => tls.cafile = take(tail, &mut i),
            "--client-cert" => tls.client_cert = take(tail, &mut i),
            "--client-key" => tls.client_key = take(tail, &mut i),
            "--min-tls" => tls.min_tls = take(tail, &mut i),
            "--sni" => tls.server_hostname = take(tail, &mut i),
            "--mac" => mac = take_str(tail, &mut i),
            "--language" => language = take(tail, &mut i).unwrap_or_else(|| "cn".to_string()),
            "--captcha-retries" => {
                captcha_retries = take(tail, &mut i).and_then(|v| v.parse::<u32>().ok()).unwrap_or(8).max(1);
            }
            "--vldcode" => vld_code = take_str(tail, &mut i),
            "--ead" => ead = true,
            "--split-tunnel" => split_tunnel = true,
            "--auto-captcha" => auto_captcha = true,
            "--no-auto-captcha" => auto_captcha = false,
            "--show-captcha" => show_captcha = true,
            "--no-show-captcha" => show_captcha = false,
            "--no-tunnel" | "--auth-only" => no_tunnel = true,
            "--ifname" => ifname = take(tail, &mut i).unwrap_or_else(|| c::IFNAME_TEMPLATE.to_string()),
            "--spa-key" => spa_key = take_str(tail, &mut i),
            "--spa-aid" => spa_aid = take_str(tail, &mut i),
            "--spa-ports" => spa_ports = take_str(tail, &mut i),
            "--spa-knock-port" => {
                spa_knock_port = take(tail, &mut i).and_then(|v| v.parse::<u16>().ok()).unwrap_or(c::SPA_KNOCK_PORT_GW);
            }
            "--rsa-pubkey" => rsa_pubkey_path = take_str(tail, &mut i),
            "-v" | "--verbose" => {} // always verbose to stderr
            other => eprintln!("[config] ignoring unknown backend flag: {other}"),
        }
    }

    if tls.pin_sha256.is_some() {
        // A pin overrides trust mode; keep verify off so the chain is bypassed.
        tls.verify = false;
    }
    if !tls.verify && tls.pin_sha256.is_none() {
        eprintln!(
            "[!] WARNING: TLS verification disabled (--insecure). This exposes you to MITM. Prefer --pin-sha256."
        );
    }

    let password = match get_password() {
        Some(p) => p,
        None => {
            eprintln!("[x] no password ($H3C_SVPN_PASSWORD unset and no terminal input)");
            return 2;
        }
    };

    let mut config = ClientConfig::new(&host, port, user, password);
    config.domain = domain;
    config.language = language;
    config.mac = mac;
    config.tls = tls;
    config.ead = ead;
    config.split_tunnel = split_tunnel;
    config.auto_captcha = auto_captcha;
    config.captcha_retries = captcha_retries;
    config.show_captcha = show_captcha;
    config.vld_code = vld_code;
    config.spa_knock_port = spa_knock_port;

    if !rsa_pubkey_path.is_empty() {
        match std::fs::read(&rsa_pubkey_path) {
            Ok(bytes) => {
                eprintln!("[config] RSA password mode enabled (H3C_USER_RSAKEY) from {rsa_pubkey_path}");
                config.rsa_pubkey = Some(bytes);
            }
            Err(e) => {
                eprintln!("[x] cannot read --rsa-pubkey file {rsa_pubkey_path}: {e}");
                return 2;
            }
        }
    }

    if !spa_key.is_empty() {
        match build_spa(&spa_key, &spa_aid, &spa_ports) {
            Some(sc) => {
                eprintln!("[SPA] Zero-Trust knock enabled (knock-port={spa_knock_port})");
                config.zero_trust = Some(sc);
            }
            None => {
                eprintln!("[x] invalid --spa-* value (expected hex key/aid)");
                return 2;
            }
        }
    }

    let mut client = Client::new(config).with_logger(|m: &str| eprintln!("{m}"));
    let mut session = match client.authenticate() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[x] {e}");
            return 2;
        }
    };

    if no_tunnel {
        println!("Authentication succeeded (--no-tunnel).");
        session.logout();
        return 0;
    }

    let (mut tun, cfg) = match session.open_tunnel() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[x] tunnel setup failed: {e}");
            session.logout();
            return 3;
        }
    };

    if !vnic::have_root() {
        eprintln!(
            "[x] tunnel needs root (CAP_NET_ADMIN) to create the TUN device. Re-run with sudo, or use --auth-only."
        );
        session.logout();
        return 4;
    }

    let server_ip = resolve_first_ip(&host, port);
    let mut nic = VirtualNIC::new(&ifname);
    let setup = (|| {
        nic.open()?;
        nic.configure(&cfg, server_ip.as_deref(), split_tunnel)?;
        Ok::<(), InodeError>(())
    })();
    if let Err(e) = setup {
        eprintln!("[x] tunnel setup failed: {e}");
        session.logout();
        return 3;
    }
    if let Some(tunfile) = nic.take_tun() {
        tun.set_tun(tunfile);
    }

    let dns = if cfg.dns.is_empty() { "-".to_string() } else { cfg.dns.join(",") };
    println!("[+] Connected. interface={} ip={} dns={dns}. Ctrl-C to disconnect.", nic.ifname, cfg.ipaddress);

    // SIGINT/SIGTERM/SIGHUP -> stop request (clean teardown).
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [SIGINT, SIGTERM, SIGHUP] {
        drop(signal_hook::flag::register(sig, Arc::clone(&stop)));
    }

    let on_event = |ev: Event| match ev {
        Event::Up(m) => eprintln!("{m}"),
        Event::NetConfig(nc) => eprintln!("netconfig update: ip={} gw={}", nc.ipaddress, nc.gateway),
        Event::Heartbeat => {}
        Event::LogOff(m) => eprintln!("{m}"),
        Event::Down(m) => eprintln!("{m}"),
    };
    let run_result = tun.run(&stop, &on_event);

    println!("[+] disconnecting...");
    nic.close();
    session.logout();
    match run_result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[x] {e}");
            1
        }
    }
}

fn take(tail: &[String], i: &mut usize) -> Option<String> {
    let v = tail.get(*i).cloned();
    if v.is_some() {
        *i += 1;
    }
    v
}

/// Like [`take`] but yields an empty string when the value is absent.
fn take_str(tail: &[String], i: &mut usize) -> String {
    match tail.get(*i) {
        Some(v) => {
            *i += 1;
            v.clone()
        }
        None => String::new(),
    }
}

fn get_password() -> Option<Zeroizing<String>> {
    match std::env::var("H3C_SVPN_PASSWORD") {
        Ok(p) => return Some(Zeroizing::new(p)),
        Err(e) => drop(e),
    }
    use std::io::Write;
    eprint!("Password: ");
    drop(std::io::stderr().flush());
    let mut s = String::new();
    match std::io::stdin().read_line(&mut s) {
        Ok(0) => None,
        Ok(_) => Some(Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_string())),
        Err(e) => {
            drop(e);
            None
        }
    }
}

fn split_host(gateway: &str, default_port: u16) -> (String, u16) {
    let g = gateway.strip_prefix("https://").or_else(|| gateway.strip_prefix("http://")).unwrap_or(gateway);
    if let Some(rest) = g.strip_prefix('[') {
        let Some(end) = rest.find(']') else { return (g.to_string(), default_port) };
        let host = rest.get(..end).unwrap_or("").to_string();
        let port = rest
            .get(end + 1..)
            .and_then(|a| a.strip_prefix(':'))
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return (host, port);
    }
    if g.matches(':').count() == 1 {
        if let Some((h, p)) = g.split_once(':') {
            return (h.to_string(), p.parse::<u16>().ok().unwrap_or(default_port));
        }
    }
    (g.to_string(), default_port)
}

fn resolve_first_ip(host: &str, port: u16) -> Option<String> {
    (host, port).to_socket_addrs().ok().and_then(|mut it| it.next()).map(|a| a.ip().to_string())
}

fn build_spa(spa_key: &str, spa_aid: &str, spa_ports: &str) -> Option<SpaConfig> {
    let key = unhex(spa_key)?;
    let aid = if spa_aid.is_empty() { Vec::new() } else { unhex(spa_aid)? };
    let mut ports: Vec<u16> = spa_ports.split(',').filter_map(|p| p.trim().parse::<u16>().ok()).collect();
    if ports.is_empty() {
        ports = vec![c::SPA_AUTH_PORT];
    }
    let mut sc = SpaConfig::new(aid, key);
    sc.ports = ports;
    Some(sc)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|ch| !ch.is_whitespace() && *ch != ':').collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hexv(bytes.get(i).copied().unwrap_or(0))?;
        let lo = hexv(bytes.get(i + 1).copied().unwrap_or(0))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hexv(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
