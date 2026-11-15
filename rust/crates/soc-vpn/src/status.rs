//! VPN status detection for the on-wall indicator — privilege-free.
//!
//! Detection, in order of reliability:
//!  1. `vpn.ready_probe` (a `host:port` reachable only once the VPN is up) — a
//!     TCP connect. The accurate, type-agnostic signal.
//!  2. otherwise the presence of the expected tunnel interface under
//!     `/sys/class/net` (the wg interface, `tun0`, `ppp0`, or `vpn.interface`).

use crate::driver;
use soc_core::guard::split_host_port;
use soc_core::vpnargs::{vpn_interface, vpn_kind};
use soc_core::{Dict, DictExt, VpnKind};
use std::net::{Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// What the indicator shows for one VPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VpnState {
    /// The entry is absent or disabled.
    NotConfigured,
    /// The tunnel looks up.
    Online,
    /// Configured but no evidence of a live tunnel.
    Offline,
    /// The ready probe timed out (slow, or mid-handshake).
    Connecting,
}

impl VpnState {
    pub const fn as_str(self) -> &'static str {
        match self {
            VpnState::NotConfigured => "not_configured",
            VpnState::Online => "online",
            VpnState::Offline => "offline",
            VpnState::Connecting => "connecting",
        }
    }

    /// The indicator's text.
    pub const fn label(self) -> &'static str {
        match self {
            VpnState::NotConfigured => "VPN: not configured",
            VpnState::Online => "VPN: online",
            VpnState::Offline => "VPN: offline",
            VpnState::Connecting => "VPN: connecting",
        }
    }
}

impl std::fmt::Display for VpnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of one TCP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// The connect succeeded.
    Ok,
    /// No answer in time (slow / not routed yet).
    Timeout,
    /// Actively rejected, unresolvable, or malformed.
    Refused,
}

/// Split a ready-probe target into `(host, port)`, IPv6-aware. `("", "")`
/// when it cannot be parsed; the port is `""` when absent.
///
/// | input               | result                     |
/// |---------------------|----------------------------|
/// | `host:443`          | `("host", "443")`          |
/// | `[2001:db8::1]:443` | `("2001:db8::1", "443")`   |
/// | `[2001:db8::1]`     | `("2001:db8::1", "")`      |
/// | `2001:db8::1:443`   | `("2001:db8::1", "443")`   |
///
/// Unlike a gateway (resolved against a default port), a probe always names
/// its port, so for a bare IPv6 literal the last segment is the port whenever
/// what precedes it is a valid address.
pub fn split_probe(target: &str) -> (String, String) {
    let s = target.trim();
    if !s.contains(':') {
        return (s.to_string(), String::new());
    }
    if !s.starts_with('[') && s.matches(':').count() >= 2 {
        if let Some((host, port)) = s.rsplit_once(':') {
            if is_digits(port) && host.parse::<Ipv6Addr>().is_ok() {
                return (host.to_string(), port.to_string());
            }
        }
        return (s.to_string(), String::new());
    }
    match split_host_port(s, &serde_json::Value::from(443)) {
        Ok((host, port)) => (host, if s.ends_with(']') { String::new() } else { port.to_string() }),
        Err(_) => (String::new(), String::new()), // audit-allow: a malformed target reads as empty, then refused
    }
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The network and sysfs lookups status detection needs, injectable so the
/// supervisor's health logic is tested without a network.
pub trait Prober: Send + Sync {
    fn tcp(&self, hostport: &str, timeout: f64) -> Probe;
    fn iface_up(&self, iface: &str) -> bool;
}

/// The real prober.
pub struct NetProber;

impl Prober for NetProber {
    fn tcp(&self, hostport: &str, timeout: f64) -> Probe {
        tcp_probe(hostport, timeout)
    }

    fn iface_up(&self, iface: &str) -> bool {
        iface_up(iface)
    }
}

/// TCP-connect to `host:port`. A malformed target reads as refused rather
/// than an error, so a typo cannot break a health-check loop.
pub fn tcp_probe(hostport: &str, timeout: f64) -> Probe {
    let (host, port) = split_probe(hostport);
    let port = match port.parse::<u16>() {
        Ok(p) if is_digits(&port) && p >= 1 => p,
        _ => return Probe::Refused,
    };
    if host.is_empty() {
        return Probe::Refused;
    }
    let Ok(addrs) = (host.as_str(), port).to_socket_addrs() else {
        return Probe::Refused;
    };
    let timeout = crate::clock::secs(timeout).max(Duration::from_millis(1));
    let mut outcome = Probe::Refused;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => return Probe::Ok,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => outcome = Probe::Timeout,
            Err(_) => outcome = Probe::Refused, // audit-allow: any other connect failure reads as refused
        }
    }
    outcome
}

/// The interface a live tunnel of this entry would use. An explicit
/// `vpn.interface` wins for every type — the only signal that survives a
/// non-default ppp name, `dev tunN` or a renamed wg link.
pub fn expected_iface(vpn: &Dict) -> String {
    let explicit = vpn_interface(vpn);
    if !explicit.is_empty() {
        return explicit;
    }
    match vpn_kind(vpn) {
        VpnKind::Wireguard => {
            let iface = driver::wireguard_iface(vpn);
            if iface.is_empty() { "wg0".into() } else { iface }
        }
        VpnKind::Openvpn => "tun0".into(),
        VpnKind::Fortinet | VpnKind::Inode => "ppp0".into(),
    }
}

/// Whether a network interface of that name exists.
pub fn iface_up(iface: &str) -> bool {
    // The name comes from config; keep the lookup inside /sys/class/net.
    if iface.is_empty() || iface.contains('/') || iface == "." || iface == ".." {
        return false;
    }
    std::path::Path::new("/sys/class/net").join(iface).is_dir()
}

/// The state of one VPN entry. `timeout` bounds the ready-probe connect; the
/// service passes a small value so a batch of black-holed probes cannot
/// starve the watchdog heartbeat.
pub fn vpn_state(vpn: &Dict, timeout: f64, prober: &dyn Prober) -> VpnState {
    if !vpn.truthy("enabled") {
        return VpnState::NotConfigured;
    }
    let probe = vpn.text("ready_probe");
    if !probe.is_empty() {
        return match prober.tcp(&probe, timeout) {
            Probe::Ok => VpnState::Online,
            Probe::Timeout => VpnState::Connecting,
            Probe::Refused => VpnState::Offline,
        };
    }
    if prober.iface_up(&expected_iface(vpn)) { VpnState::Online } else { VpnState::Offline }
}

/// Display name of an entry: the operator's `name:`, else type + gateway
/// host, so an unnamed entry reads `fortinet:vpn.acme.com` in the journal
/// rather than a bare `vpn` nobody can identify.
pub fn vpn_name(vpn: &Dict, idx: usize) -> String {
    let name = vpn.text("name");
    if !name.is_empty() {
        return name;
    }
    let kind = vpn.text("type").to_lowercase();
    let gateway = vpn.text("gateway");
    let host = split_probe(&gateway).0;
    let gw = if host.is_empty() { gateway } else { host };
    if !gw.is_empty() && !kind.is_empty() {
        format!("{kind}:{gw}")
    } else if !kind.is_empty() {
        format!("{kind}-{}", idx + 1)
    } else {
        format!("vpn-{}", idx + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeProber, dict};
    use serde_json::json;
    use std::net::TcpListener;

    fn split(s: &str) -> (String, String) {
        split_probe(s)
    }

    fn pair(h: &str, p: &str) -> (String, String) {
        (h.to_string(), p.to_string())
    }

    #[test]
    fn split_ipv4_and_hostname() {
        assert_eq!(split("host:443"), pair("host", "443"));
        assert_eq!(split("10.50.0.5:443"), pair("10.50.0.5", "443"));
        assert_eq!(split("host"), pair("host", ""));
        assert_eq!(split(""), pair("", ""));
        assert_eq!(split("  host:8443  "), pair("host", "8443"));
    }

    #[test]
    fn split_ipv6_forms() {
        assert_eq!(split("[2001:db8::1]:443"), pair("2001:db8::1", "443"));
        assert_eq!(split("[::1]:443"), pair("::1", "443"));
        assert_eq!(split("[2001:db8::1]"), pair("2001:db8::1", ""));
        assert_eq!(split("[2001:db8::1"), pair("", ""));
        assert_eq!(split("2001:db8::1:443"), pair("2001:db8::1", "443"));
        assert_eq!(split("2001:db8::1"), pair("2001:db8::1", ""));
    }

    #[test]
    fn split_malformed() {
        assert_eq!(split("host:notaport"), pair("", ""));
        assert_eq!(split("host:"), pair("", ""));
        assert_eq!(split("[::1]x"), pair("", ""));
    }

    #[test]
    fn malformed_probes_read_refused_and_never_panic() {
        for bad in ["", "hostonly", "host:notaport", "host:0", "host:99999", ":443", "[::1", "host:+80"] {
            assert_eq!(tcp_probe(bad, 0.2), Probe::Refused, "{bad:?}");
        }
    }

    #[test]
    fn a_listening_port_is_ok_and_a_closed_one_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(tcp_probe(&format!("127.0.0.1:{port}"), 2.0), Probe::Ok);
        // Port 1 (tcpmux) rather than the port just freed: a parallel test may
        // be handed that one the moment the listener is dropped.
        assert_eq!(tcp_probe("127.0.0.1:1", 2.0), Probe::Refused);
    }

    #[test]
    fn an_ipv6_probe_connects() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            return; // no IPv6 loopback on this machine
        };
        let port = listener.local_addr().unwrap().port();
        assert_eq!(tcp_probe(&format!("[::1]:{port}"), 2.0), Probe::Ok);
        assert_eq!(tcp_probe(&format!("::1:{port}"), 2.0), Probe::Ok);
    }

    #[test]
    fn state_from_the_ready_probe() {
        let p = FakeProber::default();
        assert_eq!(vpn_state(&dict(json!({})), 2.0, &p), VpnState::NotConfigured);
        assert_eq!(vpn_state(&dict(json!({"enabled": false, "ready_probe": "h:1"})), 2.0, &p), VpnState::NotConfigured);
        let vpn = dict(json!({"enabled": true, "ready_probe": "10.0.0.5:443"}));
        p.set_tcp(Probe::Ok);
        assert_eq!(vpn_state(&vpn, 2.0, &p), VpnState::Online);
        p.set_tcp(Probe::Timeout);
        assert_eq!(vpn_state(&vpn, 2.0, &p), VpnState::Connecting);
        p.set_tcp(Probe::Refused);
        assert_eq!(vpn_state(&vpn, 2.0, &p), VpnState::Offline);
    }

    #[test]
    fn state_from_the_interface_without_a_probe() {
        let p = FakeProber::default();
        let vpn = dict(json!({"enabled": true, "type": "openvpn"}));
        assert_eq!(vpn_state(&vpn, 2.0, &p), VpnState::Offline);
        p.set_iface("tun0", true);
        assert_eq!(vpn_state(&vpn, 2.0, &p), VpnState::Online);
    }

    #[test]
    fn state_against_real_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let up = dict(json!({"enabled": true, "type": "wireguard", "config": "wg0",
                             "ready_probe": format!("127.0.0.1:{port}")}));
        assert_eq!(vpn_state(&up, 2.0, &NetProber), VpnState::Online);
        let down = dict(json!({"enabled": true, "type": "fortinet", "ready_probe": "127.0.0.1:1"}));
        assert_eq!(vpn_state(&down, 2.0, &NetProber), VpnState::Offline);
    }

    #[test]
    fn expected_interface_per_type_and_override() {
        assert_eq!(expected_iface(&dict(json!({"type": "fortinet"}))), "ppp0");
        assert_eq!(expected_iface(&dict(json!({"type": "inode"}))), "ppp0");
        assert_eq!(expected_iface(&dict(json!({"type": "openvpn"}))), "tun0");
        assert_eq!(expected_iface(&dict(json!({"type": "wireguard", "config": "/etc/wireguard/corp.conf"}))), "corp");
        assert_eq!(expected_iface(&dict(json!({"type": "wireguard"}))), "wg0");
        assert_eq!(expected_iface(&dict(json!({"type": "fortinet", "interface": " ppp7 "}))), "ppp7");
        assert_eq!(
            expected_iface(&dict(json!({"type": "wireguard", "config": "wg0", "interface": "wgcorp"}))),
            "wgcorp"
        );
    }

    #[test]
    fn interface_lookup_stays_inside_sysfs() {
        assert!(iface_up("lo"));
        assert!(!iface_up(""));
        assert!(!iface_up(".."));
        assert!(!iface_up("../../etc"));
        assert!(!iface_up("no-such-iface0"));
    }

    #[test]
    fn display_names() {
        assert_eq!(vpn_name(&dict(json!({"name": "hq", "type": "fortinet"})), 1), "hq");
        assert_eq!(
            vpn_name(&dict(json!({"type": "Fortinet", "gateway": "vpn.acme.com:443"})), 1),
            "fortinet:vpn.acme.com"
        );
        assert_eq!(vpn_name(&dict(json!({"type": "inode", "gateway": "[fd00::1]:443"})), 1), "inode:fd00::1");
        assert_eq!(vpn_name(&dict(json!({"type": "openvpn"})), 1), "openvpn-2");
        assert_eq!(vpn_name(&dict(json!({})), 1), "vpn-2");
    }

    #[test]
    fn labels_and_names() {
        assert_eq!(VpnState::Connecting.label(), "VPN: connecting");
        assert_eq!(VpnState::NotConfigured.as_str(), "not_configured");
        assert_eq!(VpnState::Online.to_string(), "online");
    }
}
