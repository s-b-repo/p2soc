//! Classification of a VPN client's output lines.
//!
//! Plain substring matching against the exact strings each client prints
//! (openfortivpn 1.24, OpenVPN 2.x, the bundled h3csvpn backend). The first
//! matching needle wins, so table order matters.

use soc_core::VpnKind;

/// What one output line says about the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event {
    /// The tunnel is established.
    Up,
    /// The gateway rejected the credentials.
    Auth,
    /// The gateway's certificate did not verify.
    Cert,
    /// The connection dropped.
    Down,
    /// Progress only — never drives backoff or reconnects.
    Connecting,
}

impl Event {
    pub const fn as_str(self) -> &'static str {
        match self {
            Event::Up => "up",
            Event::Auth => "auth",
            Event::Cert => "cert",
            Event::Down => "down",
            Event::Connecting => "connecting",
        }
    }
}

const FORTINET: &[(&str, Event)] = &[
    ("Tunnel is up and running", Event::Up),
    ("Could not authenticate to gateway", Event::Auth),
    ("Could not authenticate to the gateway", Event::Auth),
    ("Login failed", Event::Auth),
    ("Gateway certificate validation failed", Event::Cert),
    ("Bad certificate sha256 digest", Event::Cert),
    ("Closed connection to gateway", Event::Down),
    ("Could not start tunnel", Event::Down),
    ("Connecting to gateway", Event::Connecting),
];

const OPENVPN: &[(&str, Event)] = &[
    ("Initialization Sequence Completed", Event::Up),
    ("AUTH_FAILED", Event::Auth),
    ("auth-failure", Event::Auth),
    ("Failed running command (--auth-user-pass-verify)", Event::Auth),
    ("VERIFY ERROR", Event::Cert),
    ("certificate verify failed", Event::Cert),
    ("CRL", Event::Cert),
    ("Connection reset", Event::Down),
    ("Restart pause", Event::Down),
    ("SIGTERM", Event::Down),
    ("Exiting due to fatal error", Event::Down),
    ("process exiting", Event::Down),
];

const INODE: &[(&str, Event)] = &[
    ("tunnel up:", Event::Up),
    ("authentication failed", Event::Auth),
    ("incorrect username or password", Event::Auth),
    ("authentication server error", Event::Auth),
    ("certificate pin mismatch", Event::Cert),
    ("certificate verify failed", Event::Cert),
    ("CERTIFICATE_VERIFY_FAILED", Event::Cert),
    ("heartbeat: no response", Event::Down),
    ("going offline", Event::Down),
    ("gateway forced log-off", Event::Down),
    ("tunnel socket closed", Event::Down),
    ("disconnecting", Event::Down),
    ("Connection reset", Event::Down),
    ("Connection refused", Event::Down),
];

/// Map one output line of a `kind` client to an event. WireGuard has no
/// long-lived client to read, so it never classifies.
pub fn classify(kind: VpnKind, line: &str) -> Option<Event> {
    let table = match kind {
        VpnKind::Fortinet => FORTINET,
        VpnKind::Openvpn => OPENVPN,
        VpnKind::Inode => INODE,
        VpnKind::Wireguard => &[],
    };
    table.iter().find(|(needle, _)| line.contains(needle)).map(|(_, event)| *event)
}

/// The failure events seen during one attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Seen {
    pub auth: bool,
    pub cert: bool,
    pub down: bool,
}

impl Seen {
    /// Record a failure event. `Up` and `Connecting` are not failures and are
    /// ignored, so progress chatter can never be mistaken for a drop.
    pub fn record(&mut self, event: Event) {
        match event {
            Event::Auth => self.auth = true,
            Event::Cert => self.cert = true,
            Event::Down => self.down = true,
            Event::Up | Event::Connecting => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fortinet_real_strings() {
        let c = |l| classify(VpnKind::Fortinet, l);
        assert_eq!(c("INFO:   Tunnel is up and running."), Some(Event::Up));
        assert_eq!(
            c("ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc."),
            Some(Event::Auth)
        );
        assert_eq!(
            c("ERROR:  Could not authenticate to the gateway. Please make sure tunnel mode is allowed by the \
               gateway, check the realm, etc."),
            Some(Event::Auth)
        );
        assert_eq!(c("ERROR:  Login failed"), Some(Event::Auth));
        assert_eq!(c("ERROR:  Gateway certificate validation failed."), Some(Event::Cert));
        assert_eq!(c("ERROR:  Bad certificate sha256 digest"), Some(Event::Cert));
        assert_eq!(c("INFO:   Closed connection to gateway."), Some(Event::Down));
        assert_eq!(c("ERROR:  Could not start tunnel (xx)."), Some(Event::Down));
        assert_eq!(c("INFO:   Connecting to gateway..."), Some(Event::Connecting));
        assert_eq!(c("DEBUG:  something uninteresting"), None);
    }

    #[test]
    fn openvpn_real_strings() {
        let c = |l| classify(VpnKind::Openvpn, l);
        assert_eq!(c("Mon ... Initialization Sequence Completed"), Some(Event::Up));
        assert_eq!(c("AUTH_FAILED,Auth ..."), Some(Event::Auth));
        assert_eq!(c("SIGUSR1[soft,auth-failure] received, process restarting"), Some(Event::Auth));
        assert_eq!(c("VERIFY ERROR: depth=0, error=..."), Some(Event::Cert));
        assert_eq!(c("Connection reset, restarting [0]"), Some(Event::Down));
        assert_eq!(c("SIGTERM[hard,] received, process exiting"), Some(Event::Down));
        assert_eq!(c("OpenVPN 2.6 x86_64 ..."), None);
    }

    #[test]
    fn inode_real_strings() {
        let c = |l| classify(VpnKind::Inode, l);
        assert_eq!(c("tunnel up: ip=10.0.0.2 mask=255.255.255.0"), Some(Event::Up));
        assert_eq!(c("authentication failed: result=3"), Some(Event::Auth));
        assert_eq!(c("incorrect username or password ..."), Some(Event::Auth));
        assert_eq!(c("certificate pin mismatch: peer=AA expected=BB"), Some(Event::Cert));
        assert_eq!(c("[+] disconnecting..."), Some(Event::Down));
        assert_eq!(c("heartbeat: no response, going offline"), Some(Event::Down));
        assert_eq!(c("gateway forced log-off (type=4)"), Some(Event::Down));
        assert_eq!(c("TunnelClosed: tunnel socket closed"), Some(Event::Down));
        assert_eq!(c("just chatter"), None);
    }

    #[test]
    fn wireguard_never_classifies() {
        assert_eq!(classify(VpnKind::Wireguard, "Tunnel is up and running"), None);
    }

    #[test]
    fn event_names_are_the_documented_ones() {
        let names: Vec<&str> =
            [Event::Up, Event::Auth, Event::Cert, Event::Down, Event::Connecting].iter().map(|e| e.as_str()).collect();
        assert_eq!(names, ["up", "auth", "cert", "down", "connecting"]);
    }

    #[test]
    fn progress_is_not_recorded_as_a_failure() {
        let mut seen = Seen::default();
        seen.record(Event::Connecting);
        seen.record(Event::Up);
        assert_eq!(seen, Seen::default());
        seen.record(Event::Auth);
        assert!(seen.auth && !seen.cert && !seen.down);
    }
}
