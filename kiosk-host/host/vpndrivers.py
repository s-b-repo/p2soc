"""
VPN backend drivers — one per supported tunnel type.

Each driver tells the supervisor (host/fortivpn.py) how to start a tunnel and
how to read its output, so one supervision policy (backoff, auth-lockout
protection, systemd watchdog, ready-probe health checks) covers every type.

Two shapes:
  * "process" drivers (Fortinet, OpenVPN) run a long-lived foreground process
    whose log lines are classified into up/auth/cert/down events.
  * "interface" drivers (WireGuard) configure a kernel interface with a one-shot
    `wg-quick up` and are supervised purely by health probing + up/down.

Credentials never touch argv or disk:
  * Fortinet — password via the pinentry helper (child environment).
  * OpenVPN  — username/password answered over a local management socket.
  * WireGuard — no interactive creds (keys live in the .conf, protect it 0600).
"""
from __future__ import annotations

import os

from . import config as cfg

EVENT_UP = "up"
EVENT_AUTH = "auth"
EVENT_CERT = "cert"
EVENT_DOWN = "down"


def _match(line: str, patterns):
    for needle, event in patterns:
        if needle in line:
            return event
    return None


class Driver:
    kind = ""
    binary = ""
    is_interface = False

    def needs_creds(self, vpn: dict) -> bool:
        return False

    def resolve_binary(self, vpn: dict) -> str:
        """The executable to check for presence — a PATH name, or an absolute
        path for drivers whose entrypoint is shipped with the client."""
        return self.binary

    def classify(self, line: str):
        return None


class FortinetDriver(Driver):
    kind = "fortinet"
    binary = "openfortivpn"
    # exact strings verified against openfortivpn 1.24
    _PATTERNS = (
        ("Tunnel is up and running", EVENT_UP),
        ("Could not authenticate to gateway", EVENT_AUTH),
        ("Could not authenticate to the gateway", EVENT_AUTH),
        ("Login failed", EVENT_AUTH),
        ("Gateway certificate validation failed", EVENT_CERT),
        ("Bad certificate sha256 digest", EVENT_CERT),
        ("Closed connection to gateway", EVENT_DOWN),
        ("Could not start tunnel", EVENT_DOWN),
    )

    def needs_creds(self, vpn):
        return True

    def build_cmd(self, vpn, user, pinentry, otp=""):
        cmd = ["openfortivpn", *cfg.openfortivpn_args(vpn),
               "-u", user, f"--pinentry={pinentry}"]
        if otp:
            cmd.append(f"--otp={otp}")
        return cmd

    def classify(self, line):
        return _match(line, self._PATTERNS)


class OpenVPNDriver(Driver):
    kind = "openvpn"
    binary = "openvpn"
    _PATTERNS = (
        ("Initialization Sequence Completed", EVENT_UP),
        ("AUTH_FAILED", EVENT_AUTH),
        ("auth-failure", EVENT_AUTH),
        ("Failed running command (--auth-user-pass-verify)", EVENT_AUTH),
        ("VERIFY ERROR", EVENT_CERT),
        ("certificate verify failed", EVENT_CERT),
        ("CRL", EVENT_CERT),
        ("Connection reset", EVENT_DOWN),
        ("Restart pause", EVENT_DOWN),
        ("SIGTERM", EVENT_DOWN),
        ("Exiting due to fatal error", EVENT_DOWN),
        ("process exiting", EVENT_DOWN),
    )

    def needs_creds(self, vpn):
        return bool(vpn.get("vault_item"))    # username/password auth

    def build_cmd(self, vpn, mgmt_socket=None):
        """Non-secret OpenVPN argv. When a management socket is given (for
        username/password auth), openvpn is told to ask it for the password and
        to start held, so the supervisor can connect before auth proceeds."""
        cmd = ["openvpn", *cfg.openvpn_args(vpn)]
        if mgmt_socket:
            cmd += ["--management", mgmt_socket, "unix",
                    "--management-query-passwords", "--management-hold"]
        return cmd

    def classify(self, line):
        return _match(line, self._PATTERNS)


class WireGuardDriver(Driver):
    kind = "wireguard"
    binary = "wg-quick"
    is_interface = True

    def up_cmd(self, vpn):
        return ["wg-quick", "up", cfg.wireguard_target(vpn)]

    def down_cmd(self, vpn):
        return ["wg-quick", "down", cfg.wireguard_target(vpn)]

    def iface(self, vpn) -> str:
        """Interface name for `wg show` — basename of the target, sans .conf."""
        base = os.path.basename(cfg.wireguard_target(vpn))
        return base[:-5] if base.endswith(".conf") else base


class INodeDriver(Driver):
    """H3C iNode SSL VPN, driven through the bundled headless wrapper
    (svpn-connect.sh). A process driver like Fortinet: long-lived, classified by
    log lines; the password is injected via the child env ($H3C_SVPN_PASSWORD),
    never argv. vpn.config points at the iNode-VPN-Client dir (or the script)."""
    kind = "inode"
    binary = "svpn-connect.sh"
    # strings emitted by the bundled clean-room h3csvpn backend (run with -v)
    _PATTERNS = (
        ("tunnel up:", EVENT_UP),
        ("authentication failed", EVENT_AUTH),
        ("incorrect username or password", EVENT_AUTH),
        ("authentication server error", EVENT_AUTH),
        ("certificate pin mismatch", EVENT_CERT),
        ("certificate verify failed", EVENT_CERT),
        ("CERTIFICATE_VERIFY_FAILED", EVENT_CERT),
        ("heartbeat: no response", EVENT_DOWN),    # iNode keepalive missed N times
        ("going offline", EVENT_DOWN),
        ("gateway forced log-off", EVENT_DOWN),
        ("tunnel socket closed", EVENT_DOWN),
        ("disconnecting", EVENT_DOWN),
        ("Connection reset", EVENT_DOWN),
        ("Connection refused", EVENT_DOWN),
    )

    def needs_creds(self, vpn):
        return True

    def resolve_binary(self, vpn):
        return cfg.inode_script(vpn) or self.binary

    def build_cmd(self, vpn, user):
        """svpn-connect.sh <gw:port> <user> [domain] [-- pin/insecure + extra].
        The password is NOT here — the supervisor sets $H3C_SVPN_PASSWORD."""
        cmd = [cfg.inode_script(vpn), cfg.inode_gateway(vpn), user]
        domain = str(vpn.get("domain", "") or "").strip()
        if domain:
            cmd.append(domain)
        cmd += cfg.inode_extra_args(vpn)
        return cmd

    def classify(self, line):
        return _match(line, self._PATTERNS)


_DRIVERS = {
    "fortinet": FortinetDriver,
    "openvpn": OpenVPNDriver,
    "wireguard": WireGuardDriver,
    "inode": INodeDriver,
}


def get_driver(vpn: dict) -> Driver:
    return _DRIVERS[cfg.vpn_kind(vpn)]()
