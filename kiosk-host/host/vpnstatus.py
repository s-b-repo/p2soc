"""
VPN status detection for the on-wall indicator — pure + privilege-free.

`vpn_state(vpn)` returns one of:
  "not_configured"  the vpn section is absent/disabled
  "online"          the tunnel looks up
  "offline"         configured but no evidence of a live tunnel

Detection, in order of reliability:
  1. vpn.ready_probe (a host:port reachable only once the VPN is up) — a TCP
     connect. This is the accurate, type-agnostic signal; set it.
  2. otherwise, the presence of the expected tunnel interface in
     /sys/class/net (wg<n> / tun0 / ppp0, or vpn.interface when the backend
     uses a non-default name) — best-effort, no privileges.
"""
from __future__ import annotations

import os
import socket

from . import config as cfg

STATE_NOT_CONFIGURED = "not_configured"
STATE_ONLINE = "online"
STATE_OFFLINE = "offline"


def _tcp_ok(hostport: str, timeout: float = 2.0) -> bool:
    host, _, port = hostport.rpartition(":")
    if not host or not port.isdigit():
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _expected_iface(vpn: dict) -> str:
    # An explicit vpn.interface override wins for every type — it is the only
    # signal that survives a non-default ppp_name / `dev tunN` / renamed wg link.
    override = cfg.vpn_interface(vpn)
    if override:
        return override
    kind = cfg.vpn_kind(vpn)
    if kind == "wireguard":
        from . import vpndrivers
        return vpndrivers.WireGuardDriver().iface(vpn) or "wg0"
    if kind == "openvpn":
        return "tun0"
    return "ppp0"


def _iface_up(iface: str) -> bool:
    return bool(iface) and os.path.isdir(f"/sys/class/net/{iface}")


def vpn_state(vpn: dict, timeout: float = 2.0) -> str:
    # `timeout` bounds the ready_probe TCP connect. The status path (polled per
    # VPN by the supervisor under a systemd watchdog) passes a small value so a
    # batch of black-holed probes across many VPNs cannot starve the heartbeat;
    # a reachable probe still connects far inside any sub-second timeout, so the
    # online/offline classification is unchanged.
    if not vpn or not vpn.get("enabled"):
        return STATE_NOT_CONFIGURED
    probe = (vpn.get("ready_probe") or "").strip()
    if probe:
        return STATE_ONLINE if _tcp_ok(probe, timeout=timeout) else STATE_OFFLINE
    return STATE_ONLINE if _iface_up(_expected_iface(vpn)) else STATE_OFFLINE


LABELS = {
    STATE_NOT_CONFIGURED: "VPN: not configured",
    STATE_ONLINE: "VPN: online",
    STATE_OFFLINE: "VPN: offline",
}
