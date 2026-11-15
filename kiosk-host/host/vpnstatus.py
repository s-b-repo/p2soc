"""
VPN status detection for the on-wall indicator — pure + privilege-free.

`vpn_state(vpn)` returns one of:
  "not_configured"  the vpn section is absent/disabled
  "online"          the tunnel looks up
  "connecting"      the ready_probe timed out (slow, or mid-handshake)
  "offline"         configured but no evidence of a live tunnel

Detection, in order of reliability:
  1. vpn.ready_probe (a host:port reachable only once the VPN is up) — a TCP
     connect. This is the accurate, type-agnostic signal; set it.
  2. otherwise, the presence of the expected tunnel interface in
     /sys/class/net (wg<n> / tun0 / ppp0, or vpn.interface when the backend
     uses a non-default name) — best-effort, no privileges.
"""
from __future__ import annotations

import ipaddress
import os
import socket

from . import config as cfg

STATE_NOT_CONFIGURED = "not_configured"
STATE_ONLINE = "online"
STATE_OFFLINE = "offline"
STATE_CONNECTING = "connecting"     # probe timed out (slow / mid-handshake)


def _is_ipv6(host: str) -> bool:
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        return False


def _split_host_port(target: str):
    """Split a ready_probe-style target into (host, port_str), IPv6-aware
    (RFC 3986). ('', '') when it cannot be parsed; port is '' when absent.

      host:443            -> ('host', '443')
      [2001:db8::1]:443   -> ('2001:db8::1', '443')
      [2001:db8::1]       -> ('2001:db8::1', '')
      2001:db8::1:443     -> ('2001:db8::1', '443')   (bare IPv6 + port)

    A thin adapter over config._split_host_port, which owns the parsing and the
    port validation. It stays separate because that helper answers a different
    question: it resolves a gateway against a default port, so it returns an int
    and cannot say "no port", and it reads 'addr:443' as an ambiguous IPv6
    literal. A probe always names a port, so here the last segment is the port
    whenever what precedes it is a valid IPv6 address."""
    s = (target or "").strip()
    if ":" not in s:
        return s, ""
    if not s.startswith("[") and s.count(":") >= 2:
        host, _, port = s.rpartition(":")
        return (host, port) if port.isdigit() and _is_ipv6(host) else (s, "")
    try:
        host, port = cfg._split_host_port(s, 443)
    except ValueError:
        return "", ""
    return host, "" if s.endswith("]") else str(port)


def _tcp_probe(hostport: str, timeout: float = 1.5) -> str:
    """Three-way probe behind the status pill:
      'ok'       the TCP connect succeeded
      'timeout'  no answer within `timeout` (slow / not routed yet): connecting
      'refused'  actively rejected, unresolvable, or malformed: offline"""
    host, port = _split_host_port(hostport)
    if not (host and port.isdigit() and 0 < int(port) < 65536):
        return "refused"
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return "ok"
    except socket.timeout:
        return "timeout"
    except OSError:
        return "refused"


def _tcp_ok(hostport: str, timeout: float = 2.0) -> bool:
    """Boolean form, for callers that do not distinguish timeout from refusal."""
    return _tcp_probe(hostport, timeout=timeout) == "ok"


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
        result = _tcp_probe(probe, timeout=timeout)
        if result == "ok":
            return STATE_ONLINE
        return STATE_CONNECTING if result == "timeout" else STATE_OFFLINE
    return STATE_ONLINE if _iface_up(_expected_iface(vpn)) else STATE_OFFLINE


def vpn_name(vpn: dict, idx: int = 0) -> str:
    """Display name for a vpn entry: the operator's `name:`, else type + gateway
    host, so an unnamed entry reads 'fortinet:vpn.acme.com' in the journal rather
    than a bare 'vpn' nobody can identify."""
    if vpn.get("name"):
        return str(vpn["name"])
    kind = str(vpn.get("type") or "").lower()
    gateway = str(vpn.get("gateway") or "")
    gw = _split_host_port(gateway)[0] or gateway
    if gw and kind:
        return f"{kind}:{gw}"
    if kind:
        return f"{kind}-{idx + 1}"
    return f"vpn-{idx + 1}"


LABELS = {
    STATE_NOT_CONFIGURED: "VPN: not configured",
    STATE_ONLINE: "VPN: online",
    STATE_CONNECTING: "VPN: connecting",
    STATE_OFFLINE: "VPN: offline",
}
