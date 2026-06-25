"""H3C SSL-VPN network-config parsing: redirect-all (full-tunnel) detection.

The gateway signals "route everything through the VPN" either implicitly (no
``ROUTES`` line) or explicitly with a ``ROUTES:0.0.0.0/0`` entry. ``parse_netconfig``
must fold that catch-all into ``default_gateway`` AND drop it from ``routes`` so
the vnic full-tunnel path engages: ``full_tunnel = default_gateway and not routes``
gates the server-IP bypass that keeps the encrypted TLS link OFF the tunnel.

If a ``0.0.0.0/0`` route were left in ``routes`` instead, ``full_tunnel`` would be
False, the bypass would never install, and the literal default route would send
the TLS connection back into the tunnel and deadlock — the exact failure the
bypass exists to prevent. A bare ``ROUTES:0.0.0.0/0`` with no GATEWAY line must
also satisfy ``is_valid`` (redirect-all needs no explicit next hop).
"""
import os
import sys

import pytest

# The vendored h3csvpn package uses relative imports; import it as the top-level
# package ``h3csvpn`` by putting the ``backends`` dir on sys.path (as session.py
# / transport.py do with ``from .tunnel import ...``).
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_BACKENDS = os.path.join(_REPO, "vendor", "iNode-VPN-Client", "backends")
if _BACKENDS not in sys.path:
    sys.path.insert(0, _BACKENDS)

tunnel = pytest.importorskip("h3csvpn.tunnel")


def _full_tunnel(cfg):
    # Mirror the gate in vnic._program_routes (non-split-tunnel path).
    return cfg.default_gateway and not cfg.routes


@pytest.mark.parametrize("routes_line", ["0.0.0.0/0", "0.0.0.0"])
def test_explicit_default_route_triggers_full_tunnel(routes_line):
    data = (b"IPADDRESS:10.0.0.5\nGATEWAY:10.0.0.1\nROUTES:" +
            routes_line.encode() + b"\n")
    cfg = tunnel.parse_netconfig(data)
    assert cfg.default_gateway is True
    # Catch-all stripped so the full-tunnel + server-IP-bypass path engages.
    assert cfg.routes == []
    assert _full_tunnel(cfg) is True
    assert cfg.is_valid is True


def test_default_route_without_gateway_is_valid():
    # Redirect-all needs no explicit next hop; missing GATEWAY must not fail
    # validation when a 0.0.0.0/0 route is present.
    cfg = tunnel.parse_netconfig(b"IPADDRESS:10.0.0.5\nROUTES:0.0.0.0/0\n")
    assert cfg.default_gateway is True
    assert cfg.is_valid is True


def test_no_routes_keeps_implicit_default():
    cfg = tunnel.parse_netconfig(b"IPADDRESS:10.0.0.5\nGATEWAY:10.0.0.1\n")
    assert cfg.default_gateway is True
    assert cfg.routes == []
    assert _full_tunnel(cfg) is True


def test_specific_routes_stay_split_tunnel():
    cfg = tunnel.parse_netconfig(
        b"IPADDRESS:10.0.0.5\nGATEWAY:10.0.0.1\nROUTES:10.1.0.0/16\n")
    assert cfg.default_gateway is False
    assert cfg.routes == ["10.1.0.0/16"]
    assert _full_tunnel(cfg) is False


def test_default_plus_specific_records_default_and_keeps_specific():
    # A gateway that pushes both a catch-all and a specific subnet: the catch-all
    # is folded into the flag (so is_valid passes and IPv6 default-split engages),
    # the specific subnet stays an explicit tunnel route.
    cfg = tunnel.parse_netconfig(
        b"IPADDRESS:10.0.0.5\nGATEWAY:10.0.0.1\nROUTES:0.0.0.0/0,10.1.0.0/16\n")
    assert cfg.default_gateway is True
    assert cfg.routes == ["10.1.0.0/16"]
    assert cfg.is_valid is True
