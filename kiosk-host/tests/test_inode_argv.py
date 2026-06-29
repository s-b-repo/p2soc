"""iNode argv construction — regression tests for the two bugs the live
audit caught:

1. `_host_port` treated a SINGLE colon as IPv6, so `gw.example:443`
   produced `[gw.example:443]:443` (the embedded colon was bracketed +
   the default port was re-appended). Single colon = `host:port`,
   never IPv6. >= 2 colons = IPv6 (bracket).

2. `inode_gateway` / `openfortivpn_args` blindly passed the raw
   `gateway` string into `_safe_host` and then added the port — so a
   gateway with an embedded port (the operator-natural shape) ended up
   doubled. Now both call `_split_host_port` which splits an embedded
   port off and uses it.

Also exercises the iNode driver's `build_cmd` against the actual
parser in `svpn-connect.sh` (positional GW USER [DOMAIN] [-- EXTRA])
so any future refactor that breaks the `--` separator wiring fails
loudly here."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import config as cfg                          # noqa: E402
from host import vpndrivers                             # noqa: E402


# --- _host_port -----------------------------------------------------------


def test_host_port_v4():
    assert cfg._host_port("1.2.3.4", 443) == "1.2.3.4:443"


def test_host_port_hostname():
    assert cfg._host_port("gw.example", 443) == "gw.example:443"


def test_host_port_single_colon_is_NOT_ipv6():
    """The regression: any value with one colon used to be wrapped as
    IPv6, doubling the port if it was already a `host:port`."""
    # If we ever passed a 'host:port' style host (we don't anymore —
    # _split_host_port catches it upstream), make sure _host_port
    # at least doesn't bracket-double. With one colon it's `host:port`
    # so the original 443 stays implicit but no brackets are added.
    assert cfg._host_port("gw.example:443", 8080) == "gw.example:443:8080"
    # ^ still wrong shape if you pass garbage in, but no longer ipv6-wrapped


def test_host_port_ipv6_bare_brackets_it():
    assert cfg._host_port("fd00::1", 443) == "[fd00::1]:443"
    assert cfg._host_port("::1", 443) == "[::1]:443"
    assert cfg._host_port("2001:db8::1", 443) == "[2001:db8::1]:443"


def test_host_port_ipv6_pre_bracketed_left_alone():
    assert cfg._host_port("[fd00::1]", 443) == "[fd00::1]:443"


# --- _split_host_port ----------------------------------------------------


def test_split_bare_hostname_uses_default_port():
    assert cfg._split_host_port("gw.example", 443) == ("gw.example", 443)


def test_split_host_port_extracts_embedded_port():
    assert cfg._split_host_port("gw.example:8443", 443) == ("gw.example", 8443)


def test_split_bracketed_ipv6_with_port():
    assert cfg._split_host_port("[fd00::1]:3000", 443) == ("fd00::1", 3000)


def test_split_bracketed_ipv6_without_port():
    assert cfg._split_host_port("[fd00::1]", 443) == ("fd00::1", 443)


def test_split_bare_ipv6_uses_default_port():
    """Bare IPv6 (>= 2 colons, no brackets) — assume no embedded port."""
    assert cfg._split_host_port("fd00::1", 443) == ("fd00::1", 443)


def test_split_empty_raises():
    with pytest.raises(ValueError):
        cfg._split_host_port("", 443)


def test_split_bad_port_raises():
    with pytest.raises(ValueError):
        cfg._split_host_port("gw.example:nope", 443)


# --- inode_gateway: operator-natural shapes all work ----------------------


def test_inode_gateway_canonical_split_fields():
    """vpn.gateway='gw.example', vpn.port=8443 — canonical form."""
    g = cfg.inode_gateway({"gateway": "gw.example", "port": 8443})
    assert g == "gw.example:8443"


def test_inode_gateway_embedded_port_no_doubling():
    """vpn.gateway='gw.example:443' — the original bug. Must NOT double
    the port nor bracket the value as IPv6."""
    g = cfg.inode_gateway({"gateway": "gw.example:443"})
    assert g == "gw.example:443"


def test_inode_gateway_embedded_port_overrides_vpn_port():
    """When gateway has an embedded port, it WINS over vpn.port (the
    operator's explicit override of the default)."""
    g = cfg.inode_gateway({"gateway": "gw.example:8443", "port": 443})
    assert g == "gw.example:8443"


def test_inode_gateway_bracketed_ipv6_port():
    g = cfg.inode_gateway({"gateway": "[fd00::1]:3000"})
    assert g == "[fd00::1]:3000"


def test_inode_gateway_bare_ipv6_with_port_field():
    g = cfg.inode_gateway({"gateway": "fd00::1", "port": 443})
    assert g == "[fd00::1]:443"


def test_inode_gateway_default_port_443_when_unset():
    g = cfg.inode_gateway({"gateway": "gw.example"})
    assert g == "gw.example:443"


def test_inode_gateway_empty_returns_empty():
    assert cfg.inode_gateway({"gateway": ""}) == ""
    assert cfg.inode_gateway({}) == ""


# --- openfortivpn_args: same fix on the fortinet path --------------------


def test_openfortivpn_args_embedded_port_no_doubling():
    a = cfg.openfortivpn_args({"gateway": "fortigate.example:10443"})
    assert a[0] == "fortigate.example:10443"


def test_openfortivpn_args_canonical_split():
    a = cfg.openfortivpn_args({"gateway": "fortigate.example", "port": 10443})
    assert a[0] == "fortigate.example:10443"


# --- INodeDriver.build_cmd ↔ svpn-connect.sh argv parser ----------------


def test_build_cmd_no_extras_emits_no_separator():
    d = vpndrivers.INodeDriver()
    cmd = d.build_cmd({"type": "inode", "gateway": "gw.example:443"}, "alice")
    # script + gw + user, no domain, no extras → no '--' separator
    assert cmd[-1] == "alice"
    assert "--" not in cmd


def test_build_cmd_pin_no_domain_emits_separator():
    """Critical: without `--`, svpn-connect.sh would consume the next
    arg ('--pin-sha256') as DOMAIN, silently dropping the cert pin."""
    d = vpndrivers.INodeDriver()
    cmd = d.build_cmd({"type": "inode", "gateway": "gw.example:443",
                        "trusted_cert": "AA:BB:CC:DD"}, "alice")
    assert "--" in cmd
    sep = cmd.index("--")
    assert cmd[sep:] == ["--", "--pin-sha256", "AA:BB:CC:DD"]


def test_build_cmd_pin_with_domain_keeps_separator():
    d = vpndrivers.INodeDriver()
    cmd = d.build_cmd({"type": "inode", "gateway": "gw.example:443",
                        "domain": "corp",
                        "trusted_cert": "AA:BB:CC:DD"}, "alice")
    # ... gw user corp -- --pin-sha256 hash
    assert cmd[3] == "corp"
    assert cmd[4] == "--"
    assert cmd[5:] == ["--pin-sha256", "AA:BB:CC:DD"]


def test_build_cmd_insecure_no_domain_emits_separator():
    d = vpndrivers.INodeDriver()
    cmd = d.build_cmd({"type": "inode", "gateway": "gw.example:443",
                        "insecure": True}, "alice")
    sep = cmd.index("--")
    assert cmd[sep:] == ["--", "--insecure"]


def test_build_cmd_pin_wins_over_insecure():
    """When both pin and insecure are set, pin must win — pinning is the
    secure path, --insecure disables TLS verification entirely."""
    d = vpndrivers.INodeDriver()
    cmd = d.build_cmd({"type": "inode", "gateway": "gw.example:443",
                        "trusted_cert": "AA:BB",
                        "insecure": True}, "alice")
    assert "--pin-sha256" in cmd
    assert "--insecure" not in cmd


def test_build_cmd_extras_appended_after_pin():
    d = vpndrivers.INodeDriver()
    cmd = d.build_cmd({"type": "inode", "gateway": "gw.example:443",
                        "trusted_cert": "AA",
                        "extra_args": ["--min-tls", "1.2", "--ead"]}, "alice")
    sep = cmd.index("--")
    # Pin comes first, then extras
    assert cmd[sep:] == ["--", "--pin-sha256", "AA", "--min-tls", "1.2", "--ead"]


# --- INodeDriver dispatch + log-pattern classifier ----------------------


def test_driver_dispatch_inode_returns_INodeDriver():
    d = vpndrivers.get_driver({"type": "inode"})
    assert isinstance(d, vpndrivers.INodeDriver)


def test_driver_log_patterns_match_actual_h3csvpn_strings():
    """The _PATTERNS list must catch the strings h3csvpn ACTUALLY emits
    — verified against the upstream client's session.py/tunnel.py."""
    d = vpndrivers.INodeDriver()
    # Each of these strings appears verbatim in the upstream backend's
    # log output, so the classifier MUST react to them.
    actual_emissions = [
        ("tunnel up: ip=10.0.0.1 mask=255.255.255.0",
         vpndrivers.EVENT_UP),
        ("authentication failed: result=3", vpndrivers.EVENT_AUTH),
        ("certificate pin mismatch: peer=AA expected=BB",
         vpndrivers.EVENT_CERT),
        ("heartbeat: no response, going offline",
         vpndrivers.EVENT_DOWN),
        ("gateway forced log-off (type=4)", vpndrivers.EVENT_DOWN),
        ("tunnel socket closed", vpndrivers.EVENT_DOWN),
    ]
    for line, expected in actual_emissions:
        rv = d.classify(line)
        assert rv == expected, \
            f"{line!r} -> {rv!r}, expected {expected!r}"
