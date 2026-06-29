"""Hardening tests for host/config.py: argv option-injection defenses, RFC 3986
IPv6 host:port bracketing, compute_geometry clamping, and panel-id charset.

Mirrors the style/fixtures of tests/test_host.py (load via a temp YAML file and
assert on ConfigError text) and tests/test_url_validation.py (direct helper
calls)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest  # noqa: E402

from host import config  # noqa: E402


# --------------------------------------------------------------------------- #
# helpers (same shape as test_host.py)
# --------------------------------------------------------------------------- #
def _load_yaml_text(text):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(text)
        path = fh.name
    return config.load(path)


def _expect_error(yaml_text, *snippets):
    try:
        _load_yaml_text(yaml_text)
    except config.ConfigError as e:
        for s in snippets:
            assert s in str(e), f"expected {s!r} in error:\n{e}"
        return
    raise AssertionError(f"expected ConfigError with {snippets}")


MINIMAL_PANEL = """
    vault_item: "X"
    selectors: {user: "#u", pass: "#p", submit: "#s"}
"""


# --------------------------------------------------------------------------- #
# Fix 1 — argv option-injection on VPN/tunnel argv builders
# --------------------------------------------------------------------------- #
def test_safe_host_rejects_leading_dash_and_blank_and_ctrl():
    for bad in ("-oProxyCommand=evil", "  -x", "host with space", "h\nost",
                "h\tost", "host\x00", "", "   "):
        with pytest.raises(ValueError):
            config._safe_host(bad)
    # a normal host passes and is returned stripped
    assert config._safe_host("  vpn.example.net  ") == "vpn.example.net"
    assert config._safe_host("10.0.0.1") == "10.0.0.1"


def test_safe_port_range():
    assert config._safe_port(443) == 443
    assert config._safe_port("8443") == 8443
    for bad in (0, -1, 65536, 99999, "notaport", None):
        with pytest.raises(ValueError):
            config._safe_port(bad)


def test_safe_word_rejects_newline_and_leading_dash():
    with pytest.raises(ValueError):
        config._safe_word("a\nb", "vpn.realm")
    with pytest.raises(ValueError):
        config._safe_word("--set-routes=0", "vpn.realm")
    assert config._safe_word("  soc  ", "vpn.realm") == "soc"


def test_openfortivpn_args_rejects_dash_gateway():
    with pytest.raises(ValueError):
        config.openfortivpn_args({"gateway": "-oProxyCommand=evil", "port": 443})


def test_openfortivpn_args_rejects_dash_realm():
    with pytest.raises(ValueError):
        config.openfortivpn_args(
            {"gateway": "vpn.example.net", "port": 443, "realm": "-x"})


def test_openfortivpn_args_rejects_bad_port():
    with pytest.raises(ValueError):
        config.openfortivpn_args({"gateway": "vpn.example.net", "port": 99999})


def test_inode_gateway_rejects_dash_host():
    with pytest.raises(ValueError):
        config.inode_gateway({"gateway": "-bad", "port": 443})


def test_extra_args_passthrough_allows_flags_but_blocks_ctrl():
    # leading '-' flags are operator-trusted and pass through unchanged
    args = config.openfortivpn_args(
        {"gateway": "vpn.example.net", "port": 443, "extra_args": ["-v", "--trace"]})
    assert args[-2:] == ["-v", "--trace"]
    # an embedded newline/control char is rejected (log/arg smuggling)
    with pytest.raises(ValueError):
        config.openfortivpn_args(
            {"gateway": "vpn.example.net", "extra_args": ["ok\nINJECT"]})


def test_validation_tunnel_remote_host_leading_dash_rejected():
    _expect_error("""
panels:
  - id: t1
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19001, remote_host: "-oProxyCommand=evil", remote_port: 8443}
""" + MINIMAL_PANEL + """
tunnel: {enabled: true, jump_host: "u@j"}
""", "remote_host", "option injection")


def test_validation_tunnel_bad_remote_port_rejected():
    _expect_error("""
panels:
  - id: t1
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19001, remote_host: h, remote_port: 99999}
""" + MINIMAL_PANEL + """
tunnel: {enabled: true, jump_host: "u@j"}
""", "tunnel.remote_port must be a port number")


# --------------------------------------------------------------------------- #
# Fix 2 — IPv6 host:port bracketing (RFC 3986)
# --------------------------------------------------------------------------- #
def test_host_port_brackets_ipv6():
    assert config._host_port("fd00::1", 443) == "[fd00::1]:443"
    assert config._host_port("2001:db8::5", 8443) == "[2001:db8::5]:8443"
    # IPv4 / hostname unchanged
    assert config._host_port("10.0.0.1", 443) == "10.0.0.1:443"
    assert config._host_port("vpn.example.net", 443) == "vpn.example.net:443"
    # already bracketed is left alone
    assert config._host_port("[fd00::1]", 443) == "[fd00::1]:443"


def test_openfortivpn_args_ipv6_gateway_bracketed():
    args = config.openfortivpn_args({"gateway": "fd00::1", "port": 10443})
    assert args[0] == "[fd00::1]:10443"


def test_inode_gateway_ipv6_bracketed():
    assert config.inode_gateway({"gateway": "2001:db8::7", "port": 4433}) \
        == "[2001:db8::7]:4433"


# --------------------------------------------------------------------------- #
# Fix 3 — compute_geometry never yields a zero/negative cell
# --------------------------------------------------------------------------- #
def test_compute_geometry_oversized_gap_clamps_to_at_least_one():
    # gap far larger than the width would drive cell_w negative without clamping
    disp = config.DisplayCfg(width=1920, height=1080, cols=2, rows=2, gap=100000)
    for grid in ((0, 0), (1, 1)):
        g = config.compute_geometry(disp, grid)
        assert g.w >= 1 and g.h >= 1


def test_compute_geometry_happy_path_unchanged():
    # the valid-input result must be byte-for-byte what it was before hardening
    disp = config.DisplayCfg(width=1920, height=1080, cols=2, rows=2, gap=0)
    g00 = config.compute_geometry(disp, (0, 0))
    g11 = config.compute_geometry(disp, (1, 1))
    assert (g00.w, g00.h, g00.x, g00.y) == (960, 540, 0, 0)
    assert (g11.w, g11.h, g11.x, g11.y) == (960, 540, 960, 540)
    # a modest gap also matches the pre-hardening arithmetic
    disp.gap = 10
    g = config.compute_geometry(disp, (1, 0))
    assert g.w == (1920 - 10) // 2          # 955
    assert g.x == 1 * (g.w + 10)


# --------------------------------------------------------------------------- #
# Fix 4 — panel id charset (XML-injection defense)
# --------------------------------------------------------------------------- #
def test_invalid_panel_id_rejected():
    # YAML single-quoted scalars keep these verbatim (no escaping needed) but the
    # charset guard must still reject them. Each contains a char outside
    # [A-Za-z0-9_-] that could break out of an XML attribute downstream.
    for bad in ("p 1", "p<1>", "p&1", "p/1", "p.1", "a:b", 'q"x'):
        _expect_error(
            "panels:\n  - id: '" + bad.replace("'", "''") + "'\n"
            "    grid: [0, 0]\n    url: \"http://x/\"\n",
            "must match [A-Za-z0-9_-]+")


def test_valid_panel_ids_still_accepted():
    conf = _load_yaml_text("""
display: {cols: 2, rows: 2}
panels:
  - id: p1
    grid: [0, 0]
    url: "http://x/"
  - id: Wazuh_main-2
    grid: [1, 0]
    url: "http://y/"
""")
    assert {p.id for p in conf.panels} == {"p1", "Wazuh_main-2"}


# --------------------------------------------------------------------------- #
# Regression — valid full config still loads and builds argv unchanged
# --------------------------------------------------------------------------- #
def test_valid_inputs_unchanged_end_to_end():
    conf = _load_yaml_text("""
display: {width: 1920, height: 1080, cols: 2, rows: 2, gap: 0}
panels:
  - id: p1
    grid: [0, 0]
    mode: direct
    url: "http://10.0.0.1:3000/login"
  - id: p2
    grid: [1, 1]
    mode: tunnel
    tunnel: {local_port: 19103, remote_host: 10.20.0.7, remote_port: 8443}
    path: "/app"
tunnel: {enabled: true, jump_host: "u@jump"}
vpn:
  enabled: true
  gateway: "vpn.example.net"
  port: 10443
  vault_item: "SOC FortiGate VPN"
  realm: "soc"
  extra_args: ["-v"]
""")
    args = config.openfortivpn_args(conf.vpn)
    assert args[0] == "vpn.example.net:10443"
    assert "--realm=soc" in args
    assert args[-1] == "-v"
    g = {p.id: p.geometry for p in conf.panels}
    assert (g["p1"].w, g["p1"].h) == (960, 540)
    assert (g["p2"].x, g["p2"].y) == (960, 540)
