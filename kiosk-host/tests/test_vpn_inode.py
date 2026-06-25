"""iNode (H3C SSL VPN) — config helpers, driver classification, render round-trip."""
import importlib.util
import os
import socket
import sys

import pytest

from host import config, vpndrivers

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# The vendored clean-room backend is imported as the top-level package
# `h3csvpn` with PYTHONPATH=<...>/backends (see inode-svpn-helper).
_BACKENDS = os.path.join(_REPO, "vendor", "iNode-VPN-Client", "backends")


def test_vpn_kind_inode():
    assert config.vpn_kind({"type": "inode"}) == "inode"
    assert "inode" in config.VALID_VPN_TYPES


def test_inode_helpers():
    vpn = {"gateway": "vpn.ex.net", "port": 3000, "config": "/opt/iNode-VPN-Client",
           "trusted_cert": "AA:BB:CC"}
    assert config.inode_gateway(vpn) == "vpn.ex.net:3000"
    assert config.inode_gateway({"gateway": "h"}) == "h:443"
    assert config.inode_gateway({}) == ""
    assert config.inode_script(vpn) == "/opt/iNode-VPN-Client/svpn-connect.sh"
    assert config.inode_script({"config": "/x/svpn-connect.sh"}) == "/x/svpn-connect.sh"
    assert config.inode_extra_args(vpn) == ["--", "--pin-sha256", "AA:BB:CC"]
    assert config.inode_extra_args({"insecure": True}) == ["--", "--insecure"]
    assert config.inode_extra_args({}) == []


def test_inode_script_defaults_to_bundled(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_ROOT", str(tmp_path))
    assert config.inode_script({}) == str(
        tmp_path / "vendor" / "iNode-VPN-Client" / "svpn-connect.sh")


def test_inode_driver_classify():
    d = vpndrivers.get_driver({"type": "inode"})
    assert d.kind == "inode" and d.needs_creds({}) is True
    assert d.classify("tunnel up: ip=10.0.0.2 mask=255.255.255.0") == "up"
    assert d.classify("authentication failed: result=...") == "auth"
    assert d.classify("incorrect username or password ...") == "auth"
    assert d.classify("certificate pin mismatch: peer=x") == "cert"
    assert d.classify("[+] disconnecting...") == "down"
    assert d.classify("heartbeat: no response, going offline") == "down"
    assert d.classify("gateway forced log-off (type=4)") == "down"
    assert d.classify("TunnelClosed: tunnel socket closed") == "down"
    assert d.classify("just chatter") is None


def test_inode_build_cmd_no_password_on_argv():
    d = vpndrivers.get_driver({"type": "inode"})
    vpn = {"gateway": "g", "port": 3000, "config": "/c", "domain": "system",
           "trusted_cert": "AA:BB"}
    assert d.build_cmd(vpn, "user1") == [
        "/c/svpn-connect.sh", "g:3000", "user1", "system", "--", "--pin-sha256", "AA:BB"]
    assert d.resolve_binary(vpn) == "/c/svpn-connect.sh"


def test_inode_config_validation():
    good = ("vpn: {enabled: true, type: inode, gateway: g, vault_item: I, "
            "config: /opt/iNode, trusted_cert: 'AA:BB'}\n"
            "display: {cols: 1, rows: 1}\n"
            "panels:\n  - {id: a, grid: [0,0], mode: direct, url: 'http://x/'}\n")
    assert config.vpn_kind(config.load_str(good, "t").vpn) == "inode"
    bad = ("vpn: {enabled: true, type: inode}\n"
           "display: {cols: 1, rows: 1}\n"
           "panels:\n  - {id: a, grid: [0,0], mode: direct, url: 'http://x/'}\n")
    with pytest.raises(config.ConfigError) as e:
        config.load_str(bad, "t")
    msg = str(e.value)
    assert "gateway" in msg and "vault_item" in msg
    # config is now OPTIONAL (defaults to the bundled client) — valid without it
    nocfg = ("vpn: {enabled: true, type: inode, gateway: g, vault_item: I}\n"
             "display: {cols: 1, rows: 1}\n"
             "panels:\n  - {id: a, grid: [0,0], mode: direct, url: 'http://x/'}\n")
    assert config.vpn_kind(config.load_str(nocfg, "t").vpn) == "inode"


def test_inode_render_roundtrips():
    spec = importlib.util.spec_from_file_location(
        "s_render", os.path.join(_REPO, "setup.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    cfg = {
        "display": {"auto": True, "width": 1920, "height": 1080, "cols": 1,
                    "rows": 1, "gap": 0, "layout": "auto"},
        "panels": [{"id": "a", "engine": "webkit", "grid": [0, 0], "mode": "direct",
                    "url": "http://x/", "vault_item": "",
                    "selectors": {"user": "#u", "pass": "#p", "submit": "b"},
                    "login_marker": "#p", "keepalive": {"strategy": "none"}}],
        "tunnel": {"enabled": False},
        "vpn": {"enabled": True, "type": "inode", "gateway": "g", "port": 3000,
                "vault_item": "I", "config": "/opt/iNode", "domain": "system",
                "trusted_cert": "AA:BB", "insecure": False},
        "proxy": {"enabled": False},
    }
    c = config.load_str(m.render_panels_yaml(cfg), "render")
    assert config.vpn_kind(c.vpn) == "inode"
    assert c.vpn["gateway"] == "g" and c.vpn["vault_item"] == "I"
    assert c.vpn["config"] == "/opt/iNode" and c.vpn["domain"] == "system"


# -- wire-level: tunnel preamble body cap -------------------------------------
# After NET_EXTEND the netconfig is read on the raw socket (not via the capped
# httpclient). A hostile gateway must not be able to drive an unbounded
# reassembly buffer by declaring a giant Content-Length; the preamble reader
# enforces the same C.MAX_BODY_BYTES cap that Connection._read_exact does.

def _load_h3c_session():
    if _BACKENDS not in sys.path:
        sys.path.insert(0, _BACKENDS)
    try:
        from h3csvpn import constants as C  # noqa: WPS433 (vendored package)
        from h3csvpn import session as s
    except Exception as exc:  # pragma: no cover - backend must import here
        pytest.skip(f"h3csvpn backend unavailable: {exc}")
    return C, s


class _FakeConn:
    """Minimal stand-in for httpclient.Connection for _read_tunnel_preamble:
    exposes a real (selectable) socket and the take_buffered() leftover API."""

    def __init__(self, sock, buffered=b""):
        self.sock = sock
        self._buf = buffered

    def take_buffered(self):
        out, self._buf = self._buf, b""
        return out


def _make_session(s):
    return s.SslVpnSession(s.Credentials("u", "p"), s.Options(host="h"))


def test_tunnel_preamble_rejects_oversized_content_length():
    """A gateway declaring Content-Length > MAX_BODY_BYTES is rejected up front
    with AuthError, before the recv loop can grow the reassembly buffer."""
    C, s = _load_h3c_session()
    sess = _make_session(s)
    a, b = socket.socketpair()
    try:
        head = (b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: %d\r\n\r\n" % (C.MAX_BODY_BYTES + 1))
        a.sendall(head)
        with pytest.raises(s.AuthError) as e:
            sess._read_tunnel_preamble(_FakeConn(b))
        msg = str(e.value).lower()
        assert "content-length" in msg and "exceeds" in msg
    finally:
        a.close()
        b.close()


def test_tunnel_preamble_parses_bounded_netconfig_body():
    """The unchanged success path: a small HTTP-body netconfig (Content-Length
    well under the cap) is still read and parsed."""
    _C, s = _load_h3c_session()
    sess = _make_session(s)
    a, b = socket.socketpair()
    try:
        body = b"IPADDRESS:10.0.0.2\nSUBNETMASK:255.255.255.0\n"
        head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)
        a.sendall(head + body)
        leftover, cfg = sess._read_tunnel_preamble(_FakeConn(b))
        assert cfg is not None
        assert leftover == b""
    finally:
        a.close()
        b.close()
