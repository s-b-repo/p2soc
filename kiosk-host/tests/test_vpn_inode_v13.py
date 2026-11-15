"""Regression tests recovered from v1.3.0 (test_vpn_inode.py): cases for this line's own
features that were lost when the suite was replaced. Kept separate so they stay
visibly additive to test_vpn_inode.py."""
import importlib.util


import os


import socket


import sys


import pytest


from host import config, vpndrivers


_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


_BACKENDS = os.path.join(_REPO, "vendor", "iNode-VPN-Client", "backends")


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
