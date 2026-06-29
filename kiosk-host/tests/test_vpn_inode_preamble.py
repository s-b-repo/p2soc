"""h3c SSL-VPN tunnel preamble: gateway-controlled sizes must be capped.

``SslVpnSession._read_tunnel_preamble`` re-implements HTTP framing directly on
the raw tunnel socket after NET_EXTEND (the only gateway-facing read path that
does not go through ``httpclient.Connection``). The VPN gateway is external and
potentially hostile, so the preamble parser must enforce the same RAM caps the
rest of the client does:

  * a never-terminating HTTP *header* block must be rejected at MAX_HEADER_BYTES
  * an oversized ``Content-Length`` *body* must be rejected at MAX_BODY_BYTES

Both would otherwise let a malicious gateway exhaust RAM and OOM-kill the root
VPN process on the 1 GB Pi. These tests feed malformed gateway responses over a
real socketpair (so ``select.select`` behaves) and assert rejection.
"""
import os
import socket
import sys

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_VENDOR = os.path.join(_REPO, "vendor", "iNode-VPN-Client")
if _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

session = pytest.importorskip("backends.h3csvpn.session")
from backends.h3csvpn.httpclient import Connection  # noqa: E402
from backends.h3csvpn import constants as C  # noqa: E402
from backends.h3csvpn import tunnel as tunnelmod  # noqa: E402


def _session():
    creds = session.Credentials(username="u", password="p")
    return session.SslVpnSession(creds, session.Options(), log=lambda m: None)


def _conn_feeding(payload: bytes) -> Connection:
    """A Connection whose socket already has ``payload`` queued to recv().

    Uses a real socketpair so ``select.select`` on ``sock`` reports readable.
    The far end stays open, so reads block (not EOF) once the queued bytes are
    drained — modelling a gateway that keeps the connection up while streaming.
    """
    near, far = socket.socketpair()
    far.sendall(payload)
    conn = Connection(near, host="gw", port=443)
    # keep a reference so the far end is not GC-closed mid-test
    conn._test_far = far  # type: ignore[attr-defined]
    return conn


def test_preamble_rejects_unbounded_header_block():
    """A never-terminating header block (no CRLFCRLF) is capped, not buffered
    without bound."""
    cap = session.C.MAX_HEADER_BYTES
    # HTTP-looking start so we enter the header loop, then endless filler with
    # no header terminator. More than the cap so the guard must fire.
    payload = b"HTTP/1.1 200 OK\r\nX-Filler: " + b"A" * (cap + 4096)
    conn = _conn_feeding(payload)
    sess = _session()
    with pytest.raises(session.AuthError) as ei:
        sess._read_tunnel_preamble(conn)
    assert "header" in str(ei.value).lower()
    conn._test_far.close()  # type: ignore[attr-defined]


def test_preamble_rejects_oversized_content_length():
    """A Content-Length larger than MAX_BODY_BYTES is rejected before the body
    read loop, so no allocation/streaming of attacker-sized data occurs."""
    over = session.C.MAX_BODY_BYTES + 1
    payload = (b"HTTP/1.1 200 OK\r\n"
               b"Content-Length: " + str(over).encode() + b"\r\n\r\n")
    conn = _conn_feeding(payload)
    sess = _session()
    with pytest.raises(session.AuthError) as ei:
        sess._read_tunnel_preamble(conn)
    msg = str(ei.value).lower()
    assert "cap" in msg and ("body" in msg or "content-length" in msg)
    conn._test_far.close()  # type: ignore[attr-defined]


def test_preamble_accepts_normal_header_param_block():
    """The legitimate path still works: a small HTTP preamble carrying the param
    block in the headers (IPADDRESS/...) parses without raising."""
    payload = (b"HTTP/1.1 200 OK\r\n"
               b"IPADDRESS:10.0.0.2\r\n"
               b"SUBNETMASK:255.255.255.0\r\n"
               b"Content-Length: 0\r\n\r\n")
    conn = _conn_feeding(payload)
    sess = _session()
    leftover, netcfg = sess._read_tunnel_preamble(conn)
    assert netcfg is not None
    assert netcfg.ipaddress == "10.0.0.2"
    conn._test_far.close()  # type: ignore[attr-defined]


# -- wait_netconfig early-frame flood cap -------------------------------------
# While Tunnel.wait_netconfig waits for the first netconfig frame after
# NET_EXTEND, every non-netconfig frame is retained in self._early. Without a
# cap, a post-TLS gateway that floods data frames for the whole timeout could
# pile hundreds of MB into self._early -> a memory spike that matters on the
# 1 GB Pi. The accumulated payload bytes are now bounded by C.MAX_EARLY_BYTES.

def _frame(ftype: int, subtype: int, payload: bytes = b"") -> bytes:
    return tunnelmod.encode_frame(ftype, subtype, payload)


def test_wait_netconfig_caps_early_frame_flood(monkeypatch):
    """A gateway that streams non-netconfig data frames (and never sends the
    netconfig) is cut off once retained early-frame bytes exceed the cap, rather
    than buffering for the full timeout window."""
    # Shrink the cap so the test stays cheap and stays within socketpair buffers.
    monkeypatch.setattr(C, "MAX_EARLY_BYTES", 64 * 1024)
    near, far = socket.socketpair()
    try:
        # Each data frame carries a 4 KiB payload; >16 of them exceed 64 KiB.
        flood = _frame(C.FRAME_DATA, 0, b"x" * 4096) * 32
        far.sendall(flood)
        tun = tunnelmod.Tunnel(near, None, log=lambda m: None)
        with pytest.raises(tunnelmod.TunnelClosed) as ei:
            tun.wait_netconfig(timeout=5.0)
        assert "early frames" in str(ei.value).lower()
    finally:
        near.close()
        far.close()


def test_wait_netconfig_retains_bounded_early_frames(monkeypatch):
    """Behavior-preserving: a handful of early data frames before the netconfig
    are still retained for run() and the netconfig is found and parsed."""
    monkeypatch.setattr(C, "MAX_EARLY_BYTES", 64 * 1024)
    near, far = socket.socketpair()
    try:
        early = (_frame(C.FRAME_DATA, 0, b"early-packet-1")
                 + _frame(C.FRAME_DATA, 0, b"early-packet-2"))
        netcfg = _frame(C.FRAME_NETCONFIG, C.NETCONFIG_SUB_UPDATE,
                        b"IPADDRESS:10.0.0.2\nGATEWAY:10.0.0.1\n")
        far.sendall(early + netcfg)
        tun = tunnelmod.Tunnel(near, None, log=lambda m: None)
        cfg = tun.wait_netconfig(timeout=5.0)
        assert cfg is not None and cfg.ipaddress == "10.0.0.2"
        # the two pre-netconfig data frames were retained, not dropped
        assert len(tun._early) == 2
        assert all(ft == C.FRAME_DATA for ft, _, _ in tun._early)
    finally:
        near.close()
        far.close()
