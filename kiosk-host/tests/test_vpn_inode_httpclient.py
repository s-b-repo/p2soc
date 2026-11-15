"""H3C SSL-VPN httpclient parse-boundary hardening.

These tests drive the vendored ``h3csvpn.httpclient.Connection`` HTTP/1.1 parser
with a fake socket feeding attacker-controlled bytes, proving the size/length
guards at the untrusted-gateway parse boundary:

  * a negative chunk-size line (``-1\\r\\n``) is rejected instead of slicing the
    reassembly buffer with a negative index (and bypassing MAX_BODY_BYTES);
  * a hostile gateway dribbling endless trailer lines after the final 0-size
    chunk is bounded by MAX_TRAILER_LINES rather than hanging the auth path.

A well-formed chunked body is also decoded to guard against regressions.
"""
import os
import sys

import pytest

# The vendored h3csvpn package uses relative imports (``from . import
# constants``), so it must be importable as the top-level package ``h3csvpn``.
# Add the ``backends`` directory (its parent) to sys.path, mirroring how
# transport.py / session.py import ``from .httpclient import Connection``.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_BACKENDS = os.path.join(_REPO, "vendor", "iNode-VPN-Client", "backends")
if _BACKENDS not in sys.path:
    sys.path.insert(0, _BACKENDS)

h3c = pytest.importorskip("h3csvpn.httpclient")
hc_const = pytest.importorskip("h3csvpn.constants")


class _FakeSock:
    """A minimal stream socket that hands out a queued response in chunks.

    ``recv`` pops the next pre-baked slice; an empty queue returns ``b""`` which
    the client treats as 'connection closed by peer'. ``sendall`` is a no-op.
    """

    def __init__(self, slices):
        self._slices = list(slices)

    def sendall(self, data):  # requests are not under test here
        return None

    def recv(self, _n):
        if not self._slices:
            return b""
        return self._slices.pop(0)


def _conn(payload: bytes) -> "h3c.Connection":
    return h3c.Connection(_FakeSock([payload]), "gw.example", 443)


def _resp_with_body(body_block: bytes) -> bytes:
    return (b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n") + body_block


def test_well_formed_chunked_body_decodes():
    # "abc" + "de" across two chunks, then the 0-size terminator (no trailers).
    body = b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
    resp = _conn(_resp_with_body(body))._read_response()
    assert resp.body == b"abcde"
    assert resp.status == 200


def test_negative_chunk_size_is_rejected():
    # A hostile gateway sends a negative chunk size; int("-1", 16) == -1, which
    # historically slipped past the `n > MAX_BODY_BYTES` check and sliced the
    # reassembly buffer with a negative index. It must now raise HTTPError.
    body = b"-1\r\nignored\r\n0\r\n\r\n"
    with pytest.raises(h3c.HTTPError) as ei:
        _conn(_resp_with_body(body))._read_response()
    assert "negative" in str(ei.value).lower()


def test_negative_read_exact_rejected_directly():
    c = _conn(b"")
    with pytest.raises(h3c.HTTPError):
        c._read_exact(-1)
    # The legitimate zero-length read is still allowed (chunked 0-size path).
    assert c._read_exact(0) == b""


def test_oversize_chunk_size_still_capped():
    # Sanity: the existing upper bound continues to fire (behavior preserved).
    big = format(hc_const.MAX_BODY_BYTES + 1, "x").encode()
    body = big + b"\r\nx\r\n0\r\n\r\n"
    with pytest.raises(h3c.HTTPError) as ei:
        _conn(_resp_with_body(body))._read_response()
    assert "exceeds cap" in str(ei.value)


def test_trailer_lines_are_bounded():
    # After the 0-size chunk, a gateway that never sends the terminating empty
    # CRLF (only endless short trailer lines) must be cut off by
    # MAX_TRAILER_LINES instead of looping forever.
    trailers = b"X\r\n" * (hc_const.MAX_TRAILER_LINES + 5)
    body = b"0\r\n" + trailers  # no final b"\r\n" -> would loop unbounded
    with pytest.raises(h3c.HTTPError) as ei:
        _conn(_resp_with_body(body))._read_response()
    assert "trailer" in str(ei.value).lower()


def test_a_few_trailers_then_terminator_is_fine():
    # A handful of real trailers followed by the empty CRLF decodes normally.
    body = b"3\r\nabc\r\n0\r\nFoo: bar\r\nBaz: qux\r\n\r\n"
    resp = _conn(_resp_with_body(body))._read_response()
    assert resp.body == b"abc"
