"""H3C iNode SSL-VPN captcha decoder — malformed-BMP rejection / DoS bounds.

``decode_bmp`` is fed the untrusted ``/vldimg.cgi`` image body straight from the
(possibly hostile / MITM'd) gateway. These tests pin the input-validation
boundary: truncated headers raise the module's documented ``ValueError`` (not a
leaked ``struct.error``), and an over-declared 8-bit palette count cannot drive
an unbounded allocation loop on the 1 GB board.
"""
import importlib.util
import os
import struct
import time

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_CAPTCHA_PY = os.path.join(
    _REPO, "vendor", "iNode-VPN-Client", "backends", "h3csvpn", "captcha.py")


def _load_captcha():
    spec = importlib.util.spec_from_file_location("h3c_captcha", _CAPTCHA_PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


cap = _load_captcha()


# -- helpers: build minimal valid BMPs --------------------------------------
def _bmp24(width, height, pixels_rgb):
    """24bpp BMP. ``pixels_rgb[y][x] == (r, g, b)`` with row 0 at the TOP."""
    dib, bpp = 40, 24
    stride = ((bpp * width + 31) // 32) * 4
    pix_off = 14 + dib
    body = bytearray()
    for ry in range(abs(height) - 1, -1, -1):          # stored bottom-up
        rowb = bytearray()
        for x in range(width):
            r, g, b = pixels_rgb[ry][x]
            rowb += bytes((b, g, r))
        rowb += b"\x00" * (stride - len(rowb))
        body += rowb
    fh = b"BM" + struct.pack("<IHHI", pix_off + len(body), 0, 0, pix_off)
    ih = struct.pack("<IiiHHIIiiII", dib, width, height, 1, bpp, 0,
                     len(body), 0, 0, 0, 0)
    return bytes(fh + ih + body)


def _bmp8(width, height, ncol_field, palette_entries, pixel_indices,
          body_pad=0):
    """8bpp BMP. ``ncol_field`` is the (attacker-controllable) clrUsed@46 value;
    ``body_pad`` injects extra bytes into the palette region to widen the body."""
    dib, bpp = 40, 8
    stride = ((bpp * width + 31) // 32) * 4
    palette = bytearray()
    for (r, g, b) in palette_entries:
        palette += bytes((b, g, r, 0))
    palette += b"\x00" * body_pad
    pix_off = 14 + dib + len(palette)
    body = bytearray()
    for ry in range(abs(height) - 1, -1, -1):
        rowb = bytearray(pixel_indices[ry])
        rowb += b"\x00" * (stride - len(rowb))
        body += rowb
    fh = b"BM" + struct.pack("<IHHI", pix_off + len(body), 0, 0, pix_off)
    ih = struct.pack("<IiiHHIIiiII", dib, width, height, 1, bpp, 0,
                     len(body), 0, 0, ncol_field, 0)
    return bytes(fh + ih + palette + body)


# -- valid decode still works (behaviour-preserving) ------------------------
def test_decode_bmp_24bpp_roundtrip():
    px = [[(10, 20, 30), (40, 50, 60)], [(70, 80, 90), (100, 110, 120)]]
    w, h, rows = cap.decode_bmp(_bmp24(2, 2, px))
    assert (w, h) == (2, 2)
    assert rows == px


def test_decode_bmp_8bpp_roundtrip():
    pal = [(11, 22, 33), (44, 55, 66)]
    w, h, rows = cap.decode_bmp(_bmp8(2, 2, 2, pal, [[0, 1], [1, 0]]))
    assert (w, h) == (2, 2)
    assert rows == [[(11, 22, 33), (44, 55, 66)],
                    [(44, 55, 66), (11, 22, 33)]]


# -- fix 2: truncated header -> ValueError, not leaked struct.error ----------
def test_not_a_bmp_rejected():
    with pytest.raises(ValueError):
        cap.decode_bmp(b"\x89PNG\r\n")


@pytest.mark.parametrize("n", [2, 14, 33, 53])
def test_truncated_header_raises_valueerror(n):
    # 'BM' magic passes, but the body is shorter than a full 54-byte header.
    with pytest.raises(ValueError):
        cap.decode_bmp(b"BM" + b"\x00" * (n - 2))


# -- fix 1a: over-declared palette count is bounded (no OOM/CPU DoS) ----------
def test_oversized_palette_count_is_capped_and_fast():
    # ncol declared as 5,000,000 but a tiny body — the loop must not iterate
    # past the legitimate maximum / the buffer, so decode stays trivial.
    data = _bmp8(2, 2, 5_000_000, [(1, 2, 3), (4, 5, 6)], [[0, 1], [1, 0]])
    t = time.time()
    w, h, rows = cap.decode_bmp(data)
    assert time.time() - t < 0.5
    assert rows == [[(1, 2, 3), (4, 5, 6)], [(4, 5, 6), (1, 2, 3)]]


def test_oversized_palette_count_with_large_body_is_bounded():
    # The original DoS: pad the palette region toward MAX_BODY so a naive loop
    # would build millions of tuples. The 1<<bpp cap holds it to <=256 entries.
    data = _bmp8(2, 2, 5_000_000, [(1, 2, 3), (4, 5, 6)], [[0, 1], [1, 0]],
                 body_pad=8 * 1024 * 1024)
    t = time.time()
    w, h, rows = cap.decode_bmp(data)
    assert time.time() - t < 0.5
    assert rows[0][0] == (1, 2, 3)


# -- fix 1b: pixel index past a short palette -> safe fallback, not IndexError
def test_pixel_index_beyond_short_palette_does_not_crash():
    # ncol=1 (one real colour) but pixels reference index 1; out-of-range
    # indices fall back to black instead of raising IndexError mid-decode.
    w, h, rows = cap.decode_bmp(_bmp8(2, 2, 1, [(9, 9, 9)], [[0, 1], [1, 0]]))
    assert rows[0] == [(9, 9, 9), (0, 0, 0)]
    assert rows[1] == [(0, 0, 0), (9, 9, 9)]
