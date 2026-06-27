"""
RFC 6238 TOTP, stdlib only — no pyotp dependency.

Used by the on-wall kiosk lock (locker.py) so the operator can unlock with a
phone authenticator code as well as / instead of a static PIN. The same
shared-secret -> 6-digit-code algorithm Google Authenticator / Authy /
1Password / Bitwarden all implement.

Why no pyotp:
  * the project keeps stdlib + a couple of well-vetted deps; pyotp would be
    a new dep for something we can implement in ~30 lines and unit-test
    against RFC 4226 / 6238 official vectors.
  * fewer moving parts in the path between "operator types 6 digits" and
    "PIN/TOTP unlock". HMAC-SHA1 is the only thing we need.

Public surface (all stateless except generate_secret + the on-disk store):

    generate_secret() -> str                # 20 random bytes, base32-encoded
    totp(secret_b32, *, t=None, step=30, digits=6, algorithm="sha1") -> str
    verify(secret_b32, code, *, window=1, **kw) -> bool
    provision_uri(secret_b32, label, issuer="SOC Wall", **kw) -> str

    load(path) -> str | None                # read a stored base32 secret
    save(path, secret_b32) -> None          # write 0600 secret to path
    clear(path) -> None                     # remove the stored secret

TOTP storage is FILE-backed only — the secret lives 0600 in $SOC_STATE_DIR
alongside panellock.pin. (Our vaultseed lacks upsert_secure_note/delete_login,
so there is no vault-write path here.)
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
import urllib.parse


_VALID_ALGOS = {"sha1": hashlib.sha1,
                "sha256": hashlib.sha256,
                "sha512": hashlib.sha512}


def generate_secret(num_bytes: int = 20) -> str:
    """20 random bytes encoded as RFC 4648 base32 (no padding) — the standard
    Google Authenticator seed length. The trailing `=` padding is stripped
    because most authenticator apps accept it stripped + adding it back is
    cheap (we do it ourselves before decoding)."""
    if num_bytes < 16:
        raise ValueError("TOTP secret must be at least 16 bytes (128 bits)")
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def _decode_secret(secret_b32: str) -> bytes:
    """Tolerant base32 decode. Accepts mixed-case, spaces, missing padding —
    operators copy-paste these from QR codes / phones, so be generous."""
    s = re.sub(r"\s+", "", secret_b32).upper()
    if not s or not re.fullmatch(r"[A-Z2-7=]+", s):
        raise ValueError(f"not valid base32: {secret_b32!r}")
    # pad to a multiple of 8
    pad = (-len(s)) % 8
    try:
        return base64.b32decode(s + "=" * pad, casefold=False)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"base32 decode failed: {e}") from None


def totp(secret_b32: str, *, t: float | None = None,
         step: int = 30, digits: int = 6,
         algorithm: str = "sha1") -> str:
    """RFC 6238 TOTP code. `t` is the unix-time seconds (default: now).
    `step` is the time-step seconds (30 is RFC default).
    `algorithm` is "sha1" / "sha256" / "sha512" (sha1 is RFC default + what
    every authenticator app actually uses)."""
    if not 6 <= digits <= 10:
        raise ValueError("digits must be 6..10")
    h = _VALID_ALGOS.get(algorithm.lower())
    if h is None:
        raise ValueError(f"unsupported algorithm: {algorithm!r}")
    key = _decode_secret(secret_b32)
    counter = int((t if t is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    mac = hmac.new(key, msg, h).digest()
    # RFC 4226 dynamic truncation
    offset = mac[-1] & 0x0F
    code_int = (
        ((mac[offset] & 0x7F) << 24)
        | (mac[offset + 1] << 16)
        | (mac[offset + 2] << 8)
        | mac[offset + 3]
    ) % (10 ** digits)
    return str(code_int).zfill(digits)


def verify(secret_b32: str, code: str, *, window: int = 1,
           step: int = 30, digits: int = 6, algorithm: str = "sha1",
           t: float | None = None) -> bool:
    """Verify `code` against `secret_b32`. `window` is the +/- number of
    `step` intervals to accept (default 1 → ±30 s tolerance for clock skew
    + the user typing the code at the edge of an interval).

    Uses hmac.compare_digest on each comparison so the timing of a wrong
    code can't leak which digit was wrong."""
    if not code or not code.isdigit():
        return False
    code = code.strip().zfill(digits)
    now = t if t is not None else time.time()
    for w in range(-window, window + 1):
        cand = totp(secret_b32, t=now + w * step, step=step,
                    digits=digits, algorithm=algorithm)
        if hmac.compare_digest(cand, code):
            return True
    return False


def provision_uri(secret_b32: str, label: str, issuer: str = "SOC Wall",
                  *, step: int = 30, digits: int = 6,
                  algorithm: str = "sha1") -> str:
    """`otpauth://totp/...` URI suitable for a QR code. The standard format
    a phone authenticator scans to enroll the wall's secret."""
    # Standard otpauth label shape: "Issuer:account" — keep `@` and `:`
    # un-escaped so it reads `Issuer:user@host` after URL-decode, the way
    # every authenticator app expects.
    label_q = urllib.parse.quote(f"{issuer}:{label}", safe=":/@")
    params = urllib.parse.urlencode({
        "secret": secret_b32.replace(" ", "").upper().rstrip("="),
        "issuer": issuer,
        "algorithm": algorithm.upper(),
        "digits": digits,
        "period": step,
    })
    return f"otpauth://totp/{label_q}?{params}"


# --- tiny on-disk store ---------------------------------------------------- #
# A TOTP secret is just a base32 string — single line, no extra metadata.
# We store it 0600 in $SOC_STATE_DIR alongside config.pin.

def load(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            s = fh.read().strip()
        return s or None
    except (OSError, ValueError):
        return None


def save(path: str, secret_b32: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(secret_b32.strip() + "\n")


def clear(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
