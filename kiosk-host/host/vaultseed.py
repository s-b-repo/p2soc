"""
Write a credential into Vaultwarden over its REST API.

So setup.py and the on-screen Settings can *store* usernames/passwords (and a
VPN config in Notes) in the vault — the kiosk still READS them via rbw. This is
the programmatic equivalent of adding a login in the web vault, generalised from
dev/seed-ciphers.py.

Needs the `cryptography` package (imported lazily). When it is absent, callers
get a VaultSeedError telling the operator to add the login in the web vault
instead — so this stays an optional convenience, never a hard dependency of the
running wall.

Supports PBKDF2 master-key KDF (Vaultwarden's default). An Argon2 vault raises a
clear error.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request


class VaultSeedError(Exception):
    pass


# Cap on a single Vaultwarden HTTP response body. A real personal vault's
# /api/ciphers is well under this; the ceiling exists so a compromised/MITM'd
# endpoint can't stream a multi-GB (or infinite) body into one bytes object and
# OOM the 1 GB Pi. Mirrors the h3c httpclient's MAX_BODY_BYTES defense.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _ub64(s: str) -> bytes:
    return base64.b64decode(s)


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
        return Cipher, algorithms, modes
    except ImportError:
        raise VaultSeedError(
            "the 'cryptography' package is required to write into Vaultwarden — "
            "install it (pip install cryptography), or add the login in the "
            "Vaultwarden web vault instead")


def _enc(plaintext: bytes, ek: bytes, mk: bytes) -> str:
    Cipher, algorithms, modes = _aes()
    iv = os.urandom(16)
    pad = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    mac = hmac.new(mk, iv + ct, hashlib.sha256).digest()
    return f"2.{_b64(iv)}|{_b64(ct)}|{_b64(mac)}"


def _dec(s: str, ek: bytes, mk: bytes) -> bytes:
    Cipher, algorithms, modes = _aes()
    body = s.split(".", 1)
    parts = body[1].split("|") if len(body) == 2 else []
    if len(parts) != 3:
        raise VaultSeedError("malformed EncString")
    try:
        iv, ct, mac = (_ub64(p) for p in parts)
    except (ValueError, TypeError) as e:  # binascii.Error is a ValueError
        raise VaultSeedError(f"bad EncString base64: {e}")
    if not hmac.compare_digest(
            hmac.new(mk, iv + ct, hashlib.sha256).digest(), mac):
        raise VaultSeedError("MAC mismatch decrypting the account key")
    dec = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    if not pt or pt[-1] < 1 or pt[-1] > 16:
        raise VaultSeedError("bad PKCS7 padding")
    return pt[:-pt[-1]]


def _req(url, headers=None, data=None, method="GET", form=False):
    h = dict(headers or {})
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            buf = r.read(MAX_RESPONSE_BYTES + 1)
            if len(buf) > MAX_RESPONSE_BYTES:
                raise VaultSeedError(
                    f"{method} {url}: vault response exceeds "
                    f"{MAX_RESPONSE_BYTES} bytes")
            raw = buf.decode()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        raise VaultSeedError(f"{method} {url} -> HTTP {e.code}: "
                             f"{e.read().decode()[:200]}")
    except OSError as e:
        raise VaultSeedError(f"could not reach Vaultwarden at {url}: {e}")


class Session:
    """An authenticated Vaultwarden session that can create/update logins."""

    def __init__(self, url: str, email: str, master_password: str):
        self.base = url.rstrip("/")
        email = email.lower()
        pw = master_password.encode()

        pre = _req(self.base + "/identity/accounts/prelogin",
                   data={"email": email}, method="POST")
        kdf = int(pre.get("kdf", pre.get("Kdf", 0)) or 0)
        iters = int(pre.get("kdfIterations", pre.get("KdfIterations", 600000)) or 600000)
        if kdf != 0:
            raise VaultSeedError("this vault uses the Argon2 KDF — vaultseed "
                                 "supports PBKDF2 only; add the login in the web vault")

        master_key = hashlib.pbkdf2_hmac("sha256", pw, email.encode(), iters, 32)
        master_hash = _b64(hashlib.pbkdf2_hmac("sha256", master_key, pw, 1, 32))
        senc = _hkdf_expand(master_key, b"enc")
        smac = _hkdf_expand(master_key, b"mac")

        tok = _req(self.base + "/identity/connect/token", data={
            "grant_type": "password", "username": email, "password": master_hash,
            "scope": "api offline_access", "client_id": "cli", "deviceType": "8",
            "deviceIdentifier": "soc-setup-0001", "deviceName": "soc-setup",
        }, method="POST", form=True)
        if "Key" not in tok or "access_token" not in tok:
            raise VaultSeedError("login failed — check the email/master password")
        sym = _dec(tok["Key"], senc, smac)              # 64-byte account key
        self.ek, self.mk = sym[:32], sym[32:]
        self.auth = {"Authorization": f"Bearer {tok['access_token']}"}

    def _ciphers(self):
        r = _req(self.base + "/api/ciphers", headers=self.auth)
        return r.get("Data", r.get("data", []))

    def _find(self, name: str):
        for c in self._ciphers():
            enc_name = c.get("Name") or c.get("name")
            try:
                if enc_name and _dec(enc_name, self.ek, self.mk).decode() == name:
                    return c.get("Id") or c.get("id")
            except VaultSeedError:
                continue
        return None

    def upsert_login(self, name, username, password, notes=None, uri=None) -> str:
        """Create or update a login item named `name`. Returns 'created'|'updated'."""
        def e(s):
            return _enc(s.encode(), self.ek, self.mk)
        body = {
            "type": 1,
            "name": e(name),
            "favorite": False,
            "notes": e(notes) if notes else None,
            "login": {
                "username": e(username) if username else None,
                "password": e(password) if password else None,
                "uris": [{"uri": e(uri), "match": None}] if uri else None,
            },
        }
        cid = self._find(name)
        if cid:
            _req(self.base + f"/api/ciphers/{cid}", headers=self.auth,
                 data=body, method="PUT")
            return "updated"
        _req(self.base + "/api/ciphers", headers=self.auth, data=body, method="POST")
        return "created"


def upsert_login(url, email, master_password, name, username, password,
                 notes=None, uri=None) -> str:
    """One-shot: log in and create/update a Vaultwarden login. Returns the action."""
    return Session(url, email, master_password).upsert_login(
        name, username, password, notes=notes, uri=uri)


def available() -> bool:
    """True if the crypto backend needed to write is importable."""
    try:
        _aes()
        return True
    except VaultSeedError:
        return False
