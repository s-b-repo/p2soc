"""
Write a credential into Vaultwarden over its REST API.

So setup.py and the on-screen Settings can *store* usernames/passwords (and a
VPN config in Notes) in the vault — the kiosk still READS them from the vault. This is
the programmatic equivalent of adding a login in the web vault, generalised from
dev/seed-ciphers.py.

Needs the `cryptography` package (imported lazily). When it is absent, callers
get a VaultSeedError telling the operator to add the login in the web vault
instead — so this stays an optional convenience, never a hard dependency of the
running wall.

Supports both the PBKDF2 (Vaultwarden's default) and Argon2id master-key KDFs:
key derivation is routed through litebw.derive_master_key (lazy import), so the
editor works on modern Argon2id accounts exactly like the wall reader does.
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


class LoginRejectedError(VaultSeedError):
    """Vaultwarden refused the password grant. Its 400 invalid_grant covers both
    'no such account' and 'wrong password' (anti-enumeration), so the caller
    cannot tell which — only that the server answered and said no."""


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


def _token_subject(token: str) -> str:
    """The user id from a Bitwarden access token (the JWT `sub` claim), or '' if it
    can't be read. Only used to label our own writes, so the signature doesn't need
    verifying: the server does that on every request."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get("sub", ""))
    except (IndexError, ValueError):
        return ""


class Session:
    """An authenticated Vaultwarden session that can create/update logins."""

    user_id = ""

    def __init__(self, url: str, email: str, master_password: str):
        self.base = url.rstrip("/")
        email = email.lower()

        pre = _req(self.base + "/identity/accounts/prelogin",
                   data={"email": email}, method="POST")
        kdf = int(pre.get("kdf", pre.get("Kdf", 0)) or 0)
        # Clamp the server-supplied iteration count: /identity/accounts/prelogin
        # is UNAUTHENTICATED network input, so a hostile/MITM'd Vaultwarden could
        # declare kdfIterations in the billions to pin the 1 GB Pi's CPU for
        # minutes during a credential-edit unlock. The 10M ceiling (with a >=1
        # floor) is a no-op for any real vault (Bitwarden default 600k) and
        # mirrors litebw.derive_master_key's identical hardening.
        iters = min(max(1, int(pre.get("kdfIterations",
                                       pre.get("KdfIterations", 600000)) or 600000)),
                    10_000_000)
        mem = int(pre.get("kdfMemory", pre.get("KdfMemory", 0)) or 0)
        par = int(pre.get("kdfParallelism", pre.get("KdfParallelism", 0)) or 0)

        # Route key derivation through litebw so this editor supports Argon2id
        # vaults (the modern Bitwarden/Vaultwarden default) exactly like the wall
        # reader does. Lazy import is REQUIRED: litebw imports vaultseed at module
        # top (litebw.py:50), so a top-level import here would be circular. For a
        # PBKDF2 vault (kdf==0) derive_master_key / master_password_hash are
        # byte-identical to the previous inline PBKDF2 (salt=email.lower(), same
        # iters; auth hash = pbkdf2(master_key, pw, 1, 32)).
        from host import litebw
        master_key = litebw.derive_master_key(master_password, email, kdf,
                                              iters, mem, par)
        master_hash = litebw.master_password_hash(master_key, master_password)
        senc = _hkdf_expand(master_key, b"enc")
        smac = _hkdf_expand(master_key, b"mac")

        try:
            tok = _req(self.base + "/identity/connect/token", data={
                "grant_type": "password", "username": email, "password": master_hash,
                "scope": "api offline_access", "client_id": "cli", "deviceType": "8",
                "deviceIdentifier": "soc-setup-0001", "deviceName": "soc-setup",
            }, method="POST", form=True)
        except VaultSeedError as e:
            if "HTTP 400" in str(e) or "HTTP 401" in str(e):
                raise LoginRejectedError(
                    f"Vaultwarden rejected the login for '{email}'. Either the "
                    f"master password is wrong, or no account exists for that "
                    f"email — register at {self.base}/#/login (a kiosk install "
                    f"typically uses setup.py first-run, which can register the "
                    f"account for you).")
            raise
        if "Key" not in tok or "access_token" not in tok:
            raise VaultSeedError("login failed — check the email/master password")
        sym = _dec(tok["Key"], senc, smac)              # 64-byte account key
        self.ek, self.mk = sym[:32], sym[32:]
        self.auth = {"Authorization": f"Bearer {tok['access_token']}"}
        self.user_id = _token_subject(tok["access_token"])

    def _for_user(self, body: dict) -> dict:
        """Current Vaultwarden rejects a cipher write with HTTP 422 unless it names
        the user it was encrypted for; older servers ignore the field."""
        if self.user_id:
            body["encryptedFor"] = self.user_id
        return body

    def _ciphers(self):
        r = _req(self.base + "/api/ciphers", headers=self.auth)
        return r.get("Data", r.get("data", []))

    def _find_typed(self, name: str, cipher_type: int):
        """Cipher id of the live cipher of `cipher_type` named `name`, or None.
        Only that type matches, so an update/delete can never hit a different kind
        of item, or a trashed one, that happens to share the visible name."""
        for c in self._ciphers():
            if (c.get("Type") or c.get("type")) != cipher_type:
                continue
            if c.get("DeletedDate") or c.get("deletedDate"):
                continue
            enc_name = c.get("Name") or c.get("name")
            try:
                if enc_name and _dec(enc_name, self.ek, self.mk).decode() == name:
                    return c.get("Id") or c.get("id")
            except (VaultSeedError, ValueError):
                continue
        return None

    def _find_login(self, name: str):
        """Cipher id of the LOGIN named `name`, or None. Mirrors the read paths
        (list_logins/get_login)."""
        return self._find_typed(name, 1)

    def _find(self, name: str):
        """Cipher id of the SECURE NOTE named `name`, or None — the lookup behind
        upsert_secure_note/delete_item, so a note write can never overwrite a login
        of the same name and a repeat write updates the note instead of adding a
        duplicate. Logins go through _find_login."""
        return self._find_typed(name, 2)

    def _folder_id(self, folder: str) -> str:
        """Id of the folder named `folder`, created if absent. Folder names are
        encrypted, so they can only be matched client-side."""
        r = _req(self.base + "/api/folders", headers=self.auth)
        for f in r.get("Data", r.get("data", [])):
            enc_name = f.get("Name") or f.get("name")
            try:
                if enc_name and _dec(enc_name, self.ek, self.mk).decode() == folder:
                    return f.get("Id") or f.get("id")
            except (VaultSeedError, ValueError):
                continue
        made = _req(self.base + "/api/folders", headers=self.auth,
                    data={"name": self._e(folder)}, method="POST")
        return made.get("Id") or made.get("id")

    def _e(self, s):
        """Encrypt a str to an EncString with the session keys (helper used by
        the body builder + the field decryptors below)."""
        return _enc(s.encode(), self.ek, self.mk)

    def _d(self, enc):
        """Decrypt an EncString to str; "" for a missing/None field. Raises
        VaultSeedError only on a genuinely malformed/MAC-failing value."""
        if not enc:
            return ""
        return _dec(enc, self.ek, self.mk).decode()

    def upsert_login(self, name, username, password, notes=None, uri=None,
                     totp=None, rename_from=None) -> str:
        """Create or update a login item named `name`. Returns 'created'|'updated'.

        `totp` is written into the login object's "totp" field, encrypted like
        username/password. None/"" omits it, so the body is byte-identical to
        before for callers that don't pass it.

        `rename_from` (new trailing kwarg) supports renaming an existing login:
        when given AND different from `name`, the cipher is resolved by
        `rename_from` (its current name) rather than by `name`, and the body —
        which carries the new encrypted name — is PUT to that id, so the rename
        happens in place instead of creating a duplicate orphan. Before doing so
        it guards against a collision: if a DIFFERENT live login already uses
        `name`, it raises VaultSeedError rather than overwriting that third
        login. When rename_from is None/"" or equal to `name`, behaviour is
        byte-identical to before (resolve + upsert by `name`)."""
        body = self._for_user(_login_body(self._e, name, username, password,
                                          notes=notes, uri=uri, totp=totp))
        if rename_from and rename_from != name:
            # Renaming: fail CLOSED if the new name already belongs to a
            # different login, so we never overwrite an unrelated cipher.
            clash = self._find_login(name)
            src = self._find_login(rename_from)
            if clash and clash != src:
                raise VaultSeedError(
                    f"a login named '{name}' already exists")
            if src:
                _req(self.base + f"/api/ciphers/{src}", headers=self.auth,
                     data=body, method="PUT")
                return "updated"
            # Original is gone (e.g. deleted out from under the editor): fall
            # through and create the renamed login fresh.
            _req(self.base + "/api/ciphers", headers=self.auth,
                 data=body, method="POST")
            return "created"
        cid = self._find_login(name)
        if cid:
            _req(self.base + f"/api/ciphers/{cid}", headers=self.auth,
                 data=body, method="PUT")
            return "updated"
        _req(self.base + "/api/ciphers", headers=self.auth, data=body, method="POST")
        return "created"

    def upsert_secure_note(self, name, notes, folder=None) -> str:
        """Create or update a secure note (type 2), for items whose payload lives
        entirely in the Notes field, e.g. TOTP secrets. `folder` is a folder NAME,
        created if needed. Returns 'created'|'updated'."""
        folder_id = self._folder_id(folder) if folder else None
        body = self._for_user(_note_body(self._e, name, notes, folder_id=folder_id))
        cid = self._find(name)
        if cid:
            _req(self.base + f"/api/ciphers/{cid}", headers=self.auth,
                 data=body, method="PUT")
            return "updated"
        _req(self.base + "/api/ciphers", headers=self.auth, data=body, method="POST")
        return "created"

    def list_logins(self) -> list:
        """One dict per LOGIN cipher (type 1). Password is NEVER returned here.
        Ciphers that fail to decrypt are skipped rather than aborting the list."""
        out = []
        for c in self._ciphers():
            if (c.get("Type") or c.get("type")) != 1:
                continue
            login = c.get("Login") or c.get("login") or {}
            try:
                name = self._d(c.get("Name") or c.get("name"))
                username = self._d(login.get("Username") or login.get("username"))
                uris = login.get("Uris") or login.get("uris") or []
                uri = ""
                if uris:
                    first = uris[0] or {}
                    uri = self._d(first.get("Uri") or first.get("uri"))
                totp = login.get("Totp") or login.get("totp")
            except VaultSeedError:
                continue
            out.append({
                "name": name,
                "username": username,
                "has_totp": bool(totp),
                "uri": uri,
            })
        return out

    def get_login(self, name: str):
        """Full decrypted record for `name` (for the editor), or None if no
        login cipher matches. Includes the password + totp (decrypted)."""
        for c in self._ciphers():
            if (c.get("Type") or c.get("type")) != 1:
                continue
            enc_name = c.get("Name") or c.get("name")
            try:
                if not enc_name or self._d(enc_name) != name:
                    continue
                login = c.get("Login") or c.get("login") or {}
                uris = login.get("Uris") or login.get("uris") or []
                uri = ""
                if uris:
                    first = uris[0] or {}
                    uri = self._d(first.get("Uri") or first.get("uri"))
                return {
                    "name": name,
                    "username": self._d(login.get("Username") or login.get("username")),
                    "password": self._d(login.get("Password") or login.get("password")),
                    "totp": self._d(login.get("Totp") or login.get("totp")),
                    "uri": uri,
                    "notes": self._d(c.get("Notes") or c.get("notes")),
                }
            except VaultSeedError:
                continue
        return None

    def delete_login(self, name: str) -> bool:
        """Delete the login cipher named `name`. True if one was deleted,
        False if no match was found."""
        cid = self._find_login(name)
        if not cid:
            return False
        _req(self.base + f"/api/ciphers/{cid}", headers=self.auth, method="DELETE")
        return True

    def delete_item(self, name) -> bool:
        """Delete the secure note named `name`. True if one was deleted, False if
        no match was found. Raises on transport / auth errors, so a 5xx surfaces
        as a GUI 'delete failed' rather than as 'nothing to delete'."""
        cid = self._find(name)
        if not cid:
            return False
        _req(self.base + f"/api/ciphers/{cid}", headers=self.auth, method="DELETE")
        return True


def _login_body(enc, name, username, password, notes=None, uri=None, totp=None):
    """Pure assembler for a Vaultwarden login cipher body. `enc` is a callable
    str->EncString. Kept module-level + pure so it is unit-testable without a
    server: with totp omitted the body is byte-identical to the historical one
    (no "totp" key in the login object)."""
    login = {
        "username": enc(username) if username else None,
        "password": enc(password) if password else None,
        "uris": [{"uri": enc(uri), "match": None}] if uri else None,
    }
    if totp:
        login["totp"] = enc(totp)
    return {
        "type": 1,
        "name": enc(name),
        "favorite": False,
        "notes": enc(notes) if notes else None,
        "login": login,
    }


def _note_body(enc, name, notes, folder_id=None):
    """Pure assembler for a Vaultwarden secure-note cipher body; `enc` is a
    callable str->EncString, as for _login_body."""
    body = {
        "type": 2,
        "name": enc(name),
        "favorite": False,
        "notes": enc(notes) if notes else None,
        "secureNote": {"type": 0},
    }
    if folder_id:
        body["folderId"] = folder_id
    return body


def upsert_login(url, email, master_password, name, username, password,
                 notes=None, uri=None, totp=None, rename_from=None) -> str:
    """One-shot: log in and create/update a Vaultwarden login. Returns the action.

    `rename_from` threads through to Session.upsert_login to rename an existing
    login in place (with a new-name collision guard) instead of orphaning it."""
    return Session(url, email, master_password).upsert_login(
        name, username, password, notes=notes, uri=uri, totp=totp,
        rename_from=rename_from)


def list_logins(url, email, master_password) -> list:
    """One-shot: log in and list the login ciphers (no passwords)."""
    return Session(url, email, master_password).list_logins()


def get_login(url, email, master_password, name):
    """One-shot: log in and fetch the full record for `name` (or None)."""
    return Session(url, email, master_password).get_login(name)


def upsert_secure_note(url, email, master_password, name, notes,
                       folder=None) -> str:
    """One-shot: log in and create/update a secure note. Returns the action."""
    return Session(url, email, master_password).upsert_secure_note(
        name, notes, folder=folder)


def delete_login(url, email, master_password, name) -> bool:
    """One-shot: log in and delete the login named `name` or, failing that, the
    secure note of that name (where TOTP secrets live). True if deleted."""
    session = Session(url, email, master_password)
    return session.delete_login(name) or session.delete_item(name)


def account_exists(url: str, email: str, master_password: str) -> bool:
    """True if `email` + `master_password` opens a session against the vault at
    `url`. False if the server rejects the login (no account OR wrong password, the
    API hides which). Anything else (vault unreachable, say) propagates, so the
    caller can tell 'no account' from 'cannot reach the vault'."""
    try:
        Session(url, email, master_password)
    except LoginRejectedError:
        return False
    return True


def register_account(url: str, email: str, master_password: str,
                     kdf_iterations: int = 600000) -> None:
    """Create a Vaultwarden account, raising VaultSeedError on any failure,
    including an account that already exists. The registration itself lives in
    host.vaultsetup (lazy import: it imports this module); needs signups enabled
    on the server."""
    from host import vaultsetup
    if vaultsetup.register_account(url, email, master_password,
                                   kdf_iterations=kdf_iterations) == "exists":
        raise VaultSeedError(
            f"an account for '{email}' already exists in this vault — use the "
            f"existing master password, or remove the account.")


def available() -> bool:
    """True if the crypto backend needed to write is importable."""
    try:
        _aes()
        return True
    except VaultSeedError:
        return False
