"""
litebw — a pure-Python, lightweight Vaultwarden client for the SOC wall.

A drop-in replacement for the heavy Rust `rbw` CLI (which OOMs / fills the 40GB
Pi when built). litebw needs NO Rust toolchain: it talks to Vaultwarden's REST
API with stdlib urllib + the `cryptography` package (already a project dep) and
reuses the crypto primitives proven in host/vaultseed.py.

It serves two roles:

  (a) an in-process backend (`LitebwBackend`) for the long-running kiosk host —
      it caches the decrypted vault in RAM, refreshes the bearer token on 401,
      and only re-unseals the host-bound master as a last resort; and
  (b) a drop-in `litebw` CLI (`def main`) for the few call-sites that shell out:
        litebw config set email|base_url|pinentry <val>
        litebw login | unlock | unlocked | sync
        litebw get <item>                  -> password only
        litebw get --field username <item> -> username only
        litebw get --field notes <item>    -> notes / secure-note body
        litebw code <item>                 -> current TOTP

Key differences from vaultseed (which this module imports, never edits):
  * Argon2id (kdf==1) support, in addition to PBKDF2 (kdf==0).
  * read path: list/decrypt every cipher field (name/username/password/notes/totp).
  * token lifecycle for a 24/7 wall: keep the refresh_token; on HTTP 401 refresh
    via grant_type=refresh_token (no master needed); re-unseal only if that fails.

The master password is NEVER read from a plaintext file: it comes from
host.secretstore (host-bound, sealed) and only falls back to $SOC_VAULT_PASSWORD
for dev — exactly the precedence in scripts/pinentry-vault.py.

Stdlib + `cryptography` only. No new pip deps, no Rust.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from host import mastersource, secretstore, vaultseed
from host.vaultseed import VaultSeedError, _b64, _dec, _hkdf_expand, _ub64


# --------------------------------------------------------------------------- #
# Config persistence (mirrors `rbw config set`)
# --------------------------------------------------------------------------- #
def _config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "litebw")


def _config_path() -> str:
    return os.path.join(_config_dir(), "config.json")


def load_config() -> dict:
    try:
        with open(_config_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(cfg: dict) -> None:
    d = _config_dir()
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    path = _config_path()
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(cfg, indent=2).encode())
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# CLI key -> config.json key. `rbw` uses email / base_url / pinentry.
_CONFIG_KEYS = {"email": "email", "base_url": "base_url", "pinentry": "pinentry"}


def resolve_email() -> str:
    return os.environ.get("SOC_VAULT_EMAIL") or load_config().get("email", "")


def resolve_url() -> str:
    return os.environ.get("SOC_VAULT_URL") or load_config().get("base_url", "")


# --------------------------------------------------------------------------- #
# Master password acquisition (host-bound; never a plaintext file)
# --------------------------------------------------------------------------- #
def get_master() -> str:
    """Obtain the vault master password via the pluggable, universal source layer
    (host.mastersource): SOC_MASTER_SOURCE = auto|sealed|secret-service|env. The
    default 'auto' tries the host-bound seal first, then the freedesktop Secret
    Service (KWallet/GNOME-keyring/KeePassXC via secret-tool), then the dev-only
    $SOC_VAULT_PASSWORD. Never reads a plaintext master from disk.

    mastersource shares this module's `host.secretstore` object (Python caches
    modules), so monkeypatching litebw.secretstore in tests still steers it."""
    return mastersource.get_master()


# --------------------------------------------------------------------------- #
# KDF: derive the master key (PBKDF2 or Argon2id)
# --------------------------------------------------------------------------- #
def _argon2id_available() -> bool:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # noqa: F401
        return True
    except ImportError:
        return False


def derive_master_key(password: str, email: str, kdf: int, iterations: int,
                      memory: int = 0, parallelism: int = 0) -> bytes:
    """Master key from the password, per the vault's KDF.

    kdf==0  PBKDF2-HMAC-SHA256  (identical to vaultseed): salt = email.lower().
    kdf==1  Argon2id            : salt = sha256(email.lower()); iterations = time
            cost; memory = MiB (Bitwarden) -> memory_cost in KiB (=*1024);
            parallelism = lanes.
    """
    email_l = email.lower()
    pw = password.encode()
    if kdf == 0:
        # Clamp server-supplied iteration count: the prelogin response is
        # UNAUTHENTICATED network input, and a hostile/MITM'd Vaultwarden can
        # declare kdfIterations in the billions to pin the CPU for minutes and
        # wedge every unlock()/boot. The 10M ceiling keeps the floor (>=1) and
        # changes nothing for any real vault (Bitwarden default 600k); the KDF
        # math itself is untouched.
        iters = min(max(1, iterations), 10_000_000)
        return hashlib.pbkdf2_hmac("sha256", pw, email_l.encode(), iters, 32)
    if kdf == 1:
        if not _argon2id_available():
            raise VaultSeedError(
                "this vault uses the Argon2id KDF but this Python's "
                "'cryptography' is too old to provide Argon2id. Upgrade "
                "cryptography (pip install -U cryptography), or switch the "
                "Vaultwarden account to the PBKDF2 KDF.")
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        salt = hashlib.sha256(email_l.encode()).digest()
        # Clamp the server-supplied Argon2id parameters. memory is in MiB and
        # becomes memory_cost = memory*1024 KiB fed to .derive(): an unbounded
        # kdfMemory (e.g. 8_000_000) makes cryptography attempt a multi-TB
        # allocation -> instant OOM-kill of the 1GB kiosk at boot. The ceilings
        # (1024 MiB ~= 1GB-equivalent work, 10M iters, 16 lanes) mirror sane
        # Bitwarden limits and leave the MiB->KiB *1024 mapping and every value
        # <= the ceiling (all KATs + real vaults) byte-for-byte identical.
        return Argon2id(
            salt=salt,
            length=32,
            iterations=min(max(1, iterations), 10_000_000),
            lanes=min(max(1, parallelism or 1), 16),
            memory_cost=min(max(8, memory), 1024) * 1024,   # MiB -> KiB, <=1 GiB
        ).derive(pw)
    raise VaultSeedError(f"unsupported KDF type {kdf} (only PBKDF2 and Argon2id)")


def master_password_hash(master_key: bytes, password: str) -> str:
    """The auth hash sent to /connect/token — KDF-agnostic (vaultseed line 118)."""
    return _b64(hashlib.pbkdf2_hmac("sha256", master_key, password.encode(), 1, 32))


# --------------------------------------------------------------------------- #
# EncString decrypt dispatcher (types 0/1/2)
# --------------------------------------------------------------------------- #
def decrypt_field(value, ek: bytes, mk: bytes) -> str:
    """Decrypt an EncString cipher field to a UTF-8 string.

    A missing/empty field decrypts to ''. Type 2 (AesCbc256_HmacSha256_B64) is
    the common, MAC-verified path and reuses vaultseed._dec (so a tampered or
    wrong-key field RAISES, never returns garbage). Type 0 (AesCbc256_B64) has
    no MAC by design. Type 1 shares type 2's structure.
    """
    if not value:
        return ""
    head = value.split(".", 1)
    if len(head) != 2:
        # No type prefix — not an EncString we can decrypt; return as-is.
        return value
    try:
        etype = int(head[0])
    except ValueError:
        return value

    if etype in (1, 2):
        # MAC-verified via vaultseed._dec (iv|ct|mac, HMAC over iv+ct).
        # The plaintext is authenticated but need not be valid UTF-8 (another
        # client may have stored a binary secret). Decode tolerantly so a
        # non-text-but-MAC-valid field never raises UnicodeDecodeError and
        # aborts the whole sync — per-item skipping handles real failures.
        return _dec(value, ek, mk).decode("utf-8", "replace")
    if etype == 0:
        # AesCbc256_B64: iv|ct, NO MAC. Without an integrity gate, malformed
        # base64 / non-block-aligned ct / empty ct are attacker- or
        # corruption-reachable, so every failure here must surface as a
        # VaultSeedError (caught per-item by list_ciphers), never a raw
        # binascii.Error / ValueError / IndexError that kills the sync.
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)
        parts = head[1].split("|")
        if len(parts) < 2:
            raise VaultSeedError("malformed type-0 EncString")
        try:
            iv, ct = _ub64(parts[0]), _ub64(parts[1])
            dec = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
            pt = dec.update(ct) + dec.finalize()
        except (ValueError, TypeError) as e:  # binascii.Error is a ValueError
            raise VaultSeedError(f"bad type-0 EncString: {e}")
        if not pt or pt[-1] < 1 or pt[-1] > 16:
            raise VaultSeedError("bad PKCS7 padding in type-0 EncString")
        return pt[:-pt[-1]].decode("utf-8", "replace")
    raise VaultSeedError(f"unsupported EncString type {etype}")


# --------------------------------------------------------------------------- #
# TOTP (RFC 6238 / RFC 4226), stdlib only
# --------------------------------------------------------------------------- #
_STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"
_HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def _b32decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad)


def _hotp_truncate(digest: bytes) -> int:
    offset = digest[-1] & 0x0F
    return int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF


def generate_totp(totp_secret: str, at: float | None = None) -> str:
    """Compute the current code from a cipher's login.totp value.

    Accepts a bare Base32 secret, an otpauth:// URI, or a Steam secret
    (steam:// prefix or otpauth ...&algorithm=steam / type 'steam'). Defaults:
    digits=6, period=30, algorithm=SHA1. Raises ValueError on an unparseable
    secret so callers can map that to a non-zero exit with empty stdout.
    """
    if not totp_secret:
        raise ValueError("empty TOTP secret")
    raw = totp_secret.strip()
    digits = 6
    period = 30
    algo = "SHA1"
    steam = False
    secret = raw

    low = raw.lower()
    if low.startswith("steam://"):
        steam = True
        secret = raw[len("steam://"):]
    elif low.startswith("otpauth://"):
        parsed = urllib.parse.urlparse(raw)
        if parsed.netloc.lower() == "steam":
            steam = True
        q = urllib.parse.parse_qs(parsed.query)
        secret = (q.get("secret", [""])[0]) or ""
        if not secret:
            raise ValueError("otpauth URI has no secret")
        # digits/period are attacker-controlled (the otpauth URI comes from a
        # vault item that a compromised/MITM'd server or shared org item can
        # set). Guard + range-clamp BEFORE the dangerous 10**digits / // period
        # math below: a huge digits builds a 100M-digit int (hard DoS on the
        # 1GB board), period=0 is a ZeroDivisionError, and non-numeric raises.
        # The bounds cover every legitimate code (digits 6-8, period 15-60), so
        # no real secret is affected and no wire/crypto behaviour changes.
        if q.get("digits"):
            try:
                digits = int(q["digits"][0])
            except ValueError:
                raise ValueError("TOTP digits is not an integer")
            if not (1 <= digits <= 10):
                raise ValueError("TOTP digits out of range")
        if q.get("period"):
            try:
                period = int(q["period"][0])
            except ValueError:
                raise ValueError("TOTP period is not an integer")
            if period < 1:
                raise ValueError("TOTP period out of range")
        if q.get("algorithm"):
            alg = q["algorithm"][0].upper()
            if alg == "STEAM":
                steam = True
            elif alg in _HASHES:
                algo = alg

    key = _b32decode(secret)
    counter = int((at if at is not None else time.time()) // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, _HASHES[algo]).digest()
    binary = _hotp_truncate(digest)

    if steam:
        out = []
        for _ in range(5):
            out.append(_STEAM_ALPHABET[binary % len(_STEAM_ALPHABET)])
            binary //= len(_STEAM_ALPHABET)
        return "".join(out)
    return str(binary % (10 ** digits)).zfill(digits)


# --------------------------------------------------------------------------- #
# Read-capable session
# --------------------------------------------------------------------------- #
class ReadSession:
    """An authenticated Vaultwarden session that can READ + decrypt every cipher.

    Performs the same login flow as vaultseed.Session (prelogin -> KDF master key
    -> /connect/token password grant -> decrypt tok['Key'] -> ek/mk) but also
    supports Argon2id and keeps the refresh_token + access-token expiry so a
    24/7 process can refresh the bearer on 401 without the master password.
    """

    DEVICE_ID = "soc-litebw-0001"
    DEVICE_NAME = "soc-litebw"

    def __init__(self, url: str, email: str, master_password: str):
        if not url:
            raise VaultSeedError("no Vaultwarden URL (set SOC_VAULT_URL or "
                                 "`litebw config set base_url ...`)")
        if not email:
            raise VaultSeedError("no vault email (set SOC_VAULT_EMAIL or "
                                 "`litebw config set email ...`)")
        self.base = url.rstrip("/")
        self.email = email.lower()
        self._master = master_password
        self.ek = self.mk = b""
        self.access_token = ""
        self.refresh_token = ""
        self.token_expiry = 0.0
        self._login()

    # -- HTTP with 401-aware error branching -------------------------------- #
    def _req(self, path, headers=None, data=None, method="GET", form=False):
        """Like vaultseed._req but raises a 401-distinguishable error so sync()
        can branch on token expiry (vaultseed._req flattens the status code)."""
        url = self.base + path
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
                buf = r.read(vaultseed.MAX_RESPONSE_BYTES + 1)
                if len(buf) > vaultseed.MAX_RESPONSE_BYTES:
                    raise VaultSeedError(
                        f"{method} {url}: vault response exceeds "
                        f"{vaultseed.MAX_RESPONSE_BYTES} bytes")
                raw = buf.decode()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:200]
            raise _HTTPStatusError(e.code, f"{method} {url} -> HTTP {e.code}: "
                                   f"{detail}")
        except OSError as e:
            raise VaultSeedError(f"could not reach Vaultwarden at {url}: {e}")

    # -- login / token ------------------------------------------------------ #
    def _login(self):
        pre = self._req("/identity/accounts/prelogin",
                        data={"email": self.email}, method="POST")
        kdf = int(pre.get("kdf", pre.get("Kdf", 0)) or 0)
        iters = int(pre.get("kdfIterations",
                            pre.get("KdfIterations", 600000)) or 600000)
        mem = int(pre.get("kdfMemory", pre.get("KdfMemory", 0)) or 0)
        par = int(pre.get("kdfParallelism", pre.get("KdfParallelism", 0)) or 0)

        master_key = derive_master_key(self._master, self.email, kdf, iters,
                                       mem, par)
        master_hash = master_password_hash(master_key, self._master)
        senc = _hkdf_expand(master_key, b"enc")
        smac = _hkdf_expand(master_key, b"mac")

        tok = self._req("/identity/connect/token", data={
            "grant_type": "password", "username": self.email,
            "password": master_hash, "scope": "api offline_access",
            "client_id": "cli", "deviceType": "8",
            "deviceIdentifier": self.DEVICE_ID, "deviceName": self.DEVICE_NAME,
        }, method="POST", form=True)
        if "Key" not in tok or "access_token" not in tok:
            raise VaultSeedError("login failed — check the email/master password")
        self._apply_token(tok)
        sym = _dec(tok["Key"], senc, smac)              # 64-byte account key
        self.ek, self.mk = sym[:32], sym[32:]

    def _apply_token(self, tok: dict):
        self.access_token = tok["access_token"]
        if tok.get("refresh_token"):
            self.refresh_token = tok["refresh_token"]
        # Refresh a minute early to avoid races at the boundary.
        self.token_expiry = time.time() + max(0, int(tok.get("expires_in", 0)) - 60)

    def refresh(self) -> bool:
        """Refresh the bearer using the refresh_token (no master). False if we
        have no refresh_token or the server rejects it (caller re-unlocks)."""
        if not self.refresh_token:
            return False
        try:
            tok = self._req("/identity/connect/token", data={
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token, "client_id": "cli",
            }, method="POST", form=True)
        except (_HTTPStatusError, VaultSeedError):
            return False
        if "access_token" not in tok:
            return False
        self._apply_token(tok)
        return True

    @property
    def auth(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}

    # -- ciphers ------------------------------------------------------------ #
    def _raw_ciphers(self):
        def fetch():
            r = self._req("/api/ciphers", headers=self.auth)
            return r.get("Data", r.get("data", []))
        try:
            return fetch()
        except _HTTPStatusError as e:
            if e.code == 401 and self.refresh():
                return fetch()
            raise

    @staticmethod
    def _ci(cipher: dict, *names):
        for n in names:
            if n in cipher and cipher[n] is not None:
                return cipher[n]
        return None

    def _decrypt_cipher(self, c: dict) -> dict:
        name = self._ci(c, "Name", "name")
        login = self._ci(c, "Login", "login") or {}
        notes = self._ci(c, "Notes", "notes")
        user = self._ci(login, "Username", "username")
        pw = self._ci(login, "Password", "password")
        totp = self._ci(login, "Totp", "totp")
        return {
            "id": self._ci(c, "Id", "id"),
            "name": decrypt_field(name, self.ek, self.mk),
            "username": decrypt_field(user, self.ek, self.mk),
            "password": decrypt_field(pw, self.ek, self.mk),
            "notes": decrypt_field(notes, self.ek, self.mk),
            "totp": decrypt_field(totp, self.ek, self.mk),
        }

    def list_ciphers(self) -> list:
        out = []
        for c in self._raw_ciphers():
            try:
                out.append(self._decrypt_cipher(c))
            except (VaultSeedError, ValueError, IndexError):
                # A single undecryptable item (e.g. org key we lack, a malformed
                # type-0 EncString, or non-UTF-8 plaintext) is skipped, not
                # fatal — the wall's items are personal-vault logins. ValueError
                # (covers binascii.Error / UnicodeDecodeError) and IndexError
                # are belt-and-braces so one bad cipher never kills the sync.
                continue
        return out

    def get_cipher(self, name: str) -> dict | None:
        for item in self.list_ciphers():
            if item["name"] == name:
                return item
        return None


class _HTTPStatusError(VaultSeedError):
    """A VaultSeedError that also carries the HTTP status code, so sync() can
    branch on 401 without parsing a flattened error string."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class VaultLockedError(VaultSeedError):
    """Raised in interactive mode when a session is needed but no master is
    available yet — a catchable signal that the host should pop the themed
    'Unlock Vaultwarden' dialog and feed the master back via unlock_with(),
    NOT a hard misconfig. Distinct class so the host can tell 'prompt the
    operator' apart from 'server unreachable / wrong URL'."""


# --------------------------------------------------------------------------- #
# In-process backend (mirrors vault.RbwBackend's interface)
# --------------------------------------------------------------------------- #
class LitebwBackend:
    """Drop-in for vault.RbwBackend, but talks to Vaultwarden directly and caches
    the decrypted vault in RAM. Selected via SOC_VAULT_BACKEND in a separate
    wiring workflow (vault._make_backend gains the branch there)."""

    def __init__(self):
        self.email = os.environ.get("SOC_VAULT_EMAIL", "") or load_config().get("email", "")
        self.url = os.environ.get("SOC_VAULT_URL", "") or load_config().get("base_url", "")
        self.pinentry = os.environ.get("SOC_PINENTRY", "") or load_config().get("pinentry", "")
        self.interactive = os.environ.get("SOC_VAULT_INTERACTIVE", "0") == "1"
        self._session: ReadSession | None = None
        self._ciphers: dict[str, dict] | None = None

    # -- VaultError import is lazy so this module loads before host.vault ---- #
    @staticmethod
    def _vault_error(msg: str) -> Exception:
        try:
            from host.vault import VaultError
            return VaultError(msg)
        except ImportError:
            return VaultSeedError(msg)

    def configure(self):
        """Persist email/base_url/pinentry to config.json so the CLI path and
        the host path agree. Idempotent; never hard-fails on a benign re-set."""
        cfg = load_config()
        changed = False
        for key, val in (("email", self.email), ("base_url", self.url),
                         ("pinentry", self.pinentry)):
            if val and cfg.get(key) != val:
                cfg[key] = val
                changed = True
        if changed:
            try:
                save_config(cfg)
            except OSError:
                pass

    def unlock(self):
        self.configure()
        master = get_master()
        if not master:
            # Interactive: defer to the host's themed Unlock dialog, which feeds
            # the master back via unlock_with(). _ensure_session signals this
            # with VaultLockedError rather than masquerading as "unlocked".
            if self.interactive:
                return
            raise self._vault_error(
                "no vault master password (host not sealed and no "
                "$SOC_VAULT_PASSWORD)")
        try:
            self._session = ReadSession(self.url, self.email, master)
        except VaultSeedError as e:
            # A sealed/env master that fails to log in is a real auth/connect
            # error even in interactive mode — propagate it as-is so the host
            # tells the operator *which* (wrong password vs. unreachable),
            # instead of silently looping on a dead session.
            raise self._vault_error(str(e))

    def unlock_with(self, master: str):
        """Open the session with an operator-supplied master (from the host's
        Unlock dialog). Kept in RAM only — never written to a file, preserving
        the no-plaintext-master guarantee. Raises on bad password / unreachable
        server so the dialog can report the failure and re-prompt."""
        if not master:
            raise self._vault_error("empty master password")
        try:
            self._session = ReadSession(self.url, self.email, master)
        except VaultSeedError as e:
            self._session = None
            raise self._vault_error(str(e))

    def _ensure_session(self) -> ReadSession:
        if self._session is None:
            self.unlock()
        if self._session is None:
            # Interactive + no master yet: a catchable "please unlock" signal,
            # not a dead end. Non-interactive: the generic locked fatal.
            if self.interactive:
                raise VaultLockedError(
                    "vault is locked — Vaultwarden master needed")
            raise self._vault_error("vault is locked")
        return self._session

    def sync(self):
        """Fetch + decrypt all ciphers into the RAM cache. Refreshes the bearer
        on 401; re-unlocks (re-unseals the master) only if refresh also fails."""
        try:
            session = self._ensure_session()
            items = session.list_ciphers()
        except VaultLockedError:
            # Interactive "please unlock" signal — propagate AS-IS (never wrap it
            # into a generic VaultError) so the host can tell it apart from a real
            # misconfig and pop the themed Unlock dialog. Caught before the broad
            # VaultSeedError branch below because it IS a VaultSeedError subclass.
            raise
        except _HTTPStatusError as e:
            if e.code != 401:
                raise self._vault_error(str(e))
            # refresh already attempted inside list_ciphers; full re-unlock now.
            # The retry can still fail (server still 401, refresh_token expired,
            # or a cipher decrypt error) — funnel every backend exception
            # through _vault_error so worker threads (Vault.prewarm) only ever
            # see host.vault.VaultError. _HTTPStatusError is a VaultSeedError
            # subclass, so the single except covers both.
            self._session = None
            try:
                session = self._ensure_session()
                items = session.list_ciphers()
            except VaultLockedError:
                raise
            except VaultSeedError as e2:
                raise self._vault_error(str(e2))
        except VaultSeedError as e:
            raise self._vault_error(str(e))
        self._ciphers = {it["name"]: it for it in items}

    def _lookup(self, item: str) -> dict | None:
        if self._ciphers is None:
            self.sync()
        return (self._ciphers or {}).get(item)

    def get(self, item: str):
        rec = self._lookup(item)
        if not rec or not rec.get("password"):
            raise self._vault_error(
                f"vault item '{item}' has no password (or not found)")
        return rec.get("username", ""), rec["password"]

    def notes(self, item: str) -> str:
        rec = self._lookup(item)
        return (rec or {}).get("notes", "") if rec else ""

    def code(self, item: str) -> str:
        rec = self._lookup(item)
        if not rec or not rec.get("totp"):
            raise self._vault_error(f"vault item '{item}' has no TOTP secret")
        return generate_totp(rec["totp"])


# --------------------------------------------------------------------------- #
# CLI (rbw-compatible subcommands)
# --------------------------------------------------------------------------- #
_USAGE = """\
litebw — lightweight Vaultwarden client (rbw-compatible subset)

usage:
  litebw config set <email|base_url|pinentry> <value>
  litebw login
  litebw unlock | unlocked
  litebw sync
  litebw get [--field username|password|notes] <item>
  litebw code <item>
"""


def _open_session() -> ReadSession:
    return ReadSession(resolve_url(), resolve_email(), get_master())


def _cmd_config(argv) -> int:
    if len(argv) < 1 or argv[0] != "set":
        sys.stderr.write("litebw config: only 'set' is supported\n")
        return 2
    rest = argv[1:]
    if len(rest) < 2:
        sys.stderr.write("litebw config set <key> <value>\n")
        return 2
    key, value = rest[0], rest[1]
    if key not in _CONFIG_KEYS:
        sys.stderr.write(f"litebw config set: unknown key '{key}' "
                         f"(email|base_url|pinentry)\n")
        return 2
    cfg = load_config()
    cfg[_CONFIG_KEYS[key]] = value
    try:
        save_config(cfg)
    except OSError as e:
        sys.stderr.write(f"litebw config set: {e}\n")
        return 2
    return 0


def _cmd_login() -> int:
    try:
        _open_session()   # prelogin + token grant proves creds + reachability
    except VaultSeedError as e:
        sys.stderr.write(f"litebw login: {e}\n")
        return 1
    return 0


def _cmd_sync() -> int:
    try:
        _open_session().list_ciphers()
    except VaultSeedError as e:
        sys.stderr.write(f"litebw sync: {e}\n")
        return 1
    return 0


def _cmd_get(argv) -> int:
    field = "password"
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--field":
            if i + 1 >= len(argv):
                sys.stderr.write("litebw get: --field needs a value\n")
                return 2
            field = argv[i + 1]
            i += 2
            continue
        if a.startswith("--field="):
            field = a.split("=", 1)[1]
            i += 1
            continue
        rest.append(a)
        i += 1
    if not rest:
        sys.stderr.write("litebw get: missing <item>\n")
        return 2
    item = rest[0]
    if field not in ("password", "username", "notes"):
        sys.stderr.write(f"litebw get: unknown --field '{field}'\n")
        return 2

    try:
        rec = _open_session().get_cipher(item)
    except VaultSeedError as e:
        sys.stderr.write(f"litebw get: {e}\n")
        return 1
    if rec is None:
        sys.stderr.write(f"litebw get: item '{item}' not found\n")
        return 1

    if field == "password":
        pw = rec.get("password", "")
        if not pw:
            sys.stderr.write(f"litebw get: item '{item}' has no password\n")
            return 1
        sys.stdout.write(pw + "\n")
        return 0
    # username / notes: item found -> exit 0 even when the value is empty
    # (RbwBackend calls these check=False and tolerates empty stdout).
    val = rec.get(field, "")
    if val:
        sys.stdout.write(val + "\n")
    return 0


def _cmd_code(argv) -> int:
    if not argv:
        sys.stderr.write("litebw code: missing <item>\n")
        return 2
    item = argv[0]
    try:
        rec = _open_session().get_cipher(item)
    except VaultSeedError as e:
        sys.stderr.write(f"litebw code: {e}\n")
        return 1
    if rec is None or not rec.get("totp"):
        sys.stderr.write(f"litebw code: item '{item}' has no TOTP secret\n")
        return 1
    try:
        sys.stdout.write(generate_totp(rec["totp"]) + "\n")
    except Exception as e:  # malformed secret -> non-zero exit, no stdout
        sys.stderr.write(f"litebw code: {e}\n")
        return 1
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(_USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]

    if cmd == "config":
        return _cmd_config(rest)
    if cmd == "login":
        return _cmd_login()
    if cmd == "unlock":
        # CLI no-op-success: the long-running host uses LitebwBackend.unlock().
        # Tolerate repeated calls; never crash.
        return 0
    if cmd == "unlocked":
        return 0     # no agent concept in litebw — always "unlocked"
    if cmd == "sync":
        return _cmd_sync()
    if cmd == "get":
        return _cmd_get(rest)
    if cmd == "code":
        return _cmd_code(rest)

    sys.stderr.write(f"litebw: unknown command '{cmd}'\n{_USAGE}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
