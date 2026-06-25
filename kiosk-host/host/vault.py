"""
Credential access for the SOC kiosk host.

Backends, selected by $SOC_VAULT_BACKEND:

  litebw (default, production)  Pure-Python, rbw-compatible Vaultwarden client
                             (host/litebw.py) — no Rust toolchain, so it runs on
                             the 1 GB Raspberry Pi without compiling rbw. Unattended
                             unlock UNSEALS the host-bound master — no plaintext
                             master password on disk. ('native' is an alias.)
  rbw  (legacy/optional)     Reads logins from Vaultwarden via the `rbw` CLI.
                             Same unattended-unlock model via a pinentry wrapper
                             that unseals the host-bound master
                             (scripts/pinentry-vault.py). Still selectable if rbw
                             is installed; no longer the default.
  dev  (local testing)       Reads logins from a JSON file ($SOC_DEV_VAULT),
                             so the kiosk host runs end-to-end on x86 without
                             Vaultwarden installed.

Credentials are held only in a short-TTL in-RAM cache and never written to disk
by this process.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from typing import Dict, Tuple


class VaultError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class RbwBackend:
    def __init__(self):
        self.email = os.environ.get("SOC_VAULT_EMAIL", "")
        self.url = os.environ.get("SOC_VAULT_URL", "")
        self.pinentry = os.environ.get("SOC_PINENTRY", "")
        self.interactive = os.environ.get("SOC_VAULT_INTERACTIVE", "0") == "1"

    def _rbw(self, *args, check=True, env=None) -> str:
        e = dict(os.environ)
        if env:
            e.update(env)
        try:
            r = subprocess.run(["rbw", *args], capture_output=True, text=True,
                               env=e, timeout=30)
        except FileNotFoundError:
            raise VaultError("rbw not found on PATH (install it or use SOC_VAULT_BACKEND=dev)")
        except subprocess.TimeoutExpired:
            raise VaultError(f"rbw {' '.join(args)} timed out")
        if check and r.returncode != 0:
            raise VaultError(f"rbw {' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
        return r.stdout.strip()

    def configure(self):
        """Idempotently point rbw at the right server / account / pinentry."""
        if self.email:
            self._rbw("config", "set", "email", self.email, check=False)
        if self.url:
            self._rbw("config", "set", "base_url", self.url, check=False)
        if self.pinentry:
            self._rbw("config", "set", "pinentry", self.pinentry, check=False)

    def unlock(self):
        self.configure()
        if self.interactive:
            # operator unlocks manually after boot; just make sure agent is up.
            self._rbw("unlocked", check=False)
            return
        # Non-interactive: pinentry wrapper supplies the master password.
        self._rbw("unlock")

    def sync(self):
        self._rbw("sync")

    def get(self, item: str) -> Tuple[str, str]:
        user = self._rbw("get", "--field", "username", item, check=False)
        password = self._rbw("get", item)
        if not password:
            raise VaultError(f"vault item '{item}' has no password (or not found)")
        return user, password

    def notes(self, item: str) -> str:
        """The item's Notes field (used to hold a VPN config — wg .conf / .ovpn —
        so its keys live in Vaultwarden instead of on disk). '' if empty."""
        out = self._rbw("get", "--field", "notes", item, check=False)
        if out:
            return out
        # secure-note items return the note as the main value
        return self._rbw("get", item, check=False)


class DevFileBackend:
    """JSON: { "Item Name": {"username": "...", "password": "..."}, ... }"""
    def __init__(self):
        self.path = os.environ.get("SOC_DEV_VAULT", "dev/run/dev-vault.json")
        self._data = None

    def _load(self):
        if self._data is None:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    self._data = json.load(fh)
            except FileNotFoundError:
                raise VaultError(f"dev vault file not found: {self.path}")
        return self._data

    def configure(self):
        pass

    def unlock(self):
        self._load()

    def sync(self):
        self._data = None
        self._load()

    def get(self, item: str) -> Tuple[str, str]:
        rec = self._load().get(item)
        if not rec:
            raise VaultError(f"dev vault has no item '{item}'")
        return rec.get("username", ""), rec["password"]

    def notes(self, item: str) -> str:
        rec = self._load().get(item) or {}
        return rec.get("notes", "")


def _make_backend():
    name = os.environ.get("SOC_VAULT_BACKEND", "litebw").lower()
    if name == "dev":
        return DevFileBackend()
    if name in ("litebw", "native"):
        from host.litebw import LitebwBackend
        return LitebwBackend()
    if name == "rbw":
        return RbwBackend()
    raise VaultError(f"unknown SOC_VAULT_BACKEND={name}")


# --------------------------------------------------------------------------- #
# Facade with TTL cache
# --------------------------------------------------------------------------- #
class Vault:
    def __init__(self, ttl: float = 30.0):
        self.backend = _make_backend()
        self.ttl = ttl
        self._cache: Dict[str, Tuple[float, Tuple[str, str]]] = {}
        # Last-good copy, populated only when stale-serve is enabled. Lets a
        # transient Vaultwarden/litebw outage fall back to the last creds that
        # actually worked instead of de-authenticating a live panel.
        self._lastgood: Dict[str, Tuple[float, Tuple[str, str]]] = {}
        try:
            self.stale_ttl = max(0.0, float(os.environ.get("SOC_CRED_STALE_TTL", "0")))
        except ValueError:
            self.stale_ttl = 0.0
        self._stale_logged: set = set()    # per-item log throttle
        self._lock = threading.Lock()      # creds()/prewarm run on worker threads
        self._ready = False

    def open(self):
        """Unlock + initial sync. Call once at startup."""
        self.backend.unlock()
        self.backend.sync()
        self._ready = True

    def ready(self) -> bool:
        return self._ready

    def _evict_expired_locked(self, now: float = None):
        """Drop expired entries so the cache can't grow unbounded over a 24/7 run
        and stale credentials don't linger in RAM past their TTL. Call under lock."""
        now = now if now is not None else time.time()
        for k in [k for k, (ts, _) in self._cache.items() if now - ts >= self.ttl]:
            self._cache.pop(k, None)

    def cached(self, item: str) -> bool:
        """True if a fresh credential is in the cache (no backend call needed)."""
        with self._lock:
            self._evict_expired_locked()
            hit = self._cache.get(item)
            return bool(hit and (time.time() - hit[0]) < self.ttl)

    def creds(self, item: str) -> dict:
        with self._lock:
            self._evict_expired_locked()
            hit = self._cache.get(item)
            if hit and (time.time() - hit[0]) < self.ttl:
                user, pw = hit[1]
                return {"user": user, "pass": pw}
        # fetch outside the lock — rbw is a subprocess; don't serialise all
        # callers (a duplicate fetch of the same item is harmless)
        try:
            user, pw = self.backend.get(item)
        except VaultError:
            # Backend unreachable: serve the last creds that worked, but only
            # when stale-serve is enabled and still within its window. With the
            # default (SOC_CRED_STALE_TTL=0) _lastgood is empty and we re-raise.
            if self.stale_ttl > 0:
                with self._lock:
                    lg = self._lastgood.get(item)
                    if lg and (time.time() - lg[0]) < self.stale_ttl:
                        if item not in self._stale_logged:
                            self._stale_logged.add(item)
                            try:
                                import sys
                                print(f"vault: serving last-good creds for '{item}' "
                                      f"(backend unreachable, within SOC_CRED_STALE_TTL)",
                                      file=sys.stderr)
                            except Exception:
                                pass
                        u, p = lg[1]
                        return {"user": u, "pass": p}
            raise
        now = time.time()
        with self._lock:
            self._cache[item] = (now, (user, pw))
            if self.stale_ttl > 0:
                self._lastgood[item] = (now, (user, pw))
                self._stale_logged.discard(item)   # reset throttle after a good fetch
        return {"user": user, "pass": pw}

    def prewarm(self, items, log=None) -> int:
        """Fetch creds for many items in parallel (off the GTK thread) so each
        panel's first login is served from cache instead of blocking the UI on
        an rbw call. Per-item failures are logged, not raised."""
        from concurrent.futures import ThreadPoolExecutor
        uniq = [i for i in dict.fromkeys(items) if i]
        if not uniq:
            return 0

        def one(it):
            try:
                self.creds(it)
                return True
            except VaultError as e:
                if log:
                    log(f"prewarm '{it}': {e}")
                return False
        with ThreadPoolExecutor(max_workers=min(4, len(uniq))) as ex:
            return sum(1 for r in ex.map(one, uniq) if r)

    def notes(self, item: str) -> str:
        """Fetch the item's Notes field (not cached — read once at connect)."""
        return self.backend.notes(item)

    def invalidate(self, item: str = None):
        with self._lock:
            if item:
                self._cache.pop(item, None)
                self._lastgood.pop(item, None)
                self._stale_logged.discard(item)
            else:
                self._cache.clear()
                self._lastgood.clear()
                self._stale_logged.clear()
