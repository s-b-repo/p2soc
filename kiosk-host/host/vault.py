"""
Credential access for the SOC kiosk host.

Two backends, selected by $SOC_VAULT_BACKEND:

  rbw  (default, production)  Reads logins from Vaultwarden via the `rbw` CLI.
                             Unattended unlock uses a pinentry wrapper that
                             UNSEALS the host-bound master (scripts/pinentry-vault.py)
                             — no plaintext master password on disk.
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
    name = os.environ.get("SOC_VAULT_BACKEND", "rbw").lower()
    if name == "dev":
        return DevFileBackend()
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
        self._lock = threading.Lock()      # creds()/prewarm run on worker threads
        self._ready = False

    def open(self):
        """Unlock + initial sync. Call once at startup."""
        self.backend.unlock()
        self.backend.sync()
        self._ready = True

    def ready(self) -> bool:
        return self._ready

    def cached(self, item: str) -> bool:
        """True if a fresh credential is in the cache (no backend call needed)."""
        with self._lock:
            hit = self._cache.get(item)
            return bool(hit and (time.time() - hit[0]) < self.ttl)

    def creds(self, item: str) -> dict:
        with self._lock:
            hit = self._cache.get(item)
            if hit and (time.time() - hit[0]) < self.ttl:
                user, pw = hit[1]
                return {"user": user, "pass": pw}
        # fetch outside the lock — rbw is a subprocess; don't serialise all
        # callers (a duplicate fetch of the same item is harmless)
        user, pw = self.backend.get(item)
        with self._lock:
            self._cache[item] = (time.time(), (user, pw))
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
            else:
                self._cache.clear()
