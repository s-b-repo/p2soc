"""
Domain login memory — remembers which Vaultwarden item auto-logged-in a domain,
so the same domain auto-logs-in again even on a different / re-pointed panel.

Stored in $SOC_STATE_DIR/domain_logins.json (0600): { "host.example.com": "Vault Item" }.
This holds only the *name* of the vault login, never a credential.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from urllib.parse import urlsplit

# remember() is called from the GTK thread (WebKit panels) AND each Chromium
# panel's control thread, so serialise the read-modify-write.
_lock = threading.Lock()


def _state_dir() -> str:
    d = os.environ.get("SOC_STATE_DIR") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
        "soc-wall")
    os.makedirs(d, exist_ok=True)
    return d


def _path() -> str:
    return os.path.join(_state_dir(), "domain_logins.json")


def domain_of(url: str) -> str:
    """The origin authority host:port (default ports normalised). Keyed per
    origin — not bare hostname — so different apps on the same host (different
    ports) never share a remembered login."""
    try:
        u = urlsplit(url or "")
        host = (u.hostname or "").lower()
        if not host:
            return ""
        port = u.port or (443 if u.scheme == "https" else 80)
        return f"{host}:{port}"
    except ValueError:
        return ""


def load() -> dict:
    try:
        with open(_path(), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def vault_item_for(url: str) -> str:
    return load().get(domain_of(url), "")


def remember(url: str, vault_item: str):
    dom = domain_of(url)
    if not dom or not vault_item:
        return
    with _lock:
        d = load()
        if d.get(dom) == vault_item:
            return
        d[dom] = vault_item
        path = _path()
        # unique temp in the same dir (atomic replace; no shared-tmp clobber)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".dl-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
