"""
Liveness heartbeat for the kiosk host.

WHY this exists: a process that is alive is not a wall that is working. A wedged
GTK main loop leaves the host running forever while the screen is frozen, and on
an unattended box nobody is there to notice. So the host calls `write()` from a
timer ON THE MAIN LOOP: if the loop hangs, the heartbeat stops, and that absence
is the signal.

Two independent readers depend on this file:

  * scripts/launcher.sh restarts a host whose heartbeat has gone stale;
  * scripts/soc-update.py decides whether a freshly-activated release is healthy,
    and rolls it back if not.

The file lives on tmpfs (/run/soc-wall), so the 15 s write cadence costs no SD
wear. Writes are atomic (temp file + rename), so a reader never sees a torn
document. Pure stdlib, no GTK, safe to import anywhere.

The document:

    {"ts": 1730000000.0, "pid": 1234, "commit": "<sha>",
     "panels_total": 4, "panels_ok": 3, "state": "running"}

`state` is free-form but "running" means the wall is up; a fail-safe screen uses
another value so the updater can tell "alive but not showing panels" apart.
"""
from __future__ import annotations

import json
import os
import tempfile
import time

_DEFAULT_DIR = "/run/soc-wall"
_NAME = "heartbeat.json"

_commit_cache: "str | None" = None


def path() -> str:
    """Where this host's heartbeat lives.

    $SOC_HEARTBEAT_FILE wins: launcher.sh exports it so the supervisor and the
    host can never disagree about the location. Otherwise /run/soc-wall when it
    is writable (the deployed kiosk), then the per-user runtime dir, so a desktop
    or dev run still works without any system setup."""
    explicit = os.environ.get("SOC_HEARTBEAT_FILE", "").strip()
    if explicit:
        return explicit
    if os.access(_DEFAULT_DIR, os.W_OK):
        return os.path.join(_DEFAULT_DIR, _NAME)
    runtime = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if runtime:
        return os.path.join(runtime, "soc-wall", _NAME)
    return os.path.join(tempfile.gettempdir(), f"soc-wall-{os.getuid()}", _NAME)


def deployed_commit() -> str:
    """The commit this code was deployed from, or '' if unknown. Read once: the
    release a process was started from cannot change underneath it."""
    global _commit_cache
    if _commit_cache is None:
        root = os.environ.get("SOC_ROOT") or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", ".."))
        try:
            with open(os.path.join(root, ".commit"), encoding="utf-8") as fh:
                _commit_cache = fh.read().strip()
        except OSError:
            _commit_cache = ""
    return _commit_cache


def write(panels_total: int = 0, panels_ok: int = 0, *, state: str = "running",
          dest: "str | None" = None) -> bool:
    """Publish a heartbeat. Returns False (never raises) if it can't be written:
    a full tmpfs must not take the wall down with it."""
    target = dest or path()
    doc = {
        "ts": time.time(),
        "pid": os.getpid(),
        "commit": deployed_commit(),
        "panels_total": int(panels_total),
        "panels_ok": int(panels_ok),
        "state": state,
    }
    tmp = f"{target}.{os.getpid()}.tmp"
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def read(src: "str | None" = None) -> "dict | None":
    """The last heartbeat, or None if there is none or it is unreadable."""
    try:
        with open(src or path(), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def age(doc: "dict | None", now: "float | None" = None) -> float:
    """Seconds since a heartbeat was written; infinity when there is none, or
    when it is malformed, so 'no data' can never read as 'fresh'."""
    try:
        return max(0.0, (now if now is not None else time.time()) - float(doc["ts"]))
    except (KeyError, TypeError, ValueError):
        return float("inf")
