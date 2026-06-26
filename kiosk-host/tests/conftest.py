"""Pytest bootstrap: make the kiosk-host package importable as `host.*`.

The suite is normally run as `cd kiosk-host && pytest tests/` (see `make test`),
which puts `kiosk-host/` on sys.path implicitly. But it can also be invoked from
the repo root (e.g. `pytest kiosk-host/tests/test_litebw.py`), where `host` would
not resolve. Prepending the kiosk-host directory here makes `from host import ...`
work regardless of the working directory, without changing any production code.
"""
import os
import sys

import pytest

_KIOSK_HOST = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _KIOSK_HOST not in sys.path:
    sys.path.insert(0, _KIOSK_HOST)


@pytest.fixture(autouse=True)
def _isolate_webdata(tmp_path, monkeypatch):
    """Point the private web-data dir (cookies/storage — the renderer-security
    persistence root) at a per-test tmp dir. Without this, configpaths.
    resolve_webdata_dir() lands on /etc/soc-display/webdata on a box where
    /etc/soc-display exists, and a panel build would try (and fail) to mkdir it
    0700. Keeps the suite hermetic on dev + CI + the Pi alike."""
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "webdata"))
