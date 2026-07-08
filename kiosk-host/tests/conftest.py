"""Pytest bootstrap: make the kiosk-host package importable as `host.*`.

The suite is normally run as `cd kiosk-host && pytest tests/` (see `make test`),
which puts `kiosk-host/` on sys.path implicitly. But it can also be invoked from
the repo root (e.g. `pytest kiosk-host/tests/test_litebw.py`), where `host` would
not resolve. Prepending the kiosk-host directory here makes `from host import ...`
work regardless of the working directory, without changing any production code.
"""
import os
import sys

_KIOSK_HOST = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _KIOSK_HOST not in sys.path:
    sys.path.insert(0, _KIOSK_HOST)
