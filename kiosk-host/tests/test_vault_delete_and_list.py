"""Phase 4: vault.delete + vault.list_by_folder facade methods.

Backend behaviour is exercised against the FakeBackend in conftest. The
real RbwBackend.delete/list_by_folder wrap rbw subprocess calls; those are
tested in test_vaultseed_delete_and_secure_note.py at the HTTP level.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import vault                                  # noqa: E402


def _build_vault(data, folders=None):
    v = vault.Vault(ttl=30.0)
    # use the FakeBackend declared in conftest.py
    from conftest import FakeBackend
    v.backend = FakeBackend(dict(data))
    if folders is not None:
        v.backend.folders = dict(folders)
    return v


# --- vault.delete -------------------------------------------------------- #

def test_delete_returns_true_when_item_exists():
    v = _build_vault({"foo": {"password": "x"}})
    assert v.delete("foo") is True
    assert v.delete("foo") is False         # idempotent — gone the second time


def test_delete_invalidates_cache():
    """After a delete the cached username/password must NOT linger."""
    v = _build_vault({"foo": {"username": "u", "password": "p"}})
    v.creds("foo")                          # populate cache
    assert v.cached("foo") is True
    v.delete("foo")
    assert v.cached("foo") is False


def test_delete_returns_false_when_backend_raises():
    v = _build_vault({"foo": {"password": "p"}})

    def boom(_item):
        raise RuntimeError("subprocess fell over")
    v.backend.delete = boom
    # Must not propagate — the GUI shows a single 'delete failed' toast
    # rather than a stack trace at the glass.
    assert v.delete("foo") is False


# --- vault.list_by_folder ----------------------------------------------- #

def test_list_by_folder_returns_names():
    v = _build_vault({}, folders={"SOC Wall Auth": ["SOC Settings TOTP",
                                                    "SOC Panel Lock TOTP"]})
    assert v.list_by_folder("SOC Wall Auth") == [
        "SOC Settings TOTP", "SOC Panel Lock TOTP"]


def test_list_by_folder_empty_or_unknown_returns_empty():
    v = _build_vault({}, folders={"SOC Wall Auth": []})
    assert v.list_by_folder("SOC Wall Auth") == []
    assert v.list_by_folder("does-not-exist") == []


def test_list_by_folder_returns_empty_on_backend_error():
    v = _build_vault({})

    def boom(_folder):
        raise RuntimeError("rbw down")
    v.backend.list_by_folder = boom
    assert v.list_by_folder("any") == []
