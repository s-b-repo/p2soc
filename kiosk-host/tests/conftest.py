"""Shared pytest fixtures.

The product is rbw-only (no JSON "dev" vault backend), so tests that exercise the
Vault facade or anything that builds a Vault inject an in-memory fake backend
instead of shelling out to rbw / Vaultwarden.
"""
import os
import sys

# Make `host` importable regardless of the CWD pytest was launched from.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest  # noqa: E402

from host import vault  # noqa: E402


class FakeBackend:
    """In-memory stand-in for the rbw vault backend.

    data maps item name -> {"username": ..., "password": ..., "notes": ...}.
    Mirrors the backend duck-type the Vault facade expects (configure/unlock/
    sync/get/notes).
    """

    def __init__(self, data=None):
        self.data = dict(data or {})

    def configure(self):
        pass

    def unlock(self):
        pass

    def sync(self):
        pass

    def get(self, item):
        rec = self.data.get(item)
        if not rec:
            raise vault.VaultError(f"no vault item '{item}'")
        return rec.get("username", ""), rec["password"]

    def notes(self, item):
        return (self.data.get(item) or {}).get("notes", "")

    def notes_required(self, item, purpose=""):
        out = self.notes(item)
        if not out.strip():
            what = f" for {purpose}" if purpose else ""
            raise vault.VaultError(
                f"vault item '{item}' has an empty Notes field{what}")
        return out

    def delete(self, item):
        """Symmetric to RbwBackend.delete — True on hit, False if absent."""
        return self.data.pop(item, None) is not None

    def list_by_folder(self, folder):
        """Optional folder index. Tests that exercise list_by_folder seed
        FakeBackend(...) with a `folders` kwarg via direct attribute set:
        backend.folders = {'SOC Wall Auth': ['SOC Settings TOTP']}.
        Default: empty list (so vault.list_by_folder is safe-no-op)."""
        return list(getattr(self, "folders", {}).get(folder, []))


@pytest.fixture
def fake_vault():
    """Builder: fake_vault(data, ttl) -> a Vault wired to a FakeBackend."""
    def _build(data=None, ttl=30.0):
        v = vault.Vault(ttl=ttl)
        v.backend = FakeBackend(data)
        return v
    return _build


@pytest.fixture
def use_fake_backend(monkeypatch):
    """Patch vault._make_backend so any Vault() built during the test (e.g. one
    constructed deep inside the VPN supervisor) uses an in-memory FakeBackend."""
    def _install(data=None):
        monkeypatch.setattr(vault, "_make_backend", lambda: FakeBackend(data))
    return _install
