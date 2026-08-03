"""Phase 5: TOTP secrets stored in Vaultwarden notes (centralised across
roaming walls). The local file store stays as fallback / migration source."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import totp                                  # noqa: E402


class _FakeVault:
    def __init__(self, notes_by_item=None):
        self._notes = dict(notes_by_item or {})
        self.invalidations = []
        self.ready = True

    def notes(self, item):
        return self._notes.get(item, "")

    def invalidate(self, item=None):
        self.invalidations.append(item)


def test_vault_item_for_known_kinds():
    assert totp.vault_item_for("settings") == "SOC Settings TOTP"
    assert totp.vault_item_for("panellock") == "SOC Panel Lock TOTP"


def test_vault_item_for_unknown_kind_raises():
    with pytest.raises(ValueError):
        totp.vault_item_for("frobnitz")


def test_load_vault_returns_secret_when_present():
    v = _FakeVault({"SOC Settings TOTP": "JBSWY3DPEHPK3PXP"})
    assert totp.load_vault(v, "settings") == "JBSWY3DPEHPK3PXP"


def test_load_vault_strips_surrounding_whitespace():
    v = _FakeVault({"SOC Panel Lock TOTP": "  ABCD2345  \n"})
    assert totp.load_vault(v, "panellock") == "ABCD2345"


def test_load_vault_returns_none_when_absent():
    v = _FakeVault({})
    assert totp.load_vault(v, "settings") is None


def test_load_vault_returns_none_when_vault_is_none():
    """A caller without a ready vault must get None back, not an error."""
    assert totp.load_vault(None, "settings") is None


def test_load_vault_returns_none_on_backend_exception():
    """A flaky vault.notes() must not crash the locker prompt."""
    class _Boom:
        ready = True
        def notes(self, _item):
            raise RuntimeError("vault hiccup")

    assert totp.load_vault(_Boom(), "panellock") is None


def test_save_vault_writes_secure_note_and_invalidates_cache(monkeypatch):
    """save_vault delegates to vaultseed.upsert_secure_note + invalidates
    the vault cache so a subsequent read sees the new value."""
    captured = []
    from host import vaultseed

    def fake_upsert(url, email, master, *, name, notes, folder=None):
        captured.append({"url": url, "email": email, "master": master,
                         "name": name, "notes": notes, "folder": folder})
        return "created"

    monkeypatch.setattr(vaultseed, "upsert_secure_note", fake_upsert)
    v = _FakeVault({})
    totp.save_vault(v, ("http://127.0.0.1:8222", "kiosk@soc.local", "secret"),
                    "settings", "JBSWY3DPEHPK3PXP")
    assert len(captured) == 1
    c = captured[0]
    assert c["name"] == "SOC Settings TOTP"
    assert c["notes"] == "JBSWY3DPEHPK3PXP"
    assert c["folder"] == "SOC Wall Auth"
    assert v.invalidations == ["SOC Settings TOTP"]


def test_clear_vault_calls_delete_login(monkeypatch):
    """clear_vault delegates to vaultseed.delete_login + invalidates cache."""
    captured = []
    from host import vaultseed

    def fake_delete(url, email, master, *, name):
        captured.append({"url": url, "name": name})
        return True

    monkeypatch.setattr(vaultseed, "delete_login", fake_delete)
    v = _FakeVault({})
    rc = totp.clear_vault(v, ("http://127.0.0.1:8222", "k@s", "m"),
                          "panellock")
    assert rc is True
    assert captured == [{"url": "http://127.0.0.1:8222",
                         "name": "SOC Panel Lock TOTP"}]
    assert v.invalidations == ["SOC Panel Lock TOTP"]
