"""Phase 4: vaultseed.Session.delete_item + upsert_secure_note.

These tests mock the HTTP layer (urllib via the module-level `_req`) rather
than spin up a Vaultwarden — same pattern other vaultseed callers use.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import vaultseed                              # noqa: E402


class _FakeSession(vaultseed.Session):
    """Bypass the master-password handshake (which needs a real Vaultwarden)
    and pre-seed everything Session methods touch downstream of __init__."""
    def __init__(self, base_url="http://127.0.0.1:8222"):
        # Skip super().__init__ — it would do real network I/O.
        self.base = base_url.rstrip("/")
        self.ek = b"E" * 32
        self.mk = b"M" * 32
        self.auth = {"Authorization": "Bearer fake-token"}


def test_delete_item_unknown_name_returns_false(monkeypatch):
    """No matching cipher → no DELETE issued, returns False."""
    sess = _FakeSession()
    calls = []
    monkeypatch.setattr(sess, "_find", lambda name: None)
    monkeypatch.setattr(vaultseed, "_req",
                        lambda *a, **kw: calls.append((a, kw)) or {})
    assert sess.delete_item("missing") is False
    assert calls == []                           # no HTTP traffic


def test_delete_item_known_issues_http_delete(monkeypatch):
    """Found cipher → exactly one DELETE /api/ciphers/<id> with Bearer auth."""
    sess = _FakeSession()
    monkeypatch.setattr(sess, "_find", lambda name: "abc-123")
    calls = []

    def fake_req(url, headers=None, data=None, method="GET", form=False):
        calls.append({"url": url, "headers": headers, "method": method})
        return {}

    monkeypatch.setattr(vaultseed, "_req", fake_req)
    assert sess.delete_item("SOC VPN hq") is True
    assert len(calls) == 1
    c = calls[0]
    assert c["method"] == "DELETE"
    assert c["url"].endswith("/api/ciphers/abc-123")
    assert c["headers"]["Authorization"] == "Bearer fake-token"


def test_delete_item_propagates_http_error(monkeypatch):
    """A 500 from Vaultwarden surfaces as VaultSeedError (caller catches it
    to show a 'delete failed; check journal' at the glass)."""
    sess = _FakeSession()
    monkeypatch.setattr(sess, "_find", lambda name: "abc-123")

    def fake_req(*_a, **_kw):
        raise vaultseed.VaultSeedError("DELETE http://… -> HTTP 500: oops")

    monkeypatch.setattr(vaultseed, "_req", fake_req)
    with pytest.raises(vaultseed.VaultSeedError):
        sess.delete_item("anything")


# --- upsert_secure_note --------------------------------------------------- #

def test_upsert_secure_note_creates_when_absent(monkeypatch):
    """No matching cipher → POST /api/ciphers with type=2 body."""
    sess = _FakeSession()
    monkeypatch.setattr(sess, "_find", lambda name: None)
    captured = []

    def fake_req(url, headers=None, data=None, method="GET", form=False):
        captured.append({"url": url, "method": method, "data": data})
        return {}

    monkeypatch.setattr(vaultseed, "_req", fake_req)
    rc = sess.upsert_secure_note("SOC Settings TOTP", "JBSWY3DPEHPK3PXP")
    assert rc == "created"
    assert len(captured) == 1
    c = captured[0]
    assert c["method"] == "POST"
    assert c["url"].endswith("/api/ciphers")
    assert c["data"]["type"] == 2                # secure note, not login
    assert c["data"]["secureNote"] == {"type": 0}


def test_upsert_secure_note_updates_when_present(monkeypatch):
    """Existing cipher → PUT /api/ciphers/<id>, NOT POST."""
    sess = _FakeSession()
    monkeypatch.setattr(sess, "_find", lambda name: "cipher-987")
    captured = []

    def fake_req(url, headers=None, data=None, method="GET", form=False):
        captured.append({"url": url, "method": method})
        return {}

    monkeypatch.setattr(vaultseed, "_req", fake_req)
    rc = sess.upsert_secure_note("SOC Panel Lock TOTP", "ABCD")
    assert rc == "updated"
    assert captured == [{
        "url": sess.base + "/api/ciphers/cipher-987",
        "method": "PUT",
    }]
