"""Phase 6: re-auth helpers + inventory pure logic.

Tests exercise the pure-Python pieces of the re-auth gate (the GTK
dialog itself is GUI-heavy and exercised by manual verification).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _fresh(monkeypatch, tmp_path):
    """Point state_dir at a tmp dir + reload configwin so the module-level
    file paths re-resolve."""
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    import importlib
    from host import configwin
    return importlib.reload(configwin)


# --- _reauth_required / _reauth_verify --------------------------------- #

def test_reauth_required_false_when_nothing_enrolled(monkeypatch, tmp_path):
    cw = _fresh(monkeypatch, tmp_path)
    assert cw._reauth_required() is False


def test_reauth_required_true_when_pin_set(monkeypatch, tmp_path):
    cw = _fresh(monkeypatch, tmp_path)
    cw.set_pin("321987")
    assert cw._reauth_required() is True


def test_reauth_verify_accepts_pin(monkeypatch, tmp_path):
    cw = _fresh(monkeypatch, tmp_path)
    cw.set_pin("321987")
    assert cw._reauth_verify("321987") is True
    assert cw._reauth_verify("wrong0") is False


def test_reauth_verify_rejects_empty(monkeypatch, tmp_path):
    cw = _fresh(monkeypatch, tmp_path)
    cw.set_pin("321987")
    assert cw._reauth_verify("") is False
    assert cw._reauth_verify("   ") is False


def test_reauth_verify_accepts_totp(monkeypatch, tmp_path):
    cw = _fresh(monkeypatch, tmp_path)
    from host import totp
    secret = totp.generate_secret()
    totp.save(cw._totp_path(), secret)
    code = totp.totp(secret)
    assert cw._reauth_verify(code) is True
    assert cw._reauth_verify("000000") is False


# --- _collect_inventory ------------------------------------------------- #

class _StubPanel:
    def __init__(self, id, vault_item):
        self.id = id
        self.vault_item = vault_item


class _FakeVault:
    def __init__(self, folders=None):
        self.folders = dict(folders or {})

    def list_by_folder(self, folder):
        return list(self.folders.get(folder, []))


def _build_inventory(panels=None, vpns=None, proxy="", tunnel=None, vault=None):
    """Construct a minimal object exposing the attributes _collect_inventory
    reads — no GTK widgets needed."""
    class _Ctx:
        pass
    ctx = _Ctx()
    ctx.panels = panels or []
    ctx._vpns = vpns or []
    ctx._proxy_vault_item = proxy
    ctx._tunnel = tunnel
    ctx._vault = vault
    from host import configwin
    return configwin.ConfigWindow._collect_inventory(ctx)


def test_inventory_dedupes_when_two_panels_share_vault_item(monkeypatch, tmp_path):
    _fresh(monkeypatch, tmp_path)
    items = _build_inventory(panels=[
        _StubPanel("p1", "zabbix"),
        _StubPanel("p2", "zabbix"),     # same item — should appear once
    ])
    assert [i["name"] for i in items] == ["zabbix"]
    # First-wins on origin label.
    assert items[0]["origin"] == "panel:p1"


def test_inventory_orders_panels_then_vpns_then_proxy(monkeypatch, tmp_path):
    _fresh(monkeypatch, tmp_path)
    items = _build_inventory(
        panels=[_StubPanel("p1", "zabbix")],
        vpns=[{"name": "hq", "vault_item": "vpn-hq"}],
        proxy="proxy-creds",
    )
    names = [i["name"] for i in items]
    assert names == ["zabbix", "vpn-hq", "proxy-creds"]


def test_inventory_skips_nullified_vpn_entry(monkeypatch, tmp_path):
    """Phase 4 marks removed VPNs as None in self._vpns — inventory must
    skip those without crashing on the v.get() lookup."""
    _fresh(monkeypatch, tmp_path)
    items = _build_inventory(vpns=[None, {"name": "dr",
                                          "vault_item": "vpn-dr"}])
    assert [i["name"] for i in items] == ["vpn-dr"]


def test_inventory_includes_folder_items(monkeypatch, tmp_path):
    _fresh(monkeypatch, tmp_path)
    v = _FakeVault({"SOC Wall Auth": ["SOC Settings TOTP",
                                       "SOC Panel Lock TOTP"]})
    items = _build_inventory(vault=v)
    names = [i["name"] for i in items]
    assert "SOC Settings TOTP" in names
    assert "SOC Panel Lock TOTP" in names
    # Folder items carry the dedicated origin tag.
    origins = {i["name"]: i["origin"] for i in items}
    assert origins["SOC Settings TOTP"] == "SOC Wall Auth folder"


def test_inventory_empty_when_nothing_configured(monkeypatch, tmp_path):
    _fresh(monkeypatch, tmp_path)
    items = _build_inventory()
    assert items == []


def test_inventory_swallows_vault_list_exception(monkeypatch, tmp_path):
    _fresh(monkeypatch, tmp_path)

    class _Boom:
        def list_by_folder(self, _f):
            raise RuntimeError("vault down")

    items = _build_inventory(panels=[_StubPanel("p1", "x")],
                              vault=_Boom())
    # Panel item is still present; folder lookup failure didn't crash.
    assert [i["name"] for i in items] == ["x"]
