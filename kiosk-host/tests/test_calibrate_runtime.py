"""Phase 8 runtime wiring: main.calibrate_panel + the override-save path.

Tests cover the route — given a panels_view list, calibrate_panel must
find the right view, call its calibrate() method, and on success persist
the captured zones into the override file. The actual JS injection is
exercised by the WebKit/Chromium calibrate() methods which need a live
renderer (manual verification only)."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _fresh_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    import importlib
    from host import configwin
    importlib.reload(configwin)
    return tmp_path


class _StubPanel:
    def __init__(self, id):
        self.id = id
        self.login_zones = {}


class _StubView:
    def __init__(self, panel):
        self.panel = panel
        self.called_with = None

    def calibrate(self, on_done):
        self.called_with = on_done


def _build_host(views=None):
    """Build a minimal KioskHost without running its __init__ (which
    constructs a real Vault). We only need calibrate_panel + its
    dependencies, which is just panels_view + _save_login_zones_override."""
    from host import main as host_main
    h = host_main.KioskHost.__new__(host_main.KioskHost)
    h.panels_view = views or []
    return h


def test_calibrate_panel_routes_to_matching_view(monkeypatch, tmp_path):
    _fresh_state_dir(monkeypatch, tmp_path)
    view = _StubView(_StubPanel("zabbix"))
    h = _build_host([view])
    done = []
    h.calibrate_panel("zabbix", lambda z: done.append(z))
    assert view.called_with is not None, \
        "calibrate_panel must call view.calibrate()"


def test_calibrate_panel_unknown_id_calls_on_done_none(monkeypatch, tmp_path):
    _fresh_state_dir(monkeypatch, tmp_path)
    view = _StubView(_StubPanel("zabbix"))
    h = _build_host([view])
    rc = []
    h.calibrate_panel("does-not-exist", lambda z: rc.append(z))
    assert rc == [None]
    assert view.called_with is None                    # never invoked


def test_calibrate_panel_persists_override_on_success(monkeypatch, tmp_path):
    _fresh_state_dir(monkeypatch, tmp_path)
    view = _StubView(_StubPanel("zabbix"))
    h = _build_host([view])
    received = []
    h.calibrate_panel("zabbix", lambda z: received.append(z))
    # Simulate the operator completing all 3 clicks.
    zones = {"user": {"x_pct": 0.5, "y_pct": 0.4},
             "pass": {"x_pct": 0.5, "y_pct": 0.5},
             "submit": {"x_pct": 0.55, "y_pct": 0.6}}
    view.called_with(zones)
    # The host wrote zones into the override file.
    override = tmp_path / "overrides.json"
    assert override.exists()
    data = json.loads(override.read_text())
    assert data["zabbix"]["login_zones"] == zones
    # And updated the live Panel.
    assert view.panel.login_zones == zones
    # on_done was forwarded.
    assert received == [zones]


def test_calibrate_panel_passes_through_cancel(monkeypatch, tmp_path):
    _fresh_state_dir(monkeypatch, tmp_path)
    view = _StubView(_StubPanel("zabbix"))
    h = _build_host([view])
    received = []
    h.calibrate_panel("zabbix", lambda z: received.append(z))
    # Operator cancelled — the view fires None.
    view.called_with(None)
    assert received == [None]
    # No override was written for the cancelled session.
    override = tmp_path / "overrides.json"
    assert not override.exists() or "login_zones" not in (
        json.loads(override.read_text()).get("zabbix") or {})


def test_calibrate_panel_view_without_calibrate_method(monkeypatch, tmp_path):
    """A renderer that doesn't implement calibrate() (e.g. a future
    headless engine) must fail closed — on_done(None), no crash."""
    _fresh_state_dir(monkeypatch, tmp_path)

    class _ViewNoCalibrate:
        panel = _StubPanel("zabbix")

    h = _build_host([_ViewNoCalibrate()])
    rc = []
    h.calibrate_panel("zabbix", lambda z: rc.append(z))
    assert rc == [None]


def test_save_login_zones_helper_merges_with_existing_overrides(monkeypatch, tmp_path):
    """_save_login_zones_override must merge into per-panel overrides
    rather than overwriting them (a panel may already have url / title /
    selector overrides we mustn't clobber)."""
    _fresh_state_dir(monkeypatch, tmp_path)
    # Seed an existing override (url + title).
    from host import configwin
    configwin.save_overrides({"p1": {"url": "https://example.test/",
                                       "title": "Zabbix"}})
    h = _build_host()
    h._save_login_zones_override(
        "p1",
        {"user": {"x_pct": 0.5, "y_pct": 0.5}})
    data = json.loads((tmp_path / "overrides.json").read_text())
    # Existing fields survived.
    assert data["p1"]["url"] == "https://example.test/"
    assert data["p1"]["title"] == "Zabbix"
    # And the new zones were added.
    assert data["p1"]["login_zones"]["user"] == {"x_pct": 0.5, "y_pct": 0.5}
