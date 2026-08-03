"""apply_config's display branch — verify what applies LIVE vs what
needs a soft-restart. The runtime side (wall.window.resize, grid reflow)
is GTK-heavy and exercised by manual verification; here we test the
dispatch logic in pure Python."""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _host(panels=None, cols=2, rows=2, width=1920, height=1080,
          fullscreen=True, layout="single"):
    """Build a minimal KioskHost — bypasses __init__ which constructs a
    real Vault. We mutate just enough state for apply_config's display
    branch to make decisions."""
    from host import main as host_main
    from host import config as cfg
    h = host_main.KioskHost.__new__(host_main.KioskHost)
    h.conf = SimpleNamespace(
        display=cfg.DisplayCfg(cols=cols, rows=rows, width=width,
                                height=height, fullscreen=fullscreen,
                                layout=layout, gap=0, auto=True),
        panels=panels or [],
        vpns=[],
        vpn=None,
        proxy=cfg.ProxyCfg(),
        tunnel={},
    )
    h.panels_view = []
    h.wall = SimpleNamespace(
        window=SimpleNamespace(resize=lambda *a, **kw: None),
        grid=SimpleNamespace(set_row_spacing=lambda *_: None,
                              set_column_spacing=lambda *_: None,
                              set_row_homogeneous=lambda *_: None,
                              set_column_homogeneous=lambda *_: None,
                              remove=lambda *_: None,
                              show_all=lambda: None),
        attach=lambda *_a, **_kw: None,
        _fit_to_screen=lambda: None,
        _fullscreen=fullscreen,
        _toggle_fullscreen=lambda: None,
    )
    h._can_systemctl_restart = lambda: False
    h._push_config_to_vault = lambda: "ok"
    h._restart_wall_at_tail = lambda: None
    return h


def test_width_change_applies_live(monkeypatch):
    h = _host()
    # Stub _apply_display_live to record what was sent.
    captured = []
    monkeypatch.setattr(h, "_apply_display_live",
                        lambda chg, cur: captured.append(("apply", chg, cur))
                        or True)
    out = h.apply_config({"_display": {"width": 1600, "height": 900}})
    assert out["self_restart"] is False
    assert sorted(out.get("applied_live") or []) == ["height", "width"]
    assert captured and captured[0][1] == {"width": 1600, "height": 900}


def test_fullscreen_toggle_applies_live(monkeypatch):
    h = _host(fullscreen=True)
    monkeypatch.setattr(h, "_apply_display_live",
                        lambda chg, cur: True)
    out = h.apply_config({"_display": {"fullscreen": False}})
    assert out["self_restart"] is False
    assert out.get("applied_live") == ["fullscreen"]


def test_cols_grow_applies_live(monkeypatch):
    """Growing the grid is safe — existing panels (at 0..N-1 in the old
    layout) stay within bounds of the larger grid."""
    from host import config as cfg
    panels = [SimpleNamespace(id="p1", grid=(0, 0)),
              SimpleNamespace(id="p2", grid=(1, 0))]
    h = _host(panels=panels, cols=2, rows=1)
    monkeypatch.setattr(h, "_apply_display_live", lambda *_: True)
    out = h.apply_config({"_display": {"cols": 4, "rows": 2}})
    assert out["self_restart"] is False
    assert sorted(out.get("applied_live")) == ["cols", "rows"]


def test_cols_shrink_orphan_triggers_restart():
    """Shrinking the grid below an existing panel's (col, row) would
    orphan it — that needs operator confirmation via a real restart."""
    panels = [SimpleNamespace(id="p1", grid=(0, 0)),
              SimpleNamespace(id="p2", grid=(1, 0)),
              SimpleNamespace(id="p3", grid=(0, 1)),
              SimpleNamespace(id="p4", grid=(1, 1))]
    h = _host(panels=panels, cols=2, rows=2)
    out = h.apply_config({"_display": {"cols": 1, "rows": 2}})
    assert out["self_restart"] is True
    # The pending message names the orphans for the operator.
    assert any("orphan" in s and "p2" in s and "p4" in s
               for s in out["pending_restarts"])


def test_layout_change_triggers_restart(monkeypatch):
    """layout (single ↔ windows) is a windowing-model swap — we cannot
    in-place-recreate a WallWindow type, so this always restarts."""
    h = _host(layout="single")
    out = h.apply_config({"_display": {"layout": "windows"}})
    assert out["self_restart"] is True


def test_no_display_change_no_restart(monkeypatch):
    """A change to a non-display section (e.g. vault item edits) leaves
    self_restart False + applied_live absent."""
    h = _host()
    out = h.apply_config({"_display": {"width": 1920}})  # same as current
    assert out["self_restart"] is False
    assert not (out.get("applied_live") or [])


def test_apply_display_live_handles_missing_wall_safely(monkeypatch):
    """When self.wall is None (booting / shutting down), live apply
    returns False so the caller falls through to soft-restart."""
    h = _host()
    h.wall = None
    rc = h._apply_display_live({"width": 1024}, {"width": 1920})
    assert rc is False


def test_apply_display_live_mutates_config_first():
    """After a successful live apply, self.conf.display reflects the new
    values immediately — other code paths (override save, status tab)
    read the post-change values."""
    h = _host(width=1920, height=1080, cols=2, rows=2, fullscreen=True)
    rc = h._apply_display_live(
        {"width": 1600, "height": 900, "cols": 3, "rows": 2,
         "fullscreen": False},
        {"width": 1920, "height": 1080, "cols": 2, "rows": 2,
         "fullscreen": True})
    assert rc is True
    assert h.conf.display.width == 1600
    assert h.conf.display.height == 900
    assert h.conf.display.cols == 3
    assert h.conf.display.rows == 2
    assert h.conf.display.fullscreen is False
