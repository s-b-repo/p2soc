"""On-screen Display settings: extended override merge (grid + resolution)."""
from host import config, configwin


def _disp(**kw):
    d = config.DisplayCfg()
    for k, v in kw.items():
        setattr(d, k, v)
    return d


def test_display_override_layout_and_gap_still_work():
    d = _disp(layout="auto", gap=0)
    configwin.apply_display_override(d, {"_display": {"layout": "single", "gap": 8}})
    assert d.layout == "single" and d.gap == 8


def test_display_override_grid_and_resolution():
    d = _disp(cols=2, rows=2, width=1920, height=1080, auto=True)
    configwin.apply_display_override(d, {"_display": {
        "cols": 2, "rows": 3, "width": 3840, "height": 2160, "auto": False}})
    assert d.cols == 2 and d.rows == 3
    assert d.width == 3840 and d.height == 2160
    assert d.auto is False


def test_display_override_rejects_out_of_range():
    d = _disp(cols=2, rows=2, width=1920, height=1080)
    configwin.apply_display_override(d, {"_display": {
        "cols": 0, "rows": 99, "width": 100, "height": 999_999}})
    assert d.cols == 2 and d.rows == 2                  # bounds: 1..8
    assert d.width == 1920 and d.height == 1080         # bounds: 320..16384


def test_display_override_noop():
    d = _disp(cols=2, rows=2, gap=4)
    configwin.apply_display_override(d, {})
    assert (d.cols, d.rows, d.gap) == (2, 2, 4)


def test_display_override_invalid_layout_ignored():
    d = _disp(layout="auto")
    configwin.apply_display_override(d, {"_display": {"layout": "bogus"}})
    assert d.layout == "auto"
