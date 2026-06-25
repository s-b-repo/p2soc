"""Headless wiring tests for the launcher menu (host.launchermenu).

Exercise the entry table + the --check smoke WITHOUT importing gi / a display.
"""
import os
import subprocess
import sys

from host import launchermenu

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_KIOSK = os.path.join(_REPO, "kiosk-host")


def test_four_entries_with_appearance():
    e = launchermenu._ENTRIES
    assert len(e) == 4
    assert all(len(row) == 7 and callable(row[-1]) for row in e)
    # the 4th tile is Appearance, wired to launch_appearance
    by_class = {row[4]: row for row in e}
    assert "soc-appearance" in by_class
    assert by_class["soc-appearance"][-1] is launchermenu.launch_appearance
    assert by_class["soc-appearance"][1] == "Appearance"


def test_entries_use_known_mode_glyphs():
    # index-0 is now a mode GLYPH key (gear/window/expand/swatch), not a numeral.
    keys = [row[0] for row in launchermenu._ENTRIES]
    assert keys == ["gear", "window", "expand", "swatch"]
    assert all(k in launchermenu._GLYPHS for k in keys)
    # each glyph template renders a non-empty accent-stroked SVG body (headless,
    # no gi) and has a unicode fallback so a box without the SVG loader still shows.
    for k in keys:
        body = launchermenu._GLYPHS[k]("#1FA463")
        assert "#1FA463" in body and "stroke" in body
        assert k in launchermenu._GLYPH_FALLBACK


def test_shorten_path_collapses_home_and_truncates():
    import os
    home = os.path.expanduser("~")
    assert launchermenu._shorten_path(home + "/.config/soc-display/panels.yaml").startswith("~")
    # an over-long absolute path keeps the basename behind a leading ellipsis.
    long = "/very/deep/nested/tree/of/dirs/soc-display/panels.yaml"
    short = launchermenu._shorten_path(long, limit=20)
    assert short.startswith("…/") and short.endswith("panels.yaml")
    # a short path is returned verbatim.
    assert launchermenu._shorten_path("/etc/x") == "/etc/x"


def test_launch_appearance_is_callable():
    assert callable(launchermenu.launch_appearance)


def test_reapply_safe_without_provider():
    # _reapply must be a no-op (not crash) when no launcher window is built.
    launchermenu._Launcher.provider = None
    launchermenu._reapply()  # should not raise


def test_check_smoke_no_gi():
    """`--check` must validate the 4-tile wiring in a fresh interpreter without gi."""
    code = (
        "import sys\n"
        "import host.launchermenu as m\n"
        "rc = m.main(['--check'])\n"
        "assert rc == 0, rc\n"
        "assert 'gi' not in sys.modules, 'launchermenu --check must not import gi'\n"
        "print('ok')\n"
    )
    env = dict(os.environ, PYTHONPATH=_KIOSK)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout
