"""Headless wiring tests for the launcher menu (host.launchermenu).

Exercise the entry table + the --check smoke WITHOUT importing gi / a display.
"""
import os
import subprocess
import sys

from host import launchermenu

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_KIOSK = os.path.join(_REPO, "kiosk-host")


def test_seven_grouped_entries_with_system_actions():
    e = launchermenu._ENTRIES
    assert len(e) == 7
    # each row is now an 8-tuple: (section, glyph, title, sub, tag, class, ckey, action)
    assert all(len(row) == 8 for row in e)
    # action is a plain callable OR a known in-process sentinel (install/uninstall).
    for row in e:
        act = row[-1]
        assert callable(act) or act in (launchermenu._ACT_INSTALL,
                                        launchermenu._ACT_UNINSTALL)
    by_class = {row[5]: row for row in e}
    # configure group: Appearance still wired to launch_appearance.
    assert by_class["soc-appearance"][-1] is launchermenu.launch_appearance
    assert by_class["soc-appearance"][2] == "Appearance"
    # configure group: the new Credentials & Security tile -> launch_credentials.
    assert by_class["soc-credentials"][-1] is launchermenu.launch_credentials
    assert by_class["soc-credentials"][2] == "Credentials & Security"
    # system group: Install/Uninstall sentinels (in-process, need the window).
    assert by_class["soc-install"][-1] == launchermenu._ACT_INSTALL
    assert by_class["soc-uninstall"][-1] == launchermenu._ACT_UNINSTALL
    # every entry lives under a known // section, in run -> configure -> system order.
    assert all(row[0] in launchermenu._SECTIONS for row in e)
    seen = [row[0] for row in e]
    # sections appear contiguously (the build loop groups by section change).
    assert seen == sorted(seen, key=launchermenu._SECTIONS.index)


def test_entries_use_known_mode_glyphs():
    # index-1 is the mode GLYPH key (gear/window/expand/swatch/shield/download/trash).
    keys = [row[1] for row in launchermenu._ENTRIES]
    assert keys == ["window", "expand", "gear", "swatch", "shield", "download", "trash"]
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


def test_launch_credentials_is_callable():
    assert callable(launchermenu.launch_credentials)


def test_health_is_installed_force_override(monkeypatch):
    # The adaptive // system group keys off health.is_installed(); the
    # SOC_FORCE_INSTALLED override (verify's analogue of SOC_VAULT_BACKEND=dev) must
    # drive both states deterministically without touching /etc or /opt.
    from host import health
    keys = {"installed", "etc_present", "opt_present", "units_present",
            "kiosk_user", "reason"}
    monkeypatch.setenv("SOC_FORCE_INSTALLED", "1")
    on = health.is_installed()
    assert set(on) == keys and on["installed"] is True
    monkeypatch.setenv("SOC_FORCE_INSTALLED", "0")
    off = health.is_installed()
    assert off["installed"] is False


def test_reapply_safe_without_provider():
    # _reapply must be a no-op (not crash) when no launcher window is built.
    launchermenu._Launcher.provider = None
    launchermenu._reapply()  # should not raise


def test_check_smoke_no_gi():
    """`--check` must validate the 7-tile control-center wiring in a fresh
    interpreter without importing gi (sysaction._check runs headless too)."""
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
