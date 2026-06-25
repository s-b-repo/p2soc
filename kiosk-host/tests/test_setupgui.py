"""Headless tests for the graphical setup wizard (host.setupgui).

These exercise the config-building + rendering path WITHOUT importing gi / needing
a display, so they run in the display-less `make test`. The GUI codepath (gi) is
never touched here.
"""
import os
import subprocess
import sys

import pytest

from host import config, setupgui

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_KIOSK = os.path.join(_REPO, "kiosk-host")


def test_no_gi_on_headless_path(tmp_path):
    """Importing host.setupgui + running the headless render must not pull in gi.

    Checked in a FRESH interpreter so other tests in the suite (which legitimately
    import gi for the WebKit panel) can't pollute the result.
    """
    code = (
        "import sys\n"
        "import host.setupgui as g\n"
        f"rc = g.build_headless('empty', {str(tmp_path)!r}, non_interactive=True)\n"
        "assert rc == 0, rc\n"
        "assert 'gi' not in sys.modules, 'setupgui must not import gi on the headless path'\n"
        "print('ok')\n"
    )
    env = dict(os.environ, PYTHONPATH=_KIOSK)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_list_presets_nonempty():
    names = setupgui.preset_names()
    assert "empty" in names
    assert "single-panel" in names
    assert "wazuh-zabbix-2x2" in names
    # each discovered preset carries a human name + description
    for name, disp, desc in setupgui.discover_presets():
        assert disp and isinstance(desc, str)


@pytest.mark.parametrize("preset,expect_panels", [
    ("empty", 0),
    ("single-panel", 1),
    ("wazuh-zabbix-2x2", 4),
])
def test_build_headless_writes_valid_config(preset, expect_panels, tmp_path):
    rc = setupgui.build_headless(preset, str(tmp_path), non_interactive=True)
    assert rc == 0

    panels = tmp_path / "panels.yaml"
    socenv = tmp_path / "soc.env"
    assert panels.exists() and socenv.exists()
    # modes: panels 0644, soc.env 0600 (dev target)
    assert oct(panels.stat().st_mode & 0o777) == "0o644"
    assert oct(socenv.stat().st_mode & 0o777) == "0o600"

    # the generated panels.yaml parses through the kiosk validator
    conf = config.load(str(panels))
    assert len(conf.panels) == expect_panels

    # the master password is NEVER written to soc.env
    text = socenv.read_text()
    assert "SOC_VAULT_PASSWORD" not in text
    assert "SOC_VAULT_BACKEND=" in text
    assert "SOC_SESSION=" in text


def test_every_discovered_preset_renders_valid_config(tmp_path):
    """Every preset the app auto-discovers (config/presets/*.yaml) must render to a
    panels.yaml that passes config.load(). Iterates preset_names() rather than a
    hardcoded list so a newly-added preset cannot ship un-validated."""
    names = setupgui.preset_names()
    assert names, "no presets discovered"
    for name in names:
        out = tmp_path / name
        rc = setupgui.build_headless(name, str(out), non_interactive=True)
        assert rc == 0, f"build_headless({name!r}) returned {rc}"
        config.load(str(out / "panels.yaml"))  # raises ConfigError on a bad preset


def test_unknown_preset_returns_nonzero(tmp_path):
    rc = setupgui.build_headless("does-not-exist", str(tmp_path))
    assert rc != 0


def test_soc_env_seeds_every_key(tmp_path):
    """render_soc_env indexes e[k] directly — a partial dict KeyErrors. The model
    must seed every key the renderer needs."""
    setup = setupgui._load_setup()
    paths = setup.resolve_paths("dev")
    model = setupgui.WizardModel(setup, paths)
    text = setup.render_soc_env(model.soc_env())   # must not raise KeyError
    assert "SOC_ROOT=" in text
    assert "SOC_CDP_BASE_PORT=" in text


def test_master_never_in_cfg_or_env(tmp_path):
    setup = setupgui._load_setup()
    paths = setup.resolve_paths("dev")
    model = setupgui.WizardModel(setup, paths)
    model.master_password = "super-secret-master"
    # the master lives only on the model; it must not leak into cfg / soc.env.
    assert "super-secret-master" not in setup.render_panels_yaml(model.cfg())
    assert "super-secret-master" not in setup.render_soc_env(model.soc_env())


def test_validate_catches_broken_cfg(tmp_path):
    setup = setupgui._load_setup()
    paths = setup.resolve_paths("dev")
    model = setupgui.WizardModel(setup, paths)
    model.apply_preset("wazuh-zabbix-2x2")
    assert model.validate() == []
    # duplicate ids -> validation problem
    cfg = model.cfg()
    if len(cfg["panels"]) >= 2:
        cfg["panels"][1]["id"] = cfg["panels"][0]["id"]
        assert model.validate() != []
