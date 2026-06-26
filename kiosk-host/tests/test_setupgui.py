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


def test_soc_env_secret_dir_tracks_paths_after_fallback(tmp_path):
    """Regression: when the wizard's /etc pkexec escalation is declined and it falls
    back to the per-user dir, _write() updates model.paths['secret_dir'] to the
    user-dir secret and then RE-DERIVES soc.env from it. If soc.env were rendered
    from the stale /etc paths, the wall (run as this user) would hunt for the sealed
    master in root-owned /etc and never self-unlock. Assert soc_env() tracks paths."""
    setup = setupgui._load_setup()
    paths = dict(setup.resolve_paths("dev"))
    paths["secret_dir"] = "/etc/soc-display/secret"
    model = setupgui.WizardModel(setup, paths)
    assert model.soc_env()["SOC_SECRET_DIR"] == "/etc/soc-display/secret"
    # the per-user fallback repoints secret_dir; re-deriving soc_env must follow it
    user_secret = str(tmp_path / "soc-display" / "secret")
    p2 = dict(model.paths)
    p2["secret_dir"] = user_secret
    model.paths = p2
    assert model.soc_env()["SOC_SECRET_DIR"] == user_secret
    assert "SOC_VAULT_PASSWORD" not in setup.render_soc_env(model.soc_env())


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


# --------------------------------------------------------------------------- #
# Multi-VPN: the wizard/CLI vpns[] LIST (config + GUI normalize must agree)
# --------------------------------------------------------------------------- #
def test_gui_normalize_legacy_single_vpn():
    """A legacy `vpn: {}` (single dict) normalizes to a one-entry vpns[] with a
    stable default name, and the back-compat `vpn` mirror tracks vpns[0]."""
    setup = setupgui._load_setup()
    n = setupgui.normalize_cfg(
        {"vpn": {"enabled": True, "type": "wireguard", "config": "/x.conf"}}, setup)
    assert [v["name"] for v in n["vpns"]] == ["vpn"]
    assert n["vpns"][0]["type"] == "wireguard"
    assert n["vpn"]["type"] == "wireguard"   # back-compat mirror


def test_gui_normalize_vpns_list_and_vpnless():
    setup = setupgui._load_setup()
    n = setupgui.normalize_cfg({"vpns": [
        {"name": "corp", "enabled": True, "type": "fortinet"},
        {"enabled": True, "type": "wireguard", "config": "/lab.conf"},
    ]}, setup)
    # names: explicit kept; unnamed second gets a deterministic fill
    assert [v["name"] for v in n["vpns"]] == ["corp", "vpn2"]
    # vpn-less stays vpn-less
    n2 = setupgui.normalize_cfg({}, setup)
    assert n2["vpns"] == []
    assert n2["vpn"] == {"enabled": False}


def test_gui_def_vpn_unique_names():
    a, b = setupgui._def_vpn(0), setupgui._def_vpn(1)
    assert a["name"] == "vpn" and b["name"] == "vpn2"
    assert a["enabled"] is False and a["default_route"] is False


def test_model_multi_vpn_round_trips_and_validates(tmp_path):
    """A multi-VPN cfg renders to vpns:[] YAML and re-parses to N entries; a single
    plain VPN stays a byte-stable `vpn:` block."""
    setup = setupgui._load_setup()
    model = setupgui.WizardModel(setup, setup.resolve_paths("dev"))
    cfg = model.cfg()
    cfg["vpns"] = [
        {"name": "corp", "enabled": True, "type": "fortinet", "gateway": "g.example.com",
         "port": 443, "vault_item": "Corp VPN", "trusted_cert": "", "realm": "",
         "set_routes": True, "set_dns": False, "half_internet_routes": False,
         "persistent": 0, "otp_from_vault": False, "default_route": True},
        {"name": "lab", "enabled": True, "type": "wireguard", "config": "/etc/wireguard/lab.conf"},
        {"name": "dc", "enabled": True, "type": "openvpn", "config": "/etc/openvpn/dc.ovpn",
         "vault_item": "DC VPN", "set_routes": True},
    ]
    model.set_cfg(cfg)
    assert model.validate() == []
    y = model.panels_yaml()
    assert "vpns:" in y and "\nvpn:\n" not in y
    conf = config.load_str(y)
    assert [v.get("name") for v in conf.vpns] == ["corp", "lab", "dc"]
    assert [v.get("name") for v in conf.vpns if v.get("default_route")] == ["corp"]


def test_model_rejects_duplicate_names_and_two_default_routes():
    setup = setupgui._load_setup()
    model = setupgui.WizardModel(setup, setup.resolve_paths("dev"))
    cfg = model.cfg()
    cfg["vpns"] = [
        {"name": "dup", "enabled": True, "type": "wireguard", "config": "/a.conf",
         "default_route": True},
        {"name": "dup", "enabled": True, "type": "wireguard", "config": "/b.conf",
         "default_route": True},
    ]
    model.set_cfg(cfg)
    problems = "\n".join(model.validate())
    assert "duplicate" in problems
    assert "at most one" in problems
