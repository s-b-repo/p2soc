"""Phase 8: click-zone calibrate mode for login fallback.

Tests cover:
  * Panel.login_zones schema acceptance + validation rejection.
  * inject.bootstrap_js renders the {{LOGIN_ZONES_JSON}} placeholder
    cleanly (valid zones in, invalid zones filtered out).
  * The calibrate.js.tmpl ships intact with the three expected steps.
  * Round-trip persistence via Config.to_yaml + reload.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import config, inject                        # noqa: E402


# --- schema acceptance / rejection ---------------------------------------- #


_PANEL_HEADER = textwrap.dedent("""\
    panels:
      - id: p1
        engine: webkit
        grid: [0, 0]
        mode: direct
        url: https://example.test/login
        vault_item: zabbix
        selectors:
          user: "#user"
          pass: "#pass"
          submit: "#submit"
        login_marker: "#user"
""")


def _yaml_with_zones(zones_dict):
    """Helper: a minimal panels.yaml exercising login_zones on p1. `zones_dict`
    is a Python dict; we serialise via PyYAML so indentation can never drift."""
    import yaml
    panels = yaml.safe_load(_PANEL_HEADER)["panels"]
    panels[0]["login_zones"] = zones_dict
    return yaml.safe_dump({"panels": panels}, sort_keys=False)


def _load(yaml_text):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml",
                                     delete=False) as fh:
        fh.write(yaml_text)
        path = fh.name
    try:
        return config.load(path)
    finally:
        os.unlink(path)


def test_login_zones_valid_ratios_load_cleanly():
    conf = _load(_yaml_with_zones({
        "user":   {"x_pct": 0.5,  "y_pct": 0.25},
        "pass":   {"x_pct": 0.5,  "y_pct": 0.40},
        "submit": {"x_pct": 0.55, "y_pct": 0.60},
    }))
    p = conf.panels[0]
    assert p.login_zones["user"] == {"x_pct": 0.5, "y_pct": 0.25}
    assert p.login_zones["pass"]["y_pct"] == 0.40
    assert p.login_zones["submit"]["x_pct"] == 0.55


def test_login_zones_missing_is_ok_default_empty():
    """A panel without login_zones loads with the empty-dict default."""
    yaml = textwrap.dedent("""
        panels:
          - id: p1
            engine: webkit
            grid: [0, 0]
            mode: direct
            url: https://example.test/login
            vault_item: zabbix
            selectors: {user: "#u", pass: "#p", submit: "#s"}
            login_marker: "#u"
    """)
    conf = _load(yaml)
    assert conf.panels[0].login_zones == {}


def test_login_zones_x_pct_out_of_range_rejected():
    with pytest.raises(config.ConfigError) as ei:
        _load(_yaml_with_zones({"user": {"x_pct": 1.5, "y_pct": 0.5}}))
    assert "0.0..1.0" in str(ei.value)


def test_login_zones_unknown_key_rejected():
    with pytest.raises(config.ConfigError) as ei:
        _load(_yaml_with_zones({"hackme": {"x_pct": 0.5, "y_pct": 0.5}}))
    assert "login_zones" in str(ei.value)


def test_login_zones_missing_axis_rejected():
    with pytest.raises(config.ConfigError) as ei:
        _load(_yaml_with_zones({"user": {"x_pct": 0.5}}))
    assert "y_pct" in str(ei.value)


# --- inject.bootstrap_js renders {{LOGIN_ZONES_JSON}} -------------------- #


class _StubKeepAlive:
    strategy = "none"; intervalSec = 600; url = None; target = None


class _StubPanel:
    id = "p1"
    selectors = {"user": "#u", "pass": "#p", "submit": "#s"}
    login_marker = "#u"
    keepalive = _StubKeepAlive()
    login_zones = {}


def test_inject_zones_present_when_calibrated():
    p = _StubPanel()
    p.login_zones = {"user": {"x_pct": 0.4, "y_pct": 0.3},
                     "submit": {"x_pct": 0.7, "y_pct": 0.8}}
    js = inject.bootstrap_js(p, "webkit")
    # The placeholder must have been substituted away.
    assert "{{LOGIN_ZONES_JSON}}" not in js
    # And the rendered JSON must round-trip with our exact ratios.
    start = js.index("loginZones:") + len("loginZones:")
    chunk = js[start:start + 200]
    # Strip everything from the opening { to its matching close brace by
    # counting depth (the chunk is short + has a trailing comma after the
    # object — keeps the parse simple without pulling a JSON tokeniser).
    open_i = chunk.index("{")
    depth = 0
    end_i = None
    for i in range(open_i, len(chunk)):
        if chunk[i] == "{": depth += 1
        elif chunk[i] == "}":
            depth -= 1
            if depth == 0:
                end_i = i + 1
                break
    assert end_i is not None
    parsed = json.loads(chunk[open_i:end_i])
    assert parsed["user"] == {"x_pct": 0.4, "y_pct": 0.3}
    assert parsed["submit"] == {"x_pct": 0.7, "y_pct": 0.8}


def test_inject_zones_empty_when_uncalibrated():
    p = _StubPanel()
    p.login_zones = {}
    js = inject.bootstrap_js(p, "webkit")
    assert "loginZones: {}" in js


def test_inject_zones_filters_malformed_entries():
    """Hand-edited YAML could still slip past at runtime (e.g. someone
    mutates .login_zones in-process). inject.bootstrap_js must defensively
    drop anything with non-numeric or out-of-range ratios so the rendered
    JS doesn't carry junk that confuses zoneInput()."""
    p = _StubPanel()
    p.login_zones = {
        "user":   {"x_pct": 0.5, "y_pct": 0.5},
        "pass":   {"x_pct": "nope", "y_pct": 0.5},          # bad type
        "submit": {"x_pct": 1.5, "y_pct": 0.5},             # out of range
    }
    js = inject.bootstrap_js(p, "webkit")
    # user (valid) survived; pass + submit (invalid) were dropped.
    assert '"user"' in js[js.index("loginZones:"):]
    assert '"pass"' not in js[js.index("loginZones:"):js.index("loginZones:")+200]
    assert '"submit"' not in js[js.index("loginZones:"):js.index("loginZones:")+200]


# --- calibrate.js.tmpl ships ---------------------------------------------- #


def test_calibrate_template_ships_with_three_steps():
    """Sanity-check the template file shipped alongside login.js.tmpl."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "inject",
                        "calibrate.js.tmpl")
    src = open(path, encoding="utf-8").read()
    # The three click steps the operator walks through.
    assert '"user"' in src
    assert '"pass"' in src
    assert '"submit"' in src
    # Stuffs result into the agreed-upon global so the host can poll it.
    assert "__SOC_CALIBRATE_RESULT" in src
    # Esc cancels.
    assert "Escape" in src
    # Crosshair cursor for the affordance.
    assert "cursor:crosshair" in src


# --- to_yaml round-trip --------------------------------------------------- #


def test_login_zones_roundtrip_through_to_yaml():
    conf = _load(_yaml_with_zones({
        "user": {"x_pct": 0.3, "y_pct": 0.4},
        "pass": {"x_pct": 0.3, "y_pct": 0.5},
    }))
    text = config.to_yaml(conf)
    re = _load(text)
    assert re.panels[0].login_zones["user"] == {"x_pct": 0.3, "y_pct": 0.4}
    assert re.panels[0].login_zones["pass"] == {"x_pct": 0.3, "y_pct": 0.5}
    assert "submit" not in re.panels[0].login_zones
