"""Unit tests for the pure-Python parts of the kiosk host (no GTK/display)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from host import config, inject, vault  # noqa: E402


DEV_YAML = """
display: {auto: false, width: 1920, height: 1080, cols: 2, rows: 2, gap: 0}
panels:
  - id: p1
    engine: webkit
    grid: [0, 0]
    mode: direct
    url: "http://10.0.0.1:3000/login"
    vault_item: "Item 1"
    selectors: {user: "#u", pass: "input[name=\\"pw\\"]", submit: ".go"}
    login_marker: "#u"
    keepalive: {strategy: reload, intervalSec: 42}
  - id: p2
    engine: chromium
    grid: [1, 1]
    mode: tunnel
    tunnel: {local_port: 19103, remote_host: 10.20.0.7, remote_port: 8443}
    path: "/app"
    scheme: "http"
    vault_item: "Item 2"
    selectors: {user: "#u", pass: "#p", submit: "#s"}
    keepalive: {strategy: none}
tunnel: {enabled: true, jump_host: "u@jump", identity: "/k"}
"""


def _load():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(DEV_YAML)
        path = fh.name
    return config.load(path)


def test_geometry_2x2():
    conf = _load()
    g = {p.id: p.geometry for p in conf.panels}
    assert (g["p1"].w, g["p1"].h) == (960, 540)
    assert (g["p1"].x, g["p1"].y) == (0, 0)
    assert (g["p2"].x, g["p2"].y) == (960, 540)


def test_effective_url():
    conf = _load()
    p = {x.id: x for x in conf.panels}
    assert p["p1"].effective_url == "http://10.0.0.1:3000/login"
    assert p["p2"].effective_url == "http://127.0.0.1:19103/app"
    assert p["p2"].tunnel_local_port == 19103
    assert p["p1"].wmclass == "soc-p1"


def test_inject_substitution_and_escaping():
    conf = _load()
    p1 = conf.panels[0]
    js = inject.bootstrap_js(p1, mode="webkit")
    for tok in ("{{PANEL_ID}}", "{{USER_SEL}}", "{{PASS_SEL}}", "{{SUBMIT_SEL}}",
                "{{LOGIN_MARKER}}", "{{MODE}}", "{{KEEPALIVE_JSON}}"):
        assert tok not in js                          # every placeholder filled
    assert '"p1"' in js
    assert '"reload"' in js and "42" in js
    # a selector containing a double quote must be JSON-escaped, not raw
    assert 'input[name=\\"pw\\"]' in js

    call = inject.login_call({"user": 'a"b', "pass": "p\\x"})
    assert '\\"' in call                               # quote escaped
    assert "socLogin(" in call


def test_vault_dev_backend(monkeypatch):
    data = {"Item 1": {"username": "u1", "password": "s3cr3t"}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        path = fh.name
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    monkeypatch.setenv("SOC_DEV_VAULT", path)
    v = vault.Vault()
    v.open()
    c = v.creds("Item 1")
    assert c == {"user": "u1", "pass": "s3cr3t"}
    # caching: second call returns same without error
    assert v.creds("Item 1")["pass"] == "s3cr3t"


def test_vault_dev_missing_item(monkeypatch):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({}, fh)
        path = fh.name
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    monkeypatch.setenv("SOC_DEV_VAULT", path)
    v = vault.Vault()
    v.open()
    try:
        v.creds("nope")
        assert False, "expected VaultError"
    except vault.VaultError:
        pass
