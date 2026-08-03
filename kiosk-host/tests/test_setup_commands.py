"""Unit tests for setup.py commands: first-run (seal), clean, env render."""
import importlib.util
import os

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _setup():
    spec = importlib.util.spec_from_file_location(
        "soc_setup_cmds", os.path.join(_REPO, "setup.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_render_soc_env_no_secret():
    m = _setup()
    keys = ("SOC_VAULT_BACKEND", "SOC_VAULT_EMAIL", "SOC_VAULT_URL", "SOC_ROOT",
            "SOC_PANELS_FILE", "SOC_INJECT_TMPL", "SOC_LAUNCH_STAGGER",
            "SOC_READY_TIMEOUT", "SOC_CDP_BASE_PORT", "SOC_CRED_TTL", "SOC_VPN_DRY_RUN")
    out = m.render_soc_env({k: "" for k in keys})
    assert "SOC_VAULT_PASSWORD" not in out
    assert "SOC_PINENTRY" not in out
    assert "SOC_SECRET_DIR" in out
    assert "SOC_CONFIG_VAULT_ITEM" in out


def test_cmd_firstrun_seals(tmp_path, monkeypatch):
    m = _setup()
    from host import secretstore
    monkeypatch.setenv("SOC_MACHINE_ID", "test-host")
    soc_env = tmp_path / "soc.env"
    soc_env.write_text("SOC_VAULT_BACKEND=rbw\nSOC_VAULT_EMAIL=k@s.local\n"
                       "SOC_VAULT_URL=http://127.0.0.1:8222\n")
    secret = tmp_path / "secret"
    fake = dict(mode="pi", soc_env=str(soc_env), secret_dir=str(secret),
                pinentry="x", default_backend="rbw", config_vault_item="SOC Wall Config")
    monkeypatch.setattr(m, "resolve_paths", lambda t: fake)
    monkeypatch.setattr(m, "ask_secret", lambda *a, **k: "M-pw")
    monkeypatch.setattr(m, "ask", lambda *a, **k: "")          # blank PIN -> generate
    monkeypatch.setattr(m, "ask_bool", lambda *a, **k: True)
    monkeypatch.setattr(m, "_readline", lambda *a, **k: "")
    monkeypatch.setattr(m, "_have", lambda b: False)           # skip rbw config

    class A:
        target = "pi"; dry_run = False; defaults = False; section = "all"; clean = False

    assert m.cmd_firstrun(A()) == 0
    assert secretstore.is_sealed(str(secret))
    assert secretstore.unseal(str(secret)) == "M-pw"


def test_clean_state_removes(tmp_path, monkeypatch):
    m = _setup()
    f = tmp_path / "panels.yaml"; f.write_text("x")
    env = tmp_path / "soc.env"; env.write_text("y")
    vw = tmp_path / "vw.env"; vw.write_text("z")
    secret = tmp_path / "secret"; secret.mkdir()
    state = tmp_path / "state"; state.mkdir()
    monkeypatch.setenv("SOC_STATE_DIR", str(state))
    paths = dict(mode="pi", panels_out=str(f), soc_env=str(env), vw_env=str(vw),
                 secret_dir=str(secret))
    monkeypatch.setattr(m, "ask_bool", lambda *a, **k: True)

    class A:
        dry_run = False

    m.clean_state(paths, A())
    assert not f.exists()
    assert not env.exists()
    assert not secret.exists()
    assert not state.exists()


def _deploy_paths(m, tmp_path, backend="rbw", stamped=False):
    soc_env = tmp_path / "soc.env"
    soc_env.write_text(f"SOC_VAULT_BACKEND={backend}\n")
    if stamped:
        (tmp_path / ".installed").write_text("installed")
    return dict(mode="pi", soc_env=str(soc_env), soc_root="/nonexistent",
                panels_installed=str(tmp_path / "none.yaml"), vw_env=str(tmp_path / "vw"),
                secret_dir=str(tmp_path / "secret"), default_backend=backend,
                config_vault_item="X")


def _install_calls(calls):
    return [c for c in calls if any("install.sh" in str(x) for x in c)]


def test_deploy_skips_install_when_stamped(tmp_path, monkeypatch):
    m = _setup()
    calls = []
    monkeypatch.setattr(m, "_run", lambda cmd, **k: (calls.append(cmd) or 0))
    monkeypatch.setattr(m, "cmd_doctor", lambda a: 0)
    monkeypatch.setattr(m, "ask_bool", lambda prompt, default=False, **k: False)
    monkeypatch.setattr(m, "resolve_paths", lambda t: _deploy_paths(m, tmp_path, stamped=True))

    class A:
        target = "pi"; dry_run = False; defaults = False; section = "all"
        clean = False; fresh = False

    m.cmd_deploy(A())
    assert _install_calls(calls) == []          # skipped: fast path


def test_deploy_fresh_forces_install(tmp_path, monkeypatch):
    m = _setup()
    calls = []
    monkeypatch.setattr(m, "_run", lambda cmd, **k: (calls.append(cmd) or 0))
    monkeypatch.setattr(m, "cmd_doctor", lambda a: 0)
    monkeypatch.setattr(m, "ask_bool", lambda prompt, default=False, **k: False)
    monkeypatch.setattr(m, "resolve_paths", lambda t: _deploy_paths(m, tmp_path, stamped=True))

    class A:
        target = "pi"; dry_run = False; defaults = False; section = "all"
        clean = False; fresh = True

    m.cmd_deploy(A())
    ic = _install_calls(calls)
    assert ic and any("--fresh" in str(x) for x in ic[0])


_WALL_ENV = {
    "SOC_VAULT_BACKEND": "rbw", "SOC_VAULT_EMAIL": "k@soc.local",
    "SOC_VAULT_URL": "http://127.0.0.1:8222",
    "SOC_SECRET_DIR": "/etc/soc-display/secret",
    "SOC_CONFIG_VAULT_ITEM": "SOC Wall Config", "SOC_ROOT": "/opt/soc-display",
    "SOC_PANELS_FILE": "/etc/soc-display/panels.yaml",
    "SOC_INJECT_TMPL": "/opt/soc-display/inject/login.js.tmpl",
    "SOC_LAUNCH_STAGGER": "1.5", "SOC_READY_TIMEOUT": "120",
    "SOC_CDP_BASE_PORT": "9222", "SOC_CRED_TTL": "30", "SOC_VPN_DRY_RUN": "0",
    "SOC_SESSION": "auto",
}


def test_render_wall_unit_no_secret_and_supervised():
    m = _setup()
    unit = m.render_wall_unit(_WALL_ENV, user="soc", soc_root="/opt/soc-display")
    assert "SOC_VAULT_PASSWORD" not in unit          # the master is never baked in
    assert "Restart=always" in unit                  # supervised (compositor recovers)
    assert "Environment=SOC_VAULT_EMAIL=k@soc.local" in unit
    # a value with spaces must be quoted as a whole assignment for systemd
    assert 'Environment="SOC_CONFIG_VAULT_ITEM=SOC Wall Config"' in unit
    assert "ExecStart=/opt/soc-display/scripts/start-session.sh" in unit
    # PERF-1: soft reclaim cap, NO hard MemoryMax (it would bounce the whole
    # session before the in-host watchdog can recycle a single panel).
    assert "MemoryHigh=80%" in unit
    assert "MemoryMax=" not in unit                  # no hard cap directive
    assert "Environment=SOC_MEM_MIN_AVAIL_MB=150" in unit
    # SEC-11 defense-in-depth knobs present
    assert "ProtectClock=yes" in unit and "LockPersonality=yes" in unit
    # SEC-7: physical-access config surface locked down by default
    assert "Environment=SOC_ONSCREEN_CONFIG=0" in unit
    assert "Environment=SOC_CONFIG_REQUIRE_PIN=1" in unit


def test_wall_unit_env_roundtrip(tmp_path):
    m = _setup()
    p = tmp_path / "soc-wall.service"
    p.write_text(m.render_wall_unit(_WALL_ENV))
    back = m.load_unit_env(str(p))
    for k, v in _WALL_ENV.items():
        assert back[k] == v


# --- screen presets (section_display) ---------------------------------------
def test_section_display_auto_is_default():
    m = _setup()
    m.ASSUME_DEFAULTS = True                       # accept every default
    d = m.section_display(None)
    assert d["auto"] is True                       # auto-detect at launch
    assert (d["width"], d["height"]) == (1920, 1080)
    assert d["cols"] == 2 and d["rows"] == 2 and d["layout"] == "auto"


def test_section_display_preset_sets_fixed_size(monkeypatch):
    m = _setup()
    # screen=#3 (2560x1440), then blank cols/rows/gap/layout -> defaults
    answers = iter(["3", "", "", "", ""])
    monkeypatch.setattr(m, "_readline", lambda *a, **k: next(answers))
    d = m.section_display(None)
    assert d["auto"] is False
    assert (d["width"], d["height"]) == (2560, 1440)


def test_section_display_custom_size(monkeypatch):
    m = _setup()
    # screen=#6 (custom), width, height, then blank cols/rows/gap/layout
    answers = iter(["6", "3000", "2000", "", "", "", ""])
    monkeypatch.setattr(m, "_readline", lambda *a, **k: next(answers))
    d = m.section_display(None)
    assert d["auto"] is False
    assert (d["width"], d["height"]) == (3000, 2000)


# --- the "configured once" marker -------------------------------------------
def test_marker_roundtrip(tmp_path):
    m = _setup()
    paths = {"configured_marker": str(tmp_path / ".configured")}
    assert m.is_configured(paths) is False
    m.mark_configured(paths, dry=True)             # dry-run writes nothing
    assert m.is_configured(paths) is False
    m.mark_configured(paths)
    assert m.is_configured(paths) is True


def _firstboot_paths(tmp_path, sealed):
    """A resolve_paths() stand-in for cmd_firstboot tests (rbw backend)."""
    soc_env = tmp_path / "soc.env"
    soc_env.write_text("SOC_VAULT_BACKEND=rbw\n")
    return dict(mode="pi", soc_env=str(soc_env), panels_installed=str(tmp_path / "p.yaml"),
                secret_dir=str(tmp_path / "secret"), default_backend="rbw",
                configured_marker=str(tmp_path / ".configured"), config_vault_item="X")


def _wire_firstboot(m, monkeypatch, paths, calls):
    monkeypatch.setattr(m, "resolve_paths", lambda t=None: paths)
    monkeypatch.setattr(m.os, "geteuid", lambda: 0)        # firstboot needs root
    monkeypatch.setattr(m, "cmd_wizard", lambda a: 0)
    monkeypatch.setattr(m, "load_yaml", lambda p: {"panels": []})
    monkeypatch.setattr(m, "cmd_firstrun",
                        lambda a: calls.__setitem__("firstrun", calls.get("firstrun", 0) + 1) or 0)
    monkeypatch.setattr(m, "push_config_to_vault", lambda *a, **k: False)
    monkeypatch.setattr(m, "store_credentials", lambda *a, **k: None)
    monkeypatch.setattr(m, "ask_bool", lambda *a, **k: True)


class _FbArgs:
    target = "pi"; dry_run = False; defaults = False; section = "all"; clean = False


def test_firstboot_skips_seal_when_already_sealed(tmp_path, monkeypatch):
    m = _setup()
    from host import secretstore
    monkeypatch.setenv("SOC_MACHINE_ID", "test-host")
    paths = _firstboot_paths(tmp_path, sealed=True)
    secretstore.seal("Master-pw", "654321", paths["secret_dir"])   # pre-seal
    calls = {}
    _wire_firstboot(m, monkeypatch, paths, calls)
    assert m.cmd_firstboot(_FbArgs()) == 0
    assert calls.get("firstrun", 0) == 0           # already sealed -> no re-seal
    assert m.is_configured(paths)                  # marker written


def test_firstboot_seals_when_unsealed(tmp_path, monkeypatch):
    m = _setup()
    monkeypatch.setenv("SOC_MACHINE_ID", "test-host")
    paths = _firstboot_paths(tmp_path, sealed=False)
    calls = {}
    _wire_firstboot(m, monkeypatch, paths, calls)
    assert m.cmd_firstboot(_FbArgs()) == 0
    assert calls.get("firstrun", 0) == 1           # not sealed -> seal once
    assert m.is_configured(paths)


def test_n_url_defaults_scheme_for_bare_host():
    """Operators may type a bare host or host/path at URL prompts; n_url should
    default it to http:// while leaving already-schemed URLs untouched."""
    m = _setup()
    assert m.n_url("10.14.0.2") == "http://10.14.0.2"
    assert m.n_url("10.14.0.2/zabbix/index.php") == "http://10.14.0.2/zabbix/index.php"
    assert m.n_url("127.0.0.1:8222") == "http://127.0.0.1:8222"
    assert m.n_url("http://already/login") == "http://already/login"
    assert m.n_url("https://host:443/login") == "https://host:443/login"


def test_normalized_bare_host_passes_url_validation():
    """The normalize+validate pipeline used by ask(): a bare host is accepted,
    but normalization never bypasses the validator (bad port / scheme rejected)."""
    m = _setup()
    assert m.v_url(m.n_url("10.14.0.2/zabbix/index.php")) is None
    assert m.v_url(m.n_url("127.0.0.1:8222")) is None
    assert m.v_url(m.n_url("host:99999")) is not None       # bad port still caught
    assert m.v_url(m.n_url("ftp://nope")) is not None       # wrong scheme still caught


# --------------------------------------------------------------------------- #
# Login-form auto-detection (parse_login_html — pure, no network)
# --------------------------------------------------------------------------- #
_ZABBIX_HTML = """<html><head><title>Zabbix</title></head><body>
<form action="index.php" method="post">
  <input type="text" name="name" id="name" autofocus>
  <input type="password" name="password" id="password">
  <button type="submit" id="enter">Sign in</button>
</form></body></html>"""

_GRAFANA_SPA = """<html><head><title>Grafana</title></head><body>
<div id="reactRoot"></div><script>window.grafanaBootData={};</script></body></html>"""


def test_detect_zabbix_form_selectors():
    """Server-rendered Zabbix login -> real DOM selectors, not credentials."""
    m = _setup()
    r = m.parse_login_html(_ZABBIX_HTML, "http://10.14.0.2/zabbix/index.php")
    assert r["kind"] == "form" and r["product"] == "Zabbix"
    assert r["user"] == "#name"
    assert r["pass"] == "#password"
    assert r["submit"] == "#enter"
    assert r["login_marker"] == "#password"      # marker defaults to the pass field


def test_detect_selector_priority_and_blank_submit():
    """Selector derivation prefers id>name>type; a form with no submit button
    yields a blank submit (login.js then submits natively == press Enter)."""
    m = _setup()
    named = m.parse_login_html(
        '<form><input type="text" name="user">'
        '<input type="password" name="pass">'
        '<input type="submit" value="Go"></form>')
    assert named["user"] == 'input[name="user"]'
    assert named["pass"] == 'input[name="pass"]'
    assert named["submit"] == 'input[type="submit"]'

    nosub = m.parse_login_html('<form><input type="text" id="u">'
                               '<input type="password" id="p"></form>')
    assert nosub["submit"] == ""                 # -> press Enter


def test_detect_spa_falls_back_to_product_preset():
    """A JS-rendered (SPA) login has no form in static HTML, so detection
    fingerprints the product and supplies its known selector preset."""
    m = _setup()
    r = m.parse_login_html(_GRAFANA_SPA, "http://grafana.local/login")
    assert r["kind"] == "spa" and r["product"] == "Grafana"
    assert r["pass"] == 'input[name="password"]'
    assert r["login_marker"] == r["pass"]


def test_detect_unknown_page_returns_no_selectors():
    """No form, no fingerprint -> empty suggestion (wizard falls back to help)."""
    m = _setup()
    r = m.parse_login_html("<html><body><p>nothing here</p></body></html>", "http://x/")
    assert r["kind"] == "unknown"
    assert r["user"] == "" and r["pass"] == "" and r["product"] is None


def test_detect_fingerprint_from_url_path_only():
    """Even with no HTML (unreachable host), the URL path can identify a product
    so the wizard can still suggest a preset."""
    m = _setup()
    name, preset = m._match_product("", "", "/zabbix/index.php")
    assert name == "Zabbix" and preset["pass"] == "#password"
