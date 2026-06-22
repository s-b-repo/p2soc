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
    fake = dict(mode="dev", soc_env=str(soc_env), secret_dir=str(secret),
                pinentry="x", default_backend="rbw", config_vault_item="SOC Wall Config")
    monkeypatch.setattr(m, "resolve_paths", lambda t: fake)
    monkeypatch.setattr(m, "ask_secret", lambda *a, **k: "M-pw")
    monkeypatch.setattr(m, "ask", lambda *a, **k: "")          # blank PIN -> generate
    monkeypatch.setattr(m, "ask_bool", lambda *a, **k: True)
    monkeypatch.setattr(m, "_readline", lambda *a, **k: "")
    monkeypatch.setattr(m, "_have", lambda b: False)           # skip rbw config

    class A:
        target = "dev"; dry_run = False; defaults = False; section = "all"; clean = False

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


def _deploy_paths(m, tmp_path, backend="dev", stamped=False):
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
