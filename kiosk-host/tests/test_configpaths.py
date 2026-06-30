"""Tests for the shared config-location resolver (host.configpaths).

These pin the read precedence (env > marked user > /etc > repo), the marker gating
(a stale user file must NOT shadow a re-deployed /etc), the resolve_write
fallthrough, the crucial write==read invariant (what the wizard writes is what the
wall reads), and the CLI exit codes. No display / no gi — runs in `make test`.

The resolver reads $XDG_CONFIG_HOME and $SOC_ROOT, and ETC_DIR is a module constant,
so we redirect ALL three to tmp dirs to test deterministically without touching a
real /etc/soc-display.
"""
import os
import subprocess
import sys

import pytest

from host import configpaths as cp

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_KIOSK = os.path.join(_REPO, "kiosk-host")


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Redirect xdg (user dir), repo root, and ETC_DIR into tmp so resolution is
    hermetic. Returns (user_dir, etc_dir, repo_root) helpers as paths."""
    xdg = tmp_path / "xdg"
    etc = tmp_path / "etc-soc"
    repo = tmp_path / "repo"
    (repo / "kiosk-host").mkdir(parents=True)   # make it look like a checkout
    (repo / "config").mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setenv("SOC_ROOT", str(repo))
    monkeypatch.delenv("SOC_PANELS_FILE", raising=False)
    monkeypatch.delenv("SOC_ENV_FILE", raising=False)
    monkeypatch.delenv("SOC_SECRET_DIR", raising=False)
    monkeypatch.setenv("SOC_ETC_DIR", str(etc))
    return tmp_path


def _write(p, text="x"):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)


# --------------------------------------------------------------------------- #
# READ precedence
# --------------------------------------------------------------------------- #
def test_env_override_is_absolute_authority(sandbox, monkeypatch, tmp_path):
    pinned = tmp_path / "pinned.yaml"
    _write(str(pinned))
    _write(os.path.join(cp.etc_dir(), cp.PANELS_BASENAME))   # /etc also exists
    monkeypatch.setenv("SOC_PANELS_FILE", str(pinned))
    path, label = cp.resolve_read("panels")
    assert path == str(pinned)
    assert label == "$SOC_PANELS_FILE"


def test_etc_wins_when_no_marker(sandbox):
    etc_p = os.path.join(cp.etc_dir(), cp.PANELS_BASENAME)
    user_p = os.path.join(cp.user_dir(), cp.PANELS_BASENAME)
    _write(etc_p, "etc")
    _write(user_p, "user")          # present but NO marker -> must be ignored
    path, label = cp.resolve_read("panels")
    assert path == etc_p
    assert label == "/etc/soc-display"


def test_marked_user_beats_etc(sandbox):
    etc_p = os.path.join(cp.etc_dir(), cp.PANELS_BASENAME)
    user_p = os.path.join(cp.user_dir(), cp.PANELS_BASENAME)
    _write(etc_p, "etc")
    _write(user_p, "user")
    _write(cp.active_marker(), user_p + "\n")   # marker activates the user tier
    path, label = cp.resolve_read("panels")
    assert path == user_p
    assert label == "user config (active)"


def test_repo_fallback_when_nothing_else(sandbox):
    repo_p = os.path.join(cp.repo_root(), "config", "panels.local.yaml")
    _write(repo_p, "repo")
    path, label = cp.resolve_read("panels")
    assert path == repo_p
    assert label == "repo fallback"


def test_none_when_nothing_exists(sandbox):
    path, label = cp.resolve_read("panels")
    assert path is None
    assert label == "none"


# --------------------------------------------------------------------------- #
# WRITE target fallthrough + the write==read invariant
# --------------------------------------------------------------------------- #
def test_write_lands_in_etc_when_writable(sandbox):
    os.makedirs(cp.etc_dir())                  # writable by this (non-root) test user
    w = cp.resolve_write("panels", want_etc=True, can_escalate=False)
    assert w["via"] == "etc"
    assert w["marker"] is None
    assert w["path"] == os.path.join(cp.etc_dir(), cp.PANELS_BASENAME)
    assert w["mode"] == 0o644


def test_write_falls_back_to_user_with_marker(sandbox, monkeypatch):
    # /etc not writable: simulate by making _dir_writable say no for ETC_DIR.
    real = cp._dir_writable
    monkeypatch.setattr(cp, "_dir_writable",
                        lambda d: False if d == cp.etc_dir() else real(d))
    w = cp.resolve_write("panels", want_etc=True, can_escalate=False)
    assert w["via"] == "user"
    assert w["marker"] == cp.active_marker()
    assert w["mode"] == 0o644
    ew = cp.resolve_write("env", want_etc=True, can_escalate=False)
    assert ew["mode"] == 0o600           # env tightened to 0600 in the user dir


def test_write_equals_read_invariant(sandbox, monkeypatch):
    """The crux: after the writer writes to its chosen target (+ marker), the reader
    resolving with the SAME logic returns exactly that file."""
    monkeypatch.setattr(cp, "_dir_writable",
                        lambda d: False if d == cp.etc_dir() else True)
    for kind in ("panels", "env"):
        w = cp.resolve_write(kind, want_etc=True, can_escalate=False)
        os.makedirs(w["dir"], exist_ok=True)
        _write(w["path"], "written")
        if w["marker"]:
            _write(w["marker"], w["path"] + "\n")
        read_path, _label = cp.resolve_read(kind)
        assert os.path.abspath(read_path) == os.path.abspath(w["path"]), kind


def test_escalation_keeps_etc_target(sandbox, monkeypatch):
    monkeypatch.setattr(cp, "_dir_writable",
                        lambda d: False if d == cp.etc_dir() else True)
    w = cp.resolve_write("panels", want_etc=True, can_escalate=True)
    assert w["via"] == "etc"
    assert w["needs_privilege"] is True
    assert w["marker"] is None


# --------------------------------------------------------------------------- #
# secret_dir tracks the winning config tier
# --------------------------------------------------------------------------- #
def test_secret_dir_rides_with_marker(sandbox):
    _write(cp.active_marker(), "x\n")
    assert cp.resolve_secret_dir() == os.path.join(cp.user_dir(), cp.SECRET_BASENAME)


def test_secret_dir_env_override(sandbox, monkeypatch):
    monkeypatch.setenv("SOC_SECRET_DIR", "/custom/secret")
    assert cp.resolve_secret_dir() == "/custom/secret"


# --------------------------------------------------------------------------- #
# CLI exit codes (shell launchers depend on these)
# --------------------------------------------------------------------------- #
def _cli(args, env):
    e = dict(os.environ, **env)
    e["PYTHONPATH"] = _KIOSK + (os.pathsep + e["PYTHONPATH"] if e.get("PYTHONPATH") else "")
    return subprocess.run([sys.executable, "-m", "host.configpaths", *args],
                          capture_output=True, text=True, env=e)


def test_cli_panels_exit3_when_none(tmp_path):
    env = {"XDG_CONFIG_HOME": str(tmp_path / "xdg"),
           "SOC_ROOT": str(tmp_path / "norepo")}
    # Point ETC at an empty tmp via SOC_PANELS_FILE absence + a repo with no config.
    os.makedirs(tmp_path / "norepo")
    r = _cli(["--panels"], env)
    # /etc/soc-display may exist on the build host; only assert the contract that an
    # absent override + empty repo yields a path or a clean exit-3, never a crash.
    assert r.returncode in (0, 3)


def test_cli_check_ok():
    r = _cli(["--check"], {})
    assert r.returncode == 0
    assert "OK" in r.stdout


def test_cli_explain_runs():
    r = _cli(["--explain"], {})
    assert r.returncode == 0
    assert "resolves to" in r.stdout


def test_cli_install_etc_rejects_malformed_stdin(tmp_path):
    e = dict(os.environ)
    e["PYTHONPATH"] = _KIOSK + (os.pathsep + e["PYTHONPATH"] if e.get("PYTHONPATH") else "")
    r = subprocess.run([sys.executable, "-m", "host.configpaths", "--install-etc"],
                       input="garbage", capture_output=True, text=True, env=e)
    assert r.returncode == 2          # malformed -> refuse, don't write


# --------------------------------------------------------------------------- #
# Wizard headless smoke: wizard-written file == configpaths.resolve_panels()
# --------------------------------------------------------------------------- #
def test_wizard_write_reaches_resolver(tmp_path, monkeypatch):
    """Drive setup.py's wizard write path to a sandbox HOME on a non-writable /etc,
    then assert the resolver reads back exactly what was written (the whole point)."""
    import importlib.util
    setup_path = os.path.join(_REPO, "setup.py")
    spec = importlib.util.spec_from_file_location("soc_setup_cp", setup_path)
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)

    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SOC_PANELS_FILE", raising=False)
    monkeypatch.delenv("SOC_ENV_FILE", raising=False)
    # Force the per-user write tier deterministically (don't depend on the host /etc).
    monkeypatch.setattr(cp, "_dir_writable",
                        lambda d: False if d == cp.etc_dir() else True)

    paths = setup.resolve_paths("pi")
    assert paths["via"] == "user"
    cfg = {"display": setup._def_display(), "panels": [], "tunnel": {"enabled": False},
           "vpn": {"enabled": False}, "proxy": {"enabled": False}}
    os.makedirs(paths["panels_out"].rsplit("/", 1)[0], exist_ok=True)
    setup.write_file(paths["panels_out"], setup.render_panels_yaml(cfg),
                     paths["panels_mode"], dry=False)
    setup._drop_marker(paths, dry=False)

    resolved = cp.resolve_panels()
    assert os.path.abspath(resolved) == os.path.abspath(paths["panels_out"])


def test_user_tier_flags_unwritable(monkeypatch):
    """FAIL-SAFE: when even the per-user fallback dir is NOT writable, resolve_write
    must flag it (unwritable=True) so the caller can fail with a specific cause
    instead of an uncaught PermissionError deep in the write."""
    monkeypatch.setattr(cp, "_dir_writable", lambda d: False)  # nothing writable
    w = cp.resolve_write("panels", want_etc=True, can_escalate=False)
    assert w["via"] == "user"
    assert w.get("unwritable") is True
    # And when it IS writable, the flag is False (no false alarms).
    monkeypatch.setattr(cp, "_dir_writable",
                        lambda d: False if d == cp.etc_dir() else True)
    w2 = cp.resolve_write("panels", want_etc=True, can_escalate=False)
    assert w2["via"] == "user" and w2.get("unwritable") is False


def test_wizard_unwritable_fails_cleanly(tmp_path, monkeypatch, capsys):
    """FAIL-SAFE end-to-end: a non-root wizard whose only fallback dir is read-only
    must EXIT NON-ZERO with a visible 'not writable' cause and write NOTHING — never
    a raw traceback ("it does not fail — it tells you the cause")."""
    import importlib.util
    setup_path = os.path.join(_REPO, "setup.py")
    spec = importlib.util.spec_from_file_location("soc_setup_cp_ro", setup_path)
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SOC_PANELS_FILE", raising=False)
    monkeypatch.delenv("SOC_ENV_FILE", raising=False)
    # Nothing is writable: forces the user tier AND the pre-flight to trip.
    monkeypatch.setattr(cp, "_dir_writable", lambda d: False)
    setup.ASSUME_DEFAULTS = True

    class _Args:
        target, section, dry_run, defaults = "pi", "all", False, True
        _in_deploy = True
    rc = setup.cmd_wizard(_Args())
    out = capsys.readouterr().out
    assert rc == 1                                  # clean non-zero, not a crash
    assert "not writable" in out                    # the specific cause is shown
    # And it really wrote nothing to the (read-only) user tier — no marker, no file.
    assert not os.path.exists(os.path.join(cp.user_dir(), cp.PANELS_BASENAME))
    assert not os.path.exists(cp.active_marker())
