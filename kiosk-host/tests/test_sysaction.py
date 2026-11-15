"""Headless wiring tests for host.sysaction — the privileged Install/Uninstall
runner behind the control center's // system group.

These NEVER run the real install.sh / uninstall.sh: the SOC_SYSACTION_CMD fake hook
(the analogue of SOC_VAULT_BACKEND=dev) makes build_argv point at a stand-in, and
the elevation branches (pkexec/terminal/manual) are wiring-checked, not executed.
No gi / no display is imported here.
"""
import os
import subprocess
import sys

from host import sysaction

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_KIOSK = os.path.join(_REPO, "kiosk-host")


def test_fake_takes_precedence_over_elevation(monkeypatch):
    # SOC_SYSACTION_CMD set -> run that fake DIRECTLY (no pkexec/sudo), same env knobs.
    monkeypatch.setenv("SOC_SYSACTION_CMD", "/bin/true")
    argv, how = sysaction.build_argv("install", mode="kiosk")
    assert how == "fake"
    assert "/bin/true" in argv
    # the mode threads in as an env knob, never a bare flag.
    assert any("INSTALL_MODE=kiosk" in a for a in argv)


def test_install_mode_threads_into_argv(monkeypatch):
    monkeypatch.setenv("SOC_SYSACTION_CMD", "/bin/true")
    argv, _ = sysaction.build_argv("install", mode="desktop")
    assert any("INSTALL_MODE=desktop" in a for a in argv)
    argv, _ = sysaction.build_argv("install")  # default
    assert any("INSTALL_MODE=desktop" in a for a in argv)


def test_install_threads_shared_user_knobs_via_provision(monkeypatch):
    """When provision.py is resolvable, the GUI Install threads the SAME env-knob
    set provision.install_env_knobs() derives (the user names too, not just
    INSTALL_MODE) and names the SAME install.sh — parity with the CLI deploy."""
    monkeypatch.setenv("SOC_SYSACTION_CMD", "/bin/true")
    # Point ROOT at the repo so provision.py is found; reset the lazy cache.
    monkeypatch.setattr(sysaction, "ROOT", _REPO)
    monkeypatch.setattr(sysaction, "_PROVISION", None)
    monkeypatch.setattr(sysaction, "_PROVISION_TRIED", False)
    argv, how = sysaction.build_argv("install", mode="kiosk")
    assert how == "fake"
    assert any("INSTALL_MODE=kiosk" in a for a in argv)
    # the shared knob set carries the user names too (from install_env_knobs).
    assert any(a.startswith("KIOSK_USER=") for a in argv), argv
    assert any(a.startswith("DESKTOP_USER=") for a in argv), argv
    assert any(a.startswith("SVC_USER=") for a in argv), argv


def test_install_script_resolves_via_provision_helper(monkeypatch):
    """_script_path('install') resolves the deploy engine through the SAME helper
    the CLI uses (provision.install_sh), so both paths name one file."""
    if _REPO not in sys.path:
        sys.path.insert(0, _REPO)
    import provision  # noqa: PLC0415
    monkeypatch.setattr(sysaction, "ROOT", _REPO)
    monkeypatch.setattr(sysaction, "_PROVISION", None)
    monkeypatch.setattr(sysaction, "_PROVISION_TRIED", False)
    assert sysaction._script_path("install") == provision.install_sh()


def test_uninstall_always_force_purge_optional(monkeypatch):
    monkeypatch.setenv("SOC_SYSACTION_CMD", "/bin/true")
    argv, _ = sysaction.build_argv("uninstall")
    assert "--force" in argv and "--purge" not in argv
    argv, _ = sysaction.build_argv("uninstall", purge=True)
    assert "--force" in argv and "--purge" in argv


def test_elevation_precedence_without_fake(monkeypatch):
    # No fake -> the path resolves to pkexec, else terminal, else manual; always a
    # usable (non-empty) argv, never a raise.
    monkeypatch.delenv("SOC_SYSACTION_CMD", raising=False)
    for action, kw in (("install", {"mode": "desktop"}),
                       ("uninstall", {"purge": True})):
        argv, how = sysaction.build_argv(action, **kw)
        assert argv and isinstance(argv, list)
        assert how in ("pkexec", "terminal", "manual")


def test_build_argv_rejects_unknown_action():
    import pytest
    with pytest.raises(ValueError):
        sysaction.build_argv("frobnicate")


def test_manual_hint_names_script_and_flags():
    assert "install.sh" in sysaction.manual_hint("install", mode="kiosk")
    assert "INSTALL_MODE=kiosk" in sysaction.manual_hint("install", mode="kiosk")
    h = sysaction.manual_hint("uninstall", purge=True)
    assert "uninstall.sh" in h and "--force" in h and "--purge" in h


def test_check_exits_zero_no_gi():
    """`--check` validates the wiring in a fresh interpreter, importing no gi and
    running no real script."""
    code = (
        "import sys\n"
        "import host.sysaction as m\n"
        "rc = m.main(['--check'])\n"
        "assert rc == 0, rc\n"
        "assert 'gi' not in sys.modules, 'sysaction --check must not import gi'\n"
        "print('ok')\n"
    )
    env = dict(os.environ, PYTHONPATH=_KIOSK)
    env.pop("SOC_SYSACTION_CMD", None)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout
