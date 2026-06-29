"""Smoke + dry-run coverage for scripts/reinstall.py.

The tool is stdlib + argparse; we exercise the parser, the safety
gates, and the dry-run path with mocked subprocess so no real systemctl
calls fire. Real uninstall requires root + a live install and is out of
scope for unit tests.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "reinstall.py")


def _load():
    """Import scripts/reinstall.py as a module (it isn't on sys.path)."""
    spec = importlib.util.spec_from_file_location("soc_reinstall", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- module loads cleanly + ships expected constants --------------------- #

def test_script_compiles_and_exposes_main():
    m = _load()
    assert hasattr(m, "main")
    assert callable(m.main)


def test_constants_point_at_real_deploy_layout():
    m = _load()
    assert m.DEPLOY_ROOT == "/opt/soc-display"
    assert m.ETC_ROOT == "/etc/soc-display"
    # The systemd units the installer actually creates must all be in UNITS.
    for unit in ("soc-wall.service", "soc-tarpit.service",
                 "forti-vpn@.service", "autossh-tunnel.service"):
        assert unit in m.UNITS


def test_etc_children_keeps_secret_dir_by_default():
    """`secret/` must NOT be in the always-remove list (the sealed master
    needs to survive a default reinstall — that's the whole point of
    keeping the safe-default tier)."""
    m = _load()
    assert "secret" not in m.ETC_CHILDREN_REMOVE


# --- safety gates --------------------------------------------------------- #

def test_assert_not_running_from_deploy_blocks_self_destruct(monkeypatch):
    """Refuses to run if its own file lives under /opt/soc-display."""
    m = _load()
    monkeypatch.setattr(m, "repo_root", lambda: "/opt/soc-display")
    with pytest.raises(SystemExit) as ei:
        m.assert_not_running_from_deploy()
    assert "source git checkout" in str(ei.value)


def test_assert_not_running_from_deploy_passes_for_source_repo():
    """The real checkout path (which is NOT under /opt) must NOT exit."""
    m = _load()
    m.assert_not_running_from_deploy()                 # no raise


# --- CLI parsing --------------------------------------------------------- #

def test_parse_args_defaults_are_safe():
    """Out-of-the-box: keep secrets + keep vault + reinstall + ask first."""
    m = _load()
    a = m.parse_args([])
    assert a.purge is False
    assert a.purge_vault is False
    assert a.purge_vault_data is False
    assert a.uninstall_only is False
    assert a.no_firstrun is False
    assert a.dry_run is False
    assert a.yes is False
    assert a.keep_units is False


def test_parse_args_flags_carry_through():
    m = _load()
    a = m.parse_args(["--uninstall-only", "--purge", "--purge-vault",
                       "--purge-vault-data", "--no-firstrun", "--dry-run",
                       "--yes", "--verbose", "--keep-units"])
    assert a.uninstall_only and a.purge and a.purge_vault
    assert a.purge_vault_data and a.no_firstrun and a.dry_run
    assert a.yes and a.verbose and a.keep_units


# --- Runner dry-run never spawns subprocesses ---------------------------- #

def test_runner_dry_run_records_actions_without_executing(monkeypatch):
    m = _load()
    r = m.Runner(dry_run=True, verbose=False)
    sentinel = []
    monkeypatch.setattr("subprocess.run",
                        lambda *a, **kw: sentinel.append(a) or None)
    rc = r.run(["systemctl", "stop", "soc-wall"])
    assert sentinel == []                              # never called
    assert r.actions == 1
    assert rc.returncode == 0


def test_runner_remove_path_dry_run_does_not_touch_fs(tmp_path):
    m = _load()
    target = tmp_path / "must-not-be-deleted.txt"
    target.write_text("survive\n")
    r = m.Runner(dry_run=True, verbose=False)
    r.remove_path(str(target))
    assert target.exists()                             # untouched


# --- full uninstall + reinstall under --dry-run --yes --no-firstrun ------- #

def test_full_dry_run_walks_every_step_without_executing(monkeypatch, capsys):
    """End-to-end dry-run: every step prints its [dry-run] line, no
    subprocess spawns, and the exit code is 0."""
    m = _load()
    monkeypatch.setattr(m, "assert_root", lambda: None)
    # subprocess.run is the underlying spawn — stub it loud.
    spawns = []
    monkeypatch.setattr("subprocess.run",
                        lambda *a, **kw: spawns.append(a) or None)
    rc = m.main(["--dry-run", "--yes", "--no-firstrun"])
    assert rc == 0
    assert spawns == [], f"dry-run still spawned: {spawns}"
    out = capsys.readouterr().out
    # Every uninstall section ran.
    for section in ("Stopping services", "Disabling services",
                     "Removing systemd unit files",
                     "Restoring default boot target",
                     "Removing /opt/soc-display",
                     "Cleaning /etc/soc-display",
                     "Vaultwarden"):
        assert section in out
    # Reinstall section ran (because --uninstall-only NOT set).
    assert "Reinstalling" in out
    # First-run was skipped per flag.
    assert "first-run" not in out.lower() or "skipping" in out.lower()


def test_uninstall_only_skips_reinstall(monkeypatch, capsys):
    m = _load()
    monkeypatch.setattr(m, "assert_root", lambda: None)
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: None)
    rc = m.main(["--dry-run", "--yes", "--uninstall-only"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Reinstalling" not in out
    assert "done (uninstall-only)" in out
