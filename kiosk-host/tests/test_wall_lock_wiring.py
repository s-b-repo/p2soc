"""Phase 1: wire tray + locker into the wall runtime.

These tests cover the pure-Python wiring — the delete-event handler logic,
the actions-dict plumbing, and KioskHost's locker construction — without
spinning up real GTK windows. The Gdk/Gtk import paths are exercised
because the modules are imported, but no toplevel window is shown.
"""
from __future__ import annotations

import os
import sys

# Make `host` importable regardless of CWD.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# --- delete-event pure-logic --------------------------------------------- #

def test_delete_event_no_tray_returns_false_so_close_proceeds():
    from host.wall import _delete_event_action
    assert _delete_event_action(None) is False


def test_delete_event_with_tray_calls_callback_and_swallows():
    from host.wall import _delete_event_action
    called = []
    rc = _delete_event_action(lambda: called.append(True))
    assert called == [True]
    assert rc is True


def test_delete_event_swallows_even_if_callback_raises_returns_false():
    """A callback that bombs must not leave a zombie window — degrade to
    letting GTK destroy the window so the operator can recover."""
    from host.wall import _delete_event_action

    def bombs():
        raise RuntimeError("hide failed")

    rc = _delete_event_action(bombs)
    assert rc is False


# --- KioskHost locker construction --------------------------------------- #

def test_kioskhost_constructs_locker_with_state_dir(monkeypatch, tmp_path):
    """KioskHost.__init__ must build a KioskLocker pointed at
    configwin.state_dir(). The locker module + state_dir are module-level
    imports so we can verify the wiring without launching the wall."""
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    # Reload configwin so state_dir() picks up the env var.
    import importlib
    from host import configwin
    importlib.reload(configwin)
    from host import main as host_main
    from host import config

    # Build a minimum config — no panels, no VPN.
    conf = config.Config(panels=[], vpns=[],
                         proxy=config.ProxyCfg(),
                         display=config.DisplayCfg(),
                         tunnel={})
    # Pass an inert vault stand-in to avoid touching rbw.
    class _NullVault:
        ready = False
        def open(self): pass
        def notes(self, _): return ""

    host = host_main.KioskHost(conf, vault=_NullVault())
    assert host._locker is not None
    assert host._locker.state_dir == str(tmp_path)


def test_kioskhost_tray_starts_none(tmp_path, monkeypatch):
    """The tray is constructed lazily in build_and_show, not in __init__,
    so a freshly-constructed KioskHost has _tray = None."""
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    import importlib
    from host import configwin
    importlib.reload(configwin)
    from host import main as host_main
    from host import config

    conf = config.Config(panels=[], vpns=[],
                         proxy=config.ProxyCfg(),
                         display=config.DisplayCfg(),
                         tunnel={})

    class _NullVault:
        ready = False
        def open(self): pass

    host = host_main.KioskHost(conf, vault=_NullVault())
    assert host._tray is None


def test_kioskhost_lock_wall_invokes_locker(monkeypatch, tmp_path):
    """The _lock_wall helper must call locker.lock() exactly once."""
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    import importlib
    from host import configwin
    importlib.reload(configwin)
    from host import main as host_main
    from host import config

    conf = config.Config(panels=[], vpns=[],
                         proxy=config.ProxyCfg(),
                         display=config.DisplayCfg(),
                         tunnel={})

    class _NullVault:
        ready = False
        def open(self): pass

    host = host_main.KioskHost(conf, vault=_NullVault())
    calls = []
    host._locker.lock = lambda **kw: calls.append(kw)
    host._lock_wall()
    assert len(calls) == 1
    # The plan reserves on_unlock for future use; today it's passed as None.
    assert calls[0].get("on_unlock") is None
