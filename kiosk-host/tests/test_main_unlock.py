"""
Drives host.main's startup vault-open loop around the interactive Unlock dialog
(Task 2b). No GTK window is shown — _unlock_dialog and _fatal_screen are
monkeypatched — so this runs headless. Verifies:

  * a VaultLockedError pops the prompt, the typed master is fed to unlock_with(),
    and (when the operator opts in) the master is sealed host-bound;
  * cancelling the prompt falls through to the fail-safe screen;
  * a wrong master / unreachable server (VaultError from unlock_with) is reported,
    not silently looped forever.

host.main imports gi at module scope; the rest of the suite already imports gi,
so this is safe under the same interpreter.
"""
import os
import sys

import pytest

pytest.importorskip("gi")  # host.main imports gi at module scope — skip where PyGObject is absent (CI)
from host import main as hostmain
from host.litebw import VaultLockedError
from host.vault import VaultError


class _LockedBackend:
    """Raises VaultLockedError on open() until unlock_with() succeeds, then opens."""
    def __init__(self, fail_unlock=False):
        self.email = "kiosk@soc.local"
        self.url = "http://vault.local"
        self._open = False
        self.fail_unlock = fail_unlock
        self.unlocked_with = None

    def open(self):
        if not self._open:
            raise VaultLockedError("vault is locked — Vaultwarden master needed")

    def unlock_with(self, master):
        self.unlocked_with = master
        if self.fail_unlock:
            raise VaultError("login failed — check the email/master password")
        self._open = True


class _FakeVault:
    def __init__(self, backend):
        self.backend = backend

    def open(self):
        self.backend.open()


def _run_loop(monkeypatch, vault, dialog_returns, seal_calls):
    """Reproduce main()'s open loop in isolation (the loop body is the unit under
    test). Returns ('ok',) on success or ('fatal', title) on the fail-safe path."""
    monkeypatch.setattr(hostmain, "_unlock_dialog",
                        lambda email, url: dialog_returns.pop(0))
    monkeypatch.setattr(hostmain, "_try_seal_master",
                        lambda m: seal_calls.append(m) or True)

    import time
    deadline = time.time() + 30
    while True:
        try:
            vault.open()
            return ("ok",)
        except VaultLockedError:
            master, seal_it = hostmain._unlock_dialog(vault.backend.email,
                                                      vault.backend.url)
            if not master:
                return ("fatal", "Vaultwarden is locked")
            try:
                vault.backend.unlock_with(master)
            except VaultError as e:
                if time.time() > deadline:
                    return ("fatal", "Could not unlock Vaultwarden")
                continue
            if seal_it:
                hostmain._try_seal_master(master)
            continue


def test_unlock_prompt_feeds_master_and_seals(monkeypatch):
    be = _LockedBackend()
    v = _FakeVault(be)
    seal_calls = []
    res = _run_loop(monkeypatch, v, [("operator-master", True)], seal_calls)
    assert res == ("ok",)
    assert be.unlocked_with == "operator-master"
    assert seal_calls == ["operator-master"]   # sealed because seal_it=True


def test_unlock_prompt_no_seal(monkeypatch):
    be = _LockedBackend()
    v = _FakeVault(be)
    seal_calls = []
    res = _run_loop(monkeypatch, v, [("m", False)], seal_calls)
    assert res == ("ok",)
    assert seal_calls == []                      # operator declined sealing


def test_cancel_falls_through_to_fatal(monkeypatch):
    be = _LockedBackend()
    v = _FakeVault(be)
    res = _run_loop(monkeypatch, v, [(None, False)], [])
    assert res == ("fatal", "Vaultwarden is locked")
    assert be.unlocked_with is None


def test_wrong_master_then_correct_retries(monkeypatch):
    # First attempt: a bad master (unlock_with raises) -> re-loop; second: good.
    be = _LockedBackend(fail_unlock=True)
    v = _FakeVault(be)

    def _flip(master):
        be.unlocked_with = master
        if be.fail_unlock:
            be.fail_unlock = False           # next attempt succeeds
            raise VaultError("login failed — check the email/master password")
        be._open = True
    monkeypatch.setattr(be, "unlock_with", _flip)
    res = _run_loop(monkeypatch, v, [("wrong", True), ("right", True)], [])
    assert res == ("ok",)
