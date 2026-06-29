"""host.ospass — OS-password verification for the Credentials-tab Edit
flow. Tests cover the operator-user resolver + the backend dispatch
chain (python3-pam preferred, pamtester next, su last)."""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import ospass                                 # noqa: E402


# --- operator_user resolution -------------------------------------------- #


def test_operator_user_prefers_env_var(monkeypatch):
    """SOC_OPERATOR_USER wins over every fallback (even when 'root' —
    operator's explicit choice; they may have set a root password)."""
    monkeypatch.setenv("SOC_OPERATOR_USER", "root")    # always exists
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert ospass.operator_user() == "root"


def test_operator_user_sudo_user_root_is_skipped(monkeypatch):
    """SUDO_USER=root is the DOUBLE-SUDO trap: the wall was launched
    via `sudo … sudo -u soc bash …`, so soc's env carries SUDO_USER=root.
    operator_user() must skip 'root' here and fall through to the
    /etc/passwd scan, otherwise we'd prompt for root's password — which
    is locked on Kali / Ubuntu / Fedora out of the box."""
    monkeypatch.delenv("SOC_OPERATOR_USER", raising=False)
    monkeypatch.setenv("SUDO_USER", "root")
    rv = ospass.operator_user()
    # Should be a real human user (uid >= 1000), not root.
    assert rv != "root"
    import pwd
    assert pwd.getpwnam(rv).pw_uid >= 1000


def test_operator_user_sudo_user_real_user_wins(monkeypatch):
    """SUDO_USER set to a real (non-root, existing) user IS used —
    most common path when a desktop user runs `sudo launch.sh` directly."""
    monkeypatch.delenv("SOC_OPERATOR_USER", raising=False)
    import pwd
    # Find a real human user on this box to assert against.
    target = None
    for e in pwd.getpwall():
        if e.pw_uid >= 1000 and e.pw_uid != 65534:
            target = e.pw_name
            break
    if target is None:
        return                                          # nothing to test
    monkeypatch.setenv("SUDO_USER", target)
    assert ospass.operator_user() == target


def test_operator_user_skips_nonexistent_env_values(monkeypatch):
    """A typo'd SOC_OPERATOR_USER (no such user on the box) doesn't get
    returned — falls through to SUDO_USER / conventional guesses.
    With SUDO_USER=root (which we now skip), we fall further to the
    /etc/passwd scan."""
    monkeypatch.setenv("SOC_OPERATOR_USER", "this-user-does-not-exist-12345")
    monkeypatch.setenv("SUDO_USER", "root")
    rv = ospass.operator_user()
    assert rv != "root"
    import pwd
    assert pwd.getpwnam(rv).pw_uid >= 1000


def test_operator_user_always_returns_string(monkeypatch):
    monkeypatch.delenv("SOC_OPERATOR_USER", raising=False)
    monkeypatch.delenv("SUDO_USER", raising=False)
    rv = ospass.operator_user()
    assert isinstance(rv, str) and rv


# --- verify_os_password ----------------------------------------------------- #


def test_verify_returns_false_for_empty_user_or_password():
    assert ospass.verify_os_password("", "anything") is False
    assert ospass.verify_os_password("root", "") is False
    assert ospass.verify_os_password("", "") is False


def test_verify_uses_su_backend_first(monkeypatch):
    """su is tried first because it's the only backend that reliably
    works cross-user from an unprivileged caller (the wall runs as
    `soc` and needs to verify the desktop operator's password)."""
    calls = []
    monkeypatch.setattr(ospass, "_verify_via_su",
                        lambda u, p, *, timeout: (calls.append("su"), True)[1])
    monkeypatch.setattr(ospass, "_verify_via_pamtester",
                        lambda *a, **kw: (calls.append("pamtester"), False)[1])
    monkeypatch.setattr(ospass, "_verify_via_pam",
                        lambda *a, **kw: (calls.append("pam"), False)[1])
    monkeypatch.setattr(ospass, "_MIN_LATENCY_SEC", 0.0)
    assert ospass.verify_os_password("alice", "right-password") is True
    assert calls == ["su"]


def test_verify_falls_through_su_to_pamtester(monkeypatch):
    """When su is unusable (missing binary), pamtester is next."""
    calls = []
    monkeypatch.setattr(ospass, "_verify_via_su",
                        lambda u, p, *, timeout: (calls.append("su"), None)[1])
    monkeypatch.setattr(ospass, "_verify_via_pamtester",
                        lambda u, p, *, timeout: (calls.append("pamtester"),
                                                    True)[1])
    monkeypatch.setattr(ospass, "_verify_via_pam",
                        lambda *a, **kw: (calls.append("pam"), True)[1])
    monkeypatch.setattr(ospass, "_MIN_LATENCY_SEC", 0.0)
    assert ospass.verify_os_password("alice", "pw") is True
    assert calls == ["su", "pamtester"]


def test_verify_falls_all_the_way_to_pam(monkeypatch):
    """When su + pamtester are both unavailable, python3-pampy is the
    last resort."""
    calls = []
    monkeypatch.setattr(ospass, "_verify_via_su",
                        lambda *a, **kw: (calls.append("su"), None)[1])
    monkeypatch.setattr(ospass, "_verify_via_pamtester",
                        lambda *a, **kw: (calls.append("pamtester"), None)[1])
    monkeypatch.setattr(ospass, "_verify_via_pam",
                        lambda *a, **kw: (calls.append("pam"), False)[1])
    monkeypatch.setattr(ospass, "_MIN_LATENCY_SEC", 0.0)
    assert ospass.verify_os_password("alice", "pw") is False
    assert calls == ["su", "pamtester", "pam"]


def test_verify_returns_false_when_every_backend_unavailable(monkeypatch):
    """All three unusable → False. Operator gets 'rejected'; nothing leaks."""
    monkeypatch.setattr(ospass, "_verify_via_pam",
                        lambda *a, **kw: None)
    monkeypatch.setattr(ospass, "_verify_via_pamtester",
                        lambda *a, **kw: None)
    monkeypatch.setattr(ospass, "_verify_via_su",
                        lambda *a, **kw: None)
    monkeypatch.setattr(ospass, "_MIN_LATENCY_SEC", 0.0)
    assert ospass.verify_os_password("alice", "pw") is False


def test_verify_swallows_backend_exception(monkeypatch):
    """A misbehaving PAM module raising must not crash the GUI prompt —
    we move to the next backend."""
    def _pam_explode(*a, **kw):
        raise RuntimeError("pam module broken")
    monkeypatch.setattr(ospass, "_verify_via_pam", _pam_explode)
    monkeypatch.setattr(ospass, "_verify_via_pamtester",
                        lambda u, p, *, timeout: True)
    monkeypatch.setattr(ospass, "_verify_via_su",
                        lambda *a, **kw: None)
    monkeypatch.setattr(ospass, "_MIN_LATENCY_SEC", 0.0)
    assert ospass.verify_os_password("alice", "pw") is True


def test_verify_enforces_min_latency(monkeypatch):
    """Constant-time wall clock: a wrong password resolves at least as
    slowly as a right one, so timing can't tell them apart."""
    monkeypatch.setattr(ospass, "_verify_via_pam",
                        lambda *a, **kw: False)         # instant-fail backend
    monkeypatch.setattr(ospass, "_verify_via_pamtester",
                        lambda *a, **kw: None)
    monkeypatch.setattr(ospass, "_verify_via_su",
                        lambda *a, **kw: None)
    monkeypatch.setattr(ospass, "_MIN_LATENCY_SEC", 0.10)
    t0 = time.monotonic()
    ospass.verify_os_password("alice", "wrong")
    assert (time.monotonic() - t0) >= 0.09


def test_pam_backend_returns_none_when_module_missing(monkeypatch):
    """If `import pam` itself ImportError's, the backend returns None
    (not False) so dispatch knows to skip."""
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) \
        else __builtins__.__import__

    def _fake_import(name, *a, **kw):
        if name == "pam":
            raise ImportError("no pam")
        return real_import(name, *a, **kw)
    monkeypatch.setattr("builtins.__import__", _fake_import)
    assert ospass._verify_via_pam("alice", "pw", timeout=1.0) is None


def test_pamtester_backend_returns_none_when_binary_missing(monkeypatch):
    """No pamtester on PATH → returns None (skip)."""
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert ospass._verify_via_pamtester("alice", "pw", timeout=1.0) is None


def test_su_backend_returns_none_when_binary_missing(monkeypatch):
    """No su on PATH (extremely unlikely) → returns None (skip)."""
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert ospass._verify_via_su("alice", "pw", timeout=1.0) is None
