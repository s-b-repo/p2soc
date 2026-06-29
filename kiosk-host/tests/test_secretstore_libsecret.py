"""Phase 5: libsecret (KWallet / GNOME-Keyring / Secret-Service) backend
for the vault master. Opt-in via SOC_SECRET_BACKEND=libsecret."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import secretstore                           # noqa: E402


# Whether the libsecret gi typelib is actually installed on the test host.
# On Kali with default packages it usually is; on a minimal CI it may not
# be. Tests that need the *real* backend skip when unavailable; tests of
# the env-driven dispatch use monkeypatching and run unconditionally.
_REAL = secretstore.libsecret_available()


def test_libsecret_available_returns_bool():
    """Cheap probe — must return a bool either way, never raise."""
    rv = secretstore.libsecret_available()
    assert isinstance(rv, bool)


def test_libsecret_load_returns_none_when_backend_missing(monkeypatch):
    """If the typelib import fails, load gracefully returns None."""
    monkeypatch.setattr(secretstore, "_try_libsecret", lambda: None)
    assert secretstore.libsecret_load() is None


def test_libsecret_clear_returns_false_when_backend_missing(monkeypatch):
    monkeypatch.setattr(secretstore, "_try_libsecret", lambda: None)
    assert secretstore.libsecret_clear() is False


def test_libsecret_store_raises_when_backend_missing(monkeypatch):
    monkeypatch.setattr(secretstore, "_try_libsecret", lambda: None)
    try:
        secretstore.libsecret_store("anything")
    except RuntimeError as e:
        assert "libsecret not available" in str(e)
    else:
        raise AssertionError("expected RuntimeError")


def test_unseal_falls_back_to_file_when_libsecret_missing(monkeypatch, tmp_path):
    """SOC_SECRET_BACKEND=libsecret + no entry stored → log a warning and
    fall through to the sealed-file path (which raises here because there's
    no seal in tmp_path; the point is that the fallback fires)."""
    monkeypatch.setenv("SOC_SECRET_BACKEND", "libsecret")
    monkeypatch.setattr(secretstore, "libsecret_load", lambda: None)
    monkeypatch.setenv("SOC_SECRET_DIR", str(tmp_path))
    # No seal in tmp_path → SecretStoreError from the file path.
    try:
        secretstore.unseal()
    except secretstore.SecretStoreError as e:
        assert "sealed" in str(e).lower() or "host.key" in str(e).lower()
    else:
        raise AssertionError("expected SecretStoreError from file fallback")


def test_unseal_returns_libsecret_value_when_present(monkeypatch, tmp_path):
    """libsecret_load returns a value → unseal returns it without ever
    touching the file path (so a missing seal is fine here)."""
    monkeypatch.setenv("SOC_SECRET_BACKEND", "libsecret")
    monkeypatch.setattr(secretstore, "libsecret_load",
                        lambda: "vault-master-from-keyring")
    monkeypatch.setenv("SOC_SECRET_DIR", str(tmp_path))
    assert secretstore.unseal() == "vault-master-from-keyring"


def test_unseal_default_backend_uses_file(monkeypatch, tmp_path):
    """No SOC_SECRET_BACKEND env → libsecret_load is NEVER called even if
    a keyring entry exists. Backwards-compatible default."""
    monkeypatch.delenv("SOC_SECRET_BACKEND", raising=False)
    called = []
    monkeypatch.setattr(secretstore, "libsecret_load",
                        lambda: called.append(True))
    monkeypatch.setenv("SOC_SECRET_DIR", str(tmp_path))
    try:
        secretstore.unseal()
    except secretstore.SecretStoreError:
        pass                                    # expected: no seal in tmp_path
    assert called == []
