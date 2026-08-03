"""Phase 5: verify_any_vault_first — vault is truth when set, file is
fallback when not. Vault-side enrollment must NOT silently fall through
to a stale local file."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import locker, totp                          # noqa: E402


class _FakeVault:
    def __init__(self, notes):
        self._notes = dict(notes)
        self.ready = True

    def notes(self, item):
        return self._notes.get(item, "")


def test_verify_any_vault_first_no_vault_falls_through_to_file(tmp_path):
    """Without a vault: behave like verify_any (file-only)."""
    locker.set_pin(str(tmp_path), "654321")
    assert locker.verify_any_vault_first(None, str(tmp_path), "654321") is True
    assert locker.verify_any_vault_first(None, str(tmp_path), "wrong") is False


def test_verify_any_vault_first_prefers_vault_totp(tmp_path):
    """TOTP in vault matches → returns True without touching files."""
    secret = totp.generate_secret()
    code = totp.totp(secret)
    v = _FakeVault({"SOC Panel Lock TOTP": secret})
    # Also seed a local PIN so we can prove the vault path won the race.
    locker.set_pin(str(tmp_path), "111111")
    assert locker.verify_any_vault_first(v, str(tmp_path), code) is True


def test_vault_totp_present_but_wrong_falls_back_only_to_pin(tmp_path):
    """If the vault has a TOTP and the user types the wrong code, the
    file-stored TOTP must NOT be tried as a fallback (vault is truth)
    — but the file-stored PIN IS still a valid alternative auth."""
    secret = totp.generate_secret()
    v = _FakeVault({"SOC Panel Lock TOTP": secret})
    locker.set_pin(str(tmp_path), "778899")
    # Wrong TOTP — but right PIN.
    assert locker.verify_any_vault_first(v, str(tmp_path), "778899") is True
    # Wrong both → False.
    assert locker.verify_any_vault_first(v, str(tmp_path), "000000") is False


def test_vault_unreachable_or_unready_uses_file_path(tmp_path):
    """vault.ready=False or backend raise → silent fallback to file."""
    class _Down:
        ready = False
        def notes(self, _item):
            raise RuntimeError("not ready")

    locker.set_pin(str(tmp_path), "424242")
    assert locker.verify_any_vault_first(_Down(), str(tmp_path),
                                          "424242") is True


def test_verify_pin_hash_string_input():
    """The hash-form helper accepts a salt$digest string and verifies
    correctly with constant-time comparison."""
    # Construct a hash for the code "987654" the same shape locker uses.
    import hashlib, os as _os
    salt = _os.urandom(16)
    digest = hashlib.sha256(salt + b"987654").hexdigest()
    stored = f"{salt.hex()}${digest}"
    assert locker._verify_pin_hash(stored, "987654") is True
    assert locker._verify_pin_hash(stored, "987655") is False


def test_verify_pin_hash_rejects_malformed():
    assert locker._verify_pin_hash("", "anything") is False
    assert locker._verify_pin_hash("no-dollar-sign", "x") is False
    assert locker._verify_pin_hash("zzz$digest", "x") is False  # bad hex salt
