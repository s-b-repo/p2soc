"""Pure on-disk + verify_any helpers from host.locker (no GTK)."""
import os

from host import locker
from host import totp


def test_pin_roundtrip(tmp_path):
    sd = str(tmp_path)
    assert locker.pin_is_set(sd) is False
    locker.set_pin(sd, "847291")
    assert locker.pin_is_set(sd) is True
    assert locker.verify_pin(sd, "847291") is True
    assert locker.verify_pin(sd, "wrong") is False
    locker.clear_pin(sd)
    assert locker.pin_is_set(sd) is False


def test_verify_any_prefers_totp(tmp_path):
    sd = str(tmp_path)
    locker.set_pin(sd, "847291")
    secret = totp.generate_secret()
    totp.save(locker._totp_path(sd), secret)
    # PIN still works
    assert locker.verify_any(sd, "847291")
    # TOTP works
    assert locker.verify_any(sd, totp.totp(secret))
    # Garbage fails
    assert not locker.verify_any(sd, "")
    assert not locker.verify_any(sd, "000000")
    assert not locker.verify_any(sd, "this-is-not-a-pin")


def test_verify_any_no_credentials_returns_false(tmp_path):
    """When NOTHING is enrolled, verify_any is a flat False. (The interactive
    overlay treats no-credentials-enrolled as 'don't lock' separately.)"""
    sd = str(tmp_path)
    assert not locker.verify_any(sd, "anything")
    assert not locker.verify_any(sd, "847291")


def test_setting_empty_pin_clears(tmp_path):
    sd = str(tmp_path)
    locker.set_pin(sd, "847291")
    locker.set_pin(sd, "")          # empty -> clear
    assert not locker.pin_is_set(sd)


def test_pin_file_mode_owner_only(tmp_path):
    import stat
    sd = str(tmp_path)
    locker.set_pin(sd, "847291")
    assert stat.S_IMODE(os.stat(locker._pin_path(sd)).st_mode) == 0o600
