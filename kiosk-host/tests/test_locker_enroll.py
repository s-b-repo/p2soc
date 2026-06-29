"""locker.py security-store enroll API: set/clear/is_set + load for BOTH pin and
totp, and verify_any across them.

This is the control-center enroll surface (configcenter writes these via the
locker functions, the live lock reads them). Pure/file-backed — no display is
mapped — so it runs headlessly under `make test`. We skip where PyGObject is
absent because host.locker imports gi at module scope.
"""
import os

import pytest

pytest.importorskip("gi")
from host import locker, totp


def test_totp_store_set_clear_is_set_load(tmp_path):
    sd = str(tmp_path)
    assert locker.totp_is_set(sd) is False
    assert locker.load_totp(sd) is None

    secret = totp.generate_secret()
    locker.set_totp(sd, secret)
    assert locker.totp_is_set(sd) is True
    assert locker.load_totp(sd) == secret
    # stored 0600, secret on disk (file-backed store, by design)
    assert (os.stat(locker._totp_path(sd)).st_mode & 0o777) == 0o600

    locker.clear_totp(sd)
    assert locker.totp_is_set(sd) is False
    assert locker.load_totp(sd) is None


def test_set_totp_empty_clears(tmp_path):
    sd = str(tmp_path)
    locker.set_totp(sd, totp.generate_secret())
    assert locker.totp_is_set(sd) is True
    locker.set_totp(sd, "")            # empty -> clear, mirroring set_pin
    assert locker.totp_is_set(sd) is False


def test_verify_any_pin_via_enroll_api(tmp_path):
    sd = str(tmp_path)
    assert locker.pin_is_set(sd) is False
    locker.set_pin(sd, "8642")
    assert locker.pin_is_set(sd) is True
    assert locker.verify_any(sd, "8642") is True
    assert locker.verify_any(sd, "0000") is False
    locker.clear_pin(sd)
    assert locker.pin_is_set(sd) is False
    assert locker.verify_any(sd, "8642") is False


def test_verify_any_totp_via_enroll_api(tmp_path):
    sd = str(tmp_path)
    secret = totp.generate_secret()
    locker.set_totp(sd, secret)
    code = totp.totp(secret)                       # host.totp generates the code
    assert locker.verify_any(sd, code) is True
    assert locker.verify_any(sd, "000000") is False
    assert locker.verify_any(sd, "") is False
    locker.clear_totp(sd)
    assert locker.verify_any(sd, totp.totp(secret)) is False


def test_verify_any_accepts_either_when_both_enrolled(tmp_path):
    sd = str(tmp_path)
    secret = totp.generate_secret()
    locker.set_pin(sd, "8642")
    locker.set_totp(sd, secret)
    assert locker.verify_any(sd, "8642") is True       # PIN path
    assert locker.verify_any(sd, totp.totp(secret)) is True   # TOTP path
    assert locker.verify_any(sd, "9999") is False


def test_provision_uri_roundtrips_for_enrollment(tmp_path):
    # The control center shows provision_uri(secret) as a QR; enrolling that
    # same secret must verify_any against the code the app would show.
    sd = str(tmp_path)
    secret = totp.generate_secret()
    uri = totp.provision_uri(secret, "wall@host")
    assert uri.startswith("otpauth://totp/")
    locker.set_totp(sd, secret)
    assert locker.verify_any(sd, totp.totp(secret)) is True
