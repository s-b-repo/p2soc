"""Unit tests for host/secretstore.py — the host-bound, PIN-sealed master pw."""
import glob
import os

import pytest

from host import secretstore as ss


def test_available():
    # cryptography is a hard dependency of the wall now
    assert ss.available() is True


def test_gen_pin():
    p = ss.gen_pin()
    assert len(p) == 8 and p.isdigit()
    assert ss.gen_pin(6).isdigit() and len(ss.gen_pin(6)) == 6
    assert len(ss.gen_pin(2)) == 4          # floored at 4


def test_seal_unseal_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    assert not ss.is_sealed(d)
    pin = ss.gen_pin()
    ss.seal("Master-PW!", pin, d)
    assert ss.is_sealed(d)
    assert ss.unseal(d) == "Master-PW!"
    assert ss.verify_pin(pin, d)
    assert not ss.verify_pin("00000000", d)


def test_files_are_0600_and_no_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("PlAiNtExT-secret", "12345678", d)
    for f in glob.glob(os.path.join(d, "*")):
        assert (os.stat(f).st_mode & 0o777) == 0o600
        with open(f, "rb") as fh:
            assert b"PlAiNtExT-secret" not in fh.read()


def test_host_binding(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("bound", "12345678", d)
    monkeypatch.setenv("SOC_MACHINE_ID", "host-B")     # different machine
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(d)


def test_refuses_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    with pytest.raises(ss.SecretStoreError):
        ss.seal("", "1234", d)
    with pytest.raises(ss.SecretStoreError):
        ss.seal("m", "", d)


def test_unseal_missing_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(str(tmp_path))


def test_is_sealed_requires_all_three_files(tmp_path, monkeypatch):
    # A half-written seal (e.g. only master.enc present) must read as NOT sealed,
    # so the operator re-seals instead of booting into an unrecoverable state.
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("m", "12345678", d)
    assert ss.is_sealed(d)
    for f in ("pin.enc", "pin.hash"):
        os.remove(os.path.join(d, f))
        assert not ss.is_sealed(d)
        ss.seal("m", "12345678", d)             # restore a complete seal
        assert ss.is_sealed(d)


def test_seal_leaves_no_tmp_files(tmp_path, monkeypatch):
    # The staged *.tmp blobs must be os.replace()d into place, never left behind.
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("m", "12345678", d)
    assert glob.glob(os.path.join(d, "*.tmp")) == []
    assert sorted(os.path.basename(f) for f in glob.glob(os.path.join(d, "*"))) \
        == ["master.enc", "pin.enc", "pin.hash"]


def test_reseal_overwrites_and_unseals(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("old-pw", "11111111", d)
    ss.seal("new-pw", "22222222", d)            # re-seal with new pin
    assert ss.unseal(d) == "new-pw"
    assert ss.verify_pin("22222222", d)
    assert not ss.verify_pin("11111111", d)
