"""Unit tests for host/secretstore.py — the host-bound, PIN-sealed master pw."""
import glob
import importlib.util
import os

import pytest

from host import secretstore as ss


def _load_pinentry_vault():
    path = os.path.join(os.path.dirname(__file__), "..", "..",
                        "scripts", "pinentry-vault.py")
    spec = importlib.util.spec_from_file_location("pinentry_vault", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_available():
    # cryptography is a hard dependency of the wall now
    assert ss.available() is True


def test_gen_pin():
    p = ss.gen_pin()
    assert len(p) == 8 and p.isdigit()
    assert ss.gen_pin(6).isdigit() and len(ss.gen_pin(6)) == 6
    assert len(ss.gen_pin(2)) == ss._MIN_PIN_LEN   # floored at the 800-63B minimum


def test_seal_rejects_short_pin(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    with pytest.raises(ss.SecretStoreError):
        ss.seal("master", "123", str(tmp_path))     # below _MIN_PIN_LEN
    # a PIN at the floor is accepted
    ss.seal("master", "1" * ss._MIN_PIN_LEN, str(tmp_path))
    assert ss.unseal(str(tmp_path)) == "master"


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
        == ["host.key", "master.enc", "pin.enc", "pin.hash"]


def test_reseal_overwrites_and_unseals(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("old-pw", "11111111", d)
    ss.seal("new-pw", "22222222", d)            # re-seal with new pin
    assert ss.unseal(d) == "new-pw"
    assert ss.verify_pin("22222222", d)
    assert not ss.verify_pin("11111111", d)


def test_fips_pbkdf2_roundtrip(tmp_path, monkeypatch):
    # FIPS 140 mode: PBKDF2-HMAC-SHA256 (NIST SP 800-132) seals and unseals.
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    monkeypatch.setenv("SOC_FIPS_KDF", "1")
    d = str(tmp_path)
    ss.seal("fips-master", "123456", d)
    assert ss.unseal(d) == "fips-master"
    # the blob records the PBKDF2 algorithm id (self-describing format)
    with open(os.path.join(d, "master.enc"), "rb") as fh:
        blob = fh.read()
    assert blob[:len(ss._MAGIC)] == ss._MAGIC
    assert blob[len(ss._MAGIC)] == ss._ALGO_PBKDF2


def test_blob_algo_is_self_describing(tmp_path, monkeypatch):
    # A blob sealed under FIPS/PBKDF2 must still unseal when SOC_FIPS_KDF is later
    # unset — the KDF is chosen from the blob's ALGO byte, not the environment.
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    monkeypatch.setenv("SOC_FIPS_KDF", "1")
    d = str(tmp_path)
    ss.seal("portable", "123456", d)
    monkeypatch.delenv("SOC_FIPS_KDF", raising=False)        # default scrypt now
    assert ss.unseal(d) == "portable"


def test_default_algo_is_scrypt(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    monkeypatch.delenv("SOC_FIPS_KDF", raising=False)
    d = str(tmp_path)
    ss.seal("m", "123456", d)
    with open(os.path.join(d, "master.enc"), "rb") as fh:
        assert fh.read()[len(ss._MAGIC)] == ss._ALGO_SCRYPT


def test_corrupt_blob_without_magic_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("m", "123456", d)
    with open(os.path.join(d, "master.enc"), "wb") as fh:
        fh.write(b"\x00" * 40)                               # no MAGIC prefix
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(d)


def test_scrypt_params_hardened():
    # The KDF cost is a security control: brute-forcing the (low-entropy) PIN
    # offline must stay impractical. Guard against an accidental downgrade.
    assert ss._SCRYPT["n"] >= 2 ** 17
    assert ss._SCRYPT["r"] >= 8


def test_host_key_required(tmp_path, monkeypatch):
    # The seal binds to a 0600 host.key, not just the world-readable machine-id.
    # Remove host.key and the seal must read as not-sealed AND fail to unseal.
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("bound-to-hostkey", "12345678", d)
    assert ss.is_sealed(d)
    os.remove(os.path.join(d, "host.key"))
    assert not ss.is_sealed(d)
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(d)


def test_machine_id_alone_cannot_unseal(tmp_path, monkeypatch):
    # Threat model: attacker exfiltrates the encrypted blobs and the (public,
    # 0644) machine-id, but NOT the 0600 host.key. They must not be able to
    # unseal even on a host with the identical machine-id.
    import shutil
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    src = str(tmp_path / "src")
    os.makedirs(src)
    ss.seal("TOP-SECRET", "12345678", src)

    stolen = str(tmp_path / "stolen")
    os.makedirs(stolen)
    for f in ("master.enc", "pin.enc", "pin.hash"):     # everything BUT host.key
        shutil.copy(os.path.join(src, f), os.path.join(stolen, f))

    # Same machine-id, all blobs present, host.key withheld -> still sealed-shut.
    assert not ss.is_sealed(stolen)
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(stolen)


def test_host_key_is_random_per_seal(tmp_path, monkeypatch):
    # Each (re-)seal rotates the host key, so two seals of the same secret on the
    # same machine-id produce different binding keys (and ciphertext).
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    d = str(tmp_path)
    ss.seal("same-pw", "12345678", d)
    with open(os.path.join(d, "host.key"), "rb") as fh:
        k1 = fh.read()
    ss.seal("same-pw", "12345678", d)
    with open(os.path.join(d, "host.key"), "rb") as fh:
        k2 = fh.read()
    assert len(k1) == 32 and k1 != k2
    assert ss.unseal(d) == "same-pw"


def test_pinentry_vault_prefers_sealed_over_env(tmp_path, monkeypatch):
    # A sealed wall must unseal the host-bound master and IGNORE any
    # SOC_VAULT_PASSWORD in the environment — no plaintext master path in prod.
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    monkeypatch.setenv("SOC_SECRET_DIR", str(tmp_path))
    ss.seal("SEALED-master", "12345678", str(tmp_path))
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV-master")
    pv = _load_pinentry_vault()
    assert pv._master() == "SEALED-master"


def test_pinentry_vault_env_fallback_only_when_unsealed(tmp_path, monkeypatch):
    # Dev / seeding: with nothing sealed, an explicit env master is the fallback.
    monkeypatch.setenv("SOC_MACHINE_ID", "host-A")
    monkeypatch.setenv("SOC_SECRET_DIR", str(tmp_path))    # nothing sealed here
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV-master")
    pv = _load_pinentry_vault()
    assert pv._master() == "ENV-master"
