"""
Offline unit tests for host/litebw.py — the lightweight, rbw-compatible
Vaultwarden client. No network: KDF/EncString/TOTP are tested against
known-answer vectors and vaultseed._enc round-trips; the CLI is driven with a
monkeypatched ReadSession so 'get'/'code'/'config'/'unlock' are exercised
without a server.

Run from the kiosk-host dir so `from host import litebw` resolves:
    cd kiosk-host && pytest tests/
"""
import base64
import hashlib
import json
import os

import pytest

from host import litebw, vaultseed
from host.vaultseed import VaultSeedError

# The Argon2id KATs only make sense where cryptography ships Argon2id. On an
# older 'cryptography' litebw raises a clear error instead — so skip (not fail)
# those vectors, exactly as the task allows ("covered or xfail-skipped").
_ARGON2_AVAILABLE = litebw._argon2id_available()
_requires_argon2 = pytest.mark.skipif(
    not _ARGON2_AVAILABLE,
    reason="this cryptography build has no Argon2id (litebw raises a clear error)")


# --------------------------------------------------------------------------- #
# KDF — master-key derivation (PBKDF2 and Argon2id) known-answer vectors
# --------------------------------------------------------------------------- #
def test_pbkdf2_master_key_kat():
    # Independent reference: pbkdf2_hmac('sha256', pw, email.lower(), iters, 32).
    got = litebw.derive_master_key("correct horse", "Alice@Example.com", 0, 100000)
    assert got.hex() == (
        "9c8e752452573e5788af5ad052befcd2"
        "2400fb16e23c520e290387c3898a53d3")
    # Email is lowercased before use (salt is case-insensitive).
    assert got == litebw.derive_master_key("correct horse",
                                           "alice@example.com", 0, 100000)


def test_master_password_hash_kat():
    mk = litebw.derive_master_key("correct horse", "alice@example.com", 0, 100000)
    assert litebw.master_password_hash(mk, "correct horse") == \
        "Aiw8x5jv7lQuxEjeSzdNU3/OwTpeSIqnNkiQn1w7fjw="


@_requires_argon2
def test_argon2id_master_key_kat():
    # MiB field (16) must become memory_cost = 16*1024 KiB; an off-by-1024 here
    # silently yields a wrong key, so pin the exact digest.
    got = litebw.derive_master_key("correct horse", "Alice@Example.com",
                                   1, 3, 16, 4)
    assert got.hex() == (
        "4d09931e776160f6b61c3ff70a80400f"
        "39260a9328c771d4a9620926d522374d")


@_requires_argon2
def test_argon2id_memory_mib_mapping():
    # Same params but the MiB->KiB multiply matters: 16 MiB != 16 KiB.
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    salt = hashlib.sha256(b"alice@example.com").digest()
    ref = Argon2id(salt=salt, length=32, iterations=3, lanes=4,
                   memory_cost=16 * 1024).derive(b"correct horse")
    assert litebw.derive_master_key("correct horse", "alice@example.com",
                                    1, 3, 16, 4) == ref


def test_argon2id_raises_clear_error_when_unavailable(monkeypatch):
    # On a build without Argon2id, derive_master_key(kdf=1) must raise a clear
    # VaultSeedError (never silently fall through / return a wrong key). This
    # covers the xfail/skip path's counterpart: the error message is explicit.
    monkeypatch.setattr(litebw, "_argon2id_available", lambda: False)
    with pytest.raises(VaultSeedError) as ei:
        litebw.derive_master_key("pw", "a@b.com", 1, 3, 16, 4)
    assert "Argon2id" in str(ei.value)


def test_unsupported_kdf_raises():
    with pytest.raises(VaultSeedError):
        litebw.derive_master_key("pw", "a@b.com", 7, 1000)


def test_pbkdf2_iterations_clamped_to_ceiling():
    # A hostile prelogin can declare kdfIterations in the billions to pin the
    # CPU for minutes. The 10M ceiling means anything above it computes the
    # SAME key as exactly-10M (and never more work). Verified WITHOUT actually
    # running a billion-iteration KDF by comparing against the explicit cap.
    capped = litebw.derive_master_key("pw", "a@b.com", 0, 10_000_000)
    over = litebw.derive_master_key("pw", "a@b.com", 0, 2_000_000_000)
    assert over == capped
    # And a value at/below the ceiling is unchanged (real vaults unaffected).
    assert (litebw.derive_master_key("pw", "a@b.com", 0, 600000)
            != capped)  # different iters -> different key (sanity)


@_requires_argon2
def test_argon2id_params_clamped_without_huge_allocation(monkeypatch):
    # An unbounded kdfMemory (MiB) becomes memory_cost = memory*1024 KiB and a
    # multi-TB allocation -> instant OOM. Capture the params handed to Argon2id
    # instead of running them: memory clamps to 1024 MiB (-> 1024*1024 KiB),
    # iterations to 10M, lanes to 16. derive() is stubbed so no real work runs.
    import cryptography.hazmat.primitives.kdf.argon2 as argon2mod
    seen = {}

    class _FakeArgon2id:
        def __init__(self, *, salt, length, iterations, lanes, memory_cost):
            seen.update(iterations=iterations, lanes=lanes,
                        memory_cost=memory_cost)

        def derive(self, pw):
            return b"\x00" * 32

    monkeypatch.setattr(argon2mod, "Argon2id", _FakeArgon2id)
    litebw.derive_master_key("pw", "a@b.com", 1,
                             iterations=9_999_999_999,
                             memory=8_000_000, parallelism=9999)
    assert seen["iterations"] == 10_000_000
    assert seen["lanes"] == 16
    assert seen["memory_cost"] == 1024 * 1024   # 1024 MiB cap, in KiB


# --------------------------------------------------------------------------- #
# EncString decrypt — type 2 round-trip, MAC tamper, types 0/empty
# --------------------------------------------------------------------------- #
def test_encstring_type2_roundtrip():
    ek, mk = os.urandom(32), os.urandom(32)
    enc = vaultseed._enc("héllo wörld".encode(), ek, mk)
    assert enc.startswith("2.")
    assert litebw.decrypt_field(enc, ek, mk) == "héllo wörld"


@pytest.mark.parametrize("plaintext", [
    "",                       # empty
    "a",                      # 1 byte
    "x" * 15,                 # one shy of a block
    "0123456789abcdef",       # exactly one AES block (16 bytes)
    "0123456789abcdef!",      # one over a block
    "0123456789abcdef" * 2,   # exactly two blocks (PKCS7 must add a full pad block)
    "ünïcödé · 日本語 · key",   # multibyte unicode
])
def test_encstring_type2_roundtrip_edge_lengths(plaintext):
    # vaultseed._enc -> litebw.decrypt_field must round-trip for empty, the
    # exact-block-length boundary (PKCS7 appends a whole pad block), and unicode.
    ek, mk = os.urandom(32), os.urandom(32)
    enc = vaultseed._enc(plaintext.encode("utf-8"), ek, mk)
    assert litebw.decrypt_field(enc, ek, mk) == plaintext


def test_encstring_mac_tamper_rejected():
    ek, mk = os.urandom(32), os.urandom(32)
    enc = vaultseed._enc(b"secret", ek, mk)
    parts = enc.split("|")
    parts[-1] = vaultseed._b64(b"\x00" * 32)        # clobber the MAC
    with pytest.raises(VaultSeedError):
        litebw.decrypt_field("|".join(parts), ek, mk)


def test_encstring_wrong_key_rejected():
    ek, mk = os.urandom(32), os.urandom(32)
    enc = vaultseed._enc(b"secret", ek, mk)
    with pytest.raises(VaultSeedError):
        litebw.decrypt_field(enc, ek, os.urandom(32))   # wrong mac key


def test_encstring_empty_and_none_decrypt_to_empty():
    ek, mk = os.urandom(32), os.urandom(32)
    assert litebw.decrypt_field(None, ek, mk) == ""
    assert litebw.decrypt_field("", ek, mk) == ""


def test_encstring_type0_no_mac():
    # Type 0 (AesCbc256_B64): iv|ct, no MAC. Build one and decrypt.
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes)
    ek = os.urandom(32)
    iv = os.urandom(16)
    pt = b"legacy item"
    pad = 16 - (len(pt) % 16)
    data = pt + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    s = f"0.{vaultseed._b64(iv)}|{vaultseed._b64(ct)}"
    assert litebw.decrypt_field(s, ek, os.urandom(32)) == "legacy item"


def test_encstring_type2_non_utf8_plaintext_no_crash():
    # A MAC-valid type-2 field whose authenticated plaintext is NOT valid UTF-8
    # (e.g. a binary secret written by another client) must NOT raise
    # UnicodeDecodeError — it would escape list_ciphers and drop EVERY item.
    # decrypt_field decodes tolerantly (errors="replace") instead.
    ek, mk = os.urandom(32), os.urandom(32)
    enc = vaultseed._enc(bytes([0xff, 0xfe, 0x00, 0x41]), ek, mk)
    out = litebw.decrypt_field(enc, ek, mk)   # must not raise
    assert isinstance(out, str)
    assert "A" in out                          # the 0x41 byte survives


def test_encstring_type0_empty_ciphertext_raises_vaultseederror():
    # '0.<iv>|' (truncated, empty ct) used to raise IndexError on pt[-1]; that
    # is NOT a VaultSeedError so it escaped list_ciphers and aborted the sync.
    # Now it must raise VaultSeedError so the single item is skipped.
    s = f"0.{vaultseed._b64(os.urandom(16))}|"
    with pytest.raises(VaultSeedError):
        litebw.decrypt_field(s, os.urandom(32), os.urandom(32))


def test_encstring_type0_bad_base64_raises_vaultseederror():
    # Malformed base64 in the type-0 path raised binascii.Error (a ValueError),
    # which is not VaultSeedError and escaped list_ciphers. Now -> VaultSeedError.
    s = "0.not-base64!!!|also-not-base64!!!"
    with pytest.raises(VaultSeedError):
        litebw.decrypt_field(s, os.urandom(32), os.urandom(32))


def test_encstring_type0_non_block_aligned_ct_raises_vaultseederror():
    # A ct that isn't a multiple of the AES block size makes finalize() raise
    # ValueError; this must surface as VaultSeedError (skip), not abort the sync.
    iv = vaultseed._b64(os.urandom(16))
    ct = vaultseed._b64(os.urandom(7))        # 7 bytes: not block-aligned
    with pytest.raises(VaultSeedError):
        litebw.decrypt_field(f"0.{iv}|{ct}", os.urandom(32), os.urandom(32))


# --------------------------------------------------------------------------- #
# Account symmetric-key recovery (tok['Key']) — KDF-agnostic
# --------------------------------------------------------------------------- #
def test_account_key_recovery_from_protected_key():
    master_key = litebw.derive_master_key("pw", "user@x.com", 0, 600000)
    senc = vaultseed._hkdf_expand(master_key, b"enc")
    smac = vaultseed._hkdf_expand(master_key, b"mac")
    sym = os.urandom(64)                       # the would-be account key
    protected = vaultseed._enc(sym, senc, smac)
    recovered = vaultseed._dec(protected, senc, smac)
    assert recovered == sym
    assert recovered[:32] == sym[:32]          # ek
    assert recovered[32:] == sym[32:]          # mk


# --------------------------------------------------------------------------- #
# TOTP — RFC 6238 KATs, otpauth URI, steam
# --------------------------------------------------------------------------- #
# Base32 of ASCII "12345678901234567890" — the RFC 6238 / Google test seed.
# This is byte-for-byte the standard vector string from the task spec.
_RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


def test_rfc_secret_matches_standard_vector_literal():
    # Sanity: the seed we test against is exactly the documented constant, so a
    # future refactor of _RFC_SECRET can't silently weaken every TOTP KAT below.
    assert _RFC_SECRET == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_totp_rfc6238_sha1_6digit():
    assert litebw.generate_totp(_RFC_SECRET, at=59) == "287082"


# RFC 6238 Appendix B test vectors (SHA1, 8 digits, seed "12345678901234567890").
@pytest.mark.parametrize("at,expected", [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
])
def test_totp_rfc6238_sha1_8digit_vectors(at, expected):
    uri = f"otpauth://totp/Label?secret={_RFC_SECRET}&digits=8&algorithm=SHA1"
    assert litebw.generate_totp(uri, at=at) == expected


def test_totp_bare_secret_lowercase_and_spaces():
    # Lowercased + spaced bare secret must normalise (upper/strip/pad).
    spaced = " ".join(_RFC_SECRET.lower()[i:i + 4]
                      for i in range(0, len(_RFC_SECRET), 4))
    assert litebw.generate_totp(spaced, at=59) == "287082"


def test_totp_period_from_uri():
    uri = f"otpauth://totp/L?secret={_RFC_SECRET}&period=30"
    assert litebw.generate_totp(uri, at=59) == "287082"


def test_totp_steam_is_5_char_alphabet():
    code = litebw.generate_totp("steam://" + _RFC_SECRET, at=59)
    assert len(code) == 5
    assert all(c in litebw._STEAM_ALPHABET for c in code)
    # otpauth steam type yields the same code.
    uri = f"otpauth://steam/L?secret={_RFC_SECRET}"
    assert litebw.generate_totp(uri, at=59) == code


def test_totp_empty_raises():
    with pytest.raises(ValueError):
        litebw.generate_totp("", at=59)


def test_totp_uri_without_secret_raises():
    with pytest.raises(ValueError):
        litebw.generate_totp("otpauth://totp/L?digits=6", at=59)


# A poisoned otpauth URI (from a compromised/MITM'd server or a shared org item)
# must NOT be able to DoS the 1GB board via 10**digits / // period. Each
# malicious input becomes a clean ValueError BEFORE the dangerous math runs.
@pytest.mark.parametrize("bad", [
    f"otpauth://totp/L?secret={_RFC_SECRET}&digits=100000000",  # huge int/str
    f"otpauth://totp/L?secret={_RFC_SECRET}&digits=0",          # 10**0 mod
    f"otpauth://totp/L?secret={_RFC_SECRET}&digits=-1",         # negative
    f"otpauth://totp/L?secret={_RFC_SECRET}&digits=abc",        # non-numeric
    f"otpauth://totp/L?secret={_RFC_SECRET}&period=0",          # ZeroDivision
    f"otpauth://totp/L?secret={_RFC_SECRET}&period=-5",         # negative
    f"otpauth://totp/L?secret={_RFC_SECRET}&period=xyz",        # non-numeric
])
def test_totp_malicious_digits_period_rejected(bad):
    with pytest.raises(ValueError):
        litebw.generate_totp(bad, at=59)


# --------------------------------------------------------------------------- #
# config set — persists JSON, honors XDG_CONFIG_HOME, env override at read time
# --------------------------------------------------------------------------- #
def test_config_set_persists_json(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("SOC_VAULT_EMAIL", raising=False)
    monkeypatch.delenv("SOC_VAULT_URL", raising=False)

    assert litebw.main(["config", "set", "email", "a@b.com"]) == 0
    assert litebw.main(["config", "set", "base_url", "https://vault.local"]) == 0

    cfgfile = tmp_path / "litebw" / "config.json"
    assert cfgfile.exists()
    data = json.loads(cfgfile.read_text())
    assert data["email"] == "a@b.com"
    assert data["base_url"] == "https://vault.local"
    # file perms tightened
    assert (os.stat(cfgfile).st_mode & 0o777) == 0o600

    assert litebw.resolve_email() == "a@b.com"
    assert litebw.resolve_url() == "https://vault.local"
    # env overrides the file at read time
    monkeypatch.setenv("SOC_VAULT_EMAIL", "env@b.com")
    assert litebw.resolve_email() == "env@b.com"


def test_config_set_unknown_key_exits_2(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert litebw.main(["config", "set", "bogus", "x"]) == 2


def test_config_set_missing_args_exits_2(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert litebw.main(["config", "set", "email"]) == 2


# --------------------------------------------------------------------------- #
# CLI get / code — exit codes and stdout contract, via a fake session
# --------------------------------------------------------------------------- #
class _FakeSession:
    """Stand-in for ReadSession: returns canned decrypted ciphers, no network."""
    ITEMS = {
        "wazuh": {"name": "wazuh", "username": "admin", "password": "s3cr3t",
                  "notes": "panel notes", "totp": _RFC_SECRET},
        "nouser": {"name": "nouser", "username": "", "password": "pw-only",
                   "notes": "", "totp": ""},
        "nopw": {"name": "nopw", "username": "u", "password": "",
                 "notes": "just a note", "totp": ""},
    }

    def get_cipher(self, name):
        return self.ITEMS.get(name)

    def list_ciphers(self):
        return list(self.ITEMS.values())


@pytest.fixture
def fake_session(monkeypatch):
    monkeypatch.setattr(litebw, "_open_session", lambda: _FakeSession())
    return _FakeSession()


def test_get_prints_only_password(fake_session, capsys):
    rc = litebw.main(["get", "wazuh"])
    out = capsys.readouterr()
    assert rc == 0
    assert out.out == "s3cr3t\n"      # value only, no label


def test_get_field_username(fake_session, capsys):
    rc = litebw.main(["get", "--field", "username", "wazuh"])
    out = capsys.readouterr()
    assert rc == 0
    assert out.out == "admin\n"


def test_get_field_notes(fake_session, capsys):
    rc = litebw.main(["get", "--field", "notes", "wazuh"])
    out = capsys.readouterr()
    assert rc == 0
    assert out.out == "panel notes\n"


def test_get_field_username_empty_still_exit0(fake_session, capsys):
    # RbwBackend calls 'get --field username' with check=False: empty username
    # MUST exit 0 (not error) and print nothing.
    rc = litebw.main(["get", "--field", "username", "nouser"])
    out = capsys.readouterr()
    assert rc == 0
    assert out.out == ""


def test_get_not_found_exit_nonzero_empty_stdout(fake_session, capsys):
    rc = litebw.main(["get", "does-not-exist"])
    out = capsys.readouterr()
    assert rc != 0
    assert out.out == ""              # nothing on stdout
    assert out.err                    # error went to stderr


def test_get_password_missing_exit_nonzero(fake_session, capsys):
    # Item exists but has no password -> non-zero (plain 'get' contract).
    rc = litebw.main(["get", "nopw"])
    out = capsys.readouterr()
    assert rc != 0
    assert out.out == ""


def test_code_prints_only_digits(fake_session, capsys, monkeypatch):
    # Pin time so the KAT is deterministic.
    monkeypatch.setattr(litebw.time, "time", lambda: 59.0)
    rc = litebw.main(["code", "wazuh"])
    out = capsys.readouterr()
    assert rc == 0
    assert out.out == "287082\n"


def test_code_missing_secret_exit_nonzero_empty_stdout(fake_session, capsys):
    rc = litebw.main(["code", "nouser"])     # has no totp
    out = capsys.readouterr()
    assert rc != 0
    assert out.out == ""


# --------------------------------------------------------------------------- #
# unlock / unlocked / login CLI behavior
# --------------------------------------------------------------------------- #
def test_unlock_and_unlocked_are_noop_success():
    assert litebw.main(["unlock"]) == 0
    assert litebw.main(["unlocked"]) == 0


def test_help_no_traceback(capsys):
    assert litebw.main([]) == 0
    assert litebw.main(["--help"]) == 0
    assert "litebw" in capsys.readouterr().out


def test_unknown_command_exit_2(capsys):
    assert litebw.main(["frobnicate"]) == 2


# --------------------------------------------------------------------------- #
# get_master — sealed wins via host.secretstore.unseal; env is the fallback
# --------------------------------------------------------------------------- #
def test_get_master_uses_secretstore_when_sealed(monkeypatch):
    monkeypatch.setattr(litebw.secretstore, "is_sealed", lambda *a, **k: True)
    monkeypatch.setattr(litebw.secretstore, "unseal",
                        lambda *a, **k: "sealed-master")
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "env-master")
    assert litebw.get_master() == "sealed-master"     # sealed wins


def test_get_master_falls_back_to_env_when_unsealed(monkeypatch):
    monkeypatch.setattr(litebw.secretstore, "is_sealed", lambda *a, **k: False)
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "env-master")
    assert litebw.get_master() == "env-master"


def test_get_master_degrades_on_secretstore_error(monkeypatch, capsys):
    def boom(*a, **k):
        raise litebw.secretstore.SecretStoreError("no machine-id")
    monkeypatch.setattr(litebw.secretstore, "is_sealed", lambda *a, **k: True)
    monkeypatch.setattr(litebw.secretstore, "unseal", boom)
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "env-master")
    # is_sealed True but unseal raises -> degrade to env (like pinentry-vault.py)
    assert litebw.get_master() == "env-master"


# --------------------------------------------------------------------------- #
# LitebwBackend — interface mirrors RbwBackend; cache + lookup via fake session
# --------------------------------------------------------------------------- #
def test_backend_interface_methods_present():
    for m in ("configure", "unlock", "sync", "get", "notes", "code"):
        assert callable(getattr(litebw.LitebwBackend, m))


def test_backend_get_notes_code_from_cache(monkeypatch):
    be = litebw.LitebwBackend()
    be._session = _FakeSession()
    be.sync()
    assert be.get("wazuh") == ("admin", "s3cr3t")
    assert be.notes("wazuh") == "panel notes"
    monkeypatch.setattr(litebw.time, "time", lambda: 59.0)
    assert be.code("wazuh") == "287082"


def test_backend_get_missing_password_raises():
    be = litebw.LitebwBackend()
    be._session = _FakeSession()
    be.sync()
    with pytest.raises(Exception):
        be.get("nopw")            # no password -> VaultError (RbwBackend parity)


def test_backend_notes_missing_item_empty():
    be = litebw.LitebwBackend()
    be._session = _FakeSession()
    be.sync()
    assert be.notes("ghost") == ""


# --------------------------------------------------------------------------- #
# list_ciphers — one malformed cipher is skipped, never aborts the whole read
# --------------------------------------------------------------------------- #
def _make_read_session(ek, mk):
    # Build a ReadSession without touching the network (__init__ logs in), so we
    # can drive list_ciphers' per-item skipping with crafted raw ciphers.
    sess = litebw.ReadSession.__new__(litebw.ReadSession)
    sess.ek, sess.mk = ek, mk
    return sess


def test_list_ciphers_skips_non_utf8_field_keeps_good_items(monkeypatch):
    # A cipher whose password is a MAC-valid-but-non-UTF-8 type-2 field used to
    # raise UnicodeDecodeError out of list_ciphers, dropping EVERY item. Now the
    # bad item still decodes (errors=replace) and good items are unaffected.
    ek, mk = os.urandom(32), os.urandom(32)
    sess = _make_read_session(ek, mk)
    good = {
        "Id": "1", "Name": vaultseed._enc(b"wazuh", ek, mk),
        "Login": {"Username": vaultseed._enc(b"admin", ek, mk),
                  "Password": vaultseed._enc(b"s3cr3t", ek, mk)},
    }
    nasty = {
        "Id": "2", "Name": vaultseed._enc(b"binary", ek, mk),
        "Login": {"Password": vaultseed._enc(bytes([0xff, 0xfe]), ek, mk)},
    }
    monkeypatch.setattr(sess, "_raw_ciphers", lambda: [good, nasty])
    items = sess.list_ciphers()
    names = {it["name"] for it in items}
    assert "wazuh" in names                      # good item survived
    assert any(it["name"] == "binary" for it in items)  # bad item not fatal


def test_list_ciphers_skips_corrupt_type0_item(monkeypatch):
    # A corrupt type-0 field (empty ct -> IndexError before the fix) must cause
    # only that one item to be skipped, not abort the whole vault read.
    ek, mk = os.urandom(32), os.urandom(32)
    sess = _make_read_session(ek, mk)
    good = {
        "Id": "1", "Name": vaultseed._enc(b"keep", ek, mk),
        "Login": {"Password": vaultseed._enc(b"pw", ek, mk)},
    }
    corrupt = {
        "Id": "2", "Name": f"0.{vaultseed._b64(os.urandom(16))}|",  # empty ct
        "Login": {},
    }
    monkeypatch.setattr(sess, "_raw_ciphers", lambda: [corrupt, good])
    items = sess.list_ciphers()
    assert {it["name"] for it in items} == {"keep"}   # corrupt item dropped only


# --------------------------------------------------------------------------- #
# sync() 401 re-unlock retry — every failure funnels through VaultError
# --------------------------------------------------------------------------- #
def test_sync_401_reunlock_retry_failure_raises_vaulterror(monkeypatch):
    # On a 401, sync() drops the session and re-unlocks. If the retry still
    # fails (server still 401, or decrypt error), the leaked exception used to
    # be a VaultSeedError/_HTTPStatusError — NOT host.vault.VaultError — which
    # escapes Vault.prewarm's `except VaultError` and crashes worker threads.
    # The retry must now funnel through _vault_error -> VaultError.
    from host.vault import VaultError

    be = litebw.LitebwBackend()

    class _Stale:
        def list_ciphers(self):
            raise litebw._HTTPStatusError(401, "GET /api/ciphers -> HTTP 401")

    be._session = _Stale()
    # After the 401, _ensure_session() re-unlocks; force that to yield a session
    # whose retry list_ciphers() also fails with a VaultSeedError.
    class _StillBad:
        def list_ciphers(self):
            raise VaultSeedError("re-unlock decrypt failed")

    def fake_unlock():
        be._session = _StillBad()
    monkeypatch.setattr(be, "unlock", fake_unlock)

    with pytest.raises(VaultError):
        be.sync()


def test_sync_401_reunlock_retry_success(monkeypatch):
    # Happy path of the 401 branch: after re-unlock the retry succeeds and the
    # cache is populated.
    be = litebw.LitebwBackend()

    class _Stale:
        def list_ciphers(self):
            raise litebw._HTTPStatusError(401, "HTTP 401")

    be._session = _Stale()

    def fake_unlock():
        be._session = _FakeSession()
    monkeypatch.setattr(be, "unlock", fake_unlock)

    be.sync()
    assert be.get("wazuh") == ("admin", "s3cr3t")


# --------------------------------------------------------------------------- #
# Interactive unlock — sync() with no master must raise the catchable
# VaultLockedError (NOT a generic VaultError), so the host can pop the themed
# Unlock dialog instead of a cryptic fatal. Then unlock_with() opens a session.
# --------------------------------------------------------------------------- #
def test_sync_interactive_no_master_raises_vaultlocked(monkeypatch):
    # Regression: sync()'s broad `except VaultSeedError` used to catch + wrap the
    # VaultLockedError into a plain VaultError, swallowing the 'please unlock'
    # signal so the host never popped the prompt. It must now propagate as-is.
    monkeypatch.setenv("SOC_VAULT_INTERACTIVE", "1")
    monkeypatch.setattr(litebw, "get_master", lambda *a, **k: "")  # no master
    be = litebw.LitebwBackend()
    be.unlock()                       # interactive + no master -> defers (no raise)
    assert be._session is None
    with pytest.raises(litebw.VaultLockedError):
        be.sync()


def test_unlock_with_opens_session(monkeypatch):
    # The operator-supplied master from the Unlock dialog opens a ReadSession,
    # then sync() populates the cache. The master is never written to a file.
    be = litebw.LitebwBackend()
    be.url, be.email = "http://vault.local", "kiosk@soc.local"
    captured = {}

    def fake_session(url, email, master):
        captured.update(url=url, email=email, master=master)
        return _FakeSession()
    monkeypatch.setattr(litebw, "ReadSession", fake_session)
    be.unlock_with("operator-typed-master")
    assert captured["master"] == "operator-typed-master"
    be.sync()
    assert be.get("wazuh") == ("admin", "s3cr3t")


def test_unlock_with_bad_password_raises_vaulterror(monkeypatch):
    from host.vault import VaultError
    be = litebw.LitebwBackend()
    be.url, be.email = "http://vault.local", "kiosk@soc.local"

    def bad_session(url, email, master):
        raise VaultSeedError("login failed — check the email/master password")
    monkeypatch.setattr(litebw, "ReadSession", bad_session)
    with pytest.raises(VaultError):
        be.unlock_with("wrong")
    assert be._session is None
