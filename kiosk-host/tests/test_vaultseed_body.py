"""vaultseed.py login-body assembly + the new totp= kwarg.

A full list/get/delete/upsert round-trip needs a live Vaultwarden server, which
the unit suite has no business spinning up. Instead we test the pure body
builder `_login_body` (and the real `_enc`/`_dec` crypto) so the contract is
locked down server-free:

  * with totp omitted the body is byte-identical to the historical shape
    (no "totp" key in the login object) — backward-compatible for _seed_panels
    and the existing editor.
  * with totp set, it lands in login["totp"] ENCRYPTED (never plaintext), the
    same way username/password are.
"""
import pytest

from host import vaultseed


# A reversible fake "encryptor" so the body-SHAPE tests don't need the
# cryptography package: tag the plaintext so we can assert what got encrypted.
def _fake_enc(s):
    return f"ENC({s})"


def test_login_body_omits_totp_by_default_byte_compatible():
    body = vaultseed._login_body(_fake_enc, "Item", "alice", "s3cret",
                                 notes=None, uri=None)
    # Historical shape — exactly the keys the pre-totp builder produced.
    assert body == {
        "type": 1,
        "name": "ENC(Item)",
        "favorite": False,
        "notes": None,
        "login": {
            "username": "ENC(alice)",
            "password": "ENC(s3cret)",
            "uris": None,
        },
    }
    assert "totp" not in body["login"]


def test_login_body_with_uri_and_notes():
    body = vaultseed._login_body(_fake_enc, "I", "u", "p",
                                 notes="hello", uri="https://x/")
    assert body["notes"] == "ENC(hello)"
    assert body["login"]["uris"] == [{"uri": "ENC(https://x/)", "match": None}]


def test_login_body_includes_encrypted_totp():
    body = vaultseed._login_body(_fake_enc, "I", "u", "p",
                                 totp="JBSWY3DPEHPK3PXP")
    assert body["login"]["totp"] == "ENC(JBSWY3DPEHPK3PXP)"


def test_login_body_empty_totp_omitted():
    # None and "" both omit the key (so the body stays byte-identical).
    for empty in (None, ""):
        body = vaultseed._login_body(_fake_enc, "I", "u", "p", totp=empty)
        assert "totp" not in body["login"]


def test_login_body_totp_is_encrypted_not_plaintext_with_real_crypto():
    pytest.importorskip("cryptography")
    # Use the real session encryptor path (random 32-byte keys) so we exercise
    # _enc/_dec exactly as a live Session would, and confirm the secret never
    # appears verbatim in the body.
    import os
    ek, mk = os.urandom(32), os.urandom(32)

    def enc(s):
        return vaultseed._enc(s.encode(), ek, mk)

    secret = "JBSWY3DPEHPK3PXP"
    body = vaultseed._login_body(enc, "Item", "alice", "pw", totp=secret)
    enc_totp = body["login"]["totp"]
    assert secret not in enc_totp                      # encrypted, not plaintext
    assert enc_totp.startswith("2.")                   # Bitwarden EncString v2
    # round-trips back to the original secret
    assert vaultseed._dec(enc_totp, ek, mk).decode() == secret
    # password likewise encrypted, recoverable
    assert vaultseed._dec(body["login"]["password"], ek, mk).decode() == "pw"


def test_upsert_login_signature_accepts_totp_kwarg():
    # Backward-compat guard: the existing positional signature still works and
    # totp is a trailing keyword-only-by-convention extension.
    import inspect
    sig = inspect.signature(vaultseed.Session.upsert_login)
    params = list(sig.parameters)
    assert params[:6] == ["self", "name", "username", "password", "notes", "uri"]
    assert "totp" in params
    assert sig.parameters["totp"].default is None
    # Module-level wrapper mirrors it.
    msig = inspect.signature(vaultseed.upsert_login)
    assert "totp" in msig.parameters and msig.parameters["totp"].default is None


def test_module_level_read_helpers_exist():
    for fn in ("list_logins", "get_login", "delete_login"):
        assert hasattr(vaultseed, fn)
        assert hasattr(vaultseed.Session, fn)
