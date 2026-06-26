"""RFC 4226 / 6238 vectors + edge cases for kiosk-host/host/totp.py."""
from host import totp


# RFC 6238 Appendix B reference vectors (SHA-1 secret = ASCII "12345678901234567890").
# The published codes use 8-digit output; we also check the 6-digit truncation.
_RFC6238_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"     # b32("12345678901234567890")
_RFC6238_8DIGIT = {
    59:          "94287082",
    1111111109:  "07081804",
    1111111111:  "14050471",
    1234567890:  "89005924",
    2000000000:  "69279037",
    20000000000: "65353130",
}


def test_rfc6238_appendix_b_vectors():
    for t, want in _RFC6238_8DIGIT.items():
        got = totp.totp(_RFC6238_SECRET_B32, t=t, digits=8)
        assert got == want, f"t={t}: got {got!r}, want {want!r}"


def test_truncates_to_6_digits():
    # The 6-digit output is the last 6 of the corresponding 8-digit code.
    for t, want8 in _RFC6238_8DIGIT.items():
        assert totp.totp(_RFC6238_SECRET_B32, t=t, digits=6) == want8[-6:]


def test_verify_within_window():
    secret = _RFC6238_SECRET_B32
    base = 1111111111
    code = totp.totp(secret, t=base, digits=6)
    assert totp.verify(secret, code, t=base, window=0)
    # ±1 step (=30s) accepted by default
    assert totp.verify(secret, code, t=base + 25)
    assert totp.verify(secret, code, t=base - 25)
    # +2 steps rejected with default window=1
    assert not totp.verify(secret, code, t=base + 90)


def test_verify_rejects_garbage():
    s = _RFC6238_SECRET_B32
    assert not totp.verify(s, "abcdef")
    assert not totp.verify(s, "")
    assert not totp.verify(s, "000000")
    assert not totp.verify(s, None or "")


def test_generate_secret_is_b32_and_unique():
    s1 = totp.generate_secret()
    s2 = totp.generate_secret()
    assert s1 != s2
    # Roundtrip-decodable
    import base64
    base64.b32decode(s1 + "=" * ((-len(s1)) % 8))


def test_decode_tolerates_spaces_and_lowercase():
    # Authenticator apps often present the secret with spaces every 4 chars
    # and in lowercase. Operators copy-paste this into our enrollment field.
    spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
    assert totp.totp(spaced, t=59, digits=8) == "94287082"


def test_provision_uri_shape():
    uri = totp.provision_uri("ABCDEFGHIJKLMNOP", "kiosk@soc.local",
                              issuer="SOC Wall")
    assert uri.startswith("otpauth://totp/SOC%20Wall:kiosk@soc.local?")
    assert "secret=ABCDEFGHIJKLMNOP" in uri
    assert "issuer=SOC+Wall" in uri or "issuer=SOC%20Wall" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


def test_load_save_clear_roundtrip(tmp_path):
    p = str(tmp_path / "config.totp")
    assert totp.load(p) is None
    totp.save(p, "ABCDEFGHIJKLMNOP")
    assert totp.load(p) == "ABCDEFGHIJKLMNOP"
    import os, stat
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    totp.clear(p)
    assert totp.load(p) is None
    totp.clear(p)                                       # idempotent
