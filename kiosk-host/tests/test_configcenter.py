"""Tests for host/configcenter.py pure-logic / non-GTK functions.

Targets the module-level helpers ``_resolve_master`` and ``ControlCenter._totp_code``
which have zero existing coverage. The GTK-bound ``_build_gate`` is skipped — it
requires widget construction and a display."""
import pytest

from host import totp as host_totp
from host.configcenter import _resolve_master
from host.configcenter import ControlCenter


class _MinimalCC:
    """Minimally-created ControlCenter stand-in carrying only the attributes
    ``_totp_code`` touches — no GTK initialisation, no display needed."""
    def __init__(self, litebw=None):
        self.litebw = litebw
        self.totp = host_totp


def _bind_totp_code(cc):
    return ControlCenter._totp_code.__get__(cc)


# --------------------------------------------------------------------------- #
# _resolve_master
# --------------------------------------------------------------------------- #
def test_resolve_master_empty_when_nothing_available(monkeypatch):
    """Returns '' when neither mastersource nor secretstore can provide a master."""
    # Force mastersource to return empty
    def _no_master(*a, **k):
        return ""
    monkeypatch.setattr("host.mastersource.get_master", _no_master)
    monkeypatch.setattr("host.secretstore.is_sealed", lambda *a, **k: False)
    assert _resolve_master() == ""


def test_resolve_master_from_mastersource(monkeypatch):
    """Returns the master when mastersource.get_master() succeeds."""
    monkeypatch.setattr("host.mastersource.get_master",
                        lambda *a, **k: "mastersource-master")
    monkeypatch.setattr("host.secretstore.is_sealed", lambda *a, **k: False)
    assert _resolve_master() == "mastersource-master"


def test_resolve_master_falls_through_mastersource_exception(monkeypatch):
    """When mastersource raises, falls through to secretstore."""
    def _boom(*a, **k):
        raise RuntimeError("no mastersource")
    monkeypatch.setattr("host.mastersource.get_master", _boom)
    monkeypatch.setattr("host.secretstore.is_sealed", lambda *a, **k: False)
    assert _resolve_master() == ""


def test_resolve_master_from_sealed_secretstore(monkeypatch):
    """Returns the unsealed master when secretstore is sealed."""
    def _get_master(*a, **k):
        raise RuntimeError("no mastersource")
    monkeypatch.setattr("host.mastersource.get_master", _get_master)
    monkeypatch.setattr("host.secretstore.is_sealed", lambda *a, **k: True)
    monkeypatch.setattr("host.secretstore.unseal", lambda *a, **k: "sealed-master")
    assert _resolve_master() == "sealed-master"


def test_resolve_master_empty_when_not_sealed(monkeypatch):
    """Returns '' when secretstore is not sealed."""
    def _get_master(*a, **k):
        raise RuntimeError("no mastersource")
    monkeypatch.setattr("host.mastersource.get_master", _get_master)
    monkeypatch.setattr("host.secretstore.is_sealed", lambda *a, **k: False)
    assert _resolve_master() == ""


def test_resolve_master_empty_when_unseal_returns_none(monkeypatch):
    """Returns '' when unseal returns None."""
    monkeypatch.setattr("host.mastersource.get_master",
                        lambda *a, **k: "")
    monkeypatch.setattr("host.secretstore.is_sealed", lambda *a, **k: True)
    monkeypatch.setattr("host.secretstore.unseal", lambda *a, **k: None)
    assert _resolve_master() == ""


def test_resolve_master_secretstore_exception_falls_through(monkeypatch):
    """Returns '' when secretstore import or calls raise."""
    def _get_master(*a, **k):
        raise RuntimeError("no mastersource")
    monkeypatch.setattr("host.mastersource.get_master", _get_master)
    monkeypatch.setattr("host.secretstore.is_sealed", lambda *a, **k: True)
    monkeypatch.setattr("host.secretstore.unseal",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _resolve_master() == ""


# --------------------------------------------------------------------------- #
# ControlCenter._totp_code
# --------------------------------------------------------------------------- #
_BARE_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"     # RFC 6238 test secret
_OTPAUTH_URI = (
    "otpauth://totp/Test%20Panel:operator@soc.local"
    "?secret=JBSWY3DPEHPK3PXP&issuer=SOC+Wall&algorithm=SHA1&digits=6&period=30"
)


def test_totp_code_bare_base32_via_totp_fallback():
    """When litebw is None, falls back to host.totp.totp."""
    cc = _MinimalCC(litebw=None)
    fn = _bind_totp_code(cc)
    code = fn(_BARE_B32)
    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isdigit()
    assert code == host_totp.totp(_BARE_B32)


def test_totp_code_otpauth_uri_fails_without_litebw():
    """When litebw is None, an otpauth:// URI raises ValueError because
    host.totp.totp only handles bare base32."""
    cc = _MinimalCC(litebw=None)
    fn = _bind_totp_code(cc)
    with pytest.raises(ValueError):
        fn(_OTPAUTH_URI)


def test_totp_code_raises_on_empty_secret():
    cc = _MinimalCC(litebw=None)
    fn = _bind_totp_code(cc)
    with pytest.raises(ValueError):
        fn("")


def test_totp_code_raises_on_garbage_secret():
    cc = _MinimalCC(litebw=None)
    fn = _bind_totp_code(cc)
    with pytest.raises(ValueError):
        fn("!!!!not-base32!!!")


def test_totp_code_via_litebw(monkeypatch):
    """When litebw is present, generate_totp delegates to it."""
    class _FakeLitebw:
        @staticmethod
        def generate_totp(secret):
            return "123456"

    cc = _MinimalCC(litebw=_FakeLitebw())
    fn = _bind_totp_code(cc)
    assert fn("anything") == "123456"


def test_totp_code_litebw_handles_otpauth_uri(monkeypatch):
    """otpauth:// URI flows through litebw.generate_totp when litebw is set."""
    calls = []

    class _FakeLitebw:
        @staticmethod
        def generate_totp(secret):
            calls.append(secret)
            return "654321"

    cc = _MinimalCC(litebw=_FakeLitebw())
    fn = _bind_totp_code(cc)
    code = fn(_OTPAUTH_URI)
    assert code == "654321"
    assert len(calls) == 1
    assert calls[0] == _OTPAUTH_URI


def test_totp_code_consistent_across_backends():
    """litebw.generate_totp and host.totp.totp produce the same code for a bare
    base32 secret (same algorithm)."""
    from host import litebw
    cc_litebw = _MinimalCC(litebw=litebw)
    cc_totp = _MinimalCC(litebw=None)
    fn_litebw = _bind_totp_code(cc_litebw)
    fn_totp = _bind_totp_code(cc_totp)
    assert fn_litebw(_BARE_B32) == fn_totp(_BARE_B32)


def test_totp_code_6_digit_format():
    """Every valid secret returns exactly 6 digits, zero-padded."""
    cc = _MinimalCC(litebw=None)
    fn = _bind_totp_code(cc)
    for _ in range(5):
        secret = host_totp.generate_secret()
        code = fn(secret)
        assert len(code) == 6
        assert code.isdigit()
        assert int(code) >= 0
