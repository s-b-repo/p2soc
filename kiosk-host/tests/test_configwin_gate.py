"""SEC-7 regression: the on-screen config must not open without a PIN in prod."""
from host import configwin as cw


def test_gate_truth_table():
    # dev, no PIN -> opens freely (convenience)
    assert cw.gate_unlocked(False, False) is True
    # a PIN is set -> always gated
    assert cw.gate_unlocked(False, True) is False
    # production (require) -> always gated, even with no PIN set (no glass access)
    assert cw.gate_unlocked(True, False) is False
    assert cw.gate_unlocked(True, True) is False


def test_require_pin_env(monkeypatch):
    monkeypatch.delenv("SOC_CONFIG_REQUIRE_PIN", raising=False)
    assert cw.require_pin() is False
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "1")
    assert cw.require_pin() is True
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "0")
    assert cw.require_pin() is False


def test_pin_roundtrip(tmp_path, monkeypatch):
    # set_pin/verify_pin store only a salted digest (no plaintext PIN on disk).
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    cw.set_pin("4242")
    assert cw.pin_is_set()
    assert cw.verify_pin("4242")
    assert not cw.verify_pin("0000")
    with open(cw._pin_path(), "rb") as fh:
        assert b"4242" not in fh.read()
    cw.clear_pin()
    assert not cw.pin_is_set()
