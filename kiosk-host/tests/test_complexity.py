"""Password / PIN complexity policy."""
from host import complexity


def test_pin_defaults_accept_non_trivial_4plus_digits():
    # 4-digit minimum + numeric-only — and not a common-bad sequence.
    r = complexity.check("7029", kind="pin")
    assert r.ok, r.issues
    assert complexity.check("83619274", kind="pin").ok


def test_pin_defaults_reject_too_short():
    r = complexity.check("12", kind="pin")
    assert not r.ok
    assert any("at least 4" in i for i in r.issues)


def test_pin_rejects_letters_under_numeric_only_default():
    r = complexity.check("abcd", kind="pin")
    assert not r.ok
    assert any("digits only" in i for i in r.issues)


def test_password_default_rejects_common():
    r = complexity.check("password", kind="password")
    assert not r.ok
    assert any("common" in i or "leaked" in i for i in r.issues)


def test_password_default_rejects_short():
    r = complexity.check("Aa1!", kind="password")
    assert not r.ok
    assert any("at least 12" in i for i in r.issues)


def test_password_default_requires_classes():
    # 12 chars but only lowercase + digit (2 classes < default 3)
    r = complexity.check("abcdef123456", kind="password")
    assert not r.ok
    assert any("3 of" in i for i in r.issues)


def test_password_default_accepts_strong():
    r = complexity.check("Tr0ub4dor&3xtra", kind="password")
    assert r.ok, r.issues


def test_no_spaces_no_controls():
    r = complexity.check("Aa1! with space", kind="password")
    assert not r.ok
    assert any("spaces" in i for i in r.issues)
    r2 = complexity.check("Aa1!\x07hello", kind="password")
    assert not r2.ok
    assert any("control" in i for i in r2.issues)


def test_kwargs_override_policy(tmp_path):
    # an explicit min_len=8 raises the bar above the default min_len=4 for pin
    r = complexity.check("1234", kind="pin", min_len=8)
    assert not r.ok


def test_policy_json_overrides_defaults(tmp_path, monkeypatch):
    p = tmp_path / "policy.json"
    p.write_text('{"pin": {"min_len": 8, "classes": 1, "numeric_only": true}}')
    # 4-digit fails under the bumped policy
    assert not complexity.check("7029", kind="pin",
                                 policy_path=str(p)).ok
    # 8-digit succeeds (non-trivial — common-bad list still applies)
    assert complexity.check("83619274", kind="pin",
                             policy_path=str(p)).ok


def test_summary_human_readable():
    r = complexity.check("a", kind="password")
    assert "ok" not in r.summary()
    assert isinstance(r.summary(), str)
    r2 = complexity.check("Tr0ub4dor&3xtra", kind="password")
    assert r2.summary() == "ok"


def test_complexity_is_wired_into_configwin():
    # complexity used to ship as dead code — the Security section now imports it
    # and runs a live PIN check. Guard against it being orphaned again.
    import inspect
    from host import configwin
    assert configwin._cx is complexity
    src = inspect.getsource(configwin.ConfigWindow._cx_hint)
    assert "_cx.check" in src
