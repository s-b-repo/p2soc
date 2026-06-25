"""Panel-lock (locker.py) + its Settings-window enrollment UI (configwin.py).

The 🔒 toolbar button / Ctrl+Alt+L raise locker.KioskLocker, which unlocks via
locker.verify_any() against $SOC_STATE_DIR/panellock.pin and panellock.totp.
Those files are WRITTEN by the Security section of the config window
(_build_panel_lock_section). These tests prove the round-trip: enrolling via the
config-window handlers makes locker.verify_any() return True — i.e. the lock is
no longer decorative.

All pure/file-backed — no display is mapped (we never call show_all()), so this
runs under `make test` headlessly.
"""
import os

from host import locker, totp


# --------------------------------------------------------------------------- #
# locker.py — the file-backed PIN/TOTP store + verify_any
# --------------------------------------------------------------------------- #
def test_pin_store_roundtrip_and_digest(tmp_path):
    sd = str(tmp_path)
    assert locker.pin_is_set(sd) is False
    locker.set_pin(sd, "2468")
    assert locker.pin_is_set(sd) is True
    assert locker.verify_pin(sd, "2468") is True
    assert locker.verify_pin(sd, "0000") is False
    # salted digest, never the clear PIN, 0600
    raw = open(tmp_path / "panellock.pin").read()
    assert "2468" not in raw and "$" in raw
    assert (os.stat(tmp_path / "panellock.pin").st_mode & 0o777) == 0o600
    locker.clear_pin(sd)
    assert locker.pin_is_set(sd) is False


def test_verify_any_with_pin(tmp_path):
    sd = str(tmp_path)
    assert locker.verify_any(sd, "2468") is False        # nothing enrolled
    locker.set_pin(sd, "2468")
    assert locker.verify_any(sd, "2468") is True
    assert locker.verify_any(sd, "9999") is False
    assert locker.verify_any(sd, "") is False
    assert locker.verify_any(sd, "  ") is False


def test_verify_any_with_totp(tmp_path):
    sd = str(tmp_path)
    secret = totp.generate_secret()
    totp.save(locker._totp_path(sd), secret)
    assert locker.totp_is_set(sd) is True
    code = totp.totp(secret)
    assert locker.verify_any(sd, code) is True
    assert locker.verify_any(sd, "000000") is False


def test_pin_separate_file_from_settings_gate(tmp_path):
    # panellock.pin (locker) and config.pin (configwin Settings gate) are
    # intentionally distinct files so the at-the-desk PIN != the admin PIN.
    sd = str(tmp_path)
    locker.set_pin(sd, "13579")
    assert os.path.exists(tmp_path / "panellock.pin")
    assert not os.path.exists(tmp_path / "config.pin")


# --------------------------------------------------------------------------- #
# configwin.py — the Security section that ENROLLS the panel-lock PIN/TOTP.
# Drive the real handlers (no full window / no display) and assert the lock
# can then be opened by verify_any. Before this UI existed nothing wrote those
# files, so the lock tore down on any input.
# --------------------------------------------------------------------------- #
class _Shell:
    """Stand-in for a ConfigWindow that carries only the widgets the panel-lock
    handlers touch. The real handlers are *bound* onto it below so the exact
    production code in configwin.py runs — we just avoid allocating a full
    Gtk.Window (a GObject subclass can't be object.__new__'d)."""


def _bind(shell, configwin, name):
    setattr(shell, name, getattr(configwin.ConfigWindow, name).__get__(shell))


def _bare_configwin(monkeypatch, tmp_path):
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    from host import configwin
    w = _Shell()
    w._pl_pin = Gtk.Entry()
    w._pl_uri = Gtk.Entry()
    w._pl_cx = Gtk.Label()
    w._pl_state = Gtk.Label()
    for m in ("_pl_set_pin", "_pl_clear_pin", "_pl_enroll_totp",
              "_pl_clear_totp", "_cx_hint", "_panel_lock_status_text"):
        _bind(w, configwin, m)
    return w


def test_ui_enroll_pin_makes_verify_any_pass(monkeypatch, tmp_path):
    w = _bare_configwin(monkeypatch, tmp_path)
    sd = str(tmp_path)
    w._pl_pin.set_text("8642")
    w._pl_set_pin()
    assert locker.pin_is_set(sd) is True
    assert locker.verify_any(sd, "8642") is True          # lock now functional
    assert w._pl_pin.get_text() == ""                     # entry cleared
    # remove via the UI handler
    w._pl_clear_pin()
    assert locker.pin_is_set(sd) is False


def test_ui_rejects_weak_pin(monkeypatch, tmp_path):
    w = _bare_configwin(monkeypatch, tmp_path)
    sd = str(tmp_path)
    w._pl_pin.set_text("1234")                            # common/leaked PIN
    w._pl_set_pin()
    assert locker.pin_is_set(sd) is False                 # refused by complexity
    assert "rejected" in w._pl_state.get_text().lower()


def test_ui_enroll_totp_makes_verify_any_pass(monkeypatch, tmp_path):
    w = _bare_configwin(monkeypatch, tmp_path)
    sd = str(tmp_path)
    w._pl_enroll_totp()
    assert locker.totp_is_set(sd) is True
    assert w._pl_uri.get_text().startswith("otpauth://totp/")
    secret = totp.load(locker._totp_path(sd))
    assert locker.verify_any(sd, totp.totp(secret)) is True
    w._pl_clear_totp()
    assert locker.totp_is_set(sd) is False
    assert w._pl_uri.get_text() == ""


def test_ui_cx_hint_is_wired(monkeypatch, tmp_path):
    # The live complexity hint must populate from the entry text (this is the
    # call that wires complexity.py into the host — it was orphaned before).
    w = _bare_configwin(monkeypatch, tmp_path)
    w._pl_pin.set_text("1234")
    w._cx_hint(w._pl_pin, w._pl_cx)
    assert w._pl_cx.get_text().startswith("✗")            # common PIN flagged
    w._pl_pin.set_text("8642")
    w._cx_hint(w._pl_pin, w._pl_cx)
    assert w._pl_cx.get_text().startswith("✓")
