"""
Kiosk lock — an in-app input firewall that doesn't hide the display.

When the operator (via the toolbar lock-button or Ctrl+Alt+L) engages the
lock, a transparent fullscreen GTK window is raised above the wall window. The
wall + WebKit panels keep painting underneath — the panels are still readable
from the operator's perspective, except… they aren't, because every input
event (mouse + keys + scroll + drag) hits the lock overlay and is swallowed.

An unlock card is centered on the overlay: padlock icon + an entry field that
accepts EITHER the configured panel-lock PIN, OR a TOTP code (the same secret a
phone authenticator uses), OR — as an admin emergency unlock — the host's
sealed setup PIN (secretstore). Wrong code → on-screen "incorrect" + an
exponential backoff/lockout.

Why a top-level window and NOT GtkOverlay:
    The wall is laid out as `vbox(toolbar, grid_of_webviews)`. A WebKit
    panel is a NATIVE window — GTK overlay siblings paint UNDER it. A separate
    top-level Gtk.Window with `set_keep_above(True)` paints over the natives
    reliably.

Hardening:
    * Wrong-code rate limit — exponential lockout after 3 wrong tries.
    * Esc + window-close are swallowed when locked — the operator MUST enter
      the code to dismiss. No "close to bypass" shortcut.
    * Idempotent show()/hide() — calling lock() twice doesn't stack windows.
    * Lock state is process-local; nothing on disk. The PIN/TOTP secrets ARE
      on disk (state_dir()/panellock.pin, panellock.totp); the admin override
      PIN is the host-sealed setup PIN under $SOC_SECRET_DIR.

Storage is FILE-backed only — our vaultseed lacks the secure-note write
helpers PROD used, so there is no vault-backed PIN/TOTP path here.
"""
from __future__ import annotations

import hashlib
import hmac
import os

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import totp as _totp  # noqa: E402
from . import style as _style  # noqa: E402

try:
    from . import secretstore as _secretstore  # noqa: E402
except Exception:                              # noqa: BLE001
    _secretstore = None


# --- on-disk PIN store for the panel lock --------------------------------- #
# Mirrors the ⚙ Settings PIN store (configwin) — same salt+SHA256 shape so
# anybody reading both files knows it's the same scheme. Separate file so the
# operator can use a DIFFERENT PIN for "open Settings" vs "unlock the panel"
# (settings is for the admin, panel-lock is for an at-the-desk user).
def _pin_path(state_dir: str) -> str:
    return os.path.join(state_dir, "panellock.pin")


def _totp_path(state_dir: str) -> str:
    return os.path.join(state_dir, "panellock.totp")


def pin_is_set(state_dir: str) -> bool:
    return os.path.exists(_pin_path(state_dir))


def totp_is_set(state_dir: str) -> bool:
    return os.path.exists(_totp_path(state_dir))


def set_pin(state_dir: str, pin: str) -> None:
    if not pin:
        clear_pin(state_dir)
        return
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + pin.encode("utf-8")).hexdigest()
    path = _pin_path(state_dir)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"{salt.hex()}${digest}")


def clear_pin(state_dir: str) -> None:
    try:
        os.remove(_pin_path(state_dir))
    except OSError:
        pass


def set_totp(state_dir: str, secret_b32: str) -> None:
    """Enroll a panel-lock TOTP secret (base32). Stored 0600 at _totp_path via
    host.totp's writer. Empty/None clears it, mirroring set_pin's shape."""
    if not secret_b32:
        clear_totp(state_dir)
        return
    _totp.save(_totp_path(state_dir), secret_b32)


def clear_totp(state_dir: str) -> None:
    _totp.clear(_totp_path(state_dir))


def load_totp(state_dir: str) -> str | None:
    """The stored panel-lock TOTP secret (base32), or None if not enrolled."""
    return _totp.load(_totp_path(state_dir))


def verify_pin(state_dir: str, pin: str) -> bool:
    try:
        with open(_pin_path(state_dir), "r", encoding="utf-8") as fh:
            salt_hex, _, digest = fh.read().strip().partition("$")
        want = hashlib.sha256(bytes.fromhex(salt_hex) +
                              pin.encode("utf-8")).hexdigest()
        return hmac.compare_digest(want, digest)
    except (OSError, ValueError):
        return False


def _sealed_pin_ok(code: str) -> bool:
    """True if `code` matches the host's sealed setup PIN (secretstore).

    This is the admin emergency override: even if the at-the-desk operator
    forgot the panel-lock PIN/TOTP, whoever holds the setup PIN can unlock.
    Swallows every error (missing seal, no crypto backend, bad machine-id) so
    a locker prompt never stack-traces — it just means "no override available"."""
    if _secretstore is None or not code:
        return False
    try:
        return bool(_secretstore.verify_pin(code))
    except Exception:                              # noqa: BLE001
        return False


def verify_any(state_dir: str, code: str) -> bool:
    """True if `code` matches the saved panel-lock PIN, the saved TOTP, OR the
    host's sealed setup PIN (admin override). Any of these may be unset — the
    operator typically picks one. Empty code never matches.

    Order: try TOTP first when enrolled (more secure; rotating codes), then
    the static panel PIN, then the sealed admin PIN. Every path uses
    hmac.compare_digest internally so timing doesn't disclose which matched."""
    if not code or not code.strip():
        return False
    code = code.strip()
    if totp_is_set(state_dir):
        s = load_totp(state_dir)
        if s and _totp.verify(s, code):
            return True
    if pin_is_set(state_dir) and verify_pin(state_dir, code):
        return True
    if _sealed_pin_ok(code):
        return True
    return False


# --- the GTK lock window -------------------------------------------------- #
class KioskLocker:
    """Holds a single lock window. Idempotent — calling lock() while locked
    is a no-op. Owns its own backoff timer state."""

    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        self._win = None
        self._entry = None
        self._err = None
        self._unlock_btn = None
        self._fails = 0
        self._on_unlock = None

    @property
    def is_locked(self) -> bool:
        return self._win is not None

    def lock(self, on_unlock=None):
        """Show the lock overlay. `on_unlock` is called once the operator
        enters the right code."""
        if self._win is not None:
            self._win.present()
            return
        # Fail CLOSED: with no PIN/TOTP/seal enrolled there is nothing to
        # verify against, so a lock overlay would be purely decorative (any
        # keypress would dismiss it) — worse than none, since it gives a false
        # sense of security on an unattended-by-design wall. Refuse to lock and
        # tell the operator to enroll a credential. (Happy path — a credential
        # present — falls straight through to _build() exactly as before.)
        if not self._has_credential():
            self._advise_no_credential()
            return
        self._on_unlock = on_unlock
        self._build()

    def unlock(self):
        """Force-unlock (used by an admin programmatic emergency-clear)."""
        self._teardown()

    def _advise_no_credential(self):
        """Themed, self-disposing advisory shown instead of a decorative lock
        when no unlock credential is enrolled. Non-blocking; the OK button
        destroys the card. Reuses the _build() CSS/idiom so it reads correctly
        on any operator theme."""
        try:
            _style.apply_css()
        except Exception:                          # noqa: BLE001 — never block
            pass
        win = Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
        win.set_decorated(False)
        win.set_resizable(False)
        win.set_skip_taskbar_hint(True)
        win.set_keep_above(True)
        win.set_position(Gtk.WindowPosition.CENTER)
        card = Gtk.Frame()
        card.get_style_context().add_class("soc-config")
        card.set_size_request(420, 0)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(20)
        title = Gtk.Label(label="⚠  Wall NOT locked")
        title.set_xalign(0.5)
        title.get_style_context().add_class("soc-config-title")
        sub = Gtk.Label(label="No panel-lock credential is enrolled, so the lock "
                              "would be decorative.\nSet a panel-lock PIN first: "
                              "⚙ Settings → Security.")
        sub.set_xalign(0.5)
        sub.set_line_wrap(True)
        sub.get_style_context().add_class("soc-config-sub")
        ok = Gtk.Button(label="OK")
        ok.get_style_context().add_class("soc-config-primary")
        ok.connect("clicked", lambda *_: win.destroy())
        for w in (title, sub, ok):
            box.pack_start(w, False, False, 0)
        card.add(box)
        win.add(card)
        win.show_all()

    # --- internals -----
    def _build(self):
        # Install the screen-wide wall CSS so the lock card's soc-config-* classes
        # resolve. The live wall (main.py) only installs scoped providers for the
        # unlock dialog, never style.apply_css(); without this the lock overlay's
        # title/hint/error labels fall back to the operator's GTK stock theme —
        # near-black text on the 55%-black overlay (dark-on-dark, unreadable).
        # apply_css() is idempotent + GTK-only, safe to call here on the main loop.
        try:
            _style.apply_css()
        except Exception:                          # noqa: BLE001 — never block lock
            pass
        win = Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
        win.set_decorated(False)
        win.set_resizable(False)
        win.set_skip_taskbar_hint(True)
        win.set_skip_pager_hint(True)
        win.set_keep_above(True)
        win.set_modal(False)
        # Try transparency (RGBA visual) — the panels stay readable
        # underneath. Falls back to opaque (still functional) on a screen
        # without a compositor.
        screen = win.get_screen()
        visual = screen.get_rgba_visual() if screen else None
        if visual is not None and screen.is_composited():
            win.set_visual(visual)
            win.set_app_paintable(True)
            win.connect("draw", lambda w, cr: (
                cr.set_source_rgba(0, 0, 0, 0.55),
                cr.set_operator(__import__("cairo").OPERATOR_SOURCE),
                cr.paint(), False)[3])

        # Event mask: every interactive input must hit us, not the panels.
        win.add_events(Gdk.EventMask.BUTTON_PRESS_MASK |
                        Gdk.EventMask.BUTTON_RELEASE_MASK |
                        Gdk.EventMask.SCROLL_MASK |
                        Gdk.EventMask.POINTER_MOTION_MASK |
                        Gdk.EventMask.KEY_PRESS_MASK |
                        Gdk.EventMask.KEY_RELEASE_MASK)
        # Swallow stray clicks/keys/scrolls/motion that aren't on the unlock
        # card itself. The card's own widgets handle their own events.
        for sig in ("button-press-event", "button-release-event",
                    "scroll-event"):
            win.connect(sig, lambda *_: True)
        win.connect("delete-event", lambda *_: True)      # ignore window-close
        # Esc/F11 must not bypass the lock.
        win.connect("key-press-event", self._on_key)

        # Centered unlock card. Tag it soc-config so it gets the solid dark panel
        # background (#0b1020) — otherwise the card is a transparent frame and the
        # entry/labels float on the dim overlay with no readable card surface.
        card = Gtk.Frame()
        card.get_style_context().add_class("soc-config")
        card.set_halign(Gtk.Align.CENTER)
        card.set_valign(Gtk.Align.CENTER)
        card.set_size_request(380, 230)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(20)
        title = Gtk.Label(label="🔒  Wall locked")
        title.set_xalign(0.5)
        title.get_style_context().add_class("soc-config-title")
        hint = self._hint_text()
        hint_lbl = Gtk.Label(label=hint)
        hint_lbl.set_xalign(0.5)
        hint_lbl.set_line_wrap(True)
        hint_lbl.get_style_context().add_class("soc-config-sub")
        self._entry = Gtk.Entry()
        self._entry.set_visibility(False)
        self._entry.set_input_purpose(Gtk.InputPurpose.PIN)
        self._entry.set_alignment(0.5)
        self._entry.set_placeholder_text("PIN or 6-digit code")
        self._entry.connect("activate", lambda *_: self._try())
        self._err = Gtk.Label(label="")
        self._err.set_xalign(0.5)
        self._err.get_style_context().add_class("soc-config-error")
        self._unlock_btn = Gtk.Button(label="Unlock")
        self._unlock_btn.get_style_context().add_class("soc-config-primary")
        self._unlock_btn.connect("clicked", lambda *_: self._try())
        for w in (title, hint_lbl, self._entry, self._err, self._unlock_btn):
            box.pack_start(w, False, False, 0)
        card.add(box)
        win.add(card)

        # Fullscreen so it covers all monitors / the entire desktop.
        win.fullscreen()
        win.show_all()
        win.grab_focus()
        self._entry.grab_focus()
        self._win = win

    def _has_credential(self) -> bool:
        """Any unlock credential at all: panel PIN, panel TOTP, or a host
        seal (the admin override is a real credential)."""
        if pin_is_set(self.state_dir) or totp_is_set(self.state_dir):
            return True
        if _secretstore is not None:
            try:
                return bool(_secretstore.is_sealed())
            except Exception:                          # noqa: BLE001
                return False
        return False

    def _hint_text(self) -> str:
        has_pin = pin_is_set(self.state_dir)
        has_totp = totp_is_set(self.state_dir)
        if has_pin and has_totp:
            return "Enter your PIN or a 6-digit authenticator code."
        if has_totp:
            return "Enter the 6-digit code from your authenticator app."
        if has_pin:
            return "Enter your PIN."
        # Only the host-sealed setup PIN remains as an unlock path. (lock()
        # refuses to build the overlay when no credential is enrolled, so the
        # no-credential case is unreachable here.)
        return "Enter the host setup PIN to unlock."

    def _on_key(self, _w, event):
        # Esc must not close the lock; Enter activates.
        if event.keyval == Gdk.KEY_Escape:
            return True
        if event.keyval in (Gdk.KEY_Return, Gdk.KEY_KP_Enter):
            self._try()
            return True
        return False

    def _try(self):
        code = (self._entry.get_text() or "").strip()
        # _try() is only reachable with a credential present (lock() refuses to
        # build the overlay otherwise), so we gate strictly on verify_any() —
        # there is no fail-open "no credential → always unlock" path.
        if verify_any(self.state_dir, code):
            self._fails = 0
            self._teardown()
            if self._on_unlock:
                try:
                    self._on_unlock()
                except Exception:                          # noqa: BLE001
                    pass
            return
        self._entry.set_text("")
        self._fails += 1
        if self._fails >= 3:
            wait = min(5 * (self._fails - 2), 60)
            self._err.set_text(f"Incorrect — locked for {wait}s "
                               f"({self._fails} attempts)")
            self._entry.set_sensitive(False)
            self._unlock_btn.set_sensitive(False)
            GLib.timeout_add_seconds(wait, self._rearm)
        else:
            self._err.set_text("Incorrect")

    def _rearm(self):
        if not self._entry:
            return False
        self._entry.set_sensitive(True)
        self._unlock_btn.set_sensitive(True)
        self._err.set_text("")
        self._entry.grab_focus()
        return False

    def _teardown(self):
        if self._win is None:
            return
        try:
            self._win.destroy()
        finally:
            self._win = None
            self._entry = None
            self._err = None
            self._unlock_btn = None
