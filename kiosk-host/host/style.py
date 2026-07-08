"""
Shared look & feel for the wall.

apply_css()  — installs the application CSS once (dark background, status
               card styling). Safe to call multiple times.
PanelFrame   — wraps a panel's webview in a Gtk.Stack with a branded status
               page: "connecting…" while the first load runs, a clear
               offline/recovering card when the panel fails. The webview is
               crossfaded back in the moment a load finishes, so a dark cell
               on the wall always says *why* and what happens next (and the
               stock white WebKit error page is never shown).

A Gtk.Stack is used instead of a Gtk.Overlay on purpose: WebKitWebView renders
through its own native subwindow and paints OVER overlay siblings, so floating
cards above a live webview are not reliable across backends.

Chromium panels run in their own OS process and cannot carry GTK widgets;
their state goes to the journal instead.
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk  # noqa: E402

BACKGROUND = "#0b1020"

_CSS = b"""
window, grid, stack { background-color: #0b1020; }

.soc-status {
  background-color: rgba(10, 15, 32, 0.92);
  border: 1px solid rgba(126, 150, 255, 0.28);
  border-radius: 10px;
  padding: 18px 28px;
}
.soc-status.error { border-color: rgba(255, 120, 110, 0.55); }

.soc-status-id {
  color: #7e96ff;
  font-weight: bold;
  font-size: 12px;
  letter-spacing: 2px;
}
.soc-status.error .soc-status-id { color: #ff9c8f; }

.soc-status-msg { color: #c9d3f2; font-size: 15px; }
.soc-status.error .soc-status-msg { color: #ffc2b8; }

.soc-status spinner { color: #7e96ff; min-width: 22px; min-height: 22px; }

/* on-screen config window + corner gear */
.soc-config { background-color: #0b1020; }
.soc-config-title { color: #e7ecff; font-size: 18px; font-weight: bold; }
.soc-config-sub  { color: #8694c4; font-size: 12px; }
.soc-config-tag  { color: #7e96ff; font-weight: bold; }
.soc-config-ok    { color: #57d9a3; font-size: 12px; }
.soc-config-error { color: #ff8f80; font-size: 12px; }
.soc-config entry {
  background-color: #131a31; color: #e7ecff;
  border: 1px solid rgba(126,150,255,0.3); border-radius: 6px; padding: 6px 8px;
}
.soc-config entry:focus { border-color: #7e96ff; }
.soc-config button {
  background-image: none; background-color: #1b2b4a; color: #c9d3f2;
  border: 1px solid rgba(126,150,255,0.3); border-radius: 6px; padding: 6px 12px;
}
.soc-config-primary {
  background-color: #2f4fd0; color: #ffffff; border-color: #2f4fd0;
}
.soc-config-sec { color: #8694c4; }

.soc-gear {
  background-color: rgba(20,28,54,0.72);
  border: 1px solid rgba(126,150,255,0.35);
  border-radius: 8px; padding: 3px 12px; margin: 0 2px;
  color: #aeb9e6; font-size: 13px; font-weight: bold;
}
.soc-gear:hover { background-color: rgba(47,79,208,0.85); color: #ffffff; }

/* toolbar action buttons (Lock, VPN log) -- share the gear's look */
.soc-toolbar-action {
  background-color: rgba(20,28,54,0.72);
  border: 1px solid rgba(126,150,255,0.35);
  border-radius: 8px; padding: 3px 12px; margin: 0 2px;
  color: #aeb9e6; font-size: 13px; font-weight: bold;
}
.soc-toolbar-action:hover { background-color: rgba(47,79,208,0.85); color: #ffffff; }

/* boot-time file-integrity drift banner (above the toolbar) */
.soc-warn-bar {
  background-color: rgba(120,70,12,0.92);
  border-bottom: 1px solid rgba(255,180,80,0.5);
}
.soc-warn-bar label { color: #ffe6c2; font-weight: bold; }

/* top toolbar (always-visible controls; webviews can't paint over it) */
.soc-toolbar {
  background-color: #0a0f1f;
  border-bottom: 1px solid rgba(126,150,255,0.18);
  padding: 4px 8px;
}

/* VPN status pill (top of the wall) */
.soc-vpn-pill {
  background-image: none;
  background-color: rgba(20,28,54,0.82);
  border: 1px solid rgba(126,150,255,0.30);
  border-radius: 12px; padding: 3px 14px; margin: 0 2px;
  color: #c9d3f2; font-size: 13px; font-weight: bold;
}
.soc-vpn-pill.online    { border-color: rgba(87,217,163,0.7);  color: #57d9a3; }
.soc-vpn-pill.offline   { border-color: rgba(255,120,110,0.7); color: #ff8f80; }
.soc-vpn-pill.checking  { color: #d9c66a; }
.soc-vpn-pill.unconfigured { color: #8694c4; }
"""

_applied = False


def apply_css():
    """Install the wall CSS for the whole screen (idempotent)."""
    global _applied
    if _applied:
        return
    screen = Gdk.Screen.get_default()
    if screen is None:
        return
    provider = Gtk.CssProvider()
    provider.load_from_data(_CSS)
    Gtk.StyleContext.add_provider_for_screen(
        screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _applied = True


class _StatusCard(Gtk.Box):
    """Centered card: panel name, spinner, one-line message."""

    def __init__(self, panel_id: str):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.set_halign(Gtk.Align.CENTER)
        self.set_valign(Gtk.Align.CENTER)
        self.get_style_context().add_class("soc-status")

        self._id = Gtk.Label(label=panel_id.upper())
        self._id.get_style_context().add_class("soc-status-id")
        self._spinner = Gtk.Spinner()
        self._msg = Gtk.Label(label="")
        self._msg.get_style_context().add_class("soc-status-msg")
        self._msg.set_line_wrap(True)
        self._msg.set_max_width_chars(46)
        self._msg.set_justify(Gtk.Justification.CENTER)

        self.pack_start(self._id, False, False, 0)
        self.pack_start(self._spinner, False, False, 0)
        self.pack_start(self._msg, False, False, 0)

    def set_state(self, message: str, error: bool, busy: bool):
        ctx = self.get_style_context()
        if error:
            ctx.add_class("error")
        else:
            ctx.remove_class("error")
        self._msg.set_text(message)
        if busy:
            self._spinner.start()
        else:
            self._spinner.stop()
        self._spinner.set_visible(busy)


class PanelFrame(Gtk.Stack):
    """content page (the webview) + status page, crossfaded."""

    def __init__(self, panel_id: str, widget):
        super().__init__()
        apply_css()
        # NONE, not CROSSFADE: a crossfade snapshots the outgoing child to an
        # offscreen surface; a WebKitWebView renders through its own (often
        # native-window) pipeline that doesn't always snapshot cleanly. A plain
        # map/unmap switch shows the card reliably on every backend.
        self.set_transition_type(Gtk.StackTransitionType.NONE)
        self._content = widget
        self._card = _StatusCard(panel_id)
        self.add_named(widget, "content")
        self.add_named(self._card, "status")

    def update(self, message: str, error: bool = False, busy: bool = True):
        """Show the status page with this message."""
        self._card.set_state(message, error, busy)
        self.set_visible_child_name("status")

    def clear(self):
        """Back to the live panel."""
        self._card.set_state("", False, False)
        self.set_visible_child_name("content")
