"""
Shared look & feel for the wall, derived from branding so the setup wizard's theme
controls the wall itself, not just the control center.

TOKENS       — the semantic colour palette, rebuilt from branding.
apply_css()  — installs the application CSS once. Safe to call multiple times;
               apply_css(refresh=True) repaints the running wall after a theme
               change.
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

# Hard fallback palette anchor: used only when branding can't be imported (gi may
# not be ready, or a broken theme file). Everything else derives from branding.
_FALLBACK_BG = "#0b1020"

_applied = False
_provider = None


def _rgba(hexc: str, alpha: float) -> str:
    """#RRGGBB -> rgba(r,g,b,alpha). Tolerant: a malformed colour degrades to a
    mid-grey instead of raising out of the CSS build."""
    h = (hexc or "").lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    try:
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        r = g = b = 128
    return f"rgba({r},{g},{b},{alpha:.2f})"


def _build_tokens() -> dict:
    """Semantic colour tokens — the single source of truth for the wall palette.
    Every colour in _css() comes from here, and every token comes from branding,
    so the setup wizard's theme controls the wall itself (not just the control
    center). Falls back to the built-in dark palette if branding is unavailable."""
    try:
        from . import branding
        c = branding.load().get("colors", {}) or {}
    except Exception:                          # noqa: BLE001 — theming is best-effort
        branding = None
        c = {}

    def col(key, default):
        return c.get(key) or default

    bg = col("background", _FALLBACK_BG)
    surface = col("surface_top", "#131a31")
    sunken = col("surface_bottom", "#1b2b4a")
    border = col("border", "#1b2b4a")
    text = col("text", "#e7ecff")
    dim = col("text_dim", "#8694c4")
    primary = col("primary", "#7e96ff")
    strong = col("accent_strong", "#2f4fd0")
    good = col("good", "#57d9a3")
    warn = col("warn", "#ffb450")
    bad = col("bad", "#ff8f80")
    try:
        on_accent = branding.text_on(strong, light="#ffffff")
    except Exception:                          # noqa: BLE001
        on_accent = "#ffffff"
    return {
        "bg":            bg,                   # primary background (wall + config)
        "bg-toolbar":    _rgba(bg, 0.92),      # toolbar / headerbar
        "bg-elev":       surface,              # raised cells, inactive buttons
        "bg-elev-2":     sunken,               # entries, wells
        "bg-card":       _rgba(surface, 0.92),  # panel status card
        "border-soft":   _rgba(primary, 0.18),
        "border":        border,
        "border-accent": _rgba(primary, 0.30),
        "border-strong": _rgba(primary, 0.35),
        "fg":            text,                 # primary text
        "fg-soft":       _rgba(text, 0.88),    # body text
        "fg-muted":      _rgba(dim, 0.95),     # toolbar buttons, less-prominent text
        "fg-dim":        dim,                  # captions / sub-labels
        "accent":        strong,               # primary action fill
        "accent-text":   primary,              # accent foreground (links, tags)
        "accent-hover":  _rgba(primary, 0.85),
        "on-accent":     on_accent,            # label on an accent fill
        "ok":            good,                 # online / success
        "warn":          warn,                 # connecting / caution
        "warn-bg":       _rgba(warn, 0.15),    # drift-warning banner
        "err":           bad,                  # offline / destructive
        "err-soft":      _rgba(bad, 0.80),
        "err-bg":        _rgba(bad, 0.12),
    }


def _css() -> bytes:
    """Render the wall stylesheet from TOKENS."""
    t = TOKENS
    ok_ring = _rgba(t["ok"], 0.7)
    warn_ring = _rgba(t["warn"], 0.75)
    err_ring = _rgba(t["err"], 0.7)
    panel_btn = _rgba(t["bg-elev-2"], 0.72)
    pill_bg = _rgba(t["bg-elev-2"], 0.82)
    return f"""
window, grid, stack {{ background-color: {t['bg']}; }}

.soc-status {{
  background-color: {t['bg-card']};
  border: 1px solid {t['border-accent']};
  border-radius: 10px;
  padding: 18px 28px;
}}
.soc-status.error {{ border-color: {_rgba(t['err'], 0.55)}; }}

.soc-status-id {{
  color: {t['accent-text']};
  font-weight: bold;
  font-size: 12px;
  letter-spacing: 2px;
}}
.soc-status.error .soc-status-id {{ color: {t['err']}; }}

.soc-status-msg {{ color: {t['fg-soft']}; font-size: 15px; }}
.soc-status.error .soc-status-msg {{ color: {t['err-soft']}; }}

.soc-status spinner {{ color: {t['accent-text']}; min-width: 22px; min-height: 22px; }}

/* on-screen config window + corner gear */
.soc-config {{ background-color: {t['bg']}; }}
.soc-config-title {{ color: {t['fg']}; font-size: 18px; font-weight: bold; }}
.soc-config-sub  {{ color: {t['fg-dim']}; font-size: 12px; }}
.soc-config-tag  {{ color: {t['accent-text']}; font-weight: bold; }}
.soc-config-ok    {{ color: {t['ok']}; font-size: 12px; }}
.soc-config-error {{ color: {t['err']}; font-size: 12px; }}
.soc-config entry {{
  background-color: {t['bg-elev-2']}; color: {t['fg']};
  border: 1px solid {t['border-accent']}; border-radius: 6px; padding: 6px 8px;
}}
.soc-config entry:focus {{ border-color: {t['accent-text']}; }}
.soc-config button {{
  background-image: none; background-color: {t['bg-elev']}; color: {t['fg-soft']};
  border: 1px solid {t['border-accent']}; border-radius: 6px; padding: 6px 12px;
}}
.soc-config-primary {{
  background-color: {t['accent']}; color: {t['on-accent']}; border-color: {t['accent']};
}}
.soc-config-sec {{ color: {t['fg-dim']}; }}

/* Destructive buttons (Remove VPN, Delete vault item, Clear PIN): a subtle red
 * outline + label, so the intent is visible at a glance without screaming. */
.soc-config button.destructive-action,
.destructive-action {{
  background-color: {t['bg-elev']};
  color: {t['err']};
  border-color: {_rgba(t['err'], 0.5)};
}}
.soc-config button.destructive-action:hover,
.destructive-action:hover {{
  background-color: {t['err-bg']};
  border-color: {t['err']};
}}

/* toolbar action buttons (Settings, Lock, Shot, VPN log) */
.soc-gear, .soc-toolbar-action {{
  background-image: none;
  background-color: {panel_btn};
  border: 1px solid {t['border-strong']};
  border-radius: 8px; padding: 3px 12px; margin: 0 2px;
  color: {t['fg-muted']}; font-size: 13px; font-weight: bold;
}}
.soc-gear:hover, .soc-toolbar-action:hover {{
  background-color: {t['accent-hover']}; color: {t['on-accent']};
}}

/* boot-time file-integrity drift banner (above the toolbar) */
.soc-warn-bar {{
  background-color: {t['warn-bg']};
  border-bottom: 1px solid {_rgba(t['warn'], 0.45)};
}}
.soc-warn-bar label {{ color: {t['warn']}; font-weight: bold; }}

/* top toolbar (always-visible controls; webviews can't paint over it) */
.soc-toolbar {{
  background-color: {t['bg-toolbar']};
  border-bottom: 1px solid {t['border-soft']};
  padding: 4px 8px;
}}

/* VPN status pill (top of the wall). Traffic-light colours: green=online,
 * amber=connecting (probe timed out, still mid-handshake), red=offline. */
.soc-vpn-pill {{
  background-image: none;
  background-color: {pill_bg};
  border: 1px solid {t['border-accent']};
  border-radius: 12px; padding: 3px 14px; margin: 0 2px;
  color: {t['fg-soft']}; font-size: 13px; font-weight: bold;
}}
.soc-vpn-pill.online       {{ border-color: {ok_ring};   color: {t['ok']}; }}
.soc-vpn-pill.connecting   {{ border-color: {warn_ring}; color: {t['warn']}; }}
.soc-vpn-pill.offline      {{ border-color: {err_ring};  color: {t['err']}; }}
.soc-vpn-pill.checking     {{ color: {t['warn']}; }}
.soc-vpn-pill.unconfigured {{ color: {t['fg-dim']}; }}

/* Settings notebook tabs: match the palette, so they aren't a black-on-black
   default-theme artifact inside the themed settings window. */
notebook header {{ background-color: {t['bg']}; border-bottom: 1px solid {t['border']}; }}
notebook tab {{ background-color: {t['bg']}; color: {t['fg-dim']}; padding: 6px 14px;
  border: 1px solid transparent; border-bottom: none; }}
notebook tab:checked {{ background-color: {t['bg-elev']}; color: {t['fg']};
  border-color: {t['border']}; }}
notebook tab:hover {{ color: {t['accent-text']}; }}
""".encode("utf-8")


def _refresh():
    """Re-derive the palette and stylesheet from the current branding."""
    global TOKENS, BACKGROUND, _CSS
    TOKENS = _build_tokens()
    BACKGROUND = TOKENS["bg"]
    _CSS = _css()


# Populated at import (no GTK needed), so tests and modules can read them without
# a Gdk.Screen. apply_css(refresh=True) rebuilds them after a theme change.
TOKENS: dict = {}
BACKGROUND = _FALLBACK_BG
_CSS: bytes = b""
_refresh()


def apply_css(refresh: bool = False):
    """Install the wall CSS for the whole screen (idempotent). With refresh=True,
    re-read the theme and repaint the running wall in place — one provider for the
    life of the process, so a theme change can't stack duplicates."""
    global _applied, _provider
    if _applied and not refresh:
        return
    screen = Gdk.Screen.get_default()
    if screen is None:
        return
    if refresh:
        _refresh()
    if _provider is None:
        _provider = Gtk.CssProvider()
        Gtk.StyleContext.add_provider_for_screen(
            screen, _provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _provider.load_from_data(_CSS)
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
