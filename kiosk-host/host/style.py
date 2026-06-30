"""
Shared look & feel for the wall — derived from branding so the setup wizard's
theme controls the wall itself, not just the control center.

apply_css()  — installs the application CSS once. Re-apply on theme change.
PanelFrame   — wraps a panel's webview in a Gtk.Stack with a branded status
               page.
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk  # noqa: E402

# Hard fallback (no branding importable at module level — gi may not be ready).
_FALLBACK_BG = "#0b1020"

_applied = False
_provider = None
# Built on first apply_css(); TOKENS and _CSS exposed for tests.
TOKENS: dict = {}
_CSS: bytes = b""


def _rgba(hexc: str, alpha: float) -> str:
    """#RRGGBB → rgba(r, g, b, alpha)."""
    h = (hexc or "").lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    try:
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        r = g = b = 128
    return f"rgba({r},{g},{b},{alpha:.2f})"


def _build_css() -> bytes:
    """Build the wall CSS from branding.load(), falling back to the hardcoded
    dark theme if branding isn't importable."""
    try:
        from . import branding
        c = branding.load().get("colors", {})
    except Exception:
        c = {}

    def col(k, d):
        return c.get(k) or d

    bg = col("background", _FALLBACK_BG)
    surface = col("surface_top", "#141c36")
    sunken = col("surface_bottom", "#0d1224")
    border = col("border", "#1b2b4a")
    text = col("text", "#e7ecff")
    dim = col("text_dim", "#8694c4")
    accent = col("primary", "#7e96ff")
    accent_strong = col("accent_strong", "#2f4fd0")
    good = col("good", "#57d9a3")
    bad = col("bad", "#ff8f80")
    warn = col("warn", "#d9c66a")

    # Derived: text that reads on the accent fill
    try:
        on_accent = branding.text_on(accent_strong, light="#ffffff")
    except Exception:
        on_accent = "#ffffff"

    # Alpha-blended variants
    surface_a = _rgba(surface, 0.92)
    border_a = _rgba(border, 0.55) if border.startswith("#") else f"rgba(27,43,74,0.55)"
    accent_border_a = _rgba(accent, 0.30) if accent.startswith("#") else f"rgba(126,150,255,0.30)"
    accent_hover_a = _rgba(accent, 0.85) if accent.startswith("#") else f"rgba(47,79,208,0.85)"
    warn_bg_a = _rgba(warn, 0.15) if warn.startswith("#") else f"rgba(217,198,106,0.15)"
    warn_border_a = _rgba(warn, 0.45) if warn.startswith("#") else f"rgba(255,180,80,0.50)"
    toolbar_bg = _rgba(bg, 0.92)  # slightly darker toolbar

    css = f"""\
window, grid, stack {{ background-color: {bg}; }}

.soc-status {{
  background-color: {surface_a};
  border: 1px solid {border_a};
  border-radius: 10px;
  padding: 18px 28px;
}}
.soc-status.error {{ border-color: {_rgba(bad, 0.55)}; }}

.soc-status-id {{
  color: {accent};
  font-weight: bold;
  font-size: 12px;
  letter-spacing: 2px;
}}
.soc-status.error .soc-status-id {{ color: {bad}; }}

.soc-status-msg {{ color: {text}; font-size: 15px; }}
.soc-status.error .soc-status-msg {{ color: {_rgba(bad, 0.8) if bad.startswith('#') else '#ffc2b8'}; }}

.soc-status spinner {{ color: {accent}; min-width: 22px; min-height: 22px; }}

.soc-config {{ background-color: {bg}; }}
.soc-config-title {{ color: {text}; font-size: 18px; font-weight: bold; }}
.soc-config-sub  {{ color: {dim}; font-size: 12px; }}
.soc-config-tag  {{ color: {accent}; font-weight: bold; }}
.soc-config-ok    {{ color: {good}; font-size: 12px; }}
.soc-config-error {{ color: {bad}; font-size: 12px; }}
.soc-config entry {{
  background-color: {sunken}; color: {text};
  border: 1px solid {accent_border_a}; border-radius: 6px; padding: 6px 8px;
}}
.soc-config entry:focus {{ border-color: {accent}; }}
.soc-config button {{
  background-image: none; background-color: {surface}; color: {dim};
  border: 1px solid {accent_border_a}; border-radius: 6px; padding: 6px 12px;
}}
.soc-config-primary {{
  background-color: {accent_strong}; color: {on_accent}; border-color: {accent_strong};
}}
.soc-config-sec {{ color: {dim}; }}

.soc-gear {{
  background-color: {_rgba(sunken, 0.72)};
  border: 1px solid {_rgba(accent, 0.35)};
  border-radius: 8px; padding: 3px 12px; margin: 0 2px;
  color: {dim}; font-size: 13px; font-weight: bold;
}}
.soc-gear:hover {{ background-color: {accent_hover_a}; color: {on_accent}; }}

.soc-toolbar-action {{
  background-color: {_rgba(sunken, 0.72)};
  border: 1px solid {_rgba(accent, 0.35)};
  border-radius: 8px; padding: 3px 12px; margin: 0 2px;
  color: {dim}; font-size: 13px; font-weight: bold;
}}
.soc-toolbar-action:hover {{ background-color: {accent_hover_a}; color: {on_accent}; }}

.soc-warn-bar {{
  background-color: {warn_bg_a};
  border-bottom: 1px solid {warn_border_a};
}}
.soc-warn-bar label {{ color: {warn}; font-weight: bold; }}

.soc-toolbar {{
  background-color: {toolbar_bg};
  border-bottom: 1px solid {_rgba(accent, 0.18)};
  padding: 4px 8px;
}}

.soc-vpn-pill {{
  background-image: none;
  background-color: {_rgba(sunken, 0.82)};
  border: 1px solid {accent_border_a};
  border-radius: 12px; padding: 3px 14px; margin: 0 2px;
  color: {text}; font-size: 13px; font-weight: bold;
}}
.soc-vpn-pill.online    {{ border-color: {_rgba(good, 0.7) if good.startswith('#') else 'rgba(87,217,163,0.7)'}; color: {good}; }}
.soc-vpn-pill.connecting {{ border-color: {_rgba(accent, 0.7) if accent.startswith('#') else 'rgba(126,150,255,0.7)'}; color: {accent}; }}
.soc-vpn-pill.offline   {{ border-color: {_rgba(bad, 0.7) if bad.startswith('#') else 'rgba(255,120,110,0.7)'}; color: {bad}; }}
.soc-vpn-pill.checking  {{ color: {warn}; }}
.soc-vpn-pill.unconfigured {{ color: {dim}; }}

/* Locked-state border — visible on the PIN overlay card */
.soc-locked {{
  border: 2px solid {accent};
  border-radius: 12px;
}}

.destructive-action {{
  color: {bad};
  border-color: {_rgba(bad, 0.5)};
}}
.destructive-action:hover {{
  background-color: {_rgba(bad, 0.12)};
  border-color: {bad};
}}
"""
    return css.encode()


def apply_css():
    """Install the wall CSS for the whole screen (idempotent). Call again after
    a theme change to repaint the running wall."""
    global _applied, _provider, TOKENS, _CSS
    screen = Gdk.Screen.get_default()
    if screen is None:
        return
    _CSS = _build_css()
    TOKENS = _build_tokens()
    if _provider is None:
        _provider = Gtk.CssProvider()
        Gtk.StyleContext.add_provider_for_screen(
            screen, _provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        _applied = True
    _provider.load_from_data(_CSS)


def _build_tokens() -> dict:
    """Semantic colour tokens for the wall, derived from branding."""
    try:
        from . import branding
        c = branding.load().get("colors", {})
    except Exception:
        c = {}

    def col(k, d):
        return c.get(k) or d

    bg = col("background", "#0b1020")
    return {
        "bg": bg,
        "bg-toolbar": _rgba(bg, 0.92),
        "bg-elev": col("surface_top", "#141c36"),
        "fg": col("text", "#e7ecff"),
        "fg-soft": col("text", "#c9d3f2"),
        "fg-dim": col("text_dim", "#8694c4"),
        "accent": col("primary", "#7e96ff"),
        "accent-text": "#ffffff",  # text on accent fill
        "ok": col("good", "#57d9a3"),
        "warn": col("warn", "#d9c66a"),
        "err": col("bad", "#ff8f80"),
        "border": col("border", "#1b2b4a"),
    }


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
        self.set_transition_type(Gtk.StackTransitionType.NONE)
        self._content = widget
        self._card = _StatusCard(panel_id)
        self.add_named(widget, "content")
        self.add_named(self._card, "status")

    def update(self, message: str, error: bool = False, busy: bool = True):
        self._card.set_state(message, error, busy)
        self.set_visible_child_name("status")

    def clear(self):
        self._card.set_state("", False, False)
        self.set_visible_child_name("content")


# Populate tokens + CSS at import time (no GTK needed) so tests can inspect them
# without calling apply_css() which requires Gdk.Screen.
try:
    _CSS = _build_css()
    TOKENS = _build_tokens()
except Exception:
    pass
