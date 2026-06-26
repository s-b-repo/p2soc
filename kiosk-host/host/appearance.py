"""
SOC video-wall — APPEARANCE editor (GTK3 / PyGObject).

A self-contained theme editor: pick a built-in PRESET (SOC Green / Midnight /
High Contrast / Amber Ops) or tweak any of the 14 branding palette keys with
per-colour pickers, see it LIVE (a sample card + the whole surface recolour as
you change), and Save -> persist to branding.yaml (host.branding.save_colors).
The persisted branding.yaml IS the startup theme — the launcher, wizard and
guierror already read host.branding on every launch.

Reachable three ways:
  * standalone (startup / XDG / launcher tile):  python -m host.appearance
  * in the launcher menu (the 4th "Appearance" tile)  — embeds the same editor
  * in the setup wizard (the Appearance page)          — embeds the editor body

Headless-safe like host.setupgui: NO top-level ``import gi`` — gi is imported only
inside the GUI build path, so ``import host.appearance`` and the headless contract
below work where GTK cannot initialise a display (CI / make test):

    python -m host.appearance --check                 # validate wiring, no gi
    python -m host.appearance --list-presets
    python -m host.appearance --preset NAME --output FILE   # write a preset, no gi

GTK objects are created + mutated on the GTK main thread only (no threads).
"""
from __future__ import annotations

import gc
import os
import sys

from host import branding


# --------------------------------------------------------------------------- #
# Presets — pure data (NO gi). Each carries the COMPLETE 14-key palette so
# applying a preset is a total replace and live-apply never reads a missing key.
# --------------------------------------------------------------------------- #
PALETTE_KEYS = (
    "primary", "setup", "desktop", "kiosk", "background", "surface_top",
    "surface_bottom", "border", "text", "text_dim", "accent_strong",
    "good", "warn", "bad",
)

PRESETS: "dict[str, dict]" = {
    # The default — lifted verbatim from branding._DEFAULTS so "Reset to default"
    # is exact and a no-op against a fresh install.
    "soc-green": dict(branding._DEFAULTS["colors"]),
    # Dark console: near-black field, light green-grey text, same green family.
    "midnight": {
        "primary": "#2FD27E",
        "setup": "#2FD27E",
        "desktop": "#2FD27E",
        "kiosk": "#16B8B5",
        "background": "#0B1411",
        "surface_top": "#12211B",
        "surface_bottom": "#0E1A15",
        "border": "#24443A",
        "text": "#E6F2EB",
        "text_dim": "#8FB3A4",
        "accent_strong": "#1FA463",
        "good": "#2FD27E",
        "warn": "#E0A200",
        "bad": "#F2635A",
    },
    # Accessibility: pure black/white, WCAG-safe saturated accents.
    "high-contrast": {
        "primary": "#006B2D",
        "setup": "#006B2D",
        "desktop": "#006B2D",
        "kiosk": "#005A58",
        "background": "#FFFFFF",
        "surface_top": "#FFFFFF",
        "surface_bottom": "#F0F0F0",
        "border": "#000000",
        "text": "#000000",
        "text_dim": "#333333",
        "accent_strong": "#006B2D",
        "good": "#006B2D",
        "warn": "#8A5A00",
        "bad": "#B00000",
    },
    # Phosphor-amber NOC wall on near-black.
    "amber-ops": {
        "primary": "#E8A317",
        "setup": "#E8A317",
        "desktop": "#E8A317",
        "kiosk": "#C77A2A",
        "background": "#0C0A06",
        "surface_top": "#1A150C",
        "surface_bottom": "#13100A",
        "border": "#3A2F18",
        "text": "#F5E6C8",
        "text_dim": "#B9A47A",
        "accent_strong": "#C8860B",
        "good": "#E8A317",
        "warn": "#E8A317",
        "bad": "#E0533A",
    },
}

# Stable display order — soc-green first / selected by default.
PRESET_ORDER = ("soc-green", "midnight", "high-contrast", "amber-ops")

# Human labels for the preset combo (the keys are the on-disk / API names).
PRESET_LABELS = {
    "soc-green": "SOC Green / White  (default)",
    "midnight": "Midnight  (dark)",
    "high-contrast": "High Contrast",
    "amber-ops": "Amber Ops",
}

# Grouped picker layout: (group title, [(key, label), ...]).
_PICKER_GROUPS = (
    ("brand", [("primary", "Primary"), ("accent_strong", "Accent (strong)"),
               ("setup", "Setup card"), ("desktop", "Desktop card"),
               ("kiosk", "Kiosk card")]),
    ("surfaces", [("background", "Background"), ("surface_top", "Surface (top)"),
                  ("surface_bottom", "Surface (sunken)"), ("border", "Border")]),
    ("text", [("text", "Text"), ("text_dim", "Text (dim)")]),
    ("status", [("good", "Good"), ("warn", "Warn"), ("bad", "Bad")]),
)


# --------------------------------------------------------------------------- #
# Colour helpers — identical maths to launchermenu/setupgui so the sample card
# reads exactly like the real UI. No gi (pure string building).
# --------------------------------------------------------------------------- #
def _to_rgb(hexc: str) -> "tuple[int, int, int]":
    h = (hexc or "").lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    try:
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        return 136, 136, 136


def _rgba(hexc: str, alpha: float) -> str:
    r, g, b = _to_rgb(hexc)
    return f"rgba({r},{g},{b},{alpha})"


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_css(colors: dict) -> bytes:
    """The SINGLE source of the editor's own theme + sample-card CSS. Returns bytes
    (load_from_data wants bytes). Built from one f-string — no per-swatch
    concatenation — so a live colour change is a string rebuild + one CSS parse,
    never widget churn. Themes the WHOLE editor window (so it recolours live) plus
    the sample card, Save/Reset/Close buttons and the picker grid surface."""
    def col(k, d):
        return colors.get(k) or d
    bg = col("background", "#FFFFFF")
    s_top = col("surface_top", "#F4F8F5")
    s_bot = col("surface_bottom", "#EAF1EC")
    border = col("border", "#CFE0D4")
    text = col("text", "#0B1F14")
    text_dim = col("text_dim", "#5B7567")
    accent = col("primary", "#1FA463")
    accent_strong = col("accent_strong", "#157A49")
    good = col("good", "#1FA463")
    warn = col("warn", "#B8860B")
    bad = col("bad", "#C0341D")
    glow = _rgba(accent, 0.28)
    return f"""
window.soc-appearance {{ background-color: {bg}; }}
.soc-appearance {{ background-color: {bg}; color: {text}; }}
.soc-ap-header {{ background-color: {s_top};
  border-top: 2px solid {accent_strong}; border-bottom: 1px solid {border};
  padding: 14px 18px 12px 18px; }}
.soc-ap-body {{ background-color: {bg}; padding: 14px 18px 16px 18px; }}
.soc-ap-group {{ color: {text_dim}; font-family: monospace; }}

/* Text elements driven by CSS classes (NOT baked Pango foreground=) so they
   recolour LIVE with the provider — readable in any preview theme. */
.soc-ap-eyebrow {{ color: {accent}; font-family: monospace; font-weight: bold; }}
.soc-ap-title {{ color: {text}; font-weight: bold; }}
.soc-ap-sub {{ color: {text_dim}; }}
.soc-ap-dim {{ color: {text_dim}; font-family: monospace; }}
.soc-ap-label {{ color: {text}; }}

.soc-ap-sample {{ background-color: {s_top};
  border: 1px solid {border}; border-left: 4px solid {accent}; border-radius: 6px;
  padding: 13px 16px; }}
.soc-ap-sample-sunken {{ background-color: {s_bot};
  border: 1px solid {border}; border-radius: 5px; padding: 9px 12px; }}

.soc-ap-grid {{ background-color: {s_top};
  border: 1px solid {border}; border-radius: 6px; padding: 12px 14px; }}
.soc-ap-grid label {{ color: {text}; }}

button.soc-primary {{ background-image: none; background-color: {accent_strong};
  color: #FFFFFF; border: 1px solid {accent_strong}; border-radius: 6px;
  font-weight: bold; padding: 6px 14px; }}
button.soc-primary:hover {{ background-color: {accent}; border-color: {accent}; }}
button.soc-ghost {{ background-image: none; background-color: transparent;
  color: {accent_strong}; border: 1px solid {border}; border-radius: 6px;
  padding: 6px 12px; }}
button.soc-ghost:hover {{ background-color: {s_bot}; border-color: {accent}; }}

.soc-ap-status {{ color: {text_dim}; }}
.soc-ap-status-bad {{ color: {bad}; }}
.soc-ap-good {{ color: {good}; }}
.soc-ap-warn {{ color: {warn}; }}
.soc-ap-bad {{ color: {bad}; }}
.soc-ap-focus {{ box-shadow: 0 6px 18px {glow}; }}
""".encode()


# --------------------------------------------------------------------------- #
# Headless preset writer — NO gi. Mirrors setupgui's --preset/--output contract.
# --------------------------------------------------------------------------- #
def write_preset(name: str, output: str) -> int:
    """Write PRESETS[name]'s palette to `output` (a branding.yaml) via
    branding.save_colors. No gi, no display. Returns 0 / non-zero."""
    if name not in PRESETS:
        sys.stderr.write(
            f"appearance: unknown preset {name!r} (have: {', '.join(PRESET_ORDER)})\n")
        return 2
    try:
        path = branding.save_colors(dict(PRESETS[name]), path=output)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"appearance: could not write {output!r}: {e}\n")
        return 1
    sys.stdout.write(f"wrote preset {name!r} -> {path}\n")
    return 0


# --------------------------------------------------------------------------- #
# The editor — built lazily; all gi use lives here. Usable as a standalone window
# OR embedded (build_body) into the launcher tile / wizard page.
# --------------------------------------------------------------------------- #
class AppearanceEditor:
    """Wraps the live theme editor. Construct with the gi modules tuple plus two
    injected callbacks:

      on_apply(colors)  -> repaint the HOST surface live (launcher/wizard/standalone
                           provider.load_from_data). May be None.
      on_saved(colors)  -> called after a successful Save so the host repaints from
                           the now-persisted palette. May be None.

    The editor owns ONE Gtk.CssProvider for its own surface (self._provider),
    repainted via load_from_data on every change — never re-added to the screen.
    The 14 ColorButtons are created once; preset-apply sets their RGBA in place.
    """

    def __init__(self, gtk_mods, on_apply=None, on_saved=None):
        self.Gtk, self.Gdk, self.GdkPixbuf = gtk_mods
        self.on_apply = on_apply
        self.on_saved = on_saved
        self._colors = dict(branding.load(refresh=True).get("colors") or {})
        # ensure a full 14-key working copy even against a partial file
        for k in PALETTE_KEYS:
            self._colors.setdefault(k, PRESETS["soc-green"][k])
        self._pickers: "dict[str, object]" = {}
        self._provider = None      # the editor's OWN surface provider (screen-scoped)
        self._sample_provider = None  # repainted-only sample provider (window-scoped)
        self._screen = None
        self._status_label = None
        self._preset_combo = None
        self._suppress = False     # guard: don't fire on_change while setting RGBA
        self.window = None

    # ---- small helpers --------------------------------------------------- #
    def _rgba_of(self, hexc: str):
        rgba = self.Gdk.RGBA()
        rgba.parse(hexc)
        return rgba

    def _hex_of(self, rgba) -> str:
        """Gdk.RGBA -> #RRGGBB (round each channel * 255), the form branding wants."""
        r = round(rgba.red * 255)
        g = round(rgba.green * 255)
        b = round(rgba.blue * 255)
        return f"#{r:02X}{g:02X}{b:02X}"

    def _clabel(self, text, css_class, markup_attrs=""):
        """A label whose COLOUR comes from a CSS class (so it recolours live with
        the provider), not baked Pango foreground=. `markup_attrs` adds non-colour
        Pango span attrs (size/letter_spacing) only."""
        lbl = self.Gtk.Label(xalign=0)
        if markup_attrs:
            lbl.set_markup(f'<span {markup_attrs}>{_esc(text)}</span>')
        else:
            lbl.set_text(text)
        lbl.get_style_context().add_class(css_class)
        return lbl

    # ---- live apply ------------------------------------------------------ #
    def _on_change(self):
        """A picker or preset changed -> repaint the sample, then the host surface."""
        if self._sample_provider is not None:
            self._sample_provider.load_from_data(build_css(self._colors))
        if callable(self.on_apply):
            try:
                self.on_apply(dict(self._colors))
            except Exception:  # noqa: BLE001 — a host repaint must never crash the editor
                pass

    def _on_picker(self, key):
        def _cb(btn):
            if self._suppress:
                return
            self._colors[key] = self._hex_of(btn.get_rgba())
            self._on_change()
        return _cb

    def _apply_palette(self, palette: dict):
        """Set the working copy + every picker's RGBA from `palette` without
        firing 14 individual repaints (suppressed), then one repaint at the end."""
        self._suppress = True
        try:
            for k in PALETTE_KEYS:
                v = palette.get(k, self._colors.get(k))
                self._colors[k] = v
                pk = self._pickers.get(k)
                if pk is not None:
                    pk.set_rgba(self._rgba_of(v))
        finally:
            self._suppress = False
        self._on_change()

    def _on_preset(self, combo):
        idx = combo.get_active()
        if idx < 0 or idx >= len(PRESET_ORDER):
            return
        name = PRESET_ORDER[idx]
        self._apply_palette(PRESETS[name])
        self._set_status(f"loaded preset: {PRESET_LABELS.get(name, name)}")

    # ---- status ---------------------------------------------------------- #
    def _set_status(self, text, bad=False):
        if self._status_label is None:
            return
        col = branding.color("bad") if bad else branding.color("good")
        glyph = "✗ " if bad else "● "
        self._status_label.set_markup(
            f'<span font_family="monospace" foreground="{col}">{glyph}</span>'
            f'<span foreground="{col if bad else branding.color("text_dim")}">'
            f'{_esc(text)}</span>')

    # ---- save / reset ---------------------------------------------------- #
    def _on_save(self, _btn):
        try:
            path = branding.save_colors(dict(self._colors))
        except (OSError, ValueError) as e:
            msg = f"could not save theme: {e}"
            self._set_status(msg, bad=True)
            try:
                from host import guierror  # type: ignore
                guierror.show("Couldn't save the theme", str(e))
            except Exception:  # noqa: BLE001 — status line already shows it
                pass
            return
        branding.load(refresh=True)
        self._set_status(f"saved theme -> {path}")
        if callable(self.on_saved):
            try:
                self.on_saved(dict(self._colors))
            except Exception:  # noqa: BLE001
                pass

    def _on_reset(self, _btn):
        # Reset to the on-disk palette if it differs from the default, else default.
        self._apply_palette(PRESETS["soc-green"])
        if self._preset_combo is not None:
            self._suppress = True
            try:
                self._preset_combo.set_active(PRESET_ORDER.index("soc-green"))
            finally:
                self._suppress = False
        self._set_status("reset to SOC Green (default) — not yet saved")

    # ---- body (embeddable) ---------------------------------------------- #
    def build_body(self, parent_box):
        """Build the editor's widget tree into `parent_box` (any Gtk container).
        Used both by the standalone window and by the launcher tile / wizard page.
        Creates the sample provider (window-scoped) once and repaints it via
        load_from_data; never re-adds it to the screen."""
        Gtk = self.Gtk

        # The window/page-scoped sample provider — added ONCE at the parent's screen.
        if self._sample_provider is None:
            self._sample_provider = Gtk.CssProvider()
            self._sample_provider.load_from_data(build_css(self._colors))
            screen = self.Gdk.Screen.get_default()
            if screen is not None:
                Gtk.StyleContext.add_provider_for_screen(
                    screen, self._sample_provider,
                    Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION + 1)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        body.get_style_context().add_class("soc-ap-body")
        parent_box.pack_start(body, True, True, 0)

        # --- preset row ----------------------------------------------------
        prow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        prow.pack_start(self._clabel("Theme preset", "soc-ap-label"),
                        False, False, 0)
        combo = Gtk.ComboBoxText()
        for name in PRESET_ORDER:
            combo.append_text(PRESET_LABELS.get(name, name))
        combo.set_active(0)
        combo.connect("changed", self._on_preset)
        self._preset_combo = combo
        prow.pack_start(combo, True, True, 0)
        body.pack_start(prow, False, False, 0)

        # --- two columns: pickers (left) + live sample (right) -------------
        cols = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        body.pack_start(cols, True, True, 0)

        grid_frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        grid_frame.get_style_context().add_class("soc-ap-grid")
        cols.pack_start(grid_frame, False, False, 0)
        grid_frame.pack_start(self._clabel(
            "// palette", "soc-ap-dim",
            'font_family="monospace" size="8800"'), False, False, 0)

        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(5)
        grid_frame.pack_start(grid, False, False, 0)

        r = 0
        for group_title, keys in _PICKER_GROUPS:
            gl = self._clabel(
                group_title, "soc-ap-dim",
                'font_family="monospace" size="8200" letter_spacing="800"')
            gl.set_margin_top(4 if r else 0)
            grid.attach(gl, 0, r, 2, 1)
            r += 1
            for key, label in keys:
                lbl = self._clabel(label, "soc-ap-label", 'size="9800"')
                lbl.set_size_request(140, -1)
                btn = Gtk.ColorButton()
                btn.set_rgba(self._rgba_of(self._colors.get(
                    key, PRESETS["soc-green"][key])))
                btn.set_title(label)
                btn.connect("color-set", self._on_picker(key))
                self._pickers[key] = btn
                grid.attach(lbl, 0, r, 1, 1)
                grid.attach(btn, 1, r, 1, 1)
                r += 1

        # --- live sample card ---------------------------------------------
        sample_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        sample_col.set_hexpand(True)
        cols.pack_start(sample_col, True, True, 0)
        sample_col.pack_start(self._clabel(
            "// live preview", "soc-ap-dim",
            'font_family="monospace" size="8800"'), False, False, 0)
        sample_col.pack_start(self._build_sample(), False, False, 0)

        # --- status + buttons ---------------------------------------------
        self._status_label = Gtk.Label(xalign=0, wrap=True)
        self._status_label.get_style_context().add_class("soc-ap-status")
        body.pack_start(self._status_label, False, False, 0)
        self._set_status("pick a preset or a colour — Save persists it as the theme")

        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btns.set_halign(Gtk.Align.END)
        save = Gtk.Button.new_with_label("Save")
        save.get_style_context().add_class("soc-primary")
        save.connect("clicked", self._on_save)
        reset = Gtk.Button.new_with_label("Reset to default")
        reset.get_style_context().add_class("soc-ghost")
        reset.connect("clicked", self._on_reset)
        btns.pack_start(reset, False, False, 0)
        btns.pack_start(save, False, False, 0)
        body.pack_start(btns, False, False, 0)
        self._save_btn, self._reset_btn = save, reset
        return body

    def _build_sample(self):
        """A small mock of the real UI: a header eyebrow, a mock action tile, and
        good/warn/bad status dots — re-styled (never rebuilt) on every change."""
        Gtk = self.Gtk
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("soc-ap-sample")

        card.pack_start(self._clabel(
            "// sample", "soc-ap-eyebrow",
            'font_family="monospace" size="8200" letter_spacing="800"'),
            False, False, 0)

        tile = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        tile.get_style_context().add_class("soc-ap-sample-sunken")
        tile.pack_start(self._clabel("Action tile", "soc-ap-title",
                                     'size="12800" letter_spacing="-300"'),
                        False, False, 0)
        tile.pack_start(self._clabel("Theme preview surface", "soc-ap-sub",
                                     'size="9500"'), False, False, 0)
        card.pack_start(tile, False, False, 0)

        dots = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        for cls, name in (("soc-ap-good", "online"), ("soc-ap-warn", "warn"),
                          ("soc-ap-bad", "fault")):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
            d = Gtk.Label()
            d.get_style_context().add_class(cls)
            d.set_markup('<span size="11000">●</span>')
            row.pack_start(d, False, False, 0)
            row.pack_start(self._clabel(name, "soc-ap-sub", 'size="9000"'),
                           False, False, 0)
            dots.pack_start(row, False, False, 0)
        card.pack_start(dots, False, False, 0)
        return card

    # ---- standalone window ---------------------------------------------- #
    def build_window(self):
        """Build the editor as its own Gtk.Window (NOT a dialog, so the surface
        theme applies). Adds ONE screen-scoped editor provider (self._provider),
        repainted by on_apply so the whole window recolours live."""
        Gtk = self.Gtk
        b = branding.load()
        self._screen = self.Gdk.Screen.get_default()

        # The editor's OWN surface provider — added ONCE at the screen.
        self._provider = Gtk.CssProvider()
        self._provider.load_from_data(build_css(self._colors))
        if self._screen is not None:
            Gtk.StyleContext.add_provider_for_screen(
                self._screen, self._provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        # When standalone, on_apply repaints THIS provider so the window recolours.
        if self.on_apply is None:
            self.on_apply = lambda colors: self._provider.load_from_data(
                build_css(colors))

        win = Gtk.Window(
            title=(b.get("short_name") or b.get("name") or "SOC Wall") + " — Appearance")
        win.get_style_context().add_class("soc-appearance")
        win.set_resizable(True)
        win.set_default_size(-1, -1)
        win.set_position(Gtk.WindowPosition.CENTER)
        icon = branding.icon_path()
        if icon:
            try:
                win.set_icon_from_file(icon)
            except Exception:
                pass

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        win.add(root)

        # header (matches launcher/wizard signature)
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header.get_style_context().add_class("soc-ap-header")
        if icon:
            try:
                px = self.GdkPixbuf.Pixbuf.new_from_file_at_size(icon, 40, 40)
                header.pack_start(Gtk.Image.new_from_pixbuf(px), False, False, 0)
            except Exception:
                pass
        htext = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        htext.set_valign(Gtk.Align.CENTER)
        htext.pack_start(self._clabel(
            "// appearance", "soc-ap-dim",
            'font_family="monospace" size="8200" letter_spacing="800"'),
            False, False, 0)
        htext.pack_start(self._clabel(
            "THEME", "soc-ap-eyebrow",
            'font_family="monospace" size="9000" letter_spacing="2600"'),
            False, False, 0)
        htext.pack_start(self._clabel(
            "Colours & presets — live, then Save", "soc-ap-sub", 'size="9500"'),
            False, False, 0)
        header.pack_start(htext, True, True, 0)
        root.pack_start(header, False, False, 0)

        self.build_body(root)

        win.connect("destroy", self._teardown)
        self.window = win
        gc.collect()
        return win

    # ---- teardown -------------------------------------------------------- #
    def _teardown(self, *_):
        """Drop refs + remove screen-scoped providers so repeated in-launcher
        open->close leaks nothing (the launcher window persists across opens)."""
        Gtk = self.Gtk
        screen = self._screen or self.Gdk.Screen.get_default()
        for prov in (self._provider, self._sample_provider):
            if prov is not None and screen is not None:
                try:
                    Gtk.StyleContext.remove_provider_for_screen(screen, prov)
                except Exception:  # noqa: BLE001
                    pass
        self._provider = None
        self._sample_provider = None
        self._pickers = {}
        self._status_label = None
        self._preset_combo = None
        self.window = None
        gc.collect()
        if getattr(self, "_quit_on_close", False):
            Gtk.main_quit()


# --------------------------------------------------------------------------- #
# Standalone GUI entry
# --------------------------------------------------------------------------- #
def run_gui(argv=None) -> int:
    """Standalone: build the editor window + run a Gtk.main loop. Imports gi lazily.
    On exception prints + returns 1 (the shell wrapper then pops guierror)."""
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, Gdk, GdkPixbuf
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"appearance: GTK unavailable ({e})\n")
        return 1

    try:
        editor = AppearanceEditor((Gtk, Gdk, GdkPixbuf))
        win = editor.build_window()
        editor._quit_on_close = True
        win.show_all()
        Gtk.main()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"appearance: editor failed to start ({e})\n")
        return 1
    return 0


# --------------------------------------------------------------------------- #
# CLI / self-check
# --------------------------------------------------------------------------- #
def _check() -> int:
    """Validate wiring with NO gi / NO display (the lint/CI smoke):
      * every PRESET has exactly the 14 branding keys,
      * build_css(p) is bytes for each preset,
      * save_colors round-trips a preset through a temp branding.yaml.
    """
    import tempfile
    keys = set(PALETTE_KEYS)
    assert set(branding._DEFAULTS["colors"]) == keys, "branding default key drift"
    assert tuple(PRESET_ORDER) and set(PRESET_ORDER) == set(PRESETS), \
        "PRESET_ORDER must match PRESETS"
    for name, palette in PRESETS.items():
        assert set(palette) == keys, f"preset {name!r} key mismatch: {set(palette) ^ keys}"
        css = build_css(palette)
        assert isinstance(css, (bytes, bytearray)) and css, f"build_css({name!r}) not bytes"
    # save round-trip in a temp file
    with tempfile.TemporaryDirectory() as d:
        target = os.path.join(d, "branding.yaml")
        path = branding.save_colors(dict(PRESETS["midnight"]), path=target)
        assert path == target, path
        reloaded = branding._load_file(target).get("colors") or {}
        for k, v in PRESETS["midnight"].items():
            assert (reloaded.get(k) or "").upper() == v.upper(), \
                f"round-trip mismatch for {k}: {reloaded.get(k)} != {v}"
        # comment-preserving round-trip: rewrite an existing commented file
        commented = os.path.join(d, "c.yaml")
        with open(commented, "w", encoding="utf-8") as fh:
            fh.write("# header comment\nname: \"Keep Me\"\ncolors:\n"
                     "  primary: \"#1FA463\"  # inline doc\n")
        branding.save_colors({"primary": "#abcdef"}, path=commented)
        body = open(commented, encoding="utf-8").read()
        assert "# header comment" in body and "Keep Me" in body and "inline doc" in body, \
            "comment-preserving write dropped comments/structure"
        assert "#ABCDEF" in body, "value not rewritten"
    print("appearance ok")
    return 0


def main(argv=None) -> int:
    import argparse
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(
        prog="host.appearance",
        description="SOC-wall theme editor (presets + per-colour pickers, live + persisted).")
    ap.add_argument("--check", action="store_true",
                    help="validate wiring (no gi / no display) and exit")
    ap.add_argument("--list-presets", action="store_true",
                    help="print the built-in preset names and exit")
    ap.add_argument("--preset", choices=tuple(PRESET_ORDER) or None,
                    help="HEADLESS: write this preset's palette to --output")
    ap.add_argument("--output", help="HEADLESS: branding.yaml path to write the preset to")
    args = ap.parse_args(argv)

    if args.check:
        try:
            return _check()
        except AssertionError as e:
            sys.stderr.write(f"appearance --check: {e}\n")
            return 1

    if args.list_presets:
        for name in PRESET_ORDER:
            print(f"{name}\t{PRESET_LABELS.get(name, name)}")
        return 0

    if args.preset or args.output:
        if not (args.preset and args.output):
            sys.stderr.write("appearance: --preset and --output must be given together\n")
            return 2
        return write_preset(args.preset, args.output)

    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        sys.stderr.write("appearance: no graphical display "
                         "(run this from your desktop session).\n")
        return 1
    return run_gui(argv)


if __name__ == "__main__":
    sys.exit(main())
