"""
Visible GUI error dialog for the SOC-wall launch path — the fail-safe.

A desktop (.desktop, Terminal=false) launch discards stderr, so when a helper
script fails the icon just looks dead ("nothing happens"). This module is the
fail-safe: the launcher scripts run ``python -m host.guierror "<title>" "<detail>"``
after a helper exits non-zero, popping a themed GTK dialog that TELLS the operator
the cause (and how to recover) instead of dying silently. With no display it falls
back to printing, so it is always safe to call.

Styling flows from host.branding (the same green-on-white console palette), so a
rebrand reskins it too. Lazy ``import gi`` keeps the headless/print path light.

Usage:  python -m host.guierror "TITLE" "DETAIL"
"""
from __future__ import annotations

import os
import sys


def show(title: str, detail: str = "") -> int:
    """Pop a themed error window (blocks until closed). Prints + returns on no display."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        sys.stderr.write(f"{title}\n{detail}\n")
        return 0
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, Gdk
    except Exception as e:  # noqa: BLE001 — GTK missing: degrade to stderr, never crash.
        sys.stderr.write(f"{title}\n{detail}\n(guierror: GTK unavailable: {e})\n")
        return 0

    try:
        from host import branding
        c = branding.load().get("colors", {})
    except Exception:  # noqa: BLE001 — branding optional; fall back to safe literals.
        c = {}
    bad = c.get("bad", "#C2374A")
    text = c.get("text", "#0B1F14")
    dim = c.get("text_dim", "#5B7567")
    bg = c.get("background", "#FFFFFF")
    border = c.get("border", "#CFE0D4")
    sunken = c.get("surface_bottom") or "#EAF1EC"
    accent_strong = c.get("accent_strong") or "#157A49"

    css = (
        f"window {{ background-color: {bg}; color: {text}; }}"
        f".soc-err-bar {{ border-top: 3px solid {bad}; }}"
        f".soc-err-title {{ color: {bad}; font-weight: bold; font-size: 15px; }}"
        f".soc-err-detail {{ color: {text}; font-family: monospace; font-size: 11px; }}"
        f".soc-err-hint {{ color: {dim}; }}"
        f".soc-err-detail-frame {{ border: 1px solid {border}; border-radius: 5px; "
        f"  background-color: {sunken}; padding: 8px; }}"
        # Close as a branding ghost button — not a stock-light island on dark themes.
        f"button.soc-ghost {{ background-image: none; background-color: transparent;"
        f" color: {accent_strong}; border: 1px solid {border}; border-radius: 6px;"
        f" padding: 6px 14px; }}"
        f"button.soc-ghost:hover {{ background-color: {sunken};"
        f" border-color: {accent_strong}; }}"
    ).encode()
    provider = Gtk.CssProvider()
    provider.load_from_data(css)
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    win = Gtk.Window(title="SOC Wall")
    win.get_style_context().add_class("soc-err-bar")
    win.set_position(Gtk.WindowPosition.CENTER)
    win.set_default_size(560, -1)
    win.set_border_width(18)

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    win.add(box)

    t = Gtk.Label(xalign=0, label=title)
    t.get_style_context().add_class("soc-err-title")
    t.set_line_wrap(True)
    box.pack_start(t, False, False, 0)

    if detail:
        frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        frame.get_style_context().add_class("soc-err-detail-frame")
        sw = Gtk.ScrolledWindow()
        sw.set_min_content_height(150)
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        d = Gtk.Label(xalign=0, label=detail)
        d.get_style_context().add_class("soc-err-detail")
        d.set_line_wrap(True)
        d.set_selectable(True)
        d.set_valign(Gtk.Align.START)
        sw.add(d)
        frame.pack_start(sw, True, True, 0)
        box.pack_start(frame, True, True, 0)

    hint = Gtk.Label(xalign=0)
    hint.get_style_context().add_class("soc-err-hint")
    hint.set_markup('<span size="9500">Fix the cause shown above, then open '
                    '<b>Setup</b> again. For a text-mode wizard run '
                    '<tt>python3 setup.py wizard</tt>.</span>')
    hint.set_line_wrap(True)
    box.pack_start(hint, False, False, 0)

    btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    btns.set_halign(Gtk.Align.END)
    close = Gtk.Button(label="Close")
    close.get_style_context().add_class("soc-ghost")
    close.connect("clicked", lambda *_: Gtk.main_quit())
    btns.pack_start(close, False, False, 0)
    box.pack_start(btns, False, False, 0)

    win.connect("destroy", lambda *_: Gtk.main_quit())
    win.set_keep_above(True)
    win.show_all()
    Gtk.main()
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    title = argv[0] if argv else "SOC Wall: a helper failed to start"
    detail = argv[1] if len(argv) > 1 else ""
    return show(title, detail)


if __name__ == "__main__":
    sys.exit(main())
