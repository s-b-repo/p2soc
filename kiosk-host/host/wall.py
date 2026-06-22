"""
Single-window layout (display.layout: single): one fullscreen top-level window
holding every WebKit panel in a homogeneous GtkGrid.

This is the native Wayland path — Wayland clients cannot position their own
windows, but a grid inside ONE fullscreen window needs no window management at
all, so it works identically under cage, labwc, sway, Openbox or a bare Xvfb.
Cells track the real screen size automatically (no resolution detection), and
`display.gap` becomes the grid spacing.

Chromium panels cannot be embedded (they are separate OS processes); config
validation rejects layout: single with engine: chromium.
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk  # noqa: E402

from . import style  # noqa: E402


class WallWindow:
    def __init__(self, conf, log, on_destroy=None, on_config=None, on_vpn=None):
        self.conf = conf
        self.log = log
        self.on_config = on_config        # callable() -> open the config window
        self.on_vpn = on_vpn              # callable() -> re-check / reconnect VPN
        self.vpn_pill = None
        win = Gtk.Window()
        win.set_title("soc-wall")
        try:
            win.set_wmclass("soc-wall", "soc-wall")       # X11 only; harmless on Wayland
        except Exception:
            pass

        grid = Gtk.Grid()
        grid.set_row_homogeneous(True)
        grid.set_column_homogeneous(True)
        grid.set_row_spacing(conf.display.gap)
        grid.set_column_spacing(conf.display.gap)

        style.apply_css()

        # A real top toolbar (NOT an overlay): a loaded WebKitWebView is a native
        # window that paints over GTK overlay siblings, which would hide a
        # floating gear once a panel shows a page. Putting the controls in their
        # own region above the grid keeps them always visible + clickable.
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        toolbar.get_style_context().add_class("soc-toolbar")
        pill = Gtk.Button(label="VPN: …")
        pill.get_style_context().add_class("soc-vpn-pill")
        pill.get_style_context().add_class("unconfigured")
        pill.set_tooltip_text("VPN status — click to re-check / reconnect")
        pill.connect("clicked", lambda *_: self.on_vpn and self.on_vpn())
        self.vpn_pill = pill
        toolbar.pack_start(pill, False, False, 0)
        toolbar.pack_start(Gtk.Box(), True, True, 0)        # spacer
        if on_config is not None:
            gear = Gtk.Button(label="⚙ Settings")
            gear.get_style_context().add_class("soc-gear")
            gear.set_tooltip_text("Configure panels (Ctrl+Shift+C)")
            gear.connect("clicked", lambda *_: self.on_config and self.on_config())
            toolbar.pack_end(gear, False, False, 0)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        vbox.pack_start(toolbar, False, False, 0)
        vbox.pack_start(grid, True, True, 0)
        win.add(vbox)

        win.connect("key-press-event", self._on_key)
        # window-wide accelerator so Ctrl+Shift+C still opens settings even when
        # a webview has the keyboard focus
        if on_config is not None:
            accel = Gtk.AccelGroup()
            win.add_accel_group(accel)
            key, mod = Gtk.accelerator_parse("<Control><Shift>c")
            if key:
                accel.connect(key, mod, 0, self._accel_config)

        if on_destroy:
            # losing the wall window (e.g. the compositor killed it) leaves
            # nothing on screen — exit so the launcher restarts the host
            win.connect("destroy", lambda *_: on_destroy())

        self.window = win
        self.grid = grid

    def _accel_config(self, *_):
        if self.on_config:
            self.on_config()
        return True

    def _on_key(self, _w, event):
        ctrl = event.state & Gdk.ModifierType.CONTROL_MASK
        shift = event.state & Gdk.ModifierType.SHIFT_MASK
        # Ctrl+Shift+C opens the on-screen config
        if ctrl and shift and event.keyval in (Gdk.KEY_c, Gdk.KEY_C):
            if self.on_config:
                self.on_config()
            return True
        # F11 toggles fullscreen (handy when running windowed/in dev)
        if event.keyval == Gdk.KEY_F11:
            self._toggle_fullscreen()
            return True
        return False

    def _toggle_fullscreen(self):
        self._fullscreen = not getattr(self, "_fullscreen", True)
        if self._fullscreen:
            self.window.fullscreen()
            self._fit_to_screen()
        else:
            self.window.unfullscreen()

    def set_vpn_status(self, state: str, label: str):
        """Update the pill. `state` in online|offline|unconfigured|checking."""
        if self.vpn_pill is None:
            return
        ctx = self.vpn_pill.get_style_context()
        for c in ("online", "offline", "unconfigured", "checking"):
            ctx.remove_class(c)
        ctx.add_class(state)
        dot = {"online": "● ", "offline": "● ", "checking": "… "}.get(state, "")
        self.vpn_pill.set_label(f"{dot}{label}")

    def attach(self, panel, widget):
        col, row = panel.grid
        widget.set_hexpand(True)
        widget.set_vexpand(True)
        self.grid.attach(widget, col, row, 1, 1)

    def _screen_size(self):
        w, h = self.conf.display.width, self.conf.display.height
        try:
            disp = Gdk.Display.get_default()
            mon = disp.get_primary_monitor() or disp.get_monitor(0)
            geo = mon.get_geometry()
            if geo.width > 0 and geo.height > 0:
                w, h = geo.width, geo.height
        except Exception:  # noqa: BLE001
            pass
        return w, h

    def _fit_to_screen(self, *_):
        """Resize the window to fill the current screen. Needed when there is no
        window manager to maximise us (a resized Xephyr, a bare Xvfb, or a
        resolution/monitor change), where fullscreen() alone is a no-op."""
        w, h = self._screen_size()
        try:
            self.window.move(0, 0)
            self.window.resize(w, h)
        except Exception:  # noqa: BLE001
            pass
        return False

    def show(self):
        self._fullscreen = True
        w, h = self._screen_size()
        self.window.set_default_size(w, h)
        self.window.fullscreen()
        self.window.show_all()
        self._fit_to_screen()
        # keep filling the screen when it changes size under us: a resized
        # nested window (Xephyr/cage), a monitor hotplug, or a mode switch.
        scr = Gdk.Screen.get_default()
        if scr is not None:
            scr.connect("size-changed", self._fit_to_screen)
            scr.connect("monitors-changed", self._fit_to_screen)
        # also re-fit shortly after first map (some compositors settle late)
        from gi.repository import GLib
        GLib.timeout_add(400, self._fit_to_screen)
        self.log(f"wall window shown (single-window layout, {w}x{h}; "
                 f"F11 toggles fullscreen)")
