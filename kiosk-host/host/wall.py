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

import os

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import style  # noqa: E402


class WallWindow:
    def __init__(self, conf, log, on_destroy=None, on_config=None, on_vpn=None,
                 on_lock=None, on_show_vpn_log=None):
        self.conf = conf
        self.log = log
        self.on_config = on_config        # callable() -> open the config window
        self.on_vpn = on_vpn              # callable() -> re-check / reconnect VPN
        self.on_lock = on_lock            # callable() -> show kiosk-lock overlay
        # callable() -> open the live VPN log viewer WITHOUT triggering a
        # reconnect. Kept SEPARATE from the pill (which reconnects): the 📜
        # button only observes, the pill only restarts.
        self.on_show_vpn_log = on_show_vpn_log
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
            # pack_end pushes right; this lands rightmost.
            toolbar.pack_end(gear, False, False, 0)
        if on_lock is not None:
            # pack_end in reverse-visual order: gear is already on the right,
            # pack_end the lock NEXT so it sits to gear's LEFT.
            lock = Gtk.Button(label="🔒 Lock")
            lock.get_style_context().add_class("soc-toolbar-action")
            lock.set_tooltip_text("Lock the wall — unlock with PIN or TOTP "
                                  "(Ctrl+Alt+L). Panels stay visible.")
            lock.connect("clicked", lambda *_: self.on_lock and self.on_lock())
            toolbar.pack_end(lock, False, False, 0)
        # Screenshot button — saves wall state to ~/soc-wall-*.png
        ss_btn = Gtk.Button(label="📷 Shot")
        ss_btn.get_style_context().add_class("soc-toolbar-action")
        ss_btn.set_tooltip_text("Save a screenshot of the wall")
        ss_btn.connect("clicked", lambda *_: self._take_screenshot())
        toolbar.pack_end(ss_btn, False, False, 0)

        if on_show_vpn_log is not None:
            # Dedicated 'show the VPN log' button — distinct from the VPN
            # pill (which RECONNECTS), this just opens the live log viewer
            # so the operator can observe without forcing a restart.
            # Pack_end so it sits to the LEFT of the lock button.
            vlog = Gtk.Button(label="📜 VPN log")
            vlog.get_style_context().add_class("soc-toolbar-action")
            vlog.set_tooltip_text("Open the live VPN log viewer — streams "
                                  "`journalctl -u forti-vpn.service`. Does "
                                  "NOT reconnect the VPN (use the pill for "
                                  "that).")
            vlog.connect("clicked",
                         lambda *_: self.on_show_vpn_log and self.on_show_vpn_log())
            toolbar.pack_end(vlog, False, False, 0)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        vbox.pack_start(toolbar, False, False, 0)

        # Wrap grid in an overlay so the PIN lock can cover panels
        overlay = Gtk.Overlay()
        overlay.add(grid)
        self._lock_overlay = self._build_lock_overlay()
        overlay.add_overlay(self._lock_overlay)
        self._lock_overlay.set_visible(False)
        self._locked = False
        self._lock_entry = None  # set by _build_lock_overlay
        self._lock_err = None
        self._lock_fails = 0
        self._overlay = overlay

        vbox.pack_start(overlay, True, True, 0)
        win.add(vbox)

        win.connect("key-press-event", self._on_key)
        # window-wide accelerators so the hotkeys still work even when a webview
        # has the keyboard focus: Ctrl+Shift+C opens settings, Ctrl+Alt+L locks.
        if on_config is not None or on_lock is not None:
            accel = Gtk.AccelGroup()
            win.add_accel_group(accel)
            if on_config is not None:
                key, mod = Gtk.accelerator_parse("<Control><Shift>c")
                if key:
                    accel.connect(key, mod, 0, self._accel_config)
            if on_lock is not None:
                key, mod = Gtk.accelerator_parse("<Control><Alt>l")
                if key:
                    accel.connect(key, mod, 0, self._accel_lock)

        if on_destroy:
            # losing the wall window (e.g. the compositor killed it) leaves
            # nothing on screen — exit so the launcher restarts the host. Make
            # this fail-safe: if on_destroy (KioskHost.shutdown) raises BEFORE
            # it reaches Gtk.main_quit, the GTK loop would otherwise keep
            # spinning with no visible window — a dark, launcher-won't-restart
            # wall (the process is still alive). On the happy path shutdown
            # already calls Gtk.main_quit, so we just return; only force-exit in
            # the except branch so a window-less live loop can never persist.
            def _on_destroy(*_):
                try:
                    on_destroy()
                except Exception as e:                  # noqa: BLE001
                    try:
                        self.log(f"shutdown raised on wall-window destroy: {e}")
                    except Exception:                   # noqa: BLE001
                        pass
                    try:
                        Gtk.main_quit()
                    finally:
                        os._exit(0)   # force respawn via launcher/systemd
            win.connect("destroy", _on_destroy)

        self.window = win
        self.grid = grid

    def _accel_config(self, *_):
        if self.on_config:
            self.on_config()
        return True

    def _accel_lock(self, *_):
        if self.on_lock:
            self.on_lock()
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

    def show_top_bar_warning(self, text: str, detail: dict = None):
        """Surface a banner above the toolbar — used for the file-hash drift
        warning at boot. Idempotent: replaces an existing banner if any.

        With `detail` (a manifest.check_drift dict) the banner becomes
        click-to-open-a-detail-modal; without it, click dismisses for this
        session. The warning re-paints on next boot if drift persists."""
        prev = getattr(self, "_warn_bar", None)
        if prev is not None:
            try:
                prev.destroy()
            except Exception:                          # noqa: BLE001
                pass
            self._warn_bar = None
        if not text:
            return
        bar = Gtk.EventBox()
        bar.get_style_context().add_class("soc-warn-bar")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        lbl = Gtk.Label(label=text)
        lbl.set_xalign(0.0)
        lbl.set_line_wrap(True)
        lbl.set_margin_start(12); lbl.set_margin_end(8)
        lbl.set_margin_top(6);   lbl.set_margin_bottom(6)
        box.pack_start(lbl, True, True, 0)
        if detail is not None:
            hint = Gtk.Label(label="Details ›")
            hint.set_margin_end(12)
            box.pack_start(hint, False, False, 0)
            bar.set_tooltip_text("Click to see the full list of changed / "
                                 "missing / extra files + a link to the "
                                 "deployed commit on GitHub.")
        else:
            bar.set_tooltip_text("Click to dismiss for this session. The "
                                 "warning re-paints on next boot if drift "
                                 "persists.")
        bar.add(box)

        def _on_click(*_):
            if detail is not None:
                self._open_drift_detail_dialog(text, detail)
            else:
                try:
                    bar.destroy()
                except Exception:                      # noqa: BLE001
                    pass
                self._warn_bar = None
            return True

        bar.connect("button-press-event", _on_click)
        vbox = self.window.get_child()
        if vbox is not None and hasattr(vbox, "pack_start"):
            vbox.pack_start(bar, False, False, 0)
            vbox.reorder_child(bar, 0)
            bar.show_all()
        self._warn_bar = bar

    def _open_drift_detail_dialog(self, summary: str, detail: dict):
        """Modal dialog listing the drift contents + a clickable URL to the
        deployed commit on GitHub. Dismiss clears the banner for this session."""
        dlg = Gtk.Dialog(transient_for=self.window, modal=True,
                         title="File integrity — drift detected")
        dlg.add_buttons("Dismiss banner", Gtk.ResponseType.CLOSE)
        dlg.set_default_size(640, 420)
        area = dlg.get_content_area()
        area.set_spacing(8)
        area.set_margin_start(14); area.set_margin_end(14)
        area.set_margin_top(10);  area.set_margin_bottom(10)

        head = Gtk.Label(label=summary)
        head.set_xalign(0.0); head.set_line_wrap(True)
        head.get_style_context().add_class("soc-config-sub")
        area.pack_start(head, False, False, 0)

        commit = (detail.get("commit") or "").strip()
        repo = (detail.get("repo") or "").strip()
        if commit and repo:
            url = f"{repo.rstrip('/')}/tree/{commit}"
            try:
                link = Gtk.LinkButton.new_with_label(
                    url, f"open commit {commit[:12]} on GitHub")
                link.set_halign(Gtk.Align.START)
                area.pack_start(link, False, False, 0)
            except Exception:                          # noqa: BLE001
                fall = Gtk.Label(label=url)
                fall.get_style_context().add_class("soc-config-sub")
                fall.set_xalign(0.0)
                area.pack_start(fall, False, False, 0)

        def _section(title: str, items: list, marker: str):
            if not items:
                return
            hdr = Gtk.Label()
            # soc-config-sub gives the explicit light palette colour: without a
            # theme class the bold title inherits the operator desktop theme's
            # near-black text, which is ~1.5:1 on the dark dialog bg (#0b1020)
            # under a light GTK theme — dark-on-dark.
            hdr.get_style_context().add_class("soc-config-sub")
            hdr.set_markup(f"<b>{GLib.markup_escape_text(title)}</b>  "
                           f"<span color='#888'>({len(items)})</span>")
            hdr.set_xalign(0.0)
            area.pack_start(hdr, False, False, 0)
            sw = Gtk.ScrolledWindow()
            sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            sw.set_min_content_height(min(150, 18 * max(3, len(items)) + 8))
            tv = Gtk.TextView()
            tv.set_editable(False)
            tv.set_cursor_visible(False)
            tv.set_monospace(True)
            tv.set_left_margin(8); tv.set_right_margin(8)
            tv.get_buffer().set_text("\n".join(f"{marker} {p}" for p in items))
            sw.add(tv)
            area.pack_start(sw, True, True, 0)

        _section("Changed (hash differs)", detail.get("changed") or [], "M")
        _section("Missing (in manifest, not on disk)",
                 detail.get("missing") or [], "D")
        _section("Extra (on disk, not in manifest)",
                 detail.get("extras") or [], "?")

        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()
        if rc == Gtk.ResponseType.CLOSE:
            prev = getattr(self, "_warn_bar", None)
            if prev is not None:
                try:
                    prev.destroy()
                except Exception:                      # noqa: BLE001
                    pass
                self._warn_bar = None

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

    def detach(self, pid: str):
        """Remove a panel's widget from the grid by panel id."""
        for child in self.grid.get_children():
            # Find the PanelFrame wrapping this panel's widget
            if hasattr(child, '_content') and hasattr(child._content, 'panel'):
                if getattr(child._content.panel, 'id', '') == pid:
                    self.grid.remove(child)
                    return
            # Direct widget check
            if hasattr(child, 'panel') and getattr(child.panel, 'id', '') == pid:
                self.grid.remove(child)
                return

    # ---- PIN lock overlay ----------------------------------------------------
    def _build_lock_overlay(self):
        """Floating, draggable PIN unlock dialog. Panels stay fully visible;
        clicks/keys pass through to panels except on the dialog itself."""
        # Transparent event box — lets clicks through to panels below
        outer = Gtk.EventBox()

        # Draggable floating card
        card = Gtk.Frame()
        ctx = card.get_style_context()
        ctx.add_class("soc-config")
        ctx.add_class("soc-locked")

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(18)

        title = Gtk.Label(label="🔒  Unlock Wall")
        title.get_style_context().add_class("soc-config-title")
        title.set_halign(Gtk.Align.CENTER)

        self._lock_entry = Gtk.Entry()
        self._lock_entry.set_visibility(False)
        self._lock_entry.set_placeholder_text("Enter PIN")
        self._lock_entry.set_alignment(0.5)
        self._lock_entry.set_width_chars(16)
        self._lock_entry.connect("activate", lambda *_: self._try_unlock())

        self._lock_err = Gtk.Label(label="")
        self._lock_err.get_style_context().add_class("soc-config-error")
        self._lock_err.set_halign(Gtk.Align.CENTER)

        unlock_btn = Gtk.Button(label="Unlock")
        unlock_btn.get_style_context().add_class("soc-config-primary")
        unlock_btn.connect("clicked", lambda *_: self._try_unlock())

        for w in (title, self._lock_entry, self._lock_err, unlock_btn):
            box.pack_start(w, False, False, 0)

        card.add(box)

        # Make the card draggable via a title-bar grab area
        drag_bar = Gtk.EventBox()
        drag_bar.add(card)
        drag_bar.connect("button-press-event", self._on_drag_start)
        drag_bar.connect("button-release-event", self._on_drag_end)
        drag_bar.connect("motion-notify-event", self._on_drag_motion)
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._dragging = False

        # Center the card
        center = Gtk.Box()
        center.set_halign(Gtk.Align.CENTER)
        center.set_valign(Gtk.Align.CENTER)
        center.add(drag_bar)
        outer.add(center)
        self._drag_parent = center
        return outer

    def _on_drag_start(self, w, event):
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root
        self._dragging = True

    def _on_drag_end(self, w, event):
        self._dragging = False

    def _on_drag_motion(self, w, event):
        if not self._dragging:
            return
        dx = event.x_root - self._drag_start_x
        dy = event.y_root - self._drag_start_y
        if abs(dx) < 3 and abs(dy) < 3:
            return
        hal = self._drag_parent.get_halign()
        val = self._drag_parent.get_valign()
        self._drag_parent.set_halign(Gtk.Align.START)
        self._drag_parent.set_valign(Gtk.Align.START)
        self._drag_parent.set_margin_start(
            max(0, self._drag_parent.get_margin_start() + dx))
        self._drag_parent.set_margin_top(
            max(0, self._drag_parent.get_margin_top() + dy))
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root

    def lock_panels(self):
        """Show the PIN overlay — panels keep rendering underneath."""
        if self._locked:
            return
        self._locked = True
        self._lock_fails = 0
        self._lock_err.set_text("")
        self._lock_entry.set_text("")
        self._lock_overlay.set_visible(True)
        self._lock_overlay.show_all()
        self._lock_entry.grab_focus()

    def unlock_panels(self):
        """Hide the PIN overlay."""
        self._locked = False
        self._lock_overlay.set_visible(False)

    def _try_unlock(self):
        """Verify PIN from the lock overlay entry."""
        from .locker import verify_pin
        from .configwin import state_dir
        pin = self._lock_entry.get_text()
        if verify_pin(state_dir(), pin):
            self.unlock_panels()
            return
        self._lock_entry.set_text("")
        self._lock_fails += 1
        if self._lock_fails >= 3:
            wait = min(5 * (self._lock_fails - 2), 60)
            self._lock_err.set_text(f"Incorrect PIN — locked {wait}s")
            self._lock_entry.set_sensitive(False)
            GLib.timeout_add_seconds(wait, self._rearm_lock_entry)
        else:
            self._lock_err.set_text("Incorrect PIN")

    def _rearm_lock_entry(self):
        self._lock_entry.set_sensitive(True)
        self._lock_entry.grab_focus()
        self._lock_err.set_text("")
        return False

    def is_locked(self) -> bool:
        return self._locked

    def _take_screenshot(self):
        """Save a PNG screenshot of the wall window to ~/soc-wall-*.png."""
        import time
        try:
            win = self.window.get_window()
            if win is None:
                return
            w = win.get_width()
            h = win.get_height()
            if w <= 0 or h <= 0:
                return
            pb = Gdk.pixbuf_get_from_window(win, 0, 0, w, h)
            if pb is None:
                return
            path = os.path.expanduser(
                "~/soc-wall-{}.png".format(time.strftime("%Y%m%d-%H%M%S")))
            pb.savev(path, "png", [], [])
            self.log("screenshot saved: {}".format(path))
        except Exception:
            pass

    # ---- screen / size ------------------------------------------------------
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
        # Windowed mode: opt-in via SOC_WINDOWED=1 OR display.fullscreen=false.
        # Opens as a regular WM-managed window sized to display.width/height —
        # the wall lives ON your desktop instead of taking over the screen
        # (this backs the desktop INSTALL_MODE). F11 still toggles fullscreen
        # at runtime. Defaults to fullscreen so the kiosk path on a Pi 5 is
        # unchanged.
        env_windowed = os.environ.get("SOC_WINDOWED") == "1"
        cfg_fullscreen = getattr(self.conf.display, "fullscreen", True)
        self._fullscreen = not (env_windowed or not cfg_fullscreen)
        w, h = (self.conf.display.width, self.conf.display.height) \
            if not self._fullscreen else self._screen_size()
        self.window.set_default_size(w, h)
        if self._fullscreen:
            self.window.fullscreen()
        else:
            # Stay decorated + resizable so the user can move/close it. Don't
            # set keep-above; the wall is just another app.
            try:
                self.window.set_decorated(True)
                self.window.set_resizable(True)
            except Exception:  # noqa: BLE001
                pass
        self.window.show_all()
        if self._fullscreen:
            self._fit_to_screen()
            # keep filling the screen when it changes size under us: a resized
            # nested window (Xephyr/cage), a monitor hotplug, or a mode switch.
            scr = Gdk.Screen.get_default()
            if scr is not None:
                scr.connect("size-changed", self._fit_to_screen)
                scr.connect("monitors-changed", self._fit_to_screen)
            # also re-fit shortly after first map (some compositors settle late)
            GLib.timeout_add(400, self._fit_to_screen)
        self.log(f"wall window shown ({'fullscreen' if self._fullscreen else 'windowed'}"
                 f"; single-window layout, {w}x{h}; F11 toggles fullscreen)")
