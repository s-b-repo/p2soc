"""
System-tray icon for the wall — best-effort, never required.

The wall normally runs fullscreen on tty1 (a real kiosk has nowhere for a
tray icon to live). On a desk install — windowed mode on a normal desktop
session, e.g. KDE / GNOME — the operator wants the wall to minimise to the
system tray when they close it, with a tray menu offering: Show wall, Lock,
Open Settings, Restart wall, Reboot, Quit.

We try, in order:
  1. **AyatanaAppIndicator3** — the modern API, supported by KDE Plasma,
     GNOME (with the AppIndicator extension), Cinnamon, MATE, XFCE. Renders
     as a real DBus StatusNotifierItem.
  2. **AppIndicator3** — the older Ubuntu Unity API (renamed Ayatana when
     Canonical handed it to the freedesktop community). Same shape.
  3. **Gtk.StatusIcon** — XEmbed; deprecated but ubiquitous + works under
     X11 directly. Falls back here when no AppIndicator is installed.
  4. None of the above → `available()` returns False and the wall stays
     normal (close = quit, no tray). The caller logs "no tray support"
     and life continues.

The `Tray` class encapsulates the cross-backend juggling so wall.py /
main.py just hand it a menu spec and a few callbacks.
"""
from __future__ import annotations

import os

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib  # noqa: E402


# --- backend discovery ---------------------------------------------------- #
_Indicator = None
_INDICATOR_BACKEND = None       # "ayatana" | "appindicator" | "statusicon" | None


def _try_load_appindicator():
    global _Indicator, _INDICATOR_BACKEND
    if _Indicator is not None:
        return _INDICATOR_BACKEND
    for v, name in (("0.1", "AyatanaAppIndicator3"),
                    ("0.1", "AppIndicator3")):
        try:
            gi.require_version(name, v)
            from gi.repository import AyatanaAppIndicator3 as A  # noqa: F401
        except (ValueError, ImportError):
            try:
                gi.require_version(name, v)
                from gi.repository import AppIndicator3 as A    # noqa: F401
                _Indicator = A
                _INDICATOR_BACKEND = "appindicator"
                return _INDICATOR_BACKEND
            except (ValueError, ImportError):
                continue
        else:
            from gi.repository import AyatanaAppIndicator3 as A
            _Indicator = A
            _INDICATOR_BACKEND = "ayatana"
            return _INDICATOR_BACKEND
    return None


def available() -> bool:
    """True if the host has at least one tray backend installed. Cheap —
    only loads modules the first time. Always True on hosts that ship
    Gtk.StatusIcon (i.e. essentially every GTK install)."""
    return _try_load_appindicator() is not None or hasattr(Gtk, "StatusIcon")


# --- the cross-backend Tray facade ---------------------------------------- #
class Tray:
    """Hide-to-tray icon with a static menu. `menu_spec` is a list of
    (label, callback) tuples in display order. A None callback inserts a
    separator. The label "Quit" wires to `on_quit` so the caller can intercept
    that specifically (e.g. confirm-before-quit)."""

    def __init__(self, *, app_id: str = "soc-wall",
                 icon_name: str = "video-display",
                 title: str = "SOC wall"):
        self.app_id = app_id
        self.icon_name = icon_name
        self.title = title
        self._menu = None
        self._ind = None        # AppIndicator
        self._status_icon = None  # StatusIcon fallback
        self._backend = None

    def install(self, menu_spec) -> bool:
        """Install the tray icon + menu. Returns True on success."""
        self._menu = Gtk.Menu()
        for entry in menu_spec:
            if entry is None or entry[0] is None:
                self._menu.append(Gtk.SeparatorMenuItem())
                continue
            label, cb = entry
            item = Gtk.MenuItem(label=label)
            if cb is not None:
                item.connect("activate", lambda _w, c=cb: c())
            self._menu.append(item)
        self._menu.show_all()

        backend = _try_load_appindicator()
        if backend in ("ayatana", "appindicator"):
            cat = (_Indicator.IndicatorCategory.APPLICATION_STATUS
                   if hasattr(_Indicator, "IndicatorCategory")
                   else _Indicator.CATEGORY_APPLICATION_STATUS)
            self._ind = _Indicator.Indicator.new(
                self.app_id, self.icon_name, cat)
            active = (_Indicator.IndicatorStatus.ACTIVE
                      if hasattr(_Indicator, "IndicatorStatus")
                      else _Indicator.STATUS_ACTIVE)
            self._ind.set_status(active)
            self._ind.set_title(self.title)
            self._ind.set_menu(self._menu)
            self._backend = backend
            return True

        if hasattr(Gtk, "StatusIcon"):
            self._status_icon = Gtk.StatusIcon.new_from_icon_name(self.icon_name)
            self._status_icon.set_tooltip_text(self.title)
            self._status_icon.set_title(self.title)
            self._status_icon.connect(
                "popup-menu",
                lambda icon, btn, t: self._menu.popup(
                    None, None, Gtk.StatusIcon.position_menu, icon, btn, t))
            self._status_icon.connect(
                "activate", self._on_statusicon_activate)
            self._status_icon.set_visible(True)
            self._backend = "statusicon"
            return True

        return False

    def remove(self):
        if self._ind is not None:
            try:
                inactive = (_Indicator.IndicatorStatus.PASSIVE
                            if hasattr(_Indicator, "IndicatorStatus")
                            else _Indicator.STATUS_PASSIVE)
                self._ind.set_status(inactive)
            except Exception:                              # noqa: BLE001
                pass
            self._ind = None
        if self._status_icon is not None:
            try:
                self._status_icon.set_visible(False)
            except Exception:                              # noqa: BLE001
                pass
            self._status_icon = None

    @property
    def backend(self):
        return self._backend

    # --- StatusIcon-only: a left-click should activate the first item
    # (typically "Show wall") — AppIndicator doesn't get this signal because
    # plain left-click is a no-op there.
    def _on_statusicon_activate(self, _icon):
        if not self._menu:
            return
        for child in self._menu.get_children():
            if isinstance(child, Gtk.SeparatorMenuItem):
                continue
            child.activate()
            return
