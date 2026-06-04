"""
WebKitGTK panel: one top-level GTK window hosting one WebKitWebView.

Login is injected natively: a credential-free bootstrap user script detects the
login page and posts to the `socCreds` script-message handler; the host responds
by evaluating socLogin({user,pass}) with creds fetched just-in-time from the
vault. Credentials never traverse the network or page-context fetch.

Handles both webkit2gtk-4.1 (Pi OS Bookworm) and 4.0 (older / this dev box).
"""
from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
# Prefer 4.1 (Bookworm); fall back to 4.0.
_WK_VER = None
for _v in ("4.1", "4.0"):
    try:
        gi.require_version("WebKit2", _v)
        _WK_VER = _v
        break
    except ValueError:
        continue
if _WK_VER is None:
    raise RuntimeError("No WebKit2 typelib (install gir1.2-webkit2-4.1 or 4.0)")

from gi.repository import Gtk, Gdk, WebKit2, GLib  # noqa: E402

from . import inject  # noqa: E402


class WebKitPanel:
    def __init__(self, panel, on_need_login, log):
        self.panel = panel
        self.on_need_login = on_need_login   # callable(panel) -> {"user","pass"} | None
        self.log = log
        self.window = None
        self.webview = None
        self._build()

    # ---- construction ------------------------------------------------------
    def _build(self):
        p = self.panel
        g = p.geometry

        ucm = WebKit2.UserContentManager()
        ucm.register_script_message_handler("socCreds")
        ucm.connect("script-message-received::socCreds", self._on_message)

        # credential-free bootstrap, injected at document start
        boot = inject.bootstrap_js(p, mode="webkit")
        script = WebKit2.UserScript(
            boot,
            WebKit2.UserContentInjectedFrames.TOP_FRAME,
            WebKit2.UserScriptInjectionTime.START,
            None, None,
        )
        ucm.add_script(script)

        self.webview = WebKit2.WebView.new_with_user_content_manager(ucm)
        # Lean settings for 1 GB: keep JS, drop extras.
        s = self.webview.get_settings()
        s.set_property("enable-developer-extras", False)
        try:
            s.set_property("enable-back-forward-navigation-gestures", False)
        except TypeError:
            pass
        s.set_property("enable-page-cache", False)        # save RAM
        s.set_property("enable-html5-database", False)
        s.set_property("enable-offline-web-application-cache", False)

        win = Gtk.Window()
        # WM_CLASS so Openbox rc.xml can place this window into its 2x2 cell.
        try:
            win.set_wmclass(p.wmclass, p.wmclass)         # deprecated but works on X11
        except Exception:
            pass
        win.set_title(f"SOC {p.id}")
        win.set_default_size(g.w, g.h)
        win.set_decorated(True)                           # titlebar -> draggable
        win.add(self.webview)
        win.connect("destroy", self._on_destroy)
        self.window = win

    # ---- lifecycle ---------------------------------------------------------
    def show(self):
        g = self.panel.geometry
        self.window.show_all()
        # Best-effort placement when our Openbox rules aren't active (e.g. a
        # plain nested X). Openbox <position force="yes"> overrides this on the Pi.
        try:
            self.window.move(g.x, g.y)
            self.window.resize(g.w, g.h)
        except Exception:
            pass
        self.load()

    def load(self):
        self.webview.load_uri(self.panel.effective_url)
        self.log(f"[{self.panel.id}] webkit loading {self.panel.effective_url}")

    # ---- login -------------------------------------------------------------
    def _on_message(self, ucm, message):
        # Each webview is bound to exactly one panel, so we don't need the
        # payload — just inject this panel's creds.
        self._do_login()

    def _do_login(self):
        try:
            creds = self.on_need_login(self.panel)
        except Exception as e:
            self.log(f"[{self.panel.id}] vault error: {e}")
            return
        if not creds:
            return
        js = inject.login_call(creds)
        creds["pass"] = ""  # scrub our copy
        self._evaluate(js)
        self.log(f"[{self.panel.id}] injected login")

    def _evaluate(self, js: str):
        # 4.1 prefers evaluate_javascript(); 4.0 has run_javascript().
        if hasattr(self.webview, "evaluate_javascript"):
            try:
                self.webview.evaluate_javascript(js, -1, None, None, None, None, None)
                return
            except TypeError:
                pass
        self.webview.run_javascript(js, None, None, None)

    def _on_destroy(self, *_):
        self.log(f"[{self.panel.id}] window closed")
