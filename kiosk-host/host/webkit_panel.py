"""
WebKitGTK panel: one WebKitWebView, either in its own top-level GTK window
(layout: windows — Openbox/labwc rules place it into its grid cell) or embedded
into the shared wall window (layout: single — see wall.py).

Login is injected natively: a credential-free bootstrap user script detects the
login page and posts to the `socCreds` script-message handler; the host responds
by evaluating socLogin({user,pass}) with creds fetched just-in-time from the
vault. Credentials never traverse the network or page-context fetch.

Self-healing for 24/7 operation:
  * web-process-terminated / web-process-crashed  -> reload the view
  * load-failed (network hiccup, panel rebooting) -> retry with backoff
Backoff resets once a load finishes, so a flapping panel recovers fast when the
target comes back. A status card (style.PanelStatus) overlays the view while
connecting and whenever it is offline, so a dark cell always says why.

Proxy: when config has an enabled `proxy:`, panels route through it via
WebKitNetworkProxySettings (loopback + ignore_hosts bypassed). If the proxy
demands authentication, the `authenticate` signal is answered with credentials
fetched just-in-time from the vault (proxy.vault_item) — they are never part
of the proxy URL, argv or any file. Panels with `proxy: false` get their own
WebContext pinned to NO_PROXY.

Handles both webkit2gtk-4.1 (Pi OS Bookworm) and 4.0 (older / this dev box).
"""
from __future__ import annotations

import os

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

from gi.repository import Gtk, Gdk, GLib, GObject, WebKit2  # noqa: E402

from . import config as cfg  # noqa: E402
from . import inject, perf, style  # noqa: E402

RETRY_INITIAL = 5       # seconds; load-failure retry backoff
RETRY_MAX = 120
PROXY_AUTH_MAX_ATTEMPTS = 3   # then stop, or a bad password hammers the proxy
MAX_LOGIN_ATTEMPTS = 3        # then show the "please sign in" popup instead

_default_ctx_proxied = False
_tuned_contexts = set()
_mem_pressure_done = False


def _apply_memory_pressure():
    """4.1+ only: cap web/network-process memory + tune GC thresholds on small
    boards (the biggest RAM lever on a 1 GB Pi). Must run before the first
    WebContext/WebsiteDataManager is created. Best-effort: a no-op on 4.0 (the API
    does not exist) or on any error, so it can never break the dev path. Tune the
    per-process cap with SOC_WEBKIT_MEM_LIMIT_MB (default 256)."""
    global _mem_pressure_done
    if _mem_pressure_done:
        return
    _mem_pressure_done = True
    if not perf.low_memory():
        return
    MPS = getattr(WebKit2, "MemoryPressureSettings", None)
    DM = getattr(WebKit2, "WebsiteDataManager", None)
    if MPS is None or DM is None or not hasattr(DM, "set_memory_pressure_settings"):
        return                                   # webkit2gtk-4.0 — feature absent
    try:
        mps = MPS.new()
        limit = int(os.environ.get("SOC_WEBKIT_MEM_LIMIT_MB", "256"))
        if hasattr(mps, "set_memory_limit"):
            mps.set_memory_limit(limit)          # MB, per web/network process
        if hasattr(mps, "set_conservative_threshold"):
            mps.set_conservative_threshold(0.50)
        if hasattr(mps, "set_strict_threshold"):
            mps.set_strict_threshold(0.65)
        if hasattr(mps, "set_poll_interval"):
            mps.set_poll_interval(30.0)
        DM.set_memory_pressure_settings(mps)
    except Exception:                            # any 4.1 API drift -> skip safely
        pass


def _tune_context(ctx):
    """Apply the performance profile to a WebContext (idempotent per context)."""
    if id(ctx) in _tuned_contexts:
        return
    _tuned_contexts.add(id(ctx))
    # DOCUMENT_VIEWER drops the page/back-forward caches — right for a wall
    # that shows one page per view, and a big win on 1 GB boards.
    if perf.low_memory():
        ctx.set_cache_model(WebKit2.CacheModel.DOCUMENT_VIEWER)


def _hwaccel_policy():
    mode = perf.hwaccel_mode()
    return {
        "always": WebKit2.HardwareAccelerationPolicy.ALWAYS,
        "never": WebKit2.HardwareAccelerationPolicy.NEVER,
        "ondemand": WebKit2.HardwareAccelerationPolicy.ON_DEMAND,
    }.get(mode)


def _apply_tls(ctx, panel, log):
    if panel.allow_insecure and hasattr(ctx, "set_tls_errors_policy"):
        try:
            ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
            log(f"[{panel.id}] TLS verification DISABLED for this panel "
                f"(allow_insecure: self-signed cert accepted)")
        except Exception:                                  # very old 4.0 builds
            pass


def _context_for(panel, proxy, log):
    """The WebContext for a panel: the shared default one (with the global proxy
    applied once, if any), or a *private* context when this panel must differ —
    it bypasses the global proxy (`proxy: false`) or accepts self-signed TLS
    (`allow_insecure: true`)."""
    global _default_ctx_proxied
    _apply_memory_pressure()                      # before any WebContext is created
    proxied = bool(proxy and proxy.enabled)
    if (proxied and not panel.proxy) or panel.allow_insecure:
        ctx = WebKit2.WebContext.new()
        if proxied and panel.proxy:
            ignore = cfg.proxy_ignore_hosts(proxy)
            ctx.set_network_proxy_settings(
                WebKit2.NetworkProxyMode.CUSTOM,
                WebKit2.NetworkProxySettings.new(proxy.url, ignore))
        elif proxied:
            ctx.set_network_proxy_settings(WebKit2.NetworkProxyMode.NO_PROXY, None)
        _apply_tls(ctx, panel, log)
        _tune_context(ctx)
        return ctx
    ctx = WebKit2.WebContext.get_default()
    if proxied and not _default_ctx_proxied:
        ignore = cfg.proxy_ignore_hosts(proxy)
        settings = WebKit2.NetworkProxySettings.new(proxy.url, ignore)
        ctx.set_network_proxy_settings(WebKit2.NetworkProxyMode.CUSTOM, settings)
        _default_ctx_proxied = True
        log(f"proxy: webkit panels -> {proxy.url} "
            f"(bypass: {', '.join(ignore)})")
    _tune_context(ctx)
    return ctx


class WebKitPanel:
    def __init__(self, panel, on_need_login, log, embedded: bool = False,
                 proxy=None, proxy_creds=None, on_config=None,
                 on_login_success=None):
        self.panel = panel
        self.on_need_login = on_need_login   # callable(panel) -> {"user","pass"} | None
        self.log = log
        self.embedded = embedded
        self.proxy = proxy                   # config.ProxyCfg | None
        self.proxy_creds = proxy_creds       # callable() -> {"user","pass"} | None
        self.on_config = on_config           # callable() -> open the config window
        self.on_login_success = on_login_success   # callable(panel) on a good login
        self._login_attempts = 0
        self.window = None
        self.webview = None
        self.frame = None                    # style.PanelFrame (the widget)
        self.status = None
        self._retry_delay = RETRY_INITIAL
        self._retry_pending = False
        self._ever_loaded = False
        self._load_failed = False
        self._proxy_auth_attempts = 0
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

        ctx = _context_for(p, self.proxy, self.log)
        self.webview = WebKit2.WebView(web_context=ctx,
                                       user_content_manager=ucm)
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
        # WebGL / WebAudio / media pin RAM + GPU; SOC dashboards rarely need them.
        # Off by default; set `allow_media: true` on a panel that does (video,
        # WebGL Grafana, screen share). Each property is guarded — names vary by
        # webkit2gtk version.
        if not getattr(p, "allow_media", False):
            for _prop in ("enable-webgl", "enable-webaudio", "enable-media",
                          "enable-media-stream", "enable-mediasource",
                          "enable-encrypted-media"):
                try:
                    s.set_property(_prop, False)
                except Exception:                          # unknown on this build
                    pass
        hw = _hwaccel_policy()
        if hw is not None:
            try:
                s.set_hardware_acceleration_policy(hw)
            except Exception:                              # very old 4.0 builds
                pass

        # ---- self-healing ----------------------------------------------------
        # 4.0 has web-process-crashed; >= 2.20 (both 4.0 and 4.1 builds we
        # target) has web-process-terminated. Connect whichever exists.
        if GObject.signal_lookup("web-process-terminated", WebKit2.WebView):
            self.webview.connect("web-process-terminated", self._on_terminated)
        elif GObject.signal_lookup("web-process-crashed", WebKit2.WebView):
            self.webview.connect("web-process-crashed",
                                 lambda *_: self._on_terminated(None, None))
        self.webview.connect("load-failed", self._on_load_failed)
        self.webview.connect("load-changed", self._on_load_changed)
        self.webview.connect("authenticate", self._on_authenticate)

        # match the wall background so navigations never flash white
        rgba = Gdk.RGBA()
        if rgba.parse(style.BACKGROUND):
            try:
                self.webview.set_background_color(rgba)
            except Exception:                              # very old 4.0 builds
                pass

        # stack: live view <-> branded status page (connecting/offline/crash)
        self.frame = style.PanelFrame(p.display_name, self.webview)
        self.status = self.frame

        if self.embedded:
            return                                         # wall.py owns the window

        win = Gtk.Window()
        # WM_CLASS so Openbox rc.xml can place this window into its grid cell.
        try:
            win.set_wmclass(p.wmclass, p.wmclass)         # deprecated; X11 only
        except Exception:
            pass
        # On Wayland there is no per-window WM_CLASS; the generated labwc rules
        # match the title instead, so keep it equal to the wmclass and stable.
        win.set_title(p.wmclass)
        win.set_default_size(g.w, g.h)
        win.set_decorated(True)                           # titlebar -> draggable
        win.add(self.frame)
        win.connect("destroy", self._on_destroy)
        win.connect("key-press-event", self._on_key)
        self.window = win

    def _on_key(self, _w, event):
        # Ctrl+Shift+C opens the on-screen config (windows-layout case)
        ctrl = event.state & Gdk.ModifierType.CONTROL_MASK
        shift = event.state & Gdk.ModifierType.SHIFT_MASK
        if ctrl and shift and event.keyval in (Gdk.KEY_c, Gdk.KEY_C) and self.on_config:
            self.on_config()
            return True
        return False

    @property
    def widget(self):
        """The embeddable widget (used by wall.py in single-window layout)."""
        return self.frame

    # ---- lifecycle ---------------------------------------------------------
    def show(self):
        if self.embedded:
            self.load()
            return
        g = self.panel.geometry
        self.window.show_all()
        # Best-effort placement when our WM rules aren't active (e.g. a plain
        # nested X). Openbox/labwc force-placement overrides this on the Pi.
        try:
            self.window.move(g.x, g.y)
            self.window.resize(g.w, g.h)
        except Exception:
            pass
        self.load()

    def load(self):
        url = self.panel.effective_url
        if not url:
            # unconfigured tile — prompt instead of loading nothing
            self.status.update("not configured — open ⚙ or press Ctrl+Shift+C "
                               "to set this panel's URL", busy=False)
            return
        if not self._ever_loaded:
            self.status.update("connecting…")
        self._login_attempts = 0           # fresh page = fresh login budget
        self.webview.load_uri(url)
        self.log(f"[{self.panel.id}] webkit loading {url}")

    def set_url(self, url: str):
        """Repoint this panel live (from the on-screen config)."""
        url = (url or "").strip()
        # defence in depth: only http(s) ever reaches load_uri()
        if url and not url.lower().startswith(("http://", "https://")):
            self.log(f"[{self.panel.id}] refusing non-http(s) URL: {url!r}")
            self.status.update("rejected: only http:// or https:// URLs are allowed",
                               error=True, busy=False)
            return
        self.panel.url = url or None
        if url:
            self.panel.mode = "direct"
        self._retry_delay = RETRY_INITIAL
        self._retry_pending = False
        self._load_failed = False
        self._ever_loaded = False
        self.log(f"[{self.panel.id}] reconfigured -> {url or '(cleared)'}")
        self.load()

    # ---- self-healing ------------------------------------------------------
    def _on_terminated(self, _wv, reason):
        why = reason.value_nick if hasattr(reason, "value_nick") else "crashed"
        self.log(f"[{self.panel.id}] web process terminated ({why}); "
                 f"reloading in 3s")
        self.status.update(f"renderer {why} — recovering…", error=True)
        self._schedule_retry(3)

    def _on_load_failed(self, _wv, _event, uri, error):
        # CANCELLED fires on perfectly normal in-page navigation; not a failure.
        if error.matches(WebKit2.NetworkError.quark(),
                         WebKit2.NetworkError.CANCELLED):
            return False
        self._load_failed = True
        self.log(f"[{self.panel.id}] load failed: {error.message} ({uri}); "
                 f"retrying in {self._retry_delay}s")
        self.status.update(f"offline: {error.message}\n"
                           f"retrying in {self._retry_delay}s", error=True)
        self._schedule_retry(self._retry_delay)
        self._retry_delay = min(self._retry_delay * 2, RETRY_MAX)
        # TRUE = handle the error ourselves: our status card is the error UI, so
        # WebKit must NOT load its own (white) error page. Crucially this also
        # suppresses the error page's own load-changed→FINISHED, which would
        # otherwise immediately clear() the card and reveal the error page.
        return True

    def _on_load_changed(self, _wv, event):
        # A new navigation starts clean; the failure flag is set later only if
        # this load fails. WebKit emits FINISHED even for a failed load (right
        # after load-failed), so without this flag the card would be cleared
        # the instant a panel goes offline.
        if event == WebKit2.LoadEvent.STARTED:
            self._load_failed = False
        elif event == WebKit2.LoadEvent.FINISHED:
            if self._load_failed:
                return                     # keep the offline card; retry pending
            self._retry_delay = RETRY_INITIAL
            self._ever_loaded = True
            # a finished load means the proxy accepted the creds — reset the
            # budget so routine re-auth on new connections keeps working
            self._proxy_auth_attempts = 0
            self.status.clear()

    def _schedule_retry(self, delay: float):
        if self._retry_pending:
            return
        self._retry_pending = True

        def _go():
            self._retry_pending = False
            self.load()
            return False                   # one-shot
        GLib.timeout_add_seconds(int(delay), _go)

    # ---- proxy auth ---------------------------------------------------------
    def _on_authenticate(self, _wv, request):
        """Answer the proxy's 407 challenge with vault credentials. Site-level
        auth (401) is left to the page (panels log in via injection instead)."""
        try:
            if not request.is_for_proxy():
                return False
        except Exception:
            return False
        pid = self.panel.id
        where = f"{request.get_host()}:{request.get_port()}"
        if not (self.proxy and self.proxy.vault_item and self.proxy_creds):
            self.log(f"[{pid}] proxy {where} demands authentication but "
                     f"proxy.vault_item is not set in panels.yaml — cancelling")
            request.cancel()
            return True
        self._proxy_auth_attempts += 1
        if self._proxy_auth_attempts > PROXY_AUTH_MAX_ATTEMPTS:
            self.log(f"[{pid}] proxy {where} rejected the credentials from "
                     f"vault item '{self.proxy.vault_item}' "
                     f"{PROXY_AUTH_MAX_ATTEMPTS} times — giving up. "
                     f"Check the username/password in the vault.")
            self.status.update("proxy authentication failed — check the vault "
                               "login for the proxy", error=True, busy=False)
            request.cancel()
            return True
        creds = self.proxy_creds()
        if not creds:
            self.log(f"[{pid}] proxy {where}: could not fetch credentials "
                     f"(vault item '{self.proxy.vault_item}') — cancelling")
            request.cancel()
            return True
        credential = WebKit2.Credential.new(
            creds.get("user", ""), creds.get("pass", ""),
            WebKit2.CredentialPersistence.FOR_SESSION)
        creds["pass"] = ""                  # scrub our copy
        request.authenticate(credential)
        return True

    # ---- login -------------------------------------------------------------
    def _reason(self, message) -> str:
        # webkit 4.0 hands a JavascriptResult (.get_js_value()); 4.1 a JSCValue.
        try:
            v = message.get_js_value() if hasattr(message, "get_js_value") else message
            if hasattr(v, "to_string"):
                return v.to_string()
        except Exception:                              # noqa: BLE001
            pass
        return "login"

    def _on_message(self, ucm, message):
        if self._reason(message) == "loggedin":
            self._on_logged_in()
        else:
            self._do_login()

    def _on_logged_in(self):
        """The login form went away — we are in. Remember it + clear the popup."""
        self._login_attempts = 0
        self._evaluate(inject.prompt_clear_call())
        if self.on_login_success:
            try:
                self.on_login_success(self.panel)
            except Exception as e:  # noqa: BLE001
                self.log(f"[{self.panel.id}] login-success hook: {e}")

    def _do_login(self):
        self._login_attempts += 1
        # auto-login kept failing (wrong/expired creds) — stop and ask the user
        if self._login_attempts > MAX_LOGIN_ATTEMPTS:
            self._evaluate(inject.prompt_call(
                "Auto-login failed — please sign in here, or open Settings (⚙ top "
                "bar) to fix the saved login."))
            return
        try:
            creds = self.on_need_login(self.panel)
        except Exception as e:
            self.log(f"[{self.panel.id}] vault error: {e}")
            creds = None
        if not creds:
            # no credentials known for this page — prompt the operator
            self._evaluate(inject.prompt_call(
                "Sign-in needed — no saved login for this page. Open Settings (⚙ "
                "top bar) to add one, or just log in here."))
            return
        js = inject.login_call(creds)
        creds["pass"] = ""  # scrub our copy
        self._evaluate(js)
        self.log(f"[{self.panel.id}] injected login (attempt {self._login_attempts})")

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
