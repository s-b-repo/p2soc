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
import time

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
from . import configpaths, inject, perf, style, websecurity  # noqa: E402

RETRY_INITIAL = 5       # seconds; load-failure retry backoff
RETRY_MAX = 120
PANEL_STABLE_SEC = 30   # a load must stay up this long before backoff resets
PROXY_AUTH_MAX_ATTEMPTS = 3   # then stop, or a bad password hammers the proxy
MAX_LOGIN_ATTEMPTS = 3        # then show the "please sign in" popup instead

_default_ctx_proxied = False
_mem_pressure_done = False

# The compiled tracker UserContentFilter is process-wide (it holds no secrets and
# the rule set is identical for every blocking panel). Compile ONCE, lazily, off
# the data file; panels add_filter() it as soon as it lands. Keyed by the sorted
# `unblock` set so a panel that legitimately needs one tracker gets its own
# variant. None until the first compile is requested.
_filter_store = None                     # WebKit2.UserContentFilterStore | None
_filters: "dict[tuple, object]" = {}     # unblock-key -> compiled UserContentFilter
_filters_pending: "set[tuple]" = set()   # compiles in flight (don't double-submit)
_filter_waiters: "dict[tuple, list]" = {}  # unblock-key -> [callbacks awaiting it]


def _ucf_supported() -> bool:
    """4.1 ships UserContentFilterStore (compiled WKContentRuleList); 4.0 does
    not — there we fall back to a resource-load redirect."""
    return getattr(WebKit2, "UserContentFilterStore", None) is not None


def _webdata_base() -> str:
    """The private 0700 web-data root for this wall, created on first use. Holds
    session tokens, so kiosk-user-owned + 0700, outside the repo (see
    configpaths.resolve_webdata_dir)."""
    base = configpaths.resolve_webdata_dir()
    try:
        os.makedirs(base, mode=0o700, exist_ok=True)
        os.chmod(base, 0o700)            # tighten even if it pre-existed 0755
    except OSError:
        pass
    return base


def _panel_data_dir(panel) -> str:
    """Per-panel web-data subdir (profile isolation: one panel's cookies/storage
    are not readable by another). 0700, under the private base."""
    d = os.path.join(_webdata_base(), "wk-" + panel.id)
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _ensure_tracker_filter(panel, on_ready, log):
    """Compile (once, async, on the GLib main loop) the tracker UserContentFilter
    variant for this panel's `unblock` set and call on_ready(filter) when it
    lands. Best-effort: silently does nothing if the store/data file is absent —
    the panel just renders without the filter (the host fallback covers 4.0)."""
    global _filter_store
    if not _ucf_supported():
        return
    rules = websecurity.load_tracker_rules_text()
    if not rules:
        return
    # Trim the rule set to honour this panel's `unblock:` hosts.
    unblock = tuple(sorted({h.lower() for h in (getattr(panel, "unblock", ()) or ())}))
    if unblock:
        try:
            import json as _json
            keep = [r for r in _json.loads(rules)
                    if not _rule_unblocked(r, unblock)]
            rules = _json.dumps(keep)
        except Exception:                # malformed -> fall back to the full set
            unblock = ()
    key = unblock

    if key in _filters:                  # already compiled — hand it back at once
        on_ready(_filters[key])
        return
    _filter_waiters.setdefault(key, []).append(on_ready)
    if key in _filters_pending:
        return                           # a compile for this key is already running
    _filters_pending.add(key)

    if _filter_store is None:
        store_dir = os.path.join(_webdata_base(), "filter-store")
        try:
            os.makedirs(store_dir, mode=0o700, exist_ok=True)
        except OSError:
            pass
        try:
            _filter_store = WebKit2.UserContentFilterStore.new(store_dir)
        except Exception:                # very old/odd build — give up gracefully
            _filters_pending.discard(key)
            return

    ident = "soc-trackers" + ("-" + "_".join(key) if key else "")

    def _done(store, result):
        _filters_pending.discard(key)
        try:
            filt = store.save_finish(result)
        except Exception as e:           # compile failed -> no filter, log once
            log(f"tracker filter compile failed ({ident}): {e}")
            _filter_waiters.pop(key, None)
            return
        _filters[key] = filt
        for cb in _filter_waiters.pop(key, []):
            try:
                cb(filt)
            except Exception:
                pass

    try:
        _filter_store.save(ident, GLib.Bytes.new(rules.encode("utf-8")), None, _done)
    except Exception as e:
        _filters_pending.discard(key)
        _filter_waiters.pop(key, None)
        log(f"tracker filter save failed: {e}")


def _rule_unblocked(rule, unblock) -> bool:
    """True if this WKContentRuleList rule targets a host the panel unblocked."""
    try:
        uf = str(rule["trigger"]["url-filter"]).replace("\\.", ".").lower()
    except (KeyError, TypeError):
        return False
    return any(u in uf for u in unblock)


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
        limit = cfg.env_int("SOC_WEBKIT_MEM_LIMIT_MB", 256, lo=16, hi=4096)
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
    """Apply the performance profile to a WebContext. set_cache_model is cheap +
    idempotent, so call it unconditionally — no id()-keyed dedup, whose ids can be
    reused by a GC'd private context and wrongly skip a fresh one's tuning."""
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


def _harden_settings(s, panel):
    """Attack-surface reduction applied to EVERY WebView's settings (both the
    shared-default and the private-context panels) in ONE place, so no branch can
    silently skip a control. None of these are features a SOC dashboard needs.

    Each property is guarded — names/availability differ between webkit2gtk-4.0
    and 4.1 (and across aarch64 builds), so an unknown key must never crash boot.
    """
    # file:// can't read other files / reach other origins (no local-file escalation)
    for _prop, _val in (
        ("allow-file-access-from-file-urls", False),
        ("allow-universal-access-from-file-urls", False),
        # legacy plugin / Java surface — absent on most 4.1 builds (guarded)
        ("enable-java", False),
        ("enable-plugins", False),
        # block mixed content on HTTPS dashboards (the active-mixed block is the
        # real attack-surface win; display-mixed off too)
        ("allow-running-of-insecure-content", False),
        ("allow-display-of-insecure-content", False),
    ):
        try:
            s.set_property(_prop, _val)
        except Exception:                    # unknown on this build -> skip
            pass
    # UA override (some dashboards gate on UA). Only when explicitly set.
    ua = getattr(panel, "user_agent", None)
    if ua:
        try:
            s.set_property("user-agent", ua)
        except Exception:
            pass


def _apply_tls(ctx, panel, log):
    if panel.allow_insecure and hasattr(ctx, "set_tls_errors_policy"):
        try:
            ctx.set_tls_errors_policy(WebKit2.TLSErrorsPolicy.IGNORE)
            log(f"[{panel.id}] TLS verification DISABLED for this panel "
                f"(allow_insecure: self-signed cert accepted)")
        except Exception:                                  # very old 4.0 builds
            pass


def _data_manager_for(panel, log):
    """A per-panel WebsiteDataManager: persistent (base/cache dirs under the
    private 0700 web-data root) when `persist` is True, else ephemeral (no
    on-disk session). Per-panel base dir == profile ISOLATION: one panel's
    cookies/localStorage/IndexedDB are not readable by another.

    Guarded: webkit2gtk-4.0's constructor differs / may lack the kwargs — on any
    failure return None so the caller builds a plain context (persistence
    degrades but the wall never crashes)."""
    DM = getattr(WebKit2, "WebsiteDataManager", None)
    if DM is None:
        return None
    persist = getattr(panel, "persist", True)
    try:
        if not persist:
            return DM.new_ephemeral() if hasattr(DM, "new_ephemeral") else None
        base = _panel_data_dir(panel)
        return DM(base_data_directory=base,
                  base_cache_directory=os.path.join(base, "cache"))
    except Exception as e:                       # 4.0 API drift -> default DM
        log(f"[{panel.id}] WebsiteDataManager unavailable ({e}); "
            f"session persistence degraded for this panel")
        return None


def _setup_cookies(ctx, dm, panel, log):
    """Persistent SQLITE cookie storage (survives a wall restart) + a hardened
    NO_THIRD_PARTY accept policy (refuse third-party cookie writes — complements
    the tracker blocklist). Ephemeral panels (`persist:false`) skip the on-disk
    store and just harden the policy."""
    try:
        cm = dm.get_cookie_manager() if dm is not None and hasattr(dm, "get_cookie_manager") \
            else ctx.get_cookie_manager()
    except Exception:
        return
    if cm is None:
        return
    persist = getattr(panel, "persist", True)
    if persist:
        try:
            cm.set_persistent_storage(
                os.path.join(_panel_data_dir(panel), "cookies.sqlite"),
                WebKit2.CookiePersistentStorage.SQLITE)
        except Exception as e:                   # very old 4.0 -> session-only
            log(f"[{panel.id}] persistent cookies unavailable ({e})")
    try:
        cm.set_accept_policy(WebKit2.CookieAcceptPolicy.NO_THIRD_PARTY)
    except Exception:
        pass


def _new_context(dm):
    """Build a WebContext bound to `dm` (per-panel persistence + isolation), or a
    plain WebContext when no DM is available (4.0 fallback)."""
    if dm is not None and hasattr(WebKit2.WebContext, "new_with_website_data_manager"):
        try:
            return WebKit2.WebContext.new_with_website_data_manager(dm)
        except Exception:
            pass
    return WebKit2.WebContext.new()


def _context_for(panel, proxy, log):
    """A PRIVATE, per-panel WebContext backed by its own WebsiteDataManager, so
    each panel persists cookies/web-storage independently (profile isolation) and
    sessions survive a wall restart. The previous shared get_default() context is
    gone — sharing would defeat isolation and a single persistent store can't be
    keyed per panel. The global proxy (if any) is applied to every panel's
    context; a `proxy: false` panel is pinned to NO_PROXY; `allow_insecure`
    relaxes TLS for that panel only."""
    global _default_ctx_proxied
    _apply_memory_pressure()                      # before any WebContext/DM is created
    dm = _data_manager_for(panel, log)
    ctx = _new_context(dm)

    proxied = bool(proxy and proxy.enabled)
    if proxied:
        ignore = cfg.proxy_ignore_hosts(proxy)
        if panel.proxy:
            ctx.set_network_proxy_settings(
                WebKit2.NetworkProxyMode.CUSTOM,
                WebKit2.NetworkProxySettings.new(proxy.url, ignore))
            if not _default_ctx_proxied:
                _default_ctx_proxied = True
                log(f"proxy: webkit panels -> {proxy.url} "
                    f"(bypass: {', '.join(ignore)})")
        else:
            ctx.set_network_proxy_settings(WebKit2.NetworkProxyMode.NO_PROXY, None)

    _apply_tls(ctx, panel, log)
    _setup_cookies(ctx, dm, panel, log)
    _tune_context(ctx)
    return ctx


class WebKitPanel:
    def __init__(self, panel, on_need_login, log, embedded: bool = False,
                 proxy=None, proxy_creds=None, on_config=None,
                 on_login_success=None, security=None):
        self.panel = panel
        self.on_need_login = on_need_login   # callable(panel) -> {"user","pass"} | None
        self.log = log
        self.embedded = embedded
        self.proxy = proxy                   # config.ProxyCfg | None
        self.proxy_creds = proxy_creds       # callable() -> {"user","pass"} | None
        self.security = security             # config.SecurityCfg | None (wall-wide)
        self.on_config = on_config           # callable() -> open the config window
        self.on_login_success = on_login_success   # callable(panel) on a good login
        self._login_attempts = 0
        self.window = None
        self.webview = None
        self.frame = None                    # style.PanelFrame (the widget)
        self.status = None
        self._retry_delay = RETRY_INITIAL
        self._loaded_at = 0.0                 # monotonic time of the last FINISHED load
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
        self._ucm = ucm
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

        # Per-panel top-level navigation allowlist, computed ONCE (a cached set
        # lookup on each main-frame nav). Gate honoured at decision time.
        self._allowlist = websecurity.build_allowlist(p, self._security())
        self._nav_gate = self._nav_gate_enabled()

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
        # IndexedDB/WebSQL — SPA dashboards use it for offline state + session;
        # lives under the per-panel DM base dir (private 0700). REVERSED from the
        # old lean-off so a cookie/IDB-session dashboard stays logged in.
        s.set_property("enable-html5-database", True)
        s.set_property("enable-offline-web-application-cache", False)
        # Attack-surface hardening (file://, plugins/Java, mixed content, UA) —
        # one helper so every WebView gets it identically.
        _harden_settings(s, p)
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

        # ---- renderer security: nav allowlist + trackers + no downloads -------
        # Top-level navigation allowlist (and always-ignore new windows).
        self.webview.connect("decide-policy", self._on_decide_policy)
        # A SOC wall never saves a file — refuse all downloads (neutralises
        # drive-by file drops). Signal name differs 4.0/4.1 + lives on context.
        for _sig, _obj in (("download-started", ctx),
                           ("download-started", self.webview)):
            if GObject.signal_lookup(_sig, type(_obj)):
                try:
                    _obj.connect(_sig, self._on_download_started)
                    break
                except Exception:
                    pass
        # Tracker blocklist: compile-once WKContentRuleList (4.1) added when ready;
        # 4.0 fallback observes resource loads and redirects matches to about:blank.
        self._install_tracker_block(ctx)

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

    # ---- renderer security -------------------------------------------------
    def _security(self):
        """The wall-wide SecurityCfg, if the host passed one (via on_config's
        config). Falls back to None -> websecurity uses its safe defaults."""
        return getattr(self, "security", None)

    def _nav_gate_enabled(self) -> bool:
        """Master gate for the nav allowlist: the env toggle AND the security
        block both default ON; either set to off disables it (escape hatch for a
        brand-new dashboard whose redirect chain isn't mapped yet)."""
        sec = self._security()
        sec_on = getattr(sec, "nav_allowlist", True) if sec is not None else True
        env_on = cfg.env_bool("SOC_NAV_ALLOWLIST", True)
        on = sec_on and env_on
        if not on:
            self.log(f"[{self.panel.id}] nav allowlist DISABLED "
                     f"(SOC_NAV_ALLOWLIST / security.nav_allowlist) — top-level "
                     f"navigation is not gated")
        return on

    def _on_decide_policy(self, _wv, decision, decision_type):
        """Refuse top-level navigation outside the panel's allowlist (own origin
        + its SSO/redirect domains + configured allow). Only main-frame top-level
        nav is gated — sub-resources/CDNs/XHR/websockets/SSO POST-backs are NOT
        (they go through the tracker filter only), so real dashboards + logins
        keep working. New windows are always refused (a wall panel never opens
        one). Returning True = we handled it; False = let WebKit proceed."""
        PDT = WebKit2.PolicyDecisionType
        try:
            if decision_type == PDT.NEW_WINDOW_ACTION:
                decision.ignore()                 # a wall panel never opens a new window
                return True
            if decision_type != PDT.NAVIGATION_ACTION:
                return False                      # response/other -> default
        except Exception:
            return False
        if not self._nav_gate:
            return False
        try:
            na = decision.get_navigation_action()
            # Only gate the TOP-LEVEL frame; sub-frames are not gated (the tracker
            # filter still protects them). On builds lacking is_main_frame, fail
            # OPEN for sub-frames so a dashboard's iframes are never broken.
            if hasattr(na, "is_main_frame") and not na.is_main_frame():
                return False
            uri = na.get_request().get_uri()
        except Exception:
            return False
        host = websecurity.host_of(uri)
        # about:blank / non-http(s) have no host: allow (set_url already refuses
        # non-http(s) loads upstream; about:blank is our own status/sink target).
        if not host:
            return False
        if websecurity.host_matches(host, self._allowlist):
            return False                          # allowed -> proceed
        try:
            decision.ignore()
        except Exception:
            return False
        self.log(f"[{self.panel.id}] refused off-allowlist nav -> {uri}")
        return True

    def _on_download_started(self, _ctx_or_view, download):
        """Cancel every download — a SOC wall never needs to save a file."""
        try:
            download.cancel()
        except Exception:
            pass
        self.log(f"[{self.panel.id}] download refused (downloads disabled)")
        return True

    def _install_tracker_block(self, ctx):
        """Add the top-20 analytics/tracker blocklist for this panel, honouring
        block_trackers / unblock. 4.1: a compiled WKContentRuleList (added async
        when it lands). 4.0: a resource-load-started redirect to about:blank."""
        if not websecurity.should_block_trackers(
                self.panel, self._security(),
                cfg.env_bool("SOC_BLOCK_TRACKERS", True)):
            return
        if _ucf_supported():
            def _add(filt):
                try:
                    self._ucm.add_filter(filt)
                except Exception:
                    pass
            _ensure_tracker_filter(self.panel, _add, self.log)
            return
        # 4.0 fallback: no compiled-filter store. Observe resource loads and
        # redirect any whose host matches the (unblock-trimmed) blocklist.
        self._tracker_hosts = websecurity.effective_tracker_hosts(
            self.panel, self._security())
        if self._tracker_hosts and GObject.signal_lookup(
                "resource-load-started", WebKit2.WebView):
            try:
                self.webview.connect("resource-load-started",
                                     self._on_resource_load_started)
            except Exception:
                pass

    def _on_resource_load_started(self, _wv, resource, request):
        """4.0 tracker fallback: redirect a matched request to about:blank (a true
        cancel isn't available on this signal). Coarse but cuts third-party JS."""
        try:
            host = websecurity.host_of(request.get_uri())
        except Exception:
            return
        if not host:
            return
        if any(host == h or host.endswith("." + h) for h in self._tracker_hosts):
            try:
                request.set_uri("about:blank")
            except Exception:
                pass

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

    def mem_rss_kb(self):
        # WebKit's renderer runs in a separate WebKitWebProcess we can't attribute
        # per-panel, so the watchdog can't measure it — it recycles us round-robin.
        return None

    def recycle(self):
        """Reclaim accumulated renderer memory by reloading the page."""
        self.log(f"[{self.panel.id}] recycling webkit (reload) to reclaim memory")
        self.load()

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
        # Use the same exponential backoff as load failures. On a 1 GB Pi a
        # web-process termination is usually the memory-pressure killer; a fixed
        # 3s reload of a heavy page would just crash-OOM-loop and starve the
        # other panels. A sustained successful load resets the delay
        # (_on_load_changed FINISHED).
        self.log(f"[{self.panel.id}] web process terminated ({why}); "
                 f"reloading in {self._retry_delay}s")
        self.status.update(f"renderer {why} — recovering in {self._retry_delay}s",
                           error=True)
        self._load_failed = True              # keep the card; don't clear on the
        #                                       error page's FINISHED event
        self._schedule_retry(self._retry_delay)
        self._retry_delay = min(self._retry_delay * 2, RETRY_MAX)

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
            now = time.monotonic()
            stable = cfg.env_float("SOC_PANEL_STABLE_SEC", PANEL_STABLE_SEC, lo=0.0)
            # Only reset the backoff once a previous load has actually stayed up
            # long enough; a renderer that loads then OOM-crashes within a few
            # seconds keeps climbing toward RETRY_MAX instead of pinning a tight
            # 5s reload loop. The first-ever load (_loaded_at == 0.0) just stamps.
            if self._loaded_at and (now - self._loaded_at) >= stable:
                self._retry_delay = RETRY_INITIAL
            self._loaded_at = now
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
