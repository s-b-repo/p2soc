"""
Chromium fallback panel (for the rare Chrome-only site).

Spawns a single Chromium app-window with remote debugging on localhost, then
drives it over the Chrome DevTools Protocol from a background thread:

  * installs the credential-free bootstrap (addScriptToEvaluateOnNewDocument +
    one immediate eval for the already-loaded document),
  * polls window.__SOC.needLogin and, when set, fetches creds from the vault and
    evaluates socLogin({user,pass}),
  * respawns Chromium (with backoff) if the process dies and re-attaches CDP,
    so a crashed panel heals itself on a 24/7 wall.

Proxy: an enabled global `proxy:` becomes --proxy-server=scheme://host:port
(+ --proxy-bypass-list) — host:port only, NEVER credentials. When the proxy
demands auth, the CDP Fetch domain is enabled briefly: Fetch.authRequired is
answered with credentials fetched just-in-time from the vault, then Fetch is
disabled again (Chromium caches the proxy session) so steady-state requests
pay no interception cost. Panels with `proxy: false` get --no-proxy-server.

Display backend: Chromium runs on X11/XWayland by default even inside a
Wayland session — that keeps WM_CLASS-based placement working under both
Openbox and labwc (labwc matches XWayland WM_CLASS via `identifier`). Set
SOC_CHROMIUM_OZONE=wayland to force native Wayland (placement is then up to
the compositor). CDP binds to 127.0.0.1 only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import urllib.request

from websocket import create_connection
from websocket import WebSocketTimeoutException

from . import config as cfg
from . import inject
from . import perf

RESPAWN_INITIAL = 5.0    # seconds; doubled up to RESPAWN_MAX after each death
RESPAWN_MAX = 60.0
RESPAWN_STABLE_SEC = 30.0  # only reset the backoff after the spawn survives this long
RPC_TIMEOUT = 30.0       # hard ceiling on a single CDP round-trip (anti-wedge)


def cdp_allowed_origin(port: int) -> str:
    """The exact Origin our CDP websocket client sends (the websocket-client lib
    derives it from the ws URL as http://host:port). We pin
    --remote-allow-origins to THIS value so ONLY our own connection is accepted:
    a panel page's JS cannot reach the debugger because browsers forbid scripts
    from forging the Origin header, so its WebSocket carries the page's real
    (remote) origin, which is not in the allow-list. NEVER use "*" here — that
    disables the check and lets any rendered dashboard hijack CDP and read the
    injected credentials of every panel."""
    return f"http://127.0.0.1:{port}"
PROXY_AUTH_MAX_ATTEMPTS = 3     # then cancel — don't hammer the proxy
PROXY_AUTH_WINDOW = 20.0        # seconds of fast Fetch pumping after attach
# shown for an unconfigured tile (no URL set yet) — a dark blank page
UNCONFIGURED_URL = "data:text/html,%3Cbody%20style%3D%22background:%230b1020%22%3E"


def _chromium_bin() -> str:
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("no chromium binary found")


def _ozone_platform() -> str:
    """x11 (incl. XWayland) unless explicitly overridden or X is unavailable."""
    ozone = os.environ.get("SOC_CHROMIUM_OZONE", "auto")
    if ozone != "auto":
        return ozone
    return "x11" if os.environ.get("DISPLAY") else "wayland"


def _hwaccel_flags() -> list:
    """GPU-acceleration flags for Chromium on ARM boards (Pi 5 V3D).

    WebKit panels get V3D compositing via HardwareAccelerationPolicy.ALWAYS, but
    Chromium in a minimal Openbox/cage kiosk frequently fails to auto-init the
    V3D GPU and silently drops to the SwiftShader/llvmpipe SOFTWARE path —
    software-compositing a 2x2 grid is exactly the CPU/RAM load the 1 GB board
    can least afford. Mirror WebKit's policy: when on ARM with a render node
    (Mesa V3D at /dev/dri/renderD128), nudge Chromium onto the GPU.

    SOC_CHROMIUM_HWACCEL=auto|never mirrors SOC_WEBKIT_HWACCEL so a problematic
    Chromium build can opt out. Gated behind perf.is_arm() so x86 dev sees no
    new flags (keeps `make verify` byte-identical there)."""
    mode = os.environ.get("SOC_CHROMIUM_HWACCEL", "auto").lower()
    if mode == "never":
        return []
    if mode not in ("auto", ""):
        return []
    if not (perf.is_arm() and perf.has_gpu_render_node()):
        return []
    return [
        "--ignore-gpu-blocklist",        # V3D is blocklisted on some builds
        "--enable-gpu-rasterization",
        "--enable-zero-copy",
        "--use-gl=egl",                  # force EGL/V3D, not SwiftShader
    ]


def proxy_flags(proxy) -> list:
    """Non-secret Chromium proxy flags (safe to appear in `ps`)."""
    bypass = ";".join(cfg.proxy_ignore_hosts(proxy))
    return [f"--proxy-server={proxy.url}", f"--proxy-bypass-list={bypass}"]


class CDPError(Exception):
    pass


class _CDP:
    def __init__(self, port: int):
        self.port = port
        self.ws = None
        self._id = 0
        self._noreply_ids = set()
        self.on_event = None        # callable(method, params) | None

    def _targets(self):
        url = f"http://127.0.0.1:{self.port}/json"
        with urllib.request.urlopen(url, timeout=2) as r:
            return json.loads(r.read().decode())

    def connect(self, timeout=20.0):
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                for t in self._targets():
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        # Let websocket-client send its single default Origin
                        # (http://127.0.0.1:<port>); we pin --remote-allow-origins
                        # to exactly that (see cdp_allowed_origin) so only this
                        # connection is accepted. Do NOT also pass an explicit
                        # Origin header — Chromium then sees two and rejects both.
                        self.ws = create_connection(
                            t["webSocketDebuggerUrl"],
                            timeout=10,
                        )
                        return
            except Exception as e:  # noqa: BLE001
                last = e
            time.sleep(0.5)
        raise CDPError(f"could not attach CDP on :{self.port} ({last})")

    def _dispatch(self, msg) -> bool:
        """Route one incoming message. Returns True if it was consumed
        (event or fire-and-forget response)."""
        mid = msg.get("id")
        if mid is None:
            if self.on_event and msg.get("method"):
                try:
                    self.on_event(msg["method"], msg.get("params", {}))
                except Exception:   # an event handler must never kill the loop
                    pass
            return True
        if mid in self._noreply_ids:
            self._noreply_ids.discard(mid)
            return True
        return False

    def send_nowait(self, method, params=None):
        """Send a command whose response we don't care about (used from event
        handlers — they run inside a recv loop and must not recv themselves)."""
        self._id += 1
        self._noreply_ids.add(self._id)
        self.ws.send(json.dumps({"id": self._id, "method": method,
                                 "params": params or {}}))

    def rpc(self, method, params=None, timeout=RPC_TIMEOUT):
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        # Overall deadline so a flood of unsolicited events (which keep recv()
        # returning before its socket timeout) can never starve the matching
        # reply and wedge the panel's control loop forever.
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv())
            if self._dispatch(msg):
                continue
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CDPError(msg["error"])
                return msg.get("result", {})
            # response to a stale call — drop it
        raise CDPError(f"CDP rpc {method} timed out after {timeout:.0f}s")

    def pump(self, duration: float):
        """Process incoming events for `duration` seconds (no RPC in flight)."""
        if not self.ws:
            return
        old = self.ws.gettimeout()
        deadline = time.time() + duration
        try:
            while time.time() < deadline:
                left = max(0.05, deadline - time.time())
                self.ws.settimeout(left)
                try:
                    msg = json.loads(self.ws.recv())
                except WebSocketTimeoutException:
                    break
                self._dispatch(msg)
        finally:
            self.ws.settimeout(old)

    def evaluate(self, expr: str, return_value=False):
        res = self.rpc("Runtime.evaluate", {
            "expression": expr,
            "returnByValue": return_value,
            "awaitPromise": False,
        })
        if return_value:
            return res.get("result", {}).get("value")
        return None

    def close(self):
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass


MAX_LOGIN_ATTEMPTS = 3


class ChromiumPanel:
    def __init__(self, panel, on_need_login, log, cdp_port: int,
                 poll_interval: float = 2.0, proxy=None, proxy_creds=None,
                 on_login_success=None):
        self.panel = panel
        self.on_need_login = on_need_login
        self.on_login_success = on_login_success
        self.log = log
        self.cdp_port = cdp_port
        self.poll_interval = poll_interval
        self.proxy = proxy                  # config.ProxyCfg | None
        self.proxy_creds = proxy_creds      # callable() -> {"user","pass"} | None
        self._login_attempts = 0
        self.proc = None
        self.cdp = None
        self._stop = threading.Event()
        self._thread = None
        self._auth_attempts = 0
        self._auth_failed = False
        self._last_fetch_event = 0.0

    def _uses_proxy(self) -> bool:
        return bool(self.proxy and self.proxy.enabled and self.panel.proxy)

    def _needs_proxy_auth(self) -> bool:
        return self._uses_proxy() and bool(self.proxy.vault_item)

    def show(self):
        self._thread = threading.Thread(target=self._control_loop, daemon=True)
        self._thread.start()

    def _spawn(self):
        p = self.panel
        g = p.geometry
        self._login_attempts = 0                 # fresh process = fresh budget
        profile = os.path.join(
            os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "soc-profiles", p.id)
        os.makedirs(os.path.join(profile, "Default"), exist_ok=True)
        # Seed prefs so Chromium never shows the "Save password?" bubble or the
        # session-restore prompt over a panel.
        prefs = os.path.join(profile, "Default", "Preferences")
        if not os.path.exists(prefs):
            with open(prefs, "w", encoding="utf-8") as fh:
                json.dump({
                    "credentials_enable_service": False,
                    "profile": {"password_manager_enabled": False,
                                "exit_type": "Normal"},
                }, fh)
        # With an authenticating proxy, start on a dark placeholder and only
        # navigate once the CDP Fetch auth handler is armed — otherwise the
        # first load hits the 407 before we can answer it and Chromium pops a
        # native credentials dialog nobody is there to fill in. (Not
        # about:blank — that demotes --app to a normal tabbed window.)
        target = p.effective_url or UNCONFIGURED_URL     # unconfigured -> blank
        first_url = UNCONFIGURED_URL if self._needs_proxy_auth() else target
        args = [
            _chromium_bin(),
            f"--app={first_url}",
            f"--class={p.wmclass}",
            f"--user-data-dir={profile}",
            f"--remote-debugging-port={self.cdp_port}",
            "--remote-debugging-address=127.0.0.1",
            f"--remote-allow-origins={cdp_allowed_origin(self.cdp_port)}",
            f"--window-position={g.x},{g.y}",
            f"--window-size={g.w},{g.h}",
            "--no-first-run", "--no-default-browser-check",
            "--disable-translate", "--disable-session-crashed-bubble",
            "--noerrdialogs", "--disable-infobars",
            "--password-store=basic", "--disable-component-update",
            "--disable-background-networking", "--disable-sync",
            "--disable-breakpad", "--metrics-recording-only",
            # 24/7 dashboard wall: keep panels refreshing even when occluded or
            # unfocused (Chromium otherwise throttles their background timers).
            "--disable-background-timer-throttling",
            "--disable-renderer-backgrounding",
            "--disable-backgrounding-occluded-windows",
            # Disk cache lives on tmpfs (RAM) via --user-data-dir under
            # XDG_RUNTIME_DIR, so this is a RAM cap, NOT an SD-card kindness.
            # Shrunk to 10 MB under the low-memory profile to protect the tight
            # 1 GB budget (set just below).
            "--disable-dev-shm-usage",             # /dev/shm is tiny on a 1 GB Pi
            "--disable-pinch", "--overscroll-history-navigation=0",
            "--disable-features=Translate,OptimizationHints",
            f"--ozone-platform={_ozone_platform()}",
            # sandbox stays ON in production. Some restricted CI/containers can't
            # init Chromium's namespace sandbox; SOC_CHROMIUM_NO_SANDBOX=1 is a
            # DEV-ONLY escape hatch (never set it on the Pi).
        ]
        # low-memory + media tuning (1 GB Pi): cap renderers; drop WebGL unless
        # the panel opted in with allow_media. The disk cache is on tmpfs (RAM),
        # so shrink it to 10 MB on small boards instead of the 50 MB default.
        if perf.low_memory():
            args.append("--renderer-process-limit=1")
            args.append("--disk-cache-size=10485760")   # 10 MB (RAM-backed)
        else:
            args.append("--disk-cache-size=52428800")    # 50 MB (RAM-backed)
        # GPU compositing on ARM (Pi 5 V3D) — no-op / empty on x86 dev.
        args += _hwaccel_flags()
        if not getattr(p, "allow_media", False):
            args.append("--disable-3d-apis")       # no WebGL/WebGL2
        if self._uses_proxy():
            args += proxy_flags(self.proxy)
        elif self.proxy and self.proxy.enabled:
            args.append("--no-proxy-server")   # panel opted out (proxy: false)
        if os.environ.get("SOC_CHROMIUM_NO_SANDBOX") == "1":
            args.append("--no-sandbox")
        self.log(f"[{p.id}] chromium spawning (CDP :{self.cdp_port}, "
                 f"ozone {_ozone_platform()})")
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

    # ---- proxy auth over CDP ------------------------------------------------
    def _on_cdp_event(self, method, params):
        self._last_fetch_event = time.time()
        if method == "Fetch.requestPaused":
            self.cdp.send_nowait("Fetch.continueRequest",
                                 {"requestId": params["requestId"]})
            return
        if method != "Fetch.authRequired":
            return
        rid = params["requestId"]
        challenge = params.get("authChallenge", {})
        if challenge.get("source") != "Proxy":
            # site-level auth is not ours to answer (panels log in via injection)
            self.cdp.send_nowait("Fetch.continueWithAuth", {
                "requestId": rid,
                "authChallengeResponse": {"response": "Default"}})
            return
        self._auth_attempts += 1
        if self._auth_attempts > PROXY_AUTH_MAX_ATTEMPTS or not self.proxy_creds:
            if not self._auth_failed:
                self._auth_failed = True
                self.log(f"[{self.panel.id}] proxy "
                         f"{challenge.get('origin', self.proxy.url)} rejected the "
                         f"credentials from vault item '{self.proxy.vault_item}' "
                         f"{PROXY_AUTH_MAX_ATTEMPTS} times — giving up. "
                         f"Check the username/password in the vault.")
            self.cdp.send_nowait("Fetch.continueWithAuth", {
                "requestId": rid,
                "authChallengeResponse": {"response": "CancelAuth"}})
            return
        creds = self.proxy_creds()
        if not creds:
            self.log(f"[{self.panel.id}] proxy auth: could not fetch credentials "
                     f"(vault item '{self.proxy.vault_item}')")
            self.cdp.send_nowait("Fetch.continueWithAuth", {
                "requestId": rid,
                "authChallengeResponse": {"response": "CancelAuth"}})
            return
        self.cdp.send_nowait("Fetch.continueWithAuth", {
            "requestId": rid,
            "authChallengeResponse": {"response": "ProvideCredentials",
                                      "username": creds.get("user", ""),
                                      "password": creds.get("pass", "")}})
        creds["pass"] = ""                  # scrub our copy
        self.log(f"[{self.panel.id}] proxy auth answered "
                 f"(vault item '{self.proxy.vault_item}')")

    def _proxy_auth_phase(self):
        """Brief window after attach where the Fetch domain is enabled and
        pumped fast, so the proxy's 407 gets answered without slowing the wall
        long-term. Chromium caches the proxy session afterwards."""
        if not self._needs_proxy_auth():
            return
        self._auth_attempts = 0
        self._auth_failed = False
        try:
            self.cdp.on_event = self._on_cdp_event
            self.cdp.rpc("Fetch.enable", {"handleAuthRequests": True})
            # we spawned on about:blank; now that auth is handled, go to the panel
            self.cdp.send_nowait("Page.navigate",
                                 {"url": self.panel.effective_url})
            start = time.time()
            self._last_fetch_event = start
            deadline = start + PROXY_AUTH_WINDOW
            while time.time() < deadline and not self._stop.is_set():
                self.cdp.pump(0.25)
                if self._auth_failed:
                    break
                # page settled (no paused requests for 2s after the initial
                # burst) -> auth is done, stop intercepting
                if (time.time() - start > 3.0
                        and time.time() - self._last_fetch_event > 2.0):
                    break
            self.cdp.rpc("Fetch.disable")
        except Exception as e:  # noqa: BLE001
            self.log(f"[{self.panel.id}] proxy auth phase: {e}")
        finally:
            if self.cdp:
                self.cdp.on_event = None

    def _attach_cdp(self) -> bool:
        p = self.panel
        if self.cdp:
            self.cdp.close()
            self.cdp = None
        try:
            cdp = _CDP(self.cdp_port)
            cdp.connect()
            cdp.rpc("Page.enable")
            cdp.rpc("Runtime.enable")
            boot = inject.bootstrap_js(p, mode="chromium")
            # future documents:
            cdp.rpc("Page.addScriptToEvaluateOnNewDocument", {"source": boot})
            # already-loaded document (bootstrap is idempotent):
            cdp.evaluate(boot)
            self.cdp = cdp
            self.log(f"[{p.id}] chromium CDP attached + bootstrap installed")
            self._proxy_auth_phase()
            return True
        except Exception as e:  # noqa: BLE001
            self.log(f"[{p.id}] chromium CDP setup failed: {e}")
            # close the half-open CDP websocket so a partial connect doesn't leak
            # an FD across the respawn
            try:
                cdp.close()
            except Exception:   # noqa: BLE001 — cdp may be unbound on early failure
                pass
            # a live process we cannot drive is useless — reap it (terminate +
            # wait, escalating to kill) and clear the handle so the control loop
            # cleanly respawns next iteration instead of dereferencing self.cdp
            # (now None) while the async-terminated process is still polling alive.
            self._reap()
            self.proc = None
            return False

    def _control_loop(self):
        p = self.panel
        respawn_delay = RESPAWN_INITIAL
        spawn_time = time.monotonic()
        while not self._stop.is_set():
            # (re)spawn + (re)attach when the process is missing or dead
            if self.proc is None or self.proc.poll() is not None:
                if self.proc is not None:
                    self.log(f"[{p.id}] chromium exited "
                             f"({self.proc.returncode}); restarting in "
                             f"{respawn_delay:.0f}s")
                    self._stop.wait(respawn_delay)
                    respawn_delay = min(respawn_delay * 2, RESPAWN_MAX)
                    if self._stop.is_set():
                        break
                try:
                    self._spawn()
                except Exception as e:  # noqa: BLE001
                    self.log(f"[{p.id}] chromium spawn failed: {e}; "
                             f"retrying in {respawn_delay:.0f}s")
                    self._stop.wait(respawn_delay)
                    respawn_delay = min(respawn_delay * 2, RESPAWN_MAX)
                    continue
                if not self._attach_cdp():
                    continue
                spawn_time = time.monotonic()   # mark a fresh, attached spawn

            try:
                # one round-trip for both flags
                st = self.cdp.evaluate(
                    "(function(){var s=window.__SOC||{};"
                    "return {n:!!s.needLogin,l:!!s.justLoggedIn};})()",
                    return_value=True) or {}
                need, logged_in = st.get("n"), st.get("l")
                if logged_in:
                    self.cdp.evaluate("window.__SOC.justLoggedIn=false")
                    self._login_attempts = 0
                    self.cdp.evaluate(inject.prompt_clear_call())
                    if self.on_login_success:
                        try:
                            self.on_login_success(p)
                        except Exception:        # noqa: BLE001
                            pass
                if need:
                    self._login_attempts += 1
                    if self._login_attempts > MAX_LOGIN_ATTEMPTS:
                        self.cdp.evaluate(inject.prompt_call(
                            "Auto-login failed — please sign in here, or open "
                            "Settings (⚙ top bar) to fix the saved login."))
                    else:
                        creds = self.on_need_login(p)
                        if creds:
                            self.cdp.evaluate(inject.login_call(creds))
                            creds["pass"] = ""
                            self.log(f"[{p.id}] injected login (chromium, "
                                     f"attempt {self._login_attempts})")
                        else:
                            self.cdp.evaluate(inject.prompt_call(
                                "Sign-in needed — no saved login for this page. "
                                "Open Settings (⚙ top bar) to add one, or log in here."))
                # Only clear the backoff once the spawn has actually survived a
                # while: a panel that attaches, polls once, then has its renderer
                # killed would otherwise reset to the floor delay and respawn
                # forever instead of climbing to RESPAWN_MAX.
                if time.monotonic() - spawn_time >= RESPAWN_STABLE_SEC:
                    respawn_delay = RESPAWN_INITIAL      # healthy again
            except Exception as e:  # noqa: BLE001
                if self.proc and self.proc.poll() is not None:
                    continue        # process died — handled by the respawn branch
                # page navigation can briefly drop the context; just retry
                self.log(f"[{p.id}] chromium poll: {e}")
            self._stop.wait(self.poll_interval)

    def set_url(self, url: str):
        """Repoint this panel live (from the on-screen config). Chromium can't be
        driven cross-thread safely, so we update the URL and recycle the process;
        the control loop respawns it with the new --app within a few seconds."""
        url = (url or "").strip()
        if url and not url.lower().startswith(("http://", "https://")):
            self.log(f"[{self.panel.id}] refusing non-http(s) URL: {url!r}")
            return
        self.panel.url = url or None
        if url:
            self.panel.mode = "direct"
        self.log(f"[{self.panel.id}] reconfigured -> {url or '(cleared)'}; "
                 f"restarting chromium")
        # Don't touch self.cdp here: this runs on the GTK main thread while the
        # control-loop worker may be mid-RPC on the same (non-thread-safe)
        # websocket. Just terminate the process; the worker detects the dead
        # proc and closes/reattaches the CDP on its own thread (_attach_cdp).
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()        # control loop respawns with the new URL

    def mem_rss_kb(self):
        """RSS of the Chromium process (KiB), or None if it isn't running. Note
        Chromium's helper processes aren't summed, so this under-counts — it is a
        relative signal for picking the heaviest panel, not an exact total."""
        p = self.proc
        if p and p.poll() is None:
            return perf.proc_rss_kb(p.pid)
        return None

    def recycle(self):
        """Reclaim memory by restarting the Chromium process; the control loop
        respawns it with the current URL within a few seconds."""
        self.log(f"[{self.panel.id}] recycling chromium to reclaim memory")
        # Don't touch self.cdp here (runs on the GTK main thread): the worker may
        # be mid-RPC on the same non-thread-safe websocket. Terminating the proc
        # is enough — the worker reaps the dead proc and closes/reattaches the
        # CDP on its own thread (_attach_cdp).
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def _reap(self):
        """Terminate the Chromium child and actually wait for it, escalating to
        kill(), so shutdown doesn't orphan a half-dead process (and leak its CDP
        port / profile lock) on a 24/7 box that restarts the service."""
        p = self.proc
        if not p or p.poll() is not None:
            return
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    def stop(self):
        self._stop.set()
        if self.cdp:
            self.cdp.close()
        self._reap()
