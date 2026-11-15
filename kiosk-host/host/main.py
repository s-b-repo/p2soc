"""
SOC kiosk host — entry point.

Boot sequence:
  1. load + validate config (panels.yaml) — a broken config fails loudly with
     every problem listed
  2. open the vault (unlock + sync via the vault backend, litebw by default)  [required]
  3. wait for the VPN (if any) + each tunnel's local port to answer  [best-effort]
  4. create the panel views, staggered:
       layout windows : one GTK window per panel (Openbox/labwc places them)
       layout single  : every WebKit panel in one fullscreen grid window
     (resolved from display.layout + the running backend, see config.resolve_layout)
  5. run the GTK main loop; inject logins on demand; keep sessions alive

Runs natively on X11 and Wayland (GTK picks the backend; we only adapt layout).

Liveness: from the moment GTK is up, a GLib timer on the main loop publishes a
heartbeat (host/heartbeat.py). It keeps firing inside the nested loops of the
unlock and fail-safe screens, and `state` says which of those is showing;
only the real wall reports "running".

With SOC_UNATTENDED=1 nobody is at the keyboard, so nothing here may wait for a
person. A vault that is late, locked or unreachable becomes a status screen and a
retry on a capped backoff, forever, and recovers with no restart; bad config shows
the fail-safe screen and exits periodically to reload; the operator-action exit
code (2) is never used. See _StatusBoard. Unset, none of this applies.

Run:  SOC_PANELS_FILE=config/panels.dev.yaml python3 -m host.main
"""
from __future__ import annotations

import os
import signal
import socket
import sys
import threading
import time

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import config as cfg  # noqa: E402
from . import configpaths  # noqa: E402  (shared read/write-location resolver)
from . import heartbeat  # noqa: E402
from . import perf  # noqa: E402
from .vault import Vault, VaultError  # noqa: E402

BEAT_SEC = 15                  # heartbeat cadence; launcher.sh gives up at 120 s
EXIT_OPERATOR = 2              # launcher.sh: stop supervising, back to the menu
EXIT_RELOAD = 1                # launcher.sh: restart us (unattended uses this one)
# Unattended vault retry: first wait, then doubling to the cap, forever.
UNATTENDED_RETRY_INITIAL = 3.0
UNATTENDED_RETRY_MAX = 60.0
# One attempt that outlives this has wedged a thread we cannot kill; the only clean
# recovery is a new process.
UNATTENDED_ATTEMPT_TIMEOUT = 300


def log(msg: str):
    t = time.strftime("%H:%M:%S")
    print(f"{t} [soc-kiosk] {msg}", flush=True)


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


def _on_color(hexc: str) -> str:
    """Pick black or white for text drawn ON a filled accent, by WCAG relative
    luminance — so a button label stays readable over any accent colour the
    palette supplies (e.g. a pale Amber fill needs black, a dark green needs
    white). Mirrors the contrast maths used by the appearance editor."""
    def _lin(v: float) -> float:
        v /= 255.0
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = _to_rgb(hexc)
    lum = 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)
    # Contrast vs white = 1.05/(L+0.05); vs black = (L+0.05)/0.05. Pick the higher.
    return "#FFFFFF" if (1.05 / (lum + 0.05)) >= ((lum + 0.05) / 0.05) else "#0B1F14"


class _Beat:
    """The heartbeat: one GLib timer on the main loop, so if the loop hangs the
    beats stop, and that absence is the signal launcher.sh and soc-update act on.
    Never write it from a worker thread: a beat from anywhere else proves nothing.
    GLib runs this timer inside Gtk.main(), Gtk.Dialog.run() and a bare
    GLib.MainLoop alike, since all of them iterate the default context, so the
    unlock and fail-safe screens beat too. The boot stretches that block the main
    thread between loops call set() directly."""

    def __init__(self):
        self.state = "starting"
        self._views = list            # callable() -> the live panel views
        self._src = 0

    def start(self, state: str = "starting"):
        self.state = state
        if not self._src:
            self._src = GLib.timeout_add_seconds(BEAT_SEC, self._tick)
        self._write()

    def set(self, state: str, views=None):
        """Change what the next beats say, and say it now. `views` is a callable
        returning the panel views, handed over once the wall exists."""
        self.state = state
        if views is not None:
            self._views = views
        self._write()

    def stop(self, state: str = "stopping"):
        """Last beat + remove the timer. No-op unless start() ran."""
        if not self._src:
            return
        GLib.source_remove(self._src)
        self._src = 0
        self.state = state
        self._write()

    def _write(self):
        views = list(self._views())
        heartbeat.write(len(views), sum(1 for v in views if _loaded_ok(v)),
                        state=self.state)

    def _tick(self):
        try:
            self._write()
        except Exception as e:        # noqa: BLE001 — must return True: a raise
            log(f"heartbeat failed: {e}")   # here would remove the timer for good
        return True


_beat = _Beat()


def _signal_add(sig, fn) -> int:
    """A main-loop signal handler. The API moved to GLibUnix in PyGObject 3.46;
    older builds only have the GLib spelling."""
    try:
        gi.require_version("GLibUnix", "2.0")
        from gi.repository import GLibUnix
        return GLibUnix.signal_add(GLib.PRIORITY_DEFAULT, sig, fn)
    except (ValueError, ImportError):
        return GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, fn)


def _loaded_ok(view) -> bool:
    """Did this panel's page finish loading without error? Never raises."""
    try:
        return bool(view.loaded_ok())
    except Exception:                  # noqa: BLE001
        return False


def _resolved_panels() -> str:
    """The panels.yaml the wall reads when $SOC_PANELS_FILE is unset — via the SAME
    resolver the wizard writes through, so a bare `python -m host.main` self-resolves
    to exactly what was just configured (per-user marker > /etc > repo). The literal
    'config/panels.yaml' is only the last-ditch fallback if nothing resolves."""
    return configpaths.resolve_panels() or "config/panels.yaml"


def detect_backend() -> str:
    """'wayland' or 'x11', from the GDK display GTK actually connected to."""
    disp = Gdk.Display.get_default()
    name = type(disp).__name__ if disp else ""
    return "wayland" if "Wayland" in name else "x11"


def detect_resolution():
    """(width, height) of the primary monitor, or None if it can't be read."""
    try:
        disp = Gdk.Display.get_default()
        mon = disp.get_primary_monitor() or disp.get_monitor(0)
        geo = mon.get_geometry()
        if geo.width > 0 and geo.height > 0:
            return geo.width, geo.height
    except Exception:  # noqa: BLE001
        pass
    return None


def _port_open(host: str, port: int, timeout=1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_tunnels(panels, timeout: float):
    """Report each tunnel as it comes up. One sweep over all of them, not one wait
    after another: a dead first tunnel must not hide the rest for its whole budget.
    These are loopback ports, so a sweep is instant and needs no thread per port."""
    waiting = [p for p in panels if p.mode == "tunnel" and p.tunnel_local_port]
    for p in waiting:
        log(f"[{p.id}] waiting for tunnel port 127.0.0.1:{p.tunnel_local_port} ...")
    deadline = time.time() + timeout
    while waiting and time.time() < deadline:
        for p in list(waiting):
            if _port_open("127.0.0.1", p.tunnel_local_port):
                log(f"[{p.id}] tunnel up")
                waiting.remove(p)
        if waiting:
            time.sleep(1)
    for p in waiting:
        log(f"[{p.id}] WARNING tunnel port {p.tunnel_local_port} never came up; "
            f"window will show a connection error")


def heaviest_panel(views):
    """The panel view with the largest measurable RSS, or None if none can be
    measured. Pure (testable) — the memory watchdog uses it to pick a recycle
    target under pressure."""
    best, best_rss = None, -1
    for v in views:
        try:
            rss = v.mem_rss_kb()
        except Exception:                  # noqa: BLE001 — never crash the watchdog
            rss = None
        if rss is not None and rss > best_rss:
            best, best_rss = v, rss
    return best


def _wait_for_one_vpn(vpn: dict, timeout: float):
    """Wait (best-effort) for ONE VPN's ready_probe to answer. Non-fatal."""
    name = (vpn.get("name") or "vpn")
    probe = (vpn.get("ready_probe") or "").strip()
    if not probe:
        return
    host, _, port = probe.rpartition(":")
    if not host or not port.isdigit():
        log(f"[vpn:{name}] ignoring malformed ready_probe '{probe}' (want host:port)")
        return
    port = int(port)
    log(f"[vpn:{name}] waiting for VPN reachability {host}:{port} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(host, port):
            log(f"[vpn:{name}] VPN up")
            return
        time.sleep(1)
    log(f"[vpn:{name}] WARNING {host}:{port} never became reachable; "
        f"VPN-side panels may show a connection error "
        f"(check: systemctl status forti-vpn / journalctl -u forti-vpn)")


def wait_for_vpn(vpns, timeout: float):
    """Best-effort gate over the WHOLE vpns[] list: for each enabled VPN that has
    a `ready_probe` (a host:port reachable only once that VPN is up), wait for it
    before opening VPN-side panels. The VPNs are brought up by forti-vpn.service;
    this only avoids loading panels into a dead route. Non-fatal.

    Accepts a list (conf.vpns) or, for back-compat, a single vpn dict. Probes run
    sequentially — a probe-less VPN is skipped instantly, so the common 0-or-1
    case costs the same as before."""
    if isinstance(vpns, dict):                  # back-compat: a single vpn dict
        vpns = [vpns] if vpns else []
    for vpn in (vpns or []):
        if isinstance(vpn, dict) and vpn.get("enabled"):
            _wait_for_one_vpn(vpn, timeout)


class KioskHost:
    def __init__(self, conf: cfg.Config, vault: "Vault | None" = None):
        self.conf = conf
        self.vault = vault or Vault(ttl=cfg.env_float("SOC_CRED_TTL", 30.0, lo=1.0))
        self.panels_view = []          # live panel objects (WebKit/Chromium)
        self.wall = None               # WallWindow in single-window layout
        self._config_win = None        # the on-screen config window, when open
        self._vpn_log_viewer = None    # live VPN-log viewer window, when open
        self._tray = None              # tray icon: windowed desktop runs only
        self._timers = []              # GLib sources removed on shutdown
        self._logged_in = set()        # panel ids whose current login is on record
        self._restart_src = 0          # a pending restart_wall()
        self._vpn_was_enabled = False  # last periodic poll saw an enabled VPN
        # Kiosk locker: PIN/TOTP-gated transparent overlay. State files live
        # under configwin.state_dir(); the vault enables its vault-backed TOTP
        # path. Built lazily so a missing module never blocks boot.
        try:
            from . import locker as _locker
            from . import configwin as _cw
            self._locker = _locker.KioskLocker(_cw.state_dir(), vault=self.vault)
        except Exception as e:         # noqa: BLE001
            self._locker = None
            log(f"kiosk locker unavailable: {e}")

    # creds callback handed to each panel
    def need_login(self, panel):
        # use the panel's vault_item, or a login remembered for this domain
        # (so a domain logged-in-before auto-logs-in on any panel)
        from . import loginmemory
        item = panel.vault_item or loginmemory.vault_item_for(panel.effective_url)
        panel._resolved_vault = item
        self._logged_in.discard(panel.id)
        if not item:
            return None                   # no creds known -> panel shows the popup
        # a panel with its own vault_item registers its domain immediately, so
        # other panels at the same domain reuse it (login often navigates away,
        # so we can't wait for an in-page "logged in" signal to record it)
        if panel.vault_item:
            loginmemory.remember(panel.effective_url, panel.vault_item)
        try:
            return self.vault.creds(item)
        except VaultError as e:
            log(f"[{panel.id}] vault: {e}")
            return None

    # called by a panel when a login succeeds — remember the domain -> vault item
    def login_success(self, panel):
        # The page reports "logged in" on every document it loads, so a dashboard
        # that reloads itself lands here all day. Once per login is enough: this is
        # a disk read plus a journal line on the SD card.
        if panel.id in self._logged_in:
            return
        from . import loginmemory
        item = getattr(panel, "_resolved_vault", "") or panel.vault_item
        if item:
            self._logged_in.add(panel.id)
            loginmemory.remember(panel.effective_url, item)
            log(f"[{panel.id}] login OK — remembered "
                f"{loginmemory.domain_of(panel.effective_url)} -> '{item}'")

    # proxy-credential callback (proxy.vault_item) handed to each panel
    def proxy_creds(self):
        item = self.conf.proxy.vault_item
        if not item:
            return None
        try:
            return self.vault.creds(item)
        except VaultError as e:
            log(f"[proxy] vault: {e}")
            return None

    def open_vault(self):
        """Unlock + re-sync the vault. Blocks on the network: worker threads only."""
        backend = os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND)
        log(f"opening vault (backend={backend}) ...")
        self.vault.open()
        log("vault unlocked + synced")

    def _start_vault_resync(self):
        """Unattended: litebw serves logins from the RAM copy of the vault taken at
        boot, so a password rotated in Vaultwarden would never reach this wall
        without a restart, and nobody is here to do one. Re-sync hourly. A failed
        sync keeps the copy we have."""
        sec = cfg.env_int("SOC_VAULT_RESYNC_SEC", 3600, lo=60, hi=86400)
        self._keep_timer(GLib.timeout_add_seconds(sec, self._resync_vault))

    def _resync_vault(self):
        def work():
            try:
                self.open_vault()
            except Exception as e:     # noqa: BLE001 — the RAM copy still serves
                log(f"vault re-sync failed; keeping the current copy: {e}")
        threading.Thread(target=work, daemon=True).start()
        return True

    def prewarm_creds(self):
        """Fetch every panel/proxy/remembered login into the cache in the
        background, so the first login of each panel is served from cache and
        never blocks the GTK thread on a vault call."""
        from . import loginmemory
        items = [p.vault_item for p in self.conf.panels if p.vault_item]
        if self.conf.proxy.vault_item:
            items.append(self.conf.proxy.vault_item)
        items += list(loginmemory.load().values())
        if not items:
            return

        def work():
            n = self.vault.prewarm(items, log)
            log(f"prewarmed {n} vault credential(s)")
        threading.Thread(target=work, daemon=True).start()

    def _autosize(self):
        """display.auto: recompute the grid from the real screen size."""
        if not self.conf.display.auto:
            return
        res = detect_resolution()
        if not res:
            return
        d = self.conf.display
        if (d.width, d.height) != res:
            log(f"display auto-detect: {res[0]}x{res[1]} "
                f"(config said {d.width}x{d.height})")
            d.width, d.height = res
            for p in self.conf.panels:
                p.geometry = cfg.compute_geometry(d, p.grid)

    def build_and_show(self):
        backend = detect_backend()
        layout = cfg.resolve_layout(self.conf, backend)
        env_layout = os.environ.get("SOC_LAYOUT", "")
        if env_layout in ("windows", "single"):
            layout = env_layout       # session script override (e.g. under cage)
        log(f"backend={backend} layout={layout}")
        self._autosize()

        # the on-screen config (gear + Ctrl+Shift+C) can be disabled for a
        # locked-down wall: SOC_ONSCREEN_CONFIG=0
        config_cb = (self.open_config
                     if os.environ.get("SOC_ONSCREEN_CONFIG", "1") != "0" else None)
        if config_cb is None:
            log("on-screen config disabled (SOC_ONSCREEN_CONFIG=0)")

        if layout == "single":
            from .wall import WallWindow
            # A tray needs a desktop to live on, and someone to bring the wall back
            # from it: a hidden wall on an unattended box would stay hidden.
            windowed = (os.environ.get("SOC_WINDOWED") == "1"
                        or not getattr(self.conf.display, "fullscreen", True))
            if windowed and not perf.unattended():
                self._install_tray()
            self.wall = WallWindow(self.conf, log, on_destroy=self.shutdown,
                                   on_config=config_cb, on_vpn=self.vpn_action,
                                   on_lock=(self._lock_wall
                                            if self._locker is not None else None),
                                   on_show_vpn_log=self.open_vpn_log_viewer,
                                   on_hide_to_tray=(self._hide_to_tray
                                                    if self._tray is not None
                                                    else None))

        stagger = cfg.env_float("SOC_LAUNCH_STAGGER", 1.5, lo=0.0, hi=60.0)
        cdp_base = cfg.env_int("SOC_CDP_BASE_PORT", 9222, lo=1024, hi=65535)
        delay = 0.0
        for idx, panel in enumerate(self.conf.panels):
            # Guard each per-panel constructor: one malformed panel (bad
            # geometry, a WebKit2 version mismatch, an OSError creating the 0700
            # chromium profile dir) is logged + skipped so the REST of the wall
            # still paints, instead of one bad panel aborting build_and_show()
            # to the fatal screen. The happy path is unchanged.
            try:
                view = self._make_view(panel, cdp_base + idx, config_cb)
            except Exception as e:  # noqa: BLE001 — skip one bad panel, keep the wall
                log(f"[{getattr(panel, 'id', '?')}] panel construction failed; "
                    f"skipping this panel: {e}")
                continue
            self.panels_view.append(view)
            self._keep_timer(GLib.timeout_add(int(delay * 1000), self._show_one, view))
            delay += stagger

        if self.wall is not None:
            self.wall.show()
            self._start_vpn_monitor()
            # boot-time file-integrity check: warn on the top bar if the
            # deployed tree has drifted from the install-time manifest.
            self._check_deploy_drift()
        self._start_mem_watch()
        # Theme sync: repaint on a theme saved by the setup wizard (15 s is plenty).
        self._keep_timer(GLib.timeout_add_seconds(15, self._check_branding))
        # The first Apply must not stall the GTK thread on a `sudo -n` probe:
        # settle the cached answer now, off-thread.
        threading.Thread(target=self._can_systemctl_restart, daemon=True).start()
        if perf.unattended():
            self._start_vault_resync()

    def _make_view(self, panel, cdp_port: int, config_cb):
        """Build one panel view and, in single layout, attach it to the wall."""
        if panel.engine == "chromium":
            from .chromium_panel import ChromiumPanel
            return ChromiumPanel(panel, self.need_login, log,
                                 cdp_port=cdp_port,
                                 proxy=self.conf.proxy,
                                 proxy_creds=self.proxy_creds,
                                 security=self.conf.security,
                                 on_login_success=self.login_success)
        from .webkit_panel import WebKitPanel
        view = WebKitPanel(panel, self.need_login, log,
                           embedded=self.wall is not None,
                           proxy=self.conf.proxy,
                           proxy_creds=self.proxy_creds,
                           security=self.conf.security,
                           on_config=config_cb,
                           on_login_success=self.login_success)
        if self.wall is not None:
            self.wall.attach(panel, view.widget)
        return view

    def _keep_timer(self, src: int) -> int:
        """Remember a GLib source so shutdown() can remove it."""
        self._timers.append(src)
        return src

    def _check_branding(self):
        """Detect a theme saved by another process (the setup wizard touches a
        marker) and repaint the running wall without a restart."""
        try:
            from . import branding, style
            mt = branding._marker_mtime()
            if mt > branding._marker_mtime_val:
                branding._marker_mtime_val = mt
                branding.load(refresh=True)
                style.apply_css(refresh=True)
                log("theme changed — wall repainted")
        except Exception as e:         # noqa: BLE001 — a theme must not stop the wall
            log(f"theme sync failed: {e}")
        return True

    # ---- memory watchdog ---------------------------------------------------
    def _start_mem_watch(self):
        """On a 1 GB Pi a single leaking dashboard can OOM the box. Periodically
        check MemAvailable and, under sustained pressure, recycle one panel
        (heaviest measurable first) to reclaim memory — with hysteresis and a
        cooldown so it can't thrash."""
        if perf.mem_available_mb() is None:
            return                          # not Linux/proc — nothing to watch
        self._mem_min_mb = cfg.env_int("SOC_MEM_MIN_AVAIL_MB", 150, lo=16, hi=8192)
        self._mem_check_sec = cfg.env_int("SOC_MEM_CHECK_SEC", 30, lo=5, hi=3600)
        self._mem_cooldown = cfg.env_int("SOC_MEM_RECYCLE_COOLDOWN", 120, lo=10)
        self._mem_low_streak = 0
        self._mem_last_recycle = 0.0
        self._mem_rr = 0
        log(f"memory watchdog on: recycle a panel when MemAvailable < "
            f"{self._mem_min_mb} MB (every {self._mem_check_sec}s)")
        self._keep_timer(GLib.timeout_add_seconds(self._mem_check_sec,
                                                  self._check_memory))

    def _check_memory(self):
        avail = perf.mem_available_mb()
        if not perf.under_pressure(avail, self._mem_min_mb):
            self._mem_low_streak = 0
            return True
        self._mem_low_streak += 1
        now = time.time()
        # need two consecutive low readings (ignore a transient dip) and respect
        # the cooldown since the last recycle
        if self._mem_low_streak < 2 or (now - self._mem_last_recycle) < self._mem_cooldown:
            return True
        view = self._pick_recycle_target()
        if view is not None:
            log(f"[mem] MemAvailable {avail} MB < {self._mem_min_mb} MB — "
                f"recycling panel {view.panel.id}")
            try:
                view.recycle()
            except Exception as e:          # noqa: BLE001
                # The recycle FAILED and reclaimed nothing while memory is still
                # critical. Do NOT consume the cooldown or fully reset the
                # streak — that would throttle the watchdog out of retrying for
                # the full cooldown while the box stays under the floor and gets
                # OOM-killed. Leave _mem_last_recycle untouched and clamp the
                # streak to 1 so a single next low reading re-arms a retry.
                log(f"[mem] recycle of {view.panel.id} failed: {e}")
                self._mem_low_streak = 1
            else:
                # Recycle succeeded — start the cooldown and reset hysteresis.
                self._mem_last_recycle = now
                self._mem_low_streak = 0
        return True

    def _pick_recycle_target(self):
        """The heaviest panel by renderer RSS. Round-robin only when no panel can
        be measured at all (no /proc), so the watchdog still does something."""
        heaviest = heaviest_panel(self.panels_view)
        if heaviest is not None:
            return heaviest
        if self.panels_view:
            v = self.panels_view[self._mem_rr % len(self.panels_view)]
            self._mem_rr += 1
            return v
        return None

    # ---- VPN status pill ---------------------------------------------------
    def _start_vpn_monitor(self):
        """Poll the VPN state in the background and keep the wall pill current."""
        if self.wall is None:
            return
        interval = cfg.env_int("SOC_VPN_STATUS_INTERVAL", 10, lo=1, hi=3600)
        self._poll_vpn()                              # immediate first reading
        self._keep_timer(GLib.timeout_add_seconds(max(3, interval),
                                                  self._poll_vpn_periodic))

    def _poll_vpn_periodic(self):
        # With no VPN enabled there is nothing to probe. One last pass after the
        # list empties, so the pill doesn't stay on the state of a removed VPN.
        enabled = any(isinstance(v, dict) and v.get("enabled")
                      for v in (self.conf.vpns or []))
        if enabled or self._vpn_was_enabled:
            self._poll_vpn()
        self._vpn_was_enabled = enabled
        return True                                   # keep the timeout alive

    def _poll_vpn(self):
        # each probe can block (TCP connect), so compute off the GTK thread
        from . import vpnstatus, vpnmanager

        # Skip this tick if the previous probe is still running, so a slow/hung
        # connect near the poll interval can't pile up daemon threads. A probe
        # thread that dies without reporting back would otherwise freeze the pill
        # forever, so a grossly overdue one is abandoned and we probe afresh.
        interval = cfg.env_int("SOC_VPN_STATUS_INTERVAL", 10, lo=1, hi=3600)
        if getattr(self, "_vpn_poll_busy", False):
            if time.time() - getattr(self, "_vpn_poll_started", 0.0) < interval * 3:
                return False
            log("[vpn] previous status probe overdue — starting a fresh one")
        self._vpn_poll_busy = True
        self._vpn_poll_started = time.time()

        def work():
            # Per-name states for EACH enabled VPN, plus one aggregate for the
            # single pill of a 0-or-1-VPN wall. The tooltip lists every VPN, so a
            # multi-VPN wall shows which one is down at a glance.
            states = {}
            try:
                enabled = [v for v in (self.conf.vpns or [])
                           if isinstance(v, dict) and v.get("enabled")]
                for i, v in enumerate(enabled):
                    states[vpnstatus.vpn_name(v, i)] = vpnstatus.vpn_state(v)
            except Exception:                          # never let the pill crash us
                states = {}
            finally:
                GLib.idle_add(self._clear_vpn_busy)

            def css(state):
                return {"not_configured": "unconfigured"}.get(state, state)
            # tooltip: per-name breakdown ("corp: online | lab: offline")
            tip = " | ".join(
                f"{nm}: {st.replace('_', ' ')}" for nm, st in states.items()
            ) or "VPN: not configured"
            if len(states) <= 1:
                agg = vpnmanager.aggregate_state(states)
                results = [("", css(agg), vpnstatus.LABELS.get(agg, "VPN: ?"), tip)]
            else:
                results = [(nm, css(st), f"{nm}: {st.replace('_', ' ')}", tip)
                           for nm, st in states.items()]
            GLib.idle_add(self._set_pills, results)
        # If thread start fails (RuntimeError 'can't start new thread' under
        # thread exhaustion / OOM on the 1 GB board), work() never runs to clear
        # _vpn_poll_busy, so clear it here and let the next tick retry. Keep setting
        # the flag on the GTK thread: the early-return must see it before work()
        # is scheduled.
        try:
            threading.Thread(target=work, daemon=True).start()
        except RuntimeError as e:
            self._vpn_poll_busy = False
            log(f"[vpn] could not start status-poll thread; will retry next tick: {e}")
        return False

    def _clear_vpn_busy(self):
        self._vpn_poll_busy = False
        return False

    def _set_pills(self, results):
        """Apply pill updates: results is a list of (name, css, label, tooltip);
        name '' is the wall's single pill."""
        if self.wall is not None:
            for name, css, label, tip in results:
                self.wall.set_vpn_status(css, label, name=name)
                for pill in self.wall.vpn_pills:
                    if pill["name"] == name:
                        pill["button"].set_tooltip_text(
                            f"{tip}\nClick to re-check / reconnect")
        return False

    # ---- kiosk lock + VPN-log viewer --------------------------------------
    def _lock_wall(self):
        """Show the kiosk-lock overlay (toolbar 🔒 / Ctrl+Alt+L). Panels keep
        rendering underneath; keyboard + mouse are inert until the operator
        enters the PIN/TOTP (or the sealed setup PIN as an admin override)."""
        if self._locker is None:
            log("lock requested but the kiosk locker is unavailable")
            return
        self._close_config()
        try:
            self._locker.lock(on_unlock=None)
        except Exception as e:  # noqa: BLE001
            log(f"lock failed: {e}")

    def _close_config(self):
        """Take the Settings window down. It is a top-level of its own, so left open
        it would stay usable above the lock screen. A failure here must not stop
        the lock that follows."""
        win, self._config_win = getattr(self, "_config_win", None), None
        if win is None:
            return
        try:
            win.destroy()
        except Exception as e:  # noqa: BLE001
            log(f"could not close Settings before locking: {e}")

    def _install_tray(self):
        """Best-effort tray icon. If no backend is available the close button
        simply quits, as it would without a tray."""
        try:
            from . import tray as _tray
        except Exception as e:                          # noqa: BLE001
            log(f"tray module import failed: {e}")
            return
        if not _tray.available():
            log("no tray backend available — close button will quit")
            return
        t = _tray.Tray(app_id="soc-wall", icon_name="video-display", title="SOC wall")
        ok = t.install([
            ("Show wall",      lambda: self.wall and self.wall.window.present()),
            ("Lock panel",     self._lock_wall),
            None,
            ("Open Settings",  self.open_config),
            ("Show VPN log",   self.open_vpn_log_viewer),
            ("Restart wall",   self.restart_wall),
            None,
            ("Reboot machine", self._tray_reboot),
            None,
            ("Quit",           self.shutdown),
        ])
        if ok:
            self._tray = t
            log(f"tray installed (backend={t.backend})")
        else:
            log("tray install failed")

    def _hide_to_tray(self):
        """delete-event with a tray: hide. The wall keeps running; the tray's
        'Show wall' brings it back."""
        if self.wall is not None and self.wall.window is not None:
            self.wall.window.hide()

    def _tray_reboot(self):
        """`systemctl reboot`, off the GTK thread. Needs privilege; a refusal is
        logged, not fatal."""
        import subprocess

        def work():
            log("tray: reboot requested")
            try:
                subprocess.run(["systemctl", "reboot"], timeout=10, check=True,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            except (OSError, subprocess.SubprocessError) as e:
                log(f"tray: reboot not permitted ({e})")
        threading.Thread(target=work, daemon=True).start()

    def open_vpn_log_viewer(self):
        """Open (or present) the live VPN log viewer — streams
        `journalctl -u forti-vpn.service` so the operator sees every supervisor
        step + error as it lands. Single-instance; SEPARATE from the reconnect
        pill (this only observes, it never restarts the VPN)."""
        try:
            from . import vpn_log_viewer as _vlv
        except Exception as e:                          # noqa: BLE001
            log(f"vpn-log-viewer module unavailable: {e}")
            return
        if self._vpn_log_viewer is None:
            names = [v.get("name") or "vpn"
                     for v in (self.conf.vpns or [])
                     if isinstance(v, dict) and v.get("enabled")]
            self._vpn_log_viewer = _vlv.VpnLogViewer(
                on_reconnect=self.vpn_action,
                on_close=lambda: setattr(self, "_vpn_log_viewer", None),
                names=names)
        self._vpn_log_viewer.show()

    # ---- privileged systemctl ---------------------------------------------
    def _can_systemctl_restart(self) -> bool:
        """True iff this process can `systemctl restart` the wall's managed
        units WITHOUT a password prompt. Three paths:

          1. euid 0 — running as root (dev), trivially yes.
          2. `sudo -n systemctl status forti-vpn.service` exits 0/3/4 —
             /etc/sudoers.d/soc-wall-restart granted `soc` NOPASSWD systemctl
             on a minimal allowlist (forti-vpn, autossh-tunnel). systemctl
             status returns 0 (active), 3 (dead but loaded) or 4 (no such
             unit) once it's run — any of those means we cleared sudo's auth
             gate; sudo with no NOPASSWD rule returns 1 without ever running
             systemctl.
          3. Otherwise False.

        Cached after the first probe so the apply path stays fast."""
        import os as _os
        if _os.geteuid() == 0:
            return True
        cached = getattr(self, "_sudo_systemctl_ok", None)
        if cached is not None:
            return cached
        import subprocess
        ok = False
        try:
            r = subprocess.run(
                ["sudo", "-n", "/usr/bin/systemctl", "status",
                 "forti-vpn.service"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
            )
            ok = r.returncode in (0, 3, 4)
        except (OSError, subprocess.SubprocessError):
            ok = False
        self._sudo_systemctl_ok = ok
        return ok

    def _privileged_systemctl(self, *args) -> "tuple[bool, str]":
        """Run `systemctl <args>` with the minimum privilege needed: bare if
        we're root, `sudo -n` if we have NOPASSWD coverage, else refuse
        (returning False) so the caller can surface a clean message. Returns
        (ok, stdout-or-stderr)."""
        import os as _os
        import subprocess
        if _os.geteuid() != 0 and not self._can_systemctl_restart():
            return False, "no NOPASSWD sudo for systemctl"
        cmd = ["/usr/bin/systemctl", *args] if _os.geteuid() == 0 \
            else ["sudo", "-n", "/usr/bin/systemctl", *args]
        try:
            r = subprocess.run(cmd, timeout=15,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True)
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"systemctl invocation failed: {e}"
        if r.returncode == 0:
            return True, (r.stdout or "ok").strip()
        return False, (r.stderr or r.stdout or "").strip()

    def _restart_vpn_service(self, ok_msg, fail_msg, on_done=None):
        """Restart `forti-vpn.service` off the GTK thread via the privileged
        path (root, or the NOPASSWD sudoers drop-in install.sh writes). The
        single unit supervises Fortinet/OpenVPN/WireGuard. On failure the
        systemctl stderr is surfaced (no longer swallowed) so the operator
        knows why the reconnect didn't take. Schedules on_done(ok, info) if
        given so the caller can surface the outcome on-screen (not just log it)."""

        def work():
            try:
                ok, info = self._privileged_systemctl("restart", "forti-vpn.service")
                if ok:
                    log(ok_msg)
                else:
                    log(f"{fail_msg} ({info})")
                if on_done is not None:
                    # on_done may touch GTK widgets (pill tooltip), so hop to the
                    # main thread — work() is on a daemon worker.
                    GLib.idle_add(on_done, ok, info)
            except Exception as e:  # noqa: BLE001 — worker must not die silently
                # If work() raised BEFORE scheduling on_done, the pill would
                # stay frozen on 'checking…' forever (on_done never runs, no
                # re-poll). Log it (not swallowed) and reset the pill promptly
                # via a re-poll. NOT a finally — the happy path already re-polls
                # through _vpn_reconnect_done, so a finally would double-schedule.
                log(f"VPN restart worker error: {e}")
                GLib.idle_add(self._poll_vpn)
        threading.Thread(target=work, daemon=True).start()

    def _vpn_reconnect_done(self, ok, info, sink=None):
        """Reconnect finished. On a privilege refusal the pill would otherwise
        just snap back to 'down' with the reason buried in a log the kiosk
        operator never sees — surface it as a pill tooltip pointing at the VPN
        log viewer, so the click isn't a silent dead-end. Then re-poll.

        `sink` (when the VPN-log viewer requested the reconnect) gets the same
        human outcome so the viewer prints success/refusal/failure instead of
        leaving a lone '[viewer] reconnect requested' with no result line.
        Runs on the GTK main thread (dispatched via GLib.idle_add), so calling
        the viewer's buffer append is thread-safe."""
        if ok:
            tip = "VPN status — click to re-check / reconnect"
            outcome = "reconnect requested OK — see the log below for each step"
        elif "no NOPASSWD sudo" in (info or ""):
            tip = ("Reconnect needs privilege this user doesn't have. Run the "
                   "wall as root, or let install.sh add the NOPASSWD systemctl "
                   "sudoers rule. Click the \U0001f4dc VPN-log button for details.")
            outcome = ("reconnect refused: no NOPASSWD sudo for systemctl — "
                       "see pill tooltip")
        else:
            tip = (f"Reconnect failed: {info}\nClick the \U0001f4dc VPN-log "
                   f"button to see the supervisor output.")
            outcome = f"reconnect failed: {info}"
        if self.wall is not None and self.wall.vpn_pill is not None:
            try:
                self.wall.vpn_pill.set_tooltip_text(tip)
            except Exception:  # noqa: BLE001 — tooltip is a nicety, never fatal
                pass
        if sink is not None:
            try:
                sink(outcome)
            except Exception:  # noqa: BLE001 — viewer line is a nicety, never fatal
                pass
        GLib.timeout_add_seconds(2, self._poll_vpn)
        return False

    def vpn_action(self, sink=None):
        """Pill click: show 'checking', best-effort reconnect, then re-poll. The
        reconnect runs off the GTK thread so it can't freeze the wall.

        `sink` is an optional callable(text) the VPN-log viewer passes so the
        reconnect OUTCOME (success / privilege-refusal / failure) is printed in
        the viewer too — not just on the pill tooltip. Default None keeps both
        no-arg call sites (the pill's on_vpn and the viewer's on_reconnect)
        working unchanged on the happy path."""
        if self.wall is not None:
            self.wall.set_vpn_status("checking", "VPN: checking…", name=None)
        any_enabled = any(
            isinstance(v, dict) and v.get("enabled")
            for v in (self.conf.vpns or []))
        if not any_enabled:
            if sink is not None:
                try:
                    sink("no VPN is enabled — nothing to reconnect")
                except Exception:  # noqa: BLE001
                    pass
            self._poll_vpn()
            return
        self._restart_vpn_service(
            "VPN reconnect requested (systemctl restart forti-vpn)",
            "VPN reconnect not permitted from the wall; re-checking",
            on_done=lambda ok, info: self._vpn_reconnect_done(ok, info, sink=sink))

    # ---- on-screen configuration ------------------------------------------
    def open_config(self):
        """Open the floating, PIN-lockable config window (gear / Ctrl+Shift+C)."""
        if getattr(self, "_config_win", None) is not None:
            self._config_win.present()
            return
        try:
            from .configwin import ConfigWindow
            win = ConfigWindow(self.conf.panels, self.apply_config,
                               on_close=self._config_closed,
                               display=self.conf.display,
                               vpn=self.conf.vpn,
                               vpns=self.conf.vpns,
                               proxy=self.conf.proxy,
                               tunnel=self.conf.tunnel,
                               proxy_vault_item=self.conf.proxy.vault_item,
                               login_stats=self.login_stats,
                               vault=self.vault,
                               actions={
                                   "restart_wall": self.restart_wall,
                                   "reload_panels": self.reload_all_panels,
                                   "lock_wall": self._lock_wall,
                                   "calibrate_panel": self.calibrate_panel,
                                   "stop_vpn_unit": self._stop_vpn_unit,
                                   "show_vpn_log": self.open_vpn_log_viewer,
                               })
            self._config_win = win
            win.show_all()
            win.present()
        except Exception as e:  # noqa: BLE001 — never let the config UI kill the wall
            self._config_win = None
            log(f"config window failed to open: {e}")

    def _check_deploy_drift(self):
        """Compare on-disk file hashes against the deploy-time manifest and
        paint a top-bar warning if anything has drifted. Best-effort +
        non-fatal: a missing/unreadable manifest, or any other error, is logged
        and skipped — the warning only appears when we positively find drift.

        check_drift() SHA-256-hashes the whole deploy tree, which is slow on the
        SD card — run it on a daemon worker so the just-mapped wall stays
        interactive, and deliver the warning via idle_add (mirrors _poll_vpn)."""
        if self.wall is None:
            return
        try:
            from . import manifest as _mf
        except Exception as e:                         # noqa: BLE001
            log(f"manifest check skipped: import failed ({e})")
            return
        deploy_root = (os.environ.get("SOC_DEPLOY_ROOT")
                       or os.environ.get("SOC_ROOT") or "/opt/soc-display")

        def work():
            try:
                drift = _mf.check_drift(deploy_root)
            except FileNotFoundError:
                log(f"manifest check skipped: no manifest at "
                    f"{_mf.MANIFEST_PATH} (re-run install.sh to enable)")
                return
            except (OSError, ValueError, KeyError) as e:
                log(f"manifest check skipped: {e}")
                return
            msg = _mf.format_drift_summary(drift)
            if msg:
                # Pass the full drift dict so wall.py can open a detail modal
                # listing changed / missing / extras + a link to the deployed
                # commit on GitHub.
                GLib.idle_add(self.wall.show_top_bar_warning, msg, drift)
                log(f"file drift detected: {len(drift['changed'])} changed, "
                    f"{len(drift['missing'])} missing, "
                    f"{len(drift['extras'])} extras (commit "
                    f"{(drift.get('commit') or 'unknown')[:12]})")
            else:
                log("manifest check ok — no drift")
        threading.Thread(target=work, daemon=True).start()

    def _config_closed(self):
        self._config_win = None

    def calibrate_panel(self, panel_id: str, on_done):
        """Start click-zone calibration on a panel. on_done(zones or None) fires
        when the operator finishes, cancels, or it times out. Captured zones are
        saved to the overrides and go live on the panel straight away."""
        view = next((v for v in self.panels_view
                     if getattr(getattr(v, "panel", None), "id", None) == panel_id),
                    None)
        if view is None or not hasattr(view, "calibrate"):
            log(f"calibrate_panel: no calibratable view for id={panel_id!r}")
            on_done(None)
            return

        def _on_zones(zones):
            if zones is not None:
                try:
                    view.panel.login_zones = dict(zones)
                    self._save_login_zones_override(panel_id, zones)
                    reinject = getattr(view, "reinject", None)
                    if reinject is not None:
                        reinject()
                except Exception as e:                 # noqa: BLE001
                    log(f"calibrate_panel: persist failed for {panel_id}: {e}")
            try:
                on_done(zones)
            except Exception as e:                     # noqa: BLE001
                log(f"calibrate_panel: on_done raised: {e}")

        try:
            view.calibrate(_on_zones)
        except Exception as e:                         # noqa: BLE001
            log(f"calibrate_panel: view.calibrate raised: {e}")
            on_done(None)

    def _save_login_zones_override(self, panel_id: str, zones: dict):
        """Merge the zones into this panel's overrides, keeping its other fields,
        so a calibration survives a restart."""
        from . import configwin
        ov = configwin.load_overrides()
        per = dict(ov.get(panel_id) or {})
        per["login_zones"] = {k: dict(v) for k, v in zones.items()}
        ov[panel_id] = per
        configwin.save_overrides(ov)
        log(f"saved login_zones override for {panel_id} ({sorted(zones)})")

    def reload_all_panels(self) -> int:
        """Reload every panel in place, with no teardown and no exit. Returns how
        many were refreshed."""
        n = 0
        for v in self.panels_view:
            try:
                v.set_url(v.panel.url or "")
                n += 1
            except Exception as e:                     # noqa: BLE001
                log(f"[{getattr(v.panel, 'id', '?')}] reload failed: {e}")
        log(f"reload_all_panels: refreshed {n}/{len(self.panels_view)} panel(s)")
        return n

    def restart_wall(self):
        """Soft restart with the current config. After 500 ms, so the GUI can paint
        its 'restarting' message first. Under systemd (which also covers
        launcher.sh) we exit cleanly and get respawned; run bare, there is nobody
        to do that, so we re-exec ourselves."""
        if self._restart_src:
            return
        log("restart_wall: restarting in 0.5 s")
        self._restart_src = GLib.timeout_add(500, self._do_restart)

    def _do_restart(self):
        self._restart_src = 0
        if not os.environ.get("INVOCATION_ID"):
            log("restart_wall: re-execing")
            for v in self.panels_view:
                try:
                    v.stop()
                except Exception as e:                 # noqa: BLE001
                    log(f"restart_wall: stop failed: {e}")
            try:
                os.execv(sys.executable, [sys.executable, "-m", "host.main"])
            except OSError as e:
                log(f"restart_wall: execv failed ({e}); exiting instead")
        self.shutdown()
        return False

    def _restart_wall_at_tail(self):
        """apply_config's last act: everything else in the Apply has landed."""
        self.restart_wall()

    def login_stats(self) -> dict:
        """Per-panel auto-login stats for the Status tab: {id: {attempts, stale}}. A
        panel that burned half its budget without logging in probably has stale
        selectors after a dashboard redesign."""
        out = {}
        for v in self.panels_view:
            try:
                attempts = int(getattr(v, "_login_attempts", 0))
                out[v.panel.id] = {"attempts": attempts, "stale": attempts >= 2}
            except Exception:                          # noqa: BLE001
                continue
        return out

    def _apply_display_live(self, changes: dict, current: dict) -> bool:
        """Apply width/height/fullscreen/cols/rows in place. Mutates conf.display
        first, so other paths see the new values, then nudges the wall. False (never
        a raise) tells the caller to fall back to a soft restart."""
        try:
            wall = self.wall
            if wall is None or wall.window is None:
                return False
            d = self.conf.display
            for key in ("width", "height", "cols", "rows"):
                if key in changes:
                    setattr(d, key, int(changes[key]))
            if "fullscreen" in changes:
                d.fullscreen = bool(changes["fullscreen"])

            if "width" in changes or "height" in changes:
                # In fullscreen the WM owns the size; the re-fit covers both cases.
                wall.window.resize(d.width, d.height)
                wall._fit_to_screen()
            if "fullscreen" in changes and d.fullscreen != bool(
                    getattr(wall, "_fullscreen", True)):
                wall._toggle_fullscreen()
            if "cols" in changes or "rows" in changes:
                # Detach + re-attach so the homogeneous grid recomputes its layout.
                # The widgets are the live webviews: no reload, no flicker.
                for p in self.conf.panels:
                    p.geometry = cfg.compute_geometry(d, p.grid)
                grid = wall.grid
                views = [v for v in self.panels_view
                         if getattr(v, "widget", None) is not None]
                for v in views:
                    grid.remove(v.widget)
                grid.set_row_homogeneous(True)
                grid.set_column_homogeneous(True)
                for v in views:
                    wall.attach(v.panel, v.widget)
                grid.show_all()
            log(f"display: applied live {sorted(changes)} (now {d.cols}x{d.rows} @ "
                f"{d.width}x{d.height}, fullscreen={getattr(d, 'fullscreen', True)})")
            return True
        except Exception as e:                         # noqa: BLE001
            log(f"display: live apply failed ({e}); falling back to soft-restart")
            return False

    def _apply_display_changes(self, disp: dict, result: dict):
        """Live-apply what can be; flag a soft restart for what can't: a layout
        swap (a different windowing model), or a grid shrink that would orphan a
        configured panel."""
        d = self.conf.display
        current = {"layout": d.layout, "cols": d.cols, "rows": d.rows,
                   "width": d.width, "height": d.height,
                   "fullscreen": getattr(d, "fullscreen", True)}
        live = {k: disp[k] for k in ("width", "height", "fullscreen", "cols", "rows")
                if k in disp and disp[k] != current[k]}
        layout_change = "layout" in disp and disp["layout"] != current["layout"]
        orphans = []
        if "cols" in live or "rows" in live:
            cols = int(live.get("cols", current["cols"]))
            rows = int(live.get("rows", current["rows"]))
            orphans = [p.id for p in self.conf.panels
                       if p.grid[0] >= cols or p.grid[1] >= rows]
        if layout_change or orphans:
            result["self_restart"] = True
            if orphans:
                result["pending_restarts"].append(
                    f"grid shrink would orphan {orphans} — restart to confirm")
        elif live:
            if self._apply_display_live(live, current):
                result["applied_live"] = sorted(live)
            else:
                result["self_restart"] = True

    def apply_config(self, changes: dict) -> dict:
        """Live-apply edits from the config window: panels added/removed/edited,
        display, VPNs, proxy, tunnel. Returns what actually happened, so Apply tells
        the truth about what went live and what is queued:
          {"pending_restarts": [...], "write_back": "ok"|"deferred:<reason>",
           "self_restart": bool, "applied_live": [...]}"""
        result = {"pending_restarts": [], "write_back": "ok", "self_restart": False}
        added = changes.pop("_add_panel", None)
        if added:
            if self.wall is None:
                result["pending_restarts"].append(
                    "soc-wall (new panels appear on next boot)")
            else:
                for pdict in added:
                    try:
                        self._add_panel_live(pdict)
                    except Exception as e:             # noqa: BLE001
                        log(f"[{pdict.get('id', '?')}] add panel failed: {e}")
        for pid in changes.pop("_remove_panel", None) or ():
            self._remove_panel_live(pid)

        disp = changes.pop("_display", None)
        if disp and self.wall is not None:
            if "gap" in disp:                           # gap applies live
                try:
                    self.wall.grid.set_row_spacing(disp["gap"])
                    self.wall.grid.set_column_spacing(disp["gap"])
                except Exception:  # noqa: BLE001
                    pass
            self._apply_display_changes(disp, result)
        elif disp:
            result["pending_restarts"].append(
                "soc-wall (display changes apply on next boot)")

        # _vpns is the canonical list; _vpn is the legacy single-VPN edit. One
        # supervisor unit runs them all, so either way one restart picks it up.
        vpns_ch = changes.pop("_vpns", None)
        vpn_ch = changes.pop("_vpn", None)
        if vpns_ch is not None:
            self.conf.vpns = list(vpns_ch)
            self.conf.vpn = self.conf.vpns[0] if self.conf.vpns else {}
        elif vpn_ch is not None:
            self.conf.vpn = vpn_ch                      # persisted to the vault note
        if vpns_ch is not None or vpn_ch is not None:
            if self._can_systemctl_restart():
                self._restart_vpn_async()               # pick up the new config
                result.setdefault("applied_live", []).append("forti-vpn")
            else:
                result["pending_restarts"].append("forti-vpn")

        proxy_ch = changes.pop("_proxy", None)
        if proxy_ch is not None:
            # The browsers read the proxy at WebView creation, so this takes effect
            # next boot; updating conf keeps the vault write-back current.
            self.conf.proxy = cfg.ProxyCfg(
                enabled=bool(proxy_ch.get("enabled")),
                url=str(proxy_ch.get("url") or ""),
                vault_item=str(proxy_ch.get("vault_item") or ""),
                ignore_hosts=tuple(proxy_ch.get("ignore_hosts") or ()))
            result["pending_restarts"].append("soc-wall (proxy applies on next boot)")

        tunnel_ch = changes.pop("_tunnel", None)
        if tunnel_ch is not None:
            # A merge, so advanced keys the form doesn't show survive a glass edit.
            self.conf.tunnel = {**(self.conf.tunnel or {}), **tunnel_ch}
            if self._can_systemctl_restart():
                self._restart_tunnel_async()
            else:
                result["pending_restarts"].append("autossh-tunnel")

        by_id = {v.panel.id: v for v in self.panels_view}
        for pid, ch in changes.items():
            view = by_id.get(pid)
            if view is None:
                continue
            if "title" in ch:
                view.panel.title = ch["title"]
            vault_changed = ("vault_item" in ch
                             and ch["vault_item"] != (view.panel.vault_item or ""))
            if vault_changed:
                view.panel.vault_item = ch["vault_item"]
            url_changed = "url" in ch and ch["url"] != (view.panel.url or "")
            if url_changed:
                view.set_url(ch["url"])      # reload (also re-triggers login)
            elif vault_changed and hasattr(view, "set_url"):
                # vault item changed but URL didn't — reload to re-trigger login
                view.set_url(view.panel.url or "")
        result["write_back"] = self._push_config_to_vault()
        if result["self_restart"]:
            self._restart_wall_at_tail()
        return result

    def _free_cell(self) -> tuple:
        """The first empty (col, row) in reading order; a full grid grows a row."""
        used = {tuple(p.grid) for p in self.conf.panels}
        cols = max(1, self.conf.display.cols)
        n = 0
        while (n % cols, n // cols) in used:
            n += 1
        return (n % cols, n // cols)

    def _add_panel_live(self, pdict: dict):
        """Create and attach a new panel at runtime, without a restart."""
        pid = pdict["id"]
        if any(p.id == pid for p in self.conf.panels):
            raise ValueError(f"panel id {pid!r} already exists")
        url = pdict.get("url") or None
        if not cfg.valid_http_url(url):
            raise ValueError(f"not a valid http(s) URL: {cfg._url_for_msg(url)}")
        engine = pdict.get("engine", "webkit")
        if engine == "chromium" and self.wall is not None:
            raise ValueError("layout 'single' cannot host chromium panels")
        panel = cfg.Panel(
            id=pid, engine=engine, url=url,
            grid=tuple(pdict.get("grid") or self._free_cell()),
            mode=pdict.get("mode", "direct"),
            vault_item=pdict.get("vault_item", ""),
            selectors=pdict.get("selectors", {}),
            login_marker=pdict.get("login_marker", ""),
            keepalive=cfg.KeepAlive(strategy="none"),
            title=pdict.get("title", ""),
            allow_insecure=pdict.get("allow_insecure", False))
        panel.geometry = cfg.compute_geometry(self.conf.display, panel.grid)
        config_cb = (self.open_config
                     if os.environ.get("SOC_ONSCREEN_CONFIG", "1") != "0" else None)
        # Ports stay with their views, so a removal can leave a hole: take the first
        # free one, never one derived from the list length.
        base = cfg.env_int("SOC_CDP_BASE_PORT", 9222, lo=1024, hi=65535)
        used = {getattr(v, "cdp_port", None) for v in self.panels_view}
        port = next(p for p in range(base, 65536) if p not in used)
        view = self._make_view(panel, port, config_cb)
        self.conf.panels.append(panel)
        self.panels_view.append(view)
        self._show_one(view)
        if self.wall is not None:
            self.wall.grid.show_all()
        log(f"[{pid}] panel added live")

    def _remove_panel_live(self, pid: str):
        """Stop a panel and take it off the wall at runtime."""
        view = next((v for v in self.panels_view if v.panel.id == pid), None)
        if view is None:
            log(f"[{pid}] panel not found for removal")
            return
        try:
            view.stop()
        except Exception as e:                         # noqa: BLE001
            log(f"[{pid}] stop failed: {e}")
        self.panels_view.remove(view)
        self.conf.panels = [p for p in self.conf.panels if p.id != pid]
        if self.wall is not None:
            self.wall.detach(pid)
        log(f"[{pid}] panel removed live")

    def _restart_vpn_async(self):
        """A VPN-tab change — restart the VPN service so it re-reads the config
        (off the GTK thread; best-effort, needs privilege)."""
        self._restart_vpn_service(
            "VPN config changed — restarted forti-vpn",
            "VPN restart not permitted from the wall")

    def _stop_vpn_unit(self, name: str):
        """Settings' Remove-VPN action, called from a worker before the entry leaves
        the config. One forti-vpn.service supervises every VPN (no per-VPN units, and
        sudoers allows only this one), so a restart now would drop the healthy
        tunnels and bring this one straight back. Apply restarts the supervisor on
        the new list; what can go wrong is that it isn't allowed to, so raise now
        and let Settings warn the operator while they are still there."""
        if not self._can_systemctl_restart():
            raise RuntimeError("no NOPASSWD sudo for systemctl, so forti-vpn must be "
                               "restarted by hand after Apply")
        log(f"VPN '{name}' removed — forti-vpn restarts on Apply")

    def _restart_tunnel_async(self):
        """A Tunnel-tab change — restart autossh-tunnel so the new jump host /
        identity / forwards come up. Same caveats as _restart_vpn_async."""
        def work():
            ok, info = self._privileged_systemctl("restart", "autossh-tunnel.service")
            log("tunnel config changed — restarted autossh-tunnel" if ok
                else f"tunnel restart not permitted from the wall ({info})")
        threading.Thread(target=work, daemon=True).start()

    def _push_config_to_vault(self) -> str:
        """After an on-screen edit, write the merged config back to the vault note
        (the source of truth) so it does not drift. Off the GTK thread, best-effort
        — the local overrides remain the durable record if this fails.

        Returns at once: 'ok' (the prerequisites are met and the upload is running,
        though it may still fail) or 'deferred:<reason>', meaning overrides.json is
        the only record and the stale vault note wins at next boot. The unseal is
        slow, so only the cheap checks happen here."""
        if os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND) not in ("rbw", "litebw", "native"):
            return "deferred:this vault backend has no config note"
        item = os.environ.get("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config")
        if not item:
            return "deferred:SOC_CONFIG_VAULT_ITEM is empty"
        from . import secretstore
        sd = os.environ.get("SOC_SECRET_DIR")
        url = os.environ.get("SOC_VAULT_URL", "")
        email = os.environ.get("SOC_VAULT_EMAIL", "")
        if not url:
            return "deferred:SOC_VAULT_URL is empty"
        if not email:
            return "deferred:SOC_VAULT_EMAIL is empty"
        if not secretstore.is_sealed(sd):
            return "deferred:master password is not host-sealed"

        def work():
            try:
                from . import vaultseed
                # Master comes ONLY from the host-bound sealed store — never from
                # a plaintext SOC_VAULT_PASSWORD in soc.env.
                master = secretstore.unseal(sd)
                yaml_text = cfg.to_yaml(self.conf)
                vaultseed.upsert_login(url, email, master, item, "", "",
                                       notes=yaml_text)
                master = ""
                log(f"config written back to vault note '{item}'")
            except Exception as e:  # noqa: BLE001
                log(f"config write-back failed (local overrides kept): {e}")
        threading.Thread(target=work, daemon=True).start()
        return "ok"

    def _show_one(self, view):
        try:
            view.show()
        except Exception as e:  # noqa: BLE001
            log(f"[{view.panel.id}] show failed: {e}")
        return False  # one-shot timeout

    def shutdown(self, *_):
        # try/finally so Gtk.main_quit() ALWAYS runs — even if the leading log()
        # or an attribute access before the guarded block raises. Otherwise a
        # SIGTERM handler that raised here would never quit the loop, hanging
        # `systemctl stop` until TimeoutStopSec forces a SIGKILL (orphaning
        # chromium children whose _reap never runs).
        try:
            log("shutting down ...")
            _beat.stop()
            ctx = GLib.main_context_default()
            for src in (*getattr(self, "_timers", ()),
                        getattr(self, "_restart_src", 0)):
                if src and ctx.find_source_by_id(src) is not None:
                    GLib.source_remove(src)
            self._timers, self._restart_src = [], 0
            for v in self.panels_view:
                if hasattr(v, "stop"):
                    try:
                        v.stop()
                    except Exception as e:  # noqa: BLE001
                        # Surface which panel failed (a swallowed Chromium stop
                        # can orphan a child / leak a CDP port + profile lock
                        # across 24/7 restarts) but never block main_quit on one
                        # bad panel. getattr is double-hardened so the except
                        # handler itself can't raise.
                        log(f"[{getattr(getattr(v, 'panel', None), 'id', '?')}] "
                            f"stop failed: {e}")
        finally:
            Gtk.main_quit()
        return False


def _config_cache_path() -> str:
    base = os.environ.get("SOC_STATE_DIR") or os.path.expanduser("~/.config/soc-wall")
    return os.path.join(base, "config-cache.yaml")


def _cache_config(text: str):
    """Best-effort: remember the last-known-good vault config so a later boot can
    paint from it if the vault note is briefly unreadable."""
    try:
        p = _config_cache_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, text.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, p)
    except OSError:
        pass


def _read_cached_config() -> str:
    try:
        with open(_config_cache_path(), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def load_config(vault: Vault) -> cfg.Config:
    """Load the wall config. With the rbw backend the config is the vault's — a
    Vaultwarden secure-note (SOC_CONFIG_VAULT_ITEM, default 'SOC Wall Config') is
    the source of truth, and a local panels.yaml is only an offline fallback. The
    dev backend always reads the file. SOC_CONFIG_FROM_VAULT=0 forces the file."""
    backend = os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND)
    item = os.environ.get("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config")
    if backend in ("rbw", "litebw", "native") and item and os.environ.get("SOC_CONFIG_FROM_VAULT", "1") != "0":
        try:
            text = vault.notes(item)
        except VaultError as e:
            log(f"config note '{item}' unreadable ({e}); falling back to the file")
            text = ""
        if text and text.strip():
            conf = cfg.load_str(text, f"vault:{item}")
            _cache_config(text)                  # only validated text is "good"
            log(f"config source: vault note '{item}'")
            return conf
        cached = _read_cached_config()
        if cached.strip():
            try:
                conf = cfg.load_str(cached, "cache:config-cache.yaml")
                log("config source: last-known-good cache (vault note unavailable)")
                return conf
            except cfg.ConfigError:
                pass
        log(f"config note '{item}' empty/absent; using the local file")
    panels_file = os.environ.get("SOC_PANELS_FILE") or _resolved_panels()
    if not os.path.exists(panels_file):
        # NOT CONFIGURED YET (no vault note, no file): launch a built-in DEFAULT
        # template instead of dead-ending on a fatal screen. The wall comes up empty
        # with its toolbar + an on-screen "add panels" hint, and the operator
        # configures real panels later via Setup or the on-screen Settings
        # (gear / Ctrl+Shift+C). A *malformed* file still raises (cfg.load below) so a
        # broken config the operator wrote is surfaced, not silently replaced.
        log(f"no config at {panels_file} — launching the default template; "
            f"add panels via Setup or the on-screen Settings (Ctrl+Shift+C)")
        return _default_template()
    log(f"config source: {panels_file}")
    return cfg.load(panels_file)


# A complete, valid, panel-less config — the safe default when nothing is configured
# yet, so `launch` never dead-ends. The wall renders its toolbar + a "not configured"
# hint; the operator adds real panels in Setup / the on-screen Settings.
_DEFAULT_TEMPLATE = (
    "display: {auto: true, cols: 2, rows: 2, gap: 0}\n"
    "panels: []\n"
    "tunnel: {enabled: false}\n"
    "vpn: {enabled: false}\n"
)


def _default_template() -> cfg.Config:
    """Built-in always-valid default config for the unconfigured-launch path."""
    return cfg.load_str(_DEFAULT_TEMPLATE, "default-template")


class _GtkUnlockUI:
    """The GTK side of the Unlock prompt, behind a tiny interface so the retry
    state machine (_unlock_attempt_loop) can be unit-tested without a window. ONE
    instance wraps ONE already-built dialog — every attempt re-runs the SAME dialog
    (no 're-pop')."""

    def __init__(self, dlg, entry, seal_chk, err):
        self._dlg, self._entry, self._seal, self._err = dlg, entry, seal_chk, err

    def prompt(self):
        """Run the dialog for one attempt. Returns (ok, master, seal_it); ok is
        False on Cancel/close/timeout (the timeout source responds CANCEL)."""
        resp = self._dlg.run()
        return (resp == Gtk.ResponseType.OK,
                self._entry.get_text(), self._seal.get_active())

    def show_error(self, text):
        self._err.set_text(text)
        self._err.show()
        self._entry.grab_focus()

    def clear_entry(self):
        self._entry.set_text("")          # master stays in RAM only — never a file
        self._entry.grab_focus()


def _unlock_attempt_loop(verify, ui):
    """Retry state machine for the Unlock prompt, factored out of _unlock_dialog so
    it is unit-testable without a GTK window (tests/test_main_unlock.py). `ui`
    provides prompt()/show_error()/clear_entry(); ONE ui (one dialog) serves every
    attempt — the dialog is NEVER re-created, so a wrong master re-prompts IN PLACE.

    `verify(master)` returns (ok, reason): on a wrong master / unreachable server,
    `reason` is shown in the error label and the entry is cleared for another try.
    Returns (master, seal_it) once a master verifies, or (None, False) on
    Cancel/close/timeout (ui.prompt() -> ok False). The master is RAM-only here —
    never written to a file, preserving the no-plaintext-master guarantee."""
    while True:
        ok, master, seal_it = ui.prompt()
        if not ok:
            return (None, False)            # Cancel / close / timeout
        if not master:
            ui.show_error("Enter the master password to unlock the vault.")
            continue
        if verify is None:
            return (master, seal_it)
        verified, reason = verify(master)
        if verified:
            return (master, seal_it)
        ui.show_error(reason or "The master password was rejected. Try again.")
        ui.clear_entry()
        # loop: the SAME dialog stays up for another attempt — no re-pop


_MASTER_REJECTED = "Master password rejected — check it and try again."


def _classify_unlock_error(msg: str, url: str) -> str:
    """Turn a raw VaultError string into a short, operator-actionable reason for the
    Unlock dialog. A reachability fault (DNS/connect/timeout) and a credential
    rejection get DIFFERENT guidance — otherwise the operator re-types a correct
    master forever against a dead URL with no clue which is actually wrong."""
    low = (msg or "").lower()
    unreachable = ("reach", "refused", "timed out", "timeout", "connection",
                   "resolve", "name or service", "unreachable", "no route",
                   "network is")
    if any(s in low for s in unreachable):
        where = f" at {url}" if url else ""
        return (f"Could not reach Vaultwarden{where} — check the server is running "
                f"and the URL/account in Setup, then try again.")
    # Rate-limit (HTTP 429): Vaultwarden throttles repeated logins. Even a CORRECT
    # master fails here — tell the operator to wait, not to re-type, so they don't
    # spiral into more attempts (which extend the lockout).
    if "429" in low or "too many" in low:
        return ("Vaultwarden is rate-limiting logins (too many attempts) — wait "
                "about a minute, then enter the master once and try again.")
    # No account email loaded: the wall's env (soc.env) wasn't sourced (e.g. it is
    # not readable by this user), so the login has no account to target. This is a
    # config/permissions fault, NOT a wrong master.
    if "no vault email" in low or "set soc_vault_email" in low or (
            "email" in low and "no " in low):
        return ("No vault account email is configured — the wall's env (soc.env) "
                "was not loaded. Check that /etc/soc-display/soc.env is readable "
                "and SOC_VAULT_EMAIL is set, then relaunch.")
    if "no vault master" in low or "vault is locked" in low:
        return ("This host has no sealed vault master password — provision it "
                "with Setup (the master is sealed host-bound).")
    return _MASTER_REJECTED


def _unlock_dialog(email: str, url: str, verify=None, timeout: float = 180.0):
    """Themed, time-boxed 'Unlock Vaultwarden' prompt shown at startup when the
    host is not sealed (no usable master) or the vault is locked — instead of the
    cryptic 'no vault master password' fatal. Runs on the GTK main thread (startup
    is single-threaded, pre-Gtk.main), so a plain nested dialog loop is correct.

    The prompt re-prompts IN PLACE: ONE dialog handles the whole attempt sequence.
    When `verify(master)` is given it is called for each Unlock press and returns
    (ok, reason); on a wrong master / unreachable server the reason is shown in the
    error label and the entry is cleared for a retry — no fresh dialog 're-pops'.

    Returns (master, seal_it): the verified master (kept in RAM only — NEVER written
    to a file) and whether the operator asked to seal it host-bound for next boot.
    Returns (None, False) on Cancel/close/timeout so the caller falls through to the
    fail-safe screen (exit 2 -> launcher menu). The single timeout below bounds the
    whole attempt sequence so a headless wall never wedges. The 'Seal for next boot'
    check defaults ON for unattended use, but the master is only ever sealed via
    secretstore (AES-GCM, host-bound) — the plaintext never touches soc.env or any
    file, preserving no-plaintext-master."""
    if perf.unattended():
        return (None, False)  # nobody to ask; the boot retries by itself instead
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return (None, False)  # headless: can't prompt; let the fatal path log it
    try:
        from gi.repository import GLib as _GLib
        try:
            from . import branding
            c = branding.load().get("colors", {})
        except Exception:  # noqa: BLE001 — theming is best-effort
            c = {}
        bg, text = c.get("background", "#FFFFFF"), c.get("text", "#0B1F14")
        dim = c.get("text_dim", "#5B7567")
        primary = c.get("primary", "#1FA463")
        bad = c.get("bad", "#C0341D")
        sunken = c.get("surface_bottom", "#EAF1EC")
        border = c.get("border", "#CFE0D4")
        accent_strong = c.get("accent_strong", "#157A49")
        on_accent = _on_color(accent_strong)        # readable label over the fill
        glow = _rgba(primary, 0.28)
        prov = Gtk.CssProvider()
        prov.load_from_data(
            (f"dialog, window {{ background-color: {bg}; color: {text}; }}"
             f".u-title {{ color: {text}; }} .u-sub {{ color: {dim}; }}"
             f".u-err {{ color: {bad}; }}"
             # The password Gtk.Entry must follow the palette too — without these it
             # falls back to GTK's default LIGHT entry well (a white island inside a
             # dark dialog on Midnight/Amber). Mirrors the setupgui entry rules.
             f"entry {{ background-color: {sunken}; color: {text};"
             f" border: 1px solid {border}; border-radius: 4px; padding: 6px 8px;"
             f" caret-color: {primary}; }}"
             f"entry:focus {{ border: 1px solid {primary};"
             f" box-shadow: 0 0 0 2px {glow}; }}"
             # Theme the Unlock button through the palette instead of the stock
             # .suggested-action (low-contrast on a dark dialog). on_accent is the
             # luminance-picked label colour so it reads on any accent.
             f"button.u-go {{ background-image: none;"
             f" background-color: {accent_strong}; color: {on_accent};"
             f" border: 1px solid {accent_strong}; border-radius: 6px;"
             f" font-weight: bold; padding: 6px 14px; }}"
             f"button.u-go:hover {{ background-color: {primary};"
             f" border-color: {primary}; }}"
             # Cancel as a branding ghost (not a stock-light island on dark themes).
             f"button.soc-ghost {{ background-image: none;"
             f" background-color: transparent; color: {accent_strong};"
             f" border: 1px solid {border}; border-radius: 6px; padding: 6px 14px; }}"
             f"button.soc-ghost:hover {{ background-color: {sunken};"
             f" border-color: {accent_strong}; }}").encode())
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        dlg = Gtk.Dialog(title="Unlock Vaultwarden")
        dlg.set_default_size(460, -1)
        if os.environ.get("SOC_WINDOW_MODE") != "window":
            dlg.set_keep_above(True)
        cancel_btn = dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        cancel_btn.get_style_context().add_class("soc-ghost")
        ok_btn = dlg.add_button("Unlock", Gtk.ResponseType.OK)
        ok_btn.get_style_context().add_class("u-go")
        dlg.set_default_response(Gtk.ResponseType.OK)

        box = dlg.get_content_area()
        box.set_spacing(10)
        box.set_margin_top(18)
        box.set_margin_bottom(8)
        box.set_margin_start(22)
        box.set_margin_end(22)

        esc = (lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        title = Gtk.Label(xalign=0)
        title.get_style_context().add_class("u-title")
        title.set_markup("<span size='x-large' weight='bold'>Unlock Vaultwarden</span>")
        box.pack_start(title, False, False, 0)
        sub = Gtk.Label(xalign=0)
        sub.get_style_context().add_class("u-sub")
        sub.set_line_wrap(True)
        sub.set_max_width_chars(52)
        who = email or "this host"
        sub.set_markup(f"<span size='small'>Enter the master password for "
                       f"<b>{esc(who)}</b>{(' at ' + esc(url)) if url else ''} to unlock "
                       f"the secrets vault for this session.</span>")
        box.pack_start(sub, False, False, 0)

        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        entry.set_placeholder_text("master password")
        entry.set_activates_default(True)
        box.pack_start(entry, False, False, 0)

        seal_chk = Gtk.CheckButton(label="Seal on this host for next boot (no password file)")
        seal_chk.set_active(True)
        box.pack_start(seal_chk, False, False, 0)

        err = Gtk.Label(xalign=0)
        err.get_style_context().add_class("u-err")
        err.set_line_wrap(True)
        err.set_max_width_chars(52)
        err.set_no_show_all(True)
        box.pack_start(err, False, False, 0)

        # Time-box: a headless wall must never wedge forever on a prompt nobody is
        # at. On timeout, respond CANCEL so the caller hits the fail-safe screen.
        timed_out = {"v": False}

        def _expire():
            timed_out["v"] = True
            timed_out["src"] = None       # auto-removed by returning False
            dlg.response(Gtk.ResponseType.CANCEL)
            return False
        timed_out["src"] = _GLib.timeout_add_seconds(int(max(1.0, timeout)), _expire)

        dlg.show_all()
        entry.grab_focus()

        def _finish(result):
            # Only remove a source that is still live (answered before the timeout).
            # Removing an already-fired source emits a noisy GLib-Warning.
            if timed_out["src"] is not None:
                try:
                    _GLib.source_remove(timed_out["src"])
                except Exception:  # noqa: BLE001 — defensive; already gone
                    pass
            dlg.destroy()
            # Drain the destroy so the next GTK window starts clean.
            while Gtk.events_pending():
                Gtk.main_iteration()
            return result

        # Re-prompt IN PLACE via the extracted retry state machine (unit-tested in
        # tests/test_main_unlock.py without a GTK window): a wrong master /
        # unreachable server shows the reason and clears the entry for a retry; the
        # dialog is NEVER re-created (no 're-pop'). Cancel/close/timeout ->
        # (None, False). The timeout above is a hard overall bound across all
        # retries so a headless wall cannot wedge.
        return _finish(_unlock_attempt_loop(verify, _GtkUnlockUI(dlg, entry, seal_chk, err)))
    except Exception as e:  # noqa: BLE001 — never let the prompt mask the real error
        log(f"(could not show the unlock dialog: {e})")
        return (None, False)


def _try_seal_master(master: str):
    """Best-effort host-bound seal of an operator-supplied master from the Unlock
    dialog, so the next boot is unattended. AES-GCM under $SOC_SECRET_DIR via
    secretstore — the master is NEVER written as plaintext. A failure here (e.g. a
    read-only /etc on a locked-down box) is logged, not fatal: the vault is already
    unlocked for this session."""
    try:
        from . import secretstore
        import secrets as _secrets
        pin = "".join(_secrets.choice("0123456789") for _ in range(6))
        secretstore.seal(master, pin)
        log("sealed the master host-bound — next boot unlocks unattended")
        return True
    except Exception as e:  # noqa: BLE001
        log(f"could not seal the master ({e}); will prompt again next boot")
        return False


def _title_markup(title: str) -> str:
    esc = str(title).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"<span size='xx-large' weight='bold'>{esc}</span>"


def _failsafe_window(title: str, detail: str, hint: str = "", window_title: str =
                     "SOC Video Wall — cannot start", buttons=()):
    """The themed full-screen status window behind every fail-safe screen. Returns
    (window, title label, detail label, hint label); the caller shows it and runs
    a loop."""
    try:
        from . import branding
        c = branding.load().get("colors", {})
    except Exception:  # noqa: BLE001 — theming is best-effort
        c = {}
    bg, text = c.get("background", "#FFFFFF"), c.get("text", "#0B1F14")
    dim, bad = c.get("text_dim", "#5B7567"), c.get("bad", "#C0341D")
    border = c.get("border", "#CFE0D4")
    s_bot = c.get("surface_bottom", "#EAF1EC")
    accent_strong = c.get("accent_strong", "#157A49")
    prov = Gtk.CssProvider()
    prov.load_from_data((f"window {{ background-color: {bg}; color: {text}; }}"
                         f".e-title {{ color: {bad}; }} .e-detail {{ color: {text}; }}"
                         f".e-hint {{ color: {dim}; }}"
                         # buttons as branding ghosts (not stock-light on dark).
                         f"button.soc-ghost {{ background-image: none;"
                         f" background-color: transparent; color: {accent_strong};"
                         f" border: 1px solid {border}; border-radius: 6px;"
                         f" padding: 6px 16px; }}"
                         f"button.soc-ghost:hover {{ background-color: {s_bot};"
                         f" border-color: {accent_strong}; }}").encode())
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    win = Gtk.Window(title=window_title)
    if os.environ.get("SOC_WINDOW_MODE") == "window":
        win.set_default_size(660, 440)
    else:
        win.fullscreen()
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
    box.set_halign(Gtk.Align.CENTER)
    box.set_valign(Gtk.Align.CENTER)
    box.set_margin_top(40)
    box.set_margin_bottom(40)
    box.set_margin_start(60)
    box.set_margin_end(60)
    win.add(box)
    t = Gtk.Label(xalign=0.5)
    t.get_style_context().add_class("e-title")
    t.set_markup(_title_markup(title))
    box.pack_start(t, False, False, 0)
    d = Gtk.Label(label=detail.strip())
    d.get_style_context().add_class("e-detail")
    d.set_line_wrap(True)
    d.set_max_width_chars(74)
    d.set_selectable(True)
    box.pack_start(d, False, False, 0)
    h = Gtk.Label(label=hint)
    h.get_style_context().add_class("e-hint")
    h.set_line_wrap(True)
    h.set_max_width_chars(74)
    h.set_no_show_all(not hint)
    box.pack_start(h, False, False, 0)
    if buttons:
        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btns.set_halign(Gtk.Align.CENTER)
        for b in buttons:
            btns.pack_start(b, False, False, 0)
        box.pack_start(btns, False, False, 0)
    return win, t, d, h


def _fatal_screen(title: str, detail: str, hint: str = "") -> int:
    """Fail-safe: instead of exiting silently (which launcher.sh would just restart
    into a black screen, so the operator sees *nothing*), show a visible, themed
    error window explaining WHY the wall could not start, with an 'Open Setup'
    button to fix it. It runs its own GTK loop so it STAYS on screen (the launcher
    won't busy-restart while it's up). Returns 2 after the operator dismisses it;
    falls back to a log-only exit when there is no display (headless / pre-session).

    Unattended there is nobody to dismiss it: see _fatal_unattended."""
    log(f"FATAL: {title}: {detail}")
    _beat.set("fatal")
    if perf.unattended():
        return _fatal_unattended(title, detail)
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return EXIT_OPERATOR  # nothing to render on; the journal line is the diagnostic
    try:
        def _open_setup(_b):
            import subprocess  # local: subprocess isn't a module-level import
            root = os.environ.get("SOC_ROOT") or os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", ".."))
            sh = os.path.join(root, "scripts", "soc-wall-setup-gui.sh")
            argv = (["bash", sh] if os.path.exists(sh)
                    else [sys.executable, "-m", "host.setupgui"])
            try:
                subprocess.Popen(argv, start_new_session=True)
            except OSError as e:
                log(f"could not open Setup: {e}")
        setup_btn = Gtk.Button(label="Open Setup")
        setup_btn.get_style_context().add_class("soc-ghost")
        setup_btn.connect("clicked", _open_setup)
        quit_btn = Gtk.Button(label="Quit")
        quit_btn.get_style_context().add_class("soc-ghost")
        quit_btn.connect("clicked", lambda _b: Gtk.main_quit())
        win = _failsafe_window(title, detail, hint,
                               buttons=(setup_btn, quit_btn))[0]
        win.connect("destroy", lambda _w: Gtk.main_quit())
        win.show_all()
        Gtk.main()
    except Exception as e:  # noqa: BLE001 — never let the diagnostic mask the real error
        log(f"(could not show the fail-safe error screen: {e})")
    return EXIT_OPERATOR


class _AttemptHung(Exception):
    """A boot step outlived UNATTENDED_ATTEMPT_TIMEOUT."""


class _StatusBoard:
    """What an unattended wall shows while it cannot show the wall, and the main
    loop that keeps the process alive meanwhile. No buttons and no prompt: nothing
    here waits for a person. Without a usable display the screen is skipped and the
    loop still runs, so the retry and the heartbeat don't depend on one."""

    def __init__(self):
        self.stopped = False           # SIGTERM/SIGINT arrived: wind down
        self._loop = None
        self._win = self._title = self._detail = self._hint = None
        self._no_display = not (os.environ.get("DISPLAY")
                                or os.environ.get("WAYLAND_DISPLAY"))
        self._sigs = [_signal_add(sig, self._on_signal)
                      for sig in (signal.SIGINT, signal.SIGTERM)]

    def _on_signal(self):
        self.stopped = True
        if self._loop is not None:
            self._loop.quit()
        return True

    def show(self, title: str, detail: str, hint: str = ""):
        """Put this on screen, updating the window in place if it is already up."""
        if self._no_display:
            return
        try:
            if self._win is None:
                self._win, self._title, self._detail, self._hint = _failsafe_window(
                    title, detail, hint, window_title="SOC Video Wall")
                self._win.connect("delete-event", lambda *_: True)
                self._hint.set_no_show_all(False)
                self._detail.set_selectable(False)     # no caret: nobody types here
                res = detect_resolution()
                if res and os.environ.get("SOC_WINDOW_MODE") != "window":
                    self._win.set_default_size(*res)   # for a bare X with no WM
                self._win.show_all()
            else:
                self._title.set_markup(_title_markup(title))
                self._detail.set_text(detail.strip())
                self._hint.set_text(hint)
        except Exception as e:         # noqa: BLE001 — status is a nicety, boot isn't
            log(f"(no status screen, continuing without one: {e})")
            self._no_display = True

    def sleep(self, seconds: float):
        """Wait, with the main loop turning."""
        if self.stopped:
            return
        self._loop = GLib.MainLoop()
        src = GLib.timeout_add(int(seconds * 1000), self._wake, self._loop)
        self._loop.run()
        if self._loop.get_context().find_source_by_id(src) is not None:
            GLib.source_remove(src)    # woken early by a signal
        self._loop = None

    @staticmethod
    def _wake(loop):
        loop.quit()
        return False

    def run(self, fn, *args):
        """fn(*args) on a worker thread, with the main loop turning until it
        returns; hands back its result or re-raises its exception. Raises
        _AttemptHung if it outlives UNATTENDED_ATTEMPT_TIMEOUT."""
        loop = self._loop = GLib.MainLoop()
        done = {}

        def work():
            try:
                done["value"] = fn(*args)
            except BaseException as e:  # noqa: BLE001 — carried to the main thread
                done["error"] = e
            GLib.idle_add(loop.quit)

        threading.Thread(target=work, daemon=True).start()
        src = GLib.timeout_add_seconds(UNATTENDED_ATTEMPT_TIMEOUT, self._wake, loop)
        loop.run()
        if loop.get_context().find_source_by_id(src) is not None:
            GLib.source_remove(src)
        self._loop = None
        if "error" in done:
            raise done["error"]
        if "value" not in done:
            if self.stopped:
                return None
            raise _AttemptHung(getattr(fn, "__name__", "boot step"))
        return done["value"]

    def close(self):
        """Take the screen down and hand the signals back."""
        for src in self._sigs:
            GLib.source_remove(src)
        self._sigs = []
        if self._win is not None:
            self._win.destroy()
            self._win = None
            while Gtk.events_pending():  # so the next window starts clean
                Gtk.main_iteration()


def _fatal_unattended(title: str, detail: str) -> int:
    """The fail-safe screen with nobody to read it: stay up, keep beating with
    state 'fatal', then exit so launcher.sh restarts us and everything is re-read
    from scratch. Whatever fixes this (a redeploy, an edited vault note) reaches the
    wall on its own. Never EXIT_OPERATOR, which would strand it on the menu."""
    sec = cfg.env_int("SOC_UNATTENDED_RELOAD_SEC", 300, lo=1, hi=86400)
    board = _StatusBoard()
    try:
        board.show(title, detail,
                   f"This wall needs nothing pressed. It checks again every "
                   f"{sec} s and recovers by itself once the problem is fixed.")
        board.sleep(sec)
        return 0 if board.stopped else EXIT_RELOAD
    finally:
        board.close()


def _retry_delay(attempt: int) -> float:
    """Capped exponential backoff for the unattended vault retry; attempt >= 1."""
    return min(UNATTENDED_RETRY_INITIAL * 2 ** min(attempt - 1, 16),
               UNATTENDED_RETRY_MAX)


def _open_vault_unattended(vault, board: _StatusBoard) -> "int | None":
    """Open the vault with nobody here: on a worker, with the status screen up,
    retrying on a capped backoff for as long as it takes. A vault that is late
    (network not up, Vaultwarden starting after the wall), locked, or misconfigured
    all land here, and each attempt re-reads the sealed master and the server, so a
    fix takes effect without a restart. Returns None when open, or an exit code."""
    url = getattr(vault.backend, "url", "") or os.environ.get("SOC_VAULT_URL", "")
    attempt = 0
    board.show("Waiting for the vault", "Opening the secrets vault…",
               "This wall needs nothing pressed. It keeps trying by itself.")
    while not board.stopped:
        attempt += 1
        try:
            board.run(vault.open)
            return 0 if board.stopped else None
        except _AttemptHung:
            log("vault open wedged; exiting so the launcher starts a clean process")
            return EXIT_RELOAD
        except Exception as e:         # noqa: BLE001 — whatever it is, we retry
            # "Rejected" is only the classifier's catch-all, right when someone has
            # just typed a password. Here nobody has: show the real reason.
            reason = _classify_unlock_error(str(e), url)
            if reason == _MASTER_REJECTED:
                reason = f"The vault did not open: {e}"
            delay = _retry_delay(attempt)
            log(f"vault not ready (attempt {attempt}): {e}; retrying in {delay:.0f}s")
            board.show("Waiting for the vault", reason,
                       f"This wall needs nothing pressed. Attempt {attempt}; "
                       f"trying again in {delay:.0f} s.")
            board.sleep(delay)
    return 0


def main():
    try:
        return _main()
    finally:
        _beat.stop()                   # no-op unless the heartbeat ever started


def _merge_vpn_overrides(conf: cfg.Config, ov: dict):
    """Lay the on-screen VPN edits over the loaded config. conf.vpn is the first of
    conf.vpns, so it follows the merged list: a removed or reordered first VPN must
    not stay behind in it (apply_config keeps the same rule at runtime)."""
    from .configwin import apply_vpn_override, apply_vpns_override
    if "_vpns" in ov:
        conf.vpns = apply_vpns_override(conf.vpns, ov)
        conf.vpn = conf.vpns[0] if conf.vpns else {}
    else:
        apply_vpn_override(conf.vpn, ov)


def _main():
    unattended = perf.unattended()
    # Geometry preview (no display, no vault needed) — read the local file.
    if os.environ.get("SOC_DRY_RUN") == "1":
        panels_file = os.environ.get("SOC_PANELS_FILE") or _resolved_panels()
        try:
            conf = cfg.load(panels_file)
        except cfg.ConfigError as e:
            log(f"FATAL config error:\n{e}")
            return EXIT_RELOAD if unattended else EXIT_OPERATOR
        for p in conf.panels:
            g = p.geometry
            log(f"  {p.id:4s} {p.engine:8s} {p.mode:6s} -> {p.effective_url}  "
                f"@ {g.w}x{g.h}+{g.x}+{g.y}")
        return 0

    # 1. open the vault FIRST — with the rbw backend the wall config itself lives
    #    in the vault, so it must be unlocked before we can read the config.
    #    Required: fail loudly if it will not open within the timeout.
    # Interactive when a display is up: the litebw backend then DEFERS on a missing
    # master (returns instead of raising) so the wall can pop the themed Unlock
    # dialog below, rather than dying with the cryptic 'no vault master password'.
    have_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if unattended:
        # Nobody can answer a prompt, so no backend may defer to one, whatever the
        # environment says.
        os.environ["SOC_VAULT_INTERACTIVE"] = "0"
    elif have_display and "SOC_VAULT_INTERACTIVE" not in os.environ:
        os.environ["SOC_VAULT_INTERACTIVE"] = "1"
    # The heartbeat starts here, before anything can block.
    _beat.start("unlocking")
    board = None
    try:
        vault = Vault(ttl=cfg.env_float("SOC_CRED_TTL", 30.0, lo=1.0))
    except VaultError as e:
        if not unattended:
            raise
        return _fatal_screen("Vault backend error", str(e))
    backend = os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND)
    log(f"opening vault (backend={backend}) ...")
    # VaultLockedError (litebw) is the catchable 'please unlock' signal — distinct
    # from a real connect/auth failure, which still surfaces as VaultError.
    try:
        from .litebw import VaultLockedError
    except Exception:  # noqa: BLE001 — non-litebw backends never raise it
        class VaultLockedError(Exception):
            pass
    ready_timeout = cfg.env_float("SOC_READY_TIMEOUT", 120.0, lo=0.0, hi=3600.0)
    deadline = time.time() + ready_timeout
    # Count consecutive 'accepted the master but vault.open() still reports
    # locked' cycles. A backend that re-locks right after a successful unlock
    # (litebw session that doesn't persist across open(), clock-skew session
    # expiry, a sync that re-locks) would otherwise re-pop the unlock dialog
    # forever. A wall-clock deadline alone can't gate this — a slow first-time
    # operator could blow the 120s deadline on the FIRST (legitimate) prompt —
    # so we count the relock cycles instead.
    unlock_relock_attempts = 0
    if unattended:
        board = _StatusBoard()
        rc = _open_vault_unattended(vault, board)
        if rc is not None:
            board.close()
            return rc
    while not unattended:
        try:
            vault.open()
            break
        except VaultLockedError:
            # No usable master yet (host not sealed + no $SOC_VAULT_PASSWORD).
            # Pop the interactive unlock prompt instead of the cryptic fatal. The
            # dialog verifies IN PLACE: a wrong master / unreachable server is shown
            # in the dialog and the operator retries in the SAME window — no re-pop.
            email = getattr(vault.backend, "email", "") or os.environ.get("SOC_VAULT_EMAIL", "")
            url = getattr(vault.backend, "url", "") or os.environ.get("SOC_VAULT_URL", "")

            def _verify(master):
                """Attempt the unlock for the dialog; (ok, human reason). On success
                the backend session is open. master is RAM-only — never written."""
                try:
                    vault.backend.unlock_with(master)
                    return (True, "")
                except VaultError as e:
                    log(f"unlock failed: {e}")
                    return (False, _classify_unlock_error(str(e), url))

            master, seal_it = _unlock_dialog(email, url, verify=_verify)
            if not master:
                # Cancel / close / timeout — return cleanly to the menu (exit 2),
                # never re-pop the dialog.
                return _fatal_screen(
                    "Vaultwarden is locked",
                    "No master password is configured for the secrets vault, and the "
                    "unlock prompt was cancelled, so the wall cannot read its logins.",
                    "Run Setup to configure + seal the vault master, or relaunch and "
                    "enter the master password when prompted.")
            # _verify already opened the backend session on success.
            if seal_it:
                _try_seal_master(master)
            master = ""                # drop the plaintext as soon as it's used
            # The operator gave a master that verified, yet we are back here
            # because vault.open() re-raised VaultLockedError. If that keeps
            # happening, the backend is rejecting the session immediately after
            # login — re-popping the dialog forever would trap the operator.
            unlock_relock_attempts += 1
            if unlock_relock_attempts >= 3:
                return _fatal_screen(
                    "Vault keeps re-locking",
                    "The vault accepted the master password but locked again "
                    "immediately several times in a row. This usually means the "
                    "Vaultwarden session is being rejected right after login "
                    "(clock skew on the Pi or server, or an invalidated session).",
                    "Check the Pi and Vaultwarden clocks (chrony/ntp), confirm the "
                    "server session/token settings, then relaunch.")
            continue   # session is open now; re-run open() to sync
        except VaultError as e:
            if time.time() > deadline:
                return _fatal_screen(
                    "Vault did not open",
                    f"The vault did not unlock and sync within {ready_timeout}s.\n\n{e}",
                    "Check that Vaultwarden is running and the master password is "
                    "configured (sealed host-bound, or via the keyring). "
                    "Use Open Setup to configure the vault, then relaunch.")
            log(f"vault not ready ({e}); retrying ...")
            _beat.set("unlocking")     # no loop is turning here: beat by hand
            time.sleep(3)
    log("vault unlocked + synced")

    # 2. config — from the vault note (rbw) or the local file
    _beat.set("starting")
    try:
        if board is not None:
            board.show("Starting the wall", "Reading the wall configuration…")
            conf = board.run(load_config, vault)
            board.close()
            board = None
        else:
            conf = load_config(vault)
    except cfg.ConfigError as e:
        if board is not None:
            board.close()
        return _fatal_screen(
            "Configuration error",
            str(e),
            "The wall config (vault note or panels.yaml) is invalid. "
            "Use Open Setup to fix it, then relaunch.")
    except Exception as e:             # noqa: BLE001
        if board is None:
            raise
        board.close()
        return _fatal_screen("Configuration error", str(e))
    if conf is None:                   # SIGTERM during the read
        return 0
    for w in conf.warnings:
        log(f"WARNING {w}")

    # apply any settings set previously from the on-screen config
    try:
        from .configwin import (load_overrides, apply_overrides_to_panels,
                                 apply_display_override, apply_proxy_override,
                                 apply_tunnel_override)
        ov = load_overrides()
        if ov:
            apply_display_override(conf.display, ov)
            _merge_vpn_overrides(conf, ov)
            apply_proxy_override(conf.proxy, ov)
            apply_tunnel_override(conf.tunnel, ov)
            apply_overrides_to_panels(conf.panels, ov)
            for p in conf.panels:                        # geometry may have moved
                p.geometry = cfg.compute_geometry(conf.display, p.grid)
            log(f"applied {len(ov)} saved override(s) from the on-screen config")
    except Exception as e:  # noqa: BLE001
        log(f"WARNING could not load config overrides: {e}")

    log(f"{len(conf.panels)} panels, grid {conf.display.cols}x{conf.display.rows} "
        f"@ {conf.display.width}x{conf.display.height}")
    if conf.proxy.enabled:
        auth = (f"auth via vault item '{conf.proxy.vault_item}'"
                if conf.proxy.vault_item else "no auth")
        log(f"proxy: {conf.proxy.url} ({auth})")
    # Not configured yet (the built-in default template has no panels): DON'T dead-end
    # on a fatal screen. Bring the wall up (toolbar + empty grid) and open the on-screen
    # Settings so the operator adds panels live — no relaunch needed.
    unconfigured = not conf.panels
    if unconfigured:
        log("no panels configured — launching empty; the on-screen Settings opens so "
            "you can add panels (or use Setup)")

    # Everything from here on builds windows/panels and enters the loop. A
    # constructor (WallWindow, a WebKit/Chromium panel, CSS provider, the 0700
    # chromium profile dir) can raise; without a guard that would crash to a
    # BLACK screen (no themed diagnostic) and the launcher would busy-restart
    # into the same crash. Route any such failure to the fail-safe screen
    # instead; let KeyboardInterrupt propagate so Ctrl+C still exits cleanly.
    try:
        host = KioskHost(conf, vault=vault)

        # warm the credential cache off-thread while we wait for VPN/tunnels, so
        # the first login of each panel never blocks the GTK loop on a vault call
        host.prewarm_creds()

        # 4. windows FIRST — paint immediately so a boot-time VPN/carrier outage
        #    shows each panel's branded 'connecting…' card (with its own load
        #    backoff self-heal) instead of a long black screen while the
        #    best-effort readiness probes run. (build_and_show must precede the
        #    probes; see the daemon worker below.)
        host.build_and_show()

        # 3. VPN + tunnels (best-effort), now OFF the main thread so they never
        #    gate first paint. VPN first: its routes may be what makes a tunnel's
        #    jump host (or a direct VPN-side panel) reachable at all — preserved
        #    here by running them sequentially in one worker. The probes only do
        #    socket.create_connection + log() (thread-safe); they touch GTK only
        #    via the VPN pill, which already hops through GLib.idle_add. daemon
        #    so the worker can never block host.shutdown.
        def _readiness_probes():
            wait_for_vpn(conf.vpns, timeout=ready_timeout)
            wait_for_tunnels(conf.panels, timeout=ready_timeout)
        threading.Thread(target=_readiness_probes, daemon=True).start()

        # Unconfigured launch: open the on-screen Settings once the loop is running so the
        # operator configures panels live on an otherwise-empty wall (no relaunch).
        # With nobody here to fill it in, keep the wall clear and look for a config
        # (a redeploy, a vault note) by restarting periodically: an empty wall has
        # nothing to lose.
        if unconfigured and unattended:
            host._keep_timer(GLib.timeout_add_seconds(
                cfg.env_int("SOC_UNATTENDED_RELOAD_SEC", 300, lo=1, hi=86400),
                host.shutdown))
        elif unconfigured:
            GLib.idle_add(host.open_config)

        # all panel views, WebContexts and config objects are now built and live
        # for the whole 24/7 uptime — freeze them out of the GC so the steady-state
        # loop stops re-scanning these permanent objects on every gen-2 collection.
        import gc
        gc.collect()
        if hasattr(gc, "freeze"):
            gc.freeze()

        # 5. signals + main loop
        for sig in (signal.SIGINT, signal.SIGTERM):
            host._keep_timer(_signal_add(sig, host.shutdown))
        log("entering GTK main loop")
        _beat.set("running", views=lambda: host.panels_view)
    except KeyboardInterrupt:
        raise
    except Exception as e:  # noqa: BLE001 — a build/window crash must not go black
        import traceback
        log(f"window/panel construction failed:\n{traceback.format_exc()}")
        return _fatal_screen(
            "The wall could not start",
            f"Building the panel windows failed:\n\n{e}",
            "This is usually a renderer/display problem (WebKit/Chromium, the "
            "GTK theme, or the screen). Check the log above, then relaunch — "
            "use Open Setup to review the configuration.")
    Gtk.main()
    return 0


if __name__ == "__main__":
    # Ctrl+C during boot (or any point before/after Gtk.main) should exit
    # cleanly (rc 0) so the launcher loop respawns without printing a
    # noisy KeyboardInterrupt traceback. Inside Gtk.main, SIGINT is
    # handled by the GLib.unix_signal_add hook + host.shutdown.
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n[soc-kiosk] interrupted (Ctrl+C); exiting cleanly\n")
        sys.exit(0)
