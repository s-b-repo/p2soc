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

Run:  SOC_PANELS_FILE=config/panels.dev.yaml python3 -m host.main
"""
from __future__ import annotations

import os
import signal
import socket
import sys
import time

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import config as cfg  # noqa: E402
from . import configpaths  # noqa: E402  (shared read/write-location resolver)
from . import perf  # noqa: E402
from .vault import Vault, VaultError  # noqa: E402


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
    tunneled = [p for p in panels if p.mode == "tunnel"]
    for p in tunneled:
        port = p.tunnel_local_port
        if not port:                       # malformed/None tunnel — nothing to wait on
            continue
        log(f"[{p.id}] waiting for tunnel port 127.0.0.1:{port} ...")
        deadline = time.time() + timeout   # per-tunnel budget — a slow first tunnel
        while time.time() < deadline:      # must not starve the rest of the deadline
            if _port_open("127.0.0.1", port):
                log(f"[{p.id}] tunnel up")
                break
            time.sleep(1)
        else:
            log(f"[{p.id}] WARNING tunnel port {port} never came up; "
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
        # Kiosk locker: PIN/TOTP-gated transparent overlay. State files live
        # under configwin.state_dir(). Built lazily so a missing module never
        # blocks boot.
        try:
            from . import locker as _locker
            from . import configwin as _cw
            self._locker = _locker.KioskLocker(_cw.state_dir())
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
        from . import loginmemory
        item = getattr(panel, "_resolved_vault", "") or panel.vault_item
        if item:
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

    def prewarm_creds(self):
        """Fetch every panel/proxy/remembered login into the cache in the
        background, so the first login of each panel is served from cache and
        never blocks the GTK thread on a vault call."""
        import threading
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
            self.wall = WallWindow(self.conf, log, on_destroy=self.shutdown,
                                   on_config=config_cb, on_vpn=self.vpn_action,
                                   on_lock=(self._lock_wall
                                            if self._locker is not None else None),
                                   on_show_vpn_log=self.open_vpn_log_viewer)

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
                if panel.engine == "chromium":
                    from .chromium_panel import ChromiumPanel
                    view = ChromiumPanel(panel, self.need_login, log,
                                         cdp_port=cdp_base + idx,
                                         proxy=self.conf.proxy,
                                         proxy_creds=self.proxy_creds,
                                         security=self.conf.security,
                                         on_login_success=self.login_success)
                else:
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
            except Exception as e:  # noqa: BLE001 — skip one bad panel, keep the wall
                log(f"[{getattr(panel, 'id', '?')}] panel construction failed; "
                    f"skipping this panel: {e}")
                continue
            self.panels_view.append(view)
            GLib.timeout_add(int(delay * 1000), self._show_one, view)
            delay += stagger

        if self.wall is not None:
            self.wall.show()
            self._start_vpn_monitor()
            # boot-time file-integrity check: warn on the top bar if the
            # deployed tree has drifted from the install-time manifest.
            self._check_deploy_drift()
        self._start_mem_watch()

    # ---- memory watchdog ---------------------------------------------------
    def _start_mem_watch(self):
        """On a 1 GB Pi a single leaking dashboard can OOM the box. Periodically
        check MemAvailable and, under sustained pressure, recycle one panel
        (heaviest measurable first) to reclaim memory — with hysteresis and a
        cooldown so it can't thrash."""
        if perf.mem_available_mb() is None:
            return                          # not Linux/proc — nothing to watch
        self._mem_min_mb = cfg.env_int("SOC_MEM_MIN_AVAIL_MB", 96, lo=16, hi=8192)
        self._mem_check_sec = cfg.env_int("SOC_MEM_CHECK_SEC", 30, lo=5, hi=3600)
        self._mem_cooldown = cfg.env_int("SOC_MEM_RECYCLE_COOLDOWN", 120, lo=10)
        self._mem_low_streak = 0
        self._mem_last_recycle = 0.0
        self._mem_rr = 0
        log(f"memory watchdog on: recycle a panel when MemAvailable < "
            f"{self._mem_min_mb} MB (every {self._mem_check_sec}s)")
        GLib.timeout_add_seconds(self._mem_check_sec, self._check_memory)

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
                # streak to 1 so a single next low reading re-arms a retry; the
                # round-robin target picker naturally tries a different panel.
                log(f"[mem] recycle of {view.panel.id} failed: {e}")
                self._mem_low_streak = 1
            else:
                # Recycle succeeded — start the cooldown and reset hysteresis.
                self._mem_last_recycle = now
                self._mem_low_streak = 0
        return True

    def _pick_recycle_target(self):
        """The heaviest panel with a measurable RSS (Chromium); otherwise reload
        WebKit panels round-robin (their RSS isn't separable)."""
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
        GLib.timeout_add_seconds(max(3, interval), self._poll_vpn_periodic)

    def _poll_vpn_periodic(self):
        self._poll_vpn()
        return True                                   # keep the timeout alive

    def _poll_vpn(self):
        # each probe can block (TCP connect), so compute off the GTK thread
        import threading
        from . import vpnstatus, vpnmanager

        # Skip this tick if the previous probe is still running, so a slow/hung
        # connect near the poll interval can't pile up daemon threads.
        if getattr(self, "_vpn_poll_busy", False):
            return False
        self._vpn_poll_busy = True

        def work():
            # Per-name states for EACH enabled VPN, plus one aggregate for the
            # main pill label. The tooltip lists every VPN so a multi-VPN wall
            # shows which one is down at a glance.
            states = {}
            try:
                for v in (self.conf.vpns or []):
                    if isinstance(v, dict) and v.get("enabled"):
                        nm = v.get("name") or "vpn"
                        states[nm] = vpnstatus.vpn_state(v)
            except Exception:                          # never let the pill crash us
                states = {}
            finally:
                self._vpn_poll_busy = False
            agg = vpnmanager.aggregate_state(states)
            n = len(states)
            if n <= 1:
                label = vpnstatus.LABELS.get(agg, "VPN: ?")
            else:
                up = sum(1 for s in states.values()
                         if s == vpnstatus.STATE_ONLINE)
                label = f"VPN: {up}/{n} up"
            css = {"not_configured": "unconfigured"}.get(agg, agg)
            # tooltip: per-name breakdown ("corp: online | lab: offline")
            tip = " | ".join(
                f"{nm}: {st.replace('_', ' ')}" for nm, st in states.items()
            ) or "VPN: not configured"
            GLib.idle_add(self._set_pill, css, label, tip)
        # If thread start fails (RuntimeError 'can't start new thread' under
        # thread exhaustion / OOM on the 1 GB board), work()'s finally never
        # runs to reset _vpn_poll_busy — which would wedge every future tick at
        # the early-return above and freeze the pill forever. Reset the flag and
        # log here so the next tick can retry. Keep setting the flag on the GTK
        # thread (do NOT move it into the worker — the early-return must already
        # see it set before work() is scheduled).
        try:
            threading.Thread(target=work, daemon=True).start()
        except RuntimeError as e:
            self._vpn_poll_busy = False
            log(f"[vpn] could not start status-poll thread; will retry next tick: {e}")
        return False

    def _set_pill(self, css, label, tip=None):
        if self.wall is not None:
            self.wall.set_vpn_status(css, label)
            if tip and self.wall.vpn_pill is not None:
                self.wall.vpn_pill.set_tooltip_text(
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
        try:
            self._locker.lock(on_unlock=None)
        except Exception as e:  # noqa: BLE001
            log(f"lock failed: {e}")

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
        import threading

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
            self.wall.set_vpn_status("checking", "VPN: checking…")
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
                               proxy_vault_item=self.conf.proxy.vault_item)
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
        deploy_root = os.environ.get("SOC_DEPLOY_ROOT", "/opt/soc-display")
        import threading

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

    def apply_config(self, changes: dict):
        """Live-apply URL/title/vault edits from the config window to the panels."""
        disp = changes.pop("_display", None)
        if disp and self.wall is not None and "gap" in disp:
            try:                                        # gap applies live
                self.wall.grid.set_row_spacing(disp["gap"])
                self.wall.grid.set_column_spacing(disp["gap"])
            except Exception:  # noqa: BLE001
                pass
        vpn_ch = changes.pop("_vpn", None)
        if vpn_ch is not None:
            self.conf.vpn = vpn_ch                      # persisted to the vault note
            self._restart_vpn_async()                   # pick up the new config
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
        self._push_config_to_vault()

    def _restart_vpn_async(self):
        """A VPN-tab change — restart the VPN service so it re-reads the config
        (off the GTK thread; best-effort, needs privilege)."""
        self._restart_vpn_service(
            "VPN config changed — restarted forti-vpn",
            "VPN restart not permitted from the wall")

    def _push_config_to_vault(self):
        """After an on-screen edit, write the merged config back to the vault note
        (the source of truth) so it does not drift. Off the GTK thread, best-effort
        — the local overrides remain the durable record if this fails."""
        if os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND) not in ("rbw", "litebw", "native"):
            return
        item = os.environ.get("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config")
        if not item:
            return
        import threading

        def work():
            try:
                from . import secretstore, vaultseed
                sd = os.environ.get("SOC_SECRET_DIR")
                url = os.environ.get("SOC_VAULT_URL", "")
                email = os.environ.get("SOC_VAULT_EMAIL", "")
                # Master comes ONLY from the host-bound sealed store — never from
                # a plaintext SOC_VAULT_PASSWORD in soc.env.
                master = secretstore.unseal(sd) if secretstore.is_sealed(sd) else ""
                if not (url and email and master):
                    log("config write-back skipped (need url/email + sealed master)")
                    return
                yaml_text = cfg.to_yaml(self.conf)
                vaultseed.upsert_login(url, email, master, item, "", "",
                                       notes=yaml_text)
                master = ""
                log(f"config written back to vault note '{item}'")
            except Exception as e:  # noqa: BLE001
                log(f"config write-back failed (local overrides kept): {e}")
        threading.Thread(target=work, daemon=True).start()

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
            _cache_config(text)                  # remember last-known-good
            log(f"config source: vault note '{item}'")
            return cfg.load_str(text, f"vault:{item}")
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
    return "Master password rejected — check it and try again."


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


def _fatal_screen(title: str, detail: str, hint: str = "") -> int:
    """Fail-safe: instead of exiting silently (which launcher.sh would just restart
    into a black screen, so the operator sees *nothing*), show a visible, themed
    error window explaining WHY the wall could not start, with an 'Open Setup'
    button to fix it. It runs its own GTK loop so it STAYS on screen (the launcher
    won't busy-restart while it's up). Returns 2 after the operator dismisses it;
    falls back to a log-only exit when there is no display (headless / pre-session)."""
    log(f"FATAL: {title}: {detail}")
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return 2  # nothing to render on; the journal line above is the diagnostic
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, Gdk
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
        win = Gtk.Window(title="SOC Video Wall — cannot start")
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
        esc = (lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        t = Gtk.Label(xalign=0.5)
        t.get_style_context().add_class("e-title")
        t.set_markup(f"<span size='xx-large' weight='bold'>{esc(title)}</span>")
        box.pack_start(t, False, False, 0)
        d = Gtk.Label(label=detail.strip())
        d.get_style_context().add_class("e-detail")
        d.set_line_wrap(True)
        d.set_max_width_chars(74)
        d.set_selectable(True)
        box.pack_start(d, False, False, 0)
        if hint:
            h = Gtk.Label(label=hint)
            h.get_style_context().add_class("e-hint")
            h.set_line_wrap(True)
            h.set_max_width_chars(74)
            box.pack_start(h, False, False, 0)
        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btns.set_halign(Gtk.Align.CENTER)

        def _open_setup(_b):
            import subprocess  # local: subprocess isn't a module-level import
            root = os.environ.get("SOC_ROOT", "/opt/soc-display")
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
        btns.pack_start(setup_btn, False, False, 0)
        btns.pack_start(quit_btn, False, False, 0)
        box.pack_start(btns, False, False, 0)
        win.connect("destroy", lambda _w: Gtk.main_quit())
        win.show_all()
        Gtk.main()
    except Exception as e:  # noqa: BLE001 — never let the diagnostic mask the real error
        log(f"(could not show the fail-safe error screen: {e})")
    return 2


def main():
    # Geometry preview (no display, no vault needed) — read the local file.
    if os.environ.get("SOC_DRY_RUN") == "1":
        panels_file = os.environ.get("SOC_PANELS_FILE") or _resolved_panels()
        try:
            conf = cfg.load(panels_file)
        except cfg.ConfigError as e:
            log(f"FATAL config error:\n{e}")
            return 2
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
    if have_display and "SOC_VAULT_INTERACTIVE" not in os.environ:
        os.environ["SOC_VAULT_INTERACTIVE"] = "1"
    vault = Vault(ttl=cfg.env_float("SOC_CRED_TTL", 30.0, lo=1.0))
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
    while True:
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
            time.sleep(3)
    log("vault unlocked + synced")

    # 2. config — from the vault note (rbw) or the local file
    try:
        conf = load_config(vault)
    except cfg.ConfigError as e:
        return _fatal_screen(
            "Configuration error",
            str(e),
            "The wall config (vault note or panels.yaml) is invalid. "
            "Use Open Setup to fix it, then relaunch.")
    for w in conf.warnings:
        log(f"WARNING {w}")

    # apply any settings set previously from the on-screen config
    try:
        from .configwin import (load_overrides, apply_overrides_to_panels,
                                 apply_display_override, apply_vpn_override)
        ov = load_overrides()
        if ov:
            apply_display_override(conf.display, ov)
            apply_vpn_override(conf.vpn, ov)
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
        import threading

        def _readiness_probes():
            wait_for_vpn(conf.vpns, timeout=ready_timeout)
            wait_for_tunnels(conf.panels, timeout=ready_timeout)
        threading.Thread(target=_readiness_probes, daemon=True).start()

        # Unconfigured launch: open the on-screen Settings once the loop is running so the
        # operator configures panels live on an otherwise-empty wall (no relaunch).
        if unconfigured:
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
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, host.shutdown)
        log("entering GTK main loop")
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
