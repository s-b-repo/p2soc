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
from . import perf  # noqa: E402
from .vault import Vault, VaultError  # noqa: E402


def log(msg: str):
    t = time.strftime("%H:%M:%S")
    print(f"{t} [soc-kiosk] {msg}", flush=True)


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


def wait_for_vpn(vpn: dict, timeout: float):
    """Best-effort gate: if a Fortinet VPN is enabled with a `ready_probe`
    (host:port reachable only once the VPN is up), wait for it before opening
    VPN-side panels. The VPN itself is brought up by forti-vpn.service; this only
    avoids loading those panels into a dead route. Non-fatal."""
    vpn = vpn or {}
    if not vpn.get("enabled"):
        return
    probe = (vpn.get("ready_probe") or "").strip()
    if not probe:
        return
    host, _, port = probe.rpartition(":")
    if not host or not port.isdigit():
        log(f"[vpn] ignoring malformed ready_probe '{probe}' (want host:port)")
        return
    port = int(port)
    log(f"[vpn] waiting for VPN reachability {host}:{port} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(host, port):
            log("[vpn] VPN up")
            return
        time.sleep(1)
    log(f"[vpn] WARNING {host}:{port} never became reachable; "
        f"VPN-side panels may show a connection error "
        f"(check: systemctl status forti-vpn / journalctl -u forti-vpn)")


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

    def open_vault(self):
        backend = os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND)
        log(f"opening vault (backend={backend}) ...")
        self.vault.open()
        log("vault unlocked + synced")

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
            if panel.engine == "chromium":
                from .chromium_panel import ChromiumPanel
                view = ChromiumPanel(panel, self.need_login, log,
                                     cdp_port=cdp_base + idx,
                                     proxy=self.conf.proxy,
                                     proxy_creds=self.proxy_creds,
                                     on_login_success=self.login_success)
            else:
                from .webkit_panel import WebKitPanel
                view = WebKitPanel(panel, self.need_login, log,
                                   embedded=self.wall is not None,
                                   proxy=self.conf.proxy,
                                   proxy_creds=self.proxy_creds,
                                   on_config=config_cb,
                                   on_login_success=self.login_success)
                if self.wall is not None:
                    self.wall.attach(panel, view.widget)
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
                log(f"[mem] recycle of {view.panel.id} failed: {e}")
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
        # the probe can block (TCP connect), so compute off the GTK thread
        import threading
        from . import vpnstatus

        # Skip this tick if the previous probe is still running, so a slow/hung
        # connect near the poll interval can't pile up daemon threads.
        if getattr(self, "_vpn_poll_busy", False):
            return False
        self._vpn_poll_busy = True

        def work():
            try:
                state = vpnstatus.vpn_state(self.conf.vpn)
            except Exception:                          # never let the pill crash us
                state = vpnstatus.STATE_OFFLINE
            finally:
                self._vpn_poll_busy = False
            label = vpnstatus.LABELS.get(state, "VPN: ?")
            css = {"not_configured": "unconfigured"}.get(state, state)
            GLib.idle_add(self._set_pill, css, label)
        threading.Thread(target=work, daemon=True).start()
        return False

    def _set_pill(self, css, label):
        if self.wall is not None:
            self.wall.set_vpn_status(css, label)
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
            self._vpn_log_viewer = _vlv.VpnLogViewer(
                on_reconnect=self.vpn_action,
                on_close=lambda: setattr(self, "_vpn_log_viewer", None))
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
        knows why the reconnect didn't take. Schedules on_done() if given."""
        import threading

        def work():
            ok, info = self._privileged_systemctl("restart", "forti-vpn.service")
            if ok:
                log(ok_msg)
            else:
                log(f"{fail_msg} ({info})")
            if on_done is not None:
                on_done()
        threading.Thread(target=work, daemon=True).start()

    def vpn_action(self):
        """Pill click: show 'checking', best-effort reconnect, then re-poll. The
        reconnect runs off the GTK thread so it can't freeze the wall."""
        if self.wall is not None:
            self.wall.set_vpn_status("checking", "VPN: checking…")
        if not (self.conf.vpn or {}).get("enabled"):
            self._poll_vpn()
            return
        self._restart_vpn_service(
            "VPN reconnect requested (systemctl restart forti-vpn)",
            "VPN reconnect not permitted from the wall; re-checking",
            on_done=lambda: GLib.timeout_add_seconds(2, self._poll_vpn))

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
        and skipped — the warning only appears when we positively find drift."""
        if self.wall is None:
            return
        try:
            from . import manifest as _mf
        except Exception as e:                         # noqa: BLE001
            log(f"manifest check skipped: import failed ({e})")
            return
        deploy_root = os.environ.get("SOC_DEPLOY_ROOT", "/opt/soc-display")
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
            self.wall.show_top_bar_warning(msg, detail=drift)
            log(f"file drift detected: {len(drift['changed'])} changed, "
                f"{len(drift['missing'])} missing, "
                f"{len(drift['extras'])} extras (commit "
                f"{(drift.get('commit') or 'unknown')[:12]})")
        else:
            log("manifest check ok — no drift")

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
        log("shutting down ...")
        for v in self.panels_view:
            if hasattr(v, "stop"):
                try:
                    v.stop()
                except Exception:
                    pass
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
    panels_file = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    log(f"config source: {panels_file}")
    return cfg.load(panels_file)


def main():
    # Geometry preview (no display, no vault needed) — read the local file.
    if os.environ.get("SOC_DRY_RUN") == "1":
        panels_file = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
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
    vault = Vault(ttl=cfg.env_float("SOC_CRED_TTL", 30.0, lo=1.0))
    backend = os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND)
    log(f"opening vault (backend={backend}) ...")
    ready_timeout = cfg.env_float("SOC_READY_TIMEOUT", 120.0, lo=0.0, hi=3600.0)
    deadline = time.time() + ready_timeout
    while True:
        try:
            vault.open()
            break
        except VaultError as e:
            if time.time() > deadline:
                log(f"FATAL: vault did not open within {ready_timeout}s: {e}")
                return 2
            log(f"vault not ready ({e}); retrying ...")
            time.sleep(3)
    log("vault unlocked + synced")

    # 2. config — from the vault note (rbw) or the local file
    try:
        conf = load_config(vault)
    except cfg.ConfigError as e:
        log(f"FATAL config error:\n{e}")
        return 2
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
    if not conf.panels:
        log("FATAL: no panels defined — nothing to show (edit the config)")
        return 2

    host = KioskHost(conf, vault=vault)

    # warm the credential cache off-thread while we wait for VPN/tunnels, so
    # the first login of each panel never blocks the GTK loop on a vault call
    host.prewarm_creds()

    # 3. VPN + tunnels (best-effort). VPN first: its routes may be what makes a
    #    tunnel's jump host (or a direct VPN-side panel) reachable at all.
    wait_for_vpn(conf.vpn, timeout=ready_timeout)
    wait_for_tunnels(conf.panels, timeout=ready_timeout)

    # 4. windows
    host.build_and_show()

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
