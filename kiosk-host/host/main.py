"""
SOC kiosk host — entry point.

Boot sequence:
  1. load config (panels.yaml)
  2. open the vault (rbw unlock + sync)  [required]
  3. wait for each tunnel's local port to answer  [best-effort, timed]
  4. create the panel windows (WebKit) / processes (Chromium), staggered
  5. run the GTK main loop; inject logins on demand; keep sessions alive

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
from gi.repository import Gtk, GLib  # noqa: E402

from . import config as cfg  # noqa: E402
from .vault import Vault, VaultError  # noqa: E402


def log(msg: str):
    t = time.strftime("%H:%M:%S")
    print(f"{t} [soc-kiosk] {msg}", flush=True)


def _port_open(host: str, port: int, timeout=1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_tunnels(panels, timeout: float):
    deadline = time.time() + timeout
    tunneled = [p for p in panels if p.mode == "tunnel"]
    for p in tunneled:
        port = p.tunnel_local_port
        log(f"[{p.id}] waiting for tunnel port 127.0.0.1:{port} ...")
        while time.time() < deadline:
            if _port_open("127.0.0.1", port):
                log(f"[{p.id}] tunnel up")
                break
            time.sleep(1)
        else:
            log(f"[{p.id}] WARNING tunnel port {port} never came up; "
                f"window will show a connection error")


class KioskHost:
    def __init__(self, conf: cfg.Config):
        self.conf = conf
        self.vault = Vault(ttl=float(os.environ.get("SOC_CRED_TTL", "30")))
        self.panels_view = []          # live panel objects (WebKit/Chromium)

    # creds callback handed to each panel
    def need_login(self, panel):
        try:
            return self.vault.creds(panel.vault_item)
        except VaultError as e:
            log(f"[{panel.id}] vault: {e}")
            return None

    def open_vault(self):
        backend = os.environ.get("SOC_VAULT_BACKEND", "rbw")
        log(f"opening vault (backend={backend}) ...")
        self.vault.open()
        log("vault unlocked + synced")

    def build_and_show(self):
        stagger = float(os.environ.get("SOC_LAUNCH_STAGGER", "1.5"))
        cdp_base = int(os.environ.get("SOC_CDP_BASE_PORT", "9222"))
        delay = 0.0
        for idx, panel in enumerate(self.conf.panels):
            if panel.engine == "chromium":
                from .chromium_panel import ChromiumPanel
                view = ChromiumPanel(panel, self.need_login, log,
                                     cdp_port=cdp_base + idx)
            else:
                from .webkit_panel import WebKitPanel
                view = WebKitPanel(panel, self.need_login, log)
            self.panels_view.append(view)
            GLib.timeout_add(int(delay * 1000), self._show_one, view)
            delay += stagger

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


def main():
    panels_file = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    log(f"config: {panels_file}")
    conf = cfg.load(panels_file)
    log(f"{len(conf.panels)} panels, grid {conf.display.cols}x{conf.display.rows} "
        f"@ {conf.display.width}x{conf.display.height}")

    if os.environ.get("SOC_DRY_RUN") == "1":
        for p in conf.panels:
            g = p.geometry
            log(f"  {p.id:4s} {p.engine:8s} {p.mode:6s} -> {p.effective_url}  "
                f"@ {g.w}x{g.h}+{g.x}+{g.y}")
        return 0

    host = KioskHost(conf)

    # 2. vault is required — fail loudly if it won't open
    ready_timeout = float(os.environ.get("SOC_READY_TIMEOUT", "120"))
    deadline = time.time() + ready_timeout
    while True:
        try:
            host.open_vault()
            break
        except VaultError as e:
            if time.time() > deadline:
                log(f"FATAL: vault did not open within {ready_timeout}s: {e}")
                return 2
            log(f"vault not ready ({e}); retrying ...")
            time.sleep(3)

    # 3. tunnels (best-effort)
    wait_for_tunnels(conf.panels, timeout=ready_timeout)

    # 4. windows
    host.build_and_show()

    # 5. signals + main loop
    for sig in (signal.SIGINT, signal.SIGTERM):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, host.shutdown)
    log("entering GTK main loop")
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
