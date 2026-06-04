"""
Chromium fallback panel (for the rare Chrome-only site).

Spawns a single Chromium app-window with remote debugging on localhost, then
drives it over the Chrome DevTools Protocol from a background thread:

  * installs the credential-free bootstrap (addScriptToEvaluateOnNewDocument +
    one immediate eval for the already-loaded document),
  * polls window.__SOC.needLogin and, when set, fetches creds from the vault and
    evaluates socLogin({user,pass}).

CDP binds to 127.0.0.1 only. Runs independently of the GTK main loop.
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

from . import inject


def _chromium_bin() -> str:
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("no chromium binary found")


class CDPError(Exception):
    pass


class _CDP:
    def __init__(self, port: int):
        self.port = port
        self.ws = None
        self._id = 0

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
                        self.ws = create_connection(
                            t["webSocketDebuggerUrl"],
                            timeout=10,
                            # modern Chromium rejects CDP ws unless origin allowed;
                            # we pass --remote-allow-origins=* on the cmdline, and
                            # also send a localhost Origin header here.
                            header=["Origin: http://127.0.0.1"],
                        )
                        return
            except Exception as e:  # noqa: BLE001
                last = e
            time.sleep(0.5)
        raise CDPError(f"could not attach CDP on :{self.port} ({last})")

    def rpc(self, method, params=None):
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CDPError(msg["error"])
                return msg.get("result", {})
            # ignore protocol events

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


class ChromiumPanel:
    def __init__(self, panel, on_need_login, log, cdp_port: int,
                 poll_interval: float = 2.0):
        self.panel = panel
        self.on_need_login = on_need_login
        self.log = log
        self.cdp_port = cdp_port
        self.poll_interval = poll_interval
        self.proc = None
        self.cdp = None
        self._stop = threading.Event()
        self._thread = None

    def show(self):
        self._spawn()
        self._thread = threading.Thread(target=self._control_loop, daemon=True)
        self._thread.start()

    def _spawn(self):
        p = self.panel
        g = p.geometry
        profile = os.path.join(
            os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "soc-profiles", p.id)
        os.makedirs(os.path.join(profile, "Default"), exist_ok=True)
        # Seed prefs so Chromium never shows the "Save password?" bubble or the
        # session-restore prompt over a panel.
        prefs = os.path.join(profile, "Default", "Preferences")
        if not os.path.exists(prefs):
            import json as _json
            with open(prefs, "w", encoding="utf-8") as fh:
                _json.dump({
                    "credentials_enable_service": False,
                    "profile": {"password_manager_enabled": False,
                                "exit_type": "Normal"},
                }, fh)
        args = [
            _chromium_bin(),
            f"--app={p.effective_url}",
            f"--class={p.wmclass}",
            f"--user-data-dir={profile}",
            f"--remote-debugging-port={self.cdp_port}",
            "--remote-debugging-address=127.0.0.1",
            "--remote-allow-origins=*",
            f"--window-position={g.x},{g.y}",
            f"--window-size={g.w},{g.h}",
            "--no-first-run", "--no-default-browser-check",
            "--disable-translate", "--disable-session-crashed-bubble",
            "--noerrdialogs", "--disable-infobars",
            "--password-store=basic", "--disable-component-update",
            "--disable-features=Translate,OptimizationHints",
            "--ozone-platform=x11",
            # sandbox stays ON in production. Some restricted CI/containers can't
            # init Chromium's namespace sandbox; SOC_CHROMIUM_NO_SANDBOX=1 is a
            # DEV-ONLY escape hatch (never set it on the Pi).
        ]
        if os.environ.get("SOC_CHROMIUM_NO_SANDBOX") == "1":
            args.append("--no-sandbox")
        self.log(f"[{p.id}] chromium spawning (CDP :{self.cdp_port})")
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

    def _control_loop(self):
        p = self.panel
        try:
            self.cdp = _CDP(self.cdp_port)
            self.cdp.connect()
            self.cdp.rpc("Page.enable")
            self.cdp.rpc("Runtime.enable")
            boot = inject.bootstrap_js(p, mode="chromium")
            # future documents:
            self.cdp.rpc("Page.addScriptToEvaluateOnNewDocument", {"source": boot})
            # already-loaded document (bootstrap is idempotent):
            self.cdp.evaluate(boot)
            self.log(f"[{p.id}] chromium CDP attached + bootstrap installed")
        except Exception as e:  # noqa: BLE001
            self.log(f"[{p.id}] chromium CDP setup failed: {e}")
            return

        while not self._stop.is_set():
            try:
                need = self.cdp.evaluate(
                    "(window.__SOC && window.__SOC.needLogin) || false",
                    return_value=True)
                if need:
                    creds = self.on_need_login(p)
                    if creds:
                        self.cdp.evaluate(inject.login_call(creds))
                        creds["pass"] = ""
                        self.log(f"[{p.id}] injected login (chromium)")
            except Exception as e:  # noqa: BLE001
                # page navigation can briefly drop the context; just retry
                self.log(f"[{p.id}] chromium poll: {e}")
            self._stop.wait(self.poll_interval)

    def stop(self):
        self._stop.set()
        if self.cdp:
            self.cdp.close()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
