#!/usr/bin/env python3
"""Compare Rust and Python on identical WebKit dashboards on Linux."""

import argparse
import http.server
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse


REPO = Path(__file__).resolve().parent.parent
TICKS_PER_SECOND = os.sysconf("SC_CLK_TCK")
PAGE_KIB = os.sysconf("SC_PAGE_SIZE") // 1024
LOGIN = b"""<!doctype html><title>Benchmark login</title>
<form method=post action=login><input id=u name=u><input id=p name=p type=password>
<button id=go type=submit>Sign in</button></form>"""
DASHBOARD = b"""<!doctype html><title>Benchmark dashboard</title>
<h1>Dashboard</h1><table><tr><th>Service</th><th>Status</th></tr>
<tr><td>Example service</td><td>Ready</td></tr></table>"""


class Dashboard(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        panel = self.path.strip("/")
        if panel not in self.server.panels:
            self.send_error(404)
            return
        signed_in = "dashboard=1" in self.headers.get("Cookie", "")
        page = DASHBOARD if signed_in else LOGIN
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)
        if signed_in:
            self.server.loaded(panel)

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length", "0")), 4096)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        panel = self.path.removesuffix("/login").strip("/")
        if panel not in self.server.panels or form != {"u": ["benchmark-user"], "p": ["benchmark-password"]}:
            self.send_error(401)
            return
        self.send_response(303)
        self.send_header("Location", f"/{panel}/")
        self.send_header("Set-Cookie", f"dashboard=1; Path=/{panel}/")
        self.send_header("Content-Length", "0")
        self.end_headers()


class Fixture(http.server.ThreadingHTTPServer):
    def __init__(self, panels):
        super().__init__(("127.0.0.1", 0), Dashboard)
        self.panels = panels
        self.ready = threading.Event()
        self.finished = None
        self._lock = threading.Lock()
        self._loaded = set()

    def reset(self):
        with self._lock:
            self._loaded.clear()
            self.ready.clear()
            self.finished = None

    def loaded(self, panel):
        with self._lock:
            self._loaded.add(panel)
            if len(self._loaded) == len(self.panels) and self.finished is None:
                self.finished = time.monotonic()
                self.ready.set()


def process_tree(root):
    """Read a /proc snapshot and return PID → (RSS KiB, CPU ticks)."""
    children = {}
    processes = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            stat = (entry / "stat").read_text().rsplit(")", maxsplit=1)[1].split()
            pid = int(entry.name)
            processes[pid] = (int(stat[21]) * PAGE_KIB, int(stat[11]) + int(stat[12]))
            children.setdefault(int(stat[1]), []).append(pid)
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
            continue
    tree = {}
    pending = [root]
    while pending:
        pid = pending.pop()
        if pid in processes and pid not in tree:
            tree[pid] = processes[pid]
            pending.extend(children.get(pid, ()))
    return tree


def pss_kib(pid):
    try:
        for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return 0
    raise RuntimeError(f"PSS missing for process {pid}")


def cpu_percent(before, after, pids, elapsed):
    ticks = sum(after[pid][1] - before[pid][1] for pid in pids if pid in before)
    return 100 * ticks / TICKS_PER_SECOND / elapsed


def wall_env(work, fixture, stagger):
    panels = []
    vault = {}
    for index, panel in enumerate(fixture.panels):
        panels.append({
            "id": panel,
            "engine": "webkit",
            "grid": [index % 2, index // 2],
            "url": f"http://127.0.0.1:{fixture.server_port}/{panel}/",
            "vault_item": panel,
            "login_marker": "#p",
            "selectors": {"user": "#u", "pass": "#p", "submit": "#go"},
        })
        vault[panel] = {"username": "benchmark-user", "password": "benchmark-password"}
    config = {
        "display": {"width": 1280, "height": 720, "auto": False, "cols": 2, "rows": 2, "layout": "single"},
        "panels": panels,
    }
    (work / "panels.yaml").write_text(json.dumps(config))
    (work / "vault.json").write_text(json.dumps(vault))
    (work / "runtime").mkdir(mode=0o700)
    env = {key: value for key, value in os.environ.items() if not key.startswith("SOC_")}
    env.update(
        HOME=str(work), XDG_CONFIG_HOME=str(work / "config"), XDG_CACHE_HOME=str(work / "cache"),
        XDG_RUNTIME_DIR=str(work / "runtime"), GDK_BACKEND="x11",
        PYTHONPATH=str(REPO / "kiosk-host"), MALLOC_ARENA_MAX="2",
        SOC_ROOT=str(REPO), SOC_PANELS_FILE=str(work / "panels.yaml"), SOC_STATE_DIR=str(work / "state"),
        SOC_HEARTBEAT_FILE=str(work / "heartbeat.json"), SOC_WEBDATA_DIR=str(work / "web"),
        SOC_VAULT_BACKEND="dev", SOC_DEV_VAULT=str(work / "vault.json"), SOC_LAUNCH_STAGGER=str(stagger),
        SOC_MEM_MIN_AVAIL_MB="150", SOC_WEBKIT_HWACCEL="never", SOC_UNATTENDED="1",
    )
    return env


def stop_wall(wall):
    if wall.poll() is not None:
        return
    try:
        os.killpg(wall.pid, signal.SIGTERM)
        wall.wait(timeout=5)
    except ProcessLookupError:
        wall.wait()
    except subprocess.TimeoutExpired:
        os.killpg(wall.pid, signal.SIGKILL)
        wall.wait()


def run_trial(command, fixture, opts):
    fixture.reset()
    with tempfile.TemporaryDirectory(prefix="wall-bench-") as directory:
        work = Path(directory)
        env = wall_env(work, fixture, opts.stagger)
        log_path = work / "wall.log"
        with log_path.open("w") as log:
            start = time.monotonic()
            wall = subprocess.Popen(command, cwd=REPO, env=env, stdout=log, stderr=log, start_new_session=True)
            try:
                peak = 0
                while wall.poll() is None and time.monotonic() - start < opts.login_timeout:
                    peak = max(peak, sum(row[0] for row in process_tree(wall.pid).values()))
                    if fixture.ready.wait(0.20):
                        break
                if fixture.finished is None:
                    raise RuntimeError(f"{command} failed to load every dashboard:\n{log_path.read_text()}")
                time.sleep(opts.settle)
                before = process_tree(wall.pid)
                window_start = time.monotonic()
                host_rss = []
                tree_pss = []
                for sample in range(opts.idle):
                    tree = process_tree(wall.pid)
                    host_rss.append(tree[wall.pid][0])
                    tree_pss.append(sum(pss_kib(pid) for pid in tree))
                    peak = max(peak, sum(row[0] for row in tree.values()))
                    time.sleep(max(0, window_start + sample + 1 - time.monotonic()))
                after = process_tree(wall.pid)
                elapsed = time.monotonic() - window_start
                return {
                    "login_seconds": fixture.finished - start,
                    "host_rss_mib": statistics.median(host_rss) / 1024,
                    "tree_pss_mib": statistics.median(tree_pss) / 1024,
                    "tree_peak_rss_mib": peak / 1024,
                    "host_cpu_percent": cpu_percent(before, after, (wall.pid,), elapsed),
                    "tree_cpu_percent": cpu_percent(before, after, after, elapsed),
                }
            finally:
                stop_wall(wall)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5, help="trials per implementation")
    parser.add_argument("--panels", type=int, choices=(1, 2, 3, 4), default=4)
    parser.add_argument("--idle", type=int, default=10, help="whole seconds to sample")
    parser.add_argument("--settle", type=float, default=3, help="seconds before idle sampling")
    parser.add_argument("--stagger", type=float, default=0.5, help="seconds between starting panels")
    parser.add_argument("--login-timeout", type=float, default=35)
    parser.add_argument("--python", default=sys.executable, help="Python with PyGObject and PyYAML installed")
    parser.add_argument("--rust", type=Path, default=REPO / "rust/target/release/soc-wall")
    opts = parser.parse_args()
    if opts.runs < 1 or opts.idle < 1 or not os.environ.get("DISPLAY"):
        parser.error("run with DISPLAY set and positive --runs and --idle values")
    commands = {"rust": [str(opts.rust.resolve()), "run"], "python": [opts.python, "-m", "host.main"]}
    trials = {"rust": [], "python": []}
    with Fixture(tuple(f"p{i + 1}" for i in range(opts.panels))) as fixture:
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        try:
            for number in range(opts.runs):
                order = ("rust", "python") if number % 2 == 0 else ("python", "rust")
                for implementation in order:
                    trial = run_trial(commands[implementation], fixture, opts)
                    trials[implementation].append(trial)
                    print(f"{implementation} trial {number + 1}: {trial}", file=sys.stderr, flush=True)
        finally:
            fixture.shutdown()
    result = {
        "platform": platform.platform(),
        "settings": {"panels": opts.panels, "idle_seconds": opts.idle, "settle_seconds": opts.settle, "stagger_seconds": opts.stagger},
        "medians": {
            name: {metric: statistics.median(trial[metric] for trial in rows) for metric in rows[0]}
            for name, rows in trials.items()
        },
        "trials": trials,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
