#!/usr/bin/env python3
"""
SOC wall scanner-deception tarpit — stdlib HTTP server, port 80.

A passing port-scanner that touches admin.php / wp-login.php / .env / etc.
gets a `200 OK` with random-looking junk (4–32 KB) after a 0.5–2.0 s drip.
Everything else gets a `404`. Goal: make automated scanners waste real time
+ chew up false-positive triage cycles, without exposing anything real.

Design notes:
  * Stdlib only — no Flask, no FastAPI, runs anywhere the wall does.
  * Strips the `Server:` header so the response doesn't fingerprint Python /
    BaseHTTPServer / kernel version.
  * Per-source-IP rate limit (bounded LRU): a chatty scanner hits the same
    box from one or two IPs; we slow them down per-IP instead of globally so
    a single noisy scanner can't shoulder out a quiet one.
  * Picks a Content-Type that matches the path (PHP -> text/html, .env ->
    text/plain, /api/v1 -> application/json) so the body looks plausible.
  * The body is `os.urandom(N)` wrapped in the chosen MIME — for JSON we wrap
    in a string literal; for HTML in a comment; for env in `KEY=...` lines.
    Plausible enough to fool a header-only scanner; junk enough to be useless.
  * `Connection: close` after every response — never let a scanner pipeline.
  * Structured JSON line per response to stderr (systemd journal).

Prod-hardening (this revision):
  * BoundedSemaphore reserves a worker slot per request; over-limit requests
    are dropped silently (TCP close, no 503). Caps thread blowup from
    slowloris-style floods independently of the systemd TasksMax cap.
  * Per-connection socket.settimeout(5s) so a half-open scanner can't peg a
    worker indefinitely waiting on header bytes.
  * http.client._MAXLINE / _MAXHEADERS pinned at module import — caps the
    request line and header count globally so a giant URL or header smear
    can't cost more than 4 KiB to reject.
  * SIGHUP reloads `/etc/soc-display/tarpit-paths.list` (lines = paths;
    "/foo/*" syntax = prefix; `#` comments). Built-in lists are the
    fallback when the file is absent / empty / unreadable.
  * SIGUSR1 dumps the top-20 source IPs by hit count + current worker
    usage as a single JSON line.
  * IPv6: the server family is picked from SOC_TARPIT_HOST at boot.
  * HEAD returns the correct Content-Length without a body (RFC 9110).
  * Plausibility headers (ETag, Last-Modified, Cache-Control) so a scanner
    fingerprint that walks "what app is this?" by header shape doesn't
    immediately say "stdlib python".

Off by default. Opt-in via `SOC_TARPIT_ENABLE=1` in /etc/soc-display/soc.env,
or `systemctl enable --now soc-tarpit.service` after dropping the unit in.
"""
from __future__ import annotations

import base64
import collections
import email.utils
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import random
import signal
import socket
import socketserver
import sys
import threading
import time

# Globally cap request-line length + header count BEFORE BaseHTTPRequestHandler
# reads its first byte. http.server reads these via http.client internals.
http.client._MAXLINE = 4096
http.client._MAXHEADERS = 64

# Common scanner targets — keep this list updated; order doesn't matter (lookup
# is a set + a prefix walk). Mostly drawn from public scanner signatures
# (Nuclei, ZAP, dirbuster wordlists). Anything not in here returns 404.
EXACT_PATHS = {
    "/admin", "/admin.php", "/admin/", "/admin/login", "/admin/login.php",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-admin/admin-ajax.php", "/wp-login.php",
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
    "/.aws/credentials", "/.ssh/id_rsa", "/.htpasswd", "/.htaccess",
    "/phpmyadmin/", "/phpmyadmin/index.php", "/pma/", "/myadmin/",
    "/server-status", "/server-info",
    "/manager/html", "/manager/status", "/host-manager/html",
    "/console/", "/jolokia/list", "/jmx-console",
    "/HNAP1/", "/HNAP1",
}
PREFIX_PATHS = (
    "/actuator/",            # spring-boot
    "/api/v1/",              # generic api fishing
    "/wp-content/",
    "/wp-includes/",
    "/cgi-bin/",
    "/vendor/",
    "/dbeaver/",
    "/.git/",
    "/owa/",                 # exchange
    "/Autodiscover/",
    "/ecp/",
)

# Bind defaults; overrideable from env so a non-80 deploy can also use this.
TARPIT_HOST = os.environ.get("SOC_TARPIT_HOST", "0.0.0.0")
TARPIT_PORT = int(os.environ.get("SOC_TARPIT_PORT", "80") or 80)
# Per-IP rate: at most BURST hits, then 1 hit per WINDOW seconds.
RL_BURST = int(os.environ.get("SOC_TARPIT_BURST", "8") or 8)
RL_WINDOW = float(os.environ.get("SOC_TARPIT_WINDOW", "2.0") or 2.0)
# Drip range: each matched request sleeps this long before answering.
DRIP_MIN = float(os.environ.get("SOC_TARPIT_DRIP_MIN", "0.5") or 0.5)
DRIP_MAX = float(os.environ.get("SOC_TARPIT_DRIP_MAX", "2.0") or 2.0)

# Concurrency cap. The systemd unit's TasksMax is a kernel-level kill switch;
# this is a per-request reservation that returns nothing (close the socket) if
# all slots are taken. Keeps slowloris from chewing every thread on the box.
CONC_MAX = int(os.environ.get("SOC_TARPIT_MAX_WORKERS", "64") or 64)
_CONC = threading.BoundedSemaphore(CONC_MAX)
_CONC_BUSY = 0
_CONC_LOCK = threading.Lock()

# Per-connection header-read timeout in seconds. After the headers are in, the
# drip + body write are bounded by DRIP_MAX + body-size and don't need an
# explicit timeout (the BoundedSemaphore caps total concurrency anyway).
CONN_TIMEOUT = float(os.environ.get("SOC_TARPIT_CONN_TIMEOUT", "5.0") or 5.0)

# External paths file; reloaded on SIGHUP. Falls back to the built-in lists.
PATHS_FILE = os.environ.get("SOC_TARPIT_PATHS_FILE",
                            "/etc/soc-display/tarpit-paths.list")
_PATHS_LOCK = threading.Lock()
_EXACT_PATHS_LIVE: set[str] = set(EXACT_PATHS)
_PREFIX_PATHS_LIVE: tuple[str, ...] = tuple(PREFIX_PATHS)

# Hit counter (bounded LRU) for SIGUSR1 dumps. We don't need exact counts
# under heavy load; we just need to identify the top offenders.
HIT_CAP = int(os.environ.get("SOC_TARPIT_HIT_CAP", "4096") or 4096)
_HIT_COUNTS: collections.OrderedDict[str, int] = collections.OrderedDict()
_HIT_LOCK = threading.Lock()


def _log_json(event: str, **fields):
    """One JSON line per event to stderr (→ journald). Lossy on full pipe —
    logging must never block a request."""
    rec = {"ts": round(time.time(), 3), "event": event, **fields}
    try:
        sys.stderr.write(json.dumps(rec, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except (BrokenPipeError, ValueError):
        pass


def _reload_paths(*_args):
    """SIGHUP handler. Atomically rebuilds `_EXACT_PATHS_LIVE` and
    `_PREFIX_PATHS_LIVE` from PATHS_FILE; built-in defaults survive when
    the file is absent / unreadable / empty (so a misconfigured file
    doesn't quietly turn the tarpit into a passive 404)."""
    global _EXACT_PATHS_LIVE, _PREFIX_PATHS_LIVE
    exact = set(EXACT_PATHS)
    prefix = list(PREFIX_PATHS)
    file_seen = False
    try:
        with open(PATHS_FILE, encoding="utf-8") as fh:
            file_seen = True
            for raw in fh:
                line = raw.partition("#")[0].strip()
                if not line:
                    continue
                if line.endswith("/*"):
                    prefix.append(line[:-1])
                else:
                    exact.add(line)
    except FileNotFoundError:
        pass
    except OSError as e:
        _log_json("paths_reload_failed", path=PATHS_FILE, err=str(e))
        return
    with _PATHS_LOCK:
        _EXACT_PATHS_LIVE = exact
        _PREFIX_PATHS_LIVE = tuple(prefix)
    _log_json("paths_reloaded", path=PATHS_FILE,
              file_seen=file_seen,
              exact=len(exact), prefix=len(prefix))


def _bump_hit(ip: str):
    with _HIT_LOCK:
        v = _HIT_COUNTS.pop(ip, 0) + 1
        _HIT_COUNTS[ip] = v
        while len(_HIT_COUNTS) > HIT_CAP:
            _HIT_COUNTS.popitem(last=False)


def _dump_hits(*_args):
    """SIGUSR1 handler. Logs top-20 hitters + busy worker count."""
    with _HIT_LOCK:
        snap = sorted(_HIT_COUNTS.items(), key=lambda kv: kv[1],
                      reverse=True)[:20]
    with _CONC_LOCK:
        busy = _CONC_BUSY
    _log_json("metrics_dump", busy=busy, workers_max=CONC_MAX,
              top=[{"ip": ip, "hits": n} for ip, n in snap])


def _matches(path: str) -> bool:
    """True if `path` looks like a known scanner target. Reads the live sets
    so SIGHUP reload is picked up without restart."""
    with _PATHS_LOCK:
        exact = _EXACT_PATHS_LIVE
        prefix = _PREFIX_PATHS_LIVE
    if path in exact:
        return True
    return any(path.startswith(p) for p in prefix)


def _mime_for(path: str) -> tuple[str, str]:
    """(Content-Type, body-generator-key) for a matched path. The body shape
    matches what a header-only scanner expects to see, so a Quick Look reads
    'yep, it's an env file' rather than 'random bytes' (which would tip them
    off that this is fake)."""
    if path.endswith((".env", ".env.local", ".env.production")):
        return "text/plain; charset=utf-8", "env"
    if path.endswith((".json",)) or path.startswith(("/api/", "/actuator/",
                                                      "/jolokia/")):
        return "application/json", "json"
    if path.startswith(("/.git/", "/.htpasswd", "/.htaccess",
                         "/.aws/", "/.ssh/")):
        return "text/plain; charset=utf-8", "text"
    return "text/html; charset=utf-8", "html"


def _junk_env(n: int) -> bytes:
    """Random `KEY=base64-junk` lines for a fake .env response."""
    lines = []
    keys = ["DATABASE_URL", "APP_KEY", "MAIL_PASSWORD", "S3_SECRET",
            "REDIS_URL", "JWT_SECRET", "API_TOKEN", "DEBUG_TOKEN"]
    while sum(len(x) + 1 for x in lines) < n:
        k = random.choice(keys)
        v = base64.urlsafe_b64encode(os.urandom(random.randint(16, 48))).decode().rstrip("=")
        lines.append(f"{k}={v}")
    return ("\n".join(lines) + "\n").encode()


def _junk_json(n: int) -> bytes:
    """A JSON blob shaped like an actuator or generic-API response."""
    keys = ["status", "data", "result", "token", "id", "name", "value"]
    pairs = []
    while sum(len(p) + 2 for p in pairs) < n:
        k = random.choice(keys)
        v = base64.urlsafe_b64encode(os.urandom(random.randint(8, 32))).decode().rstrip("=")
        pairs.append(f'"{k}_{len(pairs)}": "{v}"')
    return ("{" + ", ".join(pairs) + "}").encode()


def _junk_html(n: int) -> bytes:
    """A '<html>...random base64 in a comment...</html>' that looks like a
    real admin page on cursory inspection. Don't try to mimic specific apps —
    just enough HTML chrome that header-only scanners are satisfied."""
    body = base64.b64encode(os.urandom(max(64, n - 200))).decode()
    return (b"<!doctype html><html><head><title>Admin</title></head><body>"
            b"<h1>Login</h1><!-- "
            + body.encode()
            + b" --></body></html>")


def _junk_text(n: int) -> bytes:
    """Plain base64-looking bytes (for /.git/HEAD, /.htpasswd, ...)."""
    return base64.urlsafe_b64encode(os.urandom(max(48, n // 4 * 3))).decode().rstrip("=").encode()


_BODY_MAKERS = {
    "env": _junk_env,
    "json": _junk_json,
    "html": _junk_html,
    "text": _junk_text,
}


def _plausibility_headers(path: str, ip: str, body_len: int) -> list[tuple[str, str]]:
    """ETag + Last-Modified + Cache-Control. ETag is deterministic per
    (path, ip-hour-bucket) so a scanner that retries within an hour gets
    the same ETag — fingerprinting "are these all the same response?" is
    no longer a useful signal."""
    hour_bucket = int(time.time()) // 3600
    seed = f"{path}|{ip}|{hour_bucket}".encode()
    etag = hashlib.md5(seed).hexdigest()[:16]
    # Last-Modified within the last 30 days.
    lm = email.utils.formatdate(
        time.time() - random.randint(60, 86400 * 30), usegmt=True)
    return [
        ("ETag", f'W/"{etag}"'),
        ("Last-Modified", lm),
        ("Cache-Control", "no-store, no-cache, must-revalidate"),
    ]


# Bounded per-IP rate limiter. We use an OrderedDict so eviction is O(1) — the
# worst case (a /16 worth of attackers) only ever keeps the most-recent 4096
# IPs, which is plenty for triage + bounds the memory footprint forever.
class RateLimiter:
    def __init__(self, burst: int, window: float, cap: int = 4096):
        self._buckets: collections.OrderedDict[str, tuple[float, int]] = \
            collections.OrderedDict()
        self.burst = burst
        self.window = window
        self.cap = cap
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.pop(ip, None)
            if bucket is None:
                self._buckets[ip] = (now, 1)
                self._evict_lru()
                return True
            last, count = bucket
            elapsed = now - last
            # Leak the bucket — refill at 1/window per second.
            refilled = max(0, count - int(elapsed / self.window))
            if refilled >= self.burst:
                # Re-insert without changing the window head, so they stay capped.
                self._buckets[ip] = (last, self.burst)
                self._evict_lru()
                return False
            self._buckets[ip] = (now, refilled + 1)
            self._evict_lru()
            return True

    def _evict_lru(self):
        while len(self._buckets) > self.cap:
            self._buckets.popitem(last=False)


_LIMITER = RateLimiter(RL_BURST, RL_WINDOW)


class _Handler(http.server.BaseHTTPRequestHandler):
    """The whole tarpit. Default `do_GET` / `do_HEAD` / `do_POST` all funnel
    to `_respond` so the path detection runs regardless of method."""
    # http.server is chatty by default — silence the line-per-request log;
    # systemd journal already records our explicit JSON log lines.
    def log_request(self, code="-", size="-"):
        return

    def log_message(self, format, *args):  # noqa: A002 — match parent sig
        return

    # Override the Server header to drop the BaseHTTPServer/Python fingerprint.
    server_version = ""
    sys_version = ""

    # Cap accepted header bytes + protocol line len (parent reads via http.client
    # internals, capped above at module import). Unbuffered reads so the socket
    # timeout actually fires on a slowloris.
    rbufsize = 0
    timeout = CONN_TIMEOUT

    def setup(self):
        super().setup()
        # Per-connection deadline for the request line + headers. The drip is
        # not part of this — it runs after we've decided to respond.
        try:
            self.connection.settimeout(self.timeout)
        except (AttributeError, OSError):
            pass

    def _client_ip(self) -> str:
        # Trust X-Forwarded-For only if running behind a known proxy — for the
        # kiosk's default (port 80 directly exposed) the socket peer is truth.
        return self.client_address[0] if self.client_address else "0.0.0.0"

    def _respond(self):
        ip = self._client_ip()
        path = self.path.split("?", 1)[0]
        if not _matches(path):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # Reserve a worker slot. If we're at CONC_MAX, drop the socket
        # silently — saying 503 would tell a slowloris that its strategy is
        # working; saying nothing wastes their wait on TCP close.
        if not _CONC.acquire(blocking=False):
            try:
                self.connection.close()
            except OSError:
                pass
            _log_json("dropped_at_cap", ip=ip, path=path, busy=CONC_MAX)
            return

        global _CONC_BUSY
        with _CONC_LOCK:
            _CONC_BUSY += 1
        try:
            if not _LIMITER.allow(ip):
                # Don't even bother replying: close the socket. Bot operators
                # waiting on a response time out — much slower than a 429.
                _log_json("rate_limited", ip=ip, path=path)
                return
            _bump_hit(ip)
            # Drip — eat real scanner wall-clock. Once we own a worker slot,
            # this is bounded by DRIP_MAX, so total worker hold ≤ DRIP_MAX +
            # ~body-write time. Slowloris on the response side is bounded by
            # the body write, which is small (<= 32 KiB).
            drip = random.uniform(DRIP_MIN, DRIP_MAX)
            time.sleep(drip)
            ctype, kind = _mime_for(path)
            size = random.randint(4 * 1024, 32 * 1024)
            body = _BODY_MAKERS[kind](size)

            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _plausibility_headers(path, ip, len(body)):
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            # HEAD: send headers (incl. correct Content-Length) but no body.
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            _log_json("served", ip=ip, method=self.command, path=path,
                      status=200, bytes=len(body), drip_s=round(drip, 3))
        finally:
            with _CONC_LOCK:
                _CONC_BUSY -= 1
            _CONC.release()

    def do_GET(self):  return self._respond()
    def do_HEAD(self): return self._respond()
    def do_POST(self): return self._respond()
    def do_PUT(self):  return self._respond()


def _address_family(host: str) -> int:
    """Pick AF_INET or AF_INET6 based on the configured host. Falls back to
    AF_INET on any parse error so existing v4 deployments stay v4."""
    try:
        ipaddress.IPv6Address(host)
        return socket.AF_INET6
    except (ValueError, ipaddress.AddressValueError):
        return socket.AF_INET


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    # `daemon_threads = True` so a worker stuck mid-drip dies with the parent.
    daemon_threads = True
    allow_reuse_address = True
    # address_family set in main() per host.


def main() -> int:
    # Refuse to start if not explicitly opted in — defense in depth against an
    # operator who installed the unit but didn't mean to expose port 80.
    if os.environ.get("SOC_TARPIT_ENABLE", "0") != "1":
        sys.stderr.write("[tarpit] SOC_TARPIT_ENABLE=1 not set — exiting.\n")
        return 0
    # Wire signals BEFORE binding — a fast SIGHUP from systemd reload should
    # never race with bind.
    _reload_paths()                                  # initial load
    signal.signal(signal.SIGHUP, _reload_paths)
    signal.signal(signal.SIGUSR1, _dump_hits)
    _Server.address_family = _address_family(TARPIT_HOST)
    try:
        srv = _Server((TARPIT_HOST, TARPIT_PORT), _Handler)
    except PermissionError:
        sys.stderr.write(f"[tarpit] cannot bind {TARPIT_HOST}:{TARPIT_PORT} "
                         f"(needs CAP_NET_BIND_SERVICE for port <1024)\n")
        return 1
    except OSError as e:
        sys.stderr.write(f"[tarpit] bind failed: {e}\n")
        return 1
    _log_json("listening", host=TARPIT_HOST, port=TARPIT_PORT,
              family=("inet6" if _Server.address_family == socket.AF_INET6
                      else "inet"),
              burst=RL_BURST, window=RL_WINDOW,
              drip_min=DRIP_MIN, drip_max=DRIP_MAX,
              workers_max=CONC_MAX, conn_timeout=CONN_TIMEOUT,
              paths_file=PATHS_FILE)
    try:
        srv.serve_forever(poll_interval=1.0)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
