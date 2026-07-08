"""
openfortivpn supervisor — keeps the Fortinet SSL-VPN connected 24/7.

Run by forti-vpn.service (root) via scripts/forti-vpn-connect.py. Instead of
exec'ing openfortivpn once and letting systemd churn through restarts, this
module runs it as a supervised child and owns the reconnect policy:

  * streams openfortivpn's output into the journal and classifies it
    (strings verified against openfortivpn 1.24),
  * reconnects with exponential backoff on network drops,
  * backs off MUCH longer on authentication failures (hammering a FortiGate
    with a bad password locks the account) and on certificate-validation
    failures (retrying cannot fix a wrong/missing trusted_cert) — each with a
    loud, actionable error message,
  * re-reads the credentials from the vault and re-fetches the one-time OTP
    before every attempt (passwords rotate; OTPs are single-use),
  * optionally probes vpn.ready_probe while the tunnel is up and restarts the
    connection when it goes stale (the "connected but dead" case),
  * speaks the systemd notify protocol: READY/STATUS plus WATCHDOG heartbeats
    so a wedged supervisor is itself restarted.

The FortiGate password reaches openfortivpn only through the pinentry helper
(scripts/forti-pinentry.sh) fed via the child's environment — never argv, never
disk. Credentials are scrubbed from our copies after each spawn.
"""
from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback

from . import config as cfg
from . import vpndrivers
from .vault import Vault, VaultError

# --- log-line classification (exact strings from openfortivpn 1.24) ----------
# Kept module-level for the Fortinet path + back-compat; other types classify
# through their driver (host/vpndrivers.py).
EVENT_UP = "up"
EVENT_AUTH = "auth"
EVENT_CERT = "cert"
EVENT_DOWN = "down"
EVENT_CONNECTING = "connecting"     # progress only — never drives backoff/reconnect


class OtpUnavailable(Exception):
    """Raised by _spawn when an OTP is required (otp_from_vault) but could not be
    fetched after a bounded retry. run() routes this onto the slow vault path
    instead of spawning a guaranteed blank-OTP auth attempt (which would burn the
    long auth-lockout backoff and can lock the account). The arg is the vault item."""


_PATTERNS = (
    ("Tunnel is up and running", EVENT_UP),
    ("Could not authenticate to gateway", EVENT_AUTH),       # bad password / cert
    ("Could not authenticate to the gateway", EVENT_AUTH),   # tunnel mode / realm
    ("Login failed", EVENT_AUTH),
    ("Gateway certificate validation failed", EVENT_CERT),
    ("Bad certificate sha256 digest", EVENT_CERT),
    ("Closed connection to gateway", EVENT_DOWN),
    ("Could not start tunnel", EVENT_DOWN),
    ("Connecting to gateway", EVENT_CONNECTING),             # progress, logged only
)


def classify(line: str):
    """Map one openfortivpn output line to an event (or None)."""
    for needle, event in _PATTERNS:
        if needle in line:
            return event
    return None


class Backoff:
    """Exponential backoff: initial, initial*factor, ... capped at maximum."""

    def __init__(self, initial: float = 5.0, maximum: float = 60.0,
                 factor: float = 2.0):
        self.initial = initial
        self.maximum = maximum
        self.factor = factor
        self._next = initial

    def next(self) -> float:
        delay = self._next
        self._next = min(self._next * self.factor, self.maximum)
        return delay

    def reset(self):
        self._next = self.initial


# --- systemd integration ------------------------------------------------------
def sd_notify(state: str):
    """Best-effort sd_notify(3): datagram to $NOTIFY_SOCKET. No-op outside systemd."""
    addr = os.environ.get("NOTIFY_SOCKET", "")
    if not addr:
        return
    if addr.startswith("@"):                 # abstract-namespace socket
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(state.encode(), addr)
    except OSError:
        pass


class SdWatchdog:
    """Sends WATCHDOG=1 at half of WatchdogSec. ping() is cheap to call often."""

    def __init__(self):
        usec = os.environ.get("WATCHDOG_USEC", "")
        self.interval = (int(usec) / 1e6) / 2 if usec.isdigit() else 0
        self._last = 0.0

    def ping(self):
        if self.interval and (time.monotonic() - self._last) >= self.interval:
            sd_notify("WATCHDOG=1")
            self._last = time.monotonic()


# --- command assembly ---------------------------------------------------------
def build_cmd(vpn: dict, user: str, pinentry: str, otp: str = "") -> list:
    """Full openfortivpn argv. The password travels via the pinentry helper
    (environment), never argv. The one exception is the optional single-use OTP
    (otp_from_vault): openfortivpn 1.x accepts it only as `--otp=` on argv, so
    when supplied it is briefly visible in the process list (single-use,
    consumed in ~1s) — see docs/SECURITY.md."""
    cmd = ["openfortivpn", *cfg.openfortivpn_args(vpn),
           "-u", user, f"--pinentry={pinentry}"]
    if otp:
        cmd.append(f"--otp={otp}")
    return cmd


def probe_tcp(probe: str, timeout: float = 3.0) -> bool:
    host, sep, port = (probe or "").rpartition(":")
    # Validate host:port up front: a malformed ready_probe must return False,
    # not raise ValueError inside the health-check loop and kill it silently.
    if not (sep and host and port.isdigit() and 0 < int(port) < 65536):
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


# --- supervisor ---------------------------------------------------------------
class Supervisor:
    def __init__(self, vpn: dict, pinentry: str, log=None, driver=None):
        self.vpn = vpn
        self.pinentry = pinentry
        self.driver = driver or vpndrivers.get_driver(vpn or {})
        self.log = log or (lambda m: print(f"[soc-vpn] {m}",
                                           file=sys.stderr, flush=True))
        self.stop_event = threading.Event()
        self.child = None
        self._materialized = None       # transient VPN config file from the vault
        self._mgmt = None               # transient OpenVPN mgmt socket (best-effort cleanup)
        self._reader_thread = None      # current child-stdout reader (joined per attempt)
        self._mgmt_thread = None        # current openvpn mgmt-injector thread
        # ONE Vault for the supervisor's lifetime, opened lazily once and reused
        # across reconnect attempts. A bounded TTL caches the decrypted creds so a
        # flapping link doesn't redo a scrypt unseal + full HTTPS sync per attempt,
        # while still re-fetching after the TTL so rotated passwords recover. A
        # VaultError forces a re-open (vault-not-ready-at-boot also recovers).
        self._vault = None
        self._cred_ttl = cfg.env_float("SOC_VPN_CRED_TTL", 30.0, lo=0.0, hi=3600.0)
        self.watchdog = SdWatchdog()
        self.backoff = Backoff(
            initial=cfg.env_float("SOC_VPN_BACKOFF_INITIAL", 5.0, lo=0.1, hi=3600.0),
            maximum=cfg.env_float("SOC_VPN_BACKOFF_MAX", 60.0, lo=0.1, hi=3600.0))
        self.auth_delay = cfg.env_float("SOC_VPN_AUTH_RETRY_DELAY", 300.0, lo=0.0)
        self.cert_delay = cfg.env_float("SOC_VPN_CERT_RETRY_DELAY", 300.0, lo=0.0)
        # per-attempt state, set by the reader thread
        self._tunnel_up = False
        self._up_since = 0.0            # monotonic time the tunnel last reported UP (0 = never up this attempt)
        self._saw = set()
        self._mgmt_unreachable = False  # openvpn mgmt-socket handshake never connected this attempt

    # -- signals ---------------------------------------------------------------
    def install_signal_handlers(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._on_signal)

    def _on_signal(self, signum, _frame):
        self.log(f"received {signal.Signals(signum).name}; shutting down")
        self.stop_event.set()
        self._terminate_child()

    def _terminate_child(self, grace: float = 10.0):
        """SIGTERM the child so openfortivpn tears down routes/resolv.conf,
        escalate to SIGKILL after `grace`."""
        child = self.child
        if not child or child.poll() is not None:
            return
        try:
            child.terminate()
            try:
                child.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                self.log(f"openfortivpn did not exit within {grace:.0f}s; killing")
                child.kill()
                child.wait(timeout=5)
        except OSError:
            pass

    # -- credentials -----------------------------------------------------------
    def _open_vault(self):
        """Lazily construct + open() the one shared Vault, reusing it across
        attempts. Raises VaultError on failure (callers drop it so the next
        attempt re-opens — boot races + rotated passwords still recover)."""
        if self._vault is None:
            self._vault = Vault(ttl=self._cred_ttl)
        if not self._vault.ready():
            self._vault.open()
        return self._vault

    def _resolve_creds(self, timeout: float):
        """Reuse the shared Vault (bounded cred TTL) instead of a fresh unseal +
        full sync per attempt. The TTL still expires within `SOC_VPN_CRED_TTL`,
        so rotated passwords recover; a VaultError drops the instance and forces
        a re-open, so a failed unlock at boot (vaultwarden still starting) is not
        permanent. Returns (user, password) or None when asked to stop.

        Note: the single-use OTP is fetched fresh per attempt in _spawn via
        _otp_code() (a separate CLI call), so caching the Vault never reuses an
        OTP."""
        deadline = time.monotonic() + timeout
        while not self.stop_event.is_set():
            self.watchdog.ping()
            try:
                c = self._open_vault().creds(self.vpn["vault_item"])
                if not c["user"]:
                    self.log(f"WARNING vault item '{self.vpn['vault_item']}' "
                             f"has no username")
                return c["user"], c["pass"]
            except VaultError as e:
                self._vault = None        # force a clean re-open next try
                if time.monotonic() > deadline:
                    self.log(f"ERROR vault/creds not ready within {timeout:.0f}s: {e}")
                    return None
                self.log(f"vault not ready ({e}); retrying in 3s ...")
                sd_notify("STATUS=waiting for the credentials vault")
                self.stop_event.wait(3)
        return None

    def _otp_code(self) -> str:
        item = self.vpn["vault_item"]
        # Use the same CLI the configured backend uses (litebw is the default;
        # rbw stays selectable). Both expose an rbw-compatible `code <item>`.
        cli = "rbw" if os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND).lower() == "rbw" \
            else "litebw"
        try:
            r = subprocess.run([cli, "code", item], capture_output=True,
                               text=True, stdin=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            self.log(f"WARNING OTP fetch from vault item '{item}' timed out (CLI {cli})")
            return ""
        except FileNotFoundError:
            self.log(f"WARNING OTP CLI '{cli}' not found — install it or fix "
                     f"SOC_VAULT_BACKEND")
            return ""
        if r.returncode != 0:
            self.log(f"WARNING OTP fetch from vault item '{item}' failed "
                     f"(rc {r.returncode}): {(r.stderr or '').strip()}")
            return ""
        return r.stdout.strip()

    def _otp_code_retry(self, tries: int = 2) -> str:
        """Fetch the single-use OTP with a short bounded retry. A transient OTP
        outage (vault still syncing, momentary CLI failure) should NOT immediately
        spend a doomed blank-OTP auth attempt and trip the long auth-lockout
        backoff. Interruptible + watchdog-fed between tries; returns '' only after
        every try fails (each _otp_code already logged its own cause)."""
        for i in range(max(1, tries)):
            code = self._otp_code()
            if code:
                return code
            if i < tries - 1 and not self.stop_event.is_set():
                self.watchdog.ping()
                self.stop_event.wait(2)
        return ""

    # -- child output ----------------------------------------------------------
    def _reader(self, pipe):
        tag = self.driver.binary
        for line in iter(pipe.readline, ""):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            self.log(f"[{tag}] {line}")
            event = self.driver.classify(line)
            if event == EVENT_UP:
                self._tunnel_up = True
                self._up_since = time.monotonic()   # reset backoff later, only if it stays up
                self.log("tunnel established")
                sd_notify("STATUS=connected: tunnel is up")
            elif event == EVENT_CONNECTING:
                # Progress feedback for the wall only — must NOT land in _saw, so
                # it can never be mistaken for a drop and perturb the backoff.
                sd_notify("STATUS=connecting to gateway")
            elif event:
                self._saw.add(event)
        try:
            pipe.close()
        except OSError:
            pass

    # -- VPN config from the vault (keys never on disk persistently) -----------
    def _soc_vpn_dir(self) -> str:
        base = os.environ.get("XDG_RUNTIME_DIR") or "/run"
        d = os.path.join(base, "soc-vpn")
        try:
            os.makedirs(d, 0o700, exist_ok=True)
            os.chmod(d, 0o700)
            return d
        except OSError:
            return base

    def _materialize_config(self) -> bool:
        """If vpn.config_from_vault, fetch the .ovpn/.conf from the vault item's
        Notes and write it to a 0600 file in the 0700 soc-vpn dir, then point
        vpn['config'] at it. Returns False if it cannot be read/written."""
        if not self.vpn.get("config_from_vault"):
            return True
        item = self.vpn.get("vault_item")
        # Bounded retry, mirroring _resolve_creds: a transient vault blip at
        # connect time (vaultwarden still starting, a momentary outage) must not
        # collapse the VPN straight to idle — ride it out to the ready deadline,
        # falling through to a hard error only if it is genuinely persistent.
        # Reuse the one already-synced Vault; force a clean re-open on each error.
        deadline = time.monotonic() + cfg.env_float(
            "SOC_READY_TIMEOUT", 120.0, lo=0.0, hi=3600.0)
        while True:
            try:
                content = self._open_vault().notes(item)
                break
            except VaultError as e:
                self._vault = None
                if self.stop_event.is_set() or time.monotonic() > deadline:
                    self.log(f"ERROR reading VPN config from vault item "
                             f"'{item}': {e}")
                    return False
                self.log(f"vault not ready for VPN config ({e}); retrying in 3s")
                sd_notify("STATUS=waiting for the vault (VPN config)")
                self.stop_event.wait(3)
        if not content.strip():
            self.log(f"ERROR vault item '{item}' has no Notes content (the VPN config)")
            return False
        d = self._soc_vpn_dir()
        if self.driver.kind == "wireguard":
            iface = os.path.basename(str(self.vpn.get("config") or "wg0"))
            if iface.endswith(".conf"):
                iface = iface[:-5]
            path = os.path.join(d, f"{iface or 'wg0'}.conf")
        else:
            path = os.path.join(d, f"openvpn-{os.getpid()}.ovpn")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content if content.endswith("\n") else content + "\n")
        except OSError as e:
            self.log(f"ERROR writing VPN config: {e}")
            return False
        self._materialized = path
        self.vpn["config"] = path
        self.log(f"materialized VPN config from vault item '{item}' "
                 f"-> {path} (0600)")
        return True

    def _cleanup_materialized(self):
        if self._materialized:
            try:
                os.unlink(self._materialized)
            except OSError:
                pass
            self._materialized = None

    def _cleanup_mgmt(self):
        """Remove the OpenVPN management socket left by the last attempt.
        Per-attempt cleanup is also done at the top of the next _spawn (line
        unlinks before re-create); this covers the FINAL socket on clean stop so
        the 0700 runtime dir doesn't accumulate a stale socket per supervisor."""
        if self._mgmt:
            try:
                os.unlink(self._mgmt)
            except OSError:
                pass
            self._mgmt = None

    def _retire_attempt_threads(self):
        """Push the previous attempt's child-stdout reader (and the openvpn mgmt
        thread) to EOF and bounded-join them, so a fast connect/drop flap can't
        accumulate short-lived daemon threads + open pipe fds. Closing stdout
        from here forces the reader's blocking readline() to EOF; the join is a
        SHORT bounded timeout (the threads are daemon, so shutdown is never
        blocked even if a grandchild holds the pipe open)."""
        child = self.child
        if child is not None and child.stdout is not None:
            try:
                child.stdout.close()
            except (OSError, ValueError):
                pass
        for attr in ("_reader_thread", "_mgmt_thread"):
            t = getattr(self, attr, None)
            if t is not None and t.is_alive():
                t.join(timeout=2.0)
            setattr(self, attr, None)

    # -- OpenVPN management socket (secure user/pass injection) -----------------
    def _mgmt_path(self) -> str:
        # The OpenVPN password transits this socket, so keep it in an owner-only
        # 0700 directory — no other local user can reach it.
        base = os.environ.get("XDG_RUNTIME_DIR") or "/run"
        d = os.path.join(base, "soc-vpn")
        try:
            os.makedirs(d, 0o700, exist_ok=True)
            os.chmod(d, 0o700)
        except OSError:
            d = base
        self._sweep_orphan_mgmt(d)
        return os.path.join(d, f"openvpn-{os.getpid()}.sock")

    def _sweep_orphan_mgmt(self, d: str):
        """Best-effort: reap mgmt sockets left by a crashed/SIGKILLed supervisor.
        The path is pid-scoped, so any openvpn-<pid>.sock whose <pid> is not us
        and is not a live process is by definition an orphan. Pure stat/unlink —
        cannot hang; swallow OSError like the other best-effort cleanups."""
        try:
            entries = os.listdir(d)
        except OSError:
            return
        for fn in entries:
            if not (fn.startswith("openvpn-") and fn.endswith(".sock")):
                continue
            pid_str = fn[len("openvpn-"):-len(".sock")]
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, 0)
                continue                 # still alive — not ours to reap
            except ProcessLookupError:
                pass                     # dead pid: orphaned socket
            except OSError:
                continue                 # EPERM etc: leave it alone
            try:
                os.unlink(os.path.join(d, fn))
            except OSError:
                pass

    def _openvpn_mgmt(self, sock_path: str, creds):
        """Answer OpenVPN's password query over its management socket, so the
        username/password never appears on argv or disk."""
        user, password = creds
        password = password.replace("\n", "")
        deadline = time.monotonic() + 30
        s = None
        while time.monotonic() < deadline and not self.stop_event.is_set():
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(sock_path)
                break
            except OSError:
                s = None
                self.stop_event.wait(0.3)
        if s is None:
            # openvpn was started with --management-hold, so it is sitting HELD
            # and will never proceed past auth until we send 'hold release' over
            # this socket — which we just failed to reach. Without this, the
            # child blocks forever, _watch_child waits forever, no event is
            # recorded, and the supervisor retries the same broken path with a
            # short network backoff. Instead: flag the cause, record a DOWN, tell
            # systemd, and terminate the held child so the watch loop unblocks and
            # run() can apply a LONG backoff (this is a config/setup fault, not a
            # transient network drop).
            if self.stop_event.is_set():
                return
            self._mgmt_unreachable = True
            self._saw.add(EVENT_DOWN)
            self.log("ERROR could not reach the OpenVPN management socket — the "
                     "child started --management-hold and cannot authenticate; "
                     "check that openvpn created the socket (selinux/apparmor, "
                     "runtime dir perms). Terminating the held child and backing "
                     "off.")
            sd_notify("STATUS=OpenVPN management socket unreachable; backing off")
            self._terminate_child()
            return
        f = s.makefile("rw")
        try:
            f.write("hold release\n")
            f.flush()
            for line in f:
                line = line.strip()
                if line.startswith(">PASSWORD:Need 'Auth'"):
                    f.write(f'username "Auth" {user}\n')
                    f.write(f'password "Auth" {password}\n')
                    f.flush()
                elif "Verification Failed" in line:
                    self._saw.add(EVENT_AUTH)
        except OSError:
            pass
        finally:
            try:
                f.close()
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    # -- one attempt (process drivers: fortinet / openvpn) ---------------------
    def _spawn(self, creds):
        self._tunnel_up = False
        self._up_since = 0.0
        self._saw = set()
        self._mgmt_unreachable = False
        env = dict(os.environ)
        mgmt = None
        if self.driver.kind == "fortinet":
            user, password = creds
            otp = ""
            if self.vpn.get("otp_from_vault"):
                otp = self._otp_code_retry()
                if not otp:
                    # We KNOW we have no OTP to send. Do NOT spawn a guaranteed
                    # bad-auth attempt (records EVENT_AUTH + burns the full
                    # auth-lockout backoff, and rapid blank-OTP logins can lock
                    # the account). Signal run() to take the slow vault path.
                    raise OtpUnavailable(self.vpn.get("vault_item"))
            cmd = self.driver.build_cmd(self.vpn, user, self.pinentry, otp=otp)
            env["SOC_VPN_PASSWORD"] = password
        elif self.driver.kind == "inode":
            user, password = creds
            cmd = self.driver.build_cmd(self.vpn, user)
            env["H3C_SVPN_PASSWORD"] = password   # via child env, never argv/disk
        else:  # openvpn
            if creds:
                mgmt = self._mgmt_path()
                try:
                    os.unlink(mgmt)
                except OSError:
                    pass
                self._mgmt = mgmt          # track for teardown cleanup
                cmd = self.driver.build_cmd(self.vpn, mgmt_socket=mgmt)
            else:
                cmd = self.driver.build_cmd(self.vpn)
        # Actively retire the previous attempt's reader/mgmt threads + pipe before
        # spawning the next, so a fast flap can't accumulate short-lived threads.
        self._retire_attempt_threads()
        self.child = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        self._reader_thread = threading.Thread(
            target=self._reader, args=(self.child.stdout,), daemon=True)
        self._reader_thread.start()
        if mgmt and creds:
            self._mgmt_thread = threading.Thread(
                target=self._openvpn_mgmt, args=(mgmt, creds), daemon=True)
            self._mgmt_thread.start()

    def _watch_child(self):
        """Wait for the child to exit; meanwhile heartbeat + health-check."""
        interval = int(self.vpn.get("health_check_interval", 0) or 0)
        threshold = int(self.vpn.get("health_check_failures", 3) or 3)
        probe = (self.vpn.get("ready_probe") or "").strip()
        next_check = time.monotonic() + interval if interval and probe else None
        failures = 0
        while self.child.poll() is None:
            if self.stop_event.is_set():
                self._terminate_child()
                break
            self.watchdog.ping()
            if next_check and self._tunnel_up and time.monotonic() >= next_check:
                next_check = time.monotonic() + interval
                if probe_tcp(probe):
                    failures = 0
                else:
                    failures += 1
                    self.log(f"health check: {probe} unreachable "
                             f"({failures}/{threshold})")
                    if failures >= threshold:
                        self.log("health check failed — tunnel looks dead; "
                                 "restarting openfortivpn")
                        sd_notify("STATUS=health check failed; reconnecting")
                        self._terminate_child()
                        break
            self.stop_event.wait(1)

    # -- target description + dry-run ------------------------------------------
    def _target(self) -> str:
        k = self.driver.kind
        if k == "fortinet":
            return f"to {self.vpn.get('gateway')}"
        if k == "openvpn":
            return f"OpenVPN ({self.vpn.get('config')})"
        if k == "inode":
            return f"iNode SSL-VPN ({self.vpn.get('gateway')})"
        return f"WireGuard ({cfg.wireguard_target(self.vpn)})"

    def _dry_print(self, creds):
        if self.driver.kind == "fortinet":
            user = creds[0] if creds else "<user>"
            cmd = self.driver.build_cmd(
                self.vpn, user, self.pinentry,
                otp="<otp>" if self.vpn.get("otp_from_vault") else "")
            self.log("DRY RUN — would run: " + " ".join(cmd))
            self.log(f"resolved user='{user}'; password fed via {self.pinentry} "
                     f"(not shown)")
        elif self.driver.kind == "inode":
            user = creds[0] if creds else "<user>"
            cmd = self.driver.build_cmd(self.vpn, user)
            self.log("DRY RUN — would run: " + " ".join(cmd))
            self.log(f"resolved user='{user}'; password fed via "
                     f"$H3C_SVPN_PASSWORD (not shown)")
        else:  # openvpn
            cmd = self.driver.build_cmd(
                self.vpn, mgmt_socket=self._mgmt_path() if creds else None)
            self.log("DRY RUN — would run: " + " ".join(cmd))
            if creds:
                self.log(f"resolved user='{creds[0]}'; password injected over the "
                         f"management socket (not shown)")

    # -- the loop (process drivers: fortinet / openvpn) ------------------------
    def run(self) -> int:
        """Top-level supervise entry. A supervisor thread must NEVER die on an
        unexpected exception — that would orphan a child and leave this VPN
        permanently offline (the manager reports it down and never restarts it).
        Any escape is logged loudly with a traceback, the child/config/socket are
        cleaned, and we fall into idle() so the thread stays alive and
        watchdog-pingable instead of dying silently."""
        try:
            if self.driver.is_interface:
                return self._run_interface()
            return self._run_process()
        except Exception as e:                          # noqa: BLE001
            self.log(f"UNEXPECTED supervisor error: {e!r}\n{traceback.format_exc()}")
            sd_notify("STATUS=internal supervisor error; idling (will not churn)")
            try:
                self._terminate_child()
                self._cleanup_materialized()
                self._cleanup_mgmt()
            except Exception:                           # noqa: BLE001
                pass
            return self.idle()

    def _run_process(self) -> int:
        timeout = cfg.env_float("SOC_READY_TIMEOUT", 120.0, lo=0.0, hi=3600.0)
        needs = self.driver.needs_creds(self.vpn)

        # dry-run is a config check — it must work even without the binary present
        if os.environ.get("SOC_VPN_DRY_RUN") == "1":
            creds = self._resolve_creds(timeout) if needs else None
            self._dry_print(creds)
            return 0

        binpath = self.driver.resolve_binary(self.vpn)
        if not (shutil.which(binpath)
                or (os.path.isfile(binpath) and os.access(binpath, os.X_OK))):
            self.log(f"FATAL: {binpath} not found / not executable — install it "
                     f"(or fix vpn.config) and restart the VPN service")
            sd_notify(f"STATUS={os.path.basename(binpath)} is not available")
            return self.idle()

        if not self._materialize_config():
            sd_notify("STATUS=could not load VPN config from the vault")
            return self.idle()

        target = self._target()
        attempt = 0

        while not self.stop_event.is_set():
            creds = None
            if needs:
                creds = self._resolve_creds(timeout)
                if creds is None:
                    if self.stop_event.is_set():
                        break
                    # vault outage: keep the service alive, retry on the slow path
                    sd_notify("STATUS=vault unavailable; retrying")
                    self._sleep(min(self.auth_delay, 60))
                    continue

            attempt += 1
            who = f" as '{creds[0]}'" if creds else ""
            self.log(f"connecting {target}{who} (attempt {attempt})")
            sd_notify(f"STATUS=connecting {target} (attempt {attempt})")
            try:
                self._spawn(creds)
            except OtpUnavailable as e:
                # OTP required but unavailable — no child was started. Take the
                # slow vault path (like a vault outage) rather than the angry
                # auth-lockout backoff: this is a transient fetch fault, not a
                # rejected credential.
                self.log(f"could not retrieve the OTP from vault item '{e}' — "
                         f"not attempting a blank-OTP login; retrying shortly")
                sd_notify(f"STATUS=could not retrieve OTP from vault item {e}")
                self._sleep(min(self.auth_delay, 60))
                continue
            except OSError as e:
                self.log(f"ERROR could not start {self.driver.binary}: {e}")
                self._sleep(self.backoff.next())
                continue
            except Exception as e:                      # noqa: BLE001
                # An UNEXPECTED spawn error must not escape and kill the
                # supervisor thread (which would orphan a child + leave the VPN
                # permanently dead). Log loudly, reap any child we did create,
                # back off, and keep trying to reconnect — never swallow silently.
                self.log(f"UNEXPECTED supervisor error during spawn: {e!r}; "
                         f"terminating child and backing off")
                self._terminate_child()
                self._sleep(self.backoff.next())
                continue
            finally:
                creds = None  # scrub our copy

            try:
                self._watch_child()
            except Exception as e:                      # noqa: BLE001
                self.log(f"UNEXPECTED supervisor error while watching the child: "
                         f"{e!r}; terminating child and backing off")
                self._terminate_child()
                self._retire_attempt_threads()
                self._sleep(self.backoff.next())
                continue
            self._retire_attempt_threads()
            rc = self.child.returncode if self.child else -1
            if self.stop_event.is_set():
                break

            # the child is gone — decide how angrily to come back
            if self._mgmt_unreachable:
                # The OpenVPN management socket never became reachable, so auth
                # was never even attempted — this is a setup/config fault, not a
                # transient drop. Apply a LONG backoff (like auth/cert) so we
                # don't spin retrying the same broken path with a short delay.
                self.log("=" * 70)
                self.log(f"OPENVPN MANAGEMENT SOCKET UNREACHABLE ({self.driver.kind}, "
                         f"exit {rc}).")
                self.log("  openvpn could not be authenticated because its "
                         "management socket never came up; verify openvpn can "
                         "create the socket (runtime dir perms, selinux/apparmor).")
                self.log(f"  Backing off {self.auth_delay:.0f}s before retrying.")
                self.log("=" * 70)
                sd_notify("STATUS=OpenVPN management socket unreachable (long backoff)")
                self._sleep(self.auth_delay)
            elif EVENT_AUTH in self._saw:
                item = self.vpn.get("vault_item")
                self.log("=" * 70)
                self.log(f"AUTHENTICATION FAILED ({self.driver.kind}, exit {rc}).")
                self.log(f"  * check the username/password in vault item '{item}'")
                if self.driver.kind == "fortinet":
                    self.log("  * check vpn.realm and that SSL-VPN tunnel mode is "
                             "enabled for this user/group on the FortiGate")
                    if self.vpn.get("otp_from_vault"):
                        self.log("  * OTP was attached — verify the TOTP secret in "
                                 "the vault item")
                self.log(f"  NOT retrying for {self.auth_delay:.0f}s — rapid retries "
                         f"with a bad password can LOCK the account")
                self.log("=" * 70)
                sd_notify("STATUS=authentication failed; "
                          "fix the vault credentials (long backoff)")
                self._sleep(self.auth_delay)
            elif EVENT_CERT in self._saw:
                self.log("=" * 70)
                self.log(f"CERTIFICATE VALIDATION FAILED ({self.driver.kind}, "
                         f"exit {rc}).")
                if self.driver.kind == "fortinet":
                    self.log("  Pin the gateway cert: copy the sha256 digest from the "
                             "message above into vpn.trusted_cert, or set vpn.ca_file.")
                else:
                    self.log("  The server certificate did not verify. Check the "
                             "ca/cert/key in the .ovpn profile and the system clock.")
                self.log("  Retrying cannot succeed until the config is fixed.")
                self.log("=" * 70)
                sd_notify("STATUS=certificate validation failed (long backoff)")
                self._sleep(self.cert_delay)
            else:
                # A tunnel that stayed up past the backoff floor was a real
                # connection: reset so the next drop retries fast. A sub-floor
                # connect/drop flap is throttled — the backoff climbs toward
                # SOC_VPN_BACKOFF_MAX instead of looping at the 5s floor.
                if self._up_since and (time.monotonic() - self._up_since) >= self.backoff.initial:
                    self.backoff.reset()
                delay = self.backoff.next()
                why = "connection closed" if EVENT_DOWN in self._saw else \
                      f"{self.driver.binary} exited ({rc})"
                self.log(f"{why}; reconnecting in {delay:.0f}s")
                sd_notify(f"STATUS=disconnected; reconnecting in {delay:.0f}s")
                self._sleep(delay)

        self._terminate_child()
        self._cleanup_materialized()
        self._cleanup_mgmt()
        self.log("stopped")
        sd_notify("STATUS=stopped")
        return 0

    # -- the loop (interface drivers: wireguard) -------------------------------
    def _run_oneshot(self, cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=60)
            return r.returncode, (r.stdout + r.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            return 1, str(e)

    def _wg_is_up(self, iface) -> bool:
        rc, _ = self._run_oneshot(["wg", "show", iface])
        return rc == 0

    def _wg_handshake_ok(self, iface, max_age=180) -> bool:
        rc, out = self._run_oneshot(["wg", "show", iface, "latest-handshakes"])
        if rc != 0:
            return False
        now = time.time()
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[-1].isdigit():
                ts = int(parts[-1])
                if ts > 0 and (now - ts) < max_age:
                    return True
        return False

    def _run_interface(self) -> int:
        probe = (self.vpn.get("ready_probe") or "").strip()
        interval = int(self.vpn.get("health_check_interval", 0) or 0) or 30
        threshold = int(self.vpn.get("health_check_failures", 3) or 3)
        if os.environ.get("SOC_VPN_DRY_RUN") == "1":
            self.log("DRY RUN — would run: " + " ".join(self.driver.up_cmd(self.vpn)))
            return 0
        if not shutil.which(self.driver.binary):
            self.log(f"FATAL: {self.driver.binary} not found — install "
                     f"wireguard-tools and restart the VPN service")
            sd_notify("STATUS=wg-quick is not installed")
            return self.idle()
        if not self._materialize_config():      # may rewrite vpn['config']
            sd_notify("STATUS=could not load WireGuard config from the vault")
            return self.idle()
        target = cfg.wireguard_target(self.vpn)
        iface = self.driver.iface(self.vpn)

        first = True
        try:
            while not self.stop_event.is_set():
                if not self._wg_is_up(iface):
                    self.log(f"bringing up WireGuard ({target})")
                    sd_notify(f"STATUS=connecting WireGuard {iface}")
                    rc, out = self._run_oneshot(self.driver.up_cmd(self.vpn))
                    if rc != 0:
                        d = self.backoff.next()
                        self.log(f"wg-quick up failed (rc {rc}): {out}; "
                                 f"retrying in {d:.0f}s")
                        sd_notify("STATUS=wg-quick up failed; retrying")
                        self._sleep(d)
                        continue
                    self.backoff.reset()
                    self.log("WireGuard interface up")
                    sd_notify("STATUS=connected: WireGuard up")
                elif first:
                    # A previous run left the interface up (its teardown never
                    # ran — e.g. the supervisor crashed). Tear it down ONCE so the
                    # next iteration reasserts fresh keys/routes instead of
                    # trusting a stale iface; only ever on the first iteration.
                    first = False
                    self.log(f"WireGuard {iface} already up at start — cycling "
                             f"once to reassert fresh keys/routes")
                    self._run_oneshot(self.driver.down_cmd(self.vpn))
                    continue
                first = False
                failures = 0
                next_check = time.monotonic() + interval
                while not self.stop_event.is_set():
                    self.watchdog.ping()
                    if time.monotonic() >= next_check:
                        next_check = time.monotonic() + interval
                        ok = probe_tcp(probe) if probe else self._wg_handshake_ok(iface)
                        if ok:
                            failures = 0
                        else:
                            failures += 1
                            self.log(f"WireGuard health check failed "
                                     f"({failures}/{threshold})")
                            if failures >= threshold:
                                self.log("cycling the WireGuard interface")
                                sd_notify("STATUS=health check failed; reconnecting")
                                drc, dout = self._run_oneshot(
                                    self.driver.down_cmd(self.vpn))
                                if drc != 0 and self._wg_is_up(iface):
                                    # down failed but the iface is still up — the
                                    # next `wg-quick up` would refuse ('already
                                    # exists'). Force-remove the device so the
                                    # cycle recovers (this drops its routes too).
                                    self.log(f"wg-quick down failed (rc {drc}): "
                                             f"{dout}; force-removing {iface}")
                                    self._run_oneshot(["ip", "link", "delete",
                                                       "dev", iface])
                                break
                    self.stop_event.wait(1)
                if self.stop_event.is_set():
                    break
        finally:
            # Guarantee teardown on EVERY exit path (clean stop, break, or an
            # escaping exception) so a crash can't leave the interface + its
            # routes installed for the next process to trip over.
            self._run_oneshot(self.driver.down_cmd(self.vpn))
            self._cleanup_materialized()
        self.log("stopped")
        sd_notify("STATUS=stopped")
        return 0

    def _sleep(self, seconds: float):
        """Interruptible sleep that keeps feeding the systemd watchdog."""
        deadline = time.monotonic() + seconds
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            self.watchdog.ping()
            self.stop_event.wait(min(1.0, max(0.0, deadline - time.monotonic())))

    def idle(self) -> int:
        """Stay alive without churning systemd restarts (disabled/unfixable VPN).
        The reason was already logged + put in STATUS."""
        while not self.stop_event.is_set():
            self.watchdog.ping()
            self.stop_event.wait(60)
        return 0


# --- litebw bootstrap (root's first run) ---------------------------------------
def ensure_litebw_session(log):
    """Idempotently point root's litebw at the kiosk vault and register the
    device, so the unattended `litebw unlock` inside Vault.open() can succeed.
    The master password is supplied non-interactively by the pinentry in
    $SOC_PINENTRY. litebw is the default; the rbw backend reuses this flow
    against the rbw CLI (the two share a config layout)."""
    cli = "rbw" if os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND).lower() == "rbw" \
        else "litebw"
    for key, val in (("email", os.environ.get("SOC_VAULT_EMAIL", "")),
                     ("base_url", os.environ.get("SOC_VAULT_URL", "")),
                     ("pinentry", os.environ.get("SOC_PINENTRY", ""))):
        if val:
            subprocess.run([cli, "config", "set", key, val],
                           stdin=subprocess.DEVNULL, timeout=30)
    # no-op if the device is already registered; pinentry supplies the password
    try:
        r = subprocess.run([cli, "login"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=60)
        if r.returncode != 0:
            log(f"{cli} login rc={r.returncode}: {(r.stderr or '').strip()}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log(f"{cli} login: {e}")


# back-compat alias (older callers / tests may import the rbw-era name)
ensure_rbw_session = ensure_litebw_session


def _vpn_incomplete(vpn: dict) -> bool:
    """A per-type completeness gate (validation already reported the details).
    True means the entry is enabled but cannot connect — skip/idle it."""
    kind = cfg.vpn_kind(vpn)
    from_vault = bool(vpn.get("config_from_vault"))
    return (
        (kind == "fortinet" and (not vpn.get("gateway") or not vpn.get("vault_item")))
        or (kind == "inode" and (not vpn.get("gateway") or not vpn.get("vault_item")))
        or (kind in ("openvpn", "wireguard") and not from_vault and not vpn.get("config"))
        or (kind in ("openvpn", "wireguard") and from_vault and not vpn.get("vault_item")))


def main() -> int:
    """Entry point used by scripts/forti-vpn-connect.py (forti-vpn.service).

    Single unit, N supervisors: this reads conf.vpns (the authoritative list —
    a legacy `vpn:{}` is normalized to a one-entry list, so the single-VPN case
    is byte-for-byte identical behaviour) and fans it out to a VpnManager that
    runs one independent supervisor thread per enabled entry. The unit stays a
    SINGLE journald stream tagged [vpn:<name>] per line."""
    from . import vpnmanager

    def log(msg):
        print(f"[forti-vpn] {msg}", file=sys.stderr, flush=True)

    # Tell systemd we are up immediately: the *service* (the manager) is ready
    # even while the tunnels are still connecting — tunnel state is surfaced via
    # STATUS=, and VPN-side consumers gate on each vpn.ready_probe.
    sd_notify("READY=1\nSTATUS=starting")

    panels = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    try:
        conf = cfg.load(panels)
    except cfg.ConfigError as e:
        log(f"FATAL: {e}")
        log("fix the config, then: systemctl restart forti-vpn")
        sd_notify("STATUS=config error — see journal")
        sup = Supervisor({}, "")
        sup.install_signal_handlers()
        return sup.idle()
    for w in conf.warnings:
        log(f"WARNING {w}")

    pinentry = os.environ.get("SOC_VPN_PINENTRY") or os.path.join(
        os.environ.get("SOC_ROOT", os.getcwd()), "scripts", "forti-pinentry.sh")

    # Filter conf.vpns down to the entries that can actually run; idle the rest
    # (the manager only ever sees runnable entries, so a bad one never thrashes).
    vpns = list(conf.vpns or [])
    enabled = [v for v in vpns if isinstance(v, dict) and v.get("enabled")]
    if not enabled:
        log("no VPN enabled in config; idling")
        sd_notify("STATUS=disabled in panels.yaml")
        idler = Supervisor({}, "")
        idler.install_signal_handlers()
        return idler.idle()

    runnable = []
    backend = os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND).lower()
    need_vault_session = False
    for vpn in enabled:
        name = vpn.get("name") or "vpn"
        kind = cfg.vpn_kind(vpn)
        if _vpn_incomplete(vpn):
            log(f"[vpn:{name}] config incomplete for type '{kind}'; "
                f"skipping (see warnings above)")
            continue
        log(f"[vpn:{name}] type: {kind}")
        if kind == "fortinet" and int(vpn.get("persistent", 0) or 0) > 0:
            log(f"[vpn:{name}] NOTE persistent > 0: openfortivpn reconnects "
                f"in-process; the supervisor only adds health checks + crash "
                f"restarts. Set persistent: 0 for the classified backoff.")
        driver = vpndrivers.get_driver(vpn)
        if driver.needs_creds(vpn) or bool(vpn.get("config_from_vault")):
            need_vault_session = True
        runnable.append(vpn)

    if not runnable:
        log("no runnable VPN (all enabled entries are incomplete); idling")
        sd_notify("STATUS=incomplete vpn config — see journal")
        idler = Supervisor({}, "")
        idler.install_signal_handlers()
        return idler.idle()

    # a CLI vault session is needed when ANY VPN reads creds OR its config from
    # the vault; litebw is the default, rbw stays selectable. One session covers
    # all supervisors.
    if need_vault_session and backend in ("litebw", "rbw"):
        try:
            ensure_litebw_session(log)
        except Exception as e:  # noqa: BLE001 — best effort; Vault.open() is the gate
            log(f"litebw session setup warning: {e}")

    mgr = vpnmanager.VpnManager(runnable, pinentry, log=log)
    stop = threading.Event()

    def on_signal(signum, _frame):
        log(f"received {signal.Signals(signum).name}; shutting down all VPNs")
        stop.set()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal)

    log(f"starting {mgr.count} VPN supervisor(s): {', '.join(mgr.names)}")
    mgr.start()

    # Dry-run (make vpn-check): each supervisor resolves creds + prints its
    # command and returns immediately. Give the threads a moment to print, then
    # tear down and exit 0 — DON'T block in the supervise loop forever.
    if os.environ.get("SOC_VPN_DRY_RUN") == "1":
        for name, t in list(mgr._threads.items()):
            t.join(timeout=cfg.env_float("SOC_READY_TIMEOUT", 120.0, lo=1.0) + 5)
        mgr.stop()
        return 0

    # Block until stopped, petting the watchdog and aggregating per-name STATUS
    # so journalctl/`systemctl status` shows the live picture. We keep the
    # watchdog alive while ANY supervisor thread is healthy (a single wedged
    # supervisor must not silently mask the whole unit, but it also must not
    # restart everyone — the manager owns that blast-radius tradeoff).
    watchdog = SdWatchdog()
    last_status = ""
    while not stop.is_set():
        watchdog.ping()
        # states() may TCP-probe each ready_probe (small bounded per-probe). Pet
        # the watchdog BETWEEN each per-VPN probe (on_each) as well as before/after
        # so no batch size — however many VPNs, however many black-holed probes —
        # can ever starve the heartbeat and self-kill the unit.
        states = mgr.states(on_each=watchdog.ping)
        watchdog.ping()
        agg = vpnmanager.aggregate_state(states)
        status = (f"STATUS={agg}: "
                  + ", ".join(f"{n}={s}" for n, s in states.items()))
        if status != last_status:
            sd_notify(status)
            last_status = status
        stop.wait(5)

    mgr.stop()
    log("all VPNs stopped")
    sd_notify("STATUS=stopped")
    return 0
