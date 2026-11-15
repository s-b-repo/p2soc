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

import collections
import errno
import itertools
import os
import re
import resource
import select
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
from . import vpnstatus
# Re-exported: the one IPv6-aware probe parser lives in vpnstatus, which cannot
# import this module (it is the privilege-free side the GTK host polls from).
from .vpnstatus import _split_host_port  # noqa: F401
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


def _mgmt_sanitize(value) -> str:
    """Strip CR/LF before anything reaches the OpenVPN management socket. The
    protocol is line-oriented, so a vault value holding a newline would otherwise
    inject management commands (`signal SIGTERM`, ...) onto the control channel."""
    return (value or "").replace("\r", "").replace("\n", "")


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
    """Sends WATCHDOG=1 at half of WatchdogSec. ping() is cheap to call often.

    `beat` records the last ping whether or not it reached systemd. A supervisor
    run by the VpnManager has notify=False: if every thread could pet systemd,
    any one healthy thread would hide a wedged sibling. The manager reads `beat`
    instead, and only the main loop sends WATCHDOG=1, and only while every
    supervisor is beating (see _supervise)."""

    def __init__(self, notify: bool = True):
        usec = os.environ.get("WATCHDOG_USEC", "")
        self.interval = (int(usec) / 1e6) / 2 if usec.isdigit() else 0
        self.notify = notify
        self.beat = time.monotonic()
        self._last = 0.0

    def ping(self):
        self.beat = time.monotonic()
        if self.notify and self.interval and (self.beat - self._last) >= self.interval:
            sd_notify("WATCHDOG=1")
            self._last = self.beat


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
    # _tcp_probe is IPv6-aware and turns a malformed ready_probe into 'refused'
    # rather than raising inside the health-check loop.
    return vpnstatus._tcp_probe(probe or "", timeout=timeout) == "ok"


def _redact_argv(cmd: list) -> list:
    """An argv safe to print: masks the value after any secret-bearing flag."""
    out, hide = [], False
    for arg in cmd:
        out.append("<redacted>" if hide else arg)
        hide = arg == "--spa-key"
    return out


# --- supervisor ---------------------------------------------------------------
_TICK = 5.0                     # longest a waiting loop goes without a heartbeat;
                                # stop_event ends every such wait at once anyway
_MAX_LINE = 64 * 1024           # a child writing without newlines cannot grow RAM
_CHILD_ENV_DROP = ("SOC_VAULT_PASSWORD",)   # the vault master; no VPN client needs it

# Per-supervisor scratch dirs, plus the flat names older versions left behind.
_ORPHAN_RE = re.compile(r"^(?:openvpn-(\d+)\.(?:sock|ovpn)|vpn-(\d+)-\d+)$")


class _ChildOutput:
    """Line reader over a child's stdout that can be told to stop.

    Why not read the Popen pipe directly: closing a buffered file blocks for as
    long as another thread is reading it, so retiring an attempt wedged the
    supervisor whenever a grandchild held the write end. Polling the raw fd lets
    `done` end the read instead, and the reader closes its own pipe. Bytes are
    decoded here with errors replaced, because gateway text is not always UTF-8
    and a strict decoder would kill the reader on the first bad byte."""

    def __init__(self, stream, done: threading.Event):
        self._stream = stream
        self._done = done
        self._poller = select.poll()
        self._poller.register(stream.fileno(), select.POLLIN | select.POLLHUP)
        self._lines = collections.deque()
        self._tail = b""

    def _fill(self) -> bool:
        """Queue more lines; False once the stream is finished or abandoned."""
        while not self._done.is_set():
            if not self._poller.poll(1000):
                continue
            try:
                chunk = os.read(self._stream.fileno(), _MAX_LINE)
            except OSError:
                chunk = b""
            if not chunk:
                break
            lines = (self._tail + chunk).split(b"\n")
            self._tail = lines.pop()
            if len(self._tail) >= _MAX_LINE:
                lines.append(self._tail)
                self._tail = b""
            if lines:
                self._lines.extend(lines)
                return True
        if self._tail:
            self._lines.append(self._tail)
            self._tail = b""
            return True
        return False

    def readline(self) -> str:
        """The next line including its newline, or '' at EOF or once told to stop."""
        if not self._lines and not self._fill():
            return ""
        return self._lines.popleft().decode("utf-8", "replace") + "\n"

    def close(self):
        self._stream.close()


# Threads share a pid, so anything pid-scoped would be shared by every VPN in the
# unit: this count is what keeps their keys and sockets apart.
_instances = itertools.count(1)


class Supervisor:
    # Keys an operator may set in a vault Notes KEY=VALUE block when
    # config_from_vault is on for fortinet/inode. A strict allowlist, so a note
    # cannot smuggle an arbitrary setting past the on-screen review. Mirrors the
    # GUI VPN tab fields.
    _VAULT_VPN_NOTES_KEYS = {"gateway", "port", "realm", "domain",
                             "trusted_cert", "ca_file", "ready_probe",
                             "insecure", "set_routes", "set_dns",
                             "half_internet_routes", "otp_from_vault"}
    _VAULT_VPN_NOTES_BOOLS = {"insecure", "set_routes", "set_dns",
                              "half_internet_routes", "otp_from_vault"}

    def __init__(self, vpn: dict, pinentry: str, log=None, driver=None):
        self.vpn = vpn
        self.pinentry = pinentry
        self.driver = driver or vpndrivers.get_driver(vpn or {})
        self.log = log or (lambda m: print(f"[soc-vpn] {m}",
                                           file=sys.stderr, flush=True))
        self.stop_event = threading.Event()
        self.child = None
        self._instance = next(_instances)
        self._scratch = None            # this supervisor's private 0700 dir
        self._materialized = None       # transient VPN config file from the vault
        self._mgmt = None               # transient OpenVPN mgmt socket (best-effort cleanup)
        self._reader_thread = None      # current child-stdout reader (joined per attempt)
        self._mgmt_thread = None        # current openvpn mgmt-injector thread
        self._attempt_done = None       # Event telling that attempt's threads to quit
        # ONE Vault for the supervisor's lifetime, opened lazily once and reused
        # across reconnect attempts, so a flapping link doesn't redo a scrypt unseal
        # + full HTTPS sync per attempt. A rejected login re-syncs it, so rotated
        # passwords recover (_refresh_vault). A VaultError forces a re-open
        # (vault-not-ready-at-boot also recovers).
        self._vault = None
        self._cred_ttl = cfg.env_float("SOC_VPN_CRED_TTL", 30.0, lo=0.0, hi=3600.0)
        self.watchdog = SdWatchdog()
        self.backoff = Backoff(
            initial=cfg.env_float("SOC_VPN_BACKOFF_INITIAL", 5.0, lo=0.1, hi=3600.0),
            maximum=cfg.env_float("SOC_VPN_BACKOFF_MAX", 60.0, lo=0.1, hi=3600.0))
        # Floors of 1s: at 0 a fast-failing login would respawn in a tight loop,
        # which is both a CPU spin and exactly the rapid retry that locks accounts.
        self.auth_delay = cfg.env_float("SOC_VPN_AUTH_RETRY_DELAY", 300.0, lo=1.0)
        self.cert_delay = cfg.env_float("SOC_VPN_CERT_RETRY_DELAY", 300.0, lo=1.0)
        self._slow_retry = min(self.auth_delay, 60.0)   # vault/OTP outage path
        # A tunnel must outlive the longest delay we would otherwise impose before
        # it counts as a real connection: resetting any sooner lets a link that
        # survives a few seconds per try reconnect at the floor forever.
        self.stable_after = max(60.0, self.backoff.maximum)
        # Each failed unlock re-runs scrypt plus a login; retried at a fixed 3s,
        # a Vaultwarden outage pins the 1 GB board, once per VPN.
        self._vault_retry = Backoff(initial=3.0, maximum=60.0)
        # 0 disables. Without this a child that hangs before UP is waited on forever.
        self.connect_timeout = cfg.env_float(
            "SOC_VPN_CONNECT_TIMEOUT", 300.0, lo=0.0, hi=3600.0)
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

    def _signal_group(self, child, sig):
        """Signal the attempt's whole process group (start_new_session makes the
        child's pid its pgid). The leader alone is not enough: svpn-connect.sh is
        a bash wrapper whose TERM trap cannot run until its foreground pipeline
        ends, so signalling only bash waits out the grace period, then SIGKILLs
        bash and orphans the backend, leaving the tunnel up and the pipe held."""
        try:
            os.killpg(child.pid, sig)
        except OSError:
            pass

    def _terminate_child(self, grace: float = 10.0, child=None):
        """SIGTERM the child so openfortivpn tears down routes/resolv.conf,
        escalate to SIGKILL after `grace`. `child` names a specific attempt's
        process; the default is the current one."""
        child = child or self.child
        if not child or child.poll() is not None:
            return
        self._signal_group(child, signal.SIGTERM)
        try:
            child.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self.log(f"{self.driver.binary} did not exit within {grace:.0f}s; killing")
            self._signal_group(child, signal.SIGKILL)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Do not log the exception: it carries the full argv, --otp included.
                self.log(f"{self.driver.binary} survived SIGKILL (stuck in the "
                         f"kernel?); it will be retried before the next attempt")

    def _reap_group(self, child, grace: float = 2.0):
        """Clear anything a finished attempt left in its process group. A straggler
        holds the tunnel and our stdout pipe, and would fight the next attempt.
        Safe to signal by pid here: a pgid cannot be reused while its group has
        members, and an empty group is the ordinary ESRCH case."""
        if child is None or child.poll() is None:
            return
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except OSError:
            return
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            try:
                os.killpg(child.pid, 0)
            except OSError:
                return
            time.sleep(0.1)
        self._signal_group(child, signal.SIGKILL)

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
        """Reuse the shared Vault instead of a fresh unseal + full sync per
        attempt. A VaultError drops the instance and forces a re-open, so a failed
        unlock at boot (vaultwarden still starting) is not permanent. Returns
        (user, password) or None when asked to stop.

        Note: the single-use OTP is computed fresh per attempt in _spawn via
        _otp_code(), so caching the Vault never reuses an OTP."""
        deadline = time.monotonic() + timeout
        while not self.stop_event.is_set():
            self.watchdog.ping()
            try:
                c = self._open_vault().creds(self.vpn["vault_item"])
                self._vault_retry.reset()
                if not c["user"]:
                    self.log(f"WARNING vault item '{self.vpn['vault_item']}' "
                             f"has no username")
                return c["user"], c["pass"]
            except VaultError as e:
                self._vault = None        # force a clean re-open next try
                if time.monotonic() > deadline:
                    self.log(f"ERROR vault/creds not ready within {timeout:.0f}s: {e}")
                    return None
                delay = self._vault_retry.next()
                self.log(f"vault not ready ({e}); retrying in {delay:.0f}s ...")
                sd_notify("STATUS=waiting for the credentials vault")
                self._sleep(delay)
        return None

    def _refresh_vault(self):
        """Re-sync the shared Vault with the server. The backend serves creds and
        TOTP secrets from the RAM snapshot taken at its last sync, and nothing else
        renews that for this Vault's lifetime, so without this a rotated password
        is never seen: the old one is resent until someone restarts the service.
        A sync is an HTTPS round trip and does not re-derive the sealed master, so
        it suits the slow paths that call it. If it fails the Vault is dropped:
        resending a possibly rotated password risks locking the account."""
        vault = self._vault
        if vault is None:
            return
        self.watchdog.ping()
        try:
            vault.invalidate()
            vault.backend.sync()
        except Exception as e:                          # noqa: BLE001
            self.log(f"could not re-sync the vault ({type(e).__name__}); "
                     f"it will be re-opened")
            self._vault = None

    def _otp_code(self) -> str:
        item = self.vpn["vault_item"]
        # The configured backend's CLI: rbw has no in-process code(), and needs no
        # open Vault for this either, so its path must not depend on opening one.
        cli = "rbw" if os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND).lower() == "rbw" \
            else "litebw"
        if cli != "rbw":
            # In-process: a new litebw process re-derives the sealed master every
            # time (about 150 MiB), on every retry. `_vault` stays open on failure
            # for the same reason; _refresh_vault renews a stale copy.
            try:
                backend_code = getattr(self._open_vault().backend, "code", None)
                if backend_code is not None:
                    return (backend_code(item) or "").strip()
            except VaultError as e:
                self.log(f"WARNING OTP fetch from vault item '{item}' failed: {e}")
                return ""
            except Exception as e:                      # noqa: BLE001
                # By type only: an unparseable-secret error may quote the TOTP secret.
                self.log(f"WARNING OTP fetch from vault item '{item}' failed "
                         f"({type(e).__name__}); check its TOTP secret")
                return ""
        try:
            r = subprocess.run([cli, "code", item], capture_output=True,
                               text=True, errors="replace",
                               stdin=subprocess.DEVNULL, timeout=30)
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
    def _on_child_line(self, line: str):
        line = line.rstrip("\r\n")
        if not line.strip():
            return
        self.log(f"[{self.driver.binary}] {line}")
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

    def _reader(self, pipe):
        """Drain one attempt's child output. It must keep draining whatever a line
        does: a dead reader leaves the child blocked on a full pipe with the tunnel
        apparently up."""
        for line in iter(pipe.readline, ""):
            try:
                self._on_child_line(line)
            except Exception:                           # noqa: BLE001
                pass                # logging itself failed; nowhere to report it
        try:
            pipe.close()
        except (OSError, ValueError):
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

    def _scratch_dir(self) -> str:
        """This supervisor's private 0700 dir under soc-vpn. Keys and the mgmt
        socket live here rather than under a pid-scoped name because supervisors
        are threads: with one shared name, two OpenVPN entries would overwrite and
        delete each other's keys, and one's password could reach the other's
        openvpn. A directory also lets a WireGuard .conf keep the <iface>.conf
        name wg-quick requires while still being attributable to a pid for the
        orphan sweep."""
        d = self._soc_vpn_dir()
        scratch = os.path.join(d, f"vpn-{os.getpid()}-{self._instance}")
        try:
            os.makedirs(scratch, 0o700, exist_ok=True)
        except OSError:
            return d
        self._scratch = scratch
        return scratch

    def _drop_scratch(self):
        if self._scratch:
            try:
                os.rmdir(self._scratch)
                self._scratch = None
            except OSError:
                pass                    # still holds the other artifact

    def _parse_vpn_notes_kv(self, notes: str) -> dict:
        """Parse a vault Notes KEY=VALUE block for a fortinet/inode overlay. Blank
        lines and `#` comments are ignored. A key outside the allowlist or a value
        failing config's argv guards is refused loudly and the panels.yaml value
        stands: load-time validation never saw these, and a note holding
        `gateway=--pppd-plugin=...` must not reach a root process's argv. Values
        are not echoed, since a note may hold secrets."""
        out = {}
        for ln in (notes or "").splitlines():
            s = ln.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, _, v = s.partition("=")
            k = k.strip().lower()
            v = v.strip().strip('"').strip("'")
            if k not in self._VAULT_VPN_NOTES_KEYS:
                self.log(f"WARNING vault VPN notes: unknown key {k!r} ignored "
                         f"(allowed: {sorted(self._VAULT_VPN_NOTES_KEYS)})")
                continue
            try:
                if k == "port":
                    out[k] = cfg._safe_port(v, k)
                elif k == "gateway":
                    out[k] = cfg._safe_host(v, k)
                elif k in self._VAULT_VPN_NOTES_BOOLS:
                    if v.lower() not in ("true", "yes", "1", "false", "no", "0"):
                        raise ValueError(f"{k} must be true or false")
                    out[k] = v.lower() in ("true", "yes", "1")
                else:
                    out[k] = cfg._safe_word(v, k)
            except ValueError:
                # Not the exception text: config's guards quote the value.
                self.log(f"WARNING vault VPN notes: invalid value for {k} refused")
        return out

    def _materialize_config(self) -> bool:
        """If vpn.config_from_vault, hydrate the VPN config from the vault item's
        Notes. The shape depends on the type:

          fortinet / inode    a KEY=VALUE block overlaid onto self.vpn in memory.
                              Never written to disk.
          openvpn / wireguard a whole .ovpn/.conf, written to a 0600 file in this
                              supervisor's 0700 dir; vpn['config'] then points at it.

        Returns False if it cannot be read/written."""
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
            self.watchdog.ping()
            try:
                content = self._open_vault().notes(item)
                self._vault_retry.reset()
                break
            except VaultError as e:
                self._vault = None
                if self.stop_event.is_set() or time.monotonic() > deadline:
                    self.log(f"ERROR reading VPN config from vault item "
                             f"'{item}': {e}")
                    return False
                delay = self._vault_retry.next()
                self.log(f"vault not ready for VPN config ({e}); "
                         f"retrying in {delay:.0f}s")
                sd_notify("STATUS=waiting for the vault (VPN config)")
                self._sleep(delay)
        if not content.strip():
            self.log(f"ERROR vault item '{item}' has no Notes content (the VPN config)")
            return False
        if self.driver.kind in ("fortinet", "inode"):
            kv = self._parse_vpn_notes_kv(content)
            if not kv:
                self.log(f"ERROR vault item '{item}' Notes had no usable KEY=VALUE "
                         f"lines for this {self.driver.kind} VPN")
                return False
            self.vpn.update(kv)
            self.log(f"overlaid VPN field(s) {sorted(kv)} from vault item '{item}'")
            if kv.get("insecure"):
                self.log(f"WARNING vault item '{item}' turns OFF gateway certificate "
                         f"verification (insecure=true)")
            return True
        d = self._scratch_dir()
        if self.driver.kind == "wireguard":
            iface = os.path.basename(str(self.vpn.get("config") or "wg0"))
            if iface.endswith(".conf"):
                iface = iface[:-5]
            path = os.path.join(d, f"{iface or 'wg0'}.conf")
        else:
            path = os.path.join(d, f"openvpn-{self._instance}.ovpn")
        self._materialized = path       # tracked first: a torn write still holds keys
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content if content.endswith("\n") else content + "\n")
        except OSError as e:
            self.log(f"ERROR writing VPN config: {e}")
            self._cleanup_materialized()
            return False
        self.vpn["config"] = path
        self.log(f"materialized VPN config from vault item '{item}' "
                 f"-> {path} (0600)")
        return True

    def _cleanup_materialized(self):
        # Idempotent: a second call, or a file already gone, is a no-op.
        if self._materialized:
            try:
                os.unlink(self._materialized)
            except OSError:
                pass
            self._materialized = None
            self._drop_scratch()

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
            self._drop_scratch()

    def _retire_attempt_threads(self):
        """End the finished attempt's reader and mgmt threads and clear what it
        left behind, so a fast connect/drop flap can't accumulate threads, pipe
        fds or tunnel helpers, and a late line from an old attempt can't land in
        the next attempt's state. Runs once per attempt: the pgid is only safe to
        signal right after the child exits. Bounded: the threads are told to
        stop, never closed under, so this cannot block on a held pipe."""
        done, self._attempt_done = self._attempt_done, None
        if done is None:
            return
        done.set()
        child, reader = self.child, self._reader_thread
        self._reap_group(child)
        for attr in ("_reader_thread", "_mgmt_thread"):
            t = getattr(self, attr, None)
            if t is not None and t.is_alive():
                t.join(timeout=2.0)
                if t.is_alive():
                    self.log(f"WARNING {attr[1:]} still running after its attempt ended")
            setattr(self, attr, None)
        # The reader closes its own pipe, so this is only for one that never
        # started. Never close under a live reader: that is the blocking close.
        stdout = child.stdout if child is not None else None
        if stdout and not stdout.closed and not (reader and reader.is_alive()):
            try:
                stdout.close()
            except (OSError, ValueError):
                pass

    # -- OpenVPN management socket (secure user/pass injection) -----------------
    def _mgmt_path(self) -> str:
        # The OpenVPN password transits this socket, so keep it in an owner-only
        # 0700 directory — no other local user can reach it.
        return os.path.join(self._scratch_dir(), f"openvpn-{self._instance}.sock")

    def _sweep_orphan_mgmt(self, d: str):
        """Best-effort: clear what a crashed/SIGKILLed supervisor left, including
        its materialized keys. No finally runs on SIGKILL, on OOM or when systemd's
        watchdog aborts us, so this is the only cleanup those exits get. Everything
        here is pid-scoped, so an entry whose <pid> is not us and is not a live
        process is by definition an orphan. Pure stat/unlink — cannot hang;
        swallow OSError like the other best-effort cleanups."""
        try:
            entries = os.listdir(d)
        except OSError:
            return
        for fn in entries:
            m = _ORPHAN_RE.match(fn)
            if not m:
                continue
            pid = int(m.group(1) or m.group(2))
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, 0)
                continue                 # still alive — not ours to reap
            except ProcessLookupError:
                pass                     # dead pid: orphan
            except (OSError, OverflowError):
                continue                 # EPERM etc: leave it alone
            path = os.path.join(d, fn)
            try:
                if m.group(1):
                    os.unlink(path)
                else:
                    for inner in os.listdir(path):
                        os.unlink(os.path.join(path, inner))
                    os.rmdir(path)
            except OSError:
                pass

    def _openvpn_mgmt(self, sock_path: str, creds, child=None):
        """Answer OpenVPN's password query over its management socket, so the
        username/password never appears on argv or disk. `child` is the attempt
        this thread serves: its mgmt path is reused by the next attempt, so a
        thread outliving its openvpn must stand down rather than connect to, or
        terminate, the attempt after it."""
        user, password = creds
        deadline = time.monotonic() + 30
        s = None

        def child_gone():
            return child is not None and child.poll() is not None

        while (time.monotonic() < deadline and not self.stop_event.is_set()
               and not child_gone()):
            attempt = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                attempt.connect(sock_path)
                s = attempt
                break
            except OSError:
                attempt.close()
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
            if self.stop_event.is_set() or child_gone():
                return
            self._mgmt_unreachable = True
            self._saw.add(EVENT_DOWN)
            self.log("ERROR could not reach the OpenVPN management socket — the "
                     "child started --management-hold and cannot authenticate; "
                     "check that openvpn created the socket (selinux/apparmor, "
                     "runtime dir perms). Terminating the held child and backing "
                     "off.")
            sd_notify("STATUS=OpenVPN management socket unreachable; backing off")
            self._terminate_child(child=child)
            return
        f = s.makefile("rw", encoding="utf-8", errors="replace")

        def send(line):
            # The only way onto the socket, so no line can skip the CR/LF strip.
            f.write(_mgmt_sanitize(line) + "\n")

        try:
            send("hold release")
            f.flush()
            for line in f:
                line = line.strip()
                if line.startswith(">PASSWORD:Need 'Auth'"):
                    send(f'username "Auth" {user}')
                    send(f'password "Auth" {password}')
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
        # Retire the previous attempt BEFORE clearing its state, so a late line
        # from it cannot land in this attempt.
        self._retire_attempt_threads()
        if self.child is not None and self.child.poll() is None:
            self._terminate_child()
            if self.child.poll() is None:
                # Two clients would fight over the same routes and tunnel device.
                raise OSError(errno.EBUSY, "previous child is still running")
        self._tunnel_up = False
        self._up_since = 0.0
        self._saw = set()
        self._mgmt_unreachable = False
        env = dict(os.environ)
        for key in _CHILD_ENV_DROP:     # up-scripts and pppd inherit this env
            env.pop(key, None)
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
        child = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, bufsize=0, env=env,
            start_new_session=True)     # its own group: see _signal_group
        self.child = child
        self._attempt_done = threading.Event()
        self._reader_thread = threading.Thread(
            target=self._reader, args=(_ChildOutput(child.stdout, self._attempt_done),),
            daemon=True)
        self._reader_thread.start()
        if mgmt and creds:
            self._mgmt_thread = threading.Thread(
                target=self._openvpn_mgmt, args=(mgmt, creds, child), daemon=True)
            self._mgmt_thread.start()

    def _looks_connected(self) -> bool:
        """Evidence of a live tunnel that does not rest on log classification, so
        a client whose wording changed is not killed for never saying 'up'."""
        probe = (self.vpn.get("ready_probe") or "").strip()
        if probe:
            return probe_tcp(probe)
        return vpnstatus._iface_up(vpnstatus._expected_iface(self.vpn))

    def _watch_child(self):
        """Wait for the child to exit; meanwhile heartbeat + health-check."""
        connect_by = (time.monotonic() + self.connect_timeout
                      if self.connect_timeout else None)
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
            if connect_by and not self._tunnel_up and time.monotonic() >= connect_by:
                # Health checks only run once UP, so a child hung before that
                # (gateway stalls after accept, openvpn asking for a passphrase we
                # cannot answer) would otherwise be waited on forever.
                connect_by = None
                if not self._looks_connected():
                    self.log(f"no tunnel after {self.connect_timeout:.0f}s; "
                             f"restarting {self.driver.binary}")
                    sd_notify("STATUS=connect timed out; reconnecting")
                    self._terminate_child()
                    break
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
            self.log("DRY RUN — would run: " + " ".join(_redact_argv(cmd)))
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
        """Top-level supervise entry. Secrets, the child and its threads are
        cleaned on every exit path, then an unexpected exception propagates:
        VpnManager._supervised_run owns recovery and relaunches with a backoff.
        This used to fall into idle() instead, which left the VPN dead while the
        unit looked healthy and the watchdog stayed fed, forever."""
        if self.driver.is_interface:
            return self._run_interface()
        return self._run_process()

    def _await_config(self):
        """Materialize the vault-held config, retrying on the slow path until it
        works or we are stopped. A vault that outlasts SOC_READY_TIMEOUT, or an
        item an operator has yet to fix, must heal by itself: nobody is there to
        restart the service. Returning to idle() here made that outage permanent."""
        while not self.stop_event.is_set():
            if self._materialize_config():
                return
            self._cleanup_materialized()    # e.g. a failed catch-all rewrite
            sd_notify("STATUS=could not load VPN config from the vault; retrying")
            self._sleep(self._slow_retry)

    def _teardown_process(self):
        """Runs on every exit path of a process driver. Key material goes first:
        removing it cannot hang, while a stuck child can use up all of systemd's
        stop timeout. Nothing here needs the file once we are tearing down."""
        for step in (self._cleanup_materialized, self._cleanup_mgmt,
                     self._terminate_child, self._retire_attempt_threads):
            try:
                step()
            except Exception as e:                      # noqa: BLE001
                self.log(f"ERROR during teardown ({step.__name__}): {e!r}")

    def _run_process(self) -> int:
        timeout = cfg.env_float("SOC_READY_TIMEOUT", 120.0, lo=0.0, hi=3600.0)
        needs = self.driver.needs_creds(self.vpn)

        # dry-run is a config check — it must work even without the binary present
        if os.environ.get("SOC_VPN_DRY_RUN") == "1":
            # A vault Notes overlay stays in memory and may hold the gateway the
            # command needs. A .ovpn would put keys on disk just for a check.
            if (self.driver.kind in ("fortinet", "inode")
                    and not self._materialize_config()):
                self.log("DRY RUN — could not load the VPN config from the vault")
                return 0
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

        self._sweep_orphan_mgmt(self._soc_vpn_dir())
        # From here on a 0600 .ovpn (private keys) may sit in the runtime dir.
        try:
            self._await_config()
            return self._run_loop()
        finally:
            self._teardown_process()

    def _run_loop(self) -> int:
        target = self._target()
        timeout = cfg.env_float("SOC_READY_TIMEOUT", 120.0, lo=0.0, hi=3600.0)
        needs = self.driver.needs_creds(self.vpn)
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
                    self._sleep(self._slow_retry)
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
                self._sleep(self._slow_retry)
                self._refresh_vault()       # a secret added since our last sync
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
                self._refresh_vault()       # the fix may be a rotated secret
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
                # Only a tunnel that outlived the backoff ceiling was a real
                # connection: reset so the next drop retries fast. Anything shorter
                # is a flap, and the backoff keeps climbing toward
                # SOC_VPN_BACKOFF_MAX instead of looping near the floor.
                if self._up_since and (time.monotonic() - self._up_since) >= self.stable_after:
                    self.backoff.reset()
                delay = self.backoff.next()
                why = "connection closed" if EVENT_DOWN in self._saw else \
                      f"{self.driver.binary} exited ({rc})"
                self.log(f"{why}; reconnecting in {delay:.0f}s")
                sd_notify(f"STATUS=disconnected; reconnecting in {delay:.0f}s")
                self._sleep(delay)

        self._terminate_child()
        self.log("stopped")
        sd_notify("STATUS=stopped")
        return 0

    # -- the loop (interface drivers: wireguard) -------------------------------
    def _run_oneshot(self, cmd):
        self.watchdog.ping()            # each step may legitimately take 60s
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                               stdin=subprocess.DEVNULL, timeout=60)
            return r.returncode, (r.stdout + r.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            return 1, str(e)
        finally:
            self.watchdog.ping()

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
        if os.environ.get("SOC_VPN_DRY_RUN") == "1":
            self.log("DRY RUN — would run: " + " ".join(self.driver.up_cmd(self.vpn)))
            return 0
        if not shutil.which(self.driver.binary):
            self.log(f"FATAL: {self.driver.binary} not found — install "
                     f"wireguard-tools and restart the VPN service")
            sd_notify("STATUS=wg-quick is not installed")
            return self.idle()
        self._sweep_orphan_mgmt(self._soc_vpn_dir())
        # A materialized .conf holds a private key. Guarantee teardown on EVERY
        # exit path so a crash can't leave the key on disk, or the interface and
        # its routes installed for the next process to trip over. `down` first:
        # wg-quick reads the .conf to take the interface down.
        try:
            self._await_config()            # may rewrite vpn['config']
            return self._run_interface_loop()
        finally:
            try:
                self._run_oneshot(self.driver.down_cmd(self.vpn))
            finally:
                self._cleanup_materialized()

    def _run_interface_loop(self) -> int:
        probe = (self.vpn.get("ready_probe") or "").strip()
        interval = int(self.vpn.get("health_check_interval", 0) or 0) or 30
        threshold = int(self.vpn.get("health_check_failures", 3) or 3)
        target = cfg.wireguard_target(self.vpn)
        iface = self.driver.iface(self.vpn)
        tick = min(_TICK, self.watchdog.interval or _TICK)

        first = True
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
                        # Not at `wg-quick up`: that succeeds without ever reaching
                        # the peer, so it proves nothing about the tunnel.
                        self.backoff.reset()
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
                self.stop_event.wait(min(tick, max(0.0, next_check - time.monotonic())))
            if self.stop_event.is_set():
                break
            d = self.backoff.next()
            self.log(f"reconnecting WireGuard in {d:.0f}s")
            self._sleep(d)
        self.log("stopped")
        sd_notify("STATUS=stopped")
        return 0

    def _sleep(self, seconds: float):
        """Interruptible sleep that keeps feeding the systemd watchdog."""
        deadline = time.monotonic() + seconds
        tick = min(_TICK, self.watchdog.interval or _TICK)
        while not self.stop_event.is_set() and time.monotonic() < deadline:
            self.watchdog.ping()
            self.stop_event.wait(min(tick, max(0.0, deadline - time.monotonic())))

    def idle(self) -> int:
        """Stay alive without churning systemd restarts (disabled/unfixable VPN).
        The reason was already logged + put in STATUS. Reserved for what a restart
        cannot fix: anything that can heal retries on a slow path instead."""
        wait = min(60.0, self.watchdog.interval or 60.0)
        while not self.stop_event.is_set():
            self.watchdog.ping()
            self.stop_event.wait(wait)
        return 0


# --- litebw bootstrap (root's first run) ---------------------------------------
def ensure_litebw_session(log, on_step=lambda: None):
    """Idempotently point root's litebw at the kiosk vault and register the
    device, so the unattended `litebw unlock` inside Vault.open() can succeed.
    The master password is supplied non-interactively by the pinentry in
    $SOC_PINENTRY. litebw is the default; the rbw backend reuses this flow
    against the rbw CLI (the two share a config layout).

    Runs after READY=1, so systemd's watchdog is already armed: `on_step` is
    called between CLI calls, whose worst case (150s) is past WatchdogSec."""
    cli = "rbw" if os.environ.get("SOC_VAULT_BACKEND", cfg.DEFAULT_VAULT_BACKEND).lower() == "rbw" \
        else "litebw"
    for key, val in (("email", os.environ.get("SOC_VAULT_EMAIL", "")),
                     ("base_url", os.environ.get("SOC_VAULT_URL", "")),
                     ("pinentry", os.environ.get("SOC_PINENTRY", ""))):
        if val:
            on_step()
            subprocess.run([cli, "config", "set", key, val],
                           stdin=subprocess.DEVNULL, timeout=30)
    on_step()
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
    # With config_from_vault the gateway may arrive in the vault Notes overlay.
    return (
        (kind in ("fortinet", "inode") and not vpn.get("vault_item"))
        or (kind in ("fortinet", "inode") and not from_vault and not vpn.get("gateway"))
        or (kind in ("openvpn", "wireguard") and not from_vault and not vpn.get("config"))
        or (kind in ("openvpn", "wireguard") and from_vault and not vpn.get("vault_item")))


def _disable_core_dumps(log):
    """systemd's watchdog ends a wedged unit with SIGABRT, which would have
    systemd-coredump write this process's memory, decrypted vault credentials
    included, to disk. Inherited by the VPN children, whose env holds the password."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError) as e:
        log(f"WARNING could not disable core dumps: {e}")


def _supervise(mgr, stop, watchdog, log):
    """The unit's single WATCHDOG=1 source. Pets systemd only while every
    supervisor is making progress: threads cannot be killed from inside the
    process, so withholding the ping is the only way a wedged one gets recovered,
    by restarting the unit. Runs until `stop` is set.

    The ping and the STATUS poll run on separate clocks. STATUS only feeds
    `systemctl status` (the wall polls for itself), and each poll is a TCP connect
    per ready_probe, so it does not need the heartbeat's cadence."""
    from . import vpnmanager

    every = cfg.env_float("SOC_VPN_STATUS_INTERVAL", 30.0, lo=5.0, hi=3600.0)
    wait = min(_TICK, watchdog.interval or _TICK)
    last_status = ""
    reported = []
    next_status = 0.0

    def pet():
        if not mgr.stalled():
            watchdog.ping()

    while not stop.is_set():
        stalled = mgr.stalled()
        if stalled != reported:
            reported = stalled
            if stalled:
                log(f"ERROR no progress from VPN supervisor(s): {', '.join(stalled)}"
                    f" — withholding the watchdog so systemd restarts the unit")
                sd_notify(f"STATUS=wedged: {', '.join(stalled)}")
                last_status = ""
            else:
                log("all VPN supervisors are making progress again")
        if not stalled:
            watchdog.ping()
        if time.monotonic() >= next_status:
            # states() may TCP-probe each ready_probe (small bounded per-probe).
            # Pet BETWEEN probes as well, so no batch size can starve the heartbeat
            # and self-kill the unit, while still honouring a stall.
            states = mgr.states(on_each=pet)
            next_status = time.monotonic() + every
            agg = vpnmanager.aggregate_state(states)
            status = (f"STATUS={agg}: "
                      + ", ".join(f"{n}={s}" for n, s in states.items()))
            if status != last_status and not stalled:
                sd_notify(status)
                last_status = status
        stop.wait(wait)


def main() -> int:
    """Entry point used by scripts/forti-vpn-connect.py (forti-vpn.service).

    Single unit, N supervisors: this reads conf.vpns (the authoritative list —
    a legacy `vpn:{}` is normalized to a one-entry list, so the single-VPN case
    is byte-for-byte identical behaviour) and fans it out to a VpnManager that
    runs one independent supervisor thread per enabled entry. The unit stays a
    SINGLE journald stream tagged [vpn:<name>] per line.

    The forti-vpn@<name> template sets SOC_VPN_NAME: that instance runs only the
    named entry, while the routing policy is still decided across the whole list."""
    from . import vpnmanager

    def log(msg):
        try:
            print(f"[forti-vpn] {msg}", file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass                # a lost journal stream must not take a tunnel down

    _disable_core_dumps(log)

    # Tell systemd we are up immediately: the *service* (the manager) is ready
    # even while the tunnels are still connecting — tunnel state is surfaced via
    # STATUS=, and VPN-side consumers gate on each vpn.ready_probe.
    sd_notify("READY=1\nSTATUS=starting")
    watchdog = SdWatchdog()     # armed by READY=1, so it covers the setup below too

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
    for idx, vpn in enumerate(enabled):
        name = vpnstatus.vpn_name(vpn, idx)
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
            ensure_litebw_session(log, on_step=watchdog.ping)
        except Exception as e:  # noqa: BLE001 — best effort; Vault.open() is the gate
            log(f"litebw session setup warning: {e}")

    wanted = (os.environ.get("SOC_VPN_NAME") or "").strip()
    mgr = vpnmanager.VpnManager(runnable, pinentry, log=log, only=wanted)
    if wanted and not mgr.count:
        log(f"FATAL: no runnable VPN named {wanted!r} in config")
        sd_notify(f"STATUS=no VPN named {wanted}")
        idler = Supervisor({}, "")
        idler.install_signal_handlers()
        return idler.idle()
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

    _supervise(mgr, stop, watchdog, log)

    mgr.stop()
    log("all VPNs stopped")
    sd_notify("STATUS=stopped")
    return 0
