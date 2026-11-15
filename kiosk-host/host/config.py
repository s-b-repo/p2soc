"""
Configuration loading for the SOC kiosk host.

Reads config/panels.yaml (path from $SOC_PANELS_FILE), validates it, normalises
each panel, derives the effective URL (direct vs. tunnel) and the on-screen
geometry of each grid cell. Pure data — no GTK / no I/O beyond reading the YAML.

Validation is collect-everything: a broken file raises ConfigError whose message
lists *every* problem at once (file, panel, key), so one edit round fixes all.
Unknown keys are not fatal but are reported in Config.warnings — the host logs
them, which catches typos like `vault_iten:` before they bite at 3 AM.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

import yaml


def _env_num(name, default, cast, lo, hi):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = cast(raw.strip())
    except (TypeError, ValueError):
        sys.stderr.write(f"[soc-kiosk] {name}={raw!r} is not a valid number; "
                         f"using {default}\n")
        return default
    if lo is not None and v < lo:
        v = lo
    if hi is not None and v > hi:
        v = hi
    return v


def env_int(name: str, default: int, *, lo: int = None, hi: int = None) -> int:
    """os.environ[name] as an int, clamped to [lo, hi]; on a missing/garbage
    value, warn and fall back to default. A typo'd tunable must never crash the
    wall at boot."""
    return _env_num(name, default, int, lo, hi)


def env_float(name: str, default: float, *, lo: float = None, hi: float = None) -> float:
    """os.environ[name] as a float, clamped to [lo, hi]; missing/garbage -> default."""
    return _env_num(name, default, float, lo, hi)


def env_bool(name: str, default: bool) -> bool:
    """os.environ[name] as a bool. '0'/'false'/'no'/'off' (any case) -> False,
    '1'/'true'/'yes'/'on' -> True; missing/garbage -> default. Used for the
    security master toggles (SOC_NAV_ALLOWLIST / SOC_BLOCK_TRACKERS) — a typo'd
    value must never crash the wall, it falls back to the SAFE default."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    sys.stderr.write(f"[soc-kiosk] {name}={raw!r} is not a boolean; "
                     f"using {default}\n")
    return default


# The vault backend selected when $SOC_VAULT_BACKEND is unset. The pure-Python
# litebw client is the production default (no Rust toolchain on the 1 GB Pi);
# 'native' is its alias and 'rbw' stays selectable. Callers re-derive the name
# from the environment in several places — share this so they cannot drift.
DEFAULT_VAULT_BACKEND = "litebw"


class ConfigError(Exception):
    """panels.yaml is invalid. The message lists every problem found."""


VALID_ENGINES = {"webkit", "chromium"}
VALID_MODES = {"direct", "tunnel"}
VALID_LAYOUTS = {"auto", "windows", "single"}
VALID_KEEPALIVE = {"reload", "click", "xhr", "none"}
VALID_URL_SCHEMES = ("http", "https")
VALID_SCHEMES = set(VALID_URL_SCHEMES)
VALID_PROXY_SCHEMES = {"http", "https", "socks", "socks4", "socks5"}
VALID_VPN_TYPES = {"fortinet", "openvpn", "wireguard", "inode"}
# ssh StrictHostKeyChecking values an operator may select (SEC-6). 'no' is
# deliberately absent; see host_key_checking().
VALID_HOST_KEY_CHECKING = ("yes", "accept-new")

# An upper bound on concurrently-supervised VPNs. N supervisors = N vault
# unseals + HTTPS syncs at boot on a 1 GB Pi; 8 is a generous-but-sane cap that
# turns "operator pasted 200 entries" into a clear error instead of a thrash.
MAX_VPNS = 8

# A VPN `name` is the identity key used everywhere downstream (supervisor key,
# log tag, pill row) and must stay a clean token so a future per-VPN systemd
# instance / journald grep cannot be tripped by spaces/slashes/control chars.
_VPN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# A panel id is substituted verbatim into Openbox/labwc rc.xml (as a window
# wm-class / title) by the WM-config generators, so keep it to characters that
# cannot break out of an XML attribute. \Z, not $: '$' also matches before a
# trailing newline, which would let "p1\n" through.
_PANEL_ID_RE = re.compile(r"^[A-Za-z0-9_-]+\Z")

# Same bound the on-screen config has always applied to the field.
MAX_TENANT_LEN = 100

_TOP_KEYS = {"display", "panels", "tunnel", "vpn", "vpns", "proxy", "security"}
_DISPLAY_KEYS = {"auto", "width", "height", "cols", "rows", "gap", "layout",
                 "fullscreen"}
_LOGIN_ZONE_KEYS = {"x_pct", "y_pct"}
_LOGIN_ZONES_KEYS = {"user", "pass", "submit"}
_PANEL_KEYS = {"id", "engine", "grid", "mode", "url", "tunnel", "path", "scheme",
               "vault_item", "selectors", "login_marker", "keepalive", "proxy",
               "title", "allow_insecure", "allow_media", "tenant", "login_zones",
               # renderer security/compat knobs (all optional, safe defaults):
               "persist", "user_agent", "allow", "block_trackers", "unblock",
               "insecure_tls"}
_SECURITY_KEYS = {"nav_allowlist", "allow", "block_trackers", "sso_allow"}
_PROXY_KEYS = {"enabled", "url", "vault_item", "ignore_hosts"}
_TUNNEL_PANEL_KEYS = {"local_port", "remote_host", "remote_port"}
_KEEPALIVE_KEYS = {"strategy", "intervalSec", "url", "target"}
_TUNNEL_KEYS = {"enabled", "jump_host", "identity", "extra_forwards",
                "host_key_checking", "known_hosts"}
_VPN_KEYS = {"name", "default_route",
             "enabled", "type", "config", "config_from_vault", "gateway", "port",
             "vault_item", "trusted_cert", "ca_file", "realm", "set_routes",
             "set_dns", "half_internet_routes", "persistent", "otp_from_vault",
             "ready_probe", "extra_args", "health_check_interval",
             "health_check_failures", "domain", "insecure", "interface",
             # iNode (H3C SSL VPN) — additional backend flags from h3csvpn cli.py
             "ead", "spa_key", "spa_aid", "spa_ports", "spa_knock_port",
             "split_tunnel", "client_cert", "client_key",
             "captcha_retries", "mac", "language"}

# Free-text VPN values that end up as their own argv token (or flag value), and
# so get the _safe_word treatment both at load and at connect time.
_VPN_ARGV_WORDS = ("realm", "domain", "trusted_cert", "ca_file", "client_cert",
                   "client_key", "mac", "language", "spa_key", "spa_aid",
                   "spa_ports")


# --------------------------------------------------------------------------- #
# Input guards. These are the single implementation shared by load-time
# validation, the VPN/tunnel argv builders and scripts/tunnel-args.py. The
# _safe_* family raises ValueError; the argv builders must re-check because a
# config_from_vault overlay can change a VPN entry after validation has run.
# --------------------------------------------------------------------------- #
def _has_ctrl(s: str) -> bool:
    """True if s holds a control char (incl. \\n / \\r / \\t / NUL / DEL)."""
    return any(ord(c) < 0x20 or ord(c) == 0x7f for c in s)


def _has_ctrl_or_space(s: str) -> bool:
    """True if s holds a control char or any whitespace. These enable argv
    smuggling, request splitting and log injection."""
    return _has_ctrl(s) or any(c.isspace() for c in s)


def valid_http_url(url, *, allow_empty: bool = True) -> bool:
    """RFC 3986-aware check for a panel URL. Stricter than a `startswith` scheme
    test: it parses the URL, requires an http/https scheme, a real host and a
    well-formed port, and rejects embedded credentials (`user:pass@host`, a
    confusion/leak vector) and any control or whitespace character (RFC 3986
    forbids them; they enable scheme-smuggling like `http://x\\njavascript:...`
    and request splitting). Empty is accepted only when `allow_empty` (an
    unconfigured tile)."""
    if url is None:
        return allow_empty
    s = str(url).strip()
    if s == "":
        return allow_empty
    if _has_ctrl_or_space(s):
        return False
    try:
        parts = urlsplit(s)
        parts.port                  # raises ValueError on a bad/out-of-range port
    except ValueError:
        return False
    if parts.scheme.lower() not in VALID_URL_SCHEMES or not parts.hostname:
        return False
    return "@" not in parts.netloc  # no userinfo (user:pass@host)


def _url_for_msg(url) -> str:
    """repr(url) with any userinfo masked. ConfigError text reaches the journal
    and the on-screen error card, so a rejected `user:pass@host` URL must not
    leak the password it was rejected for."""
    return repr(re.sub(r"[^/?#]*@", "***@", str(url), count=1))


def _safe_host(v, what: str = "host") -> str:
    """Validate a hostname/IP destined for a VPN/tunnel argv slot and return it
    stripped. Rejects values that are empty, carry whitespace/control chars, or
    begin with '-' (which a downstream binary would parse as an OPTION, not a
    host: classic argv option-injection). Raises ValueError on bad input."""
    s = str(v if v is not None else "").strip()
    if not s:
        raise ValueError(f"{what} is empty")
    if _has_ctrl_or_space(s):
        raise ValueError(f"{what} {s!r} contains whitespace/control characters")
    if s.startswith("-"):
        raise ValueError(f"{what} {s!r} may not begin with '-' (option injection)")
    return s


def _safe_port(v, what: str = "port") -> int:
    """Validate an int (or digit-string) port in 1..65535. Raises ValueError."""
    if isinstance(v, (bool, float)):        # int() would silently coerce these
        raise ValueError(f"{what} {v!r} is not an integer")
    try:
        p = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{what} {v!r} is not an integer")
    if not (0 < p < 65536):
        raise ValueError(f"{what} {p} is out of range 1..65535")
    return p


def _safe_word(v, what: str) -> str:
    """Validate a free-text argv token (realm / path / key). Rejects newlines
    (log/arg injection) and a leading '-' (option injection). Returns it
    stripped. The value is not echoed: some of these (spa_key) are sensitive.
    Raises ValueError on bad input."""
    s = str(v if v is not None else "")
    if "\n" in s or "\r" in s:
        raise ValueError(f"{what} must not contain newlines")
    s = s.strip()
    if s.startswith("-"):
        raise ValueError(f"{what} may not begin with '-' (option injection)")
    return s


def _safe_extra_args(v) -> list:
    """Validate the pass-through `extra_args` list. extra_args is operator-trusted
    (it lives in the same config file as the gateway), so a leading '-' is NOT
    rejected: those are legitimate flags ('-v', '--trace'). Items carrying
    newlines/NUL/control characters can never be a valid single argv token and
    would smuggle extra lines into logs, so they raise ValueError, as does a
    non-list (a bare string would otherwise be split into characters)."""
    if v is None or v == "":
        return []
    if not isinstance(v, (list, tuple)):
        raise ValueError(f"extra_args must be a list, got {type(v).__name__}")
    out = []
    for i, a in enumerate(v):
        s = str(a)
        if _has_ctrl(s):
            raise ValueError(f"extra_args item #{i + 1} contains control characters")
        out.append(s)
    return out


def _host_port(host: str, port: int) -> str:
    """Format 'host:port', bracketing a bare IPv6 literal per RFC 3986 so that
    'fd00::1' becomes '[fd00::1]:443' rather than an ambiguous 'fd00::1:443'.
    Already-bracketed hosts are left as-is.

    IPv6 is detected by >= 2 colons, which every literal has. A single colon
    means 'hostname:port', which must NOT be bracketed; _split_host_port removes
    such a port before a value ever gets here."""
    if host.startswith("["):
        return f"{host}:{port}"
    if host.count(":") >= 2:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _split_host_port(value: str, default_port: int):
    """Accept the operator-natural gateway shapes and return (host, port):
       'gw.example'        -> ('gw.example', default_port)
       'gw.example:443'    -> ('gw.example', 443)
       'fd00::1'           -> ('fd00::1', default_port)      # bare IPv6
       '[fd00::1]'         -> ('fd00::1', default_port)
       '[fd00::1]:443'     -> ('fd00::1', 443)
       'fd00::1:443'       -> ('fd00::1:443', default_port)  # ambiguous: IPv6
    An embedded port wins over default_port. Raises ValueError on malformed
    input ('host:', '[::1', '[::1]x') or a bad port."""
    s = str(value if value is not None else "").strip()
    if not s:
        raise ValueError("host is empty")
    if s.startswith("["):
        host, sep, rest = s[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError(f"malformed bracketed host {s!r}")
        has_port, port = bool(rest), rest[1:]
    elif s.count(":") == 1:             # 'host:port': a single colon is never IPv6
        host, _, port = s.partition(":")
        has_port = True
    else:                               # bare IPv6 (>= 2 colons) or a plain name
        host, port, has_port = s, "", False
    if not has_port:
        return host, _safe_port(default_port, "default port")
    if not port:
        raise ValueError(f"{s!r} has a ':' but no port")
    return host, _safe_port(port, "embedded port")


def _gateway_hostport(vpn: dict) -> str:
    """The canonical, bracketed 'host:port' for vpn.gateway + vpn.port (default
    443). Shared by the Fortinet and iNode argv builders."""
    host, port = _split_host_port(vpn.get("gateway"), vpn.get("port", 443) or 443)
    return _host_port(_safe_host(host, "vpn.gateway"), port)


def _safe_remote_host(v) -> str:
    """Validate a panel's tunnel.remote_host. On top of _safe_host, a single ':'
    means the operator wrote 'host:port' here instead of using remote_port; that
    builds a forward ssh rejects, which autossh would then retry forever."""
    s = _safe_host(v, "tunnel.remote_host")
    if s.count(":") == 1:
        raise ValueError(f"tunnel.remote_host {s!r} has an embedded ':port' "
                         f"(use a separate remote_port)")
    return s


def panel_forward(tn: dict) -> str:
    """The `ssh -L` spec for one mode: tunnel panel. Raises ValueError on a
    missing or malformed field."""
    tn = tn or {}
    lp = _safe_port(tn.get("local_port"), "tunnel.local_port")
    rp = _safe_port(tn.get("remote_port"), "tunnel.remote_port")
    return f"127.0.0.1:{lp}:{_host_port(_safe_remote_host(tn.get('remote_host')), rp)}"


# One host field of an `ssh -L` spec: a bracketed IPv6 literal, or a name/IPv4.
# ssh needs the brackets, so a bare IPv6 here is rejected rather than mis-split.
_FWD_HOST = r"(?:\[[0-9A-Za-z:.%_-]+\]|[A-Za-z0-9_.][A-Za-z0-9_.-]*)"
_FORWARD_RE = re.compile(rf"(?:{_FWD_HOST}:)?([0-9]+):{_FWD_HOST}:([0-9]+)")


def _safe_forward(entry) -> str:
    """Vet one tunnel.extra_forwards entry, returning it unchanged. It is spliced
    straight into ssh's -L argument, so it MUST be a plain [bindaddr:]port:host:
    port spec: never an option-looking token ('-D 1080') or anything with
    whitespace, which could smuggle in a second option. Raises ValueError."""
    s = str(entry if entry is not None else "")
    if _has_ctrl_or_space(s):
        raise ValueError(f"extra_forward contains whitespace/control characters: "
                         f"{entry!r}")
    m = _FORWARD_RE.fullmatch(s)
    if not m:
        raise ValueError(f"extra_forward must be [bindaddr:]port:host:port, "
                         f"got {entry!r}")
    for port in m.groups():
        _safe_port(port, "extra_forward port")
    return s


def host_key_checking(tunnel: dict) -> str:
    """The effective ssh StrictHostKeyChecking mode for the `tunnel:` section
    (SEC-6). Default is strict 'yes': a MITM at first connect must not be able
    to intercept the tunnel carrying the SOC dashboards and their logins.
    'accept-new' (TOFU) is an explicit opt-in. Anything else, including a typo,
    'no', or an unquoted YAML boolean, fails closed to 'yes'."""
    v = str((tunnel or {}).get("host_key_checking", "yes")).strip().lower()
    return v if v in VALID_HOST_KEY_CHECKING else "yes"


@dataclass
class KeepAlive:
    strategy: str = "none"          # reload | click | xhr | none
    intervalSec: int = 600
    url: Optional[str] = None
    target: Optional[str] = None


@dataclass
class Geometry:
    x: int
    y: int
    w: int
    h: int


@dataclass
class Panel:
    id: str
    engine: str                     # webkit | chromium
    grid: tuple                     # (col, row)
    mode: str                       # direct | tunnel
    vault_item: str
    selectors: dict
    login_marker: str
    keepalive: KeepAlive
    # one of these is set depending on mode:
    url: Optional[str] = None
    tunnel: Optional[dict] = None
    path: str = "/"
    scheme: str = "http"
    proxy: bool = True              # use the global proxy (when one is enabled)
    title: str = ""                 # display name (defaults to id)
    allow_insecure: bool = False    # accept self-signed TLS (trusted LAN only).
                                    # `insecure_tls:` in YAML is an accepted alias.
    allow_media: bool = False       # keep WebGL/WebAudio/<video> (off by default
                                    # to save RAM/GPU on 1 GB boards)
    tenant: str = ""                # optional tenant tag (multi-tenant grouping)
    # --- renderer security / compat knobs (consumed by webkit_panel/chromium_panel) ---
    persist: bool = True            # persist cookies + web storage on disk so a
                                    # session survives reload + wall restart
                                    # (False -> ephemeral, no on-disk session)
    user_agent: Optional[str] = None  # UA override (some dashboards gate on it)
    allow: tuple = ()               # extra allowed top-level nav domains
                                    # (wildcard '*.example.com' ok)
    block_trackers: bool = True     # apply the analytics/tracker blocklist
    unblock: tuple = ()             # tracker hosts this panel may load anyway
    # Click-zone fallback for auto-login: when the CSS selectors and the
    # text-pattern heuristic both fail, the injected JS falls back to
    # document.elementFromPoint(x_pct * vw, y_pct * vh). Captured by the on-screen
    # Calibrate mode; ratios survive a wall resize. Schema: optional "user",
    # "pass", "submit" keys, each {"x_pct": 0.0..1.0, "y_pct": 0.0..1.0}.
    login_zones: dict = field(default_factory=dict)
    geometry: Optional[Geometry] = None

    @property
    def wmclass(self) -> str:
        return f"soc-{self.id}"

    @property
    def display_name(self) -> str:
        return self.title or self.id

    @property
    def configured(self) -> bool:
        """A tunnel panel always resolves; a direct panel needs a url (which can
        be set at the glass via the on-screen config, so it may start empty)."""
        return self.mode == "tunnel" or bool(self.url)

    @property
    def effective_url(self) -> str:
        if self.mode == "tunnel":
            # Be defensive: live reconfigure / restored overrides can flip mode
            # or null out `tunnel`, and this is read on the GTK thread during
            # repaints — a KeyError here would take down the main loop.
            lp = (self.tunnel or {}).get("local_port")
            if lp is None:
                return ""
            return f"{self.scheme}://127.0.0.1:{lp}{self.path}"
        return self.url or ""

    @property
    def auto_login(self) -> bool:
        """Inject credentials only when a vault item is configured."""
        return bool(self.vault_item)

    @property
    def tunnel_local_port(self) -> Optional[int]:
        if self.mode != "tunnel":
            return None
        return (self.tunnel or {}).get("local_port")


@dataclass
class ProxyCfg:
    """Outbound HTTP(S)/SOCKS proxy for the panel browsers.

    Authentication is vault-backed: `vault_item` names a Vaultwarden login
    holding the proxy username/password. The credentials are fetched
    just-in-time and answered to the proxy's auth challenge in memory — they
    never appear in the proxy URL, on a command line, or on disk.
    """
    enabled: bool = False
    url: str = ""                   # scheme://host:port (no userinfo!)
    vault_item: str = ""            # optional: vault login with proxy creds
    ignore_hosts: tuple = ()        # extra hosts to bypass (glob ok)


def proxy_ignore_hosts(proxy: "ProxyCfg") -> list:
    """The effective bypass list: configured hosts + loopback (tunnels, CDP and
    the local Vaultwarden must never be routed through a corporate proxy)."""
    base = ["localhost", "127.0.0.1", "::1"]
    return list(proxy.ignore_hosts) + [h for h in base if h not in proxy.ignore_hosts]


@dataclass
class DisplayCfg:
    auto: bool = True
    width: int = 1920
    height: int = 1080
    cols: int = 2
    rows: int = 2
    gap: int = 0
    layout: str = "auto"            # auto | windows | single
    fullscreen: bool = True         # false -> windowed (lives on the desktop);
                                    # env SOC_WINDOWED=1 also forces windowed


@dataclass
class SecurityCfg:
    """Wall-wide renderer security defaults (optional top-level `security:` block).

    Every field defaults to the SAFE/ON value, so a config that omits the block
    behaves exactly as before. The env toggles SOC_NAV_ALLOWLIST /
    SOC_BLOCK_TRACKERS override nav_allowlist / block_trackers at boot.
    """
    nav_allowlist: bool = True      # gate top-level navigation to the allowlist
    allow: tuple = ()               # extra allowed domains added to every panel
    block_trackers: bool = True     # global default for the per-panel knob
    sso_allow: tuple = ()           # extra SSO/redirect domains on top of the
                                    # bundled security/allowlist-sso.txt


@dataclass
class Config:
    display: DisplayCfg
    panels: list = field(default_factory=list)
    tunnel: dict = field(default_factory=dict)
    # vpns is the authoritative LIST of independent VPNs (any supported type),
    # each a flat dict + a `name`/`default_route`. `vpn` is the back-compat
    # PRIMARY (vpns[0] if any, else {}) so downstream readers that still take a
    # single vpn dict keep working — see _normalize_vpns / _parse.
    vpns: list = field(default_factory=list)
    vpn: dict = field(default_factory=dict)
    proxy: ProxyCfg = field(default_factory=ProxyCfg)
    security: SecurityCfg = field(default_factory=SecurityCfg)
    warnings: list = field(default_factory=list)


def _keepalive(d: dict) -> KeepAlive:
    d = d or {}
    return KeepAlive(
        strategy=d.get("strategy", "none"),
        intervalSec=int(d.get("intervalSec", 600)),
        url=d.get("url"),
        target=d.get("target"),
    )


def openfortivpn_args(vpn: dict) -> list:
    """Build the **non-secret** openfortivpn argument list from the `vpn:` section.

    Returns the gateway and routing/DNS/cert flags only. The username, the
    password (supplied via --pinentry) and any OTP are appended at connect time
    by the VPN supervisor (host/fortivpn.py) — they are never produced here, so
    this list is safe to print/log. Returns [] when no gateway is configured.
    """
    vpn = vpn or {}
    gateway = vpn.get("gateway")
    if not gateway:
        return []
    args = [_gateway_hostport(vpn)]
    if vpn.get("trusted_cert"):
        args.append(f"--trusted-cert={vpn['trusted_cert']}")
    if vpn.get("ca_file"):
        args.append(f"--ca-file={vpn['ca_file']}")
    if vpn.get("realm"):
        args.append(f"--realm={_safe_word(vpn['realm'], 'vpn.realm')}")
    # Routing / DNS: emit explicit 0/1 so the gateway can't silently change them.
    if "set_routes" in vpn:
        args.append(f"--set-routes={1 if vpn['set_routes'] else 0}")
    if "set_dns" in vpn:
        args.append(f"--set-dns={1 if vpn['set_dns'] else 0}")
    if "half_internet_routes" in vpn:
        args.append(f"--half-internet-routes={1 if vpn['half_internet_routes'] else 0}")
    # --persistent is OPT-IN only: our supervisor (host/fortivpn.py) already owns
    # the reconnect policy (classified backoff, auth/cert lockout protection), so
    # we never emit it by default — that would layer openfortivpn's own in-process
    # reconnect on top of ours. Honour it only when the operator sets it explicitly.
    persistent = int(vpn.get("persistent", 0) or 0)
    if persistent > 0:
        args.append(f"--persistent={persistent}")
    args += _safe_extra_args(vpn.get("extra_args"))
    return args


def vpn_kind(vpn: dict) -> str:
    """The VPN backend: 'fortinet' (default), 'openvpn', 'wireguard', 'inode'."""
    t = str((vpn or {}).get("type", "fortinet") or "fortinet").lower()
    return t if t in VALID_VPN_TYPES else "fortinet"


def vpn_interface(vpn: dict) -> str:
    """An explicit tunnel interface-name override for status detection.

    openfortivpn/openvpn normally bring up ppp0/tun0, but a non-default
    setup (e.g. ppp_name in the PPP profile, or `dev tunN` in an .ovpn) can use
    another name. `vpn.interface` lets the on-wall indicator find it.
    Empty ('' / unset) keeps the per-type default — behaviour unchanged."""
    return str((vpn or {}).get("interface", "") or "").strip()


def openvpn_args(vpn: dict) -> list:
    """Non-secret OpenVPN argv (safe to log). The config file carries the server
    + certs; a username/password (when the server needs one) is injected over the
    management interface by the supervisor, never via argv/disk. Returns the
    flags after the `openvpn` binary."""
    vpn = vpn or {}
    config = vpn.get("config")
    if not config:
        return []
    args = ["--config", str(config)]
    # routing/DNS hints map onto OpenVPN where they have an equivalent
    if vpn.get("set_routes") is False:
        args += ["--route-nopull"]            # ignore server-pushed routes
    args += _safe_extra_args(vpn.get("extra_args"))
    return args


def wireguard_target(vpn: dict) -> str:
    """The wg-quick target: a .conf path, or a bare interface name resolved from
    /etc/wireguard/<name>.conf. Empty when not configured."""
    return str((vpn or {}).get("config", "") or "").strip()


def inode_gateway(vpn: dict) -> str:
    """'host:port' for the H3C iNode SSL-VPN gateway (default port 443), with an
    IPv6 host bracketed. '' when no gateway is configured. vpn.gateway may carry
    its own port ('gw.example:8443', '[fd00::1]:3000'), which wins over vpn.port."""
    vpn = vpn or {}
    if not str(vpn.get("gateway", "") or "").strip():
        return ""
    return _gateway_hostport(vpn)


def _bundled_inode_dir() -> str:
    """The iNode SSL-VPN client shipped with the wall (vendor/iNode-VPN-Client),
    under $SOC_ROOT (the Pi install) or the repo (dev)."""
    root = os.environ.get("SOC_ROOT") or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "vendor", "iNode-VPN-Client")


def inode_script(vpn: dict) -> str:
    """Resolve the connect script. vpn.config may be the iNode-VPN-Client dir or a
    direct svpn-connect.sh path; when unset, the BUNDLED client shipped with the
    wall (vendor/iNode-VPN-Client) is used."""
    base = str((vpn or {}).get("config", "") or "").strip() or _bundled_inode_dir()
    base = os.path.expanduser(base)
    return base if base.endswith(".sh") else os.path.join(base, "svpn-connect.sh")


def inode_extra_args(vpn: dict) -> list:
    """The NON-secret backend args after svpn-connect.sh's '--' separator: cert
    pin (vpn.trusted_cert) or --insecure, plus any vpn.extra_args. [] if none
    (the username + gateway are positional; the password travels via the child
    env $H3C_SVPN_PASSWORD, never argv)."""
    vpn = vpn or {}

    def word(key):
        return _safe_word(vpn.get(key) or "", f"vpn.{key}")

    tail = []
    pin = word("trusted_cert")
    if pin:
        tail += ["--pin-sha256", pin]
    elif vpn.get("insecure"):
        tail += ["--insecure"]

    cafile = word("ca_file")
    if cafile:
        tail += ["--cafile", cafile]
    cert = word("client_cert")
    key = word("client_key")
    if cert:
        tail += ["--client-cert", cert]
    if key:
        tail += ["--client-key", key]

    mac = word("mac")
    if mac:
        tail += ["--mac", mac]
    language = word("language")
    if language:
        tail += ["--language", language]

    captcha_retries = int(vpn.get("captcha_retries", 0) or 0)
    if captcha_retries > 0:
        tail += ["--captcha-retries", str(captcha_retries)]

    if vpn.get("ead"):
        tail += ["--ead"]
    if vpn.get("split_tunnel", True):
        tail += ["--split-tunnel"]

    spa_key = word("spa_key")
    if spa_key:
        tail += ["--spa-key", spa_key]
        aid = word("spa_aid")
        if aid:
            tail += ["--spa-aid", aid]
        ports = word("spa_ports")
        if ports:
            tail += ["--spa-ports", ports]
        knock = int(vpn.get("spa_knock_port", 0) or 0)
        if knock > 0:
            tail += ["--spa-knock-port", str(knock)]

    tail += _safe_extra_args(vpn.get("extra_args"))
    return ["--"] + tail if tail else []


def compute_geometry(disp: DisplayCfg, grid) -> Geometry:
    """Map a (col,row) grid cell to an on-screen rectangle."""
    col, row = grid
    # Cap the gap so the grid always fits: an unbounded gap from a config file or
    # vault note could otherwise drive the cell size to zero/negative, and a
    # non-positive window size crashes the WM/compositor. Leave >= 1px per cell.
    gap = max(0, disp.gap)
    if disp.cols > 1:
        gap = min(gap, (disp.width - disp.cols) // (disp.cols - 1))
    if disp.rows > 1:
        gap = min(gap, (disp.height - disp.rows) // (disp.rows - 1))
    gap = max(0, gap)
    cell_w = max(1, (disp.width - gap * (disp.cols - 1)) // disp.cols)
    cell_h = max(1, (disp.height - gap * (disp.rows - 1)) // disp.rows)
    x = col * (cell_w + gap)
    y = row * (cell_h + gap)
    return Geometry(x=x, y=y, w=cell_w, h=cell_h)


def resolve_layout(conf: "Config", backend: str) -> str:
    """Resolve display.layout for the running backend ('x11' | 'wayland').

    `auto` keeps the proven per-window path on X11 (Openbox places the windows)
    and prefers the single fullscreen grid window on Wayland — where clients
    cannot position their own windows — unless a Chromium panel needs its own
    OS window (then labwc window rules take over placement).
    """
    layout = conf.display.layout
    if layout != "auto":
        return layout
    if backend == "wayland" and all(p.engine == "webkit" for p in conf.panels):
        return "single"
    return "windows"


# --------------------------------------------------------------------------- #
# Validation helpers — append human messages to errs/warns, never raise inline.
# --------------------------------------------------------------------------- #
def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_cert_pin(cert: str) -> bool:
    """A FortiGate trusted-cert pin, openfortivpn-compatible: a SHA-256 (64 hex)
    or SHA-1 (40 hex) digest, case-insensitive. openfortivpn --trusted-cert
    accepts both, so we do too (SHA-256 is preferred — SHA-1 is for older
    gateways/digests)."""
    s = str(cert)
    return len(s) in (40, 64) and all(c in "0123456789abcdefABCDEF" for c in s)


# A hostname/IP for a VPN gateway: non-empty, no spaces or shell metacharacters,
# and shaped like an RFC-1123 hostname, an IPv4 dotted-quad, or an IPv6 literal
# (with optional %zone / [brackets]). Kept permissive enough for real gateways;
# the value is only ever passed as a single argv token, so this is an early,
# clear error — not a security boundary.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
_IPV4_RE = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
_IPV6_RE = re.compile(r"^[0-9A-Fa-f:]+(?:%[0-9A-Za-z._-]+)?$")


def _is_gateway_host(host: str) -> bool:
    """True if `host` is a plausible gateway hostname or IP address. Rejects
    empty strings, anything with whitespace, and shell/URL metacharacters."""
    h = str(host).strip()
    if not h or any(c.isspace() for c in h):
        return False
    if h.startswith("[") and h.endswith("]"):       # bracketed IPv6 literal
        h = h[1:-1]
    if _IPV4_RE.match(h) or _HOSTNAME_RE.match(h):
        return True
    return bool(h.count(":") >= 2 and _IPV6_RE.match(h))  # IPv6 has >= 2 colons


def _probe_ok(probe: str) -> bool:
    host, _, port = probe.rpartition(":")
    return bool(host) and port.isdigit() and 0 < int(port) < 65536


def _unknown_keys(d: dict, known: set, where: str, warns: list):
    for k in sorted(set(d) - known):
        warns.append(f"{where}: unknown key '{k}' (typo?) — it is ignored")


def _validate_domain_list(v, where: str, errs: list):
    """A list of non-empty domain strings (wildcard '*.d.com' ok). Empty list ok."""
    if not isinstance(v, list) or not all(
            isinstance(x, str) and x.strip() for x in v):
        errs.append(f"{where}: must be a list of non-empty domain strings, got {v!r}")


def _validate_security(sec, errs: list, warns: list):
    if not isinstance(sec, dict):
        errs.append("security: must be a mapping")
        return
    _unknown_keys(sec, _SECURITY_KEYS, "security", warns)
    for k in ("nav_allowlist", "block_trackers"):
        if k in sec and not isinstance(sec[k], bool):
            errs.append(f"security.{k}: must be true or false, got {sec[k]!r}")
    for k in ("allow", "sso_allow"):
        if k in sec:
            _validate_domain_list(sec[k], f"security.{k}", errs)


def _validate_display(d: dict, errs: list, warns: list):
    _unknown_keys(d, _DISPLAY_KEYS, "display", warns)
    for k in ("width", "height", "cols", "rows"):
        if k in d and (not _is_int(d[k]) or d[k] < 1):
            errs.append(f"display.{k}: must be a positive integer, got {d[k]!r}")
    if "gap" in d and (not _is_int(d["gap"]) or d["gap"] < 0):
        errs.append(f"display.gap: must be an integer >= 0, got {d['gap']!r}")
    layout = d.get("layout", "auto")
    if layout not in VALID_LAYOUTS:
        errs.append(f"display.layout: must be one of {sorted(VALID_LAYOUTS)}, got {layout!r}")
    if "fullscreen" in d and not isinstance(d["fullscreen"], bool):
        errs.append(f"display.fullscreen: must be true or false, got {d['fullscreen']!r}")


def _validate_login_zones(lz, where: str, errs: list, warns: list):
    """login_zones is a mapping of optional user/pass/submit click targets, each
    with x_pct + y_pct ratios in 0.0..1.0."""
    if not isinstance(lz, dict):
        errs.append(f"{where}: login_zones must be a mapping with optional "
                    f"'user', 'pass', 'submit' entries")
        return
    extra = set(lz) - _LOGIN_ZONES_KEYS
    if extra:
        errs.append(f"{where}: unknown login_zones key(s) "
                    f"{sorted(str(k) for k in extra)}; "
                    f"valid: {sorted(_LOGIN_ZONES_KEYS)}")
    for k, z in lz.items():
        if not isinstance(z, dict):
            errs.append(f"{where}: login_zones.{k} must be a mapping with "
                        f"x_pct + y_pct, got {z!r}")
            continue
        _unknown_keys(z, _LOGIN_ZONE_KEYS, f"{where}.login_zones.{k}", warns)
        missing = _LOGIN_ZONE_KEYS - set(z)
        if missing:
            errs.append(f"{where}: login_zones.{k} missing {sorted(missing)}")
            continue
        for axis in sorted(_LOGIN_ZONE_KEYS):
            v = z[axis]
            if isinstance(v, bool) or not isinstance(v, (int, float)) \
                    or not 0.0 <= float(v) <= 1.0:
                errs.append(f"{where}: login_zones.{k}.{axis} must be a "
                            f"0.0..1.0 ratio, got {v!r}")


def _validate_panel(i: int, p: dict, disp: DisplayCfg, errs: list, warns: list):
    pid = p.get("id") or f"#{i + 1}"
    where = f"panel {pid}"
    if not isinstance(p, dict):
        errs.append(f"panel #{i + 1}: must be a mapping")
        return
    _unknown_keys(p, _PANEL_KEYS, where, warns)

    if not p.get("id"):
        errs.append(f"panel #{i + 1}: missing required key 'id'")
    elif not _PANEL_ID_RE.match(str(p["id"])):
        errs.append(f"panel #{i + 1}: id {p['id']!r} must match [A-Za-z0-9_-]+ "
                    f"(it is substituted into the WM rc.xml: no spaces/markup)")

    engine = p.get("engine", "webkit")
    if engine not in VALID_ENGINES:
        errs.append(f"{where}: engine must be one of {sorted(VALID_ENGINES)}, got {engine!r}")

    grid = p.get("grid", [0, 0])
    if (not isinstance(grid, (list, tuple)) or len(grid) != 2
            or not all(_is_int(g) for g in grid)):
        errs.append(f"{where}: grid must be [col, row] integers, got {grid!r}")
    else:
        col, row = grid
        if not (0 <= col < disp.cols and 0 <= row < disp.rows):
            errs.append(f"{where}: grid [{col}, {row}] is outside the "
                        f"{disp.cols}x{disp.rows} grid (0-based)")

    mode = p.get("mode", "direct")
    if mode not in VALID_MODES:
        errs.append(f"{where}: mode must be one of {sorted(VALID_MODES)}, got {mode!r}")
    elif mode == "direct":
        url = p.get("url") or ""
        if not url:
            # allowed: an unconfigured tile, set later from the on-screen config
            warns.append(f"{where}: no url yet — shows a 'not configured' card "
                         f"until you set it (on-screen config, or edit panels.yaml)")
        elif not valid_http_url(url, allow_empty=False):
            errs.append(f"{where}: url must be a valid http:// or https:// URL with "
                        f"a host and no embedded credentials, got {_url_for_msg(url)}")
    else:  # tunnel
        t = p.get("tunnel")
        if not isinstance(t, dict):
            errs.append(f"{where}: mode 'tunnel' requires a 'tunnel:' mapping "
                        f"(local_port, remote_host, remote_port)")
        else:
            _unknown_keys(t, _TUNNEL_PANEL_KEYS, f"{where}.tunnel", warns)
            lp = t.get("local_port")
            if not _is_int(lp) or not (0 < lp < 65536):
                errs.append(f"{where}: tunnel.local_port must be a port number "
                            f"(1-65535), got {lp!r}")
            if not t.get("remote_host"):
                errs.append(f"{where}: tunnel.remote_host is required")
            else:
                try:
                    _safe_remote_host(t["remote_host"])
                except ValueError as e:
                    errs.append(f"{where}: {e}")
            if "remote_port" in t:
                rp = t["remote_port"]
                if not _is_int(rp) or not (0 < rp < 65536):
                    errs.append(f"{where}: tunnel.remote_port must be a port number "
                                f"(1-65535), got {rp!r}")
            # `path` is concatenated straight into effective_url for tunnel
            # panels (f"...127.0.0.1:{lp}{path}"); without a leading slash a value
            # like "@evil.com/dash" turns 127.0.0.1:lp into userinfo and
            # redirects the panel (and any injected creds) to an attacker host.
            # Requiring isinstance(str) also stops a non-str path crashing the
            # f-string. All real tunnel paths start with '/', so this is
            # behaviour-preserving.
            path = p.get("path", "/")
            if not (isinstance(path, str) and path.startswith("/")):
                errs.append(f"{where}: tunnel path must be a string starting "
                            f"with '/', got {path!r}")

    if p.get("scheme", "http") not in VALID_SCHEMES:
        errs.append(f"{where}: scheme must be http or https, got {p['scheme']!r}")

    if "proxy" in p and not isinstance(p["proxy"], bool):
        errs.append(f"{where}: proxy must be true or false (use the global proxy "
                    f"or bypass it), got {p['proxy']!r}")

    if "allow_insecure" in p and not isinstance(p["allow_insecure"], bool):
        errs.append(f"{where}: allow_insecure must be true or false, "
                    f"got {p['allow_insecure']!r}")

    if "allow_media" in p and not isinstance(p["allow_media"], bool):
        errs.append(f"{where}: allow_media must be true or false, "
                    f"got {p['allow_media']!r}")

    tenant = p.get("tenant")
    if tenant is not None and (not isinstance(tenant, str) or _has_ctrl(tenant)
                               or len(tenant.strip()) > MAX_TENANT_LEN):
        errs.append(f"{where}: tenant must be a single-line string of at most "
                    f"{MAX_TENANT_LEN} characters, got {tenant!r}")

    if p.get("login_zones") is not None:
        _validate_login_zones(p["login_zones"], where, errs, warns)

    # renderer security/compat knobs — all optional, validated mirroring the
    # allow_insecure/allow_media bool pattern (and list-of-str for domain lists).
    for k in ("persist", "block_trackers"):
        if k in p and not isinstance(p[k], bool):
            errs.append(f"{where}: {k} must be true or false, got {p[k]!r}")
    # insecure_tls is an ALIAS of allow_insecure — same bool check, same field.
    if "insecure_tls" in p and not isinstance(p["insecure_tls"], bool):
        errs.append(f"{where}: insecure_tls must be true or false, "
                    f"got {p['insecure_tls']!r}")
    if "insecure_tls" in p and "allow_insecure" in p \
            and p["insecure_tls"] != p["allow_insecure"]:
        errs.append(f"{where}: insecure_tls and allow_insecure both set to "
                    f"conflicting values (they are aliases — set only one)")
    for k in ("allow", "unblock"):
        if k in p:
            _validate_domain_list(p[k], f"{where}: {k}", errs)
    if "user_agent" in p and p["user_agent"] is not None \
            and not (isinstance(p["user_agent"], str) and p["user_agent"].strip()):
        errs.append(f"{where}: user_agent must be a non-empty string (or omit it), "
                    f"got {p['user_agent']!r}")

    # Auto-login is optional: a panel with a vault_item logs itself in (and then
    # needs selectors); a panel without one is display-only (the page just shows,
    # an operator logs in once if needed). This makes the wall usable as a pure
    # "show these URLs" board, configurable at the glass.
    sel = p.get("selectors")
    if p.get("vault_item"):
        if not isinstance(sel, dict):
            errs.append(f"{where}: has a vault_item but no 'selectors:' mapping "
                        f"(user, pass) needed to inject the login")
        else:
            for k in ("user", "pass"):
                if not sel.get(k):
                    errs.append(f"{where}: selectors.{k} is required for auto-login "
                                f"(CSS selector of the "
                                f"{'username' if k == 'user' else 'password'} field)")
            if not (p.get("login_marker") or sel.get("pass")):
                errs.append(f"{where}: needs a login_marker (or at least selectors.pass)")
    elif sel is not None and not isinstance(sel, dict):
        errs.append(f"{where}: selectors must be a mapping (or omit it for "
                    f"a display-only panel)")

    ka = p.get("keepalive") or {}
    if isinstance(ka, dict):
        _unknown_keys(ka, _KEEPALIVE_KEYS, f"{where}.keepalive", warns)
        strat = ka.get("strategy", "none")
        if strat not in VALID_KEEPALIVE:
            errs.append(f"{where}: keepalive.strategy must be one of "
                        f"{sorted(VALID_KEEPALIVE)}, got {strat!r}")
        if "intervalSec" in ka and (not _is_int(ka["intervalSec"]) or ka["intervalSec"] < 1):
            errs.append(f"{where}: keepalive.intervalSec must be a positive integer")
        if strat == "xhr" and not ka.get("url"):
            warns.append(f"{where}: keepalive strategy 'xhr' without a 'url' does nothing")
        if strat == "click" and not ka.get("target"):
            warns.append(f"{where}: keepalive strategy 'click' without a 'target' does nothing")
    else:
        errs.append(f"{where}: keepalive must be a mapping")


def _validate_cross(raw: dict, disp: DisplayCfg, panels_raw: list, errs: list, warns: list):
    ids = [p.get("id") for p in panels_raw if isinstance(p, dict) and p.get("id")]
    for dup in sorted({i for i in ids if ids.count(i) > 1}):
        errs.append(f"panel id '{dup}' is used more than once — ids must be unique")

    cells = {}
    for p in panels_raw:
        if isinstance(p, dict) and isinstance(p.get("grid"), (list, tuple)) \
                and len(p["grid"]) == 2:
            cells.setdefault(tuple(p["grid"]), []).append(p.get("id", "?"))
    for cell, who in sorted(cells.items()):
        if len(who) > 1:
            errs.append(f"panels {', '.join(who)} share grid cell {list(cell)} — "
                        f"each panel needs its own cell")

    ports = [p["tunnel"].get("local_port") for p in panels_raw
             if isinstance(p, dict) and isinstance(p.get("tunnel"), dict)]
    for dup in sorted({x for x in ports if x is not None and ports.count(x) > 1}):
        errs.append(f"tunnel local_port {dup} is used by more than one panel")

    if disp.layout == "single":
        chrom = [p.get("id", "?") for p in panels_raw
                 if isinstance(p, dict) and p.get("engine") == "chromium"]
        if chrom:
            errs.append(f"display.layout 'single' cannot host chromium panels "
                        f"({', '.join(chrom)}) — Chromium runs in its own OS window. "
                        f"Use engine: webkit for them, or layout: windows")

    tun = raw.get("tunnel") or {}
    if isinstance(tun, dict):
        _unknown_keys(tun, _TUNNEL_KEYS, "tunnel", warns)
        any_tunnel = any(isinstance(p, dict) and p.get("mode") == "tunnel"
                         for p in panels_raw)
        if any_tunnel and tun.get("enabled", True) and not tun.get("jump_host"):
            errs.append("tunnel: panels use mode 'tunnel' but tunnel.jump_host is not set")
        if any_tunnel and not tun.get("enabled", True):
            warns.append("tunnel: panels use mode 'tunnel' but tunnel.enabled is false — "
                         "their local ports will never come up")
        if tun.get("enabled", True):
            _validate_tunnel_argv(tun, errs, warns)
    else:
        errs.append("tunnel: must be a mapping")


def _validate_tunnel_argv(tun: dict, errs: list, warns: list):
    """Everything scripts/tunnel-args.py emits, one arg per line, for autossh. A
    bad extra_forward or host-key setting is a warning, not an error: tunnel-args
    refuses it (or fails closed), so the tunnel stays safe and the wall itself
    still comes up."""
    try:
        if tun.get("jump_host"):
            _safe_host(tun["jump_host"], "tunnel.jump_host")
    except ValueError as e:
        errs.append(str(e))
    for k in ("identity", "known_hosts"):
        try:
            _safe_word(tun.get(k), f"tunnel.{k}")
        except ValueError as e:
            errs.append(str(e))

    forwards = tun.get("extra_forwards") or []
    if not isinstance(forwards, list):
        errs.append(f"tunnel.extra_forwards: must be a list, got {forwards!r}")
        forwards = []
    for entry in forwards:
        try:
            _safe_forward(entry)
        except ValueError as e:
            warns.append(f"tunnel: {e} (the tunnel will refuse to start)")

    raw = tun.get("host_key_checking")
    effective = host_key_checking(tun)
    if raw is not None and str(raw).strip().lower() != effective:
        warns.append(f"tunnel.host_key_checking: {raw!r} is not one of "
                     f"{list(VALID_HOST_KEY_CHECKING)}; using strict 'yes'")
    elif effective != "yes" and not str(tun.get("known_hosts") or "").strip():
        warns.append(f"tunnel.host_key_checking: {effective!r} needs an explicit "
                     f"tunnel.known_hosts (the tunnel will refuse to start)")


def _validate_proxy(proxy: dict, errs: list, warns: list):
    if not isinstance(proxy, dict):
        errs.append("proxy: must be a mapping")
        return
    _unknown_keys(proxy, _PROXY_KEYS, "proxy", warns)
    if not proxy.get("enabled"):
        return
    url = (proxy.get("url") or "").strip()
    if not url:
        errs.append("proxy: enabled but 'url' is not set (want scheme://host:port)")
    elif _has_ctrl_or_space(url):
        # urlsplit silently drops \t \r \n, so check before parsing.
        errs.append("proxy.url: must not contain whitespace or control characters")
    else:
        try:
            u = urlsplit(url)
            scheme, host, port, userinfo = u.scheme, u.hostname, u.port, u.username
        except ValueError:
            scheme = host = port = userinfo = None
        if scheme not in VALID_PROXY_SCHEMES:
            errs.append(f"proxy.url: scheme must be one of "
                        f"{sorted(VALID_PROXY_SCHEMES)}, got {_url_for_msg(url)}")
        elif not host:
            errs.append(f"proxy.url: missing host, got {_url_for_msg(url)}")
        elif port is None:
            errs.append(f"proxy.url: missing port — want scheme://host:port, "
                        f"got {_url_for_msg(url)}")
        if userinfo is not None:
            errs.append("proxy.url: must not embed credentials (user:pass@...). "
                        "Put them in a vault login and set proxy.vault_item — "
                        "they are then injected in memory and never stored")
        if scheme in {"socks", "socks4", "socks5"} and proxy.get("vault_item"):
            warns.append("proxy: SOCKS with vault_item — browsers have little/no "
                         "SOCKS auth support; an authenticating proxy normally "
                         "needs to be http://")
    ih = proxy.get("ignore_hosts", [])
    if not isinstance(ih, list) or not all(isinstance(h, str) for h in ih):
        errs.append("proxy.ignore_hosts: must be a list of hostnames/patterns")


def _normalize_vpns(raw: dict, warns: list) -> list:
    """Resolve the `vpn:`/`vpns:` sections of a raw config into the authoritative
    LIST of VPN dicts, applying the mandatory backward-compat rules:

      * `vpns:` present (a list)  -> use it verbatim (a stray `vpn:` is ignored,
        with a warning if both are set, so the list form always wins);
      * else `vpn:` present (a dict) -> wrap it as a one-entry list [that_dict]
        (every shipped/legacy single-VPN config keeps working unchanged);
      * else (vpn-less config)    -> [] (stays vpn-less; no VPN service wanted).

    Each entry is left as its raw dict (validation happens in _validate_vpns) but
    is given a stable, non-empty `name`: an explicit name is kept; otherwise the
    first entry becomes "vpn" and the rest "vpn2".."vpnN" so a legacy config that
    never named its VPN still gains a deterministic identity key. Non-dict/garbage
    entries are passed through untouched for _validate_vpns to reject cleanly.
    """
    has_vpns = "vpns" in raw and raw.get("vpns") is not None
    has_vpn = "vpn" in raw and raw.get("vpn") is not None
    if has_vpns:
        if has_vpn:
            warns.append("config: both 'vpn:' and 'vpns:' are set — using 'vpns:' "
                         "(the list) and ignoring the stray 'vpn:' block")
        lst = raw.get("vpns")
        if not isinstance(lst, list):
            return lst  # not a list -> let _validate_vpns report it
        entries = [dict(v) if isinstance(v, dict) else v for v in lst]
    elif has_vpn:
        v = raw.get("vpn")
        entries = [dict(v) if isinstance(v, dict) else v]
    else:
        return []

    # Fill stable names for entries that lack one (legacy/unnamed). Keep explicit
    # names verbatim; duplicate-name detection is _validate_vpns' job.
    for i, e in enumerate(entries):
        if isinstance(e, dict):
            nm = str(e.get("name", "") or "").strip()
            if not nm:
                e["name"] = "vpn" if i == 0 else f"vpn{i + 1}"
    return entries


def _validate_vpns(vpns, errs: list, warns: list, legacy: bool = False):
    """Collect-everything validation of the whole vpns[] list: the cap, unique
    non-empty names, at-most-one default-route owner, plus every per-entry
    problem (never short-circuits). `legacy` means the list came from a single
    `vpn:` block, so messages say 'vpn.port', not "vpns[0] 'vpn'.port"."""
    if not isinstance(vpns, list):
        errs.append("vpns: must be a list of VPN mappings")
        return
    if len(vpns) > MAX_VPNS:
        errs.append(f"vpns: at most {MAX_VPNS} VPNs supported; got {len(vpns)} — "
                    f"remove some")

    names_seen: dict = {}      # lowercased name -> first label, for dup detection
    dup_names: list = []
    route_owners: list = []
    for i, vpn in enumerate(vpns):
        label = "vpn" if legacy else f"vpns[{i}]"
        if isinstance(vpn, dict):
            nm = str(vpn.get("name", "") or "").strip()
            if nm and not legacy:
                label = f"vpns[{i}] {nm!r}"
            if not nm:
                errs.append(f"{label}: 'name' is required and must be non-empty "
                            f"(it is the identity key used for the supervisor, "
                            f"status pill and logs)")
            elif not _VPN_NAME_RE.match(nm):
                errs.append(f"{label}: 'name' must start alphanumeric and contain "
                            f"only letters/digits/'.'/'_'/'-' (no spaces or "
                            f"slashes), got {nm!r}")
            else:
                key = nm.lower()
                if key in names_seen:
                    if nm not in dup_names:
                        dup_names.append(nm)
                else:
                    names_seen[key] = label
            if vpn.get("default_route"):
                route_owners.append(nm or label)
        _validate_vpn(vpn, errs, warns, label)

    if dup_names:
        errs.append("vpns: duplicate VPN name(s) — each must be unique: "
                    + ", ".join(repr(n) for n in dup_names))
    if len(route_owners) > 1:
        errs.append("vpns: at most one VPN may set 'default_route: true' (the "
                    "full-tunnel owner); these claim it: "
                    + ", ".join(str(n) for n in route_owners))


def _validate_gateway(vpn: dict, errs: list, label: str, kind: str):
    """Check vpn.gateway with the same parser the argv builders use, so load
    accepts exactly what connect can format: 'host', 'host:port', IPv6 with or
    without brackets. vpn.port has its own check, so only an embedded port is
    judged here. config_from_vault may supply the gateway from the vault item's
    Notes, in which case it is only checked (by _safe_host) at connect time."""
    gw = vpn.get("gateway")
    if not gw:
        if not vpn.get("config_from_vault"):
            errs.append(f"{label}: type '{kind}' but 'gateway' is not set (or set "
                        "config_from_vault: true to load it from the vault item)")
        return
    try:
        host, _ = _split_host_port(gw, 443)
        _safe_host(host, "gateway host")
    except ValueError as e:
        errs.append(f"{label}.gateway: not a valid hostname or IP address ({e}), "
                    f"got {gw!r}")
        return
    if not _is_gateway_host(host):
        errs.append(f"{label}.gateway: not a valid hostname or IP address, got {gw!r}")


def _validate_vpn_argv(vpn: dict, errs: list, label: str):
    """Report at load what the argv builders would otherwise only refuse at
    connect time, when the failure is a supervisor log line."""
    for k in _VPN_ARGV_WORDS:
        try:
            _safe_word(vpn.get(k), f"{label}.{k}")
        except ValueError as e:
            errs.append(str(e))
    try:
        _safe_extra_args(vpn.get("extra_args"))
    except ValueError as e:
        errs.append(f"{label}: {e}")


def _validate_vpn(vpn: dict, errs: list, warns: list, label: str = "vpn"):
    """Validate ONE VPN entry. `label` prefixes every message ('vpn' for a legacy
    single block, "vpns[i] 'name'" for a list entry) so list errors point at the
    right row. Per-type checks are unchanged; only the prefix differs."""
    if not isinstance(vpn, dict):
        errs.append(f"{label}: must be a mapping")
        return
    _unknown_keys(vpn, _VPN_KEYS, label, warns)
    if "default_route" in vpn and not isinstance(vpn["default_route"], bool):
        errs.append(f"{label}.default_route: must be true or false, got "
                    f"{vpn['default_route']!r}")
    if not vpn.get("enabled"):
        return

    kind = str(vpn.get("type", "fortinet") or "fortinet").lower()
    if kind not in VALID_VPN_TYPES:
        errs.append(f"{label}.type: must be one of {sorted(VALID_VPN_TYPES)}, got "
                    f"{vpn.get('type')!r}")
        kind = "fortinet"

    # shared numeric / probe checks (all types)
    for k in ("persistent", "health_check_interval", "health_check_failures"):
        if k in vpn and (not _is_int(vpn[k]) or vpn[k] < 0):
            errs.append(f"{label}.{k}: must be an integer >= 0, got {vpn[k]!r}")
    probe = (vpn.get("ready_probe") or "").strip()
    if probe and not _probe_ok(probe):
        errs.append(f"{label}.ready_probe: want 'host:port', got {probe!r}")
    # fortinet/openvpn health-check needs a TCP probe; wireguard can fall back to
    # the peer's last-handshake age, so a probe is optional there.
    if vpn.get("health_check_interval") and not probe and kind != "wireguard":
        errs.append(f"{label}.health_check_interval is set but {label}.ready_probe "
                    f"is empty — the health check needs a host:port to probe")
    _validate_vpn_argv(vpn, errs, label)

    if kind == "fortinet":
        _validate_gateway(vpn, errs, label, kind)
        if not vpn.get("vault_item"):
            errs.append(f"{label}: type 'fortinet' but 'vault_item' is not set "
                        "(the vault login holding the FortiGate credentials)")
        if "port" in vpn and (not _is_int(vpn["port"]) or not (0 < vpn["port"] < 65536)):
            errs.append(f"{label}.port: must be a port number (1-65535), got {vpn['port']!r}")
        cert = vpn.get("trusted_cert", "")
        if cert and not _is_cert_pin(cert):
            errs.append(f"{label}.trusted_cert: expected a sha256 (64-char) or sha1 "
                        f"(40-char) hex digest, got {len(str(cert))} chars")
        if not cert and not vpn.get("ca_file"):
            warns.append(f"{label}: no trusted_cert / ca_file pinned — the connection "
                         "relies on system CAs; if the gateway uses a self-signed "
                         "cert the VPN will refuse to connect (see "
                         "docs/CONFIGURATION.md to pin it)")
    elif kind == "openvpn":
        from_vault = bool(vpn.get("config_from_vault"))
        if from_vault and not vpn.get("vault_item"):
            errs.append(f"{label}: openvpn with config_from_vault needs 'vault_item' "
                        "(its Notes hold the .ovpn profile)")
        elif not from_vault and not vpn.get("config"):
            errs.append(f"{label}: type 'openvpn' requires 'config' (path to the .ovpn "
                        "profile), or config_from_vault: true")
        if not from_vault and not vpn.get("vault_item"):
            warns.append(f"{label}: openvpn with no vault_item — assuming certificate-only "
                         "auth (the .ovpn must carry the client cert/key). Set "
                         "vault_item for a username/password login.")
    elif kind == "wireguard":
        from_vault = bool(vpn.get("config_from_vault"))
        if from_vault and not vpn.get("vault_item"):
            errs.append(f"{label}: wireguard with config_from_vault needs 'vault_item' "
                        "(its Notes hold the .conf — keys included)")
        elif not from_vault and not vpn.get("config"):
            errs.append(f"{label}: type 'wireguard' requires 'config' (a .conf path or an "
                        "interface name under /etc/wireguard), or config_from_vault: true")
        if vpn.get("vault_item") and not from_vault:
            warns.append(f"{label}: wireguard ignores vault_item unless config_from_vault "
                         "is set — otherwise its keys live in the .conf file (0600)")
    elif kind == "inode":
        _validate_gateway(vpn, errs, label, kind)
        if not vpn.get("vault_item"):
            errs.append(f"{label}: type 'inode' but 'vault_item' is not set (the vault "
                        "login holding the SSL-VPN username + password)")
        if "port" in vpn and (not _is_int(vpn["port"]) or not (0 < vpn["port"] < 65536)):
            errs.append(f"{label}.port: must be a port number (1-65535), got {vpn['port']!r}")
        if "insecure" in vpn and not isinstance(vpn["insecure"], bool):
            errs.append(f"{label}.insecure: must be true or false, got {vpn['insecure']!r}")
        # The iNode pin flows into --pin-sha256 and is compared (in transport.py)
        # against sha256(cert).hexdigest() after stripping ':'/' ' — i.e. it must
        # normalise to a 64-hex (or 40-hex sha1) digest. A typo'd/truncated pin
        # fails closed (compare_digest just won't match) but only at connect time
        # as an opaque "pin mismatch", so warn early. Mirror _normalize_pin's
        # strip so the AA:BB:.. colon form is accepted; warning only (no hard
        # error) — existing configs use placeholder pins like 'AA:BB'.
        cert = str(vpn.get("trusted_cert", "") or "").strip()
        if cert and not _is_cert_pin(cert.replace(":", "").replace(" ", "")):
            warns.append(f"{label}.trusted_cert: does not look like a sha256/sha1 "
                         f"cert pin (expected 64- or 40-hex digits, ':'-separated "
                         f"ok) — it will only fail at connect time if wrong, "
                         f"got {vpn.get('trusted_cert')!r}")
        if not vpn.get("trusted_cert") and not vpn.get("insecure"):
            warns.append(f"{label}: iNode with no trusted_cert pin and insecure not set — a "
                         "self-signed gateway will fail TLS. Pin its sha256 in "
                         f"{label}.trusted_cert (the AA:BB:.. --pin-sha256 form), or set "
                         "insecure: true (trusted LAN only)")
        for k in ("ead", "split_tunnel"):
            if k in vpn and not isinstance(vpn[k], bool):
                errs.append(f"{label}.{k}: must be true or false, got {vpn[k]!r}")
        if "captcha_retries" in vpn:
            cr = vpn["captcha_retries"]
            if not _is_int(cr) or cr < 0:
                errs.append(f"{label}.captcha_retries: must be an integer >= 0, got {cr!r}")
        if "spa_knock_port" in vpn:
            sp = vpn["spa_knock_port"]
            if not _is_int(sp) or not (0 < sp < 65536):
                errs.append(f"{label}.spa_knock_port: must be a port (1-65535), got {sp!r}")
        if vpn.get("spa_key") and not vpn.get("trusted_cert") and not vpn.get("insecure"):
            warns.append(f"{label}: SDP/SPA without cert pin or insecure — the knock may "
                         "open the port, but TLS verification will still fail on a "
                         "self-signed gateway. Add trusted_cert or set insecure: true.")


# --------------------------------------------------------------------------- #
def load(path: Optional[str] = None) -> Config:
    if path is None:
        path = os.environ.get("SOC_PANELS_FILE")
    if path is None:
        # No explicit path / override: resolve through the SHARED resolver so a bare
        # cfg.load() reads exactly what the wizard wrote (per-user marker > /etc > repo).
        from . import configpaths
        path = configpaths.resolve_panels() or "config/panels.yaml"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path} "
                          f"(set SOC_PANELS_FILE or run setup.py)")
    except yaml.YAMLError as e:
        raise ConfigError(f"{path} is not valid YAML: {e}")
    return _parse(raw, path)


def load_str(text: str, source: str = "<vault>") -> Config:
    """Parse + validate a panels config from a YAML *string* — used when the wall
    config lives in a Vaultwarden secure-note instead of an on-disk file. Same
    collect-everything validation as load()."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"{source} is not valid YAML: {e}")
    return _parse(raw, source)


def _parse(raw, path: str) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping with "
                          f"display/panels/tunnel/vpn sections")

    errs: list = []
    warns: list = []
    _unknown_keys(raw, _TOP_KEYS, path, warns)

    d = raw.get("display", {}) or {}
    if not isinstance(d, dict):
        raise ConfigError(f"{path}: display must be a mapping")
    _validate_display(d, errs, warns)

    disp = DisplayCfg(
        auto=bool(d.get("auto", True)),
        width=int(d.get("width", 1920) or 1920),
        height=int(d.get("height", 1080) or 1080),
        cols=int(d.get("cols", 2) or 2),
        rows=int(d.get("rows", 2) or 2),
        gap=int(d.get("gap", 0) or 0),
        layout=str(d.get("layout", "auto")),
        fullscreen=bool(d.get("fullscreen", True)),
    ) if not errs or all("display." not in e for e in errs) else DisplayCfg()

    panels_raw = raw.get("panels", []) or []
    if not isinstance(panels_raw, list):
        errs.append("panels: must be a list")
        panels_raw = []
    for i, p in enumerate(panels_raw):
        _validate_panel(i, p if isinstance(p, dict) else {}, disp, errs, warns)
    _validate_cross(raw, disp, panels_raw, errs, warns)
    vpns_norm = _normalize_vpns(raw, warns)
    _validate_vpns(vpns_norm, errs, warns, legacy=raw.get("vpns") is None)
    _validate_proxy(raw.get("proxy", {}) or {}, errs, warns)
    _validate_security(raw.get("security", {}) or {}, errs, warns)

    if errs:
        raise ConfigError(
            f"{path} has {len(errs)} problem(s):\n  - " + "\n  - ".join(errs))

    panels = []
    for p in panels_raw:
        sel = p.get("selectors") or {}
        url = p.get("url")
        panel = Panel(
            id=p["id"],
            engine=p.get("engine", "webkit"),
            grid=tuple(p.get("grid", [0, 0])),
            mode=p.get("mode", "direct"),
            vault_item=p.get("vault_item", "") or "",
            selectors=sel,
            login_marker=p.get("login_marker", sel.get("pass", "")),
            keepalive=_keepalive(p.get("keepalive")),
            # valid_http_url judged the stripped form, so store that one.
            url=url.strip() if isinstance(url, str) else url,
            tunnel=p.get("tunnel"),
            path=p.get("path", "/"),
            scheme=p.get("scheme", "http"),
            proxy=bool(p.get("proxy", True)),
            title=str(p.get("title", "") or ""),
            # insecure_tls is an alias of allow_insecure: either name opts in.
            allow_insecure=bool(p.get("allow_insecure", p.get("insecure_tls", False))),
            allow_media=bool(p.get("allow_media", False)),
            tenant=str(p.get("tenant") or "").strip(),
            persist=bool(p.get("persist", True)),
            user_agent=(str(p["user_agent"]) if p.get("user_agent") else None),
            allow=tuple(p.get("allow") or ()),
            block_trackers=bool(p.get("block_trackers", True)),
            unblock=tuple(p.get("unblock") or ()),
            login_zones=dict(p.get("login_zones") or {}),
        )
        panel.geometry = compute_geometry(disp, panel.grid)
        panels.append(panel)

    pr = raw.get("proxy", {}) or {}
    proxy = ProxyCfg(
        enabled=bool(pr.get("enabled")),
        url=str(pr.get("url") or "").strip(),
        vault_item=str(pr.get("vault_item") or ""),
        ignore_hosts=tuple(pr.get("ignore_hosts") or ()),
    )

    sc = raw.get("security", {}) or {}
    # env toggles override the file default (and the file overrides the dataclass
    # default) — all default to the SAFE/ON value.
    security = SecurityCfg(
        nav_allowlist=env_bool("SOC_NAV_ALLOWLIST", bool(sc.get("nav_allowlist", True))),
        allow=tuple(sc.get("allow") or ()),
        block_trackers=env_bool("SOC_BLOCK_TRACKERS", bool(sc.get("block_trackers", True))),
        sso_allow=tuple(sc.get("sso_allow") or ()),
    )

    # vpns_norm is the validated authoritative list; conf.vpn is the back-compat
    # PRIMARY (first entry, else {}) so downstream readers that still take one vpn
    # dict see the primary VPN instead of breaking. New code must read conf.vpns.
    return Config(display=disp, panels=panels,
                  tunnel=raw.get("tunnel", {}) or {},
                  vpns=vpns_norm if isinstance(vpns_norm, list) else [],
                  vpn=(vpns_norm[0] if isinstance(vpns_norm, list) and vpns_norm
                       else {}),
                  proxy=proxy,
                  security=security,
                  warnings=warns)


def _vpn_is_plain_single(vpn: dict) -> bool:
    """True when a one-entry list can round-trip as a legacy `vpn: {}` block:
    its only added keys (name/default_route) are the parse-time defaults
    (name=='vpn', default_route falsey). Anything richer must emit `vpns: [...]`."""
    if not isinstance(vpn, dict):
        return False
    if vpn.get("default_route"):
        return False
    nm = str(vpn.get("name", "") or "").strip()
    return nm in ("", "vpn")


def _vpn_emit_dict(vpn: dict, *, with_name: bool) -> dict:
    """A VPN dict ready for YAML: drop a parse-time-default `name`/falsey
    `default_route` so single-block configs stay byte-stable; keep them in the
    list form so each entry's identity/owner round-trips."""
    out = dict(vpn) if isinstance(vpn, dict) else {}
    if not with_name:
        out.pop("name", None)
    if not out.get("default_route"):
        out.pop("default_route", None)
    return out


def _emit_vpns(conf: "Config", out: dict):
    """Serialise conf.vpns back to YAML. A single, plainly-named, non-default-route
    VPN emits a legacy `vpn: {}` block (byte-stable with existing one-VPN tooling);
    anything multi / named / default-route-owning emits a `vpns: [...]` list."""
    vpns = list(conf.vpns or [])
    if not vpns:
        # No vpns[]; fall back to the back-compat primary if something only set
        # conf.vpn directly (e.g. a hand-built Config).
        if conf.vpn:
            out["vpn"] = conf.vpn
        return
    if len(vpns) == 1 and _vpn_is_plain_single(vpns[0]):
        out["vpn"] = _vpn_emit_dict(vpns[0], with_name=False)
    else:
        out["vpns"] = [_vpn_emit_dict(v, with_name=True) for v in vpns]


def to_yaml(conf: "Config") -> str:
    """Serialise a loaded Config back to YAML — used to push on-screen edits back
    into the Vaultwarden config note (the source of truth). Round-trips through
    load_str()."""
    d = conf.display
    out = {
        "display": {"auto": bool(d.auto), "width": d.width, "height": d.height,
                    "cols": d.cols, "rows": d.rows, "gap": d.gap, "layout": d.layout},
        "panels": [],
    }
    if not d.fullscreen:            # default stays implicit, like the other knobs
        out["display"]["fullscreen"] = False
    for p in conf.panels:
        pd = {"id": p.id, "engine": p.engine, "grid": [p.grid[0], p.grid[1]],
              "mode": p.mode}
        if p.mode == "tunnel":
            pd["tunnel"] = dict(p.tunnel or {})
            pd["path"] = p.path
            pd["scheme"] = p.scheme
        else:
            pd["url"] = p.url or ""
        if p.vault_item:
            pd["vault_item"] = p.vault_item
        if p.selectors:
            pd["selectors"] = dict(p.selectors)
        if p.login_marker:
            pd["login_marker"] = p.login_marker
        k = p.keepalive
        ka = {"strategy": k.strategy}
        if k.strategy != "none":
            ka["intervalSec"] = k.intervalSec
        if k.url:
            ka["url"] = k.url
        if k.target:
            ka["target"] = k.target
        pd["keepalive"] = ka
        if not p.proxy:
            pd["proxy"] = False
        if p.title:
            pd["title"] = p.title
        if p.allow_insecure:
            pd["allow_insecure"] = True
        if p.allow_media:
            pd["allow_media"] = True
        if p.tenant:
            pd["tenant"] = p.tenant
        if p.login_zones:
            pd["login_zones"] = {k: dict(v) for k, v in p.login_zones.items()}
        # renderer knobs — emit only when non-default (keeps round-tripped
        # configs minimal and backward-compatible).
        if not p.persist:
            pd["persist"] = False
        if p.user_agent:
            pd["user_agent"] = p.user_agent
        if p.allow:
            pd["allow"] = list(p.allow)
        if not p.block_trackers:
            pd["block_trackers"] = False
        if p.unblock:
            pd["unblock"] = list(p.unblock)
        out["panels"].append(pd)
    if conf.tunnel:
        out["tunnel"] = conf.tunnel
    _emit_vpns(conf, out)
    sec = conf.security
    # Emit the security block only when it deviates from the all-safe defaults,
    # so existing minimal configs round-trip unchanged.
    sd: dict = {}
    if not sec.nav_allowlist:
        sd["nav_allowlist"] = False
    if not sec.block_trackers:
        sd["block_trackers"] = False
    if sec.allow:
        sd["allow"] = list(sec.allow)
    if sec.sso_allow:
        sd["sso_allow"] = list(sec.sso_allow)
    if sd:
        out["security"] = sd
    pr = conf.proxy
    if pr.enabled:
        out["proxy"] = {"enabled": True, "url": pr.url}
        if pr.vault_item:
            out["proxy"]["vault_item"] = pr.vault_item
        if pr.ignore_hosts:
            out["proxy"]["ignore_hosts"] = list(pr.ignore_hosts)
    else:
        out["proxy"] = {"enabled": False}
    return yaml.safe_dump(out, sort_keys=False, default_flow_style=False)
