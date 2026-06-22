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
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

import yaml


class ConfigError(Exception):
    """panels.yaml is invalid. The message lists every problem found."""


VALID_ENGINES = {"webkit", "chromium"}
VALID_MODES = {"direct", "tunnel"}
VALID_LAYOUTS = {"auto", "windows", "single"}
VALID_KEEPALIVE = {"reload", "click", "xhr", "none"}
VALID_SCHEMES = {"http", "https"}
VALID_PROXY_SCHEMES = {"http", "https", "socks", "socks4", "socks5"}
VALID_VPN_TYPES = {"fortinet", "openvpn", "wireguard", "inode"}

_TOP_KEYS = {"display", "panels", "tunnel", "vpn", "proxy"}
_DISPLAY_KEYS = {"auto", "width", "height", "cols", "rows", "gap", "layout"}
_PANEL_KEYS = {"id", "engine", "grid", "mode", "url", "tunnel", "path", "scheme",
               "vault_item", "selectors", "login_marker", "keepalive", "proxy",
               "title", "allow_insecure", "allow_media"}
_PROXY_KEYS = {"enabled", "url", "vault_item", "ignore_hosts"}
_TUNNEL_PANEL_KEYS = {"local_port", "remote_host", "remote_port"}
_KEEPALIVE_KEYS = {"strategy", "intervalSec", "url", "target"}
_TUNNEL_KEYS = {"enabled", "jump_host", "identity", "extra_forwards"}
_VPN_KEYS = {"enabled", "type", "config", "config_from_vault", "gateway", "port",
             "vault_item", "trusted_cert", "ca_file", "realm", "set_routes",
             "set_dns", "half_internet_routes", "persistent", "otp_from_vault",
             "ready_probe", "extra_args", "health_check_interval",
             "health_check_failures", "domain", "insecure"}


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
    allow_insecure: bool = False    # accept self-signed TLS (trusted LAN only)
    allow_media: bool = False       # keep WebGL/WebAudio/<video> (off by default
                                    # to save RAM/GPU on 1 GB boards)
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


@dataclass
class Config:
    display: DisplayCfg
    panels: list = field(default_factory=list)
    tunnel: dict = field(default_factory=dict)
    vpn: dict = field(default_factory=dict)
    proxy: ProxyCfg = field(default_factory=ProxyCfg)
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
    args = [f"{gateway}:{int(vpn.get('port', 443))}"]
    if vpn.get("trusted_cert"):
        args.append(f"--trusted-cert={vpn['trusted_cert']}")
    if vpn.get("ca_file"):
        args.append(f"--ca-file={vpn['ca_file']}")
    if vpn.get("realm"):
        args.append(f"--realm={vpn['realm']}")
    # Routing / DNS: emit explicit 0/1 so the gateway can't silently change them.
    if "set_routes" in vpn:
        args.append(f"--set-routes={1 if vpn['set_routes'] else 0}")
    if "set_dns" in vpn:
        args.append(f"--set-dns={1 if vpn['set_dns'] else 0}")
    if "half_internet_routes" in vpn:
        args.append(f"--half-internet-routes={1 if vpn['half_internet_routes'] else 0}")
    persistent = int(vpn.get("persistent", 0) or 0)
    if persistent > 0:
        args.append(f"--persistent={persistent}")
    args += [str(a) for a in (vpn.get("extra_args") or [])]
    return args


def vpn_kind(vpn: dict) -> str:
    """The VPN backend: 'fortinet' (default), 'openvpn', or 'wireguard'."""
    t = str((vpn or {}).get("type", "fortinet") or "fortinet").lower()
    return t if t in VALID_VPN_TYPES else "fortinet"


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
    args += [str(a) for a in (vpn.get("extra_args") or [])]
    return args


def wireguard_target(vpn: dict) -> str:
    """The wg-quick target: a .conf path, or a bare interface name resolved from
    /etc/wireguard/<name>.conf. Empty when not configured."""
    return str((vpn or {}).get("config", "") or "").strip()


def inode_gateway(vpn: dict) -> str:
    """'host:port' for the H3C iNode SSL-VPN gateway (default port 443). '' when
    no gateway is configured."""
    vpn = vpn or {}
    host = str(vpn.get("gateway", "") or "").strip()
    return f"{host}:{int(vpn.get('port', 443) or 443)}" if host else ""


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
    tail = []
    pin = str(vpn.get("trusted_cert", "") or "").strip()
    if pin:
        tail += ["--pin-sha256", pin]
    elif vpn.get("insecure"):
        tail += ["--insecure"]
    tail += [str(a) for a in (vpn.get("extra_args") or [])]
    return ["--"] + tail if tail else []


def compute_geometry(disp: DisplayCfg, grid) -> Geometry:
    """Map a (col,row) grid cell to an on-screen rectangle."""
    col, row = grid
    gap = disp.gap
    cell_w = (disp.width - gap * (disp.cols - 1)) // disp.cols
    cell_h = (disp.height - gap * (disp.rows - 1)) // disp.rows
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


def _probe_ok(probe: str) -> bool:
    host, _, port = probe.rpartition(":")
    return bool(host) and port.isdigit() and 0 < int(port) < 65536


def _unknown_keys(d: dict, known: set, where: str, warns: list):
    for k in sorted(set(d) - known):
        warns.append(f"{where}: unknown key '{k}' (typo?) — it is ignored")


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


def _validate_panel(i: int, p: dict, disp: DisplayCfg, errs: list, warns: list):
    pid = p.get("id") or f"#{i + 1}"
    where = f"panel {pid}"
    if not isinstance(p, dict):
        errs.append(f"panel #{i + 1}: must be a mapping")
        return
    _unknown_keys(p, _PANEL_KEYS, where, warns)

    if not p.get("id"):
        errs.append(f"panel #{i + 1}: missing required key 'id'")

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
        elif not url.startswith(("http://", "https://")):
            errs.append(f"{where}: url must start with http:// or https://, got {url!r}")
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
    else:
        errs.append("tunnel: must be a mapping")


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
    else:
        try:
            u = urlsplit(url)
            scheme, host, port, userinfo = u.scheme, u.hostname, u.port, u.username
        except ValueError:
            scheme = host = port = userinfo = None
        if scheme not in VALID_PROXY_SCHEMES:
            errs.append(f"proxy.url: scheme must be one of "
                        f"{sorted(VALID_PROXY_SCHEMES)}, got {url!r}")
        elif not host:
            errs.append(f"proxy.url: missing host, got {url!r}")
        elif port is None:
            errs.append(f"proxy.url: missing port — want scheme://host:port, got {url!r}")
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


def _validate_vpn(vpn: dict, errs: list, warns: list):
    if not isinstance(vpn, dict):
        errs.append("vpn: must be a mapping")
        return
    _unknown_keys(vpn, _VPN_KEYS, "vpn", warns)
    if not vpn.get("enabled"):
        return

    kind = str(vpn.get("type", "fortinet") or "fortinet").lower()
    if kind not in VALID_VPN_TYPES:
        errs.append(f"vpn.type: must be one of {sorted(VALID_VPN_TYPES)}, got "
                    f"{vpn.get('type')!r}")
        kind = "fortinet"

    # shared numeric / probe checks (all types)
    for k in ("persistent", "health_check_interval", "health_check_failures"):
        if k in vpn and (not _is_int(vpn[k]) or vpn[k] < 0):
            errs.append(f"vpn.{k}: must be an integer >= 0, got {vpn[k]!r}")
    probe = (vpn.get("ready_probe") or "").strip()
    if probe and not _probe_ok(probe):
        errs.append(f"vpn.ready_probe: want 'host:port', got {probe!r}")
    # fortinet/openvpn health-check needs a TCP probe; wireguard can fall back to
    # the peer's last-handshake age, so a probe is optional there.
    if vpn.get("health_check_interval") and not probe and kind != "wireguard":
        errs.append("vpn.health_check_interval is set but vpn.ready_probe is empty — "
                    "the health check needs a host:port to probe")

    if kind == "fortinet":
        if not vpn.get("gateway"):
            errs.append("vpn: type 'fortinet' but 'gateway' is not set")
        if not vpn.get("vault_item"):
            errs.append("vpn: type 'fortinet' but 'vault_item' is not set "
                        "(the vault login holding the FortiGate credentials)")
        if "port" in vpn and (not _is_int(vpn["port"]) or not (0 < vpn["port"] < 65536)):
            errs.append(f"vpn.port: must be a port number (1-65535), got {vpn['port']!r}")
        cert = vpn.get("trusted_cert", "")
        if cert and not (len(cert) == 64
                         and all(c in "0123456789abcdefABCDEF" for c in cert)):
            errs.append(f"vpn.trusted_cert: expected a 64-char sha256 hex digest, "
                        f"got {len(str(cert))} chars")
        if not cert and not vpn.get("ca_file"):
            warns.append("vpn: no trusted_cert / ca_file pinned — the connection "
                         "relies on system CAs; if the gateway uses a self-signed "
                         "cert the VPN will refuse to connect (see "
                         "docs/CONFIGURATION.md to pin it)")
    elif kind == "openvpn":
        from_vault = bool(vpn.get("config_from_vault"))
        if from_vault and not vpn.get("vault_item"):
            errs.append("vpn: openvpn with config_from_vault needs 'vault_item' "
                        "(its Notes hold the .ovpn profile)")
        elif not from_vault and not vpn.get("config"):
            errs.append("vpn: type 'openvpn' requires 'config' (path to the .ovpn "
                        "profile), or config_from_vault: true")
        if not from_vault and not vpn.get("vault_item"):
            warns.append("vpn: openvpn with no vault_item — assuming certificate-only "
                         "auth (the .ovpn must carry the client cert/key). Set "
                         "vault_item for a username/password login.")
    elif kind == "wireguard":
        from_vault = bool(vpn.get("config_from_vault"))
        if from_vault and not vpn.get("vault_item"):
            errs.append("vpn: wireguard with config_from_vault needs 'vault_item' "
                        "(its Notes hold the .conf — keys included)")
        elif not from_vault and not vpn.get("config"):
            errs.append("vpn: type 'wireguard' requires 'config' (a .conf path or an "
                        "interface name under /etc/wireguard), or config_from_vault: true")
        if vpn.get("vault_item") and not from_vault:
            warns.append("vpn: wireguard ignores vault_item unless config_from_vault "
                         "is set — otherwise its keys live in the .conf file (0600)")
    elif kind == "inode":
        if not vpn.get("gateway"):
            errs.append("vpn: type 'inode' but 'gateway' is not set (the H3C "
                        "SSL-VPN gateway host)")
        if not vpn.get("vault_item"):
            errs.append("vpn: type 'inode' but 'vault_item' is not set (the vault "
                        "login holding the SSL-VPN username + password)")
        if "port" in vpn and (not _is_int(vpn["port"]) or not (0 < vpn["port"] < 65536)):
            errs.append(f"vpn.port: must be a port number (1-65535), got {vpn['port']!r}")
        if "insecure" in vpn and not isinstance(vpn["insecure"], bool):
            errs.append(f"vpn.insecure: must be true or false, got {vpn['insecure']!r}")
        if not vpn.get("trusted_cert") and not vpn.get("insecure"):
            warns.append("vpn: iNode with no trusted_cert pin and insecure not set — a "
                         "self-signed gateway will fail TLS. Pin its sha256 in "
                         "vpn.trusted_cert (the AA:BB:.. --pin-sha256 form), or set "
                         "insecure: true (trusted LAN only)")


# --------------------------------------------------------------------------- #
def load(path: Optional[str] = None) -> Config:
    path = path or os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
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
    ) if not errs or all("display." not in e for e in errs) else DisplayCfg()

    panels_raw = raw.get("panels", []) or []
    if not isinstance(panels_raw, list):
        errs.append("panels: must be a list")
        panels_raw = []
    for i, p in enumerate(panels_raw):
        _validate_panel(i, p if isinstance(p, dict) else {}, disp, errs, warns)
    _validate_cross(raw, disp, panels_raw, errs, warns)
    _validate_vpn(raw.get("vpn", {}) or {}, errs, warns)
    _validate_proxy(raw.get("proxy", {}) or {}, errs, warns)

    if errs:
        raise ConfigError(
            f"{path} has {len(errs)} problem(s):\n  - " + "\n  - ".join(errs))

    panels = []
    for p in panels_raw:
        sel = p.get("selectors") or {}
        panel = Panel(
            id=p["id"],
            engine=p.get("engine", "webkit"),
            grid=tuple(p.get("grid", [0, 0])),
            mode=p.get("mode", "direct"),
            vault_item=p.get("vault_item", "") or "",
            selectors=sel,
            login_marker=p.get("login_marker", sel.get("pass", "")),
            keepalive=_keepalive(p.get("keepalive")),
            url=p.get("url"),
            tunnel=p.get("tunnel"),
            path=p.get("path", "/"),
            scheme=p.get("scheme", "http"),
            proxy=bool(p.get("proxy", True)),
            title=str(p.get("title", "") or ""),
            allow_insecure=bool(p.get("allow_insecure", False)),
            allow_media=bool(p.get("allow_media", False)),
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

    return Config(display=disp, panels=panels,
                  tunnel=raw.get("tunnel", {}) or {},
                  vpn=raw.get("vpn", {}) or {},
                  proxy=proxy,
                  warnings=warns)


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
        out["panels"].append(pd)
    if conf.tunnel:
        out["tunnel"] = conf.tunnel
    if conf.vpn:
        out["vpn"] = conf.vpn
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
