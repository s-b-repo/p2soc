#!/usr/bin/env python3
"""
SOC video-wall — interactive setup wizard.

Walks you through configuring the whole wall step by step and writes the three
files the kiosk reads:

  * panels.yaml        — the 4 panels, the autossh tunnel, and the Fortinet VPN
  * soc.env            — vault settings + the unattended-unlock master password
  * vaultwarden.env    — the Vaultwarden server settings (admin token, bind)

It is **pure standard library** (so it runs before the venv exists), idempotent
(re-running loads your previous answers as defaults), and never overwrites a file
without backing it up first.

Usage:
  python3 setup.py                 # interactive menu (deploy / configure / diagnose / ...)
  python3 setup.py deploy          # full automated deployment, end to end
  python3 setup.py wizard          # just the configuration wizard
  python3 setup.py doctor          # diagnose an existing install
  python3 setup.py repair          # fix what doctor flags (packages / venv / keys)
  python3 setup.py creds           # store logins in Vaultwarden
  python3 setup.py --dry-run       # show what it would write, write nothing
  python3 setup.py --defaults      # accept every default (non-interactive wizard)
  python3 setup.py --target pi     # write to /etc/soc-display (default when root)
  python3 setup.py --target dev    # write to the repo (config/panels.local.yaml, .env)
  python3 setup.py --section vpn   # jump straight to one section
                                   #   (display|panels|tunnel|vpn|proxy|vault|server|all)

Run with no arguments on a terminal for the menu; piped input or --defaults runs
the wizard directly. Nothing here needs root unless you ask it to run ./install.sh.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s


def cyan(s):   return _c("36", s)
def green(s):  return _c("32", s)
def yellow(s): return _c("33", s)
def red(s):    return _c("31", s)
def bold(s):   return _c("1", s)
def dim(s):    return _c("2", s)


def banner(title: str):
    line = "─" * (len(title) + 2)
    print()
    print(cyan(f"┌{line}┐"))
    print(cyan(f"│ {bold(title)} │"))
    print(cyan(f"└{line}┘"))


def step(n, total, title):
    print()
    print(cyan(f"━━ Step {n}/{total} · {bold(title)} ") + cyan("━" * max(0, 50 - len(title))))


def note(s):  print(dim("   " + s))
def ok(s):    print(green("  ✓ " + s))
def warn(s):  print(yellow("  ! " + s))
def err(s):   print(red("  ✗ " + s))


# --------------------------------------------------------------------------- #
# Input primitives (honour --defaults and EOF/Ctrl-C)
# --------------------------------------------------------------------------- #
ASSUME_DEFAULTS = False

# Set by the wizard so `deploy` can reuse the just-built config/env in-process
# (a fresh Pi's system python may not have PyYAML to re-read the file).
_LAST_CFG = None
_LAST_SOC_ENV = None


def _readline(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        print()
        return ""
    except KeyboardInterrupt:
        print()
        err("aborted — nothing was written")
        sys.exit(130)


def ask(prompt: str, default: str = "", *, allow_empty=True, validate=None) -> str:
    """Prompt for a value. `validate(value) -> error string | None` rejects +
    re-prompts on bad input. A non-empty default is assumed already valid."""
    d = f" [{default}]" if default != "" else ""
    while True:
        if ASSUME_DEFAULTS:
            print(dim(f"   {prompt}{d} -> {default}"))
            return default
        raw = _readline(f"   {prompt}{d}: ").strip()
        if raw == "":
            if default != "" or allow_empty:
                return default
            warn("a value is required")
            continue
        if validate is not None:
            problem = validate(raw)
            if problem:
                warn(problem)
                continue
        return raw


# --------------------------------------------------------------------------- #
# Input validators — return an error string (re-prompt) or None (accept).
# --------------------------------------------------------------------------- #
def v_url(s: str):
    if not re.match(r"^https?://[^\s/:]+(:\d+)?(/.*)?$", s):
        return "want a http:// or https:// URL (e.g. https://host:443/login)"
    m = re.search(r":(\d+)", s.split("/", 3)[2] if "//" in s else s)
    if m and not (0 < int(m.group(1)) < 65536):
        return "port must be 1-65535"
    return None


def v_hostport(s: str):
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit() or not (0 < int(port) < 65536):
        return "want host:port (e.g. 10.50.0.5:443)"
    return None


def v_email(s: str):
    return None if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s) else "not a valid email address"


def v_path_exists(s: str):
    return None if os.path.exists(os.path.expanduser(s)) else f"path not found: {s}"


def v_selector(s: str):
    return None if s.strip() else "a CSS selector is required"


def v_sha256(s: str):
    s = s.strip()
    if not s:
        return None                                    # optional (cert pinning off)
    return None if (len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)) \
        else "expected a 64-character sha256 hex digest"


def v_host(s: str):
    return None if re.match(r"^[A-Za-z0-9._-]+$", s) else "not a valid hostname"


def ask_bool(prompt: str, default: bool) -> bool:
    dd = "Y/n" if default else "y/N"
    if ASSUME_DEFAULTS:
        print(dim(f"   {prompt} [{dd}] -> {'yes' if default else 'no'}"))
        return default
    while True:
        raw = _readline(f"   {prompt} [{dd}]: ").strip().lower()
        if raw == "":
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        warn("please answer y or n")


def ask_int(prompt: str, default: int, lo=None, hi=None) -> int:
    while True:
        raw = ask(prompt, str(default))
        try:
            v = int(raw)
        except ValueError:
            warn("enter a whole number")
            continue
        if lo is not None and v < lo:
            warn(f"must be >= {lo}")
            continue
        if hi is not None and v > hi:
            warn(f"must be <= {hi}")
            continue
        return v


def ask_choice(prompt: str, options: list, default: str) -> str:
    if ASSUME_DEFAULTS:
        print(dim(f"   {prompt} -> {default}"))
        return default
    print(f"   {prompt}")
    for i, o in enumerate(options, 1):
        mark = green(" (default)") if o == default else ""
        print(f"     {i}) {o}{mark}")
    while True:
        raw = _readline(f"   choose 1-{len(options)} [{options.index(default)+1}]: ").strip()
        if raw == "":
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        if raw in options:
            return raw
        warn("pick one of the listed numbers")


def ask_secret(prompt: str, default: str = "") -> str:
    if ASSUME_DEFAULTS:
        return default or "CHANGE-ME"
    import getpass
    d = " [keep existing]" if default else ""
    try:
        v = getpass.getpass(f"   {prompt}{d}: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return v if v != "" else default


# --------------------------------------------------------------------------- #
# Environment detection + file IO
# --------------------------------------------------------------------------- #
class Env:
    def __init__(self):
        self.is_root = (os.geteuid() == 0)
        self.has_apt = shutil.which("apt-get") is not None
        self.is_pi = os.path.exists("/etc/rpi-issue") or "raspberry" in _uname().lower()
        self.venv_py = os.path.join(REPO, ".venv", "bin", "python")
        self.has_venv = os.path.exists(self.venv_py)


def _uname() -> str:
    try:
        return subprocess.run(["uname", "-a"], capture_output=True, text=True,
                              timeout=5).stdout
    except Exception:
        return ""


def backup(path: str):
    if not os.path.exists(path):
        return
    stamp = time.strftime("%Y%m%d-%H%M%S")
    bak = f"{path}.bak.{stamp}"
    shutil.copy2(path, bak)
    note(f"backed up existing {path} -> {os.path.basename(bak)}")


def write_file(path: str, content: str, mode: int, dry: bool):
    if dry:
        print(yellow(f"   [dry-run] would write {path} (mode {oct(mode)})"))
        for ln in content.splitlines():
            print(dim("     | " + ln))
        return
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    backup(path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, mode)
    ok(f"wrote {path}  ({oct(mode)[2:]})")


def load_env_file(path: str) -> dict:
    """Tiny KEY=VALUE reader for using a previous soc.env as defaults."""
    out = {}
    if not os.path.exists(path):
        return out
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] in "'\"" and v[-1] == v[0]:
                    v = v[1:-1]
                out[k.strip()] = v
    except OSError:
        pass
    return out


def load_yaml(path: str):
    """Load a YAML file if PyYAML is available (used only for re-run defaults)."""
    if not os.path.exists(path):
        return None
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# YAML / env rendering (string templating — keeps comments, no PyYAML needed)
# --------------------------------------------------------------------------- #
def yq(s) -> str:
    """Quote a scalar as a safe double-quoted YAML string."""
    s = "" if s is None else str(s)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


_SAFE_ENV = re.compile(r"^[A-Za-z0-9_@%+=:,./-]+$")


def envq(v) -> str:
    """Quote a value for a shell-sourced env file (single quotes when needed)."""
    v = "" if v is None else str(v)
    if v == "" or _SAFE_ENV.match(v):
        return v
    return "'" + v.replace("'", "'\\''") + "'"


def render_panels_yaml(cfg: dict) -> str:
    d = cfg["display"]
    L = []
    L.append("# =============================================================================")
    L.append("# SOC video-wall configuration — generated by setup.py")
    L.append("# Re-run `python3 setup.py` to change it (your answers become the defaults).")
    L.append("# =============================================================================")
    L.append("display:")
    L.append(f"  auto: {str(bool(d['auto'])).lower()}")
    L.append(f"  width: {d['width']}")
    L.append(f"  height: {d['height']}")
    L.append(f"  cols: {d['cols']}")
    L.append(f"  rows: {d['rows']}")
    L.append(f"  gap: {d['gap']}")
    L.append(f"  layout: {d.get('layout', 'auto')}")
    L.append("")
    L.append("panels:")
    for p in cfg["panels"]:
        L.append(f"  - id: {p['id']}")
        L.append(f"    engine: {p['engine']}")
        L.append(f"    grid: [{p['grid'][0]}, {p['grid'][1]}]")
        L.append(f"    mode: {p['mode']}")
        if p["mode"] == "tunnel":
            t = p["tunnel"]
            L.append(f"    tunnel: {{ local_port: {t['local_port']}, "
                     f"remote_host: {yq(t['remote_host'])}, remote_port: {t['remote_port']} }}")
            L.append(f"    path: {yq(p.get('path', '/'))}")
            L.append(f"    scheme: {yq(p.get('scheme', 'http'))}")
        else:
            L.append(f"    url: {yq(p['url'])}")
        L.append(f"    vault_item: {yq(p['vault_item'])}")
        s = p["selectors"]
        L.append("    selectors:")
        L.append(f"      user: {yq(s['user'])}")
        L.append(f"      pass: {yq(s['pass'])}")
        if s.get("submit"):
            L.append(f"      submit: {yq(s['submit'])}")
        L.append(f"    login_marker: {yq(p['login_marker'])}")
        k = p["keepalive"]
        ka = f"    keepalive: {{ strategy: {k['strategy']}"
        if k["strategy"] != "none":
            ka += f", intervalSec: {k.get('intervalSec', 600)}"
        if k["strategy"] == "xhr" and k.get("url"):
            ka += f", url: {yq(k['url'])}"
        if k["strategy"] == "click" and k.get("target"):
            ka += f", target: {yq(k['target'])}"
        ka += " }"
        L.append(ka)
        L.append("")
    # tunnel
    t = cfg["tunnel"]
    L.append("# autossh SSH jump-host tunnel — -L forwards are derived from mode: tunnel panels")
    L.append("tunnel:")
    L.append(f"  enabled: {str(bool(t['enabled'])).lower()}")
    if t["enabled"]:
        L.append(f"  jump_host: {yq(t['jump_host'])}")
        L.append(f"  identity: {yq(t['identity'])}")
        L.append("  extra_forwards: []")
    L.append("")
    # vpn
    v = cfg["vpn"]
    vtype = v.get("type", "fortinet")
    L.append("# VPN — supervised tunnel (Fortinet / OpenVPN / WireGuard / iNode), run as root")
    L.append("vpn:")
    L.append(f"  enabled: {str(bool(v['enabled'])).lower()}")
    if v["enabled"]:
        L.append(f"  type: {vtype}")
        if vtype == "openvpn":
            L.append(f"  config: {yq(v['config'])}")
            L.append(f"  vault_item: {yq(v.get('vault_item', ''))}")
            L.append(f"  ready_probe: {yq(v.get('ready_probe', ''))}")
            L.append(f"  set_routes: {str(bool(v.get('set_routes', True))).lower()}")
            L.append("  extra_args: []")
        elif vtype == "wireguard":
            L.append(f"  config: {yq(v['config'])}")
            L.append(f"  ready_probe: {yq(v.get('ready_probe', ''))}")
            L.append(f"  health_check_interval: {v.get('health_check_interval', 30)}")
            L.append(f"  health_check_failures: {v.get('health_check_failures', 3)}")
        elif vtype == "inode":
            L.append(f"  gateway: {yq(v['gateway'])}")
            L.append(f"  port: {v.get('port', 443)}")
            L.append(f"  vault_item: {yq(v['vault_item'])}")
            if v.get("config"):
                L.append(f"  config: {yq(v['config'])}")
            if v.get("domain"):
                L.append(f"  domain: {yq(v['domain'])}")
            L.append(f"  trusted_cert: {yq(v.get('trusted_cert', ''))}")
            L.append(f"  insecure: {str(bool(v.get('insecure', False))).lower()}")
            L.append(f"  ready_probe: {yq(v.get('ready_probe', ''))}")
            L.append(f"  health_check_interval: {v.get('health_check_interval', 0)}")
            L.append(f"  health_check_failures: {v.get('health_check_failures', 3)}")
            L.append("  extra_args: []")
        else:  # fortinet
            L.append(f"  gateway: {yq(v['gateway'])}")
            L.append(f"  port: {v['port']}")
            L.append(f"  vault_item: {yq(v['vault_item'])}")
            L.append(f"  trusted_cert: {yq(v.get('trusted_cert', ''))}")
            L.append(f"  realm: {yq(v.get('realm', ''))}")
            L.append(f"  set_routes: {str(bool(v['set_routes'])).lower()}")
            L.append(f"  set_dns: {str(bool(v['set_dns'])).lower()}")
            L.append(f"  half_internet_routes: {str(bool(v['half_internet_routes'])).lower()}")
            L.append(f"  persistent: {v['persistent']}")
            L.append(f"  otp_from_vault: {str(bool(v['otp_from_vault'])).lower()}")
            L.append(f"  ready_probe: {yq(v.get('ready_probe', ''))}")
            L.append(f"  health_check_interval: {v.get('health_check_interval', 0)}")
            L.append(f"  health_check_failures: {v.get('health_check_failures', 3)}")
            L.append("  extra_args: []")
    L.append("")
    # proxy
    pr = cfg.get("proxy") or {"enabled": False}
    L.append("# Outbound proxy for the panel browsers — auth creds come from the vault")
    L.append("proxy:")
    L.append(f"  enabled: {str(bool(pr.get('enabled'))).lower()}")
    if pr.get("enabled"):
        L.append(f"  url: {yq(pr['url'])}")
        L.append(f"  vault_item: {yq(pr.get('vault_item', ''))}")
        if pr.get("ignore_hosts"):
            L.append("  ignore_hosts:")
            for h in pr["ignore_hosts"]:
                L.append(f"    - {yq(h)}")
        else:
            L.append("  ignore_hosts: []")
    L.append("")
    return "\n".join(L)


def render_soc_env(e: dict) -> str:
    L = []
    L.append("# SOC kiosk environment — generated by setup.py. NON-SECRET.")
    L.append("# The vault master password is NOT here: it is sealed host-bound under")
    L.append("# $SOC_SECRET_DIR and fed to rbw by pinentry-vault.py (no .env secret).")
    L.append("# The wall config lives in Vaultwarden (SOC_CONFIG_VAULT_ITEM). See")
    L.append("# docs/SECURITY.md.")
    L.append("")
    L.append("# --- vault (rbw -> Vaultwarden) ---")
    for k in ("SOC_VAULT_BACKEND", "SOC_VAULT_EMAIL", "SOC_VAULT_URL"):
        L.append(f"{k}={envq(e[k])}")
    L.append(f"SOC_SECRET_DIR={envq(e.get('SOC_SECRET_DIR', ''))}")
    L.append(f"SOC_CONFIG_VAULT_ITEM={envq(e.get('SOC_CONFIG_VAULT_ITEM', 'SOC Wall Config'))}")
    L.append("")
    L.append("# --- paths ---")
    for k in ("SOC_ROOT", "SOC_PANELS_FILE", "SOC_INJECT_TMPL"):
        L.append(f"{k}={envq(e[k])}")
    L.append("")
    L.append("# --- host tuning ---")
    for k in ("SOC_LAUNCH_STAGGER", "SOC_READY_TIMEOUT", "SOC_CDP_BASE_PORT",
              "SOC_CRED_TTL", "SOC_VPN_DRY_RUN"):
        L.append(f"{k}={envq(e[k])}")
    L.append("")
    L.append("# --- display stack: auto|wayland|xwayland|xlibre|xorg|x11 ---")
    L.append(f"SOC_SESSION={envq(e.get('SOC_SESSION', 'auto'))}")
    L.append("")
    return "\n".join(L)


def render_vw_env(e: dict) -> str:
    L = []
    L.append("# Vaultwarden server env — generated by setup.py. Mode 0600.")
    L.append("# Keep the vault bound to localhost; the kiosk reaches it via rbw on 8222.")
    for k in ("DATA_FOLDER", "ROCKET_ADDRESS", "ROCKET_PORT", "SIGNUPS_ALLOWED",
              "SIGNUPS_VERIFY", "WEBSOCKET_ENABLED"):
        L.append(f"{k}={envq(e[k])}")
    L.append("# Admin page token (argon2). Generate with: vaultwarden hash")
    L.append(f"ADMIN_TOKEN={envq(e['ADMIN_TOKEN'])}")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Wizard sections
# --------------------------------------------------------------------------- #
DEF_SELECTORS = {"user": "#username", "pass": "#password", "submit": "button[type=submit]"}


def section_display(prev) -> dict:
    step(1, 7, "Display geometry")
    note("The screen is split into a grid; each cell holds one panel window.")
    pd = (prev or {}).get("display", {}) if prev else {}
    auto = ask_bool("Auto-detect resolution from xrandr at launch?", pd.get("auto", True))
    width = ask_int("Screen width (px), used when auto is off", int(pd.get("width", 1920)))
    height = ask_int("Screen height (px)", int(pd.get("height", 1080)))
    cols = ask_int("Grid columns", int(pd.get("cols", 2)), lo=1, hi=4)
    rows = ask_int("Grid rows", int(pd.get("rows", 2)), lo=1, hi=4)
    gap = ask_int("Gap between cells (px, 0 = seamless)", int(pd.get("gap", 0)), lo=0)
    note("Layout: auto = per-panel windows on X11, one fullscreen grid window on")
    note("Wayland (all-webkit walls). 'single' is the most robust (webkit only).")
    layout = ask_choice("layout", ["auto", "windows", "single"], pd.get("layout", "auto"))
    return dict(auto=auto, width=width, height=height, cols=cols, rows=rows, gap=gap,
                layout=layout)


def section_panels(display, prev) -> list:
    step(2, 7, "Panels")
    cols, rows = display["cols"], display["rows"]
    cap = cols * rows
    prev_panels = (prev or {}).get("panels", []) if prev else []
    count = ask_int(f"How many panels? (grid holds {cap})", min(cap, len(prev_panels) or 4),
                    lo=1, hi=cap)
    panels = []
    for i in range(count):
        pp = prev_panels[i] if i < len(prev_panels) else {}
        print()
        print(cyan(f"   ── Panel {i+1} of {count} ──"))
        pid = ask("id (window class becomes soc-<id>)", pp.get("id", f"p{i+1}"), allow_empty=False)
        engine = ask_choice("engine", ["webkit", "chromium"], pp.get("engine", "webkit"))
        gc = i % cols
        gr = i // cols
        pgrid = pp.get("grid", [gc, gr])
        col = ask_int("grid column (0-based)", int(pgrid[0]), lo=0, hi=cols - 1)
        row = ask_int("grid row (0-based)", int(pgrid[1]), lo=0, hi=rows - 1)
        mode = ask_choice("mode", ["direct", "tunnel"], pp.get("mode", "direct"))
        panel = dict(id=pid, engine=engine, grid=[col, row], mode=mode)
        if mode == "tunnel":
            pt = pp.get("tunnel", {})
            note("This panel is reached through the autossh jump host.")
            lp = ask_int("local forward port (127.0.0.1:<port>)", int(pt.get("local_port", 19100 + i + 1)))
            rh = ask("remote host (as seen from the jump host)", pt.get("remote_host", "10.20.0.7"), allow_empty=False)
            rp = ask_int("remote port", int(pt.get("remote_port", 443)))
            panel["tunnel"] = dict(local_port=lp, remote_host=rh, remote_port=rp)
            panel["path"] = ask("path on the app", pp.get("path", "/login"))
            panel["scheme"] = ask_choice("local scheme", ["http", "https"], pp.get("scheme", "http"))
        else:
            panel["url"] = ask("login URL", pp.get("url", f"http://192.168.1.{50+i}:3000/login"),
                               allow_empty=False, validate=v_url)
        panel["vault_item"] = ask("vault item name (the Vaultwarden login to use)",
                                  pp.get("vault_item", f"SOC Panel {i+1}"), allow_empty=False)
        note("CSS selectors for the login form — Inspect the page to find these.")
        ps = pp.get("selectors", {})
        sel = {
            "user": ask("  username field selector", ps.get("user", DEF_SELECTORS["user"])),
            "pass": ask("  password field selector", ps.get("pass", DEF_SELECTORS["pass"])),
            "submit": ask("  submit button selector (blank = press Enter)",
                          ps.get("submit", DEF_SELECTORS["submit"])),
        }
        panel["selectors"] = sel
        panel["login_marker"] = ask("login_marker (selector present ONLY on the login page)",
                                    pp.get("login_marker", sel["pass"]))
        pk = pp.get("keepalive", {})
        strat = ask_choice("keep-alive strategy", ["reload", "xhr", "click", "none"],
                           pk.get("strategy", "reload"))
        ka = dict(strategy=strat)
        if strat != "none":
            ka["intervalSec"] = ask_int("  interval (seconds)", int(pk.get("intervalSec", 600)))
        if strat == "xhr":
            ka["url"] = ask("  heartbeat URL to fetch", pk.get("url", ""))
        if strat == "click":
            ka["target"] = ask("  selector to click", pk.get("target", ""))
        panel["keepalive"] = ka
        panels.append(panel)
        ok(f"panel {pid} configured")
    return panels


def section_tunnel(panels, prev) -> dict:
    step(3, 7, "autossh SSH jump-host tunnel")
    has_tunnel = any(p["mode"] == "tunnel" for p in panels)
    pt = (prev or {}).get("tunnel", {}) if prev else {}
    if not has_tunnel:
        note("No panel uses mode: tunnel.")
        if not ask_bool("Configure a tunnel anyway?", bool(pt.get("enabled", False))):
            return dict(enabled=False, jump_host="", identity="", extra_forwards=[])
    else:
        note("One or more panels are tunneled; configure the jump host.")
    jump = ask("jump host (user@host)", pt.get("jump_host", "tunneluser@jump.example.net"),
               allow_empty=False)
    ident = ask("identity key path (on the Pi)", pt.get("identity", "/etc/soc-display/keys/tunnel_ed25519"))
    return dict(enabled=True, jump_host=jump, identity=ident, extra_forwards=[])


def _fetch_cert_digest(host: str, port: int) -> str:
    if not shutil.which("openssl"):
        warn("openssl not found; skipping cert fetch")
        return ""
    try:
        p1 = subprocess.run(["openssl", "s_client", "-connect", f"{host}:{port}"],
                            input="", capture_output=True, text=True, timeout=15)
        p2 = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
                            input=p1.stdout, capture_output=True, text=True, timeout=10)
        m = re.search(r"=([0-9A-Fa-f:]+)", p2.stdout)
        if m:
            return m.group(1).replace(":", "").lower()
    except Exception as e:  # noqa: BLE001
        warn(f"cert fetch failed: {e}")
    return ""


def section_vpn(prev) -> dict:
    step(4, 7, "VPN (Fortinet / OpenVPN / WireGuard / iNode)")
    note("One supervised tunnel so VPN-side panels can use mode: direct.")
    pv = (prev or {}).get("vpn", {}) if prev else {}
    if not ask_bool("Enable a VPN?", bool(pv.get("enabled", False))):
        return dict(enabled=False)
    vtype = ask_choice("VPN type", ["fortinet", "openvpn", "wireguard", "inode"],
                       pv.get("type", "fortinet"))
    if vtype == "openvpn":
        note("Point at an .ovpn profile (carries the server + certs).")
        config = ask("path to the .ovpn profile (on the host)",
                     pv.get("config", "/etc/openvpn/soc.ovpn"), allow_empty=False)
        note("If the server needs a username/password, store them in the vault;")
        note("they are injected over OpenVPN's management socket (never on disk).")
        vault_item = ask("vault item for user/pass (blank = certificate-only)",
                         pv.get("vault_item", ""))
        probe = ask("ready_probe host:port the host waits on (blank = none)",
                    pv.get("ready_probe", ""),
                    validate=lambda s: None if not s.strip() else v_hostport(s))
        return dict(enabled=True, type="openvpn", config=config, vault_item=vault_item,
                    ready_probe=probe, set_routes=bool(pv.get("set_routes", True)),
                    extra_args=[])
    if vtype == "wireguard":
        note("Point at a wg .conf (or a bare interface name under /etc/wireguard).")
        note("Keys live in the .conf — chmod 0600 it; there is no interactive login.")
        config = ask("path to the WireGuard .conf",
                     pv.get("config", "/etc/wireguard/wg0.conf"), allow_empty=False)
        probe = ask("ready_probe host:port the host waits on (blank = none)",
                    pv.get("ready_probe", ""),
                    validate=lambda s: None if not s.strip() else v_hostport(s))
        hc = ask_int("liveness check interval (s, 0 = handshake-based)",
                     int(pv.get("health_check_interval", 30)), lo=0)
        return dict(enabled=True, type="wireguard", config=config,
                    ready_probe=probe, health_check_interval=hc,
                    health_check_failures=int(pv.get("health_check_failures", 3)))

    if vtype == "inode":
        note("H3C iNode SSL-VPN, driven headlessly via the bundled svpn-connect.sh.")
        gateway = ask("iNode SSL-VPN gateway host", pv.get("gateway", "vpn.example.com"),
                      allow_empty=False, validate=v_host)
        port = ask_int("gateway port", int(pv.get("port", 443)))
        vault_item = ask("vault item (SSL-VPN username + password)",
                         pv.get("vault_item", "SOC iNode VPN"), allow_empty=False)
        note("Leave config blank to use the iNode client bundled with the wall "
             "(vendor/iNode-VPN-Client).")
        config = ask("iNode client dir (blank = bundled)", pv.get("config", ""))
        domain = ask("auth domain (blank if none)", pv.get("domain", ""))
        note("Self-signed gateway: pin its sha256 (AA:BB:.. form), or allow insecure.")
        trusted = ask("trusted_cert sha256 pin (blank = none)", pv.get("trusted_cert", ""))
        insecure = False
        if not trusted:
            insecure = ask_bool("skip TLS verification (insecure — trusted LAN only)?",
                                bool(pv.get("insecure", False)))
        probe = ask("ready_probe host:port the host waits on (blank = none)",
                    pv.get("ready_probe", ""),
                    validate=lambda s: None if not s.strip() else v_hostport(s))
        hc = ask_int("liveness check interval (s, 0 = off)",
                     int(pv.get("health_check_interval", 60)), lo=0) if probe else 0
        return dict(enabled=True, type="inode", gateway=gateway, port=port,
                    vault_item=vault_item, config=config, domain=domain,
                    trusted_cert=trusted, insecure=insecure, ready_probe=probe,
                    health_check_interval=hc,
                    health_check_failures=int(pv.get("health_check_failures", 3)),
                    extra_args=[])

    note("openfortivpn logs in with FortiGate creds from the vault and brings up the route.")
    gateway = ask("FortiGate gateway host", pv.get("gateway", "vpn.example.com"),
                  allow_empty=False, validate=v_host)
    port = ask_int("gateway port", int(pv.get("port", 443)))
    vault_item = ask("vault item (FortiGate username + password)",
                     pv.get("vault_item", "SOC FortiGate VPN"), allow_empty=False)
    trusted = pv.get("trusted_cert", "")
    if ask_bool("Pin the gateway certificate (recommended)?", True):
        if not ASSUME_DEFAULTS and ask_bool(f"  Fetch the sha256 digest from {gateway}:{port} now?", True):
            d = _fetch_cert_digest(gateway, port)
            if d:
                trusted = d
                ok(f"pinned cert {d[:16]}…")
        if not trusted:
            trusted = ask("  trusted_cert sha256 digest (paste, or leave blank)", trusted,
                          validate=v_sha256)
    realm = ask("realm (blank if none)", pv.get("realm", ""))
    note("Routing: accepting gateway routes can pull ALL traffic over the VPN.")
    set_routes = ask_bool("accept routes pushed by the gateway?", bool(pv.get("set_routes", True)))
    half = ask_bool("keep your own default route (half-internet-routes)?",
                    bool(pv.get("half_internet_routes", False)))
    set_dns = ask_bool("use DNS pushed by the gateway?", bool(pv.get("set_dns", False)))
    note("Reconnects: 0 (recommended) lets the supervisor reconnect with backoff")
    note("and long holds on auth/cert failures; >0 = openfortivpn retries blindly.")
    persistent = ask_int("in-process auto-reconnect interval (s, 0 = supervisor-managed)",
                         int(pv.get("persistent", 0)))
    otp = ask_bool("pull a TOTP 2FA code from the vault item (rbw code)?", bool(pv.get("otp_from_vault", False)))
    probe = ask("ready_probe host:port the host waits on (blank = none)", pv.get("ready_probe", ""),
                validate=lambda s: None if not s.strip() else v_hostport(s))
    hc_int, hc_fail = 0, 3
    if probe:
        note("The supervisor can keep probing this while connected and reconnect")
        note("when it goes stale (catches a dead-but-connected tunnel).")
        hc_int = ask_int("liveness check interval (s, 0 = off)",
                         int(pv.get("health_check_interval", 60)), lo=0)
        if hc_int:
            hc_fail = ask_int("  consecutive failures before reconnecting",
                              int(pv.get("health_check_failures", 3)), lo=1)
    return dict(enabled=True, type="fortinet", gateway=gateway, port=port,
                vault_item=vault_item, trusted_cert=trusted, realm=realm,
                set_routes=set_routes, set_dns=set_dns,
                half_internet_routes=half, persistent=persistent, otp_from_vault=otp,
                ready_probe=probe, health_check_interval=hc_int,
                health_check_failures=hc_fail, extra_args=[])


def section_proxy(prev) -> dict:
    step(5, 7, "Outbound proxy")
    note("Route panel traffic through a corporate HTTP(S)/SOCKS proxy.")
    pp = (prev or {}).get("proxy", {}) if prev else {}
    if not ask_bool("Use an outbound proxy?", bool(pp.get("enabled", False))):
        return dict(enabled=False)
    url = ask("proxy URL (scheme://host:port)",
              pp.get("url", "http://proxy.example.com:3128"), allow_empty=False,
              validate=lambda s: None if re.match(
                  r"^(https?|socks[45]?)://[^\s/:]+:\d+/?$", s)
                  else "want scheme://host:port (http/https/socks5)")
    note("If the proxy requires a username/password, store them as a vault login —")
    note("they are answered to the proxy challenge in memory, never written anywhere.")
    vault_item = ask("vault item with the proxy credentials (blank = no auth)",
                     pp.get("vault_item", ""))
    raw = ask("extra hosts to bypass, comma-separated (loopback always bypasses)",
              ", ".join(pp.get("ignore_hosts") or []))
    ignore = [h.strip() for h in raw.split(",") if h.strip()]
    return dict(enabled=True, url=url, vault_item=vault_item, ignore_hosts=ignore)


def section_vault(paths, prev_env, has_vpn) -> dict:
    step(6, 7, "Secrets vault (rbw / Vaultwarden)")
    e = dict(prev_env)
    note("The kiosk reads every login — and its own config — from Vaultwarden via")
    note("rbw (or a JSON file in dev). No secret is written to any .env: the master")
    note("password is sealed host-bound under $SOC_SECRET_DIR; first-run / deploy")
    note("generates the one-time PIN and seals it.")
    backend = ask_choice("vault backend", ["rbw", "dev"], e.get("SOC_VAULT_BACKEND", paths["default_backend"]))
    e["SOC_VAULT_BACKEND"] = backend
    if backend == "dev":
        note("Dev backend reads dev/run/dev-vault.json — no Vaultwarden needed.")
        e.setdefault("SOC_VAULT_EMAIL", "kiosk@soc.local")
        e.setdefault("SOC_VAULT_URL", "http://127.0.0.1:8222")
    else:
        e["SOC_VAULT_EMAIL"] = ask("vault account email",
                                   e.get("SOC_VAULT_EMAIL", "kiosk@soc.local"),
                                   allow_empty=False, validate=v_email)
        e["SOC_VAULT_URL"] = ask("Vaultwarden URL",
                                 e.get("SOC_VAULT_URL", "http://127.0.0.1:8222"),
                                 allow_empty=False, validate=v_url)
        note("Master password: sealed at first-run (setup.py first-run / deploy),")
        note("never written in cleartext. Re-run first-run to change/re-seal it.")
    e["SOC_SECRET_DIR"] = paths["secret_dir"]
    e["SOC_CONFIG_VAULT_ITEM"] = e.get(
        "SOC_CONFIG_VAULT_ITEM", paths.get("config_vault_item", "SOC Wall Config"))
    e["SOC_ROOT"] = paths["soc_root"]
    e["SOC_PANELS_FILE"] = paths["panels_installed"]
    e["SOC_INJECT_TMPL"] = paths["inject_tmpl"]
    e.setdefault("SOC_LAUNCH_STAGGER", "1.5")
    e.setdefault("SOC_READY_TIMEOUT", "120")
    e.setdefault("SOC_CDP_BASE_PORT", "9222")
    e.setdefault("SOC_CRED_TTL", "30")
    e["SOC_VPN_DRY_RUN"] = "0"
    note("Display stack: auto tries Wayland -> XWayland -> XLibre -> Xorg.")
    note("Or force one: wayland | xwayland | xlibre | xorg | x11.")
    e["SOC_SESSION"] = ask_choice(
        "display stack", ["auto", "wayland", "xwayland", "xlibre", "xorg", "x11"],
        e.get("SOC_SESSION", "auto"))
    return e


def section_server(paths, dry) -> dict | None:
    step(7, 7, "Vaultwarden server")
    if not ask_bool("Configure the Vaultwarden server file (vaultwarden.env)?", True):
        note("Skipped — only needed on the host that runs Vaultwarden.")
        return None
    prev = load_env_file(paths["vw_env"])
    e = dict(prev)
    e.setdefault("DATA_FOLDER", "/var/lib/vaultwarden")
    e["ROCKET_ADDRESS"] = ask("bind address (keep on localhost)", e.get("ROCKET_ADDRESS", "127.0.0.1"))
    e["ROCKET_PORT"] = ask("port", e.get("ROCKET_PORT", "8222"))
    e["SIGNUPS_ALLOWED"] = "true" if ask_bool("allow signups now (turn off after creating the account)?",
                                              e.get("SIGNUPS_ALLOWED", "false") == "true") else "false"
    e.setdefault("SIGNUPS_VERIFY", "false")
    e.setdefault("WEBSOCKET_ENABLED", "false")
    token = e.get("ADMIN_TOKEN", "")
    if ask_bool("Generate an admin token now (needs vaultwarden or docker)?", not token):
        token = _gen_admin_token() or token
    e["ADMIN_TOKEN"] = token
    return e


def _gen_admin_token() -> str:
    import getpass
    pw = getpass.getpass("   admin password to hash: ") if not ASSUME_DEFAULTS else ""
    if not pw:
        return ""
    if shutil.which("vaultwarden"):
        cmd = ["vaultwarden", "hash", "--preset", "owasp"]
        try:
            r = subprocess.run(cmd, input=pw + "\n" + pw + "\n", capture_output=True, text=True, timeout=30)
            m = re.search(r"\$argon2\S+", r.stdout)
            if m:
                return m.group(0)
        except Exception:
            pass
    if shutil.which("docker"):
        try:
            r = subprocess.run(["docker", "run", "--rm", "-i", "vaultwarden/server:latest",
                                "/vaultwarden", "hash", "--preset", "owasp"],
                               input=pw + "\n" + pw + "\n", capture_output=True, text=True, timeout=120)
            m = re.search(r"\$argon2\S+", r.stdout)
            if m:
                return m.group(0)
        except Exception:
            pass
    warn("could not generate a hash here — run `vaultwarden hash` later and paste it in")
    return ""


# --------------------------------------------------------------------------- #
# Post-write validation + actions
# --------------------------------------------------------------------------- #
def validate_panels(panels_path: str):
    sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    try:
        from host import config as hostcfg  # type: ignore
    except Exception as e:  # noqa: BLE001 — PyYAML/host not importable (e.g. no venv yet)
        note(f"skipping config validation ({e.__class__.__name__}); run `make test` later")
        return
    try:
        conf = hostcfg.load(panels_path)
        geoms = [f"{p.id}:{p.geometry.w}x{p.geometry.h}+{p.geometry.x}+{p.geometry.y}"
                 for p in conf.panels]
        ok(f"config parses — {len(conf.panels)} panels, "
           f"tunnel={'on' if conf.tunnel.get('enabled') else 'off'}, "
           f"vpn={'on' if (conf.vpn or {}).get('enabled') else 'off'}")
        note("geometry: " + "  ".join(geoms))
    except Exception as e:  # noqa: BLE001
        err(f"generated config did NOT parse: {e}")


def _run(cmd: list, cwd=REPO):
    print(dim("   $ " + " ".join(cmd)))
    try:
        return subprocess.run(cmd, cwd=cwd).returncode
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError:
        err(f"command not found: {cmd[0]}")
        return 127


def post_actions(env: Env, cfg: dict, target: str, dry: bool):
    banner("Next actions")
    if dry:
        note("dry-run: skipping actions")
        return
    if env.has_apt and ask_bool("Run the installer (sudo ./install.sh) now?", False):
        installer = os.path.join(REPO, "install.sh")
        _run((["./install.sh"] if env.is_root else ["sudo", "./install.sh"]))
    if target == "dev":
        if ask_bool("Seed the dev vault (make dev-vault)?", True):
            _run(["make", "dev-vault"])
        if cfg["vpn"].get("enabled") and ask_bool("Dry-run the VPN wiring (make vpn-check)?", True):
            _run(["make", "vpn-check"])
        if ask_bool("Run the headless end-to-end check (make verify)?", False):
            _run(["make", "verify"])
        if ask_bool("Launch the wall now in a window (make dev)?", False):
            _run(["make", "dev"])
    else:
        note("On the Pi, finish: start Vaultwarden, create the account, then store")
        note("the logins with:  python3 setup.py creds   (or add them in the web vault).")
        note("Check everything with:  python3 setup.py doctor   then reboot.")


# --------------------------------------------------------------------------- #
# Credential writing (store usernames/passwords IN Vaultwarden)
# --------------------------------------------------------------------------- #
def _vault_items(cfg: dict):
    """(kind, vault_item, uri) for every configured item that needs a login."""
    items = []
    for p in cfg.get("panels", []):
        if p.get("vault_item"):
            items.append(("panel", p["vault_item"], p.get("url", "")))
    v = cfg.get("vpn") or {}
    if v.get("enabled") and v.get("vault_item"):
        items.append(("vpn", v["vault_item"], ""))
    pr = cfg.get("proxy") or {}
    if pr.get("enabled") and pr.get("vault_item"):
        items.append(("proxy", pr["vault_item"], pr.get("url", "")))
    return items


def store_credentials(soc_env: dict, cfg: dict, dry: bool):
    """Write each item's username+password into Vaultwarden (vaultseed). Run this
    AFTER Vaultwarden is up + the account exists. Operator can skip + add by hand."""
    banner("Store credentials in Vaultwarden")
    if (soc_env or {}).get("SOC_VAULT_BACKEND") != "rbw":
        note("vault backend is not 'rbw' — credentials live in the dev JSON; skipping.")
        return
    url = soc_env.get("SOC_VAULT_URL", "")
    email = soc_env.get("SOC_VAULT_EMAIL", "")
    pw = soc_env.get("SOC_VAULT_PASSWORD", "")
    items = _vault_items(cfg)
    if not items:
        note("no vault items configured.")
        return
    note("Store each login's username + password directly in Vaultwarden, or skip")
    note("and create them yourself in the web vault (names must match vault_item).")
    if not ask_bool("Store credentials in Vaultwarden now?", False):
        note("Skipped. Create logins in the web vault named: "
             + ", ".join(repr(n) for _, n, _ in items))
        return

    sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    try:
        from host import vaultseed  # type: ignore
    except Exception as e:  # noqa: BLE001
        err(f"cannot load the vault writer ({e}); add the logins in the web vault")
        return
    if not vaultseed.available():
        err("the 'cryptography' package is not installed — `pip install cryptography` "
            "(or add the logins in the web vault) and re-run")
        return
    if not pw:
        pw = _unseal_master(soc_env.get("SOC_SECRET_DIR"),
                            "vault master password (to write the logins)")
    if not (url and email and pw):
        warn("need the Vaultwarden URL, email and master password — skipping")
        return

    for kind, name, uri in items:
        note(f"— {name} ({kind})")
        user = ask(f"  username for '{name}' (blank = skip)", "")
        if not user:
            note("  skipped")
            continue
        secret = ask_secret(f"  password for '{name}'")
        if dry:
            print(yellow(f"   [dry-run] would store login '{name}' (user={user})"))
            secret = ""
            continue
        try:
            action = vaultseed.upsert_login(url, email, pw, name, user, secret,
                                            uri=uri or None)
            ok(f"  {action} '{name}'")
        except vaultseed.VaultSeedError as e:
            err(f"  could not write '{name}': {e}")
        secret = ""  # scrub
    pw = ""  # scrub


# --------------------------------------------------------------------------- #
# doctor — diagnose; repair — fix; install — orchestrate
# --------------------------------------------------------------------------- #
class _Doc:
    def __init__(self):
        self.fails = 0
        self.warns = 0

    def check(self, name, fn):
        try:
            status, msg, fix = fn()
        except Exception as e:  # noqa: BLE001
            status, msg, fix = "FAIL", f"{e.__class__.__name__}: {e}", ""
        icon = {"OK": green("✓"), "WARN": yellow("!"), "FAIL": red("✗")}[status]
        print(f"   {icon} {bold(name)}: {msg}")
        if fix and status != "OK":
            print(dim(f"       → {fix}"))
        if status == "FAIL":
            self.fails += 1
        elif status == "WARN":
            self.warns += 1


def _have(b):
    return shutil.which(b) is not None


def _probe_venv(venv_py):
    probe = (
        "import yaml, websocket, gi\n"
        "gi.require_version('Gtk','3.0')\n"
        "from gi.repository import Gtk\n"
        "ok=False\n"
        "for v in ('4.1','4.0'):\n"
        "  try:\n"
        "    gi.require_version('WebKit2', v); from gi.repository import WebKit2; ok=True; break\n"
        "  except Exception: pass\n"
        "assert ok, 'WebKit2 typelib missing'\n"
        "print('ok')\n")
    try:
        r = subprocess.run([venv_py, "-c", probe], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return "FAIL", f"venv python not runnable ({e})", "run: setup.py repair"
    if r.returncode == 0 and "ok" in r.stdout:
        return "OK", "venv + gi/WebKit2/yaml/websocket import", ""
    return "FAIL", (r.stderr.strip().splitlines() or ["import error"])[-1], \
        "run: setup.py repair  (recreates venv --system-site-packages + deps)"


def _alive(url):
    import urllib.request
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/alive", timeout=4) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def cmd_doctor(args) -> int:
    env = Env()
    target = args.target or ("pi" if env.is_root else "dev")
    paths = resolve_paths(target)
    soc_env = load_env_file(paths["soc_env"])
    banner("SOC video-wall · doctor")
    print(f"   target {bold(target)}   soc.env {paths['soc_env']}")
    d = _Doc()

    d.check("venv + Python deps", lambda: _probe_venv(paths.get("soc_root", REPO) + "/.venv/bin/python")
            if os.path.exists(paths.get("soc_root", REPO) + "/.venv/bin/python")
            else _probe_venv(env.venv_py))

    backend = soc_env.get("SOC_VAULT_BACKEND", paths["default_backend"])
    d.check("rbw (Vaultwarden CLI)", lambda: (
        ("OK", "on PATH", "") if _have("rbw")
        else ("WARN" if backend != "rbw" else "FAIL",
              "not installed", "cargo install rbw  (or your package manager)")))

    # display stack for SOC_SESSION
    sess = soc_env.get("SOC_SESSION", "auto")
    def _disp():
        wl = _have("cage") or _have("labwc")
        x = _have("Xorg") or _have("X") or _have("Xlibre")
        if sess in ("wayland", "xwayland"):
            return ("OK", "compositor present", "") if wl else \
                ("FAIL", "no Wayland compositor", "install labwc or cage")
        if sess in ("xorg", "xlibre", "x11"):
            return ("OK", "X server present", "") if x else \
                ("FAIL", "no X server", "install xorg/xlibre + xinit + openbox")
        # auto
        return ("OK", f"available (wayland={wl} x11={x})", "") if (wl or x) else \
            ("FAIL", "no display stack", "install labwc/cage or xorg")
    d.check(f"display stack (SOC_SESSION={sess})", _disp)

    # VPN client for the configured type
    try:
        sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
        from host import config as hostcfg  # type: ignore
        conf = hostcfg.load(paths["panels_installed"])
        d.check("panels.yaml parses", lambda: (
            "OK", f"{len(conf.panels)} panels"
            + (f", {len(conf.warnings)} warning(s)" if conf.warnings else ""), ""))
        vpn = conf.vpn or {}
        if vpn.get("enabled"):
            kind = hostcfg.vpn_kind(vpn)
            if kind == "inode":
                script = hostcfg.inode_script(vpn)
                d.check("iNode client (svpn-connect.sh)", lambda: (
                    ("OK", script, "")
                    if os.path.isfile(script) and os.access(script, os.X_OK)
                    else ("FAIL", f"missing/not executable: {script}",
                          "ship vendor/iNode-VPN-Client or set vpn.config")))
                d.check("tesseract (iNode login CAPTCHA)", lambda: (
                    ("OK", "on PATH", "") if _have("tesseract")
                    else ("WARN", "not installed", "install tesseract-ocr — the "
                          "gateway CAPTCHA cannot be auto-solved without it")))
            else:
                need = {"fortinet": "openfortivpn", "openvpn": "openvpn",
                        "wireguard": "wg-quick"}[kind]
                d.check(f"VPN client ({kind})", lambda: (
                    ("OK", f"{need} present", "") if _have(need)
                    else ("FAIL", f"{need} not installed",
                          f"install {need} (setup.py repair)")))
        # autossh tunnel: the binary + the restricted key (when panels are tunneled)
        if any(p.mode == "tunnel" for p in conf.panels) and conf.tunnel.get("enabled", True):
            d.check("autossh (SSH jump-host tunnel)", lambda: (
                ("OK", "on PATH", "") if _have("autossh")
                else ("FAIL", "not installed",
                      "install autossh (setup.py repair / install.sh)")))
            ident = conf.tunnel.get("identity", "")
            d.check("tunnel identity key", lambda: (
                ("OK", ident, "") if ident and os.path.exists(os.path.expanduser(ident))
                else ("FAIL", f"missing: {ident or '(unset)'}",
                      "setup.py repair  (generates a restricted ed25519 key)")))
    except Exception as e:  # noqa: BLE001
        d.check("panels.yaml parses", lambda: ("FAIL", str(e),
                "fix the config / run the wizard: setup.py"))

    # vault reachability + master password sanity
    if backend == "rbw":
        url = soc_env.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        d.check("Vaultwarden reachable", lambda: (
            ("OK", url, "") if _alive(url)
            else ("WARN", f"{url} not answering /alive",
                  "start it: systemctl start vaultwarden")))
        # host-bound sealed master password (no plaintext .env)
        sec = soc_env.get("SOC_SECRET_DIR") or "/etc/soc-display/secret"

        def _seal():
            sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
            try:
                from host import secretstore  # type: ignore
            except Exception as e:  # noqa: BLE001
                return ("FAIL", f"secretstore import failed: {e}", "setup.py repair")
            if not secretstore.available():
                return ("FAIL", "cryptography not installed",
                        "pip install cryptography (setup.py repair)")
            if soc_env.get("SOC_VAULT_PASSWORD"):
                return ("WARN", "plaintext SOC_VAULT_PASSWORD still in soc.env",
                        "remove it, then: setup.py first-run  (seals it host-bound)")
            if secretstore.is_sealed(sec):
                try:
                    secretstore.unseal(sec)
                    return ("OK", f"sealed + unseals on this host ({sec})", "")
                except Exception as e:  # noqa: BLE001
                    return ("FAIL",
                            f"sealed but cannot unseal ({e}) — machine-id changed?",
                            "re-run: setup.py first-run  (re-seal with your PIN)")
            return ("FAIL", f"no sealed master password in {sec}",
                    "run: setup.py first-run  (one-time PIN + seal)")
        d.check("vault master password (sealed)", _seal)
        # the wall config is the vault's secure-note; the local file is a fallback
        item = soc_env.get("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config")
        d.check("config source", lambda: (
            "OK", f"vault note '{item}' (local file fallback)", ""))

    # file perms
    for f, want in ((paths["soc_env"], 0o640), (paths["vw_env"], 0o600)):
        if os.path.exists(f):
            d.check(f"perms {os.path.basename(f)}", (lambda f=f, want=want: (
                ("OK", oct(os.stat(f).st_mode & 0o777), "")
                if (os.stat(f).st_mode & 0o777) <= want
                else ("WARN", oct(os.stat(f).st_mode & 0o777),
                      f"chmod {oct(want)[2:]} {f}"))))

    # systemd units
    if _have("systemctl") and os.path.isdir("/run/systemd/system"):
        for unit in ("vaultwarden", "forti-vpn", "autossh-tunnel"):
            d.check(f"unit {unit}", (lambda u=unit: (
                lambda s: ("OK", s, "") if s == "active"
                else ("WARN", s, f"systemctl status {u}"))(
                subprocess.run(["systemctl", "is-active", u], capture_output=True,
                               text=True).stdout.strip() or "unknown")))

    print()
    if d.fails:
        print(red(f"   {d.fails} problem(s), {d.warns} warning(s) — run: setup.py repair"))
        return 1
    print(green(f"   all good ({d.warns} warning(s))"))
    return 0


def cmd_repair(args) -> int:
    env = Env()
    target = args.target or ("pi" if env.is_root else "dev")
    paths = resolve_paths(target)
    root = paths.get("soc_root", REPO)
    banner("SOC video-wall · repair")
    note("Fixes what doctor flags. Some steps need root/network.")

    # 1) venv + python deps
    venv_py = os.path.join(root, ".venv", "bin", "python")
    if _probe_venv(venv_py)[0] != "OK" and ask_bool("Recreate the venv + install Python deps?", True):
        _run(["python3", "-m", "venv", "--system-site-packages",
              os.path.join(root, ".venv")])
        _run([venv_py, "-m", "pip", "install", "-q", "--upgrade", "pip"])
        _run([venv_py, "-m", "pip", "install", "-q",
              "PyYAML", "websocket-client", "cryptography"])

    # 2) OS packages via the installer's deps-only mode
    if env.has_apt or _have("dnf") or _have("pacman") or _have("zypper") \
            or _have("apk") or _have("xbps-install"):
        if ask_bool("Install missing OS packages (runs install.sh --deps-only)?", True):
            _run(["./install.sh", "--deps-only"] if env.is_root
                 else ["sudo", "./install.sh", "--deps-only"])

    # 3) rbw
    if not _have("rbw") and ask_bool("Install rbw via cargo (needs rust)?", False):
        _run(["cargo", "install", "rbw"])

    # 3b) sealed-secret dir + rbw pinentry (the no-plaintext-.env unlock path)
    soc_env = load_env_file(paths["soc_env"])
    if soc_env.get("SOC_VAULT_BACKEND", paths["default_backend"]) == "rbw":
        sd = paths["secret_dir"]
        try:
            os.makedirs(sd, exist_ok=True)
            os.chmod(sd, 0o700)
            ok(f"secret dir {sd} (0700)")
        except OSError as e:
            warn(f"could not create {sd}: {e}")
        if _have("rbw"):
            _run(["rbw", "config", "set", "pinentry", paths["pinentry"]])
            ok("rbw pinentry -> pinentry-vault.py")

    # 4) file perms
    for f, mode in ((paths["soc_env"], 0o640), (paths["vw_env"], 0o600)):
        if os.path.exists(f) and not env.is_root and target == "pi":
            note(f"(need root to chmod {f})")
        elif os.path.exists(f):
            try:
                os.chmod(f, mode)
                ok(f"chmod {oct(mode)[2:]} {os.path.basename(f)}")
            except OSError as e:
                warn(f"could not chmod {f}: {e}")

    # 5) tunnel key
    try:
        sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
        from host import config as hostcfg  # type: ignore
        conf = hostcfg.load(paths["panels_installed"])
        ident = conf.tunnel.get("identity", "")
        if (any(p.mode == "tunnel" for p in conf.panels)
                and conf.tunnel.get("enabled", True) and ident
                and not os.path.exists(os.path.expanduser(ident))
                and ask_bool(f"Generate the restricted tunnel key {ident}?", True)):
            ident = os.path.expanduser(ident)
            os.makedirs(os.path.dirname(ident), exist_ok=True)
            _run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "soc-wall-tunnel",
                  "-f", ident])
            try:
                os.chmod(ident, 0o600)
            except OSError:
                pass
            jump = conf.tunnel.get("jump_host", "<jump-host>")
            note(f"add the public key to {jump}'s authorized_keys with a restriction, e.g.:")
            print(dim('   restrict,permitopen="HOST:PORT",command="/usr/sbin/nologin" '
                      + f'$(cat {ident}.pub)'))
    except Exception as e:  # noqa: BLE001
        note(f"(skipping tunnel-key step: {e})")

    print()
    note("re-run `setup.py doctor` to confirm.")
    return 0


def cmd_install(args) -> int:
    env = Env()
    banner("SOC video-wall · install (full)")
    note("Runs the OS installer, then the config wizard, then doctor.")
    if not env.is_root:
        warn("the OS install needs root — you'll be prompted for sudo.")
    if ask_bool("Run the OS installer (install.sh) now?", True):
        rc = _run(["./install.sh"] if env.is_root else ["sudo", "./install.sh"])
        if rc not in (0, None):
            err("install.sh failed — fix the error above, then re-run setup.py install")
            return rc or 1
    if ask_bool("Run the configuration wizard now?", True):
        cmd_wizard(args)
    note("Now: start Vaultwarden, create the account, then `setup.py creds` to store logins.")
    return cmd_doctor(args)


def cmd_menu(args) -> int:
    """Interactive launcher — the default when run with no subcommand on a TTY."""
    env = Env()
    target = args.target or ("pi" if env.is_root else "dev")
    banner("SOC video-wall · setup")
    print(f"   target   : {bold(target)}  "
          f"({'Raspberry Pi / root' if target == 'pi' else 'dev workstation'})")
    print(f"   detected : root={env.is_root} apt={env.has_apt} pi={env.is_pi} "
          f"venv={env.has_venv} rbw={_have('rbw')}")
    options = [
        ("deploy", "Deploy", "full automated install + configure + seal PIN + credentials"),
        ("clean", "Clean deploy", "wipe generated config/state, then deploy fresh"),
        ("wizard", "Configure", "edit panels, vault, VPN, proxy (writes the config files)"),
        ("first-run", "First-time setup", "generate the one-time PIN + seal the master password"),
        ("doctor", "Diagnose", "check this install and report problems"),
        ("repair", "Repair", "install missing packages / venv / keys doctor flagged"),
        ("creds", "Credentials", "store panel / VPN / proxy logins in Vaultwarden"),
        ("quit", "Quit", "exit without changes"),
    ]
    print()
    print("   What would you like to do?")
    for i, (_key, label, desc) in enumerate(options, 1):
        print(f"     {i}) {bold(label)} {dim('— ' + desc)}")
    keys = [o[0] for o in options]
    while True:
        raw = _readline(f"   choose 1-{len(options)} [1]: ").strip().lower()
        if raw == "":
            choice = options[0][0]
            break
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            choice = options[int(raw) - 1][0]
            break
        if raw in keys:
            choice = raw
            break
        warn("pick one of the listed numbers")
    if choice == "quit":
        note("nothing to do — bye")
        return 0
    if choice == "clean":
        args.clean = True
        return cmd_deploy(args)
    return {"deploy": cmd_deploy, "wizard": cmd_wizard, "doctor": cmd_doctor,
            "repair": cmd_repair, "creds": cmd_creds,
            "first-run": cmd_firstrun}[choice](args)


def _unseal_master(secret_dir, prompt_label=None) -> str:
    """Recover the vault master password WITHOUT a plaintext .env: unseal the
    host-bound secret; if that is not possible, optionally ask. '' if neither."""
    if secret_dir:
        sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
        try:
            from host import secretstore  # type: ignore
            if secretstore.is_sealed(secret_dir):
                return secretstore.unseal(secret_dir)
        except Exception as e:  # noqa: BLE001
            note(f"(could not unseal the master password: {e})")
    return ask_secret(prompt_label) if prompt_label else ""


def cmd_firstrun(args) -> int:
    """First-time setup: generate a one-time PIN, seal the vault master password
    host-bound (no plaintext .env), point rbw at the unsealing pinentry. Asks
    before overwriting an existing seal; re-runnable to change the password."""
    env = Env()
    target = args.target or ("pi" if env.is_root else "dev")
    paths = resolve_paths(target)
    soc_env = load_env_file(paths["soc_env"])
    banner("SOC video-wall · first-time setup (PIN + seal)")
    if soc_env.get("SOC_VAULT_BACKEND", paths["default_backend"]) != "rbw":
        note("vault backend is 'dev' — no sealing needed (dev reads the JSON vault).")
        return 0
    sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    try:
        from host import secretstore  # type: ignore
    except Exception as e:  # noqa: BLE001
        err(f"cannot load the secret store ({e})")
        return 1
    if not secretstore.available():
        err("the 'cryptography' package is required to seal the master password "
            "(pip install cryptography)")
        return 1

    sd = paths["secret_dir"]
    do_seal = True
    if secretstore.is_sealed(sd):
        do_seal = ask_bool(f"A sealed secret already exists in {sd}. Re-seal (new PIN)?", False)
    if do_seal:
        master = ask_secret("vault master password (sealed, never stored in clear)")
        if not master:
            err("no master password entered — nothing sealed")
            return 1
        pin = ask("one-time PIN (blank = generate a random one)", "") or secretstore.gen_pin()
        if args.dry_run:
            print(yellow(f"   [dry-run] would seal the master password to {sd}"))
        else:
            try:
                secretstore.seal(master, pin, sd)
            except secretstore.SecretStoreError as e:
                err(f"could not seal: {e}")
                return 1
            ok(f"sealed the master password (host-bound) -> {sd}")
        master = ""  # scrub
        banner("YOUR ONE-TIME PIN")
        print()
        print("        " + bold(green("  ".join(pin))))
        print()
        note("Write this PIN down and keep it safe. It is needed ONLY to re-seal")
        note("later (re-deploy, new hardware, or changing the master password) —")
        note("NOT for normal boots (the wall self-unlocks from the host-bound seal).")
        if not ASSUME_DEFAULTS and not args.dry_run:
            _readline("   press Enter once you have recorded the PIN ... ")
    else:
        note("kept the existing sealed secret.")

    # point rbw at the unsealing pinentry + bake email/url into rbw's own config
    if _have("rbw"):
        if soc_env.get("SOC_VAULT_EMAIL"):
            _run(["rbw", "config", "set", "email", soc_env["SOC_VAULT_EMAIL"]])
        if soc_env.get("SOC_VAULT_URL"):
            _run(["rbw", "config", "set", "base_url", soc_env["SOC_VAULT_URL"]])
        _run(["rbw", "config", "set", "pinentry", paths["pinentry"]])
        ok("rbw configured (email / base_url / pinentry -> pinentry-vault.py)")
    else:
        warn("rbw is not on PATH — install it, then re-run first-run to configure it")
    return 0


def push_config_to_vault(soc_env, cfg, paths, dry) -> bool:
    """Store the wall config (panels/tunnel/vpn/proxy) in Vaultwarden as the
    SOC_CONFIG_VAULT_ITEM secure-note — the wall's source of truth at boot."""
    if (soc_env or {}).get("SOC_VAULT_BACKEND") != "rbw":
        note("dev backend — config stays in the local file; not pushing to the vault.")
        return False
    if not cfg.get("panels"):
        note("no panels configured — nothing to push.")
        return False
    item = (soc_env.get("SOC_CONFIG_VAULT_ITEM")
            or paths.get("config_vault_item", "SOC Wall Config"))
    if not ask_bool(f"Push the wall config into Vaultwarden as '{item}'?", True):
        note("skipped — the wall will fall back to the local config file.")
        return False
    url = soc_env.get("SOC_VAULT_URL", "")
    email = soc_env.get("SOC_VAULT_EMAIL", "")
    pw = _unseal_master(soc_env.get("SOC_SECRET_DIR"),
                        "vault master password (to push the config)")
    if not (url and email and pw):
        warn("need URL + email + master password — skipping the config push")
        return False
    yaml_text = render_panels_yaml(cfg)
    if dry:
        print(yellow(f"   [dry-run] would push {len(yaml_text)} bytes -> '{item}'"))
        return False
    sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    try:
        from host import vaultseed  # type: ignore
        action = vaultseed.upsert_login(url, email, pw, item, "", "", notes=yaml_text)
        ok(f"{action} config note '{item}' ({len(yaml_text)} bytes)")
        return True
    except Exception as e:  # noqa: BLE001
        err(f"could not push the config: {e}")
        return False


def clean_state(paths, args) -> None:
    """Remove generated config + runtime state for a fresh deploy (files are
    backed up first). Does NOT remove installed OS packages or Vaultwarden data."""
    banner("Clean (reset generated state)")
    state = os.environ.get("SOC_STATE_DIR") or (
        "/var/lib/soc-wall" if paths["mode"] == "pi"
        else os.path.join(REPO, "dev", "run", "state"))
    targets = [paths["panels_out"], paths["soc_env"], paths["vw_env"],
               paths["secret_dir"], state]
    if paths["mode"] == "dev":
        targets.append(os.path.join(REPO, "dev", "run"))
    note("will remove (files are backed up first):")
    for t in targets:
        print(dim(f"     - {t}" + ("  (exists)" if os.path.exists(t) else "  (absent)")))
    if args.dry_run:
        print(yellow("   [dry-run] nothing removed"))
        return
    if not ask_bool("Remove these now?", False):
        note("clean skipped.")
        return
    for t in targets:
        if not os.path.exists(t):
            continue
        try:
            if os.path.isdir(t):
                shutil.rmtree(t)
            else:
                backup(t)
                os.remove(t)
            ok(f"removed {t}")
        except OSError as e:
            warn(f"could not remove {t}: {e}")


def cmd_deploy(args) -> int:
    """End-to-end deployment: [clean] -> OS packages -> configure -> vault ->
    seal PIN -> push config + creds -> health check. Each step asks first, so it
    is safe to run (and re-run) interactively."""
    env = Env()
    target = args.target or ("pi" if env.is_root else "dev")
    paths = resolve_paths(target)
    banner("SOC video-wall · deploy (end to end)")
    if getattr(args, "clean", False):
        clean_state(paths, args)
    note("Walks the whole deployment. Each step asks before it runs.")
    if target == "pi" and not env.is_root:
        warn("a Pi deploy needs root for packages + services — re-run with sudo")
        warn("for the full flow; continuing with what is possible without it.")

    has_pm = (env.has_apt or _have("dnf") or _have("pacman") or _have("zypper")
              or _have("apk") or _have("xbps-install"))

    # 1) OS packages + services. Skip the slow package step when already installed
    #    (much faster); offer a fresh reinstall, or force it with --fresh.
    stamp = os.path.join(os.path.dirname(paths["soc_env"]), ".installed")
    installed = os.path.exists(stamp) or (
        os.path.exists(os.path.join(paths.get("soc_root", ""), ".venv"))
        and os.path.exists(paths["panels_installed"]))
    fresh = getattr(args, "fresh", False)
    if fresh:
        run_install = True
    elif installed:
        where = stamp if os.path.exists(stamp) else "venv + config present"
        note(f"Step 1/6 — existing install detected ({where}).")
        run_install = ask_bool("  reinstall from scratch (fresh)?  "
                               "[No = skip the OS install, much faster]", False)
        fresh = run_install
    else:
        run_install = ask_bool("Step 1/6 — install OS packages + services (install.sh)?", True)
    if run_install and has_pm:
        cmd = ["./install.sh"] + (["--fresh"] if fresh else [])
        rc = _run(cmd if env.is_root else ["sudo"] + cmd)
        if rc not in (0, None):
            err("install.sh failed — fix the error above, then re-run deploy")
            return rc or 1
    elif run_install:
        note("Step 1/6 — no known package manager; skipping OS install.")
    else:
        note("Step 1/6 — skipped the OS install (already installed; use --fresh to force).")

    # 2) configuration wizard (skip its own post-actions; deploy drives them)
    if ask_bool("Step 2/6 — configure the wall now (wizard)?", True):
        args._in_deploy = True
        try:
            cmd_wizard(args)
        finally:
            args._in_deploy = False

    cfg = _LAST_CFG or load_yaml(paths["panels_installed"]) or {}
    soc_env = _LAST_SOC_ENV or load_env_file(paths["soc_env"])
    is_rbw = (soc_env or {}).get("SOC_VAULT_BACKEND") == "rbw"

    # 3) bring Vaultwarden up (rbw backend only)
    if is_rbw:
        url = soc_env.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        if _have("systemctl") and os.path.isdir("/run/systemd/system"):
            if ask_bool("Step 3/6 — start Vaultwarden (systemctl start vaultwarden)?",
                        target == "pi"):
                _run(["systemctl", "start", "vaultwarden"] if env.is_root
                     else ["sudo", "systemctl", "start", "vaultwarden"])
                for _ in range(20):
                    if _alive(url):
                        ok(f"Vaultwarden answering at {url}")
                        break
                    time.sleep(1)
                else:
                    warn(f"{url} not answering /alive yet — check it before continuing")
        else:
            note("Step 3/6 — no systemd; start Vaultwarden via your init manager.")
        note("Create the kiosk account in the web vault (signups on) if not done yet.")
    else:
        note("Step 3/6 — dev vault backend; no Vaultwarden server needed.")

    # 4) first-time setup: seal the master password under a one-time PIN
    if is_rbw:
        if ask_bool("Step 4/6 — first-time setup: seal the master password (PIN)?", True):
            cmd_firstrun(args)
            soc_env = load_env_file(paths["soc_env"])
    else:
        note("Step 4/6 — dev backend; no PIN / seal needed.")

    # 5) push the config into the vault + store the logins
    if is_rbw:
        note("Step 5/6 — store the config + logins in Vaultwarden")
        push_config_to_vault(soc_env, cfg, paths, args.dry_run)
    if cfg.get("panels"):
        store_credentials(soc_env, cfg, args.dry_run)
    else:
        note("Step 5/6 — no panels configured; skipping credential storage.")

    # 6) health check
    note("Step 6/6 — health check (doctor)")
    rc = cmd_doctor(args)

    banner("Deploy complete")
    if target == "pi":
        note("If doctor is clean, reboot to bring up the wall:  systemctl reboot")
    else:
        note("Dev: launch the wall with  make dev   (headless check:  make verify)")
    return rc


def cmd_creds(args) -> int:
    env = Env()
    target = args.target or ("pi" if env.is_root else "dev")
    paths = resolve_paths(target)
    soc_env = load_env_file(paths["soc_env"])
    cfg = load_yaml(paths["panels_installed"]) or {}
    if not cfg.get("panels"):
        err(f"no config found at {paths['panels_installed']} — run the wizard first")
        return 1
    store_credentials(soc_env, cfg, args.dry_run)
    return 0


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def resolve_paths(target: str) -> dict:
    if target == "pi":
        return dict(
            mode="pi",
            panels_out="/etc/soc-display/panels.yaml",
            panels_installed="/etc/soc-display/panels.yaml",
            soc_env="/etc/soc-display/soc.env",
            vw_env="/etc/soc-display/vaultwarden.env",
            soc_root="/opt/soc-display",
            pinentry="/opt/soc-display/scripts/pinentry-vault.py",
            secret_dir="/etc/soc-display/secret",
            config_vault_item="SOC Wall Config",
            inject_tmpl="/opt/soc-display/inject/login.js.tmpl",
            default_backend="rbw",
            panels_mode=0o644, env_mode=0o640, vw_mode=0o600,
        )
    return dict(
        mode="dev",
        panels_out=os.path.join(REPO, "config", "panels.local.yaml"),
        panels_installed=os.path.join(REPO, "config", "panels.local.yaml"),
        soc_env=os.path.join(REPO, ".env"),
        vw_env=os.path.join(REPO, "vaultwarden.env"),
        soc_root=REPO,
        pinentry=os.path.join(REPO, "scripts", "pinentry-vault.py"),
        secret_dir=os.path.join(REPO, "dev", "run", "secret"),
        config_vault_item="SOC Wall Config",
        inject_tmpl=os.path.join(REPO, "inject", "login.js.tmpl"),
        default_backend="dev",
        panels_mode=0o644, env_mode=0o600, vw_mode=0o600,
    )


def main():
    global ASSUME_DEFAULTS
    ap = argparse.ArgumentParser(
        description="Setup, diagnose, repair + install the SOC video wall.")
    ap.add_argument("command", nargs="?", default=None,
                    choices=["menu", "deploy", "first-run", "wizard", "doctor",
                             "repair", "install", "creds"],
                    help="menu (default on a TTY) | deploy (full automated "
                         "deploy) | first-run (seal the one-time PIN) | wizard "
                         "(config) | doctor (diagnose) | repair (fix/install "
                         "missing) | install (OS install + wizard) | creds (logins)")
    ap.add_argument("--clean", action="store_true",
                    help="deploy: wipe generated config/state first (fresh deploy)")
    ap.add_argument("--fresh", action="store_true",
                    help="deploy: force a full OS reinstall even if already installed")
    ap.add_argument("--dry-run", action="store_true", help="show what would be written; write nothing")
    ap.add_argument("--defaults", action="store_true", help="accept every default (non-interactive)")
    ap.add_argument("--target", choices=["pi", "dev"], help="where to write (default: pi if root, else dev)")
    ap.add_argument("--section", choices=["all", "display", "panels", "tunnel", "vpn", "proxy", "vault", "server"],
                    default="all", help="run just one section (wizard)")
    args = ap.parse_args()
    ASSUME_DEFAULTS = args.defaults

    cmd = args.command
    if cmd is None:
        # No subcommand: show the interactive menu on a real terminal; fall back
        # to the wizard for piped / non-interactive / scripted runs so --defaults
        # and answer-piping keep working unchanged.
        interactive = (sys.stdin.isatty() and sys.stdout.isatty()
                       and not ASSUME_DEFAULTS and not args.dry_run
                       and args.section == "all")
        cmd = "menu" if interactive else "wizard"

    dispatch = {
        "menu": cmd_menu, "deploy": cmd_deploy, "first-run": cmd_firstrun,
        "doctor": cmd_doctor, "repair": cmd_repair, "install": cmd_install,
        "creds": cmd_creds, "wizard": cmd_wizard,
    }
    return dispatch[cmd](args)


def cmd_wizard(args) -> int:
    env = Env()
    target = args.target or ("pi" if env.is_root else "dev")
    paths = resolve_paths(target)

    banner("SOC video-wall · interactive setup")
    print(f"   target   : {bold(target)}  ({'Raspberry Pi / root' if target == 'pi' else 'dev workstation'})")
    print(f"   panels   : {paths['panels_out']}")
    print(f"   soc.env  : {paths['soc_env']}")
    print(f"   detected : root={env.is_root} apt={env.has_apt} pi={env.is_pi} venv={env.has_venv}")
    if args.dry_run:
        print(yellow("   mode     : DRY RUN — no files will be written"))
    if target == "pi" and not env.is_root:
        warn("writing to /etc/soc-display needs root; re-run with sudo, or use --target dev")

    prev = load_yaml(paths["panels_out"])
    if prev:
        note("loaded your previous answers from the existing config as defaults")

    # Collect configuration
    cfg = {}
    cfg["display"] = section_display(prev) if args.section in ("all", "display") else (prev or {}).get("display", _def_display())
    cfg["panels"] = section_panels(cfg["display"], prev) if args.section in ("all", "panels") else (prev or {}).get("panels", [])
    cfg["tunnel"] = section_tunnel(cfg["panels"], prev) if args.section in ("all", "tunnel") else (prev or {}).get("tunnel", {"enabled": False})
    cfg["vpn"] = section_vpn(prev) if args.section in ("all", "vpn") else (prev or {}).get("vpn", {"enabled": False})
    cfg["proxy"] = section_proxy(prev) if args.section in ("all", "proxy") else (prev or {}).get("proxy", {"enabled": False})

    soc_env = None
    if args.section in ("all", "vault"):
        soc_env = section_vault(paths, load_env_file(paths["soc_env"]), cfg["vpn"].get("enabled"))
    vw_env = None
    if args.section in ("all", "server"):
        vw_env = section_server(paths, args.dry_run)

    # Summary
    banner("Review")
    print(f"   {len(cfg['panels'])} panel(s); "
          f"tunnel {'ON' if cfg['tunnel'].get('enabled') else 'off'}; "
          f"VPN {'ON' if cfg['vpn'].get('enabled') else 'off'}; "
          f"proxy {'ON' if cfg.get('proxy', {}).get('enabled') else 'off'}")
    for p in cfg["panels"]:
        tgt = p.get("url") or f"tunnel:{p.get('tunnel', {}).get('local_port')}"
        print(dim(f"     - {p['id']} [{p['engine']}/{p['mode']}] {tgt}  <- {p['vault_item']}"))
    if not ask_bool("Write these files now?", True):
        err("nothing written")
        return 1

    # Write
    banner("Writing files")
    write_file(paths["panels_out"], render_panels_yaml(cfg), paths["panels_mode"], args.dry_run)
    if soc_env is not None:
        write_file(paths["soc_env"], render_soc_env(soc_env), paths["env_mode"], args.dry_run)
    if vw_env is not None:
        write_file(paths["vw_env"], render_vw_env(vw_env), paths["vw_mode"], args.dry_run)

    if not args.dry_run:
        validate_panels(paths["panels_out"])

    # Remember what we just built so `deploy` can store credentials for it
    # in-process (without re-reading the file through PyYAML).
    global _LAST_CFG, _LAST_SOC_ENV
    _LAST_CFG = cfg
    _LAST_SOC_ENV = soc_env if soc_env is not None else load_env_file(paths["soc_env"])

    if not getattr(args, "_in_deploy", False):
        post_actions(env, cfg, target, args.dry_run)

    banner("Done")
    print("   Guide: docs/SETUP.md   ·   Re-run anytime: python3 setup.py")
    return 0


def _def_display():
    return dict(auto=True, width=1920, height=1080, cols=2, rows=2, gap=0)


if __name__ == "__main__":
    sys.exit(main())
