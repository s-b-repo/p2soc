#!/usr/bin/env python3
"""
SOC video-wall — interactive setup wizard.

Walks you through configuring the whole wall step by step and writes the three
files the kiosk reads:

  * panels.yaml        — the 4 panels, the autossh tunnel, and the Fortinet VPN
  * soc.env            — vault settings + the unattended-unlock master password
  (Vaultwarden's own server config now lives in its systemd unit — no .env.)

It is **pure standard library** (so it runs before the venv exists), idempotent
(re-running loads your previous answers as defaults), and never overwrites a file
without backing it up first.

Usage:
  python3 setup.py                 # interactive menu (deploy / configure / diagnose / ...)
  python3 setup.py deploy          # full automated deployment, end to end
  python3 setup.py wizard          # just the configuration wizard
  python3 setup.py wizard-gui      # the graphical configuration wizard (desktop window)
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

# The SHARED PROVISIONING CORE. Re-exported so the GUI (which loads setup.py as a
# module) reaches the same step functions via `self.setup.provision_*` /
# `self.setup.step_*` — the single place CLI + GUI call, no parallel logic. Pure
# stdlib, so importing it here (before the venv) is safe. Best-effort: if the
# file is ever missing, the CLI subcommands degrade rather than crash setup.py.
try:
    sys.path.insert(0, REPO)
    import provision  # noqa: E402  — same dir as setup.py
    # Flat re-export so the GUI (which loads setup.py as a module) can reach the
    # core either as `self.setup.provision.step_users` OR `self.setup.step_users`
    # / `self.setup.Opts` — both resolve to the SAME object, no drift.
    Opts = provision.Opts
    ProvResult = provision.ProvResult
    Plan = provision.Plan
    step_packages = provision.step_packages
    step_users = provision.step_users
    step_deploy = provision.step_deploy
    step_units = provision.step_units
    step_vault_running = provision.step_vault_running
    step_vault_account = provision.step_vault_account
    step_vault_seed = provision.step_vault_seed
    step_seal = provision.step_seal
    step_write_config = provision.step_write_config
    provision_all = provision.provision_all
    provision_plan = provision.plan
except Exception:  # noqa: BLE001
    provision = None  # type: ignore


def _configpaths():
    """The shared read/write-location resolver (host.configpaths). Imported lazily
    via the same kiosk-host sys.path shim the rest of setup.py uses for host.* —
    it is pure stdlib, so this works before the venv exists. The writer and the
    reader resolve through this ONE module so they cannot disagree."""
    if os.path.join(REPO, "kiosk-host") not in sys.path:
        sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    from host import configpaths  # type: ignore
    return configpaths


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
    try:
        shutil.copy2(path, bak)
        note(f"backed up existing {path} -> {os.path.basename(bak)}")
    except PermissionError:
        # Non-root user can't back up root-owned files in /etc — the write
        # below will go to a user-writable path instead; skipping the backup
        # is safe because the original file is unchanged.
        note(f"cannot back up {path} (permission denied) — skipping backup, "
             f"original file untouched")


def write_file(path: str, content: str, mode: int, dry: bool):
    if dry:
        print(yellow(f"   [dry-run] would write {path} (mode {oct(mode)})"))
        for ln in content.splitlines():
            print(dim("     | " + ln))
        return
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    # If the target dir isn't writable (non-root user, /etc owned by root),
    # silently redirect to the per-user XDG dir so the install completes.
    if not os.access(parent, os.W_OK):
        import host.configpaths as cp
        base = os.path.basename(path)
        alt = cp.user_dir()
        os.makedirs(alt, exist_ok=True)
        path = os.path.join(alt, base)
        parent = alt
        note(f"  /etc not writable — writing to {path} instead")
        # Drop the active marker so the wall reads THIS file over the stale /etc copy
        marker = cp.active_marker()
        if marker:
            try:
                os.makedirs(os.path.dirname(marker), 0o700, exist_ok=True)
                with open(marker, "w", encoding="utf-8") as fh:
                    fh.write(f"{path}\n# activated {time.strftime('%Y-%m-%dT%H:%M:%S%z')} by uid {os.geteuid()}\n")
            except OSError:
                pass
    backup(path)
    # Atomic write (mirror backup.write_backup): stage into <path>.tmp in the SAME
    # dir (so os.replace is a same-fs rename, no EXDEV), fsync, force the final
    # mode, then replace — so an interrupted write (power loss / ENOSPC / kill) on
    # the Pi's SD card never leaves a truncated panels.yaml/soc.env live. A real
    # failure still surfaces (the tmp is removed and the error re-raised — never
    # swallowed); the old file stays intact.
    tmp = path + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(fd, content.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # Durability across a power cut: fsync the parent dir so the rename is on disk.
    try:
        dfd = os.open(parent or ".", os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass  # not all platforms/filesystems allow dir-fsync; best effort only
    ok(f"wrote {path}  ({oct(mode)[2:]})")


def rewrite_env(path: str, *, remove=(), set_kv=None, mode: int = 0o600,
                dry: bool = False):
    """Rewrite a KEY=VALUE env file in place: drop any key in `remove`, apply
    `set_kv` (updating a key's line, or appending if absent). Comments, blank
    lines and ordering are preserved; the file is backed up first. Used to scrub
    a plaintext secret out of soc.env after it has been sealed."""
    remove = set(remove)
    set_kv = dict(set_kv or {})
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    out, seen = [], set()
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in remove:
                continue
            if k in set_kv:
                out.append(f"{k}={set_kv[k]}\n")
                seen.add(k)
                continue
        out.append(line)
    for k, v in set_kv.items():
        if k not in seen:
            out.append(f"{k}={v}\n")
    if dry:
        print(yellow(f"   [dry-run] would rewrite {path} "
                     f"(remove {sorted(remove)}, set {sorted(set_kv)})"))
        return
    backup(path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(out)
    os.chmod(path, mode)


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


# Cap mirrors kiosk-host/host/config.py MAX_VPNS; a name must start alphanumeric
# (it becomes the supervisor key / status-pill row / log tag downstream).
MAX_VPNS = 8
_VPN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def cfg_vpns(cfg: dict) -> list:
    """The authoritative vpns[] list for a setup cfg, normalising a legacy single
    `vpn: {}` (back-compat) into a one-entry list. Mirrors config._normalize_vpns
    so the CLI/GUI agree with what the wall actually parses."""
    if cfg.get("vpns") is not None:
        v = cfg.get("vpns")
        return list(v) if isinstance(v, list) else []
    single = cfg.get("vpn")
    if isinstance(single, dict) and single:
        return [single]
    return []


def _vpn_is_plain_single(v: dict) -> bool:
    """True when a lone VPN can round-trip as a legacy `vpn: {}` block: its only
    extra keys (name/default_route) are the parse-time defaults. Mirrors
    config._vpn_is_plain_single so single-VPN configs stay byte-stable."""
    if not isinstance(v, dict):
        return False
    if v.get("default_route"):
        return False
    nm = str(v.get("name", "") or "").strip()
    return nm in ("", "vpn")


def _emit_vpn_body(L: list, v: dict, *, with_name: bool, pad: str):
    """Append the body of ONE VPN entry, each key prefixed with `pad` (two spaces
    for a single `vpn:` block, four for a `vpns:` list item). `with_name` emits the
    `name`/`default_route` identity keys (list form only)."""
    vtype = v.get("type", "fortinet")
    if with_name:
        L.append(f"{pad}name: {yq(v.get('name', ''))}")
    L.append(f"{pad}enabled: {str(bool(v.get('enabled'))).lower()}")
    if not v.get("enabled"):
        return
    L.append(f"{pad}type: {vtype}")
    if with_name and v.get("default_route"):
        L.append(f"{pad}default_route: true")
    if vtype == "openvpn":
        L.append(f"{pad}config: {yq(v['config'])}")
        L.append(f"{pad}vault_item: {yq(v.get('vault_item', ''))}")
        L.append(f"{pad}ready_probe: {yq(v.get('ready_probe', ''))}")
        L.append(f"{pad}set_routes: {str(bool(v.get('set_routes', True))).lower()}")
        L.append(f"{pad}extra_args: []")
    elif vtype == "wireguard":
        L.append(f"{pad}config: {yq(v['config'])}")
        L.append(f"{pad}ready_probe: {yq(v.get('ready_probe', ''))}")
        L.append(f"{pad}health_check_interval: {v.get('health_check_interval', 30)}")
        L.append(f"{pad}health_check_failures: {v.get('health_check_failures', 3)}")
    elif vtype == "inode":
        L.append(f"{pad}gateway: {yq(v['gateway'])}")
        L.append(f"{pad}port: {v.get('port', 443)}")
        L.append(f"{pad}vault_item: {yq(v['vault_item'])}")
        if v.get("config"):
            L.append(f"{pad}config: {yq(v['config'])}")
        if v.get("domain"):
            L.append(f"{pad}domain: {yq(v['domain'])}")
        L.append(f"{pad}trusted_cert: {yq(v.get('trusted_cert', ''))}")
        L.append(f"{pad}insecure: {str(bool(v.get('insecure', False))).lower()}")
        L.append(f"{pad}ready_probe: {yq(v.get('ready_probe', ''))}")
        L.append(f"{pad}health_check_interval: {v.get('health_check_interval', 0)}")
        L.append(f"{pad}health_check_failures: {v.get('health_check_failures', 3)}")
        L.append(f"{pad}extra_args: []")
    else:  # fortinet
        L.append(f"{pad}gateway: {yq(v['gateway'])}")
        L.append(f"{pad}port: {v['port']}")
        L.append(f"{pad}vault_item: {yq(v['vault_item'])}")
        L.append(f"{pad}trusted_cert: {yq(v.get('trusted_cert', ''))}")
        L.append(f"{pad}realm: {yq(v.get('realm', ''))}")
        L.append(f"{pad}set_routes: {str(bool(v['set_routes'])).lower()}")
        L.append(f"{pad}set_dns: {str(bool(v['set_dns'])).lower()}")
        L.append(f"{pad}half_internet_routes: {str(bool(v['half_internet_routes'])).lower()}")
        L.append(f"{pad}persistent: {v['persistent']}")
        L.append(f"{pad}otp_from_vault: {str(bool(v['otp_from_vault'])).lower()}")
        L.append(f"{pad}ready_probe: {yq(v.get('ready_probe', ''))}")
        L.append(f"{pad}health_check_interval: {v.get('health_check_interval', 0)}")
        L.append(f"{pad}health_check_failures: {v.get('health_check_failures', 3)}")
        L.append(f"{pad}extra_args: []")


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
    # vpn / vpns — emit a single `vpn:` block when there is exactly one plainly
    # named, non-default-route VPN (byte-stable with legacy one-VPN tooling), else
    # a `vpns:` list. Mirrors config._emit_vpns so the wall re-parses it identically.
    vpns = cfg_vpns(cfg)
    if len(vpns) == 1 and _vpn_is_plain_single(vpns[0]):
        L.append("# VPN — supervised tunnel (Fortinet / OpenVPN / WireGuard / iNode), run as root")
        L.append("vpn:")
        _emit_vpn_body(L, vpns[0], with_name=False, pad="  ")
    elif vpns:
        L.append("# VPNs — N supervised tunnels; each VPN owns its own (split-tunnel) routes.")
        L.append("# Mark exactly one default_route: true to give it the catch-all 0.0.0.0/0 route.")
        L.append("vpns:")
        for v in vpns:
            start = len(L)
            _emit_vpn_body(L, v, with_name=True, pad="    ")
            # turn the first body line of this entry into the `- ` list item
            L[start] = "  - " + L[start][4:]
    else:
        # vpn-less config stays vpn-less — emit NO vpn:/vpns: block so the wall
        # parses conf.vpns == [] (no VPN service wanted), not a disabled stub.
        L.append("# VPN — none configured.")
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
    L.append("# $SOC_SECRET_DIR and fed to litebw by pinentry-vault.py (no .env secret).")
    L.append("# The wall config lives in Vaultwarden (SOC_CONFIG_VAULT_ITEM). See")
    L.append("# docs/SECURITY.md.")
    L.append("")
    L.append("# --- vault (litebw -> Vaultwarden) ---")
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


# Non-secret keys baked into soc-wall.service's Environment= lines. The vault
# master password is NEVER among them (it is sealed host-bound; see secretstore).
_WALL_ENV_KEYS = (
    "SOC_VAULT_BACKEND", "SOC_VAULT_EMAIL", "SOC_VAULT_URL", "SOC_SECRET_DIR",
    "SOC_MASTER_SOURCE", "SOC_SECRET_ATTRS",
    "SOC_CONFIG_VAULT_ITEM", "SOC_ROOT", "SOC_PANELS_FILE", "SOC_INJECT_TMPL",
    "SOC_LAUNCH_STAGGER", "SOC_READY_TIMEOUT", "SOC_CDP_BASE_PORT",
    "SOC_CRED_TTL", "SOC_VPN_DRY_RUN", "SOC_SESSION",
)


def render_wall_unit(e: dict, *, user: str = "soc",
                     soc_root: str = "/opt/soc-display") -> str:
    """Generate the supervised soc-wall.service: the kiosk session as a systemd
    service with the non-secret config baked in as Environment= lines (no soc.env)
    and Restart=always (a dead compositor/session recovers instead of going dark)."""
    def env_line(k: str, v: str) -> str:
        # systemd needs the whole assignment quoted when the value has spaces.
        return f'Environment="{k}={v}"' if " " in v else f"Environment={k}={v}"

    L = [
        "# SOC video-wall kiosk session — generated by setup.py.",
        "# Non-secret config is baked in as Environment= below (no soc.env).",
        "# The vault master is sealed host-bound under $SOC_SECRET_DIR.",
        "[Unit]",
        "Description=SOC video-wall kiosk session",
        "After=systemd-user-sessions.service network-online.target vaultwarden.service",
        "Wants=network-online.target vaultwarden.service",
        "Conflicts=getty@tty1.service",
        "After=getty@tty1.service",
        "",
        "[Service]",
        "Type=simple",
        f"User={user}",
        "PAMName=login",
        "TTYPath=/dev/tty1",
        "StandardInput=tty",
        "StandardOutput=journal",
        "StandardError=journal",
        "TTYReset=yes",
        "TTYVHangup=yes",
        "UtmpIdentifier=tty1",
        "UtmpMode=user",
        "",
    ]
    L += [env_line(k, str(e.get(k, ""))) for k in _WALL_ENV_KEYS]
    L += [
        "",
        f"ExecStart={soc_root}/scripts/start-session.sh",
        "Restart=always",
        "RestartSec=3",
        "# Cap memory so a leaking dashboard throttles (and, worst case, the whole",
        "# session restarts) instead of OOM-killing an arbitrary process on the Pi.",
        "MemoryAccounting=yes",
        "MemoryHigh=80%",
        "MemoryMax=92%",
        "",
        "[Install]",
        "WantedBy=graphical.target",
        "",
    ]
    return "\n".join(L)


def load_unit_env(path: str) -> dict:
    """Read SOC_* config back out of a generated unit's Environment= lines — the
    no-soc.env replacement for load_env_file() when reading an installed wall."""
    out = {}
    if not os.path.exists(path):
        return out
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("Environment="):
                    continue
                body = line[len("Environment="):].strip()
                if len(body) >= 2 and body[0] == '"' and body[-1] == '"':
                    body = body[1:-1]
                if "=" not in body:
                    continue
                k, v = body.split("=", 1)
                out[k.strip()] = v
    except OSError:
        pass
    return out


# (render_vw_env removed — Vaultwarden has no .env; its config lives in its systemd unit.)


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


def section_vpns(prev) -> list:
    """Configure the vpns[] LIST: add up to MAX_VPNS independent VPNs (any mix of
    types), each named, validated, with an at-most-one default_route owner. Returns
    a list of per-entry dicts. Back-compat: a legacy single `vpn: {}` in `prev` is
    surfaced as the first entry's defaults via cfg_vpns()."""
    step(4, 7, "VPNs (Fortinet / OpenVPN / WireGuard / iNode)")
    note("Each VPN is an independent supervised tunnel; VPN-side panels use mode: direct.")
    note("Multiple VPNs split-tunnel by default — each owns only its own routes.")
    prev_vpns = cfg_vpns(prev or {})
    if not prev_vpns:
        if not ask_bool("Enable a VPN?", False):
            return []
    else:
        note(f"{len(prev_vpns)} VPN(s) configured previously.")
        if not ask_bool("Keep VPN(s) enabled?", True):
            return []

    out: list = []
    used_names: set = set()
    # default_route is re-decided fresh below so the at-most-one guard is honest.
    route_taken = False
    i = 0
    while len(out) < MAX_VPNS:
        pv = prev_vpns[i] if i < len(prev_vpns) else {}
        print()
        print(cyan(f"   ── VPN {len(out) + 1} ──"))
        # name — unique, identity key for the supervisor/pill/logs
        default_name = str(pv.get("name", "") or "").strip() or (
            "vpn" if not out else f"vpn{len(out) + 1}")

        def _v_name(s, _used=used_names):
            s = s.strip()
            if not _VPN_NAME_RE.match(s):
                return "name must start alphanumeric (letters/digits/._- only, no spaces)"
            if s.lower() in _used:
                return f"name {s!r} already used — each VPN name must be unique"
            return None
        name = ask("VPN name (identity key)", default_name, allow_empty=False,
                   validate=_v_name)
        used_names.add(name.lower())

        entry = _prompt_one_vpn(pv)
        entry["name"] = name
        # default_route — at most one owner; suppress the prompt once taken
        if not route_taken:
            if ask_bool("Make this the default-route owner (full-tunnel 0.0.0.0/0)?",
                        bool(pv.get("default_route", False))):
                entry["default_route"] = True
                route_taken = True
            else:
                entry["default_route"] = False
        else:
            entry["default_route"] = False
        out.append(entry)
        ok(f"VPN {name} configured")

        i += 1
        if len(out) >= MAX_VPNS:
            note(f"reached the {MAX_VPNS}-VPN cap.")
            break
        if not ask_bool("Add another VPN?", i < len(prev_vpns)):
            break
    return out


def _prompt_one_vpn(pv: dict) -> dict:
    """Prompt the per-type fields for ONE VPN (the body shared by the list loop).
    Returns the type-specific dict with enabled=True (no name/default_route — the
    caller adds those)."""
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
    otp = ask_bool("pull a TOTP 2FA code from the vault item (litebw code)?", bool(pv.get("otp_from_vault", False)))
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
    step(6, 7, "Secrets vault (litebw / Vaultwarden)")
    e = dict(prev_env)
    note("The kiosk reads every login — and its own config — from Vaultwarden via")
    note("litebw (or rbw, or a JSON file in dev). No secret is written to any .env:")
    note("the master password is sealed host-bound under $SOC_SECRET_DIR; first-run /")
    note("deploy generates the one-time PIN and seals it.")
    backend = ask_choice("vault backend", ["litebw", "rbw", "dev"], e.get("SOC_VAULT_BACKEND", paths["default_backend"]))
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
        note("never written in cleartext. first-run lets you choose the source —")
        note("sealed (host-bound, default) or the universal Secret Service wallet")
        note("(KWallet / GNOME-keyring / KeePassXC via secret-tool).")
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
    note("Vaultwarden's config now lives in its systemd unit (no .env): it binds")
    note("localhost, signups are off, and /admin is disabled (no ADMIN_TOKEN).")
    note("To create the kiosk account, temporarily allow signups:")
    note("  sudo systemctl edit vaultwarden  ->  [Service]")
    note("                                       Environment=SIGNUPS_ALLOWED=true")
    note("  sudo systemctl restart vaultwarden ; create the account ; then revert.")
    note("Enable /admin later the same way:  Environment=ADMIN_TOKEN=<vaultwarden hash>")
    return None


# (_gen_admin_token removed — no ADMIN_TOKEN; the /admin page is disabled by default.)


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
           f"vpn={sum(1 for v in (conf.vpns or []) if v.get('enabled'))} enabled")
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
        _run((["./install.sh"] if env.is_root else ["sudo", "./install.sh"]))
    if target == "dev":
        if ask_bool("Seed the dev vault (make dev-vault)?", True):
            _run(["make", "dev-vault"])
        if any(v.get("enabled") for v in cfg_vpns(cfg)) and ask_bool("Dry-run the VPN wiring (make vpn-check)?", True):
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
    for v in cfg_vpns(cfg):
        if v.get("enabled") and v.get("vault_item"):
            label = "vpn:" + str(v.get("name", "")) if v.get("name") else "vpn"
            items.append((label, v["vault_item"], ""))
    pr = cfg.get("proxy") or {}
    if pr.get("enabled") and pr.get("vault_item"):
        items.append(("proxy", pr["vault_item"], pr.get("url", "")))
    return items


def _resolve_master(soc_env: dict) -> str:
    """The vault master password — from the host-bound sealed store, or an
    interactive prompt if not sealed yet. NEVER from a plaintext
    SOC_VAULT_PASSWORD in soc.env (that path is gone; doctor fails on it)."""
    sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    sd = soc_env.get("SOC_SECRET_DIR")
    try:
        from host import secretstore  # type: ignore
        if secretstore.is_sealed(sd):
            return secretstore.unseal(sd)
    except Exception as e:  # noqa: BLE001
        warn(f"could not unseal the master ({e}); enter it manually")
    # No usable seal. In a NON-INTERACTIVE context (--defaults, or piped/EOF
    # stdin) we must NOT invent a master: ask_secret would return the literal
    # "CHANGE-ME" default (a truthy placeholder that downstream would register as
    # the real master) or block on getpass. Fail closed — return "" so the caller
    # skips the account/seal step and the operator seals it explicitly instead.
    non_interactive = ASSUME_DEFAULTS or not (
        sys.stdin.isatty() and sys.stdout.isatty())
    if non_interactive:
        warn("no usable vault master (not sealed) and not interactive — refusing "
             "to use a placeholder; seal it first (python3 setup.py first-run) "
             "or pass --master-fd")
        return ""
    return ask_secret("vault master password (used now, not stored)")


def store_credentials(soc_env: dict, cfg: dict, dry: bool):
    """Write each item's username+password into Vaultwarden (vaultseed). Run this
    AFTER Vaultwarden is up + the account exists. Operator can skip + add by hand."""
    banner("Store credentials in Vaultwarden")
    if (soc_env or {}).get("SOC_VAULT_BACKEND") not in ("rbw", "litebw"):
        note("vault backend is 'dev' — credentials live in the dev JSON; skipping.")
        return
    url = soc_env.get("SOC_VAULT_URL", "")
    email = soc_env.get("SOC_VAULT_EMAIL", "")
    pw = _resolve_master(soc_env)
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
    target = args.target or _default_target(env)
    paths = resolve_paths(target)
    # Doctor must diagnose the file the WALL ACTUALLY READS (the shared resolver),
    # not just where the wizard would write — so a write/read mismatch surfaces
    # instead of being masked. Fall back to the write target if nothing is resolved.
    cp = _configpaths()
    read_env, env_label = cp.resolve_read("env")
    read_panels, panels_label = cp.resolve_read("panels")
    soc_env_path = read_env or paths["soc_env"]
    panels_path = read_panels or paths["panels_installed"]
    soc_env = load_env_file(soc_env_path)
    banner("SOC video-wall · doctor")
    print(f"   target {bold(target)}   soc.env {soc_env_path} ({env_label})")
    print(f"   panels {panels_path} ({panels_label})")
    # If the wizard's write target differs from what the wall reads, say so loudly.
    if (read_panels and os.path.abspath(read_panels) != os.path.abspath(paths["panels_installed"])):
        warn(f"the wall reads {read_panels} but the wizard would write "
             f"{paths['panels_installed']} — run `python3 -m host.configpaths --explain`")
    d = _Doc()

    d.check("venv + Python deps", lambda: _probe_venv(paths.get("soc_root", REPO) + "/.venv/bin/python")
            if os.path.exists(paths.get("soc_root", REPO) + "/.venv/bin/python")
            else _probe_venv(env.venv_py))

    backend = soc_env.get("SOC_VAULT_BACKEND", paths["default_backend"])
    d.check("litebw (Vaultwarden client)", lambda: (
        ("OK", "on PATH", "") if _have("litebw")
        else ("WARN" if backend != "litebw" else "FAIL",
              "not installed", "deployed to /usr/local/bin/litebw by install.sh")))
    if backend == "rbw":
        d.check("rbw (Vaultwarden CLI)", lambda: (
            ("OK", "on PATH", "") if _have("rbw")
            else ("FAIL", "not installed", "cargo install rbw  (or your package manager)")))

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
        conf = hostcfg.load(panels_path)
        d.check("panels.yaml parses", lambda: (
            "OK", f"{len(conf.panels)} panels"
            + (f", {len(conf.warnings)} warning(s)" if conf.warnings else ""), ""))
        # Per-VPN client checks — iterate the WHOLE vpns[] list so a missing client
        # for the 3rd VPN is caught, not just the primary (conf.vpns[0]).
        for vpn in (conf.vpns or []):
            if not vpn.get("enabled"):
                continue
            kind = hostcfg.vpn_kind(vpn)
            nm = str(vpn.get("name", "") or "vpn")
            if kind == "inode":
                script = hostcfg.inode_script(vpn)
                d.check(f"iNode client (svpn-connect.sh) [{nm}]", lambda script=script: (
                    ("OK", script, "")
                    if os.path.isfile(script) and os.access(script, os.X_OK)
                    else ("FAIL", f"missing/not executable: {script}",
                          "ship vendor/iNode-VPN-Client or set vpn.config")))
                d.check(f"tesseract (iNode login CAPTCHA) [{nm}]", lambda: (
                    ("OK", "on PATH", "") if _have("tesseract")
                    else ("WARN", "not installed", "install tesseract-ocr — the "
                          "gateway CAPTCHA cannot be auto-solved without it")))
            else:
                need = {"fortinet": "openfortivpn", "openvpn": "openvpn",
                        "wireguard": "wg-quick"}[kind]
                d.check(f"VPN client ({kind}) [{nm}]", lambda need=need: (
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
        # Bind the message now: `e` is del'd when this except block exits, so a
        # lambda closing over `e` would NameError when d.check runs it later.
        err = str(e)
        d.check("panels.yaml parses", lambda: ("FAIL", err,
                "fix the config / run the wizard: setup.py"))

    # vault reachability + master password sanity
    if backend in ("rbw", "litebw"):
        url = soc_env.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        d.check("Vaultwarden reachable", lambda: (
            ("OK", url, "") if _alive(url)
            else ("WARN", f"{url} not answering /alive",
                  "start it: systemctl start vaultwarden")))
        # master password source (no plaintext .env, ever)
        sec = soc_env.get("SOC_SECRET_DIR") or "/etc/soc-display/secret"
        active_src = soc_env.get("SOC_MASTER_SOURCE", "auto")

        def _master_src():
            sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
            try:
                from host import mastersource, secretstore  # type: ignore
            except Exception as e:  # noqa: BLE001
                return ("FAIL", f"secretstore import failed: {e}", "setup.py repair")
            # A plaintext master in soc.env is a FAIL regardless of source.
            if soc_env.get("SOC_VAULT_PASSWORD"):
                return ("FAIL", "plaintext SOC_VAULT_PASSWORD present in soc.env",
                        "remove that line, then: setup.py first-run")
            avail = ", ".join(mastersource.available_sources()) or "(none)"

            # secret-service: explicit choice, or auto with a wallet but no seal.
            want_ss = active_src == "secret-service" or (
                active_src == "auto" and mastersource._have_secret_tool()
                and not (secretstore.available() and secretstore.is_sealed(sec)))
            if want_ss:
                if not mastersource._have_secret_tool():
                    return ("FAIL", "source=secret-service but secret-tool not on PATH",
                            "install libsecret-tools / libsecret, or: setup.py first-run")
                pw = mastersource._from_secret_service()
                if pw:
                    return ("OK", f"secret-service: item found (source={active_src}; "
                            f"avail: {avail})", "")
                return ("WARN",
                        "secret-service: no item / wallet locked (avail: " + avail + ")",
                        "secret-tool store service soc-wall account vault-master  "
                        "(and unlock the wallet)")

            # sealed (default for unattended) — explicit or auto.
            if not secretstore.available():
                return ("FAIL", "cryptography not installed",
                        "pip install cryptography (setup.py repair)")
            if secretstore.is_sealed(sec):
                try:
                    secretstore.unseal(sec)
                    return ("OK", f"sealed + unseals on this host ({sec}; "
                            f"source={active_src})", "")
                except Exception as e:  # noqa: BLE001
                    return ("FAIL",
                            f"sealed but cannot unseal ({e}) — machine-id changed?",
                            "re-run: setup.py first-run  (re-seal with your PIN)")
            return ("FAIL", f"no master source ready (source={active_src}; avail: {avail})",
                    "run: setup.py first-run  (choose sealed or secret-service)")
        d.check("vault master password source", _master_src)
        # the wall config is the vault's secure-note; the local file is a fallback
        item = soc_env.get("SOC_CONFIG_VAULT_ITEM", "SOC Wall Config")
        d.check("config source", lambda: (
            "OK", f"vault note '{item}' (local file fallback)", ""))

    # file perms — soc.env is non-secret (master sealed separately) and 0644 so
    # the desktop/kiosk user can source it; the check ceiling allows 0644.
    for f, want in ((paths["soc_env"], 0o644),):
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

    # Reconnect path: the sudoers drop-in is what lets the unprivileged kiosk
    # user restart forti-vpn / autossh-tunnel / soc-tarpit live (the ⚙ Settings
    # "Save"/reconnect button) and read their journal. Report whether the rule
    # is present AND, when we can test it, whether `sudo -n systemctl restart`
    # actually resolves for the kiosk user. install.sh drops it in via a
    # visudo-validated temp-file move; a missing/invalid file just degrades the
    # button to a "PENDING restart" message (no functional break).
    if _have("sudo"):
        dropin = "/etc/sudoers.d/soc-wall-restart"
        kiosk_user = soc_env.get("SOC_KIOSK_USER") or os.environ.get("SOC_KIOSK_USER") or "soc"

        def _sudoers_reconnect():
            if not os.path.exists(dropin):
                return ("WARN", f"{dropin} not present",
                        "install.sh installs it (visudo-validated); the reconnect "
                        "button falls back to a PENDING-restart message without it")
            # File present. Try a non-interactive dry probe of the granted command
            # so we report whether the rule actually RESOLVES for the kiosk user.
            #   * running AS the kiosk user (or dev): probe directly.
            #   * running as root: probe via `sudo -u <kiosk> -n` so we test the
            #     rule, not root's blanket privileges.
            probe = ["sudo", "-n", "-l", "/usr/bin/systemctl", "restart",
                     "forti-vpn.service"]
            import getpass
            try:
                cur = getpass.getuser()
            except Exception:  # noqa: BLE001
                cur = ""
            if env.is_root and cur != kiosk_user:
                # Only test through the kiosk user if it exists.
                user_ok = subprocess.run(["id", "-u", kiosk_user],
                                         capture_output=True, text=True).returncode == 0
                if user_ok:
                    probe = ["sudo", "-u", kiosk_user, "-n", "-l",
                             "/usr/bin/systemctl", "restart", "forti-vpn.service"]
                else:
                    return ("OK", f"{dropin} present (kiosk user "
                            f"'{kiosk_user}' not created yet)", "")
            try:
                r = subprocess.run(probe, capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.SubprocessError) as e:
                return ("WARN", f"present but probe failed ({e})", "")
            if r.returncode == 0:
                return ("OK", f"{dropin} present; sudo -n systemctl restart works", "")
            return ("WARN",
                    f"{dropin} present but `sudo -n systemctl restart` denied for "
                    f"'{kiosk_user}'",
                    "visudo -c /etc/sudoers.d/soc-wall-restart; check the user field "
                    "matches your kiosk user")
        d.check("reconnect sudoers rule", _sudoers_reconnect)

    # Fresh-box detection: if the kiosk/desktop/service users or /opt/soc-display
    # are missing, this box has never been fully installed — `repair` only patches
    # an existing install, so steer the operator to the full-install path
    # (provision == the GUI's "Install on this system": users + packages + deploy +
    # vault + seal). repair/doctor alone won't create users or deploy /opt.
    fresh_box = False
    if provision is not None:
        try:
            kiosk_u = soc_env.get("SOC_KIOSK_USER") or "soc"
            no_users = not any(provision._user_exists(u)
                               for u in (kiosk_u, "socwall", "socsvc"))
            no_opt = not os.path.isdir("/opt/soc-display")
            fresh_box = no_users or no_opt
        except Exception:  # noqa: BLE001
            fresh_box = False

    print()
    if fresh_box:
        warn("this box is not fully installed yet (missing users and/or /opt/soc-display)")
        print(dim("   run: setup.py provision  "
                   "(full install: users + packages + deploy + vault + seal)"))
        print(dim("   or:  setup.py provision --dry-run   (preview, changes nothing)"))
    if d.fails:
        print(red(f"   {d.fails} problem(s), {d.warns} warning(s) — run: setup.py repair"))
        return 1
    print(green(f"   all good ({d.warns} warning(s))"))
    return 0


def cmd_repair(args) -> int:
    env = Env()
    target = args.target or _default_target(env)
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
              "PyYAML", "websocket-client"])
        # cryptography is a Rust extension — wheel-only so `repair` never starts a
        # rustc+cc sdist build that OOM-kills the 1 GB Pi (mirrors install.sh /
        # launch.sh). install.sh has the distro-package fallback; here we just
        # refuse the source build (x86 dev always has a prebuilt wheel).
        _run([venv_py, "-m", "pip", "install", "-q", "--only-binary=:all:",
              "cryptography"])

    # 2) OS packages via the installer's deps-only mode
    if env.has_apt or _have("dnf") or _have("pacman") or _have("zypper") \
            or _have("apk") or _have("xbps-install"):
        if ask_bool("Install missing OS packages (runs install.sh --deps-only)?", True):
            _run(["./install.sh", "--deps-only"] if env.is_root
                 else ["sudo", "./install.sh", "--deps-only"])

    # 3) litebw needs no compile (pure Python); install.sh puts the launcher on PATH.
    if not _have("litebw"):
        warn("litebw is not on PATH — install.sh deploys it to /usr/local/bin/litebw")

    # 3b) sealed-secret dir + litebw pinentry (the no-plaintext-.env unlock path)
    soc_env = load_env_file(paths["soc_env"])
    backend = soc_env.get("SOC_VAULT_BACKEND", paths["default_backend"])
    if backend in ("rbw", "litebw"):
        sd = paths["secret_dir"]
        try:
            os.makedirs(sd, exist_ok=True)
            os.chmod(sd, 0o700)
            ok(f"secret dir {sd} (0700)")
        except OSError as e:
            warn(f"could not create {sd}: {e}")
        if _have(backend):
            _run([backend, "config", "set", "pinentry", paths["pinentry"]])
            ok(f"{backend} pinentry -> pinentry-vault.py")

    # 4) file perms — soc.env 0644 (non-secret) so the desktop/kiosk user can
    #    source it; repairing to 0640 would re-break desktop-mode vault unlock.
    for f, mode in ((paths["soc_env"], 0o644),):
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
    # repair only patches an EXISTING install (venv/packages/keys/perms). A fresh
    # box with no kiosk/desktop/service users or no /opt/soc-display needs the
    # full-install path instead — the same provisioner the GUI's "Install on this
    # system" runs (users + packages + deploy + vault + seal).
    if provision is not None:
        try:
            kiosk_u = soc_env.get("SOC_KIOSK_USER") or "soc"
            fresh_box = (not os.path.isdir("/opt/soc-display")) or not any(
                provision._user_exists(u) for u in (kiosk_u, "socwall", "socsvc"))
        except Exception:  # noqa: BLE001
            fresh_box = False
        if fresh_box:
            note("this looks like a fresh box — a full install needs "
                 "`setup.py provision` (users + packages + deploy + vault + seal), "
                 "not just repair.")
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


def _gui_available() -> bool:
    """True if a graphical setup is launchable: a display AND GTK3 importable.
    Pure stdlib — we only check for $DISPLAY/$WAYLAND_DISPLAY here; the actual
    gi import is left to the GUI process (which degrades on its own too)."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def cmd_wizard_gui(args) -> int:
    """Launch the graphical setup wizard (scripts/soc-wall-setup-gui.sh).

    The GUI reuses this module's renderers/validators + the host secret store,
    so it writes the SAME artifacts as `wizard`. Pure stdlib here: if there is
    no display (or the launcher script is missing), degrade gracefully to the
    TTY wizard so scripted/headless runs still work."""
    gui_sh = os.path.join(REPO, "scripts", "soc-wall-setup-gui.sh")
    if not _gui_available():
        note("no graphical display detected — falling back to the text wizard")
        return cmd_wizard(args)
    if not os.path.exists(gui_sh):
        note(f"GUI launcher not found ({gui_sh}) — falling back to the text wizard")
        return cmd_wizard(args)
    rc = _run([gui_sh])
    if rc not in (0, None):
        warn("the graphical wizard exited with an error — falling back to the text wizard")
        return cmd_wizard(args)
    return rc or 0


def cmd_menu(args) -> int:
    """Interactive launcher — the default when run with no subcommand on a TTY."""
    env = Env()
    target = args.target or _default_target(env)
    banner("SOC video-wall · setup")
    print(f"   target   : {bold(target)}  "
          f"({'Raspberry Pi / root' if target == 'pi' else 'dev workstation'})")
    print(f"   detected : root={env.is_root} apt={env.has_apt} pi={env.is_pi} "
          f"venv={env.has_venv} litebw={_have('litebw')}")
    options = [
        ("deploy", "Deploy", "full automated install + configure + seal PIN + credentials"),
        ("clean", "Clean deploy", "wipe generated config/state, then deploy fresh"),
        ("wizard", "Configure", "edit panels, vault, VPN, proxy (writes the config files)"),
        ("wizard-gui", "Configure (graphical)", "the same wizard in a desktop window (presets + live validation)"),
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
    return {"deploy": cmd_deploy, "wizard": cmd_wizard,
            "wizard-gui": cmd_wizard_gui, "doctor": cmd_doctor,
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


class SealMasterError(Exception):
    """A seal/store step failed (bad input, locked wallet, missing crypto, …).
    Carries a human-readable message both wizards surface to the operator."""


def seal_master(pw, *, source, pin, paths, soc_env, backend, dry) -> str:
    """Non-interactive seal/store CORE shared by the TTY first-run wizard and the
    GUI, so the two CANNOT drift. Given an already-collected master ``pw`` and the
    chosen ``source`` (auto|sealed|secret-service|env), it performs the mechanical
    work: seal/store + verify-unseal + ``rewrite_env(SOC_MASTER_SOURCE)`` + (for
    rbw/litebw) the email/base_url/pinentry client config + scrubbing any leftover
    plaintext ``SOC_VAULT_PASSWORD`` out of soc.env once the seal is confirmed.

    It NEVER prompts and NEVER writes the master to a file (only the SOURCE name
    is recorded). Returns the PIN actually used (the passed-in PIN, or a freshly
    generated one for the sealed path; '' for the secret-service / env sources).
    Raises ``SealMasterError`` on any hard failure. ``dry`` short-circuits every
    side effect (no seal, no store, no rewrite) but still returns the PIN that
    would have been used so a caller can preview it.

    ``source`` 'auto' is materialised by sealing host-bound (the unattended
    default) while RECORDING 'auto' in soc.env (so the secret-service -> env
    runtime fallbacks survive if the seal is ever removed)."""
    sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    try:
        from host import mastersource, secretstore  # type: ignore
    except Exception as e:  # noqa: BLE001
        raise SealMasterError(f"cannot load the secret store ({e})")

    record_src = source
    eff_src = "sealed" if source == "auto" else source
    env_mode = paths.get("env_mode", 0o600)

    if eff_src == "env":
        # DEV/seeding only — nothing to seal/store; record the source choice.
        if not dry:
            rewrite_env(paths["soc_env"], set_kv={"SOC_MASTER_SOURCE": "env"},
                        mode=env_mode)
        return ""

    if eff_src == "secret-service":
        if not mastersource._have_secret_tool():
            raise SealMasterError(
                "secret-tool (libsecret) is not on PATH — install it "
                "(apt: libsecret-tools; dnf/pacman/apk/xbps: libsecret), or pick "
                "the 'sealed' source. Nothing stored.")
        if not pw:
            raise SealMasterError("no master password entered — nothing stored")
        if not dry:
            try:
                mastersource.store_master(pw, "secret-service")
                if mastersource.get_master("secret-service") != pw:
                    raise mastersource.MasterSourceError(
                        "stored value did not read back — wallet locked?")
            except mastersource.MasterSourceError as e:
                raise SealMasterError(f"could not store the master in the wallet: {e}")
            updates = {"SOC_MASTER_SOURCE": "secret-service"}
            removes = ("SOC_VAULT_PASSWORD",) if soc_env.get("SOC_VAULT_PASSWORD") else ()
            rewrite_env(paths["soc_env"], remove=removes, set_kv=updates, mode=env_mode)
            if backend in ("rbw", "litebw") and _have(backend):
                _run([backend, "config", "set", "pinentry", paths["pinentry"]])
        return ""

    # eff_src == 'sealed' — the host-bound seal path. Needs cryptography.
    if not secretstore.available():
        raise SealMasterError(
            "the 'cryptography' package is required to seal the master password "
            "(pip install cryptography)")
    if not pw:
        raise SealMasterError("no master password entered — nothing sealed")

    # Honor a custom SOC_SECRET_DIR — doctor, the credential store, and the
    # boot-time pinentry all read it, so we MUST seal to the SAME place or the
    # wall seals here but looks for the secret elsewhere and can't self-unlock.
    sd = soc_env.get("SOC_SECRET_DIR") or paths["secret_dir"]
    use_pin = pin or secretstore.gen_pin()
    if not dry:
        try:
            secretstore.seal(pw, use_pin, sd)
            # Verify it unseals on THIS host before we trust it (and before any
            # plaintext gets scrubbed) — never lock the wall out.
            if secretstore.unseal(sd) != pw:
                raise secretstore.SecretStoreError("seal did not unseal to the same value")
        except secretstore.SecretStoreError as e:
            raise SealMasterError(f"could not seal: {e}")
        _seal_housekeeping(secretstore, sd, record_src, paths, soc_env, backend)
    return use_pin


def _seal_housekeeping(secretstore, sd, record_src, paths, soc_env, backend) -> None:
    """Post-seal client wiring shared by ``seal_master`` (after a fresh seal) and
    ``cmd_firstrun`` (when the operator KEEPS an existing seal): point the rbw/
    litebw client at the unsealing pinentry (+ email/base_url), scrub any leftover
    plaintext ``SOC_VAULT_PASSWORD`` once the seal is confirmed to unseal, and
    record the chosen source. The master itself is never written — only wiring."""
    # point the vault client at the unsealing pinentry + bake email/url
    if backend in ("rbw", "litebw") and _have(backend):
        if soc_env.get("SOC_VAULT_EMAIL"):
            _run([backend, "config", "set", "email", soc_env["SOC_VAULT_EMAIL"]])
        if soc_env.get("SOC_VAULT_URL"):
            _run([backend, "config", "set", "base_url", soc_env["SOC_VAULT_URL"]])
        _run([backend, "config", "set", "pinentry", paths["pinentry"]])

    # Clean any leftover plaintext master out of soc.env now that it is sealed —
    # only after CONFIRMING it unseals, so a failed seal never strands the
    # operator. record where we sealed + repoint a stale pinentry too.
    if soc_env.get("SOC_VAULT_PASSWORD") and secretstore.is_sealed(sd):
        try:
            secretstore.unseal(sd)
        except Exception:  # noqa: BLE001 — keep the plaintext if it won't unseal here
            pass
        else:
            updates = {}
            if (soc_env.get("SOC_SECRET_DIR") or "/etc/soc-display/secret") != sd:
                updates["SOC_SECRET_DIR"] = sd
            if soc_env.get("SOC_PINENTRY", "").endswith("pinentry-soc.sh"):
                updates["SOC_PINENTRY"] = paths["pinentry"]
            rewrite_env(paths["soc_env"], remove=("SOC_VAULT_PASSWORD",),
                        set_kv=updates, mode=paths["env_mode"])

    # Record the chosen source ('auto' preserved verbatim; 'sealed' as 'sealed').
    if secretstore.is_sealed(sd) and soc_env.get("SOC_MASTER_SOURCE") != record_src:
        rewrite_env(paths["soc_env"], set_kv={"SOC_MASTER_SOURCE": record_src},
                    mode=paths.get("env_mode", 0o600))


def cmd_firstrun(args) -> int:
    """First-time setup: generate a one-time PIN, seal the vault master password
    host-bound (no plaintext .env), point litebw at the unsealing pinentry. Asks
    before overwriting an existing seal; re-runnable to change the password.

    Gathers inputs interactively, then delegates the mechanical seal/store to
    ``seal_master`` (shared verbatim with the GUI wizard)."""
    env = Env()
    target = args.target or _default_target(env)
    paths = resolve_paths(target)
    soc_env = load_env_file(paths["soc_env"])
    banner("SOC video-wall · first-time setup (PIN + seal)")
    plaintext = soc_env.get("SOC_VAULT_PASSWORD", "")
    backend = soc_env.get("SOC_VAULT_BACKEND", paths["default_backend"])
    # A dev backend needs no seal — UNLESS a plaintext master is still sitting in
    # soc.env, in which case we seal it and scrub the line regardless of backend.
    if backend not in ("rbw", "litebw") and not plaintext:
        note("vault backend is 'dev' — no sealing needed (dev reads the JSON vault).")
        return 0
    sys.path.insert(0, os.path.join(REPO, "kiosk-host"))
    try:
        from host import mastersource, secretstore  # type: ignore  # noqa: F401
    except Exception as e:  # noqa: BLE001
        err(f"cannot load the secret store ({e})")
        return 1

    # Choose where the master password comes from. 'sealed' (host-bound, no
    # session/wallet/prompt) is the default for unattended walls. 'secret-service'
    # is the universal Secret Service path (KWallet / GNOME-keyring / KeePassXC
    # via secret-tool) for ATTENDED hosts where a login unlocks the wallet.
    # 'auto' records the runtime fallback chain (sealed -> secret-service -> env)
    # but first-run still actively establishes the host-bound seal for it.
    cur_src = soc_env.get("SOC_MASTER_SOURCE", "auto") or "auto"
    src = ask_choice(
        "master-password source", ["auto", "sealed", "secret-service", "env"],
        cur_src if cur_src in ("auto", "sealed", "secret-service", "env") else "auto")
    eff_src = "sealed" if src == "auto" else src

    if eff_src == "env":
        warn("'env' reads $SOC_VAULT_PASSWORD — DEV/seeding only; never persisted "
             "to a file. Nothing to seal/store; recording the source choice only.")
        try:
            seal_master("", source=src, pin="", paths=paths, soc_env=soc_env,
                        backend=backend, dry=args.dry_run)
        except SealMasterError as e:
            err(str(e))
            return 1
        return 0

    if eff_src == "secret-service":
        master = ask_secret("vault master password (stored in the Secret Service "
                            "wallet, never in a file)")
        if not master:
            err("no master password entered — nothing stored")
            return 1
        if args.dry_run:
            print(yellow("   [dry-run] would store the master via secret-tool "
                         "(service=soc-wall account=vault-master)"))
        try:
            seal_master(master, source=src, pin="", paths=paths, soc_env=soc_env,
                        backend=backend, dry=args.dry_run)
        except SealMasterError as e:
            master = ""  # scrub
            err(str(e))
            return 1
        master = ""  # scrub
        if not args.dry_run:
            ok("stored + verified the master in the Secret Service wallet "
               "(service=soc-wall account=vault-master)")
            if backend in ("rbw", "litebw") and _have(backend):
                ok(f"{backend} configured (pinentry -> pinentry-vault.py -> secret-service)")
        note("Reminder: a headless wall's wallet is LOCKED at boot. For unattended")
        note("use, auto-unlock the wallet (PAM / gnome-keyring --unlock) or prefer")
        note("the 'sealed' source. See docs/SECURITY.md.")
        return 0

    # eff_src == 'sealed' below — the host-bound seal path. Needs cryptography.
    if not secretstore.available():
        err("the 'cryptography' package is required to seal the master password "
            "(pip install cryptography)")
        return 1

    sd = soc_env.get("SOC_SECRET_DIR") or paths["secret_dir"]
    do_seal = True
    if secretstore.is_sealed(sd):
        do_seal = ask_bool(f"A sealed secret already exists in {sd}. Re-seal (new PIN)?", False)
    if do_seal:
        if plaintext:
            note(f"found a plaintext master in {paths['soc_env']} — sealing it, then "
                 f"removing the SOC_VAULT_PASSWORD line.")
            master = plaintext
        else:
            master = ask_secret("vault master password (sealed, never stored in clear)")
        if not master:
            err("no master password entered — nothing sealed")
            return 1
        pin = ask("one-time PIN (blank = generate a random one)", "")
        if args.dry_run:
            print(yellow(f"   [dry-run] would seal the master password to {sd}"))
        try:
            pin = seal_master(master, source=src, pin=pin, paths=paths,
                              soc_env=soc_env, backend=backend, dry=args.dry_run)
        except SealMasterError as e:
            master = ""  # scrub
            err(str(e))
            return 1
        master = ""  # scrub
        if not args.dry_run:
            ok(f"sealed + verified the master password (host-bound) -> {sd}")
            if backend in ("rbw", "litebw") and _have(backend):
                ok(f"{backend} configured (email / base_url / pinentry -> pinentry-vault.py)")
            elif backend in ("rbw", "litebw"):
                warn(f"{backend} is not on PATH — install it, then re-run first-run to configure it")
            if soc_env.get("SOC_VAULT_PASSWORD"):
                ok(f"removed plaintext SOC_VAULT_PASSWORD from {paths['soc_env']} "
                   f"(master is now host-sealed)")
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
        # Re-run the client wiring / plaintext scrub / source record against the
        # EXISTING seal (same as a fresh seal, minus the seal itself), so a
        # re-run that declines re-sealing still repoints a stale client.
        if not args.dry_run:
            _seal_housekeeping(secretstore, sd, src, paths, soc_env, backend)
            if soc_env.get("SOC_VAULT_PASSWORD"):
                ok(f"removed plaintext SOC_VAULT_PASSWORD from {paths['soc_env']} "
                   f"(master is now host-sealed)")
    return 0


def push_config_to_vault(soc_env, cfg, paths, dry) -> bool:
    """Store the wall config (panels/tunnel/vpn/proxy) in Vaultwarden as the
    SOC_CONFIG_VAULT_ITEM secure-note — the wall's source of truth at boot."""
    if (soc_env or {}).get("SOC_VAULT_BACKEND") not in ("rbw", "litebw"):
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
    targets = [paths["panels_out"], paths["soc_env"],
               paths["secret_dir"], state]
    # Removing the per-user `active` marker hands control back to /etc on a
    # redeploy (else a lingering marker would shadow the re-deployed system config —
    # the inverse of the bug this resolver fixes). Always clear it, even when the
    # current write target is /etc, so a prior user fallback can't linger.
    try:
        marker = paths.get("marker") or _configpaths().active_marker()
        if marker:
            targets.append(marker)
    except Exception:  # noqa: BLE001 — resolver optional during clean
        pass
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
    target = args.target or _default_target(env)
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
    if run_install and has_pm and args.dry_run:
        # install.sh has no --dry-run flag and mutates the host (creates users,
        # builds the venv, installs packages). Honour the dry-run contract by
        # PRINTING what would run and changing nothing — never shell the installer.
        cmd = ["./install.sh"] + (["--fresh"] if fresh else [])
        note("Step 1/6 — [dry-run] would run: "
             + " ".join((cmd if env.is_root else ["sudo"] + cmd)))
    elif run_install and has_pm:
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
    is_vault = (soc_env or {}).get("SOC_VAULT_BACKEND") in ("rbw", "litebw")

    # 3) bring Vaultwarden up (real-vault backends: litebw / rbw)
    if is_vault:
        url = soc_env.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        email = soc_env.get("SOC_VAULT_EMAIL", "")
        if args.dry_run and _have("systemctl") and os.path.isdir("/run/systemd/system"):
            note("Step 3/6 — [dry-run] would start Vaultwarden "
                 "(systemctl start vaultwarden) and wait for /alive.")
        elif _have("systemctl") and os.path.isdir("/run/systemd/system"):
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
                    # Fail CLOSED on a real run: a vault that never answered /alive
                    # means the account/seal steps below will fail too, leaving a
                    # box that boots into a wall that can't read the vault. Make the
                    # operator confirm before pressing on (dry-run never prompts).
                    err(f"{url} not answering /alive — the vault is not up; "
                        "account create + seal will fail and the wall will be dark")
                    if not ask_bool("  continue anyway (NOT recommended)?", False):
                        err("aborting deploy — start Vaultwarden, then re-run")
                        return 1
        else:
            note("Step 3/6 — no systemd; start Vaultwarden via your init manager.")
        # Ensure the account EXISTS (create if missing) via the shared core — the
        # same path the GUI's "Create account" button uses. No more "create it in
        # the web vault by hand" dead-end. The master comes from --master-fd (the
        # non-interactive escape hatch) or the sealed/interactive resolver; an
        # empty result means "no usable master" -> skip rather than register with "".
        if provision is not None and email and ask_bool(
                f"  ensure the Vaultwarden account {email} exists (create if missing)?", True):
            pw = _read_master_fd(args) or _resolve_master(soc_env)
            if not pw:
                warn("no usable master available — seal it (Step 4) or re-run with "
                     "--master-fd; skipping account create/verify")
            else:
                popts = provision.Opts(email=email, url=url, dry_run=args.dry_run)
                res = provision.step_vault_account(popts, pw)
                pw = ""  # scrub
                if res.ok:
                    ok(res.detail)
                else:
                    # Fail CLOSED: a failed account-ensure is an ERROR, not a yellow
                    # warning — without it the wall can't log into the vault. Require
                    # confirmation to continue (dry-run never prompts).
                    err(f"account create/verify failed: {res.detail}")
                    if not args.dry_run and not ask_bool(
                            "  continue anyway (the wall may not be able to log in)?", False):
                        err("aborting deploy — fix the vault account, then re-run")
                        return 1
    else:
        note("Step 3/6 — dev vault backend; no Vaultwarden server needed.")

    # 4) first-time setup: seal the master password under a one-time PIN
    if is_vault:
        if ask_bool("Step 4/6 — first-time setup: seal the master password (PIN)?", True):
            cmd_firstrun(args)
            soc_env = load_env_file(paths["soc_env"])
    else:
        note("Step 4/6 — dev backend; no PIN / seal needed.")

    # 5) push the config into the vault + store the logins
    if is_vault:
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
    target = args.target or _default_target(env)
    paths = resolve_paths(target)
    # Store logins against the config the WALL ACTUALLY READS (shared resolver),
    # not just the wizard's write target — they agree on a deployed box, but the
    # resolver is the single source of truth so creds can never target a dead file.
    cp = _configpaths()
    soc_env = load_env_file(cp.resolve_env() or paths["soc_env"])
    panels_path = cp.resolve_panels() or paths["panels_installed"]
    cfg = load_yaml(panels_path) or {}
    if not cfg.get("panels"):
        err(f"no config found at {panels_path} — run the wizard first")
        return 1
    store_credentials(soc_env, cfg, args.dry_run)
    return 0


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def resolve_paths(target: str, *, can_escalate: bool = False) -> dict:
    """Where the wizard WRITES — derived from the SHARED resolver (host.configpaths)
    so what we write is exactly what the wall (resolving with the same logic) reads.

    target:
      'dev'   -> force the repo checkout (config/panels.local.yaml, .env). Explicit,
                 deterministic — tests and `--target dev` rely on this verbatim.
      'pi' / 'auto' -> the highest-precedence location THIS euid can write:
                 /etc/soc-display when root (or escalated), else the per-user
                 ~/.config/soc-display + an `active` marker so the wall picks it up.

    The dict shape (keys) is unchanged so doctor/creds/deploy/wizard/setupgui keep
    working. New keys: 'via' (env|etc|user|repo), 'marker' (path or None),
    'needs_privilege' (pkexec required)."""
    if target == "dev":
        return dict(
            mode="dev", via="repo", marker=None, needs_privilege=False,
            panels_out=os.path.join(REPO, "config", "panels.local.yaml"),
            panels_installed=os.path.join(REPO, "config", "panels.local.yaml"),
            soc_env=os.path.join(REPO, ".env"),
            wall_unit=os.path.join(REPO, "dev", "run", "soc-wall.service"),
            soc_root=REPO,
            pinentry=os.path.join(REPO, "scripts", "pinentry-vault.py"),
            secret_dir=os.path.join(REPO, "dev", "run", "secret"),
            config_vault_item="SOC Wall Config",
            inject_tmpl=os.path.join(REPO, "inject", "login.js.tmpl"),
            default_backend="dev",
            panels_mode=0o644, env_mode=0o600,
        )

    # 'pi'/'auto': ask the shared resolver where this user can actually write.
    cp = _configpaths()
    pw = cp.resolve_write("panels", want_etc=True, can_escalate=can_escalate)
    ew = cp.resolve_write("env", want_etc=True, can_escalate=can_escalate)
    via = pw["via"]
    if via in ("etc", "env"):
        # Canonical deployed (or an explicit override pointing at the system tree).
        soc_root = "/opt/soc-display"
        secret_dir = "/etc/soc-display/secret"
        wall_unit = "/etc/systemd/system/soc-wall.service"
        inject_tmpl = "/opt/soc-display/inject/login.js.tmpl"
    else:
        # Per-user fallback: the sealed master must live where THIS user can read it,
        # so secret_dir rides alongside the user-dir panels.yaml. No systemd unit
        # (a per-user desktop wall is launched from the menu, not via root systemd).
        soc_root = "/opt/soc-display" if os.path.isdir("/opt/soc-display") else REPO
        secret_dir = os.path.join(cp.user_dir(), "secret")
        wall_unit = None
        inject_tmpl = os.path.join(soc_root, "inject", "login.js.tmpl")
    return dict(
        mode="pi", via=via, marker=pw.get("marker"),
        needs_privilege=pw.get("needs_privilege", False),
        panels_out=pw["path"],
        panels_installed=pw["path"],
        soc_env=ew["path"],
        wall_unit=wall_unit,
        soc_root=soc_root,
        pinentry=os.path.join(soc_root, "scripts", "pinentry-vault.py"),
        secret_dir=secret_dir,
        config_vault_item="SOC Wall Config",
        inject_tmpl=inject_tmpl,
        default_backend="litebw",
        panels_mode=pw["mode"], env_mode=ew["mode"],
    )


def _drop_marker(paths: dict, dry: bool):
    """When the wizard fell back to the per-user config dir, write the `active`
    marker so the reader's marker-gated user tier picks THIS file up over a stale
    /etc. The marker records the path it claims + a timestamp + the writer euid so
    doctor --explain can show 'user config active since … (uid N)'."""
    marker = paths.get("marker")
    if not marker:
        return
    if dry:
        print(yellow(f"   [dry-run] would activate per-user config: {marker}"))
        return
    os.makedirs(os.path.dirname(marker), 0o700, exist_ok=True)
    body = (f"{paths['panels_out']}\n"
            f"# activated {time.strftime('%Y-%m-%dT%H:%M:%S%z')} by uid {os.geteuid()}\n")
    with open(marker, "w", encoding="utf-8") as fh:
        fh.write(body)
    note(f"activated per-user config for this login (marker: {marker})")


def _confirm_reaches_wall(paths: dict, soc_env: "dict | None", cfg: "dict | None",
                          dry: bool) -> bool:
    """FAIL-SAFE: after writing, assert that the file the wall will READ is exactly
    what we just WROTE — resolving with the SAME shared logic. Prints the cause
    VISIBLY (never silent) when they disagree, and returns True iff they agree.

    Catches: a stale higher-precedence file shadowing our write, an $SOC_PANELS_FILE
    pinning a third path, and the litebw/rbw vault-note-is-source-of-truth case
    (a YAML-only write won't reach the wall until the note is updated)."""
    if dry:
        return True
    cp = _configpaths()
    wrote = paths["panels_out"]
    read_path, label = cp.resolve_read("panels")
    if read_path and os.path.abspath(read_path) == os.path.abspath(wrote):
        if paths.get("via") == "user":
            ok(f"Saved to {wrote} and activated for YOUR user. Launch the wall from "
               f"THIS login and it uses the new panels. For system-wide, re-run as "
               f"root (or allow the password prompt).")
        else:
            ok(f"Config written to {wrote} — the wall will read it. Launch Desktop/Kiosk mode.")
        reached = True
    else:
        err(f"Saved to {wrote} but the wall will read {read_path or '(nothing)'} "
            f"because: {label}. Unset SOC_PANELS_FILE / remove the shadowing file / "
            f"re-run as root so the config reaches the wall.")
        reached = False

    # litebw/rbw: the vault note is the source of truth unless SOC_CONFIG_FROM_VAULT=0.
    env = soc_env or {}
    backend = env.get("SOC_VAULT_BACKEND", "")
    if backend in ("litebw", "rbw") and env.get("SOC_CONFIG_FROM_VAULT", "1") != "0":
        warn(f"Backend={backend} reads the '{env.get('SOC_CONFIG_VAULT_ITEM', 'SOC Wall Config')}' "
             f"vault note FIRST; your file change won't show until that note is "
             f"updated — push it (setup.py deploy pushes config), or set "
             f"SOC_CONFIG_FROM_VAULT=0 to force the file.")
    return reached


def _default_target(env: "Env") -> str:
    """The write target when --target is not given. In a bare dev checkout (no
    deployed /etc/soc-display and no /opt/soc-display) keep today's 'dev' behaviour
    so `make dev` / tests write the repo. On a DEPLOYED box, use 'pi' even for a
    non-root desktop user: resolve_paths('pi') then lands the config where the wall
    reads it (the per-user fallback + marker), instead of silently writing a repo
    file the wall never sees — the bug this whole change fixes."""
    deployed = os.path.isdir("/etc/soc-display") or os.path.isdir("/opt/soc-display")
    if env.is_root:
        return "pi"
    return "pi" if deployed else "dev"


def main():
    global ASSUME_DEFAULTS
    ap = argparse.ArgumentParser(
        description="Setup, diagnose, repair + install the SOC video wall.")
    ap.add_argument("command", nargs="?", default=None,
                    choices=["menu", "deploy", "first-run", "wizard", "wizard-gui",
                             "doctor", "repair", "install", "creds",
                             "provision", "create-users", "vault-register",
                             "vault-seed", "seal", "write-config", "uninstall"],
                    help="menu (default on a TTY) | deploy (full automated "
                         "deploy) | first-run (seal the one-time PIN) | wizard "
                         "(config) | wizard-gui (graphical config) | doctor "
                         "(diagnose) | repair (fix/install missing) | install "
                         "(OS install + wizard) | creds (logins) || PROVISIONING "
                         "(headless parity with the GUI): provision (whole "
                         "fresh-box flow) | create-users | vault-register | "
                         "vault-seed | seal | write-config | uninstall")
    ap.add_argument("--clean", action="store_true",
                    help="deploy: wipe generated config/state first (fresh deploy)")
    ap.add_argument("--fresh", action="store_true",
                    help="deploy: force a full OS reinstall even if already installed")
    ap.add_argument("--dry-run", action="store_true", help="show what would be written; write nothing")
    ap.add_argument("--defaults", action="store_true", help="accept every default (non-interactive)")
    ap.add_argument("--target", choices=["pi", "dev"], help="where to write (default: pi if root, else dev)")
    ap.add_argument("--section", choices=["all", "display", "panels", "tunnel", "vpn", "proxy", "vault", "server"],
                    default="all", help="run just one section (wizard)")
    # --- provisioning-core flags (parity with the GUI Setup) ------------------
    ap.add_argument("--mode", choices=["kiosk", "desktop"], default="kiosk",
                    help="provision: which mode's session/units to wire (default: kiosk)")
    ap.add_argument("--email", default="", help="provision/vault-*: the Vaultwarden account email")
    ap.add_argument("--url", default="http://127.0.0.1:8222",
                    help="provision/vault-*: the Vaultwarden base URL")
    ap.add_argument("--pin", default="", help="seal: PIN for the host-bound seal (auto-generated if omitted)")
    ap.add_argument("--master-fd", type=int, default=None,
                    help="seal/vault-*: read the master password from this FD (NEVER an argv flag)")
    ap.add_argument("--seed", dest="seed", action="store_true", default=True,
                    help="provision: seed the configured panels' vault-login items (default)")
    ap.add_argument("--no-seed", dest="seed", action="store_false",
                    help="provision: do NOT seed panel-login items")
    ap.add_argument("--purge", action="store_true", help="uninstall: also remove users + Vaultwarden data")
    ap.add_argument("--yes", action="store_true", help="non-interactive: accept every prompt")
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
        "creds": cmd_creds, "wizard": cmd_wizard, "wizard-gui": cmd_wizard_gui,
        "provision": cmd_provision, "create-users": cmd_create_users,
        "vault-register": cmd_vault_register, "vault-seed": cmd_vault_seed,
        "seal": cmd_seal, "write-config": cmd_write_config,
        "uninstall": cmd_uninstall,
    }
    return dispatch[cmd](args)


# --------------------------------------------------------------------------- #
# Provisioning-core CLI wrappers — every GUI Setup action reachable headlessly.
# Each is a THIN wrapper over a provision.* function (the GUI calls the identical
# function — parity by construction; no duplicated logic).
# --------------------------------------------------------------------------- #
def _opts_from_args(args) -> "provision.Opts":
    """Build the provisioning Opts from argparse (the GUI builds the same)."""
    return provision.Opts(
        mode=getattr(args, "mode", "kiosk"),
        email=getattr(args, "email", "") or "",
        url=getattr(args, "url", "http://127.0.0.1:8222"),
        pin=getattr(args, "pin", "") or "",
        seed=getattr(args, "seed", True),
        target=getattr(args, "target", None) or "pi",
        fresh=getattr(args, "fresh", False),
        dry_run=getattr(args, "dry_run", False),
    )


def _read_master_fd(args) -> str:
    """Read the master from --master-fd (NEVER argv). Returns '' if none given —
    the seal/vault steps then fall back to the sealed source / stdin prompt."""
    fd = getattr(args, "master_fd", None)
    if fd is None:
        return ""
    try:
        with os.fdopen(os.dup(fd), "r") as fh:
            return fh.readline().rstrip("\n")
    except Exception as e:  # noqa: BLE001
        err(f"could not read the master from fd {fd}: {e}")
        return ""


def _require_provision() -> bool:
    if provision is None:
        err("the provisioning core (provision.py) is not available")
        return False
    return True


def cmd_provision(args) -> int:
    """The whole fresh-box flow — the CLI analogue of the GUI's Apply. Calls the
    SAME provision.provision_all the GUI drives. Honours --dry-run / SOC_PROVISION_DRY_RUN."""
    if not _require_provision():
        return 1
    env = Env()
    opts = _opts_from_args(args)
    if args.dry_run:
        os.environ["SOC_PROVISION_DRY_RUN"] = "1"
    paths = resolve_paths(opts.target)
    if opts.dry:
        banner("SOC video-wall · provision (DRY RUN — nothing will change)")
        provision.print_plan(opts)
        # Drive the full flow in dry-run so the printed plan is exercised end to end.
        cfg = load_yaml(paths["panels_installed"]) or {}
        soc_env = load_env_file(paths["soc_env"])
        provision.provision_all(opts, cfg=cfg, soc_env=soc_env, paths=paths,
                                master="", report=_prov_report)
        banner("Dry run complete — no host state changed")
        return 0
    if not env.is_root:
        warn("provision needs root for packages/users/deploy — re-run with sudo")
        return 1
    cfg = load_yaml(paths["panels_installed"]) or {}
    soc_env = load_env_file(paths["soc_env"])
    master = _read_master_fd(args)
    backend = (soc_env or {}).get("SOC_VAULT_BACKEND") or paths.get("default_backend", "litebw")
    banner("SOC video-wall · provision (end to end)")
    res = provision.provision_all(opts, cfg=cfg, soc_env=soc_env, paths=paths,
                                  master=master, backend=backend, report=_prov_report)
    master = ""  # scrub
    if res.ok:
        ok(res.detail)
        return 0
    err(res.detail)
    return 1


def _prov_report(step: str, status: str, detail: str = "") -> None:
    tail = f" — {detail}" if detail else ""
    if status == "FAILED":
        err(f"{step}: {status}{tail}")
    elif status == "running":
        note(f"{step} …")
    else:
        ok(f"{step}: {status}{tail}")


def cmd_create_users(args) -> int:
    """Create the kiosk + desktop (+ service) users (provision.step_users)."""
    if not _require_provision():
        return 1
    opts = _opts_from_args(args)
    if args.dry_run:
        os.environ["SOC_PROVISION_DRY_RUN"] = "1"
    if not opts.dry and os.geteuid() != 0:
        err("create-users needs root (or --dry-run)")
        return 1
    res = provision.step_users(opts)
    (ok if res.ok else err)(res.detail)
    return 0 if res.ok else 1


def cmd_vault_register(args) -> int:
    """Register / ensure the Vaultwarden account (provision.step_vault_account,
    which calls host.vaultsetup.ensure_account — the SAME path the GUI's Create
    account button uses)."""
    if not _require_provision():
        return 1
    opts = _opts_from_args(args)
    if not opts.email:
        err("vault-register needs --email")
        return 1
    if args.dry_run:
        os.environ["SOC_PROVISION_DRY_RUN"] = "1"
    master = _read_master_fd(args)
    if not master and not opts.dry:
        master = ask_secret("vault master password (for the account)")
    res = provision.step_vault_account(opts, master)
    master = ""  # scrub
    (ok if res.ok else err)(res.detail)
    return 0 if res.ok else 1


def cmd_vault_seed(args) -> int:
    """Seed the configured panels' vault-login items (provision.step_vault_seed)."""
    if not _require_provision():
        return 1
    opts = _opts_from_args(args)
    paths = resolve_paths(opts.target)
    cfg = load_yaml(paths["panels_installed"]) or {}
    if args.dry_run:
        os.environ["SOC_PROVISION_DRY_RUN"] = "1"
    master = _read_master_fd(args)
    if not master and not opts.dry:
        master = ask_secret("vault master password (to seed logins)")
    res = provision.step_vault_seed(opts, master, cfg)
    master = ""  # scrub
    (ok if res.ok else err)(res.detail)
    return 0 if res.ok else 1


def cmd_seal(args) -> int:
    """Seal the master host-bound (provision.step_seal -> setup.seal_master).
    Master via --master-fd / stdin — NEVER argv."""
    if not _require_provision():
        return 1
    env = Env()
    opts = _opts_from_args(args)
    paths = resolve_paths(opts.target)
    soc_env = load_env_file(paths["soc_env"])
    backend = (soc_env or {}).get("SOC_VAULT_BACKEND") or paths.get("default_backend", "litebw")
    if args.dry_run:
        os.environ["SOC_PROVISION_DRY_RUN"] = "1"
    master = _read_master_fd(args)
    if not master and not opts.dry:
        if not sys.stdin.isatty():
            master = sys.stdin.readline().rstrip("\n")
        else:
            master = ask_secret("vault master password (to seal)")
    res = provision.step_seal(opts, master, paths, soc_env, backend)
    master = ""  # scrub
    (ok if res.ok else err)(res.detail)
    return 0 if res.ok else 1


def cmd_write_config(args) -> int:
    """Render + write panels.yaml / soc.env / wall-unit (provision.step_write_config)."""
    if not _require_provision():
        return 1
    opts = _opts_from_args(args)
    paths = resolve_paths(opts.target)
    cfg = load_yaml(paths["panels_installed"]) or {}
    soc_env = load_env_file(paths["soc_env"])
    if args.dry_run:
        os.environ["SOC_PROVISION_DRY_RUN"] = "1"
    if not cfg.get("panels"):
        warn("no panels configured yet — run the wizard first (python3 setup.py wizard)")
    res = provision.step_write_config(opts, cfg, soc_env, paths)
    (ok if res.ok else err)(res.detail)
    return 0 if res.ok else 1


def cmd_uninstall(args) -> int:
    """Headless uninstall — shells uninstall.sh so removal == the GUI Uninstall.
    --purge passes through (also removes users + Vaultwarden data)."""
    env = Env()
    script = os.path.join(REPO, "uninstall.sh")
    if not os.path.exists(script):
        err(f"uninstall.sh not found at {script}")
        return 1
    cmd = [script] + (["--purge"] if getattr(args, "purge", False) else [])
    if getattr(args, "yes", False):
        cmd.append("--yes")
    return _run(cmd if env.is_root else ["sudo"] + cmd)


def cmd_wizard(args) -> int:
    env = Env()
    target = args.target or _default_target(env)
    paths = resolve_paths(target)

    banner("SOC video-wall · interactive setup")
    print(f"   target   : {bold(target)}  ({'Raspberry Pi / root' if target == 'pi' else 'dev workstation'})")
    print(f"   panels   : {paths['panels_out']}")
    print(f"   soc.env  : {paths['soc_env']}")
    print(f"   detected : root={env.is_root} apt={env.has_apt} pi={env.is_pi} venv={env.has_venv}")
    if args.dry_run:
        print(yellow("   mode     : DRY RUN — no files will be written"))
    if paths.get("via") == "user":
        warn("/etc/soc-display is not writable here — saving to your per-user config "
             f"({os.path.dirname(paths['panels_out'])}) and activating it for THIS login. "
             "Re-run as root for a system-wide install.")

    prev = load_yaml(paths["panels_out"])
    if prev:
        note("loaded your previous answers from the existing config as defaults")

    # Collect configuration
    cfg = {}
    cfg["display"] = section_display(prev) if args.section in ("all", "display") else (prev or {}).get("display", _def_display())
    cfg["panels"] = section_panels(cfg["display"], prev) if args.section in ("all", "panels") else (prev or {}).get("panels", [])
    cfg["tunnel"] = section_tunnel(cfg["panels"], prev) if args.section in ("all", "tunnel") else (prev or {}).get("tunnel", {"enabled": False})
    cfg["vpns"] = (section_vpns(prev) if args.section in ("all", "vpn")
                   else cfg_vpns(prev or {}))
    cfg["proxy"] = section_proxy(prev) if args.section in ("all", "proxy") else (prev or {}).get("proxy", {"enabled": False})

    cfg_vpn_list = cfg_vpns(cfg)
    any_vpn = any(v.get("enabled") for v in cfg_vpn_list)
    soc_env = None
    if args.section in ("all", "vault"):
        soc_env = section_vault(paths, load_env_file(paths["soc_env"]), any_vpn)
    if args.section in ("all", "server"):
        section_server(paths, args.dry_run)   # guidance only — Vaultwarden has no .env

    # Summary
    banner("Review")
    enabled_vpns = [v for v in cfg_vpn_list if v.get("enabled")]
    print(f"   {len(cfg['panels'])} panel(s); "
          f"tunnel {'ON' if cfg['tunnel'].get('enabled') else 'off'}; "
          f"VPN {len(enabled_vpns)} enabled; "
          f"proxy {'ON' if cfg.get('proxy', {}).get('enabled') else 'off'}")
    for v in enabled_vpns:
        owner = "  [default-route]" if v.get("default_route") else ""
        print(dim(f"     - vpn {v.get('name', '?')} [{v.get('type', 'fortinet')}]{owner}"))
    for p in cfg["panels"]:
        tgt = p.get("url") or f"tunnel:{p.get('tunnel', {}).get('local_port')}"
        print(dim(f"     - {p['id']} [{p['engine']}/{p['mode']}] {tgt}  <- {p['vault_item']}"))
    if not ask_bool("Write these files now?", True):
        err("nothing written")
        return 1

    # FAIL-SAFE pre-flight: if even the chosen fallback dir is unwritable (locked-down
    # / quota'd / immutable ~/.config), say WHY now — never die with a raw
    # PermissionError traceback half-way through the write.
    if not args.dry_run:
        wdir = os.path.dirname(paths["panels_out"]) or "."
        cp = _configpaths()
        if not cp._dir_writable(wdir):
            err(f"cannot write the config: {wdir} is not writable by this user "
                f"(uid {os.geteuid()}).")
            note("Fix the directory permissions, free up space, or re-run as root "
                 "(writes /etc/soc-display). Nothing was written.")
            return 1

    # Write
    banner("Writing files")
    write_file(paths["panels_out"], render_panels_yaml(cfg), paths["panels_mode"], args.dry_run)
    if soc_env is not None:
        write_file(paths["soc_env"], render_soc_env(soc_env), paths["env_mode"], args.dry_run)
        # The supervised session unit with the same config baked in as
        # Environment= (no soc.env at runtime) + Restart=always.
        if paths.get("wall_unit"):
            write_file(paths["wall_unit"],
                       render_wall_unit(soc_env, soc_root=paths["soc_root"]),
                       0o644, args.dry_run)

    # Per-user fallback: activate this config for the reader (marker-gated tier).
    _drop_marker(paths, args.dry_run)

    if not args.dry_run:
        validate_panels(paths["panels_out"])

    # Remember what we just built so `deploy` can store credentials for it
    # in-process (without re-reading the file through PyYAML).
    global _LAST_CFG, _LAST_SOC_ENV
    _LAST_CFG = cfg
    _LAST_SOC_ENV = soc_env if soc_env is not None else load_env_file(paths["soc_env"])

    if not getattr(args, "_in_deploy", False):
        post_actions(env, cfg, target, args.dry_run)

    # FAIL-SAFE: confirm the wall will actually read what we just wrote.
    _confirm_reaches_wall(paths, _LAST_SOC_ENV, cfg, args.dry_run)

    banner("Done")
    print("   Guide: docs/SETUP.md   ·   Re-run anytime: python3 setup.py")
    return 0


def _def_display():
    return dict(auto=True, width=1920, height=1080, cols=2, rows=2, gap=0)


if __name__ == "__main__":
    sys.exit(main())
