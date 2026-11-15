"""
On-screen configuration for the SOC wall.

A floating, always-on-top utility window an operator opens *at the glass* — via
the corner gear button or Ctrl+Shift+C — to set each tile's URL, vault login and
selectors, the VPN/proxy/tunnel/display settings and Vaultwarden credentials live,
with no SSH and no YAML editing. Changes apply immediately and are written to an
overrides file so they survive a restart.

The window is non-modal: it hovers above the wall without blocking the panels
behind it (calibrating login zones needs clicks on a panel), and a stray click
elsewhere does not dismiss it.

Access control, for a window anyone standing at the wall can reach:

  * SOC_ONSCREEN_CONFIG=0   the window refuses to open at all.
  * SOC_CONFIG_REQUIRE_PIN=1  it never opens or saves without a PIN or TOTP, even
    on a wall where none has been enrolled yet.
  * Once a PIN or TOTP is set, the form is not even built until one is entered.
  * Inside the form, every destructive or secret-bearing action re-authenticates
    (_require_reauth) first, and revealing a stored credential takes the operator's
    OS password instead (_prompt_os_password). A failed re-auth changes nothing.

The PIN is stored only as a salted SHA-256 digest (never clear text).

Nothing here may block the GTK thread: the window lives in the same process as
the panels, so a hung vault must not freeze the wall. Vault and network calls run
on workers (_in_worker, or _wait_for where a flow has to stop for the result).
Tabs are built the first time they are looked at; this box has 1 GB of RAM and
the window is rarely opened.

State lives under $SOC_STATE_DIR (default ~/.config/soc-wall):
  overrides.json   {panel_id: {"url": "...", "title": "..."}, "_vpns": [...], ...}
  config.pin       "<salt_hex>$<digest_hex>"   (mode 0600)
  config.totp      base32 TOTP secret          (mode 0600)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import threading
import time

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import config as cfg  # noqa: E402
from . import style  # noqa: E402
from . import complexity as _cx  # noqa: E402
from . import locker as _lk  # noqa: E402
from . import totp as _totp  # noqa: E402


def _run_modal(dlg):
    """dlg.run(), but one that a person can walk away from on an unattended wall."""
    from .wall import _run_bounded
    return _run_bounded(dlg)



# Sentinels for _fetch_creds_with_recovery — distinct singleton objects so `is`
# reliably tells "no such item" / "operator cancelled" from a real result dict.
_NOT_FOUND = object()
_CANCELLED = object()

MAX_URL_LEN = 2048
MAX_TITLE_LEN = 200
MAX_VAULT_ITEM_LEN = 200
MAX_SELECTOR_LEN = 500
MAX_MARKER_LEN = 200
MAX_VPN_NAME_LEN = 100
MAX_VPN_GATEWAY_LEN = 253
MAX_VPN_DOMAIN_LEN = 253
MAX_VPN_REALM_LEN = 200
MAX_VPN_CONFIG_LEN = 8192
MAX_IMPORT_BYTES = 1024 * 1024

# How long a flow that must stop for a vault/PAM answer waits before giving up.
# The Cancel button is always available sooner.
VAULT_WAIT_SEC = 20


# --------------------------------------------------------------------------- #
# State directory + overrides + PIN store (pure, no GTK — unit-testable)
# --------------------------------------------------------------------------- #
def state_dir() -> str:
    d = os.environ.get("SOC_STATE_DIR") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
        "soc-wall")
    os.makedirs(d, exist_ok=True)
    return d


def _overrides_path() -> str:
    return os.path.join(state_dir(), "overrides.json")


def load_overrides() -> dict:
    try:
        with open(_overrides_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def valid_url(url: str) -> bool:
    """A panel URL must be empty (unconfigured) or a valid http(s) URL. Delegates
    to the canonical validator so the glass and the loader agree: file:,
    javascript:, data:, embedded credentials, control-char smuggling and host-less
    URLs are all rejected here too."""
    return cfg.valid_http_url(url, allow_empty=True)


def _sanitize_len(s: str, max_len: int) -> str:
    """Strip and truncate a form value to max_len."""
    return (s or "").strip()[:max_len]


def save_overrides(d: dict):
    path = _overrides_path()
    tmp = path + ".tmp"
    # 0600: panel URLs can reveal internal hostnames; keep them owner-only.
    # fsync before replace so a power cut right after the rename can't leave a
    # zero-length overrides.json (SD-card durability); remove the stale tmp and
    # re-raise on any failure so a non-serialisable value / ENOSPC surfaces
    # instead of accumulating orphan .tmp files (mirrors backup / litebw).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _pin_path() -> str:
    return os.path.join(state_dir(), "config.pin")


def pin_is_set() -> bool:
    return os.path.exists(_pin_path())


def set_pin(pin: str):
    """Store a salted SHA-256 digest of the PIN (0600). Empty pin clears it."""
    if not pin:
        clear_pin()
        return
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + pin.encode("utf-8")).hexdigest()
    path = _pin_path()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"{salt.hex()}${digest}")


def clear_pin():
    try:
        os.remove(_pin_path())
    except OSError:
        pass


def verify_pin(pin: str) -> bool:
    try:
        with open(_pin_path(), "r", encoding="utf-8") as fh:
            salt_hex, _, digest = fh.read().strip().partition("$")
        want = hashlib.sha256(bytes.fromhex(salt_hex) + pin.encode("utf-8")).hexdigest()
        # Bytes, not str: compare_digest raises TypeError on non-ASCII text, and
        # the stored side is whatever is in the file.
        return hmac.compare_digest(want.encode(), digest.encode())
    except (OSError, ValueError):
        return False


def _totp_path() -> str:
    return os.path.join(state_dir(), "config.totp")


def totp_is_set() -> bool:
    return os.path.exists(_totp_path())


def verify_pin_or_totp(code: str) -> bool:
    """Settings-gate verify: accepts either the saved PIN OR a current TOTP code
    from the enrolled secret. Both paths compare with hmac.compare_digest."""
    if not code or not code.strip():
        return False
    code = code.strip()
    if pin_is_set() and verify_pin(code):
        return True
    if totp_is_set():
        secret = _totp.load(_totp_path())
        try:
            return bool(secret) and _totp.verify(secret, code)
        except ValueError:                          # corrupt secret: fail closed
            return False
    return False


def require_pin() -> bool:
    """SEC-7: in production the on-screen config must never open without a PIN.
    soc-wall.service bakes SOC_CONFIG_REQUIRE_PIN=1; dev leaves it unset. A value
    that is set but unparseable counts as required: this gate fails closed."""
    raw = os.environ.get("SOC_CONFIG_REQUIRE_PIN")
    return cfg.env_bool("SOC_CONFIG_REQUIRE_PIN", bool((raw or "").strip()))


def onscreen_config_enabled() -> bool:
    """SOC_ONSCREEN_CONFIG=0 disables the on-screen config outright. main.py then
    wires no gear/hotkey; this also covers the paths that call open_config()
    directly (the unconfigured launch, the tray)."""
    return os.environ.get("SOC_ONSCREEN_CONFIG", "1") != "0"


def _reauth_verify(code: str) -> bool:
    """Pure verifier shared by every destructive surface in the GUI: PIN OR TOTP.
    An empty code never passes, and neither does anything when nothing is
    enrolled."""
    if not code or not code.strip():
        return False
    return verify_pin_or_totp(code)


def _reauth_required() -> bool:
    """True when at least one Settings auth method is enrolled."""
    return pin_is_set() or totp_is_set()


def gate_unlocked(require_pin_: bool, pin_set: bool) -> bool:
    """Decide whether the config form opens WITHOUT entering a PIN. Pure, so it
    is unit-testable without a display.

      * dev, no PIN set        -> open (convenience)
      * a PIN is set           -> always gated (must enter it)
      * production (require)   -> always gated, even with no PIN set, so a box at
                                  the glass cannot reach the config surface.
    """
    return (not require_pin_) and (not pin_set)


class _AuthThrottle:
    """Back-off after wrong codes: 3+ consecutive failures -> 5 s, doubling to a
    60 s cap. One module-level instance per secret, because main.py builds a new
    ConfigWindow on every open: a counter on the window would reset by closing
    and reopening it, which is free at the glass."""

    def __init__(self):
        self.fails = 0
        self.until = 0.0

    def remaining(self) -> int:
        return max(0, math.ceil(self.until - time.monotonic()))

    def failed(self) -> int:
        """Record a wrong code. Returns the cooldown it started (0 if none)."""
        self.fails += 1
        if self.fails < 3:
            return 0
        cooldown = min(60, 5 * 2 ** min(self.fails - 3, 4))
        self.until = time.monotonic() + cooldown
        return cooldown

    def passed(self):
        self.fails = 0
        self.until = 0.0


_gate_throttle = _AuthThrottle()     # the PIN page + _require_reauth: one budget
_os_throttle = _AuthThrottle()       # the OS-password prompt


def _valid_grid(g) -> bool:
    return (isinstance(g, (list, tuple)) and len(g) == 2
            and all(cfg._is_int(x) and x >= 0 for x in g))


def _blank_panel(panel_id: str, grid) -> cfg.Panel:
    """An unconfigured tile, as added at the glass."""
    return cfg.Panel(id=panel_id, engine="webkit", grid=tuple(grid), mode="direct",
                     vault_item="", selectors={}, login_marker="",
                     keepalive=cfg.KeepAlive(strategy="none"), url="", title="")


def _merge_form(target: dict, o: dict):
    """Merge a saved form section over a loaded one, keeping advanced keys the
    form does not show. A None value removes the key (see _mark_cleared)."""
    for k, v in o.items():
        if v is None:
            target.pop(k, None)
        else:
            target[k] = v


def _mark_cleared(out: dict, form: dict, before: dict) -> dict:
    """The *_form_to_dict helpers drop empty values to keep overrides minimal, and
    overrides merge key by key, so a field the operator blanked or a flag they
    unticked would silently keep its old value after a restart: unticking 'skip
    TLS verify' would not stick. Re-add exactly those keys: False for a flag, None
    ('remove it', see _merge_form) for anything else."""
    for k in form:
        if k not in out and before.get(k):
            out[k] = False if isinstance(before[k], bool) else None
    return out


def _apply_panel_additions(panels: list, overrides: dict):
    """Replay panels added/removed at the glass, so they survive a restart on a
    wall whose config lives in panels.yaml rather than the vault note."""
    removed = overrides.get("_removed_panels")
    if isinstance(removed, list):
        panels[:] = [p for p in panels if p.id not in removed]
    have = {p.id for p in panels}
    added = overrides.get("_added_panels")
    for d in (added if isinstance(added, list) else ()):
        pid = d.get("id") if isinstance(d, dict) else None
        if (isinstance(pid, str) and cfg._PANEL_ID_RE.match(pid)
                and pid not in have and _valid_grid(d.get("grid"))):
            panels.append(_blank_panel(pid, d["grid"]))
            have.add(pid)


def apply_overrides_to_panels(panels, overrides: dict):
    """Merge a loaded overrides dict onto the panel objects at startup."""
    _apply_panel_additions(panels, overrides)
    for p in panels:
        o = overrides.get(p.id)
        if not isinstance(o, dict):
            continue
        if "url" in o and valid_url(o.get("url")):
            p.url = o["url"] or None
            if o.get("url"):
                p.mode = "direct"          # a set URL implies a direct panel
        if o.get("title"):
            p.title = o["title"]
        if "vault_item" in o:
            p.vault_item = o["vault_item"] or ""
        if o.get("engine") in ("webkit", "chromium"):
            p.engine = o["engine"]
        if isinstance(o.get("selectors"), dict):
            p.selectors = {k: v for k, v in o["selectors"].items() if v}
        if "login_marker" in o:
            p.login_marker = o["login_marker"] or p.selectors.get("pass", "")
        for flag in ("allow_insecure", "allow_media", "proxy"):
            if isinstance(o.get(flag), bool):
                setattr(p, flag, o[flag])
        if isinstance(o.get("keepalive"), dict):
            ka = o["keepalive"]
            if ka.get("strategy") in cfg.VALID_KEEPALIVE:
                p.keepalive.strategy = ka["strategy"]
            iv = ka.get("intervalSec")
            if cfg._is_int(iv) and iv >= 1:     # same floor as the loader
                p.keepalive.intervalSec = iv
        tenant = o.get("tenant")
        if isinstance(tenant, str) and not cfg._has_ctrl(tenant) \
                and len(tenant.strip()) <= cfg.MAX_TENANT_LEN:
            p.tenant = tenant.strip()
        if "login_zones" in o:
            errs = []
            cfg._validate_login_zones(o["login_zones"], f"panel {p.id}", errs, [])
            if not errs:
                p.login_zones = {k: dict(v) for k, v in o["login_zones"].items()}
        if _valid_grid(o.get("grid")):
            p.grid = tuple(o["grid"])


def apply_vpn_override(vpn: dict, overrides: dict):
    """Merge a saved VPN override (set from the on-screen VPN tab) onto the loaded
    vpn dict at startup. The override is what the operator entered at the glass;
    it merges over the config note/file so advanced fields not on the form
    (set_routes, etc.) are preserved."""
    o = overrides.get("_vpn")
    if isinstance(o, dict):
        _merge_form(vpn, o)
    return vpn


def apply_vpns_override(vpns: list, overrides: dict) -> list:
    """Multi-VPN startup merge. The _vpns override is a list of dicts; each is
    merged by name into the corresponding loaded VPN (preserving advanced fields
    set in panels.yaml that the form doesn't expose). Entries that don't match any
    loaded VPN are appended, and VPNs removed or renamed at the glass
    (_vpns_removed) are dropped: a by-name merge alone would bring them back from
    the source config. Returns the updated list."""
    o = overrides.get("_vpns")
    if not isinstance(o, list):
        return vpns
    removed = overrides.get("_vpns_removed")
    if isinstance(removed, list):
        vpns[:] = [v for v in vpns if v.get("name") not in removed]
    by_name = {v.get("name"): i for i, v in enumerate(vpns) if v.get("name")}
    for entry in o:
        if not isinstance(entry, dict):
            continue
        n = entry.get("name")
        if n and n in by_name:
            _merge_form(vpns[by_name[n]], entry)
        else:
            # New VPN added at the glass that wasn't in the source config.
            new = {}
            _merge_form(new, entry)
            vpns.append(new)
            if n:
                by_name[n] = len(vpns) - 1
    return vpns


_VPN_TEXT_KEYS = ("name", "gateway", "vault_item", "config", "domain", "realm",
                  "trusted_cert", "ready_probe", "ca_file",
                  "client_cert", "client_key", "spa_key", "spa_aid",
                  "spa_ports", "mac", "language")
_VPN_FLAG_KEYS = ("ead", "insecure", "config_from_vault")
_VPN_INT_KEYS = ("port", "health_check_interval", "spa_knock_port", "captcha_retries")


def vpn_form_to_dict(v: dict) -> dict:
    """Build a clean vpn config dict from flat on-screen form values: always sets
    enabled+type, keeps only non-empty strings, coerces port/health to int. The
    VPN service re-validates on restart and surfaces problems via its status.

    split_tunnel defaults to ON downstream (config.inode_extra_args), so unlike
    the other flags an explicit False must be kept: dropping it is what used to
    make split tunnelling impossible to turn off from the GUI."""
    out = {"enabled": bool(v.get("enabled")), "type": (v.get("type") or "fortinet")}
    for k in _VPN_TEXT_KEYS:
        val = str(v.get(k) or "").strip()
        if val:
            out[k] = val
    for k in _VPN_FLAG_KEYS:
        if v.get(k):
            out[k] = True
    if "split_tunnel" in v:
        out["split_tunnel"] = bool(v["split_tunnel"])
    for k in _VPN_INT_KEYS:
        try:
            n = int(v.get(k) or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            out[k] = n
    return out


def apply_display_override(display, overrides: dict):
    """Apply a saved display override to the DisplayCfg at startup. Covers
    layout/gap AND the grid + resolution (cols/rows/width/height/auto/fullscreen).
    Out-of-range values are ignored, so a bad override can't wreck the layout."""
    o = overrides.get("_display")
    if not isinstance(o, dict):
        return
    if o.get("layout") in ("auto", "windows", "single"):
        display.layout = o["layout"]
    if cfg._is_int(o.get("gap")) and o["gap"] >= 0:
        display.gap = o["gap"]
    for k in ("auto", "fullscreen"):
        if isinstance(o.get(k), bool):
            setattr(display, k, o[k])
    for k in ("cols", "rows"):
        v = o.get(k)
        if cfg._is_int(v) and 1 <= v <= 8:
            setattr(display, k, v)
    for k in ("width", "height"):
        v = o.get(k)
        if cfg._is_int(v) and 320 <= v <= 16384:
            setattr(display, k, v)


def proxy_form_to_dict(p: dict) -> dict:
    """Build a clean proxy override dict from on-screen form values: drops empty
    strings, coerces ignore_hosts (comma- or newline-separated) to a clean list."""
    out = {"enabled": bool(p.get("enabled"))}
    for k in ("url", "vault_item"):
        val = str(p.get(k) or "").strip()
        if val:
            out[k] = val
    raw = p.get("ignore_hosts")
    if isinstance(raw, str):
        items = [h.strip() for h in raw.replace("\n", ",").split(",")]
    else:
        items = list(raw or [])
    items = [h for h in items if h]
    if items:
        out["ignore_hosts"] = items
    return out


def apply_proxy_override(proxy, overrides: dict):
    """Merge a saved proxy override onto the loaded ProxyCfg at startup."""
    o = overrides.get("_proxy")
    if not isinstance(o, dict):
        return
    if isinstance(o.get("enabled"), bool):
        proxy.enabled = o["enabled"]
    if "url" in o:
        proxy.url = str(o.get("url") or "")
    if "vault_item" in o:
        proxy.vault_item = str(o.get("vault_item") or "")
    if "ignore_hosts" in o:
        proxy.ignore_hosts = tuple(str(h) for h in (o.get("ignore_hosts") or ()) if h)


def tunnel_form_to_dict(t: dict) -> dict:
    """Build a clean tunnel-section dict from on-screen form values. extra_forwards
    is split per-line; host_key_checking is limited to what the loader accepts
    (cfg.VALID_HOST_KEY_CHECKING: 'no' is deliberately not an option, SEC-6).
    Empty values are dropped so the override stays minimal."""
    out = {"enabled": bool(t.get("enabled", True))}
    for k in ("jump_host", "identity", "known_hosts"):
        v = str(t.get(k) or "").strip()
        if v:
            out[k] = v
    hkc = str(t.get("host_key_checking") or "").strip().lower()
    if hkc in cfg.VALID_HOST_KEY_CHECKING:
        out["host_key_checking"] = hkc
    raw = t.get("extra_forwards")
    if isinstance(raw, str):
        items = [ln.strip() for ln in raw.splitlines()]
    else:
        items = list(raw or [])
    items = [ln for ln in items if ln]
    if items:
        out["extra_forwards"] = items
    return out


def apply_tunnel_override(tunnel: dict, overrides: dict):
    """Merge a saved tunnel override onto the loaded tunnel dict at startup. As
    with apply_vpn_override, advanced keys not exposed by the form are preserved."""
    o = overrides.get("_tunnel")
    if isinstance(o, dict):
        _merge_form(tunnel, o)
    return tunnel


def _vw_reachable(url: str, timeout: float = 1.0) -> bool:
    """Cheap TCP probe for the Vaultwarden listener — used by the Status tab to
    flag a dead vault before the operator clicks Save on the Credentials tab and
    gets a confusing 'login failed' error. Does NOT speak HTTP; anything bound to
    the port reads as reachable, which is good enough for that. Blocking: call it
    from a worker."""
    import socket
    import urllib.parse
    try:
        u = urllib.parse.urlparse(url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 8222)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _vault_sync(vault):
    """Force the vault backend (litebw or rbw) to re-fetch, and drop the in-process
    TTL cache so the next read really hits it. Blocking: call it from a worker."""
    backend = getattr(vault, "backend", None)
    if backend is None or not hasattr(backend, "sync"):
        raise RuntimeError("no vault backend attached to this window")
    backend.sync()
    if hasattr(vault, "invalidate"):
        vault.invalidate()


def _inventory_items(panels, vpns, proxy_item, tunnel, folder_items=()) -> list:
    """Every vault item name the wall touches, deduped, each {name, origin}. First
    source wins the origin label: panels, VPNs, proxy, tunnel, then the auth
    folder. Items found only there are implicitly known to the wall, not pinned by
    a config field."""
    seen = {}                                    # name -> origin
    for p in (panels or []):
        n = (getattr(p, "vault_item", None) or "").strip()
        if n and n not in seen:
            seen[n] = f"panel:{p.id}"
    for v in (vpns or []):
        if not v:                                # nullified entry from remove
            continue
        n = (v.get("vault_item") or "").strip()
        if n and n not in seen:
            seen[n] = f"vpn:{v.get('name', '?')}"
    prx = (proxy_item or "").strip()
    if prx and prx not in seen:
        seen[prx] = "proxy"
    if tunnel and isinstance(tunnel, dict):
        tn = (tunnel.get("vault_item") or "").strip()
        if tn and tn not in seen:
            seen[tn] = "tunnel"
    folder = _totp._VAULT_TOTP_FOLDER
    for n in folder_items:
        n = (n or "").strip()
        if n and n not in seen:
            seen[n] = f"{folder} folder"
    return [{"name": n, "origin": o} for n, o in seen.items()]


def _zones_markup(zones) -> str:
    """Markup for the per-panel "login zones: …" status label."""
    if not zones:
        return "<b>login zones:</b> none — selectors + heuristics only"
    names = GLib.markup_escape_text(", ".join(sorted(zones)))
    return f"<b>login zones:</b> calibrated ✓  ({names})"


def _memory_summary() -> str:
    """One line from /proc/meminfo (no deps)."""
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            fields = dict(ln.split(":", 1) for ln in fh if ":" in ln)
        total = int(fields["MemTotal"].split()[0]) // 1024
        avail = int(fields["MemAvailable"].split()[0]) // 1024
        used = total - avail
        return f"memory         : {used} MB / {total} MB ({used * 100 // total}% used)"
    except (OSError, ValueError, KeyError, IndexError, ZeroDivisionError):
        return "memory         : unavailable"


def _status_warnings(vw_url, vw_email, reachable, sealed, configured,
                     with_creds, stale) -> list:
    """The Status tab's loud warnings. The operator opens that tab when something
    feels off, so each is a one-line "you have a silent failure waiting for you"
    with the fix inline."""
    out = []
    if not reachable:
        out.append(f"⚠ Vaultwarden at {vw_url} is NOT reachable — auto-login and "
                   f"the Credentials tab will fail. Check 'systemctl status "
                   f"vaultwarden'.")
    if not sealed:
        out.append("⚠ Master password is NOT host-sealed — the wall cannot "
                   "self-unlock the vault at boot, so auto-login is dead until "
                   "you run 'sudo python3 setup.py first-run'.")
    if reachable and not vw_email:
        out.append("⚠ SOC_VAULT_EMAIL is empty in soc.env — register an account "
                   "and set the email via setup.py wizard, then re-run first-run.")
    if configured > 0 and with_creds == 0:
        out.append(f"⚠ {configured} panel(s) have a URL but NO vault item — those "
                   f"panels will show the login page without auto-filling. Set a "
                   f"vault item on the Panels tab and store the login on "
                   f"Credentials.")
    if with_creds > 0 and not reachable:
        out.append(f"⚠ {with_creds} panel(s) depend on the vault for auto-login "
                   f"but the vault is unreachable — fix vaultwarden first.")
    if stale:
        out.append(f"⚠ selectors may be stale on {len(stale)} panel(s): "
                   f"{', '.join(sorted(stale))}. The dashboard probably changed; "
                   f"update the user/pass/submit selectors and login_marker on "
                   f"the Panels tab > Advanced.")
    return out


def _reboot_machine():
    import subprocess
    try:
        subprocess.run(["systemctl", "reboot"], timeout=10,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("needs root — run: sudo systemctl reboot")


def _repair_install():
    import subprocess
    root = os.environ.get("SOC_DEPLOY_ROOT", "/opt/soc-display")
    try:
        subprocess.run(["sudo", "-n", f"{root}/.venv/bin/python",
                        f"{root}/setup.py", "repair"], timeout=600,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError(f"needs root — run: sudo python3 {root}/setup.py repair")


# --------------------------------------------------------------------------- #
# The window
# --------------------------------------------------------------------------- #
class ConfigWindow(Gtk.Window):
    """on_apply(changes: {id: {"url","title"}}) is called when Apply is pressed,
    after the overrides file has been saved; the host applies them live. It may
    return a dict (pending_restarts / write_back / self_restart / applied_live) so
    the window can say what really happened.

    `vpns` is the canonical VPN list; `vpn` is the legacy single-VPN alias. Either
    gives a VPN tab. `proxy` (config.ProxyCfg) and `tunnel` (conf.tunnel) enable
    their tabs. `vault` lets the Credentials tab list, read, edit and delete items.
    `actions` holds the host callbacks the Actions tab and Calibrate use:
    {reload_panels, restart_wall, lock_wall, show_vpn_log, calibrate_panel,
    stop_vpn_unit}; an absent key just hides or disables that control."""

    def __init__(self, panels, on_apply, on_close=None, display=None, vpn=None,
                 proxy_vault_item="", proxy=None, tunnel=None, login_stats=None,
                 vpns=None, actions=None, vault=None):
        super().__init__(title="SOC wall — settings")
        style.apply_css()
        self.panels = list(panels)       # mutable copy — add/remove modify this
        self.on_apply = on_apply
        self.on_close_cb = on_close
        self.display = display           # config.DisplayCfg | None (Display tab)
        if vpns is not None:
            src = vpns
        elif isinstance(vpn, (list, tuple)):
            src = vpn
        else:
            src = [vpn] if vpn else []
        self._vpns = [dict(v) for v in src if isinstance(v, dict)]
        self._has_vpn_tab = vpns is not None or vpn is not None
        self._vpn_names_open = {v.get("name") for v in self._vpns if v.get("name")}
        self._proxy = proxy              # config.ProxyCfg | None (Proxy tab)
        self._tunnel = tunnel            # conf.tunnel dict | None (Tunnel tab)
        self._login_stats = login_stats  # callable() -> {pid: {attempts, stale}}
        self._actions = actions or {}
        self._vault = vault
        # Callers that still pass only proxy_vault_item get a Credentials-tab row
        # but no Proxy tab.
        self._proxy_vault_item = (getattr(proxy, "vault_item", None)
                                  or proxy_vault_item or "")

        self._rows = {}
        self._grids = {p.id: tuple(p.grid) for p in self.panels}
        self._added_panels: list = []    # panels created in this session
        self._removed_ids: set = set()   # panel IDs removed in this session
        self._panels_box = None
        # Widgets of tabs not built yet stay None; _apply skips those sections.
        self._vpn_ws = []                # one widget dict per VPN; None = removed
        self._vpn_base = []              # form values as loaded; None = added here
        self._vpn_dirty = False          # a VPN was removed since the last save
        self._vpn_box = None
        self._proxy_w = None
        self._proxy_base = None
        self._tunnel_w = None
        self._tunnel_ef = None
        self._tunnel_base = None
        self._layout_c = None
        self._cols_s = None
        self._rows_s = None
        self._cred_master = None
        self._cred_msg = None
        self._form_msg = None
        self._inv_list = None
        self._inv_busy = False
        self._lazy_tabs = {}
        self._form_page = None
        self._closed = False

        self._disabled = not onscreen_config_enabled()
        self._unlocked = (not self._disabled
                          and gate_unlocked(require_pin(), _reauth_required()))

        self.set_keep_above(True)
        # A floating, always-on-top utility panel — NOT modal. On a full-screen
        # kiosk the modal grab gets released by a stray click on a panel behind the
        # window (some WMs treat the lost grab as a dismiss), which looked like the
        # window had vanished. Non-modal is also what lets Calibrate receive clicks
        # on a panel while this is open.
        self.set_modal(False)
        self.set_type_hint(Gdk.WindowTypeHint.UTILITY)
        self.set_skip_taskbar_hint(True)
        self.set_skip_pager_hint(True)
        self.set_deletable(True)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_default_size(820, 600)
        self.set_resizable(True)
        self.get_style_context().add_class("soc-config")
        self.connect("key-press-event", self._on_key)
        self.connect("destroy", self._on_destroy)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.add(self._stack)
        self._stack.add_named(self._build_pin_page(), "pin")
        # The form is only built once the gate has opened: nothing behind it
        # exists for a passer-by to reach, and a locked window costs no RAM.
        if self._unlocked:
            self._enter_form()
        else:
            self._stack.set_visible_child_name("pin")
        # show_all() reverts a Stack to its first child until it is mapped, so
        # re-assert the intended page once the window actually appears.
        self.connect("map", lambda *_: self._stack.set_visible_child_name(
            "form" if self._unlocked else "pin"))

    def _on_destroy(self, *_):
        self._closed = True
        if self.on_close_cb:
            self.on_close_cb()

    # ---- off-the-main-thread helpers ---------------------------------------
    def _in_worker(self, work, done):
        """Run work() on a daemon thread, then done(result, error) on the main
        loop. `work` must not touch GTK. A result that arrives after the window
        closed is dropped."""
        def deliver(res, err):
            if not self._closed:
                done(res, err)
            return False

        def run():
            try:
                res, err = work(), None
            except Exception as e:                       # noqa: BLE001
                res, err = None, e
            GLib.idle_add(deliver, res, err)
        threading.Thread(target=run, daemon=True).start()

    def _busy_dialog(self, text):
        d = Gtk.Dialog(transient_for=self, modal=True, title=text)
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL)
        d.set_default_size(360, 0)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.set_border_width(14)
        spin = Gtk.Spinner()
        spin.start()
        lbl = Gtk.Label(label=text)
        lbl.set_line_wrap(True)
        row.pack_start(spin, False, False, 0)
        row.pack_start(lbl, True, True, 0)
        d.get_content_area().pack_start(row, False, False, 0)
        d.show_all()
        return d

    def _wait_for(self, work, text, timeout=VAULT_WAIT_SEC):
        """Run work() on a worker and wait for it WITHOUT blocking the main loop:
        the modal busy dialog spins a nested loop, so the panels keep painting
        while input to this window is held. For flows that must stop for an
        answer. Returns (status, value): ("ok", result), ("error", exception),
        ("cancelled", None), or ("timeout", None) for a vault that never answers
        (the abandoned daemon thread cannot hold anything up)."""
        st = {"status": None, "value": None, "gone": False, "timed_out": False}
        d = self._busy_dialog(text)

        def finish():
            if not st["gone"]:
                d.response(Gtk.ResponseType.OK)
            return False

        def run():
            try:
                st["value"], st["status"] = work(), "ok"
            except Exception as e:                       # noqa: BLE001
                st["value"], st["status"] = e, "error"
            GLib.idle_add(finish)

        def expired():
            st["timed_out"] = True
            d.response(Gtk.ResponseType.CANCEL)
            return False
        threading.Thread(target=run, daemon=True).start()
        timer = GLib.timeout_add_seconds(timeout, expired)
        rc = d.run()
        st["gone"] = True
        if not st["timed_out"]:
            GLib.source_remove(timer)
        d.destroy()
        if rc == Gtk.ResponseType.OK:
            return st["status"], st["value"]
        return ("timeout" if st["timed_out"] else "cancelled"), None

    # ---- PIN gate ----------------------------------------------------------
    def _gate_hint(self) -> str:
        """Why the gate cannot open at all, or "" when a code can open it."""
        if self._disabled:
            return ("On-screen settings are disabled on this wall "
                    "(SOC_ONSCREEN_CONFIG=0).")
        if require_pin() and not _reauth_required():
            return ("This wall requires a Settings PIN or TOTP and none is "
                    "enrolled, so this window cannot open. An administrator has "
                    "to enrol one first.")
        return ""

    def _build_pin_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_border_width(28)
        title = Gtk.Label(label="🔒  Enter PIN")
        title.get_style_context().add_class("soc-config-title")
        self._pin_entry = Gtk.Entry()
        self._pin_entry.set_visibility(False)
        self._pin_entry.set_input_purpose(Gtk.InputPurpose.DIGITS)
        self._pin_entry.set_alignment(0.5)
        self._pin_entry.set_placeholder_text("PIN or TOTP code")
        self._pin_entry.connect("activate", lambda *_: self._try_unlock())
        self._pin_err = Gtk.Label(label="")
        self._pin_err.get_style_context().add_class("soc-config-error")
        self._pin_err.set_line_wrap(True)
        self._pin_btn = Gtk.Button(label="Unlock")
        self._pin_btn.get_style_context().add_class("soc-config-primary")
        self._pin_btn.connect("clicked", lambda *_: self._try_unlock())
        close_b = Gtk.Button(label="Close")
        close_b.connect("clicked", lambda *_: self.close())
        for w in (title, self._pin_entry, self._pin_err, self._pin_btn, close_b):
            box.pack_start(w, False, False, 0)
        hint = self._gate_hint()
        if hint:
            self._pin_err.set_text(hint)
            self._pin_entry.set_sensitive(False)
            self._pin_btn.set_sensitive(False)
        elif _gate_throttle.remaining():
            self._hold_pin_input(_gate_throttle.remaining())
        return box

    def _hold_pin_input(self, wait: int):
        """Disable the PIN input for `wait` seconds (the back-off)."""
        self._pin_err.set_text(f"Too many wrong attempts — locked for {wait}s")
        self._pin_entry.set_sensitive(False)
        self._pin_btn.set_sensitive(False)

        def _unlock_input():
            self._pin_entry.set_sensitive(True)
            self._pin_btn.set_sensitive(True)
            self._pin_err.set_text("")
            return False
        GLib.timeout_add_seconds(wait, _unlock_input)

    def _try_unlock(self):
        if self._disabled or _gate_throttle.remaining():
            return
        if verify_pin_or_totp(self._pin_entry.get_text()):
            _gate_throttle.passed()
            self._pin_entry.set_text("")
            self._pin_err.set_text("")
            self._enter_form()
            return
        self._pin_entry.set_text("")
        wait = _gate_throttle.failed()
        if wait:                         # rate-limit brute force
            self._hold_pin_input(wait)
        else:
            self._pin_err.set_text("Incorrect PIN")

    def _enter_form(self):
        self._unlocked = True
        if self._form_page is None:
            self._form_page = self._build_form_page()
            self._stack.add_named(self._form_page, "form")
            self._form_page.show_all()
        self._stack.set_visible_child_name("form")

    # ---- config form (tabbed) ----------------------------------------------
    def _add_lazy_tab(self, nb, title, build):
        holder = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._lazy_tabs[nb.append_page(holder, Gtk.Label(label=title))] = build

    def _on_switch_page(self, _nb, page, num):
        build = self._lazy_tabs.pop(num, None)
        if build is None:
            return
        try:
            page.pack_start(build(), True, True, 0)
        except Exception as e:                           # noqa: BLE001
            self._msg(f"could not build this tab: {e}", error=True)
            return
        page.show_all()

    def _build_form_page(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(16)
        head = Gtk.Label(label="SOC wall — settings")
        head.get_style_context().add_class("soc-config-title")
        head.set_xalign(0.0)
        outer.pack_start(head, False, False, 0)

        self._form_msg = Gtk.Label(label="")
        self._form_msg.get_style_context().add_class("soc-config-ok")
        self._form_msg.set_xalign(0.0)
        self._form_msg.set_line_wrap(True)

        nb = Gtk.Notebook()
        nb.append_page(self._tab_panels(), Gtk.Label(label="Panels"))
        self._add_lazy_tab(nb, "Credentials", self._tab_credentials)
        if self.display is not None:
            self._add_lazy_tab(nb, "Display", self._tab_display)
        if self._has_vpn_tab:
            self._add_lazy_tab(nb, "VPN", self._tab_vpn)
        if self._proxy is not None:
            self._add_lazy_tab(nb, "Proxy", self._tab_proxy)
        if self._tunnel is not None:
            self._add_lazy_tab(nb, "Tunnel", self._tab_tunnel)
        self._add_lazy_tab(nb, "Actions", self._tab_actions)
        self._add_lazy_tab(nb, "Security", self._tab_security)
        self._add_lazy_tab(nb, "Status", self._tab_status)
        nb.connect("switch-page", self._on_switch_page)
        outer.pack_start(nb, True, True, 0)
        outer.pack_start(self._form_msg, False, False, 0)

        # Export / Import row
        io_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        export_btn = Gtk.Button(label="⬇ Export YAML")
        export_btn.set_tooltip_text("Save the panels as a YAML file in the "
                                    "wall user's home directory")
        export_btn.connect("clicked", lambda *_: self._export_yaml())
        import_btn = Gtk.Button(label="⬆ Import YAML")
        import_btn.set_tooltip_text("Load the panels from a validated config file")
        import_btn.connect("clicked", lambda *_: self._import_yaml())
        io_row.pack_start(export_btn, False, False, 0)
        io_row.pack_start(import_btn, False, False, 0)
        outer.pack_start(io_row, False, False, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_halign(Gtk.Align.END)
        close_b = Gtk.Button(label="Close")
        close_b.connect("clicked", lambda *_: self.close())
        apply_b = Gtk.Button(label="Apply")
        apply_b.get_style_context().add_class("soc-config-primary")
        apply_b.connect("clicked", lambda *_: self._apply())
        actions.pack_start(close_b, False, False, 0)
        actions.pack_start(apply_b, False, False, 0)
        outer.pack_start(actions, False, False, 4)
        return outer

    def _tab_panels(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(340)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(8)
        self._panels_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._rebuild_panel_rows()
        outer.pack_start(self._panels_box, True, True, 0)

        add_btn = Gtk.Button(label="＋ Add Panel")
        add_btn.get_style_context().add_class("soc-config-primary")
        add_btn.connect("clicked", lambda *_: self._add_panel())
        outer.pack_start(add_btn, False, False, 0)
        scroll.add(outer)
        return scroll

    def _rebuild_panel_rows(self):
        """Build the rows from self.panels (the initial build, and after Import).
        Add/remove/move touch only their own row, so typed-but-unapplied edits in
        the other rows survive."""
        for row in self._rows.values():
            row["frame"].destroy()
        self._rows.clear()
        for p in self.panels:
            self._panels_box.pack_start(self._panel_group(p), False, False, 0)
        self._panels_box.show_all()

    def _grid_size(self):
        """(cols, rows): the Display tab's values if it was built, else the
        loaded config's."""
        if self._cols_s is not None:
            return int(self._cols_s.get_value()), int(self._rows_s.get_value())
        return getattr(self.display, "cols", 2), getattr(self.display, "rows", 2)

    def _free_cell(self):
        cols, rows = self._grid_size()
        taken = set(self._grids.values())
        for row in range(rows):
            for col in range(cols):
                if (col, row) not in taken:
                    return col, row
        return None

    def _next_panel_id(self) -> str:
        used = {p.id for p in self.panels} | self._removed_ids
        n = len(self.panels) + 1
        while f"panel-{n}" in used:
            n += 1
        return f"panel-{n}"

    def _add_panel(self):
        """Add a blank panel in the first free grid cell. A panel outside the grid
        would fail validation when the config is next loaded, so a full grid
        refuses instead."""
        cell = self._free_cell()
        if cell is None:
            self._msg("The grid is full — raise cols/rows on the Display tab first.",
                      error=True)
            return
        panel = _blank_panel(self._next_panel_id(), cell)
        self.panels.append(panel)
        self._added_panels.append(panel)
        self._grids[panel.id] = cell
        self._panels_box.pack_start(self._panel_group(panel), False, False, 0)
        self._panels_box.show_all()

    def _remove_panel(self, panel):
        """Remove a panel from the list; the next Apply drops it from the wall."""
        if _reauth_required() and not self._require_reauth(
                f"removal of panel '{panel.id}'"):
            return
        self.panels = [p for p in self.panels if p.id != panel.id]
        unsaved = any(p.id == panel.id for p in self._added_panels)
        self._added_panels = [p for p in self._added_panels if p.id != panel.id]
        if not unsaved:                  # one added here never reached the wall
            self._removed_ids.add(panel.id)
        self._grids.pop(panel.id, None)
        row = self._rows.pop(panel.id, None)
        if row is not None:
            row["frame"].destroy()

    def _move_panel(self, panel, direction: int):
        """Move panel up (-1) or down (+1): swaps grid positions with its
        neighbour. Takes effect on Apply + restart."""
        idx = next((i for i, p in enumerate(self.panels) if p.id == panel.id), None)
        if idx is None:
            return
        new_idx = idx + direction
        if new_idx < 0 or new_idx >= len(self.panels):
            return
        other = self.panels[new_idx]
        self.panels[idx], self.panels[new_idx] = other, panel
        self._grids[panel.id], self._grids[other.id] = (
            self._grids[other.id], self._grids[panel.id])
        self._panels_box.reorder_child(self._rows[panel.id]["frame"], new_idx)

    def _panel_group(self, p):
        frame = Gtk.Frame(label=f"  {p.display_name}  ")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_border_width(8)
        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(4)
        title_e = Gtk.Entry()
        title_e.set_text(p.title or "")
        title_e.set_placeholder_text("title")
        title_e.set_width_chars(12)
        url_e = Gtk.Entry()
        url_e.set_text(p.url or "")
        url_e.set_hexpand(True)
        url_e.set_placeholder_text("https://host/…  (blank = not configured)")
        url_e.set_input_purpose(Gtk.InputPurpose.URL)
        url_e.connect("activate", lambda *_: self._apply())
        vault_e = Gtk.Entry()
        vault_e.set_text(p.vault_item or "")
        vault_e.set_placeholder_text("vault item")
        vault_e.set_width_chars(13)
        engine_c = Gtk.ComboBoxText()
        for opt in ("webkit", "chromium"):
            engine_c.append_text(opt)
        engine_c.set_active(1 if p.engine == "chromium" else 0)
        tenant_e = Gtk.Entry()
        tenant_e.set_text(getattr(p, "tenant", "") or "")
        tenant_e.set_width_chars(16)
        tenant_e.set_placeholder_text("tenant (optional)")
        for col, (lbl, w) in enumerate((("title", title_e), ("URL", url_e),
                                        ("vault login", vault_e), ("engine", engine_c),
                                        ("tenant", tenant_e))):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, col, 0, 1, 1)
            g.attach(w, col, 1, 1, 1)
        inner.pack_start(g, False, False, 0)

        exp = Gtk.Expander(label="Advanced — selectors + per-panel toggles (apply on restart)")
        adv = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        adv.set_border_width(6)
        ag = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        sel = p.selectors or {}
        user_e = Gtk.Entry(); user_e.set_text(sel.get("user", "")); user_e.set_placeholder_text("user CSS")
        pass_e = Gtk.Entry(); pass_e.set_text(sel.get("pass", "")); pass_e.set_placeholder_text("pass CSS")
        sub_e = Gtk.Entry(); sub_e.set_text(sel.get("submit", "")); sub_e.set_placeholder_text("submit CSS")
        mark_e = Gtk.Entry(); mark_e.set_text(p.login_marker or ""); mark_e.set_placeholder_text("login marker")
        for w in (user_e, pass_e, sub_e, mark_e):
            w.set_width_chars(13)
            ag.pack_start(w, True, True, 0)
        adv.pack_start(ag, False, False, 0)

        # Per-panel toggles that used to be YAML-only: a panel with self-signed
        # TLS, one that needs WebGL, or one that must bypass the global proxy.
        tg = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        ai_c = Gtk.CheckButton(label="allow self-signed TLS")
        ai_c.set_active(bool(getattr(p, "allow_insecure", False)))
        ai_c.set_tooltip_text("Accept self-signed certs on this panel only "
                              "(trusted LAN). Off by default — system CAs are "
                              "enforced.")
        am_c = Gtk.CheckButton(label="allow media (WebGL/audio/video)")
        am_c.set_active(bool(getattr(p, "allow_media", False)))
        am_c.set_tooltip_text("Re-enables WebGL/WebAudio/<video>. Off by default "
                              "to save RAM/GPU on 1 GB boards.")
        px_c = Gtk.CheckButton(label="use global proxy (if any)")
        px_c.set_active(bool(getattr(p, "proxy", True)))
        px_c.set_tooltip_text("Off = this panel ALWAYS hits the URL directly, "
                              "bypassing the corporate proxy.")
        for c in (ai_c, am_c, px_c):
            tg.pack_start(c, False, False, 0)
        adv.pack_start(tg, False, False, 0)

        # Keepalive: nudges idle dashboards so they don't log themselves out.
        kg = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        kg.pack_start(Gtk.Label(label="keepalive:"), False, False, 0)
        ka_strat = Gtk.ComboBoxText()
        strats = ["none"] + sorted(cfg.VALID_KEEPALIVE - {"none"})
        for s in strats:
            ka_strat.append_text(s)
        cur_strat = getattr(p.keepalive, "strategy", "none")
        ka_strat.set_active(strats.index(cur_strat) if cur_strat in strats else 0)
        ka_int = Gtk.SpinButton.new_with_range(1, 86400, 30)
        ka_int.set_value(int(getattr(p.keepalive, "intervalSec", 600) or 600))
        kg.pack_start(ka_strat, False, False, 0)
        kg.pack_start(Gtk.Label(label="every (sec):"), False, False, 0)
        kg.pack_start(ka_int, False, False, 0)
        adv.pack_start(kg, False, False, 0)

        # Click-zone calibration: the last-resort login fallback when the CSS
        # selectors AND the text-pattern heuristic both miss.
        cz_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        cz_lbl = Gtk.Label()
        cz_lbl.set_xalign(0.0); cz_lbl.set_line_wrap(True); cz_lbl.set_hexpand(True)
        cz_lbl.get_style_context().add_class("soc-config-sub")
        cz_lbl.set_markup(self._login_zones_status(p))
        cz_btn = Gtk.Button(label="Calibrate login zones")
        cz_btn.set_tooltip_text("Overlay a crosshair on the panel; click the "
                                "username, password and submit elements. Ratios "
                                "are stored, so a resize keeps them accurate.")
        cz_clr_btn = Gtk.Button(label="Clear zones")
        cz_clr_btn.set_tooltip_text("Drop the saved zones from this panel. The "
                                    "wall falls back to selectors + text-pattern "
                                    "heuristics.")
        cz_clr_btn.get_style_context().add_class("destructive-action")
        cz_btn.connect("clicked",
                       lambda _b, pid=p.id, lbl=cz_lbl:
                           self._on_calibrate_panel(pid, lbl))
        cz_clr_btn.connect("clicked",
                           lambda _b, pid=p.id, lbl=cz_lbl:
                               self._on_clear_login_zones(pid, lbl))
        cz_box.pack_start(cz_lbl, True, True, 0)
        cz_box.pack_start(cz_btn, False, False, 0)
        cz_box.pack_start(cz_clr_btn, False, False, 0)
        adv.pack_start(cz_box, False, False, 0)
        exp.add(adv)
        inner.pack_start(exp, False, False, 0)

        # Reorder + Remove buttons
        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        btn_row.set_halign(Gtk.Align.END)
        up_btn = Gtk.Button(label="↑ Up")
        up_btn.connect("clicked", lambda *_, panel=p: self._move_panel(panel, -1))
        dn_btn = Gtk.Button(label="↓ Down")
        dn_btn.connect("clicked", lambda *_, panel=p: self._move_panel(panel, 1))
        rm_btn = Gtk.Button(label="✕ Remove")
        rm_btn.get_style_context().add_class("destructive-action")
        rm_btn.connect("clicked", lambda *_, panel=p: self._remove_panel(panel))
        for b in (up_btn, dn_btn, rm_btn):
            btn_row.pack_start(b, False, False, 0)
        inner.pack_start(btn_row, False, False, 0)

        frame.add(inner)
        self._rows[p.id] = {"url": url_e, "title": title_e, "vault": vault_e,
                            "engine": engine_c, "tenant": tenant_e,
                            "user": user_e, "pass": pass_e,
                            "submit": sub_e, "marker": mark_e,
                            "allow_insecure": ai_c, "allow_media": am_c,
                            "proxy": px_c, "ka_strat": ka_strat,
                            "ka_int": ka_int, "zones_lbl": cz_lbl, "frame": frame}
        return frame

    def _login_zones_status(self, p) -> str:
        """Markup for the per-panel status label: names the captured zones, so the
        operator sees calibration state without expanding the panel."""
        return _zones_markup(getattr(p, "login_zones", None))

    def _on_calibrate_panel(self, panel_id: str, status_lbl):
        """Per-panel Calibrate button -> host.calibrate_panel(). The host persists
        the zones; this reflects them when the operator finishes."""
        action = self._actions.get("calibrate_panel")
        if action is None:
            self._alert("Calibrate is unavailable in this session: the wall "
                        "was not launched with a calibrate-capable host.",
                        error=True, title="Calibrate unavailable")
            return
        p = next((pp for pp in self.panels if pp.id == panel_id), None)

        def _on_done(zones):
            # A Chromium panel reports from its CDP reader thread.
            GLib.idle_add(self._calibrate_done, panel_id, p, zones, status_lbl)
        self._toast(f"{panel_id}: click USER → PASS → SUBMIT on the panel "
                    "(Esc cancels)")
        try:
            action(panel_id, _on_done)
        except Exception as e:                            # noqa: BLE001
            self._alert(f"Calibrate failed to start for '{panel_id}':\n\n{e}",
                        error=True, title="Calibrate failed")

    def _calibrate_done(self, panel_id, p, zones, status_lbl):
        if self._closed:
            return False
        if zones is None:
            self._toast(f"{panel_id}: calibration cancelled / timed out")
            return False
        if p is not None:
            p.login_zones = dict(zones)
        status_lbl.set_markup(_zones_markup(zones))
        self._toast(f"{panel_id}: calibrated ✓ ({len(zones)} zones)")
        return False

    def _on_clear_login_zones(self, panel_id: str, status_lbl):
        """Clear the panel's zones. Gated by re-auth — same policy as Remove VPN.
        Written as an explicit empty override rather than by deleting the key:
        zones that came from the source config would otherwise return at boot."""
        if not self._require_reauth(f"clearing login zones on '{panel_id}'"):
            return
        p = next((pp for pp in self.panels if pp.id == panel_id), None)
        ov = load_overrides()
        per = ov.get(panel_id) if isinstance(ov.get(panel_id), dict) else {}
        had = bool(per.get("login_zones") or getattr(p, "login_zones", None))
        per["login_zones"] = {}
        ov[panel_id] = per
        try:
            save_overrides(ov)
        except (OSError, ValueError, TypeError) as e:
            self._alert(f"Could not save settings: {e}\n\nCheck that {state_dir()} "
                        "is writable (disk space / permissions).",
                        error=True, title="Save failed")
            return
        if p is not None:
            p.login_zones = {}
        status_lbl.set_markup(_zones_markup(None))
        self._toast(f"{panel_id}: login zones cleared"
                    if had else f"{panel_id}: no zones to clear")

    def _tab_credentials(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_border_width(12)
        note = Gtk.Label(label="Top: the vault items the wall touches (names only). "
                               "Edit reveals a stored login and needs your OS "
                               "password; Delete needs the Settings PIN/TOTP. "
                               "Bottom: store a login's username + password directly "
                               "in Vaultwarden, so the wall reads them automatically. "
                               "Skip a row to leave it for the web vault.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        # Inventory, with its buttons at the top of the frame so they stay
        # reachable however long the list grows.
        inv_frame = Gtk.Frame(label="  Vault items in use  ")
        inv_outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inv_outer.set_border_width(8)
        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        refresh_btn = Gtk.Button(label="Refresh from vault")
        refresh_btn.set_tooltip_text("Re-scan the config + the wall's auth folder "
                                     "for items.")
        refresh_btn.connect("clicked", lambda *_: self._refresh_cred_inventory())
        sync_btn = Gtk.Button(label="Sync vault")
        sync_btn.set_tooltip_text("Fetch the latest from Vaultwarden. Use when an "
                                  "item you added in the web vault doesn't show up.")
        sync_btn.connect("clicked", lambda *_: self._sync_vault_now())
        action_row.pack_start(refresh_btn, False, False, 0)
        action_row.pack_start(sync_btn, False, False, 0)
        inv_outer.pack_start(action_row, False, False, 0)
        list_scroll = Gtk.ScrolledWindow()
        list_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        list_scroll.set_min_content_height(120)
        list_scroll.set_max_content_height(240)
        self._inv_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        list_scroll.add(self._inv_list)
        inv_outer.pack_start(list_scroll, True, True, 0)
        inv_frame.add(inv_outer)
        box.pack_start(inv_frame, False, False, 0)

        grid = Gtk.Grid()
        grid.set_column_spacing(8)
        grid.set_row_spacing(8)
        for col, t in enumerate(("vault item", "username", "password", "")):
            h = Gtk.Label(label=t)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            grid.attach(h, col, 0, 1, 1)
        seen = set()
        self._cred_r = 1

        def add_line(widget):
            widget.set_xalign(0.0)
            grid.attach(widget, 0, self._cred_r, 4, 1)
            self._cred_r += 1

        def add_section(title):
            lbl = Gtk.Label(label=title)
            lbl.get_style_context().add_class("soc-config-tag")
            lbl.set_margin_top(6)
            add_line(lbl)

        def add_row(name, uri):
            name = (name or "").strip()
            if not name or name in seen:
                return
            seen.add(name)
            r = self._cred_r
            nm = Gtk.Label(label=name)
            nm.get_style_context().add_class("soc-config-tag")
            nm.set_xalign(0.0)
            u = Gtk.Entry(); u.set_width_chars(15); u.set_placeholder_text("username")
            pw = Gtk.Entry(); pw.set_visibility(False); pw.set_width_chars(15)
            pw.set_placeholder_text("password")
            btn = Gtk.Button(label="Save to vault")
            btn.connect("clicked", (lambda b, n=name, ue=u, pe=pw, ur=uri:
                                    self._save_cred(n, ue, pe, ur)))
            grid.attach(nm, 0, r, 1, 1)
            grid.attach(u, 1, r, 1, 1)
            grid.attach(pw, 2, r, 1, 1)
            grid.attach(btn, 3, r, 1, 1)
            self._cred_r += 1

        add_section("Panel logins")
        with_item = [p for p in self.panels if p.vault_item]
        for p in with_item:
            add_row(p.vault_item, p.effective_url)
        if not with_item:
            add_line(Gtk.Label(label="No panel vault logins configured. "
                                     "Set a 'vault login' on a panel first."))
        add_section("VPN logins")
        vpn_items = [v.get("vault_item") for v in self._vpns
                     if v and v.get("vault_item")]
        for name in vpn_items:
            add_row(name, "")
        if not vpn_items:
            add_line(Gtk.Label(label="No VPN vault login. Set one in the VPN tab."))
        add_section("Proxy login")
        if self._proxy_vault_item:
            add_row(self._proxy_vault_item, "")
        else:
            add_line(Gtk.Label(label="No proxy vault login configured."))
        box.pack_start(grid, False, False, 0)

        # Only ask for the master at the glass when it isn't sealed on this host;
        # a sealed wall unseals it itself (no plaintext SOC_VAULT_PASSWORD).
        from . import secretstore
        if not secretstore.is_sealed(os.environ.get("SOC_SECRET_DIR")):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            lbl = Gtk.Label(label="vault master password:")
            lbl.get_style_context().add_class("soc-config-sub")
            self._cred_master = Gtk.Entry()
            self._cred_master.set_visibility(False)
            self._cred_master.set_hexpand(True)
            row.pack_start(lbl, False, False, 0)
            row.pack_start(self._cred_master, True, True, 0)
            box.pack_start(row, False, False, 0)
        self._cred_msg = Gtk.Label(label="")
        self._cred_msg.get_style_context().add_class("soc-config-ok")
        self._cred_msg.set_xalign(0.0)
        self._cred_msg.set_line_wrap(True)
        box.pack_start(self._cred_msg, False, False, 0)
        self._refresh_cred_inventory()
        # Scroll the whole tab so a long Save grid never pushes widgets off the
        # bottom.
        outer = Gtk.ScrolledWindow()
        outer.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.add(box)
        return outer

    def _sync_vault_now(self):
        """Force the vault to fetch the latest, then refresh the inventory."""
        v = self._vault
        if v is None:
            self._alert("No vault handle is attached to this Settings window.",
                        error=True, title="Vault unavailable")
            return
        self._toast("syncing vault …")
        self._in_worker(lambda: _vault_sync(v), self._sync_done)

    def _sync_done(self, _res, err):
        if err is None:
            self._toast("vault synced ✓")
        else:
            self._alert(f"Vault sync failed:\n\n{err}\n\nCommon causes: Vaultwarden "
                        "unreachable (check `systemctl status vaultwarden`) or the "
                        "vault is locked.",
                        error=True, title="Vault sync failed")
        self._refresh_cred_inventory()

    def _collect_inventory(self) -> list:
        """Every vault item name the wall touches, deduped, each {name, origin}.
        Lists the auth folder via the vault when one is attached, so this BLOCKS on
        it: call it from a worker (_refresh_cred_inventory does)."""
        folder_items = []
        v_handle = getattr(self, "_vault", None)
        if v_handle is not None and hasattr(v_handle, "list_by_folder"):
            try:
                folder_items = v_handle.list_by_folder(_totp._VAULT_TOTP_FOLDER)
            except Exception:                    # noqa: BLE001
                folder_items = []
        return _inventory_items(self.panels, self._vpns, self._proxy_vault_item,
                                self._tunnel, folder_items)

    def _refresh_cred_inventory(self):
        """Rebuild the inventory rows: at once from the config, then again when
        the vault's folder listing arrives. A hung vault just never adds its
        rows."""
        if self._inv_list is None:
            return
        self._render_inventory(_inventory_items(
            self.panels, self._vpns, self._proxy_vault_item, self._tunnel))
        if self._vault is None or self._inv_busy:
            return
        self._inv_busy = True

        def done(items, err):
            self._inv_busy = False
            if err is None:
                self._render_inventory(items)
        self._in_worker(self._collect_inventory, done)

    def _render_inventory(self, items):
        for child in list(self._inv_list.get_children()):
            self._inv_list.remove(child)
        if not items:
            empty = Gtk.Label(label="(no vault items pinned yet — give a "
                                    "panel/VPN/proxy a vault item first)")
            empty.set_xalign(0.0)
            empty.get_style_context().add_class("soc-config-sub")
            self._inv_list.pack_start(empty, False, False, 0)
        for it in items:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            name = Gtk.Label(label=it["name"])
            name.set_xalign(0.0)
            name.get_style_context().add_class("soc-config-tag")
            origin = Gtk.Label(label=f"({it['origin']})")
            origin.set_xalign(0.0)
            origin.get_style_context().add_class("soc-config-sub")
            # Edit reveals the stored secret, so it asks for the OS password: a
            # higher bar than the wall PIN that Delete takes.
            edit = Gtk.Button(label="Edit")
            edit.set_tooltip_text("Reveal + change the username/password for this "
                                  "vault item. Requires your OS login password "
                                  "(NOT the wall PIN).")
            edit.connect("clicked",
                         lambda _b, n=it["name"]: self._on_cred_edit(n))
            delete = Gtk.Button(label="Delete")
            delete.get_style_context().add_class("destructive-action")
            delete.set_tooltip_text("Permanent. PIN/TOTP required.")
            delete.connect("clicked",
                           lambda _b, n=it["name"]: self._on_cred_delete(n))
            row.pack_start(name, True, True, 0)
            row.pack_start(origin, False, False, 0)
            row.pack_start(edit, False, False, 0)
            row.pack_start(delete, False, False, 0)
            self._inv_list.pack_start(row, False, False, 0)
        self._inv_list.show_all()

    def _prompt_os_password(self, what: str) -> "tuple[bool, str]":
        """Modal that asks for the operator's OS login password and verifies it
        via host.ospass (on a worker: PAM can take seconds). Returns (ok, user).

        The username is pre-filled by auto-detection and editable, for a multi-user
        box or a sudo chain that confused the detection. SOC_OPERATOR_USER pins it:
        an explicit operator setting is not for the glass to override.

        The password stays in this scope: never returned, logged or stored."""
        from . import ospass as _osp
        wait = _os_throttle.remaining()
        if wait:
            self._alert(f"Wait {wait} s before trying again.",
                        title="Too many wrong attempts")
            return False, ""
        auto_user = _osp.operator_user()
        pinned = os.environ.get("SOC_OPERATOR_USER", "").strip() == auto_user
        d = Gtk.Dialog(transient_for=self, modal=True,
                       title=f"OS password required — {what}")
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                      "Verify", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        d.set_default_size(440, 0)
        box = d.get_content_area()
        box.set_spacing(8)
        box.set_margin_start(14); box.set_margin_end(14)
        box.set_margin_top(10); box.set_margin_bottom(10)
        hint = Gtk.Label()
        hint.set_xalign(0.0); hint.set_line_wrap(True)
        hint.set_markup("This action reveals + changes a stored credential. Enter "
                        "your OS login username + password to continue.  Wall "
                        "PIN/TOTP is <i>not</i> sufficient for reveal operations.")
        u_lbl = Gtk.Label(label="username")
        u_lbl.set_xalign(0.0)
        u_lbl.get_style_context().add_class("soc-config-sub")
        u_entry = Gtk.Entry()
        u_entry.set_text(auto_user)
        u_entry.set_sensitive(not pinned)
        p_lbl = Gtk.Label(label="password")
        p_lbl.set_xalign(0.0)
        p_lbl.get_style_context().add_class("soc-config-sub")
        p_entry = Gtk.Entry()
        p_entry.set_visibility(False)
        p_entry.set_activates_default(True)
        p_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        box.pack_start(hint, False, False, 0)
        for w in (u_lbl, u_entry, p_lbl, p_entry):
            box.pack_start(w, False, False, 0)
        d.show_all()
        p_entry.grab_focus()
        rc = _run_modal(d)
        user = (u_entry.get_text() or "").strip() or auto_user
        pw = p_entry.get_text()
        d.destroy()
        if rc != Gtk.ResponseType.OK:
            return False, user
        status, ok = self._wait_for(lambda: _osp.verify_os_password(user, pw),
                                    "Checking the OS password …")
        pw = ""
        if status == "cancelled":
            return False, user
        if status == "ok" and ok:
            _os_throttle.passed()
            return True, user
        _os_throttle.failed()
        self._alert(
            f"OS password rejected for user '{user}'.\n\n"
            "Common causes:\n"
            "  • Wrong username — override the detected one in the field if your "
            "desktop user is different, or set SOC_OPERATOR_USER in soc.env.\n"
            "  • Wrong password — the wall checks your LOCAL OS login password, "
            "NOT the wall PIN, vault master, or anything in Vaultwarden.\n"
            "  • The account has no password: such an account cannot vouch for "
            "anything. Set one with: sudo passwd <user>",
            error=True, title="OS password rejected")
        return False, user

    def _on_cred_edit(self, name: str):
        """Edit flow: OS password -> fetch via the vault -> modal with user + pass
        entries -> vaultseed.upsert_login. The current password is the only
        operator-side disclosure path for stored secrets, so it is gated by the
        same authentication root would need."""
        ok, _user = self._prompt_os_password(f"edit '{name}'")
        if not ok:
            return
        v_handle = self._vault
        if v_handle is None or not hasattr(v_handle, "creds"):
            self._alert(f"Cannot edit '{name}': no vault handle is attached to "
                        "this Settings window.",
                        error=True, title="Vault unavailable")
            return
        creds = self._fetch_creds_with_recovery(v_handle, name)
        if creds is _CANCELLED:
            return
        if creds is _NOT_FOUND:
            # The normal first-time path (a VPN whose creds were never saved), not
            # an error: Save below creates the item, and the OS password is
            # already enough auth for that.
            self._alert("This vault item doesn't exist yet. The next dialog lets "
                        "you fill in the username + password; Save will CREATE the "
                        "item in Vaultwarden.",
                        title=f"Create vault item '{name}'?")
            creds = {}
        d = Gtk.Dialog(transient_for=self, modal=True,
                       title=f"Edit vault item — {name}")
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                      "Save to vault", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        d.set_default_size(440, 0)
        body = d.get_content_area()
        body.set_spacing(6); body.set_margin_start(14); body.set_margin_end(14)
        body.set_margin_top(10); body.set_margin_bottom(10)
        u_e = Gtk.Entry()
        u_e.set_text(creds.get("user", "") or "")
        u_e.set_placeholder_text("username")
        u_e.set_activates_default(True)
        p_e = Gtk.Entry()
        p_e.set_text(creds.get("pass", "") or "")
        p_e.set_visibility(False)
        p_e.set_placeholder_text("password")
        p_e.set_activates_default(True)
        creds = None
        show_pass = Gtk.CheckButton(label="show password")
        show_pass.connect("toggled", lambda b: p_e.set_visibility(b.get_active()))
        for label, w in (("username", u_e), ("password", p_e)):
            lbl = Gtk.Label(label=label)
            lbl.set_xalign(0.0)
            lbl.get_style_context().add_class("soc-config-sub")
            body.pack_start(lbl, False, False, 0)
            body.pack_start(w, False, False, 0)
        body.pack_start(show_pass, False, False, 0)
        d.show_all()
        p_e.grab_focus()
        rc = _run_modal(d)
        new_user = u_e.get_text().strip()
        new_pass = p_e.get_text()
        d.destroy()
        if rc != Gtk.ResponseType.OK:
            return
        if not new_user and not new_pass:
            self._alert("Both username AND password are empty — nothing to save.",
                        title="Nothing to save")
            return
        self._do_vault_upsert(name, new_user, new_pass)

    def _do_vault_upsert(self, name: str, user: str, password: str):
        """Write the Edit modal's result, off the main thread."""
        def done(msg):
            v = self._vault
            if "✓" in msg and v is not None and hasattr(v, "invalidate"):
                v.invalidate(name)              # or the TTL cache serves the old one
            self._post_edit_done(msg)
        self._write_login(name, user, password, None, done)

    def _post_edit_done(self, msg: str):
        self._toast(msg)
        ok = "✓" in msg
        self._alert(msg, error=not ok,
                    title="Vault edit succeeded" if ok else "Vault edit failed")
        self._refresh_cred_inventory()

    def _on_cred_delete(self, name: str):
        """Delete a vault item from the inventory list. Two-step: re-auth, then
        confirm, then vault.delete (on a worker) + refresh."""
        if not self._require_reauth(f"delete of vault item '{name}'"):
            return
        if not self._ask(f"Delete vault item '{name}'?",
                         "This is permanent. Any panel / VPN / proxy referencing "
                         "this item will fail to auto-login until the item is "
                         "recreated or the field is re-pointed at a different "
                         "vault item."):
            return
        v_handle = self._vault
        if v_handle is None or not hasattr(v_handle, "delete"):
            self._alert(f"Cannot delete '{name}': no vault handle is attached to "
                        "this Settings window.",
                        error=True, title="Vault unavailable")
            return
        self._toast(f"deleting '{name}' …")
        self._in_worker(lambda: v_handle.delete(name),
                        lambda ok, err: self._cred_deleted(name, ok, err))

    def _cred_deleted(self, name, ok, err):
        if ok and err is None:
            self._toast(f"deleted '{name}' ✓")
            self._refresh_cred_inventory()
            return
        self._alert(f"Delete failed for '{name}'.\n\n"
                    f"{err or 'The vault reported a failure.'}\n\nCheck `journalctl "
                    "-u soc-wall -n 30` for details. The item may already be gone "
                    "(Refresh would then remove the row from the list).",
                    error=True, title="Delete failed")

    def _write_login(self, name, user, secret, uri, done):
        """Upsert a login in Vaultwarden on a worker, then done(msg) on the main
        thread; msg holds ✓ on success. The at-the-glass master is read here (GTK
        must stay on the main thread); the host-bound unseal, a ~100-300 ms scrypt
        on the 1 GB Pi, stays in the worker so it can't freeze the wall."""
        url = os.environ.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        email = os.environ.get("SOC_VAULT_EMAIL", "")
        sd = os.environ.get("SOC_SECRET_DIR")
        typed_master = self._cred_master.get_text() if self._cred_master else ""

        def work():
            master = ""
            try:
                # Prefer the host-bound sealed master; fall back to the at-the-glass
                # entry only when the wall isn't sealed. Never read a plaintext
                # SOC_VAULT_PASSWORD.
                from . import secretstore, vaultseed
                try:
                    master = secretstore.unseal(sd) if secretstore.is_sealed(sd) else ""
                except Exception:  # noqa: BLE001 — fall back to the manual entry
                    master = ""
                if not master:
                    master = typed_master
                if not (email and master):
                    return ("need the vault email + master password to write: set "
                            "SOC_VAULT_EMAIL via setup, and seal the master (setup "
                            "first-run) or type it on the Credentials tab")
                if not vaultseed.available():
                    return "'cryptography' not installed — add the login in the web vault"
                action = vaultseed.upsert_login(url, email, master, name, user,
                                                secret, uri=uri or None)
                return f"{action} '{name}' in Vaultwarden ✓"
            except Exception as e:  # noqa: BLE001
                # Raw cause + a remedy: the usual failures are a wrong master,
                # a down/unreachable Vaultwarden, or a rejected login payload.
                return (f"{name}: {e} — check the vault master is correct and "
                        f"Vaultwarden is reachable at {url}, then retry")
            finally:
                master = ""
        self._in_worker(work, lambda msg, _err: done(msg))

    def _save_cred(self, name, user_e, pass_e, uri):
        user = user_e.get_text().strip()
        secret = pass_e.get_text()
        if not user:
            self._cred_msg.set_text(f"{name}: enter a username first")
            return
        if _reauth_required() and not self._require_reauth(
                f"saving the login for '{name}'"):
            return
        self._cred_msg.set_text(f"writing '{name}' …")
        self._write_login(name, user, secret, uri,
                          lambda msg: self._cred_done(msg, pass_e))

    def _cred_done(self, msg, pass_e):
        self._cred_msg.set_text(msg)
        if "✓" in msg:
            pass_e.set_text("")
        else:
            self._alert(msg, error=True, title="Vault save failed")
        return False

    def _tab_display(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="Layout, spacing, grid size and resolution. Gap "
                               "applies live; layout, grid size and resolution take "
                               "effect on the next restart.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)
        g = Gtk.Grid()
        g.set_column_spacing(10)
        g.set_row_spacing(10)
        self._layout_c = Gtk.ComboBoxText()
        opts = ["auto", "windows", "single"]
        for o in opts:
            self._layout_c.append_text(o)
        cur = getattr(self.display, "layout", "auto")
        self._layout_c.set_active(opts.index(cur) if cur in opts else 0)
        self._gap_s = Gtk.SpinButton.new_with_range(0, 64, 1)
        self._gap_s.set_value(getattr(self.display, "gap", 0))
        self._cols_s = Gtk.SpinButton.new_with_range(1, 8, 1)
        self._cols_s.set_value(int(getattr(self.display, "cols", 2)))
        self._rows_s = Gtk.SpinButton.new_with_range(1, 8, 1)
        self._rows_s.set_value(int(getattr(self.display, "rows", 2)))
        self._disp_auto = Gtk.CheckButton(label="auto-detect from the screen")
        self._disp_auto.set_active(bool(getattr(self.display, "auto", True)))
        self._w_s = Gtk.SpinButton.new_with_range(320, 16384, 16)
        self._w_s.set_value(int(getattr(self.display, "width", 1920)))
        self._h_s = Gtk.SpinButton.new_with_range(320, 16384, 16)
        self._h_s.set_value(int(getattr(self.display, "height", 1080)))
        # width/height are only read when auto is off, so the UI follows suit
        self._w_s.set_sensitive(not self._disp_auto.get_active())
        self._h_s.set_sensitive(not self._disp_auto.get_active())
        self._disp_auto.connect("toggled", lambda b: (
            self._w_s.set_sensitive(not b.get_active()),
            self._h_s.set_sensitive(not b.get_active())))
        self._fullscreen_c = Gtk.CheckButton(
            label="fullscreen on start  (off = open as a windowed desktop app)")
        self._fullscreen_c.set_active(bool(getattr(self.display, "fullscreen", True)))
        rows = [("layout", self._layout_c), ("gap (px)", self._gap_s),
                ("cols", self._cols_s), ("rows", self._rows_s),
                ("resolution", self._disp_auto),
                ("width", self._w_s), ("height", self._h_s),
                ("window", self._fullscreen_c)]
        for r, (lbl, w) in enumerate(rows):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(w, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)
        return box

    def _tab_proxy(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="Outbound HTTP(S)/SOCKS proxy for the panel browsers. "
                               "Credentials live in the vault (set username + "
                               "password on the Credentials tab for this proxy's "
                               "vault item). Changes apply on the next restart.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        p = self._proxy
        w = {}
        w["enabled"] = Gtk.CheckButton(label="Proxy enabled")
        w["enabled"].set_active(bool(getattr(p, "enabled", False)))
        box.pack_start(w["enabled"], False, False, 0)

        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(6)

        def entry(val, hint, purpose=None):
            e = Gtk.Entry()
            e.set_text(str(val or ""))
            e.set_hexpand(True)
            e.set_placeholder_text(hint)
            if purpose is not None:
                e.set_input_purpose(purpose)
            return e

        w["url"] = entry(getattr(p, "url", ""),
                         "http://host:port  (no embedded user:pass)",
                         Gtk.InputPurpose.URL)
        w["vault_item"] = entry(getattr(p, "vault_item", ""),
                                "vault login holding the proxy creds (optional)")
        ignore = ", ".join(getattr(p, "ignore_hosts", ()) or ())
        w["ignore_hosts"] = entry(ignore,
                                  "host1, host2  (loopback is always bypassed)")
        rows = [("url", w["url"]), ("vault login", w["vault_item"]),
                ("ignore hosts", w["ignore_hosts"])]
        for r, (lbl, widget) in enumerate(rows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(widget, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)
        self._proxy_w = w
        self._proxy_base = self._proxy_form()
        return box

    def _tab_tunnel(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="SSH jump host used by panels in 'tunnel' mode. The "
                               "SSH key sits in the host's filesystem (the jump "
                               "host trusts its public half). Apply pushes the "
                               "change and restarts autossh-tunnel.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        t = self._tunnel or {}
        w = {}
        w["enabled"] = Gtk.CheckButton(label="Tunnel enabled")
        w["enabled"].set_active(bool(t.get("enabled", True)))
        box.pack_start(w["enabled"], False, False, 0)

        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(6)

        def entry(val, hint):
            e = Gtk.Entry()
            e.set_text(str(val or ""))
            e.set_hexpand(True)
            e.set_placeholder_text(hint)
            return e

        w["jump_host"] = entry(t.get("jump_host"), "user@host  (the SSH jump box)")
        w["identity"] = entry(t.get("identity"), "private key path on the wall")
        w["known_hosts"] = entry(t.get("known_hosts"),
                                 "known_hosts file pinning the jump box's key")
        w["host_key_checking"] = Gtk.ComboBoxText()
        hkc_opts = list(cfg.VALID_HOST_KEY_CHECKING)
        for o in hkc_opts:
            w["host_key_checking"].append_text(o)
        w["host_key_checking"].set_active(hkc_opts.index(cfg.host_key_checking(t)))
        rows = [("jump host", w["jump_host"]),
                ("identity (key)", w["identity"]),
                ("known_hosts", w["known_hosts"]),
                ("host key check", w["host_key_checking"])]
        for r, (lbl, widget) in enumerate(rows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(widget, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)

        ef_lbl = Gtk.Label(label="extra forwards  (one per line, "
                                 "bindaddr:port:host:port)")
        ef_lbl.get_style_context().add_class("soc-config-sub")
        ef_lbl.set_xalign(0.0)
        box.pack_start(ef_lbl, False, False, 0)
        self._tunnel_ef = Gtk.TextView()
        self._tunnel_ef.set_monospace(True)
        self._tunnel_ef.set_wrap_mode(Gtk.WrapMode.NONE)
        self._tunnel_ef.get_buffer().set_text(
            "\n".join(t.get("extra_forwards") or []))
        sw = Gtk.ScrolledWindow()
        sw.set_min_content_height(70)
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.add(self._tunnel_ef)
        box.pack_start(sw, False, False, 0)

        self._tunnel_w = w
        self._tunnel_base = self._tunnel_form()
        return box

    def _tab_vpn(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(12)
        note = Gtk.Label(label="Supervised VPNs. Credentials live in the vault: "
                               "save them here, or on the Credentials tab for each "
                               "VPN's vault item. Apply pushes the config into the "
                               "vault and restarts the VPN service(s).")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        outer.pack_start(note, False, False, 0)

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        add_btn = Gtk.Button(label="+ Add VPN")
        add_btn.set_tooltip_text("Add a new VPN section. It starts disabled: fill "
                                 "in the name, gateway and vault item, then enable "
                                 "it.")
        add_btn.connect("clicked", self._on_add_vpn)
        header.pack_end(add_btn, False, False, 0)
        outer.pack_start(header, False, False, 0)

        self._vpn_ws = []
        self._vpn_base = []
        self._vpn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.pack_start(self._vpn_box, False, False, 0)
        for idx, v in enumerate(self._vpns):
            exp = self._vpn_section(v, idx)
            self._vpn_box.pack_start(exp, False, False, 0)
            exp.set_expanded(idx == 0)   # the rest would sprawl on small displays
        scroll.add(outer)
        return scroll

    def _on_add_vpn(self, _btn):
        """+ Add VPN — append a blank entry, build its expander, show it."""
        live = [v for v in self._vpns if v]
        if len(live) >= cfg.MAX_VPNS:
            self._msg(f"At most {cfg.MAX_VPNS} VPNs are supported.", error=True)
            return
        used = {v.get("name") for v in live}
        n = len(self._vpns) + 1
        while f"vpn-{n}" in used:
            n += 1
        v = {"name": f"vpn-{n}", "enabled": False, "type": "fortinet"}
        idx = len(self._vpns)
        self._vpns.append(v)
        exp = self._vpn_section(v, idx, is_new=True)
        self._vpn_box.pack_start(exp, False, False, 0)
        exp.set_expanded(True)
        exp.show_all()

    def _on_remove_vpn(self, idx: int, expander):
        """Remove this VPN — re-auth, then dialog confirm, then drop it from _vpns
        + the UI (next Apply drops it from the config). The vault credential item
        is intentionally NOT deleted: the Credentials tab does that, with its own
        re-auth."""
        v = self._vpns[idx] if 0 <= idx < len(self._vpns) else None
        name = (v or {}).get("name") or f"vpn-{idx + 1}"
        if not self._require_reauth(f"removal of VPN '{name}'"):
            return
        if not self._ask(f"Remove VPN '{name}'?",
                         f"VPN '{name}' will be removed from the config on the "
                         "next Apply. The vault credential item is NOT deleted by "
                         "this action — use the Credentials tab for that."):
            return
        # Stop its supervisor now, or it keeps auto-reconnecting against a config
        # that no longer exists.
        stop_action = self._actions.get("stop_vpn_unit")
        if stop_action is not None:
            def stopped(_res, err):
                if err is not None:
                    self._alert(f"Could not stop the supervisor for VPN '{name}':"
                                f"\n\n{err}\n\nIt is still running; stop it by "
                                "hand.", error=True,
                                title="VPN supervisor still running")
            self._in_worker(lambda: stop_action(name), stopped)
        # Keep the slot, marked dead: lighter than re-indexing every expander's
        # closure, and _apply + the inventory skip it.
        self._vpns[idx] = None
        self._vpn_ws[idx] = None
        self._vpn_base[idx] = None
        self._vpn_dirty = True
        if expander is not None:
            expander.destroy()

    def _save_vpn_creds(self, idx: int, user: str, password: str, vault_item_entry):
        """Save inline VPN user/password to the vault item named by the section's
        `vault_item` entry, defaulting that to 'SOC VPN <name>' so saving Just
        Works for first-time setup."""
        if not user and not password:
            self._alert("Set a username AND a password before saving inline VPN "
                        "credentials.", error=True, title="Nothing to save")
            return
        if _reauth_required() and not self._require_reauth("saving VPN credentials"):
            return
        if not vault_item_entry.get_text().strip():
            v = self._vpns[idx] if 0 <= idx < len(self._vpns) else None
            vname = (v or {}).get("name") or f"vpn-{idx + 1}"
            vault_item_entry.set_text(f"SOC VPN {vname}")
        self._write_login(vault_item_entry.get_text().strip(), user, password,
                          None, self._vpn_creds_done)

    def _vpn_creds_done(self, msg):
        if "✓" in msg:
            self._alert(f"{msg}\n\nThe wall will pick up the new credential on the "
                        "next login attempt.", title="Vault save succeeded")
        else:
            self._alert(msg, error=True, title="Vault save failed")

    def _toast(self, msg: str):
        """Lightweight non-modal message. NOT for anything an operator MUST see:
        use _alert for auth failures, vault errors and the like."""
        for lbl in (self._form_msg, self._cred_msg):
            if lbl is not None:
                lbl.set_text(msg)

    def _fetch_creds_with_recovery(self, v_handle, name):
        """Read vault.creds(name) on a worker; on a transport error, offer 'Sync +
        retry' inside the dialog (the inventory's Refresh button sits behind the
        modal, unreachable). Returns a dict, _NOT_FOUND when the vault definitively
        has no such item (the caller turns that into a Create flow), or _CANCELLED."""
        attempts = 0
        while True:
            attempts += 1
            status, res = self._wait_for(lambda: v_handle.creds(name) or {},
                                         f"Reading '{name}' from the vault …")
            if status == "ok":
                return res
            if status == "cancelled":
                return _CANCELLED
            if status == "timeout":
                self._alert(f"The vault did not answer for '{name}' within "
                            f"{VAULT_WAIT_SEC} s.\n\nCheck `systemctl status "
                            "vaultwarden`, then retry Edit.",
                            error=True, title="Vault not responding")
                return _CANCELLED
            err_text = str(res).lower()
            if ("no entry found" in err_text or "not found" in err_text
                    or "no vault item" in err_text or "no password" in err_text):
                return _NOT_FOUND
            # A permanently-down vault must not loop here forever.
            if attempts >= 3:
                self._alert(f"Vault read still failing for '{name}' after sync "
                            f"retry:\n\n{res}\n\nCheck `systemctl status "
                            "vaultwarden`, then retry Edit.",
                            error=True, title="Vault read keeps failing")
                return _CANCELLED
            d = Gtk.MessageDialog(transient_for=self, modal=True,
                                  message_type=Gtk.MessageType.WARNING,
                                  text=f"Vault read failed for '{name}'")
            d.format_secondary_text(
                f"{res}\n\nThis usually means the vault cache is stale (the item "
                "was added, renamed or deleted in the web vault). 'Sync + retry' "
                "refreshes it and tries again.")
            d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                          "Sync + retry", Gtk.ResponseType.OK)
            d.set_default_response(Gtk.ResponseType.OK)
            rc = _run_modal(d)
            d.destroy()
            if rc != Gtk.ResponseType.OK:
                return _CANCELLED
            status, _ = self._wait_for(lambda: _vault_sync(v_handle), "Syncing the vault …")
            if status == "cancelled":
                return _CANCELLED
            # Sync failed? Say so through the retry below, which reads again.

    def _ask(self, text: str, detail: str) -> bool:
        d = Gtk.MessageDialog(transient_for=self, modal=True,
                              message_type=Gtk.MessageType.QUESTION,
                              buttons=Gtk.ButtonsType.OK_CANCEL, text=text)
        d.format_secondary_text(detail)
        rc = _run_modal(d)
        d.destroy()
        return rc == Gtk.ResponseType.OK

    def _alert(self, msg: str, *, error: bool = False, title: "str | None" = None):
        """Modal MessageDialog, for things the operator MUST see. Blocks the flow
        (not the wall) until acknowledged, so the next destructive step can never
        race ahead of an error the user hasn't seen."""
        d = Gtk.MessageDialog(transient_for=self, modal=True,
                              message_type=(Gtk.MessageType.ERROR if error
                                            else Gtk.MessageType.INFO),
                              buttons=Gtk.ButtonsType.OK,
                              text=title or ("Error" if error else "Notice"))
        d.format_secondary_text(msg)
        _run_modal(d)
        d.destroy()

    def _prompt_code(self, what: str):
        """Modal PIN/TOTP prompt. Returns the typed code, or None on Cancel."""
        d = Gtk.Dialog(transient_for=self, modal=True,
                       title=f"Confirm {what} — enter PIN or TOTP")
        d.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                      "Confirm", Gtk.ResponseType.OK)
        d.set_default_response(Gtk.ResponseType.OK)
        box = d.get_content_area()
        lbl = Gtk.Label(label=f"Enter PIN or TOTP code to confirm {what}.")
        lbl.set_xalign(0.0); lbl.set_margin_top(6); lbl.set_margin_start(12)
        lbl.set_margin_end(12)
        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_activates_default(True)
        entry.set_margin_top(6); entry.set_margin_start(12)
        entry.set_margin_end(12); entry.set_margin_bottom(6)
        box.pack_start(lbl, False, False, 0)
        box.pack_start(entry, False, False, 0)
        d.show_all()
        rc = _run_modal(d)
        code = entry.get_text()
        d.destroy()
        return code if rc == Gtk.ResponseType.OK else None

    def _require_reauth(self, what: str = "this action") -> bool:
        """Modal PIN/TOTP prompt before a destructive action. True only after the
        operator types a code matching the Settings PIN OR TOTP. Fail-closed when
        nothing is enrolled: callers that should still work on an un-enrolled wall
        check _reauth_required() first. Wrong codes share the PIN page's back-off."""
        if not _reauth_required():
            self._alert("Destructive actions need a credential. Enrol a PIN or "
                        f"TOTP on the Security tab first, then retry {what}.",
                        title="No PIN or TOTP enrolled")
            return False
        wait = _gate_throttle.remaining()
        if wait:
            self._alert(f"Wait {wait} s before trying again.",
                        title="Too many wrong attempts")
            return False
        code = self._prompt_code(what)
        if code is None:
            return False
        if _reauth_verify(code):
            _gate_throttle.passed()
            return True
        cooldown = _gate_throttle.failed()
        self._toast(f"wrong code — locked for {cooldown}s" if cooldown
                    else "wrong code")
        return False

    def _vpn_section(self, v: dict, idx: int, is_new: bool = False):
        """Build the collapsible per-VPN section, a Gtk.Expander so multiple VPNs
        don't sprawl the tab."""
        default_name = v.get("name") or f"vpn-{idx + 1}"
        # Custom label widget so the header follows the name entry live.
        header_lbl = Gtk.Label()
        header_lbl.set_markup(self._vpn_header_markup(default_name, idx, v.get("type")))
        header_lbl.set_xalign(0.0)
        exp = Gtk.Expander()
        exp.set_label_widget(header_lbl)
        exp.set_resize_toplevel(True)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_border_width(8)
        w = {}
        w["enabled"] = Gtk.CheckButton(label="VPN enabled")
        w["enabled"].set_active(bool(v.get("enabled")))
        box.pack_start(w["enabled"], False, False, 0)

        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(6)
        w["type"] = Gtk.ComboBoxText()
        types = ["fortinet", "openvpn", "wireguard", "inode"]
        for t in types:
            w["type"].append_text(t)
        cur = str(v.get("type", "fortinet"))
        w["type"].set_active(types.index(cur) if cur in types else 0)

        def entry(val, hint):
            e = Gtk.Entry()
            e.set_text(str(val or ""))
            e.set_hexpand(True)
            e.set_placeholder_text(hint)
            return e

        w["name"] = entry(default_name, "name (top-bar pill label)")

        def _on_name_change(e, i=idx, hdr=header_lbl, type_combo=w["type"]):
            hdr.set_markup(self._vpn_header_markup(
                e.get_text().strip() or f"vpn-{i + 1}", i,
                type_combo.get_active_text()))
        w["name"].connect("changed", _on_name_change)
        w["type"].connect("changed", lambda _c: _on_name_change(w["name"]))

        w["gateway"] = entry(v.get("gateway"), "gateway host (fortinet / inode)")
        w["port"] = Gtk.SpinButton.new_with_range(0, 65535, 1)
        w["port"].set_value(int(v.get("port", 443) or 0))
        w["vault_item"] = entry(v.get("vault_item"),
                                "vault login (auto-named 'SOC VPN <name>' if blank)")
        w["config"] = entry(v.get("config"), ".ovpn/.conf path, or the iNode client dir")
        w["domain"] = entry(v.get("domain"), "auth domain (inode)")
        w["realm"] = entry(v.get("realm"), "realm (fortinet)")
        w["trusted_cert"] = entry(v.get("trusted_cert"), "gateway cert sha256 pin")
        w["ready_probe"] = entry(v.get("ready_probe"), "host:port reachable only over the VPN")
        rows = [("name", w["name"]), ("type", w["type"]),
                ("gateway", w["gateway"]), ("port", w["port"]),
                ("vault login", w["vault_item"]), ("config", w["config"]),
                ("domain", w["domain"]), ("realm", w["realm"]),
                ("trusted_cert", w["trusted_cert"]), ("ready_probe", w["ready_probe"])]
        for r, (lbl, widget) in enumerate(rows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(widget, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)

        w["insecure"] = Gtk.CheckButton(label="skip TLS verify (inode — trusted LAN only)")
        w["insecure"].set_active(bool(v.get("insecure")))
        w["config_from_vault"] = Gtk.CheckButton(
            label="config from the vault item's Notes (openvpn / wireguard)")
        w["config_from_vault"].set_active(bool(v.get("config_from_vault")))
        box.pack_start(w["insecure"], False, False, 0)
        box.pack_start(w["config_from_vault"], False, False, 0)

        # --- iNode-specific fields ---
        inode_note = Gtk.Label(label="iNode (H3C SSL VPN) — gateway login + tunnel flags")
        inode_note.get_style_context().add_class("soc-config-sub")
        inode_note.set_xalign(0.0)
        box.pack_start(inode_note, False, False, 8)

        w["ead"] = Gtk.CheckButton(label="send EAD host-check ack after login (--ead)")
        w["ead"].set_active(bool(v.get("ead")))
        w["split_tunnel"] = Gtk.CheckButton(label="split tunnel — only route gateway subnets (--split-tunnel)")
        w["split_tunnel"].set_active(bool(v.get("split_tunnel", True)))
        box.pack_start(w["ead"], False, False, 0)
        box.pack_start(w["split_tunnel"], False, False, 0)

        ig = Gtk.Grid()
        ig.set_column_spacing(8)
        ig.set_row_spacing(6)
        w["ca_file"] = entry(v.get("ca_file"), "custom CA bundle path (--cafile)")
        w["client_cert"] = entry(v.get("client_cert"), "mutual-TLS client cert PEM (--client-cert)")
        w["client_key"] = entry(v.get("client_key"), "mutual-TLS client key PEM (--client-key)")
        w["spa_key"] = entry(v.get("spa_key"), "SPA/HOTP key hex (--spa-key, for SDP)")
        w["spa_key"].set_visibility(False)           # a shared secret, at the glass
        w["spa_aid"] = entry(v.get("spa_aid"), "SPA client AID hex (--spa-aid)")
        w["spa_ports"] = entry(v.get("spa_ports"), "comma-sep knock ports (--spa-ports)")
        w["spa_knock_port"] = Gtk.SpinButton.new_with_range(0, 65535, 1)
        w["spa_knock_port"].set_value(int(v.get("spa_knock_port", 0) or 0))
        w["captcha_retries"] = Gtk.SpinButton.new_with_range(0, 200, 1)
        w["captcha_retries"].set_value(int(v.get("captcha_retries", 40) or 0))
        w["mac"] = entry(v.get("mac"), "override MAC sent to gateway (--mac)")
        w["language"] = entry(v.get("language"), "auth language: cn | en (--language)")
        irows = [("CA file", w["ca_file"]), ("client cert", w["client_cert"]),
                 ("client key", w["client_key"]), ("SPA key", w["spa_key"]),
                 ("SPA AID", w["spa_aid"]), ("SPA ports", w["spa_ports"]),
                 ("SPA knock port", w["spa_knock_port"]),
                 ("CAPTCHA retries", w["captcha_retries"]), ("MAC", w["mac"]),
                 ("language", w["language"])]
        for r, (lbl, widget) in enumerate(irows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            ig.attach(h, 0, r, 1, 1)
            ig.attach(widget, 1, r, 1, 1)
        box.pack_start(ig, False, False, 0)

        # Inline credentials write straight to the vault item; they are never read
        # back (no re-display of stored secrets here).
        cred_frame = Gtk.Frame(label="  inline credentials → vault  ")
        cred_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        cred_box.set_border_width(6)
        w["user"] = entry("", "VPN username (saved to the vault item; never read back)")
        w["pass"] = Gtk.Entry()
        w["pass"].set_visibility(False)
        w["pass"].set_placeholder_text("VPN password (write-only)")
        w["pass"].set_hexpand(True)
        cred_box.pack_start(w["user"], False, False, 0)
        cred_box.pack_start(w["pass"], False, False, 0)
        save_btn = Gtk.Button(label="Save inline creds to vault")
        save_btn.set_tooltip_text("Writes to the vault item named in 'vault login'; "
                                  "auto-names it 'SOC VPN <name>' if blank.")
        save_btn.connect(
            "clicked",
            lambda _b, i=idx, u=w["user"], p=w["pass"], vi=w["vault_item"]:
                self._save_and_clear_vpn_creds(i, u, p, vi))
        cred_box.pack_start(save_btn, False, False, 0)
        cred_frame.add(cred_box)
        box.pack_start(cred_frame, False, False, 0)

        rm = Gtk.Button(label="Remove this VPN")
        rm.get_style_context().add_class("destructive-action")
        rm.set_tooltip_text("Removes the section from the config (next Apply drops "
                            "it). The vault credential item is left alone.")
        rm.connect("clicked", lambda _b, i=idx, e=exp: self._on_remove_vpn(i, e))
        box.pack_start(rm, False, False, 0)

        exp.add(box)
        while len(self._vpn_ws) <= idx:          # keep indexing in step with _vpns
            self._vpn_ws.append(None)
            self._vpn_base.append(None)
        self._vpn_ws[idx] = w
        self._vpn_base[idx] = None if is_new else self._vpn_form(w)
        return exp

    def _vpn_header_markup(self, name: str, idx: int, typ):
        """Bold name, then a small grey "(type)" suffix, so the operator sees the
        choice without expanding the section."""
        name = name or f"vpn-{idx + 1}"
        t = (typ or "").strip() or "?"
        return f"<b>VPN {idx + 1}: {GLib.markup_escape_text(name)}</b>  " \
               f"<span color='#888'>({GLib.markup_escape_text(t)})</span>"

    def _save_and_clear_vpn_creds(self, idx, user_entry, pass_entry, vault_item_entry):
        """Call _save_vpn_creds, then scrub the password entry regardless: even on
        failure it should not linger in a GTK Entry; the operator can retype."""
        self._save_vpn_creds(idx, user_entry.get_text(), pass_entry.get_text(),
                             vault_item_entry)
        pass_entry.set_text("")

    def _tab_security(self):
        """PIN + TOTP enrolment for the Settings gate AND the panel lock."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(12)
        note = Gtk.Label(label=(
            "'Settings PIN' gates THIS window so a passer-by can't repoint the "
            "wall. 'Panel lock' is the 🔒 button / Ctrl+Alt+L input firewall — "
            "enrol a PIN and/or TOTP here or that lock is decorative."))
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        # --- Settings-gate PIN + TOTP (config.pin / config.totp) ---------- #
        sgate = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        sgate.set_border_width(6)
        self._sec_state = Gtk.Label(label=self._settings_state_text())
        self._sec_state.get_style_context().add_class("soc-config-sub")
        self._sec_state.set_xalign(0.0)
        self._sec_state.set_line_wrap(True)
        sgate.pack_start(self._sec_state, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._newpin = Gtk.Entry()
        self._newpin.set_visibility(False)
        self._newpin.set_input_purpose(Gtk.InputPurpose.DIGITS)
        self._newpin.set_placeholder_text("new Settings PIN")
        self._newpin.set_hexpand(True)
        self._sgate_cx = Gtk.Label(label="")
        self._sgate_cx.set_xalign(0.0)
        self._sgate_cx.set_line_wrap(True)
        self._newpin.connect(
            "changed", lambda e: self._cx_hint(e, self._sgate_cx))
        set_b = Gtk.Button(label="Set / change PIN")
        set_b.connect("clicked", lambda *_: self._set_pin())
        clr_b = Gtk.Button(label="Remove PIN")
        clr_b.connect("clicked", lambda *_: self._clear_pin())
        row.pack_start(self._newpin, True, True, 0)
        row.pack_start(set_b, False, False, 0)
        row.pack_start(clr_b, False, False, 0)
        sgate.pack_start(row, False, False, 0)
        sgate.pack_start(self._sgate_cx, False, False, 0)

        trow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._sg_uri = Gtk.Entry()
        self._sg_uri.set_editable(False)
        self._sg_uri.set_hexpand(True)
        self._sg_uri.set_placeholder_text("otpauth://… (appears after Enroll)")
        tset = Gtk.Button(label="Enroll TOTP")
        tset.connect("clicked", lambda *_: self._enroll_totp())
        tclr = Gtk.Button(label="Remove TOTP")
        tclr.connect("clicked", lambda *_: self._clear_totp())
        trow.pack_start(self._sg_uri, True, True, 0)
        trow.pack_start(tset, False, False, 0)
        trow.pack_start(tclr, False, False, 0)
        sgate.pack_start(trow, False, False, 0)
        box.pack_start(self._frame("Settings access (this window)", sgate),
                       False, False, 0)

        # --- Panel-lock PIN + TOTP (the 🔒 input firewall over the wall) -- #
        box.pack_start(self._build_panel_lock_section(), False, False, 0)
        return box

    def _settings_state_text(self) -> str:
        if _reauth_required():
            return ("A PIN or TOTP is set — it is required to open this window "
                    "and to confirm destructive actions.")
        return ("No PIN set — anyone can open this window. Set one to lock it.")

    @staticmethod
    def _frame(title, child):
        f = Gtk.Frame(label=f"  {title}  ")
        f.add(child)
        return f

    def _cx_hint(self, entry, label):
        """Live PIN-complexity feedback on `label` for the text in `entry`."""
        v = entry.get_text()
        ctx = label.get_style_context()
        ctx.remove_class("soc-config-ok")
        ctx.remove_class("soc-config-error")
        if not v:
            label.set_text("")
            return
        r = _cx.check(v, kind="pin")
        ctx.add_class("soc-config-ok" if r.ok else "soc-config-error")
        label.set_text("✓ meets PIN policy" if r.ok
                       else "✗ " + "; ".join(r.issues))

    def _keeps_a_credential(self, other_is_set: bool) -> bool:
        """False (and says why) when removal would leave a require-PIN wall with no
        credential: the form could never be reopened, and Apply would refuse."""
        if require_pin() and not other_is_set:
            self._sec_state.set_text("Refused — this wall requires a PIN or TOTP. "
                                     "Enrol the other one first.")
            return False
        return True

    def _set_pin(self):
        pin = self._newpin.get_text().strip()
        r = _cx.check(pin, kind="pin")
        if not r.ok:
            self._sec_state.set_text("PIN rejected — " + "; ".join(r.issues))
            return
        if _reauth_required() and not self._require_reauth(
                "changing the Settings PIN"):
            return
        try:
            set_pin(pin)
        except OSError as e:
            self._sec_state.set_text(
                f"could not save the PIN: {e} — check that {state_dir()} is "
                f"writable (disk space / permissions).")
            return
        self._newpin.set_text("")
        self._sec_state.set_text("PIN updated — it will be required next time.")

    def _clear_pin(self):
        if not pin_is_set():
            self._sec_state.set_text("No PIN is set.")
            return
        if not self._keeps_a_credential(totp_is_set()):
            return
        if not self._require_reauth("removal of the Settings PIN"):
            return
        clear_pin()
        self._newpin.set_text("")
        self._sec_state.set_text(self._settings_state_text())

    def _enroll_totp(self):
        if _reauth_required() and not self._require_reauth(
                "enrolling a new Settings TOTP"):
            return
        try:
            s = _totp.generate_secret()
            _totp.save(_totp_path(), s)
            self._sg_uri.set_text(_totp.provision_uri(
                s, "kiosk@soc.local", issuer="SOC Wall — Settings"))
            self._sec_state.set_text(
                "TOTP enrolled — paste the URI into your authenticator app "
                "(or scan via `qrencode -t ANSIUTF8 '<uri>'`).")
        except Exception as e:                              # noqa: BLE001
            self._sec_state.set_text(f"could not enrol TOTP: {e}")

    def _clear_totp(self):
        if not totp_is_set():
            self._sec_state.set_text("No TOTP is enrolled.")
            return
        if not self._keeps_a_credential(pin_is_set()):
            return
        if not self._require_reauth("removal of the Settings TOTP"):
            return
        _totp.clear(_totp_path())
        self._sg_uri.set_text("")
        self._sec_state.set_text(self._settings_state_text())

    # --- panel-lock (locker.py) enrollment ---------------------------------- #
    def _panel_lock_status_text(self) -> str:
        sd = state_dir()
        bits = ["PIN: SET ✓" if _lk.pin_is_set(sd) else "PIN: (none)",
                "TOTP: SET ✓" if _lk.totp_is_set(sd) else "TOTP: (none)"]
        return "  ·  ".join(bits)

    def _build_panel_lock_section(self):
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_border_width(6)
        self._pl_state = Gtk.Label(label=self._panel_lock_status_text())
        self._pl_state.get_style_context().add_class("soc-config-sub")
        self._pl_state.set_xalign(0.0)
        self._pl_state.set_line_wrap(True)
        inner.pack_start(self._pl_state, False, False, 0)

        # PIN row + live complexity hint
        prow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._pl_pin = Gtk.Entry()
        self._pl_pin.set_visibility(False)
        self._pl_pin.set_input_purpose(Gtk.InputPurpose.PIN)
        self._pl_pin.set_placeholder_text("new panel-lock PIN")
        self._pl_pin.set_hexpand(True)
        self._pl_cx = Gtk.Label(label="")
        self._pl_cx.set_xalign(0.0)
        self._pl_cx.set_line_wrap(True)
        self._pl_pin.connect("changed", lambda e: self._cx_hint(e, self._pl_cx))
        pset = Gtk.Button(label="Set PIN")
        pset.connect("clicked", lambda *_: self._pl_set_pin())
        pclr = Gtk.Button(label="Remove PIN")
        pclr.connect("clicked", lambda *_: self._pl_clear_pin())
        prow.pack_start(self._pl_pin, True, True, 0)
        prow.pack_start(pset, False, False, 0)
        prow.pack_start(pclr, False, False, 0)
        inner.pack_start(prow, False, False, 0)
        inner.pack_start(self._pl_cx, False, False, 0)

        # TOTP row — Enroll mints a fresh secret + shows the otpauth:// URI the
        # operator pastes into their authenticator (no qrencode dep pulled in).
        trow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._pl_uri = Gtk.Entry()
        self._pl_uri.set_editable(False)
        self._pl_uri.set_hexpand(True)
        self._pl_uri.set_placeholder_text("otpauth://… (appears after Enroll)")
        tset = Gtk.Button(label="Enroll TOTP")
        tset.connect("clicked", lambda *_: self._pl_enroll_totp())
        tclr = Gtk.Button(label="Remove TOTP")
        tclr.connect("clicked", lambda *_: self._pl_clear_totp())
        trow.pack_start(self._pl_uri, True, True, 0)
        trow.pack_start(tset, False, False, 0)
        trow.pack_start(tclr, False, False, 0)
        inner.pack_start(trow, False, False, 0)
        return self._frame("Panel lock (input firewall over the wall)", inner)

    def _pl_set_pin(self):
        sd = state_dir()
        pin = self._pl_pin.get_text().strip()
        r = _cx.check(pin, kind="pin")
        if not r.ok:
            self._pl_state.set_text("PIN rejected — " + "; ".join(r.issues))
            return
        if _lk.pin_is_set(sd) and _reauth_required() and not self._require_reauth(
                "changing the panel-lock PIN"):
            return
        try:
            _lk.set_pin(sd, pin)
        except OSError as e:
            self._pl_state.set_text(
                f"could not save the lock PIN: {e} — check that {sd} "
                f"is writable (disk space / permissions).")
            return
        self._pl_pin.set_text("")
        self._pl_state.set_text(self._panel_lock_status_text())

    def _pl_clear_pin(self):
        sd = state_dir()
        if _lk.pin_is_set(sd) and _reauth_required() and not self._require_reauth(
                "removal of the panel-lock PIN"):
            return
        _lk.clear_pin(sd)
        self._pl_pin.set_text("")
        self._pl_state.set_text(self._panel_lock_status_text())

    def _pl_enroll_totp(self):
        sd = state_dir()
        if _lk.totp_is_set(sd) and _reauth_required() and not self._require_reauth(
                "replacing the panel-lock TOTP"):
            return
        try:
            s = _totp.generate_secret()
            _totp.save(_lk._totp_path(sd), s)
            self._pl_uri.set_text(_totp.provision_uri(
                s, "kiosk@soc.local", issuer="SOC Wall — Panel lock"))
            self._pl_state.set_text(
                "TOTP enrolled — paste the URI into your authenticator app "
                "(or scan via `qrencode -t ANSIUTF8 '<uri>'`).")
        except Exception as e:                              # noqa: BLE001
            self._pl_state.set_text(f"could not enrol TOTP: {e}")

    def _pl_clear_totp(self):
        sd = state_dir()
        if _lk.totp_is_set(sd) and _reauth_required() and not self._require_reauth(
                "removal of the panel-lock TOTP"):
            return
        _totp.clear(_lk._totp_path(sd))
        self._pl_uri.set_text("")
        self._pl_state.set_text(self._panel_lock_status_text())

    def _tab_actions(self):
        """Operator actions that aren't config edits: recover from a wedged panel,
        soft-restart the wall, reboot the box, or run setup.py repair without a
        shell."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="Operator actions. Restart, repair and reboot ask "
                               "for the Settings PIN/TOTP once one is enrolled.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        msg = Gtk.Label(label="")
        msg.get_style_context().add_class("soc-config-ok")
        msg.set_xalign(0.0)
        msg.set_line_wrap(True)

        def _confirm_and_run(label, callable_, *, reauth=False, worker=False):
            # Two-click confirmation: first click changes button text, second
            # actually fires. Prevents an accidental "Reboot" from a fat-finger.
            state = {"armed": False}

            def _disarm(btn):
                if state["armed"]:
                    state["armed"] = False
                    btn.set_label(label)
                return False

            def _report(_res, err):
                msg.set_text(f"{label} ✓" if err is None
                             else f"{label} failed: {err}")

            def cb(btn):
                if not state["armed"]:
                    state["armed"] = True
                    btn.set_label(f"Confirm: {label}")
                    GLib.timeout_add_seconds(4, _disarm, btn)
                    return
                state["armed"] = False
                btn.set_label(label)
                if reauth and _reauth_required() and not self._require_reauth(
                        label.lower()):
                    msg.set_text(f"{label} not run — re-authentication failed.")
                    return
                if worker:
                    msg.set_text(f"{label} …")
                    self._in_worker(callable_, _report)
                    return
                try:
                    callable_()
                    _report(None, None)
                except Exception as e:  # noqa: BLE001
                    _report(None, e)
            return cb

        def _lock_now(_b):
            # This window is non-modal: left open it would stay usable above the
            # lock. destroy(), not close(): close() is only a queued request.
            action = self._actions["lock_wall"]
            self.destroy()
            action()

        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(10)
        rows = []

        if self._actions.get("reload_panels"):
            b = Gtk.Button(label="Reload panels")
            b.set_tooltip_text("Refresh every panel in place (no restart). Use "
                               "when a panel is stuck.")
            b.connect("clicked", _confirm_and_run(
                "Reload panels", self._actions["reload_panels"]))
            rows.append(("Reload panels (in-place)", b))

        if self._actions.get("restart_wall"):
            b = Gtk.Button(label="Restart wall")
            b.get_style_context().add_class("soc-config-primary")
            b.set_tooltip_text("Soft-restart the wall process. Use this to apply "
                               "layout / grid / resolution changes without "
                               "rebooting the box.")
            b.connect("clicked", _confirm_and_run(
                "Restart wall", self._actions["restart_wall"], reauth=True))
            rows.append(("Restart wall", b))

        if self._actions.get("lock_wall"):
            b = Gtk.Button(label="🔒 Lock the wall now")
            b.set_tooltip_text("Same as the toolbar 🔒 and Ctrl+Alt+L. Panels stay "
                               "visible; keyboard + mouse are inert until a PIN or "
                               "TOTP is entered. Closes this window.")
            # Single-click (no confirm): locking is reversible and may be urgent.
            b.connect("clicked", _lock_now)
            rows.append(("Lock the wall now", b))

        if self._actions.get("show_vpn_log"):
            b = Gtk.Button(label="Show VPN log (live)")
            b.set_tooltip_text("Opens the live VPN log viewer.")
            b.connect("clicked", lambda _b: self._actions["show_vpn_log"]())
            rows.append(("Show VPN log (live)", b))

        b = Gtk.Button(label="Repair install")
        b.set_tooltip_text("Run setup.py repair as root. Fixes perms, venv, keys.")
        b.connect("clicked", _confirm_and_run("Repair install", _repair_install,
                                              reauth=True, worker=True))
        rows.append(("Repair install (setup.py repair)", b))

        b = Gtk.Button(label="Reboot machine")
        b.set_tooltip_text("systemctl reboot — needs root.")
        b.connect("clicked", _confirm_and_run("Reboot", _reboot_machine,
                                              reauth=True, worker=True))
        rows.append(("Reboot machine", b))

        for r, (lbl, w) in enumerate(rows):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            grid.attach(h, 0, r, 1, 1)
            grid.attach(w, 1, r, 1, 1)
        box.pack_start(grid, False, False, 0)
        box.pack_start(msg, False, False, 0)
        return box

    def _tab_status(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_border_width(12)
        title = Gtk.Label(label="Wall Status")
        title.get_style_context().add_class("soc-config-title")
        title.set_xalign(0.0)
        box.pack_start(title, False, False, 0)

        panels_total = len(self.panels)
        configured = sum(1 for p in self.panels if getattr(p, "configured", False))
        with_creds = sum(1 for p in self.panels if p.vault_item)
        vw_url = os.environ.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        vw_email = os.environ.get("SOC_VAULT_EMAIL", "")
        from . import secretstore
        sealed = secretstore.is_sealed(os.environ.get("SOC_SECRET_DIR"))
        cols, rows = self._grid_size()

        def line(text):
            lbl = Gtk.Label(label=text)
            lbl.get_style_context().add_class("soc-config-sub")
            lbl.set_xalign(0.0)
            lbl.set_line_wrap(True)
            box.pack_start(lbl, False, False, 0)
            return lbl

        line(_memory_summary())
        line(f"panels         : {configured}/{panels_total} configured, "
             f"grid {cols} x {rows}")
        line(f"auto-login     : {with_creds}/{panels_total} panel(s) have a vault item")
        line(f"vault backend  : {os.environ.get('SOC_VAULT_BACKEND', cfg.DEFAULT_VAULT_BACKEND)}")
        server = line(f"vault server   : {vw_url}  (checking …)")
        line(f"vault account  : {vw_email or '(SOC_VAULT_EMAIL is empty)'}")
        line("master sealed  : "
             + ("yes ✓" if sealed else "NO ✗ — run sudo python3 setup.py first-run"))
        line("VPN status     : shown in the top bar (click the pill to re-check)")

        def done(reachable, _err):
            reachable = bool(reachable)
            server.set_text(f"vault server   : {vw_url}  "
                            f"({'reachable ✓' if reachable else 'NOT REACHABLE ✗'})")
            stale = []
            # A panel that burnt its login retries without ever succeeding usually
            # means the dashboard was redesigned and the selectors no longer match.
            if callable(self._login_stats):
                try:
                    stats = self._login_stats() or {}
                except Exception:                # noqa: BLE001
                    stats = {}
                stale = [pid for pid, s in stats.items()
                         if isinstance(s, dict) and s.get("stale")]
            for w in _status_warnings(vw_url, vw_email, reachable, sealed,
                                      configured, with_creds, stale):
                lbl = Gtk.Label(label=w)
                lbl.get_style_context().add_class("soc-config-error")
                lbl.set_xalign(0.0)
                lbl.set_line_wrap(True)
                box.pack_start(lbl, False, False, 0)
            box.show_all()
        self._in_worker(lambda: _vw_reachable(vw_url), done)
        return box

    # ---- export / import ---------------------------------------------------
    def _export_yaml(self):
        """Dump the panels to a timestamped YAML file in the wall user's home,
        0600 like overrides.json: it names internal hosts. A loadable config, so
        Import can read it back. Holds no credentials (vault item names only)."""
        import yaml
        d = self.display
        out = {"display": {"auto": bool(getattr(d, "auto", True)),
                           "cols": getattr(d, "cols", 2),
                           "rows": getattr(d, "rows", 2),
                           "gap": getattr(d, "gap", 0),
                           "width": getattr(d, "width", 1920),
                           "height": getattr(d, "height", 1080),
                           "layout": getattr(d, "layout", "auto")},
               "panels": [], "tunnel": {"enabled": False},
               "vpn": {"enabled": False}, "proxy": {"enabled": False}}
        for p in self.panels:
            item = {"id": p.id, "url": p.url or "", "title": p.title or "",
                    "vault_item": p.vault_item or "", "engine": p.engine or "webkit",
                    "grid": list(self._grids.get(p.id, p.grid)), "mode": "direct",
                    "selectors": p.selectors or {},
                    "login_marker": p.login_marker or "",
                    "allow_insecure": bool(p.allow_insecure),
                    "allow_media": bool(p.allow_media),
                    "tenant": p.tenant or "",
                    "keepalive": {"strategy": p.keepalive.strategy,
                                  "intervalSec": p.keepalive.intervalSec}}
            if p.mode == "tunnel":
                item.update(mode="tunnel", tunnel=dict(p.tunnel or {}),
                            path=p.path, scheme=p.scheme)
                del item["url"]
            if p.login_zones:
                item["login_zones"] = {k: dict(v) for k, v in p.login_zones.items()}
            out["panels"].append(item)
        path = os.path.expanduser(
            "~/soc-wall-export-{}.yaml".format(time.strftime("%Y%m%d-%H%M%S")))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                yaml.safe_dump(out, fh, default_flow_style=False, allow_unicode=True)
        except (OSError, yaml.YAMLError) as e:
            self._msg(f"Export failed: {e}", error=True)
            return
        self._msg(f"Exported to {path}")

    def _import_yaml(self):
        """Replace the panel list from a config file, through the full loader so
        nothing unvalidated reaches the wall. Takes effect on Apply. Re-auths
        BEFORE the chooser: it replaces every panel, and a GTK file chooser browses
        (and can rename or delete in) the filesystem from the glass."""
        if _reauth_required() and not self._require_reauth("importing panels"):
            return
        chooser = Gtk.FileChooserDialog(title="Import panels.yaml", transient_for=self,
                                        action=Gtk.FileChooserAction.OPEN)
        chooser.add_buttons("Cancel", Gtk.ResponseType.CANCEL,
                            "Open", Gtk.ResponseType.OK)
        ffilter = Gtk.FileFilter()
        ffilter.set_name("YAML files")
        ffilter.add_pattern("*.yaml")
        ffilter.add_pattern("*.yml")
        chooser.add_filter(ffilter)
        rc = _run_modal(chooser)
        path = chooser.get_filename()
        chooser.destroy()
        if rc != Gtk.ResponseType.OK or not path:
            return
        try:
            # Regular files only: opening a FIFO would block the GTK thread.
            if not os.path.isfile(path) or os.path.getsize(path) > MAX_IMPORT_BYTES:
                raise ValueError(f"not a regular file of at most "
                                 f"{MAX_IMPORT_BYTES // 1024} KiB")
            with open(path, encoding="utf-8") as fh:
                new_panels = cfg.load_str(fh.read(), os.path.basename(path)).panels
        except Exception as e:                              # noqa: BLE001
            self._msg(f"Import failed: {e}", error=True)
            return
        if not new_panels:
            self._msg("No panels found in file", error=True)
            return
        new_ids = {p.id for p in new_panels}
        on_wall = {p.id for p in self.panels} - {p.id for p in self._added_panels}
        self._removed_ids = (self._removed_ids | on_wall) - new_ids
        self._added_panels = [p for p in new_panels if p.id not in on_wall]
        self.panels = list(new_panels)
        self._grids = {p.id: tuple(p.grid) for p in self.panels}
        self._rebuild_panel_rows()
        self._msg(f"Imported {len(new_panels)} panels from "
                  f"{os.path.basename(path)} — press Apply to keep them")

    # ---- apply -------------------------------------------------------------
    def _msg(self, text, error=False):
        if self._form_msg is None:       # still behind the gate: no form to show it
            return
        ctx = self._form_msg.get_style_context()
        ctx.remove_class("soc-config-error" if not error else "soc-config-ok")
        ctx.add_class("soc-config-error" if error else "soc-config-ok")
        self._form_msg.set_text(text)

    def _may_save(self) -> bool:
        """Re-checked at save time, not just at open: a credential can have been
        removed since the gate opened."""
        if self._disabled or not self._unlocked:
            return False
        return _reauth_required() or not require_pin()

    def _vpn_form(self, w) -> dict:
        """Flat values of one VPN section."""
        return {
            "name": _sanitize_len(w["name"].get_text(), MAX_VPN_NAME_LEN),
            "enabled": w["enabled"].get_active(),
            "type": w["type"].get_active_text() or "fortinet",
            "gateway": _sanitize_len(w["gateway"].get_text(), MAX_VPN_GATEWAY_LEN),
            "port": int(w["port"].get_value()),
            "vault_item": _sanitize_len(w["vault_item"].get_text(), MAX_VAULT_ITEM_LEN),
            "config": _sanitize_len(w["config"].get_text(), MAX_VPN_CONFIG_LEN),
            "domain": _sanitize_len(w["domain"].get_text(), MAX_VPN_DOMAIN_LEN),
            "realm": _sanitize_len(w["realm"].get_text(), MAX_VPN_REALM_LEN),
            "trusted_cert": w["trusted_cert"].get_text(),
            "ready_probe": w["ready_probe"].get_text(),
            "insecure": w["insecure"].get_active(),
            "config_from_vault": w["config_from_vault"].get_active(),
            "ead": w["ead"].get_active(),
            "split_tunnel": w["split_tunnel"].get_active(),
            "ca_file": w["ca_file"].get_text(),
            "client_cert": w["client_cert"].get_text(),
            "client_key": w["client_key"].get_text(),
            "spa_key": w["spa_key"].get_text(),
            "spa_aid": w["spa_aid"].get_text(),
            "spa_ports": w["spa_ports"].get_text(),
            "spa_knock_port": int(w["spa_knock_port"].get_value()),
            "captcha_retries": int(w["captcha_retries"].get_value()),
            "mac": w["mac"].get_text(),
            "language": w["language"].get_text(),
        }

    def _proxy_form(self) -> dict:
        w = self._proxy_w
        return {"enabled": w["enabled"].get_active(),
                "url": w["url"].get_text(),
                "vault_item": w["vault_item"].get_text(),
                "ignore_hosts": w["ignore_hosts"].get_text()}

    def _tunnel_form(self) -> dict:
        w = self._tunnel_w
        buf = self._tunnel_ef.get_buffer()
        return {"enabled": w["enabled"].get_active(),
                "jump_host": w["jump_host"].get_text(),
                "identity": w["identity"].get_text(),
                "known_hosts": w["known_hosts"].get_text(),
                "host_key_checking": w["host_key_checking"].get_active_text() or "yes",
                "extra_forwards": buf.get_text(buf.get_start_iter(),
                                               buf.get_end_iter(), False)}

    def _collect_vpns(self):
        """One (idx, form, saved, merged) per live VPN section, plus whether any
        was edited. `saved` is the override entry; `merged` is the whole VPN."""
        rows, edited = [], False
        for idx, w in enumerate(self._vpn_ws):
            if w is None:
                continue
            form = self._vpn_form(w)
            edited = edited or form != self._vpn_base[idx]
            before = self._vpns[idx] or {}
            saved = vpn_form_to_dict(form)
            saved["name"] = form["name"] or f"vpn-{idx + 1}"
            _mark_cleared(saved, form, before)
            merged = dict(before)
            _merge_form(merged, saved)
            if before.get("name") and saved["name"] != before["name"]:
                # Renamed: at boot the old entry is dropped, so nothing is left to
                # merge over and the advanced fields have to travel with it.
                saved = dict(merged)
            rows.append((idx, form, saved, merged))
        return rows, edited

    def _form_problems(self, vpn_rows, vpn_changed, proxy_form, tunnel_form) -> list:
        """Run the loader's validators on what is about to be saved. Overrides are
        applied after the config is validated, and the host writes them back into
        the vault note, so a bad value here would otherwise surface as a wall that
        no longer boots. Only checks sections that changed: an old quirk elsewhere
        must not block a URL edit."""
        errs = []
        if vpn_changed:
            cfg._validate_vpns([r[3] for r in vpn_rows], errs, [])
        if proxy_form is not None:
            cfg._validate_proxy(proxy_form_to_dict(proxy_form), errs, [])
        if tunnel_form is not None:
            t = tunnel_form_to_dict(tunnel_form)
            cfg._validate_tunnel_argv(t, errs, [])
            if (t.get("enabled") and not t.get("jump_host")
                    and any(p.mode == "tunnel" for p in self.panels)):
                errs.append("panels use mode 'tunnel' but no jump host is set")
            for entry in t.get("extra_forwards", ()):
                try:
                    cfg._safe_forward(entry)
                except ValueError as e:
                    errs.append(str(e))
        return errs

    def _merge_panels(self, changes: dict, overrides: dict):
        by_id = {p.id: p for p in self.panels}
        for pid, w in self._rows.items():
            url = _sanitize_len(w["url"].get_text(), MAX_URL_LEN)
            title = _sanitize_len(w["title"].get_text(), MAX_TITLE_LEN)
            vault_item = _sanitize_len(w["vault"].get_text(), MAX_VAULT_ITEM_LEN)
            engine = w["engine"].get_active_text() or "webkit"
            sel = {k: _sanitize_len(w[k].get_text(), MAX_SELECTOR_LEN)
                   for k in ("user", "pass", "submit")}
            sel = {k: v for k, v in sel.items() if v}
            marker = _sanitize_len(w["marker"].get_text(), MAX_MARKER_LEN)
            # only url/title/vault apply live; the rest persist for next restart
            changes[pid] = {"url": url, "title": title, "vault_item": vault_item}
            entry = overrides.get(pid, {}) if isinstance(overrides.get(pid), dict) else {}
            entry.update({"url": url, "title": title, "vault_item": vault_item,
                          "engine": engine, "selectors": sel, "login_marker": marker,
                          "allow_insecure": w["allow_insecure"].get_active(),
                          "allow_media": w["allow_media"].get_active(),
                          "proxy": w["proxy"].get_active(),
                          "keepalive": {
                              "strategy": w["ka_strat"].get_active_text() or "none",
                              "intervalSec": int(w["ka_int"].get_value())},
                          "tenant": _sanitize_len(w["tenant"].get_text(),
                                                  cfg.MAX_TENANT_LEN)})
            # Only when moved: a saved grid would otherwise outrank later edits
            # to the source config.
            if self._grids[pid] != tuple(by_id[pid].grid):
                entry["grid"] = list(self._grids[pid])
                by_id[pid].grid = self._grids[pid]
            overrides[pid] = entry

        added, removed = self._added_panels, self._removed_ids
        if not (added or removed):
            return
        # Pass add/remove signals so the wall can create/destroy views live, and
        # record them: an override keyed by id alone would not outlive a restart.
        new = {p.id for p in added}
        for pid in removed:
            overrides.pop(pid, None)
        kept = [e for e in overrides.get("_added_panels") or []
                if isinstance(e, dict) and e.get("id") not in removed | new]
        overrides["_added_panels"] = kept + [
            {"id": p.id, "grid": list(p.grid)} for p in added]
        gone = set(overrides.get("_removed_panels") or []) | removed
        overrides["_removed_panels"] = sorted(gone - new)
        if added:
            rows = self._rows
            changes["_add_panel"] = [{
                "id": p.id, "url": rows[p.id]["url"].get_text().strip(),
                "title": rows[p.id]["title"].get_text().strip(),
                "vault_item": rows[p.id]["vault"].get_text().strip(),
                "engine": rows[p.id]["engine"].get_active_text() or "webkit",
                "selectors": dict(p.selectors), "login_marker": p.login_marker,
                "mode": p.mode, "grid": list(p.grid),
                "allow_insecure": rows[p.id]["allow_insecure"].get_active(),
            } for p in added]
        if removed:
            changes["_remove_panel"] = sorted(removed)

    def _apply(self):
        if not self._may_save():
            self._msg("Not saved — this wall requires a Settings PIN or TOTP and "
                      "none is enrolled. Enrol one on the Security tab first.",
                      error=True)
            return
        bad = [pid for pid, w in self._rows.items()
               if not valid_url(w["url"].get_text())
               or len(w["url"].get_text().strip()) > MAX_URL_LEN]
        if bad:
            self._msg(f"only http:// or https:// URLs are allowed (check: {', '.join(bad)})",
                      error=True)
            return

        vpn_rows, vpn_edited = self._collect_vpns()
        vpn_changed = vpn_edited or self._vpn_dirty
        proxy_form = self._proxy_form() if self._proxy_w else None
        if proxy_form == self._proxy_base:
            proxy_form = None
        tunnel_form = self._tunnel_form() if self._tunnel_w else None
        if tunnel_form == self._tunnel_base:
            tunnel_form = None
        problems = self._form_problems(vpn_rows, vpn_changed, proxy_form, tunnel_form)
        if problems:
            self._msg("Not saved — " + "; ".join(problems[:3]), error=True)
            return

        # All of this comes before anything is written, and before the overrides
        # are loaded: the prompt spins the main loop, and calibration can save
        # meanwhile. A failed re-auth leaves the file and the wall untouched.
        touched = [name for name, hit in (("VPN", vpn_edited),
                                          ("proxy", proxy_form is not None),
                                          ("tunnel", tunnel_form is not None)) if hit]
        if touched and _reauth_required() and not self._require_reauth(
                f"changing the {' / '.join(touched)} settings"):
            self._msg("Not saved — re-authentication failed, nothing was changed.",
                      error=True)
            return

        changes, overrides = {}, load_overrides()
        self._merge_panels(changes, overrides)

        if self._layout_c is not None:
            disp = {"layout": self._layout_c.get_active_text() or "auto",
                    "gap": int(self._gap_s.get_value()),
                    "cols": int(self._cols_s.get_value()),
                    "rows": int(self._rows_s.get_value()),
                    "auto": bool(self._disp_auto.get_active()),
                    "width": int(self._w_s.get_value()),
                    "height": int(self._h_s.get_value()),
                    "fullscreen": bool(self._fullscreen_c.get_active())}
            overrides["_display"] = disp
            changes["_display"] = disp

        # VPN/proxy/tunnel are only sent when they changed: the host restarts a
        # service for each, and a URL edit must not bounce the VPN.
        if vpn_changed:
            saved = [r[2] for r in vpn_rows]
            merged = [r[3] for r in vpn_rows]
            overrides["_vpns"] = saved
            names = {m.get("name") for m in merged}
            prior = overrides.get("_vpns_removed")
            overrides["_vpns_removed"] = sorted(
                (self._vpn_names_open | set(prior if isinstance(prior, list) else ()))
                - names)
            changes["_vpns"] = merged
            # back-compat: first entry under the legacy key
            overrides["_vpn"] = saved[0] if saved else {}
            changes["_vpn"] = merged[0] if merged else {}

        if proxy_form is not None:
            p = self._proxy
            pcfg = _mark_cleared(proxy_form_to_dict(proxy_form), proxy_form,
                                 {"url": p.url, "vault_item": p.vault_item,
                                  "ignore_hosts": list(p.ignore_hosts)})
            overrides["_proxy"] = pcfg
            changes["_proxy"] = pcfg

        if tunnel_form is not None:
            tcfg = _mark_cleared(tunnel_form_to_dict(tunnel_form), tunnel_form,
                                 self._tunnel)
            overrides["_tunnel"] = tcfg
            changes["_tunnel"] = tcfg

        try:
            save_overrides(overrides)
        except (OSError, ValueError, TypeError) as e:  # noqa: BLE001 — disk full /
            # dir not writable (OSError), a circular reference (ValueError) or a
            # non-serialisable override value (TypeError) from json.dump — all
            # surface here as a guiding message, not a generic 'apply error' that
            # would escape to GLib.
            self._msg(f"could not save settings: {e} — check that "
                      f"{state_dir()} is writable (disk space / permissions)",
                      error=True)
            return

        # Saved: what is on screen is now the baseline.
        if vpn_changed:
            for idx, form, _saved, merged_vpn in vpn_rows:
                self._vpn_base[idx] = form
                self._vpns[idx] = merged_vpn
            self._vpn_dirty = False
        if proxy_form is not None:
            self._proxy_base = proxy_form
        if tunnel_form is not None:
            self._tunnel_base = tunnel_form
        self._added_panels = []
        self._removed_ids = set()

        try:
            result = self.on_apply(changes)
        except Exception as e:  # noqa: BLE001 — never let a bad apply kill the window
            self._msg(f"apply error: {e}", error=True)
            return
        self._report_apply(result if isinstance(result, dict) else {})

    def _report_apply(self, result: dict):
        """Tell the truth about what happened: a host that returns details gets
        them shown (pending restarts, or a vault note that could not be written,
        which the next boot's stale note would silently win over)."""
        if not result:
            self._msg("Applied ✓  — URL/title/vault live; engine/selectors/layout on restart")
            return
        pending = result.get("pending_restarts") or []
        write_back = result.get("write_back", "")
        deferred = isinstance(write_back, str) and write_back.startswith("deferred:")
        bits = ["Saved ✓ — overrides.json updated"]
        applied_live = result.get("applied_live") or []
        if applied_live:
            bits.append(f"applied live ✓ ({', '.join(applied_live)} — no restart)")
        if result.get("self_restart"):
            bits.append("restarting wall to apply layout change")
        if pending:
            bits.append(f"⚠ PENDING restart: {', '.join(pending)}")
        if deferred:
            bits.append(f"⚠ vault config-note NOT written ({write_back[9:]}) — your "
                        "changes will be lost at the next boot unless you fix this. "
                        "Local overrides remain in effect for now.")
        elif write_back == "ok":
            bits.append("vault note write-back scheduled")
        self._msg("  ·  ".join(bits), error=bool(pending) or deferred)

    def _on_key(self, _w, event):
        if event.keyval == Gdk.KEY_Escape:
            self.close()
            return True
        return False
