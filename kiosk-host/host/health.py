"""
Honest, cheap, timeboxed health state for the launcher (and SSH/tests).

WHY this module exists: the launcher's header dot used to be hardcoded green and
its tiles promised more than they proved. This is the single source of truth for
"is the wall actually ready to launch?" — split into a CHEAP SYNC part (so the
launcher opens with NO perceptible delay) and a SLOW PROBE part (so a locked vault
or a dead VPN can never hang the UI). The GTK caller renders neutral from the sync
state instantly, kicks the probe on a background thread, and recolours via
GLib.idle_add when it returns.

Design rules (load-bearing):
  * Pure stdlib (os, socket, json, argparse, urllib.parse) + a tiny self-contained
    KEY=VALUE env reader — importable headless, never needs GTK, never needs the venv.
  * config.py (PyYAML) is imported LAZILY and wrapped in try/except, so a
    missing-yaml / pre-venv import can never break the sync part.
  * The probe has a HARD per-facet timeout (~0.3s). UNKNOWN degrades to neutral/amber
    — never a false green, never a hang.
  * No secrets in any field or log: only the vault NOTE NAME and a host:port ever
    appear; never the URL userinfo, password, or email.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from urllib.parse import urlsplit

# Hard ceiling for any single network probe. Loopback Vaultwarden answers in <1ms;
# this only bites a mis-set non-loopback SOC_VAULT_URL, and even then off-thread.
PROBE_TIMEOUT = 0.3


# --------------------------------------------------------------------------- #
# Tiny env reader — cloned from setup.py.load_env_file so health stays stdlib
# and importable before the venv exists. Reads the RESOLVED soc.env (configpaths)
# and overlays os.environ, so an exported SOC_* wins (matches what the wall sees).
# --------------------------------------------------------------------------- #
def _load_env_file(path: "str | None") -> dict:
    out: dict = {}
    if not path or not os.path.exists(path):
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


def _read_env() -> dict:
    """The effective soc.env: file values (resolved path) overlaid by os.environ,
    so an explicitly-exported SOC_* takes precedence (the wall reads it that way)."""
    path = None
    try:
        from . import configpaths
        path = configpaths.resolve_env()
    except Exception:
        path = os.environ.get("SOC_ENV_FILE")
    env = _load_env_file(path)
    # os.environ wins — an operator who exported SOC_VAULT_URL means it.
    for k in ("SOC_CONFIG_VAULT_ITEM", "SOC_VAULT_URL", "SOC_VAULT_BACKEND"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def _vault_hostport(url: str) -> "str | None":
    """'host:port' from SOC_VAULT_URL, defaulting the port by scheme. Returns None
    when unparseable/absent. NEVER returns userinfo — only host:port, safe to log."""
    url = (url or "").strip()
    if not url:
        return None
    try:
        u = urlsplit(url if "://" in url else "http://" + url)
    except ValueError:
        return None
    host = u.hostname
    if not host:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    return f"{host}:{port}"


# --------------------------------------------------------------------------- #
# SYNC — cheap, no sockets, no blocking. Safe in the launcher's build path.
# --------------------------------------------------------------------------- #
def sync_state() -> dict:
    """The instantly-available state: is-configured, the resolved panels path +
    tier, the panel count (best-effort), the vault note name, vpn-configured.

    Never raises, never opens a socket. config.load() (a fast local YAML parse, no
    network) is attempted in a try so a ConfigError surfaces as valid=False and a
    missing PyYAML surfaces as count=None/valid=None (deferred, NOT a failure).
    """
    panels_path = None
    panels_tier = "none"
    try:
        from . import configpaths
        panels_path, panels_tier = configpaths.resolve_read("panels")
    except Exception:
        panels_path = os.environ.get("SOC_PANELS_FILE")
        panels_tier = "$SOC_PANELS_FILE" if panels_path else "none"

    configured = bool(panels_path) and os.path.exists(panels_path)

    panels_count = None
    panels_valid = None
    config_error = None
    vpn_configured = False
    vpn = None  # secret-free vpn subset carried to probe_state (avoids a 2nd parse)
    if configured:
        try:
            from . import config as cfg
            conf = cfg.load(panels_path)
            panels_count = len(conf.panels)
            panels_valid = True
            vc = conf.vpn or {}
            vpn_configured = bool(vc.get("enabled"))
            # Only the keys _vpn_state_fast/_expected_iface need; all non-secret
            # (host:port/iface/path/type), so this stays safe to keep in memory.
            vpn = {k: vc.get(k) for k in
                   ("enabled", "type", "interface", "config", "ready_probe")}
        except ImportError:
            # PyYAML absent (pre-venv / headless) — defer the count, NOT a failure.
            panels_count = None
            panels_valid = None
        except Exception as e:  # ConfigError or any parse fault -> invalid config
            panels_valid = False
            # first line only, never a multi-line dump in a status label
            config_error = str(e).splitlines()[0] if str(e) else e.__class__.__name__

    env = _read_env()
    vault_note = env.get("SOC_CONFIG_VAULT_ITEM") or None
    vault_url_hostport = _vault_hostport(env.get("SOC_VAULT_URL", ""))

    if not configured:
        overall = "unconfigured"
    elif panels_valid is False:
        overall = "invalid"
    else:
        overall = "configured"

    return {
        "configured": configured,
        "panels_path": panels_path,
        "panels_tier": panels_tier,
        "panels_count": panels_count,
        "panels_valid": panels_valid,
        "config_error": config_error,
        "vault_note": vault_note,
        "vault_url_hostport": vault_url_hostport,
        "vpn_configured": vpn_configured,
        "vpn": vpn,
        "overall_sync": overall,
    }


# --------------------------------------------------------------------------- #
# is_installed — SYNC-class (cheap os.path.exists / pwd.getpwnam, NO sockets, NO
# subprocess). Drives the launcher's adaptive system-group (Install hero vs
# Reinstall + Uninstall). Probes the LITERAL /opt + /etc paths the installer writes
# — never SOC_ROOT, so a dev checkout doesn't read as "installed". A
# SOC_FORCE_INSTALLED=0|1 override (the analogue of SOC_VAULT_BACKEND=dev) lets
# verify drive both states without touching /etc or /opt.
# --------------------------------------------------------------------------- #
def is_installed() -> dict:
    """{installed, etc_present, opt_present, units_present, kiosk_user, reason}.

    `installed = stamp or (opt_present and units_present)`. The stamp
    (/etc/soc-display/.installed) is the most authoritative signal; opt+units is the
    fallback for an older install with no stamp. Never raises, never blocks."""
    force = os.environ.get("SOC_FORCE_INSTALLED")
    stamp = os.path.exists("/etc/soc-display/.installed")
    etc_present = os.path.isdir("/etc/soc-display")
    opt_present = os.path.isdir("/opt/soc-display")  # LITERAL — never SOC_ROOT
    units_present = (os.path.exists("/etc/systemd/system/soc-wall.service")
                     or os.path.exists("/usr/lib/systemd/system/soc-wall.service"))
    kiosk_user = False
    try:
        import pwd
        pwd.getpwnam(os.environ.get("SOC_KIOSK_USER", "soc"))
        kiosk_user = True
    except Exception:  # noqa: BLE001 — KeyError (no user) / no pwd -> not present
        kiosk_user = False

    installed = bool(stamp or (opt_present and units_present))
    # reason names the strongest present signal (for tooltips / debugging).
    if stamp:
        reason = "install stamp"
    elif opt_present and units_present:
        reason = "/opt tree + units"
    elif opt_present:
        reason = "/opt tree only"
    elif units_present:
        reason = "units only"
    else:
        reason = "no install signals"

    if force in ("0", "1"):
        installed = force == "1"
        reason = f"forced ({force})"

    return {
        "installed": installed,
        "etc_present": etc_present,
        "opt_present": opt_present,
        "units_present": units_present,
        "kiosk_user": kiosk_user,
        "reason": reason,
    }


# --------------------------------------------------------------------------- #
# PROBE — slow, thread-only. HARD-timeboxed sockets; UNKNOWN -> None.
# --------------------------------------------------------------------------- #
def _tcp_ok(hostport: str, timeout: float) -> "bool | None":
    """A single bounded TCP connect. True=reachable, False=refused/timeout,
    None=unparseable. Pre-split host:port; a bad hostname's DNS resolution can
    exceed `timeout`, so resolution failure is treated as None (amber), not False."""
    host, _, port = (hostport or "").rpartition(":")
    if not host or not port.isdigit():
        return None
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except socket.gaierror:
        return None  # name didn't resolve — unknown, not "down"
    except OSError:
        return False


def _vpn_state_fast(vpn: dict, timeout: float) -> "str | None":
    """vpnstatus.vpn_state but with our 0.3s ceiling on the ready_probe connect
    (the upstream default is 2.0s — too slow for the launcher probe thread).

    Trustworthy signal = the ready_probe TCP connect. The iface-presence fallback
    (filesystem, instant) can false-positive (iface up but route dead), so it is a
    last resort. Returns 'online'|'offline'|'not_configured', or None on error.
    """
    try:
        from . import vpnstatus
    except Exception:
        return None
    if not vpn or not vpn.get("enabled"):
        return vpnstatus.STATE_NOT_CONFIGURED
    probe = (vpn.get("ready_probe") or "").strip()
    if probe:
        ok = _tcp_ok(probe, timeout)
        if ok is None:
            return None  # unparseable/unresolvable probe -> unknown
        return vpnstatus.STATE_ONLINE if ok else vpnstatus.STATE_OFFLINE
    # No probe configured: fall back to the instant iface-presence check.
    try:
        iface = vpnstatus._expected_iface(vpn)
        return vpnstatus.STATE_ONLINE if vpnstatus._iface_up(iface) \
            else vpnstatus.STATE_OFFLINE
    except Exception:
        return None


def probe_state(sync: "dict | None" = None, *, vault_timeout: float = PROBE_TIMEOUT,
                vpn_timeout: float = PROBE_TIMEOUT) -> dict:
    """The slow facets: vault reachability + vpn up/down. THREAD-ONLY (each facet
    is bounded by its timeout). `sync` is reused if given to avoid re-resolving.

    vault_reachable: True/False/None (None = no/garbage SOC_VAULT_URL).
    vpn_state:       'online'|'offline'|'not_configured'|None.
    """
    if sync is None:
        sync = sync_state()

    vault_reachable = None
    hp = sync.get("vault_url_hostport")
    if hp:
        vault_reachable = _tcp_ok(hp, vault_timeout)

    vpn_state = None
    if sync.get("vpn_configured"):
        # sync_state() already parsed+validated panels.yaml and carried the
        # secret-free vpn block forward — reuse it instead of a 2nd full parse.
        vpn = sync.get("vpn")
        if vpn is None:
            # No carried block (e.g. a hand-built sync) — degrade safely; never a
            # second yaml parse on this path.
            vpn_state = None
        else:
            try:
                vpn_state = _vpn_state_fast(vpn, vpn_timeout)
            except Exception:
                vpn_state = None
    else:
        # Either genuinely not configured, or we couldn't tell (yaml deferred).
        vpn_state = "not_configured" if sync.get("panels_valid") is True else None

    return {"vault_reachable": vault_reachable, "vpn_state": vpn_state}


# --------------------------------------------------------------------------- #
# dot_for — the single colour/label mapping (launcher uses it for both the
# initial neutral render and the post-probe recolour). VPN-down outranks all.
# --------------------------------------------------------------------------- #
def dot_for(sync: dict, probe: "dict | None") -> "tuple[str, str]":
    """(level, label) where level in {green, amber, red, neutral}. UNKNOWN never
    false-greens. Precedence: red (config invalid / vpn down) > amber (unconfigured
    / vault unreachable-or-unknown / vpn unknown) > green (all clear)."""
    # RED — a configured-but-broken config, or a confirmed-down VPN.
    if sync.get("panels_valid") is False:
        return "red", "config invalid"
    if probe and probe.get("vpn_state") == "offline":
        return "red", "vpn down"

    # AMBER — nothing configured yet.
    if sync.get("overall_sync") == "unconfigured":
        return "amber", "not configured"

    # Before the probe returns we genuinely don't know vault/vpn yet.
    if probe is None:
        return "neutral", "checking…"

    # AMBER — vault not reachable (down) or unknown (no URL / unresolvable).
    if probe.get("vault_reachable") is False:
        return "amber", "vault locked"
    if probe.get("vault_reachable") is None and sync.get("vault_url_hostport"):
        return "amber", "vault unknown"

    # AMBER — VPN configured but we couldn't determine its state.
    if sync.get("vpn_configured") and probe.get("vpn_state") not in (
            "online", "not_configured"):
        return "amber", "vpn unknown"

    # GREEN — configured + valid, vault ok (or no URL set is acceptable here only
    # when reachable was True), VPN online or not configured.
    if probe.get("vault_reachable") is True or not sync.get("vault_url_hostport"):
        return "green", "secure"
    return "amber", "vault unknown"


# --------------------------------------------------------------------------- #
# full_check — Validate (item 4): sync + probe merged, with a single worst cause.
# Severity mirrors setup.py doctor: fail = config invalid / vpn offline;
# warn = unconfigured / vault unreachable / vault note missing / vpn unknown.
# --------------------------------------------------------------------------- #
def full_check() -> dict:
    sync = sync_state()
    probe = probe_state(sync)
    merged = dict(sync)
    merged.update(probe)

    overall = "pass"
    first_cause = None

    # FAIL — the worst, decodable single line.
    if sync.get("panels_valid") is False:
        overall = "fail"
        first_cause = f"config invalid: {sync.get('config_error') or 'see panels.yaml'}"
    elif probe.get("vpn_state") == "offline":
        overall = "fail"
        first_cause = "VPN down"
    # WARN — degraded but launchable-ish.
    elif sync.get("overall_sync") == "unconfigured":
        overall = "warn"
        first_cause = "not configured — run Setup"
    elif sync.get("vault_url_hostport") and probe.get("vault_reachable") is not True:
        overall = "warn"
        first_cause = "vault unreachable"
    elif sync.get("vpn_configured") and probe.get("vpn_state") != "online":
        overall = "warn"
        first_cause = "VPN state unknown"
    elif not sync.get("vault_note"):
        overall = "warn"
        first_cause = "vault config note not set (using panels.yaml fallback)"

    merged["overall"] = overall
    merged["first_cause"] = first_cause
    return merged


# --------------------------------------------------------------------------- #
# CLI — for tests + SSH. No GTK anywhere.
# --------------------------------------------------------------------------- #
def _check() -> int:
    """Validate wiring headless: sync_state() returns without raising, dot_for maps
    every level. Nonzero + message on any inconsistency. No display, no GTK."""
    problems: "list[str]" = []
    try:
        s = sync_state()
    except Exception as e:
        sys.stderr.write(f"health --check: sync_state raised: {e}\n")
        return 1
    required = {"configured", "panels_path", "panels_tier", "panels_count",
                "panels_valid", "config_error", "vault_note", "vault_url_hostport",
                "vpn_configured", "vpn", "overall_sync"}
    missing = required - set(s)
    if missing:
        problems.append(f"sync_state missing keys: {sorted(missing)}")

    # dot_for must produce a known level for the neutral (no-probe) and every
    # synthetic facet combination.
    levels_seen = set()
    cases = [
        ({"overall_sync": "unconfigured", "panels_valid": None}, None),
        ({"overall_sync": "invalid", "panels_valid": False}, {}),
        ({"overall_sync": "configured", "panels_valid": True,
          "vault_url_hostport": "127.0.0.1:8222", "vpn_configured": False},
         {"vault_reachable": True, "vpn_state": "not_configured"}),
        ({"overall_sync": "configured", "panels_valid": True,
          "vault_url_hostport": "127.0.0.1:8222", "vpn_configured": True},
         {"vault_reachable": True, "vpn_state": "offline"}),
        (s, None),
    ]
    for syn, prb in cases:
        try:
            level, label = dot_for(syn, prb)
        except Exception as e:
            problems.append(f"dot_for raised on {syn!r}/{prb!r}: {e}")
            continue
        if level not in {"green", "amber", "red", "neutral"}:
            problems.append(f"dot_for returned bad level {level!r}")
        if not isinstance(label, str) or not label:
            problems.append(f"dot_for returned bad label {label!r}")
        levels_seen.add(level)
    for need in ("red", "amber", "green", "neutral"):
        if need not in levels_seen:
            problems.append(f"dot_for never produced level {need!r}")

    # is_installed must return the fixed key-set with a bool `installed`, never
    # raise, and honour the SOC_FORCE_INSTALLED override in both directions.
    try:
        inst = is_installed()
    except Exception as e:
        problems.append(f"is_installed raised: {e}")
        inst = {}
    inst_keys = {"installed", "etc_present", "opt_present", "units_present",
                 "kiosk_user", "reason"}
    if set(inst) != inst_keys:
        problems.append(f"is_installed key-set: {sorted(set(inst))}")
    elif not isinstance(inst.get("installed"), bool):
        problems.append("is_installed['installed'] not bool")
    else:
        _save = os.environ.get("SOC_FORCE_INSTALLED")
        try:
            os.environ["SOC_FORCE_INSTALLED"] = "1"
            if is_installed().get("installed") is not True:
                problems.append("SOC_FORCE_INSTALLED=1 did not force installed")
            os.environ["SOC_FORCE_INSTALLED"] = "0"
            if is_installed().get("installed") is not False:
                problems.append("SOC_FORCE_INSTALLED=0 did not force uninstalled")
        finally:
            if _save is None:
                os.environ.pop("SOC_FORCE_INSTALLED", None)
            else:
                os.environ["SOC_FORCE_INSTALLED"] = _save

    if problems:
        for p in problems:
            sys.stderr.write(f"health --check: {p}\n")
        return 1
    sys.stdout.write("health ok\n")
    return 0


def _main(argv: "list[str]") -> int:
    ap = argparse.ArgumentParser(
        prog="host.health",
        description="Resolve the SOC-wall health state (sync + bounded probe).")
    ap.add_argument("--json", action="store_true",
                    help="print json.dumps(full_check()) (runs the probe inline)")
    ap.add_argument("--check", action="store_true",
                    help="validate wiring headless (nonzero on inconsistency)")
    args = ap.parse_args(argv)

    if args.check:
        return _check()
    if args.json:
        sys.stdout.write(json.dumps(full_check(), default=str) + "\n")
        return 0
    # Default: human-ish summary of the sync state + dot.
    s = sync_state()
    level, label = dot_for(s, None)
    sys.stdout.write(json.dumps({"sync": s, "dot": [level, label]},
                                default=str, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
