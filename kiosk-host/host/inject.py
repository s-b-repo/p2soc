"""
Builds the JavaScript injected into each panel:

  bootstrap_js(panel, mode)  -> the credential-free login/keep-alive bootstrap
                                (rendered from inject/login.js.tmpl).
  bootstrap_with_origin(...) -> bootstrap_js + a warning when no origin gate could
                                be derived (what the panels actually call).
  login_call(creds)          -> a `socLogin({...})` call carrying real creds,
                                evaluated just-in-time by the host.
  calibrate_js()             -> the click-zone calibration overlay.

String values are substituted as JSON literals so selectors containing quotes
(e.g. input[name="user"]) can't break out of the JS string context.
"""
from __future__ import annotations

import json
import os
import sys
import time
from functools import lru_cache
from urllib.parse import urlsplit

_DEFAULT_TMPL = os.path.join(os.path.dirname(__file__), "..", "..", "inject", "login.js.tmpl")

# Minimal idempotent bootstrap used when login.js.tmpl is missing/unreadable
# (e.g. SOC_INJECT_TMPL typo). It installs window.__SOC with needLogin:false so
# NO auto-login fires (render-no-login beats a dark wall / blank respawn loop),
# carries installed:true so the idempotency guard and Chromium's defensive
# `window.__SOC||{}` read behave, and adds no token the .replace() in
# bootstrap_js() would corrupt.
_FALLBACK_BOOTSTRAP = ("(function(){if(window.__SOC&&window.__SOC.installed)return;"
                       "window.__SOC={installed:true,needLogin:false,justLoggedIn:false,lastLogin:0};})();")


@lru_cache(maxsize=1)
def _template() -> str:
    path = os.path.abspath(os.environ.get("SOC_INJECT_TMPL", _DEFAULT_TMPL))
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        # Loud once-per-cold-start diagnostic: print the resolved abspath AND
        # the env-var name so a SOC_INJECT_TMPL typo is obvious. Returning the
        # built-in fallback keeps panels RENDERING (without auto-login) instead
        # of crashing _build() (dark wall) or looping CDP setup forever.
        sys.stderr.write(f"[soc-inject] login bootstrap template unreadable at {path} "
                         f"(SOC_INJECT_TMPL); panels render WITHOUT auto-login: {e}\n")
        return _FALLBACK_BOOTSTRAP


def panel_origin(url: str) -> str:
    """Browser-style origin (scheme://host[:port], default ports omitted) for a
    panel's effective_url — matches JS `location.origin`. Returns '' if not
    derivable (non-http(s) / no host), which leaves the autofill origin gate
    unset (legacy fill-anywhere behaviour). Used to gate credential injection
    to the panel's configured origin (see inject/login.js.tmpl)."""
    try:
        u = urlsplit(url or "")
        if u.scheme not in ("http", "https") or not u.hostname:
            return ""
        host = u.hostname
        default = 443 if u.scheme == "https" else 80
        port = u.port
        if port and port != default:
            return f"{u.scheme}://{host}:{port}"
        return f"{u.scheme}://{host}"
    except ValueError:
        return ""


def _safe_zones(panel) -> dict:
    """The panel's login_zones reduced to known keys with in-range numeric ratios.
    Config validation already rejects bad zones, but .login_zones is also mutated
    at runtime (calibration, a hand-edited override), and this is rendered straight
    into page JS, so it is filtered again here."""
    zones = {}
    raw = getattr(panel, "login_zones", None) or {}
    for key in ("user", "pass", "submit"):
        z = raw.get(key)
        if not isinstance(z, dict):
            continue
        x, y = z.get("x_pct"), z.get("y_pct")
        if (isinstance(x, (int, float)) and not isinstance(x, bool)
                and isinstance(y, (int, float)) and not isinstance(y, bool)
                and 0.0 <= float(x) <= 1.0 and 0.0 <= float(y) <= 1.0):
            zones[key] = {"x_pct": float(x), "y_pct": float(y)}
    return zones


def bootstrap_js(panel, mode: str) -> str:
    sel = panel.selectors
    ka = {
        "strategy": panel.keepalive.strategy,
        "intervalSec": panel.keepalive.intervalSec,
    }
    if panel.keepalive.url:
        ka["url"] = panel.keepalive.url
    if panel.keepalive.target:
        ka["target"] = panel.keepalive.target

    # Origin gate: socLogin refuses to fill creds on any origin other than the
    # panel's configured one (defends against open redirects / a compromised
    # dashboard navigating off-site). '' (non-http(s) url) = legacy no-gate.
    origin = panel_origin(getattr(panel, "effective_url", "") or "")

    # token (including surrounding quotes where present) -> replacement literal
    repl = {
        '"{{PANEL_ID}}"':       json.dumps(panel.id),
        '"{{MODE}}"':           json.dumps(mode),
        '"{{USER_SEL}}"':       json.dumps(sel.get("user", "")),
        '"{{PASS_SEL}}"':       json.dumps(sel.get("pass", "")),
        '"{{SUBMIT_SEL}}"':     json.dumps(sel.get("submit", "")),
        '"{{LOGIN_MARKER}}"':   json.dumps(panel.login_marker),
        '"{{ALLOWED_ORIGIN}}"': json.dumps(origin),
        "{{KEEPALIVE_JSON}}":   json.dumps(ka),
        "{{LOGIN_ZONES_JSON}}": json.dumps(_safe_zones(panel)),
    }
    js = _template()
    for token, value in repl.items():
        js = js.replace(token, value)
    return js


def bootstrap_with_origin(panel, mode: str, log=None) -> str:
    """bootstrap_js, warning when no origin gate could be derived: an unresolvable
    origin renders allowedOrigin '' (legacy fill-anywhere), which must not be silent
    on a wall that autofills credentials."""
    if log is not None and not panel_origin(getattr(panel, "effective_url", "") or ""):
        log(f"[{getattr(panel, 'id', '?')}] no allowed-origin for credential gate "
            f"(url not http(s)); creds may fill on any page")
    return bootstrap_js(panel, mode)


def calibrate_js() -> str:
    """The click-zone calibration overlay. Read on each use (calibration is rare),
    from beside the login template so SOC_INJECT_TMPL relocates both. Raises
    OSError if it is missing; callers report that to the operator."""
    tmpl = os.path.abspath(os.environ.get("SOC_INJECT_TMPL", _DEFAULT_TMPL))
    with open(os.path.join(os.path.dirname(tmpl), "calibrate.js.tmpl"),
              "r", encoding="utf-8") as fh:
        return fh.read()


# The overlay leaves its result in this page global AS A JSON STRING, so the host
# reads it verbatim rather than re-stringifying it.
CALIBRATE_POLL_JS = "window.__SOC_CALIBRATE_RESULT||''"
CALIBRATE_CLEAR_JS = "window.__SOC_CALIBRATE_RESULT=null;"
CALIBRATE_ABORT_JS = ("try{document.getElementById('__soc_calibrate').remove();}"
                      "catch(e){}window.__SOC_CALIBRATE_ACTIVE=false;"
                      "window.__SOC_CALIBRATE_RESULT=null;")


def calibrate_zones(raw, log, panel_id: str):
    """The zones dict from the overlay's JSON result, or None if the operator
    cancelled or it is malformed. Drops unknown keys, so the saved override stays
    schema-conformant. Shared by both engines."""
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        log(f"[{panel_id}] calibrate: malformed result")
        return None
    if not isinstance(obj, dict) or obj.get("cancelled"):
        log(f"[{panel_id}] calibrate: cancelled")
        return None
    zones = {k: obj[k] for k in ("user", "pass", "submit") if isinstance(obj.get(k), dict)}
    log(f"[{panel_id}] calibrate: captured {sorted(zones)}")
    return zones


class LoginRearm:
    """When a panel's auto-login budget runs out it stops and asks a human to sign
    in, which is right when a human is there. On an unattended wall that is a dead
    end: one bad hour of an upstream IdP would leave the panel on its login page
    until someone walks up to it. Instead the budget refills after a backoff that
    doubles to `maximum`: slow enough not to lock the account, but never giving up.

    `due()` is called from wherever the panel noticed the budget is spent; the
    first call starts the wait. Pure and engine-independent, shared by both panels."""

    def __init__(self, initial: float = 300.0, maximum: float = 3600.0,
                 clock=time.monotonic):
        self.initial = initial
        self.maximum = maximum
        self._clock = clock
        self._delay = initial
        self._since = None

    def due(self) -> bool:
        now = self._clock()
        if self._since is None:
            self._since = now
            return False
        if now - self._since < self._delay:
            return False
        self._since = None
        self._delay = min(self._delay * 2, self.maximum)
        return True

    def reset(self):
        """A login worked: the next failure starts from the short wait again."""
        self._delay = self.initial
        self._since = None


def login_call(creds: dict) -> str:
    payload = json.dumps({"user": creds.get("user", ""), "pass": creds.get("pass", "")})
    return f"try{{window.socLogin && window.socLogin({payload});}}catch(e){{}}"


def prompt_call(msg: str) -> str:
    """JS to show the in-page 'sign-in needed' popup."""
    return f"try{{window.socPrompt && window.socPrompt({json.dumps(msg)});}}catch(e){{}}"


def prompt_clear_call() -> str:
    return "try{window.socPromptClear && window.socPromptClear();}catch(e){}"
