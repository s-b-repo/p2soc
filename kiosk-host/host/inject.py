"""
Builds the JavaScript injected into each panel:

  bootstrap_js(panel, mode)  -> the credential-free login/keep-alive bootstrap
                                (rendered from inject/login.js.tmpl).
  login_call(creds)          -> a `socLogin({...})` call carrying real creds,
                                evaluated just-in-time by the host.

String values are substituted as JSON literals so selectors containing quotes
(e.g. input[name="user"]) can't break out of the JS string context.
"""
from __future__ import annotations

import json
import os
import sys
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
    }
    js = _template()
    for token, value in repl.items():
        js = js.replace(token, value)
    return js


def login_call(creds: dict) -> str:
    payload = json.dumps({"user": creds.get("user", ""), "pass": creds.get("pass", "")})
    return f"try{{window.socLogin && window.socLogin({payload});}}catch(e){{}}"


def prompt_call(msg: str) -> str:
    """JS to show the in-page 'sign-in needed' popup."""
    return f"try{{window.socPrompt && window.socPrompt({json.dumps(msg)});}}catch(e){{}}"


def prompt_clear_call() -> str:
    return "try{window.socPromptClear && window.socPromptClear();}catch(e){}"
