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
from functools import lru_cache
from urllib.parse import urlsplit

_DEFAULT_TMPL = os.path.join(os.path.dirname(__file__), "..", "..", "inject", "login.js.tmpl")


@lru_cache(maxsize=1)
def _template() -> str:
    path = os.environ.get("SOC_INJECT_TMPL", _DEFAULT_TMPL)
    with open(os.path.abspath(path), "r", encoding="utf-8") as fh:
        return fh.read()


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
