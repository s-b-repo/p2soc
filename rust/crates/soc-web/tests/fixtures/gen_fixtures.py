#!/usr/bin/env python3
"""Regenerate the parity fixtures from the real Python implementation.

    python3 rust/crates/soc-web/tests/fixtures/gen_fixtures.py

The Rust tests assert byte equality against these files, so the injected
JavaScript (and the CSS / origin / host derivations) cannot drift from what the
Python wall renders. Inputs live in cases.json; everything else here is output.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REPO, "kiosk-host"))

# The fixtures must describe the checkout, not whatever this machine deploys.
for var in ("SOC_INJECT_TMPL", "SOC_SECURITY_DIR", "SOC_ETC_DIR", "SOC_NAV_ALLOWLIST",
            "SOC_BLOCK_TRACKERS"):
    os.environ.pop(var, None)
os.environ["SOC_ROOT"] = REPO
os.environ["SOC_ETC_DIR"] = os.path.join(HERE, "no-such-etc")

import yaml  # noqa: E402

from host import config, inject, loginmemory, siteguard, websecurity  # noqa: E402


def write(name, text):
    path = os.path.join(HERE, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def dump(name, obj):
    write(name, json.dumps(obj, indent=1, ensure_ascii=True) + "\n")


def load_panel(raw):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        # Each case is loaded alone, so its wall position is irrelevant.
        doc = {"panels": [dict(raw, grid=[0, 0])]}
        if raw.get("mode") == "tunnel":
            doc["tunnel"] = {"enabled": True, "jump_host": "u@jump", "identity": "/k"}
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True)
        path = fh.name
    try:
        return config.load(path).panels[0]
    finally:
        os.unlink(path)


def bootstraps():
    with open(os.path.join(HERE, "cases.json"), encoding="utf-8") as fh:
        cases = json.load(fh)
    for case in cases:
        panel = load_panel(case["panel"])
        for key, value in (case.get("mutate") or {}).items():
            setattr(panel, key, value)
        write(os.path.join("expected", case["name"] + ".js"),
              inject.bootstrap_js(panel, case["mode"]))


CALL_INPUTS = [
    ["alice", "hunter2"],
    ["a\"b", "p\\x"],
    ["", ""],
    ["dom\\user", "p\u00e4ss w\u00f6rd \u4e2d\u6587 \U0001f511"],
    ["u\u2028v\u2029w", "tab\there\nnewline\rcr\x00nul\x7fdel\x1besc"],
    ["quote'single", "back`tick ${x} {{MODE}}"],
]

PROMPTS = [
    "Auto-login failed \u2014 please sign in here, or open Settings (\u2699 top bar) to fix the saved login.",
    "Sign-in needed \u2014 no saved login for this page. Open Settings (\u2699 top bar) to add one, or log in here.",
    "say \"hi\"",
    "",
]


def calls():
    dump("calls.json", {
        "login": [[u, p, inject.login_call({"user": u, "pass": p})] for u, p in CALL_INPUTS],
        "prompt": [[m, inject.prompt_call(m)] for m in PROMPTS],
        "prompt_clear": inject.prompt_clear_call(),
        "calibrate_poll": inject.CALIBRATE_POLL_JS,
        "calibrate_clear": inject.CALIBRATE_CLEAR_JS,
        "calibrate_abort": inject.CALIBRATE_ABORT_JS,
        "fallback_bootstrap": inject._FALLBACK_BOOTSTRAP,
    })


URLS = [
    "http://10.0.0.1:3000/login",
    "http://127.0.0.1:19103/app",
    "https://app.example.com/x",
    "https://app.example.com:443/x",
    "http://h:80/x",
    "https://h:8443/",
    "https://soc.example/path?q=1",
    "HTTPS://Dash.Example.COM:8443/a?b#c",
    "http://[fd00::1]:8080/x",
    "http://[::1]/",
    "https://[2001:db8::1]:443/",
    "http://example.com./",
    "http://user:pw@host.example/",
    "http://user@host.example:81/",
    "http://h:0/",
    "http://h:/x",
    "http://h:99999/",
    "http://h:8x/",
    "http://h:-1/",
    "http://[::1/",
    "http://::1]/",
    "http://[not-an-ip]/",
    "http://[fe80::1%25eth0]/",
    "http://a:b:80/",
    "http:///nohost",
    "http://",
    "http:/one-slash",
    "http:relative",
    "//schemeless.example/x",
    "",
    "ftp://x/y",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "data:text/html,x",
    "about:blank",
    "ws://h/",
    "not a url",
    "  http://lead.example/",
    "http://trail.example/  ",
    "ht\ntp://nl.example/",
    "http://ta\tb.example/",
    "http://evil.example\\@good.example/",
    "http://good.example#@evil.example/",
    "http://good.example?@evil.example/",
    "http://b\u00fccher.example/",
    "http://UPPER.Example/",
    "http://1.2.3.4/",
    "http://0x7f.1/",
    "https://h.example:443",
    "https://h.example:80/",
    "http://h.example:443/",
]


def origins():
    rows = []
    for u in URLS:
        rows.append({
            "url": u,
            "origin": inject.panel_origin(u),
            "host": siteguard.host_of(u),
            "domain": loginmemory.domain_of(u),
        })
    dump("origins.json", rows)


def security():
    class P:
        effective_url = "https://dash.example.com/overview"
        allow = ["*.cdn.example.net", "extra.io"]
        unblock = []
    class S:
        nav_allowlist = True
        allow = ["global.example.org"]
        block_trackers = True
        sso_allow = ["idp.self-hosted.example"]
    dump("security.json", {
        "sso": siteguard.load_sso_domains(),
        "tracker_hosts": siteguard.tracker_hosts(P()),
        "tracker_hosts_websecurity": websecurity.tracker_hosts(),
        "allowlist": sorted(siteguard.build_allowlist(P(), S())),
        "allowlist_websecurity": sorted(websecurity.build_allowlist(P(), S())),
    })


def style():
    from host import branding, style as st
    out = []
    palettes = {
        "branding_default": None,
        "style_fallback": {},
        "midnight": {
            "primary": "#7e96ff", "background": "#0b1020", "surface_top": "#131a31",
            "surface_bottom": "#1b2b4a", "border": "#1b2b4a", "text": "#e7ecff",
            "text_dim": "#8694c4", "accent_strong": "#2f4fd0", "good": "#57d9a3",
            "warn": "#ffb450", "bad": "#ff8f80",
        },
        "light_accent": {
            "primary": "#abc", "background": "#fff", "surface_top": "#F4F8F5",
            "accent_strong": "#FFD54A", "text": "#0B1F14",
        },
    }
    for name, colors in palettes.items():
        if colors is None:
            branding._cache = None
            colors = dict(branding.load().get("colors") or {})
        else:
            branding._cache = {"colors": dict(colors)}
        st._refresh()
        out.append({"name": name, "colors": colors, "tokens": st.TOKENS,
                    "background": st.BACKGROUND, "css": st._CSS.decode("utf-8")})
    dump("style.json", out)


if __name__ == "__main__":
    bootstraps()
    calls()
    origins()
    security()
    style()
    print("fixtures regenerated in", HERE)
