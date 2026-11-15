"""Chromium renderer-security leg: the engine-shared siteguard logic + the
Chromium launch-arg / CDP-guard assembly.

Covers (no display, no real Chromium — pure assembly + decision logic):
  * siteguard host-matching (subdomain-inclusive), allowlist composition,
    nav decisions, tracker host extraction + per-panel unblock, chromium URL
    patterns, and the global toggles.
  * ChromiumPanel._spawn arg assembly: persistent vs ephemeral --user-data-dir,
    the user-agent override, the security flags.
  * The CDP guards (_setup_network_guards) issuing Network.setBlockedURLs +
    Page.setDownloadBehavior deny + the Document-only Fetch nav gate, honouring
    block_trackers / nav_allowlist.
  * _on_cdp_event refusing an off-allowlist Document nav (BlockedByClient) while
    letting an allowed one and sub-resources continue.

Runs in `make test`.
"""
import os
import tempfile

from host import config
from host import siteguard
from host import chromium_panel


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _load(text):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(text)
        path = fh.name
    return config.load(path)


def _panel(text, pid="a"):
    return {p.id: p for p in _load(text).panels}[pid]


_DASH = """
panels:
  - id: a
    engine: chromium
    grid: [0, 0]
    url: "https://dash.example.com/overview"
"""


# --------------------------------------------------------------------------- #
# siteguard: host matching
# --------------------------------------------------------------------------- #
def test_host_matches_subdomain_inclusive():
    allowed = {"dashboard.com"}
    assert siteguard.host_matches("dashboard.com", allowed)
    assert siteguard.host_matches("auth.dashboard.com", allowed)
    assert siteguard.host_matches("a.b.dashboard.com", allowed)
    # not a subdomain — a lookalike suffix must NOT match
    assert not siteguard.host_matches("evildashboard.com", allowed)
    assert not siteguard.host_matches("dashboard.com.evil.com", allowed)
    assert not siteguard.host_matches("other.com", allowed)


def test_host_matches_case_insensitive_and_empty():
    assert siteguard.host_matches("DASH.Example.COM", {"example.com"})
    assert not siteguard.host_matches("", {"example.com"})


def test_host_of():
    assert siteguard.host_of("https://dash.example.com:8443/x") == "dash.example.com"
    assert siteguard.host_of("not a url") == ""


# --------------------------------------------------------------------------- #
# siteguard: allowlist composition + nav decision
# --------------------------------------------------------------------------- #
def test_build_allowlist_includes_own_origin_and_sso():
    conf = _load(_DASH)
    p = conf.panels[0]
    allowed = siteguard.build_allowlist(p, conf.security)
    assert "dash.example.com" in allowed                 # own origin
    assert "accounts.google.com" in allowed              # bundled SSO
    # wildcard SSO entries are normalised to bare hosts
    assert "okta.com" in allowed


def test_build_allowlist_adds_per_panel_and_global():
    conf = _load(_DASH + "    allow: ['*.cdn.example.net', 'extra.io']\n"
                 "security:\n  allow: ['global.example.org']\n")
    p = conf.panels[0]
    allowed = siteguard.build_allowlist(p, conf.security)
    assert "cdn.example.net" in allowed and "extra.io" in allowed
    assert "global.example.org" in allowed


def test_nav_allowed_decisions():
    conf = _load(_DASH)
    p = conf.panels[0]
    allowed = siteguard.build_allowlist(p, conf.security)
    # own origin + subdomain + bundled SSO -> allowed
    assert siteguard.nav_allowed("https://dash.example.com/page", allowed)
    assert siteguard.nav_allowed("https://sub.dash.example.com/", allowed)
    assert siteguard.nav_allowed("https://accounts.google.com/o/oauth2", allowed)
    # off-allowlist top-level nav -> refused
    assert not siteguard.nav_allowed("https://evil.example/", allowed)
    # about:/data: placeholder pages are always allowed
    assert siteguard.nav_allowed("about:blank", allowed)
    assert siteguard.nav_allowed(chromium_panel.UNCONFIGURED_URL, allowed)


def test_nav_gate_can_be_disabled():
    conf = _load(_DASH + "security:\n  nav_allowlist: false\n")
    assert siteguard.nav_gate_enabled(conf.security) is False


def test_nav_gate_env_kill_switch(monkeypatch):
    monkeypatch.setenv("SOC_NAV_ALLOWLIST", "0")
    conf = _load(_DASH)
    assert siteguard.nav_gate_enabled(conf.security) is False


# --------------------------------------------------------------------------- #
# siteguard: tracker blocklist
# --------------------------------------------------------------------------- #
def test_tracker_hosts_loaded_and_curated():
    conf = _load(_DASH)
    hosts = siteguard.tracker_hosts(conf.panels[0])
    assert "google-analytics.com" in hosts
    assert "doubleclick.net" in hosts
    assert "connect.facebook.net" in hosts
    # no escaping leaked through from the regex url-filter
    assert all("\\" not in h for h in hosts)


def test_chromium_blocked_urls_are_wildcards():
    conf = _load(_DASH)
    urls = siteguard.chromium_blocked_urls(conf.panels[0])
    assert "*google-analytics.com*" in urls
    assert all(u.startswith("*") and u.endswith("*") for u in urls)


def test_per_panel_unblock_removes_a_tracker():
    p = _panel(_DASH + "    unblock: ['segment.io']\n")
    hosts = siteguard.tracker_hosts(p)
    assert "segment.io" not in hosts
    assert "google-analytics.com" in hosts          # the rest stay blocked


def test_trackers_enabled_honours_both_toggles():
    on = _load(_DASH)
    assert siteguard.trackers_enabled(on.panels[0], on.security) is True
    per_panel_off = _load(_DASH + "    block_trackers: false\n")
    assert siteguard.trackers_enabled(per_panel_off.panels[0],
                                      per_panel_off.security) is False
    global_off = _load(_DASH + "security:\n  block_trackers: false\n")
    assert siteguard.trackers_enabled(global_off.panels[0],
                                      global_off.security) is False


# --------------------------------------------------------------------------- #
# Chromium launch-arg assembly
# --------------------------------------------------------------------------- #
class _FakePopen:
    def __init__(self, args, **kw):
        self.args = args
    def poll(self):
        return None


def _spawn_args(panel, monkeypatch, tmp_path, security=None):
    monkeypatch.setattr(chromium_panel, "_chromium_bin", lambda: "/bin/true")
    captured = {}
    monkeypatch.setattr(chromium_panel.subprocess, "Popen",
                        lambda args, **kw: captured.setdefault("args", args)
                        or _FakePopen(args))
    cp = chromium_panel.ChromiumPanel(panel, lambda _p: None, lambda *_a: None,
                                      cdp_port=9444, security=security)
    cp._spawn()
    return captured["args"], cp


def test_spawn_persistent_profile_under_webdata(monkeypatch, tmp_path):
    # persist (default) -> profile lives under the private webdata base (created
    # 0700), NOT on the tmpfs runtime dir that gets wiped each restart.
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "wd"))
    p = _panel(_DASH)
    args, _ = _spawn_args(p, monkeypatch, tmp_path)
    udd = [a for a in args if a.startswith("--user-data-dir=")][0]
    profile = udd.split("=", 1)[1]
    assert str(tmp_path / "wd") in profile
    assert profile.endswith(os.path.join("chromium", "a"))
    # the webdata base + chromium subdir + the per-panel profile are all 0700
    base = str(tmp_path / "wd")
    assert (os.stat(base).st_mode & 0o777) == 0o700
    assert (os.stat(os.path.join(base, "chromium")).st_mode & 0o777) == 0o700
    assert (os.stat(profile).st_mode & 0o777) == 0o700


def test_spawn_ephemeral_profile_when_persist_false(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "wd"))
    p = _panel(_DASH + "    persist: false\n")
    args, _ = _spawn_args(p, monkeypatch, tmp_path)
    udd = [a for a in args if a.startswith("--user-data-dir=")][0].split("=", 1)[1]
    # ephemeral -> tmpfs runtime path, NOT the persistent webdata base
    assert str(tmp_path / "run") in udd
    assert "soc-profiles" in udd
    assert str(tmp_path / "wd") not in udd


def test_spawn_user_agent_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "wd"))
    p = _panel(_DASH + '    user_agent: "SOC/1.0 (kiosk)"\n')
    args, _ = _spawn_args(p, monkeypatch, tmp_path)
    assert "--user-agent=SOC/1.0 (kiosk)" in args
    # default panel emits no UA override
    p0 = _panel(_DASH)
    args0, _ = _spawn_args(p0, monkeypatch, tmp_path)
    assert not any(a.startswith("--user-agent=") for a in args0)


def test_spawn_security_flags_present(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "wd"))
    args, _ = _spawn_args(_panel(_DASH), monkeypatch, tmp_path)
    assert "--block-new-web-contents" in args
    assert any("DownloadBubble" in a for a in args)
    # CDP origin stays pinned (no wildcard) — security regression guard
    assert "--remote-allow-origins=*" not in args


# --------------------------------------------------------------------------- #
# CDP guards: Network.setBlockedURLs + download deny + nav Fetch gate
# --------------------------------------------------------------------------- #
class _FakeCDP:
    def __init__(self):
        self.rpc_calls = []
        self.nowait = []
        self.on_event = None
    def rpc(self, method, params=None):
        self.rpc_calls.append((method, params or {}))
        return {}
    def send_nowait(self, method, params=None):
        self.nowait.append((method, params or {}))

    def methods(self):
        return [m for m, _ in self.rpc_calls]


def _guarded_panel(text, tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "wd"))
    conf = _load(text)
    p = conf.panels[0]
    cp = chromium_panel.ChromiumPanel(p, lambda _p: None, lambda *_a: None,
                                      cdp_port=9444, security=conf.security)
    cp.cdp = _FakeCDP()
    return cp


def test_setup_network_guards_blocks_trackers_and_downloads(tmp_path, monkeypatch):
    cp = _guarded_panel(_DASH, tmp_path, monkeypatch)
    cp._setup_network_guards()
    methods = cp.cdp.methods()
    assert "Network.enable" in methods
    blocked = dict(cp.cdp.rpc_calls)["Network.setBlockedURLs"]["urls"]
    assert any("google-analytics.com" in u for u in blocked)
    assert dict(cp.cdp.rpc_calls)["Page.setDownloadBehavior"]["behavior"] == "deny"
    # Document-only Fetch nav gate armed, with the persistent event handler
    fetch = dict(cp.cdp.rpc_calls)["Fetch.enable"]
    assert fetch["handleAuthRequests"] is True
    assert fetch["patterns"] == [{"requestStage": "Request",
                                  "resourceType": "Document"}]
    assert cp.cdp.on_event == cp._on_cdp_event


def test_setup_network_guards_skips_trackers_when_disabled(tmp_path, monkeypatch):
    cp = _guarded_panel(_DASH + "    block_trackers: false\n", tmp_path, monkeypatch)
    cp._setup_network_guards()
    assert "Network.setBlockedURLs" not in cp.cdp.methods()
    # the nav gate + download deny still apply (independent of tracker blocking)
    assert "Page.setDownloadBehavior" in cp.cdp.methods()
    assert "Fetch.enable" in cp.cdp.methods()


def test_setup_network_guards_skips_nav_gate_when_disabled(tmp_path, monkeypatch):
    cp = _guarded_panel(_DASH + "security:\n  nav_allowlist: false\n",
                        tmp_path, monkeypatch)
    cp._setup_network_guards()
    assert "Fetch.enable" not in cp.cdp.methods()
    assert cp.cdp.on_event is None
    # tracker block + download deny are unaffected
    assert "Network.setBlockedURLs" in cp.cdp.methods()


# --------------------------------------------------------------------------- #
# CDP nav decision: refuse off-allowlist Document, allow the rest
# --------------------------------------------------------------------------- #
def _paused(url, rtype="Document", rid="r1"):
    return {"requestId": rid, "resourceType": rtype, "request": {"url": url}}


def test_on_cdp_event_refuses_off_allowlist_document(tmp_path, monkeypatch):
    cp = _guarded_panel(_DASH, tmp_path, monkeypatch)
    cp._on_cdp_event("Fetch.requestPaused", _paused("https://evil.example/"))
    assert ("Fetch.failRequest",
            {"requestId": "r1", "errorReason": "BlockedByClient"}) in cp.cdp.nowait


def test_on_cdp_event_allows_own_and_sso_documents(tmp_path, monkeypatch):
    cp = _guarded_panel(_DASH, tmp_path, monkeypatch)
    cp._on_cdp_event("Fetch.requestPaused",
                     _paused("https://dash.example.com/x", rid="a"))
    cp._on_cdp_event("Fetch.requestPaused",
                     _paused("https://accounts.google.com/o", rid="b"))
    cont = [c for c in cp.cdp.nowait if c[0] == "Fetch.continueRequest"]
    assert {"requestId": "a"} in [p for _, p in cont]
    assert {"requestId": "b"} in [p for _, p in cont]
    assert not any(c[0] == "Fetch.failRequest" for c in cp.cdp.nowait)


def test_on_cdp_event_lets_off_allowlist_subresource_through(tmp_path, monkeypatch):
    # Only Document (top-level nav) is gated; an off-allowlist sub-resource
    # (e.g. a CDN) must continue, otherwise dashboards break.
    cp = _guarded_panel(_DASH, tmp_path, monkeypatch)
    cp._on_cdp_event("Fetch.requestPaused",
                     _paused("https://cdn.other.net/lib.js", rtype="Script"))
    assert ("Fetch.continueRequest", {"requestId": "r1"}) in cp.cdp.nowait
    assert not any(c[0] == "Fetch.failRequest" for c in cp.cdp.nowait)


def test_set_url_recomputes_allowlist(tmp_path, monkeypatch):
    cp = _guarded_panel(_DASH, tmp_path, monkeypatch)
    assert "dash.example.com" in cp._allowlist
    cp.proc = None       # no live process -> set_url just updates state
    cp.set_url("https://new-dash.example.org/")
    assert "new-dash.example.org" in cp._allowlist
    assert "dash.example.com" not in cp._allowlist
