"""Unit tests for the runtime-hardening fixes (memory/reliability/credential
gate) in chromium_panel.py / webkit_panel.py. No real display or browser — the
GTK/WebKit/CDP edges are mocked exactly like tests/test_host.py does."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest  # noqa: E402

from host import chromium_panel  # noqa: E402


# --------------------------------------------------------------------------- #
# Credential-injection origin gate (security fix #6)
# --------------------------------------------------------------------------- #
def test_panel_origin_matches_browser_location_origin():
    o = chromium_panel.panel_origin
    # default ports are omitted (mirrors JS location.origin)
    assert o("http://10.0.0.1:3000/login") == "http://10.0.0.1:3000"
    assert o("http://127.0.0.1:19103/app") == "http://127.0.0.1:19103"
    assert o("https://app.example.com/x") == "https://app.example.com"
    assert o("https://app.example.com:443/x") == "https://app.example.com"
    assert o("http://h:80/x") == "http://h"
    assert o("https://h:8443/") == "https://h:8443"
    # not an http(s) origin -> empty (gate stays in legacy fill-anywhere mode)
    for bad in ("", None, "ftp://x/y", "file:///etc/passwd", "javascript:1"):
        assert o(bad) == ""


class _FakeKA:
    strategy = "reload"
    intervalSec = 42
    url = None
    target = None


class _FakePanel:
    id = "p1"
    selectors = {"user": "#u", "pass": "#p", "submit": "#s"}
    login_marker = "#u"
    keepalive = _FakeKA()
    effective_url = "http://10.0.0.1:3000/login"


def test_bootstrap_fills_allowed_origin_token():
    js = chromium_panel.bootstrap_with_origin(_FakePanel(), "webkit")
    # the gate placeholder is always substituted (never left raw in the page)
    assert "{{ALLOWED_ORIGIN}}" not in js
    assert 'allowedOrigin: "http://10.0.0.1:3000"' in js


def test_bootstrap_origin_unresolvable_is_legacy_and_warns():
    class _NoUrl(_FakePanel):
        effective_url = ""

    logs = []
    js = chromium_panel.bootstrap_with_origin(_NoUrl(), "webkit", logs.append)
    # backward-compatible: empty allowedOrigin == no gate (dev dummy panels work)
    assert 'allowedOrigin: ""' in js
    assert any("no allowed-origin" in m for m in logs)


# --------------------------------------------------------------------------- #
# CDP rpc() per-recv socket timeout (fix #5)
# --------------------------------------------------------------------------- #
def test_cdp_rpc_sets_per_recv_timeout_and_wedge_raises():
    # a socket that "goes silent" (recv raises WebSocketTimeoutException) must
    # surface as CDPError so the control loop respawns rather than blocking.
    class _WedgedWS:
        def __init__(self):
            self.timeouts = []
            self._to = 10.0

        def gettimeout(self):
            return self._to

        def settimeout(self, t):
            self._to = t
            self.timeouts.append(t)

        def send(self, _data):
            pass

        def recv(self):
            raise chromium_panel.WebSocketTimeoutException("silent")

    cdp = chromium_panel._CDP(9333)
    cdp.ws = _WedgedWS()
    with pytest.raises(chromium_panel.CDPError):
        cdp.rpc("Page.enable", timeout=0.5)
    # a per-recv timeout was actually applied (and bounded), then restored
    assert cdp.ws.timeouts, "rpc() never set a per-recv timeout"
    assert all(t <= chromium_panel.RPC_TIMEOUT for t in cdp.ws.timeouts)
    assert cdp.ws.gettimeout() == 10.0          # original restored in finally


def test_cdp_rpc_restores_timeout_on_success():
    class _ReplyWS:
        def __init__(self):
            self._sent_id = None
            self._to = 7.0

        def gettimeout(self):
            return self._to

        def settimeout(self, t):
            self._to = t

        def send(self, data):
            self._sent_id = json.loads(data)["id"]

        def recv(self):
            return json.dumps({"id": self._sent_id, "result": {"ok": True}})

    cdp = chromium_panel._CDP(9333)
    cdp.ws = _ReplyWS()
    assert cdp.rpc("Page.enable") == {"ok": True}
    assert cdp.ws.gettimeout() == 7.0           # restored


# --------------------------------------------------------------------------- #
# Chromium respawn cap parks after N failures, re-arms on set_url (fix #2)
# --------------------------------------------------------------------------- #
def _chromium_panel_with_failing_spawn(monkeypatch, max_respawns):
    monkeypatch.setattr(chromium_panel, "MAX_RESPAWNS", max_respawns)
    p = _FakePanel()
    logs = []
    panel = chromium_panel.ChromiumPanel(
        p, lambda _p: None, logs.append, cdp_port=9333, poll_interval=0.01)

    spawn_calls = {"n": 0}

    def _boom():
        spawn_calls["n"] += 1
        raise RuntimeError("no chromium here")

    monkeypatch.setattr(panel, "_spawn", _boom)
    # make backoff instant so the loop reaches the cap quickly
    monkeypatch.setattr(panel._stop, "wait", lambda _t=None: False)
    return panel, spawn_calls, logs


def test_chromium_parks_after_max_respawns(monkeypatch):
    panel, spawn_calls, logs = _chromium_panel_with_failing_spawn(monkeypatch, 3)
    import threading
    t = threading.Thread(target=panel._control_loop, daemon=True)
    t.start()
    # wait for it to park
    deadline = time.time() + 5
    while not panel._parked and time.time() < deadline:
        time.sleep(0.01)
    assert panel._parked, "panel never parked after repeated spawn failures"
    # it tried exactly MAX_RESPAWNS times then stopped respawning
    assert spawn_calls["n"] == 3
    # a snapshot now; give the loop a moment — it must NOT keep spawning
    snap = spawn_calls["n"]
    time.sleep(0.1)
    assert spawn_calls["n"] == snap, "parked panel kept respawning"
    assert any("parked" in m for m in logs)
    panel._stop.set()
    t.join(timeout=2)


def test_chromium_set_url_rearms_parked_panel(monkeypatch):
    panel, _spawn_calls, _logs = _chromium_panel_with_failing_spawn(monkeypatch, 2)
    # simulate the parked terminal state
    panel._parked = True
    panel._fail_streak = 7
    panel.proc = None
    panel.cdp = None
    panel.set_url("http://10.0.0.1:9999/new")
    assert panel._parked is False
    assert panel._fail_streak == 0
    assert panel.panel.url == "http://10.0.0.1:9999/new"


def test_chromium_set_url_rejects_non_http(monkeypatch):
    panel, _s, logs = _chromium_panel_with_failing_spawn(monkeypatch, 5)
    panel._parked = True
    panel.set_url("file:///etc/passwd")
    # a bad URL is refused and must NOT silently re-arm a parked panel
    assert panel._parked is True
    assert any("refusing non-http" in m for m in logs)


# --------------------------------------------------------------------------- #
# WebKit retry-source bookkeeping (fix #3): a scheduled retry is removed on
# set_url so a stale _go can't stack a retry on the old URL. Tested against the
# real timer-management methods bound to a light stand-in (no WebView needed).
# --------------------------------------------------------------------------- #
def test_webkit_cancel_retry_removes_glib_source():
    from host import webkit_panel
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import GLib

    # a stand-in carrying only the retry state the timer methods touch
    class _Stub:
        _retry_pending = False
        _retry_id = 0
        _stopped = False

    s = _Stub()
    s.load = lambda: None
    # bind the real methods
    webkit_panel.WebKitPanel._schedule_retry(s, 999)
    assert s._retry_pending is True
    assert s._retry_id != 0
    sid = s._retry_id
    # the GLib source really exists while pending...
    assert GLib.main_context_default().find_source_by_id(sid) is not None
    webkit_panel.WebKitPanel._cancel_retry(s)
    assert s._retry_id == 0
    assert s._retry_pending is False
    # ...and is gone after cancel — no stale _go can fire on the old URL
    assert GLib.main_context_default().find_source_by_id(sid) is None
    # cancelling again is a guarded no-op (never raises)
    webkit_panel.WebKitPanel._cancel_retry(s)


def test_webkit_schedule_retry_noop_when_stopped():
    from host import webkit_panel

    class _Stub:
        _retry_pending = False
        _retry_id = 0
        _stopped = True

    s = _Stub()
    s.load = lambda: (_ for _ in ()).throw(AssertionError("load() must not run"))
    webkit_panel.WebKitPanel._schedule_retry(s, 1)
    assert s._retry_id == 0
    assert s._retry_pending is False
