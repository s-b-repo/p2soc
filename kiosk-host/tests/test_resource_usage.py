"""Regression tests for the resource work: every buffer stays bounded, polls back off
without getting slower where it matters, and a memory recycle hits the heaviest panel.
The numbers behind each change are in the merge report, not here."""
from __future__ import annotations

import os

import pytest

from host import chromium_panel, perf
from host import main as hostmain


# --------------------------------------------------------------------------- #
# /proc helpers
# --------------------------------------------------------------------------- #
def _fake_proc(root, procs):
    """procs: {pid: (ppid, comm, state, rss_kb)}."""
    for pid, (ppid, comm, state, rss) in procs.items():
        d = root / str(pid)
        d.mkdir()
        (d / "stat").write_bytes(
            f"{pid} ({comm}) {state} {ppid} 0 0 0 0".encode())
        (d / "status").write_text(f"Name:\t{comm}\nVmRSS:\t{rss} kB\n")
    return str(root)


def _rss_from(root):
    return lambda pid: perf.proc_rss_kb(pid, f"{root}/{pid}/status")


def test_proc_table_reads_odd_comms_and_skips_zombies(tmp_path):
    root = _fake_proc(tmp_path, {
        10: (1, "plain", "S", 1),
        11: (10, "a) b (c", "R", 1),
        12: (10, "dead", "Z", 0),
    })
    assert perf.proc_table(root) == {10: (1, "plain"), 11: (10, "a) b (c")}


def test_proc_table_without_proc_is_empty(tmp_path):
    assert perf.proc_table(str(tmp_path / "nope")) == {}


def test_web_process_pids_are_our_webkit_children_only():
    table = {
        5: (1, "WebKitWebProces"),        # the kernel cuts comm at 15 characters
        6: (1, "WebKitNetworkPr"),
        7: (2, "WebKitWebProces"),        # somebody else's
    }
    assert perf.web_process_pids(table, parent=1) == {5}


def test_proc_tree_rss_sums_the_whole_tree(tmp_path):
    root = _fake_proc(tmp_path, {
        20: (1, "chromium", "S", 100),
        21: (20, "zygote", "S", 10),
        22: (21, "renderer", "S", 500),
        23: (1, "unrelated", "S", 9000),
    })
    table = perf.proc_table(root)
    assert perf.proc_tree_rss_kb(20, table, _rss_from(root)) == 610


def test_proc_tree_rss_of_a_gone_process_is_none():
    assert perf.proc_tree_rss_kb(99, {1: (0, "init")}, lambda _p: 1) is None


# --------------------------------------------------------------------------- #
# Log rate limit
# --------------------------------------------------------------------------- #
def test_log_repeat_tells_the_start_then_samples():
    lines = [n for n in range(1, 121) if perf.log_repeat(n)]
    assert lines == [1, 2, 3, 4, 5, 30, 60, 90, 120]


# --------------------------------------------------------------------------- #
# Memory watchdog: the heaviest panel, not round-robin
# --------------------------------------------------------------------------- #
class _View:
    def __init__(self, pid, rss):
        self.panel = type("P", (), {"id": pid})()
        self.rss = rss
        self.recycled = 0

    def mem_rss_kb(self):
        return self.rss

    def recycle(self):
        self.recycled += 1


def _host_with(views, monkeypatch):
    host = hostmain.KioskHost.__new__(hostmain.KioskHost)
    host.panels_view = views
    host._mem_min_mb = 150
    host._mem_cooldown = 0
    host._mem_low_streak = 1           # the transient-dip guard is already satisfied
    host._mem_last_recycle = 0.0
    host._mem_rr = 0
    monkeypatch.setattr(hostmain.perf, "mem_available_mb", lambda: 10)
    return host


def test_watchdog_recycles_the_heaviest_panel_every_time(monkeypatch):
    a, b, c = _View("a", 100), _View("b", 900), _View("c", 300)
    host = _host_with([a, b, c], monkeypatch)
    for _ in range(3):
        host._mem_low_streak = 1
        host._check_memory()
    assert (a.recycled, b.recycled, c.recycled) == (0, 3, 0)


def test_watchdog_skips_a_panel_with_nothing_to_measure(monkeypatch):
    crashed, live = _View("crashed", None), _View("live", 5)
    host = _host_with([crashed, live], monkeypatch)
    host._check_memory()
    assert live.recycled == 1 and crashed.recycled == 0


def test_round_robin_is_only_the_no_proc_fallback(monkeypatch):
    a, b = _View("a", None), _View("b", None)
    host = _host_with([a, b], monkeypatch)
    assert [host._pick_recycle_target() for _ in range(3)] == [a, b, a]


# --------------------------------------------------------------------------- #
# WebKit renderer attribution
# --------------------------------------------------------------------------- #
@pytest.fixture
def wk(monkeypatch):
    wp = pytest.importorskip("host.webkit_panel")
    monkeypatch.setattr(wp, "_web_pids", {})
    return wp


def _wk_panel(wp, pid):
    view = wp.WebKitPanel.__new__(wp.WebKitPanel)
    view.panel = type("P", (), {"id": pid})()
    return view


def test_each_panel_claims_its_own_web_process(wk, monkeypatch):
    live = set()
    monkeypatch.setattr(wk.perf, "web_process_pids", lambda: set(live))
    monkeypatch.setattr(wk.perf, "proc_rss_kb", {101: 500, 102: 900}.get)
    p1, p2 = _wk_panel(wk, "p1"), _wk_panel(wk, "p2")
    live.add(101)
    p1._note_web_process()
    live.add(102)
    p2._note_web_process()
    assert (p1.mem_rss_kb(), p2.mem_rss_kb()) == (500, 900)
    assert hostmain.heaviest_panel([p1, p2]) is p2


def test_a_swapped_process_stays_with_its_panel(wk, monkeypatch):
    live = {101, 102}
    monkeypatch.setattr(wk.perf, "web_process_pids", lambda: set(live))
    monkeypatch.setattr(wk.perf, "proc_rss_kb", {101: 500, 102: 900, 103: 50}.get)
    wk._web_pids.update({101: "p1", 102: "p2"})
    p1 = _wk_panel(wk, "p1")
    live.add(103)                      # a cross-site load launched a new one
    p1._note_web_process()
    assert p1.mem_rss_kb() == 550
    live.discard(101)                  # ...and the old one went away
    assert p1.mem_rss_kb() == 50


def test_a_crashed_panel_measures_nothing(wk, monkeypatch):
    monkeypatch.setattr(wk.perf, "web_process_pids", set)
    wk._web_pids[101] = "p1"
    assert _wk_panel(wk, "p1").mem_rss_kb() is None


def test_web_pid_registry_stays_the_size_of_the_wall(wk, monkeypatch):
    """A leak here would be one entry per crash, forever."""
    live = set()
    monkeypatch.setattr(wk.perf, "web_process_pids", lambda: set(live))
    view = _wk_panel(wk, "p1")
    for pid in range(1000, 3000):
        live.clear()
        live.add(pid)
        view._note_web_process()
    assert wk._web_pids == {2999: "p1"}


def test_memory_settings_survive_the_thresholds_ordering(wk, monkeypatch):
    if getattr(wk.WebKit2, "MemoryPressureSettings", None) is None:
        pytest.skip("webkit2gtk without MemoryPressureSettings")
    monkeypatch.setattr(wk, "_mem_pressure_done", False)
    monkeypatch.setattr(wk, "_mem_pressure", None)
    monkeypatch.setenv("SOC_LOW_MEMORY", "1")
    mps = wk._memory_pressure_settings()
    assert mps.get_memory_limit() == 256
    assert mps.get_conservative_threshold() == pytest.approx(0.50)
    assert mps.get_strict_threshold() == pytest.approx(0.65)


def test_web_contexts_get_the_memory_limit(wk, monkeypatch):
    """The website data manager's setter only reaches the network process: the
    web processes get theirs from the context, at construction."""
    built = {}

    class Ctx:
        def __init__(self, **kw):
            built.update(kw)

    monkeypatch.setattr(wk, "_memory_pressure_settings", lambda: "settings")
    monkeypatch.setattr(wk.WebKit2, "WebContext", Ctx)
    wk._new_context("dm")
    assert built == {"website_data_manager": "dm",
                     "memory_pressure_settings": "settings"}


def test_full_size_boards_keep_the_engine_defaults(wk, monkeypatch):
    monkeypatch.setattr(wk, "_mem_pressure_done", False)
    monkeypatch.setattr(wk, "_mem_pressure", None)
    monkeypatch.setenv("SOC_LOW_MEMORY", "0")
    assert wk._memory_pressure_settings() is None


# --------------------------------------------------------------------------- #
# Chromium: the poll backs off once a page has settled
# --------------------------------------------------------------------------- #
class _P:
    id = "p1"
    url = "http://10.0.0.1/"
    effective_url = "http://10.0.0.1/"
    selectors = {}
    login_marker = ""
    unblock = ()
    allow = ()
    vault_item = "x"


class _Proc:
    returncode = None

    @staticmethod
    def poll():
        return None


class _ScriptedCDP:
    """Answers each poll from a script, then asks the loop to stop."""
    ws = object()
    activity = False

    def __init__(self, panel, polls):
        self.panel, self.polls = panel, list(polls)

    def evaluate(self, expr, return_value=False):
        if not return_value:
            return None
        st = self.polls.pop(0)
        if not self.polls:
            self.panel._stop.set()
        return st


def _poll_delays(polls):
    panel = chromium_panel.ChromiumPanel(_P(), lambda _p: None, lambda _m: None,
                                         cdp_port=9333, poll_interval=2.0)
    panel.proc = _Proc()
    panel.cdp = _ScriptedCDP(panel, polls)
    delays = []
    panel._idle = delays.append
    panel._control_loop()
    return delays


OK = {"r": True}
LOGIN = {"n": True, "r": True}
JUST_IN = {"l": True, "r": True}
LOADING = {}
ERROR = {"e": True}


def test_poll_backs_off_only_once_the_page_has_settled():
    assert _poll_delays([LOADING, LOGIN, JUST_IN, OK, OK]) == [
        2.0, 2.0, 2.0, chromium_panel.POLL_SETTLED_SEC,
        chromium_panel.POLL_SETTLED_SEC]


def test_poll_goes_back_to_fast_as_soon_as_login_is_needed():
    assert _poll_delays([OK, LOGIN, OK])[1] == 2.0


def test_an_error_page_stays_on_the_fast_poll():
    assert _poll_delays([ERROR, ERROR]) == [2.0, 2.0]


def test_an_unconfigured_tile_has_nothing_to_poll_for():
    panel = chromium_panel.ChromiumPanel(_P(), None, None, cdp_port=9333)
    panel.panel = type("P", (), {"effective_url": None})()
    assert panel._settled({})


def test_calibration_keeps_the_fast_poll():
    panel = chromium_panel.ChromiumPanel(_P(), None, None, cdp_port=9333)
    panel._calib = {"src": ""}
    assert not panel._settled(OK)


class _PumpCDP:
    ws = object()

    def __init__(self, clock, on_pump):
        self.activity = False
        self.clock, self.on_pump, self.slices = clock, on_pump, []

    def pump(self, duration):
        self.slices.append(duration)
        self.clock["now"] += duration
        self.on_pump()


def _idle(monkeypatch, event=lambda _panel: None):
    """Run one settled wait on a fake clock; `event` fires during the first slice."""
    clock = {"now": 0.0}
    monkeypatch.setattr(chromium_panel.time, "monotonic", lambda: clock["now"])
    panel = chromium_panel.ChromiumPanel(_P(), None, lambda _m: None,
                                         cdp_port=9333, poll_interval=2.0)
    panel.proc = _Proc()
    panel.cdp = _PumpCDP(clock, lambda: event(panel))
    panel._idle(chromium_panel.POLL_SETTLED_SEC)
    return clock["now"], panel


def test_a_settled_wait_runs_its_whole_length_in_slices(monkeypatch):
    waited, panel = _idle(monkeypatch)
    assert waited == chromium_panel.POLL_SETTLED_SEC
    assert max(panel.cdp.slices) <= 2.0


def test_a_navigation_cuts_the_wait_to_one_poll_interval(monkeypatch):
    waited, _ = _idle(monkeypatch, lambda p: setattr(p.cdp, "activity", True))
    assert waited == 2.0


def test_a_calibration_request_cuts_the_wait_too(monkeypatch):
    waited, _ = _idle(monkeypatch, lambda p: setattr(p, "_calib", {"src": ""}))
    assert waited == 2.0


def test_a_dead_process_ends_the_wait(monkeypatch):
    waited, _ = _idle(monkeypatch, lambda p: setattr(p.proc, "poll", lambda: 1))
    assert waited == 2.0


def test_a_dying_socket_still_backs_off_instead_of_spinning(monkeypatch):
    panel = chromium_panel.ChromiumPanel(_P(), None, lambda _m: None,
                                         cdp_port=9333, poll_interval=2.0)

    class Dead:
        ws = object()
        activity = False

        @staticmethod
        def pump(_d):
            raise chromium_panel.CDPError("socket closed")

    waits = []
    panel.cdp = Dead()
    monkeypatch.setattr(panel._stop, "wait", waits.append)
    panel._idle(chromium_panel.POLL_SETTLED_SEC)
    assert waits == [2.0]              # one poll interval, as it always waited


@pytest.mark.parametrize("method,params,expected", [
    ("Page.frameNavigated", {"frame": {"id": "top"}}, True),
    ("Page.frameNavigated", {"frame": {"id": "x", "parentId": "top"}}, False),
    ("Page.navigatedWithinDocument", {}, True),
    ("Inspector.targetCrashed", {}, True),
    ("Network.requestWillBeSent", {}, False),
])
def test_what_counts_as_activity(method, params, expected):
    cdp = chromium_panel._CDP(9333)
    cdp._dispatch({"method": method, "params": params})
    assert cdp.activity is expected


def test_response_bodies_are_not_buffered_for_a_debugger():
    """The Network domain (which the tracker block needs) otherwise keeps 200 MB of
    response bodies in the renderer of any page that keeps fetching."""
    panel = chromium_panel.ChromiumPanel(_P(), None, lambda _m: None, cdp_port=9333)
    panel._blocked_urls = ["*tracker*"]
    calls = {}

    class CDP:
        def rpc(self, method, params=None):
            calls[method] = params

    panel.cdp = CDP()
    panel._setup_network_guards()
    assert calls["Network.enable"] == {"maxTotalBufferSize": 0,
                                       "maxResourceBufferSize": 0}
    assert calls["Network.setBlockedURLs"]["urls"] == ["*tracker*"]


def test_chromium_memory_counts_its_renderers(monkeypatch):
    panel = chromium_panel.ChromiumPanel(_P(), None, lambda _m: None, cdp_port=9333)
    panel.proc = _Proc()
    panel.proc.pid = 20
    monkeypatch.setattr(chromium_panel.perf, "proc_tree_rss_kb",
                        lambda pid: 610 if pid == 20 else None)
    assert panel.mem_rss_kb() == 610


# --------------------------------------------------------------------------- #
# Tunnels: one dead port does not hide the others
# --------------------------------------------------------------------------- #
class _Tunnel:
    mode = "tunnel"

    def __init__(self, pid, port):
        self.id, self.tunnel_local_port = pid, port


def test_tunnels_are_watched_together_not_one_after_another(monkeypatch):
    clock = {"now": 0.0}
    logs = []
    up = {8002}
    monkeypatch.setattr(hostmain.time, "time", lambda: clock["now"])
    monkeypatch.setattr(hostmain.time, "sleep",
                        lambda s: clock.__setitem__("now", clock["now"] + s))
    monkeypatch.setattr(hostmain, "_port_open", lambda _h, port: port in up)
    monkeypatch.setattr(hostmain, "log", logs.append)
    hostmain.wait_for_tunnels(
        [_Tunnel("a", 8001), _Tunnel("b", 8002), _Tunnel("c", 8003)], timeout=10)
    assert clock["now"] == 10                     # one budget, not one per tunnel
    assert logs.index("[b] tunnel up") < logs.index(
        "[a] WARNING tunnel port 8001 never came up; "
        "window will show a connection error")
    assert sum("never came up" in line for line in logs) == 2


def test_tunnel_wait_ignores_what_has_no_port(monkeypatch):
    monkeypatch.setattr(hostmain, "_port_open", lambda *_: pytest.fail("probed"))
    hostmain.wait_for_tunnels([_Tunnel("a", None)], timeout=5)


# --------------------------------------------------------------------------- #
# Journal: what a healthy wall repeats all day
# --------------------------------------------------------------------------- #
def test_login_ok_is_logged_once_per_login_not_per_page_load(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    logs = []
    monkeypatch.setattr(hostmain, "log", logs.append)
    host = hostmain.KioskHost.__new__(hostmain.KioskHost)
    host._logged_in = set()

    class Panel:
        id = "p1"
        vault_item = "Item"
        effective_url = "http://10.0.0.1/"

    for _ in range(50):                # a dashboard that reloads itself
        host.login_success(Panel)
    assert len(logs) == 1

    host.vault = type("V", (), {"creds": staticmethod(lambda _i: {})})
    host.need_login(Panel)             # logged out: the next success is news
    host.login_success(Panel)
    assert len(logs) == 2


# --------------------------------------------------------------------------- #
# VPN pill: nothing to do, so do nothing
# --------------------------------------------------------------------------- #
def _vpn_host(vpns):
    host = hostmain.KioskHost.__new__(hostmain.KioskHost)
    host.conf = type("C", (), {"vpns": vpns})()
    host._vpn_was_enabled = False
    host.polls = 0

    def poll():
        host.polls += 1
    host._poll_vpn = poll
    return host


def test_vpn_poll_is_idle_with_no_vpn_enabled():
    host = _vpn_host([{"name": "off", "enabled": False}])
    for _ in range(5):
        assert host._poll_vpn_periodic() is True      # the timer must stay alive
    assert host.polls == 0


def test_vpn_poll_runs_while_a_vpn_is_enabled_and_once_after():
    host = _vpn_host([{"name": "on", "enabled": True}])
    host._poll_vpn_periodic()
    host._poll_vpn_periodic()
    assert host.polls == 2
    host.conf.vpns = []                # removed: the pill must not keep its state
    host._poll_vpn_periodic()
    host._poll_vpn_periodic()
    assert host.polls == 3


def test_vpn_poll_wakes_up_when_a_vpn_is_added_live():
    host = _vpn_host([])
    host._poll_vpn_periodic()
    host.conf.vpns = [{"name": "new", "enabled": True}]
    host._poll_vpn_periodic()
    assert host.polls == 1


def test_an_unchanged_pill_is_not_restyled():
    wall_mod = pytest.importorskip("host.wall")

    class Ctx:
        def __init__(self):
            self.calls = 0

        def remove_class(self, _c):
            self.calls += 1

        def add_class(self, _c):
            self.calls += 1

    class Pill:
        def __init__(self):
            self.ctx, self.labels = Ctx(), []

        def get_style_context(self):
            return self.ctx

        def set_label(self, text):
            self.labels.append(text)

    pill = Pill()
    wall = wall_mod.WallWindow.__new__(wall_mod.WallWindow)
    wall.vpn_pill, wall.vpn_pills, wall._pill_shown = pill, [], {}
    for _ in range(4):
        wall.set_vpn_status("offline", "VPN: offline")
    assert len(pill.labels) == 1
    wall.set_vpn_status("online", "VPN: online")
    assert len(pill.labels) == 2


# --------------------------------------------------------------------------- #
# The heartbeat is the one thing this work must not touch
# --------------------------------------------------------------------------- #
def test_heartbeat_keeps_its_cadence_and_its_main_loop_timer(monkeypatch):
    sources = []
    monkeypatch.setattr(hostmain.GLib, "timeout_add_seconds",
                        lambda sec, fn: sources.append((sec, fn)) or 7)
    monkeypatch.setattr(hostmain.heartbeat, "write", lambda *a, **k: True)
    beat = hostmain._Beat()
    beat.start()
    assert sources == [(15, beat._tick)]


# --------------------------------------------------------------------------- #
# The login bootstrap: the ping-pong that pegged two cores
# --------------------------------------------------------------------------- #
def _bootstrap() -> str:
    path = os.path.join(os.path.dirname(__file__), "..", "..", "inject",
                        "login.js.tmpl")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_the_prompt_does_not_rewrite_the_same_text():
    """A DOM write fires the observer, which asks the host, which answers with this
    prompt: on a login page with no saved login that loop never ends."""
    assert "if (el.textContent !== text) el.textContent = text;" in _bootstrap()


def test_the_host_is_asked_again_on_the_periodic_check_only():
    js = _bootstrap()
    assert 'if (!periodic && document.getElementById("__soc_prompt")) return;' in js
    assert "setInterval(function () { check(true); }, 5000);" in js

