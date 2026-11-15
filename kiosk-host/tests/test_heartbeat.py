"""The liveness heartbeat: host/heartbeat.py itself, and its wiring in host/main.py.

launcher.sh kills a host whose heartbeat goes stale and soc-update.py rolls a
release back on it, so what matters is that a beat proves the MAIN LOOP is turning:
they come from a GLib timer on that loop, keep coming inside the nested loops of
the unlock and fail-safe screens, and stop when the loop stops.
"""
import json
import os
import threading
import time

import pytest

pytest.importorskip("gi")

from host import heartbeat                             # noqa: E402
from host import main as hostmain                      # noqa: E402
from host import chromium_panel, webkit_panel          # noqa: E402
from host.main import GLib, Gtk                        # noqa: E402


@pytest.fixture
def hb(tmp_path, monkeypatch):
    """A private heartbeat file + a fresh _Beat, recording every write."""
    path = tmp_path / "run" / "heartbeat.json"
    monkeypatch.setenv("SOC_HEARTBEAT_FILE", str(path))
    beat = hostmain._Beat()
    monkeypatch.setattr(hostmain, "_beat", beat)
    writes = []
    real = heartbeat.write

    def spy(total=0, ok=0, *, state="running", dest=None):
        writes.append({"total": total, "ok": ok, "state": state,
                       "thread": threading.current_thread()})
        return real(total, ok, state=state, dest=dest)
    monkeypatch.setattr(heartbeat, "write", spy)
    yield type("HB", (), {"path": path, "beat": beat, "writes": writes})
    beat.stop()


# timeout_add_seconds aligns its wakeups (that is why it is cheap), so a 1 s timer
# can take almost 2 s to fire first.
SETTLE = 2.6


def _turn_loop(seconds):
    loop = GLib.MainLoop()
    GLib.timeout_add(int(seconds * 1000), loop.quit)
    loop.run()


# --- host/heartbeat.py ---------------------------------------------------- #

def test_write_is_atomic_and_leaves_no_temp_file(tmp_path):
    dest = str(tmp_path / "sub" / "hb.json")
    assert heartbeat.write(4, 3, state="running", dest=dest) is True
    doc = json.load(open(dest, encoding="utf-8"))
    assert doc["panels_total"] == 4 and doc["panels_ok"] == 3
    assert doc["state"] == "running" and doc["pid"] == os.getpid()
    assert os.listdir(os.path.dirname(dest)) == ["hb.json"]


def test_failed_replace_keeps_the_old_doc_and_cleans_up(tmp_path, monkeypatch):
    """Atomic means a reader sees the old document or the new one, never a torn
    one, and a failure leaves nothing behind."""
    dest = str(tmp_path / "hb.json")
    heartbeat.write(1, 1, state="old", dest=dest)

    def boom(_src, _dst):
        raise OSError("no space")
    monkeypatch.setattr(heartbeat.os, "replace", boom)
    assert heartbeat.write(9, 9, state="new", dest=dest) is False
    assert heartbeat.read(dest)["state"] == "old"
    assert os.listdir(tmp_path) == ["hb.json"]


def test_unwritable_dir_returns_false_never_raises(tmp_path):
    # A file where the directory should be: fails for root as well.
    (tmp_path / "blocker").write_text("x")
    assert heartbeat.write(1, 1, dest=str(tmp_path / "blocker" / "hb.json")) is False


@pytest.mark.parametrize("body", ["{not json", "", "[1, 2]", '"text"', "null"])
def test_read_of_garbage_is_none(tmp_path, body):
    f = tmp_path / "hb.json"
    f.write_text(body)
    assert heartbeat.read(str(f)) is None


def test_read_of_missing_file_is_none(tmp_path):
    assert heartbeat.read(str(tmp_path / "nope.json")) is None


@pytest.mark.parametrize("doc", [None, {}, {"ts": "soon"}, {"ts": None}, "junk"])
def test_age_of_missing_or_malformed_doc_is_inf(doc):
    assert heartbeat.age(doc) == float("inf")


def test_age_of_fresh_doc_and_clock_skew():
    assert heartbeat.age({"ts": 100.0}, now=130.0) == 30.0
    assert heartbeat.age({"ts": 200.0}, now=100.0) == 0.0      # never negative


def test_path_prefers_the_launchers_explicit_file(monkeypatch):
    monkeypatch.setenv("SOC_HEARTBEAT_FILE", "/some/where.json")
    assert heartbeat.path() == "/some/where.json"


def test_deployed_commit_reads_the_release_marker(tmp_path, monkeypatch):
    (tmp_path / ".commit").write_text("abc123\n")
    monkeypatch.setenv("SOC_ROOT", str(tmp_path))
    monkeypatch.setattr(heartbeat, "_commit_cache", None)
    assert heartbeat.deployed_commit() == "abc123"
    monkeypatch.setattr(heartbeat, "_commit_cache", None)


# --- the main-loop timer -------------------------------------------------- #

def test_timer_beats_on_the_main_loop_thread(hb, monkeypatch):
    monkeypatch.setattr(hostmain, "BEAT_SEC", 1)
    hb.beat.start("unlocking")
    _turn_loop(SETTLE)
    assert len(hb.writes) >= 2                     # start + at least one tick
    assert all(w["thread"] is threading.main_thread() for w in hb.writes)
    assert heartbeat.read(str(hb.path))["state"] == "unlocking"


def test_no_beats_when_the_loop_is_not_turning(hb, monkeypatch):
    """The whole point: a hung main loop stops the beats. Nothing else may keep
    them going."""
    monkeypatch.setattr(hostmain, "BEAT_SEC", 1)
    hb.beat.start()
    time.sleep(SETTLE)                             # main thread "hung"
    assert len(hb.writes) == 1


def test_default_cadence_is_15_seconds(hb, monkeypatch):
    armed = []
    monkeypatch.setattr(hostmain.GLib, "timeout_add_seconds",
                        lambda sec, fn: armed.append(sec) or 99)
    monkeypatch.setattr(hostmain.GLib, "source_remove", lambda _s: True)
    hb.beat.start()
    assert armed == [15]


def test_beats_continue_inside_a_nested_loop(hb, monkeypatch):
    """Dialog.run() and Gtk.main() are nested loops on the default context, which
    is what lets the unlock and fail-safe screens beat."""
    monkeypatch.setattr(hostmain, "BEAT_SEC", 1)
    hb.beat.start("unlocking")

    def nested():
        _turn_loop(SETTLE)
        outer.quit()
        return False
    outer = GLib.MainLoop()
    GLib.idle_add(nested)
    outer.run()
    assert len(hb.writes) >= 2


@pytest.mark.skipif(not hostmain.Gdk.Display.get_default(), reason="needs a display")
def test_beats_continue_inside_a_real_gtk_dialog(hb, monkeypatch):
    monkeypatch.setattr(hostmain, "BEAT_SEC", 1)
    hb.beat.start("unlocking")
    dlg = Gtk.Dialog(title="heartbeat test")
    GLib.timeout_add(int(SETTLE * 1000),
                     lambda: dlg.response(Gtk.ResponseType.CANCEL) or False)
    dlg.run()
    dlg.destroy()
    assert len(hb.writes) >= 2


def test_beat_counts_only_loaded_panels(hb):
    class V:
        def __init__(self, ok):
            self.ok = ok

        def loaded_ok(self):
            if self.ok is None:
                raise RuntimeError("view went away")
            return self.ok

    views = [V(True), V(False), V(True), V(None)]
    hb.beat.start()
    hb.beat.set("running", views=lambda: views)
    doc = heartbeat.read(str(hb.path))
    assert doc["panels_total"] == 4 and doc["panels_ok"] == 2
    assert doc["state"] == "running"


def test_tick_survives_an_error_so_the_timer_is_not_removed(hb):
    def broken():
        raise RuntimeError("boom")
    hb.beat._views = broken
    assert hb.beat._tick() is True


def test_stop_writes_a_last_beat_and_removes_the_timer(hb):
    hb.beat.start()
    src = hb.beat._src
    hb.beat.stop()
    assert heartbeat.read(str(hb.path))["state"] == "stopping"
    assert GLib.main_context_default().find_source_by_id(src) is None
    n = len(hb.writes)
    hb.beat.stop()                                 # idempotent
    assert len(hb.writes) == n


def test_stop_before_start_writes_nothing(hb):
    hb.beat.stop()
    assert hb.writes == []


# --- states through a real main() ----------------------------------------- #

class _Vault:
    backend = type("B", (), {"email": "", "url": ""})()

    def open(self):
        pass


def test_fatal_screen_reports_fatal_and_main_cleans_up(hb, monkeypatch):
    monkeypatch.delenv("SOC_UNATTENDED", raising=False)
    monkeypatch.delenv("SOC_DRY_RUN", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(hostmain, "Vault", lambda **kw: _Vault())
    monkeypatch.setattr(hostmain, "load_config",
                        lambda v: (_ for _ in ()).throw(hostmain.cfg.ConfigError("x")))
    assert hostmain.main() == 2
    states = [w["state"] for w in hb.writes]
    assert states[0] == "unlocking" and "fatal" in states
    assert "running" not in states                 # never claims a real wall
    assert states[-1] == "stopping"
    assert hb.beat._src == 0                       # the timer did not leak


def test_real_wall_reports_running(hb, monkeypatch):
    monkeypatch.delenv("SOC_UNATTENDED", raising=False)
    monkeypatch.delenv("SOC_DRY_RUN", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr("gc.freeze", lambda: None)
    monkeypatch.setattr(hostmain, "Vault", lambda **kw: _Vault())
    monkeypatch.setattr(hostmain, "load_config",
                        lambda v: hostmain._default_template())
    hosts = []
    monkeypatch.setattr(hostmain.KioskHost, "build_and_show",
                        lambda self: hosts.append(self))
    monkeypatch.setattr(hostmain.KioskHost, "open_config", lambda self: None)
    monkeypatch.setattr(hostmain.Gtk, "main_quit", lambda: None)
    seen = {}

    def fake_main():
        seen.update(heartbeat.read(str(hb.path)))
        hosts[0].shutdown()                        # as the real loop's exit does
    monkeypatch.setattr(hostmain.Gtk, "main", fake_main)
    assert hostmain.main() == 0
    assert seen["state"] == "running"


def test_shutdown_writes_stopping(hb, monkeypatch):
    monkeypatch.setattr(hostmain.Gtk, "main_quit", lambda: None)
    host = object.__new__(hostmain.KioskHost)
    host.panels_view = []
    hb.beat.start()
    host.shutdown()
    assert heartbeat.read(str(hb.path))["state"] == "stopping"


# --- panel accessors ------------------------------------------------------ #

class _Card:
    def clear(self):
        pass

    def update(self, *_a, **_k):
        pass


def _webkit_stub():
    s = object.__new__(webkit_panel.WebKitPanel)
    s.panel = type("P", (), {"id": "p1"})()
    s.log = lambda *_a: None
    s.status = _Card()
    s._load_failed = s._ever_loaded = s._page_ok = s._recycling = False
    s._loaded_at = 0.0
    s._retry_delay = webkit_panel.RETRY_INITIAL
    s._proxy_auth_attempts = 0
    s._proxy_retry_delay = webkit_panel.PROXY_RETRY_INITIAL
    s._consec_fail = 0
    s._first_fail_at = 0.0
    s._stopped = False
    s._retry_pending = False
    s._retry_id = 0
    return s


def test_webkit_loaded_ok_follows_the_load_cycle():
    E = webkit_panel.WebKit2.LoadEvent
    s = _webkit_stub()
    assert s.loaded_ok() is False                  # nothing loaded yet
    s._on_load_changed(None, E.STARTED)
    assert s.loaded_ok() is False                  # started is not finished
    s._on_load_changed(None, E.FINISHED)
    assert s.loaded_ok() is True


def test_webkit_failed_load_is_not_ok_even_after_finished():
    """WebKit emits FINISHED after load-failed; that must not read as loaded."""
    E = webkit_panel.WebKit2.LoadEvent
    s = _webkit_stub()
    s._on_load_changed(None, E.FINISHED)
    s._load_failed = True
    s._page_ok = False
    s._on_load_changed(None, E.FINISHED)
    assert s.loaded_ok() is False


def test_webkit_crash_clears_loaded_ok():
    E = webkit_panel.WebKit2.LoadEvent
    s = _webkit_stub()
    s._on_load_changed(None, E.FINISHED)
    s._schedule_retry = lambda _d: None
    s._on_terminated(None, None)
    assert s.loaded_ok() is False


def _chromium_once(states):
    """Run the real control loop for len(states) polls against a fake CDP."""
    class _CDP:
        ws = object()
        script = list(states)

        def evaluate(self, expr, return_value=False):
            return self.script.pop(0) if return_value and self.script else None

        def rpc(self, *_a, **_k):
            return {}

        def close(self):
            pass

    class _Proc:
        pid = 1

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            pass

    class _Panel:
        id = "p1"
        effective_url = "http://10.0.0.1/"
        selectors = {}
        login_marker = ""
        unblock = ()
        allow = ()

    p = chromium_panel.ChromiumPanel(_Panel(), lambda _p: None, lambda *_a: None,
                                     cdp_port=9333)
    p._nav_gate = False
    p.proc, p.cdp = _Proc(), _CDP()
    seen = []
    n = {"left": len(states)}

    def wait(_t=None):
        seen.append(p.loaded_ok())
        n["left"] -= 1
        if n["left"] <= 0:
            p._stop.set()
        return False
    p._stop.wait = wait
    p._control_loop()
    return seen


def test_chromium_loaded_ok_tracks_the_polled_document():
    assert _chromium_once([{"r": True}, {"r": False, "e": True}, {"r": True}]) == [
        True, False, True]


def test_chromium_not_ok_until_polled():
    class _P:
        id = "p"
        effective_url = ""
        selectors = {}
        login_marker = ""
        unblock = ()
        allow = ()
    assert chromium_panel.ChromiumPanel(_P(), None, None, cdp_port=9).loaded_ok() is False
