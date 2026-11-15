"""SOC_UNATTENDED=1: nobody is at the keyboard, so nothing may wait for a human.

Drives the real main() with a fake vault and no display: the real retry loop, a
real GLib main loop and real worker threads, only with the delays shrunk. The
interactive path is pinned too, because it must not change.
"""
import os
import signal
import threading
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("gi")

from host import chromium_panel, config, heartbeat, inject, perf  # noqa: E402
from host import main as hostmain                      # noqa: E402
from host import wall, webkit_panel                    # noqa: E402
from host.litebw import VaultLockedError               # noqa: E402
from host.main import GLib, Gtk                        # noqa: E402
from host.vault import VaultError                      # noqa: E402


class _Vault:
    """vault.open() runs a script of failures, then succeeds."""

    def __init__(self, failures=()):
        self.failures = list(failures)
        self.opens = 0
        self.threads = []
        self.backend = SimpleNamespace(email="k@soc", url="http://vault.local")

    def open(self):
        self.opens += 1
        self.threads.append(threading.current_thread())
        if self.failures:
            raise self.failures.pop(0)


def _config_error(_vault):
    raise config.ConfigError("panels: bad")


@pytest.fixture
def box(tmp_path, monkeypatch):
    """Unattended + headless, with fast retries and private state. Every human
    prompt is a test failure."""
    hb = tmp_path / "heartbeat.json"
    monkeypatch.setenv("SOC_UNATTENDED", "1")
    monkeypatch.setenv("SOC_HEARTBEAT_FILE", str(hb))
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("SOC_UNATTENDED_RELOAD_SEC", "1")
    monkeypatch.setenv("SOC_VAULT_INTERACTIVE", "1")   # main() must override this
    monkeypatch.delenv("SOC_DRY_RUN", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(hostmain, "UNATTENDED_RETRY_INITIAL", 0.01)
    monkeypatch.setattr(hostmain, "UNATTENDED_RETRY_MAX", 0.02)
    monkeypatch.setattr(hostmain, "_beat", hostmain._Beat())
    monkeypatch.setattr("gc.freeze", lambda: None)

    def no_human(*_a, **_k):
        raise AssertionError("prompted a human on an unattended wall")
    monkeypatch.setattr(hostmain, "_unlock_dialog", no_human)
    states = []
    real = heartbeat.write

    def spy(total=0, ok=0, *, state="running", dest=None):
        states.append(state)
        return real(total, ok, state=state, dest=dest)
    monkeypatch.setattr(heartbeat, "write", spy)
    return SimpleNamespace(states=states, mp=monkeypatch, tmp=tmp_path)


def _run_main(box, vault, load=_config_error):
    box.mp.setattr(hostmain, "Vault", lambda **kw: vault)
    box.mp.setattr(hostmain, "load_config", load)
    return hostmain.main()


# --- the vault at boot ---------------------------------------------------- #

@pytest.mark.parametrize("fail", [
    VaultError("could not reach Vaultwarden: Connection refused"),   # not up yet
    VaultLockedError("vault is locked"),                             # no master
    VaultError("no vault master password (host not sealed)"),        # not sealed
    OSError("network is unreachable"),                               # not a VaultError
])
def test_vault_retries_every_failure_with_no_prompt_and_no_restart(box, fail):
    vault = _Vault([fail, fail, fail])
    rc = _run_main(box, vault)
    assert vault.opens == 4                        # kept trying, in THIS process
    assert rc == hostmain.EXIT_RELOAD              # then the config stub stopped it
    assert "unlocking" in box.states


def test_late_vault_recovers_into_the_wall_with_no_restart(box):
    """Vaultwarden starting after the wall: same process goes on to a running wall."""
    vault = _Vault([VaultError("Connection refused")] * 2)
    built = []
    box.mp.setattr(hostmain.KioskHost, "build_and_show",
                   lambda self: built.append(self))
    box.mp.setattr(hostmain.Gtk, "main_quit", lambda: None)

    def fake_main():
        box.states.append("main-loop")
        built[0].shutdown()                        # as the real loop's exit does
    box.mp.setattr(hostmain.Gtk, "main", fake_main)
    rc = _run_main(box, vault, load=lambda v: hostmain._default_template())
    assert rc == 0 and vault.opens == 3 and len(built) == 1
    assert box.states.index("running") < box.states.index("main-loop")


def test_vault_open_runs_on_a_worker_so_the_main_loop_keeps_beating(box):
    box.mp.setattr(hostmain, "BEAT_SEC", 1)

    class Slow(_Vault):
        def open(self):
            super().open()
            time.sleep(2.6)            # timeout_add_seconds(1) may take ~2 s to fire

    vault = Slow()
    _run_main(box, vault)
    assert vault.threads[0] is not threading.main_thread()
    assert box.states.count("unlocking") >= 2      # beat during the slow open


def test_status_screen_says_what_it_is_waiting_for(box):
    shown = []
    box.mp.setattr(hostmain._StatusBoard, "show",
                   lambda self, title, detail, hint="": shown.append(detail))
    _run_main(box, _Vault([VaultError("Connection refused")]))
    assert any("reach Vaultwarden" in d and "http://vault.local" in d for d in shown)


def test_status_never_blames_a_password_nobody_typed(box):
    """The classifier's catch-all assumes someone just typed a master; with nobody
    here the screen must carry the real reason, or it sends the operator after the
    wrong problem."""
    shown = []
    box.mp.setattr(hostmain._StatusBoard, "show",
                   lambda self, title, detail, hint="": shown.append(detail))
    _run_main(box, _Vault([VaultError("HTTP 500 from /api/sync")]))
    assert any("HTTP 500 from /api/sync" in d for d in shown)
    assert not any("rejected" in d.lower() for d in shown)


def test_unsealed_host_is_not_reported_as_a_wrong_password():
    msg = hostmain._classify_unlock_error(
        "no vault master password (host not sealed and no $SOC_VAULT_PASSWORD)", "")
    assert "sealed" in msg and "rejected" not in msg


def test_backoff_doubles_to_a_cap_and_never_overflows():
    delays = [hostmain._retry_delay(n) for n in (1, 2, 3, 4, 5, 6, 7, 10**6)]
    assert delays == [3, 6, 12, 24, 48, 60, 60, 60]


def test_backend_is_forced_non_interactive(box):
    seen = []
    vault = _Vault()
    vault.open = lambda: seen.append(os.environ["SOC_VAULT_INTERACTIVE"])
    _run_main(box, vault)
    assert seen == ["0"]


def test_wedged_attempt_exits_for_a_clean_process(box):
    box.mp.setattr(hostmain, "UNATTENDED_ATTEMPT_TIMEOUT", 1)
    release = threading.Event()
    vault = _Vault()
    vault.open = lambda: release.wait(10)
    assert _run_main(box, vault) == hostmain.EXIT_RELOAD
    release.set()


def test_sigterm_during_the_wait_exits_cleanly(box):
    def fail_then_signal():
        os.kill(os.getpid(), signal.SIGTERM)
        raise VaultError("Connection refused")
    vault = _Vault()
    vault.open = fail_then_signal
    assert _run_main(box, vault) == 0
    assert box.states[-1] == "stopping"


def test_unknown_backend_shows_the_failsafe_instead_of_crashing(box):
    def boom(**_kw):
        raise VaultError("unknown SOC_VAULT_BACKEND=x")
    box.mp.setattr(hostmain, "Vault", boom)
    assert hostmain.main() == hostmain.EXIT_RELOAD
    assert "fatal" in box.states


# --- bad config + exit code 2 --------------------------------------------- #

def test_bad_config_beats_fatal_then_exits_to_reload_never_2(box):
    t0 = time.monotonic()
    rc = _run_main(box, _Vault())
    assert rc == hostmain.EXIT_RELOAD != hostmain.EXIT_OPERATOR
    assert time.monotonic() - t0 >= 1              # stayed up for the reload period
    assert "fatal" in box.states and "running" not in box.states


def test_non_configerror_also_lands_on_the_failsafe(box):
    def boom(_v):
        raise OSError("panels.yaml: I/O error")
    assert _run_main(box, _Vault(), load=boom) == hostmain.EXIT_RELOAD


def test_dry_run_bad_config_does_not_use_2(box, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("panels: 7\n")
    box.mp.setenv("SOC_DRY_RUN", "1")
    box.mp.setenv("SOC_PANELS_FILE", str(bad))
    assert hostmain.main() == hostmain.EXIT_RELOAD


def test_main_source_has_no_literal_exit_2():
    src = open(hostmain.__file__, encoding="utf-8").read()
    assert "return 2" not in src and "exit(2)" not in src


def test_interactive_path_still_uses_the_operator_code(box):
    """The same failure with SOC_UNATTENDED unset behaves as it always did."""
    box.mp.delenv("SOC_UNATTENDED")
    assert _run_main(box, _Vault()) == hostmain.EXIT_OPERATOR == 2


def test_unlock_dialog_refuses_to_prompt_when_unattended(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_UNATTENDED", "1")
    monkeypatch.setenv("DISPLAY", ":99")
    assert hostmain._unlock_dialog("e", "u") == (None, False)


# --- the wall itself ------------------------------------------------------ #

def _host(panels=()):
    conf = config.Config(panels=list(panels), vpns=[], proxy=config.ProxyCfg(),
                         display=config.DisplayCfg(layout="windows", fullscreen=False),
                         tunnel={})
    host = hostmain.KioskHost(conf, vault=_Vault())
    host._can_systemctl_restart = lambda: False
    return host


def test_lock_and_tray_stay_out_of_the_way_at_boot(box):
    """The PIN lock must not engage by itself, and a hide-to-tray can't strand a
    wall with nobody to bring it back. (No idle auto-lock exists to honour.)"""
    box.mp.setattr(hostmain.Gtk, "main_quit", lambda: None)
    host = _host()
    locks = []
    host._locker.lock = lambda **kw: locks.append(kw)
    tray = []
    host._install_tray = lambda: tray.append(1)
    host.conf.display.layout = "single"
    box.mp.setattr("host.wall.WallWindow", lambda *a, **k: None)
    host.build_and_show()
    assert locks == [] and tray == []
    host.shutdown()
    assert host._timers == []


def test_tray_still_installs_for_a_windowed_interactive_run(box):
    box.mp.delenv("SOC_UNATTENDED")
    box.mp.setattr(hostmain.Gtk, "main_quit", lambda: None)
    host = _host()
    tray = []
    host._install_tray = lambda: tray.append(1)
    host.conf.display.layout = "single"
    box.mp.setattr("host.wall.WallWindow", lambda *a, **k: None)
    host.build_and_show()
    assert tray == [1]
    host.shutdown()


def test_unconfigured_wall_reloads_itself_instead_of_opening_settings(box):
    opened = []
    box.mp.setattr(hostmain.KioskHost, "open_config", lambda self: opened.append(1))
    box.mp.setattr(hostmain.KioskHost, "build_and_show", lambda self: None)
    loop = GLib.MainLoop()
    stopped = []
    box.mp.setattr(hostmain.Gtk, "main_quit",
                   lambda: stopped.append(1) or loop.quit())
    box.mp.setattr(hostmain.Gtk, "main", loop.run)
    assert _run_main(box, _Vault(), load=lambda v: hostmain._default_template()) == 0
    assert stopped == [1] and opened == []


def test_unconfigured_interactive_wall_opens_settings(box):
    box.mp.delenv("SOC_UNATTENDED")
    opened = []
    loop = GLib.MainLoop()
    box.mp.setattr(hostmain.KioskHost, "open_config",
                   lambda self: opened.append(1) or self.shutdown())
    box.mp.setattr(hostmain.KioskHost, "build_and_show", lambda self: None)
    box.mp.setattr(hostmain.Gtk, "main_quit", loop.quit)
    box.mp.setattr(hostmain.Gtk, "main", loop.run)
    assert _run_main(box, _Vault(), load=lambda v: hostmain._default_template()) == 0
    assert opened == [1]


def test_hourly_resync_runs_off_the_main_thread_and_survives_failure(box):
    host = _host()
    vault = _Vault([VaultError("Connection refused")])
    host.vault = vault
    assert host._resync_vault() is True            # keeps its timer
    deadline = time.time() + 5
    while not vault.opens and time.time() < deadline:
        time.sleep(0.01)
    assert vault.threads[0] is not threading.main_thread()


def test_modal_dismisses_itself_when_unattended(box):
    box.mp.setattr(wall, "MODAL_TIMEOUT_SEC", 1)

    class Dlg:
        def __init__(self):
            self.loop = GLib.MainLoop()
            self.rc = None

        def run(self):
            self.loop.run()
            return self.rc

        def response(self, rc):
            self.rc = rc
            self.loop.quit()

    dlg = Dlg()
    assert wall._run_bounded(dlg) == Gtk.ResponseType.DELETE_EVENT


def test_modal_waits_for_the_operator_when_interactive(box):
    box.mp.delenv("SOC_UNATTENDED")
    armed = []
    box.mp.setattr(wall.GLib, "timeout_add_seconds", lambda *a: armed.append(a))
    assert wall._run_bounded(SimpleNamespace(run=lambda: "rc")) == "rc"
    assert armed == []


@pytest.mark.skipif(not hostmain.Gdk.Display.get_default(), reason="needs a display")
def test_status_board_paints_and_updates_in_place(box):
    box.mp.setenv("DISPLAY", os.environ.get("DISPLAY") or ":0")
    box.mp.setenv("SOC_WINDOW_MODE", "window")
    board = hostmain._StatusBoard()
    board.show("Waiting", "first", "hint")
    win = board._win
    assert win is not None
    board.show("Starting", "second", "hint 2")
    assert board._win is win                       # never a re-pop
    assert board._detail.get_text() == "second"
    assert board._title.get_text() == "Starting"
    board.close()
    assert board._win is None


# --- recovery paths that used to end at a human --------------------------- #

class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_login_rearm_waits_then_doubles_to_a_cap():
    clock = _Clock()
    r = inject.LoginRearm(initial=300, maximum=1000, clock=clock)
    assert r.due() is False                        # first call starts the wait
    clock.t = 299
    assert r.due() is False
    clock.t = 300
    assert r.due() is True                         # refilled
    assert r.due() is False                        # next wait: 600
    clock.t += 599
    assert r.due() is False
    clock.t += 1
    assert r.due() is True
    r.due()
    clock.t += 999
    assert r.due() is False
    clock.t += 1
    assert r.due() is True                         # capped at 1000


def test_login_rearm_reset_returns_to_the_short_wait():
    clock = _Clock()
    r = inject.LoginRearm(initial=10, maximum=100, clock=clock)
    r.due()
    clock.t = 10
    assert r.due()
    r.reset()
    r.due()
    clock.t += 10
    assert r.due() is True


def _webkit_login_stub(monkeypatch, clock):
    s = object.__new__(webkit_panel.WebKitPanel)
    s.panel = SimpleNamespace(id="p1")
    s.log = lambda *_a: None
    s._login_attempts = webkit_panel.MAX_LOGIN_ATTEMPTS        # budget spent
    s._login_misses = 0
    s._login_inflight = False
    s._login_rearm = inject.LoginRearm(initial=60, clock=clock)
    s.prompts, s.injected = [], []
    s._evaluate = lambda js, cb=None: s.prompts.append(js) if cb is None \
        else s.injected.append(js)
    s.on_need_login = lambda _p: {"user": "u", "pass": "p"}
    return s


def test_webkit_exhausted_login_rearms_unattended(box):
    clock = _Clock()
    s = _webkit_login_stub(box.mp, clock)
    s._do_login()                                  # budget spent: prompt, start wait
    assert s.injected == [] and len(s.prompts) == 1
    clock.t = 60
    s._do_login()
    assert len(s.injected) == 1                    # tried again, with no human
    assert s._login_attempts == 0


def test_webkit_exhausted_login_stays_put_when_interactive(box):
    box.mp.delenv("SOC_UNATTENDED")
    clock = _Clock()
    s = _webkit_login_stub(box.mp, clock)
    s._do_login()
    clock.t = 10**6
    s._do_login()
    assert s.injected == []


class _AuthRequest:
    def __init__(self):
        self.cancelled = 0

    def is_for_proxy(self):
        return True

    def get_host(self):
        return "proxy"

    def get_port(self):
        return 3128

    def cancel(self):
        self.cancelled += 1


def _proxy_stub():
    s = object.__new__(webkit_panel.WebKitPanel)
    s.panel = SimpleNamespace(id="p1")
    s.log = lambda *_a: None
    s.proxy = SimpleNamespace(vault_item="item")
    s.proxy_creds = lambda: None
    s.status = SimpleNamespace(update=lambda *a, **k: None)
    s._proxy_auth_attempts = webkit_panel.PROXY_AUTH_MAX_ATTEMPTS
    s._proxy_retry_delay = webkit_panel.PROXY_RETRY_INITIAL
    s._retry_id = 0
    s._retry_pending = False
    s.retries = []
    s._cancel_retry = lambda: None
    s._schedule_retry = lambda d: s.retries.append(d)
    return s


def test_rejected_proxy_password_retries_slowly_when_unattended(box):
    s = _proxy_stub()
    assert s._on_authenticate(None, _AuthRequest()) is True
    assert s.retries == [webkit_panel.PROXY_RETRY_INITIAL]
    assert s._proxy_auth_attempts == 0             # the retry may authenticate
    assert s._proxy_retry_delay == webkit_panel.PROXY_RETRY_INITIAL * 2


def test_rejected_proxy_password_gives_up_when_interactive(box):
    box.mp.delenv("SOC_UNATTENDED")
    s = _proxy_stub()
    s._on_authenticate(None, _AuthRequest())
    assert s.retries == []


def _failing_chromium(box, max_respawns):
    box.mp.setattr(chromium_panel, "MAX_RESPAWNS", max_respawns)
    box.mp.setattr(chromium_panel, "PARK_RETRY_SEC", 0.01)

    class P:
        id = "p1"
        effective_url = "http://10.0.0.1/"
        selectors = {}
        login_marker = ""
        unblock = ()
        allow = ()

    logs = []
    panel = chromium_panel.ChromiumPanel(P(), lambda _p: None, logs.append,
                                         cdp_port=9333, poll_interval=0.001)
    calls = {"n": 0}

    def boom():
        calls["n"] += 1
        raise RuntimeError("no chromium here")
    panel._spawn = boom
    real_wait = panel._stop.wait
    panel._stop.wait = lambda _t=None: real_wait(0.001)
    return panel, calls


def _run_loop_until(panel, done):
    t = threading.Thread(target=panel._control_loop, daemon=True)
    t.start()
    deadline = time.time() + 5
    while not done() and time.time() < deadline:
        time.sleep(0.005)
    panel._stop.set()
    t.join(timeout=2)


def test_parked_chromium_rearms_itself_when_unattended(box):
    panel, calls = _failing_chromium(box, 2)
    _run_loop_until(panel, lambda: calls["n"] > 4)
    assert calls["n"] > 4                          # parked, re-armed, tried again


def test_parked_chromium_stays_parked_when_interactive(box):
    box.mp.delenv("SOC_UNATTENDED")
    panel, calls = _failing_chromium(box, 2)
    _run_loop_until(panel, lambda: panel._parked)
    time.sleep(0.05)
    assert panel._parked and calls["n"] == 2


class _ErrCDP:
    ws = object()

    def __init__(self):
        self.navigated = []

    def evaluate(self, _expr, return_value=False):
        return {"e": True} if return_value else None

    def rpc(self, method, params=None):
        self.navigated.append((method, params))
        return {}

    def close(self):
        pass


def _error_page_panel():
    class P:
        id = "p1"
        effective_url = "http://10.0.0.1/"
        selectors = {}
        login_marker = ""
        unblock = ()
        allow = ()

    panel = chromium_panel.ChromiumPanel(P(), lambda _p: None, lambda *_a: None,
                                         cdp_port=9333)
    panel.proc = SimpleNamespace(poll=lambda: None, terminate=lambda: None,
                                 wait=lambda timeout=None: None, pid=1)
    panel.cdp = _ErrCDP()
    panel._nav_gate = False
    return panel


def test_chromium_error_page_is_retried_when_unattended(box):
    box.mp.setattr(chromium_panel, "RESPAWN_INITIAL", 0.0)
    panel = _error_page_panel()
    panel._reload_delay = 0.0
    n = {"polls": 0}

    def wait(_t=None):
        n["polls"] += 1
        if n["polls"] >= 3:
            panel._stop.set()
        return False
    panel._stop.wait = wait
    panel._control_loop()
    assert ("Page.navigate", {"url": "http://10.0.0.1/"}) in panel.cdp.navigated


def test_chromium_error_page_is_left_alone_when_interactive(box):
    box.mp.delenv("SOC_UNATTENDED")
    panel = _error_page_panel()
    panel._reload_delay = 0.0
    n = {"polls": 0}

    def wait(_t=None):
        n["polls"] += 1
        if n["polls"] >= 3:
            panel._stop.set()
        return False
    panel._stop.wait = wait
    panel._control_loop()
    assert panel.cdp.navigated == []


def test_orphan_chromium_holding_the_profile_is_killed(box, tmp_path):
    """A host SIGKILLed by the heartbeat watchdog leaves its Chromium behind, and a
    new spawn would just hand off to it through the singleton lock."""
    import subprocess
    import sys
    profile = str(tmp_path / "profile")
    os.makedirs(profile)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)",
                              f"--user-data-dir={profile}"])
    try:
        os.symlink(f"host-{child.pid}", os.path.join(profile, "SingletonLock"))
        panel = _error_page_panel()
        panel._reap_orphan(profile)
        assert child.wait(timeout=5) == -signal.SIGTERM
    finally:
        child.kill()
        child.wait()


def test_orphan_check_never_kills_a_recycled_pid(box, tmp_path):
    import subprocess
    import sys
    profile = str(tmp_path / "profile")
    os.makedirs(profile)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        os.symlink(f"host-{child.pid}", os.path.join(profile, "SingletonLock"))
        _error_page_panel()._reap_orphan(profile)
        assert child.poll() is None                # not ours: left alone
    finally:
        child.kill()
        child.wait()


# --- config cache --------------------------------------------------------- #

def test_bad_vault_note_does_not_poison_last_known_good(box, monkeypatch):
    """A note that fails validation must not overwrite the good cached config."""
    monkeypatch.setenv("SOC_VAULT_BACKEND", "litebw")
    monkeypatch.delenv("SOC_CONFIG_FROM_VAULT", raising=False)
    hostmain._cache_config("display: {auto: true}\npanels: []\n")
    good = hostmain._read_cached_config()
    v = SimpleNamespace(notes=lambda _item: "panels: 7\n")
    with pytest.raises(config.ConfigError):
        hostmain.load_config(v)
    assert hostmain._read_cached_config() == good


def test_perf_unattended_spellings(monkeypatch):
    for on in ("1", "true", "YES", " on "):
        monkeypatch.setenv("SOC_UNATTENDED", on)
        assert perf.unattended() is True
    for off in ("0", "", "no", "garbage"):
        monkeypatch.setenv("SOC_UNATTENDED", off)
        assert perf.unattended() is False
    monkeypatch.delenv("SOC_UNATTENDED")
    assert perf.unattended() is False
