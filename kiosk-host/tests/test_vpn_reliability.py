"""Reliability regressions for the VPN supervisor (an unattended wall, for months).

Each test pins one concrete failure. They use real child processes wherever the
bug depends on process behaviour: a mock would never have shown that closing a
pipe blocks, or that a bash TERM trap waits for its foreground pipeline. No test
starts a VPN client or touches the network, and anything that could hang runs
under a time limit, so a regression fails rather than wedging the suite.
"""
import errno
import json
import os
import shutil
import signal
import subprocess
import threading
import time

import pytest

from host import fortivpn, vpndrivers, vpnmanager, vpnstatus
from host.vault import VaultError

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class _ScriptDriver(vpndrivers.FortinetDriver):
    """Runs an arbitrary argv through the real spawn path, down the branch that
    has no credentials, and classifies its output like openfortivpn."""
    kind = "openvpn"
    binary = "fake-vpn"

    def __init__(self, argv):
        self.argv = argv

    def needs_creds(self, vpn):
        return False

    def build_cmd(self, vpn, mgmt_socket=None):
        return self.argv


def _sup(argv=("true",), vpn=None, logs=None):
    log = logs.append if logs is not None else (lambda m: None)
    return fortivpn.Supervisor(vpn if vpn is not None else {"type": "openvpn"}, "",
                               log=log, driver=_ScriptDriver(list(argv)))


def _bounded(fn, seconds=8.0):
    """Run fn on a daemon thread; fail, rather than hang, if it does not return.
    Its exception is re-raised here: otherwise a call that blew up would pass."""
    out = {}

    def body():
        try:
            out["result"] = fn()
        except BaseException as e:      # noqa: BLE001
            out["error"] = e

    t = threading.Thread(target=body, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), f"{getattr(fn, '__name__', fn)} still blocked after {seconds}s"
    if "error" in out:
        raise out["error"]
    return out.get("result")


def _alive(pid: int) -> bool:
    """True if pid is running; a zombie has already exited, so it does not count."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _kill_quietly(pid: int):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _dead_pid() -> int:
    p = subprocess.Popen(["true"])
    p.wait()
    return p.pid


def _wait_for_pid(path, seconds=5.0) -> int:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists() and path.read_text().strip():
            return int(path.read_text().strip())
        time.sleep(0.02)
    raise AssertionError(f"{path} never appeared")


# --------------------------------------------------------------------------- #
# Child processes: orphans, zombies, blocked pipes
# --------------------------------------------------------------------------- #
def test_retire_returns_while_a_grandchild_holds_the_pipe(tmp_path):
    # close() on a pipe another thread is reading blocks until EOF, so a leftover
    # grandchild used to wedge the supervisor thread here for good.
    pidfile = tmp_path / "pid"
    sup = _sup(["sh", "-c", f"sleep 30 & echo $! > {pidfile}; exit 0"])
    sup._spawn(None)
    sup.child.wait(timeout=5)
    grandchild = _wait_for_pid(pidfile)
    try:
        _bounded(sup._retire_attempt_threads)
        assert not _alive(grandchild), "the attempt's helper outlived it"
    finally:
        _kill_quietly(grandchild)


@pytest.mark.skipif(not shutil.which("setsid"), reason="needs setsid(1)")
def test_retire_frees_thread_and_fd_when_a_daemon_escaped_the_group(tmp_path):
    # A helper that called setsid is out of reach of the group kill and keeps the
    # pipe open. Without this the reader would be stranded for each such attempt.
    pidfile = tmp_path / "pid"
    sup = _sup(["sh", "-c", f"setsid sleep 30 & echo $! > {pidfile}; exit 0"])
    sup._spawn(None)
    child, reader = sup.child, sup._reader_thread
    child.wait(timeout=5)
    escaped = _wait_for_pid(pidfile)
    try:
        _bounded(sup._retire_attempt_threads)
        assert not reader.is_alive()
        assert child.stdout.closed
    finally:
        _kill_quietly(escaped)


def test_term_reaches_the_foreground_pipeline_of_a_bash_wrapper(tmp_path):
    # svpn-connect.sh shape: bash cannot run its TERM trap until the foreground
    # pipeline ends. Signalling bash alone waited out the grace, SIGKILLed bash
    # and orphaned the backend, leaving the tunnel up.
    pidfile = tmp_path / "pid"
    script = tmp_path / "wrapper.sh"
    script.write_text("#!/usr/bin/env bash\n"
                      "trap 'exit 0' EXIT INT TERM\n"
                      f"sh -c 'echo $$ > {pidfile}; exec sleep 30' | cat\n")
    sup = _sup(["bash", str(script)])
    sup._spawn(None)
    backend = _wait_for_pid(pidfile)
    try:
        _bounded(lambda: sup._terminate_child(grace=4.0))
        assert sup.child.poll() is not None
        assert not _alive(backend), "backend orphaned with the tunnel still up"
        sup._retire_attempt_threads()
    finally:
        _kill_quietly(backend)


class _Unkillable:
    """A child stuck in uninterruptible I/O. Its pid is past any real pid_max."""
    pid = 2 ** 22 + 1
    stdout = None

    def poll(self):
        return None

    def wait(self, timeout=None):
        raise subprocess.TimeoutExpired(["openfortivpn", "--otp=123456"], timeout)

    def terminate(self):
        pass

    def kill(self):
        pass


def test_unkillable_child_neither_raises_nor_logs_its_argv():
    # The second wait raised TimeoutExpired, which is not an OSError, so it escaped
    # into a handler that logged it with repr(): argv included, so the OTP too.
    logs = []
    sup = _sup(logs=logs)
    sup.child = _Unkillable()
    sup._terminate_child(grace=0)
    assert any("SIGKILL" in m for m in logs)
    assert not any("123456" in m for m in logs)


def test_spawn_refuses_to_start_beside_a_child_it_cannot_kill():
    # Two clients would fight over the same routes and tunnel device.
    sup = _sup()
    sup.child = _Unkillable()
    with pytest.raises(OSError) as e:
        sup._spawn(None)
    assert e.value.errno == errno.EBUSY


def test_reader_survives_non_utf8_output_and_keeps_draining():
    # A strict decoder died on the first bad byte (H3C gateways speak GBK). Nothing
    # drained the pipe after that, so the child blocked on write with the tunnel
    # apparently fine. 200 KB is well past the 64 KB pipe buffer.
    sup = _sup(["sh", "-c",
                r"printf 'bad \377\376 bytes\n';"
                r" head -c 200000 /dev/zero | tr '\0' x;"
                r" printf '\nTunnel is up and running\n'"])
    sup._spawn(None)
    try:
        assert sup.child.wait(timeout=8) == 0
        sup._reader_thread.join(timeout=5)
        assert sup._tunnel_up, "the line after the bad byte was never classified"
    finally:
        sup._terminate_child(grace=1)
        sup._retire_attempt_threads()


def test_flapping_does_not_accumulate_threads_or_fds():
    sup = _sup(["true"])
    sup._spawn(None)
    sup.child.wait(timeout=5)
    sup._retire_attempt_threads()
    threads = threading.active_count()
    fds = len(os.listdir("/proc/self/fd"))
    for _ in range(15):
        sup._spawn(None)
        sup.child.wait(timeout=5)
    sup._retire_attempt_threads()
    assert threading.active_count() <= threads
    assert len(os.listdir("/proc/self/fd")) <= fds


def test_child_does_not_inherit_the_vault_master(monkeypatch):
    # soc.env is exported wholesale, and up-scripts and pppd inherit the child env.
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "hunter2")
    logs = []
    sup = _sup(["sh", "-c", 'echo "seen=[${SOC_VAULT_PASSWORD:-}]"'], logs=logs)
    sup._spawn(None)
    sup.child.wait(timeout=5)
    sup._reader_thread.join(timeout=5)
    assert any("seen=[]" in m for m in logs), logs
    assert not any("hunter2" in m for m in logs)


# --------------------------------------------------------------------------- #
# Hung attempts
# --------------------------------------------------------------------------- #
def test_child_that_never_comes_up_is_restarted():
    # Health checks only start at UP, so a child hung before it (a stalled gateway,
    # a passphrase prompt we cannot answer) was waited on forever.
    sup = _sup(["sleep", "30"])
    sup.connect_timeout = 0.2
    sup._looks_connected = lambda: False
    sup._spawn(None)
    _bounded(sup._watch_child)
    assert sup.child.poll() is not None
    sup._retire_attempt_threads()


def test_connect_timeout_spares_a_tunnel_whose_up_line_was_missed():
    # A client whose log wording changed must not be killed for never saying "up".
    sup = _sup(["sleep", "30"])
    sup.connect_timeout = 0.1
    sup._looks_connected = lambda: True
    sup._spawn(None)
    watcher = threading.Thread(target=sup._watch_child, daemon=True)
    watcher.start()
    try:
        time.sleep(1.5)
        assert sup.child.poll() is None
    finally:
        sup.stop_event.set()
        watcher.join(timeout=8)
        sup._retire_attempt_threads()


def test_mgmt_thread_stands_down_once_its_child_is_gone(tmp_path):
    # The mgmt path is reused by the next attempt. A thread still polling for its
    # dead openvpn's socket used to wake up 30s later, flag the fresh attempt as
    # unreachable and terminate its healthy child.
    dead = subprocess.Popen(["true"])
    dead.wait()
    current = subprocess.Popen(["sleep", "30"], start_new_session=True)
    sup = _sup()
    sup.child = current
    try:
        _bounded(lambda: sup._openvpn_mgmt(str(tmp_path / "none.sock"), ("u", "p"), dead))
        assert current.poll() is None
        assert not sup._mgmt_unreachable
        assert not sup._saw
    finally:
        current.kill()
        current.wait()


# --------------------------------------------------------------------------- #
# Keys on disk
# --------------------------------------------------------------------------- #
class _NotesVault:
    def __init__(self, notes):
        self._notes = notes

    def notes(self, _item):
        return self._notes


def _vault_sup(cls, vpn, notes, monkeypatch, logs=None):
    log = logs.append if logs is not None else (lambda m: None)
    sup = cls(vpn, "", log=log, driver=vpndrivers.get_driver(vpn))
    monkeypatch.setattr(sup, "_open_vault", lambda: _NotesVault(notes))
    return sup


def _ovpn(name="a"):
    return {"type": "openvpn", "name": name, "config_from_vault": True, "vault_item": "I"}


def test_two_openvpn_supervisors_share_no_key_or_socket(tmp_path, monkeypatch):
    # Supervisors are threads, so a pid-scoped name is shared by all of them: B
    # overwrote and deleted A's keys, and A's password could reach B's openvpn.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    a = _vault_sup(fortivpn.Supervisor, _ovpn("a"), "KEY-A", monkeypatch)
    b = _vault_sup(fortivpn.Supervisor, _ovpn("b"), "KEY-B", monkeypatch)
    assert a._materialize_config() and b._materialize_config()
    assert a._materialized != b._materialized
    assert a._mgmt_path() != b._mgmt_path()
    b._cleanup_materialized()
    with open(a._materialized, encoding="utf-8") as fh:
        assert fh.read() == "KEY-A\n"
    a._cleanup_materialized()


def test_scratch_dir_is_removed_with_its_contents(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    sup = _vault_sup(fortivpn.Supervisor, _ovpn(), "KEY", monkeypatch)
    assert sup._materialize_config()
    scratch = os.path.dirname(sup._materialized)
    assert (os.stat(scratch).st_mode & 0o777) == 0o700
    sup._cleanup_materialized()
    assert not os.path.exists(scratch)


def test_sweep_clears_keys_left_by_a_dead_supervisor(tmp_path):
    # SIGKILL, OOM and systemd's watchdog abort run no finally: each such exit left
    # a private key in the runtime dir until reboot.
    dead = _dead_pid()
    d = tmp_path / "soc-vpn"
    d.mkdir()
    orphan = d / f"vpn-{dead}-1"
    orphan.mkdir()
    (orphan / "wg0.conf").write_text("PrivateKey=SECRET\n")
    (d / f"openvpn-{dead}.ovpn").write_text("PRIVATE KEY\n")
    (d / f"openvpn-{dead}.sock").write_text("")
    live = d / f"vpn-{os.getppid()}-1"
    live.mkdir()
    (live / "wg0.conf").write_text("in use\n")
    (d / "unrelated.txt").write_text("keep\n")

    _sup()._sweep_orphan_mgmt(str(d))

    assert sorted(os.listdir(d)) == sorted([live.name, "unrelated.txt"])
    assert (live / "wg0.conf").exists()


def test_sweep_runs_even_when_this_run_uses_no_vault_config(tmp_path, monkeypatch):
    # It used to run only on the mgmt-socket path, so a file-based profile never
    # cleared what an earlier crash had left.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(fortivpn.shutil, "which", lambda _b: "/usr/bin/x")
    dead = _dead_pid()
    d = tmp_path / "soc-vpn"
    d.mkdir()
    leftover = d / f"openvpn-{dead}.ovpn"
    leftover.write_text("PRIVATE KEY\n")
    sup = _sup()
    monkeypatch.setattr(sup, "_run_loop", lambda: 0)
    _bounded(sup.run)
    assert not leftover.exists()


def test_interface_key_removed_after_down_when_the_loop_crashes(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(fortivpn.shutil, "which", lambda _b: "/usr/bin/wg-quick")
    vpn = {"type": "wireguard", "config": "wg0", "config_from_vault": True,
           "vault_item": "I"}
    sup = _vault_sup(fortivpn.Supervisor, vpn, "[Interface]\nPrivateKey=K\n", monkeypatch)
    seen = {}

    def oneshot(_cmd):
        seen["key_present_for_down"] = os.path.exists(sup._materialized or "")
        return 0, ""

    def boom():
        raise RuntimeError("loop blew up")

    monkeypatch.setattr(sup, "_run_oneshot", oneshot)
    monkeypatch.setattr(sup, "_run_interface_loop", boom)
    with pytest.raises(RuntimeError):
        _bounded(sup.run)
    assert seen["key_present_for_down"], "wg-quick down needs the .conf"
    assert sup._materialized is None
    assert not os.path.exists(str(tmp_path / "soc-vpn" / f"vpn-{os.getpid()}-{sup._instance}"))


def test_torn_config_write_leaves_no_partial_key(tmp_path, monkeypatch):
    # The path was only recorded after a successful write, so ENOSPC on the /run
    # tmpfs left a partial key that nothing would ever remove.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    sup = _vault_sup(fortivpn.Supervisor, _ovpn(), "PRIVATE KEY", monkeypatch)

    def enospc(fd, *_a, **_k):
        os.close(fd)
        raise OSError(errno.ENOSPC, "no space")

    monkeypatch.setattr(fortivpn.os, "fdopen", enospc)
    assert sup._materialize_config() is False
    assert sup._materialized is None
    assert not [f for _r, _d, files in os.walk(tmp_path) for f in files]


def test_failed_catch_all_rewrite_leaves_no_key_behind(tmp_path, monkeypatch):
    # The guard refuses the tunnel, but the unstripped key file used to stay on
    # disk through the whole idle() that followed, and past every exit from it.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(fortivpn.shutil, "which", lambda _b: "/usr/bin/wg-quick")
    vpn = {"type": "wireguard", "name": "w", "config": "wg0", "vault_item": "I",
           "config_from_vault": True, "_soc_split_tunnel": True}
    conf = "[Interface]\nPrivateKey=K\n[Peer]\nAllowedIPs = 0.0.0.0/0\n"
    sup = _vault_sup(vpnmanager._GuardedSupervisor, vpn, conf, monkeypatch)
    monkeypatch.setattr(sup, "_run_oneshot", lambda _c: (0, ""))
    monkeypatch.setattr(sup, "_run_interface_loop", lambda: 0)
    monkeypatch.setattr(vpnmanager.os, "replace", lambda *_a: (_ for _ in ()).throw(
        OSError(errno.EIO, "io error")))
    leaks = []

    def sleep(_seconds):
        leaks.extend(f for _r, _d, files in os.walk(tmp_path) for f in files)
        sup.stop_event.set()

    monkeypatch.setattr(sup, "_sleep", sleep)
    _bounded(sup.run)
    assert sup.stop_event.is_set(), "the failed rewrite was treated as a success"
    assert leaks == [], "the key sat on disk through the retry wait"


def test_guard_fails_closed_when_it_cannot_read_the_conf(tmp_path, monkeypatch):
    # Could not check must not mean bring up a possibly catch-all tunnel.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    vpn = {"type": "wireguard", "name": "w", "config": "wg0", "vault_item": "I",
           "config_from_vault": True, "_soc_split_tunnel": True}
    sup = _vault_sup(vpnmanager._GuardedSupervisor, vpn, "[Peer]\n", monkeypatch)
    real_open = open

    def deny(path, *a, **k):
        if str(path).endswith("wg0.conf"):
            raise OSError(errno.EIO, "io error")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", deny)
    assert sup._materialize_config() is False
    sup._cleanup_materialized()


@pytest.mark.parametrize("cidr", ["::0/0", "0::/0", "0:0::/0", "10.0.0.1/0"])
def test_guard_strips_every_spelling_of_a_catch_all(tmp_path, monkeypatch, cidr):
    # wg-quick routes these as the whole address space too.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    vpn = {"type": "wireguard", "name": "w", "config": "wg0", "vault_item": "I",
           "config_from_vault": True, "_soc_split_tunnel": True}
    conf = f"[Peer]\nAllowedIPs = {cidr}, 10.50.0.0/16\n"
    sup = _vault_sup(vpnmanager._GuardedSupervisor, vpn, conf, monkeypatch)
    assert sup._materialize_config() is True
    with open(sup._materialized, encoding="utf-8") as fh:
        body = fh.read()
    assert cidr not in body and "10.50.0.0/16" in body
    sup._cleanup_materialized()


def test_manager_stop_cleans_up_for_a_wedged_supervisor(tmp_path):
    # Its daemon thread dies with the process, so its own teardown never runs. The
    # key would stay on disk and the child would be orphaned.
    mgr = vpnmanager.VpnManager([], "", log=lambda m: None)
    sup = _sup(["sleep", "30"])
    key = tmp_path / "wg0.conf"
    key.write_text("PrivateKey=K\n")
    sup._materialized = str(key)
    sup._spawn(None)
    stuck = threading.Thread(target=threading.Event().wait, daemon=True)  # as if in the vault
    stuck.start()
    mgr._supers["w"], mgr._threads["w"] = sup, stuck
    _bounded(lambda: mgr.stop(grace=0.1))
    assert not key.exists()
    assert sup.child.poll() is not None


# --------------------------------------------------------------------------- #
# Backoff
# --------------------------------------------------------------------------- #
def _run_attempts(sup, monkeypatch, up_for):
    """Drive the real _run_loop through attempts that stay up for up_for[i]
    seconds, returning the delays it chose."""
    attempts = iter(up_for)
    delays = []

    def spawn(_creds):
        sup._saw = set()
        sup._mgmt_unreachable = False
        sup._up_since = time.monotonic() - next(attempts)

    def sleep(seconds):
        delays.append(seconds)
        if len(delays) == len(up_for):
            sup.stop_event.set()

    monkeypatch.setattr(sup, "_spawn", spawn)
    monkeypatch.setattr(sup, "_watch_child", lambda: None)
    monkeypatch.setattr(sup, "_sleep", sleep)
    _bounded(sup._run_loop)
    return delays


def test_short_lived_tunnel_does_not_reset_the_backoff(monkeypatch):
    # Reset at the 5s floor, a link that survived 10s per try reconnected at the
    # floor forever: the backoff never climbed.
    assert _run_attempts(_sup(), monkeypatch, [10, 10, 10]) == [5.0, 10.0, 20.0]


def test_stable_tunnel_does_reset_the_backoff(monkeypatch):
    assert _run_attempts(_sup(), monkeypatch, [10, 10, 600]) == [5.0, 10.0, 5.0]


def test_wg_quick_up_alone_does_not_reset_the_backoff(monkeypatch):
    # `wg-quick up` succeeds without contacting the peer, so a dead peer cycled the
    # interface forever with no backoff at all.
    vpn = {"type": "wireguard", "config": "wg0", "health_check_interval": 1,
           "health_check_failures": 1}
    sup = fortivpn.Supervisor(vpn, "", log=lambda m: None)
    delays = []

    def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 2:
            sup.stop_event.set()

    monkeypatch.setattr(sup, "_wg_is_up", lambda _i: False)
    monkeypatch.setattr(sup, "_run_oneshot", lambda _c: (0, ""))
    monkeypatch.setattr(sup, "_wg_handshake_ok", lambda _i: False)
    monkeypatch.setattr(sup, "_sleep", sleep)
    _bounded(sup._run_interface_loop)
    assert delays == [5.0, 10.0]


def test_healthy_wireguard_check_resets_the_backoff(monkeypatch):
    vpn = {"type": "wireguard", "config": "wg0", "health_check_interval": 1}
    sup = fortivpn.Supervisor(vpn, "", log=lambda m: None)
    sup.backoff.next()
    sup.backoff.next()

    def healthy(_iface):
        sup.stop_event.set()
        return True

    monkeypatch.setattr(sup, "_wg_is_up", lambda _i: True)
    monkeypatch.setattr(sup, "_run_oneshot", lambda _c: (0, ""))
    monkeypatch.setattr(sup, "_wg_handshake_ok", healthy)
    _bounded(sup._run_interface_loop)
    assert sup.backoff.next() == 5.0


def test_vault_outage_backs_off_instead_of_rerunning_scrypt_every_3s(monkeypatch):
    sup = _sup(vpn={"type": "openvpn", "vault_item": "I"})
    delays = []

    def no_vault():
        raise VaultError("down")

    def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 5:
            sup.stop_event.set()

    monkeypatch.setattr(sup, "_open_vault", no_vault)
    monkeypatch.setattr(sup, "_sleep", sleep)
    assert _bounded(lambda: sup._resolve_creds(3600.0)) is None
    assert delays == [3.0, 6.0, 12.0, 24.0, 48.0]


def test_vault_recovery_resets_its_backoff(monkeypatch):
    sup = _sup(vpn={"type": "openvpn", "vault_item": "I"})
    sup._vault_retry.next()
    sup._vault_retry.next()

    class Good:
        def creds(self, _item):
            return {"user": "u", "pass": "p"}

    monkeypatch.setattr(sup, "_open_vault", Good)
    assert sup._resolve_creds(1.0) == ("u", "p")
    assert sup._vault_retry.next() == 3.0


def test_zero_retry_delay_is_clamped_so_a_bad_password_cannot_spin(monkeypatch):
    monkeypatch.setenv("SOC_VPN_AUTH_RETRY_DELAY", "0")
    monkeypatch.setenv("SOC_VPN_CERT_RETRY_DELAY", "0")
    sup = _sup()
    assert sup.auth_delay >= 1.0 and sup.cert_delay >= 1.0 and sup._slow_retry >= 1.0


# --------------------------------------------------------------------------- #
# Recovering by itself
# --------------------------------------------------------------------------- #
def test_vault_config_outage_retries_rather_than_idling_forever(monkeypatch):
    # Past SOC_READY_TIMEOUT this went to idle(): an outage became permanent, with
    # the service looking healthy, and nobody is there to restart it.
    monkeypatch.setattr(fortivpn.shutil, "which", lambda _b: "/usr/bin/x")
    sup = _sup()
    outcomes = iter([False, False, True])
    ran = []
    monkeypatch.setattr(sup, "_materialize_config", lambda: next(outcomes))
    monkeypatch.setattr(sup, "_sleep", lambda _s: None)
    monkeypatch.setattr(sup, "_run_loop", lambda: ran.append(1) or 0)
    try:
        _bounded(sup.run)
    finally:
        sup.stop_event.set()            # releases idle() on the old behaviour
    assert ran == [1]


def _crashing_sup(crashes):
    class Crashes:
        def __init__(self):
            self.stop_event = threading.Event()
            self.runs = 0
            self.delays = []

        def run(self):
            self.runs += 1
            if self.runs > crashes:
                self.stop_event.set()
                return 0
            raise RuntimeError("deterministic bug")

        def _sleep(self, seconds):
            self.delays.append(seconds)

    return Crashes()


def test_crashing_supervisor_is_never_abandoned():
    # The old cap ended the thread after 3 crashes, leaving the VPN offline until a
    # person restarted the service. Crashes months apart counted towards it too.
    mgr = vpnmanager.VpnManager([], "", log=lambda m: None)
    sup = _crashing_sup(7)
    _bounded(lambda: mgr._supervised_run("v", sup, lambda m: None))
    assert sup.runs == 8
    assert sup.delays == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0, 60.0]


def test_crash_after_a_long_healthy_run_starts_the_backoff_again(monkeypatch):
    mgr = vpnmanager.VpnManager([], "", log=lambda m: None)
    mgr._RELAUNCH_STABLE = 0.0          # every run counts as a long one
    sup = _crashing_sup(3)
    _bounded(lambda: mgr._supervised_run("v", sup, lambda m: None))
    assert sup.delays == [5.0, 5.0, 5.0]


def test_stop_during_relaunch_wait_does_not_resurrect():
    mgr = vpnmanager.VpnManager([], "", log=lambda m: None)
    sup = _crashing_sup(99)
    sup._sleep = lambda _s: sup.stop_event.set()
    _bounded(lambda: mgr._supervised_run("v", sup, lambda m: None))
    assert sup.runs == 1


# --------------------------------------------------------------------------- #
# The systemd watchdog
# --------------------------------------------------------------------------- #
class _FakeManager:
    def __init__(self, stalled=()):
        self.stalled_names = list(stalled)
        self.polls = 0

    def stalled(self):
        return self.stalled_names

    def states(self, on_each=None):
        self.polls += 1
        if on_each:
            on_each()
        return {"a": vpnstatus.STATE_ONLINE}


class _Ticks:
    """A stop event that ends _supervise after `n` passes, with no real waiting."""

    def __init__(self, n):
        self.n = n

    def is_set(self):
        return self.n <= 0

    def wait(self, _timeout=None):
        self.n -= 1


def _notifications(monkeypatch, mgr, ticks=5):
    sent = []
    monkeypatch.setenv("WATCHDOG_USEC", "90000000")
    monkeypatch.setattr(fortivpn, "sd_notify", sent.append)
    logs = []
    fortivpn._supervise(mgr, _Ticks(ticks), fortivpn.SdWatchdog(), logs.append)
    return sent, logs


def test_watchdog_flows_while_every_supervisor_is_healthy(monkeypatch):
    sent, _logs = _notifications(monkeypatch, _FakeManager())
    assert "WATCHDOG=1" in sent


def test_watchdog_is_withheld_while_a_supervisor_is_wedged(monkeypatch):
    # The loop pinged unconditionally, so a wedged supervisor was never restarted.
    sent, logs = _notifications(monkeypatch, _FakeManager(stalled=["hq"]))
    assert "WATCHDOG=1" not in sent
    assert sum("hq" in m for m in logs) == 1, "a stall is reported once, not per tick"


def test_watchdog_on_each_callback_honours_a_stall(monkeypatch):
    # The between-probes callback is a second way to reach ping().
    sent, _logs = _notifications(monkeypatch, _FakeManager(stalled=["hq"]), ticks=1)
    assert "WATCHDOG=1" not in sent


def test_status_probes_run_on_their_own_slower_clock(monkeypatch):
    # Every heartbeat used to open a TCP connection per ready_probe: 17k a day each,
    # logged by the far side, for a STATUS line nothing reads.
    mgr = _FakeManager()
    _notifications(monkeypatch, mgr, ticks=5)
    assert mgr.polls == 1


def test_managed_supervisors_cannot_pet_systemd(monkeypatch):
    # N+1 independent pingers meant any one healthy thread hid a wedged sibling.
    sent = []
    monkeypatch.setenv("WATCHDOG_USEC", "2000000")
    monkeypatch.setattr(fortivpn, "sd_notify", sent.append)
    mgr = vpnmanager.VpnManager(
        [{"name": "a", "enabled": True, "type": "openvpn", "config": "/x.ovpn"}],
        "", log=lambda m: None)
    gate = threading.Event()
    monkeypatch.setattr(vpnmanager._GuardedSupervisor, "run",
                        lambda self: (self.watchdog.ping(), gate.wait()))
    mgr._START_STAGGER = 0
    mgr.start()
    mgr._supers["a"].watchdog.ping()
    assert "WATCHDOG=1" not in sent
    gate.set()
    mgr.stop(grace=2)


def _running_manager():
    mgr = vpnmanager.VpnManager([], "", log=lambda m: None)
    release = threading.Event()
    sup = fortivpn.Supervisor({"type": "openvpn"}, "", log=lambda m: None)
    t = threading.Thread(target=release.wait, daemon=True)
    t.start()
    mgr._supers["hq"], mgr._threads["hq"] = sup, t
    return mgr, sup, release


def test_stalled_names_a_supervisor_with_a_stale_heartbeat():
    mgr, sup, release = _running_manager()
    try:
        assert mgr.stalled() == []
        sup.watchdog.beat = time.monotonic() - mgr._stall_after - 1
        assert mgr.stalled() == ["hq"]
        sup.watchdog.ping()
        assert mgr.stalled() == [], "a supervisor that recovers is forgiven"
    finally:
        release.set()


def test_stalled_names_a_supervisor_whose_thread_died():
    mgr, _unused, release = _running_manager()
    release.set()
    mgr._threads["hq"].join(timeout=2)
    assert mgr.stalled() == ["hq"]


def test_stopping_supervisor_is_not_stalled():
    mgr, sup, release = _running_manager()
    sup.stop_event.set()
    sup.watchdog.beat = 0
    release.set()
    assert mgr.stalled() == []


def test_vault_config_wait_keeps_beating(monkeypatch):
    # This 120s retry never pinged, so it would read as a wedged supervisor.
    sup = _sup(vpn={"type": "openvpn", "config_from_vault": True, "vault_item": "I"})
    sup.watchdog.beat = 0.0

    def no_vault():
        sup.stop_event.set()
        raise VaultError("down")

    monkeypatch.setattr(sup, "_open_vault", no_vault)
    assert sup._materialize_config() is False
    assert sup.watchdog.beat > 0.0


def test_oneshot_beats_around_a_slow_command(monkeypatch):
    sup = _sup()
    sup.watchdog.beat = 0.0
    assert sup._run_oneshot(["true"])[0] == 0
    assert sup.watchdog.beat > 0.0


def test_oneshot_survives_non_utf8_output():
    # wg-quick echoes gateway-supplied text. A decode error here escaped the
    # (OSError, TimeoutExpired) handler and crashed the supervisor.
    rc, out = _sup()._run_oneshot(["sh", "-c", r"printf 'bad \377 byte\n'"])
    assert rc == 0 and "byte" in out


def test_idle_never_outwaits_the_watchdog(monkeypatch):
    # A fixed 60s wait is longer than a 15s ping interval, so a standalone idler
    # under WatchdogSec=30 would be killed in a restart loop.
    monkeypatch.setenv("WATCHDOG_USEC", "30000000")
    sup = _sup()
    waits = []

    def wait(timeout):
        waits.append(timeout)
        sup.stop_event.set()
        return True

    monkeypatch.setattr(sup.stop_event, "wait", wait)
    sup.idle()
    assert waits == [15.0]


def test_watchdog_abort_cannot_core_dump_credentials(monkeypatch):
    # Withholding the watchdog ends in SIGABRT, which would put decrypted vault
    # credentials into a core file under /var/lib/systemd/coredump.
    calls = []
    monkeypatch.setattr(fortivpn.resource, "setrlimit", lambda *a: calls.append(a))
    fortivpn._disable_core_dumps(lambda m: None)
    assert calls == [(fortivpn.resource.RLIMIT_CORE, (0, 0))]


def test_session_setup_pets_the_watchdog_between_cli_calls(monkeypatch):
    # After READY=1 the watchdog is armed, and 3 x 30s + 60s of hung CLI calls is
    # past WatchdogSec=90, so a slow boot got the unit killed mid-setup.
    for key in ("SOC_VAULT_EMAIL", "SOC_VAULT_URL", "SOC_PINENTRY"):
        monkeypatch.setenv(key, "x")
    monkeypatch.setattr(fortivpn.subprocess, "run", lambda *_a, **_k:
                        subprocess.CompletedProcess([], 0, "", ""))
    steps = []
    fortivpn.ensure_litebw_session(lambda m: None, on_step=lambda: steps.append(1))
    assert len(steps) == 4


# --------------------------------------------------------------------------- #
# Routing across supervisors, and vault Notes overlays
# --------------------------------------------------------------------------- #
def _two_fortinet():
    return [{"name": "hq", "enabled": True, "gateway": "a.example", "vault_item": "A",
             "default_route": True},
            {"name": "dr", "enabled": True, "gateway": "b.example", "vault_item": "B",
             "config_from_vault": True}]


def test_vault_notes_cannot_undo_the_split_tunnel_coercion(monkeypatch):
    # The overlay arrives after _prepare: a non-owner's note could otherwise grab
    # the default route from the owner.
    mgr = vpnmanager.VpnManager(_two_fortinet(), "", log=lambda m: None)
    entry = next(e for name, e, _o in mgr._entries if name == "dr")
    sup = _vault_sup(vpnmanager._GuardedSupervisor, entry,
                     "set_routes=true\nhalf_internet_routes=true\nrealm=x\n", monkeypatch)
    assert sup._materialize_config() is True
    assert entry["realm"] == "x"
    assert entry["set_routes"] is False and entry["half_internet_routes"] is False


def test_non_owner_inode_is_forced_split_tunnel():
    # A gateway requesting redirect-all could capture the default route.
    vpns = _two_fortinet()[:1] + [{"name": "lab", "enabled": True, "type": "inode",
                                   "gateway": "g", "vault_item": "I",
                                   "split_tunnel": False}]
    mgr = vpnmanager.VpnManager(vpns, "", log=lambda m: None)
    entry = next(e for name, e, _o in mgr._entries if name == "lab")
    assert entry["split_tunnel"] is True


def test_template_instance_runs_one_vpn_but_keeps_the_routing_policy():
    # forti-vpn@dr saw one entry and so took it for the implicit route owner.
    mgr = vpnmanager.VpnManager(_two_fortinet(), "", log=lambda m: None, only="dr")
    assert mgr.names == ["dr"]
    (_name, entry, owner), = mgr._entries
    assert owner is False and entry["set_routes"] is False


def test_notes_overlay_refuses_argv_injection_without_echoing_values():
    # Load-time validation never saw these, and the supervisor runs as root.
    logs = []
    sup = _sup(logs=logs)
    parsed = sup._parse_vpn_notes_kv(
        "gateway=--pppd-plugin=/tmp/evil.so\n"
        "port=99999\n"
        "realm=-x\n"
        "trusted_cert=--secret-looking\n"
        "insecure=maybe\n"
        "unknown=sekrit\n"
        "domain=1\n"
        "set_dns=no\n")
    assert parsed == {"domain": "1", "set_dns": False}
    assert not any("evil.so" in m or "sekrit" in m or "secret-looking" in m for m in logs)


def test_gateway_held_only_in_the_vault_is_not_called_incomplete():
    # Otherwise main() skips the entry before the overlay can run.
    assert not fortivpn._vpn_incomplete({"type": "fortinet", "vault_item": "I",
                                         "config_from_vault": True})
    assert fortivpn._vpn_incomplete({"type": "fortinet", "vault_item": "I"})
    assert fortivpn._vpn_incomplete({"type": "inode", "config_from_vault": True})


def test_dry_run_masks_the_spa_key():
    logs = []
    sup = fortivpn.Supervisor(
        {"type": "inode", "gateway": "g", "vault_item": "I", "spa_key": "deadbeef"},
        "", log=logs.append)
    sup._dry_print(("user", "pw"))
    assert logs and not any("deadbeef" in m for m in logs)


# --------------------------------------------------------------------------- #
# The vault overlay, end to end
# --------------------------------------------------------------------------- #
def _capture_argv(sup, monkeypatch):
    """Run sup through the real run() path up to the Popen call; return its argv."""
    seen = []

    def popen(cmd, **_kw):
        seen.append(cmd)
        raise OSError(errno.ENOENT, "stop here")

    monkeypatch.setattr(fortivpn.shutil, "which", lambda _b: "/usr/bin/x")
    monkeypatch.setattr(fortivpn.subprocess, "Popen", popen)
    monkeypatch.setattr(sup, "_resolve_creds", lambda _t: ("alice", "pw"))
    monkeypatch.setattr(sup, "_sleep", lambda _s: sup.stop_event.set())
    _bounded(sup.run)
    assert seen, "never reached Popen"
    return seen[0]


def test_vault_only_gateway_reaches_the_real_openfortivpn_argv(tmp_path, monkeypatch):
    # Defined is not wired: this walks run() -> overlay -> build_cmd -> Popen.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    vpn = {"type": "fortinet", "vault_item": "I", "config_from_vault": True}
    assert not fortivpn._vpn_incomplete(vpn)
    sup = _vault_sup(fortivpn.Supervisor, vpn,
                     "gateway=vpn.hq.example\nport=8443\nrealm=staff\n", monkeypatch)
    argv = _capture_argv(sup, monkeypatch)
    assert argv[0] == "openfortivpn" and "vpn.hq.example:8443" in argv
    assert not [f for _r, _d, files in os.walk(tmp_path) for f in files], "overlay hit disk"


def test_vault_only_gateway_reaches_the_inode_argv(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    vpn = {"type": "inode", "vault_item": "I", "config_from_vault": True, "config": "/c"}
    sup = _vault_sup(fortivpn.Supervisor, vpn, "gateway=gw.example\nport=3000\n", monkeypatch)
    assert _capture_argv(sup, monkeypatch)[:2] == ["/c/svpn-connect.sh", "gw.example:3000"]


def test_non_owner_overlay_reaches_argv_still_split_tunnel(tmp_path, monkeypatch):
    # The overlay's set_routes must not survive into a non-owner's real argv.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    mgr = vpnmanager.VpnManager(_two_fortinet(), "", log=lambda m: None)
    entry = next(e for name, e, _o in mgr._entries if name == "dr")
    sup = _vault_sup(vpnmanager._GuardedSupervisor, entry, "set_routes=true\n", monkeypatch)
    assert "--set-routes=0" in _capture_argv(sup, monkeypatch)


def test_dry_run_can_check_a_gateway_that_only_the_vault_holds(monkeypatch):
    # Dry-run returned before the overlay, so `make vpn-check` raised on a config
    # the real connect path accepts.
    monkeypatch.setenv("SOC_VPN_DRY_RUN", "1")
    logs = []
    vpn = {"type": "fortinet", "vault_item": "I", "config_from_vault": True}
    sup = _vault_sup(fortivpn.Supervisor, vpn, "gateway=vpn.hq.example\n", monkeypatch, logs)
    monkeypatch.setattr(sup, "_resolve_creds", lambda _t: ("alice", "pw"))
    assert _bounded(sup.run) == 0
    assert any("vpn.hq.example" in m for m in logs)


def test_dry_run_reports_an_unloadable_overlay_instead_of_raising(monkeypatch):
    monkeypatch.setenv("SOC_VPN_DRY_RUN", "1")
    logs = []
    vpn = {"type": "fortinet", "vault_item": "I", "config_from_vault": True}
    sup = _vault_sup(fortivpn.Supervisor, vpn, "", monkeypatch, logs)
    assert _bounded(sup.run) == 0
    assert any("could not load" in m for m in logs)


def test_dry_run_does_not_write_openvpn_keys_to_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_VPN_DRY_RUN", "1")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    vpn = {"type": "openvpn", "config": "/x.ovpn", "config_from_vault": True}
    sup = _vault_sup(fortivpn.Supervisor, vpn, "PRIVATE KEY", monkeypatch)
    assert _bounded(sup.run) == 0
    assert not [f for _r, _d, files in os.walk(tmp_path) for f in files]


# --------------------------------------------------------------------------- #
# OTP codes and vault freshness
# --------------------------------------------------------------------------- #
class _Backend:
    def __init__(self, code=None, error=None):
        self._code, self._error, self.syncs = code, error, 0

    def code(self, _item):
        if self._error:
            raise self._error
        return self._code

    def sync(self):
        self.syncs += 1


class _OpenVault:
    def __init__(self, backend):
        self.backend, self.invalidated = backend, 0

    def invalidate(self):
        self.invalidated += 1


def _otp_sup(backend, monkeypatch, logs=None):
    sup = _sup(vpn={"type": "fortinet", "vault_item": "I"}, logs=logs)
    sup._vault = _OpenVault(backend)
    monkeypatch.setattr(sup, "_open_vault", lambda: sup._vault)
    monkeypatch.setattr(fortivpn.subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(
        AssertionError("spawned a process for an OTP")))
    return sup


def test_otp_comes_from_the_open_vault_without_a_new_process(monkeypatch):
    # Each new litebw process re-derives the sealed master: ~150 MiB per retry.
    assert _otp_sup(_Backend(code=" 123456\n"), monkeypatch)._otp_code() == "123456"


def test_otp_retry_never_reopens_the_vault(monkeypatch):
    # Dropping `_vault` on failure would re-derive the master on every retry.
    sup = _otp_sup(_Backend(error=VaultError("vault item 'I' has no TOTP secret")), monkeypatch)
    vault = sup._vault
    monkeypatch.setattr(sup, "_sleep", lambda _s: None)
    sup.stop_event.wait = lambda _t: True
    assert sup._otp_code_retry() == ""
    assert sup._vault is vault


def test_unparseable_totp_secret_is_unavailable_and_never_logged(monkeypatch):
    # It would otherwise reach a {e!r} log line on the way out of _spawn.
    logs = []
    sup = _otp_sup(_Backend(error=ValueError("bad secret JBSWY3DPEHPK3PXP")), monkeypatch, logs)
    assert sup._otp_code() == ""
    assert any("ValueError" in m for m in logs)
    assert not any("JBSWY3DP" in m for m in logs)


def _cli_otp(sup, monkeypatch):
    seen = []

    def run(cmd, **_kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "654321\n", "")

    monkeypatch.setattr(fortivpn.subprocess, "run", run)
    assert sup._otp_code() == "654321"
    return seen


def test_rbw_otp_does_not_need_an_open_vault(monkeypatch):
    # rbw has no in-process code(). Its CLI path never needed a Vault, so a failed
    # open must not cost an rbw wall its OTP.
    monkeypatch.setenv("SOC_VAULT_BACKEND", "rbw")
    sup = _sup(vpn={"type": "fortinet", "vault_item": "I"})

    def no_vault():
        raise VaultError("down")

    monkeypatch.setattr(sup, "_open_vault", no_vault)
    assert _cli_otp(sup, monkeypatch) == [["rbw", "code", "I"]]


def test_backend_without_code_falls_back_to_a_cli(monkeypatch):
    # The dev backend has no code() either.
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    sup = _sup(vpn={"type": "fortinet", "vault_item": "I"})
    sup._vault = _OpenVault(object())
    monkeypatch.setattr(sup, "_open_vault", lambda: sup._vault)
    assert _cli_otp(sup, monkeypatch) == [["litebw", "code", "I"]]


def test_rotated_password_is_seen_after_refresh(tmp_path, monkeypatch):
    # With a real backend: creds come from the snapshot taken at sync and nothing
    # renewed it, so the rejected password was resent until a manual restart.
    store = tmp_path / "vault.json"
    store.write_text(json.dumps({"I": {"username": "u", "password": "old"}}))
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    monkeypatch.setenv("SOC_DEV_VAULT", str(store))
    sup = _sup(vpn={"type": "openvpn", "vault_item": "I"})
    sup._cred_ttl = 0.0
    assert sup._resolve_creds(1.0) == ("u", "old")
    store.write_text(json.dumps({"I": {"username": "u", "password": "new"}}))
    assert sup._resolve_creds(1.0) == ("u", "old"), "expected the stale snapshot"
    sup._refresh_vault()
    assert sup._resolve_creds(1.0) == ("u", "new")


def test_refresh_does_not_reopen_the_vault(monkeypatch):
    backend = _Backend()
    sup = _otp_sup(backend, monkeypatch)
    vault = sup._vault
    sup._refresh_vault()
    assert sup._vault is vault and backend.syncs == 1 and vault.invalidated == 1


def test_failed_refresh_drops_the_vault_rather_than_resending_old_creds(monkeypatch):
    class Down(_Backend):
        def sync(self):
            raise VaultError("server down")

    sup = _otp_sup(Down(), monkeypatch)
    sup._refresh_vault()
    assert sup._vault is None


def test_rejected_login_resyncs_before_the_next_attempt(monkeypatch):
    backend = _Backend()
    sup = _otp_sup(backend, monkeypatch)

    def spawn(_creds):
        sup._saw = {fortivpn.EVENT_AUTH}

    def sleep(_seconds):
        sup.stop_event.set()

    monkeypatch.setattr(sup, "_spawn", spawn)
    monkeypatch.setattr(sup, "_watch_child", lambda: None)
    monkeypatch.setattr(sup, "_sleep", sleep)
    _bounded(sup._run_loop)
    assert backend.syncs == 1


def test_unavailable_otp_resyncs_so_a_newly_added_secret_is_found(monkeypatch):
    backend = _Backend()
    sup = _otp_sup(backend, monkeypatch)

    def spawn(_creds):
        raise fortivpn.OtpUnavailable("I")

    def sleep(_seconds):
        sup.stop_event.set()

    monkeypatch.setattr(sup, "_spawn", spawn)
    monkeypatch.setattr(sup, "_sleep", sleep)
    _bounded(sup._run_loop)
    assert backend.syncs == 1


# --------------------------------------------------------------------------- #
# IPv6 probes and the connecting state
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("target, want", [
    ("[::1]:443", ("::1", "443")),
    ("2001:db8::1:443", ("2001:db8::1", "443")),
    ("2001:db8::1", ("2001:db8::1", "")),
    ("host:notaport", ("", "")),
    ("host:", ("", "")),
    ("[::1]x", ("", "")),
])
def test_split_host_port_edges(target, want):
    assert fortivpn._split_host_port(target) == want


def test_ipv6_ready_probe_reports_online():
    # rpartition left the brackets on, so an IPv6 probe could never succeed and the
    # wall showed a healthy tunnel as offline.
    import socket
    srv = socket.socket(socket.AF_INET6)
    try:
        srv.bind(("::1", 0))
    except OSError:
        srv.close()
        pytest.skip("no IPv6 loopback")
    srv.listen(1)
    try:
        probe = f"[::1]:{srv.getsockname()[1]}"
        assert vpnstatus.vpn_state({"enabled": True, "ready_probe": probe}) == "online"
    finally:
        srv.close()


def test_probe_timeout_reads_connecting_and_refusal_reads_offline(monkeypatch):
    import socket

    def timed_out(*_a, **_k):
        raise socket.timeout("timed out")

    monkeypatch.setattr(vpnstatus.socket, "create_connection", timed_out)
    vpn = {"enabled": True, "ready_probe": "10.0.0.5:443"}
    assert vpnstatus.vpn_state(vpn) == vpnstatus.STATE_CONNECTING
    assert vpnstatus.LABELS[vpnstatus.STATE_CONNECTING] == "VPN: connecting"
    monkeypatch.undo()
    assert vpnstatus.vpn_state({"enabled": True, "ready_probe": "127.0.0.1:1"}) == "offline"


def test_connecting_counts_as_not_online_in_the_aggregate():
    # wall.py has no CSS class for it, and an unknown class would stick to the pill.
    states = {"a": vpnstatus.STATE_ONLINE, "b": vpnstatus.STATE_CONNECTING}
    assert vpnmanager.aggregate_state(states) == vpnstatus.STATE_OFFLINE


@pytest.mark.parametrize("vpn, want", [
    ({"name": "hq", "type": "fortinet"}, "hq"),
    ({"type": "Fortinet", "gateway": "vpn.acme.com:443"}, "fortinet:vpn.acme.com"),
    ({"type": "inode", "gateway": "[fd00::1]:443"}, "inode:fd00::1"),
    ({"type": "openvpn"}, "openvpn-2"),
    ({}, "vpn-2"),
])
def test_vpn_name(vpn, want):
    assert vpnstatus.vpn_name(vpn, 1) == want


# --------------------------------------------------------------------------- #
# Service scripts merged from v1.3.0
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["autossh-tunnel.sh", "forti-pinentry.sh", "forti-vpn.sh"])
def test_service_scripts_are_executable_and_parse(name):
    # HEAD carried them as 0644, which systemd and --pinentry= both refuse to exec.
    path = os.path.join(_REPO, "scripts", name)
    assert os.access(path, os.X_OK)
    subprocess.run(["bash", "-n", path], check=True)


def _pinentry(env_password):
    env = {k: v for k, v in os.environ.items() if k != "SOC_VPN_PASSWORD"}
    if env_password is not None:
        env["SOC_VPN_PASSWORD"] = env_password
    return subprocess.run(["bash", os.path.join(_REPO, "scripts", "forti-pinentry.sh")],
                          input="GETPIN\nBYE\n", capture_output=True, text=True,
                          env=env, timeout=10).stdout


@pytest.mark.parametrize("password", [None, ""])
def test_pinentry_refuses_to_submit_a_blank_password(password):
    # Rapid blank-password attempts can lock the FortiGate account.
    out = _pinentry(password)
    assert "ERR " in out
    assert "\nD " not in out


def test_pinentry_escapes_a_real_password():
    assert "D a%25b\n" in _pinentry("a%b")
