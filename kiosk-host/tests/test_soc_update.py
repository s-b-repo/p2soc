"""End-to-end tests for scripts/soc-update.py, the zero-touch redeployer.

Only systemd and the wall itself are simulated. Git, tar, the release tree, the
atomic symlink swap, preflight and the durable state are all real, because those
are what has to work when a box is alone in a rack: a mocked swap would prove
nothing about a power cut.
"""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _load():
    path = os.path.join(_REPO, "scripts", "soc-update.py")
    spec = importlib.util.spec_from_file_location("soc_update_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod            # dataclasses resolves through sys.modules
    spec.loader.exec_module(mod)
    return mod


su = _load()


FAKE_VENV = """#!/usr/bin/env bash
set -e
mkdir -p "$2/venv-test/bin"
ln -sf "$(command -v python3)" "$2/venv-test/bin/python"
ln -sfn ../venv-test "$1/.venv"
"""

FAKE_INSTALL = """#!/usr/bin/env bash
[ "$1" = "--activate" ] || exit 0
echo "$(basename "$(dirname "$(readlink -f "$0")")") $*" >> "$SOC_ETC/activate.log"
[ -f "$(dirname "$0")/FAIL_ACTIVATE" ] && exit 1
exit 0
"""


def git(cwd, *args, env=None):
    base = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
            "-c", "commit.gpgsign=false"]
    full_env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                    **(env or {}))
    return subprocess.run(base + list(args), cwd=cwd, check=True, capture_output=True,
                          text=True, env=full_env).stdout.strip()


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class Origin:
    """A real upstream repository holding a minimal, valid release."""

    def __init__(self, path):
        self.path = str(path)
        os.makedirs(self.path)
        git(self.path, "init", "-q", "-b", "main")
        write(self.path, "install.sh", FAKE_INSTALL)
        write(self.path, "requirements.txt", "PyYAML\n")
        write(self.path, "scripts/soc-venv.sh", FAKE_VENV)
        shutil.copy(os.path.join(_REPO, "scripts", "soc-update.py"),
                    os.path.join(self.path, "scripts", "soc-update.py"))
        for mod in ("__init__", "vault", "secretstore", "fortivpn", "heartbeat", "main"):
            write(self.path, f"kiosk-host/host/{mod}.py", "")
        write(self.path, "kiosk-host/host/config.py", "def load(path):\n    return None\n")
        write(self.path, "version.txt", "1\n")
        self.commit("v1")

    @property
    def url(self):
        return "file://" + self.path

    def commit(self, msg, files=None, sign_env=None):
        for rel, text in (files or {}).items():
            write(self.path, rel, text)
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "-m", msg)
        return git(self.path, "rev-parse", "HEAD")


class FakeHost(su.Updater):
    """The real updater with systemd and the wall simulated.

    After every restart the simulated wall comes up on whatever release is live,
    writing a heartbeat from that commit, unless that commit is marked broken."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.broken_commits = set()
        self.states = {"soc-update.timer": "active"}
        self.system_calls = []
        self.restarts = 0

    def sh(self, *cmd, **kw):
        if cmd[0] in ("systemctl", "loginctl"):
            self.system_calls.append(cmd)
            result = subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[1] == "is-enabled":
                result.stdout = "enabled\n"
            elif cmd[1] == "is-active":
                result.stdout = self.states.get(cmd[2], "inactive") + "\n"
            return result
        return super().sh(*cmd, **kw)

    def restart_stack(self):
        self.restarts += 1
        super().restart_stack()
        self.simulate_wall()

    def simulate_wall(self):
        if self.deployed_commit() in self.broken_commits:
            try:
                os.unlink(self.heartbeat)
            except FileNotFoundError:
                pass
        else:
            beat(self.heartbeat, self.deployed_commit())


def beat(path, commit, pid=4242, panels_ok=4, state="running"):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"ts": time.time(), "pid": pid, "commit": commit, "panels_total": 4,
                   "panels_ok": panels_ok, "state": state}, fh)


class Box:
    """A deployed machine in a temp dir, one release live, wall up."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.origin = Origin(tmp / "origin")
        self.root = str(tmp / "opt" / "soc-display")
        self.releases = str(tmp / "opt" / "soc-releases")
        self.state_dir = str(tmp / "state")
        self.etc = str(tmp / "etc")
        self.hb = str(tmp / "heartbeat.json")
        for d in (self.releases, self.state_dir, self.etc):
            os.makedirs(d, exist_ok=True)
        self.settings = su.Settings(repo=self.origin.url, ref="main", fallback_ref="",
                                    signers=os.path.join(self.etc, "update-signers"),
                                    health_timeout=1, health_stable=0, min_free_mb=0)
        self.settings.poll = 0.01
        first = git(self.origin.path, "rev-parse", "HEAD")
        self.v1 = first
        u = self.updater()
        u.fetch("main", first)
        u.build(first, first[:12])
        os.symlink(os.path.join(self.releases, first[:12]), self.root)
        self.write_manifest_row("META|install_mode|kiosk")
        write(self.etc, ".configured", "")
        beat(self.hb, first)

    def updater(self):
        """A fresh instance every call, exactly like a fresh timer run: no state
        survives in memory between runs, only what reached the disk."""
        return FakeHost(self.settings, root_link=self.root, releases=self.releases,
                        state_dir=self.state_dir, heartbeat=self.hb, etc=self.etc)

    def write_manifest_row(self, row):
        with open(os.path.join(self.etc, ".install-manifest"), "a", encoding="utf-8") as fh:
            fh.write(row + "\n")

    def live(self):
        return os.path.basename(os.path.realpath(self.root))

    def state(self):
        return json.load(open(os.path.join(self.state_dir, "state.json"), encoding="utf-8"))

    def activations(self):
        try:
            return open(os.path.join(self.etc, "activate.log"), encoding="utf-8").read().split("\n")
        except OSError:
            return []


@pytest.fixture
def box(tmp_path):
    return Box(tmp_path)


# --- the happy path -------------------------------------------------------- #

def test_new_commit_is_deployed_and_activated(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    assert box.updater().run() == 0
    assert box.live() == v2[:12]
    assert open(os.path.join(box.root, ".commit")).read().strip() == v2
    assert open(os.path.join(box.root, "version.txt")).read() == "2\n"
    assert f"{v2[:12]} --activate" in box.activations()
    assert box.state()["pending"] is None
    assert v2[:12] in box.state()["last_result"]


def test_idle_run_is_cheap_and_touches_nothing(box):
    u = box.updater()
    assert u.run() == 0
    assert box.live() == box.v1[:12]
    assert u.restarts == 0
    assert box.activations() == []


def test_new_release_is_precompiled(box):
    """Root owns the tree, so the wall cannot write bytecode: the updater must, or
    every host start recompiles everything on the Pi."""
    box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    cache = os.path.join(box.root, "kiosk-host", "host", "__pycache__")
    assert any(f.startswith("config.") for f in os.listdir(cache))


def test_dev_only_files_never_ship_but_lookalikes_do(box):
    box.origin.commit("v2", {
        "dev/verify.sh": "x", "kiosk-host/tests/test_x.py": "x", ".github/ci.yml": "x",
        ".githooks/pre-commit": "x", "docs/dev/notes.md": "keep me",
    })
    box.updater().run()
    for gone in ("dev", "kiosk-host/tests", ".github", ".githooks"):
        assert not os.path.exists(os.path.join(box.root, gone)), gone
    assert os.path.exists(os.path.join(box.root, "docs", "dev", "notes.md"))


# --- a bad release never reaches the wall ---------------------------------- #

@pytest.mark.parametrize("files,expected", [
    ({"kiosk-host/host/config.py": "def broken(:\n"}, "compile"),
    ({"scripts/launcher.sh": "if then fi (\n"}, "launcher.sh"),
    ({"kiosk-host/host/config.py": "raise RuntimeError('boom')\n"}, "smoke"),
    ({"scripts/soc-update.py": "import sys; sys.exit(1)\n"}, "self-test"),
])
def test_broken_release_is_stopped_before_it_can_touch_the_wall(box, files, expected):
    bad = box.origin.commit("broken", files)
    u = box.updater()
    assert u.run() == 0
    assert box.live() == box.v1[:12]         # never swapped
    assert u.restarts == 0                   # the wall never blinked
    assert box.activations() == []
    assert bad in box.state()["bad"]
    assert expected in box.state()["bad"][bad]["reason"]


def test_config_that_only_the_new_code_rejects_blocks_the_release(box):
    write(box.etc, "panels.yaml", "x: 1\n")
    bad = box.origin.commit("stricter", {
        "kiosk-host/host/config.py": "def load(path):\n    raise ValueError('nope')\n"})
    box.updater().run()
    assert box.live() == box.v1[:12]
    assert bad in box.state()["bad"]


def test_a_failure_shared_with_the_live_release_is_not_blamed_on_the_new_one(box):
    """If the live release fails the same check, the cause is outside both
    (e.g. a bad panels.yaml), and refusing could block the very release that fixes
    it. So v2 must still deploy."""
    box.origin.commit("v2-broken-too", {
        "kiosk-host/host/config.py": "def load(path):\n    raise ValueError('env')\n"})
    u = box.updater()
    # Break the live release the same way before the run.
    with open(os.path.join(box.releases, box.v1[:12], "kiosk-host", "host", "config.py"), "w") as f:
        f.write("def load(path):\n    raise ValueError('env')\n")
    write(box.etc, "panels.yaml", "x: 1\n")
    u.run()
    assert box.live() != box.v1[:12]


# --- rollback ---------------------------------------------------------------- #

def test_release_that_never_comes_up_is_rolled_back_and_blocklisted(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    assert box.live() == box.v1[:12]
    assert open(os.path.join(box.root, "version.txt")).read() == "1\n"
    assert v2 in box.state()["bad"]
    assert box.state()["pending"] is None
    # activated, then the old release re-applied its own system files
    assert box.activations()[:2] == [f"{v2[:12]} --activate", f"{box.v1[:12]} --activate"]
    assert u.restarts == 2                   # forward, then back


def test_blocklisted_commit_is_not_retried(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    again = box.updater()
    again.run()
    assert again.restarts == 0
    assert box.live() == box.v1[:12]


def test_a_rolled_back_commit_gets_exactly_one_more_try_later(box, monkeypatch):
    """A rollback isn't proof: the VPN can drop during the health window. Blocklisting
    forever would strand a good commit, but retrying forever would blink the wall."""
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    assert box.state()["bad"][v2]["retry"] is True
    later = time.time() + su.RELEASE_RETRY_SEC + 1
    monkeypatch.setattr(su.time, "time", lambda: later)
    beat(box.hb, box.v1)                     # the wall has been fine all this time
    second = box.updater()
    second.broken_commits.add(v2)
    second.run()
    assert second.restarts == 2              # it really was tried again
    assert box.state()["bad"][v2]["retry"] is False
    third = box.updater()
    third.run()
    assert third.restarts == 0


def test_a_transient_failure_clears_when_the_retry_succeeds(box, monkeypatch):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    later = time.time() + su.RELEASE_RETRY_SEC + 1
    monkeypatch.setattr(su.time, "time", lambda: later)
    box.updater().run()
    assert box.live() == v2[:12]
    assert v2 not in box.state()["bad"]


def test_a_preflight_failure_is_never_retried(box, monkeypatch):
    """A syntax error can't get better with time."""
    bad = box.origin.commit("broken", {"kiosk-host/host/config.py": "def x(:\n"})
    box.updater().run()
    assert box.state()["bad"][bad]["retry"] is False


def test_blocklist_cannot_grow_without_bound(box):
    u = box.updater()
    for n in range(su.MAX_BLOCKLIST + 20):
        u.record_bad(f"{n:040x}", "x", retry=False)
    assert len(u.state["bad"]) == su.MAX_BLOCKLIST


def test_rollback_restarts_the_wall_even_if_the_old_release_wont_activate(box):
    """Found in review: a broken panels.yaml fails --activate on both releases. Stopping
    there left the old tree live but nothing running: a dark wall."""
    v2 = box.origin.commit("v2", {"FAIL_ACTIVATE": "1\n"})
    write(os.path.join(box.releases, box.v1[:12]), "FAIL_ACTIVATE", "1\n")
    u = box.updater()
    u.run()
    assert box.live() == box.v1[:12]
    assert u.restarts == 1                   # the rollback's restart still happened
    assert "INCOMPLETE" in box.state()["last_result"]


def test_a_newer_fix_moves_past_a_bad_commit(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    v3 = box.origin.commit("v3 fixes it", {"version.txt": "3\n"})
    box.updater().run()
    assert box.live() == v3[:12]


def test_failed_activation_rolls_back(box):
    v2 = box.origin.commit("v2", {"FAIL_ACTIVATE": "1\n"})
    box.updater().run()
    assert box.live() == box.v1[:12]
    assert v2 in box.state()["bad"]


def test_crash_looping_host_is_unhealthy_even_though_it_keeps_beating(box):
    """The trap this guards against: a host that crashes every few seconds still
    writes a fresh heartbeat each time. Only a stable PID proves it stayed up."""
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.settings.health_stable = 1
    box.settings.health_timeout = 2
    u = box.updater()
    pids = iter(range(1000, 9000))
    real_read = u.read_heartbeat

    def flapping():
        doc = real_read() or {}
        return dict(doc, ts=time.time(), pid=next(pids), commit=u.deployed_commit(),
                    state="running", panels_ok=4)
    u.read_heartbeat = flapping
    u.run()
    assert box.live() == box.v1[:12]
    assert v2 in box.state()["bad"]


def test_a_wall_stuck_on_the_failsafe_screen_is_unhealthy(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.simulate_wall = lambda: beat(box.hb, u.deployed_commit(), state="fatal")
    u.run()
    assert box.live() == box.v1[:12]
    assert "fatal" in box.state()["bad"][v2]["reason"]


def test_a_wall_that_cannot_load_any_panel_is_unhealthy(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.simulate_wall = lambda: beat(box.hb, u.deployed_commit(), panels_ok=0)
    u.run()
    assert box.live() == box.v1[:12]
    assert "panel" in box.state()["bad"][v2]["reason"]


def _service_goes(box, u, unit, before, after):
    """A service that is `before` when the release starts and `after` once it's live."""
    u.states[unit] = before
    wall = u.simulate_wall

    def changed():
        wall()
        if u.deployed_commit() != box.v1:
            u.states[unit] = after
        else:
            u.states[unit] = before
    u.simulate_wall = changed


def test_a_service_that_fails_under_the_new_release_is_unhealthy(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    _service_goes(box, u, "vaultwarden.service", "active", "failed")
    u.run()
    assert box.live() == box.v1[:12]
    assert v2 in box.state()["bad"]


def test_a_crash_looping_service_is_unhealthy(box):
    """Restart=always never reaches `failed`: it sits in `activating`, so looking only
    for failures would wave through a release that kills the tunnel."""
    box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    _service_goes(box, u, "autossh-tunnel.service", "active", "activating")
    u.run()
    assert box.live() == box.v1[:12]


def test_a_service_already_down_is_not_blamed_on_the_release(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.states["forti-vpn.service"] = "failed"
    u.run()
    assert box.live() == v2[:12]


def test_a_release_that_stops_the_update_timer_is_rolled_back(box):
    """Otherwise that box silently never updates again."""
    box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    _service_goes(box, u, "soc-update.timer", "active", "inactive")
    u.run()
    assert box.live() == box.v1[:12]


def test_a_wall_that_was_already_dead_cannot_get_a_good_release_rolled_back(box):
    """Without this, a box whose wall is down for an unrelated reason would reject
    every release, including the one that fixes it."""
    os.unlink(box.hb)
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)                 # no heartbeat afterwards either
    u.run()
    assert box.live() == v2[:12]


def test_a_wall_that_just_stopped_cannot_get_a_good_release_rolled_back(box):
    """Found on a real system: a stopping host writes a last, fresh heartbeat. Taken
    for a running wall, it made a good release look like it had killed the wall."""
    beat(box.hb, box.v1, state="stopping")
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    assert box.live() == v2[:12]


# --- power cuts ---------------------------------------------------------------- #

def interrupted(box, v2, *, swapped):
    """Reproduce the exact on-disk state left by a power cut mid-activation."""
    u = box.updater()
    u.fetch("main", v2)
    u.build(v2, v2[:12])
    pending = {"release": v2[:12], "commit": v2, "reason": "update",
               "previous": box.v1[:12], "previous_commit": box.v1,
               "started": time.time(), "baseline": {"alive": True, "panels_ok": 4}}
    u.state["pending"] = pending
    u.state.save()
    if swapped:
        u.swap(v2[:12])


def test_power_cut_before_the_swap_is_harmless(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    interrupted(box, v2, swapped=False)
    box.updater().run()
    # the stale record is dropped and the update simply happens again
    assert box.state()["pending"] is None
    assert box.live() == v2[:12]


def test_power_cut_after_the_swap_resumes_and_confirms_a_good_release(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    interrupted(box, v2, swapped=True)
    u = box.updater()
    u.run()
    assert box.live() == v2[:12]
    assert box.state()["pending"] is None
    assert f"{v2[:12]} --activate" in box.activations()    # system files finished


def test_power_cut_after_the_swap_rolls_back_a_bad_release(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    interrupted(box, v2, swapped=True)
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    assert box.live() == box.v1[:12]
    assert v2 in box.state()["bad"]


def test_power_cut_during_rollback_finishes_the_rollback(box):
    """Found in review: with the verdict only in memory, a power cut after the swap back
    read as 'never swapped', so the bad commit was deployed all over again."""
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    interrupted(box, v2, swapped=True)
    u = box.updater()
    u.record_bad(v2, "wall never came up", retry=True)
    pending = dict(u.state["pending"], rolling_back=True, why="wall never came up")
    u.state["pending"] = pending
    u.state.save()
    u.swap(box.v1[:12])                      # the cut lands right after the swap back

    after = box.updater()
    after.run()
    assert box.live() == box.v1[:12]
    assert box.state()["pending"] is None
    assert v2 in box.state()["bad"]
    assert after.restarts == 1               # the old release was brought up properly
    assert f"{box.v1[:12]} --activate" in box.activations()


def test_a_release_that_keeps_taking_the_box_down_is_abandoned(box):
    """It hangs the box before its health check can finish, so no verdict ever comes:
    the box just reboots and resumes it. That has to end by rolling back."""
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    interrupted(box, v2, swapped=True)
    u = box.updater()
    u.state["pending"]["activations"] = su.MAX_ACTIVATIONS
    u.state.save()
    box.updater().run()
    assert box.live() == box.v1[:12]
    assert box.state()["bad"][v2]["retry"] is False


def test_one_power_cut_is_not_treated_as_a_bad_release(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    interrupted(box, v2, swapped=True)
    box.updater().run()
    assert box.live() == v2[:12]
    assert v2 not in box.state()["bad"]


def test_torn_state_file_does_not_stop_updates_forever(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    with open(os.path.join(box.state_dir, "state.json"), "w") as fh:
        fh.write('{"pending": {"release"')
    box.updater().run()
    assert box.live() == v2[:12]


def test_interrupted_stage_dir_is_cleaned_up(box):
    os.makedirs(os.path.join(box.releases, ".stage-deadbeef0000"))
    box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    assert not any(n.startswith(".stage-") for n in os.listdir(box.releases))


def test_swap_never_exposes_a_missing_root(box):
    """The root must resolve at every instant: it is replaced by rename, so there
    is no window in which it does not exist."""
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.fetch("main", v2)
    u.build(v2, v2[:12])
    inode_before = os.lstat(box.root).st_ino
    u.swap(v2[:12])
    assert os.lstat(box.root).st_ino != inode_before       # a new link, renamed in
    assert stat.S_ISLNK(os.lstat(box.root).st_mode)
    assert not os.path.lexists(os.path.join(os.path.dirname(box.root), ".soc-display.swap"))


# --- trust ---------------------------------------------------------------------- #

def test_rewound_ref_is_refused(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    assert box.live() == v2[:12]
    git(box.origin.path, "reset", "-q", "--hard", box.v1)
    box.updater().run()
    assert box.live() == v2[:12]             # stayed on the newer code
    assert box.v1 in box.state()["bad"]


def _ssh_signed_commit(box, msg):
    key = str(box.tmp / "signing_key")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    git(box.origin.path, "add", "-A")
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "gpg.format=ssh", "-c", f"user.signingkey={key}", "commit", "-q", "-S",
         "--allow-empty", "-m", msg],
        cwd=box.origin.path, check=True,
        env=dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"))
    return git(box.origin.path, "rev-parse", "HEAD"), key


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_with_signers_configured_an_unsigned_commit_is_refused(box):
    write(box.etc, "update-signers", "t@example.invalid ssh-ed25519 AAAA\n")
    v2 = box.origin.commit("unsigned", {"version.txt": "2\n"})
    u = box.updater()
    u.run()
    assert box.live() == box.v1[:12]
    assert u.restarts == 0
    assert "signature" in box.state()["bad"][v2]["reason"]


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_with_signers_configured_a_signed_commit_deploys(box):
    write(box.origin.path, "version.txt", "2\n")
    v2, key = _ssh_signed_commit(box, "signed")
    pub = open(key + ".pub").read().split()
    write(box.etc, "update-signers", f"t@example.invalid {pub[0]} {pub[1]}\n")
    box.updater().run()
    assert box.live() == v2[:12]


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_a_commit_signed_by_an_unlisted_key_is_refused(box):
    write(box.origin.path, "version.txt", "2\n")
    v2, _ = _ssh_signed_commit(box, "signed by someone else")
    other = str(box.tmp / "other_key")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other], check=True)
    pub = open(other + ".pub").read().split()
    write(box.etc, "update-signers", f"t@example.invalid {pub[0]} {pub[1]}\n")
    box.updater().run()
    assert box.live() == box.v1[:12]
    assert v2 in box.state()["bad"]


@pytest.mark.parametrize("field,value,expected", [
    ("repo", "http://github.com/x/y.git", "https"),
    ("repo", "git@github.com:x/y.git", "https"),
    ("repo", "https://user:token@github.com/x/y.git", "credentials"),
    ("ref", "--upload-pack=/bin/sh", "ref name"),
    ("ref", "main..evil", "ref name"),
    ("healthcheck_url", "http://hc.example/x", "https"),
    ("window", "whenever", "WINDOW"),
])
def test_unsafe_settings_are_refused(field, value, expected):
    s = su.Settings()
    setattr(s, field, value)
    assert any(expected in p for p in s.problems())


def test_a_bad_setting_stops_the_run_rather_than_guessing(box):
    box.settings.ref = "--upload-pack=/bin/sh"
    u = box.updater()
    assert u.run() == 1
    assert box.live() == box.v1[:12]


# --- ref selection, windows, layout --------------------------------------------- #

def test_stable_ref_wins_over_fallback_once_it_exists(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    git(box.origin.path, "branch", "stable", box.v1)     # CI has only promoted v1
    box.settings.ref, box.settings.fallback_ref = "stable", "main"
    box.updater().run()
    assert box.live() == box.v1[:12]
    git(box.origin.path, "branch", "-f", "stable", v2)   # CI promotes v2
    box.updater().run()
    assert box.live() == v2[:12]


def test_fallback_ref_is_used_until_stable_exists(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.settings.ref, box.settings.fallback_ref = "stable", "main"
    box.updater().run()
    assert box.live() == v2[:12]


def test_update_waits_for_the_maintenance_window(box, monkeypatch):
    box.origin.commit("v2", {"version.txt": "2\n"})
    box.settings.window = "03:00-05:00"
    monkeypatch.setattr(su, "in_window", lambda spec: False)
    u = box.updater()
    u.run()
    assert box.live() == box.v1[:12]
    assert u.restarts == 0


def test_now_flag_overrides_the_window(box, monkeypatch):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.settings.window = "03:00-05:00"
    monkeypatch.setattr(su, "in_window", lambda spec: False)
    box.updater().run(ignore_window=True)
    assert box.live() == v2[:12]


@pytest.mark.parametrize("spec,hour,minute,expected", [
    ("", 12, 0, True),
    ("03:00-05:00", 4, 0, True),
    ("03:00-05:00", 3, 0, True),
    ("03:00-05:00", 5, 0, False),
    ("03:00-05:00", 12, 0, False),
    ("22:00-02:00", 23, 0, True),
    ("22:00-02:00", 1, 59, True),
    ("22:00-02:00", 2, 0, False),
    ("22:00-02:00", 12, 0, False),
])
def test_window_arithmetic(spec, hour, minute, expected):
    assert su.in_window(spec, datetime(2026, 1, 1, hour, minute)) is expected


def test_package_managed_install_is_left_alone(tmp_path):
    root = tmp_path / "soc-display"
    root.mkdir()                             # a real directory, not a release link
    state = tmp_path / "state"
    state.mkdir()
    u = su.Updater(su.Settings(), root_link=str(root), releases=str(tmp_path),
                   state_dir=str(state))
    assert u.run() == 0
    assert not (state / "repo.git").exists()


def test_disabled_does_nothing(box):
    box.origin.commit("v2", {"version.txt": "2\n"})
    box.settings.enabled = False
    box.updater().run()
    assert box.live() == box.v1[:12]


def test_unreachable_remote_is_not_fatal_and_is_retried(box):
    box.settings.repo = "file:///nonexistent/repo.git"
    u = box.updater()
    assert u.run() == 0
    assert box.live() == box.v1[:12]
    assert "retry" in box.state()["last_result"]


def test_nothing_runs_until_deployment_has_finished(box):
    """A timer firing during `setup.py deploy` must not restart things underneath it."""
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    os.unlink(os.path.join(box.etc, ".configured"))
    assert box.updater().run() == 0
    assert box.live() == box.v1[:12]
    os.makedirs(os.path.join(box.etc, "secret"))
    write(box.etc, "secret/master.enc", "x")  # a box set up by hand also counts
    box.updater().run()
    assert box.live() == v2[:12]


def test_an_idle_check_writes_nothing_to_the_sd_card(box):
    box.updater().run()
    path = os.path.join(box.state_dir, "state.json")
    before = os.stat(path).st_mtime_ns
    time.sleep(0.02)
    box.updater().run()
    assert os.stat(path).st_mtime_ns == before


def test_a_failed_build_is_not_repeated_every_tick(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.settings.min_free_mb = 10 ** 12
    box.updater().run()
    box.settings.min_free_mb = 0              # the disk is fine now, but it's too soon
    box.updater().run()
    assert box.live() == box.v1[:12]
    box.updater().run(ignore_window=True)     # an operator can always force it
    assert box.live() == v2[:12]


def test_heartbeat_cannot_hang_or_redirect_root(box):
    """The kiosk user owns this file and root reads it."""
    os.unlink(box.hb)
    os.mkfifo(box.hb)
    assert box.updater().read_heartbeat() is None     # a FIFO would block forever
    os.unlink(box.hb)
    target = box.tmp / "secret-file"
    target.write_text('{"ts": 1}')
    os.symlink(target, box.hb)
    assert box.updater().read_heartbeat() is None


def test_replace_refs_are_ignored():
    assert su.Updater(su.Settings(), state_dir="/nonexistent/x")._git_env() \
        ["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_old_git_defers_rather_than_condemning_a_signed_commit(box, monkeypatch):
    """git before 2.34 can't verify these at all, which says nothing about the commit."""
    write(box.etc, "update-signers", "t@x ssh-ed25519 AAAA\n")
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    monkeypatch.setattr(u, "_git_version", lambda: (2, 30))
    u.run()
    assert box.live() == box.v1[:12]
    assert v2 not in box.state()["bad"]


def test_low_disk_defers_without_touching_anything(box):
    box.origin.commit("v2", {"version.txt": "2\n"})
    box.settings.min_free_mb = 10 ** 12
    u = box.updater()
    assert u.run() == 0
    assert box.live() == box.v1[:12]
    assert box.state()["bad"] == {}           # the commit is fine; the disk is not


# --- self-repair ---------------------------------------------------------------- #

def _record_manifest(box):
    import hashlib
    files = {}
    root = os.path.realpath(box.root)
    for d, _, names in os.walk(root):
        if "__pycache__" in d:
            continue
        for n in names:
            p = os.path.join(d, n)
            if os.path.islink(p):
                continue
            files[os.path.relpath(p, root)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    with open(os.path.join(box.etc, "manifest.json"), "w") as fh:
        json.dump({"files": files}, fh)


def test_a_repair_found_outside_the_window_is_not_forgotten(box, monkeypatch):
    """Found in review: the scan used up the day's check, so a box whose timer never
    lined up with its window could go months without repairing."""
    _record_manifest(box)
    with open(os.path.join(box.root, "version.txt"), "w") as fh:
        fh.write("damaged\n")
    box.settings.window = "03:00-05:00"
    monkeypatch.setattr(su, "in_window", lambda spec: False)
    box.updater().run()
    assert box.live() == box.v1[:12]
    monkeypatch.setattr(su, "in_window", lambda spec: True)
    box.updater().run()
    assert box.live().startswith(box.v1[:12] + "-r")


def test_damaged_tree_is_repaired_from_the_same_commit(box):
    _record_manifest(box)
    with open(os.path.join(box.root, "version.txt"), "w") as fh:
        fh.write("corrupted by the SD card\n")
    box.updater().run()
    assert box.live().startswith(box.v1[:12] + "-r")
    assert open(os.path.join(box.root, "version.txt")).read() == "1\n"
    assert open(os.path.join(box.root, ".commit")).read().strip() == box.v1


def test_deleted_file_counts_as_damage(box):
    _record_manifest(box)
    os.unlink(os.path.join(box.root, "version.txt"))
    assert box.updater().damaged_files() == ["version.txt"]


def test_failed_repair_does_not_blocklist_the_good_commit(box):
    _record_manifest(box)
    with open(os.path.join(box.root, "version.txt"), "w") as fh:
        fh.write("x\n")
    u = box.updater()
    u.broken_commits.add(box.v1)
    u.run()
    assert box.v1 not in box.state()["bad"]


def test_repair_scan_is_rate_limited(box):
    _record_manifest(box)
    box.updater().run()
    with open(os.path.join(box.root, "version.txt"), "w") as fh:
        fh.write("x\n")
    u = box.updater()
    u.run()                                  # scanned moments ago: not due yet
    assert u.restarts == 0


def test_repair_can_be_turned_off(box):
    _record_manifest(box)
    with open(os.path.join(box.root, "version.txt"), "w") as fh:
        fh.write("local hotfix\n")
    box.settings.repair = False
    u = box.updater()
    u.run()
    assert u.restarts == 0


# --- housekeeping ---------------------------------------------------------------- #

def test_old_releases_and_unused_venvs_are_removed(box):
    os.makedirs(os.path.join(box.releases, "venv-unused0000"))
    shas = [box.v1]
    box.settings.keep = 2
    for n in range(2, 6):
        shas.append(box.origin.commit(f"v{n}", {"version.txt": f"{n}\n"}))
        box.updater().run()
        time.sleep(0.01)
    left = sorted(n for n in os.listdir(box.releases) if not n.startswith("venv-"))
    assert sorted([shas[-1][:12], shas[-2][:12]]) == left
    assert "venv-test" in os.listdir(box.releases)
    assert "venv-unused0000" not in os.listdir(box.releases)


def test_previous_release_always_survives_gc_so_rollback_stays_possible(box):
    box.settings.keep = 1
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    assert box.live() == v2[:12]
    assert os.path.isdir(os.path.join(box.releases, box.v1[:12]))


def test_gc_ignores_anything_that_is_not_a_release(box):
    keep = os.path.join(box.releases, "operator-notes")
    os.makedirs(keep)
    box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    assert os.path.isdir(keep)


def test_rollback_only_targets_releases_that_ship_the_updater(box):
    """Those are the only ones guaranteed to read the migrated secret store: a build
    predating it would strand the box behind a seal it can't open."""
    box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    live = box.live()
    # the only other release is a stray tree without the updater
    shutil.rmtree(os.path.join(box.releases, box.v1[:12], "scripts"))
    assert box.updater().manual_rollback() == 1
    assert box.live() == live


def test_manual_rollback(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    assert box.updater().manual_rollback() == 0
    assert box.live() == box.v1[:12]
    assert v2 in box.state()["bad"]          # otherwise the next timer run reinstates it


# --- restart behaviour ------------------------------------------------------------ #

def test_kiosk_session_is_ended_so_getty_logs_back_into_the_new_tree(box):
    box.write_manifest_row("META|kiosk_user|soc")
    box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.run()
    assert ("loginctl", "terminate-user", "soc") in u.system_calls


def test_supervised_wall_unit_is_restarted_instead_when_active(box):
    box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    real = u.sh

    def wall_active(*cmd, **kw):
        r = real(*cmd, **kw)
        if cmd[:3] == ("systemctl", "is-active", "soc-wall.service"):
            r.stdout = "active\n"
        return r
    u.sh = wall_active
    u.run()
    assert ("systemctl", "restart", "soc-wall.service") in u.system_calls
    assert not any(c[0] == "loginctl" and c[1] == "terminate-user" for c in u.system_calls)


def test_desktop_install_never_kills_an_operators_session(box):
    with open(os.path.join(box.etc, ".install-manifest"), "w") as fh:
        fh.write("META|install_mode|desktop\nMETA|kiosk_user|soc\n")
    box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.run()
    assert not any(c[0] == "loginctl" and c[1] == "terminate-user" for c in u.system_calls)


def test_rollback_revives_a_wall_unit_that_hit_the_start_limit(box):
    """Found on a real system: a crash-looping release trips systemd's start limit, so
    the unit sits in `failed`. Restarting only an `active` unit meant the rollback put
    the old files back and left the screen dark."""
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    real = u.sh

    def failed_wall(*cmd, **kw):
        r = real(*cmd, **kw)
        if cmd[:3] == ("systemctl", "is-active", "soc-wall.service"):
            r.stdout = "failed\n"
        return r
    u.sh = failed_wall
    u.run()
    assert box.live() == box.v1[:12]
    last_reset = len(u.system_calls) - 1 - u.system_calls[::-1].index(
        ("systemctl", "reset-failed", "soc-wall.service"))
    assert ("systemctl", "restart", "soc-wall.service") in u.system_calls[last_reset:]


def test_rejected_release_does_not_sit_on_the_sd_card(box):
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    assert not os.path.exists(os.path.join(box.releases, v2[:12]))


def test_tunnels_restart_before_the_wall(box):
    box.write_manifest_row("META|kiosk_user|soc")
    box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.run()
    order = [c[1] for c in u.system_calls if c[1] in ("try-restart", "terminate-user")]
    assert order == ["try-restart", "terminate-user"]


# --- monitoring -------------------------------------------------------------------- #

def _capture_pings(monkeypatch):
    pings = []

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(url, timeout=0):
        pings.append(url)
        return Resp()
    monkeypatch.setattr(su.urllib.request, "urlopen", fake)
    return pings


def test_healthy_run_pings_the_dead_mans_switch(box, monkeypatch):
    pings = _capture_pings(monkeypatch)
    box.settings.healthcheck_url = "https://hc.example/abc"
    box.updater().run()
    assert pings == ["https://hc.example/abc"]


def test_rollback_reports_failure(box, monkeypatch):
    pings = _capture_pings(monkeypatch)
    box.settings.healthcheck_url = "https://hc.example/abc"
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    u = box.updater()
    u.broken_commits.add(v2)
    u.run()
    assert pings == ["https://hc.example/abc/fail"]


def test_dead_wall_reports_failure_even_with_nothing_to_deploy(box, monkeypatch):
    pings = _capture_pings(monkeypatch)
    box.settings.healthcheck_url = "https://hc.example/abc"
    os.unlink(box.hb)
    box.updater().run()
    assert pings == ["https://hc.example/abc/fail"]


def test_failed_ping_never_affects_the_update(box, monkeypatch):
    def boom(url, timeout=0):
        raise OSError("network down")
    monkeypatch.setattr(su.urllib.request, "urlopen", boom)
    box.settings.healthcheck_url = "https://hc.example/abc"
    v2 = box.origin.commit("v2", {"version.txt": "2\n"})
    box.updater().run()
    assert box.live() == v2[:12]


# --- settings parsing -------------------------------------------------------------- #

def test_env_file_is_parsed_as_data_never_executed(tmp_path):
    canary = tmp_path / "canary"
    env = tmp_path / "update.env"
    env.write_text(f'SOC_UPDATE_REF="stable"\n# comment\n\nSOC_UPDATE_REPO=$(touch {canary})\n')
    assert su.read_env(str(env))["SOC_UPDATE_REF"] == "stable"
    assert not canary.exists()
    s = su.Settings.load(str(env))
    assert any("https" in p for p in s.problems())   # the literal text is rejected


def test_settings_defaults_are_safe_and_valid():
    s = su.Settings.load(os.devnull)
    assert s.problems() == []
    assert s.repo.startswith("https://")
    assert s.ref == "stable" and s.fallback_ref == "main"


def test_self_test_passes():
    assert su.self_test() == 0


def test_status_is_json_serialisable(box):
    json.dumps(box.updater().status())
