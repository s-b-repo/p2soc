#!/usr/bin/env python3
"""
soc-update: zero-touch redeploy of the SOC wall, with automatic rollback.

Runs as root from soc-update.timer. Each run:

  1. finishes any deployment a crash or power cut interrupted;
  2. asks the remote for the tip of the tracked ref (one small request);
  3. if there is something new (or the deployed tree has been damaged), builds a
     complete release beside the live one and proves it works;
  4. swaps /opt/soc-display to it with a single atomic rename;
  5. restarts the stack and watches the wall's heartbeat;
  6. keeps the release if the wall comes back healthy, otherwise swaps back and
     blocklists that commit so it is never retried.

Layout:

    /opt/soc-display          -> /opt/soc-releases/<id>     (the atomic switch)
    /opt/soc-releases/<id>/   one complete tree per release
    /opt/soc-releases/venv-*  shared venvs, keyed by requirements (soc-venv.sh)
    /var/lib/soc-update/      state.json and the git mirror

Crash safety rests on an ordering rule: the intent is durably recorded in state
BEFORE the swap. Whatever instant the power fails, the next run can tell what was
in flight and either confirm it or roll it back. Nothing is ever modified in
place, so a half-copied tree cannot exist.

Trust: git runs as an unprivileged user, and nothing from a fetched commit is
executed until the ref policy and the optional signature check have passed. With
SOC_UPDATE_SIGNERS present, an unsigned or wrongly-signed commit is refused. See
docs/AUTO_UPDATE.md.

Deliberately stdlib-only and run by the SYSTEM python, never the venv: a release
that breaks the venv must not also break the thing that recovers from it.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

ROOT_LINK = os.environ.get("SOC_ROOT", "/opt/soc-display")
RELEASES = os.environ.get("SOC_RELEASES", "/opt/soc-releases")
STATE_DIR = os.environ.get("SOC_UPDATE_STATE", "/var/lib/soc-update")
ETC = os.environ.get("SOC_ETC", "/etc/soc-display")
ENV_FILE = os.environ.get("SOC_UPDATE_ENV", os.path.join(ETC, "update.env"))
HEARTBEAT = os.environ.get("SOC_HEARTBEAT_FILE", "/run/soc-wall/heartbeat.json")

DEFAULT_REPO = "https://github.com/s-b-repo/p2soc.git"

# Never shipped to a box: they are dev-only, and leaving them out keeps the
# release small. install.sh excludes the same set.
EXCLUDES = ("dev", "kiosk-host/tests", ".github", ".githooks",
            ".pre-commit-config.yaml", "CONTRIBUTING.md")

# How old a heartbeat may be before the wall counts as not alive. The host beats
# every 15 s, so this tolerates a few missed beats under load.
HEARTBEAT_STALE_SEC = 60

# Services that must stay up through a release if they were up before it.
WATCHED_UNITS = ("vaultwarden.service", "autossh-tunnel.service", "forti-vpn.service")

# A rollback isn't proof the commit is bad: the VPN can drop during the health window.
# So it gets one more try later. Failures that can't change, like a syntax error or a
# bad signature, are permanent straight away.
MAX_RELEASE_FAILURES = 2
RELEASE_RETRY_SEC = 6 * 3600

# How many times one activation may start before it is abandoned. A release that hangs
# the box never reaches its own health verdict: the box just reboots and resumes it.
MAX_ACTIVATIONS = 2

# After a failed build (network, disk, apt), don't repeat the heavy steps every timer
# tick. An idle check is cheap, so reaching the remote isn't held back.
BUILD_RETRY_SEC = 3600

MAX_BLOCKLIST = 50

_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RELEASE_RE = re.compile(r"^[0-9a-f]{12}(-r[0-9]+)?$")
_WINDOW_RE = re.compile(r"^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$")


def log(msg: str) -> None:
    print(f"[soc-update] {msg}", flush=True)


class UpdateError(Exception):
    """This attempt failed, but the commit itself may be fine: try again later."""


class BadRelease(UpdateError):
    """The commit itself is unusable: blocklist it, never retry it."""


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
def read_env(path: str) -> Dict[str, str]:
    """Parse KEY=VALUE lines. Deliberately not sourced by a shell: this file
    steers code that runs as root, so it must only ever be data."""
    out: Dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def _flag(env: Dict[str, str], key: str, default: bool) -> bool:
    raw = env.get(key, "").strip().lower()
    return default if not raw else raw not in ("0", "false", "no", "off")


def _int(env: Dict[str, str], key: str, default: int, lo: int = 0) -> int:
    try:
        return max(lo, int(env.get(key, default)))
    except (TypeError, ValueError):
        return default


@dataclass
class Settings:
    enabled: bool = True
    repair: bool = True
    repo: str = DEFAULT_REPO
    ref: str = "stable"
    fallback_ref: str = "main"
    window: str = ""
    signers: str = ""
    health_timeout: int = 300
    health_stable: int = 60
    keep: int = 3
    healthcheck_url: str = ""
    drift_interval: int = 86400
    min_free_mb: int = 300
    git_user: str = "socupdate"
    poll: float = 5.0

    @classmethod
    def load(cls, path: str = ENV_FILE) -> "Settings":
        env = read_env(path)
        d = cls()
        return cls(
            enabled=_flag(env, "SOC_UPDATE_ENABLE", d.enabled),
            repair=_flag(env, "SOC_UPDATE_REPAIR", d.repair),
            repo=env.get("SOC_UPDATE_REPO", d.repo).strip() or d.repo,
            ref=env.get("SOC_UPDATE_REF", d.ref).strip() or d.ref,
            fallback_ref=env.get("SOC_UPDATE_FALLBACK_REF", d.fallback_ref).strip(),
            window=env.get("SOC_UPDATE_WINDOW", "").strip(),
            signers=env.get("SOC_UPDATE_SIGNERS",
                            os.path.join(ETC, "update-signers")).strip(),
            health_timeout=_int(env, "SOC_UPDATE_HEALTH_TIMEOUT", d.health_timeout, 10),
            health_stable=_int(env, "SOC_UPDATE_HEALTH_STABLE", d.health_stable, 0),
            keep=_int(env, "SOC_UPDATE_KEEP", d.keep, 1),
            healthcheck_url=env.get("SOC_HEALTHCHECK_URL", "").strip(),
            drift_interval=_int(env, "SOC_UPDATE_DRIFT_INTERVAL", d.drift_interval, 60),
            min_free_mb=_int(env, "SOC_UPDATE_MIN_FREE_MB", d.min_free_mb),
            git_user=env.get("SOC_UPDATE_GIT_USER", d.git_user).strip() or d.git_user,
        )

    def problems(self) -> List[str]:
        """Reasons this configuration must not be acted on. Checked up front so a
        typo fails loudly rather than producing a strange git invocation."""
        out = []
        if not (self.repo.startswith("https://") or self.repo.startswith("file://")):
            out.append(f"SOC_UPDATE_REPO must be https:// (got {self.repo!r})")
        if re.match(r"^https://[^/]*@", self.repo):
            out.append("SOC_UPDATE_REPO must not embed credentials")
        for name, value in (("SOC_UPDATE_REF", self.ref),
                            ("SOC_UPDATE_FALLBACK_REF", self.fallback_ref)):
            if value and (not _REF_RE.match(value) or ".." in value):
                out.append(f"{name} is not a valid ref name: {value!r}")
        if self.healthcheck_url and not self.healthcheck_url.startswith("https://"):
            out.append("SOC_HEALTHCHECK_URL must be https://")
        if self.window and not parse_window(self.window):
            out.append(f"SOC_UPDATE_WINDOW must look like 03:00-05:00 (got {self.window!r})")
        return out


def parse_window(spec: str) -> Optional[Tuple[int, int]]:
    """'HH:MM-HH:MM' to (start, end) minutes since midnight, or None if invalid."""
    m = _WINDOW_RE.match(spec)
    if not m:
        return None
    h1, m1, h2, m2 = (int(g) for g in m.groups())
    if h1 > 23 or h2 > 23 or m1 > 59 or m2 > 59:
        return None
    return h1 * 60 + m1, h2 * 60 + m2


def in_window(spec: str, now: Optional[datetime] = None) -> bool:
    """Is `now` inside the maintenance window? An empty window means any time; a
    window may wrap past midnight (22:00-02:00)."""
    if not spec:
        return True
    parsed = parse_window(spec)
    if parsed is None:
        return True          # rejected up front by problems(); never blocks updates
    start, end = parsed
    t = now or datetime.now()
    minute = t.hour * 60 + t.minute
    if start <= end:
        return start <= minute < end
    return minute >= start or minute < end


# --------------------------------------------------------------------------- #
# Durable state
# --------------------------------------------------------------------------- #
def write_durable(path: str, text: str) -> None:
    """Replace `path` so that a crash leaves the old or new content, never a mix,
    and so that the new content has reached the disk when this returns."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    fsync_dir(os.path.dirname(path))


def fsync_dir(path: str) -> None:
    fd = os.open(path or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class State:
    """What the updater knows, surviving reboots. `pending` is the crash-recovery
    record; `bad` is the commit blocklist."""

    def __init__(self, path: str):
        self.path = path
        self.data = {"pending": None, "bad": {}, "last_result": "",
                     "last_drift_check": 0, "git_failures": 0, "retry_after": 0}
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self.data.update(loaded)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            # A corrupt state file must not stop the box from ever updating again.
            log(f"state file unreadable ({e}); starting from empty state")
        self._on_disk = self._text()

    def _text(self) -> str:
        return json.dumps(self.data, indent=2, sort_keys=True)

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def save(self) -> None:
        """Written only when something changed: an idle check every 15 minutes must
        not touch the SD card."""
        text = self._text()
        if text != self._on_disk:
            write_durable(self.path, text)
            self._on_disk = text


# --------------------------------------------------------------------------- #
# The updater
# --------------------------------------------------------------------------- #
class Updater:
    def __init__(self, settings: Settings, root_link: str = ROOT_LINK,
                 releases: str = RELEASES, state_dir: str = STATE_DIR,
                 heartbeat: str = HEARTBEAT, etc: str = ETC):
        self.s = settings
        self.root_link = root_link
        self.releases = releases
        self.state_dir = state_dir
        self.heartbeat = heartbeat
        self.etc = etc
        self.repo_dir = os.path.join(state_dir, "repo.git")
        self.state = State(os.path.join(state_dir, "state.json"))

    # ---- process helpers (overridden by the tests' fake host) ---------------- #
    def sh(self, *cmd: str, timeout: int = 600, env: Optional[dict] = None,
           cwd: Optional[str] = None) -> "subprocess.CompletedProcess[str]":
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  env=env, cwd=cwd, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise UpdateError(f"{cmd[0]} timed out after {timeout}s")
        except OSError as e:
            raise UpdateError(f"could not run {cmd[0]}: {e}")

    def _git_env(self) -> dict:
        return {
            "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
            "HOME": self.state_dir,
            "LC_ALL": "C",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            # Refs in the mirror must not be able to substitute one object for another
            # between the signature check and the archive.
            "GIT_NO_REPLACE_OBJECTS": "1",
        }

    def _demote(self) -> dict:
        """subprocess kwargs that drop git to the unprivileged user. Git parses
        data from the network, so it never runs as root."""
        if os.geteuid() != 0:
            return {}
        try:
            pw = pwd.getpwnam(self.s.git_user)
        except KeyError:
            raise UpdateError(f"git user {self.s.git_user!r} does not exist")
        return {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": []}

    def git(self, *args: str, timeout: int = 300,
            repo: bool = True) -> "subprocess.CompletedProcess[str]":
        cmd = ["git"] + (["-C", self.repo_dir] if repo else []) + list(args)
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  env=self._git_env(), stdin=subprocess.DEVNULL,
                                  **self._demote())
        except subprocess.TimeoutExpired:
            raise UpdateError(f"git {args[0]} timed out after {timeout}s")

    # ---- layout --------------------------------------------------------------- #
    def is_release_layout(self) -> bool:
        return os.path.islink(self.root_link)

    def current_release(self) -> str:
        return os.path.basename(os.path.realpath(self.root_link))

    def deployed_commit(self) -> str:
        try:
            with open(os.path.join(self.root_link, ".commit"), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""

    def swap(self, release_id: str) -> None:
        """Point the root at a release. rename(2) over the old symlink is atomic:
        at every instant the path resolves to one complete tree."""
        target = os.path.join(self.releases, release_id)
        if not os.path.isdir(target):
            raise UpdateError(f"release {release_id} does not exist")
        parent = os.path.dirname(self.root_link)
        tmp = os.path.join(parent, f".{os.path.basename(self.root_link)}.swap")
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        os.symlink(target, tmp)
        os.replace(tmp, self.root_link)
        fsync_dir(parent)

    # ---- choosing what to deploy ---------------------------------------------- #
    def remote_tip(self) -> Tuple[str, str]:
        """(ref, sha) for the tracked ref, falling back to SOC_UPDATE_FALLBACK_REF
        when the ref does not exist yet. Only asks for the refs we care about, so
        an idle check is one small request and writes nothing to the SD card."""
        wanted = [r for r in (self.s.ref, self.s.fallback_ref) if r]
        patterns = []
        for ref in wanted:
            patterns += [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"]
        r = self.git("ls-remote", self.s.repo, *patterns, timeout=60, repo=False)
        if r.returncode != 0:
            raise UpdateError(f"cannot reach {self.s.repo}: {r.stderr.strip()[:200]}")
        seen: Dict[str, str] = {}
        for line in r.stdout.splitlines():
            sha, _, name = line.partition("\t")
            seen[name] = sha
        for ref in wanted:
            for name in (f"refs/heads/{ref}", f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}"):
                if name in seen:
                    if ref != self.s.ref:
                        log(f"ref {self.s.ref!r} not found; using fallback {ref!r}")
                    return ref, seen[name]
        raise UpdateError(f"none of {wanted} exist on {self.s.repo}")

    def fetch(self, ref: str, sha: str) -> None:
        """Bring `sha` into the local mirror. A mirror that fails repeatedly may be
        corrupt (a power cut mid-fetch), so it is rebuilt rather than retried
        forever. The mirror holds no state of its own, so that is always safe."""
        if self.state["git_failures"] >= 3 and os.path.isdir(self.repo_dir):
            log("git mirror keeps failing; rebuilding it from scratch")
            shutil.rmtree(self.repo_dir, ignore_errors=True)
            self.state["git_failures"] = 0
        if not os.path.isfile(os.path.join(self.repo_dir, "HEAD")):
            self._prepare_repo_dir()
            r = self.git("clone", "--quiet", "--bare", "--no-tags", self.s.repo,
                         self.repo_dir, repo=False, timeout=600)
            if r.returncode != 0:
                self._note_git_failure()
                raise UpdateError(f"git clone failed: {r.stderr.strip()[:200]}")
        r = self.git("remote", "set-url", "origin", self.s.repo)
        if r.returncode != 0:
            self._note_git_failure()
            raise UpdateError(f"git remote set-url failed: {r.stderr.strip()[:200]}")
        r = self.git("fetch", "--quiet", "--no-tags", "--force", "origin",
                     f"+{ref}:refs/soc/target", timeout=600)
        if r.returncode != 0:
            self._note_git_failure()
            raise UpdateError(f"git fetch failed: {r.stderr.strip()[:200]}")
        r = self.git("cat-file", "-e", f"{sha}^{{commit}}")
        if r.returncode != 0:
            self._note_git_failure()
            raise UpdateError(f"commit {sha[:12]} missing after fetch (moved mid-run?)")
        self.state["git_failures"] = 0

    def _note_git_failure(self) -> None:
        self.state["git_failures"] += 1

    def _prepare_repo_dir(self) -> None:
        shutil.rmtree(self.repo_dir, ignore_errors=True)
        os.makedirs(self.repo_dir, mode=0o755)
        if os.geteuid() == 0:
            pw = pwd.getpwnam(self.s.git_user)
            os.chown(self.repo_dir, pw.pw_uid, pw.pw_gid)

    def is_rewind(self, sha: str, deployed: str) -> bool:
        """True when the remote tip is an older ancestor of what is deployed, e.g.
        a force-push or a reset of the tracked ref. A deployment must never move a
        wall backwards on its own: old code may lack a security fix."""
        if not deployed or sha == deployed:
            return False
        r = self.git("merge-base", "--is-ancestor", sha, deployed)
        return r.returncode == 0

    def _git_version(self) -> Tuple[int, ...]:
        m = re.search(r"(\d+)\.(\d+)", self.git("--version", repo=False).stdout)
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    def check_signature(self, sha: str) -> None:
        """Enforce commit signatures if an allowed-signers file is installed. The
        check fails closed: once the file exists, every deployed commit must carry
        a signature from a listed key."""
        signers = self.s.signers
        if not signers or not os.path.exists(signers):
            return
        if self._git_version() < (2, 34):
            raise UpdateError("commit signatures need git 2.34 or newer; not deploying")
        r = self.git("-c", "gpg.format=ssh", "-c",
                     f"gpg.ssh.allowedSignersFile={signers}", "verify-commit", sha)
        if r.returncode != 0:
            raise BadRelease(f"commit {sha[:12]} has no valid signature from "
                             f"{signers}: {r.stderr.strip()[:200]}")

    # ---- building a release ---------------------------------------------------- #
    def extract(self, sha: str, dest: str) -> None:
        os.makedirs(dest, mode=0o755)
        # --anchored: a bare "dev" must exclude the top-level dir only, not every
        # path component of that name.
        tar = ["tar", "-x", "-C", dest, "--no-same-owner", "--anchored"]
        tar += [f"--exclude={e}" for e in EXCLUDES]
        archive = subprocess.Popen(
            ["git", "-C", self.repo_dir, "archive", "--format=tar", sha],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self._git_env(), **self._demote())
        try:
            untar = subprocess.run(tar, stdin=archive.stdout, capture_output=True,
                                   text=True, timeout=300)
        finally:
            archive.stdout.close()
        err = archive.stderr.read().decode("utf-8", "replace")
        archive.stderr.close()
        rc = archive.wait(timeout=60)
        if rc != 0 or untar.returncode != 0:
            raise UpdateError(f"could not extract {sha[:12]}: "
                              f"{err.strip()[:200]} {untar.stderr.strip()[:200]}")
        write_durable(os.path.join(dest, ".commit"), sha + "\n")

    def install_packages(self, stage: str) -> None:
        """Install any OS packages this release added. Done before the swap: if apt
        hits a network blip that must mean "retry later", not "this release is bad"
        and a rollback. Packages are additive, so the live release is unaffected."""
        r = self.sh("bash", os.path.join(stage, "install.sh"), "--deps-if-changed",
                    timeout=1800, cwd=stage,
                    env=dict(os.environ, SOC_ETC=self.etc))
        if r.returncode != 0:
            raise UpdateError(f"OS packages failed: {(r.stderr or r.stdout).strip()[-300:]}")

    def build_venv(self, stage: str) -> str:
        script = os.path.join(stage, "scripts", "soc-venv.sh")
        r = self.sh("bash", script, stage, self.releases, timeout=1800)
        if r.returncode != 0:
            raise UpdateError(f"venv build failed: {r.stderr.strip()[:300]}")
        return os.path.join(stage, ".venv", "bin", "python")

    def smoke(self, tree: str) -> Tuple[bool, str]:
        """Can this tree import its core modules and parse the live config?"""
        py = os.path.join(tree, ".venv", "bin", "python")
        if not os.path.exists(py):
            return False, f"no interpreter at {py}"
        code = (
            "import importlib.util, sys\n"
            "from host import config, vault, secretstore, fortivpn, heartbeat\n"
            "if importlib.util.find_spec('gi'):\n"
            "    import host.main\n"
            f"panels = {os.path.join(self.etc, 'panels.yaml')!r}\n"
            "import os\n"
            "if os.path.exists(panels):\n"
            "    config.load(panels)\n"
        )
        env = dict(os.environ, PYTHONPATH=os.path.join(tree, "kiosk-host"), HOME=self.state_dir)
        r = self.sh(py, "-c", code, env=env, timeout=180, cwd=tree)
        if r.returncode != 0:
            tail = r.stderr.strip().splitlines()[-1:] or ["no error output"]
            return False, tail[0][:300]
        return True, ""

    def preflight(self, stage: str, py: str) -> None:
        """Prove a release before it can touch the running system. A failure here
        costs nothing: the wall keeps running on the old release."""
        sources = [os.path.join(stage, p) for p in
                   ("kiosk-host/host", "scripts", "setup.py", "provision.py")]
        # Also the bytecode the wall runs from: the tree is root-owned, so without
        # this every host start would recompile every module on the Pi.
        r = self.sh(py, "-m", "compileall", "-q",
                    *[p for p in sources if os.path.exists(p)], timeout=300)
        if r.returncode != 0:
            raise BadRelease(f"does not compile: {(r.stdout + r.stderr).strip()[:300]}")
        shell = [os.path.join(stage, "install.sh")]
        scripts = os.path.join(stage, "scripts")
        shell += [os.path.join(scripts, f) for f in sorted(os.listdir(scripts))
                  if f.endswith(".sh")]
        for script in shell:
            r = self.sh("bash", "-n", script, timeout=60)
            if r.returncode != 0:
                raise BadRelease(f"{os.path.basename(script)}: {r.stderr.strip()[:300]}")
        r = self.sh(sys.executable, os.path.join(scripts, "soc-update.py"), "self-test",
                    timeout=60)
        if r.returncode != 0:
            raise BadRelease(f"its updater fails self-test: {r.stderr.strip()[:300]}")
        ok, why = self.smoke(stage)
        if not ok:
            # Blame the release only if the running one passes the same check;
            # otherwise the cause is outside it (e.g. a broken panels.yaml), and
            # refusing the update could block the very release that fixes it.
            live_ok, _ = self.smoke(self.root_link)
            if live_ok:
                raise BadRelease(f"smoke test failed: {why}")
            log(f"smoke test fails on the live release too, not blaming this one: {why}")

    def check_disk(self) -> None:
        free_mb = shutil.disk_usage(self.releases).free // (1024 * 1024)
        if free_mb < self.s.min_free_mb:
            self.gc(keep_extra=())
            free_mb = shutil.disk_usage(self.releases).free // (1024 * 1024)
        if free_mb < self.s.min_free_mb:
            raise UpdateError(f"only {free_mb} MB free, need {self.s.min_free_mb} MB")

    def build(self, sha: str, release_id: str) -> str:
        stage = os.path.join(self.releases, f".stage-{release_id}")
        release = os.path.join(self.releases, release_id)
        shutil.rmtree(stage, ignore_errors=True)
        try:
            self.extract(sha, stage)
            self.install_packages(stage)
            py = self.build_venv(stage)
            self.preflight(stage, py)
            shutil.rmtree(release, ignore_errors=True)
            os.rename(stage, release)
            os.sync()        # the release must be on disk before anything points at it
        finally:
            shutil.rmtree(stage, ignore_errors=True)
        return release

    # ---- activating ------------------------------------------------------------ #
    def apply_system(self, release: str) -> None:
        """Apply the release's system integration (units, sudoers, sysctl). Run
        from the release itself, so rollback restores the old release's files."""
        env = dict(os.environ, SOC_ROOT=self.root_link, SOC_RELEASES=self.releases,
                   SOC_ETC=self.etc)
        r = self.sh("bash", os.path.join(release, "install.sh"), "--activate",
                    timeout=1800, env=env, cwd=release)
        if r.returncode != 0:
            raise UpdateError(f"install.sh --activate failed: "
                              f"{(r.stderr or r.stdout).strip()[-300:]}")

    def install_meta(self, key: str, default: str) -> str:
        """A value from install.sh's manifest (META|key|value)."""
        try:
            with open(os.path.join(self.etc, ".install-manifest"), encoding="utf-8") as fh:
                for line in fh:
                    parts = line.rstrip("\n").split("|")
                    if len(parts) >= 3 and parts[0] == "META" and parts[1] == key:
                        return parts[2]
        except OSError:
            pass
        return default

    def unit_state(self, unit: str) -> str:
        return self.sh("systemctl", "is-active", unit, timeout=30).stdout.strip()

    def restart_stack(self) -> None:
        """Restart everything onto the new code. Tunnels first, the wall last, so
        panels come up with their routes already in place."""
        self.sh("systemctl", "daemon-reload", timeout=120)
        self.sh("systemctl", "try-restart", "autossh-tunnel.service",
                "forti-vpn.service", "soc-tarpit.service", timeout=120)
        # "failed" counts too. A release that crash-loops the wall trips systemd's
        # start limit and leaves the unit failed: that is exactly when a rollback has
        # to bring it back, and a plain restart would be refused until it's reset.
        if self.unit_state("soc-wall.service") in ("active", "activating", "failed"):
            self.sh("systemctl", "reset-failed", "soc-wall.service", timeout=60)
            self.sh("systemctl", "restart", "soc-wall.service", timeout=120)
            return
        if self.install_meta("install_mode", "desktop") != "kiosk":
            return           # desktop mode: never kill an operator's session
        # Boot-on-tty1 kiosk: ending the session makes getty log straight back in,
        # which starts the wall from the new tree.
        user = self.install_meta("kiosk_user", "soc")
        if self.sh("loginctl", "show-user", user, timeout=30).returncode == 0:
            self.sh("loginctl", "terminate-user", user, timeout=60)

    def wall_snapshot(self) -> dict:
        """Was the wall working before we touched it? A release is only ever judged
        against this, so an already-dead wall can't get a good release rolled back."""
        hb = self.read_heartbeat()
        return {
            # A fresh beat isn't enough: a wall that just stopped writes a last one
            # saying so, and fail-safe screens beat too. Only a working wall counts.
            "alive": (self.heartbeat_age(hb) < HEARTBEAT_STALE_SEC
                      and (hb or {}).get("state") == "running"),
            "panels_ok": int((hb or {}).get("panels_ok", 0) or 0),
            "units": {u: self.unit_state(u) for u in WATCHED_UNITS},
        }

    def read_heartbeat(self) -> Optional[dict]:
        # The kiosk user owns this file and root reads it, so it must not be able to
        # hang us (a FIFO), point us elsewhere (a symlink) or feed us gigabytes.
        try:
            fd = os.open(self.heartbeat, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            doc = json.loads(os.read(fd, 4096))
            return doc if isinstance(doc, dict) else None
        except (OSError, ValueError):
            return None
        finally:
            os.close(fd)

    @staticmethod
    def heartbeat_age(doc: Optional[dict]) -> float:
        try:
            return max(0.0, time.time() - float(doc["ts"]))
        except (KeyError, TypeError, ValueError):
            return float("inf")

    def unit_problems(self) -> List[str]:
        out = []
        for unit in ("vaultwarden.service", "autossh-tunnel.service", "forti-vpn.service"):
            enabled = self.sh("systemctl", "is-enabled", unit, timeout=30).stdout.strip()
            if enabled == "enabled" and self.unit_state(unit) == "failed":
                out.append(f"{unit} failed")
        return out

    def assess(self, pending: dict) -> Tuple[Optional[int], str]:
        """One health sample: (host pid or 0, why-not). pid None means unhealthy."""
        baseline = pending.get("baseline") or {}
        # Judged against how each service was doing before. `failed` alone isn't
        # enough: a Restart=always unit that crash-loops never reaches it.
        for unit, before in (baseline.get("units") or {}).items():
            now = self.unit_state(unit)
            if (before == "active" and now != "active") or (now == "failed" != before):
                return None, f"{unit} is {now} (was {before})"
        # Must hold whatever else happens: without it, this box never updates again.
        if self.unit_state("soc-update.timer") != "active":
            return None, "the update timer is not running"
        if not baseline.get("alive"):
            return 0, ""     # the wall wasn't up before, so don't hold that against this
        hb = self.read_heartbeat()
        if self.heartbeat_age(hb) >= HEARTBEAT_STALE_SEC:
            return None, "no fresh heartbeat from the wall"
        if hb.get("commit") != pending["commit"]:
            return None, "wall is not running the new release yet"
        if hb.get("state") != "running":
            return None, f"wall state is {hb.get('state')!r}"
        if baseline.get("panels_ok", 0) > 0 and int(hb.get("panels_ok", 0) or 0) < 1:
            return None, "no panel has loaded"
        return int(hb.get("pid", 0) or 0), ""

    def wait_healthy(self, pending: dict) -> Tuple[bool, str]:
        """Healthy means staying healthy, on the SAME host process, for a stable
        period: a host in a crash loop beats briefly and would otherwise pass."""
        deadline = time.monotonic() + self.s.health_timeout
        stable_pid = None
        stable_since = 0.0
        why = "timed out"
        while time.monotonic() < deadline:
            pid, reason = self.assess(pending)
            now = time.monotonic()
            if pid is None:
                stable_pid = None
                why = reason
            elif stable_pid != pid:
                stable_pid = pid
                stable_since = now
            if pid is not None and now - stable_since >= self.s.health_stable:
                return True, ""
            time.sleep(self.s.poll)
        return False, why

    def activate(self, release_id: str, sha: str, reason: str) -> bool:
        pending = {
            "release": release_id, "commit": sha, "reason": reason,
            "previous": self.current_release(),
            "previous_commit": self.deployed_commit(),
            "started": time.time(), "baseline": self.wall_snapshot(), "activations": 1,
        }
        # The ordering that makes a crash recoverable: intent on disk, THEN swap.
        self.state["pending"] = pending
        self.state.save()
        log(f"activating {release_id} ({reason}), previous {pending['previous']}")
        self.swap(release_id)
        return self.finish(pending)

    def finish(self, pending: dict) -> bool:
        try:
            self.apply_system(os.path.join(self.releases, pending["release"]))
            self.restart_stack()
        except (UpdateError, OSError) as e:
            self.rollback(pending, str(e))
            return False
        healthy, why = self.wait_healthy(pending)
        if not healthy:
            self.rollback(pending, why)
            return False
        self.state["pending"] = None
        self.state["bad"].pop(pending["commit"], None)
        self.state["last_result"] = f"deployed {pending['commit'][:12]} ({pending['reason']})"
        self.state.save()
        log(self.state["last_result"])
        self.gc(keep_extra=(pending["previous"],))
        return True

    def record_bad(self, sha: str, why: str, retry: bool) -> None:
        bad = self.state["bad"]
        failures = bad.get(sha, {}).get("failures", 0) + 1
        bad[sha] = {"reason": why[:300], "ts": time.time(), "failures": failures,
                    "retry": retry and failures < MAX_RELEASE_FAILURES}
        for old in sorted(bad, key=lambda k: bad[k].get("ts", 0))[:-MAX_BLOCKLIST]:
            del bad[old]

    def blocked(self, sha: str) -> bool:
        bad = self.state["bad"].get(sha)
        if not bad:
            return False
        if bad.get("retry") and time.time() - bad.get("ts", 0) >= RELEASE_RETRY_SEC:
            log(f"giving {sha[:12]} one more try (last failure: {bad.get('reason', '?')})")
            return False
        log(f"tip {sha[:12]} is blocklisted ({bad.get('reason', '?')}); staying put")
        return True

    def rollback(self, pending: dict, why: str, retry: bool = True) -> None:
        log(f"ROLLING BACK {pending['release']}: {why}")
        if pending["reason"] == "update":
            self.record_bad(pending["commit"], why, retry)
        # On disk before anything moves: a power cut from here on must finish going
        # back, not mistake the half-done swap for an activation that never happened.
        pending = dict(pending, rolling_back=True, why=why)
        self.state["pending"] = pending
        self.state.save()
        self._finish_rollback(pending)

    def _finish_rollback(self, pending: dict) -> None:
        previous, why = pending["previous"], pending.get("why", "")
        failure = ""
        try:
            self.swap(previous)
        except (UpdateError, OSError) as e:
            failure = str(e)
        else:
            try:
                self.apply_system(os.path.join(self.releases, previous))
            except (UpdateError, OSError) as e:
                failure = str(e)
            # Whatever happened above, the old tree is live again, so bring the wall
            # up on it. A broken panels.yaml can fail both releases' activation, and
            # that must not leave the screen dark.
            try:
                self.restart_stack()
            except (UpdateError, OSError) as e:
                failure = failure or str(e)
        if failure:
            self.state["last_result"] = f"ROLLBACK INCOMPLETE ({failure[:200]}); cause: {why[:200]}"
            log(self.state["last_result"])
        else:
            self.state["last_result"] = f"rolled back to {previous}: {why[:200]}"
            # It will never run again as it is, so don't let it sit on the SD card.
            shutil.rmtree(os.path.join(self.releases, pending["release"]),
                          ignore_errors=True)
        self.state["pending"] = None
        self.state.save()

    def resolve_pending(self) -> None:
        """Finish whatever a crash interrupted. Holding the lock proves the process
        that wrote this record is gone, so it can be acted on safely."""
        pending = self.state["pending"]
        if not pending:
            return
        if pending.get("rolling_back"):
            log(f"finishing interrupted rollback of {pending['release']}")
            self._finish_rollback(pending)
            return
        if self.current_release() != pending["release"]:
            log(f"discarding interrupted activation of {pending['release']} (never swapped)")
            self.state["pending"] = None
            self.state.save()
            return
        activations = pending.get("activations", 1) + 1
        if activations > MAX_ACTIVATIONS:
            # Once is a power cut. Repeatedly means the release takes the box down
            # before it can be judged, which a health check alone would never see.
            self.rollback(pending, f"never finished its health check in {activations - 1} "
                                   "tries (is it hanging the box?)", retry=False)
            return
        pending["activations"] = activations
        self.state.save()
        # The swap happened; whether the system step finished is unknown. It is
        # idempotent, so simply do it again and judge the result as usual.
        log(f"resuming interrupted activation of {pending['release']}")
        self.finish(pending)

    # ---- repair + housekeeping ------------------------------------------------- #
    def damaged_files(self) -> List[str]:
        """Files that no longer match the deploy manifest (SD-card rot, tampering,
        or an ad-hoc edit). An unreadable manifest yields nothing: no verdict."""
        try:
            with open(os.path.join(self.etc, "manifest.json"), encoding="utf-8") as fh:
                expected = json.load(fh).get("files", {})
        except (OSError, ValueError):
            return []
        out = []
        root = os.path.realpath(self.root_link)
        for rel, want in expected.items():
            try:
                h = hashlib.sha256()
                with open(os.path.join(root, rel), "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        h.update(chunk)
                if h.hexdigest() != want:
                    out.append(rel)
            except OSError:
                out.append(rel)
        return out

    def repair_due(self) -> bool:
        return (self.s.repair and time.time() - self.state["last_drift_check"]
                >= self.s.drift_interval)

    def gc(self, keep_extra=()) -> None:
        """Delete old releases and any venv nothing references. Only ever touches
        names matching the release pattern, inside the releases dir."""
        current = self.current_release()
        names = [n for n in os.listdir(self.releases)
                 if _RELEASE_RE.match(n) and os.path.isdir(os.path.join(self.releases, n))]
        names.sort(key=lambda n: os.path.getmtime(os.path.join(self.releases, n)), reverse=True)
        keep = set(names[:self.s.keep]) | {current} | {k for k in keep_extra if k}
        for name in names:
            if name not in keep:
                log(f"removing old release {name}")
                shutil.rmtree(os.path.join(self.releases, name), ignore_errors=True)
        used = set()
        for name in keep:
            link = os.path.join(self.releases, name, ".venv")
            if os.path.islink(link):
                used.add(os.path.basename(os.readlink(link).rstrip("/")))
        for name in os.listdir(self.releases):
            if name.startswith("venv-") and name not in used:
                log(f"removing unused {name}")
                shutil.rmtree(os.path.join(self.releases, name), ignore_errors=True)
            elif name.startswith(".stage-"):
                shutil.rmtree(os.path.join(self.releases, name), ignore_errors=True)

    def ping(self, ok: bool) -> None:
        """Dead-man's switch: an external monitor pages someone when these stop
        arriving, which is the one failure a box cannot report about itself."""
        url = self.s.healthcheck_url
        if not url:
            return
        try:
            with urllib.request.urlopen(url if ok else url.rstrip("/") + "/fail",  # noqa: S310
                                        timeout=10):
                pass
        except (urllib.error.URLError, OSError, ValueError) as e:
            log(f"healthcheck ping failed: {e}")

    # ---- the run --------------------------------------------------------------- #
    def plan(self, may_apply: bool = True) -> Optional[Tuple[str, str, str]]:
        """Decide what, if anything, to deploy: (ref, sha, reason) or None."""
        ref, sha = self.remote_tip()
        deployed = self.deployed_commit()
        if sha != deployed and not self.blocked(sha):
            return ref, sha, "update"
        # Only when a repair could actually happen. A scan outside the window would
        # use up the day's check, and find nothing it could act on.
        if may_apply and self.repair_due():
            self.state["last_drift_check"] = time.time()
            damaged = self.damaged_files()
            if damaged and deployed:
                log(f"{len(damaged)} deployed file(s) differ from the manifest, e.g. "
                    f"{damaged[0]}; redeploying {deployed[:12]}")
                return ref, deployed, "repair"
        return None

    def deploy(self, ref: str, sha: str, reason: str) -> bool:
        self.check_disk()
        self.fetch(ref, sha)
        if reason == "update" and self.is_rewind(sha, self.deployed_commit()):
            raise BadRelease(f"{sha[:12]} is older than the deployed commit; refusing "
                             "to move backwards")
        self.check_signature(sha)
        release_id = sha[:12] if reason == "update" else f"{sha[:12]}-r{int(time.time())}"
        self.build(sha, release_id)
        return self.activate(release_id, sha, reason)

    def configured(self) -> bool:
        """Has deployment finished? Until then there is no wall to protect, and a
        timer firing mid-setup would restart things underneath it."""
        return any(os.path.exists(os.path.join(self.etc, p))
                   for p in (".configured", "secret/master.enc"))

    def healthy_now(self) -> bool:
        return not self.unit_problems() and (
            self.install_meta("install_mode", "desktop") != "kiosk"
            or self.heartbeat_age(self.read_heartbeat()) < HEARTBEAT_STALE_SEC)

    def run(self, ignore_window: bool = False) -> int:
        if not self.s.enabled:
            log("disabled (SOC_UPDATE_ENABLE=0)")
            return 0
        if not self.is_release_layout():
            log(f"{self.root_link} is not a release symlink (package-managed install?); "
                "nothing to do")
            return 0
        problems = self.s.problems()
        if problems:
            for p in problems:
                log(f"config error: {p}")
            self.ping(False)
            return 1
        if not self.configured():
            log("not configured yet; waiting for setup.py deploy to finish")
            return 0
        ok = True
        todo = None
        try:
            self.resolve_pending()
            may_apply = ignore_window or in_window(self.s.window)
            todo = self.plan(may_apply)
            if todo and not ignore_window and time.time() < self.state["retry_after"]:
                log(f"{todo[2]} of {todo[1][:12]} is waiting after a failed attempt")
            elif todo and may_apply:
                ok = self.deploy(*todo)
                self.state["retry_after"] = 0
            elif todo:
                log(f"{todo[2]} of {todo[1][:12]} ready; waiting for window {self.s.window}")
        except BadRelease as e:
            sha = todo[1] if todo else ""
            log(f"rejected {sha[:12]}: {e}")
            if sha:
                self.record_bad(sha, str(e), retry=False)
            self.state["last_result"] = f"rejected {sha[:12]}: {str(e)[:200]}"
        except UpdateError as e:
            # Transient by definition (network, disk): a later run retries.
            log(f"will retry later: {e}")
            self.state["last_result"] = f"retry: {str(e)[:200]}"
            if todo:
                self.state["retry_after"] = time.time() + BUILD_RETRY_SEC
        self.state.save()
        self.ping(ok and self.healthy_now())
        return 0

    def manual_rollback(self) -> int:
        """`soc-update rollback`: go back to the newest other release and blocklist
        the current commit so the next timer run doesn't redeploy it."""
        current = self.current_release()
        # Only a release that ships this updater. Those are all new enough to read
        # the migrated secret store, which older builds cannot, so this also means a
        # rollback can never strand the box behind a seal it can't open.
        names = [n for n in os.listdir(self.releases)
                 if _RELEASE_RE.match(n) and n != current and os.path.isfile(
                     os.path.join(self.releases, n, "scripts", "soc-update.py"))]
        if not names:
            log("no previous release to roll back to")
            return 1
        names.sort(key=lambda n: os.path.getmtime(os.path.join(self.releases, n)), reverse=True)
        self.rollback({"release": current, "commit": self.deployed_commit(),
                       "reason": "update", "previous": names[0]}, "manual rollback",
                      retry=False)
        return 0

    def status(self) -> dict:
        return {
            "layout": "release" if self.is_release_layout() else "not-managed",
            "release": self.current_release() if self.is_release_layout() else "",
            "commit": self.deployed_commit(),
            "enabled": self.s.enabled,
            "repo": self.s.repo,
            "ref": self.s.ref,
            "window": self.s.window or "any time",
            "signatures": bool(self.s.signers and os.path.exists(self.s.signers)),
            "last_result": self.state["last_result"],
            "pending": self.state["pending"],
            "blocklisted": sorted(self.state["bad"]),
        }


class _SelfTest(Updater):
    """The real decision logic with the outside world stubbed: no network or systemd."""

    def remote_tip(self) -> Tuple[str, str]:
        return "main", self.deployed_commit()

    def unit_state(self, unit: str) -> str:
        return "active"

    def sh(self, *cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, "", "")


def self_test() -> int:
    """Run by the PREVIOUS release during preflight. A release whose updater can't get
    through this would strand the box on that version forever, so it exercises the
    code a real run depends on, not just that the file parses."""
    s = Settings()
    assert not s.problems(), s.problems()
    assert in_window("") and parse_window("03:00-05:00") == (180, 300)
    assert in_window("22:00-02:00", datetime(2026, 1, 1, 23, 30))
    assert not in_window("22:00-02:00", datetime(2026, 1, 1, 12, 0))
    assert read_env(os.devnull) == {}
    with tempfile.TemporaryDirectory() as tmp:
        root, releases, state, etc = (os.path.join(tmp, d) for d in
                                      ("root", "releases", "state", "etc"))
        for d in (state, etc, os.path.join(releases, "a" * 12)):
            os.makedirs(d)
        with open(os.path.join(releases, "a" * 12, ".commit"), "w", encoding="utf-8") as fh:
            fh.write("a" * 40 + "\n")
        with open(os.path.join(etc, ".configured"), "w", encoding="utf-8"):
            pass
        os.symlink(os.path.join(releases, "a" * 12), root)
        u = _SelfTest(s, root_link=root, releases=releases, state_dir=state,
                      heartbeat=os.path.join(tmp, "hb"), etc=etc)
        assert u.is_release_layout() and u.configured()
        assert u.current_release() == "a" * 12 and u.deployed_commit() == "a" * 40
        assert u.plan() is None
        assert u.wall_snapshot()["alive"] is False
        assert u.damaged_files() == []
        json.dumps(u.status())
        u.gc()
        assert os.path.isdir(os.path.join(releases, "a" * 12))
        u.state.save()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="soc-update", description=__doc__.split("\n")[1])
    ap.add_argument("command", nargs="?", default="run",
                    choices=["run", "status", "rollback", "self-test"])
    ap.add_argument("--now", action="store_true",
                    help="run: ignore SOC_UPDATE_WINDOW")
    args = ap.parse_args(argv)

    if args.command == "self-test":
        return self_test()
    settings = Settings.load()
    if args.command == "status":
        print(json.dumps(Updater(settings).status(), indent=2, sort_keys=True))
        return 0
    if os.geteuid() != 0:
        log("must run as root")
        return 1

    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    with open(os.path.join(STATE_DIR, "lock"), "w", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("another run is in progress")
            return 0
        updater = Updater(settings)
        try:
            if args.command == "rollback":
                return updater.manual_rollback()
            return updater.run(ignore_window=args.now)
        except Exception:  # noqa: BLE001 - a crash must reach the journal, not vanish
            log(f"unexpected failure:\n{traceback.format_exc()}")
            updater.ping(False)
            return 1


if __name__ == "__main__":
    sys.exit(main())
