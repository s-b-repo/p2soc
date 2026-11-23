"""The deploy layer: launcher watchdog, installer guarantees, and the helpers that
let a deployment finish with nobody present.

Static checks here are not style checks. Each guards a specific failure that was
real in this tree: a script the code calls that no longer ships, a sudoers wildcard
that lets a renderer restart any unit, a placeholder sealed as the vault master.
"""
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# --- launcher watchdog: the real script, a fake host ------------------------- #

FAKE_HOST = """#!/usr/bin/env bash
# Stands in for `python -m host.main`. Each run appends to runs.log, then behaves as
# the next line of behaviour.txt says.
n=$(wc -l < "$ROOT_DIR/runs.log" 2>/dev/null || echo 0)
echo "run $$" >> "$ROOT_DIR/runs.log"
mode=$(sed -n "$((n + 1))p" "$ROOT_DIR/behaviour.txt")
case "$mode" in
  hang)    echo x > "$SOC_HEARTBEAT_FILE"; exec sleep 300 ;;
  silent)  exec sleep 300 ;;
  beat)    for i in 1 2 3 4 5 6 7 8; do echo "$i" > "$SOC_HEARTBEAT_FILE"; sleep 0.5; done; exit 0 ;;
  exit2)   exit 2 ;;
  *)       exec sleep 300 ;;
esac
"""


class Wall:
    def __init__(self, tmp, behaviour, **env):
        self.root = tmp
        (tmp / "scripts").mkdir()
        (tmp / "kiosk-host").mkdir()
        (tmp / ".venv" / "bin").mkdir(parents=True)
        shutil.copy(os.path.join(_REPO, "scripts", "launcher.sh"), tmp / "scripts")
        py = tmp / ".venv" / "bin" / "python"
        py.write_text(FAKE_HOST)
        py.chmod(0o755)
        (tmp / "behaviour.txt").write_text("\n".join(behaviour) + "\n")
        (tmp / "soc.env").write_text("")
        self.env = dict(
            os.environ, ROOT_DIR=str(tmp), SOC_NO_JOURNAL="1", SOC_ENV_FILE=str(tmp / "soc.env"),
            SOC_PANELS_FILE=str(tmp / "panels.yaml"), SOC_HEARTBEAT_FILE=str(tmp / "hb.json"),
            SOC_WATCHDOG_TICK="1", SOC_HEARTBEAT_STALE="2", SOC_HEARTBEAT_STARTUP="3", **env)
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(["bash", str(self.root / "scripts" / "launcher.sh")],
                                     env=self.env, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        return self

    def __exit__(self, *a):
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait()

    def runs(self):
        try:
            return len((self.root / "runs.log").read_text().splitlines())
        except OSError:
            return 0

    def wait_runs(self, n, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.runs() >= n:
                return True
            time.sleep(0.1)
        return False


def test_a_hung_host_is_killed_and_restarted(tmp_path):
    """The heartbeat stops but the process lives: exactly the frozen-screen case."""
    with Wall(tmp_path, ["hang", "other"]) as wall:
        assert wall.wait_runs(2, timeout=25)


def test_a_host_that_never_beats_is_killed_after_the_startup_limit(tmp_path):
    with Wall(tmp_path, ["silent", "other"]) as wall:
        assert wall.wait_runs(2, timeout=25)


def test_a_beating_host_is_left_alone(tmp_path):
    with Wall(tmp_path, ["beat", "other"]) as wall:
        time.sleep(2.5)                      # past the stale limit: it must survive
        assert wall.runs() == 1


def test_clock_jump_does_not_look_like_a_hang(tmp_path):
    """No battery-backed clock: NTP moves the date after boot. A file timestamped
    far in the past or future must not count as stale while it keeps changing."""
    with Wall(tmp_path, ["beat", "other"]) as wall:
        time.sleep(1.2)
        os.utime(wall.env["SOC_HEARTBEAT_FILE"], (1, 1))
        time.sleep(1.2)
        assert wall.runs() == 1


def test_unattended_wall_keeps_trying_after_operator_exit(tmp_path, monkeypatch):
    launcher = read("scripts/launcher.sh")
    # Exit 2 means "an operator has to act". On a kiosk nobody will, so it must
    # never reach the menu, which would leave the screen dark.
    branch = launcher[launcher.index('if [ "$code" -eq 2 ]'):]
    assert branch.index("SOC_UNATTENDED") < branch.index("soc-wall-menu")
    assert "continue" in branch[:branch.index("soc-wall-menu")]


def test_host_is_stopped_with_the_session(tmp_path):
    with Wall(tmp_path, ["other"]) as wall:
        assert wall.wait_runs(1, timeout=10)
        pid = int((tmp_path / "runs.log").read_text().split()[1])
        os.kill(wall.proc.pid, signal.SIGTERM)
        wall.proc.wait(timeout=20)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        pytest.fail("host outlived its session")


# --- nothing referenced may be missing --------------------------------------- #

def _tracked_paths():
    out = set()
    for d, dirs, files in os.walk(_REPO):
        dirs[:] = [x for x in dirs if x not in (".git", "__pycache__", ".venv")]
        for f in files:
            out.add(os.path.relpath(os.path.join(d, f), _REPO))
    return out


@pytest.mark.parametrize("rel", ["install.sh", "uninstall.sh", "setup.py", "provision.py",
                                 "scripts/soc-update.py", "scripts/launcher.sh",
                                 "kiosk-host/host/setupgui.py", "kiosk-host/host/websecurity.py",
                                 "kiosk-host/host/main.py", "kiosk-host/host/launchermenu.py"])
def test_no_dangling_repo_paths(rel):
    """Files were dropped from this tree while the code calling them stayed, which
    silently disabled tracker blocking and the provisioner. Keep that from recurring."""
    files = _tracked_paths()
    pat = re.compile(r'(?<![\w./$-])((?:scripts|security|systemd|branding|packaging|inject)/'
                     r'[\w@-]+\.(?:sh|py|conf|service|timer|txt|json|yaml|sudoers|lock|tmpl|tmpfiles))')
    missing = sorted(p for p in set(pat.findall(read(rel))) if p not in files)
    assert not missing, f"{rel} references files that do not exist: {missing}"


def test_nfpm_ships_only_files_that_exist():
    import yaml
    doc = yaml.safe_load(re.sub(r"\$\{[A-Z_]+\}", "x", read("nfpm.yaml")))
    missing = []
    for entry in doc["contents"]:
        src = entry.get("src")
        if src == "./native/soc-wall" and entry.get("dst") == "/opt/soc-display/bin/soc-wall":
            # release.yml provides a different native artifact per architecture.
            assert 'install -m 0755 "$binary" native/soc-wall' in read(".github/workflows/release.yml")
        elif src and "*" not in src and entry.get("type") != "symlink" and not os.path.exists(os.path.join(_REPO, src)):
            missing.append(src)
    assert not missing


def test_package_ships_what_the_venv_builder_needs():
    assert "./requirements.txt" in read("nfpm.yaml")


def test_tracker_blocklist_and_sso_allowlist_ship():
    """Without these the blocker silently blocks nothing and SSO redirects fail."""
    trackers = json.loads(read("security/trackers-top20.json"))
    assert trackers
    assert any(ln.strip() and not ln.startswith("#")
               for ln in read("security/allowlist-sso.txt").splitlines())


# --- installer guarantees ---------------------------------------------------- #

def test_no_remote_script_is_piped_into_root():
    for rel in ("install.sh", "provision.py", "setup.py"):
        assert not re.search(r"curl[^\n|]*\|\s*(sudo\s+)?(ba)?sh", read(rel)), rel


def test_x_server_is_not_opened_to_every_user():
    assert "allowed_users=anybody" not in read("install.sh")
    assert "allowed_users=console" in read("install.sh")


def test_native_vaultwarden_is_the_default():
    assert 'VW_MODE="${VW_MODE:-native}"' in read("install.sh")


def test_native_vaultwarden_can_actually_start():
    """Only the binary is installed: with the web vault left on, Vaultwarden exits
    at startup saying the web vault is missing."""
    assert "WEB_VAULT_ENABLED=false" in read("systemd/vaultwarden.service")


def test_a_redeploy_cannot_overwrite_the_operators_firewall():
    text = read("install.sh")
    block = text[text.index('if [ "$HARDEN" = "1" ] && [ "$ACTIVATE" != "1" ]'):]
    assert 'cp "$SOC_ROOT/security/nftables.conf" /etc/nftables.conf' in block
    assert text.count("/etc/nftables.conf\n") == block.count("/etc/nftables.conf\n")


def test_a_manual_rerun_cannot_overwrite_the_operators_firewall():
    """HARDEN is remembered, so any re-run reaches this block. Replacing the file would
    wipe the admin subnet and egress sets, and cut the box off at the next boot."""
    text = read("install.sh")
    copy = text.index('cp "$SOC_ROOT/security/nftables.conf" /etc/nftables.conf')
    guard = text.rindex("if grep -q '^# SOC wall firewall' /etc/nftables.conf", 0, copy)
    assert "else" in text[guard:copy]
    assert read("security/nftables.conf").startswith("#!/usr/sbin/nft -f\n# SOC wall firewall")


def test_user_homes_are_only_touched_as_that_user():
    """A compromised renderer owns ~soc. Root following a symlink planted there, on an
    unattended redeploy, would chown a system path to it: a full root takeover."""
    text = read("install.sh")
    block = text[text.index('log "Configuring kiosk session for'):text.index("# Capture the original default target")]
    assert 'as_user "$KIOSK_USER"' in block and 'as_user "$DESKTOP_USER"' in block
    # Everything inside the heredoc runs as the user; only what's left runs as root.
    as_root = re.sub(r"<<'SESSION'.*?\nSESSION\n", "", block, flags=re.S)
    for touches_home in ('install -d -o', 'chown -R', '$HOME/', '"$HOME_DIR/', 'cp "'):
        assert touches_home not in as_root, touches_home


def test_reinstalling_the_live_commit_never_deletes_the_live_release():
    text = read("install.sh")
    assert 'rm -rf "$REL_DIR"' not in text
    assert '[ -e "$RELEASES/$REL_ID" ] && REL_ID=' in text


def test_a_config_that_wont_load_cannot_switch_a_tunnel_off():
    text = read("install.sh")
    fn = text[text.index("sync_unit_with_config(){"):]
    assert "*) warn" in fn[:fn.index("}\n")]
    assert 'except Exception' in text[text.index("config_wants(){"):text.index("sync_unit_with_config(){")]


def test_installer_and_updater_share_one_lock():
    """Without it, a manual run swaps the release mid health check, and that good
    commit is rolled back and blocklisted."""
    assert "exec 9>/var/lib/soc-update/lock" in read("install.sh")
    assert 'os.path.join(STATE_DIR, "lock")' in read("scripts/soc-update.py")


@pytest.mark.parametrize("name,key", [("SOC_TARPIT_ENABLE", "tarpit"),
                                      ("SOC_KEEP_SERVICES", "keep_services"),
                                      ("SOC_SKIP_PACKAGES", "skip_packages")])
def test_operator_choices_survive_a_redeploy(name, key):
    """A redeploy passes no environment, so a choice made once must be remembered, or
    it would disable the tarpit and Bluetooth behind the operator's back."""
    text = read("install.sh")
    assert f"keep_choice {name} {key}" in text
    assert f"printf 'META|{key}|%s\\n'" in text


def test_redeploy_is_off_rather_than_guessing_when_the_source_is_unknown():
    text = read("install.sh")
    block = text[text.index("_new_update_env=1"):text.index("# Vaultwarden config is inline")]
    assert "SOC_UPDATE_ENABLE=0" in block


def test_a_redeploy_never_touches_the_package_manager():
    text = read("install.sh")
    assert '[ "$ACTIVATE" = "1" ] && SKIP_PACKAGES=1' in text
    assert text.index("SKIP_PACKAGES=1") < text.index('log "Refreshing package metadata"')


def _revert_helper(tmp_path, manifest):
    """install.sh's real manifest_row + its capture logic, under bash."""
    text = read("install.sh")
    fn = text[text.index("manifest_row(){"):text.index("keep_choice(){")]
    (tmp_path / ".install-manifest").write_text(manifest)
    script = (f'ETC={tmp_path}\n{fn}\n'
              'ORIG="$(manifest_row REVERT orig_default_target)"\n'
              '[ -n "$ORIG" ] || ORIG=multi-user.target\n'   # what get-default says now
              'echo "$ORIG"\n')
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout.strip()


def test_rerun_keeps_the_original_boot_target_for_uninstall(tmp_path):
    """Every redeploy re-runs this. Re-capturing would record multi-user.target, the
    value we set ourselves, and uninstall could never restore the desktop."""
    assert _revert_helper(tmp_path, "REVERT|orig_default_target|graphical.target\n") \
        == "graphical.target"


def test_first_install_captures_the_boot_target(tmp_path):
    assert _revert_helper(tmp_path, "META|version|1\n") == "multi-user.target"


def test_uninstall_understands_the_rows_install_writes():
    text = read("uninstall.sh")
    assert "releases)" in text and "trimmed_units)" in text
    assert 'rm_path "${RELEASES:-/opt/soc-releases}"' in text


def test_install_and_updater_exclude_the_same_dev_files():
    install = read("install.sh")
    updater = load("scripts/soc-update.py", "soc_update_excl")
    for name in updater.EXCLUDES:
        assert f"--exclude='./{name}'" in install, name


# --- sudoers ------------------------------------------------------------------ #

def _sudo_commands():
    text = read("security/soc-wall-restart.sudoers")
    body = text[text.index("NOPASSWD:") + len("NOPASSWD:"):].replace("\\\n", " ")
    return [" ".join(c.split()) for c in body.split(",") if c.strip()]


def test_sudoers_has_no_wildcards():
    """In sudoers `*` matches spaces. A wildcard would let a compromised renderer
    append any unit, or hand journalctl any flag, as root."""
    assert all("*" not in c for c in _sudo_commands())


def test_sudoers_only_names_units_that_exist():
    for cmd in _sudo_commands():
        for unit in re.findall(r"[\w-]+\.service", cmd):
            assert os.path.exists(os.path.join(_REPO, "systemd", unit)), unit


def test_sudoers_matches_the_exact_commands_the_host_runs():
    """sudo matches argv literally: a mismatch here fails silently as 'no permission'."""
    viewer = read("kiosk-host/host/vpn_log_viewer.py")
    commands = _sudo_commands()
    assert "/usr/bin/journalctl -u forti-vpn.service -n 0 --no-pager" in commands
    assert "/usr/bin/journalctl -u forti-vpn.service -f --no-pager -n 100 -o cat" in commands
    assert '"-n", "0", "--no-pager"' in viewer
    assert '"-u", _VPN_UNIT, "-f", "--no-pager"' in viewer


# --- firewall ------------------------------------------------------------------ #

def test_firewall_lets_only_the_updater_out_on_https():
    text = read("security/nftables.conf")
    assert "meta skuid { 0, $update_uid } tcp dport 443 accept" in text
    # the only other 443 is to pinned VPN gateways
    other = [ln for ln in text.splitlines() if "443" in ln and "skuid" not in ln
             and not ln.strip().startswith("#")]
    assert all("@vpn_gateways" in ln for ln in other)


@pytest.mark.skipif(shutil.which("nft") is None or shutil.which("unshare") is None,
                    reason="needs nft + unshare")
def test_firewall_ruleset_parses():
    r = subprocess.run(["unshare", "-Urn", "nft", "-c", "-f",
                        os.path.join(_REPO, "security", "nftables.conf")],
                       capture_output=True, text=True)
    if "Operation not permitted" in r.stderr:
        pytest.skip("user namespaces unavailable here")
    assert r.returncode == 0, r.stderr


# --- wall unit + vault unit ---------------------------------------------------- #

def test_timer_is_calendar_based_so_a_failed_run_cannot_stop_updates():
    lines = [ln for ln in read("systemd/soc-update.timer").splitlines()
             if not ln.startswith("#")]
    assert any(ln.startswith("OnCalendar=") for ln in lines)
    assert not any(ln.startswith("OnUnitActiveSec") for ln in lines)


def test_updater_runs_independently_of_the_venv():
    """A release that breaks the venv must not also break what recovers from it."""
    exec_line = next(ln for ln in read("systemd/soc-update.service").splitlines()
                     if ln.startswith("ExecStart="))
    assert exec_line == "ExecStart=/opt/soc-display/scripts/soc-update.sh run"
    wrapper = read("scripts/soc-update.sh")
    assert 'exec "$NATIVE" update "$@"' in wrapper
    assert '.venv' not in wrapper
    assert ".venv" not in exec_line


def test_updater_is_stdlib_only():
    import ast
    allowed = set(sys.stdlib_module_names)
    tree = ast.parse(read("scripts/soc-update.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mods = [node.module or ""]
        else:
            continue
        assert all(m.split(".")[0] in allowed for m in mods), mods


# --- setup + provision --------------------------------------------------------- #

@pytest.fixture
def setup_mod():
    return load("setup.py", "soc_setup_layer")


@pytest.fixture
def prov():
    return load("provision.py", "soc_provision_layer")


def test_defaults_mode_never_invents_a_vault_master(setup_mod, monkeypatch):
    """`--defaults` used to return the literal CHANGE-ME, which would then be sealed
    and registered as the real master password."""
    monkeypatch.setattr(setup_mod, "ASSUME_DEFAULTS", True)
    assert setup_mod.ask_secret("vault master password") == ""
    assert "CHANGE-ME" not in read("setup.py").replace(
        '"CHANGE-ME" default', "")


class _DeployArgs:
    target = "pi"; dry_run = False; defaults = False; section = "all"; clean = False
    fresh = False; unattended = True; master_fd = None; creds_fd = None; config = ""
    email = "a@b.c"; url = "http://127.0.0.1:8222"; mode = None; pin = ""; seed = True


def test_unattended_deploy_refuses_without_a_master(setup_mod, monkeypatch):
    monkeypatch.setattr(setup_mod.os, "geteuid", lambda: 0)
    assert setup_mod.cmd_deploy(_DeployArgs()) == 1


def test_venv_hop_keeps_running_this_script(setup_mod, monkeypatch):
    """A newer clone must not quietly exec the older setup.py already in /opt."""
    seen = {}
    monkeypatch.delenv("SOC_SETUP_IN_VENV", raising=False)
    monkeypatch.setattr(setup_mod.os.path, "exists", lambda p: p.endswith("/bin/python"))

    def fake_exec(py, argv):
        seen["script"] = argv[1]
    monkeypatch.setattr(setup_mod.os, "execv", fake_exec)
    setup_mod._hop_into_venv()
    assert seen["script"] == os.path.abspath(setup_mod.__file__)


def test_fresh_survives_the_hop_at_startup(setup_mod, monkeypatch):
    monkeypatch.setenv("SOC_SETUP_IN_VENV", "1")
    monkeypatch.delenv("SOC_SETUP_INSTALLED", raising=False)
    assert 'not os.environ.get("SOC_SETUP_INSTALLED")' in read("setup.py")
    assert 'fresh = getattr(args, "fresh", False) and not os.environ.get("SOC_SETUP_IN_VENV")' \
        not in read("setup.py")


def test_creds_fd_reads_json_without_touching_argv(setup_mod, tmp_path):
    p = tmp_path / "creds.json"
    p.write_text(json.dumps({"SOC Panel 1": {"username": "u", "password": "p"}}))
    fd = os.open(str(p), os.O_RDONLY)
    try:
        class A:
            creds_fd = fd
        assert setup_mod._read_creds_fd(A())["SOC Panel 1"]["password"] == "p"
    finally:
        os.close(fd)


def test_old_env_file_can_be_rerendered(setup_mod):
    """A soc.env from before a key existed must not crash a redeploy of the config."""
    out = setup_mod.render_soc_env({"SOC_VAULT_EMAIL": "a@b.c"})
    assert "SOC_VAULT_EMAIL=" in out and "SOC_ROOT=/opt/soc-display" in out


def test_rerender_keeps_unattended_and_master_source(setup_mod):
    out = setup_mod.render_soc_env({"SOC_UNATTENDED": "1", "SOC_MASTER_SOURCE": "sealed"})
    assert "SOC_UNATTENDED=1" in out and "SOC_MASTER_SOURCE=sealed" in out


def test_rerender_keeps_settings_it_does_not_know_about(setup_mod):
    """Dropping unknown keys would silently undo a lockdown like this one on the next
    deploy, and the operator would have no way to notice."""
    out = setup_mod.render_soc_env({"SOC_ONSCREEN_CONFIG": "0"})
    assert "SOC_ONSCREEN_CONFIG=0" in out


def test_rerender_never_carries_a_plaintext_master_forward(setup_mod):
    out = setup_mod.render_soc_env({"SOC_VAULT_PASSWORD": "hunter2", "SOC_PINENTRY": "x"})
    assert "hunter2" not in out and "SOC_VAULT_PASSWORD" not in out
    assert "SOC_PINENTRY" not in out


def test_rendered_env_round_trips_through_the_loader(setup_mod, tmp_path):
    p = tmp_path / "soc.env"
    p.write_text(setup_mod.render_soc_env({"SOC_ONSCREEN_CONFIG": "0", "SOC_UNATTENDED": "1"}))
    loaded = setup_mod.load_env_file(str(p))
    assert loaded["SOC_ONSCREEN_CONFIG"] == "0" and loaded["SOC_UNATTENDED"] == "1"


@pytest.mark.parametrize("bad", ["a b", "../x", "p;rm", ""])
def test_panel_ids_are_restricted(setup_mod, bad):
    assert setup_mod.v_panel_id(bad)


def test_a_supplied_config_is_installed_as_written(prov, tmp_path, monkeypatch):
    """Found by a real deploy: re-rendering a minimal config crashed on the optional
    sections it left out, and would have dropped anything it didn't know about."""
    written = []

    class Setup:
        @staticmethod
        def write_file(path, content, mode, dry):
            written.append(path)

        @staticmethod
        def render_panels_yaml(cfg):
            raise KeyError("tunnel")

        @staticmethod
        def render_soc_env(env):
            return ""

        @staticmethod
        def render_wall_unit(env, soc_root=""):
            return ""

        @staticmethod
        def _drop_marker(paths, dry):
            pass
    monkeypatch.setattr(prov, "_load_setup", lambda: Setup)
    paths = dict(panels_out="/p", panels_mode=0o644, soc_env="/e", env_mode=0o644,
                 wall_unit="/u", soc_root="/r")
    res = prov.step_write_config(prov.Opts(keep_panels=True), {"display": {"cols": 1}}, {}, paths)
    assert res.ok and "/p" not in written and "/e" in written


def test_wall_and_getty_are_not_both_enabled(prov, monkeypatch):
    """They Conflict: enabling both makes them race for tty1 at boot."""
    calls = []
    monkeypatch.setattr(prov, "_have", lambda b: True)
    monkeypatch.setattr(prov, "_run", lambda cmd, **k: calls.append(cmd) or 0)
    prov.step_units(prov.Opts(mode="kiosk"))
    assert ["systemctl", "enable", "getty@tty1.service"] in calls
    assert not any("soc-wall.service" in c for c in calls)


class FakeSession:
    instances = []

    def __init__(self, url, email, master):
        self.writes = {}
        self.existing = dict(FakeSession.start)
        FakeSession.instances.append(self)

    def list_logins(self):                   # dicts, as the real Session returns
        return [{"name": n, "username": ""} for n in self.existing]

    def upsert_login(self, name, username, password, uri=None):
        self.writes[name] = (username, password)


def _seed(prov, monkeypatch, existing, creds=None):
    class VS:
        Session = FakeSession

        @staticmethod
        def available():
            return True
    FakeSession.start = existing
    FakeSession.instances = []
    monkeypatch.setattr(prov, "_load_vaultseed", lambda: VS)
    monkeypatch.setattr(prov, "_config_vault_items",
                        lambda cfg: [("panel", "A", ""), ("panel", "B", "")])
    res = prov.step_vault_seed(prov.Opts(email="a@b.c"), "m", {}, creds)
    return res, FakeSession.instances[0].writes


def test_reseeding_never_blanks_a_login_that_already_exists(prov, monkeypatch):
    """upsert with empty values PUTs over the item: a re-run used to destroy every
    stored credential."""
    res, writes = _seed(prov, monkeypatch, {"A": 1})
    assert res.ok
    assert "A" not in writes                 # untouched
    assert writes["B"] == ("", "")           # only the missing one gets a placeholder


def test_supplied_creds_are_written_even_over_an_existing_item(prov, monkeypatch):
    _, writes = _seed(prov, monkeypatch, {"A": 1},
                      {"A": {"username": "u", "password": "p"}})
    assert writes["A"] == ("u", "p")


def test_seed_logs_in_once_for_the_whole_run(prov, monkeypatch):
    _seed(prov, monkeypatch, {})
    assert len(FakeSession.instances) == 1   # each login costs a PBKDF2 derivation


def _signups(prov, monkeypatch, tmp_path, alive=True):
    dropin = tmp_path / "run" / "vaultwarden.service.d" / "soc-signups.conf"
    calls = []
    monkeypatch.setattr(prov, "_SIGNUP_DROPIN", str(dropin))
    monkeypatch.setattr(prov, "_run", lambda cmd, **k: calls.append(cmd) or 0)
    monkeypatch.setattr(prov, "_alive", lambda url, timeout=20.0: alive)
    return dropin, calls


def test_signups_open_only_inside_the_block(prov, monkeypatch, tmp_path):
    dropin, _ = _signups(prov, monkeypatch, tmp_path)
    with prov._SignupsOpen("http://x"):
        assert "SIGNUPS_ALLOWED=true" in dropin.read_text()
    assert not dropin.exists()


def test_signups_close_even_when_registration_fails(prov, monkeypatch, tmp_path):
    dropin, calls = _signups(prov, monkeypatch, tmp_path)
    with pytest.raises(RuntimeError):
        with prov._SignupsOpen("http://x"):
            raise RuntimeError("register failed")
    assert not dropin.exists()
    assert calls.count(["systemctl", "restart", "vaultwarden"]) == 2


def test_failing_to_close_signups_is_loud(prov, monkeypatch, tmp_path):
    dropin, _ = _signups(prov, monkeypatch, tmp_path)
    with pytest.raises(prov.ProvisionError):
        with prov._SignupsOpen("http://x"):
            prov._alive = lambda url, timeout=20.0: False


def test_signup_dropin_is_volatile_so_a_power_cut_cannot_leave_signups_open(prov):
    assert prov._SIGNUP_DROPIN.startswith("/run/")


# --- jump-host pinning ---------------------------------------------------------- #

@pytest.fixture
def pin():
    return load("scripts/pin-jump-host.py", "soc_pin_jump")


@pytest.mark.parametrize("spec,host", [("user@jump.example", "jump.example"),
                                       ("jump.example", "jump.example")])
def test_host_of(pin, spec, host):
    assert pin.host_of(spec) == host


def test_keys_are_appended_atomically_and_readable_by_the_tunnel(pin, tmp_path):
    path = tmp_path / "known_hosts"
    path.write_text("old.example ssh-ed25519 AAAA\n")
    pin.append_atomic(str(path), ["jump.example ssh-ed25519 BBBB"])
    assert path.read_text() == ("old.example ssh-ed25519 AAAA\n"
                                "jump.example ssh-ed25519 BBBB\n")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert [f.name for f in tmp_path.iterdir()] == ["known_hosts"]


def _pin_config(tmp_path, monkeypatch, pin, **tunnel):
    cfg = tmp_path / "panels.yaml"
    known = tmp_path / "known_hosts"
    monkeypatch.setenv("SOC_PANELS_FILE", str(cfg))
    monkeypatch.setattr(pin, "KNOWN_HOSTS", str(known))

    class Conf:
        pass
    Conf.tunnel = tunnel
    monkeypatch.setattr(pin.cfg, "load", lambda p: Conf)
    return known


def test_first_start_pins_the_key(pin, tmp_path, monkeypatch):
    known = _pin_config(tmp_path, monkeypatch, pin, jump_host="user@jump.example")
    monkeypatch.setattr(pin, "scan", lambda h: [f"{h} ssh-ed25519 KEY"])
    assert pin.main() == 0
    assert "jump.example ssh-ed25519 KEY" in known.read_text()


def test_an_already_pinned_key_is_never_replaced(pin, tmp_path, monkeypatch):
    """This is the whole security property: a later MITM must not get re-pinned."""
    known = _pin_config(tmp_path, monkeypatch, pin, jump_host="jump.example")
    known.write_text("jump.example ssh-ed25519 ORIGINAL\n")
    monkeypatch.setattr(pin, "pinned", lambda p, h: True)
    monkeypatch.setattr(pin, "scan", lambda h: pytest.fail("must not rescan a pinned host"))
    assert pin.main() == 0
    assert known.read_text() == "jump.example ssh-ed25519 ORIGINAL\n"


def test_an_operator_managed_file_is_left_alone(pin, tmp_path, monkeypatch):
    _pin_config(tmp_path, monkeypatch, pin, jump_host="j.example", known_hosts="/x")
    monkeypatch.setattr(pin, "scan", lambda h: pytest.fail("operator owns this"))
    assert pin.main() == 0


def test_unreachable_host_does_not_fail_the_service(pin, tmp_path, monkeypatch):
    known = _pin_config(tmp_path, monkeypatch, pin, jump_host="j.example")
    monkeypatch.setattr(pin, "scan", lambda h: [])
    assert pin.main() == 0
    assert not known.exists()


def test_pinning_never_runs_as_root_in_the_tunnel_users_directory(pin, tmp_path, monkeypatch):
    """That directory belongs to the tunnel user. As root, a symlink planted there
    would read /etc/shadow into a file they can read."""
    calls = []
    monkeypatch.setattr(pin, "KNOWN_HOSTS", str(tmp_path / "known_hosts"))
    monkeypatch.setattr(pin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pin.os, "setgroups", lambda g: calls.append("groups"))
    monkeypatch.setattr(pin.os, "setgid", lambda g: calls.append(("gid", g)))
    monkeypatch.setattr(pin.os, "setuid", lambda u: calls.append(("uid", u)))
    pin.drop_privileges()
    st = os.stat(tmp_path)
    assert calls == ["groups", ("gid", st.st_gid), ("uid", st.st_uid)]   # uid last


def test_tunnel_uses_the_pinned_file_when_it_exists(tmp_path, monkeypatch):
    args = load("scripts/tunnel-args.py", "soc_tunnel_args_pin")
    known = tmp_path / "known_hosts"
    known.write_text("x\n")
    monkeypatch.setattr(args, "PINNED_KNOWN_HOSTS", str(known))
    panels = tmp_path / "panels.yaml"
    panels.write_text(read("config/panels.yaml"))

    class P:
        mode = "tunnel"
        id = "p1"
        tunnel = {"local_port": 19101, "remote_host": "10.0.0.5", "remote_port": 443}

    class Conf:
        tunnel = {"enabled": True, "jump_host": "user@jump.example"}
        panels = [P]
    monkeypatch.setattr(args.cfg, "load", lambda p: Conf)
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    args.main()
    assert f"UserKnownHostsFile={known}" in out.getvalue()
    assert "StrictHostKeyChecking=yes" in out.getvalue()


def test_tunnel_service_pins_before_it_connects():
    unit = read("systemd/autossh-tunnel.service")
    assert unit.index("ExecStartPre=-+") < unit.index("ExecStart=/opt")


# --- Vaultwarden fetch: an offline registry ------------------------------------- #

@pytest.fixture
def fv():
    return load("scripts/fetch-vaultwarden.py", "soc_fetch_vw")


def _elf(machine):
    head = bytearray(b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 9 + b"\x02\0")
    head += machine.to_bytes(2, "little")
    return bytes(head) + b"\0" * 64


def _layer(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class FakeRegistry:
    """Serves real bytes by digest, exactly as a registry does, with one seam for
    tampering. Everything above the HTTP call runs for real."""

    def __init__(self, fv, monkeypatch, binary):
        self.fv = fv
        layer = _layer({"etc/motd": b"hi", "vaultwarden": binary})
        base = _layer({"bin/sh": b"#!"})
        self.blobs = {_sha(base): base, _sha(layer): layer}
        self.manifest = json.dumps({"layers": [{"digest": _sha(base)},
                                               {"digest": _sha(layer)}]}).encode()
        self.index = json.dumps({"manifests": [
            {"digest": _sha(self.manifest),
             "platform": {"os": "linux", "architecture": "arm64"}}]}).encode()
        self.docs = {_sha(self.index): self.index, _sha(self.manifest): self.manifest}
        self.fetched_blobs = []

        reg = self

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_open(url, headers):
            if "auth.docker.io" in url:
                return Resp(b'{"token": "t"}')
            digest = url.rsplit("/", 1)[1]
            if "/blobs/" in url:
                reg.fetched_blobs.append(digest)
                return Resp(reg.blobs[digest])
            return Resp(reg.docs[digest])
        monkeypatch.setattr(fv, "_open", fake_open)

    @property
    def lock(self):
        return {"image": "vaultwarden/server", "tag": "1.37.5-alpine",
                "digest": _sha(self.index)}


def test_installs_the_binary_and_records_the_version(fv, monkeypatch, tmp_path):
    reg = FakeRegistry(fv, monkeypatch, _elf(183))
    dest = tmp_path / "vaultwarden"
    fv.install(reg.lock, str(dest), "aarch64")
    assert dest.read_bytes() == _elf(183)
    assert os.access(dest, os.X_OK)
    assert fv.read_stamp(str(dest))["tag"] == "1.37.5-alpine"


def test_newest_layer_is_searched_first_to_avoid_needless_downloads(fv, monkeypatch, tmp_path):
    reg = FakeRegistry(fv, monkeypatch, _elf(183))
    fv.install(reg.lock, str(tmp_path / "vw"), "aarch64")
    assert len(reg.fetched_blobs) == 1


def _assert_nothing_installed(tmp_path):
    assert list(tmp_path.iterdir()) == []


def test_tampered_index_is_refused(fv, monkeypatch, tmp_path):
    reg = FakeRegistry(fv, monkeypatch, _elf(183))
    lock = reg.lock
    reg.docs[lock["digest"]] = reg.index + b" "
    with pytest.raises(fv.FetchError, match="digest mismatch"):
        fv.install(lock, str(tmp_path / "vw"), "aarch64")
    _assert_nothing_installed(tmp_path)


def test_tampered_manifest_is_refused(fv, monkeypatch, tmp_path):
    reg = FakeRegistry(fv, monkeypatch, _elf(183))
    reg.docs[_sha(reg.manifest)] = reg.manifest + b" "
    with pytest.raises(fv.FetchError, match="digest mismatch"):
        fv.install(reg.lock, str(tmp_path / "vw"), "aarch64")
    _assert_nothing_installed(tmp_path)


def test_tampered_layer_is_refused_and_not_retried(fv, monkeypatch, tmp_path):
    reg = FakeRegistry(fv, monkeypatch, _elf(183))
    digest = json.loads(reg.manifest)["layers"][-1]["digest"]
    reg.blobs[digest] = reg.blobs[digest] + b"x"
    with pytest.raises(fv.FetchError, match="digest mismatch"):
        fv.install(reg.lock, str(tmp_path / "vw"), "aarch64")
    assert reg.fetched_blobs.count(digest) == 1
    _assert_nothing_installed(tmp_path)


def test_wrong_cpu_binary_is_refused_without_being_run(fv, monkeypatch, tmp_path):
    reg = FakeRegistry(fv, monkeypatch, _elf(62))          # x86-64 under an arm64 label
    with pytest.raises(fv.FetchError, match="ELF machine"):
        fv.install(reg.lock, str(tmp_path / "vw"), "aarch64")
    _assert_nothing_installed(tmp_path)


def test_missing_architecture_is_refused(fv, monkeypatch, tmp_path):
    reg = FakeRegistry(fv, monkeypatch, _elf(62))
    with pytest.raises(fv.FetchError, match="no linux/amd64"):
        fv.install(reg.lock, str(tmp_path / "vw"), "x86_64")


def test_non_https_is_refused(fv):
    with pytest.raises(fv.FetchError):
        fv._open("http://registry-1.docker.io/v2/", {})


LOCK = {"image": "i", "tag": "1.37.5-alpine", "digest": "sha256:" + "a" * 64}


def _installed(tmp_path, tag, digest="sha256:" + "b" * 64):
    dest = tmp_path / "vaultwarden"
    dest.write_bytes(b"x")
    (tmp_path / "vaultwarden.lock-stamp").write_text(f"{tag} {digest}\n")
    return str(dest)


def test_fresh_box_installs(fv, tmp_path):
    assert fv.decide(LOCK, str(tmp_path / "vaultwarden"))


def test_same_digest_is_left_alone(fv, tmp_path):
    assert fv.decide(LOCK, _installed(tmp_path, "1.37.5-alpine", LOCK["digest"])) is None


def test_newer_lock_upgrades(fv, tmp_path):
    assert fv.decide(LOCK, _installed(tmp_path, "1.36.0-alpine"))


def test_a_rollback_never_downgrades_vaultwarden(fv, tmp_path):
    """Its database migrations only run forwards, so an older binary on a migrated
    database could lose the vault. A rolled-back release keeps the newer binary."""
    assert fv.decide(LOCK, _installed(tmp_path, "1.38.0-alpine")) is None


def test_a_binary_someone_else_installed_is_respected(fv, tmp_path):
    dest = tmp_path / "vaultwarden"
    dest.write_bytes(b"x")
    assert fv.decide(LOCK, str(dest)) is None


def test_shipped_lock_is_valid(fv):
    lock = fv.read_lock(os.path.join(_REPO, "security", "vaultwarden.lock"))
    assert lock["tag"].endswith("-alpine")     # static binary: no libc dependency
