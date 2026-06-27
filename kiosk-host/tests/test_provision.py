"""Provisioning-core (provision.py) — dry-run plan + idempotency + CLI/GUI parity.

These tests NEVER mutate the box: everything runs under SOC_PROVISION_DRY_RUN so
useradd/usermod/install.sh/systemctl are PRINTED, never executed, and the
host-state probes are monkeypatched to simulate fresh-vs-provisioned boxes.

What they lock in:
  * plan() enumerates BOTH the kiosk AND the desktop user (+ service) with the
    right groups + the right useradd/usermod command lines.
  * a fully-provisioned box yields ZERO shell-step changes (the no-op assertion).
  * step_users emits the exact useradd/usermod argv for both users.
  * the CLI subcommands and the GUI reach the SAME core symbols (parity by
    construction — they import the one provision module).
"""
import importlib.util
import os
import sys

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _load_provision():
    # Import as the real top-level name `provision` (with sys.modules registered)
    # so its @dataclass(field=...) definitions resolve — the same way setup.py
    # imports it. This is also the SAME module object setup.py re-exports.
    if _REPO not in sys.path:
        sys.path.insert(0, _REPO)
    if "provision" in sys.modules:
        return sys.modules["provision"]
    import provision  # noqa: PLC0415
    return provision


@pytest.fixture()
def prov(monkeypatch):
    monkeypatch.setenv("SOC_PROVISION_DRY_RUN", "1")
    return _load_provision()


def _fresh_box(prov, monkeypatch):
    """Simulate a box where NO soc users exist + nothing is deployed."""
    monkeypatch.setattr(prov, "_user_exists", lambda n: False)
    monkeypatch.setattr(prov, "_group_exists", lambda n: True)
    monkeypatch.setattr(prov, "_user_groups", lambda n: set())
    monkeypatch.setattr(prov, "_installed", lambda o: False)
    monkeypatch.setattr(os.path, "isdir",
                        lambda x: False if x == "/opt/soc-display" else os.path.lexists(x))


def _provisioned_box(prov, monkeypatch):
    """Simulate a box where every user exists + is in every group + is deployed."""
    monkeypatch.setattr(prov, "_user_exists", lambda n: True)
    monkeypatch.setattr(prov, "_group_exists", lambda n: True)
    monkeypatch.setattr(prov, "_user_groups",
                        lambda n: set(prov.KIOSK_GROUPS) | set(prov.DESKTOP_GROUPS))
    monkeypatch.setattr(prov, "_installed", lambda o: True)
    monkeypatch.setattr(os.path, "isdir",
                        lambda x: True if x == "/opt/soc-display" else os.path.lexists(x))


def test_plan_enumerates_both_users(prov, monkeypatch):
    _fresh_box(prov, monkeypatch)
    opts = prov.Opts(mode="kiosk", kiosk_user="soc", desktop_user="socwall",
                     svc_user="socsvc", dry_run=True)
    plan = prov.plan(opts)
    descs = [a.desc for a in plan.actions]
    assert any("kiosk user 'soc'" in d for d in descs)
    assert any("desktop user 'socwall'" in d for d in descs)
    assert any("service user 'socsvc'" in d for d in descs)

    # the exact useradd command lines for both interactive users
    cmds = [" ".join(a.cmd) for a in plan.actions if a.cmd]
    assert "useradd -m -s /bin/bash soc" in cmds
    assert "useradd -m -s /bin/bash socwall" in cmds
    # service user is a system nologin account
    assert any(c.startswith("useradd -r -m -s") and c.endswith("socsvc") for c in cmds)


def test_plan_group_assignments(prov, monkeypatch):
    _fresh_box(prov, monkeypatch)
    opts = prov.Opts(dry_run=True)
    cmds = [" ".join(a.cmd) for a in prov.plan(opts).actions if a.cmd]
    # kiosk OWNS tty1 -> tty + seat; desktop runs inside a DE -> NO tty/seat.
    assert "usermod -aG tty soc" in cmds
    assert "usermod -aG seat soc" in cmds
    assert "usermod -aG video socwall" in cmds
    assert "usermod -aG tty socwall" not in cmds
    assert "usermod -aG seat socwall" not in cmds


def test_plan_includes_packages_and_deploy_commands(prov, monkeypatch):
    _fresh_box(prov, monkeypatch)
    opts = prov.Opts(dry_run=True)
    cmds = [" ".join(a.cmd) for a in prov.plan(opts).actions if a.cmd]
    assert any(c.endswith("install.sh --deps-only") for c in cmds)
    assert any(c.endswith("/install.sh") for c in cmds)
    assert "systemctl start vaultwarden" in cmds


def test_second_run_is_a_noop(prov, monkeypatch):
    """The whole point of idempotency: a provisioned box has zero shell changes."""
    _provisioned_box(prov, monkeypatch)
    opts = prov.Opts(dry_run=True)
    plan = prov.plan(opts)
    shell_changes = [a for a in plan.changes
                     if a.step in ("packages", "users", "deploy")]
    assert shell_changes == [], [a.desc for a in shell_changes]


def test_step_users_dry_run_emits_both_users(prov, monkeypatch):
    _fresh_box(prov, monkeypatch)
    opts = prov.Opts(kiosk_user="soc", desktop_user="socwall", svc_user="socsvc",
                     dry_run=True)
    res = prov.step_users(opts)
    assert res.ok
    assert res.changed is False  # dry-run never reports a real mutation
    flat = [" ".join(c) for c in res.cmds]
    assert "useradd -m -s /bin/bash soc" in flat
    assert "useradd -m -s /bin/bash socwall" in flat


def test_step_users_dry_run_reads_real_groups_on_provisioned_box(prov, monkeypatch):
    """Regression: under dry-run, step_users must read the REAL group membership of
    an existing user (a read-only probe) so it does NOT reprint usermod -aG for
    groups the user already has. On a fully-provisioned box the printout is a pure
    no-op (zero usermod commands), matching plan()."""
    _provisioned_box(prov, monkeypatch)  # every user exists + is in every group
    opts = prov.Opts(kiosk_user="soc", desktop_user="socwall", svc_user="socsvc",
                     dry_run=True)
    res = prov.step_users(opts)
    assert res.ok and res.changed is False
    flat = [" ".join(c) for c in res.cmds]
    # nothing to create, nothing to add — the dry-run plan reflects reality.
    assert not any(c.startswith("useradd") for c in flat), flat
    assert not any(c.startswith("usermod") for c in flat), flat


def test_install_sh_is_single_shared_engine(prov):
    """The deploy engine is one file via one helper — plan/step_deploy/step_packages
    all name provision.install_sh(); install_env_knobs() carries the user knobs."""
    assert prov.install_sh().endswith("install.sh")
    opts = prov.Opts(mode="kiosk", kiosk_user="soc", desktop_user="socwall",
                     svc_user="socsvc")
    knobs = prov.install_env_knobs(opts)
    assert knobs["INSTALL_MODE"] == "kiosk"
    assert knobs["KIOSK_USER"] == "soc"
    assert knobs["DESKTOP_USER"] == "socwall"
    assert knobs["SVC_USER"] == "socsvc"


def test_step_packages_fastpaths_when_installed(prov, monkeypatch):
    _provisioned_box(prov, monkeypatch)
    opts = prov.Opts(dry_run=True)
    res = prov.step_packages(opts)
    assert res.ok and res.changed is False
    assert "already installed" in res.detail


def test_dry_run_never_runs_real_commands(prov, monkeypatch):
    """_run must NOT execute subprocess in dry-run (the no-mutation guarantee)."""
    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("subprocess.run called in dry-run")

    monkeypatch.setattr(prov.subprocess, "run", _boom)
    rc = prov._run(["useradd", "soc"], dry=True)
    assert rc == 0 and called["n"] == 0


def test_cli_and_gui_share_the_same_core(prov):
    """Parity by construction: setup.py and setupgui both reach provision.* — the
    same module object — so there is no parallel implementation to drift."""
    # setup.py re-exports the core
    path = os.path.join(_REPO, "setup.py")
    spec = importlib.util.spec_from_file_location("soc_setup_parity", path)
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)
    assert setup.provision is not None
    assert setup.step_users is setup.provision.step_users
    assert setup.provision_all is setup.provision.provision_all
    assert setup.Opts is setup.provision.Opts


# --------------------------------------------------------------------------- #
# Forgot-master destructive reset — the schema-introspecting deletion core.
# (Pure-sqlite, no service/network — manage_service is bypassed.)
# --------------------------------------------------------------------------- #
def _vw_like_db(path):
    import sqlite3
    con = sqlite3.connect(path)
    # Mirror Vaultwarden's INCONSISTENT cascade: most child tables reference
    # users(uuid) with NO cascade (ciphers), a few WITH cascade (devices); plus a
    # table with no users FK at all (must be left untouched).
    con.executescript(
        "CREATE TABLE users (uuid TEXT PRIMARY KEY, email TEXT);"
        "CREATE TABLE ciphers (uuid TEXT PRIMARY KEY, user_uuid TEXT,"
        " FOREIGN KEY(user_uuid) REFERENCES users(uuid));"
        "CREATE TABLE devices (uuid TEXT PRIMARY KEY, user_uuid TEXT,"
        " FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON DELETE CASCADE);"
        "CREATE TABLE org_policies (uuid TEXT PRIMARY KEY, org TEXT);")
    con.executemany("INSERT INTO users VALUES (?,?)",
                    [("u-keep", "keep@x"), ("u-del", "del@x")])
    con.executemany("INSERT INTO ciphers VALUES (?,?)",
                    [("c1", "u-keep"), ("c2", "u-del"), ("c3", "u-del")])
    con.executemany("INSERT INTO devices VALUES (?,?)",
                    [("d1", "u-keep"), ("d2", "u-del")])
    con.execute("INSERT INTO org_policies VALUES ('p1','o1')")
    con.commit()
    con.close()


def test_delete_user_rows_is_surgical(tmp_path):
    import sqlite3
    prov = _load_provision()
    db = str(tmp_path / "db.sqlite3")
    _vw_like_db(db)
    # case-insensitive email match; returns 1 (a user was deleted)
    assert prov._delete_user_rows(db, "DEL@X") == 1
    con = sqlite3.connect(db)
    users = [r[0] for r in con.execute("SELECT uuid FROM users ORDER BY uuid")]
    ciph = sorted(r[0] for r in con.execute("SELECT user_uuid FROM ciphers"))
    devs = sorted(r[0] for r in con.execute("SELECT user_uuid FROM devices"))
    pols = [r[0] for r in con.execute("SELECT uuid FROM org_policies")]
    con.close()
    assert users == ["u-keep"]        # target user gone, OTHER account intact
    assert ciph == ["u-keep"]         # only the target's non-cascade children removed
    assert devs == ["u-keep"]         # cascade-style children removed too
    assert pols == ["p1"]             # a table with no users-FK is untouched


def test_delete_user_rows_missing_user_is_noop(tmp_path):
    import sqlite3
    prov = _load_provision()
    db = str(tmp_path / "db.sqlite3")
    _vw_like_db(db)
    assert prov._delete_user_rows(db, "nobody@x") == 0   # no match -> 0, nothing touched
    con = sqlite3.connect(db)
    assert sorted(r[0] for r in con.execute("SELECT uuid FROM users")) == ["u-del", "u-keep"]
    con.close()


def test_reset_vault_db_account_backs_up_and_deletes(tmp_path):
    import os as _os
    import sqlite3
    prov = _load_provision()
    df = str(tmp_path)
    _vw_like_db(_os.path.join(df, "db.sqlite3"))
    # manage_service=False bypasses systemctl so the SQL+backup core is testable.
    res = prov.reset_vault_db_account("del@x", data_folder=df, manage_service=False)
    assert res["deleted"] == 1
    assert _os.path.isfile(res["backup"])         # a recoverable backup was taken
    # the backup still has BOTH users (it was copied before the delete)
    con = sqlite3.connect(res["backup"])
    assert sorted(r[0] for r in con.execute("SELECT email FROM users")) == ["del@x", "keep@x"]
    con.close()
