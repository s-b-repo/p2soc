#!/usr/bin/env python3
# =============================================================================
# provision.py — the SHARED PROVISIONING CORE for the SOC video wall.
#
# Pure stdlib (runs BEFORE the venv). This is the SINGLE place both the CLI
# (setup.py subcommands) and the GUI (setupgui via `self.setup.provision_*`)
# call, so the two can never drift. Every step is:
#   * idempotent  — checks present-state first; a re-run is a no-op
#   * dry-run-aware — SOC_PROVISION_DRY_RUN=1 (env) or opts.dry_run prints the
#     exact command it WOULD run, prefixed [dry-run], and mutates nothing
#   * structured  — returns a ProvResult(ok, changed, detail); never raises on a
#     re-run no-op
#
# STEP ORDER (fresh box -> launchable wall):
#   packages -> users -> deploy(/opt+venv+units) -> write_config ->
#   vault_running -> vault_account -> vault_seed -> seal -> doctor
# (vault account BEFORE seal — you can't seal a master that can't log in; the
#  account-create needs the URL from soc.env, so write_config precedes it.)
#
# ESCALATION (trust boundary unchanged): the CLI runs this core AS ROOT. The
# GUI runs the unprivileged parts in-process and escalates the privileged steps
# via the existing pkexec helpers (secrets over STDIN, never argv) OR re-execs
# THIS file by absolute path as `provision.py --provision` (mirrors
# secretstore.py / configpaths.py). Because of that pkexec-by-path contract this
# module imports ONLY stdlib at top level; host/crypto imports are lazy.
# =============================================================================
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

REPO = os.path.dirname(os.path.abspath(__file__))


def _dry() -> bool:
    """Dry-run is on when SOC_PROVISION_DRY_RUN is set (any non-empty value)."""
    return bool(os.environ.get("SOC_PROVISION_DRY_RUN", "").strip())


# --------------------------------------------------------------------------- #
# Result + options types
# --------------------------------------------------------------------------- #
@dataclass
class ProvResult:
    """The outcome of one provisioning step.

    ok       — the step's goal is satisfied (or would be, in dry-run).
    changed  — the step actually mutated host state (False on a re-run no-op AND
               in dry-run, since dry-run never mutates).
    detail   — one-line human summary for the progress report.
    cmds     — the exact command lines the step ran (or WOULD run in dry-run),
               so the dry-run plan + tests can assert on them.
    """
    ok: bool = True
    changed: bool = False
    detail: str = ""
    cmds: list = field(default_factory=list)


@dataclass
class Opts:
    """Everything the provisioning core needs, gathered once. Pure data — no GUI
    / no argparse coupling — so the CLI and GUI build it the same way."""
    mode: str = "kiosk"                 # kiosk | desktop
    kiosk_user: str = "soc"
    desktop_user: str = "socwall"
    svc_user: str = "socsvc"
    email: str = ""
    url: str = "http://127.0.0.1:8222"
    pin: str = ""
    seed: bool = True
    target: str = "pi"                  # resolve_paths target
    fresh: bool = False                 # force OS package reinstall
    dry_run: bool = False               # also honoured via SOC_PROVISION_DRY_RUN
    # master is passed positionally to the vault/seal steps, NEVER stored here as
    # a long-lived attribute and NEVER serialised — no-plaintext guarantee.

    @property
    def dry(self) -> bool:
        return bool(self.dry_run) or _dry()


# A null reporter: steps call report(step_name, status, detail). The CLI prints
# lines; the GUI marshals onto the main loop via idle_add.
def _default_report(step: str, status: str, detail: str = "") -> None:
    tail = f" — {detail}" if detail else ""
    print(f"[provision] {step}: {status}{tail}")


# --------------------------------------------------------------------------- #
# Low-level run helpers (the ONLY place a command is executed or printed)
# --------------------------------------------------------------------------- #
def _print_cmd(cmd: list, dry: bool) -> None:
    pretty = " ".join(cmd)
    print(("[dry-run] " if dry else "$ ") + pretty)


def _run(cmd: list, *, dry: bool, cwd: str = REPO, check: bool = False,
         env: "dict | None" = None) -> int:
    """Run (or, in dry-run, just PRINT) a command. Returns the rc (0 in dry-run).

    Never executes anything when ``dry`` — this is the single chokepoint that
    enforces the no-mutation guarantee for the whole module."""
    _print_cmd(cmd, dry)
    if dry:
        return 0
    try:
        rc = subprocess.run(cmd, cwd=cwd, env=env).returncode
    except FileNotFoundError:
        return 127
    if check and rc != 0:
        raise ProvisionError(f"command failed (rc={rc}): {' '.join(cmd)}")
    return rc


class ProvisionError(Exception):
    """A hard provisioning failure (not a no-op re-run)."""


# --------------------------------------------------------------------------- #
# Host-state probes (idempotency) — all read-only, safe in dry-run
# --------------------------------------------------------------------------- #
def _user_exists(name: str) -> bool:
    if not name:
        return False
    try:
        return subprocess.run(["id", name], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def _group_exists(name: str) -> bool:
    try:
        return subprocess.run(["getent", "group", name],
                              capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def _user_groups(name: str) -> set:
    try:
        out = subprocess.run(["id", "-nG", name], capture_output=True,
                             text=True).stdout
        return set(out.split())
    except FileNotFoundError:
        return set()


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _install_stamp(opts: Opts) -> str:
    return os.path.join(_etc_dir(opts), ".installed")


def _etc_dir(opts: Opts) -> str:
    return "/etc/soc-display"


def _installed(opts: Opts) -> bool:
    """Has a full install.sh run already stamped this box?"""
    return os.path.exists(_install_stamp(opts))


# --------------------------------------------------------------------------- #
# install.sh — THE single shared deploy engine. Both the CLI (provision.step_*)
# AND the GUI control-center's Install button (host.sysaction) invoke EXACTLY
# this script through these helpers, so there is one source of truth for "how the
# wall is deployed" and the two paths cannot drift in which script/knobs they use.
# install.sh is what actually creates the users, builds the venv, installs the
# units and records the manifest; provision.step_users is its idempotent stdlib
# mirror used only for the granular CLI/dry-run paths.
# --------------------------------------------------------------------------- #
def install_sh() -> str:
    """Absolute path to the single deploy engine (install.sh under the repo)."""
    return os.path.join(REPO, "install.sh")


def install_env_knobs(opts: Opts) -> "dict[str, str]":
    """The env knobs install.sh honours for a deploy, derived from `opts`. The GUI
    threads these as `env K=V` ahead of install.sh under pkexec; the CLI sets them
    on the child env. ONE construction, so both elevation paths pass the same set."""
    return {
        "INSTALL_MODE": opts.mode,
        "KIOSK_USER": opts.kiosk_user,
        "DESKTOP_USER": opts.desktop_user,
        "SVC_USER": opts.svc_user,
    }


# Group sets — MUST mirror install.sh's user block exactly (the verify fake-PATH
# asserts the two agree). kiosk OWNS tty1 (tty/seat); desktop runs inside an
# existing DE session (no tty/seat takeover).
KIOSK_GROUPS = ("video", "render", "input", "tty", "audio", "seat")
DESKTOP_GROUPS = ("video", "render", "input", "audio")


# --------------------------------------------------------------------------- #
# plan() — pure: compute every action from opts + host state. No mutation.
# Drives BOTH the dry-run print and the GUI progress list.
# --------------------------------------------------------------------------- #
@dataclass
class PlanAction:
    step: str
    desc: str
    needed: bool      # would this action actually change state?
    cmd: "list | None" = None


@dataclass
class Plan:
    actions: list = field(default_factory=list)

    @property
    def changes(self) -> list:
        return [a for a in self.actions if a.needed]

    def add(self, step: str, desc: str, needed: bool, cmd=None) -> None:
        self.actions.append(PlanAction(step, desc, needed, cmd))


def _useradd_cmd(name: str, *, system: bool, shell: str) -> list:
    flags = ["-r"] if system else []
    return ["useradd", *flags, "-m", "-s", shell, name]


def _nologin() -> str:
    return shutil.which("nologin") or "/usr/sbin/nologin"


def plan(opts: Opts) -> Plan:
    """Compute the full action list WITHOUT mutating anything. Idempotent: an
    action is marked needed=False when the present state already satisfies it, so
    on an already-provisioned box plan().changes is empty (the no-op assertion)."""
    p = Plan()

    # 1) packages — install.sh --deps-only (skipped when stamped, unless --fresh)
    need_pkgs = opts.fresh or not _installed(opts)
    p.add("packages",
          "OS packages via install.sh --deps-only",
          need_pkgs,
          cmd=[install_sh(), "--deps-only"]
              + (["--fresh"] if opts.fresh else []))

    # 2) users — kiosk + desktop + svc. Each: create if missing, then group adds.
    for name, system, shell, groups, label in (
        (opts.kiosk_user, False, "/bin/bash", KIOSK_GROUPS, "kiosk user"),
        (opts.desktop_user, False, "/bin/bash", DESKTOP_GROUPS, "desktop user"),
        (opts.svc_user, True, _nologin(), (), "service user"),
    ):
        exists = _user_exists(name)
        p.add("users", f"create {label} '{name}'", not exists,
              cmd=_useradd_cmd(name, system=system, shell=shell))
        if groups:
            have = _user_groups(name) if exists else set()
            for g in groups:
                if not _group_exists(g):
                    continue
                p.add("users", f"add '{name}' to group {g}", g not in have,
                      cmd=["usermod", "-aG", g, name])

    # 3) deploy — install.sh proper (/opt + venv + units + etc skeleton)
    need_deploy = opts.fresh or not os.path.isdir("/opt/soc-display")
    p.add("deploy", "deploy /opt + venv + units via install.sh", need_deploy,
          cmd=[install_sh()]
              + (["--fresh"] if opts.fresh else []))

    # 4) write_config — handled in-process (render_*); represented for the plan
    p.add("write_config", "render panels.yaml + soc.env + wall unit", True)

    # 5) vault running
    p.add("vault_running", f"start Vaultwarden + poll {opts.url}/alive", True,
          cmd=["systemctl", "start", "vaultwarden"])

    # 6) vault account — ensure (create if missing / verify if present)
    p.add("vault_account",
          f"ensure Vaultwarden account {opts.email or '(email unset)'}", True)

    # 7) vault seed — panel logins
    p.add("vault_seed", "seed panel-login items", bool(opts.seed))

    # 8) seal — host-bound master
    p.add("seal", "seal the master password host-bound", True)

    return p


def print_plan(opts: Opts, out=print) -> Plan:
    """Render plan() as a human plan (used by --dry-run and the GUI preview)."""
    p = plan(opts)
    out(f"Provisioning plan (mode={opts.mode}, dry-run={opts.dry}):")
    changes = 0
    for a in p.actions:
        mark = "CHANGE" if a.needed else "ok    "
        if a.needed:
            changes += 1
        line = f"  [{mark}] {a.step}: {a.desc}"
        out(line)
        if a.needed and a.cmd:
            out("           " + ("[dry-run] " if opts.dry else "$ ")
                + " ".join(a.cmd))
    if changes == 0:
        out("  (nothing to do — already provisioned)")
    else:
        out(f"  {changes} action(s) would change host state.")
    return p


# --------------------------------------------------------------------------- #
# Steps. Each is idempotent, dry-run-aware, returns a ProvResult.
# --------------------------------------------------------------------------- #
def step_packages(opts: Opts) -> ProvResult:
    """Install OS packages by shelling install.sh --deps-only (REUSES the
    per-distro package sets; never duplicates them). Fast-paths when stamped."""
    dry = opts.dry
    if not opts.fresh and _installed(opts):
        return ProvResult(ok=True, changed=False,
                          detail=f"packages already installed (stamp {_install_stamp(opts)})")
    cmd = [install_sh(), "--deps-only"] + (["--fresh"] if opts.fresh else [])
    rc = _run(cmd, dry=dry)
    if rc not in (0, None):
        return ProvResult(ok=False, changed=False,
                          detail=f"install.sh --deps-only failed (rc={rc})", cmds=[cmd])
    return ProvResult(ok=True, changed=not dry, detail="OS packages ensured", cmds=[cmd])


def step_users(opts: Opts) -> ProvResult:
    """Create the kiosk + desktop (+ service) users and ensure their groups.

    This is the idempotent stdlib MIRROR of install.sh's user block (install.sh
    stays the deploy engine; this is what the dry-run/CLI drives and what asserts
    the two agree). `id` / group-membership guards make every action a no-op on
    re-run."""
    dry = opts.dry
    cmds: list = []
    changed = False

    for name, system, shell, groups in (
        (opts.kiosk_user, False, "/bin/bash", KIOSK_GROUPS),
        (opts.desktop_user, False, "/bin/bash", DESKTOP_GROUPS),
        (opts.svc_user, True, _nologin(), ()),
    ):
        if not name:
            continue
        exists = _user_exists(name)
        if not exists:
            cmd = _useradd_cmd(name, system=system, shell=shell)
            rc = _run(cmd, dry=dry)
            cmds.append(cmd)
            if rc not in (0, None):
                return ProvResult(ok=False, changed=changed,
                                  detail=f"useradd {name} failed (rc={rc})", cmds=cmds)
            changed = changed or not dry
        # Read the REAL group membership even in dry-run (it's a read-only probe)
        # so the printed plan matches what would actually change — mirrors plan().
        # A not-yet-created user (dry-run, or just useradd'd) has no extra groups
        # yet, so start from empty; an existing user reflects its true membership.
        have = _user_groups(name) if exists else set()
        for g in groups:
            if not _group_exists(g):
                continue
            if g in have:
                continue
            cmd = ["usermod", "-aG", g, name]
            _run(cmd, dry=dry)
            cmds.append(cmd)
            changed = changed or not dry

    detail = (f"users ensured: {opts.kiosk_user} (kiosk), "
              f"{opts.desktop_user} (desktop), {opts.svc_user} (service)")
    return ProvResult(ok=True, changed=changed, detail=detail, cmds=cmds)


def step_deploy(opts: Opts) -> ProvResult:
    """Deploy /opt + build the venv + install units + the /etc skeleton by
    shelling install.sh proper (install.sh is the single deploy engine). In
    dry-run only the invocation is printed."""
    dry = opts.dry
    if not opts.fresh and os.path.isdir("/opt/soc-display"):
        return ProvResult(ok=True, changed=False,
                          detail="/opt/soc-display already deployed")
    env = dict(os.environ)
    for k, v in install_env_knobs(opts).items():
        env.setdefault(k, v)
    cmd = [install_sh()] + (["--fresh"] if opts.fresh else [])
    rc = _run(cmd, dry=dry, env=env)
    if rc not in (0, None):
        return ProvResult(ok=False, changed=False,
                          detail=f"install.sh deploy failed (rc={rc})", cmds=[cmd])
    return ProvResult(ok=True, changed=not dry, detail="/opt + venv + units deployed",
                      cmds=[cmd])


def step_units(opts: Opts) -> ProvResult:
    """Idempotent re-assert of the mode's units. install.sh enables them during
    deploy; this is the safe re-assert path (and where per-user desktop units
    would be recorded). A no-op when systemd is absent."""
    dry = opts.dry
    if not _have("systemctl"):
        return ProvResult(ok=True, changed=False, detail="no systemd — units skipped")
    cmds: list = []
    units = ["soc-wall.service"]
    if opts.mode == "kiosk":
        units.append("getty@tty1.service")
    for u in units:
        cmd = ["systemctl", "enable", u]
        _run(cmd, dry=dry)
        cmds.append(cmd)
    return ProvResult(ok=True, changed=not dry,
                      detail=f"units ensured ({', '.join(units)})", cmds=cmds)


def _disable_session(opts: Opts) -> None:
    """Fail-closed boot guard: disable the wall session so an un-sealable box does
    NOT autostart a session that can't reach the vault and goes dark. Best-effort
    and idempotent — a no-op without systemd; re-running provision to seal re-enables
    it. NEVER raises (any systemctl error is swallowed deliberately HERE because the
    real failure has already been reported by the failing step and is being
    surfaced in the returned PARTIAL-INSTALL message)."""
    if not _have("systemctl"):
        return
    for u in ("soc-wall.service",):
        try:
            _run(["systemctl", "disable", u], dry=False)
        except Exception:  # noqa: BLE001 — guard must not mask the original failure
            pass


def step_vault_running(opts: Opts) -> ProvResult:
    """Start Vaultwarden + poll /alive (logic lifted from cmd_deploy step 3)."""
    dry = opts.dry
    if dry:
        print(f"[dry-run] systemctl start vaultwarden ; poll {opts.url}/alive")
        return ProvResult(ok=True, changed=False, detail=f"would start Vaultwarden ({opts.url})")
    if _have("systemctl") and os.path.isdir("/run/systemd/system"):
        _run(["systemctl", "start", "vaultwarden"], dry=False)
    else:
        return ProvResult(ok=True, changed=False,
                          detail="no systemd — start Vaultwarden via your init manager")
    if _alive(opts.url):
        return ProvResult(ok=True, changed=True, detail=f"Vaultwarden answering at {opts.url}")
    return ProvResult(ok=False, changed=False,
                      detail=f"{opts.url}/alive not answering — check Vaultwarden")


def _alive(url: str, timeout: float = 20.0) -> bool:
    """Poll <url>/alive for up to `timeout` seconds. Pure stdlib (urllib)."""
    import time
    import urllib.request
    deadline = time.time() + timeout
    target = url.rstrip("/") + "/alive"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(target, timeout=3) as r:  # noqa: S310
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    return False


# --------------------------------------------------------------------------- #
# Destructive vault-account reset (forgot-master recovery), run as ROOT via pkexec.
# NO master ever crosses this boundary: deletion is by EMAIL only; the brand-new
# account is registered + sealed UNPRIVILEGED in the caller (master in memory).
# --------------------------------------------------------------------------- #
def _vw_data_folder() -> str:
    """Vaultwarden's DATA_FOLDER from the running unit's Environment, else the
    common default. Pure stdlib."""
    try:
        out = subprocess.run(
            ["systemctl", "show", "vaultwarden.service", "-p", "Environment",
             "--value"], capture_output=True, text=True, timeout=10).stdout
        for tok in out.split():
            if tok.startswith("DATA_FOLDER="):
                d = tok.split("=", 1)[1].strip()
                if d:
                    return d
    except Exception:  # noqa: BLE001
        pass
    return "/var/lib/vaultwarden"


def _delete_user_rows(db_path: str, email: str) -> int:
    """Delete the Vaultwarden user matching `email` AND every row in any table whose
    foreign key references users(uuid) — discovered by introspecting the LIVE schema
    (PRAGMA foreign_key_list), so it stays correct across Vaultwarden versions and
    leaves OTHER accounts untouched. Returns 1 if a user was deleted, else 0.

    Pure-sqlite + testable in isolation (no service, no network). The caller stops
    Vaultwarden first so the DB is not open elsewhere."""
    import sqlite3
    con = sqlite3.connect(db_path)
    try:
        con.execute("PRAGMA foreign_keys=OFF")
        row = con.execute(
            "SELECT uuid FROM users WHERE lower(email)=lower(?)", (email,)
        ).fetchone()
        if not row:
            return 0
        uuid = row[0]
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for t in tables:
            if t == "users":
                continue
            try:
                fks = list(con.execute(f'PRAGMA foreign_key_list("{t}")'))
            except sqlite3.Error:
                continue
            for fk in fks:  # (id, seq, table, from, to, on_update, on_delete, match)
                if (fk[2] or "").lower() == "users":
                    con.execute(f'DELETE FROM "{t}" WHERE "{fk[3]}"=?', (uuid,))
        con.execute("DELETE FROM users WHERE uuid=?", (uuid,))
        con.commit()
        try:                                   # fold WAL back so VW reads a clean db
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        return 1
    finally:
        con.close()


def reset_vault_db_account(email: str, *, url: str = "", data_folder: str = "",
                           manage_service: bool = True) -> dict:
    """DESTRUCTIVE forgot-master recovery (ROOT): stop Vaultwarden, BACK UP its DB,
    delete the `email` account + all its data, restart Vaultwarden. The new account
    is registered + sealed afterwards by the UNPRIVILEGED caller (no master here).

    Returns {"deleted", "backup", "data_folder"}; raises RuntimeError on failure.
    `manage_service=False` (tests) skips the stop/start so the SQL core is testable."""
    import time
    df = data_folder or _vw_data_folder()
    db = os.path.join(df, "db.sqlite3")
    if not os.path.isfile(db):
        raise RuntimeError(f"no Vaultwarden DB at {db} (DATA_FOLDER={df})")
    stopped = False
    if manage_service and _have("systemctl"):
        rc = _run(["systemctl", "stop", "vaultwarden"], dry=False)
        if rc not in (0, None):
            raise RuntimeError("could not stop vaultwarden.service before the reset")
        stopped = True
    backup = f"{db}.reset-bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(db, backup)
    try:
        deleted = _delete_user_rows(db, email)
    finally:
        if stopped:
            _run(["systemctl", "start", "vaultwarden"], dry=False)
            if url:
                _alive(url, timeout=30.0)
    return {"deleted": deleted, "backup": backup, "data_folder": df}


def step_vault_account(opts: Opts, master: str) -> ProvResult:
    """Ensure the Vaultwarden account exists (create if missing / verify if
    present). Delegates to host.vaultsetup.ensure_account — NO root needed (pure
    HTTP to 127.0.0.1:8222); the master is an in-memory arg, never argv/file.

    Degrades gracefully if vaultsetup is unavailable (e.g. cryptography missing
    or the module not yet present) — the operator can create the account in the
    web vault."""
    dry = opts.dry
    if not opts.email:
        return ProvResult(ok=False, changed=False, detail="no vault email set — skipping")
    if dry:
        print(f"[dry-run] ensure Vaultwarden account {opts.email} at {opts.url} "
              f"(create if missing; NO network in dry-run)")
        return ProvResult(ok=True, changed=False,
                          detail=f"would ensure account {opts.email}")
    vs = _load_vaultsetup()
    if vs is None:
        return ProvResult(ok=False, changed=False,
                          detail="host.vaultsetup unavailable — create the account in the web vault")
    try:
        outcome = vs.ensure_account(opts.url, opts.email, master)
    except Exception as e:  # noqa: BLE001 — surface the cause (wrong-master / signups-disabled)
        return ProvResult(ok=False, changed=False, detail=str(e))
    changed = (outcome == "created")
    return ProvResult(ok=True, changed=changed,
                      detail=f"account {opts.email}: {outcome}")


def step_vault_seed(opts: Opts, master: str, cfg: dict) -> ProvResult:
    """Seed panel-login items via host.vaultseed.upsert_login for every
    configured panel (REUSES the credential-store primitives). No root needed."""
    dry = opts.dry
    if not opts.seed:
        return ProvResult(ok=True, changed=False, detail="seeding disabled (--no-seed)")
    items = _config_vault_items(cfg)
    if not items:
        return ProvResult(ok=True, changed=False, detail="no panel logins to seed")
    names = ", ".join(n for _, n, _ in items)
    if dry:
        print(f"[dry-run] seed login items at {opts.url}: {names} (NO network)")
        return ProvResult(ok=True, changed=False, detail=f"would seed: {names}")
    vseed = _load_vaultseed()
    if vseed is None or not vseed.available():
        return ProvResult(ok=False, changed=False,
                          detail="host.vaultseed unavailable — add logins in the web vault")
    seeded = 0
    first_err = ""
    for kind, name, uri in items:
        try:
            # Seed an EMPTY placeholder login (operator fills user/pass later via
            # `setup.py creds`) so the vault item the panel references EXISTS.
            vseed.upsert_login(opts.url, opts.email, master, name, "", "",
                               uri=uri or None)
            seeded += 1
        except Exception as e:  # noqa: BLE001 — keep the FIRST cause to surface it
            first_err = first_err or str(e)
    # Total failure (e.g. wrong master / wrong URL) is NOT success: report ok=False
    # with the cause so cmd_vault_seed exits 1 and provision_all's report shows it.
    if seeded == 0:
        return ProvResult(ok=False, changed=False,
                          detail=f"seeded 0/{len(items)} — "
                                 f"{first_err or 'all upserts failed'}")
    # Partial success stays ok=True but surfaces the degradation + first cause.
    if seeded < len(items):
        return ProvResult(ok=True, changed=True,
                          detail=f"seeded {seeded}/{len(items)} "
                                 f"(some failed: {first_err})")
    return ProvResult(ok=True, changed=seeded > 0,
                      detail=f"seeded {seeded}/{len(items)} login item(s)")


def step_seal(opts: Opts, master: str, paths: dict, soc_env: dict,
              backend: str) -> ProvResult:
    """Seal the master host-bound (REUSES setup.seal_master, the shared seal/store
    core). Dry-run previews the PIN that would be used; mutates nothing."""
    dry = opts.dry
    setup = _load_setup()
    if setup is None:
        return ProvResult(ok=False, changed=False, detail="setup core unavailable for seal")
    try:
        used_pin = setup.seal_master(
            master, source="auto", pin=(opts.pin or None), paths=paths,
            soc_env=soc_env, backend=backend, dry=dry)
    except Exception as e:  # noqa: BLE001 — SealMasterError carries a human message
        return ProvResult(ok=False, changed=False, detail=str(e))
    detail = "master sealed host-bound"
    if used_pin:
        detail += f" (PIN: {used_pin})"
    return ProvResult(ok=True, changed=not dry, detail=detail)


def step_write_config(opts: Opts, cfg: dict, soc_env: dict, paths: dict) -> ProvResult:
    """Render + write panels.yaml / soc.env / wall-unit (REUSES setup.render_*).
    Honours the per-user fallback + marker. Dry-run prints, writes nothing."""
    dry = opts.dry
    setup = _load_setup()
    if setup is None:
        return ProvResult(ok=False, changed=False, detail="setup core unavailable for write-config")
    # render_panels_yaml needs at least a display config. Panels can be empty —
    # the wall opens with blank frames; the operator adds panels later via the
    # on-screen config. On a fresh box the wizard hasn't run yet — skip rather
    # than crash; the operator runs the wizard first.
    if not cfg.get("display"):
        return ProvResult(ok=True, changed=False,
                          detail="no wizard config yet — run the wizard, then write-config")
    setup.write_file(paths["panels_out"], setup.render_panels_yaml(cfg),
                     paths["panels_mode"], dry)
    if soc_env is not None:
        setup.write_file(paths["soc_env"], setup.render_soc_env(soc_env),
                         paths["env_mode"], dry)
        if paths.get("wall_unit"):
            setup.write_file(paths["wall_unit"],
                             setup.render_wall_unit(soc_env, soc_root=paths["soc_root"]),
                             0o644, dry)
    setup._drop_marker(paths, dry)
    return ProvResult(ok=True, changed=not dry,
                      detail=f"config written to {paths['panels_out']}")


# --------------------------------------------------------------------------- #
# provision_all — runs the steps IN ORDER, guarded, reporting progress.
# --------------------------------------------------------------------------- #
def provision_all(opts: Opts, *, cfg: "dict | None" = None,
                  soc_env: "dict | None" = None, paths: "dict | None" = None,
                  master: str = "", backend: str = "litebw",
                  report=_default_report) -> ProvResult:
    """The whole fresh-box flow (CLI analogue of the GUI's Apply). Runs every
    step in order, reporting progress through `report(step, status, detail)`.

    The privileged shell steps (packages/users/deploy) run directly here when the
    caller is root; the GUI escalates them via pkexec around the same plan. Stops
    at the first hard failure (returns its ProvResult) so a half-provisioned box
    is reported, not silently continued."""
    setup = _load_setup()
    if paths is None and setup is not None:
        paths = setup.resolve_paths(opts.target)
    cfg = cfg or {}
    soc_env = soc_env or {}

    overall_changed = False

    def runstep(name, fn):
        nonlocal overall_changed
        report(name, "running")
        res = fn()
        report(name, "ok" if res.ok else "FAILED", res.detail)
        overall_changed = overall_changed or res.changed
        return res

    # 1) packages
    r = runstep("packages", lambda: step_packages(opts))
    if not r.ok:
        return r
    # 2) users
    r = runstep("users", lambda: step_users(opts))
    if not r.ok:
        return r
    # 3) deploy
    r = runstep("deploy", lambda: step_deploy(opts))
    if not r.ok:
        return r
    # step_deploy (via install.sh) has now ENABLED the boot session (soc-wall +,
    # in kiosk mode, getty@tty1 autologin). If a later seal/account step fails on
    # a REAL run, the box would autostart a session that can't unseal the vault and
    # goes dark. From here on, a post-deploy vault failure must leave the box
    # NOT-SAFE-TO-BOOT-but-disabled rather than enabled-and-dead.
    deploy_mutated = (not opts.dry) and r.changed

    def _partial(cause: str) -> ProvResult:
        # Fail closed: disable the wall session so an un-sealable box doesn't
        # autostart a dead session, then return a clear, actionable result.
        if deploy_mutated:
            _disable_session(opts)
        return ProvResult(
            ok=False, changed=overall_changed,
            detail=("PARTIAL INSTALL: deploy succeeded but the vault could not be "
                    f"finished ({cause}). The wall session was left DISABLED so the "
                    "box won't boot into a dead wall. Do NOT reboot yet — re-run "
                    "`sudo setup.py provision --master-fd` (or `setup.py first-run`) "
                    "to seal the master, which re-enables boot."))

    # 4) write_config (needs setup + paths)
    if setup is not None and paths is not None:
        r = runstep("write_config", lambda: step_write_config(opts, cfg, soc_env, paths))
        if not r.ok:
            return r
    # 5) vault running
    r = runstep("vault_running", lambda: step_vault_running(opts))
    # vault_running being down is not fatal in dry-run; on a real run it's a soft
    # warning — the operator can start it and re-run. Continue.
    # 6) vault account
    if master:
        r = runstep("vault_account", lambda: step_vault_account(opts, master))
        if not r.ok and not opts.dry:
            return _partial(f"account: {r.detail}")
        # 7) vault seed
        runstep("vault_seed", lambda: step_vault_seed(opts, master, cfg))
        # 8) seal
        if setup is not None and paths is not None:
            r = runstep("seal", lambda: step_seal(opts, master, paths, soc_env, backend))
            if not r.ok and not opts.dry:
                return _partial(f"seal: {r.detail}")
    else:
        report("vault_account", "skipped", "no master provided (use --master-fd)")

    return ProvResult(ok=True, changed=overall_changed,
                      detail="provisioning complete" if not opts.dry else "dry-run complete")


# --------------------------------------------------------------------------- #
# Lazy host-module / setup loaders (keep the top of this file pure-stdlib so the
# pkexec-by-path entrypoint can't drag host imports across the boundary).
# --------------------------------------------------------------------------- #
def _ensure_host_on_path() -> None:
    kiosk = os.path.join(REPO, "kiosk-host")
    if kiosk not in sys.path:
        sys.path.insert(0, kiosk)


def _load_vaultsetup():
    _ensure_host_on_path()
    try:
        from host import vaultsetup  # type: ignore
        return vaultsetup
    except Exception:  # noqa: BLE001
        return None


def _load_vaultseed():
    _ensure_host_on_path()
    try:
        from host import vaultseed  # type: ignore
        return vaultseed
    except Exception:  # noqa: BLE001
        return None


_SETUP = None


def _load_setup():
    """Import the repo-root setup.py as a module (the same spec trick setupgui +
    the tests use). Cached. Returns None if it can't be loaded."""
    global _SETUP
    if _SETUP is not None:
        return _SETUP
    import importlib.util
    path = os.path.join(REPO, "setup.py")
    if not os.path.exists(path):
        return None
    try:
        spec = importlib.util.spec_from_file_location("soc_setup", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception:  # noqa: BLE001
        return None
    _SETUP = mod
    return mod


def _config_vault_items(cfg: dict):
    """(kind, vault_item, uri) for every configured panel login. Mirrors
    setup._vault_items but stays here so the seed step is self-contained."""
    setup = _load_setup()
    if setup is not None and hasattr(setup, "_vault_items"):
        try:
            return setup._vault_items(cfg)
        except Exception:  # noqa: BLE001
            pass
    items = []
    for p in cfg.get("panels", []):
        name = p.get("vault_item")
        if name:
            items.append(("panel", name, p.get("url") or ""))
    return items


# --------------------------------------------------------------------------- #
# Standalone pkexec-by-absolute-path entrypoint. Mirrors secretstore.py /
# configpaths.py: pure stdlib, no host imports needed to PARSE argv. The GUI
# escalates the privileged shell steps by re-execing THIS file as root.
# Secrets (master) NEVER arrive on argv — only via stdin (master-fd 0).
# --------------------------------------------------------------------------- #
def _main(argv: "list | None" = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="provision.py",
        description="SOC wall provisioning core (privileged entrypoint).")
    ap.add_argument("--provision", action="store_true",
                    help="run the privileged shell steps (packages/users/deploy)")
    ap.add_argument("--plan", action="store_true", help="print the plan and exit")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--mode", choices=["kiosk", "desktop"], default="kiosk")
    ap.add_argument("--kiosk-user", default="soc")
    ap.add_argument("--desktop-user", default="socwall")
    ap.add_argument("--svc-user", default="socsvc")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--reset-vault-db", action="store_true",
                    help="DESTRUCTIVE (root): delete a Vaultwarden account + all its "
                         "data by --email so a forgotten master can be re-registered")
    ap.add_argument("--email", default="")
    ap.add_argument("--url", default="")
    args = ap.parse_args(argv)

    if args.dry_run:
        os.environ["SOC_PROVISION_DRY_RUN"] = "1"

    # Forgot-master recovery: privileged, by EMAIL only (never a master). Distinct
    # mode — must run before the provision shell-steps block.
    if args.reset_vault_db:
        if not args.email:
            sys.stderr.write("reset-vault-db: --email is required\n")
            return 2
        try:
            res = reset_vault_db_account(args.email, url=args.url)
        except Exception as e:  # noqa: BLE001 — surface the cause to the caller
            sys.stderr.write(f"reset-vault-db FAILED: {e}\n")
            return 1
        print(f"reset-vault-db: deleted={res['deleted']} backup={res['backup']}")
        return 0

    opts = Opts(mode=args.mode, kiosk_user=args.kiosk_user,
                desktop_user=args.desktop_user, svc_user=args.svc_user,
                fresh=args.fresh, dry_run=args.dry_run)

    if args.plan and not args.provision:
        print_plan(opts)
        return 0

    # Privileged shell-only steps (no vault/seal — those run unprivileged HTTP in
    # the calling process). Run them in order, report, stop on failure.
    for name, fn in (("packages", step_packages), ("users", step_users),
                     ("deploy", step_deploy), ("units", step_units)):
        res = fn(opts)
        _default_report(name, "ok" if res.ok else "FAILED", res.detail)
        if not res.ok:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main())
