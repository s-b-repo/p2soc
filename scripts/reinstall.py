#!/usr/bin/env python3
"""
soc-wall reinstaller — clean uninstall + fresh install of the SOC video-wall.

Use when:
  * you bumped a version + want a known-clean re-deploy (CI-style);
  * an experimental edit messed up the deploy tree + you want to start fresh
    without losing the host-sealed master + Vaultwarden data;
  * you're moving the kiosk to a new disk + want the install footprint gone.

Default behaviour is SAFE:
  * stops + disables soc-wall, soc-tarpit, autossh-tunnel, forti-vpn(*),
    soc-firstboot;
  * removes /opt/soc-display + its systemd unit files;
  * removes /etc/soc-display/{soc.env,tarpit.env,tarpit-paths.list,
    manifest.json,panels.yaml,keys/};
  * KEEPS /etc/soc-display/secret/ (the host-bound sealed master). Without
    --purge, an unseal will work straight after the reinstall — no PIN prompt;
  * KEEPS the Vaultwarden Docker container + its data volume;
  * KEEPS the soc service-user account + home directory + login keyring
    (preserves libsecret entries, rbw config, sshd known_hosts).

Destructive overrides:
  --purge              also wipe /etc/soc-display/secret/  (vault must re-seal
                       → prompts for the vault master password during first-run)
  --purge-vault        also `docker stop && docker rm soc-vaultwarden`
                       (the Docker volume is left alone — vault data survives)
  --purge-vault-data   also `rm -rf ~/.local/share/soc-vaultwarden`
                       (TRULY destructive: all stored credentials are gone)
  --keep-units         leave systemd unit files in place (only stop + disable)

Workflow:
  --uninstall-only     stop here; do not reinstall
  --no-firstrun        reinstall but skip `setup.py first-run` at the end
  --dry-run            print every action without performing it
  --yes                skip the interactive confirmation
  --verbose            stream every subprocess's stdout/stderr

Usage:
  sudo python3 scripts/reinstall.py             # safe re-deploy, asks once
  sudo python3 scripts/reinstall.py --dry-run   # preview
  sudo python3 scripts/reinstall.py --purge --yes
                                                # full reset, no prompt

The script MUST be run from the source git checkout (i.e.
$REPO/scripts/reinstall.py) — running it from /opt/soc-display would
delete its own source tree mid-execution. We refuse that case loudly.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from typing import List, Optional


# --------------------------------------------------------------------------- #
# Constants — every path / service the installer creates.
# --------------------------------------------------------------------------- #
DEPLOY_ROOT = "/opt/soc-display"
ETC_ROOT = "/etc/soc-display"

# /etc/soc-display children we always remove (operator artefacts that the
# installer regenerates). secret/ is treated separately under --purge.
ETC_CHILDREN_REMOVE = [
    "soc.env",
    "tarpit.env",
    "tarpit-paths.list",
    "manifest.json",
    "panels.yaml",          # only present if firstboot.cfg.yaml was generated
    "keys",                 # autossh-tunnel jump-host keys
    ".configured",          # firstboot marker
    "config-cache.yaml",
]

# systemd units installed by install.sh. Stopped + disabled always; the .service
# file itself is removed unless --keep-units.
UNITS = [
    "soc-wall.service",
    "soc-tarpit.service",
    "soc-firstboot.service",
    "autossh-tunnel.service",
    "forti-vpn.service",
    "forti-vpn@.service",       # template — `disable` no-ops, file removal works
    "vaultwarden.service",      # legacy native unit (Docker is the prod path)
]

# `forti-vpn@<name>.service` instances — discovered dynamically from
# `systemctl list-units --all 'forti-vpn@*'` because each VPN gets its own
# instance and we don't know names at compile time.
VPN_TEMPLATE = "forti-vpn@"

# /etc/systemd/system/getty@tty1.service.d/autologin.conf drop-in (kiosk auto-
# login on tty1). Removed unless --keep-units.
GETTY_DROPIN = "/etc/systemd/system/getty@tty1.service.d/autologin.conf"
GETTY_DROPIN_DIR = "/etc/systemd/system/getty@tty1.service.d"

# Vaultwarden Docker container — the production path.
VW_CONTAINER = "soc-vaultwarden"
VW_DATA_DIRS = [
    os.path.expanduser("~/.local/share/soc-vaultwarden"),
    "/var/lib/vaultwarden",       # legacy native install path
]


# --------------------------------------------------------------------------- #
# Tiny CLI helpers — no third-party deps so this runs straight after a
# fresh OS install without needing a venv.
# --------------------------------------------------------------------------- #
class Runner:
    """Wraps subprocess so --dry-run can short-circuit + --verbose can stream."""

    def __init__(self, *, dry_run: bool, verbose: bool):
        self.dry_run = dry_run
        self.verbose = verbose
        self._actions = 0

    def run(self, cmd: List[str], *, check: bool = False,
            capture: bool = True, input_: Optional[str] = None,
            cwd: Optional[str] = None) -> subprocess.CompletedProcess:
        self._actions += 1
        if self.dry_run:
            print(f"  [dry-run] {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if self.verbose:
            print(f"  $ {' '.join(cmd)}")
        try:
            if capture and not self.verbose:
                return subprocess.run(cmd, check=check, text=True,
                                       capture_output=True, input=input_,
                                       cwd=cwd, timeout=300)
            return subprocess.run(cmd, check=check, text=True,
                                   input=input_, cwd=cwd, timeout=300)
        except subprocess.TimeoutExpired:
            print(f"  ! TIMEOUT after 300s: {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 124, "", "timeout")
        except FileNotFoundError:
            return subprocess.CompletedProcess(cmd, 127, "", "not found")

    def remove_path(self, path: str):
        """rm -rf, idempotent. Files and dirs both."""
        self._actions += 1
        if self.dry_run:
            print(f"  [dry-run] rm -rf {path}")
            return
        try:
            if os.path.islink(path) or os.path.isfile(path):
                os.remove(path)
                if self.verbose: print(f"  rm {path}")
            elif os.path.isdir(path):
                shutil.rmtree(path)
                if self.verbose: print(f"  rm -rf {path}")
            elif self.verbose:
                print(f"  (already absent: {path})")
        except OSError as e:
            print(f"  ! failed to remove {path}: {e}")

    @property
    def actions(self) -> int:
        return self._actions


def banner(text: str, ch: str = "="):
    line = ch * max(60, len(text) + 4)
    print(f"\n{line}\n{ch}{ch} {text}\n{line}")


def section(text: str):
    print(f"\n--- {text} ---")


# --------------------------------------------------------------------------- #
# Safety checks
# --------------------------------------------------------------------------- #
def repo_root() -> str:
    """The git checkout this script lives in — used to invoke install.sh."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def assert_not_running_from_deploy():
    """install.sh deletes /opt/soc-display — if we're running from inside it,
    we'd unmap our own .pyc files mid-execution. Refuse loudly."""
    here = repo_root()
    if os.path.abspath(here).startswith(DEPLOY_ROOT):
        sys.exit(
            f"ERROR: this script is at {__file__} which lives under "
            f"{DEPLOY_ROOT}. The uninstall step would delete the script's "
            f"own source tree mid-run. Re-run from the source git checkout:\n"
            f"    sudo python3 <repo>/scripts/reinstall.py [...]")


def assert_root():
    if os.geteuid() != 0:
        sys.exit(
            "ERROR: this script needs root (it stops services, removes "
            "system unit files, and rewrites /etc/soc-display).\n"
            "    sudo python3 scripts/reinstall.py [...]")


# --------------------------------------------------------------------------- #
# Uninstall steps
# --------------------------------------------------------------------------- #
def discover_vpn_instances(runner: Runner) -> List[str]:
    """List `forti-vpn@*` systemd instances currently known to the box."""
    r = runner.run(["systemctl", "list-units", "--all", "--full",
                    "--no-legend", "-t", "service", f"{VPN_TEMPLATE}*"])
    if r.returncode != 0:
        return []
    names = []
    for line in (r.stdout or "").splitlines():
        # Format: "  UNIT  LOAD  ACTIVE  SUB  DESC"; the unit may have a leading
        # bullet or whitespace.
        parts = line.strip().split()
        if not parts:
            continue
        unit = parts[0].lstrip("●*").strip()
        if unit.startswith(VPN_TEMPLATE) and unit.endswith(".service"):
            names.append(unit)
    return names


def stop_services(runner: Runner) -> None:
    """Stop the wall first (it holds locker overlay + tray), then helpers,
    then the rest. systemctl stop is idempotent — never-installed units
    just say 'unit not loaded'."""
    section("Stopping services")
    # Discover dynamic instances before issuing stop on them.
    instances = discover_vpn_instances(runner)
    order = [
        "soc-wall.service",
        "soc-tarpit.service",
        "autossh-tunnel.service",
        *instances,
        "forti-vpn.service",
        "soc-firstboot.service",
    ]
    # Stop in one call where possible; systemctl handles a list cleanly.
    runner.run(["systemctl", "stop", *order])


def disable_services(runner: Runner) -> None:
    """`systemctl disable` for everything the installer enables. Safe on
    units that were never enabled (errors are non-fatal)."""
    section("Disabling services")
    runner.run(["systemctl", "disable",
                "soc-wall.service",
                "soc-tarpit.service",
                "soc-firstboot.service",
                "autossh-tunnel.service",
                "forti-vpn.service"])


def remove_units(runner: Runner) -> None:
    """Delete the .service files + drop-ins, then daemon-reload so systemd
    forgets they ever existed."""
    section("Removing systemd unit files")
    for u in UNITS:
        runner.remove_path(os.path.join("/etc/systemd/system", u))
    # tty1 autologin drop-in (kiosk path) + its dir if empty.
    runner.remove_path(GETTY_DROPIN)
    if not runner.dry_run:
        try:
            os.rmdir(GETTY_DROPIN_DIR)        # only if now empty
        except OSError:
            pass
    runner.run(["systemctl", "daemon-reload"])
    runner.run(["systemctl", "reset-failed"])


PRIOR_TARGET_SENTINEL = "/etc/soc-display/.prior-target"


def restore_default_target(runner: Runner) -> None:
    """Restore default.target to whatever it was BEFORE the install. The
    sentinel `/etc/soc-display/.prior-target` is written by install.sh
    immediately before any flip; if it's present + readable, we restore
    that exact value. If it's absent (older install), fall back to the
    safe-default behaviour of restoring graphical.target so a desktop
    user can log in after the wall is gone."""
    section("Restoring default boot target")
    r = runner.run(["systemctl", "get-default"])
    current = (r.stdout or "").strip()
    desired = "graphical.target"
    if os.path.exists(PRIOR_TARGET_SENTINEL):
        try:
            with open(PRIOR_TARGET_SENTINEL, encoding="utf-8") as fh:
                content = fh.read().strip()
            # Sanity gate: only accept well-formed *.target names.
            if content.endswith(".target") and " " not in content:
                desired = content
                print(f"  prior target sentinel: {desired}")
        except OSError as e:
            print(f"  could not read {PRIOR_TARGET_SENTINEL}: {e}; "
                  "defaulting to graphical.target")
    else:
        print(f"  no sentinel at {PRIOR_TARGET_SENTINEL}; "
              "defaulting to graphical.target")
    if current and current != desired:
        print(f"  current default: {current} → restoring {desired}")
        runner.run(["systemctl", "set-default", desired])
    else:
        print(f"  default already {current or desired} (no change)")


def remove_deploy_tree(runner: Runner) -> None:
    """Wipe /opt/soc-display — the entire deploy. The source git checkout
    is untouched (we ran from there)."""
    section(f"Removing {DEPLOY_ROOT}")
    runner.remove_path(DEPLOY_ROOT)


def clean_etc(runner: Runner, purge_secret: bool) -> None:
    """Surgically clean /etc/soc-display. Always removes the installer-
    generated files; only wipes secret/ under --purge."""
    section(f"Cleaning {ETC_ROOT}")
    if not os.path.isdir(ETC_ROOT) and not runner.dry_run:
        print(f"  (already absent: {ETC_ROOT})")
        return
    for name in ETC_CHILDREN_REMOVE:
        runner.remove_path(os.path.join(ETC_ROOT, name))
    secret_dir = os.path.join(ETC_ROOT, "secret")
    if purge_secret:
        print(f"  --purge: removing {secret_dir} (vault master must re-seal)")
        runner.remove_path(secret_dir)
    else:
        print(f"  KEPT: {secret_dir}  (host-sealed master — pass --purge to wipe)")
    # If /etc/soc-display is now entirely empty (no secret, no anything),
    # remove the directory itself for tidiness. Skipped on dry-run.
    if not runner.dry_run and os.path.isdir(ETC_ROOT):
        try:
            if not os.listdir(ETC_ROOT):
                os.rmdir(ETC_ROOT)
                print(f"  removed empty {ETC_ROOT}")
        except OSError:
            pass


def handle_vaultwarden(runner: Runner, purge: bool, purge_data: bool) -> None:
    """Vaultwarden lives in a Docker container `soc-vaultwarden` by default.
    By default we leave it alone (data + container survive). --purge-vault
    removes the container; --purge-vault-data also wipes the volume."""
    section("Vaultwarden")
    if not purge:
        print("  KEPT: Vaultwarden container + data  "
              "(pass --purge-vault to remove)")
        return
    r = runner.run(["docker", "ps", "-a", "--format", "{{.Names}}"])
    if r.returncode == 127:
        print("  docker not installed; skipping container teardown")
    else:
        names = (r.stdout or "").splitlines()
        if VW_CONTAINER in names:
            print(f"  --purge-vault: stopping + removing container "
                  f"{VW_CONTAINER}")
            runner.run(["docker", "stop", VW_CONTAINER])
            runner.run(["docker", "rm", VW_CONTAINER])
        else:
            print(f"  container {VW_CONTAINER} not present (nothing to remove)")
    if purge_data:
        print("  --purge-vault-data: wiping Vaultwarden volumes")
        for d in VW_DATA_DIRS:
            runner.remove_path(d)
    else:
        print("  KEPT: Vaultwarden data volume  "
              "(pass --purge-vault-data to wipe)")


# --------------------------------------------------------------------------- #
# Reinstall step
# --------------------------------------------------------------------------- #
def reinstall(runner: Runner, no_firstrun: bool) -> int:
    section("Reinstalling")
    src = repo_root()
    install_sh = os.path.join(src, "install.sh")
    if not os.path.isfile(install_sh):
        print(f"  ERROR: {install_sh} not found — cannot reinstall")
        return 2
    r = runner.run(["bash", install_sh], capture=False, cwd=src)
    if r.returncode != 0:
        print(f"  ! install.sh exited {r.returncode}")
        return r.returncode
    if no_firstrun:
        print("  --no-firstrun: skipping setup.py first-run")
        return 0
    setup_py = os.path.join(src, "setup.py")
    if not os.path.isfile(setup_py):
        print(f"  ! {setup_py} missing; cannot run first-run")
        return 0                  # install.sh succeeded; first-run is optional
    section("Running setup.py first-run (interactive)")
    r = runner.run(["python3", setup_py, "first-run"], capture=False, cwd=src)
    return r.returncode


# --------------------------------------------------------------------------- #
# Confirmation
# --------------------------------------------------------------------------- #
def confirm(args: argparse.Namespace) -> bool:
    if args.yes or args.dry_run:
        return True
    risk_lines = ["", "About to perform:"]
    if not args.uninstall_only:
        risk_lines.append(f"  • REINSTALL from {repo_root()}")
        if not args.no_firstrun:
            risk_lines.append("    (then setup.py first-run, interactive)")
    risk_lines.append(f"  • stop + disable + remove soc-* systemd units")
    risk_lines.append(f"  • rm -rf {DEPLOY_ROOT}")
    risk_lines.append(f"  • clean {ETC_ROOT} (keeps secret/ unless --purge)")
    if args.purge:
        risk_lines.append(f"  • --purge: wipe {ETC_ROOT}/secret  "
                          "(vault master must be re-sealed)")
    if args.purge_vault:
        risk_lines.append(f"  • --purge-vault: docker rm {VW_CONTAINER}")
    if args.purge_vault_data:
        risk_lines.append("  • --purge-vault-data: wipe Vaultwarden volume "
                          "(ALL CREDENTIALS LOST)")
    risk_lines.append("")
    print("\n".join(risk_lines))
    try:
        ans = input("Proceed? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("y", "yes")


# --------------------------------------------------------------------------- #
# Entry
# --------------------------------------------------------------------------- #
def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="reinstall.py",
        description=__doc__.splitlines()[1] if __doc__ else "",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap_compat(__doc__ or ""))
    p.add_argument("--uninstall-only", action="store_true",
                   help="stop after uninstall; do not reinstall")
    p.add_argument("--purge", action="store_true",
                   help="also wipe /etc/soc-display/secret/ "
                        "(sealed master will need re-creation)")
    p.add_argument("--purge-vault", action="store_true",
                   help="also docker rm soc-vaultwarden  "
                        "(data volume kept unless --purge-vault-data)")
    p.add_argument("--purge-vault-data", action="store_true",
                   help="also wipe Vaultwarden's data volume "
                        "(DESTRUCTIVE — all credentials lost)")
    p.add_argument("--keep-units", action="store_true",
                   help="leave systemd unit files in place "
                        "(only stop + disable)")
    p.add_argument("--no-firstrun", action="store_true",
                   help="reinstall but skip setup.py first-run")
    p.add_argument("--dry-run", action="store_true",
                   help="print every action without performing it")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive confirmation prompt")
    p.add_argument("--verbose", action="store_true",
                   help="stream subprocess output instead of capturing")
    return p.parse_args(argv)


def textwrap_compat(s: str) -> str:
    """Strip the module docstring's leading whitespace so --help renders
    cleanly. argparse.RawDescriptionHelpFormatter respects newlines but
    not common indentation."""
    import textwrap as _tw
    return _tw.dedent(s).strip()


def main(argv=None) -> int:
    args = parse_args(argv)

    # Hard safety gates before any destructive action.
    if not args.dry_run:
        assert_root()
    assert_not_running_from_deploy()

    if not confirm(args):
        print("aborted (no changes made)")
        return 1

    runner = Runner(dry_run=args.dry_run, verbose=args.verbose)
    t0 = time.time()
    banner("soc-wall reinstaller — uninstall")

    stop_services(runner)
    disable_services(runner)
    if not args.keep_units:
        remove_units(runner)
    restore_default_target(runner)
    remove_deploy_tree(runner)
    clean_etc(runner, purge_secret=args.purge)
    handle_vaultwarden(runner, purge=args.purge_vault,
                        purge_data=args.purge_vault_data)

    elapsed = time.time() - t0
    print(f"\nuninstall complete  ({runner.actions} action(s), "
          f"{elapsed:.1f}s)")

    if args.uninstall_only:
        banner("done (uninstall-only)")
        return 0

    banner("soc-wall reinstaller — reinstall")
    rc = reinstall(runner, no_firstrun=args.no_firstrun)
    elapsed = time.time() - t0
    if rc == 0:
        banner(f"all done in {elapsed:.1f}s")
    else:
        banner(f"reinstall exited {rc} (see output above)", ch="!")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
