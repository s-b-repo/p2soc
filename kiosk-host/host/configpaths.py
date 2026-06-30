"""
Single source of truth for WHERE the wall config lives — so the WRITER (the
setup wizard / setupgui) and the READER (main.py, the shell launchers) can never
disagree about which panels.yaml / soc.env the wall actually uses.

THE BUG THIS FIXES: the wizard chose its write path from `is_root` while the wall
read a hardcoded /etc/soc-display/panels.yaml. A non-root desktop operator on a
deployed box wrote config/panels.local.yaml that NEVER reached the wall — silently.
Here the read precedence and the write target are derived from the SAME logic, so
"resolve where I wrote" == "resolve where the wall reads", always.

Pure stdlib (no gi, no PyYAML) so setup.py can import it before the venv exists
(via the same sys.path.insert(REPO+"/kiosk-host") shim it uses for host.config).

READ precedence per kind ({panels, env}), first existing wins, top-to-bottom:
  1. $SOC_PANELS_FILE / $SOC_ENV_FILE        explicit override — absolute authority
                                             (keeps the baked soc-wall.service unit
                                             + every helper working verbatim).
  2. <XDG_CONFIG_HOME or ~/.config>/soc-display/{panels.yaml,soc.env}
                                             ONLY IF the active marker exists.
  3. /etc/soc-display/{panels.yaml,soc.env}  canonical deployed location.
  4. repo: config/panels.local.yaml then panels.yaml ; .env then
                                             config/soc.env.example (dev fallback).

WHY the user-config tier is MARKER-GATED (not mtime, not unconditional):
  * Unconditional "user beats /etc" means any leftover ~/.config permanently
    shadows a re-deployed /etc — the inverse of the reported bug.
  * mtime is non-deterministic across clock skew / rsync / install-time touch, and
    is invisible (the operator cannot see WHY one won).
  * A marker is an EXPLICIT, greppable, operator-visible toggle: the WRITER drops
    it the instant it falls back to per-user, and uninstall / redeploy / --clean
    delete it to hand control back to /etc. So precedence reads as "user config
    wins iff the wizard deliberately put it there" — the writer creates the file
    AND the marker in one step, so the reader (same resolver) picks it up at once.

WRITE target: the highest-precedence location the current euid can create+write.
"""
from __future__ import annotations

import os
import sys

PANELS_BASENAME = "panels.yaml"
ENV_BASENAME = "soc.env"
SECRET_BASENAME = "secret"
WEBDATA_BASENAME = "webdata"
ETC_DIR_DEFAULT = "/etc/soc-display"
MARKER_BASENAME = "active"  # presence in user_dir() => the user config tier wins

def etc_dir():
    """The system config directory.  $SOC_ETC_DIR overrides for local installs."""
    d = os.environ.get("SOC_ETC_DIR")
    if d:
        return os.path.abspath(d)
    return ETC_DIR_DEFAULT

_BASENAME = {"panels": PANELS_BASENAME, "env": ENV_BASENAME}
_ENV_OVERRIDE = {"panels": "SOC_PANELS_FILE", "env": "SOC_ENV_FILE"}


# --------------------------------------------------------------------------- #
# Base directories
# --------------------------------------------------------------------------- #
def xdg_config_home() -> str:
    """$XDG_CONFIG_HOME (if absolute) else ~/.config — the per-user config root."""
    x = os.environ.get("XDG_CONFIG_HOME")
    if x and os.path.isabs(x):
        return x
    return os.path.join(os.path.expanduser("~"), ".config")


def user_dir() -> str:
    """The per-user config dir: <xdg>/soc-display. No root needed to create it."""
    return os.path.join(xdg_config_home(), "soc-display")


def repo_root() -> str:
    """$SOC_ROOT if set, else the checkout root (parent of kiosk-host/).
    …/kiosk-host/host/configpaths.py -> repo root is two dirs up."""
    r = os.environ.get("SOC_ROOT")
    if r:
        return os.path.abspath(r)
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, "..", ".."))


def active_marker() -> str:
    """The marker whose presence makes the user-config tier win over /etc."""
    return os.path.join(user_dir(), MARKER_BASENAME)


def _repo_candidates(kind: str) -> "list[str]":
    """Dev-checkout fallbacks, in preference order, for a given kind."""
    root = repo_root()
    if kind == "panels":
        return [os.path.join(root, "config", "panels.local.yaml"),
                os.path.join(root, "config", "panels.yaml")]
    # env: a real .env beats the committed example
    return [os.path.join(root, ".env"),
            os.path.join(root, "config", "soc.env.example")]


# --------------------------------------------------------------------------- #
# READ resolution
# --------------------------------------------------------------------------- #
def candidates(kind: str) -> "list[tuple[str, str]]":
    """The full ordered (path, human-label) read chain for `kind`, for --explain.
    The user-config tier is included with a label noting whether it is marker-gated
    so doctor can show exactly why a tier did or didn't win."""
    if kind not in _BASENAME:
        raise ValueError(f"kind must be 'panels' or 'env', not {kind!r}")
    base = _BASENAME[kind]
    out: "list[tuple[str, str]]" = []
    ov = os.environ.get(_ENV_OVERRIDE[kind])
    if ov:
        out.append((os.path.abspath(ov), f"${_ENV_OVERRIDE[kind]}"))
    marked = os.path.exists(active_marker())
    user_path = os.path.join(user_dir(), base)
    label = "user config (active)" if marked else "user config (inactive: no marker)"
    out.append((user_path, label))
    out.append((os.path.join(etc_dir(), base), "/etc/soc-display"))
    for rp in _repo_candidates(kind):
        out.append((rp, "repo fallback"))
    return out


def resolve_read(kind: str) -> "tuple[str | None, str]":
    """(path, source_label) of the file the wall WILL read for `kind`, or
    (None, 'none') if nothing exists. The user-config tier only counts when the
    active marker is present, so a stale ~/.config never shadows a fresh /etc."""
    marked = os.path.exists(active_marker())
    for path, label in candidates(kind):
        if label.startswith("user config") and not marked:
            continue  # marker-gated: skip the per-user tier unless deliberately activated
        if os.path.exists(path):
            return path, label
    return None, "none"


def resolve_panels() -> "str | None":
    return resolve_read("panels")[0]


def resolve_env() -> "str | None":
    return resolve_read("env")[0]


def resolve_secret_dir() -> str:
    """Where the sealed master lives, paired with whichever config tier wins, so a
    user-dir fallback keeps its secret next to its panels.yaml (host+user-bound).
    Mirrors resolve_read's precedence; always returns a path (the caller may need
    to create it)."""
    sd = os.environ.get("SOC_SECRET_DIR")
    if sd:
        return os.path.abspath(sd)
    if os.path.exists(active_marker()):
        return os.path.join(user_dir(), SECRET_BASENAME)
    # /etc when deployed, else repo dev location
    if os.path.isdir(etc_dir()):
        return os.path.join(etc_dir(), SECRET_BASENAME)
    return os.path.join(repo_root(), "dev", "run", SECRET_BASENAME)


def resolve_webdata_dir() -> str:
    """Where persistent panel web data (cookies.sqlite, localStorage, IndexedDB,
    cache, the compiled tracker filter) lives. This holds SESSION TOKENS, so it
    must be a PRIVATE 0700 dir owned by the kiosk user — see webkit_panel.py /
    chromium_panel.py which create it 0700.

    A SIBLING of secret/ (NOT inside it), with the SAME precedence as
    resolve_secret_dir() so the web data sits next to whichever config tier won —
    keeping the sealed-master/no-plaintext guarantee in `secret/` untouched.
    Always returns a path (the caller creates it 0700 on first use)."""
    wd = os.environ.get("SOC_WEBDATA_DIR")
    if wd:
        return os.path.abspath(wd)
    if os.path.exists(active_marker()):
        return os.path.join(user_dir(), WEBDATA_BASENAME)
    if os.path.isdir(etc_dir()):
        return os.path.join(etc_dir(), WEBDATA_BASENAME)
    return os.path.join(repo_root(), "dev", "run", WEBDATA_BASENAME)


# --------------------------------------------------------------------------- #
# WRITE resolution
# --------------------------------------------------------------------------- #
def _dir_writable(d: str) -> bool:
    """True if euid can create a file in `d` (it exists + is writable, or its
    nearest existing parent is). A probe-create would have side effects, so use
    os.access on the deepest existing ancestor."""
    p = d
    while p and not os.path.exists(p):
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return os.access(p, os.W_OK)


def resolve_write(kind: str, *, want_etc: bool = True,
                  can_escalate: bool = False) -> dict:
    """Pick the highest-precedence location the current euid can create+write, so
    that resolve_read (same resolver) then returns exactly what was written.

    Returns a dict:
      path            absolute file path to write
      dir             its parent directory (the caller mkdir -p's it)
      mode            octal file mode (0644 panels + /etc env [non-secret, must be readable
      #                  by the desktop/kiosk user]; 0600 user-tier env)
      needs_privilege True when want_etc but /etc is not writable and we will escalate
      via             'env' | 'etc' | 'user' | 'repo'  — which tier was chosen
      marker          path of the marker to write (user tier only), else None

    Order, first writable wins (mirrors resolve_read so write==read):
      A. $SOC_*_FILE set AND its dir writable        -> there (read tier #1)
      B. /etc/soc-display writable by euid            -> /etc (read tier #3), no marker
      C. /etc via pkexec escalation (want_etc + can_escalate, /etc not writable)
      D. user dir <xdg>/soc-display (+ active marker) -> read tier #2
      E. repo (dev checkout)                          -> read tier #4, no marker
    """
    if kind not in _BASENAME:
        raise ValueError(f"kind must be 'panels' or 'env', not {kind!r}")
    base = _BASENAME[kind]
    panels_mode = 0o644

    # A. explicit override wins if we can actually write it.
    ov = os.environ.get(_ENV_OVERRIDE[kind])
    if ov:
        ov = os.path.abspath(ov)
        d = os.path.dirname(ov) or "."
        if _dir_writable(d):
            return dict(path=ov, dir=d,
                        mode=(panels_mode if kind == "panels" else 0o644),
                        needs_privilege=False, via="env", marker=None)

    # B/C. /etc — canonical deployed. Writable directly, or via pkexec escalation.
    if want_etc:
        etc_path = os.path.join(etc_dir(), base)
        if _dir_writable(etc_dir()):
            return dict(path=etc_path, dir=etc_dir(),
                        mode=(panels_mode if kind == "panels" else 0o644),
                        needs_privilege=False, via="etc", marker=None)
        if can_escalate:
            return dict(path=etc_path, dir=etc_dir(),
                        mode=(panels_mode if kind == "panels" else 0o644),
                        needs_privilege=True, via="etc", marker=None)

    # E. dev checkout — when SOC_ROOT is the repo and /etc isn't the target, prefer
    #    the repo file (today's dev behaviour) only if its dir is writable.
    repo = repo_root()
    repo_path = _repo_candidates(kind)[0]
    in_repo_checkout = os.path.isdir(os.path.join(repo, "kiosk-host"))
    if not want_etc and in_repo_checkout and _dir_writable(os.path.dirname(repo_path)):
        return dict(path=repo_path, dir=os.path.dirname(repo_path),
                    mode=(panels_mode if kind == "panels" else 0o600),
                    needs_privilege=False, via="repo", marker=None)

    # D. user dir fallback — normally always writable by the user; drop the marker
    #    so the reader's marker-gated tier #2 picks this file up immediately. But a
    #    locked-down/quota'd/immutable ~/.config CAN be unwritable: flag it so the
    #    caller fails SAFE with a specific cause instead of an uncaught PermissionError
    #    deep in write_file (the "tell you why, never silently fail" guarantee).
    ud = user_dir()
    return dict(path=os.path.join(ud, base), dir=ud,
                mode=(panels_mode if kind == "panels" else 0o600),
                needs_privilege=False, via="user", marker=active_marker(),
                unwritable=not _dir_writable(ud))


# --------------------------------------------------------------------------- #
# CLI — so the shell launchers stay in lock-step with this Python.
# --------------------------------------------------------------------------- #
def _print_resolved(kind: str) -> int:
    path = resolve_read(kind)[0]
    if not path:
        return 3  # nothing resolvable — lets the shell tell "no config" from "error"
    sys.stdout.write(path + "\n")
    return 0


def _explain() -> int:
    """Print the full candidate chain + winner + why, for both kinds (doctor/debug)."""
    marked = os.path.exists(active_marker())
    sys.stdout.write(f"user marker: {active_marker()} "
                     f"({'present -> user config active' if marked else 'absent -> /etc wins'})\n")
    for kind in ("panels", "env"):
        winner, label = resolve_read(kind)
        sys.stdout.write(f"\n[{kind}] resolves to: {winner or '(none)'}  <- {label}\n")
        for path, lbl in candidates(kind):
            mark = "  *" if path == winner else "   "
            exists = "exists" if os.path.exists(path) else "missing"
            sys.stdout.write(f"{mark} {lbl:32s} {exists:8s} {path}\n")
    sys.stdout.write(f"\nsecret_dir resolves to: {resolve_secret_dir()}\n")
    sys.stdout.write(f"webdata_dir resolves to: {resolve_webdata_dir()}\n")
    return 0


def _write_target(kind: str) -> int:
    """Print the chosen WRITE path. Honours SOC_FORCE_ETC / SOC_ALLOW_PKEXEC so the
    wizard shell wrapper and Python agree on the target."""
    want_etc = os.environ.get("SOC_FORCE_ETC", "1") != "0"
    can_escalate = os.environ.get("SOC_ALLOW_PKEXEC", "0") == "1"
    t = resolve_write(kind, want_etc=want_etc, can_escalate=can_escalate)
    sys.stdout.write(t["path"] + "\n")
    return 0


def _check() -> int:
    """Validate this module's own wiring (no display, nonzero on inconsistency)."""
    problems: "list[str]" = []
    for kind in ("panels", "env"):
        # candidates must be non-empty and start with the override slot iff set
        cands = candidates(kind)
        if not cands:
            problems.append(f"{kind}: empty candidate chain")
        # The write target, once written, must be where resolve_read lands. We can't
        # write here, but we CAN assert the invariant structurally: a user-dir write
        # carries a marker, and resolve_read's user tier is marker-gated to that path.
        w = resolve_write(kind, want_etc=False, can_escalate=False)
        if w["via"] == "user" and not w["marker"]:
            problems.append(f"{kind}: user-dir write target lacks a marker (would be shadowed)")
        if os.path.isabs(w["path"]) is False:
            problems.append(f"{kind}: write path not absolute: {w['path']}")
    # the env-override slot must be honoured for both kinds
    for kind, var in _ENV_OVERRIDE.items():
        if os.environ.get(var):
            top = candidates(kind)[0]
            if top[1] != f"${var}":
                problems.append(f"{kind}: {var} set but not the top read candidate")
    if problems:
        for p in problems:
            sys.stderr.write(f"configpaths --check: {p}\n")
        return 1
    sys.stdout.write("configpaths --check: OK\n")
    return 0


def _write_atomic(path: str, text: str, mode: int) -> str:
    """Write `text` to `path` atomically: stage into <path>.tmp in the SAME dir
    (so os.replace is a same-fs rename, never EXDEV), fsync the data, then return
    the tmp path WITHOUT replacing yet — the caller stages every file first and
    swaps them back-to-back so a crash never leaves one new / one stale. The final
    `mode` is baked into the open, so there is no post-replace chmod race. Mirrors
    secretstore._write_atomic / backup.write_backup. Re-raises OSError (ENOSPC)."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp


def _install_etc() -> int:
    """pkexec helper: read rendered panels.yaml + soc.env from STDIN and write them
    root-owned into /etc/soc-display (panels 0644, env 0644 — non-secret). Content comes from
    STDIN — NEVER argv — so panel URLs / emails never appear on the process table,
    and SOC_VAULT_PASSWORD is never passed in (it isn't in soc.env). Input format:
        ---PANELS---\n<panels.yaml>\n---ENV---\n<soc.env>
    Both files are staged (written + fsync'd) into <path>.tmp BEFORE either is
    swapped in, then the two os.replace() calls run back-to-back, so a crash /
    ENOSPC mid-write can never leave a NEW panels.yaml beside a STALE soc.env (the
    half-updated /etc that bricks the next boot). Leftover *.tmp are unlinked on
    any failure, leaving the previous pair intact."""
    data = sys.stdin.read()
    PMARK, EMARK = "---PANELS---\n", "\n---ENV---\n"
    if not data.startswith(PMARK) or EMARK not in data:
        sys.stderr.write("configpaths --install-etc: malformed STDIN "
                         "(want ---PANELS---/---ENV--- markers)\n")
        return 2
    body = data[len(PMARK):]
    panels_text, env_text = body.split(EMARK, 1)
    pf = os.path.join(etc_dir(), PANELS_BASENAME)
    ef = os.path.join(etc_dir(), ENV_BASENAME)
    # Writing /etc requires root; this helper is only ever invoked via pkexec (as
    # root). If it's run directly by a non-root user the os.makedirs/open raise
    # PermissionError — catch it and emit the same clean, actionable error the
    # secretstore --seal helper uses instead of dumping a traceback. ENOSPC is NOT
    # swallowed into success either: it surfaces via the same OSError arm.
    p_tmp = e_tmp = None
    try:
        os.makedirs(etc_dir(), exist_ok=True)
        os.chmod(etc_dir(), 0o755)
        # Stage BOTH temps fully (written + fsync'd, final mode baked in) before
        # swapping either — so the swap step can't be interrupted half-way.
        p_tmp = _write_atomic(pf, panels_text, 0o644)
        e_tmp = _write_atomic(ef, env_text, 0o644)
        os.replace(p_tmp, pf)
        p_tmp = None
        os.replace(e_tmp, ef)
        e_tmp = None
    except OSError as e:
        sys.stderr.write(f"configpaths --install-etc: {e} "
                         f"(must run as root via pkexec)\n")
        return 1
    finally:
        # Remove any leftover *.tmp so a partial failure leaves no orphan temps
        # (the previous pf/ef pair stays intact because we never truncated them).
        for t in (p_tmp, e_tmp):
            if t:
                try:
                    os.unlink(t)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
    # Best-effort group: leave to install.sh/setfacl for the kiosk user's read access.
    sys.stdout.write(f"wrote {pf} (0644) and {ef} (0644)\n")
    return 0


def _main(argv: "list[str]") -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="host.configpaths",
        description="Resolve the SOC-wall config read/write locations.")
    ap.add_argument("--panels", action="store_true", help="print the resolved panels.yaml READ path")
    ap.add_argument("--env", action="store_true", help="print the resolved soc.env READ path")
    ap.add_argument("--secret-dir", action="store_true", help="print the resolved secret dir")
    ap.add_argument("--webdata-dir", action="store_true", help="print the resolved web-data dir")
    ap.add_argument("--panels-write", action="store_true", help="print the chosen panels.yaml WRITE path")
    ap.add_argument("--env-write", action="store_true", help="print the chosen soc.env WRITE path")
    ap.add_argument("--write-target", choices=["panels", "env"],
                    help="print the chosen WRITE path for the given kind")
    ap.add_argument("--explain", action="store_true", help="print the candidate chain + winner")
    ap.add_argument("--check", action="store_true", help="validate wiring (nonzero on inconsistency)")
    ap.add_argument("--install-etc", action="store_true",
                    help="pkexec helper: write /etc from STDIN (---PANELS---/---ENV---)")
    args = ap.parse_args(argv)

    if args.panels:        return _print_resolved("panels")
    if args.env:           return _print_resolved("env")
    if args.secret_dir:    sys.stdout.write(resolve_secret_dir() + "\n"); return 0
    if args.webdata_dir:   sys.stdout.write(resolve_webdata_dir() + "\n"); return 0
    if args.panels_write:  return _write_target("panels")
    if args.env_write:     return _write_target("env")
    if args.write_target:  return _write_target(args.write_target)
    if args.explain:       return _explain()
    if args.check:         return _check()
    if args.install_etc:   return _install_etc()
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
