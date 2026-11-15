"""
Verify an operator's OPERATING-SYSTEM password — separate from the wall's
own PIN / TOTP gates.

Why this exists: the password-manager Edit flow (read+modify an existing
vault item) is more sensitive than Delete. Delete needs the wall PIN/TOTP
because the operator who set the PIN clearly has physical access. Edit
hands the operator a STORED CREDENTIAL — which is the worst possible
data class for a stolen PIN to leak.

So Edit is gated by the same authentication the box uses to grant root /
unlock the session: the operator's local UNIX password. A local-only
attacker with the PIN still gets nothing without that.

Three backends are tried in order, su first because it's the only one
that reliably works cross-user when the wall runs as `soc` and needs to
verify the desktop operator's password:

  1. `su` subprocess — universal Unix fallback, but actually the most
     reliable when caller and target user differ. `su - USER -c true`
     with the password on stdin. su is setuid root and PAM-stack-aware
     so it can read /etc/shadow + verify arbitrary users' passwords.
     This is the production path because pam/pamtester both fail for
     cross-user checks (pam_unix uses the setgid-shadow `unix_chkpwd`
     helper, which intentionally refuses to verify someone else's
     password from a non-privileged caller).
  2. `pamtester` CLI — works only when the caller has shadow group
     access OR the target user IS the caller. Tried second as a
     latency optimisation (no shell startup overhead vs su).
  3. python3-pampy (`import pam`) — same constraint as pamtester.
     Tried last because it shares pamtester's limitations and adds
     a Python-binding dep. Two import shapes accepted:
     `pam.pam().authenticate(user, pw)`  (modern pampy)
     `pam.authenticate(user, pw)`        (older < 1.8)

Every backend returns ONLY a bool. We never store / log / display the
entered password; the variable goes out of scope at function return. It travels
on the backend's stdin, never argv.

`su` only proves something when it actually asks. Two cases where it does not
are refused rather than trusted: a root caller (pam_rootok lets root su to anyone
with no password at all, so su is skipped and the PAM backends decide) and a
target account with an empty password (su then succeeds whatever was typed, so
a random wrong password is tried too, and an account that accepts it fails).

The username reaches su/pamtester as its own argv slot and can be typed at the
glass, so anything shaped like an option is rejected before a backend runs.
"""
from __future__ import annotations

import logging
import os
import pwd
import re
import secrets
import shutil
import subprocess
import time


_log = logging.getLogger("soc.ospass")

# A POSIX-ish account name. Rejects a leading '-': the name is an argv slot of a
# setuid binary, and at the glass it is free text.
_USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\$?\Z")


def operator_user() -> str:
    """The OS user whose password Edit should validate against.

    Resolution order:
      1. SOC_OPERATOR_USER env var (explicit operator config, recommended).
      2. SUDO_USER (set by sudo — the user who launched the wall) — but
         ONLY if it's a real desktop user, not 'root'. The double-sudo
         pattern `sudo … sudo -u soc bash …` sets SUDO_USER=root in
         soc's environment; we'd then prompt for root's password which
         is locked on most distros (Kali, Ubuntu, Fedora workstation).
      3. The first /etc/passwd entry with uid >= 1000 AND a real
         interactive shell — the standard Linux convention for human
         desktop users. This catches `kali`, `pi`, `debian`, or
         whatever the operator created at install time.
      4. The kali / pi / debian conventional usernames as a final
         specific-name fallback.
      5. The wall's own running user (usually `soc`) — last resort,
         will only authenticate if that user has a password set.

    Never raises; always returns a non-empty string."""
    if v := os.environ.get("SOC_OPERATOR_USER", "").strip():
        if _user_exists(v):
            return v
    sudo_u = os.environ.get("SUDO_USER", "").strip()
    if sudo_u and sudo_u != "root" and _user_exists(sudo_u):
        return sudo_u
    # /etc/passwd scan for the first real human user.
    try:
        for entry in pwd.getpwall():
            if entry.pw_uid < 1000 or entry.pw_uid == 65534:  # nobody
                continue
            shell = (entry.pw_shell or "").rsplit("/", 1)[-1]
            if shell in _NON_LOGIN_SHELLS:
                continue
            return entry.pw_name
    except Exception:                                  # noqa: BLE001
        pass
    for guess in ("kali", "pi", "operator", "admin", "debian", "ubuntu"):
        if _user_exists(guess):
            return guess
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return "root"


_NON_LOGIN_SHELLS = frozenset((
    "nologin", "false", "sync", "halt", "shutdown",
))


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def verify_os_password(user: str, password: str,
                       *, timeout: float = 5.0) -> bool:
    """Returns True iff `password` is `user`'s current OS login password.

    Never raises. Constant-time wall-clock: every backend takes at least
    `_MIN_LATENCY_SEC` seconds so wrong-vs-right can't be distinguished by
    response timing (PAM modules vary, su is fast)."""
    if not user or not password or not _USERNAME_RE.match(user):
        return False
    start = time.monotonic()
    try:
        # Order matters: su is the only backend that reliably works
        # cross-user from an unprivileged caller (see module docstring).
        for backend in (_verify_via_su,
                        _verify_via_pamtester,
                        _verify_via_pam):
            try:
                rv = backend(user, password, timeout=timeout)
            except Exception as e:                       # noqa: BLE001
                # Type only: an encode error's text quotes the input, which here
                # is the password.
                _log.debug("ospass backend %s raised %s",
                           backend.__name__, type(e).__name__)
                rv = None
            if rv is None:
                continue                                 # backend unusable
            return bool(rv)
        _log.warning("no OS-password verifier available "
                     "(python3-pam, pamtester, or su)")
        return False
    finally:
        elapsed = time.monotonic() - start
        if elapsed < _MIN_LATENCY_SEC:
            time.sleep(_MIN_LATENCY_SEC - elapsed)


_MIN_LATENCY_SEC = 0.30


def _verify_via_pam(user: str, password: str, *, timeout: float):
    """python3-pam path. Returns True/False on a real attempt; None if the
    binding is unavailable."""
    try:
        import pam as _pam                              # type: ignore
    except ImportError:
        return None
    # Two API shapes exist; try both.
    if hasattr(_pam, "pam"):
        try:
            p = _pam.pam()
            return bool(p.authenticate(user, password, service="login"))
        except TypeError:
            return bool(p.authenticate(user, password))
    if hasattr(_pam, "authenticate"):
        try:
            return bool(_pam.authenticate(user, password, service="login"))
        except TypeError:
            return bool(_pam.authenticate(user, password))
    return None


def _verify_via_pamtester(user: str, password: str, *, timeout: float):
    """pamtester CLI. Returns True/False on a real attempt; None if the
    binary isn't installed."""
    if not shutil.which("pamtester"):
        return None
    try:
        r = subprocess.run(
            ["pamtester", "login", user, "authenticate"],
            input=password,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _su_accepts(user: str, password: str, timeout: float) -> bool:
    """One `su` attempt. A timeout or OS error counts as a refusal."""
    # `su - <user> -c true` reads the password on stdin via PAM when no
    # tty is attached. Works on every Linux distro tested. Returns 0 on
    # success, non-zero on auth failure (and on other errors, which we
    # conservatively treat as auth failure).
    try:
        r = subprocess.run(
            ["su", "-", user, "-c", "true"],
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _verify_via_su(user: str, password: str, *, timeout: float):
    """su subprocess fallback. Returns True/False on a real attempt; None
    if su can't vouch for anything here: the binary is missing (extremely
    unlikely on Linux), or we run as root, where pam_rootok makes it succeed
    with no password check at all."""
    if not shutil.which("su") or os.geteuid() == 0:
        return None
    if not _su_accepts(user, password, timeout):
        return False
    # A password-less account lets su through whatever was typed, which would
    # let anyone at the glass name that account and pass this gate.
    return not _su_accepts(user, secrets.token_urlsafe(24), timeout)
