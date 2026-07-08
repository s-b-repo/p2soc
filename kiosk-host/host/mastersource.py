"""
Pluggable, universal source for the Vaultwarden MASTER PASSWORD.

The master password (which derives the account key) must NOT live in a plaintext
.env. This module resolves it from one of three sources, chosen by the
SOC_MASTER_SOURCE environment variable (default 'auto'):

  sealed          Host-bound AES-256-GCM seal via host/secretstore.py
                  (machine-id + sealed PIN). DEFAULT for unattended / headless
                  kiosks: no login session, wallet, or prompt is needed to unlock,
                  so the wall self-unlocks at boot. KEEP this as the default.

  secret-service  The freedesktop Secret Service API (org.freedesktop.secrets),
                  reached via the `secret-tool` CLI from libsecret. KWallet,
                  GNOME Keyring and KeePassXC ALL implement it, and it is D-Bus
                  based (display-server-agnostic) — so it is the *universal*
                  answer that covers KDE and is portable across Wayland
                  compositors (Wayfire, labwc, cage, sway) AND X11. The wallet
                  must be running and UNLOCKED (see the headless caveat in
                  docs/SECURITY.md).

  env             os.environ['SOC_VAULT_PASSWORD']. DEV / seeding ONLY — prints a
                  deprecation warning. The master is NEVER written to a file by
                  any production flow.

  auto            sealed (if a complete seal exists) -> secret-service (if
                  secret-tool is present and the lookup succeeds) -> env.

Resolution NEVER raises for a missing/absent source: it degrades to '' and writes
a one-line diagnostic to stderr (matching scripts/pinentry-vault.py / litebw), so
a locked wallet or absent tool never wedges the kiosk boot. store_master() DOES
raise (MasterSourceError) — it is only ever called from setup.py, which surfaces
the typed error to the operator.

`from host import secretstore` is shared with litebw (Python caches the module
object) so a test that monkeypatches secretstore.is_sealed/unseal affects both.

Stdlib only (+ shelling out to secret-tool). No new pip deps.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from host import secretstore

# Default Secret Service attribute pair. A lookup and a store must present the
# SAME attributes or they won't match. Overridable via SOC_SECRET_ATTRS (space-
# separated key=value pairs) or an explicit `attrs` argument.
_DEFAULT_ATTRS = {"service": "soc-wall", "account": "vault-master"}
_LABEL = "SOC wall vault master"

# A locked wallet can make `secret-tool lookup` block on an interactive prompt;
# bound it so a locked KWallet/keyring degrades to '' instead of wedging boot.
_SECRET_TOOL_TIMEOUT = 10

VALID_SOURCES = ("sealed", "secret-service", "env")


class MasterSourceError(Exception):
    """Raised only by store_master() (refused / empty writes). get_master() never
    raises this — it degrades to '' so the boot path stays crash-free."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _secret_dir() -> str:
    """Mirror secretstore.secret_dir() so the sealed source honours a custom
    $SOC_SECRET_DIR exactly like the rest of the wall."""
    return secretstore.secret_dir()


def _have_secret_tool() -> bool:
    """True if the libsecret `secret-tool` CLI is on PATH. The single source of
    truth for secret-service availability (used by auto, available_sources, and
    setup.py's doctor)."""
    return shutil.which("secret-tool") is not None


def _resolve_attrs(attrs: dict | None = None) -> "dict[str, str]":
    """The Secret Service attribute pairs to look up / store under.

    Precedence: an explicit `attrs` dict > SOC_SECRET_ATTRS (space-separated
    key=value) > the fixed default (service=soc-wall account=vault-master).
    """
    if attrs:
        return dict(attrs)
    raw = os.environ.get("SOC_SECRET_ATTRS", "").strip()
    if raw:
        out: dict[str, str] = {}
        for tok in raw.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                if k:
                    out[k] = v
        if out:
            return out
    return dict(_DEFAULT_ATTRS)


def _attr_argv(attrs: "dict[str, str]") -> list:
    argv: list = []
    for k, v in attrs.items():
        argv += [k, v]
    return argv


# --------------------------------------------------------------------------- #
# Source resolvers (private)
# --------------------------------------------------------------------------- #
def _from_sealed(secret_dir: str | None = None) -> str:
    """Unseal the host-bound master. '' when nothing is sealed; degrades to ''
    (one-line stderr note) on a SecretStoreError — never crashes the boot."""
    sd = secret_dir or _secret_dir()
    try:
        if secretstore.is_sealed(sd):
            return secretstore.unseal(sd)
    except secretstore.SecretStoreError as e:
        sys.stderr.write(f"mastersource: {e}\n")
    return ""


def _from_secret_service(attrs: dict | None = None) -> str:
    """`secret-tool lookup <k> <v> ...`. Returns the value verbatim (only a
    single trailing newline, if libsecret added one, is stripped — so a master
    with surrounding spaces survives). '' when the item is absent, the tool is
    missing, the wallet is locked (timeout), or any OSError."""
    pairs = _resolve_attrs(attrs)
    try:
        proc = subprocess.run(
            ["secret-tool", "lookup", *_attr_argv(pairs)],
            capture_output=True, text=True, timeout=_SECRET_TOOL_TIMEOUT)
    except FileNotFoundError:
        # tool absent — only worth a note when explicitly asked for this source
        sys.stderr.write("mastersource: secret-tool not found (install libsecret)\n")
        return ""
    except subprocess.TimeoutExpired:
        sys.stderr.write("mastersource: secret-tool timed out (wallet locked?)\n")
        return ""
    except OSError as e:
        sys.stderr.write(f"mastersource: secret-tool failed: {e}\n")
        return ""
    if proc.returncode != 0:
        return ""   # item not present in the wallet
    out = proc.stdout
    if out.endswith("\n"):
        out = out[:-1]
    return out


def _from_env() -> str:
    """os.environ['SOC_VAULT_PASSWORD'] (DEV / seeding only). Warns once when a
    value is actually present so an accidental prod use is visible."""
    pw = os.environ.get("SOC_VAULT_PASSWORD", "")
    if pw:
        sys.stderr.write(
            "mastersource: SOC_VAULT_PASSWORD from the environment is DEV/seeding "
            "only; production uses the sealed or secret-service source\n")
    return pw


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def available_sources() -> list:
    """Sources usable RIGHT NOW on this host, in resolution order — for doctor /
    wizard reporting. Pure capability probe: never unseals or performs a lookup
    (no side effects, no secret material returned).

    'env' is always listed (the variable may be set later); 'sealed' iff a
    complete seal exists and cryptography is importable; 'secret-service' iff
    secret-tool is on PATH.
    """
    out = []
    try:
        if secretstore.available() and secretstore.is_sealed(_secret_dir()):
            out.append("sealed")
    except secretstore.SecretStoreError:
        pass
    if _have_secret_tool():
        out.append("secret-service")
    out.append("env")
    return out


def get_master(source: str | None = None) -> str:
    """Resolve and RETURN the plaintext master password.

    `source` defaults to $SOC_MASTER_SOURCE or 'auto'. An explicit unknown source
    raises ValueError; everything else degrades to '' (never raises) so the boot
    path stays crash-free. The first non-empty value wins.
    """
    src = (source or os.environ.get("SOC_MASTER_SOURCE") or "auto").strip()
    if src == "sealed":
        return _from_sealed()
    if src == "secret-service":
        return _from_secret_service()
    if src == "env":
        return _from_env()
    if src == "auto":
        # sealed first so a sealed wall never reads a master from elsewhere.
        try:
            if secretstore.is_sealed(_secret_dir()):
                pw = _from_sealed()
                if pw:
                    return pw
        except secretstore.SecretStoreError as e:
            sys.stderr.write(f"mastersource: {e}\n")
        if _have_secret_tool():
            pw = _from_secret_service()
            if pw:
                return pw
        return _from_env()
    raise ValueError(
        f"unknown SOC_MASTER_SOURCE '{src}' (expected: auto|sealed|"
        f"secret-service|env)")


def store_master(pw: str, source: str, attrs: dict | None = None) -> None:
    """Persist `pw` to the named source.

    Only 'secret-service' is writable here (it hands the value to the wallet
    daemon — never to a plaintext file). 'sealed' is refused (sealing needs the
    PIN + machine-id flow in secretstore.seal()/setup.py first-run). 'env' is
    refused outright — this is the programmatic guarantee that no production flow
    writes the master to a file.
    """
    if not pw:
        raise MasterSourceError("refusing to store an empty master password")
    if source == "secret-service":
        _store_secret_service(pw, attrs)
        return
    if source == "sealed":
        raise MasterSourceError(
            "the 'sealed' source is written by setup.py first-run (one-time PIN "
            "+ host-bound seal), not by store_master()")
    if source == "env":
        raise MasterSourceError(
            "the 'env' source is read-only / dev-only; refusing to write a "
            "plaintext master to any file")
    raise MasterSourceError(
        f"unknown master source '{source}' (expected: secret-service)")


def _store_secret_service(pw: str, attrs: dict | None = None) -> None:
    """`secret-tool store --label ... <k> <v> ...`, feeding the secret on STDIN
    (never on argv, so it can't leak via ps/proc). Requires a running, unlocked
    Secret Service daemon + a D-Bus session."""
    if not _have_secret_tool():
        raise MasterSourceError(
            "secret-tool not found — install libsecret (apt: libsecret-tools, "
            "dnf/pacman/apk/xbps: libsecret) to use the secret-service source")
    pairs = _resolve_attrs(attrs)
    try:
        proc = subprocess.run(
            ["secret-tool", "store", "--label", _LABEL, *_attr_argv(pairs)],
            input=pw, text=True, capture_output=True,
            timeout=_SECRET_TOOL_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise MasterSourceError(
            "secret-tool store timed out — is the wallet (KWallet / "
            "gnome-keyring / KeePassXC) running and unlocked?")
    except OSError as e:
        raise MasterSourceError(f"secret-tool store failed: {e}")
    if proc.returncode != 0:
        raise MasterSourceError(
            f"secret-tool store failed: {(proc.stderr or '').strip() or 'no Secret Service?'}")
