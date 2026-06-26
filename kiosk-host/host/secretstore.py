"""
Host-bound, PIN-sealed storage for the vault master password.

This removes the plaintext master password from disk — there is no
SOC_VAULT_PASSWORD in any .env any more. The master password is sealed with
AES-256-GCM under a key derived (scrypt) from BOTH this host's machine-id AND a
one-time PIN that `setup.py` generates and shows the operator exactly once.

So the wall can boot unattended (no prompt), the PIN is itself sealed under a
machine-id-only key. Net effect:

  * nothing on disk is the plaintext master password;
  * the sealed files are useless if copied to another machine (different
    machine-id → key derivation fails → GCM auth fails);
  * the operator's one-time PIN is needed to *re-seal* (re-deploy, move to new
    hardware, or change the password) and to authorise destructive setup steps.

Files (under $SOC_SECRET_DIR, default /etc/soc-display/secret, dir 0700, files 0600):
  master.enc   salt|nonce|AESGCM(key = scrypt(machine_id + pin)) of the master pw
  pin.enc      salt|nonce|AESGCM(key = scrypt(machine_id))       of the PIN
  pin.hash     "<salt_hex>$<sha256(salt+pin)>"  — lets setup verify the PIN

Needs the `cryptography` package (imported lazily). available() reports whether
it is importable; callers degrade to a clear error otherwise.

For tests, $SOC_MACHINE_ID overrides the real machine-id (simulate other hosts).
"""
from __future__ import annotations

import hashlib
import hmac
import os

_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32, maxmem=96 * 1024 * 1024)


class SecretStoreError(Exception):
    pass


def secret_dir(d: str | None = None) -> str:
    return d or os.environ.get("SOC_SECRET_DIR") or "/etc/soc-display/secret"


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        raise SecretStoreError(
            "the 'cryptography' package is required to seal/unseal the vault "
            "master password (pip install cryptography)")


def available() -> bool:
    """True if the crypto backend needed to seal/unseal is importable."""
    try:
        _aesgcm()
        return True
    except SecretStoreError:
        return False


def _machine_id() -> bytes:
    v = os.environ.get("SOC_MACHINE_ID")
    if v:
        return v.strip().encode()
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p, encoding="utf-8") as fh:
                s = fh.read().strip()
            if s:
                return s.encode()
        except OSError:
            continue
    raise SecretStoreError("no machine-id (/etc/machine-id missing or empty) — "
                           "set SOC_MACHINE_ID, or run `systemd-machine-id-setup`")


def _kdf(material: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(material, salt=salt, **_SCRYPT)


def _encrypt(material: bytes, plaintext: bytes) -> bytes:
    AESGCM = _aesgcm()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ct = AESGCM(_kdf(material, salt)).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def _decrypt(material: bytes, blob: bytes) -> bytes:
    AESGCM = _aesgcm()
    if len(blob) < 28:
        raise SecretStoreError("sealed blob is too short / corrupt")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    try:
        return AESGCM(_kdf(material, salt)).decrypt(nonce, ct, None)
    except Exception:  # cryptography.exceptions.InvalidTag, etc.
        raise SecretStoreError(
            "could not unseal — wrong machine (the secret is bound to the host "
            "it was sealed on) or the files are corrupt; re-run setup.py to re-seal")


def _write(path: str, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _write_atomic(path: str, data: bytes) -> str:
    """Write `data` to `path`.tmp (0600, fsync'd) and return the tmp path. The
    caller os.replace()s it into place once every blob is staged, so an
    interrupted seal never leaves a torn file under `path`."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        raise SecretStoreError(f"sealed secret not found: {path} (run setup.py)")


_SEAL_FILES = ("pin.hash", "pin.enc", "master.enc")


def is_sealed(d: str | None = None) -> bool:
    """True only when a *complete* seal is present. Requiring all three files
    (not just master.enc) means a half-written seal reads as 'not sealed' so the
    operator re-seals instead of booting into an unrecoverable state."""
    sd = secret_dir(d)
    return all(os.path.exists(os.path.join(sd, f)) for f in _SEAL_FILES)


def seal(master: str, pin: str, d: str | None = None):
    """Seal the master password + PIN under this host. Overwrites any prior seal.

    All three blobs are written to `*.tmp` (fsync'd) first, then os.replace()d
    into place with master.enc — the is_sealed() sentinel — last. So an
    interruption during a fresh seal leaves master.enc absent (is_sealed False),
    never a torn file that looks sealed but cannot unseal."""
    if not master:
        raise SecretStoreError("refusing to seal an empty master password")
    if not pin:
        raise SecretStoreError("refusing to seal an empty PIN")
    sd = secret_dir(d)
    os.makedirs(sd, exist_ok=True)
    try:
        os.chmod(sd, 0o700)
    except OSError:
        pass
    mid = _machine_id()
    salt = os.urandom(16)
    blobs = {
        "master.enc": _encrypt(mid + pin.encode(), master.encode()),
        "pin.enc": _encrypt(mid, pin.encode()),
        "pin.hash": f"{salt.hex()}${hashlib.sha256(salt + pin.encode()).hexdigest()}".encode(),
    }
    # stage every blob before swapping any into place
    tmps = {name: _write_atomic(os.path.join(sd, name), data)
            for name, data in blobs.items()}
    # commit in dependency order; master.enc (the sentinel) goes last
    for name in _SEAL_FILES:
        os.replace(tmps[name], os.path.join(sd, name))


def unseal(d: str | None = None) -> str:
    """Recover the master password (machine-id only — unattended). Raises
    SecretStoreError if not sealed / wrong host / corrupt."""
    sd = secret_dir(d)
    mid = _machine_id()
    pin = _decrypt(mid, _read(os.path.join(sd, "pin.enc"))).decode()
    return _decrypt(mid + pin.encode(), _read(os.path.join(sd, "master.enc"))).decode()


def verify_pin(pin: str, d: str | None = None) -> bool:
    """True if `pin` matches the sealed PIN (constant-time, via pin.hash)."""
    try:
        raw = _read(os.path.join(secret_dir(d), "pin.hash")).decode()
        salt_hex, want = raw.split("$", 1)
    except (SecretStoreError, ValueError):
        return False
    got = hashlib.sha256(bytes.fromhex(salt_hex) + pin.encode()).hexdigest()
    return hmac.compare_digest(got, want)


def gen_pin(digits: int = 8) -> str:
    """A fresh, uniformly-random numeric PIN (no modulo bias)."""
    import secrets
    return "".join(secrets.choice("0123456789") for _ in range(max(4, digits)))


# --------------------------------------------------------------------------- #
# CLI — a pkexec helper so the GUI/TTY wizard can RE-SEAL the master into a
# root-owned secret dir (e.g. /etc/soc-display/secret on a deployed box) without
# being root itself. The master + PIN arrive over STDIN — NEVER argv — so the
# master never appears on the process table, and nothing plaintext is ever written
# (it goes straight into the AES-GCM seal). The PIN actually used is printed to
# stdout so the caller can show the operator their one-time PIN.
#
#     printf '%s' "---MASTER---\n<master>\n---PIN---\n<pin>" \
#         | pkexec python3 -m host.secretstore --seal --dir /etc/soc-display/secret
#
# (<pin> may be empty -> a fresh PIN is generated.)
# --------------------------------------------------------------------------- #
_SEAL_MARK = "---MASTER---\n"
_PIN_MARK = "\n---PIN---\n"


def _seal_from_stdin(secret_dir: str) -> int:
    import sys
    data = sys.stdin.read()
    if not data.startswith(_SEAL_MARK) or _PIN_MARK not in data:
        sys.stderr.write("secretstore --seal: malformed STDIN "
                         "(want ---MASTER---/---PIN--- markers)\n")
        return 2
    body = data[len(_SEAL_MARK):]
    master, pin = body.split(_PIN_MARK, 1)
    if not master:
        sys.stderr.write("secretstore --seal: empty master — nothing sealed\n")
        return 2
    pin = pin or gen_pin()
    try:
        seal(master, pin, secret_dir)
        # Verify it round-trips on THIS host before we report success, so the
        # caller never trusts a seal the wall can't later unseal.
        if unseal(secret_dir) != master:
            raise SecretStoreError("seal did not unseal to the same value")
    except SecretStoreError as e:
        sys.stderr.write(f"secretstore --seal: {e}\n")
        return 1
    sys.stdout.write(pin + "\n")   # the one-time PIN, for the caller to surface
    return 0


def _main(argv: "list[str]") -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="host.secretstore",
        description="Seal the vault master host-bound (pkexec helper for the wizard).")
    ap.add_argument("--seal", action="store_true",
                    help="read ---MASTER---/---PIN--- from STDIN and seal into --dir")
    ap.add_argument("--dir", help="secret dir to seal into (default $SOC_SECRET_DIR)")
    args = ap.parse_args(argv)
    if args.seal:
        return _seal_from_stdin(secret_dir(args.dir))
    ap.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
