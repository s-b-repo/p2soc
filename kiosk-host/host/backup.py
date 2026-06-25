"""
Portable, passphrase-encrypted backup of the Vaultwarden data dir.

Why this is separate from the host-bound seal (`secretstore`): a backup exists
precisely so the vault can be restored on **different hardware** after an
SD-card failure. The seal is bound to the machine-id and `host.key`, so it cannot
travel. A backup is therefore encrypted under an **operator passphrase** kept off
the box — never the machine-id.

Crypto (reuses the vetted primitives in `secretstore`):
  * AES-256-GCM (AEAD) over a gzip tar of the data dir.
  * scrypt (RFC 7914) KDF — the same single, memory-hard KDF `secretstore`
    uses for the host-bound seal.

On-disk format (single file):
    MAGIC(4) | salt(16) | nonce(12) | AESGCM(gzip(tar(src_dir)))

The whole archive is built in memory: a kiosk vault is small (a handful of
logins). For a large vault with attachments, back up out-of-band instead.

CLI:
    python -m host.backup backup  <src_dir> <out_file>
    python -m host.backup restore <in_file>  <dest_dir>
The passphrase is read from $SOC_BACKUP_PASSPHRASE or prompted (never on argv).
"""
from __future__ import annotations

import io
import os
import tarfile

from . import secretstore as ss

_MAGIC = b"PSBK"                       # p2soc backup, distinct from the seal's "PS"
_MIN_PASSPHRASE = 8                    # NIST SP 800-63B: user-chosen secret floor
_HEADER = len(_MAGIC) + 16 + 12       # magic + salt + nonce


class BackupError(Exception):
    pass


def _tar_gz(src_dir: str) -> bytes:
    if not os.path.isdir(src_dir):
        raise BackupError(f"backup source is not a directory: {src_dir}")
    buf = io.BytesIO()
    # gzip keeps the archive compact on the SD card.
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        tar.add(src_dir, arcname=os.path.basename(src_dir.rstrip("/")) or "data")
    return buf.getvalue()


def make_backup(src_dir: str, passphrase: str) -> bytes:
    """Return an encrypted backup blob of `src_dir`."""
    if not passphrase or len(passphrase) < _MIN_PASSPHRASE:
        raise BackupError(
            f"backup passphrase too short: need at least {_MIN_PASSPHRASE} "
            "characters (NIST SP 800-63B)")
    AESGCM = ss._aesgcm()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = ss._kdf(passphrase.encode("utf-8"), salt)
    ct = AESGCM(key).encrypt(nonce, _tar_gz(src_dir), None)
    return _MAGIC + salt + nonce + ct


def open_backup(blob: bytes, passphrase: str) -> bytes:
    """Decrypt a backup blob and return the inner gzip-tar bytes."""
    if len(blob) < _HEADER or blob[:len(_MAGIC)] != _MAGIC:
        raise BackupError("not a p2soc backup file (bad magic) or truncated")
    off = len(_MAGIC)
    salt, nonce, ct = blob[off:off + 16], blob[off + 16:off + 28], blob[off + 28:]
    AESGCM = ss._aesgcm()
    try:
        key = ss._kdf(passphrase.encode("utf-8"), salt)
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:                  # InvalidTag -> wrong passphrase / tampered
        raise BackupError("could not decrypt backup — wrong passphrase or the "
                          "file is corrupt/tampered")


def write_backup(src_dir: str, out_path: str, passphrase: str) -> None:
    """Write an encrypted backup to `out_path` (0600, atomic)."""
    blob = make_backup(src_dir, passphrase)
    tmp = out_path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, blob)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, out_path)


def restore_backup(in_path: str, dest_dir: str, passphrase: str) -> None:
    """Decrypt `in_path` and extract its tar into `dest_dir`."""
    with open(in_path, "rb") as fh:
        inner = open_backup(fh.read(), passphrase)
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r:gz") as tar:
        _safe_extract(tar, dest_dir)


def _safe_extract(tar: "tarfile.TarFile", dest_dir: str) -> None:
    """Extract guarding against path traversal (CVE-2007-4559 / Zip-Slip): every
    member must resolve to inside dest_dir, and we refuse links/devices."""
    dest = os.path.realpath(dest_dir)
    for m in tar.getmembers():
        if m.issym() or m.islnk() or m.isdev():
            raise BackupError(f"refusing unsafe archive member: {m.name!r}")
        target = os.path.realpath(os.path.join(dest, m.name))
        if target != dest and not target.startswith(dest + os.sep):
            raise BackupError(f"path traversal in archive member: {m.name!r}")
    # belt-and-suspenders: also use the stdlib 'data' filter where available
    # (Python 3.12+; default-on in 3.14). Fall back cleanly on older runtimes.
    try:
        tar.extractall(dest_dir, filter="data")
    except TypeError:
        tar.extractall(dest_dir)


def _passphrase_from_env_or_prompt(confirm: bool = False) -> str:
    pw = os.environ.get("SOC_BACKUP_PASSPHRASE")
    if pw:
        return pw
    import getpass
    pw = getpass.getpass("Backup passphrase: ")
    if confirm and getpass.getpass("Confirm passphrase: ") != pw:
        raise BackupError("passphrases did not match")
    return pw


def _cli(argv) -> int:
    if len(argv) >= 4 and argv[1] == "backup":
        write_backup(argv[2], argv[3],
                     _passphrase_from_env_or_prompt(confirm=True))
        print(f"wrote encrypted backup -> {argv[3]}")
        return 0
    if len(argv) >= 4 and argv[1] == "restore":
        restore_backup(argv[2], argv[3], _passphrase_from_env_or_prompt())
        print(f"restored {argv[2]} -> {argv[3]}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    import sys
    try:
        sys.exit(_cli(sys.argv))
    except BackupError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
