"""
Host-bound, PIN-sealed storage for the vault master password.

This removes the plaintext master password from disk — there is no
SOC_VAULT_PASSWORD in any .env any more. The master password is sealed with
AES-256-GCM under a key derived from THREE factors:

  1. a 256-bit random *host key* (`host.key`, 0600, never world-readable),
  2. this host's machine-id, and
  3. a one-time PIN that `setup.py` generates and shows the operator exactly once.

So the wall can boot unattended (no prompt), the PIN is itself sealed under a
key derived from (host key + machine-id). Net effect:

  * nothing on disk is the plaintext master password;
  * the seal's strength does NOT rest on the machine-id, which is world-readable
    (0644) on systemd hosts and therefore not a secret — the binding secret is
    the 0600 `host.key`. Knowing the machine-id is useless without it;
  * the sealed files are useless if copied to another machine (different
    machine-id) *or* copied without `host.key` (key derivation → GCM auth fails);
  * the operator's one-time PIN is needed to *re-seal* (re-deploy, move to new
    hardware, or change the password) and to authorise destructive setup steps.

Files (under $SOC_SECRET_DIR, default /etc/soc-display/secret, dir 0700, files 0600):
  host.key     32 random bytes — the per-host binding secret (never leaves 0700 dir)
  master.enc   MAGIC|ALGO|salt|nonce|AESGCM(key = KDF(host_key+machine_id+pin)) of the master pw
  pin.enc      MAGIC|ALGO|salt|nonce|AESGCM(key = KDF(host_key+machine_id))     of the PIN
  pin.hash     "<salt_hex>$<sha256(salt+pin)>"  — lets setup verify the PIN

KDF: scrypt (RFC 7914) N=2**17, r=8, p=1 (~128 MiB) by default. FIPS 140
deployments set SOC_FIPS_KDF=1 to use PBKDF2-HMAC-SHA256 (NIST SP 800-132, an
approved KDF) instead. The KDF id is stored in each blob (ALGO byte), so a sealed
blob always unseals with the algorithm it was sealed under, regardless of the
current SOC_FIPS_KDF setting.

Legacy seals (in the field): earlier releases wrote salt|nonce|ct with scrypt
N=2**14, keyed by the machine-id alone, and no host.key. unseal() still reads
those and transparently migrates them, same PIN, with no prompt — see
_migrate_legacy(). If the secret dir cannot be written the master is still
returned and the box simply stays on the legacy format until it can be.

Unseal cost: a full unseal runs the KDF twice (~128 MiB each on the 1 GB Pi), and
it happens far more often than once per boot — every retry of the boot-time vault
open, every 401 re-unlock, every credential save, every `litebw` subprocess. Each
one after the first is served by a per-uid *session ticket* on tmpfs (see
_ticket_load()): the master wrapped under a key derived from host.key, bound to
this boot, to the exact sealed bytes and to a TTL. It is ciphertext, never the
plaintext master, and it never reaches the disk or survives a reboot. Set
SOC_UNSEAL_CACHE_TTL=0 to disable it.

Needs the `cryptography` package (imported lazily). available() reports whether
it is importable; callers degrade to a clear error otherwise.

For tests, $SOC_MACHINE_ID overrides the real machine-id (simulate other hosts).
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import logging
import os
import stat
import struct
import time

_log = logging.getLogger("host.secretstore")

# Standards alignment:
#   * AES-256-GCM (AEAD), SHA-256 — NIST SP 800-131A approved; FIPS 140 ciphers.
#   * scrypt (RFC 7914) memory-hard KDF — N=2**17, r=8, p=1 (~128 MiB working set).
#     scrypt is NOT FIPS-approved; SOC_FIPS_KDF=1 selects PBKDF2-HMAC-SHA256.
#   * os.urandom — NIST SP 800-90A compliant CSPRNG.
#   * hmac.compare_digest — constant-time verification (timing-safe).
_SCRYPT = dict(n=2 ** 17, r=8, p=1, dklen=32, maxmem=200 * 1024 * 1024)
# What every seal and backup written before the v2 format used. Read-only: nothing
# new is ever sealed under it.
_LEGACY_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32, maxmem=96 * 1024 * 1024)

# Self-describing sealed-blob format:  MAGIC(2) | ALGO(1) | salt(16) | nonce(12) | ct
# The algorithm id is stored IN the blob, so a blob always unseals with the KDF it
# was sealed under — independent of the current SOC_FIPS_KDF setting.
_MAGIC = b"PS"
_ALGO_LEGACY_SCRYPT = 0   # internal id for unlabelled legacy data; never on disk
_ALGO_SCRYPT = 1          # RFC 7914 scrypt (default — memory-hard)
_ALGO_PBKDF2 = 2          # NIST SP 800-132 PBKDF2-HMAC-SHA256 (FIPS-approved)
# NIST SP 800-132 sets a 1000-iteration floor; this follows modern (OWASP) guidance
# for PBKDF2-HMAC-SHA256.
_PBKDF2_ITERS = 600_000
_BLOB_HEADER = len(_MAGIC) + 1 + 16 + 12   # magic + algo + salt + nonce
_LEGACY_HEADER = 16 + 12                   # salt + nonce

# Domain-separation label (NIST SP 800-108 "context"): bound into the KDF input so
# this seal's keys can never collide with any other scrypt use of the same inputs.
# The version suffix lets the on-disk format evolve without silent ambiguity.
_KDF_CONTEXT = b"p2soc-seal/v2"

# NIST SP 800-63B: a memorized authenticator floor. The PIN only authorises
# *re-seal*; host.key is the real binding secret, but reject trivially short PINs.
# Enforced when a PIN is CHOSEN (seal()), never when a legacy seal migrates: older
# releases allowed 4-digit PINs and such a box must not be locked out.
_MIN_PIN_LEN = 6

_HOST_KEY_FILE = "host.key"
_HOST_KEY_LEN = 32

# How long unseal()/seal() wait for another process holding the seal lock. Long
# enough for a concurrent unseal or migration on a loaded Pi; on expiry a reader
# carries on unlocked (safe, see unseal()) so a stuck peer can never block a boot.
_LOCK_WAIT = 20.0

_TICKET_FILE = "soc-unseal.ticket"
_TICKET_CONTEXT = b"p2soc-unseal-ticket/v1"
_TICKET_TTL = 3600                      # seconds; SOC_UNSEAL_CACHE_TTL overrides
_TICKET_MAX_BYTES = 64 * 1024
_RAM_FILESYSTEMS = ("tmpfs", "ramfs")


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


def _host_key_path(sd: str) -> str:
    return os.path.join(sd, _HOST_KEY_FILE)


def _read_host_key(sd: str) -> bytes:
    """Read the per-host binding secret. Its absence is fatal for a v2 seal —
    without it the seal cannot be derived (that is the whole point: machine-id
    alone is not a secret)."""
    try:
        with open(_host_key_path(sd), "rb") as fh:
            key = fh.read()
    except FileNotFoundError:
        raise SecretStoreError(
            "host.key missing — the seal is bound to a per-host key that is not "
            "present (copied without it, or never sealed); re-run `sudo python3 "
            "setup.py first-run` to re-seal")
    except OSError as e:
        raise SecretStoreError(f"cannot read host.key: {e}")
    if len(key) < _HOST_KEY_LEN:
        raise SecretStoreError("host.key is truncated/corrupt — re-run `sudo "
                               "python3 setup.py first-run` to re-seal")
    return key


def _binding_material(host_key: bytes) -> bytes:
    """The non-PIN key material: a domain-separation label (NIST SP 800-108
    context) + host key (the real secret) + machine-id (binds the seal to this
    physical host). machine-id is NOT trusted for secrecy."""
    return _KDF_CONTEXT + b"\x00" + host_key + b"\x00" + _machine_id()


def _kdf(material: bytes, salt: bytes, algo: int) -> bytes:
    try:
        if algo == _ALGO_PBKDF2:
            return hashlib.pbkdf2_hmac("sha256", material, salt, _PBKDF2_ITERS,
                                       dklen=32)
        if algo == _ALGO_SCRYPT:
            return hashlib.scrypt(material, salt=salt, **_SCRYPT)
        if algo == _ALGO_LEGACY_SCRYPT:
            return hashlib.scrypt(material, salt=salt, **_LEGACY_SCRYPT)
    except (ValueError, MemoryError) as e:
        # On the 1 GB Pi this is memory pressure, not a wrong key — don't let it
        # surface as "wrong machine" and send the operator after the wrong fix.
        raise SecretStoreError(f"key derivation failed ({e}) — out of memory?")
    raise SecretStoreError(f"unknown KDF algorithm id {algo} in sealed blob")


def _active_algo() -> int:
    """FIPS 140 deployments select PBKDF2 (an approved KDF) via SOC_FIPS_KDF=1;
    the default is scrypt (memory-hard, stronger against brute force)."""
    return _ALGO_PBKDF2 if os.environ.get("SOC_FIPS_KDF") == "1" else _ALGO_SCRYPT


def _is_v2_blob(blob: bytes) -> bool:
    """True if `blob` carries the v2 header. A legacy blob starts with a random
    salt, so about 1 in 8 million of them look like this by chance — which is why
    _open_blob() falls back to the legacy reader when v2 decryption fails."""
    return (len(blob) >= _BLOB_HEADER and blob[:len(_MAGIC)] == _MAGIC
            and blob[len(_MAGIC)] in (_ALGO_SCRYPT, _ALGO_PBKDF2))


def _encrypt(material: bytes, plaintext: bytes) -> bytes:
    AESGCM = _aesgcm()
    algo = _active_algo()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ct = AESGCM(_kdf(material, salt, algo)).encrypt(nonce, plaintext, None)
    return _MAGIC + bytes([algo]) + salt + nonce + ct


_UNSEAL_FAILED = ("could not unseal — wrong machine (the secret is bound to the "
                  "host it was sealed on) or the files are corrupt; re-run `sudo "
                  "python3 setup.py first-run` to re-seal")


def _decrypt(material: bytes, blob: bytes) -> bytes:
    AESGCM = _aesgcm()
    if len(blob) < _BLOB_HEADER or blob[:len(_MAGIC)] != _MAGIC:
        raise SecretStoreError(
            "sealed blob is too short / not in the expected format — re-run "
            "setup.py to re-seal")
    algo = blob[len(_MAGIC)]
    off = len(_MAGIC) + 1
    salt, nonce, ct = blob[off:off + 16], blob[off + 16:off + 28], blob[off + 28:]
    key = _kdf(material, salt, algo)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:  # cryptography.exceptions.InvalidTag, etc.
        raise SecretStoreError(_UNSEAL_FAILED)


def _decrypt_legacy(material: bytes, blob: bytes) -> bytes:
    """Read a pre-v2 blob: salt|nonce|ct, scrypt N=2**14."""
    AESGCM = _aesgcm()
    if len(blob) < _LEGACY_HEADER:
        raise SecretStoreError("sealed blob is too short / corrupt")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = _kdf(material, salt, _ALGO_LEGACY_SCRYPT)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:  # cryptography.exceptions.InvalidTag, etc.
        raise SecretStoreError(_UNSEAL_FAILED)


def _open_blob(blob: bytes, v2_material, legacy_material: bytes, key_err):
    """Decrypt one sealed blob of either format → (plaintext, was_legacy).

    The decision is made per blob, never per seal: an interrupted migration leaves
    a v2 pin.enc beside a legacy master.enc, and that state has to unseal.
    `v2_material` is None when there is no usable host.key; `key_err` says why."""
    if not _is_v2_blob(blob):
        return _decrypt_legacy(legacy_material, blob), True
    try:
        if v2_material is None:
            raise key_err
        return _decrypt(v2_material, blob), False
    except SecretStoreError as err:
        try:                            # a legacy salt that happens to look v2
            return _decrypt_legacy(legacy_material, blob), True
        except SecretStoreError:
            raise err


def _write(path: str, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _write_atomic(path: str, data: bytes, owner=None, mode: int = 0o600) -> str:
    """Write `data` to `path`.tmp (0600 unless `mode` says otherwise, fsync'd) and
    return the tmp path. The caller os.replace()s it into place once every blob is
    staged, so an interrupted seal never leaves a torn file under `path`. `owner`
    is a (uid, gid) to give the file; failing to is an error, not a shrug, because
    a seal its readers cannot open is a lockout."""
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        if owner is not None:
            os.fchown(fd, *owner)
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp


def _fsync_dir(sd: str) -> None:
    """Make completed renames durable, in order: without this a power cut can
    persist a later os.replace() and lose an earlier one."""
    try:
        fd = os.open(sd, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _commit(sd: str, names) -> None:
    """os.replace() staged `names` into place, in order, each durable before the
    next."""
    for name in names:
        path = os.path.join(sd, name)
        os.replace(path + ".tmp", path)
        _fsync_dir(sd)


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        raise SecretStoreError(f"sealed secret not found: {path} (run setup.py)")
    except OSError as e:
        # e.g. sealed as root but unsealing as the kiosk user. Callers (and the
        # crash-free boot path in mastersource) only expect SecretStoreError.
        raise SecretStoreError(f"cannot read sealed secret {path}: {e}")


@contextlib.contextmanager
def _seal_lock(sd: str, wait: float):
    """Exclusive advisory lock on the secret dir, yielding whether it is held.

    Commits touch several files and two writers interleaving them could pair one's
    host.key with the other's blobs — permanently unreadable — and at boot the wall
    (soc) and the VPN supervisor (root) can both reach a legacy seal at once. Held
    by every writer, and around the expensive unseal path too, so N waiters on the
    1 GB Pi run the 128 MiB KDF one at a time and then hit the fresh ticket.

    flock() on the directory itself: no lock file to leave behind, works for any
    process that can open the dir (read-only included), excludes across threads
    because each call opens its own description, and dies with its holder, so a
    crash cannot wedge the next boot."""
    fd = None
    held = False
    try:
        fd = os.open(sd, os.O_RDONLY | os.O_DIRECTORY)
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
    except OSError:
        pass                        # no dir yet, or no flock on this filesystem
    try:
        yield held
    finally:
        if fd is not None:
            os.close(fd)


# Commit order matters: host.key is needed to *derive* the seal, and master.enc
# is the is_sealed() sentinel — so host.key is committed first and master.enc
# last.
_SEAL_FILES = (_HOST_KEY_FILE, "pin.hash", "pin.enc", "master.enc")
_CORE_SEAL_FILES = ("pin.hash", "pin.enc", "master.enc")


def _header_is_v2(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return _is_v2_blob(fh.read(_BLOB_HEADER))
    except OSError:
        return False


def is_sealed(d: str | None = None) -> bool:
    """True only when a *complete* seal is present. Requiring every file (not just
    master.enc) means a half-written seal reads as 'not sealed' so the operator
    re-seals instead of booting into an unrecoverable state.

    host.key is required only by v2 blobs: a v2 seal copied without it reads as not
    sealed, while a legacy seal, which never had one, stays sealed."""
    sd = secret_dir(d)
    if not all(os.path.exists(os.path.join(sd, f)) for f in _CORE_SEAL_FILES):
        return False
    if os.path.exists(_host_key_path(sd)):
        return True
    return not any(_header_is_v2(os.path.join(sd, f))
                   for f in ("pin.enc", "master.enc"))


def _dir_owner(sd: str):
    """(uid, gid) new seal files should get: root writing into a directory it does
    not own (`sudo setup.py first-run`, the pkexec --seal helper, into the
    kiosk-owned /etc/soc-display/secret) must not leave files the wall cannot read."""
    if os.geteuid() != 0:
        return None
    st = os.stat(sd)
    return st.st_uid, st.st_gid


def seal(master: str, pin: str, d: str | None = None):
    """Seal the master password + PIN under this host. Overwrites any prior seal.

    Every file is written to `*.tmp` (fsync'd) first, then os.replace()d into place
    with master.enc — the is_sealed() sentinel — last. So an interruption during a
    fresh seal leaves master.enc absent (is_sealed False), never a torn file that
    looks sealed but cannot unseal."""
    if not master:
        raise SecretStoreError("refusing to seal an empty master password")
    if not pin:
        raise SecretStoreError("refusing to seal an empty PIN")
    if len(pin) < _MIN_PIN_LEN:
        raise SecretStoreError(
            f"PIN too short: need at least {_MIN_PIN_LEN} characters "
            "(NIST SP 800-63B memorized-authenticator floor)")
    sd = secret_dir(d)
    os.makedirs(sd, exist_ok=True)
    try:
        os.chmod(sd, 0o700)
    except OSError:
        pass
    # A fresh host key per (re-)seal: the 256-bit binding secret.
    host_key = os.urandom(_HOST_KEY_LEN)
    material = _binding_material(host_key)
    salt = os.urandom(16)
    blobs = {
        _HOST_KEY_FILE: host_key,
        "master.enc": _encrypt(material + b"\x00" + pin.encode(), master.encode()),
        "pin.enc": _encrypt(material, pin.encode()),
        "pin.hash": f"{salt.hex()}${hashlib.sha256(salt + pin.encode()).hexdigest()}".encode(),
    }
    owner = _dir_owner(sd)
    with _seal_lock(sd, _LOCK_WAIT) as locked:
        if not locked:
            _log.warning("sealing %s without the seal lock", sd)
        # stage every blob before swapping any into place
        for name, data in blobs.items():
            _write_atomic(os.path.join(sd, name), data, owner=owner)
        # commit in dependency order; host.key first, master.enc (the sentinel) last
        _commit(sd, _SEAL_FILES)
    _ticket_discard()


# Secret dirs this process already failed to migrate: staging costs two 128 MiB
# KDF runs, so a box that cannot complete it must not pay again on every unseal.
# Cleared by a restart, which is when whatever blocked it may have been fixed.
_migration_skip: set = set()


def _discard_tmp(sd: str, names) -> None:
    for name in names:
        with contextlib.suppress(OSError):
            os.unlink(os.path.join(sd, name) + ".tmp")


def _migrate_legacy(sd: str, pin: bytes, master: bytes, host_key, locked: bool):
    """Re-seal an unsealed legacy seal as v2, same PIN, with no prompt. Returns
    (host_key, pin_blob, master_blob) on success, None if it did not happen.
    NEVER raises: the caller already holds the master and a boot must not fail
    over an upgrade, so every failure is a logged warning and the box stays legacy.

    Crash safety. Everything is staged and verified first, then committed in this
    order, each rename durable before the next:

        legacy state                      unseals: both blobs legacy
        1. host.key                       unseals: both blobs legacy
        2. pin.enc   (v2)                 unseals: v2 PIN, legacy master
        3. master.enc (v2), the sentinel  unseals: fully v2

    Every intermediate state unseals because the format is chosen per blob, and
    the next unseal resumes the migration. That resume MUST reuse the host.key
    already on disk (`host_key`): a v2 pin.enc may depend on it, so rotating here
    could strand the PIN. pin.hash is untouched, since the PIN does not change.

    New files copy master.enc's owner and mode so migrating can never change who
    can read the seal: this runs as whichever of the wall (soc) or the VPN
    supervisor (root) gets there first."""
    if not locked:
        _log.info("not migrating legacy seal in %s: another process holds the "
                  "seal lock", sd)
        return None
    if sd in _migration_skip:
        return None
    staged: list = []
    try:
        # Before any KDF: on a read-only box this runs on every unseal.
        if not os.access(sd, os.W_OK | os.X_OK):
            raise PermissionError("directory is not writable by this process")
        like = os.stat(os.path.join(sd, "master.enc"))
        owner, mode = (like.st_uid, like.st_gid), stat.S_IMODE(like.st_mode)
        fresh_key = host_key is None
        key = os.urandom(_HOST_KEY_LEN) if fresh_key else host_key
        binding = _binding_material(key)
        master_material = binding + b"\x00" + pin
        pin_blob = _encrypt(binding, pin)
        master_blob = _encrypt(master_material, master)
        files = {"pin.enc": pin_blob, "master.enc": master_blob}
        if fresh_key:
            files = {_HOST_KEY_FILE: key, **files}
        for name, data in files.items():
            staged.append(name)
            _write_atomic(os.path.join(sd, name), data, owner=owner, mode=mode)
        # The legacy blobs are about to be gone for good: prove what actually
        # landed on the card opens before giving them up.
        staged_path = os.path.join(sd, "%s.tmp")
        if (_decrypt(binding, _read(staged_path % "pin.enc")) != pin
                or _decrypt(master_material, _read(staged_path % "master.enc")) != master
                or (fresh_key and _read(staged_path % _HOST_KEY_FILE) != key)):
            raise SecretStoreError("staged seal did not round-trip")
        _commit(sd, tuple(files))
    except Exception as e:  # noqa: BLE001 — incl. MemoryError; see the docstring
        _discard_tmp(sd, staged)
        _migration_skip.add(sd)
        _log.warning("could not migrate the legacy seal in %s (%s) — still using "
                     "it; will retry on the next start", sd, e)
        return None
    _discard_tmp(sd, _SEAL_FILES)     # leftovers from any earlier interrupted run
    _log.info("migrated the legacy seal in %s to the host.key format", sd)
    return key, pin_blob, master_blob


def _unseal_files(sd: str, locked: bool) -> str:
    """The expensive path: decrypt the sealed files, migrating if they are legacy."""
    # Blobs BEFORE host.key. Writers commit host.key first, so any v2 blob seen
    # here guarantees its key is visible below, even with no lock against a
    # concurrent migration.
    pin_blob = _read(os.path.join(sd, "pin.enc"))
    master_blob = _read(os.path.join(sd, "master.enc"))
    host_key, key_err = None, None
    try:
        host_key = _read_host_key(sd)
    except SecretStoreError as e:
        key_err = e
    mid = _machine_id()
    binding = _binding_material(host_key) if host_key else None
    pin, pin_legacy = _open_blob(pin_blob, binding, mid, key_err)
    master, master_legacy = _open_blob(
        master_blob, binding + b"\x00" + pin if binding else None,
        mid + pin, key_err)
    if pin_legacy or master_legacy:
        migrated = _migrate_legacy(sd, pin, master, host_key, locked)
        if migrated:
            _ticket_save(*migrated, master)
    else:
        _ticket_save(host_key, pin_blob, master_blob, master)
    return master.decode()


def unseal(d: str | None = None) -> str:
    """Recover the master password (host.key + machine-id, no PIN prompt —
    unattended). Raises SecretStoreError if not sealed / wrong host / missing
    host.key / corrupt. A legacy seal is read and migrated on the way through.

    Backend selection: when SOC_SECRET_BACKEND=libsecret is set, try the
    user-keyring path first (KWallet / GNOME-Keyring via the freedesktop
    Secret-Service spec). If it has an entry, return it; otherwise log a
    warning and fall through to the sealed-file path. Either way the
    sealed files remain the on-disk source of truth so re-seal works."""
    if os.environ.get("SOC_SECRET_BACKEND") == "libsecret":
        try:
            v = libsecret_load()
        except Exception as e:                         # noqa: BLE001
            _log.warning("libsecret unseal failed: %s — falling back to sealed "
                         "file", e)
            v = None
        if v:
            return v
        _log.warning("SOC_SECRET_BACKEND=libsecret but no entry found — falling "
                     "back to sealed file")
    sd = secret_dir(d)
    cached = _ticket_load(sd)
    if cached is not None:
        return cached
    with _seal_lock(sd, _LOCK_WAIT) as locked:
        cached = _ticket_load(sd)       # a peer may have finished while we waited
        if cached is not None:
            return cached
        return _unseal_files(sd, locked)


# --- session ticket: makes repeat unseals cheap, across processes -------------
# Security: the ticket key is derived from host.key + machine-id, the same inputs
# as the seal, so reading a ticket proves nothing beyond what reading the seal
# already gives. Skipping the slow KDF gives nothing away either: host.key is 256
# random bits, and anyone holding it can run the KDF themselves. It is bound to the
# boot, the exact sealed bytes and an authenticated expiry, so a re-seal, a reboot,
# a removed host.key or a different machine-id all turn it into a harmless miss,
# and every failure here falls back to the sealed files. Never raises.

def _ticket_ttl() -> int:
    try:
        return max(0, int(os.environ.get("SOC_UNSEAL_CACHE_TTL", _TICKET_TTL)))
    except ValueError:
        return _TICKET_TTL


def _is_ram_backed(path: str) -> bool:
    """True if `path` lives on tmpfs/ramfs, per the mount table. The ticket is only
    ever written there; there is deliberately no fallback to a disk directory."""
    best, fstype = "", ""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            for line in fh:
                before, _, after = line.partition(" - ")
                mount = before.split(" ")[4].replace("\\040", " ")
                if ((path == mount or path.startswith(mount.rstrip("/") + "/"))
                        and len(mount) >= len(best)):
                    best, fstype = mount, after.split(" ")[0]
    except (OSError, IndexError):
        return False
    return fstype in _RAM_FILESYSTEMS


def _runtime_dir():
    """A private, RAM-backed directory for this uid, or None for no ticket at all.
    Root services get no XDG_RUNTIME_DIR, so root gets /run/soc-display."""
    uid = os.geteuid()
    candidates = [os.environ.get("XDG_RUNTIME_DIR"), f"/run/user/{uid}"]
    if uid == 0:
        with contextlib.suppress(OSError):
            os.mkdir("/run/soc-display", 0o700)
        candidates.append("/run/soc-display")
    for path in candidates:
        if not path:
            continue
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if (stat.S_ISDIR(st.st_mode) and st.st_uid == uid
                and not st.st_mode & 0o077 and _is_ram_backed(path)):
            return path
    return None


def _ticket_path():
    if _ticket_ttl() <= 0:
        return None
    rd = _runtime_dir()
    return os.path.join(rd, _TICKET_FILE) if rd else None


def _boot_id() -> bytes:
    with open("/proc/sys/kernel/random/boot_id", "rb") as fh:
        return fh.read().strip()


def _ticket_key(host_key: bytes, pin_blob: bytes, master_blob: bytes) -> bytes:
    bound = hashlib.sha256()
    for part in (_machine_id(), _boot_id(), pin_blob, master_blob):
        bound.update(struct.pack(">Q", len(part)) + part)
    return hmac.new(host_key, _TICKET_CONTEXT + bound.digest(),
                    hashlib.sha256).digest()


def _ticket_load(sd: str):
    """The master from this boot's ticket, or None on any kind of miss."""
    path = _ticket_path()
    if path is None:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_TICKET_MAX_BYTES)
        expires = struct.unpack(">Q", raw[:8])[0]
        now = time.time()
        if not now < expires <= now + _ticket_ttl():
            return None
        key = _ticket_key(_read_host_key(sd), _read(os.path.join(sd, "pin.enc")),
                          _read(os.path.join(sd, "master.enc")))
        return _aesgcm()(key).decrypt(raw[8:20], raw[20:], raw[:8]).decode()
    except Exception:  # noqa: BLE001 — absent, stale, tampered: all just a miss
        return None


def _ticket_save(host_key: bytes, pin_blob: bytes, master_blob: bytes,
                 master: bytes) -> None:
    path = _ticket_path()
    if path is None:
        return
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        expires = struct.pack(">Q", int(time.time()) + _ticket_ttl())
        nonce = os.urandom(12)
        ct = _aesgcm()(_ticket_key(host_key, pin_blob, master_blob)).encrypt(
            nonce, master, expires)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                     0o600)
        try:
            os.write(fd, expires + nonce + ct)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except Exception as e:  # noqa: BLE001 — a cache must never fail an unseal
        _log.debug("unseal ticket not saved: %s", e)
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def _ticket_discard() -> None:
    path = _ticket_path()
    if path is not None:
        with contextlib.suppress(OSError):
            os.unlink(path)


# --- libsecret backend (opt-in via SOC_SECRET_BACKEND=libsecret) --------------
# Stores the master password in the user's login keyring. KWallet,
# GNOME-Keyring, and KeePassXC's secret-service integration all speak the
# freedesktop Secret-Service spec via libsecret. The keyring is unlocked
# when the user logs in, so the wall starts under the user's session without
# prompting. Populate it with `python3 -m host.secretstore --libsecret-store`.
#
# Trade-off vs the sealed-file backend:
#   * sealed file = host-bound, root-readable, survives without a user
#     session (good for tty1 kiosk; bad for sharing across walls);
#   * libsecret = user-bound, only accessible while the user's keyring is
#     unlocked (good for desk deploys; the wall must run as that user).
# Operators choose at setup time; we never auto-promote.

_LIBSECRET_SCHEMA_NAME = "com.soc-wall.master"


def _try_libsecret():
    try:
        import gi as _gi
        _gi.require_version("Secret", "1")
        from gi.repository import Secret as _Secret      # noqa: N812
        return _Secret
    except (ValueError, ImportError):
        return None


def libsecret_available() -> bool:
    """True if the gi Secret-Service typelib is importable. Cheap probe —
    only loads the binding once, doesn't hit DBus."""
    return _try_libsecret() is not None


def _libsecret_schema(Secret):
    return Secret.Schema.new(
        _LIBSECRET_SCHEMA_NAME, Secret.SchemaFlags.NONE,
        {"role": Secret.SchemaAttributeType.STRING})


def libsecret_store(master: str) -> None:
    """Store the master password under role=master in the default
    collection. Raises RuntimeError if libsecret is not installed."""
    Secret = _try_libsecret()
    if not Secret:
        raise RuntimeError("libsecret not available — install gir1.2-secret-1")
    schema = _libsecret_schema(Secret)
    Secret.password_store_sync(
        schema, {"role": "master"},
        Secret.COLLECTION_DEFAULT,
        "SOC Wall vault master",
        master, None)


def libsecret_load() -> str | None:
    """Read the stored master, or None if not stored / agent unreachable."""
    Secret = _try_libsecret()
    if not Secret:
        return None
    schema = _libsecret_schema(Secret)
    try:
        return Secret.password_lookup_sync(schema, {"role": "master"}, None)
    except Exception:                                  # noqa: BLE001
        return None


def libsecret_clear() -> bool:
    """Remove the stored master. Returns True on success, False if the
    backend is absent. Safe to call when nothing is stored."""
    Secret = _try_libsecret()
    if not Secret:
        return False
    schema = _libsecret_schema(Secret)
    try:
        Secret.password_clear_sync(schema, {"role": "master"}, None)
        return True
    except Exception:                                  # noqa: BLE001
        return False


def verify_pin(pin: str, d: str | None = None) -> bool:
    """True if `pin` matches the sealed PIN (constant-time, via pin.hash)."""
    try:
        raw = _read(os.path.join(secret_dir(d), "pin.hash")).decode()
        salt_hex, want = raw.split("$", 1)
        got = hashlib.sha256(bytes.fromhex(salt_hex) + pin.encode()).hexdigest()
    except (SecretStoreError, ValueError):
        return False
    return hmac.compare_digest(got.encode(), want.encode())


def gen_pin(digits: int = 8) -> str:
    """A fresh, uniformly-random numeric PIN (no modulo bias), never shorter than
    the NIST SP 800-63B floor (_MIN_PIN_LEN)."""
    import secrets
    return "".join(secrets.choice("0123456789")
                   for _ in range(max(_MIN_PIN_LEN, digits)))


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


def _libsecret_store_from_stdin() -> int:
    """`--libsecret-store`: the master arrives over STDIN, NEVER argv."""
    import sys
    master = sys.stdin.read()
    if master.endswith("\n"):
        master = master[:-1]
    if not master:
        sys.stderr.write("secretstore --libsecret-store: empty master — "
                         "nothing stored\n")
        return 2
    try:
        libsecret_store(master)
    except Exception as e:                             # noqa: BLE001
        sys.stderr.write(f"secretstore --libsecret-store: {e}\n")
        return 1
    return 0


def _main(argv: "list[str]") -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="host.secretstore",
        description="Seal the vault master host-bound (pkexec helper for the wizard).")
    ap.add_argument("--seal", action="store_true",
                    help="read ---MASTER---/---PIN--- from STDIN and seal into --dir")
    ap.add_argument("--dir", help="secret dir to seal into (default $SOC_SECRET_DIR)")
    ap.add_argument("--libsecret-store", action="store_true",
                    help="read the master from STDIN into the user's keyring "
                         "(for SOC_SECRET_BACKEND=libsecret)")
    ap.add_argument("--libsecret-clear", action="store_true",
                    help="remove the master from the user's keyring")
    args = ap.parse_args(argv)
    if args.seal:
        return _seal_from_stdin(secret_dir(args.dir))
    if args.libsecret_store:
        return _libsecret_store_from_stdin()
    if args.libsecret_clear:
        return 0 if libsecret_clear() else 1
    ap.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
