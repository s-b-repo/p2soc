"""In-field seal compatibility: a box sealed by an earlier release boots unattended
and must never be locked out by an upgrade.

Legacy format: raw salt|nonce|ct, scrypt N=2**14, keyed by the machine-id alone, no
host.key. The fixtures below write it by hand, deliberately NOT through any
secretstore constant, so these tests pin the format actually on those boxes.
"""
import glob
import hashlib
import io
import logging
import os
import stat
import subprocess
import sys
import tarfile
import threading

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from host import backup, mastersource
from host import secretstore as ss

KIOSK_HOST = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MID = "host-A"
MASTER = "Legacy-Master!"
PIN = "12345678"


def legacy_blob(material, plaintext, salt=None):
    salt = salt or os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.scrypt(material, salt=salt, n=2 ** 14, r=8, p=1, dklen=32,
                         maxmem=96 * 1024 * 1024)
    return salt + nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def write_legacy_seal(d, master=MASTER, pin=PIN, mid=MID, salts=(None, None)):
    os.makedirs(d, exist_ok=True)
    hash_salt = os.urandom(16)
    digest = hashlib.sha256(hash_salt + pin.encode()).hexdigest()
    files = {
        "pin.hash": f"{hash_salt.hex()}${digest}".encode(),
        "pin.enc": legacy_blob(mid.encode(), pin.encode(), salts[0]),
        "master.enc": legacy_blob((mid + pin).encode(), master.encode(), salts[1]),
    }
    for name, data in files.items():
        fd = os.open(os.path.join(d, name), os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, data)
        os.close(fd)


def read(d, name):
    with open(os.path.join(d, name), "rb") as fh:
        return fh.read()


def snapshot(d):
    return {os.path.basename(p): read(d, os.path.basename(p))
            for p in glob.glob(os.path.join(d, "*"))}


def assert_fully_migrated(d):
    assert sorted(os.path.basename(f) for f in glob.glob(os.path.join(d, "*"))) \
        == ["host.key", "master.enc", "pin.enc", "pin.hash"]
    assert len(read(d, "host.key")) == 32
    assert ss._is_v2_blob(read(d, "pin.enc"))
    assert ss._is_v2_blob(read(d, "master.enc"))


class PowerCut(BaseException):
    """Not an Exception, so no handler can tidy up: as abrupt as losing power."""


def cut_power_after(mp, commits):
    real = os.replace
    done = []

    def replace(src, dst):
        if len(done) == commits:
            raise PowerCut
        done.append(dst)
        return real(src, dst)
    mp.setattr(ss.os, "replace", replace)


def run_python(code, env=None):
    full_env = {**os.environ, "PYTHONPATH": KIOSK_HOST, **(env or {})}
    return subprocess.Popen([sys.executable, "-c", code], env=full_env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    monkeypatch.setenv("SOC_MACHINE_ID", MID)
    monkeypatch.delenv("SOC_FIPS_KDF", raising=False)
    monkeypatch.delenv("SOC_SECRET_BACKEND", raising=False)
    monkeypatch.setenv("SOC_UNSEAL_CACHE_TTL", "0")   # exercise the sealed files
    ss._migration_skip.clear()
    yield
    ss._migration_skip.clear()


@pytest.fixture
def sd(tmp_path):
    d = str(tmp_path / "secret")
    write_legacy_seal(d)
    return d


# --- reading ---------------------------------------------------------------- #

def test_legacy_seal_is_sealed_without_a_host_key(sd):
    assert not os.path.exists(os.path.join(sd, "host.key"))
    assert ss.is_sealed(sd)


def test_incomplete_legacy_seal_is_not_sealed(sd):
    os.remove(os.path.join(sd, "pin.enc"))
    assert not ss.is_sealed(sd)


def test_legacy_seal_unseals(sd):
    assert ss.unseal(sd) == MASTER


def test_legacy_seal_unseals_through_mastersource(sd, monkeypatch):
    monkeypatch.setenv("SOC_SECRET_DIR", sd)
    monkeypatch.delenv("SOC_MASTER_SOURCE", raising=False)
    assert mastersource.get_master() == MASTER


def test_legacy_seal_on_the_wrong_machine_fails_and_changes_nothing(sd, monkeypatch):
    before = snapshot(sd)
    monkeypatch.setenv("SOC_MACHINE_ID", "host-B")
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(sd)
    assert snapshot(sd) == before


def test_legacy_salt_that_looks_like_a_v2_header_still_unseals(tmp_path):
    # A legacy blob opens with a random salt; about 1 in 8 million open with the
    # v2 magic + a valid ALGO byte. That box must not be locked out.
    d = str(tmp_path / "secret")
    salt = ss._MAGIC + bytes([ss._ALGO_SCRYPT]) + b"\x07" * 13
    write_legacy_seal(d, salts=(salt, salt))
    assert ss.unseal(d) == MASTER
    assert_fully_migrated(d)


# --- migrating -------------------------------------------------------------- #

def test_unseal_migrates_with_the_same_pin_and_no_prompt(sd):
    pin_hash = read(sd, "pin.hash")
    assert ss.unseal(sd) == MASTER
    assert_fully_migrated(sd)
    for name in ("host.key", "pin.enc", "master.enc", "pin.hash"):
        assert stat.S_IMODE(os.stat(os.path.join(sd, name)).st_mode) == 0o600
    assert read(sd, "pin.hash") == pin_hash
    assert ss.verify_pin(PIN, sd)
    assert ss.is_sealed(sd)
    assert ss.unseal(sd) == MASTER          # and reads back as a plain v2 seal


def test_migration_closes_the_machine_id_only_hole(sd):
    ss.unseal(sd)
    os.remove(os.path.join(sd, "host.key"))     # blobs + public machine-id alone
    assert not ss.is_sealed(sd)
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(sd)


def test_migrated_blobs_use_the_hardened_kdf_by_default(sd):
    ss.unseal(sd)
    assert read(sd, "master.enc")[len(ss._MAGIC)] == ss._ALGO_SCRYPT


def test_fips_box_migrates_to_pbkdf2(sd, monkeypatch):
    monkeypatch.setenv("SOC_FIPS_KDF", "1")
    assert ss.unseal(sd) == MASTER
    assert read(sd, "pin.enc")[len(ss._MAGIC)] == ss._ALGO_PBKDF2
    assert read(sd, "master.enc")[len(ss._MAGIC)] == ss._ALGO_PBKDF2
    assert ss.unseal(sd) == MASTER


def test_pin_below_the_new_floor_still_migrates(tmp_path):
    # Earlier releases generated and accepted 4-digit PINs; seal() now refuses
    # those. A box already using one must migrate anyway, keeping its PIN.
    d = str(tmp_path / "secret")
    write_legacy_seal(d, pin="1234")
    assert ss.unseal(d) == MASTER
    assert_fully_migrated(d)
    assert ss.verify_pin("1234", d)
    assert ss.unseal(d) == MASTER


def test_migration_keeps_the_owner_and_mode_of_the_seal(sd, monkeypatch):
    # Whichever of the wall (soc) or the VPN supervisor (root) migrates, the seal's
    # readers must not change, or root migrating would lock the wall out.
    os.chmod(os.path.join(sd, "master.enc"), 0o640)
    want = os.stat(os.path.join(sd, "master.enc"))
    seen = []
    real = os.fchown
    monkeypatch.setattr(ss.os, "fchown",
                        lambda fd, u, g: (seen.append((u, g)), real(fd, u, g))[1])
    ss.unseal(sd)
    assert seen == [(want.st_uid, want.st_gid)] * 3
    for name in ("host.key", "pin.enc", "master.enc"):
        assert stat.S_IMODE(os.stat(os.path.join(sd, name)).st_mode) == 0o640


def test_stale_tmp_files_are_ignored_and_swept(sd):
    for name in ("host.key.tmp", "pin.enc.tmp", "pin.hash.tmp", "master.enc.tmp"):
        with open(os.path.join(sd, name), "wb") as fh:
            fh.write(b"junk from an earlier power cut")
    assert ss.unseal(sd) == MASTER
    assert_fully_migrated(sd)


def test_seal_over_a_legacy_seal_replaces_it(sd):
    ss.seal("new-master", "87654321", sd)
    assert_fully_migrated(sd)
    assert ss.unseal(sd) == "new-master"
    assert ss.verify_pin("87654321", sd)


def test_seal_as_root_gives_the_files_to_the_dir_owner(tmp_path, monkeypatch):
    # `sudo setup.py first-run` and the pkexec --seal helper run as root, but the
    # secret dir belongs to the kiosk user: root-owned 0600 files there would be
    # unreadable by the wall.
    d = str(tmp_path / "secret")
    os.makedirs(d)
    want = os.stat(d)
    seen = []
    monkeypatch.setattr(ss.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ss.os, "fchown",
                        lambda fd, u, g: seen.append((u, g)))
    ss.seal(MASTER, PIN, d)
    assert seen == [(want.st_uid, want.st_gid)] * 4


# --- a crash mid-migration must leave a state that still unseals ------------- #

@pytest.mark.parametrize("commits, v2_blobs", [(0, 0), (1, 0), (2, 1)],
                         ids=["before-any-commit", "after-host.key", "after-pin.enc"])
def test_power_cut_mid_migration_still_unseals(sd, monkeypatch, commits, v2_blobs):
    with monkeypatch.context() as mp:
        cut_power_after(mp, commits)
        with pytest.raises(PowerCut):
            ss.unseal(sd)
    assert ss._is_v2_blob(read(sd, "pin.enc")) == bool(v2_blobs)
    assert not ss._is_v2_blob(read(sd, "master.enc"))    # the sentinel goes last
    assert ss.is_sealed(sd)
    assert ss.verify_pin(PIN, sd)
    assert ss.unseal(sd) == MASTER          # still boots, and resumes
    assert_fully_migrated(sd)
    assert ss.unseal(sd) == MASTER


def test_resume_reuses_the_host_key_a_v2_blob_may_depend_on(sd, monkeypatch):
    with monkeypatch.context() as mp:
        cut_power_after(mp, 2)              # host.key + v2 pin.enc are committed
        with pytest.raises(PowerCut):
            ss.unseal(sd)
    key = read(sd, "host.key")
    assert ss.unseal(sd) == MASTER
    assert read(sd, "host.key") == key


def test_repeated_power_cuts_never_lock_the_box_out(sd, monkeypatch):
    for commits in (2, 1, 0, 1):
        with monkeypatch.context() as mp:
            cut_power_after(mp, commits)
            with pytest.raises(PowerCut):
                ss.unseal(sd)
        assert ss.is_sealed(sd)
    assert ss.unseal(sd) == MASTER
    assert_fully_migrated(sd)


@pytest.mark.parametrize("commits", [0, 1, 2])
def test_process_killed_mid_migration_still_unseals(sd, commits):
    # The real thing: the process dies mid-commit, stranding its *.tmp files, and
    # the next boot is a new process.
    code = f"""
import os
from host import secretstore as ss
real, n = os.replace, [0]
def replace(a, b):
    if n[0] == {commits}:
        os._exit(9)
    n[0] += 1
    real(a, b)
ss.os.replace = replace
ss.unseal({sd!r})
"""
    assert run_python(code).wait(timeout=60) == 9
    assert glob.glob(os.path.join(sd, "*.tmp"))     # really died part-way
    assert ss.is_sealed(sd)
    assert ss.unseal(sd) == MASTER
    assert_fully_migrated(sd)


# --- concurrent boots: the wall and the VPN supervisor race for the seal ------ #

def test_concurrent_processes_migrate_exactly_one_consistent_seal(sd):
    code = f"from host import secretstore as ss; print(ss.unseal({sd!r}))"
    procs = [run_python(code) for _ in range(4)]
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert (p.returncode, out.strip()) == (0, MASTER), err
    assert_fully_migrated(sd)
    assert ss.unseal(sd) == MASTER


def test_concurrent_threads_migrate_exactly_one_consistent_seal(sd):
    got = []
    threads = [threading.Thread(target=lambda: got.append(ss.unseal(sd)))
               for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert got == [MASTER] * 4
    assert_fully_migrated(sd)
    assert ss.unseal(sd) == MASTER


def test_blocked_by_a_peer_still_unseals_and_defers_migration(sd, monkeypatch):
    monkeypatch.setattr(ss, "_LOCK_WAIT", 0.05)
    with ss._seal_lock(sd, 0) as held:
        assert held
        assert ss.unseal(sd) == MASTER
        assert not os.path.exists(os.path.join(sd, "host.key"))
    assert ss.unseal(sd) == MASTER          # the peer went away: migrate now
    assert_fully_migrated(sd)


def test_seal_lock_is_released_when_its_holder_dies(sd):
    code = f"""
import os
from host import secretstore as ss
with ss._seal_lock({sd!r}, 0) as held:
    os._exit(7 if held else 1)
"""
    assert run_python(code).wait(timeout=30) == 7
    with ss._seal_lock(sd, 0) as held:
        assert held


# --- an unwritable dir still unseals, with only a warning -------------------- #

def spy_on_encrypt(monkeypatch):
    calls = []
    real = ss._encrypt
    monkeypatch.setattr(ss, "_encrypt",
                        lambda *a: (calls.append(1), real(*a))[1])
    return calls


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
def test_unwritable_dir_returns_the_master_and_warns(sd, monkeypatch, caplog):
    before = snapshot(sd)
    encrypts = spy_on_encrypt(monkeypatch)
    os.chmod(sd, 0o500)
    try:
        with caplog.at_level(logging.WARNING, logger="host.secretstore"):
            assert ss.unseal(sd) == MASTER
        assert snapshot(sd) == before
    finally:
        os.chmod(sd, 0o700)
    assert "legacy seal" in caplog.text
    # a read-only box re-enters this on every unseal: it must not pay 128 MiB KDFs
    assert encrypts == []


def test_read_only_filesystem_returns_the_master_and_warns(sd, monkeypatch, caplog):
    before = snapshot(sd)

    def read_only(*_a, **_k):
        raise OSError(30, "Read-only file system")
    monkeypatch.setattr(ss, "_write_atomic", read_only)
    with caplog.at_level(logging.WARNING, logger="host.secretstore"):
        assert ss.unseal(sd) == MASTER
    assert snapshot(sd) == before
    assert "legacy seal" in caplog.text


def test_commit_failure_returns_the_master_and_stays_unsealable(sd, monkeypatch):
    with monkeypatch.context() as mp:
        def enospc(*_a):
            raise OSError(28, "No space left on device")
        mp.setattr(ss.os, "replace", enospc)
        assert ss.unseal(sd) == MASTER
    assert glob.glob(os.path.join(sd, "*.tmp")) == []
    ss._migration_skip.clear()              # as a restart would
    assert ss.unseal(sd) == MASTER
    assert_fully_migrated(sd)


def test_wrong_owner_aborts_rather_than_changing_who_can_read(sd, monkeypatch):
    before = snapshot(sd)

    def eperm(*_a):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(ss.os, "fchown", eperm)
    assert ss.unseal(sd) == MASTER
    assert snapshot(sd) == before


def test_out_of_memory_during_migration_does_not_fail_the_boot(sd, monkeypatch):
    def oom(*_a):
        raise MemoryError
    monkeypatch.setattr(ss, "_encrypt", oom)
    assert ss.unseal(sd) == MASTER


@pytest.mark.parametrize("victim", ["host.key", "pin.enc", "master.enc"])
def test_staged_file_torn_on_the_card_is_never_committed(sd, monkeypatch, victim):
    # The legacy blobs are the only copy until the commit: a bad write has to be
    # caught while they still exist.
    before = snapshot(sd)
    real = ss._write_atomic

    def corrupting(path, data, **kw):
        if path.endswith(victim):
            data = data[:-1] + bytes([data[-1] ^ 0xFF])
        return real(path, data, **kw)
    monkeypatch.setattr(ss, "_write_atomic", corrupting)
    assert ss.unseal(sd) == MASTER
    assert snapshot(sd) == before


def test_a_failed_migration_is_not_retried_by_the_same_process(sd, monkeypatch):
    def read_only(*_a, **_k):
        raise OSError(30, "Read-only file system")
    monkeypatch.setattr(ss, "_write_atomic", read_only)
    encrypts = spy_on_encrypt(monkeypatch)
    ss.unseal(sd)
    paid = len(encrypts)
    assert ss.unseal(sd) == MASTER
    assert len(encrypts) == paid


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_seal_degrades_instead_of_raising_oserror(sd, monkeypatch):
    # e.g. sealed as root, unsealed as the kiosk user. The boot path promises it
    # never crashes, and only handles SecretStoreError.
    os.chmod(os.path.join(sd, "master.enc"), 0)
    try:
        with pytest.raises(ss.SecretStoreError):
            ss.unseal(sd)
        monkeypatch.setenv("SOC_SECRET_DIR", sd)
        assert mastersource.get_master("sealed") == ""
    finally:
        os.chmod(os.path.join(sd, "master.enc"), 0o600)


# --- the session ticket that keeps repeat unseals cheap ---------------------- #

def spy_on_kdf(monkeypatch):
    calls = []
    real = ss._kdf
    monkeypatch.setattr(ss, "_kdf",
                        lambda *a: (calls.append(a[2]), real(*a))[1])
    return calls


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    d = tmp_path / "run"
    d.mkdir(mode=0o700)
    monkeypatch.delenv("SOC_UNSEAL_CACHE_TTL")
    monkeypatch.setattr(ss, "_runtime_dir", lambda: str(d))
    return str(d)


def ticket(run_dir):
    return os.path.join(run_dir, ss._TICKET_FILE)


@pytest.fixture
def sealed_v2(tmp_path):
    d = str(tmp_path / "v2")
    ss.seal(MASTER, PIN, d)
    return d


def test_repeat_unseal_runs_no_kdf(sealed_v2, run_dir, monkeypatch):
    assert ss.unseal(sealed_v2) == MASTER
    kdf = spy_on_kdf(monkeypatch)
    for _ in range(5):
        assert ss.unseal(sealed_v2) == MASTER
    assert kdf == []


def test_ticket_is_private_and_holds_no_plaintext(sealed_v2, run_dir):
    ss.unseal(sealed_v2)
    assert stat.S_IMODE(os.stat(ticket(run_dir)).st_mode) == 0o600
    with open(ticket(run_dir), "rb") as fh:
        raw = fh.read()
    assert MASTER.encode() not in raw and PIN.encode() not in raw


def test_ticket_serves_a_separate_process(sealed_v2, tmp_path):
    # The hot path: each `litebw` subprocess is a brand-new interpreter.
    rd = tmp_path / "xdg"
    rd.mkdir(mode=0o700)
    if not ss._is_ram_backed(str(rd)):
        pytest.skip("this tmp dir is not on tmpfs")
    env = {"XDG_RUNTIME_DIR": str(rd), "SOC_UNSEAL_CACHE_TTL": "60"}
    first = run_python(f"from host import secretstore as ss; ss.unseal({sealed_v2!r})",
                       env)
    assert first.wait(timeout=60) == 0
    code = f"""
from host import secretstore as ss
def forbidden(*a):
    raise SystemExit("the KDF ran")
ss._kdf = forbidden
print(ss.unseal({sealed_v2!r}))
"""
    p = run_python(code, env)
    out, err = p.communicate(timeout=60)
    assert (p.returncode, out.strip()) == (0, MASTER), err


def test_migration_leaves_a_ticket_too(sd, run_dir, monkeypatch):
    assert ss.unseal(sd) == MASTER
    kdf = spy_on_kdf(monkeypatch)
    assert ss.unseal(sd) == MASTER
    assert kdf == []


def test_unmigrated_legacy_seal_writes_no_ticket(sd, run_dir, monkeypatch):
    monkeypatch.setattr(ss, "_LOCK_WAIT", 0.0)
    with ss._seal_lock(sd, 0):
        ss.unseal(sd)
    assert not os.path.exists(ticket(run_dir))


def test_reseal_invalidates_the_ticket(sealed_v2, run_dir):
    ss.unseal(sealed_v2)
    ss.seal("rotated-master", "87654321", sealed_v2)
    assert ss.unseal(sealed_v2) == "rotated-master"


def test_reseal_by_another_process_invalidates_the_ticket(sealed_v2, run_dir):
    # A separate process's re-seal cannot unlink this uid's ticket; the binding to
    # the sealed bytes has to do it.
    ss.unseal(sealed_v2)
    p = run_python("from host import secretstore as ss; "
                   f"ss.seal('rotated-master', '87654321', {sealed_v2!r})")
    assert p.wait(timeout=60) == 0
    assert ss.unseal(sealed_v2) == "rotated-master"


def test_ticket_does_not_outlive_host_key(sealed_v2, run_dir):
    ss.unseal(sealed_v2)
    os.remove(os.path.join(sealed_v2, "host.key"))
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(sealed_v2)


def test_ticket_does_not_survive_a_corrupted_seal(sealed_v2, run_dir):
    ss.unseal(sealed_v2)
    with open(os.path.join(sealed_v2, "master.enc"), "ab") as fh:
        fh.write(b"\x00")
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(sealed_v2)


def test_ticket_does_not_cross_machines(sealed_v2, run_dir, monkeypatch):
    ss.unseal(sealed_v2)
    monkeypatch.setenv("SOC_MACHINE_ID", "host-B")
    with pytest.raises(ss.SecretStoreError):
        ss.unseal(sealed_v2)


def test_ticket_does_not_survive_a_reboot(sealed_v2, run_dir, monkeypatch):
    ss.unseal(sealed_v2)
    monkeypatch.setattr(ss, "_boot_id", lambda: b"another-boot")
    kdf = spy_on_kdf(monkeypatch)
    assert ss.unseal(sealed_v2) == MASTER
    assert len(kdf) == 2


def test_expired_ticket_is_a_miss(sealed_v2, run_dir, monkeypatch):
    ss.unseal(sealed_v2)
    real = ss.time.time
    monkeypatch.setattr(ss.time, "time", lambda: real() + ss._TICKET_TTL + 1)
    kdf = spy_on_kdf(monkeypatch)
    assert ss.unseal(sealed_v2) == MASTER
    assert len(kdf) == 2


@pytest.mark.parametrize("garbage", [b"", b"short", b"\xff" * 64])
def test_damaged_ticket_falls_back_to_the_seal(sealed_v2, run_dir, garbage):
    ss.unseal(sealed_v2)
    with open(ticket(run_dir), "wb") as fh:
        fh.write(garbage)
    assert ss.unseal(sealed_v2) == MASTER


def test_tampered_expiry_is_rejected(sealed_v2, run_dir, monkeypatch):
    ss.unseal(sealed_v2)
    with open(ticket(run_dir), "r+b") as fh:
        fh.write(b"\x00" * 7 + b"\x01")     # authenticated: not just "expired"
    kdf = spy_on_kdf(monkeypatch)
    assert ss.unseal(sealed_v2) == MASTER
    assert len(kdf) == 2


def test_ttl_zero_disables_the_ticket(sealed_v2, run_dir, monkeypatch):
    monkeypatch.setenv("SOC_UNSEAL_CACHE_TTL", "0")
    assert ss.unseal(sealed_v2) == MASTER
    assert not os.path.exists(ticket(run_dir))


def test_an_unusable_runtime_dir_still_unseals(sealed_v2, run_dir):
    os.chmod(run_dir, 0o500)
    try:
        assert ss.unseal(sealed_v2) == MASTER
    finally:
        os.chmod(run_dir, 0o700)


def test_ticket_is_never_placed_on_a_disk_filesystem(tmp_path, monkeypatch):
    rd = tmp_path / "xdg"
    rd.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(rd))
    monkeypatch.setattr(ss, "_is_ram_backed", lambda _p: False)
    assert ss._runtime_dir() is None


def test_ticket_dir_must_be_private_and_a_real_directory(tmp_path, monkeypatch):
    if not ss._is_ram_backed(str(tmp_path)):
        pytest.skip("this tmp dir is not on tmpfs")
    monkeypatch.setattr(ss.os, "geteuid", ss.os.geteuid)    # the real uid
    monkeypatch.setattr(ss, "_is_ram_backed", lambda _p: True)
    rd = tmp_path / "xdg"
    rd.mkdir(mode=0o750)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(rd))
    uid_dir = f"/run/user/{os.geteuid()}"
    assert ss._runtime_dir() in (None, uid_dir)     # not the group-readable one
    rd.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to(rd)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(link))
    assert ss._runtime_dir() in (None, uid_dir)     # not through a symlink


def test_mount_table_tells_ram_from_disk():
    assert ss._is_ram_backed("/proc/self") is False


# --- backups have an in-field format too ------------------------------------- #

def legacy_backup(src, passphrase, salt=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(src, arcname="vaultwarden")
    salt = salt or os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=2 ** 14, r=8, p=1,
                         dklen=32, maxmem=96 * 1024 * 1024)
    return b"PSBK" + salt + nonce + AESGCM(key).encrypt(nonce, buf.getvalue(), None)


@pytest.mark.parametrize("salt", [None, bytes([1]) + b"\x07" * 15,
                                  bytes([2]) + b"\x07" * 15],
                         ids=["random", "salt-resembles-scrypt-algo",
                              "salt-resembles-pbkdf2-algo"])
def test_backup_from_an_earlier_release_still_restores(tmp_path, salt):
    src = tmp_path / "vaultwarden"
    src.mkdir()
    (src / "db.sqlite3").write_bytes(b"vault-bytes")
    bak = tmp_path / "old.bak"
    bak.write_bytes(legacy_backup(str(src), "correct horse battery", salt))
    dest = str(tmp_path / "restored")
    backup.restore_backup(str(bak), dest, "correct horse battery")
    with open(os.path.join(dest, "vaultwarden", "db.sqlite3"), "rb") as fh:
        assert fh.read() == b"vault-bytes"


def test_backup_from_an_earlier_release_still_rejects_a_wrong_passphrase(tmp_path):
    src = tmp_path / "vaultwarden"
    src.mkdir()
    blob = legacy_backup(str(src), "correct horse battery")
    with pytest.raises(backup.BackupError):
        backup.open_backup(blob, "wrong passphrase!")
