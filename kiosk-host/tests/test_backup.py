"""OPS-1: portable, passphrase-encrypted Vaultwarden backup (host/backup.py)."""
import io
import os
import tarfile

import pytest

from host import backup


def _make_vault(tmp_path):
    d = tmp_path / "vaultwarden"
    d.mkdir()
    (d / "db.sqlite3").write_bytes(b"SQLite format 3\x00secret-vault-bytes")
    (d / "rsa_key.pem").write_text("-----BEGIN KEY-----\nxxxx\n")
    sub = d / "attachments"
    sub.mkdir()
    (sub / "a.bin").write_bytes(b"\x01\x02\x03")
    return str(d)


def test_roundtrip_restore(tmp_path):
    src = _make_vault(tmp_path)
    out = str(tmp_path / "vault.bak")
    backup.write_backup(src, out, "correct horse battery")
    dest = str(tmp_path / "restored")
    backup.restore_backup(out, dest, "correct horse battery")
    r = os.path.join(dest, "vaultwarden")
    assert open(os.path.join(r, "db.sqlite3"), "rb").read() == \
        b"SQLite format 3\x00secret-vault-bytes"
    assert os.path.exists(os.path.join(r, "attachments", "a.bin"))


def test_restore_oversized_blob_rejected(tmp_path, monkeypatch):
    # A backup file larger than the on-disk cap must be refused BEFORE it is
    # slurped into memory (so a corrupt/giant file can't OOM the 1GB Pi).
    src = _make_vault(tmp_path)
    out = str(tmp_path / "vault.bak")
    backup.write_backup(src, out, "correct horse battery")
    monkeypatch.setattr(backup, "_MAX_BLOB", 1)
    with pytest.raises(backup.BackupError) as e:
        backup.restore_backup(out, str(tmp_path / "restored"), "correct horse battery")
    assert "too large" in str(e.value)


def test_restore_oversized_inner_rejected(tmp_path, monkeypatch):
    # The decompressed (gzip-tar) cap is enforced after decrypt, before extract.
    src = _make_vault(tmp_path)
    out = str(tmp_path / "vault.bak")
    backup.write_backup(src, out, "correct horse battery")
    monkeypatch.setattr(backup, "_MAX_INNER", 1)
    with pytest.raises(backup.BackupError) as e:
        backup.restore_backup(out, str(tmp_path / "restored"), "correct horse battery")
    assert "too large" in str(e.value)


def test_restore_rolls_back_on_extract_failure(tmp_path, monkeypatch):
    # A mid-extraction failure must leave the pre-existing dest_dir intact (the
    # atomic stage-then-swap never touches dest_dir until extraction succeeds),
    # and must not leave a staging/backout dir behind.
    src = _make_vault(tmp_path)
    out = str(tmp_path / "vault.bak")
    backup.write_backup(src, out, "correct horse battery")
    dest = tmp_path / "restored"
    dest.mkdir()
    (dest / "PRE_EXISTING").write_text("keep me")

    def boom(_tar, _dest):
        raise backup.BackupError("simulated extract I/O error")
    monkeypatch.setattr(backup, "_safe_extract", boom)
    with pytest.raises(backup.BackupError):
        backup.restore_backup(out, str(dest), "correct horse battery")
    # rolled back: original content survives, no temp dirs left
    assert (dest / "PRE_EXISTING").read_text() == "keep me"
    sibs = [p.name for p in tmp_path.iterdir()]
    assert not any(".restore." in n or ".bak." in n for n in sibs), sibs


def test_backup_file_is_0600_and_not_plaintext(tmp_path):
    src = _make_vault(tmp_path)
    out = str(tmp_path / "vault.bak")
    backup.write_backup(src, out, "correct horse battery")
    assert (os.stat(out).st_mode & 0o777) == 0o600
    assert b"secret-vault-bytes" not in open(out, "rb").read()   # encrypted


def test_wrong_passphrase_fails(tmp_path):
    src = _make_vault(tmp_path)
    blob = backup.make_backup(src, "right-passphrase")
    with pytest.raises(backup.BackupError):
        backup.open_backup(blob, "wrong-passphrase")


def test_tamper_is_detected(tmp_path):
    src = _make_vault(tmp_path)
    blob = bytearray(backup.make_backup(src, "right-passphrase"))
    blob[-1] ^= 0xFF                                   # flip a ciphertext byte
    with pytest.raises(backup.BackupError):
        backup.open_backup(bytes(blob), "right-passphrase")


def test_short_passphrase_rejected(tmp_path):
    src = _make_vault(tmp_path)
    with pytest.raises(backup.BackupError):
        backup.make_backup(src, "short")              # < 8 chars


def test_bad_magic_rejected(tmp_path):
    with pytest.raises(backup.BackupError):
        backup.open_backup(b"NOTPS" + b"\x00" * 40, "whatever-passphrase")


def test_safe_extract_blocks_path_traversal(tmp_path):
    # craft a malicious tar with a ../ member and ensure extraction refuses it
    mal = io.BytesIO()
    with tarfile.open(fileobj=mal, mode="w:gz") as tar:
        data = b"pwned"
        info = tarfile.TarInfo(name="../escape.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    mal.seek(0)
    dest = str(tmp_path / "out")
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=mal, mode="r:gz") as tar:
        with pytest.raises(backup.BackupError):
            backup._safe_extract(tar, dest)
    assert not os.path.exists(os.path.join(str(tmp_path), "escape.txt"))


def test_safe_extract_refuses_symlinks(tmp_path):
    mal = io.BytesIO()
    with tarfile.open(fileobj=mal, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    mal.seek(0)
    with tarfile.open(fileobj=mal, mode="r:gz") as tar:
        with pytest.raises(backup.BackupError):
            backup._safe_extract(tar, str(tmp_path))
