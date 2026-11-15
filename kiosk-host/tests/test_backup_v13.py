"""Regression tests recovered from v1.3.0 (test_backup.py): cases for this line's own
features that were lost when the suite was replaced. Kept separate so they stay
visibly additive to test_backup.py."""
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
