"""Deploy-time file-hash manifest + boot-time drift/tamper detection.

Exercises host/manifest.py: hash a fake deploy tree, mutate/drop/add files, and
assert the drift report flags `changed`/`missing`/`extras`. The `extras` path is
the covert-drop case (a sketchy `.py` appearing in /opt/soc-display). conftest.py
puts `kiosk-host/` on sys.path so `from host import manifest` resolves regardless
of the working directory.
"""
from __future__ import annotations

import json

import pytest

from host import manifest


def _seed_tree(tmp_path):
    """Build a fake deploy tree under tmp_path with a mix of tracked + skip
    files; returns the root."""
    (tmp_path / "kiosk-host").mkdir()
    (tmp_path / "kiosk-host" / "host").mkdir()
    (tmp_path / "kiosk-host" / "host" / "main.py").write_text("print('hi')\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "tarpit.py").write_text("# tarpit\n")
    (tmp_path / "README.md").write_text("# soc\n")
    # Skip-dir + skip-suffix decoys.
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("ignored\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "foo.pyc").write_text("ignored\n")
    (tmp_path / "wall.log").write_text("ignored\n")
    (tmp_path / "PROMPT.txt").write_text("operator scratchpad\n")
    return tmp_path


# --- build_manifest -------------------------------------------------------


def test_build_manifest_skips_excluded_dirs_and_suffixes(tmp_path):
    root = _seed_tree(tmp_path)
    m = manifest.build_manifest(str(root), commit_sha="deadbeef")
    files = m["files"]
    assert "kiosk-host/host/main.py" in files
    assert "scripts/tarpit.py" in files
    assert "README.md" in files
    # Excluded:
    assert ".git/config" not in files
    assert "__pycache__/foo.pyc" not in files
    assert "wall.log" not in files
    assert "PROMPT.txt" not in files


def test_build_manifest_records_metadata(tmp_path):
    root = _seed_tree(tmp_path)
    m = manifest.build_manifest(str(root), commit_sha="abc123")
    assert m["version"] == 1
    assert m["commit"] == "abc123"
    assert m["repo"] == "https://github.com/s-b-repo/p2soc"


def test_build_manifest_hashes_are_deterministic(tmp_path):
    root = _seed_tree(tmp_path)
    a = manifest.build_manifest(str(root), commit_sha="x")
    b = manifest.build_manifest(str(root), commit_sha="x")
    assert a == b


# --- write_manifest -------------------------------------------------------


def test_write_manifest_creates_parent_and_returns_path(tmp_path):
    root = _seed_tree(tmp_path)
    dest = tmp_path / "etc" / "manifest.json"
    rc = manifest.write_manifest(str(root), dest=str(dest))
    assert rc == str(dest)
    assert dest.exists()
    raw = json.loads(dest.read_text())
    assert raw["version"] == 1
    assert "kiosk-host/host/main.py" in raw["files"]


# --- check_drift ----------------------------------------------------------


def test_check_drift_clean_returns_empty_lists(tmp_path):
    root = _seed_tree(tmp_path)
    dest = tmp_path / "manifest.json"
    manifest.write_manifest(str(root), dest=str(dest))
    drift = manifest.check_drift(str(root), manifest_path=str(dest))
    assert drift["changed"] == []
    assert drift["missing"] == []
    assert drift["extras"] == []


def test_check_drift_detects_modified_file(tmp_path):
    root = _seed_tree(tmp_path)
    dest = tmp_path / "manifest.json"
    manifest.write_manifest(str(root), dest=str(dest))
    # Tamper with one shipped file.
    (root / "scripts" / "tarpit.py").write_text("# evil edit\n")
    drift = manifest.check_drift(str(root), manifest_path=str(dest))
    assert "scripts/tarpit.py" in drift["changed"]
    assert drift["missing"] == []


def test_check_drift_detects_missing_file(tmp_path):
    root = _seed_tree(tmp_path)
    dest = tmp_path / "manifest.json"
    manifest.write_manifest(str(root), dest=str(dest))
    (root / "README.md").unlink()
    drift = manifest.check_drift(str(root), manifest_path=str(dest))
    assert "README.md" in drift["missing"]
    assert drift["changed"] == []


def test_check_drift_detects_extras(tmp_path):
    """Covert-drop case: a sketchy .py appears in /opt/soc-display after deploy."""
    root = _seed_tree(tmp_path)
    dest = tmp_path / "manifest.json"
    manifest.write_manifest(str(root), dest=str(dest))
    (root / "kiosk-host" / "host" / "rogue.py").write_text("# new\n")
    drift = manifest.check_drift(str(root), manifest_path=str(dest))
    assert "kiosk-host/host/rogue.py" in drift["extras"]


def test_check_drift_raises_when_manifest_missing(tmp_path):
    root = _seed_tree(tmp_path)
    with pytest.raises(FileNotFoundError):
        manifest.check_drift(str(root),
                             manifest_path=str(tmp_path / "nope.json"))


# --- format_drift_summary ------------------------------------------------


def test_format_drift_summary_empty_returns_empty_string():
    assert manifest.format_drift_summary({
        "commit": "abc", "repo": "x",
        "changed": [], "missing": [], "extras": [],
    }) == ""


def test_format_drift_summary_mentions_counts_and_commit():
    msg = manifest.format_drift_summary({
        "commit": "abcdef0123456789",
        "repo": "x",
        "changed": ["a", "b"],
        "missing": ["c"],
        "extras": [],
    })
    assert "2 changed" in msg
    assert "1 missing" in msg
    assert "abcdef012345" in msg
    assert "⚠" in msg


def test_format_drift_summary_handles_unknown_commit():
    msg = manifest.format_drift_summary({
        "commit": "", "repo": "x",
        "changed": ["a"], "missing": [], "extras": [],
    })
    assert "unknown" in msg
