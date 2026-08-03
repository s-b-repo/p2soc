"""Exercise the .githooks/pre-commit secrets-scrub hook in a throwaway
git repo. The hook is written in POSIX sh; these tests subprocess it
with a controlled stage list and assert exit codes."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK = REPO_ROOT / ".githooks" / "pre-commit"


def _git(repo, *args, env=None, check=True, **kw):
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(["git", "-C", str(repo), *args],
                          env=full_env, check=check,
                          capture_output=True, text=True, **kw)


@pytest.fixture
def repo(tmp_path):
    """A fresh git repo with the hook installed at core.hooksPath."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "test@example.com")
    _git(r, "config", "user.name", "test")
    hooks = r / ".githooks"
    hooks.mkdir()
    shutil.copy(HOOK, hooks / "pre-commit")
    (hooks / "pre-commit").chmod(0o755)
    _git(r, "config", "core.hooksPath", ".githooks")
    return r


def _run_hook(repo):
    """Run the hook as `git commit` would. Returns (rc, stderr)."""
    res = subprocess.run([str(repo / ".githooks" / "pre-commit")],
                         cwd=str(repo), capture_output=True, text=True)
    return res.returncode, res.stderr


def test_hook_executable_and_present():
    assert HOOK.exists(), f"expected hook at {HOOK}"
    assert os.access(HOOK, os.X_OK), "hook must be executable"


def test_passes_clean_diff(repo):
    (repo / "README.md").write_text("Just docs.\n")
    _git(repo, "add", "README.md")
    rc, err = _run_hook(repo)
    assert rc == 0, f"expected pass on clean diff, stderr={err!r}"


def test_blocks_canary_password(repo):
    # The hook's regex uses [i]lovekalilinux so the *hook source* doesn't
    # self-match. A staged file with the literal string still matches.
    (repo / "config.yaml").write_text("sudo: " + "i" + "lovekalilinux777\n")
    _git(repo, "add", "config.yaml")
    rc, err = _run_hook(repo)
    assert rc != 0, "expected block on canary password"
    assert "secret-shaped content" in err


def test_blocks_pem_private_key(repo):
    # Assemble the literal at runtime so this test source itself doesn't
    # carry the canary pattern (the hook would otherwise self-block when
    # this file is staged).
    pem_head = "-----" + "BEGIN " + "RSA PRIVATE KEY" + "-----"
    pem_tail = "-----" + "END " + "RSA PRIVATE KEY" + "-----"
    (repo / "id_rsa.txt").write_text(
        pem_head + "\nMIIEpAIBAAKCAQEAxxx\n" + pem_tail + "\n"
    )
    _git(repo, "add", "id_rsa.txt")
    rc, err = _run_hook(repo)
    assert rc != 0
    assert "secret-shaped content" in err


def test_blocks_github_pat(repo):
    # Use string concat so this test file itself doesn't match the regex.
    body = "TOKEN=" + "gh" + "p_" + "0123456789abcdef0123456789abcdef0123\n"
    (repo / "deploy.sh").write_text(body)
    _git(repo, "add", "deploy.sh")
    rc, err = _run_hook(repo)
    assert rc != 0


def test_example_ok_escape_lets_fixture_through(repo):
    body = "TOKEN=" + "gh" + "p_" + "0123456789abcdef0123456789abcdef0123" \
           + "   # EXAMPLE-OK\n"
    (repo / ".env.example").write_text(body)
    # Path is .env.example, not .env, so the path-blacklist allows it
    # (.env$ is anchored).
    _git(repo, "add", ".env.example")
    rc, err = _run_hook(repo)
    assert rc == 0, f"EXAMPLE-OK escape should pass, stderr={err!r}"


def test_blocks_dotenv_path(repo):
    (repo / ".env").write_text("anything\n")
    _git(repo, "add", ".env")
    rc, err = _run_hook(repo)
    assert rc != 0
    assert "never-commit path" in err


def test_blocks_secret_dir_path(repo):
    (repo / "secret").mkdir()
    (repo / "secret" / "host.key").write_text("opaque\n")
    _git(repo, "add", "secret/host.key")
    rc, err = _run_hook(repo)
    assert rc != 0
    assert "never-commit path" in err


def test_blocks_prompt_txt_path(repo):
    (repo / "PROMPT.txt").write_text("handoff doc\n")
    _git(repo, "add", "PROMPT.txt")
    rc, err = _run_hook(repo)
    assert rc != 0


def test_blocks_claude_dir(repo):
    (repo / ".claude").mkdir()
    (repo / ".claude" / "state.json").write_text("{}\n")
    _git(repo, "add", ".claude/state.json")
    rc, err = _run_hook(repo)
    assert rc != 0


def test_hook_does_not_self_match_when_staged(repo):
    """The hook's own source contains all the patterns it scans for.
    The .githooks/* exclusion must keep it from blocking itself."""
    # Already staged via repo fixture? No — the fixture copies it but
    # doesn't `git add`. Stage it now.
    _git(repo, "add", ".githooks/pre-commit")
    rc, err = _run_hook(repo)
    assert rc == 0, f"hook self-staged should pass, stderr={err!r}"


def test_blocks_private_ssh_key_by_suffix(repo):
    (repo / "id_ed25519").write_text("opaque\n")
    _git(repo, "add", "id_ed25519")
    rc, err = _run_hook(repo)
    assert rc != 0
    assert "never-commit path" in err
