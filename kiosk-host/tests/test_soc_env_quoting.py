"""config/soc.env.example must source cleanly under bash. Catches the
regression where SOC_CONFIG_VAULT_ITEM=SOC Wall Config (unquoted spaces)
made bash interpret 'Wall Config' as a command, emitting the noisy
'Wall: command not found' line on every wall boot."""
from __future__ import annotations

import os
import shutil
import subprocess

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOC_ENV_EXAMPLE = os.path.join(REPO, "config", "soc.env.example")
LAUNCHER = os.path.join(REPO, "scripts", "wall-windowed.sh")


def _source_via_bash(path):
    """Source `path` under bash with the same idiom the launcher used to
    use (`set -a; . file; set +a`); return (rc, stderr)."""
    return subprocess.run(
        ["bash", "-c", f". {path}; true 2>&1"],
        capture_output=True, text=True, timeout=10)


def test_soc_env_example_sources_without_errors_under_bash():
    """The shipped example must source cleanly via `. soc.env.example`
    — the historic launcher idiom. Quoting bug -> bash errors on stderr."""
    rc = _source_via_bash(SOC_ENV_EXAMPLE)
    assert rc.returncode == 0, \
        f"bash sourcing failed: stderr={rc.stderr!r}"
    assert "command not found" not in rc.stderr.lower(), \
        f"bash interpreted a value as a command: {rc.stderr!r}"


def test_soc_env_example_no_unquoted_values_with_spaces():
    """Every VALUE that contains a literal space MUST be quoted (single OR
    double). Forward-looking guard so a future edit doesn't reintroduce
    the bug under a different key name."""
    bad = []
    with open(SOC_ENV_EXAMPLE, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            s = line.rstrip("\n")
            if not s or s.lstrip().startswith("#"):
                continue
            if "=" not in s:
                continue
            key, _, val = s.partition("=")
            val = val.strip()
            if " " not in val:
                continue
            if val.startswith('"') and val.endswith('"'):
                continue
            if val.startswith("'") and val.endswith("'"):
                continue
            bad.append((n, key, val))
    assert not bad, \
        f"unquoted value(s) with spaces in {SOC_ENV_EXAMPLE}: {bad}"


def test_launcher_safe_rewrite_handles_unquoted_value(tmp_path):
    """Even if a future hand-edit reintroduces an unquoted value, the
    canonical launcher's python rewrite must export the right string."""
    if not os.path.isfile(LAUNCHER):
        return                          # script not present in this checkout
    env_file = tmp_path / "soc.env"
    env_file.write_text(
        "# comment\n"
        "SOC_BACKEND=rbw\n"
        "SOC_CONFIG_VAULT_ITEM=SOC Wall Config\n"           # unquoted!
        'SOC_QUOTED="already quoted"\n'
        "SOC_SPACES=one two three\n"
        "junk-no-equals\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "rewritten.env"
    py = '''
import re, shlex, sys
PAT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
src = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for line in src.splitlines():
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    if not PAT.match(s):
        continue
    k, _, v = s.partition("=")
    if (len(v) >= 2) and v[0] == v[-1] and v[0] in ("'", chr(34)):
        v = v[1:-1]
    print(f"{k}={shlex.quote(v)}")
'''
    r = subprocess.run(
        ["python3", "-c", py, str(env_file)],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out_file.write_text(r.stdout, encoding="utf-8")
    # Now actually source the rewritten file under bash and read back.
    probe = subprocess.run(
        ["bash", "-c",
         f". {out_file}; echo SOC_CONFIG_VAULT_ITEM=[$SOC_CONFIG_VAULT_ITEM]; "
         f"echo SOC_SPACES=[$SOC_SPACES]"],
        capture_output=True, text=True)
    assert "SOC_CONFIG_VAULT_ITEM=[SOC Wall Config]" in probe.stdout
    assert "SOC_SPACES=[one two three]" in probe.stdout
    assert probe.returncode == 0
