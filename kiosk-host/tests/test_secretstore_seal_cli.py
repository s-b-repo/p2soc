"""
Tests for the `host.secretstore --seal` pkexec helper — the root-side seal the
GUI/TTY wizard invokes (over pkexec) to RE-SEAL the vault master into a root-owned
secret dir (e.g. /etc/soc-display/secret on a deployed box) when re-running Setup
as a non-root desktop user.

The contract under test (no pkexec / no root needed — we run the helper directly
against a sandbox secret dir):
  * master + PIN arrive over STDIN (---MASTER---/---PIN--- markers), the seal
    round-trips (unseal == master), and the one-time PIN is printed to stdout;
  * a blank PIN makes the helper generate one (and print it);
  * the plaintext master is NEVER written to any file — only the AES-GCM blob;
  * malformed STDIN / empty master are refused with a non-zero exit and no seal.
"""
import os
import subprocess
import sys

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_KIOSK = os.path.join(_REPO, "kiosk-host")

secretstore = pytest.importorskip("host.secretstore")
if not secretstore.available():
    pytest.skip("cryptography not available — no seal backend", allow_module_level=True)


def _run_seal(secret_dir, stdin_text, machine_id="seal-cli-test-host"):
    """Invoke the helper exactly as pkexec would, by ABSOLUTE PATH (the GUI calls it
    by path because pkexec strips PYTHONPATH). Returns the CompletedProcess."""
    helper = os.path.join(_KIOSK, "host", "secretstore.py")
    env = dict(os.environ)
    env["SOC_MACHINE_ID"] = machine_id      # stand in for /etc/machine-id
    return subprocess.run(
        [sys.executable, helper, "--seal", "--dir", str(secret_dir)],
        input=stdin_text, text=True, capture_output=True, env=env)


def _no_plaintext_anywhere(d, master):
    for root, _dirs, files in os.walk(d):
        for fn in files:
            with open(os.path.join(root, fn), "rb") as fh:
                if master.encode() in fh.read():
                    return False
    return True


def test_seal_cli_round_trips_and_hides_plaintext(tmp_path, monkeypatch):
    sd = tmp_path / "secret"
    master, pin = "Tr0ub4dor-&-3", "20461"
    r = _run_seal(sd, f"---MASTER---\n{master}\n---PIN---\n{pin}")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == pin          # the one-time PIN is echoed for the caller
    # The seal is complete and unseals to the master on THIS (env-pinned) host.
    monkeypatch.setenv("SOC_MACHINE_ID", "seal-cli-test-host")
    assert secretstore.is_sealed(str(sd))
    assert secretstore.unseal(str(sd)) == master
    assert _no_plaintext_anywhere(sd, master)   # only the AES-GCM blob, never plaintext


def test_seal_cli_generates_pin_when_blank(tmp_path, monkeypatch):
    sd = tmp_path / "secret"
    master = "another-master"
    r = _run_seal(sd, f"---MASTER---\n{master}\n---PIN---\n")
    assert r.returncode == 0, r.stderr
    gen = r.stdout.strip()
    assert gen.isdigit() and len(gen) >= 4    # a fresh numeric PIN was generated + shown
    monkeypatch.setenv("SOC_MACHINE_ID", "seal-cli-test-host")
    assert secretstore.unseal(str(sd)) == master


def test_seal_cli_refuses_malformed_stdin(tmp_path):
    sd = tmp_path / "secret"
    r = _run_seal(sd, "no markers here")
    assert r.returncode == 2
    assert not os.path.exists(sd)             # nothing sealed on malformed input


def test_seal_cli_refuses_empty_master(tmp_path):
    sd = tmp_path / "secret"
    r = _run_seal(sd, "---MASTER---\n\n---PIN---\n1234")
    assert r.returncode == 2
    assert not secretstore.is_sealed(str(sd))
