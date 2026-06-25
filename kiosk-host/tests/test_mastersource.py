"""Offline tests for host/mastersource.py — the pluggable master-password source.

Everything is faked: secretstore.is_sealed/unseal are monkeypatched, and
secret-tool is faked two ways — (1) a lightweight shutil.which + subprocess.run
monkeypatch for the bulk of the matrix, and (2) a REAL fake `secret-tool` script
dropped on a tmp PATH that echoes a known master for `lookup` and records its
argv/stdin for `store`, exercising the true subprocess path end-to-end. No real
D-Bus, wallet, or machine-id is touched (mirrors SOC_VAULT_BACKEND=dev offline).
"""
import os
import subprocess

import pytest

from host import mastersource as ms
from host import secretstore


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_sealed(monkeypatch, value="sealed-master", sealed=True):
    monkeypatch.setattr(secretstore, "is_sealed", lambda *a, **k: sealed)
    monkeypatch.setattr(secretstore, "unseal", lambda *a, **k: value)
    monkeypatch.setattr(secretstore, "available", lambda *a, **k: True)


def _have_tool(monkeypatch, present=True):
    monkeypatch.setattr(ms.shutil, "which",
                        lambda name: "/usr/bin/secret-tool" if present else None)


def _fake_secret_tool(monkeypatch, *, lookup_value=None, store_ok=True,
                      raises=None):
    """Patch subprocess.run so 'secret-tool lookup' returns `lookup_value`
    (None => absent, returncode 1) and 'secret-tool store' succeeds/fails."""
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        if raises is not None:
            raise raises
        sub = argv[1] if len(argv) > 1 else ""
        if sub == "lookup":
            if lookup_value is None:
                return _FakeProc(returncode=1, stdout="")
            return _FakeProc(returncode=0, stdout=lookup_value)
        if sub == "store":
            return _FakeProc(returncode=0 if store_ok else 1,
                             stderr="" if store_ok else "no Secret Service")
        return _FakeProc(returncode=0)

    monkeypatch.setattr(ms.subprocess, "run", run)
    return calls


# --------------------------------------------------------------------------- #
# Explicit-source resolution
# --------------------------------------------------------------------------- #
def test_sealed_source(monkeypatch):
    _fake_sealed(monkeypatch, "SEAL")
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV")
    assert ms.get_master("sealed") == "SEAL"


def test_sealed_source_empty_when_not_sealed(monkeypatch):
    _fake_sealed(monkeypatch, sealed=False)
    assert ms.get_master("sealed") == ""


def test_sealed_source_degrades_on_error(monkeypatch, capsys):
    monkeypatch.setattr(secretstore, "is_sealed", lambda *a, **k: True)

    def boom(*a, **k):
        raise secretstore.SecretStoreError("no machine-id")
    monkeypatch.setattr(secretstore, "unseal", boom)
    assert ms.get_master("sealed") == ""           # never raises
    assert "no machine-id" in capsys.readouterr().err


def test_secret_service_source(monkeypatch):
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch, lookup_value="SS-master")
    assert ms.get_master("secret-service") == "SS-master"


def test_secret_service_strips_one_trailing_newline_only(monkeypatch):
    # secret-tool may emit a single trailing newline; surrounding spaces in the
    # actual secret MUST survive (no .strip()).
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch, lookup_value="  pw with spaces  \n")
    assert ms.get_master("secret-service") == "  pw with spaces  "


def test_secret_service_absent_item_is_empty(monkeypatch):
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch, lookup_value=None)   # returncode 1
    assert ms.get_master("secret-service") == ""


def test_secret_service_timeout_degrades(monkeypatch, capsys):
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch,
                      raises=subprocess.TimeoutExpired("secret-tool", 10))
    assert ms.get_master("secret-service") == ""
    assert "timed out" in capsys.readouterr().err


def test_secret_service_tool_absent_degrades(monkeypatch):
    _fake_secret_tool(monkeypatch, raises=FileNotFoundError())
    assert ms.get_master("secret-service") == ""


def test_env_source(monkeypatch, capsys):
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV-master")
    assert ms.get_master("env") == "ENV-master"
    assert "DEV/seeding only" in capsys.readouterr().err   # deprecation warning


def test_unknown_source_raises(monkeypatch):
    with pytest.raises(ValueError):
        ms.get_master("bogus")


# --------------------------------------------------------------------------- #
# 'auto' resolution order: sealed -> secret-service -> env
# --------------------------------------------------------------------------- #
def test_auto_prefers_sealed(monkeypatch):
    _fake_sealed(monkeypatch, "SEAL", sealed=True)
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch, lookup_value="SS")
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV")
    assert ms.get_master("auto") == "SEAL"


def test_auto_falls_to_secret_service_when_unsealed(monkeypatch):
    _fake_sealed(monkeypatch, sealed=False)
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch, lookup_value="SS")
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV")
    assert ms.get_master("auto") == "SS"


def test_auto_falls_to_env_when_no_seal_no_wallet(monkeypatch):
    _fake_sealed(monkeypatch, sealed=False)
    _have_tool(monkeypatch, False)                 # no secret-tool on PATH
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV")
    assert ms.get_master("auto") == "ENV"


def test_auto_skips_empty_secret_service_then_env(monkeypatch):
    _fake_sealed(monkeypatch, sealed=False)
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch, lookup_value=None)   # wallet has no item
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV")
    assert ms.get_master("auto") == "ENV"


def test_auto_default_via_env_var(monkeypatch):
    # No explicit source arg: SOC_MASTER_SOURCE drives it; unset => 'auto'.
    _fake_sealed(monkeypatch, "SEAL", sealed=True)
    monkeypatch.delenv("SOC_MASTER_SOURCE", raising=False)
    assert ms.get_master() == "SEAL"
    monkeypatch.setenv("SOC_MASTER_SOURCE", "env")
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "ENV")
    assert ms.get_master() == "ENV"


# --------------------------------------------------------------------------- #
# available_sources — capability probe (no side effects)
# --------------------------------------------------------------------------- #
def test_available_sources_lists_present(monkeypatch):
    _fake_sealed(monkeypatch, sealed=True)
    _have_tool(monkeypatch, True)
    assert ms.available_sources() == ["sealed", "secret-service", "env"]


def test_available_sources_env_always(monkeypatch):
    monkeypatch.setattr(secretstore, "available", lambda *a, **k: True)
    monkeypatch.setattr(secretstore, "is_sealed", lambda *a, **k: False)
    _have_tool(monkeypatch, False)
    assert ms.available_sources() == ["env"]


def test_available_sources_no_unseal_side_effect(monkeypatch):
    # Must probe is_sealed but NEVER call unseal (no secret material leaks).
    monkeypatch.setattr(secretstore, "available", lambda *a, **k: True)
    monkeypatch.setattr(secretstore, "is_sealed", lambda *a, **k: True)

    def fail(*a, **k):
        raise AssertionError("available_sources must not unseal")
    monkeypatch.setattr(secretstore, "unseal", fail)
    _have_tool(monkeypatch, False)
    assert ms.available_sources() == ["sealed", "env"]


# --------------------------------------------------------------------------- #
# Attribute scheme + SOC_SECRET_ATTRS override
# --------------------------------------------------------------------------- #
def test_default_attrs():
    assert ms._resolve_attrs() == {"service": "soc-wall", "account": "vault-master"}


def test_attrs_env_override(monkeypatch):
    monkeypatch.setenv("SOC_SECRET_ATTRS", "service=acme account=vw extra=1")
    assert ms._resolve_attrs() == {"service": "acme", "account": "vw", "extra": "1"}


def test_attrs_explicit_wins(monkeypatch):
    monkeypatch.setenv("SOC_SECRET_ATTRS", "service=env-one account=x")
    assert ms._resolve_attrs({"service": "explicit"}) == {"service": "explicit"}


def test_lookup_uses_resolved_attrs_on_argv(monkeypatch):
    _have_tool(monkeypatch, True)
    calls = _fake_secret_tool(monkeypatch, lookup_value="x")
    ms.get_master("secret-service")
    argv = calls[0][0]
    assert argv[:2] == ["secret-tool", "lookup"]
    assert argv[2:] == ["service", "soc-wall", "account", "vault-master"]


# --------------------------------------------------------------------------- #
# store_master — only secret-service writes; env/sealed are refused
# --------------------------------------------------------------------------- #
def test_store_master_secret_service(monkeypatch):
    _have_tool(monkeypatch, True)
    calls = _fake_secret_tool(monkeypatch, store_ok=True)
    ms.store_master("the-master", "secret-service")
    argv, kw = calls[0]
    assert argv[:3] == ["secret-tool", "store", "--label"]
    assert "service" in argv and "soc-wall" in argv
    # the secret is fed on stdin, NEVER on argv (no leak via ps/proc)
    assert "the-master" not in argv
    assert kw.get("input") == "the-master"


def test_store_master_refuses_env(monkeypatch):
    with pytest.raises(ms.MasterSourceError):
        ms.store_master("pw", "env")


def test_store_master_refuses_sealed(monkeypatch):
    with pytest.raises(ms.MasterSourceError):
        ms.store_master("pw", "sealed")


def test_store_master_refuses_empty(monkeypatch):
    with pytest.raises(ms.MasterSourceError):
        ms.store_master("", "secret-service")


def test_store_master_needs_secret_tool(monkeypatch):
    _have_tool(monkeypatch, False)
    with pytest.raises(ms.MasterSourceError):
        ms.store_master("pw", "secret-service")


def test_store_master_surfaces_store_failure(monkeypatch):
    _have_tool(monkeypatch, True)
    _fake_secret_tool(monkeypatch, store_ok=False)
    with pytest.raises(ms.MasterSourceError):
        ms.store_master("pw", "secret-service")


# --------------------------------------------------------------------------- #
# REAL on-PATH fake `secret-tool` — exercises the true subprocess path
# (PATH lookup + a real child process + actual stdin plumbing), not a
# subprocess.run monkeypatch. Proves the master is fed on STDIN, never argv.
# --------------------------------------------------------------------------- #
# `lookup` echoes a fixed master verbatim (with the trailing newline libsecret
# adds). `store` appends one line to $REC: the full argv it was called with, then
# a tab, then everything it read on stdin — so the test can assert the master is
# on stdin and absent from argv. `$REC` is exported by the test before each call.
_FAKE_SECRET_TOOL = """\
#!/usr/bin/env python3
import sys
if len(sys.argv) > 1 and sys.argv[1] == "lookup":
    sys.stdout.write("on-path-master\\n")
    sys.exit(0)
if len(sys.argv) > 1 and sys.argv[1] == "store":
    data = sys.stdin.read()
    with open(__import__("os").environ["REC"], "a", encoding="utf-8") as fh:
        fh.write("\\x1f".join(sys.argv[1:]) + "\\t" + data + "\\n")
    sys.exit(0)
sys.exit(2)
"""


@pytest.fixture
def on_path_secret_tool(tmp_path, monkeypatch):
    """Drop an executable fake `secret-tool` onto a tmp dir and prepend it to
    PATH, so shutil.which() and subprocess.run() resolve the REAL fake binary.
    Yields the path of the file the fake records `store` invocations into."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = bindir / "secret-tool"
    tool.write_text(_FAKE_SECRET_TOOL)
    tool.chmod(0o755)
    rec = tmp_path / "rec.log"
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("REC", str(rec))
    # SOC_SECRET_ATTRS unset => the fixed default attribute pair is used.
    monkeypatch.delenv("SOC_SECRET_ATTRS", raising=False)
    return rec


def test_real_lookup_returns_echoed_master(on_path_secret_tool):
    # shutil.which finds the fake on PATH and the real subprocess runs it.
    assert ms._have_secret_tool() is True
    assert ms.get_master("secret-service") == "on-path-master"


def test_real_auto_uses_on_path_secret_tool(on_path_secret_tool, monkeypatch):
    # Unsealed + no env => 'auto' must reach the real on-PATH secret-tool.
    monkeypatch.setattr(secretstore, "is_sealed", lambda *a, **k: False)
    monkeypatch.delenv("SOC_VAULT_PASSWORD", raising=False)
    assert ms.get_master("auto") == "on-path-master"


def test_real_store_feeds_master_on_stdin_not_argv(on_path_secret_tool):
    rec = on_path_secret_tool
    ms.store_master("S3cr3t-on-stdin", "secret-service")
    line = rec.read_text().splitlines()[0]
    argv_str, stdin = line.split("\t", 1)
    argv = argv_str.split("\x1f")
    # the recorded argv is exactly the store invocation with attrs, no secret
    assert argv[0] == "store"
    assert argv[1:3] == ["--label", ms._LABEL]
    assert argv[3:] == ["service", "soc-wall", "account", "vault-master"]
    # the master reached the child ONLY via stdin (never via argv => no ps leak)
    assert stdin == "S3cr3t-on-stdin"
    assert "S3cr3t-on-stdin" not in argv_str


def test_real_store_then_lookup_roundtrip_argv_has_no_secret(on_path_secret_tool):
    # End-to-end: store records, lookup echoes; the master never appears on argv.
    ms.store_master("round-trip-master", "secret-service")
    assert ms.get_master("secret-service") == "on-path-master"
    recorded = on_path_secret_tool.read_text()
    assert "round-trip-master" not in recorded.split("\t", 1)[0]
