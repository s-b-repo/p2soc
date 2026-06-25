"""iNode (H3C SSL VPN) vnic: privileged `ip`/`resolvectl` subprocesses must not
hang the root-running VPN supervisor forever.

These tests pin the timeout-handling contract for the three subprocess sites in
``backends/h3csvpn/vnic.py``: a stuck local tool (``TimeoutExpired``) folds into
each site's *existing* failure path instead of blocking indefinitely. Without the
``timeout=`` + handler, a wedged netlink / systemd-resolved D-Bus call would stall
VPN bring-up/teardown and defeat the 24/7 self-healing guarantee.
"""
import os
import subprocess
import sys

import pytest

# Load the vendored backend (relative-import package) the same way the rest of
# the suite reaches repo-root assets: prepend the client dir, import the package.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_INODE = os.path.join(_REPO, "vendor", "iNode-VPN-Client")
if _INODE not in sys.path:
    sys.path.insert(0, _INODE)

vnic = pytest.importorskip("backends.h3csvpn.vnic")


def _make_timeout(monkeypatch):
    """Patch vnic.subprocess.run to behave like a hung local tool."""
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd=(a[0] if a else "x"), timeout=15)
    monkeypatch.setattr(vnic.subprocess, "run", boom)


def test_ip_timeout_check_true_raises_like_failure(monkeypatch):
    # check=True callers (addr/route add) already expect RuntimeError on failure;
    # a timeout must surface the same way so cleanup/retry can proceed.
    _make_timeout(monkeypatch)
    with pytest.raises(RuntimeError) as ei:
        vnic._ip("route", "add", "10.0.0.0/24", "dev", "inode0", check=True)
    assert "timed out" in str(ei.value)


def test_ip_timeout_check_false_returns_nonzero(monkeypatch):
    # check=False callers just skip tracking the route on non-zero; a timeout
    # must look like a non-zero return, not propagate.
    _make_timeout(monkeypatch)
    assert vnic._ip("route", "add", "10.0.0.0/24", check=False) == 1


def test_original_default_gw_timeout_returns_empty(monkeypatch):
    # A hung `ip route show default` falls back to "" (best-effort, same as its
    # existing "no gateway found" value) rather than blocking route programming.
    _make_timeout(monkeypatch)
    assert vnic._original_default_gw() == ""


def test_resolvectl_timeout_is_swallowed(monkeypatch):
    # The split-tunnel resolvectl call is fire-and-forget; a TimeoutExpired (not
    # an OSError) must be caught by the broadened handler, not propagate.
    monkeypatch.setattr(vnic.shutil, "which", lambda _n: "/usr/bin/resolvectl")
    _make_timeout(monkeypatch)

    class _Cfg:
        dns = ["10.0.0.1"]
        ipv6dns = []

    nic = vnic.VirtualNIC()
    nic.ifname = "inode0"
    nic._program_dns(_Cfg(), split_tunnel=True)  # must not raise


def test_resolvectl_oserror_still_swallowed(monkeypatch):
    # Regression guard: broadening `except OSError` to also catch TimeoutExpired
    # must not stop catching the original OSError case.
    monkeypatch.setattr(vnic.shutil, "which", lambda _n: "/usr/bin/resolvectl")

    def boom(*a, **k):
        raise OSError("resolvectl missing")
    monkeypatch.setattr(vnic.subprocess, "run", boom)

    class _Cfg:
        dns = ["10.0.0.1"]
        ipv6dns = []

    nic = vnic.VirtualNIC()
    nic.ifname = "inode0"
    nic._program_dns(_Cfg(), split_tunnel=True)  # must not raise
