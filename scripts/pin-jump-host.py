#!/usr/bin/env python3
"""
Record the SSH jump host's key the first time the tunnel starts.

The tunnel verifies the jump host strictly (StrictHostKeyChecking=yes), and strict
checking needs a key to check against. Before this, the unit's ProtectHome hid
~/.ssh, so ssh could never save a key and every connection trusted whatever it was
shown. Now the first start pins the key and every later connection is held to it.
That first start is still trust-on-first-use, and happens during deployment. To
remove even that window, put the key in the file yourself: it is then left alone.

Runs as root from autossh-tunnel.service (ExecStartPre), since the sandbox makes
the key directory read-only for the tunnel itself. It never fails the service: if
the host is unreachable, the tunnel fails closed, Restart= brings us back here, and
pinning is simply retried.
"""
import os
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))
from host import config as cfg  # noqa: E402

KNOWN_HOSTS = os.environ.get("SOC_KNOWN_HOSTS", "/etc/soc-display/keys/known_hosts")


def log(msg):
    print(f"[pin-jump-host] {msg}", flush=True)


def host_of(jump):
    """The host part of a user@host jump spec."""
    return jump.rsplit("@", 1)[-1]


def pinned(path, host):
    """True if `path` already holds a key for `host`."""
    return subprocess.run(["ssh-keygen", "-F", host, "-f", path], capture_output=True,
                          timeout=30).returncode == 0


def scan(host):
    r = subprocess.run(["ssh-keyscan", "-T", "10", "-t", "ed25519,ecdsa,rsa", host],
                       capture_output=True, text=True, timeout=60)
    return [ln for ln in r.stdout.splitlines() if ln and not ln.startswith("#")]


def append_atomic(path, lines):
    """Add keys without ever exposing a partial file."""
    parent = os.path.dirname(path)
    existing = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            existing = fh.read()
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".known_hosts.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(existing + "\n".join(lines) + "\n")
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def drop_privileges():
    """Become the key directory's owner. Root is only how this gets past the unit's
    sandbox: that directory belongs to the tunnel user, so root must not read or write
    anything in it, or a symlink planted there would be followed with root's rights."""
    if os.geteuid() != 0:
        return
    st = os.stat(os.path.dirname(KNOWN_HOSTS))
    os.setgroups([])
    os.setgid(st.st_gid)
    os.setuid(st.st_uid)


def main():
    drop_privileges()
    panels = os.environ.get("SOC_PANELS_FILE", "/etc/soc-display/panels.yaml")
    t = cfg.load(panels).tunnel or {}
    if not t.get("enabled", True) or not t.get("jump_host"):
        return 0
    if str(t.get("known_hosts") or "").strip():
        return 0                 # the operator manages this file themselves
    host = host_of(cfg._safe_host(t["jump_host"], "tunnel.jump_host"))
    if os.path.exists(KNOWN_HOSTS) and pinned(KNOWN_HOSTS, host):
        return 0
    keys = scan(host)
    if not keys:
        log(f"could not reach {host} to read its key; will retry on the next start")
        return 0
    append_atomic(KNOWN_HOSTS, keys)
    log(f"pinned {len(keys)} key(s) for {host} in {KNOWN_HOSTS}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - must never stop the tunnel from starting
        log(f"skipped: {e}")
        sys.exit(0)
