#!/usr/bin/env python3
"""
Emit the autossh argument list (one arg per line) from config/panels.yaml.

Builds an -L local forward for every panel with mode: tunnel, so each remote
panel becomes http://127.0.0.1:<local_port>/... Prints nothing if there are no
tunnels (the wrapper then idles).

  autossh $(this script) ==> persistent jump-host tunnel

Every value is vetted by the guards in host/config.py first. The output is
line-based, so a value holding a newline would otherwise inject a whole extra
argument, and anything starting with '-' could be read as an ssh option.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))
from host import config as cfg  # noqa: E402


# Where scripts/pin-jump-host.py records the jump host's key on first start.
PINNED_KNOWN_HOSTS = "/etc/soc-display/keys/known_hosts"


def _validate_extra_forward(entry):
    """Return a vetted [bindaddr:]port:host:port forward, or raise ValueError."""
    return cfg._safe_forward(entry)


def main():
    panels = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    conf = cfg.load(panels)
    t = conf.tunnel or {}

    # A disabled tunnel section, or one with nowhere to connect, is a legitimate
    # no-op: print nothing and let autossh-tunnel.sh idle.
    if not t.get("enabled", True) or not t.get("jump_host"):
        return
    jump = cfg._safe_host(t["jump_host"], "tunnel.jump_host")

    forwards = []
    for p in conf.panels:
        if p.mode == "tunnel" and p.tunnel:
            # One bad panel must not take down the other panels' forwards, and
            # a malformed -L is one ssh rejects and autossh retries forever.
            try:
                forwards.append(cfg.panel_forward(p.tunnel))
            except ValueError as e:
                sys.stderr.write(f"tunnel-args: skipping panel {p.id!r}: "
                                 f"malformed tunnel section ({e})\n")
    forwards += [_validate_extra_forward(f)
                 for f in (t.get("extra_forwards") or [])]

    # An ENABLED tunnel with a jump_host but zero forwards is a misconfiguration,
    # not a no-op: the operator meant to tunnel something. Surface it to the
    # journal instead of looking identical to "no tunnels intended".
    if not forwards:
        sys.stderr.write(
            "tunnel-args: tunnel.enabled=true and jump_host is set, but NO "
            "panels use mode: tunnel and tunnel.extra_forwards is empty, so "
            "there is nothing for autossh to forward. Either disable the "
            "tunnel section, or give a panel mode: tunnel / add an "
            "extra_forward.\n")
        sys.exit(2)

    # SEC-6: verify the jump host's key. With anything weaker than strict 'yes'
    # (i.e. 'accept-new' TOFU), require an explicit known_hosts path: otherwise
    # ssh writes first-use keys into a default file we don't control, a silent
    # MITM window. The operator must pin a dedicated, provisioned file.
    hkc = cfg.host_key_checking(t)
    known = cfg._safe_word(t.get("known_hosts"), "tunnel.known_hosts")
    if not known and os.path.exists(PINNED_KNOWN_HOSTS):
        known = PINNED_KNOWN_HOSTS
    if hkc != "yes" and not known:
        raise ValueError(
            "host_key_checking={!r} requires an explicit 'known_hosts' path "
            "(set tunnel.known_hosts) so first-connect keys are pinned to a "
            "controlled file; refusing to weaken host-key verification without "
            "it.".format(t.get("host_key_checking")))

    args = ["-M", "0", "-N",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-o", f"StrictHostKeyChecking={hkc}",
            "-o", "BatchMode=yes"]
    if known:
        args += ["-o", f"UserKnownHostsFile={os.path.expanduser(known)}"]
    ident = cfg._safe_word(t.get("identity"), "tunnel.identity")
    if ident:
        args += ["-i", os.path.expanduser(ident)]
    for f in forwards:
        args += ["-L", f]
    args.append(jump)
    sys.stdout.write("\n".join(args) + "\n")


if __name__ == "__main__":
    main()
