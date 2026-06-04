#!/usr/bin/env python3
"""
Emit the autossh argument list (one arg per line) from config/panels.yaml.

Builds an -L local forward for every panel with mode: tunnel, so each remote
panel becomes http://127.0.0.1:<local_port>/... Prints nothing if there are no
tunnels (the wrapper then idles).

  autossh $(this script) ==> persistent jump-host tunnel
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))
from host import config as cfg  # noqa: E402


def main():
    panels = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    conf = cfg.load(panels)
    t = conf.tunnel or {}

    forwards = []
    for p in conf.panels:
        if p.mode == "tunnel" and p.tunnel:
            tn = p.tunnel
            forwards.append(
                f"127.0.0.1:{tn['local_port']}:{tn['remote_host']}:{tn['remote_port']}")
    forwards += list(t.get("extra_forwards", []) or [])

    if not t.get("enabled", True) or not forwards or not t.get("jump_host"):
        return  # nothing to tunnel

    args = ["-M", "0", "-N",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes"]
    ident = t.get("identity")
    if ident:
        args += ["-i", os.path.expanduser(ident)]
    for f in forwards:
        args += ["-L", f]
    args.append(t["jump_host"])
    sys.stdout.write("\n".join(args) + "\n")


if __name__ == "__main__":
    main()
