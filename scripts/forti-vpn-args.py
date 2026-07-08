#!/usr/bin/env python3
"""
Emit the **non-secret** openfortivpn argument list (one arg per line) from the
`vpn:` section of config/panels.yaml. For inspection / debugging / tests only —
the live connection is made by scripts/forti-vpn-connect.py, which adds the
username, password (via --pinentry) and any OTP. Prints nothing when the VPN is
disabled or has no gateway.

  openfortivpn $(this script) -u <user> --pinentry=...   ==> Fortinet SSL-VPN
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))
from host import config as cfg  # noqa: E402


def main():
    panels = os.environ.get("SOC_PANELS_FILE", "config/panels.yaml")
    vpn = (cfg.load(panels).vpn or {})
    if not vpn.get("enabled", False):
        return
    args = cfg.openfortivpn_args(vpn)
    if args:
        sys.stdout.write("\n".join(args) + "\n")


if __name__ == "__main__":
    main()
