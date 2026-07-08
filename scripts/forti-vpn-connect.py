#!/usr/bin/env python3
"""
Connect the SOC wall to a Fortinet (FortiGate) SSL-VPN — thin entry point.

All the logic lives in kiosk-host/host/fortivpn.py: a supervisor that keeps
openfortivpn running with classified error handling (auth vs. certificate vs.
network), exponential backoff, per-attempt OTP, an optional liveness probe, and
systemd READY/STATUS/WATCHDOG integration. Run by forti-vpn.service (as root)
via scripts/forti-vpn.sh.

Upstream: https://github.com/adrienverge/openfortivpn

Env:
  SOC_VAULT_BACKEND   litebw (default) | rbw | dev — selects the vault backend
  SOC_PANELS_FILE     path to panels.yaml
  SOC_READY_TIMEOUT   seconds to wait for the vault per attempt (default 120)
  SOC_VPN_DRY_RUN=1   resolve creds + print the command, then exit (no connect) —
                      used by `make vpn-check` to verify wiring without a FortiGate
  SOC_VPN_AUTH_RETRY_DELAY / SOC_VPN_CERT_RETRY_DELAY   long backoffs (default 300)
  SOC_VPN_BACKOFF_INITIAL / SOC_VPN_BACKOFF_MAX         network backoff (5 / 60)
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))

# the pinentry helper lives next to this script — pass an absolute path so the
# supervisor works no matter what cwd systemd gave us
os.environ.setdefault("SOC_VPN_PINENTRY", os.path.join(_HERE, "forti-pinentry.sh"))

from host import fortivpn  # noqa: E402

if __name__ == "__main__":
    sys.exit(fortivpn.main())
