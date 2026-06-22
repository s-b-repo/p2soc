#!/usr/bin/env bash
# systemd entry point for the Fortinet SSL-VPN (forti-vpn.service).
# Sources the kiosk env (vault config + master password for unattended unlock),
# then hands off to the Python connector, which reads the FortiGate creds from
# the vault and execs openfortivpn. Mirrors scripts/autossh-tunnel.sh.
set -euo pipefail

ROOT="${SOC_ROOT:-/opt/soc-display}"
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"
[ -f "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-/etc/soc-display/panels.yaml}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

exec "$PYBIN" "$ROOT/scripts/forti-vpn-connect.py"
