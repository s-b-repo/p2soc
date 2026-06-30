#!/usr/bin/env bash
# systemd entry point for the Fortinet SSL-VPN (forti-vpn.service).
# Sources the kiosk env (vault config + master password for unattended unlock),
# then hands off to the Python connector, which reads the FortiGate creds from
# the vault and execs openfortivpn. Mirrors scripts/autossh-tunnel.sh.
set -euo pipefail

# Self-locate: parent of this scripts/ dir (works from any checkout).
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
CHECKOUT="$(cd "$(dirname "$SELF")/.." 2>/dev/null && pwd)"
if [ -d "$CHECKOUT/kiosk-host" ]; then
  ROOT="$CHECKOUT"
else
  ROOT="${SOC_ROOT:-/opt/soc-display}"
fi
[ -d "$ROOT/kiosk-host" ] || { echo "forti-vpn.sh: cannot find installation root (no kiosk-host/). Set SOC_ROOT=/path/to/repo" >&2; exit 1; }
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"
[ -r "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-/etc/soc-display/panels.yaml}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

exec "$PYBIN" "$ROOT/scripts/forti-vpn-connect.py"
