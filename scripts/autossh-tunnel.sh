#!/usr/bin/env bash
# Persistent autossh tunnel to the jump host. Builds -L local forwards from
# config/panels.yaml (one per mode: tunnel panel) and execs autossh. If no
# tunnels are configured it idles (so Restart=always doesn't churn).
set -euo pipefail

ROOT="${SOC_ROOT:-/opt/soc-display}"
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"
[ -r "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-/etc/soc-display/panels.yaml}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

mapfile -t ARGS < <("$PYBIN" "$ROOT/scripts/tunnel-args.py")

if [ "${#ARGS[@]}" -eq 0 ]; then
  echo "[autossh-tunnel] no tunnels configured; idling" >&2
  exec sleep infinity
fi

export AUTOSSH_GATETIME=0
echo "[autossh-tunnel] autossh ${ARGS[*]}" >&2
exec autossh "${ARGS[@]}"
