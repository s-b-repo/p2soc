#!/usr/bin/env bash
# Launch and supervise the SOC kiosk host inside the X session.
# Started by Openbox autostart. Sources the (tmpfs) env, then restarts the host
# if it ever exits so the wall self-heals.
set -u

ROOT="${SOC_ROOT:-/opt/soc-display}"
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"

# Load environment (vault creds, ports, timeouts). Keep this file on tmpfs 0600.
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

export PYTHONPATH="$ROOT/kiosk-host${PYTHONPATH:+:$PYTHONPATH}"
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-/etc/soc-display/panels.yaml}"
export SOC_INJECT_TMPL="${SOC_INJECT_TMPL:-$ROOT/inject/login.js.tmpl}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

cd "$ROOT" || exit 1

while true; do
  echo "[launcher] starting kiosk host $(date -Is)" >&2
  "$PYBIN" -m host.main
  code=$?
  echo "[launcher] kiosk host exited ($code); restarting in 3s" >&2
  sleep 3
done
