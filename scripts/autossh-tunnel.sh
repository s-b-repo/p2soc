#!/usr/bin/env bash
# Persistent autossh tunnel to the jump host. Builds -L local forwards from
# config/panels.yaml (one per mode: tunnel panel) and execs autossh. If no
# tunnels are configured it idles (so Restart=always doesn't churn).
set -euo pipefail

# Self-locate: parent of this scripts/ dir (works from any checkout).
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
CHECKOUT="$(cd "$(dirname "$SELF")/.." 2>/dev/null && pwd)"
if [ -d "$CHECKOUT/kiosk-host" ]; then
  ROOT="$CHECKOUT"
else
  ROOT="${SOC_ROOT:-/opt/soc-display}"
fi
[ -d "$ROOT/kiosk-host" ] || { echo "autossh-tunnel.sh: cannot find installation root (no kiosk-host/). Set SOC_ROOT=/path/to/repo" >&2; exit 1; }
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"
[ -r "$ENV_FILE" ] && { set -a; . "$ENV_FILE"; set +a; }
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-/etc/soc-display/panels.yaml}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

# Capture the python exit status separately from its output: process
# substitution (`mapfile < <(...)`) hides the python exit code, so a crashing
# tunnel-args.py (bad panels.yaml / missing PyYAML) would otherwise yield zero
# args and look like "no tunnels configured" — a silent dead-end. Fail loud and
# idle (so Restart=always doesn't churn on an unfixable config error) instead.
if ! ARGS_RAW="$("$PYBIN" "$ROOT/scripts/tunnel-args.py")"; then
  echo "[autossh-tunnel] FATAL: tunnel-args.py failed (bad panels.yaml or missing PyYAML?); idling so Restart does not churn — fix config and restart" >&2
  exec sleep infinity
fi
mapfile -t ARGS <<< "$ARGS_RAW"
# `<<< ""` yields a single empty element; normalize it back to an empty array so
# the no-tunnel happy path idles rather than exec'ing `autossh ""`.
if [ "${#ARGS[@]}" -eq 1 ] && [ -z "${ARGS[0]}" ]; then
  ARGS=()
fi

if [ "${#ARGS[@]}" -eq 0 ]; then
  echo "[autossh-tunnel] no tunnels configured; idling" >&2
  exec sleep infinity
fi

# -M 0 + ServerAlive (in tunnel-args.py) provides liveness; keep a small gate so
# autossh retains its tight-respawn protection — repeated sub-gate exits trip
# autossh's give-up, then systemd's RestartSec bounds the respawn. A bare
# GATETIME=0 disables that guard and lets a flapping link hot-loop with no
# backoff at either layer. Both knobs stay overridable from soc.env.
export AUTOSSH_GATETIME=${AUTOSSH_GATETIME:-30}
export AUTOSSH_POLL=${AUTOSSH_POLL:-30}
echo "[autossh-tunnel] autossh ${ARGS[*]}" >&2
exec autossh "${ARGS[@]}"
