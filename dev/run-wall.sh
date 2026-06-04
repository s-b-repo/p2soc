#!/usr/bin/env bash
# Interactive dev runner: shows the SOC wall in a Xephyr window on your desktop
# (with Openbox if installed) against the dummy panels + dev vault backend.
# Ctrl-C to stop. This is meant to be run in a normal terminal (not CI).
#
#   make dev            # -> bash dev/run-wall.sh
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
PY="$ROOT/.venv/bin/python"
DISP="${SOC_DEV_DISPLAY:-:8}"
RES="${SOC_DEV_RES:-1600x900}"

export HOME_REAL="$HOME"
export DISPLAY_OUTER="${DISPLAY:-:0}"
export LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
export SOC_VAULT_BACKEND="${SOC_VAULT_BACKEND:-dev}"
export SOC_DEV_VAULT="$ROOT/dev/run/dev-vault.json"
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-config/panels.dev.yaml}"
export SOC_READY_TIMEOUT=20 SOC_LAUNCH_STAGGER=1.2
export SOC_CHROMIUM_NO_SANDBOX=1
export XDG_RUNTIME_DIR="$ROOT/dev/run/xdgrt"; mkdir -p "$XDG_RUNTIME_DIR"
rm -rf "$XDG_RUNTIME_DIR/soc-profiles"
mkdir -p dev/run

[ -f dev/run/dev-vault.json ] || { echo "run 'make dev-vault' first"; exit 1; }

pids=()
cleanup(){ echo; echo "stopping..."; kill "${pids[@]}" 2>/dev/null; pkill -f "remote-debugging-port=92" 2>/dev/null; }
trap cleanup EXIT INT TERM
waitport(){ for _ in $(seq 1 60); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.3; done; return 1; }

echo "[dev] Xephyr $DISP ($RES) on outer display $DISPLAY_OUTER"
DISPLAY="$DISPLAY_OUTER" Xephyr "$DISP" -screen "$RES" -ac -resizeable -title "SOC wall (dev)" >dev/run/xephyr.log 2>&1 & pids+=($!)
for _ in $(seq 1 40); do DISPLAY="$DISP" xdpyinfo >/dev/null 2>&1 && break; sleep 0.3; done

export DISPLAY="$DISP"
if command -v openbox >/dev/null 2>&1; then
  echo "[dev] generating openbox rc.xml + starting openbox"
  W="${RES%x*}"; H="${RES#*x}"
  "$PY" scripts/gen-openbox-rc.py --panels "$SOC_PANELS_FILE" \
        --template openbox/rc.xml.tmpl --out dev/run/openbox/rc.xml --width "$W" --height "$H" >/dev/null
  openbox --config-file dev/run/openbox/rc.xml >dev/run/openbox.log 2>&1 & pids+=($!)
  sleep 1
else
  echo "[dev] openbox not installed — windows placed by the host (no titlebars)"
fi

echo "[dev] dummy panels"
"$PY" dev/dummy-panels/server.py >dev/run/panels.log 2>&1 & pids+=($!)
waitport 9001 || { echo "panels failed"; exit 1; }

echo "[dev] tunnel stand-in 19102 -> 9002"
"$PY" dev/tcp-forward.py 19102 127.0.0.1 9002 >dev/run/fwd.log 2>&1 & pids+=($!)
waitport 19102 || true

echo "[dev] kiosk host (Ctrl-C to stop)"
PYTHONPATH=kiosk-host "$PY" -m host.main
