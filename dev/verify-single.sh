#!/usr/bin/env bash
# Headless check of the single-window (Wayland-style) layout on Xvfb: all
# panels render inside ONE fullscreen grid window and log in. This is the same
# code path cage/labwc exercise on the Pi (the compositor only goes fullscreen).
# Run:  make verify-single
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
PY="$ROOT/.venv/bin/python"
DISP="${SOC_TEST_DISPLAY:-:7}"

export HOME="$ROOT/dev/run/home"; mkdir -p "$HOME"
export DISPLAY="$DISP"
export LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
export SOC_VAULT_BACKEND=dev SOC_DEV_VAULT="$ROOT/dev/run/dev-vault.json"
export SOC_READY_TIMEOUT=20 SOC_LAUNCH_STAGGER=0.5
export XDG_RUNTIME_DIR="$ROOT/dev/run/xdgrt"; mkdir -p "$XDG_RUNTIME_DIR"

mkdir -p dev/run
# all-webkit copy of the dev config with layout: single
"$PY" - <<'EOF'
import yaml
c = yaml.safe_load(open("config/panels.dev.yaml"))
c["display"]["layout"] = "single"
for p in c["panels"]:
    p["engine"] = "webkit"
yaml.safe_dump(c, open("dev/run/panels.single.yaml", "w"))
EOF
export SOC_PANELS_FILE=dev/run/panels.single.yaml

pids=()
cleanup(){ kill "${pids[@]}" 2>/dev/null; }
trap cleanup EXIT

waitport(){ for _ in $(seq 1 60); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.3; done; return 1; }

echo "[verify-single] starting Xvfb on $DISP"
timeout 70 Xvfb "$DISP" -screen 0 1920x1080x24 -ac >dev/run/xvfb.log 2>&1 & pids+=($!)
for _ in $(seq 1 40); do xdpyinfo -display "$DISP" >/dev/null 2>&1 && break; sleep 0.3; done

echo "[verify-single] starting dummy panels + tunnel stand-in"
timeout 70 "$PY" dev/dummy-panels/server.py >dev/run/panels.log 2>&1 & pids+=($!)
waitport 9001 || { echo "FAIL: panels did not start"; exit 1; }
timeout 70 "$PY" dev/tcp-forward.py 19102 127.0.0.1 9002 >dev/run/fwd.log 2>&1 & pids+=($!)
waitport 19102 || { echo "FAIL: tunnel forward not up"; exit 1; }

echo "[verify-single] starting kiosk host (layout: single)"
PYTHONPATH=kiosk-host timeout 50 "$PY" -m host.main >dev/run/host-single.log 2>&1 & pids+=($!)

distinct_logins(){ grep -oE '\[p[0-9]+\] injected login' dev/run/host-single.log 2>/dev/null | sort -u | wc -l; }
for _ in $(seq 1 30); do
  [ "$(distinct_logins)" -ge 4 ] && break
  sleep 1
done

DISPLAY="$DISP" import -window root dev/run/verify-single.png 2>/dev/null

echo "----- host-single.log -----"
grep -E "layout|wall|injected|WARNING|FATAL" dev/run/host-single.log || true
echo "---------------------------"

fail=0
grep -q "layout=single" dev/run/host-single.log && echo "PASS: single layout resolved" || { echo "FAIL: layout"; fail=1; }
grep -q "wall window shown" dev/run/host-single.log && echo "PASS: wall window" || { echo "FAIL: wall window"; fail=1; }
[ "$(distinct_logins)" -ge 4 ] && echo "PASS: all 4 panels injected login" || { echo "FAIL: only $(distinct_logins)/4 panels logged in"; fail=1; }
[ -s dev/run/verify-single.png ] && echo "PASS: screenshot dev/run/verify-single.png" || { echo "FAIL: no screenshot"; fail=1; }

[ "$fail" -eq 0 ] && echo "=== VERIFY-SINGLE OK ===" || echo "=== VERIFY-SINGLE FAILED ==="
exit "$fail"
