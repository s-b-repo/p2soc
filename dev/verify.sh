#!/usr/bin/env bash
# Automated end-to-end verification on the x86 dev box (headless via Xvfb).
# Brings up the full stack against the dummy panels + dev vault backend and
# asserts: all panels auto-log-in, the tunnel readiness gate works, and a
# screenshot is produced. Exit 0 = pass.
#
# Run:  make verify    (or: bash dev/verify.sh)
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
PY="$ROOT/.venv/bin/python"
DISP="${SOC_TEST_DISPLAY:-:7}"

export HOME="$ROOT/dev/run/home"; mkdir -p "$HOME"
export DISPLAY="$DISP"
export LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
export SOC_VAULT_BACKEND=dev SOC_DEV_VAULT="$ROOT/dev/run/dev-vault.json"
export SOC_PANELS_FILE="config/panels.dev.yaml"
export SOC_READY_TIMEOUT=20 SOC_LAUNCH_STAGGER=1.0
export SOC_CHROMIUM_NO_SANDBOX=1
export XDG_RUNTIME_DIR="$ROOT/dev/run/xdgrt"; mkdir -p "$XDG_RUNTIME_DIR"
rm -rf "$XDG_RUNTIME_DIR/soc-profiles"

mkdir -p dev/run
# ensure the dev vault file exists (dev backend)
if [ ! -f dev/run/dev-vault.json ]; then
  cat > dev/run/dev-vault.json <<'EOF'
{
  "SOC Dev Panel 1": {"username": "viewer1", "password": "devpass1"},
  "SOC Dev Panel 2": {"username": "viewer2", "password": "devpass2"},
  "SOC Dev Panel 3": {"username": "viewer3", "password": "devpass3"},
  "SOC Dev Panel 4": {"username": "viewer4", "password": "devpass4"},
  "SOC Dev VPN": {"username": "vpnuser", "password": "vpnpass"}
}
EOF
fi

pids=()
cleanup(){ kill "${pids[@]}" 2>/dev/null; pkill -f "remote-debugging-port=92" 2>/dev/null; }
trap cleanup EXIT

waitport(){ for _ in $(seq 1 60); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.3; done; return 1; }

echo "[verify] starting Xvfb on $DISP"
timeout 70 Xvfb "$DISP" -screen 0 1920x1080x24 -ac >dev/run/xvfb.log 2>&1 & pids+=($!)
for _ in $(seq 1 40); do xdpyinfo -display "$DISP" >/dev/null 2>&1 && break; sleep 0.3; done

echo "[verify] starting dummy panels"
timeout 70 "$PY" dev/dummy-panels/server.py >dev/run/panels.log 2>&1 & pids+=($!)
waitport 9001 || { echo "FAIL: panels did not start"; exit 1; }

echo "[verify] starting tunnel stand-in 19102 -> 9002"
timeout 70 "$PY" dev/tcp-forward.py 19102 127.0.0.1 9002 >dev/run/fwd.log 2>&1 & pids+=($!)
waitport 19102 || { echo "FAIL: tunnel forward not up"; exit 1; }

echo "[verify] starting kiosk host"
PYTHONPATH=kiosk-host timeout 55 "$PY" -m host.main >dev/run/host.log 2>&1 & pids+=($!)

# give windows time to load + log in (chromium cold start can take ~10s)
distinct_logins(){ grep -oE '\[p[0-9]+\] injected login' dev/run/host.log 2>/dev/null | sort -u | wc -l; }
for _ in $(seq 1 35); do
  if [ "$(distinct_logins)" -ge 4 ] && grep -q 'chromium CDP attached' dev/run/host.log 2>/dev/null; then
    break
  fi
  sleep 1
done

DISPLAY="$DISP" import -window root dev/run/verify.png 2>/dev/null

echo "----- host.log -----"; grep -E "panels|tunnel|injected|chromium|WARNING|FATAL" dev/run/host.log || true
echo "--------------------"

fail=0
logins=$(distinct_logins)
[ "$logins" -ge 4 ] && echo "PASS: all 4 panels injected login" || { echo "FAIL: only $logins/4 panels logged in"; fail=1; }
grep -q "\[p2\] tunnel up" dev/run/host.log && echo "PASS: tunnel readiness gate" || { echo "FAIL: tunnel gate"; fail=1; }
grep -q "chromium CDP attached" dev/run/host.log && echo "PASS: chromium CDP path" || { echo "FAIL: chromium CDP"; fail=1; }
[ -s dev/run/verify.png ] && echo "PASS: screenshot dev/run/verify.png" || { echo "FAIL: no screenshot"; fail=1; }

[ "$fail" -eq 0 ] && echo "=== VERIFY OK ===" || echo "=== VERIFY FAILED ==="
exit "$fail"
