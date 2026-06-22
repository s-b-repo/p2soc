#!/usr/bin/env bash
# Headless end-to-end check of the authenticated-proxy path (Xvfb).
#
# Panel URLs are rewritten to hostnames that DO NOT resolve on this machine
# (p1.soc.test ...); the dev auth-proxy maps any host to 127.0.0.1:<port> but
# only after Basic auth. So a panel can only render + log in if its traffic
# went through the proxy AND the host answered the 407 with the vault creds.
# The tunnel panel (p2, 127.0.0.1) asserts the bypass list still works.
# Run:  make verify-proxy
set -u
cd "$(dirname "$0")/.."
ROOT="$PWD"
PY="$ROOT/.venv/bin/python"
DISP="${SOC_TEST_DISPLAY:-:7}"

export HOME="$ROOT/dev/run/home"; mkdir -p "$HOME"
export DISPLAY="$DISP"
export LIBGL_ALWAYS_SOFTWARE=1 GDK_BACKEND=x11
export SOC_VAULT_BACKEND=dev SOC_DEV_VAULT="$ROOT/dev/run/dev-vault.json"
export SOC_READY_TIMEOUT=20 SOC_LAUNCH_STAGGER=0.5
export SOC_CHROMIUM_NO_SANDBOX=1
export XDG_RUNTIME_DIR="$ROOT/dev/run/xdgrt"; mkdir -p "$XDG_RUNTIME_DIR"
rm -rf "$XDG_RUNTIME_DIR/soc-profiles"

mkdir -p dev/run
# dev config variant: unresolvable hostnames + the auth proxy
"$PY" - <<'EOF'
import json, yaml
c = yaml.safe_load(open("config/panels.dev.yaml"))
for p in c["panels"]:
    if p["mode"] == "direct":
        port = p["url"].split(":")[2].split("/")[0]
        p["url"] = f"http://{p['id']}.soc.test:{port}/login"
c["proxy"] = {"enabled": True, "url": "http://127.0.0.1:3128",
              "vault_item": "SOC Proxy", "ignore_hosts": []}
yaml.safe_dump(c, open("dev/run/panels.proxy.yaml", "w"))

# make sure the dev vault holds the proxy credentials
path = "dev/run/dev-vault.json"
try:
    vault = json.load(open(path))
except FileNotFoundError:
    vault = {}
vault.setdefault("SOC Proxy", {"username": "proxyuser", "password": "proxypass"})
json.dump(vault, open(path, "w"), indent=2)
EOF
export SOC_PANELS_FILE=dev/run/panels.proxy.yaml

pids=()
cleanup(){ kill "${pids[@]}" 2>/dev/null; pkill -f "remote-debugging-port=92" 2>/dev/null; }
trap cleanup EXIT

waitport(){ for _ in $(seq 1 60); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.3; done; return 1; }

echo "[verify-proxy] starting Xvfb on $DISP"
timeout 90 Xvfb "$DISP" -screen 0 1920x1080x24 -ac >dev/run/xvfb.log 2>&1 & pids+=($!)
for _ in $(seq 1 40); do xdpyinfo -display "$DISP" >/dev/null 2>&1 && break; sleep 0.3; done

echo "[verify-proxy] starting dummy panels + tunnel stand-in + auth proxy"
timeout 90 "$PY" dev/dummy-panels/server.py >dev/run/panels.log 2>&1 & pids+=($!)
waitport 9001 || { echo "FAIL: panels did not start"; exit 1; }
timeout 90 "$PY" dev/tcp-forward.py 19102 127.0.0.1 9002 >dev/run/fwd.log 2>&1 & pids+=($!)
waitport 19102 || { echo "FAIL: tunnel forward not up"; exit 1; }
timeout 90 "$PY" dev/auth-proxy.py 3128 proxyuser proxypass >dev/run/proxy.log 2>&1 & pids+=($!)
waitport 3128 || { echo "FAIL: auth proxy not up"; exit 1; }

echo "[verify-proxy] starting kiosk host"
PYTHONPATH=kiosk-host timeout 70 "$PY" -m host.main >dev/run/host-proxy.log 2>&1 & pids+=($!)

distinct_logins(){ grep -oE '\[p[0-9]+\] injected login' dev/run/host-proxy.log 2>/dev/null | sort -u | wc -l; }
for _ in $(seq 1 45); do
  [ "$(distinct_logins)" -ge 4 ] && break
  sleep 1
done

DISPLAY="$DISP" import -window root dev/run/verify-proxy.png 2>/dev/null

echo "----- host-proxy.log -----"
grep -E "proxy|injected|tunnel|WARNING|FATAL" dev/run/host-proxy.log || true
echo "----- proxy.log (counts) -----"
echo "407: $(grep -c '^407 ' dev/run/proxy.log)  AUTH-OK: $(grep -c '^AUTH-OK' dev/run/proxy.log)"
echo "------------------------------"

fail=0
[ "$(distinct_logins)" -ge 4 ] && echo "PASS: all 4 panels injected login (via proxy)" \
  || { echo "FAIL: only $(distinct_logins)/4 panels logged in"; fail=1; }
grep -q "^407 " dev/run/proxy.log && echo "PASS: proxy challenged (407)" \
  || { echo "FAIL: proxy never challenged — auth path not exercised"; fail=1; }
grep -q "^AUTH-OK GET http://p1.soc.test:9001" dev/run/proxy.log \
  && echo "PASS: webkit panel authenticated through the proxy" \
  || { echo "FAIL: no authenticated webkit traffic for p1"; fail=1; }
grep -q "^AUTH-OK GET http://p3.soc.test:9003" dev/run/proxy.log \
  && echo "PASS: chromium panel authenticated through the proxy" \
  || { echo "FAIL: no authenticated chromium traffic for p3"; fail=1; }
grep -q "\[p3\] proxy auth answered" dev/run/host-proxy.log \
  && echo "PASS: chromium CDP answered the auth challenge" \
  || { echo "FAIL: chromium CDP auth handler never fired"; fail=1; }
grep -q "\[p2\] injected login" dev/run/host-proxy.log \
  && echo "PASS: loopback tunnel panel bypassed the proxy" \
  || { echo "FAIL: tunnel panel (bypass list) broke"; fail=1; }
[ -s dev/run/verify-proxy.png ] && echo "PASS: screenshot dev/run/verify-proxy.png" \
  || { echo "FAIL: no screenshot"; fail=1; }

[ "$fail" -eq 0 ] && echo "=== VERIFY-PROXY OK ===" || echo "=== VERIFY-PROXY FAILED ==="
exit "$fail"
