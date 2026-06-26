#!/usr/bin/env bash
# Behavioral check of ALL four VPN backends with fake clients (no real tunnels,
# no root). Drives host/fortivpn.py's Supervisor through each driver and asserts
# the load-line classification, the secure credential paths, and connect/reconnect.
# Run:  make verify-vpn
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
PY="$ROOT/.venv/bin/python"
FAKE="$ROOT/dev/run/vpnverify"; rm -rf "$FAKE"; mkdir -p "$FAKE/run"

# --- fake clients -----------------------------------------------------------
cat > "$FAKE/openfortivpn" <<'PY'
#!/usr/bin/env python3
import os, sys, time, signal
if os.environ.get("FAKE_FORTI_MODE") == "authfail":
    print("ERROR:  Could not authenticate to gateway. Please check the password.", flush=True)
    sys.exit(1)
print("INFO:   Tunnel is up and running.", flush=True)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(0.3)
PY
cat > "$FAKE/openvpn" <<'PY'
#!/usr/bin/env python3
import os, sys, socket, signal, time
a = sys.argv[1:]
if "--management" in a:
    sock = a[a.index("--management")+1]
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try: os.unlink(sock)
    except OSError: pass
    srv.bind(sock); srv.listen(1); conn,_ = srv.accept()
    f = conn.makefile("rw")
    f.write(">PASSWORD:Need 'Auth' username/password\n"); f.flush()
    u=p=None
    for line in f:
        line=line.strip()
        if line.startswith('username "Auth"'): u=line.split(None,2)[2].strip('"')
        elif line.startswith('password "Auth"'): p=line.split(None,2)[2]
        if u and p: break
    open(os.environ["OVPN_MARKER"],"w").write(f"{u}:{p}")
print("Initialization Sequence Completed", flush=True)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(0.3)
PY
cat > "$FAKE/wg-quick" <<'SH'
#!/bin/sh
echo "$1 $2" >> "$WG_MARKER"
[ "$1" = "up" ] && cp "$2" "$WG_CONF_SEEN" 2>/dev/null && : > "$WG_STATE"
[ "$1" = "down" ] && rm -f "$WG_STATE"
exit 0
SH
cat > "$FAKE/wg" <<'SH'
#!/bin/sh
[ -f "$WG_STATE" ] || exit 1
[ "$3" = "latest-handshakes" ] && echo "PEER $(date +%s)"
exit 0
SH
mkdir -p "$FAKE/inode"
cat > "$FAKE/inode/svpn-connect.sh" <<'PY'
#!/usr/bin/env python3
import os, sys, time, signal
open(os.environ["INODE_RUNS"], "a").write("1\n")          # count (re)connect attempts
open(os.environ["INODE_MARKER"], "w").write(
    os.environ.get("H3C_SVPN_PASSWORD", "") + " | argv=" + " ".join(sys.argv[1:]))
print("tunnel up: ip=10.9.9.2 mask=255.255.255.0", flush=True)
fail_after = os.environ.get("INODE_FAIL_AFTER")
if fail_after:                                            # simulate iNode heartbeat death
    time.sleep(float(fail_after))
    print("heartbeat: no response, going offline", flush=True)
    sys.exit(1)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True: time.sleep(0.3)
PY
chmod +x "$FAKE"/openfortivpn "$FAKE"/openvpn "$FAKE"/wg-quick "$FAKE"/wg "$FAKE/inode/svpn-connect.sh"

# vault: fortinet+openvpn creds, and the wireguard .conf (key) in Notes
cat > "$FAKE/vault.json" <<'JSON'
{ "SOC Forti":  {"username":"fortiuser","password":"fortipass"},
  "SOC OVPN":   {"username":"ovpnuser","password":"ovpnpass"},
  "SOC WG":     {"username":"","password":"x",
                 "notes":"[Interface]\nPrivateKey = WGSECRET==\nAddress = 10.9.0.2/32\n"},
  "SOC iNode":  {"username":"inodeuser","password":"inodepass"} }
JSON

export PATH="$FAKE:$PATH" XDG_RUNTIME_DIR="$FAKE/run"
export SOC_VAULT_BACKEND=dev SOC_DEV_VAULT="$FAKE/vault.json"
export SOC_VPN_AUTH_RETRY_DELAY=1 SOC_VPN_BACKOFF_INITIAL=1
export WG_MARKER="$FAKE/wg.calls" WG_STATE="$FAKE/wg.state" WG_CONF_SEEN="$FAKE/seen.conf"
export OVPN_MARKER="$FAKE/ovpn.creds"
export INODE_DIR="$FAKE/inode" INODE_MARKER="$FAKE/inode.cred" INODE_RUNS="$FAKE/inode.runs"

PYTHONPATH=kiosk-host "$PY" - <<'EOF'
import os, sys, threading, time
sys.path.insert(0, "kiosk-host")
from host import fortivpn, vpndrivers

def run(vpn, secs):
    logs = []
    sup = fortivpn.Supervisor(vpn, "/x/pinentry.sh", log=lambda m: logs.append(m))
    t = threading.Thread(target=sup.run, daemon=True); t.start()
    time.sleep(secs); sup.stop_event.set(); sup._terminate_child(); t.join(timeout=5)
    return logs

fails = 0
def check(name, ok):
    global fails
    print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    if not ok: fails += 1

# 1) Fortinet — up + clean stop
logs = run({"enabled":True,"type":"fortinet","gateway":"gw","vault_item":"SOC Forti"}, 1.5)
check("fortinet: tunnel established", any("tunnel established" in l for l in logs))
check("fortinet: clean stop", any(l=="stopped" for l in logs))

# 2) Fortinet — auth failure -> loud banner + long hold (not a tight retry loop)
os.environ["FAKE_FORTI_MODE"] = "authfail"
logs = run({"enabled":True,"type":"fortinet","gateway":"gw","vault_item":"SOC Forti"}, 1.5)
del os.environ["FAKE_FORTI_MODE"]
check("fortinet: auth failure detected + banner",
      any("AUTHENTICATION FAILED" in l for l in logs))

# 3) OpenVPN — username/password injected over the management socket
logs = run({"enabled":True,"type":"openvpn","config":"/x.ovpn","vault_item":"SOC OVPN"}, 2.0)
got = open(os.environ["OVPN_MARKER"]).read() if os.path.exists(os.environ["OVPN_MARKER"]) else ""
check("openvpn: creds injected over mgmt socket (not argv)", got == "ovpnuser:ovpnpass")
check("openvpn: tunnel established", any("tunnel established" in l for l in logs))

# 4) WireGuard — config (with key) materialized from the vault, up + cleaned
open(os.environ["WG_MARKER"],"w").close()
logs = run({"enabled":True,"type":"wireguard","config":"wg0","config_from_vault":True,
            "vault_item":"SOC WG","health_check_interval":1}, 2.0)
seen = open(os.environ["WG_CONF_SEEN"]).read() if os.path.exists(os.environ["WG_CONF_SEEN"]) else ""
check("wireguard: key came from the vault Notes", "WGSECRET==" in seen)
check("wireguard: interface brought up", any("WireGuard interface up" in l for l in logs))
mat = os.path.join(os.environ["XDG_RUNTIME_DIR"],"soc-vpn","wg0.conf")
check("wireguard: transient config cleaned up", not os.path.exists(mat))

# 5) iNode (H3C SSL VPN) — driven via the bundled svpn-connect.sh; password via
#    $H3C_SVPN_PASSWORD (child env, never argv); classified "tunnel up"
logs = run({"enabled":True,"type":"inode","gateway":"vpn.gw","port":3000,
            "vault_item":"SOC iNode","config":os.environ["INODE_DIR"],
            "trusted_cert":"AA:BB:CC"}, 1.5)
m = open(os.environ["INODE_MARKER"]).read() if os.path.exists(os.environ["INODE_MARKER"]) else ""
pw, _, argv = m.partition(" | argv=")
check("inode: tunnel established", any("tunnel established" in l for l in logs))
check("inode: password via $H3C_SVPN_PASSWORD env (not argv)",
      pw == "inodepass" and "inodepass" not in argv)
check("inode: gateway+user+pin on argv",
      "vpn.gw:3000" in argv and "inodeuser" in argv and "--pin-sha256" in argv)
check("inode: clean stop", any(l == "stopped" for l in logs))

# 6) iNode auto-reconnect — the backend's heartbeat death ("going offline") makes
#    it exit; the supervisor must respawn it (same logic as the iNode client)
open(os.environ["INODE_RUNS"], "w").close()
os.environ["INODE_FAIL_AFTER"] = "0.3"
logs = run({"enabled":True,"type":"inode","gateway":"vpn.gw","port":3000,
            "vault_item":"SOC iNode","config":os.environ["INODE_DIR"],
            "trusted_cert":"AA:BB:CC"}, 2.6)
os.environ.pop("INODE_FAIL_AFTER", None)
runs = sum(1 for _ in open(os.environ["INODE_RUNS"])) if os.path.exists(os.environ["INODE_RUNS"]) else 0
check("inode: auto-reconnects after heartbeat death (>=2 attempts)", runs >= 2)
check("inode: drop classified + reconnect logged", any("reconnecting" in l for l in logs))

# 7) MULTI-VPN MANAGER — drive host/vpnmanager.py over 2-3 distinct-named,
#    mixed-type entries with the SAME fakes. Assert: one supervisor per ENABLED
#    entry, distinct names, each connects + reconnects independently, the split-
#    tunnel routing coercion (only the owner keeps the default route), the wg
#    0.0.0.0/0 guard, and a full teardown.
from host import vpnmanager, vpnstatus

print()
print("--- multi-VPN manager ---")

# distinct names, mixed types; one disabled (must be skipped); 'corp' owns route
vpns = [
    {"name":"corp","enabled":True,"type":"fortinet","gateway":"gw","vault_item":"SOC Forti",
     "default_route":True,"set_routes":True,"half_internet_routes":True},
    {"name":"lab","enabled":True,"type":"openvpn","config":"/x.ovpn","vault_item":"SOC OVPN",
     "set_routes":True},
    {"name":"dmz","enabled":True,"type":"inode","gateway":"vpn.gw","port":3000,
     "vault_item":"SOC iNode","config":os.environ["INODE_DIR"],"trusted_cert":"AA:BB:CC"},
    {"name":"off","enabled":False,"type":"fortinet","gateway":"gw","vault_item":"SOC Forti"},
]
mlogs = []
mgr = vpnmanager.VpnManager(vpns, "/x/pinentry.sh", log=lambda m: mlogs.append(m))

# only the 3 enabled entries are prepared, with distinct names
check("manager: one supervisor per ENABLED entry (3, disabled skipped)",
      mgr.count == 3 and set(mgr.names) == {"corp","lab","dmz"})

# routing coercion happened at _prepare: the non-owner openvpn 'lab' was forced
# split-tunnel (set_routes False); the owner 'corp' keeps its full-tunnel config.
ent = {name: e for name, e, owner in mgr._entries}
owner = {name: owner for name, e, owner in mgr._entries}
check("manager: exactly one default-route owner (corp)",
      owner["corp"] is True and owner["lab"] is False and owner["dmz"] is False)
check("manager: non-owner openvpn coerced split-tunnel (set_routes False)",
      ent["lab"].get("set_routes") is False)
check("manager: owner fortinet keeps full-tunnel (set_routes True)",
      ent["corp"].get("set_routes") is True)

mgr.start()
time.sleep(2.0)
states = mgr.states()
check("manager: per-name states cover every enabled VPN",
      set(states) == {"corp","lab","dmz"})
# every supervisor line is attributable to a name
check("manager: logs tagged [vpn:<name>] per supervisor",
      any("[vpn:corp]" in l for l in mlogs)
      and any("[vpn:lab]" in l for l in mlogs)
      and any("[vpn:dmz]" in l for l in mlogs))
check("manager: each tunnel established independently",
      sum(1 for l in mlogs if "tunnel established" in l) >= 3)

mgr.stop()
# all three threads joined, supervisor table cleared
alive = [t for t in threading.enumerate() if t.name.startswith("vpn:")]
check("manager: clean teardown — no VPN threads left", not alive)
check("manager: stop() cleared the supervisor table", mgr._supers == {})

# 8) ROUTING SAFETY — two default_route:true entries must NEVER both get the
#    default route. The manager refuses ALL of them rather than let two fight.
two_owners = [
    {"name":"a","enabled":True,"type":"openvpn","config":"/a.ovpn","default_route":True,"set_routes":True},
    {"name":"b","enabled":True,"type":"openvpn","config":"/b.ovpn","default_route":True,"set_routes":True},
]
olog = []
mgr2 = vpnmanager.VpnManager(two_owners, "/x/pinentry.sh", log=lambda m: olog.append(m))
e2 = {name: e for name, e, owner in mgr2._entries}
o2 = {name: owner for name, e, owner in mgr2._entries}
check("manager: two default_route claims -> NONE owns it (refused)",
      o2["a"] is False and o2["b"] is False)
check("manager: both coerced split-tunnel when route is contested",
      e2["a"].get("set_routes") is False and e2["b"].get("set_routes") is False)
check("manager: refusal is logged loudly",
      any("multiple VPNs claim default_route" in l for l in olog))

# 9) WireGuard 0.0.0.0/0 GUARD — a non-owner wg .conf carrying a catch-all
#    AllowedIPs must be stripped at materialize so it can't hijack the route.
import json, tempfile
vault = json.load(open(os.environ["SOC_DEV_VAULT"]))
vault["WG Catchall"] = {"username":"","password":"x",
    "notes":"[Interface]\nPrivateKey = K==\nAddress = 10.9.0.2/32\n[Peer]\nAllowedIPs = 0.0.0.0/0, 10.50.0.0/16\n"}
json.dump(vault, open(os.environ["SOC_DEV_VAULT"],"w"))
try: os.unlink(os.environ["WG_CONF_SEEN"])
except OSError: pass
wgvpns = [
    {"name":"owner","enabled":True,"type":"fortinet","gateway":"gw","vault_item":"SOC Forti","default_route":True},
    {"name":"wgnon","enabled":True,"type":"wireguard","config":"wgx","config_from_vault":True,
     "vault_item":"WG Catchall","health_check_interval":1},
]
wlog = []
mgrw = vpnmanager.VpnManager(wgvpns, "/x/pinentry.sh", log=lambda m: wlog.append(m))
mgrw.start(); time.sleep(2.0); mgrw.stop()
seen = open(os.environ["WG_CONF_SEEN"]).read() if os.path.exists(os.environ["WG_CONF_SEEN"]) else ""
check("manager: non-owner wg catch-all AllowedIPs stripped (no 0.0.0.0/0)",
      "0.0.0.0/0" not in seen and "10.50.0.0/16" in seen)
check("manager: wg catch-all refusal logged",
      any("REFUSED a catch-all" in l for l in wlog))

print()
print("=== VERIFY-VPN OK ===" if fails==0 else f"=== VERIFY-VPN FAILED ({fails}) ===")
sys.exit(1 if fails else 0)
EOF