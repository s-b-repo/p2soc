# iNode VPN Client — Packaged Runtime

Self-contained build of the Qt6 iNode Client with a working H3C SSL VPN implementation. This is the **packaged runtime** — the editable source lives at `~/Downloads/Linux/iNodeManager/iNodeClient-Qt/`.

## Layout

```
bin/iNodeClient-Qt      The Qt6 application binary
backends/h3csvpn/       Vendored SSL VPN protocol backend (Python)
scripts/                Privileged helpers (pkexec/polkit)
  inode-svpn-helper     SSL VPN connect/stop (runs h3csvpn, password on stdin)
  inode-dot1x-helper    802.1X (minieap wrapper)
  inode-l2tp-helper     L2TP/IPSec (strongSwan, secrets on stdin)
  inode-ipcfg-helper    Static IP configuration (post-auth)
docs/                   README + PROTOCOLS.md
iNode-VPN.sh            Launch the GUI
svpn-connect.sh         Quick CLI SSL VPN connect (no GUI)
```

## Build & deploy (from source tree)

```bash
# Source is at ~/Downloads/Linux/iNodeManager/iNodeClient-Qt/
cd ~/Downloads/Linux/iNodeManager/iNodeClient-Qt
cmake --build build -j$(nproc)
# Smoke test
QT_QPA_PLATFORM=offscreen ./build/iNodeClient-Qt --version
# Deploy to packaged tree: rm then cp (ETXTBSY if running)
rm ~/Downloads/Linux/iNode-VPN-Client/bin/iNodeClient-Qt
cp build/iNodeClient-Qt ~/Downloads/Linux/iNode-VPN-Client/bin/
```

## Protocols

| Protocol | Status | Backend |
|---|---|---|
| 802.1X / WLAN | Working | minieap / nmcli |
| L2TP/IPSec | Working | strongSwan (secrets on stdin) |
| Portal | Working | subprocess wrapper |
| SSL VPN (H3C) | Working | `backends/h3csvpn` via pkexec helper |
| EAD posture | Implemented (untested vs live iMC) | Native UDP/9019 SEC in `EadProtocol` |
| H3C Portal dialect | Experimental (untested) | Real H3C opcode/attr set in `PortalProtocol` |
| SDP | Experimental | SPA knock (HOTP) + SSL VPN |

## Key facts

- Helper scripts resolved at runtime via `applicationDirPath()/../scripts/<name>`
- UTF-16 string literals in binary — search with `strings -e l`
- SSL VPN password passed on stdin → env var (never argv)
- Live test gateway: `102.134.120.103:3000` (credential-stage blocker unresolved)
