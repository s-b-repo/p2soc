# iNode Client — Qt Edition

A Qt6 / KF6-native, KDE-friendly reimplementation of the H3C iNode authentication client. Feature-matched against the original where it matters, without the DLP / DAM / posture-agent baggage.

## Status

### Protocols

| Protocol | Status | Backend |
|---|---|---|
| **802.1X** (wired HC-CHAPv2) | ✅ Working | `minieap` (preferred) or `mentohust` subprocess, full rjv3 controls |
| **WLAN** (wireless 802.1X) | ✅ Working | `nmcli` for association, then the 802.1X supplicant |
| **Portal v2** (GB/T 28181) | ✅ Working | Native UDP client with MD5-keyed checksum, keep-alive |
| **L2TP/IPSec** | ✅ Working (RFC-compliant servers) | `strongswan` + `xl2tpd` via polkit helper |
| **H3C Portal (proprietary dialect)** | 🧪 Experimental (faithful framing, untested vs live H3C) | Native UDP, H3C opcode space + attributes, MD5 authenticator |
| **SSL VPN** (H3C SVPN, "V7") | ✅ Working (auth + tunnel) | bundled `h3csvpn` clean-room backend via `inode-svpn-helper` |
| **EAD** (posture check) | 🧪 Standalone SEC posture implemented (untested vs live iMC); SSL-VPN host-check ✅ | Native UDP/9019, keyed-MD5 SEC packets |
| **SDP** | 🧪 Experimental (SPA knock + SSL VPN) | `h3csvpn` SPA knock (HOTP) then the SSL VPN flow |

### Client surface — parity with the original

| Feature | Original client | Qt edition |
|---|---|---|
| Profile list + per-scenario connections | ✅ | ✅ |
| Secure credential storage | ✅ (custom keystore) | ✅ (KWallet → freedesktop Secret Service → obfuscated fallback) |
| Auto-connect on startup | ✅ | ✅ (per-profile flag) |
| Auto-reconnect with backoff | ❌ | ✅ (per-profile, capped retries) |
| System tray icon + state badges | ✅ | ✅ (QSystemTrayIcon + desktop notifications) |
| Minimize to tray on close | ✅ | ✅ (togglable in Preferences) |
| Live connection statistics (iface/IP/gateway/bytes/uptime) | ✅ | ✅ |
| DHCP renew on demand (mirrors `renew.ps`) | ✅ | ✅ (`nmcli` first, falls back to `dhclient`) |
| IP mode per profile (Inherit / DHCP / Static) | ✅ | ✅ (applied post-auth for 802.1X/WLAN via `inode-ipcfg-helper`) |
| Log panel + save log | ✅ | ✅ |
| Rotating file log | ✅ (`log/iNodeSetup*.log`) | ✅ (`$XDG_DATA_HOME/iNodeClient-Qt/logs/`) |
| Themes / skins | ✅ (aero / brightness / star) | ✅ (four stylesheets; modern dark **Mullvad** theme is the default) |
| English / Simplified Chinese / Japanese | ✅ | ✅ (Qt tr + `.ts` scaffolds) |
| Import existing `iNodeCustom.xml` / `locations.xml` | — | ✅ (File → Import from iNode install…) |
| CLI mode (`--connect / --disconnect / --status / --list-profiles`) | ❌ | ✅ |
| Polkit helper for privileged ops | ❌ (ran as root) | ✅ (`inode-{l2tp,dot1x,svpn,ipcfg}-helper`) |
| Bundled OpenSSL 1.1 shipped in-tree | ❌ (security liability) | Uses system SSL stack |
| Posture agent (EAD blob signer) | ✅ | ✗ — deliberately absent |
| DLP / DAM / TRLD / VNC | ✅ (mandatory) | ✗ — out of scope |

Experimental protocols (🧪) register in the UI and attempt a real, wire-faithful connection; where a deployment-specific detail is still unknown they log an honest warning rather than faking success. See [`docs/PROTOCOLS.md`](docs/PROTOCOLS.md) for what is verified vs. unconfirmed per protocol.

## Why this exists

The original H3C iNode client (`iNodeClient`, ~71 MB, Qt5, x86-64 only) is a closed-source Linux binary that:

- Only ships for Ubuntu 18–21, CentOS, Kylin, UOS, Deepin — explicitly *not* Kali, Fedora 30+, Arch, openSUSE, ARM, etc.
- Hasn't been meaningfully updated in years; bundles ancient OpenSSL 1.1.
- Pulls in DAM (USB-storage blocker), DLP (TRLD), and ESM (posture agent) components that are unwelcome on a user-owned laptop.

A Qt6/KF6 reimplementation that speaks *enough* of the wire protocol to connect is what this project aims for.

## Build

```sh
sudo apt install qt6-base-dev libqt6-xml-dev cmake g++    # or the equivalent
# Optional, for secure credential storage + KDE integration:
sudo apt install libkf6wallet-dev libkf6config-dev libkf6i18n-dev libkf6coreaddons-dev
# Optional, for .ts → .qm translation compilation:
sudo apt install qt6-tools-dev qt6-tools-dev-tools

cd iNodeClient-Qt
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
./build/iNodeClient-Qt
```

## Runtime dependencies

| Feature | Required |
|---|---|
| 802.1X | `minieap` (preferred) or `mentohust` in `$PATH`. Install from your distro or build from [github.com/updateing/minieap](https://github.com/updateing/minieap). |
| WLAN | `NetworkManager` (for `nmcli`) + the 802.1X prereq above. |
| L2TP/IPSec | `strongswan`, `xl2tpd`, `ppp`, `polkit`. |
| Portal v2 | None — pure Qt UDP. |
| SSL VPN | `python3` (stdlib); `tesseract` for CAPTCHA OCR; `polkit`/`pkexec` for the TUN tunnel. Optional `python3-defusedxml`, `python3-cryptography`. |
| DHCP renew | `nmcli` (preferred), otherwise `dhclient`. |
| Secure credentials | Any of: KWallet (`kwalletd6`) **or** a freedesktop Secret Service daemon — `gnome-keyring`, `ksecretd`, KeePassXC, … (`libsecret-1.so.0`, loaded at runtime). Without any keyring, passwords fall back to an obfuscated QSettings store. |

## Installation

```sh
sudo cmake --install build
```

This installs:
- `/usr/bin/iNodeClient-Qt`
- `/usr/libexec/iNodeClient-Qt/{inode-l2tp-helper,inode-dot1x-helper,inode-svpn-helper,inode-ipcfg-helper}`
- `/usr/share/polkit-1/actions/org.inode.ClientQt.policy`
- `/usr/share/applications/org.inode.ClientQt.desktop`
- `/usr/share/icons/hicolor/scalable/apps/org.inode.ClientQt.svg`

The helpers are invoked via `pkexec` when the GUI needs root (raw sockets for 802.1X; IPSec/xl2tpd config). The GUI itself never runs privileged.

## Importing from an existing iNode install

If the original `iNodeClient` is installed at `/opt/apps/com.client.inode.amd/files/`, use **File → Import from iNode install…** to pull scenarios from `custom/clientfiles/locations.xml` and EAD defaults from `custom/iNodeCustom.xml`. You'll still need to enter credentials.

## Command-line usage

```sh
iNodeClient-Qt --list-profiles               # print names + protocols
iNodeClient-Qt --connect "Office 802.1X"      # open + connect to named profile
iNodeClient-Qt --disconnect                   # tear down the active session
iNodeClient-Qt --minimized                    # start hidden in tray (for autostart)
```

## Architecture

```
src/
├── main.cpp                      app entry, CLI, auto-connect
├── MainWindow.{h,cpp}            profile list + connect/disconnect UI + log pane + tray wiring
├── core/
│   ├── AutoReconnect.{h,cpp}     exponential-backoff reconnect scheduler
│   ├── ConnectionStats.h         live-connection data struct
│   ├── CredentialStore.{h,cpp}   KWallet (preferred) / scrambled QSettings fallback
│   ├── CustomXmlImporter.{h,cpp} reads legacy iNodeCustom.xml + locations.xml
│   ├── Dhcp.{h,cpp}              mirrors renew.ps
│   ├── InterfaceDiscovery.{h,cpp} wired/wireless interface enumeration
│   ├── IpConfigurator.{h,cpp}    applies per-profile IP mode (static/DHCP) post-auth via inode-ipcfg-helper
│   ├── LogFile.{h,cpp}           rotating file sink
│   ├── Logger.{h,cpp}            single-channel timestamped log signal w/ levels
│   ├── NetUtil.{h,cpp}           /proc/net helpers (IP, gateway, byte counters)
│   ├── Profile.{h,cpp}           per-profile data model
│   ├── ProfileStore.{h,cpp}      JSON-backed profile persistence
│   ├── Protocol.{h,cpp}          IProtocol interface + state + stats
│   ├── ProtocolFactory.{h,cpp}   kind → IProtocol dispatcher
│   └── Settings.{h,cpp}          app-wide user preferences
├── protocols/
│   ├── Dot1xProtocol.{h,cpp}     minieap/mentohust subprocess wrapper w/ rjv3 options
│   ├── EadProtocol.{h,cpp}       stub
│   ├── L2tpIpsecProtocol.{h,cpp} strongswan + xl2tpd via polkit helper (secrets on stdin)
│   ├── PortalProtocol.{h,cpp}    Portal v2 UDP client with keep-alive
│   ├── SslVpnProtocol.{h,cpp}    drives the bundled h3csvpn backend via inode-svpn-helper
│   └── WlanProtocol.{h,cpp}      nmcli-assoc + 802.1X chain
└── ui/
    ├── LogPane.{h,cpp}           log widget with clear/save actions
    ├── ProfileEditor.{h,cpp}     tabbed add/edit dialog
    ├── SettingsDialog.{h,cpp}    preferences
    ├── StatsPane.{h,cpp}         live statistics strip
    ├── ThemeManager.{h,cpp}      Aero / Brightness / Star stylesheet switching
    └── TrayIcon.{h,cpp}          QSystemTrayIcon wrapper
```

The protocol surface (`IProtocol`) is deliberately small so each of the stub protocols can be replaced with a real implementation without touching the UI. Each protocol plugin emits `stateChanged`, `statsUpdated`, `logLine`, and `errorOccurred`; the main window consumes those signals.

## What "fully compatible" means here

- **Connection-compatible** against RFC-compliant L2TP/IPSec servers, standard-conforming Portal v2 (CMCC/GB/T 28181) servers, and campus/enterprise 802.1X deployments using the HC-CHAPv2 variant that `minieap`/`mentohust` implement.
- **Functional parity** (auto-connect, auto-reconnect, tray, themes, stats, DHCP renew, log rotation, CLI) with the original client.
- **SSL VPN (H3C SVPN "V7")** via the bundled `h3csvpn` backend — a clean-room
  implementation reverse-engineered from the unstripped Linux iNode 7.3 client
  and validated against a live `SSLVPN-Gateway/7.0` (XML-over-HTTPS auth,
  OCR-defeated CAPTCHA, SMS/challenge 2FA, `NET_EXTEND` tunnel, TUN/routes/DNS).
  Defaults to an **enterprise split tunnel**: only the gateway's own subnets are
  routed through the VPN, so general internet traffic stays on the local link.
- **Experimental, faithful-but-unverified** for H3C's proprietary Portal dialect
  and the standalone iMC EAD (SEC) posture protocol — both fully reverse-
  engineered from the original client's libraries and implemented to match the
  wire format byte-for-byte, but **untested against a live H3C Portal / iMC EIA
  server** (we have none). See [`docs/PROTOCOLS.md`](docs/PROTOCOLS.md). Captures
  / PRs from anyone with such a deployment are very welcome.

## License — fully free / open source

Licensed **GPL-3.0-or-later** (full text in [`LICENSE`](LICENSE)). This repository is
**100% FOSS** and self-contained:

- All Qt/KF6 code is original.
- The SSL VPN backend (`backends/h3csvpn/`) is a **clean-room** pure-Python
  reimplementation — no decompiled or vendor code.
- **No proprietary H3C binaries are included or redistributed** (they are
  `.gitignore`d). The app links none of them at build or runtime; it speaks the
  protocols over the wire instead.
- `docs/PROTOCOLS.md` documents the wire formats and constants recovered by
  reverse-engineering for **interoperability** — protocol facts, not vendor code.
