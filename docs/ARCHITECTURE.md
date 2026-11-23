# Architecture

`p2soc` turns a Raspberry Pi 5 (or any mainstream Linux box, x86-64 or ARM) into
a Security-Operations-Center video wall: four web panels in a 2×2 grid, each
auto-logged-in from a local secrets vault, self-healing for 24/7 operation. It
runs on X11 (X.Org or XLibre) and Wayland (cage/labwc), with optional reach
through an SSH jump host, a supervised VPN, or an authenticated outbound proxy.
The Rust executable is the default on source and packaged installations.

## Runtime topology

```
Raspberry Pi 5 (Raspberry Pi OS, desktop session disabled)
┌──────────────────────────────────────────────────────────────────────────┐
│ systemd (system scope)                                                     │
│   ├─ zram (systemd-zram-generator, zstd)   compressed swap, 1 GB headroom  │
│   ├─ vaultwarden.service ───────────────► 127.0.0.1:8222  encrypted vault  │
│   ├─ autossh-tunnel.service ────────────► autossh -L 127.0.0.1:191xx:…     │
│   │                                          user@jump  (per-panel forwards)│
│   └─ forti-vpn.service (root) ──────────► openfortivpn → FortiGate SSL-VPN  │
│                                              login from vault, via pinentry │
│                                                                            │
│   forti-vpn.service runs a SUPERVISOR (soc-wall vpn): classifies          │
│   openfortivpn output, reconnects with backoff, holds ~5 min on auth failure, │
│   Type=notify + watchdog, reports state to `systemctl status` (STATUS=)        │
│                                                                            │
│ getty@tty1 autologin (soc) → start-session.sh dispatcher (per SOC_SESSION) │
│   ├─ x11      → startx → Openbox  (rc.xml tiles WM_CLASS=soc-pN per cell)  │
│   └─ wayland  → cage (one fullscreen grid window) | labwc (generated rules)│
│   └─ autostart/launcher.sh → soc-wall supervise → soc-wall run              │
│        ├─ native Vaultwarden session → short-TTL RAM credential cache    │
│        ├─ engine: webkit  → WebKitWebView (own window, or embedded in the │
│        │      single fullscreen wall); proxy + status overlay; self-heal  │
│        └─ engine: chromium→ chromium --app + CDP (localhost)               │
└──────────────────────────────────────────────────────────────────────────┘
```

Without systemd the same processes run under any init (the launcher and the VPN
supervisor self-restart); only autologin + unit supervision are wired by hand.

## Boot / data flow

1. **getty** auto-logs-in the `soc` user on tty1. `~/.bash_profile` starts the display dispatcher.
2. **Openbox** starts with no panel/menu; `autostart` disables blanking, hides the
   cursor, and runs `launcher.sh`.
3. **launcher.sh** starts `soc-wall with-env supervise`. The launcher resolves
   the site configuration and the supervisor restarts the wall after crashes or
   stalled heartbeats.
4. **`soc-wall run`** performs startup in this order:
   - unlocks the vault, retrying unattended until it is ready;
   - if a VPN is enabled with a `ready_probe`, **polls** it until the
     VPN-side network answers (best-effort) so no window loads a dead route;
   - **polls** each tunnel's local port until it answers (best-effort, timed) so
     no window loads a dead tunnel;
   - creates one window/process per panel, staggered to smooth the RAM spike.
5. For each panel a credential-free **bootstrap script** (`inject/login.js.tmpl`)
   is injected. When it sees the login page it signals the host, which fetches the
   creds just-in-time and evaluates `socLogin({user,pass})`. A `MutationObserver`
   re-triggers login if the session later expires.

## Components

| Component | File(s) | Responsibility |
|---|---|---|
| Config | `soc-core`, `soc-sys::paths` | Parse and validate layouts, panel URLs, VPN and proxy settings. Resolve the active system or per-user config. |
| Vault and secret store | `soc-vault`, `soc-seal` | Native Vaultwarden access, in-memory credential cache, host-bound seal, backup and legacy client compatibility. |
| Browser injection | `soc-web`, `inject/login.js.tmpl` | Shared login, calibration, relogin and keep-alive logic. |
| WebKit and wall UI | `soc-wall/src/gui` | WebKit panels, layout, Settings, lock and tray. |
| Chromium | `soc-web/src/chromium` | Start Chromium app windows, communicate over CDP, recover on exit. |
| Desktop tools | `soc-gui` | Launcher menu, setup wizard, credentials, appearance and error dialogs. |
| Terminal setup | `soc-setup` | Deploy, first boot, validation, repair, credential enrollment and account recovery. |
| Display and watchdog | `soc-sys`, `scripts/start-session.sh`, `scripts/launcher.sh` | X11/Wayland selection, placement rules, hardware profiles, heartbeat and restart. |
| Updates | `soc-sys::update`, `soc-update.timer` | Stage and check a native build, switch releases atomically, watch health and roll back. |
| SSH tunnel | `soc-sys::tunnel`, `scripts/autossh-tunnel.sh` | Pin jump-host keys, validate forwarding arguments and run autossh. |
| VPN | `soc-vpn`, `soc-inode` | Fortinet, OpenVPN, WireGuard and iNode drivers with backoff and systemd notification. |

The crate names are under `rust/crates/`. The release installs one executable
at `/opt/soc-display/bin/soc-wall`. System units and desktop launchers call that
binary through the shell entry points in `scripts/`. The Python compatibility
implementation lives under `kiosk-host/host/`.

## Design rationale (Pi 5, 1 GB)

- **Real floating windows, not iframes.** Login portals send `X-Frame-Options` /
  CSP `frame-ancestors`, so a single page with four iframes shows blank frames.
  Openbox + real browser windows works with any site.
- **WebKitGTK primary, Chromium per-panel fallback.** Memory depends on the
  dashboards, display stack and browser version. Use Chromium where a dashboard
  requires it. See the measured host and process-tree comparison in
  [Performance](PERFORMANCE.md).
- **Native injection, no broker.** Because the host injects creds itself, there is
  no credential service, no localhost port, and creds never reach page-context
  `fetch` — the single biggest attack surface of the "extension + broker" design
  is removed.
- **`-L` local forwards, not SOCKS.** Chromium's proxy is per-profile and awkward
  to scope per-window; `-L` turns each remote panel into a clean
  `http://127.0.0.1:<port>` with zero browser proxy config.
- **Cookies isolate by origin.** The four panels are different `IP:port` origins,
  so a single browser profile keeps their sessions separate — no per-panel
  profiles needed.

## VPN supervisor

openfortivpn has no stable exit codes for "auth failed" vs "network blip", so
`soc-wall vpn` runs it as a child and **classifies its log lines** (exact
strings from openfortivpn 1.24: tunnel-up, two auth-failure variants, cert
validation, closed-connection). The supervisor:

- reconnects with **exponential backoff** on a normal drop;
- on an **auth failure** holds for `SOC_VPN_AUTH_RETRY_DELAY` (default 300 s) —
  rapid retries with a bad password can lock the FortiGate account;
- on a **cert** failure prints the actionable `trusted_cert` fix and holds;
- optionally **health-probes** `ready_probe` while connected and forces a
  reconnect after N consecutive misses (catches a dead-but-connected tunnel);
- speaks the **systemd notify** protocol (`Type=notify`, `READY=1`, `STATUS=…`,
  `WATCHDOG=1`) so `systemctl status forti-vpn` shows live state and a hung
  process is killed and restarted by the watchdog. Fresh vault creds (and OTP)
  are fetched per attempt; the password only ever reaches openfortivpn through
  the pinentry helper.

## Sessions, compositors & layout

`start-session.sh` dispatches on `SOC_SESSION` (`x11` | `wayland` | `auto`):

- **X11** → `startx` → Openbox. `xinitrc` regenerates the placement rules from
  the live `xrandr` resolution, then Openbox forces each `WM_CLASS=soc-pN`
  window into its cell. Works with X.Org **or XLibre** (same `startx`).
- **Wayland** → `wayland-session.sh` picks the lightest compositor: **cage** for
  an all-WebKit wall (the host draws the whole grid in one fullscreen window — no
  WM placement needed), else **labwc** with window rules generated from
  `panels.yaml`. `SOC_COMPOSITOR` overrides the choice (e.g. sway).

`soc-core` chooses `windows` vs `single` from the backend + engines.
The **single-window layout** (`soc-wall/src/gui/wall.rs`) is the portable core: because Wayland
clients can't position their own windows, embedding every WebKit view in one
fullscreen `GtkGrid` needs no window manager at all, so the exact same code path
runs under cage, labwc, sway, Openbox, or a bare Xvfb (which is how CI verifies
it headlessly).

## Outbound proxy

When `proxy.enabled`, WebKit panels share a `WebContext` with a custom
`NetworkProxySettings` (loopback + `ignore_hosts` bypassed); a `proxy: false`
panel gets its own `NO_PROXY` context. Chromium panels get
`--proxy-server`/`--proxy-bypass-list` (host:port only). **Authentication is
vault-backed and in-memory**: WebKit answers the `authenticate` signal, Chromium
answers the CDP `Fetch.authRequired` event, each with credentials fetched
just-in-time from `proxy.vault_item`. The credentials never appear in the proxy
URL, on argv, or on disk; a wrong password is retried a few times then held.

## Resource sizing

The benchmark measures the wall process and its browser descendants on x86-64.
Raspberry Pi sizing also depends on the OS, compositor, Vaultwarden, VPN
clients, dashboard content and zram. The bring-up guide includes checks for
memory pressure and recovery on the actual device. [Performance](PERFORMANCE.md)
