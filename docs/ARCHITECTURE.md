# Architecture

`p2soc` turns a Raspberry Pi 5 (or any mainstream Linux box, x86-64 or ARM) into
a Security-Operations-Center video wall: four web panels in a 2×2 grid, each
auto-logged-in from a local secrets vault, self-healing for 24/7 operation. It
runs on X11 (X.Org or XLibre) and Wayland (cage/labwc), with optional reach
through an SSH jump host, a supervised Fortinet SSL-VPN, and/or an authenticated
outbound proxy.

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
│   forti-vpn.service runs a SUPERVISOR (host/fortivpn.py): classifies          │
│   openfortivpn output, reconnects with backoff, holds ~5 min on auth failure, │
│   Type=notify + watchdog, reports state to `systemctl status` (STATUS=)        │
│                                                                            │
│ getty@tty1 autologin (soc) → start-session.sh dispatcher (per SOC_SESSION) │
│   ├─ x11      → startx → Openbox  (rc.xml tiles WM_CLASS=soc-pN per cell)  │
│   └─ wayland  → cage (one fullscreen grid window) | labwc (generated rules)│
│   └─ autostart/launcher.sh → kiosk host (Python / PyGObject)              │
│        ├─ litebw unlock + sync → read logins into a short-TTL RAM cache    │
│        ├─ engine: webkit  → WebKitWebView (own window, or embedded in the │
│        │      single fullscreen wall); proxy + status overlay; self-heal  │
│        └─ engine: chromium→ chromium --app + CDP (localhost)               │
└──────────────────────────────────────────────────────────────────────────┘
```

Without systemd the same processes run under any init (the launcher and the VPN
supervisor self-restart); only autologin + unit supervision are wired by hand.

## Boot / data flow

1. **getty** auto-logs-in the `soc` user on tty1; `~/.bash_profile` `exec startx`.
2. **Openbox** starts with no panel/menu; `autostart` disables blanking, hides the
   cursor, and runs `launcher.sh`.
3. **launcher.sh** sources `/etc/soc-display/soc.env`, then runs the kiosk host in
   a restart loop (self-heals on crash).
4. The **host** (`kiosk-host/host/main.py`):
   - opens the vault (`litebw unlock` + `sync`) — **required**, retried until ready;
   - if a Fortinet VPN is enabled with a `ready_probe`, **polls** it until the
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
| Config | `kiosk-host/host/config.py`, `config/panels.yaml` | parse panels, derive effective URL + 2×2 geometry |
| Vault | `kiosk-host/host/vault.py` | read creds via `litebw` (default; pure-Python Vaultwarden client) or the legacy `rbw`, or a JSON file (dev); RAM-only TTL cache |
| Injection | `kiosk-host/host/inject.py`, `inject/login.js.tmpl` | render the bootstrap + the just-in-time `socLogin` call (JSON-escaped) |
| WebKit panel | `kiosk-host/host/webkit_panel.py` | WebKitWebView (own window or embedded) + `socCreds` handler, proxy auth, crash-reload, status overlay |
| Chromium panel | `kiosk-host/host/chromium_panel.py` | spawn `chromium --app`, drive login + proxy auth over CDP, respawn on death |
| Single-window wall | `kiosk-host/host/wall.py` | one fullscreen GtkGrid holding every WebKit view (`layout: single`); tracks screen-size changes |
| On-screen config | `kiosk-host/host/configwin.py` | floating PIN-lockable panel to set tile URL/title/vault item live (⚙ / Ctrl+Shift+C); persists to `overrides.json` |
| Look & feel | `kiosk-host/host/style.py` | shared dark CSS + per-panel status cards (connecting/offline/recovering) |
| Perf profile | `kiosk-host/host/perf.py` | detect low-memory boards + ARM GPU → cache model + hw-accel policy; `MemAvailable`/RSS probes for the watchdog |
| Orchestrator | `kiosk-host/host/main.py` | backend/layout resolution, readiness gating, staggered launch, signals, GTK loop; **memory watchdog** (recycle the heaviest panel under sustained `MemAvailable` pressure, with hysteresis + cooldown) |
| Window mgmt (X11) | `openbox/rc.xml.tmpl`, `scripts/gen-openbox-rc.py` | no-panel WM, forced 2×2 placement by WM_CLASS, draggable |
| Window mgmt (Wayland) | `labwc/rc.xml.tmpl`, `scripts/gen-labwc-rc.py` | generated labwc window rules (app_id/title) tile panel windows |
| Tunnel | `scripts/tunnel-args.py`, `scripts/autossh-tunnel.sh` | build `-L` forwards from config, run autossh |
| VPN supervisor | `kiosk-host/host/fortivpn.py`, `kiosk-host/host/vpndrivers.py`, `scripts/forti-vpn-connect.py` | one supervisor for Fortinet/OpenVPN/WireGuard: classify output, reconnect with backoff, auth-lockout protection, sd_notify watchdog; creds via pinentry (Fortinet) or management socket (OpenVPN) |
| Session | `scripts/start-session.sh`, `scripts/wayland-session.sh`, `scripts/xinitrc`, `scripts/launcher.sh`, `systemd/soc-wall.service` | dispatch X11/Wayland per `SOC_SESSION`, pick compositor, start + supervise the wall. Optionally run as a supervised systemd unit (`soc-wall.service`, generated by `setup.py`) with config baked in as `Environment=` (no `soc.env`) and `Restart=always` so a dead session self-recovers |

## Design rationale (Pi 5, 1 GB)

- **Real floating windows, not iframes.** Login portals send `X-Frame-Options` /
  CSP `frame-ancestors`, so a single page with four iframes shows blank frames.
  Openbox + real browser windows works with any site.
- **WebKitGTK primary, Chromium per-panel fallback.** One WebKit process tree is
  ~250–450 MB versus ~600–800 MB for four Chromium renderers — decisive on 1 GB.
  Chromium is opt-in (`engine: chromium`) only for a Chrome-only panel.
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
`host/fortivpn.py` runs it as a child and **classifies its log lines** (exact
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

`config.resolve_layout()` chooses `windows` vs `single` from the backend + engines.
The **single-window layout** (`wall.py`) is the portable core: because Wayland
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

## Approximate RAM budget (1 GB + zram zstd ≈ 2.5×)

| Piece | RAM |
|---|---|
| Base OS (desktop disabled) | ~150 MB |
| Xorg + Openbox | ~60 MB |
| Vaultwarden | ~20–60 MB |
| litebw + autossh | ~15 MB |
| Kiosk host + 3–4 WebKit views | ~350–500 MB |
| **All-WebKit total** | **~600–720 MB (comfortable)** |
| + one Chromium fallback panel | ~850 MB–1.05 GB (tight; zram absorbs it) |
