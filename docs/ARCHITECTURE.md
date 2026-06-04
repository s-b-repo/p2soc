# Architecture

`p2soc` turns a Raspberry Pi 5 into a Security-Operations-Center video wall: four
real, draggable browser windows in a 2×2 grid, each showing a different web
panel, each auto-logged-in from a local secrets vault, with at least one panel
reachable only through an SSH jump host.

## Runtime topology

```
Raspberry Pi 5 (Raspberry Pi OS, desktop session disabled)
┌──────────────────────────────────────────────────────────────────────────┐
│ systemd (system scope)                                                     │
│   ├─ zram (systemd-zram-generator, zstd)   compressed swap, 1 GB headroom  │
│   ├─ vaultwarden.service ───────────────► 127.0.0.1:8222  encrypted vault  │
│   └─ autossh-tunnel.service ────────────► autossh -L 127.0.0.1:191xx:…     │
│                                              user@jump  (per-panel forwards)│
│                                                                            │
│ getty@tty1 autologin (soc) → startx → Openbox (no panel)                   │
│   └─ autostart → launcher.sh → kiosk host (Python / PyGObject)             │
│        ├─ rbw unlock + sync → read the 4 logins into a short-TTL RAM cache │
│        ├─ engine: webkit  → GTK window + WebKitWebView                      │
│        │      native login via the socCreds message handler               │
│        └─ engine: chromium→ chromium --app + CDP (localhost)               │
│               native login via Runtime.evaluate(socLogin)                 │
│   Openbox rc.xml forces each WM_CLASS=soc-pN window into its 2×2 cell      │
└──────────────────────────────────────────────────────────────────────────┘
```

## Boot / data flow

1. **getty** auto-logs-in the `soc` user on tty1; `~/.bash_profile` `exec startx`.
2. **Openbox** starts with no panel/menu; `autostart` disables blanking, hides the
   cursor, and runs `launcher.sh`.
3. **launcher.sh** sources `/etc/soc-display/soc.env`, then runs the kiosk host in
   a restart loop (self-heals on crash).
4. The **host** (`kiosk-host/host/main.py`):
   - opens the vault (`rbw unlock` + `sync`) — **required**, retried until ready;
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
| Vault | `kiosk-host/host/vault.py` | read creds via `rbw` (prod) or a JSON file (dev); RAM-only TTL cache |
| Injection | `kiosk-host/host/inject.py`, `inject/login.js.tmpl` | render the bootstrap + the just-in-time `socLogin` call (JSON-escaped) |
| WebKit panel | `kiosk-host/host/webkit_panel.py` | GTK window + WebKitWebView + `socCreds` message handler |
| Chromium panel | `kiosk-host/host/chromium_panel.py` | spawn `chromium --app`, drive login over CDP on localhost |
| Orchestrator | `kiosk-host/host/main.py` | readiness gating, staggered launch, signals, GTK loop |
| Window mgmt | `openbox/rc.xml.tmpl`, `scripts/gen-openbox-rc.py` | no-panel WM, forced 2×2 placement by WM_CLASS, draggable |
| Tunnel | `scripts/tunnel-args.py`, `scripts/autossh-tunnel.sh` | build `-L` forwards from config, run autossh |
| Session | `scripts/launcher.sh`, `scripts/xinitrc`, `openbox/autostart` | start + supervise the wall inside X |

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

## Approximate RAM budget (1 GB + zram zstd ≈ 2.5×)

| Piece | RAM |
|---|---|
| Base OS (desktop disabled) | ~150 MB |
| Xorg + Openbox | ~60 MB |
| Vaultwarden | ~20–60 MB |
| rbw agent + autossh | ~15 MB |
| Kiosk host + 3–4 WebKit views | ~350–500 MB |
| **All-WebKit total** | **~600–720 MB (comfortable)** |
| + one Chromium fallback panel | ~850 MB–1.05 GB (tight; zram absorbs it) |
