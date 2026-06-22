# Configuration

Everything about the wall lives in **`config/panels.yaml`** (deployed to
`/etc/soc-display/panels.yaml`). The kiosk host reads it to decide what to render,
where, how to log in, and how to keep the session alive.

## `display`

```yaml
display:
  auto: true        # detect resolution from xrandr/monitor at launch
  width: 1920       # used when auto: false (or as a fallback)
  height: 1080
  cols: 2           # grid columns
  rows: 2           # grid rows
  gap: 0            # px between cells (0 = seamless)
  layout: auto      # auto | windows | single
```

Cell geometry is computed as `(width - gap*(cols-1)) / cols` × `(height - gap*(rows-1)) / rows`.

**`layout`** decides how panels are placed:

| `layout` | What it does | Works on |
|---|---|---|
| `windows` | one OS window per panel; the WM (Openbox/labwc) tiles them into cells | X11 always; Wayland via generated labwc rules |
| `single` | every WebKit panel embedded in **one** fullscreen grid window — no window manager placement needed | every compositor (cage/labwc/sway/Openbox/Xvfb); **WebKit only** |
| `auto` (default) | `single` on Wayland when all panels are `engine: webkit`, else `windows` | — |

`single` is the most robust option and the reason the wall runs unchanged under
a bare `cage`. It cannot host `engine: chromium` panels (Chromium is a separate
OS process); config validation rejects that combination.

## `panels[]`

```yaml
panels:
  - id: p1                      # short id; window class = soc-p1
    engine: webkit              # webkit (light, default) | chromium (per-panel fallback)
    grid: [0, 0]                # [col, row]; [0,0]=top-left, [1,1]=bottom-right
    mode: direct                # direct | tunnel
    url: "http://10.0.0.5:3000/login"
    vault_item: "SOC Panel 1"   # Vaultwarden login item name (exact match)
    selectors:
      user:   "#username"       # CSS selector for the username field
      pass:   "#password"       # CSS selector for the password field
      submit: "button[type=submit]"   # selector for the submit button (optional)
    login_marker: "#password"   # selector present ONLY on the login page
    keepalive:
      strategy: reload          # reload | click | xhr | none
      intervalSec: 600
```

### Tunneled panels

For a panel reachable only through the SSH jump host, use `mode: tunnel`:

```yaml
  - id: p3
    engine: chromium
    grid: [0, 1]
    mode: tunnel
    tunnel:
      local_port: 19103         # autossh -L 127.0.0.1:19103:remote_host:remote_port
      remote_host: 10.20.0.7
      remote_port: 8443
    path: "/login"              # path on the local side of the tunnel
    scheme: "http"              # http | https (local side)
    vault_item: "SOC Panel 3"
    selectors: { user: "#user", pass: "#pw", submit: "#submit" }
    login_marker: "#pw"
    keepalive: { strategy: reload, intervalSec: 900 }
```

The host builds `effective_url = http://127.0.0.1:19103/login` and waits for that
port before opening the window.

### Optional per-panel keys

| Key | Default | Meaning |
|---|---|---|
| `title` | the `id` | display name (shown on the status card + on-screen config) |
| `url` | — | for `mode: direct`; **may be omitted** — the tile then shows a "not configured" card until a URL is set (in YAML or at the glass) |
| `vault_item` | — | the Vaultwarden login to auto-fill this panel; **omit for a display-only tile** (no auto-login). When set, `selectors` are required |
| `allow_insecure` | `false` | accept a self-signed TLS cert for this panel (trusted LAN only) |
| `allow_media` | `false` | keep WebGL / WebAudio / HTML5 media enabled (off by default to save RAM/GPU on 1 GB boards) |

So the minimum panel is just `{id, grid}` (a blank, configurable tile); add `url`
to display a page, and `vault_item` + `selectors` to auto-log-in.

### Auto-login & the sign-in popup

Each panel auto-logs-in: a credential-free bootstrap detects the login form and
the host fills it with the credentials for that panel's `vault_item` (the page
DOM is the only place the password lands, at submit time). What's automatic:

- **No selectors needed for standard forms.** If `selectors` aren't set, the
  bootstrap finds the page's password field (and the username field before it)
  heuristically — so a tile set at the glass logs in to most login pages with no
  per-site config. Set `selectors` only for unusual forms.
- **Domain memory.** When a panel with a `vault_item` logs in to an origin
  (`host:port`), that origin is remembered (`domain_logins.json`, names only).
  Point *another* panel at the same origin without a `vault_item` and it reuses
  the remembered login automatically. Different ports are different origins — a
  login is never reused across them.
- **Sign-in popup.** If a login form appears and there's **no** saved login, or
  auto-login keeps failing (wrong/expired creds, 3 tries), the panel shows a
  small in-page banner — *"Sign-in needed… open Settings (⚙) to add a login, or
  log in here"* — so an operator can finish manually without losing the wall.

### On-screen configuration (⚙)

The wall has a built-in config panel — click the **gear** in the **top bar** or
press **Ctrl+Shift+C** (the bar stays above the panels, so it's reachable even
when a tile is showing a full page). Per tile you can set the **URL**, a **title**,
and the **vault login** (the Vaultwarden item that auto-fills it). Changes apply
live and are saved to `~/.config/soc-wall/overrides.json` (override the location
with `SOC_STATE_DIR`), so they reload on the next start and layer on top of
`panels.yaml`. An optional **PIN lock** (set it under "Security — lock PIN")
gates the panel; the PIN is stored only as a salted SHA-256 hash. This lets you
ship a wall with blank tiles and point them at real tools at the glass — no SSH,
no file editing.

The panel is **tabbed**: **Panels** (per-tile URL/title/vault/engine + advanced
selectors), **Credentials** (store a panel/VPN/proxy login's username+password
straight into Vaultwarden), **VPN** (pick the type — fortinet/openvpn/wireguard/
iNode — and its gateway, vault item, config, domain, cert pin, ready-probe; Apply
pushes it into the vault config note and restarts the VPN service), **Display**
(layout/gap), and **Status**. So the whole wall — panels, credentials *and* the
VPN — is configurable at the glass, with config + creds stored in the vault.

## `tunnel`

```yaml
tunnel:
  enabled: true
  jump_host: "tunneluser@jump.example.net"
  identity: "/etc/soc-display/keys/tunnel_ed25519"
  extra_forwards: []            # optional extra "127.0.0.1:lport:rhost:rport" strings
```

`-L` forwards are derived automatically from every `mode: tunnel` panel.

## `vpn` (Fortinet, OpenVPN, WireGuard, or iNode)

For panels that live on a network reached through a VPN, enable the `vpn`
section. One supervised tunnel is brought up by `forti-vpn.service` (root);
panels behind it then use plain `mode: direct` with their real IPs. Pick the
backend with **`type`** (default `fortinet`):

| `type` | Client | Key fields | Credentials |
|---|---|---|---|
| `fortinet` (default) | openfortivpn | `gateway`, `port`, `vault_item`, `trusted_cert` | FortiGate user+pass from the vault, via pinentry |
| `openvpn` | openvpn | `config` (`.ovpn` path), optional `vault_item` | user+pass over the OpenVPN management socket; or certificate-only |
| `wireguard` | wg-quick | `config` (`.conf` path or interface name) | keys in the `.conf` (no interactive login) |
| `inode` | H3C iNode SSL VPN (**bundled** in `vendor/iNode-VPN-Client`) | `gateway`, `port`, `vault_item`, optional `config` (defaults to the bundled client), `domain`, `trusted_cert`/`insecure` | SSL-VPN user+pass from the vault, via `$H3C_SVPN_PASSWORD` (never argv) |

```yaml
# OpenVPN (username/password auth — creds injected over the management socket):
vpn: { enabled: true, type: openvpn, config: "/etc/openvpn/soc.ovpn",
       vault_item: "SOC OpenVPN", ready_probe: "10.50.0.5:443" }

# WireGuard (keys live in the .conf — chmod 0600 it):
vpn: { enabled: true, type: wireguard, config: "/etc/wireguard/wg0.conf",
       ready_probe: "10.50.0.5:443", health_check_interval: 30 }

# iNode (H3C SSL VPN — the client is BUNDLED in vendor/iNode-VPN-Client, so no
# `config` is needed; set it only to use a client elsewhere. Needs tesseract for
# the gateway CAPTCHA and root for the TUN, which the service has):
vpn: { enabled: true, type: inode, gateway: "vpn.example.com", port: 3000,
       vault_item: "SOC iNode VPN", domain: "system",
       trusted_cert: "AA:BB:CC:...", ready_probe: "10.50.0.5:443" }
```

All four share the supervisor: backoff on drops, a long hold on auth/cert
failures, the systemd watchdog, and the `ready_probe` health check (which forces
a reconnect when the tunnel goes stale — for WireGuard it falls back to the
peer's last handshake age when no `ready_probe` is set). `make vpn-check`
dry-runs any type without connecting; `make verify-vpn` behaviorally tests all
four with fake clients. iNode self-detects a dead tunnel via its keepalive
heartbeat (~30 s × 5 misses), a forced log-off, or a socket close and exits, so
the supervisor reconnects it automatically — no `ready_probe` required.

**Keys in the vault, not on disk** (`config_from_vault: true`). By default the
OpenVPN `.ovpn` / WireGuard `.conf` lives in a file (which holds the client
cert/key). Set `config_from_vault: true` and the supervisor reads the whole
profile from the **Notes** field of `vault_item`, writes it to a transient
`0600` file in a `0700` dir only while connecting, and deletes it on disconnect
— so the private key lives in Vaultwarden:

```yaml
vpn: { enabled: true, type: wireguard, config: "wg0",   # config = interface name
       config_from_vault: true, vault_item: "SOC WireGuard" }   # Notes = the .conf
```

**On-wall status.** The wall shows a **VPN pill** at the top — `online` (green),
`offline` (red), or `not configured` — updated from `ready_probe` (or the tunnel
interface). Click it to re-check / request a reconnect. It is most accurate when
`ready_probe` is set.

The rest of this section covers the **Fortinet** backend. It runs
[openfortivpn](https://github.com/adrienverge/openfortivpn) as root, logs in with
the FortiGate **username + password stored in the vault** (`vault_item`), and
brings up the route.

```yaml
vpn:
  enabled: true
  gateway: "vpn.example.com"        # FortiGate SSL-VPN host
  port: 443
  vault_item: "SOC FortiGate VPN"   # Vaultwarden login: FortiGate user + password
  trusted_cert: ""                  # sha256 digest to pin the gateway cert (recommended)
  realm: ""                         # FortiGate realm, if your gateway uses one
  set_routes: true                  # accept routes pushed by the gateway
  set_dns: false                    # usually keep the local resolver
  half_internet_routes: false       # true to avoid replacing the default route
  persistent: 0                     # in-process reconnect interval (s); 0 = recommended
  otp_from_vault: false             # true: pull a TOTP from the vault item (rbw code)
  ready_probe: "10.50.0.5:443"      # optional host:port the host waits on before
                                    # opening VPN-side panels (best-effort, non-fatal)
  health_check_interval: 0          # s between liveness probes while connected (0=off)
  health_check_failures: 3          # consecutive misses before forcing a reconnect
  extra_args: []                    # any extra openfortivpn flags, e.g. ["-v"]
```

**Supervised, not fire-and-forget.** `forti-vpn.service` runs a supervisor
(`host/fortivpn.py`) that classifies openfortivpn's output and reconnects with
exponential backoff. Keep **`persistent: 0`** so the supervisor owns reconnects:
on an **auth failure** it holds for `SOC_VPN_AUTH_RETRY_DELAY` (default 300 s)
instead of hammering the gateway — rapid retries with a bad password can **lock
the FortiGate account**. A `persistent > 0` instead lets openfortivpn itself
reconnect blindly every N seconds (no auth-aware backoff). The supervisor reports
live state to `systemctl status forti-vpn` (the `STATUS=` line) and logs
classified errors to `journalctl -u forti-vpn`.

**Liveness.** Set `health_check_interval` (with a `ready_probe`) to catch the
"connected but dead tunnel" failure mode: the supervisor probes `ready_probe`
every N seconds and forces a reconnect after `health_check_failures` consecutive
misses.

How the password stays safe: the supervisor reads the FortiGate password from the
vault and hands it to openfortivpn through a **pinentry helper**
(`scripts/forti-pinentry.sh`), exactly like `rbw` is unlocked — so it is **never
on the command line and never written to disk**. Only the gateway, username, and
routing flags are visible in the process list.

**Pin the cert.** Get the digest from the first connection attempt's error, or:

```bash
openssl s_client -connect vpn.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr A-Z a-z
```

**Routing care.** `set_routes: true` accepts whatever routes the gateway pushes;
if the gateway pushes a default route it can pull *all* traffic (including your
LAN SSH path) over the VPN. Use `half_internet_routes: true` or `set_routes: false`
to keep your own default route, and `set_dns: false` to keep the local resolver.

Verify the wiring without a real FortiGate (resolves the vault creds and prints
the command it would run, but does not connect):

```bash
make vpn-check
```

## `proxy` (outbound HTTP(S)/SOCKS proxy)

To route the panel browsers through a corporate proxy, enable the `proxy`
section. It applies to every panel by default; a panel can opt out with
`proxy: false` (it then connects directly).

```yaml
proxy:
  enabled: true
  url: "http://proxy.corp:3128"     # http | https | socks5 ://host:port — NO credentials
  vault_item: "SOC Proxy"           # vault login with the proxy user+password (blank = no auth)
  ignore_hosts: ["*.corp.lan"]      # extra hosts to bypass (loopback is always bypassed)
```

**Authentication is vault-backed and in-memory.** If `vault_item` is set, the
host answers the proxy's `407` challenge with the username/password from that
vault login — WebKit via the `authenticate` signal, Chromium via the DevTools
`Fetch.authRequired` event. The credentials are **never** placed in the proxy
URL, on a command line, or on disk. Only `--proxy-server=host:port` (no userinfo)
is ever visible in the process list. A bad password is retried a few times and
then held, so a wrong vault entry can't lock out the proxy account.

**Loopback always bypasses the proxy** (`localhost`, `127.0.0.1`, `::1`), so SSH
tunnels, the Chromium CDP channel, and the local Vaultwarden keep working; add
internal hosts/domains to `ignore_hosts`. Per-panel `proxy: false` is useful for
a panel on the local LAN while the rest go through the proxy.

> SOCKS proxies have little/no browser auth support — use `http://` for an
> authenticating proxy. The validator warns if you pair SOCKS with `vault_item`.

## Finding selectors

1. Open the panel's login page in a desktop browser.
2. Right-click the username field → **Inspect**.
3. Pick a stable CSS selector — prefer `#id`, then `input[name="…"]`, then a class.
4. Do the same for the password field and the submit button.
5. Set `login_marker` to something that exists **only** on the login page (the
   password field is usually perfect). It's how the host detects "logged out" and
   re-logs-in.

Selectors are JSON-escaped before injection, so quotes are safe:
`input[name="user"]` works verbatim.

## Keep-alive strategies

| `strategy` | Behaviour | Use when |
|---|---|---|
| `reload` | periodically reloads the page (skipped while on the login page) | most dashboards |
| `xhr` | periodically `fetch`es `keepalive.url` with credentials | the app has a lightweight ping/heartbeat endpoint |
| `click` | periodically clicks `keepalive.target` | activity-based idle timers |
| `none` | nothing | the app never times out, or you rely on auto re-login only |

The real anti-timeout safety net is the `MutationObserver` that detects the login
form reappearing and re-logs-in — the timer just reduces how often that happens.

## Performance & low-memory boards

The host auto-profiles the hardware (no config needed) and exposes overrides in
`soc.env`:

| Env var | Default | Effect |
|---|---|---|
| `SOC_LOW_MEMORY` | auto | `1`/`0` to force the low-memory profile. Auto-on when `MemTotal ≤ 1.5 GB` (1 GB-class Pi). It switches WebKit to the `DOCUMENT_VIEWER` cache model (drops the page/back-forward caches — right for a one-page-per-view wall). |
| `SOC_WEBKIT_HWACCEL` | `auto` | `always` \| `never` \| `ondemand` \| `auto`. Auto = GPU-accelerated compositing on ARM boards that expose a render node (Pi 5 V3D), on-demand under the low-memory profile, engine default elsewhere. |
| `SOC_LAUNCH_STAGGER` | `1.5` | seconds between panel launches — spreads the boot RAM/CPU spike. |
| `SOC_CHROMIUM_OZONE` | `auto` | `x11` \| `wayland`. Chromium panels default to X11/XWayland so WM_CLASS placement works under Openbox and labwc. |
| `SOC_MEM_MIN_AVAIL_MB` | `96` | Memory-watchdog floor: when `MemAvailable` falls below this, the host recycles a panel (heaviest Chromium first, else a WebKit reload) to reclaim memory. |
| `SOC_MEM_CHECK_SEC` | `30` | How often the memory watchdog samples `MemAvailable`. |
| `SOC_MEM_RECYCLE_COOLDOWN` | `120` | Minimum seconds between watchdog recycles (anti-thrash; it also needs two consecutive low readings before acting). |

All numeric tunables are parsed defensively: a missing or non-numeric value logs
a warning and falls back to the default (and is clamped to a sane range) rather
than crashing the host at boot.

Chromium panels also run with a capped 50 MB disk cache, background networking
and sync disabled — kinder to SD cards and RAM. When the wall runs as
`soc-wall.service`, the unit additionally caps the whole session with
`MemoryHigh=80%` / `MemoryMax=92%` so a leak throttles (or restarts the session)
instead of OOM-killing the box.

Other tips:

- Prefer `engine: webkit`; use `engine: chromium` only for a panel WebKit can't render.
- For Grafana/Kibana-style panels, add kiosk/refresh params to the URL, e.g.
  `…/d/abc?kiosk&refresh=30s`, to cut live-update CPU/RAM.
- On 32-bit ARM (armv7), run a 64-bit OS instead if you can — WebKitGTK is heavy.
