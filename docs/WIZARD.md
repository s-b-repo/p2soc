# Setup wizard — what to enter at every prompt

This is the friendly, **prompt-by-prompt** companion to the [full setup
guide](SETUP.md) (the map) and the [configuration reference](CONFIGURATION.md)
(the file format). For every question the wizard asks, it tells you what it
means and exactly what to type — with a worked example.

Run the configuration questions any time:

```bash
sudo soc-wall setup wizard        # just the configuration wizard
```

A kiosk without a configured marker runs first-boot setup on tty1.
Run `soc-wall setup-gui` from a desktop session for the graphical wizard.

A few things that are true at every prompt:

- The default is shown in `[brackets]`. **Press Enter to accept it.**
- Re-running loads your previous answers as those defaults, so a second pass is
  mostly just Enter, Enter, Enter.
- **Nothing is saved until the very end.** The wizard collects every answer,
  validates the configuration, and writes files after you confirm **“Write this
  configuration”**. Press **Ctrl-C** at any point to abort with nothing changed.

---

## ⭐ The one rule that trips everyone up: a selector is **not** a credential

The wizard asks for two completely different kinds of thing. Keep them straight
and the rest is easy:

| The wizard asks for… | Looks like | Secret? | Where it ends up |
|---|---|---|---|
| **Where / how** — a URL, or a **CSS selector** for a box on the page | `#name`, `#password`, `button[type=submit]` | No | `panels.yaml` (plain config) |
| **Who you are** — a **username / password** | `Admin`, `S3cr3t-Pa55!` | **YES** | **Vaultwarden only** |

A **CSS selector** is just an address that points the wall at *where* the
username and password boxes are on the login page. It is **not** your username
and **not** your password.

> ❌ **Wrong:** typing `Admin` at *“username field selector”* and your password
> at *“password field selector”*.
> ✅ **Right:** `#name` and `#password` (or let auto-detect fill them). Your real
> `Admin` / password go into **Vaultwarden** — see
> [After the wizard: store the credentials](#after-the-wizard-store-the-credentials).

If you put a credential in a selector field, two bad things happen: auto-login
breaks (the selector matches nothing), and your password gets written in
cleartext into a non-secret config file.

The wizard now **auto-detects** the selectors for you, so for most panels you
never type a selector at all — you just confirm.

---

## Display geometry

How the screen is divided into a grid of panels.

| Prompt | What it is | What to type |
|---|---|---|
| `screen size` | resolution | Pick **`auto`** (detect at launch — the usual choice), a preset like `1920x1080`, or `custom` |
| `Screen width/height (px)` | only if you chose `custom` | e.g. `1920` / `1080` |
| `Grid columns` / `Grid rows` | the panel grid | `2` and `2` for the classic 2×2 wall (4 panels) |
| `Gap between cells (px…)` | space between tiles | `0` for seamless |
| `layout` | window placement | **`auto`** is right almost always (see [CONFIGURATION](CONFIGURATION.md#display)) |

---

## Panels

Enter a number of panels up to the grid size. Zero leaves an empty wall for
configuration in [Settings](#configure-at-the-glass-no-wizard-needed). For each
panel, give a unique ID and pick the grid cell, browser engine and connection.

### Per-panel prompts, in order

| Prompt | What it is | What to type |
|---|---|---|
| `id (window class becomes soc-<id>)` | short name for the tile | e.g. `zabbix`, `wazuh`, `p1` |
| `engine` | renderer | **`webkit`** (light, default). Use `chromium` only if WebKit can’t render the page |
| `grid column / row (0-based)` | which cell | `0,0` = top-left, `1,0` = top-right, `0,1` = bottom-left… |
| `mode` | how it’s reached | **`direct`** (a reachable URL) or `tunnel` (via the SSH jump host) |
| `login URL` *(direct)* | the page to open | the panel’s login page, e.g. `http://10.14.0.2/zabbix/index.php`. Include the URL scheme |
| *(tunnel fields)* | for `mode: tunnel` | local port, remote host/port (as seen from the jump host), path, scheme — see below |
| `vault item name` | **the Vaultwarden login this panel uses** | a name, e.g. `zabbix`. This is **where the real username/password live** — store them later with `soc-wall setup creds`. Leave blank for a display-only tile (no login) |

Then the wizard probes the URL and either auto-fills the selectors or asks you
for them. That’s the next part.

### Auto-detect: the happy path

For a direct panel, answer **yes** to **Detect the login form**. The wizard
reads the page and suggests selectors for the username, password and submit
controls. Press Enter at each selector prompt to keep the suggestion. Pages
that render their controls with JavaScript may require manual selectors or
login-zone calibration in the running wall.

### What each selector means

| Prompt | Plain meaning | Typical value |
|---|---|---|
| `username field selector` | where the **username box** is | `#name` (Zabbix), `#username`, `input[name="user"]` |
| `password field selector` | where the **password box** is | `#password` |
| `submit button selector (blank = press Enter)` | the **Sign-in button**. Leave **blank** to just press Enter in the password box | `#enter`, `button[type=submit]`, or blank |
| `login_marker (selector seen ONLY on the login page)` | **how the wall knows a panel is logged OUT** so it can log back in. Pick something that exists *only* on the login screen — the password box is perfect | `#password` (same as the password selector) |

#### So what *is* `login_marker`?

It’s the wall’s “are we logged out?” detector. Every so often the wall checks the
page for this selector:

- **found** → we’re on the login screen → fill the form and sign in again;
- **not found** → we’re logged in → leave it alone.

Because a password box only ever appears on a login page, the password selector
(`#password`) is almost always the right answer — which is why the wizard
pre-fills it. **Just press Enter to accept it.**

### How to find a selector by hand

If auto-detect can’t reach the panel (common during setup if the VPN/tunnel
isn’t up yet) or you answered “n”:

1. Open the panel’s login page in any desktop browser.
2. Right-click the **username** box → **Inspect**.
3. Read the highlighted `<input>` tag and use, in order of preference:
   - its **id** → `#theId`
   - its **name** → `input[name="theName"]`
   - its **type** → `input[type="password"]`
4. Repeat for the password box and the Sign-in button.
5. Test in the browser console — this should return the element, not `null`:
   ```js
   document.querySelector('#password')
   ```

### Login types the wizard recognises

| What it finds | What happens |
|---|---|
| A normal HTML form (Zabbix, most server-rendered apps) | reads the real selectors from the page |
| A JavaScript-rendered login (Grafana, Wazuh/Kibana, Keycloak) | can’t read the live form, so it fills a **known preset** for that product, marked **“VERIFY”** — confirm it in a browser |
| **HTTP Basic auth** (a browser popup, not a web form) | flagged — form-fill can’t drive it; put the panel behind a proxy that shows an HTML form |
| Self-signed HTTPS | asks first before reading the page without verifying the cert (the probe sends **no** credentials). Pin the cert for production |
| Unreachable / nothing found | falls back to the manual steps above |

### Keep-alive (last per-panel prompts)

| Prompt | What to type |
|---|---|
| `keep-alive strategy` | **`reload`** for most dashboards; `xhr`/`click` for apps with a heartbeat or idle timer; `mouse` to dispatch an invisible synthetic mousemove inside the page (good for dashboards that idle-time-out on inactivity but don't expose a heartbeat URL); `none` if it never times out |
| `interval (seconds)` | how often, e.g. `600` |
| `heartbeat URL` / `selector to click` | only for `xhr` / `click` |

#### `keepalive: mouse`

When the dashboard doesn't have a heartbeat URL to ping or a "refresh"
button to click, but does idle-time-out after N minutes of inactivity,
pick `mouse`. The wall dispatches a synthetic `MouseEvent("mousemove",
{...})` to the page on the interval — the page's idle timer resets, but
the real OS cursor doesn't move (so it's safe on a shared desk where a
real cursor jump would interrupt a human operator).

```yaml
keepalive:
  strategy: mouse
  intervalSec: 60
```

### `relogin_url` (jump to the dashboard after auto-login)

When the panel's login URL is `https://wazuh.example/app/login` but the
useful screen is `https://wazuh.example/app/dashboards`, set:

```yaml
relogin_url: https://wazuh.example/app/dashboards
```

After auto-login succeeds (the `login_marker` selector goes away, the
text-pattern login detection clears, or the panel posts the `loggedin`
message), the wall navigates to this URL once per load. Guarded against
loops if the relogin URL itself bounces back to a login page.

### `blocked_url_patterns` (keep the wall away from settings pages)

A list of fnmatch-style patterns the panel may NOT navigate to:

```yaml
blocked_url_patterns:
  - "*account/settings*"
  - "*/admin/users*"
  - "*/logout*"
```

WebKit enforces this via the `decide-policy` signal returning
`decision.ignore()`; Chromium does it via the CDP
`Fetch.failRequest(BlockedByClient)`. The list is exposed in
⚙ Settings → Panels → Advanced → "blocked URLs (one per line)".

Stops a stray click on the wall (or a hostile actor with keyboard
access) from steering the panel into its account-settings,
change-password or sign-out flow.

### Worked example — a Zabbix panel

```
id            : zabbix
engine        : webkit
grid          : 0, 0
mode          : direct
login URL     : http://10.14.0.2/zabbix/index.php
vault item    : zabbix                     ← the vault login; creds stored separately
Use these detected selectors? [Y]          ← Enter  (→ #name / #password / #enter)
keep-alive    : reload, 600
```

Your Zabbix **username (`Admin`) and password** are **not** entered above —
they go into the `zabbix` vault item with `soc-wall setup creds`.

### Tunneled panels (`mode: tunnel`)

For a panel only reachable through the SSH jump host:

| Prompt | What to type |
|---|---|
| `local forward port` | a free local port, e.g. `19103` |
| `remote host (as seen from the jump host)` | the panel’s host on the far side, e.g. `10.20.0.7` |
| `remote port` | e.g. `443` |
| `path on the app` | e.g. `/login` |
| `local scheme` | `http` or `https` |

Auto-detect is skipped for tunnels (the tunnel isn’t up yet), so you’ll enter
selectors by hand — use the “find a selector” steps above.

---

## SSH jump-host tunnel

Only relevant if a panel uses `mode: tunnel` (you’re asked anyway, default off).

| Prompt | What to type |
|---|---|
| `jump host (user@host)` | the SSH bastion, e.g. `tunneluser@jump.example.net` |
| `identity key path (on the Pi)` | the private key, e.g. `/etc/soc-display/keys/tunnel_ed25519` (see [`security/tunnel_key.note`](../security/tunnel_key.note)) |

---

## VPN

“Enable a VPN?” → `n` if your panels are directly reachable. If `y`, pick the
**type** (`fortinet` / `openvpn` / `wireguard` / `inode`) and answer its fields.
Highlights (full detail in [CONFIGURATION](CONFIGURATION.md#vpn-fortinet-openvpn-wireguard-or-inode)):

| Type | You’ll be asked for |
|---|---|
| `fortinet` | gateway host + port, **vault item** (FortiGate user+pass), cert pin (it can **fetch the sha256 for you**), routing/DNS, reconnect/liveness, optional TOTP |
| `openvpn` | path to the `.ovpn`, optional vault item (or certificate-only), `ready_probe` |
| `wireguard` | path to the `.conf` (keys live in it — `chmod 0600`), `ready_probe`, liveness interval |
| `inode` | gateway host+port, vault item, optional client dir (blank = bundled), domain, cert pin or insecure |

As with panels, **VPN credentials live in the vault** (`vault_item`), never in a
config field. Routing tip: accepting gateway routes can pull *all* traffic over
the VPN — keep your own default route with “half-internet-routes” if unsure.

### Multiple VPNs (`vpns:` list)

A SOC wall that needs two tunnels (e.g. one to HQ, one to a DR site) uses the
new `vpns:` top-level list. The legacy `vpn:` mapping still parses — the
loader normalises both shapes to a list, so old configs keep working.

```yaml
vpns:
  - name: hq                    # the systemd instance: forti-vpn@hq.service
    enabled: true
    type: fortinet
    gateway: vpn.hq.acme.com
    vault_item: "VPN HQ"
    ready_probe: 10.14.0.1:443
  - name: dr
    enabled: true
    type: openvpn
    config: /etc/soc-display/openvpn/dr.conf
    vault_item: "VPN DR"
    ready_probe: 10.20.0.1:1194
```

Each entry runs in its own supervised systemd instance
(`forti-vpn@<name>.service` — `systemctl status forti-vpn@hq`) and gets its
own **top-bar pill**: green when the `ready_probe` returns, **amber** while
the probe is timing out (mid-handshake), red when it actively refuses. Click
a pill to reconnect *just that VPN*. The ⚙ Settings → VPN tab shows two
sections side-by-side and can edit both.

### Storing VPN config in Vaultwarden (`config_from_vault: true`)

For Fortinet/iNode, you can pin the entire VPN config (`gateway`, `port`,
`realm`, `trusted_cert`, `domain`, `set_routes`, ...) inside the vault item's
Notes as `KEY=VALUE` lines:

```
# in the "VPN HQ" Vaultwarden item Notes:
gateway = vpn.hq.acme.com
port = 443
realm = staff
trusted_cert = aabb...64hexchars...ff
set_routes = true
```

With `config_from_vault: true` on the VPN entry, the supervisor reads the
Notes at boot and overlays the values onto the live config — nothing
sensitive ends up in `panels.yaml` or on disk. Means you can rotate a
gateway / cert from the web vault without touching the panels file. Unknown
keys are rejected (strict allowlist) and logged.

For OpenVPN / WireGuard the existing `config_from_vault` flow continues to
work: the Notes hold a full `.ovpn` / `.conf` and the supervisor writes it
to a 0600 temp file in the soc-vpn dir for the duration of the connection.

---

## Outbound proxy

“Use an outbound proxy?” → `n` unless your network forces one.

| Prompt | What to type |
|---|---|
| `proxy URL (scheme://host:port)` | `http://proxy.corp:3128` (**no** username/password in the URL) |
| `vault item with the proxy credentials` | a vault login if the proxy needs auth, else blank |
| `extra hosts to bypass` | comma-separated, e.g. `*.corp.lan` (loopback always bypasses) |

---

## Vault

Where the wall reads every login (and its own config) from.

| Prompt | What to type |
|---|---|
| `vault account email` | the kiosk Vaultwarden account, e.g. `kiosk@soc.local` |
| `Vaultwarden URL` | usually `http://127.0.0.1:8222` (a bare `127.0.0.1:8222` is accepted) |
| `Vault backend` | `litebw` or `native` uses the native Vaultwarden client, `rbw` uses the external client, and `dev` reads a JSON fixture. |
| `Vault configuration item` | The vault note that stores the wall configuration. |

The **master password is not entered here.** It’s sealed host-bound later by
`soc-wall setup first-run` (or `deploy`), which mints a one-time PIN — no plaintext on
disk.

---

## Kiosk session and Vaultwarden

Choose `auto` for the display stack, or select Wayland, XWayland, XLibre, Xorg or
X11 explicitly. Vaultwarden uses the settings in its systemd unit, with a
loopback listener and signups disabled. `soc-wall setup deploy` can create the
local account using a temporary runtime drop-in.

---

## Review & write

The terminal wizard writes `panels.yaml` and `soc.env` after confirmation.
Use `--dry-run` to print the generated files. On a desktop the Review step
shows the output paths, configuration, and any validation warnings. Installed
hosts with polkit can request authorization to save system configuration.
The wizard can also save for the current login.

---

## Configure at the glass (no wizard needed)

You can install the wall with **blank tiles** and set everything up on the screen
itself — ideal when you don’t know the panel URLs or logins at install time, or
want a non-technical operator to finish it without SSH.

On the running wall, open the settings window: click the **⚙ gear** in the top
bar, or press **Ctrl+Shift+C**. Its tabs:

| Tab | What you do there |
|---|---|
| **Panels** | Set URL, title, vault item and engine for each tile. Use the advanced fields for selectors or open login-zone calibration for WebKit and Chromium. Changes apply live and are saved to `overrides.json` (they layer on top of `panels.yaml`) |
| **Credentials** | for each panel/VPN/proxy vault item, type the **username + password** and click **Save to vault** — stored straight into Vaultwarden (the wall reads it through its configured vault backend). If the wall isn’t host-sealed, it asks for the vault master password right here |
| **Display** | layout, gap, **grid size (cols × rows)**, and **resolution (width × height + auto-detect)**. Gap applies live; layout / grid / resolution take effect on the next restart. **Growing the grid auto-creates blank click-to-configure tiles for the new cells** — so adding a 5th panel is just bumping `rows` from 2 to 3 and restarting |
| **VPN** | type + gateway + vault item + cert pin; Apply pushes it to the vault config note and restarts the VPN |
| **Proxy** | outbound HTTP(S)/SOCKS proxy for the panel browsers: **enabled**, **URL**, **vault login** (proxy creds), **ignore hosts**. Applies on the next restart |
| **Tunnel** | the SSH **jump host** used by panels in *tunnel* mode: jump host, identity (private-key path), `known_hosts` file, host-key-checking mode, and **extra forwards** (one `bindaddr:port:host:port` per line). Apply restarts `autossh-tunnel` |
| **Actions** | one-click **Reload panels** (no restart) · **Restart wall** (soft, ~3 s via systemd respawn — applies layout/grid/resolution changes without a reboot) · **🔒 Lock the wall now** (same as the toolbar lock and Ctrl+Alt+L; panels stay visible, input is inert until PIN/TOTP) · **Reboot machine** · **Repair install** (runs `soc-wall setup repair`) |
| **Security** | enrol / clear / change the PIN that gates this Settings window AND the panel-lock PIN. Optionally enrol a TOTP (RFC 6238) — the unlock prompt accepts either. Live complexity validation for both (min length, character classes, common-bad rejection). The panel-lock secret is separate from the Settings secret — typically operators choose one PIN for both, but they can be different |
| **Status** | live health of the panels and VPN |

So the entire loop — point a tile at a tool, configure the VPN / proxy / tunnel
it sits behind, **and** store the logins — happens at the glass. An optional
**PIN lock** (under Security) gates the window so a kiosk in a public space
can’t be reconfigured by a passer-by.

### Tray mode for desk deploys

When the wall is run **windowed** (`SOC_WINDOWED=1` env or
`display.fullscreen: false`) AND a tray backend is available (any of
AyatanaAppIndicator3, AppIndicator3, or `Gtk.StatusIcon`), closing the
wall window hides it to the system tray instead of quitting the host.

Tray menu:

| Item | Action |
|---|---|
| Show wall | bring the hidden window back |
| Lock panel | same as Ctrl+Alt+L / the toolbar 🔒 button |
| View wall log | open the wall log |
| Open Settings | open the ⚙ window |
| Restart wall | soft restart (systemd respawn ~3 s) |
| Reboot machine | `systemctl reboot` (needs root) |
| Quit | clean shutdown of the host |

Pure-kiosk mode on tty1 has no tray surface, so the tray is silently
skipped in that path — close-button behaviour is unchanged there.

**Two prerequisites for storing credentials at the glass:** Vaultwarden must be
running with the kiosk account created, and the vault must be unlockable — either
host-sealed via `soc-wall setup first-run`, or by typing the master password into the
Credentials tab.

For an empty wall, choose zero panels in the terminal setup or load the Empty
preset in the desktop wizard. Set the tiles and credentials from **Settings**.

## After the wizard: store the credentials

This is the step that completes a panel — and the home for the username/password
you did **not** type into the selector prompts:

```bash
sudo soc-wall setup creds
```

For each panel’s `vault_item` (e.g. `zabbix`), enter the real **username**
(`Admin`) and **password**. They’re stored encrypted in Vaultwarden; the wall
pulls them at sign-in time and types them into the boxes your selectors point at.
Do the same for any VPN/proxy `vault_item`.

That’s the whole model in one line: **selectors say where the boxes are; the
vault holds what goes in them.**

---

## See also

- [Full setup guide](SETUP.md) — start-to-finish bring-up on the Pi
- [Configuration reference](CONFIGURATION.md) — the `panels.yaml` file format,
  [finding selectors](CONFIGURATION.md#finding-selectors), keep-alive, VPN, proxy
- [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md)
