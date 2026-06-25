# p2soc — Raspberry Pi 5 → SOC Video Wall

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205-c51a4a)
![engine](https://img.shields.io/badge/render-WebKitGTK%20%2B%20Chromium-informational)

Convert a Raspberry Pi 5 (1 GB) into a **Security-Operations-Center video wall**:
an HDMI display that boots straight into a **taskbar-less desktop with four
draggable browser windows in a 2×2 grid**. Each window shows a different web
panel (different IP/port), **auto-logs in** from a local secrets vault, and
**keeps the session alive / re-logs-in** on timeout. One or more panels can live
on a remote network reached only through an **SSH jump host**, kept up by a
persistent **autossh** tunnel, or behind a supervised **VPN** — **Fortinet
SSL-VPN, OpenVPN, or WireGuard** (`vpn.type`) — with auto-reconnect, health
checks, and classified error handling, credentials from the same vault. Tiles
are **universal**: point any panel at any URL from the **on-screen config**
(corner ⚙ or Ctrl+Shift+C, optional PIN lock) — no SSH, no file editing. Outbound
traffic can go through an **authenticated HTTP(S)/SOCKS proxy** whose credentials
also come from the vault and are answered **in memory** (never on argv or disk).
Everything starts on boot and self-heals: crashed web processes reload, dead
panels show a clear on-screen status card and retry with backoff, Chromium
respawns, the VPN reconnects.

Runs on **X11 (X.Org or XLibre, Openbox)** or **Wayland (cage / labwc)**, on
**x86-64 and ARM**, and installs on **Raspberry Pi OS / Debian / Ubuntu,
Fedora/RHEL, Arch, openSUSE, Alpine and Void** — plus any other distro with
`SOC_SKIP_PACKAGES=1`, and degrades gracefully on non-systemd inits. The Pi 5 is
the reference target. Built entirely from open-source parts: **WebKitGTK** (with
a **Chromium** fallback per panel), **Vaultwarden** + **litebw** (a pure-Python,
`rbw`-compatible client — no Rust toolchain; the legacy `rbw` still works), **autossh**,
**openfortivpn**, **systemd**, **zram**. It auto-profiles the hardware (lighter
WebKit cache on 1 GB boards, GPU compositing on the Pi 5).

![wall](docs/img/wall.png)

> Produced by the dev harness (`make verify`): four panels logged in — WebKit
> direct, WebKit through a tunnel, Chromium via CDP, and a WebKit panel with a
> live chart.

## Docs

- [**Full setup guide**](docs/SETUP.md) — start-to-finish bring-up (dev + Pi) via the `setup.py` wizard
- [**Production deploy**](docs/DEPLOY.md) — the real Pi/kiosk install + `setup.py install/doctor/repair`
- [Architecture](docs/ARCHITECTURE.md) — topology, boot/data-flow, RAM budget, rationale
- [Install on the Pi](docs/INSTALL.md) — step-by-step bring-up + checklist
- [Configuration](docs/CONFIGURATION.md) — `panels.yaml` reference, finding selectors, keep-alive
- [Security](docs/SECURITY.md) — threat model, the unattended-unlock tradeoff, hardening
- [Development](docs/DEVELOPMENT.md) — dev harness, make targets, testing
- [Changelog](CHANGELOG.md) — what changed

---

## How it works

```
systemd (system)
  ├─ zram (zstd)                compressed swap so 1 GB holds 4 panels
  ├─ vaultwarden.service        encrypted vault on 127.0.0.1:8222
  ├─ autossh-tunnel.service     autossh -L 127.0.0.1:191xx:remote:port  user@jump
  └─ forti-vpn.service          supervised openfortivpn → FortiGate SSL-VPN
                                (vault creds, auto-reconnect + health check,
                                 systemd watchdog, STATUS= in systemctl status)

getty@tty1 autologin (soc) → start-session.sh   (SOC_SESSION=x11|wayland|auto)
  ├─ x11:     startx → Openbox → launcher.sh → kiosk host (Python / PyGObject)
  │           Openbox rc.xml forces each WM_CLASS=soc-pN window into its cell
  └─ wayland: cage (all-webkit wall → ONE fullscreen grid window)
              or labwc (generated window rules tile the panel windows)
  kiosk host:
        ├─ litebw unlock + sync → read the logins into RAM
        ├─ engine: webkit  → WebKitWebView; native login injection; crash auto-reload
        └─ engine: chromium→ chromium --app + CDP login injection; auto-respawn
```

**Auto-login is injected by the host**, not by a browser extension or a network
service: the host reads credentials from the vault and types them into each
view itself (WebKit via a `socCreds` message handler; Chromium via the DevTools
Protocol on localhost). There is **no credential broker, no open port, no
page-context fetch** — credentials never leave the host process except as the
values typed into the login form.

**Why these choices on 1 GB:** the 4 panels are different `IP:port` origins, so
cookies isolate naturally — no need for 4 browser profiles. WebKitGTK shares one
process tree (~250–450 MB) versus four Chromium renderers (~600–800 MB), so
Chromium is opt-in per panel. zram + throttled chart refresh absorb the rest.

---

## Repo layout

| Path | What |
|------|------|
| `config/panels.yaml` | wall config (panels, tunnel, vpn, proxy). In production the Vaultwarden `SOC Wall Config` note is the source of truth; this file is the offline fallback |
| `kiosk-host/host/` | the host: `main.py`, `webkit_panel.py`, `chromium_panel.py`, `wall.py` (single-window grid), `fortivpn.py` (VPN supervisor), `style.py` (status cards), `perf.py` (hw profile), `vault.py`, `secretstore.py` (sealed master pw), `inject.py`, `config.py` |
| `inject/login.js.tmpl` | shared auto-login + keep-alive + re-login script (both engines) |
| `openbox/` | `rc.xml.tmpl` (2×2, no panel, draggable), `menu.xml`, `autostart` |
| `labwc/` | `rc.xml.tmpl` — the Wayland twin of the Openbox config |
| `scripts/` | `start-session.sh`, `wayland-session.sh`, `launcher.sh`, `autossh-tunnel.sh`, `forti-vpn*.{sh,py}`, `gen-openbox-rc.py`, `gen-labwc-rc.py`, `tunnel-args.py`, `pinentry-vault.py`, `xinitrc` |
| `systemd/` | `vaultwarden(-docker).service`, `autossh-tunnel.service`, `forti-vpn.service`, `getty-autologin.conf` |
| `security/` | `nftables.conf`, `sshd_hardening.conf`, `zram.conf`, `99-soc-sysctl.conf`, `tunnel_key.note` |
| `dev/` | dummy panels, vault seeding, tunnel stand-in, `auth-proxy.py`, `verify*.sh`, `run-wall.sh` |
| `setup.py` | menu / `deploy` / `first-run` / `wizard` / `doctor` / `repair` / `creds`: writes config, seals the master password (one-time PIN), pushes config to the vault |
| `install.sh` | idempotent multi-distro installer (apt/dnf/pacman/zypper/apk/xbps, X.Org/XLibre/Wayland) |

---

## Try it on your workstation (no Pi needed)

Requires: `python3` + `python3-gi` + `gir1.2-webkit2-4.x`, `Xvfb`/`Xephyr`,
`chromium`, ImageMagick (`import`).

**Fastest first run** — one idempotent command sets up the venv + dev vault, then
launches the wall (use `--pi` instead to hand off to the production deploy):

```bash
./launch.sh             # show the wall in a window (Xephyr); headless if no display
./launch.sh --headless  # headless end-to-end check (Xvfb + screenshot)
./launch.sh --pi        # production: sudo setup.py deploy (install + configure + seal + checks)
```

Or drive the pieces directly:

```bash
make verify         # headless: brings up 4 dummy panels + the host, asserts logins,
                    # tunnel gate, Chromium CDP, writes dev/run/verify.png
make verify-single  # headless check of the single-window (Wayland-style) layout
make verify-proxy   # headless check of the authenticated-proxy path (WebKit + Chromium)
make dev            # interactive: shows the wall in a Xephyr window (Ctrl-C to stop)
make test           # unit tests (config, geometry, injection, VPN supervisor, proxy, perf)
make vpn-check      # dry-run the VPN: resolve creds + print the openfortivpn command
```

`make verify` uses the **dev vault backend** (a JSON file) so it needs no
Vaultwarden. To exercise the real **litebw → Vaultwarden** path:

```bash
make vault      # starts Vaultwarden in Docker, registers an account,
                # seeds 4 logins via the API, verifies litebw can read them
```

---

## Install on the Raspberry Pi (or any supported distro)

Flash **Raspberry Pi OS (64-bit)** — or start from Debian/Ubuntu, Fedora/RHEL,
Arch, openSUSE, Alpine or Void — enable SSH, boot, copy this repo over, then
configure with the interactive wizard and run the installer:

```bash
sudo python3 setup.py deploy      # end-to-end: install + configure + seal PIN + push config + creds
sudo ./install.sh                 # VW_MODE=docker (default) | native ; HARDEN=1 to firewall
                                  # SESSION=x11 (default) | wayland | auto
                                  # SOC_SKIP_PACKAGES=1 on an unsupported distro
```

Auto-installs packages via apt/dnf/pacman/zypper/apk/xbps; honours an existing
X.Org **or XLibre** server; degrades gracefully without systemd (prints the
service + autologin steps to wire up by hand). See [docs/INSTALL.md](docs/INSTALL.md).

The wizard (`setup.py`) is re-runnable and writes/validates all three config
files; see the [full setup guide](docs/SETUP.md). You can also edit the
`*.example` templates by hand.

The installer: installs deps, creates the `soc` (kiosk) and `socsvc` (tunnel)
users, deploys to `/opt/soc-display`, builds the venv, lays down `/etc/soc-display`
config, sets up Vaultwarden + autossh systemd units, zram, the Openbox session,
and tty1 autologin. It **disables the desktop session** (keeps your preloaded
card; the desktop just doesn't run) — same RAM benefit as Pi OS Lite, reversible.

Then finish setup (the installer prints this):

1. `‎/etc/soc-display/panels.yaml` — your 4 panels (IPs, ports, **selectors**, `vault_item`, tunnel).
2. `‎/etc/soc-display/soc.env` — email, url, `SOC_SESSION` (**non-secret**; `chmod 0640`).
3. Vaultwarden's config is in its systemd unit (no `.env`); the `/admin` page is off.
4. `systemctl start vaultwarden`, create the kiosk account in the web vault, add
   the 4 logins **named to match each `vault_item`**.
5. `sudo python3 setup.py first-run` — generate the **one-time PIN** + seal the
   master password host-bound (no plaintext `.env`); or `setup.py deploy` for all of it.
5. Tunnel key: see `security/tunnel_key.note` (restricted `permitopen` key).
6. `systemctl reboot` → the wall comes up logged-in, hands-free.

### Finding selectors for a panel
Open the panel's login page in a browser, right-click the username field →
Inspect, and copy a CSS selector for the username input, password input, and the
submit button into `selectors:`. `login_marker` should be a selector that exists
**only** on the login page (usually the password field) — it's how the host
detects a logged-out state and re-logs-in.

---

## Configuration reference (`panels.yaml`)

```yaml
panels:
  - id: p1                      # short id; window class becomes soc-p1
    engine: webkit              # webkit (light, default) | chromium (fallback)
    grid: [0, 0]                # [col, row] in the 2x2 grid
    mode: direct                # direct | tunnel
    url: "http://10.0.0.5:3000/login"
    # for mode: tunnel, instead of url:
    # tunnel: {local_port: 19103, remote_host: 10.20.0.7, remote_port: 8443}
    # path: "/login"  ; scheme: http
    vault_item: "SOC Panel 1"   # Vaultwarden login item name
    selectors: {user: "#username", pass: "#password", submit: "button[type=submit]"}
    login_marker: "#password"   # exists only on the login page
    keepalive: {strategy: reload, intervalSec: 600}   # reload | click | xhr | none
```

The same file also holds the `display.layout` (auto/windows/single), `tunnel`,
`vpn`, and `proxy` sections — for example, an authenticated proxy for all panels:

```yaml
proxy:
  enabled: true
  url: "http://proxy.corp:3128"   # no credentials in the URL
  vault_item: "SOC Proxy"         # username+password answered in memory
  ignore_hosts: ["*.corp.lan"]    # loopback always bypasses
```

For Grafana/Kibana-style panels, append kiosk/refresh params to the URL
(e.g. `...?kiosk&refresh=30s`) to cut RAM/CPU on the 1 GB Pi. The host
auto-tunes its WebKit cache + GPU policy from the detected RAM/CPU
(override with `SOC_LOW_MEMORY` / `SOC_WEBKIT_HWACCEL`).

---

## Security model & tradeoffs

- **Vault**: Vaultwarden bound to `127.0.0.1`. The host reads via `litebw` (the
  pure-Python default; legacy `rbw` optional); creds
  stay in a short-TTL in-RAM cache, never written to disk by the host, never
  logged.
- **Unattended unlock**: the master password is **sealed host-bound** (AES-256-GCM,
  key = scrypt(machine-id + a one-time PIN); `secretstore.py` + `pinentry-vault.py`),
  so there is no plaintext secret in any `.env` and the sealed files are useless if
  copied off the box. A local root on the running Pi can still derive it — the cost
  of any unattended wall. Generate the PIN + seal with `setup.py first-run`.
- **Residual exposure**: auto-filling any login form puts the password into the
  page DOM at submit time — inherent to form auto-login. The host scrubs its copy
  after injection and uses no network channel for creds.
- **Tunnel key**: dedicated, passphrase-less ed25519 key restricted to exact
  `permitopen` forwards on the jump host (see `security/tunnel_key.note`).
- **Fortinet VPN**: `forti-vpn.service` reads the FortiGate login from the vault
  and feeds the password to `openfortivpn` via a pinentry helper — never on argv
  or disk. Pin the gateway cert (`vpn.trusted_cert`); see `docs/CONFIGURATION.md`.
- **Proxy auth**: an authenticating proxy's credentials live in the vault
  (`proxy.vault_item`) and are answered to its challenge in memory; the proxy URL
  carries no `user:pass@`, and the validator rejects it if it does.
- **Network**: optional `HARDEN=1` installs an nftables default-deny firewall and
  key-only sshd. Review `ssh_admin_cidr` and ensure you have a key before reboot.

---

## Operations

```bash
systemctl status vaultwarden autossh-tunnel forti-vpn   # services
journalctl -u autossh-tunnel -u forti-vpn -f     # tunnel + VPN logs
loginctl ; journalctl _UID=$(id -u soc) -f       # kiosk session / host logs
# Re-place windows for a different resolution:
sudo -u soc /opt/soc-display/.venv/bin/python /opt/soc-display/scripts/gen-openbox-rc.py \
  --panels /etc/soc-display/panels.yaml --template /opt/soc-display/openbox/rc.xml.tmpl \
  --out ~soc/.config/openbox/rc.xml --width 1920 --height 1080
```

Windows are draggable by their titlebar and **Alt+drag** anywhere; **Alt+right-drag**
resizes. The host respawns if it crashes (launcher loop); autossh and vaultwarden
restart via systemd.

## Troubleshooting

| Symptom | Fix |
|---|---|
| A panel renders blank/broken in WebKit | set that panel's `engine: chromium` |
| Panel never logs in | check `selectors`/`login_marker` against the real page; check `journalctl` for `[pN] injected login` |
| Tunneled panel shows connection error | `systemctl status autossh-tunnel`; verify the jump key/`permitopen` |
| Windows not in 2×2 | re-run `gen-openbox-rc.py` with the real `--width/--height` |
| OOM / sluggish charts | confirm zram active (`zramctl`); lower panel refresh; prefer `engine: webkit` |

---

## License

`p2soc` is free software licensed under the **GNU General Public License v3.0**
(see [LICENSE](LICENSE)). You may redistribute and/or modify it under the terms of
the GPLv3. It is distributed in the hope that it will be useful, but **WITHOUT ANY
WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.

## Contributing

Issues and PRs welcome. Run `make lint && make test && make verify` before
submitting; see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

> Use only against panels and networks you are authorized to access. This is a
> defensive monitoring tool, not an access-bypass tool — it auto-fills
> credentials you legitimately hold.
