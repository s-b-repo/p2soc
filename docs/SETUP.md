# Full setup guide

This is the single, start-to-finish walkthrough for bringing up the SOC video
wall — on a **Raspberry Pi** (production) or on a **dev workstation** (no Pi
needed). It ties together the interactive wizard (`soc-wall setup`) and the manual
steps, and covers the autossh **tunnel** and the Fortinet **VPN**.

For deep dives see [ARCHITECTURE](ARCHITECTURE.md), [CONFIGURATION](CONFIGURATION.md),
[INSTALL](INSTALL.md), and [SECURITY](SECURITY.md). This page is the map.

---

## 0. What you're building

Four browser windows in a 2×2 grid, each auto-logging into a different web panel
using credentials from a local **Vaultwarden** vault. Panels can be reached
directly, through an **SSH jump host** (autossh `-L`), or across a **Fortinet
SSL-VPN** (openfortivpn). Everything starts on boot and self-heals.

The deployment uses these files:

| File | Purpose | Where (Pi) |
|---|---|---|
| `panels.yaml` | the 4 panels + `tunnel` + `vpn` | `/etc/soc-display/panels.yaml` |
| `soc.env` | vault settings (email/url) + paths — **non-secret** | `/etc/soc-display/soc.env` |
| _(Vaultwarden)_ | server config inline in its systemd unit — **no `.env`** | `systemd/vaultwarden*.service` |

The wizard writes the panel and environment configuration. The installer
installs the Vaultwarden service unit.

Two more things live outside these files: the vault **master password** is sealed
host-bound under `/etc/soc-display/secret/` (`soc-wall setup first-run`, no plaintext
`.env`), and in production the wall **config is pushed into the Vaultwarden
`SOC Wall Config` note** (the source of truth; `panels.yaml` is the fallback).

---

## 1. The fast path: `soc-wall setup`

`soc-wall setup wizard` is a re-runnable terminal wizard. It detects your environment,
asks one section at a time, validates the result and saves the configuration.

```bash
soc-wall setup              # interactive menu (Deploy / Configure / First-time setup / …)
soc-wall setup deploy       # end-to-end: install → configure → seal PIN → creds → check
soc-wall setup deploy --clean  # wipe generated config/state first, then deploy fresh
soc-wall setup deploy --fresh   # force a full OS reinstall (deploy skips it if already installed)
soc-wall setup first-run    # generate the one-time PIN + seal the master password
soc-wall setup wizard       # just the configuration wizard
soc-wall setup wizard --dry-run    # show what it would write, write nothing
soc-wall setup wizard --defaults   # accept every default (non-interactive wizard)
soc-wall setup wizard --target dev # force dev output (config/panels.local.yaml, .env)
soc-wall setup wizard --target pi  # force Pi output (/etc/soc-display/...)  [needs sudo]
soc-wall setup wizard --section vpn   # one section: display|panels|tunnel|vpn|proxy|vault|server
```

The wizard defaults to the Pi target for root and on deployed hosts. It uses
the development target on an unprivileged checkout. Re-running loads the
previous configuration as defaults and backs up each overwritten file.

The seven sections:

1. **Display** — resolution (auto/manual), the grid (cols × rows, gap), and the
   `layout` (auto/windows/single).
2. **Panels** — per panel: id, engine (`webkit`/`chromium`), grid cell, `direct`
   vs `tunnel`, URL or tunnel forward, `vault_item`, login **selectors**,
   `login_marker`, keep-alive.
3. **Tunnel** — autossh jump host + identity key (asked when any panel is tunneled).
4. **VPN** — Fortinet, OpenVPN, WireGuard, or iNode settings, including
   routing and readiness checks.
5. **Proxy** — optional outbound HTTP(S)/SOCKS proxy: URL, the vault login holding
   its credentials (in-memory auth), and hosts to bypass.
6. **Vault** — backend, account email and URL, and the config-note name.
   The first-run command seals the master and displays the one-time PIN.
7. **Session** — choose the kiosk display stack.

> **Selectors tip:** open the panel's login page in a browser, right-click the
> username field → Inspect, and copy a stable CSS selector (prefer `#id`). Do the
> same for the password field and submit button. `login_marker` should exist
> **only** on the login page (the password field is usually perfect) — it's how
> the host detects "logged out" and re-logs-in. See
> [CONFIGURATION.md](CONFIGURATION.md#finding-selectors).

After it writes the files it runs a parse + geometry check, so you'll know
immediately if anything is off.

For production, follow the wizard with **`soc-wall setup first-run`** (generates the
one-time PIN and seals the master password). The deploy command can also
push the configuration into the Vaultwarden `SOC Wall Config` note.
**`soc-wall setup deploy`** chains the installer, the wizard, sealing, and credential
storage in one go.

---

## 2. Dev workstation walkthrough (no Pi)

Build on a workstation with the GTK and WebKitGTK headers listed in
[Development](DEVELOPMENT.md). The preview uses a development vault and can
open with a preset or a local panel configuration.

```bash
make rust-release
./launch.sh
./launch.sh --headless
make test
```

`./launch.sh --setup` opens the terminal menu. For a graphical wizard or a
named preset, use the release binary:

```bash
rust/target/release/soc-wall setup-gui
rust/target/release/soc-wall setup-gui --list-presets
```

To check VPN wiring without connecting, use
`soc-wall vpn-args --config /path/to/panels.yaml`. See
[Performance](PERFORMANCE.md) for the repeatable comparison with Python.

---

## 3. Raspberry Pi walkthrough (production)

Target: **Raspberry Pi 5 (1 GB+)**, Raspberry Pi OS 64-bit (Bookworm), HDMI
monitor. The installer keeps your card and just **disables the desktop session**
(reversible).

### 3.1 Prepare

1. Flash/boot Raspberry Pi OS 64-bit, enable SSH, connect to the network.
2. Copy this repo to the Pi (`scp -r p2soc pi@<ip>:` or `git clone`), then SSH in.

### 3.2 Configure, then install

You can configure **before or after** running the installer — the installer
preserves any `/etc/soc-display/*` you already wrote.

```bash
cd p2soc
make rust-release
sudo ./rust/target/release/soc-wall setup deploy --mode kiosk
# …or do the two main steps by hand:
sudo ./install.sh
sudo /opt/soc-display/bin/soc-wall setup wizard
```

Installer knobs (env): `VW_MODE=native|docker`, `HARDEN=1` (nftables + key-only
sshd), `KIOSK_USER=soc`, `SVC_USER=socsvc`. It is **idempotent**.

The installer auto-enables `autossh-tunnel.service` only if a panel uses
`mode: tunnel`, and `forti-vpn.service` only if `vpn.enabled` has a gateway.

### 3.3 Create the vault account + add logins

```bash
sudo systemctl start vaultwarden
```

The default native Vaultwarden install provides the service API. Register the
configured account and store its credentials through the setup commands:

```bash
sudo soc-wall setup vault-register --email ops@example.com
sudo soc-wall setup first-run
sudo soc-wall setup creds
```

Enter a consistent vault email in the wizard and in `vault-register`. Store each
login under the name configured in its `vault_item`.

The wall config is stored in the Vaultwarden `SOC Wall Config` note — the source
of truth at boot; the local `panels.yaml` is only the offline fallback.

### 3.4 Tunnel key (if any panel uses `mode: tunnel`)

Generate a dedicated, restricted ed25519 key and authorize it on the jump host
with `restrict,permitopen="host:port",…`. Full steps in
[`security/tunnel_key.note`](../security/tunnel_key.note). Point `tunnel.identity`
at the key.

### 3.5 Fortinet VPN (if `vpn.enabled`)

Set the VPN configuration and pin the gateway certificate. Fetch and verify
the digest before entering it in the wizard:

```bash
openssl s_client -connect vpn.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//;s/://g' | tr A-Z a-z
```

The VPN supervisor reads the configured vault item and gives the password to
openfortivpn through pinentry. Check the connection with these commands:

```bash
sudo systemctl status forti-vpn
journalctl -u forti-vpn -f          # should reach "connecting to <gateway>"
ip a show ppp0                      # has an address once connected
```

Routing note: accepting all gateway routes can pull your LAN/SSH path over the
VPN. Use `half_internet_routes: true` or `set_routes: false` to keep your own
default route, and `set_dns: false` to keep your resolver. See
[CONFIGURATION.md](CONFIGURATION.md#vpn-fortinet-openvpn-wireguard-or-inode).

### 3.6 Calibrate the monitor (if not 1920×1080)

```bash
sudo -u soc /opt/soc-display/bin/soc-wall wm-rc openbox \
  --panels /etc/soc-display/panels.yaml \
  --template /opt/soc-display/openbox/rc.xml.tmpl \
  --out ~soc/.config/openbox/rc.xml --width <W> --height <H>
```

### 3.7 Reboot

```bash
sudo systemctl reboot
```

The wall comes up automatically: tty1 → `startx` → Openbox → four logged-in
panels, hands-free.

---

## 4. Bring-up checklist

- [ ] `systemctl status vaultwarden` active; `curl 127.0.0.1:8222/alive` → 200
- [ ] `journalctl _UID=$(id -u soc)` shows `[pN] injected login` for all panels
- [ ] `systemctl status autossh-tunnel` active (if tunnels) and `nc -z 127.0.0.1 191xx`
- [ ] `systemctl status forti-vpn` active (if VPN) and `ip a show ppp0` has an address
- [ ] each VPN-side panel host answers from the Pi (`nc -z <host> <port>`)
- [ ] `zramctl` shows an active zram swap device
- [ ] no credentials appear in `journalctl` (incl. `journalctl -u forti-vpn`)
- [ ] the master password is **sealed** (`soc-wall setup first-run`); the one-time PIN is recorded off-device

---

## 5. Changing things later

Re-run the wizard (it loads your current answers as defaults):

```bash
soc-wall setup                 # all sections
soc-wall setup wizard --section panels   # just edit the panels
soc-wall setup wizard --section vpn      # just edit the VPN
```

> In production the wall reads its config from the Vaultwarden `SOC Wall Config`
> note, so after a local edit re-push it with `sudo soc-wall setup deploy` — or
> edit live from the on-screen ⚙ Settings, which writes changes back to the note
> automatically.

Then restart the host without rebooting (the launcher loop restarts it):

```bash
sudo pkill -f host.main
# tunnel / VPN service changes:
sudo systemctl restart autossh-tunnel forti-vpn
```

---

## 6. Troubleshooting

| Symptom | Where to look |
|---|---|
| A panel never logs in | `selectors`/`login_marker` vs the real page; `journalctl` for `[pN] injected login` |
| A panel renders blank in WebKit | set that panel's `engine: chromium` |
| Tunneled panel shows connection error | `systemctl status autossh-tunnel`; jump key/`permitopen`; `nc -z 127.0.0.1 191xx` |
| VPN won't connect | `journalctl -u forti-vpn`; check `vpn.trusted_cert`, gateway/port, vault item exists |
| VPN up but lost LAN/SSH | gateway pushed a default route — set `half_internet_routes: true` / `set_routes: false` |
| Windows not in 2×2 | re-run `gen-openbox-rc.py` with the real `--width/--height` |
| OOM / sluggish | confirm zram (`zramctl`); lower panel refresh; prefer `engine: webkit` |

More detail: [INSTALL.md](INSTALL.md) · [CONFIGURATION.md](CONFIGURATION.md) ·
[SECURITY.md](SECURITY.md) · [DEVELOPMENT.md](DEVELOPMENT.md).
