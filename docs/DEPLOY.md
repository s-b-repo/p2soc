# Production deploy

The real install on a Raspberry Pi / kiosk box, where systemd autostarts the
wall on boot and restarts it after a crash. The dev `make dev` runner is for a
workstation only; production is `install.sh` + systemd.

## 0. Prereqs

- A supported distro (see [INSTALL.md](INSTALL.md) — apt/dnf/pacman/zypper/apk/xbps),
  64-bit recommended, an HDMI monitor, network, SSH.
- Copy this repo to the box and `cd` into it.

## 1. One command

```bash
sudo python3 setup.py deploy        # or run `setup.py` and pick "Deploy" from the menu
```

End-to-end: OS installer → config wizard → start Vaultwarden → **seal the master
password (one-time PIN)** → push the config + logins into the vault → `doctor`.
Add `--clean` to wipe generated config/state first. On a box that is already
installed, deploy **skips the slow OS-package step** (it asks first; pass
`--fresh` to force a full reinstall). The manual equivalent:

```bash
sudo ./install.sh                 # packages, users, /opt + /etc, systemd units, launcher
sudo python3 setup.py             # menu → Configure (panels.yaml + soc.env)
sudo python3 setup.py first-run   # one-time PIN + seal the master password
sudo python3 setup.py doctor
```

The installer picks the display stack at runtime (`SOC_SESSION=auto` →
Wayland → XWayland → XLibre → Xorg); force one with `SESSION=...` if needed.

### Desktop vs kiosk mode (`INSTALL_MODE`)

`install.sh` honours `INSTALL_MODE=desktop|kiosk` (**default `desktop`**):

```bash
sudo INSTALL_MODE=desktop ./install.sh   # default: coexist with the desktop
sudo INSTALL_MODE=kiosk   ./install.sh   # dedicated tty1-autologin appliance
```

- **`desktop`** — deploy everything (packages, users, `/opt` + `/etc`, systemd
  units, the launcher icon) but **don't touch the boot**: the default systemd
  target and tty1 autologin are left alone, so the existing DE/login manager
  keeps working. Launch the wall on demand from the **desktop icon** or
  `systemctl start soc-wall`.
- **`kiosk`** — the appliance takeover: enable tty1 autologin + the multi-user
  target so the box boots straight into the wall, hands-free (the original boot
  target is saved so uninstall can restore it).

You can switch later by re-running `install.sh` with the other `INSTALL_MODE`.

### The clickable launcher

Both modes install a **desktop entry** (`soc-wall.desktop`) that opens a small
GTK chooser (`scripts/soc-wall-menu` → `kiosk-host/host/launchermenu.py`) with
three actions: **Setup**, **Desktop mode** (windowed), and **Kiosk mode**
(fullscreen). This is the everyday entry point in desktop installs — no terminal
needed. (The launcher's "Setup" entry is the graphical front door; the full GUI
setup wizard is still in progress.)

## 2. Configure (the wizard does this)

The wizard writes, with input validation:

- **`/etc/soc-display/panels.yaml`** — your panels (URL or tunnel, `vault_item`,
  selectors), plus `tunnel` / `vpn` / `proxy`. See [CONFIGURATION.md](CONFIGURATION.md).
  In production this is pushed into the Vaultwarden `SOC Wall Config` note (the
  boot source of truth); the file is the offline fallback.
- **`/etc/soc-display/soc.env`** — `SOC_VAULT_EMAIL/URL`, `SOC_SECRET_DIR`,
  `SOC_CONFIG_VAULT_ITEM`, `SOC_SESSION` (**non-secret**; the master password is
  sealed by `setup.py first-run`, never stored here).
- **Vaultwarden** — config inline in its systemd unit (no `.env`): localhost, signups off, `/admin` off.

You can also point tiles at URLs + set their vault logins later from the
on-screen **⚙ Settings** (top bar, optional PIN lock).

## 3. Vaultwarden + credentials

All secrets live in Vaultwarden (the wall reads them via `litebw`). There is **no
plaintext secret on disk** — the vault master password is sealed host-bound
(`setup.py first-run`; see [SECURITY.md](SECURITY.md)).

```bash
sudo systemctl start vaultwarden
# create the kiosk account (email = SOC_VAULT_EMAIL) in the web vault
# (http://<host>:8222 over an SSH tunnel), then:
python3 setup.py creds          # stores a username+password per vault_item
```

`setup.py creds` writes the logins into Vaultwarden for you (panels, `vpn`,
`proxy`). Prefer the web vault? Just create one login per `vault_item` name. For
OpenVPN/WireGuard with `config_from_vault`, paste the `.ovpn`/`.conf` into that
item's **Notes**. Then set `SIGNUPS_ALLOWED=false` and restart Vaultwarden.

## 4. Check, then reboot

```bash
sudo python3 setup.py doctor    # all green?
sudo systemctl reboot
```

The wall comes up on tty1 → session dispatcher → compositor/X → logged-in panels,
and self-heals (the launcher restarts the host with backoff; `forti-vpn.service`
reconnects; the panels reload on crash).

## Troubleshooting + repair

```bash
python3 setup.py doctor   # diagnose: deps, venv, config, vault, services, perms
sudo python3 setup.py repair   # install missing packages, recreate venv, fix perms,
                               # generate the tunnel key, …
journalctl -t soc-kiosk -f     # the wall's own log
journalctl -u forti-vpn -f     # VPN supervisor (STATUS= in systemctl status)
```

`doctor` checks each of: venv + `gi`/WebKit2/yaml imports, `litebw`, the VPN client
for your `vpn.type`, an X server / Wayland compositor for `SOC_SESSION`,
`panels.yaml` parses, **autossh** + the tunnel key, Vaultwarden reachable, the
**sealed master password (it test-unseals — catching `machine-id` drift)**, the
config source, file perms, and the systemd units.

## Bring-up checklist

- [ ] `setup.py doctor` is all-green (or only expected WARNs)
- [ ] the master password is **sealed** (`setup.py first-run`); the one-time PIN is recorded off-device
- [ ] `systemctl status vaultwarden` active; `curl 127.0.0.1:8222/alive` → 200
- [ ] a Vaultwarden login exists for every `vault_item` (`setup.py creds` or web vault)
- [ ] `journalctl -t soc-kiosk` shows `[pN] injected login` for the auto-login panels
- [ ] VPN (if used): `systemctl status forti-vpn` STATUS reads "Tunnel up"; pill is green
- [ ] tunnel key (if used) is `permitopen`-restricted on the jump host
- [ ] reboot ×3 → the wall returns fully logged-in, hands-free

## Installing from a package (deb / rpm / apk)

Instead of running `install.sh` from a checkout, you can install a prebuilt
package. CI builds them on a `vX.Y.Z` tag (`.github/workflows/release.yml`, via
nfpm) and attaches them — plus a source tarball and `SHA256SUMS` — to the GitHub
Release:

- **deb** — `arm64` (Pi 5), `armhf`, `amd64`
- **rpm** — `aarch64`, `x86_64`
- **apk** — `aarch64`, `x86_64`

```bash
sudo apt install ./p2soc_1.0.0-1_arm64.deb     # Debian/Raspberry Pi OS/Ubuntu
sudo dnf install ./p2soc-1.0.0-1.aarch64.rpm   # Fedora/RHEL/openSUSE
sudo apk add --allow-untrusted ./p2soc-1.0.0-r1_aarch64.apk
```

The package lays down `/opt/soc-display`, the units and the launcher; its
post-install hook (`packaging/postinstall.sh`) wires up the rest. Packages
default to **desktop** mode (they don't hijack the boot). After install, finish
on the box exactly as for a checkout:

```bash
sudo python3 /opt/soc-display/setup.py first-run   # seal the master password
sudo python3 /opt/soc-display/setup.py doctor
```

Prefer `install.sh` when you need `INSTALL_MODE=kiosk`, an unsupported distro
(`SOC_SKIP_PACKAGES=1`), or to deploy straight from a local checkout.

## Uninstall / revert

```bash
sudo ./uninstall.sh            # or: make uninstall
sudo ./uninstall.sh --purge    # or: make uninstall ARGS="--purge"
```

`uninstall.sh` is **manifest-driven** — `install.sh` records what it changed in
`/etc/soc-display/.install-manifest` (paths, users, the saved default boot
target, whether it flipped the boot target / wrote the getty override). The
uninstaller reads that to cleanly reverse the install and **restore the original
boot target** (relevant only for a `kiosk` install). It's idempotent: safe to
re-run.

By default it **preserves operator data** — the `soc`/service/Vaultwarden users
and their homes, `/etc/soc-display` (panels.yaml, soc.env, the sealed secrets)
and `/var/lib/vaultwarden` (the vault) are kept. Pass **`--purge`** to also wipe
those (one explicit confirmation; add `--force` for unattended). A package
install removes the same way via the package manager (`apt remove p2soc`, etc.),
whose pre-remove hook calls the same revert logic.

## Rebranding

The product name, tagline, icon and accent colours come from one file —
`branding/branding.yaml` (read by `host/branding.py`) — and flow into the
launcher, the desktop entry (generated at install time) and the setup screens.
Override per-host with `/etc/soc-display/branding.yaml` or by pointing
`SOC_BRANDING_FILE` at your own copy; the icon is `share/icons/soc-wall.svg`.
Edit the file, re-run `install.sh` (or restart the launcher) and the new
branding shows up everywhere — no code changes.
