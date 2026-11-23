# Installing the SOC wall

Primary target: **Raspberry Pi 5 (1 GB+)**, Raspberry Pi OS (64-bit, Bookworm),
HDMI monitor — but the installer runs on any mainstream Linux. It keeps your
existing system intact.

By default (`INSTALL_MODE=auto`) it picks the right behaviour for the box. With no
desktop environment it installs as a **kiosk**: the box autologins on tty1 into its own
session at boot. Where a display manager is in use it installs as **desktop**: it deploys
everything and adds a clickable "SOC Wall" launcher, but leaves the default target and
tty1 alone, so your existing desktop keeps working and you start the wall from the menu.
Either way it is reversible (see [Uninstall](#uninstall)). Force one with
`INSTALL_MODE=kiosk` or `INSTALL_MODE=desktop`.

## Supported distros

Package install is automatic on:

| Family | Package manager | Distros |
|---|---|---|
| debian | `apt` | Debian, Raspberry Pi OS, Ubuntu, Kali |
| fedora | `dnf` | Fedora, RHEL, Rocky, Alma |
| arch | `pacman` | Arch, Manjaro, EndeavourOS |
| suse | `zypper` | openSUSE Leap, Tumbleweed |
| alpine | `apk` | Alpine |
| void | `xbps` | Void |

Any other distro: install the dependencies from the package lists in
`install.sh` by hand, then run with **`SOC_SKIP_PACKAGES=1`** — everything else
(deploy, config, services) is distro-agnostic.

- **CPU**: 64-bit ARM (`aarch64`, e.g. Pi 5) and x86-64 are both first-class; the
  installer detects the arch and warns on 32-bit ARM (WebKitGTK is heavy there).
- **Init**: systemd is preferred (autologin + service supervision). On a
  non-systemd init (OpenRC/runit/…) the installer still deploys everything and
  prints the autostart + supervision snippets you wire up by hand.
- **Display server**: with `SESSION=auto` (default) the wall picks the best
  available stack at launch — **Wayland → XWayland → XLibre → Xorg** — falling
  through automatically (native Wayland drops to XWayland if it can't start; no
  compositor drops to X11; XLibre is preferred over X.Org when present). Force a
  specific stack with `SESSION=`/`SOC_SESSION=` (`wayland`/`xwayland`/`xlibre`/
  `xorg`/`x11`), the compositor with `SOC_COMPOSITOR`, or the X server with
  `SOC_XSERVER`.

## 1. Prepare the machine

1. Install/boot a supported distro, enable SSH, connect to the network.
2. Copy this repo over (e.g. `scp -r p2soc user@<ip>:` or `git clone`).
3. SSH in.

## 2. Run the installer

```bash
cd p2soc
sudo ./install.sh
```

For a source install, put Rust 1.87 or newer on the build user's PATH. The
installer can build the executable when Cargo is available to root. You can
also run `make rust-release` first or use a published package.

Knobs (env vars):

| Var | Default | Meaning |
|---|---|---|
| `INSTALL_MODE` | `auto` | `auto`: kiosk on a box with no desktop environment, else desktop. `desktop`: deploy everything + add the "SOC Wall" menu launcher, but leave the systemd default target and tty1 untouched (your DE keeps working). `kiosk`: also take over tty1 (autologin into the kiosk session) and `set-default multi-user.target` — the dedicated-appliance path |
| `SESSION` | `auto` | display stack: `auto` (install both; at runtime try **Wayland → XWayland → XLibre → Xorg**), or force one of `wayland` / `xwayland` / `xlibre` / `xorg` / `x11` |
| `VW_MODE` | `native` | `native`: hardened unit, with the official binary fetched and pinned by digest, no Docker daemon. `docker`: the same pinned image under the distro's Docker |
| `HARDEN` | `0` | `1` also installs the nftables firewall + key-only sshd |
| `KIOSK_USER` | `soc` | kiosk login user (autologin on tty1) |
| `SVC_USER` | `socsvc` | service user that owns the autossh tunnel |
| `COMPOSITOR` | `labwc` | Wayland compositor to install (e.g. `sway`); runtime override is `SOC_COMPOSITOR` |
| `SOC_SKIP_PACKAGES` | `0` | `1` to skip all OS-package installs (deps already present / unknown distro) |

The installer is **idempotent** — safe to re-run. It installs deps, creates the
users, deploys the Rust binary to `/opt/soc-display/bin/soc-wall`, lays down
`/etc/soc-display`, installs the systemd units (or prints the manual equivalents
without systemd), configures zram, generates the 2×2 layout, and installs the
"SOC Wall" menu launcher. In **kiosk** mode it additionally enables tty1
autologin and sets `multi-user.target` as the default; in the default
**desktop** mode it does neither (your DE is untouched). The chosen `SESSION` is
written to `soc.env` as `SOC_SESSION` and can be changed there any time.

The installer records every file it lays down and every system change it makes
in a manifest at `/etc/soc-display/.install-manifest` — that is what
[`uninstall.sh`](#uninstall) replays to revert cleanly.

### Launching the wall (desktop mode)

After a desktop-mode install, open your applications menu and click **SOC Wall**
(category: System / Network). The launcher sources `/etc/soc-display/soc.env` and
runs the kiosk host against your **current** display (`$DISPLAY` /
`$WAYLAND_DISPLAY`) — no tty1, no separate login. Run it from a terminal the same
way with `/opt/soc-display/scripts/soc-wall-desktop.sh`. Close the windows to
stop the wall; it leaves your desktop session as it was.

> Easiest path: after the installer, run the guided wizard
> `sudo /opt/soc-display/bin/soc-wall setup deploy` to configure the wall and vault.
> On a desktop, **Setup** offers a per-user configuration and an administrator
> authorization prompt for saving system-wide on an installed host.

## 3. Configure (the installer prints this list)

1. **`/etc/soc-display/panels.yaml`** — your 4 panels: IPs/ports, **selectors**,
   `vault_item` names, and any `tunnel`. See [CONFIGURATION.md](CONFIGURATION.md).
2. **`/etc/soc-display/soc.env`** — `SOC_VAULT_EMAIL`, `SOC_VAULT_URL`,
   `SOC_SECRET_DIR`, `SOC_CONFIG_VAULT_ITEM` (**non-secret**; `chmod 0644`). The
   master password is sealed separately — see step 4b.
3. **Vaultwarden** — config is inline in its systemd unit (no `.env`); `/admin` off.

## 4. Create the vault + add logins

`sudo /opt/soc-display/bin/soc-wall setup deploy` creates the account, then stores
each panel's login under its `vault_item` name, and `vpn.vault_item` too if you enabled
a VPN. To add or change a login later, run `/opt/soc-display/bin/soc-wall setup creds`.

Native Vaultwarden runs without its web interface: the binary is installed alone, and
the kiosk has no use for that surface. Signups stay off except for the moment `deploy`
creates the account.

## 4b. Seal the master password (no plaintext .env)

```bash
sudo /opt/soc-display/bin/soc-wall setup first-run
```

Generates a **one-time PIN** and seals the vault master password host-bound under
`/etc/soc-display/secret/` (AES-256-GCM with the private host key, machine ID and PIN); the
default `litebw` backend (and the legacy `rbw` via `pinentry-vault.sh`) unseal it
in memory. Record the PIN — you need it only to re-seal
(re-deploy, new hardware, or changing the password). The wall then self-unlocks at
boot with no prompt and no secret in any `.env`. (`soc-wall setup deploy` runs this as
part of the whole flow.) See [SECURITY.md](SECURITY.md).

## 5. Tunnel key (if any panel uses `mode: tunnel`)

Follow [`security/tunnel_key.note`](../security/tunnel_key.note): generate a
restricted ed25519 key as `socsvc`, point `tunnel.identity` at it, and add it to
the jump host's `authorized_keys` with `restrict,permitopen="host:port",…`.

## 5b. Fortinet VPN (if `vpn.enabled`)

Set the `vpn` section of `panels.yaml` (gateway, `vault_item`, and ideally
`trusted_cert` to pin the cert — see [CONFIGURATION.md](CONFIGURATION.md)). The
installer enables `forti-vpn.service` automatically when `vpn.enabled` has a
gateway. The service runs a **supervisor** that classifies openfortivpn's output,
reconnects with backoff, and holds for ~5 min on an auth failure (so a bad
password can't lock the FortiGate account). It reads the login from Vaultwarden
and supplies the password through pinentry. Check it:

```bash
sudo systemctl status forti-vpn    # the STATUS= line shows the live state
journalctl -u forti-vpn -f         # classified events: "Tunnel is up", auth/cert errors
```

(No systemd? Run `sudo /opt/soc-display/scripts/forti-vpn.sh` under your init.
It supervises its VPN clients.)

## 5c. Proxy (if `proxy.enabled`)

If the panels reach the internet through a corporate proxy, set the `proxy`
section (URL + optional `vault_item` for authentication). Add a vault login for
the proxy credentials named to match `proxy.vault_item`. The host answers the
proxy challenge in memory — see [CONFIGURATION.md](CONFIGURATION.md#proxy-outbound-https-socks-proxy).

## 6. Monitor resolution

No manual calibration needed: with `display.auto: true` the X11 session
regenerates the Openbox grid from `xrandr` at every start, the Wayland session
does the same for labwc, and the single-window layout tracks the real screen
size directly. Just plug in any HDMI monitor.

## 7. Start it

`soc-wall setup deploy` starts the wall on a kiosk installation.
To run the steps by hand instead, finish with a reboot:

```bash
sudo systemctl reboot     # or: reboot  (non-systemd)
```

**Kiosk mode:** the wall comes up automatically: tty1 → session dispatcher →
(`startx` → Openbox, or cage/labwc on Wayland) → four logged-in panels in a 2×2
grid, no manual steps.

**Desktop mode:** the machine boots back into your normal desktop; launch the
wall when you want it from the **SOC Wall** menu icon (see above). No reboot is
required to start it.

## Uninstall

The install is fully reversible via the manifest-driven uninstaller:

```bash
sudo ./uninstall.sh          # or: sudo make uninstall
```

By default it **preserves operator data**: the `soc`/`socsvc` users, the
`/etc/soc-display` secrets (sealed master password, config), and the Vaultwarden
data at `/var/lib/vaultwarden` are kept, so you can re-install without re-sealing
the vault. Everything else the installer added is reversed: it stops/disables the
units and removes them, removes the `/opt/soc-display` tree, the `litebw`
launcher, the "SOC Wall" menu entry, and — if this was a **kiosk** install —
restores the previous systemd default target and removes the tty1 autologin
drop-in, handing the console back to your DE/login manager.

To wipe everything, including the operator data above:

```bash
sudo ./uninstall.sh --purge      # or: sudo make uninstall PURGE=1
```

`--purge` additionally deletes `/etc/soc-display`, the Vaultwarden data
directory, and the kiosk/service users. Use it only when you are decommissioning
the box — sealed vault credentials are gone after a purge.

> Without systemd, the uninstaller reverses the file deploy and prints the
> autostart/supervision lines to remove by hand, mirroring the install.

## Bring-up checklist

- [ ] `systemctl status vaultwarden` is active; `curl 127.0.0.1:8222/alive` → 200
- [ ] `journalctl -t soc-kiosk` shows `[pN] injected login` for all 4 panels
- [ ] `systemctl status autossh-tunnel` active (if tunnels configured)
- [ ] each tunneled panel's port answers: `nc -z 127.0.0.1 191xx`
- [ ] `systemctl status forti-vpn` active (if VPN configured); its `STATUS=` line
      reads "Tunnel up"; `ip a show ppp0` has an address
- [ ] each VPN-side panel host answers from the box (e.g. `nc -z <vpn-host> <port>`)
- [ ] if a proxy is set: panels render and `journalctl -t soc-kiosk` shows
      `proxy auth answered` (when `proxy.vault_item` is used)
- [ ] `zramctl` shows an active zram swap device
- [ ] reboot ×3 → the wall returns fully logged-in, hands-free
- [ ] `vcgencmd measure_temp` (Pi) + `free -m` look healthy under sustained load

> Without systemd, swap the `systemctl status` checks for your init's status
> command, and tail the launcher's stdout/syslog instead of `journalctl`.

## Verifying a change

After editing `panels.yaml`, choose **Restart wall** in Settings or restart the
service that owns the kiosk session. For a tty1 installation:

```bash
sudo systemctl restart getty@tty1.service
```
