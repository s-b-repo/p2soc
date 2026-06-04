# Installing on a Raspberry Pi 5

Target: **Raspberry Pi 5 (1 GB+)**, Raspberry Pi OS (64-bit, Bookworm), HDMI
monitor. The installer keeps your preloaded card and simply **disables the
desktop session** (reversible) instead of reflashing to Lite.

## 1. Prepare the Pi

1. Flash / boot Raspberry Pi OS 64-bit, enable SSH, connect to the network.
2. Copy this repo to the Pi (e.g. `scp -r p2soc pi@<ip>:` or `git clone`).
3. SSH in.

## 2. Run the installer

```bash
cd p2soc
sudo ./install.sh
```

Knobs (env vars):

| Var | Default | Meaning |
|---|---|---|
| `VW_MODE` | `docker` | `docker` (official image) or `native` (binary at `/usr/local/bin/vaultwarden`) |
| `HARDEN` | `0` | `1` also installs the nftables firewall + key-only sshd |
| `KIOSK_USER` | `soc` | kiosk login user (autologin on tty1) |
| `SVC_USER` | `socsvc` | service user that owns the autossh tunnel |

The installer is **idempotent** — safe to re-run. It installs deps, creates the
users, deploys to `/opt/soc-display`, builds the venv, lays down
`/etc/soc-display`, installs the systemd units, configures zram, generates the
Openbox 2×2 layout, and enables tty1 autologin.

## 3. Configure (the installer prints this list)

1. **`/etc/soc-display/panels.yaml`** — your 4 panels: IPs/ports, **selectors**,
   `vault_item` names, and any `tunnel`. See [CONFIGURATION.md](CONFIGURATION.md).
2. **`/etc/soc-display/soc.env`** — `SOC_VAULT_PASSWORD`, `SOC_VAULT_EMAIL`,
   `SOC_VAULT_URL` (`chmod 0640`).
3. **`/etc/soc-display/vaultwarden.env`** — set `ADMIN_TOKEN` (`vaultwarden hash`).

## 4. Create the vault + add logins

```bash
sudo systemctl start vaultwarden
```

Open the Vaultwarden web vault (over an SSH tunnel for safety:
`ssh -L 8222:127.0.0.1:8222 pi@<ip>` then browse `http://127.0.0.1:8222`), create
the kiosk account (matching `SOC_VAULT_EMAIL`), then add one **login item per
panel, named exactly to match its `vault_item`**, with the username/password the
panel expects. Set `SIGNUPS_ALLOWED=false` in `vaultwarden.env` afterwards.

## 5. Tunnel key (if any panel uses `mode: tunnel`)

Follow [`security/tunnel_key.note`](../security/tunnel_key.note): generate a
restricted ed25519 key as `socsvc`, point `tunnel.identity` at it, and add it to
the jump host's `authorized_keys` with `restrict,permitopen="host:port",…`.

## 6. Calibrate the monitor (if not 1920×1080)

```bash
sudo -u soc /opt/soc-display/.venv/bin/python \
  /opt/soc-display/scripts/gen-openbox-rc.py \
  --panels /etc/soc-display/panels.yaml \
  --template /opt/soc-display/openbox/rc.xml.tmpl \
  --out ~soc/.config/openbox/rc.xml --width 1920 --height 1080
```

## 7. Reboot

```bash
sudo systemctl reboot
```

The wall comes up automatically: tty1 → `startx` → Openbox → four logged-in
panels in a 2×2 grid, no manual steps.

## Bring-up checklist

- [ ] `systemctl status vaultwarden` is active; `curl 127.0.0.1:8222/alive` → 200
- [ ] `journalctl _UID=$(id -u soc)` shows `[pN] injected login` for all 4 panels
- [ ] `systemctl status autossh-tunnel` active (if tunnels configured)
- [ ] each tunneled panel's port answers: `nc -z 127.0.0.1 191xx`
- [ ] `zramctl` shows an active zram swap device
- [ ] reboot ×3 → the wall returns fully logged-in, hands-free
- [ ] `vcgencmd measure_temp` + `free -m` look healthy under sustained load

## Verifying a change

After editing `panels.yaml`, restart the host without rebooting:

```bash
sudo pkill -f host.main      # launcher.sh restarts it automatically
```
