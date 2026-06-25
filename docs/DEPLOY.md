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
sudo ./install.sh                 # packages, users, /opt + /etc, systemd units, autologin
sudo python3 setup.py             # menu → Configure (panels.yaml + soc.env)
sudo python3 setup.py first-run   # one-time PIN + seal the master password
sudo python3 setup.py doctor
```

The installer picks the display stack at runtime (`SOC_SESSION=auto` →
Wayland → XWayland → XLibre → Xorg); force one with `SESSION=...` if needed.

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
