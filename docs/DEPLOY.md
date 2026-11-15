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

End-to-end: OS installer → config wizard → start Vaultwarden → create the account →
seal the master password (one-time PIN) → push the config + logins into the vault →
`doctor` → **start the wall**. There is nothing to do afterwards: no reboot, no account
to create by hand. From then on the box runs itself; see
[AUTO_UPDATE.md](AUTO_UPDATE.md).

Add `--clean` to wipe generated config/state first. On a box that is already
installed, deploy **skips the slow OS-package step** (it asks first; pass `--fresh`
to force a full reinstall).

`install.sh` picks the install mode by itself: **kiosk** on a box with no desktop
environment (it takes over tty1), **desktop** where a display manager is in use, so a
workstation is never hijacked. Force one with `INSTALL_MODE=kiosk|desktop`.

### Scripted, with no prompts at all

For imaging or a fleet, supply everything up front. Secrets arrive over file
descriptors, so they never appear in `ps`, shell history or argv:

```bash
sudo python3 setup.py deploy --unattended \
    --email ops@example.com \
    --config wall.yaml \
    --master-fd 3 3<master.txt \
    --creds-fd 4 4<logins.json
```

`logins.json` holds the panel logins, by `vault_item` name:

```json
{"SOC Panel 1": {"username": "analyst", "password": "..."}}
```

It refuses to run without a master password rather than invent one. A step that fails
stops the deploy, and a re-run picks up where it left off: an existing account is
verified rather than recreated, an existing seal is kept, and a login that is already
in the vault is never blanked. **The output contains the one-time PIN**, so capture it
somewhere safe and don't leave it in a CI log.

The display stack is picked at runtime (`SOC_SESSION=auto` → Wayland → XWayland →
XLibre → Xorg); force one with `SESSION=...` if needed.

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
plaintext secret on disk**: the vault master password is sealed host-bound (see
[SECURITY.md](SECURITY.md)).

Vaultwarden runs natively by default, under a hardened systemd unit. Its binary comes
straight from the official image, pinned by digest in `security/vaultwarden.lock`, with
no Docker daemon on the box. Signups are off, always, except for the seconds it takes
`deploy` to create the one account. That window is opened through a `/run` drop-in, so
even a power cut can't leave it open.

`setup.py creds` stores or changes a login at any time (panels, `vpn`, `proxy`). For
OpenVPN/WireGuard with `config_from_vault`, paste the `.ovpn`/`.conf` into that item's
**Notes**.

## 4. Verify

```bash
sudo python3 setup.py doctor    # all green?
soc-update status               # redeploy is armed, tracking the right ref
```

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
- [ ] the one-time PIN is recorded off-device
- [ ] `journalctl -t soc-kiosk` shows `[pN] injected login` for the auto-login panels
- [ ] VPN (if used): `systemctl status forti-vpn` STATUS reads "Tunnel up"; pill is green
- [ ] tunnel key (if used) is `permitopen`-restricted on the jump host
- [ ] `soc-update status` shows the right repo and ref
- [ ] you've decided on signed commits and a dead-man's switch ([AUTO_UPDATE.md](AUTO_UPDATE.md))
- [ ] reboot ×3 → the wall returns fully logged-in, hands-free
