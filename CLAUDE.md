# p2soc — SOC Video Wall (Raspberry Pi 5)

Raspberry Pi 5 (1 GB) kiosk that boots into a 2x2 grid of browser windows showing SOC panels (Wazuh, Zabbix, etc.). Auto-logs in from a local Vaultwarden, self-heals crashed panels, reconnects VPN/tunnels.

## Project layout

```
kiosk-host/host/     Python kiosk host (PyGObject/WebKitGTK + Chromium/CDP)
kiosk-host/tests/    Unit tests (pytest)
config/              Panel configs (panels.yaml variants)
scripts/             Session startup, VPN, tunnel, pinentry helpers
dev/                 Dev harness: verify.sh, dummy panels, seed-ciphers
docs/                Architecture, config, deploy, security docs
inject/              login.js.tmpl — injected login bootstrap
security/            sysctl, nftables, sshd hardening
systemd/             Service units (vaultwarden, autossh, forti-vpn, autologin)
setup.py             Multi-mode wizard (wizard/doctor/repair/deploy/creds/first-run)
install.sh           Multi-distro installer (apt/dnf/pacman/zypper/apk/xbps)
launch.sh            Boot entrypoint
```

## Build / test commands

```bash
make venv            # create .venv (system-site-packages for PyGObject)
make test            # unit tests (no display needed)
make lint            # shell + python syntax check
make verify          # headless e2e (Xvfb, 4 panels, auto-login, screenshot)
make verify-single   # single-window Wayland layout check
make verify-proxy    # authenticated proxy path check
make verify-vpn      # all 3 VPN backends (fortinet/openvpn/wireguard) with fakes
make dev             # interactive dev in Xephyr
make vault           # start Vaultwarden in Docker + seed via litebw
make dev-vault       # write dev vault JSON (no Docker needed)
make install         # install on the Pi (sudo)
```

## Key architecture

- **Renderer:** WebKitGTK primary, Chromium opt-in per panel (`engine: chromium`)
- **Login injection:** host-side (WebKit socCreds handler, Chromium CDP) — no extensions/brokers
- **Secrets:** all in Vaultwarden, master password sealed host-bound (AES-256-GCM, scrypt)
- **Config source of truth:** Vaultwarden secure-note (`SOC_CONFIG_VAULT_ITEM`), panels.yaml fallback
- **VPN:** `vpn.type: fortinet|openvpn|wireguard` — supervised, log-classifying, auto-reconnect
- **Display:** X11 (Openbox) or Wayland (cage/labwc), `SOC_SESSION=auto` fallback chain
- **No .env secrets:** soc.env is non-secret; vault master sealed under `$SOC_SECRET_DIR`

## Conventions

- Pure stdlib for setup.py (runs before venv)
- `config/panels.yaml` is the reference config; `panels.local.yaml` for local overrides
- `.env` / `vaultwarden.env` contain actual secrets — NEVER commit (gitignored)
- Tests run with `SOC_VAULT_BACKEND=dev` and a JSON file vault
- Multi-distro: install.sh detects package manager; `SOC_SKIP_PACKAGES=1` for unsupported
- Non-systemd graceful: deploys files, prints manual steps
