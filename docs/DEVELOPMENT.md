# Development

You can build and verify ~90% of `p2soc` on an x86 Linux workstation against
dummy panels — no Pi or real infrastructure required.

## Requirements

- `python3`, `python3-gi`, `gir1.2-gtk-3.0`, `gir1.2-webkit2-4.1` (or `4.0`)
- `Xvfb` and/or `Xephyr`, `chromium`, ImageMagick (`import`) for screenshots
- optional: `docker` + `rbw` to exercise the real Vaultwarden path

## Make targets

| Target | What |
|---|---|
| `make venv` | create the venv (`--system-site-packages` for PyGObject/WebKit) |
| `make dev-vault` | write `dev/run/dev-vault.json` (dev vault backend; no server) |
| `make verify` | **headless** end-to-end: dummy panels + host under Xvfb; asserts logins, tunnel gate, Chromium CDP; writes `dev/run/verify.png` |
| `make verify-single` | **headless** check of the single-window (Wayland) layout — all panels in one fullscreen grid window |
| `make verify-proxy` | **headless** check of the authenticated-proxy path: panels reach unresolvable hostnames *only* via the dev auth-proxy, exercising WebKit + Chromium vault-backed proxy auth and the loopback bypass |
| `make vpn-check` | dry-run the Fortinet VPN: resolve vault creds + print the openfortivpn command (no connect; password never shown) |
| `make verify-vpn` | behavioral check of **all three** VPN backends (fortinet/openvpn/wireguard) with fake clients: log classification, mgmt-socket creds, config-from-vault, connect/reconnect |
| `make gen-labwc` / `make gen-openbox` | render the Wayland/X11 window-placement rules from `config/panels.yaml` |
| `make dev` | **interactive**: the wall in a Xephyr window (Openbox if installed) |
| `make vault` | start Vaultwarden in Docker, register an account, seed via API, verify `rbw` reads it |
| `make test` | unit tests (geometry, injection escaping, vault, config validation, VPN supervisor, proxy, perf, WM generators) |
| `make lint` | `bash -n` + `py_compile` everything |
| `make clean` / `make distclean` | stop dev procs / also remove venv + Docker container |

## How the dev harness works

```
dev/dummy-panels/server.py   4 login-protected panels on 127.0.0.1:9001-9004
                             p1 hard-expires every 60s (tests re-login)
                             p2 exposes /api/ping (tests xhr keepalive)
                             p4 renders a live chart (tests RAM/CPU)
dev/tcp-forward.py           stands in for an autossh -L tunnel (19102 -> 9002)
dev/seed-ciphers.py          seeds Vaultwarden via REST (rbw `add` needs a TTY)
dev/register-vaultwarden.py  PBKDF2 account registration for CI/dev
dev/verify.sh                the automated end-to-end check `make verify` runs
dev/run-wall.sh              the interactive runner `make dev` runs
```

The **dev vault backend** (`SOC_VAULT_BACKEND=dev`) reads creds from a JSON file
so the whole host runs without Vaultwarden. The **rbw backend** (default, prod)
shells out to `rbw`. `dev/run/` is gitignored — all runtime state lives there.

## Two engines, one injection

Both engines inject the same `inject/login.js.tmpl` bootstrap (rendered by
`host/inject.py`):

- **WebKit** (`host/webkit_panel.py`): the bootstrap posts to the `socCreds`
  message handler → the host evaluates `socLogin({user,pass})`.
- **Chromium** (`host/chromium_panel.py`): the bootstrap is installed via CDP
  `Page.addScriptToEvaluateOnNewDocument`; the host polls `window.__SOC.needLogin`
  and evaluates `socLogin(...)` over the DevTools Protocol on localhost.

## Useful env vars

| Var | Purpose |
|---|---|
| `SOC_PANELS_FILE` | which config to load (`config/panels.dev.yaml`, etc.) |
| `SOC_VAULT_BACKEND` | `rbw` (prod) or `dev` (JSON file) |
| `SOC_DEV_VAULT` | path to the dev vault JSON |
| `SOC_CHROMIUM_NO_SANDBOX=1` | **dev only** — Chromium can't sandbox in some CI envs |
| `SOC_LAUNCH_STAGGER` / `SOC_READY_TIMEOUT` | launch pacing / readiness gate |
| `SOC_LAYOUT` | force `windows`/`single` (the session scripts set this; e.g. cage uses `single`) |
| `SOC_LOW_MEMORY` / `SOC_WEBKIT_HWACCEL` | force the low-memory profile / WebKit GPU policy (default auto-detected) |
| `SOC_COMPOSITOR` | force a specific Wayland compositor (e.g. `cage`, `sway`) |
| `SOC_DRY_RUN=1` | print the resolved plan (engines, URLs, geometry) and exit |

## Gotchas

- **WebKit2 typelib** is `4.1` on Pi OS Bookworm but may be `4.0` elsewhere — the
  code tries 4.1 then falls back.
- If the working directory path contains a **space**, `rbw`'s `$EDITOR`-based
  `add` and `sshd_config` paths break — the Pi install path `/opt/soc-display` has
  none. Seed Vaultwarden via `dev/seed-ciphers.py`, not `rbw add`.
- Keep the Chromium **sandbox on** in production (never set `--no-sandbox`).
