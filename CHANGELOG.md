# Changelog

All notable changes to **p2soc** (the SOC video-wall kiosk). Format follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0.

## [Unreleased]

Production-hardening pass on top of the initial single-engine wall: multi-distro
+ multi-display-server install, a supervised multi-protocol VPN, an outbound
proxy, on-screen configuration, self-healing panels, and hardware auto-tuning.

### Added

- **iNode client bundled.** The headless H3C iNode SSL-VPN client (the clean-room
  `h3csvpn` backend + `svpn-connect.sh` + helpers) ships in `vendor/iNode-VPN-Client`
  and installs to `/opt/soc-display/vendor/…`, so `vpn.type: inode` works out of the
  box — `vpn.config` is now optional (defaults to the bundled client; set it only to
  point elsewhere). The Qt GUI and large assets are not vendored.
- **iNode auto-reconnect.** The supervisor classifies iNode's keepalive heartbeat
  death ("going offline"), a forced log-off, and socket close as a disconnect and
  reconnects — the same liveness logic as the iNode client itself (which exits on
  a dead tunnel rather than reconnecting). The SSL-VPN self-heals with no
  `ready_probe` required; covered by a reconnect case in `make verify-vpn`.
- **VPN configurable from the on-screen ⚙ Settings.** A new **VPN** tab edits the
  supervised VPN (type incl. iNode, gateway, vault item, config, domain, cert pin,
  ready-probe); Apply persists it (overrides + the vault config note) and restarts
  the VPN service. The **Credentials** tab now also lists the VPN + proxy vault
  items, so their username/password go straight into Vaultwarden from the glass —
  every VPN is vault-backed for both config and credentials.
- **iNode (H3C SSL VPN) support** — new `vpn.type: inode`, driven headlessly by the
  bundled `svpn-connect.sh`; a process driver under the same supervisor (backoff,
  auth/cert holds, ready-probe health). Credentials come from the vault
  (`vault_item`) and reach the client only via `$H3C_SVPN_PASSWORD` (never argv);
  `config` points at the iNode-VPN-Client dir; `domain` + `trusted_cert`
  (`--pin-sha256`) / `insecure` cover the gateway. Wizard + `make verify-vpn`
  (fake client) cover it; install.sh adds tesseract for the login CAPTCHA.
- **Faster, idempotent deploy.** `install.sh` stamps `$ETC/.installed` on a
  successful run and **skips the slow OS-package step** on re-runs (the
  package-manager refresh + re-resolution) unless `--fresh` / `SOC_FRESH=1`.
  `setup.py deploy` detects an existing install and **skips it automatically**,
  offering a fresh reinstall (or force with `setup.py deploy --fresh`).
- **Performance + robustness pass (1 GB Pi tuning).** WebKit applies `WebKitMemoryPressureSettings` on low-memory boards (per web/network-process cap + GC thresholds; webkit2gtk-4.1, no-op on 4.0; `SOC_WEBKIT_MEM_LIMIT_MB`) and disables WebGL/WebAudio/media by default — opt back in per panel with `allow_media: true`. Chromium gains `--disable-dev-shm-usage`, `--renderer-process-limit=1` (low-mem) and `--disable-3d-apis` (unless `allow_media`). The vault config note is cached as last-known-good so a boot paints even if the note is briefly unreadable. On-screen ⚙ edits write the merged config **back** into the vault note (off-thread, via `config.to_yaml()`) so it stays the source of truth. `doctor` now test-unseals the secret (catches `machine-id` drift after a re-image) and `repair` converges the sealed-secret dir + rbw pinentry.
- **Secrets + config moved into Vaultwarden; no plaintext `.env`.** The wall
  config now lives in the vault as a `SOC Wall Config` secure-note (the source of
  truth, fetched after unlock; the local `panels.yaml` is the offline fallback),
  and the vault master password is **sealed host-bound** — AES-256-GCM under
  `scrypt(machine-id + a one-time PIN)` (`host/secretstore.py` +
  `scripts/pinentry-vault.py`), useless if copied off the box. `soc.env` holds no
  secret. `setup.py first-run` generates the one-time PIN and seals it; the new
  top-level **menu** (no-arg `setup.py`), `deploy` (end-to-end), `deploy --clean`
  (wipe generated state first), and an autossh-tunnel **doctor** check round it
  out. `cryptography` is now a required dependency.
- **`setup.py` is now an install/diagnose/repair tool**: `wizard` (config, with
  input validation on every field), **`doctor`** (diagnose deps/venv/config/vault/
  services/perms with fix hints), **`repair`** (install missing OS packages via
  `install.sh --deps-only`, recreate the venv, fix perms, generate the tunnel
  key), **`install`** (OS install → wizard → doctor), **`creds`** (store logins).
- **All secrets in Vaultwarden, writable** (`host/vaultseed.py`): setup.py
  (`creds`) and the on-screen Settings can store each panel/VPN/proxy
  username+password (and a VPN config in Notes) directly in Vaultwarden over its
  REST API — the wall still reads via rbw. Optional (`cryptography`); operator
  can still add logins in the web vault. The only on-disk secret is the
  unattended-unlock master password.
- **Tabbed on-screen ⚙ Settings**: Panels (URL/title/vault/engine + advanced
  selectors), Credentials (write to Vaultwarden), Display (layout/gap), Status.
- [**docs/DEPLOY.md**](docs/DEPLOY.md) — the production runbook.
- **On-screen configuration** (`host/configwin.py`): a floating, always-on-top
  panel opened by the corner **⚙** button or **Ctrl+Shift+C**. Set each tile's
  URL, title, and **Vaultwarden login** live; changes apply immediately and
  persist to `~/.config/soc-wall/overrides.json` (`SOC_STATE_DIR`), layered over
  `panels.yaml`. Optional **PIN lock** (salted SHA-256, `0600`) with brute-force
  cooldown. Disable entirely with `SOC_ONSCREEN_CONFIG=0`.
- **Display-first schema**: panels may ship unconfigured (no `url`) and
  display-only (no `vault_item`); a tile then shows a "not configured" card until
  set at the glass. New per-panel keys `title`, `allow_insecure` (accept
  self-signed TLS on a trusted LAN), and the universal `config/panels.live.yaml`.
- **Outbound proxy** (`proxy:` section): HTTP(S)/SOCKS for the panel browsers,
  per-panel opt-out. **Authenticated proxies** answer their `407` in memory —
  WebKit `authenticate` signal, Chromium CDP `Fetch.authRequired` — with
  credentials from `proxy.vault_item`; never on argv/disk. Loopback always
  bypassed. Dev harness: `dev/auth-proxy.py` + `make verify-proxy`.
- **Multi-protocol VPN** (`vpn.type: fortinet | openvpn | wireguard`,
  `host/vpndrivers.py`): one supervisor now drives all three. OpenVPN injects
  username/password over its **management socket** (in a `0700` dir); WireGuard
  is brought up via `wg-quick` with handshake/`ready_probe` health checks.
  Installer adds `openvpn` + `wireguard-tools`; the wizard asks the type.
  `make verify-vpn` behaviorally tests all three with fake clients.
- **VPN config in the vault** (`config_from_vault: true`): the OpenVPN `.ovpn` /
  WireGuard `.conf` (which hold the client key) can live in the Vaultwarden
  item's Notes; the supervisor materializes it to a transient `0600` file only
  while connecting and deletes it on disconnect. `Vault.notes()` added.
- **On-wall VPN status pill** (`host/vpnstatus.py`): top-of-wall indicator —
  online / offline / not configured — from `ready_probe` (or the tunnel
  interface), click to re-check / reconnect.
- **Smarter auto-login**: heuristic login-form detection (finds the password +
  username field when no `selectors` are set, so tiles set at the glass log in);
  **domain memory** (`host/loginmemory.py`) — a panel with a `vault_item`
  registers its origin (`host:port`), and other panels at the same origin reuse
  that login; an in-page **sign-in popup** when there's no saved login or
  auto-login keeps failing.
- **Always-reachable top bar**: the VPN pill + ⚙ Settings live in a real toolbar
  above the grid (a loaded WebKitWebView is a native window that painted over the
  old floating gear); plus a window-wide Ctrl+Shift+C accelerator.
- **Self-healing panels**: WebKit reloads on renderer crash and retries
  load failures with backoff; Chromium respawns and re-attaches CDP. Per-panel
  **status cards** (`host/style.py`) show connecting / offline / recovering.
- **Hardware auto-tuning** (`host/perf.py`): low-memory profile (lighter WebKit
  cache) auto-enabled ≤1.5 GB RAM; GPU compositing on ARM boards with a render
  node. Overrides: `SOC_LOW_MEMORY`, `SOC_WEBKIT_HWACCEL`. Chromium gets a capped
  disk cache and background networking/sync off.
- **Wayland support**: `single` layout (one fullscreen `GtkGrid`, `host/wall.py`)
  works on any compositor; `cage`/`labwc` session via `scripts/wayland-session.sh`
  with generated window rules (`scripts/gen-labwc-rc.py`); `SOC_COMPOSITOR`
  override; `SOC_SESSION=x11|wayland|auto` dispatcher.
- **More distros + display servers**: Alpine (`apk`) and Void (`xbps`) added to
  the installer (now apt/dnf/pacman/zypper/apk/xbps), plus `SOC_SKIP_PACKAGES=1`
  for anything else. Accepts X.Org **or XLibre**; degrades gracefully on
  non-systemd inits; ARM architecture detection.
- `F11` toggles fullscreen; `make verify-single` / `make verify-proxy` /
  `make gen-labwc` targets.

### Changed

- **VPN is supervised, not exec-once** (`host/fortivpn.py`): classifies the
  client's output, reconnects with exponential backoff, holds ~5 min on auth
  failure (avoids account lockout), speaks the systemd notify/watchdog protocol
  and reports state via `systemctl status`. `forti-vpn.service` is now generic.
- Config validation is collect-everything: one `ConfigError` lists every problem;
  unknown keys become warnings.
- Single-window wall tracks screen-size changes (refills on a resized
  Xephyr/cage, a monitor hotplug, or a mode switch) instead of leaving margins.

### Security

- On-screen config accepts **http(s) only** — `file://`, `javascript:`, `data:`
  URLs are rejected at the overlay, in `set_url`, and when merging saved
  overrides. `overrides.json` is `0600` (internal hostnames stay owner-only).
- Proxy/VPN credentials never reach a command line or disk: proxy auth answered
  in memory; the proxy URL may not embed `user:pass@` (validator rejects it);
  OpenVPN creds go over a `0700` management socket; Fortinet via pinentry.
- PIN stored only as a salted SHA-256 hash with a brute-force cooldown.
- `forti-vpn.service` keeps `/dev` open for `/dev/ppp` + `/dev/net/tun` without
  switching to device-whitelist mode (which could starve a backend).

### Changed (display stack)

- `SOC_SESSION` is now a launch option with an automatic fallback chain
  (`auto`, the new default): at startup the wall tries **Wayland → XWayland →
  XLibre → Xorg**, falling through automatically (native Wayland drops to
  XWayland via the launcher; no compositor drops to X11; XLibre preferred over
  X.Org when present). Force a stage with `wayland`/`xwayland`/`xlibre`/`xorg`/
  `x11`; override the X server with `SOC_XSERVER`.

### Fixed

- **Settings unreachable after a panel loaded** — the gear + VPN pill moved from
  a GTK overlay (which a native-window WebKitWebView paints over) into a real top
  toolbar above the grid; plus a window-wide Ctrl+Shift+C accelerator.
- **Lost-update / clobber race** in the domain-login store (written from the GTK
  thread *and* Chromium control threads) — now a lock + unique temp file.
- **UI stall on login** — `need_login` ran `rbw` on the GTK thread; credentials
  are now prewarmed in parallel off-thread and the cache is thread-safe.
- **UI freeze** — the VPN pill's `systemctl restart` ran on the GTK thread; moved
  off-thread (and the credential write in Settings runs off-thread too).
- **Auto-login attempt counter crept to the popup threshold** over a long session
  for navigation-based logins; the bootstrap now reports the login state on every
  page, resetting it and recording the domain.
- WebKit error pages no longer flash over the status card: `load-failed` returns
  `TRUE` and a failed `FINISHED` no longer clears the card.
- Status cards render via a `Gtk.Stack` (not an overlay), which native-window
  WebKit views paint over.
- Chromium proxy-auth navigates from a dark placeholder (not `about:blank`, which
  demoted `--app` to a tabbed window) and settles before disabling interception.
