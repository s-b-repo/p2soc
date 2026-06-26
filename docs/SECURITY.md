# Security model

`p2soc` is an **unattended** appliance: it must boot and log into four panels with
no human present. That goal sets the security envelope — read this before
deploying anywhere sensitive.

## What protects the credentials

- **Vault on localhost.** Vaultwarden binds `127.0.0.1:8222`. Nothing SOC-related
  listens on the LAN.
- **No broker, no port, no page fetch.** The kiosk host reads creds via `litebw` and
  injects them into each view itself (WebKit `socCreds` message handler; Chromium
  CDP). Credentials never traverse a network socket or page-context `fetch`.
- **CDP debugger locked to the host.** The Chromium control channel binds
  `127.0.0.1` and `--remote-allow-origins` is pinned to the exact
  `http://127.0.0.1:<port>` the host connects from — never `*`. Because browsers
  forbid page JS from forging the `Origin` header, a rendered dashboard (or XSS
  on a panel) cannot open the DevTools websocket, attach CDP, and read the
  injected credentials of every panel.
- **RAM only.** Creds live in a short-TTL (~30 s) in-memory cache in the host
  process; the host never writes them to disk and never logs them. The host
  scrubs its copy right after injecting.

## The unattended-unlock model (read this)

There is **no plaintext master password on disk** and **no secret in any
`.env`**. The vault master password is sealed with AES-256-GCM under a key
derived (scrypt) from this host's `machine-id` **and** a one-time PIN that
`setup.py first-run` generates and shows you once (`host/secretstore.py`). The
PIN is itself sealed under a machine-id-only key, so the wall self-unlocks at
boot with no prompt, while the sealed files (`/etc/soc-display/secret/*.enc`,
`0600`, owned by the kiosk user) are **useless if copied to another machine** — a
different `machine-id` makes the GCM authentication fail. `litebw` (default) — or
the legacy `rbw` — gets the master password from `scripts/pinentry-vault.py`,
which unseals it in memory.

The wall **config** is the vault's too: a secure-note (`SOC Wall Config`) is the
source of truth, fetched after unlock; the local `panels.yaml` is only an offline
fallback. `soc.env` now holds **no secrets** — just the backend/email/URL, the
secret-dir and config-item names, the master-password *source* name, paths and
tuning.

### Where the master password comes from (`SOC_MASTER_SOURCE`)

The master-password source is **pluggable and universal** (`host/mastersource.py`,
resolved the same way by `litebw`, the long-running host, and the legacy `rbw`
`pinentry-vault.py`). Set `SOC_MASTER_SOURCE` to one of:

| source | how | when |
| --- | --- | --- |
| `sealed` *(default)* | host-bound AES-256-GCM seal (`secretstore.py`) — machine-id + sealed PIN | **unattended / headless walls**: no login session, wallet, or prompt is needed to unlock at boot |
| `secret-service` | freedesktop Secret Service (`org.freedesktop.secrets`) via the libsecret `secret-tool` CLI | **attended** hosts where a human login unlocks the wallet |
| `env` | `$SOC_VAULT_PASSWORD` from the process environment (prints a deprecation warning) | **dev / seeding only** — never written to a file by any production flow |
| `auto` | `sealed` (if a complete seal exists) → `secret-service` (if `secret-tool` is present and the lookup succeeds) → `env` | the default when `SOC_MASTER_SOURCE` is unset |

**Why Secret Service is the universal answer.** KWallet, GNOME Keyring **and**
KeePassXC all implement the *same* `org.freedesktop.secrets` D-Bus API, so a
single `secret-tool` call works against whichever wallet is running — there is no
KDE-specific code path. Because it is **D-Bus based, it is display-server
agnostic**: it behaves identically under Wayland (Wayfire, labwc, cage, sway) and
X11. The only requirement is a session bus (`DBUS_SESSION_BUS_ADDRESS`), which the
compositor's session provides. This is why we chose it over a KDE-only KWallet
integration.

Store / look up the master with a fixed attribute pair (override via
`SOC_SECRET_ATTRS`):

```sh
secret-tool store --label 'SOC wall vault master' service soc-wall account vault-master
secret-tool lookup service soc-wall account vault-master
```

`secret-tool store` reads the secret from its own prompt / stdin, never from
`argv`, so the password cannot leak via `ps`/`/proc`. `setup.py first-run` lets
you pick the source and, for `secret-service`, stores + verifies the value in the
wallet; it persists only the **source name** to `soc.env`, never the password.

> **Headless auto-unlock caveat.** `secret-service` needs a **running, unlocked**
> wallet on the D-Bus session bus. An unattended kiosk boots straight to a
> compositor with no human typing a login password, so the default wallet is
> **locked at boot** and `secret-tool lookup` blocks on a prompt (bounded by a
> 10 s timeout, then degrades to "no master"). To use `secret-service`
> headlessly you must auto-unlock the wallet at session start — e.g.
> `pam_gnome_keyring.so` in the autologin PAM stack (the login password unlocks
> the keyring), `gnome-keyring-daemon --unlock` fed the password on stdin from a
> unit, `kwallet-pam`, or unlocking a KeePassXC database at session start. All of
> these **reintroduce a secret needed to unlock the wallet**, which is exactly why
> **`sealed` (no session, no wallet, no prompt) stays the default for the
> always-on wall.** Use `secret-service` on an attended workstation; use `sealed`
> on the Pi.

**The residual tradeoff is unchanged in kind:** a local `root` on the *running*
Pi can still derive the key (machine-id + the sealed PIN are both on the box).
Host-binding defeats card/file theft, not local root — inherent to any
unattended appliance.

If even that is unacceptable:

- Do not seal: keep the wall attended and run `litebw unlock` (or `rbw unlock`) once after each reboot
  (e.g. over SSH) within `SOC_READY_TIMEOUT` — the host retries opening the vault
  and logs in only once it is unlocked.
- Keep the one-time PIN off the device; you need it only to re-seal (re-deploy,
  new hardware, or changing the master password).
- Consider full-disk encryption (LUKS) with a remote unlock so a stolen card is
  inert.

## Residual exposure: form auto-fill

Auto-filling **any** login form necessarily places the password into the page DOM
at submit time — true of every password manager and every auto-login scheme. A
malicious panel that compromises its own renderer could read its own filled
fields. Mitigations in place: localhost-only everything, no shared broker, creds
delivered per-page and scrubbed, sessions isolated by origin. Only point the wall
at panels you trust.

## On-screen configuration (⚙ / Ctrl+Shift+C)

The wall can be repointed at the glass — convenient, but a surface to control:

- **PIN lock.** Set a PIN under "Security — lock PIN"; it then gates the config
  panel. It is stored only as a **salted SHA-256 digest** (`config.pin`, `0600`),
  never in clear text, with a brute-force **cooldown** after repeated misses. The
  PIN is casual physical-access protection, not a secret-grade barrier.
- **URL allow-list.** Only `http://` / `https://` URLs are accepted — at the
  overlay, in `set_url`, and when merging a (possibly hand-edited)
  `overrides.json`. `file://`, `javascript:`, `data:` etc. are refused, so the
  config cannot be turned into a local-file or script-injection vector.
- **Saved state is owner-only.** `overrides.json` is written `0600` because panel
  URLs can reveal internal hostnames.
- **Disable it entirely** for a locked-down deployment with
  `SOC_ONSCREEN_CONFIG=0` (the gear and hotkey then do nothing). Credentials are
  never entered here — only the *name* of the Vaultwarden login to use; the
  secrets stay in Vaultwarden.

## Renderer hardening & site containment

Each panel renders a third-party-fronted SOC dashboard that could be compromised
or buggy. The renderer reduces blast radius without breaking the dashboard; the
defaults are safe and every loosening is explicit opt-in (see
[CONFIGURATION.md](CONFIGURATION.md#renderer-security--site-restriction) for the
knobs). The trust model:

- **Hardening is pure attack-surface reduction** — no plugins/Java, no file://
  escalation, no mixed content on HTTPS, no downloads/file pickers, the WebKit
  sandbox where available. None of these are features a SOC dashboard uses, so
  the defaults are invisible. TLS certs are verified (fail-closed); a panel opts
  out per-tile with `allow_insecure` / `insecure_tls` (trusted LAN only).
- **The navigation allowlist is the containment boundary.** A hijacked page can
  still reach its own CDNs/SSO (allowed) but cannot drive the wall's top-level
  frame to an arbitrary attacker site (refused + logged). Only main-frame
  top-level navigation is gated; sub-resources, XHR, websockets and SSO redirect
  chains pass through, so real logins and live dashboards keep working. The
  bundled cloud-SSO list (`security/allowlist-sso.txt`) covers the common case;
  self-hosted origins are one `allow:` line; `SOC_NAV_ALLOWLIST=0` is the
  kill-switch for an unmapped dashboard.
- **Tracker blocking is defence + perf.** The curated top-20 analytics/tracker
  domains (`security/trackers-top20.json`) are dropped as third-party requests —
  less third-party JS means a smaller attack surface and less RAM/CPU. A
  dashboard's own first-party telemetry is never caught (`load-type:third-party`);
  `block_trackers: false` / `unblock:` are the escape hatches.
- **Persistent web data holds session tokens**, so it is the most sensitive new
  data on disk: stored under a `0700` kiosk-user-only `webdata/` dir, a **sibling**
  of the sealed-master `secret/` dir (never inside it — the no-plaintext-master
  guarantee is untouched), outside the repo, never world-readable, never logged,
  and per-panel isolated (`webdata/<panel-id>/`) so one panel cannot read
  another's session. The cookie accept policy is `NO_THIRD_PARTY`. A panel opts
  out of on-disk sessions with `persist: false` (ephemeral).

Both render engines enforce these identically: WebKit via settings / a
`decide-policy` nav guard / a `WKContentRuleList`, Chromium via launch flags /
a CDP nav guard / `Network.setBlockedURLs`.

## Network hardening (`HARDEN=1`)

Installs:

- **nftables** (`security/nftables.conf`): default-deny inbound; allow loopback,
  established, ICMP, and rate-limited SSH from `ssh_admin_cidr` (set this to your
  admin subnet — it defaults to "anywhere").
- **sshd** (`security/sshd_hardening.conf`): key-only, no root, no forwarding,
  `MaxAuthTries 3`. **Ensure you have an authorized key before rebooting** or you
  can lock yourself out.

Neither is started automatically — review them first, then
`systemctl start nftables` and `systemctl reload ssh`.

## Tunnel key hardening

The autossh tunnel uses a **dedicated, passphrase-less ed25519 key** that is
restricted on the jump host to *only* forward to the exact panels:

```
restrict,permitopen="10.20.0.7:8443",command="/usr/sbin/nologin" ssh-ed25519 AAAA… soc-wall-tunnel
```

So even if the Pi is compromised, that key cannot open a shell or forward
anywhere except the whitelisted panels. Full steps in
[`security/tunnel_key.note`](../security/tunnel_key.note).

## VPN credentials

The supervised VPN supports `vpn.type: fortinet` (openfortivpn), `openvpn`,
`wireguard`, and `inode` (the bundled H3C client). Whichever backend is in use, the
username + password live in the **same vault** as the panels (`vpn.vault_item`) and
are read into memory — they **never reach `argv`** (where `ps`/`/proc` would expose
them) and are **never written to disk**. Each backend has a secret path that keeps
the password off the command line:

- **fortinet:** handed to `openfortivpn` through a **pinentry helper** (`pinentry-env`
  / `forti-pinentry.sh`) — the same unseal-in-memory mechanism that unlocks the vault.
- **openvpn:** delivered over openvpn's **management socket** (`mgmt-socket`), not via
  `--auth-user-pass` on a world-readable file or argv.
- **inode (H3C):** read from `$H3C_SVPN_PASSWORD` in the process environment, never argv.

Only the gateway, username, and routing flags appear in the process list. The
gateway is validated as a hostname / IPv4 / IPv6 before use, and the trusted cert is
pinned by **SHA-1 *or* SHA-256** with a **constant-time compare** so a pin check is
not a timing oracle.

Two caveats specific to the VPN unit:

- **It runs as root.** Unlike `autossh-tunnel` (unprivileged), openfortivpn must
  run `pppd` and rewrite the routing table, so the unit runs as root with only
  light sandboxing. Its vault profile (under `/root`) is a second client of the same
  kiosk account.
- **OTP on argv (opt-in).** `otp_from_vault: true` passes a one-time `--otp=` code
  on the command line. It is single-use and short-lived, but briefly visible in
  the process list — leave it off unless your gateway requires TOTP.

### Bundled iNode / H3C client hardening

The `inode` backend ships a pure-Python, aarch64-portable H3C SSL-VPN client
(`vendor/iNode-VPN-Client`) that was security-hardened because it parses
attacker-influenced network frames and server-supplied images:

- **Frame-reassembly cap (1 MiB).** The wire reader caps reassembled frame size so a
  malicious/compromised gateway cannot drive unbounded memory growth (the SPA
  wire-format was also corrected).
- **BMP dimension caps.** Server-supplied CAPTCHA bitmaps (decoded with tesseract)
  have their width/height bounded before allocation, blocking decompression-bomb /
  giant-allocation inputs at the parse boundary.
- **Root-RCE-hardened privileged helper.** The root helper that applies routes was
  hardened against argument/command injection so a compromised unprivileged caller
  cannot turn it into local root code execution.
- **Constant-time cert-pin compare.** The trusted-cert pin check uses a constant-time
  comparison, so it cannot be probed as a timing side channel.

**Account-lockout protection.** The supervisor classifies an auth failure and
then *stops trying* for `SOC_VPN_AUTH_RETRY_DELAY` (default 300 s) rather than
reconnecting in a tight loop — a misconfigured password must not lock the
FortiGate account. The same protection applies to the proxy (below). The unit is
`Type=notify` with a `WatchdogSec` so a hung connection is detected and restarted
rather than silently wedging the wall.

## Proxy credentials

If an outbound proxy needs authentication (`proxy.vault_item`), the username and
password are kept in the **same vault** and answered to the proxy's `407`
challenge **in memory** — WebKit via the `authenticate` signal, Chromium via the
CDP `Fetch.authRequired` event. Only `--proxy-server=host:port` (no userinfo)
ever reaches a command line; the validator **rejects** a proxy URL that embeds
`user:pass@`. Loopback always bypasses the proxy, so the tunnels, the Chromium
CDP channel, and the local Vaultwarden are never routed through it. A wrong proxy
password is retried a few times and then held, like the VPN.

## systemd sandboxing

The `vaultwarden` and `autossh-tunnel` units run with `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, restricted address families,
`MemoryDenyWriteExecute` (vault), and read-only access to the key directory.

The `forti-vpn` unit is deliberately lighter (`ProtectSystem=true`, `PrivateTmp`,
restricted address families incl. `AF_NETLINK`/`AF_PPPOX`) because `pppd` needs
`/dev/ppp`, netlink, and write access to `/etc/resolv.conf` — over-hardening it
breaks the tunnel. The vault master password is never in the unit nor in
`soc.env`: the wrapper unlocks `litebw` (default; legacy `rbw`) via the same
host-bound sealed secret + `pinentry-vault.py` as the kiosk host, so it never
appears in `systemctl show`
or the process environment.

The kiosk session itself can run as a supervised unit (`soc-wall.service`,
generated by `setup.py`) with the non-secret config baked in as `Environment=`
lines instead of a sourced `soc.env`, and `Restart=always` so a dead compositor
recovers rather than leaving a black screen. The vault master is never among
those `Environment=` lines — it stays host-sealed. (Switching the boot from
getty-autologin to this service is validated per-deployment on the target Pi.)

## Uninstall preserves operator secrets

`./uninstall.sh` (and `make uninstall`) is **manifest-driven** (it removes only what
`install.sh` recorded in `/etc/soc-display/.install-manifest`) and **preserves
operator data by default** — the sealed master secret + PIN (`/etc/soc-display/secret/*.enc`),
the vault data, and your config are left in place, and the boot target / autologin
are restored. Pass `--purge` to deliberately wipe operator secrets and data. So a
routine uninstall/reinstall does **not** silently destroy the sealed credentials, and
nothing is overwritten or deleted that the manifest did not create.

## Checklist before exposing anything

- [ ] `ss -ltnp` shows Vaultwarden on `127.0.0.1` only and **no** extra SOC ports
- [ ] `soc.env` (now **non-secret**) is `0640`; Vaultwarden has **no `.env`**;
      `/etc/soc-display/secret/` is `0700` (kiosk user), `*.enc` are `0600`
- [ ] `SIGNUPS_ALLOWED=false` after the kiosk account exists; `/admin` left off
- [ ] tunnel key is `permitopen`-restricted on the jump host
- [ ] if using the VPN: `vpn.trusted_cert` pins the gateway; consider
      `half_internet_routes`/`set_routes: false` so the VPN can't hijack your admin path
- [ ] if using a proxy: `proxy.url` has **no** embedded credentials; the proxy
      login lives in the vault (`proxy.vault_item`)
- [ ] no credentials appear in `journalctl` (incl. `journalctl -u forti-vpn`) or
      in `ps`/`/proc` for the VPN client or chromium
- [ ] decide on the on-screen config: set a PIN, or disable it with
      `SOC_ONSCREEN_CONFIG=0` for a locked-down wall
- [ ] the master password is **sealed** (`setup.py first-run`), not in any
      `.env`; the one-time PIN is recorded off-device; you accept the host-bound
      unattended-unlock tradeoff
