# Security model

`p2soc` is an **unattended** appliance: it must boot and log into four panels with
no human present. That goal sets the security envelope — read this before
deploying anywhere sensitive.

## What protects the credentials

- **Vault on localhost.** Vaultwarden binds `127.0.0.1:8222`. Nothing SOC-related
  listens on the LAN.
- **No broker, no port, no page fetch.** The kiosk host reads creds via `rbw` and
  injects them into each view itself (WebKit `socCreds` message handler; Chromium
  CDP). Credentials never traverse a network socket or page-context `fetch`.
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
different `machine-id` makes the GCM authentication fail. `rbw` gets the master
password from `scripts/pinentry-vault.py`, which unseals it in memory.

The wall **config** is the vault's too: a secure-note (`SOC Wall Config`) is the
source of truth, fetched after unlock; the local `panels.yaml` is only an offline
fallback. `soc.env` now holds **no secrets** — just the backend/email/URL, the
secret-dir and config-item names, paths and tuning.

**The residual tradeoff is unchanged in kind:** a local `root` on the *running*
Pi can still derive the key (machine-id + the sealed PIN are both on the box).
Host-binding defeats card/file theft, not local root — inherent to any
unattended appliance.

If even that is unacceptable:

- Do not seal: keep the wall attended and run `rbw unlock` once after each reboot
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

## Fortinet VPN credentials

`forti-vpn.service` logs into the FortiGate with a username + password kept in the
**same vault** as the panels (`vpn.vault_item`). The password is read into memory
and handed to `openfortivpn` through a **pinentry helper** (`forti-pinentry.sh`) —
the identical mechanism that unlocks `rbw`. So the FortiGate password is **never
on the command line** (where `ps`/`/proc` would expose it) and **never written to
disk**; only the gateway, username, and routing flags appear in the process list.

Two caveats specific to the VPN unit:

- **It runs as root.** Unlike `autossh-tunnel` (unprivileged), openfortivpn must
  run `pppd` and rewrite the routing table, so the unit runs as root with only
  light sandboxing. Its rbw profile (under `/root`) is a second client of the same
  kiosk account.
- **OTP on argv (opt-in).** `otp_from_vault: true` passes a one-time `--otp=` code
  on the command line. It is single-use and short-lived, but briefly visible in
  the process list — leave it off unless your gateway requires TOTP.

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
`soc.env`: the wrapper unlocks `rbw` via the same host-bound sealed secret +
`pinentry-vault.py` as the kiosk host, so it never appears in `systemctl show`
or the process environment.

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
