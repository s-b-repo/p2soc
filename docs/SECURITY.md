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

## The unattended-unlock tradeoff (read this)

For a hands-free boot the vault master password is stored in
`/etc/soc-display/soc.env` (`0640`). **A powered-on kiosk can therefore unlock its
own vault.** Physical access to the Pi ≈ access to the panel credentials. That is
inherent to any unattended auto-login appliance.

If that is unacceptable for your environment:

- Set `SOC_VAULT_INTERACTIVE=1` in `soc.env` and remove `SOC_VAULT_PASSWORD`. The
  host will not auto-unlock; run `rbw unlock` once after each reboot (e.g. over
  SSH). The wall logs in only after you unlock.
- Consider full-disk encryption (LUKS) with a remote unlock so a stolen card is
  inert.

## Residual exposure: form auto-fill

Auto-filling **any** login form necessarily places the password into the page DOM
at submit time — true of every password manager and every auto-login scheme. A
malicious panel that compromises its own renderer could read its own filled
fields. Mitigations in place: localhost-only everything, no shared broker, creds
delivered per-page and scrubbed, sessions isolated by origin. Only point the wall
at panels you trust.

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

## systemd sandboxing

The `vaultwarden` and `autossh-tunnel` units run with `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, restricted address families,
`MemoryDenyWriteExecute` (vault), and read-only access to the key directory.

## Checklist before exposing anything

- [ ] `ss -ltnp` shows Vaultwarden on `127.0.0.1` only and **no** extra SOC ports
- [ ] `soc.env` and `vaultwarden.env` are `0640`/`0600`, not world-readable
- [ ] `SIGNUPS_ALLOWED=false` after the kiosk account exists; `ADMIN_TOKEN` set
- [ ] tunnel key is `permitopen`-restricted on the jump host
- [ ] no credentials appear in `journalctl`
- [ ] you have decided on attended vs. unattended unlock and accept the tradeoff
