# Standards conformance — NIST & RFC

This matrix maps implementation controls to standards. It is an engineering
reference. See the threat model in [Security](SECURITY.md).

## Cryptography & secret storage

| Std | Control | Status | Where |
|-----|---------|:--:|-------|
| **NIST SP 800-131A** | AES-256-GCM (AEAD), SHA-256 | ✅ | `soc-seal/src/blob.rs` |
| **RFC 7914** | scrypt memory-hard KDF, N=2¹⁷ r=8 p=1 (~128 MiB) for the low-entropy PIN | ✅ | `soc-seal/src/blob.rs` |
| **NIST SP 800-108** | KDF domain separation via a versioned context label | ✅ | `soc-seal/src/store.rs` |
| **NIST SP 800-90A** | OS CSPRNG for keys, salts, nonces and PINs | ✅ | `soc-seal/src/rng.rs` |
| **NIST SP 800-63B** | Memorized-authenticator minimum length (PIN ≥ 6); salted+hashed verifier; constant-time check | ✅ | `soc-seal/src/pin.rs` |
| **NIST SP 800-38D** | AES-GCM with a fresh 96-bit random nonce per encryption | ✅ | `soc-seal/src/blob.rs` |
| **NIST SP 800-132** (KDF) | PBKDF2-HMAC-SHA256 selectable via `SOC_FIPS_KDF=1`; scrypt is the stronger default. KDF id stored per-blob so seals stay portable across the setting | ✅ | `soc-seal/src/blob.rs`, `soc-seal/src/store.rs` |
| **NIST SP 800-57** | Host-bound key, re-key (re-seal) on hardware change / restore | ✅ | `soc-seal/src/store.rs` |

## Network, transport & access

| Std | Control | Status | Where |
|-----|---------|:--:|-------|
| **RFC 4251/4253** | SSH jump-host **host-key verification** (strict by default, `known_hosts`) | ✅ | `soc-sys/src/tunnel.rs` |
| **RFC 4252** | SSH public-key-only auth; no passwords, no root | ✅ | `security/sshd_hardening.conf` |
| **NIST SP 800-41** | Default-deny firewall **both directions** (ingress + egress allowlist) | ✅ | `security/nftables.conf` (SEC-1/SEC-2) |
| **NIST SP 800-77** | VPN supervised with auth-failure backoff, watchdog, ready-probe | ✅ | `soc-vpn` |
| **RFC 5280** | X.509 path validation on by default; SHA-256 cert pinning; `--insecure` opt-in only | ✅ | `soc-inode` and the configured gateway client |
| **RFC 3986** | URI validation: scheme allowlist (`http`/`https`), required host, no userinfo, no control/whitespace (anti scheme-smuggling). One canonical validator at the glass, loader, and live `set_url` | ✅ | `soc-core/src/guard.rs`, `soc-wall/src/gui`, `soc-web` |
| **NIST SP 800-52r2** | TLS for transport; secrets store bound to loopback (no cleartext on the wire) | ◑ | Vaultwarden `127.0.0.1` only; dashboards' TLS is the operator's |
| **RFC 6238 / 4226** | TOTP/HOTP for VPN where the gateway requires it (single-use OTP) | ◑ | `soc-vpn` (optional gateway OTP) |

## Platform & operations

| Std | Control | Status | Where |
|-----|---------|:--:|-------|
| **NIST SP 800-123** | Service least-privilege: systemd sandboxing, dedicated unprivileged users | ◑ | `systemd/*.service` (vault/tunnel strict; VPN/session as tight as the workload allows — SEC-5/SEC-11) |
| **NIST SP 800-92** | Bounded, retained audit logging (journald size cap, retention) | ✅ | `security/journald-soc.conf` (PERF-2) |
| **NIST SP 800-53 AC-7** | Throttle/lock after repeated failed PIN attempts | ✅ | `soc-state` and `soc-wall/src/gui/settings` |
| **NIST SP 800-53 CM-7** | Least functionality: physical-access config surface off by default, PIN-gated if on | ✅ | SEC-7 (`gate_unlocked`, generated unit) |
| **NIST SP 800-88** | Sanitise the plaintext master from `.env` after sealing (atomic rewrite) | ◑ | `soc-wall setup first-run` (logical erase; flash wear-levelling caveat noted) |
| **CIS / least-priv** | Kiosk + service accounts denied SSH; X server limited to console | ✅ | `sshd_hardening.conf` (SEC-10), `install.sh` Xwrapper (SEC-9) |

## Known gaps (tracked)

- **CDP transport (SEC-8)** — move Chromium DevTools off loopback TCP to
  `--remote-debugging-pipe` (removes the local-TCP attack surface).
- **TLS to dashboards (800-52r2)** — the wall trusts whatever TLS the panels
  present; document a per-panel CA-pinning option.
