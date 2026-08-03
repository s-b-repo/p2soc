# Standards conformance — NIST & RFC

How p2soc's security controls map to recognised standards. This is a living
matrix: ✅ conforms, ◑ partial / conditional, ☐ tracked gap. Grounded in the
implementation — each row cites the file that enforces it. See
[`SECURITY.md`](SECURITY.md) for the threat model and
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) for open items.

## Cryptography & secret storage

| Std | Control | Status | Where |
|-----|---------|:--:|-------|
| **NIST SP 800-131A** / FIPS 140 | Approved primitives: AES-256-GCM (AEAD), SHA-256 | ✅ | `host/secretstore.py` (`_aesgcm`, `_SCRYPT dklen=32`) |
| **RFC 7914** | scrypt memory-hard KDF, N=2¹⁷ r=8 p=1 (~128 MiB) for the low-entropy PIN | ✅ | `secretstore._SCRYPT`, `_kdf` |
| **NIST SP 800-108** | KDF domain separation via a versioned context label | ✅ | `secretstore._KDF_CONTEXT` bound into `_binding_material` |
| **NIST SP 800-90A** | CSPRNG for keys/salts/nonces/PINs (`os.urandom`, `secrets`) | ✅ | `secretstore` (`os.urandom`), `gen_pin` (`secrets.choice`) |
| **NIST SP 800-63B** | Memorized-authenticator minimum length (PIN ≥ 6); salted+hashed verifier; constant-time check | ✅ | `_MIN_PIN_LEN`, `verify_pin` (`hmac.compare_digest`) |
| **NIST SP 800-38D** | AES-GCM with a fresh 96-bit random nonce per encryption | ✅ | `secretstore._encrypt` (`os.urandom(12)`) |
| **NIST SP 800-132** / FIPS 140 (KDF) | PBKDF2-HMAC-SHA256 (FIPS-approved) selectable via `SOC_FIPS_KDF=1`; scrypt is the stronger default. KDF id stored per-blob so seals stay portable across the setting | ✅ | `secretstore._kdf`, `_active_algo`, `_ALGO_PBKDF2` |
| **NIST SP 800-57** | Host-bound key, re-key (re-seal) on hardware change / restore | ✅ | `secretstore.seal` (fresh `host.key` per seal) |

## Network, transport & access

| Std | Control | Status | Where |
|-----|---------|:--:|-------|
| **RFC 4251/4253** | SSH jump-host **host-key verification** (strict by default, `known_hosts`) | ✅ | `scripts/tunnel-args.py` (SEC-6) |
| **RFC 4252** | SSH public-key-only auth; no passwords, no root | ✅ | `security/sshd_hardening.conf` |
| **NIST SP 800-41** | Default-deny firewall **both directions** (ingress + egress allowlist) | ✅ | `security/nftables.conf` (SEC-1/SEC-2) |
| **NIST SP 800-77** | VPN supervised with auth-failure backoff, watchdog, ready-probe | ✅ | `host/fortivpn.py`, `host/vpndrivers.py` |
| **RFC 5280** | X.509 path validation on by default; SHA-256 cert pinning; `--insecure` opt-in only | ✅ | `vendor/iNode-VPN-Client/.../transport.py` |
| **RFC 3986** | URI validation: scheme allowlist (`http`/`https`), required host, no userinfo, no control/whitespace (anti scheme-smuggling). One canonical validator at the glass, loader, and live `set_url` | ✅ | `config.valid_http_url` (used by `configwin`, `webkit_panel`, `chromium_panel`) |
| **NIST SP 800-52r2** | TLS for transport; secrets store bound to loopback (no cleartext on the wire) | ◑ | Vaultwarden `127.0.0.1` only; dashboards' TLS is the operator's |
| **RFC 6238 / 4226** | TOTP/HOTP for VPN where the gateway requires it (single-use OTP) | ◑ | `fortivpn._otp_code` (opt-in; OTP-on-argv documented) |

## Platform & operations

| Std | Control | Status | Where |
|-----|---------|:--:|-------|
| **NIST SP 800-123** | Service least-privilege: systemd sandboxing, dedicated unprivileged users | ◑ | `systemd/*.service` (vault/tunnel strict; VPN/session as tight as the workload allows — SEC-5/SEC-11) |
| **NIST SP 800-92** | Bounded, retained audit logging (journald size cap, retention) | ✅ | `security/journald-soc.conf` (PERF-2) |
| **NIST SP 800-53 AC-7** | Throttle/lock after repeated failed PIN attempts | ✅ | `host/configwin.py` (`_try_unlock` cooldown) |
| **NIST SP 800-53 CM-7** | Least functionality: physical-access config surface off by default, PIN-gated if on | ✅ | SEC-7 (`gate_unlocked`, generated unit) |
| **NIST SP 800-88** | Sanitise the plaintext master from `.env` after sealing (atomic rewrite) | ◑ | `setup.py first-run` (logical erase; flash wear-levelling caveat noted) |
| **CIS / least-priv** | Kiosk + service accounts denied SSH; X server limited to console | ✅ | `sshd_hardening.conf` (SEC-10), `install.sh` Xwrapper (SEC-9) |

## Known gaps (tracked)

- **CDP transport (SEC-8)** — move Chromium DevTools off loopback TCP to
  `--remote-debugging-pipe` (removes the local-TCP attack surface).
- **TLS to dashboards (800-52r2)** — the wall trusts whatever TLS the panels
  present; document a per-panel CA-pinning option.
