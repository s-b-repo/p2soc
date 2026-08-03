# Production Merge & Security Audit Report

**Project:** p2soc — SOC Video Wall (Raspberry Pi 5 kiosk)
**Date:** 2026-06-23
**Deliverable:** `soc-wall-prod/` (this folder)
**Scope:** Merge `soc display/` + `soc-wall-deploy/` into one production-ready tree;
audit for bugs, security issues, performance issues, gaps, and RFC-compliance gaps;
apply fixes.

---

## 1. Merge provenance

Two source folders existed:

| Folder | Role | Verdict |
|---|---|---|
| `soc display/` | Canonical git repo, active dev copy | **Source of truth** — strictly newer in every diffing source file; has modules the deploy copy lacks (`backup.py`, extra tests, `PRODUCTION_READINESS.md`, `STANDARDS.md`). |
| `soc-wall-deploy/` | Older deployed copy | Stale. Unique content was only real secrets (`.env`, `vaultwarden.env`) and a site-specific `config/panels.local.yaml` (LAN IPs) — intentionally **not** carried into prod. |

`soc-wall-prod/` was built from canonical `soc display/`, excluding `.git`, `.venv`,
`__pycache__`, `.pytest_cache`, `dev/run/` (browser/cache junk), `.claude`, and all
real secrets. It has its own fresh git history (baseline commit → hardening commit).
Result: **125 files, 1.4 MB, zero secrets, zero transient artifacts.** Configure a real
deployment from `.env.example` + `config/panels.yaml` (see `docs/INSTALL.md`).

## 2. Audit method

Four independent read-only audits ran in parallel against the merged tree, by domain:
secrets/crypto/vault/login-injection; kiosk host runtime (bugs + performance);
VPN/networking/RFC compliance; installer/setup/systemd/OS-hardening. Findings were
consolidated, deduped, and fixed by four disjoint-file fix passes. Verification:
`make lint` (shell + python syntax) and the unit suite, which went **136 → 186 passing**
(+50 regression tests). Raw per-domain findings are archived under `.audit/` (gitignored).

**Headline:** the codebase was already security-conscious — sound AEAD crypto, no
`shell=True`/`eval`/`curl|bash`, list-argv everywhere, secrets off disk/argv, a real CDP
origin lockdown, fail-closed nftables. The audit found **no Critical security holes in the
production path**; the two Critical items were *reliability/memory* bugs specific to the
1 GB Pi. Everything below in §3 is fixed in this tree; §4 lists what remains.

## 3. Findings fixed

### 3.1 Kiosk runtime — bugs & performance (1 GB Pi)
- **[Critical] Memory watchdog was a no-op for WebKit.** `recycle()` only reloaded the
  page (renderer process reused → leaked heap never freed) and `mem_rss_kb()` always
  returned `None` (watchdog blind). On a leaking dashboard this trended straight to the
  OOM-killer. **Fix:** `recycle()` terminates the web process + clears website data;
  `mem_rss_kb()` reports the web-process RSS. Feature-detected, reload fallback.
- **[Critical] No Chromium respawn cap.** A permanently-broken panel respawned Chromium
  every 60 s forever (memory/CPU/SD-card churn). **Fix:** `SOC_MAX_RESPAWNS` ceiling +
  parked terminal state; re-arms only on `set_url`/config change.
- **[High] WebKit retry timers leaked/stacked** (source IDs discarded; `set_url` reset the
  flag without removing the pending source). **Fix:** track + `GLib.source_remove`.
- **[High] No `WebKitPanel.stop()`** → web processes/timers survived shutdown. **Fix:** added.
- **[High] CDP `rpc()` had no per-recv timeout** → a wedged Chromium delayed self-heal.
  **Fix:** per-recv `settimeout` (mirrors `pump`), timeout → close + respawn.
- **[Medium] Chromium `Popen`** lacked `start_new_session`/`close_fds` (signal-group race
  on systemd restart). **Fix:** added. `_vpn_poll_busy` could wedge the status pill if its
  thread died → now cleared on the main thread + overdue force-clear.

### 3.2 Secrets / crypto / login-injection
- **[Medium] No origin gate before credential injection.** `socLogin()` filled the first
  user/pass field on whatever page was loaded; selection was config-bound (good) but fill
  was not. A panel navigating off its configured origin could get SOC creds autofilled
  into an attacker page. **Fix:** origin allow-list gate (`location.origin` must equal the
  configured origin) wired from `effective_url`; empty = legacy/back-compat.
- **Verified sound (no change):** AES-256-GCM, `os.urandom`/`secrets` nonces & salts (no
  reuse), scrypt N=2¹⁷ (PBKDF2-600k FIPS fallback), atomic 0600 seals, host-binding via a
  0600 `host.key` (not world-readable machine-id), CDP bound to `127.0.0.1` with exact
  `--remote-allow-origins` (no `*`), config-bound credential selection.

### 3.3 VPN / networking / RFC compliance
- **[High] OpenVPN management-socket line injection** — username written raw, password
  stripped only `\n`. **Fix:** CR/LF-sanitize both.
- **[Medium] Materialized vault keys** (`.ovpn`/`.conf`, 0600) leaked on early exit. **Fix:**
  `try/finally` cleanup on every path, idempotent.
- **[Medium] IPv6 `host:port`** mis-parsed by `rpartition(":")`. **Fix:** bracket-aware split.
- **Verified sound:** list-argv (no shell injection) connect builders; exponential backoff
  with separate AUTH/CERT backoffs (anti account-lockout); `-L` binds `127.0.0.1` only;
  `ExitOnForwardFailure`/`ServerAlive`/`BatchMode` present.

### 3.4 Config validation
- **[High] argv option-injection** via unvalidated `gateway`/`remote_host`/`jump_host`/
  `realm`/`extra_args`. **Fix:** reject leading-dash/control/whitespace; `remote_port`
  range-checked 1–65535.
- **[High] `compute_geometry` negative cell dims** from an unbounded `gap`. **Fix:** clamp
  to ≥1 cell; cap gap to fit the resolution.
- **[Medium] Panel `id` XML-injection** into Openbox/labwc `rc.xml`. **Fix:** restrict id to
  `[A-Za-z0-9_-]` (config) **and** XML-escape in the generators (defense-in-depth).

### 3.5 Installer / systemd / OS hardening
- **[High] Over-broad `soc.env` read** — fallback added `socsvc` to the kiosk login group.
  **Fix:** dedicated `socenv` group scoped to `soc.env` only.
- **[High] `vm.swappiness=180`** silently clamped on kernels <5.8 (defeats zram). **Fix:**
  documented the ≥5.8 requirement (Pi OS Bookworm is 6.x).
- **[Medium] nftables egress** allowed NTP/ICMP to any host (beacon/exfil path). **Fix:**
  pin NTP to `@ntp_servers`; rate-limit outbound ICMP echo.
- **[Medium] `soc-wall.service` 0644** leaked `SOC_VAULT_EMAIL`. **Fix:** write `0640`.
- **[Medium] `clean_state` `shutil.rmtree`** had no path guard. **Fix:** path-prefix allowlist.
- **[Medium] ssh `-L` `extra_forwards`** unvalidated + TOFU host-key default. **Fix:** shape
  validation; require `known_hosts` when `host_key_checking != yes`.
- **[Low] `cmdline.txt` sed** appended to every line. **Fix:** first line only.

## 4. Deferred / residual (require on-hardware validation)

These were **intentionally not changed** in a headless environment because they need a real
Pi + live VPN backends to validate safely. Each is low residual risk and documented:

1. **`forti-vpn.service` capability/syscall sandboxing** — runs as root for pppd/wg. Proposed
   `CapabilityBoundingSet` + `SystemCallFilter=@system-service` must be validated against all
   three backends (fortinet/openvpn/wireguard) on hardware before enabling.
2. **WebKit web-process RSS reclaim** — the `terminate_web_process()` recycle path and
   web-process pid discovery are feature-detected with a reload fallback; confirm real reclaim
   with `make verify` on a device.
3. **Single-use VPN OTP on argv** — `--otp=` is briefly visible via `ps`; bounded (one-time,
   short TTL). Moving it to stdin/pinentry needs openfortivpn behavior validation on hardware.
4. **Proxy `CONNECT`/`Proxy-Authorization` for HTTPS panels** — reactive auth is correct, but
   the dev proxy only exercises absolute-form HTTP; verify against a real CONNECT proxy.
5. **`pin.hash`** uses a fast SHA-256 over a low-entropy PIN (bounded — only authorizes
   re-seal; an attacker with `host.key`+machine-id already recovers the PIN). Optional: derive
   the verifier via scrypt or verify via `unseal()`.
6. **`forti-vpn` log classification** is substring-based and pinned to current client wording;
   re-verify on client upgrades.

## 5. Verification status

All green on an x86 Xvfb host (2026-06-23):

- `make lint` — shell + python syntax: **pass**
- Unit suite (`cd kiosk-host && pytest tests/ -q`): **186 passed** (was 136; +50 regression tests)
- `make verify` — 4-panel grid, auto-login on all panels, **origin gate does not break login**,
  Chromium CDP path, tunnel readiness gate, screenshot: **VERIFY OK**
- `make verify-vpn` — all 4 backends (fortinet/openvpn/wireguard/inode), 14 checks incl.
  *"openvpn creds over mgmt socket (not argv)"* and *"wireguard transient config cleaned up"*
  (directly exercising the CR/LF-sanitize and `try/finally` cleanup fixes): **VERIFY-VPN OK**
- `make verify-proxy` — authenticated proxy for both WebKit and Chromium, loopback bypass: **VERIFY-PROXY OK**
- `make verify-single` — Wayland/single-window layout, all panels login: **VERIFY-SINGLE OK**

**Live VPN backend validation (2026-06-23):**
- *Fortinet (openfortivpn)* — tested against a real FortiGate. Both the raw invocation and the
  **project code path** (`config.openfortivpn_args` + `FortinetDriver.build_cmd` +
  `forti-pinentry.sh`, password via `$SOC_VPN_PASSWORD`, never on argv) authenticated and
  reached *"Tunnel is up and running"* (`ppp0` UP, VPN address allocated); `--trusted-cert`
  pinning matched; clean teardown (`--set-routes=0 --set-dns=0`). Classifier matched real output.
- *H3C iNode SSL-VPN* — tested against a real H3C gateway via the bundled client. `--auth-only`
  authenticated with a **pinned cert** (`--pin-sha256`, not `--insecure`); the full tunnel came
  up (`tunnel up: ip=… routes=5 keepalive=30s`, `inode0` interface), captcha auto-solved by the
  client, and the `INodeDriver` classifier pattern (`"tunnel up:"`) matched. Teardown via the
  helper's `stop` removed the TUN and left routing intact.
- *Observation (minor):* the standalone `svpn-connect.sh` CLI wrapper's `timeout`/SIGTERM
  teardown is unreliable when its internal `sudo` needs to re-auth (the privileged helper can be
  orphaned). The production kiosk runs the iNode backend under the root `fortivpn.py` supervisor
  (systemd), not this CLI+sudo path, so it's largely a test-harness artifact; the wrapper could
  still be hardened to always `stop` by name on exit.

**Fortinet + iNode backends: validated live.** Still recommended on the **target Pi** before
cutover: re-run the four `verify*` suites on-device, plus the remaining §4 items
(openvpn/wireguard backends on real gateways, on-device RSS reclaim).

## 6. Recommended pre-deployment checklist

1. `make verify && make verify-single && make verify-proxy && make verify-vpn` on a display host.
2. On the target Pi: provision `known_hosts` out-of-band for any SSH tunnel; pin the iNode/
   Fortinet cert (`pin_sha256`) rather than `insecure`.
3. Set `@dns_servers` and `@ntp_servers` in `security/nftables.conf` to your real resolvers/NTP.
4. Validate and enable the hardened `forti-vpn.service` sandboxing (deferred item 1).
5. First-run sealing of the vault master; confirm `soc.env` has no `SOC_VAULT_PASSWORD`.
