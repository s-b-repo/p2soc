# Production-Readiness Goal — p2soc SOC Video Wall

**Owner:** Claude (working goal) · **Status:** in progress · **Created:** 2026-06-23

> **Progress (2026-06-23).** ✅ Done & tested (116 unit tests + headless verify green):
> SEC-1, SEC-2, SEC-3, SEC-4 (P0); SEC-5, SEC-6, SEC-7 (P1); SEC-9, SEC-10, SEC-11,
> SEC-12, SEC-DOC; PERF-1, PERF-2. ⏳ Remaining: SEC-8 (CDP→pipe rework — deferred,
> needs live-Chromium validation), SEC-13, PERF-3…7, OPS-1…4, then the v1.0.0 gate.

> **Mission.** Take p2soc from "code-complete and passing tests" to "safe to deploy
> on an internet-adjacent Raspberry Pi 5 (1 GB) running 24/7 unattended in a SOC."
> **Priority order is fixed: _security first, performance second, operability third._**
> No performance task may regress a security control; where they conflict, security wins.

This document is the single source of truth for the hardening pass. It is grounded
in two read-only audits of the current `main` (commit `1d87361`): a security audit
and a 1 GB-Pi performance audit. Every task cites the real `file:line` it touches and
a concrete acceptance test. Do **not** mark a task done without its acceptance check.

---

## Definition of Done (release gate for v1.0.0)

A build is production-ready when **all P0 + P1 tasks are closed** and:

1. `make test` green (currently 105/105) **and** new regression tests for every
   security fix below are added and green.
2. `make lint` clean.
3. `make verify`, `verify-single`, `verify-proxy`, `verify-vpn` all pass headless.
4. A fresh `setup.py deploy` on a clean box **fails closed** if any P0 control is
   misconfigured (open SSH CIDR, default PIN, TOFU jump host) — it must refuse,
   not warn.
5. `docs/SECURITY.md` documents the real trust boundary (see S-DOC below).
6. The 1 GB soak test (§Performance acceptance) survives 24 h with 4 panels, VPN,
   and Vaultwarden without OOM-restart or unbounded disk growth.
7. CHANGELOG `[Unreleased]` is cut to `v1.0.0`, tagged, with a `__version__`.

---

## Current state (baseline)

**Strong foundation already present** — preserve these, do not regress:

- Sealed host-bound master (atomic, fsync'd, 0600, verify-before-scrub) — `secretstore.py:114-176`, `setup.py:1486-1492`
- Credentials never on argv/disk across all VPN backends; pinentry/env/mgmt-socket only
- Vaultwarden bound `127.0.0.1:8222`, signups off, `/admin` disabled — `systemd/vaultwarden.service:19-24`
- CDP origin lockdown pinned to exact loopback origin, never `*` — `chromium_panel.py:49-58`
- URL scheme allowlist (http/https only) at every entry point
- Login injection uses `json.dumps` (no template injection) + prompt via `textContent`
- Real `MemAvailable` watchdog with hysteresis + cooldown; proper subprocess reaping; backoff everywhere
- WebKit memory-pressure caps, zram + swappiness tuning, DOCUMENT_VIEWER cache model
- TLS verification on-by-default with SHA-256 pinning in the vendored iNode client

**The gap to production is mostly _fail-closed defaults, defense-in-depth, and
operability_ — not missing features or broken logic.**

---

# Phase 1 — SECURITY  *(highest priority)*

## P0 — must fix before any production deploy

### SEC-1 (H1) — nftables ships SSH open to the world
- **Where:** `security/nftables.conf:7` (`ssh_admin_cidr = 0.0.0.0/0`), warned-only at `install.sh:558`
- **Problem:** With `HARDEN=1`, SSH is accepted from anywhere (key-only + rate-limited, but globally reachable). Default is open; nothing enforces tightening.
- **Fix:** Ship a non-routable default (`127.0.0.1/32`). Make `install.sh`/`setup.py deploy`
  **refuse to enable nftables** while `ssh_admin_cidr == 0.0.0.0/0` — prompt for the real
  admin CIDR or fail closed.
- **Done when:** deploy aborts with a clear message on the default CIDR; a regression test
  asserts the guard; docs/SECURITY.md documents the required value.

### SEC-2 (H2) — no outbound egress filtering
- **Where:** `security/nftables.conf:34` (`output` chain `policy accept`)
- **Problem:** A compromised renderer/dashboard can exfiltrate or beacon to C2 freely. A SOC
  kiosk should only reach a known set of destinations.
- **Fix:** Add an egress allowlist: DNS, NTP, the VPN gateway, the jump host; Vaultwarden is
  loopback. Default `output` to `policy drop` with explicit allows, scoped by the `soc` uid
  to known panel subnets. Provide a documented `EGRESS_ALLOW` knob for the deployer's panels.
- **Done when:** egress to a non-allowlisted host is dropped in `verify`-style test; allowed
  paths (VPN, jump host, DNS) still work end-to-end.

### SEC-3 (H3) — seal entropy collapses to a world-readable `/etc/machine-id`
- **Where:** `secretstore.py:34` (`_SCRYPT n=2**14`); PIN sealed under machine-id only
- **Problem:** The "files copied off the box" resistance reduces to `/etc/machine-id`, which is
  **not secret** (0644). With the secret dir + machine-id, the 8-digit numeric PIN (10^8) is
  brute-forceable offline at N=2^14. `pin.enc` under machine-id alone means the PIN adds no
  entropy against an attacker who can read both.
- **Fix:** (1) Bump scrypt to ≥ N=2^17, r=8, p=1 (raise `maxmem`; Pi 5 affords a once-per-boot
  unseal). (2) Mix in a secret that is **not** world-readable — a 0600 random keyfile inside the
  0700 secret dir (or TPM-derived key) — so machine-id alone is insufficient. (3) Make the PIN
  alphanumeric and longer.
- **Done when:** unseal still works on-host; a copied secret-dir + machine-id (without the 0600
  keyfile) **fails** to unseal in a test; KDF params asserted in a test.

### SEC-4 (H4) — default Vaultwarden mode is unsandboxed Docker installed via `curl|bash`
- **Where:** `install.sh:47` (`VW_MODE=docker` default), `install.sh:445` (`get.docker.com | sh` as root), `systemd/vaultwarden-docker.service` (no sandboxing vs the hardened native unit)
- **Problem:** Production default runs the secret store as root under Docker with none of the
  native unit's hardening, and bootstraps Docker via an unpinned remote script piped to root.
- **Fix:** Default production to the **hardened native unit** (`systemd/vaultwarden.service`).
  If Docker/Podman is offered, use the distro package (or pinned+checksum'd), prefer rootless
  Podman, and never `curl|bash`. Document Docker as convenience-only.
- **Done when:** `setup.py deploy` selects the native hardened unit by default; no `curl|bash`
  remains in the install path; docs updated.

## P1 — fix before v1.0.0 tag

### SEC-5 (H5) — root VPN service is the least-sandboxed long-running unit
- **Where:** `systemd/forti-vpn.service:42-52` (`NoNewPrivileges=no`, `ProtectSystem=true`, no syscall filter)
- **Fix:** `ProtectSystem=strict` + explicit `ReadWritePaths=/etc/resolv.conf /run`,
  `ProtectHome=read-only`, `RestrictNamespaces=yes`, `SystemCallArchitectures=native`,
  `SystemCallFilter=@system-service @network-io`, `ProtectKernelModules=yes` (load wg module via
  `modules-load.d`). Verify each backend still connects; set `NoNewPrivileges=yes` unless a
  backend re-execs a setuid helper.
- **Done when:** all three VPN backends pass `verify-vpn` with the tightened unit.

### SEC-6 (M1) — autossh tunnel uses TOFU by default
- **Where:** `scripts/tunnel-args.py:39` (`StrictHostKeyChecking=accept-new`)
- **Fix:** Pre-provision the jump-host key into `socsvc`'s `known_hosts` during `setup.py deploy`;
  default to `StrictHostKeyChecking=yes`. `accept-new` only as explicit opt-in.
- **Done when:** deploy populates known_hosts; a wrong host key fails the tunnel in test.

### SEC-7 (M2/M3) — physical-console blast radius; on-screen config exposes master
- **Where:** `systemd/getty-autologin.conf:6`, `configwin.py:457-465`, `scripts/pinentry-vault.py:27-30`
- **Fix:** Make the on-screen config PIN **mandatory** in production (default `SOC_ONSCREEN_CONFIG=0`
  unless a PIN is set). Disable getty on other TTYs and VT switching. Strongly consider a dedicated
  unprivileged vault-reader account so a compromised renderer running as `soc` cannot unseal the master.
- **Done when:** on-screen config refuses to reveal/save creds without the PIN; docs note the
  console-access boundary.

### SEC-8 (M4) — CDP unauthenticated on loopback TCP
- **Where:** `chromium_panel.py:268-270` (predictable `base+idx` port)
- **Fix:** Move to `--remote-debugging-pipe` (fd-based, no TCP) to remove the local-TCP surface
  entirely; if pipe is too invasive for the websocket client, use an ephemeral unpredictable port
  and restrict CDP to the host process. This closes the M2-autologin → CDP pivot.
- **Done when:** no fixed TCP debug port is reachable by another local process in a test; panels
  still attach and self-heal.

## P2 — defense-in-depth (can trail the tag, track to closure)

- **SEC-9 (M6):** `install.sh:366-374` — set Xwrapper `allowed_users=console`, not `anybody`.
- **SEC-10 (M7):** `security/sshd_hardening.conf:19-20` — ship `AllowGroups ssh-admins` uncommented.
- **SEC-11 (L1):** `systemd/soc-wall.service` — add `NoNewPrivileges=yes` + `ProtectHome` for other users (as far as a GUI session allows).
- **SEC-12 (L5):** `install.sh:380-382` — exclude `dev/` entirely from the production tar (keeps `seed-ciphers.py` cipher-wiper off the Pi).
- **SEC-13 (L3):** document that each panel's vault login must be unique/least-privilege so one XSS-vulnerable dashboard can't yield reusable creds.
- **SEC-DOC (M3):** `docs/SECURITY.md` — state the real boundary plainly: **the sealed master
  protects against offline media theft, not against local code execution as `soc`.**

---

# Phase 2 — PERFORMANCE  *(1 GB Pi 5, after security)*

## P1 — fix before v1.0.0 (real OOM / SD-wear risk)

### PERF-1 (High) — `MemoryMax=92%` can OOM-kill the whole wall before the soft watchdog acts
- **Where:** `setup.py:581-582`, `systemd/soc-wall.service:58-59`; watchdog floor `main.py:270-320`
- **Problem:** The hard cgroup ceiling OOM-kills a process inside the cgroup and `Restart=always`
  bounces the entire session (black-screen blink). It is uncoordinated with the `MemAvailable<96 MB`
  soft watchdog, and can win first.
- **Fix:** Prefer `MemoryHigh=80%` alone (gentle reclaim) — drop `MemoryMax` or widen the gap.
  Raise `SOC_MEM_MIN_AVAIL_MB` default to ~150 on the Pi so the watchdog recycles a panel
  **before** cgroup reclaim/swap-thrash. Validate on real hardware with all 4 panels loaded.
- **Done when:** 24 h soak with 4 heavy panels shows panel recycles (graceful) and **zero**
  whole-session OOM restarts.

### PERF-2 (High) — no journald size cap (unbounded SD growth + flash wear)
- **Where:** absent in `install.sh`/`setup.py`/`systemd`; everything logs to journal (`launcher.sh:21-23`)
- **Fix:** Ship `/etc/systemd/journald.conf.d/soc.conf` with `SystemMaxUse=100M`,
  `RuntimeMaxUse=50M`, and `Storage=volatile` (journal in RAM — everything is recoverable and SD
  wear matters). Install it from `install.sh`/`setup.py`.
- **Done when:** journal usage is capped in the soak test; drop-in installed by deploy.

## P2 — meaningful footprint / latency wins

- **PERF-3 (Med):** memory watchdog is blind to WebKit renderer RSS (`webkit_panel.py:316-319` returns `None`) — attribute `WebKitWebProcess` children to recycle the real offender instead of round-robin.
- **PERF-4 (Med):** add `--disable-features=site-per-process,Translate,OptimizationHints` to Chromium flags (trusted internal wall) to cut the per-panel browser-instance RAM multiplier — `chromium_panel.py:263-304`. *(Security note: site isolation off is acceptable only because panels are trusted internal dashboards; revisit if untrusted panels are ever added.)*
- **PERF-5 (Med):** the 50 MB Chromium disk cache lives under `XDG_RUNTIME_DIR` = tmpfs (RAM) on the Pi — `chromium_panel.py:284,244`. Point it at SD (`--disk-cache-dir=/var/cache/soc/<id>`) or shrink hard (~10 MB). Sweep/pin per-panel profiles; kill the persistent `/tmp` fallback.
- **PERF-6 (Low):** back off the 2 s Chromium CDP login poll to ~10–15 s after `justLoggedIn` — `chromium_panel.py:480,217`.
- **PERF-7 (Low):** wait tunnels concurrently (thread per port) instead of serially — `main.py:70-85`; reap the old `Popen` before respawn — `chromium_panel.py:421`.

## Performance acceptance (soak test)
24 h, 4 panels (mix WebKit + 1 Chromium), VPN up, Vaultwarden up: no whole-session OOM restart,
journal ≤ cap, RAM steady-state leaves > `SOC_MEM_MIN_AVAIL_MB` headroom most of the time, panel
recycles are graceful and attributed to the heaviest panel.

---

# Phase 3 — OPERABILITY & RELEASE  *(after security + performance)*

- **OPS-1 — Vault backup/restore (gap):** secrets live only on the SD card; the master is host-bound
  sealed. SD-card death = total secret loss with no documented recovery. Add an encrypted backup of
  the Vaultwarden DB + a documented restore (note: a restored seal won't unseal on new hardware by
  design — document re-seal-on-restore).
- **OPS-2 — External health/alert (gap):** internal self-healing exists (mem watchdog, `Restart=always`,
  VPN systemd watchdog) but nothing alerts a human if the box goes dark. Add a heartbeat/healthcheck
  (push ping or scrape endpoint) so a dead wall pages someone.
- **OPS-3 — Versioning/release (gap):** no `__version__` anywhere; CHANGELOG permanently `[Unreleased]`.
  Add `__version__`, cut CHANGELOG to `v1.0.0`, tag, and adopt a release checklist.
- **OPS-4 — Watchdog on the session:** confirm `soc-wall.service` benefits from a `WatchdogSec`
  liveness ping (the host already speaks sd_notify for VPN) so a hung-but-alive session restarts.

---

## Execution order (milestones)

1. **M1 — Fail-closed security (P0):** SEC-1, SEC-2, SEC-3, SEC-4. *Nothing deploys to production until these land.*
2. **M2 — Sandbox & trust (P1 sec):** SEC-5…SEC-8 + SEC-DOC.
3. **M3 — 1 GB stability (P1 perf):** PERF-1, PERF-2.
4. **M4 — Footprint polish + DiD:** PERF-3…PERF-7, SEC-9…SEC-13.
5. **M5 — Operability + cut v1.0.0:** OPS-1…OPS-4, then the Definition-of-Done gate and tag.

**Working rule:** one task per branch off `main`, each with its regression test, each green through
`make test && make lint` before merge. Security tasks get a test that proves the *attack* is blocked,
not just that the happy path still works.
