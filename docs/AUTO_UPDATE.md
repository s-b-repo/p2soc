# Zero-touch operation

After `soc-wall setup deploy`, the wall boots into the panels, recovers
from failures, and redeploys itself when a new version is published. This page
covers how that works, what it needs from you, and how to operate it.

## What keeps it running

| Failure | What happens |
|---|---|
| Panel crashes or leaks memory | Reloaded or recycled, heaviest first |
| Host process dies | `launcher.sh` restarts it |
| Host hangs (frozen screen, process alive) | Its heartbeat stops, and `launcher.sh` kills and restarts it |
| Compositor or X server dies | getty logs back in and the session restarts |
| Vault locked, late or unreachable | Status on screen, retries forever, recovers without a restart |
| Bad config | Fail-safe screen, keeps retrying, so a redeploy can fix it |
| VPN or tunnel drops | Supervised reconnect with backoff |
| Kernel or PID 1 hangs | Hardware watchdog reboots the box (kiosk mode) |
| Kernel panic | Reboots after 10 seconds |
| Deployed files damaged | Redeployed from the same commit, checked once a day |
| Bad release | Rolled back automatically, retried once later, then blocklisted |

`SOC_UNATTENDED=1` (set by the installer in kiosk mode) is what guarantees no
dialog can wait on a person. Without it, an interactive desktop keeps its dialogs.

## How a redeploy works

Every 15 minutes, and 3 minutes after boot, `soc-update.timer` asks the remote for the
tip of the tracked ref. That is one small request and writes nothing to the SD card.
When there is a new commit:

1. **Fetch** it, as the unprivileged `socupdate` user.
2. **Refuse** it if the tip is older than what is deployed, or if signature
   enforcement is on and the commit isn't validly signed.
3. **Build** a complete release beside the live one, in `/opt/soc-releases/<id>/`.
   Any new OS packages install here. A failure here means "retry later".
4. **Prove** it. The candidate builds, its shell scripts parse, its config checks
   pass, and its updater passes its self-test before activation.
5. **Swap.** `/opt/soc-display` is a symlink, so switching is one atomic rename. The
   intent is written to disk first, so a power cut at any moment is recoverable.
6. **Restart** tunnels, then the wall.
7. **Watch.** The wall must beat from the new commit, with `state=running`, at least
   one panel loaded and the same process staying up for a full minute.
8. **Keep it, or roll back.** A failure swaps back, restores the previous release's
   system files and restarts.

What happens to a rolled-back commit depends on why it failed. A failure at step 4
can't get better, so that commit is blocked for good. A failed health check might not
be the release's fault (the VPN can drop during the window), so it gets one more try six
hours later. A second failure blocks it. A release that takes the box down before its
health check can finish is abandoned after two attempts.

The wall blanks briefly during step 6, for up to a minute on a Pi. Use
`SOC_UPDATE_WINDOW` if that matters.

A release is judged only against how things were before it. If the wall or a service
was already down, a good release isn't rolled back for that, so a release that fixes
the problem can still land.

Nothing runs until deployment has finished, and `install.sh` and the updater share a
lock, so a manual install can't collide with an update.

## What it needs from you

**Decide who can deploy to your walls.** This is the one decision to make. The
updater runs what it fetches as root, so by default **anyone who can push to the
tracked ref can run code as root on every wall.** To close that, require signed
commits:

```bash
# on each wall: who may sign releases (ssh-keygen allowed-signers format)
echo 'you@example.com ssh-ed25519 AAAA...' | sudo tee /etc/soc-display/update-signers
```

From then on, an unsigned or wrongly-signed commit is refused. The check fails closed:
it applies whenever the file exists, and needs git 2.34 or newer. Sign with
`git config gpg.format ssh && git config user.signingkey ~/.ssh/id_ed25519 && git config commit.gpgsign true`.
Note that GitHub's squash and merge buttons create commits signed by GitHub's key, not
yours, so use fast-forward or rebase merges, or add that key too.

**Add a dead-man's switch.** A box can't report that it has lost power or network.
Set `SOC_HEALTHCHECK_URL` to a monitor such as healthchecks.io. The updater pings it
after every healthy run and appends `/fail` after a bad one, and the monitor pages you
when the pings stop.

## The release channel

Walls follow `stable`, and only CI moves `stable`: `.github/workflows/ci.yml`
fast-forwards it to `main` after lint, tests and the secret scan all pass. So a push
that breaks the build never reaches a wall. Until `stable` first exists, walls use
`main` (`SOC_UPDATE_FALLBACK_REF`).

The health check catches a release that won't run. CI catches a release that runs but
is wrong. You want both.

Version tags build downloadable packages. They do not move the tracked
`stable` branch. See [Releasing](RELEASING.md).

## Configuration

`/etc/soc-display/update.env`, read as plain data and never sourced:

| Key | Default | Meaning |
|---|---|---|
| `SOC_UPDATE_ENABLE` | `1` | `0` turns off redeploys and self-repair |
| `SOC_UPDATE_REPO` | the repo installed from | `https://` only, no embedded credentials. If the source can't be worked out (a tarball, say), redeploys stay off until you set this |
| `SOC_UPDATE_REF` | `stable` | Branch or tag to follow |
| `SOC_UPDATE_FALLBACK_REF` | `main` | Used while the ref doesn't exist |
| `SOC_UPDATE_WINDOW` | any time | When to apply, e.g. `03:00-05:00`, may wrap midnight |
| `SOC_UPDATE_REPAIR` | `1` | Repair damaged files. `0` if you hand-edit `/opt` |
| `SOC_UPDATE_SIGNERS` | `/etc/soc-display/update-signers` | Enforced if the file exists |
| `SOC_HEALTHCHECK_URL` | off | Dead-man's switch, `https://` only |
| `SOC_UPDATE_HEALTH_TIMEOUT` | `300` | Seconds a new release has to prove itself |
| `SOC_UPDATE_HEALTH_STABLE` | `60` | Seconds it must stay healthy on one process |
| `SOC_UPDATE_KEEP` | `3` | Releases kept for rollback |
| `SOC_UPDATE_MIN_FREE_MB` | `300` | Minimum free disk before staging a release. Allow additional room for Cargo’s build files on source installations. |

## Operating it

Source installations stage and build the native binary before switching the live
release. Run the updater with Rust 1.87 or newer on root’s `PATH`. Distribution
packages use the distribution’s package manager for updates.

```bash
soc-update status                 # what's deployed, last result, blocklist
sudo soc-update run --now         # check now, ignoring the window
sudo soc-update rollback          # back one release, and blocklist the current one
journalctl -u soc-update          # full history
```

To retry a blocked commit, remove it from `bad` in `/var/lib/soc-update/state.json`.
Normally you'd push a fix, which has a new hash and is not blocked. After a failed build
(no network, a full disk) the updater waits an hour before trying again; `--now` skips
that wait.

## What a redeploy never touches

- `/etc/soc-display`: panels, `soc.env`, the sealed master, keys, branding.
- `/etc/nftables.conf`, which holds your subnets and egress sets. Even a manual
  `install.sh` keeps it once it exists. Edit it directly.
- The Vaultwarden database. Moving to a new Vaultwarden is a deliberate change to
  `security/vaultwarden.lock`, and a copy of the database is kept at
  `db.sqlite3.pre-upgrade`. Its migrations only run forwards, so **a rollback keeps the
  newer Vaultwarden binary** rather than downgrade it.

## Limits

- **Packaged installs** (deb/rpm/apk) update through the package manager. `/opt/soc-display`
  is a real directory there, so the timer stays off.
- **No systemd, no redeploys.** Everything else still works, but the updater needs its timer.
- **`HARDEN=1` firewalls** let web traffic out only for the updater's uids. If your
  network also filters outbound traffic, allow `github.com` and your package mirrors.
- **A person is still needed** for hardware failure, for credentials that expire on the
  far side (a rotated VPN password has to be updated in the vault), and to read the
  alert if a release is rolled back.
- The first deployment still needs someone to supply panels and logins, once, unless
  you script it with `soc-wall setup deploy --unattended` (see [DEPLOY.md](DEPLOY.md)).
