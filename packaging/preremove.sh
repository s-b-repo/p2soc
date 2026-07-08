#!/usr/bin/env bash
# =============================================================================
# p2soc — package preremove (deb/rpm/apk).
#
# Stops and disables the p2soc services so nothing keeps running once the files
# are gone. It deliberately leaves operator data in place:
#   * /etc/soc-display      (panels.yaml, soc.env, sealed master, keys/secret)
#   * /var/lib/vaultwarden  (the vault database)
#   * the `soc` / `socsvc` / `vaultwarden` users
# so a reinstall (or an upgrade that re-runs preremove) keeps the configured
# wall intact. Purge of that data is an explicit operator action, never ours.
#
# Idempotent and best-effort: a unit that was never enabled, or a host without
# systemd, must not fail the package transaction.
# =============================================================================
set -euo pipefail

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*"; }

# No running systemd (build chroot / non-systemd host): nothing to stop.
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
  warn "no running systemd — nothing to stop/disable"
  exit 0
fi

# Stop + disable in dependency-friendly order (the wall, then its supports, then
# the vault). `--now` stops as it disables; everything is best-effort so a
# not-installed / not-enabled unit is a no-op.
UNITS="soc-wall.service autossh-tunnel.service forti-vpn.service vaultwarden.service"
for unit in $UNITS; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    log "Disabling $unit"
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  fi
done

systemctl daemon-reload >/dev/null 2>&1 || true

# NOTE: operator data is intentionally preserved (see header). We do NOT touch
# /etc/soc-display, /var/lib/vaultwarden, the getty@tty1 autologin override, or
# the soc/socsvc/vaultwarden users.

exit 0
