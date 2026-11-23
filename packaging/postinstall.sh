#!/usr/bin/env bash
# Install packaged files and services using the same installer as source builds.
set -euo pipefail

SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
ETC="${SOC_ETC:-/etc/soc-display}"
INSTALLER="$SOC_ROOT/install.sh"

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*"; }

# nfpm guard: if the payload is missing (partial/odd install), do nothing rather
# than fail the package transaction.
[ -x "$INSTALLER" ] || { warn "$INSTALLER not found/executable — skipping postinstall"; exit 0; }

# systemd may be absent in a build chroot or a non-systemd host. install.sh
# already degrades gracefully (its `command -v systemctl && [ -d /run/systemd/system ]`
# gate), and we mirror that gate for our own enable step below.
HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  HAS_SYSTEMD=1
fi

# --------------------------------------------------------------------------- #
# 1. Run the project installer with package management disabled (Depends did it).
#    SESSION/VW_MODE are overridable via the package env; default to the same
#    values install.sh itself defaults to (auto / native).
# --------------------------------------------------------------------------- #
log "Running install.sh (SOC_SKIP_PACKAGES=1 — OS deps came from package Depends)"
SOC_SKIP_PACKAGES=1 \
SESSION="${SESSION:-auto}" \
VW_MODE="${VW_MODE:-native}" \
SOC_ROOT="$SOC_ROOT" \
  "$INSTALLER"

# --------------------------------------------------------------------------- #
# 2. Enable (do NOT start) the core units. install.sh already enables
#    vaultwarden (+ conditionally autossh-tunnel/forti-vpn from panels.yaml);
#    re-affirm vaultwarden idempotently here so an upgrade can't leave it
#    disabled. soc-wall.service is deliberately left NOT enabled — boot stays on
#    getty autologin until the operator validates the wall on the real display.
# --------------------------------------------------------------------------- #
if [ "$HAS_SYSTEMD" = "1" ]; then
  systemctl daemon-reload || true
  systemctl enable vaultwarden.service >/dev/null 2>&1 || true
  log "Units installed. soc-wall.service is installed but NOT enabled (enable it"
  log "after validating the wall: systemctl enable --now soc-wall.service)."
else
  warn "no running systemd — units deployed but not enabled. See $SOC_ROOT/systemd/."
fi

# --------------------------------------------------------------------------- #
# 3. Next steps (the package is installed; the operator still does first-run).
# --------------------------------------------------------------------------- #
cat <<EOF

$(printf '\033[32mp2soc installed.\033[0m')  Next steps:

  1. Configure panels:   sudo \$EDITOR $ETC/panels.yaml
     (IPs, ports, selectors, vault_item, tunnel, vpn) — or use the wizard below.
  2. Non-secret env:     sudo \$EDITOR $ETC/soc.env
     (email/url + SOC_SESSION; the master password is NOT here — it is sealed
      host-bound at first-run, step 3).
  3. First-time setup:   sudo $SOC_ROOT/bin/soc-wall setup first-run
     -> seals the Vaultwarden master password host-bound (no plaintext .env),
        points litebw at the sealed master, and generates the one-time PIN.
     (Guided menu for everything:  sudo $SOC_ROOT/bin/soc-wall setup)
  4. Start the vault, create the kiosk account + logins (named to match each
     vault_item), then validate + enable the wall:
        sudo systemctl start vaultwarden
        sudo systemctl enable --now soc-wall.service

EOF

exit 0
