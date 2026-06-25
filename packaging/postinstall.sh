#!/usr/bin/env bash
# =============================================================================
# p2soc — package postinstall (deb/rpm/apk).
#
# Reuses the project's own installer for ALL deploy/config/service work:
#
#     SOC_SKIP_PACKAGES=1 /opt/soc-display/install.sh
#
# SOC_SKIP_PACKAGES=1 turns install.sh's pm_install/pm_try/pm_refresh into
# no-ops — the package's declared per-packager Depends already pulled every OS
# package — so install.sh runs only its distro-agnostic steps: create the `soc`
# (kiosk) + `socsvc` (service) users, self-deploy/re-chown the tree, install the
# litebw launcher, build the --system-site-packages venv (PyYAML +
# websocket-client + wheel-only cryptography), populate /etc/soc-display, copy
# the systemd units, daemon-reload, enable vaultwarden + (conditionally)
# autossh-tunnel/forti-vpn, and wire the kiosk session + tty1 autologin.
# soc-wall.service is deployed but intentionally left NOT enabled (boot stays on
# getty autologin until validated on the target display).
#
# This script only adds a thin safety-net on top of install.sh: it guards on the
# installer being present, re-affirms the venv deps if for any reason install.sh
# skipped them, makes sure the core units are enabled, and prints the next
# steps. It is idempotent — safe to run on every upgrade.
# =============================================================================
set -euo pipefail

SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
ETC="${SOC_ETC:-/etc/soc-display}"
INSTALLER="$SOC_ROOT/install.sh"
VENV="$SOC_ROOT/.venv"

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
#    values install.sh itself defaults to (auto / docker).
# --------------------------------------------------------------------------- #
log "Running install.sh (SOC_SKIP_PACKAGES=1 — OS deps came from package Depends)"
SOC_SKIP_PACKAGES=1 \
SESSION="${SESSION:-auto}" \
VW_MODE="${VW_MODE:-docker}" \
SOC_ROOT="$SOC_ROOT" \
  "$INSTALLER"

# --------------------------------------------------------------------------- #
# 2. venv safety-net. install.sh already builds the venv and pip-installs these,
#    so this is a no-op on a normal run; it only repairs the rare case where the
#    installer's venv step was skipped (e.g. an older install.sh) so the wall is
#    never left without its Python deps. cryptography stays wheel-only and falls
#    back to the distro python3-cryptography Depends (the venv is
#    --system-site-packages) — never a source build on the Pi.
# --------------------------------------------------------------------------- #
PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
if [ ! -x "$PY" ]; then
  log "venv missing after install.sh — creating $VENV"
  python3 -m venv --system-site-packages "$VENV"
  "$PIP" install -q --upgrade pip || true
fi

if ! "$PY" -c 'import yaml, websocket, cryptography' >/dev/null 2>&1; then
  log "Ensuring venv deps (PyYAML, websocket-client, cryptography)"
  "$PIP" install -q PyYAML websocket-client || warn "pip install PyYAML/websocket-client failed"
  # wheel-only; if no wheel for this arch, the distro python3-cryptography Depends
  # is already importable through --system-site-packages.
  if ! "$PY" -c 'import cryptography' >/dev/null 2>&1; then
    "$PIP" install -q --only-binary=:all: cryptography \
      || warn "no cryptography wheel for this arch — relying on the distro python3-cryptography Depends"
  fi
fi

# --------------------------------------------------------------------------- #
# 3. Enable (do NOT start) the core units. install.sh already enables
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
# 4. Next steps (the package is installed; the operator still does first-run).
# --------------------------------------------------------------------------- #
cat <<EOF

$(printf '\033[32mp2soc installed.\033[0m')  Next steps:

  1. Configure panels:   sudo \$EDITOR $ETC/panels.yaml
     (IPs, ports, selectors, vault_item, tunnel, vpn) — or use the wizard below.
  2. Non-secret env:     sudo \$EDITOR $ETC/soc.env
     (email/url + SOC_SESSION; the master password is NOT here — it is sealed
      host-bound at first-run, step 3).
  3. First-time setup:   sudo python3 $SOC_ROOT/setup.py first-run
     -> seals the Vaultwarden master password host-bound (no plaintext .env),
        points litebw at the sealed master, and generates the one-time PIN.
     (Guided menu for everything:  sudo python3 $SOC_ROOT/setup.py)
  4. Start the vault, create the kiosk account + logins (named to match each
     vault_item), then validate + enable the wall:
        sudo systemctl start vaultwarden
        sudo systemctl enable --now soc-wall.service

EOF

exit 0
