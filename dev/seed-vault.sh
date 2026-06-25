#!/usr/bin/env bash
# DEV: register the kiosk account in a local Vaultwarden and seed the 4 dev
# panel logins via litebw, then mirror them into dev/run/dev-vault.json for the
# `dev` vault backend. Idempotent. Requires: Vaultwarden running.
#
# On the Pi you create the account in the Vaultwarden web UI and seed real
# logins — this script is only for local end-to-end testing.
set -euo pipefail
cd "$(dirname "$0")/.."

VW_URL="${SOC_VAULT_URL:-http://127.0.0.1:8222}"
EMAIL="${SOC_VAULT_EMAIL:-kiosk@soc.local}"
PASS="${SOC_VAULT_PASSWORD:-DevMaster#1}"

export PATH="$PWD/scripts:$HOME/.cargo/bin:$PATH"
# isolate vault state under dev/run so we don't touch the user's real vault config
export XDG_CONFIG_HOME="$PWD/dev/run/xdg/config"
export XDG_CACHE_HOME="$PWD/dev/run/xdg/cache"
export XDG_DATA_HOME="$PWD/dev/run/xdg/data"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" dev/run
export SOC_VAULT_PASSWORD="$PASS"

echo "==> registering account (idempotent)"
.venv/bin/python dev/register-vaultwarden.py "$VW_URL" "$EMAIL" "$PASS" || true

echo "==> configuring litebw"
litebw config set email "$EMAIL"
litebw config set base_url "$VW_URL"
litebw config set pinentry "$PWD/scripts/pinentry-vault.py"

echo "==> login + unlock + sync"
litebw login
litebw unlock

# Seed the 4 dev login items via the Vaultwarden REST API. (We use the API
# rather than a litebw add command because litebw is read-only by design; the
# kiosk host only ever READS via litebw, which this verifies.)
echo "==> seeding items via API"
.venv/bin/python dev/seed-ciphers.py "$VW_URL" "$EMAIL" "$PASS"
litebw sync

echo "==> mirroring to dev/run/dev-vault.json (for SOC_VAULT_BACKEND=dev)"
cat > dev/run/dev-vault.json <<'EOF'
{
  "SOC Dev Panel 1": {"username": "viewer1", "password": "devpass1"},
  "SOC Dev Panel 2": {"username": "viewer2", "password": "devpass2"},
  "SOC Dev Panel 3": {"username": "viewer3", "password": "devpass3"},
  "SOC Dev Panel 4": {"username": "viewer4", "password": "devpass4"},
  "SOC Dev VPN": {"username": "vpnuser", "password": "vpnpass"}
}
EOF

echo "==> done. verifying a seeded item via litebw get:"
litebw get --field username "SOC Dev Panel 1"
