#!/usr/bin/env bash
# DEV: register the kiosk account in a local Vaultwarden and seed the 4 dev
# panel logins via rbw, then mirror them into dev/run/dev-vault.json for the
# `dev` vault backend. Idempotent. Requires: rbw on PATH, Vaultwarden running.
#
# On the Pi you create the account in the Vaultwarden web UI and seed real
# logins — this script is only for local end-to-end testing.
set -euo pipefail
cd "$(dirname "$0")/.."

VW_URL="${SOC_VAULT_URL:-http://127.0.0.1:8222}"
EMAIL="${SOC_VAULT_EMAIL:-kiosk@soc.local}"
PASS="${SOC_VAULT_PASSWORD:-DevMaster#1}"

export PATH="$HOME/.cargo/bin:$PATH"
# isolate rbw state under dev/run so we don't touch the user's real vault config
export XDG_CONFIG_HOME="$PWD/dev/run/xdg/config"
export XDG_CACHE_HOME="$PWD/dev/run/xdg/cache"
export XDG_DATA_HOME="$PWD/dev/run/xdg/data"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" dev/run
export SOC_VAULT_PASSWORD="$PASS"

echo "==> registering account (idempotent)"
.venv/bin/python dev/register-vaultwarden.py "$VW_URL" "$EMAIL" "$PASS" || true

echo "==> configuring rbw"
rbw config set email "$EMAIL"
rbw config set base_url "$VW_URL"
rbw config set pinentry "$PWD/scripts/pinentry-soc.sh"

echo "==> login + unlock + sync"
rbw login
rbw unlock

# Seed the 4 dev login items via the Vaultwarden REST API. (We use the API
# rather than `rbw add` because rbw's editor-based add needs an interactive TTY;
# the kiosk host only ever READS via rbw, which this verifies.)
echo "==> seeding items via API"
.venv/bin/python dev/seed-ciphers.py "$VW_URL" "$EMAIL" "$PASS"
rbw sync

echo "==> mirroring to dev/run/dev-vault.json (for SOC_VAULT_BACKEND=dev)"
cat > dev/run/dev-vault.json <<'EOF'
{
  "SOC Dev Panel 1": {"username": "viewer1", "password": "devpass1"},
  "SOC Dev Panel 2": {"username": "viewer2", "password": "devpass2"},
  "SOC Dev Panel 3": {"username": "viewer3", "password": "devpass3"},
  "SOC Dev Panel 4": {"username": "viewer4", "password": "devpass4"}
}
EOF

echo "==> done. rbw list:"
rbw list
