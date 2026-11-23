#!/bin/sh
set -eu
SELF="$(readlink -f "$0")"
ROOT="${SOC_ROOT:-$(dirname "$(dirname "$SELF")")}"
. "$ROOT/scripts/soc-native.sh"
if NATIVE="$(soc_native_path "$ROOT")"; then
  exec "$NATIVE" with-env pinentry
fi
exec "$ROOT/.venv/bin/python" "$ROOT/scripts/pinentry-vault.py"
