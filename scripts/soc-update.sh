#!/bin/sh
set -eu
SELF="$(readlink -f "$0")"
ROOT="$(dirname "$(dirname "$SELF")")"
. "$ROOT/scripts/soc-native.sh"
if NATIVE="$(soc_native_path "$ROOT")"; then
  exec "$NATIVE" update "$@"
fi
exec python3 "$ROOT/scripts/soc-update.py" "$@"
