#!/bin/sh
set -eu
SELF="$(readlink -f "$0")"
ROOT="${SOC_ROOT:-$(dirname "$(dirname "$SELF")")}"
export SOC_ROOT="$ROOT"
ACTION="$1"
shift
. "$ROOT/scripts/soc-native.sh"
NATIVE="$(soc_native_path "$ROOT" || true)"
PYTHON="$ROOT/.venv/bin/python"
case "$ACTION" in
  firstboot)
    if [ -n "$NATIVE" ]; then exec "$NATIVE" setup firstboot "$@"; fi
    exec "$PYTHON" "$ROOT/setup.py" firstboot "$@" ;;
  tarpit)
    if [ -n "$NATIVE" ]; then exec "$NATIVE" tarpit "$@"; fi
    exec python3 "$ROOT/scripts/tarpit.py" "$@" ;;
  pin-jump-host)
    if [ -n "$NATIVE" ]; then exec "$NATIVE" with-env pin-jump-host "$@"; fi
    exec "$PYTHON" "$ROOT/scripts/pin-jump-host.py" "$@" ;;
  *) echo "unknown SOC service: $ACTION" >&2; exit 2 ;;
esac
