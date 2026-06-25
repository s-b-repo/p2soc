#!/usr/bin/env bash
# OPS-1: encrypted backup / restore of the Vaultwarden data dir.
#
# The backup is encrypted under a passphrase you keep OFF the box (not the
# host-bound seal), so it can be restored on fresh hardware after an SD failure.
# After restoring on a new host you must RE-SEAL the master (setup.py first-run),
# because the seal is bound to the old machine-id + host.key.
#
#   scripts/vault-backup.sh backup   [/path/out.bak]
#   scripts/vault-backup.sh restore  /path/in.bak  [/restore/dest]
#
# Passphrase comes from $SOC_BACKUP_PASSPHRASE or an interactive prompt — never
# on the command line.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PY="${SOC_PY:-$ROOT/.venv/bin/python}"
[ -x "$PY" ] || PY=python3
DATA_DIR="${SOC_VAULT_DATA_DIR:-/var/lib/vaultwarden}"
export PYTHONPATH="$ROOT/kiosk-host${PYTHONPATH:+:$PYTHONPATH}"

cmd="${1:-}"
case "$cmd" in
  backup)
    out="${2:-vaultwarden-$(date +%Y%m%d-%H%M%S 2>/dev/null || echo backup).bak}"
    exec "$PY" -m host.backup backup "$DATA_DIR" "$out"
    ;;
  restore)
    [ -n "${2:-}" ] || { echo "usage: $0 restore <in.bak> [dest]" >&2; exit 2; }
    dest="${3:-$DATA_DIR}"
    exec "$PY" -m host.backup restore "$2" "$dest"
    ;;
  *)
    echo "usage: $0 {backup [out.bak] | restore <in.bak> [dest]}" >&2
    exit 2
    ;;
esac
