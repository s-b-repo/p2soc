#!/usr/bin/env bash
# ftnt-connect.sh — native Python Fortinet SSL-VPN connect (no openfortivpn).
#
#   ftnt-connect.sh <gateway[:port]> <username> [-- <extra backend args>]
#
# Password: taken from $FTNT_SVPN_PASSWORD if set, otherwise prompted.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$DIR/backends"

usage() { sed -n '2,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 1; }
case "${1:-}" in -h|--help) usage;; esac

GW="${1:-}"; USER="${2:-}"
[ -n "$GW" ] && [ -n "$USER" ] || usage
shift 2

EXTRA=( "$@" )

PW="${FTNT_SVPN_PASSWORD:-}"
if [ -z "$PW" ]; then read -rsp "Password: " PW; echo; fi

export PYTHONPATH="$BACKEND${PYTHONPATH:+:$PYTHONPATH}" PYTHONSAFEPATH=1
export FTNT_SVPN_PASSWORD="$PW"
exec python3 -m fortigate "$GW" -u "$USER" "${EXTRA[@]}"
