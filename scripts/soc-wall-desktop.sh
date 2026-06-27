#!/usr/bin/env bash
# On-demand SOC wall launcher for an existing desktop session (DE/login manager).
# This is the clickable-launcher path (soc-wall.desktop): unlike start-session.sh
# it does NOT take over tty1 or spawn a compositor/X server — it attaches to the
# display you are ALREADY logged into ($DISPLAY / $WAYLAND_DISPLAY) and runs the
# kiosk host in the foreground, so closing the window / Ctrl-C ends it cleanly.
#
#   soc-wall-desktop.sh --fullscreen   (default) wall fills the current display
#   soc-wall-desktop.sh --window       run windowed (handy for testing on a DE)
#   soc-wall-desktop.sh --help
set -euo pipefail

# Self-locating: ROOT = the parent of this scripts/ dir, so it works from a dev
# checkout OR the deployed /opt/soc-display. SOC_ROOT overrides.
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
ROOT="${SOC_ROOT:-$(CDPATH= cd -- "$(dirname -- "$SELF")/.." 2>/dev/null && pwd)}"
[ -d "$ROOT/kiosk-host" ] || ROOT="/opt/soc-display"
MODE="fullscreen"

# Resolve which soc.env the wall reads via the SAME resolver the wizard writes
# with (host.configpaths), so shell + Python never drift. Needs PYTHONPATH/PYBIN.
export PYTHONPATH="$ROOT/kiosk-host${PYTHONPATH:+:$PYTHONPATH}"
RESOLVE_PY="$ROOT/.venv/bin/python"
[ -x "$RESOLVE_PY" ] || RESOLVE_PY="$(command -v python3)"
: "${SOC_ENV_FILE:=$("$RESOLVE_PY" -m host.configpaths --env 2>/dev/null || true)}"
: "${SOC_ENV_FILE:=/etc/soc-display/soc.env}"
ENV_FILE="$SOC_ENV_FILE"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

for a in "$@"; do
  case "$a" in
    --fullscreen) MODE="fullscreen" ;;
    --window)     MODE="window" ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "soc-wall-desktop: unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

# Require a display owned by the current session. Without one there is nothing to
# attach to — point the operator at the kiosk (tty1) install instead of failing
# with a cryptic GTK backend error.
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  echo "soc-wall-desktop: no graphical display detected" >&2
  echo "  Run this from inside your desktop session (\$DISPLAY or \$WAYLAND_DISPLAY)." >&2
  echo "  For an unattended kiosk on tty1, install with INSTALL_MODE=kiosk instead." >&2
  exit 1
fi

# Load the (non-secret) env for vault creds, ports and timeouts if it is present.
# Absent in dev checkouts — the host falls back to its defaults / dev vault.
if [ -r "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
elif [ -e "$ENV_FILE" ]; then
  # soc.env exists but THIS user cannot read it -> the vault config (email/URL)
  # never loads and unlock fails with an empty account. soc.env is NON-SECRET
  # (the master is sealed separately), so surface this loudly instead of silently
  # skipping it. The #1 cause of "desktop mode can't unlock the vault".
  echo "WARNING: $ENV_FILE exists but is not readable by $(id -un 2>/dev/null) —" >&2
  echo "  the wall's vault config will not load. Fix: sudo chmod 0644 $ENV_FILE" >&2
fi

# Attach to whichever display the DE gave us. If only Wayland is present, use the
# native GTK Wayland backend; otherwise let GTK use X11/XWayland as usual.
if [ -z "${DISPLAY:-}" ] && [ -n "${WAYLAND_DISPLAY:-}" ]; then
  export GDK_BACKEND="${GDK_BACKEND:-wayland}"
fi

case "$MODE" in
  fullscreen) export SOC_WINDOW_MODE="${SOC_WINDOW_MODE:-fullscreen}" ;;
  window)     export SOC_WINDOW_MODE="window" ;;
esac

# Prefer the in-tree launcher (self-healing supervisor) when this is a deployed
# tree; in a dev checkout fall back to running the host module directly.
if [ -x "$ROOT/scripts/launcher.sh" ]; then
  exec "$ROOT/scripts/launcher.sh"
fi

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

# Resolve SOC_PANELS_FILE AFTER sourcing soc.env so an explicit one in the env wins.
: "${SOC_PANELS_FILE:=$("$PYBIN" -m host.configpaths --panels 2>/dev/null || true)}"
: "${SOC_PANELS_FILE:=/etc/soc-display/panels.yaml}"
export SOC_PANELS_FILE SOC_ENV_FILE
export SOC_INJECT_TMPL="${SOC_INJECT_TMPL:-$ROOT/inject/login.js.tmpl}"
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"

cd "$ROOT" 2>/dev/null || true
exec "$PYBIN" -m host.main
