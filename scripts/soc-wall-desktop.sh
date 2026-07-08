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

ROOT="${SOC_ROOT:-/opt/soc-display}"
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"
MODE="fullscreen"

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

# Load the (tmpfs, 0600) env for vault creds, ports and timeouts if it is present.
# Absent in dev checkouts — the host falls back to its defaults / dev vault.
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
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

export PYTHONPATH="$ROOT/kiosk-host${PYTHONPATH:+:$PYTHONPATH}"
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-/etc/soc-display/panels.yaml}"
export SOC_INJECT_TMPL="${SOC_INJECT_TMPL:-$ROOT/inject/login.js.tmpl}"
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

cd "$ROOT" 2>/dev/null || true
exec "$PYBIN" -m host.main
