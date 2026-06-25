#!/usr/bin/env bash
# Launch the graphical SOC wall setup wizard (host.setupgui).
# This is the clickable path (soc-wall-setup.desktop / the launcher's "Setup"
# card). It sources the (tmpfs, 0600) env, sets PYTHONPATH to the in-tree host
# package, requires a graphical display, and runs the wizard in the foreground.
# Any extra args are passed through (e.g. --preset NAME --output DIR for headless
# use, --list-presets), but the GUI is the default with no args.
set -euo pipefail

ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"

# Self-locating: prefer the parent of THIS scripts/ dir (so running from a dev
# checkout wins over a stale /opt deploy), then SOC_ROOT, then /opt/soc-display.
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
ROOT="${SOC_ROOT:-$(CDPATH= cd -- "$(dirname -- "$SELF")/.." 2>/dev/null && pwd)}"
[ -d "$ROOT/kiosk-host" ] || ROOT="/opt/soc-display"

# Headless / discovery invocations don't need a display.
HEADLESS=0
for a in "$@"; do
  case "$a" in
    --preset|--preset=*|--output|--output=*|--list-presets|--non-interactive)
      HEADLESS=1 ;;
  esac
done

# A real GUI run requires a display owned by the current session.
if [ "$HEADLESS" -eq 0 ]; then
  if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "soc-wall-setup-gui: no graphical display detected" >&2
    echo "  Run this from inside your desktop session (\$DISPLAY or \$WAYLAND_DISPLAY)." >&2
    echo "  For a text-mode wizard over SSH/tty, run instead: python3 setup.py wizard" >&2
    exit 1
  fi
fi

# Load the (tmpfs, 0600) env for vault backend, paths and timeouts if present.
# Absent in dev checkouts — the wizard falls back to its defaults / dev vault.
if [ -r "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

# Attach to a Wayland-only display via the native GTK backend.
if [ -z "${DISPLAY:-}" ] && [ -n "${WAYLAND_DISPLAY:-}" ]; then
  export GDK_BACKEND="${GDK_BACKEND:-wayland}"
fi

export SOC_ROOT="$ROOT"
export PYTHONPATH="$ROOT/kiosk-host${PYTHONPATH:+:$PYTHONPATH}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

cd "$ROOT" 2>/dev/null || true
exec "$PYBIN" -m host.setupgui "$@"
