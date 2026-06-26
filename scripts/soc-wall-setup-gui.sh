#!/usr/bin/env bash
# Launch the graphical SOC wall setup wizard (host.setupgui).
# The control center (soc-wall.desktop) execs this wrapper for its "Setup" card —
# there is no separate setup .desktop entry. It sources the (tmpfs, 0600) env, sets PYTHONPATH to the in-tree host
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

# Cap GLib/GTK per-thread malloc arenas (default 8*ncpu) — the single biggest RSS
# cut on the 1GB Pi (same rationale as launcher.sh).
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

cd "$ROOT" 2>/dev/null || true

# Headless / discovery runs (CI, setup.py reuse): let output flow and exec.
if [ "$HEADLESS" -eq 1 ]; then
  exec "$PYBIN" -m host.setupgui "$@"
fi

# GUI run: do NOT exec — a clickable .desktop launch (Terminal=false) discards
# stderr, so a silent early failure would look like "the button does nothing".
# Run it, and if it dies, surface the cause in a visible themed dialog (fail-safe).
ERRLOG="$(mktemp 2>/dev/null || echo "/tmp/soc-wall-setup.$$.log")"
set +e
"$PYBIN" -m host.setupgui "$@" 2>"$ERRLOG"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  cat "$ERRLOG" >&2 2>/dev/null || true       # still log to a terminal if there is one
  detail="$(tail -n 15 "$ERRLOG" 2>/dev/null)"
  [ -n "$detail" ] || detail="The setup wizard exited with status $rc and produced no message."
  "$PYBIN" -m host.guierror "SOC Wall setup couldn't start (exit $rc)" "$detail" 2>/dev/null || true
  rm -f "$ERRLOG" 2>/dev/null || true
  exit "$rc"
fi
rm -f "$ERRLOG" 2>/dev/null || true

# Success: when launched from the launcher menu, return to it (the "main page")
# so the operator lands back where they started and can start the wall with the
# fresh config. Standalone (.desktop) launches just exit back to the desktop.
if [ "${SOC_RETURN_TO_MENU:-0}" = "1" ] && [ -x "$ROOT/scripts/soc-wall-menu" ]; then
  exec "$ROOT/scripts/soc-wall-menu"
fi
exit 0
