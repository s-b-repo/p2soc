#!/usr/bin/env bash
# Launch the graphical SOC wall setup wizard (host.setupgui).
# The control center (soc-wall.desktop) execs this wrapper for its "Setup" card —
# there is no separate setup .desktop entry. It sources the (non-secret) env, sets PYTHONPATH to the in-tree host
# package, requires a graphical display, and runs the wizard in the foreground.
# Any extra args are passed through (e.g. --preset NAME --output DIR for headless
# use, --list-presets), but the GUI is the default with no args.
set -euo pipefail

ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"

# Self-locating: prefer the parent of THIS scripts/ dir (so running from a dev
# checkout wins over a stale /opt deploy), then SOC_ROOT, then /opt/soc-display.
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
ROOT="${SOC_ROOT:-$(CDPATH= cd -- "$(dirname -- "$SELF")/.." 2>/dev/null && pwd)}"
[ -d "$ROOT/kiosk-host" ] || { echo "soc-wall-setup-gui: cannot find installation root (no kiosk-host/). Set SOC_ROOT=/path/to/repo" >&2; exit 1; }

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

# Load the (non-secret) env for vault backend, paths and timeouts if present.
# Absent in dev checkouts — the wizard falls back to its defaults / dev vault.
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
# Reap the temp file on EVERY exit — including Ctrl-C / SIGTERM while the blocking
# guierror dialog is open — so repeated desktop launches don't litter /tmp.
# Single-quoted so $ERRLOG expands at trap-fire time. (Same idiom as dev/run-wall.sh.)
trap 'rm -f "$ERRLOG" 2>/dev/null' EXIT INT TERM
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
