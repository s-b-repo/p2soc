#!/usr/bin/env bash
# Launch the graphical SOC wall APPEARANCE editor (host.appearance).
# The control center (soc-wall.desktop) execs this wrapper for its "Appearance"
# tile — there is no separate appearance .desktop entry. Sources the (non-secret) env if readable, sets
# PYTHONPATH to the in-tree host package, requires a graphical display, runs the
# editor in the foreground; on a non-zero exit it pops the themed guierror so a
# clickable launch never "does nothing". Honours SOC_RETURN_TO_MENU like setup.
set -euo pipefail

ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"

# Self-locating: prefer the parent of THIS scripts/ dir (a dev checkout wins over
# a stale /opt deploy), then SOC_ROOT, then /opt/soc-display.
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
ROOT="${SOC_ROOT:-$(CDPATH= cd -- "$(dirname -- "$SELF")/.." 2>/dev/null && pwd)}"
[ -d "$ROOT/kiosk-host" ] || ROOT="/opt/soc-display"

# Cap GLib/GTK per-thread malloc arenas (default 8*ncpu) — the single biggest RSS
# cut on the 1GB Pi (same rationale as launcher.sh). Trim the GTK runtime too.
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"

# The editor is GUI-only; --check/--list-presets/--preset are headless smokes.
HEADLESS=0
for a in "$@"; do
  case "$a" in
    --check|--list-presets|--preset|--preset=*|--output|--output=*) HEADLESS=1 ;;
  esac
done

if [ "$HEADLESS" -eq 0 ]; then
  if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "soc-wall-appearance: no graphical display detected" >&2
    echo "  Run this from inside your desktop session (\$DISPLAY or \$WAYLAND_DISPLAY)." >&2
    exit 1
  fi
fi

# Load the (non-secret) env if present (non-secret knobs). Absent in dev checkouts.
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

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

cd "$ROOT" 2>/dev/null || true

# Headless / discovery runs (CI): let output flow and exec.
if [ "$HEADLESS" -eq 1 ]; then
  exec "$PYBIN" -m host.appearance "$@"
fi

# GUI run: don't exec — a clickable .desktop launch discards stderr, so surface a
# silent failure in a visible themed dialog (fail-safe).
ERRLOG="$(mktemp 2>/dev/null || echo "/tmp/soc-wall-appearance.$$.log")"
# Reap the temp file on EVERY exit — including Ctrl-C / SIGTERM while the blocking
# guierror dialog is open — so repeated desktop launches don't litter /tmp.
# Single-quoted so $ERRLOG expands at trap-fire time. (Same idiom as dev/run-wall.sh.)
trap 'rm -f "$ERRLOG" 2>/dev/null' EXIT INT TERM
set +e
"$PYBIN" -m host.appearance "$@" 2>"$ERRLOG"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  cat "$ERRLOG" >&2 2>/dev/null || true
  detail="$(tail -n 15 "$ERRLOG" 2>/dev/null)"
  [ -n "$detail" ] || detail="The appearance editor exited with status $rc and produced no message."
  "$PYBIN" -m host.guierror "SOC Wall appearance couldn't start (exit $rc)" "$detail" 2>/dev/null || true
  rm -f "$ERRLOG" 2>/dev/null || true
  exit "$rc"
fi
rm -f "$ERRLOG" 2>/dev/null || true

# When launched from the launcher menu, return to it (the "main page").
if [ "${SOC_RETURN_TO_MENU:-0}" = "1" ] && [ -x "$ROOT/scripts/soc-wall-menu" ]; then
  exec "$ROOT/scripts/soc-wall-menu"
fi
exit 0
