#!/usr/bin/env bash
# Launch and supervise the SOC kiosk host inside the session (X11 or Wayland).
# Started by Openbox autostart / labwc autostart / cage. Sources the (tmpfs)
# env, then restarts the host if it ever exits so the wall self-heals — with
# backoff, so a config error doesn't busy-loop the CPU.
set -u

ROOT="${SOC_ROOT:-/opt/soc-display}"

# Resolve which soc.env / panels.yaml the wall reads through the SAME resolver the
# wizard writes with (host.configpaths), so the shell and Python can never drift.
# PYBIN/PYTHONPATH are needed for the module import — set them early.
export PYTHONPATH="$ROOT/kiosk-host${PYTHONPATH:+:$PYTHONPATH}"
PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"

# Resolve SOC_ENV_FILE BEFORE sourcing it (so we source the right env). `|| true`
# + the literal fallback (== read tier #3) keeps the non-systemd/pre-install path
# working when the resolver module isn't importable yet.
: "${SOC_ENV_FILE:=$("$PYBIN" -m host.configpaths --env 2>/dev/null || true)}"
: "${SOC_ENV_FILE:=/etc/soc-display/soc.env}"
ENV_FILE="$SOC_ENV_FILE"

# Load environment (vault creds, ports, timeouts). Keep this file on tmpfs 0600.
if [ -r "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

# Send everything to the journal when possible: `journalctl -t soc-kiosk -f`
# is then the one place to debug the wall. SOC_NO_JOURNAL=1 keeps stderr (dev).
if [ "${SOC_NO_JOURNAL:-0}" != "1" ] && command -v systemd-cat >/dev/null 2>&1; then
  exec > >(systemd-cat -t soc-kiosk) 2>&1
fi

# Resolve SOC_PANELS_FILE AFTER sourcing soc.env, so an explicit SOC_PANELS_FILE
# baked into the env (read tier #1) wins over the resolver's choice.
: "${SOC_PANELS_FILE:=$("$PYBIN" -m host.configpaths --panels 2>/dev/null || true)}"
: "${SOC_PANELS_FILE:=/etc/soc-display/panels.yaml}"
export SOC_PANELS_FILE SOC_ENV_FILE
export SOC_INJECT_TMPL="${SOC_INJECT_TMPL:-$ROOT/inject/login.js.tmpl}"

# Cap glibc malloc arenas. The default (8*ncpu = 32 on a 4-core Pi 5) lets each
# of the host's many threads (prewarm pool, VPN poll, GTK/GLib workers) scatter
# allocations across arenas that each grow a 64MB heap and never give it back —
# tens to >100MB of RSS bloat on a 1GB board. 2 arenas keeps that headroom.
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"

cd "$ROOT" || exit 1

# Wayland GTK backend, set by the session (SOC_WAYLAND_BACKEND):
#   wayland  native Wayland       x11  XWayland (GDK_BACKEND=x11)
#   auto     start native, and if the host can't bring up a Wayland display
#            (fails fast twice), fall back to XWayland for the rest of the session
wl="${SOC_WAYLAND_BACKEND:-}"
case "$wl" in
  wayland) export GDK_BACKEND=wayland ;;
  x11)     export GDK_BACKEND=x11 ;;
  auto)    export GDK_BACKEND=wayland ;;
esac
native_fails=0

delay=3
while true; do
  started=$(date +%s)
  echo "[launcher] starting kiosk host $(date -Is) (GDK_BACKEND=${GDK_BACKEND:-default})" >&2
  "$PYBIN" -m host.main
  code=$?
  ran=$(( $(date +%s) - started ))

  # native Wayland that fails fast twice -> switch to XWayland (auto only)
  if [ "$wl" = auto ] && [ "${GDK_BACKEND:-}" = wayland ] && [ "$ran" -lt 8 ]; then
    native_fails=$(( native_fails + 1 ))
    if [ "$native_fails" -ge 2 ]; then
      echo "[launcher] native Wayland failed to start twice — switching to" \
           "XWayland (GDK_BACKEND=x11) for this session" >&2
      export GDK_BACKEND=x11
    fi
  fi

  # ran fine for a while -> fast restart; crashing on boot -> back off to 30s
  if [ "$ran" -ge 60 ]; then
    delay=3
  else
    delay=$(( delay * 2 )); [ "$delay" -gt 30 ] && delay=30
  fi
  echo "[launcher] kiosk host exited ($code); restarting in ${delay}s" >&2
  sleep "$delay"
done
