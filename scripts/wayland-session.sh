#!/usr/bin/env bash
# Wayland kiosk session for the SOC wall. Started by start-session.sh on tty1.
#
# Picks the lightest compositor that fits the configured wall:
#   * all panels webkit + layout single/auto  -> cage  (single fullscreen app)
#   * anything else                           -> labwc (openbox-like window
#     rules generated from panels.yaml place each window into its grid cell)
# SOC_COMPOSITOR overrides the choice (e.g. sway, or a custom kiosk compositor).
# Falls back gracefully and prints actionable errors when nothing fits.
set -u

ROOT="${SOC_ROOT:-/opt/soc-display}"
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi
export SOC_PANELS_FILE="${SOC_PANELS_FILE:-/etc/soc-display/panels.yaml}"

PYBIN="$ROOT/.venv/bin/python"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"
LAUNCHER="$ROOT/scripts/launcher.sh"

log(){ echo "[wayland-session] $*" >&2; }

# What does the wall need? (layout=..., all_webkit=...)
layout=windows; all_webkit=0
eval "$("$PYBIN" "$ROOT/scripts/session-info.py" 2>/dev/null)" || true

start_cage(){
  # host draws the whole grid in one fullscreen window — no WM needed
  export SOC_LAYOUT=single
  log "starting cage (single-window wall)"
  exec cage -- "$LAUNCHER"
}

start_labwc(){
  CFGDIR="${XDG_CONFIG_HOME:-$HOME/.config}/labwc"
  mkdir -p "$CFGDIR"
  if ! "$PYBIN" "$ROOT/scripts/gen-labwc-rc.py" --panels "$SOC_PANELS_FILE" \
       --template "$ROOT/labwc/rc.xml.tmpl" --out "$CFGDIR/rc.xml"; then
    log "WARNING could not generate labwc rc.xml — windows will not be tiled"
  fi
  printf '"%s" &\n' "$LAUNCHER" > "$CFGDIR/autostart"
  log "starting labwc"
  exec labwc
}

start_generic(){
  # best effort for a cage-like kiosk compositor: most accept "-- <cmd>"
  export SOC_LAYOUT="${SOC_LAYOUT:-single}"
  log "starting $1 (SOC_COMPOSITOR; generic single-window invocation)"
  exec "$1" -- "$LAUNCHER"
}

# 0) explicit override wins.
if [ -n "${SOC_COMPOSITOR:-}" ]; then
  if command -v "$SOC_COMPOSITOR" >/dev/null 2>&1; then
    case "$SOC_COMPOSITOR" in
      cage)  start_cage ;;
      labwc) start_labwc ;;
      *)     start_generic "$SOC_COMPOSITOR" ;;
    esac
  fi
  log "WARNING SOC_COMPOSITOR='$SOC_COMPOSITOR' not found on PATH — auto-selecting"
fi

# 1) cage: ideal for an all-webkit wall.
if [ "$all_webkit" = "1" ] && [ "$layout" != "windows" ] \
   && command -v cage >/dev/null 2>&1; then
  start_cage
fi

# 2) labwc: general case — generated window rules tile the panel windows.
if command -v labwc >/dev/null 2>&1; then
  start_labwc
fi

# 3) cage as a last resort, even for layout: windows, when the wall is all
#    webkit — better a tiled single window than no wall.
if [ "$all_webkit" = "1" ] && command -v cage >/dev/null 2>&1; then
  log "labwc not found; falling back to cage (single-window wall)"
  start_cage
fi

# No compositor started. In the `auto` chain, fall through to X11 (XLibre/Xorg)
# rather than leaving a black screen.
if [ "${SOC_ALLOW_X_FALLBACK:-0}" = "1" ]; then
  log "no Wayland compositor available — falling back to the X11 session"
  SOC_SESSION=xlibre SOC_ALLOW_X_FALLBACK=0 exec "$ROOT/scripts/start-session.sh"
fi

log "ERROR: no usable Wayland compositor."
log "  install labwc (any wall) or cage (all-webkit walls):"
log "    Debian/Ubuntu: apt install labwc   |  Fedora: dnf install labwc"
log "    Arch: pacman -S labwc              |  openSUSE: zypper install labwc"
log "    Alpine: apk add labwc              |  Void: xbps-install labwc"
log "  or set SOC_COMPOSITOR to a compositor you have installed,"
if [ "$all_webkit" != "1" ]; then
  log "  (cage alone cannot host Chromium panels — they need labwc window rules)"
fi
log "  or set SOC_SESSION=xorg in /etc/soc-display/soc.env to use the X11 session"
exit 1
