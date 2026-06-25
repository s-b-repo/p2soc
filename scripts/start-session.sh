#!/bin/sh
# tty1 session dispatcher for the SOC wall — exec'd from the kiosk user's
# ~/.bash_profile after autologin. Picks the display stack per SOC_SESSION
# (set in /etc/soc-display/soc.env), the launch option:
#
#   auto      (default) try in order: Wayland -> XWayland -> XLibre -> Xorg
#   wayland   native Wayland (cage/labwc, GTK Wayland backend)
#   xwayland  Wayland compositor, GTK via XWayland (GDK_BACKEND=x11)
#   xlibre    X11 with the XLibre server (falls back to any X server)
#   xorg      X11 with the X.Org server
#   x11       (legacy alias) X11 with whatever X server is present
#
# In `auto`, native Wayland falls back to XWayland at runtime inside the
# launcher; if no compositor starts at all it falls back to X11. Other values
# are honoured exactly (no silent fallback). Overrides: SOC_COMPOSITOR (which
# Wayland compositor), SOC_XSERVER (explicit X server binary/command).

ROOT="${SOC_ROOT:-/opt/soc-display}"
ENV_FILE="${SOC_ENV_FILE:-/etc/soc-display/soc.env}"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

log() { echo "[start-session] $*" >&2; }

have_compositor() {
  if [ -n "${SOC_COMPOSITOR:-}" ] && command -v "$SOC_COMPOSITOR" >/dev/null 2>&1; then
    return 0
  fi
  command -v labwc >/dev/null 2>&1 || command -v cage >/dev/null 2>&1
}

# Echo an X server binary. For "xlibre" only succeed when XLibre is actually
# present (a dedicated binary, or an Xorg that reports itself as XLibre), so the
# auto chain can fall through to plain Xorg.
pick_xserver() {
  if [ -n "${SOC_XSERVER:-}" ] && command -v "${SOC_XSERVER%% *}" >/dev/null 2>&1; then
    echo "$SOC_XSERVER"; return 0
  fi
  if [ "$1" = xlibre ]; then
    for b in Xlibre xlibre; do
      command -v "$b" >/dev/null 2>&1 && { echo "$b"; return 0; }
    done
    if command -v Xorg >/dev/null 2>&1 && Xorg -version 2>&1 | grep -qi xlibre; then
      echo Xorg; return 0
    fi
    return 1
  fi
  for b in Xorg X; do
    command -v "$b" >/dev/null 2>&1 && { echo "$b"; return 0; }
  done
  return 1
}

start_wayland() {                       # $1 = auto|wayland|x11  (GTK backend)
  have_compositor || { log "no Wayland compositor (cage/labwc) installed"; return 1; }
  log "starting Wayland session (GTK backend: $1)"
  export SOC_WAYLAND_BACKEND="$1"
  exec "$ROOT/scripts/wayland-session.sh"
  return 1                              # only if exec failed
}

start_x() {                             # $1 = xlibre|xorg
  command -v startx >/dev/null 2>&1 || { log "startx not found — X11 unavailable"; return 1; }
  xs="$(pick_xserver "$1")" || { log "no $1 X server found"; return 1; }
  xbin="$(command -v "${xs%% *}")"
  log "starting X11 session (server: $xs)"
  exec startx -- "$xbin" :0 -nocursor
  return 1
}

case "${SOC_SESSION:-auto}" in
  wayland)  start_wayland wayland; log "FATAL: Wayland requested but no compositor"; exit 1 ;;
  xwayland) start_wayland x11;     log "FATAL: XWayland requested but no compositor"; exit 1 ;;
  xlibre)   start_x xlibre || start_x xorg; log "FATAL: no X server"; exit 1 ;;
  xorg)     start_x xorg; log "FATAL: no X.Org server"; exit 1 ;;
  x11)      start_x xlibre || start_x xorg; log "FATAL: no X server"; exit 1 ;;
  auto)
    # Wayland -> (XWayland at runtime, or X11 if no compositor starts) -> XLibre -> Xorg
    if have_compositor; then
      SOC_WAYLAND_BACKEND=auto SOC_ALLOW_X_FALLBACK=1 \
        exec "$ROOT/scripts/wayland-session.sh"
    fi
    start_x xlibre
    start_x xorg
    log "ERROR: no usable display stack — no Wayland compositor and no X server."
    log "Install one (labwc/cage, or xorg/xlibre + xinit), or set SOC_SESSION"
    log "explicitly (wayland|xwayland|xlibre|xorg) in $ENV_FILE."
    exit 1 ;;
  *)
    log "WARNING unknown SOC_SESSION='${SOC_SESSION}' (want auto|wayland|xwayland|"
    log "xlibre|xorg|x11); using auto"
    SOC_SESSION=auto exec "$0" ;;
esac
