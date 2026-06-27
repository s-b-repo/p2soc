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

# Resolve SOC_ENV_FILE via the SHARED resolver (host.configpaths) so this kiosk
# path agrees with the wizard + the in-session launcher. Running as the root kiosk
# user there is no per-user marker, so /etc wins here as before; the literal
# fallback (== read tier #3) keeps the pre-install/non-systemd path working.
RESOLVE_PY="$ROOT/.venv/bin/python"
[ -x "$RESOLVE_PY" ] || RESOLVE_PY="$(command -v python3 2>/dev/null || true)"
if [ -n "$RESOLVE_PY" ]; then
  : "${SOC_ENV_FILE:=$(PYTHONPATH="$ROOT/kiosk-host${PYTHONPATH:+:$PYTHONPATH}" \
        "$RESOLVE_PY" -m host.configpaths --env 2>/dev/null || true)}"
fi
: "${SOC_ENV_FILE:=/etc/soc-display/soc.env}"
ENV_FILE="$SOC_ENV_FILE"
if [ -r "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
elif [ -e "$ENV_FILE" ]; then
  # exists but unreadable -> vault config never loads (and -f + source would abort
  # the session under set -e). soc.env is non-secret; surface it loudly.
  echo "[start-session] WARNING: $ENV_FILE exists but is not readable by $(id -un 2>/dev/null) —" >&2
  echo "[start-session]   vault config not loaded. Fix: sudo chmod 0644 $ENV_FILE" >&2
fi

log() { echo "[start-session] $*" >&2; }

# Bounded in-script supervisor for a display stack. `exec` only returns when the
# binary is missing; once startx/cage/labwc actually runs and then EXITS (X server
# crashed on boot, GPU/seat briefly not ready, transient device-busy), an exec'd
# process is gone and the shell is replaced — so start-session never retries and
# the auto fallback chain (which only fires on START refusal) never fires. Instead
# we RUN the stack and watch it:
#   * if a run lasts >= SOC_STEADY_SECS it's steady-state -> exec it for a clean
#     process tree (the happy path: one long-running server, no extra shell);
#   * if it dies faster, that's a fast-flap -> count it, sleep capped-exponential
#     backoff (2->4->8->max 30s), and retry up to SOC_MAX_FASTFAIL times;
#   * on exhausting the cap, RETURN non-zero so the caller falls through to the
#     next stage (auto chain) or exits 1 (explicit single-stage mode).
# Never an unbounded loop, never a swallow: every attempt is logged to the journal
# and exhaustion surfaces as a non-zero return.
SOC_STEADY_SECS="${SOC_STEADY_SECS:-20}"
SOC_MAX_FASTFAIL="${SOC_MAX_FASTFAIL:-3}"
supervise() {                           # $1 = label; $2.. = command + args
  label="$1"; shift
  fails=0; backoff=2
  while :; do
    log "starting $label (attempt $((fails + 1))/$SOC_MAX_FASTFAIL): $*"
    started="$(date +%s 2>/dev/null || echo 0)"
    "$@"; rc=$?
    ended="$(date +%s 2>/dev/null || echo 0)"
    ran=$((ended - started)); [ "$ran" -lt 0 ] && ran=0
    if [ "$ran" -ge "$SOC_STEADY_SECS" ]; then
      # ran long enough to be the real session — hand off cleanly via exec so the
      # steady-state run has no leftover supervisor shell in its process tree.
      log "$label ran ${ran}s (>= ${SOC_STEADY_SECS}s) then exited rc=$rc — re-exec for steady-state"
      exec "$@"
      log "FATAL: exec of $label failed"; return 127   # only if exec itself failed
    fi
    fails=$((fails + 1))
    if [ "$fails" -ge "$SOC_MAX_FASTFAIL" ]; then
      log "$label fast-failed ${fails}x (last rc=$rc, ran ${ran}s) — giving up on this stage"
      return "${rc:-1}"
    fi
    log "$label exited rc=$rc after only ${ran}s — retrying in ${backoff}s (fast-flap $fails/$SOC_MAX_FASTFAIL)"
    sleep "$backoff"
    backoff=$((backoff * 2)); [ "$backoff" -gt 30 ] && backoff=30
  done
}

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
  export SOC_WAYLAND_BACKEND="$1"
  # supervised: a steady-state compositor exec-replaces this shell; a fast-flap is
  # retried with backoff, then we return non-zero so the caller can fall through.
  supervise "Wayland session (GTK backend: $1)" "$ROOT/scripts/wayland-session.sh"
  return $?
}

start_x() {                             # $1 = xlibre|xorg
  command -v startx >/dev/null 2>&1 || { log "startx not found — X11 unavailable"; return 1; }
  xs="$(pick_xserver "$1")" || { log "no $1 X server found"; return 1; }
  xbin="$(command -v "${xs%% *}")"
  supervise "X11 session (server: $xs)" startx -- "$xbin" :0 -nocursor
  return $?
}

case "${SOC_SESSION:-auto}" in
  wayland)  start_wayland wayland; log "FATAL: Wayland requested but no compositor"; exit 1 ;;
  xwayland) start_wayland x11;     log "FATAL: XWayland requested but no compositor"; exit 1 ;;
  xlibre)   start_x xlibre || start_x xorg; log "FATAL: no X server"; exit 1 ;;
  xorg)     start_x xorg; log "FATAL: no X.Org server"; exit 1 ;;
  x11)      start_x xlibre || start_x xorg; log "FATAL: no X server"; exit 1 ;;
  auto)
    # Wayland -> (XWayland at runtime, or X11 if no compositor starts) -> XLibre -> Xorg
    # Supervise the Wayland stack (RUN, not exec) so a compositor that starts then
    # fast-flaps doesn't strand us in a dead exec — on flap-exhaustion supervise()
    # returns non-zero and we fall through to the X11 stages, exactly as the
    # START-refusal chain already does. (wayland-session.sh's own
    # SOC_ALLOW_X_FALLBACK=1 path still handles the no-compositor-at-all case.)
    if have_compositor; then
      supervise "Wayland session (auto)" \
        env SOC_WAYLAND_BACKEND=auto SOC_ALLOW_X_FALLBACK=1 \
            "$ROOT/scripts/wayland-session.sh"
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
