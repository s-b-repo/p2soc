#!/usr/bin/env bash
#
# Canonical "launch the SOC wall as a windowed app on the running desktop
# session" launcher.
#
# Why a script: the operator wants the wall on an existing Plasma / GNOME
# desktop (test box, demo, second-monitor wall on a developer workstation)
# rather than the production tty1-kiosk path that systemd would normally
# drive. Three integration points have bitten us:
#
#   1. XDG_RUNTIME_DIR.  Wayland + WebKitGTK both expect /run/user/<uid> to
#      exist with mode 0700 owned by the wall user. If the wall is launched
#      out-of-band (not via the soc-wall.service unit, which has the
#      ExecStartPre that creates it), the dir may be missing and the wall
#      dies with "Can't create a GtkStyleContext without a display".
#
#   2. XAUTHORITY.  When the wall user differs from the console user, the
#      X11 cookie must be discoverable. This launcher walks the common
#      locations and exports XAUTHORITY if found.
#
#   3. soc.env.  Older versions of /etc/soc-display/soc.env had unquoted
#      values containing spaces (SOC_CONFIG_VAULT_ITEM=SOC Wall Config)
#      that bash parsed as a prefixed-command. install.sh now writes the
#      file correctly, but this script also re-emits the broken lines into
#      a safe form before sourcing — defence in depth for hand-edited
#      installs.
#
# Run as the wall user (typically `soc`):
#     sudo -u soc /opt/soc-display/scripts/wall-windowed.sh
#
# Or via the per-user copy install.sh deploys to the wall user's home:
#     sudo -u soc /home/soc/wall-launcher.sh

set -u
# Don't `set -e` — we want graceful fallbacks on every probe.

# Self-locate: parent of this scripts/ dir (works from any checkout).
# SOC_ROOT overrides; /opt/soc-display is the deployed default.
SELF="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || echo "$0")"
CHECKOUT="$(cd "$(dirname "$SELF")/.." 2>/dev/null && pwd)"
if [ -d "$CHECKOUT/kiosk-host" ]; then
  SOC_ROOT="$CHECKOUT"
else
  SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
fi
[ -d "$SOC_ROOT/kiosk-host" ] || { echo "wall-windowed.sh: cannot find installation root (no kiosk-host/). Set SOC_ROOT=/path/to/repo" >&2; exit 1; }

SOC_ETC="${SOC_ETC:-/etc/soc-display}"
SOC_ENV_FILE="${SOC_ENV_FILE:-$SOC_ETC/soc.env}"

# --- 1. XDG_RUNTIME_DIR --------------------------------------------------- #
ensure_xdg_runtime_dir() {
    local uid
    uid="$(id -u)"
    local target="${XDG_RUNTIME_DIR:-/run/user/$uid}"
    if [ ! -d "$target" ]; then
        # Try mkdir as ourselves first — works if /run/user is permissive.
        if mkdir -p "$target" 2>/dev/null && chmod 0700 "$target" 2>/dev/null; then
            :
        elif command -v sudo >/dev/null 2>&1; then
            # /run/user usually needs root to write. The wall user may have
            # sudo NOPASSWD for `install`; if not, this fails and we warn.
            sudo -n /usr/bin/install -d -m 0700 \
                -o "$(id -un)" -g "$(id -gn)" "$target" 2>/dev/null \
                || echo >&2 "[wall-windowed] could not create $target — " \
                            "the wall may fail to start (Wayland/WebKit need it)"
        fi
    fi
    export XDG_RUNTIME_DIR="$target"
}

# --- 2. XAUTHORITY -------------------------------------------------------- #
discover_xauthority() {
    # If already set + readable, trust the operator.
    if [ -n "${XAUTHORITY:-}" ] && [ -r "$XAUTHORITY" ]; then
        return
    fi
    local home_xauth="$HOME/.Xauthority"
    if [ -r "$home_xauth" ]; then
        export XAUTHORITY="$home_xauth"
        return
    fi
    # XDG_RUNTIME_DIR variant (modern DMs put a per-session cookie here).
    local uid; uid="$(id -u)"
    local candidate
    for candidate in "/run/user/$uid"/xauth_* "/run/user/$uid"/.mutter-Xwaylandauth.*; do
        [ -r "$candidate" ] || continue
        export XAUTHORITY="$candidate"
        return
    done
    # Console-user fallback when we're impersonating with `sudo -u soc` from
    # a desktop user's shell. SUDO_USER is set by sudo; resolve their home +
    # XDG_RUNTIME_DIR. Cookie files are usually root-only or user-only; we
    # don't copy them — we only export the path so X reads them via the file
    # ACL the operator may have already arranged (e.g. via group membership).
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "$(id -un)" ]; then
        local sudo_home sudo_uid
        sudo_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        sudo_uid="$(id -u "$SUDO_USER" 2>/dev/null)"
        for candidate in "$sudo_home/.Xauthority" "/run/user/$sudo_uid"/xauth_*; do
            [ -r "$candidate" ] || continue
            export XAUTHORITY="$candidate"
            return
        done
    fi
    # No discovery possible — leave XAUTHORITY unset. If the desktop user
    # has run scripts/grant-soc-x-display.sh, xhost allows us through
    # without a cookie. Otherwise the wall will fail with a clear error.
    echo >&2 "[wall-windowed] no XAUTHORITY discovered; relying on xhost grant."
    echo >&2 "[wall-windowed] If the wall fails on X auth, run from the desktop user:"
    echo >&2 "[wall-windowed]     /opt/soc-display/scripts/grant-soc-x-display.sh"
}

# --- 3. soc.env source (safe even with unquoted spaces) ------------------- #
source_soc_env() {
    [ -r "$SOC_ENV_FILE" ] || {
        echo >&2 "[wall-windowed] $SOC_ENV_FILE not readable — proceeding without it"
        return
    }
    # Rewrite each KEY=VALUE so values with spaces become single-quoted, then
    # source the rewritten copy. Skips blank/comment lines. Idempotent on
    # an already-quoted line (regex skips lines that already start with ").
    local tmp
    tmp="$(mktemp 2>/dev/null || echo "/tmp/soc-env.$$")"
    # Use python for the rewrite — sidesteps awk single-quote escaping pain
    # AND handles the full range of operator hand-edit hazards: values with
    # spaces, embedded quotes, backslashes. Pure stdlib (no deps).
    python3 - "$SOC_ENV_FILE" >"$tmp" <<'PYEOF' || {
import re, shlex, sys
PAT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
src = open(sys.argv[1], encoding="utf-8", errors="replace").read()
for line in src.splitlines():
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    if not PAT.match(s):
        continue                         # malformed → drop, don't fail
    k, _, v = s.partition("=")
    # Strip a balanced pair of surrounding quotes the operator typed.
    if (len(v) >= 2) and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
    print(f"{k}={shlex.quote(v)}")
PYEOF
        echo >&2 "[wall-windowed] soc.env rewrite failed; sourcing raw."
        cp -f "$SOC_ENV_FILE" "$tmp"
    }
    set -a
    # shellcheck disable=SC1090
    . "$tmp"
    set +a
    rm -f "$tmp"
}

# --- 4. windowed wall env ------------------------------------------------- #
configure_wall_env() {
    export DISPLAY="${DISPLAY:-:0}"
    export WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-wayland-0}"
    export GDK_BACKEND="${GDK_BACKEND:-wayland,x11}"
    export PYTHONPATH="${PYTHONPATH:-$SOC_ROOT/kiosk-host}"
    export SOC_LAYOUT="${SOC_LAYOUT:-single}"
    export SOC_WINDOWED="${SOC_WINDOWED:-1}"
}

main() {
    ensure_xdg_runtime_dir
    source_soc_env
    discover_xauthority
    configure_wall_env
    cd "$SOC_ROOT/kiosk-host"
    # Respawn loop. When the operator hits ⚙ Settings → Actions → "Restart
    # wall", main.py calls sys.exit(0) — under systemd that triggers
    # Restart=always; standalone (this launcher) we re-run here. Exit code 2
    # means "really quit" (operator pressed Quit in the tray menu). Any
    # other non-zero exit waits 1 s before respawning so a crash-loop
    # doesn't peg the CPU.
    while :; do
        "$SOC_ROOT/.venv/bin/python" -m host.main
        rc=$?
        case $rc in
            0)
                echo >&2 "[wall-windowed] wall exited cleanly (rc=0) — respawning"
                ;;
            2)
                echo >&2 "[wall-windowed] operator quit (rc=2) — done"
                exit 0
                ;;
            *)
                echo >&2 "[wall-windowed] wall died unexpectedly (rc=$rc) — respawning in 1s"
                sleep 1
                ;;
        esac
    done
}

main "$@"
