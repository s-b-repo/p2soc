#!/usr/bin/env bash
#
# Grant a different local user permission to open windows on your X display.
#
# Use case: you're logged into Plasma / GNOME as your normal user (`kali`,
# `pi`, whatever), but the SOC wall runs as the dedicated service user
# (`soc` by default). When `sudo -u soc /home/soc/wall-launcher.sh` runs,
# the X server refuses with "Authorization required" because soc isn't the
# session owner. This script flips xhost to let soc through. Idempotent;
# survives until the X session ends (so re-run after each login). Pass
# --autostart to also add an XDG autostart entry so the grant re-applies
# at every desktop login.
#
# Usage:
#     ./grant-soc-x-display.sh                # grant for user "soc"
#     ./grant-soc-x-display.sh --user pi      # grant for a different user
#     ./grant-soc-x-display.sh --autostart    # also write ~/.config/autostart/
#     ./grant-soc-x-display.sh --revoke       # undo the grant for this session
#
# Run from the DESKTOP user's shell (NOT as root). xhost is a per-X-session
# operation; running it as root would target root's display (if any).

set -eu

USER_TO_GRANT="soc"
DO_AUTOSTART=0
DO_REVOKE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            shift; USER_TO_GRANT="${1:-soc}" ;;
        --autostart)
            DO_AUTOSTART=1 ;;
        --revoke)
            DO_REVOKE=1 ;;
        -h|--help)
            sed -n '2,/^set -eu/p' "$0" | sed 's/^# \{0,1\}//; /^set/d'
            exit 0 ;;
        *)
            echo >&2 "unknown arg: $1 (use --help)"; exit 2 ;;
    esac
    shift
done

if [ "$(id -u)" = "0" ]; then
    echo >&2 "ERROR: run this as your desktop user, not root."
    echo >&2 "(xhost is per-X-session; root has its own display state.)"
    exit 1
fi

if ! command -v xhost >/dev/null 2>&1; then
    echo >&2 "ERROR: xhost not found. On Debian/Kali: sudo apt install x11-xserver-utils"
    exit 1
fi

if [ -z "${DISPLAY:-}" ]; then
    echo >&2 "ERROR: no DISPLAY set — are you in an X (or XWayland) session?"
    exit 1
fi

# Sanity-check the target user exists (so we don't paper over a typo).
if ! id -u "$USER_TO_GRANT" >/dev/null 2>&1; then
    echo >&2 "ERROR: user '$USER_TO_GRANT' does not exist on this system."
    exit 1
fi

ACL="SI:localuser:$USER_TO_GRANT"

if [ "$DO_REVOKE" = "1" ]; then
    xhost "-$ACL" >/dev/null
    echo "revoked $ACL"
    exit 0
fi

xhost "+$ACL" >/dev/null
echo "granted X access to local user '$USER_TO_GRANT' on $DISPLAY"

if [ "$DO_AUTOSTART" = "1" ]; then
    AUTOSTART_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"
    install -d -m 0700 "$AUTOSTART_DIR"
    entry="$AUTOSTART_DIR/grant-soc-x-display.desktop"
    cat > "$entry" <<EOF
[Desktop Entry]
Type=Application
Name=Grant X display access to ${USER_TO_GRANT}
Comment=Let the SOC wall (run as ${USER_TO_GRANT}) open windows on this session.
Exec=$(command -v xhost) +$ACL
Terminal=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
EOF
    chmod 0600 "$entry"
    echo "autostart written: $entry"
    echo "  (the grant will re-apply at every desktop login)"
fi
