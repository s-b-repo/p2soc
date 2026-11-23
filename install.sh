#!/usr/bin/env bash
# =============================================================================
# SOC video-wall kiosk installer
#
# Supported distros (package install is automatic):
#   * Debian / Raspberry Pi OS / Ubuntu / Kali   (apt)
#   * Fedora / RHEL / Rocky / Alma               (dnf)
#   * Arch / Manjaro / EndeavourOS               (pacman)
#   * openSUSE Leap / Tumbleweed                 (zypper)
#   * Alpine                                     (apk)
#   * Void                                       (xbps)
# Any other distro: run with SOC_SKIP_PACKAGES=1 after installing the deps from
# docs/INSTALL.md by hand — everything else (deploy, venv, config, services) is
# distro-agnostic.
#
# systemd is preferred (autologin + service supervision). On a non-systemd
# init (OpenRC/runit/...) the installer still deploys everything and prints the
# autostart + supervision snippets you need to wire up by hand.
#
# X11 sessions work with X.Org OR XLibre (the installer accepts whichever X
# server is present, and falls back to xlibre-* package names where needed).
#
# Idempotent: safe to re-run. Run as root:  sudo ./install.sh
#
# Knobs (env):
#   SESSION=auto|wayland|xwayland|xlibre|xorg|x11   stack to install + use
#                             (default: auto). auto = install both stacks and at
#                             runtime try Wayland -> XWayland -> XLibre -> Xorg.
#                             wayland/xwayland install the Wayland compositor;
#                             xlibre/xorg/x11 install the X11 server + openbox.
#   INSTALL_MODE=auto|desktop|kiosk how the wall starts        (default: auto)
#                             auto    = kiosk on a box with no desktop environment,
#                             desktop where a display manager is in use.
#                             desktop = deploy everything but DON'T touch the boot
#                             (your DE/login manager keeps working; launch the wall
#                             from the desktop icon or `systemctl start soc-wall`).
#                             kiosk   = dedicated appliance: enable tty1 autologin +
#                             `systemctl set-default multi-user.target`.
#   VW_MODE=native|docker     how to run Vaultwarden           (default: native)
#                             native = hardened unit, binary fetched without Docker
#                             (saves dockerd + containerd on a 1 GB board). docker
#                             uses your distro's package, never a remote script.
#   SSH_ADMIN_CIDR=<cidr>      admin subnet baked into nftables (HARDEN=1; fail-closed)
#   HARDEN=1                  apply nftables + sshd hardening  (default: off)
#                             also: kernel-hardening sysctls, a USB/DMA modprobe
#                             blacklist, and nodev,nosuid,noexec on /tmp.
#   SOC_SKIP_MODPROBE=1       under HARDEN=1, do NOT blacklist usb_storage/
#                             firewire_core/cdc_acm modules (default: apply)
#   SOC_SKIP_FSTAB=1          under HARDEN=1, do NOT harden /tmp mount options
#                             (nodev,nosuid,noexec)                (default: apply)
#   KIOSK_USER=soc            kiosk login user (tty1 autologin) (default: soc)
#   DESKTOP_USER=socwall      desktop-mode wall user (DE session)(default: socwall)
#   SVC_USER=socsvc           service user (autossh)           (default: socsvc)
#   COMPOSITOR=labwc          Wayland compositor to install    (default: labwc)
#                             (e.g. sway/cage — runtime override is SOC_COMPOSITOR)
#   SOC_SKIP_PACKAGES=1       do not install any OS packages (deps already present)
#   --fresh | SOC_FRESH=1     reinstall OS packages even if already installed
#                             (a successful install stamps $ETC/.installed; re-runs
#                             and `setup.py deploy` skip the slow package step)
#   SOC_ROOT=/opt/soc-display  the live tree: a symlink into SOC_RELEASES
#   SOC_RELEASES=/opt/soc-releases  one directory per deployed release
#
# Earlier choices stick: a re-run reuses the values recorded in the install
# manifest unless you set them again.
#
# Internal modes, used by scripts/soc-update.py (the unattended redeployer):
#   --activate            integrate the release the live link points at: units,
#                         sudoers, sysctl, session files. Never moves the boot,
#                         never touches packages, and never overwrites anything
#                         an operator owns (firewall, sshd, /etc/soc-display).
#   --deps-if-changed     install OS packages only if DEPS_REV changed, then exit.
#                         Runs BEFORE the swap, so a failure just means retry.
# =============================================================================
set -euo pipefail

# Bump whenever the package lists below change. A redeploy only runs the package
# manager when this differs from what the box last installed, so an ordinary update
# never touches apt.
DEPS_REV=3

SESSION_WAS_SET="${SESSION+yes}"
# Note which knobs were set for this run: the rest keep their recorded value.
for _k in SESSION VW_MODE HARDEN KIOSK_USER DESKTOP_USER SVC_USER INSTALL_MODE \
          SOC_TARPIT_ENABLE SOC_KEEP_SERVICES SOC_SKIP_PACKAGES; do
  printf -v "_SET_$_k" '%s' "${!_k+yes}"
done
SESSION="${SESSION:-auto}"
VW_MODE="${VW_MODE:-native}"
HARDEN="${HARDEN:-0}"
SSH_ADMIN_CIDR="${SSH_ADMIN_CIDR:-}"
KIOSK_USER="${KIOSK_USER:-soc}"
DESKTOP_USER="${DESKTOP_USER:-socwall}"
SVC_USER="${SVC_USER:-socsvc}"
# Runs git for the redeployer. Separate from SVC_USER on purpose: git parses data
# from the network, and SVC_USER holds the tunnel key.
UPDATE_USER="${UPDATE_USER:-socupdate}"
COMPOSITOR="${COMPOSITOR:-labwc}"
# auto (default): kiosk on a box with no desktop environment, desktop where a
# display manager is in use, so an operator's workstation is never hijacked.
# desktop: deploy everything but DON'T hijack the boot. kiosk: the tty1 takeover
# (autologin + multi-user default target) for a dedicated SOC-wall appliance.
INSTALL_MODE="${INSTALL_MODE:-auto}"
# scanner-deception tarpit on :80 — installed always, ENABLED only when opted in.
SOC_TARPIT_ENABLE="${SOC_TARPIT_ENABLE:-0}"
# HARDEN sub-knobs: per-item opt-OUT for the physical-attack-surface hardening so
# an operator can keep nftables/sshd hardening but skip module-blacklist / fstab.
SOC_SKIP_MODPROBE="${SOC_SKIP_MODPROBE:-0}"
SOC_SKIP_FSTAB="${SOC_SKIP_FSTAB:-0}"
SOC_KEEP_SERVICES="${SOC_KEEP_SERVICES:-0}"
SOC_SKIP_PACKAGES="${SOC_SKIP_PACKAGES:-0}"
DEPS_ONLY=0
DEPS_IF_CHANGED=0
ACTIVATE=0
USERS_ONLY=0
FRESH="${SOC_FRESH:-0}"
for _a in "$@"; do
  [ "$_a" = "--deps-only" ] && DEPS_ONLY=1
  [ "$_a" = "--deps-if-changed" ] && { DEPS_ONLY=1; DEPS_IF_CHANGED=1; }
  [ "$_a" = "--activate" ] && ACTIVATE=1
  [ "$_a" = "--fresh" ] && FRESH=1
  [ "$_a" = "--users-only" ] && USERS_ONLY=1
done
SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
RELEASES="${SOC_RELEASES:-/opt/soc-releases}"
ETC="${SOC_ETC:-/etc/soc-display}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd -P)"
# The desktop tools export their checkout as SOC_ROOT for resource lookup.
# A source checkout is an input to deployment, never the live release tree.
if [ "$ACTIVATE" != 1 ] && [ "$SOC_ROOT" = "$SRC_DIR" ] && [ -e "$SRC_DIR/.git" ]; then
  SOC_ROOT=/opt/soc-display
fi
. "$SRC_DIR/scripts/soc-native.sh"
NATIVE_SOURCE="$(soc_native_path "$SRC_DIR" || true)"
NATIVE_BUILD=0
if [ -z "$NATIVE_SOURCE" ] && [ -f "$SRC_DIR/rust/Cargo.toml" ] && [ "${SOC_LEGACY_PYTHON:-0}" != 1 ]; then
  NATIVE_BUILD=1
fi
ARCH="$(uname -m)"

# `sudo ./install.sh` from a clone owned by a normal user is the usual case, and git
# refuses to read another user's repository as root unless told it is expected.
src_git(){ git -c safe.directory="$SRC_DIR" -C "$SRC_DIR" "$@"; }

log(){ printf '\033[36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m!!\033[0m %s\n' "$*"; }
die(){ printf '\033[31mEE\033[0m %s\n' "$*" >&2; exit 1; }

# docker pull with bounded retry/backoff — a transient registry/network failure
# (common on a Pi bringing up Wi-Fi during first boot) shouldn't throw away a long
# install on the first flake. Up to 3 attempts, bounded sleep; returns non-zero on
# exhaustion so the caller can `die` with actionable text. Re-running is idempotent.
docker_pull_retry(){ # $1=image
  local img="$1" n=0
  until docker pull "$img"; do
    n=$((n+1)); [ "$n" -ge 3 ] && return 1
    warn "docker pull $img failed (attempt $n/3) — retrying in $((n*3))s (network/registry)"
    sleep "$((n*3))"
  done
}

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"

create_users() {
  log "Creating users ($KIOSK_USER kiosk, $DESKTOP_USER desktop, $SVC_USER service)"
  if ! id "$KIOSK_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$KIOSK_USER"
  fi
  for grp in video render input tty audio seat; do
    getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$KIOSK_USER" || true
  done
  if ! id "$DESKTOP_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$DESKTOP_USER"
  fi
  for grp in video render input audio; do
    getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$DESKTOP_USER" || true
  done
  if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd -r -m -s "$(command -v nologin || echo /usr/sbin/nologin)" "$SVC_USER"
  fi
  if ! id "$UPDATE_USER" >/dev/null 2>&1; then
    useradd -r -M -d /nonexistent -s "$(command -v nologin || echo /usr/sbin/nologin)" "$UPDATE_USER"
  fi
}
if [ "$USERS_ONLY" = "1" ]; then
  create_users
  exit 0
fi

# Rows from the previous run's manifest (empty on a first install).
manifest_row(){ # $1=TYPE $2=key
  [ -f "$ETC/.install-manifest" ] || return 0
  awk -F'|' -v t="$1" -v k="$2" '$1==t && $2==k {print $3; exit}' "$ETC/.install-manifest"
}
keep_choice(){ # $1=variable $2=manifest key
  local was_set="_SET_$1" recorded
  [ -n "${!was_set:-}" ] && return 0
  recorded="$(manifest_row META "$2")"
  [ -n "$recorded" ] && printf -v "$1" '%s' "$recorded"
  return 0
}
keep_choice SESSION session
keep_choice VW_MODE vw_mode
keep_choice HARDEN harden
keep_choice KIOSK_USER kiosk_user
keep_choice DESKTOP_USER desktop_user
keep_choice SVC_USER svc_user
keep_choice INSTALL_MODE install_mode
keep_choice SOC_TARPIT_ENABLE tarpit
keep_choice SOC_KEEP_SERVICES keep_services
keep_choice SOC_SKIP_PACKAGES skip_packages
SKIP_PACKAGES="$SOC_SKIP_PACKAGES"

# One deployment at a time. The redeployer holds this lock for a whole run, and its
# own --activate and --deps-if-changed calls run inside that. Without it, a manual
# run could swap the release during a health check, or have its stage collected.
if [ "$ACTIVATE" != "1" ] && [ "$DEPS_IF_CHANGED" != "1" ] && command -v flock >/dev/null 2>&1; then
  mkdir -p /var/lib/soc-update
  exec 9>/var/lib/soc-update/lock
  flock -w 1800 9 || die "a redeploy has held the lock for 30 minutes; try again later"
fi

# Anything touching a user's home runs AS that user. Run as root, a symlink planted
# there would be followed by root: the kiosk user runs the browsers, so a compromised
# renderer could then take over the box on the next unattended redeploy.
as_user(){ # $1=user $2..=command
  local user="$1"
  shift
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- "$@"
  else
    su -s /bin/bash "$user" -c "$(printf '%q ' "$@")"
  fi
}

case "$VW_MODE" in native|docker) ;; *)
  die "VW_MODE must be native|docker (got '$VW_MODE')";; esac
case "$SESSION" in auto|wayland|xwayland|xlibre|xorg|x11) ;; *)
  die "SESSION must be auto|wayland|xwayland|xlibre|xorg|x11 (got '$SESSION')";; esac
case "$INSTALL_MODE" in auto|desktop|kiosk) ;; *)
  die "INSTALL_MODE must be auto|desktop|kiosk (got '$INSTALL_MODE')";; esac

# systemd is preferred but not required — degrade gracefully without it.
HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  HAS_SYSTEMD=1
else
  warn "no running systemd detected — will deploy files + scripts but NOT install"
  warn "services or tty autologin. See the end-of-run notes for the manual steps."
fi

# Resolve auto now that we know the init system.
if [ "$INSTALL_MODE" = "auto" ]; then
  INSTALL_MODE=desktop
  if [ "$HAS_SYSTEMD" = "1" ] && ! systemctl is-enabled display-manager.service >/dev/null 2>&1 \
     && [ "$(systemctl get-default 2>/dev/null)" != "graphical.target" ]; then
    INSTALL_MODE=kiosk
  fi
  log "INSTALL_MODE=auto resolved to $INSTALL_MODE"
fi

# Architecture note (ARM boards are the primary target; x86 works too).
case "$ARCH" in
  aarch64|arm64)  log "CPU architecture: $ARCH (64-bit ARM — e.g. Raspberry Pi 5)" ;;
  armv7l|armv6l)  warn "CPU architecture: $ARCH (32-bit ARM). WebKitGTK is heavy here;"
                  warn "  a 64-bit OS is strongly recommended for the SOC wall." ;;
  x86_64|amd64)   log "CPU architecture: $ARCH (x86-64)" ;;
  *)              warn "CPU architecture: $ARCH (untested — proceeding anyway)" ;;
esac

# --------------------------------------------------------------------------- #
# Distro detection + package-manager abstraction
# --------------------------------------------------------------------------- #
FAMILY=""
. /etc/os-release 2>/dev/null || true
_ids="${ID:-} ${ID_LIKE:-}"
case " $_ids " in
  *" debian "*|*" ubuntu "*|*" raspbian "*|*" kali "*) FAMILY=debian ;;
  *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*) FAMILY=fedora ;;
  *" arch "*|*" manjaro "*|*" endeavouros "*) FAMILY=arch ;;
  *" suse "*|*" opensuse "*|*" opensuse-leap "*|*" opensuse-tumbleweed "*) FAMILY=suse ;;
  *" alpine "*) FAMILY=alpine ;;
  *" void "*) FAMILY=void ;;
esac
# Last-resort detection by package manager when os-release is unhelpful.
if [ -z "$FAMILY" ]; then
  if command -v apt-get >/dev/null 2>&1;   then FAMILY=debian
  elif command -v dnf >/dev/null 2>&1;     then FAMILY=fedora
  elif command -v pacman >/dev/null 2>&1;  then FAMILY=arch
  elif command -v zypper >/dev/null 2>&1;  then FAMILY=suse
  elif command -v apk >/dev/null 2>&1;     then FAMILY=alpine
  elif command -v xbps-install >/dev/null 2>&1; then FAMILY=void
  fi
fi
if [ -z "$FAMILY" ] && [ "$SKIP_PACKAGES" != "1" ]; then
  die "unsupported distro: ID='${ID:-?}' ID_LIKE='${ID_LIKE:-?}'.
   Auto-install supports apt/dnf/pacman/zypper/apk/xbps. Install the deps from
   docs/INSTALL.md by hand, then re-run with SOC_SKIP_PACKAGES=1."
fi
log "Distro: ${PRETTY_NAME:-${FAMILY:-unknown}} (family: ${FAMILY:-none}, packages: $([ "$SKIP_PACKAGES" = 1 ] && echo skip || echo auto))"

pm_refresh(){
  [ "$SKIP_PACKAGES" = "1" ] && return 0
  case "$FAMILY" in
    debian) export DEBIAN_FRONTEND=noninteractive; apt-get update -qq ;;
    fedora) : ;;                              # dnf resolves metadata on install
    arch)   pacman -Sy --noconfirm >/dev/null ;;
    suse)   zypper -n refresh >/dev/null ;;
    alpine) apk update >/dev/null ;;
    void)   xbps-install -S >/dev/null ;;
  esac
}

pm_install_cmd(){   # one transaction; returns non-zero on any failure
  case "$FAMILY" in
    debian) apt-get install -y -qq "$@" ;;
    fedora) dnf install -y -q "$@" ;;
    arch)   pacman -S --noconfirm --needed "$@" ;;
    suse)   zypper -n install --no-recommends "$@" ;;
    alpine) apk add "$@" ;;
    void)   xbps-install -y "$@" ;;
  esac
}

pkg_exists(){       # is a package name known to the active package manager?
  case "$FAMILY" in
    debian) apt-cache show "$1" >/dev/null 2>&1 ;;
    fedora) dnf info "$1" >/dev/null 2>&1 ;;
    arch)   pacman -Si "$1" >/dev/null 2>&1 ;;
    suse)   zypper -n info "$1" >/dev/null 2>&1 ;;
    alpine) apk info -e "$1" >/dev/null 2>&1 || apk search -x "$1" 2>/dev/null | grep -q . ;;
    void)   xbps-query -Rp pkgver "$1" >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

pm_install(){       # required packages: try the set, then bisect to name culprits
  [ "$SKIP_PACKAGES" = "1" ] && return 0
  pm_install_cmd "$@" >/dev/null 2>&1 && return 0
  local failed=()
  for p in "$@"; do
    pm_install_cmd "$p" >/dev/null 2>&1 || failed+=("$p")
  done
  [ "${#failed[@]}" -eq 0 ] && return 0
  die "could not install required package(s): ${failed[*]}
   Check the package names for your distro and install them manually,
   then re-run ./install.sh (or with SOC_SKIP_PACKAGES=1 once they are present)."
}

pm_try(){           # optional packages: best effort, one by one, warn only
  [ "$SKIP_PACKAGES" = "1" ] && return 0
  for p in "$@"; do
    pm_install_cmd "$p" >/dev/null 2>&1 || warn "optional package '$p' not installed (skipping)"
  done
}

# --------------------------------------------------------------------------- #
# Package sets per family
# --------------------------------------------------------------------------- #
# Per family:
#   PK_CORE       python/GTK/WebKit + autossh/openfortivpn (required)
#   PK_XSRV       the X server package (skipped if an X server is already present,
#                 which is also how an existing XLibre install is honoured)
#   PK_XSRV_ALT   XLibre server package name(s) to try if PK_XSRV is unavailable
#   PK_X11        the rest of the X session (xinit + openbox), server excluded
#   PK_WAYLAND    Wayland compositor(s); $COMPOSITOR is appended below
#   PK_TOOLS      optional niceties (cursor hider, fonts, pinentry)
#   PK_ZRAM       zram swap generator (optional)
#   PK_SECRETTOOL libsecret `secret-tool` (optional; only the secret-service
#                 master source needs it — KWallet / GNOME-keyring / KeePassXC)
PK_XSRV_ALT=()
case "$FAMILY" in
  debian)
    PK_CORE=(python3 python3-venv python3-gi gir1.2-gtk-3.0
             curl ca-certificates git sudo autossh openfortivpn ppp)
    PK_XSRV=(xserver-xorg xserver-xorg-legacy)
    PK_X11=(xinit x11-xserver-utils openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(unclutter fonts-dejavu-core pinentry-tty)
    PK_ZRAM=(systemd-zram-generator)
    PK_SECRETTOOL=(libsecret-tools)
    # WebKit2 typelib: prefer 4.1 (Bookworm+), fall back to 4.0
    if pkg_exists gir1.2-webkit2-4.1; then
      PK_CORE+=(gir1.2-webkit2-4.1)
    else
      PK_CORE+=(gir1.2-webkit2-4.0)
    fi
    ;;
  fedora)
    PK_CORE=(python3 python3-gobject gtk3 webkit2gtk4.1
             curl ca-certificates git sudo autossh openfortivpn ppp)
    PK_XSRV=(xorg-x11-server-Xorg)
    PK_X11=(xorg-x11-xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xorg-x11-server-utils xsetroot unclutter
              dejavu-sans-fonts pinentry)
    PK_ZRAM=(zram-generator zram-generator-defaults)
    PK_SECRETTOOL=(libsecret)
    ;;
  arch)
    PK_CORE=(python python-gobject gtk3 webkit2gtk-4.1
             curl ca-certificates git sudo autossh openfortivpn ppp)
    PK_XSRV=(xorg-server)
    PK_XSRV_ALT=(xlibre-xserver)   # AUR / Artix; honoured if already installed
    PK_X11=(xorg-xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xorg-xset xorg-xsetroot xorg-xrandr unclutter
              ttf-dejavu pinentry)
    PK_ZRAM=(zram-generator)
    PK_SECRETTOOL=(libsecret)
    ;;
  suse)
    PK_CORE=(python3 python3-gobject typelib-1_0-Gtk-3_0 typelib-1_0-WebKit2-4_1
             curl ca-certificates git sudo autossh openfortivpn ppp)
    PK_XSRV=(xorg-x11-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(unclutter dejavu-fonts pinentry)
    PK_ZRAM=()
    PK_SECRETTOOL=(libsecret-tools)
    ;;
  alpine)
    PK_CORE=(python3 py3-gobject3 gtk+3.0 webkit2gtk-4.1
             curl ca-certificates git sudo autossh openfortivpn ppp)
    PK_XSRV=(xorg-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xrandr xset font-dejavu pinentry)
    PK_ZRAM=()
    PK_SECRETTOOL=(libsecret)
    ;;
  void)
    PK_CORE=(python3 python3-gobject gtk+3 webkit2gtk
             curl ca-certificates git sudo autossh openfortivpn ppp)
    PK_XSRV=(xorg-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xrandr xset dejavu-fonts-ttf pinentry)
    PK_ZRAM=()
    PK_SECRETTOOL=(libsecret)
    ;;
  *)   # SOC_SKIP_PACKAGES=1 with an unknown distro — arrays just stay empty
    PK_CORE=(); PK_XSRV=(); PK_X11=(); PK_WAYLAND=(); PK_TOOLS=(); PK_ZRAM=()
    PK_SECRETTOOL=()
    ;;
esac
if [ -n "$NATIVE_SOURCE" ] || [ "$NATIVE_BUILD" = 1 ]; then
  NATIVE_PK_CORE=()
  for package in "${PK_CORE[@]}"; do
    case "$package" in
      python|python3|python3-venv|python3-gi|python-gobject|python3-gobject|py3-gobject3|gir1.2-gtk-3.0|gir1.2-webkit2-4.?) ;;
      *) NATIVE_PK_CORE+=("$package") ;;
    esac
  done
  PK_CORE=("${NATIVE_PK_CORE[@]}")
  [ "$FAMILY" != debian ] || PK_CORE+=(libgtk-3-0 libwebkit2gtk-4.1-0)
fi
if [ "$NATIVE_BUILD" = 1 ]; then
  case "$FAMILY" in
    debian) PK_CORE+=(build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev) ;;
    fedora) PK_CORE+=(gcc pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel) ;;
    arch)   PK_CORE+=(base-devel pkgconf gtk3 webkit2gtk-4.1) ;;
    suse)   PK_CORE+=(gcc pkg-config gtk3-devel webkit2gtk3-devel) ;;
    alpine) PK_CORE+=(build-base pkgconf gtk+3.0-dev webkit2gtk-4.1-dev) ;;
    void)   PK_CORE+=(base-devel pkg-config gtk+3-devel webkit2gtk-devel) ;;
  esac
fi
# The chosen compositor (default labwc) leads the Wayland set unless skipping.
[ -n "$COMPOSITOR" ] && PK_WAYLAND=("$COMPOSITOR" "${PK_WAYLAND[@]}")

x_server_present(){ command -v Xorg >/dev/null 2>&1 || command -v X >/dev/null 2>&1; }

install_x_server(){   # honour an existing X.Org/XLibre; else install one
  [ "$SKIP_PACKAGES" = "1" ] && return 0
  if x_server_present; then
    log "X server already present ($(command -v Xorg || command -v X)) — keeping it"
    return 0
  fi
  [ "${#PK_XSRV[@]}" -gt 0 ] || return 0
  if pm_install_cmd "${PK_XSRV[@]}" >/dev/null 2>&1; then return 0; fi
  # xorg package missing/failed — try a XLibre package name before giving up
  for alt in "${PK_XSRV_ALT[@]}"; do
    if pkg_exists "$alt" && pm_install_cmd "$alt" >/dev/null 2>&1; then
      log "installed XLibre server ($alt)"; return 0
    fi
  done
  die "could not install an X server (${PK_XSRV[*]}).
   Install X.Org or XLibre for your distro by hand, then re-run with
   SOC_SKIP_PACKAGES=1 — or use SESSION=wayland to skip X entirely."
}

# Fast re-runs: an existing install (the install stamp is present) skips the OS
# package step unless --fresh / SOC_FRESH=1. The slow part is the package-manager
# metadata refresh + re-resolution; the deploy/config/service steps below still
# run (they are idempotent and pick up code changes).
if [ "$DEPS_IF_CHANGED" = "1" ] && [ "$(cat "$ETC/.deps-rev" 2>/dev/null)" = "$DEPS_REV" ] \
   && { [ "$NATIVE_BUILD" != 1 ] || pkg-config --exists gtk+-3.0 webkit2gtk-4.1; }; then
  exit 0           # the common case: this update needs no OS packages
fi
# A redeploy never runs the package manager here: --deps-if-changed already did,
# before the swap, where a failure means "retry" instead of "roll back".
[ "$ACTIVATE" = "1" ] && SKIP_PACKAGES=1
if [ "$FRESH" != "1" ] && [ "$SKIP_PACKAGES" != "1" ] && [ "$DEPS_ONLY" != "1" ] \
   && [ -f "$ETC/.installed" ] && [ "$(cat "$ETC/.deps-rev" 2>/dev/null)" = "$DEPS_REV" ]; then
  log "Existing install detected ($ETC/.installed) — skipping OS package install"
  log "  (pass --fresh or SOC_FRESH=1 to reinstall/upgrade packages)"
  SKIP_PACKAGES=1
fi

log "Refreshing package metadata"
pm_refresh

log "Installing core dependencies (GTK/WebKit, autossh, openfortivpn)"
pm_install "${PK_CORE[@]}"

case "$SESSION" in
  xlibre|xorg|x11)
           log "Installing X11 session (X server + openbox)"
           install_x_server; pm_install "${PK_X11[@]}" ;;
  wayland|xwayland)
           log "Installing Wayland session ($COMPOSITOR + cage)"
           pm_install "${PK_WAYLAND[@]}" ;;
  auto)    log "Installing X11 + Wayland sessions (runtime: Wayland→XWayland→XLibre→Xorg)"
           install_x_server; pm_install "${PK_X11[@]}"; pm_try "${PK_WAYLAND[@]}" ;;
esac

log "Installing optional tools"
pm_try "${PK_TOOLS[@]}"
[ "${#PK_ZRAM[@]}" -gt 0 ] && pm_try "${PK_ZRAM[@]}"
[ "$HARDEN" = "1" ] && pm_install nftables

# libsecret `secret-tool` — OPTIONAL: only the secret-service master source needs
# it (SOC_MASTER_SOURCE=secret-service). The default 'sealed' source does not, so
# this is warn-only — a wall using the host-bound seal works without it.
[ "${#PK_SECRETTOOL[@]}" -gt 0 ] && pm_try "${PK_SECRETTOOL[@]}"

# Optional VPN clients (only the one matching vpn.type is actually used).
# openfortivpn is in PK_CORE; add OpenVPN + WireGuard so any vpn.type works.
log "Installing optional VPN clients (openvpn, wireguard-tools; tesseract for iNode)"
pm_try openvpn wireguard-tools
# iNode SSL-VPN solves the gateway's login CAPTCHA with tesseract (pkg name varies)
pm_try tesseract-ocr tesseract

# litebw (pure-Python, rbw-compatible) is how the kiosk reads Vaultwarden — it
# needs no package or Rust toolchain; its launcher is installed onto PATH below.

# Chromium (only needed for engine: chromium panels) — names differ
if ! command -v chromium >/dev/null 2>&1 && ! command -v chromium-browser >/dev/null 2>&1; then
  pm_try chromium chromium-browser
  command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || \
    warn "chromium not installed (only needed for engine: chromium panels)"
fi

# --deps-only: stop here (used by `setup.py repair` to install missing packages)
if [ "$DEPS_ONLY" = "1" ]; then
  if [ "$DEPS_IF_CHANGED" = "1" ]; then
    install -d -m 0755 "$ETC"
    printf '%s\n' "$DEPS_REV" > "$ETC/.deps-rev"
  fi
  log "dependencies installed (--deps-only) — done."
  exit 0
fi

if [ "$NATIVE_BUILD" = 1 ]; then
  command -v cargo >/dev/null 2>&1 || die "a current Rust toolchain is required to build the wall; run make rust-release or use a binary package"
  log "Building the native SOC Wall"
  if [ "$FAMILY" = alpine ]; then
    export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=-crt-static"
  fi
  (cd "$SRC_DIR/rust" && cargo build --locked --release --bin soc-wall --jobs "${CARGO_BUILD_JOBS:-1}")
  NATIVE_SOURCE="$SRC_DIR/rust/target/release/soc-wall"
fi

# --------------------------------------------------------------------------- #
create_users

# Debian's Xorg wrapper restricts who may start X. The kiosk starts X from the
# console VT, so `console` is enough; `anybody` would let any account spawn a
# root-privileged X server.
if [ "$FAMILY" = "debian" ]; then
  if [ -f /etc/X11/Xwrapper.config ]; then
    sed -i 's/^allowed_users=.*/allowed_users=console/' /etc/X11/Xwrapper.config || true
    grep -q '^needs_root_rights' /etc/X11/Xwrapper.config || \
      echo "needs_root_rights=yes" >>/etc/X11/Xwrapper.config
  else
    printf 'allowed_users=console\nneeds_root_rights=yes\n' >/etc/X11/Xwrapper.config
  fi
fi

# --------------------------------------------------------------------------- #
# Each deploy is a complete tree under $RELEASES, and $SOC_ROOT is a symlink to one
# of them, so switching releases is a single atomic rename. Nothing is updated in
# place: a power cut can't leave a half-copied tree, and rollback is another rename.
ROOT_REAL="$(readlink -f "$SOC_ROOT" 2>/dev/null || echo "$SOC_ROOT")"
IN_PLACE=0
[ "$ACTIVATE" = "1" ] || [ "$SRC_DIR" = "$ROOT_REAL" ] && IN_PLACE=1

mkdir -p "$RELEASES"
if [ "$IN_PLACE" = "1" ]; then
  # Already where it runs from: a redeploy (soc-update built and proved this
  # release), or a package install, whose payload is managed by dpkg/rpm.
  REL_DIR="$ROOT_REAL"
  log "Using the tree already at $REL_DIR"
  if [ -n "$NATIVE_SOURCE" ] && [ ! -x "$REL_DIR/bin/soc-wall" ]; then
    install -D -m 0755 "$NATIVE_SOURCE" "$REL_DIR/bin/soc-wall"
  fi
else
  log "Installing project under $RELEASES"
  src_commit="$(src_git rev-parse HEAD 2>/dev/null || true)"
  if [ -z "$src_commit" ]; then
    # No git metadata (a tarball): still give it a unique, valid release id.
    REL_ID="$(date +%s%N | sha256sum | cut -c1-12)"
  elif [ -n "$(src_git status --porcelain 2>/dev/null)" ]; then
    # Local edits: same commit, different content, so it needs its own release.
    REL_ID="${src_commit:0:12}-r$(date +%s)"
  else
    REL_ID="${src_commit:0:12}"
  fi
  # Re-installing the live commit gets its own release. Replacing that directory in
  # place would leave no wall and no updater if the power failed part-way through.
  [ -e "$RELEASES/$REL_ID" ] && REL_ID="${REL_ID%%-r*}-r$(date +%s)"
  REL_DIR="$RELEASES/$REL_ID"
  STAGE="$RELEASES/.stage-$REL_ID"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  # Same exclusions as scripts/soc-update.py (dev-only files never ship).
  tar -C "$SRC_DIR" \
      --exclude='./.git' --exclude='./.venv' --exclude='./dev' --exclude='__pycache__' \
      --exclude='./kiosk-host/tests' --exclude='./.github' --exclude='./.githooks' \
      --exclude='./rust/target' --exclude='./rust/fuzz/target' --exclude='./rust/crates/*/tests' \
      --exclude='./.pre-commit-config.yaml' --exclude='./CONTRIBUTING.md' \
      -cf - . | tar -C "$STAGE" -xf -
  if [ -n "$NATIVE_SOURCE" ]; then
    install -D -m 0755 "$NATIVE_SOURCE" "$STAGE/bin/soc-wall"
    ln -sfn soc-wall "$STAGE/bin/soc-vpn-pinentry"
  fi
  [ -n "$src_commit" ] && printf '%s\n' "$src_commit" > "$STAGE/.commit"
  mv "$STAGE" "$REL_DIR"
fi
chown -R root:root "$REL_DIR/" 2>/dev/null || true
chmod +x "$REL_DIR"/scripts/*.sh "$REL_DIR"/scripts/*.py 2>/dev/null || true
chmod +x "$REL_DIR"/scripts/soc-wall-entrypoint "$REL_DIR"/scripts/soc-wall-menu \
         "$REL_DIR"/scripts/litebw 2>/dev/null || true
# the bundled iNode SSL-VPN client (vendor/) — its connect script + helpers
chmod +x "$REL_DIR"/vendor/iNode-VPN-Client/svpn-connect.sh \
         "$REL_DIR"/vendor/iNode-VPN-Client/scripts/* 2>/dev/null || true
# Root runs this code, so nothing else may write it, whatever umask the clone had.
# inode-svpn-helper also refuses to load a group/other-writable backend.
chmod -R go-w "$REL_DIR/" 2>/dev/null || true

if [ ! -x "$REL_DIR/bin/soc-wall" ]; then
log "Preparing the Python venv for the compatibility runtime"
crypto_distro_pkg(){
  case "$FAMILY" in
    debian|fedora|suse|void) echo python3-cryptography ;;
    arch)                    echo python-cryptography ;;
    alpine)                  echo py3-cryptography ;;
    *)                       echo "" ;;
  esac
}
# Shared between releases, keyed by requirements (scripts/soc-venv.sh), so a normal
# redeploy reuses it. PyYAML + websocket-client + cryptography are all REQUIRED:
# cryptography seals the master password and writes logins into Vaultwarden.
ensure_venv(){
  bash "$REL_DIR/scripts/soc-venv.sh" "$REL_DIR" "$RELEASES" >/dev/null
}
_venv_rc=0
ensure_venv || _venv_rc=$?
if [ "$_venv_rc" = "3" ]; then
  # Never compile cryptography on the Pi (rustc needs over 1 GB of RAM). A distro
  # package is importable through --system-site-packages, so use that instead.
  cpkg="$(crypto_distro_pkg)"
  warn "no prebuilt 'cryptography' wheel for $ARCH — trying the distro package '$cpkg'"
  [ -n "$cpkg" ] && pm_try "$cpkg"
  _venv_rc=0
  ensure_venv || _venv_rc=$?
fi
[ "$_venv_rc" = "0" ] || die "could not build the venv (see the error above). Install your distro's cryptography (e.g. $(crypto_distro_pkg)) and re-run. Do NOT let pip build it from source on a 1 GB Pi."

# The tree is root-owned, so the wall can't write bytecode: without this, every
# start recompiles every module (and on a 1 GB board that is seconds of CPU on
# each boot). Harmless when already compiled; quiet on anything unparsable.
"$REL_DIR/.venv/bin/python" -m compileall -q \
  "$REL_DIR/kiosk-host/host" "$REL_DIR/scripts" "$REL_DIR/setup.py" "$REL_DIR/provision.py" \
  >/dev/null 2>&1 || warn "bytecode precompile reported problems (harmless at runtime)"
fi

# Switch the live link. A pre-release-layout install has a real directory here:
# move it aside first (it is removed once this install has succeeded).
LEGACY_TREE=""
if [ "$IN_PLACE" != "1" ]; then
  if [ -e "$SOC_ROOT" ] && [ ! -L "$SOC_ROOT" ]; then
    LEGACY_TREE="$RELEASES/.legacy-$(date +%s)"
    log "Migrating the old in-place tree to the release layout"
    mv "$SOC_ROOT" "$LEGACY_TREE"
  fi
  mkdir -p "$(dirname "$SOC_ROOT")"
  ln -sfn "$REL_DIR" "$SOC_ROOT.new"
  mv -Tf "$SOC_ROOT.new" "$SOC_ROOT"
fi

# litebw launcher onto PATH — pure-Python Vaultwarden client (replaces rbw).
# It execs `python -m host.litebw` from $SOC_ROOT; deployed under scripts/.
install -d -m 0755 /usr/local/bin
install -m 0755 "$SOC_ROOT/scripts/litebw" /usr/local/bin/litebw
if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
  ln -sfn soc-wall "$SOC_ROOT/bin/soc-vpn-pinentry"
  ln -sfn "$SOC_ROOT/bin/soc-wall" /usr/local/bin/soc-wall
fi
# `soc-update status`, `soc-update rollback`, ... for an operator at a shell.
ln -sfn "$SOC_ROOT/scripts/soc-update.sh" /usr/local/bin/soc-update

# Deploy-time manifest: record every shipped file's sha256 + the source commit.
# The wall warns in the top bar if anything has drifted (tampered install, ad-hoc
# edit), and soc-update uses it to find and repair damage. Best-effort: without
# python3 the wall just won't show the warning.
log "Recording deploy manifest (file hashes + source commit)"
if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
  "$SOC_ROOT/bin/soc-wall" manifest "$SOC_ROOT" "$ETC/manifest.json" || warn "could not write deploy manifest"
elif command -v python3 >/dev/null 2>&1; then
  install -d -m 0755 "$ETC"
  PYTHONPATH="$SOC_ROOT/kiosk-host" python3 -c "
from host import manifest
import sys
try:
    p = manifest.write_manifest('$SOC_ROOT', dest='$ETC/manifest.json')
    print(f'manifest: wrote {p}')
except Exception as e:
    sys.stderr.write(f'manifest: skipped ({e})\n')
" || warn "could not write deploy manifest (drift detection disabled)"
fi

# --------------------------------------------------------------------------- #
log "Setting up $ETC (config + secrets)"
mkdir -p "$ETC" "$ETC/keys"
install_template(){  # src dst mode owner
  if [ -f "$2" ]; then warn "keep existing $2"; else
    cp "$1" "$2"; chmod "$3" "$2"; chown "$4" "$2"; log "created $2"; fi
}
install_template "$SOC_ROOT/config/panels.yaml"          "$ETC/panels.yaml"      0644 "root:root"
install_template "$SOC_ROOT/config/soc.env.example"      "$ETC/soc.env"          0644 "root:root"
[ -f "$ETC/update.env" ] && _new_update_env=0 || _new_update_env=1
install_template "$SOC_ROOT/config/update.env.example"   "$ETC/update.env"       0644 "root:root"
# Follow the repository this box was installed from. Decided once, when the file is
# first created, and it stays the operator's after that. If the source can't be
# worked out, redeploys stay off: this code runs as root, so it must never end up
# following a repository nobody chose.
if [ "$_new_update_env" = "1" ]; then
  _origin="$(src_git remote get-url origin 2>/dev/null || true)"
  case "$_origin" in
    git@*:*)            _origin="https://$(printf '%s' "${_origin#git@}" | sed 's|:|/|')" ;;
    ssh://git@*)        _origin="https://${_origin#ssh://git@}" ;;
  esac
  case "$_origin" in
    https://*@*|'')
      sed -i 's|^SOC_UPDATE_ENABLE=.*|SOC_UPDATE_ENABLE=0|' "$ETC/update.env"
      warn "redeploy left OFF: no https source for this tree. Set SOC_UPDATE_REPO and"
      warn "  SOC_UPDATE_ENABLE=1 in $ETC/update.env to turn it on." ;;
    https://*)
      sed -i "s|^SOC_UPDATE_REPO=.*|SOC_UPDATE_REPO=$_origin|" "$ETC/update.env" ;;
  esac
fi
# Vaultwarden config is inline in its systemd unit (no .env) — nothing to install.
chmod 0750 "$ETC/keys"; chown "$SVC_USER:$SVC_USER" "$ETC/keys"
# Host-bound sealed vault secret (master.enc / pin.enc) — owned by the kiosk user
# (it unlocks the vault at boot), 0700. setup.py first-run/deploy seals it here.
mkdir -p "$ETC/secret"; chmod 0700 "$ETC/secret"; chown "$KIOSK_USER:$KIOSK_USER" "$ETC/secret"
# Persistent panel web data (cookies.sqlite, localStorage, IndexedDB, Chromium
# --user-data-dir) — holds SESSION TOKENS, so 0700 and owned by the kiosk user
# (the panels write it). A SIBLING of secret/, not inside it, so the sealed-master
# guarantee is untouched. The wall creates per-panel 0700 subdirs on first use.
mkdir -p "$ETC/webdata"; chmod 0700 "$ETC/webdata"; chown "$KIOSK_USER:$KIOSK_USER" "$ETC/webdata"
# soc.env is NON-SECRET (vault email/URL, secret-dir PATH, config-item name,
# ports, timeouts — NO password; the master is sealed 0600 under $ETC/secret).
# It is 0644 root:root so EVERY launch path can source it: the kiosk user (tty1
# session), the desktop user (a DE session via soc-wall-desktop.sh — which may be
# ANY logged-in operator, not a fixed account), and the autossh/forti service
# users. A non-readable soc.env is the #1 cause of "desktop mode can't unlock the
# vault" (the launcher silently skips an unreadable env -> empty SOC_VAULT_EMAIL).
# The actual secret (the sealed master) stays 0700/0600, so this exposes no creds.
chmod 0644 "$ETC/soc.env"; chown root:root "$ETC/soc.env"
if ! grep -q '^SOC_KIOSK_USER=' "$ETC/soc.env"; then
  printf '\nSOC_KIOSK_USER=%s\n' "$KIOSK_USER" >> "$ETC/soc.env"
fi

# Backfill the default for older installations that lack the backend key.
if ! grep -q '^SOC_VAULT_BACKEND=' "$ETC/soc.env"; then
  printf '\n# vault backend: litebw (default) | rbw | dev\nSOC_VAULT_BACKEND=litebw\n' >> "$ETC/soc.env"
fi

# A kiosk has nobody at the keyboard: the host must retry forever rather than ever
# wait on a dialog. Only added once, so an operator can set it to 0.
if [ "$INSTALL_MODE" = "kiosk" ] && ! grep -q '^SOC_UNATTENDED=' "$ETC/soc.env"; then
  printf '\n# kiosk: never wait for a human; retry forever (see docs/AUTO_UPDATE.md)\nSOC_UNATTENDED=1\n' \
    >> "$ETC/soc.env"
fi

# record the chosen session in soc.env — only override a manual edit when the
# operator explicitly passed SESSION= to this run
if ! grep -q '^SOC_SESSION=' "$ETC/soc.env"; then
  printf '\n# session backend: x11 | wayland | auto (see docs/INSTALL.md)\nSOC_SESSION=%s\n' \
    "$SESSION" >> "$ETC/soc.env"
elif [ -n "$SESSION_WAS_SET" ]; then
  sed -i "s/^SOC_SESSION=.*/SOC_SESSION=$SESSION/" "$ETC/soc.env"
fi

# --------------------------------------------------------------------------- #
log "Vaultwarden ($VW_MODE)"
mkdir -p /var/lib/vaultwarden
VW_LOCK="$SOC_ROOT/security/vaultwarden.lock"
VW_RESTART=0
if [ "$VW_MODE" = "docker" ]; then
  warn "VW_MODE=docker: costs dockerd + containerd on a 1 GB board and the unit is not"
  warn "  systemd-sandboxed; prefer VW_MODE=native for a production wall."
  if [ "$ACTIVATE" != "1" ]; then
    if ! command -v docker >/dev/null 2>&1; then
      # Signed distro repos only: never pipe a remote bootstrap script into root.
      log "installing Docker from the distro repos"
      case "$FAMILY" in
        debian) pm_install docker.io ;;
        fedora) pm_install moby-engine ;;
        *)      pm_install docker ;;
      esac
    fi
    [ "$HAS_SYSTEMD" = "1" ] && systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  # Pin the image by digest: `latest` would change a security-critical service
  # underneath the wall on an unrelated restart. Multi-arch, so no --platform.
  VW_IMAGE="$(awk -F= '$1=="image"{print $2}' "$VW_LOCK")@$(awk -F= '$1=="digest"{print $2}' "$VW_LOCK")"
  if [ "$ACTIVATE" != "1" ]; then
    docker_pull_retry "$VW_IMAGE" \
      || die "could not pull $VW_IMAGE after 3 attempts — check network/DNS/registry reachability (Pi Wi-Fi may still be coming up), then re-run ./install.sh (it is idempotent)."
  fi
  sed "s|vaultwarden/server:latest|$VW_IMAGE|" "$SOC_ROOT/systemd/vaultwarden-docker.service" \
    > "$ETC/.vaultwarden-docker.service"
  VW_UNIT_SRC="$ETC/.vaultwarden-docker.service"
else
  VW_BIN=/usr/local/bin/vaultwarden
  VW_DB=/var/lib/vaultwarden/db.sqlite3
  if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
    VW_FETCH=("$SOC_ROOT/bin/soc-wall" fetch-vaultwarden)
  else
    VW_FETCH=(python3 "$SOC_ROOT/scripts/fetch-vaultwarden.py")
  fi
  if "${VW_FETCH[@]}" --lock "$VW_LOCK" --dest "$VW_BIN" --check; then
    # Migrations run forwards only, so keep a copy of the database across an
    # upgrade. Stopped first: a copy of a live SQLite file can be inconsistent.
    if [ -x "$VW_BIN" ] && [ -f "$VW_DB" ]; then
      [ "$HAS_SYSTEMD" = "1" ] && systemctl stop vaultwarden.service 2>/dev/null || true
      cp -a "$VW_DB" "$VW_DB.pre-upgrade"
    fi
    if "${VW_FETCH[@]}" --lock "$VW_LOCK" --dest "$VW_BIN"; then
      VW_RESTART=1
    elif [ -x "$VW_BIN" ]; then
      warn "could not fetch the pinned Vaultwarden; keeping the installed one"
      VW_RESTART=1       # it was stopped above
    else
      die "could not fetch the Vaultwarden binary — check network/DNS (Pi Wi-Fi may still be coming up), then re-run ./install.sh (it is idempotent). To supply your own, place it at $VW_BIN."
    fi
  elif [ ! -x "$VW_BIN" ]; then
    die "Vaultwarden is missing and its install check failed. Check $VW_LOCK and the native executable's shared libraries."
  fi
  id vaultwarden >/dev/null 2>&1 || \
    useradd -r -s "$(command -v nologin || echo /usr/sbin/nologin)" vaultwarden
  chown -R vaultwarden:vaultwarden /var/lib/vaultwarden
  VW_UNIT_SRC="$SOC_ROOT/systemd/vaultwarden.service"
fi

# --------------------------------------------------------------------------- #
# has panels.yaml configured tunnels / a VPN? (used to enable services)
# Exit 0 yes, 1 no, 2 can't tell. The third must stay distinct: a config that doesn't
# load is no reason to switch off a tunnel or VPN that is working right now.
config_wants(){ # $1=tunnel|vpn
  if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
    "$SOC_ROOT/bin/soc-wall" config-wants "$1" "$ETC/panels.yaml"
    return
  fi
  "$SOC_ROOT/.venv/bin/python" - "$1" "$ETC/panels.yaml" "$SOC_ROOT/kiosk-host" <<'PY'
import sys
sys.path.insert(0, sys.argv[3])
try:
    from host import config
    conf = config.load(sys.argv[2])
except Exception as e:  # noqa: BLE001
    sys.stderr.write(f"could not read the wall config: {e}\n")
    sys.exit(2)


def complete(v):
    kind, from_vault = config.vpn_kind(v), bool(v.get("config_from_vault"))
    if kind in ("fortinet", "inode"):
        return bool(v.get("gateway") and v.get("vault_item"))
    return bool(v.get("vault_item") if from_vault else v.get("config"))


if sys.argv[1] == "tunnel":
    wanted = (any(p.mode == "tunnel" for p in conf.panels)
              and conf.tunnel.get("enabled", True))
else:
    # The single unit fans out to N supervisors, so any complete entry needs it.
    wanted = any(isinstance(v, dict) and v.get("enabled") and complete(v)
                 for v in conf.vpns or [])
sys.exit(0 if wanted else 1)
PY
}
sync_unit_with_config(){ # $1=tunnel|vpn $2=unit
  local rc=0
  config_wants "$1" || rc=$?
  case "$rc" in
    0) systemctl enable "$2" >/dev/null 2>&1 || warn "could not enable $2"
       log "$2 enabled ($1 configured)" ;;
    1) systemctl disable "$2" >/dev/null 2>&1 || true
       log "no $1 in panels.yaml — $2 left disabled" ;;
    *) warn "could not read the config; leaving $2 as it is" ;;
  esac
}

if [ "$HAS_SYSTEMD" = "1" ]; then
  log "Installing systemd services (vaultwarden, autossh-tunnel, forti-vpn, soc-wall, soc-tarpit, soc-update)"
  # Reports whether the unit changed, so a redeploy restarts only what it must.
  install_unit(){ # $1=source [$2=unit name]
    local dst="/etc/systemd/system/${2:-$(basename "$1")}"
    cmp -s "$1" "$dst" && return 1
    cp "$1" "$dst"
    return 0
  }
  install_unit "$VW_UNIT_SRC" vaultwarden.service && VW_RESTART=1
  install_unit "$SOC_ROOT/systemd/autossh-tunnel.service" || true
  install_unit "$SOC_ROOT/systemd/forti-vpn.service" || true
  # Scanner-deception tarpit on port 80. Installed but NEVER auto-enabled —
  # opt-in with: SOC_TARPIT_ENABLE=1 in $ETC/tarpit.env, then
  # `systemctl enable --now soc-tarpit`. See docs/SECURITY.md.
  install_unit "$SOC_ROOT/systemd/soc-tarpit.service" || true
  install_unit "$SOC_ROOT/systemd/soc-update.service" || true
  install_unit "$SOC_ROOT/systemd/soc-update.timer" || true
  # Supervised kiosk session (env baked in, no soc.env) — setup.py regenerates it
  # with the wizard's values. Installed but NOT enabled: switching the boot from
  # getty-autologin to this service must be validated on the target display (see
  # the end-of-run notes), so we don't flip it automatically.
  [ -f /etc/systemd/system/soc-wall.service ] || \
    cp "$SOC_ROOT/systemd/soc-wall.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable vaultwarden.service
  # A plain restart: the upgrade above stopped it, and try-restart would leave it down.
  [ "$VW_RESTART" = "1" ] && { systemctl restart vaultwarden.service || true; }

  # Unattended redeploy. A package-managed tree (a real directory) gets its updates
  # from dpkg/rpm instead, so the timer stays off there.
  if [ ! -L "$SOC_ROOT" ]; then
    log "soc-update not enabled: $SOC_ROOT is package-managed"
  elif grep -q '^SOC_UPDATE_ENABLE=0' "$ETC/update.env" 2>/dev/null; then
    systemctl disable --now soc-update.timer >/dev/null 2>&1 || true
    log "soc-update disabled (SOC_UPDATE_ENABLE=0 in $ETC/update.env)"
  else
    systemctl enable --now soc-update.timer >/dev/null 2>&1 \
      && log "soc-update.timer enabled: this box now redeploys itself" \
      || warn "could not enable soc-update.timer"
  fi
  sync_unit_with_config tunnel autossh-tunnel.service
  sync_unit_with_config vpn forti-vpn.service
  # Tarpit: installed above, enabled ONLY on explicit opt-in. It also self-guards
  # at runtime (refuses to start unless SOC_TARPIT_ENABLE=1 in tarpit.env), so we
  # seed that env when enabling here. Without opt-in it stays disabled + dormant.
  if [ "$SOC_TARPIT_ENABLE" = "1" ]; then
    install -m 0644 /dev/stdin "$ETC/tarpit.env" <<'EOF'
# Scanner-deception tarpit (port 80). Set to 1 to arm it; the unit refuses to
# start otherwise. Installed by ./install.sh with SOC_TARPIT_ENABLE=1.
SOC_TARPIT_ENABLE=1
EOF
    systemctl enable soc-tarpit.service 2>/dev/null \
      && log "soc-tarpit enabled (SOC_TARPIT_ENABLE=1) — scanner-deception on :80" \
      || warn "could not enable soc-tarpit.service"
  else
    systemctl disable soc-tarpit.service 2>/dev/null || true
    log "soc-tarpit installed but disabled (opt-in: SOC_TARPIT_ENABLE=1 + tarpit.env)"
  fi
else
  warn "no systemd — skipping service installation. Supervise these by hand"
  warn "with your init (OpenRC/runit/sysvinit), all simple long-running commands:"
  warn "  vaultwarden : $SOC_ROOT/systemd/vaultwarden*.service shows the command"
  warn "  autossh     : $SOC_ROOT/scripts/launcher.sh-style restart loop around autossh"
  warn "  forti-vpn   : $SOC_ROOT/.venv/bin/python $SOC_ROOT/scripts/forti-vpn-connect.py"
  warn "                (self-supervising: reconnect/backoff built in; run as root)"
fi

# --------------------------------------------------------------------------- #
# sudoers drop-in: lets the soc user restart ONLY the VPN/tunnel/tarpit units
# without a password, so ⚙ Settings → Save applies VPN edits LIVE (no "PENDING
# restart" message) and the on-screen reconnect button + journalctl pane work
# for the unprivileged kiosk user. This deploy line uses the SINGLE-VPN model
# (forti-vpn.service); the sudoers file lists no @-instances. visudo -cf
# validates a TEMP copy before we move it into /etc/sudoers.d, so a syntax
# error can NEVER break the system-wide sudoers stack.
SUDOERS_INSTALLED=0
log "Installing sudoers drop-in (soc -> systemctl restart forti-vpn/tunnel/tarpit)"
SUDOERS_SRC="$SOC_ROOT/security/soc-wall-restart.sudoers"
SUDOERS_TMP="/etc/sudoers.d/.soc-wall-restart.tmp"
SUDOERS_DST="/etc/sudoers.d/soc-wall-restart"
if command -v visudo >/dev/null 2>&1 && [ -f "$SUDOERS_SRC" ]; then
  # The sudoers file names the user literally as `soc`; when KIOSK_USER differs,
  # rewrite the leading user field so the rule applies to the real kiosk user.
  if [ "$KIOSK_USER" != "soc" ]; then
    sed "s/^soc ALL=/$KIOSK_USER ALL=/" "$SUDOERS_SRC" > "$SUDOERS_TMP"
    chmod 0440 "$SUDOERS_TMP"; chown root:root "$SUDOERS_TMP"
  else
    install -m 0440 -o root -g root "$SUDOERS_SRC" "$SUDOERS_TMP"
  fi
  if visudo -cf "$SUDOERS_TMP" >/dev/null 2>&1; then
    mv -f "$SUDOERS_TMP" "$SUDOERS_DST"
    SUDOERS_INSTALLED=1
    log "  sudoers OK -> $SUDOERS_DST"
  else
    warn "  visudo rejected $SUDOERS_SRC — NOT installing; VPN/tunnel"
    warn "  edits will continue to surface PENDING restart messages."
    rm -f "$SUDOERS_TMP"
  fi
else
  warn "  visudo not found OR sudoers source missing — skipping drop-in"
fi

# --------------------------------------------------------------------------- #
log "Configuring zram + sysctl"
if [ "$HAS_SYSTEMD" = "1" ] && [ "${#PK_ZRAM[@]}" -gt 0 ]; then
  cp "$SOC_ROOT/security/zram.conf" /etc/systemd/zram-generator.conf
fi
cp "$SOC_ROOT/security/99-soc-sysctl.conf" /etc/sysctl.d/99-soc.conf
# Capability-gate each key: a sysctl knob missing on an older Pi kernel must
# skip-with-reason, not make `sysctl --system` complain. Comment out any line
# whose /proc/sys/<path> isn't present so the deployed file only sets what this
# kernel supports. Idempotent: a re-run re-copies the pristine file first, then
# re-evaluates. kernel.foo.bar -> /proc/sys/kernel/foo/bar.
while IFS= read -r _sline; do
  case "$_sline" in
    ''|'#'*) continue ;;
  esac
  _skey="${_sline%%=*}"
  _skey="${_skey// /}"
  [ -n "$_skey" ] || continue
  if [ ! -e "/proc/sys/${_skey//.//}" ]; then
    sed -i "s|^[[:space:]]*${_skey}[[:space:]]*=.*|# (unsupported on this kernel) &|" \
      /etc/sysctl.d/99-soc.conf 2>/dev/null || true
    warn "  sysctl: $_skey not present on this kernel — skipped"
  fi
done < "$SOC_ROOT/security/99-soc-sysctl.conf"
sysctl --system >/dev/null 2>&1 || true
[ "$HAS_SYSTEMD" = "1" ] && systemctl daemon-reload

# --------------------------------------------------------------------------- #
# Bound the journal + coredumps so 24/7 logging and crash dumps can't fill the
# 40 GB SD card. The kiosk logs continuously (panel loads, VPN pill every 10s,
# memory watchdog every 30s) and panels DO crash/OOM-restart by design, so both
# are unbounded sinks without a cap. Only meaningful with systemd's journal.
if [ "$HAS_SYSTEMD" = "1" ]; then
  log "Capping journald size + disabling coredumps (40 GB SD-card safety)"
  install -d -m 0755 /etc/systemd/journald.conf.d
  cp "$SOC_ROOT/security/journald-soc.conf" /etc/systemd/journald.conf.d/10-soc.conf
  install -d -m 0755 /etc/systemd/coredump.conf.d
  cp "$SOC_ROOT/security/coredump-soc.conf" /etc/systemd/coredump.conf.d/10-soc.conf
  systemctl restart systemd-journald >/dev/null 2>&1 || true
fi

# --------------------------------------------------------------------------- #
# /run/soc-wall holds the heartbeat: tmpfs, so a 15 s cadence costs no SD wear.
if [ "$HAS_SYSTEMD" = "1" ]; then
  install -d -m 0755 /etc/tmpfiles.d
  sed "s/ soc soc / $KIOSK_USER $KIOSK_USER /" "$SOC_ROOT/security/soc-wall.tmpfiles" \
    > /etc/tmpfiles.d/soc-wall.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/soc-wall.conf >/dev/null 2>&1 || true
fi

# Appliance-only system changes. Neither belongs on a workstation.
TRIMMED_UNITS="$(manifest_row REVERT trimmed_units)"
if [ "$INSTALL_MODE" = "kiosk" ] && [ "$HAS_SYSTEMD" = "1" ]; then
  # The last resort when even the kernel or PID 1 hangs (a thrashing 1 GB box can
  # get there): the hardware watchdog reboots it. Harmless without the hardware.
  install -d -m 0755 /etc/systemd/system.conf.d
  cp "$SOC_ROOT/security/watchdog-soc.conf" /etc/systemd/system.conf.d/10-soc-watchdog.conf

  # Stop services a dedicated wall never uses, which frees tens of MB on a 1 GB
  # board. Each one is recorded so uninstall turns it back on. SOC_KEEP_SERVICES=1
  # opts out (e.g. for a Bluetooth keyboard).
  if [ "${SOC_KEEP_SERVICES:-0}" != "1" ]; then
    for _u in bluetooth.service hciuart.service avahi-daemon.service avahi-daemon.socket \
              ModemManager.service triggerhappy.service triggerhappy.socket \
              cups.service cups-browsed.service; do
      if [ "$(systemctl is-enabled "$_u" 2>/dev/null)" = "enabled" ]; then
        systemctl disable --now "$_u" >/dev/null 2>&1 && {
          TRIMMED_UNITS="${TRIMMED_UNITS:+$TRIMMED_UNITS }$_u"
          log "  disabled unused service: $_u"
        }
      fi
    done
  fi
fi

# --------------------------------------------------------------------------- #
log "Configuring kiosk session for $KIOSK_USER (SESSION=$SESSION)"
HOME_DIR="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
# Fail CLOSED if the home field came back empty or is not a real directory
# (NSS hiccup, a just-created account whose home isn't materialised yet, an
# account with no home). Without this guard the dotfile writes below would target
# "/.config", "/.xinitrc", and so on.
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || \
  die "kiosk user '$KIOSK_USER' has no valid home directory (got '${HOME_DIR:-<empty>}') — refusing to write session dotfiles to the filesystem root. Check the account (getent passwd $KIOSK_USER) and re-run ./install.sh (it is idempotent)."
# rc.xml with the grid placement rules from panels.yaml. 1920x1080 is only the
# install-time default: xinitrc regenerates it from xrandr at every X session
# start (display.auto), and wayland-session.sh does the same for labwc.
_session_rc=0
as_user "$KIOSK_USER" env HOME="$HOME_DIR" SOC_ROOT="$SOC_ROOT" PANELS="$ETC/panels.yaml" bash -s <<'SESSION' || _session_rc=$?
set -eu
mkdir -p "$HOME/.config/openbox"
cp "$SOC_ROOT/openbox/menu.xml" "$SOC_ROOT/openbox/autostart" "$HOME/.config/openbox/"
cp "$SOC_ROOT/scripts/xinitrc" "$HOME/.xinitrc"
# Only a default for the first boot, so a config that doesn't load must not stop a
# redeploy: the session regenerates this file when it starts.
if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
  set -- "$SOC_ROOT/bin/soc-wall" wm-rc openbox
else
  set -- "$SOC_ROOT/.venv/bin/python" "$SOC_ROOT/scripts/gen-openbox-rc.py"
fi
"$@" \
  --panels "$PANELS" --template "$SOC_ROOT/openbox/rc.xml.tmpl" \
  --out "$HOME/.config/openbox/rc.xml" --width 1920 --height 1080 \
  || echo "could not generate openbox rc.xml from $PANELS (the session retries)" >&2
# session dispatcher on tty1 login (picks X11/Wayland per SOC_SESSION)
cat > "$HOME/.bash_profile" <<EOF
export SOC_ROOT=$SOC_ROOT
if [ -z "\$DISPLAY" ] && [ -z "\$WAYLAND_DISPLAY" ] && [ "\$(tty)" = "/dev/tty1" ]; then
  exec $SOC_ROOT/scripts/start-session.sh
fi
EOF
SESSION
# On a redeploy these files already exist from the last release, so failing to refresh
# them (a full disk, or a kiosk user interfering) mustn't cost a good release.
if [ "$_session_rc" != "0" ]; then
  [ "$ACTIVATE" = "1" ] || die "could not write the session files for $KIOSK_USER (see above)"
  warn "could not refresh the session files for $KIOSK_USER; keeping the existing ones"
fi

# Desktop-mode user: seed a per-user .config dir (so appearance/branding persist
# per-user when the wall runs windowed) but DON'T touch tty1/the boot — it starts
# on demand inside the operator's DE session. Recorded as a SYSCHANGE below.
DESKTOP_HOME="$(getent passwd "$DESKTOP_USER" 2>/dev/null | cut -d: -f6)"
if [ -n "$DESKTOP_HOME" ]; then
  as_user "$DESKTOP_USER" mkdir -p "$DESKTOP_HOME/.config/soc-display"
fi

# Capture the original default target BEFORE we touch it, so uninstall.sh can
# restore it (only meaningful with systemd). The actual boot takeover (set-default
# + getty override + consoleblank) is DEFERRED to immediately before the manifest
# write further down, so any earlier failure (venv/pip, hardening, sshd validation)
# exits with the boot target UNCHANGED — never a dark/unbootable box mid-install.
#
# Every redeploy re-runs this, so a value recorded by an earlier run always wins:
# re-capturing would record multi-user.target, the value WE set, and uninstall could
# then never give the operator their original boot back.
ORIG_DEFAULT_TARGET="$(manifest_row REVERT orig_default_target)"
if [ -z "$ORIG_DEFAULT_TARGET" ] && [ "$HAS_SYSTEMD" = "1" ]; then
  ORIG_DEFAULT_TARGET="$(systemctl get-default 2>/dev/null || true)"
fi
# Whether the boot was ever changed by an install (recorded for uninstall), versus
# whether THIS run changed it (the only thing this run's trap may undo).
DID_SET_DEFAULT="$(manifest_row REVERT did_set_default)"; DID_SET_DEFAULT="${DID_SET_DEFAULT:-0}"
DID_CONSOLEBLANK="$(manifest_row REVERT did_consoleblank)"; DID_CONSOLEBLANK="${DID_CONSOLEBLANK:-0}"
SET_DEFAULT_NOW=0
CONSOLEBLANK_NOW=0

# --------------------------------------------------------------------------- #
# Clickable launcher: the "SOC Video Wall" XDG .desktop app + icon — THE single
# advertised entry, opening the control center (run / configure / install /
# uninstall in one window). Installed in BOTH modes — the primary entry point in
# desktop mode. Guarded so a repo that hasn't shipped the asset yet (or a trimmed
# deploy) degrades gracefully.
#
# Single advertised entry: only "SOC Video Wall" (soc-wall.desktop) ships. The
# control center launches Setup + Appearance via scripts/soc-wall-setup-gui.sh /
# soc-wall-appearance.sh (not via separate .desktop files), so we chmod +x those
# helpers below but install no companion XDG entries.
#
# Rebrand-aware: the control-center .desktop entry is GENERATED from branding
# (host.branding) so an operator's name/tagline/icon flow into the launcher, and the
# branding source is installed under $ETC for in-place editing. Falls back to the
# static asset when branding/python isn't available (trimmed deploy / pre-venv).
DESKTOP_FILE=""
ICON_FILE=""
BRANDING_FILE=""
VENV_PY="$SOC_ROOT/.venv/bin/python"
DESKTOP_DST="/usr/share/applications/soc-wall.desktop"
if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
  BRANDING_CMD=("$SOC_ROOT/bin/soc-wall" branding)
else
  BRANDING_CMD=("$VENV_PY" -m host.branding)
fi

# Install the branding source so operators can rebrand in place — but NEVER
# clobber an edited branding.yaml on re-install (idempotent).
if [ -f "$SOC_ROOT/branding/branding.yaml" ]; then
  if [ -f "$ETC/branding.yaml" ]; then
    warn "keep existing $ETC/branding.yaml (operator branding preserved)"
    BRANDING_FILE="$ETC/branding.yaml"
  else
    install -Dm0644 "$SOC_ROOT/branding/branding.yaml" "$ETC/branding.yaml"
    log "installed branding source -> $ETC/branding.yaml (edit to rebrand)"
    BRANDING_FILE="$ETC/branding.yaml"
  fi
fi

if [ -f "$SOC_ROOT/soc-wall.desktop" ] || [ -x "${BRANDING_CMD[0]}" ]; then
  log "Installing desktop launcher (rebrand-aware app entry + icon)"
  install -d -m 0755 /usr/share/applications
  # GENERATE the entry from branding (run from kiosk-host so `host` is importable;
  # SOC_BRANDING_FILE points at the just-installed source so operator edits win).
  if [ -x "${BRANDING_CMD[0]}" ] && SOC_ROOT="$SOC_ROOT" SOC_BRANDING_FILE="${BRANDING_FILE:-$SOC_ROOT/branding/branding.yaml}" \
       PYTHONPATH="$SOC_ROOT/kiosk-host" "${BRANDING_CMD[@]}" desktop \
       "$SOC_ROOT/scripts/soc-wall-menu" soc-wall > "$DESKTOP_DST" 2>/dev/null \
     && [ -s "$DESKTOP_DST" ]; then
    log "generated $DESKTOP_DST from branding"
    DESKTOP_FILE="$DESKTOP_DST"
  elif [ -f "$SOC_ROOT/soc-wall.desktop" ]; then
    warn "branding render unavailable — copying the static soc-wall.desktop"
    install -Dm0644 "$SOC_ROOT/soc-wall.desktop" "$DESKTOP_DST"
    DESKTOP_FILE="$DESKTOP_DST"
  else
    warn "no branding/python and no static soc-wall.desktop — skipping desktop entry"
  fi

  # Icon: a custom branding icon (if it resolves to a real file) wins; otherwise
  # the packaged share/icons/soc-wall.svg. Installed as the hicolor 'soc-wall'
  # name the generated entry references.
  if [ -n "$DESKTOP_FILE" ]; then
    BRAND_ICON=""
    if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
      BRAND_ICON="$(SOC_ROOT="$SOC_ROOT" SOC_BRANDING_FILE="${BRANDING_FILE:-$SOC_ROOT/branding/branding.yaml}" \
        "${BRANDING_CMD[@]}" icon-path 2>/dev/null || true)"
    elif [ -x "$VENV_PY" ]; then
      BRAND_ICON="$(SOC_ROOT="$SOC_ROOT" SOC_BRANDING_FILE="${BRANDING_FILE:-$SOC_ROOT/branding/branding.yaml}" \
        PYTHONPATH="$SOC_ROOT/kiosk-host" "$VENV_PY" -c \
        'from host import branding; print(branding.icon_path())' 2>/dev/null || true)"
    fi
    if [ -z "$BRAND_ICON" ] || [ ! -f "$BRAND_ICON" ]; then
      BRAND_ICON="$SOC_ROOT/share/icons/soc-wall.svg"
    fi
    if [ -f "$BRAND_ICON" ]; then
      install -Dm0644 "$BRAND_ICON" \
        /usr/share/icons/hicolor/scalable/apps/soc-wall.svg
      ICON_FILE="/usr/share/icons/hicolor/scalable/apps/soc-wall.svg"
      log "installed app icon -> $ICON_FILE (from ${BRAND_ICON#"$SOC_ROOT/"})"
    fi
  fi

  # The control center execs these helpers by path (bash <sh>); chmod +x so direct
  # exec works too. No companion .desktop entries — soc-wall.desktop is the sole entry.
  [ -f "$SOC_ROOT/scripts/soc-wall-setup-gui.sh" ] && \
    chmod +x "$SOC_ROOT/scripts/soc-wall-setup-gui.sh" 2>/dev/null || true
  [ -f "$SOC_ROOT/scripts/soc-wall-appearance.sh" ] && \
    chmod +x "$SOC_ROOT/scripts/soc-wall-appearance.sh" 2>/dev/null || true

  # refresh the desktop + icon caches best-effort (absent on headless/minimal)
  command -v update-desktop-database >/dev/null 2>&1 && \
    update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 && \
    gtk-update-icon-cache -qtf /usr/share/icons/hicolor >/dev/null 2>&1 || true
else
  warn "no $SOC_ROOT/soc-wall.desktop and no venv python — skipping desktop launcher"
fi

# --------------------------------------------------------------------------- #
# A redeploy never touches this block: /etc/nftables.conf holds the operator's own
# egress sets and admin subnet, and overwriting them would cut the box off.
if [ "$HARDEN" = "1" ] && [ "$ACTIVATE" != "1" ]; then
  log "Applying hardening (nftables + sshd)"
  # Only ever a first install: an existing ruleset of ours holds this site's admin
  # subnet and egress sets, and replacing it would cut the box off at the next boot.
  if grep -q '^# SOC wall firewall' /etc/nftables.conf 2>/dev/null; then
    log "  keeping the existing /etc/nftables.conf"
    grep -q '^define update_uid' /etc/nftables.conf || \
      warn "  /etc/nftables.conf predates redeploys: add the update_uid rule from security/nftables.conf"
  else
    cp "$SOC_ROOT/security/nftables.conf" /etc/nftables.conf
  fi
  # Let the redeployer's git user reach HTTPS. By uid, so a renderer stays blocked.
  sed -i "s|^define update_uid =.*|define update_uid = $(id -u "$UPDATE_USER")     # set by installer|" \
    /etc/nftables.conf

  # Optionally bake the admin subnet in from SSH_ADMIN_CIDR= (e.g. 192.168.1.0/24).
  if [ -n "$SSH_ADMIN_CIDR" ]; then
    sed -i "s|^define ssh_admin_cidr =.*|define ssh_admin_cidr = $SSH_ADMIN_CIDR    # set by installer|" \
      /etc/nftables.conf
  fi

  # FAIL-CLOSED (SEC-1): never enable a ruleset that accepts SSH from the whole
  # internet. Default is loopback-only; the operator must pick a real subnet.
  eff_cidr="$(awk '/^define ssh_admin_cidr =/{print $4}' /etc/nftables.conf)"
  if [ "$eff_cidr" = "0.0.0.0/0" ]; then
    die "refusing to enable nftables: ssh_admin_cidr is 0.0.0.0/0 (SSH open to the world). Set a real admin subnet: SSH_ADMIN_CIDR=192.168.1.0/24 ./install.sh  (or edit /etc/nftables.conf)."
  fi

  # (B) Dry-run parse the BAKED ruleset before enabling it. A corrupt ruleset
  # must NOT be wired into the next boot. nft present? parse it; on failure warn
  # + skip-enable (fail-safe, never die). nft absent -> can't validate, skip-enable.
  NFT_OK=0
  if command -v nft >/dev/null 2>&1; then
    if nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
      NFT_OK=1
    else
      warn "nftables ruleset failed 'nft -c -f /etc/nftables.conf' — NOT enabling the"
      warn "  service (left the file in place for review). Fix it, then enable by hand."
    fi
  else
    warn "nft not found — cannot validate /etc/nftables.conf; NOT enabling the service."
  fi
  if [ "$NFT_OK" = "1" ]; then
    [ "$HAS_SYSTEMD" = "1" ] && systemctl enable nftables.service || \
      warn "no systemd — enable nftables with your init (e.g. rc-update add nftables)"
    log "nftables admin SSH source: $eff_cidr (egress is allowlisted — set vpn_gateways/jump_hosts in /etc/nftables.conf)"
    warn "review /etc/nftables.conf egress sets (vpn_gateways, jump_hosts, dns_servers) before 'systemctl start nftables'"
  fi

  # (A) sshd hardening: install the drop-in, then VALIDATE the whole sshd config
  # with `sshd -t`. On success reload sshd so key-only takes effect now (not just
  # at reboot). On failure REMOVE the drop-in (fail-safe — a syntax error must
  # never brick sshd on reboot) and warn. SSHD_INSTALLED gates the manifest row.
  SSHD_INSTALLED=0
  install -d /etc/ssh/sshd_config.d
  cp "$SOC_ROOT/security/sshd_hardening.conf" /etc/ssh/sshd_config.d/10-soc-hardening.conf
  _sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
  if [ -x "$_sshd_bin" ] && "$_sshd_bin" -t >/dev/null 2>&1; then
    SSHD_INSTALLED=1
    if [ "$HAS_SYSTEMD" = "1" ]; then
      systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || \
        warn "  sshd config valid but reload failed — it applies on next sshd restart."
    fi
    warn "sshd hardening installed (key-only). Ensure you have an authorized key before reboot!"
  elif [ ! -x "$_sshd_bin" ]; then
    # No sshd to validate against — leave the drop-in (inert until sshd appears)
    # but warn we couldn't verify it.
    SSHD_INSTALLED=1
    warn "sshd binary not found — installed the hardening drop-in UNVALIDATED."
  else
    rm -f /etc/ssh/sshd_config.d/10-soc-hardening.conf
    warn "sshd hardening drop-in REJECTED by 'sshd -t' — removed it (sshd left as-is)."
  fi

  # (D) modprobe blacklist: block auto-load of USB-storage / FireWire-DMA / USB-modem
  # drivers on a physically-exposed kiosk. Gate on /etc/modprobe.d existing; opt-out
  # with SOC_SKIP_MODPROBE=1. MODPROBE_INSTALLED gates the manifest row.
  MODPROBE_INSTALLED=0
  if [ "$SOC_SKIP_MODPROBE" = "1" ]; then
    log "  SOC_SKIP_MODPROBE=1 — skipping USB/DMA module blacklist"
  elif [ ! -d /etc/modprobe.d ]; then
    warn "  /etc/modprobe.d missing — skipping module blacklist"
  elif [ ! -f "$SOC_ROOT/security/modprobe-blacklist.conf" ]; then
    warn "  security/modprobe-blacklist.conf missing — skipping module blacklist"
  else
    cp "$SOC_ROOT/security/modprobe-blacklist.conf" /etc/modprobe.d/soc-blacklist.conf
    MODPROBE_INSTALLED=1
    log "  blacklisted usb_storage, firewire_core, cdc_acm (-> /etc/modprobe.d/soc-blacklist.conf)"
  fi

  # (E) /tmp mount hardening: nodev,nosuid,noexec. Probe with findmnt; only act if
  # /tmp is a real mount AND the options aren't already applied. Idempotent: a
  # uniquely-tagged marker block in /etc/fstab is grep-guarded and removed by
  # uninstall. Opt-out with SOC_SKIP_FSTAB=1. FSTAB_HARDENED gates the manifest row.
  # /tmp ONLY — never /boot (Pi firmware) or /var.
  FSTAB_HARDENED=0
  if [ "$SOC_SKIP_FSTAB" = "1" ]; then
    log "  SOC_SKIP_FSTAB=1 — skipping /tmp mount-option hardening"
  elif ! command -v findmnt >/dev/null 2>&1; then
    warn "  findmnt not found — skipping /tmp mount-option hardening"
  elif [ ! -f /etc/fstab ]; then
    warn "  /etc/fstab missing — skipping /tmp mount-option hardening"
  elif grep -q '# soc-wall:/tmp-harden' /etc/fstab 2>/dev/null; then
    FSTAB_HARDENED=1
    log "  /tmp hardening already present in /etc/fstab — no change"
  else
    _tmp_opts="$(findmnt -no OPTIONS /tmp 2>/dev/null || true)"
    if [ -n "$_tmp_opts" ] \
       && printf '%s' "$_tmp_opts" | grep -q '\bnodev\b' \
       && printf '%s' "$_tmp_opts" | grep -q '\bnosuid\b' \
       && printf '%s' "$_tmp_opts" | grep -q '\bnoexec\b'; then
      log "  /tmp already mounted nodev,nosuid,noexec — no fstab change needed"
    elif grep -qE '^[^#]*[[:space:]]/tmp[[:space:]]' /etc/fstab 2>/dev/null; then
      # /tmp has its own fstab line we'd have to rewrite in place — too risky to
      # edit blind; tell the operator instead of mangling their mount spec.
      warn "  /tmp has an existing /etc/fstab entry — add nodev,nosuid,noexec to it"
      warn "  by hand (left it untouched to avoid breaking your mount spec)."
    else
      # /tmp is not separately listed in fstab (typically a systemd tmpfs or part
      # of /). Append a self-contained tmpfs mount so /tmp becomes a hardened
      # tmpfs on next boot. Tagged so uninstall can strip exactly this block.
      {
        printf '# soc-wall:/tmp-harden BEGIN (HARDEN=1; removed by uninstall.sh)\n'
        printf 'tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,mode=1777 0 0\n'
        printf '# soc-wall:/tmp-harden END\n'
      } >> /etc/fstab
      FSTAB_HARDENED=1
      log "  added hardened tmpfs /tmp to /etc/fstab (nodev,nosuid,noexec; applies on reboot)"
      warn "  /tmp becomes a fresh tmpfs on next boot — existing /tmp contents won't persist."
    fi
  fi
fi

# --------------------------------------------------------------------------- #
# DEFERRED boot takeover. Everything that can fail on a flaky network or a picky
# box (docker pull, venv/pip, the HARDEN nftables `die`, sshd validation, the
# launcher/cp steps) has now run. Only here — with all of that behind us — do we
# flip the boot: switch the default target to multi-user, install the tty1
# autologin override, and disable console blanking. So any earlier failure exits
# with the boot COMPLETELY UNCHANGED (no dark/unbootable box mid-install), and the
# REVERT rows are written into the manifest right after this mutation. The
# happy-path end state is byte-identical to doing this earlier.
#
# Belt-and-suspenders: a scoped trap rolls the mutation back if we're interrupted
# (SIGINT) or hit an unexpected failure in the tiny window between here and the
# manifest+stamp write. Every rollback command is `|| true` so the trap can never
# itself abort under set -e or mask the original non-zero exit (we always re-exit
# $_rc). The trap is disarmed (`trap - ERR EXIT`) right after the stamp write.
trap '_rc=$?; trap - ERR EXIT; if [ "$_rc" -ne 0 ] && [ "${SET_DEFAULT_NOW:-0}" = 1 ] && [ -n "$ORIG_DEFAULT_TARGET" ]; then systemctl set-default "$ORIG_DEFAULT_TARGET" >/dev/null 2>&1 || true; fi; if [ "$_rc" -ne 0 ] && [ "${CONSOLEBLANK_NOW:-0}" = 1 ]; then sed -i "s/ consoleblank=0//" /boot/firmware/cmdline.txt 2>/dev/null || true; fi; exit $_rc' ERR EXIT

# tty1 takeover (autologin + multi-user default target) is the dedicated-appliance
# behaviour — kiosk mode only. In desktop mode we deploy the same session bits but
# leave the boot alone so the existing DE/login manager keeps working; the wall is
# launched on demand (desktop icon / `systemctl start soc-wall`).
if [ "$INSTALL_MODE" = "kiosk" ]; then
  if [ "$HAS_SYSTEMD" = "1" ]; then
    log "Enabling tty1 autologin (INSTALL_MODE=kiosk)"
    mkdir -p /etc/systemd/system/getty@tty1.service.d
    sed "s/--autologin soc /--autologin $KIOSK_USER /" \
      "$SOC_ROOT/systemd/getty-autologin.conf" > /etc/systemd/system/getty@tty1.service.d/override.conf
    sed -e "s|@SOC_ROOT@|$SOC_ROOT|g" -e "s|@ETC@|$ETC|g" \
      "$SOC_ROOT/systemd/soc-firstboot.service" > /etc/systemd/system/soc-firstboot.service
    if [ "$(systemctl get-default 2>/dev/null)" != "multi-user.target" ]; then
      systemctl set-default multi-user.target  # no desktop env; we run our own session
      DID_SET_DEFAULT=1
      SET_DEFAULT_NOW=1
    fi
    systemctl daemon-reload
    systemctl enable soc-firstboot.service
  else
    warn "no systemd — set up tty1 autologin for '$KIOSK_USER' with your init."
    warn "  agetty:  agetty --autologin $KIOSK_USER --noclear tty1 (in inittab/respawn)"
    warn "  Its login runs ~$KIOSK_USER/.bash_profile, which execs the SOC session."
  fi
else
  log "INSTALL_MODE=desktop — leaving the boot/default target + getty untouched"
  log "  launch the wall from the 'SOC Video Wall' desktop icon, or:"
  log "  $([ "$HAS_SYSTEMD" = 1 ] && echo "systemctl start soc-wall" || echo "$SOC_ROOT/scripts/launcher.sh")"
  log "  (re-run with INSTALL_MODE=kiosk for a dedicated tty1-autologin appliance)"

  # Auto-launch the control center when running in a graphical session so the
  # operator sees the app immediately after install (no hunting through menus).
  if [ "$ACTIVATE" != "1" ] && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] \
     && [ -x "$SOC_ROOT/scripts/soc-wall-menu" ]; then
    log "  launching the SOC Video Wall control center now…"
    SOC_ROOT="$SOC_ROOT" "$SOC_ROOT/scripts/soc-wall-menu" 9>&- &
  fi
fi

# kernel console blanking off (Raspberry Pi). Track whether WE added it so
# uninstall.sh only strips it back out if this install introduced it.
if [ -f /boot/firmware/cmdline.txt ] && ! grep -q consoleblank /boot/firmware/cmdline.txt; then
  sed -i 's/$/ consoleblank=0/' /boot/firmware/cmdline.txt
  DID_CONSOLEBLANK=1
  CONSOLEBLANK_NOW=1
fi

# --------------------------------------------------------------------------- #
# Install manifest + revert state for uninstall.sh. Simple line format:
#   TYPE|VALUE|NOTE
# TYPE is one of: META, DIR, FILE, UNIT, USER, SYSCHANGE, REVERT. Idempotent —
# rewritten in full on every run. uninstall.sh reads REVERT lines to restore the
# default systemd target and (only if WE added it) the consoleblank cmdline flag.
# By convention uninstall.sh PRESERVES operator data (users, $ETC secrets,
# /var/lib/vaultwarden) unless run with --purge; the manifest tags those rows so
# it knows what to keep.
log "Recording install manifest at $ETC/.install-manifest"
HOME_DIR_M="$(getent passwd "$KIOSK_USER" 2>/dev/null | cut -d: -f6)"
{
  printf 'META|version|1\n'
  printf 'META|date|%s\n' "$(date -Is 2>/dev/null || date 2>/dev/null || echo unknown)"
  printf 'META|install_mode|%s\n' "$INSTALL_MODE"
  printf 'META|arch|%s\n' "$ARCH"
  printf 'META|session|%s\n' "$SESSION"
  printf 'META|vw_mode|%s\n' "$VW_MODE"
  printf 'META|harden|%s\n' "$HARDEN"
  printf 'META|kiosk_user|%s\n' "$KIOSK_USER"
  printf 'META|desktop_user|%s\n' "$DESKTOP_USER"
  printf 'META|svc_user|%s\n' "$SVC_USER"
  printf 'META|has_systemd|%s\n' "$HAS_SYSTEMD"
  printf 'META|tarpit|%s\n' "$SOC_TARPIT_ENABLE"
  printf 'META|keep_services|%s\n' "$SOC_KEEP_SERVICES"
  printf 'META|skip_packages|%s\n' "$SOC_SKIP_PACKAGES"

  # users (PRESERVE on plain uninstall; --purge removes). Every created user MUST
  # be recorded so uninstall removes it (+ its home) — no orphans.
  printf 'USER|%s|kiosk user (preserve unless --purge)\n' "$KIOSK_USER"
  printf 'USER|%s|desktop-mode user (preserve unless --purge)\n' "$DESKTOP_USER"
  printf 'USER|%s|service user (preserve unless --purge)\n' "$SVC_USER"
  printf 'USER|%s|redeploy git user (preserve unless --purge)\n' "$UPDATE_USER"
  [ "$VW_MODE" = "native" ] && printf 'USER|%s|vaultwarden user (preserve unless --purge)\n' vaultwarden
  # NOTE: the desktop user's home is removed by `userdel -r` when the USER row is
  # purged — we deliberately DON'T emit a DIR row for it (uninstall.sh's DIR
  # handler treats an unknown DIR as the project root and would mis-target it).

  # deployed trees + config (config dir holds secrets -> preserve unless --purge)
  printf 'DIR|%s|project root (remove on uninstall)\n' "$SOC_ROOT"
  printf 'META|releases|%s\n' "$RELEASES"
  printf 'DIR|%s|config + sealed secrets (preserve unless --purge)\n' "$ETC"
  [ "$VW_MODE" = "native" ] && printf 'DIR|%s|vaultwarden data (preserve unless --purge)\n' /var/lib/vaultwarden

  # files on PATH / shared trees
  printf 'FILE|/usr/local/bin/litebw|litebw launcher (remove on uninstall)\n'
  if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
    printf 'FILE|/usr/local/bin/soc-wall|native wall launcher (remove on uninstall)\n'
  fi
  printf 'FILE|/usr/local/bin/soc-update|redeploy command link (remove on uninstall)\n'
  [ "$VW_MODE" = "native" ] && \
    printf 'FILE|/usr/local/bin/vaultwarden.lock-stamp|pinned Vaultwarden record (remove on uninstall)\n'
  # deploy-time SHA-256 manifest (drift detection) lives under $ETC but is install
  # metadata, not operator data -> always remove on uninstall (even keep-data).
  printf 'FILE|%s/manifest.json|deploy file-hash manifest (remove on uninstall)\n' "$ETC"
  # sudoers drop-in: only listed when actually installed (visudo-validated).
  [ "$SUDOERS_INSTALLED" = "1" ] && \
    printf 'FILE|/etc/sudoers.d/soc-wall-restart|soc -> systemctl restart vpn/tunnel/tarpit (remove on uninstall)\n'
  # tarpit.env is install metadata (the arm-flag), seeded only with SOC_TARPIT_ENABLE=1.
  [ "$SOC_TARPIT_ENABLE" = "1" ] && \
    printf 'FILE|%s/tarpit.env|tarpit arm-flag (remove on uninstall)\n' "$ETC"
  [ -n "$DESKTOP_FILE" ] && printf 'FILE|%s|XDG desktop launcher (rebrand-generated; remove on uninstall)\n' "$DESKTOP_FILE"
  [ -n "$ICON_FILE" ]    && printf 'FILE|%s|app icon (remove on uninstall)\n' "$ICON_FILE"
  # branding source lives under $ETC -> operator data, preserved unless --purge
  [ -n "$BRANDING_FILE" ] && printf 'FILE|%s|branding source (preserve unless --purge; edit to rebrand)\n' "$BRANDING_FILE"

  # systemd units (and any drop-ins/configs we dropped). Listed regardless of
  # enabled-state; uninstall.sh disables+removes them.
  if [ "$HAS_SYSTEMD" = "1" ]; then
    printf 'UNIT|vaultwarden.service|%s\n' "$([ "$VW_MODE" = native ] && echo "/etc/systemd/system/vaultwarden.service" || echo "docker-run unit")"
    printf 'UNIT|autossh-tunnel.service|/etc/systemd/system/autossh-tunnel.service\n'
    printf 'UNIT|forti-vpn.service|/etc/systemd/system/forti-vpn.service\n'
    printf 'UNIT|soc-tarpit.service|/etc/systemd/system/soc-tarpit.service\n'
    printf 'UNIT|soc-wall.service|/etc/systemd/system/soc-wall.service\n'
    printf 'UNIT|soc-update.timer|/etc/systemd/system/soc-update.timer\n'
    printf 'UNIT|soc-update.service|/etc/systemd/system/soc-update.service\n'
    printf 'FILE|/etc/tmpfiles.d/soc-wall.conf|heartbeat run dir (remove on uninstall)\n'
    if [ "$INSTALL_MODE" = "kiosk" ]; then
      printf 'UNIT|soc-firstboot.service|/etc/systemd/system/soc-firstboot.service\n'
      printf 'FILE|/etc/systemd/system/getty@tty1.service.d/override.conf|tty1 autologin drop-in (kiosk)\n'
      printf 'FILE|/etc/systemd/system.conf.d/10-soc-watchdog.conf|hardware watchdog (kiosk)\n'
    fi
    [ "$HARDEN" = "1" ] && printf 'UNIT|nftables.service|enabled by HARDEN=1\n'
    printf 'FILE|/etc/sysctl.d/99-soc.conf|sysctl tuning (remove on uninstall)\n'
    printf 'FILE|/etc/systemd/zram-generator.conf|zram config (remove on uninstall)\n'
    printf 'FILE|/etc/systemd/journald.conf.d/10-soc.conf|journald cap (remove on uninstall)\n'
    printf 'FILE|/etc/systemd/coredump.conf.d/10-soc.conf|coredump off (remove on uninstall)\n'
  fi
  if [ "$HARDEN" = "1" ]; then
    printf 'FILE|/etc/nftables.conf|firewall (HARDEN=1; review before removing)\n'
    # sshd drop-in: only recorded when it survived `sshd -t` (or sshd was absent).
    [ "${SSHD_INSTALLED:-0}" = "1" ] && \
      printf 'FILE|/etc/ssh/sshd_config.d/10-soc-hardening.conf|sshd hardening (HARDEN=1)\n'
    # (D) modprobe blacklist: plain /etc file -> reversed by the generic FILE loop.
    [ "${MODPROBE_INSTALLED:-0}" = "1" ] && \
      printf 'FILE|/etc/modprobe.d/soc-blacklist.conf|USB/DMA module blacklist (HARDEN=1)\n'
    # (E) /tmp fstab hardening: an in-place edit, NOT a removable file. Recorded as
    # a REVERT row so uninstall.sh strips the tagged block from /etc/fstab.
    [ "${FSTAB_HARDENED:-0}" = "1" ] && \
      printf 'REVERT|fstab_tmp_harden|1\n'
  fi

  # other system changes touched in place (NOT owned by us — informational only)
  [ "$FAMILY" = "debian" ] && printf 'SYSCHANGE|/etc/X11/Xwrapper.config|allowed_users=console (edited in place)\n'

  # revert state for uninstall.sh
  printf 'REVERT|orig_default_target|%s\n' "${ORIG_DEFAULT_TARGET:-unknown}"
  printf 'REVERT|did_set_default|%s\n' "$DID_SET_DEFAULT"
  printf 'REVERT|did_consoleblank|%s\n' "$DID_CONSOLEBLANK"
  printf 'REVERT|cmdline_path|%s\n' "/boot/firmware/cmdline.txt"
  printf 'REVERT|trimmed_units|%s\n' "$TRIMMED_UNITS"
  [ -n "$HOME_DIR_M" ] && printf 'SYSCHANGE|%s|kiosk session dotfiles (.bash_profile/.xinitrc/.config/openbox)\n' "$HOME_DIR_M"
  [ -n "$DESKTOP_HOME" ] && printf 'SYSCHANGE|%s|desktop-user .config/soc-display (per-user appearance/branding)\n' "$DESKTOP_HOME"
} > "$ETC/.install-manifest.new" 2>/dev/null || warn "could not write $ETC/.install-manifest"
# A redeploy skips the hardening block, so its own rows don't record what the full
# install did. Keep every earlier row and only add what is new (e.g. a new unit).
if [ "$ACTIVATE" = "1" ] && [ -f "$ETC/.install-manifest" ]; then
  awk -F'|' 'NR==FNR { if ($2 == "trimmed_units") next; seen[$1 "|" $2]=1; print; next }
             !(($1 "|" $2) in seen)' \
    "$ETC/.install-manifest" "$ETC/.install-manifest.new" > "$ETC/.install-manifest.merged" \
    && mv -f "$ETC/.install-manifest.merged" "$ETC/.install-manifest.new"
fi
mv -f "$ETC/.install-manifest.new" "$ETC/.install-manifest" 2>/dev/null || true
chmod 0644 "$ETC/.install-manifest" 2>/dev/null || true

# --------------------------------------------------------------------------- #
# Stamp a successful full install so re-runs + `setup.py deploy` can fast-path
# the package step (skip unless --fresh).
printf 'installed=%s arch=%s session=%s mode=%s\n' \
  "$(date -Is 2>/dev/null || date 2>/dev/null || echo unknown)" "$ARCH" "$SESSION" "$INSTALL_MODE" \
  > "$ETC/.installed" 2>/dev/null || true
[ "$ACTIVATE" = "1" ] || printf '%s\n' "$DEPS_REV" > "$ETC/.deps-rev" 2>/dev/null || true

# The boot mutation + its REVERT rows + the success stamp are all on disk now —
# disarm the scoped boot-rollback trap so a normal exit doesn't undo the takeover.
trap - ERR EXIT

# Everything worked, so the pre-release-layout tree is no longer needed.
[ -n "$LEGACY_TREE" ] && rm -rf "$LEGACY_TREE"

if [ "$ACTIVATE" = "1" ]; then
  log "Release activated: $(readlink -f "$SOC_ROOT")"
  exit 0
fi

if [ -x "$SOC_ROOT/bin/soc-wall" ]; then
  SETUP_CMD="$SOC_ROOT/bin/soc-wall setup"
else
  SETUP_CMD="python3 $SOC_ROOT/setup.py"
fi

cat <<EOF

$(printf '\033[32mInstall complete.\033[0m')  One step left:

  sudo $SETUP_CMD deploy

It asks for your panels and logins once, creates the vault account, seals the
master password and brings the wall up. After that nothing needs a person: the
wall starts at boot, repairs itself, and redeploys itself from the tracked branch
(see $SOC_ROOT/docs/AUTO_UPDATE.md). For a scripted install, use
  sudo $SETUP_CMD deploy --unattended --master-fd N    (see docs/DEPLOY.md).

$(if [ "$INSTALL_MODE" = "kiosk" ]; then printf 'INSTALL_MODE=kiosk: the wall owns tty1 from the next boot.'; else printf 'INSTALL_MODE=desktop: your DE/login manager is untouched. Launch the wall from the\n  "SOC Video Wall" desktop icon, or %s.\n  Re-run with INSTALL_MODE=kiosk for a dedicated tty1-autologin appliance.' "$([ "$HAS_SYSTEMD" = 1 ] && echo "systemctl start soc-wall" || echo "$SOC_ROOT/scripts/launcher.sh")"; fi)
$([ "$HAS_SYSTEMD" = 1 ] || printf '%s\n' "NOTE: no systemd here — see the warnings above for service supervision and tty1
      autologin, which you must wire into your init. Auto-redeploy needs systemd.")
Debugging: $([ "$HAS_SYSTEMD" = 1 ] && echo "journalctl -t soc-kiosk -f (host)  journalctl -u forti-vpn -f (VPN)  soc-update status" || echo "the launcher logs to stdout/syslog; run forti-vpn-connect.py in the foreground to watch it")
EOF
