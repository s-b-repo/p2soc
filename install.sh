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
#   INSTALL_MODE=desktop|kiosk how the wall starts             (default: desktop)
#                             desktop = deploy everything but DON'T touch the boot
#                             (your DE/login manager keeps working; launch the wall
#                             from the desktop icon or `systemctl start soc-wall`).
#                             kiosk   = dedicated appliance: enable tty1 autologin +
#                             `systemctl set-default multi-user.target`.
#   VW_MODE=docker|native     how to run Vaultwarden           (default: docker)
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
#   SOC_ROOT=/opt/soc-display
# =============================================================================
set -euo pipefail

SESSION_WAS_SET="${SESSION+yes}"
SESSION="${SESSION:-auto}"
VW_MODE="${VW_MODE:-docker}"
HARDEN="${HARDEN:-0}"
SSH_ADMIN_CIDR="${SSH_ADMIN_CIDR:-}"
KIOSK_USER="${KIOSK_USER:-soc}"
DESKTOP_USER="${DESKTOP_USER:-socwall}"
SVC_USER="${SVC_USER:-socsvc}"
COMPOSITOR="${COMPOSITOR:-labwc}"
# desktop (default): deploy everything but DON'T hijack the boot — the existing
# DE/login manager keeps working; the wall launches via the desktop icon or
# `systemctl start soc-wall`. kiosk: the tty1 takeover (autologin + multi-user
# default target) for a dedicated SOC-wall appliance.
INSTALL_MODE="${INSTALL_MODE:-desktop}"
# scanner-deception tarpit on :80 — installed always, ENABLED only when opted in.
SOC_TARPIT_ENABLE="${SOC_TARPIT_ENABLE:-0}"
# HARDEN sub-knobs: per-item opt-OUT for the physical-attack-surface hardening so
# an operator can keep nftables/sshd hardening but skip module-blacklist / fstab.
SOC_SKIP_MODPROBE="${SOC_SKIP_MODPROBE:-0}"
SOC_SKIP_FSTAB="${SOC_SKIP_FSTAB:-0}"
SKIP_PACKAGES="${SOC_SKIP_PACKAGES:-0}"
DEPS_ONLY=0
FRESH="${SOC_FRESH:-0}"
for _a in "$@"; do
  [ "$_a" = "--deps-only" ] && DEPS_ONLY=1
  [ "$_a" = "--fresh" ] && FRESH=1
done
SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
ETC="/etc/soc-display"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCH="$(uname -m)"

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
case "$SESSION" in auto|wayland|xwayland|xlibre|xorg|x11) ;; *)
  die "SESSION must be auto|wayland|xwayland|xlibre|xorg|x11 (got '$SESSION')";; esac
case "$INSTALL_MODE" in desktop|kiosk) ;; *)
  die "INSTALL_MODE must be desktop|kiosk (got '$INSTALL_MODE')";; esac

# systemd is preferred but not required — degrade gracefully without it.
HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  HAS_SYSTEMD=1
else
  warn "no running systemd detected — will deploy files + scripts but NOT install"
  warn "services or tty autologin. See the end-of-run notes for the manual steps."
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
             curl ca-certificates autossh openfortivpn ppp)
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
             curl ca-certificates autossh openfortivpn ppp)
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
             curl ca-certificates autossh openfortivpn ppp)
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
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xorg-x11-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(unclutter dejavu-fonts pinentry)
    PK_ZRAM=()
    PK_SECRETTOOL=(libsecret-tools)
    ;;
  alpine)
    PK_CORE=(python3 py3-gobject3 gtk+3.0 webkit2gtk-4.1
             curl ca-certificates autossh openfortivpn ppp)
    PK_XSRV=(xorg-server)
    PK_X11=(xinit openbox)
    PK_WAYLAND=(cage)
    PK_TOOLS=(xrandr xset font-dejavu pinentry)
    PK_ZRAM=()
    PK_SECRETTOOL=(libsecret)
    ;;
  void)
    PK_CORE=(python3 python3-gobject gtk+3 webkit2gtk
             curl ca-certificates autossh openfortivpn ppp)
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
# The chosen compositor (default labwc) leads the Wayland set unless skipping.
[ -n "$COMPOSITOR" ] && PK_WAYLAND=("$COMPOSITOR" "${PK_WAYLAND[@]}")

x_server_present(){ command -v Xorg >/dev/null 2>&1 || command -v X >/dev/null 2>&1; }

install_x_server(){   # honour an existing X.Org/XLibre; else install one
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
if [ "$FRESH" != "1" ] && [ "$SKIP_PACKAGES" != "1" ] && [ "$DEPS_ONLY" != "1" ] \
   && [ -f "$ETC/.installed" ]; then
  log "Existing install detected ($ETC/.installed) — skipping OS package install"
  log "  (pass --fresh or SOC_FRESH=1 to reinstall/upgrade packages)"
  SKIP_PACKAGES=1
fi

log "Refreshing package metadata"
pm_refresh

log "Installing core dependencies (python/GTK/WebKit, autossh, openfortivpn)"
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
  log "dependencies installed (--deps-only) — done."
  exit 0
fi

# --------------------------------------------------------------------------- #
log "Creating users ($KIOSK_USER kiosk, $DESKTOP_USER desktop, $SVC_USER service)"
# Both the kiosk + desktop users are created REGARDLESS of INSTALL_MODE so a box
# can switch modes later without re-provisioning; only the mode's user gets the
# tty1-autologin/session wiring (below). All three are unprivileged.
if ! id "$KIOSK_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$KIOSK_USER"
fi
# kiosk user needs video/render/input/tty/seat — it OWNS tty1 (its own session).
for grp in video render input tty audio seat; do
  getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$KIOSK_USER" || true
done
if ! id "$DESKTOP_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$DESKTOP_USER"
fi
# desktop user runs the wall windowed INSIDE the operator's already-running DE
# session, so it needs GPU/input access but NOT tty/seat takeover.
for grp in video render input audio; do
  getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$DESKTOP_USER" || true
done
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd -r -m -s "$(command -v nologin || echo /usr/sbin/nologin)" "$SVC_USER"
fi

# Debian's Xorg wrapper forbids non-console X by default (startx on tty needs this)
if [ "$FAMILY" = "debian" ]; then
  if [ -f /etc/X11/Xwrapper.config ]; then
    sed -i 's/^allowed_users=.*/allowed_users=anybody/' /etc/X11/Xwrapper.config || true
    grep -q '^needs_root_rights' /etc/X11/Xwrapper.config || \
      echo "needs_root_rights=yes" >>/etc/X11/Xwrapper.config
  else
    printf 'allowed_users=anybody\nneeds_root_rights=yes\n' >/etc/X11/Xwrapper.config
  fi
fi

# --------------------------------------------------------------------------- #
log "Installing project to $SOC_ROOT"
mkdir -p "$SOC_ROOT"
# copy everything except dev runtime / venv / git
tar -C "$SRC_DIR" \
    --exclude='.git' --exclude='.venv' --exclude='dev/run' --exclude='__pycache__' \
    -cf - . | tar -C "$SOC_ROOT" -xf -
chown -R root:root "$SOC_ROOT"
chmod +x "$SOC_ROOT"/scripts/*.sh "$SOC_ROOT"/scripts/*.py 2>/dev/null || true
# the bundled iNode SSL-VPN client (vendor/) — its connect script + helpers
chmod +x "$SOC_ROOT"/vendor/iNode-VPN-Client/svpn-connect.sh \
         "$SOC_ROOT"/vendor/iNode-VPN-Client/scripts/* 2>/dev/null || true

# litebw launcher onto PATH — pure-Python Vaultwarden client (replaces rbw).
# It execs `python -m host.litebw` from $SOC_ROOT; deployed under scripts/.
install -d -m 0755 /usr/local/bin
install -m 0755 "$SOC_ROOT/scripts/litebw" /usr/local/bin/litebw

# Deploy-time manifest: record every shipped file's sha256 + the source commit.
# The wall reads /etc/soc-display/manifest.json at boot and warns in the top bar
# if anything has drifted (tampered install, ad-hoc edit on the Pi). We hash
# SOC_ROOT (the deployed tree) AND write a `.commit` sentinel into SOC_ROOT so
# the manifest CLI can refresh it later (after a manual `rsync … /opt/soc-display/`)
# without losing the source-commit anchor. Best-effort: if python3 / git aren't
# available yet, skip and the wall just won't show the drift warning.
log "Recording deploy manifest (file hashes + source commit)"
if command -v python3 >/dev/null 2>&1; then
  install -d -m 0755 "$ETC"
  # Capture the source commit from SRC_DIR (it has the .git checkout).
  src_commit="$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || true)"
  if [ -n "$src_commit" ]; then
    printf '%s\n' "$src_commit" > "$SOC_ROOT/.commit"
    chmod 0644 "$SOC_ROOT/.commit"
  fi
  # Write the manifest from SOC_ROOT (the deployed tree). _current_commit falls
  # back to SOC_ROOT/.commit when SOC_ROOT itself has no .git.
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

log "Creating Python venv"
if [ ! -x "$SOC_ROOT/.venv/bin/python" ]; then
  python3 -m venv --system-site-packages "$SOC_ROOT/.venv" || \
    die "python3 -m venv failed (on Debian: apt install python3-venv)"
fi
"$SOC_ROOT/.venv/bin/pip" install -q --upgrade pip
# PyYAML + websocket-client + cryptography are all REQUIRED: cryptography seals/
# unseals the host-bound vault master password (no plaintext .env) and writes the
# logins + config into Vaultwarden.
#
# `cryptography` (>=3.5) is a Rust extension. PyPI ships prebuilt aarch64 wheels
# (manylinux2014 arm64), but if pip can't match one it falls back to an sdist and
# tries to compile with rustc+cc — which needs a Rust toolchain AND ~1 GB+ RAM
# and reliably OOM-kills the 1 GB Pi 5. So FORBID the source build (--only-binary)
# and, if no wheel is found, fall back to the distro package (the venv is
# --system-site-packages, so a distro-installed cryptography is importable) rather
# than ever starting a rustc build. x86 dev is unaffected — the wheel is always
# present there.
crypto_distro_pkg(){
  case "$FAMILY" in
    debian)            echo python3-cryptography ;;
    fedora|suse)       echo python3-cryptography ;;
    arch)              echo python-cryptography ;;
    alpine)            echo py3-cryptography ;;
    void)              echo python3-cryptography ;;
    *)                 echo "" ;;
  esac
}
# Pure-Python deps first (these always have wheels / no toolchain).
"$SOC_ROOT/.venv/bin/pip" install -q PyYAML websocket-client \
  || die "pip install failed (PyYAML and websocket-client are required)"
# cryptography: wheel-only, never compile on the Pi.
if ! "$SOC_ROOT/.venv/bin/pip" install -q --only-binary=:all: cryptography; then
  warn "no prebuilt 'cryptography' wheel for this arch — trying the distro package"
  cpkg="$(crypto_distro_pkg)"
  if [ -n "$cpkg" ] && pm_try "$cpkg" && \
     "$SOC_ROOT/.venv/bin/python" -c 'import cryptography' 2>/dev/null; then
    log "cryptography provided by distro package '$cpkg' (via --system-site-packages)"
  else
    die "no prebuilt 'cryptography' wheel for $ARCH and no usable distro package.
   Install your distro's cryptography (e.g. ${cpkg:-python3-cryptography}) and re-run.
   Do NOT let pip build it from source on a 1 GB Pi — the rustc build OOMs."
  fi
fi

# --------------------------------------------------------------------------- #
log "Setting up $ETC (config + secrets)"
mkdir -p "$ETC" "$ETC/keys"
install_template(){  # src dst mode owner
  if [ -f "$2" ]; then warn "keep existing $2"; else
    cp "$1" "$2"; chmod "$3" "$2"; chown "$4" "$2"; log "created $2"; fi
}
install_template "$SOC_ROOT/config/panels.yaml"          "$ETC/panels.yaml"      0644 "root:root"
install_template "$SOC_ROOT/config/soc.env.example"      "$ETC/soc.env"          0640 "root:$KIOSK_USER"
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
# soc.env must be readable by BOTH the kiosk user (sources it at session start)
# and the autossh service user — but NEVER world-readable (it holds the vault
# email/URL, secret-dir path and config-item name). Prefer an ACL; if ACLs are
# unavailable, fall back to a shared group (add the service user to the kiosk
# user's group). The sealed-secret dir stays 0700, so this grants soc.env only.
if ! setfacl -m u:"$SVC_USER":r "$ETC/soc.env" 2>/dev/null; then
  warn "setfacl unavailable — granting $SVC_USER read on soc.env via group membership (not world-readable)"
  usermod -aG "$KIOSK_USER" "$SVC_USER" 2>/dev/null \
    || warn "could not add $SVC_USER to group $KIOSK_USER; autossh may not read soc.env"
  chown "root:$KIOSK_USER" "$ETC/soc.env"; chmod 0640 "$ETC/soc.env"
fi

# default the vault backend to litebw (pure-Python; rbw/dev stay selectable).
# The shipped soc.env.example already defaults to litebw; this only migrates a
# legacy 'rbw' default left in an existing soc.env (pre-litebw installs) and
# backfills a missing key — never clobbering an operator's explicit choice.
if grep -q '^SOC_VAULT_BACKEND=rbw[[:space:]]*$' "$ETC/soc.env"; then
  sed -i 's/^SOC_VAULT_BACKEND=rbw[[:space:]]*$/SOC_VAULT_BACKEND=litebw/' "$ETC/soc.env"
elif ! grep -q '^SOC_VAULT_BACKEND=' "$ETC/soc.env"; then
  printf '\n# vault backend: litebw (default) | rbw | dev\nSOC_VAULT_BACKEND=litebw\n' >> "$ETC/soc.env"
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
if [ "$VW_MODE" = "docker" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    log "installing Docker"
    case "$FAMILY" in
      arch)  pm_install docker ;;
      suse)  pm_install docker ;;
      *)     curl -fsSL https://get.docker.com | sh ;;
    esac
  fi
  [ "$HAS_SYSTEMD" = "1" ] && systemctl enable --now docker >/dev/null 2>&1 || true
  docker_pull_retry vaultwarden/server:latest \
    || die "could not pull vaultwarden/server:latest after 3 attempts — check network/DNS/registry reachability (Pi Wi-Fi may still be coming up), then re-run ./install.sh (it is idempotent)."
  # Verify the daemon resolved the correct multi-arch variant (do NOT force
  # --platform — that would break x86 dev). Warn-only; the image is multi-arch,
  # so a mismatch means a stale/side-loaded wrong-arch image that would only fail
  # at `docker run` mid-boot with a cryptic 'exec format error' (or run slowly
  # under qemu emulation). Surface it now, at install time.
  case "$ARCH" in
    aarch64|arm64) want_goarch=arm64 ;;
    x86_64|amd64)  want_goarch=amd64 ;;
    armv7l|armv6l) want_goarch=arm ;;
    *)             want_goarch= ;;
  esac
  img_goarch="$(docker image inspect --format '{{.Architecture}}' vaultwarden/server:latest 2>/dev/null || echo unknown)"
  if [ -n "$want_goarch" ] && [ "$img_goarch" != "$want_goarch" ]; then
    warn "Vaultwarden image arch '$img_goarch' != host '$want_goarch' — pulled wrong variant?"
    warn "  Run: docker rmi vaultwarden/server:latest && docker pull vaultwarden/server:latest"
  else
    log "Vaultwarden image arch: $img_goarch (matches host)"
  fi
  cp "$SOC_ROOT/systemd/vaultwarden-docker.service" /etc/systemd/system/vaultwarden.service
else
  if [ ! -x /usr/local/bin/vaultwarden ]; then
    # dani-garcia/vaultwarden publishes NO official static binaries — only
    # multi-arch container images. Compiling from source on a 1 GB Pi (Rust
    # toolchain) is unsupported here. Extract the arch-correct binary from the
    # official image when Docker is available; otherwise tell the operator how.
    warn "native mode: /usr/local/bin/vaultwarden is missing (host arch: $ARCH)"
    if command -v docker >/dev/null 2>&1; then
      log "extracting the $ARCH vaultwarden binary from vaultwarden/server:latest"
      docker pull vaultwarden/server:latest >/dev/null 2>&1 || true
      _vwcid="$(docker create vaultwarden/server:latest 2>/dev/null || true)"
      if [ -n "$_vwcid" ] && docker cp "$_vwcid:/vaultwarden" /usr/local/bin/vaultwarden 2>/dev/null; then
        chmod 0755 /usr/local/bin/vaultwarden
        log "installed /usr/local/bin/vaultwarden (arch-correct, from the official image)"
      else
        warn "could not extract the binary from the image — place an $ARCH vaultwarden"
        warn "binary at /usr/local/bin/vaultwarden by hand. Do NOT compile on the Pi."
      fi
      [ -n "$_vwcid" ] && docker rm "$_vwcid" >/dev/null 2>&1 || true
    else
      warn "no Docker to extract from. Get an $ARCH vaultwarden binary from the"
      warn "official multi-arch image (docker create vaultwarden/server:latest +"
      warn "docker cp <id>:/vaultwarden ...). Compiling on the 1 GB Pi is unsupported."
    fi
  fi
  id vaultwarden >/dev/null 2>&1 || \
    useradd -r -s "$(command -v nologin || echo /usr/sbin/nologin)" vaultwarden
  chown -R vaultwarden:vaultwarden /var/lib/vaultwarden
  cp "$SOC_ROOT/systemd/vaultwarden.service" /etc/systemd/system/vaultwarden.service
fi

# --------------------------------------------------------------------------- #
# has panels.yaml configured tunnels / a VPN? (used to enable services)
want_tunnel(){ "$SOC_ROOT/.venv/bin/python" -c "import sys;sys.path.insert(0,'$SOC_ROOT/kiosk-host');from host import config;c=config.load('$ETC/panels.yaml');sys.exit(0 if any(p.mode=='tunnel' for p in c.panels) and c.tunnel.get('enabled',True) else 1)"; }
# want_vpn: enable forti-vpn.service if ANY vpns[] entry is enabled + complete
# (the single unit fans out to N supervisors). Iterates conf.vpns so a multi-VPN
# config — or a legacy vpn:{} normalized to one entry — is handled the same way.
want_vpn(){ "$SOC_ROOT/.venv/bin/python" -c "import sys;sys.path.insert(0,'$SOC_ROOT/kiosk-host');from host import config
def complete(v):
    k=config.vpn_kind(v); fv=bool(v.get('config_from_vault'))
    if k in ('fortinet','inode'): return bool(v.get('gateway') and v.get('vault_item'))
    return bool(v.get('vault_item') if fv else v.get('config'))
vs=config.load('$ETC/panels.yaml').vpns or []
ok=any(isinstance(v,dict) and v.get('enabled') and complete(v) for v in vs)
sys.exit(0 if ok else 1)"; }

if [ "$HAS_SYSTEMD" = "1" ]; then
  log "Installing systemd services (vaultwarden, autossh-tunnel, forti-vpn, soc-wall, soc-tarpit)"
  cp "$SOC_ROOT/systemd/autossh-tunnel.service" /etc/systemd/system/
  cp "$SOC_ROOT/systemd/forti-vpn.service" /etc/systemd/system/
  # Scanner-deception tarpit on port 80. Installed but NEVER auto-enabled —
  # opt-in with: SOC_TARPIT_ENABLE=1 in $ETC/tarpit.env, then
  # `systemctl enable --now soc-tarpit`. See docs/SECURITY.md.
  cp "$SOC_ROOT/systemd/soc-tarpit.service" /etc/systemd/system/
  # Supervised kiosk session (env baked in, no soc.env) — setup.py regenerates it
  # with the wizard's values. Installed but NOT enabled: switching the boot from
  # getty-autologin to this service must be validated on the target display (see
  # the end-of-run notes), so we don't flip it automatically.
  [ -f /etc/systemd/system/soc-wall.service ] || \
    cp "$SOC_ROOT/systemd/soc-wall.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable vaultwarden.service
  if want_tunnel; then
    systemctl enable autossh-tunnel.service
    log "autossh-tunnel enabled (tunnels configured)"
  else
    systemctl disable autossh-tunnel.service 2>/dev/null || true
    warn "no tunnels in panels.yaml — autossh-tunnel left disabled"
  fi
  if want_vpn; then
    systemctl enable forti-vpn.service
    log "VPN service enabled (forti-vpn.service supervises Fortinet/OpenVPN/WireGuard)"
  else
    systemctl disable forti-vpn.service 2>/dev/null || true
    warn "no vpn in panels.yaml — VPN service left disabled"
  fi
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
log "Configuring kiosk session for $KIOSK_USER (SESSION=$SESSION)"
HOME_DIR="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
# Fail CLOSED if the home field came back empty or is not a real directory
# (NSS hiccup, a just-created account whose home isn't materialised yet, an
# account with no home). Without this guard the install -d / dotfile writes /
# chown -R below would target "/.config", "/.xinitrc", etc. — corrupting the
# filesystem root and chowning root-level paths to the kiosk user.
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || \
  die "kiosk user '$KIOSK_USER' has no valid home directory (got '${HOME_DIR:-<empty>}') — refusing to write session dotfiles to the filesystem root. Check the account (getent passwd $KIOSK_USER) and re-run ./install.sh (it is idempotent)."
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$HOME_DIR/.config/openbox"
# rc.xml with the grid placement rules from panels.yaml. 1920x1080 is only the
# install-time default: xinitrc regenerates it from xrandr at every X session
# start (display.auto), and wayland-session.sh does the same for labwc.
RES_W=1920; RES_H=1080
cp "$SOC_ROOT/openbox/menu.xml"  "$HOME_DIR/.config/openbox/menu.xml"
cp "$SOC_ROOT/openbox/autostart" "$HOME_DIR/.config/openbox/autostart"
"$SOC_ROOT/.venv/bin/python" "$SOC_ROOT/scripts/gen-openbox-rc.py" \
  --panels "$ETC/panels.yaml" --template "$SOC_ROOT/openbox/rc.xml.tmpl" \
  --out "$HOME_DIR/.config/openbox/rc.xml" --width "$RES_W" --height "$RES_H"
cp "$SOC_ROOT/scripts/xinitrc" "$HOME_DIR/.xinitrc"
# session dispatcher on tty1 login (picks X11/Wayland per SOC_SESSION)
cat > "$HOME_DIR/.bash_profile" <<EOF
export SOC_ROOT=$SOC_ROOT
if [ -z "\$DISPLAY" ] && [ -z "\$WAYLAND_DISPLAY" ] && [ "\$(tty)" = "/dev/tty1" ]; then
  exec $SOC_ROOT/scripts/start-session.sh
fi
EOF
chown -R "$KIOSK_USER:$KIOSK_USER" "$HOME_DIR/.config" "$HOME_DIR/.xinitrc" "$HOME_DIR/.bash_profile"

# Desktop-mode user: seed a per-user .config dir (so appearance/branding persist
# per-user when the wall runs windowed) but DON'T touch tty1/the boot — it starts
# on demand inside the operator's DE session. Recorded as a SYSCHANGE below.
DESKTOP_HOME="$(getent passwd "$DESKTOP_USER" 2>/dev/null | cut -d: -f6)"
if [ -n "$DESKTOP_HOME" ]; then
  install -d -o "$DESKTOP_USER" -g "$DESKTOP_USER" "$DESKTOP_HOME/.config/soc-display"
fi

# Capture the original default target BEFORE we touch it, so uninstall.sh can
# restore it (only meaningful with systemd). The actual boot takeover (set-default
# + getty override + consoleblank) is DEFERRED to immediately before the manifest
# write further down, so any earlier failure (docker pull, venv/pip, hardening,
# sshd validation) exits with the boot target UNCHANGED — never a dark/unbootable
# box mid-install. This capture must stay BEFORE that deferred set-default.
ORIG_DEFAULT_TARGET=""
if [ "$HAS_SYSTEMD" = "1" ]; then
  ORIG_DEFAULT_TARGET="$(systemctl get-default 2>/dev/null || true)"
fi
# Boot-takeover state flags (mutated only by the deferred block before the manifest).
DID_SET_DEFAULT=0
DID_CONSOLEBLANK=0

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

if [ -f "$SOC_ROOT/soc-wall.desktop" ] || [ -x "$VENV_PY" ]; then
  log "Installing desktop launcher (rebrand-aware app entry + icon)"
  install -d -m 0755 /usr/share/applications
  # GENERATE the entry from branding (run from kiosk-host so `host` is importable;
  # SOC_BRANDING_FILE points at the just-installed source so operator edits win).
  if [ -x "$VENV_PY" ] && SOC_ROOT="$SOC_ROOT" SOC_BRANDING_FILE="${BRANDING_FILE:-$SOC_ROOT/branding/branding.yaml}" \
       PYTHONPATH="$SOC_ROOT/kiosk-host" "$VENV_PY" -m host.branding desktop \
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
    [ -x "$VENV_PY" ] && BRAND_ICON="$(SOC_ROOT="$SOC_ROOT" \
      SOC_BRANDING_FILE="${BRANDING_FILE:-$SOC_ROOT/branding/branding.yaml}" \
      PYTHONPATH="$SOC_ROOT/kiosk-host" "$VENV_PY" -c \
      'from host import branding; print(branding.icon_path())' 2>/dev/null || true)"
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
if [ "$HARDEN" = "1" ]; then
  log "Applying hardening (nftables + sshd)"
  cp "$SOC_ROOT/security/nftables.conf" /etc/nftables.conf

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
trap '_rc=$?; trap - ERR EXIT; if [ "$_rc" -ne 0 ] && [ "${DID_SET_DEFAULT:-0}" = 1 ] && [ -n "$ORIG_DEFAULT_TARGET" ]; then systemctl set-default "$ORIG_DEFAULT_TARGET" >/dev/null 2>&1 || true; fi; if [ "$_rc" -ne 0 ] && [ "${DID_CONSOLEBLANK:-0}" = 1 ]; then sed -i "s/ consoleblank=0//" /boot/firmware/cmdline.txt 2>/dev/null || true; fi; exit $_rc' ERR EXIT

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
    systemctl set-default multi-user.target    # no desktop env; we run our own session
    DID_SET_DEFAULT=1
    systemctl daemon-reload
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
fi

# kernel console blanking off (Raspberry Pi). Track whether WE added it so
# uninstall.sh only strips it back out if this install introduced it.
if [ -f /boot/firmware/cmdline.txt ] && ! grep -q consoleblank /boot/firmware/cmdline.txt; then
  sed -i 's/$/ consoleblank=0/' /boot/firmware/cmdline.txt
  DID_CONSOLEBLANK=1
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

  # users (PRESERVE on plain uninstall; --purge removes). Every created user MUST
  # be recorded so uninstall removes it (+ its home) — no orphans.
  printf 'USER|%s|kiosk user (preserve unless --purge)\n' "$KIOSK_USER"
  printf 'USER|%s|desktop-mode user (preserve unless --purge)\n' "$DESKTOP_USER"
  printf 'USER|%s|service user (preserve unless --purge)\n' "$SVC_USER"
  [ "$VW_MODE" = "native" ] && printf 'USER|%s|vaultwarden user (preserve unless --purge)\n' vaultwarden
  # NOTE: the desktop user's home is removed by `userdel -r` when the USER row is
  # purged — we deliberately DON'T emit a DIR row for it (uninstall.sh's DIR
  # handler treats an unknown DIR as the project root and would mis-target it).

  # deployed trees + config (config dir holds secrets -> preserve unless --purge)
  printf 'DIR|%s|project root (remove on uninstall)\n' "$SOC_ROOT"
  printf 'DIR|%s|config + sealed secrets (preserve unless --purge)\n' "$ETC"
  [ "$VW_MODE" = "native" ] && printf 'DIR|%s|vaultwarden data (preserve unless --purge)\n' /var/lib/vaultwarden

  # files on PATH / shared trees
  printf 'FILE|/usr/local/bin/litebw|litebw launcher (remove on uninstall)\n'
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
    [ "$INSTALL_MODE" = "kiosk" ] && \
      printf 'FILE|/etc/systemd/system/getty@tty1.service.d/override.conf|tty1 autologin drop-in (kiosk)\n'
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
  [ "$FAMILY" = "debian" ] && printf 'SYSCHANGE|/etc/X11/Xwrapper.config|allowed_users=anybody (edited in place)\n'

  # revert state for uninstall.sh
  printf 'REVERT|orig_default_target|%s\n' "${ORIG_DEFAULT_TARGET:-unknown}"
  printf 'REVERT|did_set_default|%s\n' "$DID_SET_DEFAULT"
  printf 'REVERT|did_consoleblank|%s\n' "$DID_CONSOLEBLANK"
  printf 'REVERT|cmdline_path|%s\n' "/boot/firmware/cmdline.txt"
  [ -n "$HOME_DIR_M" ] && printf 'SYSCHANGE|%s|kiosk session dotfiles (.bash_profile/.xinitrc/.config/openbox)\n' "$HOME_DIR_M"
  [ -n "$DESKTOP_HOME" ] && printf 'SYSCHANGE|%s|desktop-user .config/soc-display (per-user appearance/branding)\n' "$DESKTOP_HOME"
} > "$ETC/.install-manifest" 2>/dev/null || warn "could not write $ETC/.install-manifest"
chmod 0644 "$ETC/.install-manifest" 2>/dev/null || true

# --------------------------------------------------------------------------- #
# Stamp a successful full install so re-runs + `setup.py deploy` can fast-path
# the package step (skip unless --fresh).
printf 'installed=%s arch=%s session=%s mode=%s\n' \
  "$(date -Is 2>/dev/null || date 2>/dev/null || echo unknown)" "$ARCH" "$SESSION" "$INSTALL_MODE" \
  > "$ETC/.installed" 2>/dev/null || true

# The boot mutation + its REVERT rows + the success stamp are all on disk now —
# disarm the scoped boot-rollback trap so a normal exit doesn't undo the takeover.
trap - ERR EXIT

cat <<EOF

$(printf '\033[32mInstall complete.\033[0m')  Next steps:

  0. Easiest: run the guided menu ->  python3 $SOC_ROOT/setup.py
     (Deploy / Clean deploy / Configure / First-time setup / Diagnose / Repair)
  1. Edit $ETC/panels.yaml         -> your panels (IPs, ports, selectors, vault_item, tunnel, vpn)
     (or let the wizard write it; the config is then pushed into Vaultwarden as
      the 'SOC Wall Config' note — the wall's source of truth at boot)
  2. Edit $ETC/soc.env             -> email/url + SOC_SESSION (NON-SECRET; the
     master password is NOT here — it is sealed at first-run, step 3).
  3. First-time setup: python3 $SOC_ROOT/setup.py first-run
     -> generates a ONE-TIME PIN + seals the master password host-bound (no
        plaintext .env), and points the vault backend (litebw by default) at
        pinentry-vault.py. Record the PIN.
  4. Vaultwarden config is in its systemd unit (no .env). /admin is off; to create
     the account, temporarily allow signups (systemctl edit vaultwarden ->
     Environment=SIGNUPS_ALLOWED=true), restart, create it, then revert.
  5. Start the vault:   $([ "$HAS_SYSTEMD" = 1 ] && echo "systemctl start vaultwarden" || echo "(start vaultwarden via your init)")
     Create the kiosk account in the web vault (http://<host>:8222 via SSH tunnel
     or temporarily on the LAN), add your logins named to match vault_item.
     If using the Fortinet VPN, also add a login named to match vpn.vault_item
     (FortiGate username + password) — see docs/CONFIGURATION.md (vpn section).
     If using a proxy with auth, add a login for it and set proxy.vault_item.
  6. Tunnel key (if used): see $SOC_ROOT/security/tunnel_key.note
  7. Reboot:  $([ "$HAS_SYSTEMD" = 1 ] && echo "systemctl reboot" || echo "reboot")
$([ "$HAS_SYSTEMD" = 1 ] || printf '%s\n' "  NOTE: no systemd here — see the warnings above for service supervision +")
$([ "$HAS_SYSTEMD" = 1 ] || printf '%s\n' "        tty1 autologin you must wire into your init before the wall starts.")

$(if [ "$INSTALL_MODE" = "kiosk" ]; then printf 'The wall comes up automatically on tty1 -> %s -> logged-in panels.' "$([ "$SESSION" = x11 ] && echo "startx -> Openbox" || echo "cage/labwc (Wayland)")"; else printf 'INSTALL_MODE=desktop: your DE/login manager is untouched. Launch the wall from\n  the "SOC Video Wall" desktop icon, or %s. Re-run with\n  INSTALL_MODE=kiosk for a dedicated tty1-autologin appliance.' "$([ "$HAS_SYSTEMD" = 1 ] && echo "systemctl start soc-wall" || echo "$SOC_ROOT/scripts/launcher.sh")"; fi)
Debugging: $([ "$HAS_SYSTEMD" = 1 ] && echo "journalctl -t soc-kiosk -f (host)  journalctl -u forti-vpn -f (VPN)" || echo "the launcher logs to stdout/syslog; run forti-vpn-connect.py in the foreground to watch it")
EOF
