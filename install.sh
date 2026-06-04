#!/usr/bin/env bash
# =============================================================================
# SOC video-wall kiosk installer  —  Raspberry Pi OS (Bookworm, 64-bit)
# Idempotent: safe to re-run. Run as root:  sudo ./install.sh
#
# Knobs (env):
#   VW_MODE=docker|native   how to run Vaultwarden        (default: docker)
#   HARDEN=1                apply nftables + sshd hardening (default: off)
#   KIOSK_USER=soc          kiosk login user               (default: soc)
#   SVC_USER=socsvc         service user (autossh)         (default: socsvc)
#   SOC_ROOT=/opt/soc-display
# =============================================================================
set -euo pipefail

VW_MODE="${VW_MODE:-docker}"
HARDEN="${HARDEN:-0}"
KIOSK_USER="${KIOSK_USER:-soc}"
SVC_USER="${SVC_USER:-socsvc}"
SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
ETC="/etc/soc-display"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

log(){ printf '\033[36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m!!\033[0m %s\n' "$*"; }
die(){ printf '\033[31mEE\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"
command -v apt-get >/dev/null || die "this installer targets Raspberry Pi OS / Debian"

# --------------------------------------------------------------------------- #
log "Installing apt dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
PKGS=(
  xserver-xorg xinit x11-xserver-utils xserver-xorg-legacy
  openbox obconf
  wmctrl xdotool unclutter
  python3 python3-venv python3-gi gir1.2-gtk-3.0
  fonts-dejavu-core
  autossh rbw pinentry-tty
  curl ca-certificates jq
  systemd-zram-generator
)
# WebKit2 typelib: prefer 4.1 (Bookworm), fall back to 4.0
if apt-cache show gir1.2-webkit2-4.1 >/dev/null 2>&1; then
  PKGS+=(gir1.2-webkit2-4.1)
else
  PKGS+=(gir1.2-webkit2-4.0)
fi
[ "$HARDEN" = "1" ] && PKGS+=(nftables)
apt-get install -y -qq "${PKGS[@]}" || die "apt install failed"

# Chromium package name differs across releases
if ! command -v chromium >/dev/null 2>&1; then
  apt-get install -y -qq chromium 2>/dev/null || apt-get install -y -qq chromium-browser || \
    warn "could not install chromium (only needed for engine: chromium panels)"
fi

# --------------------------------------------------------------------------- #
log "Creating users ($KIOSK_USER kiosk, $SVC_USER service)"
if ! id "$KIOSK_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$KIOSK_USER"
fi
# kiosk user needs access to video/render/input/tty for X + GPU
usermod -aG video,render,input,tty,audio "$KIOSK_USER"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd -r -m -s /usr/sbin/nologin "$SVC_USER"
fi

# Allow non-root X on tty (Xorg.wrap)
if [ -f /etc/X11/Xwrapper.config ]; then
  sed -i 's/^allowed_users=.*/allowed_users=anybody/' /etc/X11/Xwrapper.config || true
  grep -q '^needs_root_rights' /etc/X11/Xwrapper.config || echo "needs_root_rights=yes" >>/etc/X11/Xwrapper.config
else
  printf 'allowed_users=anybody\nneeds_root_rights=yes\n' >/etc/X11/Xwrapper.config
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

log "Creating Python venv"
if [ ! -x "$SOC_ROOT/.venv/bin/python" ]; then
  python3 -m venv --system-site-packages "$SOC_ROOT/.venv"
fi
"$SOC_ROOT/.venv/bin/pip" install -q --upgrade pip
"$SOC_ROOT/.venv/bin/pip" install -q PyYAML websocket-client

# --------------------------------------------------------------------------- #
log "Setting up $ETC (config + secrets)"
mkdir -p "$ETC" "$ETC/keys"
install_template(){  # src dst mode owner
  if [ -f "$2" ]; then warn "keep existing $2"; else
    cp "$1" "$2"; chmod "$3" "$2"; chown "$4" "$2"; log "created $2"; fi
}
install_template "$SOC_ROOT/config/panels.yaml"          "$ETC/panels.yaml"      0644 "root:root"
install_template "$SOC_ROOT/config/soc.env.example"      "$ETC/soc.env"          0640 "root:$KIOSK_USER"
install_template "$SOC_ROOT/config/vaultwarden.env.example" "$ETC/vaultwarden.env" 0640 "root:root"
chmod 0750 "$ETC/keys"; chown "$SVC_USER:$SVC_USER" "$ETC/keys"
# soc.env is also read by the autossh service user
setfacl -m u:"$SVC_USER":r "$ETC/soc.env" 2>/dev/null || chmod 0644 "$ETC/soc.env"

# --------------------------------------------------------------------------- #
log "Vaultwarden ($VW_MODE)"
mkdir -p /var/lib/vaultwarden
if [ "$VW_MODE" = "docker" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    log "installing Docker"; curl -fsSL https://get.docker.com | sh
  fi
  docker pull vaultwarden/server:latest
  cp "$SOC_ROOT/systemd/vaultwarden-docker.service" /etc/systemd/system/vaultwarden.service
else
  if [ ! -x /usr/local/bin/vaultwarden ]; then
    warn "native mode: place the aarch64 vaultwarden binary at /usr/local/bin/vaultwarden"
    warn "(see https://github.com/dani-garcia/vaultwarden — build or fetch a static build)"
  fi
  id vaultwarden >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin vaultwarden
  chown -R vaultwarden:vaultwarden /var/lib/vaultwarden
  cp "$SOC_ROOT/systemd/vaultwarden.service" /etc/systemd/system/vaultwarden.service
fi

# --------------------------------------------------------------------------- #
log "Installing systemd services (vaultwarden, autossh-tunnel)"
cp "$SOC_ROOT/systemd/autossh-tunnel.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable vaultwarden.service
# enable the tunnel only if panels.yaml actually defines tunnels
if "$SOC_ROOT/.venv/bin/python" -c "import sys;sys.path.insert(0,'$SOC_ROOT/kiosk-host');from host import config;c=config.load('$ETC/panels.yaml');sys.exit(0 if any(p.mode=='tunnel' for p in c.panels) and c.tunnel.get('enabled',True) else 1)"; then
  systemctl enable autossh-tunnel.service
  log "autossh-tunnel enabled (tunnels configured)"
else
  systemctl disable autossh-tunnel.service 2>/dev/null || true
  warn "no tunnels in panels.yaml — autossh-tunnel left disabled"
fi

# --------------------------------------------------------------------------- #
log "Configuring zram + sysctl (1 GB headroom)"
cp "$SOC_ROOT/security/zram.conf" /etc/systemd/zram-generator.conf
cp "$SOC_ROOT/security/99-soc-sysctl.conf" /etc/sysctl.d/99-soc.conf
sysctl --system >/dev/null 2>&1 || true
systemctl daemon-reload

# --------------------------------------------------------------------------- #
log "Configuring kiosk session for $KIOSK_USER"
HOME_DIR="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$HOME_DIR/.config/openbox"
# rc.xml with the 2x2 placement rules from panels.yaml + detected resolution
RES_W=1920; RES_H=1080
cp "$SOC_ROOT/openbox/menu.xml"  "$HOME_DIR/.config/openbox/menu.xml"
cp "$SOC_ROOT/openbox/autostart" "$HOME_DIR/.config/openbox/autostart"
"$SOC_ROOT/.venv/bin/python" "$SOC_ROOT/scripts/gen-openbox-rc.py" \
  --panels "$ETC/panels.yaml" --template "$SOC_ROOT/openbox/rc.xml.tmpl" \
  --out "$HOME_DIR/.config/openbox/rc.xml" --width "$RES_W" --height "$RES_H"
cp "$SOC_ROOT/scripts/xinitrc" "$HOME_DIR/.xinitrc"
# auto-startx on tty1 login
cat > "$HOME_DIR/.bash_profile" <<EOF
export SOC_ROOT=$SOC_ROOT
if [ -z "\$DISPLAY" ] && [ "\$(tty)" = "/dev/tty1" ]; then
  exec startx -- -nocursor
fi
EOF
chown -R "$KIOSK_USER:$KIOSK_USER" "$HOME_DIR/.config" "$HOME_DIR/.xinitrc" "$HOME_DIR/.bash_profile"

log "Enabling tty1 autologin"
mkdir -p /etc/systemd/system/getty@tty1.service.d
sed "s/--autologin soc /--autologin $KIOSK_USER /" \
  "$SOC_ROOT/systemd/getty-autologin.conf" > /etc/systemd/system/getty@tty1.service.d/override.conf
systemctl set-default multi-user.target    # no desktop env; we run our own X
systemctl daemon-reload

# kernel console blanking off
if [ -f /boot/firmware/cmdline.txt ] && ! grep -q consoleblank /boot/firmware/cmdline.txt; then
  sed -i 's/$/ consoleblank=0/' /boot/firmware/cmdline.txt
fi

# --------------------------------------------------------------------------- #
if [ "$HARDEN" = "1" ]; then
  log "Applying hardening (nftables + sshd)"
  cp "$SOC_ROOT/security/nftables.conf" /etc/nftables.conf
  systemctl enable nftables.service
  warn "review /etc/nftables.conf (set ssh_admin_cidr) before 'systemctl start nftables'"
  install -d /etc/ssh/sshd_config.d
  cp "$SOC_ROOT/security/sshd_hardening.conf" /etc/ssh/sshd_config.d/10-soc-hardening.conf
  warn "sshd hardening installed (key-only). Ensure you have an authorized key before reboot!"
fi

# --------------------------------------------------------------------------- #
cat <<EOF

\033[32mInstall complete.\033[0m  Next steps:

  1. Edit $ETC/panels.yaml         -> your 4 panels (IPs, ports, selectors, vault_item, tunnel)
  2. Edit $ETC/soc.env             -> SOC_VAULT_PASSWORD + email/url (chmod 0640)
  3. Edit $ETC/vaultwarden.env     -> set ADMIN_TOKEN (vaultwarden hash)
  4. Start the vault:   systemctl start vaultwarden
     Create the kiosk account in the web vault (http://<pi>:8222 via SSH tunnel
     or temporarily on the LAN), add your 4 logins named to match vault_item.
  5. Tunnel key (if used): see $SOC_ROOT/security/tunnel_key.note
  6. Re-run openbox geometry if your monitor isn't 1920x1080:
       $SOC_ROOT/.venv/bin/python $SOC_ROOT/scripts/gen-openbox-rc.py \\
         --panels $ETC/panels.yaml --template $SOC_ROOT/openbox/rc.xml.tmpl \\
         --out $HOME_DIR/.config/openbox/rc.xml --width W --height H
  7. Reboot:  systemctl reboot

The wall comes up automatically on tty1 -> startx -> Openbox -> 4 logged-in panels.
EOF
