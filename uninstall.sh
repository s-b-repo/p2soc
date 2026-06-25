#!/usr/bin/env bash
# =============================================================================
# SOC video-wall kiosk uninstaller — cleanly reverses ./install.sh.
#
# Manifest-driven: install.sh records what it changed in $ETC/.install-manifest
# (paths, users, the saved default systemd target, whether it flipped the boot
# target / wrote the getty override / touched cmdline.txt). This script reads
# that manifest when present and falls back to the known default paths otherwise,
# so it still does the right thing on an install that predates the manifest.
#
# PRESERVES operator data by default. The users + their homes, /etc/soc-display
# (panels.yaml, soc.env, sealed secrets) and /var/lib/vaultwarden (the operator's
# vault) are kept unless you pass --purge. --purge asks for one explicit
# confirmation before it deletes anything irreversible.
#
# Idempotent: safe to re-run (every step tolerates already-gone state).
#
# Usage (run as root):
#   sudo ./uninstall.sh                 revert install, keep all operator data
#   sudo ./uninstall.sh --purge         also remove users, $ETC, the vault, image
#   sudo ./uninstall.sh --force         don't prompt before destructive steps
#   sudo ./uninstall.sh --purge --force unattended full wipe
#   sudo ./uninstall.sh --help
# =============================================================================
set -euo pipefail

PURGE=0
FORCE=0
for _a in "$@"; do
  case "$_a" in
    --purge)         PURGE=1 ;;
    --force|--yes|-y) FORCE=1 ;;
    -h|--help)
      sed -n '3,23p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) printf 'unknown option: %s (try --help)\n' "$_a" >&2; exit 2 ;;
  esac
done

log(){  printf '\033[36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m!!\033[0m %s\n' "$*"; }
die(){  printf '\033[31mEE\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./uninstall.sh)"

# A running record of everything we actually changed, printed as the summary.
DID=()
did(){ DID+=("$*"); }

confirm(){   # confirm "question" — true unless the operator declines (skipped by --force)
  [ "$FORCE" = "1" ] && return 0
  local ans
  read -r -p "$(printf '\033[33m??\033[0m %s [y/N]: ' "$1")" ans || ans=""
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  HAS_SYSTEMD=1
fi

# --------------------------------------------------------------------------- #
# Defaults (also the fallback when no manifest is present)
# --------------------------------------------------------------------------- #
SOC_ROOT="${SOC_ROOT:-/opt/soc-display}"
ETC="/etc/soc-display"
MANIFEST="$ETC/.install-manifest"
KIOSK_USER="soc"
SVC_USER="socsvc"
VW_USER="vaultwarden"
VW_DATA="/var/lib/vaultwarden"
INSTALL_MODE="desktop"
VW_MODE="docker"
HARDEN=0                   # installer applied nftables + sshd hardening
PREV_DEFAULT_TARGET=""     # saved original systemd default target (kiosk takeover)
SET_DEFAULT_CHANGED=0      # installer flipped the boot target
GETTY_OVERRIDE=0           # installer wrote the getty@tty1 autologin override
CONSOLEBLANK_ADDED=0       # installer appended consoleblank=0 to cmdline.txt
CMDLINE_PATH=""            # cmdline.txt path the installer touched
# Extra files/units the manifest lists for removal (collected generically so new
# install-created artifacts are reversed without editing this script every time).
MANIFEST_FILES=()
MANIFEST_UNITS=()

# --------------------------------------------------------------------------- #
# Load the manifest. install.sh writes pipe-delimited rows:
#   TYPE|VALUE|NOTE   where TYPE is META|DIR|FILE|UNIT|USER|SYSCHANGE|REVERT
# META/REVERT rows carry key|value pairs (VALUE=key, NOTE=value); the rest carry
# a path/name in VALUE. Parse them into the vars the steps below already use. The
# function is round-trip tested in kiosk-host/tests/test_uninstall_manifest.py.
# --------------------------------------------------------------------------- #
parse_manifest(){   # parse_manifest <manifest-path>
  local typ val note
  while IFS='|' read -r typ val note; do
    case "$typ" in ''|\#*) continue ;; esac
    case "$typ" in
      META)
        case "$val" in
          install_mode) INSTALL_MODE="$note" ;;
          vw_mode)      VW_MODE="$note" ;;
          kiosk_user)   KIOSK_USER="$note" ;;
          svc_user)     SVC_USER="$note" ;;
          harden)       HARDEN="$note" ;;
        esac ;;
      REVERT)
        case "$val" in
          orig_default_target) PREV_DEFAULT_TARGET="$note" ;;
          did_set_default)     SET_DEFAULT_CHANGED="$note" ;;
          did_consoleblank)    CONSOLEBLANK_ADDED="$note" ;;
          cmdline_path)        CMDLINE_PATH="$note" ;;
        esac ;;
      DIR)
        # the project root is the only DIR we remove wholesale; $ETC + vault data
        # are operator data handled by the keep-data / --purge logic below.
        case "$val" in
          /var/lib/vaultwarden) VW_DATA="$val" ;;
          *)
            if [ "$val" != "$ETC" ]; then SOC_ROOT="$val"; fi ;;
        esac ;;
      FILE)
        MANIFEST_FILES+=("$val")
        # the getty autologin drop-in is the kiosk-takeover marker
        case "$val" in
          */getty@tty1.service.d/override.conf) GETTY_OVERRIDE=1 ;;
        esac ;;
      UNIT)
        MANIFEST_UNITS+=("$val") ;;
      USER)
        case "$note" in
          *vaultwarden*) VW_USER="$val" ;;
        esac ;;
    esac
  done < "$1"
}

if [ -f "$MANIFEST" ]; then
  log "Reading install manifest: $MANIFEST"
  parse_manifest "$MANIFEST"
  # Belt-and-suspenders: even with a present-but-stale manifest, derive the
  # kiosk-takeover reversals from on-disk reality so the boot is always restored.
  [ -f "/etc/systemd/system/getty@tty1.service.d/override.conf" ] && GETTY_OVERRIDE=1
  if [ "$HAS_SYSTEMD" = "1" ] && [ "$SET_DEFAULT_CHANGED" != "1" ] \
     && [ "$(systemctl get-default 2>/dev/null || echo '')" = "multi-user.target" ] \
     && [ "$INSTALL_MODE" = "kiosk" ]; then
    SET_DEFAULT_CHANGED=1
  fi
else
  warn "no manifest at $MANIFEST — falling back to default paths."
  warn "  (an install before the manifest existed, or already partly removed.)"
  # Without a manifest we can't know whether the installer flipped the boot
  # target, but a kiosk install always did — restore graphical.target to be safe.
  GETTY_OVERRIDE=1
  SET_DEFAULT_CHANGED=1
fi

log "SOC video-wall uninstall — mode: $([ "$PURGE" = 1 ] && echo PURGE || echo keep-data)$([ "$FORCE" = 1 ] && echo ', non-interactive')"
log "  SOC_ROOT=$SOC_ROOT  ETC=$ETC  users: $KIOSK_USER/$SVC_USER"

if [ "$FORCE" != "1" ]; then
  confirm "Uninstall the SOC wall now?" || die "aborted — nothing changed"
fi

# --------------------------------------------------------------------------- #
# 1) systemd units — disable + remove
# --------------------------------------------------------------------------- #
UNITS=(soc-wall.service forti-vpn.service autossh-tunnel.service vaultwarden.service)
if [ "$HAS_SYSTEMD" = "1" ]; then
  log "Disabling + removing systemd units"
  for u in "${UNITS[@]}"; do
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
    if [ -f "/etc/systemd/system/$u" ]; then
      rm -f "/etc/systemd/system/$u"; did "removed unit $u"
    fi
  done
  systemctl daemon-reload || true
else
  warn "no systemd — remove any hand-wired service supervision yourself."
fi

# --------------------------------------------------------------------------- #
# 2) tty1 autologin override + restore the boot target (kiosk takeover)
# --------------------------------------------------------------------------- #
GETTY_DIR="/etc/systemd/system/getty@tty1.service.d"
if [ "$GETTY_OVERRIDE" = "1" ] && [ -f "$GETTY_DIR/override.conf" ]; then
  log "Removing tty1 autologin override"
  rm -f "$GETTY_DIR/override.conf"; did "removed getty@tty1 autologin override"
  rmdir "$GETTY_DIR" 2>/dev/null || true
fi

if [ "$HAS_SYSTEMD" = "1" ] && [ "$SET_DEFAULT_CHANGED" = "1" ]; then
  cur="$(systemctl get-default 2>/dev/null || echo '')"
  # Only restore if the installer's takeover target is still the active default —
  # don't clobber a deliberate operator change made after install.
  if [ "$cur" = "multi-user.target" ] || [ -z "$cur" ]; then
    restore="${PREV_DEFAULT_TARGET:-graphical.target}"
    log "Restoring default systemd target -> $restore"
    systemctl set-default "$restore" >/dev/null 2>&1 \
      && did "restored default target to $restore" \
      || warn "could not set default target to $restore"
  else
    log "default target is '$cur' (operator-set) — leaving it as-is"
  fi
fi

# --------------------------------------------------------------------------- #
# 3) cmdline.txt — remove the consoleblank=0 the installer appended
# --------------------------------------------------------------------------- #
CMDLINE="${CMDLINE_PATH:-/boot/firmware/cmdline.txt}"
if [ "$CONSOLEBLANK_ADDED" = "1" ] && [ -f "$CMDLINE" ] && grep -q 'consoleblank=0' "$CMDLINE"; then
  log "Removing consoleblank=0 from $CMDLINE"
  sed -i 's/ \{0,1\}consoleblank=0//g' "$CMDLINE"; did "reverted $CMDLINE (consoleblank)"
fi

# --------------------------------------------------------------------------- #
# 4) deployed files (non-data): code tree, launcher, desktop entry, drop-ins
# --------------------------------------------------------------------------- #
log "Removing deployed files"
rm_path(){   # remove a file/dir/symlink if present, and record it
  if [ -e "$1" ] || [ -L "$1" ]; then
    rm -rf "$1"; did "removed $1"
  fi
}

rm_path "$SOC_ROOT"
rm_path /usr/local/bin/litebw
rm_path /usr/share/applications/soc-wall.desktop
rm_path /usr/share/applications/soc-wall-setup.desktop
rm_path /usr/share/icons/hicolor/scalable/apps/soc-wall.svg
rm_path /etc/sysctl.d/99-soc.conf
rm_path /etc/systemd/zram-generator.conf
rm_path /etc/systemd/journald.conf.d/10-soc.conf
rm_path /etc/systemd/coredump.conf.d/10-soc.conf
# native Vaultwarden binary (install.sh extracts it to /usr/local/bin in VW_MODE=native)
[ "$VW_MODE" = "native" ] && rm_path /usr/local/bin/vaultwarden
# refresh the desktop database / icon cache if the tooling is around (best effort)
command -v update-desktop-database >/dev/null 2>&1 && \
  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true

# --------------------------------------------------------------------------- #
# 4a) HARDEN=1 reversal — nftables service/config + sshd hardening drop-in.
# These survive a normal uninstall otherwise; a key-only sshd drop-in left behind
# can lock an operator out. Gated on the manifest's harden flag.
# --------------------------------------------------------------------------- #
if [ "$HARDEN" = "1" ]; then
  log "Reverting HARDEN=1 artifacts (nftables + sshd hardening)"
  if [ "$HAS_SYSTEMD" = "1" ]; then
    systemctl disable --now nftables.service >/dev/null 2>&1 \
      && did "disabled nftables.service" || true
  fi
  # /etc/nftables.conf is a shared file the installer overwrote — don't silently
  # delete it; warn loudly that the SOC firewall ruleset remains in place.
  if [ -f /etc/nftables.conf ] && grep -qi 'soc wall firewall' /etc/nftables.conf 2>/dev/null; then
    warn "left /etc/nftables.conf in place (SOC firewall ruleset). Remove or replace"
    warn "  it by hand if you want stock firewalling back; nftables.service is disabled."
  fi
  if [ -f /etc/ssh/sshd_config.d/10-soc-hardening.conf ]; then
    rm_path /etc/ssh/sshd_config.d/10-soc-hardening.conf
    did "removed sshd hardening drop-in (sshd reverts to defaults on reload)"
    if [ "$HAS_SYSTEMD" = "1" ]; then
      systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true
    fi
    warn "sshd hardening removed — reloaded sshd (key-only login no longer forced)."
  fi
fi

if [ "$HAS_SYSTEMD" = "1" ]; then
  systemctl daemon-reload || true
  systemctl restart systemd-journald >/dev/null 2>&1 || true
fi
# re-apply sysctl so the kernel knobs the drop-in set go back to defaults on reboot
sysctl --system >/dev/null 2>&1 || true

# --------------------------------------------------------------------------- #
# 5) kiosk user's generated session files (NOT the home / account itself)
# --------------------------------------------------------------------------- #
KHOME="$(getent passwd "$KIOSK_USER" 2>/dev/null | cut -d: -f6)"
if [ -n "$KHOME" ] && [ -d "$KHOME" ]; then
  log "Removing generated session files in $KHOME"
  for f in .config/openbox .xinitrc .bash_profile; do
    rm_path "$KHOME/$f"
  done
fi

# --------------------------------------------------------------------------- #
# 5a) install bookkeeping — the .installed stamp + .install-manifest live inside
# $ETC (preserved data dir) but are install metadata, not operator secrets. On a
# keep-data uninstall remove them so a later reinstall doesn't fast-path the
# package step off a stale stamp and so no stale manifest lingers. (On --purge the
# whole $ETC goes anyway, below — and we've already parsed the manifest into vars.)
# --------------------------------------------------------------------------- #
if [ "$PURGE" != "1" ]; then
  rm_path "$ETC/.installed"
  rm_path "$ETC/.install-manifest"
fi

# --------------------------------------------------------------------------- #
# 6) PURGE — operator data (only with --purge, after an explicit confirm)
# --------------------------------------------------------------------------- #
if [ "$PURGE" = "1" ]; then
  warn "--purge will DELETE operator data: the $KIOSK_USER/$SVC_USER/$VW_USER users"
  warn "and homes, $ETC (panels.yaml, soc.env, SEALED SECRETS) and the vault at"
  warn "$VW_DATA. This is IRREVERSIBLE."
  if confirm "Purge all operator data + accounts now?"; then
    # Docker Vaultwarden container/image (best effort, only when docker present)
    if [ "$VW_MODE" = "docker" ] && command -v docker >/dev/null 2>&1; then
      log "Removing Vaultwarden Docker container + image"
      docker rm -f soc-vaultwarden vaultwarden >/dev/null 2>&1 || true
      docker rmi vaultwarden/server:latest >/dev/null 2>&1 || true
      did "removed Vaultwarden Docker container/image (best effort)"
    fi
    rm_path "$ETC"
    rm_path "$VW_DATA"
    for u in "$KIOSK_USER" "$SVC_USER" "$VW_USER"; do
      if id "$u" >/dev/null 2>&1; then
        userdel -r "$u" >/dev/null 2>&1 \
          && did "deleted user $u (and home)" \
          || { userdel "$u" >/dev/null 2>&1 && did "deleted user $u (home kept)" \
               || warn "could not delete user $u (still logged in?)"; }
      fi
    done
  else
    warn "purge declined — operator data preserved."
  fi
else
  log "Preserving operator data (use --purge to remove):"
  log "  users $KIOSK_USER/$SVC_USER/$VW_USER, $ETC, vault $VW_DATA"
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
printf '\n\033[32mUninstall complete.\033[0m\n'
if [ "${#DID[@]}" -eq 0 ]; then
  echo "  (nothing to do — already removed.)"
else
  echo "  Reverted:"
  for d in "${DID[@]}"; do echo "    - $d"; done
fi
if [ "$PURGE" != "1" ]; then
  echo
  echo "  Operator data was KEPT. To remove it too: sudo ./uninstall.sh --purge"
fi
if [ "$HAS_SYSTEMD" = "1" ] && [ "$SET_DEFAULT_CHANGED" = "1" ]; then
  echo "  Reboot to return to your normal desktop/login manager."
fi
