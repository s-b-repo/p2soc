#!/usr/bin/env bash
# Minimal Assuan pinentry that feeds $SOC_VAULT_PASSWORD to rbw for unattended
# unlock. rbw's agent inherits the environment it was started with, so
# SOC_VAULT_PASSWORD must be set when the agent first launches (systemd
# EnvironmentFile=/etc/soc-display/soc.env handles this on the Pi).
#
# Security: this enables a powered-on kiosk to self-unlock the vault. Keep
# soc.env on tmpfs, mode 0600. For higher security set SOC_VAULT_INTERACTIVE=1
# and unlock manually after each reboot.
set -u
printf 'OK Pleased to meet you\n'
while IFS= read -r line; do
  case "$line" in
    GETPIN*)
      enc=${SOC_VAULT_PASSWORD//%/%25}
      enc=${enc//$'\n'/%0A}
      enc=${enc//$'\r'/%0D}
      printf 'D %s\n' "$enc"
      printf 'OK\n'
      ;;
    BYE*)
      printf 'OK\n'
      exit 0
      ;;
    *)
      printf 'OK\n'
      ;;
  esac
done
