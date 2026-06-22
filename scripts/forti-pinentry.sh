#!/usr/bin/env bash
# Minimal Assuan pinentry that feeds $SOC_VPN_PASSWORD to openfortivpn for
# unattended Fortinet login (openfortivpn --pinentry=...). It is the VPN twin of
# scripts/pinentry-vault.py (which feeds the vault master password to rbw).
#
# openfortivpn sends SETTITLE / SETDESC / SETKEYINFO / SETPROMPT then GETPIN; we
# answer OK to everything and return the (URI-escaped) FortiGate password on
# GETPIN. The password is the FortiGate account password that
# forti-vpn-connect.py read from the vault and exported into our environment — it
# is never placed on the command line and never written to disk.
set -u
printf 'OK Pleased to meet you\n'
while IFS= read -r line; do
  case "$line" in
    GETPIN*)
      enc=${SOC_VPN_PASSWORD//%/%25}
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
