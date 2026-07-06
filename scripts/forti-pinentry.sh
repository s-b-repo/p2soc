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
      # Fail closed on an empty/unset password: answer Assuan ERR so openfortivpn
      # aborts the GETPIN instead of submitting a blank password (rapid
      # blank-password attempts can lock the FortiGate account). The :- default
      # also keeps `set -u` from crashing if the var is unset.
      if [ -z "${SOC_VPN_PASSWORD:-}" ]; then
        printf 'ERR 83886179 No password available\n'
      else
         enc=$(printf '%s' "$SOC_VPN_PASSWORD" | LC_ALL=C sed -z '
           s/%/%25/g
           s/\x0a/%0A/g
           s/\x0d/%0D/g
           s/\\/\\x5c/g
           s/\x00/\\x00/g
           s/\x01/\\x01/g
           s/\x02/\\x02/g
           s/\x03/\\x03/g
           s/\x04/\\x04/g
           s/\x05/\\x05/g
           s/\x06/\\x06/g
           s/\x07/\\x07/g
           s/\x08/\\x08/g
           s/\x09/\\x09/g
           s/\x0b/\\x0b/g
           s/\x0c/\\x0c/g
           s/\x0e/\\x0e/g
           s/\x0f/\\x0f/g
           s/\x10/\\x10/g
           s/\x11/\\x11/g
           s/\x12/\\x12/g
           s/\x13/\\x13/g
           s/\x14/\\x14/g
           s/\x15/\\x15/g
           s/\x16/\\x16/g
           s/\x17/\\x17/g
           s/\x18/\\x18/g
           s/\x19/\\x19/g
           s/\x1a/\\x1a/g
           s/\x1b/\\x1b/g
           s/\x1c/\\x1c/g
           s/\x1d/\\x1d/g
           s/\x1e/\\x1e/g
           s/\x1f/\\x1f/g
           s/\x7f/\\x7f/g
         ')
        printf 'D %s\n' "$enc"
        printf 'OK\n'
      fi
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
