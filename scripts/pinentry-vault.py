#!/usr/bin/env python3
"""
Assuan pinentry for rbw that returns the vault master password by UNSEALING the
host-bound secret (host/secretstore.py). This is what lets the wall self-unlock
Vaultwarden with no plaintext master password anywhere on disk (no .env).

rbw is pointed at it with:
    rbw config set pinentry /opt/soc-display/scripts/pinentry-vault.py

For dev / migration it falls back to $SOC_VAULT_PASSWORD when that is set.
"""
import os
import sys


def _master() -> str:
    pw = os.environ.get("SOC_VAULT_PASSWORD")
    if pw:
        return pw
    # find the host package: installed tree, then a source checkout
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (os.environ.get("SOC_ROOT", "/opt/soc-display"),
                 os.path.dirname(here)):
        cand = os.path.join(base, "kiosk-host")
        if os.path.isdir(cand):
            sys.path.insert(0, cand)
    try:
        from host import secretstore
        return secretstore.unseal()
    except Exception as e:  # noqa: BLE001 — surface to rbw's stderr, return empty
        sys.stderr.write(f"pinentry-vault: {e}\n")
        return ""


def _enc(s: str) -> str:
    return s.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D")


def main() -> int:
    out = sys.stdout
    out.write("OK Pleased to meet you\n")
    out.flush()
    secret = None
    for line in sys.stdin:
        cmd = line.strip().split(" ", 1)[0].upper()
        if cmd == "GETPIN":
            if secret is None:
                secret = _master()
            out.write(f"D {_enc(secret)}\n")
            out.write("OK\n")
            out.flush()
        elif cmd == "BYE":
            out.write("OK\n")
            out.flush()
            return 0
        else:
            out.write("OK\n")
            out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
