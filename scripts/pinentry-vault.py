#!/usr/bin/env python3
"""
Assuan pinentry for rbw that returns the vault master password by UNSEALING the
host-bound secret (host/secretstore.py). This is what lets the wall self-unlock
Vaultwarden with no plaintext master password anywhere on disk (no .env).

rbw is pointed at it with:
    rbw config set pinentry /opt/soc-display/scripts/pinentry-vault.py

Production unseals the host-bound secret — there is no plaintext master anywhere
on disk. Only when nothing is sealed (dev / local seeding) does it fall back to
an explicit $SOC_VAULT_PASSWORD from the environment (never from prod soc.env).
"""
import os
import sys


def _master() -> str:
    # Resolve the master via the pluggable, universal source layer
    # (host.mastersource): SOC_MASTER_SOURCE = auto|sealed|secret-service|env.
    # 'auto' (default) tries the host-bound seal FIRST so a sealed wall never
    # reads a master from elsewhere, then the freedesktop Secret Service
    # (KWallet/GNOME-keyring/KeePassXC via secret-tool), then the dev-only
    # $SOC_VAULT_PASSWORD. So legacy rbw benefits from secret-service too.
    here = os.path.dirname(os.path.abspath(__file__))
    for base in (os.environ.get("SOC_ROOT", "/opt/soc-display"),
                 os.path.dirname(here)):
        cand = os.path.join(base, "kiosk-host")
        if os.path.isdir(cand):
            sys.path.insert(0, cand)
    try:
        from host import mastersource
        master = mastersource.get_master()
    except Exception as e:  # noqa: BLE001 — surface to rbw's stderr, fall through
        sys.stderr.write(f"pinentry-vault: {e}\n")
        # Last resort if mastersource cannot even be imported (dev / seeding only).
        master = os.environ.get("SOC_VAULT_PASSWORD", "")
    if not master:
        # An empty answer makes rbw fail with a generic decryption error that gives
        # the operator no idea WHY. rbw forwards pinentry stderr to the journal.
        sd = os.environ.get("SOC_SECRET_DIR") or "/etc/soc-display/secret"
        sys.stderr.write(
            f"pinentry-vault: no usable master (secret dir {sd}) — the vault "
            f"cannot be unlocked. If this box is new or was re-imaged, run:\n"
            f"    sudo python3 setup.py first-run\n"
            f"to seal the master password host-bound.\n")
    return master


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
