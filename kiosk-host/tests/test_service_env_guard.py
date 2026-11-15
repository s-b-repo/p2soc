"""Lock the env-file source guard in the systemd service entry scripts.

autossh-tunnel.sh and forti-vpn.sh run `set -euo pipefail` and then source the
kiosk env file. They must guard that source with `-r` (readable), not `-f`
(exists): the env file is 0640 root:soc and the service may run as an unprivileged
user, so an existing-but-unreadable file with a `-f` test would still attempt the
`. "$ENV_FILE"` and abort the whole unit under `set -e` before the tunnel/VPN ever
starts. The clickable launchers already use `-r`; these two service scripts must
match so the guard can't silently drift back to `-f`.
"""
import os
import re

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SERVICE_SCRIPTS = ("scripts/autossh-tunnel.sh", "scripts/forti-vpn.sh")


def test_service_scripts_use_readable_guard_under_set_e():
    for rel in _SERVICE_SCRIPTS:
        with open(os.path.join(_REPO, rel), encoding="utf-8") as fh:
            text = fh.read()
        # The script must opt into `set -e` (the foot-gun being guarded against)
        assert re.search(r"^set -euo pipefail$", text, re.MULTILINE), rel
        # ... and the env-file source must be gated on readability, not mere
        # existence, so a non-readable env file cannot abort the unit.
        assert '[ -r "$ENV_FILE" ]' in text, rel
        assert '[ -f "$ENV_FILE" ]' not in text, rel


def test_launcher_uses_readable_guard():
    # launcher.sh supervises the kiosk host and sources the same env file. It
    # runs under `set -u` (no `-e`), so a present-but-unreadable env file with a
    # `-f` guard would not abort but would silently drop the vault creds/ports.
    # Gate the source on readability (`-r`) for parity with the clickable
    # launchers and the service scripts, and keep that guard from drifting back
    # to `-f` under a future copy-paste into a `set -e` context.
    with open(os.path.join(_REPO, "scripts/launcher.sh"), encoding="utf-8") as fh:
        text = fh.read()
    assert '[ -r "$ENV_FILE" ]' in text
    assert '[ -f "$ENV_FILE" ]' not in text
