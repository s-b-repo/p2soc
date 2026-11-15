"""Lock the install-root fallback in the litebw shell launcher.

scripts/litebw is installed to /usr/local/bin/litebw (nfpm + install.sh), so
when an operator runs the documented `litebw unlock` from a plain shell the
wrapper self-locates ROOT as dirname(dirname($0)) -> /usr/local, which has no
kiosk-host. Without a fallback, PYTHONPATH becomes /usr/local/kiosk-host and
`python -m host.litebw` dies with ModuleNotFoundError. The wrapper must fall
back to the install root (SOC_ROOT, default /opt/soc-display) when the
self-located ROOT has no kiosk-host, mirroring soc-wall-menu et al.
"""
import os

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_LAUNCHER = os.path.join(_REPO, "scripts", "litebw")


def test_litebw_launcher_falls_back_to_install_root():
    with open(_LAUNCHER, encoding="utf-8") as fh:
        text = fh.read()
    # Self-located ROOT (dirname(dirname($0))) is /usr/local when deployed, so
    # the launcher must drop to the install root when ROOT/kiosk-host is absent,
    # defaulting to /opt/soc-display and honouring SOC_ROOT when set.
    assert '[ -d "$ROOT/kiosk-host" ] || ROOT="${SOC_ROOT:-/opt/soc-display}"' in text
