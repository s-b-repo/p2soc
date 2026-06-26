"""Round-trip lock between install.sh's manifest WRITER and uninstall.sh's READER.

install.sh records what it changed in a pipe-delimited manifest:
    TYPE|VALUE|NOTE   (TYPE in META|DIR|FILE|UNIT|USER|SYSCHANGE|REVERT)
uninstall.sh's parse_manifest() must read exactly that format and populate the
revert vars (boot target, getty/consoleblank flags, users, paths). The two
scripts drifted once (install wrote pipes, uninstall parsed `key=value`), which
silently disabled the entire manifest-driven revert. These tests feed a sample
install-format manifest through the REAL parse_manifest() extracted from
uninstall.sh and assert the parsed vars, so the format can never silently drift
again.

The sample manifests below mirror the rows install.sh emits (install.sh
"Recording install manifest" block); if you change the writer, change these and
the parser together — that is the whole point of this test.
"""
import os
import re
import subprocess

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_UNINSTALL = os.path.join(_REPO, "uninstall.sh")
_INSTALL = os.path.join(_REPO, "install.sh")

# A kiosk-mode, HARDEN=1, native-vaultwarden install manifest (the rows that
# matter for revert), exactly as install.sh writes them (pipe-delimited).
_KIOSK_MANIFEST = """\
META|version|1
META|install_mode|kiosk
META|vw_mode|native
META|harden|1
META|kiosk_user|kiosk
META|svc_user|svc2
USER|kiosk|kiosk user (preserve unless --purge)
USER|svc2|service user (preserve unless --purge)
USER|vaultwarden|vaultwarden user (preserve unless --purge)
DIR|/opt/soc-display|project root (remove on uninstall)
DIR|/etc/soc-display|config + sealed secrets (preserve unless --purge)
DIR|/var/lib/vaultwarden|vaultwarden data (preserve unless --purge)
FILE|/usr/local/bin/litebw|litebw launcher (remove on uninstall)
FILE|/etc/systemd/system/getty@tty1.service.d/override.conf|tty1 autologin drop-in (kiosk)
UNIT|vaultwarden.service|/etc/systemd/system/vaultwarden.service
REVERT|orig_default_target|graphical.target
REVERT|did_set_default|1
REVERT|did_consoleblank|1
REVERT|cmdline_path|/boot/firmware/cmdline.txt
"""

# A desktop-mode install: NO boot takeover, docker vault, no hardening.
_DESKTOP_MANIFEST = """\
META|version|1
META|install_mode|desktop
META|vw_mode|docker
META|harden|0
META|kiosk_user|soc
META|svc_user|socsvc
DIR|/opt/soc-display|project root (remove on uninstall)
DIR|/etc/soc-display|config + sealed secrets (preserve unless --purge)
REVERT|orig_default_target|graphical.target
REVERT|did_set_default|0
REVERT|did_consoleblank|0
REVERT|cmdline_path|/boot/firmware/cmdline.txt
"""


def _parse(manifest_text, tmp_path):
    """Run uninstall.sh's real parse_manifest() over a manifest and dump vars."""
    man = tmp_path / "manifest"
    man.write_text(manifest_text)
    # Extract the parse_manifest function body from uninstall.sh (first line that
    # is exactly `}` closes it) so the test exercises the production parser.
    extract = (
        r"""awk '/^parse_manifest\(\)\{/{f=1} f{print} f&&/^}$/{exit}' """
        + f'"{_UNINSTALL}"'
    )
    # Seed the same defaults uninstall.sh sets before parsing, then parse + print.
    script = f"""
set -euo pipefail
SOC_ROOT=/opt/soc-display; ETC=/etc/soc-display
KIOSK_USER=soc; SVC_USER=socsvc; VW_USER=vaultwarden; VW_DATA=/var/lib/vaultwarden
INSTALL_MODE=desktop; VW_MODE=docker; HARDEN=0
PREV_DEFAULT_TARGET=""; SET_DEFAULT_CHANGED=0; GETTY_OVERRIDE=0
CONSOLEBLANK_ADDED=0; CMDLINE_PATH=""
MANIFEST_FILES=(); MANIFEST_UNITS=()
eval "$({extract})"
parse_manifest "{man}"
for k in INSTALL_MODE VW_MODE HARDEN KIOSK_USER SVC_USER VW_USER SOC_ROOT \
         PREV_DEFAULT_TARGET SET_DEFAULT_CHANGED GETTY_OVERRIDE \
         CONSOLEBLANK_ADDED CMDLINE_PATH; do
  eval "printf '%s=%s\\n' \\"$k\\" \\"\\${{$k}}\\""
done
"""
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    res = {}
    for line in out.stdout.splitlines():
        k, _, v = line.partition("=")
        res[k] = v
    return res


def test_kiosk_manifest_round_trips(tmp_path):
    v = _parse(_KIOSK_MANIFEST, tmp_path)
    # Boot-takeover reversal must be armed from the manifest (the original bug:
    # these stayed 0 and the boot target was never restored).
    assert v["SET_DEFAULT_CHANGED"] == "1"
    assert v["PREV_DEFAULT_TARGET"] == "graphical.target"
    assert v["GETTY_OVERRIDE"] == "1"      # derived from the getty override FILE row
    assert v["CONSOLEBLANK_ADDED"] == "1"
    assert v["CMDLINE_PATH"] == "/boot/firmware/cmdline.txt"
    # Custom users + native vault must be honored (not the hardcoded defaults).
    assert v["KIOSK_USER"] == "kiosk"
    assert v["SVC_USER"] == "svc2"
    assert v["VW_MODE"] == "native"
    assert v["HARDEN"] == "1"
    assert v["INSTALL_MODE"] == "kiosk"


def test_desktop_manifest_no_takeover(tmp_path):
    v = _parse(_DESKTOP_MANIFEST, tmp_path)
    # Desktop mode never touched the boot — nothing to revert.
    assert v["SET_DEFAULT_CHANGED"] == "0"
    assert v["GETTY_OVERRIDE"] == "0"
    assert v["CONSOLEBLANK_ADDED"] == "0"
    assert v["INSTALL_MODE"] == "desktop"
    assert v["VW_MODE"] == "docker"
    assert v["HARDEN"] == "0"
    assert v["KIOSK_USER"] == "soc"


def test_uninstall_removes_every_installed_desktop_entry():
    """install/uninstall symmetry: every /usr/share/applications/*.desktop entry
    install.sh installs must have a matching rm_path in uninstall.sh's section-4
    removal block. Once asymmetric (soc-wall-setup.desktop was installed but never
    removed); now soc-wall.desktop is the SOLE advertised entry (the control center
    execs the setup/appearance scripts directly, no secondary entries). This guards
    the asymmetry from coming back for any desktop entry."""
    install_src = open(_INSTALL, encoding="utf-8").read()
    uninstall_src = open(_UNINSTALL, encoding="utf-8").read()
    # Destinations install.sh writes into the shared XDG applications dir.
    installed = set(
        re.findall(r"(/usr/share/applications/[\w.-]+\.desktop)", install_src)
    )
    assert installed, "expected install.sh to install at least one .desktop entry"
    removed = set(re.findall(r"rm_path\s+(\S+\.desktop)", uninstall_src))
    missing = installed - removed
    assert not missing, f"uninstall.sh never removes installed desktop entries: {sorted(missing)}"
    # The single advertised entry must be covered explicitly.
    assert "/usr/share/applications/soc-wall.desktop" in removed
    # The secondary setup/appearance entries were merged away — they must NOT be
    # installed (the control center execs the scripts directly).
    assert "/usr/share/applications/soc-wall-setup.desktop" not in installed
    assert "/usr/share/applications/soc-wall-appearance.desktop" not in installed


def test_pipe_format_is_not_parsed_as_key_value(tmp_path):
    """Regression guard: the old reader used IFS='=' and matched nothing. Confirm
    the pipe rows actually move the vars off their defaults (i.e. the parser sees
    the format), not silently no-op the way the broken version did."""
    v = _parse(_KIOSK_MANIFEST, tmp_path)
    # If the parser were still IFS='=' / UPPER_CASE keys, every value would stay
    # at its seeded default; assert at least the install_mode flipped.
    assert v["INSTALL_MODE"] != "desktop"
