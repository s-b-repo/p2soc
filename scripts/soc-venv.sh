#!/usr/bin/env bash
# =============================================================================
# soc-venv.sh <release-dir> [releases-dir]
#
# Give a release its Python environment. Venvs are SHARED between releases and
# keyed by (requirements.txt + interpreter version + arch), so an update that
# does not change dependencies reuses the existing venv: no network, no pip run
# and no SD-card churn. A dependency change builds a new venv alongside the old
# one, so rolling back never has to rebuild anything.
#
#   <release-dir>/.venv -> <releases-dir>/venv-<hash>
#
# A half-built venv can never be picked up: a venv counts only once its .complete
# marker exists, which is written after its imports have been proven.
#
# Exit codes: 0 ok | 1 failed | 3 no cryptography wheel for this arch (install.sh
# reacts by installing the distro package and retrying).
# =============================================================================
set -euo pipefail

RELEASE="${1:?usage: soc-venv.sh <release-dir> [releases-dir]}"
RELEASES="${2:-$(dirname "$(readlink -f "$RELEASE")")}"
REQ="$RELEASE/requirements.txt"
PY="${SOC_PYTHON:-$(command -v python3)}"

[ -f "$REQ" ] || { echo "soc-venv: no $REQ" >&2; exit 1; }

key="$( { cat "$REQ"; "$PY" -c 'import platform,sys;print(sys.version_info[:2],platform.machine())'; } \
        | sha256sum | cut -c1-12 )"
VENV="$RELEASES/venv-$key"

proves_imports(){ "$1/bin/python" -c 'import yaml, websocket, cryptography' >/dev/null 2>&1; }

if [ ! -f "$VENV/.complete" ] || ! proves_imports "$VENV"; then
  # Moved aside, not deleted: the running wall may use it, and the rebuild can fail.
  PREVIOUS=""
  if [ -e "$VENV" ]; then
    PREVIOUS="$VENV.previous.$$"
    mv "$VENV" "$PREVIOUS"
  fi
  restore(){ [ -z "$PREVIOUS" ] || { rm -rf "$VENV"; mv "$PREVIOUS" "$VENV"; }; }
  trap restore EXIT
  "$PY" -m venv --system-site-packages "$VENV" \
    || { echo "soc-venv: python3 -m venv failed (on Debian: apt install python3-venv)" >&2; exit 1; }
  # Pure-Python deps always have wheels and need no toolchain.
  "$VENV/bin/python" -m pip install -q --disable-pip-version-check PyYAML websocket-client \
    || { echo "soc-venv: pip install failed (PyYAML, websocket-client are required)" >&2; exit 1; }
  # cryptography is a Rust extension: never let pip fall back to a source build,
  # which needs a toolchain and over 1 GB of RAM and OOM-kills the Pi. A distro
  # package is importable through --system-site-packages, so accept that too.
  if ! "$VENV/bin/python" -c 'import cryptography' >/dev/null 2>&1; then
    "$VENV/bin/python" -m pip install -q --disable-pip-version-check \
        --only-binary=:all: cryptography \
      || { echo "soc-venv: no prebuilt cryptography wheel for this arch" >&2; exit 3; }
  fi
  proves_imports "$VENV" || { echo "soc-venv: venv $VENV failed its import check" >&2; exit 1; }
  touch "$VENV/.complete"
  trap - EXIT
  [ -z "$PREVIOUS" ] || rm -rf "$PREVIOUS"
fi

ln -sfn "$VENV" "$RELEASE/.venv"
echo "$VENV"
