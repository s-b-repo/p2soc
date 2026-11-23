#!/usr/bin/env bash
# =============================================================================
# launch.sh — first-time bring-up + launch of the SOC video wall.
#
#   ./launch.sh              Open the wall in a desktop window.
#   ./launch.sh --headless   Run the WebKit and Settings smoke tests in Xvfb.
#   ./launch.sh --setup      Open the terminal setup menu.
#   ./launch.sh --pi         Install the wall and open the configuration wizard.
#   ./launch.sh --help       Show these commands.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"

MODE="dev-window"
for a in "$@"; do
  case "$a" in
    --headless)               MODE="headless" ;;
    --setup)                  MODE="setup" ;;
    --pi|--prod|--production)  MODE="pi" ;;
    -h|--help) sed -n '5,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

log(){  printf '\033[36m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m!!\033[0m %s\n' "$*"; }

. "$ROOT/scripts/soc-native.sh"
if [ "${SOC_LEGACY_PYTHON:-0}" != 1 ]; then
  if ! NATIVE="$(soc_native_path "$ROOT")"; then
    log "Building the native SOC Wall"
    make rust-release
    NATIVE="$(soc_native_path "$ROOT")"
  fi
  export SOC_ROOT="$ROOT"
  case "$MODE" in
    pi)
      if [ "$(id -u)" -eq 0 ]; then
        exec "$NATIVE" setup install --target pi
      fi
      exec sudo "$NATIVE" setup install --target pi ;;
    setup) exec "$NATIVE" setup ;;
  esac
  if [ "$MODE" = headless ] || { [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; }; then
    if [ -d "$ROOT/rust/crates/soc-wall/tests" ]; then
      exec xvfb-run -a cargo test --manifest-path rust/Cargo.toml --locked -p soc-wall --test gui_smoke --test settings_smoke
    fi
    exec "$NATIVE" check "$ROOT/config/panels.yaml"
  fi
  export SOC_VAULT_BACKEND="${SOC_VAULT_BACKEND:-dev}" SOC_WINDOW_MODE=window
  export SOC_PANELS_FILE="${SOC_PANELS_FILE:-$ROOT/config/presets/empty.yaml}"
  exec "$NATIVE" with-env run
fi

# ---- production: delegate to the full deploy flow --------------------------
if [ "$MODE" = "pi" ]; then
  log "Production first-time deploy -> setup.py deploy"
  if [ "$(id -u)" -eq 0 ]; then exec python3 setup.py deploy
  else exec sudo python3 setup.py deploy; fi
fi

# ---- 1. Python venv (created on first run) ---------------------------------
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  log "Creating the Python venv (.venv) + installing deps"
  python3 -m venv --system-site-packages "$ROOT/.venv" \
    || { warn "python3 -m venv failed — on Debian: apt install python3-venv"; exit 1; }
  "$PY" -m pip install -q --upgrade pip
  "$PY" -m pip install -q PyYAML websocket-client \
    || warn "pip install had problems (PyYAML/websocket-client)"
  # cryptography is a Rust extension — wheel-only so pip never starts a rustc+cc
  # sdist build that OOMs the 1 GB Pi. install.sh has the distro-package fallback;
  # this boot entrypoint just refuses the source build (x86 dev always has a wheel).
  "$PY" -m pip install -q --only-binary=:all: cryptography \
    || warn "no prebuilt cryptography wheel — run install.sh (it falls back to the distro package; never compile on the Pi)"
else
  log "venv present (.venv)"
fi

# ---- guided setup only -----------------------------------------------------
if [ "$MODE" = "setup" ]; then
  log "Opening the setup.py menu"
  exec python3 setup.py
fi

# ---- 2. dev vault (JSON backend; no Vaultwarden needed) --------------------
if [ "${SOC_VAULT_BACKEND:-dev}" = "dev" ] && [ ! -f "$ROOT/dev/run/dev-vault.json" ]; then
  log "Seeding the dev vault (dev/run/dev-vault.json)"
  make dev-vault >/dev/null
fi

# ---- 3. launch -------------------------------------------------------------
have_display(){ [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; }

if [ "$MODE" = "headless" ] || ! have_display; then
  [ "$MODE" = "headless" ] || warn "no display detected — running the headless check instead"
  log "Headless end-to-end check (Xvfb + screenshot) -> make verify"
  exec make verify
fi

log "Launching the wall in a window (Xephyr). Ctrl-C to stop."
exec bash dev/run-wall.sh
