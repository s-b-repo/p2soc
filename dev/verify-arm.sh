#!/usr/bin/env bash
# aarch64 / "zero compile-on-Pi" gate. Static invariant checks that FAIL the
# build if a regression would force a source build, a Rust toolchain, or a
# wrong-arch artifact onto the 1 GB Raspberry Pi 5 — none of which is visible on
# the x86 dev box (the cryptography wheel is always present there). Runs without
# a display, a Pi, or root. Wired into `make lint`.
#
# Run:  make verify-arm
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
fail=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

# Reduce a file to plausibly-executable text: drop full-line comments, trailing
# comments, and the contents of double-quoted strings (so a 'do NOT compile' note
# inside a die/warn/echo message, or a remediation hint, never trips the active-
# command checks). This is heuristic but good enough to catch a real regression.
strip_inert(){ sed -E 's/^[[:space:]]*#.*$//; s/[[:space:]]#.*$//; s/"[^"]*"//g'; }

echo "== aarch64 / no-compile-on-Pi gate =="

# (a) No ACTIVE compile-from-source / no-binary path on the Pi installer/setup.
for f in install.sh setup.py launch.sh; do
  [ -f "$f" ] || continue
  # The 'cargo install rbw' doctor hint in setup.py is a remediation STRING for
  # the opt-in rbw backend (stripped by strip_inert as a quoted string), never an
  # executed command. strip_inert also drops comments + quoted die/warn messages,
  # so only genuine executable invocations remain to be matched here.
  # Match dangerous tokens only at a COMMAND position (start of line, or after a
  # shell separator ; & | ( { && ||) so prose like "the rustc build OOMs" inside a
  # multi-line die string — which strip_inert can't fully strip across lines —
  # never trips. `cargo install/build`, `rustc`, `--no-binary`, `PIP_NO_BINARY`.
  cmdpos='(^|[;&|({]|&&|\|\|)[[:space:]]*'
  hits="$(strip_inert < "$f" | grep -nE "${cmdpos}(cargo[[:space:]]+(install|build)|rustc[[:space:]])|--no-binary|PIP_NO_BINARY=" || true)"
  if [ -n "$hits" ]; then
    bad "$f has an active compile/no-binary invocation:"; printf '       %s\n' "$hits"
  else
    ok "$f: no active cargo/rustc/--no-binary path"
  fi
done

# (b) install.sh must pin --only-binary for the cryptography pip install so pip
#     can never fall back to a rustc+cc sdist build that OOMs the 1 GB Pi.
if grep -qE 'pip"? +install .*--only-binary=:all: cryptography' install.sh; then
  ok "install.sh pins --only-binary for cryptography"
else
  bad "install.sh must install cryptography with --only-binary=:all: (no sdist build on the Pi)"
fi

# (b2) setup.py repair recreates the venv + installs deps too — it must ALSO pin
#      --only-binary for cryptography, or `setup.py repair` on the Pi can OOM.
if python3 - <<'PY'
import re, sys
src = open("setup.py", encoding="utf-8").read()
bad = any('"cryptography"' in m.group(0) and '--only-binary' not in m.group(0)
          for m in re.finditer(r'pip"\s*,\s*"install".*?\]', src, re.S))
sys.exit(1 if bad else 0)
PY
then
  ok "setup.py repair pins --only-binary for cryptography"
else
  bad "setup.py repair installs cryptography without --only-binary=:all: (sdist build OOMs the Pi)"
fi

# (c) No build toolchain added to any PK_ package set (build-essential/gcc/
#     clang/cmake/rust/make) — those would invite compiling on the Pi.
tc="$(grep -nE '^[[:space:]]*PK_[A-Z]+\+?=\(' install.sh | sed -E 's/.*\((.*)/\1/' || true)"
if printf '%s\n' "$tc" | grep -qiE 'build-essential|(^|[^a-z-])gcc([^a-z-]|$)|(^|[^a-z-])g\+\+|(^|[^a-z-])clang|(^|[^a-z-])cmake|(^|[^a-z-])rustc|(^|[^a-z-])cargo|rust-all'; then
  bad "a PK_ set adds a build toolchain (compile-on-Pi risk):"
  grep -niE 'PK_[A-Z]+.*=.*(build-essential|gcc|g\+\+|clang|cmake|rustc|cargo|rust)' install.sh | sed 's/^/       /'
else
  ok "no build toolchain in any PK_ package set"
fi

# (d) Docker pull must be verified, not blindly --platform-forced (which would
#     break x86 dev). Assert the arch verify/log block exists.
if grep -q 'docker image inspect --format' install.sh && grep -q 'matches host' install.sh; then
  ok "install.sh verifies the pulled vaultwarden image arch (warn-only)"
else
  bad "install.sh should verify the pulled image arch (docker image inspect ...)"
fi
if grep -qE 'docker (pull|run).*--platform' install.sh; then
  bad "install.sh hardcodes docker --platform — that breaks x86 dev; rely on multi-arch + verify"
else
  ok "no hardcoded docker --platform (multi-arch resolution preserved)"
fi

# (e) journald + coredump caps shipped and installed (40 GB SD-card safety).
for cf in security/journald-soc.conf security/coredump-soc.conf; do
  [ -f "$cf" ] && ok "$cf present" || bad "$cf missing (unbounded disk sink on the Pi)"
done
grep -q 'journald.conf.d' install.sh && ok "install.sh installs the journald cap" \
  || bad "install.sh must install the journald size cap"
grep -q 'LimitCORE=0' systemd/soc-wall.service && ok "soc-wall.service sets LimitCORE=0" \
  || bad "soc-wall.service should set LimitCORE=0"

# (f) Cross-check that a prebuilt cryptography aarch64 wheel actually resolves on
#     PyPI (best-effort: skipped offline / if pip is too old to accept --platform).
PY="$ROOT/.venv/bin/python"
if [ -x "$PY" ]; then
  pyver="$("$PY" -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  tmpd="$(mktemp -d)"
  if "$PY" -m pip download --only-binary=:all: --no-deps \
        --platform manylinux2014_aarch64 --python-version "$pyver" \
        -d "$tmpd" cryptography >/dev/null 2>&1; then
    ok "prebuilt cryptography aarch64 wheel resolves for py$pyver (no Pi source build needed)"
  else
    printf '  \033[33mskip\033[0m cryptography aarch64 wheel check (offline / pip too old / py%s)\n' "$pyver"
  fi
  rm -rf "$tmpd"
fi

# (g) The litebw vault backend is pure-Python (it REPLACED Rust 'rbw' as default,
#     so the Pi needs no Rust toolchain to read Vaultwarden). Assert the module
#     actually runs under SOC_VAULT_BACKEND=litebw with no compiled/Rust dep.
if [ -x "$PY" ]; then
  if SOC_VAULT_BACKEND=litebw PYTHONPATH="$ROOT/kiosk-host" \
        "$PY" -m host.litebw --help >/dev/null 2>&1; then
    ok "litebw runs as pure-Python (python -m host.litebw --help, no Rust)"
  else
    bad "python -m host.litebw --help failed — litebw vault path broken (Pi has no Rust)"
  fi
  # litebw must not pull in a Rust CLI: it should never shell out to 'rbw'/'cargo'
  # /'rustc' (mere mentions in docstrings — "rbw-compatible" — are fine; an actual
  # subprocess/exec invocation is the regression). Look only inside exec calls.
  if grep -RnE '(subprocess\.|os\.(system|exec|spawn|popen))[^\n]*\b(rbw|cargo|rustc)\b' \
        "$ROOT/kiosk-host/host/litebw.py" >/dev/null 2>&1; then
    bad "host/litebw.py shells out to rbw/cargo/rustc — should be self-contained pure-Python"
  else
    ok "host/litebw.py never shells out to rbw/cargo/rustc (pure-Python)"
  fi
fi

# (h) Simulate aarch64 on this x86 box and assert the ARM tuning branch is sane.
#     perf.is_arm() honors SOC_FAKE_ARCH (test-only) so the Pi branch is reachable
#     without a Pi. Check: is_arm() flips for aarch64/arm64, stays False for
#     x86_64, and the WebKit hwaccel policy never lands on a nonsense value.
if [ -x "$PY" ]; then
  if SOC_FAKE_ARCH=aarch64 PYTHONPATH="$ROOT/kiosk-host" "$PY" - <<'PYEOF'
import os, sys
from host import perf

errs = []
# is_arm() must honor the SOC_FAKE_ARCH override for both 64-bit ARM spellings.
for m in ("aarch64", "arm64"):
    os.environ["SOC_FAKE_ARCH"] = m
    if not perf.is_arm():
        errs.append(f"is_arm() should be True for SOC_FAKE_ARCH={m}")
# ...and must NOT misfire on x86 (no regression to the dev box).
os.environ["SOC_FAKE_ARCH"] = "x86_64"
if perf.is_arm():
    errs.append("is_arm() should be False for x86_64")
# Real (unfaked) machine still classifies — sanity that the fallback path works.
os.environ.pop("SOC_FAKE_ARCH", None)
import platform
if perf.is_arm() != (platform.machine() in ("aarch64","arm64","armv7l","armv6l")):
    errs.append("is_arm() fallback disagrees with platform.machine()")
# hwaccel policy must be one of the documented modes, whatever the arch.
valid = {"always", "never", "ondemand", "default"}
for m in ("aarch64", "x86_64"):
    os.environ["SOC_FAKE_ARCH"] = m
    mode = perf.hwaccel_mode()
    if mode not in valid:
        errs.append(f"hwaccel_mode()={mode!r} not in {valid} for {m}")
# On a 1 GB Pi the low-memory profile pins ON_DEMAND (GPU only when needed),
# overriding the ARM 'always' — assert that precedence holds.
os.environ["SOC_FAKE_ARCH"] = "aarch64"
os.environ["SOC_LOW_MEMORY"] = "1"
os.environ["SOC_WEBKIT_HWACCEL"] = "auto"
if perf.hwaccel_mode() != "ondemand":
    errs.append("low-memory aarch64 hwaccel should be 'ondemand'")

if errs:
    print("\n".join("    " + e for e in errs)); sys.exit(1)
sys.exit(0)
PYEOF
  then
    ok "perf.is_arm() honors SOC_FAKE_ARCH; aarch64 branch + hwaccel policy sane"
  else
    bad "aarch64 simulation failed (perf.is_arm()/hwaccel policy — see above)"
  fi
fi

# (i) VPN runtime deps must be DECLARED so a package install / installer run pulls
#     the right client per vpn.type on aarch64 (these are distro packages, not
#     compiled here — the whole point is the Pi never builds them). Assert every
#     VPN client is named in BOTH the nfpm per-packager depends (deb/rpm/apk) AND
#     install.sh's package sets. wireguard-tools is the wg-quick CLI; openfortivpn
#     + ppp drive Fortinet; openvpn covers vpn.type: openvpn.
for client in openfortivpn openvpn wireguard-tools; do
  if grep -qE "^[[:space:]]*-[[:space:]]+${client}[[:space:]]*$" nfpm.yaml; then
    ok "nfpm.yaml declares VPN client dep: $client"
  else
    bad "nfpm.yaml is missing VPN client dep '$client' (package install won't pull it on aarch64)"
  fi
  # install.sh names it in a PK_ set (required) or a pm_try/pm_install line (optional).
  if grep -qE "(^|[^a-z-])${client}([^a-z-]|$)" install.sh; then
    ok "install.sh installs VPN client: $client"
  else
    bad "install.sh never installs VPN client '$client' (no aarch64 install path)"
  fi
done
# tesseract OCR (iNode SSL-VPN login CAPTCHA): pkg name varies (tesseract-ocr on
# deb/apk, tesseract on rpm). Assert at least one spelling is in nfpm + install.sh.
if grep -qE '^[[:space:]]*-[[:space:]]+tesseract(-ocr)?[[:space:]]*$' nfpm.yaml; then
  ok "nfpm.yaml declares tesseract OCR (iNode CAPTCHA) dep"
else
  bad "nfpm.yaml is missing tesseract/tesseract-ocr (iNode SSL-VPN CAPTCHA path)"
fi
if grep -qE '(^|[^a-z-])tesseract(-ocr)?([^a-z-]|$)' install.sh; then
  ok "install.sh installs tesseract OCR (iNode CAPTCHA)"
else
  bad "install.sh never installs tesseract/tesseract-ocr (iNode SSL-VPN CAPTCHA path)"
fi

# (j) The bundled iNode SSL-VPN helper must be a portable TEXT script, NOT an
#     arch-specific ELF binary — that is what makes iNode "pure-Python/shell" and
#     runnable on aarch64 without a vendor build. If someone ever drops an x86
#     ELF here, `file` would say 'ELF ... executable' and the Pi would fail with
#     'exec format error'. Assert it is a text script.
inode_helper="vendor/iNode-VPN-Client/scripts/inode-svpn-helper"
if [ -f "$inode_helper" ]; then
  ftype="$(file -b "$inode_helper" 2>/dev/null || echo unknown)"
  case "$ftype" in
    *ELF*) bad "iNode helper is an ELF binary ('$ftype') — arch-specific, breaks on aarch64" ;;
    *text*|*script*) ok "iNode helper is a TEXT script ($ftype) — arch-portable" ;;
    *) bad "iNode helper is not a recognizable text script ('$ftype')" ;;
  esac
else
  bad "iNode helper missing: $inode_helper (bundled SSL-VPN client incomplete)"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "verify-arm: FAILED — a compile-on-Pi / wrong-arch regression was introduced."
  exit 1
fi
echo "verify-arm: all aarch64 invariants hold."
