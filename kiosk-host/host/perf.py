"""
Performance profile detection — pure helpers, no GTK imports, unit-testable.

The wall targets anything from a 1 GB Raspberry Pi 5 to an x86 workstation.
Rather than asking the operator to hand-tune browser knobs, the host picks a
profile from the actual hardware and exposes overrides:

  SOC_LOW_MEMORY=0|1        force the low-memory profile off/on
                            (auto: on when MemTotal <= ~1.5 GB)
  SOC_WEBKIT_HWACCEL=auto|always|never|ondemand
                            WebKit hardware (GPU) acceleration policy.
                            auto = ALWAYS on ARM boards with a render node
                            (Pi 5 V3D — compositing on the GPU instead of the
                            CPU), ON_DEMAND under the low-memory profile,
                            engine default elsewhere.
  SOC_CHROMIUM_HWACCEL=auto|never
                            Chromium counterpart (see host/chromium_panel.py
                            _hwaccel_flags): auto adds V3D GPU flags on ARM
                            boards with a render node, never opts out.
  SOC_FAKE_ARCH=<machine>   TEST-ONLY override for is_arm() — pretend the host
                            reports this platform.machine() (e.g. aarch64) so the
                            ARM tuning branch can be exercised on an x86 dev box /
                            CI (see dev/verify-arm.sh). Never set in production.
"""
from __future__ import annotations

import os
import platform

LOW_MEMORY_THRESHOLD_MB = 1536      # 1 GB-class boards (Pi) after GPU carve-out


def total_ram_mb(meminfo: str = "/proc/meminfo"):
    """MemTotal in MiB, or None when it cannot be read (non-Linux, tests)."""
    try:
        with open(meminfo, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def low_memory() -> bool:
    """True on small boards — panels then trade cache for headroom."""
    env = os.environ.get("SOC_LOW_MEMORY", "")
    if env in ("0", "1"):
        return env == "1"
    mb = total_ram_mb()
    return mb is not None and mb <= LOW_MEMORY_THRESHOLD_MB


def mem_available_mb(meminfo: str = "/proc/meminfo"):
    """MemAvailable in MiB (kernel's estimate of allocatable memory), or None.
    Used by the runtime memory watchdog to detect pressure on a 1 GB Pi."""
    try:
        with open(meminfo, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def proc_rss_kb(pid: int, status_path: str = None):
    """Resident-set size (KiB) of a process from /proc/<pid>/status, or None.
    Lets the watchdog pick the heaviest panel to recycle under memory pressure."""
    path = status_path or f"/proc/{pid}/status"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def under_pressure(avail_mb, min_mb) -> bool:
    """True when available memory is known and below the floor."""
    return avail_mb is not None and avail_mb < min_mb


def is_arm() -> bool:
    # SOC_FAKE_ARCH: test-only override so the ARM tuning branch is reachable on
    # x86 dev/CI (dev/verify-arm.sh). Falls back to the real machine when unset.
    machine = os.environ.get("SOC_FAKE_ARCH") or platform.machine()
    return machine in ("aarch64", "arm64", "armv7l", "armv6l")


def has_gpu_render_node() -> bool:
    try:
        return any(n.startswith("renderD") for n in os.listdir("/dev/dri"))
    except OSError:
        return False


def hwaccel_mode() -> str:
    """'always' | 'never' | 'ondemand' | 'default' (leave the engine default)."""
    env = os.environ.get("SOC_WEBKIT_HWACCEL", "auto").lower()
    if env in ("always", "never", "ondemand"):
        return env
    if env not in ("", "auto"):
        return "default"
    if low_memory():
        return "ondemand"
    if is_arm() and has_gpu_render_node():
        return "always"
    return "default"
