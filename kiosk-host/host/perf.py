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


def is_arm() -> bool:
    return platform.machine() in ("aarch64", "arm64", "armv7l", "armv6l")


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
