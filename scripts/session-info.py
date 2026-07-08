#!/usr/bin/env python3
"""
Print shell-eval'able facts about the configured wall, for the session scripts:

  layout=single|windows     display.layout resolved for a Wayland backend
  all_webkit=1|0            whether every panel uses the webkit engine

Used by scripts/wayland-session.sh to pick cage (single, all-webkit) vs labwc.
Prints safe defaults on any error so the session can still start.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))


def main():
    try:
        from host import config as cfg
        conf = cfg.load(os.environ.get("SOC_PANELS_FILE", "config/panels.yaml"))
        layout = cfg.resolve_layout(conf, "wayland")
        all_webkit = all(p.engine == "webkit" for p in conf.panels)
    except Exception as e:  # noqa: BLE001 — host.main reports config errors properly
        print(f"# session-info: {e}", file=sys.stderr)
        layout, all_webkit = "windows", False
    print(f"layout={layout}")
    print(f"all_webkit={1 if all_webkit else 0}")


if __name__ == "__main__":
    main()
