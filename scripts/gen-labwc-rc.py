#!/usr/bin/env python3
"""
Generate ~/.config/labwc/rc.xml from labwc/rc.xml.tmpl + config/panels.yaml —
the Wayland twin of gen-openbox-rc.py.

Emits two placement rules per panel: one matching `identifier` (app_id for
native Wayland clients, WM_CLASS for XWayland clients such as the Chromium
panels) and one matching `title` (the host names each WebKit window soc-<id>,
since a single GTK process cannot give its windows distinct app_ids on
Wayland). Each rule moves + resizes the window into its grid cell.

Run automatically by scripts/wayland-session.sh at session start.

Usage:
  gen-labwc-rc.py --panels config/panels.yaml --template labwc/rc.xml.tmpl \
                  --out ~/.config/labwc/rc.xml [--width W --height H] [--if-auto]
"""
import argparse
import os
import sys

# make host.config importable regardless of CWD
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))
from host import config as cfg  # noqa: E402

APP_RULE = """  <windowRule {match}="{cls}">
    <action name="MoveTo" x="{x}" y="{y}"/>
    <action name="ResizeTo" width="{w}" height="{h}"/>
  </windowRule>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panels", default="config/panels.yaml")
    ap.add_argument("--template", default="labwc/rc.xml.tmpl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--width", type=int)
    ap.add_argument("--height", type=int)
    ap.add_argument("--if-auto", action="store_true",
                    help="apply --width/--height only when display.auto is true")
    args = ap.parse_args()

    conf = cfg.load(args.panels)
    if args.width and args.height and (conf.display.auto or not args.if_auto):
        conf.display.width, conf.display.height = args.width, args.height
        for p in conf.panels:
            p.geometry = cfg.compute_geometry(conf.display, p.grid)

    rules = []
    for p in conf.panels:
        g = p.geometry
        for match in ("identifier", "title"):
            rules.append(APP_RULE.format(match=match, cls=p.wmclass,
                                         x=g.x, y=g.y, w=g.w, h=g.h))
    block = "\n".join(rules)

    with open(args.template, encoding="utf-8") as fh:
        tmpl = fh.read()
    out = tmpl.replace("  <!-- SOC_APPS -->", block)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"wrote {args.out} ({len(conf.panels)} panels @ "
          f"{conf.display.width}x{conf.display.height})")


if __name__ == "__main__":
    main()
