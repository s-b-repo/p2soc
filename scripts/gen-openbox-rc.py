#!/usr/bin/env python3
"""
Generate ~/.config/openbox/rc.xml from openbox/rc.xml.tmpl + config/panels.yaml.

Emits one forced-placement <application class="soc-pN"> rule per panel so
Openbox drops each window into its 2x2 cell (belt-and-suspenders alongside the
host's own move/resize). Resolution comes from --width/--height (the installer
passes the values it reads from xrandr) or from the panels.yaml `display` block.

Usage:
  gen-openbox-rc.py --panels config/panels.yaml --template openbox/rc.xml.tmpl \
                    --out ~/.config/openbox/rc.xml [--width W --height H]
"""
import argparse
import os
import sys

# make host.config importable regardless of CWD
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "kiosk-host"))
from host import config as cfg  # noqa: E402

APP_RULE = """  <application class="{cls}">
    <decor>yes</decor>
    <maximized>no</maximized>
    <position force="yes"><x>{x}</x><y>{y}</y><monitor>1</monitor></position>
    <size><width>{w}</width><height>{h}</height></size>
    <layer>normal</layer>
    <focus>yes</focus>
  </application>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panels", default="config/panels.yaml")
    ap.add_argument("--template", default="openbox/rc.xml.tmpl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--width", type=int)
    ap.add_argument("--height", type=int)
    ap.add_argument("--if-auto", action="store_true",
                    help="apply --width/--height only when display.auto is true")
    args = ap.parse_args()

    conf = cfg.load(args.panels)
    if args.width and args.height and (conf.display.auto or not args.if_auto):
        conf.display.width, conf.display.height = args.width, args.height
        # recompute geometry with the real resolution
        for p in conf.panels:
            p.geometry = cfg.compute_geometry(conf.display, p.grid)

    rules = []
    for p in conf.panels:
        g = p.geometry
        rules.append(APP_RULE.format(cls=p.wmclass, x=g.x, y=g.y, w=g.w, h=g.h))
    block = "\n".join(rules)

    with open(args.template, encoding="utf-8") as fh:
        tmpl = fh.read()
    out = tmpl.replace("  <!-- SOC_APPS -->", block)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(out)
    print(f"wrote {args.out} ({len(conf.panels)} placement rules @ "
          f"{conf.display.width}x{conf.display.height})")


if __name__ == "__main__":
    main()
