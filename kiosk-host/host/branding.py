"""
Branding / rebranding for the SOC wall — a single source of truth.

Edit ``branding/branding.yaml`` (or set ``SOC_BRANDING_FILE``, or drop a
``branding.yaml`` in ``/etc/soc-display/``) to rebrand: the name, tagline, icon
and accent colours flow into the launcher menu, the setup wizard and — at install
time — the desktop entry + packaged metadata.

Robust by design: a missing or partial file falls back to the built-in SOC-wall
defaults, and loading works with PyYAML *or* a tiny stdlib parser (so setup.py,
which runs before the venv, can read branding too). It never raises on a bad file.

CLI (used by install.sh to render the .desktop without duplicating the schema):
    python -m host.branding get <key>        # e.g. name / short_name / icon
    python -m host.branding color <name>      # e.g. primary / kiosk
    python -m host.branding desktop <exec> [icon-name]   # print a .desktop entry
"""
from __future__ import annotations

import os
import sys

_DEFAULTS = {
    "name": "SOC Video Wall",
    "short_name": "SOC Wall",
    "tagline": "Operations console",
    "vendor": "s-b-repo",
    "homepage": "https://github.com/s-b-repo/p2soc",
    "icon": "share/icons/soc-wall.svg",
    "colors": {
        "primary": "#2BE0C8",
        "setup": "#8B9CFF",
        "desktop": "#2BE0C8",
        "kiosk": "#F5B14C",
        "background": "#0B1220",
        "surface_top": "#16213A",
        "surface_bottom": "#0F1828",
        "border": "#22324E",
        "text": "#E8EEF7",
        "text_dim": "#8194B0",
    },
}


def _root() -> str:
    return os.environ.get("SOC_ROOT") or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _candidates():
    env = os.environ.get("SOC_BRANDING_FILE")
    if env:
        yield env
    yield "/etc/soc-display/branding.yaml"
    root = _root()
    yield os.path.join(root, "branding", "branding.yaml")
    yield os.path.join(root, "config", "branding.yaml")


def _parse_flat(path: str) -> dict:
    """Stdlib fallback parser for the branding schema: top-level ``key: value``
    plus a single nested ``colors:`` block of indented ``name: value`` pairs."""
    data: dict = {}
    section = None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indented = line[:1] in (" ", "\t")
            key, sep, val = line.strip().partition(":")
            if not sep:
                continue
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if not indented:
                if val == "":
                    section = key
                    data.setdefault(key, {})
                else:
                    section = None
                    data[key] = val
            elif section is not None:
                data.setdefault(section, {})[key] = val
    return data


def _load_file(path: str) -> dict:
    try:
        import yaml  # type: ignore
        with open(path, encoding="utf-8") as fh:
            d = yaml.safe_load(fh)
        return d if isinstance(d, dict) else {}
    except ImportError:
        try:
            return _parse_flat(path)
        except OSError:
            return {}
    except Exception:
        # malformed YAML — try the lenient parser, else give up to defaults
        try:
            return _parse_flat(path)
        except Exception:
            return {}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        elif v not in (None, ""):
            out[k] = v
    return out


_cache: dict | None = None


def load(refresh: bool = False) -> dict:
    """Return the merged branding (defaults <- first existing branding file)."""
    global _cache
    if _cache is not None and not refresh:
        return _cache
    data: dict = {}
    for path in _candidates():
        if path and os.path.exists(path):
            data = _load_file(path)
            break
    _cache = _deep_merge(_DEFAULTS, data if isinstance(data, dict) else {})
    return _cache


def get(key: str, default=None):
    return load().get(key, default if default is not None else _DEFAULTS.get(key))


def color(name: str, default: str | None = None) -> str:
    cols = load().get("colors") or {}
    return cols.get(name) or default or _DEFAULTS["colors"].get(name, "#888888")


def icon_path() -> str:
    """Resolve the branding icon to an existing file, else the packaged default."""
    ic = load().get("icon") or _DEFAULTS["icon"]
    cands = [ic] if os.path.isabs(ic) else [
        os.path.join(_root(), ic),
        os.path.join("/usr/share/soc-display", ic),
        os.path.join("/etc/soc-display", ic),
    ]
    cands += [
        os.path.join(_root(), "share/icons/soc-wall.svg"),
        "/usr/share/icons/hicolor/scalable/apps/soc-wall.svg",
    ]
    for p in cands:
        if p and os.path.exists(p):
            return p
    return ""


def _main(argv) -> int:
    if not argv:
        for k in ("name", "short_name", "tagline", "vendor", "homepage", "icon"):
            print(f"{k}={get(k)}")
        return 0
    cmd = argv[0]
    if cmd == "get" and len(argv) > 1:
        print(get(argv[1], ""))
        return 0
    if cmd == "color" and len(argv) > 1:
        print(color(argv[1]))
        return 0
    if cmd == "desktop":
        # desktop <Exec> [icon-name]  -> print an XDG entry from the branding
        exec_cmd = argv[1] if len(argv) > 1 else "/opt/soc-display/scripts/soc-wall-menu"
        icon_name = argv[2] if len(argv) > 2 else "soc-wall"
        print("[Desktop Entry]")
        print(f"Name={get('name')}")
        print(f"Comment={get('tagline')}")
        print(f"Exec={exec_cmd}")
        print(f"Icon={icon_name}")
        print("Terminal=false")
        print("Type=Application")
        print("Categories=System;")
        print("Keywords=soc;security;wall;kiosk;dashboard;")
        return 0
    sys.stderr.write("usage: python -m host.branding [get KEY|color NAME|desktop EXEC [ICON]]\n")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
