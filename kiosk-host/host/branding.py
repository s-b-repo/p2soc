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
import time

_DEFAULTS = {
    "name": "SOC Video Wall",
    "short_name": "SOC Wall",
    "tagline": "Operations console",
    "vendor": "s-b-repo",
    "homepage": "https://github.com/s-b-repo/p2soc",
    "icon": "share/icons/soc-wall.svg",
    "colors": {
        # SOC green-on-white console theme. Recolour here to rebrand.
        "primary": "#1FA463",        # SOC-green brand: eyebrow, status dot, focus glow
        "setup": "#1FA463",          # Setup card accent (unified green)
        "desktop": "#1FA463",        # Desktop card accent (green)
        "kiosk": "#0E7C7B",          # Kiosk card accent (teal-green, differentiated hue)
        "background": "#FFFFFF",     # app/window background (clean near-white field)
        "surface_top": "#F4F8F5",    # card/page surface (barely-green tinted white)
        "surface_bottom": "#EAF1EC", # sunken/checked card + input wells
        "border": "#CFE0D4",         # thin green-grey hairline borders + dividers
        "text": "#0B1F14",           # near-black-green primary text
        "text_dim": "#51695C",       # green-grey secondary (subtitles, hints) — AA on tinted surfaces
        "accent_strong": "#157A49",  # darker green: button fills, hover borders, header rule, ON-SURFACE accent/dots
        "good": "#157A49",           # valid-field ring + ONLINE status dot (AA-readable on tinted surfaces)
        "warn": "#9C7209",           # amber-on-white caution (the lone non-green accent), AA on tinted surfaces
        "bad": "#C0341D",            # error ring + invalid status (brick red on white)
    },
}


def _root() -> str:
    return os.environ.get("SOC_ROOT") or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _user_branding() -> str:
    """Per-user theme file (XDG) — always writable by a desktop user, so the
    appearance editor / Setup never needs root on a deployed box (root-owned /etc).
    Read above /etc (below SOC_BRANDING_FILE) so a user's saved theme wins for them."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "soc-display", "branding.yaml")


def _candidates():
    env = os.environ.get("SOC_BRANDING_FILE")
    if env:
        yield env
    user = _user_branding()
    if os.path.exists(user):
        yield user
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


def _warn_ignored(path: str, exc: BaseException) -> None:
    """Emit one non-fatal diagnostic naming the rejected file + cause, so an operator
    whose hand-edited branding silently fell back to defaults can see WHY. Wrapped so
    the diagnostic write itself can never raise (matches the module's stderr idiom)."""
    try:
        sys.stderr.write(f"branding: ignoring {path}: {exc}\n")
    except Exception:  # noqa: BLE001 — diagnostics must never become a new failure.
        pass


def _load_file(path: str) -> dict:
    try:
        import yaml  # type: ignore
        with open(path, encoding="utf-8") as fh:
            d = yaml.safe_load(fh)
        return d if isinstance(d, dict) else {}
    except ImportError:
        try:
            return _parse_flat(path)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            _warn_ignored(path, exc)
            return {}
    except Exception as yaml_exc:  # noqa: BLE001 — some loader errors are not YAMLError.
        # malformed YAML — try the lenient parser, else give up to defaults. Keep the
        # broad catch so non-YAMLError loader faults still hit the fallback parser.
        try:
            return _parse_flat(path)
        except (OSError, ValueError, UnicodeDecodeError):
            # Realistic file/parse faults degrade to defaults, but surface the ORIGINAL
            # yaml cause so the operator can tell 'rejected' from 'missing'. An unexpected
            # programmer error in _parse_flat is NOT caught here and propagates.
            _warn_ignored(path, yaml_exc)
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
_marker_mtime_val: float = 0.0


def _marker_path() -> str:
    """Cross-process signal file: touched by save_colors(), checked by load()."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache")
    d = os.path.join(base, "soc-display")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "branding-changed")


def _touch_marker() -> None:
    """Write current timestamp into the marker file so other processes see it."""
    with open(_marker_path(), "w") as fh:
        fh.write(str(time.time()))


def _marker_mtime() -> float:
    """Return the mtime of the marker file, or 0 if absent."""
    try:
        return os.path.getmtime(_marker_path())
    except OSError:
        return 0.0


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


# --------------------------------------------------------------------------- #
# WCAG contrast helpers — pure stdlib (no deps), used so the CSS/markup builders
# can pick an ACCENT and BUTTON-TEXT colour that actually reads on the current
# surface, instead of hardcoding one that breaks on an alternate (dark) theme.
# This is what keeps the palette legible across every preset without per-surface
# special-casing: an accent that fails on its surface is swapped for a stronger
# palette key (accent_strong), and button text is black/white by luminance.
# --------------------------------------------------------------------------- #
def _rgb(hexc: str) -> "tuple[int, int, int]":
    h = (hexc or "").lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    try:
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        return 136, 136, 136


def relative_luminance(hexc: str) -> float:
    """WCAG 2.x relative luminance of a #RRGGBB colour (0.0=black, 1.0=white)."""
    def chan(c: int) -> float:
        s = c / 255.0
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4
    r, g, b = _rgb(hexc)
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def contrast_ratio(fg: str, bg: str) -> float:
    """WCAG 2.x contrast ratio between two #RRGGBB colours (1.0 .. 21.0)."""
    l1, l2 = relative_luminance(fg), relative_luminance(bg)
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


def is_dark(hexc: str) -> bool:
    """True when `hexc` is a dark surface (luminance below the WCAG mid-point) —
    used to gate the dark-theme glow rules onto ANY dark palette, not just the
    named Midnight preset (so a custom dark palette gets the cyber glow too)."""
    return relative_luminance(hexc) < 0.18


def text_on(bg: str, *, dark: str | None = None, light: str = "#FFFFFF") -> str:
    """Pick the highest-contrast text colour for an accent fill `bg`: white on a
    dark accent, near-black on a LIGHT accent (amber / bright green) — so a button
    label never goes invisible on an alternate theme. Considers the palette's own
    `text` plus a hard white/near-black pair, because on a dark THEME the palette
    text is itself light and would fail on a light accent fill; the near-black
    guarantees a readable option for any fill. Returns the best of the candidates."""
    cands = [c for c in (dark, color("text", "#0B1F14"), light, "#101010") if c]
    return max(cands, key=lambda c: contrast_ratio(c, bg))


def accent_on(bg: str, *, accent: str | None = None, strong: str | None = None,
              minimum: float = 3.0) -> str:
    """Return an accent colour that meets `minimum` contrast on surface `bg`:
    prefer the brand `accent` (primary); if it fails, fall back to the stronger
    palette accent (accent_strong); if that ALSO fails (very light surface) keep
    whichever of the two contrasts better. Keeps the brand identity where it reads
    and only swaps where the tinted/sunken surface would make it illegible."""
    accent = accent or color("primary", "#1FA463")
    strong = strong or color("accent_strong", "#157A49")
    if contrast_ratio(accent, bg) >= minimum:
        return accent
    if contrast_ratio(strong, bg) >= minimum:
        return strong
    return strong if contrast_ratio(strong, bg) >= contrast_ratio(accent, bg) else accent


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


# --------------------------------------------------------------------------- #
# Persistence — write the palette back to branding.yaml (the Appearance editor's
# Save). PURE STDLIB (no PyYAML) so branding stays importable before the venv,
# exactly like load(). Comment-preserving: only colour *values* are rewritten;
# the heavily-commented header + per-key docs + key order survive untouched.
# --------------------------------------------------------------------------- #
_COLOR_KEYS = tuple(_DEFAULTS["colors"].keys())


def _fmt_hex(value: str) -> str:
    """Validate + normalise a colour to #RRGGBB uppercase. Accepts #RGB / #RRGGBB
    (with or without the leading '#'); raises ValueError on anything else so a bad
    pick can never corrupt the file."""
    h = str(value).strip().lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    if len(h) != 6:
        raise ValueError(f"not a hex colour: {value!r}")
    try:
        int(h, 16)
    except ValueError:
        raise ValueError(f"not a hex colour: {value!r}")
    return "#" + h.upper()


def _save_target(path: str | None) -> str:
    """Resolve the branding.yaml write target, mirroring _candidates()'s order and
    honouring SOC_BRANDING_FILE. Returns the first tier whose parent dir the euid
    can create+write; raises PermissionError (with the exact path) otherwise — the
    editor catches it and tells the operator to re-run elevated / fix perms. Never
    escalates to /etc here (that stays the wizard's pkexec path)."""
    def _writable(target: str) -> bool:
        d = os.path.dirname(os.path.abspath(target)) or "."
        p = d
        while p and not os.path.exists(p):
            parent = os.path.dirname(p)
            if parent == p:
                break
            p = parent
        return os.access(p or "/", os.W_OK)

    # 1. explicit path arg (the headless / test hook).
    if path:
        if not _writable(path):
            raise PermissionError(
                f"cannot write branding to {path!r} (directory not writable) — "
                f"re-run as root or fix the directory permissions")
        return os.path.abspath(path)
    # 2. $SOC_BRANDING_FILE.
    env = os.environ.get("SOC_BRANDING_FILE")
    if env:
        if not _writable(env):
            raise PermissionError(
                f"cannot write branding to $SOC_BRANDING_FILE={env!r} "
                f"(directory not writable) — re-run as root or fix permissions")
        return os.path.abspath(env)
    # 3. /etc/soc-display/branding.yaml ONLY if the dir exists and is writable (root).
    if os.path.isdir("/etc/soc-display") and os.access("/etc/soc-display", os.W_OK):
        return "/etc/soc-display/branding.yaml"
    # 4. per-user XDG file WHEN IT ALREADY EXISTS — matches _candidates() read order
    #    (user file wins over repo). If a previous save created it, update in place
    #    so read+write stay consistent; don't create a new user file that would then
    #    permanently shadow an operator's hand-edited repo branding.yaml.
    user = _user_branding()
    if os.path.exists(user):
        return os.path.abspath(user)
    # 5. repo checkout — keep the theme with the source in a dev tree.
    repo = os.path.join(_root(), "branding", "branding.yaml")
    if _writable(repo):
        return os.path.abspath(repo)
    # 6. per-user XDG file (create) — last resort, always writable by the desktop user.
    #    (root-owned /etc, non-writable /opt) never needs root; _candidates() reads
    #    it above /etc so the saved theme applies on next launch. This is the path
    #    that fixes "cannot write branding ... and no writable repo fallback".
    user = _user_branding()
    os.makedirs(os.path.dirname(user), exist_ok=True)
    return os.path.abspath(user)


def _rewrite_colors_inplace(lines: "list[str]", colors: dict) -> "list[str]":
    """In an existing file's text, rewrite ONLY the values of `  <key>: "<hex>"`
    lines inside the `colors:` block (keeping indentation, key, quote style and any
    inline trailing comment). Keys absent from the file are appended inside the
    block. Everything else — comments, blanks, key order, non-colour lines — is
    preserved verbatim."""
    out: "list[str]" = []
    in_colors = False
    colors_indent = ""
    seen: "set[str]" = set()
    last_color_idx = -1  # index in `out` of the last colour line written

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        # Detect the start of the top-level `colors:` block (no indent, value-less).
        if not (line[:1] in (" ", "\t")) and stripped.rstrip() == "colors:":
            in_colors = True
            out.append(line)
            continue
        if in_colors:
            indented = line[:1] in (" ", "\t")
            # A new top-level (non-indented, non-blank, non-comment) key ends the block.
            if stripped and not stripped.startswith("#") and not indented:
                in_colors = False
            elif indented and stripped and not stripped.startswith("#"):
                key, sep, rest = stripped.partition(":")
                key = key.strip()
                if sep and key in colors:
                    indent = line[:len(line) - len(line.lstrip())]
                    colors_indent = colors_indent or indent
                    # Preserve any inline trailing comment that follows the VALUE.
                    # The value itself starts with '#' (a hex colour) and may be
                    # quoted, so only a '#' that appears AFTER the value token (the
                    # first whitespace-separated chunk) counts as a comment.
                    comment = ""
                    val_part = rest.strip()
                    after = ""
                    if val_part:
                        bits = val_part.split(None, 1)
                        after = bits[1] if len(bits) > 1 else ""
                    hashpos = after.find("#")
                    if hashpos != -1:
                        comment = "  " + after[hashpos:].strip()
                    new_val = _fmt_hex(colors[key])
                    out.append(f'{indent}{key}: "{new_val}"{comment}')
                    seen.add(key)
                    last_color_idx = len(out) - 1
                    continue
        out.append(line)

    # Append any colour keys present in `colors` but missing from the file, inside
    # the colours block (after the last colour line), in _DEFAULTS order.
    missing = [k for k in _COLOR_KEYS if k in colors and k not in seen]
    # also honour any non-default keys the caller passed
    missing += [k for k in colors if k not in _COLOR_KEYS and k not in seen]
    if missing:
        indent = colors_indent or "  "
        insert = [f'{indent}{k}: "{_fmt_hex(colors[k])}"' for k in missing]
        if last_color_idx >= 0:
            out[last_color_idx + 1:last_color_idx + 1] = insert
        else:
            out.extend(insert)
    return out


def _render_fresh(colors: dict) -> "list[str]":
    """Render a brand-new branding.yaml when the target doesn't exist: a short
    header, a `colors:` block with the 14 keys in _DEFAULTS order, then any extra
    keys. Also carries through name/short_name/tagline/icon from load() so a
    from-scratch /etc file is still a valid full branding.yaml."""
    b = load()
    lines = ["# Theme palette written by the Appearance editor — edit to rebrand."]
    for k in ("name", "short_name", "tagline", "vendor", "homepage", "icon"):
        v = b.get(k)
        if v:
            lines.append(f'{k}: "{v}"')
    lines.append("colors:")
    keys = list(_COLOR_KEYS) + [k for k in colors if k not in _COLOR_KEYS]
    for k in keys:
        if k in colors:
            lines.append(f'  {k}: "{_fmt_hex(colors[k])}"')
    return lines


def save_colors(colors: dict, path: str | None = None) -> str:
    """Write the palette in `colors` back to branding.yaml and return the path
    written. PURE STDLIB. Resolves the target via _save_target (SOC_BRANDING_FILE >
    /etc/soc-display > repo, honouring an explicit `path`), preserving the file's
    comments/structure when it already exists (only colour values are rewritten;
    NEVER secrets — only palette keys are ever touched). Atomic: writes a temp file
    in the same dir + os.replace(); mode 0644. Refreshes the in-process cache so the
    live process picks up the new palette."""
    if not isinstance(colors, dict) or not colors:
        raise ValueError("save_colors: colors must be a non-empty dict")
    # Validate every value up front so a bad pick aborts before any write.
    clean = {str(k): _fmt_hex(v) for k, v in colors.items()}

    target = _save_target(path)
    d = os.path.dirname(target) or "."
    os.makedirs(d, exist_ok=True)

    if os.path.exists(target):
        with open(target, encoding="utf-8") as fh:
            src_lines = fh.read().splitlines()
        out_lines = _rewrite_colors_inplace(src_lines, clean)
    else:
        out_lines = _render_fresh(clean)
    text = "\n".join(out_lines) + "\n"

    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".branding.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    load(refresh=True)
    # Touch a cross-process marker so other processes (launchermenu) detect the
    # change without polling the YAML file on every frame.
    try:
        _touch_marker()
    except OSError:
        pass
    return target


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
