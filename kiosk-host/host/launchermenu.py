"""
The SOC video-wall CONTROL CENTER — the single window behind soc-wall.desktop. It
does NOT take over the machine; it is the one place to run, configure and manage
the wall, grouped under quiet '// ' section eyebrows:

  // run        Desktop mode (windowed)        Kiosk mode (fullscreen)
  // configure  Setup / Configure (wizard)     Appearance (theme editor)
  // system     Install / Update               Uninstall

The layout is ADAPTIVE to install state (host.health.is_installed()): on a box
that isn't installed yet, Install is the hero and the Run tiles dim with an
'install first' hint; once installed, Run is the hero, Install reads 'Reinstall /
Update' and Uninstall sits in the quiet // system group. Spawned flows (Run/Setup/
Appearance) hand off / detach; IN-PROCESS flows (Install, Uninstall, Validate)
refresh the control center in place so the operator always lands back on 'start'.

Privileged actions (Install/Uninstall) never silently sudo — they go through
host.sysaction (graphical pkexec, terminal fallback, else an honest manual hint)
and stream live into a themed progress window. The name, tagline, icon and accent
colours come from host.branding (edit branding/branding.yaml to rebrand); every
surface is branding-driven so a rebrand reskins it. Pure PyGObject/GTK3 + stdlib.

`--check` validates wiring without importing GTK / needing a display (for CI).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from host import branding

ROOT = os.environ.get("SOC_ROOT", "/opt/soc-display")


def _script(name: str) -> str:
    return os.path.join(ROOT, "scripts", name)


def _venv_python() -> str:
    """The interpreter the wall's deps live under — prefer $SOC_ROOT/.venv/bin/python
    (PyYAML/websocket-client/cryptography/WebKit typelibs install there), exactly like
    the shell wrappers. sys.executable (the menu's own interpreter) may be the bare
    system python3 with none of those, so a module-spawn fallback under it would crash
    host.main on import. Mirrors scripts/*.sh's venv-preference resolution."""
    cand = os.path.join(ROOT, ".venv", "bin", "python")
    return cand if os.access(cand, os.X_OK) else (shutil.which("python3") or sys.executable)


def _spawn(argv, cwd=None, env=None) -> "tuple[bool, str]":
    """Start a helper in its own session so the menu can exit without killing it.
    Returns (ok, reason): reason names the failing binary on the spawn-time OSError so
    callers can SURFACE the cause (the menu's stderr is discarded under Terminal=false).
    Note: this only sees the spawn-time error, not a later in-child ImportError, which a
    detached Popen cannot observe."""
    try:
        subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True)
        return True, ""
    except OSError as e:
        msg = f"could not launch {argv[0]}: {e}"
        sys.stderr.write(f"soc-wall menu: {msg}\n")
        return False, msg


def launch_wall(mode: str) -> "tuple[bool, str]":
    """mode: '--fullscreen' (kiosk) or '--window' (desktop). Returns (ok, reason)."""
    sh = _script("soc-wall-desktop.sh")
    if os.path.exists(sh):
        return _spawn(["bash", sh, mode])
    kiosk = os.path.join(ROOT, "kiosk-host")
    env = dict(os.environ)
    env["SOC_WINDOW_MODE"] = "fullscreen" if mode == "--fullscreen" else "window"
    env["PYTHONPATH"] = kiosk + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    # Pin the resolved config in the child env so this fallback wall reads exactly
    # what the wizard wrote (per-user marker > /etc > repo) — same resolver as the
    # shell launchers, so menu-spawned and script-spawned walls never disagree.
    try:
        from host import configpaths  # type: ignore
        if not env.get("SOC_PANELS_FILE"):
            p = configpaths.resolve_panels()
            if p:
                env["SOC_PANELS_FILE"] = p
        if not env.get("SOC_ENV_FILE"):
            e = configpaths.resolve_env()
            if e:
                env["SOC_ENV_FILE"] = e
    except Exception:  # noqa: BLE001 — resolver best-effort; host.main self-resolves too
        pass
    # Use the venv interpreter (deps live there), not the menu's own — same as scripts/*.sh.
    return _spawn([_venv_python(), "-m", "host.main"], cwd=kiosk, env=env)


def launch_setup() -> "tuple[bool, str]":
    """Prefer the GUI setup wizard; fall back to the TTY wizard in a terminal.
    Returns (ok, reason)."""
    gui = _script("soc-wall-setup-gui.sh")
    if os.path.exists(gui):
        # Ask the wizard to come back HERE (the "main page") when it finishes, so
        # the operator lands on the launcher again and can start the wall with the
        # fresh config rather than being dropped back to the bare desktop.
        env = dict(os.environ)
        env["SOC_RETURN_TO_MENU"] = "1"
        return _spawn(["bash", gui], env=env)
    setup = os.path.join(ROOT, "setup.py")
    term = next((t for t in ("x-terminal-emulator", "gnome-terminal", "konsole",
                             "xfce4-terminal", "mate-terminal", "xterm")
                 if shutil.which(t)), None)
    if term and os.path.exists(setup):
        py = shutil.which("python3") or sys.executable
        return _spawn([term, "-e", py, setup, "wizard"])
    reason = "no setup wizard available — run: python3 setup.py wizard"
    sys.stderr.write(f"soc-wall menu: {reason}\n")
    return False, reason


def launch_appearance() -> "tuple[bool, str]":
    """Open the theme/appearance editor. Prefer the shell wrapper (detached, so the
    menu can stay open / exit independently); fall back to spawning the module."""
    sh = _script("soc-wall-appearance.sh")
    if os.path.exists(sh):
        return _spawn(["bash", sh])
    kiosk = os.path.join(ROOT, "kiosk-host")
    env = dict(os.environ)
    env["PYTHONPATH"] = kiosk + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    # Venv interpreter (deps live there), not the menu's own — same as scripts/*.sh.
    return _spawn([_venv_python(), "-m", "host.appearance"], cwd=kiosk, env=env)


# (section, glyph, title, subtitle, tag, css_class, colour_key, action). `section`
# is the '// ' eyebrow this tile lives under (run/configure/system); the build loop
# emits the eyebrow when the section changes. `glyph` names the per-tile mode icon
# (a themed inline-SVG, see _GLYPHS / _glyph_image) — these are PARALLEL choices, so
# an action-describing glyph beats a numeral that would imply a sequence. colour_key
# indexes host.branding colours so a rebrand recolours the cards AND their glyphs.
# `action` is either a plain callable (spawn + close) or a sentinel string the build
# loop binds to an in-process handler needing the window (install/uninstall).
_ACT_INSTALL = "install"      # sentinel -> _on_install(win) (in-process; needs win)
_ACT_UNINSTALL = "uninstall"  # sentinel -> _on_uninstall(win) (in-process; needs win)

_ENTRIES = (
    ("run", "window", "Desktop mode", "Run the wall in a window", "windowed",
     "soc-desktop", "desktop", lambda: launch_wall("--window")),
    ("run", "expand", "Kiosk mode", "Fill this display, no desktop", "fullscreen",
     "soc-kiosk", "kiosk", lambda: launch_wall("--fullscreen")),
    ("configure", "gear", "Setup / Configure", "Panels, vault and VPN", "",
     "soc-setup", "setup", launch_setup),
    ("configure", "swatch", "Appearance", "Theme colours & presets", "",
     "soc-appearance", "primary", launch_appearance),
    ("system", "download", "Install / Update", "Deploy or update the wall", "",
     "soc-install", "accent_strong", _ACT_INSTALL),
    ("system", "trash", "Uninstall", "Remove the deployed wall", "",
     "soc-uninstall", "bad", _ACT_UNINSTALL),
)

# Ordered section eyebrows, with a human label for the '// ' line. Drives both the
# build loop's grouping and the --check assertion that every entry's section is known.
_SECTIONS = ("run", "configure", "system")


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _shorten_path(p: str, limit: int = 42) -> str:
    """Collapse $HOME -> '~', then if still long keep the basename + a parent or two
    behind a leading '…/'. Keeps the active-config line short; never hides secrets
    (panels.yaml has none — this is purely cosmetic truncation)."""
    if not p:
        return p
    home = os.path.expanduser("~")
    if home and p.startswith(home):
        p = "~" + p[len(home):]
    if len(p) <= limit:
        return p
    parts = p.split(os.sep)
    tail = parts[-2:] if len(parts) >= 2 else parts[-1:]
    return "…/" + "/".join(tail)


def _rgba(hexc: str, alpha: float) -> str:
    h = (hexc or "").lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    try:
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        r, g, b = 136, 136, 136
    return f"rgba({r},{g},{b},{alpha})"


# --------------------------------------------------------------------------- #
# Mode glyphs — tiny accent-stroked inline SVGs rasterised to a GdkPixbuf at the
# exact tile px (no full-res, no new deps, no network). Each fn(accent)->svg str
# draws a single-meaning icon in the tile's branding accent so a rebrand reskins
# them. A Pango-unicode fallback (_GLYPH_FALLBACK) covers a box whose gdk-pixbuf
# lacks the librsvg SVG loader, so the tile always shows SOMETHING branded.
# --------------------------------------------------------------------------- #
# Gear-teeth endpoints are a pure deterministic function of i (cog centred at 12,12,
# 8 radial spokes from r=7.2 to r=9.6) — precompute the <line> markup once at import
# so _svg_gear is a plain join with no per-call trig / in-function `import math` on
# each launcher open. `math` is touched only here at import, not on the hot path.
def _gear_teeth() -> str:
    import math
    out = []
    for i in range(8):
        a = i * math.pi / 4
        out.append(
            f'<line x1="{12 + 7.2 * math.cos(a):.2f}" y1="{12 + 7.2 * math.sin(a):.2f}" '
            f'x2="{12 + 9.6 * math.cos(a):.2f}" y2="{12 + 9.6 * math.sin(a):.2f}"/>')
    return "".join(out)


_GEAR_TEETH = _gear_teeth()


def _svg_gear(ac: str) -> str:
    # cog: outer circle + 8 short radial teeth (precomputed) + inner hub — "configure".
    return (f'<g fill="none" stroke="{ac}" stroke-width="1.7" '
            f'stroke-linecap="round">{_GEAR_TEETH}'
            f'<circle cx="12" cy="12" r="6.4"/><circle cx="12" cy="12" r="2.4"/></g>')


def _svg_window(ac: str) -> str:
    # windowed rectangle: rounded frame + a title-bar line near the top — "desktop".
    return (f'<g fill="none" stroke="{ac}" stroke-width="1.7" '
            f'stroke-linejoin="round" stroke-linecap="round">'
            f'<rect x="3.5" y="4.5" width="17" height="15" rx="2.2"/>'
            f'<line x1="3.5" y1="8.6" x2="20.5" y2="8.6"/></g>')


def _svg_expand(ac: str) -> str:
    # four corner L-brackets pointing outward — "fill the screen / fullscreen".
    return (f'<g fill="none" stroke="{ac}" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="M4 9 V4 H9"/><path d="M15 4 H20 V9"/>'
            f'<path d="M20 15 V20 H15"/><path d="M9 20 H4 V15"/></g>')


def _svg_swatch(ac: str) -> str:
    # 2x2 colour-swatch grid — reads as "theme / appearance" crisply at 22px.
    return (f'<g fill="none" stroke="{ac}" stroke-width="1.6" '
            f'stroke-linejoin="round">'
            f'<rect x="4" y="4" width="6.5" height="6.5" rx="1.3"/>'
            f'<rect x="13.5" y="4" width="6.5" height="6.5" rx="1.3"/>'
            f'<rect x="4" y="13.5" width="6.5" height="6.5" rx="1.3"/>'
            f'<rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.3"/></g>')


def _svg_download(ac: str) -> str:
    # tray + down-arrow into it — "box-in / install / deploy onto this box".
    return (f'<g fill="none" stroke="{ac}" stroke-width="1.8" '
            f'stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="M12 3 V13"/><path d="M8 9.5 L12 13.5 L16 9.5"/>'
            f'<path d="M4.5 16 V19.5 H19.5 V16"/></g>')


def _svg_trash(ac: str) -> str:
    # lid + can with two bars — "box-out / remove / uninstall".
    return (f'<g fill="none" stroke="{ac}" stroke-width="1.7" '
            f'stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="M4.5 6.5 H19.5"/><path d="M9.5 6.5 V4.5 H14.5 V6.5"/>'
            f'<path d="M6.5 6.5 L7.4 19.5 H16.6 L17.5 6.5"/>'
            f'<line x1="10" y1="9.5" x2="10" y2="16.5"/>'
            f'<line x1="14" y1="9.5" x2="14" y2="16.5"/></g>')


_GLYPHS = {"gear": _svg_gear, "window": _svg_window,
           "expand": _svg_expand, "swatch": _svg_swatch,
           "download": _svg_download, "trash": _svg_trash}
# Unicode fallback per glyph (themed Pango) if the SVG loader is unavailable.
_GLYPH_FALLBACK = {"gear": "⚙", "window": "▢",
                   "expand": "⤢", "swatch": "▦",
                   "download": "⤓", "trash": "✕"}


def _glyph_image(glyph: str, accent: str, px: int = 22):
    """Render the mode glyph to a Gtk.Image at `px`. Inline SVG -> GdkPixbuf via a
    PixbufLoader sized up-front (librsvg honours set_size, so we rasterise at ~22px,
    never full-res). On ANY failure fall back to a themed Pango-unicode label so a
    box without the SVG loader still shows a branded glyph and never crashes."""
    Gtk = _Launcher.Gtk
    body = _GLYPHS.get(glyph, _svg_gear)(accent)
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{px}" height="{px}" '
           f'viewBox="0 0 24 24">{body}</svg>').encode("utf-8")
    try:
        from gi.repository import GdkPixbuf
        loader = GdkPixbuf.PixbufLoader.new_with_type("svg")
        loader.set_size(px, px)
        loader.write(svg)
        loader.close()
        pixbuf = loader.get_pixbuf()
        if pixbuf is not None:
            return Gtk.Image.new_from_pixbuf(pixbuf)
    except Exception:  # noqa: BLE001 — no SVG loader / parse fault -> Pango fallback
        pass
    lbl = Gtk.Label()
    lbl.set_markup(f'<span foreground="{accent}" size="17000">'
                   f'{_GLYPH_FALLBACK.get(glyph, "●")}</span>')
    return lbl


def _css(colors=None) -> bytes:
    """Build the launcher stylesheet from the branding palette: a crisp green-on-
    white technical console — flat surfaces, thin accent left-borders, low radius,
    a green hover glow. Every colour flows from branding so a rebrand reskins it.

    `colors` (an explicit palette dict) lets the in-launcher Appearance editor preview
    an UNSAVED palette WITHOUT mutating branding's process-wide cache; default-None
    keeps every other caller reading the persisted theme."""
    c = colors if colors is not None else branding.load().get("colors", {})

    def col(k, d):
        return c.get(k) or d
    bg = col("background", "#FFFFFF")
    s_top = col("surface_top", "#F4F8F5")
    s_bot = col("surface_bottom", "#EAF1EC")
    border = col("border", "#CFE0D4")
    accent = col("primary", "#1FA463")
    accent_strong = col("accent_strong", "#157A49")
    bad = col("bad", "#C0341D")
    text = col("text", "#0B1F14")
    text_dim = col("text_dim", "#5B7567")
    setup, desktop, kiosk = (col("setup", "#1FA463"), col("desktop", "#1FA463"),
                             col("kiosk", "#0E7C7B"))
    appearance = col("primary", "#1FA463")  # the Appearance tile uses the brand accent
    glow = _rgba(accent, 0.28)
    emph_glow = _rgba(accent, 0.22)
    bad_glow = _rgba(bad, 0.26)

    def card(cls, ac):
        # flat fill at rest; on hover the accent left-border, an inset accent ring
        # and the green focus glow lift the card off the white field.
        return (f".{cls} {{ border-left-color: {ac}; }}\n"
                f".{cls}:hover {{ border-color: {ac};\n"
                f"  box-shadow: inset 0 0 0 1px {ac}, 0 6px 18px {glow}; }}")

    # REDUCED MOTION: gate the card transition on the GTK animations setting (which
    # tracks prefers-reduced-motion). When animations are off we omit the transition
    # but KEEP the static hover colours so hover still gives feedback — just no
    # animated lift. Default-ON when the setting can't be read (headless _css()).
    animate = True
    try:
        s = _Launcher.Gtk.Settings.get_default() if _Launcher.Gtk else None
        if s is not None:
            animate = bool(s.get_property("gtk-enable-animations"))
    except Exception:  # noqa: BLE001 — pre-GTK / no settings -> assume animations on
        animate = True
    transition = "transition: all 160ms ease; " if animate else ""

    # CYBER GLOW (dark palettes only): a tasteful accent halo on the header rule and
    # the hovered card, branding-derived so ANY dark theme lights up while the
    # default green-on-white stays flat. Static (the box-shadow halo) is always on
    # for a dark palette; no motion is added here (the launcher has no pulsing
    # element), so reduced-motion needs no extra gating beyond the card transition
    # already gated above.
    glow_css = ""
    if branding.is_dark(bg):
        halo = _rgba(accent, 0.5)
        glow_css = f"""
.soc-header {{ box-shadow: inset 0 2px 0 -1px {halo}; }}
.soc-card:hover {{ box-shadow: inset 0 0 0 1px {border}, 0 4px 16px {_rgba(accent, 0.18)}; }}
"""

    return f"""
window.soc-launcher {{ background-color: {bg}; }}
.soc-header {{ background-color: {s_top};
  border-top: 2px solid {accent_strong};
  border-bottom: 1px solid {border}; padding: 18px 20px 16px 20px; }}
.soc-body {{ padding: 16px 18px 26px 18px; background-color: {bg}; }}
.soc-card {{ background-color: {s_top};
  border: 1px solid {border}; border-left: 4px solid {border}; border-radius: 6px;
  padding: 13px 16px; {transition}}}
.soc-card:hover {{ background-color: {s_bot}; }}
.soc-card:focus {{ outline: none; }}
{card("soc-setup", setup)}
{card("soc-desktop", desktop)}
{card("soc-kiosk", kiosk)}
{card("soc-appearance", appearance)}
{card("soc-install", accent_strong)}
.soc-tag {{ background-color: {s_bot}; border: 1px solid {border};
  border-radius: 4px; padding: 2px 9px; color: {text_dim}; }}
/* first-run / not-installed empty state: dim tiles that would only fail,
   emphasise the hero (Setup when unconfigured, Install when not installed). */
.soc-disabled {{ opacity: 0.45; }}
.soc-emphasis {{ border-left-width: 4px; border-left-color: {accent};
  box-shadow: inset 0 0 0 1px {accent}, 0 4px 14px {emph_glow}; }}
.soc-validate {{ padding: 1px 6px; border-radius: 4px; }}
.soc-validate:hover {{ background-color: {s_bot}; }}
/* Uninstall is the only destructive action — bad-coloured left border + a
   bad-tinted hover ring. Danger styling lives ONLY here (and its confirm flow). */
.soc-uninstall {{ border-left-color: {bad}; }}
.soc-danger {{ border-left-color: {bad}; }}
.soc-danger:hover {{ border-color: {bad};
  box-shadow: inset 0 0 0 1px {bad}, 0 6px 18px {bad_glow}; }}
/* danger eyebrow / heading colour for the uninstall confirm surfaces. */
.soc-danger-head {{ color: {bad}; }}
{glow_css}""".encode()


class _Launcher:
    """A tiny holder so an in-launcher Appearance edit can repaint the launcher's
    ONE cached CssProvider live (re-adding a provider to the screen would stack
    duplicates = a leak + cumulative parse cost). Built once in _build_window."""
    provider = None
    Gtk = None
    Gdk = None
    # True only during an in-place control-center refresh (Install/Uninstall done):
    # the old window's destroy must NOT Gtk.main_quit when we're swapping in a fresh
    # one in the same loop. Reset by the new window's destroy handler.
    refreshing = False
    # An UNSAVED Appearance preview palette, held HERE rather than mutated into
    # branding's process-wide cache (which any concurrent reader — Validate, _refresh
    # — would otherwise bake into freshly-built widgets). Cleared on Save/Cancel.
    preview_colors = None


def _reapply(colors=None):
    """Repaint the launcher's cached provider — the in-launcher Appearance editor calls
    this after a live colour change so the open launcher window recolours instantly.
    `colors` previews an UNSAVED palette; default-None repaints from the persisted
    branding theme. No new provider is added to the screen."""
    if _Launcher.provider is not None:
        _Launcher.provider.load_from_data(_css(colors))


def _open_appearance(parent_win):
    """Open the Appearance editor IN-PROCESS as a child window so a live colour
    change recolours the open launcher (on_apply -> _reapply). gi is already loaded
    here (we're in the launcher GUI), so this never re-pays the GTK import cost."""
    from host import appearance  # lazy; gi already up in this codepath
    Gtk, Gdk = _Launcher.Gtk, _Launcher.Gdk
    from gi.repository import GdkPixbuf

    def on_apply(colors):
        # Preview WITHOUT mutating branding's shared cache: merge the picked colours
        # over the persisted base, stash on _Launcher and repaint from THAT palette.
        # Every other reader (cards, Validate, _refresh) still sees the persisted theme,
        # so no half-applied palette can leak even if teardown is skipped.
        base = dict(branding.load().get("colors", {}))
        base.update(colors)
        _Launcher.preview_colors = base
        _reapply(base)

    def on_saved(_colors):
        _Launcher.preview_colors = None
        branding.load(refresh=True)   # pick up the persisted palette
        _reapply()

    editor = appearance.AppearanceEditor((Gtk, Gdk, GdkPixbuf),
                                         on_apply=on_apply, on_saved=on_saved)
    win = editor.build_window()
    win.set_transient_for(parent_win)

    def _on_close(_w):
        # CANCEL path: drop any unsaved preview and repaint from the persisted theme.
        # The preview was never written to branding's cache, so this is just dropping
        # the held palette — nothing to un-poison — but we still repaint to revert any
        # live preview the operator applied before cancelling.
        _Launcher.preview_colors = None
        branding.load(refresh=True)
        _reapply()
    win.connect("destroy", _on_close)
    win.show_all()


def _dot_markup(cols: dict, level: str, primary: str) -> str:
    """Pango markup for the status dot at `level`, coloured from branding so a
    rebrand reskins it. neutral reuses text_dim (no dedicated 'neutral' key)."""
    colour = {
        "green": cols.get("good", primary),
        "amber": cols.get("warn", "#B8860B"),
        "red": cols.get("bad", "#C0341D"),
        "neutral": cols.get("text_dim", "#5B7567"),
    }.get(level, cols.get("text_dim", "#5B7567"))
    return f'<span foreground="{colour}" size="11000">●</span>'


def _flash_validate(vbtn, cols, text: str, colour: str, ms: int = 2600):
    """Flip the Validate button's label to a transient PASS result (e.g. green
    '✓ checks passed') for a few seconds, then restore 'validate'. In-process, no
    extra window — the lightest honest confirmation."""
    Gtk = _Launcher.Gtk
    from gi.repository import GLib  # gi already up in this GUI codepath
    child = vbtn.get_child()
    if not isinstance(child, Gtk.Label):
        return
    dim = cols.get("text_dim", "#5B7567")
    child.set_markup(f'<span font_family="monospace" foreground="{colour}" '
                     f'size="8200" letter_spacing="600">{_esc(text)}</span>')

    def _restore():
        if isinstance(vbtn.get_child(), Gtk.Label):
            vbtn.get_child().set_markup(
                f'<span font_family="monospace" foreground="{dim}" '
                f'size="8200" letter_spacing="600">validate</span>')
        return False
    GLib.timeout_add(ms, _restore)


def _show_result_window(parent, cols, cause: str, result: dict):
    """Show the first failing/ warning cause in a small THEMED transient child
    window. Deliberately NOT guierror.show() — that runs its own Gtk.main (a nested
    loop). This child reuses the launcher's CssProvider and only win.destroy()s
    itself on close, so the launcher's loop is never touched."""
    Gtk = _Launcher.Gtk
    # Link text on the dialog background — routed through accent_on at AA-body (4.5)
    # so the small 'close' link reads on a white field too (brand green dips under).
    bg = cols.get("background", "#FFFFFF")
    primary = branding.accent_on(bg, accent=cols.get("primary", "#1FA463"),
                                 strong=cols.get("accent_strong", "#157A49"),
                                 minimum=4.5)
    dim = cols.get("text_dim", "#5B7567")
    text = cols.get("text", "#0B1F14")
    sev = result.get("overall", "warn")
    accent = cols.get("bad", "#C0341D") if sev == "fail" else cols.get("warn", "#B8860B")

    w = Gtk.Window(title="Validate")
    w.set_transient_for(parent)
    w.set_modal(True)
    w.set_resizable(False)
    w.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
    w.get_style_context().add_class("soc-launcher")
    # The launcher's provider is already screen-wide (added in _build_window), so the
    # .soc-launcher class on this child window is enough — no second add needed.

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    box.set_margin_top(18)
    box.set_margin_bottom(18)
    box.set_margin_start(20)
    box.set_margin_end(20)
    box.set_size_request(320, -1)

    head = Gtk.Label(xalign=0)
    word = "FAILED" if sev == "fail" else "WARNING"
    head.set_markup(f'<span font_family="monospace" foreground="{accent}" '
                    f'size="9500" weight="bold" letter_spacing="800">// {word}</span>')
    msg = Gtk.Label(xalign=0)
    msg.set_line_wrap(True)
    msg.set_markup(f'<span foreground="{text}" size="11500" weight="bold">'
                   f'{_esc(cause)}</span>')
    box.pack_start(head, False, False, 0)
    box.pack_start(msg, False, False, 0)

    hint = Gtk.Label(xalign=0)
    hint.set_markup(f'<span foreground="{dim}" size="9000">'
                    f'Run Setup, then Validate again.</span>')
    box.pack_start(hint, False, False, 0)

    close = Gtk.Button(label="Close")
    close.set_relief(Gtk.ReliefStyle.NONE)
    close.get_style_context().add_class("soc-validate")
    if isinstance(close.get_child(), Gtk.Label):
        close.get_child().set_markup(
            f'<span font_family="monospace" foreground="{primary}" '
            f'size="9000" letter_spacing="600">close</span>')
    close.set_halign(Gtk.Align.END)
    close.connect("clicked", lambda _b: w.destroy())  # destroy CHILD only, never main_quit
    box.pack_start(close, False, False, 0)

    w.add(box)
    w.show_all()


# --------------------------------------------------------------------------- #
# Privileged system actions (Install / Uninstall) — themed confirm dialogs, then
# host.sysaction runs the script in a live progress window and _refresh lands the
# operator back on the control center. Every surface here reuses the launcher's
# CssProvider (.soc-launcher) so a rebrand reskins it; danger styling appears ONLY
# in the uninstall flow. GTK on the main thread only; no nested Gtk.main.
# --------------------------------------------------------------------------- #
def _child_window(parent, title, danger=False):
    """A themed transient modal child reusing the launcher provider. `danger` flips
    the top accent to the bad colour (uninstall only)."""
    Gtk = _Launcher.Gtk
    w = Gtk.Window(title=title)
    w.set_transient_for(parent)
    w.set_modal(True)
    w.set_resizable(True)
    w.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
    w.get_style_context().add_class("soc-launcher")
    if danger:
        w.get_style_context().add_class("soc-danger")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_margin_top(18)
    box.set_margin_bottom(18)
    box.set_margin_start(20)
    box.set_margin_end(20)
    box.set_size_request(420, -1)
    w.add(box)
    return w, box


def _eyebrow(text: str, colour: str):
    """A '// '-style mono eyebrow label (the kept console signature)."""
    Gtk = _Launcher.Gtk
    lbl = Gtk.Label(xalign=0)
    lbl.set_markup(f'<span font_family="monospace" foreground="{colour}" '
                   f'size="9500" weight="bold" letter_spacing="800">{_esc(text)}</span>')
    return lbl


def _manual_window(parent, cols, action, line):
    """No pkexec AND no terminal — show the exact shell line in a themed child
    (selectable) instead of failing silently or nesting guierror's own Gtk.main."""
    Gtk = _Launcher.Gtk
    dim = cols.get("text_dim", "#5B7567")
    text = cols.get("text", "#0B1F14")
    # Code line + 'close' link on the dialog background — AA-body routed accent so
    # the brand green (below AA on a white field) is swapped where it wouldn't read.
    primary = branding.accent_on(cols.get("background", "#FFFFFF"),
                                 accent=cols.get("primary", "#1FA463"),
                                 strong=cols.get("accent_strong", "#157A49"),
                                 minimum=4.5)
    w, box = _child_window(parent, "Run in a shell")
    box.pack_start(_eyebrow("// manual", dim), False, False, 0)
    msg = Gtk.Label(xalign=0)
    msg.set_line_wrap(True)
    msg.set_markup(f'<span foreground="{text}" size="11000">No graphical sudo '
                   f'(pkexec) or terminal was found. Run this in a shell to '
                   f'{_esc(action)}:</span>')
    box.pack_start(msg, False, False, 0)
    code = Gtk.Label(xalign=0)
    code.set_selectable(True)
    code.set_line_wrap(True)
    code.set_markup(f'<span font_family="monospace" foreground="{primary}" '
                    f'size="10500">{_esc(line)}</span>')
    box.pack_start(code, False, False, 0)
    close = Gtk.Button(label="Close")
    close.set_relief(Gtk.ReliefStyle.NONE)
    close.get_style_context().add_class("soc-validate")
    close.set_halign(Gtk.Align.END)
    if isinstance(close.get_child(), Gtk.Label):
        close.get_child().set_markup(f'<span font_family="monospace" '
                                     f'foreground="{primary}" size="9000" '
                                     f'letter_spacing="600">close</span>')
    close.connect("clicked", lambda _b: w.destroy())
    box.pack_start(close, False, False, 0)
    w.show_all()


def _launch_error_window(parent, cols, reason: str, shell_line: str = ""):
    """A spawn FAILED (helper missing / OSError) — surface the cause in a themed child
    instead of silently destroying the launcher. Deliberately NOT guierror.show() (it
    runs its OWN Gtk.main, nesting/quitting this live loop); mirrors _manual_window:
    transient modal child, selectable shell line, Close destroys the CHILD only."""
    Gtk = _Launcher.Gtk
    dim = cols.get("text_dim", "#5B7567")
    text = cols.get("text", "#0B1F14")
    bad = cols.get("bad", "#C0341D")
    primary = branding.accent_on(cols.get("background", "#FFFFFF"),
                                 accent=cols.get("primary", "#1FA463"),
                                 strong=cols.get("accent_strong", "#157A49"),
                                 minimum=4.5)
    w, box = _child_window(parent, "Could not start")
    box.pack_start(_eyebrow("// failed", bad), False, False, 0)
    msg = Gtk.Label(xalign=0)
    msg.set_line_wrap(True)
    msg.set_markup(f'<span foreground="{text}" size="11000" weight="bold">'
                   f'{_esc(reason)}</span>')
    box.pack_start(msg, False, False, 0)
    if shell_line:
        sub = Gtk.Label(xalign=0)
        sub.set_line_wrap(True)
        sub.set_markup(f'<span foreground="{dim}" size="10000">'
                       f'You can run it in a shell instead:</span>')
        box.pack_start(sub, False, False, 0)
        code = Gtk.Label(xalign=0)
        code.set_selectable(True)
        code.set_line_wrap(True)
        code.set_markup(f'<span font_family="monospace" foreground="{primary}" '
                        f'size="10500">{_esc(shell_line)}</span>')
        box.pack_start(code, False, False, 0)
    close = Gtk.Button(label="Close")
    close.set_relief(Gtk.ReliefStyle.NONE)
    close.get_style_context().add_class("soc-validate")
    close.set_halign(Gtk.Align.END)
    if isinstance(close.get_child(), Gtk.Label):
        close.get_child().set_markup(f'<span font_family="monospace" '
                                     f'foreground="{primary}" size="9000" '
                                     f'letter_spacing="600">close</span>')
    close.connect("clicked", lambda _b: w.destroy())  # CHILD only, never main_quit
    box.pack_start(close, False, False, 0)
    w.show_all()


def _run_privileged(win, cols, action, *, mode=None, purge=False, on_done=None):
    """Build the elevation argv via host.sysaction and either run it in the live
    progress window or, when neither pkexec nor a terminal exists, show the manual
    shell line. NEVER fails silently."""
    from host import sysaction
    argv, how = sysaction.build_argv(action, mode=mode, purge=purge)
    if how == "manual":
        line = sysaction.manual_hint(action, mode=mode, purge=purge)
        verb = "install / update the wall" if action == "install" else "uninstall the wall"
        _manual_window(win, cols, verb, line)
        return
    title = "Install / Update" if action == "install" else "Uninstall"
    sysaction.run_streamed(win, title, argv, on_done=on_done)


def _on_install(win, cols, installed, on_done):
    """Themed mode-picker BEFORE running install.sh — Desktop (default) vs Kiosk
    appliance, each with its consequence stated inline. On Install -> run_streamed."""
    Gtk = _Launcher.Gtk
    dim = cols.get("text_dim", "#5B7567")
    warn = cols.get("warn", "#B8860B")
    w, box = _child_window(win, "Install / Update")

    verb = "Reinstall / Update" if installed else "Install"
    box.pack_start(_eyebrow(f"// {verb.lower()}", dim), False, False, 0)

    # Two radio cards sharing state. Desktop pre-selected (the safe default).
    rb_desktop = Gtk.RadioButton.new_with_label_from_widget(
        None, "Desktop (keep my boot/DE)")
    rb_kiosk = Gtk.RadioButton.new_with_label_from_widget(
        rb_desktop, "Kiosk appliance")
    rb_desktop.set_active(True)

    def _consequence(parent_rb, markup):
        lbl = Gtk.Label(xalign=0)
        lbl.set_line_wrap(True)
        lbl.set_markup(markup)
        lbl.set_margin_start(24)
        lbl.set_margin_bottom(4)
        return lbl

    box.pack_start(rb_desktop, False, False, 0)
    box.pack_start(_consequence(
        rb_desktop,
        f'<span font_family="monospace" foreground="{dim}" size="9000">'
        f'deploys everything; your login manager/desktop stays — launch the '
        f'wall from this app or <tt>systemctl start soc-wall</tt>.</span>'),
        False, False, 0)
    box.pack_start(rb_kiosk, False, False, 0)
    box.pack_start(_consequence(
        rb_kiosk,
        f'<span foreground="{warn}" size="9000">this box <b>BOOTS</b> into the '
        f'wall — autologin on tty1, no desktop. For a dedicated screen.</span>'),
        False, False, 0)

    if installed:
        note = Gtk.Label(xalign=0)
        note.set_line_wrap(True)
        note.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                        f'size="9000">safe to re-run; packages are skipped unless '
                        f'<tt>--fresh</tt>.</span>')
        box.pack_start(note, False, False, 0)

    btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    btns.set_halign(Gtk.Align.END)
    cancel = Gtk.Button(label="Cancel")
    cancel.connect("clicked", lambda _b: w.destroy())
    primary_btn = Gtk.Button(label=verb)
    primary_btn.get_style_context().add_class("suggested-action")

    def _go(_b):
        mode = "kiosk" if rb_kiosk.get_active() else "desktop"
        w.destroy()
        _run_privileged(win, cols, "install", mode=mode, on_done=on_done)
    primary_btn.connect("clicked", _go)
    btns.pack_start(cancel, False, False, 0)
    btns.pack_start(primary_btn, False, False, 0)
    box.pack_start(btns, False, False, 0)
    w.show_all()
    cancel.grab_focus()  # safe default focus


def _on_uninstall(win, cols, on_done):
    """DOUBLE-confirm danger flow (only reachable when installed). Step 1 lists what
    gets removed + an optional purge checkbox; step 2 is a final explicit confirm.
    Only then does uninstall.sh run (always --force; +--purge if checked)."""
    Gtk = _Launcher.Gtk
    dim = cols.get("text_dim", "#5B7567")
    text = cols.get("text", "#0B1F14")
    bad = cols.get("bad", "#C0341D")
    w, box = _child_window(win, "Uninstall", danger=True)
    box.pack_start(_eyebrow("// REMOVE", bad), False, False, 0)

    intro = Gtk.Label(xalign=0)
    intro.set_line_wrap(True)
    intro.set_markup(f'<span foreground="{text}" size="11000" weight="bold">'
                     f'This removes the deployed SOC wall.</span>')
    box.pack_start(intro, False, False, 0)

    # EXACTLY what uninstall.sh removes on the keep-data path (kept in sync with
    # uninstall.sh: /opt tree, the 5 units, the desktop entries + icon, litebw,
    # sudoers + hardening drop-ins, the tty1 autologin override on kiosk).
    removed = Gtk.Label(xalign=0)
    removed.set_line_wrap(True)
    removed.set_markup(
        f'<span font_family="monospace" foreground="{text}" size="9500">'
        f'• /opt/soc-display (deployed tree)\n'
        f'• units: soc-wall, forti-vpn, autossh-tunnel, soc-tarpit, vaultwarden\n'
        f'• desktop entries + icon, /usr/local/bin/litebw\n'
        f'• sudoers drop-in + hardening drop-ins\n'
        f'• (kiosk) the tty1 autologin override</span>')
    box.pack_start(removed, False, False, 0)

    kept = Gtk.Label(xalign=0)
    kept.set_line_wrap(True)
    kept.set_markup(
        f'<span font_family="monospace" foreground="{dim}" size="9000">'
        f'KEPT unless Purge: /etc/soc-display config + sealed secrets, the '
        f'soc/socsvc/vaultwarden users + homes, the Vaultwarden vault.</span>')
    box.pack_start(kept, False, False, 0)

    purge = Gtk.CheckButton.new_with_label(
        "Also purge config, secrets & users (irreversible)")
    box.pack_start(purge, False, False, 0)

    btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    btns.set_halign(Gtk.Align.END)
    cancel = Gtk.Button(label="Cancel")
    cancel.connect("clicked", lambda _b: w.destroy())
    cont = Gtk.Button(label="Continue…")
    cont.get_style_context().add_class("destructive-action")

    def _step2(_b):
        do_purge = purge.get_active()
        w.destroy()
        w2, box2 = _child_window(win, "Confirm uninstall", danger=True)
        box2.pack_start(_eyebrow("// CONFIRM", bad), False, False, 0)
        msg = Gtk.Label(xalign=0)
        msg.set_line_wrap(True)
        if do_purge:
            txt = ("This permanently removes the deployed wall AND your config, "
                   "secrets and users — this cannot be undone.")
        else:
            txt = "This permanently removes the deployed wall."
        msg.set_markup(f'<span foreground="{text}" size="11000" weight="bold">'
                       f'{_esc(txt)}</span>')
        box2.pack_start(msg, False, False, 0)
        b2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        b2.set_halign(Gtk.Align.END)
        c2 = Gtk.Button(label="Cancel")
        c2.connect("clicked", lambda _x: w2.destroy())
        go = Gtk.Button(label="Uninstall")
        go.get_style_context().add_class("destructive-action")

        def _do(_x):
            w2.destroy()
            _run_privileged(win, cols, "uninstall", purge=do_purge, on_done=on_done)
        go.connect("clicked", _do)
        b2.pack_start(c2, False, False, 0)
        b2.pack_start(go, False, False, 0)
        box2.pack_start(b2, False, False, 0)
        w2.show_all()
        c2.grab_focus()
    cont.connect("clicked", _step2)
    btns.pack_start(cancel, False, False, 0)
    btns.pack_start(cont, False, False, 0)
    box.pack_start(btns, False, False, 0)
    w.show_all()
    cancel.grab_focus()


def _build_window():
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, Gdk, GLib, Pango
    import threading
    from host import health

    b = branding.load()
    cols = b.get("colors", {})

    # CHEAP sync state — drives the config line, the initial neutral dot and the
    # first-run steering, all instantly (no socket, no blocking). The slow probe
    # runs later on a thread.
    try:
        sync = health.sync_state()
        # is_installed() is SYNC-class (cheap os.path.exists / pwd) — drives the
        # adaptive // system group (Install hero vs Reinstall + Uninstall). Same
        # guard as sync_state: install-state probing must never block the open.
        inst = health.is_installed()
    except Exception:  # noqa: BLE001 — health must never block the launcher opening
        sync = {"overall_sync": "unconfigured", "panels_path": None,
                "panels_tier": "none", "panels_count": None, "panels_valid": None,
                "config_error": None, "vault_note": None, "vault_url_hostport": None,
                "vpn_configured": False, "configured": False}
        inst = {"installed": False, "reason": "health unavailable"}

    # An in-place refresh (Install/Uninstall -> _refresh) rebuilds the window, so drop
    # the PREVIOUS screen-scoped provider before adding the new one — otherwise each
    # rebuild stacks another whole-screen provider (memory + re-parse cost, and stale
    # providers keep painting since _reapply only repaints the newest). First call is a
    # no-op (provider is None). Mirrors appearance.py / sysaction.py teardown.
    if _Launcher.provider is not None:
        try:
            Gtk.StyleContext.remove_provider_for_screen(
                Gdk.Screen.get_default(), _Launcher.provider)
        except Exception:  # noqa: BLE001 — narrow: only guards the GTK remove call
            pass
    provider = Gtk.CssProvider()
    _Launcher.Gtk, _Launcher.Gdk = Gtk, Gdk   # set BEFORE _css() so the motion gate reads Settings
    provider.load_from_data(_css())
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _Launcher.provider = provider

    win = Gtk.Window(title=b.get("short_name") or b.get("name") or "SOC Video Wall")
    win.get_style_context().add_class("soc-launcher")
    # Dynamic sizing: size to content, resizable, with a comfortable minimum width.
    win.set_resizable(True)
    win.set_default_size(-1, -1)
    win.set_position(Gtk.WindowPosition.CENTER)
    icon = branding.icon_path()
    if icon:
        try:
            win.set_icon_from_file(icon)
        except Exception:
            pass

    root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    # min width bumped for the three grouped sections so they never clip.
    root.set_size_request(380, -1)
    win.add(root)

    # --- header --------------------------------------------------------------
    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    header.get_style_context().add_class("soc-header")
    if icon:
        try:
            from gi.repository import GdkPixbuf
            px = GdkPixbuf.Pixbuf.new_from_file_at_size(icon, 40, 40)
            header.pack_start(Gtk.Image.new_from_pixbuf(px), False, False, 0)
        except Exception:
            pass
    htext = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
    htext.set_valign(Gtk.Align.CENTER)
    primary = cols.get("primary", "#1FA463")
    # The header + cards sit on surface_top; the brand accent (primary) dips below
    # AA on that tinted surface in the default light theme, so route on-surface
    # accent TEXT/GLYPHS through accent_on (keeps primary where it reads, swaps to
    # accent_strong where it wouldn't). Brand fills/borders keep using primary.
    s_top = cols.get("surface_top", "#F4F8F5")
    accent_top = branding.accent_on(s_top, accent=primary,
                                    strong=cols.get("accent_strong", "#157A49"))
    dim = cols.get("text_dim", "#5B7567")
    # '//'-overline (mono, dim) above the wide-tracked green name eyebrow — the
    # kept comment-style + terminal-console signature, recoloured to SOC-green.
    over = Gtk.Label(xalign=0)
    over.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                    f'size="8200" letter_spacing="800">// launcher</span>')
    name_spaced = _esc(b.get("name", "SOC Video Wall")).upper().replace(" ", "&#160;")
    eyebrow = Gtk.Label(xalign=0)
    eyebrow.set_markup(f'<span font_family="monospace" foreground="{accent_top}" '
                       f'size="9000" weight="bold" letter_spacing="2600">{name_spaced}</span>')
    sub = Gtk.Label(xalign=0)
    sub.set_markup(f'<span foreground="{dim}" size="9500">'
                   f'{_esc(b.get("tagline", "Operations console"))}</span>')
    htext.pack_start(over, False, False, 0)
    htext.pack_start(eyebrow, False, False, 0)
    htext.pack_start(sub, False, False, 0)

    # ACTIVE-CONFIG line (item 3): one quiet mono line saying what WILL launch —
    # path · panel count · vault note. Built from the SYNC state so it appears
    # instantly with the window. The tier (which file won) goes in the tooltip to
    # keep the line short. Never prints a secret (panels path + note name only).
    p = sync.get("panels_path")
    if p:
        seg_path = f"config · {_esc(_shorten_path(p))}"
    else:
        seg_path = "config · (none — run Setup)"
    if sync.get("panels_valid") is False:
        seg_count = "INVALID config"
    elif sync.get("panels_count") is not None:
        n = sync["panels_count"]
        seg_count = f"{n} panel{'' if n == 1 else 's'}"
    elif p:
        seg_count = "count n/a"
    else:
        seg_count = None
    note = sync.get("vault_note")
    seg_vault = f"vault: {_esc(note)}" if note else None
    line = " · ".join(s for s in (seg_path, seg_count, seg_vault) if s)
    cfgline = Gtk.Label(xalign=0)
    cfgline.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                       f'size="8500">{line}</span>')
    cfgline.set_margin_top(3)
    cfgline.set_ellipsize(Pango.EllipsizeMode.END)
    tier = sync.get("panels_tier")
    cfgline.set_tooltip_text(f"{p}\nsource: {tier}" if p else "no config resolved — run Setup")
    htext.pack_start(cfgline, False, False, 0)

    header.pack_start(htext, True, True, 0)

    # --- header right column: honest status dot + decodable label + Validate ----
    hright = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    hright.set_valign(Gtk.Align.START)

    # The dot starts NEUTRAL (grey "checking…") — the slow probe recolours it via
    # idle_add. dot_for() owns the colour/label mapping so the dot and Validate
    # never disagree. A label next to the dot makes the colour decodable; a tooltip
    # carries the same word so colour is never the only signal.
    init_level, init_label = health.dot_for(sync, None)
    dotbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    dotbox.set_halign(Gtk.Align.END)
    dot = Gtk.Label()
    dot.set_markup(_dot_markup(cols, init_level, primary))
    dotlabel = Gtk.Label()
    dotlabel.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                        f'size="8200" letter_spacing="600">{_esc(init_label)}</span>')
    dotbox.pack_start(dot, False, False, 0)
    dotbox.pack_start(dotlabel, False, False, 0)
    dotbox.set_tooltip_text(init_label)
    hright.pack_start(dotbox, False, False, 0)

    def _recolour_dot(level, label):
        # MAIN-THREAD only (called via idle_add). Single source = dot_for/full_check.
        dot.set_markup(_dot_markup(cols, level, primary))
        dotlabel.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                            f'size="8200" letter_spacing="600">{_esc(label)}</span>')
        dotbox.set_tooltip_text(label)

    # Validate (item 4): a quiet link that runs the doctor checks off-thread and
    # shows the result inline (PASS) or the first failing cause (themed transient
    # child window — NOT guierror.show(), which would nest a Gtk.main loop).
    vbtn = Gtk.Button(label="Validate")
    vbtn.set_relief(Gtk.ReliefStyle.NONE)
    vbtn.set_halign(Gtk.Align.END)
    vbtn.get_style_context().add_class("soc-validate")
    vlbl = vbtn.get_child()
    if isinstance(vlbl, Gtk.Label):
        vlbl.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                        f'size="8200" letter_spacing="600">validate</span>')

    def _validate_done(result):
        vbtn.set_sensitive(True)
        if isinstance(vbtn.get_child(), Gtk.Label):
            vbtn.get_child().set_markup(
                f'<span font_family="monospace" foreground="{dim}" '
                f'size="8200" letter_spacing="600">validate</span>')
        # Validate and the passive dot share ONE source: recolour from this result.
        level, label = health.dot_for(result, result)
        _recolour_dot(level, label)
        if result.get("overall") == "pass":
            _flash_validate(vbtn, cols, "✓ checks passed", cols.get("good", primary))
        else:
            cause = result.get("first_cause") or "validation failed"
            _show_result_window(win, cols, cause, result)
        return False  # idle_add one-shot

    def _validate_run():
        try:
            res = health.full_check()
        except Exception as e:  # noqa: BLE001 — surface, never crash the thread
            res = {"overall": "fail", "first_cause": f"validate error: {e}",
                   "panels_valid": None}
        GLib.idle_add(_validate_done, res)

    def _on_validate(_b):
        vbtn.set_sensitive(False)
        if isinstance(vbtn.get_child(), Gtk.Label):
            vbtn.get_child().set_markup(
                f'<span font_family="monospace" foreground="{dim}" '
                f'size="8200" letter_spacing="600">validating…</span>')
        threading.Thread(target=_validate_run, daemon=True).start()
    vbtn.connect("clicked", _on_validate)
    hright.pack_start(vbtn, False, False, 0)

    header.pack_start(hright, False, False, 0)
    root.pack_start(header, False, False, 0)

    # PROBE: kick the slow facets (vault reachability, vpn up) on a background
    # thread AFTER the window is built, so the launcher opens instantly on the
    # neutral dot. The result hops back to the main thread to recolour.
    def _probe_run():
        try:
            probe = health.probe_state(sync)
            level, label = health.dot_for(sync, probe)
        except Exception:  # noqa: BLE001 — unknown -> stay neutral/amber, never hang
            level, label = "amber", "unknown"
        GLib.idle_add(_recolour_dot, level, label)
    threading.Thread(target=_probe_run, daemon=True).start()

    # --- body: the grouped action cards --------------------------------------
    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    body.get_style_context().add_class("soc-body")
    root.pack_start(body, True, True, 0)

    text = cols.get("text", "#0B1F14")

    # IN-PLACE REFRESH (item 4): after an in-process action completes (Install,
    # Uninstall) re-read health + rebuild the control center so the operator lands
    # back on a fresh 'start'. Implemented by destroying THIS window and building a
    # new one in the SAME Gtk.main loop — _Launcher.refreshing suppresses the
    # destroy->main_quit so the loop survives the swap.
    def _refresh(_rc=None):
        _Launcher.refreshing = True
        win.destroy()
        new_win, _ = _build_window()
        new_win.show_all()
        return False  # idle_add one-shot if ever scheduled

    def on(action):
        def _cb(_btn):
            # Appearance opens IN-PROCESS as a child window (so a live colour change
            # recolours THIS launcher) and the menu stays open. Install/Uninstall run
            # IN-PROCESS too (confirm dialog -> progress window -> _refresh in place).
            # Every other tile spawns its detached helper and closes the menu.
            if action is launch_appearance:
                _open_appearance(win)
                return
            if action == _ACT_INSTALL:
                _on_install(win, cols, inst.get("installed", False), _refresh)
                return
            if action == _ACT_UNINSTALL:
                _on_uninstall(win, cols, _refresh)
                return
            # Spawn tiles (Run desktop/kiosk, Setup) return (ok, reason). Only quit the
            # loop when the helper actually STARTED; on failure keep the launcher open
            # and surface the cause (the menu's stderr is discarded under .desktop) so
            # the single entry point is never a silent dead-end.
            result = action()
            ok, reason = result if isinstance(result, tuple) else (bool(result), "")
            if ok:
                win.destroy()  # helper started; hand off + close the menu as before
            else:
                # Offer a copy-pasteable shell line where we can name one.
                shell_line = ""
                if action is launch_setup:
                    shell_line = f"python3 {os.path.join(ROOT, 'setup.py')} wizard"
                _launch_error_window(win, cols,
                                     reason or "the helper could not be started",
                                     shell_line)
        return _cb

    # ADAPTIVE STATE (item 2): the install state tells a story.
    #  * NOT installed -> Install is the HERO (emphasised); the Run tiles dim with an
    #    'install first' hint (nothing to run yet). Uninstall is hidden (nothing to
    #    remove). Install reads "Install".
    #  * installed -> Run is the hero; Install reads "Reinstall / Update" (not
    #    emphasised); Uninstall sits enabled in the quiet // system group (.soc-danger).
    # When installed-but-unconfigured, Setup also gets the emphasis + Run still dims
    # (it would only fail) — generalising the old first-run steering to BOTH signals.
    installed = bool(inst.get("installed"))
    unconfigured = sync.get("overall_sync") == "unconfigured"
    _RUN_TILES = {"soc-desktop", "soc-kiosk"}
    # Run dims when there's nothing to run yet (not installed) OR nothing configured.
    dim_run = (not installed) or unconfigured

    def _make_card(glyph, title, subtitle, tag, css_class, colour_key, action):
        accent = branding.color(colour_key)
        # The glyph + '▸' mark are accent-coloured TEXT/ICONS on the card surface
        # (surface_top); route them through accent_on so the brand green (which dips
        # below AA on the tinted surface in the light theme) is swapped for the
        # stronger accent only where needed. The card left-border keeps `accent`.
        accent_glyph = branding.accent_on(
            cols.get("surface_top", "#F4F8F5"), accent=accent,
            strong=cols.get("accent_strong", "#157A49"))
        steer_off = dim_run and css_class in _RUN_TILES
        emphasise = False
        if not installed and css_class == "soc-install":
            emphasise = True            # hero: set this box up first
        elif installed and unconfigured and css_class == "soc-setup":
            emphasise = True            # installed but empty -> steer to Setup
        # Adaptive copy: Install title/subtitle flip once installed.
        if css_class == "soc-install":
            title = "Reinstall / Update" if installed else "Install"
            subtitle = ("Re-run or update the deployment" if installed
                        else "Set this box up first")
        btn = Gtk.Button()
        btn.set_relief(Gtk.ReliefStyle.NONE)
        btn.get_style_context().add_class("soc-card")
        btn.get_style_context().add_class(css_class)
        if css_class == "soc-uninstall":
            btn.get_style_context().add_class("soc-danger")  # the only danger tile
        if steer_off:
            btn.set_sensitive(False)               # they'd only fail -> honest disable
            btn.get_style_context().add_class("soc-disabled")
        elif emphasise:
            btn.get_style_context().add_class("soc-emphasis")

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        gimg = _glyph_image(glyph, accent_glyph, px=22)
        gimg.set_valign(Gtk.Align.START)
        gimg.set_margin_top(1)
        row.pack_start(gimg, False, False, 0)

        txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t = Gtk.Label(xalign=0)
        t.set_markup(f'<span foreground="{text}" size="12800" weight="bold" '
                     f'letter_spacing="-300">{_esc(title)}</span>')
        s = Gtk.Label(xalign=0)
        # when steered-off, the subtitle becomes the honest 'install first' hint.
        sub_text = "install first" if steer_off else subtitle
        s.set_markup(f'<span foreground="{dim}" size="9800">{_esc(sub_text)}</span>')
        txt.pack_start(t, False, False, 0)
        txt.pack_start(s, False, False, 0)
        row.pack_start(txt, True, True, 0)
        if tag and not steer_off:
            tg = Gtk.Label()
            tg.get_style_context().add_class("soc-tag")
            tg.set_valign(Gtk.Align.CENTER)
            tg.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                          f'size="8200" letter_spacing="800">{_esc(tag)}</span>')
            row.pack_start(tg, False, False, 0)
        mark = Gtk.Label()
        mark.set_valign(Gtk.Align.CENTER)
        mark.set_markup(f'<span font_family="monospace" foreground="{accent_glyph}" '
                        f'size="11000">▸</span>')
        row.pack_start(mark, False, False, 0)
        btn.add(row)
        btn.connect("clicked", on(action))
        return btn

    # GROUPED build: emit a dim '// <section>' eyebrow when the section changes, then
    # its cards. Uninstall is omitted entirely when nothing is installed.
    cur_section = None
    for section, glyph, title, subtitle, tag, css_class, colour_key, action in _ENTRIES:
        if css_class == "soc-uninstall" and not installed:
            continue  # nothing to remove yet — hide the tile entirely
        if section != cur_section:
            cur_section = section
            eb = Gtk.Label(xalign=0)
            eb.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                          f'size="8200" letter_spacing="800">// {section}</span>')
            eb.set_margin_top(6 if section != _SECTIONS[0] else 0)
            eb.set_margin_bottom(1)
            body.pack_start(eb, False, False, 0)
        body.pack_start(
            _make_card(glyph, title, subtitle, tag, css_class, colour_key, action),
            False, False, 0)

    # Destroy quits the loop UNLESS we're swapping windows for an in-place refresh.
    def _on_destroy(_w):
        if _Launcher.refreshing:
            _Launcher.refreshing = False   # the new window owns the loop now
            return
        Gtk.main_quit()
    win.connect("destroy", _on_destroy)
    # One collect after the whole tree is built reclaims the many short-lived Python
    # wrappers GTK construction creates, before Gtk.main() idles. One-shot, cheap.
    import gc
    gc.collect()
    return win, Gtk


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--check" in argv:               # CI: verify wiring, no GTK / no display
        # SIX tiles now, each an 8-tuple (section, glyph, title, sub, tag, class,
        # colour_key, action) with a callable-or-sentinel action.
        assert len(_ENTRIES) == 6
        assert all(len(e) == 8 for e in _ENTRIES), "every entry is an 8-tuple"
        assert all(callable(e[-1]) or e[-1] in (_ACT_INSTALL, _ACT_UNINSTALL)
                   for e in _ENTRIES), "action must be callable or a known sentinel"
        # every tile lives under a known // section.
        assert all(e[0] in _SECTIONS for e in _ENTRIES), "unknown section in _ENTRIES"
        by_class = {e[5]: e for e in _ENTRIES}
        assert by_class["soc-appearance"][-1] is launch_appearance
        assert by_class["soc-install"][-1] == _ACT_INSTALL
        assert by_class["soc-uninstall"][-1] == _ACT_UNINSTALL
        # Spawn-tile contract: the helpers return (ok, reason) so the menu can gate
        # win.destroy() on success and surface the cause on failure (never a silent
        # dead-end). A bad argv must fail closed to a (False, reason) tuple.
        ok, reason = _spawn(["/nonexistent/soc-wall-check-binary"])
        assert ok is False and isinstance(reason, str) and reason, "spawn must report failure"
        assert isinstance(_venv_python(), str) and _venv_python(), "venv resolver returns a path"
        # every tile names a known mode glyph (the per-tile inline-SVG icon), and the
        # new system glyphs exist with unicode fallbacks.
        assert all(e[1] in _GLYPHS for e in _ENTRIES), "unknown glyph key in _ENTRIES"
        for g in ("download", "trash"):
            assert g in _GLYPHS and g in _GLYPH_FALLBACK, f"missing glyph {g!r}"
        # the honest dot is health-driven: health must import + map every level
        # headless (no GTK), and dot_for must produce a real (level, label).
        from host import health
        for lvl in ("green", "amber", "red", "neutral"):
            assert any(health.dot_for(*c)[0] == lvl for c in (
                ({"panels_valid": False, "overall_sync": "invalid"}, {}),
                ({"overall_sync": "unconfigured"}, None),
                ({"overall_sync": "configured", "panels_valid": True,
                  "vault_url_hostport": None, "vpn_configured": False},
                 {"vault_reachable": None, "vpn_state": "not_configured"}),
                ({"overall_sync": "configured", "panels_valid": True}, None),
            )), f"health.dot_for never yields {lvl!r}"
        # the adaptive system group is driven by health.is_installed() — it must be
        # present and return a bool `installed` headless.
        inst = health.is_installed()
        assert isinstance(inst.get("installed"), bool), "is_installed missing/bad"
        # host.sysaction (the privileged runner) must import + wire headless too.
        from host import sysaction
        assert sysaction._check() == 0, "sysaction wiring check failed"
        branding.load()                 # branding must load without raising
        print("launchermenu ok")
        return 0
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        sys.stderr.write("soc-wall menu: no graphical display "
                         "(run this from your desktop session).\n")
        return 1
    win, Gtk = _build_window()
    win.show_all()
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
