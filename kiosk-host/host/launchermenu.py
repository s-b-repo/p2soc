"""
GTK launcher menu for the SOC video-wall — shown when the desktop icon
(soc-wall.desktop) is clicked. It does NOT take over the machine; it offers:

  * Setup / Configure        -> the setup wizard (GUI if available, else TTY)
  * Desktop mode             -> the wall windowed on the current display
  * Kiosk mode               -> the wall fullscreen on the current display

Each choice spawns the matching helper (detached) and the menu closes. The name,
tagline, icon and accent colours come from host.branding (edit branding/branding
.yaml to rebrand). Styled via a Gtk.CssProvider; the window sizes to its content
and is resizable. Pure PyGObject/GTK3 + stdlib.

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


def _spawn(argv, cwd=None, env=None) -> bool:
    """Start a helper in its own session so the menu can exit without killing it."""
    try:
        subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True)
        return True
    except OSError as e:
        sys.stderr.write(f"soc-wall menu: could not launch {argv[0]}: {e}\n")
        return False


def launch_wall(mode: str) -> bool:
    """mode: '--fullscreen' (kiosk) or '--window' (desktop)."""
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
    return _spawn([sys.executable, "-m", "host.main"], cwd=kiosk, env=env)


def launch_setup() -> bool:
    """Prefer the GUI setup wizard; fall back to the TTY wizard in a terminal."""
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
    sys.stderr.write("soc-wall menu: no setup wizard available "
                     "(run 'python3 setup.py wizard').\n")
    return False


def launch_appearance() -> bool:
    """Open the theme/appearance editor. Prefer the shell wrapper (detached, so the
    menu can stay open / exit independently); fall back to spawning the module."""
    sh = _script("soc-wall-appearance.sh")
    if os.path.exists(sh):
        return _spawn(["bash", sh])
    kiosk = os.path.join(ROOT, "kiosk-host")
    env = dict(os.environ)
    env["PYTHONPATH"] = kiosk + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return _spawn([sys.executable, "-m", "host.appearance"], cwd=kiosk, env=env)


# (glyph, title, subtitle, tag, css_class, colour_key, action). `glyph` names the
# per-tile mode icon (a themed inline-SVG, see _GLYPHS / _glyph_image) — these are
# PARALLEL choices, so an action-describing glyph beats a numeral that would imply a
# sequence. colour_key indexes host.branding colours so a rebrand recolours the
# cards AND their glyphs. (The wizard's '// step NN' IS a sequence — left numbered.)
_ENTRIES = (
    ("gear", "Setup / Configure", "Panels, vault and VPN", "", "soc-setup", "setup",
     launch_setup),
    ("window", "Desktop mode", "Run the wall in a window", "windowed", "soc-desktop", "desktop",
     lambda: launch_wall("--window")),
    ("expand", "Kiosk mode", "Fill this display, no desktop", "fullscreen", "soc-kiosk", "kiosk",
     lambda: launch_wall("--fullscreen")),
    ("swatch", "Appearance", "Theme colours & presets", "", "soc-appearance", "primary",
     launch_appearance),
)


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
def _svg_gear(ac: str) -> str:
    # cog: outer circle + 8 short radial teeth + inner hub — "configure".
    teeth = ""
    import math
    for i in range(8):
        a = i * math.pi / 4
        x1, y1 = 12 + 7.2 * math.cos(a), 12 + 7.2 * math.sin(a)
        x2, y2 = 12 + 9.6 * math.cos(a), 12 + 9.6 * math.sin(a)
        teeth += f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}"/>'
    return (f'<g fill="none" stroke="{ac}" stroke-width="1.7" '
            f'stroke-linecap="round">{teeth}'
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


_GLYPHS = {"gear": _svg_gear, "window": _svg_window,
           "expand": _svg_expand, "swatch": _svg_swatch}
# Unicode fallback per glyph (themed Pango) if the SVG loader is unavailable.
_GLYPH_FALLBACK = {"gear": "⚙", "window": "▢",
                   "expand": "⤢", "swatch": "▦"}


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


def _css() -> bytes:
    """Build the launcher stylesheet from the branding palette: a crisp green-on-
    white technical console — flat surfaces, thin accent left-borders, low radius,
    a green hover glow. Every colour flows from branding so a rebrand reskins it."""
    c = branding.load().get("colors", {})

    def col(k, d):
        return c.get(k) or d
    bg = col("background", "#FFFFFF")
    s_top = col("surface_top", "#F4F8F5")
    s_bot = col("surface_bottom", "#EAF1EC")
    border = col("border", "#CFE0D4")
    accent = col("primary", "#1FA463")
    accent_strong = col("accent_strong", "#157A49")
    text_dim = col("text_dim", "#5B7567")
    setup, desktop, kiosk = (col("setup", "#1FA463"), col("desktop", "#1FA463"),
                             col("kiosk", "#0E7C7B"))
    appearance = col("primary", "#1FA463")  # the Appearance tile uses the brand accent
    glow = _rgba(accent, 0.28)
    emph_glow = _rgba(accent, 0.22)

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
.soc-tag {{ background-color: {s_bot}; border: 1px solid {border};
  border-radius: 4px; padding: 2px 9px; color: {text_dim}; }}
/* first-run empty state: dim tiles that would only fail, emphasise Setup. */
.soc-disabled {{ opacity: 0.45; }}
.soc-emphasis {{ border-left-width: 4px; border-left-color: {accent};
  box-shadow: inset 0 0 0 1px {accent}, 0 4px 14px {emph_glow}; }}
.soc-validate {{ padding: 1px 6px; border-radius: 4px; }}
.soc-validate:hover {{ background-color: {s_bot}; }}
""".encode()


class _Launcher:
    """A tiny holder so an in-launcher Appearance edit can repaint the launcher's
    ONE cached CssProvider live (re-adding a provider to the screen would stack
    duplicates = a leak + cumulative parse cost). Built once in _build_window."""
    provider = None
    Gtk = None
    Gdk = None


def _reapply():
    """Repaint the launcher's cached provider from the (refreshed) branding palette
    — the in-launcher Appearance editor calls this after a live colour change so the
    open launcher window recolours instantly. No new provider is added to the screen."""
    if _Launcher.provider is not None:
        _Launcher.provider.load_from_data(_css())


def _open_appearance(parent_win):
    """Open the Appearance editor IN-PROCESS as a child window so a live colour
    change recolours the open launcher (on_apply -> _reapply). gi is already loaded
    here (we're in the launcher GUI), so this never re-pays the GTK import cost."""
    from host import appearance  # lazy; gi already up in this codepath
    Gtk, Gdk = _Launcher.Gtk, _Launcher.Gdk
    from gi.repository import GdkPixbuf

    def on_apply(colors):
        # Monkeypatch branding's in-memory palette so _css() reflects the preview,
        # then repaint the launcher's cached provider (no persistence yet).
        cur = branding.load()
        cur.setdefault("colors", {}).update(colors)
        _reapply()

    def on_saved(_colors):
        branding.load(refresh=True)   # pick up the persisted palette
        _reapply()

    editor = appearance.AppearanceEditor((Gtk, Gdk, GdkPixbuf),
                                         on_apply=on_apply, on_saved=on_saved)
    win = editor.build_window()
    win.set_transient_for(parent_win)
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
    primary = cols.get("primary", "#1FA463")
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
    except Exception:  # noqa: BLE001 — health must never block the launcher opening
        sync = {"overall_sync": "unconfigured", "panels_path": None,
                "panels_tier": "none", "panels_count": None, "panels_valid": None,
                "config_error": None, "vault_note": None, "vault_url_hostport": None,
                "vpn_configured": False, "configured": False}

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
    root.set_size_request(360, -1)
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
    dim = cols.get("text_dim", "#5B7567")
    # '//'-overline (mono, dim) above the wide-tracked green name eyebrow — the
    # kept comment-style + terminal-console signature, recoloured to SOC-green.
    over = Gtk.Label(xalign=0)
    over.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                    f'size="8200" letter_spacing="800">// launcher</span>')
    name_spaced = _esc(b.get("name", "SOC Video Wall")).upper().replace(" ", "&#160;")
    eyebrow = Gtk.Label(xalign=0)
    eyebrow.set_markup(f'<span font_family="monospace" foreground="{primary}" '
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

    # --- body: the action cards ----------------------------------------------
    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=11)
    body.get_style_context().add_class("soc-body")
    root.pack_start(body, True, True, 0)

    # '//'-section header above the action tiles (mono, dim).
    comment = Gtk.Label(xalign=0)
    comment.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                       f'size="8200" letter_spacing="800">// actions</span>')
    comment.set_margin_bottom(2)
    body.pack_start(comment, False, False, 0)

    text = cols.get("text", "#0B1F14")

    def on(action):
        def _cb(_btn):
            # Appearance opens IN-PROCESS as a child window (so a live colour change
            # recolours THIS launcher) and the menu stays open. Every other tile
            # spawns its detached helper and closes the menu.
            if action is launch_appearance:
                _open_appearance(win)
                return
            action()
            win.destroy()
        return _cb

    # FIRST-RUN / EMPTY STATE (item 5): when NOTHING is configured, Desktop+Kiosk
    # would only fail — dim + disable them with a 'configure first' hint and put a
    # branded emphasis on Setup so the eye goes there. A configured (or merely
    # invalid-but-present) box looks UNCHANGED. We key off 'unconfigured' only:
    # 'invalid' is a configured-but-broken RED state, not an empty state.
    unconfigured = sync.get("overall_sync") == "unconfigured"
    _DIM_TILES = {"soc-desktop", "soc-kiosk"}

    for glyph, title, subtitle, tag, css_class, colour_key, action in _ENTRIES:
        accent = branding.color(colour_key)
        steer_off = unconfigured and css_class in _DIM_TILES
        btn = Gtk.Button()
        btn.set_relief(Gtk.ReliefStyle.NONE)
        btn.get_style_context().add_class("soc-card")
        btn.get_style_context().add_class(css_class)
        if steer_off:
            btn.set_sensitive(False)               # they'd only fail -> honest disable
            btn.get_style_context().add_class("soc-disabled")
        elif unconfigured and css_class == "soc-setup":
            btn.get_style_context().add_class("soc-emphasis")  # steer the eye to Setup

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        # Per-tile mode glyph (themed inline-SVG, accent-stroked) replaces the old
        # numeral watermark — it says what the action IS, not a fake sequence.
        gimg = _glyph_image(glyph, accent, px=22)
        gimg.set_valign(Gtk.Align.START)
        gimg.set_margin_top(1)
        row.pack_start(gimg, False, False, 0)

        txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t = Gtk.Label(xalign=0)
        # title in near-black-green display bold with tight tracking (sans, technical).
        t.set_markup(f'<span foreground="{text}" size="12800" weight="bold" '
                     f'letter_spacing="-300">{_esc(title)}</span>')
        s = Gtk.Label(xalign=0)
        # when steered-off, the subtitle becomes the honest 'configure first' hint.
        sub_text = "configure first" if steer_off else subtitle
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
        # mono '▸' marker = the run/select cue, in the card's accent.
        mark = Gtk.Label()
        mark.set_valign(Gtk.Align.CENTER)
        mark.set_markup(f'<span font_family="monospace" foreground="{accent}" '
                        f'size="11000">▸</span>')
        row.pack_start(mark, False, False, 0)
        btn.add(row)
        btn.connect("clicked", on(action))
        body.pack_start(btn, False, False, 0)

    win.connect("destroy", Gtk.main_quit)
    # One collect after the whole tree is built reclaims the many short-lived Python
    # wrappers GTK construction creates, before Gtk.main() idles. One-shot, cheap.
    import gc
    gc.collect()
    return win, Gtk


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--check" in argv:               # CI: verify wiring, no GTK / no display
        assert len(_ENTRIES) == 4 and all(len(e) == 7 and callable(e[-1]) for e in _ENTRIES)
        assert any(e[4] == "soc-appearance" and e[-1] is launch_appearance for e in _ENTRIES)
        # every tile names a known mode glyph (the per-tile inline-SVG icon).
        assert all(e[0] in _GLYPHS for e in _ENTRIES), "unknown glyph key in _ENTRIES"
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
