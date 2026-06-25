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


# (num, title, subtitle, tag, css_class, colour_key, action). `num` is the mono
# tile numeral watermark (01/02/03/04); colour_key indexes host.branding colours
# so a rebrand recolours the cards.
_ENTRIES = (
    ("01", "Setup / Configure", "Panels, vault and VPN", "", "soc-setup", "setup",
     launch_setup),
    ("02", "Desktop mode", "Run the wall in a window", "windowed", "soc-desktop", "desktop",
     lambda: launch_wall("--window")),
    ("03", "Kiosk mode", "Fill this display, no desktop", "fullscreen", "soc-kiosk", "kiosk",
     lambda: launch_wall("--fullscreen")),
    ("04", "Appearance", "Theme colours & presets", "", "soc-appearance", "primary",
     launch_appearance),
)


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _rgba(hexc: str, alpha: float) -> str:
    h = (hexc or "").lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    try:
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        r, g, b = 136, 136, 136
    return f"rgba({r},{g},{b},{alpha})"


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

    def card(cls, ac):
        # flat fill at rest; on hover the accent left-border, an inset accent ring
        # and the green focus glow lift the card off the white field.
        return (f".{cls} {{ border-left-color: {ac}; }}\n"
                f".{cls}:hover {{ border-color: {ac};\n"
                f"  box-shadow: inset 0 0 0 1px {ac}, 0 6px 18px {glow}; }}")

    return f"""
window.soc-launcher {{ background-color: {bg}; }}
.soc-header {{ background-color: {s_top};
  border-top: 2px solid {accent_strong};
  border-bottom: 1px solid {border}; padding: 18px 20px 16px 20px; }}
.soc-body {{ padding: 16px 18px 20px 18px; background-color: {bg}; }}
.soc-card {{ background-color: {s_top};
  border: 1px solid {border}; border-left: 4px solid {border}; border-radius: 6px;
  padding: 13px 16px; transition: all 160ms ease; }}
.soc-card:hover {{ background-color: {s_bot}; }}
.soc-card:focus {{ outline: none; }}
{card("soc-setup", setup)}
{card("soc-desktop", desktop)}
{card("soc-kiosk", kiosk)}
{card("soc-appearance", appearance)}
.soc-tag {{ background-color: {s_bot}; border: 1px solid {border};
  border-radius: 4px; padding: 2px 9px; color: {text_dim}; }}
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


def _build_window():
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, Gdk

    b = branding.load()
    cols = b.get("colors", {})

    provider = Gtk.CssProvider()
    provider.load_from_data(_css())
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    _Launcher.provider = provider
    _Launcher.Gtk, _Launcher.Gdk = Gtk, Gdk

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
    header.pack_start(htext, True, True, 0)
    # live SOC-green status dot = ONLINE/secure (uses `good`, falls back to accent).
    dot = Gtk.Label()
    dot.set_valign(Gtk.Align.START)
    dot.set_markup(f'<span foreground="{cols.get("good", primary)}" size="11000">●</span>')
    header.pack_start(dot, False, False, 0)
    root.pack_start(header, False, False, 0)

    # --- body: the action cards ----------------------------------------------
    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=11)
    body.get_style_context().add_class("soc-body")
    root.pack_start(body, True, True, 0)

    # '//'-section header above the numbered action tiles (mono, dim).
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

    for num, title, subtitle, tag, css_class, colour_key, action in _ENTRIES:
        accent = branding.color(colour_key)
        btn = Gtk.Button()
        btn.set_relief(Gtk.ReliefStyle.NONE)
        btn.get_style_context().add_class("soc-card")
        btn.get_style_context().add_class(css_class)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        # mono '01/02/03' numeral watermark: low-opacity accent behind the title.
        numl = Gtk.Label()
        numl.set_valign(Gtk.Align.START)
        # Pango `alpha` (0-65535) renders the numeral as a ~30%% accent watermark;
        # `foreground` itself only accepts a solid colour spec, not rgba().
        numl.set_markup(f'<span font_family="monospace" foreground="{accent}" alpha="30%" '
                        f'size="20000" weight="bold">{_esc(num)}</span>')
        row.pack_start(numl, False, False, 0)

        txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t = Gtk.Label(xalign=0)
        # title in near-black-green display bold with tight tracking (sans, technical).
        t.set_markup(f'<span foreground="{text}" size="12800" weight="bold" '
                     f'letter_spacing="-300">{_esc(title)}</span>')
        s = Gtk.Label(xalign=0)
        s.set_markup(f'<span foreground="{dim}" size="9800">{_esc(subtitle)}</span>')
        txt.pack_start(t, False, False, 0)
        txt.pack_start(s, False, False, 0)
        row.pack_start(txt, True, True, 0)
        if tag:
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
