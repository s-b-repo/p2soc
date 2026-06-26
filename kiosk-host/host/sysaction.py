"""
Privileged system actions for the control center — Install / Update + Uninstall.

A button cannot silently sudo, and a black terminal is not an honest UI. This
module is the bridge between the launcher's // system tiles and the real
install.sh / uninstall.sh: it resolves an elevation path ONCE (graphical polkit
via pkexec; a terminal fallback; else a guierror telling the operator the exact
shell line — NEVER a silent failure), then streams the script's combined output
LIVE into a themed GTK progress window (monospace log, autoscroll, a spinner then
a clear PASS/FAIL with the exit code, Close disabled until done).

GTK is touched ONLY on the main thread: a daemon reader thread iterates the
subprocess output and hands each line to the UI via GLib.idle_add. There is NO gi
import at module load, so `python -m host.sysaction --check` validates the wiring
headless (no display, no pkexec spawned, nothing run).

Test/dev hook: SOC_SYSACTION_CMD=<fake-script> makes build_argv run that script
DIRECTLY (no pkexec, no root) with the same env knobs — the analogue of
SOC_VAULT_BACKEND=dev. The full confirm + progress UI is exercised WITHOUT
mutating the box. NEVER run the real scripts during tests/verify.

Usage:  python -m host.sysaction --check      # headless wiring validator
        python -m host.sysaction --selftest   # drive the progress UI on a fake
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading

ROOT = os.environ.get("SOC_ROOT", "/opt/soc-display")

# The terminals we try, in order, for the no-pkexec fallback (same set the launcher
# uses for the TTY wizard so behaviour is consistent across the app).
_TERMINALS = ("x-terminal-emulator", "gnome-terminal", "konsole",
              "xfce4-terminal", "mate-terminal", "xterm")

# install.sh / uninstall.sh emit ANSI colour (cyan ==> , yellow !! ); strip it so
# the in-window log reads clean. Precompiled once — runs per output line.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _terminal() -> "str | None":
    """First terminal emulator on PATH, or None."""
    return next((t for t in _TERMINALS if shutil.which(t)), None)


def _script_path(action: str) -> str:
    """Resolve the REAL script for an action under ROOT (SOC_ROOT or /opt)."""
    name = "install.sh" if action == "install" else "uninstall.sh"
    return os.path.join(ROOT, name)


def build_argv(action: str, *, mode: "str | None" = None,
               purge: bool = False) -> "tuple[list[str], str]":
    """Resolve the elevation path ONCE for `action` in {'install','uninstall'}.

    Returns (argv, how) where how in {'fake','pkexec','terminal','manual'}:
      * fake     — SOC_SYSACTION_CMD set: run that script DIRECTLY (no root), same
                   env knobs/args, so the UI is exercised without mutating the box.
      * pkexec   — graphical polkit auth; env-var form keeps args secret-free.
      * terminal — no pkexec: x-terminal-emulator/... -e sudo env ... script.
      * manual   — neither available: caller pops guierror with the shell line.

    Never raises; always returns a usable tuple. Install threads INSTALL_MODE via
    the env (mirrors configpaths._install_etc, keeps it out of the visible argv).
    Uninstall ALWAYS passes --force (pkexec/terminal give no tty for its y/N
    reads); --purge only when requested.
    """
    if action not in ("install", "uninstall"):
        raise ValueError(f"unknown action: {action!r}")

    # env knobs passed via `env K=V` so they survive sudo/pkexec and stay readable.
    envparts = []
    extra_args: "list[str]" = []
    if action == "install":
        envparts.append(f"INSTALL_MODE={mode or 'desktop'}")
    else:  # uninstall — no tty for prompts under pkexec/terminal, so force.
        extra_args.append("--force")
        if purge:
            extra_args.append("--purge")

    # DEV/TEST: a fake script stands in for the real one — run it DIRECTLY, no
    # elevation, but with the SAME env knobs + args so the flow is identical.
    fake = os.environ.get("SOC_SYSACTION_CMD")
    if fake:
        argv = [fake] + extra_args
        # Carry the env knob as a leading `env K=V` too so a fake can echo it back,
        # mirroring the real argv shape (tests assert the knob is present).
        if envparts:
            argv = ["env"] + envparts + argv
        return argv, "fake"

    script = _script_path(action)

    if shutil.which("pkexec"):
        # pkexec env <KNOBS> <script> <args> — graphical polkit, secret-free argv.
        argv = ["pkexec", "env"] + envparts + [script] + extra_args
        return argv, "pkexec"

    term = _terminal()
    if term:
        # <term> -e sudo env <KNOBS> <script> <args>. sudo will prompt in the term.
        argv = [term, "-e", "sudo", "env"] + envparts + [script] + extra_args
        return argv, "terminal"

    # NEITHER — the caller shows the exact shell line (manual_hint) instead of
    # executing this argv; still thread the env knob so the shape matches the
    # pkexec/terminal/fake branches (and --check passes where neither pkexec nor a
    # terminal exists, e.g. the CI runner).
    argv = [script] + extra_args
    if envparts:
        argv = ["env"] + envparts + argv
    return argv, "manual"


def manual_hint(action: str, *, mode: "str | None" = None,
                purge: bool = False) -> str:
    """The exact shell line for the manual fallback (no pkexec, no terminal)."""
    script = _script_path(action)
    if action == "install":
        return f"sudo INSTALL_MODE={mode or 'desktop'} {script}"
    bits = [script, "--force"] + (["--purge"] if purge else [])
    return "sudo " + " ".join(bits)


# --------------------------------------------------------------------------- #
# Live progress window — GTK on the MAIN THREAD ONLY. The reader thread never
# touches a widget; it hops every line back via GLib.idle_add. Built lazily so the
# module imports headless.
# --------------------------------------------------------------------------- #
def run_streamed(parent, title, argv, on_done=None):
    """Run `argv`, streaming combined stdout/stderr LIVE into a themed transient
    child window. `on_done(rc)` (optional) fires after the operator closes the
    window, so the launcher can refresh in place. Never blocks the UI; never calls
    Gtk.main_quit (destroys the CHILD only)."""
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, GLib

    from host import branding
    c = branding.load().get("colors", {})
    dim = c.get("text_dim", "#5B7567")
    good = c.get("good", "#1FA463")
    bad = c.get("bad", "#C0341D")

    win = Gtk.Window(title=title)
    win.get_style_context().add_class("soc-launcher")  # reuse the launcher provider
    if parent is not None:
        win.set_transient_for(parent)
        win.set_modal(True)
    win.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
    win.set_resizable(True)
    win.set_default_size(640, 420)

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    box.set_margin_top(16)
    box.set_margin_bottom(16)
    box.set_margin_start(18)
    box.set_margin_end(18)
    win.add(box)

    # // running eyebrow + a spinner (or a static 'running…' under reduced motion).
    headrow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    eyebrow = Gtk.Label(xalign=0)
    eyebrow.set_markup(f'<span font_family="monospace" foreground="{dim}" '
                       f'size="9500" weight="bold" letter_spacing="800">'
                       f'// running</span>')
    headrow.pack_start(eyebrow, False, False, 0)
    animate = True
    try:
        s = Gtk.Settings.get_default()
        if s is not None:
            animate = bool(s.get_property("gtk-enable-animations"))
    except Exception:  # noqa: BLE001 — no settings -> assume animations on
        animate = True
    spinner = None
    if animate:
        spinner = Gtk.Spinner()
        spinner.start()
        spinner.set_halign(Gtk.Align.END)
        headrow.pack_end(spinner, False, False, 0)
    else:
        stat = Gtk.Label()
        stat.set_markup(f'<span foreground="{dim}" size="9000">running…</span>')
        stat.set_halign(Gtk.Align.END)
        headrow.pack_end(stat, False, False, 0)
    box.pack_start(headrow, False, False, 0)

    # monospace log in a scroller — autoscrolls to the end mark on each append.
    sw = Gtk.ScrolledWindow()
    sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    sw.set_min_content_height(280)
    sw.set_min_content_width(560)
    view = Gtk.TextView()
    view.set_editable(False)
    view.set_cursor_visible(False)
    view.set_monospace(True)   # GTK picks the themed monospace; no override needed.
    view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    sw.add(view)
    box.pack_start(sw, True, True, 0)
    buf = view.get_buffer()

    btnrow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    btnrow.set_halign(Gtk.Align.END)
    close = Gtk.Button(label="Close")
    close.set_sensitive(False)               # disabled until the process exits
    btnrow.pack_start(close, False, False, 0)
    box.pack_start(btnrow, False, False, 0)

    state = {"rc": None}

    def _append(line: str):
        # MAIN-THREAD only (via idle_add). Append + autoscroll to the end mark.
        end = buf.get_end_iter()
        buf.insert(end, _strip_ansi(line))
        mark = buf.create_mark(None, buf.get_end_iter(), False)
        view.scroll_to_mark(mark, 0.0, False, 0, 0)
        buf.delete_mark(mark)
        return False  # idle_add one-shot

    def _finish(rc: int):
        state["rc"] = rc
        if spinner is not None:
            spinner.stop()
            spinner.hide()
        ok = rc == 0
        colour = good if ok else bad
        word = f"// done — exit {rc}" if ok else f"// failed — exit {rc}"
        eyebrow.set_markup(f'<span font_family="monospace" foreground="{colour}" '
                           f'size="9500" weight="bold" letter_spacing="800">'
                           f'{word}</span>')
        close.set_sensitive(True)
        close.grab_focus()
        return False  # idle_add one-shot

    def _reader(proc):
        # DAEMON THREAD — never touches a widget; only GLib.idle_add.
        try:
            for line in proc.stdout:
                GLib.idle_add(_append, line)
        except Exception as e:  # noqa: BLE001 — surface the read fault in the log
            GLib.idle_add(_append, f"\n[sysaction: read error: {e}]\n")
        finally:
            try:
                rc = proc.wait()
            except Exception:  # noqa: BLE001
                rc = -1
            GLib.idle_add(_finish, rc)

    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True)
    except OSError as e:
        # Couldn't even spawn — show it in the window and finish FAIL, never hang.
        GLib.idle_add(_append, f"could not launch: {e}\n")
        GLib.idle_add(_finish, -1)
    else:
        threading.Thread(target=_reader, args=(proc,), daemon=True).start()

    def _on_close(_b):
        rc = state["rc"]
        win.destroy()                         # CHILD only — never Gtk.main_quit
        if on_done is not None and rc is not None:
            on_done(rc)
    close.connect("clicked", _on_close)
    # Closing via the WM 'x' also refreshes (only meaningful once done).
    win.connect("destroy", lambda _w: (on_done and state["rc"] is not None
                                       and on_done(state["rc"])))

    win.show_all()
    return win


# --------------------------------------------------------------------------- #
# Headless wiring validator + a tiny bundled fake for --selftest.
# --------------------------------------------------------------------------- #
_FAKE_SCRIPT = r"""#!/bin/sh
# bundled fake for host.sysaction --selftest — prints N lines then exits 0.
echo "fake sysaction: args=$*"
echo "INSTALL_MODE=${INSTALL_MODE:-<unset>}"
for i in 1 2 3 4 5; do echo "  step $i / 5 …"; done
echo "fake done."
exit 0
"""


def _check() -> int:
    """Validate the elevation wiring headless — no GTK, no display, nothing run.

    Asserts build_argv yields a non-empty argv for every action/mode, that the
    SOC_SYSACTION_CMD fake takes precedence, that uninstall always carries --force
    and --purge only when asked, and that the mode threads into the install argv.
    """
    problems: "list[str]" = []

    def want(cond, msg):
        if not cond:
            problems.append(msg)

    # Without a fake, the path is pkexec/terminal/manual — all must give a usable argv.
    _save = os.environ.pop("SOC_SYSACTION_CMD", None)
    try:
        for action, kw in (("install", {"mode": "desktop"}),
                           ("install", {"mode": "kiosk"}),
                           ("uninstall", {}),
                           ("uninstall", {"purge": True})):
            argv, how = build_argv(action, **kw)
            want(argv and isinstance(argv, list), f"empty argv for {action} {kw}")
            want(how in ("pkexec", "terminal", "manual"),
                 f"unexpected how={how!r} for {action} {kw}")
        # mode threads into the install argv (as env INSTALL_MODE=...).
        argv, _ = build_argv("install", mode="kiosk")
        want(any("INSTALL_MODE=kiosk" in a for a in argv),
             "INSTALL_MODE=kiosk not in install argv")
        # uninstall ALWAYS --force; --purge only when asked.
        argv, _ = build_argv("uninstall")
        want("--force" in argv, "uninstall argv missing --force")
        want("--purge" not in argv, "uninstall argv has spurious --purge")
        argv, _ = build_argv("uninstall", purge=True)
        want("--force" in argv and "--purge" in argv,
             "uninstall+purge argv missing --force/--purge")

        # FAKE takes precedence over pkexec/terminal/manual.
        os.environ["SOC_SYSACTION_CMD"] = "/bin/true"
        argv, how = build_argv("install", mode="desktop")
        want(how == "fake", f"SOC_SYSACTION_CMD not honoured (how={how!r})")
        want("/bin/true" in argv, "fake script not in argv")
        want(any("INSTALL_MODE=desktop" in a for a in argv),
             "fake install argv missing INSTALL_MODE")
        argv, how = build_argv("uninstall", purge=True)
        want(how == "fake" and "--force" in argv and "--purge" in argv,
             "fake uninstall argv wrong")
    finally:
        if _save is None:
            os.environ.pop("SOC_SYSACTION_CMD", None)
        else:
            os.environ["SOC_SYSACTION_CMD"] = _save

    # manual_hint never raises and names the script.
    want("install.sh" in manual_hint("install", mode="kiosk"),
         "manual_hint(install) malformed")
    want("uninstall.sh" in manual_hint("uninstall", purge=True)
         and "--purge" in manual_hint("uninstall", purge=True),
         "manual_hint(uninstall) malformed")

    if problems:
        for p in problems:
            sys.stderr.write(f"sysaction --check: {p}\n")
        return 1
    sys.stdout.write("sysaction ok\n")
    return 0


def _selftest() -> int:
    """Drive the progress UI against the bundled fake under a display (verify only).
    Writes the fake to a temp file, points SOC_SYSACTION_CMD at it, runs the window
    in its own Gtk.main, exits when closed. Never runs the real scripts."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        sys.stderr.write("sysaction --selftest: no display\n")
        return 1
    import tempfile
    fd, path = tempfile.mkstemp(prefix="soc-sysaction-fake-", suffix=".sh")
    with os.fdopen(fd, "w") as fh:
        fh.write(_FAKE_SCRIPT)
    os.chmod(path, 0o755)
    os.environ["SOC_SYSACTION_CMD"] = path
    argv, how = build_argv("install", mode="desktop")
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    win = run_streamed(None, "Self-test", argv, on_done=lambda _rc: Gtk.main_quit())
    win.connect("destroy", lambda _w: Gtk.main_quit())
    Gtk.main()
    try:
        os.unlink(path)
    except OSError:
        pass
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in argv:
        return _selftest()
    if "--check" in argv:
        return _check()
    sys.stderr.write("host.sysaction: use --check (headless) or --selftest "
                     "(progress UI). Not a standalone runner.\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
