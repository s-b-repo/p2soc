"""
Live VPN log viewer — a small Gtk.Window that streams
`journalctl -u forti-vpn.service -f` line-by-line, plus Reconnect / Clear
controls and a collapse-to-bar toggle.

The operator's ask was: "when it reconnects it should open up a small box
printing every step and error for the VPN". This is that box — every
supervisor + driver log line (the forti-vpn supervisor's `[soc-vpn] ...`,
openfortivpn's own output, the wireguard/openvpn backend stderr) lands here
verbatim.

One unit, N VPNs: the single `forti-vpn.service` unit fans out to one
supervisor per enabled `vpns:[]` entry, so there is exactly ONE journald
stream — but the manager tags every supervisor line `[vpn:<name>]`. When the
wall runs more than one VPN, a "Show:" dropdown filters the stream to one VPN
by that tag (untagged manager/header lines always show). The journal-stream
subprocess runs read-only; on a non-root host
(the wall runs as the `soc` user) it goes through `sudo -n journalctl`,
which needs a NOPASSWD sudoers allowance for journalctl.

Design:
  * One Gtk.Window: a Gtk.TextView (read-only, monospace, auto-scroll) +
    Reconnect button (calls back into the host's existing VPN-restart
    path) + Clear button + a collapse-to-bar toggle.
  * Streaming uses subprocess.Popen + GLib.io_add_watch on the process's
    stdout fd — pure event-driven, no polling. The buffer is trimmed to a
    ~5k-line ring so 24/7 wall operation can't pin memory on a chatty VPN.
  * On window close the tail process is SIGTERM'd (terminate -> wait(2) ->
    kill); start_new_session=True so the teardown signal can't be raced by
    a parent shell.
  * The window is single-instance (one viewer per host); a second "open"
    just present()s the existing window.
"""
from __future__ import annotations

import subprocess
from typing import Optional

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib, Gdk     # noqa: E402

from . import style                          # noqa: E402


# The single VPN supervisor unit (this tree is single-VPN; the unit drives
# Fortinet/OpenVPN/WireGuard internally based on vpn.type).
_VPN_UNIT = "forti-vpn.service"

_MAX_LINES = 5_000          # ring-buffer cap; older lines trimmed first


def _have_nopasswd_journalctl() -> bool:
    """Cheap probe: can we run `sudo -n journalctl -u <unit>` without a
    prompt? Used at window-build time so the fallback path can WARN the
    operator (instead of the subprocess silently hanging on a sudo prompt
    that has no TTY).

    The probe uses the same command shape we'll run for real
    (`journalctl -u forti-vpn.service ...`) so it exercises the exact
    sudoers allowance the stream needs — a bare `journalctl --version`
    would not. `-n 0 --no-pager` returns 0 even when the unit has no
    journal entries yet (it may never have run on this box)."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/bin/journalctl", "-u", _VPN_UNIT,
             "-n", "0", "--no-pager"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class VpnLogViewer:
    """Single-instance window. Open with .show(); close with .close().
    A re-show() reuses the same window if it is still alive.

    `on_reconnect` is a no-arg callable that kicks the host's existing
    `systemctl restart forti-vpn` path (this tree is single-VPN, so no
    name argument)."""

    def __init__(self, *, on_reconnect, on_close=None, names=None):
        self._on_reconnect = on_reconnect
        self._on_close = on_close
        # Per-VPN names for the [vpn:<name>] tag filter. The manager tags every
        # supervisor line `[vpn:<name>]`, so a >1-VPN wall can narrow the single
        # stream to one VPN without a separate journald unit. Empty/<=1 -> the
        # filter row is hidden (the single-VPN view is unchanged).
        self._names = [str(n) for n in (names or []) if str(n).strip()]
        self._filter = ""              # "" = all VPNs; else a single name
        self._filter_combo = None
        self._win: Optional[Gtk.Window] = None
        self._buf: Optional[Gtk.TextBuffer] = None
        self._view: Optional[Gtk.TextView] = None
        self._end_mark = None
        self._proc: Optional[subprocess.Popen] = None
        self._io_tag: Optional[int] = None
        self._collapsed = False
        self._sudo = _have_nopasswd_journalctl()
        # Bounded auto-restart of the journal stream after a HUP/EOF (e.g. a
        # non-root host without NOPASSWD journalctl where the tail dies almost
        # immediately). Without a cap a failing journalctl would respawn in a
        # tight loop; with one, the viewer tries a few times then stops and
        # tells the operator to use Reconnect.
        self._stream_restarts = 0
        self._max_stream_restarts = 3
        self._restart_tag = None       # pending GLib timeout id for a restart

    @property
    def is_open(self) -> bool:
        return self._win is not None

    def show(self):
        """Open (or present) the viewer and start streaming if it isn't
        already."""
        if self._win is None:
            self._build()
            self._start_stream()
        self._win.present()

    def close(self):
        if self._win is None:
            return
        self._stop_stream()
        try:
            self._win.destroy()
        except Exception:                              # noqa: BLE001
            pass
        self._win = None
        self._buf = None
        self._view = None
        self._end_mark = None
        if self._on_close:
            try:
                self._on_close()
            except Exception:                          # noqa: BLE001
                pass

    # ---- window construction ------------------------------------------ #
    def _build(self):
        # Install the wall palette so this window's labels/buttons get the
        # explicit light-on-dark colours. Without this, the screen-wide CSS
        # still forces the window background dark (#0b1020) while bare
        # Gtk.Labels keep the operator desktop theme's near-black text — i.e.
        # dark-on-dark, ~1.5:1 contrast on a light GTK theme. Tagging the
        # window + labels with the soc-config-* classes fixes the contrast.
        style.apply_css()
        self._win = Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
        self._win.get_style_context().add_class("soc-config")
        self._win.set_title("SOC wall — VPN log")
        self._expanded_size = (720, 460)
        self._win.set_default_size(*self._expanded_size)
        self._win.set_keep_above(False)                # operator may bg it
        self._win.connect("delete-event", lambda *_: (self.close(), True)[1])
        self._win.connect("key-press-event", self._on_key)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        outer.set_border_width(8)

        # Top bar: collapse/expand toggle + status summary + close. Always
        # visible — in collapsed mode this is the only thing on screen.
        self._bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._collapse_btn = Gtk.Button(label="▾ Collapse")
        self._collapse_btn.set_tooltip_text(
            "Shrink to a thin bar — keeps streaming in the background, "
            "tap Expand to see the log again. Esc closes the window.")
        self._collapse_btn.connect("clicked", lambda *_: self.toggle_collapsed())
        self._summary = Gtk.Label(label=f"VPN log — {_VPN_UNIT} (streaming)")
        self._summary.get_style_context().add_class("soc-config-sub")
        self._summary.set_xalign(0.0)
        self._summary.set_hexpand(True)
        close_btn = Gtk.Button(label="✕")
        close_btn.set_tooltip_text("Close (Esc)")
        close_btn.connect("clicked", lambda *_: self.close())
        self._bar.pack_start(self._collapse_btn, False, False, 0)
        self._bar.pack_start(self._summary, True, True, 0)
        self._bar.pack_start(close_btn, False, False, 0)
        outer.pack_start(self._bar, False, False, 0)

        if not self._sudo:
            warn = Gtk.Label()
            warn.get_style_context().add_class("soc-config-error")
            warn.set_xalign(0.0)
            warn.set_line_wrap(True)
            warn.set_markup(
                "<b>Warning:</b> sudo NOPASSWD for journalctl isn't "
                "available, so the log tail will fail with 'a password is "
                "required'. The wall runs as the <tt>soc</tt> user and needs "
                "a sudoers allowance for "
                f"<tt>journalctl -u {GLib.markup_escape_text(_VPN_UNIT)}</tt> "
                "(or run the host as root).")
            outer.pack_start(warn, False, False, 0)

        # Action row: Reconnect + Clear.
        head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        unit_lbl = Gtk.Label()
        unit_lbl.get_style_context().add_class("soc-config-sub")
        unit_lbl.set_xalign(0.0)
        unit_lbl.set_markup(f"<tt>{GLib.markup_escape_text(_VPN_UNIT)}</tt>")
        head.pack_start(unit_lbl, True, True, 0)
        # Per-VPN tag filter — only when the wall runs more than one VPN. The
        # single forti-vpn.service stream carries every VPN's lines tagged
        # `[vpn:<name>]`; this narrows the view to one without a second unit.
        if len(self._names) > 1:
            flt = Gtk.ComboBoxText()
            flt.append_text("All VPNs")
            for nm in self._names:
                flt.append_text(nm)
            flt.set_active(0)
            flt.set_tooltip_text("Filter the log to one VPN (matches the "
                                 "[vpn:<name>] tag the manager writes).")
            flt.connect("changed", self._on_filter_changed)
            self._filter_combo = flt
            head.pack_start(Gtk.Label(label="Show:"), False, False, 0)
            head.pack_start(flt, False, False, 0)
        reconn = Gtk.Button(label="Reconnect")
        reconn.set_tooltip_text("Restart the VPN supervisor "
                                "(systemctl restart forti-vpn); the log "
                                "below shows each step + error.")
        reconn.connect("clicked", lambda *_: self._reconnect())
        clr = Gtk.Button(label="Clear")
        clr.set_tooltip_text("Clear the log view (the actual journal is "
                             "untouched; re-open the window to see the "
                             "trimmed history again).")
        clr.connect("clicked", lambda *_: self._clear())
        head.pack_start(reconn, False, False, 0)
        head.pack_start(clr, False, False, 0)

        # Body — monospace, read-only, scrolling text view. Hidden when
        # collapsed.
        self._body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._body.pack_start(head, False, False, 0)
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        sw.set_min_content_height(280)
        self._buf = Gtk.TextBuffer()
        self._view = Gtk.TextView(buffer=self._buf)
        self._view.set_editable(False)
        self._view.set_cursor_visible(False)
        self._view.set_monospace(True)
        self._view.set_left_margin(6)
        self._view.set_right_margin(6)
        self._view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        sw.add(self._view)
        self._body.pack_start(sw, True, True, 0)
        outer.pack_start(self._body, True, True, 0)

        # An "end" mark kept on the last char + scrolled-to after every
        # append, so the operator always sees the freshest line without
        # losing the ability to scroll up.
        self._end_mark = self._buf.create_mark(
            "_soc_end", self._buf.get_end_iter(), False)

        self._collapsed = False
        self._win.add(outer)
        self._win.show_all()

    # ---- streaming ---------------------------------------------------- #
    def _start_stream(self):
        if self._proc is not None:
            return                                     # already streaming
        # `journalctl -u <unit> -f --no-pager -n 100 -o cat`:
        #   -f       follow (live)
        #   --no-pager  don't pipe through less
        #   -n 100   prime with last 100 lines so the operator sees context
        #   -o cat   one log message per line, NO timestamp/host/unit prefix
        #            (the unit is already named in the header)
        cmd = ["/usr/bin/journalctl",
               "-u", _VPN_UNIT, "-f", "--no-pager",
               "-n", "100", "-o", "cat"]
        if self._sudo:
            cmd = ["sudo", "-n"] + cmd
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,                             # line-buffered
                text=True,
                # New session so SIGTERM on close isn't raced by a parent
                # shell.
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as e:
            self._append(
                f"[viewer] could not start journalctl for {_VPN_UNIT}:\n"
                f"  {e}\n"
                f"[viewer] If you see 'sudo: a password is required', the\n"
                f"  soc user lacks a NOPASSWD journalctl allowance. Run the\n"
                f"  host as root, or add a sudoers drop-in permitting\n"
                f"  `journalctl -u {_VPN_UNIT} *`.\n")
            return
        # Empty-state placeholder: if the VPN unit has never run on this box,
        # `-n 100` yields zero lines and the view sits blank with no
        # explanation. Seed one waiting line so the operator always sees that
        # the stream is live and just has nothing to show yet (real journal
        # lines append after it).
        self._append(
            f"[viewer] waiting for {_VPN_UNIT} log output…\n"
            f"[viewer] (no lines yet means the VPN service has not run, or "
            f"has produced no journal entries on this host)\n")
        # Watch the subprocess's stdout fd for new data. GLib invokes
        # _on_io on the GTK thread, so we can append without locks.
        fd = self._proc.stdout.fileno()
        # `IO_IN | IO_HUP` — readable OR end-of-pipe (subprocess died).
        self._io_tag = GLib.io_add_watch(
            fd, GLib.IO_IN | GLib.IO_HUP, self._on_io)

    def _on_io(self, _source, condition):
        if condition & GLib.IO_HUP:
            self._append(f"[viewer] journalctl exited for {_VPN_UNIT}\n")
            self._handle_stream_end()
            return False                               # source removes itself
        try:
            line = self._proc.stdout.readline()
        except (OSError, ValueError):
            self._handle_stream_end()
            return False
        if not line:                                   # EOF -> stream ended
            self._handle_stream_end()
            return False
        # A real line means the (possibly just-restarted) stream is healthy —
        # reset the restart budget so a later, unrelated exit gets fresh retries
        # instead of inheriting an exhausted counter.
        self._stream_restarts = 0
        self._append(line)
        return True                                    # keep watching

    def _handle_stream_end(self):
        """The journalctl tail died (HUP/EOF). The GLib io watch is removing
        itself (we returned False), so clear our stale _io_tag, reap the exited
        child here (don't leave a zombie until window close), and schedule a
        bounded auto-restart so a transient exit recovers without the operator
        reopening the window."""
        self._io_tag = None                            # the watch is gone now
        p = self._proc
        self._proc = None
        if p is not None:
            try:
                p.wait(timeout=2)                      # reap the exited child
            except (OSError, subprocess.SubprocessError,
                    subprocess.TimeoutExpired):
                try:
                    p.kill()
                    p.wait(timeout=2)
                except (OSError, subprocess.SubprocessError,
                        subprocess.TimeoutExpired):
                    pass
        # Window already closing? Don't respawn.
        if self._win is None:
            return
        if self._stream_restarts >= self._max_stream_restarts:
            self._append(
                f"[viewer] giving up auto-restarting the {_VPN_UNIT} log after "
                f"{self._max_stream_restarts} attempts — use Reconnect or "
                f"reopen the window to try again.\n")
            return
        self._stream_restarts += 1
        delay_ms = 2000 * self._stream_restarts        # 2s, 4s, 6s backoff
        self._append(
            f"[viewer] restarting the log stream in {delay_ms // 1000}s "
            f"(attempt {self._stream_restarts}/{self._max_stream_restarts})…\n")
        self._restart_tag = GLib.timeout_add(delay_ms, self._restart_stream)

    def _restart_stream(self):
        self._restart_tag = None
        if self._win is not None and self._proc is None:
            self._start_stream()
        return False                                   # one-shot

    def _stop_stream(self):
        # Cancel any pending auto-restart so a queued respawn can't fire after
        # the window is gone.
        if self._restart_tag is not None:
            try:
                GLib.source_remove(self._restart_tag)
            except (AttributeError, ValueError, TypeError):
                pass
            self._restart_tag = None
        if self._io_tag is not None:
            try:
                GLib.source_remove(self._io_tag)
            except (AttributeError, ValueError, TypeError):
                pass
            self._io_tag = None
        p = self._proc
        if p is not None:
            try:
                p.terminate()
                p.wait(timeout=2)
            except (OSError, subprocess.SubprocessError,
                    subprocess.TimeoutExpired):
                try:
                    p.kill()
                except OSError:
                    pass
            self._proc = None

    # ---- per-VPN filter ----------------------------------------------- #
    def _on_filter_changed(self, combo):
        active = combo.get_active_text() or ""
        self._filter = "" if active in ("", "All VPNs") else active
        self._summary.set_label(
            f"VPN log — {_VPN_UNIT}"
            + (f" — {self._filter}" if self._filter else " (streaming)"))

    def _passes_filter(self, line: str) -> bool:
        """When a VPN is selected, show its `[vpn:<name>]`-tagged lines plus any
        UNtagged line (manager headers, viewer notes) so context isn't lost.
        Lines tagged for a DIFFERENT VPN are hidden."""
        if not self._filter:
            return True
        if f"[vpn:{self._filter}]" in line:
            return True
        # a line tagged for some OTHER vpn is the only thing we drop
        return "[vpn:" not in line

    # ---- text buffer -------------------------------------------------- #
    def _append(self, text: str):
        if self._buf is None:
            return
        if not self._passes_filter(text):
            return
        end = self._buf.get_end_iter()
        self._buf.insert(end, text)
        # Trim to _MAX_LINES from the bottom so a chatty VPN can't pin
        # memory on a 24/7 wall.
        line_count = self._buf.get_line_count()
        if line_count > _MAX_LINES:
            extra = line_count - _MAX_LINES
            start = self._buf.get_start_iter()
            cut_to = self._buf.get_iter_at_line(extra)
            self._buf.delete(start, cut_to)
        # Auto-scroll. scroll_mark_onscreen keeps the end mark visible
        # without fighting an operator who scrolled up to read history.
        if self._view is not None and self._end_mark is not None:
            self._view.scroll_mark_onscreen(self._end_mark)

    def _clear(self):
        if self._buf is not None:
            self._buf.set_text("")

    def _reconnect(self):
        self._append(f"[viewer] reconnect requested for {_VPN_UNIT}\n")
        # Pass a sink so the reconnect OUTCOME (success / privilege-refusal /
        # failure) is printed here too — the most common failure (no NOPASSWD
        # sudo) only ever surfaced on the pill tooltip, leaving the viewer with a
        # lone 'requested' line and no result. The sink runs on the GTK main
        # thread (host dispatches it via GLib.idle_add), so appending is safe.
        sink = lambda msg: self._append(f"[viewer] {msg}\n")  # noqa: E731
        try:
            try:
                self._on_reconnect(sink=sink)
            except TypeError:
                # Back-compat: an on_reconnect that doesn't accept the kwarg
                # (older host) — fall back to the no-arg call so the reconnect
                # still happens; the outcome line just won't appear.
                self._on_reconnect()
        except Exception as e:                         # noqa: BLE001
            self._append(f"[viewer] reconnect raised: {e}\n")

    # ---- collapse / expand -------------------------------------------- #
    def toggle_collapsed(self):
        """Operator clicked Collapse/Expand. Collapsed: the body hides and
        the window shrinks to just the top bar; the journalctl tail keeps
        running in the background so logs land the moment it expands again
        (mirrors an IDE's bottom-panel collapse)."""
        if self._collapsed:
            self._body.show()
            self._collapse_btn.set_label("▾ Collapse")
            try:
                self._win.resize(*self._expanded_size)
            except Exception:                          # noqa: BLE001
                pass
            self._collapsed = False
        else:
            self._body.hide()
            self._collapse_btn.set_label("▸ Expand")
            try:
                # The bar's natural height dictates the actual collapsed
                # height (≈ 40 px); 1 just asks the WM to shrink.
                self._win.resize(self._expanded_size[0], 1)
            except Exception:                          # noqa: BLE001
                pass
            self._collapsed = True

    def _on_key(self, _w, event):
        if event.keyval == Gdk.KEY_Escape:
            self.close()
            return True
        return False
