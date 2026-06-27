"""
SOC video-wall — modern, sidebar-nav "SOC Wall Settings" control center (GTK3 /
PyGObject).

This is the operator-facing settings hub for a running wall. A tinted LEFT
SIDEBAR rail switches a Gtk.Stack between two panes:

  * Credentials — resolve the Vaultwarden master (sealed / secret-service /
    typed), list every login, and add / edit / delete one. The editor exposes a
    password reveal toggle and a TOTP field with a "Generate" button, a LIVE
    6-digit code that ticks every second, and a "Show setup URI" for enrolling a
    phone authenticator. All vault I/O runs OFF the GTK thread; the master lives
    in memory only and is never written or logged.

  * Security — the wall-lock enrolment surface: set / change / clear the
    panel-lock PIN, and enable / disable a panel-lock TOTP (with a scannable
    otpauth URI + a live preview), all via host.locker.

When a panel-lock PIN or TOTP is enrolled, a GATE pane is shown FIRST: the
sidebar + stack stay hidden until host.locker.verify_any() accepts the code. If
neither is enrolled the gate is skipped and the Security pane invites enrolling
one.

Theming is the same green-on-white console look as the launcher / setup wizard,
built from host.branding so a rebrand (branding/branding.yaml) reskins this too.

GTK is imported lazily INSIDE run() (never at module top) so `import
host.configcenter`, `--help`, and `make test` all work where GTK cannot
initialise a display.

Entry points::

    python3 -m host.configcenter         # the GUI control center
    host.configcenter.run()  -> int      # launch + Gtk.main(), returns 0
    host.configcenter.main(argv=None)    # thin CLI wrapper
"""
from __future__ import annotations

import os
import sys


# --------------------------------------------------------------------------- #
# Repo / module wiring — headless-safe (NO gi here).
# --------------------------------------------------------------------------- #
def _repo_root() -> str:
    env_root = os.environ.get("SOC_ROOT")
    if env_root and os.path.isdir(env_root):
        return os.path.abspath(env_root)
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, "..", ".."))


def _ensure_host_on_path() -> None:
    """Put ``<repo>/kiosk-host`` on sys.path so ``from host import …`` resolves
    when run outside the package. Idempotent."""
    kiosk = os.path.join(_repo_root(), "kiosk-host")
    if os.path.isdir(kiosk) and kiosk not in sys.path:
        sys.path.insert(0, kiosk)


def _esc(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# --------------------------------------------------------------------------- #
# CSS — the green console theme, palette-driven from host.branding. Pure string
# building (no gi); mirrors setupgui._css so the control center reads as the same
# app, plus a tinted left sidebar rail + active-row highlight.
# --------------------------------------------------------------------------- #
def _to_rgb(hexc: str) -> "tuple[int, int, int]":
    h = (hexc or "").lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    try:
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        return 136, 136, 136


def _rgba(hexc: str, alpha: float) -> str:
    r, g, b = _to_rgb(hexc)
    return f"rgba({r},{g},{b},{alpha})"


def _css(branding) -> bytes:
    c = branding.load().get("colors", {})

    def col(k, d):
        return c.get(k) or d
    bg = col("background", "#FFFFFF")
    surface = col("surface_top", "#F4F8F5")
    sunken = col("surface_bottom", "#EAF1EC")
    border = col("border", "#CFE0D4")
    text = col("text", "#0B1F14")
    text_dim = col("text_dim", "#5B7567")
    accent = col("primary", "#1FA463")
    accent_strong = col("accent_strong", "#157A49")
    good = col("good", "#1FA463")
    bad = col("bad", "#C0341D")
    glow = _rgba(accent, 0.28)
    accent_surf = branding.accent_on(surface, accent=accent, strong=accent_strong)
    btn_fg = branding.text_on(accent_strong, dark=text)
    dark = branding.is_dark(bg)
    glow_css = ""
    if dark:
        glow_css = f"""
.soc-section-title {{ text-shadow: 0 0 6px {_rgba(accent, 0.6)}; }}
.soc-rail-btn:checked {{ box-shadow: inset 3px 0 0 {accent}, 0 0 10px {_rgba(accent, 0.25)}; }}
"""
    return f"""
window.soc-center {{ background-color: {bg}; }}
.soc-center {{ background-color: {bg}; color: {text}; }}

/* Top brand header bar. */
.soc-header {{ background-color: {surface};
  border-top: 2px solid {accent}; border-bottom: 1px solid {border};
  padding: 12px 18px; }}

/* Left navigation rail. */
.soc-rail {{ background-color: {surface}; border-right: 1px solid {border};
  padding: 10px 8px; }}
.soc-rail-btn {{ background-image: none; background-color: transparent;
  color: {text_dim}; border: 0; border-radius: 6px;
  padding: 9px 12px; margin: 2px 0; }}
.soc-rail-btn label {{ color: {text_dim}; }}
.soc-rail-btn:hover {{ background-color: {sunken}; }}
.soc-rail-btn:hover label {{ color: {text}; }}
.soc-rail-btn:checked {{ background-color: {sunken};
  box-shadow: inset 3px 0 0 {accent}; }}
.soc-rail-btn:checked label {{ color: {accent_strong}; font-weight: bold; }}

.soc-page {{ background-color: {bg}; padding: 18px 20px; }}
.soc-section-title {{ color: {accent_surf}; font-weight: bold; }}
.soc-divider {{ background-color: {border}; min-height: 1px; }}

.soc-card {{ background-color: {surface};
  border: 1px solid {border}; border-left: 4px solid {accent}; border-radius: 8px;
  padding: 14px 16px; }}

/* Login list rows. */
list.soc-list {{ background-color: {surface}; border: 1px solid {border};
  border-radius: 8px; }}
list.soc-list row {{ padding: 2px 4px; }}
list.soc-list row:selected {{ background-color: {_rgba(accent, 0.16)};
  box-shadow: inset 3px 0 0 {accent}; }}
list.soc-list row:selected label {{ color: {text}; }}
.soc-badge {{ background-color: {_rgba(accent, 0.16)}; color: {accent_strong};
  border: 1px solid {_rgba(accent, 0.5)}; border-radius: 10px;
  padding: 0 7px; font-size: 9px; font-weight: bold; }}

entry {{ background-color: {sunken}; color: {text};
  border: 1px solid {border}; border-radius: 5px; padding: 6px 9px; }}
entry:focus {{ border: 1px solid {accent}; box-shadow: 0 0 0 2px {glow}; }}
entry image, entry placeholder {{ color: {text_dim}; }}
.soc-field-bad {{ border: 1px solid {bad}; }}
.soc-field-bad:focus {{ border: 1px solid {bad}; box-shadow: 0 0 0 2px {_rgba(bad, 0.28)}; }}

textview, textview text {{ background-color: {sunken}; color: {text}; }}

button {{ background-image: none; background-color: {sunken};
  color: {text}; border: 1px solid {border}; border-radius: 6px; padding: 6px 12px; }}
button:hover {{ border-color: {accent}; background-color: {sunken}; }}
button:disabled {{ color: {text_dim}; opacity: 1; }}

button.soc-primary {{ background-image: none; background-color: {accent_strong};
  color: {btn_fg}; border: 1px solid {accent_strong}; border-radius: 6px;
  font-weight: bold; padding: 7px 16px; }}
button.soc-primary:hover {{ background-color: {accent_strong};
  border-color: {accent}; color: {btn_fg};
  box-shadow: inset 0 0 0 1px {accent}, 0 4px 14px {glow}; }}
button.soc-primary:disabled {{ background-color: {sunken}; color: {text_dim};
  border-color: {border}; box-shadow: none; }}
button.soc-ghost {{ background-image: none; background-color: transparent;
  color: {accent_strong}; border: 1px solid {border}; border-radius: 6px;
  padding: 6px 12px; }}
button.soc-ghost:hover {{ background-color: {sunken}; border-color: {accent}; }}
button.soc-danger {{ background-image: none; background-color: transparent;
  color: {bad}; border: 1px solid {_rgba(bad, 0.5)}; border-radius: 6px;
  padding: 6px 12px; }}
button.soc-danger:hover {{ background-color: {_rgba(bad, 0.10)}; border-color: {bad}; }}
button.soc-danger:disabled {{ color: {text_dim}; border-color: {border}; }}

/* Keyboard focus rings — the rail, list rows, and every button (entries get
   theirs above). Mirrors setupgui so Tab navigation is visible. The :checked:focus
   rule is more specific than :checked so the active rail marker survives. (vt-3) */
.soc-rail-btn:focus, .soc-rail-btn:focus-visible {{ box-shadow: 0 0 0 2px {glow}; }}
.soc-rail-btn:checked:focus, .soc-rail-btn:checked:focus-visible {{
  box-shadow: inset 3px 0 0 {accent}, 0 0 0 2px {glow}; }}
button:focus, button:focus-visible {{ border-color: {accent};
  box-shadow: 0 0 0 2px {glow}; }}
button.soc-primary:focus, button.soc-primary:focus-visible {{
  box-shadow: 0 0 0 2px {glow}, inset 0 0 0 1px {accent}; }}
button.soc-ghost:focus, button.soc-ghost:focus-visible {{ border-color: {accent};
  box-shadow: 0 0 0 2px {glow}; }}
button.soc-danger:focus, button.soc-danger:focus-visible {{ border-color: {bad};
  box-shadow: 0 0 0 2px {_rgba(bad, 0.28)}; }}
list.soc-list row:focus {{ box-shadow: inset 3px 0 0 {accent}, 0 0 0 2px {glow}; }}

.soc-mono {{ font-family: monospace; }}
.soc-code {{ font-family: monospace; font-size: 22px; font-weight: bold;
  color: {accent_surf}; letter-spacing: 3px; }}
.soc-ok {{ color: {good}; }}
.soc-problem {{ color: {bad}; }}
.soc-dim {{ color: {text_dim}; }}
{glow_css}""".encode()


# --------------------------------------------------------------------------- #
# Vault endpoint resolution (no gi) — url/email from SOC_VAULT_* env, then
# litebw's config.json fallback (~/.config/litebw/config.json) exactly like the
# CLI and wall; the state dir from configwin.state_dir().
# --------------------------------------------------------------------------- #
def _vault_endpoint() -> "tuple[str, str]":
    url = os.environ.get("SOC_VAULT_URL", "")
    email = os.environ.get("SOC_VAULT_EMAIL", "")
    if not url or not email:
        _ensure_host_on_path()
        try:
            from host import litebw  # type: ignore
            url = url or litebw.resolve_url()
            email = email or litebw.resolve_email()
        except Exception:  # noqa: BLE001 — never let a missing dep wedge the window
            pass
    return url or "http://127.0.0.1:8222", email


def _state_dir() -> str:
    _ensure_host_on_path()
    try:
        from host import configwin  # type: ignore
        return configwin.state_dir()
    except Exception:  # noqa: BLE001 — never let a missing dep wedge the window
        d = os.environ.get("SOC_STATE_DIR") or os.path.join(
            os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
            "soc-wall")
        os.makedirs(d, exist_ok=True)
        return d


def _resolve_master() -> str:
    """Best-effort sealed / secret-service master (NEVER raises). '' when nothing
    is available so the Credentials pane falls back to a typed-master entry."""
    _ensure_host_on_path()
    try:
        from host import mastersource  # type: ignore
        pw = mastersource.get_master()
        if pw:
            return pw
    except Exception:  # noqa: BLE001
        pass
    try:
        from host import secretstore  # type: ignore
        sd = os.environ.get("SOC_SECRET_DIR")
        if secretstore.is_sealed(sd):
            return secretstore.unseal(sd) or ""
    except Exception:  # noqa: BLE001
        pass
    return ""


# --------------------------------------------------------------------------- #
# The control center. Everything below touches gi; it is only built from run().
# --------------------------------------------------------------------------- #
class ControlCenter:
    """The "SOC Wall · Settings" window: a gate (when a wall-lock credential is
    enrolled), then a sidebar rail switching a Stack between Credentials and
    Security. All vault/seal work runs OFF the GTK thread via GLib.idle_add."""

    def __init__(self, gtk_mods):
        self.Gtk, self.Gdk, self.GLib = gtk_mods
        _ensure_host_on_path()
        from host import branding  # type: ignore
        from host import locker, totp  # type: ignore
        self.branding = branding
        self.locker = locker
        self.totp = totp
        # vaultseed is optional (needs cryptography) — degrade gracefully.
        try:
            from host import vaultseed  # type: ignore
            self.vaultseed = vaultseed
        except Exception:  # noqa: BLE001
            self.vaultseed = None
        # litebw is the wall's TOTP read path: litebw.generate_totp accepts bare
        # base32, otpauth:// URIs AND Steam secrets. Use it for the credential
        # editor's Save-validation + live preview so the editor accepts exactly
        # what the wall does (pure stdlib; degrade to host.totp if absent).
        try:
            from host import litebw  # type: ignore
            self.litebw = litebw
        except Exception:  # noqa: BLE001
            self.litebw = None

        self.state_dir = _state_dir()
        self.vault_url, self.vault_email = _vault_endpoint()

        # Master + per-pane runtime state. The master lives in memory ONLY.
        self._master = ""
        self._logins = []            # last list_logins() result
        self._editing = None         # name of the record being edited, or None
        self._editing_notes = ""     # notes body of the record being edited (G1)
        self._timeouts = set()       # live GLib timeout source ids to clean up
        self._destroyed = False      # set in _on_destroy; guards pending timeouts
        self._gate_fails = 0         # consecutive wrong gate codes (SEC-3 lockout)

        self.win = None
        self._provider = None
        self._stack = None
        self._rail = None
        self._body = None            # the sidebar+stack HBox (hidden behind gate)
        self._gate = None

        # Credentials widgets (filled by _build_credentials).
        self._cred_unlock_box = None
        self._cred_main_box = None
        self._cred_master_entry = None
        self._login_list = None
        self._cred_status = None
        self._f_name = None
        self._f_user = None
        self._f_pass = None
        self._f_pass_toggle = None
        self._f_totp = None
        self._f_uri = None
        self._cred_code_lbl = None
        self._save_btn = None
        self._delete_btn = None

        # Security widgets.
        self._sec_pin_status = None
        self._sec_totp_status = None
        self._sec_pin_entry = None
        self._sec_pin_confirm = None
        self._sec_status = None
        self._sec_totp_secret = None
        self._sec_totp_uri = None
        self._sec_totp_code = None
        self._sec_new_totp = ""      # pending (unsaved) generated secret

        self._build()

    # ---- small theming helpers ------------------------------------------ #
    def _color(self, name, default=None):
        return self.branding.color(name, default)

    def _code_color(self):
        """AA-clearing accent for the live-code labels — the SAME value the
        ``.soc-code`` CSS uses (accent_on(surface_top)). A Pango ``foreground=``
        override otherwise defeats the CSS ``color`` and drops the security-
        critical code below WCAG AA on the default light theme. (vt-1)"""
        return self.branding.accent_on(
            self._color("surface_top"), accent=self._color("primary"),
            strong=self._color("accent_strong"))

    def _totp_code(self, secret):
        """Current TOTP code via the SAME parser the wall uses
        (``litebw.generate_totp`` — bare base32, otpauth:// URIs and Steam
        secrets), falling back to ``host.totp`` only if litebw is unavailable.
        Raises ValueError on a bad secret like both backends, so existing
        try/except callers are unchanged. (G5)"""
        if self.litebw is not None:
            return self.litebw.generate_totp(secret)
        return self.totp.totp(secret)

    def _markup(self, text, *, size=None, weight=None, color=None, mono=False):
        Gtk = self.Gtk
        lbl = Gtk.Label(xalign=0)
        attrs = []
        if size:
            attrs.append(f'size="{size}"')
        if weight:
            attrs.append(f'weight="{weight}"')
        if color:
            attrs.append(f'foreground="{color}"')
        if mono:
            attrs.append('font_family="monospace"')
        lbl.set_markup(f'<span {" ".join(attrs)}>{_esc(text)}</span>')
        return lbl

    def _section_title(self, text):
        lbl = self._markup(text, size="14000", weight="bold",
                           color=self._color("text"))
        lbl.get_style_context().add_class("soc-section-title")
        return lbl

    def _subtitle(self, text):
        lbl = self._markup(text, size="9800", color=self._color("text_dim"))
        lbl.set_line_wrap(True)
        lbl.get_style_context().add_class("soc-dim")
        return lbl

    def _field_row(self, label, widget):
        Gtk = self.Gtk
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        lbl = self._markup(label, color=self._color("text"))
        lbl.set_size_request(120, -1)
        lbl.set_valign(Gtk.Align.CENTER)
        row.pack_start(lbl, False, False, 0)
        row.pack_start(widget, True, True, 0)
        return row

    def _track_timeout(self, seconds, fn):
        """GLib.timeout that auto-forgets its id when the callback returns False
        and is force-removed on destroy (no leaked tickers)."""
        GLib = self.GLib
        holder = {}

        def _cb():
            keep = False
            try:
                keep = bool(fn())
            except Exception:  # noqa: BLE001 — a ticker must never crash the loop
                keep = False
            if not keep:
                self._timeouts.discard(holder.get("id"))
            return keep
        sid = GLib.timeout_add_seconds(seconds, _cb)
        holder["id"] = sid
        self._timeouts.add(sid)
        return sid

    # ---- build ----------------------------------------------------------- #
    def _build(self):
        Gtk = self.Gtk
        win = Gtk.Window(type=Gtk.WindowType.TOPLEVEL)
        win.get_style_context().add_class("soc-center")
        b = self.branding
        brand = b.get("short_name") or b.get("name") or "SOC Wall"
        win.set_title(f"{brand} · Settings")
        win.set_default_size(960, 600)
        win.set_position(Gtk.WindowPosition.CENTER)
        icon = b.icon_path()
        if icon:
            try:
                win.set_icon_from_file(icon)
            except Exception:  # noqa: BLE001
                pass
        win.connect("destroy", self._on_destroy)
        self.win = win

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.pack_start(self._build_header(brand), False, False, 0)

        # The gate stack: either the unlock gate OR the sidebar+stack body.
        self._content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._content.set_vexpand(True)
        outer.pack_start(self._content, True, True, 0)
        win.add(outer)

        self._body = self._build_body()
        self._gate = self._build_gate()

        if self.locker.pin_is_set(self.state_dir) or \
                self.locker.totp_is_set(self.state_dir):
            self._content.pack_start(self._gate, True, True, 0)
        else:
            self._content.pack_start(self._body, True, True, 0)

    def _build_header(self, brand):
        Gtk = self.Gtk
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        bar.get_style_context().add_class("soc-header")
        title = self._markup(f"{brand} Settings", size="15000", weight="bold",
                             color=self._color("text"))
        sub = self._markup("control center", size="9000",
                          color=self._color("text_dim"), mono=True)
        sub.set_valign(Gtk.Align.END)
        bar.pack_start(title, False, False, 0)
        bar.pack_start(sub, False, False, 6)
        return bar

    # ---- gate ------------------------------------------------------------ #
    def _build_gate(self):
        Gtk = self.Gtk
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.get_style_context().add_class("soc-page")
        page.set_halign(Gtk.Align.CENTER)
        page.set_valign(Gtk.Align.CENTER)
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("soc-card")
        card.set_size_request(360, -1)
        card.pack_start(self._markup("\U0001f512  Settings locked", size="13000",
                                    weight="bold", color=self._color("text")),
                        False, False, 0)
        has_pin = self.locker.pin_is_set(self.state_dir)
        has_totp = self.locker.totp_is_set(self.state_dir)
        if has_pin and has_totp:
            hint = "Enter the wall-lock PIN or a 6-digit authenticator code."
        elif has_totp:
            hint = "Enter the 6-digit code from your authenticator app."
        else:
            hint = "Enter the wall-lock PIN."
        card.pack_start(self._subtitle(hint), False, False, 0)
        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_input_purpose(Gtk.InputPurpose.PIN)
        entry.set_placeholder_text("PIN or 6-digit code")
        err = self._markup("", color=self._color("bad"))
        err.get_style_context().add_class("soc-problem")
        btn = Gtk.Button.new_with_label("Unlock")
        btn.get_style_context().add_class("soc-primary")

        def _rearm():
            # Re-enable the gate after a lockout window. Guard against a torn-down
            # window (this one-shot timeout may fire after destroy) — never touch
            # dead GTK objects. (SEC-3)
            if self._destroyed:
                return False
            try:
                entry.set_sensitive(True)
                btn.set_sensitive(True)
                err.set_text("Try again")
                entry.grab_focus()
            except Exception:  # noqa: BLE001
                pass
            return False

        def _try(*_a):
            code = (entry.get_text() or "").strip()
            ok = False
            try:
                ok = self.locker.verify_any(self.state_dir, code)
            except Exception as e:  # noqa: BLE001
                err.set_text(f"verify failed: {e}")
                return
            if ok:
                self._gate_fails = 0
                self._reveal_body()
                return
            # Wrong code — count it and, past the threshold, lock out with the
            # SAME exponential backoff KioskLocker uses, so the PIN guarding every
            # plaintext vault credential can't be brute-forced from this window at
            # machine speed. (SEC-3)
            entry.set_text("")
            self._gate_fails += 1
            if self._gate_fails >= 3:
                wait = min(5 * (self._gate_fails - 2), 60)
                entry.set_sensitive(False)
                btn.set_sensitive(False)
                err.set_text(f"Too many attempts — locked for {wait}s")
                self.GLib.timeout_add_seconds(wait, _rearm)
            else:
                err.set_text("Incorrect — try again")
                entry.grab_focus()
        entry.connect("activate", _try)
        btn.connect("clicked", _try)
        card.pack_start(entry, False, False, 0)
        card.pack_start(err, False, False, 0)
        card.pack_start(btn, False, False, 0)
        page.pack_start(card, False, False, 0)
        self._gate_entry = entry
        return page

    def _reveal_body(self):
        """Swap the gate out and the sidebar+stack in (after a good code)."""
        for ch in self._content.get_children():
            self._content.remove(ch)
        self._content.pack_start(self._body, True, True, 0)
        self._content.show_all()
        # Re-assert the default pane so timers/state are consistent.
        self._select_pane("credentials")
        # The gate just verified the operator — auto-unlock the vault from a
        # host-bound/secret-service master so the most security-conscious path
        # (lock enrolled) isn't the only one forced to re-type the master.
        self.try_auto_unlock()

    # ---- body: sidebar rail + stack -------------------------------------- #
    def _build_body(self):
        Gtk = self.Gtk
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)

        rail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        rail.get_style_context().add_class("soc-rail")
        rail.set_size_request(200, -1)
        self._rail = rail

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(120)
        self._stack.set_hexpand(True)
        self._stack.set_vexpand(True)

        cred = self._build_credentials()
        sec = self._build_security()
        self._stack.add_named(self._scroll(cred), "credentials")
        self._stack.add_named(self._scroll(sec), "security")

        self._rail_buttons = {}
        group = None
        for key, label in (("credentials", "Credentials"), ("security", "Security")):
            btn = Gtk.RadioButton.new_from_widget(group)
            if group is None:
                group = btn
            btn.set_mode(False)            # button look, not a radio dot
            btn.set_label(label)
            btn.get_style_context().add_class("soc-rail-btn")
            btn.connect("toggled", self._on_rail_toggled, key)
            rail.pack_start(btn, False, False, 0)
            self._rail_buttons[key] = btn

        hbox.pack_start(rail, False, False, 0)
        sep = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        hbox.pack_start(sep, False, False, 0)
        hbox.pack_start(self._stack, True, True, 0)

        self._rail_buttons["credentials"].set_active(True)
        self._stack.set_visible_child_name("credentials")
        return hbox

    def _scroll(self, child):
        Gtk = self.Gtk
        sc = Gtk.ScrolledWindow()
        sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        sc.add(child)
        return sc

    def _on_rail_toggled(self, btn, key):
        if btn.get_active():
            self._select_pane(key)

    def _select_pane(self, key):
        if self._stack is not None:
            self._stack.set_visible_child_name(key)
        b = self._rail_buttons.get(key) if hasattr(self, "_rail_buttons") else None
        if b is not None and not b.get_active():
            b.set_active(True)
        # Both live-code tickers run continuously (registered once as keepalives;
        # each early-returns when its field has no secret) — refresh the security
        # pane's status when it becomes visible.
        if key == "security":
            self._sec_refresh()

    # ===================================================================== #
    # CREDENTIALS pane
    # ===================================================================== #
    def _build_credentials(self):
        Gtk = self.Gtk
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.get_style_context().add_class("soc-page")
        page.pack_start(self._section_title("Vault credentials"), False, False, 0)
        page.pack_start(self._subtitle(
            "Logins the wall reads from Vaultwarden. Add, edit, or delete one; "
            "set a TOTP secret to auto-fill 2FA. The master password stays in "
            "memory and is never written."), False, False, 0)

        # Unlock sub-pane (shown when no sealed/secret-service master resolves).
        unlock = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        unlock.get_style_context().add_class("soc-card")
        unlock.pack_start(self._markup(
            "Enter the vault master password to unlock.",
            color=self._color("text")), False, False, 0)
        me = Gtk.Entry()
        me.set_visibility(False)
        me.set_placeholder_text("vault master password")
        me.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self._cred_master_entry = me
        ubtn = Gtk.Button.new_with_label("Unlock")
        ubtn.get_style_context().add_class("soc-primary")
        ubtn.connect("clicked", self._on_master_unlock)
        me.connect("activate", self._on_master_unlock)
        urow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        urow.pack_start(me, True, True, 0)
        urow.pack_start(ubtn, False, False, 0)
        unlock.pack_start(urow, False, False, 0)
        self._cred_unlock_box = unlock
        page.pack_start(unlock, False, False, 0)

        # Main sub-pane: login list (left) + editor (right).
        main = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        main.set_no_show_all(True)          # revealed only after unlock
        self._cred_main_box = main

        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        left.set_size_request(280, -1)
        listbox = Gtk.ListBox()
        listbox.get_style_context().add_class("soc-list")
        listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        listbox.connect("row-selected", self._on_login_selected)
        # Empty-state: GTK shows this only when the list has no visible rows and
        # hides it once logins are added, so _populate_logins needs no changes.
        # (cc-empty-vault-no-state)
        ph = self._markup('No vault logins yet — use "Add login" to create one.',
                          color=self._color("text_dim"))
        ph.set_halign(Gtk.Align.CENTER)
        ph.set_valign(Gtk.Align.CENTER)
        ph.set_margin_top(24)
        ph.set_margin_bottom(24)
        ph.set_line_wrap(True)
        ph.show()
        listbox.set_placeholder(ph)
        self._login_list = listbox
        lsc = Gtk.ScrolledWindow()
        lsc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        lsc.set_min_content_height(320)
        lsc.set_vexpand(True)
        lsc.add(listbox)
        left.pack_start(lsc, True, True, 0)
        lbtns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        addb = Gtk.Button.new_with_label("Add login")
        addb.get_style_context().add_class("soc-ghost")
        addb.connect("clicked", self._on_add_login)
        refb = Gtk.Button.new_with_label("Refresh")
        refb.get_style_context().add_class("soc-ghost")
        refb.connect("clicked", lambda *_: self._reload_logins())
        lbtns.pack_start(addb, False, False, 0)
        lbtns.pack_start(refb, False, False, 0)
        left.pack_start(lbtns, False, False, 0)
        main.pack_start(left, False, False, 0)

        main.pack_start(self._build_editor(), True, True, 0)
        page.pack_start(main, True, True, 0)

        self._cred_status = self._markup("", color=self._color("text_dim"))
        self._cred_status.get_style_context().add_class("soc-dim")
        page.pack_start(self._cred_status, False, False, 0)
        return page

    def _build_editor(self):
        Gtk = self.Gtk
        ed = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        ed.get_style_context().add_class("soc-card")

        self._f_name = Gtk.Entry()
        self._f_name.set_placeholder_text("login name (e.g. Wazuh)")
        ed.pack_start(self._field_row("Name", self._f_name), False, False, 0)

        self._f_user = Gtk.Entry()
        ed.pack_start(self._field_row("Username", self._f_user), False, False, 0)

        # Password with a reveal toggle.
        pbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._f_pass = Gtk.Entry()
        self._f_pass.set_visibility(False)
        self._f_pass.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        tog = Gtk.ToggleButton.new_with_label("Show")
        tog.get_style_context().add_class("soc-ghost")

        def _reveal(b):
            self._f_pass.set_visibility(b.get_active())
            b.set_label("Hide" if b.get_active() else "Show")
        tog.connect("toggled", _reveal)
        self._f_pass_toggle = tog
        pbox.pack_start(self._f_pass, True, True, 0)
        pbox.pack_start(tog, False, False, 0)
        ed.pack_start(self._field_row("Password", pbox), False, False, 0)

        # TOTP secret + Generate + live code + setup URI.
        tbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self._f_totp = Gtk.Entry()
        self._f_totp.set_placeholder_text("base32 secret (optional)")
        genb = Gtk.Button.new_with_label("Generate")
        genb.get_style_context().add_class("soc-ghost")
        genb.connect("clicked", self._on_gen_totp)
        urib = Gtk.Button.new_with_label("Show setup URI")
        urib.get_style_context().add_class("soc-ghost")
        urib.connect("clicked", self._on_show_totp_uri)
        tbox.pack_start(self._f_totp, True, True, 0)
        tbox.pack_start(genb, False, False, 0)
        tbox.pack_start(urib, False, False, 0)
        ed.pack_start(self._field_row("TOTP secret", tbox), False, False, 0)

        self._cred_code_lbl = self._markup("------", color=self._color("text_dim"))
        self._cred_code_lbl.get_style_context().add_class("soc-code")
        crow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        crow.pack_start(self._cred_code_lbl, False, False, 0)
        ed.pack_start(self._field_row("Live code", crow), False, False, 0)
        # Tick the credential TOTP preview once per second (lifetime of window).
        self._f_totp.connect("changed", lambda *_: self._tick_cred_code())
        self._track_timeout(1, self._tick_cred_code_keepalive)

        self._f_uri = Gtk.Entry()
        self._f_uri.set_placeholder_text("https://host/login (optional)")
        ed.pack_start(self._field_row("URI", self._f_uri), False, False, 0)

        # Actions.
        abox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        save = Gtk.Button.new_with_label("Save")
        save.get_style_context().add_class("soc-primary")
        save.connect("clicked", self._on_save_login)
        self._save_btn = save
        delete = Gtk.Button.new_with_label("Delete")
        delete.get_style_context().add_class("soc-danger")
        delete.connect("clicked", self._on_delete_login)
        delete.set_sensitive(False)
        self._delete_btn = delete
        abox.pack_start(save, False, False, 0)
        abox.pack_start(delete, False, False, 0)
        ed.pack_start(abox, False, False, 0)
        return ed

    # ---- credentials: master unlock + list ------------------------------ #
    def _post_unlock(self):
        """After we have a master in memory, hide the unlock box, reveal the main
        box, and load the login list — but ONLY if the vault is actually reachable
        (crypto present + email configured). Otherwise keep the operator on the
        unlock card with guidance instead of stranding them in a dead editor with
        the unlock entry already hidden. (cc-postunlock-hides-unlock-on-failure)"""
        if self.vaultseed is None or not self.vaultseed.available():
            self._cred_set_status(
                "'cryptography' not installed — install it to read/write the "
                "vault", bad=True)
            return
        if not self.vault_email:
            self._cred_set_status(
                "no vault email set (SOC_VAULT_EMAIL) — cannot manage logins",
                bad=True)
            return
        if self._cred_unlock_box is not None:
            self._cred_unlock_box.hide()
        if self._cred_main_box is not None:
            self._cred_main_box.set_no_show_all(False)
            self._cred_main_box.show_all()
        if self._cred_master_entry is not None:
            self._cred_master_entry.set_text("")
        self._reload_logins()

    def try_auto_unlock(self):
        """Attempt a sealed/secret-service master so the operator doesn't have to
        type one. Runs off-thread (unseal can be ~100-300ms scrypt on the Pi)."""
        self._cred_set_status("resolving vault master…")

        def work():
            master = ""
            try:
                master = _resolve_master()
            except Exception:  # noqa: BLE001
                master = ""
            self.GLib.idle_add(self._auto_unlock_done, master)
        self._run_bg(work)

    def _auto_unlock_done(self, master):
        if master:
            self._master = master
            self._cred_set_status("vault unlocked (host-bound master)")
            self._post_unlock()
        else:
            self._cred_set_status(
                "no sealed master available — enter it to unlock", dim=True)
        return False

    def _on_master_unlock(self, *_a):
        master = self._cred_master_entry.get_text() if self._cred_master_entry else ""
        if not master:
            self._cred_set_status("enter the vault master password", bad=True)
            return
        self._master = master
        self._post_unlock()

    def _reload_logins(self):
        if self.vaultseed is None or not self.vaultseed.available():
            self._cred_set_status(
                "'cryptography' not installed — install it to read/write the "
                "vault", bad=True)
            return
        if not self._master:
            return
        if not self.vault_email:
            self._cred_set_status(
                "no vault email set (SOC_VAULT_EMAIL) — cannot list logins",
                bad=True)
            return
        self._cred_set_status("loading logins…")
        url, email, master = self.vault_url, self.vault_email, self._master

        def work():
            try:
                rows = self.vaultseed.list_logins(url, email, master)
                self.GLib.idle_add(self._populate_logins, rows)
            except Exception as e:  # noqa: BLE001
                self.GLib.idle_add(self._cred_set_status,
                                  f"could not list logins: {e}", False, True)
        self._run_bg(work)

    def _populate_logins(self, rows):
        Gtk = self.Gtk
        # Pango isn't imported at module top (gi only inits inside run()); by the
        # time rows render the GUI is up, so requiring it here is safe + idempotent.
        import gi
        gi.require_version("Pango", "1.0")
        from gi.repository import Pango
        self._logins = list(rows or [])
        for ch in self._login_list.get_children():
            self._login_list.remove(ch)
        for rec in self._logins:
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            box.set_border_width(6)
            txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            # Ellipsize (+ tooltip) so long names/usernames shrink to honour the
            # 280px column instead of clipping or distorting the window. (vt-5)
            rec_name = rec.get("name", "") or ""
            name_lbl = self._markup(rec_name, weight="bold",
                                    color=self._color("text"))
            name_lbl.set_ellipsize(Pango.EllipsizeMode.END)
            name_lbl.set_max_width_chars(28)
            if rec_name:
                name_lbl.set_tooltip_text(rec_name)
            txt.pack_start(name_lbl, False, False, 0)
            username = rec.get("username") or ""
            sub = username or "—"
            sub_lbl = self._markup(sub, size="9000",
                                   color=self._color("text_dim"))
            sub_lbl.set_ellipsize(Pango.EllipsizeMode.END)
            sub_lbl.set_max_width_chars(28)
            if username:
                sub_lbl.set_tooltip_text(username)
            txt.pack_start(sub_lbl, False, False, 0)
            box.pack_start(txt, True, True, 0)
            if rec.get("has_totp"):
                badge = self._markup("TOTP", size="8500")
                badge.get_style_context().add_class("soc-badge")
                badge.set_valign(Gtk.Align.CENTER)
                box.pack_start(badge, False, False, 0)
            row._soc_name = rec.get("name", "")
            row.add(box)
            self._login_list.add(row)
        self._login_list.show_all()
        n = len(self._logins)
        self._cred_set_status(f"{n} login{'s' if n != 1 else ''} in the vault")
        return False

    def _on_login_selected(self, _listbox, row):
        if row is None:
            return
        name = getattr(row, "_soc_name", None)
        if not name:
            return
        self._cred_set_status(f"loading '{name}'…")
        url, email, master = self.vault_url, self.vault_email, self._master

        def work():
            try:
                rec = self.vaultseed.get_login(url, email, master, name)
                self.GLib.idle_add(self._fill_editor, rec)
            except Exception as e:  # noqa: BLE001
                self.GLib.idle_add(self._cred_set_status,
                                  f"could not load '{name}': {e}", False, True)
        self._run_bg(work)

    def _fill_editor(self, rec):
        if not rec:
            self._cred_set_status("login not found", bad=True)
            return False
        self._editing = rec.get("name", "")
        # Carry the notes body so Save round-trips it instead of nulling it (the
        # wall/VPN config YAML lives in a login's notes). (G1)
        self._editing_notes = rec.get("notes", "") or ""
        self._f_name.set_text(rec.get("name", "") or "")
        self._f_user.set_text(rec.get("username", "") or "")
        self._f_pass.set_text(rec.get("password", "") or "")
        self._f_totp.set_text(rec.get("totp", "") or "")
        self._f_uri.set_text(rec.get("uri", "") or "")
        self._delete_btn.set_sensitive(True)
        self._tick_cred_code()
        self._cred_set_status(f"editing '{self._editing}'")
        return False

    def _on_add_login(self, *_a):
        self._editing = None
        # Reset carried notes so a previously-loaded body (incl. the config YAML)
        # cannot leak into a brand-new login. (G1)
        self._editing_notes = ""
        for e in (self._f_name, self._f_user, self._f_pass, self._f_totp, self._f_uri):
            e.set_text("")
        if self._login_list is not None:
            self._login_list.unselect_all()
        self._delete_btn.set_sensitive(False)
        self._tick_cred_code()
        self._f_name.grab_focus()
        self._cred_set_status("new login — fill the form and Save")

    def _on_save_login(self, *_a):
        if not self._master:
            self._cred_set_status("unlock the vault first", bad=True)
            return
        name = (self._f_name.get_text() or "").strip()
        if not name:
            self._cred_set_status("a login needs a name", bad=True)
            return
        # Without an email every save dead-ends deep in the network layer with a
        # low-level error; surface the actionable config message instead, matching
        # _reload_logins. (cc-no-email-button-deadends)
        if not self.vault_email:
            self._cred_set_status(
                "no vault email set (SOC_VAULT_EMAIL) — set it in "
                "/etc/soc-display/soc.env and reopen this window", bad=True)
            return
        # Adding a brand-new record whose name collides with an existing login
        # would silently PUT over it (the server resolves the cipher by name).
        # Confirm before clobbering another panel's credentials. (cc-dup-name-overwrite)
        if self._editing is None and name in [r.get("name") for r in self._logins]:
            Gtk = self.Gtk
            dlg = Gtk.MessageDialog(
                transient_for=self.win, modal=True,
                message_type=Gtk.MessageType.QUESTION,
                buttons=Gtk.ButtonsType.OK_CANCEL,
                text=f"A login named '{name}' already exists.")
            dlg.format_secondary_text(
                "Saving will overwrite its username, password and TOTP. "
                "Select it from the list to edit instead.")
            resp = dlg.run()
            dlg.destroy()
            if resp != Gtk.ResponseType.OK:
                self._cred_set_status(
                    f"'{name}' already exists — not overwritten", bad=True)
                return
        user = self._f_user.get_text()
        pw = self._f_pass.get_text()
        totp_secret = (self._f_totp.get_text() or "").strip()
        uri = (self._f_uri.get_text() or "").strip()
        # Validate the TOTP secret up front with the SAME parser the wall uses
        # (litebw.generate_totp accepts otpauth:// URIs + Steam, not just bare
        # base32) so a bad paste fails on the GTK thread with a clear message
        # instead of mid-write. (G5)
        if totp_secret:
            try:
                self._totp_code(totp_secret)
            except Exception as e:  # noqa: BLE001
                self._cred_set_status(f"invalid TOTP secret: {e}", bad=True)
                return
        # A rename (editing an existing record and the Name changed) must move the
        # SAME cipher, not create a duplicate orphan; thread the original name so
        # vaultseed resolves the cipher by it and aborts on a name collision.
        # (cc-rename-orphan)
        rename_from = self._editing if (
            self._editing and self._editing != name) else None
        notes = self._editing_notes or None    # round-trip notes (G1)
        self._cred_set_status(f"saving '{name}'…")
        self._save_btn.set_sensitive(False)
        url, email, master = self.vault_url, self.vault_email, self._master

        def work():
            try:
                action = self.vaultseed.upsert_login(
                    url, email, master, name, user, pw,
                    notes=notes, uri=uri or None, totp=totp_secret or None,
                    rename_from=rename_from)
                self.GLib.idle_add(self._save_done, action, name, None)
            except Exception as e:  # noqa: BLE001
                self.GLib.idle_add(self._save_done, None, name, str(e))
        self._run_bg(work)

    def _save_done(self, action, name, err):
        self._save_btn.set_sensitive(True)
        if err:
            self._cred_set_status(f"could not save '{name}': {err}", bad=True)
            return False
        self._editing = name
        self._cred_set_status(f"{action} '{name}' ✓")
        self._reload_logins()
        return False

    def _on_delete_login(self, *_a):
        name = (self._editing or self._f_name.get_text() or "").strip()
        if not name:
            return
        Gtk = self.Gtk
        dlg = Gtk.MessageDialog(
            transient_for=self.win, modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text=f"Delete '{name}'?")
        dlg.format_secondary_text(
            "This removes the login from Vaultwarden. This cannot be undone.")
        resp = dlg.run()
        dlg.destroy()
        if resp != Gtk.ResponseType.OK:
            return
        self._cred_set_status(f"deleting '{name}'…")
        url, email, master = self.vault_url, self.vault_email, self._master

        def work():
            try:
                ok = self.vaultseed.delete_login(url, email, master, name)
                self.GLib.idle_add(self._delete_done, name, ok, None)
            except Exception as e:  # noqa: BLE001
                self.GLib.idle_add(self._delete_done, name, False, str(e))
        self._run_bg(work)

    def _delete_done(self, name, ok, err):
        if err:
            self._cred_set_status(f"could not delete '{name}': {err}", bad=True)
            return False
        if ok:
            self._cred_set_status(f"deleted '{name}' ✓")
            self._on_add_login()
            self._reload_logins()
        else:
            self._cred_set_status(f"no login named '{name}' to delete", bad=True)
        return False

    def _on_gen_totp(self, *_a):
        # Replacing an existing secret rotates that login's 2FA on Save and breaks
        # the already-enrolled authenticator — confirm first. No dialog when the
        # field is empty (the common "add TOTP" flow). (cc-gen-totp-clobbers-existing)
        existing = (self._f_totp.get_text() or "").strip()
        if existing:
            Gtk = self.Gtk
            name = (self._editing or self._f_name.get_text()
                    or "this login").strip() or "this login"
            dlg = Gtk.MessageDialog(
                transient_for=self.win, modal=True,
                message_type=Gtk.MessageType.QUESTION,
                buttons=Gtk.ButtonsType.OK_CANCEL,
                text=f"Replace the existing TOTP secret for '{name}'?")
            dlg.format_secondary_text(
                "The current authenticator enrollment will stop working "
                "once you Save.")
            resp = dlg.run()
            dlg.destroy()
            if resp != Gtk.ResponseType.OK:
                return
        try:
            secret = self.totp.generate_secret()
        except Exception as e:  # noqa: BLE001
            self._cred_set_status(f"could not generate secret: {e}", bad=True)
            return
        self._f_totp.set_text(secret)
        self._tick_cred_code()
        self._cred_set_status("generated a new TOTP secret — Save to store it")

    def _on_show_totp_uri(self, *_a):
        secret = (self._f_totp.get_text() or "").strip()
        if not secret:
            self._cred_set_status("no TOTP secret to build a URI from", bad=True)
            return
        name = (self._f_name.get_text() or "login").strip() or "login"
        # A pasted otpauth:// secret IS already a provisioning URI — show it as-is
        # (provision_uri only accepts bare base32). Matches the wall, which reads
        # otpauth:// secrets via litebw.generate_totp. (G5 residual)
        if secret.lower().startswith("otpauth://"):
            uri = secret
        else:
            try:
                uri = self.totp.provision_uri(secret, name)
            except Exception as e:  # noqa: BLE001
                self._cred_set_status(f"invalid TOTP secret: {e}", bad=True)
                return
        self._show_uri_dialog("TOTP setup URI", uri,
                             f"Add '{name}' to a phone authenticator:")

    def _tick_cred_code_keepalive(self):
        """Persistent 1s ticker — refreshes the credential live-code label while
        the window lives. Returns True to keep ticking."""
        self._tick_cred_code()
        return True

    def _tick_cred_code(self):
        if self._cred_code_lbl is None:
            return False
        secret = (self._f_totp.get_text() or "").strip() if self._f_totp else ""
        if not secret:
            self._cred_code_lbl.set_markup(
                f'<span foreground="{self._color("text_dim")}">------</span>')
            return False
        try:
            code = self._totp_code(secret)
            self._cred_code_lbl.set_markup(
                f'<span foreground="{self._code_color()}" weight="bold">'
                f'{_esc(code)}</span>')
        except Exception:  # noqa: BLE001
            self._cred_code_lbl.set_markup(
                f'<span foreground="{self._color("bad")}">invalid</span>')
        return False

    def _cred_set_status(self, text, ok_unused=False, bad=False, dim=False):
        # Signature accommodates GLib.idle_add(positional) callers: idle_add passes
        # extra args positionally, so (text, bad, dim) map cleanly.
        if self._cred_status is None:
            return False
        color = self._color("bad") if bad else (
            self._color("text_dim") if dim else self._color("text"))
        self._cred_status.set_markup(
            f'<span foreground="{color}">{_esc(text)}</span>')
        return False

    # ===================================================================== #
    # SECURITY pane
    # ===================================================================== #
    def _build_security(self):
        Gtk = self.Gtk
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.get_style_context().add_class("soc-page")
        page.pack_start(self._section_title("Wall lock"), False, False, 0)
        page.pack_start(self._subtitle(
            "Protect the wall and this settings window with a PIN and/or a phone "
            "authenticator (TOTP). Either unlocks; enrol at least one to lock the "
            "wall."), False, False, 0)

        # --- PIN card --- #
        pin_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        pin_card.get_style_context().add_class("soc-card")
        pin_card.pack_start(self._markup("PIN", weight="bold",
                                        color=self._color("text")), False, False, 0)
        self._sec_pin_status = self._markup("", color=self._color("text_dim"))
        pin_card.pack_start(self._sec_pin_status, False, False, 0)
        self._sec_pin_entry = Gtk.Entry()
        self._sec_pin_entry.set_visibility(False)
        self._sec_pin_entry.set_input_purpose(Gtk.InputPurpose.PIN)
        self._sec_pin_entry.set_placeholder_text("new PIN")
        self._sec_pin_confirm = Gtk.Entry()
        self._sec_pin_confirm.set_visibility(False)
        self._sec_pin_confirm.set_input_purpose(Gtk.InputPurpose.PIN)
        self._sec_pin_confirm.set_placeholder_text("confirm PIN")
        pin_card.pack_start(self._field_row("New PIN", self._sec_pin_entry),
                            False, False, 0)
        pin_card.pack_start(self._field_row("Confirm", self._sec_pin_confirm),
                            False, False, 0)
        pin_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        setpin = Gtk.Button.new_with_label("Set / Change PIN")
        setpin.get_style_context().add_class("soc-primary")
        setpin.connect("clicked", self._on_set_pin)
        clrpin = Gtk.Button.new_with_label("Clear PIN")
        clrpin.get_style_context().add_class("soc-danger")
        clrpin.connect("clicked", self._on_clear_pin)
        pin_btns.pack_start(setpin, False, False, 0)
        pin_btns.pack_start(clrpin, False, False, 0)
        pin_card.pack_start(pin_btns, False, False, 0)
        page.pack_start(pin_card, False, False, 0)

        # --- TOTP card --- #
        totp_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        totp_card.get_style_context().add_class("soc-card")
        totp_card.pack_start(self._markup("Authenticator (TOTP)", weight="bold",
                                         color=self._color("text")), False, False, 0)
        self._sec_totp_status = self._markup("", color=self._color("text_dim"))
        totp_card.pack_start(self._sec_totp_status, False, False, 0)

        self._sec_totp_uri = Gtk.Entry()
        self._sec_totp_uri.set_editable(False)
        self._sec_totp_uri.get_style_context().add_class("soc-mono")
        self._sec_totp_uri.set_placeholder_text(
            "otpauth:// setup URI appears here when enabling")
        totp_card.pack_start(self._field_row("Setup URI", self._sec_totp_uri),
                            False, False, 0)

        self._sec_totp_code = self._markup("------", color=self._color("text_dim"))
        self._sec_totp_code.get_style_context().add_class("soc-code")
        totp_card.pack_start(self._field_row("Live code", self._sec_totp_code),
                            False, False, 0)

        totp_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        enab = Gtk.Button.new_with_label("Enable TOTP")
        enab.get_style_context().add_class("soc-primary")
        enab.connect("clicked", self._on_enable_totp)
        disab = Gtk.Button.new_with_label("Disable TOTP")
        disab.get_style_context().add_class("soc-danger")
        disab.connect("clicked", self._on_disable_totp)
        totp_btns.pack_start(enab, False, False, 0)
        totp_btns.pack_start(disab, False, False, 0)
        totp_card.pack_start(totp_btns, False, False, 0)
        page.pack_start(totp_card, False, False, 0)

        self._sec_status = self._markup("", color=self._color("text_dim"))
        page.pack_start(self._sec_status, False, False, 0)

        # One persistent 1s ticker drives the security live-code label.
        self._track_timeout(1, self._sec_tick_keepalive)
        self._sec_refresh()
        return page

    def _sec_refresh(self):
        """Re-read enrolled state from disk and repaint the status lines."""
        if self._sec_pin_status is None:
            return
        pin_on = self.locker.pin_is_set(self.state_dir)
        totp_on = self.locker.totp_is_set(self.state_dir)
        self._sec_pin_status.set_markup(self._enrolled_markup(pin_on))
        self._sec_totp_status.set_markup(self._enrolled_markup(totp_on))

    def _enrolled_markup(self, on):
        if on:
            return (f'<span foreground="{self._color("good")}">'
                    f'● enrolled</span>')
        return (f'<span foreground="{self._color("text_dim")}">'
                f'○ not enrolled</span>')

    def _on_set_pin(self, *_a):
        pin = self._sec_pin_entry.get_text()
        confirm = self._sec_pin_confirm.get_text()
        if not pin:
            self._sec_set_status("enter a PIN", bad=True)
            return
        if pin != confirm:
            self._sec_set_status("the two PINs do not match", bad=True)
            return
        try:
            self.locker.set_pin(self.state_dir, pin)
        except Exception as e:  # noqa: BLE001
            self._sec_set_status(f"could not save PIN: {e}", bad=True)
            return
        self._sec_pin_entry.set_text("")
        self._sec_pin_confirm.set_text("")
        self._sec_set_status("PIN saved ✓")
        self._sec_refresh()

    def _on_clear_pin(self, *_a):
        # Clearing the PIN tears down a wall-lock factor — confirm first, mirroring
        # the Delete-login flow. (cc-clear-pin-no-confirm)
        if not self.locker.pin_is_set(self.state_dir):
            self._sec_set_status("no PIN to clear")
            return
        Gtk = self.Gtk
        dlg = Gtk.MessageDialog(
            transient_for=self.win, modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Clear the wall-lock PIN?")
        dlg.format_secondary_text(
            "The wall will no longer require this PIN to unlock.")
        resp = dlg.run()
        dlg.destroy()
        if resp != Gtk.ResponseType.OK:
            return
        try:
            self.locker.clear_pin(self.state_dir)
        except Exception as e:  # noqa: BLE001
            self._sec_set_status(f"could not clear PIN: {e}", bad=True)
            return
        self._sec_set_status("PIN cleared")
        self._sec_refresh()

    def _on_enable_totp(self, *_a):
        # Re-clicking Enable while already enrolled must NOT silently rotate the
        # secret (that locks out every already-enrolled phone) — confirm the
        # replacement first; keep a deliberate replace path. (cc-enable-totp-clobbers-secret)
        if self.locker.totp_is_set(self.state_dir):
            Gtk = self.Gtk
            dlg = Gtk.MessageDialog(
                transient_for=self.win, modal=True,
                message_type=Gtk.MessageType.QUESTION,
                buttons=Gtk.ButtonsType.OK_CANCEL,
                text="Replace the existing authenticator secret?")
            dlg.format_secondary_text(
                "A new secret is generated and the old one stops working — every "
                "already-enrolled phone must re-scan the new setup URI.")
            resp = dlg.run()
            dlg.destroy()
            if resp != Gtk.ResponseType.OK:
                return
        try:
            secret = self.totp.generate_secret()
            self.locker.set_totp(self.state_dir, secret)
        except Exception as e:  # noqa: BLE001
            self._sec_set_status(f"could not enable TOTP: {e}", bad=True)
            return
        self._sec_new_totp = secret
        b = self.branding
        issuer = b.get("short_name") or b.get("name") or "SOC Wall"
        try:
            uri = self.totp.provision_uri(secret, "wall-lock", issuer=issuer)
        except Exception:  # noqa: BLE001
            uri = ""
        self._sec_totp_uri.set_text(uri)
        self._sec_set_status(
            "TOTP enabled — scan the setup URI with your authenticator app")
        self._sec_refresh()

    def _on_disable_totp(self, *_a):
        # Disabling TOTP destroys the enrolled factor (only re-enrollable with a
        # fresh secret) — confirm first, like Delete-login. (cc-disable-totp-no-confirm)
        if not self.locker.totp_is_set(self.state_dir):
            self._sec_set_status("no authenticator to disable")
            return
        Gtk = self.Gtk
        dlg = Gtk.MessageDialog(
            transient_for=self.win, modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Disable the authenticator (TOTP)?")
        dlg.format_secondary_text(
            "You will need the setup URI again to re-enrol. This cannot be undone.")
        resp = dlg.run()
        dlg.destroy()
        if resp != Gtk.ResponseType.OK:
            return
        try:
            self.locker.clear_totp(self.state_dir)
        except Exception as e:  # noqa: BLE001
            self._sec_set_status(f"could not disable TOTP: {e}", bad=True)
            return
        self._sec_new_totp = ""
        self._sec_totp_uri.set_text("")
        self._sec_set_status("TOTP disabled")
        self._sec_refresh()

    def _sec_tick_keepalive(self):
        self._sec_tick_code()
        return True

    def _sec_tick_code(self):
        if self._sec_totp_code is None:
            return
        # Prefer the freshly-generated (unsaved) secret; else the stored one.
        secret = self._sec_new_totp
        if not secret:
            try:
                secret = self.locker.load_totp(self.state_dir) or ""
            except Exception:  # noqa: BLE001
                secret = ""
        if not secret:
            self._sec_totp_code.set_markup(
                f'<span foreground="{self._color("text_dim")}">------</span>')
            return
        try:
            code = self.totp.totp(secret)
            self._sec_totp_code.set_markup(
                f'<span foreground="{self._code_color()}" weight="bold">'
                f'{_esc(code)}</span>')
        except Exception:  # noqa: BLE001
            self._sec_totp_code.set_markup(
                f'<span foreground="{self._color("bad")}">invalid</span>')

    def _sec_set_status(self, text, bad=False):
        if self._sec_status is None:
            return
        color = self._color("bad") if bad else self._color("good")
        self._sec_status.set_markup(
            f'<span foreground="{color}">{_esc(text)}</span>')

    # ---- shared: a selectable-URI dialog -------------------------------- #
    def _show_uri_dialog(self, title, uri, hint):
        Gtk = self.Gtk
        dlg = Gtk.Dialog(title=title, transient_for=self.win, modal=True)
        # Paint the dialog body with the palette surface so the hint sentence is
        # readable on dark/glow presets (an unthemed default-GTK box would show
        # near-invisible low-contrast text). (vt-2)
        dlg.get_style_context().add_class("soc-center")
        dlg.add_button("Close", Gtk.ResponseType.CLOSE)
        box = dlg.get_content_area()
        box.set_spacing(8)
        box.set_border_width(12)
        box.pack_start(self._subtitle(hint), False, False, 0)
        ent = Gtk.Entry()
        ent.set_text(uri)
        ent.set_editable(False)
        ent.set_width_chars(56)
        ent.get_style_context().add_class("soc-mono")
        ent.select_region(0, -1)
        box.pack_start(ent, False, False, 0)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    # ---- background-thread helper --------------------------------------- #
    def _run_bg(self, fn):
        import threading
        threading.Thread(target=fn, daemon=True).start()

    # ---- lifecycle ------------------------------------------------------- #
    def _on_destroy(self, *_a):
        self._destroyed = True
        # Clean up every live timeout source so no ticker survives the window.
        for sid in list(self._timeouts):
            try:
                self.GLib.source_remove(sid)
            except Exception:  # noqa: BLE001
                pass
        self._timeouts.clear()
        # Drop our reference to the master on close (CPython cannot zero an
        # immutable str; copies in vaultseed/GC may persist until collected). (SEC-6)
        self._master = ""
        self.Gtk.main_quit()

    def show(self):
        self.win.show_all()
        # When the gate is showing, hide the (not-yet-added) body widgets.
        if self.locker.pin_is_set(self.state_dir) or \
                self.locker.totp_is_set(self.state_dir):
            if hasattr(self, "_gate_entry") and self._gate_entry is not None:
                self._gate_entry.grab_focus()
        else:
            # No gate: kick off an auto-unlock attempt for the Credentials pane.
            self.try_auto_unlock()


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def run() -> int:
    """Launch the GTK control center, run the main loop, return 0. gi is imported
    HERE (never at module top) so importing this module stays headless-safe."""
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, Gdk, GLib

    _ensure_host_on_path()
    from host import branding  # type: ignore

    # ONE theme provider, added to the screen once (palette-driven console look).
    provider = Gtk.CssProvider()
    try:
        provider.load_from_data(_css(branding))
        screen = Gdk.Screen.get_default()
        if screen is not None:
            Gtk.StyleContext.add_provider_for_screen(
                screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    except Exception as e:  # noqa: BLE001 — theming must never block the window
        sys.stderr.write(f"configcenter: theme load failed ({e}); using defaults\n")

    cc = ControlCenter((Gtk, Gdk, GLib))
    cc._provider = provider
    cc.show()
    Gtk.main()
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "-h" in argv or "--help" in argv:
        sys.stdout.write(
            "usage: python3 -m host.configcenter [--check]\n\n"
            "Launch the SOC Wall settings control center (Credentials + "
            "Security).\nNeeds a graphical display (except --check).\n")
        return 0
    if "--check" in argv:
        # Headless smoke (no gi / no display): the deps resolve, the theme CSS
        # builds, and the backend surfaces the panes need exist. Mirrors
        # appearance.py --check so `make lint` / the launcher script can verify
        # wiring on a box with no display.
        try:
            _ensure_host_on_path()
            from host import branding, locker, totp  # noqa: F401
            _css(branding)
            for fn in ("pin_is_set", "totp_is_set", "verify_any", "set_totp"):
                assert hasattr(locker, fn), f"locker.{fn} missing"
            sys.stdout.write("configcenter ok\n")
            return 0
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"configcenter --check FAILED: {e}\n")
            return 1
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        sys.stderr.write(
            "configcenter: no graphical display "
            "($DISPLAY / $WAYLAND_DISPLAY unset)\n")
        return 1
    try:
        return run()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"configcenter: failed to start ({e})\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
