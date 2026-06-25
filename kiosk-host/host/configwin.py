"""
On-screen configuration for the SOC wall.

A floating, always-on-top window an operator opens *at the glass* — via the
corner gear button or Ctrl+Shift+C — to set each tile's URL (and title) live,
with no SSH and no YAML editing. Changes apply immediately and are written to an
overrides file so they survive a restart.

Optional PIN lock: once a PIN is set, the window demands it before showing the
form, so a passer-by can't repoint the wall. The PIN is stored only as a salted
SHA-256 digest (never clear text); it can be set, changed, or removed from
inside the form.

State lives under $SOC_STATE_DIR (default ~/.config/soc-wall):
  overrides.json   {panel_id: {"url": "...", "title": "..."}}
  config.pin       "<salt_hex>$<digest_hex>"   (mode 0600)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib  # noqa: E402

from . import config as cfg  # noqa: E402
from . import style  # noqa: E402
from . import complexity as _cx  # noqa: E402
from . import locker as _lk  # noqa: E402
from . import totp as _totp  # noqa: E402


# --------------------------------------------------------------------------- #
# State directory + overrides + PIN store (pure, no GTK — unit-testable)
# --------------------------------------------------------------------------- #
def state_dir() -> str:
    d = os.environ.get("SOC_STATE_DIR") or os.path.join(
        os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
        "soc-wall")
    os.makedirs(d, exist_ok=True)
    return d


def _overrides_path() -> str:
    return os.path.join(state_dir(), "overrides.json")


def load_overrides() -> dict:
    try:
        with open(_overrides_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


ALLOWED_URL_SCHEMES = ("http://", "https://")


def valid_url(url: str) -> bool:
    """A panel URL must be empty (unconfigured) or plain http(s). Rejecting
    other schemes stops file://, javascript:, data: etc. being set at the glass."""
    u = (url or "").strip().lower()
    return u == "" or u.startswith(ALLOWED_URL_SCHEMES)


def save_overrides(d: dict):
    path = _overrides_path()
    tmp = path + ".tmp"
    # 0600: panel URLs can reveal internal hostnames; keep them owner-only
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _pin_path() -> str:
    return os.path.join(state_dir(), "config.pin")


def pin_is_set() -> bool:
    return os.path.exists(_pin_path())


def set_pin(pin: str):
    """Store a salted SHA-256 digest of the PIN (0600). Empty pin clears it."""
    if not pin:
        clear_pin()
        return
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + pin.encode("utf-8")).hexdigest()
    path = _pin_path()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"{salt.hex()}${digest}")


def clear_pin():
    try:
        os.remove(_pin_path())
    except OSError:
        pass


def verify_pin(pin: str) -> bool:
    try:
        with open(_pin_path(), "r", encoding="utf-8") as fh:
            salt_hex, _, digest = fh.read().strip().partition("$")
        want = hashlib.sha256(bytes.fromhex(salt_hex) + pin.encode("utf-8")).hexdigest()
        return hmac.compare_digest(want, digest)
    except (OSError, ValueError):
        return False


def apply_overrides_to_panels(panels, overrides: dict):
    """Merge a loaded overrides dict onto the panel objects at startup."""
    for p in panels:
        o = overrides.get(p.id)
        if not isinstance(o, dict):
            continue
        if "url" in o and valid_url(o.get("url")):
            p.url = o["url"] or None
            if o.get("url"):
                p.mode = "direct"          # a set URL implies a direct panel
        if o.get("title"):
            p.title = o["title"]
        if "vault_item" in o:
            p.vault_item = o["vault_item"] or ""
        if o.get("engine") in ("webkit", "chromium"):
            p.engine = o["engine"]
        if isinstance(o.get("selectors"), dict):
            p.selectors = {k: v for k, v in o["selectors"].items() if v}
        if "login_marker" in o:
            p.login_marker = o["login_marker"] or p.selectors.get("pass", "")


def apply_vpn_override(vpn: dict, overrides: dict):
    """Merge a saved VPN override (set from the on-screen VPN tab) onto the loaded
    vpn dict at startup. The override is what the operator entered at the glass;
    it merges over the config note/file so advanced fields not on the form
    (set_routes, etc.) are preserved."""
    o = overrides.get("_vpn")
    if isinstance(o, dict):
        vpn.update(o)
    return vpn


def vpn_form_to_dict(v: dict) -> dict:
    """Build a clean vpn config dict from flat on-screen form values: always sets
    enabled+type, keeps only non-empty strings, coerces port/health to int. The
    VPN service re-validates on restart and surfaces problems via its status."""
    out = {"enabled": bool(v.get("enabled")), "type": (v.get("type") or "fortinet")}
    for k in ("gateway", "vault_item", "config", "domain", "realm",
              "trusted_cert", "ready_probe"):
        val = str(v.get(k) or "").strip()
        if val:
            out[k] = val
    if v.get("insecure"):
        out["insecure"] = True
    if v.get("config_from_vault"):
        out["config_from_vault"] = True
    for k in ("port", "health_check_interval"):
        try:
            n = int(v.get(k) or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            out[k] = n
    return out


def apply_display_override(display, overrides: dict):
    """Apply a saved display override (layout/gap) to the DisplayCfg at startup."""
    o = overrides.get("_display")
    if not isinstance(o, dict):
        return
    if o.get("layout") in ("auto", "windows", "single"):
        display.layout = o["layout"]
    if isinstance(o.get("gap"), int) and o["gap"] >= 0:
        display.gap = o["gap"]


# --------------------------------------------------------------------------- #
# The window
# --------------------------------------------------------------------------- #
class ConfigWindow(Gtk.Window):
    """on_apply(changes: {id: {"url","title"}}) is called when Apply is pressed,
    after the overrides file has been saved; the host applies them live."""

    def __init__(self, panels, on_apply, on_close=None, display=None, vpn=None,
                 proxy_vault_item=""):
        super().__init__(title="SOC wall — settings")
        style.apply_css()
        self.panels = panels
        self.on_apply = on_apply
        self.on_close_cb = on_close
        self.display = display          # config.DisplayCfg | None (Display tab)
        self._vpn = vpn                 # conf.vpn dict | None (VPN tab)
        self._proxy_vault_item = proxy_vault_item
        self._vpn_w = None
        self._rows = {}
        self._unlocked = not pin_is_set()

        self.set_keep_above(True)
        self.set_modal(True)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_default_size(820, 600)
        self.set_resizable(True)
        self.get_style_context().add_class("soc-config")
        self.connect("key-press-event", self._on_key)
        self.connect("destroy", lambda *_: self.on_close_cb and self.on_close_cb())

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.add(self._stack)
        self._stack.add_named(self._build_pin_page(), "pin")
        self._stack.add_named(self._build_form_page(), "form")
        self._stack.set_visible_child_name("form" if self._unlocked else "pin")
        # show_all() reverts a Stack to its first child until it is mapped, so
        # re-assert the intended page once the window actually appears.
        self.connect("map", lambda *_: self._stack.set_visible_child_name(
            "form" if self._unlocked else "pin"))

    # ---- PIN gate ----------------------------------------------------------
    def _build_pin_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_border_width(28)
        title = Gtk.Label(label="🔒  Enter PIN")
        title.get_style_context().add_class("soc-config-title")
        self._pin_entry = Gtk.Entry()
        self._pin_entry.set_visibility(False)
        self._pin_entry.set_input_purpose(Gtk.InputPurpose.DIGITS)
        self._pin_entry.set_alignment(0.5)
        self._pin_entry.set_placeholder_text("PIN")
        self._pin_entry.connect("activate", lambda *_: self._try_unlock())
        self._pin_err = Gtk.Label(label="")
        self._pin_err.get_style_context().add_class("soc-config-error")
        self._pin_btn = Gtk.Button(label="Unlock")
        self._pin_btn.get_style_context().add_class("soc-config-primary")
        self._pin_btn.connect("clicked", lambda *_: self._try_unlock())
        self._pin_fails = 0
        for w in (title, self._pin_entry, self._pin_err, self._pin_btn):
            box.pack_start(w, False, False, 0)
        return box

    def _try_unlock(self):
        if verify_pin(self._pin_entry.get_text()):
            self._unlocked = True
            self._pin_fails = 0
            self._pin_err.set_text("")
            self._stack.set_visible_child_name("form")
            return
        self._pin_entry.set_text("")
        self._pin_fails += 1
        # rate-limit brute force: lock the input for a growing cooldown
        if self._pin_fails >= 3:
            wait = min(5 * (self._pin_fails - 2), 60)
            self._pin_err.set_text(f"Incorrect PIN — locked for {wait}s "
                                   f"({self._pin_fails} attempts)")
            self._pin_entry.set_sensitive(False)
            self._pin_btn.set_sensitive(False)

            def _unlock_input():
                self._pin_entry.set_sensitive(True)
                self._pin_btn.set_sensitive(True)
                self._pin_err.set_text("")
                return False
            GLib.timeout_add_seconds(wait, _unlock_input)
        else:
            self._pin_err.set_text("Incorrect PIN")

    # ---- config form (tabbed) ----------------------------------------------
    def _build_form_page(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        outer.set_border_width(16)
        head = Gtk.Label(label="SOC wall — settings")
        head.get_style_context().add_class("soc-config-title")
        head.set_xalign(0.0)
        outer.pack_start(head, False, False, 0)

        nb = Gtk.Notebook()
        nb.append_page(self._tab_panels(), Gtk.Label(label="Panels"))
        nb.append_page(self._tab_credentials(), Gtk.Label(label="Credentials"))
        if self.display is not None:
            nb.append_page(self._tab_display(), Gtk.Label(label="Display"))
        if self._vpn is not None:
            nb.append_page(self._tab_vpn(), Gtk.Label(label="VPN"))
        nb.append_page(self._tab_status(), Gtk.Label(label="Status"))
        outer.pack_start(nb, True, True, 0)

        self._form_msg = Gtk.Label(label="")
        self._form_msg.get_style_context().add_class("soc-config-ok")
        self._form_msg.set_xalign(0.0)
        self._form_msg.set_line_wrap(True)
        outer.pack_start(self._form_msg, False, False, 0)
        outer.pack_start(self._build_security(), False, False, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_halign(Gtk.Align.END)
        close_b = Gtk.Button(label="Close")
        close_b.connect("clicked", lambda *_: self.close())
        apply_b = Gtk.Button(label="Apply")
        apply_b.get_style_context().add_class("soc-config-primary")
        apply_b.connect("clicked", lambda *_: self._apply())
        actions.pack_start(close_b, False, False, 0)
        actions.pack_start(apply_b, False, False, 0)
        outer.pack_start(actions, False, False, 4)
        return outer

    def _tab_panels(self):
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(340)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(8)
        for p in self.panels:
            box.pack_start(self._panel_group(p), False, False, 0)
        scroll.add(box)
        return scroll

    def _panel_group(self, p):
        frame = Gtk.Frame(label=f"  {p.display_name}  ")
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_border_width(8)
        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(4)
        title_e = Gtk.Entry()
        title_e.set_text(p.title or "")
        title_e.set_placeholder_text("title")
        title_e.set_width_chars(12)
        url_e = Gtk.Entry()
        url_e.set_text(p.url or "")
        url_e.set_hexpand(True)
        url_e.set_placeholder_text("https://host/…  (blank = not configured)")
        url_e.set_input_purpose(Gtk.InputPurpose.URL)
        url_e.connect("activate", lambda *_: self._apply())
        vault_e = Gtk.Entry()
        vault_e.set_text(p.vault_item or "")
        vault_e.set_placeholder_text("vault item")
        vault_e.set_width_chars(13)
        engine_c = Gtk.ComboBoxText()
        for opt in ("webkit", "chromium"):
            engine_c.append_text(opt)
        engine_c.set_active(1 if p.engine == "chromium" else 0)
        for col, (lbl, w) in enumerate((("title", title_e), ("URL", url_e),
                                        ("vault login", vault_e), ("engine", engine_c))):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, col, 0, 1, 1)
            g.attach(w, col, 1, 1, 1)
        inner.pack_start(g, False, False, 0)

        exp = Gtk.Expander(label="Advanced — auto-login selectors (apply on restart)")
        ag = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        ag.set_border_width(6)
        sel = p.selectors or {}
        user_e = Gtk.Entry(); user_e.set_text(sel.get("user", "")); user_e.set_placeholder_text("user CSS")
        pass_e = Gtk.Entry(); pass_e.set_text(sel.get("pass", "")); pass_e.set_placeholder_text("pass CSS")
        sub_e = Gtk.Entry(); sub_e.set_text(sel.get("submit", "")); sub_e.set_placeholder_text("submit CSS")
        mark_e = Gtk.Entry(); mark_e.set_text(p.login_marker or ""); mark_e.set_placeholder_text("login marker")
        for w in (user_e, pass_e, sub_e, mark_e):
            w.set_width_chars(13)
            ag.pack_start(w, True, True, 0)
        exp.add(ag)
        inner.pack_start(exp, False, False, 0)
        frame.add(inner)
        self._rows[p.id] = {"url": url_e, "title": title_e, "vault": vault_e,
                            "engine": engine_c, "user": user_e, "pass": pass_e,
                            "submit": sub_e, "marker": mark_e}
        return frame

    def _tab_credentials(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.set_border_width(12)
        note = Gtk.Label(label="Store a login's username + password directly in "
                               "Vaultwarden, so the wall reads them automatically. "
                               "Skip a row to leave it for the web vault.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        grid = Gtk.Grid()
        grid.set_column_spacing(8)
        grid.set_row_spacing(8)
        for col, t in enumerate(("vault item", "username", "password", "")):
            h = Gtk.Label(label=t)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            grid.attach(h, col, 0, 1, 1)
        seen = set()
        self._cred_r = 1

        def add_row(name, uri):
            name = (name or "").strip()
            if not name or name in seen:
                return
            seen.add(name)
            r = self._cred_r
            nm = Gtk.Label(label=name)
            nm.get_style_context().add_class("soc-config-tag")
            nm.set_xalign(0.0)
            u = Gtk.Entry(); u.set_width_chars(15); u.set_placeholder_text("username")
            pw = Gtk.Entry(); pw.set_visibility(False); pw.set_width_chars(15)
            pw.set_placeholder_text("password")
            btn = Gtk.Button(label="Save to vault")
            btn.connect("clicked", (lambda b, n=name, ue=u, pe=pw, ur=uri:
                                    self._save_cred(n, ue, pe, ur)))
            grid.attach(nm, 0, r, 1, 1)
            grid.attach(u, 1, r, 1, 1)
            grid.attach(pw, 2, r, 1, 1)
            grid.attach(btn, 3, r, 1, 1)
            self._cred_r += 1

        for p in self.panels:
            add_row(p.vault_item, p.effective_url)
        add_row((self._vpn or {}).get("vault_item", ""), "")   # VPN login -> vault
        add_row(self._proxy_vault_item, "")                    # proxy login -> vault
        if self._cred_r == 1:
            box.pack_start(Gtk.Label(label="No vault logins to set yet (give a "
                                           "panel/VPN/proxy a vault item first)."),
                           False, False, 0)
        else:
            box.pack_start(grid, False, False, 0)

        self._cred_master = None
        # Only ask for the master at the glass when it isn't sealed on this host;
        # a sealed wall unseals it itself (no plaintext SOC_VAULT_PASSWORD).
        from . import secretstore
        if not secretstore.is_sealed(os.environ.get("SOC_SECRET_DIR")):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            lbl = Gtk.Label(label="vault master password:")
            lbl.get_style_context().add_class("soc-config-sub")
            self._cred_master = Gtk.Entry()
            self._cred_master.set_visibility(False)
            self._cred_master.set_hexpand(True)
            row.pack_start(lbl, False, False, 0)
            row.pack_start(self._cred_master, True, True, 0)
            box.pack_start(row, False, False, 0)
        self._cred_msg = Gtk.Label(label="")
        self._cred_msg.get_style_context().add_class("soc-config-ok")
        self._cred_msg.set_xalign(0.0)
        box.pack_start(self._cred_msg, False, False, 0)
        return box

    def _save_cred(self, name, user_e, pass_e, uri):
        user = user_e.get_text().strip()
        secret = pass_e.get_text()
        if not user:
            self._cred_msg.set_text(f"{name}: enter a username first")
            return
        url = os.environ.get("SOC_VAULT_URL", "http://127.0.0.1:8222")
        email = os.environ.get("SOC_VAULT_EMAIL", "")
        # Prefer the host-bound sealed master; fall back to the at-the-glass entry
        # only when the wall isn't sealed. Never read a plaintext SOC_VAULT_PASSWORD.
        from . import secretstore
        sd = os.environ.get("SOC_SECRET_DIR")
        try:
            master = secretstore.unseal(sd) if secretstore.is_sealed(sd) else ""
        except Exception:  # noqa: BLE001 — fall back to the manual entry below
            master = ""
        if not master and self._cred_master:
            master = self._cred_master.get_text()
        if not (email and master):
            self._cred_msg.set_text("need the vault email + master password to write")
            return
        self._cred_msg.set_text(f"writing '{name}' …")
        import threading

        def work():
            try:
                from . import vaultseed
                if not vaultseed.available():
                    msg = "'cryptography' not installed — add the login in the web vault"
                else:
                    action = vaultseed.upsert_login(url, email, master, name, user,
                                                    secret, uri=uri or None)
                    msg = f"{action} '{name}' in Vaultwarden ✓"
            except Exception as e:  # noqa: BLE001
                msg = f"{name}: {e}"
            GLib.idle_add(self._cred_done, msg, pass_e)
        threading.Thread(target=work, daemon=True).start()

    def _cred_done(self, msg, pass_e):
        self._cred_msg.set_text(msg)
        if "✓" in msg:
            pass_e.set_text("")
        return False

    def _tab_display(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="Layout + spacing. A layout change takes effect on "
                               "the next restart; gap applies live.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)
        g = Gtk.Grid()
        g.set_column_spacing(10)
        g.set_row_spacing(10)
        self._layout_c = Gtk.ComboBoxText()
        opts = ["auto", "windows", "single"]
        for o in opts:
            self._layout_c.append_text(o)
        cur = getattr(self.display, "layout", "auto")
        self._layout_c.set_active(opts.index(cur) if cur in opts else 0)
        self._gap_s = Gtk.SpinButton.new_with_range(0, 64, 1)
        self._gap_s.set_value(getattr(self.display, "gap", 0))
        for r, (lbl, w) in enumerate((("layout", self._layout_c), ("gap (px)", self._gap_s))):
            h = Gtk.Label(label=lbl)
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(w, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)
        return box

    def _tab_vpn(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_border_width(12)
        note = Gtk.Label(label="The supervised VPN. Credentials live in the vault "
                               "(set the username/password on the Credentials tab "
                               "for this VPN's vault item). Apply pushes the config "
                               "into the vault and restarts the VPN service.")
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        v = self._vpn or {}
        w = {}
        w["enabled"] = Gtk.CheckButton(label="VPN enabled")
        w["enabled"].set_active(bool(v.get("enabled")))
        box.pack_start(w["enabled"], False, False, 0)

        g = Gtk.Grid()
        g.set_column_spacing(8)
        g.set_row_spacing(6)
        w["type"] = Gtk.ComboBoxText()
        types = ["fortinet", "openvpn", "wireguard", "inode"]
        for t in types:
            w["type"].append_text(t)
        cur = str(v.get("type", "fortinet"))
        w["type"].set_active(types.index(cur) if cur in types else 0)

        def entry(val, hint):
            e = Gtk.Entry()
            e.set_text(str(val or ""))
            e.set_hexpand(True)
            e.set_placeholder_text(hint)
            return e

        w["gateway"] = entry(v.get("gateway"), "gateway host (fortinet / inode)")
        w["port"] = Gtk.SpinButton.new_with_range(0, 65535, 1)
        w["port"].set_value(int(v.get("port", 443) or 0))
        w["vault_item"] = entry(v.get("vault_item"), "vault login (username + password)")
        w["config"] = entry(v.get("config"), ".ovpn/.conf path, or the iNode client dir")
        w["domain"] = entry(v.get("domain"), "auth domain (inode)")
        w["realm"] = entry(v.get("realm"), "realm (fortinet)")
        w["trusted_cert"] = entry(v.get("trusted_cert"), "gateway cert sha256 pin")
        w["ready_probe"] = entry(v.get("ready_probe"), "host:port reachable only over the VPN")
        rows = [("type", w["type"]), ("gateway", w["gateway"]), ("port", w["port"]),
                ("vault login", w["vault_item"]), ("config", w["config"]),
                ("domain", w["domain"]), ("realm", w["realm"]),
                ("trusted_cert", w["trusted_cert"]), ("ready_probe", w["ready_probe"])]
        for r, (lbl, widget) in enumerate(rows, start=1):
            h = Gtk.Label(label=lbl)
            h.get_style_context().add_class("soc-config-sub")
            h.set_xalign(0.0)
            g.attach(h, 0, r, 1, 1)
            g.attach(widget, 1, r, 1, 1)
        box.pack_start(g, False, False, 0)

        w["insecure"] = Gtk.CheckButton(label="skip TLS verify (inode — trusted LAN only)")
        w["insecure"].set_active(bool(v.get("insecure")))
        w["config_from_vault"] = Gtk.CheckButton(
            label="config from the vault item's Notes (openvpn / wireguard)")
        w["config_from_vault"].set_active(bool(v.get("config_from_vault")))
        box.pack_start(w["insecure"], False, False, 0)
        box.pack_start(w["config_from_vault"], False, False, 0)
        self._vpn_w = w
        return box

    def _tab_status(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_border_width(12)
        configured = sum(1 for p in self.panels if getattr(p, "configured", False))
        lines = [
            f"vault backend : {os.environ.get('SOC_VAULT_BACKEND', cfg.DEFAULT_VAULT_BACKEND)}",
            f"panels        : {configured}/{len(self.panels)} configured",
            f"auto-login    : {sum(1 for p in self.panels if p.vault_item)} panel(s)",
            "VPN status    : shown in the top bar (click the pill to re-check)",
        ]
        for ln in lines:
            lbl = Gtk.Label(label=ln)
            lbl.get_style_context().add_class("soc-config-sub")
            lbl.set_xalign(0.0)
            box.pack_start(lbl, False, False, 0)
        return box

    def _build_security(self):
        exp = Gtk.Expander(label="Security — lock PIN / panel lock")
        exp.get_style_context().add_class("soc-config-sec")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(8)
        note = Gtk.Label(label=(
            "'Settings PIN' gates THIS window so a passer-by can't repoint the "
            "wall. 'Panel lock' is the 🔒 button / Ctrl+Alt+L input firewall — "
            "enrol a PIN and/or TOTP here or that lock is decorative."))
        note.get_style_context().add_class("soc-config-sub")
        note.set_xalign(0.0)
        note.set_line_wrap(True)
        box.pack_start(note, False, False, 0)

        # --- Settings-gate PIN (config.pin — opens this window) ----------- #
        sgate = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        state = ("A PIN is set — it is required to open this window."
                 if pin_is_set() else
                 "No PIN set — anyone can open this window. Set one to lock it.")
        self._sec_state = Gtk.Label(label=state)
        self._sec_state.get_style_context().add_class("soc-config-sub")
        self._sec_state.set_xalign(0.0)
        self._sec_state.set_line_wrap(True)
        sgate.pack_start(self._sec_state, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._newpin = Gtk.Entry()
        self._newpin.set_visibility(False)
        self._newpin.set_input_purpose(Gtk.InputPurpose.DIGITS)
        self._newpin.set_placeholder_text("new Settings PIN")
        self._newpin.set_hexpand(True)
        self._sgate_cx = Gtk.Label(label="")
        self._sgate_cx.set_xalign(0.0)
        self._sgate_cx.set_line_wrap(True)
        self._newpin.connect(
            "changed", lambda e: self._cx_hint(e, self._sgate_cx))
        set_b = Gtk.Button(label="Set / change PIN")
        set_b.connect("clicked", lambda *_: self._set_pin())
        clr_b = Gtk.Button(label="Remove PIN")
        clr_b.connect("clicked", lambda *_: self._clear_pin())
        row.pack_start(self._newpin, True, True, 0)
        row.pack_start(set_b, False, False, 0)
        row.pack_start(clr_b, False, False, 0)
        sgate.pack_start(row, False, False, 0)
        sgate.pack_start(self._sgate_cx, False, False, 0)
        box.pack_start(self._frame("Settings access (this window)", sgate),
                       False, False, 0)

        # --- Panel-lock PIN + TOTP (the 🔒 input firewall over the wall) -- #
        box.pack_start(self._build_panel_lock_section(), False, False, 0)
        exp.add(box)
        return exp

    @staticmethod
    def _frame(title, child):
        f = Gtk.Frame(label=f"  {title}  ")
        f.add(child)
        return f

    def _cx_hint(self, entry, label):
        """Live PIN-complexity feedback on `label` for the text in `entry`."""
        v = entry.get_text()
        ctx = label.get_style_context()
        ctx.remove_class("soc-config-ok")
        ctx.remove_class("soc-config-error")
        if not v:
            label.set_text("")
            return
        r = _cx.check(v, kind="pin")
        ctx.add_class("soc-config-ok" if r.ok else "soc-config-error")
        label.set_text("✓ meets PIN policy" if r.ok
                       else "✗ " + "; ".join(r.issues))

    def _set_pin(self):
        pin = self._newpin.get_text().strip()
        r = _cx.check(pin, kind="pin")
        if not r.ok:
            self._sec_state.set_text("PIN rejected — " + "; ".join(r.issues))
            return
        set_pin(pin)
        self._newpin.set_text("")
        self._sec_state.set_text("PIN updated — it will be required next time.")

    def _clear_pin(self):
        clear_pin()
        self._newpin.set_text("")
        self._sec_state.set_text("PIN removed — the window now opens without one.")

    # --- panel-lock (locker.py) enrollment ---------------------------------- #
    def _panel_lock_status_text(self) -> str:
        sd = state_dir()
        bits = ["PIN: SET ✓" if _lk.pin_is_set(sd) else "PIN: (none)",
                "TOTP: SET ✓" if _lk.totp_is_set(sd) else "TOTP: (none)"]
        return "  ·  ".join(bits)

    def _build_panel_lock_section(self):
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_border_width(6)
        self._pl_state = Gtk.Label(label=self._panel_lock_status_text())
        self._pl_state.get_style_context().add_class("soc-config-sub")
        self._pl_state.set_xalign(0.0)
        self._pl_state.set_line_wrap(True)
        inner.pack_start(self._pl_state, False, False, 0)

        # PIN row + live complexity hint
        prow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._pl_pin = Gtk.Entry()
        self._pl_pin.set_visibility(False)
        self._pl_pin.set_input_purpose(Gtk.InputPurpose.PIN)
        self._pl_pin.set_placeholder_text("new panel-lock PIN")
        self._pl_pin.set_hexpand(True)
        self._pl_cx = Gtk.Label(label="")
        self._pl_cx.set_xalign(0.0)
        self._pl_cx.set_line_wrap(True)
        self._pl_pin.connect("changed", lambda e: self._cx_hint(e, self._pl_cx))
        pset = Gtk.Button(label="Set PIN")
        pset.connect("clicked", lambda *_: self._pl_set_pin())
        pclr = Gtk.Button(label="Remove PIN")
        pclr.connect("clicked", lambda *_: self._pl_clear_pin())
        prow.pack_start(self._pl_pin, True, True, 0)
        prow.pack_start(pset, False, False, 0)
        prow.pack_start(pclr, False, False, 0)
        inner.pack_start(prow, False, False, 0)
        inner.pack_start(self._pl_cx, False, False, 0)

        # TOTP row — Enroll mints a fresh secret + shows the otpauth:// URI the
        # operator pastes into their authenticator (no qrencode dep pulled in).
        trow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._pl_uri = Gtk.Entry()
        self._pl_uri.set_editable(False)
        self._pl_uri.set_hexpand(True)
        self._pl_uri.set_placeholder_text("otpauth://… (appears after Enroll)")
        tset = Gtk.Button(label="Enroll TOTP")
        tset.connect("clicked", lambda *_: self._pl_enroll_totp())
        tclr = Gtk.Button(label="Remove TOTP")
        tclr.connect("clicked", lambda *_: self._pl_clear_totp())
        trow.pack_start(self._pl_uri, True, True, 0)
        trow.pack_start(tset, False, False, 0)
        trow.pack_start(tclr, False, False, 0)
        inner.pack_start(trow, False, False, 0)
        return self._frame("Panel lock (input firewall over the wall)", inner)

    def _pl_set_pin(self):
        pin = self._pl_pin.get_text().strip()
        r = _cx.check(pin, kind="pin")
        if not r.ok:
            self._pl_state.set_text("PIN rejected — " + "; ".join(r.issues))
            return
        _lk.set_pin(state_dir(), pin)
        self._pl_pin.set_text("")
        self._pl_state.set_text(self._panel_lock_status_text())

    def _pl_clear_pin(self):
        _lk.clear_pin(state_dir())
        self._pl_pin.set_text("")
        self._pl_state.set_text(self._panel_lock_status_text())

    def _pl_enroll_totp(self):
        try:
            s = _totp.generate_secret()
            _totp.save(_lk._totp_path(state_dir()), s)
            self._pl_uri.set_text(_totp.provision_uri(
                s, "kiosk@soc.local", issuer="SOC Wall — Panel lock"))
            self._pl_state.set_text(
                "TOTP enrolled — paste the URI into your authenticator app "
                "(or scan via `qrencode -t ANSIUTF8 '<uri>'`).")
        except Exception as e:                              # noqa: BLE001
            self._pl_state.set_text(f"could not enrol TOTP: {e}")

    def _pl_clear_totp(self):
        _totp.clear(_lk._totp_path(state_dir()))
        self._pl_uri.set_text("")
        self._pl_state.set_text(self._panel_lock_status_text())

    # ---- apply -------------------------------------------------------------
    def _msg(self, text, error=False):
        ctx = self._form_msg.get_style_context()
        ctx.remove_class("soc-config-error" if not error else "soc-config-ok")
        ctx.add_class("soc-config-error" if error else "soc-config-ok")
        self._form_msg.set_text(text)

    def _apply(self):
        if not self._unlocked:
            return
        bad = [pid for pid, w in self._rows.items() if not valid_url(w["url"].get_text())]
        if bad:
            self._msg(f"only http:// or https:// URLs are allowed (check: {', '.join(bad)})",
                      error=True)
            return

        changes, overrides = {}, load_overrides()
        for pid, w in self._rows.items():
            url = w["url"].get_text().strip()
            title = w["title"].get_text().strip()
            vault_item = w["vault"].get_text().strip()
            engine = w["engine"].get_active_text() or "webkit"
            sel = {k: w[k].get_text().strip() for k in ("user", "pass", "submit")}
            sel = {k: v for k, v in sel.items() if v}
            marker = w["marker"].get_text().strip()
            # only url/title/vault apply live; the rest persist for next restart
            changes[pid] = {"url": url, "title": title, "vault_item": vault_item}
            entry = overrides.get(pid, {}) if isinstance(overrides.get(pid), dict) else {}
            entry.update({"url": url, "title": title, "vault_item": vault_item,
                          "engine": engine, "selectors": sel, "login_marker": marker})
            overrides[pid] = entry

        if self.display is not None:
            disp = {"layout": self._layout_c.get_active_text() or "auto",
                    "gap": int(self._gap_s.get_value())}
            overrides["_display"] = disp
            changes["_display"] = disp

        if self._vpn is not None and self._vpn_w:
            w = self._vpn_w
            vpncfg = vpn_form_to_dict({
                "enabled": w["enabled"].get_active(),
                "type": w["type"].get_active_text() or "fortinet",
                "gateway": w["gateway"].get_text(),
                "port": int(w["port"].get_value()),
                "vault_item": w["vault_item"].get_text(),
                "config": w["config"].get_text(),
                "domain": w["domain"].get_text(),
                "realm": w["realm"].get_text(),
                "trusted_cert": w["trusted_cert"].get_text(),
                "ready_probe": w["ready_probe"].get_text(),
                "insecure": w["insecure"].get_active(),
                "config_from_vault": w["config_from_vault"].get_active(),
            })
            overrides["_vpn"] = vpncfg
            changes["_vpn"] = vpncfg

        save_overrides(overrides)
        try:
            self.on_apply(changes)
        except Exception as e:  # noqa: BLE001 — never let a bad apply kill the window
            self._msg(f"apply error: {e}", error=True)
            return
        self._msg("Applied ✓  — URL/title/vault live; engine/selectors/layout on restart")

    def _on_key(self, _w, event):
        if event.keyval == Gdk.KEY_Escape:
            self.close()
            return True
        return False
