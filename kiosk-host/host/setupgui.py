"""
SOC video-wall — GRAPHICAL setup wizard (GTK3 / PyGObject).

A desktop-launchable wizard that produces the SAME artifacts as the TTY wizard
(``setup.py wizard``): ``panels.yaml`` + the non-secret ``soc.env`` (+ the
supervised ``soc-wall.service`` unit), and seals/stores the vault master per the
chosen source. It does NOT duplicate any rendering / validation / sealing logic:
it imports ``setup.py`` as a module and calls its renderers (``render_panels_yaml``
/ ``render_soc_env`` / ``render_wall_unit``), its validators (``v_*``), and its
credential + master-seal flow — so the two wizards can never drift.

Styling matches host.launchermenu (the ops-room navy launcher) via a shared
Gtk.CssProvider; window title / header / accents come from host.branding so a
rebrand reskins it automatically.

Two entry points share ``main(argv=None)``:

  * GUI (default)::

        python -m host.setupgui

  * HEADLESS (CI / scripting — NO gi import, NO window, NO Gtk.main loop)::

        python -m host.setupgui --preset NAME --output DIR [--non-interactive]
        python -m host.setupgui --list-presets

The master password lives ONLY in memory (a Gtk.Entry buffer + a WizardModel
field, scrubbed after sealing); it is NEVER placed in cfg / soc_env / any file.
The headless path never touches the master at all.

GTK is imported lazily inside the GUI codepath only, so ``import host.setupgui``
and the headless path work where GTK cannot initialise a display (CI / make test).
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys


# --------------------------------------------------------------------------- #
# Repo / module wiring — reuse setup.py + host.* by reference (no duplication).
# --------------------------------------------------------------------------- #
def _repo_root() -> str:
    """The repo root: $SOC_ROOT if it holds setup.py, else 3 dirs up from this
    file (…/kiosk-host/host/setupgui.py -> repo root)."""
    env_root = os.environ.get("SOC_ROOT")
    if env_root and os.path.exists(os.path.join(env_root, "setup.py")):
        return os.path.abspath(env_root)
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, "..", ".."))


_SETUP = None


def _load_setup():
    """Import the repo-root setup.py AS A MODULE (the same spec_from_file_location
    trick the tests use). It is import-safe today (its only side effects are under
    ``if __name__ == '__main__'``). Cached so repeated calls are cheap."""
    global _SETUP
    if _SETUP is not None:
        return _SETUP
    path = os.path.join(_repo_root(), "setup.py")
    if not os.path.exists(path):
        raise RuntimeError(
            f"cannot find setup.py at {path} — set $SOC_ROOT to the repo/install "
            f"tree (the dir holding setup.py)")
    spec = importlib.util.spec_from_file_location("soc_setup", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _SETUP = mod
    return mod


def _ensure_host_on_path():
    """Put ``<repo>/kiosk-host`` on sys.path[0] (idempotent) so ``from host import
    …`` resolves when running outside the package (e.g. the headless CLI)."""
    kiosk = os.path.join(_repo_root(), "kiosk-host")
    if kiosk not in sys.path:
        sys.path.insert(0, kiosk)


def _presets_dir() -> str:
    return os.path.join(_repo_root(), "config", "presets")


def _preset_path(name: str) -> str:
    return os.path.join(_presets_dir(), f"{name}.yaml")


def discover_presets() -> "list[tuple[str, str, str]]":
    """(name, display_name, description) for every config/presets/*.yaml, read
    cheaply from the leading ``# name:`` / ``# desc:`` comment pair."""
    out = []
    d = _presets_dir()
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".yaml"):
            continue
        name = fn[:-len(".yaml")]
        disp, desc = name, ""
        in_desc = False
        try:
            with open(os.path.join(d, fn), encoding="utf-8") as fh:
                for line in fh:
                    s = line.strip()
                    if not s.startswith("#"):
                        break          # comment header ended -> stop scanning
                    body = s.lstrip("#").strip()
                    low = body.lower()
                    if low.startswith("name:"):
                        disp = body.split(":", 1)[1].strip()
                        in_desc = False
                    elif low.startswith("desc:"):
                        desc = body.split(":", 1)[1].strip()
                        in_desc = True
                    elif in_desc and body and not set(body) <= set("=-"):
                        desc += " " + body   # continuation of a wrapped desc line
                    else:
                        in_desc = False
        except OSError:
            pass
        out.append((name, disp, desc))
    return out


def preset_names() -> "list[str]":
    return [n for n, _d, _x in discover_presets()]


# --------------------------------------------------------------------------- #
# Config normalisation — turn a parsed preset (or GUI state) into the EXACT cfg
# dict the setup.render_* functions consume (so they never KeyError).
# --------------------------------------------------------------------------- #
def _def_panel(idx: int, cols: int, setup) -> dict:
    sel = dict(setup.DEF_SELECTORS)
    return dict(
        id=f"p{idx + 1}",
        engine="webkit",
        grid=[idx % max(1, cols), idx // max(1, cols)],
        mode="direct",
        url="http://192.168.1.50:3000/login",
        vault_item=f"SOC Panel {idx + 1}",
        selectors={"user": sel["user"], "pass": sel["pass"], "submit": sel["submit"]},
        login_marker=sel["pass"],
        keepalive={"strategy": "reload", "intervalSec": 600},
    )


def normalize_cfg(raw: dict | None, setup) -> dict:
    """Coerce a loosely-parsed config (from a preset file or the GUI) into the
    full shape render_panels_yaml expects: every panel has id/engine/grid/mode/
    (url|tunnel)/vault_item/selectors{user,pass,submit}/login_marker/keepalive,
    and the tunnel/vpn/proxy blocks are present."""
    raw = dict(raw or {})
    d = dict(raw.get("display") or {})
    display = dict(
        auto=bool(d.get("auto", True)),
        width=int(d.get("width", 1920)),
        height=int(d.get("height", 1080)),
        cols=int(d.get("cols", 2)),
        rows=int(d.get("rows", 2)),
        gap=int(d.get("gap", 0)),
        layout=d.get("layout", "auto") or "auto",
    )
    cols = display["cols"]
    panels = []
    for i, p in enumerate(raw.get("panels") or []):
        p = dict(p or {})
        base = _def_panel(i, cols, setup)
        out = dict(base)
        out["id"] = str(p.get("id", base["id"]))
        out["engine"] = p.get("engine", base["engine"]) or "webkit"
        g = p.get("grid") or base["grid"]
        try:
            out["grid"] = [int(g[0]), int(g[1])]
        except (TypeError, ValueError, IndexError):
            out["grid"] = base["grid"]
        out["mode"] = p.get("mode", base["mode"]) or "direct"
        if out["mode"] == "tunnel":
            t = dict(p.get("tunnel") or {})
            out["tunnel"] = dict(
                local_port=int(t.get("local_port", 19100 + i + 1)),
                remote_host=str(t.get("remote_host", "10.20.0.7")),
                remote_port=int(t.get("remote_port", 443)),
            )
            out["path"] = p.get("path", "/")
            out["scheme"] = p.get("scheme", "http")
            out.pop("url", None)
        else:
            out["url"] = p.get("url", base["url"])
        out["vault_item"] = p.get("vault_item", base["vault_item"])
        s = dict(p.get("selectors") or {})
        out["selectors"] = {
            "user": s.get("user", base["selectors"]["user"]),
            "pass": s.get("pass", base["selectors"]["pass"]),
            "submit": s.get("submit", base["selectors"].get("submit", "")),
        }
        out["login_marker"] = p.get("login_marker", out["selectors"]["pass"])
        k = dict(p.get("keepalive") or {})
        ka = {"strategy": k.get("strategy", "reload")}
        if ka["strategy"] != "none":
            ka["intervalSec"] = int(k.get("intervalSec", 600))
        if ka["strategy"] == "xhr" and k.get("url"):
            ka["url"] = k["url"]
        if ka["strategy"] == "click" and k.get("target"):
            ka["target"] = k["target"]
        out["keepalive"] = ka
        panels.append(out)

    tunnel = dict(raw.get("tunnel") or {"enabled": False})
    tunnel.setdefault("enabled", False)
    if tunnel.get("enabled"):
        tunnel.setdefault("jump_host", "")
        tunnel.setdefault("identity", "")
        tunnel.setdefault("extra_forwards", [])

    vpn = dict(raw.get("vpn") or {"enabled": False})
    vpn.setdefault("enabled", False)

    proxy = dict(raw.get("proxy") or {"enabled": False})
    proxy.setdefault("enabled", False)

    return dict(display=display, panels=panels, tunnel=tunnel, vpn=vpn, proxy=proxy)


# --------------------------------------------------------------------------- #
# WizardModel — the data the renderers consume. Holds the master password IN
# MEMORY ONLY (never put into cfg / soc_env / any file).
# --------------------------------------------------------------------------- #
class WizardModel:
    def __init__(self, setup, paths: dict):
        self._setup = setup
        self.paths = paths
        self._cfg = normalize_cfg(None, setup)
        # vault / env knobs (mirrors setup.section_vault defaults)
        self.vault_backend = paths.get("default_backend", "dev")
        self.vault_email = "kiosk@soc.local"
        self.vault_url = "http://127.0.0.1:8222"
        self.session = "auto"
        # master-source page state — IN MEMORY ONLY
        self.master_source = "auto"          # auto|sealed|secret-service|env
        self.master_password = ""            # scrubbed after seal/store
        self.master_pin = ""                 # optional; gen_pin if blank
        # config-to-vault
        self.push_config = False

    # ---- cfg ------------------------------------------------------------- #
    def cfg(self) -> dict:
        return self._cfg

    def set_cfg(self, raw: dict):
        self._cfg = normalize_cfg(raw, self._setup)

    def apply_preset(self, name: str) -> "str | None":
        """Load a preset into the model. Returns an error string (and falls back
        to 'empty') if the preset is missing / malformed, else None."""
        setup = self._setup
        path = _preset_path(name)
        raw = setup.load_yaml(path) if os.path.exists(path) else None
        if raw is None:
            self._cfg = normalize_cfg(None, setup)
            return f"could not load preset {name!r}; starting blank"
        try:
            self._ensure_config_mod().load_str(setup.render_panels_yaml(
                normalize_cfg(raw, setup)))
        except Exception as e:  # noqa: BLE001
            self._cfg = normalize_cfg(None, setup)
            return f"preset {name!r} did not validate ({e}); starting blank"
        self._cfg = normalize_cfg(raw, setup)
        return None

    def _ensure_config_mod(self):
        _ensure_host_on_path()
        from host import config  # type: ignore
        return config

    # ---- soc.env --------------------------------------------------------- #
    def soc_env(self) -> dict:
        """The FULL env dict render_soc_env indexes (every e[k]); a partial dict
        would KeyError. Seeds setup.section_vault's defaults + the paths."""
        p = self.paths
        return {
            "SOC_VAULT_BACKEND": self.vault_backend,
            "SOC_VAULT_EMAIL": self.vault_email,
            "SOC_VAULT_URL": self.vault_url,
            "SOC_SECRET_DIR": p["secret_dir"],
            "SOC_CONFIG_VAULT_ITEM": p.get("config_vault_item", "SOC Wall Config"),
            "SOC_ROOT": p["soc_root"],
            "SOC_PANELS_FILE": p["panels_installed"],
            "SOC_INJECT_TMPL": p["inject_tmpl"],
            "SOC_LAUNCH_STAGGER": "1.5",
            "SOC_READY_TIMEOUT": "120",
            "SOC_CDP_BASE_PORT": "9222",
            "SOC_CRED_TTL": "30",
            "SOC_VPN_DRY_RUN": "0",
            "SOC_SESSION": self.session,
        }

    # ---- validation ------------------------------------------------------ #
    def validate(self) -> "list[str]":
        """Render the panels.yaml and run the kiosk's collect-everything
        validation; returns a list of human-readable problems ([] if valid)."""
        setup = self._setup
        config = self._ensure_config_mod()
        try:
            config.load_str(setup.render_panels_yaml(self.cfg()))
        except config.ConfigError as e:
            return [str(e)]
        except Exception as e:  # noqa: BLE001
            return [f"{e.__class__.__name__}: {e}"]
        return []

    def panels_yaml(self) -> str:
        return self._setup.render_panels_yaml(self.cfg())


# --------------------------------------------------------------------------- #
# Headless path — NO gi, NO window, NO Gtk.main loop.
# --------------------------------------------------------------------------- #
def build_headless(preset: str, output_dir: str, *, non_interactive: bool = True) -> int:
    """Render ``<preset>`` to ``<output_dir>/panels.yaml`` + ``<output_dir>/soc.env``
    using setup.py's renderers + the kiosk validator. Returns 0 on success,
    non-zero on unknown preset / validation failure. Never touches the master
    password / sealing (that is GUI-only). Imports NO gi."""
    setup = _load_setup()
    config = None
    _ensure_host_on_path()
    try:
        from host import config as _config  # type: ignore
        config = _config
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"setupgui: cannot import host.config ({e})\n")
        return 2

    names = preset_names()
    if preset not in names:
        sys.stderr.write(
            f"setupgui: unknown preset {preset!r} (have: {', '.join(names) or 'none'})\n")
        return 2

    raw = setup.load_yaml(_preset_path(preset))
    if raw is None:
        sys.stderr.write(
            f"setupgui: could not load preset {preset!r} "
            f"(PyYAML missing or malformed file)\n")
        return 2

    # dev-safe paths anchored at the output dir; no wallet / Vaultwarden needed.
    out = os.path.abspath(output_dir)
    os.makedirs(out, exist_ok=True)
    paths = setup.resolve_paths("dev")
    paths = dict(paths)
    paths["panels_out"] = os.path.join(out, "panels.yaml")
    paths["panels_installed"] = os.path.join(out, "panels.yaml")
    paths["soc_env"] = os.path.join(out, "soc.env")
    if non_interactive:
        paths["default_backend"] = "dev"

    model = WizardModel(setup, paths)
    model.set_cfg(raw)
    if non_interactive:
        model.vault_backend = "dev"
        model.master_source = "auto"

    problems = model.validate()
    if problems:
        sys.stderr.write(f"setupgui: preset {preset!r} did not validate:\n")
        for pr in problems:
            sys.stderr.write(f"  - {pr}\n")
        return 1

    panels_text = model.panels_yaml()
    env_text = setup.render_soc_env(model.soc_env())
    # sanity: the master password must NEVER appear in the generated env.
    assert "SOC_VAULT_PASSWORD" not in env_text, "soc.env must not carry a master"

    setup.write_file(paths["panels_out"], panels_text, paths["panels_mode"], dry=False)
    setup.write_file(paths["soc_env"], env_text, paths["env_mode"], dry=False)
    return 0


# --------------------------------------------------------------------------- #
# CSS / small markup helpers — adapted from launchermenu so the wizard reads as
# the same app. (No gi here; pure string building.)
# --------------------------------------------------------------------------- #
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


def _css(branding) -> bytes:
    c = branding.load().get("colors", {})

    def col(k, d):
        return c.get(k) or d
    bg = col("background", "#0B1220")
    s_top = col("surface_top", "#16213A")
    s_bot = col("surface_bottom", "#0F1828")
    border = col("border", "#22324E")
    setup_c = col("setup", "#8B9CFF")
    text_dim = col("text_dim", "#8194B0")
    good = "#2BE0C8"
    bad = "#F56565"
    return f"""
window.soc-assistant {{ background-color: {bg}; }}
assistant.soc-assistant {{ background-color: {bg}; }}
.soc-assistant {{ background-color: {bg}; color: {col("text", "#E8EEF7")}; }}
.soc-header {{ background-image: linear-gradient(to bottom, {s_top}, {bg});
  border-bottom: 1px solid {border}; padding: 16px 20px 14px 20px; }}
.soc-page {{ background-image: linear-gradient(to bottom, {s_top}, {s_bot});
  padding: 16px 18px; }}
.soc-section-title {{ color: {setup_c}; font-weight: bold; }}
.soc-card {{ background-image: linear-gradient(to bottom, {s_top}, {s_bot});
  border: 1px solid {border}; border-left: 4px solid {setup_c}; border-radius: 12px;
  padding: 11px 14px; transition: all 160ms ease; }}
.soc-card:hover {{ border-color: {setup_c}; box-shadow: 0 8px 24px {_rgba(setup_c, 0.22)}; }}
.soc-card:checked {{ border-color: {setup_c}; background-image: linear-gradient(to bottom, {s_top}, {s_top}); }}
.soc-field-bad {{ border: 1px solid {bad}; }}
.soc-field-good {{ border: 1px solid {_rgba(good, 0.6)}; }}
.soc-mono {{ font-family: monospace; font-size: 10px; }}
.soc-problem {{ color: {bad}; }}
""".encode()


# --------------------------------------------------------------------------- #
# GUI assistant.  Everything below imports gi; it is only reached from run_gui.
# --------------------------------------------------------------------------- #
class SetupAssistant:
    """Wraps a Gtk.Assistant with the six wizard pages. All GTK objects are
    created + mutated on the GTK main thread (the wizard runs no background
    threads — the seal/network work on Write runs synchronously in the handler)."""

    def __init__(self, model: WizardModel, setup, gtk_mods):
        self.model = model
        self.setup = setup
        self.Gtk, self.Gdk, self.GLib, self.GdkPixbuf = gtk_mods
        _ensure_host_on_path()
        from host import branding, config, mastersource, secretstore  # type: ignore
        self.branding = branding
        self.config = config
        self.mastersource = mastersource
        self.secretstore = secretstore
        self._pin_shown = ""        # set after a successful seal, shown on review
        self._status = ""
        self.assistant = None
        self._review_label = None
        self._preview_buf = None
        self._build()

    # ---- shared widget helpers ------------------------------------------ #
    def _header(self, title, subtitle):
        Gtk = self.Gtk
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t = Gtk.Label(xalign=0)
        t.set_markup(f'<span size="13000" weight="bold" '
                     f'foreground="{self.branding.color("setup")}">{_esc(title)}</span>')
        s = Gtk.Label(xalign=0, wrap=True)
        s.set_markup(f'<span size="9800" foreground="'
                     f'{self.branding.color("text_dim")}">{_esc(subtitle)}</span>')
        box.pack_start(t, False, False, 0)
        box.pack_start(s, False, False, 0)
        return box

    def _page(self, title, subtitle):
        Gtk = self.Gtk
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.get_style_context().add_class("soc-page")
        page.set_border_width(8)
        page.pack_start(self._header(title, subtitle), False, False, 0)
        return page

    def _entry(self, value, validator, on_change):
        """A Gtk.Entry that runs a setup.v_* validator on every change, toggles
        the bad/good CSS class, and reports validity via on_change(is_valid)."""
        Gtk = self.Gtk
        e = Gtk.Entry()
        e.set_text("" if value is None else str(value))
        e.set_hexpand(True)

        def _changed(entry):
            txt = entry.get_text()
            problem = validator(txt) if validator else None
            ctx = entry.get_style_context()
            ctx.remove_class("soc-field-bad")
            ctx.remove_class("soc-field-good")
            if problem:
                ctx.add_class("soc-field-bad")
                entry.set_tooltip_text(problem)
            else:
                ctx.add_class("soc-field-good")
                entry.set_tooltip_text(None)
            on_change(entry.get_text(), problem is None)
        e.connect("changed", _changed)
        return e

    def _row(self, label, widget):
        Gtk = self.Gtk
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        lbl = Gtk.Label(xalign=0)
        lbl.set_markup(f'<span foreground="{self.branding.color("text")}">'
                       f'{_esc(label)}</span>')
        lbl.set_size_request(170, -1)
        row.pack_start(lbl, False, False, 0)
        row.pack_start(widget, True, True, 0)
        return row

    def _page_appended(self, page):
        """True once `page` has actually been appended to the assistant — guards
        set_page_complete() from firing during page construction (when a field's
        'changed' handler runs before append_page)."""
        a = self.assistant
        if a is None or page is None:
            return False
        return any(a.get_nth_page(i) is page for i in range(a.get_n_pages()))

    def _revalidate_page(self, page):
        """Whole-config re-check; sets page complete on the model validating."""
        ok = not self.model.validate()
        if self._page_appended(page):
            self.assistant.set_page_complete(page, ok)
        return ok

    # ---- build ----------------------------------------------------------- #
    def _build(self):
        Gtk = self.Gtk
        self.assistant = Gtk.Assistant()
        self.assistant.get_style_context().add_class("soc-assistant")
        b = self.branding
        self.assistant.set_title((b.get("short_name") or b.get("name")
                                  or "SOC Wall") + " — Setup")
        self.assistant.set_resizable(True)
        self.assistant.set_default_size(-1, -1)
        self.assistant.set_position(Gtk.WindowPosition.CENTER)
        icon = b.icon_path()
        if icon:
            try:
                self.assistant.set_icon_from_file(icon)
            except Exception:
                pass

        self._page_preset()
        self._page_display()
        self._page_panels()
        self._page_vault()
        self._page_vpn()
        self._page_review()

        self.assistant.connect("cancel", lambda *_: self.Gtk.main_quit())
        self.assistant.connect("close", lambda *_: self.Gtk.main_quit())
        self.assistant.connect("escape", lambda *_: self.Gtk.main_quit())
        self.assistant.connect("destroy", lambda *_: self.Gtk.main_quit())
        self.assistant.connect("apply", self._on_apply)
        self.assistant.connect("prepare", self._on_prepare)

    # ---- Page 1: presets ------------------------------------------------- #
    def _page_preset(self):
        Gtk = self.Gtk
        page = self._page("Choose a starting point",
                          "Pick a preset to load, then customise it on the next pages.")
        group = None
        first = True
        for name, disp, desc in discover_presets():
            btn = Gtk.RadioButton.new_from_widget(group)
            if group is None:
                group = btn
            btn.set_label("")
            for ch in btn.get_children():
                btn.remove(ch)
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            card.get_style_context().add_class("soc-card")
            t = Gtk.Label(xalign=0)
            t.set_markup(f'<span weight="bold" foreground="'
                         f'{self.branding.color("setup")}" size="11500">'
                         f'{_esc(disp)}</span>')
            d = Gtk.Label(xalign=0, wrap=True)
            d.set_markup(f'<span foreground="{self.branding.color("text_dim")}" '
                         f'size="9500">{_esc(desc)}</span>')
            card.pack_start(t, False, False, 0)
            card.pack_start(d, False, False, 0)
            btn.add(card)

            def _toggled(b, nm=name, pg=page):
                if b.get_active():
                    err = self.model.apply_preset(nm)
                    if err:
                        self._set_status(err, bad=True)
                    else:
                        self._set_status(f"loaded preset: {nm}")
                    self._refresh_dynamic_pages()
            btn.connect("toggled", _toggled)
            page.pack_start(btn, False, False, 0)
            if first:
                self.model.apply_preset(name)
                first = False

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.INTRO)
        self.assistant.set_page_title(page, "Preset")
        self.assistant.set_page_complete(page, True)

    # ---- Page 2: display ------------------------------------------------- #
    def _page_display(self):
        Gtk = self.Gtk
        page = self._page("Display & grid",
                          "The screen is split into a cols x rows grid; one panel per cell.")
        d = self.model.cfg()["display"]

        def spin(val, lo, hi):
            sb = Gtk.SpinButton.new_with_range(lo, hi, 1)
            sb.set_value(val)
            return sb

        cols = spin(d["cols"], 1, 4)
        rows = spin(d["rows"], 1, 4)
        gap = spin(d["gap"], 0, 512)
        width = spin(d["width"], 320, 7680)
        height = spin(d["height"], 240, 4320)
        auto = Gtk.Switch()
        auto.set_active(bool(d["auto"]))
        auto.set_halign(Gtk.Align.START)
        layout = Gtk.ComboBoxText()
        for L in ("auto", "windows", "single"):
            layout.append_text(L)
        layout.set_active(("auto", "windows", "single").index(d.get("layout", "auto")))

        def apply(*_):
            dd = self.model.cfg()["display"]
            dd["cols"] = int(cols.get_value())
            dd["rows"] = int(rows.get_value())
            dd["gap"] = int(gap.get_value())
            dd["width"] = int(width.get_value())
            dd["height"] = int(height.get_value())
            dd["auto"] = auto.get_active()
            dd["layout"] = layout.get_active_text() or "auto"
            self._revalidate_page(page)
        for w, sig in ((cols, "value-changed"), (rows, "value-changed"),
                       (gap, "value-changed"), (width, "value-changed"),
                       (height, "value-changed"), (layout, "changed")):
            w.connect(sig, apply)
        auto.connect("notify::active", apply)

        page.pack_start(self._row("Grid columns (1-4)", cols), False, False, 0)
        page.pack_start(self._row("Grid rows (1-4)", rows), False, False, 0)
        page.pack_start(self._row("Gap between cells (px)", gap), False, False, 0)
        page.pack_start(self._row("Auto-detect resolution", auto), False, False, 0)
        page.pack_start(self._row("Screen width (px)", width), False, False, 0)
        page.pack_start(self._row("Screen height (px)", height), False, False, 0)
        page.pack_start(self._row("Layout", layout), False, False, 0)

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "Display")
        self._display_page = page
        self._display_widgets = dict(cols=cols, rows=rows, gap=gap, width=width,
                                     height=height, auto=auto, layout=layout)
        self._revalidate_page(page)

    # ---- Page 3: panels -------------------------------------------------- #
    def _page_panels(self):
        Gtk = self.Gtk
        page = self._page("Panels",
                          "Each row is one dashboard window. Validation runs over the whole "
                          "wall, so duplicate ids / grid cells are caught here.")
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(260)
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.add(listbox)

        btnbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        add = Gtk.Button.new_with_label("Add panel")
        rem = Gtk.Button.new_with_label("Remove last")
        btnbar.pack_start(add, False, False, 0)
        btnbar.pack_start(rem, False, False, 0)

        self._panels_page = page
        self._panels_listbox = listbox

        def cap():
            d = self.model.cfg()["display"]
            return max(1, d["cols"] * d["rows"])

        def rebuild():
            for child in listbox.get_children():
                listbox.remove(child)
            for i, p in enumerate(self.model.cfg()["panels"]):
                listbox.add(self._panel_row(i, p, page))
            listbox.show_all()
            self._revalidate_page(page)

        def on_add(_b):
            panels = self.model.cfg()["panels"]
            if len(panels) >= cap():
                self._set_status(f"grid holds at most {cap()} panels", bad=True)
                return
            panels.append(_def_panel(len(panels), self.model.cfg()["display"]["cols"],
                                     self.setup))
            self.model.set_cfg(self.model.cfg())  # renormalise
            rebuild()

        def on_rem(_b):
            panels = self.model.cfg()["panels"]
            if panels:
                panels.pop()
                rebuild()
        add.connect("clicked", on_add)
        rem.connect("clicked", on_rem)

        page.pack_start(btnbar, False, False, 0)
        page.pack_start(scroller, True, True, 0)
        self._rebuild_panels = rebuild
        rebuild()

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "Panels")

    def _panel_row(self, idx, p, page):
        Gtk = self.Gtk
        row = Gtk.ListBoxRow()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.get_style_context().add_class("soc-card")
        box.set_border_width(6)
        title = Gtk.Label(xalign=0)
        title.set_markup(f'<span weight="bold" foreground="'
                         f'{self.branding.color("setup")}">Panel {idx + 1}</span>')
        box.pack_start(title, False, False, 0)

        grid = Gtk.Grid()
        grid.set_column_spacing(8)
        grid.set_row_spacing(4)
        r = 0

        def add_field(label, widget):
            nonlocal r
            lbl = Gtk.Label(xalign=0, label=label)
            lbl.set_size_request(130, -1)
            grid.attach(lbl, 0, r, 1, 1)
            grid.attach(widget, 1, r, 1, 1)
            r += 1

        def on_change(*_):
            self._revalidate_page(page)

        pid = Gtk.Entry()
        pid.set_text(str(p.get("id", "")))
        pid.set_hexpand(True)

        def _pid(e):
            p["id"] = e.get_text()
            on_change()
        pid.connect("changed", _pid)
        add_field("id", pid)

        engine = Gtk.ComboBoxText()
        for eng in ("webkit", "chromium"):
            engine.append_text(eng)
        engine.set_active(0 if p.get("engine", "webkit") == "webkit" else 1)

        def _eng(c):
            p["engine"] = c.get_active_text() or "webkit"
            on_change()
        engine.connect("changed", _eng)
        add_field("engine", engine)

        d = self.model.cfg()["display"]
        gcol = Gtk.SpinButton.new_with_range(0, max(0, d["cols"] - 1), 1)
        gcol.set_value(p.get("grid", [0, 0])[0])
        grow = Gtk.SpinButton.new_with_range(0, max(0, d["rows"] - 1), 1)
        grow.set_value(p.get("grid", [0, 0])[1])

        def _grid(*_):
            p["grid"] = [int(gcol.get_value()), int(grow.get_value())]
            on_change()
        gcol.connect("value-changed", _grid)
        grow.connect("value-changed", _grid)
        gbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        gbox.pack_start(gcol, False, False, 0)
        gbox.pack_start(grow, False, False, 0)
        add_field("grid [col,row]", gbox)

        mode = Gtk.ComboBoxText()
        for m in ("direct", "tunnel"):
            mode.append_text(m)
        mode.set_active(0 if p.get("mode", "direct") == "direct" else 1)

        url = self._entry(p.get("url", ""), self.setup.v_url,
                          lambda v, ok: (_set(p, "url", v), on_change()))

        def _mode(c):
            p["mode"] = c.get_active_text() or "direct"
            if p["mode"] == "tunnel":
                p.setdefault("tunnel", dict(local_port=19100 + idx + 1,
                                            remote_host="10.20.0.7", remote_port=443))
                p.pop("url", None)
            else:
                p["url"] = url.get_text() or "http://192.168.1.50:3000/login"
                p.pop("tunnel", None)
            url.set_sensitive(p["mode"] == "direct")
            on_change()
        mode.connect("changed", _mode)
        add_field("mode", mode)
        add_field("url", url)
        url.set_sensitive(p.get("mode", "direct") == "direct")

        vault = Gtk.Entry()
        vault.set_text(str(p.get("vault_item", "")))
        vault.set_hexpand(True)

        def _vault(e):
            p["vault_item"] = e.get_text()
            on_change()
        vault.connect("changed", _vault)
        add_field("vault item", vault)

        sel = p.setdefault("selectors", {})
        for key, label in (("user", "user selector"), ("pass", "pass selector"),
                           ("submit", "submit selector")):
            ent = Gtk.Entry()
            ent.set_text(str(sel.get(key, "")))
            ent.set_hexpand(True)

            def _sel(e, k=key):
                sel[k] = e.get_text()
                on_change()
            ent.connect("changed", _sel)
            add_field(label, ent)

        box.pack_start(grid, False, False, 0)
        row.add(box)
        return row

    # ---- Page 4: vault + master ----------------------------------------- #
    def _page_vault(self):
        Gtk = self.Gtk
        page = self._page("Secrets vault & master password",
                          "Where the kiosk reads logins from, and how the master password "
                          "is sealed. The master is NEVER written to any file.")
        m = self.model

        backend = Gtk.ComboBoxText()
        for be in ("litebw", "rbw", "dev"):
            backend.append_text(be)
        backend.set_active(("litebw", "rbw", "dev").index(
            m.vault_backend if m.vault_backend in ("litebw", "rbw", "dev") else "dev"))

        # Gate the page on the SAME validators the entries already paint with, so
        # the GUI matches the TTY wizard's no-invalid-submit behaviour (an invalid
        # email/URL is un-submittable there). The `ok` flag the _entry callback
        # hands back drives these — never written unconditionally. Seed the initial
        # state by running the validators once on the model's current values.
        self._vault_email_ok = self.setup.v_email(m.vault_email or "") is None
        self._vault_url_ok = self.setup.v_url(m.vault_url or "") is None

        def _set_email(v, ok):
            m.vault_email = v
            self._vault_email_ok = ok
            self._recheck_vault(page)

        def _set_url(v, ok):
            m.vault_url = v
            self._vault_url_ok = ok
            self._recheck_vault(page)

        email = self._entry(m.vault_email, self.setup.v_email, _set_email)
        url = self._entry(m.vault_url, self.setup.v_url, _set_url)

        srcs = self.mastersource.available_sources()
        source = Gtk.ComboBoxText()
        for s in ("auto", "sealed", "secret-service", "env"):
            mark = "" if s in srcs or s == "auto" else "  (unavailable)"
            source.append_text(s + mark)
        source.set_active(0)

        pw = Gtk.Entry()
        pw.set_visibility(False)
        pw.set_placeholder_text("master password (sealed on Write, never stored to a file)")
        pw.set_hexpand(True)

        pin = Gtk.Entry()
        pin.set_placeholder_text("one-time PIN (blank = auto-generate)")
        pin.set_hexpand(True)

        hint = Gtk.Label(xalign=0, wrap=True)
        hint.set_markup(f'<span size="9000" foreground="'
                        f'{self.branding.color("text_dim")}">'
                        f'A headless wall’s wallet is locked at boot — prefer '
                        f'“sealed” for unattended use. “env” is dev-only.'
                        f'</span>')

        def on_backend(*_):
            be = backend.get_active_text() or "dev"
            m.vault_backend = be
            dev = be == "dev"
            for w in (email, url, pw, pin, source):
                w.set_sensitive(not dev)
            self._recheck_vault(page)

        def on_source(*_):
            txt = (source.get_active_text() or "auto").split("  ")[0]
            m.master_source = txt
            pin.set_sensitive(txt in ("auto", "sealed"))

        def on_pw(e):
            m.master_password = e.get_text()

        def on_pin(e):
            m.master_pin = e.get_text()
        backend.connect("changed", on_backend)
        source.connect("changed", on_source)
        pw.connect("changed", on_pw)
        pin.connect("changed", on_pin)

        page.pack_start(self._row("Vault backend", backend), False, False, 0)
        page.pack_start(self._row("Account email", email), False, False, 0)
        page.pack_start(self._row("Vaultwarden URL", url), False, False, 0)
        page.pack_start(self._row("Master source", source), False, False, 0)
        page.pack_start(self._row("Master password", pw), False, False, 0)
        page.pack_start(self._row("One-time PIN", pin), False, False, 0)
        page.pack_start(hint, False, False, 0)

        on_backend()
        on_source()

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "Vault")
        self._recheck_vault(page)

    def _recheck_vault(self, page):
        """Vault page is complete when the backend is 'dev' (email/URL ignored),
        or — for litebw/rbw — BOTH the account email and the Vaultwarden URL pass
        their setup.v_* validators. Mirrors the TTY wizard, which won't accept an
        invalid email/URL, so the GUI can't write a broken soc.env."""
        m = self.model
        ok = (m.vault_backend == "dev") or (self._vault_email_ok and self._vault_url_ok)
        if self._page_appended(page):
            self.assistant.set_page_complete(page, ok)
        return ok

    # ---- Page 5: VPN (+ proxy) ------------------------------------------ #
    def _page_vpn(self):
        Gtk = self.Gtk
        page = self._page("VPN (optional)",
                          "One supervised tunnel so VPN-side panels can use mode: direct.")
        v = self.model.cfg()["vpn"]

        enable = Gtk.Switch()
        enable.set_active(bool(v.get("enabled")))
        enable.set_halign(Gtk.Align.START)
        page.pack_start(self._row("Enable VPN", enable), False, False, 0)

        fields = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        page.pack_start(fields, False, False, 0)

        vtype = Gtk.ComboBoxText()
        for t in ("fortinet", "openvpn", "wireguard", "inode"):
            vtype.append_text(t)
        vtype.set_active(0)
        fields.pack_start(self._row("VPN type", vtype), False, False, 0)

        gateway = self._entry(v.get("gateway", ""), self.setup.v_host,
                              lambda val, ok: _set(v, "gateway", val))
        port = Gtk.SpinButton.new_with_range(1, 65535, 1)
        port.set_value(int(v.get("port", 443)))
        vault = Gtk.Entry()
        vault.set_text(str(v.get("vault_item", "")))
        cert = self._entry(v.get("trusted_cert", ""), self.setup.v_sha256,
                           lambda val, ok: _set(v, "trusted_cert", val))
        config_path = Gtk.Entry()
        config_path.set_text(str(v.get("config", "")))

        fields.pack_start(self._row("Gateway host", gateway), False, False, 0)
        fields.pack_start(self._row("Gateway port", port), False, False, 0)
        fields.pack_start(self._row("Vault item", vault), False, False, 0)
        fields.pack_start(self._row("Trusted cert (sha256)", cert), False, False, 0)
        fields.pack_start(self._row("Config path (ovpn/wg)", config_path), False, False, 0)

        def collect(*_):
            v = self.model.cfg()["vpn"]
            if not enable.get_active():
                v.clear()
                v["enabled"] = False
                self._revalidate_page(page)
                fields.set_sensitive(False)
                return
            fields.set_sensitive(True)
            t = vtype.get_active_text() or "fortinet"
            v.clear()
            v["enabled"] = True
            v["type"] = t
            if t in ("fortinet", "inode"):
                v["gateway"] = gateway.get_text()
                v["port"] = int(port.get_value())
                v["vault_item"] = vault.get_text()
                v["trusted_cert"] = cert.get_text()
                if t == "fortinet":
                    v["realm"] = ""
                    v["set_routes"] = True
                    v["set_dns"] = False
                    v["half_internet_routes"] = False
                    v["persistent"] = 0
                    v["otp_from_vault"] = False
                else:
                    v["insecure"] = False
            else:  # openvpn / wireguard
                v["config"] = config_path.get_text()
                if t == "openvpn":
                    v["vault_item"] = vault.get_text()
                    v["set_routes"] = True
            self._revalidate_page(page)

        enable.connect("notify::active", collect)
        vtype.connect("changed", collect)
        for w in (gateway, vault, cert, config_path):
            w.connect("changed", lambda *_: collect())
        port.connect("value-changed", collect)
        collect()

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "VPN")
        self._vpn_page = page
        self._revalidate_page(page)

    # ---- Page 6: review + write ----------------------------------------- #
    def _page_review(self):
        Gtk = self.Gtk
        page = self._page("Review & write",
                          "Confirm the summary, then Apply to write the files and seal the master.")
        self._review_label = Gtk.Label(xalign=0)
        self._review_label.get_style_context().add_class("soc-mono")
        page.pack_start(self._review_label, False, False, 0)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(220)
        view = Gtk.TextView()
        view.set_editable(False)
        view.set_monospace(True)
        view.get_style_context().add_class("soc-mono")
        self._preview_buf = view.get_buffer()
        scroller.add(view)
        page.pack_start(scroller, True, True, 0)

        self._status_label = Gtk.Label(xalign=0, wrap=True)
        page.pack_start(self._status_label, False, False, 0)

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONFIRM)
        self.assistant.set_page_title(page, "Review")
        self._review_page = page

    # ---- dynamic refresh ------------------------------------------------- #
    def _refresh_dynamic_pages(self):
        if hasattr(self, "_display_widgets"):
            d = self.model.cfg()["display"]
            w = self._display_widgets
            w["cols"].set_value(d["cols"])
            w["rows"].set_value(d["rows"])
            w["gap"].set_value(d["gap"])
            w["width"].set_value(d["width"])
            w["height"].set_value(d["height"])
            w["auto"].set_active(bool(d["auto"]))
            w["layout"].set_active(("auto", "windows", "single").index(
                d.get("layout", "auto")))
        if hasattr(self, "_rebuild_panels"):
            self._rebuild_panels()

    def _on_prepare(self, assistant, page):
        if page is getattr(self, "_review_page", None):
            self._update_review()
        if page is getattr(self, "_panels_page", None) and hasattr(self, "_rebuild_panels"):
            self._rebuild_panels()

    def _update_review(self):
        cfg = self.model.cfg()
        lines = []
        lines.append(f"{len(cfg['panels'])} panel(s); "
                     f"tunnel {'ON' if cfg['tunnel'].get('enabled') else 'off'}; "
                     f"VPN {'ON' if cfg['vpn'].get('enabled') else 'off'}; "
                     f"proxy {'ON' if cfg.get('proxy', {}).get('enabled') else 'off'}")
        for p in cfg["panels"]:
            tgt = p.get("url") or f"tunnel:{p.get('tunnel', {}).get('local_port')}"
            lines.append(f"  - {p['id']} [{p['engine']}/{p['mode']}] {tgt}  <- {p['vault_item']}")
        problems = self.model.validate()
        self._review_label.set_text("\n".join(lines))
        if self._preview_buf is not None:
            self._preview_buf.set_text(self.model.panels_yaml())
        ok = not problems
        if problems:
            self._set_status("config invalid: " + "; ".join(problems), bad=True)
        else:
            self._set_status(self._status or "ready to write")
        self.assistant.set_page_complete(self._review_page, ok)

    # ---- status ---------------------------------------------------------- #
    def _set_status(self, text, bad=False):
        self._status = "" if bad else text
        if getattr(self, "_status_label", None) is not None:
            col = self.branding.color("text_dim") if not bad else "#F56565"
            self._status_label.set_markup(
                f'<span foreground="{col}">{_esc(text)}</span>')

    # ---- Apply / Write --------------------------------------------------- #
    def _on_apply(self, assistant):
        try:
            self._write()
        except Exception as e:  # noqa: BLE001
            self._set_status(f"write failed: {e}", bad=True)

    def _write(self):
        setup = self.setup
        paths = self.model.paths
        cfg = self.model.cfg()
        env = self.model.soc_env()

        setup.write_file(paths["panels_out"], setup.render_panels_yaml(cfg),
                         paths["panels_mode"], dry=False)
        env_text = setup.render_soc_env(env)
        assert "SOC_VAULT_PASSWORD" not in env_text
        setup.write_file(paths["soc_env"], env_text, paths["env_mode"], dry=False)
        if paths.get("wall_unit"):
            setup.write_file(paths["wall_unit"],
                             setup.render_wall_unit(env, soc_root=paths["soc_root"]),
                             0o644, dry=False)

        # Seal / store the master per the chosen source. NEVER write it to a file.
        # Delegate the whole seal/store/verify/rewrite/client-config orchestration
        # to setup.seal_master — the SAME core the TTY first-run wizard runs — so
        # the two wizards seal identically and cannot drift.
        pw = self.model.master_password
        src = self.model.master_source
        backend = self.model.vault_backend
        if pw and backend in ("litebw", "rbw"):
            try:
                pin = setup.seal_master(
                    pw, source=src, pin=self.model.master_pin, paths=paths,
                    soc_env=env, backend=backend, dry=False)
                if pin:                       # sealed path -> surface the one-time PIN
                    self._pin_shown = pin
                    self._set_status(f"sealed master (host-bound). ONE-TIME PIN: {pin}")
                elif src == "secret-service":
                    self._set_status("stored master in the Secret Service wallet")
                else:
                    self._set_status("files written")
            except setup.SealMasterError as e:
                self._set_status(f"seal failed: {e}", bad=True)
            finally:
                pw = ""
                self.model.master_password = ""
        else:
            self._set_status("files written")

        # Optional: push the wall config into Vaultwarden (reuses setup.py verbatim).
        if self.model.push_config and backend in ("litebw", "rbw"):
            try:
                setup.push_config_to_vault(env, cfg, paths, dry=False)
            except Exception as e:  # noqa: BLE001
                self._set_status(f"config-to-vault skipped: {e}", bad=True)


def _set(d: dict, k, v):
    d[k] = v


# --------------------------------------------------------------------------- #
# GUI driver
# --------------------------------------------------------------------------- #
def run_gui() -> int:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, Gdk, GLib, GdkPixbuf

    setup = _load_setup()
    _ensure_host_on_path()
    from host import branding  # type: ignore

    env = setup.Env()
    target = "pi" if env.is_root else "dev"
    paths = setup.resolve_paths(target)

    provider = Gtk.CssProvider()
    provider.load_from_data(_css(branding))
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    model = WizardModel(setup, paths)
    sa = SetupAssistant(model, setup, (Gtk, Gdk, GLib, GdkPixbuf))
    sa.assistant.show_all()
    Gtk.main()
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    names = preset_names()
    ap = argparse.ArgumentParser(
        prog="host.setupgui",
        description="Graphical SOC-wall setup wizard (and a headless preset renderer).")
    ap.add_argument("--preset", choices=names or None,
                    help="HEADLESS: render this preset's panels.yaml + soc.env to --output")
    ap.add_argument("--output", help="HEADLESS: output directory (created if absent)")
    ap.add_argument("--non-interactive", action="store_true",
                    help="HEADLESS: no prompts; dev-safe defaults (no sealing)")
    ap.add_argument("--list-presets", action="store_true",
                    help="print the available presets and exit")
    ap.add_argument("--gui", action="store_true", help="force the GUI")
    args = ap.parse_args(argv)

    if args.list_presets:
        for name, disp, desc in discover_presets():
            print(f"{name}\t{disp}\t{desc}")
        return 0

    # HEADLESS render path — no gi, no window.
    if args.preset or args.output:
        if not (args.preset and args.output):
            sys.stderr.write("setupgui: --preset and --output must be given together\n")
            return 2
        return build_headless(args.preset, args.output,
                              non_interactive=args.non_interactive)

    # GUI path — needs a display unless explicitly forced.
    if not args.gui and not (os.environ.get("DISPLAY")
                             or os.environ.get("WAYLAND_DISPLAY")):
        sys.stderr.write(
            "setupgui: no graphical display — run the text wizard instead:\n"
            "  python3 setup.py wizard\n")
        return 1
    try:
        return run_gui()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"setupgui: GUI failed to start ({e}); "
                         "run the text wizard: python3 setup.py wizard\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
