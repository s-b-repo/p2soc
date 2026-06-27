"""
SOC video-wall — GRAPHICAL setup wizard (GTK3 / PyGObject).

A desktop-launchable wizard that produces the SAME artifacts as the TTY wizard
(``setup.py wizard``): ``panels.yaml`` + the non-secret ``soc.env`` (+ the
supervised ``soc-wall.service`` unit), and seals/stores the vault master per the
chosen source. It does NOT duplicate any rendering / validation / sealing logic:
it imports ``setup.py`` as a module and calls its renderers (``render_panels_yaml``
/ ``render_soc_env`` / ``render_wall_unit``), its validators (``v_*``), and its
credential + master-seal flow — so the two wizards can never drift.

Styling matches host.launchermenu (the green-on-white SOC console) via a shared
Gtk.CssProvider; window title / header / accents come from host.branding so a
rebrand (branding/branding.yaml) reskins both the launcher and this wizard.

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
import re
import shutil
import subprocess
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


_PROVISION = None


def _load_provision():
    """Import the repo-root provision.py AS A MODULE (same spec_from_file_location
    trick as _load_setup). provision.py is a TOP-LEVEL module (NOT under host/) and
    is import-safe (pure-stdlib top; side effects only under ``if __name__ ==
    '__main__'``). Cached so repeated calls are cheap. Returns None if absent."""
    global _PROVISION
    if _PROVISION is not None:
        return _PROVISION
    path = os.path.join(_repo_root(), "provision.py")
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location("soc_provision", path)
    mod = importlib.util.module_from_spec(spec)
    # Register BEFORE exec: provision.py uses @dataclass, and dataclasses resolves
    # each class's __module__ via sys.modules — an unregistered module makes
    # _process_class raise AttributeError('NoneType' has no '__dict__').
    sys.modules["soc_provision"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop("soc_provision", None)
        raise
    _PROVISION = mod
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

    vpns = _normalize_vpns_gui(raw)

    proxy = dict(raw.get("proxy") or {"enabled": False})
    proxy.setdefault("enabled", False)

    # Keep a back-compat `vpn` mirror (vpns[0] or a disabled stub) so the review
    # summary and any old single-VPN reader keep working — new code reads `vpns`.
    vpn = dict(vpns[0]) if vpns else {"enabled": False}
    return dict(display=display, panels=panels, tunnel=tunnel,
                vpns=vpns, vpn=vpn, proxy=proxy)


# Cap + name charset mirror kiosk-host/host/config.py (MAX_VPNS / _VPN_NAME_RE).
MAX_VPNS = 8
_VPN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _def_vpn(idx: int = 0) -> dict:
    """A fresh, disabled VPN row with a stable unique-ish default name."""
    return dict(name=("vpn" if idx == 0 else f"vpn{idx + 1}"),
                enabled=False, type="fortinet", default_route=False,
                gateway="", port=443, vault_item="", trusted_cert="", config="")


def _normalize_vpns_gui(raw: dict) -> list:
    """Resolve raw `vpns:`/`vpn:` into the authoritative LIST, mirroring
    config._normalize_vpns: a `vpns:` list wins; else a legacy `vpn:` dict is
    wrapped as one entry; else []. Each entry gets a stable `name` and a
    `default_route` default so the GUI rows have something to bind to."""
    if raw.get("vpns") is not None:
        src = raw.get("vpns")
        src = list(src) if isinstance(src, list) else []
    elif isinstance(raw.get("vpn"), dict) and raw.get("vpn"):
        src = [raw["vpn"]]
    else:
        src = []
    out = []
    for i, v in enumerate(src):
        e = dict(v) if isinstance(v, dict) else {}
        nm = str(e.get("name", "") or "").strip()
        e["name"] = nm or ("vpn" if i == 0 else f"vpn{i + 1}")
        e["enabled"] = bool(e.get("enabled", False))
        e["type"] = e.get("type", "fortinet") or "fortinet"
        e["default_route"] = bool(e.get("default_route", False))
        out.append(e)
    return out


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
        # full-install mode (kiosk = takes over tty1; desktop = runs in a DE session).
        # Matches provision.Opts default; bound to the Install page's mode combo.
        self.install_mode = "kiosk"

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
        # normalize ONCE; validate that same dict by rendering it (don't re-normalize)
        normalized = normalize_cfg(raw, setup)
        try:
            self._ensure_config_mod().load_str(setup.render_panels_yaml(normalized))
        except Exception as e:  # noqa: BLE001
            self._cfg = normalize_cfg(None, setup)
            return f"preset {name!r} did not validate ({e}); starting blank"
        self._cfg = normalized
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
    _ensure_host_on_path()
    try:
        # Imported only to confirm host.config is importable before we proceed;
        # the actual validation runs via setup.py's renderers below.
        from host import config as _config  # type: ignore  # noqa: F401
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


def _mix(fg: str, bg: str, t: float) -> str:
    """Solid #RRGGBB = `fg` blended `t` of the way toward `bg`. Used for the
    low-opacity watermark numerals, since Pango markup ``foreground=`` accepts a
    colour spec but NOT an rgba() with alpha (unlike CSS)."""
    fr, fgc, fb = _to_rgb(fg)
    br, bg2, bb = _to_rgb(bg)
    t = max(0.0, min(1.0, t))
    r = round(fr + (br - fr) * t)
    g = round(fgc + (bg2 - fgc) * t)
    b = round(fb + (bb - fb) * t)
    return f"#{r:02X}{g:02X}{b:02X}"


def _css(branding) -> bytes:
    """The green-on-white console theme, driven entirely from branding colours so a
    rebrand (branding.yaml) reskins the wizard exactly as it reskins the launcher.
    Flat surfaces, low radius, a 4px green left-border + green focus glow — the
    recoloured terminal/console aesthetic. No gradients, no rest-state shadows."""
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
    setup_c = col("setup", "#1FA463")
    good = col("good", "#1FA463")
    bad = col("bad", "#C0341D")
    glow = _rgba(accent, 0.28)
    # On-surface accent for the section-title TEXT (sits on `surface`): swap the
    # brand green for accent_strong where it dips below AA on the tinted surface.
    accent_surf = branding.accent_on(surface, accent=accent, strong=accent_strong)
    # Primary-button label: palette-derived so it reads on the accent fill on any
    # theme (white on a dark fill, near-black on a light one) — never hardcoded.
    btn_fg = branding.text_on(accent_strong, dark=text)
    # CYBER GLOW (dark palettes only), branding-derived, motion gated below.
    dark = branding.is_dark(bg)
    glow_css = ""
    if dark:
        halo = _rgba(accent, 0.5)
        glow_css = f"""
.soc-section-title {{ text-shadow: 0 0 6px {_rgba(accent, 0.6)}; }}
.soc-header {{ box-shadow: inset 0 2px 0 -1px {halo}; }}
.soc-card:hover {{ box-shadow: inset 0 0 0 1px {accent}, 0 6px 18px {_rgba(accent, 0.22)}; }}
"""
    return f"""
window.soc-assistant {{ background-color: {bg}; }}
assistant.soc-assistant {{ background-color: {bg}; }}
.soc-assistant {{ background-color: {bg}; color: {text}; }}
.soc-assistant headerbar {{ background-color: {surface};
  border-bottom: 1px solid {border}; box-shadow: inset 0 2px 0 {accent}; }}
.soc-header {{ background-color: {surface};
  border-top: 2px solid {accent}; border-bottom: 1px solid {border};
  padding: 16px 20px 14px 20px; }}
.soc-page {{ background-color: {surface}; padding: 16px 18px; }}
.soc-section-title {{ color: {accent_surf}; font-weight: bold; }}
.soc-divider {{ background-color: {border}; min-height: 1px; }}

.soc-card {{ background-color: {surface};
  border: 1px solid {border}; border-left: 4px solid {setup_c}; border-radius: 6px;
  padding: 13px 16px; transition: all 160ms ease; }}
.soc-card:hover {{ border-color: {accent}; background-color: {sunken};
  box-shadow: inset 0 0 0 1px {accent}, 0 6px 18px {glow}; }}
.soc-card:checked {{ border-color: {accent}; border-left: 4px solid {accent};
  background-color: {sunken}; }}

/* Gtk.Assistant left page-list sidebar — recolour the default-GTK selection
   (blue) current-page marker to a green left-bar + green-tinted fill so the
   page list reads as the green console, not stock GTK. */
.soc-assistant .sidebar {{ background-color: {surface};
  border-right: 1px solid {border}; }}
.soc-assistant .sidebar label {{ color: {text_dim}; padding: 4px 10px; }}
.soc-assistant .sidebar label.highlight {{ background-color: {sunken};
  color: {accent_strong}; box-shadow: inset 3px 0 0 {accent}; font-weight: bold; }}

/* Preset-tile radio indicators — the tile already shows a green '▸' marker on
   selection, so hide the default-GTK (blue) check/ring for a clean card look. */
.soc-assistant radio {{ -gtk-icon-source: none; min-width: 0; min-height: 0;
  margin: 0; padding: 0; border: 0; background: none; box-shadow: none; }}

entry {{ background-color: {sunken}; color: {text};
  border: 1px solid {border}; border-radius: 4px; padding: 6px 8px; }}
entry:focus {{ border: 1px solid {accent}; box-shadow: 0 0 0 2px {glow}; }}
entry image, entry placeholder {{ color: {text_dim}; }}
.soc-field-bad {{ border: 1px solid {bad}; }}
.soc-field-bad:focus {{ border: 1px solid {bad}; box-shadow: 0 0 0 2px {_rgba(bad, 0.28)}; }}
.soc-field-good {{ border: 1px solid {good}; }}

/* SpinButton, ComboBox + its dropdown popup, and any plain button — palette-driven
   so they don't fall back to GTK's stock LIGHT theme (a white spin/combo + white
   button) on a DARK palette, which is the classic dark-theme black-on-white glitch
   (and where the unthemed white 'Test connection' button came from). */
spinbutton {{ background-color: {sunken}; color: {text};
  border: 1px solid {border}; border-radius: 4px; }}
spinbutton entry {{ border: 0; background-color: transparent; }}
spinbutton button {{ background-image: none; background-color: {sunken};
  color: {text_dim}; border: 0; }}
spinbutton button:hover {{ color: {accent_surf}; }}
combobox button.combo {{ background-image: none; background-color: {sunken};
  color: {text}; border: 1px solid {border}; border-radius: 4px; padding: 4px 8px; }}
combobox button.combo:hover {{ border-color: {accent}; }}
combobox arrow {{ color: {text_dim}; }}
combobox window, combobox window.background,
combobox menu, .menu, menu {{ background-color: {surface}; color: {text};
  border: 1px solid {border}; }}
combobox cellview, cellview {{ color: {text}; }}
menuitem {{ color: {text}; padding: 3px 8px; }}
menuitem:hover, menuitem:selected {{ background-color: {sunken}; color: {text}; }}
/* A plain (unclassed) button on a page — give it the ghost look so it isn't a
   stock white box on a dark theme (e.g. 'Test connection', 'Add panel'). */
.soc-page button {{ background-image: none; background-color: {sunken};
  color: {text}; border: 1px solid {border}; border-radius: 6px; padding: 5px 12px; }}
.soc-page button:hover {{ border-color: {accent}; background-color: {sunken}; }}

/* The Assistant's OWN nav buttons (Cancel/Back/Next/Apply) live in its headerbar.
   GTK leaves them stock-light, so on a DARK palette the label inherits the theme's
   light `color` while the button stays light -> unreadable ("the Next button is not
   readable"). Theme them from the palette: plain = ghost; the suggested-action
   (Next/Apply) = the primary accent fill with a palette-contrasting label. */
.soc-assistant headerbar button {{ background-image: none; background-color: {sunken};
  color: {text}; border: 1px solid {border}; border-radius: 6px; padding: 5px 14px; }}
.soc-assistant headerbar button:hover {{ border-color: {accent}; background-color: {sunken}; }}
.soc-assistant headerbar button:disabled {{ color: {text_dim}; opacity: 1; }}
.soc-assistant headerbar button.suggested-action {{ background-color: {accent_strong};
  color: {btn_fg}; border-color: {accent_strong}; font-weight: bold; }}
.soc-assistant headerbar button.suggested-action:hover {{ border-color: {accent};
  box-shadow: inset 0 0 0 1px {accent}; }}

button.soc-primary {{ background-image: none; background-color: {accent_strong};
  color: {btn_fg}; border: 1px solid {accent_strong}; border-radius: 6px;
  font-weight: bold; padding: 6px 14px; }}
button.soc-primary:hover {{ background-color: {accent_strong};
  border-color: {accent}; color: {btn_fg};
  box-shadow: inset 0 0 0 1px {accent}, 0 4px 14px {glow}; }}
button.soc-ghost {{ background-image: none; background-color: transparent;
  color: {accent_strong}; border: 1px solid {border}; border-radius: 6px;
  padding: 6px 12px; }}
button.soc-ghost:hover {{ background-color: {sunken}; border-color: {accent}; }}

.soc-mono {{ font-family: monospace; font-size: 10px; }}
.soc-problem {{ color: {bad}; }}
{glow_css}""".encode()


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
        # Vault account creation (register the kiosk account when it doesn't yet
        # exist). Optional — degrades to "create it in the web vault" if the
        # crypto backend is missing, so it is never a hard dependency.
        try:
            from host import vaultsetup  # type: ignore
            self.vaultsetup = vaultsetup
        except Exception:  # noqa: BLE001 — never block the wizard on this
            self.vaultsetup = None
        # Full-install / provisioning core (the GUI analogue of `setup.py provision`).
        # Optional — degrades to "use the CLI: setup.py provision" if absent, so the
        # config-only Finish never depends on it.
        self.provision = _load_provision()
        self._install_dry = True    # dry-run preview by default (safe)
        self._install_buf = None    # the per-step progress TextView buffer
        self._install_page = None
        self._install_run_btn = None
        self._install_status = None
        self._install_busy = False  # True while a real (non-dry) run is in flight
        self._pin_shown = ""        # set after a successful seal, shown on review
        self._status = ""
        self.assistant = None
        self._review_label = None
        self._preview_buf = None
        self._step = 0              # '// step NN' counter for page overlines
        self._build()

    def _step_overline(self, label):
        """Next '// step NN — <label>' overline; bumps the page counter."""
        self._step += 1
        return f"step {self._step:02d} — {label}"

    # ---- shared widget helpers ------------------------------------------ #
    def _comment(self, text):
        """A '// comment-style' mono overline (text_dim) — the kept section-header
        signature. The literal '// ' prefix reads as a code comment."""
        Gtk = self.Gtk
        lbl = Gtk.Label(xalign=0)
        lbl.set_markup(
            f'<span font_family="monospace" size="8800" '
            f'foreground="{self.branding.color("text_dim")}">'
            f'// {_esc(text)}</span>')
        return lbl

    def _header(self, title, subtitle, overline=None):
        """A page/section header: a '// <overline>' mono comment, a TIGHT bold sans
        title in near-black-green text, then a body subtitle in text_dim."""
        Gtk = self.Gtk
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        if overline:
            box.pack_start(self._comment(overline), False, False, 0)
        t = Gtk.Label(xalign=0)
        t.set_markup(f'<span size="13000" weight="bold" letter_spacing="-400" '
                     f'foreground="{self.branding.color("text")}">{_esc(title)}</span>')
        s = Gtk.Label(xalign=0, wrap=True)
        s.set_markup(f'<span size="9800" foreground="'
                     f'{self.branding.color("text_dim")}">{_esc(subtitle)}</span>')
        box.pack_start(t, False, False, 0)
        box.pack_start(s, False, False, 0)
        return box

    def _page(self, title, subtitle, overline=None):
        Gtk = self.Gtk
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.get_style_context().add_class("soc-page")
        page.set_border_width(8)
        page.pack_start(self._header(title, subtitle, overline=overline),
                        False, False, 0)
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
        brand_title = (b.get("short_name") or b.get("name") or "SOC Wall") + " — Setup"
        # FIX: Gtk.Assistant copies each page's set_page_title() into the window
        # title bar, leaking the per-page name ("Display", "Vault", ...). Attach a
        # custom Gtk.HeaderBar carrying the branded '<name> — Setup' title (+ tagline
        # subtitle) so the window chrome always reads as the product, not the page.
        # set_title() is kept as a fallback for WMs that ignore client-side headerbars.
        self.assistant.set_title(brand_title)
        # Do NOT set a custom Gtk.HeaderBar via set_titlebar() here. A Gtk.Assistant
        # keeps its Back/Next/Cancel/Apply navigation buttons in its OWN header bar;
        # replacing it removes them, leaving the wizard with no way to advance — that
        # was the "Next button is broken" bug. The per-page title leak is handled
        # instead by _clamp_title (notify::title), which resets the WINDOW title the
        # default header bar shows — so we keep both the branded title AND the buttons.
        self._headerbar = None
        self._brand_title = brand_title
        # Gtk.Assistant's own 'prepare' default-handler stamps the *current page's*
        # title onto the window every transition (running AFTER our 'prepare'), which
        # leaks "Display"/"Vault"/... into the chrome. Clamp it: whenever the window
        # title is changed to anything but our branded title, set it straight back.
        # notify::title fires after Assistant's write, so this always wins. A reentry
        # guard stops our own set_title from recursing.
        self._title_guard = False
        self.assistant.connect("notify::title", self._clamp_title)
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
        self._page_appearance()
        self._page_display()
        self._page_panels()
        self._page_vault()
        self._page_vpn()
        self._page_review()
        self._page_install()

        # On any non-apply exit, drop the Appearance preview from branding's cache
        # (on_apply mutated it in place) so a same-process re-read isn't poisoned.
        self.assistant.connect("cancel", self._on_quit)
        self.assistant.connect("close", lambda *_: self.Gtk.main_quit())
        self.assistant.connect("escape", self._on_quit)
        self.assistant.connect("destroy", self._on_quit)
        self.assistant.connect("apply", self._on_apply)
        self.assistant.connect("prepare", self._on_prepare)
        # The page appends above stamped page-0's title onto the chrome; restore it.
        self._clamp_title()
        # One collect after the whole page tree is built reclaims the short-lived
        # Python wrappers GTK construction creates, before Gtk.main() idles.
        import gc
        gc.collect()

    # ---- Page 1: presets ------------------------------------------------- #
    def _page_preset(self):
        Gtk = self.Gtk
        page = self._page("Choose a starting point",
                          "Pick a preset to load, then customise it on the next pages.",
                          overline=self._step_overline("preset"))
        text = self.branding.color("text")
        dim = self.branding.color("text_dim")
        surface = self.branding.color("surface_top")
        # The '▸' selection mark is accent TEXT on the card surface — route through
        # accent_on so the brand green (below AA on the tinted surface in the light
        # theme) is swapped for accent_strong only where it wouldn't read.
        accent = self.branding.accent_on(
            surface, accent=self.branding.color("primary"),
            strong=self.branding.color("accent_strong"))
        group = None
        first = True
        for n, (name, disp, desc) in enumerate(discover_presets()):
            btn = Gtk.RadioButton.new_from_widget(group)
            if group is None:
                group = btn
            btn.set_label("")
            for ch in btn.get_children():
                btn.remove(ch)
            # Numbered tile: a low-opacity mono '01/02/03' watermark numeral, a
            # tight bold sans title and a text_dim body description.
            card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            card.get_style_context().add_class("soc-card")
            num = Gtk.Label()
            num.set_valign(Gtk.Align.START)
            num.set_markup(
                f'<span font_family="monospace" size="20000" weight="bold" '
                f'foreground="{_mix(accent, surface, 0.62)}">{n + 1:02d}</span>')
            card.pack_start(num, False, False, 0)
            txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            t = Gtk.Label(xalign=0)
            t.set_markup(f'<span weight="bold" letter_spacing="-300" '
                         f'foreground="{text}" size="12000">{_esc(disp)}</span>')
            d = Gtk.Label(xalign=0, wrap=True)
            d.set_markup(f'<span foreground="{dim}" size="9500">{_esc(desc)}</span>')
            txt.pack_start(t, False, False, 0)
            txt.pack_start(d, False, False, 0)
            card.pack_start(txt, True, True, 0)
            # A mono '▸' selection marker, shown only on the active tile.
            mark = Gtk.Label()
            mark.set_valign(Gtk.Align.CENTER)
            mark.set_markup(f'<span font_family="monospace" size="13000" '
                            f'foreground="{accent}">▸</span>')
            mark.set_no_show_all(True)
            mark.set_visible(btn.get_active())
            card.pack_start(mark, False, False, 0)
            btn.add(card)

            def _toggled(b, nm=name, mk=mark):
                mk.set_visible(b.get_active())
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
                mark.set_visible(True)
                first = False

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.INTRO)
        self.assistant.set_page_title(page, "Preset")
        self.assistant.set_page_complete(page, True)

    # ---- Page 2: appearance (theme) ------------------------------------- #
    def _page_appearance(self):
        """Embed the host.appearance editor as a wizard page (runs at first-run).
        Cosmetic — page-complete is always True so it never blocks the config flow.
        on_apply monkeypatches branding's in-memory palette + repaints the wizard's
        cached theme provider (preview only); Save persists via branding.save_colors
        and repaints from the now-persisted palette."""
        Gtk = self.Gtk
        from host import appearance  # type: ignore  (gi-only path; already imported)
        page = self._page("Appearance (theme)",
                          "Pick a preset or tune the palette. Live preview; Save persists "
                          "it as the theme used everywhere.",
                          overline=self._step_overline("appearance"))

        def on_apply(colors):
            cur = self.branding.load()
            cur.setdefault("colors", {}).update(colors)
            if getattr(self, "_theme_provider", None) is not None:
                self._theme_provider.load_from_data(_css(self.branding))

        def on_saved(_colors):
            self.branding.load(refresh=True)
            if getattr(self, "_theme_provider", None) is not None:
                self._theme_provider.load_from_data(_css(self.branding))

        editor = appearance.AppearanceEditor(
            (self.Gtk, self.Gdk, self.GdkPixbuf), on_apply=on_apply, on_saved=on_saved)
        editor.build_body(page)
        self._appearance_editor = editor   # keep a ref so its providers live

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "Appearance")
        self.assistant.set_page_complete(page, True)

    # ---- Page 3: display ------------------------------------------------- #
    def _page_display(self):
        Gtk = self.Gtk
        page = self._page("Display & grid",
                          "The screen is split into a cols x rows grid; one panel per cell.",
                          overline=self._step_overline("display"))
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
                          "wall, so duplicate ids / grid cells are caught here.",
                          overline=self._step_overline("panels"))
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(260)
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.add(listbox)

        btnbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        add = Gtk.Button.new_with_label("Add panel")
        rem = Gtk.Button.new_with_label("Remove last")
        add.get_style_context().add_class("soc-ghost")
        rem.get_style_context().add_class("soc-ghost")
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
        thead = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        num = Gtk.Label()
        num.set_markup(
            f'<span font_family="monospace" size="13000" weight="bold" '
            f'foreground="{_mix(self.branding.color("primary"), self.branding.color("surface_top"), 0.30)}">'
            f'{idx + 1:02d}</span>')
        title = Gtk.Label(xalign=0)
        title.set_markup(f'<span weight="bold" letter_spacing="-300" foreground="'
                         f'{self.branding.color("text")}">Panel {idx + 1}</span>')
        thead.pack_start(num, False, False, 0)
        thead.pack_start(title, False, False, 0)
        box.pack_start(thead, False, False, 0)

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
                          "is sealed. The master is NEVER written to any file.",
                          overline=self._step_overline("vault"))
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
        # Live-test state — seeded BEFORE the entries below, whose set_text fires
        # _set_email/_set_url during construction (which read these).
        self._vault_tested_ok = False
        self._vault_test_running = False
        self._vault_tested_key = None

        def _set_email(v, ok):
            m.vault_email = v
            self._vault_email_ok = ok
            self._vault_tested_ok = False   # changed identity -> re-test required
            self._recheck_vault(page)

        def _set_url(v, ok):
            m.vault_url = v
            self._vault_url_ok = ok
            self._vault_tested_ok = False   # changed identity -> re-test required
            self._recheck_vault(page)

        email = self._entry(m.vault_email, self.setup.v_email, _set_email)
        url = self._entry(m.vault_url, self.setup.v_url, _set_url)

        # Selectable-source availability is a CAPABILITY probe for the wizard, NOT
        # mastersource.available_sources() (which means "usable RIGHT NOW" and only
        # lists 'sealed' once a seal already exists — wrong for a fresh box). Here
        # 'sealed' is offered whenever cryptography can seal, independent of an
        # existing seal; 'secret-service' needs a real Secret Service backend; 'env'
        # is dev-only. A genuinely-unavailable source shows a one-line reason.
        try:
            _sealed_ok = self.secretstore.available()
        except Exception:  # noqa: BLE001 — never block the wizard on a probe
            _sealed_ok = False
        _ss_ok = "secret-service" in self.mastersource.available_sources()
        src_reason = {
            "auto": "",
            "sealed": "" if _sealed_ok else "  (install 'cryptography')",
            "secret-service": "" if _ss_ok else "  (no secret-tool/libsecret)",
            "env": "  (dev only)",
        }
        source = Gtk.ComboBoxText()
        for s in ("auto", "sealed", "secret-service", "env"):
            source.append_text(s + src_reason.get(s, ""))
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

        # Test connection: prove litebw can reach + log into Vaultwarden BEFORE the
        # wizard seals, so a well-formed-but-WRONG url/email/master can't slip past
        # and leave the wall dying later with the cryptic vault error. The probe runs
        # OFF the GTK main thread (ReadSession does network I/O); the result returns
        # via GLib.idle_add. A passing test is REQUIRED to leave the page (litebw/rbw).
        test_btn = Gtk.Button(label="Test connection")
        # RESET / re-seal the master: prove the (new) master against Vaultwarden,
        # then RE-SEAL it host-bound (replacing any old seal) — so a forgotten or
        # rotated master can be re-set without a reinstall. On a deployed box whose
        # secret dir is root-owned, the re-seal escalates via pkexec (system prompt).
        reset_btn = Gtk.Button(label="Reset / re-seal master")
        reset_btn.get_style_context().add_class("soc-ghost")
        reset_btn.set_tooltip_text(
            "Test the master above against Vaultwarden, then re-seal it host-bound "
            "(replaces the existing sealed master). No plaintext is ever written.")
        # Create the Vaultwarden account when Test reveals it does not exist yet
        # (the fresh-box dead-end: kiosk@soc.local was never registered, so login
        # 400s). Registered off the GTK thread with the entered email + master;
        # the master stays in-memory (never written to a file). Hidden until a
        # Test failure signals the account is absent, so an existing vault can't be
        # accidentally re-registered.
        create_btn = Gtk.Button(label="Create account")
        create_btn.get_style_context().add_class("soc-ghost")
        create_btn.set_tooltip_text(
            "Register this email + master as a new Vaultwarden account, then "
            "re-test. Only offered when Test shows the account does not exist.")
        create_btn.set_no_show_all(True)
        create_btn.hide()
        test_status = Gtk.Label(xalign=0, wrap=True)
        test_status.set_max_width_chars(56)

        # Identity of the last params that passed, so editing any field after a green
        # test re-arms the gate (a stale pass can't authorise a changed config).
        def _vault_key():
            return (m.vault_backend, m.vault_email, m.vault_url, pw.get_text())

        def _set_test(markup):
            test_status.set_markup(markup)

        def _test_done(ok, msg, offer_create=False):
            self._vault_test_running = False
            test_btn.set_sensitive(True)
            self._vault_tested_ok = ok
            self._vault_tested_key = _vault_key() if ok else None
            col = self.branding.color("good" if ok else "bad")
            glyph = "● " if ok else "✗ "
            _set_test(f'<span foreground="{col}">{glyph}{_esc(msg)}</span>')
            # A failed login can mean the account was never created (fresh box) OR
            # a wrong master for an existing account. Test can't tell them apart
            # without mutating, so on ANY login failure we reveal "Create account"
            # — it authoritatively distinguishes (registers -> created, or detects
            # the account already exists with a different master and says so).
            # Create stays reachable on ANY failure for a real backend (litebw/rbw)
            # — never hidden by a transport blip or a successful test, so the
            # operator always has a way forward. It is only hidden for the dev
            # backend (no account to create). The companion seed checkbox rides
            # with it. When cryptography is genuinely missing, on_create surfaces a
            # clear "create it in the web vault" message rather than silently no-op.
            if create_btn is not None and m.vault_backend != "dev":
                create_btn.show()
                seed_chk.show()
            self._recheck_vault(page)
            return False

        def on_test(_b):
            be = m.vault_backend
            if be == "dev":
                return
            master = pw.get_text()
            if not (m.vault_url and m.vault_email and master):
                _set_test(f'<span foreground="{self.branding.color("bad")}">'
                          f'✗ Enter URL, email and master password first.</span>')
                return
            self._vault_test_running = True
            test_btn.set_sensitive(False)
            _set_test(f'<span foreground="{self.branding.color("text_dim")}">'
                      f'… contacting {_esc(m.vault_url)}</span>')
            self._recheck_vault(page)
            url_, email_, be_ = m.vault_url, m.vault_email, be

            def _worker():
                try:
                    from host import litebw  # type: ignore
                    sess = litebw.ReadSession(url_, email_, master)
                    sess.list_ciphers()      # confirm decrypt, not just login
                    self.GLib.idle_add(_test_done, True,
                                       "Connected + logged in — vault reachable.",
                                       False)
                except Exception as e:  # noqa: BLE001 — surface the message verbatim
                    msg = str(e) or e.__class__.__name__
                    # A login failure is the fresh-box dead-end: offer to create
                    # the account. Pure transport failures (host unreachable) are
                    # NOT account problems — don't offer create for those.
                    offer = not self._vault_unreachable(msg)
                    if offer:
                        msg = (msg + "  — if this account was never created, "
                               "use “Create account”.")
                    self.GLib.idle_add(_test_done, False, msg, offer)

            import threading
            threading.Thread(target=_worker, daemon=True).start()

        test_btn.connect("clicked", on_test)

        def _reset_done(ok, payload):
            self._vault_test_running = False
            dev = m.vault_backend == "dev"
            test_btn.set_sensitive(not dev)
            reset_btn.set_sensitive(not dev)
            if ok:
                # A fresh seal means the master tested good too: arm the page gate so
                # Next works, keyed to the params that were proven + sealed.
                self._vault_tested_ok = True
                self._vault_tested_key = _vault_key()
                col = self.branding.color("good")
                _set_test(f'<span foreground="{col}">● Master re-sealed (host-bound). '
                          f'ONE-TIME PIN: {_esc(payload)}</span>')
            else:
                self._vault_tested_ok = False
                col = self.branding.color("bad")
                _set_test(f'<span foreground="{col}">✗ {_esc(payload)}</span>')
                # Reset rejection used to be a dead-end: no Create button. A
                # rejected master can mean the account was never created OR the
                # wrong master for an existing one — reveal Create (litebw/rbw) so
                # the operator can register it / it reports the account exists.
                if create_btn is not None and not dev:
                    create_btn.show()
                    seed_chk.show()
            self._recheck_vault(page)
            return False

        def on_reset(_b):
            be = m.vault_backend
            if be == "dev":
                _set_test(f'<span foreground="{self.branding.color("bad")}">'
                          f'✗ Reset needs a real vault backend (litebw/rbw).</span>')
                return
            master = pw.get_text()
            if not (m.vault_url and m.vault_email and master):
                _set_test(f'<span foreground="{self.branding.color("bad")}">'
                          f'✗ Enter URL, email and the NEW master first.</span>')
                return
            # Where the re-seal must land — the SAME dir the wall unseals from.
            sd = self.model.paths.get("secret_dir")
            if not sd:
                from host import configpaths  # type: ignore
                sd = configpaths.resolve_secret_dir()
            self._vault_test_running = True
            test_btn.set_sensitive(False)
            reset_btn.set_sensitive(False)
            _set_test(f'<span foreground="{self.branding.color("text_dim")}">'
                      f'… testing the new master, then re-sealing</span>')
            self._recheck_vault(page)
            url_, email_, master_, pin_ = m.vault_url, m.vault_email, master, m.master_pin

            def _worker():
                try:
                    from host import litebw  # type: ignore
                    litebw.ReadSession(url_, email_, master_).list_ciphers()
                except Exception as e:  # noqa: BLE001 — surface the vault's reason
                    msg = str(e) or e.__class__.__name__
                    if not self._vault_unreachable(msg):
                        msg += ("  — use “Create account” if this account was "
                                "never created, or enter the correct master if "
                                "it already exists.")
                    self.GLib.idle_add(_reset_done, False,
                                       f"vault rejected the master: {msg}")
                    return
                try:
                    used = self._seal_host_bound(master_, pin_, sd)
                except Exception as e:  # noqa: BLE001 — seal/escalation failure
                    self.GLib.idle_add(_reset_done, False, f"re-seal failed: {e}")
                    return
                self.GLib.idle_add(_reset_done, True, used)

            import threading
            threading.Thread(target=_worker, daemon=True).start()

        reset_btn.connect("clicked", on_reset)

        # Offer to seed the configured panels' login items right after creating the
        # account (so the wall has logins to read). Opt-in via this checkbox.
        seed_chk = Gtk.CheckButton(
            label="Seed the configured panels' login items after creating")
        seed_chk.set_active(False)
        seed_chk.set_no_show_all(True)
        seed_chk.hide()

        def _create_done(ok, payload):
            self._vault_test_running = False
            dev = m.vault_backend == "dev"
            test_btn.set_sensitive(not dev)
            reset_btn.set_sensitive(not dev)
            create_btn.set_sensitive(True)
            if ok:
                create_btn.hide()
                seed_chk.hide()
                col = self.branding.color("good")
                _set_test(f'<span foreground="{col}">● {_esc(payload)} '
                          f'Re-testing…</span>')
                self._recheck_vault(page)
                # Re-run Test so the green gate (and seal) become reachable.
                on_test(None)
            else:
                col = self.branding.color("bad")
                _set_test(f'<span foreground="{col}">✗ {_esc(payload)}</span>')
                self._recheck_vault(page)
            return False

        def _seed_panels(url_, email_, master_):
            """Best-effort: write each configured panel's login item. Never fatal —
            a seed failure is reported but the account still exists + tests green."""
            try:
                from host import vaultseed  # type: ignore
            except Exception:  # noqa: BLE001
                return "(seed skipped — vault writer unavailable)"
            if not vaultseed.available():
                return "(seed skipped — 'cryptography' missing)"
            items = []
            for p in self.model.cfg().get("panels", []):
                if p.get("vault_item"):
                    items.append((p["vault_item"], p.get("url", "")))
            if not items:
                return ""
            seeded = 0
            for name, uri in items:
                try:
                    # Empty user/pass placeholder logins the operator fills in the
                    # web vault — names match vault_item so the wall finds them.
                    vaultseed.upsert_login(url_, email_, master_, name, "", "",
                                           uri=uri or None)
                    seeded += 1
                except Exception:  # noqa: BLE001 — seeding is best-effort
                    pass
            return f"seeded {seeded}/{len(items)} panel item(s);" if items else ""

        def on_create(_b):
            be = m.vault_backend
            if be == "dev":
                return
            master = pw.get_text()
            if not (m.vault_url and m.vault_email and master):
                _set_test(f'<span foreground="{self.branding.color("bad")}">'
                          f'✗ Enter URL, email and master password first.</span>')
                return
            if self.vaultsetup is None or not self.vaultsetup.available():
                _set_test(f'<span foreground="{self.branding.color("bad")}">'
                          f'✗ Cannot create the account here ('
                          f'\'cryptography\' missing) — create it in the '
                          f'Vaultwarden web vault.</span>')
                return
            self._vault_test_running = True
            test_btn.set_sensitive(False)
            reset_btn.set_sensitive(False)
            create_btn.set_sensitive(False)
            _set_test(f'<span foreground="{self.branding.color("text_dim")}">'
                      f'… registering {_esc(m.vault_email)} at '
                      f'{_esc(m.vault_url)}</span>')
            self._recheck_vault(page)
            url_, email_, master_ = m.vault_url, m.vault_email, master
            do_seed = seed_chk.get_active()

            def _worker():
                vs = self.vaultsetup
                try:
                    result = vs.ensure_account(url_, email_, master_)
                except vs.WrongMasterError as e:
                    # Account EXISTS with a different master — never re-register.
                    self.GLib.idle_add(_create_done, False, str(e))
                    return
                except vs.SignupsDisabledError as e:
                    self.GLib.idle_add(_create_done, False, str(e))
                    return
                except Exception as e:  # noqa: BLE001 — surface the reason
                    msg = str(e) or e.__class__.__name__
                    self.GLib.idle_add(_create_done, False,
                                       f"could not create the account: {msg}")
                    return
                verb = ("Account created." if result == "created"
                        else "Account already existed (master verified).")
                extra = ""
                if do_seed and result == "created":
                    extra = " " + _seed_panels(url_, email_, master_)
                self.GLib.idle_add(_create_done, True, verb + extra)

            import threading
            threading.Thread(target=_worker, daemon=True).start()

        create_btn.connect("clicked", on_create)

        def on_backend(*_):
            be = backend.get_active_text() or "dev"
            m.vault_backend = be
            dev = be == "dev"
            for w in (email, url, pw, pin, source, test_btn, reset_btn,
                      create_btn):
                w.set_sensitive(not dev)
            # Create is ALWAYS present for a real backend (litebw/rbw) — so the
            # fresh-box "account never registered" path is reachable without first
            # having to click Test and get a rejection. Hidden only for dev (no
            # account to create). seed_chk rides with it.
            if dev:
                create_btn.hide()
                seed_chk.hide()
            else:
                create_btn.show()
                seed_chk.show()
            # A backend change invalidates any prior green test.
            self._vault_tested_ok = False
            self._vault_tested_key = None
            self._recheck_vault(page)

        def on_source(*_):
            txt = (source.get_active_text() or "auto").split("  ")[0]
            m.master_source = txt
            pin.set_sensitive(txt in ("auto", "sealed"))

        def on_pw(e):
            m.master_password = e.get_text()
            # Editing the master after a green test re-arms the gate.
            if self._vault_tested_key != _vault_key():
                self._vault_tested_ok = False
            self._recheck_vault(page)

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
        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_row.pack_start(test_btn, False, False, 0)
        btn_row.pack_start(reset_btn, False, False, 0)
        btn_row.pack_start(create_btn, False, False, 0)
        page.pack_start(self._row("", btn_row), False, False, 0)
        page.pack_start(test_status, False, False, 0)
        page.pack_start(self._row("", seed_chk), False, False, 0)
        page.pack_start(hint, False, False, 0)

        on_backend()
        on_source()

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "Vault")
        self._recheck_vault(page)

    @staticmethod
    def _vault_unreachable(msg: str) -> bool:
        """True if a Test failure looks like a transport problem (server down /
        DNS / refused) rather than an auth problem. We only offer 'Create account'
        for auth-shaped failures — a server we can't reach can't be registered
        against, and showing Create there would mislead."""
        low = (msg or "").lower()
        return any(s in low for s in (
            "could not reach", "connection refused", "name or service",
            "timed out", "no route to host", "ssl", "certificate"))

    def _recheck_vault(self, page):
        """Vault page is complete when the backend is 'dev' (email/URL ignored),
        or — for litebw/rbw — BOTH the account email and the Vaultwarden URL pass
        their setup.v_* validators AND the live 'Test connection' has SUCCEEDED for
        the current params (so a well-formed-but-wrong vault can't be sealed). A
        running test holds the page incomplete so Next can't race the probe."""
        m = self.model
        if m.vault_backend == "dev":
            ok = True
        elif getattr(self, "_vault_test_running", False):
            ok = False
        else:
            ok = (self._vault_email_ok and self._vault_url_ok
                  and getattr(self, "_vault_tested_ok", False)
                  and self._vault_tested_key == (m.vault_backend, m.vault_email,
                                                 m.vault_url, m.master_password))
        if self._page_appended(page):
            self.assistant.set_page_complete(page, ok)
        return ok

    # ---- Page 5: VPNs (a LIST, mirroring the Panels page) --------------- #
    def _page_vpn(self):
        Gtk = self.Gtk
        page = self._page("VPNs (optional)",
                          "Each row is one independent supervised tunnel. Multiple VPNs "
                          "split-tunnel by default — each owns only its own routes; mark "
                          "exactly one as the default-route owner for catch-all traffic.",
                          overline=self._step_overline("vpn"))

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(300)
        listbox = Gtk.ListBox()
        listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        scroller.add(listbox)

        btnbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        add = Gtk.Button.new_with_label("Add VPN")
        rem = Gtk.Button.new_with_label("Remove last")
        add.get_style_context().add_class("soc-ghost")
        rem.get_style_context().add_class("soc-ghost")
        btnbar.pack_start(add, False, False, 0)
        btnbar.pack_start(rem, False, False, 0)

        self._vpn_page = page
        self._vpn_listbox = listbox

        def cap():
            return MAX_VPNS

        def rebuild():
            for child in listbox.get_children():
                listbox.remove(child)
            for i, v in enumerate(self.model.cfg()["vpns"]):
                listbox.add(self._vpn_row(i, v, page))
            listbox.show_all()
            self._revalidate_page(page)

        def on_add(_b):
            vpns = self.model.cfg()["vpns"]
            if len(vpns) >= cap():
                self._set_status(f"at most {cap()} VPNs", bad=True)
                return
            vpns.append(_def_vpn(len(vpns)))
            self.model.set_cfg(self.model.cfg())   # renormalise (refills names/back-compat vpn)
            rebuild()

        def on_rem(_b):
            vpns = self.model.cfg()["vpns"]
            if vpns:
                vpns.pop()
                self.model.set_cfg(self.model.cfg())
                rebuild()
        add.connect("clicked", on_add)
        rem.connect("clicked", on_rem)

        page.pack_start(btnbar, False, False, 0)
        page.pack_start(scroller, True, True, 0)
        self._rebuild_vpns = rebuild
        rebuild()

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "VPNs")
        self._revalidate_page(page)

    _VPN_TYPES = ("fortinet", "openvpn", "wireguard", "inode")

    def _vpn_row(self, idx, v, page):
        """One VPN row: name + enable + type combo + default_route + type-specific
        fields, all writing into `v` in place. Mirrors _panel_row's structure."""
        Gtk = self.Gtk
        row = Gtk.ListBoxRow()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.get_style_context().add_class("soc-card")
        box.set_border_width(6)

        thead = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        num = Gtk.Label()
        num.set_markup(
            f'<span font_family="monospace" size="13000" weight="bold" '
            f'foreground="{_mix(self.branding.color("primary"), self.branding.color("surface_top"), 0.30)}">'
            f'{idx + 1:02d}</span>')
        title = Gtk.Label(xalign=0)
        title.set_markup(f'<span weight="bold" letter_spacing="-300" foreground="'
                         f'{self.branding.color("text")}">VPN {idx + 1}</span>')
        thead.pack_start(num, False, False, 0)
        thead.pack_start(title, False, False, 0)
        box.pack_start(thead, False, False, 0)

        grid = Gtk.Grid()
        grid.set_column_spacing(8)
        grid.set_row_spacing(4)
        r = 0

        def add_field(label, widget):
            """Attach a labelled widget; return (label, widget) so a per-type field
            can toggle BOTH visible/hidden together."""
            nonlocal r
            # Branding-driven foreground (mirror _row): without an explicit colour
            # these labels inherit GTK's default text colour and render
            # light-on-light on the tinted .soc-card surface.
            lbl = Gtk.Label(xalign=0)
            lbl.set_markup(f'<span foreground="{self.branding.color("text")}">'
                           f'{_esc(label)}</span>')
            lbl.set_size_request(150, -1)
            grid.attach(lbl, 0, r, 1, 1)
            grid.attach(widget, 1, r, 1, 1)
            r += 1
            return (lbl, widget)

        def on_change(*_):
            self._revalidate_page(page)

        # name — unique identity key; live charset/uniqueness validation
        name = Gtk.Entry()
        name.set_text(str(v.get("name", "")))
        name.set_hexpand(True)

        def _name(e):
            v["name"] = e.get_text()
            ctx = e.get_style_context()
            ctx.remove_class("soc-field-bad")
            ctx.remove_class("soc-field-good")
            nm = e.get_text().strip()
            others = [str(x.get("name", "")).strip().lower()
                      for j, x in enumerate(self.model.cfg()["vpns"]) if j != idx]
            if not _VPN_NAME_RE.match(nm):
                ctx.add_class("soc-field-bad")
                e.set_tooltip_text("start alphanumeric; letters/digits/._- only (no spaces)")
            elif nm.lower() in others:
                ctx.add_class("soc-field-bad")
                e.set_tooltip_text("name must be unique across VPNs")
            else:
                ctx.add_class("soc-field-good")
                e.set_tooltip_text(None)
            on_change()
        name.connect("changed", _name)
        add_field("name", name)

        enable = Gtk.Switch()
        enable.set_active(bool(v.get("enabled")))
        enable.set_halign(Gtk.Align.START)

        type_combo = Gtk.ComboBoxText()
        for t in self._VPN_TYPES:
            type_combo.append_text(t)
        try:
            type_combo.set_active(self._VPN_TYPES.index(v.get("type", "fortinet")))
        except ValueError:
            type_combo.set_active(0)

        droute = Gtk.CheckButton.new_with_label("default-route owner (full-tunnel 0.0.0.0/0)")
        droute.set_active(bool(v.get("default_route")))

        # type-specific field widgets — built once, shown/hidden by type
        gateway = self._entry(v.get("gateway", ""), self.setup.v_host,
                              lambda val, ok: (_set(v, "gateway", val), on_change()))
        port = Gtk.SpinButton.new_with_range(1, 65535, 1)
        port.set_value(int(v.get("port", 443) or 443))
        vault = Gtk.Entry()
        vault.set_text(str(v.get("vault_item", "")))
        vault.set_hexpand(True)
        cert = self._entry(v.get("trusted_cert", ""), self.setup.v_sha256,
                           lambda val, ok: (_set(v, "trusted_cert", val), on_change()))
        config_path = Gtk.Entry()
        config_path.set_text(str(v.get("config", "")))
        config_path.set_hexpand(True)

        def _collect_type():
            """Write the type-specific keys into `v` for its CURRENT type, dropping
            keys foreign to the chosen type so the rendered YAML stays clean."""
            t = type_combo.get_active_text() or "fortinet"
            v["enabled"] = bool(enable.get_active())
            v["type"] = t
            v["default_route"] = bool(droute.get_active())
            # strip cross-type leftovers, keep name/enabled/type/default_route
            for k in ("gateway", "port", "vault_item", "trusted_cert", "realm",
                      "set_routes", "set_dns", "half_internet_routes", "persistent",
                      "otp_from_vault", "insecure", "config", "ready_probe",
                      "health_check_interval", "health_check_failures", "extra_args"):
                v.pop(k, None)
            if t == "fortinet":
                v["gateway"] = gateway.get_text()
                v["port"] = int(port.get_value())
                v["vault_item"] = vault.get_text()
                v["trusted_cert"] = cert.get_text()
                v["realm"] = ""
                v["set_routes"] = True
                v["set_dns"] = False
                v["half_internet_routes"] = False
                v["persistent"] = 0
                v["otp_from_vault"] = False
            elif t == "inode":
                v["gateway"] = gateway.get_text()
                v["port"] = int(port.get_value())
                v["vault_item"] = vault.get_text()
                v["trusted_cert"] = cert.get_text()
                v["insecure"] = False
            else:  # openvpn / wireguard
                v["config"] = config_path.get_text()
                if t == "openvpn":
                    v["vault_item"] = vault.get_text()
                    v["set_routes"] = True

        # rows for each field (built, then visibility toggled per type)
        add_field("enable", enable)
        add_field("type", type_combo)
        add_field("routing", droute)
        gw_row = add_field("gateway host", gateway)
        port_row = add_field("gateway port", port)
        vault_row = add_field("vault item", vault)
        cert_row = add_field("trusted cert (sha256)", cert)
        cfg_row = add_field("config path (ovpn/wg)", config_path)

        def _apply_visibility():
            t = type_combo.get_active_text() or "fortinet"
            host_type = t in ("fortinet", "inode")
            file_type = t in ("openvpn", "wireguard")
            on = bool(enable.get_active())
            for pair, vis in (
                (gw_row, on and host_type),
                (port_row, on and host_type),
                (cert_row, on and host_type),
                (cfg_row, on and file_type),
                # vault: fortinet/inode always; openvpn optional; wireguard never
                (vault_row, on and t in ("fortinet", "inode", "openvpn")),
            ):
                for x in pair:
                    x.set_visible(vis)
                    x.set_no_show_all(not vis)
            type_combo.set_sensitive(on)
            droute.set_sensitive(on)

        def changed(*_):
            _collect_type()
            _apply_visibility()
            on_change()

        enable.connect("notify::active", changed)
        type_combo.connect("changed", changed)

        def _droute_toggled(btn):
            # at-most-one default_route: ticking this one unticks every other row.
            v["default_route"] = bool(btn.get_active())
            if btn.get_active():
                for j, x in enumerate(self.model.cfg()["vpns"]):
                    if j != idx:
                        x["default_route"] = False
                # repaint the other rows so the unticked state is visible
                if getattr(self, "_rebuild_vpns", None):
                    self.GLib.idle_add(self._rebuild_vpns)
            on_change()
        droute.connect("toggled", _droute_toggled)
        for w in (vault, config_path):
            w.connect("changed", lambda *_: changed())
        port.connect("value-changed", changed)

        box.pack_start(grid, False, False, 0)
        row.add(box)
        # seed v from current widgets + set initial visibility after show_all
        _collect_type()
        self.GLib.idle_add(_apply_visibility) if hasattr(self, "GLib") else _apply_visibility()
        return row

    # ---- Page 6: review + write ----------------------------------------- #
    def _page_review(self):
        Gtk = self.Gtk
        page = self._page("Review & write",
                          "Confirm the summary, then Apply to write the files and seal the master.",
                          overline=self._step_overline("review"))
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

    # ---- Page 7: full install (the GUI analogue of `setup.py provision`) -- #
    def _page_install(self):
        """OPTIONAL final page: run the COMPLETE provisioner (packages + users +
        deploy + units + vault account/seed + seal) from the wizard.

        This is purely ADDITIVE — the config-only Finish (Review -> Apply) still
        reconfigures/redeploys WITHOUT a full install. The page is CONTENT with its
        OWN in-page buttons (no Assistant 'apply' collision): a dry-run plan PREVIEW
        gates an explicit 'Install on this system', which runs provision_all OFF the
        GTK main thread and marshals per-step progress back via GLib.idle_add."""
        Gtk = self.Gtk
        page = self._page(
            "Install on this system (optional)",
            "Provision the whole box: create users, install packages, deploy files "
            "+ units, register the vault account and seal the master. Preview the "
            "plan first; nothing changes until you confirm.",
            overline=self._step_overline("install"))

        if self.provision is None:
            lbl = Gtk.Label(xalign=0, wrap=True)
            lbl.set_markup(
                f'<span foreground="{self.branding.color("bad")}">'
                f'Provisioning core (provision.py) unavailable — run the full install '
                f'from the CLI: <tt>setup.py provision</tt></span>')
            page.pack_start(lbl, False, False, 0)
            self.assistant.append_page(page)
            self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
            self.assistant.set_page_title(page, "Install")
            self.assistant.set_page_complete(page, True)
            self._install_page = page
            return

        # mode chooser (kiosk takes over tty1 / desktop runs in a DE session)
        mode_combo = Gtk.ComboBoxText()
        for m in ("kiosk", "desktop"):
            mode_combo.append(m, m)
        mode_combo.set_active_id(self.model.install_mode)

        def _on_mode(c):
            self.model.install_mode = c.get_active_id() or "kiosk"
        mode_combo.connect("changed", _on_mode)
        page.pack_start(self._row("Install mode", mode_combo), False, False, 0)

        # dry-run toggle (default CHECKED == safe preview, mutates nothing)
        dry_chk = Gtk.CheckButton.new_with_label(
            "Dry-run (preview only — no changes to this system)")
        dry_chk.set_active(True)
        self._install_dry = True

        def _on_dry(b):
            self._install_dry = bool(b.get_active())
        dry_chk.connect("toggled", _on_dry)
        page.pack_start(dry_chk, False, False, 0)

        # action buttons
        btnbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        preview_btn = Gtk.Button.new_with_label("Preview plan")
        preview_btn.get_style_context().add_class("soc-ghost")
        run_btn = Gtk.Button.new_with_label("Install on this system")
        run_btn.get_style_context().add_class("soc-primary")
        run_btn.set_sensitive(False)   # forced: preview the plan at least once first
        preview_btn.connect("clicked", self._on_install_preview)
        run_btn.connect("clicked", self._on_install_run)
        btnbar.pack_start(preview_btn, False, False, 0)
        btnbar.pack_start(run_btn, False, False, 0)
        page.pack_start(btnbar, False, False, 0)
        self._install_run_btn = run_btn
        self._install_preview_btn = preview_btn
        self._install_dry_chk = dry_chk
        self._install_mode_combo = mode_combo

        # per-step progress view (monospace, scrollable)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_min_content_height(240)
        view = Gtk.TextView()
        view.set_editable(False)
        view.set_monospace(True)
        view.get_style_context().add_class("soc-mono")
        self._install_buf = view.get_buffer()
        scroller.add(view)
        page.pack_start(scroller, True, True, 0)

        self._install_status = Gtk.Label(xalign=0, wrap=True)
        page.pack_start(self._install_status, False, False, 0)

        self.assistant.append_page(page)
        self.assistant.set_page_type(page, Gtk.AssistantPageType.CONTENT)
        self.assistant.set_page_title(page, "Install")
        self.assistant.set_page_complete(page, True)
        self._install_page = page

    # ---- install helpers ------------------------------------------------- #
    def _install_say(self, text):
        """Append one line to the progress TextView (MAIN thread only). A
        Gtk.TextBuffer has no Pango markup, so colour is conveyed by the status word
        / [CHANGE] mark in the text itself (matches the other mono progress views)."""
        buf = self._install_buf
        if buf is None:
            return
        buf.insert(buf.get_end_iter(), text + "\n")

    def _install_set_status(self, text, *, bad=False):
        lbl = self._install_status
        if lbl is None:
            return
        col = (self.branding.color("bad") if bad else self.branding.color("good"))
        glyph = "✗ " if bad else "● "
        lbl.set_markup(
            f'<span font_family="monospace" foreground="{col}">{glyph}</span>'
            f'<span foreground="{col if bad else self.branding.color("text_dim")}">'
            f'{_esc(text)}</span>')

    def _build_opts(self):
        """Build provision.Opts EXACTLY like the CLI's _opts_from_args. The master
        is NEVER an Opts field (it goes only to the in-process vault/seal steps)."""
        m = self.model
        P = self.provision
        return P.Opts(
            mode=m.install_mode,
            email=m.vault_email,
            url=m.vault_url,
            pin=m.master_pin or "",
            seed=bool(m.push_config) or True,
            target=self.setup._default_target(self.setup.Env()),
            fresh=False,
            dry_run=self._install_dry,
        )

    def _install_dry_env(self):
        """Deterministically set/clear the process-global SOC_PROVISION_DRY_RUN so
        Opts.dry AND child pkexec/provision.py processes agree. CRITICAL: cleared
        before a real run so a later real run can't silently no-op."""
        if self._install_dry:
            os.environ["SOC_PROVISION_DRY_RUN"] = "1"
        else:
            os.environ.pop("SOC_PROVISION_DRY_RUN", None)

    def _on_install_preview(self, _btn):
        """DRY-RUN preview: iterate provision.plan(opts).actions and render one
        themed line per PlanAction. Enables the Install button once shown."""
        if self.provision is None or self._install_busy:
            return
        self._install_dry_env()
        try:
            plan = self.provision.plan(self._build_opts())
        except Exception as e:  # noqa: BLE001
            self._install_set_status(f"could not compute the plan: {e}", bad=True)
            return
        if self._install_buf is not None:
            self._install_buf.set_text("")
        changes = 0
        self._install_say(f"// provisioning plan (mode={self.model.install_mode}, "
                          f"dry-run={'yes' if self._install_dry else 'NO'})")
        for a in plan.actions:
            mark = "[CHANGE]" if a.needed else "[ok]    "
            if a.needed:
                changes += 1
            line = f"  {mark} {a.step}: {a.desc}"
            if a.needed and a.cmd:
                line += "\n             $ " + " ".join(str(x) for x in a.cmd)
            self._install_say(line)
        if changes == 0:
            self._install_say("  (nothing to do — already provisioned)")
        else:
            self._install_say(f"  {changes} action(s) would change host state.")
        if self._install_run_btn is not None:
            self._install_run_btn.set_sensitive(True)
        self._install_set_status(
            "plan ready — review it, then click Install on this system"
            + ("  (dry-run: nothing will change)" if self._install_dry else ""))

    def _on_install_run(self, _btn):
        """Run the provisioner OFF the GTK main thread; marshal per-step progress
        back via GLib.idle_add. Root shell steps escalate via pkexec (master NEVER
        on argv); vault account/seed/seal run in-process with the master in memory."""
        if self.provision is None or self._install_busy:
            return
        self._install_busy = True
        self._install_dry_env()
        dry = self._install_dry

        # On a REAL run, lock the controls so a daemon-thread kill can't leave a
        # half-provisioned box mid-flight.
        if not dry:
            for w in (self._install_run_btn, self._install_preview_btn,
                      self._install_dry_chk, self._install_mode_combo):
                if w is not None:
                    w.set_sensitive(False)
            self.assistant.set_page_complete(self._install_page, False)

        if self._install_buf is not None:
            self._install_buf.set_text("")
        self._install_set_status(
            ("dry-run: simulating — no changes" if dry else "installing…"))

        opts = self._build_opts()
        # Capture the model's config ONCE, AFTER the wizard pages have populated it,
        # and HOLD that snapshot for the whole worker run so write_config can never
        # see a transiently-empty cfg (the "no wizard config yet" artifact).
        cfg = self.model.cfg()
        soc_env = self.model.soc_env()
        paths = self.model.paths
        backend = soc_env.get("SOC_VAULT_BACKEND") or paths.get("default_backend", "litebw")

        # Guard: never launch the worker with nothing to install. Surface a
        # guiding status instead of a silent "no wizard config yet" line buried in
        # the per-step log — the operator must configure display + panels first.
        if not (cfg.get("display") and cfg.get("panels")):
            self._install_busy = False
            for w in (self._install_run_btn, self._install_preview_btn,
                      self._install_dry_chk, self._install_mode_combo):
                if w is not None:
                    w.set_sensitive(True)
            self._install_set_status(
                "configure the display + panels first (run the wizard pages), "
                "then install", bad=True)
            return

        # No-plaintext-master guarantee on this path (mirror _write :2028).
        env_text = self.setup.render_soc_env(soc_env)
        assert "SOC_VAULT_PASSWORD" not in env_text

        # Capture the master into a mutable holder (so the worker can scrub the
        # reference in its finally); scrub the model copy below before the thread runs.
        master_box = [self.model.master_password]

        def report(step, status, detail=""):
            # Runs on the WORKER thread — only ever SCHEDULE a main-thread update.
            self.GLib.idle_add(self._provision_report, step, status, detail)

        def _worker():
            P = self.provision
            ok = True
            try:
                # 1) Privileged shell steps (packages/users/deploy/units).
                #    In DRY-RUN they mutate nothing and only PRINT — so run them
                #    in-process (no pkexec prompt for a preview). On a REAL run they
                #    need root: escalate via pkexec (provision.py --provision; NO
                #    secret on argv — that entrypoint has no master flag).
                if opts.dry:
                    for nm, fn in (("packages", P.step_packages),
                                   ("users", P.step_users),
                                   ("deploy", P.step_deploy),
                                   ("units", P.step_units)):
                        report(nm, "running")
                        r = fn(opts)
                        report(nm, "ok" if r.ok else "FAILED", r.detail)
                        ok = ok and r.ok
                else:
                    report("escalate", "running",
                           "requesting system password (pkexec)")
                    rc, errtxt = self._provision_shell_via_pkexec(opts)
                    if rc != 0:
                        report("escalate", "FAILED",
                               errtxt or f"pkexec returned {rc}")
                        ok = False
                    else:
                        report("escalate", "ok",
                               "packages/users/deploy/units complete")

                # 2) Unprivileged in-process vault/seal steps (master in memory only).
                #    Do NOT call the top-level provision_all here — its shell steps
                #    would PermissionError unprivileged; we ran them via pkexec above.
                if ok:
                    r = P.step_write_config(opts, cfg, soc_env, paths)
                    report("write_config", "ok" if r.ok else "FAILED", r.detail)
                    # vault_running probe (soft — a down vault is a warning, not fatal)
                    rv = P.step_vault_running(opts)
                    report("vault_running", "ok" if rv.ok else "skipped", rv.detail)
                    master_ = master_box[0]
                    # In DRY-RUN the vault/seal steps mutate nothing and touch no
                    # network — show them in the preview even without a master entered
                    # (a non-empty placeholder that NEVER leaves the dry-run branch).
                    if not master_ and opts.dry:
                        master_ = "(dry-run-placeholder)"
                    if master_:
                        r = P.step_vault_account(opts, master_)
                        report("vault_account", "ok" if r.ok else "FAILED", r.detail)
                        if r.ok or opts.dry:
                            r = P.step_vault_seed(opts, master_, cfg)
                            report("vault_seed", "ok" if r.ok else "FAILED", r.detail)
                            r = P.step_seal(opts, master_, paths, soc_env, backend)
                            # step_seal's detail carries the one-time PIN — surface it.
                            report("seal", "ok" if r.ok else "FAILED", r.detail)
                            if not r.ok and not opts.dry:
                                ok = False
                        elif not opts.dry:
                            ok = False
                    else:
                        report("vault_account", "skipped",
                               "no master entered — seal/account skipped")
            except Exception as e:  # noqa: BLE001
                report("install", "FAILED", str(e) or e.__class__.__name__)
                ok = False
            finally:
                # Scrub the master holder (mirror _write :2104-2105). The model copy
                # was already scrubbed below before the thread started.
                master_box[0] = ""
                self.GLib.idle_add(self._install_finish, ok, opts.dry)

        # Scrub the model's long-lived copy now that the worker holds its own.
        self.model.master_password = ""
        import threading
        threading.Thread(target=_worker, daemon=True).start()

    def _provision_shell_via_pkexec(self, opts):
        """Run the privileged shell steps (packages/users/deploy/units) via the
        existing provision.py --provision entrypoint under pkexec. NO secret on argv
        (that entrypoint has no master flag). By ABSOLUTE PATH (pkexec strips
        PYTHONPATH). Returns (returncode, stderr). Worker-thread safe (no widgets)."""
        if not shutil.which("pkexec"):
            return (127, "pkexec is unavailable — cannot escalate the install")
        helper = os.path.join(_repo_root(), "provision.py")
        py = shutil.which("python3") or sys.executable
        argv = ["pkexec", py, helper, "--provision",
                "--mode", opts.mode,
                "--kiosk-user", opts.kiosk_user,
                "--desktop-user", opts.desktop_user,
                "--svc-user", opts.svc_user]
        if opts.dry:
            argv.append("--dry-run")
        if opts.fresh:
            argv.append("--fresh")
        try:
            p = subprocess.run(argv, text=True, capture_output=True, timeout=600)
        except Exception as e:  # noqa: BLE001 — treat any spawn fault as declined/failed
            return (126, f"pkexec escalation failed: {e}")
        return (p.returncode, (p.stderr or "").strip())

    def _provision_report(self, step, status, detail=""):
        """MAIN-thread: append a plain 'step: status — detail' line to the progress
        view. A Gtk.TextBuffer has no Pango markup, so the status word itself
        ('ok'/'FAILED'/'skipped') carries the meaning — matching the other mono
        progress views. (Never receives the master — only the report() details the
        steps emit; step_seal's detail carries the one-time PIN.)"""
        if self._install_buf is not None:
            end = self._install_buf.get_end_iter()
            self._install_buf.insert(
                end, f"{step}: {status}{(' — ' + detail) if detail else ''}\n")
        return False

    def _install_finish(self, ok, dry):
        """MAIN-thread completion: on a successful REAL run, RETURN TO THE START
        MENU (clean Gtk.main_quit -> the launcher wrapper relaunches the menu)."""
        self._install_busy = False
        # Re-arm controls (so a failed/dry run can be retried).
        for w in (self._install_run_btn, self._install_preview_btn,
                  self._install_dry_chk, self._install_mode_combo):
            if w is not None:
                w.set_sensitive(True)
        if self._install_page is not None:
            self.assistant.set_page_complete(self._install_page, True)
        if ok and dry:
            self._install_set_status(
                "dry-run complete — no host state changed. Uncheck Dry-run to install.")
        elif ok:
            self._install_set_status("Installed — returning to menu…")
            # Drop the Appearance preview poison (mirror _on_quit) then quit cleanly;
            # the setup-gui wrapper (SOC_RETURN_TO_MENU=1) relaunches the start menu.
            try:
                self.branding.load(refresh=True)
            except Exception:  # noqa: BLE001
                pass
            self.GLib.timeout_add(900, lambda: (self.Gtk.main_quit(), False)[1])
        else:
            self._install_set_status("install FAILED — see the log above", bad=True)
        return False

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

    def _clamp_title(self, assistant=None, _pspec=None):
        """notify::title handler — keep the window/headerbar showing the branded
        '<name> — Setup', overriding the per-page title Gtk.Assistant tries to set.
        Guarded so our own set_title() doesn't recurse."""
        bt = getattr(self, "_brand_title", None)
        if not bt or getattr(self, "_title_guard", False):
            return
        hb = getattr(self, "_headerbar", None)
        if hb is not None and hb.get_title() != bt:
            try:
                hb.set_title(bt)
            except Exception:
                pass
        if self.assistant.get_title() != bt:
            self._title_guard = True
            try:
                self.assistant.set_title(bt)
            finally:
                self._title_guard = False

    def _on_prepare(self, assistant, page):
        self._clamp_title()
        if page is getattr(self, "_review_page", None):
            self._update_review()
        if page is getattr(self, "_panels_page", None) and hasattr(self, "_rebuild_panels"):
            self._rebuild_panels()

    def _update_review(self):
        cfg = self.model.cfg()
        lines = []
        en_vpns = [v for v in cfg.get("vpns", []) if v.get("enabled")]
        lines.append(f"{len(cfg['panels'])} panel(s); "
                     f"tunnel {'ON' if cfg['tunnel'].get('enabled') else 'off'}; "
                     f"VPN {len(en_vpns)} enabled; "
                     f"proxy {'ON' if cfg.get('proxy', {}).get('enabled') else 'off'}")
        for v in en_vpns:
            owner = "  [default-route]" if v.get("default_route") else ""
            lines.append(f"  - vpn {v.get('name', '?')} [{v.get('type', 'fortinet')}]{owner}")
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
            col = (self.branding.color("bad") if bad
                   else self.branding.color("good"))
            glyph = "✗ " if bad else "● "
            self._status_label.set_markup(
                f'<span font_family="monospace" foreground="{col}">{glyph}</span>'
                f'<span foreground="{col if bad else self.branding.color("text_dim")}">'
                f'{_esc(text)}</span>')

    # ---- Apply / Write --------------------------------------------------- #
    def _on_quit(self, *_):
        # Cancel/Escape/destroy without Finish: the Appearance preview poked the
        # live palette into branding's cache (on_apply, _page_appearance). Drop it
        # so a later same-process branding read sees the on-disk theme, not a
        # preview that was never saved.
        try:
            self.branding.load(refresh=True)
        except Exception:  # noqa: BLE001
            pass
        self.Gtk.main_quit()

    def _persist_appearance(self):
        """Auto-persist the wizard Appearance palette on Finish when the user
        touched it, so clicking Finish (without the page's own Save) never silently
        loses a colour change. No-op when the user never changed a colour/preset (or
        already Saved). branding.save_colors refreshes the cache, clearing any
        preview poison too."""
        editor = getattr(self, "_appearance_editor", None)
        if editor is None or not getattr(editor, "dirty", False):
            return
        try:
            self.branding.save_colors(dict(editor._colors))
            editor.dirty = False
            # Don't overwrite a seal/PIN status from _write() on success (silent win);
            # only surface a failure to persist the theme.
        except (OSError, ValueError) as e:
            self._set_status(f"theme not saved: {e}", bad=True)

    def _on_apply(self, assistant):
        try:
            self._write()
            self._persist_appearance()
        except Exception as e:  # noqa: BLE001
            self._set_status(f"write failed: {e}", bad=True)

    def _write(self):
        setup = self.setup
        paths = self.model.paths
        cfg = self.model.cfg()
        env = self.model.soc_env()
        panels_text = setup.render_panels_yaml(cfg)
        env_text = setup.render_soc_env(env)
        assert "SOC_VAULT_PASSWORD" not in env_text  # no-plaintext-master guarantee

        # FAIL-SAFE pre-flight: when we're NOT escalating, the chosen dir must be
        # writable. A locked-down ~/.config would otherwise PermissionError mid-write;
        # surface the specific cause (status + dialog) instead and stop.
        if not paths.get("needs_privilege"):
            from host import configpaths  # type: ignore
            wdir = os.path.dirname(paths["panels_out"]) or "."
            if not configpaths._dir_writable(wdir):
                msg = (f"Cannot write the config: {wdir} is not writable by this user. "
                       f"Fix its permissions or re-run as root.")
                self._set_status(msg, bad=True)
                try:
                    from host import guierror  # type: ignore
                    guierror.show("Config directory not writable", msg)
                except Exception:  # noqa: BLE001 — status line already shows it
                    pass
                return

        if paths.get("needs_privilege"):
            # The resolver chose /etc but this user can't write it. Escalate via the
            # FIXED pkexec helper: rendered content goes over STDIN (never argv, so
            # panel URLs/emails don't hit the process table), and SOC_VAULT_PASSWORD
            # is never passed (sealing stays in the user flow below).
            if not self._install_etc_via_pkexec(panels_text, env_text):
                # Escalation declined/failed -> fall back to the per-user dir so the
                # config STILL reaches the wall (for this login), visibly.
                from host import configpaths  # type: ignore
                pwrite = configpaths.resolve_write("panels", want_etc=False)
                ewrite = configpaths.resolve_write("env", want_etc=False)
                paths = dict(paths)
                paths.update(panels_out=pwrite["path"], panels_installed=pwrite["path"],
                             soc_env=ewrite["path"], wall_unit=None,
                             panels_mode=pwrite["mode"], env_mode=ewrite["mode"],
                             via=pwrite["via"], marker=pwrite.get("marker"),
                             needs_privilege=False,
                             secret_dir=os.path.join(configpaths.user_dir(), "secret"))
                self.model.paths = paths
                # Re-render soc.env from the per-user paths so SOC_SECRET_DIR points at
                # the user-dir seal — NOT the /etc dir we just failed to write. Without
                # this the wall (run as this user) would hunt for the sealed master in
                # root-owned /etc and never self-unlock, and the seal below would
                # needlessly re-prompt for pkexec after the operator already declined.
                env = self.model.soc_env()
                env_text = setup.render_soc_env(env)
                assert "SOC_VAULT_PASSWORD" not in env_text
                setup.write_file(paths["panels_out"], panels_text, paths["panels_mode"], dry=False)
                setup.write_file(paths["soc_env"], env_text, paths["env_mode"], dry=False)
        else:
            setup.write_file(paths["panels_out"], panels_text, paths["panels_mode"], dry=False)
            setup.write_file(paths["soc_env"], env_text, paths["env_mode"], dry=False)
            if paths.get("wall_unit"):
                setup.write_file(paths["wall_unit"],
                                 setup.render_wall_unit(env, soc_root=paths["soc_root"]),
                                 0o644, dry=False)

        # Per-user fallback: drop the `active` marker so the reader's marker-gated
        # tier picks THIS file up over a stale /etc.
        setup._drop_marker(paths, dry=False)

        # Seal / store the master per the chosen source. NEVER write it to a file.
        # Delegate the whole seal/store/verify/rewrite/client-config orchestration
        # to setup.seal_master — the SAME core the TTY first-run wizard runs — so
        # the two wizards seal identically and cannot drift.
        pw = self.model.master_password
        src = self.model.master_source
        backend = self.model.vault_backend
        if pw and backend in ("litebw", "rbw"):
            try:
                pin = self._apply_seal(
                    pw, src, self.model.master_pin, paths, env, backend)
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

        # FAIL-SAFE: confirm the wall will read what we just wrote; surface the exact
        # cause on the status line (and a fatal dialog) when it won't — never silent.
        self._confirm_reaches_wall(paths, env)

    # ---- master sealing (shared by Apply + the Vault-page Reset control) ---- #
    def _apply_seal(self, pw: str, src: str, pin: str, paths: dict,
                    env: dict, backend: str) -> str:
        """Seal/store the master per `src`, ESCALATING the host-bound seal via
        pkexec when the secret dir is root-owned (a deployed /etc) and this user
        can't write it. Returns the PIN actually used ('' for secret-service/env).
        Raises setup.SealMasterError on failure. Never writes the master to a file.

        The writable + the secret-service/env cases delegate to setup.seal_master
        (the shared TTY-wizard core, so they can't drift); only the root-owned
        host-bound case takes the pkexec branch (where seal_master would otherwise
        die with a bare PermissionError after the /etc config was already written)."""
        eff = "sealed" if src == "auto" else src
        sd = env.get("SOC_SECRET_DIR") or paths.get("secret_dir") or ""
        from host import configpaths  # type: ignore
        if eff == "sealed" and sd and not configpaths._dir_writable(sd):
            return self._seal_host_bound(pw, pin, sd)
        return self.setup.seal_master(
            pw, source=src, pin=pin, paths=paths,
            soc_env=env, backend=backend, dry=False)

    def _seal_host_bound(self, master: str, pin: str, secret_dir: str) -> str:
        """Host-bound (AES-GCM) seal of `master` into `secret_dir`, escalating via
        pkexec when the dir is root-owned. GTK-free, so it is also safe to call from
        a worker thread (the Reset control). Returns the PIN used; raises
        setup.SealMasterError on failure."""
        ss = self.secretstore
        if not ss.available():
            raise self.setup.SealMasterError(
                "the 'cryptography' package is required to seal the master password")
        if not master:
            raise self.setup.SealMasterError("no master password entered — nothing sealed")
        pin = pin or ss.gen_pin()
        from host import configpaths  # type: ignore
        if configpaths._dir_writable(secret_dir):
            try:
                ss.seal(master, pin, secret_dir)
                if ss.unseal(secret_dir) != master:
                    raise ss.SecretStoreError("seal did not unseal to the same value")
            except ss.SecretStoreError as e:
                raise self.setup.SealMasterError(f"could not seal: {e}")
            return pin
        used = self._seal_via_pkexec(master, pin, secret_dir)
        if used is None:
            raise self.setup.SealMasterError(
                f"could not seal to {secret_dir} (root-owned) — the system-password "
                f"prompt was declined or pkexec is unavailable")
        return used

    def _seal_via_pkexec(self, master: str, pin: str, secret_dir: str) -> "str | None":
        """Seal into a root-owned `secret_dir` via the fixed host.secretstore pkexec
        helper: master + PIN go over STDIN (never argv, so neither hits the process
        table), the operator gets the graphical SYSTEM-password prompt, and the seal
        is written as root. Returns the PIN used on success, or None if pkexec is
        absent / declined / failed (the caller then surfaces the failure)."""
        if not shutil.which("pkexec"):
            return None
        # Invoke secretstore BY ABSOLUTE PATH, not `-m host.secretstore`: pkexec
        # sanitises the environment, so PYTHONPATH does NOT cross the privilege
        # boundary (host.sysaction avoids this by shelling out via `pkexec env`).
        # Under `-m` the root child would `ModuleNotFoundError: No module named
        # 'host'` (the GUI runs from $SOC_ROOT, where `host` is not importable),
        # and the seal would silently fail. By-path needs no PYTHONPATH — the file
        # runs as __main__ and imports only its own stdlib + lazy crypto.
        helper = os.path.join(_repo_root(), "kiosk-host", "host", "secretstore.py")
        py = shutil.which("python3") or sys.executable
        payload = f"---MASTER---\n{master}\n---PIN---\n{pin}"
        try:
            p = subprocess.run(
                ["pkexec", py, helper, "--seal", "--dir", secret_dir],
                input=payload, text=True, capture_output=True, timeout=120)
        except Exception:  # noqa: BLE001 — treat any spawn fault as "declined/failed"
            return None
        if p.returncode != 0:
            return None
        out = (p.stdout or "").strip()
        return out or pin

    def _install_etc_via_pkexec(self, panels_text: str, env_text: str) -> bool:
        """Write /etc via the fixed pkexec helper. Content over STDIN (not argv) so
        no values/secrets hit the process table; never passes SOC_VAULT_PASSWORD.
        Returns True on success, False if pkexec is absent/declined/fails (caller
        then falls back to the per-user dir, visibly)."""
        if not shutil.which("pkexec"):
            return False
        # By ABSOLUTE PATH, not `-m host.configpaths`: pkexec strips PYTHONPATH at
        # the privilege boundary, so `-m` would `ModuleNotFoundError: No module
        # named 'host'` in the root child (the GUI's cwd is $SOC_ROOT, not
        # kiosk-host). configpaths is pure stdlib, so by-path runs with no
        # PYTHONPATH needed.
        helper = os.path.join(_repo_root(), "kiosk-host", "host", "configpaths.py")
        py = shutil.which("python3") or sys.executable
        payload = f"---PANELS---\n{panels_text}\n---ENV---\n{env_text}"
        try:
            p = subprocess.run(
                ["pkexec", py, helper, "--install-etc"],
                input=payload, text=True,
                capture_output=True, timeout=120)
        except Exception as e:  # noqa: BLE001
            self._set_status(f"pkexec escalation failed: {e}", bad=True)
            return False
        if p.returncode != 0:
            self._set_status(
                f"pkexec declined or failed ({p.stderr.strip() or p.returncode}); "
                f"falling back to your per-user config", bad=True)
            return False
        return True

    def _confirm_reaches_wall(self, paths: dict, env: dict):
        """Assert write_path == reader-resolved path via setup._confirm_reaches_wall;
        on disagreement raise a visible guierror dialog AND a red status line."""
        try:
            reached = self.setup._confirm_reaches_wall(paths, env, self.model.cfg(), dry=False)
        except Exception as e:  # noqa: BLE001 — never let the check mask a real write
            self._set_status(f"could not verify the wall will see the config: {e}", bad=True)
            return
        if reached:
            if paths.get("via") == "user":
                self._set_status(
                    "Saved for YOUR login (per-user config activated). Launch the wall "
                    "from this desktop and it uses the new panels.")
            else:
                self._set_status("Config saved where the wall reads it. Launch Desktop/Kiosk mode.")
        else:
            from host import configpaths  # type: ignore
            read_path = configpaths.resolve_panels()
            msg = (f"Saved to {paths['panels_out']} but the wall will read "
                   f"{read_path or '(nothing)'}. Unset SOC_PANELS_FILE / remove the "
                   f"shadowing file / re-run as root.")
            self._set_status(msg, bad=True)
            try:
                from host import guierror  # type: ignore
                guierror.show("Config will not reach the wall", msg)
            except Exception:  # noqa: BLE001 — status line already shows it
                pass


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
    # Same write-target logic as the TTY wizard: on a deployed box even a non-root
    # desktop user targets 'pi' so resolve_paths lands the config where the wall
    # reads it (per-user fallback + marker), never a dead repo file.
    target = setup._default_target(env)
    # pkexec escalation is offered only when both pkexec and a polkit-capable GUI
    # session are present; the dialog (in _maybe_escalate) gets the user's consent.
    can_escalate = bool(shutil.which("pkexec")) and bool(
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    paths = setup.resolve_paths(target, can_escalate=can_escalate)

    # ONE cached theme provider, added to the screen once. The Appearance page
    # repaints it via load_from_data for a live preview (never re-adds it).
    provider = Gtk.CssProvider()
    provider.load_from_data(_css(branding))
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(), provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    model = WizardModel(setup, paths)
    sa = SetupAssistant(model, setup, (Gtk, Gdk, GLib, GdkPixbuf))
    sa._theme_provider = provider
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
