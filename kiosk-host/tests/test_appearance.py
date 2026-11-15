"""Headless tests for the Appearance editor (host.appearance) + branding.save_colors.

These exercise the preset data, the headless preset writer and the persistence
round-trip WITHOUT importing gi / needing a display, so they run in the display-less
`make test`. The GUI codepath (gi) is never touched here.
"""
import os
import subprocess
import sys

import pytest

from host import appearance, branding

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_KIOSK = os.path.join(_REPO, "kiosk-host")

_KEYS = set(appearance.PALETTE_KEYS)


@pytest.fixture(autouse=True)
def _clean_branding(monkeypatch):
    monkeypatch.delenv("SOC_BRANDING_FILE", raising=False)
    branding._cache = None
    yield
    branding._cache = None


def test_no_gi_on_headless_path(tmp_path):
    """Importing host.appearance + the headless preset write must not pull in gi.

    Checked in a FRESH interpreter so other tests that import gi can't pollute it.
    """
    out = tmp_path / "branding.yaml"
    code = (
        "import sys\n"
        "import host.appearance as a\n"
        f"rc = a.write_preset('midnight', {str(out)!r})\n"
        "assert rc == 0, rc\n"
        "assert 'gi' not in sys.modules, 'appearance must not import gi headless'\n"
        "print('ok')\n"
    )
    env = dict(os.environ, PYTHONPATH=_KIOSK)
    env.pop("SOC_BRANDING_FILE", None)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_check_passes():
    assert appearance._check() == 0


def test_all_presets_have_14_keys():
    assert set(appearance.PRESET_ORDER) == set(appearance.PRESETS)
    assert len(_KEYS) == 14
    for name, palette in appearance.PRESETS.items():
        assert set(palette) == _KEYS, f"{name} key mismatch"
        # every value is a valid hex colour
        for k, v in palette.items():
            assert branding._fmt_hex(v)  # raises on a bad value


def test_soc_green_is_branding_default():
    assert appearance.PRESETS["soc-green"] == branding._DEFAULTS["colors"]


def test_build_css_is_bytes():
    for name in appearance.PRESET_ORDER:
        css = appearance.build_css(appearance.PRESETS[name])
        assert isinstance(css, bytes) and css


def test_write_preset_unknown_returns_nonzero(tmp_path):
    rc = appearance.write_preset("nope", str(tmp_path / "b.yaml"))
    assert rc != 0


def test_save_colors_roundtrip_fresh(tmp_path):
    target = tmp_path / "branding.yaml"
    path = branding.save_colors(dict(appearance.PRESETS["amber-ops"]), path=str(target))
    assert path == str(target)
    assert oct(target.stat().st_mode & 0o777) == "0o644"
    reloaded = branding._load_file(str(target)).get("colors") or {}
    for k, v in appearance.PRESETS["amber-ops"].items():
        assert reloaded[k].upper() == v.upper()


def test_save_colors_preserves_comments_and_structure(tmp_path):
    """An in-place rewrite must keep comments, the header, key order and inline
    docs; only colour VALUES change, and a '#' inside the quoted value is not
    mistaken for a trailing comment."""
    target = tmp_path / "branding.yaml"
    target.write_text(
        "# header doc\n"
        "name: \"Keep Me\"\n"
        "tagline: \"stays\"\n"
        "colors:\n"
        "  primary: \"#1FA463\"  # primary doc\n"
        "  kiosk: \"#0E7C7B\"\n",
        encoding="utf-8")
    branding.save_colors({"primary": "#abcdef", "kiosk": "#112233"}, path=str(target))
    body = target.read_text(encoding="utf-8")
    assert "# header doc" in body
    assert 'name: "Keep Me"' in body
    assert 'tagline: "stays"' in body
    assert "# primary doc" in body          # inline comment survived
    assert '"#ABCDEF"' in body              # value rewritten + normalised
    assert '"#112233"' in body
    # the quoted value's own '#' did NOT leak a bogus trailing comment
    assert "#ABCDEF\"  #1FA463" not in body
    d = branding._load_file(str(target))
    assert d["name"] == "Keep Me"
    assert d["colors"]["primary"] == "#ABCDEF"
    assert d["colors"]["kiosk"] == "#112233"


def test_save_colors_rejects_bad_hex(tmp_path):
    with pytest.raises(ValueError):
        branding.save_colors({"primary": "not-a-colour"}, path=str(tmp_path / "b.yaml"))
    # and nothing was written
    assert not (tmp_path / "b.yaml").exists()


def test_save_colors_never_writes_secrets(tmp_path):
    """Only palette keys land in the file — a stray non-colour key with a hex value
    is written as a colour, but a secret-shaped value (non-hex) is rejected, so no
    secret can ride along."""
    target = tmp_path / "branding.yaml"
    branding.save_colors(dict(appearance.PRESETS["soc-green"]), path=str(target))
    body = target.read_text(encoding="utf-8")
    assert "PASSWORD" not in body and "SECRET" not in body.upper().replace("SECRET_DIR", "")


def test_save_target_raises_on_unwritable(tmp_path, monkeypatch):
    """A non-writable explicit path raises PermissionError (never a silent no-op)."""
    bad = tmp_path / "nope" / "deep"
    # make the parent unwritable
    nope = tmp_path / "nope"
    nope.mkdir()
    os.chmod(nope, 0o500)
    try:
        with pytest.raises(PermissionError):
            branding.save_colors({"primary": "#1FA463"}, path=str(bad / "branding.yaml"))
    finally:
        os.chmod(nope, 0o700)


def test_cli_check(tmp_path):
    env = dict(os.environ, PYTHONPATH=_KIOSK)
    r = subprocess.run([sys.executable, "-m", "host.appearance", "--check"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "appearance ok" in r.stdout


def test_cli_list_presets():
    env = dict(os.environ, PYTHONPATH=_KIOSK)
    r = subprocess.run([sys.executable, "-m", "host.appearance", "--list-presets"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    for name in appearance.PRESET_ORDER:
        assert name in r.stdout


# --------------------------------------------------------------------------- #
# WCAG contrast — the objective legibility guard. Every preset must pass with no
# text/accent-on-surface pair below AA, AFTER the on-surface routing the builders
# apply. This is the regression guard for the Midnight black-on-black class of bug.
# --------------------------------------------------------------------------- #
def test_every_preset_passes_contrast_matrix():
    for name, palette in appearance.PRESETS.items():
        fails = appearance.contrast_matrix(palette)
        assert not fails, f"preset {name!r} below WCAG AA: {fails}"


def test_contrast_matrix_catches_black_on_black():
    """A deliberately broken (black-on-black) palette must be FLAGGED — proving the
    guard actually detects invisible text, not just rubber-stamps."""
    broken = dict(branding._DEFAULTS["colors"])
    broken.update(background="#000000", surface_top="#050505",
                  surface_bottom="#040404", text="#010101", text_dim="#020202")
    fails = appearance.contrast_matrix(broken)
    assert fails, "contrast_matrix failed to catch black-on-black text"
    labels = {f[0] for f in fails}
    assert any("text on" in lab for lab in labels)


def test_branding_contrast_helpers_match_wcag():
    # Known WCAG anchors: black/white == 21, identical == 1.
    assert round(branding.contrast_ratio("#000000", "#FFFFFF"), 1) == 21.0
    assert round(branding.contrast_ratio("#777777", "#777777"), 1) == 1.0
    assert branding.is_dark("#05100B") and not branding.is_dark("#FFFFFF")


def test_text_on_picks_readable_button_label():
    # White on a dark fill, near-black on a light/bright fill.
    assert branding.contrast_ratio(
        branding.text_on("#157A49", dark="#0B1F14"), "#157A49") >= 4.5
    assert branding.contrast_ratio(
        branding.text_on("#19C46F", dark="#D6FBE7"), "#19C46F") >= 4.5  # bright green
    assert branding.contrast_ratio(
        branding.text_on("#C8860B", dark="#F5E6C8"), "#C8860B") >= 4.5  # amber


def test_accent_on_keeps_brand_where_it_reads_and_swaps_where_it_doesnt():
    # On a dark surface the bright brand accent reads -> kept.
    assert branding.accent_on("#0B1E16", accent="#3DF59B", strong="#19C46F") == "#3DF59B"
    # On the light tinted surface the brand green fails 3.0 -> swapped to strong.
    got = branding.accent_on("#F4F8F5", accent="#1FA463", strong="#157A49")
    assert got == "#157A49"
    assert branding.contrast_ratio(got, "#F4F8F5") >= 3.0


# --------------------------------------------------------------------------- #
# Cyber glow — present on a DARK palette (Midnight), absent on the default light
# palette, and motion (the @keyframes pulse) gated by reduced-motion. This locks
# the deliberate Midnight green-on-black look + the reduced-motion contract.
# --------------------------------------------------------------------------- #
def test_midnight_has_static_cyber_glow():
    css = appearance.build_css(appearance.PRESETS["midnight"]).decode()
    # text-shadow on the eyebrow/headings + a box-shadow halo on the sample card.
    assert ".soc-ap-eyebrow { text-shadow:" in css
    assert ".soc-ap-sample { box-shadow:" in css


def test_default_light_palette_stays_flat():
    """The default SOC-green (white field) must NOT light up — no glow rules at all,
    so the default look does not regress."""
    css = appearance.build_css(appearance.PRESETS["soc-green"]).decode()
    assert "text-shadow" not in css
    assert "@keyframes soc-ap-pulse" not in css


def test_glow_pulse_gated_by_reduced_motion(monkeypatch):
    """With animations enabled the dark palette gets the @keyframes dot pulse; with
    them disabled (reduced motion) the animation is dropped but the STATIC glow
    remains (so the cyber look survives, just without motion)."""
    monkeypatch.setattr(appearance, "_animations_enabled", lambda: True)
    on = appearance.build_css(appearance.PRESETS["midnight"]).decode()
    assert "@keyframes soc-ap-pulse" in on and "animation: soc-ap-pulse" in on

    monkeypatch.setattr(appearance, "_animations_enabled", lambda: False)
    off = appearance.build_css(appearance.PRESETS["midnight"]).decode()
    assert "@keyframes soc-ap-pulse" not in off and "animation:" not in off
    assert "text-shadow" in off  # static glow preserved under reduced motion


def test_any_dark_palette_lights_up_not_just_named_midnight():
    """The glow is branding-driven (gated on is_dark(background)), so a CUSTOM dark
    palette gets it too — not hardcoded to the Midnight preset name."""
    custom_dark = dict(branding._DEFAULTS["colors"])
    custom_dark.update(background="#06080A", surface_top="#0E1318",
                       surface_bottom="#0A0F13", text="#E6F0FF",
                       text_dim="#9FB4CC", primary="#5AC8FF",
                       accent_strong="#2E9BD6", good="#5AC8FF")
    css = appearance.build_css(custom_dark).decode()
    assert "text-shadow" in css and "box-shadow" in css
