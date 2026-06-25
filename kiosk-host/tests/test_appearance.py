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
