"""Unit tests for host.branding (rebranding source of truth)."""
import builtins
import subprocess
import sys

import pytest

from host import branding


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with no branding file pointed at and a cold cache."""
    monkeypatch.delenv("SOC_BRANDING_FILE", raising=False)
    monkeypatch.delenv("SOC_ROOT", raising=False)
    branding._cache = None
    yield
    branding._cache = None


def _point_at(monkeypatch, tmp_path, text):
    """Write a branding file and make it the *only* candidate that exists."""
    f = tmp_path / "branding.yaml"
    f.write_text(text, encoding="utf-8")
    monkeypatch.setenv("SOC_BRANDING_FILE", str(f))
    # Ensure stray /etc or repo files can't win — SOC_BRANDING_FILE is yielded first.
    branding._cache = None
    return f


def test_defaults_when_no_file(monkeypatch, tmp_path):
    # Point SOC_ROOT at an empty dir so no repo branding.yaml is found.
    monkeypatch.setenv("SOC_ROOT", str(tmp_path))
    monkeypatch.setenv("SOC_BRANDING_FILE", str(tmp_path / "does-not-exist.yaml"))
    branding._cache = None
    data = branding.load(refresh=True)
    assert data["name"] == "SOC Video Wall"
    assert data["short_name"] == "SOC Wall"
    assert data["colors"]["primary"] == "#2BE0C8"


def test_env_override_merges_over_defaults(monkeypatch, tmp_path):
    _point_at(monkeypatch, tmp_path,
              "name: Acme NOC\n"
              "colors:\n"
              "  primary: \"#FF0000\"\n")
    data = branding.load(refresh=True)
    # Overridden keys take effect.
    assert data["name"] == "Acme NOC"
    assert data["colors"]["primary"] == "#FF0000"
    # Unspecified top-level keys keep defaults.
    assert data["short_name"] == "SOC Wall"
    assert data["tagline"] == "Operations console"
    # Unspecified colours keep defaults (deep merge, not replace).
    assert data["colors"]["kiosk"] == "#F5B14C"
    assert data["colors"]["background"] == "#0B1220"


def test_color_resolution(monkeypatch, tmp_path):
    _point_at(monkeypatch, tmp_path, "colors:\n  kiosk: \"#123456\"\n")
    branding.load(refresh=True)
    assert branding.color("kiosk") == "#123456"
    # Falls back to default colour for an unspecified name.
    assert branding.color("primary") == "#2BE0C8"
    # Unknown colour name with an explicit default.
    assert branding.color("nope", "#000111") == "#000111"
    # Unknown colour name, no default -> the module's last-resort grey.
    assert branding.color("nope") == "#888888"


def test_icon_path_resolves_existing(monkeypatch, tmp_path):
    icon = tmp_path / "logo.svg"
    icon.write_text("<svg/>", encoding="utf-8")
    _point_at(monkeypatch, tmp_path,
              "icon: {}\n".format(icon))  # absolute path
    branding.load(refresh=True)
    assert branding.icon_path() == str(icon)


def test_icon_path_missing_returns_empty(monkeypatch, tmp_path):
    # Absolute icon that does not exist, and an empty SOC_ROOT so no fallback file.
    monkeypatch.setenv("SOC_ROOT", str(tmp_path))
    _point_at(monkeypatch, tmp_path,
              "icon: {}\n".format(tmp_path / "nope.svg"))
    branding.load(refresh=True)
    assert branding.icon_path() == ""


def test_malformed_file_falls_back_to_defaults(monkeypatch, tmp_path):
    # Garbage that is not valid YAML mapping (a bare list / broken structure).
    _point_at(monkeypatch, tmp_path,
              "name: [unclosed\n\t\t: : :\nthis is not: : valid: yaml\n")
    data = branding.load(refresh=True)
    # Must not raise; whatever survived, defaults still fill the gaps.
    assert data["short_name"] == "SOC Wall"
    assert data["colors"]["primary"] == "#2BE0C8"
    assert isinstance(data["colors"], dict)


def test_stdlib_parser_when_pyyaml_unavailable(monkeypatch, tmp_path):
    """Force the import of `yaml` to fail so _load_file uses _parse_flat."""
    f = _point_at(monkeypatch, tmp_path,
                  "name: Stdlib NOC\n"
                  "tagline: parsed without yaml\n"
                  "colors:\n"
                  "  primary: \"#0A0B0C\"\n"
                  "  kiosk: '#0D0E0F'\n")
    real_import = builtins.__import__

    def _no_yaml(name, *a, **k):
        if name == "yaml":
            raise ImportError("yaml disabled for test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _no_yaml)
    monkeypatch.delitem(sys.modules, "yaml", raising=False)

    # Exercise the parser directly...
    flat = branding._parse_flat(str(f))
    assert flat["name"] == "Stdlib NOC"
    assert flat["tagline"] == "parsed without yaml"
    assert flat["colors"]["primary"] == "#0A0B0C"
    assert flat["colors"]["kiosk"] == "#0D0E0F"

    # ...and through the public load() path (deep-merged over defaults).
    data = branding.load(refresh=True)
    assert data["name"] == "Stdlib NOC"
    assert data["colors"]["primary"] == "#0A0B0C"
    assert data["colors"]["background"] == "#0B1220"  # default preserved


def test_desktop_cli_emits_branded_entry(monkeypatch, tmp_path):
    f = tmp_path / "branding.yaml"
    f.write_text("name: Acme NOC\ntagline: Eyes on glass\n", encoding="utf-8")
    repo = subprocess.run(
        [sys.executable, "-m", "host.branding", "desktop",
         "/opt/soc-display/scripts/soc-wall-menu", "acme-noc"],
        cwd=_kiosk_host(),
        env={**_env(), "SOC_BRANDING_FILE": str(f)},
        capture_output=True, text=True, check=True)
    out = repo.stdout
    assert out.startswith("[Desktop Entry]")
    assert "Name=Acme NOC" in out
    assert "Comment=Eyes on glass" in out
    assert "Exec=/opt/soc-display/scripts/soc-wall-menu" in out
    assert "Icon=acme-noc" in out
    assert "Type=Application" in out
    assert "Terminal=false" in out


def _kiosk_host():
    import os
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env():
    import os
    e = dict(os.environ)
    # Ensure the subprocess can import `host` regardless of cwd.
    e["PYTHONPATH"] = _kiosk_host() + os.pathsep + e.get("PYTHONPATH", "")
    return e
