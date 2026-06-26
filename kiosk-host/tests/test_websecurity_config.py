"""Config + data-file tests for the renderer security/compat layer.

Covers the new, backward-compatible panels.yaml knobs (persist / user_agent /
allow / block_trackers / unblock + the insecure_tls alias), the optional
top-level `security:` block (+ its env toggles), a clean round-trip through
to_yaml(), the curated tracker blocklist + SSO allowlist data files being
well-formed, and configpaths.resolve_webdata_dir() precedence. No display / no
gi — runs in `make test`.
"""
import json
import os
import tempfile

import pytest

from host import config
from host import configpaths as cp


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _load(text):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(text)
        path = fh.name
    return config.load(path)


def _expect_error(text, *snippets):
    try:
        _load(text)
    except config.ConfigError as e:
        for s in snippets:
            assert s in str(e), f"expected {s!r} in:\n{e}"
        return
    raise AssertionError(f"expected ConfigError with {snippets}")


_BASE_PANEL = """
panels:
  - id: a
    grid: [0, 0]
    url: "https://dash.example.com/"
"""


# --------------------------------------------------------------------------- #
# backward compatibility: absence == old behaviour
# --------------------------------------------------------------------------- #
def test_defaults_are_safe_and_backward_compatible():
    conf = _load(_BASE_PANEL)
    p = conf.panels[0]
    assert p.persist is True
    assert p.user_agent is None
    assert p.allow == ()
    assert p.block_trackers is True
    assert p.unblock == ()
    assert p.allow_insecure is False
    # the security block defaults to all-safe
    s = conf.security
    assert s.nav_allowlist is True
    assert s.block_trackers is True
    assert s.allow == () and s.sso_allow == ()


# --------------------------------------------------------------------------- #
# per-panel knobs
# --------------------------------------------------------------------------- #
def test_panel_knobs_parsed():
    conf = _load("""
panels:
  - id: a
    grid: [0, 0]
    url: "https://dash.example.com/"
    persist: false
    user_agent: "Mozilla/5.0 SOC"
    allow: ["*.cdn.example.com", "auth.example.net"]
    block_trackers: false
    unblock: ["segment.io"]
""")
    p = conf.panels[0]
    assert p.persist is False
    assert p.user_agent == "Mozilla/5.0 SOC"
    assert p.allow == ("*.cdn.example.com", "auth.example.net")
    assert p.block_trackers is False
    assert p.unblock == ("segment.io",)


def test_insecure_tls_is_alias_of_allow_insecure():
    conf = _load("""
panels:
  - id: a
    grid: [0, 0]
    url: "https://self-signed.lan/"
    insecure_tls: true
""")
    assert conf.panels[0].allow_insecure is True


def test_insecure_tls_conflict_is_an_error():
    _expect_error("""
panels:
  - id: a
    grid: [0, 0]
    url: "https://x/"
    insecure_tls: true
    allow_insecure: false
""", "aliases")


def test_panel_knob_type_validation():
    _expect_error(_BASE_PANEL.rstrip() + "\n    persist: \"yes\"\n",
                  "persist must be true or false")
    _expect_error(_BASE_PANEL.rstrip() + "\n    block_trackers: 1\n",
                  "block_trackers must be true or false")
    _expect_error(_BASE_PANEL.rstrip() + "\n    allow: \"example.com\"\n",
                  "must be a list")
    _expect_error(_BASE_PANEL.rstrip() + "\n    unblock: [\"\"]\n",
                  "non-empty domain")
    _expect_error(_BASE_PANEL.rstrip() + "\n    user_agent: \"\"\n",
                  "user_agent must be a non-empty string")


# --------------------------------------------------------------------------- #
# the security: block + env toggles
# --------------------------------------------------------------------------- #
def test_security_block_parsed():
    conf = _load(_BASE_PANEL + """
security:
  nav_allowlist: false
  block_trackers: false
  allow: ["internal.corp.lan"]
  sso_allow: ["*.keycloak.corp.lan"]
""")
    s = conf.security
    assert s.nav_allowlist is False
    assert s.block_trackers is False
    assert s.allow == ("internal.corp.lan",)
    assert s.sso_allow == ("*.keycloak.corp.lan",)


def test_security_block_validation():
    _expect_error(_BASE_PANEL + "security:\n  nav_allowlist: \"no\"\n",
                  "nav_allowlist: must be true or false")
    _expect_error(_BASE_PANEL + "security:\n  allow: \"x\"\n",
                  "security.allow: must be a list")
    # an unknown key is a warning, not an error
    conf = _load(_BASE_PANEL + "security:\n  nav_allowlst: false\n")
    assert any("nav_allowlst" in w for w in conf.warnings)


def test_env_toggles_override_security_defaults(monkeypatch):
    monkeypatch.setenv("SOC_NAV_ALLOWLIST", "0")
    monkeypatch.setenv("SOC_BLOCK_TRACKERS", "off")
    conf = _load(_BASE_PANEL)        # file omits the block -> defaults True
    assert conf.security.nav_allowlist is False
    assert conf.security.block_trackers is False


def test_env_bool_helper(monkeypatch):
    monkeypatch.delenv("X_SOC_T", raising=False)
    assert config.env_bool("X_SOC_T", True) is True
    monkeypatch.setenv("X_SOC_T", "garbage")
    assert config.env_bool("X_SOC_T", True) is True     # safe fallback
    for v, exp in (("1", True), ("yes", True), ("ON", True),
                   ("0", False), ("no", False), ("OFF", False)):
        monkeypatch.setenv("X_SOC_T", v)
        assert config.env_bool("X_SOC_T", not exp) is exp


# --------------------------------------------------------------------------- #
# round-trip: only non-defaults are emitted, and load(to_yaml(x)) == x
# --------------------------------------------------------------------------- #
def test_to_yaml_roundtrip_of_new_knobs():
    src = _BASE_PANEL + """
  - id: b
    grid: [1, 0]
    url: "https://b.example.com/"
    persist: false
    user_agent: "UA/1"
    allow: ["*.b.example.com"]
    block_trackers: false
    unblock: ["mixpanel.com"]
security:
  nav_allowlist: false
  allow: ["g.lan"]
  sso_allow: ["*.idp.lan"]
"""
    conf = _load(src)
    out = config.to_yaml(conf)
    conf2 = config.load_str(out)
    a, b = conf2.panels[0], conf2.panels[1]
    assert a.persist is True and a.allow == ()          # defaults not emitted
    assert b.persist is False and b.user_agent == "UA/1"
    assert b.allow == ("*.b.example.com",) and b.unblock == ("mixpanel.com",)
    assert b.block_trackers is False
    assert conf2.security.nav_allowlist is False
    assert conf2.security.allow == ("g.lan",)
    assert conf2.security.sso_allow == ("*.idp.lan",)


def test_to_yaml_omits_defaults():
    conf = _load(_BASE_PANEL)
    out = config.to_yaml(conf)
    # an all-default config must not grow a security: block or panel knobs
    assert "security:" not in out
    assert "block_trackers" not in out
    assert "persist" not in out


# --------------------------------------------------------------------------- #
# data files: curated, well-formed, extensible
# --------------------------------------------------------------------------- #
_SECURITY_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "security")


def test_tracker_blocklist_is_valid_wkcontentrulelist():
    path = os.path.join(_SECURITY_DIR, "trackers-top20.json")
    rules = json.load(open(path))
    assert isinstance(rules, list) and len(rules) >= 20
    hosts = set()
    for r in rules:
        assert r["action"]["type"] == "block"
        trig = r["trigger"]
        assert "url-filter" in trig and trig["url-filter"]
        # third-party only, so a dashboard's own first-party metrics aren't caught
        assert trig.get("load-type") == ["third-party"]
        hosts.add(trig["url-filter"])
    # the canonical heavy hitters must be present
    joined = " ".join(hosts)
    for must in ("google-analytics", "googletagmanager", "doubleclick",
                 "facebook", "hotjar", "mixpanel", "clarity", "yandex"):
        assert must in joined, f"{must} missing from blocklist"


def test_sso_allowlist_is_well_formed():
    path = os.path.join(_SECURITY_DIR, "allowlist-sso.txt")
    lines = [ln.strip() for ln in open(path)
             if ln.strip() and not ln.strip().startswith("#")]
    assert lines, "allowlist-sso.txt has no domains"
    for d in lines:
        assert " " not in d and "/" not in d, f"bad domain entry: {d!r}"
    joined = " ".join(lines)
    for must in ("microsoftonline.com", "okta.com",
                 "accounts.google.com", "auth0.com", "duosecurity.com"):
        assert must in joined, f"{must} missing from SSO allowlist"


# --------------------------------------------------------------------------- #
# configpaths.resolve_webdata_dir precedence + isolation from secret/
# --------------------------------------------------------------------------- #
@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    xdg = tmp_path / "xdg"
    etc = tmp_path / "etc-soc"
    repo = tmp_path / "repo"
    (repo / "kiosk-host").mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setenv("SOC_ROOT", str(repo))
    monkeypatch.delenv("SOC_WEBDATA_DIR", raising=False)
    monkeypatch.setattr(cp, "ETC_DIR", str(etc))
    return tmp_path


def test_webdata_env_override(sandbox, monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "wd"))
    assert cp.resolve_webdata_dir() == str(tmp_path / "wd")


def test_webdata_marker_gates_user_tier(sandbox):
    # no marker, no /etc -> dev repo fallback
    assert cp.resolve_webdata_dir() == os.path.join(
        cp.repo_root(), "dev", "run", cp.WEBDATA_BASENAME)
    # drop the marker -> user tier
    os.makedirs(cp.user_dir(), exist_ok=True)
    open(cp.active_marker(), "w").close()
    assert cp.resolve_webdata_dir() == os.path.join(
        cp.user_dir(), cp.WEBDATA_BASENAME)


def test_webdata_prefers_etc_when_deployed(sandbox):
    os.makedirs(cp.ETC_DIR, exist_ok=True)        # looks deployed, no marker
    assert cp.resolve_webdata_dir() == os.path.join(
        cp.ETC_DIR, cp.WEBDATA_BASENAME)


def test_webdata_is_sibling_not_inside_secret(sandbox):
    # the no-plaintext-master guarantee: webdata must NOT live under secret/
    os.makedirs(cp.ETC_DIR, exist_ok=True)
    secret = cp.resolve_secret_dir()
    webdata = cp.resolve_webdata_dir()
    assert not webdata.startswith(secret.rstrip("/") + "/")
    assert os.path.dirname(secret) == os.path.dirname(webdata)
