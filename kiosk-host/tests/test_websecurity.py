"""Tests for the shared renderer-security logic (host.websecurity) + the
web-data dir resolver (configpaths.resolve_webdata_dir).

Pure stdlib / no gi — runs in `make test`. These pin:
  * host-match semantics for the nav allowlist (subdomain-inclusive, wildcards,
    off-allowlist refusal, loopback),
  * the tracker data file is well-formed + the derived host list,
  * per-panel allowlist composition (own origin + SSO + allow + global),
  * the block_trackers / unblock honouring,
  * resolve_webdata_dir precedence (sibling of secret/, env override, 0700-able).
"""
import json
import os
from dataclasses import dataclass

import pytest

from host import configpaths as cp
from host import websecurity as ws

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@dataclass
class _Panel:
    id: str = "p"
    effective_url: str = "https://dash.example.com/"
    allow: tuple = ()
    block_trackers: bool = True
    unblock: tuple = ()


@dataclass
class _Sec:
    nav_allowlist: bool = True
    allow: tuple = ()
    block_trackers: bool = True
    sso_allow: tuple = ()


@pytest.fixture(autouse=True)
def _root(monkeypatch):
    # Point at the real repo so the curated data files load.
    monkeypatch.setenv("SOC_ROOT", _REPO)


# --------------------------------------------------------------------------- #
# host matching
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host,allowed,expect", [
    ("dash.example.com", {"dash.example.com"}, True),       # exact
    ("auth.dash.example.com", {"dash.example.com"}, True),  # subdomain-inclusive
    ("dash.example.com", {"example.com"}, True),            # parent allows child
    ("evil.com", {"dash.example.com"}, False),              # off-allowlist
    ("example.com.evil.com", {"example.com"}, False),       # suffix-spoof refused
    ("login.okta.com", {"*.okta.com"}, True),               # wildcard
    ("okta.com", {"*.okta.com"}, True),                     # wildcard matches apex
    ("127.0.0.1", {"127.0.0.1"}, True),                     # loopback (tunnels)
    ("", {"example.com"}, False),                           # no host
    ("DASH.EXAMPLE.COM", {"dash.example.com"}, True),       # case-insensitive
])
def test_host_matches(host, allowed, expect):
    assert ws.host_matches(host, allowed) is expect


def test_host_of():
    assert ws.host_of("https://a.b.com:8443/x?y=1") == "a.b.com"
    assert ws.host_of("about:blank") == ""
    assert ws.host_of("") == ""


# --------------------------------------------------------------------------- #
# tracker data file
# --------------------------------------------------------------------------- #
def test_tracker_json_well_formed():
    text = ws.load_tracker_rules_text()
    assert text, "trackers-top20.json must ship"
    rules = json.loads(text)
    assert isinstance(rules, list) and len(rules) >= 20
    for r in rules:
        assert r["action"]["type"] == "block"
        # third-party only, so a dashboard's own first-party metrics aren't caught
        assert r["trigger"]["load-type"] == ["third-party"]
        assert r["trigger"]["url-filter"]


def test_tracker_hosts_derived():
    hosts = ws.tracker_hosts()
    assert "google-analytics.com" in hosts
    assert "doubleclick.net" in hosts
    assert "mc.yandex.ru" in hosts
    # no leftover regex escaping leaked into the host list
    assert all("\\" not in h for h in hosts)


def test_unblock_trims_tracker_hosts():
    p = _Panel(unblock=("segment.io", "cdn.segment.com"))
    hosts = ws.effective_tracker_hosts(p, _Sec())
    assert "segment.io" not in hosts
    assert "cdn.segment.com" not in hosts
    assert "google-analytics.com" in hosts   # others untouched


def test_should_block_trackers_precedence():
    assert ws.should_block_trackers(_Panel(), _Sec(), True) is True
    # env off -> off
    assert ws.should_block_trackers(_Panel(), _Sec(), False) is False
    # global security off -> off
    assert ws.should_block_trackers(_Panel(), _Sec(block_trackers=False), True) is False
    # per-panel off -> off
    assert ws.should_block_trackers(_Panel(block_trackers=False), _Sec(), True) is False


# --------------------------------------------------------------------------- #
# allowlist composition
# --------------------------------------------------------------------------- #
def test_build_allowlist_includes_own_origin_and_sso():
    al = ws.build_allowlist(_Panel(), _Sec())
    assert "dash.example.com" in al          # own origin
    assert "*.okta.com" in al                # bundled SSO
    # and it actually allows the panel's own SSO redirect + own subdomain
    assert ws.host_matches("login.microsoftonline.com", al)
    assert ws.host_matches("auth.dash.example.com", al)
    assert not ws.host_matches("totally-unrelated.com", al)


def test_build_allowlist_per_panel_and_global_allow():
    p = _Panel(allow=("extra.corp.com", "*.cdn.net"))
    sec = _Sec(allow=("global.allowed.com",), sso_allow=("idp.self-hosted.com",))
    al = ws.build_allowlist(p, sec)
    assert ws.host_matches("extra.corp.com", al)
    assert ws.host_matches("img.cdn.net", al)
    assert ws.host_matches("global.allowed.com", al)
    assert ws.host_matches("idp.self-hosted.com", al)


def test_build_allowlist_tunnel_loopback():
    al = ws.build_allowlist(_Panel(effective_url="http://127.0.0.1:8080/d"), _Sec())
    assert ws.host_matches("127.0.0.1", al)


# --------------------------------------------------------------------------- #
# resolve_webdata_dir
# --------------------------------------------------------------------------- #
def test_webdata_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_WEBDATA_DIR", str(tmp_path / "wd"))
    assert cp.resolve_webdata_dir() == str(tmp_path / "wd")


def test_webdata_is_sibling_of_secret_not_inside(monkeypatch, tmp_path):
    # No env override, no marker, no /etc -> dev repo location; secret/ and
    # webdata/ must be SIBLINGS (webdata must not live inside the sealed secret).
    monkeypatch.delenv("SOC_WEBDATA_DIR", raising=False)
    monkeypatch.delenv("SOC_SECRET_DIR", raising=False)
    monkeypatch.setenv("SOC_ROOT", str(tmp_path))
    monkeypatch.setenv("SOC_ETC_DIR", str(tmp_path / "no-etc"))
    monkeypatch.setattr(cp, "xdg_config_home", lambda: str(tmp_path / "xdg"))
    secret = cp.resolve_secret_dir()
    webdata = cp.resolve_webdata_dir()
    assert os.path.basename(webdata) == "webdata"
    assert os.path.dirname(secret) == os.path.dirname(webdata)
    assert not webdata.startswith(secret + os.sep)


def test_webdata_marker_gated_user_tier(monkeypatch, tmp_path):
    monkeypatch.delenv("SOC_WEBDATA_DIR", raising=False)
    user = tmp_path / "xdg" / "soc-display"
    monkeypatch.setattr(cp, "xdg_config_home", lambda: str(tmp_path / "xdg"))
    monkeypatch.setenv("SOC_ETC_DIR", str(tmp_path / "no-etc"))
    # marker present -> user tier wins
    os.makedirs(user, exist_ok=True)
    (user / cp.MARKER_BASENAME).write_text("")
    assert cp.resolve_webdata_dir() == str(user / "webdata")
