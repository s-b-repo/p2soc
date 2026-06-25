"""Unit tests for setup.py (the install/config/doctor tool)."""
import importlib.util
import os

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _setup():
    spec = importlib.util.spec_from_file_location(
        "soc_setup", os.path.join(_REPO, "setup.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_validators():
    s = _setup()
    assert s.v_url("https://host:443/login") is None
    assert s.v_url("http://h/") is None
    assert s.v_url("ftp://x") is not None
    assert s.v_url("http://h:99999/") is not None        # bad port
    assert s.v_hostport("10.0.0.5:443") is None
    assert s.v_hostport("nope") is not None
    assert s.v_hostport("h:0") is not None
    assert s.v_email("a@b.co") is None
    assert s.v_email("bad") is not None
    assert s.v_sha256("") is None                        # optional
    assert s.v_sha256("0" * 64) is None
    assert s.v_sha256("abc") is not None
    assert s.v_selector("#user") is None
    assert s.v_selector("   ") is not None
    assert s.v_host("vpn.example.com") is None
    assert s.v_host("bad host") is not None


def test_vault_items_collection():
    s = _setup()
    cfg = {
        "panels": [
            {"vault_item": "P1", "url": "http://a/"},
            {"url": "http://b/"},                         # no vault_item -> skipped
        ],
        "vpn": {"enabled": True, "vault_item": "V"},
        "proxy": {"enabled": False, "vault_item": "PX"},  # disabled -> skipped
    }
    items = s._vault_items(cfg)
    names = sorted(n for _, n, _ in items)
    assert names == ["P1", "V"]
