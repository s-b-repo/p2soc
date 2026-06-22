"""iNode (H3C SSL VPN) — config helpers, driver classification, render round-trip."""
import importlib.util
import os

import pytest

from host import config, vpndrivers

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def test_vpn_kind_inode():
    assert config.vpn_kind({"type": "inode"}) == "inode"
    assert "inode" in config.VALID_VPN_TYPES


def test_inode_helpers():
    vpn = {"gateway": "vpn.ex.net", "port": 3000, "config": "/opt/iNode-VPN-Client",
           "trusted_cert": "AA:BB:CC"}
    assert config.inode_gateway(vpn) == "vpn.ex.net:3000"
    assert config.inode_gateway({"gateway": "h"}) == "h:443"
    assert config.inode_gateway({}) == ""
    assert config.inode_script(vpn) == "/opt/iNode-VPN-Client/svpn-connect.sh"
    assert config.inode_script({"config": "/x/svpn-connect.sh"}) == "/x/svpn-connect.sh"
    assert config.inode_extra_args(vpn) == ["--", "--pin-sha256", "AA:BB:CC"]
    assert config.inode_extra_args({"insecure": True}) == ["--", "--insecure"]
    assert config.inode_extra_args({}) == []


def test_inode_script_defaults_to_bundled(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_ROOT", str(tmp_path))
    assert config.inode_script({}) == str(
        tmp_path / "vendor" / "iNode-VPN-Client" / "svpn-connect.sh")


def test_inode_driver_classify():
    d = vpndrivers.get_driver({"type": "inode"})
    assert d.kind == "inode" and d.needs_creds({}) is True
    assert d.classify("tunnel up: ip=10.0.0.2 mask=255.255.255.0") == "up"
    assert d.classify("authentication failed: result=...") == "auth"
    assert d.classify("incorrect username or password ...") == "auth"
    assert d.classify("certificate pin mismatch: peer=x") == "cert"
    assert d.classify("[+] disconnecting...") == "down"
    assert d.classify("heartbeat: no response, going offline") == "down"
    assert d.classify("gateway forced log-off (type=4)") == "down"
    assert d.classify("TunnelClosed: tunnel socket closed") == "down"
    assert d.classify("just chatter") is None


def test_inode_build_cmd_no_password_on_argv():
    d = vpndrivers.get_driver({"type": "inode"})
    vpn = {"gateway": "g", "port": 3000, "config": "/c", "domain": "system",
           "trusted_cert": "AA:BB"}
    assert d.build_cmd(vpn, "user1") == [
        "/c/svpn-connect.sh", "g:3000", "user1", "system", "--", "--pin-sha256", "AA:BB"]
    assert d.resolve_binary(vpn) == "/c/svpn-connect.sh"


def test_inode_config_validation():
    good = ("vpn: {enabled: true, type: inode, gateway: g, vault_item: I, "
            "config: /opt/iNode, trusted_cert: 'AA:BB'}\n"
            "display: {cols: 1, rows: 1}\n"
            "panels:\n  - {id: a, grid: [0,0], mode: direct, url: 'http://x/'}\n")
    assert config.vpn_kind(config.load_str(good, "t").vpn) == "inode"
    bad = ("vpn: {enabled: true, type: inode}\n"
           "display: {cols: 1, rows: 1}\n"
           "panels:\n  - {id: a, grid: [0,0], mode: direct, url: 'http://x/'}\n")
    with pytest.raises(config.ConfigError) as e:
        config.load_str(bad, "t")
    msg = str(e.value)
    assert "gateway" in msg and "vault_item" in msg
    # config is now OPTIONAL (defaults to the bundled client) — valid without it
    nocfg = ("vpn: {enabled: true, type: inode, gateway: g, vault_item: I}\n"
             "display: {cols: 1, rows: 1}\n"
             "panels:\n  - {id: a, grid: [0,0], mode: direct, url: 'http://x/'}\n")
    assert config.vpn_kind(config.load_str(nocfg, "t").vpn) == "inode"


def test_inode_render_roundtrips():
    spec = importlib.util.spec_from_file_location(
        "s_render", os.path.join(_REPO, "setup.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    cfg = {
        "display": {"auto": True, "width": 1920, "height": 1080, "cols": 1,
                    "rows": 1, "gap": 0, "layout": "auto"},
        "panels": [{"id": "a", "engine": "webkit", "grid": [0, 0], "mode": "direct",
                    "url": "http://x/", "vault_item": "",
                    "selectors": {"user": "#u", "pass": "#p", "submit": "b"},
                    "login_marker": "#p", "keepalive": {"strategy": "none"}}],
        "tunnel": {"enabled": False},
        "vpn": {"enabled": True, "type": "inode", "gateway": "g", "port": 3000,
                "vault_item": "I", "config": "/opt/iNode", "domain": "system",
                "trusted_cert": "AA:BB", "insecure": False},
        "proxy": {"enabled": False},
    }
    c = config.load_str(m.render_panels_yaml(cfg), "render")
    assert config.vpn_kind(c.vpn) == "inode"
    assert c.vpn["gateway"] == "g" and c.vpn["vault_item"] == "I"
    assert c.vpn["config"] == "/opt/iNode" and c.vpn["domain"] == "system"
