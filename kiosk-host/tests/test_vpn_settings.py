"""On-screen VPN settings: form->dict + boot override merge (pure, no GTK)."""
import pytest

pytest.importorskip("gi")  # configwin imports gi at module scope — skip where PyGObject is absent (CI)
from host import configwin


def test_vpn_form_to_dict_full():
    d = configwin.vpn_form_to_dict({
        "enabled": True, "type": "inode", "gateway": "g", "port": 3000,
        "vault_item": "I", "config": "/c", "domain": "system", "realm": "",
        "trusted_cert": "AA:BB", "ready_probe": "10.0.0.5:443",
        "insecure": False, "config_from_vault": False, "health_check_interval": 60})
    assert d["enabled"] is True and d["type"] == "inode"
    assert d["gateway"] == "g" and d["port"] == 3000 and d["vault_item"] == "I"
    assert d["config"] == "/c" and d["domain"] == "system"
    assert d["trusted_cert"] == "AA:BB" and d["ready_probe"] == "10.0.0.5:443"
    assert d["health_check_interval"] == 60
    assert "realm" not in d and "insecure" not in d   # empty / false dropped


def test_vpn_form_to_dict_minimal():
    d = configwin.vpn_form_to_dict({"enabled": False, "type": "fortinet", "port": 0})
    assert d == {"enabled": False, "type": "fortinet"}


def test_vpn_form_flags():
    assert configwin.vpn_form_to_dict({"type": "inode", "insecure": True})["insecure"] is True
    assert configwin.vpn_form_to_dict(
        {"type": "openvpn", "config_from_vault": True})["config_from_vault"] is True


def test_apply_vpn_override_merges():
    vpn = {"enabled": True, "type": "fortinet", "gateway": "old", "set_routes": True}
    configwin.apply_vpn_override(
        vpn, {"_vpn": {"type": "inode", "gateway": "new", "config": "/c"}})
    assert vpn["type"] == "inode" and vpn["gateway"] == "new" and vpn["config"] == "/c"
    assert vpn["set_routes"] is True            # advanced field preserved (merge)


def test_apply_vpn_override_noop():
    vpn = {"type": "fortinet"}
    configwin.apply_vpn_override(vpn, {})
    assert vpn == {"type": "fortinet"}
