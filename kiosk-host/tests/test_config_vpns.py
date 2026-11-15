"""vpns:[] list schema — normalization, validation, conf API + to_yaml round-trip.

The CONFIG foundation for multi-VPN: a `vpns:[]` list, backward-compat from a
legacy `vpn:{}` single block, and the conf.vpns (list) + conf.vpn (primary)
API the runtime/GUI/CLI agents build against. No real VPN is brought up here —
pure parse/validate/serialise.
"""
import pytest
from host import config


_BASE = (
    "display: {cols: 2, rows: 1}\n"
    "panels:\n"
    "  - {id: a, grid: [0,0], mode: direct, url: \"http://x/\"}\n"
)


def _err(text):
    with pytest.raises(config.ConfigError) as e:
        config.load_str(_BASE + text, "t")
    return str(e.value)


# --- normalization -------------------------------------------------------- #
def test_legacy_vpn_dict_normalizes_to_one_entry():
    c = config.load_str(
        _BASE + "vpn: {enabled: true, type: fortinet, gateway: g.example, vault_item: L}\n", "t")
    assert len(c.vpns) == 1
    assert c.vpns[0]["type"] == "fortinet"
    assert c.vpns[0]["name"] == "vpn"          # stable default name back-filled
    # conf.vpn is the back-compat PRIMARY == vpns[0]
    assert c.vpn is c.vpns[0]


def test_vpns_list_mixed_types():
    c = config.load_str(_BASE + """vpns:
  - {name: corp, enabled: true, type: fortinet, gateway: g.example, vault_item: L, default_route: true}
  - {name: lab, enabled: true, type: wireguard, config: /etc/wireguard/lab.conf}
  - {name: h3c, enabled: false, type: inode, gateway: ssl.example, vault_item: H}
""", "t")
    assert [v["name"] for v in c.vpns] == ["corp", "lab", "h3c"]
    assert [v["type"] for v in c.vpns] == ["fortinet", "wireguard", "inode"]
    assert c.vpns[0]["default_route"] is True
    assert c.vpn["name"] == "corp"             # primary == first entry


def test_vpnless_config_stays_vpnless():
    c = config.load_str(_BASE, "t")
    assert c.vpns == []
    assert c.vpn == {}


def test_both_vpn_and_vpns_warns_and_uses_list():
    c = config.load_str(
        _BASE + "vpn: {enabled: false, type: fortinet}\n"
                "vpns:\n  - {name: a, enabled: false, type: fortinet}\n", "t")
    assert [v["name"] for v in c.vpns] == ["a"]
    assert any("both 'vpn:' and 'vpns:'" in w for w in c.warnings)


def test_unnamed_list_entries_get_stable_names():
    c = config.load_str(_BASE + """vpns:
  - {enabled: false, type: fortinet}
  - {enabled: false, type: fortinet}
""", "t")
    assert [v["name"] for v in c.vpns] == ["vpn", "vpn2"]


# --- validation: collect-everything --------------------------------------- #
def test_duplicate_names_rejected():
    msg = _err("""vpns:
  - {name: dup, enabled: false, type: fortinet}
  - {name: DUP, enabled: false, type: fortinet}
""")
    assert "duplicate VPN name" in msg and "'DUP'" in msg  # case-insensitive clash


def test_empty_name_is_backfilled_not_rejected():
    # a blank/absent name is treated like a legacy unnamed VPN: back-filled to a
    # stable default ("vpn") rather than erroring, so it keeps a usable identity.
    c = config.load_str(_BASE + "vpns:\n  - {name: \"\", enabled: false, type: fortinet}\n", "t")
    assert c.vpns[0]["name"] == "vpn"


def test_bad_name_charset_rejected():
    msg = _err("vpns:\n  - {name: \"bad name\", enabled: false, type: fortinet}\n")
    assert "letters/digits" in msg


def test_at_most_one_default_route():
    msg = _err("""vpns:
  - {name: a, enabled: true, type: fortinet, gateway: g.example, vault_item: L, default_route: true}
  - {name: b, enabled: true, type: fortinet, gateway: h.example, vault_item: M, default_route: true}
""")
    assert "at most one VPN may set 'default_route" in msg
    assert "a" in msg and "b" in msg


def test_cap_enforced():
    entries = "".join(
        f"  - {{name: v{i}, enabled: false, type: fortinet}}\n"
        for i in range(config.MAX_VPNS + 1))
    msg = _err("vpns:\n" + entries)
    assert f"at most {config.MAX_VPNS} VPNs" in msg


def test_per_entry_errors_collected_with_index_label():
    msg = _err("""vpns:
  - {name: corp, enabled: true, type: fortinet}
  - {name: lab, enabled: true, type: openvpn}
""")
    # both rows' problems surface, each pointing at its own labelled row
    assert "vpns[0] 'corp'" in msg
    assert "vpns[1] 'lab'" in msg


def test_default_route_must_be_bool():
    msg = _err("vpns:\n  - {name: a, enabled: false, type: fortinet, default_route: maybe}\n")
    assert "default_route: must be true or false" in msg


def test_vpns_not_a_list_rejected():
    msg = _err("vpns: not-a-list\n")
    assert "vpns: must be a list" in msg


# --- to_yaml round-trip --------------------------------------------------- #
def test_legacy_single_emits_vpn_block_bytestable():
    src = (
        "display: {auto: true, width: 1920, height: 1080, cols: 2, rows: 1, gap: 0, layout: auto}\n"
        "panels:\n  - {id: a, grid: [0,0], mode: direct, url: \"http://x/\"}\n"
        "vpn: {enabled: true, type: fortinet, gateway: g.example, vault_item: L}\n")
    c1 = config.load_str(src, "t")
    y1 = config.to_yaml(c1)
    assert "vpn:" in y1 and "vpns:" not in y1
    assert "name:" not in y1.split("vpn:", 1)[1]   # default name not leaked
    # stable across re-parse + re-emit
    y2 = config.to_yaml(config.load_str(y1, "t"))
    assert y1 == y2


def test_multi_emits_vpns_list_and_round_trips():
    src = _BASE + """vpns:
  - {name: corp, enabled: true, type: fortinet, gateway: g.example, vault_item: L, default_route: true}
  - {name: lab, enabled: true, type: wireguard, config: /etc/wireguard/lab.conf}
"""
    c1 = config.load_str(src, "t")
    y1 = config.to_yaml(c1)
    assert "vpns:" in y1
    c2 = config.load_str(y1, "t")
    assert [v["name"] for v in c2.vpns] == ["corp", "lab"]
    assert [v["name"] for v in c2.vpns if v.get("default_route")] == ["corp"]
    assert config.to_yaml(c2) == y1               # byte-stable


def test_named_single_emits_list_form():
    # a single VPN with a non-default name/owner must NOT collapse to vpn:{}
    src = _BASE + "vpns:\n  - {name: corp, enabled: false, type: fortinet, default_route: true}\n"
    y = config.to_yaml(config.load_str(src, "t"))
    assert "vpns:" in y and "name: corp" in y
