"""config.load_str / to_yaml / allow_media — vault-note config + serialization."""
import pytest
from host import config


_CFG = """
display: {cols: 2, rows: 1}
panels:
  - {id: a, grid: [0, 0], mode: direct, url: "http://x/", allow_media: true}
  - {id: b, grid: [1, 0], mode: direct, url: "http://y/"}
"""


def test_default_vault_backend_constant():
    # The default backend name is shared from config so the ~9 call-sites that
    # re-derive it from the env (main/vault/fortivpn/configwin) cannot drift.
    # It must also be a vault-capable backend, or the default install would skip
    # config-from-vault and the OTP/session flows.
    assert config.DEFAULT_VAULT_BACKEND == "litebw"
    assert config.DEFAULT_VAULT_BACKEND in ("rbw", "litebw", "native")


def test_load_str_parses():
    c = config.load_str(_CFG, "vault:test")
    assert [p.id for p in c.panels] == ["a", "b"]


def test_load_str_rejects_bad_yaml():
    with pytest.raises(config.ConfigError):
        config.load_str("display: [not a map]\npanels: 5", "vault:bad")


def test_load_str_matches_load(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text(_CFG)
    a = config.load(str(f))
    b = config.load_str(_CFG, "vault:test")
    assert [p.id for p in a.panels] == [p.id for p in b.panels]


def test_allow_media_default_and_parse():
    c = config.load_str(_CFG, "t")
    assert c.panels[0].allow_media is True       # explicit
    assert c.panels[1].allow_media is False      # default off (saves RAM/GPU)


def test_allow_media_rejects_non_bool():
    bad = ('display: {cols: 1, rows: 1}\npanels:\n'
           '  - {id: m, grid: [0,0], mode: direct, url: "http://x/", allow_media: "yes"}\n')
    with pytest.raises(config.ConfigError):
        config.load_str(bad, "t")


def test_to_yaml_roundtrips():
    a = config.load_str(_CFG, "t")
    b = config.load_str(config.to_yaml(a), "roundtrip")
    assert [p.id for p in a.panels] == [p.id for p in b.panels]
    assert [p.effective_url for p in a.panels] == [p.effective_url for p in b.panels]
    assert [p.allow_media for p in a.panels] == [p.allow_media for p in b.panels]


def test_to_yaml_preserves_tunnel_and_vault_item():
    cfg_txt = (
        'display: {cols: 2, rows: 1}\n'
        'panels:\n'
        '  - {id: t, grid: [0,0], mode: tunnel, '
        'tunnel: {local_port: 19101, remote_host: 10.0.0.5, remote_port: 443}, '
        'vault_item: "Item T", selectors: {user: "#u", pass: "#p"}}\n'
        '  - {id: d, grid: [1,0], mode: direct, url: "http://x/"}\n'
        'tunnel: {enabled: true, jump_host: "u@jump", identity: "/k"}\n')
    a = config.load_str(cfg_txt, "t")
    b = config.load_str(config.to_yaml(a), "roundtrip")
    bt = {p.id: p for p in b.panels}
    assert bt["t"].mode == "tunnel"
    assert bt["t"].tunnel["local_port"] == 19101
    assert bt["t"].vault_item == "Item T"
    assert b.tunnel.get("jump_host") == "u@jump"
