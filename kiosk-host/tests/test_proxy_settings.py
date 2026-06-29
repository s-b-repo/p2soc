"""On-screen Proxy settings: form->dict + boot override merge (pure, no GTK)."""
from host import config, configwin


def test_proxy_form_to_dict_full():
    d = configwin.proxy_form_to_dict({
        "enabled": True, "url": " http://proxy:3128 ",
        "vault_item": " HQ Proxy ", "ignore_hosts": "intranet, *.lan ,  10.0.0.0/8"})
    assert d["enabled"] is True
    assert d["url"] == "http://proxy:3128"
    assert d["vault_item"] == "HQ Proxy"
    assert d["ignore_hosts"] == ["intranet", "*.lan", "10.0.0.0/8"]


def test_proxy_form_to_dict_minimal():
    d = configwin.proxy_form_to_dict({"enabled": False})
    assert d == {"enabled": False}                  # empty strings dropped


def test_proxy_form_to_dict_accepts_iterable_ignore_hosts():
    d = configwin.proxy_form_to_dict({"enabled": True, "url": "http://p:1",
                                      "ignore_hosts": ("a", "", "b")})
    assert d["ignore_hosts"] == ["a", "b"]


def test_apply_proxy_override_sets_fields():
    p = config.ProxyCfg(enabled=False, url="", vault_item="", ignore_hosts=())
    configwin.apply_proxy_override(p, {"_proxy": {
        "enabled": True, "url": "http://p:1", "vault_item": "L",
        "ignore_hosts": ["a", "b"]}})
    assert p.enabled is True and p.url == "http://p:1" and p.vault_item == "L"
    assert p.ignore_hosts == ("a", "b")


def test_apply_proxy_override_noop():
    p = config.ProxyCfg(enabled=True, url="http://x:1")
    configwin.apply_proxy_override(p, {})
    assert p.enabled is True and p.url == "http://x:1"


def test_apply_proxy_override_partial_keeps_others():
    p = config.ProxyCfg(enabled=True, url="http://x:1", vault_item="L",
                        ignore_hosts=("a",))
    configwin.apply_proxy_override(p, {"_proxy": {"enabled": False}})
    assert p.enabled is False
    # url/vault_item/ignore_hosts not in override -> unchanged
    assert p.url == "http://x:1" and p.vault_item == "L"
    assert p.ignore_hosts == ("a",)
