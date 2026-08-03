"""On-screen Tunnel settings: form->dict + boot override merge (pure, no GTK)."""
from host import configwin


def test_tunnel_form_to_dict_full():
    d = configwin.tunnel_form_to_dict({
        "enabled": True, "jump_host": "ops@jump.lan",
        "identity": "/home/wall/.ssh/id_ed25519",
        "known_hosts": "/etc/soc-display/known_hosts",
        "host_key_checking": "accept-new",
        "extra_forwards": "127.0.0.1:5000:db:5432\n127.0.0.1:6000:cache:6379\n"})
    assert d["enabled"] is True
    assert d["jump_host"] == "ops@jump.lan"
    assert d["identity"] == "/home/wall/.ssh/id_ed25519"
    assert d["known_hosts"] == "/etc/soc-display/known_hosts"
    assert d["host_key_checking"] == "accept-new"
    assert d["extra_forwards"] == [
        "127.0.0.1:5000:db:5432", "127.0.0.1:6000:cache:6379"]


def test_tunnel_form_to_dict_minimal():
    # only the enabled flag — empty strings + blank multiline are dropped
    d = configwin.tunnel_form_to_dict({"enabled": False,
                                       "extra_forwards": "\n   \n"})
    assert d == {"enabled": False}


def test_tunnel_form_to_dict_rejects_bad_host_key_value():
    # an invalid host_key_checking value is dropped, not echoed back — the
    # autossh wrapper would refuse it on the next start.
    d = configwin.tunnel_form_to_dict({"enabled": True,
                                       "host_key_checking": "MAYBE"})
    assert "host_key_checking" not in d


def test_apply_tunnel_override_merges_preserving_advanced():
    t = {"enabled": True, "jump_host": "old@host",
         "extra_forwards": ["127.0.0.1:9999:hidden:9999"]}
    configwin.apply_tunnel_override(t, {"_tunnel": {
        "jump_host": "new@host", "identity": "/k"}})
    assert t["jump_host"] == "new@host" and t["identity"] == "/k"
    # advanced field (not on the form) survives the merge
    assert t["extra_forwards"] == ["127.0.0.1:9999:hidden:9999"]


def test_apply_tunnel_override_noop():
    t = {"jump_host": "x"}
    configwin.apply_tunnel_override(t, {})
    assert t == {"jump_host": "x"}
