"""VpnManager runtime invariants — routing policy + lifecycle keying.

These exercise the manager's PURE decision logic (which entries it prepares,
which one owns the default route, how non-owners are coerced split-tunnel, the
aggregate state) WITHOUT spawning any real VPN process. The full threaded
start/stop + reconnect + wg-guard behaviour is covered behaviourally with fake
backends in dev/verify-vpn.sh (`make verify-vpn`); here we assert the
deterministic policy that protects routing.
"""
import os
import tempfile

import pytest

from host import vpnmanager, vpnstatus


def _mgr(vpns):
    logs = []
    m = vpnmanager.VpnManager(vpns, "/x/pin.sh", log=logs.append)
    return m, logs


def _entries(m):
    return {name: e for name, e, owner in m._entries}


def _owners(m):
    return {name: owner for name, e, owner in m._entries}


# --- which entries are prepared ------------------------------------------- #
def test_only_enabled_entries_prepared_and_named():
    m, _ = _mgr([
        {"name": "corp", "enabled": True, "type": "fortinet",
         "gateway": "g", "vault_item": "L"},
        {"name": "off", "enabled": False, "type": "fortinet",
         "gateway": "g", "vault_item": "L"},
        {"name": "lab", "enabled": True, "type": "openvpn", "config": "/x.ovpn"},
    ])
    assert m.count == 2
    assert set(m.names) == {"corp", "lab"}


def test_unnamed_entries_get_stable_fallback_names():
    # a hand-built list that skipped _normalize_vpns still keys cleanly
    m, _ = _mgr([
        {"enabled": True, "type": "openvpn", "config": "/a.ovpn"},
        {"enabled": True, "type": "openvpn", "config": "/b.ovpn"},
    ])
    assert m.names == ["vpn", "vpn2"]


# --- routing: single VPN implicitly owns its route (back-compat) ----------- #
def test_single_vpn_keeps_full_tunnel_and_is_implicit_owner():
    m, logs = _mgr([
        {"name": "vpn", "enabled": True, "type": "fortinet",
         "gateway": "g", "vault_item": "L",
         "set_routes": True, "half_internet_routes": True},
    ])
    ent, own = _entries(m), _owners(m)
    # full-tunnel config preserved exactly — NOT coerced split-tunnel
    assert ent["vpn"].get("set_routes") is True
    assert ent["vpn"].get("half_internet_routes") is True
    assert own["vpn"] is True
    # and the single-VPN journal stays quiet about routing
    assert not [l for l in logs if "routing" in l]


# --- routing: explicit owner keeps full-tunnel, non-owners coerced --------- #
def test_explicit_owner_keeps_route_others_split_tunnel():
    m, logs = _mgr([
        {"name": "corp", "enabled": True, "type": "fortinet", "gateway": "g",
         "vault_item": "L", "default_route": True, "set_routes": True,
         "half_internet_routes": True},
        {"name": "lab", "enabled": True, "type": "openvpn", "config": "/x.ovpn",
         "set_routes": True},
        {"name": "dmz", "enabled": True, "type": "fortinet", "gateway": "g2",
         "vault_item": "L2", "set_routes": True, "half_internet_routes": True},
    ])
    ent, own = _entries(m), _owners(m)
    assert own == {"corp": True, "lab": False, "dmz": False}
    # owner untouched
    assert ent["corp"].get("set_routes") is True
    assert ent["corp"].get("half_internet_routes") is True
    # non-owner openvpn -> --route-nopull
    assert ent["lab"].get("set_routes") is False
    # non-owner fortinet -> --set-routes=0 + no half-internet
    assert ent["dmz"].get("set_routes") is False
    assert ent["dmz"].get("half_internet_routes") is False
    assert any("routing: 'corp' owns the default route" in l for l in logs)


def test_two_default_route_claims_grant_none():
    """Two owners must NEVER both grab 0.0.0.0/0 — the manager refuses all."""
    m, logs = _mgr([
        {"name": "a", "enabled": True, "type": "openvpn", "config": "/a.ovpn",
         "default_route": True, "set_routes": True},
        {"name": "b", "enabled": True, "type": "openvpn", "config": "/b.ovpn",
         "default_route": True, "set_routes": True},
    ])
    ent, own = _entries(m), _owners(m)
    assert own == {"a": False, "b": False}
    assert ent["a"].get("set_routes") is False
    assert ent["b"].get("set_routes") is False
    assert any("multiple VPNs claim default_route" in l for l in logs)


def test_no_owner_multi_is_all_split_tunnel():
    m, logs = _mgr([
        {"name": "a", "enabled": True, "type": "openvpn", "config": "/a.ovpn",
         "set_routes": True},
        {"name": "b", "enabled": True, "type": "fortinet", "gateway": "g",
         "vault_item": "L", "set_routes": True},
    ])
    own = _owners(m)
    assert own == {"a": False, "b": False}
    assert _entries(m)["a"].get("set_routes") is False
    assert _entries(m)["b"].get("set_routes") is False
    assert any("split-tunnel — no default-route owner" in l for l in logs)


def test_non_owner_wireguard_flagged_split_tunnel():
    m, logs = _mgr([
        {"name": "owner", "enabled": True, "type": "fortinet", "gateway": "g",
         "vault_item": "L", "default_route": True},
        {"name": "wg", "enabled": True, "type": "wireguard", "config": "wg0"},
    ])
    ent = _entries(m)
    assert ent["wg"].get("_soc_split_tunnel") is True
    assert any("MUST scope AllowedIPs" in l for l in logs)


def test_owner_wireguard_not_flagged():
    m, _ = _mgr([
        {"name": "wg", "enabled": True, "type": "wireguard", "config": "wg0",
         "default_route": True},
    ])
    assert _entries(m)["wg"].get("_soc_split_tunnel") is None


# --- manager never mutates the caller's list ------------------------------- #
def test_prepare_does_not_mutate_caller_entries():
    src = [
        {"name": "corp", "enabled": True, "type": "fortinet", "gateway": "g",
         "vault_item": "L", "default_route": True, "set_routes": True},
        {"name": "lab", "enabled": True, "type": "openvpn", "config": "/x.ovpn",
         "set_routes": True},
    ]
    vpnmanager.VpnManager(src, "/x/pin.sh", log=lambda m: None)
    # the non-owner's set_routes in the SOURCE must be untouched (deep copy)
    assert src[1]["set_routes"] is True


# --- aggregate state ------------------------------------------------------- #
def test_aggregate_state():
    on, off, nc = (vpnstatus.STATE_ONLINE, vpnstatus.STATE_OFFLINE,
                   vpnstatus.STATE_NOT_CONFIGURED)
    assert vpnmanager.aggregate_state({}) == nc
    assert vpnmanager.aggregate_state({"a": nc, "b": nc}) == nc
    assert vpnmanager.aggregate_state({"a": on, "b": on}) == on
    assert vpnmanager.aggregate_state({"a": on, "b": off}) == off
    # a not_configured entry is ignored in the aggregate
    assert vpnmanager.aggregate_state({"a": on, "b": nc}) == on


# --- wg catch-all guard (the materialize hook) ----------------------------- #
def test_guarded_supervisor_strips_catchall_allowedips(tmp_path, monkeypatch):
    """A non-owner wg .conf carrying 0.0.0.0/0 is scrubbed at materialize so it
    cannot hijack the default route; a scoped subnet is kept."""
    runtime = tmp_path / "run"
    runtime.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    conf = ("[Interface]\nPrivateKey = K==\nAddress = 10.9.0.2/32\n"
            "[Peer]\nAllowedIPs = 0.0.0.0/0, 10.50.0.0/16\n")

    entry = {"name": "wg", "type": "wireguard", "config": "wgx",
             "config_from_vault": True, "vault_item": "WG",
             "_soc_split_tunnel": True}
    sup = vpnmanager._GuardedSupervisor(entry, "/x/pin.sh", log=lambda m: None)

    # stub the vault Notes fetch the real _materialize_config performs
    class _FakeVault:
        def notes(self, item):
            return conf
    monkeypatch.setattr(sup, "_open_vault", lambda: _FakeVault())

    assert sup._materialize_config() is True
    materialized = open(sup._materialized, encoding="utf-8").read()
    assert "0.0.0.0/0" not in materialized
    assert "10.50.0.0/16" in materialized
    sup._cleanup_materialized()


def test_guarded_supervisor_owner_keeps_catchall(tmp_path, monkeypatch):
    """An OWNER wg entry (no _soc_split_tunnel flag) keeps its .conf verbatim."""
    runtime = tmp_path / "run"
    runtime.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    conf = ("[Interface]\nPrivateKey = K==\nAddress = 10.9.0.2/32\n"
            "[Peer]\nAllowedIPs = 0.0.0.0/0\n")
    entry = {"name": "wg", "type": "wireguard", "config": "wgx",
             "config_from_vault": True, "vault_item": "WG"}
    sup = vpnmanager._GuardedSupervisor(entry, "/x/pin.sh", log=lambda m: None)

    class _FakeVault:
        def notes(self, item):
            return conf
    monkeypatch.setattr(sup, "_open_vault", lambda: _FakeVault())

    assert sup._materialize_config() is True
    materialized = open(sup._materialized, encoding="utf-8").read()
    assert "0.0.0.0/0" in materialized
    sup._cleanup_materialized()
