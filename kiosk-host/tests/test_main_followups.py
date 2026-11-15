"""Regression tests for two host fixes: the lock screen must not leave Settings
usable above it, and the boot merge must not leave conf.vpn stale."""
from __future__ import annotations

from host import config as cfg
from host import main as hostmain


def _conf(vpns, vpn):
    conf = cfg.load_str("display: {auto: false, cols: 1, rows: 1}\npanels: []\n",
                        "test")
    conf.vpns, conf.vpn = vpns, vpn
    return conf


class _Win:
    def __init__(self, fail=False):
        self.destroyed = 0
        self.fail = fail

    def destroy(self):
        self.destroyed += 1
        if self.fail:
            raise RuntimeError("gone already")


class _Locker:
    def __init__(self, order):
        self.order = order

    def lock(self, on_unlock=None):
        self.order.append("locked")


def _host(win):
    host = hostmain.KioskHost.__new__(hostmain.KioskHost)
    order = []
    host._locker = _Locker(order)
    host._config_win = win
    return host, order


def test_lock_closes_settings_first():
    order = []
    win = _Win()
    win.destroy = lambda: order.append("settings destroyed")
    host, _ = _host(win)
    host._locker = _Locker(order)
    host._lock_wall()
    assert order == ["settings destroyed", "locked"]
    assert host._config_win is None


def test_lock_without_settings_open_still_locks():
    host, order = _host(None)
    host._lock_wall()
    assert order == ["locked"]


def test_settings_that_will_not_close_cannot_stop_the_lock():
    win = _Win(fail=True)
    host, order = _host(win)
    host._lock_wall()
    assert win.destroyed == 1 and order == ["locked"]


def test_boot_merge_refreshes_vpn_when_first_vpn_is_removed():
    a, b = {"name": "a", "enabled": True}, {"name": "b", "enabled": True}
    conf = _conf([a, b], a)
    hostmain._merge_vpn_overrides(conf, {"_vpns": [{"name": "b"}],
                                         "_vpns_removed": ["a"]})
    assert [v["name"] for v in conf.vpns] == ["b"]
    assert conf.vpn is conf.vpns[0]


def test_boot_merge_empties_vpn_when_every_vpn_is_removed():
    a = {"name": "a", "enabled": True}
    conf = _conf([a], a)
    hostmain._merge_vpn_overrides(conf, {"_vpns": [], "_vpns_removed": ["a"]})
    assert conf.vpns == [] and conf.vpn == {}


def test_boot_merge_adopts_a_vpn_added_at_the_glass():
    conf = _conf([], {})
    hostmain._merge_vpn_overrides(conf, {"_vpns": [{"name": "new"}]})
    assert conf.vpn is conf.vpns[0]
    assert conf.vpn.get("name") == "new"


def test_legacy_single_vpn_override_still_merges_in_place():
    v = {"name": "a", "gateway": "old"}
    conf = _conf([v], v)
    hostmain._merge_vpn_overrides(conf, {"_vpn": {"gateway": "new"}})
    assert conf.vpn is v
    assert v["gateway"] == "new"
