"""Regression tests for the three-way configwin merge (HEAD + v1.3.0 + pi2soc).

Beyond the pure helpers, these drive a REAL ConfigWindow: real entries, real
clicked buttons, the real overrides file. The window is built but never shown, so
nothing appears on a developer's screen; the modal prompts are the one thing
stubbed, because they need a human.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time

import pytest

pytest.importorskip("gi")

import gi  # noqa: E402

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

from host import config as cfg  # noqa: E402
from host import locker, ospass, totp  # noqa: E402

GOOD_PIN = "8642"
ALL_ENV = ("SOC_CONFIG_REQUIRE_PIN", "SOC_ONSCREEN_CONFIG", "SOC_OPERATOR_USER",
           "SOC_SECRET_DIR", "SOC_VAULT_EMAIL")

needs_display = pytest.mark.skipif(not Gtk.init_check()[0], reason="no display")


@pytest.fixture
def cw(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("SOC_SECRET_DIR", str(tmp_path / "secrets"))
    for name in ALL_ENV[:3]:
        monkeypatch.delenv(name, raising=False)
    from host import configwin
    configwin._gate_throttle.passed()
    configwin._os_throttle.passed()
    yield configwin
    configwin._gate_throttle.passed()
    configwin._os_throttle.passed()


def _panel(pid="p1", grid=(0, 0), **kw):
    kw.setdefault("url", "http://a.test/")
    return cfg.Panel(id=pid, engine="webkit", grid=grid, mode="direct",
                     vault_item=kw.pop("vault_item", ""), selectors={},
                     login_marker="", keepalive=cfg.KeepAlive(), **kw)


class _Vault:
    """Records calls. `hang` makes the vault-side calls block until released."""

    def __init__(self, hang=None):
        self.hang = hang
        self.threads = []
        self.deleted = []
        self.read = []

    def _call(self):
        self.threads.append(threading.current_thread())
        if self.hang is not None:
            self.hang.wait(10)

    def list_by_folder(self, _folder):
        self._call()
        return ["SOC Settings TOTP"]

    def delete(self, name):
        self._call()
        self.deleted.append(name)
        return True

    def creds(self, name):
        self._call()
        self.read.append(name)
        return {"user": "u", "pass": "p"}


def _window(cw, **kw):
    applied = []
    kw.setdefault("display", cfg.DisplayCfg())
    kw.setdefault("vpns", [{"name": "hq", "enabled": True, "type": "inode",
                            "gateway": "gw.test", "vault_item": "vpn-hq",
                            "insecure": True, "set_routes": True}])
    kw.setdefault("proxy", cfg.ProxyCfg(enabled=True, url="http://old:3128",
                                        vault_item="pxy", ignore_hosts=("a",)))
    kw.setdefault("tunnel", {"enabled": True, "jump_host": "ops@jump",
                             "identity": "/k"})
    panels = kw.pop("panels", None) or [_panel(), _panel("p2", (1, 0))]
    win = cw.ConfigWindow(panels, lambda c: applied.append(c), **kw)
    win.applied = applied
    return win


def _unlock(win):
    win._pin_entry.set_text(GOOD_PIN)
    win._try_unlock()
    assert win._unlocked


def _reauth(win, result):
    """Stub the modal prompt; everything around it stays real."""
    calls = []

    def fake(what="this action"):
        calls.append(what)
        return result
    win._require_reauth = fake
    return calls


def _notebook(win):
    found = []

    def walk(w):
        if isinstance(w, Gtk.Notebook):
            found.append(w)
        elif isinstance(w, Gtk.Container):
            w.forall(walk)
    walk(win)
    return found[0]


def _tab(win, title):
    nb = _notebook(win)
    for i in range(nb.get_n_pages()):
        page = nb.get_nth_page(i)
        if nb.get_tab_label_text(page) == title:
            nb.set_current_page(i)
            return page
    raise AssertionError(f"no tab {title!r}")


def _buttons(root, label):
    found = []

    def walk(w):
        if isinstance(w, Gtk.Button) and w.get_label() == label:
            found.append(w)
        elif isinstance(w, Gtk.Container):
            w.forall(walk)
    walk(root)
    return found


def _apply_button(win):
    return _buttons(win._form_page, "Apply")[0]


def _pump(until, timeout=3.0):
    """Run the main loop until `until()`; worker results arrive through idle_add."""
    ctx = GLib.MainContext.default()
    end = time.monotonic() + timeout
    while not until() and time.monotonic() < end:
        while ctx.pending():
            ctx.iteration(False)
        time.sleep(0.005)
    return until()


class _Busy:
    """Stands in for the modal busy dialog. run() spins a real nested GLib loop,
    which is what Gtk.Dialog.run does, without putting a window on screen."""

    def __init__(self):
        self.loop = GLib.MainLoop()
        self.rc = None

    def run(self):
        self.loop.run()
        return self.rc

    def response(self, rc):
        self.rc = rc
        self.loop.quit()

    def destroy(self):
        pass


# --- the split_tunnel bug ---------------------------------------------------- #

def test_split_tunnel_false_is_kept(cw):
    assert cw.vpn_form_to_dict({"split_tunnel": False})["split_tunnel"] is False
    assert cw.vpn_form_to_dict({"split_tunnel": True})["split_tunnel"] is True
    assert "split_tunnel" not in cw.vpn_form_to_dict({})


def test_split_tunnel_off_reaches_the_inode_argv(cw):
    # Why the False matters: the driver treats an absent key as ON.
    vpn = {"type": "inode", "split_tunnel": True}
    assert "--split-tunnel" in cfg.inode_extra_args(vpn)
    saved = cw.vpn_form_to_dict({"type": "inode", "split_tunnel": False})
    cw.apply_vpn_override(vpn, {"_vpn": saved})
    assert "--split-tunnel" not in cfg.inode_extra_args(vpn)


@needs_display
def test_split_tunnel_checkbox_turns_off_end_to_end(cw):
    win = _window(cw)
    _tab(win, "VPN")
    win._vpn_ws[0]["split_tunnel"].set_active(False)
    _apply_button(win).clicked()
    assert cw.load_overrides()["_vpns"][0]["split_tunnel"] is False
    assert win.applied[0]["_vpns"][0]["split_tunnel"] is False


# --- a cleared field must stay cleared --------------------------------------- #

@needs_display
def test_unticked_flag_and_blanked_field_survive_a_restart(cw):
    loaded = {"name": "hq", "enabled": True, "type": "inode", "gateway": "gw.test",
              "vault_item": "v", "insecure": True, "realm": "corp",
              "set_routes": True}
    win = _window(cw, vpns=[dict(loaded)])
    _tab(win, "VPN")
    win._vpn_ws[0]["insecure"].set_active(False)
    win._vpn_ws[0]["realm"].set_text("")
    _apply_button(win).clicked()

    boot = [dict(loaded)]
    cw.apply_vpns_override(boot, cw.load_overrides())
    assert boot[0]["insecure"] is False         # TLS verification really came back
    assert "realm" not in boot[0]
    assert boot[0]["set_routes"] is True        # advanced field not on the form


@needs_display
def test_renamed_vpn_keeps_its_advanced_fields_after_a_restart(cw):
    loaded = {"name": "hq", "enabled": True, "type": "inode", "gateway": "gw.test",
              "vault_item": "v", "set_routes": True}
    win = _window(cw, vpns=[dict(loaded)])
    _tab(win, "VPN")
    win._vpn_ws[0]["name"].set_text("hq2")
    _apply_button(win).clicked()

    boot = [dict(loaded)]
    cw.apply_vpns_override(boot, cw.load_overrides())
    assert [v["name"] for v in boot] == ["hq2"]
    assert boot[0]["set_routes"] is True


@needs_display
def test_blanked_proxy_url_does_not_come_back(cw):
    win = _window(cw)
    _tab(win, "Proxy")
    win._proxy_w["enabled"].set_active(False)
    win._proxy_w["url"].set_text("")
    win._proxy_w["ignore_hosts"].set_text("")
    _apply_button(win).clicked()
    p = cfg.ProxyCfg(enabled=True, url="http://old:3128", ignore_hosts=("a",))
    cw.apply_proxy_override(p, cw.load_overrides())
    assert (p.enabled, p.url, p.ignore_hosts) == (False, "", ())


# --- multi-VPN boot merge ---------------------------------------------------- #

def test_apply_vpns_override_merges_by_name_and_appends(cw):
    vpns = [{"name": "hq", "gateway": "old", "set_routes": True}]
    out = cw.apply_vpns_override(vpns, {"_vpns": [
        {"name": "hq", "gateway": "new"}, {"name": "dr", "gateway": "dr.test"}]})
    assert out is vpns
    assert vpns[0] == {"name": "hq", "gateway": "new", "set_routes": True}
    assert vpns[1] == {"name": "dr", "gateway": "dr.test"}


def test_apply_vpns_override_noop_and_garbage(cw):
    vpns = [{"name": "hq"}]
    assert cw.apply_vpns_override(vpns, {}) == [{"name": "hq"}]
    assert cw.apply_vpns_override(vpns, {"_vpns": "x"}) == [{"name": "hq"}]
    assert cw.apply_vpns_override(vpns, {"_vpns": ["x"]}) == [{"name": "hq"}]


@needs_display
def test_vpn_removed_at_the_glass_stays_removed_after_boot(cw):
    cw.set_pin(GOOD_PIN)
    win = _window(cw, vpns=[{"name": "hq", "enabled": False},
                            {"name": "dr", "enabled": False}])
    _unlock(win)
    _reauth(win, True)
    win._ask = lambda *_: True
    page = _tab(win, "VPN")
    _buttons(page, "Remove this VPN")[1].clicked()
    _apply_button(win).clicked()
    boot = [{"name": "hq"}, {"name": "dr"}]         # the source config still has dr
    cw.apply_vpns_override(boot, cw.load_overrides())
    assert [v["name"] for v in boot] == ["hq"]


@needs_display
def test_remove_vpn_needs_reauth_and_a_failure_changes_nothing(cw):
    cw.set_pin(GOOD_PIN)
    stopped = []
    win = _window(cw, actions={"stop_vpn_unit": stopped.append})
    _unlock(win)
    prompts = _reauth(win, False)
    win._ask = lambda *_: pytest.fail("must re-auth before asking")
    _buttons(_tab(win, "VPN"), "Remove this VPN")[0].clicked()
    assert len(prompts) == 1
    assert win._vpns[0] is not None and win._vpn_ws[0] is not None
    assert win._vpn_dirty is False and stopped == []


@needs_display
def test_remove_vpn_stops_its_supervisor_off_the_main_thread(cw):
    cw.set_pin(GOOD_PIN)
    stopped = []
    win = _window(cw, actions={"stop_vpn_unit": lambda n: stopped.append(
        (n, threading.current_thread()))})
    _unlock(win)
    _reauth(win, True)
    win._ask = lambda *_: True
    _buttons(_tab(win, "VPN"), "Remove this VPN")[0].clicked()
    assert _pump(lambda: stopped)
    assert stopped[0][0] == "hq"
    assert stopped[0][1] is not threading.main_thread()


@needs_display
def test_add_vpn_is_capped_and_names_stay_unique(cw):
    win = _window(cw, vpns=[{"name": f"vpn-{i}", "enabled": False}
                            for i in range(2, cfg.MAX_VPNS + 1)])
    page = _tab(win, "VPN")
    add = _buttons(page, "+ Add VPN")[0]
    add.clicked()
    assert len([v for v in win._vpns if v]) == cfg.MAX_VPNS
    names = [v["name"] for v in win._vpns]
    assert len(set(names)) == len(names)
    add.clicked()
    assert len([v for v in win._vpns if v]) == cfg.MAX_VPNS


# --- panel overrides --------------------------------------------------------- #

def test_valid_url_is_the_shared_implementation(cw):
    assert not hasattr(cw, "ALLOWED_URL_SCHEMES")
    # the old startswith check accepted both of these
    assert cw.valid_url("http://user:pass@host/") is False
    assert cw.valid_url("http://") is False
    assert cw.valid_url("") is True


def test_tenant_and_login_zones_overrides(cw):
    p = _panel()
    zones = {"user": {"x_pct": 0.5, "y_pct": 0.25}}
    cw.apply_overrides_to_panels([p], {"p1": {"tenant": " acme ", "login_zones": zones}})
    assert p.tenant == "acme"
    assert p.login_zones == zones
    assert p.login_zones is not zones


@pytest.mark.parametrize("zones", [
    {"user": {"x_pct": 2, "y_pct": 0}},
    {"nope": {"x_pct": 0, "y_pct": 0}},
    "x"])
def test_invalid_login_zones_are_ignored(cw, zones):
    p = _panel()
    p.login_zones = {"pass": {"x_pct": 0.1, "y_pct": 0.1}}
    cw.apply_overrides_to_panels([p], {"p1": {"login_zones": zones}})
    assert p.login_zones == {"pass": {"x_pct": 0.1, "y_pct": 0.1}}


def test_empty_login_zones_override_clears_zones_from_the_source_config(cw):
    p = _panel()
    p.login_zones = {"pass": {"x_pct": 0.1, "y_pct": 0.1}}
    cw.apply_overrides_to_panels([p], {"p1": {"login_zones": {}}})
    assert p.login_zones == {}


@pytest.mark.parametrize("tenant", ["a\nb", "x" * (cfg.MAX_TENANT_LEN + 1), 7])
def test_invalid_tenant_is_ignored(cw, tenant):
    p = _panel()
    p.tenant = "kept"
    cw.apply_overrides_to_panels([p], {"p1": {"tenant": tenant}})
    assert p.tenant == "kept"


def test_keepalive_override_matches_what_the_loader_accepts(cw):
    # A value the loader rejects would stop the wall booting once written back
    # to the vault note.
    p = _panel()
    cw.apply_overrides_to_panels([p], {"p1": {"keepalive": {
        "strategy": "mouse", "intervalSec": 0}}})
    assert p.keepalive.strategy == "none"
    assert p.keepalive.intervalSec == 600
    cw.apply_overrides_to_panels([p], {"p1": {"keepalive": {
        "strategy": "reload", "intervalSec": 90}}})
    assert (p.keepalive.strategy, p.keepalive.intervalSec) == ("reload", 90)


def test_per_panel_flags_only_accept_booleans(cw):
    p = _panel()
    cw.apply_overrides_to_panels([p], {"p1": {
        "allow_insecure": True, "allow_media": True, "proxy": False}})
    assert p.allow_insecure is True and p.allow_media is True and p.proxy is False
    cw.apply_overrides_to_panels([p], {"p1": {"allow_insecure": "no"}})
    assert p.allow_insecure is True


def test_display_override_covers_fullscreen_and_refuses_bools_as_ints(cw):
    d = cfg.DisplayCfg()
    cw.apply_display_override(d, {"_display": {
        "fullscreen": False, "cols": True, "gap": True, "width": True}})
    assert d.fullscreen is False
    assert d.cols == 2 and d.gap == 0 and d.width == 1920


def test_tunnel_form_cannot_turn_host_key_checking_off(cw):
    # SEC-6: pi2soc offered 'no'; this tree's loader refuses it.
    assert "host_key_checking" not in cw.tunnel_form_to_dict(
        {"host_key_checking": "no"})


# --- added / removed panels -------------------------------------------------- #

def test_panels_added_and_removed_at_the_glass_survive_a_restart(cw):
    panels = [_panel(), _panel("p2", (1, 0))]
    cw.apply_overrides_to_panels(panels, {
        "_removed_panels": ["p2"],
        "_added_panels": [{"id": "panel-3", "grid": [0, 1]},
                          {"id": "bad id", "grid": [1, 1]},
                          {"id": "p1", "grid": [1, 1]}],
        "panel-3": {"url": "http://new.test/", "title": "New"}})
    assert [p.id for p in panels] == ["p1", "panel-3"]
    assert panels[1].url == "http://new.test/" and panels[1].grid == (0, 1)


@needs_display
def test_add_panel_uses_a_free_cell_and_refuses_when_full(cw):
    # v1.3.0 placed by index, which runs off the grid: the loader then rejects
    # the written-back config at the next boot.
    win = _window(cw, display=cfg.DisplayCfg(cols=2, rows=1))
    assert len(win.panels) == 2
    _buttons(win._form_page, "＋ Add Panel")[0].clicked()
    assert len(win.panels) == 2
    assert "full" in win._form_msg.get_text()
    win = _window(cw)
    _buttons(win._form_page, "＋ Add Panel")[0].clicked()
    assert win.panels[-1].grid == (0, 1)


@needs_display
def test_new_panel_id_never_collides(cw):
    win = _window(cw, panels=[_panel("panel-3"), _panel("panel-4", (1, 0))])
    win._add_panel()
    ids = [p.id for p in win.panels]
    assert len(set(ids)) == 3


@needs_display
def test_adding_a_panel_keeps_unsaved_edits_and_applies_once(cw):
    win = _window(cw)
    win._rows["p1"]["title"].set_text("typed, not applied")
    win._add_panel()
    assert win._rows["p1"]["title"].get_text() == "typed, not applied"
    new_id = win.panels[-1].id
    win._rows[new_id]["url"].set_text("http://new.test/")
    apply_b = _apply_button(win)
    apply_b.clicked()
    assert win.applied[0]["_add_panel"][0]["url"] == "http://new.test/"
    assert cw.load_overrides()["_added_panels"] == [
        {"id": new_id, "grid": [0, 1]}]
    apply_b.clicked()
    assert "_add_panel" not in win.applied[1]      # a second Apply must not re-add


@needs_display
def test_panel_move_only_commits_on_apply(cw):
    p1, p2 = _panel(), _panel("p2", (1, 0))
    win = _window(cw, panels=[p1, p2])
    _buttons(win._rows["p1"]["frame"], "↓ Down")[0].clicked()
    assert p1.grid == (0, 0)                       # closing now loses nothing
    _apply_button(win).clicked()
    assert p1.grid == (1, 0) and p2.grid == (0, 0)
    assert cw.load_overrides()["p1"]["grid"] == [1, 0]


@needs_display
def test_an_unmoved_panel_does_not_pin_its_grid(cw):
    # A saved grid would outrank later edits to panels.yaml.
    win = _window(cw)
    _apply_button(win).clicked()
    assert "grid" not in cw.load_overrides()["p1"]


# --- the gate ---------------------------------------------------------------- #

def test_require_pin_fails_closed_on_garbage(cw, monkeypatch):
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "maybe")
    assert cw.require_pin() is True
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "true")
    assert cw.require_pin() is True
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "")
    assert cw.require_pin() is False


def test_corrupt_totp_secret_fails_closed(cw):
    totp.save(cw._totp_path(), "not base32 !!")
    assert cw.verify_pin_or_totp("123456") is False


def test_corrupt_pin_file_fails_closed(cw):
    with open(cw._pin_path(), "w", encoding="utf-8") as fh:
        fh.write("00$é")
    assert cw.verify_pin("1234") is False


@needs_display
def test_locked_window_builds_nothing_behind_the_gate(cw):
    cw.set_pin(GOOD_PIN)
    vault = _Vault()
    win = _window(cw, vault=vault)
    assert win._unlocked is False
    assert win._form_page is None and win._rows == {}
    assert vault.threads == []
    win._apply()
    assert win.applied == [] and not os.path.exists(cw._overrides_path())


@needs_display
def test_wrong_code_stays_locked_right_codes_open(cw):
    cw.set_pin(GOOD_PIN)
    secret = totp.generate_secret()
    totp.save(cw._totp_path(), secret)
    win = _window(cw)
    win._pin_entry.set_text("0000")
    win._try_unlock()
    assert win._unlocked is False and win._form_page is None
    win._pin_entry.set_text(totp.totp(secret))
    win._try_unlock()
    assert win._unlocked is True and win._form_page is not None
    assert win._pin_entry.get_text() == ""


@needs_display
def test_production_refuses_to_open_or_save_without_a_pin(cw, monkeypatch):
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "1")
    win = _window(cw)
    assert win._unlocked is False and win._form_page is None
    assert win._pin_entry.get_sensitive() is False
    assert "none is enrolled" in win._pin_err.get_text()
    win._pin_entry.set_text("")
    win._try_unlock()
    win._apply()
    assert win._unlocked is False
    assert win.applied == [] and not os.path.exists(cw._overrides_path())


@needs_display
def test_onscreen_config_0_refuses_even_with_a_correct_pin(cw, monkeypatch):
    monkeypatch.setenv("SOC_ONSCREEN_CONFIG", "0")
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    win._pin_entry.set_text(GOOD_PIN)
    win._try_unlock()
    win._apply()
    assert win._unlocked is False and win._form_page is None
    assert "disabled" in win._pin_err.get_text()
    assert win.applied == []


@needs_display
def test_onscreen_config_0_covers_an_unenrolled_dev_wall(cw, monkeypatch):
    monkeypatch.setenv("SOC_ONSCREEN_CONFIG", "0")
    win = _window(cw)
    assert win._unlocked is False and win._form_page is None


@needs_display
def test_apply_refuses_once_the_last_credential_is_gone(cw, monkeypatch):
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "1")
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    _unlock(win)
    cw.clear_pin()                                 # e.g. removed behind our back
    _apply_button(win).clicked()
    assert win.applied == [] and not os.path.exists(cw._overrides_path())


@needs_display
@pytest.mark.parametrize("enrolled", ["pin", "totp"])
def test_cannot_remove_the_only_credential_on_a_require_pin_wall(cw, monkeypatch,
                                                                  enrolled):
    monkeypatch.setenv("SOC_CONFIG_REQUIRE_PIN", "1")
    secret = totp.generate_secret()
    if enrolled == "pin":
        cw.set_pin(GOOD_PIN)
    else:
        totp.save(cw._totp_path(), secret)
    win = _window(cw)
    win._pin_entry.set_text(GOOD_PIN if enrolled == "pin" else totp.totp(secret))
    win._try_unlock()
    prompts = _reauth(win, True)
    page = _tab(win, "Security")
    label = "Remove PIN" if enrolled == "pin" else "Remove TOTP"
    _buttons(page, label)[0].clicked()
    assert cw._reauth_required() is True
    assert prompts == []
    assert "Refused" in win._sec_state.get_text()


@needs_display
def test_reopening_the_window_does_not_reset_the_back_off(cw):
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    for _ in range(3):
        win._pin_entry.set_text("0000")
        win._try_unlock()
    assert cw._gate_throttle.remaining() > 0
    win.destroy()

    again = _window(cw)                            # what main.py does on each open
    assert again._pin_entry.get_sensitive() is False
    again._pin_entry.set_text(GOOD_PIN)
    again._try_unlock()
    assert again._unlocked is False                # even the right code must wait


def test_throttle_schedule_and_cap(cw):
    t = cw._AuthThrottle()
    assert [t.failed() for _ in range(9)] == [0, 0, 5, 10, 20, 40, 60, 60, 60]
    assert t.remaining() > 0
    t.passed()
    assert t.remaining() == 0 and t.failed() == 0


# --- re-authentication ------------------------------------------------------- #

@needs_display
def test_require_reauth_fails_closed_with_nothing_enrolled(cw):
    win = _window(cw)
    alerts = []
    win._alert = lambda msg, **kw: alerts.append(kw.get("title"))
    win._prompt_code = lambda _w: pytest.fail("nothing to verify against")
    assert win._require_reauth("x") is False
    assert alerts == ["No PIN or TOTP enrolled"]


@needs_display
def test_require_reauth_checks_the_code_and_shares_the_back_off(cw):
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    _unlock(win)
    win._alert = lambda *a, **k: None
    win._prompt_code = lambda _w: "0000"
    assert win._require_reauth("x") is False
    win._prompt_code = lambda _w: None             # Cancel
    assert win._require_reauth("x") is False
    win._prompt_code = lambda _w: GOOD_PIN
    assert win._require_reauth("x") is True
    assert cw._gate_throttle.fails == 0
    win._prompt_code = lambda _w: "0000"
    for _ in range(3):
        win._require_reauth("x")
    win._prompt_code = lambda _w: pytest.fail("must not even prompt in a cooldown")
    assert win._require_reauth("x") is False


@needs_display
def test_a_prompt_nobody_answers_fails_closed(cw, monkeypatch):
    # On an unattended wall a modal dismisses itself with DELETE_EVENT: that must
    # read as a refusal at every gate, never as a yes.
    monkeypatch.setattr(cw, "_run_modal", lambda _d: Gtk.ResponseType.DELETE_EVENT)
    monkeypatch.setattr(cw.Gtk.Dialog, "show_all", lambda _d: None)
    monkeypatch.setattr(ospass, "operator_user", lambda: "op")
    monkeypatch.setattr(ospass, "verify_os_password",
                        lambda *a: pytest.fail("nothing was confirmed"))
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    _unlock(win)
    assert win._require_reauth("x") is False
    assert win._ask("sure?", "really?") is False
    assert win._prompt_os_password("edit 'x'") == (False, "op")


def _edit_vpn(win):
    _tab(win, "VPN")
    win._vpn_ws[0]["gateway"].set_text("evil.test")


def _edit_proxy(win):
    _tab(win, "Proxy")
    win._proxy_w["url"].set_text("http://evil.test:3128")


def _edit_tunnel(win):
    _tab(win, "Tunnel")
    win._tunnel_w["jump_host"].set_text("ops@evil.test")


@needs_display
@pytest.mark.parametrize("edit,word", [(_edit_vpn, "VPN"), (_edit_proxy, "proxy"),
                                       (_edit_tunnel, "tunnel")])
def test_network_config_change_needs_reauth(cw, edit, word):
    cw.set_pin(GOOD_PIN)
    cw.save_overrides({"p1": {"title": "before"}})
    with open(cw._overrides_path(), "rb") as fh:
        before = fh.read()
    win = _window(cw)
    _unlock(win)
    prompts = _reauth(win, False)
    edit(win)
    win._rows["p1"]["url"].set_text("http://changed.test/")   # must not sneak out
    _apply_button(win).clicked()
    assert len(prompts) == 1 and word in prompts[0]
    with open(cw._overrides_path(), "rb") as fh:
        assert fh.read() == before
    assert win.applied == []
    assert "nothing was changed" in win._form_msg.get_text()

    prompts = _reauth(win, True)
    _apply_button(win).clicked()
    assert len(prompts) == 1
    assert cw.load_overrides()["p1"]["url"] == "http://changed.test/"
    assert len(win.applied) == 1


@needs_display
def test_network_config_change_needs_no_prompt_on_an_unenrolled_wall(cw):
    win = _window(cw)
    _edit_proxy(win)
    win._require_reauth = lambda *_: pytest.fail("nothing is enrolled")
    _apply_button(win).clicked()
    assert cw.load_overrides()["_proxy"]["url"] == "http://evil.test:3128"


@needs_display
def test_url_edit_neither_prompts_nor_bounces_the_network_services(cw):
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    _unlock(win)
    prompts = _reauth(win, False)
    for title in ("VPN", "Proxy", "Tunnel"):       # built, but untouched
        _tab(win, title)
    win._rows["p1"]["url"].set_text("http://changed.test/")
    _apply_button(win).clicked()
    assert prompts == []
    keys = set(win.applied[0])
    assert not keys & {"_vpn", "_vpns", "_proxy", "_tunnel"}


@needs_display
def test_reauth_is_not_asked_twice_for_the_same_saved_change(cw):
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    _unlock(win)
    prompts = _reauth(win, True)
    _edit_tunnel(win)
    apply_b = _apply_button(win)
    apply_b.clicked()
    apply_b.clicked()
    assert len(prompts) == 1


@needs_display
@pytest.mark.parametrize("edit,marker", [
    (lambda w: w._vpn_ws[0]["gateway"].set_text("--config=/tmp/evil"), "gateway"),
    (lambda w: w._vpn_ws[0]["name"].set_text("a b"), "name"),
])
def test_invalid_vpn_is_refused_before_anything_is_saved(cw, edit, marker):
    win = _window(cw)
    _tab(win, "VPN")
    edit(win)
    _apply_button(win).clicked()
    assert not os.path.exists(cw._overrides_path())
    assert win.applied == []
    assert marker in win._form_msg.get_text()


@needs_display
def test_bad_extra_forward_is_refused(cw):
    win = _window(cw)
    _tab(win, "Tunnel")
    win._tunnel_ef.get_buffer().set_text("-D 1080")
    _apply_button(win).clicked()
    assert not os.path.exists(cw._overrides_path())
    assert "extra_forward" in win._form_msg.get_text()


@needs_display
def test_blank_jump_host_is_refused_while_tunnel_panels_exist(cw):
    # The loader rejects that combination, so it would stop the next boot.
    tunnel_panel = cfg.Panel(id="t1", engine="webkit", grid=(0, 0), mode="tunnel",
                             vault_item="", selectors={}, login_marker="",
                             keepalive=cfg.KeepAlive(),
                             tunnel={"local_port": 5000, "remote_host": "h",
                                     "remote_port": 80})
    win = _window(cw, panels=[tunnel_panel])
    _tab(win, "Tunnel")
    win._tunnel_w["jump_host"].set_text("")
    _apply_button(win).clicked()
    assert not os.path.exists(cw._overrides_path())
    assert "jump host" in win._form_msg.get_text()


@needs_display
def test_proxy_url_with_credentials_is_refused(cw):
    win = _window(cw)
    _tab(win, "Proxy")
    win._proxy_w["url"].set_text("http://user:hunter2@proxy:3128")
    _apply_button(win).clicked()
    assert not os.path.exists(cw._overrides_path())
    assert "hunter2" not in win._form_msg.get_text()


def _set_settings_totp(cw):
    totp.save(cw._totp_path(), totp.generate_secret())


def _enrolled_state(cw):
    sd = cw.state_dir()
    return (cw.pin_is_set(), cw.totp_is_set(), locker.pin_is_set(sd),
            locker.totp_is_set(sd))


@needs_display
@pytest.mark.parametrize("label,which", [
    ("Remove PIN", 0), ("Remove TOTP", 0), ("Remove PIN", 1), ("Remove TOTP", 1),
    ("Enroll TOTP", 0), ("Enroll TOTP", 1), ("Set / change PIN", 0), ("Set PIN", 0)])
def test_security_buttons_are_gated_and_a_failed_reauth_changes_nothing(cw, label,
                                                                        which):
    sd = cw.state_dir()
    cw.set_pin(GOOD_PIN)
    _set_settings_totp(cw)
    locker.set_pin(sd, GOOD_PIN)
    locker.set_totp(sd, totp.generate_secret())
    with open(cw._pin_path(), "rb") as fh:
        pin_before = fh.read()
    with open(cw._totp_path(), "rb") as fh:
        totp_before = fh.read()
    win = _window(cw)
    _unlock(win)
    prompts = _reauth(win, False)
    page = _tab(win, "Security")
    win._newpin.set_text("9753")
    win._pl_pin.set_text("9753")
    _buttons(page, label)[which].clicked()
    assert len(prompts) == 1
    assert _enrolled_state(cw) == (True, True, True, True)
    with open(cw._pin_path(), "rb") as fh:
        assert fh.read() == pin_before
    with open(cw._totp_path(), "rb") as fh:
        assert fh.read() == totp_before
    assert locker.verify_pin(sd, GOOD_PIN)


@needs_display
def test_remove_pin_works_after_a_good_reauth(cw):
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    _unlock(win)
    _reauth(win, True)
    _buttons(_tab(win, "Security"), "Remove PIN")[0].clicked()
    assert not cw.pin_is_set()


@needs_display
def test_settings_totp_enrol_unlocks_the_gate(cw):
    win = _window(cw)
    _buttons(_tab(win, "Security"), "Enroll TOTP")[0].clicked()
    assert cw.totp_is_set()
    assert win._sg_uri.get_text().startswith("otpauth://totp/")
    again = _window(cw)
    assert again._unlocked is False                # a TOTP alone gates the window
    again._pin_entry.set_text(totp.totp(totp.load(cw._totp_path())))
    again._try_unlock()
    assert again._unlocked is True


@needs_display
def test_delete_vault_item_needs_reauth_and_then_runs_off_the_main_thread(cw):
    cw.set_pin(GOOD_PIN)
    vault = _Vault()
    panels = [_panel(vault_item="zabbix")]
    win = _window(cw, vault=vault, panels=panels)
    _unlock(win)
    prompts = _reauth(win, False)
    win._ask = lambda *_: pytest.fail("must re-auth before asking")
    page = _tab(win, "Credentials")
    _buttons(page, "Delete")[0].clicked()
    assert len(prompts) == 1 and vault.deleted == []

    prompts = _reauth(win, True)
    win._ask = lambda *_: True
    _buttons(page, "Delete")[0].clicked()
    assert _pump(lambda: vault.deleted)
    assert vault.deleted == ["zabbix"]
    assert threading.main_thread() not in vault.threads


@needs_display
def test_delete_failure_is_shown_not_swallowed(cw):
    cw.set_pin(GOOD_PIN)
    vault = _Vault()
    vault.delete = lambda _n: False
    win = _window(cw, vault=vault, panels=[_panel(vault_item="z")])
    _unlock(win)
    _reauth(win, True)
    win._ask = lambda *_: True
    alerts = []
    win._alert = lambda msg, **kw: alerts.append(kw.get("title"))
    _buttons(_tab(win, "Credentials"), "Delete")[0].clicked()
    assert _pump(lambda: alerts)
    assert alerts == ["Delete failed"]


@needs_display
def test_delete_is_refused_with_nothing_enrolled(cw):
    # Unlike the save paths, delete has no un-enrolled mode.
    vault = _Vault()
    win = _window(cw, vault=vault, panels=[_panel(vault_item="z")])
    alerts = []
    win._alert = lambda msg, **kw: alerts.append(kw.get("title"))
    _buttons(_tab(win, "Credentials"), "Delete")[0].clicked()
    assert alerts == ["No PIN or TOTP enrolled"] and vault.deleted == []


@needs_display
def test_edit_reveals_nothing_without_the_os_password(cw):
    vault = _Vault()
    win = _window(cw, vault=vault, panels=[_panel(vault_item="zabbix")])
    asked = []

    def refuse(what):
        asked.append(what)
        return False, "op"
    win._prompt_os_password = refuse
    _buttons(_tab(win, "Credentials"), "Edit")[0].clicked()
    assert len(asked) == 1 and vault.read == []


@needs_display
@pytest.mark.parametrize("path", ["save_cred", "vpn_creds"])
def test_saving_a_credential_needs_reauth(cw, monkeypatch, path):
    from host import vaultseed
    monkeypatch.setattr(vaultseed, "upsert_login",
                        lambda *a, **k: pytest.fail("reached the vault"))
    cw.set_pin(GOOD_PIN)
    win = _window(cw, panels=[_panel(vault_item="zabbix")])
    _unlock(win)
    prompts = _reauth(win, False)
    if path == "save_cred":
        page = _tab(win, "Credentials")

        def fill(w):
            if isinstance(w, Gtk.Entry) and w.get_placeholder_text() == "username":
                w.set_text("op")
            elif isinstance(w, Gtk.Container):
                w.forall(fill)
        fill(page)
        _buttons(page, "Save to vault")[0].clicked()
    else:
        page = _tab(win, "VPN")
        win._vpn_ws[0]["pass"].set_text("hunter2")
        win._vpn_ws[0]["user"].set_text("op")
        _buttons(page, "Save inline creds to vault")[0].clicked()
        assert win._vpn_ws[0]["pass"].get_text() == ""   # never left in the entry
    assert len(prompts) == 1


@needs_display
def test_vault_write_runs_off_the_main_thread_and_never_reads_a_plain_master(
        cw, monkeypatch):
    from host import vaultseed
    monkeypatch.setenv("SOC_VAULT_EMAIL", "a@b.test")
    monkeypatch.setenv("SOC_VAULT_PASSWORD", "plaintext-must-not-be-used")
    seen = []
    monkeypatch.setattr(vaultseed, "available", lambda: True)

    def upsert(url, email, master, name, user, secret, uri=None):
        seen.append((threading.current_thread(), master, name, user, secret))
        return "created"
    monkeypatch.setattr(vaultseed, "upsert_login", upsert)
    win = _window(cw, panels=[_panel(vault_item="zabbix")], vpns=[], proxy=None)
    page = _tab(win, "Credentials")
    win._cred_master.set_text("typed-master")
    grid_entries = []

    def walk(w):
        if isinstance(w, Gtk.Entry):
            grid_entries.append(w)
        elif isinstance(w, Gtk.Container):
            w.forall(walk)
    walk(page)
    user_e = next(e for e in grid_entries if e.get_placeholder_text() == "username")
    pass_e = next(e for e in grid_entries if e.get_placeholder_text() == "password")
    user_e.set_text("op")
    pass_e.set_text("hunter2")
    _buttons(page, "Save to vault")[0].clicked()
    assert _pump(lambda: seen and "✓" in win._cred_msg.get_text())
    assert seen[0][0] is not threading.main_thread()
    assert seen[0][1:] == ("typed-master", "zabbix", "op", "hunter2")
    assert pass_e.get_text() == ""


@needs_display
@pytest.mark.parametrize("label", ["Reboot", "Repair install", "Restart wall"])
def test_machine_actions_need_two_clicks_and_reauth(cw, monkeypatch, label):
    ran = []
    monkeypatch.setattr(cw, "_reboot_machine",
                        lambda: ran.append(threading.current_thread()))
    monkeypatch.setattr(cw, "_repair_install",
                        lambda: ran.append(threading.current_thread()))
    cw.set_pin(GOOD_PIN)
    win = _window(cw, actions={"restart_wall": lambda: ran.append("restart")})
    _unlock(win)
    prompts = _reauth(win, False)
    page = _tab(win, "Actions")
    shown = "Reboot machine" if label == "Reboot" else label
    btn = _buttons(page, shown)[0]
    btn.clicked()
    assert btn.get_label() == f"Confirm: {label}" and ran == []
    btn.clicked()
    assert len(prompts) == 1 and ran == []


@needs_display
def test_reboot_runs_on_a_worker_after_reauth(cw, monkeypatch):
    ran = []
    monkeypatch.setattr(cw, "_reboot_machine",
                        lambda: ran.append(threading.current_thread()))
    win = _window(cw)
    btn = _buttons(_tab(win, "Actions"), "Reboot machine")[0]
    btn.clicked()
    btn.clicked()
    assert _pump(lambda: ran)
    assert ran[0] is not threading.main_thread()


@needs_display
def test_lock_from_actions_closes_this_window_first(cw):
    order = []
    win = _window(cw, actions={"lock_wall": lambda: order.append(win._closed)},
                  on_close=lambda: order.append("closed"))
    _buttons(_tab(win, "Actions"), "🔒 Lock the wall now")[0].clicked()
    assert order == ["closed", True]


@needs_display
def test_remove_panel_and_clear_zones_are_gated(cw):
    cw.set_pin(GOOD_PIN)
    p = _panel()
    p.login_zones = {"pass": {"x_pct": 0.1, "y_pct": 0.1}}
    win = _window(cw, panels=[p, _panel("p2", (1, 0))])
    _unlock(win)
    prompts = _reauth(win, False)
    frame = win._rows["p1"]["frame"]
    _buttons(frame, "✕ Remove")[0].clicked()
    _buttons(frame, "Clear zones")[0].clicked()
    assert len(prompts) == 2
    assert "p1" in win._rows and p.login_zones
    assert not os.path.exists(cw._overrides_path())


@needs_display
def test_clear_zones_persists_an_empty_override(cw):
    cw.set_pin(GOOD_PIN)
    cw.save_overrides({"p1": {"title": "kept"}})
    p = _panel()
    p.login_zones = {"pass": {"x_pct": 0.1, "y_pct": 0.1}}
    win = _window(cw, panels=[p])
    _unlock(win)
    _reauth(win, True)
    _buttons(win._rows["p1"]["frame"], "Clear zones")[0].clicked()
    saved = cw.load_overrides()["p1"]
    assert saved == {"title": "kept", "login_zones": {}}
    assert p.login_zones == {}


@needs_display
def test_removed_panel_is_dropped_on_apply(cw):
    cw.save_overrides({"p2": {"title": "stale"}})
    win = _window(cw)
    _buttons(win._rows["p2"]["frame"], "✕ Remove")[0].clicked()
    _apply_button(win).clicked()
    ov = cw.load_overrides()
    assert "p2" not in ov and ov["_removed_panels"] == ["p2"]
    assert win.applied[0]["_remove_panel"] == ["p2"]


# --- calibration ------------------------------------------------------------- #

@needs_display
def test_calibrate_button_routes_to_the_host_and_marshals_the_result(cw):
    calls = []
    win = _window(cw, actions={"calibrate_panel":
                               lambda pid, done: calls.append((pid, done))})
    _buttons(win._rows["p1"]["frame"], "Calibrate login zones")[0].clicked()
    assert calls[0][0] == "p1"
    zones = {"user": {"x_pct": 0.5, "y_pct": 0.5}}
    # a Chromium panel reports from its CDP thread
    threading.Thread(target=calls[0][1], args=(zones,)).start()
    assert _pump(lambda: win.panels[0].login_zones == zones)
    assert "calibrated" in win._rows["p1"]["zones_lbl"].get_text()


@needs_display
def test_calibrate_without_a_host_action_says_so(cw):
    win = _window(cw)
    alerts = []
    win._alert = lambda msg, **kw: alerts.append(kw.get("title"))
    _buttons(win._rows["p1"]["frame"], "Calibrate login zones")[0].clicked()
    assert alerts == ["Calibrate unavailable"]


# --- a hung vault must never freeze the wall --------------------------------- #

@needs_display
def test_wait_for_gives_up_on_a_hung_call_while_the_main_loop_keeps_running(cw):
    win = _window(cw)
    win._busy_dialog = lambda _t: _Busy()
    ticks = []
    tick = GLib.timeout_add(10, lambda: ticks.append(1) or True)
    release = threading.Event()
    try:
        status, value = win._wait_for(lambda: release.wait(10), "x", timeout=1)
    finally:
        release.set()
        GLib.source_remove(tick)
    assert (status, value) == ("timeout", None)
    assert len(ticks) > 20            # the panels' main loop was never held up


@needs_display
def test_wait_for_reports_a_result_and_an_exception(cw):
    win = _window(cw)
    win._busy_dialog = lambda _t: _Busy()
    assert win._wait_for(lambda: 41 + 1, "x") == ("ok", 42)

    def boom():
        raise RuntimeError("vault down")
    status, err = win._wait_for(boom, "x")
    assert status == "error" and "vault down" in str(err)


@needs_display
def test_wait_for_cancel_abandons_the_worker(cw):
    win = _window(cw)
    busy = _Busy()
    win._busy_dialog = lambda _t: busy
    release = threading.Event()
    GLib.timeout_add(20, lambda: busy.response(Gtk.ResponseType.CANCEL) or False)
    assert win._wait_for(lambda: release.wait(10), "x")[0] == "cancelled"
    release.set()


@needs_display
def test_credentials_tab_opens_instantly_on_a_hung_vault(cw):
    hang = threading.Event()
    vault = _Vault(hang=hang)
    win = _window(cw, vault=vault, panels=[_panel(vault_item="zabbix")],
                  vpns=[], proxy=None)
    t0 = time.monotonic()
    try:
        page = _tab(win, "Credentials")
        assert time.monotonic() - t0 < 1.0
        # the rows that need no vault are already there
        assert len(_buttons(page, "Delete")) == 1
        assert _pump(lambda: vault.threads, timeout=2)
    finally:
        hang.set()
    assert threading.main_thread() not in vault.threads
    assert _pump(lambda: len(_buttons(page, "Delete")) == 2)


@needs_display
def test_inventory_refresh_does_not_pile_up_threads_on_a_hung_vault(cw):
    hang = threading.Event()
    vault = _Vault(hang=hang)
    win = _window(cw, vault=vault)
    try:
        _tab(win, "Credentials")
        assert _pump(lambda: vault.threads, timeout=2)
        for _ in range(5):
            win._refresh_cred_inventory()
        assert len(vault.threads) == 1
    finally:
        hang.set()


@needs_display
def test_status_tab_probes_off_the_main_thread(cw, monkeypatch):
    probes = []

    def probe(_url):
        probes.append(threading.current_thread())
        return False
    monkeypatch.setattr(cw, "_vw_reachable", probe)
    win = _window(cw)
    page = _tab(win, "Status")
    assert _pump(lambda: probes)
    assert probes[0] is not threading.main_thread()

    def texts():
        found = []

        def walk(w):
            if isinstance(w, Gtk.Label):
                found.append(w.get_text())
            elif isinstance(w, Gtk.Container):
                w.forall(walk)
        walk(page)
        return found
    assert _pump(lambda: any("NOT reachable" in t for t in texts()))


@needs_display
def test_result_after_the_window_closed_is_dropped(cw):
    win = _window(cw)
    release = threading.Event()
    seen = []
    win._in_worker(lambda: release.wait(5), lambda *a: seen.append(a))
    win.destroy()
    release.set()
    _pump(lambda: False, timeout=0.2)
    assert seen == []


@needs_display
def test_fetch_creds_recovery_paths(cw):
    win = _window(cw)
    alerts = []
    win._alert = lambda msg, **kw: alerts.append(kw.get("title"))
    results = iter([("timeout", None)])
    win._wait_for = lambda *a, **k: next(results)
    assert win._fetch_creds_with_recovery(_Vault(), "x") is cw._CANCELLED
    assert alerts == ["Vault not responding"]

    results = iter([("error", RuntimeError(
        "vault item 'x' has no password (or not found)"))])
    assert win._fetch_creds_with_recovery(_Vault(), "x") is cw._NOT_FOUND
    results = iter([("cancelled", None)])
    assert win._fetch_creds_with_recovery(_Vault(), "x") is cw._CANCELLED
    results = iter([("ok", {"user": "u"})])
    assert win._fetch_creds_with_recovery(_Vault(), "x") == {"user": "u"}


def test_vault_sync_goes_through_the_backend_not_the_rbw_cli(cw, monkeypatch):
    # The default backend is litebw: shelling out to `rbw sync` would not work.
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: pytest.fail("no subprocess here"))
    calls = []

    class Backend:
        def sync(self):
            calls.append("sync")

    class V:
        backend = Backend()

        def invalidate(self, item=None):
            calls.append("invalidate")
    cw._vault_sync(V())
    assert calls == ["sync", "invalidate"]
    with pytest.raises(RuntimeError):
        cw._vault_sync(object())


def test_vw_reachable(cw):
    import socket
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        assert cw._vw_reachable(f"http://127.0.0.1:{port}") is True
    assert cw._vw_reachable(f"http://127.0.0.1:{port}", timeout=0.2) is False
    assert cw._vw_reachable("http://[bad", timeout=0.2) is False


# --- lazy building ----------------------------------------------------------- #

@needs_display
def test_tabs_are_built_on_first_view_only(cw, monkeypatch):
    built = []
    real = cw.ConfigWindow._tab_status
    monkeypatch.setattr(cw.ConfigWindow, "_tab_status",
                        lambda self: (built.append(1), real(self))[1])
    monkeypatch.setattr(cw, "_vw_reachable", lambda _u: True)
    win = _window(cw)
    assert built == []
    assert win._layout_c is None and win._vpn_ws == []
    _tab(win, "Status")
    _tab(win, "Panels")
    _tab(win, "Status")
    assert built == [1]


@needs_display
def test_apply_with_unopened_tabs_only_saves_the_panels(cw):
    win = _window(cw)
    _apply_button(win).clicked()
    ov = cw.load_overrides()
    assert not set(ov) & {"_display", "_vpn", "_vpns", "_proxy", "_tunnel"}
    assert set(ov) == {"p1", "p2"}


@needs_display
def test_no_proxy_or_tunnel_tab_without_a_config_for_them(cw):
    win = _window(cw, proxy=None, tunnel=None, proxy_vault_item="pxy")
    nb = _notebook(win)
    titles = [nb.get_tab_label_text(nb.get_nth_page(i))
              for i in range(nb.get_n_pages())]
    assert "Proxy" not in titles and "Tunnel" not in titles
    assert win._proxy_vault_item == "pxy"


@needs_display
def test_legacy_constructor_call_still_works(cw):
    # What main.py passes until its merge lands.
    win = cw.ConfigWindow([_panel()], lambda c: None, on_close=None,
                          display=cfg.DisplayCfg(), vpn={"type": "inode"},
                          proxy_vault_item="p")
    assert win._vpns == [{"type": "inode"}]
    assert _tab(win, "VPN") is not None


# --- iNode / panel-lock fields survived the merge ---------------------------- #

@needs_display
def test_inode_fields_are_still_on_the_form_and_saved(cw):
    win = _window(cw)
    _tab(win, "VPN")
    w = win._vpn_ws[0]
    w["spa_key"].set_text("ab12")
    assert w["spa_key"].get_visibility() is False         # a shared secret
    w["ca_file"].set_text("/ca.pem")
    w["ead"].set_active(True)
    w["captcha_retries"].set_value(7)
    w["mac"].set_text("aa:bb:cc:dd:ee:ff")
    _apply_button(win).clicked()
    saved = cw.load_overrides()["_vpns"][0]
    assert saved["spa_key"] == "ab12" and saved["ca_file"] == "/ca.pem"
    assert saved["ead"] is True and saved["captcha_retries"] == 7
    assert saved["mac"] == "aa:bb:cc:dd:ee:ff"


@needs_display
def test_changes_carry_the_whole_vpn_so_advanced_fields_survive_the_host(cw):
    # The host replaces conf.vpns with this; a sparse entry would lose set_routes.
    win = _window(cw)
    _tab(win, "VPN")
    win._vpn_ws[0]["gateway"].set_text("gw2.test")
    _apply_button(win).clicked()
    assert win.applied[0]["_vpns"][0]["set_routes"] is True
    assert None not in win.applied[0]["_vpns"][0].values()


@needs_display
def test_panel_lock_section_is_on_the_security_tab(cw):
    win = _window(cw)
    page = _tab(win, "Security")
    win._pl_pin.set_text("9753")
    _buttons(page, "Set PIN")[0].clicked()
    assert locker.verify_pin(cw.state_dir(), "9753")


# --- export / import --------------------------------------------------------- #

@needs_display
def test_export_is_owner_only_and_import_reads_it_back(cw, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    win = _window(cw, panels=[_panel(tenant="acme"), _panel("p2", (1, 0))])
    _buttons(win._form_page, "⬇ Export YAML")[0].clicked()
    path = win._form_msg.get_text().split("Exported to ")[1]
    assert os.stat(path).st_mode & 0o777 == 0o600
    with open(path, encoding="utf-8") as fh:
        conf = cfg.load_str(fh.read(), "t")
    assert [p.id for p in conf.panels] == ["p1", "p2"]
    assert conf.panels[0].tenant == "acme"


class _Chooser:
    """Stands in for Gtk.FileChooserDialog."""
    path = None
    opened = 0

    def __init__(self, **_kw):
        type(self).opened += 1

    def add_buttons(self, *_a):
        pass

    def add_filter(self, _f):
        pass

    def run(self):
        return Gtk.ResponseType.OK

    def get_filename(self):
        return self.path

    def destroy(self):
        pass


@needs_display
def test_import_is_gated_before_the_file_chooser_opens(cw, monkeypatch):
    monkeypatch.setattr(cw.Gtk, "FileChooserDialog", _Chooser)
    _Chooser.opened = 0
    cw.set_pin(GOOD_PIN)
    win = _window(cw)
    _unlock(win)
    prompts = _reauth(win, False)
    _buttons(win._form_page, "⬆ Import YAML")[0].clicked()
    assert len(prompts) == 1 and _Chooser.opened == 0


@needs_display
def test_import_goes_through_the_validator(cw, monkeypatch, tmp_path):
    monkeypatch.setattr(cw.Gtk, "FileChooserDialog", _Chooser)
    bad = tmp_path / "bad.yaml"
    bad.write_text("display: {cols: 2, rows: 2}\npanels:\n"
                   "  - {id: x, grid: [0, 0], url: 'file:///etc/passwd'}\n"
                   "tunnel: {enabled: false}\nvpn: {enabled: false}\n")
    _Chooser.path = str(bad)
    win = _window(cw)
    win._import_yaml()
    assert [p.id for p in win.panels] == ["p1", "p2"]
    assert "Import failed" in win._form_msg.get_text()

    good = tmp_path / "good.yaml"
    good.write_text("display: {cols: 2, rows: 2}\npanels:\n"
                    "  - {id: p1, grid: [0, 0], url: 'http://n.test/'}\n"
                    "  - {id: p3, grid: [1, 0], url: 'http://m.test/'}\n"
                    "tunnel: {enabled: false}\nvpn: {enabled: false}\n")
    _Chooser.path = str(good)
    win._import_yaml()
    assert [p.id for p in win.panels] == ["p1", "p3"]
    assert win._rows["p3"]["url"].get_text() == "http://m.test/"
    _apply_button(win).clicked()
    assert win.applied[0]["_remove_panel"] == ["p2"]
    assert [a["id"] for a in win.applied[0]["_add_panel"]] == ["p3"]


@needs_display
def test_import_refuses_a_fifo(cw, monkeypatch, tmp_path):
    # open() on one would block the GTK thread forever.
    monkeypatch.setattr(cw.Gtk, "FileChooserDialog", _Chooser)
    fifo = tmp_path / "f.yaml"
    os.mkfifo(fifo)
    _Chooser.path = str(fifo)
    win = _window(cw)
    win._import_yaml()
    assert "Import failed" in win._form_msg.get_text()


# --- apply reporting --------------------------------------------------------- #

@needs_display
def test_host_details_are_reported_truthfully(cw):
    win = _window(cw)
    win._report_apply({"pending_restarts": ["forti-vpn"],
                       "write_back": "deferred:sealed master missing"})
    text = win._form_msg.get_text()
    assert "PENDING restart: forti-vpn" in text
    assert "sealed master missing" in text
    win._report_apply({"applied_live": ["width"], "write_back": "ok"})
    assert "applied live" in win._form_msg.get_text()
    win._report_apply({})
    assert win._form_msg.get_text().startswith("Applied ✓")


@needs_display
def test_unwritable_state_dir_is_reported_and_nothing_is_applied(cw, monkeypatch):
    def full(_d):
        raise OSError("No space left on device")
    monkeypatch.setattr(cw, "save_overrides", full)
    win = _window(cw)
    _apply_button(win).clicked()
    assert win.applied == []
    assert "could not save settings" in win._form_msg.get_text()


# --- ospass ------------------------------------------------------------------ #

def _fake_su(monkeypatch, accepts):
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw.get("input", "")))
        return subprocess.CompletedProcess(
            argv, 0 if accepts(kw.get("input", "").strip()) else 1)
    monkeypatch.setattr(ospass.subprocess, "run", run)
    monkeypatch.setattr(ospass.shutil, "which", lambda _n: "/bin/su")
    monkeypatch.setattr(ospass.os, "geteuid", lambda: 1000)
    return calls


def test_su_accepts_the_right_password_only(monkeypatch):
    _fake_su(monkeypatch, lambda pw: pw == "right")
    assert ospass._verify_via_su("alice", "right", timeout=1.0) is True
    assert ospass._verify_via_su("alice", "wrong", timeout=1.0) is False


def test_passwordless_account_cannot_pass_the_su_gate(monkeypatch):
    # su lets an empty-password account through whatever was typed.
    calls = _fake_su(monkeypatch, lambda _pw: True)
    assert ospass._verify_via_su("guest", "anything", timeout=1.0) is False
    assert calls[0][1] != calls[1][1]              # the probe is a different value


def test_su_is_not_trusted_as_root(monkeypatch):
    # pam_rootok: root su's to anyone with no password at all.
    calls = _fake_su(monkeypatch, lambda _pw: True)
    monkeypatch.setattr(ospass.os, "geteuid", lambda: 0)
    assert ospass._verify_via_su("alice", "anything", timeout=1.0) is None
    assert calls == []


def test_password_travels_on_stdin_never_argv(monkeypatch):
    calls = _fake_su(monkeypatch, lambda pw: pw == "s3cret")
    ospass._verify_via_su("alice", "s3cret", timeout=1.0)
    assert all("s3cret" not in " ".join(argv) for argv, _ in calls)
    assert calls[0][1] == "s3cret\n"


@pytest.mark.parametrize("user", ["-c", "--shell=/bin/sh", "a b", "a\nb", "a;b", "$x"])
def test_option_shaped_username_never_reaches_a_backend(monkeypatch, user):
    monkeypatch.setattr(ospass, "_verify_via_su",
                        lambda *a, **k: pytest.fail("reached su"))
    assert ospass.verify_os_password(user, "pw") is False


def test_backend_exception_text_is_not_logged(monkeypatch, caplog):
    def boom(u, p, *, timeout):
        raise UnicodeEncodeError("ascii", p, 0, 1, f"bad: {p}")
    monkeypatch.setattr(ospass, "_verify_via_su", boom)
    monkeypatch.setattr(ospass, "_verify_via_pamtester", lambda *a, **k: None)
    monkeypatch.setattr(ospass, "_verify_via_pam", lambda *a, **k: None)
    monkeypatch.setattr(ospass, "_MIN_LATENCY_SEC", 0.0)
    with caplog.at_level(logging.DEBUG, logger="soc.ospass"):
        assert ospass.verify_os_password("alice", "s3cretpw") is False
    assert "s3cretpw" not in caplog.text


@needs_display
def test_os_password_check_runs_off_the_main_thread(cw, monkeypatch):
    seen = []

    def verify(user, pw):
        seen.append((threading.current_thread(), user, pw))
        return False
    monkeypatch.setattr(ospass, "verify_os_password", verify)
    monkeypatch.setattr(ospass, "operator_user", lambda: "op")
    monkeypatch.setattr(cw.Gtk.Dialog, "run", lambda _d: Gtk.ResponseType.OK)
    monkeypatch.setattr(cw.Gtk.Dialog, "show_all", lambda _d: None)
    win = _window(cw)
    win._busy_dialog = lambda _t: _Busy()
    alerts = []
    win._alert = lambda msg, **kw: alerts.append(kw.get("title"))
    assert win._prompt_os_password("edit 'x'") == (False, "op")
    assert seen[0][0] is not threading.main_thread()
    assert alerts == ["OS password rejected"]
    assert cw._os_throttle.fails == 1


@needs_display
def test_os_password_prompt_backs_off(cw, monkeypatch):
    monkeypatch.setattr(ospass, "operator_user",
                        lambda: pytest.fail("must not even prompt"))
    for _ in range(3):
        cw._os_throttle.failed()
    win = _window(cw)
    alerts = []
    win._alert = lambda msg, **kw: alerts.append(kw.get("title"))
    assert win._prompt_os_password("x") == (False, "")
    assert alerts == ["Too many wrong attempts"]


# --- secrets stay out of the file -------------------------------------------- #

@needs_display
def test_inline_vpn_password_is_never_written_to_overrides(cw):
    win = _window(cw)
    _tab(win, "VPN")
    win._vpn_ws[0]["user"].set_text("op")
    win._vpn_ws[0]["pass"].set_text("hunter2")
    win._vpn_ws[0]["gateway"].set_text("gw2.test")
    _apply_button(win).clicked()
    with open(cw._overrides_path(), encoding="utf-8") as fh:
        data = fh.read()
    assert "hunter2" not in data
    assert json.loads(data)["_vpns"][0]["gateway"] == "gw2.test"
