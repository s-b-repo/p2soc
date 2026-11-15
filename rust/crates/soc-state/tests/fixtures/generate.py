"""Produce soc-state compatibility fixtures with the real Python functions."""
import json, os, sys, types
from unittest import mock

out = sys.argv[1]
state = os.path.join(out, "state")
os.makedirs(state, exist_ok=True)
os.environ["SOC_STATE_DIR"] = state
for k in ("SOC_CONFIG_REQUIRE_PIN", "SOC_ONSCREEN_CONFIG"):
    os.environ.pop(k, None)

# host.configwin / host.locker import Gtk at module scope; stub it out.
gi = types.ModuleType("gi")
gi.require_version = lambda *a, **k: None
repo = types.ModuleType("gi.repository")
for name in ("Gtk", "Gdk", "GLib", "Pango", "GdkPixbuf", "Gio", "WebKit2", "GObject"):
    setattr(repo, name, mock.MagicMock())
gi.repository = repo
sys.modules["gi"] = gi
sys.modules["gi.repository"] = repo
sys.path.insert(0, os.getcwd())

from host import config as cfg, configwin as cw, locker, totp

# --- PIN + TOTP state files (obviously fake credentials) ---
cw.set_pin("864213")
locker.set_pin(state, "135790")
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
totp.save(cw._totp_path(), SECRET)
locker.set_totp(state, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
assert cw.verify_pin("864213") and locker.verify_pin(state, "135790")

vectors = {"secret": SECRET, "codes": {str(t): totp.totp(SECRET, t=t) for t in
           (0, 59, 1111111109, 1234567890, 1700000000, 2000000000, 1700000029, 1700000030)},
           "spaced_secret": "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
           "spaced_code_1700000000": totp.totp("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", t=1700000000),
           "uri_settings": totp.provision_uri(SECRET, "kiosk@soc.local", issuer="SOC Wall — Settings"),
           "uri_lock": totp.provision_uri(SECRET, "kiosk@soc.local", issuer="SOC Wall — Panel lock"),
           "gate_schedule": [cw._AuthThrottle().failed() for _ in range(1)],
           }
t = cw._AuthThrottle()
vectors["gate_schedule"] = [t.failed() for _ in range(9)]
vectors["lock_schedule"] = [0 if f < 3 else min(5 * (f - 2), 60) for f in range(1, 16)]
json.dump(vectors, open(os.path.join(out, "totp_vectors.json"), "w"), indent=2, sort_keys=True, ensure_ascii=True)

# --- overrides.json written by the real save_overrides ---
BASE = """\
display: {auto: false, width: 1920, height: 1080, cols: 2, rows: 2, gap: 0, layout: windows}
panels:
  - {id: p1, grid: [0, 0], url: 'http://a.test/', title: Alpha}
  - id: p2
    grid: [1, 0]
    url: 'http://b.test/'
    vault_item: item-b
    selectors: {user: '#u', pass: '#p', submit: '#go'}
    login_zones: {pass: {x_pct: 0.1, y_pct: 0.2}}
  - {id: p3, grid: [0, 1], url: 'http://c.test/'}
tunnel: {enabled: true, jump_host: ops@jump.test, identity: /keys/id, known_hosts: /keys/kh}
vpns:
  - {name: hq, enabled: true, type: inode, gateway: gw.test, vault_item: vpn-hq, insecure: true, realm: corp, set_routes: true}
  - {name: dr, enabled: false, type: fortinet}
proxy: {enabled: true, url: 'http://old.test:3128', vault_item: pxy, ignore_hosts: [a.test]}
"""
conf = cfg.load_str(BASE, "base.yaml")
vpn_form = {"name": "hq", "enabled": True, "type": "inode", "gateway": "gw2.test", "port": 8443,
            "vault_item": "vpn-hq", "config": "", "domain": "", "realm": "", "trusted_cert": "",
            "ready_probe": "", "insecure": False, "config_from_vault": False, "ead": False,
            "split_tunnel": False, "ca_file": "", "client_cert": "", "client_key": "", "spa_key": "",
            "spa_aid": "", "spa_ports": "", "spa_knock_port": 0, "captcha_retries": 0, "mac": "",
            "language": ""}
before = dict(conf.vpns[0])
saved = cw.vpn_form_to_dict(vpn_form)
saved["name"] = vpn_form["name"]
cw._mark_cleared(saved, vpn_form, before)
new_vpn = cw.vpn_form_to_dict({"name": "lab", "enabled": False, "type": "openvpn", "config": "/etc/lab.ovpn"})
proxy_form = {"enabled": True, "url": "http://new.test:8080", "vault_item": "", "ignore_hosts": "x.test, y.test\nz.test"}
pcfg = cw._mark_cleared(cw.proxy_form_to_dict(proxy_form), proxy_form,
                        {"url": conf.proxy.url, "vault_item": conf.proxy.vault_item,
                         "ignore_hosts": list(conf.proxy.ignore_hosts)})
tunnel_form = {"enabled": True, "jump_host": "ops@jump2.test", "identity": "", "known_hosts": "/keys/kh",
               "host_key_checking": "accept-new", "extra_forwards": "8080:web.test:80\n\n 9090:db.test:5432 "}
tcfg = cw._mark_cleared(cw.tunnel_form_to_dict(tunnel_form), tunnel_form, conf.tunnel)
overrides = {
    "p1": {"url": "https://a2.test/dash", "title": "Alpha — Ops ✓", "vault_item": "item-a", "engine": "webkit",
           "selectors": {"user": "#user", "pass": "#pass"}, "login_marker": "", "allow_insecure": True,
           "allow_media": False, "proxy": False, "keepalive": {"strategy": "reload", "intervalSec": 90},
           "tenant": " acme ", "grid": [1, 1]},
    "p2": {"url": "http://b.test/", "title": "", "vault_item": "item-b", "engine": "webkit",
           "selectors": {"user": "#u", "pass": "#p", "submit": "#go"}, "login_marker": "#p",
           "allow_insecure": False, "allow_media": False, "proxy": True,
           "keepalive": {"strategy": "none", "intervalSec": 600}, "tenant": "",
           "login_zones": {"user": {"x_pct": 0.5, "y_pct": 0.25}, "submit": {"x_pct": 1.0, "y_pct": 0}}},
    "panel-4": {"url": "http://new.test/", "title": "New"},
    "_added_panels": [{"id": "panel-4", "grid": [1, 0]}],
    "_removed_panels": ["p3"],
    "_display": {"layout": "windows", "gap": 4, "cols": 3, "rows": 2, "auto": False,
                 "width": 2560, "height": 1440, "fullscreen": False},
    "_vpns": [saved, new_vpn], "_vpns_removed": ["dr"], "_vpn": saved,
    "_proxy": pcfg, "_tunnel": tcfg,
}
# p2 moves out of p1's way first, the way a Down/Up swap at the glass saves it.
overrides["p2"]["grid"] = [0, 0]
overrides["p1"]["grid"] = [1, 0]
overrides["_added_panels"][0]["grid"] = [2, 1]
cw.save_overrides(overrides)
assert cw.load_overrides() == overrides

# --- what the Python boot path makes of base + overrides ---
ov = cw.load_overrides()
cw.apply_display_override(conf.display, ov)
conf.vpns = cw.apply_vpns_override(conf.vpns, ov)
conf.vpn = conf.vpns[0] if conf.vpns else {}
cw.apply_proxy_override(conf.proxy, ov)
cw.apply_tunnel_override(conf.tunnel, ov)
cw.apply_overrides_to_panels(conf.panels, ov)
merged = cfg.to_yaml(conf)
cfg.load_str(merged, "merged")            # must still validate
open(os.path.join(out, "base.yaml"), "w").write(BASE)
open(os.path.join(out, "merged_expected.yaml"), "w").write(merged)

# --- pure form helpers: input -> output vectors ---
cases = []
def case(fn, *args):
    import copy
    a = copy.deepcopy(args)
    cases.append({"fn": fn.__name__, "args": list(a), "out": fn(*args)})
case(cw.vpn_form_to_dict, vpn_form)
case(cw.vpn_form_to_dict, {})
case(cw.vpn_form_to_dict, {"split_tunnel": False, "port": "443", "health_check_interval": -3, "ead": 1,
                           "gateway": "  gw  ", "type": "", "enabled": "yes", "captcha_retries": 2.9,
                           "spa_knock_port": "x"})
case(cw.proxy_form_to_dict, proxy_form)
case(cw.proxy_form_to_dict, {"enabled": 0, "url": "  ", "ignore_hosts": ["a", "", "b"]})
case(cw.proxy_form_to_dict, {})
case(cw.tunnel_form_to_dict, tunnel_form)
case(cw.tunnel_form_to_dict, {"host_key_checking": "no"})
case(cw.tunnel_form_to_dict, {"enabled": False, "host_key_checking": " YES ", "extra_forwards": ["1:a:2", ""]})
case(cw.tunnel_form_to_dict, {})
case(cw._mark_cleared, cw.vpn_form_to_dict(vpn_form), vpn_form, before)
case(cw._mark_cleared, {"enabled": True}, {"url": "", "vault_item": "", "ignore_hosts": ""},
     {"url": "http://x:1", "vault_item": "", "ignore_hosts": ["a"]})
json.dump(cases, open(os.path.join(out, "forms.json"), "w"), indent=2, sort_keys=True)

inv = cw._inventory_items(conf.panels, conf.vpns + [None], "pxy", {"vault_item": "tun"},
                          ["SOC Settings TOTP", "item-b", " "])
warn = cw._status_warnings("http://127.0.0.1:8222", "", False, False, 3, 0, ["p2", "p1"])
warn2 = cw._status_warnings("http://127.0.0.1:8222", "", True, True, 2, 1, [])
json.dump({"inventory": inv, "status_all": warn, "status_email": warn2},
          open(os.path.join(out, "misc.json"), "w"), indent=2, sort_keys=True, ensure_ascii=False)
print("ok")
