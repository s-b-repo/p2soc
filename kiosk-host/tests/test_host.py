"""Unit tests for the pure-Python parts of the kiosk host (no GTK/display)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from host import config, inject, vault  # noqa: E402


DEV_YAML = """
display: {auto: false, width: 1920, height: 1080, cols: 2, rows: 2, gap: 0}
panels:
  - id: p1
    engine: webkit
    grid: [0, 0]
    mode: direct
    url: "http://10.0.0.1:3000/login"
    vault_item: "Item 1"
    selectors: {user: "#u", pass: "input[name=\\"pw\\"]", submit: ".go"}
    login_marker: "#u"
    keepalive: {strategy: reload, intervalSec: 42}
  - id: p2
    engine: chromium
    grid: [1, 1]
    mode: tunnel
    tunnel: {local_port: 19103, remote_host: 10.20.0.7, remote_port: 8443}
    path: "/app"
    scheme: "http"
    vault_item: "Item 2"
    selectors: {user: "#u", pass: "#p", submit: "#s"}
    keepalive: {strategy: none}
tunnel: {enabled: true, jump_host: "u@jump", identity: "/k"}
vpn:
  enabled: true
  gateway: "vpn.example.net"
  port: 10443
  vault_item: "SOC FortiGate VPN"
  trusted_cert: "deadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafe0123"
  realm: "soc"
  set_routes: true
  set_dns: false
  half_internet_routes: true
  persistent: 30
  ready_probe: "10.50.0.5:443"
  extra_args: ["-v"]
"""


def _load():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(DEV_YAML)
        path = fh.name
    return config.load(path)


def test_geometry_2x2():
    conf = _load()
    g = {p.id: p.geometry for p in conf.panels}
    assert (g["p1"].w, g["p1"].h) == (960, 540)
    assert (g["p1"].x, g["p1"].y) == (0, 0)
    assert (g["p2"].x, g["p2"].y) == (960, 540)


def test_effective_url():
    conf = _load()
    p = {x.id: x for x in conf.panels}
    assert p["p1"].effective_url == "http://10.0.0.1:3000/login"
    assert p["p2"].effective_url == "http://127.0.0.1:19103/app"
    assert p["p2"].tunnel_local_port == 19103
    assert p["p1"].wmclass == "soc-p1"


def test_vpn_config_parsed():
    conf = _load()
    assert conf.vpn["enabled"] is True
    assert conf.vpn["gateway"] == "vpn.example.net"
    assert conf.vpn["vault_item"] == "SOC FortiGate VPN"
    assert conf.vpn["ready_probe"] == "10.50.0.5:443"


def test_openfortivpn_args_builder():
    conf = _load()
    args = config.openfortivpn_args(conf.vpn)
    assert args[0] == "vpn.example.net:10443"          # gateway:port first
    assert ("--trusted-cert=deadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafe"
            "deadbeefcafe0123") in args
    assert "--realm=soc" in args
    assert "--set-routes=1" in args
    assert "--set-dns=0" in args                        # explicit 0, not omitted
    assert "--half-internet-routes=1" in args
    assert "--persistent=30" in args
    assert args[-1] == "-v"                             # extra_args passed through
    # the non-secret arg list must never carry username / password / pinentry
    joined = " ".join(args).lower()
    assert "pinentry" not in joined and "password" not in joined
    assert not any(a == "-u" or a.startswith("--password") for a in args)


def test_openfortivpn_args_empty_without_gateway():
    assert config.openfortivpn_args({}) == []
    assert config.openfortivpn_args({"port": 443, "enabled": True}) == []


def test_openfortivpn_persistent_is_opt_in():
    # --persistent is NOT emitted by default (the supervisor owns reconnect) ...
    base = {"gateway": "gw", "port": 443}
    assert not any("--persistent" in a for a in config.openfortivpn_args(base))
    assert not any("--persistent" in a
                   for a in config.openfortivpn_args({**base, "persistent": 0}))
    # ... but is honoured verbatim when the operator sets it explicitly
    assert "--persistent=30" in config.openfortivpn_args({**base, "persistent": 30})


def test_inject_substitution_and_escaping():
    conf = _load()
    p1 = conf.panels[0]
    js = inject.bootstrap_js(p1, mode="webkit")
    for tok in ("{{PANEL_ID}}", "{{USER_SEL}}", "{{PASS_SEL}}", "{{SUBMIT_SEL}}",
                "{{LOGIN_MARKER}}", "{{MODE}}", "{{KEEPALIVE_JSON}}",
                "{{ALLOWED_ORIGIN}}"):
        assert tok not in js                          # every placeholder filled
    assert '"p1"' in js
    assert '"reload"' in js and "42" in js
    # a selector containing a double quote must be JSON-escaped, not raw
    assert 'input[name=\\"pw\\"]' in js
    # autofill origin gate: filled from the panel's effective_url origin
    # (default ports omitted; non-default port kept) — matches location.origin.
    assert '"http://10.0.0.1:3000"' in js


def test_inject_panel_origin():
    # http(s) origins: scheme + host, default ports omitted, others kept.
    assert inject.panel_origin("http://10.0.0.1:3000/login") == "http://10.0.0.1:3000"
    assert inject.panel_origin("https://soc.example/path?q=1") == "https://soc.example"
    assert inject.panel_origin("http://host:80/x") == "http://host"
    assert inject.panel_origin("https://host:443/x") == "https://host"
    # non-http(s) / unparseable -> '' (gate stays unset = legacy fill-anywhere).
    assert inject.panel_origin("") == ""
    assert inject.panel_origin("file:///etc/passwd") == ""
    assert inject.panel_origin("data:text/html,x") == ""


def test_inject_origin_gate_unset_for_tunnel_without_port():
    # A tunnel panel whose local_port isn't resolved yet has no effective_url,
    # so the gate stays unset ('') rather than blocking all autofill.
    conf = _load()
    p2 = conf.panels[1]
    p2.tunnel = {}                                    # drop local_port
    js = inject.bootstrap_js(p2, mode="chromium")
    assert 'allowedOrigin: ""' in js

    call = inject.login_call({"user": 'a"b', "pass": "p\\x"})
    assert '\\"' in call                               # quote escaped
    assert "socLogin(" in call


def test_vault_dev_backend(monkeypatch):
    data = {"Item 1": {"username": "u1", "password": "s3cr3t"}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        path = fh.name
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    monkeypatch.setenv("SOC_DEV_VAULT", path)
    v = vault.Vault()
    v.open()
    c = v.creds("Item 1")
    assert c == {"user": "u1", "pass": "s3cr3t"}
    # caching: second call returns same without error
    assert v.creds("Item 1")["pass"] == "s3cr3t"


def test_vault_dev_missing_item(monkeypatch):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({}, fh)
        path = fh.name
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    monkeypatch.setenv("SOC_DEV_VAULT", path)
    v = vault.Vault()
    v.open()
    try:
        v.creds("nope")
        assert False, "expected VaultError"
    except vault.VaultError:
        pass


# --------------------------------------------------------------------------- #
# Config validation (clear error handling)
# --------------------------------------------------------------------------- #
def _load_yaml_text(text):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(text)
        path = fh.name
    return config.load(path)


def _expect_error(yaml_text, *snippets):
    try:
        _load_yaml_text(yaml_text)
    except config.ConfigError as e:
        for s in snippets:
            assert s in str(e), f"expected {s!r} in error:\n{e}"
        return
    raise AssertionError(f"expected ConfigError with {snippets}")


MINIMAL_PANEL = """
    vault_item: "X"
    selectors: {user: "#u", pass: "#p", submit: "#s"}
"""


def test_validation_collects_everything():
    # several independent problems must all be reported at once
    try:
        _load_yaml_text("""
display: {cols: 2, rows: 2, layout: bogus}
panels:
  - id: p1
    mode: direct
    url: "http://ok/login"
    vault_item: "X"
    selectors: {user: "#u"}
  - id: p1
    grid: [5, 0]
    url: "ftp://nope"
""" + MINIMAL_PANEL)
    except config.ConfigError as e:
        msg = str(e)
        assert "display.layout" in msg
        assert "selectors.pass is required" in msg     # has vault_item but no pass
        assert "used more than once" in msg
        assert "outside the 2x2 grid" in msg
        assert "http:// or https://" in msg
        return
    raise AssertionError("expected ConfigError")


def test_validation_display_only_and_unconfigured_panels():
    # a panel with no vault_item is display-only (selectors optional);
    # a direct panel with no url is "unconfigured" — a warning, not an error
    conf = _load_yaml_text("""
panels:
  - id: a
    grid: [0, 0]
    url: "http://dash/"
  - id: b
    grid: [1, 0]
    title: "Wazuh"
""")
    assert conf.panels[0].auto_login is False            # no vault_item
    assert conf.panels[0].configured is True
    assert conf.panels[1].configured is False            # no url yet
    assert conf.panels[1].display_name == "Wazuh"
    assert any("not configured" in w.lower() or "no url" in w.lower()
               for w in conf.warnings)


def test_validation_vault_item_requires_selectors():
    _expect_error("""
panels:
  - id: a
    grid: [0, 0]
    url: "http://x/"
    vault_item: "Acct"
""", "selectors")


def test_panel_allow_insecure():
    conf = _load_yaml_text("""
panels:
  - id: a
    grid: [0, 0]
    url: "https://self-signed.lan/"
    allow_insecure: true
""")
    assert conf.panels[0].allow_insecure is True
    _expect_error("""
panels:
  - id: a
    grid: [0, 0]
    url: "https://x/"
    allow_insecure: "yes"
""", "allow_insecure must be true or false")


def test_validation_duplicate_cells_and_ports():
    _expect_error("""
panels:
  - id: a
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19000, remote_host: h}
""" + MINIMAL_PANEL + """
  - id: b
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19000, remote_host: h}
""" + MINIMAL_PANEL + """
tunnel: {enabled: true, jump_host: "u@j"}
""", "share grid cell", "local_port 19000 is used by more than one panel")


def test_validation_tunnel_path_must_start_with_slash():
    # a tunnel `path` is concatenated straight into effective_url, so a value
    # without a leading slash (e.g. userinfo injection "@evil.com/x") must be
    # rejected — it would redirect the loopback panel to an attacker host.
    _expect_error("""
panels:
  - id: t1
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19002, remote_host: h}
    path: "@evil.com/dash"
""" + MINIMAL_PANEL + """
tunnel: {enabled: true, jump_host: "u@j"}
""", "tunnel path must be a string starting with '/'")
    # a non-string path is also rejected (would crash the effective_url f-string)
    _expect_error("""
panels:
  - id: t1
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19002, remote_host: h}
    path: 123
""" + MINIMAL_PANEL + """
tunnel: {enabled: true, jump_host: "u@j"}
""", "tunnel path must be a string starting with '/'")
    # a normal "/..." path is accepted unchanged, and resolves to loopback
    conf = _load_yaml_text("""
panels:
  - id: t1
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19002, remote_host: h}
    path: "/dash"
""" + MINIMAL_PANEL + """
tunnel: {enabled: true, jump_host: "u@j"}
""")
    assert conf.panels[0].effective_url == "http://127.0.0.1:19002/dash"


def test_validation_single_layout_rejects_chromium():
    _expect_error("""
display: {layout: single}
panels:
  - id: c1
    engine: chromium
    url: "http://x/login"
""" + MINIMAL_PANEL, "layout 'single' cannot host chromium panels")


def test_validation_tunnel_needs_jump_host():
    _expect_error("""
panels:
  - id: t1
    mode: tunnel
    tunnel: {local_port: 19001, remote_host: h}
""" + MINIMAL_PANEL + """
tunnel: {enabled: true}
""", "jump_host is not set")


def test_validation_vpn():
    _expect_error("""
panels: []
vpn:
  enabled: true
  port: 99999
  trusted_cert: "tooshort"
  ready_probe: "noport"
""", "gateway", "vault_item", "vpn.port", "sha256", "want 'host:port'")


def test_validation_vpn_health_check_needs_probe():
    _expect_error("""
panels: []
vpn:
  enabled: true
  gateway: "gw.example"
  vault_item: "VPN"
  health_check_interval: 60
""", "health_check_interval is set but vpn.ready_probe is empty")


# --- trusted_cert: accept both sha256 (64-hex) and sha1 (40-hex) pins ---------
_SHA256 = "deadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafe0123"  # 64
_SHA1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"                            # 40, upper


def _forti_yaml(cert):
    return f"""
panels: [{{id: a, grid: [0,0], url: "http://x/"}}]
vpn: {{enabled: true, type: fortinet, gateway: gw.example, vault_item: VPN,
       trusted_cert: "{cert}"}}
"""


def test_trusted_cert_accepts_sha256_and_sha1():
    # sha256 (64 hex) — the preferred pin
    c = _load_yaml_text(_forti_yaml(_SHA256))
    assert c.vpn["trusted_cert"] == _SHA256
    # sha1 (40 hex, case-insensitive) — openfortivpn accepts it, so do we
    assert config._is_cert_pin(_SHA1)
    assert config._is_cert_pin(_SHA1.lower())
    c = _load_yaml_text(_forti_yaml(_SHA1))
    assert c.vpn["trusted_cert"] == _SHA1


def test_trusted_cert_rejects_bad_pin():
    # wrong length (48), non-hex, and the sha256-only message is now sha1+sha256
    _expect_error(_forti_yaml("deadbeef" * 6), "sha256", "sha1")
    _expect_error(_forti_yaml("z" * 64), "sha256", "sha1")   # 64 chars but non-hex
    assert not config._is_cert_pin("")
    assert not config._is_cert_pin("AA:BB:CC")               # colon form is iNode's


# --- iNode trusted_cert: warn (not error) on a malformed pin ------------------
def _inode_yaml(cert):
    return f"""
panels: [{{id: a, grid: [0,0], url: "http://x/"}}]
vpn: {{enabled: true, type: inode, gateway: g, vault_item: VPN,
       trusted_cert: "{cert}"}}
"""


def test_inode_trusted_cert_warns_on_bad_pin():
    # a typo'd/truncated iNode pin loads (it fails closed at connect time) but
    # must surface a config warning so it isn't a silent false sense of pinning.
    conf = _load_yaml_text(_inode_yaml("nothex"))
    assert any("trusted_cert" in w and "cert pin" in w for w in conf.warnings), \
        conf.warnings
    # a real sha256 pin in the ':'-separated --pin-sha256 form is fine (no warning)
    colon_pin = ":".join(_SHA256[i:i + 2] for i in range(0, 64, 2))   # AA:BB:..
    conf = _load_yaml_text(_inode_yaml(colon_pin))
    assert not any("trusted_cert" in w and "cert pin" in w for w in conf.warnings), \
        conf.warnings
    # a bad pin is a WARNING, never a hard error (behaviour-preserving)
    assert config.vpn_kind(conf.vpn) == "inode"


# --- gateway validation: accept real gateways, reject garbage -----------------
def test_gateway_validation_accepts_real_hosts():
    for host in ("vpn.example.net", "fw01", "10.50.0.1", "2001:db8::1",
                 "[2001:db8::1]", "vpn-gw.corp.example.com", "fe80::1%eth0"):
        assert config._is_gateway_host(host), host
        c = _load_yaml_text(f"""
panels: [{{id: a, grid: [0,0], url: "http://x/"}}]
vpn: {{enabled: true, type: fortinet, gateway: "{host}", vault_item: VPN}}
""")
        assert c.vpn["gateway"] == host


def test_gateway_validation_rejects_garbage():
    for bad in ("a b", "gw;rm -rf", "http://gw/", "gw$(id)", "gw|nc", "-leadingdash",
                "tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong"
                + ".x", ""):
        assert not config._is_gateway_host(bad), bad
    _expect_error("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: fortinet, gateway: "gw with space", vault_item: VPN}
""", "not a valid hostname or IP")
    # iNode gateway is validated the same way (also passed as argv)
    _expect_error("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: inode, gateway: "bad;host", vault_item: VPN}
""", "not a valid hostname or IP")


# --- vpn.interface override for status detection ------------------------------
def test_vpn_interface_override():
    from host import vpnstatus
    # default (unset): per-type interface — behaviour unchanged
    assert config.vpn_interface({}) == ""
    assert vpnstatus._expected_iface({"type": "fortinet"}) == "ppp0"
    assert vpnstatus._expected_iface({"type": "openvpn"}) == "tun0"
    # explicit override wins for every type
    assert config.vpn_interface({"interface": " ppp1 "}) == "ppp1"
    assert vpnstatus._expected_iface({"type": "fortinet", "interface": "ppp7"}) == "ppp7"
    assert vpnstatus._expected_iface({"type": "openvpn", "interface": "tun9"}) == "tun9"
    assert vpnstatus._expected_iface(
        {"type": "wireguard", "config": "wg0", "interface": "wgcorp"}) == "wgcorp"
    # the override is a known key (no 'unknown key' warning)
    conf = _load_yaml_text("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: fortinet, gateway: gw.example, vault_item: VPN,
      interface: ppp1}
""")
    assert conf.vpn["interface"] == "ppp1"
    assert not any("interface" in w for w in conf.warnings)


def test_validation_warnings_for_unknown_keys():
    conf = _load_yaml_text("""
display: {cols: 2, rows: 2}
panels:
  - id: p1
    url: "http://x/login"
    vault_iten: "typo"
""" + MINIMAL_PANEL + """
vpn: {enabled: false, gatway: "typo.example"}
""")
    joined = "\n".join(conf.warnings)
    assert "unknown key 'vault_iten'" in joined
    assert "unknown key 'gatway'" in joined


def test_validation_yaml_and_missing_file_errors():
    try:
        config.load("/nonexistent/panels.yaml")
        raise AssertionError("expected ConfigError")
    except config.ConfigError as e:
        assert "not found" in str(e)
    try:
        _load_yaml_text("just a string")
        raise AssertionError("expected ConfigError")
    except config.ConfigError as e:
        assert "top level" in str(e)


def test_resolve_layout():
    conf = _load()                                   # p1 webkit + p2 chromium
    assert config.resolve_layout(conf, "x11") == "windows"
    assert config.resolve_layout(conf, "wayland") == "windows"   # chromium present
    conf.display.layout = "single"
    assert config.resolve_layout(conf, "wayland") == "single"    # explicit wins
    conf.display.layout = "auto"
    for p in conf.panels:
        p.engine = "webkit"
    assert config.resolve_layout(conf, "wayland") == "single"
    assert config.resolve_layout(conf, "x11") == "windows"


# --------------------------------------------------------------------------- #
# VPN supervisor primitives (host/fortivpn.py)
# --------------------------------------------------------------------------- #
from host import fortivpn  # noqa: E402


def test_fortivpn_classify_real_strings():
    # exact strings emitted by openfortivpn 1.24
    assert fortivpn.classify("INFO:   Tunnel is up and running.") == "up"
    assert fortivpn.classify(
        "ERROR:  Could not authenticate to gateway. Please check the password, "
        "client certificate, etc.") == "auth"
    assert fortivpn.classify(
        "ERROR:  Could not authenticate to the gateway. Please make sure tunnel "
        "mode is allowed by the gateway, check the realm, etc.") == "auth"
    assert fortivpn.classify("ERROR:  Gateway certificate validation failed.") == "cert"
    assert fortivpn.classify("INFO:   Closed connection to gateway.") == "down"
    assert fortivpn.classify("ERROR:  Could not start tunnel (xx).") == "down"
    assert fortivpn.classify("DEBUG:  something uninteresting") is None
    # progress line -> 'connecting' (logged only; must not be auth/cert/down)
    assert fortivpn.classify("INFO:   Connecting to gateway...") == "connecting"


def test_fortivpn_connecting_does_not_perturb_backoff():
    # EVENT_CONNECTING is progress feedback only: it must never land in _saw, so
    # it can't be misread as a drop and trigger reconnect/backoff. The driver
    # classifies it, and the supervisor's reader keeps it out of _saw.
    from host import vpndrivers
    assert vpndrivers.FortinetDriver().classify(
        "INFO:   Connecting to gateway...") == vpndrivers.EVENT_CONNECTING
    sup = fortivpn.Supervisor(
        {"enabled": True, "type": "fortinet", "vault_item": "VPN"},
        "", log=lambda m: None)
    sup._saw = set()

    class _Pipe:
        def __init__(self, lines):
            self._it = iter(lines)
        def readline(self):
            return next(self._it, "")
        def close(self):
            pass

    sup._reader(_Pipe(["INFO:   Connecting to gateway...\n", ""]))
    assert sup._saw == set()                       # progress did not pollute _saw
    assert fortivpn.EVENT_AUTH not in sup._saw and fortivpn.EVENT_DOWN not in sup._saw


def test_fortivpn_backoff():
    b = fortivpn.Backoff(initial=5, maximum=60, factor=2)
    assert [b.next() for _ in range(5)] == [5, 10, 20, 40, 60]
    assert b.next() == 60                            # capped
    b.reset()
    assert b.next() == 5


def test_fortivpn_deferred_backoff_reset():
    # A connect/drop flap shorter than the backoff floor must NOT reset the
    # backoff (it should climb 5,10,20,...); a connection that dwelt at least
    # the floor before dropping is real and resets back to the floor.
    import time
    sup = fortivpn.Supervisor(
        {"enabled": True, "type": "fortinet", "vault_item": "VPN"},
        "", log=lambda m: None)
    sup.backoff = fortivpn.Backoff(initial=5, maximum=60, factor=2)

    def drop_delay(dwell):
        """Mimic run()'s down-path rule for a tunnel that was up `dwell` s."""
        now = time.monotonic()
        sup._up_since = now - dwell if dwell is not None else 0.0
        if sup._up_since and (now - sup._up_since) >= sup.backoff.initial:
            sup.backoff.reset()
        return sup.backoff.next()

    # never came up this attempt -> climbs from the floor
    assert drop_delay(None) == 5
    # came up then dropped sub-floor (flap) -> keeps climbing, no reset
    assert drop_delay(0.0) == 10
    assert drop_delay(1.0) == 20
    # a real connection (dwell past the floor) -> resets back to the floor
    assert drop_delay(5.0) == 5
    # and a fresh flap after the reset climbs again
    assert drop_delay(0.0) == 10


def test_fortivpn_build_cmd():
    vpn = {"enabled": True, "gateway": "gw.example", "port": 443,
           "vault_item": "VPN", "set_routes": True}
    cmd = fortivpn.build_cmd(vpn, "alice", "/x/pinentry.sh", otp="123456")
    assert cmd[0] == "openfortivpn"
    assert cmd[1] == "gw.example:443"
    assert "-u" in cmd and cmd[cmd.index("-u") + 1] == "alice"
    assert "--pinentry=/x/pinentry.sh" in cmd
    assert "--otp=123456" in cmd
    # never a password on argv
    assert not any("password" in a.lower() for a in cmd)
    # no OTP flag when there is no OTP
    assert "--otp" not in " ".join(fortivpn.build_cmd(vpn, "a", "/p"))


def test_fortivpn_sd_notify(monkeypatch, tmp_path):
    import socket as socklib
    sock_path = str(tmp_path / "notify.sock")
    srv = socklib.socket(socklib.AF_UNIX, socklib.SOCK_DGRAM)
    srv.bind(sock_path)
    srv.settimeout(2)
    monkeypatch.setenv("NOTIFY_SOCKET", sock_path)
    fortivpn.sd_notify("READY=1\nSTATUS=test")
    assert srv.recv(256) == b"READY=1\nSTATUS=test"
    srv.close()
    # and a silent no-op without the socket
    monkeypatch.delenv("NOTIFY_SOCKET")
    fortivpn.sd_notify("WATCHDOG=1")


def test_fortivpn_watchdog_interval(monkeypatch):
    monkeypatch.setenv("WATCHDOG_USEC", "90000000")  # 90s -> ping every 45s
    assert fortivpn.SdWatchdog().interval == 45.0
    monkeypatch.delenv("WATCHDOG_USEC")
    assert fortivpn.SdWatchdog().interval == 0


# --------------------------------------------------------------------------- #
# WM config generators (openbox + labwc)
# --------------------------------------------------------------------------- #
import subprocess  # noqa: E402

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _run_gen(script, template, out, extra=()):
    r = subprocess.run(
        [sys.executable, os.path.join(_REPO, "scripts", script),
         "--panels", os.path.join(_REPO, "config", "panels.dev.yaml"),
         "--template", os.path.join(_REPO, template), "--out", out, *extra],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": os.path.join(_REPO, "kiosk-host")})
    assert r.returncode == 0, r.stderr
    with open(out, encoding="utf-8") as fh:
        return fh.read()


def test_gen_labwc_rules(tmp_path):
    out = _run_gen("gen-labwc-rc.py", "labwc/rc.xml.tmpl",
                   str(tmp_path / "rc.xml"))
    import xml.etree.ElementTree as ET
    root = ET.fromstring(out)
    rules = root.find("windowRules")
    assert len(list(rules)) == 8                     # identifier + title per panel
    idents = {r.get("identifier") for r in rules if r.get("identifier")}
    titles = {r.get("title") for r in rules if r.get("title")}
    assert idents == titles == {"soc-p1", "soc-p2", "soc-p3", "soc-p4"}
    move = rules[2].find("action[@name='MoveTo']")   # p2 -> top-right cell
    assert (move.get("x"), move.get("y")) == ("960", "0")
    resize = rules[2].find("action[@name='ResizeTo']")
    assert (resize.get("width"), resize.get("height")) == ("960", "540")


def test_gen_openbox_if_auto(tmp_path):
    # panels.dev.yaml has auto: true -> --if-auto applies the override
    out = _run_gen("gen-openbox-rc.py", "openbox/rc.xml.tmpl",
                   str(tmp_path / "rc.xml"),
                   extra=("--width", "1280", "--height", "720", "--if-auto"))
    assert "<width>640</width>" in out               # 1280/2


# --------------------------------------------------------------------------- #
# Proxy configuration + auth wiring (host/config.py, chromium_panel.py)
# --------------------------------------------------------------------------- #
_PROXY_BASE = """
panels:
  - id: p1
    grid: [0, 0]
    url: "http://10.0.0.1/login"
    vault_item: "X"
    selectors: {user: "#u", pass: "#p", submit: "#s"}
"""


def test_proxy_config_parsed():
    conf = _load_yaml_text(_PROXY_BASE + """
proxy:
  enabled: true
  url: "http://proxy.corp:3128"
  vault_item: "SOC Proxy"
  ignore_hosts: ["*.corp.lan"]
""")
    assert conf.proxy.enabled
    assert conf.proxy.url == "http://proxy.corp:3128"
    assert conf.proxy.vault_item == "SOC Proxy"
    # loopback is always appended to the bypass list, after the configured hosts
    ignore = config.proxy_ignore_hosts(conf.proxy)
    assert ignore[0] == "*.corp.lan"
    for h in ("localhost", "127.0.0.1", "::1"):
        assert h in ignore
    # default: panels use the proxy
    assert conf.panels[0].proxy is True


def test_proxy_panel_opt_out():
    conf = _load_yaml_text(_PROXY_BASE.replace(
        'selectors: {user: "#u", pass: "#p", submit: "#s"}',
        'selectors: {user: "#u", pass: "#p", submit: "#s"}\n    proxy: false'))
    assert conf.panels[0].proxy is False


def test_proxy_validation_errors():
    _expect_error(_PROXY_BASE + "proxy: {enabled: true}",
                  "'url' is not set")
    _expect_error(_PROXY_BASE + "proxy: {enabled: true, url: 'ftp://x:1'}",
                  "scheme must be one of")
    _expect_error(_PROXY_BASE + "proxy: {enabled: true, url: 'http://proxy.corp'}",
                  "missing port")
    # credentials must never live in the URL — they belong in the vault
    _expect_error(_PROXY_BASE + "proxy: {enabled: true, url: 'http://u:p@h:3128'}",
                  "must not embed credentials")


def test_proxy_panel_flag_must_be_bool():
    _expect_error("""
panels:
  - id: bad
    proxy: "yes"
    url: "http://10.0.0.1/login"
    vault_item: "X"
    selectors: {user: "#u", pass: "#p", submit: "#s"}
""", "proxy must be true or false")


def test_proxy_validation_socks_auth_warns():
    conf = _load_yaml_text(_PROXY_BASE + """
proxy: {enabled: true, url: "socks5://p.corp:1080", vault_item: "X"}
""")
    assert any("SOCKS" in w for w in conf.warnings)


def test_chromium_proxy_flags_no_secrets():
    from host import chromium_panel
    proxy = config.ProxyCfg(enabled=True, url="http://proxy.corp:3128",
                            vault_item="SOC Proxy", ignore_hosts=("*.lan",))
    flags = chromium_panel.proxy_flags(proxy)
    assert "--proxy-server=http://proxy.corp:3128" in flags
    bypass = [f for f in flags if f.startswith("--proxy-bypass-list=")][0]
    assert "*.lan" in bypass and "127.0.0.1" in bypass
    # the proxy credentials never appear on the command line
    assert not any("SOC Proxy" in f for f in flags)


def test_panel_url_props_are_none_safe():
    # A tunnel panel whose `tunnel` got nulled out by a live reconfigure / a
    # restored override must not raise on the GTK thread — it should degrade.
    conf = _load()
    p2 = {x.id: x for x in conf.panels}["p2"]
    assert p2.mode == "tunnel"
    p2.tunnel = None
    assert p2.effective_url == ""
    assert p2.tunnel_local_port is None


def test_chromium_cdp_origin_is_pinned_not_wildcard(monkeypatch, tmp_path):
    # The CDP debugger must accept ONLY the host's own origin; a wildcard would
    # let any rendered dashboard hijack CDP and read injected credentials.
    from host import chromium_panel
    assert chromium_panel.cdp_allowed_origin(9333) == "http://127.0.0.1:9333"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(chromium_panel, "_chromium_bin", lambda: "/bin/true")
    captured = {}

    class _FakePopen:
        def __init__(self, args, **kw):
            captured["args"] = args
        def poll(self):
            return None

    monkeypatch.setattr(chromium_panel.subprocess, "Popen", _FakePopen)
    p2 = {x.id: x for x in _load().panels}["p2"]
    panel = chromium_panel.ChromiumPanel(p2, lambda _p: None, lambda *_a: None,
                                         cdp_port=9333)
    panel._spawn()
    args = captured["args"]
    assert "--remote-allow-origins=http://127.0.0.1:9333" in args
    assert "--remote-allow-origins=*" not in args


def test_chromium_cdp_rpc_times_out_on_event_flood():
    # A flood of unsolicited events must not starve the matching reply forever;
    # rpc() has an overall deadline and raises rather than wedging the panel.
    from host import chromium_panel

    class _FloodWS:
        def send(self, _data):
            pass
        def recv(self):
            return json.dumps({"method": "Runtime.consoleAPICalled",
                               "params": {}})        # never a matching id

    cdp = chromium_panel._CDP(9333)
    cdp.ws = _FloodWS()
    import pytest
    with pytest.raises(chromium_panel.CDPError):
        cdp.rpc("Page.enable", timeout=0.2)


def test_chromium_cdp_rpc_returns_matching_result():
    from host import chromium_panel

    class _ReplyWS:
        def __init__(self):
            self._sent_id = None
        def send(self, data):
            self._sent_id = json.loads(data)["id"]
        def recv(self):
            return json.dumps({"id": self._sent_id, "result": {"ok": True}})

    cdp = chromium_panel._CDP(9333)
    cdp.ws = _ReplyWS()
    assert cdp.rpc("Page.enable") == {"ok": True}


def test_chromium_attach_failure_backs_off(monkeypatch):
    # Regression: when _spawn() succeeds but _attach_cdp() fails (DevTools socket
    # never becomes attachable), the control loop must back off and GROW the
    # respawn delay — not spin spawn->attach-fail->respawn with no wait and the
    # delay frozen at the 5s floor (an uncapped spawn loop on a 1 GB Pi).
    from host import chromium_panel

    p2 = {x.id: x for x in _load().panels}["p2"]
    panel = chromium_panel.ChromiumPanel(p2, lambda _p: None, lambda *_a: None,
                                         cdp_port=9333)

    class _AliveProc:
        returncode = None
        def poll(self):
            return None        # alive, so the loop proceeds to _attach_cdp

    monkeypatch.setattr(panel, "_spawn",
                        lambda: setattr(panel, "proc", _AliveProc()))

    # Always fail to attach, mirroring the real failure path (reap + clear proc).
    # Hard-stop after a bounded number of spawns so a regression (no backoff =>
    # _stop.wait never fires from this branch => endless spin) fails the test
    # fast instead of hanging the suite.
    attaches = []

    def _fail_attach():
        attaches.append(1)
        if len(attaches) > 20:
            panel._stop.set()
        panel.proc = None
        return False

    monkeypatch.setattr(panel, "_attach_cdp", _fail_attach)

    waited = []

    def _fake_wait(delay):
        waited.append(delay)
        if len(waited) >= 3:        # let the backoff climb a few times, then stop
            panel._stop.set()
        return panel._stop.is_set()

    monkeypatch.setattr(panel._stop, "wait", _fake_wait)
    panel._control_loop()

    # The attach-fail branch must wait each iteration (without the fix it never
    # waits — it spins) and the delay must grow, not stay pinned at the floor.
    assert len(waited) >= 2
    assert waited[0] == chromium_panel.RESPAWN_INITIAL
    assert waited[1] == min(chromium_panel.RESPAWN_INITIAL * 2,
                            chromium_panel.RESPAWN_MAX)
    assert waited == sorted(waited)        # monotonically non-decreasing


# --------------------------------------------------------------------------- #
# Input validation + resource usage
# --------------------------------------------------------------------------- #
def test_env_num_helpers(monkeypatch):
    monkeypatch.delenv("SOC_TEST_X", raising=False)
    assert config.env_int("SOC_TEST_X", 7) == 7              # missing -> default
    monkeypatch.setenv("SOC_TEST_X", "notanumber")
    assert config.env_int("SOC_TEST_X", 7) == 7              # garbage -> default
    monkeypatch.setenv("SOC_TEST_X", "999")
    assert config.env_int("SOC_TEST_X", 7, hi=100) == 100    # clamp to hi
    monkeypatch.setenv("SOC_TEST_X", "-5")
    assert config.env_int("SOC_TEST_X", 7, lo=0) == 0        # clamp to lo
    monkeypatch.setenv("SOC_TEST_X", "42")
    assert config.env_int("SOC_TEST_X", 7) == 42             # valid passes through
    monkeypatch.setenv("SOC_TEST_F", "")
    assert config.env_float("SOC_TEST_F", 2.0) == 2.0        # empty -> default
    monkeypatch.setenv("SOC_TEST_F", "1.5")
    assert config.env_float("SOC_TEST_F", 0.0) == 1.5


def test_probe_tcp_rejects_malformed():
    from host import fortivpn
    # malformed probes must return False, never raise (raising kills the health loop)
    for bad in ("", "hostonly", "host:notaport", "host:0", "host:99999", ":443"):
        assert fortivpn.probe_tcp(bad) is False


def test_vault_cache_evicts_expired(monkeypatch):
    import time as _t
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    v = vault.Vault(ttl=30.0)
    v._cache["stale"] = (_t.time() - 60.0, ("u", "p"))       # older than ttl
    v._cache["fresh"] = (_t.time(), ("u", "p"))
    assert v.cached("fresh") is True                          # sweeps on access
    assert "stale" not in v._cache                            # expired entry dropped
    assert "fresh" in v._cache


def test_mem_available_and_rss(tmp_path):
    from host import perf
    mi = tmp_path / "meminfo"
    mi.write_text("MemTotal:     1024000 kB\nMemAvailable:    65536 kB\nMemFree: 1 kB\n")
    assert perf.mem_available_mb(str(mi)) == 64               # 65536 KiB -> 64 MiB
    assert perf.mem_available_mb(str(tmp_path / "missing")) is None
    st = tmp_path / "status"
    st.write_text("Name:\tchromium\nVmRSS:\t  204800 kB\nThreads:\t9\n")
    assert perf.proc_rss_kb(0, str(st)) == 204800
    assert perf.proc_rss_kb(0, str(tmp_path / "nope")) is None


def test_under_pressure():
    from host import perf
    assert perf.under_pressure(50, 96) is True
    assert perf.under_pressure(200, 96) is False
    assert perf.under_pressure(None, 96) is False             # unknown -> not pressure


def test_heaviest_panel_picks_max_rss():
    from host import main as hostmain

    class FakeV:
        def __init__(self, pid, rss):
            self.panel = type("P", (), {"id": pid})()
            self._rss = rss
        def mem_rss_kb(self):
            return self._rss

    a, b, c = FakeV("a", 100), FakeV("b", None), FakeV("c", 300)
    assert hostmain.heaviest_panel([a, b, c]) is c            # largest measurable RSS
    assert hostmain.heaviest_panel([b]) is None               # none measurable
    assert hostmain.heaviest_panel([]) is None


def _run_restart_vpn_service(hostmain, monkeypatch, *, fail):
    """Drive KioskHost._restart_vpn_service synchronously: stub the worker thread
    to run inline, capture log lines, and record the subprocess.run call.

    Forces euid 0 so the privileged path takes the bare `/usr/bin/systemctl`
    form (no `sudo -n` prefix) — the helper restarts forti-vpn.service through
    _privileged_systemctl and surfaces stderr on failure."""
    calls = {}
    logs = []

    class _Res:
        def __init__(self, rc, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    def fake_run(argv, **kw):
        calls["argv"] = argv
        calls["kw"] = kw
        if fail:
            return _Res(1, "", "Failed to restart forti-vpn.service: access denied")
        return _Res(0, "ok", "")

    class InlineThread:
        def __init__(self, target, daemon=None):
            self._target = target
            self.daemon = daemon
        def start(self):
            self._target()

    import os as _os
    import subprocess as _sub
    import threading as _thr
    monkeypatch.setattr(_os, "geteuid", lambda: 0)   # root path: bare systemctl
    monkeypatch.setattr(_sub, "run", fake_run)
    monkeypatch.setattr(_thr, "Thread", InlineThread)
    monkeypatch.setattr(hostmain, "log", logs.append)
    # on_done is now marshalled to the GTK main thread via GLib.idle_add (it may
    # touch widgets); run it inline so the synchronous test still sees it fire.
    monkeypatch.setattr(hostmain.GLib, "idle_add",
                        lambda fn, *a: fn(*a))

    app = object.__new__(hostmain.KioskHost)        # no GTK app/window needed
    done = []
    # on_done now receives (ok, info) so the caller can surface the outcome.
    app._restart_vpn_service("ok!", "bad!",
                             on_done=lambda ok, info: done.append((ok, info)))
    return calls, logs, done


def test_restart_vpn_service_shape_and_on_done(monkeypatch):
    from host import main as hostmain

    calls, logs, done = _run_restart_vpn_service(hostmain, monkeypatch, fail=False)
    # privileged path (euid 0): bare /usr/bin/systemctl, full unit name, PIPE
    # streams (so stderr can be surfaced), 15s timeout.
    assert calls["argv"] == ["/usr/bin/systemctl", "restart", "forti-vpn.service"]
    assert calls["kw"]["timeout"] == 15
    import subprocess
    assert calls["kw"]["stdin"] == subprocess.DEVNULL
    assert calls["kw"]["stdout"] == subprocess.PIPE
    assert calls["kw"]["stderr"] == subprocess.PIPE
    assert logs == ["ok!"]                           # success message
    assert done == [(True, "ok")]                    # on_done ran with (ok, info)


def test_restart_vpn_service_failure_surfaces_stderr_and_runs_on_done(monkeypatch):
    from host import main as hostmain

    calls, logs, done = _run_restart_vpn_service(hostmain, monkeypatch, fail=True)
    assert calls["argv"] == ["/usr/bin/systemctl", "restart", "forti-vpn.service"]
    # fail message now carries the systemctl stderr (no longer swallowed)
    assert len(logs) == 1 and logs[0].startswith("bad!")
    assert "access denied" in logs[0]
    assert len(done) == 1 and done[0][0] is False          # on_done ran, ok=False
    assert "access denied" in done[0][1]                   # info carries stderr


def test_vpn_reconnect_done_surfaces_privilege_guidance(monkeypatch):
    """A refused reconnect (no NOPASSWD sudo) must put an actionable reason on the
    pill tooltip — not just snap the pill back to 'down' with the cause hidden in
    a log the kiosk operator never sees."""
    from host import main as hostmain

    monkeypatch.setattr(hostmain.GLib, "timeout_add_seconds",
                        lambda *a, **k: 0)

    class _Pill:
        def __init__(self):
            self.tip = None

        def set_tooltip_text(self, t):
            self.tip = t

    class _Wall:
        def __init__(self):
            self.vpn_pill = _Pill()

    app = object.__new__(hostmain.KioskHost)
    app.wall = _Wall()

    app._vpn_reconnect_done(False, "no NOPASSWD sudo for systemctl")
    tip = app.wall.vpn_pill.tip
    assert tip and "privilege" in tip and "VPN-log" in tip   # guidance, not silence

    # Success clears the guidance back to the neutral hint.
    app._vpn_reconnect_done(True, "ok")
    assert "re-check / reconnect" in app.wall.vpn_pill.tip


def test_can_systemctl_restart_root_is_true(monkeypatch):
    from host import main as hostmain
    import os as _os
    monkeypatch.setattr(_os, "geteuid", lambda: 0)
    app = object.__new__(hostmain.KioskHost)
    assert app._can_systemctl_restart() is True


def test_can_systemctl_restart_probe_shape_and_rc(monkeypatch):
    """Non-root: probes `sudo -n systemctl status forti-vpn.service`. rc 0/3/4
    means we cleared sudo's auth gate (NOPASSWD present); rc 1 means no rule.
    Result is cached so repeat calls don't re-probe."""
    from host import main as hostmain
    import os as _os
    import subprocess as _sub
    monkeypatch.setattr(_os, "geteuid", lambda: 1000)
    seen = {}

    class _Res:
        def __init__(self, rc):
            self.returncode = rc

    def make_run(rc):
        def fake_run(argv, **kw):
            seen["argv"] = argv
            seen["n"] = seen.get("n", 0) + 1
            return _Res(rc)
        return fake_run

    # rc 4 (no such unit) still means the sudoers gate passed -> True
    monkeypatch.setattr(_sub, "run", make_run(4))
    app = object.__new__(hostmain.KioskHost)
    assert app._can_systemctl_restart() is True
    assert seen["argv"] == ["sudo", "-n", "/usr/bin/systemctl", "status",
                            "forti-vpn.service"]
    # cached: a second call must NOT re-probe
    app._can_systemctl_restart()
    assert seen["n"] == 1

    # rc 1 (sudo: a password is required) -> no NOPASSWD rule -> False
    monkeypatch.setattr(_sub, "run", make_run(1))
    app2 = object.__new__(hostmain.KioskHost)
    assert app2._can_systemctl_restart() is False


# --------------------------------------------------------------------------- #
# Performance profile detection (host/perf.py)
# --------------------------------------------------------------------------- #
from host import perf  # noqa: E402


def test_perf_total_ram_mb(tmp_path):
    mi = tmp_path / "meminfo"
    mi.write_text("MemTotal:        1024000 kB\nMemFree: 1 kB\n")
    assert perf.total_ram_mb(str(mi)) == 1000
    assert perf.total_ram_mb(str(tmp_path / "missing")) is None


def test_perf_low_memory_env(monkeypatch):
    monkeypatch.setenv("SOC_LOW_MEMORY", "1")
    assert perf.low_memory() is True
    monkeypatch.setenv("SOC_LOW_MEMORY", "0")
    assert perf.low_memory() is False


def test_perf_hwaccel_mode(monkeypatch):
    for val in ("always", "never", "ondemand"):
        monkeypatch.setenv("SOC_WEBKIT_HWACCEL", val)
        assert perf.hwaccel_mode() == val
    # low-memory boards prefer on-demand acceleration
    monkeypatch.setenv("SOC_WEBKIT_HWACCEL", "auto")
    monkeypatch.setenv("SOC_LOW_MEMORY", "1")
    assert perf.hwaccel_mode() == "ondemand"


def test_perf_is_arm(monkeypatch):
    # aarch64 / arm64 Pi boards are ARM; x86 dev box is not. This branch is dead
    # on the x86 dev box (platform.machine()=='x86_64'), so monkeypatch it.
    for m in ("aarch64", "arm64", "armv7l", "armv6l"):
        monkeypatch.setattr(perf.platform, "machine", lambda m=m: m)
        assert perf.is_arm() is True
    monkeypatch.setattr(perf.platform, "machine", lambda: "x86_64")
    assert perf.is_arm() is False


def test_perf_has_gpu_render_node(monkeypatch):
    monkeypatch.setattr(perf.os, "listdir", lambda p: ["renderD128", "card0"])
    assert perf.has_gpu_render_node() is True
    monkeypatch.setattr(perf.os, "listdir", lambda p: ["card0"])
    assert perf.has_gpu_render_node() is False
    def _raise(p):
        raise OSError
    monkeypatch.setattr(perf.os, "listdir", _raise)   # no /dev/dri (x86 headless)
    assert perf.has_gpu_render_node() is False


def test_perf_hwaccel_mode_aarch64(monkeypatch):
    # On an aarch64 Pi with a V3D render node and no low-memory override, WebKit
    # gets ALWAYS. This is the arch branch that's dead on the x86 dev box.
    monkeypatch.delenv("SOC_LOW_MEMORY", raising=False)
    monkeypatch.setenv("SOC_WEBKIT_HWACCEL", "auto")
    monkeypatch.setattr(perf.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(perf, "has_gpu_render_node", lambda: True)
    monkeypatch.setattr(perf, "low_memory", lambda: False)
    assert perf.hwaccel_mode() == "always"
    # no render node -> engine default even on ARM
    monkeypatch.setattr(perf, "has_gpu_render_node", lambda: False)
    assert perf.hwaccel_mode() == "default"


def test_perf_hwaccel_mode_x86_default(monkeypatch):
    monkeypatch.delenv("SOC_LOW_MEMORY", raising=False)
    monkeypatch.setenv("SOC_WEBKIT_HWACCEL", "auto")
    monkeypatch.setattr(perf.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(perf, "low_memory", lambda: False)
    assert perf.hwaccel_mode() == "default"


def test_chromium_hwaccel_flags_arm(monkeypatch):
    # ARM + render node -> GPU flags present; x86 -> none (keeps make verify
    # byte-identical on the dev box).
    from host import chromium_panel
    monkeypatch.delenv("SOC_CHROMIUM_HWACCEL", raising=False)
    monkeypatch.setattr(chromium_panel.perf, "is_arm", lambda: True)
    monkeypatch.setattr(chromium_panel.perf, "has_gpu_render_node", lambda: True)
    flags = chromium_panel._hwaccel_flags()
    assert "--ignore-gpu-blocklist" in flags
    assert "--enable-gpu-rasterization" in flags
    assert "--use-gl=egl" in flags
    # opt-out override
    monkeypatch.setenv("SOC_CHROMIUM_HWACCEL", "never")
    assert chromium_panel._hwaccel_flags() == []
    # x86 dev box: no render node / not ARM -> no flags
    monkeypatch.delenv("SOC_CHROMIUM_HWACCEL", raising=False)
    monkeypatch.setattr(chromium_panel.perf, "is_arm", lambda: False)
    assert chromium_panel._hwaccel_flags() == []


# --------------------------------------------------------------------------- #
# On-screen config: PIN store + overrides persistence (host/configwin.py)
# --------------------------------------------------------------------------- #
def test_configwin_overrides_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    from host import configwin
    assert configwin.load_overrides() == {}
    configwin.save_overrides({"p1": {"url": "http://x/", "title": "X"}})
    again = configwin.load_overrides()
    assert again["p1"]["url"] == "http://x/" and again["p1"]["title"] == "X"


def test_configwin_credentials_note_is_backend_agnostic():
    # The Credentials-tab note shown on the wall must not name the legacy reader:
    # since litebw the default backend is litebw, not rbw (vault.py / install.sh).
    # Source-level check so it stays display-free (no GTK window needed).
    import inspect
    from host import configwin
    src = inspect.getsource(configwin.ConfigWindow._tab_credentials)
    assert "rbw" not in src.lower(), "config-window note must not mention rbw"


def test_configwin_pin_store(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    from host import configwin
    assert configwin.pin_is_set() is False          # optional — off by default
    configwin.set_pin("2468")
    assert configwin.pin_is_set() is True
    assert configwin.verify_pin("2468") is True
    assert configwin.verify_pin("0000") is False
    # stored as a salted digest, never the clear PIN, and 0600
    raw = open(tmp_path / "config.pin").read()
    assert "2468" not in raw and "$" in raw
    assert (os.stat(tmp_path / "config.pin").st_mode & 0o777) == 0o600
    configwin.clear_pin()
    assert configwin.pin_is_set() is False


def test_configwin_apply_overrides_to_panels(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    from host import configwin
    conf = _load_yaml_text("""
panels:
  - id: p1
    grid: [0, 0]
    title: "old"
""")
    assert conf.panels[0].configured is False        # no url yet
    configwin.apply_overrides_to_panels(
        conf.panels, {"p1": {"url": "http://set/", "title": "New"}})
    assert conf.panels[0].url == "http://set/"
    assert conf.panels[0].title == "New"
    assert conf.panels[0].configured is True


# --------------------------------------------------------------------------- #
# Multi-VPN: types, builders, drivers, validation (host/vpndrivers.py)
# --------------------------------------------------------------------------- #
from host import vpndrivers  # noqa: E402


def test_vpn_kind_default_and_types():
    assert config.vpn_kind({}) == "fortinet"
    assert config.vpn_kind({"type": "openvpn"}) == "openvpn"
    assert config.vpn_kind({"type": "WireGuard"}) == "wireguard"   # case-insensitive
    assert config.vpn_kind({"type": "bogus"}) == "fortinet"        # safe default


def test_openvpn_args_builder():
    a = config.openvpn_args({"config": "/etc/openvpn/soc.ovpn", "set_routes": False,
                             "extra_args": ["--verb", "3"]})
    assert a[:2] == ["--config", "/etc/openvpn/soc.ovpn"]
    assert "--route-nopull" in a
    assert a[-2:] == ["--verb", "3"]
    assert config.openvpn_args({}) == []                           # no config -> empty


def test_wireguard_target_and_cmds():
    d = vpndrivers.WireGuardDriver()
    vpn = {"config": "/etc/wireguard/wg0.conf"}
    assert config.wireguard_target(vpn) == "/etc/wireguard/wg0.conf"
    assert d.up_cmd(vpn) == ["wg-quick", "up", "/etc/wireguard/wg0.conf"]
    assert d.down_cmd(vpn) == ["wg-quick", "down", "/etc/wireguard/wg0.conf"]
    assert d.iface(vpn) == "wg0"
    assert d.iface({"config": "corp"}) == "corp"                   # bare interface name
    assert d.is_interface is True


def test_openvpn_driver_classify_real_strings():
    d = vpndrivers.OpenVPNDriver()
    assert d.classify("Mon ... Initialization Sequence Completed") == "up"
    assert d.classify("AUTH_FAILED,Auth ...") == "auth"
    assert d.classify("VERIFY ERROR: depth=0, error=...") == "cert"
    assert d.classify("Connection reset, restarting [0]") == "down"
    assert d.classify("OpenVPN 2.6 x86_64 ...") is None
    # username/password auth is what triggers vault use
    assert d.needs_creds({"vault_item": "X"}) is True
    assert d.needs_creds({}) is False
    # build_cmd takes NO credential argument — creds go over the mgmt socket
    cmd = d.build_cmd({"config": "/x.ovpn"}, mgmt_socket="/run/m.sock")
    assert "--management" in cmd and "/run/m.sock" in cmd
    assert "--management-hold" in cmd                   # held until creds are sent


def test_fortinet_driver_build_cmd_otp_is_only_secret_on_argv():
    # Pins the documented invariant (host/vpndrivers.py module docstring): the
    # password reaches openfortivpn via --pinentry (child env), NEVER argv; the
    # single-use OTP is the lone exception openfortivpn 1.x accepts only as
    # --otp= on argv. A future change that leaks the password onto argv, or that
    # silently appends an OTP flag when none was supplied, must break here.
    d = vpndrivers.FortinetDriver()
    vpn = {"enabled": True, "gateway": "gw.example", "port": 443,
           "vault_item": "VPN", "set_routes": True}
    cmd = d.build_cmd(vpn, "alice", "/x/pinentry.sh", otp="123456")
    assert cmd[0] == "openfortivpn"
    assert "-u" in cmd and cmd[cmd.index("-u") + 1] == "alice"
    assert "--pinentry=/x/pinentry.sh" in cmd
    assert "--otp=123456" in cmd                 # documented argv exception
    # the OTP is the ONLY secret on argv: no password, ever
    assert not any("password" in a.lower() for a in cmd)
    # no OTP flag at all when no OTP is supplied
    assert "--otp" not in " ".join(d.build_cmd(vpn, "alice", "/x/pinentry.sh"))


def test_fortivpn_otp_code_uses_configured_backend_cli(monkeypatch):
    # The per-attempt OTP fetch must shell out to the CLI of the SELECTED
    # backend (litebw default, rbw selectable) — not always `litebw`. Picking
    # the wrong CLI when SOC_VAULT_BACKEND=rbw means litebw may be absent, the
    # FileNotFoundError is swallowed, the OTP is dropped, and every connect
    # attempt fails auth into the supervisor's auth-lockout backoff.
    sup = fortivpn.Supervisor(
        {"enabled": True, "type": "fortinet", "vault_item": "VPN"},
        "", log=lambda m: None)
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="654321\n", stderr="")

    monkeypatch.setattr(fortivpn.subprocess, "run", fake_run)

    monkeypatch.setenv("SOC_VAULT_BACKEND", "rbw")
    assert sup._otp_code() == "654321"
    assert seen["cmd"] == ["rbw", "code", "VPN"]

    monkeypatch.setenv("SOC_VAULT_BACKEND", "litebw")
    assert sup._otp_code() == "654321"
    assert seen["cmd"] == ["litebw", "code", "VPN"]

    monkeypatch.delenv("SOC_VAULT_BACKEND", raising=False)   # default -> litebw
    assert sup._otp_code() == "654321"
    assert seen["cmd"] == ["litebw", "code", "VPN"]


def test_get_driver_dispatch():
    assert vpndrivers.get_driver({"type": "openvpn"}).kind == "openvpn"
    assert vpndrivers.get_driver({"type": "wireguard"}).kind == "wireguard"
    assert vpndrivers.get_driver({}).kind == "fortinet"


def test_vpn_validation_by_type():
    _expect_error("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: openvpn}
""", "type 'openvpn' requires 'config'")
    _expect_error("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: wireguard}
""", "type 'wireguard' requires 'config'")
    _expect_error("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: ipsec, config: x}
""", "vpn.type: must be one of")


def test_vpn_validation_openvpn_wireguard_ok():
    ov = _load_yaml_text("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: openvpn, config: "/etc/openvpn/soc.ovpn"}
""")
    assert config.vpn_kind(ov.vpn) == "openvpn"
    assert any("certificate-only" in w for w in ov.warnings)       # no vault_item
    wg = _load_yaml_text("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: wireguard, config: "/etc/wireguard/wg0.conf"}
""")
    assert config.vpn_kind(wg.vpn) == "wireguard"


def test_configwin_url_validation_and_perms(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    from host import configwin
    assert configwin.valid_url("") is True
    assert configwin.valid_url("https://host/path") is True
    assert configwin.valid_url("HTTP://Host") is True
    assert configwin.valid_url("file:///etc/passwd") is False
    assert configwin.valid_url("javascript:alert(1)") is False
    assert configwin.valid_url("data:text/html,x") is False
    # the overrides file is written 0600 (URLs can reveal internal hostnames)
    configwin.save_overrides({"p1": {"url": "http://internal/"}})
    assert (os.stat(tmp_path / "overrides.json").st_mode & 0o777) == 0o600
    # a hand-edited override with a bad scheme is ignored at merge time
    conf = _load_yaml_text("panels: [{id: p1, grid: [0,0]}]")
    configwin.apply_overrides_to_panels(conf.panels, {"p1": {"url": "file:///x"}})
    assert conf.panels[0].url is None


def test_vpn_wireguard_health_without_probe_ok():
    # wireguard can health-check via the peer handshake — no ready_probe needed
    wg = _load_yaml_text("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: wireguard, config: "/etc/wireguard/wg0.conf", health_check_interval: 30}
""")
    assert wg.vpn["health_check_interval"] == 30
    # but openvpn (TCP-probe based) still requires a ready_probe for that check
    _expect_error("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: openvpn, config: "/x.ovpn", health_check_interval: 30}
""", "ready_probe is empty")


def test_vpn_config_from_vault_validation():
    # config_from_vault swaps the config-path requirement for a vault_item
    ov = _load_yaml_text("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: openvpn, config_from_vault: true, vault_item: "SOC OVPN"}
""")
    assert ov.vpn["config_from_vault"] is True
    _expect_error("""
panels: [{id: a, grid: [0,0], url: "http://x/"}]
vpn: {enabled: true, type: wireguard, config_from_vault: true}
""", "config_from_vault needs 'vault_item'")


def test_vpn_materialize_config_from_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    vfile = tmp_path / "vault.json"
    vfile.write_text(json.dumps({"WG": {"username": "", "password": "x",
                                        "notes": "[Interface]\nPrivateKey=SECRET\n"}}))
    monkeypatch.setenv("SOC_DEV_VAULT", str(vfile))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    from host import fortivpn
    vpn = {"enabled": True, "type": "wireguard", "config": "wg0",
           "config_from_vault": True, "vault_item": "WG"}
    sup = fortivpn.Supervisor(vpn, "", log=lambda m: None)
    assert sup._materialize_config() is True
    path = sup._materialized
    assert path.endswith("wg0.conf")
    body = open(path, encoding="utf-8").read()
    assert "PrivateKey=SECRET" in body                 # the key came from the vault
    assert (os.stat(path).st_mode & 0o777) == 0o600     # transient + owner-only
    sup._cleanup_materialized()
    assert not os.path.exists(path)                     # removed on disconnect


def test_vpn_state_indicator():
    import socket as _s
    from host import vpnstatus
    assert vpnstatus.vpn_state({}) == "not_configured"
    assert vpnstatus.vpn_state({"enabled": False}) == "not_configured"
    # configured but the probe is unreachable -> offline
    assert vpnstatus.vpn_state(
        {"enabled": True, "type": "fortinet", "ready_probe": "127.0.0.1:1"}) == "offline"
    # a listening probe target -> online
    srv = _s.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    assert vpnstatus.vpn_state(
        {"enabled": True, "type": "wireguard", "config": "wg0",
         "ready_probe": f"127.0.0.1:{port}"}) == "online"
    srv.close()


def test_loginmemory(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    from host import loginmemory
    # origin = host:port (default ports normalised)
    assert loginmemory.domain_of("https://app.example.com:8443/login") == "app.example.com:8443"
    assert loginmemory.domain_of("https://app.example.com/x") == "app.example.com:443"
    assert loginmemory.vault_item_for("https://app.example.com/x") == ""
    loginmemory.remember("https://app.example.com/login", "App Login")
    # a different panel at the same origin finds the remembered login
    assert loginmemory.vault_item_for("https://app.example.com/other") == "App Login"
    # a different port is a different origin — no credential bleed
    assert loginmemory.vault_item_for("https://app.example.com:8443/") == ""
    assert (os.stat(tmp_path / "domain_logins.json").st_mode & 0o777) == 0o600
    # only the vault item NAME is stored, never a credential
    assert "App Login" in open(tmp_path / "domain_logins.json").read()
    # empty url / item are no-ops
    loginmemory.remember("", "X"); loginmemory.remember("http://h/", "")
    assert "h:80" not in loginmemory.load()


def test_loginmemory_remember_no_fd_leak_on_error(tmp_path, monkeypatch):
    # If os.fdopen raises before taking ownership of the mkstemp fd, the raw
    # descriptor must still be closed — otherwise a 24/7 wall leaks one fd per
    # failed remember() and eventually exhausts descriptors.
    import resource

    monkeypatch.setenv("SOC_STATE_DIR", str(tmp_path))
    from host import loginmemory

    real_fdopen = os.fdopen

    def boom(fd, *a, **k):
        # Simulate os.fdopen failing *before* it takes ownership of fd: the raw
        # descriptor is left open, so the production code must close it. We must
        # NOT close it here, or we'd mask the very leak this test checks for.
        raise OSError("injected")

    monkeypatch.setattr(loginmemory.os, "fdopen", boom)

    def open_fds() -> int:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        n = 0
        for i in range(min(soft, 4096)):
            try:
                os.fstat(i)
                n += 1
            except OSError:
                pass
        return n

    before = open_fds()
    for _ in range(200):
        loginmemory.remember("https://leak.example.com/login", "App Login")
    assert open_fds() == before
    # the write never landed, so nothing was remembered
    monkeypatch.setattr(loginmemory.os, "fdopen", real_fdopen)
    assert loginmemory.vault_item_for("https://leak.example.com/") == ""


def test_inject_prompt_calls():
    from host import inject
    c = inject.prompt_call('say "hi"')
    assert "window.socPrompt" in c and '\\"hi\\"' in c     # message is JSON-escaped
    assert "socPromptClear" in inject.prompt_clear_call()


# --------------------------------------------------------------------------- #
# vaultseed — Vaultwarden credential writer (offline crypto checks)
# --------------------------------------------------------------------------- #
def test_vaultseed_crypto_roundtrip():
    from host import vaultseed
    if not vaultseed.available():
        import pytest; pytest.skip("cryptography not installed")
    import os as _os
    ek, mk = _os.urandom(32), _os.urandom(32)
    s = vaultseed._enc(b"p@ss word!", ek, mk)
    assert s.startswith("2.") and "|" in s            # Bitwarden EncString type-2
    assert vaultseed._dec(s, ek, mk) == b"p@ss word!"
    # tampering with the ciphertext is caught by the MAC
    iv_b, ct_b, mac_b = s.split(".", 1)[1].split("|")
    bad = f"2.{iv_b}|{ct_b[:-2]}AA|{mac_b}"
    try:
        vaultseed._dec(bad, ek, mk)
        assert False, "MAC tamper not caught"
    except vaultseed.VaultSeedError:
        pass


def test_vaultseed_dec_rejects_bad_pkcs7_padding():
    # A MAC-valid ciphertext whose plaintext has an invalid PKCS7 final byte
    # (e.g. 0x00) must fail closed, not silently strip the wrong number of
    # bytes. Without the guard, last-byte 0x00 yields pt[:-0] == b'' and a
    # last byte > 16 over-strips — both returning a wrong key with no error.
    from host import vaultseed
    if not vaultseed.available():
        import pytest; pytest.skip("cryptography not installed")
    import os as _os
    import hashlib as _hashlib
    import hmac as _hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    ek, mk = _os.urandom(32), _os.urandom(32)
    iv = _os.urandom(16)
    for last in (0x00, 0x11):  # 0x00 (==len 0) and 17 (>16): both invalid
        plaintext = bytes([0x41] * 15) + bytes([last])  # exactly one block
        enc = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
        ct = enc.update(plaintext) + enc.finalize()
        mac = _hmac.new(mk, iv + ct, _hashlib.sha256).digest()
        s = f"2.{vaultseed._b64(iv)}|{vaultseed._b64(ct)}|{vaultseed._b64(mac)}"
        try:
            vaultseed._dec(s, ek, mk)
            assert False, f"bad PKCS7 padding {last:#x} not rejected"
        except vaultseed.VaultSeedError:
            pass


def test_vaultseed_dec_malformed_encstring_raises_vaultseederror():
    # _dec() runs on server-returned EncStrings: the account key tok['Key'] and,
    # in _find's loop, every cipher Name. A field with any '|' part-count other
    # than 3, or with non-base64 parts, used to raise a bare ValueError (bad
    # tuple-unpack / binascii.Error) that escaped the caller's per-item
    # `except VaultSeedError` and aborted the entire seed/find. Each must now
    # raise VaultSeedError so the single bad item is skipped, not crash.
    from host import vaultseed
    import os as _os
    ek, mk = _os.urandom(32), _os.urandom(32)
    b16 = vaultseed._b64(b"\x00" * 16)
    for bad in (
        "2.onlyone",                         # 1 part (no '|')
        f"2.{b16}|{b16}",                    # 2 parts
        "2." + "|".join(["AAAA"] * 4),       # 4 parts
        "no-dot-at-all",                     # no type separator -> 1 part
        "2.not-base64!!!|also!!!|nope!!!",   # 3 parts, none decodable
    ):
        try:
            vaultseed._dec(bad, ek, mk)
            assert False, f"malformed EncString not rejected: {bad!r}"
        except vaultseed.VaultSeedError:
            pass


def test_vault_prewarm_and_threadsafe_cache(monkeypatch, tmp_path):
    data = {"A": {"username": "ua", "password": "pa"},
            "B": {"username": "ub", "password": "pb"}}
    f = tmp_path / "v.json"
    f.write_text(json.dumps(data))
    monkeypatch.setenv("SOC_VAULT_BACKEND", "dev")
    monkeypatch.setenv("SOC_DEV_VAULT", str(f))
    v = vault.Vault(ttl=60)
    v.open()
    assert v.cached("A") is False
    # prewarm dedups + skips empties and populates the cache
    assert v.prewarm(["A", "B", "A", ""]) == 2
    assert v.cached("A") and v.cached("B")
    assert v.creds("A")["pass"] == "pa"
    # concurrent creds() from many threads is race-free
    import threading
    errs = []
    def grab():
        try:
            assert v.creds("B")["user"] == "ub"
        except Exception as e:  # noqa: BLE001
            errs.append(e)
    ts = [threading.Thread(target=grab) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert not errs
