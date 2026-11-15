"""Regression tests recovered from v1.3.0 (test_host.py): cases for this line's own
features that were lost when the suite was replaced. Kept separate so they stay
visibly additive to test_host.py."""
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


def test_openfortivpn_persistent_is_opt_in():
    # --persistent is NOT emitted by default (the supervisor owns reconnect) ...
    base = {"gateway": "gw", "port": 443}
    assert not any("--persistent" in a for a in config.openfortivpn_args(base))
    assert not any("--persistent" in a
                   for a in config.openfortivpn_args({**base, "persistent": 0}))
    # ... but is honoured verbatim when the operator sets it explicitly
    assert "--persistent=30" in config.openfortivpn_args({**base, "persistent": 30})


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


from host import fortivpn  # noqa: E402


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


_PROXY_BASE = """
panels:
  - id: p1
    grid: [0, 0]
    url: "http://10.0.0.1/login"
    vault_item: "X"
    selectors: {user: "#u", pass: "#p", submit: "#s"}
"""


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


from host import perf  # noqa: E402


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


def test_configwin_credentials_note_is_backend_agnostic():
    # The Credentials-tab note shown on the wall must not name the legacy reader:
    # since litebw the default backend is litebw, not rbw (vault.py / install.sh).
    # Source-level check so it stays display-free (no GTK window needed).
    import inspect
    from host import configwin
    src = inspect.getsource(configwin.ConfigWindow._tab_credentials)
    assert "rbw" not in src.lower(), "config-window note must not mention rbw"


from host import vpndrivers  # noqa: E402


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

    # litebw has an in-process backend, so it never spawns: a new process would
    # re-derive the sealed master on every retry (about 150 MiB each time).
    class Backend:
        def code(self, item):
            seen["item"] = item
            return "111222\n"

    class Vault:
        backend = Backend()

    seen.clear()
    monkeypatch.setenv("SOC_VAULT_BACKEND", "litebw")
    monkeypatch.setattr(sup, "_open_vault", lambda: Vault())
    assert sup._otp_code() == "111222"
    assert seen == {"item": "VPN"}            # no "cmd": nothing was spawned


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
