"""Hardening tests for the VPN subsystem (host/fortivpn.py, host/vpndrivers.py).

Covers four defensive fixes:
  1) OpenVPN management-socket line-injection: _mgmt_sanitize strips CR/LF from
     both username and password.
  2) Materialized vault secrets cleaned on early exit: _cleanup_materialized is
     idempotent and tolerates a missing file.
  3) IPv6-aware host:port split: _split_host_port handles host:port, bracketed
     and bare IPv6 literals (RFC 3986).
  4) --otp on argv is a documented residual: build behavior is unchanged.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from host import fortivpn, vpndrivers  # noqa: E402


# --------------------------------------------------------------------------- #
# 1) _mgmt_sanitize — strip CR/LF from user + pass (mgmt-socket line injection)
# --------------------------------------------------------------------------- #
def test_mgmt_sanitize_strips_cr_lf():
    # a vault value with embedded newlines must not inject extra commands
    assert fortivpn._mgmt_sanitize("alice") == "alice"
    assert fortivpn._mgmt_sanitize("al\nice") == "alice"
    assert fortivpn._mgmt_sanitize("al\rice") == "alice"
    assert fortivpn._mgmt_sanitize("al\r\nice") == "alice"
    # the classic injection payload: a newline followed by a mgmt command
    assert fortivpn._mgmt_sanitize('user"\nsignal SIGTERM') == 'user"signal SIGTERM'
    # the empty / falsy cases never raise
    assert fortivpn._mgmt_sanitize("") == ""
    assert fortivpn._mgmt_sanitize(None) == ""


def test_mgmt_sanitize_applied_to_both_user_and_pass(tmp_path):
    # drive _openvpn_mgmt against a real AF_UNIX server and assert what is
    # written back contains NO CR/LF from the (malicious) creds.
    import socket
    import threading

    sock_path = str(tmp_path / "ovpn.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)

    received = []

    def serve():
        conn, _ = srv.accept()
        f = conn.makefile("rw")
        f.readline()                       # consume "hold release\n"
        f.write(">PASSWORD:Need 'Auth' username/password\n")
        f.flush()
        received.append(f.readline())      # username "Auth" ...
        received.append(f.readline())      # password "Auth" ...
        conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    sup = fortivpn.Supervisor({"type": "openvpn"}, "", log=lambda m: None)
    evil_user = "ad\nmin"
    evil_pass = "p\r\nsignal SIGTERM"
    sup._openvpn_mgmt(sock_path, (evil_user, evil_pass))
    t.join(timeout=3)
    srv.close()

    assert len(received) == 2, received
    user_line, pass_line = received
    # each write is exactly one line (its own trailing \n), with no injected CR/LF
    assert user_line == 'username "Auth" admin\n'
    assert pass_line == 'password "Auth" psignal SIGTERM\n'
    # belt and braces: no stray CR anywhere, and only the one trailing LF each
    for line in received:
        assert "\r" not in line
        assert line.count("\n") == 1


# --------------------------------------------------------------------------- #
# 3) _split_host_port — IPv6-aware host:port split (RFC 3986)
# --------------------------------------------------------------------------- #
def test_split_host_port_ipv4_and_hostname():
    assert fortivpn._split_host_port("host:443") == ("host", "443")
    assert fortivpn._split_host_port("10.50.0.5:443") == ("10.50.0.5", "443")
    assert fortivpn._split_host_port("host") == ("host", "")
    assert fortivpn._split_host_port("") == ("", "")
    assert fortivpn._split_host_port("  host:8443  ") == ("host", "8443")


def test_split_host_port_bracketed_ipv6():
    assert fortivpn._split_host_port("[2001:db8::1]:443") == ("2001:db8::1", "443")
    assert fortivpn._split_host_port("[::1]:443") == ("::1", "443")
    assert fortivpn._split_host_port("[2001:db8::1]") == ("2001:db8::1", "")
    # malformed bracket -> not parseable (host empty so probe_tcp rejects it)
    assert fortivpn._split_host_port("[2001:db8::1") == ("", "")


def test_split_host_port_bare_ipv6():
    # a bare IPv6 literal with a trailing port: only the last segment is the port
    assert fortivpn._split_host_port("2001:db8::1:443") == ("2001:db8::1", "443")


def test_probe_tcp_handles_ipv6_forms_without_raising():
    # the health loop must never raise on these; unreachable -> False, malformed -> False
    for probe in ("[2001:db8::1]:443", "2001:db8::1:443", "[::1]:1"):
        assert fortivpn.probe_tcp(probe, timeout=0.2) is False
    # still rejects the malformed cases the old rpartition path covered
    for bad in ("", "hostonly", "host:notaport", "host:0", "host:99999", ":443"):
        assert fortivpn.probe_tcp(bad) is False


# --------------------------------------------------------------------------- #
# 2) _cleanup_materialized — idempotent + tolerant of a missing file
# --------------------------------------------------------------------------- #
def test_cleanup_materialized_idempotent(tmp_path):
    sup = fortivpn.Supervisor({"type": "openvpn"}, "", log=lambda m: None)
    f = tmp_path / "openvpn-x.ovpn"
    f.write_text("secret\n")
    sup._materialized = str(f)

    sup._cleanup_materialized()
    assert not f.exists()                  # removed
    assert sup._materialized is None       # state reset
    # second call is a no-op and does not raise
    sup._cleanup_materialized()
    assert sup._materialized is None


def test_cleanup_materialized_tolerates_missing_file(tmp_path):
    sup = fortivpn.Supervisor({"type": "openvpn"}, "", log=lambda m: None)
    # the file was already removed out from under us
    sup._materialized = str(tmp_path / "gone.conf")
    sup._cleanup_materialized()             # must not raise
    assert sup._materialized is None
    # no _materialized set at all -> safe
    sup._cleanup_materialized()


def test_run_cleans_up_materialized_on_early_exit(tmp_path, monkeypatch):
    # guarantee the finally-wrapped run body removes the 0600 file even when the
    # loop body raises before reaching the normal stop path.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    sup = fortivpn.Supervisor({"type": "openvpn", "config": "/x.ovpn"}, "",
                              log=lambda m: None)
    f = tmp_path / "openvpn-leak.ovpn"
    f.write_text("PRIVATE KEY\n")
    sup._materialized = str(f)

    monkeypatch.setattr(sup, "_materialize_config", lambda: True)
    monkeypatch.setattr(sup, "_target", lambda: "OpenVPN")

    boom = RuntimeError("spawn blew up mid-loop")

    def explode():
        raise boom

    monkeypatch.setattr(sup, "_run_loop", explode)
    monkeypatch.setattr(fortivpn, "shutil",
                        type("S", (), {"which": staticmethod(lambda _b: "/usr/bin/openvpn")}))

    try:
        sup.run()
        assert False, "expected the loop to propagate its exception"
    except RuntimeError as e:
        assert e is boom
    # the secret file was cleaned up by the finally despite the exception
    assert not f.exists()
    assert sup._materialized is None


# --------------------------------------------------------------------------- #
# 4) --otp on argv is unchanged behavior (documented residual)
# --------------------------------------------------------------------------- #
def test_build_cmd_otp_still_on_argv_unchanged():
    vpn = {"enabled": True, "gateway": "gw.example", "port": 443,
           "vault_item": "VPN"}
    # module-level helper
    cmd = fortivpn.build_cmd(vpn, "alice", "/p/pinentry.sh", otp="123456")
    assert "--otp=123456" in cmd
    assert "--otp" not in " ".join(fortivpn.build_cmd(vpn, "a", "/p"))
    # password never on argv
    assert not any("password" in a.lower() for a in cmd)
    # driver path matches the module-level builder
    d = vpndrivers.FortinetDriver()
    dcmd = d.build_cmd(vpn, "alice", "/p/pinentry.sh", otp="123456")
    assert "--otp=123456" in dcmd
    assert "--otp" not in " ".join(d.build_cmd(vpn, "a", "/p"))
