"""SEC-6 regression: the autossh arg builder must verify the jump-host key."""
import importlib.util
import io
import os
import pytest
from contextlib import redirect_stdout


def _load():
    """Import scripts/tunnel-args.py fresh and return the module."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "tunnel-args.py")
    spec = importlib.util.spec_from_file_location("tunnel_args", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _run(panels_path):
    """Run main() against a panels file, returning the emitted args as lines."""
    m = _load()
    os.environ["SOC_PANELS_FILE"] = str(panels_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        m.main()
    return buf.getvalue().splitlines()


_PANELS = """\
display: {grid: "2x2"}
panels:
  - id: p1
    grid: [0, 0]
    mode: tunnel
    tunnel: {local_port: 19101, remote_host: 10.0.0.5, remote_port: 8443}
tunnel:
  enabled: true
  jump_host: "u@jump"
  __EXTRA__
"""


def _write(tmp_path, extra=""):
    p = tmp_path / "panels.yaml"
    p.write_text(_PANELS.replace("__EXTRA__", extra))
    return p


def test_default_is_strict_host_key_checking(tmp_path):
    args = _run(_write(tmp_path))
    assert "StrictHostKeyChecking=yes" in args
    assert "StrictHostKeyChecking=accept-new" not in args


def test_accept_new_is_explicit_optin(tmp_path):
    # accept-new (TOFU) is allowed only with an explicit, pinned known_hosts.
    args = _run(_write(
        tmp_path,
        extra='host_key_checking: "accept-new"\n'
              '  known_hosts: "/etc/soc-display/keys/known_hosts"'))
    assert "StrictHostKeyChecking=accept-new" in args
    assert "UserKnownHostsFile=/etc/soc-display/keys/known_hosts" in args


def test_accept_new_without_known_hosts_raises(tmp_path):
    # Weakening host-key checking without pinning known_hosts is a silent MITM
    # window — must raise rather than emit an accept-new tunnel.
    with pytest.raises(ValueError):
        _run(_write(tmp_path, extra='host_key_checking: "accept-new"'))


def test_unknown_value_falls_back_to_strict(tmp_path):
    # A bogus / unsafe value must NOT silently weaken verification.
    args = _run(_write(tmp_path, extra='host_key_checking: "no"'))
    assert "StrictHostKeyChecking=yes" in args
    assert "StrictHostKeyChecking=no" not in args


def test_known_hosts_is_passed_through(tmp_path):
    args = _run(_write(tmp_path, extra='known_hosts: "/etc/soc-display/keys/known_hosts"'))
    assert "UserKnownHostsFile=/etc/soc-display/keys/known_hosts" in args


# --------------------------------------------------------------------------- #
# extra_forwards shape validation (option-injection guard into ssh -L)
# --------------------------------------------------------------------------- #
def test_valid_extra_forward_unchanged():
    m = _load()
    spec = "127.0.0.1:19200:10.0.0.9:443"
    assert m._validate_extra_forward(spec) == spec


def test_valid_extra_forward_emitted_in_args(tmp_path):
    args = _run(_write(
        tmp_path, extra='extra_forwards: ["127.0.0.1:19200:10.0.0.9:443"]'))
    # appears as the value following a -L flag
    assert "127.0.0.1:19200:10.0.0.9:443" in args
    assert args[args.index("127.0.0.1:19200:10.0.0.9:443") - 1] == "-L"


@pytest.mark.parametrize("bad", [
    "-D 1080",                              # leading dash: looks like an ssh option
    "-L 127.0.0.1:1:h:2",
    "127.0.0.1:19200:10.0.0.9:443 -oProxyCommand=evil",  # embedded whitespace/option
    "127.0.0.1: 19200:10.0.0.9:443",        # internal whitespace
    "  127.0.0.1:19200:10.0.0.9:443",       # leading whitespace
    "127.0.0.1:19200:10.0.0.9",             # too few fields
    "127.0.0.1:notaport:10.0.0.9:443",      # non-numeric port
    "",                                      # empty
])
def test_bad_extra_forward_rejected(bad):
    m = _load()
    with pytest.raises(ValueError):
        m._validate_extra_forward(bad)


def test_bad_extra_forward_rejected_via_main(tmp_path):
    with pytest.raises(ValueError):
        _run(_write(tmp_path, extra='extra_forwards: ["-D 1080"]'))
