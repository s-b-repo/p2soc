"""RFC 3986-aware URL validation (config.valid_http_url) — the shared guard for
panel URLs at the glass, in the loader, and on live set_url."""
from host import config


def test_accepts_plain_http_https():
    assert config.valid_http_url("http://host")
    assert config.valid_http_url("https://host:8443/path?q=1#f")
    assert config.valid_http_url("http://127.0.0.1:19101/")
    assert config.valid_http_url("https://wazuh.internal.example/app/")


def test_empty_respects_allow_empty():
    assert config.valid_http_url("", allow_empty=True)
    assert config.valid_http_url(None, allow_empty=True)
    assert config.valid_http_url("   ", allow_empty=True)
    assert not config.valid_http_url("", allow_empty=False)
    assert not config.valid_http_url(None, allow_empty=False)


def test_rejects_dangerous_schemes():
    for u in ("javascript:alert(1)", "file:///etc/passwd",
              "data:text/html,<script>1</script>", "ftp://h/x", "about:blank"):
        assert not config.valid_http_url(u), u


def test_rejects_control_char_and_whitespace_smuggling():
    # scheme-smuggling / request-splitting via embedded control chars or spaces
    assert not config.valid_http_url("http://x\njavascript:alert(1)")
    assert not config.valid_http_url("http://e vil/path")
    assert not config.valid_http_url("http://host/\x00")
    assert not config.valid_http_url("http://host\t/x")


def test_rejects_embedded_credentials():
    assert not config.valid_http_url("https://user:pass@host/")
    assert not config.valid_http_url("http://admin@host/")


def test_rejects_hostless_urls():
    assert not config.valid_http_url("http://")
    assert not config.valid_http_url("https:///just/a/path")
    assert not config.valid_http_url("http://:8080/")
