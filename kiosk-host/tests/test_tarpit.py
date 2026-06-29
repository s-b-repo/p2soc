"""Scanner-deception tarpit: pure-helper tests (no socket bind)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
import tarpit                                       # noqa: E402


def test_matches_known_paths():
    for p in ("/admin.php", "/wp-login.php", "/.env",
              "/phpmyadmin/", "/wp-admin/admin-ajax.php",
              "/actuator/health", "/api/v1/login", "/.git/HEAD"):
        assert tarpit._matches(p), f"should match: {p}"


def test_does_not_match_real_app_paths():
    for p in ("/", "/index.html", "/healthz", "/static/app.js",
              "/login", "/api"):
        assert not tarpit._matches(p), f"should NOT match: {p}"


def test_mime_picks_plausible_type():
    assert tarpit._mime_for("/.env")[0].startswith("text/plain")
    assert tarpit._mime_for("/api/v1/foo")[0] == "application/json"
    assert tarpit._mime_for("/actuator/env")[0] == "application/json"
    assert tarpit._mime_for("/admin.php")[0].startswith("text/html")
    assert tarpit._mime_for("/.git/HEAD")[0].startswith("text/plain")


def test_junk_bodies_have_plausible_shape():
    env = tarpit._junk_env(400)
    assert b"=" in env and env.count(b"\n") >= 1
    j = tarpit._junk_json(400)
    assert j.startswith(b"{") and j.endswith(b"}")
    h = tarpit._junk_html(400)
    assert h.startswith(b"<!doctype html") and b"</body></html>" in h
    t = tarpit._junk_text(400)
    assert len(t) > 0 and b" " not in t              # base64-ish, no whitespace


def test_ratelimiter_caps_burst_then_leaks():
    import time
    rl = tarpit.RateLimiter(burst=3, window=0.05)
    assert [rl.allow("9.9.9.9") for _ in range(5)] == [True, True, True, False, False]
    time.sleep(0.12)                                # window passes
    # leaked at least one token
    assert rl.allow("9.9.9.9") is True


def test_ratelimiter_per_ip_independent():
    rl = tarpit.RateLimiter(burst=2, window=1.0)
    assert [rl.allow("1.1.1.1") for _ in range(2)] == [True, True]
    assert rl.allow("1.1.1.1") is False              # 1.1.1.1 capped
    assert rl.allow("2.2.2.2") is True               # 2.2.2.2 unaffected


def test_ratelimiter_bounded_capacity():
    rl = tarpit.RateLimiter(burst=1, window=60.0, cap=4)
    for i in range(20):
        rl.allow(f"10.0.0.{i}")
    assert len(rl._buckets) <= 4                     # LRU evicted older IPs


# --- Phase 2 hardening tests ------------------------------------------------


def test_paths_reload_picks_up_external_file(tmp_path, monkeypatch):
    """SIGHUP reload reads PATHS_FILE: exact paths line-by-line, '/foo/*'
    syntax for prefix matches. Built-in defaults survive (additive)."""
    f = tmp_path / "paths.list"
    f.write_text("# comment\n/private/data\n/secrets/* \n\n")
    monkeypatch.setattr(tarpit, "PATHS_FILE", str(f))
    tarpit._reload_paths()
    assert tarpit._matches("/private/data")
    assert tarpit._matches("/secrets/anything")
    # Built-in defaults still present.
    assert tarpit._matches("/admin.php")


def test_paths_reload_falls_back_when_file_missing(tmp_path, monkeypatch):
    """Missing file → defaults restored; not an error condition."""
    nope = tmp_path / "does-not-exist.list"
    monkeypatch.setattr(tarpit, "PATHS_FILE", str(nope))
    tarpit._reload_paths()
    assert tarpit._matches("/admin.php")
    assert not tarpit._matches("/private/data")


def test_paths_reload_ignores_unreadable(tmp_path, monkeypatch, capsys):
    """A permissions-locked file gets a reload_failed log line but the
    live sets are untouched (defense in depth: bad file ≠ open tarpit)."""
    f = tmp_path / "locked.list"
    f.write_text("/should-not-load\n")
    f.chmod(0o000)
    monkeypatch.setattr(tarpit, "PATHS_FILE", str(f))
    # Seed something distinctive so we can detect overwrite.
    with tarpit._PATHS_LOCK:
        tarpit._EXACT_PATHS_LIVE = {"/sentinel"}
        tarpit._PREFIX_PATHS_LIVE = ()
    tarpit._reload_paths()
    captured = capsys.readouterr()
    # Live sets untouched.
    assert "/sentinel" in tarpit._EXACT_PATHS_LIVE
    assert "/should-not-load" not in tarpit._EXACT_PATHS_LIVE
    assert "paths_reload_failed" in captured.err
    # Restore so other tests aren't poisoned.
    f.chmod(0o644)
    tarpit._reload_paths()


def test_concurrency_semaphore_releases(monkeypatch):
    """Acquire the full pool, attempt one more, then release one and re-acquire.
    The BoundedSemaphore must release cleanly so workers come back."""
    import threading
    cap = 4
    sem = threading.BoundedSemaphore(cap)
    monkeypatch.setattr(tarpit, "_CONC", sem)
    monkeypatch.setattr(tarpit, "CONC_MAX", cap)
    held = [sem.acquire(blocking=False) for _ in range(cap)]
    assert all(held)
    # Pool exhausted — next non-blocking acquire fails.
    assert sem.acquire(blocking=False) is False
    sem.release()
    # And succeeds after release.
    assert sem.acquire(blocking=False) is True
    # Cleanup.
    for _ in range(cap):
        try: sem.release()
        except ValueError: break


def test_log_json_shape(capsys):
    """One JSON line per event; round-trip via json.loads."""
    tarpit._log_json("served", ip="1.2.3.4", path="/x",
                    status=200, bytes=10, drip_s=1.0)
    err = capsys.readouterr().err.strip()
    assert err, "expected a stderr line"
    rec = __import__("json").loads(err.splitlines()[-1])
    assert rec["event"] == "served"
    assert rec["ip"] == "1.2.3.4"
    assert rec["path"] == "/x"
    assert rec["status"] == 200
    assert "ts" in rec


def test_hit_counter_lru_eviction(monkeypatch):
    """Bumping past HIT_CAP evicts the oldest entry; newest survives."""
    monkeypatch.setattr(tarpit, "HIT_CAP", 8)
    import collections as _c
    monkeypatch.setattr(tarpit, "_HIT_COUNTS", _c.OrderedDict())
    for i in range(12):
        tarpit._bump_hit(f"10.0.0.{i}")
    counts = tarpit._HIT_COUNTS
    assert len(counts) == 8
    assert "10.0.0.11" in counts
    assert "10.0.0.0" not in counts        # evicted as the oldest


def test_dump_hits_emits_top_n(capsys, monkeypatch):
    """SIGUSR1 → metrics_dump line with the highest hitters first."""
    import collections as _c
    monkeypatch.setattr(tarpit, "_HIT_COUNTS", _c.OrderedDict())
    # Add 30 IPs with varying counts: ip i gets i hits.
    for i in range(1, 31):
        for _ in range(i):
            tarpit._bump_hit(f"203.0.113.{i}")
    tarpit._dump_hits()
    err = capsys.readouterr().err.strip()
    rec = __import__("json").loads(err.splitlines()[-1])
    assert rec["event"] == "metrics_dump"
    assert len(rec["top"]) == 20
    # Top entry has the most hits (.30) and the list is monotone-decreasing.
    assert rec["top"][0]["ip"] == "203.0.113.30"
    assert rec["top"][0]["hits"] == 30
    hits = [e["hits"] for e in rec["top"]]
    assert hits == sorted(hits, reverse=True)


def test_plausibility_headers_present(monkeypatch):
    """ETag + Last-Modified + Cache-Control present on a matched response."""
    hdrs = dict(tarpit._plausibility_headers("/admin.php", "1.2.3.4", 4096))
    assert hdrs["ETag"].startswith('W/"')
    assert "GMT" in hdrs["Last-Modified"]
    assert "no-store" in hdrs["Cache-Control"]


def test_etag_stable_within_hour_per_ip_path(monkeypatch):
    """Same (path, ip, hour) → same ETag (prevents 'are these the same
    response?' fingerprinting). Different ip → different ETag."""
    a = dict(tarpit._plausibility_headers("/admin.php", "1.2.3.4", 100))["ETag"]
    b = dict(tarpit._plausibility_headers("/admin.php", "1.2.3.4", 100))["ETag"]
    c = dict(tarpit._plausibility_headers("/admin.php", "9.9.9.9", 100))["ETag"]
    assert a == b
    assert a != c


def test_address_family_v4_default():
    assert tarpit._address_family("0.0.0.0") == __import__("socket").AF_INET
    assert tarpit._address_family("127.0.0.1") == __import__("socket").AF_INET


def test_address_family_v6_detected():
    import socket as _s
    assert tarpit._address_family("::") == _s.AF_INET6
    assert tarpit._address_family("::1") == _s.AF_INET6
    assert tarpit._address_family("2001:db8::1") == _s.AF_INET6


def test_max_line_and_headers_capped_globally():
    """Module import pins http.client._MAXLINE / _MAXHEADERS — any later
    BaseHTTPRequestHandler instance inherits the cap."""
    import http.client
    assert http.client._MAXLINE == 4096
    assert http.client._MAXHEADERS == 64

