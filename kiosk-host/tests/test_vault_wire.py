"""The Vaultwarden wire protocol, against a server that behaves like the real one.

Every behaviour here was observed from a live Vaultwarden 1.37.5, not assumed. The
earlier code was written against an older API and its mocks encoded the same
assumptions, so all of these failed in production and passed in tests:

  * /api/accounts/register and /identity/accounts/register are gone (404);
  * registering is two steps, and the first returns the token as raw text, not JSON;
  * "signups are off" and "the account exists" are the same error message;
  * a cipher write without `encryptedFor` is rejected with HTTP 422.
"""
import base64
import http.server
import importlib.util
import json
import os
import sys
import threading

import pytest

from host import vaultseed, vaultsetup

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REFUSED = {"message": "Registration not allowed or user already exists"}
MISSING = {"message": "Registration is missing required parameters"}


class FakeVaultwarden(http.server.BaseHTTPRequestHandler):
    server_version = "fake-vw"

    def log_message(self, *a):
        pass

    def _send(self, code, body, raw=False):
        data = body.encode() if raw else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        s = self.server
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        s.requests.append((self.path, body))
        if s.legacy:
            if self.path == "/api/accounts/register":
                s.accounts.add(body["email"])
                return self._send(200, {})
            return self._send(404, {"error": "Not Found"})
        if self.path == "/identity/accounts/register/send-verification-email":
            if not s.signups:
                return self._send(400, REFUSED)
            return self._send(200, "eyJ.token.sig", raw=True)     # raw text, not JSON
        if self.path == "/identity/accounts/register/finish":
            if not body.get("emailVerificationToken"):
                return self._send(400, MISSING)
            if body["email"] in s.accounts or not s.signups:
                return self._send(400, REFUSED)
            s.accounts.add(body["email"])
            return self._send(200, {})
        return self._send(404, {"error": "Not Found"})


@pytest.fixture
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeVaultwarden)
    srv.requests, srv.accounts, srv.signups, srv.legacy = [], set(), True, False
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def paths(server):
    return [p for p, _ in server.requests]


# --- registration ------------------------------------------------------------- #

def test_registration_is_two_steps_and_sends_the_token(server):
    assert vaultsetup.register_account(server.url, "a@b.c", "master") == "created"
    assert paths(server) == ["/identity/accounts/register/send-verification-email",
                             "/identity/accounts/register/finish"]
    assert server.requests[1][1]["emailVerificationToken"] == "eyJ.token.sig"


def test_signups_off_is_reported_as_signups_off_not_as_an_existing_account(server):
    """The message contains both "not allowed" and "exists". Matching "exists" first
    told operators their password was wrong when the vault was simply closed."""
    server.signups = False
    with pytest.raises(vaultsetup.SignupsDisabledError):
        vaultsetup.register_account(server.url, "a@b.c", "master")


def test_a_malformed_registration_is_not_mistaken_for_signups_off(server, monkeypatch):
    """"Registration is missing..." contains "registration", which used to be enough
    to be reported as signups being disabled."""
    monkeypatch.setattr(vaultsetup, "_verification_token", lambda *a: "")
    server.legacy = False
    with pytest.raises(vaultseed.VaultSeedError) as e:
        vaultsetup.register_account(server.url, "a@b.c", "master")
    assert not isinstance(e.value, vaultsetup.SignupsDisabledError)


def test_older_server_still_works(server):
    server.legacy = True
    assert vaultsetup.register_account(server.url, "a@b.c", "master") == "created"
    assert paths(server)[-1] == "/api/accounts/register"


def test_empty_master_is_never_registered(server):
    with pytest.raises(vaultseed.VaultSeedError):
        vaultsetup.register_account(server.url, "a@b.c", "")
    assert server.requests == []


# --- ensure_account ------------------------------------------------------------ #

def _login(monkeypatch, works):
    from host import litebw

    class Session:
        def __init__(self, url, email, master):
            pass

        def list_ciphers(self):
            if not works:
                raise vaultseed.VaultSeedError("Username or password is incorrect")
            return []
    monkeypatch.setattr(litebw, "ReadSession", Session)


def test_existing_account_with_the_right_master_never_touches_registration(server, monkeypatch):
    _login(monkeypatch, True)
    assert vaultsetup.ensure_account(server.url, "a@b.c", "master") == "exists"
    assert server.requests == []


def test_new_account_is_created(server, monkeypatch):
    _login(monkeypatch, False)
    assert vaultsetup.ensure_account(server.url, "a@b.c", "master") == "created"


def test_closed_signups_surface_so_the_caller_can_open_them(server, monkeypatch):
    _login(monkeypatch, False)
    server.signups = False
    with pytest.raises(vaultsetup.SignupsDisabledError):
        vaultsetup.ensure_account(server.url, "a@b.c", "master")


def _prov():
    spec = importlib.util.spec_from_file_location(
        "soc_provision_wire", os.path.join(_REPO, "provision.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _account_step(monkeypatch, server, *, can_open=True):
    prov = _prov()
    monkeypatch.setattr(prov, "_load_vaultsetup", lambda: vaultsetup)
    monkeypatch.setattr(prov, "_can_open_signups", lambda: can_open)

    class Opened:
        def __init__(self, url):
            pass

        def __enter__(self):
            server.signups = True

        def __exit__(self, *a):
            server.signups = False
            return False
    monkeypatch.setattr(prov, "_SignupsOpen", Opened)
    return prov.step_vault_account(prov.Opts(email="a@b.c", url=server.url), "master")


def test_provision_opens_signups_for_exactly_one_registration(server, monkeypatch):
    _login(monkeypatch, False)
    server.signups = False
    res = _account_step(monkeypatch, server)
    assert res.ok and res.changed
    assert "a@b.c" in server.accounts
    assert server.signups is False           # closed again


def test_wrong_master_on_an_existing_account_is_named_as_such(server, monkeypatch):
    _login(monkeypatch, False)
    server.signups = False
    server.accounts.add("a@b.c")
    res = _account_step(monkeypatch, server)
    assert not res.ok
    assert "already exists" in res.detail and "master" in res.detail


def test_without_root_the_closed_signups_are_reported(server, monkeypatch):
    _login(monkeypatch, False)
    server.signups = False
    res = _account_step(monkeypatch, server, can_open=False)
    assert not res.ok
    assert "signups" in res.detail


# --- cipher writes ----------------------------------------------------------------- #

def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


def test_user_id_comes_from_the_access_token():
    assert vaultseed._token_subject(_jwt({"sub": "user-uuid"})) == "user-uuid"


@pytest.mark.parametrize("bad", ["", "notajwt", "a.%%%.c", "a.bm90anNvbg.c"])
def test_unreadable_token_is_not_fatal(bad):
    assert vaultseed._token_subject(bad) == ""


def _session(monkeypatch):
    s = vaultseed.Session.__new__(vaultseed.Session)
    s.base, s.auth, s.user_id = "http://x", {}, "user-uuid"
    s._e = lambda v: f"enc({v})"
    sent = []

    def fake_req(url, headers=None, data=None, method="GET", form=False):
        if method == "GET":
            return {"data": []}
        sent.append((method, url, data))
        return {}
    monkeypatch.setattr(vaultseed, "_req", fake_req)
    return s, sent


def test_login_write_names_the_user_it_was_encrypted_for(monkeypatch):
    s, sent = _session(monkeypatch)
    s._find_login = lambda name: None
    s.upsert_login("Item", "u", "p")
    assert sent[0][2]["encryptedFor"] == "user-uuid"


def test_note_write_names_the_user_it_was_encrypted_for(monkeypatch):
    s, sent = _session(monkeypatch)
    s._find = lambda name: None
    s._find_typed = lambda name, t: None
    s._folder_id = lambda folder: None
    s.upsert_secure_note("Item", "notes")
    assert sent[0][2]["encryptedFor"] == "user-uuid"


def test_pure_body_builders_stay_byte_identical():
    """The field is added at the session layer on purpose."""
    assert "encryptedFor" not in vaultseed._login_body(str, "n", "u", "p")
    assert "encryptedFor" not in vaultseed._note_body(str, "n", "x")
