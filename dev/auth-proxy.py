#!/usr/bin/env python3
"""
Tiny authenticating HTTP forward proxy for development/verification only.

Speaks classic absolute-form HTTP proxying (GET http://host:port/path) and
demands Proxy-Authorization: Basic <user:pass> — exactly what a corporate
authenticated proxy does — so the kiosk's vault-backed proxy auth can be
exercised end-to-end without real infrastructure.

Every upstream connection is forced to 127.0.0.1:<port-from-url>, whatever
hostname the client asked for. The verify script exploits this: panel URLs use
hostnames that do NOT resolve on the dev box (p1.soc.test), so a panel can
only render if its traffic really went through this proxy *and* authenticated.

Log lines (stdout):  407 <method> <url>   |   AUTH-OK <method> <url>

Usage: python3 dev/auth-proxy.py [port] [user] [password]
"""
import base64
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 3128
USER = sys.argv[2] if len(sys.argv) > 2 else "proxyuser"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "proxypass"

_HOP = {"connection", "keep-alive", "proxy-authorization", "proxy-connection",
        "proxy-authenticate", "te", "trailers", "transfer-encoding", "upgrade"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # a proxy must relay 3xx (and their Set-Cookie!) verbatim, not follow them
    def redirect_request(self, *_args, **_kw):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):          # quiet; we print our own lines
        pass

    def _say(self, what):
        print(f"{what} {self.command} {self.path}", flush=True)

    def _authorized(self) -> bool:
        hdr = self.headers.get("Proxy-Authorization", "")
        want = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        return hdr == f"Basic {want}"

    def _reject(self):
        self._say("407")
        body = b"proxy authentication required"
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="soc-dev-proxy"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def _serve(self):
        if not self.path.startswith("http://"):
            self.send_error(400, "absolute-form http:// URI required")
            return
        if not self._authorized():
            self._reject()
            return
        u = urlsplit(self.path)
        port = u.port or 80
        target = f"http://127.0.0.1:{port}{u.path or '/'}"
        if u.query:
            target += f"?{u.query}"
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(target, data=body, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in _HOP and k.lower() != "host":
                req.add_header(k, v)
        req.add_header("Host", u.netloc)
        try:
            with _OPENER.open(req, timeout=10) as r:
                data = r.read()
                self._say("AUTH-OK")
                self.send_response(r.status)
                for k, v in r.getheaders():
                    if k.lower() not in _HOP and k.lower() != "content-length":
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self._say(f"AUTH-OK({e.code})")
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in _HOP and k.lower() != "content-length":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError as e:
            self._say(f"UPSTREAM-FAIL({e})")
            self.send_error(502, f"upstream: {e}")

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _serve


if __name__ == "__main__":
    print(f"[auth-proxy] listening on 127.0.0.1:{PORT} "
          f"(Basic auth, user={USER})", flush=True)
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
