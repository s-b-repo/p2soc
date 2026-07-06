"""FortiGate SSL-VPN authentication — TLS handshake, cookie login, keepalive."""
from __future__ import annotations

import re
import socket
import time
import urllib.parse
from typing import Optional, Callable

from . import constants as C
from .transport import tls_connect, TransportError


class AuthError(Exception):
    pass


def authenticate(
    host: str, port: int,
    user: str, password: str,
    *,
    pin_sha256: str = "",
    cafile: str = "",
    insecure: bool = False,
    realm: str = "",
    timeout: float = 30.0,
) -> tuple[socket.socket, str, dict]:
    """Authenticate to the FortiGate gateway.
    Returns (socket, svpncookie, tunnel_config)."""

    # 1) TLS handshake
    sock = tls_connect(host, port, pin_sha256, cafile, insecure, timeout)
    deadline = time.monotonic() + timeout

    def _send(s: socket.socket, data: bytes):
        s.settimeout(max(1.0, deadline - time.monotonic()))
        s.sendall(data)

    def _recv_http(s: socket.socket) -> tuple[int, dict, bytes]:
        s.settimeout(max(1.0, deadline - time.monotonic()))
        buf = b""
        while b"\r\n\r\n" not in buf:
            if time.monotonic() > deadline:
                raise TransportError("read deadline exceeded")
            chunk = s.recv(8192)
            if not chunk:
                raise TransportError("connection closed")
            buf += chunk
            if len(buf) > C.MAX_RESPONSE_SIZE:
                raise TransportError("response too large")
        hdr_end = buf.index(b"\r\n\r\n") + 4
        head = buf[:hdr_end]
        rest = buf[hdr_end:]
        lines = head.decode("latin-1").split("\r\n")
        status_line = lines[0]
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 else 0
        headers = {}
        for ln in lines[1:]:
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()

        # Read body: chunked or content-length
        te = headers.get("transfer-encoding", "").lower()
        body_bytes = b""
        if te == "chunked":
            buf = rest
            while True:
                while b"\r\n" not in buf:
                    if time.monotonic() > deadline:
                        raise TransportError("chunk deadline exceeded")
                    c = s.recv(8192)
                    if not c:
                        raise TransportError("connection closed")
                    buf += c
                size_line, buf = buf.split(b"\r\n", 1)
                try:
                    chunk_size = int(size_line.strip().split(b";")[0], 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    break
                while len(buf) < chunk_size + 2:
                    c = s.recv(min(8192, chunk_size + 2 - len(buf)))
                    if not c:
                        break
                    buf += c
                body_bytes += buf[:chunk_size]
                buf = buf[chunk_size + 2:]  # skip trailing \r\n
        else:
            cl = int(headers.get("content-length", 0))
            if cl > C.MAX_RESPONSE_SIZE:
                raise TransportError(f"Content-Length {cl} exceeds max")
            body_bytes = rest
            while len(body_bytes) < cl:
                if time.monotonic() > deadline:
                    raise TransportError("body deadline exceeded")
                chunk = s.recv(min(8192, cl - len(body_bytes)))
                if not chunk:
                    break
                body_bytes += chunk

        return status, headers, body_bytes

    def _get_cookie(headers: dict) -> str:
        sc = headers.get("set-cookie", "")
        # Accept SVPNCOOKIE, SVPNTMPCOOKIE, or any SVPN* variant
        for part in sc.split(";"):
            part = part.strip()
            if part.upper().startswith("SVPN") and "COOKIE=" in part:
                idx = part.index("=") + 1
                val = part[idx:].strip()
                if val:
                    return val
        return ""

    # 2) GET /remote/login — get initial cookie + realm if needed
    req = (f"GET {C.PATH_LOGIN} HTTP/1.1\r\n"
           f"Host: {host}:{port}\r\n"
           f"User-Agent: {C.UA_V7}\r\n"
           "Connection: keep-alive\r\n\r\n").encode("latin-1")
    try:
        _send(sock, req)
        status, hdrs, body = _recv_http(sock)
    except TransportError:
        sock.close()
        raise AuthError("GET /remote/login failed")

    svpncookie = _get_cookie(hdrs) or ""
    if status >= 400 and not svpncookie:
        sock.close()
        raise AuthError(f"GET /remote/login returned {status}")

    # 3) POST /remote/logincheck — authenticate
    params = {
        "username": user,
        "credential": password,
        "realm": realm,
        "ajax": "1",
    }
    post_body = urllib.parse.urlencode(params).encode("ascii")
    cookie_hdr = f"{C.SVPNCOOKIE}={svpncookie}" if svpncookie else ""

    req = (f"POST {C.PATH_LOGIN_CHECK} HTTP/1.1\r\n"
           f"Host: {host}:{port}\r\n"
           f"User-Agent: {C.UA_V7}\r\n"
           "Connection: keep-alive\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(post_body)}\r\n")
    if cookie_hdr:
        req += f"Cookie: {cookie_hdr}\r\n"
    req = (req + "\r\n").encode("latin-1") + post_body

    try:
        _send(sock, req)
        status, hdrs, body = _recv_http(sock)
    except TransportError:
        sock.close()
        raise AuthError("POST /remote/logincheck failed")

    new_cookie = _get_cookie(hdrs) or svpncookie
    if new_cookie:
        svpncookie = new_cookie

    body_str = body.decode("utf-8", errors="replace")[:1000]
    if status >= 400 or "Authentication failed" in body_str or \
       "Login failed" in body_str:
        m = re.search(r'returl=([^&]+)', body_str)
        if m:
            raise AuthError(f"authentication failed: "
                            f"{urllib.parse.unquote(m.group(1))[:200]}")
        raise AuthError(f"authentication failed (status {status})")

    # 4) Follow the post-login redirect to get the real SVPNCOOKIE.
    #    The gateway sets a temp cookie (SVPNTMPCOOKIE) on logincheck, then
    #    the real SVPNCOOKIE on the portal redirect.
    redirect_url = hdrs.get("location", "")
    if not redirect_url:
        # JS-based redirect: extract URL from body
        m = re.search(r"location\s*=\s*['\"]([^'\"]+)", body_str)
        if m:
            redirect_url = m.group(1)
    if redirect_url:
        req = (f"GET {redirect_url} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n"
               f"User-Agent: {C.UA_V7}\r\n"
               "Connection: keep-alive\r\n\r\n").encode("latin-1")
        try:
            _send(sock, req)
            status, hdrs, body = _recv_http(sock)
        except TransportError:
            pass
        new_cookie = _get_cookie(hdrs)
        if new_cookie:
            svpncookie = new_cookie

    if not svpncookie:
        sock.close()
        raise AuthError("no SVPNCOOKIE — authentication failed")

    # 4) Open a SECOND TLS connection for the tunnel (matches openfortivpn behaviour)
    sock2 = tls_connect(host, port, pin_sha256, cafile, insecure, timeout)
    deadline2 = time.monotonic() + timeout

    def _send2(s: socket.socket, data: bytes):
        s.settimeout(max(1.0, deadline2 - time.monotonic()))
        s.sendall(data)

    req = (f"GET {C.PATH_TUNNEL} HTTP/1.1\r\n"
           f"Host: {host}:{port}\r\n"
           f"User-Agent: {C.UA_V7}\r\n"
           "Connection: keep-alive\r\n"
           f"Cookie: {C.SVPNCOOKIE}={svpncookie}\r\n\r\n").encode("latin-1")
    try:
        _send2(sock2, req)
        sock.close()  # close auth socket, we use sock2 now
        nonlocal deadline
        deadline = deadline2  # update closed-over deadline for tunnel reads
        status2, hdrs2, body2 = _recv_http(sock2)
    except TransportError:
        sock.close()
        sock2.close()
        raise AuthError("GET /remote/fortisslvpn_xml failed")

    tcfg = _parse_tunnel_xml(body2, status2, hdrs2)
    if not tcfg:
        sock2.close()
        raise AuthError("could not parse tunnel config from gateway response")

    return sock2, svpncookie, tcfg


def _parse_tunnel_xml(body: bytes, status: int, hdrs: dict) -> dict:
    text = body.decode("utf-8", errors="replace")
    cfg = {"ip": "", "netmask": "255.255.255.255",
           "dns": [], "routes": [], "split_tunnel": False}

    for tag, key in [
        (r'<assigned[^>]*ip[^>]*>\s*([^<\s]+)', "ip"),
        (r'<ip4?[^>]*mask[^>]*>\s*([^<\s]+)', "netmask"),
        (r'<dns[^>]*>\s*([^<\s]+)', "dns"),
        (r'<route[^>]*>\s*([^<\s]+)', "routes"),
    ]:
        for m in re.finditer(tag, text, re.I):
            val = m.group(1).strip()
            if key == "dns":
                cfg["dns"].append(val)
            elif key == "routes":
                cfg["routes"].append(val)
            else:
                cfg[key] = val

    m = re.search(r'<split-tunnel[^>]*>\s*(\d)', text, re.I)
    if m and m.group(1) == "1":
        cfg["split_tunnel"] = True

    return cfg if cfg["ip"] else {}


def logout(sock: socket.socket, host: str, port: int, svpncookie: str):
    try:
        req = (f"GET {C.PATH_LOGOUT} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n"
               f"Cookie: {C.SVPNCOOKIE}={svpncookie}\r\n\r\n").encode()
        sock.settimeout(5.0)
        sock.sendall(req)
    except Exception:
        pass
