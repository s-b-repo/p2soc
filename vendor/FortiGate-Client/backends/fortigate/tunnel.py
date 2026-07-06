"""FortiGate SSL-VPN tunnel — pppd launch, keepalive, route/DNS setup."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from typing import Optional, Callable

from . import constants as C
from .auth import authenticate


class TunnelError(Exception):
    pass


class Tunnel:
    """Manages a PPP tunnel over the FortiGate TLS connection."""

    def __init__(self, sock: socket.socket, host: str, port: int,
                 svpncookie: str, tunnel_cfg: dict,
                 *,
                 set_routes: bool = True,
                 set_dns: bool = True,
                 log: Callable[[str], None] = None):
        self.sock = sock
        self.host = host
        self.port = port
        self.svpncookie = svpncookie
        self.cfg = tunnel_cfg
        self.set_routes = set_routes
        self.set_dns = set_dns
        self._log = log or (lambda m: sys.stderr.write(f"[ftnt] {m}\n"))
        self.pppd: Optional[subprocess.Popen] = None
        self._stop = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None

    def _find_pppd(self) -> str:
        import shutil
        for p in ("/usr/sbin/pppd", "/usr/bin/pppd", "/sbin/pppd"):
            if shutil.which(p):
                return p
        raise TunnelError("pppd not found — install ppp")

    def start(self) -> None:
        pppd = self._find_pppd()
        ipup = "/usr/sbin/fortivpn-ip-up"

        args = [pppd,
                "noipdefault", "noauth", "nodefaultroute", "nodetach",
                "nopcomp", "noaccomp", "novj", "novjccomp", "nobsdcomp",
                "lock",
                "usepeerdns" if self.set_dns else "nodns",
                ]
        # Only add ip-up-script if it exists — otherwise pppd tries to
        # execute the next token as a script name
        if os.path.exists(ipup):
            args += ["ip-up-script", ipup]

        args += [str(C.PPP_SPEED),
                 ":{}".format(self.host),
                 "ipparam", "fortigate"]

        if self.set_routes and not self.cfg.get("split_tunnel"):
            args.insert(1, "defaultroute")

        self._log(f"pppd: {' '.join(args[:8])}...")
        self.pppd = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)

        self._hb_thread = threading.Thread(
            target=self._keepalive, daemon=True)
        self._hb_thread.start()

        self._log(f"tunnel up: {self.cfg.get('ip')} "
                  f"({self.cfg.get('netmask')})")
        if self.cfg.get("dns"):
            self._log(f"  dns: {', '.join(self.cfg['dns'])}")

    def _keepalive(self) -> None:
        """Send periodic keepalive XML POSTs over the existing tunnel socket."""
        xml = ('<?xml version="1.0" encoding="utf-8"?>'
               '<sslvpn-tunnel ver="2"><keepalive/></sslvpn-tunnel>')
        body = xml.encode("utf-8")
        while not self._stop.is_set():
            self._stop.wait(C.KEEPALIVE_INTERVAL)
            if self._stop.is_set():
                break
            try:
                req = (f"POST {C.PATH_TUNNEL} HTTP/1.1\r\n"
                       f"Host: {self.host}:{self.port}\r\n"
                       "User-Agent: Mozilla/5.0\r\n"
                       "Connection: keep-alive\r\n"
                       f"Content-Type: text/xml\r\n"
                       f"Content-Length: {len(body)}\r\n"
                       f"Cookie: {C.SVPNCOOKIE}={self.svpncookie}\r\n"
                       "\r\n").encode("latin-1") + body
                self.sock.settimeout(10.0)
                self.sock.sendall(req)
                # Read response (don't block the loop on slow recv)
                self.sock.settimeout(2.0)
                try:
                    self.sock.recv(4096)
                except (socket.timeout, OSError):
                    pass
            except (OSError, socket.timeout):
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._hb_thread and self._hb_thread.is_alive():
            self._hb_thread.join(timeout=3.0)
        if self.pppd and self.pppd.poll() is None:
            try:
                self.pppd.terminate()
                self.pppd.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                self.pppd.kill()
                self.pppd.wait(timeout=5)
            except OSError:
                pass
        try:
            self.sock.close()
        except OSError:
            pass
        self._log("tunnel stopped")

    def wait(self, timeout: float = 0.0):
        if self.pppd is None:
            return
        try:
            if timeout > 0:
                self.pppd.wait(timeout=timeout)
            else:
                self.pppd.wait()
        except subprocess.TimeoutExpired:
            pass


def connect(
    host: str, port: int,
    user: str, password: str,
    *,
    pin_sha256: str = "",
    cafile: str = "",
    insecure: bool = False,
    realm: str = "",
    set_routes: bool = True,
    set_dns: bool = True,
    timeout: float = 30.0,
    log: Callable[[str], None] = None,
) -> Optional[Tunnel]:
    sock, svpncookie, tcfg = authenticate(
        host, port, user, password,
        pin_sha256=pin_sha256, cafile=cafile,
        insecure=insecure, realm=realm,
        timeout=timeout)

    tun = Tunnel(sock, host, port, svpncookie, tcfg,
                 set_routes=set_routes, set_dns=set_dns, log=log)
    tun.start()
    return tun
