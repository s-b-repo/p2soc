"""CLI entry point: python -m fortigate <host:port> -u <user> [options]."""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading

from . import VERSION
from .auth import authenticate, AuthError, logout
from .tunnel import Tunnel, TunnelError


def main(argv: list[str] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="fortigate",
        description="Native Python Fortinet SSL-VPN client")
    ap.add_argument("host", help="gateway host[:port]")
    ap.add_argument("-u", "--user", required=True,
                    help="FortiGate username")
    ap.add_argument("-p", "--password",
                    help="password (or set $FTNT_SVPN_PASSWORD)")
    ap.add_argument("--realm", default="", help="auth realm")
    ap.add_argument("--pin-sha256", default="",
                    help="gateway cert SHA-256 fingerprint (hex)")
    ap.add_argument("--cafile", default="",
                    help="CA bundle for cert verification")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (UNSAFE)")
    ap.add_argument("--no-routes", action="store_true",
                    help="don't set routes")
    ap.add_argument("--no-dns", action="store_true",
                    help="don't set DNS")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="verbose output")
    ap.add_argument("--version", action="version",
                    version=f"fortigate {VERSION}")
    ap.add_argument("--no-tunnel", action="store_true",
                    help="authenticate only, no tunnel")

    args = ap.parse_args(argv)

    host, _, port_str = args.host.partition(":")
    port = int(port_str) if port_str else 443

    password = args.password or os.environ.get("FTNT_SVPN_PASSWORD", "")
    if not password:
        import getpass
        password = getpass.getpass("Password: ")

    def log(msg):
        prefix = "[ftnt] " if args.verbose else ""
        print(f"{prefix}{msg}", file=sys.stderr, flush=True)

    try:
        sock, svpncookie, tcfg = authenticate(
            host, port, args.user, password,
            pin_sha256=args.pin_sha256,
            cafile=args.cafile,
            insecure=args.insecure,
            realm=args.realm,
            timeout=60.0)
        if args.no_tunnel:
            log("authentication OK")
            logout(sock, host, port, svpncookie)
            return 0

        tun = Tunnel(sock, host, port, svpncookie, tcfg,
                     set_routes=not args.no_routes,
                     set_dns=not args.no_dns, log=log)
        tun.start()
        log(f"tunnel up: {tcfg.get('ip')}")
        log("Ctrl-C to disconnect")

        # Block until interrupted
        import signal
        stop = threading.Event()
        def _sig(s, f):
            stop.set()
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)
        while not stop.is_set():
            stop.wait(60)
        tun.stop()
        logout(sock, host, port, svpncookie)
        return 0

    except AuthError as e:
        print(f"[x] authentication failed: {e}", file=sys.stderr)
        return 1
    except TunnelError as e:
        print(f"[x] tunnel failed: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nstopped")
        return 0


if __name__ == "__main__":
    sys.exit(main())
