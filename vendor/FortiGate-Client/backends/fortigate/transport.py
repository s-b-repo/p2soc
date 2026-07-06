"""TLS transport for FortiGate SSL-VPN — connection + certificate pinning."""
from __future__ import annotations

import socket
import ssl
from typing import Optional


class TransportError(Exception):
    pass


def create_ssl_context(
    pin_sha256: str = "",
    cafile: str = "",
    insecure: bool = False,
) -> ssl.SSLContext:
    """Build an SSLContext for the FortiGate gateway.

    Prefer --pin-sha256 for self-signed certs; --cafile for a custom CA;
    --insecure is opt-in and logs a loud warning."""
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ctx = ssl.create_default_context(cafile=cafile or None)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    if pin_sha256:
        # Replace default verify with fingerprint check
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # We'll check the pin ourselves after handshake
        ctx._ftnt_pin = pin_sha256.replace(":", "").replace(" ", "").lower()

    return ctx


def tls_connect(
    host: str, port: int,
    pin_sha256: str = "",
    cafile: str = "",
    insecure: bool = False,
    timeout: float = 30.0,
) -> socket.socket:
    """Establish a TLS connection to the FortiGate gateway, verify the cert."""
    ctx = create_ssl_context(pin_sha256, cafile, insecure)

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise TransportError(f"TLS handshake to {host}:{port} failed")

    # Verify fingerprint if pinning
    fp = getattr(ctx, "_ftnt_pin", "")
    if fp:
        der = ssock.getpeercert(binary_form=True)
        if der is None:
            ssock.close()
            raise TransportError("peer did not present a certificate")
        import hashlib
        actual = hashlib.sha256(der).hexdigest()
        if actual != fp:
            ssock.close()
            raise TransportError(
                f"cert SHA-256 mismatch: got {actual}, expected {fp}")

    return ssock
