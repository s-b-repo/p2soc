"""Native Python Fortinet SSL-VPN client — clean-room implementation.

Speaks the same wire protocol as openfortivpn but is pure Python:
  * TLS to gateway
  * GET /remote/info — realm/capability discovery
  * POST /remote/login — cookie-based authentication
  * POST /remote/fortisslvpn_xml — tunnel setup request
  * pppd launch + config from gateway response
  * periodic keepalive

See openfortivpn source (GPLv3) for the original protocol reverse-engineering.
This implementation is original code, not a port.
"""
from __future__ import annotations

VERSION = "0.1.0"
