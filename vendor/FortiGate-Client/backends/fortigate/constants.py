"""FortiGate SSL-VPN protocol constants.

Values confirmed against openfortivpn 1.24 source + live gateway behaviour.
"""
from __future__ import annotations

# HTTP / TLS
DEFAULT_PORT = 443
UA_V7 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " \
        "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"

# Cookie names
SVPNCOOKIE = "SVPNCOOKIE"

# CGI endpoints
PATH_INFO = "/remote/info"
PATH_LOGIN = "/remote/login"
PATH_LOGOUT = "/remote/logout"
PATH_TUNNEL = "/remote/fortisslvpn_xml"

# Token for HTML login page (we only use the XML path)
PATH_LOGIN_CHECK = "/remote/logincheck"

# Keepalive interval (seconds)
KEEPALIVE_INTERVAL = 30

# Tunnel timeout (seconds) — gateway drops idle
TUNNEL_TIMEOUT = 300

# pppd settings
PPP_SPEED = 0         # no speed limit
PPP_ACCM = "00000000" # no async control character map
PPP_DEFAULT_ROUTE = True
PPP_USE_PEER_DNS = False

# Frame encoding
PPP_MAX_MTU = 1500
PPP_HEADER = b"\x7e"  # PPP flag byte

# Response sizes
MAX_RESPONSE_SIZE = 256 * 1024  # 256 KB
