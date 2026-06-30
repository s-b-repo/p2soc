"""
Engine-shared site-guard logic: the navigation allowlist + the tracker blocklist.

Both renderers (webkit_panel.py via decide-policy/UserContentFilter, and
chromium_panel.py via CDP Fetch/Network.setBlockedURLs) compute the SAME
allowlist set and consume the SAME curated blocklists from here, so a panel is
contained identically regardless of engine.

Pure stdlib (urllib + json) — no gi, no PyYAML, no new pip deps. Safe to import
on the GTK main thread; nothing here blocks or touches the network.

Granularity (the safety valve): the allowlist gates ONLY top-level/main-frame
navigation. Sub-resources, XHR, websockets and SSO redirect chains are NOT
gated here — they go through the tracker filter only — so a dashboard's CDN,
fonts, and SSO POST-backs keep working while a hijacked page still cannot drive
the wall's top frame to an arbitrary attacker site.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

from . import configpaths

# Data files shipped under security/ (packaged by nfpm; see nfpm.yaml). The
# SSO allowlist is curated cloud identity providers; the tracker list is the
# canonical top-20. Both are operator-extendable.
_SSO_FILE = "allowlist-sso.txt"
_TRACKERS_FILE = "trackers-top20.json"


def _security_dir() -> str:
    """Where the curated data files live: $SOC_SECURITY_DIR override, else the
    deployed /etc location's sibling, else the repo's security/ (dev). We probe
    candidates so the same module works deployed and in a checkout."""
    override = os.environ.get("SOC_SECURITY_DIR")
    if override:
        return os.path.abspath(override)
    for cand in (
        os.path.join(configpaths.etc_dir(), "security"),
        os.path.join(configpaths.repo_root(), "security"),
    ):
        if os.path.isdir(cand):
            return cand
    return os.path.join(configpaths.repo_root(), "security")


def host_of(url: str) -> str:
    """Lowercased hostname of a URL (no port), or '' if it has none. Reused for
    both the allowlist match and deriving a panel's own origin host."""
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _norm_domain(d: str) -> str:
    """Normalise an allowlist entry to a bare lowercase host (drop a leading
    '*.' wildcard marker and any stray whitespace)."""
    d = (d or "").strip().lower()
    if d.startswith("*."):
        d = d[2:]
    return d


def host_matches(host: str, allowed: "set[str]") -> bool:
    """Subdomain-inclusive, case-insensitive host match. `allowed` is a set of
    bare hosts (already normalised). A host matches if it equals an allowed host
    OR is a subdomain of one ('auth.dashboard.com' matches when 'dashboard.com'
    is allowed) — the common dashboard case. This approximates same-registrable-
    domain by subdomain suffix to avoid a PSL dependency (no new pip deps)."""
    host = (host or "").lower()
    if not host:
        return False
    for a in allowed:
        if not a:
            continue
        if host == a or host.endswith("." + a):
            return True
    return False


def load_sso_domains() -> "list[str]":
    """The bundled curated cloud-SSO/redirect domains (one per line; '#' and
    blank lines ignored). Missing file -> empty list (the gate then relies on
    the panel's own origin + per-panel/global allow)."""
    path = os.path.join(_security_dir(), _SSO_FILE)
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except OSError:
        pass
    return out


def build_allowlist(panel, security) -> "set[str]":
    """The set of bare hosts a panel may navigate to at the TOP level:
      1. the panel's OWN origin host (loopback for tunnel panels),
      2. the bundled cloud-SSO list + security.sso_allow,
      3. per-panel panel.allow,
      4. global security.allow.
    Everything is normalised (wildcard '*.' stripped); matching is subdomain-
    inclusive via host_matches(), so listing 'dashboard.com' covers
    'auth.dashboard.com'. Computed ONCE per panel and cached by the caller."""
    allowed: "set[str]" = set()
    own = host_of(getattr(panel, "effective_url", "") or "")
    if own:
        allowed.add(own)
    for d in load_sso_domains():
        allowed.add(_norm_domain(d))
    for d in getattr(security, "sso_allow", ()) or ():
        allowed.add(_norm_domain(d))
    for d in getattr(panel, "allow", ()) or ():
        allowed.add(_norm_domain(d))
    for d in getattr(security, "allow", ()) or ():
        allowed.add(_norm_domain(d))
    allowed.discard("")
    return allowed


def nav_allowed(url: str, allowed: "set[str]") -> bool:
    """True if a top-level navigation to `url` is permitted. about:blank and
    other non-http(s) schemes are always allowed (data: placeholder pages,
    blank tiles); only http(s) hosts are gated against the allowlist."""
    u = (url or "").strip()
    if not u:
        return True
    low = u.lower()
    if low.startswith("about:") or low.startswith("data:"):
        return True
    scheme = urlsplit(u).scheme.lower()
    if scheme not in ("http", "https"):
        return True  # non-web schemes are refused upstream in set_url, not here
    return host_matches(host_of(u), allowed)


# --------------------------------------------------------------------------- #
# Tracker blocklist
# --------------------------------------------------------------------------- #
def load_tracker_rules() -> "list[dict]":
    """The raw WKContentRuleList rule array (also the source of truth for the
    Chromium host list). Missing/garbage file -> empty list (tracker blocking
    degrades to off rather than crashing the wall)."""
    path = os.path.join(_security_dir(), _TRACKERS_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _hosts_from_rules(rules) -> "list[str]":
    """Extract the bare tracker hosts from the rule array by un-escaping each
    rule's `url-filter` regex (the file stores e.g. 'google-analytics\\.com')."""
    hosts = []
    for r in rules:
        try:
            uf = r["trigger"]["url-filter"]
        except (KeyError, TypeError):
            continue
        host = uf.replace("\\.", ".").strip()
        if host:
            hosts.append(host.lower())
    return hosts


def tracker_hosts(panel) -> "list[str]":
    """The tracker hosts to block for this panel, honouring its `unblock` list
    (hosts the panel legitimately needs). Returns [] when blocking is disabled
    for the panel — the caller decides that via block_trackers + the global
    toggle; this just applies the per-panel unblock subtraction."""
    rules = load_tracker_rules()
    hosts = _hosts_from_rules(rules)
    unblock = {(_norm_domain(d)) for d in (getattr(panel, "unblock", ()) or ())}
    if not unblock:
        return hosts
    # drop any host that equals or is a subdomain of an unblock entry
    return [h for h in hosts if not host_matches(h, unblock)]


def chromium_blocked_urls(panel) -> "list[str]":
    """Translate the tracker hosts into the wildcard patterns
    Network.setBlockedURLs expects (`*host*`), so any URL containing the host is
    blocked. Reuses tracker_hosts() so WebKit + Chromium block the same set."""
    return [f"*{h}*" for h in tracker_hosts(panel)]


def trackers_enabled(panel, security) -> bool:
    """Whether tracker blocking applies to this panel: the global default
    (security.block_trackers, itself overridable by SOC_BLOCK_TRACKERS in
    config.py) AND the per-panel block_trackers knob must both be on."""
    return bool(getattr(security, "block_trackers", True)
                and getattr(panel, "block_trackers", True))


def nav_gate_enabled(security) -> bool:
    """Whether the top-level nav allowlist is active (security.nav_allowlist,
    itself overridable by SOC_NAV_ALLOWLIST in config.py)."""
    return bool(getattr(security, "nav_allowlist", True))
