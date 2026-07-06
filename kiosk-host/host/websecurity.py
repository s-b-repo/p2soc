"""
Shared renderer-security data + matching logic for both engines (WebKit + the
Chromium/CDP path). Pure stdlib, no gi — so it is unit-testable without a display
and importable before the venv exists.

It owns:
  * loading the curated data files (security/trackers-top20.json, the WKContent
    RuleList; security/allowlist-sso.txt, the cloud-SSO nav allowlist),
  * deriving a plain tracker-HOST list from the rule list (for the CDP /
    resource-load fallback paths that block by host, not by compiled filter),
  * building a per-panel top-level navigation allowlist (own origin + bundled
    SSO + per-panel `allow:` + global `security.allow:`/`security.sso_allow:`),
  * the host-match predicate (case-insensitive, subdomain-inclusive, `*.d.com`),
  * the Chromium-specific URL pattern builder (chromium_blocked_urls) and
    the nav-allowed check (nav_allowed) so a panel is contained identically
    regardless of engine.

siteguard.py re-exports the public API from here — that module exists only for
backward compatibility with older imports.  New code should import from
websecurity directly.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

from . import configpaths

_SENTINEL = object()
_tracker_rules_text_cache = _SENTINEL
_tracker_rules_cache = _SENTINEL
_sso_allowlist_cache = _SENTINEL

SSO_ALLOWLIST_TXT = "allowlist-sso.txt"
TRACKERS_JSON = "trackers-top20.json"


def _security_dir() -> str:
    override = os.environ.get("SOC_SECURITY_DIR")
    if override:
        return os.path.abspath(override)
    for cand in (
        os.path.join(configpaths.ETC_DIR, "security"),
        os.path.join(configpaths.repo_root(), "security"),
    ):
        if os.path.isdir(cand):
            return cand
    return os.path.join(configpaths.repo_root(), "security")


# --------------------------------------------------------------------------- #
# Host extraction + matching
# --------------------------------------------------------------------------- #
def host_of(uri: str) -> str:
    """The lowercase hostname of a URI, or '' if it has none (about:, data:)."""
    try:
        return (urlsplit(uri or "").hostname or "").lower()
    except ValueError:
        return ""


def _norm_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if d.startswith("*."):
        d = d[2:]
    return d


def host_matches(host: str, allowed: "set[str] | frozenset[str]") -> bool:
    """True if `host` is permitted by the allowlist `allowed` (a set of patterns).

    Matching is SUBDOMAIN-INCLUSIVE by default — the common dashboard case where
    `dashboard.com` should also allow `auth.dashboard.com`:
      * '*.d.com'  matches 'd.com' and any subdomain of it.
      * 'd.com'    matches 'd.com' and any subdomain of it (bare == subdomain-incl).
    Same-registrable-domain is approximated by suffix match (no PSL dependency —
    no new pip deps). Loopback is matched literally by the caller's allowlist.
    """
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for a in allowed:
        p = _norm_domain(a)
        if not p:
            continue
        if host == p or host.endswith("." + p):
            return True
    return False


# --------------------------------------------------------------------------- #
# Tracker blocklist
# --------------------------------------------------------------------------- #
def trackers_json_path() -> str:
    return os.path.join(_security_dir(), TRACKERS_JSON)


def load_tracker_rules_text() -> "str | None":
    """The raw WKContentRuleList JSON text (for UserContentFilterStore), or None
    if the file is missing/unreadable — every caller treats None as 'no filter'
    so a missing data file degrades to no-blocking, never a crash."""
    global _tracker_rules_text_cache
    if _tracker_rules_text_cache is not _SENTINEL:
        return _tracker_rules_text_cache
    try:
        with open(trackers_json_path(), "r", encoding="utf-8") as fh:
            _tracker_rules_text_cache = fh.read()
    except OSError:
        _tracker_rules_text_cache = None
    return _tracker_rules_text_cache


def load_tracker_rules() -> "list[dict]":
    """The raw WKContentRuleList rule array as parsed list[dict], also the source
    of truth for the Chromium host list. Missing/garbage file -> empty list."""
    global _tracker_rules_cache
    if _tracker_rules_cache is not _SENTINEL:
        return _tracker_rules_cache
    text = load_tracker_rules_text()
    if not text:
        _tracker_rules_cache = []
        return _tracker_rules_cache
    try:
        data = json.loads(text)
        _tracker_rules_cache = data if isinstance(data, list) else []
    except (ValueError, TypeError):
        _tracker_rules_cache = []
    return _tracker_rules_cache


def _hosts_from_rules(rules) -> "list[str]":
    hosts: "list[str]" = []
    for r in rules:
        try:
            uf = r["trigger"]["url-filter"]
        except (KeyError, TypeError):
            continue
        host = uf.replace("\\.", ".").strip()
        if host:
            hosts.append(host.lower())
    return hosts


def tracker_hosts() -> "list[str]":
    """The plain tracker host list, derived from the rule file's `url-filter`
    regexes (un-escaping the `\\.`). Used by the host-blocking fallbacks (WebKit
    4.0 resource-load redirect, Chromium Network.setBlockedURLs) which can't use a
    compiled WKContentRuleList. Empty list if the file is missing/garbage."""
    return _hosts_from_rules(load_tracker_rules())


def effective_tracker_hosts(panel, security) -> "list[str]":
    """The tracker hosts to block for `panel`: the curated list MINUS this panel's
    `unblock:` hosts. Honours the per-panel/global `block_trackers` toggle — the
    caller checks `should_block_trackers` first; this only trims the list."""
    hosts = tracker_hosts()
    unblock = {_norm_domain(d) for d in (getattr(panel, "unblock", ()) or ())}
    if not unblock:
        return hosts
    return [h for h in hosts if not host_matches(h, unblock)]


def should_block_trackers(panel, security, env_default: bool) -> bool:
    """Block trackers for this panel iff the global default (env + security block)
    AND the per-panel knob both allow it. Any 'off' wins (explicit opt-out)."""
    if not env_default:
        return False
    if security is not None and not getattr(security, "block_trackers", True):
        return False
    return bool(getattr(panel, "block_trackers", True))


def trackers_enabled(panel, security) -> bool:
    """Whether tracker blocking applies to this panel: the global default
    (security.block_trackers, itself overridable by SOC_BLOCK_TRACKERS in
    config.py) AND the per-panel block_trackers knob must both be on."""
    return bool(getattr(security, "block_trackers", True)
                and getattr(panel, "block_trackers", True))


# --------------------------------------------------------------------------- #
# Navigation allowlist
# --------------------------------------------------------------------------- #
def load_sso_allowlist() -> "list[str]":
    """The bundled cloud-SSO/redirect domains (security/allowlist-sso.txt).
    Comments (#) and blank lines ignored. [] if the file is missing."""
    global _sso_allowlist_cache
    if _sso_allowlist_cache is not _SENTINEL:
        return _sso_allowlist_cache
    path = os.path.join(_security_dir(), SSO_ALLOWLIST_TXT)
    out: "list[str]" = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except OSError:
        pass
    _sso_allowlist_cache = out
    return _sso_allowlist_cache


def build_allowlist(panel, security) -> "set[str]":
    """The per-panel top-level navigation allowlist:
      1. the panel's OWN origin host (effective_url) — loopback for tunnels,
      2. the bundled cloud-SSO list,
      3. per-panel `allow:`,
      4. global `security.allow:` + `security.sso_allow:`.
    All entries are normalised (wildcard '*.' stripped, lowercased, trimmed).
    Cached by the caller (computed once per panel build)."""
    out: "set[str]" = set()
    own = host_of(getattr(panel, "effective_url", "") or "")
    if own:
        out.add(own)
    for d in load_sso_allowlist():
        out.add(_norm_domain(d))
    for d in getattr(security, "sso_allow", ()) or ():
        out.add(_norm_domain(d))
    for d in getattr(panel, "allow", ()) or ():
        out.add(_norm_domain(d))
    for d in getattr(security, "allow", ()) or ():
        out.add(_norm_domain(d))
    out.discard("")
    return out


def nav_gate_enabled(security) -> bool:
    """Whether the top-level nav allowlist is active (security.nav_allowlist,
    itself overridable by SOC_NAV_ALLOWLIST in config.py)."""
    return bool(getattr(security, "nav_allowlist", True))


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
        return True
    return host_matches(host_of(u), allowed)


def chromium_blocked_urls(panel) -> "list[str]":
    """Translate the tracker hosts into the wildcard patterns
    Network.setBlockedURLs expects (`*host*`), so any URL containing the host is
    blocked. Reuses tracker_hosts() so WebKit + Chromium block the same set,
    honouring the panel's `unblock:` list."""
    hosts = effective_tracker_hosts(panel, None)
    return [f"*{h}*" for h in hosts]
