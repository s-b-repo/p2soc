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
  * the host-match predicate (case-insensitive, subdomain-inclusive, `*.d.com`).

WHY here (not in webkit_panel): the Chromium engine needs the exact same
allowlist + blocklist so a panel behaves identically regardless of engine, and
the matching logic must be unit-tested without GTK.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

# Resolve the shipped data files relative to the repo root (…/security/…), with a
# $SOC_ROOT override for the deployed Pi. Mirrors config._bundled_inode_dir.
_HERE = os.path.abspath(os.path.dirname(__file__))


def _security_dir() -> str:
    root = os.environ.get("SOC_ROOT") or os.path.abspath(
        os.path.join(_HERE, "..", ".."))
    return os.path.join(root, "security")


TRACKERS_JSON = "trackers-top20.json"
SSO_ALLOWLIST_TXT = "allowlist-sso.txt"


# --------------------------------------------------------------------------- #
# Host extraction + matching
# --------------------------------------------------------------------------- #
def host_of(uri: str) -> str:
    """The lowercase hostname of a URI, or '' if it has none (about:, data:)."""
    try:
        return (urlsplit(uri or "").hostname or "").lower()
    except ValueError:
        return ""


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
    for pat in allowed:
        p = (pat or "").lower().strip().rstrip(".")
        if not p:
            continue
        if p.startswith("*."):
            p = p[2:]
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
    try:
        with open(trackers_json_path(), "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def tracker_hosts() -> "list[str]":
    """The plain tracker host list, derived from the rule file's `url-filter`
    regexes (un-escaping the `\\.`). Used by the host-blocking fallbacks (WebKit
    4.0 resource-load redirect, Chromium Network.setBlockedURLs) which can't use a
    compiled WKContentRuleList. Empty list if the file is missing/garbage."""
    text = load_tracker_rules_text()
    if not text:
        return []
    try:
        rules = json.loads(text)
    except (ValueError, TypeError):
        return []
    hosts: "list[str]" = []
    for r in rules if isinstance(rules, list) else []:
        try:
            uf = r["trigger"]["url-filter"]
        except (KeyError, TypeError):
            continue
        # url-filter is a regex like "google-analytics\\.com"; un-escape to a host.
        host = str(uf).replace("\\.", ".").replace("\\", "").strip().strip("^$")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def effective_tracker_hosts(panel, security) -> "list[str]":
    """The tracker hosts to block for `panel`: the curated list MINUS this panel's
    `unblock:` hosts. Honours the per-panel/global `block_trackers` toggle — the
    caller checks `should_block_trackers` first; this only trims the list."""
    unblock = {h.lower() for h in (getattr(panel, "unblock", ()) or ())}
    if not unblock:
        return tracker_hosts()
    return [h for h in tracker_hosts()
            if h.lower() not in unblock
            and not any(h.lower().endswith("." + u) or h.lower() == u
                        for u in unblock)]


def should_block_trackers(panel, security, env_default: bool) -> bool:
    """Block trackers for this panel iff the global default (env + security block)
    AND the per-panel knob both allow it. Any 'off' wins (explicit opt-out)."""
    if not env_default:
        return False
    if security is not None and not getattr(security, "block_trackers", True):
        return False
    return bool(getattr(panel, "block_trackers", True))


# --------------------------------------------------------------------------- #
# Navigation allowlist
# --------------------------------------------------------------------------- #
def load_sso_allowlist() -> "list[str]":
    """The bundled cloud-SSO/redirect domains (security/allowlist-sso.txt).
    Comments (#) and blank lines ignored. [] if the file is missing."""
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
    return out


def build_allowlist(panel, security) -> "frozenset[str]":
    """The per-panel top-level navigation allowlist:
      1. the panel's OWN origin host (effective_url) — loopback for tunnels,
      2. the bundled cloud-SSO list,
      3. per-panel `allow:`,
      4. global `security.allow:` + `security.sso_allow:`.
    Cached by the caller (computed once per panel build)."""
    out: "set[str]" = set()
    own = host_of(getattr(panel, "effective_url", "") or "")
    if own:
        out.add(own)
    out.update(load_sso_allowlist())
    out.update(str(a).strip() for a in (getattr(panel, "allow", ()) or ()) if a)
    if security is not None:
        out.update(str(a).strip() for a in (getattr(security, "allow", ()) or ()) if a)
        out.update(str(a).strip() for a in (getattr(security, "sso_allow", ()) or ()) if a)
    out.discard("")
    return frozenset(out)
