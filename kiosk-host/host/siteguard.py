"""
Backward-compatibility re-export of the shared renderer-security logic.

This module exists so existing imports (e.g. chromium_panel, test_chromium_security)
continue to work without modification.  The canonical source is websecurity.py.
New code should import from host.websecurity directly.
"""
from .websecurity import (              # noqa: F401
    build_allowlist,
    chromium_blocked_urls,
    effective_tracker_hosts,
    host_matches,
    host_of,
    load_sso_allowlist,
    load_tracker_rules,
    load_tracker_rules_text,
    nav_allowed,
    nav_gate_enabled,
    should_block_trackers,
    trackers_enabled,
    tracker_hosts,
    trackers_json_path,
)
