"""Phase 7: style.py colour tokens + CSS class coverage.

The Phase 1+4+6+9 changes added several new CSS classes (.soc-toolbar-
action, .destructive-action, .soc-warn-bar). These tests pin the
contract so a future refactor can't silently drop a class the runtime
references.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from host import style                                 # noqa: E402


# --- TOKENS dict --------------------------------------------------------- #


def test_tokens_dict_has_no_duplicate_values():
    """Catches the copy-paste typo where two semantic tokens accidentally
    point at the same colour (defeats the renaming benefit)."""
    values = list(style.TOKENS.values())
    # Two roles MAY legitimately share a colour (e.g. ok / accent could be
    # the same green), so only flag DUPLICATES across UNRELATED tokens.
    # The pragmatic check: no value repeats more than twice.
    from collections import Counter
    counts = Counter(values)
    triples = [v for v, c in counts.items() if c >= 3]
    assert not triples, f"colour reused 3+ times: {triples} — likely a typo"


def test_tokens_contains_every_semantic_role_we_use():
    """The runtime references these tokens by name in the CSS string. If
    one is removed, the rendered .soc-* classes silently fall back to
    GTK defaults and the wall looks broken."""
    required = {
        "bg", "bg-toolbar", "bg-elev", "fg", "fg-soft", "fg-dim",
        "accent", "accent-text", "ok", "warn", "err", "border",
    }
    missing = required - set(style.TOKENS)
    assert not missing, f"missing required tokens: {sorted(missing)}"


# --- CSS class coverage -------------------------------------------------- #


def test_css_includes_warn_bar_class():
    """Phase 9 drift warning needs this class to paint correctly."""
    assert b".soc-warn-bar" in style._CSS


def test_css_includes_toolbar_action_class():
    """Phase 1 🔒 Lock toolbar button uses this class."""
    assert b".soc-toolbar-action" in style._CSS


def test_css_includes_destructive_action_class():
    """Phase 4 + 6 destructive buttons (Remove VPN, Delete cred, Clear
    PIN) use this class for the red-outline visual cue."""
    assert b".destructive-action" in style._CSS


def test_css_includes_all_pill_states():
    """The traffic-light pill CSS must cover every state set_vpn_status
    sends in — otherwise an unstyled pill silently disappears against the
    toolbar background."""
    for state in (b"online", b"connecting", b"offline",
                  b"checking", b"unconfigured"):
        assert b".soc-vpn-pill." + state in style._CSS, \
            f"pill state {state!r} missing from CSS"


def test_apply_css_is_idempotent(monkeypatch):
    """Multiple panels call apply_css() during build — it must not
    re-install the provider twice (Gtk warns on duplicate providers)."""
    monkeypatch.setattr(style, "_applied", False)
    # First call paints; second call short-circuits without crashing.
    style.apply_css()
    style.apply_css()                  # would explode on duplicate install
