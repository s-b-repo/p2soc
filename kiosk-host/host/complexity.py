"""
Password / PIN complexity policy — pure stdlib, testable.

Surfaced in the ⚙ Settings → Security tab. The same `check()` runs both at
PIN-change time (rejects a weak PIN before it's saved) AND when the PIN gate
is invoked (so a previously-saved-but-now-too-weak PIN is flagged — operator
must rotate to a stronger one).

Defaults — chosen for the SOC-wall threat model (an operator in front of a
public-facing kiosk, not a personal device):

    pin       — numeric only, min 4. Easy to type on a touchscreen.
    password  — min 12, requires ≥3 of {upper, lower, digit, symbol}.

Both are configurable via $SOC_STATE_DIR/policy.json (read once at startup):

    {
      "pin":      {"min_len": 6, "classes": 1},
      "password": {"min_len": 16, "classes": 4}
    }

If `policy.json` is missing/unparseable we fall back to the built-in defaults.
"""
from __future__ import annotations

import json
import os
import string
from dataclasses import dataclass, field


@dataclass
class PolicyResult:
    ok: bool
    issues: list = field(default_factory=list)         # human-readable strings
    score: int = 0                                     # 0..4 (classes satisfied)

    def summary(self) -> str:
        return "ok" if self.ok else "; ".join(self.issues)


_CLASS_FNS = {
    "lower":  lambda c: c.islower(),
    "upper":  lambda c: c.isupper(),
    "digit":  lambda c: c.isdigit(),
    "symbol": lambda c: not c.isalnum() and not c.isspace(),
}


_DEFAULTS = {
    "pin":      {"min_len": 4,  "classes": 1, "numeric_only": True},
    "password": {"min_len": 12, "classes": 3, "numeric_only": False},
}


def _load_policy(path: str | None = None) -> dict:
    """Read policy.json — falls back to _DEFAULTS on any error. Validated
    minimally; bad keys are ignored, not raised."""
    if path is None:
        from . import configwin
        path = os.path.join(configwin.state_dir(), "policy.json")
    out = {"pin": dict(_DEFAULTS["pin"]),
           "password": dict(_DEFAULTS["password"])}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return out
    for kind in ("pin", "password"):
        block = cfg.get(kind)
        if not isinstance(block, dict):
            continue
        if isinstance(block.get("min_len"), int) and block["min_len"] > 0:
            out[kind]["min_len"] = block["min_len"]
        if isinstance(block.get("classes"), int) and 0 <= block["classes"] <= 4:
            out[kind]["classes"] = block["classes"]
        if isinstance(block.get("numeric_only"), bool):
            out[kind]["numeric_only"] = block["numeric_only"]
    return out


# --- public --------------------------------------------------------------- #
def check(secret: str, *, kind: str = "pin",
          min_len: int | None = None, classes: int | None = None,
          numeric_only: bool | None = None,
          policy_path: str | None = None) -> PolicyResult:
    """Validate `secret` against the policy for `kind` ('pin' | 'password').
    Explicit kwargs override the on-disk / built-in defaults — useful for
    callers that want a one-off check (e.g. an admin form with a per-field
    higher bar)."""
    pol = _load_policy(policy_path).get(kind, _DEFAULTS.get(kind, {}))
    min_len = min_len if min_len is not None else pol["min_len"]
    classes = classes if classes is not None else pol["classes"]
    numeric_only = (numeric_only if numeric_only is not None
                    else pol.get("numeric_only", False))

    issues = []
    score = sum(1 for fn in _CLASS_FNS.values() if any(fn(c) for c in secret))

    if not secret:
        issues.append("must not be empty")
    if len(secret) < min_len:
        issues.append(f"must be at least {min_len} characters (got {len(secret)})")
    if numeric_only and not secret.isdigit():
        issues.append("must contain digits only (e.g. 1234)")
    if not numeric_only and score < classes:
        want = " / ".join(sorted(_CLASS_FNS))
        issues.append(f"must include at least {classes} of: {want} "
                      f"(got {score})")
    if " " in secret:
        issues.append("spaces are not allowed")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in secret):
        issues.append("control characters are not allowed")
    # Light-touch common-secrets check (don't import a 14 MB wordlist).
    if secret.lower() in _COMMON_BAD:
        issues.append("looks like a common/leaked password — choose another")

    return PolicyResult(ok=not issues, issues=issues, score=score)


_COMMON_BAD = {
    # token list — top breached PINs/passwords. Not comprehensive (that's a
    # job for `zxcvbn` if the operator wants it); just enough to catch the
    # absolutely-don't-use-this defaults.
    "password", "password1", "password123", "qwerty", "qwerty123",
    "admin", "admin123", "letmein", "welcome", "welcome1",
    "abc123", "iloveyou", "monkey", "dragon", "111111", "123123",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "1234", "12345", "0000", "1111", "2222", "9999",
    "soc", "kiosk", "wall", "default",
}


_CLASS_LABELS = {  # for GUI display
    "lower": "lowercase",
    "upper": "uppercase",
    "digit": "digit",
    "symbol": "symbol",
}
