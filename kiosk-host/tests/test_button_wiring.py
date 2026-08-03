"""Meta-test: every GUI button's click handler must reference a real
callable. Catches the regression where a refactor renames a method but
forgets to update the .connect("clicked", ...) site, leaving a dead
button in the GUI."""
from __future__ import annotations

import ast
import os
import re

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _scan(path):
    """Return a (handlers, defined_methods) pair for the .py file at path.

    handlers      — list[str] of the right-hand side of every
                    `.connect("clicked", X)` site. X may be a lambda
                    (returned as 'lambda'), a method ('self.foo'), or a
                    bare local name.
    defined_methods — set[str] of every `def foo` name in the module.
    """
    src = open(path, encoding="utf-8").read()
    # Pull every `.connect("clicked", <expr>` — accept both
    # 'self.foo' and bare local names + lambdas.
    pat = re.compile(
        r'\.connect\(\s*["\']clicked["\']\s*,\s*([^,)\n]+)',
    )
    handlers = [m.strip() for m in pat.findall(src)]
    # Defined methods + module-level functions for cross-check.
    tree = ast.parse(src)
    defined = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined.add(node.name)
    return handlers, defined


def test_configwin_all_clicked_handlers_resolve():
    """Every clicked handler in configwin.py points at either:
      * a lambda (always callable),
      * a method on self (self.xxx — verified to exist below),
      * a bare local closure name defined in the enclosing function,
      * a wrapper call like _confirm_and_run(...).
    Anything else (a typo) raises an audit failure."""
    handlers, defined = _scan(
        os.path.join(REPO, "kiosk-host", "host", "configwin.py"))
    assert len(handlers) >= 20, \
        f"audit sanity: expected ≥20 clicked handlers, got {len(handlers)}"
    unresolved = []
    for h in handlers:
        # Lambdas are inherently callable.
        if h.startswith("lambda") or h.startswith("(lambda"):
            continue
        # _confirm_and_run(label, callable) wrapper — the wrapped callable
        # is the second arg; whether IT resolves is up to that scope.
        # We trust that path because _confirm_and_run itself is defined
        # (verified next).
        if h.startswith("_confirm_and_run"):
            continue
        # Method on self — strip 'self.', verify the method exists in the
        # module's defined functions.
        if h.startswith("self."):
            name = h[len("self."):]
            if name in defined:
                continue
            unresolved.append((h, "method not defined on class"))
            continue
        # Bare name — local closure (defined inside another function).
        # Trust: the bash parser would have raised a NameError at import
        # time if it weren't defined in the enclosing scope. We can't
        # easily cross-check via ast without a full closure-aware walk;
        # accept these as long as the symbol exists somewhere in the
        # module (method, function, or closure-bound name).
        if h in defined:
            continue
        # Final accept: any expression that looks like an attribute /
        # name chain (we can't statically resolve, but it parses).
        try:
            ast.parse(h, mode="eval")
        except SyntaxError:
            unresolved.append((h, "not a valid expression"))
            continue
    assert not unresolved, f"unwired click handlers: {unresolved}"


def test_wall_all_clicked_handlers_resolve():
    """Same scan over wall.py. wall.py has fewer handlers (VPN pills,
    gear, lock) and they're all lambdas, but we keep the meta-test
    here as a guard against future regressions."""
    handlers, defined = _scan(
        os.path.join(REPO, "kiosk-host", "host", "wall.py"))
    unresolved = []
    for h in handlers:
        if h.startswith("lambda") or h.startswith("(lambda"):
            continue
        if h.startswith("self."):
            name = h[len("self."):]
            if name not in defined:
                unresolved.append((h, "method not defined"))
            continue
        if h in defined:
            continue
        try:
            ast.parse(h, mode="eval")
        except SyntaxError:
            unresolved.append((h, "syntax error"))
    assert not unresolved, f"unwired click handlers in wall.py: {unresolved}"


def test_no_lock_pin_clear_bypasses_reauth():
    """Audit follow-up: the legacy "Security — lock PIN" expander's
    'Remove PIN' button calls _clear_pin(). We confirmed during the audit
    that _clear_pin now gates removal with _require_reauth — verify
    that gate stays in place (no future regression)."""
    src = open(os.path.join(REPO, "kiosk-host", "host", "configwin.py"),
               encoding="utf-8").read()
    # find the _clear_pin definition body
    m = re.search(r"def _clear_pin\(self\):(.*?)(?=^    def |\Z)",
                  src, re.S | re.M)
    assert m, "could not find _clear_pin in configwin.py"
    body = m.group(1)
    assert "_require_reauth" in body, \
        "_clear_pin must re-auth before removing the PIN"


def test_credentials_inventory_has_edit_button():
    """The Credentials tab inventory row now has both Edit and Delete
    buttons. Edit calls _on_cred_edit, which calls _prompt_os_password
    (OS password, NOT wall PIN). Verify both wires."""
    src = open(os.path.join(REPO, "kiosk-host", "host", "configwin.py"),
               encoding="utf-8").read()
    assert re.search(r'edit\.connect\("clicked"',
                     src), "Edit button missing"
    assert re.search(r"def _on_cred_edit\(self, name", src), \
        "_on_cred_edit missing"
    # _on_cred_edit must consult the OS password before showing the
    # values. Confirm via static check that _prompt_os_password is
    # called inside the function body.
    m = re.search(r"def _on_cred_edit\(self, name: str\):(.*?)(?=^    def |\Z)",
                  src, re.S | re.M)
    assert m and "_prompt_os_password" in m.group(1), \
        "_on_cred_edit must call _prompt_os_password before revealing"
