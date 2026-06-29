"""
Drives host.main's interactive Unlock-prompt contract WITHOUT a GTK window.

After the re-prompt-IN-PLACE redesign the retry lives inside ONE dialog, not in
main()'s outer loop, so the retry logic is factored into the GTK-free helper
`_unlock_attempt_loop(verify, ui)` (the real `_GtkUnlockUI` is the only other
caller). We drive that helper with a fake `ui` + the `verify` seam, asserting:

  * wrong-then-right uses ONE dialog (no 're-pop'), shows the rejection reason
    after the first failure, clears the entry between attempts, returns the master;
  * an unreachable server shows a 'reach' reason and keeps the SAME dialog up;
  * Cancel/close returns (None, False) and is NOT treated as success (verify is
    never consulted on a cancel);
  * crossing the overall timeout (ui.prompt() -> ok False) stops with NO further
    prompt — a headless wall can never wedge re-prompting.

`_classify_unlock_error` is checked directly (wrong-master vs. unreachable wording),
and a main()-level test covers the orchestration around the dialog: a cancelled
prompt -> _fatal_screen -> rc 2; a verified master -> seal (when asked) + re-open.

The master is RAM-only throughout — it is NEVER written to a file.

host.main imports gi at module scope; the rest of the suite already imports gi,
so this is safe under the same interpreter (importorskip covers CI without gi).
"""
import pytest

pytest.importorskip("gi")  # host.main imports gi at module scope — skip where PyGObject is absent (CI)
from host import main as hostmain
from host.litebw import VaultLockedError


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class _FakeUnlockUI:
    """Stand-in for _GtkUnlockUI: feeds scripted (ok, master, seal) tuples and
    records error labels / entry clears, so _unlock_attempt_loop is testable with
    no display. ONE instance models ONE dialog — reuse across attempts proves the
    dialog is never re-created ('re-pop')."""

    def __init__(self, prompts):
        self._prompts = list(prompts)
        self.prompt_calls = 0
        self.errors = []     # text passed to show_error(), in order
        self.clears = 0      # number of clear_entry() calls

    def prompt(self):
        self.prompt_calls += 1
        return self._prompts.pop(0)

    def show_error(self, text):
        self.errors.append(text)

    def clear_entry(self):
        self.clears += 1


def _verify_only(good):
    """A verify(master) -> (ok, reason) seam using the REAL classifier for the
    reason, exactly as main()'s _verify does: anything but `good` is a credential
    rejection."""
    def verify(master):
        if master == good:
            return (True, "")
        return (False, hostmain._classify_unlock_error(
            "login failed — check the email/master password", "http://vault.local"))
    return verify


# --------------------------------------------------------------------------- #
# _unlock_attempt_loop — the re-prompt-in-place retry contract
# --------------------------------------------------------------------------- #
def test_wrong_master_then_correct_reprompts_in_place():
    # (a) wrong -> right: ONE dialog (one ui), the rejection reason is shown after
    # the first failure, the entry is cleared between attempts, returns the master.
    ui = _FakeUnlockUI([(True, "wrong", True), (True, "right", True)])
    res = hostmain._unlock_attempt_loop(_verify_only("right"), ui)
    assert res == ("right", True)
    assert ui.prompt_calls == 2          # same dialog re-run — never re-created
    assert ui.clears == 1                # entry cleared once, after the wrong try
    assert len(ui.errors) == 1
    assert "reject" in ui.errors[0].lower()


def test_unreachable_shows_reach_reason_and_keeps_dialog():
    # (b) an unreachable server -> a 'reach' reason, same dialog stays up for retry.
    def verify(master):
        if master == "good":
            return (True, "")
        return (False, hostmain._classify_unlock_error(
            "could not reach Vaultwarden at http://vault.local: Connection refused",
            "http://vault.local"))

    ui = _FakeUnlockUI([(True, "x", False), (True, "good", False)])
    res = hostmain._unlock_attempt_loop(verify, ui)
    assert res == ("good", False)
    assert ui.prompt_calls == 2
    assert "reach" in ui.errors[0].lower()


def test_cancel_returns_none_and_is_not_success():
    # (c) Cancel/close -> (None, False); verify must NOT be consulted (no silent
    # 'success'), and no further prompt is shown.
    consulted = []

    def verify(master):
        consulted.append(master)
        return (True, "")

    ui = _FakeUnlockUI([(False, "", False)])
    res = hostmain._unlock_attempt_loop(verify, ui)
    assert res == (None, False)
    assert ui.prompt_calls == 1
    assert consulted == []               # cancel is never treated as an unlock


def test_timeout_stops_with_no_further_prompt():
    # (d) crossing the overall timeout (the GTK timeout source responds CANCEL, so
    # ui.prompt() returns ok False) stops immediately — a second scripted response
    # must NOT be consumed, proving a headless wall never wedges re-prompting.
    ui = _FakeUnlockUI([(False, "", False), (True, "too-late", True)])
    res = hostmain._unlock_attempt_loop(_verify_only("too-late"), ui)
    assert res == (None, False)
    assert ui.prompt_calls == 1          # NO further prompt after the timeout
    assert ui._prompts == [(True, "too-late", True)]   # the extra was left untouched


def test_empty_master_reprompts_without_calling_verify():
    # An empty entry is a local validation error: show the hint, re-prompt the SAME
    # dialog, and never bother verify() with a blank master.
    consulted = []

    def verify(master):
        consulted.append(master)
        return (True, "")

    ui = _FakeUnlockUI([(True, "", True), (True, "real", True)])
    res = hostmain._unlock_attempt_loop(verify, ui)
    assert res == ("real", True)
    assert ui.prompt_calls == 2
    assert consulted == ["real"]         # blank attempt never reached verify
    assert len(ui.errors) == 1 and "master password" in ui.errors[0].lower()


def test_no_verify_returns_first_nonempty_master():
    # verify=None (e.g. a non-litebw backend) -> accept the first non-empty master.
    ui = _FakeUnlockUI([(True, "m", False)])
    res = hostmain._unlock_attempt_loop(None, ui)
    assert res == ("m", False)
    assert ui.prompt_calls == 1


# --------------------------------------------------------------------------- #
# _classify_unlock_error — wrong-master vs. unreachable wording
# --------------------------------------------------------------------------- #
def test_classify_unlock_error_unreachable_vs_wrong():
    # A connect/DNS/timeout fault names the server (so the operator fixes the URL,
    # not the password); everything else reads as a credential rejection.
    url = "http://vault.local:8222"
    for raw in ("could not reach Vaultwarden at http://vault.local: Connection refused",
                "<urlopen error [Errno -2] Name or service not known>",
                "the read operation timed out"):
        msg = hostmain._classify_unlock_error(raw, url)
        assert "reach" in msg.lower()
        assert url in msg
    for raw in ("login failed — check the email/master password",
                "vault item 'x' has no password"):
        msg = hostmain._classify_unlock_error(raw, url)
        assert "reject" in msg.lower()
        assert url not in msg


# --------------------------------------------------------------------------- #
# main() — orchestration around the dialog
# --------------------------------------------------------------------------- #
class _MainFakeVault:
    """vault.open() raises VaultLockedError until `unlocked` is set True (the
    dialog's verify opens the backend session on success); then it returns."""

    def __init__(self):
        self.unlocked = False
        self.open_calls = 0

        class _Backend:
            email = "kiosk@soc.local"
            url = "http://vault.local"

            def unlock_with(self, master):  # only reached via the real dialog
                pass

        self.backend = _Backend()

    def open(self):
        self.open_calls += 1
        if not self.unlocked:
            raise VaultLockedError("vault is locked — Vaultwarden master needed")


def _wire_main(monkeypatch, fake, fatal_calls, seal_calls):
    monkeypatch.delenv("SOC_DRY_RUN", raising=False)
    monkeypatch.setattr(hostmain, "Vault", lambda **kw: fake)
    monkeypatch.setattr(hostmain, "_fatal_screen",
                        lambda title, detail, hint="": fatal_calls.append(title) or 2)
    monkeypatch.setattr(hostmain, "_try_seal_master",
                        lambda m: seal_calls.append(m) or True)


def test_main_cancel_falls_through_to_fatal(monkeypatch):
    fake = _MainFakeVault()                      # stays locked forever
    fatal_calls, seal_calls, dialog_calls = [], [], []
    _wire_main(monkeypatch, fake, fatal_calls, seal_calls)

    def _stub_dialog(email, url, verify=None, timeout=180.0):
        dialog_calls.append((email, url))
        return (None, False)                     # operator cancelled
    monkeypatch.setattr(hostmain, "_unlock_dialog", _stub_dialog)

    rc = hostmain.main()
    assert rc == 2
    assert fatal_calls == ["Vaultwarden is locked"]
    assert len(dialog_calls) == 1                # NOT re-popped after cancel
    assert seal_calls == []


def test_main_verified_master_seals_and_reopens(monkeypatch):
    fake = _MainFakeVault()
    fatal_calls, seal_calls, dialog_calls = [], [], []
    _wire_main(monkeypatch, fake, fatal_calls, seal_calls)

    def _stub_dialog(email, url, verify=None, timeout=180.0):
        dialog_calls.append((email, url))
        fake.unlocked = True                     # verify opened the session in-dialog
        return ("master", True)
    monkeypatch.setattr(hostmain, "_unlock_dialog", _stub_dialog)
    # Stop deterministically just past the vault loop (re-open succeeded).
    monkeypatch.setattr(hostmain, "load_config",
                        lambda v: (_ for _ in ()).throw(hostmain.cfg.ConfigError("stop")))

    rc = hostmain.main()
    assert rc == 2                               # from the stubbed _fatal_screen
    assert fatal_calls == ["Configuration error"]  # reached config => vault re-opened
    assert seal_calls == ["master"]              # sealed because the operator opted in
    assert len(dialog_calls) == 1
    assert fake.open_calls == 2                  # locked, then opened after unlock
    assert dialog_calls[0] == ("kiosk@soc.local", "http://vault.local")
