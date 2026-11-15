//! The Security tab: PIN + TOTP enrolment for the settings gate AND for the
//! panel lock, with live PIN-complexity feedback.
//!
//! The credentials themselves live in `soc-state` (`SettingsAuth`,
//! `LockStore`); this file only drives them. A PIN stretch takes a few hundred
//! milliseconds, so setting one runs on a worker.

use super::widgets::{button, frame, hbox, in_worker, note, secret_text, vbox};
use super::{Win, on_click};
use gtk::prelude::*;
use soc_state::policy;
use soc_sys::complexity::{Policy, SecretKind};
use std::rc::Rc;

/// The tab's widgets, shared by its handlers.
#[derive(Clone)]
struct Tab {
    /// Status line of the settings-gate section.
    state: gtk::Label,
    new_pin: gtk::Entry,
    uri: gtk::Entry,
    /// Status line of the panel-lock section.
    lock_state: gtk::Label,
    lock_pin: gtk::Entry,
    lock_uri: gtk::Entry,
}

fn settings_state_text(win: &Win) -> &'static str {
    if win.auth.reauth_required() {
        "A PIN or TOTP is set — it is required to open this window and to confirm destructive actions."
    } else {
        "No PIN set — anyone can open this window. Set one to lock it."
    }
}

/// Live PIN-complexity feedback on `hint` for the text in `entry`.
fn complexity_hint(win: &Win, entry: &gtk::Entry, hint: &gtk::Label) {
    let ctx = hint.style_context();
    ctx.remove_class("soc-config-ok");
    ctx.remove_class("soc-config-error");
    let text = entry.text().to_string();
    if text.is_empty() {
        return hint.set_text("");
    }
    let verdict = pin_policy(win).check(&text, SecretKind::Pin);
    ctx.add_class(if verdict.ok { "soc-config-ok" } else { "soc-config-error" });
    hint.set_text(&if verdict.ok {
        "✓ meets PIN policy".to_string()
    } else {
        format!("✗ {}", verdict.issues.join("; "))
    });
}

fn pin_policy(win: &Win) -> Policy {
    Policy::load(&win.ctx.state_dir.join("policy.json"))
}

/// A PIN entry row: masked entry, complexity hint, Set and Remove buttons.
fn pin_row(
    win: &Rc<Win>,
    section: &gtk::Box,
    placeholder: &str,
    set_label: &str,
    on_set: impl Fn(&Rc<Win>) + 'static,
    on_clear: impl Fn(&Rc<Win>) + 'static,
) -> gtk::Entry {
    let row = hbox(8);
    let pin = gtk::Entry::new();
    pin.set_visibility(false);
    pin.set_input_purpose(gtk::InputPurpose::Digits);
    pin.set_placeholder_text(Some(placeholder));
    pin.set_hexpand(true);
    let hint = gtk::Label::new(None);
    hint.set_xalign(0.0);
    hint.set_line_wrap(true);
    {
        let (weak, hint) = (Rc::downgrade(win), hint.clone());
        pin.connect_changed(move |e| {
            if let Some(win) = weak.upgrade() {
                complexity_hint(&win, e, &hint);
            }
        });
    }
    let set = button(set_label, None);
    on_click(&set, win, on_set);
    let clear = button("Remove PIN", None);
    on_click(&clear, win, on_clear);
    row.pack_start(&pin, true, true, 0);
    row.pack_start(&set, false, false, 0);
    row.pack_start(&clear, false, false, 0);
    section.pack_start(&row, false, false, 0);
    section.pack_start(&hint, false, false, 0);
    pin
}

/// A TOTP row: read-only provisioning URI, Enroll and Remove buttons.
fn totp_row(
    win: &Rc<Win>,
    section: &gtk::Box,
    on_enroll: impl Fn(&Rc<Win>) + 'static,
    on_clear: impl Fn(&Rc<Win>) + 'static,
) -> gtk::Entry {
    let row = hbox(8);
    let uri = gtk::Entry::new();
    uri.set_editable(false);
    uri.set_hexpand(true);
    uri.set_placeholder_text(Some("otpauth://… (appears after Enroll)"));
    let enroll = button("Enroll TOTP", None);
    on_click(&enroll, win, on_enroll);
    let clear = button("Remove TOTP", None);
    on_click(&clear, win, on_clear);
    row.pack_start(&uri, true, true, 0);
    row.pack_start(&enroll, false, false, 0);
    row.pack_start(&clear, false, false, 0);
    section.pack_start(&row, false, false, 0);
    uri
}

pub fn build(win: &Rc<Win>) -> gtk::Widget {
    let boxv = vbox(12, 12);
    boxv.pack_start(
        &note(
            "'Settings PIN' gates THIS window so a passer-by can't repoint the wall. 'Panel lock' is the 🔒 button / \
             Ctrl+Alt+L input firewall — enrol a PIN and/or TOTP here or that lock is decorative.",
        ),
        false,
        false,
        0,
    );

    // The widgets the handlers need exist before the handlers do.
    let state = note(settings_state_text(win));
    let lock_state = note(&win.lock.status_text());
    let sgate = vbox(6, 6);
    sgate.pack_start(&state, false, false, 0);
    let plock = vbox(6, 6);
    plock.pack_start(&lock_state, false, false, 0);

    let cell: Rc<std::cell::RefCell<Option<Tab>>> = Rc::default();
    let tab_of = {
        let cell = cell.clone();
        move || cell.borrow().clone()
    };

    let new_pin = {
        let (a, b) = (tab_of.clone(), tab_of.clone());
        pin_row(
            win,
            &sgate,
            "new Settings PIN",
            "Set / change PIN",
            move |w| {
                if let Some(t) = a() {
                    set_pin(w, &t);
                }
            },
            move |w| {
                if let Some(t) = b() {
                    clear_pin(w, &t);
                }
            },
        )
    };
    let uri = {
        let (a, b) = (tab_of.clone(), tab_of.clone());
        totp_row(
            win,
            &sgate,
            move |w| {
                if let Some(t) = a() {
                    enroll_totp(w, &t);
                }
            },
            move |w| {
                if let Some(t) = b() {
                    clear_totp(w, &t);
                }
            },
        )
    };
    let lock_pin = {
        let (a, b) = (tab_of.clone(), tab_of.clone());
        pin_row(
            win,
            &plock,
            "new panel-lock PIN",
            "Set PIN",
            move |w| {
                if let Some(t) = a() {
                    lock_set_pin(w, &t);
                }
            },
            move |w| {
                if let Some(t) = b() {
                    lock_clear_pin(w, &t);
                }
            },
        )
    };
    let lock_uri = {
        let (a, b) = (tab_of.clone(), tab_of);
        totp_row(
            win,
            &plock,
            move |w| {
                if let Some(t) = a() {
                    lock_enroll_totp(w, &t);
                }
            },
            move |w| {
                if let Some(t) = b() {
                    lock_clear_totp(w, &t);
                }
            },
        )
    };
    *cell.borrow_mut() = Some(Tab { state, new_pin, uri, lock_state, lock_pin, lock_uri });

    boxv.pack_start(&frame("Settings access (this window)", &sgate), false, false, 0);
    boxv.pack_start(&frame("Panel lock (input firewall over the wall)", &plock), false, false, 0);

    // The renderer's navigation allowlist and tracker blocking come from the
    // wall config (the loader's `security:` block); the glass shows them but
    // does not save them (overrides.json has no key for them).
    let sec = win.conf.borrow().security.clone();
    let on_off = |b: bool| if b { "on" } else { "off" };
    boxv.pack_start(
        &frame(
            "Renderer hardening (from the wall config)",
            &note(&format!(
                "navigation allowlist: {}  ·  tracker blocking: {}  ·  extra allowed domains: {}  ·  SSO domains: {}\n\
                 Change these in the wall config (the vault note or panels.yaml).",
                on_off(sec.nav_allowlist),
                on_off(sec.block_trackers),
                sec.allow.len(),
                sec.sso_allow.len()
            )),
        ),
        false,
        false,
        0,
    );
    scrolled_page(boxv)
}

fn scrolled_page(b: gtk::Box) -> gtk::Widget {
    super::widgets::scrolled(&b).upcast()
}

// ---- the settings gate ----------------------------------------------------------------

/// False (and says why) when removal would leave a require-PIN wall with no
/// credential: the form could never be reopened, and Apply would refuse.
fn keeps_a_credential(win: &Win, tab: &Tab, other_is_set: bool) -> bool {
    if policy::keeps_a_credential(win.ctx.require_pin, other_is_set) {
        return true;
    }
    tab.state.set_text("Refused — this wall requires a PIN or TOTP. Enrol the other one first.");
    false
}

fn set_pin(win: &Rc<Win>, tab: &Tab) {
    let pin = secret_text(&tab.new_pin);
    let pin = zeroize::Zeroizing::new(pin.trim().to_string());
    let verdict = pin_policy(win).check(&pin, SecretKind::Pin);
    if !verdict.ok {
        return tab.state.set_text(&format!("PIN rejected — {}", verdict.issues.join("; ")));
    }
    if win.auth.reauth_required() && !win.require_reauth("changing the Settings PIN") {
        return;
    }
    let (auth, weak, tab) = (win.auth.clone(), Rc::downgrade(win), tab.clone());
    tab.state.set_text("setting the PIN …");
    in_worker(
        move || auth.pin().set(&pin).map_err(|e| e.to_string()),
        move |res| {
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            match res.and_then(|r| r) {
                Ok(()) => {
                    tab.new_pin.set_text("");
                    tab.state.set_text("PIN updated — it will be required next time.");
                }
                Err(e) => tab.state.set_text(&format!(
                    "could not save the PIN: {e} — check that {} is writable (disk space / permissions).",
                    win.ctx.state_dir.display()
                )),
            }
        },
    );
}

fn clear_pin(win: &Rc<Win>, tab: &Tab) {
    if !win.auth.pin().is_set() {
        return tab.state.set_text("No PIN is set.");
    }
    if !keeps_a_credential(win, tab, win.auth.totp().is_set()) || !win.require_reauth("removal of the Settings PIN") {
        return;
    }
    match win.auth.pin().clear() {
        Ok(()) => {
            tab.new_pin.set_text("");
            tab.state.set_text(settings_state_text(win));
        }
        Err(e) => tab.state.set_text(&format!("could not remove the PIN: {e}")),
    }
}

fn enroll_totp(win: &Rc<Win>, tab: &Tab) {
    if win.auth.reauth_required() && !win.require_reauth("enrolling a new Settings TOTP") {
        return;
    }
    match win.auth.enroll_totp() {
        Ok(enrolment) => {
            tab.uri.set_text(&enrolment.uri);
            tab.state.set_text(
                "TOTP enrolled — paste the URI into your authenticator app (or scan via `qrencode -t ANSIUTF8 '<uri>'`).",
            );
        }
        Err(e) => tab.state.set_text(&format!("could not enrol TOTP: {e}")),
    }
}

fn clear_totp(win: &Rc<Win>, tab: &Tab) {
    if !win.auth.totp().is_set() {
        return tab.state.set_text("No TOTP is enrolled.");
    }
    if !keeps_a_credential(win, tab, win.auth.pin().is_set()) || !win.require_reauth("removal of the Settings TOTP") {
        return;
    }
    match win.auth.totp().clear() {
        Ok(()) => {
            tab.uri.set_text("");
            tab.state.set_text(settings_state_text(win));
        }
        Err(e) => tab.state.set_text(&format!("could not remove the TOTP: {e}")),
    }
}

// ---- the panel lock ---------------------------------------------------------------------

fn lock_set_pin(win: &Rc<Win>, tab: &Tab) {
    let pin = secret_text(&tab.lock_pin);
    let pin = zeroize::Zeroizing::new(pin.trim().to_string());
    let verdict = pin_policy(win).check(&pin, SecretKind::Pin);
    if !verdict.ok {
        return tab.lock_state.set_text(&format!("PIN rejected — {}", verdict.issues.join("; ")));
    }
    if win.lock.pin().is_set() && win.auth.reauth_required() && !win.require_reauth("changing the panel-lock PIN") {
        return;
    }
    let (lock, weak, tab) = (win.lock.clone(), Rc::downgrade(win), tab.clone());
    in_worker(
        move || lock.pin().set(&pin).map_err(|e| e.to_string()),
        move |res| {
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            match res.and_then(|r| r) {
                Ok(()) => {
                    tab.lock_pin.set_text("");
                    tab.lock_state.set_text(&win.lock.status_text());
                }
                Err(e) => tab.lock_state.set_text(&format!(
                    "could not save the lock PIN: {e} — check that {} is writable (disk space / permissions).",
                    win.ctx.state_dir.display()
                )),
            }
        },
    );
}

fn lock_clear_pin(win: &Rc<Win>, tab: &Tab) {
    if win.lock.pin().is_set() && win.auth.reauth_required() && !win.require_reauth("removal of the panel-lock PIN") {
        return;
    }
    match win.lock.pin().clear() {
        Ok(()) => {
            tab.lock_pin.set_text("");
            tab.lock_state.set_text(&win.lock.status_text());
        }
        Err(e) => tab.lock_state.set_text(&format!("could not remove the lock PIN: {e}")),
    }
}

fn lock_enroll_totp(win: &Rc<Win>, tab: &Tab) {
    if win.lock.totp().is_set() && win.auth.reauth_required() && !win.require_reauth("replacing the panel-lock TOTP") {
        return;
    }
    match win.lock.enroll_totp() {
        Ok(enrolment) => {
            tab.lock_uri.set_text(&enrolment.uri);
            tab.lock_state.set_text(
                "TOTP enrolled — paste the URI into your authenticator app (or scan via `qrencode -t ANSIUTF8 '<uri>'`).",
            );
        }
        Err(e) => tab.lock_state.set_text(&format!("could not enrol TOTP: {e}")),
    }
}

fn lock_clear_totp(win: &Rc<Win>, tab: &Tab) {
    if win.lock.totp().is_set() && win.auth.reauth_required() && !win.require_reauth("removal of the panel-lock TOTP") {
        return;
    }
    match win.lock.totp().clear() {
        Ok(()) => {
            tab.lock_uri.set_text("");
            tab.lock_state.set_text(&win.lock.status_text());
        }
        Err(e) => tab.lock_state.set_text(&format!("could not remove the lock TOTP: {e}")),
    }
}
