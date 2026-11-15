//! Kiosk lock — an input firewall that does not hide the display.
//!
//! When the operator engages the lock (toolbar button or Ctrl+Alt+L), a
//! transparent fullscreen window is raised above the wall. The panels keep
//! painting underneath — still readable — but every mouse, key, scroll and
//! drag event hits the overlay and is swallowed; only the right PIN/TOTP in the
//! centred card dismisses it. The lock logic (enrolment, verification, backoff,
//! replay protection) lives in `soc_state::KioskLock`; this is only its window.

use super::style;
use gtk::cairo;
use gtk::prelude::*;
use soc_state::locker::{KeyAction, KioskLock, LockHint, LockRequest, LockSources, UnlockOutcome};
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;

/// Live unlock inputs rebuilt for every attempt: the current vault-held
/// panel-lock TOTP (so a rotation at the glass takes effect at once) and the
/// sealed admin-PIN override (so a forgotten credential never strands anyone).
pub struct LockInputs {
    /// A fresh vault TOTP secret, if the vault holds one and is ready.
    pub vault_totp: Rc<dyn Fn() -> Option<Zeroizing<String>>>,
    /// The sealed-store admin override check.
    pub admin_pin: Rc<dyn Fn(&str) -> bool>,
}

impl LockInputs {
    fn with_sources<R>(&self, f: impl FnOnce(&LockSources<'_>) -> R) -> R {
        let totp = (self.vault_totp)();
        let admin = &*self.admin_pin;
        let sources = LockSources { vault_totp: totp.as_ref().map(|z| z.as_str()), admin_pin: Some(admin) };
        f(&sources)
    }
}

struct Inner {
    window: gtk::Window,
    entry: gtk::Entry,
    error: gtk::Label,
    lock: Rc<RefCell<KioskLock>>,
    inputs: LockInputs,
    on_unlock: Rc<dyn Fn()>,
}

/// A live lock overlay. Dropping or [`LockOverlay::dismiss`]ing it closes the
/// window; the shared [`KioskLock`] keeps the authoritative locked state.
#[derive(Clone)]
pub struct LockOverlay {
    inner: Rc<Inner>,
}

fn hint_text(hint: LockHint) -> &'static str {
    match hint {
        LockHint::PinOrTotp => "Enter your PIN or a 6-digit authenticator code.",
        LockHint::Totp => "Enter the 6-digit code from your authenticator app.",
        LockHint::Pin => "Enter your PIN.",
        LockHint::AdminPin => "Enter the host setup PIN to unlock.",
    }
}

impl LockOverlay {
    /// Engage the lock: mark [`KioskLock`] locked and raise the overlay.
    /// Returns `None` when no unlock credential is enrolled (the caller should
    /// show the advisory instead) or the lock was already engaged.
    pub fn engage(lock: Rc<RefCell<KioskLock>>, inputs: LockInputs, on_unlock: Rc<dyn Fn()>) -> Option<LockOverlay> {
        let now = soc_state::unix_now();
        let request = inputs.with_sources(|sources| lock.borrow_mut().lock(sources, now));
        match request {
            LockRequest::NoCredential | LockRequest::AlreadyLocked => return None,
            LockRequest::Engaged => {}
        }
        let hint = inputs.with_sources(|sources| lock.borrow().hint(sources));
        Some(Self::build(lock, inputs, on_unlock, hint))
    }

    fn build(lock: Rc<RefCell<KioskLock>>, inputs: LockInputs, on_unlock: Rc<dyn Fn()>, hint: LockHint) -> LockOverlay {
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_decorated(false);
        window.set_resizable(false);
        window.set_skip_taskbar_hint(true);
        window.set_skip_pager_hint(true);
        window.set_keep_above(true);

        // A translucent black wash over the still-painting wall, when the
        // compositor can give us an RGBA visual.
        if let Some(screen) = WidgetExt::screen(&window) {
            if let Some(visual) = screen.rgba_visual().filter(|_| screen.is_composited()) {
                window.set_visual(Some(&visual));
                window.set_app_paintable(true);
                window.connect_draw(|_, cr| {
                    cr.set_source_rgba(0.0, 0.0, 0.0, 0.55);
                    cr.set_operator(cairo::Operator::Source);
                    let _ = cr.paint(); // audit-allow: best-effort paint, nothing to recover
                    glib::Propagation::Proceed
                });
            }
        }
        // Swallow every pointer and scroll event so the wall cannot be touched.
        window.add_events(
            gdk::EventMask::BUTTON_PRESS_MASK
                | gdk::EventMask::BUTTON_RELEASE_MASK
                | gdk::EventMask::SCROLL_MASK
                | gdk::EventMask::POINTER_MOTION_MASK
                | gdk::EventMask::KEY_PRESS_MASK,
        );
        window.connect_button_press_event(|_, _| glib::Propagation::Stop);
        window.connect_button_release_event(|_, _| glib::Propagation::Stop);
        window.connect_scroll_event(|_, _| glib::Propagation::Stop);
        // Refuse window-close (Alt-F4 / compositor close) — only the code unlocks.
        window.connect_delete_event(|_, _| glib::Propagation::Stop);

        let card = gtk::Frame::new(None);
        card.style_context().add_class("soc-config");
        card.set_halign(gtk::Align::Center);
        card.set_valign(gtk::Align::Center);
        card.set_size_request(380, 230);
        let column = gtk::Box::new(gtk::Orientation::Vertical, 10);
        column.set_border_width(20);

        let title = gtk::Label::new(Some("🔒  Wall locked"));
        title.set_xalign(0.5);
        title.style_context().add_class("soc-config-title");
        let hint_label = gtk::Label::new(Some(hint_text(hint)));
        hint_label.set_xalign(0.5);
        hint_label.set_line_wrap(true);
        hint_label.style_context().add_class("soc-config-sub");
        let entry = gtk::Entry::new();
        entry.set_visibility(false);
        entry.set_input_purpose(gtk::InputPurpose::Pin);
        entry.set_alignment(0.5);
        entry.set_placeholder_text(Some("PIN or 6-digit code"));
        let error = gtk::Label::new(None);
        error.set_xalign(0.5);
        error.style_context().add_class("soc-config-error");
        let unlock = gtk::Button::with_label("Unlock");
        unlock.style_context().add_class("soc-config-primary");
        for w in [
            title.upcast_ref::<gtk::Widget>(),
            hint_label.upcast_ref(),
            entry.upcast_ref(),
            error.upcast_ref(),
            unlock.upcast_ref(),
        ] {
            column.pack_start(w, false, false, 0);
        }
        card.add(&column);
        window.add(&card);

        let overlay = LockOverlay { inner: Rc::new(Inner { window, entry, error, lock, inputs, on_unlock }) };

        let weak = Rc::downgrade(&overlay.inner);
        overlay.inner.entry.connect_activate(move |_| {
            if let Some(inner) = weak.upgrade() {
                LockOverlay { inner }.attempt();
            }
        });
        let weak = Rc::downgrade(&overlay.inner);
        unlock.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                LockOverlay { inner }.attempt();
            }
        });
        // Escape is swallowed; Enter submits (handled via activate too).
        let weak = Rc::downgrade(&overlay.inner);
        overlay.inner.window.connect_key_press_event(move |_, event| {
            let is_escape = event.keyval() == gdk::keys::constants::Escape;
            let is_enter = matches!(event.keyval(), gdk::keys::constants::Return | gdk::keys::constants::KP_Enter);
            match KioskLock::key_action(is_escape, is_enter) {
                KeyAction::Swallow => glib::Propagation::Stop,
                KeyAction::Submit => {
                    if let Some(inner) = weak.upgrade() {
                        LockOverlay { inner }.attempt();
                    }
                    glib::Propagation::Stop
                }
                KeyAction::Forward => glib::Propagation::Proceed,
            }
        });

        overlay.inner.window.fullscreen();
        overlay.inner.window.show_all();
        overlay.inner.entry.grab_focus();
        overlay
    }

    fn attempt(&self) {
        let inner = &self.inner;
        let code = Zeroizing::new(inner.entry.text().to_string());
        let now = soc_state::unix_now();
        let outcome = inner.inputs.with_sources(|sources| inner.lock.borrow_mut().try_unlock(&code, sources, now));
        inner.entry.set_text("");
        match outcome {
            UnlockOutcome::Unlocked(_) | UnlockOutcome::NotLocked => {
                self.dismiss();
                (inner.on_unlock)();
            }
            other => inner.error.set_text(&other.message()),
        }
    }

    /// Take the overlay down (the shared lock state is already cleared on a
    /// successful unlock; an admin force-unlock calls this directly).
    pub fn dismiss(&self) {
        self.inner.window.close();
    }
}

/// The themed advisory shown instead of a decorative lock when nothing is
/// enrolled to unlock with. Non-blocking; OK dismisses it.
pub fn advise_no_credential() {
    style::apply_css(&style::tokens_from_colors(&std::collections::HashMap::new()));
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_decorated(false);
    window.set_resizable(false);
    window.set_skip_taskbar_hint(true);
    window.set_keep_above(true);
    window.set_position(gtk::WindowPosition::Center);
    let card = gtk::Frame::new(None);
    card.style_context().add_class("soc-config");
    card.set_size_request(420, 0);
    let column = gtk::Box::new(gtk::Orientation::Vertical, 10);
    column.set_border_width(20);
    let title = gtk::Label::new(Some("⚠  Wall NOT locked"));
    title.set_xalign(0.5);
    title.style_context().add_class("soc-config-title");
    let sub = gtk::Label::new(Some(
        "No panel-lock credential is enrolled, so the lock would be decorative.\n\
         Set a panel-lock PIN first: ⚙ Settings → Security.",
    ));
    sub.set_xalign(0.5);
    sub.set_line_wrap(true);
    sub.style_context().add_class("soc-config-sub");
    let ok = gtk::Button::with_label("OK");
    ok.style_context().add_class("soc-config-primary");
    let close = window.clone();
    ok.connect_clicked(move |_| close.close());
    for w in [title.upcast_ref::<gtk::Widget>(), sub.upcast_ref(), ok.upcast_ref()] {
        column.pack_start(w, false, false, 0);
    }
    card.add(&column);
    window.add(&card);
    window.show_all();
}
