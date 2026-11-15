//! The interactive "Unlock Vaultwarden" prompt, shown at start-up when the
//! host has no sealed master password — instead of a cryptic fatal error.
//!
//! One dialog serves the whole attempt sequence: a wrong password or an
//! unreachable server is explained in place and the operator retries in the
//! same window. The master password stays in RAM only; it is never written to
//! a file from here (sealing it host-bound is the caller's, explicit, step).

use gtk::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;
use zeroize::Zeroizing;

/// The operator's answer.
pub struct Unlocked {
    pub master: Zeroizing<String>,
    /// Seal the master host-bound so the next boot is unattended.
    pub seal: bool,
}

/// Run the prompt. `verify` is called for each Unlock press and returns the
/// reason on failure. `None` on Cancel / close / timeout — the single
/// `timeout` bounds the whole sequence so a wall never wedges on a prompt.
pub fn unlock_dialog(
    email: &str,
    url: &str,
    keep_above: bool,
    timeout: Duration,
    verify: &dyn Fn(&str) -> Result<(), String>, // audit-allow: String is the human-facing reason/display text
) -> Option<Unlocked> {
    let dialog = gtk::Dialog::new();
    dialog.set_title("Unlock Vaultwarden");
    dialog.set_default_size(460, -1);
    dialog.set_keep_above(keep_above);
    dialog.style_context().add_class("soc-config");
    dialog.add_button("Cancel", gtk::ResponseType::Cancel);
    let go = dialog.add_button("Unlock", gtk::ResponseType::Ok);
    go.style_context().add_class("soc-config-primary");
    dialog.set_default_response(gtk::ResponseType::Ok);

    let content = dialog.content_area();
    content.set_spacing(10);
    content.set_margin_top(18);
    content.set_margin_bottom(8);
    content.set_margin_start(22);
    content.set_margin_end(22);

    let label = |text: &str, class: &str| {
        let l = gtk::Label::new(Some(text));
        l.set_xalign(0.0);
        l.set_line_wrap(true);
        l.set_max_width_chars(52);
        l.style_context().add_class(class);
        content.pack_start(&l, false, false, 0);
        l
    };
    label("Unlock Vaultwarden", "soc-config-title");
    // Plain text, not markup: the account and URL come from configuration.
    let who = if email.is_empty() { "this host" } else { email };
    let at = if url.is_empty() { String::new() } else { format!(" at {url}") };
    label(
        &format!("Enter the master password for {who}{at} to unlock the secrets vault for this session."),
        "soc-config-sub",
    );
    let entry = gtk::Entry::new();
    entry.set_visibility(false);
    entry.set_input_purpose(gtk::InputPurpose::Password);
    entry.set_placeholder_text(Some("master password"));
    entry.set_activates_default(true);
    content.pack_start(&entry, false, false, 0);
    let seal = gtk::CheckButton::with_label("Seal on this host for next boot (no password file)");
    seal.set_active(true);
    content.pack_start(&seal, false, false, 0);
    let error = label("", "soc-config-error");
    error.set_no_show_all(true);

    let fired = Rc::new(Cell::new(false));
    let source = {
        let (dialog, fired) = (dialog.clone(), fired.clone());
        glib::timeout_add_local_once(timeout.max(Duration::from_secs(1)), move || {
            fired.set(true);
            dialog.response(gtk::ResponseType::Cancel);
        })
    };
    dialog.show_all();
    entry.grab_focus();

    let show_error = |text: &str| {
        error.set_text(text);
        error.show();
        entry.grab_focus();
    };
    let outcome = loop {
        if dialog.run() != gtk::ResponseType::Ok {
            break None;
        }
        let master = Zeroizing::new(entry.text().to_string());
        if master.is_empty() {
            show_error("Enter the master password to unlock the vault.");
            continue;
        }
        match verify(&master) {
            Ok(()) => break Some(Unlocked { master, seal: seal.is_active() }),
            Err(reason) => {
                let reason = if reason.is_empty() { "The master password was rejected. Try again." } else { &reason };
                show_error(reason);
                entry.set_text("");
            }
        }
    };
    if !fired.get() {
        source.remove();
    }
    entry.set_text("");
    dialog.close();
    while gtk::events_pending() {
        gtk::main_iteration();
    }
    outcome
}

/// Show a one-time notice (the freshly generated sealing PIN, say) and wait
/// for it to be acknowledged, at most `timeout`.
pub fn notice(title: &str, body: &str, timeout: Duration) {
    let dialog = gtk::MessageDialog::new(
        None::<&gtk::Window>,
        gtk::DialogFlags::MODAL,
        gtk::MessageType::Info,
        gtk::ButtonsType::Ok,
        title,
    );
    dialog.set_secondary_text(Some(body));
    dialog.set_keep_above(true);
    let fired = Rc::new(Cell::new(false));
    let source = {
        let (dialog, fired) = (dialog.clone(), fired.clone());
        glib::timeout_add_local_once(timeout, move || {
            fired.set(true);
            dialog.response(gtk::ResponseType::Close);
        })
    };
    dialog.run();
    if !fired.get() {
        source.remove();
    }
    dialog.close();
    while gtk::events_pending() {
        gtk::main_iteration();
    }
}
