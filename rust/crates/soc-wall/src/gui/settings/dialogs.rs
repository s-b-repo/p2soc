//! Modal prompts of the settings window. Each runs a short nested loop (the
//! panels keep painting); none of them does I/O.

use super::widgets::{label, secret_text};
use gtk::prelude::*;
use zeroize::Zeroizing;

fn modal(parent: &gtk::Window, title: &str, ok_label: &str) -> gtk::Dialog {
    let d = gtk::Dialog::with_buttons(
        Some(title),
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        &[("Cancel", gtk::ResponseType::Cancel), (ok_label, gtk::ResponseType::Ok)],
    );
    d.set_default_response(gtk::ResponseType::Ok);
    d.set_default_size(420, 0);
    d
}

fn body(d: &gtk::Dialog) -> gtk::Box {
    let area = d.content_area();
    area.set_spacing(8);
    area.set_margin_start(14);
    area.set_margin_end(14);
    area.set_margin_top(10);
    area.set_margin_bottom(10);
    area
}

/// Something the operator must see: blocks the flow (not the wall) until
/// acknowledged.
pub fn alert(parent: &gtk::Window, title: &str, msg: &str, error: bool) {
    let d = gtk::MessageDialog::new(
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        if error { gtk::MessageType::Error } else { gtk::MessageType::Info },
        gtk::ButtonsType::Ok,
        title,
    );
    d.set_secondary_text(Some(msg));
    d.run();
    d.close();
}

/// An OK / Cancel question.
pub fn ask(parent: &gtk::Window, text: &str, detail: &str) -> bool {
    let d = gtk::MessageDialog::new(
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        gtk::MessageType::Question,
        gtk::ButtonsType::OkCancel,
        text,
    );
    d.set_secondary_text(Some(detail));
    let ok = d.run() == gtk::ResponseType::Ok;
    d.close();
    ok
}

/// A masked PIN / TOTP prompt; `None` on Cancel.
pub fn prompt_code(parent: &gtk::Window, what: &str) -> Option<Zeroizing<String>> {
    let d = modal(parent, &format!("Confirm {what} — enter PIN or TOTP"), "Confirm");
    let area = body(&d);
    area.pack_start(&label(&format!("Enter PIN or TOTP code to confirm {what}."), None), false, false, 0);
    let entry = gtk::Entry::new();
    entry.set_visibility(false);
    entry.set_activates_default(true);
    area.pack_start(&entry, false, false, 0);
    d.show_all();
    entry.grab_focus();
    let ok = d.run() == gtk::ResponseType::Ok;
    let code = secret_text(&entry);
    entry.set_text("");
    d.close();
    ok.then_some(code)
}

/// The operator's OS login: `(username, password)`; `None` on Cancel.
/// `pinned` greys the username (`SOC_OPERATOR_USER` is an explicit setting).
pub fn prompt_os_password(
    parent: &gtk::Window,
    what: &str,
    auto_user: &str,
    pinned: bool,
) -> Option<(String, Zeroizing<String>)> {
    let d = modal(parent, &format!("OS password required — {what}"), "Verify");
    d.set_default_size(440, 0);
    let area = body(&d);
    area.pack_start(
        &label(
            "This action reveals + changes a stored credential. Enter your OS login username + password to continue. \
             Wall PIN/TOTP is not sufficient for reveal operations.",
            None,
        ),
        false,
        false,
        0,
    );
    let user = gtk::Entry::new();
    user.set_text(auto_user);
    user.set_sensitive(!pinned);
    let pass = gtk::Entry::new();
    pass.set_visibility(false);
    pass.set_activates_default(true);
    pass.set_input_purpose(gtk::InputPurpose::Password);
    for (name, w) in [("username", &user), ("password", &pass)] {
        area.pack_start(&label(name, Some("soc-config-sub")), false, false, 0);
        area.pack_start(w, false, false, 0);
    }
    d.show_all();
    pass.grab_focus();
    let ok = d.run() == gtk::ResponseType::Ok;
    let name = user.text().trim().to_string();
    let secret = secret_text(&pass);
    pass.set_text("");
    d.close();
    ok.then(|| (if name.is_empty() { auto_user.to_string() } else { name }, secret))
}

/// What the credential editor returns.
pub struct EditedLogin {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
}

/// The Edit-vault-item dialog, pre-filled with the stored login.
pub fn edit_login(parent: &gtk::Window, name: &str, user: &str, pass: &str) -> Option<EditedLogin> {
    let d = modal(parent, &format!("Edit vault item — {name}"), "Save to vault");
    let area = body(&d);
    let u = gtk::Entry::new();
    u.set_text(user);
    u.set_placeholder_text(Some("username"));
    u.set_activates_default(true);
    let p = gtk::Entry::new();
    p.set_text(pass);
    p.set_visibility(false);
    p.set_placeholder_text(Some("password"));
    p.set_activates_default(true);
    let show = gtk::CheckButton::with_label("show password");
    {
        let p = p.clone();
        show.connect_toggled(move |b| p.set_visibility(b.is_active()));
    }
    for (name, w) in [("username", &u), ("password", &p)] {
        area.pack_start(&label(name, Some("soc-config-sub")), false, false, 0);
        area.pack_start(w, false, false, 0);
    }
    area.pack_start(&show, false, false, 0);
    d.show_all();
    p.grab_focus();
    let ok = d.run() == gtk::ResponseType::Ok;
    let out = EditedLogin { username: secret_text(&u), password: secret_text(&p) };
    u.set_text("");
    p.set_text("");
    d.close();
    ok.then_some(out)
}

/// The vault-sync recovery question: `true` to sync and retry.
pub fn ask_sync_retry(parent: &gtk::Window, name: &str, err: &str) -> bool {
    let d = gtk::MessageDialog::new(
        Some(parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        gtk::MessageType::Warning,
        gtk::ButtonsType::None,
        &format!("Vault read failed for '{name}'"),
    );
    d.set_secondary_text(Some(&format!(
        "{err}\n\nThis usually means the vault cache is stale (the item was added, renamed or deleted in the web \
         vault). 'Sync + retry' refreshes it and tries again."
    )));
    d.add_button("Cancel", gtk::ResponseType::Cancel);
    d.add_button("Sync + retry", gtk::ResponseType::Ok);
    d.set_default_response(gtk::ResponseType::Ok);
    let ok = d.run() == gtk::ResponseType::Ok;
    d.close();
    ok
}

/// Pick a file to import; `None` on Cancel.
pub fn choose_yaml(parent: &gtk::Window) -> Option<std::path::PathBuf> {
    let chooser = gtk::FileChooserDialog::with_buttons(
        Some("Import panels.yaml"),
        Some(parent),
        gtk::FileChooserAction::Open,
        &[("Cancel", gtk::ResponseType::Cancel), ("Open", gtk::ResponseType::Ok)],
    );
    let filter = gtk::FileFilter::new();
    filter.set_name(Some("YAML files"));
    filter.add_pattern("*.yaml");
    filter.add_pattern("*.yml");
    chooser.add_filter(filter);
    let picked = (chooser.run() == gtk::ResponseType::Ok).then(|| chooser.filename()).flatten();
    chooser.close();
    picked
}
