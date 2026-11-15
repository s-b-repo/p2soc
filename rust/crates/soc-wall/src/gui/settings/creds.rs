//! The Credentials tab: the vault items the wall touches, edit / delete, and
//! storing a login's username + password directly in Vaultwarden.
//!
//! Every vault and PAM call runs on a worker ([`in_worker`]); the modal
//! "working..." dialog never spins a nested loop. Secrets travel in
//! `Zeroizing` strings and never reach a log or an argv.

use super::logic::{InventoryItem, inventory_items, is_missing_item, write_failure};
use super::widgets::{
    Busy, UiResult, button, entry, hbox, in_worker, label, note, scrolled, secret_entry, secret_text, vbox,
};
use super::{Win, bind, dialogs, on_click};
use gtk::prelude::*;
use soc_core::{CredError, DictExt};
use soc_state::unix_now;
use soc_vault::{LoginSpec, totp::VAULT_TOTP_FOLDER};
use std::cell::Cell;
use std::rc::Rc;
use zeroize::Zeroizing;

/// The tab's widgets.
#[derive(Clone)]
pub struct CredTab {
    pub msg: gtk::Label,
    inv: gtk::Box,
    master: Option<gtk::Entry>,
    busy: Rc<Cell<bool>>,
}

pub fn build(win: &Rc<Win>) -> gtk::Widget {
    let boxv = vbox(8, 12);
    boxv.pack_start(
        &note(
            "Top: the vault items the wall touches (names only). Edit reveals a stored login and needs your OS \
             password; Delete needs the Settings PIN/TOTP. Bottom: store a login's username + password directly in \
             Vaultwarden, so the wall reads them automatically. Skip a row to leave it for the web vault.",
        ),
        false,
        false,
        0,
    );

    // The inventory, with its buttons at the top so they stay reachable
    // however long the list grows.
    let inv_box = vbox(6, 8);
    let actions = hbox(6);
    let refresh = button("Refresh from vault", None);
    refresh.set_tooltip_text(Some("Re-scan the config + the wall's auth folder for items."));
    on_click(&refresh, win, refresh_inventory);
    let sync = button("Sync vault", None);
    sync.set_tooltip_text(Some(
        "Fetch the latest from Vaultwarden. Use when an item you added in the web vault doesn't show up.",
    ));
    on_click(&sync, win, sync_vault);
    actions.pack_start(&refresh, false, false, 0);
    actions.pack_start(&sync, false, false, 0);
    inv_box.pack_start(&actions, false, false, 0);
    let inv = vbox(4, 0);
    let list_scroll = scrolled(&inv);
    list_scroll.set_min_content_height(120);
    list_scroll.set_max_content_height(240);
    inv_box.pack_start(&list_scroll, true, true, 0);
    boxv.pack_start(&super::widgets::frame("Vault items in use", &inv_box), false, false, 0);

    boxv.pack_start(&save_grid(win), false, false, 0);

    // Only ask for the master at the glass when it isn't sealed on this host;
    // a sealed wall unseals it itself.
    let sealed = win.ctx.vault.as_ref().is_some_and(|v| v.sealed);
    let master = (!sealed).then(|| {
        let row = hbox(6);
        row.pack_start(&label("vault master password:", Some("soc-config-sub")), false, false, 0);
        let e = secret_entry("only needed when the master is not host-sealed");
        row.pack_start(&e, true, true, 0);
        boxv.pack_start(&row, false, false, 0);
        e
    });
    let msg = label("", Some("soc-config-ok"));
    boxv.pack_start(&msg, false, false, 0);
    *win.cred.borrow_mut() = Some(CredTab { msg, inv, master, busy: Rc::new(Cell::new(false)) });
    refresh_inventory(win);
    scrolled(&boxv).upcast()
}

/// The "Save to vault" grid: one row per item the config names.
fn save_grid(win: &Rc<Win>) -> gtk::Grid {
    let grid = gtk::Grid::new();
    grid.set_column_spacing(8);
    grid.set_row_spacing(8);
    for (col, t) in ["vault item", "username", "password", ""].iter().enumerate() {
        grid.attach(&label(t, Some("soc-config-sub")), i32::try_from(col).unwrap_or(0), 0, 1, 1);
    }
    let mut next_row = 1i32;
    let mut seen: Vec<String> = Vec::new();
    let line = |grid: &gtk::Grid, row: &mut i32, w: &gtk::Label| {
        grid.attach(w, 0, *row, 4, 1);
        *row += 1;
    };
    let section = |grid: &gtk::Grid, row: &mut i32, title: &str| {
        let l = label(title, Some("soc-config-tag"));
        l.set_margin_top(6);
        line(grid, row, &l);
    };
    let mut add_row = |grid: &gtk::Grid, row: &mut i32, name: &str, uri: String| {
        let name = name.trim().to_string();
        if name.is_empty() || seen.contains(&name) {
            return;
        }
        seen.push(name.clone());
        let user = entry("", "username");
        user.set_width_chars(15);
        user.set_hexpand(false);
        let pass = secret_entry("password");
        pass.set_width_chars(15);
        pass.set_hexpand(false);
        let save = button("Save to vault", None);
        {
            let (name, user, pass) = (name.clone(), user.clone(), pass.clone());
            on_click(&save, win, move |w| save_row(w, &name, &user, &pass, &uri));
        }
        grid.attach(&label(&name, Some("soc-config-tag")), 0, *row, 1, 1);
        grid.attach(&user, 1, *row, 1, 1);
        grid.attach(&pass, 2, *row, 1, 1);
        grid.attach(&save, 3, *row, 1, 1);
        *row += 1;
    };

    section(&grid, &mut next_row, "Panel logins");
    let panels = win.session.borrow().panels().to_vec();
    let with_item: Vec<_> = panels.iter().filter(|p| !p.vault_item.is_empty()).collect();
    for p in &with_item {
        add_row(&grid, &mut next_row, &p.vault_item, p.effective_url());
    }
    if with_item.is_empty() {
        line(
            &grid,
            &mut next_row,
            &label("No panel vault logins configured. Set a 'vault login' on a panel first.", None),
        );
    }
    section(&grid, &mut next_row, "VPN logins");
    let vpn_items: Vec<String> =
        win.vpn_entries().iter().map(|v| v.text("vault_item")).filter(|n| !n.is_empty()).collect();
    for name in &vpn_items {
        add_row(&grid, &mut next_row, name, String::new());
    }
    if vpn_items.is_empty() {
        line(&grid, &mut next_row, &label("No VPN vault login. Set one in the VPN tab.", None));
    }
    section(&grid, &mut next_row, "Proxy login");
    let proxy_item = win.conf.borrow().proxy.vault_item.clone();
    if proxy_item.is_empty() {
        line(&grid, &mut next_row, &label("No proxy vault login configured.", None));
    } else {
        add_row(&grid, &mut next_row, &proxy_item, String::new());
    }
    grid
}

fn save_row(win: &Rc<Win>, name: &str, user: &gtk::Entry, pass: &gtk::Entry, uri: &str) {
    let username = secret_text(user);
    if username.trim().is_empty() {
        return win.toast(&format!("{name}: enter a username first"));
    }
    if win.auth.reauth_required() && !win.require_reauth(&format!("saving the login for '{name}'")) {
        return;
    }
    let secret = secret_text(pass);
    win.toast(&format!("writing '{name}' …"));
    let pass = pass.clone();
    let uri = (!uri.is_empty()).then(|| uri.to_string());
    write_login(win, name, Zeroizing::new(username.trim().to_string()), secret, uri, move |win, msg, ok| {
        win.toast(&msg);
        if ok {
            pass.set_text("");
        } else {
            win.alert("Vault save failed", &msg, true);
        }
    });
}

/// Upsert a login in Vaultwarden on a worker, then `done(window, message, ok)`
/// on the GTK loop. An existing item keeps its notes, TOTP and URI. The
/// host-bound unseal (a ~100-300 ms scrypt on a small board) stays in the
/// worker so it cannot freeze the wall.
pub fn write_login(
    win: &Rc<Win>,
    name: &str,
    user: Zeroizing<String>,
    pass: Zeroizing<String>,
    uri: Option<String>,
    done: impl FnOnce(&Rc<Win>, String, bool) + 'static,
) {
    let Some(access) = win.ctx.vault.clone() else {
        return done(win, "no vault is attached to this Settings window".to_string(), false);
    };
    let typed = win
        .cred
        .borrow()
        .as_ref()
        .and_then(|c| c.master.as_ref().map(secret_text))
        .unwrap_or_else(|| Zeroizing::new(String::new()));
    let (name, url, weak) = (name.to_string(), access.url.clone(), Rc::downgrade(win));
    let worker_name = name.clone();
    in_worker(
        move || -> UiResult<String> {
            let session = access.write_session(&typed)?;
            let existing = session.get_login(&worker_name).map_err(|e| e.to_string())?;
            let keep = |v: Option<&Zeroizing<String>>| v.filter(|s| !s.is_empty()).map(|s| s.as_str().to_string());
            let (notes, totp, old_uri) = (
                keep(existing.as_ref().map(|r| &r.notes)),
                keep(existing.as_ref().map(|r| &r.totp)),
                keep(existing.as_ref().map(|r| &r.uri)),
            );
            let uri = uri.or(old_uri);
            let spec = LoginSpec {
                name: &worker_name,
                username: &user,
                password: &pass,
                notes: notes.as_deref(),
                uri: uri.as_deref(),
                totp: totp.as_deref(),
                rename_from: None,
            };
            let action = session.upsert_login(&spec).map_err(|e| e.to_string())?;
            // Or the TTL cache keeps serving the old one.
            access.vault.invalidate(Some(&worker_name));
            Ok(format!("{} '{worker_name}' in Vaultwarden ✓", action.as_str()))
        },
        move |res| {
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            match res.and_then(|r| r) {
                Ok(msg) => done(&win, msg, true),
                Err(e) => done(&win, write_failure(&name, &e, &url), false),
            }
        },
    );
}

// ---- inventory -------------------------------------------------------------------

fn inventory(win: &Win, folder: &[String]) -> Vec<InventoryItem> {
    let panels = win.session.borrow().panels().to_vec();
    let conf = win.conf.borrow();
    inventory_items(&panels, &win.vpn_entries(), &conf.proxy.vault_item, &conf.tunnel, folder, VAULT_TOTP_FOLDER)
}

/// Rebuild the inventory rows: at once from the config, then again when the
/// vault's folder listing arrives. A hung vault just never adds its rows.
pub fn refresh_inventory(win: &Rc<Win>) {
    let Some(cred) = win.cred.borrow().clone() else { return };
    render_inventory(win, &cred.inv, &inventory(win, &[]));
    let Some(access) = win.ctx.vault.clone() else { return };
    if cred.busy.replace(true) {
        return;
    }
    let weak = Rc::downgrade(win);
    in_worker(
        move || access.vault.list_by_folder(VAULT_TOTP_FOLDER),
        move |res| {
            cred.busy.set(false);
            let (Some(win), Ok(folder)) = (weak.upgrade().filter(|w| !w.closed.get()), res) else { return };
            render_inventory(&win, &cred.inv, &inventory(&win, &folder));
        },
    );
}

fn render_inventory(win: &Rc<Win>, list: &gtk::Box, items: &[InventoryItem]) {
    for child in list.children() {
        list.remove(&child);
    }
    if items.is_empty() {
        list.pack_start(
            &note("(no vault items pinned yet — give a panel/VPN/proxy a vault item first)"),
            false,
            false,
            0,
        );
    }
    for item in items {
        let row = hbox(8);
        let edit = button("Edit", None);
        // Edit reveals the stored secret, so it asks for the OS password: a
        // higher bar than the wall PIN that Delete takes.
        edit.set_tooltip_text(Some(
            "Reveal + change the username/password for this vault item. Requires your OS login password (NOT the wall PIN).",
        ));
        let delete = button("Delete", Some("destructive-action"));
        delete.set_tooltip_text(Some("Permanent. PIN/TOTP required."));
        for (btn, handler) in [(&edit, edit_item as fn(&Rc<Win>, &str)), (&delete, delete_item)] {
            let name = item.name.clone();
            let cb = bind(win, move |w| handler(w, &name));
            btn.connect_clicked(move |_| cb());
        }
        let name_label = label(&item.name, Some("soc-config-tag"));
        name_label.set_hexpand(true);
        row.pack_start(&name_label, true, true, 0);
        row.pack_start(&label(&format!("({})", item.origin), Some("soc-config-sub")), false, false, 0);
        row.pack_start(&edit, false, false, 0);
        row.pack_start(&delete, false, false, 0);
        list.pack_start(&row, false, false, 0);
    }
    list.show_all();
}

/// Force the vault to fetch the latest, then refresh the inventory.
fn sync_vault(win: &Rc<Win>) {
    let Some(access) = win.ctx.vault.clone() else {
        return win.alert("Vault unavailable", "No vault handle is attached to this Settings window.", true);
    };
    win.toast("syncing vault …");
    let weak = Rc::downgrade(win);
    in_worker(
        move || access.vault.resync().map_err(|e| e.to_string()),
        move |res| {
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            match res.and_then(|r| r) {
                Ok(()) => win.toast("vault synced ✓"),
                Err(e) => win.alert(
                    "Vault sync failed",
                    &format!(
                        "Vault sync failed:\n\n{e}\n\nCommon causes: Vaultwarden unreachable (check `systemctl \
                         status vaultwarden`) or the vault is locked."
                    ),
                    true,
                ),
            }
            refresh_inventory(&win);
        },
    );
}

// ---- edit ---------------------------------------------------------------------------

/// Edit flow: OS password -> read via the vault -> modal with user + pass ->
/// upsert. The OS password is the only operator-side disclosure path for
/// stored secrets, so it is gated by the same authentication root would need.
fn edit_item(win: &Rc<Win>, name: &str) {
    if win.ctx.vault.is_none() {
        return win.alert(
            "Vault unavailable",
            &format!("Cannot edit '{name}': no vault handle is attached to this Settings window."),
            true,
        );
    }
    let wait = win.os_budget.remaining(unix_now());
    if wait > 0 {
        return win.alert("Too many wrong attempts", &format!("Wait {wait} s before trying again."), false);
    }
    let auto_user = soc_seal::ospass::operator_user();
    let pinned = std::env::var("SOC_OPERATOR_USER").is_ok_and(|v| v.trim() == auto_user);
    let Some((user, password)) =
        dialogs::prompt_os_password(&win.window, &format!("edit '{name}'"), &auto_user, pinned)
    else {
        return;
    };
    let busy = Busy::show(&win.window, "Checking the OS password …");
    let (weak, name, shown_user) = (Rc::downgrade(win), name.to_string(), user.clone());
    // PAM can take seconds: off the GTK thread.
    in_worker(
        move || soc_seal::ospass::verify_os_password(&user, &password),
        move |res| {
            let cancelled = busy.cancelled();
            busy.finish();
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            if cancelled {
                return;
            }
            if matches!(res, Ok(true)) {
                win.os_budget.passed();
                return fetch_for_edit(&win, &name, 1);
            }
            win.os_budget.failed(unix_now());
            win.alert(
                "OS password rejected",
                &format!(
                    "OS password rejected for user '{shown_user}'.\n\nCommon causes:\n  • Wrong username — override the \
                     detected one in the field if your desktop user is different, or set SOC_OPERATOR_USER in \
                     soc.env.\n  • Wrong password — the wall checks your LOCAL OS login password, NOT the wall PIN, \
                     vault master, or anything in Vaultwarden.\n  • The account has no password: such an account \
                     cannot vouch for anything. Set one with: sudo passwd <user>"
                ),
                true,
            );
        },
    );
}

/// Read the item on a worker; on a transport error offer "Sync + retry".
fn fetch_for_edit(win: &Rc<Win>, name: &str, attempt: u32) {
    let busy = Busy::show(&win.window, &format!("Reading '{name}' from the vault …"));
    let (creds, weak, item) = (win.ctx.creds.clone(), Rc::downgrade(win), name.to_string());
    let worker_item = item.clone();
    in_worker(
        move || creds.creds(&worker_item),
        move |res| {
            let cancelled = busy.cancelled();
            busy.finish();
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            if cancelled {
                return;
            }
            match res {
                Ok(Ok(login)) => {
                    let (u, p) = (Zeroizing::new(login.username.clone()), Zeroizing::new(login.password.clone()));
                    edit_dialog(&win, &item, &u, &p);
                }
                Ok(Err(CredError::NotFound(_))) => create_prompt(&win, &item),
                Ok(Err(e)) if is_missing_item(&e.to_string()) => create_prompt(&win, &item),
                Ok(Err(e)) => recover_read(&win, &item, &e.to_string(), attempt),
                Err(e) => win.alert(
                    "Vault not responding",
                    &format!("{e}\n\nCheck `systemctl status vaultwarden`, then retry Edit."),
                    true,
                ),
            }
        },
    );
}

/// The normal first-time path (a VPN whose creds were never saved), not an
/// error: Save creates the item, and the OS password is already enough auth.
fn create_prompt(win: &Rc<Win>, name: &str) {
    win.alert(
        &format!("Create vault item '{name}'?"),
        "This vault item doesn't exist yet. The next dialog lets you fill in the username + password; Save will CREATE \
         the item in Vaultwarden.",
        false,
    );
    edit_dialog(win, name, "", "");
}

/// A permanently-down vault must not loop here forever: three tries.
fn recover_read(win: &Rc<Win>, name: &str, err: &str, attempt: u32) {
    if attempt >= 3 {
        return win.alert(
            "Vault read keeps failing",
            &format!("Vault read still failing for '{name}' after sync retry:\n\n{err}\n\nCheck `systemctl status vaultwarden`, then retry Edit."),
            true,
        );
    }
    if !dialogs::ask_sync_retry(&win.window, name, err) {
        return;
    }
    let Some(access) = win.ctx.vault.clone() else { return };
    let busy = Busy::show(&win.window, "Syncing the vault …");
    let (weak, name) = (Rc::downgrade(win), name.to_string());
    in_worker(
        move || access.vault.resync().map_err(|e| e.to_string()),
        move |_| {
            let cancelled = busy.cancelled();
            busy.finish();
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            // A failed sync surfaces through the retry, which reads again.
            if !cancelled {
                fetch_for_edit(&win, &name, attempt + 1);
            }
        },
    );
}

fn edit_dialog(win: &Rc<Win>, name: &str, user: &str, pass: &str) {
    let Some(edited) = dialogs::edit_login(&win.window, name, user, pass) else { return };
    if edited.username.trim().is_empty() && edited.password.is_empty() {
        return win.alert("Nothing to save", "Both username AND password are empty — nothing to save.", false);
    }
    write_login(
        win,
        name,
        Zeroizing::new(edited.username.trim().to_string()),
        edited.password,
        None,
        |win, msg, ok| {
            win.toast(&msg);
            win.alert(if ok { "Vault edit succeeded" } else { "Vault edit failed" }, &msg, !ok);
            refresh_inventory(win);
        },
    );
}

// ---- delete -------------------------------------------------------------------------

/// Two-step: re-auth, then confirm, then delete on a worker + refresh.
fn delete_item(win: &Rc<Win>, name: &str) {
    if !win.require_reauth(&format!("delete of vault item '{name}'")) {
        return;
    }
    if !win.ask(
        &format!("Delete vault item '{name}'?"),
        "This is permanent. Any panel / VPN / proxy referencing this item will fail to auto-login until the item is \
         recreated or the field is re-pointed at a different vault item.",
    ) {
        return;
    }
    let Some(access) = win.ctx.vault.clone() else {
        return win.alert(
            "Vault unavailable",
            &format!("Cannot delete '{name}': no vault handle is attached to this Settings window."),
            true,
        );
    };
    win.toast(&format!("deleting '{name}' …"));
    let (weak, item) = (Rc::downgrade(win), name.to_string());
    let worker_item = item.clone();
    in_worker(
        move || access.vault.delete(&worker_item),
        move |res| {
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            match res {
                Ok(true) => {
                    win.toast(&format!("deleted '{item}' ✓"));
                    refresh_inventory(&win);
                }
                Ok(false) => win.alert(
                    "Delete failed",
                    &format!(
                        "Delete failed for '{item}'.\n\nThe vault reported a failure. Check `journalctl -u soc-wall -n \
                         30` for details. The item may already be gone (Refresh would then remove the row from the \
                         list)."
                    ),
                    true,
                ),
                Err(e) => win.alert("Delete failed", &format!("Delete failed for '{item}'.\n\n{e}"), true),
            }
        },
    );
}
