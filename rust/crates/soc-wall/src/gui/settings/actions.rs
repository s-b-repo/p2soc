//! The Actions and Status tabs.
//!
//! Actions are what an operator needs that is not a config edit: recover a
//! wedged panel, soft-restart the wall, reconnect the VPN, push the config to
//! the vault, run repair, reboot. Anything destructive asks twice (a
//! two-click confirm) and, once a credential is enrolled, for the PIN/TOTP.

use super::logic::{StatusFacts, memory_summary, probe_target, status_warnings};
use super::widgets::{UiResult, button, form_grid, in_worker, label, note, scrolled, vbox, wd};
use super::{Win, bind};
use gtk::prelude::*;
use soc_state::plan::WriteBack;
use soc_sys::run::{Runner, SystemRunner, argv};
use std::cell::Cell;
use std::net::{TcpStream, ToSocketAddrs};
use std::rc::Rc;
use std::time::Duration;

/// How long the second click of a two-click confirm stays armed.
const ARM_SECS: u32 = 4;

type Run = Rc<dyn Fn(&Rc<Win>, &gtk::Label)>;

/// A button whose first click only arms it ("Confirm: ..."); the second
/// fires. Prevents an accidental Reboot from a fat-finger.
fn confirm_button(
    win: &Rc<Win>,
    msg: &gtk::Label,
    text: &'static str,
    primary: bool,
    reauth: bool,
    run: Run,
) -> gtk::Button {
    let b = button(text, primary.then_some("soc-config-primary"));
    let armed = Rc::new(Cell::new(false));
    let msg = msg.clone();
    let cb = {
        let (armed, b) = (armed, b.clone());
        bind(win, move |win| {
            if !armed.replace(true) {
                b.set_label(&format!("Confirm: {text}"));
                let (armed, b) = (armed.clone(), b.clone());
                glib::timeout_add_seconds_local_once(ARM_SECS, move || {
                    if armed.replace(false) {
                        b.set_label(text);
                    }
                });
                return;
            }
            armed.set(false);
            b.set_label(text);
            if reauth && win.auth.reauth_required() && !win.require_reauth(&text.to_lowercase()) {
                return msg.set_text(&format!("{text} not run — re-authentication failed."));
            }
            run(win, &msg);
        })
    };
    b.connect_clicked(move |_| cb());
    b
}

/// Run `work` off the GTK thread and report `"<label> ✓"` or the failure.
fn run_worker(msg: &gtk::Label, text: &'static str, work: impl FnOnce() -> UiResult<()> + Send + 'static) {
    msg.set_text(&format!("{text} …"));
    let msg = msg.clone();
    in_worker(work, move |res| match res.and_then(|r| r) {
        Ok(()) => msg.set_text(&format!("{text} ✓")),
        Err(e) => msg.set_text(&format!("{text} failed: {e}")),
    });
}

pub fn build_actions(win: &Rc<Win>) -> gtk::Widget {
    let boxv = vbox(10, 12);
    boxv.pack_start(
        &note("Operator actions. Restart, repair and reboot ask for the Settings PIN/TOTP once one is enrolled."),
        false,
        false,
        0,
    );
    let msg = label("", Some("soc-config-ok"));
    let mut rows: Vec<(&str, gtk::Widget)> = Vec::new();

    let reload = confirm_button(
        win,
        &msg,
        "Reload panels",
        false,
        false,
        Rc::new(|win, msg| msg.set_text(&format!("Reload panels ✓ ({} panels)", (win.ctx.reload_panels)()))),
    );
    reload.set_tooltip_text(Some("Refresh every panel in place (no restart). Use when a panel is stuck."));
    rows.push(("Reload panels (in-place)", wd(&reload)));

    let restart = confirm_button(
        win,
        &msg,
        "Restart wall",
        true,
        true,
        Rc::new(|win, msg| {
            msg.set_text("Restart wall ✓ — restarting …");
            (win.ctx.restart_wall)();
        }),
    );
    restart.set_tooltip_text(Some(
        "Soft-restart the wall process. Use this to apply layout / grid / resolution changes without rebooting the box.",
    ));
    rows.push(("Restart wall", wd(&restart)));

    if win.ctx.lock_wall.is_some() {
        let lock = button("🔒 Lock the wall now", None);
        lock.set_tooltip_text(Some(
            "Same as the toolbar 🔒 and Ctrl+Alt+L. Panels stay visible; keyboard + mouse are inert until a PIN or \
             TOTP is entered. Closes this window.",
        ));
        // Single click (no confirm): locking is reversible and may be urgent.
        let cb = bind(win, |win| {
            // This window is non-modal: left open it would stay usable above the lock.
            win.window.close();
            if let Some(lock) = win.ctx.lock_wall.as_ref() {
                lock();
            }
        });
        lock.connect_clicked(move |_| cb());
        rows.push(("Lock the wall now", wd(&lock)));
    }

    if win.ctx.show_vpn_log.is_some() {
        let log = button("Show VPN log (live)", None);
        log.set_tooltip_text(Some("Opens the live VPN log viewer."));
        let cb = bind(win, |win| {
            if let Some(show) = win.ctx.show_vpn_log.as_ref() {
                show();
            }
        });
        log.connect_clicked(move |_| cb());
        rows.push(("Show VPN log (live)", wd(&log)));
    }

    let vpn = confirm_button(
        win,
        &msg,
        "Reconnect VPN",
        false,
        false,
        Rc::new(|win, msg| {
            (win.ctx.reconnect_vpn)();
            msg.set_text("Reconnect VPN ✓ — restarting the supervisor");
        }),
    );
    vpn.set_tooltip_text(Some("Restart the VPN supervisor so it re-reads the config and reconnects."));
    rows.push(("Reconnect VPN", wd(&vpn)));

    let push = confirm_button(
        win,
        &msg,
        "Push config to vault",
        false,
        true,
        Rc::new(|win, msg| match (win.ctx.push_config_to_vault)() {
            WriteBack::Ready => msg.set_text("Push config to vault ✓ — upload started (see the log for the result)"),
            WriteBack::Deferred(why) => msg.set_text(&format!("Push config to vault not done: {why}")),
        }),
    );
    push.set_tooltip_text(Some("Write the running config to the vault config note (the source of truth at boot)."));
    rows.push(("Push config to vault", wd(&push)));

    let repair = confirm_button(
        win,
        &msg,
        "Repair install",
        false,
        true,
        Rc::new(|_, msg| run_worker(msg, "Repair install", repair_install)),
    );
    repair.set_tooltip_text(Some("Run setup repair as root. Fixes perms, keys."));
    rows.push(("Repair install (setup repair)", wd(&repair)));

    let reboot =
        confirm_button(win, &msg, "Reboot", false, true, Rc::new(|_, msg| run_worker(msg, "Reboot", reboot_machine)));
    reboot.set_tooltip_text(Some("systemctl reboot — needs root."));
    rows.push(("Reboot machine", wd(&reboot)));

    boxv.pack_start(&form_grid(&rows), false, false, 0);
    boxv.pack_start(&msg, false, false, 0);
    scrolled(&boxv).upcast()
}

fn reboot_machine() -> UiResult<()> {
    let ran = SystemRunner.run(&argv(&["systemctl", "reboot"]), Duration::from_secs(10));
    if ran.is_ok_and(|out| out.success()) {
        Ok(())
    } else {
        Err("needs root — run: sudo systemctl reboot".to_string())
    }
}

fn repair_install() -> UiResult<()> {
    let root = soc_core::env::env_str("SOC_DEPLOY_ROOT").unwrap_or_else(|| "/opt/soc-display".to_string());
    let exe = format!("{root}/.venv/bin/python");
    let setup = format!("{root}/setup.py");
    let ran = SystemRunner.run(&argv(&["sudo", "-n", &exe, &setup, "repair"]), Duration::from_secs(600));
    if ran.is_ok_and(|out| out.success()) {
        Ok(())
    } else {
        Err(format!("needs root — run: sudo python3 {setup} repair"))
    }
}

// ---- status ------------------------------------------------------------------------------

/// Cheap TCP probe of the Vaultwarden listener: flags a dead vault before the
/// operator clicks Save on the Credentials tab and gets a confusing "login
/// failed". Does not speak HTTP. Blocking: call it from a worker.
fn vault_reachable(url: &str) -> bool {
    let Some((host, port)) = probe_target(url) else { return false };
    (host.as_str(), port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .is_some_and(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok())
}

pub fn build_status(win: &Rc<Win>) -> gtk::Widget {
    let boxv = vbox(6, 12);
    boxv.pack_start(&label("Wall Status", Some("soc-config-title")), false, false, 0);
    let line = |text: &str| {
        let l = note(text);
        boxv.pack_start(&l, false, false, 0);
        l
    };

    let (configured, total, with_creds) = {
        let session = win.session.borrow();
        let panels = session.panels();
        (
            panels.iter().filter(|p| p.configured()).count(),
            panels.len(),
            panels.iter().filter(|p| !p.vault_item.is_empty()).count(),
        )
    };
    let (cols, rows) = win.grid_size();
    let (url, email, backend, sealed) = match win.ctx.vault.as_ref() {
        Some(v) => (v.url.clone(), v.email.clone(), v.backend.clone(), v.sealed),
        None => (String::new(), String::new(), "(none)".to_string(), false),
    };
    let meminfo = soc_sys::fsutil::read_capped(std::path::Path::new("/proc/meminfo"), 64 * 1024)
        .unwrap_or_else(|_| String::new());
    line(&memory_summary(&meminfo));
    line(&format!("panels         : {configured}/{total} configured, grid {cols} x {rows}"));
    line(&format!("auto-login     : {with_creds}/{total} panel(s) have a vault item"));
    line(&format!("vault backend  : {backend}"));
    let server = line(&format!("vault server   : {url}  (checking …)"));
    line(&format!("vault account  : {}", if email.is_empty() { "(SOC_VAULT_EMAIL is empty)" } else { &email }));
    line(&format!("master sealed  : {}", if sealed { "yes ✓" } else { "NO ✗ — run the setup first-run" }));
    line("VPN status     : shown in the top bar (click the pill to re-check)");

    let (weak, boxv2, probe_url) = (Rc::downgrade(win), boxv.clone(), url.clone());
    in_worker(
        move || vault_reachable(&probe_url),
        move |res| {
            let Some(win) = weak.upgrade().filter(|w| !w.closed.get()) else { return };
            let reachable = matches!(res, Ok(true));
            server.set_text(&format!(
                "vault server   : {url}  ({})",
                if reachable { "reachable ✓" } else { "NOT REACHABLE ✗" }
            ));
            // A panel that burnt its login retries without ever succeeding
            // usually means the dashboard was redesigned.
            let stale = (win.ctx.login_stats)();
            let facts = StatusFacts {
                vault_url: &url,
                vault_email: &email,
                reachable,
                sealed,
                configured,
                with_creds,
                stale: &stale,
            };
            for w in status_warnings(&facts) {
                boxv2.pack_start(&label(&w, Some("soc-config-error")), false, false, 0);
            }
            boxv2.show_all();
        },
    );
    scrolled(&boxv).upcast()
}
