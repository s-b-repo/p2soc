//! Construction smoke test of the Settings window: it opens, every tab builds
//! without a panic, the form validates through `prepare_apply` + the host
//! callback, and closing runs the close callback. Needs a display (CI runs it
//! under Xvfb); without one it is skipped.
#![cfg(feature = "gui")]

use gtk::prelude::*;
use soc_core::Config;
use soc_core::creds::StaticCreds;
use soc_state::{ApplyReport, HostCaps, plan::WriteBack};
use soc_wall::gui::settings::{SettingsContext, SettingsWindow};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

const YAML: &str = "display: {auto: false, width: 1920, height: 1080, cols: 2, rows: 2, gap: 4}\n\
    panels:\n  - {id: p1, url: 'http://a.test/', title: A, vault_item: Login A, selectors: {user: '#u', pass: '#p'}}\n  - {id: p2, grid: [1, 0]}\n\
    vpns:\n  - {name: hq, enabled: false, type: wireguard, config: wg0}\n\
    tunnel: {enabled: false}\nproxy: {enabled: false}\n";

fn find_notebook(w: &gtk::Widget) -> Option<gtk::Notebook> {
    if let Ok(nb) = w.clone().downcast::<gtk::Notebook>() {
        return Some(nb);
    }
    w.clone().downcast::<gtk::Container>().ok()?.children().iter().find_map(find_notebook)
}

fn find_button(w: &gtk::Widget, text: &str) -> Option<gtk::Button> {
    if let Ok(b) = w.clone().downcast::<gtk::Button>() {
        if b.label().is_some_and(|l| l == text) {
            return Some(b);
        }
    }
    w.clone().downcast::<gtk::Container>().ok()?.children().iter().find_map(|c| find_button(c, text))
}

fn pump() {
    for _ in 0..50 {
        while gtk::events_pending() {
            gtk::main_iteration();
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn settings_window_builds_every_tab_and_closes() {
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("no display: skipping the settings smoke test");
        return;
    }
    if gtk::init().is_err() {
        eprintln!("GTK could not initialise: skipping the settings smoke test");
        return;
    }
    let dir = std::env::temp_dir().join(format!("soc-settings-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp state dir");
    let config: Config = soc_core::load_str(YAML, "smoke").expect("valid config");
    let applied: Rc<RefCell<Vec<soc_state::Changes>>> = Rc::default();
    let closed = Rc::new(Cell::new(false));
    let ctx = SettingsContext {
        config,
        state_dir: dir.clone(),
        caps: Rc::new(|| HostCaps { single_wall: true, can_restart_services: false }),
        apply: {
            let applied = applied.clone();
            Rc::new(move |changes| {
                applied.borrow_mut().push(changes.clone());
                ApplyReport::default()
            })
        },
        reload_panels: Rc::new(|| 2),
        restart_wall: Rc::new(|| {}),
        reconnect_vpn: Rc::new(|| {}),
        set_panel_url: Rc::new(|_, _| true),
        login_stats: Rc::new(Vec::new),
        push_config_to_vault: Rc::new(|| WriteBack::Deferred("test".to_string())),
        set_login_zones: Rc::new(|_, _| Ok(false)),
        calibrate: None,
        lock_wall: None,
        show_vpn_log: None,
        creds: Arc::new(StaticCreds::default()),
        vault: None,
        onscreen_enabled: true,
        require_pin: false,
        on_close: {
            let closed = closed.clone();
            Rc::new(move || closed.set(true))
        },
    };
    let window = SettingsWindow::open(ctx);
    window.present();
    pump();

    let toplevel = gtk::Window::list_toplevels()
        .into_iter()
        .find(|w| w.clone().downcast::<gtk::Window>().is_ok_and(|w| w.title().is_some_and(|t| t.contains("settings"))))
        .expect("the settings window is a toplevel");
    let notebook = find_notebook(&toplevel).expect("the form has a notebook");
    assert_eq!(notebook.n_pages(), 9, "Panels + eight lazily built tabs");
    for page in 0..notebook.n_pages() {
        notebook.set_current_page(Some(page));
        pump();
    }

    // Apply goes through prepare_apply, saves overrides.json and calls the host.
    let apply = find_button(&toplevel, "Apply").expect("an Apply button");
    apply.clicked();
    pump();
    assert_eq!(applied.borrow().len(), 1, "Apply reached the host");
    let saved = std::fs::read_to_string(dir.join("overrides.json")).expect("overrides.json written");
    assert!(saved.contains("\"p1\"") && saved.contains("_display"), "{saved}");

    window.close();
    pump();
    assert!(closed.get(), "closing the window runs the close callback");
    std::fs::remove_dir_all(&dir).ok();
}
