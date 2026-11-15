//! Single-window layout: one fullscreen top-level window holding every WebKit
//! panel in a homogeneous grid.
//!
//! This is the native Wayland path — clients cannot position their own
//! windows there, but a grid inside ONE fullscreen window needs no window
//! management at all, so it works identically under cage, labwc, sway,
//! Openbox or a bare Xvfb. Cells track the real screen size and `display.gap`
//! becomes the grid spacing.

use super::ffi;
use gtk::prelude::*;
use soc_core::{Config, DictExt, Panel};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;
use std::rc::Rc;

/// State shown on a VPN pill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PillState {
    Online,
    Offline,
    Unconfigured,
    Checking,
    Connecting,
}

impl PillState {
    const ALL: [PillState; 5] =
        [PillState::Online, PillState::Offline, PillState::Unconfigured, PillState::Checking, PillState::Connecting];

    pub const fn css_class(self) -> &'static str {
        match self {
            PillState::Online => "online",
            PillState::Offline => "offline",
            PillState::Unconfigured => "unconfigured",
            PillState::Checking => "checking",
            PillState::Connecting => "connecting",
        }
    }

    const fn dot(self) -> &'static str {
        match self {
            PillState::Online | PillState::Offline => "● ",
            PillState::Checking => "… ",
            PillState::Connecting => "◐ ",
            PillState::Unconfigured => "",
        }
    }
}

/// What the toolbar buttons do. `None` hides the button.
#[derive(Default, Clone)]
pub struct WallActions {
    /// Open the on-screen config (also Ctrl+Shift+C).
    pub on_config: Option<Rc<dyn Fn()>>,
    /// Re-check / reconnect the VPN (the pills).
    pub on_vpn: Option<Rc<dyn Fn()>>,
    /// Lock the wall (also Ctrl+Alt+L).
    pub on_lock: Option<Rc<dyn Fn()>>,
    /// Open the live VPN-log viewer (observe only; does not reconnect).
    pub on_show_vpn_log: Option<Rc<dyn Fn()>>,
    /// The wall window is gone: shut the host down.
    pub on_destroy: Option<Rc<dyn Fn()>>,
}

struct Pill {
    button: gtk::Button,
    name: String,
    shown: RefCell<Option<(PillState, String)>>,
}

struct Inner {
    window: gtk::Window,
    grid: gtk::Grid,
    pills: Vec<Pill>,
    cells: RefCell<HashMap<String, gtk::Widget>>,
    fullscreen: Cell<bool>,
    size: (i32, i32),
    windowed: bool,
    log: Rc<dyn Fn(&str)>,
}

/// The wall window.
#[derive(Clone)]
pub struct WallWindow {
    inner: Rc<Inner>,
}

/// The names the pills carry: one pill per enabled VPN when there are
/// several, else a single aggregate pill (empty name).
pub fn pill_names(conf: &Config) -> Vec<String> {
    let enabled: Vec<String> = conf.enabled_vpns().map(|v| v.text("name")).collect();
    if enabled.len() > 1 { enabled } else { vec![String::new()] }
}

fn toolbar_button(label: &str, class: &str, tooltip: &str, action: Rc<dyn Fn()>) -> gtk::Button {
    let button = gtk::Button::with_label(label);
    button.style_context().add_class(class);
    button.set_tooltip_text(Some(tooltip));
    button.connect_clicked(move |_| action());
    button
}

impl WallWindow {
    /// Build the window (not yet shown). `windowed` keeps it a normal desktop
    /// window instead of taking over the screen.
    pub fn new(conf: &Config, windowed: bool, actions: WallActions, log: Rc<dyn Fn(&str)>) -> WallWindow {
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_title("soc-wall");
        ffi::set_wmclass(&window, "soc-wall");

        let grid = gtk::Grid::new();
        grid.set_row_homogeneous(true);
        grid.set_column_homogeneous(true);
        let gap = u32::try_from(conf.display.gap).unwrap_or(0);
        grid.set_row_spacing(gap);
        grid.set_column_spacing(gap);

        // A real toolbar, not an overlay: a loaded web view paints over
        // overlay siblings, which would hide floating controls. A region of
        // its own above the grid stays visible and clickable.
        let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        toolbar.style_context().add_class("soc-toolbar");
        let mut pills = Vec::new();
        for name in pill_names(conf) {
            let label = format!("{}: …", if name.is_empty() { "VPN" } else { &name });
            let button = gtk::Button::with_label(&label);
            button.style_context().add_class("soc-vpn-pill");
            button.style_context().add_class(PillState::Unconfigured.css_class());
            button.set_tooltip_text(Some("VPN status — click to re-check / reconnect"));
            if let Some(on_vpn) = actions.on_vpn.clone() {
                button.connect_clicked(move |_| on_vpn());
            }
            toolbar.pack_start(&button, false, false, 0);
            pills.push(Pill { button, name, shown: RefCell::new(None) });
        }
        toolbar.pack_start(&gtk::Box::new(gtk::Orientation::Horizontal, 0), true, true, 0);
        // pack_end stacks from the right: gear rightmost, lock to its left.
        if let Some(on_config) = actions.on_config.clone() {
            toolbar.pack_end(
                &toolbar_button("⚙ Settings", "soc-gear", "Configure panels (Ctrl+Shift+C)", on_config),
                false,
                false,
                0,
            );
        }
        if let Some(on_lock) = actions.on_lock.clone() {
            toolbar.pack_end(
                &toolbar_button(
                    "🔒 Lock",
                    "soc-toolbar-action",
                    "Lock the wall (Ctrl+Alt+L). Panels stay visible.",
                    on_lock,
                ),
                false,
                false,
                0,
            );
        }
        let shot = gtk::Button::with_label("📷 Shot");
        shot.style_context().add_class("soc-toolbar-action");
        shot.set_tooltip_text(Some("Save a screenshot of the wall"));
        toolbar.pack_end(&shot, false, false, 0);
        // The VPN-log button only observes (the pill reconnects), so it is
        // distinct from the pills and sits to the left of Lock.
        if let Some(on_show_vpn_log) = actions.on_show_vpn_log.clone() {
            toolbar.pack_end(
                &toolbar_button(
                    "📜 VPN log",
                    "soc-toolbar-action",
                    "Open the live VPN log viewer — streams the VPN journal. Does not reconnect (use the pill).",
                    on_show_vpn_log,
                ),
                false,
                false,
                0,
            );
        }

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 0);
        vbox.pack_start(&toolbar, false, false, 0);
        vbox.pack_start(&grid, true, true, 0);
        window.add(&vbox);

        let inner = Rc::new(Inner {
            window,
            grid,
            pills,
            cells: RefCell::new(HashMap::new()),
            fullscreen: Cell::new(!windowed),
            size: (conf.display.width, conf.display.height),
            windowed,
            log,
        });
        let wall = WallWindow { inner };

        let weak = Rc::downgrade(&wall.inner);
        shot.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                WallWindow { inner }.take_screenshot();
            }
        });

        // Window-wide accelerators so the hotkeys still work while a web view
        // has the keyboard focus.
        let accel = gtk::AccelGroup::new();
        wall.inner.window.add_accel_group(&accel);
        for (combo, action) in
            [("<Control><Shift>c", actions.on_config.clone()), ("<Control><Alt>l", actions.on_lock.clone())]
        {
            let Some(action) = action else {
                continue;
            };
            let (key, mods) = gtk::accelerator_parse(combo);
            if key != 0 {
                accel.connect_accel_group(key, mods, gtk::AccelFlags::empty(), move |_, _, _, _| {
                    action();
                    true
                });
            }
        }
        let weak = Rc::downgrade(&wall.inner);
        wall.inner.window.connect_key_press_event(move |_, event| {
            // F11 toggles fullscreen (handy when running windowed / in dev).
            if event.keyval() == gdk::keys::constants::F11 {
                if let Some(inner) = weak.upgrade() {
                    WallWindow { inner }.toggle_fullscreen();
                }
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
        // Losing the wall window (the compositor killed it) leaves nothing on
        // screen: shut down so the supervisor restarts the host.
        if let Some(on_destroy) = actions.on_destroy {
            wall.inner.window.connect_destroy(move |_| on_destroy());
        }
        wall
    }

    pub fn window(&self) -> &gtk::Window {
        &self.inner.window
    }

    /// Update a pill. `name` picks that VPN's pill; `Some("")` the first
    /// pill; `None` every pill. The same reading restyles nothing.
    pub fn set_vpn_status(&self, state: PillState, label: &str, name: Option<&str>) {
        let targets = self.inner.pills.iter().enumerate().filter(|(i, pill)| match name {
            None => true,
            Some("") => *i == 0,
            Some(n) => pill.name == n,
        });
        for (_, pill) in targets {
            let reading = (state, label.to_string());
            if pill.shown.borrow().as_ref() == Some(&reading) {
                continue;
            }
            let ctx = pill.button.style_context();
            for s in PillState::ALL {
                ctx.remove_class(s.css_class());
            }
            ctx.add_class(state.css_class());
            pill.button.set_label(&format!("{}{label}", state.dot()));
            *pill.shown.borrow_mut() = Some(reading);
        }
    }

    /// Put a panel's widget into its grid cell.
    pub fn attach(&self, panel: &Panel, widget: &gtk::Widget) {
        widget.set_hexpand(true);
        widget.set_vexpand(true);
        let (col, row) = panel.grid;
        self.inner.grid.attach(widget, i32::try_from(col).unwrap_or(0), i32::try_from(row).unwrap_or(0), 1, 1);
        widget.show_all();
        self.inner.cells.borrow_mut().insert(panel.id.clone(), widget.clone());
    }

    /// Take a panel's widget off the grid.
    pub fn detach(&self, panel_id: &str) {
        if let Some(widget) = self.inner.cells.borrow_mut().remove(panel_id) {
            self.inner.grid.remove(&widget);
        }
    }

    /// Set the grid's row and column spacing (applies live).
    pub fn set_gap(&self, gap: i32) {
        let gap = u32::try_from(gap.max(0)).unwrap_or(0);
        self.inner.grid.set_row_spacing(gap);
        self.inner.grid.set_column_spacing(gap);
    }

    /// Resize a windowed wall; a fullscreen one keeps filling the screen.
    pub fn resize(&self, width: i32, height: i32) {
        if self.inner.fullscreen.get() {
            self.fit_to_screen();
        } else {
            self.inner.window.resize(width.max(1), height.max(1));
        }
    }

    /// Switch between fullscreen and a regular window.
    pub fn set_fullscreen(&self, fullscreen: bool) {
        if self.inner.fullscreen.replace(fullscreen) == fullscreen {
            return;
        }
        if fullscreen {
            self.inner.window.fullscreen();
            self.fit_to_screen();
        } else {
            self.inner.window.unfullscreen();
        }
    }

    /// Re-attach every live view at its panel's (new) grid cell. The views are
    /// the live widgets: nothing reloads.
    pub fn reflow(&self, panels: &[Panel]) {
        let cells = self.inner.cells.borrow();
        // Detach all first: two panels swapping cells must not overlap.
        for widget in panels.iter().filter_map(|p| cells.get(&p.id)) {
            self.inner.grid.remove(widget);
        }
        for panel in panels {
            let Some(widget) = cells.get(&panel.id) else {
                continue;
            };
            let (col, row) = panel.grid;
            self.inner.grid.attach(widget, i32::try_from(col).unwrap_or(0), i32::try_from(row).unwrap_or(0), 1, 1);
            widget.show_all();
        }
    }

    fn screen_size(&self) -> (i32, i32) {
        gdk::Display::default()
            .and_then(|d| d.primary_monitor().or_else(|| d.monitor(0)))
            .map(|m| m.geometry())
            .filter(|g| g.width() > 0 && g.height() > 0)
            .map_or(self.inner.size, |g| (g.width(), g.height()))
    }

    /// Resize the window to fill the current screen. Needed when there is no
    /// window manager to maximise us (a resized nested server, a bare Xvfb, a
    /// monitor change), where `fullscreen()` alone is a no-op.
    fn fit_to_screen(&self) {
        if !self.inner.fullscreen.get() {
            return;
        }
        let (w, h) = self.screen_size();
        self.inner.window.move_(0, 0);
        self.inner.window.resize(w.max(1), h.max(1));
    }

    fn toggle_fullscreen(&self) {
        let now = !self.inner.fullscreen.get();
        self.inner.fullscreen.set(now);
        if now {
            self.inner.window.fullscreen();
            self.fit_to_screen();
        } else {
            self.inner.window.unfullscreen();
        }
    }

    /// Grab the wall on the main thread, then encode + save off it: encoding a
    /// full screen takes about a second on a Pi and would stall every panel.
    fn take_screenshot(&self) {
        let log = self.inner.log.clone();
        let Some(gdk_window) = self.inner.window.window() else {
            return log("screenshot failed: the window is not realized");
        };
        let Some(pixbuf) = gdk_window.pixbuf(0, 0, gdk_window.width(), gdk_window.height()) else {
            return log("screenshot failed: this backend cannot read the window");
        };
        let png = match pixbuf.save_to_bufferv("png", &[]) {
            Ok(png) => png,
            Err(e) => return log(&format!("screenshot failed: {e}")),
        };
        let stamp = glib::DateTime::now_local().ok().and_then(|t| t.format("%Y%m%d-%H%M%S").ok());
        let (Some(stamp), Some(home)) = (stamp, glib::home_dir().to_str().map(str::to_owned)) else {
            return log("screenshot failed: cannot name the file");
        };
        let path = std::path::Path::new(&home).join(format!("soc-wall-{stamp}.png"));
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            // 0600 from the first byte, never following a pre-placed link: a
            // wall screenshot shows whatever the dashboards were showing.
            let saved = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut file| std::io::Write::write_all(&mut file, &png));
            let outcome = match saved {
                Ok(()) => format!("screenshot saved: {}", path.display()),
                Err(e) => format!("screenshot failed: {e}"),
            };
            let _ = tx.send(outcome); // audit-allow: best-effort, receiver gone means the caller gave up
        });
        glib::timeout_add_local(std::time::Duration::from_millis(200), move || match rx.try_recv() {
            Ok(message) => {
                log(&message);
                glib::ControlFlow::Break
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
        });
    }

    /// Show the window: fullscreen by default, or a regular decorated window
    /// in windowed mode. F11 toggles at runtime.
    pub fn show(&self) {
        let inner = &self.inner;
        let fullscreen = inner.fullscreen.get();
        let (w, h) = if fullscreen { self.screen_size() } else { inner.size };
        inner.window.set_default_size(w.max(1), h.max(1));
        if fullscreen {
            inner.window.fullscreen();
        } else {
            inner.window.set_decorated(true);
            inner.window.set_resizable(true);
        }
        inner.window.show_all();
        if fullscreen {
            self.fit_to_screen();
            // Keep filling the screen when it changes under us: a resized
            // nested server, a monitor hotplug or a mode switch.
            if let Some(screen) = gdk::Screen::default() {
                for signal in ["size-changed", "monitors-changed"] {
                    let weak = Rc::downgrade(inner);
                    screen.connect_local(signal, false, move |_| {
                        if let Some(inner) = weak.upgrade() {
                            WallWindow { inner }.fit_to_screen();
                        }
                        None
                    });
                }
            }
            // Some compositors settle late: re-fit shortly after first map.
            let weak = Rc::downgrade(inner);
            glib::timeout_add_local_once(std::time::Duration::from_millis(400), move || {
                if let Some(inner) = weak.upgrade() {
                    WallWindow { inner }.fit_to_screen();
                }
            });
        }
        (inner.log)(&format!(
            "wall window shown ({}; single-window layout, {w}x{h}; F11 toggles fullscreen)",
            if inner.windowed { "windowed" } else { "fullscreen" }
        ));
    }
}
