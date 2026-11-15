//! Fail-safe screens.
//!
//! Instead of exiting silently (a supervisor would restart into a black
//! screen and the operator would see nothing), the wall shows a themed window
//! saying *why* it cannot start. [`StatusBoard`] is the unattended variant —
//! no buttons, nothing waits for a person, and it keeps a main loop turning
//! while boot steps retry on a worker thread.

use gtk::prelude::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

/// Exit code: restart the wall (the supervisor loops on this one).
pub const EXIT_RELOAD: i32 = 1;
/// Exit code: stop supervising and hand back to an operator.
pub const EXIT_OPERATOR: i32 = 2;

struct Widgets {
    window: gtk::Window,
    title: gtk::Label,
    detail: gtk::Label,
    hint: gtk::Label,
}

fn build(
    title: &str,
    detail: &str,
    hint: &str,
    window_title: &str,
    windowed: bool,
    buttons: &[gtk::Button],
) -> Widgets {
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title(window_title);
    if windowed {
        window.set_default_size(660, 440);
    } else {
        window.fullscreen();
    }
    let column = gtk::Box::new(gtk::Orientation::Vertical, 16);
    column.set_halign(gtk::Align::Center);
    column.set_valign(gtk::Align::Center);
    column.set_margin_top(40);
    column.set_margin_bottom(40);
    column.set_margin_start(60);
    column.set_margin_end(60);
    window.add(&column);

    let label = |text: &str, class: &str| {
        let l = gtk::Label::new(Some(text));
        l.style_context().add_class(class);
        l.set_line_wrap(true);
        l.set_max_width_chars(74);
        l.set_justify(gtk::Justification::Center);
        column.pack_start(&l, false, false, 0);
        l
    };
    // Plain text labels (never markup): the detail often carries an error
    // string that originated outside this process.
    let title = label(title, "soc-fatal-title");
    let detail = label(detail.trim(), "soc-fatal-detail");
    let hint = label(hint, "soc-fatal-hint");
    if !buttons.is_empty() {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        row.set_halign(gtk::Align::Center);
        for b in buttons {
            b.style_context().add_class("soc-toolbar-action");
            row.pack_start(b, false, false, 0);
        }
        column.pack_start(&row, false, false, 0);
    }
    Widgets { window, title, detail, hint }
}

/// Why [`StatusBoard::run`] returned without a value.
#[derive(Debug, PartialEq, Eq)]
pub enum RunError {
    /// SIGTERM/SIGINT arrived: wind down.
    Stopped,
    /// The step outlived its timeout; the process should restart clean.
    Hung,
}

/// What an unattended wall shows while it cannot show the wall, plus the main
/// loop that keeps the process (and its heartbeat) alive meanwhile. Without a
/// usable display the screen is skipped and the loop still runs.
pub struct StatusBoard {
    widgets: Option<Widgets>,
    stopped: Rc<Cell<bool>>,
    current: Rc<RefCell<Option<glib::MainLoop>>>,
    signals: Vec<glib::SourceId>,
    display: bool,
    windowed: bool,
}

impl StatusBoard {
    /// `display`: whether GTK was initialised. `windowed`: a normal window
    /// instead of fullscreen.
    pub fn new(display: bool, windowed: bool) -> StatusBoard {
        let stopped = Rc::new(Cell::new(false));
        let current: Rc<RefCell<Option<glib::MainLoop>>> = Rc::new(RefCell::new(None));
        let signals = [libc::SIGINT, libc::SIGTERM]
            .into_iter()
            .map(|sig| {
                let (stopped, current) = (stopped.clone(), current.clone());
                glib::unix_signal_add_local(sig, move || {
                    stopped.set(true);
                    if let Some(main_loop) = current.borrow().as_ref() {
                        main_loop.quit();
                    }
                    glib::ControlFlow::Continue
                })
            })
            .collect();
        StatusBoard { widgets: None, stopped, current, signals, display, windowed }
    }

    /// A termination signal arrived.
    pub fn stopped(&self) -> bool {
        self.stopped.get()
    }

    /// Put this on screen, updating the window in place if it is already up.
    pub fn show(&mut self, title: &str, detail: &str, hint: &str) {
        if !self.display {
            return;
        }
        match &self.widgets {
            Some(w) => {
                w.title.set_text(title);
                w.detail.set_text(detail.trim());
                w.hint.set_text(hint);
            }
            None => {
                let w = build(title, detail, hint, "SOC Video Wall", self.windowed, &[]);
                // Nobody is here to close it, and a stray close must not
                // leave the box with nothing on screen.
                w.window.connect_delete_event(|_, _| glib::Propagation::Stop);
                if !self.windowed {
                    // For a bare X server with no window manager.
                    let monitor = gdk::Display::default().and_then(|d| d.primary_monitor().or_else(|| d.monitor(0)));
                    if let Some(g) = monitor.map(|m| m.geometry()).filter(|g| g.width() > 0 && g.height() > 0) {
                        w.window.set_default_size(g.width(), g.height());
                    }
                }
                w.window.show_all();
                self.widgets = Some(w);
            }
        }
    }

    fn run_loop(&self, main_loop: &glib::MainLoop) {
        *self.current.borrow_mut() = Some(main_loop.clone());
        main_loop.run();
        *self.current.borrow_mut() = None;
    }

    /// Wait with the main loop turning. Returns early on a signal.
    pub fn sleep(&self, duration: Duration) {
        if self.stopped() {
            return;
        }
        let main_loop = glib::MainLoop::new(None, false);
        let fired = Rc::new(Cell::new(false));
        let source = {
            let (main_loop, fired) = (main_loop.clone(), fired.clone());
            glib::timeout_add_local_once(duration, move || {
                fired.set(true);
                main_loop.quit();
            })
        };
        self.run_loop(&main_loop);
        if !fired.get() {
            source.remove(); // woken early by a signal
        }
    }

    /// Run `step` on a worker thread with the main loop turning until it
    /// returns. A step that outlives `timeout` is abandoned ([`RunError::Hung`]).
    pub fn run<T: Send + 'static>(
        &self,
        timeout: Duration,
        step: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, RunError> {
        if self.stopped() {
            return Err(RunError::Stopped);
        }
        let main_loop = glib::MainLoop::new(None, false);
        let (tx, rx) = std::sync::mpsc::channel::<T>();
        {
            let main_loop = main_loop.clone();
            std::thread::spawn(move || {
                let _ = tx.send(step()); // audit-allow: best-effort, receiver gone means the caller already gave up
                glib::MainContext::default().invoke(move || main_loop.quit());
            });
        }
        let fired = Rc::new(Cell::new(false));
        let source = {
            let (main_loop, fired) = (main_loop.clone(), fired.clone());
            glib::timeout_add_local_once(timeout, move || {
                fired.set(true);
                main_loop.quit();
            })
        };
        self.run_loop(&main_loop);
        if !fired.get() {
            source.remove();
        }
        match rx.try_recv() {
            Ok(value) => Ok(value),
            Err(_) if self.stopped() => Err(RunError::Stopped), // audit-allow: try_recv error kind irrelevant: stopped vs hung is decided by self.stopped()
            Err(_) => Err(RunError::Hung), // audit-allow: try_recv error kind irrelevant: Empty/Disconnected both mean hung
        }
    }

    /// Take the screen down and hand the signals back.
    pub fn close(mut self) {
        for source in self.signals.drain(..) {
            source.remove();
        }
        if let Some(w) = self.widgets.take() {
            w.window.close();
            // So the next window starts clean.
            while gtk::events_pending() {
                gtk::main_iteration();
            }
        }
    }
}

/// The fail-safe screen with nobody to read it: stay up for `reload` so the
/// state is visible, then ask for a restart so everything is re-read from
/// scratch. Whatever fixes the problem (a redeploy, an edited vault note)
/// then reaches the wall on its own — never the operator exit code, which
/// would strand an unattended box.
pub fn fatal_unattended(display: bool, windowed: bool, title: &str, detail: &str, reload: Duration) -> i32 {
    let mut board = StatusBoard::new(display, windowed);
    board.show(
        title,
        detail,
        &format!(
            "This wall needs nothing pressed. It checks again every {} s and recovers by itself once the problem \
             is fixed.",
            reload.as_secs()
        ),
    );
    board.sleep(reload);
    let code = if board.stopped() { 0 } else { EXIT_RELOAD };
    board.close();
    code
}

/// The attended fail-safe: a themed error window that stays on screen until
/// dismissed (so a supervisor does not busy-restart into the same failure).
/// `setup` (when given) is offered as an "Open Setup" button.
pub fn fatal_attended(windowed: bool, title: &str, detail: &str, hint: &str, setup: Option<Box<dyn Fn()>>) -> i32 {
    let quit = gtk::Button::with_label("Quit");
    quit.connect_clicked(|_| gtk::main_quit());
    let mut buttons = Vec::new();
    if let Some(setup) = setup {
        let open = gtk::Button::with_label("Open Setup");
        open.connect_clicked(move |_| setup());
        buttons.push(open);
    }
    buttons.push(quit);
    let w = build(title, detail, hint, "SOC Video Wall — cannot start", windowed, &buttons);
    w.detail.set_selectable(true);
    w.window.connect_destroy(|_| gtk::main_quit());
    w.window.show_all();
    gtk::main();
    EXIT_OPERATOR
}
