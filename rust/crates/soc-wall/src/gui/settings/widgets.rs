//! Small widget builders shared by the settings tabs, plus the off-thread
//! helper every vault / PAM / network call goes through.

use gtk::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// A failure with the text the operator reads; never contains a secret.
pub type UiResult<T> = Result<T, String>; // audit-allow: String is the human-facing reason/display text

/// A worker that outlives this is abandoned (its result is dropped).
const WORKER_LIMIT: Duration = Duration::from_secs(600);

/// Run `work` on a daemon-like thread and hand its result to `done` on the GTK
/// loop. `work` must not touch GTK. `Err` means the worker died or hung.
/// The channel is polled from the main loop: the closure graph is not `Send`,
/// so `MainContext::invoke` cannot carry it.
pub fn in_worker<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
    done: impl FnOnce(UiResult<T>) + 'static,
) {
    let (tx, rx): (_, Receiver<T>) = channel();
    std::thread::spawn(move || {
        if tx.send(work()).is_err() {
            // the window is gone; nobody wants the result
        }
    });
    let started = Instant::now();
    let mut done = Some(done);
    glib::timeout_add_local(Duration::from_millis(100), move || {
        let outcome = match rx.try_recv() {
            Ok(v) => Ok(v),
            Err(TryRecvError::Empty) if started.elapsed() < WORKER_LIMIT => return glib::ControlFlow::Continue,
            Err(TryRecvError::Empty) => Err("the background task did not answer in time".to_string()),
            Err(TryRecvError::Disconnected) => Err("the background task failed".to_string()),
        };
        if let Some(done) = done.take() {
            done(outcome);
        }
        glib::ControlFlow::Break
    });
}

/// Upcast any widget for the row builders.
pub fn wd<T: IsA<gtk::Widget>>(w: &T) -> gtk::Widget {
    w.clone().upcast()
}

/// A left-aligned label with an optional style class.
pub fn label(text: &str, class: Option<&str>) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.set_xalign(0.0);
    l.set_line_wrap(true);
    if let Some(class) = class {
        l.style_context().add_class(class);
    }
    l
}

/// A grey explanatory note.
pub fn note(text: &str) -> gtk::Label {
    label(text, Some("soc-config-sub"))
}

/// A vertical box with a border.
pub fn vbox(spacing: i32, border: u32) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Vertical, spacing);
    b.set_border_width(border);
    b
}

/// A horizontal box.
pub fn hbox(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Horizontal, spacing)
}

/// A text entry that fills its row.
pub fn entry(text: &str, hint: &str) -> gtk::Entry {
    let e = gtk::Entry::new();
    e.set_text(text);
    e.set_hexpand(true);
    e.set_placeholder_text(Some(hint));
    e
}

/// A masked entry.
pub fn secret_entry(hint: &str) -> gtk::Entry {
    let e = entry("", hint);
    e.set_visibility(false);
    e.set_input_purpose(gtk::InputPurpose::Password);
    e
}

/// A drop-down; `active` picks the entry (the first when it is unknown).
pub fn combo(options: &[&str], active: &str) -> gtk::ComboBoxText {
    let c = gtk::ComboBoxText::new();
    for o in options {
        c.append_text(o);
    }
    c.set_active(Some(options.iter().position(|o| *o == active).and_then(|i| u32::try_from(i).ok()).unwrap_or(0)));
    c
}

/// The drop-down's text, or `fallback`.
pub fn combo_text(c: &gtk::ComboBoxText, fallback: &str) -> String {
    c.active_text().map_or_else(|| fallback.to_string(), |t| t.to_string())
}

/// A spin button over an integer range.
pub fn spin(min: i64, max: i64, step: i64, value: i64) -> gtk::SpinButton {
    let s = gtk::SpinButton::with_range(to_f64(min), to_f64(max), to_f64(step));
    s.set_value(to_f64(value.clamp(min, max)));
    s
}

/// The spin button's integer value.
pub fn spin_int(s: &gtk::SpinButton) -> i64 {
    i64::from(s.value_as_int())
}

fn to_f64(n: i64) -> f64 {
    f64::from(i32::try_from(n).unwrap_or(if n < 0 { i32::MIN } else { i32::MAX }))
}

/// A check box.
pub fn check(text: &str, active: bool) -> gtk::CheckButton {
    let c = gtk::CheckButton::with_label(text);
    c.set_active(active);
    c
}

/// A button with an optional style class.
pub fn button(text: &str, class: Option<&str>) -> gtk::Button {
    let b = gtk::Button::with_label(text);
    if let Some(class) = class {
        b.style_context().add_class(class);
    }
    b
}

/// `label | widget` rows in a two-column grid.
pub fn form_grid(rows: &[(&str, gtk::Widget)]) -> gtk::Grid {
    let g = gtk::Grid::new();
    g.set_column_spacing(8);
    g.set_row_spacing(6);
    for (r, (name, w)) in rows.iter().enumerate() {
        let r = i32::try_from(r).unwrap_or(i32::MAX);
        g.attach(&label(name, Some("soc-config-sub")), 0, r, 1, 1);
        g.attach(w, 1, r, 1, 1);
    }
    g
}

/// A titled frame around `child`.
pub fn frame(title: &str, child: &impl IsA<gtk::Widget>) -> gtk::Frame {
    let f = gtk::Frame::new(Some(&format!("  {title}  ")));
    f.add(child);
    f
}

/// A vertically scrolling page.
pub fn scrolled(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    let s = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
    s.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
    s.add(child);
    s
}

/// An entry's text as a wiped-on-drop string.
pub fn secret_text(e: &gtk::Entry) -> Zeroizing<String> {
    Zeroizing::new(e.text().to_string())
}

/// Show `text` on `l` as OK (`error == false`) or error styling.
pub fn set_status(l: &gtk::Label, text: &str, error: bool) {
    let ctx = l.style_context();
    ctx.remove_class("soc-config-ok");
    ctx.remove_class("soc-config-error");
    ctx.add_class(if error { "soc-config-error" } else { "soc-config-ok" });
    l.set_text(text);
}

/// A modal "working..." dialog with a Cancel button. It never spins a nested
/// loop: the caller shows it, finishes it from the worker's callback, and
/// checks [`Busy::cancelled`] before using the result.
pub struct Busy {
    dialog: gtk::Dialog,
    cancelled: Rc<Cell<bool>>,
    closing: Rc<Cell<bool>>,
}

impl Busy {
    pub fn show(parent: &gtk::Window, text: &str) -> Busy {
        let dialog = gtk::Dialog::with_buttons(
            Some(text),
            Some(parent),
            gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
            &[("Cancel", gtk::ResponseType::Cancel)],
        );
        dialog.set_default_size(360, 0);
        let row = hbox(10);
        row.set_border_width(14);
        let spinner = gtk::Spinner::new();
        spinner.start();
        row.pack_start(&spinner, false, false, 0);
        row.pack_start(&label(text, None), true, true, 0);
        dialog.content_area().pack_start(&row, false, false, 0);
        let cancelled = Rc::new(Cell::new(false));
        let closing = Rc::new(Cell::new(false));
        let (flag, guard) = (cancelled.clone(), closing.clone());
        dialog.connect_response(move |d, _| {
            // close() re-emits the response; only the first one is the operator's.
            if guard.replace(true) {
                return;
            }
            flag.set(true);
            d.close();
        });
        dialog.show_all();
        Busy { dialog, cancelled, closing }
    }

    /// True once the operator pressed Cancel (or closed the dialog).
    pub fn cancelled(&self) -> bool {
        self.cancelled.get()
    }

    pub fn finish(&self) {
        if !self.closing.replace(true) {
            self.dialog.close();
        }
    }
}
