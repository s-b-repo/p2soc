//! The fail-safe error dialog: `soc-wall guierror "<title>" "<detail>"`.
//!
//! A desktop (`.desktop`, `Terminal=false`) launch discards stderr, so when a
//! helper script fails the icon just looks dead. The launcher scripts run this
//! after a non-zero exit to pop a themed window that TELLS the operator the
//! cause. With no display it prints to stderr instead, so the diagnostic is
//! never wholly lost.

use crate::style;
use gtk::prelude::*;

/// Show the dialog. `args` is `[title, detail?]`. Returns the process exit
/// code (always 0 — this is itself the error reporter).
pub fn run(args: &[String]) -> i32 {
    let title = args.first().map(String::as_str).unwrap_or("SOC Wall error");
    let detail = args.get(1).map(String::as_str).unwrap_or("");
    if !style::init() {
        eprintln!("[soc-wall] {title}\n{detail}");
        return 0;
    }
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title(title);
    window.set_default_size(560, 260);
    window.set_position(gtk::WindowPosition::Center);
    window.style_context().add_class("soc-config");

    let column = gtk::Box::new(gtk::Orientation::Vertical, 14);
    column.set_halign(gtk::Align::Center);
    column.set_valign(gtk::Align::Center);
    column.set_margin_top(28);
    column.set_margin_bottom(28);
    column.set_margin_start(40);
    column.set_margin_end(40);

    let heading = gtk::Label::new(Some(title));
    heading.style_context().add_class("soc-config-title");
    heading.set_line_wrap(true);
    heading.set_max_width_chars(60);
    heading.set_justify(gtk::Justification::Center);
    let body = gtk::Label::new(Some(detail.trim()));
    body.style_context().add_class("soc-config-sub");
    body.set_line_wrap(true);
    body.set_max_width_chars(68);
    body.set_justify(gtk::Justification::Center);
    body.set_selectable(true);
    let ok = gtk::Button::with_label("OK");
    ok.style_context().add_class("soc-config-primary");

    column.pack_start(&heading, false, false, 0);
    column.pack_start(&body, false, false, 0);
    column.pack_start(&ok, false, false, 0);
    window.add(&column);

    let quit = window.clone();
    ok.connect_clicked(move |_| quit.close());
    window.connect_destroy(|_| gtk::main_quit());
    window.show_all();
    gtk::main();
    0
}
