//! Live VPN log viewer: a small window that streams
//! `journalctl -u soc-vpn.service -f` line by line, with Reconnect / Clear
//! controls, a per-VPN filter, and a collapse-to-bar toggle.
//!
//! Every supervisor and driver line (`[soc-vpn] …`, openfortivpn's own output,
//! the WireGuard/OpenVPN backend stderr) lands here verbatim. One unit fans out
//! to one supervisor per enabled VPN and tags each line `[vpn:<name>]`, so with
//! several VPNs the "Show:" dropdown filters to one by that tag.
//!
//! The stream reads read-only; on a non-root host it goes through
//! `sudo -n journalctl`, which needs a NOPASSWD allowance. The reader runs on a
//! thread and hands lines to the GTK loop; on close the child is terminated.

use gtk::prelude::*;
use std::cell::{Cell, RefCell};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc::{Receiver, TryRecvError};

const VPN_UNIT: &str = "forti-vpn.service";
/// Ring-buffer cap: older lines are trimmed first, so a chatty VPN cannot pin
/// memory over 24/7 operation.
const MAX_LINES: usize = 5_000;

/// Can we run `sudo -n journalctl` for the unit without a password prompt?
/// Probed with the exact command shape the stream uses, so it exercises the
/// real sudoers allowance; `-n 0` returns 0 even before the unit has logged.
fn sudo_journalctl_ok() -> bool {
    Command::new("sudo")
        .args(["-n", "/usr/bin/journalctl", "-u", VPN_UNIT, "-n", "0", "--no-pager"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The `journalctl` command, routed through `sudo -n` when we are not root.
fn stream_command() -> Command {
    let as_root = soc_sys::fsutil::euid() == 0;
    let (program, prefix): (&str, &[&str]) =
        if as_root { ("journalctl", &[]) } else { ("sudo", &["-n", "journalctl"]) };
    let mut cmd = Command::new(program);
    cmd.args(prefix);
    cmd.args(["-u", VPN_UNIT, "-n", "200", "-f", "--no-pager", "-o", "cat"]);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

struct Stream {
    child: Child,
    rx: Receiver<String>,
    poll: Option<glib::SourceId>,
}

struct Inner {
    window: gtk::Window,
    buffer: gtk::TextBuffer,
    view: gtk::TextView,
    body: gtk::Box,
    collapse: gtk::Button,
    filter: RefCell<String>,
    collapsed: Cell<bool>,
    stream: RefCell<Option<Stream>>,
    on_reconnect: Rc<dyn Fn()>,
}

/// A single-instance VPN log window. Re-opening presents the existing one.
#[derive(Clone)]
pub struct VpnLogViewer {
    inner: Rc<Inner>,
}

impl VpnLogViewer {
    /// Build and show the viewer. `names` are the enabled VPN names (for the
    /// filter dropdown); `on_reconnect` kicks the host's VPN-restart path.
    pub fn open(names: &[String], on_reconnect: Rc<dyn Fn()>, on_close: Rc<dyn Fn()>) -> VpnLogViewer {
        let window = gtk::Window::new(gtk::WindowType::Toplevel);
        window.set_title("VPN log");
        window.set_default_size(720, 420);
        window.set_keep_above(true);
        window.style_context().add_class("soc-config");

        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        toolbar.style_context().add_class("soc-toolbar");

        let reconnect = gtk::Button::with_label("⟳ Reconnect");
        reconnect.style_context().add_class("soc-toolbar-action");
        reconnect.set_tooltip_text(Some("Restart the VPN supervisor"));
        let clear = gtk::Button::with_label("Clear");
        clear.style_context().add_class("soc-toolbar-action");
        let collapse = gtk::Button::with_label("▾ Collapse");
        collapse.style_context().add_class("soc-toolbar-action");
        toolbar.pack_start(&reconnect, false, false, 0);
        toolbar.pack_start(&clear, false, false, 0);

        // The "Show:" filter only makes sense with more than one VPN.
        let names: Vec<String> = names.iter().filter(|n| !n.trim().is_empty()).cloned().collect();
        let filter_combo = (names.len() > 1).then(|| {
            let label = gtk::Label::new(Some("Show:"));
            label.style_context().add_class("soc-config-sub");
            let combo = gtk::ComboBoxText::new();
            combo.append(Some(""), "all VPNs");
            for name in &names {
                combo.append(Some(name), name);
            }
            combo.set_active_id(Some(""));
            toolbar.pack_start(&label, false, false, 0);
            toolbar.pack_start(&combo, false, false, 0);
            combo
        });
        toolbar.pack_start(&gtk::Box::new(gtk::Orientation::Horizontal, 0), true, true, 0);
        toolbar.pack_end(&collapse, false, false, 0);
        root.pack_start(&toolbar, false, false, 0);

        let scroll = gtk::ScrolledWindow::new(gtk::Adjustment::NONE, gtk::Adjustment::NONE);
        scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
        let buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
        let view = gtk::TextView::with_buffer(&buffer);
        view.set_editable(false);
        view.set_cursor_visible(false);
        view.set_monospace(true);
        view.set_wrap_mode(gtk::WrapMode::WordChar);
        scroll.add(&view);
        let body = gtk::Box::new(gtk::Orientation::Vertical, 0);
        body.pack_start(&scroll, true, true, 0);
        root.pack_start(&body, true, true, 0);
        window.add(&root);

        let viewer = VpnLogViewer {
            inner: Rc::new(Inner {
                window,
                buffer,
                view,
                body,
                collapse,
                filter: RefCell::new(String::new()),
                collapsed: Cell::new(false),
                stream: RefCell::new(None),
                on_reconnect,
            }),
        };

        let weak = Rc::downgrade(&viewer.inner);
        reconnect.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                (inner.on_reconnect)();
            }
        });
        let weak = Rc::downgrade(&viewer.inner);
        clear.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                inner.buffer.set_text("");
            }
        });
        let weak = Rc::downgrade(&viewer.inner);
        viewer.inner.collapse.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                VpnLogViewer { inner }.toggle_collapse();
            }
        });
        if let Some(combo) = &filter_combo {
            let weak = Rc::downgrade(&viewer.inner);
            combo.connect_changed(move |combo| {
                if let Some(inner) = weak.upgrade() {
                    *inner.filter.borrow_mut() = combo.active_id().map_or_else(String::new, |s| s.to_string());
                }
            });
        }
        // Closing the window stops the stream and tells the host to forget us.
        let weak = Rc::downgrade(&viewer.inner);
        viewer.inner.window.connect_delete_event(move |_, _| {
            if let Some(inner) = weak.upgrade() {
                VpnLogViewer { inner }.stop_stream();
            }
            on_close();
            glib::Propagation::Proceed
        });

        viewer.start_stream();
        viewer.inner.window.show_all();
        viewer
    }

    /// Bring an already-open viewer back to the front.
    pub fn present(&self) {
        self.inner.window.present();
    }

    fn append_line(&self, line: &str) {
        let filter = self.inner.filter.borrow();
        // An empty filter shows everything; otherwise show this VPN's tagged
        // lines plus untagged manager/header lines (which carry no `[vpn:` tag).
        if !filter.is_empty() {
            let tag = format!("[vpn:{filter}]");
            if line.contains("[vpn:") && !line.contains(&tag) {
                return;
            }
        }
        let buffer = &self.inner.buffer;
        let mut end = buffer.end_iter();
        buffer.insert(&mut end, line);
        buffer.insert(&mut end, "\n");
        // Trim the ring buffer from the top.
        let overflow = buffer.line_count().saturating_sub(i32::try_from(MAX_LINES).unwrap_or(i32::MAX));
        if overflow > 0 {
            let mut start = buffer.start_iter();
            let mut cut = buffer.iter_at_line(overflow);
            buffer.delete(&mut start, &mut cut);
        }
        // Auto-scroll to the newest line.
        let mut last = buffer.end_iter();
        self.inner.view.scroll_to_iter(&mut last, 0.0, false, 0.0, 0.0);
    }

    fn start_stream(&self) {
        if !self.ensure_authorised() {
            return;
        }
        let mut command = stream_command();
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                self.append_line(&format!("[viewer] cannot start journalctl: {e}"));
                return;
            }
        };
        let Some(stdout) = child.stdout.take() else {
            self.append_line("[viewer] journalctl produced no output stream");
            let _ = child.kill(); // audit-allow: best-effort
            let _ = child.wait(); // audit-allow: best-effort
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break; // the viewer closed
                }
            }
        });
        let weak = Rc::downgrade(&self.inner);
        let poll = glib::timeout_add_local(std::time::Duration::from_millis(120), move || {
            let Some(inner) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let viewer = VpnLogViewer { inner };
            let ended = viewer.drain();
            if ended { glib::ControlFlow::Break } else { glib::ControlFlow::Continue }
        });
        *self.inner.stream.borrow_mut() = Some(Stream { child, rx, poll: Some(poll) });
    }

    fn ensure_authorised(&self) -> bool {
        if soc_sys::fsutil::euid() == 0 || sudo_journalctl_ok() {
            return true;
        }
        self.append_line(
            "[viewer] cannot read the VPN journal: `sudo -n journalctl` is not permitted for this user.\n\
             [viewer] grant a NOPASSWD journalctl allowance (see security/soc-wall-restart.sudoers) to stream it.",
        );
        false
    }

    /// Move whatever the reader thread produced into the view. Returns true
    /// once the stream has ended (child exited and the channel is closed).
    fn drain(&self) -> bool {
        let mut lines = Vec::new();
        let ended = {
            let mut guard = self.inner.stream.borrow_mut();
            let Some(stream) = guard.as_mut() else {
                return true;
            };
            loop {
                match stream.rx.try_recv() {
                    Ok(line) => lines.push(line),
                    Err(TryRecvError::Empty) => break false,
                    Err(TryRecvError::Disconnected) => break true,
                }
            }
        };
        for line in lines {
            self.append_line(&line);
        }
        ended
    }

    fn stop_stream(&self) {
        if let Some(mut stream) = self.inner.stream.borrow_mut().take() {
            if let Some(poll) = stream.poll.take() {
                poll.remove();
            }
            let _ = stream.child.kill(); // audit-allow: best-effort
            let _ = stream.child.wait(); // audit-allow: best-effort
        }
    }

    fn toggle_collapse(&self) {
        let collapsed = !self.inner.collapsed.get();
        self.inner.collapsed.set(collapsed);
        self.inner.body.set_visible(!collapsed);
        self.inner.collapse.set_label(if collapsed { "▸ Expand" } else { "▾ Collapse" });
        if collapsed {
            self.inner.window.resize(720, 1);
        } else {
            self.inner.window.resize(720, 420);
        }
    }

    /// Close the window and stop the stream.
    pub fn close(&self) {
        self.stop_stream();
        self.inner.window.close();
    }
}
