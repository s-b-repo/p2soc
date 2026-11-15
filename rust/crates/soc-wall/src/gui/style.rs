//! Shared look & feel for the wall.
//!
//! [`Tokens`] is the semantic colour palette (derived from the branding
//! colours, so a theme change repaints the wall itself); [`apply_css`] installs
//! the stylesheet once; [`PanelFrame`] wraps a panel's web view in a
//! `GtkStack` with a status page, so a dark cell always says *why* it is dark
//! and what happens next — the stock white WebKit error page is never shown.
//!
//! A stack is used instead of an overlay on purpose: a WebKitWebView renders
//! through its own native surface and paints over overlay siblings, so cards
//! floating above a live view are not reliable across backends.

use gtk::prelude::*;
pub use soc_web::style::{FALLBACK_BG, Palette, Tokens};
use std::cell::RefCell;
use std::collections::HashMap;

/// Build the palette tokens from branding colours (missing or malformed
/// values keep the built-in theme).
pub fn tokens_from_colors(colors: &HashMap<String, String>) -> Tokens {
    let dict: soc_core::Dict = colors.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
    Tokens::from_palette(&Palette::from_colors(&dict))
}

/// The wall stylesheet: the shared theme plus the fail-safe screen classes.
pub fn css(t: &Tokens) -> String {
    format!(
        "{}\n.soc-fatal-title {{ color: {}; font-size: 24px; font-weight: bold; }}\n\
         .soc-fatal-detail {{ color: {}; font-size: 14px; }}\n\
         .soc-fatal-hint {{ color: {}; font-size: 13px; }}\n",
        soc_web::style::css(t),
        t.fg,
        t.fg_soft,
        t.fg_dim
    )
}

thread_local! {
    static PROVIDER: RefCell<Option<gtk::CssProvider>> = const { RefCell::new(None) };
    static BACKGROUND: RefCell<String> = RefCell::new(FALLBACK_BG.to_string());
}

/// The wall background colour currently applied (web views are painted with
/// it so navigations never flash white).
pub fn background() -> String {
    BACKGROUND.with(|b| b.borrow().clone())
}

/// Install (or, after a theme change, replace) the wall stylesheet for the
/// whole screen. One provider lives for the whole process, so repeated calls
/// cannot stack duplicates. Main thread only.
pub fn apply_css(tokens: &Tokens) {
    let Some(screen) = gdk::Screen::default() else {
        return;
    };
    PROVIDER.with(|slot| {
        let mut slot = slot.borrow_mut();
        let provider = slot.get_or_insert_with(|| {
            let p = gtk::CssProvider::new();
            gtk::StyleContext::add_provider_for_screen(&screen, &p, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
            p
        });
        if let Err(e) = provider.load_from_data(css(tokens).as_bytes()) {
            eprintln!("{} stylesheet rejected: {e}", soc_core::LOG_TAG);
        }
    });
    BACKGROUND.with(|b| *b.borrow_mut() = tokens.bg.clone());
}

/// The content page (a web view) plus a status card, switched without a
/// transition: a crossfade snapshots the outgoing child, which a WebKitWebView
/// does not always survive cleanly.
#[derive(Clone)]
pub struct PanelFrame {
    stack: gtk::Stack,
    card: gtk::Box,
    spinner: gtk::Spinner,
    message: gtk::Label,
}

impl PanelFrame {
    pub fn new(panel_name: &str, content: &impl IsA<gtk::Widget>) -> PanelFrame {
        let card = gtk::Box::new(gtk::Orientation::Vertical, 10);
        card.set_halign(gtk::Align::Center);
        card.set_valign(gtk::Align::Center);
        card.style_context().add_class("soc-status");
        let id = gtk::Label::new(Some(&panel_name.to_uppercase()));
        id.style_context().add_class("soc-status-id");
        let spinner = gtk::Spinner::new();
        let message = gtk::Label::new(None);
        message.style_context().add_class("soc-status-msg");
        message.set_line_wrap(true);
        message.set_max_width_chars(46);
        message.set_justify(gtk::Justification::Center);
        card.pack_start(&id, false, false, 0);
        card.pack_start(&spinner, false, false, 0);
        card.pack_start(&message, false, false, 0);

        let stack = gtk::Stack::new();
        stack.set_transition_type(gtk::StackTransitionType::None);
        stack.add_named(content, "content");
        stack.add_named(&card, "status");
        PanelFrame { stack, card, spinner, message }
    }

    pub fn widget(&self) -> &gtk::Stack {
        &self.stack
    }

    fn set_state(&self, message: &str, error: bool, busy: bool) {
        let ctx = self.card.style_context();
        if error {
            ctx.add_class("error");
        } else {
            ctx.remove_class("error");
        }
        self.message.set_text(message);
        // No spinner on a card that only waits out a backoff: GTK redraws one
        // at 60 fps for as long as the outage lasts.
        if busy {
            self.spinner.start();
        } else {
            self.spinner.stop();
        }
        self.spinner.set_visible(busy);
    }

    /// Show the status page with this message.
    pub fn update(&self, message: &str, error: bool, busy: bool) {
        self.set_state(message, error, busy);
        self.stack.set_visible_child_name("status");
    }

    /// Back to the live panel.
    pub fn clear(&self) {
        self.set_state("", false, false);
        self.stack.set_visible_child_name("content");
    }

    /// Whether the status card (not the page) is showing.
    pub fn showing_status(&self) -> bool {
        self.stack.visible_child_name().is_some_and(|n| n == "status")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stylesheet_uses_the_theme() {
        let mut colors = HashMap::new();
        colors.insert("background".to_string(), "#112233".to_string());
        let t = tokens_from_colors(&colors);
        let sheet = css(&t);
        assert!(sheet.contains("background-color: #112233"));
        assert!(sheet.contains(".soc-vpn-pill.online"));
        assert!(sheet.contains(".soc-fatal-title"));
        assert_eq!(sheet.matches('{').count(), sheet.matches('}').count());
    }

    #[test]
    fn a_malformed_colour_keeps_the_default() {
        let mut colors = HashMap::new();
        colors.insert("background".to_string(), "red; } * { color: blue".to_string());
        assert_eq!(tokens_from_colors(&colors).bg, FALLBACK_BG);
    }
}
