//! Shared GTK styling for the standalone tools, built on the wall's palette
//! (`soc_web::style`) and the operator's saved branding (`soc_brand`). One
//! provider per process, so repeated installs cannot stack duplicates.

use gtk::prelude::*;
use std::cell::RefCell;

thread_local! {
    static PROVIDER: RefCell<Option<gtk::CssProvider>> = const { RefCell::new(None) };
}

/// The tokens for the current saved theme.
pub fn tokens() -> soc_web::style::Tokens {
    let branding = soc_brand::Locations::from_env().load();
    let dict: soc_core::Dict =
        branding.colors.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
    soc_web::style::Tokens::from_palette(&soc_web::style::Palette::from_colors(&dict))
}

/// Install (or refresh) the stylesheet for the whole screen.
pub fn apply(tokens: &soc_web::style::Tokens) {
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
        let _ = provider.load_from_data(soc_web::style::css(tokens).as_bytes()); // audit-allow: best-effort; a bad stylesheet must not stop a tool
    });
}

/// Initialise GTK and install the theme; returns false when there is no
/// display (the caller then degrades to a non-GUI path).
pub fn init() -> bool {
    if gtk::init().is_err() {
        return false;
    }
    apply(&tokens());
    true
}
