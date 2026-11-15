//! The appearance (theme) editor: pick a built-in preset or tweak any of the 14
//! branding colours, see it live on a sample card and on the whole window, then
//! Save to persist it to `branding.yaml` (the startup theme).

use gtk::prelude::*;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

/// The 14 palette keys, in the built-in order. Preset palettes follow it.
const KEYS: [&str; 14] = [
    "primary",
    "setup",
    "desktop",
    "kiosk",
    "background",
    "surface_top",
    "surface_bottom",
    "border",
    "text",
    "text_dim",
    "accent_strong",
    "good",
    "warn",
    "bad",
];

/// (name, label, palette in `KEYS` order). The first is the default theme.
type Preset = (&'static str, &'static str, [&'static str; 14]);

const PRESETS: [Preset; 4] = [
    (
        "soc-green",
        "SOC Green / White  (default)",
        [
            "#1FA463", "#1FA463", "#1FA463", "#0E7C7B", "#FFFFFF", "#F4F8F5", "#EAF1EC", "#CFE0D4", "#0B1F14",
            "#51695C", "#157A49", "#157A49", "#9C7209", "#C0341D",
        ],
    ),
    (
        "midnight",
        "Midnight  (dark)",
        [
            "#3DF59B", "#3DF59B", "#3DF59B", "#34E7E0", "#05100B", "#0B1E16", "#081711", "#1F6E4A", "#D6FBE7",
            "#79C9A4", "#19C46F", "#3DF59B", "#FFC247", "#FF6B61",
        ],
    ),
    (
        "high-contrast",
        "High Contrast",
        [
            "#006B2D", "#006B2D", "#006B2D", "#005A58", "#FFFFFF", "#FFFFFF", "#F0F0F0", "#000000", "#000000",
            "#333333", "#006B2D", "#006B2D", "#8A5A00", "#B00000",
        ],
    ),
    (
        "amber-ops",
        "Amber Ops",
        [
            "#E8A317", "#E8A317", "#E8A317", "#C77A2A", "#0C0A06", "#1A150C", "#13100A", "#3A2F18", "#F5E6C8",
            "#B9A47A", "#C8860B", "#E8A317", "#E8A317", "#E0533A",
        ],
    ),
];

/// Grouped picker layout: (group title, [(key, label)]).
const GROUPS: [(&str, &[(&str, &str)]); 4] = [
    (
        "brand",
        &[
            ("primary", "Primary"),
            ("accent_strong", "Accent (strong)"),
            ("setup", "Setup card"),
            ("desktop", "Desktop card"),
            ("kiosk", "Kiosk card"),
        ],
    ),
    (
        "surfaces",
        &[
            ("background", "Background"),
            ("surface_top", "Surface (top)"),
            ("surface_bottom", "Surface (sunken)"),
            ("border", "Border"),
        ],
    ),
    ("text", &[("text", "Text"), ("text_dim", "Text (dim)")]),
    ("status", &[("good", "Good"), ("warn", "Warn"), ("bad", "Bad")]),
];

type Colors = HashMap<String, String>;

/// A preset's palette as an owned map.
fn preset_colors(preset: &Preset) -> Colors {
    KEYS.iter().zip(preset.2.iter()).map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

/// The colour for `key`, falling back to the default theme when missing or invalid.
fn col(colors: &Colors, key: &str) -> String {
    let fallback = soc_brand::DEFAULT_COLORS.iter().find(|(k, _)| *k == key).map_or("#808080", |(_, v)| *v);
    colors.get(key).filter(|v| soc_brand::is_hex_color(v)).map_or_else(|| fallback.to_string(), Clone::clone)
}

/// Stylesheet tokens for an edited palette.
fn tokens_for(colors: &Colors) -> soc_web::style::Tokens {
    let dict: soc_core::Dict = colors.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
    soc_web::style::Tokens::from_palette(&soc_web::style::Palette::from_colors(&dict))
}

/// Normalise to `#RRGGBB` (upper case); `None` for anything that is not hex.
fn canonical_hex(value: &str) -> Option<String> {
    let hex = soc_web::style::normalise_hex(value)?;
    let digits = hex.trim_start_matches('#');
    let full: String =
        if digits.len() == 3 { digits.chars().flat_map(|c| [c, c]).collect() } else { digits.to_string() };
    Some(format!("#{}", full.to_ascii_uppercase()))
}

/// `rgb(r,g,b)` / `rgba(r,g,b,a)` (as GDK prints it) -> `#RRGGBB`.
fn hex_from_rgb_string(s: &str) -> Option<String> {
    let inner = s.split_once('(')?.1.split_once(')')?.0;
    let mut parts = inner.split(',').map(|p| p.trim().parse::<u8>().ok());
    let (r, g, b) = (parts.next()??, parts.next()??, parts.next()??);
    Some(format!("#{r:02X}{g:02X}{b:02X}"))
}

/// Readability findings for a palette: (label, ratio, minimum) of the pairs below WCAG AA.
fn contrast_issues(colors: &Colors) -> Vec<(&'static str, f64, f64)> {
    let c = |k: &str| col(colors, k);
    let (bg, top, bot) = (c("background"), c("surface_top"), c("surface_bottom"));
    let pairs: [(&'static str, String, &String, f64); 11] = [
        ("text on background", c("text"), &bg, 4.5),
        ("text on surface", c("text"), &top, 4.5),
        ("text on sunken surface", c("text"), &bot, 4.5),
        ("dim text on background", c("text_dim"), &bg, 4.5),
        ("dim text on surface", c("text_dim"), &top, 4.5),
        ("accent on surface", c("accent_strong"), &top, 3.0),
        ("good on surface", c("good"), &top, 3.0),
        ("warn on surface", c("warn"), &top, 3.0),
        ("bad on surface", c("bad"), &top, 3.0),
        ("bad on background", c("bad"), &bg, 3.0),
        ("primary on surface", c("primary"), &top, 3.0),
    ];
    pairs
        .into_iter()
        .filter_map(|(label, fg, back, min)| {
            let ratio = soc_web::style::contrast_ratio(&fg, back);
            (ratio + 1e-6 < min).then_some((label, ratio, min))
        })
        .collect()
}

/// RGBA -> `#RRGGBB`, validated.
fn rgba_to_hex(rgba: &gdk::RGBA) -> Option<String> {
    hex_from_rgb_string(rgba.to_str().as_str()).and_then(|h| canonical_hex(&h))
}

/// The sample card + chrome stylesheet, from the edited palette (every value validated).
fn sample_css(colors: &Colors) -> String {
    let c = |k: &str| col(colors, k);
    let (bg, top, bot, border) = (c("background"), c("surface_top"), c("surface_bottom"), c("border"));
    let (text, dim, accent, strong) = (c("text"), c("text_dim"), c("primary"), c("accent_strong"));
    let (good, warn, bad) = (c("good"), c("warn"), c("bad"));
    format!(
        "window.soc-appearance, .soc-appearance {{ background-color: {bg}; color: {text}; }}\n\
         .soc-ap-header {{ background-color: {top}; border-top: 2px solid {strong}; border-bottom: 1px solid {border}; padding: 14px 18px 12px 18px; }}\n\
         .soc-ap-body {{ background-color: {bg}; padding: 14px 18px 16px 18px; }}\n\
         .soc-ap-eyebrow {{ color: {accent}; font-family: monospace; font-weight: bold; }}\n\
         .soc-ap-title {{ color: {text}; font-weight: bold; }}\n\
         .soc-ap-sub, .soc-ap-status {{ color: {dim}; }}\n\
         .soc-ap-dim {{ color: {dim}; font-family: monospace; }}\n\
         .soc-ap-label {{ color: {text}; }}\n\
         .soc-ap-sample {{ background-color: {top}; border: 1px solid {border}; border-left: 4px solid {accent}; border-radius: 6px; padding: 13px 16px; }}\n\
         .soc-ap-sample-sunken {{ background-color: {bot}; border: 1px solid {border}; border-radius: 5px; padding: 9px 12px; }}\n\
         .soc-ap-grid {{ background-color: {top}; border: 1px solid {border}; border-radius: 6px; padding: 12px 14px; }}\n\
         .soc-ap-good {{ color: {good}; }}\n\
         .soc-ap-warn {{ color: {warn}; }}\n\
         .soc-ap-bad, .soc-ap-status-bad {{ color: {bad}; }}\n\
         button.soc-primary {{ background-image: none; background-color: {strong}; color: {bg}; border: 1px solid {strong}; border-radius: 6px; font-weight: bold; padding: 6px 14px; }}\n\
         button.soc-ghost {{ background-image: none; background-color: transparent; color: {strong}; border: 1px solid {border}; border-radius: 6px; padding: 6px 12px; }}\n"
    )
}

/// Editor state shared by the signal handlers (GTK main thread only).
struct Editor {
    colors: RefCell<Colors>,
    pickers: RefCell<Vec<(&'static str, gtk::ColorButton)>>,
    suppress: Cell<bool>,
    sample: gtk::CssProvider,
    status: gtk::Label,
    warning: gtk::Label,
    combo: gtk::ComboBoxText,
}

impl Editor {
    /// Repaint the sample/surface and the whole-screen stylesheet, refresh the warning.
    fn refresh(&self) {
        let colors = self.colors.borrow();
        let _ = self.sample.load_from_data(sample_css(&colors).as_bytes()); // audit-allow: best-effort repaint
        crate::style::apply(&tokens_for(&colors));
        let issues = contrast_issues(&colors);
        if issues.is_empty() {
            self.warning.set_text("");
        } else {
            let list: Vec<String> =
                issues.iter().take(4).map(|(l, r, m)| format!("{l} {r:.1}:1 (needs {m:.1})")).collect();
            let more = issues.len().saturating_sub(4);
            let tail = if more > 0 { format!(" (+{more} more)") } else { String::new() };
            self.warning.set_text(&format!("Low contrast: {}{tail}", list.join("; ")));
        }
    }

    fn set_status(&self, text: &str, bad: bool) {
        self.status.set_text(&format!("{} {text}", if bad { "x" } else { "*" }));
        let ctx = self.status.style_context();
        if bad {
            ctx.add_class("soc-ap-status-bad");
        } else {
            ctx.remove_class("soc-ap-status-bad");
        }
    }

    /// Replace the whole working palette (and every picker) without per-picker repaints.
    fn apply_palette(&self, palette: &Colors) {
        self.suppress.set(true);
        {
            let mut colors = self.colors.borrow_mut();
            for (key, picker) in self.pickers.borrow().iter() {
                let value = col(palette, key);
                gdk::RGBA::parse(value.as_str()).iter().for_each(|rgba| picker.set_rgba(rgba));
                colors.insert((*key).to_string(), value);
            }
        }
        self.suppress.set(false);
        self.refresh();
    }

    fn on_picker(&self, key: &str, button: &gtk::ColorButton) {
        if self.suppress.get() {
            return;
        }
        match rgba_to_hex(&button.rgba()) {
            Some(hex) => {
                self.colors.borrow_mut().insert(key.to_string(), hex);
                self.refresh();
            }
            None => self.set_status(&format!("ignored an invalid colour for {key}"), true),
        }
    }

    fn on_preset(&self) {
        if self.suppress.get() {
            return;
        }
        let Some(idx) = self.combo.active().and_then(|i| usize::try_from(i).ok()) else {
            return;
        };
        if let Some(preset) = PRESETS.get(idx) {
            self.apply_palette(&preset_colors(preset));
            self.set_status(&format!("loaded preset: {}", preset.1), false);
        }
    }

    fn on_reset(&self) {
        if let Some(default) = PRESETS.first() {
            self.apply_palette(&preset_colors(default));
        }
        self.suppress.set(true);
        self.combo.set_active(Some(0));
        self.suppress.set(false);
        self.set_status("reset to SOC Green (default) - not yet saved", false);
    }

    fn on_save(&self) {
        let locations = soc_brand::Locations::from_env();
        let Some(target) = locations.save_target() else {
            self.set_status("could not save theme: no writable branding location", true);
            return;
        };
        let mut branding = locations.load();
        for (key, _) in soc_brand::DEFAULT_COLORS {
            branding.colors.insert((*key).to_string(), col(&self.colors.borrow(), key));
        }
        match soc_brand::save_colors(&target, &branding, &locations) {
            Ok(()) => self.set_status(&format!("saved theme -> {}", target.display()), false),
            Err(e) => self.set_status(&format!("could not save theme: {e}"), true),
        }
    }
}

fn class_label(text: &str, class: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_xalign(0.0);
    label.style_context().add_class(class);
    label
}

fn build_sample() -> gtk::Box {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 10);
    card.style_context().add_class("soc-ap-sample");
    card.pack_start(&class_label("// sample", "soc-ap-eyebrow"), false, false, 0);
    let tile = gtk::Box::new(gtk::Orientation::Vertical, 2);
    tile.style_context().add_class("soc-ap-sample-sunken");
    tile.pack_start(&class_label("Action tile", "soc-ap-title"), false, false, 0);
    tile.pack_start(&class_label("Theme preview surface", "soc-ap-sub"), false, false, 0);
    card.pack_start(&tile, false, false, 0);
    let dots = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    for (class, name) in [("soc-ap-good", "online"), ("soc-ap-warn", "warn"), ("soc-ap-bad", "fault")] {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 5);
        row.pack_start(&class_label("\u{25CF}", class), false, false, 0);
        row.pack_start(&class_label(name, "soc-ap-sub"), false, false, 0);
        dots.pack_start(&row, false, false, 0);
    }
    card.pack_start(&dots, false, false, 0);
    card
}

/// Which preset (if any) exactly matches the loaded colours, for the initial combo state.
fn matching_preset(colors: &Colors) -> Option<u32> {
    PRESETS.iter().position(|p| preset_colors(p) == *colors).and_then(|i| u32::try_from(i).ok())
}

/// Run the editor (`soc-wall appearance`). Returns the exit code.
pub fn run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--list-presets") {
        for preset in &PRESETS {
            println!("{}\t{}", preset.0, preset.1);
        }
        return 0;
    }
    if !crate::style::init() {
        eprintln!("[soc-wall] appearance: no graphical display (run this from your desktop session)");
        return 1;
    }
    let branding = soc_brand::Locations::from_env().load();
    let initial: Colors =
        soc_brand::DEFAULT_COLORS.iter().map(|(k, _)| ((*k).to_string(), col(&branding.colors, k))).collect();

    let sample = gtk::CssProvider::new();
    let combo = gtk::ComboBoxText::new();
    for preset in &PRESETS {
        combo.append_text(preset.1);
    }
    let editor = Rc::new(Editor {
        colors: RefCell::new(initial.clone()),
        pickers: RefCell::new(Vec::new()),
        suppress: Cell::new(false),
        sample: sample.clone(),
        status: gtk::Label::new(None),
        warning: gtk::Label::new(None),
        combo: combo.clone(),
    });
    if let Some(screen) = gdk::Screen::default() {
        gtk::StyleContext::add_provider_for_screen(&screen, &sample, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
    }
    editor.status.set_xalign(0.0);
    editor.status.set_line_wrap(true);
    editor.status.style_context().add_class("soc-ap-status");
    editor.warning.set_xalign(0.0);
    editor.warning.set_line_wrap(true);
    editor.warning.style_context().add_class("soc-ap-warn");

    let win = gtk::Window::new(gtk::WindowType::Toplevel);
    let name = branding.get("short_name");
    win.set_title(&format!("{} - Appearance", if name.is_empty() { "SOC Wall" } else { name }));
    win.style_context().add_class("soc-appearance");
    win.set_position(gtk::WindowPosition::Center);

    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    win.add(&root);
    let header = gtk::Box::new(gtk::Orientation::Vertical, 1);
    header.style_context().add_class("soc-ap-header");
    header.pack_start(&class_label("// appearance", "soc-ap-dim"), false, false, 0);
    header.pack_start(&class_label("THEME", "soc-ap-eyebrow"), false, false, 0);
    header.pack_start(&class_label("Colours & presets - live, then Save", "soc-ap-sub"), false, false, 0);
    root.pack_start(&header, false, false, 0);

    let body = gtk::Box::new(gtk::Orientation::Vertical, 12);
    body.style_context().add_class("soc-ap-body");
    root.pack_start(&body, true, true, 0);

    let prow = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    prow.pack_start(&class_label("Theme preset", "soc-ap-label"), false, false, 0);
    prow.pack_start(&combo, true, true, 0);
    body.pack_start(&prow, false, false, 0);

    let cols = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    body.pack_start(&cols, true, true, 0);
    let grid_frame = gtk::Box::new(gtk::Orientation::Vertical, 8);
    grid_frame.style_context().add_class("soc-ap-grid");
    cols.pack_start(&grid_frame, false, false, 0);
    grid_frame.pack_start(&class_label("// palette", "soc-ap-dim"), false, false, 0);
    let grid = gtk::Grid::new();
    grid.set_column_spacing(10);
    grid.set_row_spacing(5);
    grid_frame.pack_start(&grid, false, false, 0);

    let mut row = 0;
    for (title, keys) in &GROUPS {
        grid.attach(&class_label(title, "soc-ap-dim"), 0, row, 2, 1);
        row += 1;
        for (key, label) in *keys {
            let name_label = class_label(label, "soc-ap-label");
            name_label.set_size_request(140, -1);
            let button = gtk::ColorButton::new();
            gdk::RGBA::parse(col(&initial, key).as_str()).iter().for_each(|rgba| button.set_rgba(rgba));
            button.set_title(label);
            let weak = Rc::downgrade(&editor);
            let key_owned: &'static str = key;
            button.connect_color_set(move |b| {
                if let Some(ed) = weak.upgrade() {
                    ed.on_picker(key_owned, b);
                }
            });
            editor.pickers.borrow_mut().push((key, button.clone()));
            grid.attach(&name_label, 0, row, 1, 1);
            grid.attach(&button, 1, row, 1, 1);
            row += 1;
        }
    }

    let sample_col = gtk::Box::new(gtk::Orientation::Vertical, 8);
    sample_col.set_hexpand(true);
    cols.pack_start(&sample_col, true, true, 0);
    sample_col.pack_start(&class_label("// live preview", "soc-ap-dim"), false, false, 0);
    sample_col.pack_start(&build_sample(), false, false, 0);
    sample_col.pack_start(&editor.warning, false, false, 0);

    body.pack_start(&editor.status, false, false, 0);
    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    buttons.set_halign(gtk::Align::End);
    let reset = gtk::Button::with_label("Reset to default");
    reset.style_context().add_class("soc-ghost");
    let save = gtk::Button::with_label("Save");
    save.style_context().add_class("soc-primary");
    buttons.pack_start(&reset, false, false, 0);
    buttons.pack_start(&save, false, false, 0);
    body.pack_start(&buttons, false, false, 0);

    let weak = Rc::downgrade(&editor);
    combo.connect_changed(move |_| {
        if let Some(ed) = weak.upgrade() {
            ed.on_preset();
        }
    });
    let weak = Rc::downgrade(&editor);
    reset.connect_clicked(move |_| {
        if let Some(ed) = weak.upgrade() {
            ed.on_reset();
        }
    });
    let weak = Rc::downgrade(&editor);
    save.connect_clicked(move |_| {
        if let Some(ed) = weak.upgrade() {
            ed.on_save();
        }
    });
    win.connect_destroy(|_| gtk::main_quit());

    editor.suppress.set(true);
    combo.set_active(matching_preset(&initial).or(Some(0)));
    editor.suppress.set(false);
    editor.refresh();
    editor.set_status("pick a preset or a colour - Save persists it as the theme", false);
    win.show_all();
    gtk::main();
    drop(editor);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_complete_valid_hex() {
        for preset in &PRESETS {
            for value in preset.2 {
                assert!(soc_brand::is_hex_color(value), "{} {value}", preset.0);
            }
            assert_eq!(preset_colors(preset).len(), KEYS.len());
        }
        let default: Colors = soc_brand::DEFAULT_COLORS.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect();
        assert_eq!(preset_colors(&PRESETS[0]), default);
    }

    #[test]
    fn tokens_and_css_build_from_every_preset() {
        for preset in &PRESETS {
            let colors = preset_colors(preset);
            let _ = tokens_for(&colors);
            assert!(sample_css(&colors).contains("soc-ap-sample"));
        }
    }

    #[test]
    fn bad_colours_fall_back_and_hex_is_canonical() {
        let mut colors = preset_colors(&PRESETS[0]);
        colors.insert("text".into(), "red; } body {".into());
        assert_eq!(col(&colors, "text"), "#0B1F14");
        assert_eq!(canonical_hex("#abc").as_deref(), Some("#AABBCC"));
        assert_eq!(canonical_hex("zzz"), None);
        assert_eq!(hex_from_rgb_string("rgb(31,164,99)").as_deref(), Some("#1FA463"));
        assert_eq!(hex_from_rgb_string("rgb(300,1,1)"), None);
    }

    #[test]
    fn contrast_warning_flags_unreadable_text() {
        let mut colors = preset_colors(&PRESETS[0]);
        assert!(contrast_issues(&colors).is_empty() || contrast_issues(&colors).len() < 3);
        colors.insert("text".into(), "#FFFFFF".into());
        assert!(!contrast_issues(&colors).is_empty());
    }
}
