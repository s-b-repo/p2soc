//! Shared look and feel for the wall, derived from the branding palette so the
//! setup wizard's theme controls the wall itself.
//!
//! * [`Palette`] — the branding colours this module consumes, validated.
//! * [`Tokens`] — the semantic colour tokens every rule is written against.
//! * [`css`] — the GTK application stylesheet (same text the Python wall
//!   builds for the same palette).
//! * [`StatusCard`] — the per-panel "connecting… / offline / recovering" card,
//!   as data plus a self-contained HTML rendering, so a dark cell on the wall
//!   always says why and what happens next.
//!
//! Everything interpolated into CSS is a validated colour; everything
//! interpolated into HTML is escaped.

use soc_core::Dict;

/// Hard fallback background, used when the palette has none.
pub const FALLBACK_BG: &str = "#0b1020";

/// `#RGB` / `#RRGGBB` (the `#` optional) as a `#`-prefixed colour, or `None`.
/// Palette values are spliced into a stylesheet, so nothing but a plain hex
/// colour is ever let through.
pub fn normalise_hex(value: &str) -> Option<String> {
    let digits = value.trim();
    let digits = digits.strip_prefix('#').unwrap_or(digits);
    let ok = matches!(digits.len(), 3 | 6) && digits.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| format!("#{digits}"))
}

fn rgb(hex: &str) -> (u8, u8, u8) {
    let digits = hex.trim_start_matches('#');
    let wide: String = if digits.len() == 3 { digits.chars().flat_map(|c| [c, c]).collect() } else { digits.into() };
    let channel = |i: usize| wide.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok());
    match (channel(0), channel(2), channel(4)) {
        (Some(r), Some(g), Some(b)) => (r, g, b),
        // Unreachable for a validated colour; a mid-grey beats a panic.
        _ => (128, 128, 128),
    }
}

/// `#RRGGBB` -> `rgba(r,g,b,alpha)`.
fn rgba(hex: &str, alpha: f64) -> String {
    let (r, g, b) = rgb(hex);
    format!("rgba({r},{g},{b},{alpha:.2})")
}

/// WCAG 2.x relative luminance (0.0 = black, 1.0 = white).
fn relative_luminance(hex: &str) -> f64 {
    let chan = |c: u8| {
        let s = f64::from(c) / 255.0;
        if s <= 0.04045 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
    };
    let (r, g, b) = rgb(hex);
    0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)
}

/// WCAG 2.x contrast ratio between two colours (1.0 ..= 21.0).
pub fn contrast_ratio(fg: &str, bg: &str) -> f64 {
    let (l1, l2) = (relative_luminance(fg), relative_luminance(bg));
    (l1.max(l2) + 0.05) / (l1.min(l2) + 0.05)
}

/// The branding colours the wall is themed from. Each field is a validated
/// `#hex` colour; a missing or malformed branding value keeps the built-in
/// dark default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    pub background: String,
    pub surface_top: String,
    pub surface_bottom: String,
    pub border: String,
    pub text: String,
    pub text_dim: String,
    pub primary: String,
    pub accent_strong: String,
    pub good: String,
    pub warn: String,
    pub bad: String,
    /// Whether `text` came from branding (it is then a candidate label colour
    /// on accent fills; the built-in default is not).
    text_from_branding: bool,
}

impl Default for Palette {
    fn default() -> Self {
        Palette {
            background: FALLBACK_BG.into(),
            surface_top: "#131a31".into(),
            surface_bottom: "#1b2b4a".into(),
            border: "#1b2b4a".into(),
            text: "#e7ecff".into(),
            text_dim: "#8694c4".into(),
            primary: "#7e96ff".into(),
            accent_strong: "#2f4fd0".into(),
            good: "#57d9a3".into(),
            warn: "#ffb450".into(),
            bad: "#ff8f80".into(),
            text_from_branding: false,
        }
    }
}

impl Palette {
    /// Read the branding `colors:` mapping (`background`, `surface_top`,
    /// `surface_bottom`, `border`, `text`, `text_dim`, `primary`,
    /// `accent_strong`, `good`, `warn`, `bad`).
    pub fn from_colors(colors: &Dict) -> Palette {
        let mut p = Palette::default();
        let pick = |key: &str| colors.get(key).and_then(|v| v.as_str()).and_then(normalise_hex);
        for (key, slot) in [
            ("background", &mut p.background),
            ("surface_top", &mut p.surface_top),
            ("surface_bottom", &mut p.surface_bottom),
            ("border", &mut p.border),
            ("text_dim", &mut p.text_dim),
            ("primary", &mut p.primary),
            ("accent_strong", &mut p.accent_strong),
            ("good", &mut p.good),
            ("warn", &mut p.warn),
            ("bad", &mut p.bad),
        ] {
            if let Some(colour) = pick(key) {
                *slot = colour;
            }
        }
        if let Some(colour) = pick("text") {
            p.text = colour;
            p.text_from_branding = true;
        }
        p
    }

    /// The highest-contrast label colour for an accent fill `bg`: the palette
    /// text, white, or near-black — so a button label never goes invisible on
    /// an alternate theme.
    fn text_on(&self, bg: &str) -> String {
        let palette_text = if self.text_from_branding { self.text.as_str() } else { "#0B1F14" };
        let mut best = palette_text;
        for candidate in ["#ffffff", "#101010"] {
            if contrast_ratio(candidate, bg) > contrast_ratio(best, bg) {
                best = candidate;
            }
        }
        best.to_string()
    }
}

/// Semantic colour tokens — the single source of truth for the wall palette.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    /// Primary background (wall + config).
    pub bg: String,
    pub bg_toolbar: String,
    /// Raised cells, inactive buttons.
    pub bg_elev: String,
    /// Entries, wells.
    pub bg_elev_2: String,
    /// Panel status card.
    pub bg_card: String,
    pub border_soft: String,
    pub border: String,
    pub border_accent: String,
    pub border_strong: String,
    /// Primary text.
    pub fg: String,
    pub fg_soft: String,
    pub fg_muted: String,
    /// Captions / sub-labels.
    pub fg_dim: String,
    /// Primary action fill.
    pub accent: String,
    /// Accent foreground (links, tags).
    pub accent_text: String,
    pub accent_hover: String,
    /// Label on an accent fill.
    pub on_accent: String,
    /// Online / success.
    pub ok: String,
    /// Connecting / caution.
    pub warn: String,
    pub warn_bg: String,
    /// Offline / destructive.
    pub err: String,
    pub err_soft: String,
    pub err_bg: String,
}

impl Default for Tokens {
    fn default() -> Self {
        Tokens::from_palette(&Palette::default())
    }
}

impl Tokens {
    pub fn from_palette(p: &Palette) -> Tokens {
        Tokens {
            bg: p.background.clone(),
            bg_toolbar: rgba(&p.background, 0.92),
            bg_elev: p.surface_top.clone(),
            bg_elev_2: p.surface_bottom.clone(),
            bg_card: rgba(&p.surface_top, 0.92),
            border_soft: rgba(&p.primary, 0.18),
            border: p.border.clone(),
            border_accent: rgba(&p.primary, 0.30),
            border_strong: rgba(&p.primary, 0.35),
            fg: p.text.clone(),
            fg_soft: rgba(&p.text, 0.88),
            fg_muted: rgba(&p.text_dim, 0.95),
            fg_dim: p.text_dim.clone(),
            accent: p.accent_strong.clone(),
            accent_text: p.primary.clone(),
            accent_hover: rgba(&p.primary, 0.85),
            on_accent: p.text_on(&p.accent_strong),
            ok: p.good.clone(),
            warn: p.warn.clone(),
            warn_bg: rgba(&p.warn, 0.15),
            err: p.bad.clone(),
            err_soft: rgba(&p.bad, 0.80),
            err_bg: rgba(&p.bad, 0.12),
        }
    }

    /// `(name, value)` for every token, under the names the stylesheet docs
    /// and the Python wall use (`bg-elev-2`, `accent-text`, ...).
    pub fn pairs(&self) -> [(&'static str, &str); 23] {
        [
            ("bg", &self.bg),
            ("bg-toolbar", &self.bg_toolbar),
            ("bg-elev", &self.bg_elev),
            ("bg-elev-2", &self.bg_elev_2),
            ("bg-card", &self.bg_card),
            ("border-soft", &self.border_soft),
            ("border", &self.border),
            ("border-accent", &self.border_accent),
            ("border-strong", &self.border_strong),
            ("fg", &self.fg),
            ("fg-soft", &self.fg_soft),
            ("fg-muted", &self.fg_muted),
            ("fg-dim", &self.fg_dim),
            ("accent", &self.accent),
            ("accent-text", &self.accent_text),
            ("accent-hover", &self.accent_hover),
            ("on-accent", &self.on_accent),
            ("ok", &self.ok),
            ("warn", &self.warn),
            ("warn-bg", &self.warn_bg),
            ("err", &self.err),
            ("err-soft", &self.err_soft),
            ("err-bg", &self.err_bg),
        ]
    }
}

/// Render the wall's GTK stylesheet from `t`.
pub fn css(t: &Tokens) -> String {
    let Tokens {
        bg,
        bg_toolbar,
        bg_elev,
        bg_elev_2,
        bg_card,
        border_soft,
        border,
        border_accent,
        border_strong,
        fg,
        fg_soft,
        fg_muted,
        fg_dim,
        accent,
        accent_text,
        accent_hover,
        on_accent,
        ok,
        warn,
        warn_bg,
        err,
        err_soft,
        err_bg,
    } = t;
    let ok_ring = rgba(ok, 0.7);
    let warn_ring = rgba(warn, 0.75);
    let err_ring = rgba(err, 0.7);
    let panel_btn = rgba(bg_elev_2, 0.72);
    let pill_bg = rgba(bg_elev_2, 0.82);
    let err_a55 = rgba(err, 0.55);
    let err_a5 = rgba(err, 0.5);
    let warn_a45 = rgba(warn, 0.45);
    format!(
        r#"
window, grid, stack {{ background-color: {bg}; }}

.soc-status {{
  background-color: {bg_card};
  border: 1px solid {border_accent};
  border-radius: 10px;
  padding: 18px 28px;
}}
.soc-status.error {{ border-color: {err_a55}; }}

.soc-status-id {{
  color: {accent_text};
  font-weight: bold;
  font-size: 12px;
  letter-spacing: 2px;
}}
.soc-status.error .soc-status-id {{ color: {err}; }}

.soc-status-msg {{ color: {fg_soft}; font-size: 15px; }}
.soc-status.error .soc-status-msg {{ color: {err_soft}; }}

.soc-status spinner {{ color: {accent_text}; min-width: 22px; min-height: 22px; }}

/* on-screen config window + corner gear */
.soc-config {{ background-color: {bg}; }}
.soc-config-title {{ color: {fg}; font-size: 18px; font-weight: bold; }}
.soc-config-sub  {{ color: {fg_dim}; font-size: 12px; }}
.soc-config-tag  {{ color: {accent_text}; font-weight: bold; }}
.soc-config-ok    {{ color: {ok}; font-size: 12px; }}
.soc-config-error {{ color: {err}; font-size: 12px; }}
.soc-config entry {{
  background-color: {bg_elev_2}; color: {fg};
  border: 1px solid {border_accent}; border-radius: 6px; padding: 6px 8px;
}}
.soc-config entry:focus {{ border-color: {accent_text}; }}
.soc-config button {{
  background-image: none; background-color: {bg_elev}; color: {fg_soft};
  border: 1px solid {border_accent}; border-radius: 6px; padding: 6px 12px;
}}
.soc-config-primary {{
  background-color: {accent}; color: {on_accent}; border-color: {accent};
}}
.soc-config-sec {{ color: {fg_dim}; }}

/* Destructive buttons (Remove VPN, Delete vault item, Clear PIN): a subtle red
 * outline + label, so the intent is visible at a glance without screaming. */
.soc-config button.destructive-action,
.destructive-action {{
  background-color: {bg_elev};
  color: {err};
  border-color: {err_a5};
}}
.soc-config button.destructive-action:hover,
.destructive-action:hover {{
  background-color: {err_bg};
  border-color: {err};
}}

/* toolbar action buttons (Settings, Lock, Shot, VPN log) */
.soc-gear, .soc-toolbar-action {{
  background-image: none;
  background-color: {panel_btn};
  border: 1px solid {border_strong};
  border-radius: 8px; padding: 3px 12px; margin: 0 2px;
  color: {fg_muted}; font-size: 13px; font-weight: bold;
}}
.soc-gear:hover, .soc-toolbar-action:hover {{
  background-color: {accent_hover}; color: {on_accent};
}}

/* boot-time file-integrity drift banner (above the toolbar) */
.soc-warn-bar {{
  background-color: {warn_bg};
  border-bottom: 1px solid {warn_a45};
}}
.soc-warn-bar label {{ color: {warn}; font-weight: bold; }}

/* top toolbar (always-visible controls; webviews can't paint over it) */
.soc-toolbar {{
  background-color: {bg_toolbar};
  border-bottom: 1px solid {border_soft};
  padding: 4px 8px;
}}

/* VPN status pill (top of the wall). Traffic-light colours: green=online,
 * amber=connecting (probe timed out, still mid-handshake), red=offline. */
.soc-vpn-pill {{
  background-image: none;
  background-color: {pill_bg};
  border: 1px solid {border_accent};
  border-radius: 12px; padding: 3px 14px; margin: 0 2px;
  color: {fg_soft}; font-size: 13px; font-weight: bold;
}}
.soc-vpn-pill.online       {{ border-color: {ok_ring};   color: {ok}; }}
.soc-vpn-pill.connecting   {{ border-color: {warn_ring}; color: {warn}; }}
.soc-vpn-pill.offline      {{ border-color: {err_ring};  color: {err}; }}
.soc-vpn-pill.checking     {{ color: {warn}; }}
.soc-vpn-pill.unconfigured {{ color: {fg_dim}; }}

/* Settings notebook tabs: match the palette, so they aren't a black-on-black
   default-theme artifact inside the themed settings window. */
notebook header {{ background-color: {bg}; border-bottom: 1px solid {border}; }}
notebook tab {{ background-color: {bg}; color: {fg_dim}; padding: 6px 14px;
  border: 1px solid transparent; border-bottom: none; }}
notebook tab:checked {{ background-color: {bg_elev}; color: {fg};
  border-color: {border}; }}
notebook tab:hover {{ color: {accent_text}; }}
"#
    )
}

/// Escape text for an HTML text node or a quoted attribute.
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

/// The status page shown in place of a panel that is not (yet) live: panel
/// name, optional spinner, a short message. The stock white engine error page
/// is never shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCard {
    /// The panel's display name (rendered upper-cased).
    pub panel: String,
    /// One or two lines; `\n` is a line break.
    pub message: String,
    /// Paint the card in the error colours.
    pub error: bool,
    /// Show the spinner (only while something is actually in progress: a
    /// spinner animates at frame rate for as long as it is visible).
    pub busy: bool,
}

impl StatusCard {
    pub fn new(panel: &str, message: impl Into<String>, error: bool, busy: bool) -> StatusCard {
        StatusCard { panel: panel.to_string(), message: message.into(), error, busy }
    }

    /// The first load is running.
    pub fn connecting(panel: &str) -> StatusCard {
        StatusCard::new(panel, "connecting…", false, true)
    }

    /// The tile has no URL yet.
    pub fn unconfigured(panel: &str) -> StatusCard {
        StatusCard::new(panel, "not configured — open ⚙ or press Ctrl+Shift+C to set this panel's URL", false, false)
    }

    /// A load failed; a retry is scheduled.
    pub fn offline(panel: &str, reason: &str, retry_secs: u64) -> StatusCard {
        StatusCard::new(panel, format!("offline: {reason}\nretrying in {retry_secs}s"), true, false)
    }

    /// The same target has failed repeatedly: point at the likely cause.
    pub fn unreachable(panel: &str, failures: u32, retry_secs: u64) -> StatusCard {
        StatusCard::new(
            panel,
            format!("unreachable {failures}x — verify URL/tunnel (Ctrl+Shift+C)\nstill retrying every {retry_secs}s"),
            true,
            false,
        )
    }

    /// The renderer died; it is restarted after a backoff.
    pub fn recovering(panel: &str, why: &str, retry_secs: u64) -> StatusCard {
        StatusCard::new(panel, format!("renderer {why} — recovering in {retry_secs}s"), true, false)
    }

    /// A non-http(s) URL was refused.
    pub fn rejected_url(panel: &str) -> StatusCard {
        StatusCard::new(panel, "rejected: only http:// or https:// URLs are allowed", true, false)
    }

    /// The proxy refused the vault's credentials.
    pub fn proxy_auth_failed(panel: &str) -> StatusCard {
        StatusCard::new(panel, "proxy authentication failed — check the vault login for the proxy", true, false)
    }

    /// The card as a complete HTML document styled from `t`.
    ///
    /// Self-contained and script-free, and it says so: the embedded policy
    /// forbids everything but its own inline style, so even a future escaping
    /// mistake could not turn a status message into running code.
    pub fn to_html(&self, t: &Tokens) -> String {
        let class = if self.error { "soc-status error" } else { "soc-status" };
        let spinner = if self.busy { "<div class=\"spinner\"></div>" } else { "" };
        let title = html_escape(&self.panel.to_uppercase());
        let message = html_escape(&self.message);
        let Tokens { bg, bg_card, border_accent, accent_text, fg_soft, err, err_soft, .. } = t;
        let err_border = rgba(err, 0.55);
        format!(
            "<!doctype html>\n<html><head><meta charset=\"utf-8\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
<title>{title}</title><style>\
html,body{{height:100%;margin:0}}\
body{{background:{bg};display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif}}\
.soc-status{{background:{bg_card};border:1px solid {border_accent};border-radius:10px;padding:18px 28px;\
display:flex;flex-direction:column;align-items:center;gap:10px;max-width:46ch;text-align:center}}\
.soc-status.error{{border-color:{err_border}}}\
.soc-status-id{{color:{accent_text};font-weight:bold;font-size:12px;letter-spacing:2px}}\
.soc-status.error .soc-status-id{{color:{err}}}\
.soc-status-msg{{color:{fg_soft};font-size:15px;white-space:pre-line}}\
.soc-status.error .soc-status-msg{{color:{err_soft}}}\
.spinner{{width:22px;height:22px;border:3px solid {border_accent};border-top-color:{accent_text};\
border-radius:50%;animation:spin 1s linear infinite}}\
@keyframes spin{{to{{transform:rotate(360deg)}}}}\
</style></head><body><div class=\"{class}\"><div class=\"soc-status-id\">{title}</div>{spinner}\
<div class=\"soc-status-msg\">{message}</div></div></body></html>\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tokens_cover_every_semantic_role() {
        let t = Tokens::default();
        let names: Vec<&str> = t.pairs().iter().map(|(n, _)| *n).collect();
        for required in [
            "bg",
            "bg-toolbar",
            "bg-elev",
            "fg",
            "fg-soft",
            "fg-dim",
            "accent",
            "accent-text",
            "ok",
            "warn",
            "err",
            "border",
        ] {
            assert!(names.contains(&required), "{required} missing");
        }
        // No colour is reused three or more times (a copy-paste typo would).
        for (_, value) in t.pairs() {
            assert!(t.pairs().iter().filter(|(_, v)| *v == value).count() < 3, "{value} reused");
        }
        assert_eq!(t.bg, FALLBACK_BG);
    }

    #[test]
    fn css_carries_every_class_the_runtime_uses() {
        let sheet = css(&Tokens::default());
        for class in [
            ".soc-warn-bar",
            ".soc-toolbar-action",
            ".destructive-action",
            ".soc-status",
            ".soc-vpn-pill.online",
            ".soc-vpn-pill.connecting",
            ".soc-vpn-pill.offline",
            ".soc-vpn-pill.checking",
            ".soc-vpn-pill.unconfigured",
        ] {
            assert!(sheet.contains(class), "{class} missing from the stylesheet");
        }
        assert!(!sheet.contains("{{") && !sheet.contains("}}"));
    }

    #[test]
    fn malformed_colours_never_reach_the_stylesheet() {
        let colors = json!({
            "background": "red; } * { background-image: url(http://evil.example/x) } .y {",
            "primary": "#12345",
            "text": "#zzz",
            "good": 7,
            "warn": "abc",
            "bad": " #A1B2C3 ",
        });
        let p = Palette::from_colors(colors.as_object().unwrap());
        let d = Palette::default();
        assert_eq!((&p.background, &p.primary, &p.text, &p.good), (&d.background, &d.primary, &d.text, &d.good));
        assert_eq!(p.warn, "#abc");
        assert_eq!(p.bad, "#A1B2C3");
        let sheet = css(&Tokens::from_palette(&p));
        assert!(!sheet.contains("evil.example") && !sheet.contains("url("));
    }

    #[test]
    fn label_colour_follows_the_accent() {
        // A light accent gets a dark label, a dark accent a white one.
        let light = Palette { accent_strong: "#FFD54A".into(), ..Palette::default() };
        assert_eq!(Tokens::from_palette(&light).on_accent, "#101010");
        assert_eq!(Tokens::default().on_accent, "#ffffff");
        assert!(contrast_ratio("#000000", "#ffffff") > 20.9);
        assert!((contrast_ratio("#777", "#777") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn status_cards_escape_everything() {
        let card = StatusCard::offline("<img src=x onerror=alert(1)>", "\"><script>alert('x')</script>&", 10);
        let html = card.to_html(&Tokens::default());
        assert!(!html.contains("<script") && !html.contains("<img"));
        assert!(html.contains("&lt;IMG SRC=X ONERROR=ALERT(1)&gt;"));
        assert!(
            html.contains("offline: &quot;&gt;&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;&amp;\nretrying in 10s")
        );
        assert!(html.contains("class=\"soc-status error\""));
        assert!(html.contains("default-src 'none'"));
        // An error card that only waits out a backoff has no spinner.
        assert!(!html.contains("class=\"spinner\""));
    }

    #[test]
    fn status_card_states() {
        let t = Tokens::default();
        let connecting = StatusCard::connecting("grafana");
        assert!(connecting.busy && !connecting.error);
        let html = connecting.to_html(&t);
        assert!(html.contains("class=\"soc-status\"") && html.contains("class=\"spinner\""));
        assert!(html.contains(">GRAFANA<") && html.contains("connecting…"));

        let recovering = StatusCard::recovering("p1", "crashed", 5);
        assert_eq!(recovering.message, "renderer crashed — recovering in 5s");
        assert!(recovering.error && !recovering.busy);
        assert!(StatusCard::unreachable("p1", 4, 60).message.starts_with("unreachable 4x"));
        assert!(!StatusCard::unconfigured("p1").error);
        assert!(StatusCard::rejected_url("p1").error && StatusCard::proxy_auth_failed("p1").error);
        assert_eq!(html_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&#x27;f");
    }
}
