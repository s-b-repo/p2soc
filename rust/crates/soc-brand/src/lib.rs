//! Branding: product name, icon and the colour palette, read from the first
//! `branding.yaml` found. A missing or partial file falls back to the built-in
//! defaults and a broken one never stops the wall.

use soc_core::dict::{Dict, text};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Built-in palette (the green-on-white console theme).
pub const DEFAULT_COLORS: &[(&str, &str)] = &[
    ("primary", "#1FA463"),
    ("setup", "#1FA463"),
    ("desktop", "#1FA463"),
    ("kiosk", "#0E7C7B"),
    ("background", "#FFFFFF"),
    ("surface_top", "#F4F8F5"),
    ("surface_bottom", "#EAF1EC"),
    ("border", "#CFE0D4"),
    ("text", "#0B1F14"),
    ("text_dim", "#51695C"),
    ("accent_strong", "#157A49"),
    ("good", "#157A49"),
    ("warn", "#9C7209"),
    ("bad", "#C0341D"),
];

const DEFAULT_TEXT: &[(&str, &str)] = &[
    ("name", "SOC Video Wall"),
    ("short_name", "SOC Wall"),
    ("tagline", "Operations console"),
    ("vendor", "s-b-repo"),
    ("homepage", "https://github.com/s-b-repo/p2soc"),
    ("icon", "share/icons/soc-wall.svg"),
];

/// The merged branding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branding {
    pub text: HashMap<String, String>,
    pub colors: HashMap<String, String>,
}

impl Default for Branding {
    fn default() -> Self {
        let own = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Branding { text: own(DEFAULT_TEXT), colors: own(DEFAULT_COLORS) }
    }
}

/// `#RGB` or `#RRGGBB`. Colours are interpolated into a stylesheet, so
/// anything else is rejected rather than trusted.
pub fn is_hex_color(value: &str) -> bool {
    value.strip_prefix('#').is_some_and(|h| matches!(h.len(), 3 | 6) && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Branding {
    pub fn get(&self, key: &str) -> &str {
        self.text.get(key).map_or("", String::as_str)
    }

    /// Lay a parsed branding document over the defaults. Empty values and
    /// malformed colours keep the default.
    pub fn merged(doc: &Dict) -> Branding {
        let mut out = Branding::default();
        for (key, value) in doc {
            match value.as_object() {
                Some(colors) if key == "colors" => {
                    for (name, colour) in colors {
                        let colour = text(colour);
                        if is_hex_color(colour.trim()) {
                            out.colors.insert(name.clone(), colour.trim().to_string());
                        }
                    }
                }
                Some(_) => {}
                None => {
                    let value = text(value);
                    if !value.is_empty() && !value.chars().any(char::is_control) {
                        out.text.insert(key.clone(), value);
                    }
                }
            }
        }
        out
    }
}

/// Where the environment says branding may live.
#[derive(Debug, Clone, Default)]
pub struct Locations {
    /// `$SOC_BRANDING_FILE`.
    pub explicit: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME` (or `~/.config`).
    pub config_home: Option<PathBuf>,
    /// `$XDG_CACHE_HOME` (or `~/.cache`).
    pub cache_home: Option<PathBuf>,
    /// `$SOC_ROOT` (the install tree).
    pub root: Option<PathBuf>,
}

impl Locations {
    pub fn from_env() -> Locations {
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        let home = var("HOME");
        Locations {
            explicit: var("SOC_BRANDING_FILE"),
            config_home: var("XDG_CONFIG_HOME").or_else(|| home.as_ref().map(|h| h.join(".config"))),
            cache_home: var("XDG_CACHE_HOME").or_else(|| home.as_ref().map(|h| h.join(".cache"))),
            root: var("SOC_ROOT"),
        }
    }

    /// Candidate files, most specific first: the explicit override, the
    /// per-user theme (so a desktop user never needs root to retheme), the
    /// system file, then the install tree.
    pub fn candidates(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        out.extend(self.explicit.clone());
        out.extend(self.config_home.as_ref().map(|c| c.join("soc-display").join("branding.yaml")));
        out.push(PathBuf::from("/etc/soc-display/branding.yaml"));
        if let Some(root) = &self.root {
            out.push(root.join("branding").join("branding.yaml"));
            out.push(root.join("config").join("branding.yaml"));
        }
        out
    }

    /// The cross-process "theme changed" marker another tool touches after
    /// saving a theme.
    pub fn marker(&self) -> Option<PathBuf> {
        self.cache_home.as_ref().map(|c| c.join("soc-display").join("branding-changed"))
    }

    /// When the marker was last touched.
    pub fn marker_mtime(&self) -> Option<SystemTime> {
        std::fs::metadata(self.marker()?).and_then(|m| m.modified()).ok()
    }

    /// Where a theme save should go: the explicit `$SOC_BRANDING_FILE`, else
    /// the per-user file (so a desktop user never needs root to retheme). The
    /// system `/etc` file is never chosen as a write target.
    pub fn save_target(&self) -> Option<PathBuf> {
        self.explicit.clone().or_else(|| self.config_home.as_ref().map(|c| c.join("soc-display").join("branding.yaml")))
    }

    /// Touch the cross-process marker so a running wall notices the new theme
    /// and repaints without a restart.
    pub fn touch_marker(&self) {
        let Some(marker) = self.marker() else {
            return;
        };
        if let Some(parent) = marker.parent() {
            let _ = std::fs::create_dir_all(parent); // audit-allow: best-effort
        }
        let stamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
        let _ = std::fs::write(&marker, format!("{stamp}")); // audit-allow: best-effort
    }

    /// Load the first existing candidate over the defaults.
    pub fn load(&self) -> Branding {
        for path in self.candidates() {
            if path.exists() {
                return load_file(&path);
            }
        }
        Branding::default()
    }
}

/// Render the desktop launcher or resolve its branded icon for the installer.
pub fn cli(args: &[String]) -> i32 {
    let locations = Locations::from_env();
    let branding = locations.load();
    let arg = |i| args.get(i).map(String::as_str);
    match arg(0) {
        None => {
            for (key, _) in DEFAULT_TEXT {
                println!("{key}={}", branding.get(key));
            }
        }
        Some("get") if args.len() == 2 => println!("{}", branding.get(&args[1])),
        Some("icon-path") if args.len() == 1 => {
            let root = locations.root.as_deref().unwrap_or_else(|| Path::new("/opt/soc-display"));
            let icon = Path::new(branding.get("icon"));
            for candidate in [
                root.join(icon),
                Path::new("/usr/share/soc-display").join(icon),
                Path::new("/etc/soc-display").join(icon),
                root.join("share/icons/soc-wall.svg"),
                PathBuf::from("/usr/share/icons/hicolor/scalable/apps/soc-wall.svg"),
            ] {
                if candidate.is_file() {
                    println!("{}", candidate.display());
                    return 0;
                }
            }
            return 1;
        }
        Some("desktop") if args.len() <= 3 => {
            let program = arg(1).unwrap_or("/opt/soc-display/scripts/soc-wall-menu");
            let icon = arg(2).unwrap_or("soc-wall");
            if program.chars().any(char::is_control) || icon.chars().any(char::is_control) {
                return 2;
            }
            let escape = |s: &str| s.replace('\\', "\\\\");
            let program = program
                .replace('%', "%%")
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$")
                .replace('`', "\\`");
            println!(
                "[Desktop Entry]\nName={}\nComment={}\nExec=\"{}\"\nIcon={}\nTerminal=false\nType=Application\nCategories=System;\nKeywords=soc;security;wall;kiosk;dashboard;",
                escape(branding.get("name")),
                escape(branding.get("tagline")),
                escape(&program),
                escape(icon)
            );
        }
        _ => {
            eprintln!("usage: soc-wall branding [get KEY | icon-path | desktop [EXEC [ICON]]]");
            return 2;
        }
    }
    0
}

/// Persist a theme to `path` (0600) and touch the marker via `locations`.
/// Writes a complete, loadable `branding.yaml`: the text fields followed by the
/// 14 colour keys.
pub fn save_colors(path: &Path, branding: &Branding, locations: &Locations) -> std::io::Result<()> {
    let mut doc = String::from("# SOC video-wall branding — generated by the appearance editor.\n");
    for (key, _) in DEFAULT_TEXT {
        if let Some(value) = branding.text.get(*key) {
            doc.push_str(&format!("{key}: {}\n", yaml_scalar(value)));
        }
    }
    doc.push_str("colors:\n");
    // A stable key order (the built-in order), so saves are reproducible.
    for (key, _) in DEFAULT_COLORS {
        if let Some(colour) = branding.colors.get(*key).filter(|c| is_hex_color(c)) {
            doc.push_str(&format!("  {key}: \"{colour}\"\n"));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    soc_sys::fsutil::write_atomic(path, doc.as_bytes(), 0o600)?;
    locations.touch_marker();
    Ok(())
}

/// Quote a YAML scalar only when it needs it (contains a YAML metacharacter).
fn yaml_scalar(value: &str) -> String {
    let needs_quote = value.is_empty()
        || value.starts_with(['!', '&', '*', '#', '?', '|', '>', '%', '@', '`', '"', '\'', ' '])
        || value.contains([':', '{', '}', '[', ']', ',']);
    if needs_quote { format!("{value:?}") } else { value.to_string() }
}

/// A branding file is tiny; refuse to slurp something that is not one.
const MAX_BYTES: u64 = 256 * 1024;

fn load_file(path: &Path) -> Branding {
    let ignored = |why: &dyn std::fmt::Display| {
        eprintln!("branding: ignoring {}: {why}", path.display());
        Branding::default()
    };
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_BYTES => return ignored(&"file too large"),
        Err(e) => return ignored(&e),
        Ok(_) => {}
    }
    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => return ignored(&e),
    };
    match soc_core::load::parse_yaml(&source) {
        Ok(serde_json::Value::Object(doc)) => Branding::merged(&doc),
        Ok(_) => Branding::default(),
        Err(e) => ignored(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(yaml: &str) -> Dict {
        soc_core::load::parse_yaml(yaml).unwrap().as_object().cloned().unwrap()
    }

    #[test]
    fn defaults_are_complete() {
        let b = Branding::default();
        assert_eq!(b.get("short_name"), "SOC Wall");
        assert_eq!(b.colors.len(), DEFAULT_COLORS.len());
        assert!(b.colors.values().all(|c| is_hex_color(c)));
    }

    #[test]
    fn partial_file_overrides_only_what_it_names() {
        let b = Branding::merged(&doc("name: Acme NOC\ntagline: ''\ncolors:\n  primary: '#ff0000'\n"));
        assert_eq!(b.get("name"), "Acme NOC");
        assert_eq!(b.get("tagline"), "Operations console", "empty keeps the default");
        assert_eq!(b.colors["primary"], "#ff0000");
        assert_eq!(b.colors["background"], "#FFFFFF");
    }

    #[test]
    fn a_colour_cannot_smuggle_css() {
        let b = Branding::merged(&doc(
            "colors:\n  background: \"#fff; } * { background: url(http://evil/x)\"\n  text: red\n  bad: '#12345'\n",
        ));
        let d = Branding::default();
        assert_eq!(b.colors["background"], d.colors["background"]);
        assert_eq!(b.colors["text"], d.colors["text"]);
        assert_eq!(b.colors["bad"], d.colors["bad"]);
    }

    #[test]
    fn hex_colours() {
        for ok in ["#fff", "#FFFFFF", "#0b1020"] {
            assert!(is_hex_color(ok), "{ok}");
        }
        for bad in ["", "fff", "#ffff", "#gggggg", "#fff;", " #fff"] {
            assert!(!is_hex_color(bad), "{bad:?}");
        }
    }

    #[test]
    fn candidate_order() {
        let loc = Locations {
            explicit: Some("/x/b.yaml".into()),
            config_home: Some("/home/u/.config".into()),
            cache_home: Some("/home/u/.cache".into()),
            root: Some("/opt/soc".into()),
        };
        let c: Vec<String> = loc.candidates().iter().map(|p| p.display().to_string()).collect();
        assert_eq!(
            c,
            vec![
                "/x/b.yaml",
                "/home/u/.config/soc-display/branding.yaml",
                "/etc/soc-display/branding.yaml",
                "/opt/soc/branding/branding.yaml",
                "/opt/soc/config/branding.yaml",
            ]
        );
        assert_eq!(loc.marker().unwrap(), Path::new("/home/u/.cache/soc-display/branding-changed"));
    }

    #[test]
    fn shipped_branding_file_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../branding/branding.yaml");
        let b = load_file(&path);
        assert_eq!(b.get("name"), "SOC Video Wall");
        assert_eq!(b.colors["kiosk"], "#0E7C7B");
    }

    #[test]
    fn broken_file_falls_back_to_defaults() {
        let dir = std::env::temp_dir().join(format!("soc-branding-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("branding.yaml");
        std::fs::write(&path, "colors: [unterminated\n").unwrap();
        assert_eq!(load_file(&path), Branding::default());
        std::fs::write(&path, "- just\n- a list\n").unwrap();
        assert_eq!(load_file(&path), Branding::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
