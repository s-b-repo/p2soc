//! Window-manager placement rules.
//!
//! One generator for both session types: Openbox on X11 and labwc on Wayland
//! each get an `rc.xml` built from a template plus one forced-placement rule
//! per panel, so every panel window drops into its grid cell (belt and braces
//! alongside the host's own move/resize).
//!
//! - Openbox matches on `WM_CLASS` (`soc-<id>`).
//! - labwc gets two rules per panel: one on `identifier` (the app_id of a
//!   native Wayland client, WM_CLASS for XWayland ones such as Chromium) and
//!   one on `title` — the host names each WebKit window `soc-<id>`, because a
//!   single GTK process cannot give its windows distinct app_ids on Wayland.
//!
//! The templates are compiled in. Every substituted value is XML-escaped: a
//! panel id reaching this point is validated, but the generator must not be
//! the place where a config value turns into markup.

use crate::error::{Result, SysError};
use crate::fsutil;
use soc_core::{Config, Geometry, compute_geometry};
use std::path::{Path, PathBuf};

const OPENBOX_TEMPLATE: &str = include_str!("../../../../openbox/rc.xml.tmpl");
const LABWC_TEMPLATE: &str = include_str!("../../../../labwc/rc.xml.tmpl");

/// The line in a template that the rules replace.
const PLACEHOLDER: &str = "  <!-- SOC_APPS -->";

/// Which window manager to generate for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wm {
    Openbox,
    Labwc,
}

impl Wm {
    /// The compiled-in template.
    pub const fn template(self) -> &'static str {
        match self {
            Wm::Openbox => OPENBOX_TEMPLATE,
            Wm::Labwc => LABWC_TEMPLATE,
        }
    }

    const fn summary_noun(self) -> &'static str {
        match self {
            Wm::Openbox => "placement rules",
            Wm::Labwc => "panels",
        }
    }
}

/// Generator options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RcOptions {
    /// The real screen resolution (e.g. read from xrandr), overriding the
    /// config's `display.width/height`. Applied only when both are non-zero.
    pub size: Option<(i32, i32)>,
    /// Apply `size` only when `display.auto` is true — a fixed resolution in
    /// the config is then respected.
    pub if_auto: bool,
}

/// A generated config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcXml {
    pub xml: String,
    pub panels: usize,
    /// The resolution the rules were computed for.
    pub width: i32,
    pub height: i32,
}

/// Escape `s` for XML text or a double-quoted attribute value.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Control characters are not representable in XML 1.0 at all.
            c if u32::from(c) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

fn openbox_rule(class: &str, g: Geometry) -> String {
    format!(
        "  <application class=\"{class}\">\n    <decor>yes</decor>\n    <maximized>no</maximized>\n    \
         <position force=\"yes\"><x>{}</x><y>{}</y><monitor>1</monitor></position>\n    \
         <size><width>{}</width><height>{}</height></size>\n    <layer>normal</layer>\n    \
         <focus>yes</focus>\n  </application>",
        g.x, g.y, g.w, g.h
    )
}

fn labwc_rule(matcher: &str, class: &str, g: Geometry) -> String {
    format!(
        "  <windowRule {matcher}=\"{class}\">\n    <action name=\"MoveTo\" x=\"{}\" y=\"{}\"/>\n    \
         <action name=\"ResizeTo\" width=\"{}\" height=\"{}\"/>\n  </windowRule>",
        g.x, g.y, g.w, g.h
    )
}

/// Generate the config for `wm` from an explicit template.
pub fn generate_with_template(wm: Wm, template: &str, conf: &Config, opts: RcOptions) -> RcXml {
    let mut display = conf.display.clone();
    let resized = match opts.size {
        Some((w, h)) if w != 0 && h != 0 && (display.auto || !opts.if_auto) => {
            display.width = w;
            display.height = h;
            true
        }
        _ => false,
    };
    let mut rules = Vec::new();
    for p in &conf.panels {
        // With the real resolution the grid is recomputed; otherwise the
        // geometry the loader derived from the config stands.
        let g = match p.geometry {
            Some(g) if !resized => g,
            _ => compute_geometry(&display, p.grid),
        };
        let class = xml_escape(&p.wmclass());
        match wm {
            Wm::Openbox => rules.push(openbox_rule(&class, g)),
            Wm::Labwc => {
                rules.push(labwc_rule("identifier", &class, g));
                rules.push(labwc_rule("title", &class, g));
            }
        }
    }
    RcXml {
        xml: template.replace(PLACEHOLDER, &rules.join("\n")),
        panels: conf.panels.len(),
        width: display.width,
        height: display.height,
    }
}

/// Generate the config for `wm` from the compiled-in template.
pub fn generate(wm: Wm, conf: &Config, opts: RcOptions) -> RcXml {
    generate_with_template(wm, wm.template(), conf, opts)
}

/// Write a generated config atomically (0644), creating its directory.
pub fn write_rc(out: &Path, xml: &str) -> Result<()> {
    let fail = |e| SysError::io(format!("cannot write {}", out.display()), e);
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        fsutil::ensure_dir(parent, 0o755).map_err(fail)?;
    }
    fsutil::write_atomic(out, xml.as_bytes(), 0o644).map_err(fail)
}

/// Parsed command line of the generator.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    out: PathBuf,
    template: Option<PathBuf>,
    opts: RcOptions,
}

fn parse_cli(args: &[String]) -> Result<Cli> {
    let (mut out, mut template, mut width, mut height, mut if_auto) = (None, None, None, None, false);
    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v)),
            _ => (arg, None),
        };
        let mut value = || inline.or_else(|| it.next()).ok_or_else(|| SysError::Usage(format!("{name} needs a value")));
        let int = |v: &str| v.parse::<i32>().map_err(|_| SysError::Usage(format!("{name}: invalid integer {v:?}"))); // audit-allow: the message names the offending value
        match name {
            "--out" => out = Some(PathBuf::from(value()?)),
            "--template" => template = Some(PathBuf::from(value()?)),
            "--width" => width = Some(int(value()?)?),
            "--height" => height = Some(int(value()?)?),
            "--if-auto" if inline.is_none() => if_auto = true,
            // The config is loaded by the caller; the flag is accepted so
            // existing session scripts keep working unchanged.
            "--panels" => {
                value()?;
            }
            _ => return Err(SysError::Usage(format!("unrecognized argument: {arg}"))),
        }
    }
    let out = out.ok_or_else(|| SysError::Usage("--out is required".into()))?;
    Ok(Cli { out, template, opts: RcOptions { size: width.zip(height), if_auto } })
}

/// `gen-openbox-rc` / `gen-labwc-rc`:
/// `--out FILE [--width W --height H] [--if-auto] [--template FILE]`.
/// The config is passed in already loaded. Prints a one-line summary.
pub fn wm_rc_main(wm: Wm, conf: &Config, args: &[String]) -> i32 {
    let run = || -> Result<String> {
        let cli = parse_cli(args)?;
        let rc = match &cli.template {
            None => generate(wm, conf, cli.opts),
            Some(path) => {
                let template = fsutil::read_capped(path, 1 << 20)
                    .map_err(|e| SysError::io(format!("cannot read {}", path.display()), e))?;
                generate_with_template(wm, &template, conf, cli.opts)
            }
        };
        write_rc(&cli.out, &rc.xml)?;
        Ok(format!("wrote {} ({} {} @ {}x{})", cli.out.display(), rc.panels, wm.summary_noun(), rc.width, rc.height))
    };
    match run() {
        Ok(summary) => {
            println!("{summary}");
            0
        }
        Err(e) => {
            eprintln!("gen-rc: {e}");
            e.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, config, fixture, panel, wall_basic, wall_notunnel, wall_rich};
    use soc_core::DisplayCfg;
    use std::os::unix::fs::PermissionsExt;

    fn size(w: i32, h: i32, if_auto: bool) -> RcOptions {
        RcOptions { size: Some((w, h)), if_auto }
    }

    #[test]
    fn openbox_output_is_identical_to_the_python_script() {
        let none = RcOptions::default();
        assert_eq!(generate(Wm::Openbox, &wall_basic(), none).xml, fixture("basic.openbox.xml"));
        assert_eq!(generate(Wm::Openbox, &wall_rich(), none).xml, fixture("rich.openbox.xml"));
        assert_eq!(generate(Wm::Openbox, &wall_notunnel(), none).xml, fixture("notunnel.openbox.xml"));
        assert_eq!(
            generate(Wm::Openbox, &wall_basic(), size(1280, 720, true)).xml,
            fixture("basic.openbox-1280x720-ifauto.xml")
        );
    }

    #[test]
    fn labwc_output_is_identical_to_the_python_script() {
        let none = RcOptions::default();
        assert_eq!(generate(Wm::Labwc, &wall_basic(), none).xml, fixture("basic.labwc.xml"));
        assert_eq!(generate(Wm::Labwc, &wall_rich(), none).xml, fixture("rich.labwc.xml"));
        assert_eq!(generate(Wm::Labwc, &wall_notunnel(), none).xml, fixture("notunnel.labwc.xml"));
        assert_eq!(generate(Wm::Labwc, &wall_rich(), size(1366, 768, false)).xml, fixture("rich.labwc-1366x768.xml"));
        // display.auto is false in the rich wall, so --if-auto keeps its fixed resolution
        assert_eq!(generate(Wm::Labwc, &wall_rich(), size(1366, 768, true)).xml, fixture("rich.labwc.xml"));
    }

    #[test]
    fn output_from_the_loaded_yaml_is_identical_too() {
        for name in ["basic", "rich", "notunnel"] {
            let conf = soc_core::load_str(&fixture(&format!("wall-{name}.yaml")), name).unwrap();
            let none = RcOptions::default();
            assert_eq!(generate(Wm::Openbox, &conf, none).xml, fixture(&format!("{name}.openbox.xml")), "{name}");
            assert_eq!(generate(Wm::Labwc, &conf, none).xml, fixture(&format!("{name}.labwc.xml")), "{name}");
        }
    }

    #[test]
    fn labwc_has_an_identifier_and_a_title_rule_per_panel() {
        let rc = generate(Wm::Labwc, &wall_basic(), RcOptions::default());
        assert_eq!(rc.xml.matches("<windowRule ").count(), 8);
        for id in ["p1", "p2", "p3", "p4"] {
            assert!(rc.xml.contains(&format!("<windowRule identifier=\"soc-{id}\">")));
            assert!(rc.xml.contains(&format!("<windowRule title=\"soc-{id}\">")));
        }
        // p2 sits in the top-right cell
        let p2 = rc.xml.split("<windowRule identifier=\"soc-p2\">").nth(1).unwrap();
        assert!(p2.trim_start().starts_with("<action name=\"MoveTo\" x=\"960\" y=\"0\"/>"));
        assert!(p2.contains("<action name=\"ResizeTo\" width=\"960\" height=\"540\"/>"));
        assert_eq!((rc.panels, rc.width, rc.height), (4, 1920, 1080));
    }

    #[test]
    fn if_auto_applies_the_real_resolution_only_to_auto_displays() {
        let auto = generate(Wm::Openbox, &wall_basic(), size(1280, 720, true));
        assert!(auto.xml.contains("<width>640</width>"));
        assert_eq!((auto.width, auto.height), (1280, 720));
        let fixed = generate(Wm::Openbox, &wall_rich(), size(1280, 720, true));
        assert_eq!((fixed.width, fixed.height), (2560, 1440));
        // a missing or zero dimension is no override at all
        let zero = generate(Wm::Openbox, &wall_basic(), size(1280, 0, false));
        assert_eq!((zero.width, zero.height), (1920, 1080));
    }

    #[test]
    fn substituted_values_are_xml_escaped() {
        assert_eq!(xml_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(xml_escape("x\u{0}y\u{1b}z"), "xyz");
        let d = DisplayCfg::default();
        let hostile = "x\"><application class=\"*\"><fullscreen>yes</fullscreen></application><!--";
        let conf = config(d.clone(), vec![panel(&d, hostile, (0, 0))], serde_json::json!({}));
        for wm in [Wm::Openbox, Wm::Labwc] {
            let xml = generate(wm, &conf, RcOptions::default()).xml;
            assert!(!xml.contains("<fullscreen>"), "{wm:?}");
            assert!(xml.contains("soc-x&quot;&gt;&lt;application class=&quot;*&quot;&gt;"), "{wm:?}");
        }
        let rules = generate(Wm::Openbox, &conf, RcOptions::default()).xml.matches("<application ").count();
        assert_eq!(rules, 1, "the hostile id did not add a rule of its own");
    }

    #[test]
    fn templates_carry_exactly_one_placeholder() {
        for wm in [Wm::Openbox, Wm::Labwc] {
            assert_eq!(wm.template().matches(PLACEHOLDER).count(), 1, "{wm:?}");
            let empty = config(DisplayCfg::default(), vec![], serde_json::json!({}));
            assert!(!generate(wm, &empty, RcOptions::default()).xml.contains("SOC_APPS -->\n  </"));
        }
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn command_line_parsing() {
        let cli =
            parse_cli(&strings(&["--panels", "p.yaml", "--out", "rc.xml", "--width", "1280", "--height=720"])).unwrap();
        assert_eq!(cli.out, Path::new("rc.xml"));
        assert_eq!(cli.opts, size(1280, 720, false));
        assert!(parse_cli(&strings(&["--out", "x", "--if-auto"])).unwrap().opts.if_auto);
        assert_eq!(parse_cli(&strings(&["--out", "x", "--width", "9"])).unwrap().opts.size, None);
        for bad in [&["--width", "1"][..], &["--out"], &["--out", "x", "--width", "wide"], &["--out", "x", "--bogus"]] {
            assert!(matches!(parse_cli(&strings(bad)), Err(SysError::Usage(_))), "{bad:?}");
        }
    }

    #[test]
    fn main_writes_the_file_atomically() {
        let t = TempDir::new("wmrules-main");
        let out = t.path().join("cfg/openbox/rc.xml");
        let args = strings(&["--out", &out.display().to_string(), "--width", "1280", "--height", "720", "--if-auto"]);
        assert_eq!(wm_rc_main(Wm::Openbox, &wall_basic(), &args), 0);
        assert_eq!(std::fs::read_to_string(&out).unwrap(), fixture("basic.openbox-1280x720-ifauto.xml"));
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(std::fs::read_dir(out.parent().unwrap()).unwrap().count(), 1);
        assert_eq!(wm_rc_main(Wm::Labwc, &wall_basic(), &strings(&["--bogus"])), 2);
        // an output path that looks like an option is just a file name here
        let dashed = t.path().join("-rf");
        assert_eq!(wm_rc_main(Wm::Labwc, &wall_basic(), &strings(&["--out", &dashed.display().to_string()])), 0);
        assert!(dashed.is_file());
    }

    #[test]
    fn a_custom_template_can_be_supplied() {
        let t = TempDir::new("wmrules-template");
        let template = t.write("t.xml", "<r>\n  <!-- SOC_APPS -->\n</r>\n");
        let out = t.path().join("rc.xml");
        let args = strings(&["--template", &template.display().to_string(), "--out", &out.display().to_string()]);
        assert_eq!(wm_rc_main(Wm::Labwc, &wall_notunnel(), &args), 0);
        let xml = std::fs::read_to_string(&out).unwrap();
        assert!(xml.starts_with("<r>\n  <windowRule identifier=\"soc-left\">"), "{xml}");
    }
}
