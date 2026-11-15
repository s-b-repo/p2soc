//! Headless subcommands that need nothing but the config: validating a file
//! and previewing the grid geometry.

use soc_core::load::{ConfigError, Overrides, load_with};
use soc_core::{Config, LOG_TAG};
use std::path::Path;

/// One line per panel: what loads where.
pub fn geometry_lines(conf: &Config) -> Vec<String> {
    conf.panels
        .iter()
        .map(|p| {
            let g = p.geometry.unwrap_or(soc_core::compute_geometry(&conf.display, p.grid));
            format!(
                "  {:4} {:8} {:6} -> {}  @ {}x{}+{}+{}",
                p.id,
                p.engine.as_str(),
                p.mode.as_str(),
                soc_core::guard::url_for_msg(&p.effective_url()),
                g.w,
                g.h,
                g.x,
                g.y
            )
        })
        .collect()
}

/// `soc-wall check <file>`: validate a config, print every problem (or the
/// warnings and the resulting layout). Exit 0 when the file is usable.
pub fn check(path: &Path, out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    match load_with(path, &Overrides::from_env()) {
        Ok(conf) => {
            for w in &conf.warnings {
                let _ = writeln!(err, "warning: {w}"); // audit-allow: best-effort, diagnostics to a closed stderr are unreportable
            }
            let summary = format!(
                "{}: OK — {} panel(s), grid {}x{} @ {}x{}, {} VPN(s)",
                path.display(),
                conf.panels.len(),
                conf.display.cols,
                conf.display.rows,
                conf.display.width,
                conf.display.height,
                conf.enabled_vpns().count()
            );
            let _ = writeln!(out, "{summary}"); // audit-allow: best-effort, closed stdout is unreportable
            for line in geometry_lines(&conf) {
                let _ = writeln!(out, "{line}"); // audit-allow: best-effort, closed stdout is unreportable
            }
            0
        }
        Err(ConfigError { message, .. }) => {
            let _ = writeln!(err, "{LOG_TAG} {message}"); // audit-allow: best-effort, closed stderr is unreportable
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel)
    }

    #[test]
    fn check_accepts_the_shipped_template() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(check(&repo("config/panels.yaml"), &mut out, &mut err), 0);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("OK — 4 panel(s), grid 2x2 @ 1920x1080, 0 VPN(s)"), "{out}");
        assert!(out.contains("p3   chromium tunnel -> 'http://127.0.0.1:19103/login'  @ 960x540+0+540"), "{out}");
    }

    #[test]
    fn check_reports_every_problem_and_fails() {
        let dir = std::env::temp_dir().join(format!("soc-check-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.yaml");
        std::fs::write(&path, "panels:\n  - {id: 'a b', url: 'ftp://x'}\n").unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(check(&path, &mut out, &mut err), 1);
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("2 problem(s)"), "{err}");
        assert!(out.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn check_missing_file() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(check(Path::new("/nonexistent/panels.yaml"), &mut out, &mut err), 1);
        assert!(String::from_utf8(err).unwrap().contains("config file not found"));
    }
}
