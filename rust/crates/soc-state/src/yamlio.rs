//! Config export and import for the settings window (and the headless
//! `export-config` / `import-config` subcommands).
//!
//! Export writes the *effective* config — the base `panels.yaml` with the
//! on-screen overrides merged in — to a timestamped YAML file that Import, or
//! a plain `soc-wall check`, can read back. It holds no credentials, only
//! vault-item names. The file is created with [`fsio::write_exclusive`], so a
//! stale or planted file at the target is never overwritten, and it is 0600
//! because it names internal hosts.
//!
//! Import reads an operator-chosen file with [`fsio::read_user_file`]
//! (regular files only, size-capped) and validates it through the real
//! config loader, so nothing unvalidated ever reaches the wall.

use crate::error::{Result, StateError};
use crate::fsio;
use crate::limits::MAX_IMPORT_BYTES;
use crate::merge::apply_overrides;
use crate::overrides::Overrides;
use soc_core::Config;
use soc_core::emit::to_yaml;
use soc_core::load::load_str;
use std::path::{Path, Path as StdPath, PathBuf};

/// The effective config as shareable YAML: the base merged with `overrides`.
/// Secret-free (vault-item names only), and it round-trips through the loader.
pub fn export_yaml(base: &Config, overrides: &Overrides) -> String {
    to_yaml(&apply_overrides(base, overrides).config)
}

/// A timestamped export file name, e.g. `soc-wall-export-20260114-230000.yaml`.
/// `stamp` is a caller-supplied `YYYYmmdd-HHMMSS` string (the crate never
/// reads the clock itself).
pub fn export_filename(stamp: &str) -> String {
    format!("soc-wall-export-{stamp}.yaml")
}

/// Write the effective config to `dir/soc-wall-export-<stamp>.yaml` (0600,
/// never overwriting an existing file). Returns the path written.
pub fn export_to_dir(base: &Config, overrides: &Overrides, dir: &Path, stamp: &str) -> Result<PathBuf> {
    let path = dir.join(export_filename(stamp));
    fsio::write_exclusive(&path, export_yaml(base, overrides).as_bytes())?;
    Ok(path)
}

/// Read and validate a config the operator picked. The file must be a regular
/// file of at most [`MAX_IMPORT_BYTES`]; its contents go through the full
/// config loader, so a malformed or hostile file is rejected with every
/// problem listed, exactly as a boot-time config would be.
pub fn import_config(path: &Path) -> Result<Config> {
    let bytes = fsio::read_user_file(path, MAX_IMPORT_BYTES)?;
    let utf8 = std::str::from_utf8(&bytes).ok(); // audit-allow: fixed reason text; the Utf8Error offset adds nothing
    let text =
        utf8.ok_or_else(|| StateError::Corrupt { path: path.to_path_buf(), reason: "not valid UTF-8".into() })?;
    let source = file_label(path);
    load_str(text, &source).map_err(|e| StateError::Corrupt { path: path.to_path_buf(), reason: e.to_string() })
}

/// The short name used in validation messages (the file's base name).
fn file_label(path: &StdPath) -> String {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("import").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn base() -> Config {
        load_str(
            "display: {cols: 2, rows: 2}\npanels:\n  - id: p1\n    url: http://10.0.0.1/\n    title: One\n",
            "<base>",
        )
        .unwrap()
    }

    fn overrides(dict: serde_json::Value) -> Overrides {
        Overrides::from_dict(dict.as_object().cloned().unwrap())
    }

    #[test]
    fn export_reflects_the_overrides_and_reloads() {
        // An override repoints p1 and renames it; export must show the merged
        // result, and the result must itself be a loadable config.
        let ov = overrides(json!({"p1": {"url": "https://dash.example/x", "title": "Renamed"}}));
        let yaml = export_yaml(&base(), &ov);
        assert!(yaml.contains("https://dash.example/x"), "{yaml}");
        assert!(yaml.contains("Renamed"), "{yaml}");
        let reloaded = load_str(&yaml, "<reload>").expect("export must reload");
        let p1 = reloaded.panel("p1").unwrap();
        assert_eq!(p1.effective_url(), "https://dash.example/x");
        assert_eq!(p1.title, "Renamed");
    }

    #[test]
    fn export_is_written_0600_and_never_overwrites() {
        let dir = TempDir::new();
        let path = export_to_dir(&base(), &Overrides::new(), dir.path(), "20260114-230000").unwrap();
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "soc-wall-export-20260114-230000.yaml");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // A second export to the same stamp refuses rather than clobbering.
        assert!(export_to_dir(&base(), &Overrides::new(), dir.path(), "20260114-230000").is_err());
    }

    #[test]
    fn import_validates_through_the_loader() {
        let dir = TempDir::new();
        let good = dir.path().join("good.yaml");
        std::fs::write(&good, "panels:\n  - id: a\n    url: http://h/\n").unwrap();
        assert_eq!(import_config(&good).unwrap().panels.len(), 1);

        // A config the loader rejects surfaces as Corrupt, with the reason.
        let bad = dir.path().join("bad.yaml");
        std::fs::write(&bad, "panels:\n  - id: a\n    url: ftp://nope\n").unwrap();
        match import_config(&bad) {
            Err(StateError::Corrupt { reason, .. }) => assert!(reason.contains("url must be")),
            other => panic!("expected a Corrupt error, got {other:?}"),
        }
    }

    #[test]
    fn import_refuses_oversize_and_irregular_files() {
        let dir = TempDir::new();
        let big = dir.path().join("big.yaml");
        std::fs::write(&big, vec![b' '; (MAX_IMPORT_BYTES + 1) as usize]).unwrap();
        assert!(matches!(import_config(&big), Err(StateError::TooLarge { .. })));
        assert!(matches!(import_config(dir.path()), Err(StateError::NotRegular { .. })));
        assert!(import_config(&dir.path().join("missing.yaml")).is_err());
    }
}
