//! The `litebw` config file: `$XDG_CONFIG_HOME/litebw/config.json` (falling
//! back to `~/.config`). A flat JSON object with `email`, `base_url` and
//! `pinentry`, byte-compatible with what the Python client wrote; unknown keys
//! are preserved on rewrite.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::fsutil::{create_private_dir, write_private_atomic};

/// The keys `litebw config set` accepts (the same names `rbw` uses).
pub const CONFIG_KEYS: [&str; 3] = ["email", "base_url", "pinentry"];

/// The config file's location for the given `$XDG_CONFIG_HOME` / `$HOME`.
pub fn config_path_for(xdg_config_home: Option<&str>, home: Option<&str>) -> PathBuf {
    let base = match xdg_config_home.filter(|v| !v.is_empty()) {
        Some(xdg) => PathBuf::from(xdg),
        None => PathBuf::from(home.filter(|v| !v.is_empty()).unwrap_or("/")).join(".config"),
    };
    base.join("litebw").join("config.json")
}

/// The config file's location for this process.
pub fn default_config_path() -> PathBuf {
    config_path_for(std::env::var("XDG_CONFIG_HOME").ok().as_deref(), std::env::var("HOME").ok().as_deref())
}

/// The parsed config file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LitebwConfig {
    values: Map<String, Value>,
}

impl LitebwConfig {
    /// Load `path`; a missing, unreadable or non-object file is an empty config.
    pub fn load(path: &Path) -> LitebwConfig {
        let values = std::fs::read(path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
            .and_then(|v| match v {
                Value::Object(map) => Some(map),
                _ => None,
            })
            .unwrap_or_default(); // audit-allow: default is the intended fallback (non-object file is an empty config)
        LitebwConfig { values }
    }

    /// A string setting, `""` when absent or not a string.
    pub fn get(&self, key: &str) -> &str {
        self.values.get(key).and_then(Value::as_str).unwrap_or("")
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.values.insert(key.to_string(), Value::String(value.to_string()));
    }

    pub fn email(&self) -> &str {
        self.get("email")
    }

    pub fn base_url(&self) -> &str {
        self.get("base_url")
    }

    pub fn pinentry(&self) -> &str {
        self.get("pinentry")
    }

    /// Write the file (0600, in a 0700 directory), atomically.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        let text = serde_json::to_string_pretty(&Value::Object(self.values.clone())).map_err(std::io::Error::other)?;
        write_private_atomic(path, text.as_bytes())
    }
}

/// An environment value wins over the file; an empty one does not count.
pub fn resolve<'a>(env_value: Option<&'a str>, file_value: &'a str) -> &'a str {
    env_value.filter(|v| !v.is_empty()).unwrap_or(file_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn location_follows_xdg_then_home() {
        assert_eq!(config_path_for(Some("/x"), Some("/h")), PathBuf::from("/x/litebw/config.json"));
        assert_eq!(config_path_for(None, Some("/h")), PathBuf::from("/h/.config/litebw/config.json"));
        assert_eq!(config_path_for(Some(""), Some("/h")), PathBuf::from("/h/.config/litebw/config.json"));
    }

    #[test]
    fn set_persists_private_json() {
        let d = TestDir::new("config");
        let path = config_path_for(d.path().to_str(), None);
        let mut cfg = LitebwConfig::load(&path);
        assert_eq!(cfg.email(), "");
        cfg.set("email", "a@b.com");
        cfg.set("base_url", "https://vault.local");
        cfg.save(&path).unwrap();

        let back = LitebwConfig::load(&path);
        assert_eq!(back.email(), "a@b.com");
        assert_eq!(back.base_url(), "https://vault.local");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn reads_the_file_python_wrote_and_keeps_unknown_keys() {
        let d = TestDir::new("config-py");
        let path = d.path().join("config.json");
        // json.dumps(cfg, indent=2) output, with an escaped non-ASCII value and a foreign key.
        let python = "{\n  \"email\": \"k\\u00efosk@soc.local\",\n  \"base_url\": \"http://127.0.0.1:8222\",\n  \"future\": 7\n}";
        std::fs::write(&path, python).unwrap();
        let mut cfg = LitebwConfig::load(&path);
        assert_eq!(cfg.email(), "kïosk@soc.local");
        assert_eq!(cfg.base_url(), "http://127.0.0.1:8222");
        assert_eq!(cfg.get("future"), "");
        cfg.set("pinentry", "/usr/bin/pinentry");
        cfg.save(&path).unwrap();
        let raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["future"], 7);
        assert_eq!(raw["pinentry"], "/usr/bin/pinentry");
        // Same two-space layout Python's json.dumps(indent=2) produces.
        assert!(std::fs::read_to_string(&path).unwrap().starts_with("{\n  \"email\": "));
    }

    #[test]
    fn garbage_files_load_as_empty() {
        let d = TestDir::new("config-bad");
        let path = d.path().join("config.json");
        for junk in ["", "not json", "[1,2]", "\"str\"", "{\"email\": 5}"] {
            std::fs::write(&path, junk).unwrap();
            assert_eq!(LitebwConfig::load(&path).email(), "");
        }
    }

    #[test]
    fn env_overrides_file_unless_empty() {
        assert_eq!(resolve(Some("env@b.com"), "file@b.com"), "env@b.com");
        assert_eq!(resolve(Some(""), "file@b.com"), "file@b.com");
        assert_eq!(resolve(None, "file@b.com"), "file@b.com");
    }
}
