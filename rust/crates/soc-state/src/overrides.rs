//! `overrides.json` — the durable record of edits made at the glass.
//!
//! ```json
//! { "<panel id>": {"url": "...", "title": "...", ...},
//!   "_display": {...}, "_vpns": [...], "_vpns_removed": [...], "_vpn": {...},
//!   "_proxy": {...}, "_tunnel": {...},
//!   "_added_panels": [{"id": "...", "grid": [c, r]}], "_removed_panels": [...] }
//! ```
//!
//! The file is written the way the Python wall wrote it (sorted keys, two-space
//! indent, ASCII-only escapes) so either implementation reads the other's.
//! Nothing in it is trusted: [`crate::merge`] validates every value on the way
//! back in.

use crate::error::{Result, StateError};
use crate::fsio;
use crate::limits::MAX_OVERRIDES_BYTES;
use crate::sanitize;
use serde_json::Value;
use soc_core::Dict;
use std::path::{Path, PathBuf};

pub const KEY_DISPLAY: &str = "_display";
pub const KEY_VPN: &str = "_vpn";
pub const KEY_VPNS: &str = "_vpns";
pub const KEY_VPNS_REMOVED: &str = "_vpns_removed";
pub const KEY_PROXY: &str = "_proxy";
pub const KEY_TUNNEL: &str = "_tunnel";
pub const KEY_ADDED_PANELS: &str = "_added_panels";
pub const KEY_REMOVED_PANELS: &str = "_removed_panels";

/// Section keys. A panel may not use one as its id: the Python merge looked
/// panels up by id without this check, so a panel named `_vpn` would have
/// been handed the VPN's vault item as its own login.
pub const RESERVED_KEYS: [&str; 8] =
    [KEY_DISPLAY, KEY_VPN, KEY_VPNS, KEY_VPNS_REMOVED, KEY_PROXY, KEY_TUNNEL, KEY_ADDED_PANELS, KEY_REMOVED_PANELS];

pub fn is_reserved(key: &str) -> bool {
    RESERVED_KEYS.contains(&key)
}

/// Where the overrides live under a state directory.
pub fn overrides_path(state_dir: &Path) -> PathBuf {
    state_dir.join("overrides.json")
}

fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            Value::Object(keys.into_iter().map(|k| (k.clone(), sort_keys(&map[k]))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

/// Escape everything outside printable ASCII as `\uXXXX`, as Python's `json`
/// does. Only string contents can hold such characters in serialised JSON, so
/// this is safe on the whole text.
fn ascii_only(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    let mut units = [0u16; 2];
    for c in json.chars() {
        if c.is_ascii() && c != '\x7f' {
            out.push(c);
        } else {
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// The saved settings. A thin wrapper over the raw document: reading a value
/// out of it proves nothing about that value.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Overrides(Dict);

/// `Overrides::parse` keeps its published `Err(String)`: the reason text.
type ParseResult = std::result::Result<Overrides, String>; // audit-allow: public API; the String is the reason text for StateError::Corrupt

impl Overrides {
    pub fn new() -> Overrides {
        Overrides::default()
    }

    pub fn from_dict(dict: Dict) -> Overrides {
        Overrides(dict)
    }

    /// Parse the file's text. The top level must be an object.
    pub fn parse(text: &str) -> ParseResult {
        match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(dict)) => Ok(Overrides(dict)),
            Ok(_) => Err("top level is not an object".to_string()),
            Err(e) => Err(format!("not valid JSON: {e}")),
        }
    }

    pub fn as_dict(&self) -> &Dict {
        &self.0
    }

    pub fn as_dict_mut(&mut self) -> &mut Dict {
        &mut self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// The saved fields of one panel. Section keys are never panels.
    pub fn panel(&self, id: &str) -> Option<&Dict> {
        if is_reserved(id) {
            return None;
        }
        self.0.get(id).and_then(Value::as_object)
    }

    /// A mutable entry for one panel, created (or replaced, if it is not an
    /// object) as needed.
    pub fn panel_entry(&mut self, id: &str) -> Result<&mut Dict> {
        if is_reserved(id) || !sanitize::is_panel_id(id) {
            return Err(StateError::InvalidInput(format!("{id:?} is not a usable panel id")));
        }
        let slot = self.0.entry(id.to_string()).or_insert_with(|| Value::Object(Dict::new()));
        if !slot.is_object() {
            *slot = Value::Object(Dict::new());
        }
        match slot {
            Value::Object(dict) => Ok(dict),
            _ => Err(StateError::InvalidInput(format!("{id:?}: entry is not an object"))),
        }
    }

    /// Load the overrides under `state_dir`. A missing file is an empty set.
    /// A file that cannot be read or parsed is an error — the Python wall
    /// treated it as empty and the next Apply then overwrote it, losing every
    /// saved setting.
    pub fn load(state_dir: &Path) -> Result<Overrides> {
        let path = overrides_path(state_dir);
        let Some(bytes) = fsio::read_capped(&path, MAX_OVERRIDES_BYTES)? else {
            return Ok(Overrides::default());
        };
        let corrupt = |reason: String| StateError::Corrupt { path: path.clone(), reason };
        let text = std::str::from_utf8(&bytes).map_err(|_| corrupt("not UTF-8".to_string()))?; // audit-allow: fixed reason text; the Utf8Error offset adds nothing
        Overrides::parse(text).map_err(corrupt)
    }

    /// The file's exact bytes: sorted keys, two-space indent, ASCII only.
    pub fn to_json(&self) -> String {
        let sorted = sort_keys(&Value::Object(self.0.clone()));
        // Serialising plain maps, lists and scalars cannot fail.
        ascii_only(&serde_json::to_string_pretty(&sorted).unwrap_or_else(|_| "{}".to_string()))
    }

    /// Write the overrides under `state_dir` (0600, atomic, fsynced).
    pub fn save(&self, state_dir: &Path) -> Result<()> {
        let path = overrides_path(state_dir);
        let json = self.to_json();
        if !u64::try_from(json.len()).is_ok_and(|n| n <= MAX_OVERRIDES_BYTES) {
            return Err(StateError::TooLarge { path, limit: MAX_OVERRIDES_BYTES });
        }
        fsio::write_atomic(&path, json.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn ov(v: Value) -> Overrides {
        Overrides::from_dict(v.as_object().cloned().unwrap())
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = TempDir::new();
        assert!(Overrides::load(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn save_then_load_roundtrips_owner_only() {
        let dir = TempDir::new();
        let state = dir.path().join("state");
        let o = ov(json!({"p1": {"url": "http://a.test/", "title": "Ops ✓"}, "_display": {"gap": 4}}));
        o.save(&state).unwrap();
        let path = overrides_path(&state);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(Overrides::load(&state).unwrap(), o);
        assert_eq!(o.len(), 2);
    }

    #[test]
    fn output_is_sorted_indented_and_ascii() {
        let o = ov(json!({"b": {"z": 1, "a": [{"y": 1, "x": "é😀"}]}, "a": {}, "c": []}));
        assert_eq!(
            o.to_json(),
            "{\n  \"a\": {},\n  \"b\": {\n    \"a\": [\n      {\n        \"x\": \"\\u00e9\\ud83d\\ude00\",\n        \
             \"y\": 1\n      }\n    ],\n    \"z\": 1\n  },\n  \"c\": []\n}"
        );
        assert_eq!(Overrides::parse(&o.to_json()).unwrap(), o);
    }

    #[test]
    fn corrupt_files_are_reported_not_swallowed() {
        let dir = TempDir::new();
        let path = overrides_path(dir.path());
        for bad in ["{not json", "[1, 2]", "\"x\"", ""] {
            std::fs::write(&path, bad).unwrap();
            assert!(matches!(Overrides::load(dir.path()), Err(StateError::Corrupt { .. })), "{bad:?}");
        }
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(matches!(Overrides::load(dir.path()), Err(StateError::Corrupt { .. })));
    }

    #[test]
    fn oversized_and_irregular_files_are_refused() {
        let dir = TempDir::new();
        let path = overrides_path(dir.path());
        std::fs::write(&path, vec![b' '; MAX_OVERRIDES_BYTES as usize + 1]).unwrap();
        assert!(matches!(Overrides::load(dir.path()), Err(StateError::TooLarge { .. })));
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere.json"), &path).unwrap();
        assert!(matches!(Overrides::load(dir.path()), Err(StateError::NotRegular { .. })));
    }

    #[test]
    fn section_keys_are_never_panels() {
        let mut o = ov(json!({"_vpn": {"vault_item": "vpn-creds"}, "p1": {"url": ""}, "p2": "junk"}));
        assert!(o.panel("_vpn").is_none());
        assert!(o.panel("p1").is_some());
        assert!(o.panel("p2").is_none());
        assert!(o.panel_entry("_vpn").is_err());
        assert!(o.panel_entry("bad id").is_err());
        o.panel_entry("p2").unwrap().insert("title".into(), json!("t"));
        assert_eq!(o.get("p2"), Some(&json!({"title": "t"})));
        assert!(is_reserved("_removed_panels") && !is_reserved("_custom"));
    }
}
