//! Dynamic config values.
//!
//! The `vpn:` / `tunnel:` sections are kept as ordered JSON maps rather than
//! closed structs: a `config_from_vault` overlay can add keys after load, and
//! the sections must round-trip to YAML byte-stably (key order preserved).
//! These helpers give them the loose "falsy means unset" reading the config
//! format has always had.

use serde_json::Value;

/// An ordered string-keyed map (insertion order preserved).
pub type Dict = serde_json::Map<String, Value>;

/// "Is this value set?" — null, false, 0, "", [] and {} all count as unset.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// The value as display text: strings verbatim, scalars in their YAML spelling.
pub fn text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// The value quoted for an error message (`'text'`, `443`, `true`, `null`).
pub fn repr(v: &Value) -> String {
    match v {
        Value::String(s) => quote(s),
        other => other.to_string(),
    }
}

/// Single-quote a string for an error message, escaping control characters so
/// a hostile value cannot forge extra log lines.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || u32::from(c) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// A strict integer: a JSON integer, never a bool or a float.
pub fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// A boolean. YAML 1.1 spellings (`yes`/`no`/`on`/`off`) that a YAML 1.2
/// parser hands over as strings are accepted too, so configs written for the
/// previous (YAML 1.1) loader keep their meaning.
pub fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "yes" | "on" | "true" => Some(true),
            "no" | "off" | "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Loose accessors over a [`Dict`].
pub trait DictExt {
    /// Trimmed text of `key`; `""` when missing or unset.
    fn text(&self, key: &str) -> String;
    /// Whether `key` holds a set (truthy) value.
    fn truthy(&self, key: &str) -> bool;
    /// `key` as a bool with a default for a missing/non-bool value.
    fn flag(&self, key: &str, default: bool) -> bool;
    /// `key` as an integer; 0 when missing or not a number.
    fn int(&self, key: &str) -> i64;
    /// `key` as a nested map, if it is one.
    fn dict(&self, key: &str) -> Option<&Dict>;
    /// `key` as a list of strings (non-list -> empty; items stringified).
    fn strings(&self, key: &str) -> Vec<String>;
}

impl DictExt for Dict {
    fn text(&self, key: &str) -> String {
        match self.get(key) {
            Some(v) if truthy(v) => text(v).trim().to_string(),
            _ => String::new(),
        }
    }

    fn truthy(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| match as_bool(v) {
            Some(b) => b,
            None => truthy(v),
        })
    }

    fn flag(&self, key: &str, default: bool) -> bool {
        match self.get(key) {
            None | Some(Value::Null) => default,
            Some(v) => as_bool(v).unwrap_or_else(|| truthy(v)),
        }
    }

    fn int(&self, key: &str) -> i64 {
        match self.get(key) {
            Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0), // audit-allow: f64->i64 `as` saturates (NaN->0), the intended Python-int() clamp
            Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
            _ => 0,
        }
    }

    fn dict(&self, key: &str) -> Option<&Dict> {
        self.get(key).and_then(Value::as_object)
    }

    fn strings(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Value::Array(a)) => a.iter().map(text).collect(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn truthiness_matches_the_config_format() {
        for v in [json!(null), json!(false), json!(0), json!(""), json!([]), json!({})] {
            assert!(!truthy(&v), "{v} should be unset");
        }
        for v in [json!(true), json!(1), json!("x"), json!([0]), json!({"a": 1})] {
            assert!(truthy(&v), "{v} should be set");
        }
    }

    #[test]
    fn strict_int_rejects_bool_and_float() {
        assert_eq!(as_int(&json!(443)), Some(443));
        assert_eq!(as_int(&json!(true)), None);
        assert_eq!(as_int(&json!(4.5)), None);
        assert_eq!(as_int(&json!("443")), None);
    }

    #[test]
    fn yaml11_booleans_are_understood() {
        assert_eq!(as_bool(&json!("yes")), Some(true));
        assert_eq!(as_bool(&json!("Off")), Some(false));
        assert_eq!(as_bool(&json!("maybe")), None);
        assert_eq!(as_bool(&json!(1)), None);
    }

    #[test]
    fn quote_escapes_control_characters() {
        assert_eq!(quote("a\nb"), "'a\\nb'");
        assert_eq!(quote("it's"), "'it\\'s'");
        assert_eq!(quote("\u{1b}[0m"), "'\\x1b[0m'");
    }

    #[test]
    fn dict_accessors() {
        let d = json!({"a": " x ", "n": 3, "s": "7", "b": "no", "l": ["p", 2], "z": 0});
        let d = d.as_object().unwrap();
        assert_eq!(d.text("a"), "x");
        assert_eq!(d.text("z"), "");
        assert_eq!(d.text("missing"), "");
        assert_eq!(d.int("n"), 3);
        assert_eq!(d.int("s"), 7);
        assert!(!d.truthy("b"));
        assert!(d.flag("missing", true));
        assert!(!d.flag("b", true));
        assert_eq!(d.strings("l"), vec!["p", "2"]);
    }
}
