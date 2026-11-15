//! Stable JSON output: keys sorted at every level and two-space indentation,
//! so the same data always produces the same bytes (diffable state files,
//! reproducible manifests).

use serde_json::Value;

/// A copy of `v` with every object's keys in sorted order.
pub fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(keys.into_iter().map(|k| (k.clone(), sorted(&map[k]))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// `v` pretty-printed with sorted keys (no trailing newline).
pub fn pretty_sorted(v: &Value) -> String {
    // The alternate `Display` of a `Value` is its pretty form, and unlike
    // `to_string_pretty` has no error path to handle.
    format!("{:#}", sorted(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_recursively() {
        let v = json!({"b": 1, "a": {"z": [{"y": 1, "x": 2}], "c": null}});
        assert_eq!(
            pretty_sorted(&v),
            "{\n  \"a\": {\n    \"c\": null,\n    \"z\": [\n      {\n        \"x\": 2,\n        \"y\": 1\n      }\n    ]\n  },\n  \"b\": 1\n}"
        );
    }

    #[test]
    fn empty_containers_stay_compact() {
        assert_eq!(pretty_sorted(&json!({})), "{}");
        assert_eq!(pretty_sorted(&json!({"a": []})), "{\n  \"a\": []\n}");
    }
}
