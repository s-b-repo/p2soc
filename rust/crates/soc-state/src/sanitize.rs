//! Field-level checks shared by the boot merge (untrusted `overrides.json`)
//! and the settings form.

use serde_json::Value;
use soc_core::dict::as_int;
use soc_core::guard::has_ctrl;
use soc_core::load::{Overrides as LoadOverrides, from_value};
use soc_core::{Config, Dict, DisplayCfg};

/// A trimmed, single-line string of at most `max` characters; anything else
/// (wrong type, control characters, over-long) is `None`.
pub(crate) fn clean_str(v: &Value, max: usize) -> Option<String> {
    let s = v.as_str()?.trim();
    (!has_ctrl(s) && s.chars().count() <= max).then(|| s.to_string())
}

/// [`clean_str`], with JSON `null` read as the empty string (the form's
/// "cleared" marker).
pub(crate) fn clean_str_or_null(v: &Value, max: usize) -> Option<String> {
    if v.is_null() { Some(String::new()) } else { clean_str(v, max) }
}

/// `[col, row]` as non-negative integers (never bools or floats).
pub(crate) fn grid_cell(v: &Value) -> Option<(u32, u32)> {
    match v.as_array()?.as_slice() {
        [c, r] => Some((u32::try_from(as_int(c)?).ok()?, u32::try_from(as_int(r)?).ok()?)),
        _ => None,
    }
}

pub(crate) fn in_grid(display: &DisplayCfg, cell: (u32, u32)) -> bool {
    cell.0 < display.cols && cell.1 < display.rows
}

/// The id shape the loader accepts (`[A-Za-z0-9_-]+`).
pub(crate) fn is_panel_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

const ZONE_NAMES: [&str; 3] = ["user", "pass", "submit"];
const ZONE_AXES: [&str; 2] = ["x_pct", "y_pct"];

/// Calibrated click zones, re-checked to the loader's rules: only the
/// `user`/`pass`/`submit` entries, each exactly `{x_pct, y_pct}` with both
/// ratios in `0.0..=1.0`. Returns the cleaned mapping, or `None` if any part
/// is wrong (zones are all-or-nothing: half a calibration clicks the wrong
/// place).
pub(crate) fn login_zones(v: &Value) -> Option<Dict> {
    let mut out = Dict::new();
    for (name, zone) in v.as_object()? {
        if !ZONE_NAMES.contains(&name.as_str()) {
            return None;
        }
        let zone = zone.as_object()?;
        let mut clean = Dict::new();
        for axis in ZONE_AXES {
            let ratio = zone.get(axis)?;
            if !ratio.as_f64().is_some_and(|x| ratio.is_number() && (0.0..=1.0).contains(&x)) {
                return None;
            }
            clean.insert(axis.to_string(), ratio.clone());
        }
        out.insert(name.clone(), Value::Object(clean));
    }
    Some(out)
}

/// Every problem the config loader finds in `doc` (empty: it validates).
pub(crate) fn loader_problems(doc: &Value) -> Vec<String> {
    match from_value(doc, "settings", &LoadOverrides::default()) {
        Ok(_) => Vec::new(),
        Err(e) if e.problems.is_empty() => vec![e.message],
        Err(e) => e.problems,
    }
}

/// Whether `conf` would survive being written out and loaded again — the
/// test every merged or edited config has to pass before it is used.
pub(crate) fn config_problems(conf: &Config) -> Vec<String> {
    loader_problems(&soc_core::emit::to_value(conf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strings_are_trimmed_bounded_and_single_line() {
        assert_eq!(clean_str(&json!("  ok "), 5).as_deref(), Some("ok"));
        assert_eq!(clean_str(&json!(""), 5).as_deref(), Some(""));
        assert_eq!(clean_str(&json!("toolong"), 5), None);
        assert_eq!(clean_str(&json!("a\nb"), 5), None);
        assert_eq!(clean_str(&json!(7), 5), None);
        assert_eq!(clean_str(&json!(null), 5), None);
        assert_eq!(clean_str_or_null(&json!(null), 5).as_deref(), Some(""));
    }

    #[test]
    fn grid_cells_refuse_bools_floats_and_negatives() {
        assert_eq!(grid_cell(&json!([1, 2])), Some((1, 2)));
        for bad in [json!([1]), json!([1, 2, 3]), json!([true, 0]), json!([1.0, 0]), json!([-1, 0]), json!("1,2")] {
            assert_eq!(grid_cell(&bad), None, "{bad}");
        }
    }

    #[test]
    fn panel_ids() {
        assert!(is_panel_id("panel-3") && is_panel_id("_x"));
        for bad in ["", "bad id", "a/b", "é", &"x".repeat(65)] {
            assert!(!is_panel_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn zones_follow_the_loader() {
        let ok = json!({"user": {"x_pct": 0.5, "y_pct": 0, "extra": 1}});
        assert_eq!(Value::Object(login_zones(&ok).unwrap()), json!({"user": {"x_pct": 0.5, "y_pct": 0}}));
        assert_eq!(login_zones(&json!({})).unwrap().len(), 0);
        for bad in [
            json!({"user": {"x_pct": 2, "y_pct": 0}}),
            json!({"nope": {"x_pct": 0, "y_pct": 0}}),
            json!({"user": {"x_pct": 0.1}}),
            json!({"user": {"x_pct": true, "y_pct": 0}}),
            json!({"user": {"x_pct": "0.1", "y_pct": 0}}),
            json!("x"),
        ] {
            assert!(login_zones(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn loader_probe_reports_each_problem() {
        assert!(loader_problems(&json!({})).is_empty());
        let problems = loader_problems(&json!({"proxy": {"enabled": true, "url": "http://u:p@h:1"}}));
        assert!(problems.iter().any(|p| p.contains("credentials")), "{problems:?}");
        assert_eq!(loader_problems(&json!([])).len(), 1);
    }
}
