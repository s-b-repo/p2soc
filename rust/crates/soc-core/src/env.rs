//! Environment tunables. A typo'd tunable must never crash the wall at boot:
//! every reader warns and falls back to its (safe) default.

use std::str::FromStr;

fn warn(name: &str, raw: &str, kind: &str, default: &dyn std::fmt::Display) {
    eprintln!("[soc-kiosk] {name}={raw:?} is not a valid {kind}; using {default}");
}

fn num<T>(raw: Option<String>, name: &str, default: T, lo: Option<T>, hi: Option<T>) -> T
where
    T: FromStr + PartialOrd + Copy + std::fmt::Display,
{
    let Some(raw) = raw.filter(|r| !r.trim().is_empty()) else {
        return default;
    };
    let Ok(mut v) = raw.trim().parse::<T>() else {
        warn(name, &raw, "number", &default);
        return default;
    };
    if let Some(lo) = lo {
        if v < lo {
            v = lo;
        }
    }
    if let Some(hi) = hi {
        if v > hi {
            v = hi;
        }
    }
    v
}

/// Parse an integer tunable, clamped to `[lo, hi]`.
pub fn parse_int(raw: Option<String>, name: &str, default: i64, lo: Option<i64>, hi: Option<i64>) -> i64 {
    num(raw, name, default, lo, hi)
}

/// Parse a float tunable, clamped to `[lo, hi]`; NaN/inf fall back to default.
pub fn parse_float(raw: Option<String>, name: &str, default: f64, lo: Option<f64>, hi: Option<f64>) -> f64 {
    let v = num(raw.clone(), name, default, lo, hi);
    if v.is_finite() {
        v
    } else {
        warn(name, raw.as_deref().unwrap_or(""), "number", &default);
        default
    }
}

/// Parse a boolean tunable: `1/true/yes/on` and `0/false/no/off`, any case.
pub fn parse_bool(raw: Option<String>, name: &str, default: bool) -> bool {
    let Some(raw) = raw.filter(|r| !r.trim().is_empty()) else {
        return default;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            warn(name, &raw, "boolean", &default);
            default
        }
    }
}

/// `$name` as an integer clamped to `[lo, hi]`; missing/garbage -> `default`.
pub fn env_int(name: &str, default: i64, lo: Option<i64>, hi: Option<i64>) -> i64 {
    parse_int(std::env::var(name).ok(), name, default, lo, hi)
}

/// `$name` as a float clamped to `[lo, hi]`; missing/garbage -> `default`.
pub fn env_float(name: &str, default: f64, lo: Option<f64>, hi: Option<f64>) -> f64 {
    parse_float(std::env::var(name).ok(), name, default, lo, hi)
}

/// `$name` as a bool; missing/garbage -> `default`.
pub fn env_bool(name: &str, default: bool) -> bool {
    parse_bool(std::env::var(name).ok(), name, default)
}

/// `$name` when set and non-empty.
pub fn env_str(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn ints_clamp_and_fall_back() {
        assert_eq!(parse_int(s("7"), "X", 1, Some(0), Some(10)), 7);
        assert_eq!(parse_int(s(" 99 "), "X", 1, Some(0), Some(10)), 10);
        assert_eq!(parse_int(s("-5"), "X", 1, Some(0), Some(10)), 0);
        assert_eq!(parse_int(s("abc"), "X", 1, None, None), 1);
        assert_eq!(parse_int(s(""), "X", 1, None, None), 1);
        assert_eq!(parse_int(None, "X", 1, None, None), 1);
    }

    #[test]
    fn floats_reject_nan() {
        assert_eq!(parse_float(s("2.5"), "X", 1.0, Some(0.0), Some(3.0)), 2.5);
        assert_eq!(parse_float(s("nan"), "X", 1.0, None, None), 1.0);
        assert_eq!(parse_float(s("inf"), "X", 1.0, None, None), 1.0);
    }

    #[test]
    fn bools() {
        assert!(parse_bool(s("YES"), "X", false));
        assert!(!parse_bool(s("off"), "X", true));
        assert!(parse_bool(s("maybe"), "X", true));
        assert!(!parse_bool(None, "X", false));
    }
}
