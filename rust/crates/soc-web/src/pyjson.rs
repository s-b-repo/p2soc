//! JSON text exactly as Python's `json.dumps` writes it.
//!
//! The login bootstrap is rendered by substituting JSON literals into a shared
//! template, and the result must be byte-identical to what the Python wall
//! renders (the template is the contract with real login pages). `serde_json`
//! differs in three visible ways — separators, non-ASCII escaping and float
//! spelling — so this module reproduces the Python encoder instead.

use serde_json::Value;

/// `json.dumps(v)` with Python's defaults: `", "` / `": "` separators,
/// `ensure_ascii=True`, insertion-ordered keys.
pub fn dumps(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => out.push_str(&i.to_string()),
            (_, Some(u), _) => out.push_str(&u.to_string()),
            (_, _, Some(f)) => out.push_str(&float_repr(f)),
            _ => out.push_str("null"),
        },
        Value::String(s) => write_str(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_str(out, k);
                out.push_str(": ");
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

/// A JSON string literal as Python writes it: everything outside printable
/// ASCII becomes `\uXXXX` (astral characters as a surrogate pair), so the
/// output is pure ASCII and U+2028/U+2029 can never end a JS line.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        write_char(out, c, false);
    }
    out.push('"');
}

/// [`write_str`], additionally spelling `<`, `>` and `&` as `\u00XX`.
///
/// Used for values that are secret or page-facing (credentials, prompt text):
/// the literal then cannot contain `</script>` or `<!--` either, so it stays
/// inert even if the surrounding script is ever inlined into HTML. A JS engine
/// reads both spellings as the same string.
pub fn write_js_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        write_char(out, c, true);
    }
    out.push('"');
}

fn write_char(out: &mut String, c: char, html_safe: bool) {
    match c {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        '<' | '>' | '&' if html_safe => push_u16(out, c as u16), // audit-allow: lossless, c is one of three ASCII chars
        ' '..='~' => out.push(c),
        _ => {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                push_u16(out, *unit);
            }
        }
    }
}

fn push_u16(out: &mut String, unit: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    for shift in [12u16, 8, 4, 0] {
        out.push(char::from(HEX[usize::from((unit >> shift) & 0xf)]));
    }
}

/// Python's `repr(float)`: the shortest digits that round-trip, positional for
/// exponents in `-4..16`, otherwise scientific with a signed two-digit
/// exponent (`1e-05`, `1e+16`), and always a fractional part (`1.0`).
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f < 0.0 { "-Infinity".into() } else { "Infinity".into() };
    }
    let sign = if f.is_sign_negative() { "-" } else { "" };
    if f == 0.0 {
        return format!("{sign}0.0");
    }
    // `{:e}` yields the shortest round-trip digits as `d[.ddd]e[-]x`.
    let sci = format!("{:e}", f.abs());
    let Some((mantissa, exp)) = sci.split_once('e') else {
        return sci;
    };
    let Ok(exp) = exp.parse::<i32>() else {
        return sci;
    };
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let len = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    // Position of the decimal point relative to the start of `digits`.
    let point = exp + 1;
    if point > 16 || point <= -4 {
        let Some((head, tail)) = digits.split_at_checked(1) else {
            return sci;
        };
        let frac = if tail.is_empty() { String::new() } else { format!(".{tail}") };
        let exp_sign = if exp < 0 { '-' } else { '+' };
        format!("{sign}{head}{frac}e{exp_sign}{:02}", exp.abs())
    } else if point <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat(usize::try_from(point.unsigned_abs()).unwrap_or(0)))
    } else if point >= len {
        format!("{sign}{digits}{}.0", "0".repeat(usize::try_from(point - len).unwrap_or(0)))
    } else {
        let Some((int, frac)) = digits.split_at_checked(usize::try_from(point).unwrap_or(0)) else {
            return sci;
        };
        format!("{sign}{int}.{frac}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_match_python_repr() {
        for (f, want) in [
            (0.5, "0.5"),
            (1.0, "1.0"),
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (0.25, "0.25"),
            (0.1 + 0.2, "0.30000000000000004"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (2e-7, "2e-07"),
            (1.5e-7, "1.5e-07"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.2345e22, "1.2345e+22"),
            (123.456, "123.456"),
            (-42.0, "-42.0"),
            (1e100, "1e+100"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
        ] {
            assert_eq!(float_repr(f), want, "{f:?}");
        }
    }

    #[test]
    fn strings_are_ascii_only() {
        let mut out = String::new();
        write_str(&mut out, "a\"b\\c\n\t\u{1}\u{7f}é\u{2028}\u{1f511}</script>");
        assert_eq!(out, r#""a\"b\\c\n\t\u0001\u007f\u00e9\u2028\ud83d\udd11</script>""#);
        assert!(out.is_ascii());
    }

    #[test]
    fn js_strings_cannot_close_a_script_element() {
        let mut out = String::new();
        write_js_str(&mut out, "</script><!-- & \u{2029}");
        assert_eq!(out, r#""\u003c/script\u003e\u003c!-- \u0026 \u2029""#);
        // The two spellings decode to the same text.
        let back: String = serde_json::from_str(&out).unwrap();
        assert_eq!(back, "</script><!-- & \u{2029}");
    }

    #[test]
    fn containers_use_python_separators() {
        let v = json!({"strategy": "xhr", "intervalSec": 300, "n": [1, 2.0, null, true], "e": {}, "l": []});
        assert_eq!(
            dumps(&v),
            r#"{"strategy": "xhr", "intervalSec": 300, "n": [1, 2.0, null, true], "e": {}, "l": []}"#
        );
    }
}
