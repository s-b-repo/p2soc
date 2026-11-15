//! PIN / password complexity policy.
//!
//! The same [`check`] runs when a PIN is changed (a weak one is rejected
//! before it is saved) and when the PIN gate is used (a saved PIN that no
//! longer meets the policy is flagged for rotation).
//!
//! Defaults, chosen for an operator at a public-facing kiosk:
//!
//! - `pin` — digits only, at least 4 (easy to type on a touchscreen);
//! - `password` — at least 12 characters from 3 of {upper, lower, digit,
//!   symbol}.
//!
//! Both are configurable through `policy.json` in the state directory:
//!
//! ```json
//! { "pin": {"min_len": 6}, "password": {"min_len": 16, "classes": 4} }
//! ```
//!
//! A missing, unreadable or malformed file falls back to the defaults, and a
//! malformed key is ignored on its own — the policy file can never crash the
//! PIN gate or silently weaken it through a type confusion.

use crate::fsutil::read_capped;
use serde_json::Value;
use soc_core::dict::as_int;
use std::path::Path;

/// The outcome of a policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    pub ok: bool,
    /// Human-readable reasons, in a stable order.
    pub issues: Vec<String>,
    /// Character classes present (0..=4).
    pub score: u32,
}

impl PolicyResult {
    pub fn summary(&self) -> String {
        if self.ok { "ok".to_string() } else { self.issues.join("; ") }
    }
}

/// What kind of secret is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Pin,
    Password,
}

/// The rules for one kind of secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub min_len: usize,
    /// How many character classes must be present (ignored when
    /// `numeric_only`).
    pub classes: u32,
    pub numeric_only: bool,
}

/// The policy for both kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub pin: Rule,
    pub password: Rule,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            pin: Rule { min_len: 4, classes: 1, numeric_only: true },
            password: Rule { min_len: 12, classes: 3, numeric_only: false },
        }
    }
}

/// A secret longer than this is a paste accident; the policy cannot ask for it.
const MAX_MIN_LEN: i64 = 1024;

fn apply(rule: &mut Rule, block: Option<&Value>) {
    let Some(block) = block.and_then(Value::as_object) else {
        return;
    };
    // Strict integers only: JSON `true` is not a length of one.
    if let Some(n) = block
        .get("min_len")
        .and_then(as_int)
        .filter(|n| (1..=MAX_MIN_LEN).contains(n))
        .and_then(|n| usize::try_from(n).ok())
    {
        rule.min_len = n;
    }
    if let Some(n) =
        block.get("classes").and_then(as_int).filter(|n| (0..=4).contains(n)).and_then(|n| u32::try_from(n).ok())
    {
        rule.classes = n;
    }
    if let Some(b) = block.get("numeric_only").and_then(Value::as_bool) {
        rule.numeric_only = b;
    }
}

impl Policy {
    /// The policy described by `policy.json` text; defaults for anything
    /// missing or malformed.
    pub fn parse(text: &str) -> Policy {
        let mut policy = Policy::default();
        // Malformed JSON becomes `Null`, which has no blocks: the defaults stand.
        let doc = serde_json::from_str::<Value>(text).unwrap_or(Value::Null);
        apply(&mut policy.pin, doc.get("pin"));
        apply(&mut policy.password, doc.get("password"));
        policy
    }

    /// Load `policy.json` from `path`; the defaults on any error.
    pub fn load(path: &Path) -> Policy {
        read_capped(path, 64 * 1024).map(|text| Policy::parse(&text)).unwrap_or_default() // audit-allow: default is the intended fallback (default policy)
    }

    pub fn rule(&self, kind: SecretKind) -> Rule {
        match kind {
            SecretKind::Pin => self.pin,
            SecretKind::Password => self.password,
        }
    }

    /// Validate `secret` against the rule for `kind`.
    pub fn check(&self, secret: &str, kind: SecretKind) -> PolicyResult {
        check(secret, &self.rule(kind))
    }
}

fn is_control(c: char) -> bool {
    u32::from(c) < 0x20 || u32::from(c) == 0x7f
}

/// The top breached PINs/passwords plus the wall's own obvious words. Not
/// comprehensive — just enough to catch the absolutely-don't-use defaults
/// without shipping a multi-megabyte word list.
const COMMON_BAD: [&str; 31] = [
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome1",
    "abc123",
    "iloveyou",
    "monkey",
    "dragon",
    "111111",
    "123123",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "1234",
    "12345",
    "0000",
    "1111",
    "2222",
    "9999",
    "soc",
    "kiosk",
    "wall",
    "default",
];

/// Validate `secret` against an explicit rule.
pub fn check(secret: &str, rule: &Rule) -> PolicyResult {
    let has = |pred: fn(char) -> bool| u32::from(secret.chars().any(pred));
    let score = has(char::is_lowercase)
        + has(char::is_uppercase)
        + has(char::is_numeric)
        + has(|c| !c.is_alphanumeric() && !c.is_whitespace());
    let len = secret.chars().count();

    let mut issues = Vec::new();
    if secret.is_empty() {
        issues.push("must not be empty".to_string());
    }
    if len < rule.min_len {
        issues.push(format!("must be at least {} characters (got {len})", rule.min_len));
    }
    // ASCII digits: a PIN has to be typeable on the on-screen keypad.
    if rule.numeric_only && (secret.is_empty() || !secret.bytes().all(|b| b.is_ascii_digit())) {
        issues.push("must contain digits only (e.g. 1234)".to_string());
    }
    if !rule.numeric_only && score < rule.classes {
        issues.push(format!("must include at least {} of: digit / lower / symbol / upper (got {score})", rule.classes));
    }
    if secret.contains(' ') {
        issues.push("spaces are not allowed".to_string());
    }
    if secret.chars().any(is_control) {
        issues.push("control characters are not allowed".to_string());
    }
    if COMMON_BAD.contains(&secret.to_lowercase().as_str()) {
        issues.push("looks like a common/leaked password — choose another".to_string());
    }
    PolicyResult { ok: issues.is_empty(), issues, score }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn run(secret: &str, kind: SecretKind) -> PolicyResult {
        Policy::default().check(secret, kind)
    }

    /// Expectations generated with the Python `host.complexity.check`.
    #[test]
    fn matches_the_reference_implementation() {
        use SecretKind::{Password, Pin};
        let common = "looks like a common/leaked password — choose another";
        let classes = "must include at least 3 of: digit / lower / symbol / upper (got 1)";
        let digits = "must contain digits only (e.g. 1234)";
        let cases: [(&str, SecretKind, u32, &[&str]); 12] = [
            ("1234", Pin, 1, &[common]),
            ("482917", Pin, 1, &[]),
            ("12a4", Pin, 2, &[digits]),
            ("", Pin, 0, &["must not be empty", "must be at least 4 characters (got 0)", digits]),
            ("Tr0ub4dor&3x!", Password, 4, &[]),
            ("password", Password, 1, &["must be at least 12 characters (got 8)", classes, common]),
            ("abcdefghijkl", Password, 1, &[classes]),
            ("Abcdefghijk1", Password, 3, &[]),
            ("has space 12A!", Password, 4, &["spaces are not allowed"]),
            ("a\tbcdefgh1A!x", Password, 4, &["control characters are not allowed"]),
            ("123", Pin, 1, &["must be at least 4 characters (got 3)"]),
            ("9999", Pin, 1, &[common]),
        ];
        for (secret, kind, score, issues) in cases {
            let r = run(secret, kind);
            assert_eq!(r.score, score, "{secret:?}");
            assert_eq!(r.issues, issues, "{secret:?}");
            assert_eq!(r.ok, issues.is_empty(), "{secret:?}");
        }
    }

    #[test]
    fn summary_joins_the_issues() {
        assert_eq!(run("482917", SecretKind::Pin).summary(), "ok");
        assert_eq!(run("123", SecretKind::Pin).summary(), "must be at least 4 characters (got 3)");
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        let r = check("ééééééééééA1", &Policy::default().password);
        assert!(r.ok, "{:?}", r.issues);
    }

    #[test]
    fn a_pin_must_be_ascii_digits() {
        let r = run("١٢٣٤٥٦", SecretKind::Pin);
        assert!(!r.ok);
    }

    #[test]
    fn common_secrets_are_caught_case_insensitively() {
        assert!(!check("LetMeIn", &Rule { min_len: 1, classes: 0, numeric_only: false }).ok);
    }

    #[test]
    fn policy_file_overrides_are_validated_key_by_key() {
        let p = Policy::parse(r#"{"pin": {"min_len": 6, "classes": 9}, "password": {"min_len": 16, "classes": 4}}"#);
        assert_eq!(p.pin, Rule { min_len: 6, classes: 1, numeric_only: true });
        assert_eq!(p.password, Rule { min_len: 16, classes: 4, numeric_only: false });
        assert!(!p.check("48291", SecretKind::Pin).ok);
        assert!(p.check("482917", SecretKind::Pin).ok);
    }

    #[test]
    fn a_boolean_is_not_a_length() {
        // JSON `true` must not shrink the minimum length to one character.
        let p = Policy::parse(r#"{"pin": {"min_len": true, "classes": false, "numeric_only": 0}}"#);
        assert_eq!(p, Policy::default());
        let p = Policy::parse(r#"{"pin": {"min_len": 0}, "password": {"min_len": -3, "classes": 2.5}}"#);
        assert_eq!(p, Policy::default());
    }

    #[test]
    fn a_malformed_policy_file_falls_back_to_the_defaults() {
        for body in ["", "{not json", "[1, 2]", "null", "\"text\"", r#"{"pin": [1]}"#] {
            assert_eq!(Policy::parse(body), Policy::default(), "{body:?}");
        }
        let t = TempDir::new("complexity");
        assert_eq!(Policy::load(&t.path().join("missing.json")), Policy::default());
        let f = t.write("policy.json", r#"{"password": {"min_len": 20}}"#);
        assert_eq!(Policy::load(&f).password.min_len, 20);
    }
}
