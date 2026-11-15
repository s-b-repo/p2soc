//! The result type shared by doctor and repair.

use std::fmt::Write as _;

/// How a check ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Status::Ok => "✓",
            Status::Warn => "!",
            Status::Fail => "✗",
        }
    }
}

/// One finished check: what was checked, how it went, what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub name: String,
    pub status: Status,
    pub detail: String,
    /// The suggested fix; empty when OK or when there is none.
    pub fix: String,
}

impl CheckResult {
    pub fn new(name: impl Into<String>, status: Status, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        CheckResult { name: name.into(), status, detail: detail.into(), fix: fix.into() }
    }

    pub fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        CheckResult::new(name, Status::Ok, detail, "")
    }

    pub fn warn(name: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        CheckResult::new(name, Status::Warn, detail, fix)
    }

    pub fn fail(name: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        CheckResult::new(name, Status::Fail, detail, fix)
    }

    /// The two-line text the terminal shows (no colour).
    pub fn line(&self) -> String {
        let mut s = format!("   {} {}: {}", self.status.icon(), self.name, self.detail);
        if !self.fix.is_empty() && self.status != Status::Ok {
            let _ = write!(s, "\n       → {}", self.fix); // audit-allow: writing to a String cannot fail
        }
        s
    }
}

/// An aggregated run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Context lines printed before the checks (target, paths, mismatches).
    pub header: Vec<String>,
    pub results: Vec<CheckResult>,
    /// Advice printed after the checks (e.g. "this box is not fully installed").
    pub notes: Vec<String>,
}

impl Report {
    pub fn push(&mut self, r: CheckResult) {
        self.results.push(r);
    }

    pub fn fails(&self) -> usize {
        self.results.iter().filter(|r| r.status == Status::Fail).count()
    }

    pub fn warns(&self) -> usize {
        self.results.iter().filter(|r| r.status == Status::Warn).count()
    }

    pub fn find(&self, name: &str) -> Option<&CheckResult> {
        self.results.iter().find(|r| r.name == name)
    }

    /// 0 when nothing failed (warnings are fine), 1 otherwise.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.fails() > 0)
    }

    /// The closing line.
    pub fn summary(&self) -> String {
        if self.fails() > 0 {
            format!("   {} problem(s), {} warning(s) — run: {} repair", self.fails(), self.warns(), crate::CLI)
        } else {
            format!("   all good ({} warning(s))", self.warns())
        }
    }

    /// The whole report as terminal text.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for h in &self.header {
            out.push_str(h);
            out.push('\n');
        }
        for r in &self.results {
            out.push_str(&r.line());
            out.push('\n');
        }
        out.push('\n');
        for n in &self.notes {
            out.push_str(n);
            out.push('\n');
        }
        out.push_str(&self.summary());
        out.push('\n');
        out
    }
}
