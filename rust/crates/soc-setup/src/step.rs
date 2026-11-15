//! The outcome of one orchestration step (the Python `ProvResult`).

/// What a step did. `lines` is the human log (what a CLI prints or a GUI
/// shows); `cmds` the exact command lines run — or, in a dry run, that would
/// be run — so previews and tests can assert on them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepResult {
    /// The step's goal is satisfied (or would be, in a dry run).
    pub ok: bool,
    /// Host state was actually changed (false on a no-op re-run and in dry run).
    pub changed: bool,
    pub detail: String,
    pub lines: Vec<String>,
    pub cmds: Vec<Vec<String>>,
}

impl StepResult {
    pub fn ok(detail: impl Into<String>) -> StepResult {
        StepResult { ok: true, detail: detail.into(), ..StepResult::default() }
    }

    pub fn changed(detail: impl Into<String>) -> StepResult {
        StepResult { ok: true, changed: true, detail: detail.into(), ..StepResult::default() }
    }

    pub fn failed(detail: impl Into<String>) -> StepResult {
        StepResult { ok: false, detail: detail.into(), ..StepResult::default() }
    }

    pub fn with_line(mut self, line: impl Into<String>) -> StepResult {
        self.lines.push(line.into());
        self
    }

    pub fn with_cmds(mut self, cmds: Vec<Vec<String>>) -> StepResult {
        self.cmds = cmds;
        self
    }
}
