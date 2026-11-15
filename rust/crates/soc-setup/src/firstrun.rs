//! The first-run flow as a plan of typed steps: seal (or store) the vault
//! master, wire the client, scrub any plaintext, and surface the one-time PIN.
//! Inputs are arguments — there is no prompting; a CLI or GUI collects them and
//! drives [`FirstRunPlan::steps`] / [`FirstRunPlan::run_step`].

use crate::doctor::is_real_vault;
use crate::envfile::SocEnv;
use crate::host::Host;
use crate::paths::SetupPaths;
use crate::seal::DEFAULT_SECRET_DIR;
use crate::seal::{SealRequest, effective_source, pin_banner, seal_housekeeping, seal_master};
use crate::step::StepResult;
use soc_seal::MasterSource;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// One step of the first-run flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstRunStep {
    /// Decide whether anything needs doing (a dev backend needs no seal).
    Preflight,
    /// Seal host-bound / store in the wallet / record the `env` source.
    Seal,
    /// Keep an existing seal; re-run only the client wiring + plaintext scrub.
    KeepExisting,
    /// Surface the one-time PIN (sealed path only).
    ShowPin,
}

impl FirstRunStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            FirstRunStep::Preflight => "preflight",
            FirstRunStep::Seal => "seal",
            FirstRunStep::KeepExisting => "keep-existing",
            FirstRunStep::ShowPin => "show-pin",
        }
    }
}

/// Mutable state carried between steps.
#[derive(Default)]
pub struct FirstRunState {
    /// The one-time PIN, once a seal produced (or previewed) it.
    pub pin: Option<Zeroizing<String>>,
    /// Set by a step that ended the flow early (nothing more to do).
    pub finished: bool,
}

/// What a whole run produced.
#[derive(Default)]
pub struct FirstRunOutcome {
    pub ok: bool,
    pub pin: Option<Zeroizing<String>>,
    pub results: Vec<(FirstRunStep, StepResult)>,
}

impl FirstRunOutcome {
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.ok)
    }
}

/// Inputs of the first-run flow.
pub struct FirstRunPlan {
    pub paths: SetupPaths,
    /// The current `soc.env`.
    pub soc_env: SocEnv,
    pub backend: String,
    pub source: MasterSource,
    /// The master to seal. `None` uses a plaintext `SOC_VAULT_PASSWORD` found
    /// in `soc.env` (sealed path) — otherwise the seal step fails.
    pub master: Option<Zeroizing<String>>,
    /// The PIN to seal under; `None` generates one.
    pub pin: Option<String>,
    /// Replace an existing seal (issues a new PIN).
    pub reseal: bool,
    pub dry_run: bool,
}

impl FirstRunPlan {
    fn plaintext(&self) -> Option<&String> {
        self.soc_env.get("SOC_VAULT_PASSWORD").filter(|v| !v.is_empty())
    }

    fn secret_dir(&self) -> PathBuf {
        self.soc_env
            .get("SOC_SECRET_DIR")
            .filter(|v| !v.is_empty())
            .map_or_else(|| self.paths.secret_dir.clone(), PathBuf::from)
    }

    /// A dev backend needs no seal — unless a plaintext master is still in
    /// `soc.env`, which is sealed and scrubbed regardless of backend.
    fn nothing_to_do(&self) -> bool {
        !is_real_vault(&self.backend) && self.plaintext().is_none()
    }

    /// The steps that apply, in order.
    pub fn steps(&self, host: &Host<'_>) -> Vec<FirstRunStep> {
        let mut steps = vec![FirstRunStep::Preflight];
        if self.nothing_to_do() {
            return steps;
        }
        if effective_source(self.source) != MasterSource::Sealed {
            steps.push(FirstRunStep::Seal);
        } else if host.seal.is_sealed(&self.secret_dir()) && !self.reseal {
            steps.push(FirstRunStep::KeepExisting);
        } else {
            steps.push(FirstRunStep::Seal);
            steps.push(FirstRunStep::ShowPin);
        }
        steps
    }

    /// Run one step.
    pub fn run_step(&self, step: FirstRunStep, host: &Host<'_>, st: &mut FirstRunState) -> StepResult {
        match step {
            FirstRunStep::Preflight => {
                if self.nothing_to_do() {
                    st.finished = true;
                    return StepResult::ok("vault backend is 'dev' — no sealing needed (dev reads the JSON vault).");
                }
                StepResult::ok(format!("master-password source: {}", self.source))
            }
            FirstRunStep::Seal => self.seal(host, st),
            FirstRunStep::KeepExisting => {
                let mut actions = Vec::new();
                let sd = self.secret_dir();
                if !self.dry_run {
                    if let Err(e) = seal_housekeeping(
                        host,
                        &sd,
                        &self.source.to_string(),
                        &self.paths,
                        &self.soc_env,
                        &self.backend,
                        &mut actions,
                    ) {
                        return StepResult::failed(e.to_string());
                    }
                }
                let mut r = StepResult::ok("kept the existing sealed secret.");
                r.lines = actions;
                r
            }
            FirstRunStep::ShowPin => match &st.pin {
                Some(pin) => {
                    let mut r = StepResult::ok("one-time PIN");
                    r.lines = pin_banner(pin);
                    r
                }
                None => StepResult::failed("no PIN to show"),
            },
        }
    }

    fn seal(&self, host: &Host<'_>, st: &mut FirstRunState) -> StepResult {
        let eff = effective_source(self.source);
        // On the sealed path a plaintext master found in soc.env is sealed, then scrubbed.
        let master: Zeroizing<String> = match (&self.master, eff) {
            (Some(m), _) => m.clone(),
            (None, MasterSource::Sealed) => self.plaintext().map(|p| Zeroizing::new(p.clone())).unwrap_or_default(), // audit-allow: no plaintext master means an empty one, as before
            (None, _) => Zeroizing::new(String::new()),
        };
        let req = SealRequest {
            master: &master,
            source: self.source,
            pin: self.pin.as_deref(),
            paths: &self.paths,
            soc_env: &self.soc_env,
            backend: &self.backend,
            dry: self.dry_run,
        };
        match seal_master(&req, host) {
            Ok(out) => {
                st.pin = out.pin;
                let what = match eff {
                    MasterSource::Env => "recorded the 'env' source (DEV/seeding only; nothing sealed)",
                    MasterSource::SecretService => "stored + verified the master in the Secret Service wallet",
                    _ => "sealed + verified the master password (host-bound)",
                };
                let mut r = if self.dry_run {
                    StepResult::ok(format!("[dry-run] would: {what}"))
                } else {
                    StepResult::changed(what)
                };
                r.lines = out.actions;
                r
            }
            Err(e) => StepResult::failed(e.to_string()),
        }
    }

    /// Run the whole flow, reporting each step as it finishes. Stops at the
    /// first failure.
    pub fn run(&self, host: &Host<'_>, report: &mut dyn FnMut(FirstRunStep, &StepResult)) -> FirstRunOutcome {
        let mut st = FirstRunState::default();
        let mut out = FirstRunOutcome { ok: true, ..FirstRunOutcome::default() };
        for step in self.steps(host) {
            let r = self.run_step(step, host, &mut st);
            report(step, &r);
            let ok = r.ok;
            out.results.push((step, r));
            if !ok {
                out.ok = false;
                break;
            }
            if st.finished {
                break;
            }
        }
        out.pin = st.pin;
        out
    }
}

/// Where a sealed secret is looked for when `soc.env` names none.
pub fn default_secret_dir() -> PathBuf {
    PathBuf::from(DEFAULT_SECRET_DIR)
}
