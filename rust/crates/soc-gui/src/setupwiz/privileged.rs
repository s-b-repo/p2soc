//! Apply a reviewed system configuration through an authenticated desktop
//! prompt. The worker shares the normal setup plan and never starts GTK.

use super::{Msg, RunJob, Stage, VaultForm};
use serde::{Deserialize, Serialize};
use soc_seal::MasterSource;
use soc_setup::deploy::DeployStep;
use soc_setup::paths::{SetupPaths, Target};
use soc_setup::vault::{Creds, LoginCred};
use soc_sys::paths::{ETC_DIR_DEFAULT, PathEnv};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

const PROGRAM: &str = "/opt/soc-display/bin/soc-wall";
const APPLY: &str = "--apply-system";
const REQUEST_LIMIT: u64 = 4 << 20;
type SetupResult<T> = Result<T, String>; // audit-allow: internal GUI messages are displayed verbatim

#[derive(Serialize, Deserialize)]
struct Request {
    config: serde_json::Value,
    backend: String,
    email: String,
    url: String,
    source: String,
    master: Option<Zeroizing<String>>,
    pin: Option<String>,
    create_account: bool,
    reseal: bool,
    creds: BTreeMap<String, (String, Zeroizing<String>)>,
}

impl Request {
    fn from_job(job: &RunJob) -> Request {
        Request {
            config: soc_core::emit::to_value(&job.cfg),
            backend: job.backend.clone(),
            email: job.email.clone(),
            url: job.url.clone(),
            source: job.source.to_string(),
            master: job.master.clone(),
            pin: job.pin.clone(),
            create_account: job.stages.contains(&Stage::Deploy(DeployStep::VaultAccount)),
            reseal: job.reseal,
            creds: job.creds.iter().map(|(k, v)| (k.clone(), (v.username.clone(), v.password.clone()))).collect(),
        }
    }

    fn job(self, penv: PathEnv) -> SetupResult<RunJob> {
        let source = self.source.parse::<MasterSource>().map_err(|e| e.to_string())?;
        if source == MasterSource::SecretService {
            return Err("Select the per-user configuration for a desktop wallet.".into());
        }
        if !super::BACKENDS.contains(&self.backend.as_str()) {
            return Err("Unknown vault backend.".into());
        }
        let cfg = soc_core::load::from_value(&self.config, "system setup", &soc_core::load::Overrides::default())
            .map_err(|e| e.to_string())?;
        let paths = SetupPaths::resolve(Target::Pi, &penv, false);
        if paths.via != "etc"
            || !paths.soc_env.starts_with(ETC_DIR_DEFAULT)
            || !paths.panels_out.starts_with(ETC_DIR_DEFAULT)
        {
            return Err("System configuration requires writable /etc/soc-display paths.".into());
        }
        let master = self.master.unwrap_or_else(|| Zeroizing::new(String::new()));
        let vault = VaultForm {
            target: Target::Pi,
            backend: self.backend,
            email: self.email,
            url: self.url,
            source,
            confirm: master.clone(),
            master,
            pin: self.pin.unwrap_or_default(), // audit-allow: an absent PIN is empty in the form
            create_account: self.create_account,
            reseal: self.reseal,
            dry_run: false,
        };
        let problems = vault.problems();
        if !problems.is_empty() {
            return Err(problems.join("\n"));
        }
        let creds: Creds = self
            .creds
            .into_iter()
            .map(|(name, (username, password))| (name, LoginCred { username, password }))
            .collect();
        Ok(RunJob::new(cfg, penv, paths, &vault, creds))
    }
}

pub(super) fn available(penv: &PathEnv, form: &VaultForm) -> Option<PathBuf> {
    if form.target != Target::Pi
        || form.source == MasterSource::SecretService
        || penv.etc_dir() != Path::new(ETC_DIR_DEFAULT)
        || !SetupPaths::resolve(Target::Pi, penv, true).needs_privilege
        || !std::fs::metadata(PROGRAM).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
    {
        return None;
    }
    let path = std::env::var("PATH").ok()?;
    soc_sys::sysaction::find_pkexec(&path)
}

/// `None` means authorization failed before setup ran and the user path can
/// be tried. A failure from the worker may have already written system files.
pub(super) fn execute(pkexec: &Path, job: &RunJob, emit: &impl Fn(Msg)) -> SetupResult<Option<bool>> {
    let mut child = Command::new(pkexec)
        .args(["--disable-internal-agent", PROGRAM, "setup-gui", APPLY])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Could not request authorization: {e}"))?;
    let request = Request::from_job(job);
    let write_result = child.stdin.take().map(|stdin| serde_json::to_writer(stdin, &request));
    drop(request);
    let read_result = child.stdout.take().map(|stdout| {
        BufReader::new(stdout).lines().try_for_each(|line| {
            let line = Zeroizing::new(line.map_err(|e| e.to_string())?);
            let msg = serde_json::from_str(&line)
                .map_err(|e| format!("Invalid response from system setup at column {}.", e.column()))?;
            emit(msg);
            Ok::<(), String>(())
        })
    });
    let status = child.wait().map_err(|e| e.to_string())?;
    if matches!(status.code(), Some(126 | 127)) {
        return Ok(None);
    }
    if let Some(Err(error)) = write_result {
        return Err(format!("Could not send the configuration: {error}"));
    }
    if let Some(result) = read_result {
        result?;
    }
    if status.success() {
        match std::fs::remove_file(job.penv.active_marker()) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("System configuration saved. Could not deactivate the per-user copy: {e}")),
        }
    }
    Ok(Some(status.success()))
}

/// The root helper receives the complete request on stdin. The GUI consumes
/// progress and the one-time PIN through its private stdout pipe.
pub(super) fn apply() -> i32 {
    if soc_sys::fsutil::euid() != 0 || std::io::IsTerminal::is_terminal(&io::stdout()) {
        eprintln!("System setup requires administrator authorization and a GUI response pipe.");
        return 1;
    }
    let emit = |msg: Msg| {
        let mut out = io::stdout().lock();
        if serde_json::to_writer(&mut out, &msg).is_ok() {
            let _ = writeln!(out); // audit-allow: the GUI may have closed its progress pipe
        }
    };
    let mut body = Zeroizing::new(Vec::new());
    let result = io::stdin()
        .lock()
        .take(REQUEST_LIMIT + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("Could not read the system setup request: {e}"))
        .and_then(|len| {
            if len as u64 > REQUEST_LIMIT {
                return Err("System setup request is too large.".into());
            }
            serde_json::from_slice::<Request>(&body)
                .map_err(|e| format!("Invalid system setup request at line {}, column {}.", e.line(), e.column()))
        });
    drop(body);
    match result.and_then(|request| request.job(PathEnv::from_process())) {
        Ok(job) => i32::from(!super::execute(job, emit)),
        Err(detail) => {
            emit(Msg::Step(super::StepLine { title: "System configuration".into(), ok: false, detail, lines: vec![] }));
            1
        }
    }
}
