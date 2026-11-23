//! Atomic release activation and recovery for installations managed by install.sh.

use crate::run::{Output, Runner, SystemRunner, argv};
use crate::{fsutil, heartbeat, manifest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const UNITS: [&str; 3] = ["vaultwarden.service", "autossh-tunnel.service", "forti-vpn.service"];
const STALE: f64 = 60.0;

type Result<T> = std::result::Result<T, UpdateError>;

#[derive(Debug)]
enum UpdateError {
    Retry(String),
    Bad(String),
}

impl From<io::Error> for UpdateError {
    fn from(error: io::Error) -> Self {
        Self::Retry(error.to_string())
    }
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry(message) | Self::Bad(message) => f.write_str(message),
        }
    }
}

fn retry(message: impl Into<String>) -> UpdateError {
    UpdateError::Retry(message.into())
}

fn log(message: impl std::fmt::Display) {
    eprintln!("[soc-update] {message}");
}

fn env_path(name: &str, default: impl Into<PathBuf>) -> PathBuf {
    std::env::var_os(name).filter(|s| !s.is_empty()).map_or_else(|| default.into(), PathBuf::from)
}

struct Paths {
    live: PathBuf,
    releases: PathBuf,
    state: PathBuf,
    etc: PathBuf,
    heartbeat: PathBuf,
}

impl Paths {
    fn from_env() -> Self {
        Self {
            live: env_path("SOC_ROOT", "/opt/soc-display"),
            releases: env_path("SOC_RELEASES", "/opt/soc-releases"),
            state: env_path("SOC_UPDATE_STATE", "/var/lib/soc-update"),
            etc: env_path("SOC_ETC", "/etc/soc-display"),
            heartbeat: env_path("SOC_HEARTBEAT_FILE", "/run/soc-wall/heartbeat.json"),
        }
    }

    fn mirror(&self) -> PathBuf {
        self.state.join("repo.git")
    }

    fn release(&self, name: &str) -> Result<PathBuf> {
        if !release_id(name) {
            return Err(retry(format!("invalid release ID {name:?}")));
        }
        Ok(self.releases.join(name))
    }
}

struct Settings {
    enabled: bool,
    repair: bool,
    repo: String,
    refs: [String; 2],
    window: String,
    signers: PathBuf,
    health_timeout: Duration,
    health_stable: Duration,
    health_url: String,
    keep: usize,
    min_free_mb: u64,
    drift_interval: f64,
    git_user: String,
}

fn parse_window(window: &str) -> Option<(u16, u16)> {
    let time = |part: &str| {
        let (hours, minutes) = part.split_once(':')?;
        if !(1..=2).contains(&hours.len())
            || minutes.len() != 2
            || !hours.bytes().chain(minutes.bytes()).all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let (hours, minutes) = (hours.parse::<u16>().ok()?, minutes.parse::<u16>().ok()?);
        (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
    };
    let (start, end) = window.split_once('-')?;
    Some((time(start)?, time(end)?))
}

fn inside_window((start, end): (u16, u16), minute: u16) -> bool {
    if start <= end { (start..end).contains(&minute) } else { minute >= start || minute < end }
}

fn digest_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn release_id(value: &str) -> bool {
    let is_hex = |v: &str| v.len() == 12 && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    value.split_once("-r").map_or_else(
        || is_hex(value),
        |(head, stamp)| is_hex(head) && !stamp.is_empty() && stamp.bytes().all(|b| b.is_ascii_digit()),
    )
}

impl Settings {
    fn load(paths: &Paths) -> Self {
        let env = crate::health::load_env_file(&env_path("SOC_UPDATE_ENV", paths.etc.join("update.env")));
        let text = |key, default: &str| env.get(key).map_or(default, |s| s.trim()).to_string();
        let number =
            |key, default: u64, min| env.get(key).and_then(|s| s.parse::<u64>().ok()).unwrap_or(default).max(min);
        let enabled = |key| {
            !env.get(key).is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"))
        };
        Self {
            enabled: enabled("SOC_UPDATE_ENABLE"),
            repair: enabled("SOC_UPDATE_REPAIR"),
            repo: text("SOC_UPDATE_REPO", "https://github.com/s-b-repo/p2soc.git"),
            refs: [text("SOC_UPDATE_REF", "stable"), text("SOC_UPDATE_FALLBACK_REF", "main")],
            window: text("SOC_UPDATE_WINDOW", ""),
            signers: env.get("SOC_UPDATE_SIGNERS").map_or_else(|| paths.etc.join("update-signers"), PathBuf::from),
            health_timeout: Duration::from_secs(number("SOC_UPDATE_HEALTH_TIMEOUT", 300, 10)),
            health_stable: Duration::from_secs(number("SOC_UPDATE_HEALTH_STABLE", 60, 0)),
            health_url: text("SOC_HEALTHCHECK_URL", ""),
            keep: usize::try_from(number("SOC_UPDATE_KEEP", 3, 1)).unwrap_or(usize::MAX),
            min_free_mb: number("SOC_UPDATE_MIN_FREE_MB", 300, 0),
            drift_interval: number("SOC_UPDATE_DRIFT_INTERVAL", 86400, 60) as f64,
            git_user: text("SOC_UPDATE_GIT_USER", "socupdate"),
        }
    }

    fn validate(&self) -> Result<()> {
        if !(self.repo.starts_with("file://")
            || self.repo.starts_with("https://") && soc_core::guard::valid_http_url(&self.repo, false))
        {
            return Err(retry("SOC_UPDATE_REPO must be an HTTPS URL without credentials or a file:// URL"));
        }
        for name in self.refs.iter().filter(|name| !name.is_empty()) {
            if name.contains("..")
                || !name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"./_-".contains(&b))
            {
                return Err(retry(format!("invalid update ref {name:?}")));
            }
        }
        if self.refs.iter().all(String::is_empty) {
            return Err(retry("no update ref configured"));
        }
        if !self.health_url.is_empty()
            && !(self.health_url.starts_with("https://") && soc_core::guard::valid_http_url(&self.health_url, false))
        {
            return Err(retry("SOC_HEALTHCHECK_URL must be an HTTPS URL without credentials"));
        }
        if !self.window.is_empty() && parse_window(&self.window).is_none() {
            return Err(retry("SOC_UPDATE_WINDOW must look like 03:00-05:00"));
        }
        if self.git_user.is_empty() || self.git_user.starts_with('-') || self.git_user == "root" {
            return Err(retry("SOC_UPDATE_GIT_USER must be an unprivileged local user"));
        }
        Ok(())
    }

    fn may_apply(&self) -> Result<bool> {
        let Some(window) = parse_window(&self.window) else { return Ok(true) };
        let out = SystemRunner.run(&argv(&["date", "+%H:%M"]), Duration::from_secs(5))?;
        let value = out.stdout.trim();
        let (minute, _) = parse_window(&format!("{value}-{value}"))
            .ok_or_else(|| retry("could not read local time for the maintenance window"))?;
        Ok(inside_window(window, minute))
    }

    fn ping(&self, ok: bool) {
        if self.health_url.is_empty() {
            return;
        }
        let url = if ok { self.health_url.clone() } else { format!("{}/fail", self.health_url.trim_end_matches('/')) };
        let args = argv(&["curl", "--silent", "--fail", "--max-time", "10", "--output", "/dev/null", "--", &url]);
        if !SystemRunner.run(&args, Duration::from_secs(12)).is_ok_and(|out| out.success()) {
            log("healthcheck ping failed");
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Baseline {
    alive: bool,
    panels_ok: u64,
    units: BTreeMap<String, String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Pending {
    release: String,
    commit: String,
    reason: String,
    previous: String,
    previous_commit: String,
    started: f64,
    baseline: Baseline,
    activations: u32,
    rolling_back: bool,
    why: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Failure {
    reason: String,
    ts: f64,
    failures: u32,
    retry: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct State {
    pending: Option<Pending>,
    bad: BTreeMap<String, Failure>,
    last_result: String,
    last_drift_check: f64,
    git_failures: u32,
    retry_after: f64,
}

struct Updater {
    paths: Paths,
    settings: Settings,
    state: State,
    saved: Vec<u8>,
}

fn seconds() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

fn checked(out: Output, context: &str) -> Result<()> {
    if out.success() {
        return Ok(());
    }
    let details = if out.stderr.is_empty() { &out.stdout } else { &out.stderr };
    let detail: String = details.trim().chars().rev().take(300).collect::<Vec<_>>().into_iter().rev().collect();
    Err(retry(format!("{context} failed (status {:?}): {detail}", out.code)))
}

impl Updater {
    fn new(paths: Paths, settings: Settings) -> Self {
        let state: State = fsutil::read_capped(&paths.state.join("state.json"), 1 << 20)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default(); // audit-allow: a missing or corrupt journal starts empty
        let saved = serde_json::to_vec_pretty(&state).unwrap_or_else(|_| Vec::new());
        Self { paths, settings, state, saved }
    }

    fn save(&mut self) -> Result<()> {
        let text = serde_json::to_vec_pretty(&self.state).map_err(|e| retry(e.to_string()))?;
        if text != self.saved {
            fsutil::write_atomic(&self.paths.state.join("state.json"), &text, 0o644)?;
            File::open(&self.paths.state)?.sync_all()?;
            self.saved = text;
        }
        Ok(())
    }

    fn managed(&self) -> bool {
        self.paths.live.symlink_metadata().is_ok_and(|m| m.is_symlink())
    }

    fn current(&self) -> String {
        self.paths
            .live
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name()?.to_str().map(str::to_string))
            .unwrap_or_default() // audit-allow: a missing release target has no name
    }

    fn deployed(&self) -> String {
        manifest::read_commit_marker(&self.paths.live).filter(|s| digest_id(s)).unwrap_or_default() // audit-allow: pre-updater installs have no commit marker
    }

    fn swap(&self, release: &str) -> Result<()> {
        let dest = self.paths.release(release)?;
        if !dest.symlink_metadata().is_ok_and(|m| m.is_dir()) {
            return Err(retry(format!("release {release} does not exist")));
        }
        let parent = self.paths.live.parent().ok_or_else(|| retry("release link has no parent"))?;
        let name = self.paths.live.file_name().ok_or_else(|| retry("release link has no name"))?;
        let temp = parent.join(format!(".{}.swap", name.to_string_lossy()));
        match fs::remove_file(&temp) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        symlink(dest.canonicalize()?, &temp)?;
        fs::rename(&temp, &self.paths.live)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn git_command(&self, args: &[String], mirror: bool) -> Result<Command> {
        let mut cmd = if fsutil::euid() == 0 {
            let account =
                fsutil::passwd_lookup(Path::new(fsutil::PASSWD), |e| e.name == self.settings.git_user && e.uid != 0)
                    .ok_or_else(|| retry(format!("update account {:?} does not exist", self.settings.git_user)))?;
            let mut cmd = Command::new("runuser");
            cmd.args(["-u", &account.name, "--", "env", "-i"]);
            cmd
        } else {
            let mut cmd = Command::new("env");
            cmd.arg("-i");
            cmd
        };
        cmd.arg(format!("HOME={}", self.paths.state.display())).args([
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL=C",
            "GIT_TERMINAL_PROMPT=0",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_ALLOW_PROTOCOL=https:file",
            "git",
            "-c",
            "core.hooksPath=/dev/null",
        ]);
        if mirror {
            cmd.arg("-C").arg(self.paths.mirror());
        }
        cmd.args(args).stdin(Stdio::null());
        Ok(cmd)
    }

    fn git(&self, args: &[String], mirror: bool, timeout: u64) -> Result<Output> {
        Ok(SystemRunner.run_command(&mut self.git_command(args, mirror)?, Duration::from_secs(timeout))?)
    }

    fn tip(&self) -> Result<(String, String)> {
        let mut args = argv(&["ls-remote", "--", &self.settings.repo]);
        let mut refs = Vec::new();
        for name in self.settings.refs.iter().filter(|name| !name.is_empty()) {
            let head = format!("refs/heads/{name}");
            let tag = format!("refs/tags/{name}");
            let peeled = format!("{tag}^{{}}");
            args.extend([head.clone(), tag.clone(), peeled.clone()]);
            refs.push([(head.clone(), head), (peeled, tag.clone()), (tag.clone(), tag)]);
        }
        let out = self.git(&args, false, 60)?;
        let found: BTreeMap<_, _> =
            out.stdout.lines().filter_map(|l| l.split_once('\t')).map(|(sha, name)| (name, sha)).collect();
        for (name, fetch) in refs.iter().flatten() {
            if let Some(sha) = found.get(name.as_str()).filter(|sha| digest_id(sha)) {
                return Ok((fetch.clone(), (*sha).to_string()));
            }
        }
        checked(out, "git ls-remote")?;
        Err(retry("none of the configured update refs exist on the remote"))
    }

    fn fetch(&mut self, reference: &str, sha: &str) -> Result<()> {
        let result = self.fetch_once(reference, sha);
        if result.is_ok() {
            self.state.git_failures = 0;
        } else {
            self.state.git_failures = self.state.git_failures.saturating_add(1);
        }
        result
    }

    fn fetch_once(&self, reference: &str, sha: &str) -> Result<()> {
        let mirror = self.paths.mirror();
        if self.state.git_failures >= 3 || !mirror.join("HEAD").is_file() {
            remove_tree(&mirror)?;
            fs::create_dir(&mirror)?;
            if fsutil::euid() == 0 {
                checked(
                    SystemRunner.run(
                        &argv(&["chown", "--", &self.settings.git_user, &mirror.to_string_lossy()]),
                        Duration::from_secs(30),
                    )?,
                    "chown mirror",
                )?;
            }
            checked(
                self.git(&argv(&["init", "--bare", "--quiet", &mirror.to_string_lossy()]), false, 60)?,
                "git init",
            )?;
        }
        let spec = format!("+{reference}:refs/soc/target");
        checked(
            self.git(
                &argv(&["fetch", "--quiet", "--no-tags", "--force", "--", &self.settings.repo, &spec]),
                true,
                600,
            )?,
            "git fetch",
        )?;
        checked(
            self.git(&argv(&["cat-file", "-e", &format!("{sha}^{{commit}}")]), true, 60)?,
            "git verify fetched commit",
        )
    }

    fn verify(&self, sha: &str, reason: &str) -> Result<()> {
        let deployed = self.deployed();
        if reason == "update"
            && !deployed.is_empty()
            && sha != deployed
            && self.git(&argv(&["merge-base", "--is-ancestor", sha, &deployed]), true, 60)?.success()
        {
            return Err(UpdateError::Bad(format!("refusing to update backwards to {}", &sha[..12])));
        }
        let signers = &self.settings.signers;
        if !signers.as_os_str().is_empty() && signers.try_exists()? {
            let config = format!("gpg.ssh.allowedSignersFile={}", signers.display());
            let version = self.git(&argv(&["version"]), false, 30)?.stdout;
            let mut parts = version.split_whitespace().nth(2).unwrap_or("").split('.');
            let major = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let minor = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            if (major, minor) < (2, 34) {
                return Err(retry("SSH commit signatures require Git 2.34 or newer"));
            }
            let result = self.git(&argv(&["-c", "gpg.format=ssh", "-c", &config, "verify-commit", sha]), true, 60)?;
            if !result.success() {
                return Err(UpdateError::Bad(format!("commit {} has no valid SSH signature", &sha[..12])));
            }
        }
        Ok(())
    }

    fn install(&self, root: &Path, phase: &str) -> Result<()> {
        let mut cmd = Command::new("bash");
        cmd.arg(root.join("install.sh"))
            .arg(phase)
            .current_dir(root)
            .stdin(Stdio::null())
            .env("SOC_ROOT", &self.paths.live)
            .env("SOC_RELEASES", &self.paths.releases)
            .env("SOC_ETC", &self.paths.etc);
        checked(SystemRunner.run_command(&mut cmd, Duration::from_secs(1800))?, phase)
    }

    fn build(&self, sha: &str, name: &str) -> Result<()> {
        let dest = self.paths.release(name)?;
        let stage = self.paths.releases.join(format!(".stage-{name}"));
        remove_tree(&stage)?;
        let result = self.stage(sha, &stage).and_then(|()| {
            if self.current() == name {
                return Err(retry("staging would replace the running release"));
            }
            remove_tree(&dest)?;
            fs::rename(&stage, &dest)?;
            File::open(&self.paths.releases)?.sync_all()?;
            Ok(())
        });
        if let Err(error) = remove_tree(&stage) {
            log(format!("could not remove staging directory: {error}"));
        }
        result
    }

    fn stage(&self, sha: &str, stage: &Path) -> Result<()> {
        fs::create_dir(stage)?;
        let archive = stage.join(".soc-export.tar");
        let writer = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&archive)?;
        let file = fsutil::open_regular(&archive)?;
        fs::remove_file(&archive)?;
        let mut git = self.git_command(&argv(&["archive", "--format=tar", sha]), true)?;
        checked(SystemRunner.run_with_stdout(&mut git, writer.into(), Duration::from_secs(300))?, "git archive")?;
        let mut tar = Command::new("tar");
        tar.args(["-x", "-C"])
            .arg(stage)
            .args(["--no-same-owner", "--anchored", "-f", "-"])
            .args(
                [
                    "dev",
                    "kiosk-host/tests",
                    ".github",
                    ".githooks",
                    ".pre-commit-config.yaml",
                    "CONTRIBUTING.md",
                    "rust/fuzz",
                    "rust/crates/*/tests",
                ]
                .map(|p| format!("--exclude={p}")),
            )
            .stdin(file);
        checked(SystemRunner.run_command(&mut tar, Duration::from_secs(300))?, "extract release")?;
        fsutil::write_atomic(&stage.join(".commit"), format!("{sha}\n").as_bytes(), 0o644)?;
        let scripts = fs::read_dir(stage.join("scripts"))?;
        for file in scripts
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "sh"))
            .chain([stage.join("install.sh")])
        {
            let out = SystemRunner.run(&argv(&["bash", "-n", &file.to_string_lossy()]), Duration::from_secs(60))?;
            checked(out, &file.display().to_string()).map_err(|e| UpdateError::Bad(e.to_string()))?;
        }
        self.install(stage, "--deps-if-changed")?;
        if stage.join("scripts/soc-update.sh").is_file() {
            let mut cargo = Command::new("cargo");
            cargo
                .args(["build", "--release", "--locked", "--bin", "soc-wall"])
                .current_dir(stage.join("rust"))
                .env("CARGO_TARGET_DIR", stage.join("rust/target"))
                .stdin(Stdio::null());
            if Path::new("/etc/alpine-release").is_file() {
                let flags = std::env::var("RUSTFLAGS").unwrap_or_else(|_| String::new());
                cargo.env("RUSTFLAGS", format!("{flags} -C target-feature=-crt-static"));
            }
            checked(SystemRunner.run_command(&mut cargo, Duration::from_secs(1800))?, "native release build")?;
            let bin = stage.join("bin");
            fs::create_dir_all(&bin)?;
            fs::rename(stage.join("rust/target/release/soc-wall"), bin.join("soc-wall"))?;
            remove_tree(&stage.join("rust/target"))?;
            let binary = bin.join("soc-wall");
            let cmd = |args: &[&str]| {
                let mut cmd = vec![binary.display().to_string()];
                cmd.extend(argv(args));
                SystemRunner.run(&cmd, Duration::from_secs(60))
            };
            checked(cmd(&["update", "self-test"])?, "new updater self-test")
                .map_err(|e| UpdateError::Bad(e.to_string()))?;
            let bundled = stage.join("config/panels.yaml");
            checked(cmd(&["check", &bundled.to_string_lossy()])?, "native smoke test")
                .map_err(|e| UpdateError::Bad(e.to_string()))?;
            let live_config = self.paths.etc.join("panels.yaml");
            if live_config.is_file() {
                let config = live_config.to_string_lossy();
                let live_native = self.paths.live.join("bin/soc-wall");
                let live_valid = if live_native.is_file() {
                    let args = argv(&[&live_native.to_string_lossy(), "check", &config]);
                    SystemRunner.run(&args, Duration::from_secs(60)).is_ok_and(|o| o.success())
                } else {
                    soc_core::load(&live_config).is_ok()
                };
                if live_valid {
                    checked(cmd(&["check", &config])?, "live config smoke test")
                        .map_err(|e| UpdateError::Bad(e.to_string()))?;
                }
            }
        } else {
            self.preflight_legacy(stage)?;
        }
        rustix::fs::sync();
        Ok(())
    }

    fn preflight_legacy(&self, stage: &Path) -> Result<()> {
        let venv = stage.join("scripts/soc-venv.sh");
        checked(
            SystemRunner.run(
                &argv(&[
                    "bash",
                    &venv.to_string_lossy(),
                    &stage.to_string_lossy(),
                    &self.paths.releases.to_string_lossy(),
                ]),
                Duration::from_secs(1800),
            )?,
            "compatibility environment",
        )?;
        let py = stage.join(".venv/bin/python");
        let out = SystemRunner.run(
            &argv(&[
                &py.to_string_lossy(),
                "-m",
                "compileall",
                "-q",
                &stage.join("kiosk-host/host").to_string_lossy(),
                &stage.join("setup.py").to_string_lossy(),
                &stage.join("provision.py").to_string_lossy(),
                &stage.join("scripts").to_string_lossy(),
            ]),
            Duration::from_secs(300),
        )?;
        checked(out, "compatibility source check").map_err(|e| UpdateError::Bad(e.to_string()))?;
        let updater = stage.join("scripts/soc-update.py");
        let cmd = argv(&[&py.to_string_lossy(), &updater.to_string_lossy(), "self-test"]);
        checked(SystemRunner.run(&cmd, Duration::from_secs(60))?, "updated legacy updater self-test")
            .map_err(|e| UpdateError::Bad(e.to_string()))?;
        Ok(())
    }

    fn unit(&self, verb: &str, name: &str) -> Result<String> {
        let out = SystemRunner.run(&argv(&["systemctl", verb, name]), Duration::from_secs(30))?;
        Ok(out.stdout.trim().to_string())
    }

    fn meta(&self, key: &str, default: &str) -> String {
        fsutil::read_capped(&self.paths.etc.join(".install-manifest"), 1 << 20)
            .ok()
            .and_then(|text| {
                text.lines().find_map(|line| {
                    let mut fields = line.split('|');
                    if fields.next() == Some("META") && fields.next() == Some(key) {
                        fields.next().map(str::to_string)
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| default.to_string())
    }

    fn restart(&self) -> Result<()> {
        let cmd = |parts: &[&str]| SystemRunner.run(&argv(parts), Duration::from_secs(120));
        checked(cmd(&["systemctl", "daemon-reload"])?, "systemctl daemon-reload")?;
        cmd(&["systemctl", "try-restart", "autossh-tunnel.service", "forti-vpn.service", "soc-tarpit.service"])?;
        if matches!(self.unit("is-active", "soc-wall.service")?.as_str(), "active" | "activating" | "failed") {
            cmd(&["systemctl", "reset-failed", "soc-wall.service"])?;
            checked(cmd(&["systemctl", "restart", "soc-wall.service"])?, "restart wall")?;
        } else if self.meta("install_mode", "desktop") == "kiosk" {
            let user = self.meta("kiosk_user", "soc");
            if cmd(&["loginctl", "show-user", "--", &user])?.success() {
                checked(cmd(&["loginctl", "terminate-user", "--", &user])?, "restart kiosk session")?;
            }
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Baseline> {
        let mut units = BTreeMap::new();
        for unit in UNITS {
            units.insert(unit.to_string(), self.unit("is-active", unit)?);
        }
        let beat = heartbeat::read(&self.paths.heartbeat);
        Ok(Baseline {
            alive: heartbeat::age(beat.as_ref(), seconds()) < STALE
                && beat.as_ref().and_then(|b| b.get("state")).and_then(|v| v.as_str()) == Some("running"),
            panels_ok: beat.as_ref().and_then(|b| b.get("panels_ok")).and_then(|v| v.as_u64()).unwrap_or(0),
            units,
        })
    }

    fn assess(&self, p: &Pending) -> Result<u64> {
        for unit in UNITS {
            if let Some(before) = p.baseline.units.get(unit) {
                let now = self.unit("is-active", unit)?;
                if (before == "active" && now != "active") || (now == "failed" && before != "failed") {
                    return Err(retry(format!("{unit} is {now} (was {before})")));
                }
            }
        }
        if self.unit("is-active", "soc-update.timer")? != "active" {
            return Err(retry("the update timer is not running"));
        }
        if !p.baseline.alive {
            return Ok(0);
        }
        let beat = heartbeat::read(&self.paths.heartbeat)
            .filter(|b| heartbeat::age(Some(b), seconds()) < STALE)
            .ok_or_else(|| retry("no fresh wall heartbeat"))?;
        if beat.get("commit").and_then(|v| v.as_str()) != Some(&p.commit)
            || beat.get("state").and_then(|v| v.as_str()) != Some("running")
        {
            return Err(retry("the wall has not reached running state on the expected release"));
        }
        if p.baseline.panels_ok > 0 && beat.get("panels_ok").and_then(|v| v.as_u64()).unwrap_or(0) == 0 {
            return Err(retry("no panel has loaded"));
        }
        beat.get("pid")
            .and_then(|v| v.as_u64())
            .filter(|&id| id > 0)
            .ok_or_else(|| retry("heartbeat has no process ID"))
    }

    fn wait_healthy(&self, p: &Pending) -> Result<()> {
        let start = Instant::now();
        let mut stable = None;
        let mut why = retry("health check timed out");
        while start.elapsed() < self.settings.health_timeout {
            match self.assess(p) {
                Ok(pid) => {
                    let (last, since) = stable.get_or_insert((pid, Instant::now()));
                    if *last != pid {
                        (*last, *since) = (pid, Instant::now());
                    }
                    if since.elapsed() >= self.settings.health_stable {
                        return Ok(());
                    }
                }
                Err(e) => {
                    stable = None;
                    why = e;
                }
            }
            std::thread::sleep(
                Duration::from_secs(5).min(self.settings.health_timeout.saturating_sub(start.elapsed())),
            );
        }
        Err(why)
    }

    fn remember_bad(&mut self, sha: &str, why: &str, allow_retry: bool) {
        if !digest_id(sha) {
            return;
        }
        let old = self.state.bad.entry(sha.to_string()).or_default();
        old.failures = old.failures.saturating_add(1);
        old.reason = why.chars().take(300).collect();
        old.retry = old.failures < 2 && allow_retry;
        old.ts = seconds();
        if self.state.bad.len() > 50 {
            let oldest = self.state.bad.iter().min_by(|a, b| a.1.ts.total_cmp(&b.1.ts)).map(|(key, _)| key.clone());
            if let Some(key) = oldest {
                self.state.bad.remove(&key);
            }
        }
    }

    fn finish(&mut self, p: Pending) -> Result<bool> {
        let result = self
            .install(&self.paths.release(&p.release)?, "--activate")
            .and_then(|()| self.restart())
            .and_then(|()| self.wait_healthy(&p));
        if let Err(e) = result {
            self.rollback(p, &e.to_string(), true)?;
            return Ok(false);
        }
        self.state.last_result = format!("deployed {} ({})", p.release, p.reason);
        self.state.pending = None;
        self.state.bad.remove(&p.commit);
        self.save()?;
        log(&self.state.last_result);
        self.gc(&[&p.previous])?;
        Ok(true)
    }

    fn rollback(&mut self, mut p: Pending, why: &str, allow_retry: bool) -> Result<()> {
        if p.reason == "update" {
            self.remember_bad(&p.commit, why, allow_retry);
        }
        p.rolling_back = true;
        p.why = why.to_string();
        self.state.pending = Some(p.clone());
        self.save()?;
        self.finish_rollback(p)
    }

    fn finish_rollback(&mut self, p: Pending) -> Result<()> {
        log(format!("rolling back {} to {} ({})", p.release, p.previous, p.why));
        self.swap(&p.previous)?;
        let applied = self.install(&self.paths.release(&p.previous)?, "--activate");
        let restarted = self.restart();
        applied.and(restarted)?;
        self.state.last_result = format!("rolled back to {}: {}", p.previous, p.why);
        self.state.pending = None;
        self.save()?;
        if p.release != p.previous && !p.release.is_empty() {
            remove_tree(&self.paths.release(&p.release)?)?;
        }
        Ok(())
    }

    fn recover(&mut self) -> Result<()> {
        let Some(mut p) = self.state.pending.clone() else { return Ok(()) };
        if p.rolling_back {
            return self.finish_rollback(p);
        }
        if self.current() != p.release {
            self.state.pending = None;
            return self.save();
        }
        if p.activations >= 2 {
            return self.rollback(p, "release repeatedly failed to finish its health check", false);
        }
        p.activations += 1;
        self.state.pending = Some(p.clone());
        self.save()?;
        self.finish(p).map(|_| ())
    }

    fn releases(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.paths.releases)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !release_id(&name) || !entry.file_type()?.is_dir() {
                continue;
            }
            names.push((entry.metadata()?.modified()?, name));
        }
        names.sort_unstable_by(|a, b| b.cmp(a));
        Ok(names.into_iter().map(|(_, name)| name).collect())
    }

    fn gc(&self, extra: &[&str]) -> Result<()> {
        let names = self.releases()?;
        let current = self.current();
        let mut used_venvs = Vec::new();
        for (i, name) in names.iter().enumerate() {
            let path = self.paths.release(name)?;
            if i < self.settings.keep || name == &current || extra.contains(&name.as_str()) {
                used_venvs.extend(
                    fs::read_link(path.join(".venv"))
                        .into_iter()
                        .filter_map(|target| target.file_name().map(|s| s.to_owned())),
                );
            } else {
                remove_tree(&path)?;
            }
        }
        for entry in fs::read_dir(&self.paths.releases)? {
            let entry = entry?;
            let name = entry.file_name();
            let valid_stage = name.to_str().and_then(|s| s.strip_prefix(".stage-")).is_some_and(release_id);
            let unused_venv = name.to_str().is_some_and(|s| s.starts_with("venv-")) && !used_venvs.contains(&name);
            if (valid_stage || unused_venv) && entry.file_type()?.is_dir() {
                remove_tree(&entry.path())?;
            }
        }
        Ok(())
    }

    fn check_space(&self) -> Result<()> {
        let free = || -> Result<u64> {
            let stats = rustix::fs::statvfs(&self.paths.releases).map_err(io::Error::from)?;
            Ok(stats.f_bavail.saturating_mul(stats.f_frsize) / (1024 * 1024))
        };
        if free()? < self.settings.min_free_mb {
            self.gc(&[])?;
        }
        let available = free()?;
        if available < self.settings.min_free_mb {
            return Err(retry(format!("only {available} MiB free; need {}", self.settings.min_free_mb)));
        }
        Ok(())
    }

    fn deploy(&mut self, reference: &str, sha: &str, reason: &str) -> Result<bool> {
        self.check_space()?;
        self.fetch(reference, sha)?;
        self.verify(sha, reason)?;
        let name =
            if reason == "repair" { format!("{}-r{}", &sha[..12], seconds() as u64) } else { sha[..12].to_string() };
        self.build(sha, &name)?;
        let pending = Pending {
            release: name,
            commit: sha.to_string(),
            reason: reason.to_string(),
            previous: self.current(),
            previous_commit: self.deployed(),
            started: seconds(),
            baseline: self.snapshot()?,
            activations: 1,
            ..Pending::default()
        };
        self.paths.release(&pending.previous)?;
        self.state.pending = Some(pending.clone());
        self.save()?;
        self.swap(&pending.release)?;
        self.finish(pending)
    }

    fn healthy_now(&self) -> bool {
        !UNITS.iter().any(|unit| {
            self.unit("is-enabled", unit).is_ok_and(|s| s == "enabled")
                && self.unit("is-active", unit).is_ok_and(|s| s == "failed")
        }) && (self.meta("install_mode", "desktop") != "kiosk"
            || heartbeat::age(heartbeat::read(&self.paths.heartbeat).as_ref(), seconds()) < STALE)
    }

    fn planned(&mut self, may_apply: bool, tip: &str) -> Option<(String, &'static str)> {
        let deployed = self.deployed();
        let blocked = self.state.bad.get(tip).is_some_and(|f| !f.retry || seconds() - f.ts < 6.0 * 3600.0);
        if tip != deployed && !blocked {
            return Some((tip.to_string(), "update"));
        }
        if may_apply && self.settings.repair && seconds() - self.state.last_drift_check >= self.settings.drift_interval
        {
            self.state.last_drift_check = seconds();
            if !deployed.is_empty()
                && manifest::check_drift(&self.paths.live, &self.paths.etc.join("manifest.json"))
                    .is_ok_and(|d| !d.changed.is_empty() || !d.missing.is_empty())
            {
                return Some((deployed, "repair"));
            }
        }
        None
    }

    fn run(&mut self, now: bool) -> Result<()> {
        if !self.settings.enabled || !self.managed() {
            log("updates disabled or no managed release layout");
            return Ok(());
        }
        self.settings.validate()?;
        if ![".configured", "secret/master.enc"].iter().any(|name| self.paths.etc.join(name).exists()) {
            log("waiting for wall setup to finish");
            return Ok(());
        }
        self.recover()?;
        let may_apply = now || self.settings.may_apply()?;
        let mut ok = true;
        let mut attempted = None;
        let outcome = self.tip().and_then(|(reference, tip)| {
            if let Some((sha, reason)) = self.planned(may_apply, &tip) {
                if !may_apply || (!now && seconds() < self.state.retry_after) {
                    log(format!("{reason} of {} is waiting for its next window or retry", &sha[..12]));
                    return Ok(());
                }
                attempted = Some(sha.clone());
                ok = self.deploy(&reference, &sha, reason)?;
                self.state.retry_after = 0.0;
            }
            Ok(())
        });
        match outcome {
            Err(UpdateError::Bad(message)) => {
                if let Some(sha) = attempted {
                    self.remember_bad(&sha, &message, false);
                }
                self.state.last_result = format!("rejected: {message}");
                log(&self.state.last_result);
            }
            Err(e) if self.state.pending.is_none() => {
                if attempted.is_some() {
                    self.state.retry_after = seconds() + 3600.0;
                }
                self.state.last_result = format!("retry: {e}");
                log(&self.state.last_result);
            }
            Err(e) => return Err(e),
            Ok(()) => (),
        }
        self.save()?;
        self.settings.ping(ok && self.healthy_now());
        Ok(())
    }

    fn manual_rollback(&mut self) -> Result<()> {
        if !self.managed() {
            return Err(retry("no managed release layout"));
        }
        self.recover()?;
        let current = self.current();
        let previous = self
            .releases()?
            .into_iter()
            .find(|name| {
                let candidate = self.paths.releases.join(name);
                name != &current
                    && candidate.join("install.sh").is_file()
                    && (candidate.join("bin/soc-wall").is_file() || candidate.join("scripts/soc-update.py").is_file())
            })
            .ok_or_else(|| retry("no previous release to roll back to"))?;
        let pending = Pending {
            release: current,
            commit: self.deployed(),
            reason: "update".into(),
            previous,
            ..Pending::default()
        };
        self.rollback(pending, "manual rollback", false)
    }

    fn status(&self) -> serde_json::Value {
        json!({
            "layout": if self.managed() { "release" } else { "not-managed" },
            "release": if self.managed() { self.current() } else { String::new() },
            "commit": self.deployed(), "enabled": self.settings.enabled,
            "repo": self.settings.repo, "ref": self.settings.refs[0],
            "window": if self.settings.window.is_empty() { "any time" } else { &self.settings.window },
            "signatures": self.settings.signers.is_file(), "last_result": self.state.last_result,
            "pending": self.state.pending, "blocklisted": self.state.bad.keys().collect::<Vec<_>>(),
        })
    }
}

fn remove_tree(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn self_test() -> bool {
    parse_window("22:00-02:00").is_some_and(|window| inside_window(window, 0) && !inside_window(window, 720))
        && parse_window("23:60-00:00").is_none()
        && release_id("123456789abc-r12")
        && !release_id("../123456789abc")
        && !release_id("123456789abc-r")
}

pub fn main(args: &[String]) -> i32 {
    let command = args.first().map_or("run", String::as_str);
    if matches!(command, "-h" | "--help" | "help") {
        println!("usage: soc-wall update [run [--now] | status | rollback | self-test]");
        return 0;
    }
    if command == "self-test" && args.len() == 1 {
        return i32::from(!self_test());
    }
    let now = command == "--now" || command == "run" && args.get(1).is_some_and(|s| s == "--now");
    if (args.len() > 1 && !(args.len() == 2 && command == "run" && now))
        || !matches!(command, "run" | "status" | "rollback" | "--now")
    {
        log("usage: soc-wall update [run [--now] | status | rollback | self-test]");
        return 2;
    }
    let paths = Paths::from_env();
    let settings = Settings::load(&paths);
    if command == "status" {
        println!("{:#}", Updater::new(paths, settings).status());
        return 0;
    }
    if fsutil::euid() != 0 {
        log("updates and rollback must run as root");
        return 1;
    }
    let execute = || -> Result<()> {
        fsutil::ensure_dir(&paths.state, 0o755)?;
        let lock = match fsutil::exclusive_lock(&paths.state.join("lock")) {
            Ok(lock) => lock,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                log("another update is running");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        let mut updater = Updater::new(paths, settings);
        let result = if command == "rollback" { updater.manual_rollback() } else { updater.run(now) };
        if result.is_err() && updater.settings.validate().is_ok() {
            updater.settings.ping(false);
        }
        drop(lock);
        result
    };
    match execute() {
        Ok(()) => 0,
        Err(e) => {
            log(e);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maintenance_window_and_release_names() {
        assert!(self_test());
        assert!(!inside_window((600, 600), 600));
        assert!(inside_window((600, 601), 600));
    }

    #[test]
    fn reads_preexisting_pending_rollback_state() {
        let data = r#"{"pending":{"release":"123456789abc","previous":"0123456789ab","rolling_back":true,"started":1.5,"baseline":{"alive":true,"panels_ok":1}},"bad":{"fake":{"retry":true,"ts":12.34,"failures":1}},"retry_after":22.5}"#;
        let state: State = serde_json::from_str(data).unwrap();
        assert!(state.pending.unwrap().rolling_back);
        assert_eq!(state.bad["fake"].failures, 1);
        assert_eq!(state.retry_after, 22.5);
    }

    #[test]
    fn swaps_complete_releases_and_rejects_invalid_paths() {
        use crate::testutil::TempDir;
        let temp = TempDir::new("update-swap");
        let releases = temp.path().join("releases");
        let previous = releases.join("111111111111");
        let next = releases.join("222222222222");
        fs::create_dir_all(&previous).unwrap();
        fs::create_dir_all(&next).unwrap();
        let paths = Paths {
            live: temp.path().join("live"),
            releases,
            etc: temp.path().join("etc"),
            state: temp.path().join("state"),
            heartbeat: temp.path().join("heartbeat"),
        };
        symlink(previous, &paths.live).unwrap();
        let settings = Settings::load(&paths);
        let updater = Updater::new(paths, settings);
        assert_eq!(updater.current(), "111111111111");
        assert!(updater.swap("../111111111111").is_err());
        assert!(updater.swap("333333333333").is_err());
        assert_eq!(updater.current(), "111111111111");
        updater.swap("222222222222").unwrap();
        assert_eq!(updater.current(), "222222222222");
        updater.swap("111111111111").unwrap();
        assert_eq!(updater.current(), "111111111111");
    }
}
