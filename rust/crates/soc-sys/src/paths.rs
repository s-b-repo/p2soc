//! Where the wall's config, secret and state files live.
//!
//! One resolver decides both where a config is *read* from and where the
//! setup wizard *writes* it, so the two can never disagree — a non-root
//! operator's wizard output must be exactly what the wall then loads.
//!
//! Read precedence per kind (first existing wins):
//!
//! 1. `$SOC_PANELS_FILE` / `$SOC_ENV_FILE` — explicit override, absolute
//!    authority (keeps the systemd units working verbatim).
//! 2. `<XDG_CONFIG_HOME or ~/.config>/soc-display/` — **only** when the
//!    `active` marker exists there.
//! 3. `/etc/soc-display/` — the canonical deployed location.
//! 4. the checkout: `config/panels.local.yaml` then `config/panels.yaml`;
//!    `.env` then `config/soc.env.example` (development fallback).
//!
//! The user tier is marker-gated rather than unconditional (a leftover
//! `~/.config` would permanently shadow a re-deployed `/etc`) or mtime-based
//! (non-deterministic across clock skew and invisible to the operator). The
//! writer drops the marker in the same step as the file; uninstall/redeploy
//! delete it to hand control back to `/etc`.
//!
//! All environment input is captured once in a [`PathEnv`]; the resolution
//! functions are pure over it, so they are testable without touching the
//! process environment.

use crate::error::{Result, SysError};
use crate::fsutil::{self, abspath};
use crate::jsonfmt;
use soc_core::Dict;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const PANELS_BASENAME: &str = "panels.yaml";
pub const ENV_BASENAME: &str = "soc.env";
pub const SECRET_BASENAME: &str = "secret";
pub const WEBDATA_BASENAME: &str = "webdata";
pub const ETC_DIR_DEFAULT: &str = "/etc/soc-display";
/// Presence of this file in the user dir makes the user config tier win.
pub const MARKER_BASENAME: &str = "active";
/// Where a deployed wall lives when `$SOC_ROOT` is unset.
pub const DEPLOY_ROOT_DEFAULT: &str = "/opt/soc-display";
pub const OVERRIDES_BASENAME: &str = "overrides.json";

/// An `--install-etc` payload or an overrides file larger than this is a
/// mistake, not a config.
const MAX_STATE_BYTES: u64 = 4 << 20;

/// Which config file is being resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Panels,
    Env,
}

impl Kind {
    pub const ALL: [Kind; 2] = [Kind::Panels, Kind::Env];

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "panels" => Some(Kind::Panels),
            "env" => Some(Kind::Env),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Kind::Panels => "panels",
            Kind::Env => "env",
        }
    }

    pub const fn basename(self) -> &'static str {
        match self {
            Kind::Panels => PANELS_BASENAME,
            Kind::Env => ENV_BASENAME,
        }
    }

    /// The environment variable that pins this file's location.
    pub const fn env_var(self) -> &'static str {
        match self {
            Kind::Panels => "SOC_PANELS_FILE",
            Kind::Env => "SOC_ENV_FILE",
        }
    }
}

/// A precedence tier of the read chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Override,
    User,
    Etc,
    Repo,
}

/// One entry of the read chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub tier: Tier,
    /// Human label for `--explain` / doctor output.
    pub label: String,
}

/// Which tier a write was routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Env,
    Etc,
    User,
    Repo,
}

impl Via {
    pub const fn as_str(self) -> &'static str {
        match self {
            Via::Env => "env",
            Via::Etc => "etc",
            Via::User => "user",
            Via::Repo => "repo",
        }
    }
}

/// Where the wizard should write a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteTarget {
    pub path: PathBuf,
    /// Its parent directory (the caller creates it).
    pub dir: PathBuf,
    /// File mode: 0644 for panels and anything under `/etc` (non-secret, must
    /// be readable by the kiosk user); 0600 for a per-user or checkout env.
    pub mode: u32,
    /// `/etc` was wanted but is not writable: the write must be escalated.
    pub needs_privilege: bool,
    pub via: Via,
    /// The marker to drop alongside the file (user tier only).
    pub marker: Option<PathBuf>,
    /// Even the per-user fallback is not writable — the caller must fail with
    /// this specific cause instead of a raw permission error mid-write.
    pub unwritable: bool,
}

/// Every environment input of the resolver, captured once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathEnv {
    /// Relative overrides are resolved against this.
    pub cwd: PathBuf,
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME` (honoured only when absolute, per the XDG spec).
    pub xdg_config_home: Option<String>,
    /// `$SOC_ETC_DIR` — relocates the system tier (local installs, tests).
    pub etc_dir: Option<String>,
    /// `$SOC_ROOT`.
    pub root: Option<String>,
    /// The checkout/deploy root used when `$SOC_ROOT` is unset.
    pub default_root: PathBuf,
    /// `$SOC_PANELS_FILE`.
    pub panels_file: Option<String>,
    /// `$SOC_ENV_FILE`.
    pub env_file: Option<String>,
    /// `$SOC_SECRET_DIR`.
    pub secret_dir: Option<String>,
    /// `$SOC_WEBDATA_DIR`.
    pub webdata_dir: Option<String>,
    /// `$SOC_STATE_DIR`.
    pub state_dir: Option<String>,
    /// `$SOC_FORCE_ETC` (only `0` turns the `/etc` write tier off).
    pub force_etc: Option<String>,
    /// `$SOC_ALLOW_PKEXEC` (only `1` allows escalating a write to `/etc`).
    pub allow_pkexec: Option<String>,
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The checkout this binary was built in, if it is still running from there:
/// the nearest ancestor of the executable that looks like the repository.
fn discover_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    exe.ancestors()
        .skip(1)
        .take(6)
        .find(|d| d.join("config").join(PANELS_BASENAME).is_file() && d.join("rust").is_dir())
        .map(Path::to_path_buf)
}

impl PathEnv {
    /// Capture the process environment.
    pub fn from_process() -> PathEnv {
        let home = env_nonempty("HOME")
            .map(PathBuf::from)
            .or_else(|| fsutil::passwd_lookup(Path::new(fsutil::PASSWD), |e| e.uid == fsutil::euid()).map(|e| e.home))
            .unwrap_or_else(|| PathBuf::from("/"));
        PathEnv {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            home,
            xdg_config_home: env_nonempty("XDG_CONFIG_HOME"),
            etc_dir: env_nonempty("SOC_ETC_DIR"),
            root: env_nonempty("SOC_ROOT"),
            default_root: discover_root().unwrap_or_else(|| PathBuf::from(DEPLOY_ROOT_DEFAULT)),
            panels_file: env_nonempty("SOC_PANELS_FILE"),
            env_file: env_nonempty("SOC_ENV_FILE"),
            secret_dir: env_nonempty("SOC_SECRET_DIR"),
            webdata_dir: env_nonempty("SOC_WEBDATA_DIR"),
            state_dir: env_nonempty("SOC_STATE_DIR"),
            force_etc: std::env::var("SOC_FORCE_ETC").ok(),
            allow_pkexec: std::env::var("SOC_ALLOW_PKEXEC").ok(),
        }
    }

    fn abs(&self, p: &str) -> PathBuf {
        abspath(Path::new(p), &self.cwd)
    }

    /// The system config directory.
    pub fn etc_dir(&self) -> PathBuf {
        match &self.etc_dir {
            Some(d) => self.abs(d),
            None => PathBuf::from(ETC_DIR_DEFAULT),
        }
    }

    /// `$XDG_CONFIG_HOME` when absolute, else `~/.config`.
    pub fn xdg_config_home(&self) -> PathBuf {
        match &self.xdg_config_home {
            Some(x) if Path::new(x).is_absolute() => PathBuf::from(x),
            _ => self.home.join(".config"),
        }
    }

    /// The per-user config dir — creatable without root.
    pub fn user_dir(&self) -> PathBuf {
        self.xdg_config_home().join("soc-display")
    }

    /// `$SOC_ROOT`, else the checkout/deploy root.
    pub fn repo_root(&self) -> PathBuf {
        match &self.root {
            Some(r) => self.abs(r),
            None => self.default_root.clone(),
        }
    }

    /// The marker whose presence makes the user tier win over `/etc`.
    pub fn active_marker(&self) -> PathBuf {
        self.user_dir().join(MARKER_BASENAME)
    }

    fn override_for(&self, kind: Kind) -> Option<PathBuf> {
        match kind {
            Kind::Panels => self.panels_file.as_deref(),
            Kind::Env => self.env_file.as_deref(),
        }
        .map(|p| self.abs(p))
    }

    fn repo_candidates(&self, kind: Kind) -> [PathBuf; 2] {
        let root = self.repo_root();
        match kind {
            Kind::Panels => [root.join("config/panels.local.yaml"), root.join("config/panels.yaml")],
            // a real .env beats the committed example
            Kind::Env => [root.join(".env"), root.join("config/soc.env.example")],
        }
    }

    /// The full ordered read chain for `kind`. The user tier is always listed,
    /// labelled with whether its marker gate is open, so doctor output shows
    /// exactly why a tier did or did not win.
    pub fn candidates(&self, kind: Kind) -> Vec<Candidate> {
        let mut out = Vec::with_capacity(5);
        if let Some(path) = self.override_for(kind) {
            out.push(Candidate { path, tier: Tier::Override, label: format!("${}", kind.env_var()) });
        }
        let label =
            if self.active_marker().exists() { "user config (active)" } else { "user config (inactive: no marker)" };
        out.push(Candidate { path: self.user_dir().join(kind.basename()), tier: Tier::User, label: label.into() });
        out.push(Candidate {
            path: self.etc_dir().join(kind.basename()),
            tier: Tier::Etc,
            label: ETC_DIR_DEFAULT.into(),
        });
        for path in self.repo_candidates(kind) {
            out.push(Candidate { path, tier: Tier::Repo, label: "repo fallback".into() });
        }
        out
    }

    /// The file the wall will read for `kind`, or `None` when nothing exists.
    pub fn resolve_read(&self, kind: Kind) -> Option<Candidate> {
        let marked = self.active_marker().exists();
        self.candidates(kind).into_iter().find(|c| (c.tier != Tier::User || marked) && c.path.exists())
    }

    pub fn resolve_panels(&self) -> Option<PathBuf> {
        self.resolve_read(Kind::Panels).map(|c| c.path)
    }

    pub fn resolve_env(&self) -> Option<PathBuf> {
        self.resolve_read(Kind::Env).map(|c| c.path)
    }

    /// A directory that rides with whichever config tier wins.
    fn tier_sibling(&self, explicit: Option<&str>, basename: &str) -> PathBuf {
        if let Some(dir) = explicit {
            return self.abs(dir);
        }
        if self.active_marker().exists() {
            return self.user_dir().join(basename);
        }
        let etc = self.etc_dir();
        if etc.is_dir() {
            return etc.join(basename);
        }
        self.repo_root().join("dev").join("run").join(basename)
    }

    /// Where the sealed master lives: next to the winning config tier, so a
    /// user-dir fallback keeps its (host- and user-bound) secret beside its
    /// `panels.yaml`. Always a path; the caller may need to create it.
    pub fn resolve_secret_dir(&self) -> PathBuf {
        self.tier_sibling(self.secret_dir.as_deref(), SECRET_BASENAME)
    }

    /// Where persistent panel web data (cookies, storage, cache) lives. It
    /// holds session tokens, so the caller creates it 0700. A sibling of the
    /// secret dir — never inside it.
    pub fn resolve_webdata_dir(&self) -> PathBuf {
        self.tier_sibling(self.webdata_dir.as_deref(), WEBDATA_BASENAME)
    }

    /// [`PathEnv::resolve_write_with`] asking the kernel what is writable.
    pub fn resolve_write(&self, kind: Kind, want_etc: bool, can_escalate: bool) -> WriteTarget {
        self.resolve_write_with(kind, want_etc, can_escalate, &fsutil::dir_writable)
    }

    /// Pick the highest-precedence location the caller can create and write,
    /// so that [`PathEnv::resolve_read`] then returns exactly what was written.
    ///
    /// Order, first match wins:
    /// - the explicit override, when its directory is writable;
    /// - `/etc` when writable, or when `can_escalate` (then
    ///   `needs_privilege`);
    /// - the checkout, when `/etc` is not wanted and this is a checkout;
    /// - the user dir, with the marker that activates it.
    pub fn resolve_write_with(
        &self,
        kind: Kind,
        want_etc: bool,
        can_escalate: bool,
        writable: &dyn Fn(&Path) -> bool,
    ) -> WriteTarget {
        let private_mode = if kind == Kind::Panels { 0o644 } else { 0o600 };
        let target = |path: PathBuf, mode: u32, via: Via| {
            let dir = path.parent().map_or_else(|| PathBuf::from("/"), Path::to_path_buf);
            WriteTarget { path, dir, mode, needs_privilege: false, via, marker: None, unwritable: false }
        };

        if let Some(path) = self.override_for(kind) {
            if path.parent().is_some_and(writable) {
                return target(path, 0o644, Via::Env);
            }
        }

        if want_etc {
            let etc = self.etc_dir();
            let etc_writable = writable(&etc);
            if etc_writable || can_escalate {
                let mut t = target(etc.join(kind.basename()), 0o644, Via::Etc);
                t.needs_privilege = !etc_writable;
                return t;
            }
        }

        let root = self.repo_root();
        let [repo_path, _] = self.repo_candidates(kind);
        let in_checkout = root.join("kiosk-host").is_dir() || root.join("rust").is_dir();
        if !want_etc && in_checkout && repo_path.parent().is_some_and(writable) {
            return target(repo_path, private_mode, Via::Repo);
        }

        let user_dir = self.user_dir();
        let mut t = target(user_dir.join(kind.basename()), private_mode, Via::User);
        t.marker = Some(self.active_marker());
        t.unwritable = !writable(&user_dir);
        t
    }

    /// The write target the wizard's shell wrapper and the wizard itself agree
    /// on, honouring `$SOC_FORCE_ETC` / `$SOC_ALLOW_PKEXEC`.
    pub fn write_target(&self, kind: Kind) -> WriteTarget {
        let want_etc = self.force_etc.as_deref() != Some("0");
        let can_escalate = self.allow_pkexec.as_deref() == Some("1");
        self.resolve_write(kind, want_etc, can_escalate)
    }

    /// The candidate chain, the winner and why, for both kinds.
    pub fn explain(&self) -> String {
        let marker = self.active_marker();
        let state = if marker.exists() { "present -> user config active" } else { "absent -> /etc wins" };
        let mut out = format!("user marker: {} ({state})\n", marker.display());
        for kind in Kind::ALL {
            let winner = self.resolve_read(kind);
            let (shown, label) = match &winner {
                Some(c) => (c.path.display().to_string(), c.label.as_str()),
                None => ("(none)".to_string(), "none"),
            };
            out.push_str(&format!("\n[{}] resolves to: {shown}  <- {label}\n", kind.as_str()));
            for c in self.candidates(kind) {
                let mark = if winner.as_ref().is_some_and(|w| w.path == c.path) { "  *" } else { "   " };
                let exists = if c.path.exists() { "exists" } else { "missing" };
                out.push_str(&format!("{mark} {:32} {exists:8} {}\n", c.label, c.path.display()));
            }
        }
        out.push_str(&format!("\nsecret_dir resolves to: {}\n", self.resolve_secret_dir().display()));
        out.push_str(&format!("webdata_dir resolves to: {}\n", self.resolve_webdata_dir().display()));
        out
    }

    /// Structural self-check of the resolver: every inconsistency found.
    pub fn check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for kind in Kind::ALL {
            let name = kind.as_str();
            let cands = self.candidates(kind);
            if cands.is_empty() {
                problems.push(format!("{name}: empty candidate chain"));
            }
            // A user-dir write must carry the marker the read tier is gated on,
            // or it would be written and then never read.
            let w = self.resolve_write(kind, false, false);
            if w.via == Via::User && w.marker.is_none() {
                problems.push(format!("{name}: user-dir write target lacks a marker (would be shadowed)"));
            }
            if !w.path.is_absolute() {
                problems.push(format!("{name}: write path not absolute: {}", w.path.display()));
            }
            if self.override_for(kind).is_some() && cands.first().is_none_or(|c| c.tier != Tier::Override) {
                problems.push(format!("{name}: {} set but not the top read candidate", kind.env_var()));
            }
        }
        problems
    }

    /// The privileged half of the wizard's `/etc` write: split a
    /// `---PANELS---` / `---ENV---` framed payload and install both files
    /// (0644, non-secret) into the system config directory.
    ///
    /// The payload arrives on stdin — never argv — so panel URLs never show
    /// on the process table. Both files are fully staged (written and
    /// fsynced) before either is swapped in, so a crash or ENOSPC cannot leave
    /// a new `panels.yaml` beside a stale `soc.env`.
    pub fn install_etc(&self, payload: &str) -> Result<String> {
        const PANELS_MARK: &str = "---PANELS---\n";
        const ENV_MARK: &str = "\n---ENV---\n";
        let split = payload.strip_prefix(PANELS_MARK).and_then(|body| body.split_once(ENV_MARK));
        let Some((panels_text, env_text)) = split else {
            return Err(SysError::Invalid("malformed STDIN (want ---PANELS---/---ENV--- markers)".into()));
        };
        let etc = self.etc_dir();
        let panels = etc.join(PANELS_BASENAME);
        let env = etc.join(ENV_BASENAME);
        let io = |e| SysError::io(format!("cannot install into {} (must run as root via pkexec)", etc.display()), e);
        fsutil::ensure_dir(&etc, 0o755).map_err(io)?;
        std::fs::set_permissions(&etc, std::os::unix::fs::PermissionsExt::from_mode(0o755)).map_err(io)?;
        let staged_panels = fsutil::stage(&panels, panels_text.as_bytes(), 0o644).map_err(io)?;
        let staged_env = fsutil::stage(&env, env_text.as_bytes(), 0o644).map_err(io)?;
        staged_panels.commit().map_err(io)?;
        staged_env.commit().map_err(io)?;
        Ok(format!("wrote {} (0644) and {} (0644)", panels.display(), env.display()))
    }

    /// The wall's per-user state directory (PIN digest, on-screen overrides).
    pub fn state_dir(&self) -> PathBuf {
        match &self.state_dir {
            Some(d) => self.abs(d),
            None => self.xdg_config_home().join("soc-wall"),
        }
    }

    /// [`PathEnv::state_dir`], created owner-only if missing: it holds the
    /// config PIN digest and internal host names.
    pub fn ensure_state_dir(&self) -> std::io::Result<PathBuf> {
        let dir = self.state_dir();
        fsutil::ensure_dir(&dir, 0o700)?;
        Ok(dir)
    }

    /// The on-screen configuration overrides file.
    pub fn overrides_path(&self) -> PathBuf {
        self.state_dir().join(OVERRIDES_BASENAME)
    }
}

/// The saved on-screen overrides; empty when the file is missing, unreadable
/// or not a JSON object (a damaged file must not stop the wall).
pub fn load_overrides(path: &Path) -> Dict {
    fsutil::read_capped(path, MAX_STATE_BYTES)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default() // audit-allow: default is the intended fallback (empty overrides)
}

/// Persist the overrides atomically, owner-only (panel URLs reveal internal
/// host names), fsynced so a power cut cannot leave a zero-length file.
pub fn save_overrides(path: &Path, overrides: &Dict) -> Result<()> {
    let text = jsonfmt::pretty_sorted(&serde_json::Value::Object(overrides.clone()));
    fsutil::write_atomic(path, text.as_bytes(), 0o600)
        .map_err(|e| SysError::io(format!("cannot save {}", path.display()), e))
}

const USAGE: &str = "usage: configpaths [--panels | --env | --secret-dir | --webdata-dir | --panels-write | \
--env-write | --write-target {panels,env} | --explain | --check | --install-etc]

Resolve the SOC-wall config read/write locations.

  --panels        print the resolved panels.yaml READ path
  --env           print the resolved soc.env READ path
  --secret-dir    print the resolved secret dir
  --webdata-dir   print the resolved web-data dir
  --panels-write  print the chosen panels.yaml WRITE path
  --env-write     print the chosen soc.env WRITE path
  --write-target  print the chosen WRITE path for the given kind
  --explain       print the candidate chain + winner
  --check         validate wiring (nonzero on inconsistency)
  --install-etc   pkexec helper: write /etc from STDIN (---PANELS---/---ENV---)
";

/// Write one line to a CLI stream. A closed pipe on the reporting stream is not
/// actionable here, so the result is dropped deliberately.
fn say(w: &mut dyn Write, line: std::fmt::Arguments<'_>) {
    let _ = writeln!(w, "{line}"); // audit-allow: best-effort, a closed CLI stream is not actionable
}

/// Write raw text to a CLI stream; same best-effort contract as [`say`].
fn put(w: &mut dyn Write, text: &str) {
    let _ = w.write_all(text.as_bytes()); // audit-allow: best-effort, a closed CLI stream is not actionable
}

/// The `configpaths` command the shell launchers call to stay in lock-step
/// with the wall. Exit status: 0 ok, 1 failure, 2 usage or malformed input,
/// 3 "nothing resolvable" (lets a script tell "no config" from "error").
pub fn configpaths_main(
    args: &[String],
    env: &PathEnv,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let mut flags: Vec<&str> = Vec::new();
    let mut write_kind = None;
    let mut it = args.iter().map(String::as_str);
    while let Some(arg) = it.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (arg, None),
        };
        match name {
            "-h" | "--help" => {
                put(out, USAGE);
                return 0;
            }
            "--write-target" => {
                let Some(kind) = inline.or_else(|| it.next()).and_then(Kind::parse) else {
                    say(err, format_args!("configpaths: --write-target needs 'panels' or 'env'"));
                    return 2;
                };
                write_kind = Some(kind);
            }
            "--panels" | "--env" | "--secret-dir" | "--webdata-dir" | "--panels-write" | "--env-write"
            | "--explain" | "--check" | "--install-etc"
                if inline.is_none() =>
            {
                flags.push(name);
            }
            _ => {
                say(err, format_args!("configpaths: unrecognized argument: {arg}"));
                return 2;
            }
        }
    }
    let has = |f: &str| flags.contains(&f);
    let print_read = |kind: Kind, out: &mut dyn Write| match env.resolve_read(kind) {
        Some(c) => {
            say(out, format_args!("{}", c.path.display()));
            0
        }
        None => 3,
    };
    let print_write = |kind: Kind, out: &mut dyn Write| {
        say(out, format_args!("{}", env.write_target(kind).path.display()));
        0
    };

    if has("--panels") {
        return print_read(Kind::Panels, out);
    }
    if has("--env") {
        return print_read(Kind::Env, out);
    }
    if has("--secret-dir") {
        say(out, format_args!("{}", env.resolve_secret_dir().display()));
        return 0;
    }
    if has("--webdata-dir") {
        say(out, format_args!("{}", env.resolve_webdata_dir().display()));
        return 0;
    }
    if has("--panels-write") {
        return print_write(Kind::Panels, out);
    }
    if has("--env-write") {
        return print_write(Kind::Env, out);
    }
    if let Some(kind) = write_kind {
        return print_write(kind, out);
    }
    if has("--explain") {
        put(out, &env.explain());
        return 0;
    }
    if has("--check") {
        let problems = env.check();
        for p in &problems {
            say(err, format_args!("configpaths --check: {p}"));
        }
        if problems.is_empty() {
            say(out, format_args!("configpaths --check: OK"));
        }
        return i32::from(!problems.is_empty());
    }
    if has("--install-etc") {
        let mut payload = String::new();
        let read = Read::take(&mut *stdin, MAX_STATE_BYTES + 1).read_to_string(&mut payload);
        let result = match read {
            Ok(_) if u64::try_from(payload.len()).map_or(true, |n| n > MAX_STATE_BYTES) => {
                Err(SysError::Invalid("STDIN payload too large".into()))
            }
            Ok(_) => env.install_etc(&payload),
            Err(e) => Err(SysError::Invalid(format!("unreadable STDIN ({e})"))),
        };
        return match result {
            Ok(msg) => {
                say(out, format_args!("{msg}"));
                0
            }
            Err(e) => {
                say(err, format_args!("configpaths --install-etc: {e}"));
                if matches!(e, SysError::Invalid(_)) { 2 } else { 1 }
            }
        };
    }
    put(out, USAGE);
    0
}

/// [`configpaths_main`] on the process environment and standard streams.
pub fn configpaths_cli(args: &[String]) -> i32 {
    let (mut stdin, mut out, mut err) = (std::io::stdin().lock(), std::io::stdout().lock(), std::io::stderr().lock());
    configpaths_main(args, &PathEnv::from_process(), &mut stdin, &mut out, &mut err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    /// xdg (user dir), checkout root and the system dir all redirected into a
    /// scratch directory, so resolution is hermetic.
    fn sandbox(tag: &str) -> (TempDir, PathEnv) {
        let t = TempDir::new(tag);
        let repo = t.path().join("repo");
        std::fs::create_dir_all(repo.join("kiosk-host")).unwrap();
        std::fs::create_dir_all(repo.join("config")).unwrap();
        let env = PathEnv {
            cwd: t.path().to_path_buf(),
            home: t.path().join("home"),
            xdg_config_home: Some(t.path().join("xdg").display().to_string()),
            etc_dir: Some(t.path().join("etc-soc").display().to_string()),
            root: Some(repo.display().to_string()),
            default_root: PathBuf::from(DEPLOY_ROOT_DEFAULT),
            panels_file: None,
            env_file: None,
            secret_dir: None,
            webdata_dir: None,
            state_dir: None,
            force_etc: None,
            allow_pkexec: None,
        };
        (t, env)
    }

    fn touch(p: &Path, text: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn etc_locked(env: &PathEnv) -> impl Fn(&Path) -> bool + use<> {
        let etc = env.etc_dir();
        move |d: &Path| d != etc
    }

    #[test]
    fn env_override_is_absolute_authority() {
        let (t, mut env) = sandbox("paths-override");
        let pinned = t.write("pinned.yaml", "x");
        touch(&env.etc_dir().join(PANELS_BASENAME), "etc");
        env.panels_file = Some(pinned.display().to_string());
        let c = env.resolve_read(Kind::Panels).unwrap();
        assert_eq!(c.path, pinned);
        assert_eq!(c.label, "$SOC_PANELS_FILE");
    }

    #[test]
    fn a_relative_override_is_resolved_against_the_working_directory() {
        let (t, mut env) = sandbox("paths-relative");
        t.write("sub/p.yaml", "x");
        env.panels_file = Some("sub/../sub/p.yaml".into());
        assert_eq!(env.resolve_panels().unwrap(), t.path().join("sub/p.yaml"));
    }

    #[test]
    fn etc_wins_when_no_marker() {
        let (_t, env) = sandbox("paths-etc");
        let etc_p = env.etc_dir().join(PANELS_BASENAME);
        touch(&etc_p, "etc");
        touch(&env.user_dir().join(PANELS_BASENAME), "user"); // present but unmarked: ignored
        let c = env.resolve_read(Kind::Panels).unwrap();
        assert_eq!(c.path, etc_p);
        assert_eq!(c.label, "/etc/soc-display");
    }

    #[test]
    fn marked_user_beats_etc() {
        let (_t, env) = sandbox("paths-marked");
        let user_p = env.user_dir().join(PANELS_BASENAME);
        touch(&env.etc_dir().join(PANELS_BASENAME), "etc");
        touch(&user_p, "user");
        touch(&env.active_marker(), "x\n");
        let c = env.resolve_read(Kind::Panels).unwrap();
        assert_eq!(c.path, user_p);
        assert_eq!(c.label, "user config (active)");
    }

    #[test]
    fn repo_fallback_when_nothing_else() {
        let (_t, env) = sandbox("paths-repo");
        let repo_p = env.repo_root().join("config/panels.local.yaml");
        touch(&repo_p, "repo");
        touch(&env.repo_root().join("config/panels.yaml"), "template");
        let c = env.resolve_read(Kind::Panels).unwrap();
        assert_eq!(c.path, repo_p);
        assert_eq!(c.label, "repo fallback");
        touch(&env.repo_root().join("config/soc.env.example"), "example");
        assert_eq!(env.resolve_env().unwrap(), env.repo_root().join("config/soc.env.example"));
        touch(&env.repo_root().join(".env"), "real");
        assert_eq!(env.resolve_env().unwrap(), env.repo_root().join(".env"));
    }

    #[test]
    fn none_when_nothing_exists() {
        let (_t, env) = sandbox("paths-none");
        assert_eq!(env.resolve_read(Kind::Panels), None);
    }

    #[test]
    fn a_relative_xdg_config_home_is_ignored() {
        let (_t, mut env) = sandbox("paths-xdg");
        env.xdg_config_home = Some("relative/dir".into());
        assert_eq!(env.user_dir(), env.home.join(".config/soc-display"));
        assert_eq!(env.state_dir(), env.home.join(".config/soc-wall"));
    }

    #[test]
    fn write_lands_in_etc_when_writable() {
        let (_t, env) = sandbox("paths-write-etc");
        std::fs::create_dir_all(env.etc_dir()).unwrap();
        let w = env.resolve_write(Kind::Panels, true, false);
        assert_eq!(w.via, Via::Etc);
        assert_eq!(w.marker, None);
        assert_eq!(w.path, env.etc_dir().join(PANELS_BASENAME));
        assert_eq!(w.dir, env.etc_dir());
        assert_eq!(w.mode, 0o644);
        assert!(!w.needs_privilege);
    }

    #[test]
    fn write_falls_back_to_user_with_marker() {
        let (_t, env) = sandbox("paths-write-user");
        let writable = etc_locked(&env);
        let w = env.resolve_write_with(Kind::Panels, true, false, &writable);
        assert_eq!(w.via, Via::User);
        assert_eq!(w.marker, Some(env.active_marker()));
        assert_eq!(w.mode, 0o644);
        assert!(!w.unwritable);
        let ew = env.resolve_write_with(Kind::Env, true, false, &writable);
        assert_eq!(ew.mode, 0o600, "env is owner-only in the user dir");
    }

    #[test]
    fn write_equals_read_invariant() {
        let (_t, env) = sandbox("paths-invariant");
        let writable = etc_locked(&env);
        for kind in Kind::ALL {
            let w = env.resolve_write_with(kind, true, false, &writable);
            touch(&w.path, "written");
            if let Some(marker) = &w.marker {
                touch(marker, "x\n");
            }
            assert_eq!(env.resolve_read(kind).unwrap().path, w.path, "{kind:?}");
        }
    }

    #[test]
    fn escalation_keeps_etc_target() {
        let (_t, env) = sandbox("paths-escalate");
        let w = env.resolve_write_with(Kind::Panels, true, true, &etc_locked(&env));
        assert_eq!(w.via, Via::Etc);
        assert!(w.needs_privilege);
        assert_eq!(w.marker, None);
    }

    #[test]
    fn override_is_the_write_target_when_its_directory_is_writable() {
        let (t, mut env) = sandbox("paths-write-override");
        env.env_file = Some(t.path().join("pinned/soc.env").display().to_string());
        let w = env.resolve_write(Kind::Env, true, false);
        assert_eq!(w.via, Via::Env);
        assert_eq!(w.path, t.path().join("pinned/soc.env"));
        let locked = env.resolve_write_with(Kind::Env, true, true, &|_| false);
        assert_eq!(locked.via, Via::Etc, "an unwritable override falls through");
    }

    #[test]
    fn checkout_is_the_target_only_when_etc_is_not_wanted() {
        let (_t, env) = sandbox("paths-write-repo");
        let w = env.resolve_write(Kind::Env, false, false);
        assert_eq!(w.via, Via::Repo);
        assert_eq!(w.path, env.repo_root().join(".env"));
        assert_eq!(w.mode, 0o600);
        let p = env.resolve_write(Kind::Panels, false, false);
        assert_eq!(p.path, env.repo_root().join("config/panels.local.yaml"));
    }

    #[test]
    fn user_tier_flags_unwritable() {
        let (_t, env) = sandbox("paths-unwritable");
        let w = env.resolve_write_with(Kind::Panels, true, false, &|_| false);
        assert_eq!(w.via, Via::User);
        assert!(w.unwritable);
    }

    #[test]
    fn secret_and_webdata_dirs_ride_with_the_winning_tier() {
        let (_t, mut env) = sandbox("paths-secret");
        assert_eq!(env.resolve_secret_dir(), env.repo_root().join("dev/run/secret"));
        std::fs::create_dir_all(env.etc_dir()).unwrap();
        assert_eq!(env.resolve_secret_dir(), env.etc_dir().join("secret"));
        assert_eq!(env.resolve_webdata_dir(), env.etc_dir().join("webdata"));
        touch(&env.active_marker(), "x\n");
        assert_eq!(env.resolve_secret_dir(), env.user_dir().join("secret"));
        assert_eq!(env.resolve_webdata_dir(), env.user_dir().join("webdata"));
        env.secret_dir = Some("/custom/secret".into());
        assert_eq!(env.resolve_secret_dir(), Path::new("/custom/secret"));
    }

    fn cli(env: &PathEnv, args: &[&str], stdin: &str) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc = configpaths_main(&args, env, &mut stdin.as_bytes(), &mut out, &mut err);
        (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    #[test]
    fn cli_exit_codes() {
        let (_t, env) = sandbox("paths-cli");
        assert_eq!(cli(&env, &["--panels"], "").0, 3);
        let etc_p = env.etc_dir().join(PANELS_BASENAME);
        touch(&etc_p, "x");
        assert_eq!(cli(&env, &["--panels"], ""), (0, format!("{}\n", etc_p.display()), String::new()));
        let (rc, out, _) = cli(&env, &["--check"], "");
        assert_eq!((rc, out.as_str()), (0, "configpaths --check: OK\n"));
        let (rc, out, _) = cli(&env, &["--explain"], "");
        assert_eq!(rc, 0);
        assert!(out.contains("[panels] resolves to:") && out.contains("  * /etc/soc-display"), "{out}");
        assert!(out.contains("user config (inactive: no marker) missing "), "{out}");
        assert_eq!(cli(&env, &["--bogus"], "").0, 2);
        assert_eq!(cli(&env, &["--write-target", "nope"], "").0, 2);
        let (rc, out, _) = cli(&env, &["--write-target=env"], "");
        assert_eq!((rc, out), (0, format!("{}\n", env.etc_dir().join(ENV_BASENAME).display())));
        assert_eq!(cli(&env, &[], "").0, 0);
    }

    #[test]
    fn write_target_honours_force_etc() {
        let (_t, mut env) = sandbox("paths-force-etc");
        std::fs::create_dir_all(env.etc_dir()).unwrap();
        assert_eq!(env.write_target(Kind::Panels).via, Via::Etc);
        env.force_etc = Some("0".into());
        assert_eq!(env.write_target(Kind::Panels).via, Via::Repo);
    }

    #[test]
    fn install_etc_rejects_malformed_stdin_and_writes_nothing() {
        let (_t, env) = sandbox("paths-install-bad");
        let (rc, _, err) = cli(&env, &["--install-etc"], "garbage");
        assert_eq!(rc, 2);
        assert!(err.contains("malformed STDIN"), "{err}");
        assert!(!env.etc_dir().exists());
    }

    #[test]
    fn install_etc_writes_both_files_world_readable() {
        let (_t, env) = sandbox("paths-install");
        let (rc, out, err) = cli(&env, &["--install-etc"], "---PANELS---\npanels: []\n\n---ENV---\nSOC_X=1\n");
        assert_eq!(rc, 0, "{err}");
        assert!(out.starts_with("wrote "), "{out}");
        let etc = env.etc_dir();
        assert_eq!(std::fs::read_to_string(etc.join(PANELS_BASENAME)).unwrap(), "panels: []\n");
        assert_eq!(std::fs::read_to_string(etc.join(ENV_BASENAME)).unwrap(), "SOC_X=1\n");
        for name in [PANELS_BASENAME, ENV_BASENAME] {
            assert_eq!(std::fs::metadata(etc.join(name)).unwrap().permissions().mode() & 0o777, 0o644);
        }
        let mut names: Vec<_> = std::fs::read_dir(&etc).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        assert_eq!(names, [PANELS_BASENAME, ENV_BASENAME], "no temp files left behind");
    }

    #[test]
    fn install_etc_failure_leaves_the_previous_pair_intact() {
        let (t, mut env) = sandbox("paths-install-fail");
        // The system "directory" is a regular file: nothing can be staged in it.
        let blocker = t.write("blocker", "x");
        env.etc_dir = Some(blocker.display().to_string());
        let (rc, _, err) = cli(&env, &["--install-etc"], "---PANELS---\na\n---ENV---\nb");
        assert_eq!(rc, 1);
        assert!(err.contains("must run as root via pkexec"), "{err}");
        assert_eq!(std::fs::read_to_string(&blocker).unwrap(), "x");
    }

    #[test]
    fn overrides_round_trip_owner_only() {
        let (_t, env) = sandbox("paths-overrides");
        let dir = env.ensure_state_dir().unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let path = env.overrides_path();
        assert!(load_overrides(&path).is_empty());
        let saved = crate::testutil::dict(serde_json::json!({"p2": {"url": "http://h/"}, "_vpns": [], "a": 1}));
        save_overrides(&path, &saved).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\n  \"_vpns\": [],\n  \"a\": 1,\n  \"p2\""), "{text}");
        assert_eq!(load_overrides(&path), saved);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no temp file left behind");
    }

    #[test]
    fn damaged_overrides_read_as_empty() {
        let (t, _env) = sandbox("paths-overrides-bad");
        for body in ["{not json", "", "[1, 2]", "null"] {
            assert!(load_overrides(&t.write("o.json", body)).is_empty(), "{body:?}");
        }
    }
}
