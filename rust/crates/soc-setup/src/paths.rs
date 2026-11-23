//! Where setup writes, derived from the shared resolver (`soc_sys::paths`) so
//! that what is written is exactly what the wall reads.

use crate::error::{Result, SetupError};
use crate::util::utc_stamp;
use soc_sys::fsutil;
use soc_sys::paths::{DEPLOY_ROOT_DEFAULT, Kind, PathEnv};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The write target selected by `--target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The deployed layout (`/etc/soc-display`, or the per-user fallback).
    Pi,
    /// The repository checkout (`config/panels.local.yaml`, `.env`).
    Dev,
}

impl Target {
    pub fn parse(s: &str) -> Option<Target> {
        match s {
            "pi" => Some(Target::Pi),
            "dev" => Some(Target::Dev),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Target::Pi => "pi",
            Target::Dev => "dev",
        }
    }

    /// The target when `--target` is not given. A bare dev checkout keeps
    /// `dev`; on a deployed box even a non-root user gets `pi`, so the config
    /// lands where the wall reads it (the per-user fallback + marker).
    pub fn default_for(is_root: bool, penv: &PathEnv) -> Target {
        let deployed = penv.etc_dir().is_dir() || Path::new(DEPLOY_ROOT_DEFAULT).is_dir();
        if is_root || deployed { Target::Pi } else { Target::Dev }
    }
}

/// Every location the setup flow touches (the Python `resolve_paths` dict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPaths {
    pub target: Target,
    /// `env | etc | user | repo`.
    pub via: String,
    pub marker: Option<PathBuf>,
    pub needs_privilege: bool,
    pub panels_out: PathBuf,
    pub panels_installed: PathBuf,
    pub soc_env: PathBuf,
    /// The systemd unit to write; `None` for a per-user desktop wall.
    pub wall_unit: Option<PathBuf>,
    pub soc_root: PathBuf,
    pub pinentry: PathBuf,
    pub secret_dir: PathBuf,
    pub config_vault_item: String,
    pub inject_tmpl: PathBuf,
    pub default_backend: String,
    pub configured_marker: PathBuf,
    pub panels_mode: u32,
    pub env_mode: u32,
}

impl SetupPaths {
    /// Resolve the write locations for `target`.
    pub fn resolve(target: Target, penv: &PathEnv, can_escalate: bool) -> SetupPaths {
        if target == Target::Dev {
            let repo = penv.repo_root();
            let run = repo.join("dev").join("run");
            return SetupPaths {
                target,
                via: "repo".into(),
                marker: None,
                needs_privilege: false,
                panels_out: repo.join("config").join("panels.local.yaml"),
                panels_installed: repo.join("config").join("panels.local.yaml"),
                soc_env: repo.join(".env"),
                wall_unit: Some(run.join("soc-wall.service")),
                soc_root: repo.clone(),
                pinentry: repo.join("scripts").join("pinentry-vault.sh"),
                secret_dir: run.join("secret"),
                config_vault_item: "SOC Wall Config".into(),
                inject_tmpl: repo.join("inject").join("login.js.tmpl"),
                default_backend: "dev".into(),
                configured_marker: run.join(".configured"),
                panels_mode: 0o644,
                env_mode: 0o600,
            };
        }
        let pw = penv.resolve_write(Kind::Panels, true, can_escalate);
        let ew = penv.resolve_write(Kind::Env, true, can_escalate);
        let via = pw.via.as_str();
        let system = matches!(via, "etc" | "env");
        let (soc_root, secret_dir, wall_unit, inject_tmpl) = if system {
            (
                PathBuf::from(DEPLOY_ROOT_DEFAULT),
                penv.etc_dir().join("secret"),
                Some(PathBuf::from("/etc/systemd/system/soc-wall.service")),
                Path::new(DEPLOY_ROOT_DEFAULT).join("inject").join("login.js.tmpl"),
            )
        } else {
            // Per-user fallback: the sealed master lives where THIS user can
            // read it; no systemd unit (a per-user wall is launched from the menu).
            let root = if Path::new(DEPLOY_ROOT_DEFAULT).is_dir() {
                PathBuf::from(DEPLOY_ROOT_DEFAULT)
            } else {
                penv.repo_root()
            };
            let tmpl = root.join("inject").join("login.js.tmpl");
            (root, penv.user_dir().join("secret"), None, tmpl)
        };
        let panels_dir = pw.path.parent().map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        SetupPaths {
            target,
            via: via.into(),
            marker: pw.marker.clone(),
            needs_privilege: pw.needs_privilege,
            panels_out: pw.path.clone(),
            panels_installed: pw.path.clone(),
            soc_env: ew.path.clone(),
            wall_unit,
            pinentry: soc_root.join("scripts").join("pinentry-vault.sh"),
            soc_root,
            secret_dir,
            config_vault_item: "SOC Wall Config".into(),
            inject_tmpl,
            default_backend: "litebw".into(),
            configured_marker: panels_dir.join(".configured"),
            panels_mode: pw.mode,
            env_mode: ew.mode,
        }
    }

    /// The install stamp `install.sh` leaves next to `soc.env`.
    pub fn install_stamp(&self) -> PathBuf {
        self.soc_env.parent().map_or_else(|| PathBuf::from(".installed"), |d| d.join(".installed"))
    }
}

/// True once this host has been set up; the first-boot page only runs while
/// the marker is absent.
pub fn is_configured(paths: &SetupPaths) -> bool {
    paths.configured_marker.exists()
}

/// Drop the "configured" marker so the wall starts directly from now on.
pub fn mark_configured(paths: &SetupPaths, dry: bool) -> Result<()> {
    if dry {
        return Ok(());
    }
    let m = &paths.configured_marker;
    let body = format!("configured={}\n", utc_stamp(SystemTime::now()));
    fsutil::write_atomic(m, body.as_bytes(), 0o644).map_err(|e| SetupError::io("cannot mark configured", m, e))
}

/// When the wizard fell back to the per-user dir, write the `active` marker so
/// the reader's marker-gated user tier picks this file up over a stale `/etc`.
/// The marker records the claimed path, a timestamp and the writer's uid.
pub fn drop_marker(paths: &SetupPaths, dry: bool) -> Result<Option<PathBuf>> {
    let Some(marker) = &paths.marker else { return Ok(None) };
    if dry {
        return Ok(Some(marker.clone()));
    }
    if let Some(dir) = marker.parent() {
        fsutil::ensure_dir(dir, 0o700).map_err(|e| SetupError::io("cannot create", dir, e))?;
    }
    let body = format!(
        "{}\n# activated {} by uid {}\n",
        paths.panels_out.display(),
        utc_stamp(SystemTime::now()),
        fsutil::euid()
    );
    fsutil::write_atomic(marker, body.as_bytes(), 0o644).map_err(|e| SetupError::io("cannot write", marker, e))?;
    Ok(Some(marker.clone()))
}

/// Write `content` to `path` (parent created, old file backed up, atomic, `mode`
/// set before the content is visible). Returns the path actually written: when
/// the target directory is not writable by this user the file goes to the
/// per-user config dir instead and the marker is dropped, as the wizard did.
pub fn write_file(penv: &PathEnv, path: &Path, content: &str, mode: u32) -> Result<PathBuf> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let _ = fs::create_dir_all(parent); // audit-allow: a failure surfaces at the write below with the real cause
    let mut dest = path.to_path_buf();
    if !fsutil::access_writable(parent) {
        let alt = penv.user_dir();
        fsutil::ensure_dir(&alt, 0o700).map_err(|e| SetupError::io("cannot create", &alt, e))?;
        dest = alt.join(path.file_name().unwrap_or_default()); // audit-allow: a path with no file name writes an empty-named file, which then fails loudly
        let marker = penv.active_marker();
        if let Some(dir) = marker.parent() {
            let _ = fsutil::ensure_dir(dir, 0o700); // audit-allow: best effort, as in the original
        }
        let body =
            format!("{}\n# activated {} by uid {}\n", dest.display(), utc_stamp(SystemTime::now()), fsutil::euid());
        let _ = fsutil::write_atomic(&marker, body.as_bytes(), 0o644); // audit-allow: best effort, as in the original
    }
    crate::envfile::backup(&dest);
    fsutil::write_atomic(&dest, content.as_bytes(), mode).map_err(|e| SetupError::io("cannot write", &dest, e))?;
    Ok(dest)
}
