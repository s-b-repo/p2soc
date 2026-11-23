//! Liveness heartbeat for the kiosk host.
//!
//! A process that is alive is not a wall that is working: a wedged main loop
//! leaves the host running forever while the screen is frozen, and on an
//! unattended box nobody notices. So the host calls [`write`] from a timer
//! *on the main loop* — if the loop hangs, the heartbeat stops, and that
//! absence is the signal. Two independent readers depend on the file: the
//! launcher restarts a host whose heartbeat has gone stale, and the updater
//! rolls a freshly activated release back if it never becomes healthy.
//!
//! The file lives on tmpfs, so the 15 s cadence costs no SD wear. The
//! document:
//!
//! ```json
//! {"ts": 1730000000.0, "pid": 1234, "commit": "<sha>",
//!  "panels_total": 4, "panels_ok": 3, "state": "running"}
//! ```
//!
//! `state` is free-form, but `running` means the wall is up; a fail-safe
//! screen uses another value so the updater can tell "alive but not showing
//! panels" apart.

use crate::fsutil::{self, access_writable};
use crate::manifest::read_commit_marker;
use serde_json::{Value, json};
use soc_core::Dict;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_DIR: &str = "/run/soc-wall";
pub const FILE_NAME: &str = "heartbeat.json";

/// The environment inputs that decide where the heartbeat lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatEnv {
    /// `$SOC_HEARTBEAT_FILE`.
    pub explicit: Option<String>,
    /// The deployed location's directory.
    pub default_dir: PathBuf,
    /// `$XDG_RUNTIME_DIR`.
    pub runtime_dir: Option<String>,
    /// The system temp directory.
    pub tmp_dir: PathBuf,
    pub uid: u32,
}

impl HeartbeatEnv {
    pub fn from_process() -> HeartbeatEnv {
        let var = |name: &str| std::env::var(name).ok();
        HeartbeatEnv {
            explicit: var("SOC_HEARTBEAT_FILE"),
            default_dir: PathBuf::from(DEFAULT_DIR),
            runtime_dir: var("XDG_RUNTIME_DIR"),
            tmp_dir: std::env::temp_dir(),
            uid: fsutil::euid(),
        }
    }
}

/// Where this host's heartbeat lives. `$SOC_HEARTBEAT_FILE` wins (the
/// launcher exports it so supervisor and host can never disagree); otherwise
/// `/run/soc-wall` when it is writable (the deployed kiosk), then the
/// per-user runtime dir, so a desktop or dev run works with no system setup.
pub fn path_from(env: &HeartbeatEnv, writable: &dyn Fn(&Path) -> bool) -> PathBuf {
    let set = |v: &Option<String>| v.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    if let Some(explicit) = set(&env.explicit) {
        return PathBuf::from(explicit);
    }
    if writable(&env.default_dir) {
        return env.default_dir.join(FILE_NAME);
    }
    if let Some(runtime) = set(&env.runtime_dir) {
        return Path::new(&runtime).join("soc-wall").join(FILE_NAME);
    }
    env.tmp_dir.join(format!("soc-wall-{}", env.uid)).join(FILE_NAME)
}

/// [`path_from`] on the process environment.
pub fn path() -> PathBuf {
    path_from(&HeartbeatEnv::from_process(), &access_writable)
}

/// The commit this code was deployed from (`<root>/.commit`), or `""`. The
/// release a process was started from cannot change underneath it, so callers
/// read this once.
pub fn deployed_commit(root: &Path) -> String {
    read_commit_marker(root).unwrap_or_default() // audit-allow: default is the intended fallback (no marker means "")
}

/// Seconds since the Unix epoch.
pub fn now_ts() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// One heartbeat document.
#[derive(Debug, Clone, PartialEq)]
pub struct Beat {
    pub ts: f64,
    pub pid: u32,
    pub commit: String,
    pub panels_total: u64,
    pub panels_ok: u64,
    pub state: String,
}

impl Beat {
    /// A beat for this process, stamped now.
    pub fn now(panels_total: u64, panels_ok: u64, state: &str, commit: &str) -> Beat {
        Beat {
            ts: now_ts(),
            pid: std::process::id(),
            commit: commit.to_string(),
            panels_total,
            panels_ok,
            state: state.to_string(),
        }
    }

    pub fn to_json(&self) -> String {
        json!({
            "ts": self.ts,
            "pid": self.pid,
            "commit": self.commit,
            "panels_total": self.panels_total,
            "panels_ok": self.panels_ok,
            "state": self.state,
        })
        .to_string()
    }
}

/// The heartbeat's directory must be one nobody else can redirect: a real
/// directory (not a symlink), owned by us or root, and not world-writable
/// unless sticky. The fallback location is under the shared `/tmp`, where
/// another user can pre-create the predictable `soc-wall-<uid>` name.
fn trusted_dir(dir: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    let ours = meta.uid() == fsutil::euid() || meta.uid() == 0;
    let world_writable = meta.mode() & 0o002 != 0 && meta.mode() & 0o1000 == 0;
    meta.is_dir() && ours && !world_writable
}

/// Publish a heartbeat atomically (0644). Returns `false` — never an error —
/// if it cannot be written: a full tmpfs must not take the wall down with it.
pub fn write(dest: &Path, beat: &Beat) -> bool {
    let Some(dir) = dest.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return false;
    };
    if fsutil::ensure_dir(dir, 0o755).is_err() || !trusted_dir(dir) {
        return false;
    }
    fsutil::write_atomic(dest, beat.to_json().as_bytes(), 0o644).is_ok()
}

/// The last heartbeat, or `None` if there is none or it is unreadable.
pub fn read(src: &Path) -> Option<Dict> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fsutil::open_regular(src).ok()?.take(4097).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    serde_json::from_slice::<Value>(&bytes).ok()?.as_object().cloned()
}

/// Seconds since a heartbeat was written; infinity when there is none or it
/// is malformed (including a non-finite timestamp), so "no data" can never
/// read as "fresh". Never negative: a clock that stepped back reads as zero.
pub fn age(doc: Option<&Dict>, now: f64) -> f64 {
    let ts = match doc.and_then(|d| d.get("ts")) {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    match ts {
        Some(ts) if ts.is_finite() && now.is_finite() => (now - ts).max(0.0),
        _ => f64::INFINITY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, dict};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn beat(total: u64, ok: u64, state: &str) -> Beat {
        Beat::now(total, ok, state, "abc1234")
    }

    #[test]
    fn write_is_atomic_and_leaves_no_temp_file() {
        let t = TempDir::new("hb-write");
        let dest = t.path().join("sub/hb.json");
        assert!(write(&dest, &beat(4, 3, "running")));
        let doc = read(&dest).unwrap();
        assert_eq!(doc["panels_total"], 4);
        assert_eq!(doc["panels_ok"], 3);
        assert_eq!(doc["state"], "running");
        assert_eq!(doc["pid"], std::process::id());
        assert_eq!(doc["commit"], "abc1234");
        assert!(age(Some(&doc), now_ts()) < 60.0);
        let names: Vec<_> =
            std::fs::read_dir(dest.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["hb.json"]);
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o644);
    }

    #[test]
    fn document_keeps_the_reference_key_order_and_float_timestamp() {
        let b =
            Beat { ts: 1_730_000_000.0, pid: 7, commit: "c".into(), panels_total: 4, panels_ok: 3, state: "s".into() };
        assert_eq!(
            b.to_json(),
            r#"{"ts":1730000000.0,"pid":7,"commit":"c","panels_total":4,"panels_ok":3,"state":"s"}"#
        );
    }

    #[test]
    fn a_failed_write_keeps_the_old_doc_and_cleans_up() {
        let t = TempDir::new("hb-fail");
        let dest = t.path().join("hb.json");
        assert!(write(&dest, &beat(1, 1, "old")));
        // A directory in the way of the rename: the swap fails after staging.
        let blocked = t.path().join("blocked");
        std::fs::create_dir_all(blocked.join("hb.json/occupied")).unwrap();
        assert!(!write(&blocked.join("hb.json"), &beat(9, 9, "new")));
        assert_eq!(std::fs::read_dir(&blocked).unwrap().count(), 1, "the temp file was removed");
        assert_eq!(read(&dest).unwrap()["state"], "old");
    }

    #[test]
    fn unwritable_dir_returns_false_never_panics() {
        let t = TempDir::new("hb-unwritable");
        // A file where the directory should be: fails for root as well.
        let blocker = t.write("blocker", "x");
        assert!(!write(&blocker.join("hb.json"), &beat(1, 1, "running")));
        // A bare file name has no directory to vet: refused, never written to the cwd.
        assert!(!write(Path::new("soc-sys-test-hb.json"), &beat(1, 1, "running")));
    }

    #[test]
    fn refuses_a_symlinked_or_world_writable_directory() {
        let t = TempDir::new("hb-untrusted");
        let real = t.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = t.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(!write(&link.join("hb.json"), &beat(1, 1, "running")));
        assert!(!real.join("hb.json").exists(), "nothing was written through the link");

        let open = t.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(!write(&open.join("hb.json"), &beat(1, 1, "running")));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(write(&open.join("hb.json"), &beat(1, 1, "running")), "a sticky directory is safe to rename in");
    }

    #[test]
    fn a_planted_symlink_at_the_destination_is_replaced_not_followed() {
        let t = TempDir::new("hb-planted");
        let victim = t.write("victim", "precious");
        let dest = t.path().join("hb.json");
        symlink(&victim, &dest).unwrap();
        assert!(write(&dest, &beat(1, 1, "running")));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert!(read(&dest).is_some());
    }

    #[test]
    fn read_of_garbage_or_nothing_is_none() {
        let t = TempDir::new("hb-garbage");
        for body in ["{not json", "", "[1, 2]", "\"text\"", "null"] {
            assert_eq!(read(&t.write("hb.json", body)), None, "{body:?}");
        }
        assert_eq!(read(&t.path().join("nope.json")), None);
    }

    #[test]
    fn age_of_missing_or_malformed_doc_is_infinite() {
        assert_eq!(age(None, 1.0), f64::INFINITY);
        for doc in [
            serde_json::json!({}),
            serde_json::json!({"ts": "soon"}),
            serde_json::json!({"ts": null}),
            serde_json::json!({"ts": true}),
            serde_json::json!({"ts": "nan"}),
            serde_json::json!({"ts": "inf"}),
            serde_json::json!({"ts": "1e999"}),
            serde_json::json!({"ts": [1]}),
        ] {
            assert_eq!(age(Some(&dict(doc.clone())), 100.0), f64::INFINITY, "{doc}");
        }
    }

    #[test]
    fn age_of_fresh_doc_and_clock_skew() {
        assert_eq!(age(Some(&dict(serde_json::json!({"ts": 100.0}))), 130.0), 30.0);
        assert_eq!(age(Some(&dict(serde_json::json!({"ts": "100"}))), 130.0), 30.0);
        assert_eq!(age(Some(&dict(serde_json::json!({"ts": 200.0}))), 100.0), 0.0, "never negative");
    }

    fn env(explicit: Option<&str>, runtime: Option<&str>) -> HeartbeatEnv {
        HeartbeatEnv {
            explicit: explicit.map(str::to_string),
            default_dir: PathBuf::from(DEFAULT_DIR),
            runtime_dir: runtime.map(str::to_string),
            tmp_dir: PathBuf::from("/tmp"),
            uid: 1000,
        }
    }

    #[test]
    fn path_precedence() {
        let yes = |_: &Path| true;
        let no = |_: &Path| false;
        assert_eq!(
            path_from(&env(Some(" /some/where.json "), Some("/run/user/1000")), &yes),
            Path::new("/some/where.json")
        );
        assert_eq!(path_from(&env(Some("  "), None), &yes), Path::new("/run/soc-wall/heartbeat.json"));
        assert_eq!(
            path_from(&env(None, Some("/run/user/1000")), &no),
            Path::new("/run/user/1000/soc-wall/heartbeat.json")
        );
        assert_eq!(path_from(&env(None, None), &no), Path::new("/tmp/soc-wall-1000/heartbeat.json"));
    }

    #[test]
    fn deployed_commit_reads_the_release_marker() {
        let t = TempDir::new("hb-commit");
        assert_eq!(deployed_commit(t.path()), "");
        t.write(".commit", "abc1234\n");
        assert_eq!(deployed_commit(t.path()), "abc1234");
        t.write(".commit", &"x".repeat(100_000));
        assert_eq!(deployed_commit(t.path()), "", "garbage is never published in the heartbeat");
    }
}
