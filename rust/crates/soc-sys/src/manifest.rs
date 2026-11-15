//! Deploy-time file-hash manifest and boot-time drift detection.
//!
//! At install time every shipped file is hashed and the `path -> sha256` map
//! is recorded, with the source commit, in `/etc/soc-display/manifest.json`
//! (outside the deploy tree, so it is not itself hashed). At boot
//! [`check_drift`] re-hashes the tree and reports what changed, went missing
//! or appeared — a top-bar warning for a tampered install or an unrecorded
//! local edit.
//!
//! The check runs against a tree that may have been tampered with, so it is
//! written to be safe on hostile input: it never follows a symlink, never
//! opens a FIFO or device node, and never opens a path named by the manifest
//! unless that path stays inside the deploy root.

use crate::error::{Result, SysError};
use crate::fsutil::{self, abspath, open_regular, read_capped};
use crate::jsonfmt;
use crate::run::{Runner, SystemRunner, argv};
use crate::sha256::{Sha256, hex, hex_digest};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

pub const MANIFEST_PATH: &str = "/etc/soc-display/manifest.json";
pub const REPO_URL: &str = "https://github.com/s-b-repo/p2soc";
pub const DEPLOY_ROOT: &str = "/opt/soc-display";

/// Directories whose contents are noise (caches, the venv, VCS data) or
/// per-host secrets.
const SKIP_DIRS: [&str; 8] = [".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".audit", ".claude", "secret"];
/// Generated or transient files.
const SKIP_SUFFIXES: [&str; 3] = [".pyc", ".pyo", ".log"];
/// Operator scratchpads, and the manifest itself should it ever move inside.
const SKIP_NAMES: [&str; 3] = ["PROMPT.txt", "MEMORY.md", "manifest.json"];

const MAX_MANIFEST_BYTES: u64 = 32 << 20;

/// The recorded state of a deploy tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: u64,
    /// Source commit, or `""` when unknown.
    pub commit: String,
    pub repo: String,
    /// Relative path (`/`-separated) -> hex SHA-256.
    pub files: BTreeMap<String, String>,
}

impl Manifest {
    /// The on-disk form: sorted keys, two-space indent — the same tree always
    /// produces the same bytes.
    pub fn to_json(&self) -> String {
        jsonfmt::pretty_sorted(&json!({
            "version": self.version,
            "commit": self.commit,
            "repo": self.repo,
            "files": self.files,
        }))
    }

    /// Parse the on-disk form. Missing keys take their defaults; a `files`
    /// entry that is not `string -> string` is an error, not a crash.
    pub fn parse(text: &str) -> Result<Manifest> {
        let doc: Value =
            serde_json::from_str(text).map_err(|e| SysError::Invalid(format!("manifest is not valid JSON: {e}")))?;
        let Some(doc) = doc.as_object() else {
            return Err(SysError::Invalid("manifest is not a JSON object".into()));
        };
        let mut files = BTreeMap::new();
        match doc.get("files") {
            None | Some(Value::Null) => {}
            Some(Value::Object(map)) => {
                for (rel, hash) in map {
                    let Some(hash) = hash.as_str() else {
                        return Err(SysError::Invalid(format!("manifest entry {rel:?} has a non-string hash")));
                    };
                    files.insert(rel.clone(), hash.to_string());
                }
            }
            Some(_) => return Err(SysError::Invalid("manifest 'files' is not an object".into())),
        }
        let text_of = |key: &str| doc.get(key).and_then(Value::as_str).map(str::to_string);
        Ok(Manifest {
            version: doc.get("version").and_then(Value::as_u64).unwrap_or(1),
            commit: text_of("commit").unwrap_or_default(), // audit-allow: default is the intended fallback (no commit recorded)
            repo: text_of("repo").unwrap_or_else(|| REPO_URL.to_string()),
            files,
        })
    }
}

/// SHA-256 of a regular file, streamed in 64 KiB chunks. Refuses symlinks,
/// FIFOs and devices (see [`open_regular`]).
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = open_regular(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(hex(&hasher.finish()));
        }
        let chunk = buf.get(..n).ok_or_else(|| io::Error::other("read overran its buffer"))?;
        hasher.update(chunk);
    }
}

/// The digest recorded for a directory entry. Regular files hash their
/// content; a symlink hashes its *target text* (it is never followed, so a
/// link out of the tree or to `/dev/zero` cannot leak or hang the check); any
/// other node hashes its type.
fn digest_entry(path: &Path, meta: &Metadata) -> io::Result<String> {
    let kind = meta.file_type();
    if kind.is_file() {
        hash_file(path)
    } else if kind.is_symlink() {
        let mut data = b"symlink\0".to_vec();
        data.extend_from_slice(fs::read_link(path)?.as_os_str().as_bytes());
        Ok(hex_digest(&data))
    } else {
        Ok(hex_digest(b"special\0"))
    }
}

fn skipped_file(name: &str) -> bool {
    SKIP_NAMES.contains(&name) || SKIP_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Every entry under `root` worth hashing, as `relative path -> full path`.
/// Directories are descended (never through a symlink); everything else is
/// listed unless filtered.
fn walk_tracked(root: &Path) -> io::Result<BTreeMap<String, PathBuf>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            if entry.file_type()?.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push((entry.path(), rel));
                }
            } else if !skipped_file(&name) {
                out.insert(rel, entry.path());
            }
        }
    }
    Ok(out)
}

fn tree_error(root: &Path, e: io::Error) -> SysError {
    SysError::io(format!("cannot hash {}", root.display()), e)
}

/// Build a manifest of `root`. `commit` is opaque here — it is only recorded
/// so a drift warning can point back at the right commit.
pub fn build_manifest(root: &Path, commit: &str) -> Result<Manifest> {
    let mut files = BTreeMap::new();
    for (rel, path) in walk_tracked(root).map_err(|e| tree_error(root, e))? {
        let digest = fs::symlink_metadata(&path).and_then(|meta| digest_entry(&path, &meta));
        files.insert(rel, digest.map_err(|e| tree_error(&path, e))?);
    }
    Ok(Manifest { version: 1, commit: commit.to_string(), repo: REPO_URL.to_string(), files })
}

/// Whether `v` is plausibly a commit id (7..=64 hex digits), so a corrupted
/// marker never becomes the recorded "deployed commit".
pub fn is_commit_id(v: &str) -> bool {
    (7..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The commit recorded in `<root>/.commit` by the installer, if it is
/// commit-shaped.
pub fn read_commit_marker(root: &Path) -> Option<String> {
    let text = read_capped(&root.join(".commit"), 4096).ok()?;
    let v = text.trim();
    is_commit_id(v).then(|| v.to_string())
}

/// Resolve the source commit, tried in order: `git rev-parse HEAD` (a dev
/// checkout), the `.commit` marker (a deploy with no `.git`), the
/// `SOC_DEPLOY_COMMIT` value (ad-hoc refresh from CI), else `""`. Never fails.
pub fn current_commit(root: &Path, runner: &dyn Runner, env_commit: Option<&str>) -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    // Absolute, so the value handed to `git -C` can never look like an option.
    let abs_root = abspath(root, &cwd);
    let mut cmd = argv(&["git", "-C"]);
    cmd.push(abs_root.to_string_lossy().into_owned());
    cmd.extend(argv(&["rev-parse", "HEAD"]));
    let head = runner
        .run(&cmd, Duration::from_secs(10))
        .ok()
        .filter(|out| out.success())
        .map(|out| out.stdout.trim().to_string())
        .filter(|head| is_commit_id(head));
    if let Some(head) = head {
        return head;
    }
    read_commit_marker(root)
        .or_else(|| env_commit.map(str::trim).filter(|v| !v.is_empty()).map(str::to_string))
        .unwrap_or_default() // audit-allow: default is the intended fallback ("" when no commit is known)
}

/// Hash `root` and atomically write its manifest to `dest` (0644: the
/// contents are not secret, only their integrity matters). The parent
/// directory is created 0755 if absent.
pub fn write_manifest(root: &Path, dest: &Path, commit: &str) -> Result<()> {
    let manifest = build_manifest(root, commit)?;
    let fail = |e| SysError::io(format!("cannot write {}", dest.display()), e);
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        fsutil::ensure_dir(parent, 0o755).map_err(fail)?;
    }
    fsutil::write_atomic(dest, manifest.to_json().as_bytes(), 0o644).map_err(fail)
}

/// How a deploy tree differs from its manifest. All lists are sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drift {
    pub commit: String,
    pub repo: String,
    /// Present, but the hash differs.
    pub changed: Vec<String>,
    /// In the manifest, gone on disk.
    pub missing: Vec<String>,
    /// On disk, not in the manifest (a covert addition).
    pub extras: Vec<String>,
}

impl Drift {
    pub fn is_clean(&self) -> bool {
        self.changed.is_empty() && self.missing.is_empty() && self.extras.is_empty()
    }
}

/// A manifest path may only be opened if it stays inside the deploy root:
/// relative, with no `..`, `.` or empty components.
fn safe_relative(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.contains('\0')
        && Path::new(rel).components().all(|c| matches!(c, Component::Normal(_)))
        && !rel.split('/').any(str::is_empty)
}

/// Compare the hashes under `deploy_root` with the manifest at
/// `manifest_path`. A missing manifest is an `Io` error of kind `NotFound`
/// (the caller decides whether that is a soft skip or a loud failure).
pub fn check_drift(deploy_root: &Path, manifest_path: &Path) -> Result<Drift> {
    let text = read_capped(manifest_path, MAX_MANIFEST_BYTES)
        .map_err(|e| SysError::io(format!("cannot read {}", manifest_path.display()), e))?;
    let manifest = Manifest::parse(&text)?;
    let on_disk = walk_tracked(deploy_root).map_err(|e| tree_error(deploy_root, e))?;

    let mut drift = Drift { commit: manifest.commit, repo: manifest.repo, ..Drift::default() };
    for (rel, want) in &manifest.files {
        let path = match on_disk.get(rel) {
            Some(p) => p.clone(),
            // Not reached by the walk (filtered, or simply gone). Only look at
            // it when the name cannot escape the root.
            None if safe_relative(rel) => deploy_root.join(rel),
            None => {
                drift.missing.push(rel.clone());
                continue;
            }
        };
        match fs::symlink_metadata(&path) {
            Err(_) => drift.missing.push(rel.clone()), // audit-allow: any stat failure means the file cannot be vouched for, i.e. missing
            Ok(meta) if meta.is_dir() => drift.changed.push(rel.clone()),
            Ok(meta) => match digest_entry(&path, &meta) {
                Ok(have) if have == *want => {}
                // Unreadable counts as changed: it can no longer be vouched for.
                _ => drift.changed.push(rel.clone()),
            },
        }
    }
    drift.extras = on_disk.keys().filter(|rel| !manifest.files.contains_key(*rel)).cloned().collect();
    drift.changed.sort();
    drift.missing.sort();
    Ok(drift)
}

/// A one-line warning for the wall's top bar; `""` when there is no drift.
pub fn format_drift_summary(drift: &Drift) -> String {
    if drift.is_clean() {
        return String::new();
    }
    let commit = drift.commit.trim();
    let short: String = if commit.is_empty() { "unknown".into() } else { commit.chars().take(12).collect() };
    let mut parts = Vec::new();
    for (n, what) in [(drift.changed.len(), "changed"), (drift.missing.len(), "missing"), (drift.extras.len(), "extra")]
    {
        if n > 0 {
            parts.push(format!("{n} {what}"));
        }
    }
    format!(
        "⚠ files drift from deployed commit {short} ({}). Run `git diff {short}` against the repo to investigate.",
        parts.join(", ")
    )
}

/// `manifest [root [dest]]` — re-hash the deploy tree and overwrite the
/// manifest, e.g. after an intentional manual update, so the boot-time check
/// stops flagging it.
pub fn manifest_main(args: &[String]) -> i32 {
    let root = PathBuf::from(args.first().map_or(DEPLOY_ROOT, String::as_str));
    let dest = PathBuf::from(args.get(1).map_or(MANIFEST_PATH, String::as_str));
    let commit = current_commit(&root, &SystemRunner, std::env::var("SOC_DEPLOY_COMMIT").ok().as_deref());
    match write_manifest(&root, &dest, &commit) {
        Ok(()) => {
            println!("manifest refreshed: {}", dest.display());
            0
        }
        Err(e) => {
            println!("manifest refresh failed: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::fake::{FakeRunner, exit};
    use crate::testutil::{TempDir, fixture};
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A fake deploy tree with a mix of tracked files and skip decoys — the
    /// same tree the Python reference hashed for `manifest.expected.json`.
    fn seed_tree(tag: &str) -> TempDir {
        let t = TempDir::new(tag);
        t.write("root/kiosk-host/host/main.py", "print('hi')\n");
        t.write("root/scripts/tarpit.py", "# tarpit\n");
        t.write("root/README.md", "# soc\n");
        t.write("root/a/b/c.txt", "deep\n");
        t.write("root/empty", "");
        t.write("root/Zed.txt", "z\n");
        t.write("root/.git/config", "ignored\n");
        t.write("root/__pycache__/foo.pyc", "ignored\n");
        t.write("root/secret/host.key", "k");
        t.write("root/wall.log", "ignored\n");
        t.write("root/PROMPT.txt", "operator scratchpad\n");
        t
    }

    fn written(t: &TempDir) -> (PathBuf, PathBuf) {
        let (root, dest) = (t.path().join("root"), t.path().join("manifest.json"));
        write_manifest(&root, &dest, "deadbeef").unwrap();
        (root, dest)
    }

    #[test]
    fn manifest_is_byte_identical_to_the_python_reference() {
        let t = seed_tree("manifest-parity");
        let m = build_manifest(&t.path().join("root"), "deadbeef").unwrap();
        assert_eq!(m.to_json(), fixture("manifest.expected.json"));
    }

    #[test]
    fn build_skips_excluded_dirs_and_suffixes() {
        let t = seed_tree("manifest-skip");
        let m = build_manifest(&t.path().join("root"), "abc123").unwrap();
        for tracked in ["kiosk-host/host/main.py", "scripts/tarpit.py", "README.md"] {
            assert!(m.files.contains_key(tracked), "{tracked}");
        }
        for skipped in [".git/config", "__pycache__/foo.pyc", "wall.log", "PROMPT.txt", "secret/host.key"] {
            assert!(!m.files.contains_key(skipped), "{skipped}");
        }
        assert_eq!((m.version, m.commit.as_str()), (1, "abc123"));
        assert!(m.repo.starts_with("https://github.com/"));
        assert_eq!(build_manifest(&t.path().join("root"), "abc123").unwrap(), m, "deterministic");
    }

    #[test]
    fn write_creates_the_parent_and_round_trips() {
        let t = seed_tree("manifest-write");
        let dest = t.path().join("etc/soc/manifest.json");
        write_manifest(&t.path().join("root"), &dest, "deadbeef").unwrap();
        assert_eq!(fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o644);
        let parsed = Manifest::parse(&fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(parsed, build_manifest(&t.path().join("root"), "deadbeef").unwrap());
        assert_eq!(fs::read_dir(dest.parent().unwrap()).unwrap().count(), 1, "no temp file left behind");
    }

    #[test]
    fn clean_tree_has_no_drift() {
        let t = seed_tree("manifest-clean");
        let (root, dest) = written(&t);
        let drift = check_drift(&root, &dest).unwrap();
        assert!(drift.is_clean(), "{drift:?}");
        assert_eq!(drift.commit, "deadbeef");
        assert_eq!(format_drift_summary(&drift), "");
    }

    #[test]
    fn detects_modified_missing_and_extra_files() {
        let t = seed_tree("manifest-drift");
        let (root, dest) = written(&t);
        t.write("root/scripts/tarpit.py", "# evil edit\n");
        fs::remove_file(root.join("README.md")).unwrap();
        t.write("root/kiosk-host/host/rogue.py", "# new\n");
        let drift = check_drift(&root, &dest).unwrap();
        assert_eq!(drift.changed, ["scripts/tarpit.py"]);
        assert_eq!(drift.missing, ["README.md"]);
        assert_eq!(drift.extras, ["kiosk-host/host/rogue.py"]);
    }

    #[test]
    fn missing_manifest_is_a_not_found_error() {
        let t = seed_tree("manifest-missing");
        let err = check_drift(&t.path().join("root"), &t.path().join("nope.json")).unwrap_err();
        assert!(matches!(&err, SysError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound), "{err}");
    }

    #[test]
    fn manifest_paths_cannot_escape_the_deploy_root() {
        let t = seed_tree("manifest-traversal");
        let outside = t.write("outside.txt", "secret\n");
        let dest = t.path().join("manifest.json");
        let hash = hex_digest(b"secret\n");
        let mut files = serde_json::Map::new();
        for name in ["../outside.txt", &outside.to_string_lossy(), "a//b", "./README.md"] {
            files.insert(name.to_string(), Value::String(hash.clone()));
        }
        let evil = json!({"version": 1, "commit": "", "files": files});
        fs::write(&dest, evil.to_string()).unwrap();
        let drift = check_drift(&t.path().join("root"), &dest).unwrap();
        // Every escaping name is reported missing — it was never opened, so
        // its (matching!) hash was never confirmed.
        assert_eq!(drift.missing.len(), 4, "{drift:?}");
        assert!(drift.changed.is_empty());
    }

    #[test]
    fn symlinks_are_recorded_by_target_and_never_followed() {
        let t = seed_tree("manifest-symlink");
        let root = t.path().join("root");
        // A link to an endless device and a dangling one: neither may hang or
        // fail the build.
        symlink("/dev/zero", root.join("endless")).unwrap();
        symlink("nowhere", root.join("dangling")).unwrap();
        symlink("a", root.join("dirlink")).unwrap();
        let dest = t.path().join("manifest.json");
        write_manifest(&root, &dest, "").unwrap();
        let m = Manifest::parse(&fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(m.files["endless"], hex_digest(b"symlink\0/dev/zero"));
        assert!(m.files.contains_key("dirlink") && !m.files.contains_key("dirlink/b/c.txt"));
        assert!(check_drift(&root, &dest).unwrap().is_clean());
        // Re-pointing a link is drift.
        fs::remove_file(root.join("dangling")).unwrap();
        symlink("/etc/passwd", root.join("dangling")).unwrap();
        assert_eq!(check_drift(&root, &dest).unwrap().changed, ["dangling"]);
    }

    #[test]
    fn hash_file_refuses_anything_but_a_regular_file() {
        let t = seed_tree("manifest-regular");
        let root = t.path().join("root");
        symlink(root.join("README.md"), root.join("link")).unwrap();
        assert_eq!(hash_file(&root.join("README.md")).unwrap(), hex_digest(b"# soc\n"));
        assert!(hash_file(&root.join("link")).is_err());
        assert!(hash_file(&root).is_err());
    }

    #[test]
    fn malformed_manifests_are_errors_not_panics() {
        for body in ["", "[1]", "{\"files\": [1]}", "{\"files\": {\"a\": 1}}", "{not json"] {
            assert!(matches!(Manifest::parse(body), Err(SysError::Invalid(_))), "{body:?}");
        }
        let m = Manifest::parse("{}").unwrap();
        assert_eq!((m.commit.as_str(), m.repo.as_str(), m.files.len()), ("", REPO_URL, 0));
    }

    #[test]
    fn drift_summary_mentions_counts_and_commit() {
        let drift = Drift {
            commit: "abcdef0123456789".into(),
            repo: "x".into(),
            changed: vec!["a".into(), "b".into()],
            missing: vec!["c".into()],
            extras: vec!["d".into()],
        };
        // Byte-for-byte what the Python reference prints for this input.
        assert_eq!(
            format_drift_summary(&drift),
            "⚠ files drift from deployed commit abcdef012345 (2 changed, 1 missing, 1 extra). \
             Run `git diff abcdef012345` against the repo to investigate."
        );
        let unknown = Drift { changed: vec!["a".into()], ..Drift::default() };
        assert!(format_drift_summary(&unknown).contains("commit unknown (1 changed)"));
    }

    #[test]
    fn commit_resolution_order() {
        let t = TempDir::new("manifest-commit");
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let git_ok = FakeRunner::new(|_| exit(0, &format!("{sha}\n")));
        assert_eq!(current_commit(t.path(), &git_ok, Some("fromenv")), sha);
        let call = git_ok.calls.borrow()[0].clone();
        assert_eq!(call[..2], ["git", "-C"]);
        assert!(call[2].starts_with('/'), "the -C value is absolute: {call:?}");
        assert_eq!(call[3..], ["rev-parse", "HEAD"]);

        let no_git = FakeRunner::new(|_| exit(128, ""));
        assert_eq!(current_commit(t.path(), &no_git, Some(" fromenv ")), "fromenv");
        assert_eq!(current_commit(t.path(), &no_git, None), "");
        t.write(".commit", "abc1234\n");
        assert_eq!(current_commit(t.path(), &no_git, Some("fromenv")), "abc1234");
        // A corrupted marker is not a commit.
        t.write(".commit", "not a sha; rm -rf /\n");
        assert_eq!(current_commit(t.path(), &no_git, None), "");
        let broken = FakeRunner::new(|_| Err(io::Error::other("no git")));
        assert_eq!(current_commit(t.path(), &broken, None), "");
    }
}
