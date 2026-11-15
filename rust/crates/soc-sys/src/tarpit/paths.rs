//! Which request paths the tarpit answers.
//!
//! The built-in lists are common scanner targets drawn from public scanner
//! signatures (Nuclei, ZAP, dirbuster word lists); anything else gets a 404.
//! An optional file extends them — one path per line, `/foo/*` for a prefix,
//! `#` for comments — and is re-read on SIGHUP. The built-ins always remain,
//! so a missing or empty file can never turn the tarpit into a passive 404.

use std::collections::HashSet;
use std::io::{self, Read};
use std::path::Path;

const EXACT_PATHS: [&str; 35] = [
    "/admin",
    "/admin.php",
    "/admin/",
    "/admin/login",
    "/admin/login.php",
    "/administrator",
    "/administrator/",
    "/administrator/index.php",
    "/wp-admin",
    "/wp-admin/",
    "/wp-admin/admin-ajax.php",
    "/wp-login.php",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/.htpasswd",
    "/.htaccess",
    "/phpmyadmin/",
    "/phpmyadmin/index.php",
    "/pma/",
    "/myadmin/",
    "/server-status",
    "/server-info",
    "/manager/html",
    "/manager/status",
    "/host-manager/html",
    "/console/",
    "/jolokia/list",
    "/jmx-console",
    "/HNAP1/",
    "/HNAP1",
];

const PREFIX_PATHS: [&str; 11] = [
    "/actuator/", // spring-boot
    "/api/v1/",   // generic api fishing
    "/wp-content/",
    "/wp-includes/",
    "/cgi-bin/",
    "/vendor/",
    "/dbeaver/",
    "/.git/",
    "/owa/", // exchange
    "/Autodiscover/",
    "/ecp/",
];

/// The paths file is a short operator-maintained list; refuse to load
/// something that is clearly not one.
const MAX_FILE_BYTES: u64 = 1 << 20;
const MAX_FILE_ENTRIES: usize = 8192;

/// The set of paths that get the tarpit treatment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSet {
    exact: HashSet<String>,
    prefix: Vec<String>,
}

impl PathSet {
    /// The built-in lists.
    pub fn builtin() -> PathSet {
        PathSet {
            exact: EXACT_PATHS.iter().map(|s| (*s).to_string()).collect(),
            prefix: PREFIX_PATHS.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// The built-ins extended by the lines of a paths file.
    pub fn with_file_text(text: &str) -> PathSet {
        let mut set = PathSet::builtin();
        let entries = text.lines().filter_map(|raw| {
            let line = raw.split('#').next().unwrap_or("").trim();
            (!line.is_empty()).then_some(line)
        });
        for line in entries.take(MAX_FILE_ENTRIES) {
            match line.strip_suffix('*').filter(|p| p.ends_with('/')) {
                Some(prefix) => set.prefix.push(prefix.to_string()),
                None => {
                    set.exact.insert(line.to_string());
                }
            }
        }
        set
    }

    /// True if `path` looks like a known scanner target.
    pub fn matches(&self, path: &str) -> bool {
        self.exact.contains(path) || self.prefix.iter().any(|p| path.starts_with(p.as_str()))
    }

    /// `(exact, prefix)` entry counts.
    pub fn counts(&self) -> (usize, usize) {
        (self.exact.len(), self.prefix.len())
    }
}

/// Load the path set. A missing file is not an error: `(built-ins, false)`.
/// Any other failure (unreadable, oversized, not text) is returned so the
/// caller keeps the set it already has — a bad file must not change what the
/// tarpit answers.
pub fn load(file: &Path) -> io::Result<(PathSet, bool)> {
    let opened = match std::fs::File::open(file) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((PathSet::builtin(), false)),
        Err(e) => return Err(e),
    };
    let mut text = String::new();
    opened.take(MAX_FILE_BYTES + 1).read_to_string(&mut text)?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_FILE_BYTES) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "paths file is too large"));
    }
    Ok((PathSet::with_file_text(&text), true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn matches_known_scanner_targets() {
        let set = PathSet::builtin();
        for p in [
            "/admin.php",
            "/wp-login.php",
            "/.env",
            "/phpmyadmin/",
            "/wp-admin/admin-ajax.php",
            "/actuator/health",
            "/api/v1/login",
            "/.git/HEAD",
        ] {
            assert!(set.matches(p), "should match: {p}");
        }
    }

    #[test]
    fn does_not_match_real_app_paths() {
        let set = PathSet::builtin();
        for p in ["/", "/index.html", "/healthz", "/static/app.js", "/login", "/api", ""] {
            assert!(!set.matches(p), "should NOT match: {p}");
        }
    }

    #[test]
    fn file_extends_the_builtin_lists() {
        let t = TempDir::new("tarpit-paths");
        let f = t.write("paths.list", "# comment\n/private/data\n/secrets/* \n\n/inline # trailing comment\n");
        let (set, seen) = load(&f).unwrap();
        assert!(seen);
        assert!(set.matches("/private/data"));
        assert!(set.matches("/secrets/anything"));
        assert!(set.matches("/inline"));
        assert!(!set.matches("/private/data/deeper"));
        assert!(set.matches("/admin.php"), "built-in defaults survive");
        let (exact, prefix) = set.counts();
        assert_eq!((exact, prefix), (PathSet::builtin().counts().0 + 2, PathSet::builtin().counts().1 + 1));
    }

    #[test]
    fn a_star_without_a_slash_is_a_literal_path() {
        let set = PathSet::with_file_text("/weird*\n");
        assert!(set.matches("/weird*"));
        assert!(!set.matches("/weirder"));
    }

    #[test]
    fn missing_file_means_the_defaults() {
        let t = TempDir::new("tarpit-nopaths");
        let (set, seen) = load(&t.path().join("does-not-exist.list")).unwrap();
        assert!(!seen);
        assert_eq!(set, PathSet::builtin());
    }

    #[test]
    fn an_unusable_file_is_an_error_not_an_empty_set() {
        let t = TempDir::new("tarpit-badpaths");
        let big = t.path().join("big.list");
        std::fs::write(&big, vec![b'a'; (MAX_FILE_BYTES + 1) as usize]).unwrap();
        assert!(load(&big).is_err());
        let binary = t.path().join("binary.list");
        std::fs::write(&binary, [0xff, 0xfe, 0x00]).unwrap();
        assert!(load(&binary).is_err());
        assert!(load(t.path()).is_err(), "a directory is not a paths file");
        let locked = t.write("locked.list", "/should-not-load\n");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if crate::fsutil::euid() != 0 {
            assert!(load(&locked).is_err());
        }
    }

    #[test]
    fn the_number_of_file_entries_is_capped() {
        let text: String = (0..MAX_FILE_ENTRIES + 500).map(|i| format!("/p{i}\n")).collect();
        let set = PathSet::with_file_text(&text);
        assert_eq!(set.counts().0, PathSet::builtin().counts().0 + MAX_FILE_ENTRIES);
    }
}
