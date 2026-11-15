//! Domain login memory: which vault item logged a given origin in, so the same
//! origin auto-logs-in again on a different or re-pointed panel.
//!
//! Stored as `<state dir>/domain_logins.json` (mode 0600):
//! `{ "host.example.com:443": "Vault Item" }`. Only the *name* of the vault
//! login is kept, never a credential. The file format is shared with the
//! Python wall.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use soc_core::url::Url;

use crate::error::Error;

const FILE_NAME: &str = "domain_logins.json";
/// The file holds a handful of short lines; refuse to slurp anything else.
const MAX_FILE: u64 = 1 << 20;

/// The origin authority `host:port` of an http(s) URL (default ports made
/// explicit), or `""`. Keyed per origin — not bare host name — so different
/// apps on one host (different ports) never share a remembered login.
pub fn domain_of(url: &str) -> String {
    let Ok(parts) = Url::split(url.trim()) else {
        return String::new();
    };
    let default = match parts.scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return String::new(),
    };
    // The same strict host reading the navigation gate uses: a URL that is
    // not vetted there is not remembered here.
    match crate::siteguard::host_of(url) {
        Some(host) => format!("{host}:{}", parts.port.filter(|p| *p != 0).unwrap_or(default)),
        None => String::new(),
    }
}

/// The on-disk memory. One instance is shared by every panel (the GTK thread
/// and each Chromium control thread call [`remember`](Self::remember)), so the
/// read-modify-write is serialised.
#[derive(Debug)]
pub struct LoginMemory {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl LoginMemory {
    /// A memory kept in `state_dir` (created on first write).
    pub fn new(state_dir: impl Into<PathBuf>) -> LoginMemory {
        LoginMemory { dir: state_dir.into(), lock: Mutex::new(()) }
    }

    /// The state directory the environment selects: `$SOC_STATE_DIR`, else
    /// `<$XDG_CONFIG_HOME or ~/.config>/soc-wall`.
    pub fn from_env() -> LoginMemory {
        let env = soc_core::env::env_str;
        LoginMemory::new(state_dir(env("SOC_STATE_DIR"), env("XDG_CONFIG_HOME"), env("HOME")))
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    /// Every remembered `origin -> vault item`. A missing or damaged file is
    /// an empty memory.
    pub fn load(&self) -> BTreeMap<String, String> {
        read_map(&self.path())
    }

    /// The vault item remembered for `url`'s origin, or `""`.
    pub fn vault_item_for(&self, url: &str) -> String {
        let dom = domain_of(url);
        if dom.is_empty() {
            return String::new();
        }
        self.load().remove(&dom).unwrap_or_default() // audit-allow: default is the intended fallback (no memory -> "")
    }

    /// Record that `vault_item` logs `url`'s origin in. A no-op for an empty
    /// item, a URL without an origin, or an unchanged entry.
    pub fn remember(&self, url: &str, vault_item: &str) -> Result<(), Error> {
        let dom = domain_of(url);
        if dom.is_empty() || vault_item.is_empty() {
            return Ok(());
        }
        let _guard = self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()); // audit-allow: RAII guard held for the scope, not an ignored result
        let mut map = self.load();
        if map.get(&dom).map(String::as_str) == Some(vault_item) {
            return Ok(());
        }
        map.insert(dom, vault_item.to_string());
        let text = serde_json::to_string_pretty(&map)
            .map_err(|e| Error::io("encode login memory", std::io::Error::other(e)))?;
        self.write_atomic(text.as_bytes())
    }

    /// Replace the file through a unique 0600 temp in the same directory, so
    /// readers never see a partial file and the name is never world-readable.
    fn write_atomic(&self, data: &[u8]) -> Result<(), Error> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| Error::io(format!("create {}", self.dir.display()), e))?;
        let tmp = self.dir.join(format!(".dl-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut file| file.write_all(data).and_then(|()| file.sync_all()))
            .and_then(|()| std::fs::rename(&tmp, self.path()));
        result.map_err(|e| {
            // The temp may or may not exist; either way it must not linger.
            let _ = std::fs::remove_file(&tmp); // audit-allow: best-effort cleanup; the write error is what is reported
            Error::io(format!("write {}", self.path().display()), e)
        })
    }
}

/// Pure resolution of the state directory from the three variables.
pub fn state_dir(soc_state_dir: Option<String>, xdg_config_home: Option<String>, home: Option<String>) -> PathBuf {
    if let Some(dir) = soc_state_dir {
        return PathBuf::from(dir);
    }
    let config = xdg_config_home
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home.unwrap_or_else(|| "/".into())).join(".config"));
    config.join("soc-wall")
}

fn read_map(path: &Path) -> BTreeMap<String, String> {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return BTreeMap::new();
    };
    let mut text = String::new();
    if file.take(MAX_FILE).read_to_string(&mut text).is_err() {
        return BTreeMap::new();
    }
    let Ok(serde_json::Value::Object(obj)) = serde_json::from_str(&text) else {
        return BTreeMap::new();
    };
    // Entries a foreign writer left in another shape are dropped, not trusted.
    obj.into_iter().filter_map(|(k, v)| v.as_str().map(|item| (k, item.to_string()))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("soc-web-lm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn domain_is_host_and_port() {
        assert_eq!(domain_of("https://app.example.com:8443/login"), "app.example.com:8443");
        assert_eq!(domain_of("https://app.example.com/x"), "app.example.com:443");
        assert_eq!(domain_of("http://H.example/"), "h.example:80");
        assert_eq!(domain_of("http://h:0/"), "h:80");
        // Not an http(s) origin: nothing to remember.
        for none in ["", "ftp://x/y", "file:///etc/passwd", "//schemeless.example/x", "http://h:99999/", "nope"] {
            assert_eq!(domain_of(none), "", "{none:?}");
        }
    }

    #[test]
    fn remembers_per_origin() {
        let dir = scratch("basic");
        let mem = LoginMemory::new(&dir);
        assert_eq!(mem.vault_item_for("https://app.example.com/x"), "");
        mem.remember("https://app.example.com/login", "App Login").unwrap();
        // A different panel at the same origin finds the remembered login ...
        assert_eq!(mem.vault_item_for("https://app.example.com/other"), "App Login");
        // ... a different port is a different origin: no credential bleed.
        assert_eq!(mem.vault_item_for("https://app.example.com:8443/"), "");
        let meta = std::fs::metadata(mem.path()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        // Only the vault item NAME is stored, in the format the Python wall writes.
        assert_eq!(std::fs::read_to_string(mem.path()).unwrap(), "{\n  \"app.example.com:443\": \"App Login\"\n}");
        // Empty url / item are no-ops.
        mem.remember("", "X").unwrap();
        mem.remember("http://h/", "").unwrap();
        assert!(!mem.load().contains_key("h:80"));
        // No temp file is left behind.
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from(FILE_NAME)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_file_is_an_empty_memory_and_gets_replaced() {
        let dir = scratch("damaged");
        std::fs::create_dir_all(&dir).unwrap();
        let mem = LoginMemory::new(&dir);
        std::fs::write(mem.path(), "[1, 2").unwrap();
        assert!(mem.load().is_empty());
        std::fs::write(mem.path(), r#"{"a:80": "ok", "b:80": 7}"#).unwrap();
        assert_eq!(mem.load().len(), 1);
        mem.remember("http://c/", "C").unwrap();
        assert_eq!(mem.load().keys().collect::<Vec<_>>(), vec!["a:80", "c:80"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_write_reports_and_leaves_nothing() {
        let dir = scratch("ro");
        std::fs::create_dir_all(&dir).unwrap();
        // The target path is occupied by a directory, so the rename must fail.
        std::fs::create_dir(dir.join(FILE_NAME)).unwrap();
        let mem = LoginMemory::new(&dir);
        assert!(mem.remember("https://leak.example.com/login", "App Login").is_err());
        assert_eq!(mem.vault_item_for("https://leak.example.com/"), "");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "temp file must be cleaned up");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_writers_do_not_lose_entries() {
        let dir = scratch("threads");
        let mem = std::sync::Arc::new(LoginMemory::new(&dir));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let mem = mem.clone();
                std::thread::spawn(move || mem.remember(&format!("https://h{i}.example/"), "Item").unwrap())
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(mem.load().len(), 8);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_dir_precedence() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(state_dir(s("/state"), s("/xdg"), s("/home/k")), PathBuf::from("/state"));
        assert_eq!(state_dir(None, s("/xdg"), s("/home/k")), PathBuf::from("/xdg/soc-wall"));
        assert_eq!(state_dir(None, None, s("/home/k")), PathBuf::from("/home/k/.config/soc-wall"));
    }
}
