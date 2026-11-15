//! The wall's implementation of [`WallServices`]: vault-backed credentials,
//! the injection templates and the renderer security policy, behind the one
//! interface the panel widgets see.

use super::panel::{TrackerRules, WallServices};
use soc_core::{CredSource, Engine, Login, Panel, SecurityCfg};
use soc_web::LoginMemory;
use soc_web::inject;
use soc_web::siteguard::AllowList;
use soc_web::websecurity::{self, SecurityData};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Thread-safe logger shared by the GUI and its worker threads.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

pub struct Services {
    creds: Arc<dyn CredSource>,
    memory: Arc<LoginMemory>,
    security: SecurityCfg,
    data: Arc<SecurityData>,
    /// `$SOC_BLOCK_TRACKERS` (default on).
    trackers_env: bool,
    proxy_item: String,
    log: Log,
    /// Which vault item served each panel's current login.
    resolved: RefCell<HashMap<String, String>>,
    /// Panels whose current login is already on record.
    logged_in: RefCell<HashSet<String>>,
}

impl Services {
    pub fn new(
        creds: Arc<dyn CredSource>,
        memory: Arc<LoginMemory>,
        security: SecurityCfg,
        data: Arc<SecurityData>,
        trackers_env: bool,
        proxy_item: &str,
        log: Log,
    ) -> Rc<Services> {
        Rc::new(Services {
            creds,
            memory,
            security,
            data,
            trackers_env,
            proxy_item: proxy_item.to_string(),
            log,
            resolved: RefCell::default(),
            logged_in: RefCell::default(),
        })
    }
}

impl WallServices for Services {
    fn log(&self, msg: &str) {
        (self.log)(msg);
    }

    fn bootstrap_js(&self, panel: &Panel) -> String {
        inject::bootstrap_with_origin(panel, Engine::Webkit, &mut |m| (self.log)(m))
    }

    fn nav_gate(&self, panel: &Panel) -> Option<Box<dyn Fn(&str) -> bool>> {
        if !soc_web::siteguard::nav_gate_enabled(&self.security) {
            return None;
        }
        let allow = AllowList::build(panel, &self.security, &self.data);
        Some(Box::new(move |uri| allow.nav_allowed(uri)))
    }

    fn tracker_rules(&self, panel: &Panel) -> Option<TrackerRules> {
        if !websecurity::should_block_trackers(panel, &self.security, self.trackers_env) {
            return None;
        }
        let filter = websecurity::tracker_filter(panel, &self.data);
        (!filter.rules.trim().is_empty()).then_some(TrackerRules { key: filter.key, json: filter.rules })
    }

    fn may_login(&self, panel: &Panel, page_uri: &str) -> bool {
        let allowed = inject::allowed_origin(panel);
        !allowed.is_empty() && inject::panel_origin(page_uri) == allowed
    }

    fn login_for(&self, panel: &Panel) -> Option<Login> {
        let url = panel.effective_url();
        // The panel's own item, or one remembered for this site (so a site
        // logged in before auto-logs-in on any panel).
        let item =
            if panel.vault_item.is_empty() { self.memory.vault_item_for(&url) } else { panel.vault_item.clone() };
        self.resolved.borrow_mut().insert(panel.id.clone(), item.clone());
        self.logged_in.borrow_mut().remove(&panel.id);
        if item.is_empty() {
            return None;
        }
        // Register the site at once: a login often navigates away, so there
        // may be no later in-page signal to record it on.
        if !panel.vault_item.is_empty() {
            if let Err(e) = self.memory.remember(&url, &panel.vault_item) {
                (self.log)(&format!("[{}] could not remember the login: {e}", panel.id));
            }
        }
        match self.creds.creds(&item) {
            Ok(login) => Some(login),
            Err(e) => {
                (self.log)(&format!("[{}] vault: {e}", panel.id));
                None
            }
        }
    }

    fn login_js(&self, panel: &Panel, login: &Login) -> Option<Zeroizing<String>> {
        inject::guarded_login_call(&inject::allowed_origin(panel), login)
    }

    fn prompt_js(&self, message: &str) -> String {
        inject::prompt_call(message)
    }

    fn prompt_clear_js(&self) -> String {
        inject::prompt_clear_call().to_string()
    }

    fn login_succeeded(&self, panel: &Panel) {
        // The page reports "logged in" on every document it loads, so a
        // dashboard that reloads itself lands here all day; once per login is
        // enough (this is a disk write plus a journal line on the SD card).
        if self.logged_in.borrow().contains(&panel.id) {
            return;
        }
        let item = self.resolved.borrow().get(&panel.id).filter(|i| !i.is_empty()).cloned();
        let item = item.unwrap_or_else(|| panel.vault_item.clone());
        if item.is_empty() {
            return;
        }
        self.logged_in.borrow_mut().insert(panel.id.clone());
        let url = panel.effective_url();
        let _ = self.memory.remember(&url, &item); // audit-allow: best-effort, memory is a cache hint
        (self.log)(&format!(
            "[{}] login OK — remembered {} -> '{item}'",
            panel.id,
            soc_web::loginmemory::domain_of(&url)
        ));
    }

    fn proxy_login(&self) -> Option<Login> {
        if self.proxy_item.is_empty() {
            return None;
        }
        match self.creds.creds(&self.proxy_item) {
            Ok(login) => Some(login),
            Err(e) => {
                (self.log)(&format!("[proxy] vault: {e}"));
                None
            }
        }
    }

    fn web_process_pids(&self) -> BTreeSet<u32> {
        let table = soc_sys::perf::proc_table(Path::new("/proc"));
        soc_sys::perf::web_process_pids(&table, std::process::id())
    }

    fn proc_rss_kb(&self, pid: u32) -> Option<u64> {
        soc_sys::perf::proc_rss_kb(Path::new("/proc"), pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soc_core::creds::StaticCreds;
    use std::sync::Mutex;

    fn services(dir: &Path) -> (Rc<Services>, Arc<Mutex<Vec<String>>>) {
        let mut creds = StaticCreds::default();
        creds.logins.insert("SOC Panel 1".into(), ("operator".into(), "hunter2".into()));
        let logs = Arc::new(Mutex::new(Vec::new()));
        let sink = logs.clone();
        let svc = Services::new(
            Arc::new(creds),
            Arc::new(LoginMemory::new(dir)),
            SecurityCfg::default(),
            Arc::new(SecurityData::embedded()),
            true,
            "",
            Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string())),
        );
        (svc, logs)
    }

    fn panel(id: &str, url: &str, item: &str) -> Panel {
        let mut p = Panel::new(id);
        p.url = Some(url.to_string());
        p.vault_item = item.to_string();
        p
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("soc-services-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // audit-allow: best-effort, temp dir cleanup
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn credentials_are_pinned_to_the_panel_origin() {
        let dir = tmp("origin");
        let (svc, _) = services(&dir);
        let p = panel("p1", "https://dash.example.com/login", "SOC Panel 1");
        assert!(svc.may_login(&p, "https://dash.example.com/login?next=/"));
        for foreign in [
            "https://evil.example.net/login",
            "https://dash.example.com.evil.net/",
            "http://dash.example.com/login",
            "https://dash.example.com:8443/",
            "about:blank",
            "",
        ] {
            assert!(!svc.may_login(&p, foreign), "{foreign:?} must not receive credentials");
        }
        let js = svc.login_js(&p, &Login::new("operator", "hunter2")).unwrap();
        assert!(js.contains("window.location.origin"), "the injected call must carry its own origin check");
        assert!(js.contains("https://dash.example.com"));
        // No origin to pin to -> no credentials at all.
        assert!(svc.login_js(&Panel::new("blank"), &Login::new("u", "p")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_remembered_site_logs_in_on_another_panel() {
        let dir = tmp("memory");
        let (svc, logs) = services(&dir);
        let own = panel("p1", "https://dash.example.com/login", "SOC Panel 1");
        assert_eq!(svc.login_for(&own).unwrap().password, "hunter2");

        // A second panel at the same site, with no vault item of its own.
        let other = panel("p2", "https://dash.example.com/other", "");
        assert_eq!(svc.login_for(&other).unwrap().username, "operator");
        // ... and a site nobody has logged in to gets nothing.
        assert!(svc.login_for(&panel("p3", "https://unknown.example.org/", "")).is_none());

        svc.login_succeeded(&other);
        svc.login_succeeded(&other);
        let logs = logs.lock().unwrap();
        assert_eq!(logs.iter().filter(|l| l.contains("[p2] login OK")).count(), 1, "{logs:?}");
        assert!(logs.iter().all(|l| !l.contains("hunter2")), "a password reached the log: {logs:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_vault_item_is_logged_not_fatal() {
        let dir = tmp("missing");
        let (svc, logs) = services(&dir);
        assert!(svc.login_for(&panel("p1", "https://dash.example.com/", "No Such Item")).is_none());
        assert!(logs.lock().unwrap().iter().any(|l| l.starts_with("[p1] vault:")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn navigation_gate_and_tracker_rules_follow_the_policy() {
        let dir = tmp("policy");
        let (svc, _) = services(&dir);
        let p = panel("p1", "https://dash.example.com/", "");
        let gate = svc.nav_gate(&p).expect("gate is on by default");
        assert!(gate("https://dash.example.com/x"));
        assert!(gate("about:blank"));
        assert!(!gate("https://evil.example.net/"));
        assert!(!gate("file:///etc/passwd"));

        let rules = svc.tracker_rules(&p).expect("trackers are blocked by default");
        assert_eq!(rules.key, "");
        assert!(serde_json::from_str::<serde_json::Value>(&rules.json).unwrap().is_array());
        let mut unblocked = p.clone();
        unblocked.block_trackers = false;
        assert!(svc.tracker_rules(&unblocked).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
