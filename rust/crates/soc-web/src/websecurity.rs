//! The curated renderer-security data both engines share: the cloud-SSO
//! navigation allowlist and the tracker blocklist.
//!
//! The shipped files are compiled in, so the binary is hardened with nothing
//! on disk. An operator can still extend or replace them: a `security/`
//! directory found through `$SOC_SECURITY_DIR`, `$SOC_ETC_DIR/security`
//! (default `/etc/soc-display/security`) or `$SOC_ROOT/security` wins, file by
//! file. A missing or unparsable override file falls back to the built-in copy
//! — a typo must never silently switch a guard off.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::Value;
use soc_core::{Panel, SecurityCfg};

pub use crate::siteguard::{AllowList, host_of};

/// `security/allowlist-sso.txt` as shipped.
pub const EMBEDDED_SSO: &str = include_str!("../../../../security/allowlist-sso.txt");
/// `security/trackers-top20.json` as shipped (a WebKit content rule list).
pub const EMBEDDED_TRACKERS: &str = include_str!("../../../../security/trackers-top20.json");

pub const SSO_ALLOWLIST_TXT: &str = "allowlist-sso.txt";
pub const TRACKERS_JSON: &str = "trackers-top20.json";

const DEFAULT_ETC_DIR: &str = "/etc/soc-display";
/// Data files are tiny; anything larger is not one of ours.
const MAX_DATA_FILE: u64 = 1 << 20;

/// The loaded data files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityData {
    /// Bundled SSO / identity-provider domains, as written (`*.okta.com`).
    pub sso_domains: Vec<String>,
    /// The raw rule-list JSON, for WebKit's `UserContentFilterStore`.
    pub tracker_rules: String,
    /// Plain tracker hosts derived from the rules, lower-cased, de-duplicated.
    pub tracker_hosts: Vec<String>,
    /// Problems found while loading (for the journal).
    pub warnings: Vec<String>,
}

impl SecurityData {
    /// The data compiled into the binary.
    pub fn embedded() -> SecurityData {
        SecurityData {
            sso_domains: parse_sso_list(EMBEDDED_SSO),
            tracker_rules: EMBEDDED_TRACKERS.to_string(),
            tracker_hosts: tracker_hosts_from_rules(EMBEDDED_TRACKERS).unwrap_or_default(), // audit-allow: default is the intended fallback (embedded rules are pinned by tests)
            warnings: Vec::new(),
        }
    }

    /// The embedded data with any file present in `dir` taking its place.
    pub fn load(dir: Option<&Path>) -> SecurityData {
        let mut data = SecurityData::embedded();
        let Some(dir) = dir else {
            return data;
        };
        match read_small(&dir.join(SSO_ALLOWLIST_TXT)) {
            Ok(Some(text)) => data.sso_domains = parse_sso_list(&text),
            Ok(None) => {}
            Err(e) => {
                data.warnings.push(format!("{}/{SSO_ALLOWLIST_TXT}: {e}; using the built-in list", dir.display()))
            }
        }
        match read_small(&dir.join(TRACKERS_JSON)) {
            Ok(Some(text)) => match tracker_hosts_from_rules(&text) {
                Some(hosts) => {
                    data.tracker_hosts = hosts;
                    data.tracker_rules = text;
                }
                None => data.warnings.push(format!(
                    "{}/{TRACKERS_JSON}: not a JSON rule list; using the built-in blocklist",
                    dir.display()
                )),
            },
            Ok(None) => {}
            Err(e) => data.warnings.push(format!("{}/{TRACKERS_JSON}: {e}; using the built-in list", dir.display())),
        }
        data
    }

    /// The process-wide data, resolved from the environment once.
    pub fn global() -> &'static SecurityData {
        static DATA: OnceLock<SecurityData> = OnceLock::new();
        DATA.get_or_init(|| {
            let env = soc_core::env::env_str;
            let dir = resolve_dir(
                env("SOC_SECURITY_DIR").as_deref(),
                env("SOC_ETC_DIR").as_deref(),
                env("SOC_ROOT").as_deref(),
            );
            let data = SecurityData::load(dir.as_deref());
            for w in &data.warnings {
                eprintln!("[soc-kiosk] security data: {w}");
            }
            data
        })
    }
}

/// Where override data files live, if anywhere: the explicit directory, else
/// the deployed `<etc>/security`, else a checkout's `<root>/security`.
pub fn resolve_dir(security_dir: Option<&str>, etc_dir: Option<&str>, root: Option<&str>) -> Option<PathBuf> {
    if let Some(dir) = security_dir {
        return Some(PathBuf::from(dir));
    }
    let etc = Path::new(etc_dir.unwrap_or(DEFAULT_ETC_DIR)).join("security");
    if etc.is_dir() {
        return Some(etc);
    }
    root.map(|r| Path::new(r).join("security")).filter(|p| p.is_dir())
}

/// `Ok(None)` when the file does not exist.
fn read_small(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut text = String::new();
    file.take(MAX_DATA_FILE + 1).read_to_string(&mut text)?;
    if !u64::try_from(text.len()).is_ok_and(|n| n <= MAX_DATA_FILE) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file is too large"));
    }
    Ok(Some(text))
}

/// One domain per line; `#` comments and blank lines ignored.
pub fn parse_sso_list(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()
}

/// The plain host list behind a rule file: each rule's `url-filter` regex
/// (`google-analytics\.com`) un-escaped to a host. `None` when the text is not
/// a JSON array at all.
///
/// A filter that is not just an escaped host name (`.*`, alternations, paths)
/// is skipped: the host-based fallbacks would turn it into a pattern that
/// matches far more than intended — `.*` would block every request.
pub fn tracker_hosts_from_rules(text: &str) -> Option<Vec<String>> {
    let rules: Value = serde_json::from_str(text).ok()?;
    let mut hosts: Vec<String> = Vec::new();
    for rule in rules.as_array()? {
        if let Some(host) = rule_host(rule).filter(|h| !hosts.contains(h)) {
            hosts.push(host);
        }
    }
    Some(hosts)
}

/// A dotted DNS name made of letters, digits and hyphens.
pub(crate) fn is_plain_host(host: &str) -> bool {
    host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// The un-escaped, lower-cased host a rule's `url-filter` names, if it is one.
fn rule_host(rule: &Value) -> Option<String> {
    let filter = rule.pointer("/trigger/url-filter")?.as_str()?;
    let host = filter.replace("\\.", ".").trim().trim_matches(['^', '$']).to_ascii_lowercase();
    is_plain_host(&host).then_some(host)
}

/// The per-panel top-level navigation allowlist (own origin, bundled SSO,
/// per-panel `allow`, global `security.allow` / `security.sso_allow`).
/// Compute once per panel build.
pub fn build_allowlist(panel: &Panel, security: &SecurityCfg, data: &SecurityData) -> AllowList {
    AllowList::build(panel, security, data)
}

/// True if `host` (see [`host_of`]) is permitted by `allowlist`:
/// case-insensitive, subdomain-inclusive, whole labels only.
pub fn host_matches(host: &str, allowlist: &AllowList) -> bool {
    allowlist.matches(host)
}

/// One compiled-filter variant of the tracker rule list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerFilter {
    /// Stable name of the variant: the panel's normalised `unblock` hosts,
    /// sorted and joined by `_` (empty for the full list). Panels with the
    /// same key share one compiled filter.
    pub key: String,
    /// The rule-list JSON with the unblocked hosts' rules removed.
    pub rules: String,
}

impl TrackerFilter {
    /// Identifier for the content-filter store (`soc-trackers[-<key>]`).
    pub fn identifier(&self) -> String {
        if self.key.is_empty() { "soc-trackers".into() } else { format!("soc-trackers-{}", self.key) }
    }
}

/// The tracker rule list for `panel`, honouring its `unblock` hosts, with the
/// key identifying that variant. Whether to block at all is decided separately
/// by [`should_block_trackers`].
pub fn tracker_filter(panel: &Panel, data: &SecurityData) -> TrackerFilter {
    let unblock = crate::siteguard::unblock_hosts(panel);
    let key = unblock.iter().map(String::as_str).collect::<Vec<_>>().join("_");
    if unblock.is_empty() {
        return TrackerFilter { key, rules: data.tracker_rules.clone() };
    }
    let rules = match serde_json::from_str::<Value>(&data.tracker_rules) {
        Ok(Value::Array(rules)) => {
            let keep: Vec<Value> = rules
                .into_iter()
                .filter(|rule| !rule_host(rule).is_some_and(|h| crate::siteguard::is_unblocked(&h, &unblock)))
                .collect();
            Value::Array(keep).to_string()
        }
        // `data` only ever holds a parsed rule list; keep the full set if not.
        _ => data.tracker_rules.clone(),
    };
    TrackerFilter { key, rules }
}

/// Block trackers for this panel only if the global default (environment and
/// `security:` block) and the per-panel knob all allow it. Any "off" wins.
pub fn should_block_trackers(panel: &Panel, security: &SecurityCfg, env_default: bool) -> bool {
    env_default && security.block_trackers && panel.block_trackers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_tracker_list_is_well_formed() {
        let rules: Value = serde_json::from_str(EMBEDDED_TRACKERS).unwrap();
        let rules = rules.as_array().unwrap();
        assert!(rules.len() >= 20);
        for r in rules {
            assert_eq!(r.pointer("/action/type").and_then(Value::as_str), Some("block"));
            // Third-party only, so a dashboard's own first-party metrics are not caught.
            assert_eq!(r.pointer("/trigger/load-type"), Some(&serde_json::json!(["third-party"])));
            assert!(r.pointer("/trigger/url-filter").and_then(Value::as_str).is_some_and(|s| !s.is_empty()));
        }
    }

    #[test]
    fn tracker_hosts_are_derived_without_regex_escapes() {
        let hosts = SecurityData::embedded().tracker_hosts;
        for want in ["google-analytics.com", "doubleclick.net", "mc.yandex.ru", "connect.facebook.net"] {
            assert!(hosts.iter().any(|h| h == want), "{want} missing");
        }
        assert!(hosts.iter().all(|h| !h.contains('\\')));
    }

    #[test]
    fn regex_filters_never_become_host_patterns() {
        let text = r#"[
            {"trigger": {"url-filter": ".*"}},
            {"trigger": {"url-filter": "(ads|track)\\.example\\.com"}},
            {"trigger": {"url-filter": "^Tracker\\.Example\\.COM$"}},
            {"trigger": {"url-filter": "tracker\\.example\\.com"}},
            {"trigger": {"url-filter": 7}},
            {"trigger": {}},
            "junk"
        ]"#;
        assert_eq!(tracker_hosts_from_rules(text).unwrap(), vec!["tracker.example.com"]);
        assert_eq!(tracker_hosts_from_rules("{}"), None);
        assert_eq!(tracker_hosts_from_rules("garbage"), None);
    }

    #[test]
    fn sso_list_skips_comments() {
        let sso = SecurityData::embedded().sso_domains;
        assert!(sso.iter().any(|d| d == "*.okta.com"));
        assert!(sso.iter().any(|d| d == "accounts.google.com"));
        assert!(sso.iter().all(|d| !d.starts_with('#') && !d.is_empty()));
        assert_eq!(parse_sso_list("# c\n\n a.example \n*.b.example\n"), vec!["a.example", "*.b.example"]);
    }

    #[test]
    fn block_trackers_precedence() {
        let panel = Panel::new("p");
        let sec = SecurityCfg::default();
        assert!(should_block_trackers(&panel, &sec, true));
        assert!(!should_block_trackers(&panel, &sec, false));
        assert!(!should_block_trackers(&panel, &SecurityCfg { block_trackers: false, ..sec.clone() }, true));
        let mut off = Panel::new("p");
        off.block_trackers = false;
        assert!(!should_block_trackers(&off, &sec, true));
    }

    #[test]
    fn override_directory_replaces_files_and_bad_ones_fall_back() {
        let dir = std::env::temp_dir().join(format!("soc-web-secdata-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Nothing in the directory: everything stays built-in.
        assert_eq!(SecurityData::load(Some(&dir)), SecurityData::embedded());

        std::fs::write(dir.join(SSO_ALLOWLIST_TXT), "# ours\nidp.corp.example\n").unwrap();
        std::fs::write(dir.join(TRACKERS_JSON), r#"[{"trigger": {"url-filter": "t\\.example\\.net"}}]"#).unwrap();
        let data = SecurityData::load(Some(&dir));
        assert_eq!(data.sso_domains, vec!["idp.corp.example"]);
        assert_eq!(data.tracker_hosts, vec!["t.example.net"]);
        assert!(data.warnings.is_empty());

        // A corrupt blocklist must not switch tracker blocking off.
        std::fs::write(dir.join(TRACKERS_JSON), "{not json").unwrap();
        let data = SecurityData::load(Some(&dir));
        assert_eq!(data.tracker_hosts, SecurityData::embedded().tracker_hosts);
        assert_eq!(data.tracker_rules, EMBEDDED_TRACKERS);
        assert_eq!(data.warnings.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn allowlist_pair_for_the_webkit_leg() {
        let mut panel = Panel::new("p");
        panel.url = Some("https://dash.example.com/".into());
        panel.allow = vec!["*.cdn.example.net".into()];
        let list = build_allowlist(&panel, &SecurityCfg::default(), &SecurityData::embedded());
        let allowed = |uri: &str| host_of(uri).is_some_and(|h| host_matches(&h, &list));
        assert!(allowed("https://dash.example.com/x"));
        assert!(allowed("https://img.cdn.example.net/a.png"));
        assert!(allowed("https://login.microsoftonline.com/common"));
        assert!(!allowed("https://evildash.example.com.evil.example/"));
        assert!(!allowed("about:blank"), "a URI without a host has nothing to match");
    }

    #[test]
    fn tracker_filter_variants() {
        let data = SecurityData::embedded();
        let mut panel = Panel::new("p");
        let full = tracker_filter(&panel, &data);
        assert_eq!(full.key, "");
        assert_eq!(full.identifier(), "soc-trackers");
        assert_eq!(full.rules, EMBEDDED_TRACKERS);

        // Order, case and wildcard spelling do not change the variant.
        panel.unblock = vec!["Segment.io".into(), "*.segment.com".into(), "segment.io".into()];
        let trimmed = tracker_filter(&panel, &data);
        assert_eq!(trimmed.key, "segment.com_segment.io");
        assert_eq!(trimmed.identifier(), "soc-trackers-segment.com_segment.io");
        let hosts = tracker_hosts_from_rules(&trimmed.rules).unwrap();
        assert!(!hosts.iter().any(|h| h == "segment.io" || h == "cdn.segment.com"));
        assert_eq!(hosts.len(), data.tracker_hosts.len() - 2);
        // The surviving rules are untouched (still third-party block rules).
        let rules: Value = serde_json::from_str(&trimmed.rules).unwrap();
        assert!(rules.as_array().unwrap().iter().all(|r| r["action"]["type"] == "block"));

        // A look-alike entry releases nothing: matching is on whole labels.
        panel.unblock = vec!["analytics.com".into()];
        let same = tracker_filter(&panel, &data);
        assert_eq!(same.key, "analytics.com");
        assert_eq!(tracker_hosts_from_rules(&same.rules).unwrap(), data.tracker_hosts);
    }

    #[test]
    fn override_directory_resolution() {
        assert_eq!(resolve_dir(Some("/x/sec"), None, None), Some(PathBuf::from("/x/sec")));
        let base = std::env::temp_dir().join(format!("soc-web-secdir-{}", std::process::id()));
        let etc = base.join("etc");
        let root = base.join("root");
        std::fs::create_dir_all(root.join("security")).unwrap();
        std::fs::create_dir_all(&etc).unwrap();
        let (etc_s, root_s) = (etc.to_str().unwrap(), root.to_str().unwrap());
        // No <etc>/security: the checkout's directory is used.
        assert_eq!(resolve_dir(None, Some(etc_s), Some(root_s)), Some(root.join("security")));
        std::fs::create_dir_all(etc.join("security")).unwrap();
        assert_eq!(resolve_dir(None, Some(etc_s), Some(root_s)), Some(etc.join("security")));
        assert_eq!(resolve_dir(None, Some(base.join("none").to_str().unwrap()), None), None);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
