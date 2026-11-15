//! Engine-shared site guard: the top-level navigation allowlist and the
//! per-panel tracker blocklist.
//!
//! Both renderers compute the same [`AllowList`] and consume the same curated
//! data from [`crate::websecurity`], so a panel is contained identically
//! whichever engine draws it.
//!
//! Granularity: the allowlist gates document navigation only. Sub-resources,
//! XHR and websockets go through the tracker filter alone, so a dashboard's
//! CDN and fonts keep working while a hijacked page still cannot drive the
//! wall to an arbitrary site.

use std::collections::BTreeSet;
use std::net::IpAddr;

use soc_core::url::Url;
use soc_core::{Panel, SecurityCfg};

use crate::websecurity::SecurityData;

/// Lower-cased host of an absolute URL, or `None` when it has none or the
/// authority is malformed. Stricter than a lenient parser on purpose: a URL
/// this cannot read is never matched against the allowlist.
pub fn host_of(url: &str) -> Option<String> {
    let parts = Url::split(url.trim()).ok()?;
    let host = parts.host?;
    // Canonical URLs (what an engine reports) never carry these in the
    // authority; a string that does is a parser-confusion attempt such as
    // `https://evil.example\@good.example/`.
    if parts.netloc.chars().any(|c| c == '\\' || c.is_whitespace() || c.is_control()) {
        return None;
    }
    if parts.netloc.contains('[') && !is_ipv6_literal(&host) {
        return None;
    }
    Some(host)
}

/// Whether the text between `[` `]` is an IPv6 literal (optionally zoned).
pub(crate) fn is_ipv6_literal(host: &str) -> bool {
    let addr = host.split_once('%').map_or(host, |(addr, _zone)| addr);
    addr.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Normalise one allowlist / unblock entry to a bare lower-case host.
///
/// Accepts the shapes operators actually write — `*.d.com`, `.d.com`,
/// `d.com.`, `d.com:8443`, `https://d.com/login` — and returns `None` for
/// anything that is not a host afterwards (a stray `*`, a path, non-ASCII), so
/// such an entry is reported instead of silently never matching.
pub fn normalise_pattern(raw: &str) -> Option<String> {
    let mut p = raw.trim().to_ascii_lowercase();
    if p.contains("://") {
        p = host_of(&p)?;
    }
    let mut p = p.strip_prefix("*.").unwrap_or(&p).trim_matches('.');
    if let Some(inner) = p.strip_prefix('[') {
        // A bracketed IPv6 literal, with or without a port.
        p = inner.split_once(']')?.0;
    } else if let Some((host, port)) = p.rsplit_once(':') {
        if !host.contains(':') && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            p = host;
        }
    }
    let ok = !p.is_empty()
        && (p.parse::<IpAddr>().is_ok()
            || p.split('.').all(|label| {
                !label.is_empty() && label.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            }));
    ok.then(|| p.to_string())
}

/// Subdomain-inclusive host match over normalised entries: `host` matches when
/// it equals an entry or is a subdomain of one (`auth.dash.com` under
/// `dash.com`). The comparison is on whole labels, so `evildash.com` does not
/// match `dash.com`. IP literals match exactly only.
fn matches_set(host: &str, set: &BTreeSet<String>) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    if set.contains(host) {
        return true;
    }
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    host.match_indices('.').any(|(dot, _)| {
        let parent = &host[dot + 1..];
        set.contains(parent) && parent.parse::<IpAddr>().is_err()
    })
}

/// True if `host` is permitted by the raw `patterns` (`*.d.com` or `d.com`,
/// both subdomain-inclusive, case-insensitive, trailing dot ignored).
pub fn pattern_matches<I, S>(host: &str, patterns: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let set: BTreeSet<String> = patterns.into_iter().filter_map(|p| normalise_pattern(p.as_ref())).collect();
    matches_set(host, &set)
}

/// The set of hosts a panel may navigate to at the top level.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AllowList {
    hosts: BTreeSet<String>,
    rejected: Vec<String>,
}

impl AllowList {
    /// Build a panel's allowlist:
    ///
    /// 1. the panel's own origin host (loopback for tunnel panels),
    /// 2. the bundled cloud-SSO list and `security.sso_allow`,
    /// 3. the per-panel `allow`,
    /// 4. the global `security.allow`.
    ///
    /// Computed once per panel build (and again when its URL changes).
    pub fn build(panel: &Panel, security: &SecurityCfg, data: &SecurityData) -> AllowList {
        let mut list = AllowList::default();
        if let Some(own) = host_of(&panel.effective_url()) {
            list.hosts.insert(own.trim_end_matches('.').to_string());
        }
        let entries = data.sso_domains.iter().chain(&security.sso_allow).chain(&panel.allow).chain(&security.allow);
        for entry in entries {
            list.add(entry);
        }
        list
    }

    /// A list of exactly these entries (no bundled data).
    pub fn from_patterns<I, S>(patterns: I) -> AllowList
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = AllowList::default();
        for p in patterns {
            list.add(p.as_ref());
        }
        list
    }

    fn add(&mut self, entry: &str) {
        if entry.trim().is_empty() {
            return;
        }
        match normalise_pattern(entry) {
            Some(host) => {
                self.hosts.insert(host);
            }
            None => self.rejected.push(entry.to_string()),
        }
    }

    /// Whether `host` (as an engine reports it) is on the list.
    pub fn matches(&self, host: &str) -> bool {
        matches_set(host, &self.hosts)
    }

    pub fn contains(&self, host: &str) -> bool {
        self.hosts.contains(host)
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// The normalised hosts, sorted.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    /// Configured entries that are not host names and were ignored — worth a
    /// journal line, since the operator expected them to allow something.
    pub fn rejected(&self) -> &[String] {
        &self.rejected
    }

    /// True if a top-level navigation to `url` is permitted.
    ///
    /// * http(s): the host must be on the list;
    /// * `about:` and `data:` — the wall's own blank and placeholder pages
    ///   (engines refuse page-initiated top-level `data:` navigations
    ///   themselves) — and the browser's internal `chrome-error:` page pass;
    /// * `blob:` is judged by the origin embedded in it;
    /// * anything else (`file:`, `ftp:`, custom protocol handlers) is refused:
    ///   a wall has no use for it and an unknown scheme is not vetted.
    pub fn nav_allowed(&self, url: &str) -> bool {
        let u = url.trim();
        if u.is_empty() {
            return true;
        }
        let scheme = u.split_once(':').map_or("", |(s, _)| s).to_ascii_lowercase();
        match scheme.as_str() {
            "about" | "data" | "chrome-error" => true,
            "http" | "https" => host_of(u).is_some_and(|h| self.matches(&h)),
            "blob" => {
                let inner = u.get(5..).unwrap_or_default(); // audit-allow: default is the intended fallback (scheme is ASCII "blob", so None is unreachable)
                matches!(inner.split_once(':'), Some((s, _)) if s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
                    && host_of(inner).is_some_and(|h| self.matches(&h))
            }
            _ => false,
        }
    }
}

/// A panel's `unblock` entries as normalised hosts, sorted and de-duplicated.
pub fn unblock_hosts(panel: &Panel) -> BTreeSet<String> {
    panel.unblock.iter().filter_map(|u| normalise_pattern(u)).collect()
}

/// Whether tracker host `host` is released by the `unblock` set: it equals an
/// entry or is a subdomain of one. Label-aligned, like every other host
/// comparison here — unblocking `analytics.com` does not release
/// `google-analytics.com`.
pub fn is_unblocked(host: &str, unblock: &BTreeSet<String>) -> bool {
    matches_set(host, unblock)
}

/// The tracker hosts to block for this panel: the curated list minus anything
/// equal to, or under, one of its `unblock` entries.
pub fn tracker_hosts(panel: &Panel, data: &SecurityData) -> Vec<String> {
    let unblock = unblock_hosts(panel);
    data.tracker_hosts.iter().filter(|h| !is_unblocked(h, &unblock)).cloned().collect()
}

/// Whether a request to `host` hits the blocklist `hosts` (exact host or a
/// subdomain). For engines that block per request rather than by pattern.
pub fn is_tracker_host(host: &str, hosts: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    hosts.iter().any(|h| host == h || host.strip_suffix(h.as_str()).is_some_and(|rest| rest.ends_with('.')))
}

/// The tracker hosts as `Network.setBlockedURLs` patterns.
///
/// Each pattern is anchored to the authority (`*://host/*`, `*://*.host/*`,
/// and the same with a port), not a bare `*host*` substring: on a SOC wall
/// tracker domains routinely appear inside first-party URLs — a threat-intel
/// search for `?domain=doubleclick.net` must not be blocked as if it were a
/// request to the tracker.
pub fn chromium_blocked_urls(panel: &Panel, data: &SecurityData) -> Vec<String> {
    tracker_hosts(panel, data)
        .iter()
        .flat_map(|h| [format!("*://{h}/*"), format!("*://*.{h}/*"), format!("*://{h}:*/*"), format!("*://*.{h}:*/*")])
        .collect()
}

/// Whether tracker blocking applies to this panel: the global default and the
/// per-panel knob must both be on.
pub fn trackers_enabled(panel: &Panel, security: &SecurityCfg) -> bool {
    security.block_trackers && panel.block_trackers
}

/// Whether the top-level navigation allowlist is active.
pub fn nav_gate_enabled(security: &SecurityCfg) -> bool {
    security.nav_allowlist
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dash() -> Panel {
        let mut p = Panel::new("a");
        p.url = Some("https://dash.example.com/overview".into());
        p
    }

    fn list(panel: &Panel, security: &SecurityCfg) -> AllowList {
        AllowList::build(panel, security, &SecurityData::embedded())
    }

    #[test]
    fn host_match_is_label_aligned() {
        for (host, allowed, expect) in [
            ("dash.example.com", "dash.example.com", true),
            ("auth.dash.example.com", "dash.example.com", true),
            ("a.b.dashboard.com", "dashboard.com", true),
            ("dash.example.com", "example.com", true),
            ("evil.com", "dash.example.com", false),
            ("evildashboard.com", "dashboard.com", false),
            ("evilexample.com", "example.com", false),
            ("example.com.evil.com", "example.com", false),
            ("dashboard.com.evil.com", "dashboard.com", false),
            ("login.okta.com", "*.okta.com", true),
            ("okta.com", "*.okta.com", true),
            ("notokta.com", "*.okta.com", false),
            ("127.0.0.1", "127.0.0.1", true),
            ("", "example.com", false),
            ("DASH.EXAMPLE.COM", "dash.example.com", true),
            ("dash.example.com.", "dash.example.com", true),
            ("dash.example.com", "Dash.Example.COM.", true),
            ("dash.example.com", ".example.com", true),
            ("com", "example.com", false),
        ] {
            assert_eq!(pattern_matches(host, [allowed]), expect, "{host:?} vs {allowed:?}");
        }
    }

    #[test]
    fn ip_literals_match_exactly_only() {
        assert!(!pattern_matches("evil.127.0.0.1", ["127.0.0.1"]));
        assert!(!pattern_matches("9.10.0.0.1", ["10.0.0.1"]));
        assert!(pattern_matches("fd00::1", ["[fd00::1]"]));
        assert!(pattern_matches("fd00::1", ["fd00::1"]));
        assert!(!pattern_matches("fd00::2", ["fd00::1"]));
    }

    #[test]
    fn entries_are_normalised_or_rejected() {
        assert_eq!(normalise_pattern(" *.Okta.COM "), Some("okta.com".into()));
        assert_eq!(normalise_pattern("https://idp.corp.example/login?x=1"), Some("idp.corp.example".into()));
        assert_eq!(normalise_pattern("idp.corp.example:8443"), Some("idp.corp.example".into()));
        assert_eq!(normalise_pattern("[fd00::1]:8443"), Some("fd00::1".into()));
        assert_eq!(normalise_pattern("grafana"), Some("grafana".into()));
        for bad in ["*", "*.", ".", "", "a b.example", "exa*mple.com", "example.com/path", "bücher.example", "a..b"] {
            assert_eq!(normalise_pattern(bad), None, "{bad:?}");
        }
        let l = AllowList::from_patterns(["ok.example", "*", "bücher.example", "  "]);
        assert_eq!(l.hosts().collect::<Vec<_>>(), vec!["ok.example"]);
        assert_eq!(l.rejected(), ["*", "bücher.example"]);
    }

    #[test]
    fn host_of_reads_canonical_urls_only() {
        assert_eq!(host_of("https://dash.example.com:8443/x").as_deref(), Some("dash.example.com"));
        assert_eq!(host_of("https://a.b.com:8443/x?y=1").as_deref(), Some("a.b.com"));
        assert_eq!(host_of("https://good.example@evil.example/").as_deref(), Some("evil.example"));
        assert_eq!(host_of("not a url"), None);
        assert_eq!(host_of("about:blank"), None);
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https://evil.example\\@good.example/"), None);
        assert_eq!(host_of("https://h:99999/"), None);
    }

    #[test]
    fn allowlist_holds_own_origin_and_sso() {
        let allowed = list(&dash(), &SecurityCfg::default());
        assert!(allowed.contains("dash.example.com"));
        assert!(allowed.contains("accounts.google.com"));
        // Wildcard SSO entries are normalised to bare hosts.
        assert!(allowed.contains("okta.com"));
        assert!(allowed.matches("login.microsoftonline.com"));
        assert!(allowed.matches("auth.dash.example.com"));
        assert!(!allowed.matches("totally-unrelated.com"));
        assert!(allowed.rejected().is_empty());
    }

    #[test]
    fn allowlist_adds_per_panel_and_global_entries() {
        let mut p = dash();
        p.allow = vec!["*.cdn.example.net".into(), "extra.io".into()];
        let sec = SecurityCfg {
            allow: vec!["global.example.org".into()],
            sso_allow: vec!["idp.self-hosted.example".into()],
            ..SecurityCfg::default()
        };
        let allowed = list(&p, &sec);
        for h in ["cdn.example.net", "extra.io", "global.example.org", "idp.self-hosted.example"] {
            assert!(allowed.contains(h), "{h}");
        }
        assert!(allowed.matches("img.cdn.example.net"));
    }

    #[test]
    fn tunnel_panels_allow_loopback() {
        let mut p = Panel::new("t");
        p.url = Some("http://127.0.0.1:8080/d".into());
        assert!(list(&p, &SecurityCfg::default()).matches("127.0.0.1"));
    }

    #[test]
    fn nav_decisions() {
        let allowed = list(&dash(), &SecurityCfg::default());
        for ok in [
            "https://dash.example.com/page",
            "https://sub.dash.example.com/",
            "https://accounts.google.com/o/oauth2",
            "HTTPS://DASH.EXAMPLE.COM/",
            "http://dash.example.com:8080/",
            "about:blank",
            "",
            crate::chromium::UNCONFIGURED_URL,
            "blob:https://dash.example.com/7f3c",
            "chrome-error://chromewebdata/",
        ] {
            assert!(allowed.nav_allowed(ok), "{ok:?} should pass");
        }
        for bad in [
            "https://evil.example/",
            "https://dash.example.com.evil.example/",
            "https://evildash.example.com.evil/",
            "https://dash.example.com@evil.example/",
            "https://evil.example\\@dash.example.com/",
            "https://evil.example/?next=https://dash.example.com/",
            "https://evil.example#@dash.example.com",
            "https://:443/",
            "https:///dash.example.com",
            "http://dash.example.com:99999/",
            "blob:https://evil.example/7f3c",
            "blob:null/7f3c",
            "file:///etc/passwd",
            "ftp://dash.example.com/",
            "ssh://dash.example.com/",
            "javascript:alert(1)",
            "view-source:https://dash.example.com/",
        ] {
            assert!(!allowed.nav_allowed(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn toggles() {
        let sec = SecurityCfg::default();
        assert!(nav_gate_enabled(&sec));
        assert!(!nav_gate_enabled(&SecurityCfg { nav_allowlist: false, ..sec.clone() }));
        assert!(trackers_enabled(&dash(), &sec));
        assert!(!trackers_enabled(&dash(), &SecurityCfg { block_trackers: false, ..sec.clone() }));
        let mut off = dash();
        off.block_trackers = false;
        assert!(!trackers_enabled(&off, &sec));
    }

    #[test]
    fn unblock_trims_the_tracker_list() {
        let data = SecurityData::embedded();
        let mut p = dash();
        assert_eq!(tracker_hosts(&p, &data), data.tracker_hosts);
        p.unblock = vec!["segment.io".into(), "*.Segment.com".into()];
        let hosts = tracker_hosts(&p, &data);
        assert!(!hosts.iter().any(|h| h == "segment.io" || h == "cdn.segment.com"));
        assert!(hosts.iter().any(|h| h == "google-analytics.com"));
        assert_eq!(hosts.len(), data.tracker_hosts.len() - 2);
    }

    #[test]
    fn blocked_url_patterns_are_authority_anchored() {
        let urls = chromium_blocked_urls(&dash(), &SecurityData::embedded());
        assert!(urls.iter().any(|u| u == "*://google-analytics.com/*"));
        assert!(urls.iter().any(|u| u == "*://*.google-analytics.com/*"));
        assert!(urls.iter().any(|u| u == "*://doubleclick.net:*/*"));
        assert!(urls.iter().all(|u| u.starts_with("*://") && u.ends_with("/*")));
        // No bare-substring pattern that would also hit first-party URLs.
        assert!(!urls.iter().any(|u| u == "*google-analytics.com*"));
    }

    #[test]
    fn per_request_tracker_check() {
        let hosts = vec!["doubleclick.net".to_string()];
        assert!(is_tracker_host("doubleclick.net", &hosts));
        assert!(is_tracker_host("Stats.G.DoubleClick.net.", &hosts));
        assert!(!is_tracker_host("notdoubleclick.net", &hosts));
        assert!(!is_tracker_host("doubleclick.net.example.com", &hosts));
    }
}
