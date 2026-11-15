//! Pure helpers behind the settings window: no GTK, so they are unit-tested.

use soc_core::{Dict, DictExt, Panel};

/// One vault item the wall touches, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryItem {
    pub name: String,
    pub origin: String,
}

/// Every vault item name the wall touches, deduplicated; the first source wins
/// the origin label: panels, VPNs, proxy, tunnel, then the auth folder.
pub fn inventory_items(
    panels: &[Panel],
    vpns: &[Dict],
    proxy_item: &str,
    tunnel: &Dict,
    folder_items: &[String],
    folder_label: &str,
) -> Vec<InventoryItem> {
    let mut seen: Vec<InventoryItem> = Vec::new();
    let mut add = |name: &str, origin: String| {
        let name = name.trim();
        if !name.is_empty() && !seen.iter().any(|i| i.name == name) {
            seen.push(InventoryItem { name: name.to_string(), origin });
        }
    };
    for p in panels {
        add(&p.vault_item, format!("panel:{}", p.id));
    }
    for v in vpns {
        let name = v.text("name");
        add(&v.text("vault_item"), format!("vpn:{}", if name.is_empty() { "?" } else { &name }));
    }
    add(proxy_item, "proxy".to_string());
    add(&tunnel.text("vault_item"), "tunnel".to_string());
    for name in folder_items {
        add(name, format!("{folder_label} folder"));
    }
    seen
}

/// Pango-markup escaping (`&`, `<`, `>`, quotes).
pub fn escape_markup(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The per-panel "login zones: ..." status line (markup).
pub fn zones_markup(zones: &Dict) -> String {
    if zones.is_empty() {
        return "<b>login zones:</b> none — selectors + heuristics only".to_string();
    }
    let mut names: Vec<&str> = zones.keys().map(String::as_str).collect();
    names.sort_unstable();
    format!("<b>login zones:</b> calibrated ✓  ({})", escape_markup(&names.join(", ")))
}

/// One line from `/proc/meminfo` text.
pub fn memory_summary(meminfo: &str) -> String {
    let kb = |key: &str| -> Option<u64> {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    };
    match (kb("MemTotal"), kb("MemAvailable")) {
        (Some(total), Some(avail)) if total >= 1024 => {
            let (total, avail) = (total / 1024, avail / 1024);
            let used = total.saturating_sub(avail);
            format!("memory         : {used} MB / {total} MB ({}% used)", used * 100 / total.max(1))
        }
        _ => "memory         : unavailable".to_string(),
    }
}

/// What the Status tab knows when it picks its warnings.
pub struct StatusFacts<'a> {
    pub vault_url: &'a str,
    pub vault_email: &'a str,
    pub reachable: bool,
    pub sealed: bool,
    pub configured: usize,
    pub with_creds: usize,
    pub stale: &'a [String],
}

/// The Status tab's loud warnings: each one a silent failure waiting to bite,
/// with the fix inline.
pub fn status_warnings(f: &StatusFacts<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if !f.reachable {
        out.push(format!(
            "⚠ Vaultwarden at {} is NOT reachable — auto-login and the Credentials tab will fail. Check 'systemctl \
             status vaultwarden'.",
            f.vault_url
        ));
    }
    if !f.sealed {
        out.push(
            "⚠ Master password is NOT host-sealed — the wall cannot self-unlock the vault at boot, so auto-login is \
             dead until you run setup (first-run)."
                .to_string(),
        );
    }
    if f.reachable && f.vault_email.is_empty() {
        out.push(
            "⚠ SOC_VAULT_EMAIL is empty in soc.env — register an account and set the email via setup, then re-run \
             first-run."
                .to_string(),
        );
    }
    if f.configured > 0 && f.with_creds == 0 {
        out.push(format!(
            "⚠ {} panel(s) have a URL but NO vault item — those panels will show the login page without \
             auto-filling. Set a vault item on the Panels tab and store the login on Credentials.",
            f.configured
        ));
    }
    if f.with_creds > 0 && !f.reachable {
        out.push(format!(
            "⚠ {} panel(s) depend on the vault for auto-login but the vault is unreachable — fix vaultwarden first.",
            f.with_creds
        ));
    }
    if !f.stale.is_empty() {
        let mut ids = f.stale.to_vec();
        ids.sort();
        out.push(format!(
            "⚠ selectors may be stale on {} panel(s): {}. The dashboard probably changed; update the user/pass/submit \
             selectors and login_marker on the Panels tab > Advanced.",
            ids.len(),
            ids.join(", ")
        ));
    }
    out
}

/// Bold name then a grey "(type)" suffix, so the operator sees the choice
/// without expanding the section.
pub fn vpn_header_markup(name: &str, idx: usize, kind: &str) -> String {
    let name = if name.trim().is_empty() { format!("vpn-{}", idx + 1) } else { name.trim().to_string() };
    let kind = if kind.trim().is_empty() { "?" } else { kind.trim() };
    format!("<b>VPN {}: {}</b>  <span color='#888'>({})</span>", idx + 1, escape_markup(&name), escape_markup(kind))
}

/// A fresh `vpn-N` name not in `used`.
pub fn next_vpn_name(used: &[String], slots: usize) -> String {
    let mut n = slots + 1;
    while used.iter().any(|u| *u == format!("vpn-{n}")) {
        n += 1;
    }
    format!("vpn-{n}")
}

/// Whether a vault error text means "no such item" (the Create flow) rather
/// than a transport failure.
pub fn is_missing_item(err: &str) -> bool {
    let e = err.to_lowercase();
    ["no entry found", "not found", "no vault item", "no password"].iter().any(|m| e.contains(m))
}

/// `host:port` of a vault URL for the cheap reachability probe.
pub fn probe_target(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let default = if scheme.eq_ignore_ascii_case("https") { 443 } else { 8222 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(':') && !p.contains(']') => (h, p.parse().ok()?),
        _ => (authority, default),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| (host.to_string(), port))
}

/// The user-facing part of an inline "Save to vault" failure.
pub fn write_failure(name: &str, err: &str, url: &str) -> String {
    format!("{name}: {err} — check the vault master is correct and Vaultwarden is reachable at {url}, then retry")
}

/// Trimmed, non-empty `vault item` default for a VPN: `SOC VPN <name>`.
pub fn default_vpn_item(current: &str, vpn_name: &str, idx: usize) -> String {
    let current = current.trim();
    if !current.is_empty() {
        return current.to_string();
    }
    let name = if vpn_name.trim().is_empty() { format!("vpn-{}", idx + 1) } else { vpn_name.trim().to_string() };
    format!("SOC VPN {name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn panel(id: &str, item: &str) -> Panel {
        let mut p = Panel::new(id);
        p.vault_item = item.to_string();
        p
    }

    fn dict(v: serde_json::Value) -> Dict {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn inventory_dedups_and_labels_by_first_source() {
        let panels = [panel("p1", "Grafana"), panel("p2", "Grafana"), panel("p3", "")];
        let vpns = [dict(json!({"name": "hq", "vault_item": "VPN hq"})), dict(json!({"vault_item": "Grafana"}))];
        let tunnel = dict(json!({"vault_item": "Jump"}));
        let items =
            inventory_items(&panels, &vpns, " Proxy ", &tunnel, &["TOTP".to_string(), "Jump".to_string()], "Auth");
        let got: Vec<(&str, &str)> = items.iter().map(|i| (i.name.as_str(), i.origin.as_str())).collect();
        assert_eq!(
            got,
            vec![
                ("Grafana", "panel:p1"),
                ("VPN hq", "vpn:hq"),
                ("Proxy", "proxy"),
                ("Jump", "tunnel"),
                ("TOTP", "Auth folder")
            ]
        );
    }

    #[test]
    fn zones_markup_names_the_zones_escaped() {
        assert!(zones_markup(&Dict::new()).contains("none"));
        let z = dict(json!({"user": {}, "pass": {}, "<b>": {}}));
        let m = zones_markup(&z);
        assert!(m.contains("calibrated ✓"));
        assert!(m.contains("&lt;b&gt;, pass, user"), "{m}");
    }

    #[test]
    fn memory_summary_reads_meminfo() {
        let text = "MemTotal:        1000000 kB\nMemFree: 1 kB\nMemAvailable:     250000 kB\n";
        assert_eq!(memory_summary(text), "memory         : 732 MB / 976 MB (75% used)");
        assert_eq!(memory_summary("junk"), "memory         : unavailable");
        assert_eq!(memory_summary("MemTotal: 0 kB\nMemAvailable: 0 kB"), "memory         : unavailable");
    }

    #[test]
    fn warnings_cover_each_silent_failure() {
        let stale = vec!["b".to_string(), "a".to_string()];
        let w = status_warnings(&StatusFacts {
            vault_url: "http://v",
            vault_email: "",
            reachable: false,
            sealed: false,
            configured: 3,
            with_creds: 0,
            stale: &stale,
        });
        assert_eq!(w.len(), 4, "{w:#?}");
        assert!(w.iter().any(|l| l.contains("NOT reachable")));
        assert!(w.iter().any(|l| l.contains("NOT host-sealed")));
        assert!(w.iter().any(|l| l.contains("3 panel(s) have a URL")));
        assert!(w.iter().any(|l| l.contains("a, b")));
        let healthy = StatusFacts {
            vault_url: "http://v",
            vault_email: "me@x",
            reachable: true,
            sealed: true,
            configured: 2,
            with_creds: 2,
            stale: &[],
        };
        assert!(status_warnings(&healthy).is_empty());
        let no_email = StatusFacts { vault_email: "", ..healthy };
        assert_eq!(status_warnings(&no_email).len(), 1);
    }

    #[test]
    fn vpn_names_and_headers() {
        assert_eq!(next_vpn_name(&["vpn-2".to_string()], 1), "vpn-3");
        assert_eq!(next_vpn_name(&[], 0), "vpn-1");
        assert!(vpn_header_markup("a<b", 0, "inode").contains("a&lt;b"));
        assert!(vpn_header_markup("", 1, "").contains("vpn-2"));
        assert_eq!(default_vpn_item("", "hq", 0), "SOC VPN hq");
        assert_eq!(default_vpn_item(" X ", "hq", 0), "X");
        assert_eq!(default_vpn_item("", " ", 2), "SOC VPN vpn-3");
    }

    #[test]
    fn missing_item_vs_transport_error() {
        assert!(is_missing_item("No entry found for x"));
        assert!(is_missing_item("no vault item named"));
        assert!(!is_missing_item("connection refused"));
    }

    #[test]
    fn probe_targets() {
        assert_eq!(probe_target("http://127.0.0.1:8222"), Some(("127.0.0.1".to_string(), 8222)));
        assert_eq!(probe_target("https://vault.example/x"), Some(("vault.example".to_string(), 443)));
        assert_eq!(probe_target("http://vault.example"), Some(("vault.example".to_string(), 8222)));
        assert_eq!(probe_target("http://u:p@h:99/"), Some(("h".to_string(), 99)));
        assert_eq!(probe_target("http://[::1]:5"), Some(("::1".to_string(), 5)));
        assert_eq!(probe_target(""), None);
        assert_eq!(probe_target("http://h:notaport"), None);
    }
}
