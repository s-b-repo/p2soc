//! Config assembly for setup: loading the previous answers, rendering
//! `panels.yaml`, and listing the vault logins a config needs.

use soc_core::{Config, DictExt};
use std::path::Path;

/// One login the config needs in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultItem {
    /// `panel`, `vpn:<name>`, `vpn` or `proxy`.
    pub kind: String,
    /// The vault item name (the config's `vault_item`).
    pub name: String,
    /// The login's URI, `""` when it has none.
    pub uri: String,
}

/// `(kind, vault_item, uri)` for every configured item that needs a login.
pub fn vault_items(cfg: &Config) -> Vec<VaultItem> {
    let mut items = Vec::new();
    for p in &cfg.panels {
        if !p.vault_item.is_empty() {
            items.push(VaultItem {
                kind: "panel".into(),
                name: p.vault_item.clone(),
                uri: p.url.as_deref().unwrap_or("").to_owned(),
            });
        }
    }
    for v in &cfg.vpns {
        let item = v.text("vault_item");
        if v.truthy("enabled") && !item.is_empty() {
            let name = v.text("name");
            let kind = if name.is_empty() { "vpn".to_string() } else { format!("vpn:{name}") };
            items.push(VaultItem { kind, name: item, uri: String::new() });
        }
    }
    if cfg.proxy.enabled && !cfg.proxy.vault_item.is_empty() {
        items.push(VaultItem { kind: "proxy".into(), name: cfg.proxy.vault_item.clone(), uri: cfg.proxy.url.clone() });
    }
    items
}

/// The previous config, or the wizard's defaults (auto display 1920x1080, a
/// 2x2 grid, no panels, tunnel/proxy off) when there is none or it does not
/// parse — the "re-run defaults" behaviour of the wizard.
pub fn previous_config(path: &Path) -> Config {
    if !path.exists() {
        return Config::default();
    }
    soc_core::load(path).unwrap_or_default() // audit-allow: an unreadable previous config only means "start from the defaults"
}

/// `panels.yaml` text for `cfg` (the shared emitter; no second renderer).
pub fn render_panels_yaml(cfg: &Config) -> String {
    soc_core::emit::to_yaml(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML: &str = "display: {auto: true, width: 1920, height: 1080, cols: 2, rows: 1, gap: 0}
panels:
  - {id: p1, engine: webkit, mode: direct, url: 'http://10.0.0.1/login', vault_item: 'SOC Panel 1', selectors: {user: '#u', pass: '#p'}, grid: [0, 0]}
  - {id: p2, engine: webkit, mode: direct, url: 'http://10.0.0.2/', grid: [1, 0]}
vpns:
  - {name: hq, type: fortinet, enabled: true, gateway: vpn.example.net, vault_item: 'SOC VPN'}
  - {name: off, type: openvpn, enabled: false, vault_item: 'SOC VPN2'}
proxy: {enabled: true, url: 'http://proxy.example.net:3128', vault_item: 'SOC Proxy'}
";

    #[test]
    fn items_cover_panels_vpns_and_proxy() {
        let cfg = soc_core::load_str(YAML, "test").unwrap();
        let items = vault_items(&cfg);
        let got: Vec<(&str, &str, &str)> =
            items.iter().map(|i| (i.kind.as_str(), i.name.as_str(), i.uri.as_str())).collect();
        assert_eq!(
            got,
            vec![
                ("panel", "SOC Panel 1", "http://10.0.0.1/login"),
                ("vpn:hq", "SOC VPN", ""),
                ("proxy", "SOC Proxy", "http://proxy.example.net:3128"),
            ]
        );
    }

    #[test]
    fn rendered_yaml_reloads_to_the_same_items() {
        let cfg = soc_core::load_str(YAML, "test").unwrap();
        let again = soc_core::load_str(&render_panels_yaml(&cfg), "round").unwrap();
        assert_eq!(vault_items(&again), vault_items(&cfg));
        assert_eq!(again.panels.len(), 2);
    }

    #[test]
    fn missing_previous_config_is_the_default() {
        let cfg = previous_config(Path::new("/nonexistent/panels.yaml"));
        assert!(cfg.panels.is_empty());
        assert!(cfg.display.auto);
        assert_eq!((cfg.display.width, cfg.display.height, cfg.display.cols, cfg.display.rows), (1920, 1080, 2, 2));
    }
}
