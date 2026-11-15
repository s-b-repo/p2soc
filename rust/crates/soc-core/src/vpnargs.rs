//! Non-secret VPN argv builders.
//!
//! Everything returned here is safe to print and log: usernames, passwords and
//! one-time codes are added at connect time by the supervisor through a
//! pinentry helper, a management socket or the child environment — never argv.
//! Each builder re-runs the input guards because a `config_from_vault` overlay
//! can change an entry after load-time validation.

use crate::dict::{Dict, DictExt};
use crate::guard::{GuardError, gateway_hostport, safe_extra_args, safe_word_value};
use crate::model::VpnKind;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, GuardError>;

/// The VPN backend of an entry (`fortinet` when unset or unrecognised).
pub fn vpn_kind(vpn: &Dict) -> VpnKind {
    VpnKind::parse(&vpn.text("type").to_ascii_lowercase()).unwrap_or(VpnKind::Fortinet)
}

/// An explicit tunnel interface-name override for status detection; `""`
/// keeps the per-backend default (ppp0 / tun0 / the wg interface).
pub fn vpn_interface(vpn: &Dict) -> String {
    vpn.text("interface")
}

/// openfortivpn arguments: the gateway plus routing/DNS/cert flags. Empty when
/// no gateway is configured.
pub fn openfortivpn_args(vpn: &Dict) -> Result<Vec<String>> {
    if !vpn.truthy("gateway") {
        return Ok(Vec::new());
    }
    let mut args = vec![gateway_hostport(vpn)?];
    let cert = safe_word_value(vpn.get("trusted_cert"), "vpn.trusted_cert")?;
    if !cert.is_empty() {
        args.push(format!("--trusted-cert={cert}"));
    }
    let ca = safe_word_value(vpn.get("ca_file"), "vpn.ca_file")?;
    if !ca.is_empty() {
        args.push(format!("--ca-file={ca}"));
    }
    let realm = safe_word_value(vpn.get("realm"), "vpn.realm")?;
    if !realm.is_empty() {
        args.push(format!("--realm={realm}"));
    }
    // Emit explicit 0/1 so the gateway cannot silently change routing or DNS.
    for (key, flag) in
        [("set_routes", "--set-routes"), ("set_dns", "--set-dns"), ("half_internet_routes", "--half-internet-routes")]
    {
        if vpn.contains_key(key) {
            args.push(format!("{flag}={}", u8::from(vpn.truthy(key))));
        }
    }
    // --persistent is opt-in: the supervisor owns the reconnect policy, and
    // openfortivpn's own blind reconnect would defeat its auth-lockout guard.
    let persistent = vpn.int("persistent");
    if persistent > 0 {
        args.push(format!("--persistent={persistent}"));
    }
    args.extend(safe_extra_args(vpn.get("extra_args"))?);
    Ok(args)
}

/// OpenVPN flags (after the binary). The profile carries server + certs; a
/// username/password is injected over the management interface.
pub fn openvpn_args(vpn: &Dict) -> Result<Vec<String>> {
    let config = vpn.text("config");
    if config.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec!["--config".to_string(), config];
    if vpn.get("set_routes").is_some_and(|v| crate::dict::as_bool(v) == Some(false)) {
        args.push("--route-nopull".into());
    }
    args.extend(safe_extra_args(vpn.get("extra_args"))?);
    Ok(args)
}

/// The wg-quick target: a `.conf` path or a bare interface name.
pub fn wireguard_target(vpn: &Dict) -> String {
    vpn.text("config")
}

/// `host:port` of the H3C iNode SSL-VPN gateway; `""` when unset.
pub fn inode_gateway(vpn: &Dict) -> Result<String> {
    if vpn.text("gateway").is_empty() {
        return Ok(String::new());
    }
    gateway_hostport(vpn)
}

/// Where the iNode client shipped with the wall lives under `root`.
pub fn bundled_inode_dir(root: &Path) -> PathBuf {
    root.join("vendor").join("iNode-VPN-Client")
}

/// The iNode connect script: `vpn.config` may be the client directory or a
/// direct `.sh` path; unset selects the bundled client under `root`.
pub fn inode_script(vpn: &Dict, root: &Path, home: Option<&Path>) -> PathBuf {
    let configured = vpn.text("config");
    let base = if configured.is_empty() {
        bundled_inode_dir(root)
    } else if let (Some(rest), Some(home)) = (configured.strip_prefix("~/"), home) {
        home.join(rest)
    } else {
        PathBuf::from(configured)
    };
    if base.extension().is_some_and(|e| e == "sh") { base } else { base.join("svpn-connect.sh") }
}

/// The non-secret iNode backend arguments after the script's `--` separator.
/// Empty when there are none. (Username and gateway are positional; the
/// password travels in the child environment.)
pub fn inode_extra_args(vpn: &Dict) -> Result<Vec<String>> {
    let word = |key: &str| safe_word_value(vpn.get(key), &format!("vpn.{key}"));
    let mut tail: Vec<String> = Vec::new();
    let mut flag = |name: &str, value: String| {
        if !value.is_empty() {
            tail.push(name.to_string());
            tail.push(value);
        }
    };

    let pin = word("trusted_cert")?;
    let insecure = pin.is_empty() && vpn.truthy("insecure");
    flag("--pin-sha256", pin);
    flag("--cafile", word("ca_file")?);
    flag("--client-cert", word("client_cert")?);
    flag("--client-key", word("client_key")?);
    flag("--mac", word("mac")?);
    flag("--language", word("language")?);
    let retries = vpn.int("captcha_retries");
    if retries > 0 {
        flag("--captcha-retries", retries.to_string());
    }
    let spa_key = word("spa_key")?;
    let spa = !spa_key.is_empty();
    let (aid, ports) = (word("spa_aid")?, word("spa_ports")?);
    let knock = vpn.int("spa_knock_port");

    // Assemble in the documented order: pin|insecure, certs, identity,
    // captcha, mode switches, then SPA.
    let mut out: Vec<String> = Vec::new();
    if insecure {
        out.push("--insecure".into());
    }
    out.append(&mut tail);
    if vpn.truthy("ead") {
        out.push("--ead".into());
    }
    if vpn.flag("split_tunnel", true) {
        out.push("--split-tunnel".into());
    }
    if spa {
        out.extend(["--spa-key".to_string(), spa_key]);
        if !aid.is_empty() {
            out.extend(["--spa-aid".to_string(), aid]);
        }
        if !ports.is_empty() {
            out.extend(["--spa-ports".to_string(), ports]);
        }
        if knock > 0 {
            out.extend(["--spa-knock-port".to_string(), knock.to_string()]);
        }
    }
    out.extend(safe_extra_args(vpn.get("extra_args"))?);
    if out.is_empty() {
        return Ok(out);
    }
    out.insert(0, "--".into());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn d(v: Value) -> Dict {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn kind_defaults_to_fortinet() {
        assert_eq!(vpn_kind(&d(json!({}))), VpnKind::Fortinet);
        assert_eq!(vpn_kind(&d(json!({"type": "OpenVPN"}))), VpnKind::Openvpn);
        assert_eq!(vpn_kind(&d(json!({"type": "bogus"}))), VpnKind::Fortinet);
    }

    #[test]
    fn fortinet_args_are_explicit_and_non_secret() {
        let vpn = d(json!({
            "gateway": "vpn.example.com", "port": 10443, "vault_item": "SOC VPN",
            "trusted_cert": "ab".repeat(32), "realm": "soc",
            "set_routes": true, "set_dns": false, "half_internet_routes": false,
            "persistent": 0, "extra_args": ["-v"],
        }));
        assert_eq!(
            openfortivpn_args(&vpn).unwrap(),
            vec![
                "vpn.example.com:10443".to_string(),
                format!("--trusted-cert={}", "ab".repeat(32)),
                "--realm=soc".into(),
                "--set-routes=1".into(),
                "--set-dns=0".into(),
                "--half-internet-routes=0".into(),
                "-v".into(),
            ]
        );
    }

    #[test]
    fn fortinet_without_gateway_is_empty() {
        assert!(openfortivpn_args(&d(json!({"realm": "x"}))).unwrap().is_empty());
    }

    #[test]
    fn fortinet_rejects_injection_after_an_overlay() {
        assert!(openfortivpn_args(&d(json!({"gateway": "-oX"}))).is_err());
        assert!(openfortivpn_args(&d(json!({"gateway": "gw", "realm": "-x"}))).is_err());
        assert!(openfortivpn_args(&d(json!({"gateway": "gw", "trusted_cert": "a\nb"}))).is_err());
        assert!(openfortivpn_args(&d(json!({"gateway": "gw", "extra_args": "-v"}))).is_err());
    }

    #[test]
    fn persistent_is_opt_in() {
        let a = openfortivpn_args(&d(json!({"gateway": "gw", "persistent": 30}))).unwrap();
        assert_eq!(a, vec!["gw:443", "--persistent=30"]);
    }

    #[test]
    fn openvpn_args_shape() {
        assert!(openvpn_args(&d(json!({}))).unwrap().is_empty());
        let a = openvpn_args(&d(json!({"config": "/etc/openvpn/soc.ovpn", "set_routes": false}))).unwrap();
        assert_eq!(a, vec!["--config", "/etc/openvpn/soc.ovpn", "--route-nopull"]);
        let a = openvpn_args(&d(json!({"config": "x.ovpn", "set_routes": true}))).unwrap();
        assert_eq!(a, vec!["--config", "x.ovpn"]);
    }

    #[test]
    fn inode_script_resolution() {
        let root = Path::new("/opt/soc");
        assert_eq!(
            inode_script(&d(json!({})), root, None),
            Path::new("/opt/soc/vendor/iNode-VPN-Client/svpn-connect.sh")
        );
        assert_eq!(inode_script(&d(json!({"config": "/x/c.sh"})), root, None), Path::new("/x/c.sh"));
        assert_eq!(
            inode_script(&d(json!({"config": "~/inode"})), root, Some(Path::new("/home/soc"))),
            Path::new("/home/soc/inode/svpn-connect.sh")
        );
    }

    #[test]
    fn inode_args_default_is_split_tunnel() {
        assert_eq!(inode_extra_args(&d(json!({}))).unwrap(), vec!["--", "--split-tunnel"]);
        assert!(inode_extra_args(&d(json!({"split_tunnel": false}))).unwrap().is_empty());
    }

    #[test]
    fn inode_args_full() {
        let vpn = d(json!({
            "trusted_cert": "AA:BB", "insecure": true, "ca_file": "/ca.pem",
            "client_cert": "/c.pem", "client_key": "/k.pem", "mac": "00:11:22:33:44:55",
            "language": "en", "captcha_retries": 3, "ead": true, "split_tunnel": true,
            "spa_key": "k", "spa_aid": "a", "spa_ports": "443", "spa_knock_port": 9000,
            "extra_args": ["--debug"],
        }));
        assert_eq!(
            inode_extra_args(&vpn).unwrap(),
            vec![
                "--",
                "--pin-sha256",
                "AA:BB",
                "--cafile",
                "/ca.pem",
                "--client-cert",
                "/c.pem",
                "--client-key",
                "/k.pem",
                "--mac",
                "00:11:22:33:44:55",
                "--language",
                "en",
                "--captcha-retries",
                "3",
                "--ead",
                "--split-tunnel",
                "--spa-key",
                "k",
                "--spa-aid",
                "a",
                "--spa-ports",
                "443",
                "--spa-knock-port",
                "9000",
                "--debug",
            ]
        );
    }

    #[test]
    fn inode_insecure_only_without_a_pin() {
        let a = inode_extra_args(&d(json!({"insecure": true, "split_tunnel": false}))).unwrap();
        assert_eq!(a, vec!["--", "--insecure"]);
    }

    #[test]
    fn inode_gateway_shapes() {
        assert_eq!(inode_gateway(&d(json!({}))).unwrap(), "");
        assert_eq!(inode_gateway(&d(json!({"gateway": "[fd00::1]:3000"}))).unwrap(), "[fd00::1]:3000");
    }
}
