//! Per-backend command assembly.
//!
//! Two shapes of backend:
//!  * *process* drivers (Fortinet, OpenVPN, iNode) run a long-lived foreground
//!    client whose log lines are classified into events;
//!  * the *interface* driver (WireGuard) configures a kernel interface with a
//!    one-shot `wg-quick up` and is supervised by health probing alone.
//!
//! Everything built here is non-secret. Each builder re-runs the soc-core
//! input guards, because a vault overlay can change an entry after load-time
//! validation and the result is the argv of a root process.

use soc_core::guard::{GuardError, has_ctrl, safe_word, safe_word_value};
use soc_core::vpnargs::{
    inode_extra_args, inode_gateway, inode_script, openfortivpn_args, openvpn_args, wireguard_target,
};
use soc_core::{Dict, DictExt, VpnKind};
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, GuardError>;

/// The executables the supervisor runs. Names are resolved through `$PATH`;
/// absolute paths pin them (and let tests substitute a fake client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Programs {
    pub openfortivpn: String,
    pub openvpn: String,
    pub wg_quick: String,
    pub wg: String,
    pub ip: String,
}

impl Default for Programs {
    fn default() -> Self {
        Programs {
            openfortivpn: "openfortivpn".into(),
            openvpn: "openvpn".into(),
            wg_quick: "wg-quick".into(),
            wg: "wg".into(),
            ip: "ip".into(),
        }
    }
}

/// Filesystem locations the supervisor depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The pinentry helper handed to `openfortivpn --pinentry=`.
    pub pinentry: PathBuf,
    /// The installation root (`$SOC_ROOT`), home of the bundled iNode client.
    pub root: PathBuf,
    /// `$HOME`, for a `~/…` iNode client path.
    pub home: Option<PathBuf>,
    /// Parent of the private `soc-vpn` runtime directory
    /// (`$XDG_RUNTIME_DIR`, else `/run`).
    pub runtime_base: PathBuf,
    pub programs: Programs,
    /// The native iNode client invocation (this binary's `inode-connect`
    /// subcommand), used in place of the vendored `svpn-connect.sh`. `None`
    /// falls back to the bundled script (`SOC_INODE_NATIVE=0`, or the current
    /// executable could not be resolved).
    pub inode_native: Option<Vec<String>>,
}

impl Paths {
    /// Resolve from a variable lookup. The pinentry defaults to the
    /// `soc-vpn-pinentry` program next to the running executable.
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>, exe: Option<&Path>, cwd: &Path) -> Paths {
        let set = |name: &str| get(name).filter(|v| !v.is_empty());
        let pinentry = set("SOC_VPN_PINENTRY")
            .map(PathBuf::from)
            .unwrap_or_else(|| exe.and_then(Path::parent).unwrap_or(cwd).join(crate::pinentry::PINENTRY_NAME));
        // The native iNode client is this binary's `inode-connect`
        // subcommand, unless explicitly disabled or the exe is unknown.
        let inode_native = (set("SOC_INODE_NATIVE").as_deref() != Some("0"))
            .then(|| exe.and_then(|e| e.to_str()).map(|exe| vec![exe.to_string(), "inode-connect".to_string()]))
            .flatten();
        Paths {
            pinentry,
            root: set("SOC_ROOT").map(PathBuf::from).unwrap_or_else(|| cwd.to_path_buf()),
            home: set("HOME").map(PathBuf::from),
            runtime_base: set("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/run")),
            programs: Programs::default(),
            inode_native,
        }
    }

    pub fn from_env() -> Paths {
        let exe = std::env::current_exe().ok();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        Paths::from_lookup(&|name| std::env::var(name).ok(), exe.as_deref(), &cwd)
    }
}

/// The client's name in log lines.
pub const fn binary(kind: VpnKind) -> &'static str {
    match kind {
        VpnKind::Fortinet => "openfortivpn",
        VpnKind::Openvpn => "openvpn",
        VpnKind::Wireguard => "wg-quick",
        VpnKind::Inode => "svpn-connect.sh",
    }
}

/// Whether the backend is an interface driver (no long-lived client).
pub const fn is_interface(kind: VpnKind) -> bool {
    matches!(kind, VpnKind::Wireguard)
}

/// Whether connecting needs a username/password from the vault. OpenVPN does
/// only when a vault item is named (certificate-only profiles need none).
pub fn needs_creds(kind: VpnKind, vpn: &Dict) -> bool {
    match kind {
        VpnKind::Fortinet | VpnKind::Inode => true,
        VpnKind::Openvpn => !vpn.text("vault_item").is_empty(),
        VpnKind::Wireguard => false,
    }
}

/// The executable whose presence is checked before supervising: a `$PATH`
/// name, or the script path for the iNode client shipped with the wall.
pub fn resolve_binary(kind: VpnKind, vpn: &Dict, paths: &Paths) -> String {
    match kind {
        VpnKind::Fortinet => paths.programs.openfortivpn.clone(),
        VpnKind::Openvpn => paths.programs.openvpn.clone(),
        VpnKind::Wireguard => paths.programs.wg_quick.clone(),
        // The native client is this binary (always present); else the script.
        // An empty prefix is not reachable from `from_lookup`, but should it
        // ever be, fall back to the script rather than an empty binary path.
        VpnKind::Inode => match paths.inode_native.as_deref() {
            Some([exe, ..]) => exe.clone(),
            _ => inode_script(vpn, &paths.root, paths.home.as_deref()).display().to_string(),
        },
    }
}

/// A vault-supplied username bound for argv. Control characters could split a
/// log line; nothing else is restricted here because the name is always its
/// own argv element after `-u`.
fn safe_user(user: &str) -> Result<()> {
    if has_ctrl(user) {
        return Err(GuardError("the vault username contains control characters".into()));
    }
    Ok(())
}

/// Full openfortivpn argv. The password travels through the pinentry helper,
/// never argv. So does the one-time code, unless `otp` is given: that is the
/// legacy `--otp=` form, briefly visible in the process list.
pub fn fortinet_cmd(vpn: &Dict, paths: &Paths, user: &str, otp: Option<&str>) -> Result<Vec<String>> {
    safe_user(user)?;
    let args = openfortivpn_args(vpn)?;
    if args.is_empty() {
        return Err(GuardError("vpn.gateway is empty".into()));
    }
    let mut cmd = vec![paths.programs.openfortivpn.clone()];
    cmd.extend(args);
    cmd.extend(["-u".to_string(), user.to_string(), format!("--pinentry={}", paths.pinentry.display())]);
    if let Some(otp) = otp.filter(|o| !o.is_empty()) {
        cmd.push(format!("--otp={otp}"));
    }
    Ok(cmd)
}

/// OpenVPN argv. With a management socket (username/password auth) openvpn is
/// told to ask it for the password and to start held, so the supervisor can
/// connect before authentication proceeds.
pub fn openvpn_cmd(vpn: &Dict, paths: &Paths, mgmt_socket: Option<&Path>) -> Result<Vec<String>> {
    let args = openvpn_args(vpn)?;
    if args.is_empty() {
        return Err(GuardError("vpn.config is empty".into()));
    }
    let mut cmd = vec![paths.programs.openvpn.clone()];
    cmd.extend(args);
    if let Some(sock) = mgmt_socket {
        cmd.extend([
            "--management".to_string(),
            sock.display().to_string(),
            "unix".to_string(),
            "--management-query-passwords".to_string(),
            "--management-hold".to_string(),
        ]);
    }
    Ok(cmd)
}

/// `svpn-connect.sh <gw:port> <user> [domain] [-- flags]`. The password is
/// not here: the supervisor sets `$H3C_SVPN_PASSWORD` in the child.
pub fn inode_cmd(vpn: &Dict, paths: &Paths, user: &str) -> Result<Vec<String>> {
    safe_user(user)?;
    // The script reads its positionals itself, so a leading '-' in the user
    // or domain slot would be taken for an option.
    let user = safe_word(user, "the vault username")?;
    let gateway = inode_gateway(vpn)?;
    if gateway.is_empty() {
        return Err(GuardError("vpn.gateway is empty".into()));
    }
    // Prefer the native in-binary client; fall back to the bundled script when
    // no native prefix is configured (or, defensively, an empty one is).
    let mut cmd = match paths.inode_native.as_deref() {
        Some(prefix @ [_, ..]) => prefix.to_vec(),
        _ => vec![inode_script(vpn, &paths.root, paths.home.as_deref()).display().to_string()],
    };
    cmd.push(gateway);
    cmd.push(user);
    let domain = safe_word_value(vpn.get("domain"), "vpn.domain")?;
    if !domain.is_empty() {
        cmd.push(domain);
    }
    cmd.extend(inode_extra_args(vpn)?);
    Ok(cmd)
}

/// The wg-quick target, vetted for an argv slot.
fn wireguard_safe_target(vpn: &Dict) -> Result<String> {
    let target = wireguard_target(vpn);
    if target.is_empty() {
        return Err(GuardError("vpn.config is empty".into()));
    }
    if has_ctrl(&target) {
        return Err(GuardError("vpn.config contains control characters".into()));
    }
    safe_word(&target, "vpn.config")
}

pub fn wireguard_up(vpn: &Dict, paths: &Paths) -> Result<Vec<String>> {
    Ok(vec![paths.programs.wg_quick.clone(), "up".into(), wireguard_safe_target(vpn)?])
}

pub fn wireguard_down(vpn: &Dict, paths: &Paths) -> Result<Vec<String>> {
    Ok(vec![paths.programs.wg_quick.clone(), "down".into(), wireguard_safe_target(vpn)?])
}

/// Interface name for `wg show`: basename of the target, without `.conf`.
pub fn wireguard_iface(vpn: &Dict) -> String {
    let target = wireguard_target(vpn);
    let base = target.rsplit('/').next().unwrap_or("");
    base.strip_suffix(".conf").unwrap_or(base).to_string()
}

/// Whether `name` is something the kernel accepts as an interface name. It
/// is passed to `wg show` and `ip link delete`, and names a file in the
/// private runtime directory.
pub fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name != "."
        && name != ".."
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '+' | '.' | '-'))
}

/// An argv safe to print: masks the value of any secret-bearing flag.
pub fn redact_argv(cmd: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(cmd.len());
    let mut hide = false;
    for arg in cmd {
        if hide {
            out.push("<redacted>".to_string());
        } else if arg.starts_with("--otp=") {
            out.push("--otp=<redacted>".to_string());
        } else {
            out.push(arg.clone());
        }
        hide = arg == "--spa-key";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{dict, paths};
    use serde_json::json;

    #[test]
    fn fortinet_command_has_no_secret_by_default() {
        let vpn = dict(json!({"enabled": true, "gateway": "gw.example", "port": 443, "vault_item": "VPN",
                              "set_routes": true}));
        let cmd = fortinet_cmd(&vpn, &paths(), "alice", None).unwrap();
        assert_eq!(cmd, ["openfortivpn", "gw.example:443", "--set-routes=1", "-u", "alice", "--pinentry=/x/pinentry"]);
        assert!(!cmd.join(" ").contains("--otp"));
        assert!(!cmd.iter().any(|a| a.to_lowercase().contains("password")));
    }

    #[test]
    fn fortinet_legacy_otp_is_the_only_secret_on_argv() {
        let vpn = dict(json!({"gateway": "gw.example", "port": 10443}));
        let cmd = fortinet_cmd(&vpn, &paths(), "alice", Some("123456")).unwrap();
        assert_eq!(cmd[1], "gw.example:10443");
        assert_eq!(cmd.last().unwrap(), "--otp=123456");
        assert!(!fortinet_cmd(&vpn, &paths(), "a", Some("")).unwrap().join(" ").contains("--otp"));
    }

    #[test]
    fn fortinet_guards_run_again_at_connect_time() {
        let p = paths();
        assert!(fortinet_cmd(&dict(json!({})), &p, "u", None).is_err());
        assert!(fortinet_cmd(&dict(json!({"gateway": "--pppd-plugin=/tmp/evil.so"})), &p, "u", None).is_err());
        assert!(fortinet_cmd(&dict(json!({"gateway": "gw", "realm": "-x"})), &p, "u", None).is_err());
        assert!(fortinet_cmd(&dict(json!({"gateway": "gw"})), &p, "al\nice", None).is_err());
    }

    #[test]
    fn openvpn_command_with_and_without_management() {
        let p = paths();
        let vpn = dict(json!({"config": "/x.ovpn"}));
        assert_eq!(openvpn_cmd(&vpn, &p, None).unwrap(), ["openvpn", "--config", "/x.ovpn"]);
        let cmd = openvpn_cmd(&vpn, &p, Some(Path::new("/run/m.sock"))).unwrap();
        assert_eq!(
            cmd[3..],
            ["--management", "/run/m.sock", "unix", "--management-query-passwords", "--management-hold"]
        );
        assert!(openvpn_cmd(&dict(json!({})), &p, None).is_err());
    }

    #[test]
    fn creds_are_needed_per_backend() {
        assert!(needs_creds(VpnKind::Fortinet, &dict(json!({}))));
        assert!(needs_creds(VpnKind::Inode, &dict(json!({}))));
        assert!(needs_creds(VpnKind::Openvpn, &dict(json!({"vault_item": "X"}))));
        assert!(!needs_creds(VpnKind::Openvpn, &dict(json!({}))));
        assert!(!needs_creds(VpnKind::Wireguard, &dict(json!({"vault_item": "X"}))));
    }

    #[test]
    fn wireguard_commands_and_interface() {
        let p = paths();
        let vpn = dict(json!({"config": "/etc/wireguard/wg0.conf"}));
        assert_eq!(wireguard_up(&vpn, &p).unwrap(), ["wg-quick", "up", "/etc/wireguard/wg0.conf"]);
        assert_eq!(wireguard_down(&vpn, &p).unwrap(), ["wg-quick", "down", "/etc/wireguard/wg0.conf"]);
        assert_eq!(wireguard_iface(&vpn), "wg0");
        assert_eq!(wireguard_iface(&dict(json!({"config": "corp"}))), "corp");
        assert!(is_interface(VpnKind::Wireguard) && !is_interface(VpnKind::Openvpn));
        assert!(wireguard_up(&dict(json!({"config": "-h"})), &p).is_err());
        assert!(wireguard_up(&dict(json!({})), &p).is_err());
    }

    #[test]
    fn interface_names_are_vetted() {
        for ok in ["wg0", "corp", "wg-site.1"] {
            assert!(valid_iface(ok), "{ok}");
        }
        for bad in ["", "-h", "..", "a/b", "name with space", "sixteen-chars-xx"] {
            assert!(!valid_iface(bad), "{bad}");
        }
    }

    #[test]
    fn inode_command_shapes() {
        let p = paths();
        let vpn = dict(json!({"gateway": "g", "port": 3000, "config": "/c", "domain": "system",
                              "trusted_cert": "AA:BB", "split_tunnel": false}));
        assert_eq!(
            inode_cmd(&vpn, &p, "user1").unwrap(),
            ["/c/svpn-connect.sh", "g:3000", "user1", "system", "--", "--pin-sha256", "AA:BB"]
        );
        assert_eq!(resolve_binary(VpnKind::Inode, &vpn, &p), "/c/svpn-connect.sh");

        // With the native client, the program is this binary's inode-connect
        // subcommand and the positionals/flags follow unchanged.
        let native = Paths { inode_native: Some(vec!["/usr/bin/soc-wall".into(), "inode-connect".into()]), ..paths() };
        assert_eq!(
            inode_cmd(&vpn, &native, "user1").unwrap(),
            ["/usr/bin/soc-wall", "inode-connect", "g:3000", "user1", "system", "--", "--pin-sha256", "AA:BB"]
        );
        assert_eq!(resolve_binary(VpnKind::Inode, &vpn, &native), "/usr/bin/soc-wall");
        // Unset config selects the client bundled under the installation root.
        assert_eq!(
            resolve_binary(VpnKind::Inode, &dict(json!({})), &p),
            "/opt/soc/vendor/iNode-VPN-Client/svpn-connect.sh"
        );
    }

    #[test]
    fn inode_separator_only_when_there_are_flags() {
        let p = paths();
        let bare = dict(json!({"type": "inode", "gateway": "gw.example:443", "split_tunnel": false}));
        let cmd = inode_cmd(&bare, &p, "alice").unwrap();
        assert_eq!(cmd.last().unwrap(), "alice");
        assert!(!cmd.contains(&"--".to_string()));

        // Without `--` the script would take the next argument for the domain,
        // silently dropping the certificate pin.
        let pinned = dict(json!({"gateway": "gw.example:443", "split_tunnel": false, "trusted_cert": "AA:BB:CC:DD"}));
        let cmd = inode_cmd(&pinned, &p, "alice").unwrap();
        let sep = cmd.iter().position(|a| a == "--").unwrap();
        assert_eq!(cmd[sep..], ["--", "--pin-sha256", "AA:BB:CC:DD"]);

        let with_domain = dict(json!({"gateway": "gw.example:443", "domain": "corp", "split_tunnel": false,
                                      "trusted_cert": "AA:BB:CC:DD"}));
        let cmd = inode_cmd(&with_domain, &p, "alice").unwrap();
        assert_eq!(cmd[3..], ["corp", "--", "--pin-sha256", "AA:BB:CC:DD"]);

        let insecure = dict(json!({"gateway": "gw.example:443", "split_tunnel": false, "insecure": true}));
        let cmd = inode_cmd(&insecure, &p, "alice").unwrap();
        assert_eq!(cmd[cmd.len() - 2..], ["--", "--insecure"]);
    }

    #[test]
    fn inode_pin_wins_and_extras_follow() {
        let p = paths();
        let both = dict(json!({"gateway": "gw.example:443", "trusted_cert": "AA:BB", "insecure": true}));
        let cmd = inode_cmd(&both, &p, "alice").unwrap();
        assert!(cmd.contains(&"--pin-sha256".to_string()) && !cmd.contains(&"--insecure".to_string()));

        let extras = dict(json!({"gateway": "gw.example:443", "trusted_cert": "AA", "split_tunnel": false,
                                 "extra_args": ["--min-tls", "1.2", "--ead"]}));
        let cmd = inode_cmd(&extras, &p, "alice").unwrap();
        let sep = cmd.iter().position(|a| a == "--").unwrap();
        assert_eq!(cmd[sep..], ["--", "--pin-sha256", "AA", "--min-tls", "1.2", "--ead"]);

        // Split tunnel is the default: a gateway's redirect-all would take the
        // default route and DNS away from everything not behind the VPN.
        let default = dict(json!({"type": "inode", "gateway": "gw.example:443"}));
        assert!(inode_cmd(&default, &p, "alice").unwrap().contains(&"--split-tunnel".to_string()));
    }

    #[test]
    fn inode_refuses_option_looking_positionals() {
        let p = paths();
        let vpn = dict(json!({"gateway": "g"}));
        assert!(inode_cmd(&vpn, &p, "--auth-only").is_err());
        assert!(inode_cmd(&dict(json!({"gateway": "g", "domain": "-x"})), &p, "u").is_err());
        assert!(inode_cmd(&dict(json!({})), &p, "u").is_err());
    }

    #[test]
    fn redaction_masks_the_spa_key_and_a_legacy_otp() {
        let cmd: Vec<String> =
            ["s.sh", "g:443", "u", "--", "--spa-key", "deadbeef", "--otp=123456", "-v"].map(String::from).to_vec();
        let shown = redact_argv(&cmd).join(" ");
        assert_eq!(shown, "s.sh g:443 u -- --spa-key <redacted> --otp=<redacted> -v");
    }

    #[test]
    fn paths_resolution() {
        let lookup = |name: &str| match name {
            "SOC_ROOT" => Some("/opt/soc".to_string()),
            "XDG_RUNTIME_DIR" => Some(String::new()),
            _ => None,
        };
        let p = Paths::from_lookup(&lookup, Some(Path::new("/usr/bin/soc-wall")), Path::new("/cwd"));
        assert_eq!(p.pinentry, Path::new("/usr/bin/soc-vpn-pinentry"));
        assert_eq!(p.root, Path::new("/opt/soc"));
        assert_eq!(p.runtime_base, Path::new("/run"));
        let custom = |name: &str| (name == "SOC_VPN_PINENTRY").then(|| "/p/helper".to_string());
        let p = Paths::from_lookup(&custom, None, Path::new("/cwd"));
        assert_eq!(p.pinentry, Path::new("/p/helper"));
        assert_eq!(p.root, Path::new("/cwd"));
    }
}
