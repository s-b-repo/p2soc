//! Record the SSH jump host's key the first time the tunnel starts.
//!
//! The tunnel verifies the jump host strictly, and strict checking needs a
//! key to check against. The first start pins the key (trust on first use,
//! during deployment) and every later connection is held to it. To remove
//! even that window, the operator can put the key in the file themselves —
//! it is then left alone.
//!
//! This runs as root from the tunnel unit's `ExecStartPre` (the unit's
//! sandbox makes the key directory read-only for the tunnel itself), so the
//! first thing it does is become the key directory's owner: root must not
//! read, parse or write anything on the tunnel user's behalf. It never fails
//! the service — if the host is unreachable the tunnel fails closed on its
//! own, the unit restarts, and pinning is simply retried.

use crate::error::{Result, SysError};
use crate::fsutil;
use crate::run::{Runner, SystemRunner, argv};
use crate::tunnel::PINNED_KNOWN_HOSTS;
use soc_core::dict::{as_bool, text, truthy};
use soc_core::guard::safe_host;
use soc_core::{Config, DictExt};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A known-hosts file larger than this is not one this tool maintains.
const MAX_KNOWN_HOSTS_BYTES: u64 = 1 << 20;

/// The host-key algorithms asked for, and the key types accepted back.
const SCAN_TYPES: &str = "ed25519,ecdsa,rsa";
const KEY_TYPES: [&str; 5] =
    ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"];

/// `$SOC_KNOWN_HOSTS`, else the pinned default.
pub fn known_hosts_from_env() -> PathBuf {
    std::env::var_os("SOC_KNOWN_HOSTS")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PINNED_KNOWN_HOSTS.into(), PathBuf::from)
}

/// The host part of a `user@host` jump spec.
pub fn host_of(jump: &str) -> &str {
    jump.rsplit('@').next().unwrap_or(jump)
}

/// True if `path` already holds a key for `host`.
pub fn pinned(runner: &dyn Runner, path: &Path, host: &str) -> bool {
    let mut cmd = argv(&["ssh-keygen", "-F", host, "-f"]);
    cmd.push(path.to_string_lossy().into_owned());
    runner.run(&cmd, Duration::from_secs(30)).is_ok_and(|out| out.success())
}

/// Whether `line` is a plain `host keytype base64` entry for exactly `host`.
/// What gets appended decides who the tunnel trusts, so anything else — a
/// `@cert-authority` marker, a wildcard pattern, an entry for another host —
/// is dropped, whatever produced it.
pub fn valid_key_line(line: &str, host: &str) -> bool {
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    let [name, kind, key] = fields[..] else {
        return false;
    };
    name == host
        && KEY_TYPES.contains(&kind)
        && key.len() >= 16
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Ask `host` for its keys. Empty when it cannot be reached.
pub fn scan(runner: &dyn Runner, host: &str) -> Vec<String> {
    // `--` ends the options: the host can never be read as one.
    let cmd = argv(&["ssh-keyscan", "-T", "10", "-t", SCAN_TYPES, "--", host]);
    match runner.run(&cmd, Duration::from_secs(60)) {
        Ok(out) => out.stdout.lines().filter(|l| valid_key_line(l, host)).map(str::to_string).collect(),
        Err(_) => Vec::new(), // audit-allow: an unreachable host yields no keys, as documented
    }
}

/// Add key lines to `path` without ever exposing a partial file (0640).
pub fn append_atomic(path: &Path, lines: &[String]) -> io::Result<()> {
    let mut content = match fsutil::read_capped(path, MAX_KNOWN_HOSTS_BYTES) {
        Ok(existing) => existing,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    // An existing file without a final newline must not have the first new
    // key glued onto its last entry.
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    for line in lines {
        content.push_str(line);
        content.push('\n');
    }
    fsutil::write_atomic(path, content.as_bytes(), 0o640)
}

#[allow(unsafe_code)] // audit-allow: process-wide credential drop; rustix exposes only per-thread setuid
fn become_user(uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: plain syscalls on integer ids that touch no memory. The order
    // matters and is enforced: supplementary groups first (cleared with
    // `setgroups(0, NULL)`), then the gid, then the uid — after `setuid` the
    // process could no longer change its groups. These are the glibc
    // process-wide wrappers (all threads); rustix only offers per-thread
    // variants, which would be wrong here, so this is the one syscall site
    // the crate cannot express safely.
    let ok = unsafe { libc::setgroups(0, std::ptr::null()) == 0 && libc::setgid(gid) == 0 && libc::setuid(uid) == 0 }; // audit-allow: confined credential syscalls, see SAFETY
    if ok { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Become the owner of `dir` when running as root. Root is only how this
/// gets past the unit's sandbox: the directory belongs to the tunnel user, so
/// a symlink planted there must not be followed with root's rights.
pub fn drop_privileges(dir: &Path) -> io::Result<()> {
    if fsutil::euid() != 0 {
        return Ok(());
    }
    let meta = std::fs::metadata(dir)?;
    become_user(meta.uid(), meta.gid())?;
    if fsutil::euid() != meta.uid() {
        return Err(io::Error::other("privileges were not dropped"));
    }
    Ok(())
}

/// What a pinning run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOutcome {
    /// The tunnel is disabled or has no jump host.
    NoTunnel,
    /// `tunnel.known_hosts` is set: the operator manages that file.
    OperatorManaged,
    AlreadyPinned,
    /// The host did not answer; pinning is retried on the next start.
    Unreachable {
        host: String,
    },
    Pinned {
        host: String,
        keys: usize,
    },
}

/// Pin the jump host's key into `known_hosts` if that is still needed.
pub fn pin_jump_host(conf: &Config, known_hosts: &Path, runner: &dyn Runner) -> Result<PinOutcome> {
    let t = &conf.tunnel;
    let enabled = t.get("enabled").is_none_or(|v| as_bool(v).unwrap_or_else(|| truthy(v)));
    let Some(jump) = t.get("jump_host").filter(|v| enabled && truthy(v)) else {
        return Ok(PinOutcome::NoTunnel);
    };
    if !t.text("known_hosts").is_empty() {
        return Ok(PinOutcome::OperatorManaged);
    }
    let jump = safe_host(&text(jump), "tunnel.jump_host")?;
    // The part after `user@` is what the ssh tools receive; it is vetted on
    // its own, because `u@-oOption` passes a check of the whole spec.
    let host = safe_host(host_of(&jump), "tunnel.jump_host host")?;
    if known_hosts.exists() && pinned(runner, known_hosts, &host) {
        return Ok(PinOutcome::AlreadyPinned);
    }
    let keys = scan(runner, &host);
    if keys.is_empty() {
        return Ok(PinOutcome::Unreachable { host });
    }
    append_atomic(known_hosts, &keys)
        .map_err(|e| SysError::io(format!("cannot update {}", known_hosts.display()), e))?;
    Ok(PinOutcome::Pinned { host, keys: keys.len() })
}

fn log(msg: &str) {
    println!("[pin-jump-host] {msg}");
}

/// The `pin-jump-host` entry point. Privileges are dropped *before* `load`
/// runs, so the config is read and parsed as the key directory's owner, never
/// as root. Always returns 0: it must never stop the tunnel from starting.
pub fn pin_jump_host_main<E: std::fmt::Display>(
    known_hosts: &Path,
    load: impl FnOnce() -> std::result::Result<Config, E>,
) -> i32 {
    let run = || -> Result<PinOutcome> {
        let dir = known_hosts.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        drop_privileges(dir).map_err(|e| SysError::io(format!("cannot become the owner of {}", dir.display()), e))?;
        let conf = load().map_err(|e| SysError::Invalid(e.to_string()))?;
        pin_jump_host(&conf, known_hosts, &SystemRunner)
    };
    match run() {
        Ok(PinOutcome::Unreachable { host }) => {
            log(&format!("could not reach {host} to read its key; will retry on the next start"));
        }
        Ok(PinOutcome::Pinned { host, keys }) => {
            log(&format!("pinned {keys} key(s) for {host} in {}", known_hosts.display()));
        }
        Ok(_) => {}
        Err(e) => log(&format!("skipped: {e}")),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::fake::{FakeRunner, exit};
    use crate::testutil::{TempDir, config, tunnel_panel};
    use serde_json::json;
    use soc_core::DisplayCfg;
    use std::os::unix::fs::PermissionsExt;

    const ED: &str =
        "jump.example.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake";
    const RSA: &str = "jump.example.net ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfakefakefakefake+/==";

    fn wall(tunnel: serde_json::Value) -> Config {
        let d = DisplayCfg::default();
        config(d.clone(), vec![tunnel_panel(&d, "p1", (0, 0), 19101, "10.0.0.5", 8443)], tunnel)
    }

    fn jump() -> Config {
        wall(json!({"enabled": true, "jump_host": "tunneluser@jump.example.net"}))
    }

    /// keygen says "not pinned"; keyscan prints `scan_out`.
    fn runner(scan_out: &'static str) -> FakeRunner<impl Fn(&[String]) -> io::Result<crate::run::Output>> {
        FakeRunner::new(move |a| if a[0] == "ssh-keygen" { exit(1, "") } else { exit(0, scan_out) })
    }

    #[test]
    fn host_part_of_a_jump_spec() {
        assert_eq!(host_of("user@jump"), "jump");
        assert_eq!(host_of("jump"), "jump");
        assert_eq!(host_of("a@b@jump"), "jump");
    }

    #[test]
    fn first_start_pins_the_scanned_keys() {
        let t = TempDir::new("pin-first");
        let kh = t.path().join("known_hosts");
        let r = runner(
            "# jump.example.net:22 SSH-2.0-OpenSSH_9.6\njump.example.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake\n\njump.example.net ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfakefakefakefake+/==\n",
        );
        let outcome = pin_jump_host(&jump(), &kh, &r).unwrap();
        assert_eq!(outcome, PinOutcome::Pinned { host: "jump.example.net".into(), keys: 2 });
        assert_eq!(std::fs::read_to_string(&kh).unwrap(), format!("{ED}\n{RSA}\n"));
        assert_eq!(std::fs::metadata(&kh).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(t.names(), ["known_hosts"]);
        // keygen was not consulted (no file yet); keyscan got the bare host after `--`
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], ["ssh-keyscan", "-T", "10", "-t", "ed25519,ecdsa,rsa", "--", "jump.example.net"]);
    }

    #[test]
    fn an_already_pinned_host_is_left_alone() {
        let t = TempDir::new("pin-already");
        let kh = t.write("known_hosts", "existing\n");
        let r = FakeRunner::new(|_| exit(0, ""));
        assert_eq!(pin_jump_host(&jump(), &kh, &r).unwrap(), PinOutcome::AlreadyPinned);
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][..4], ["ssh-keygen", "-F", "jump.example.net", "-f"]);
        assert_eq!(std::fs::read_to_string(&kh).unwrap(), "existing\n");
    }

    #[test]
    fn keys_are_appended_to_an_existing_file_on_their_own_lines() {
        let t = TempDir::new("pin-append");
        let kh = t.write("known_hosts", "other.host ssh-ed25519 AAAAexistingkeywithoutnewline");
        pin_jump_host(
            &jump(),
            &kh,
            &runner(
                "jump.example.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake\n",
            ),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&kh).unwrap(),
            format!("other.host ssh-ed25519 AAAAexistingkeywithoutnewline\n{ED}\n")
        );
    }

    #[test]
    fn an_unreachable_host_writes_nothing() {
        let t = TempDir::new("pin-unreachable");
        let kh = t.path().join("known_hosts");
        let outcome = pin_jump_host(&jump(), &kh, &runner("")).unwrap();
        assert_eq!(outcome, PinOutcome::Unreachable { host: "jump.example.net".into() });
        assert!(!kh.exists());
        let failing = FakeRunner::new(|_| Err(io::Error::other("no ssh-keyscan")));
        assert!(matches!(pin_jump_host(&jump(), &kh, &failing).unwrap(), PinOutcome::Unreachable { .. }));
    }

    #[test]
    fn nothing_to_do_without_a_tunnel_or_with_an_operator_managed_file() {
        let t = TempDir::new("pin-noop");
        let kh = t.path().join("known_hosts");
        let never = FakeRunner::new(|_| exit(0, "should not run"));
        for section in [json!({"enabled": false, "jump_host": "u@j"}), json!({"enabled": true}), json!({})] {
            assert_eq!(pin_jump_host(&wall(section), &kh, &never).unwrap(), PinOutcome::NoTunnel);
        }
        let managed = wall(json!({"jump_host": "u@j", "known_hosts": "/etc/soc-display/keys/known_hosts"}));
        assert_eq!(pin_jump_host(&managed, &kh, &never).unwrap(), PinOutcome::OperatorManaged);
        assert!(never.calls.borrow().is_empty());
    }

    #[test]
    fn a_host_that_looks_like_an_option_is_refused() {
        let t = TempDir::new("pin-inject");
        let kh = t.path().join("known_hosts");
        let never = FakeRunner::new(|_| exit(0, ""));
        for bad in ["u@-oProxyCommand=evil", "u@-f/etc/shadow", "-x", "u@", "u@a b"] {
            assert!(pin_jump_host(&wall(json!({"jump_host": bad})), &kh, &never).is_err(), "{bad:?}");
        }
        assert!(never.calls.borrow().is_empty());
    }

    #[test]
    fn only_plain_keys_for_the_scanned_host_are_accepted() {
        assert!(valid_key_line(ED, "jump.example.net"));
        assert!(valid_key_line(RSA, "jump.example.net"));
        for bad in [
            "# jump.example.net:22 SSH-2.0-OpenSSH_9.6",
            "",
            "@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake",
            "* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFake",
            "other.host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFake",
            "jump.example.net ssh-dss AAAAB3NzaC1kc3MAAACBAFakeFakeFake",
            "jump.example.net ssh-ed25519 not*base64*at*all!!!",
            "jump.example.net ssh-ed25519 short",
            "jump.example.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake extra-field",
        ] {
            assert!(!valid_key_line(bad, "jump.example.net"), "{bad:?}");
        }
        let hostile = "@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFake\n";
        assert!(scan(&runner(hostile), "jump.example.net").is_empty());
    }

    #[test]
    fn dropping_privileges_is_a_no_op_for_an_unprivileged_caller() {
        if fsutil::euid() != 0 {
            let t = TempDir::new("pin-privs");
            assert!(drop_privileges(t.path()).is_ok());
            assert!(drop_privileges(Path::new("/nonexistent/keys")).is_ok());
        }
    }

    #[test]
    fn main_never_fails_the_service() {
        let t = TempDir::new("pin-main");
        let kh = t.path().join("keys/known_hosts");
        std::fs::create_dir(t.path().join("keys")).unwrap();
        assert_eq!(pin_jump_host_main(&kh, || Err::<Config, _>("panels.yaml is not valid YAML")), 0);
        assert_eq!(pin_jump_host_main(&kh, || Ok::<_, String>(wall(json!({"enabled": false})))), 0);
        assert!(!kh.exists());
    }
}
