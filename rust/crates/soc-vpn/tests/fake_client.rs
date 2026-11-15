//! End to end: the real supervisor, real processes, a real notify socket —
//! against a fake `openfortivpn` that prints the genuine log lines.
//!
//! The fake client is a shell script. Like the real one it runs the pinentry
//! helper named by `--pinentry=` (the crate's own `soc-vpn-pinentry` binary)
//! over the Assuan protocol to obtain the password, so the whole secret path
//! is exercised: vault → supervisor → child environment → pinentry → client.

use serde_json::json;
use soc_core::creds::StaticCreds;
use soc_vpn::{
    Deps, Log, NetProber, Paths, Programs, Role, SdNotifier, Supervisor, SystemClock, SystemSpawner, Tunables,
    VaultAccess,
};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PASSWORD: &str = "s3cr3t%pw with space";
/// The password as the Assuan `D` line carries it.
const PASSWORD_ESCAPED: &str = "s3cr3t%25pw with space";

/// Attempt 1 connects and then drops; attempt 2 is rejected; attempt 3
/// connects and stays up until it is told to stop.
const FAKE_OPENFORTIVPN: &str = r#"#!/bin/sh
dir=$(dirname "$0")
n=$(( $(cat "$dir/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$dir/count"
printf '%s\n' "$@" > "$dir/argv.$n"
echo "$$" > "$dir/pid.$n"
env > "$dir/env.$n"
pinentry=
for arg in "$@"; do
  case "$arg" in --pinentry=*) pinentry=${arg#--pinentry=} ;; esac
done
pin=$(printf 'SETTITLE VPN Password\nSETDESC VPN Requires a Password\nSETKEYINFO alice_staff_gw.example_password\nSETPROMPT VPN account password: \nGETPIN\nBYE\n' | "$pinentry" | sed -n 's/^D //p')
printf '%s' "$pin" > "$dir/pin.$n"
echo "INFO:   Connecting to gateway..."
case "$n" in
  1)
    echo "INFO:   Connected to gateway."
    echo "INFO:   Authenticated."
    echo "INFO:   Remote gateway has allocated a VPN."
    echo "INFO:   Interface ppp0 is UP."
    echo "INFO:   Tunnel is up and running."
    sleep 0.3
    echo "INFO:   Closed connection to gateway."
    exit 1 ;;
  2)
    echo "ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc."
    exit 1 ;;
  *)
    echo "INFO:   Connected to gateway."
    echo "INFO:   Tunnel is up and running."
    # A helper in the same process group, like pppd's children.
    sleep 300 &
    echo "$!" > "$dir/helper.$n"
    trap 'echo "INFO:   Closed connection to gateway."; exit 0' TERM
    wait ;;
esac
"#;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let path = std::env::temp_dir().join(format!("soc-vpn-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Whether `pid` is a running process (a zombie has already exited).
fn alive(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
        .ok()
        .and_then(|s| s.rsplit_once(')').map(|(_, rest)| !rest.trim_start().starts_with('Z')))
        .unwrap_or(false)
}

fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let give_up = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < give_up, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn supervises_a_fake_openfortivpn_end_to_end() {
    let tmp = TempDir::new();
    let dir = tmp.0.clone();
    let client = dir.join("openfortivpn");
    std::fs::write(&client, FAKE_OPENFORTIVPN).unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();

    // systemd's side of the notify protocol.
    let notify_path = dir.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    notify.set_nonblocking(true).unwrap();
    let received = Arc::new(Mutex::new(Vec::<String>::new()));
    let drain = {
        let received = received.clone();
        move || {
            let mut buf = [0u8; 1024];
            while let Ok(n) = notify.recv(&mut buf) {
                received.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
            received.lock().unwrap().clone()
        }
    };

    let mut vault = StaticCreds::default();
    vault.logins.insert("SOC VPN".into(), ("alice".into(), PASSWORD.into()));
    let logs = Arc::new(Mutex::new(Vec::<String>::new()));
    let log: Log = {
        let logs = logs.clone();
        Arc::new(move |msg: &str| logs.lock().unwrap().push(msg.to_string()))
    };
    let deps = Deps {
        vault: VaultAccess::new(Arc::new(vault)),
        spawner: Arc::new(SystemSpawner),
        prober: Arc::new(NetProber),
        clock: Arc::new(SystemClock::new()),
        notifier: Arc::new(SdNotifier::new(Some(notify_path.display().to_string()))),
        log,
    };
    // Real time, so the policy's delays are shrunk. The short watchdog
    // interval makes the standalone supervisor heartbeat during the test.
    let tunables = Tunables {
        backoff_initial: 0.2,
        backoff_max: 1.0,
        auth_delay: 1.0,
        cert_delay: 1.0,
        poll: 0.05,
        term_grace: 5.0,
        watchdog_interval: 0.2,
        ..Tunables::default()
    };
    let paths = Paths {
        pinentry: PathBuf::from(env!("CARGO_BIN_EXE_soc-vpn-pinentry")),
        root: dir.clone(),
        home: None,
        runtime_base: dir.clone(),
        programs: Programs { openfortivpn: client.display().to_string(), ..Programs::default() },
        inode_native: None,
    };
    let vpn = json!({"enabled": true, "type": "fortinet", "gateway": "gw.example", "port": 10443,
                     "realm": "staff", "vault_item": "SOC VPN", "set_routes": false});
    let mut supervisor = Supervisor::new(vpn.as_object().unwrap().clone(), Role::standalone(), deps, tunables, paths);
    let handle = supervisor.handle();
    let started = Instant::now();
    let runner = std::thread::spawn(move || supervisor.run());

    // Third attempt is up: its helper is running.
    wait_until("the third attempt's helper", || !read(&dir.join("helper.3")).trim().is_empty());
    wait_until("the third 'tunnel is up' status", || {
        drain().iter().filter(|m| *m == "STATUS=connected: tunnel is up").count() == 2
    });
    let (client_pid, helper_pid) = (read(&dir.join("pid.3")), read(&dir.join("helper.3")));
    assert!(alive(&client_pid) && alive(&helper_pid));

    handle.stop();
    assert_eq!(runner.join().unwrap(), 0);

    // --- nothing left running ---------------------------------------------------
    wait_until("the client and its helper to be gone", || !alive(&client_pid) && !alive(&helper_pid));
    for n in 1..=3 {
        assert!(
            !Path::new(&format!("/proc/{}", read(&dir.join(format!("pid.{n}"))).trim())).exists(),
            "attempt {n} left a zombie"
        );
    }
    assert_eq!(read(&dir.join("count")).trim(), "3");

    // --- the secret path --------------------------------------------------------
    for n in 1..=3 {
        let argv = read(&dir.join(format!("argv.{n}")));
        assert!(
            argv.starts_with("gw.example:10443\n--realm=staff\n--set-routes=0\n-u\nalice\n--pinentry="),
            "attempt {n}: {argv}"
        );
        assert!(!argv.contains("s3cr3t"), "the password reached argv");
        assert_eq!(read(&dir.join(format!("pin.{n}"))), PASSWORD_ESCAPED, "attempt {n} got the wrong password");
        let env = read(&dir.join(format!("env.{n}")));
        assert!(env.contains(&format!("SOC_VPN_PASSWORD={PASSWORD}\n")));
        assert!(!env.contains("NOTIFY_SOCKET=") && !env.contains("SOC_VAULT_PASSWORD="));
    }
    let logs = logs.lock().unwrap().clone();
    assert!(!logs.join("\n").contains("s3cr3t"), "the password reached the journal");

    // --- the journal ------------------------------------------------------------
    let has = |line: &str| logs.iter().any(|m| m == line);
    assert!(has("connecting to gw.example as 'alice' (attempt 1)"));
    assert!(has("[openfortivpn] INFO:   Tunnel is up and running."));
    assert!(has("tunnel established"));
    assert!(has("connection closed; reconnecting in 0s"));
    assert!(has("AUTHENTICATION FAILED (fortinet, exit 1)."));
    assert!(has("  NOT retrying for 1s — rapid retries with a bad password can LOCK the account"));
    assert!(has("connecting to gw.example as 'alice' (attempt 3)"));
    assert!(has("[openfortivpn] INFO:   Closed connection to gateway."), "the client's SIGTERM handler did not run");
    assert_eq!(logs.last().unwrap(), "stopped");
    assert!(!logs.iter().any(|m| m.contains("did not exit within")), "the client had to be killed");

    // --- what systemd saw -------------------------------------------------------
    let sent = drain();
    let statuses: Vec<&str> = sent.iter().filter_map(|m| m.strip_prefix("STATUS=")).collect();
    assert_eq!(
        statuses,
        [
            "connecting to gw.example (attempt 1)",
            "connecting to gateway",
            "connected: tunnel is up",
            "disconnected; reconnecting in 0s",
            "connecting to gw.example (attempt 2)",
            "connecting to gateway",
            "authentication failed; fix the vault credentials (long backoff)",
            "connecting to gw.example (attempt 3)",
            "connecting to gateway",
            "connected: tunnel is up",
            "stopped",
        ]
    );
    assert!(sent.iter().any(|m| m == "WATCHDOG=1"), "a standalone supervisor heartbeats");

    // The lockout hold was honoured: attempt 3 came at least auth_delay after 2.
    let modified = |name: &str| std::fs::metadata(dir.join(name)).unwrap().modified().unwrap();
    let hold = modified("argv.3").duration_since(modified("argv.2")).unwrap();
    assert!(hold >= Duration::from_millis(900), "retried {hold:?} after a rejected login");
    assert!(started.elapsed() < Duration::from_secs(20));

    // No key material or socket was left in the runtime directory.
    assert!(!dir.join("soc-vpn").exists());
}
