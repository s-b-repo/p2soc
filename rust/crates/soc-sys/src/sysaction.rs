//! Privileged system actions.
//!
//! Two families, both built as explicit argv (never a shell line):
//!
//! 1. **Service control** — the wall runs as an unprivileged user and may
//!    restart/inspect exactly three units through `sudo -n`, as granted by
//!    `security/soc-wall-restart.sudoers`. Every entry there is an exact
//!    command line (in sudoers `*` also matches spaces, so a wildcard would
//!    let a compromised renderer append arbitrary arguments). The verbs and
//!    units are closed enums here, so nothing outside that allowlist can even
//!    be expressed; a test keeps this file and the sudoers rule in lock-step.
//!
//! 2. **Install / uninstall** — a button cannot silently sudo. The elevation
//!    path is resolved once: graphical polkit (`pkexec`), a terminal running
//!    `sudo`, or else a manual hint showing the operator the exact command —
//!    never a silent failure. `SOC_SYSACTION_CMD=<script>` substitutes a fake
//!    script run directly with no elevation, so the flow can be exercised
//!    without mutating the box.
//!
//! The progress *window* of the original lives in the GUI crate; this module
//! provides the non-UI half: argv construction and a line-streaming runner.

use crate::fsutil::which;
use crate::run::{Runner, argv};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const JOURNALCTL: &str = "/usr/bin/journalctl";
/// Absolute, so an elevated run can never pick up an `env` planted on the
/// caller's `PATH`.
pub const ENV_BIN: &str = "/usr/bin/env";

/// The units the wall may control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unit {
    /// The single supervisor unit for every VPN backend.
    FortiVpn,
    AutosshTunnel,
    SocTarpit,
}

impl Unit {
    pub const ALL: [Unit; 3] = [Unit::FortiVpn, Unit::AutosshTunnel, Unit::SocTarpit];

    pub const fn name(self) -> &'static str {
        match self {
            Unit::FortiVpn => "forti-vpn.service",
            Unit::AutosshTunnel => "autossh-tunnel.service",
            Unit::SocTarpit => "soc-tarpit.service",
        }
    }
}

/// The `systemctl` verbs the wall may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    Restart,
    Start,
    Stop,
    Enable,
    Disable,
    Status,
}

impl Verb {
    pub const ALL: [Verb; 6] = [Verb::Restart, Verb::Start, Verb::Stop, Verb::Enable, Verb::Disable, Verb::Status];

    pub const fn as_str(self) -> &'static str {
        match self {
            Verb::Restart => "restart",
            Verb::Start => "start",
            Verb::Stop => "stop",
            Verb::Enable => "enable",
            Verb::Disable => "disable",
            Verb::Status => "status",
        }
    }
}

fn elevated(as_root: bool, command: &[&str]) -> Vec<String> {
    let mut out = if as_root { Vec::new() } else { argv(&["sudo", "-n"]) };
    out.extend(argv(command));
    out
}

/// `systemctl <verb> <unit>`: bare when already root, else through
/// `sudo -n` (which fails instead of prompting when the rule is missing).
pub fn systemctl_argv(verb: Verb, unit: Unit, as_root: bool) -> Vec<String> {
    elevated(as_root, &[SYSTEMCTL, verb.as_str(), unit.name()])
}

/// The cheap "may we read the VPN journal?" probe. It uses the same command
/// shape as the real stream so it exercises the exact sudoers allowance;
/// `-n 0` succeeds even when the unit has never logged.
pub fn journal_probe_argv(as_root: bool) -> Vec<String> {
    elevated(as_root, &[JOURNALCTL, "-u", Unit::FortiVpn.name(), "-n", "0", "--no-pager"])
}

/// Follow the VPN unit's journal: the last 100 lines for context, then live,
/// one message per line without the timestamp/host prefix.
pub fn journal_follow_argv(as_root: bool) -> Vec<String> {
    elevated(as_root, &[JOURNALCTL, "-u", Unit::FortiVpn.name(), "-f", "--no-pager", "-n", "100", "-o", "cat"])
}

/// Whether this process can control the managed units without a password
/// prompt: it is root, or `sudo -n systemctl status forti-vpn.service` gets
/// past sudo's gate. `systemctl status` exits 0 (active), 3 (loaded but dead)
/// or 4 (no such unit) once it actually runs; sudo without a NOPASSWD rule
/// exits 1 without running it.
pub fn can_systemctl(runner: &dyn Runner, euid: u32) -> bool {
    if euid == 0 {
        return true;
    }
    runner
        .run(&systemctl_argv(Verb::Status, Unit::FortiVpn, false), Duration::from_secs(4))
        .is_ok_and(|out| matches!(out.code, Some(0 | 3 | 4)))
}

/// Whether the VPN journal can be read without a prompt.
pub fn can_read_journal(runner: &dyn Runner, euid: u32) -> bool {
    runner.run(&journal_probe_argv(euid == 0), Duration::from_secs(3)).is_ok_and(|out| out.success())
}

/// The command's output on success, a message for the operator on failure.
pub type Outcome = std::result::Result<String, String>; // audit-allow: String is the human-facing reason/display text

/// Run `systemctl <verb> <unit>` with the minimum privilege needed. `Ok`
/// carries the command's output (or `ok`); `Err` a message for the operator —
/// in particular a clean refusal when there is no NOPASSWD rule, instead of a
/// hang on a prompt nobody can answer.
pub fn privileged_systemctl(runner: &dyn Runner, euid: u32, verb: Verb, unit: Unit) -> Outcome {
    if !can_systemctl(runner, euid) {
        return Err("no NOPASSWD sudo for systemctl".to_string());
    }
    match runner.run(&systemctl_argv(verb, unit, euid == 0), Duration::from_secs(15)) {
        Err(e) => Err(format!("systemctl invocation failed: {e}")),
        Ok(out) if out.success() => {
            let text = out.stdout.trim();
            Ok(if text.is_empty() { "ok".to_string() } else { text.to_string() })
        }
        Ok(out) => Err(if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() }.to_string()),
    }
}

/// How the wall is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    /// Owns tty1 and boots straight into the wall.
    Kiosk,
    /// Runs inside an existing desktop session.
    Desktop,
}

impl InstallMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            InstallMode::Kiosk => "kiosk",
            InstallMode::Desktop => "desktop",
        }
    }

    pub fn parse(s: &str) -> Option<InstallMode> {
        match s {
            "kiosk" => Some(InstallMode::Kiosk),
            "desktop" => Some(InstallMode::Desktop),
            _ => None,
        }
    }
}

/// The account names the installer is told to use. Validated on
/// construction: they end up in a root-run script's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallUsers {
    kiosk: String,
    desktop: String,
    service: String,
}

impl Default for InstallUsers {
    fn default() -> Self {
        InstallUsers { kiosk: "soc".into(), desktop: "socwall".into(), service: "socsvc".into() }
    }
}

/// A conservative POSIX account name.
fn valid_username(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && name.len() <= 32
}

impl InstallUsers {
    /// `None` if any name is not a plain account name.
    pub fn new(kiosk: &str, desktop: &str, service: &str) -> Option<InstallUsers> {
        [kiosk, desktop, service].iter().all(|n| valid_username(n)).then(|| InstallUsers {
            kiosk: kiosk.into(),
            desktop: desktop.into(),
            service: service.into(),
        })
    }
}

/// A privileged install-time action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysAction {
    Install {
        mode: InstallMode,
        users: InstallUsers,
    },
    /// Always forced: there is no tty for its confirmation under
    /// pkexec/terminal. `purge` also removes config and data.
    Uninstall {
        purge: bool,
    },
}

impl SysAction {
    /// Install with the default account names.
    pub fn install(mode: InstallMode) -> SysAction {
        SysAction::Install { mode, users: InstallUsers::default() }
    }

    fn script(&self, root: &Path) -> PathBuf {
        root.join(match self {
            SysAction::Install { .. } => "install.sh",
            SysAction::Uninstall { .. } => "uninstall.sh",
        })
    }

    /// `KEY=VALUE` knobs handed to the script through `env` (so they survive
    /// sudo/pkexec's environment scrubbing and stay readable in the argv).
    fn env_knobs(&self) -> Vec<String> {
        match self {
            SysAction::Install { mode, users } => vec![
                format!("INSTALL_MODE={}", mode.as_str()),
                format!("KIOSK_USER={}", users.kiosk),
                format!("DESKTOP_USER={}", users.desktop),
                format!("SVC_USER={}", users.service),
            ],
            SysAction::Uninstall { .. } => Vec::new(),
        }
    }

    fn script_args(&self) -> Vec<String> {
        match self {
            SysAction::Install { .. } => Vec::new(),
            SysAction::Uninstall { purge: false } => argv(&["--force"]),
            SysAction::Uninstall { purge: true } => argv(&["--force", "--purge"]),
        }
    }
}

/// How an action will be run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// `SOC_SYSACTION_CMD`: a stand-in script, run directly with no root.
    Fake,
    /// Graphical polkit authentication.
    Pkexec,
    /// A terminal emulator running `sudo`.
    Terminal,
    /// Neither is available: show the operator [`manual_hint`] instead of
    /// executing anything.
    Manual,
}

/// A terminal emulator and the flag after which it takes a command *argv*.
/// (`-e` on gnome/xfce/mate terminals takes one shell string instead.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terminal {
    pub program: &'static str,
    pub exec_flag: &'static str,
}

/// The terminals tried, in order — the same set the launcher uses for the
/// TTY wizard, so behaviour is consistent across the app.
pub const TERMINALS: [Terminal; 6] = [
    Terminal { program: "x-terminal-emulator", exec_flag: "-e" },
    Terminal { program: "gnome-terminal", exec_flag: "--" },
    Terminal { program: "konsole", exec_flag: "-e" },
    Terminal { program: "xfce4-terminal", exec_flag: "-x" },
    Terminal { program: "mate-terminal", exec_flag: "-x" },
    Terminal { program: "xterm", exec_flag: "-e" },
];

/// `pkexec` on `path_var`, but only if it is setuid: a present-but-broken
/// pkexec must degrade to the terminal fallback, not fail at run time.
pub fn find_pkexec(path_var: &str) -> Option<PathBuf> {
    which("pkexec", path_var).filter(|p| std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o4000 != 0))
}

/// The first terminal emulator on `path_var`.
pub fn find_terminal(path_var: &str) -> Option<Terminal> {
    TERMINALS.into_iter().find(|t| which(t.program, path_var).is_some())
}

/// What is available on this machine for running a [`SysAction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysEnv {
    /// Where `install.sh` / `uninstall.sh` live.
    pub root: PathBuf,
    /// `$SOC_SYSACTION_CMD`.
    pub fake_cmd: Option<String>,
    pub pkexec: Option<PathBuf>,
    pub terminal: Option<Terminal>,
}

impl SysEnv {
    /// Probe `PATH` and the environment.
    pub fn detect(root: &Path) -> SysEnv {
        let path_var = std::env::var("PATH").unwrap_or_default(); // audit-allow: default is the intended fallback (empty PATH finds nothing)
        SysEnv {
            root: root.to_path_buf(),
            fake_cmd: std::env::var("SOC_SYSACTION_CMD").ok().filter(|v| !v.is_empty()),
            pkexec: find_pkexec(&path_var),
            terminal: find_terminal(&path_var),
        }
    }
}

/// Resolve the elevation path once and build the argv for `action`.
pub fn build_argv(action: &SysAction, env: &SysEnv) -> (Vec<String>, Elevation) {
    let knobs = action.env_knobs();
    let run_via_env = |program: String| {
        // `env` would read a leading '-' as one of its own options.
        let program = if program.starts_with('-') { format!("./{program}") } else { program };
        let mut out = Vec::new();
        if !knobs.is_empty() {
            out.push(ENV_BIN.to_string());
            out.extend(knobs.iter().cloned());
        }
        out.push(program);
        out.extend(action.script_args());
        out
    };

    if let Some(fake) = &env.fake_cmd {
        return (run_via_env(fake.clone()), Elevation::Fake);
    }
    let script = action.script(&env.root).to_string_lossy().into_owned();
    // Under elevation the knobs always go through an explicit `env`, even
    // when there are none, so the shape of the command is uniform.
    let mut elevated_tail = vec![ENV_BIN.to_string()];
    elevated_tail.extend(knobs.iter().cloned());
    elevated_tail.push(script.clone());
    elevated_tail.extend(action.script_args());

    if let Some(pkexec) = &env.pkexec {
        let mut out = vec![pkexec.to_string_lossy().into_owned()];
        out.extend(elevated_tail);
        return (out, Elevation::Pkexec);
    }
    if let Some(term) = env.terminal {
        let mut out = argv(&[term.program, term.exec_flag, "sudo"]);
        out.extend(elevated_tail);
        return (out, Elevation::Terminal);
    }
    (run_via_env(script), Elevation::Manual)
}

/// Quote `s` for a POSIX shell unless it is plainly safe.
fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+=:@%".contains(&b));
    if plain { s.to_string() } else { format!("'{}'", s.replace('\'', "'\\''")) }
}

/// The exact shell line for the manual fallback (no pkexec, no terminal).
/// It is shown to a human to paste, so the script path is shell-quoted.
pub fn manual_hint(action: &SysAction, root: &Path) -> String {
    let script = shell_quote(&action.script(root).to_string_lossy());
    match action {
        SysAction::Install { mode, .. } => format!("sudo INSTALL_MODE={} {script}", mode.as_str()),
        SysAction::Uninstall { .. } => format!("sudo {script} {}", action.script_args().join(" ")),
    }
}

/// Remove ANSI CSI sequences (`ESC [ params letter`) — the install scripts
/// colour their output, and a log view should read clean.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("\x1b[") {
        let (Some(before), Some(after)) = (rest.get(..start), rest.get(start + 2..)) else {
            break;
        };
        out.push_str(before);
        let params = after.bytes().take_while(|b| b.is_ascii_digit() || *b == b';').count();
        match after.as_bytes().get(params) {
            Some(b) if b.is_ascii_alphabetic() => rest = after.get(params + 1..).unwrap_or(""),
            _ => {
                // Not a complete sequence: keep the bytes as they are.
                out.push_str("\x1b[");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// A line longer than this is delivered in pieces rather than buffered whole.
const MAX_LINE: usize = 8 * 1024;

fn pump_lines(mut pipe: impl Read, tx: &mpsc::Sender<String>) {
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let emit = |bytes: &[u8]| tx.send(strip_ansi(&String::from_utf8_lossy(bytes))).is_ok();
    loop {
        let n = match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break, // audit-allow: a failed pipe read ends the stream like EOF
            Ok(n) => n,
        };
        let Some(got) = chunk.get(..n) else {
            break;
        };
        pending.extend_from_slice(got);
        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            if !emit(line.strip_suffix(b"\n").unwrap_or(&line)) {
                return;
            }
        }
        if pending.len() >= MAX_LINE {
            if !emit(&pending) {
                return;
            }
            pending.clear();
        }
    }
    if !pending.is_empty() {
        let _ = emit(&pending); // audit-allow: best-effort, the receiver may have gone
    }
}

/// Run `argv`, handing each line of its combined stdout/stderr (colour codes
/// stripped, newline removed) to `on_line` as it is produced. Returns the
/// exit status, or `-1` if the command could not be launched or was killed by
/// a signal — a failure to spawn is reported through `on_line`, never a hang.
///
/// The child gets its own process group, so a terminal Ctrl-C aimed at the
/// wall does not also interrupt a half-finished install.
pub fn run_streamed(argv: &[String], mut on_line: impl FnMut(&str)) -> i32 {
    let Some((program, args)) = argv.split_first() else {
        on_line("could not launch: empty command");
        return -1;
    };
    let spawned = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            on_line(&format!("could not launch: {e}"));
            return -1;
        }
    };
    let (tx, rx) = mpsc::channel();
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        let tx = tx.clone();
        readers.push(thread::spawn(move || pump_lines(out, &tx)));
    }
    if let Some(err) = child.stderr.take() {
        let tx = tx.clone();
        readers.push(thread::spawn(move || pump_lines(err, &tx)));
    }
    drop(tx);
    for line in rx {
        on_line(&line);
    }
    for reader in readers {
        let _ = reader.join(); // audit-allow: best-effort, a panicked reader only loses its output
    }
    child.wait().ok().and_then(|status| status.code()).unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Output;
    use crate::run::fake::{FakeRunner, exit};
    use crate::testutil::TempDir;
    use std::collections::BTreeSet;
    use std::io;

    /// The command lines granted by the sudoers rule, whitespace-normalised.
    fn sudoers_commands() -> BTreeSet<String> {
        let text = include_str!("../../../../security/soc-wall-restart.sudoers");
        let rule: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .map(|l| l.trim_end().trim_end_matches('\\'))
            .collect::<Vec<_>>()
            .join(" ");
        let (_, commands) = rule.split_once("NOPASSWD:").expect("a NOPASSWD rule");
        commands.split(',').map(|c| c.split_whitespace().collect::<Vec<_>>().join(" ")).collect()
    }

    #[test]
    fn every_command_is_in_the_sudoers_allowlist_and_vice_versa() {
        let mut ours = BTreeSet::new();
        for verb in Verb::ALL {
            for unit in Unit::ALL {
                let cmd = systemctl_argv(verb, unit, false);
                assert_eq!(cmd[..2], ["sudo", "-n"]);
                ours.insert(cmd[2..].join(" "));
            }
        }
        ours.insert(journal_probe_argv(false)[2..].join(" "));
        ours.insert(journal_follow_argv(false)[2..].join(" "));
        assert_eq!(ours, sudoers_commands());
        assert_eq!(ours.len(), 20);
    }

    #[test]
    fn exact_command_lines() {
        assert_eq!(
            systemctl_argv(Verb::Restart, Unit::FortiVpn, false),
            ["sudo", "-n", "/usr/bin/systemctl", "restart", "forti-vpn.service"]
        );
        assert_eq!(
            systemctl_argv(Verb::Restart, Unit::AutosshTunnel, true),
            ["/usr/bin/systemctl", "restart", "autossh-tunnel.service"]
        );
        assert_eq!(
            journal_probe_argv(false),
            ["sudo", "-n", "/usr/bin/journalctl", "-u", "forti-vpn.service", "-n", "0", "--no-pager"]
        );
        assert_eq!(
            journal_follow_argv(true),
            ["/usr/bin/journalctl", "-u", "forti-vpn.service", "-f", "--no-pager", "-n", "100", "-o", "cat"]
        );
    }

    #[test]
    fn sudo_gate_accepts_only_the_status_codes_that_prove_systemctl_ran() {
        for (code, expected) in [(0, true), (3, true), (4, true), (1, false), (2, false)] {
            let runner = FakeRunner::new(move |_| exit(code, ""));
            assert_eq!(can_systemctl(&runner, 1000), expected, "exit {code}");
            assert_eq!(runner.calls.borrow()[0], ["sudo", "-n", "/usr/bin/systemctl", "status", "forti-vpn.service"]);
        }
        let broken = FakeRunner::new(|_| Err(io::Error::other("no sudo")));
        assert!(!can_systemctl(&broken, 1000));
        let killed = FakeRunner::new(|_| Ok(Output::default()));
        assert!(!can_systemctl(&killed, 1000), "a signal death is not a pass");
        // root never probes
        let never = FakeRunner::new(|_| exit(1, ""));
        assert!(can_systemctl(&never, 0));
        assert!(never.calls.borrow().is_empty());
    }

    #[test]
    fn privileged_systemctl_refuses_cleanly_without_a_rule() {
        let runner = FakeRunner::new(|_| exit(1, ""));
        assert_eq!(
            privileged_systemctl(&runner, 1000, Verb::Restart, Unit::FortiVpn),
            Err("no NOPASSWD sudo for systemctl".into())
        );
        assert_eq!(runner.calls.borrow().len(), 1, "the restart itself was never attempted");
    }

    #[test]
    fn privileged_systemctl_reports_output_and_failures() {
        let ok = FakeRunner::new(|a| if a.contains(&"status".to_string()) { exit(3, "") } else { exit(0, "") });
        assert_eq!(privileged_systemctl(&ok, 1000, Verb::Restart, Unit::AutosshTunnel), Ok("ok".into()));
        assert_eq!(ok.calls.borrow()[1], ["sudo", "-n", "/usr/bin/systemctl", "restart", "autossh-tunnel.service"]);

        let as_root = FakeRunner::new(|_| exit(0, " done \n"));
        assert_eq!(privileged_systemctl(&as_root, 0, Verb::Stop, Unit::SocTarpit), Ok("done".into()));
        assert_eq!(as_root.calls.borrow()[0], ["/usr/bin/systemctl", "stop", "soc-tarpit.service"]);

        let failing =
            FakeRunner::new(|_| Ok(Output { code: Some(5), stdout: "out".into(), stderr: "Unit not found.\n".into() }));
        assert_eq!(privileged_systemctl(&failing, 0, Verb::Start, Unit::FortiVpn), Err("Unit not found.".into()));
        let hung = FakeRunner::new(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")));
        assert!(privileged_systemctl(&hung, 0, Verb::Start, Unit::FortiVpn).unwrap_err().contains("invocation failed"));
    }

    #[test]
    fn journal_gate() {
        assert!(can_read_journal(&FakeRunner::new(|_| exit(0, "")), 1000));
        assert!(!can_read_journal(&FakeRunner::new(|_| exit(1, "")), 1000));
    }

    fn env(pkexec: bool, terminal: Option<Terminal>, fake: Option<&str>) -> SysEnv {
        SysEnv {
            root: PathBuf::from("/opt/soc-display"),
            fake_cmd: fake.map(str::to_string),
            pkexec: pkexec.then(|| PathBuf::from("/usr/bin/pkexec")),
            terminal,
        }
    }

    const KNOBS: [&str; 4] = ["INSTALL_MODE=kiosk", "KIOSK_USER=soc", "DESKTOP_USER=socwall", "SVC_USER=socsvc"];

    #[test]
    fn install_through_pkexec_threads_the_mode_via_env() {
        let (cmd, how) = build_argv(&SysAction::install(InstallMode::Kiosk), &env(true, Some(TERMINALS[5]), None));
        assert_eq!(how, Elevation::Pkexec);
        let mut want = vec!["/usr/bin/pkexec", "/usr/bin/env"];
        want.extend(KNOBS);
        want.push("/opt/soc-display/install.sh");
        assert_eq!(cmd, want);
    }

    #[test]
    fn uninstall_is_always_forced_and_purges_only_on_request() {
        let e = env(true, None, None);
        let (cmd, _) = build_argv(&SysAction::Uninstall { purge: false }, &e);
        assert_eq!(cmd, ["/usr/bin/pkexec", "/usr/bin/env", "/opt/soc-display/uninstall.sh", "--force"]);
        let (cmd, _) = build_argv(&SysAction::Uninstall { purge: true }, &e);
        assert_eq!(cmd[2..], ["/opt/soc-display/uninstall.sh", "--force", "--purge"]);
    }

    #[test]
    fn terminal_fallback_uses_each_emulators_argv_flag() {
        for term in TERMINALS {
            let (cmd, how) = build_argv(&SysAction::Uninstall { purge: false }, &env(false, Some(term), None));
            assert_eq!(how, Elevation::Terminal);
            assert_eq!(cmd[..4], [term.program, term.exec_flag, "sudo", "/usr/bin/env"]);
            assert_eq!(cmd[4..], ["/opt/soc-display/uninstall.sh", "--force"]);
        }
        // these three take a single shell string after -e, so -e must not be used
        for program in ["gnome-terminal", "xfce4-terminal", "mate-terminal"] {
            let term = TERMINALS.iter().find(|t| t.program == program).unwrap();
            assert_ne!(term.exec_flag, "-e", "{program}");
        }
    }

    #[test]
    fn manual_when_nothing_can_elevate() {
        let e = env(false, None, None);
        let (cmd, how) = build_argv(&SysAction::install(InstallMode::Desktop), &e);
        assert_eq!(how, Elevation::Manual);
        assert_eq!(cmd[0], "/usr/bin/env");
        assert_eq!(cmd[1], "INSTALL_MODE=desktop");
        assert_eq!(cmd.last().unwrap(), "/opt/soc-display/install.sh");
        let (cmd, how) = build_argv(&SysAction::Uninstall { purge: true }, &e);
        assert_eq!((cmd, how), (argv(&["/opt/soc-display/uninstall.sh", "--force", "--purge"]), Elevation::Manual));
    }

    #[test]
    fn fake_script_takes_precedence_and_keeps_the_same_shape() {
        let e = env(true, Some(TERMINALS[0]), Some("/bin/true"));
        let (cmd, how) = build_argv(&SysAction::install(InstallMode::Kiosk), &e);
        assert_eq!(how, Elevation::Fake);
        let mut want = vec!["/usr/bin/env"];
        want.extend(KNOBS);
        want.push("/bin/true");
        assert_eq!(cmd, want);
        let (cmd, how) = build_argv(&SysAction::Uninstall { purge: true }, &e);
        assert_eq!((cmd, how), (argv(&["/bin/true", "--force", "--purge"]), Elevation::Fake));
        // a fake that looks like an option is not handed to env as one
        let dashed = env(false, None, Some("-S evil"));
        let (cmd, _) = build_argv(&SysAction::install(InstallMode::Kiosk), &dashed);
        assert_eq!(cmd.last().unwrap(), "./-S evil");
    }

    #[test]
    fn account_names_are_validated() {
        assert!(InstallUsers::new("soc", "socwall", "soc_svc-2").is_some());
        for bad in ["", "Root", "a b", "x;id", "-u", "u=1", "näme", &"a".repeat(33)] {
            assert!(InstallUsers::new(bad, "socwall", "socsvc").is_none(), "{bad:?}");
        }
        assert_eq!(InstallMode::parse("kiosk"), Some(InstallMode::Kiosk));
        assert_eq!(InstallMode::parse("kiosk; reboot"), None);
    }

    #[test]
    fn manual_hint_is_a_pasteable_shell_line() {
        let root = Path::new("/opt/soc-display");
        assert_eq!(
            manual_hint(&SysAction::install(InstallMode::Kiosk), root),
            "sudo INSTALL_MODE=kiosk /opt/soc-display/install.sh"
        );
        assert_eq!(
            manual_hint(&SysAction::Uninstall { purge: true }, root),
            "sudo /opt/soc-display/uninstall.sh --force --purge"
        );
        assert_eq!(
            manual_hint(&SysAction::Uninstall { purge: false }, Path::new("/home/it's me/soc wall")),
            "sudo '/home/it'\\''s me/soc wall/uninstall.sh' --force"
        );
    }

    #[test]
    fn pkexec_must_be_setuid() {
        let t = TempDir::new("sysaction-pkexec");
        let path_var = t.path().display().to_string();
        assert_eq!(find_pkexec(&path_var), None);
        let bin = t.write("pkexec", "#!/bin/sh\n");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_pkexec(&path_var), None, "present but not setuid");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o4755)).unwrap();
        assert_eq!(find_pkexec(&path_var), Some(bin));
        assert_eq!(find_terminal(&path_var), None);
        let xterm = t.write("xterm", "#!/bin/sh\n");
        std::fs::set_permissions(&xterm, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find_terminal(&path_var).map(|t| t.program), Some("xterm"));
    }

    #[test]
    fn ansi_sequences_are_stripped() {
        assert_eq!(strip_ansi("\x1b[36m==>\x1b[0m done \x1b[1;33m!!\x1b[m"), "==> done !!");
        assert_eq!(strip_ansi("plain"), "plain");
        assert_eq!(strip_ansi("cut \x1b["), "cut \x1b[");
        assert_eq!(strip_ansi("odd \x1b[12;"), "odd \x1b[12;");
        assert_eq!(strip_ansi("é\x1b[2Kü"), "éü");
    }

    #[test]
    fn streams_both_outputs_and_returns_the_exit_status() {
        let t = TempDir::new("sysaction-stream");
        let script = t.write(
            "fake.sh",
            "#!/bin/sh\necho \"args=$*\"\nprintf '\\033[36mstep\\033[0m 1\\n'\necho oops >&2\nprintf 'no newline'\nexit 7\n",
        );
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut lines = Vec::new();
        let rc = run_streamed(&[script.display().to_string(), "--force".into()], |l| lines.push(l.to_string()));
        assert_eq!(rc, 7);
        lines.sort();
        assert_eq!(lines, ["args=--force", "no newline", "oops", "step 1"]);
    }

    #[test]
    fn a_command_that_cannot_start_is_reported_not_hung() {
        let mut lines = Vec::new();
        assert_eq!(run_streamed(&argv(&["/nonexistent/install.sh"]), |l| lines.push(l.to_string())), -1);
        assert!(lines[0].starts_with("could not launch:"), "{lines:?}");
        assert_eq!(run_streamed(&[], |_| {}), -1);
    }

    #[test]
    fn overlong_lines_are_delivered_in_bounded_pieces() {
        let (tx, rx) = mpsc::channel();
        let data = vec![b'x'; MAX_LINE * 2 + 10];
        pump_lines(&data[..], &tx);
        drop(tx);
        let pieces: Vec<String> = rx.iter().collect();
        assert!(pieces.len() >= 2 && pieces.iter().all(|p| p.len() <= MAX_LINE + 4096), "{}", pieces.len());
        assert_eq!(pieces.iter().map(String::len).sum::<usize>(), data.len());
    }
}
