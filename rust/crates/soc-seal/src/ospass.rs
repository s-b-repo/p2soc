//! Verify an operator's OPERATING-SYSTEM password — separate from the wall's
//! own PIN / TOTP gates.
//!
//! Editing a stored credential hands the operator the worst possible data
//! class for a stolen PIN to leak, so it is gated by the same authentication
//! the box uses to grant root: the operator's local UNIX password.
//!
//! libpam is not linked. Two external helpers are tried in order:
//!
//! 1. `su - USER -c true` with the password on stdin. `su` is setuid root and
//!    PAM-aware, so it is the only helper that reliably works when the wall
//!    runs as one user and must verify another's password (`pam_unix` refuses
//!    cross-user checks from an unprivileged caller).
//! 2. `pamtester login USER authenticate` — works only when the caller has
//!    shadow access or IS the target user.
//!
//! `su` only proves something when it actually asks. Two cases where it does
//! not are refused rather than trusted: a root caller (`pam_rootok` lets root
//! `su` to anyone with no password, so `su` is skipped) and a target account
//! with an empty password (`su` then succeeds whatever was typed, so a random
//! wrong password is tried too, and an account that accepts it fails).
//!
//! The password travels on the helper's stdin, never argv, and is never
//! stored, logged or displayed. The username reaches the helper as its own
//! argv slot and can be typed at the glass, so anything shaped like an option
//! is rejected before a helper runs.

use crate::log;
use crate::proc;
use crate::rng;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Every attempt takes at least this long, so a fast rejection (unknown
/// user) cannot be told from a slow one (PAM said no) by timing.
const MIN_LATENCY: Duration = Duration::from_millis(300);
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const NON_LOGIN_SHELLS: [&str; 5] = ["nologin", "false", "sync", "halt", "shutdown"];
const CONVENTIONAL_USERS: [&str; 6] = ["kali", "pi", "operator", "admin", "debian", "ubuntu"];

/// A POSIX-ish account name: `[A-Za-z_][A-Za-z0-9_.-]*\$?`. Rejects a leading
/// `-`: the name is an argv slot of a setuid binary, and at the glass it is
/// free text.
pub fn valid_username(name: &str) -> bool {
    let body = name.strip_suffix('$').unwrap_or(name);
    let mut chars = body.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// One passwd(5) entry, as far as this module cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub shell: String,
}

/// The account database (a seam: tests supply a fixed one).
pub trait Accounts {
    fn by_name(&self, name: &str) -> Option<Account>;
    fn by_uid(&self, uid: u32) -> Option<Account>;
    /// Every enumerable account, in database order.
    fn all(&self) -> Vec<Account>;
}

fn parse_passwd(text: &str) -> Vec<Account> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let (name, uid) = (*fields.first()?, fields.get(2)?.parse().ok()?);
            (!name.is_empty()).then(|| Account {
                name: name.to_string(),
                uid,
                shell: fields.get(6).map_or_else(String::new, |s| (*s).to_string()),
            })
        })
        .collect()
}

/// The system's accounts via `getent passwd` (which honours NSS: LDAP,
/// systemd-homed …), falling back to `/etc/passwd` where there is no getent.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAccounts;

impl SystemAccounts {
    fn getent(key: Option<&str>) -> Option<Vec<Account>> {
        let program = proc::find_trusted("getent")?;
        let mut args = vec!["passwd"];
        args.extend(key);
        let done = proc::run(&program, &args, None, HELPER_TIMEOUT, 4 << 20).ok()?;
        done.success.then(|| parse_passwd(&String::from_utf8_lossy(&done.stdout)))
    }

    fn local() -> Vec<Account> {
        std::fs::read_to_string("/etc/passwd").map_or_else(|_| Vec::new(), |text| parse_passwd(&text)) // audit-allow: unreadable /etc/passwd means no local accounts
    }

    fn lookup(key: &str, matches: impl Fn(&Account) -> bool) -> Option<Account> {
        Self::local()
            .into_iter()
            .find(&matches)
            .or_else(|| Self::getent(Some(key)).and_then(|found| found.into_iter().find(&matches)))
    }
}

impl Accounts for SystemAccounts {
    fn by_name(&self, name: &str) -> Option<Account> {
        // Also keeps an option-shaped name out of getent's argv.
        if !valid_username(name) {
            return None;
        }
        Self::lookup(name, |a| a.name == name)
    }

    fn by_uid(&self, uid: u32) -> Option<Account> {
        Self::lookup(&uid.to_string(), |a| a.uid == uid)
    }

    fn all(&self) -> Vec<Account> {
        Self::getent(None).filter(|all| !all.is_empty()).unwrap_or_else(Self::local)
    }
}

/// What the environment says about who the operator is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperatorHints {
    /// `$SOC_OPERATOR_USER`: the operator's explicit choice.
    pub operator_user: Option<String>,
    /// `$SUDO_USER`: who launched the wall through sudo.
    pub sudo_user: Option<String>,
    /// The uid the wall itself runs as.
    pub own_uid: u32,
}

impl OperatorHints {
    pub fn from_env() -> OperatorHints {
        let var = |name: &str| std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        OperatorHints {
            operator_user: var("SOC_OPERATOR_USER"),
            sudo_user: var("SUDO_USER"),
            own_uid: rustix::process::getuid().as_raw(),
        }
    }
}

/// The OS user whose password the Edit gate should check. Never fails and
/// never returns an empty name.
pub fn operator_user() -> String {
    operator_user_from(&OperatorHints::from_env(), &SystemAccounts)
}

/// [`operator_user`] over explicit inputs. Resolution order:
///
/// 1. `SOC_OPERATOR_USER`, if that account exists (a typo falls through).
/// 2. `SUDO_USER` — but not `root`: `sudo … sudo -u soc …` leaves
///    `SUDO_USER=root` in the wall's environment, and root's password is
///    locked on most distributions.
/// 3. The first account with uid ≥ 1000 and a real login shell — the usual
///    convention for a human desktop user.
/// 4. A conventional name (`kali`, `pi`, …) that exists.
/// 5. The wall's own user, else `root`.
pub fn operator_user_from(hints: &OperatorHints, accounts: &dyn Accounts) -> String {
    if let Some(name) = hints.operator_user.as_deref().filter(|n| accounts.by_name(n).is_some()) {
        return name.to_string();
    }
    if let Some(name) = hints.sudo_user.as_deref().filter(|n| *n != "root" && accounts.by_name(n).is_some()) {
        return name.to_string();
    }
    let human = accounts.all().into_iter().find(|a| {
        let shell = a.shell.rsplit('/').next().unwrap_or("");
        a.uid >= 1000 && a.uid != 65534 && !NON_LOGIN_SHELLS.contains(&shell)
    });
    if let Some(account) = human {
        return account.name;
    }
    if let Some(guess) = CONVENTIONAL_USERS.iter().find(|g| accounts.by_name(g).is_some()) {
        return (*guess).to_string();
    }
    accounts.by_uid(hints.own_uid).map_or_else(|| "root".to_string(), |a| a.name)
}

/// Why no verdict could be reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsPassError {
    /// No helper on this host can vouch for a password: neither `su` (absent,
    /// or the caller is root, where it checks nothing) nor `pamtester`.
    /// In-process PAM is deliberately not linked.
    Unsupported,
}

impl fmt::Display for OsPassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no OS-password verifier available (need su as a non-root user, or pamtester)")
    }
}

impl std::error::Error for OsPassError {}

/// One way of asking the OS. `None` means "cannot vouch for anything here";
/// the next backend is asked.
trait Backend: Send + Sync {
    fn verify(&self, user: &str, password: &str, timeout: Duration) -> Option<bool>;
}

struct Su {
    program: PathBuf,
}

impl Su {
    /// One `su` attempt. A timeout or OS error counts as a refusal.
    fn accepts(&self, user: &str, password: &str, timeout: Duration) -> bool {
        // With no tty attached, su reads the password from stdin via PAM.
        let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        line.extend_from_slice(password.as_bytes());
        line.push(b'\n');
        proc::run(&self.program, &["-", user, "-c", "true"], Some(&line), timeout, 4096).is_ok_and(|done| done.success)
    }
}

impl Backend for Su {
    fn verify(&self, user: &str, password: &str, timeout: Duration) -> Option<bool> {
        if !self.accepts(user, password, timeout) {
            return Some(false);
        }
        // A password-less account lets su through whatever was typed, which
        // would let anyone at the glass name that account and pass this gate.
        let Ok(random) = rng::array::<24>() else { return Some(false) };
        let probe: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Some(!self.accepts(user, &probe, timeout))
    }
}

struct Pamtester {
    program: PathBuf,
}

impl Backend for Pamtester {
    fn verify(&self, user: &str, password: &str, timeout: Duration) -> Option<bool> {
        let args = ["login", user, "authenticate"];
        Some(proc::run(&self.program, &args, Some(password.as_bytes()), timeout, 4096).is_ok_and(|done| done.success))
    }
}

/// The OS-password check, with its helpers resolved.
pub struct OsPassword {
    backends: Vec<Box<dyn Backend>>,
    min_latency: Duration,
    timeout: Duration,
}

impl fmt::Debug for OsPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsPassword").field("backends", &self.backends.len()).finish_non_exhaustive()
    }
}

impl OsPassword {
    /// The helpers installed on this host. They are looked up in the system
    /// binary directories only, never `$PATH`: a look-alike `su` must not get
    /// to see the operator's password, nor to answer for the real one.
    pub fn system() -> OsPassword {
        let is_root = rustix::process::geteuid().is_root();
        OsPassword::with_helpers(
            proc::find_trusted("su").filter(|_| !is_root).as_deref(),
            proc::find_trusted("pamtester").as_deref(),
        )
    }

    /// Use these helper programs (`None` = not available).
    pub fn with_helpers(su: Option<&Path>, pamtester: Option<&Path>) -> OsPassword {
        let mut backends: Vec<Box<dyn Backend>> = Vec::new();
        if let Some(program) = su {
            backends.push(Box::new(Su { program: program.to_path_buf() }));
        }
        if let Some(program) = pamtester {
            backends.push(Box::new(Pamtester { program: program.to_path_buf() }));
        }
        OsPassword { backends, min_latency: MIN_LATENCY, timeout: HELPER_TIMEOUT }
    }

    /// Per-helper deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> OsPassword {
        self.timeout = timeout;
        self
    }

    /// `Ok(true)` iff `password` is `user`'s current OS login password;
    /// `Err(Unsupported)` if no helper could be asked at all.
    pub fn check(&self, user: &str, password: &str) -> Result<bool, OsPassError> {
        // A newline would end the line the helper reads: it would then judge
        // only the part before it. Such a string is never the password.
        if user.is_empty() || password.is_empty() || !valid_username(user) || password.contains(['\n', '\r', '\0']) {
            return Ok(false);
        }
        let started = Instant::now();
        let verdict = self.backends.iter().find_map(|b| b.verify(user, password, self.timeout));
        if let Some(rest) = self.min_latency.checked_sub(started.elapsed()) {
            std::thread::sleep(rest);
        }
        verdict.ok_or(OsPassError::Unsupported)
    }

    /// [`OsPassword::check`] as a plain yes/no for the UI: with no verifier
    /// available the answer is "rejected" (and a warning is logged).
    pub fn verify(&self, user: &str, password: &str) -> bool {
        self.check(user, password).unwrap_or_else(|e| {
            log::warn(e);
            false
        })
    }
}

/// True iff `password` is `user`'s current OS login password, using the
/// helpers installed on this host. Never fails.
pub fn verify_os_password(user: &str, password: &str) -> bool {
    OsPassword::system().verify(user, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsio::testdir::TestDir;
    use crate::proc::testutil::script;
    use std::sync::Mutex;

    struct Fixed(Vec<Account>);

    impl Accounts for Fixed {
        fn by_name(&self, name: &str) -> Option<Account> {
            self.0.iter().find(|a| a.name == name).cloned()
        }
        fn by_uid(&self, uid: u32) -> Option<Account> {
            self.0.iter().find(|a| a.uid == uid).cloned()
        }
        fn all(&self) -> Vec<Account> {
            self.0.clone()
        }
    }

    fn account(name: &str, uid: u32, shell: &str) -> Account {
        Account { name: name.into(), uid, shell: shell.into() }
    }

    fn box_accounts() -> Fixed {
        Fixed(vec![
            account("root", 0, "/bin/bash"),
            account("daemon", 1, "/usr/sbin/nologin"),
            account("nobody", 65534, "/usr/sbin/nologin"),
            account("svc", 1000, "/bin/false"),
            account("alice", 1001, "/bin/zsh"),
            account("soc", 998, "/bin/bash"),
        ])
    }

    fn hints(operator: Option<&str>, sudo: Option<&str>) -> OperatorHints {
        OperatorHints { operator_user: operator.map(Into::into), sudo_user: sudo.map(Into::into), own_uid: 998 }
    }

    #[test]
    fn operator_user_prefers_the_explicit_setting() {
        // Even root: the operator's explicit choice (they may have set a
        // root password).
        assert_eq!(operator_user_from(&hints(Some("root"), Some("alice")), &box_accounts()), "root");
    }

    #[test]
    fn sudo_user_root_is_skipped() {
        // The double-sudo trap: prompting for root's (locked) password.
        assert_eq!(operator_user_from(&hints(None, Some("root")), &box_accounts()), "alice");
    }

    #[test]
    fn sudo_user_real_user_wins() {
        assert_eq!(operator_user_from(&hints(None, Some("soc")), &box_accounts()), "soc");
    }

    #[test]
    fn nonexistent_settings_fall_through() {
        let h = hints(Some("this-user-does-not-exist-12345"), Some("neither-does-this"));
        assert_eq!(operator_user_from(&h, &box_accounts()), "alice");
    }

    #[test]
    fn first_human_with_a_login_shell_then_conventions_then_self() {
        let no_humans = Fixed(vec![
            account("root", 0, "/bin/bash"),
            account("pi", 500, "/bin/bash"),
            account("soc", 998, "/bin/sh"),
        ]);
        assert_eq!(operator_user_from(&hints(None, None), &no_humans), "pi");
        let only_self = Fixed(vec![account("root", 0, "/bin/bash"), account("soc", 998, "/bin/sh")]);
        assert_eq!(operator_user_from(&hints(None, None), &only_self), "soc");
        assert_eq!(operator_user_from(&hints(None, None), &Fixed(vec![])), "root");
    }

    #[test]
    fn passwd_lines_parse_and_garbage_is_skipped() {
        let parsed = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\nbroken\n:x:5:5::/:/bin/sh\nkali:x:1000:1000:,,,:/home/kali:/usr/bin/zsh\nnouid:x:abc:1::/:/bin/sh\n",
        );
        assert_eq!(parsed, [account("root", 0, "/bin/bash"), account("kali", 1000, "/usr/bin/zsh")]);
    }

    #[test]
    fn system_accounts_are_consistent_and_refuse_option_shaped_names() {
        let sys = SystemAccounts;
        // Whatever this host's database holds, lookups must agree with it and
        // an option-shaped name must never be looked up at all.
        if let Some(root) = sys.by_name("root") {
            assert_eq!(root.uid, 0);
            assert!(sys.all().iter().any(|a| a.name == "root"));
        }
        if let Some(uid0) = sys.by_uid(0) {
            assert_eq!(sys.by_name(&uid0.name).map(|a| a.uid), Some(0));
        }
        assert!(sys.by_name("--help").is_none());
        assert!(sys.by_name("this-user-does-not-exist-12345").is_none());
        assert!(!operator_user().is_empty());
    }

    #[test]
    fn usernames_shaped_like_options_or_paths_are_rejected() {
        for ok in ["alice", "_svc", "a.b-c_d", "machine$", "A1"] {
            assert!(valid_username(ok), "{ok}");
        }
        for bad in ["", "-root", "--help", "1abc", "a b", "a/b", "a\n", "$", "a$b", "ali\u{0441}e", "a$$"] {
            assert!(!valid_username(bad), "{bad:?}");
        }
    }

    /// A scripted backend that records it was asked.
    struct Scripted {
        name: &'static str,
        answer: Option<bool>,
        calls: std::sync::Arc<Mutex<Vec<&'static str>>>,
    }

    impl Backend for Scripted {
        fn verify(&self, _user: &str, _password: &str, _timeout: Duration) -> Option<bool> {
            self.calls.lock().unwrap().push(self.name);
            self.answer
        }
    }

    fn chain(answers: &[(&'static str, Option<bool>)]) -> (OsPassword, std::sync::Arc<Mutex<Vec<&'static str>>>) {
        let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
        let backends = answers
            .iter()
            .map(|&(name, answer)| Box::new(Scripted { name, answer, calls: calls.clone() }) as Box<dyn Backend>)
            .collect();
        (OsPassword { backends, min_latency: Duration::ZERO, timeout: HELPER_TIMEOUT }, calls)
    }

    #[test]
    fn empty_or_malformed_input_is_rejected_before_any_backend_runs() {
        let (gate, calls) = chain(&[("su", Some(true))]);
        for (user, password) in [
            ("", "anything"),
            ("root", ""),
            ("", ""),
            ("-oProxyCommand", "pw"),
            ("alice", "pw\nmore"),
            ("alice", "pw\0"),
        ] {
            assert_eq!(gate.check(user, password), Ok(false), "{user:?}");
        }
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn first_backend_with_a_verdict_decides() {
        let (gate, calls) = chain(&[("su", Some(true)), ("pamtester", Some(false))]);
        assert!(gate.verify("alice", "right-password"));
        assert_eq!(*calls.lock().unwrap(), ["su"]);

        let (gate, calls) = chain(&[("su", Some(false)), ("pamtester", Some(true))]);
        assert!(!gate.verify("alice", "wrong"), "a refusal is a verdict, not a reason to ask someone else");
        assert_eq!(*calls.lock().unwrap(), ["su"]);
    }

    #[test]
    fn an_unusable_backend_falls_through_to_the_next() {
        let (gate, calls) = chain(&[("su", None), ("pamtester", Some(true))]);
        assert!(gate.verify("alice", "pw"));
        assert_eq!(*calls.lock().unwrap(), ["su", "pamtester"]);
    }

    #[test]
    fn no_backend_is_unsupported_and_reads_as_rejected() {
        let (gate, _) = chain(&[("su", None), ("pamtester", None)]);
        assert_eq!(gate.check("alice", "pw"), Err(OsPassError::Unsupported));
        assert!(!gate.verify("alice", "pw"));
        let none = OsPassword::with_helpers(None, None);
        assert_eq!(none.check("alice", "pw"), Err(OsPassError::Unsupported));
    }

    #[test]
    fn every_attempt_takes_at_least_the_minimum_latency() {
        let (mut gate, _) = chain(&[("su", Some(false))]);
        gate.min_latency = Duration::from_millis(100);
        let started = Instant::now();
        assert!(!gate.verify("alice", "wrong"));
        assert!(started.elapsed() >= Duration::from_millis(90));
    }

    /// A fake `su`: accepts when the line on stdin is `$accept`, and records
    /// its argv so the test can prove the password never appears there.
    fn fake_su(dir: &Path, accept: &str) -> PathBuf {
        let body = format!(
            r#"dir=$(dirname "$0"); echo "$*" >> "$dir/su.argv"
IFS= read -r line
case "{accept}" in ANY) exit 0 ;; esac
[ "$line" = "{accept}" ]"#
        );
        script(dir, "su", &body)
    }

    fn fast(gate: OsPassword) -> OsPassword {
        OsPassword { min_latency: Duration::ZERO, ..gate }
    }

    #[test]
    fn su_backend_accepts_the_right_password_only() {
        let d = TestDir::new("su");
        let gate = fast(OsPassword::with_helpers(Some(&fake_su(d.path(), "s3cret pw")), None));
        assert_eq!(gate.check("alice", "s3cret pw"), Ok(true));
        assert_eq!(gate.check("alice", "wrong"), Ok(false));
        let argv = std::fs::read_to_string(d.join("su.argv")).unwrap();
        assert!(argv.lines().all(|l| l == "- alice -c true"), "{argv}");
        assert!(!argv.contains("s3cret"));
    }

    #[test]
    fn su_that_accepts_anything_proves_nothing() {
        // A password-less account: su succeeds whatever is typed.
        let d = TestDir::new("su-any");
        let gate = fast(OsPassword::with_helpers(Some(&fake_su(d.path(), "ANY")), None));
        assert_eq!(gate.check("guest", "whatever"), Ok(false));
        assert_eq!(std::fs::read_to_string(d.join("su.argv")).unwrap().lines().count(), 2, "real try + probe");
    }

    #[test]
    fn a_hung_or_missing_su_is_a_refusal() {
        let d = TestDir::new("su-hang");
        let hung = script(d.path(), "su", "exec sleep 30");
        let gate = fast(OsPassword::with_helpers(Some(&hung), None)).with_timeout(Duration::from_millis(100));
        assert_eq!(gate.check("alice", "pw"), Ok(false));
        let gone = fast(OsPassword::with_helpers(Some(&d.join("absent")), None));
        assert_eq!(gone.check("alice", "pw"), Ok(false));
    }

    #[test]
    fn pamtester_backend_gets_the_password_on_stdin() {
        let d = TestDir::new("pamtester");
        let body = r#"dir=$(dirname "$0"); echo "$*" > "$dir/argv"; [ "$(cat)" = "right" ]"#;
        let gate = fast(OsPassword::with_helpers(None, Some(&script(d.path(), "pamtester", body))));
        assert_eq!(gate.check("alice", "right"), Ok(true));
        assert_eq!(gate.check("alice", "wrong"), Ok(false));
        assert_eq!(std::fs::read_to_string(d.join("argv")).unwrap(), "login alice authenticate\n");
    }

    #[test]
    fn system_helpers_never_include_su_for_root() {
        let gate = OsPassword::system();
        if rustix::process::geteuid().is_root() {
            assert!(gate.backends.len() <= 1, "su is skipped for root: pam_rootok checks nothing");
        }
        assert!(!format!("{gate:?}").is_empty());
    }
}
