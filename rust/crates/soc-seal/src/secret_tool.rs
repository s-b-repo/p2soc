//! The freedesktop Secret Service (KWallet, GNOME Keyring, KeePassXC), reached
//! through libsecret's `secret-tool` CLI rather than by linking libsecret: it
//! is D-Bus based, so it works the same on every compositor and on X11.
//!
//! A locked wallet can make `secret-tool` block on an interactive prompt, so
//! every call has a deadline: a locked wallet degrades instead of wedging the
//! boot.

use crate::proc::{self, RunError};
use soc_core::guard;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(10);
/// No master password is anywhere near this long.
const MAX_SECRET: usize = 8 * 1024;

/// Attribute pairs an item is stored and looked up under. A lookup and a store
/// must present the SAME attributes or they will not match.
pub type Attrs = Vec<(String, String)>;

/// Why the Secret Service could not be used.
#[derive(Debug)]
pub enum SecretToolError {
    /// `secret-tool` is not installed.
    Missing,
    /// It did not answer in time — usually a locked wallet waiting on a prompt.
    TimedOut,
    /// An attribute is unusable as an argument (option-shaped, or holding
    /// control characters).
    BadAttribute(String),
    /// It ran and failed; the text is its own stderr (never the secret).
    Failed(String),
}

impl fmt::Display for SecretToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretToolError::Missing => f.write_str(
                "secret-tool not found — install libsecret (apt: libsecret-tools, \
                 dnf/pacman/apk/xbps: libsecret)",
            ),
            SecretToolError::TimedOut => f.write_str(
                "secret-tool timed out — is the wallet (KWallet / gnome-keyring / KeePassXC) running and unlocked?",
            ),
            SecretToolError::BadAttribute(what) => write!(f, "unusable Secret Service attribute: {what}"),
            SecretToolError::Failed(why) => write!(f, "secret-tool failed: {why}"),
        }
    }
}

impl std::error::Error for SecretToolError {}

/// A handle on the `secret-tool` program (possibly absent).
#[derive(Clone, Debug)]
pub struct SecretTool {
    program: Option<PathBuf>,
    timeout: Duration,
}

impl SecretTool {
    /// Find `secret-tool` on `$PATH`.
    pub fn locate() -> SecretTool {
        let program = std::env::var_os("PATH").and_then(|path| proc::find_in("secret-tool", &path));
        SecretTool { program, timeout: TIMEOUT }
    }

    /// Use the program at `program`.
    pub fn at(program: impl Into<PathBuf>) -> SecretTool {
        SecretTool { program: Some(program.into()), timeout: TIMEOUT }
    }

    /// A handle for a host without `secret-tool`.
    pub fn absent() -> SecretTool {
        SecretTool { program: None, timeout: TIMEOUT }
    }

    /// Override the per-call deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> SecretTool {
        self.timeout = timeout;
        self
    }

    /// True if the program was found. A capability probe only: it does not
    /// say a wallet is running or unlocked.
    pub fn available(&self) -> bool {
        self.program.is_some()
    }

    /// Attributes become argv slots of `secret-tool`, and can come from the
    /// environment: refuse anything it could read as an option.
    fn argv(attrs: &[(String, String)]) -> Result<Vec<&str>, SecretToolError> {
        if attrs.is_empty() {
            return Err(SecretToolError::BadAttribute("no attributes given".into()));
        }
        let mut argv = Vec::with_capacity(attrs.len() * 2);
        for (key, value) in attrs {
            for (what, token) in [("name", key), ("value", value)] {
                if token.is_empty() || token.starts_with('-') || guard::has_ctrl(token) {
                    return Err(SecretToolError::BadAttribute(format!("{what} of {key:?}")));
                }
                argv.push(token.as_str());
            }
        }
        Ok(argv)
    }

    fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<proc::Finished, SecretToolError> {
        let program = self.program.as_deref().ok_or(SecretToolError::Missing)?;
        proc::run(program, args, stdin, self.timeout, MAX_SECRET).map_err(|e| match e {
            RunError::NotFound => SecretToolError::Missing,
            RunError::TimedOut => SecretToolError::TimedOut,
            other => SecretToolError::Failed(other.to_string()),
        })
    }

    /// `secret-tool lookup <k> <v> …`: the stored value, verbatim except for
    /// the single trailing newline libsecret may add (a secret with
    /// surrounding spaces survives). `Ok(None)` when no such item exists.
    pub fn lookup(&self, attrs: &[(String, String)]) -> Result<Option<Zeroizing<String>>, SecretToolError> {
        let mut args = vec!["lookup"];
        args.extend(Self::argv(attrs)?);
        let mut done = self.run(&args, None)?;
        if !done.success {
            return Ok(None);
        }
        if done.stdout.last() == Some(&b'\n') {
            done.stdout.pop();
        }
        if done.stdout.is_empty() {
            return Ok(None);
        }
        match String::from_utf8(std::mem::take(&mut *done.stdout)) {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(not_text) => {
                drop(Zeroizing::new(not_text.into_bytes()));
                Err(SecretToolError::Failed("the stored value is not valid UTF-8 text".into()))
            }
        }
    }

    /// `secret-tool store --label … <k> <v> …`, feeding the secret on STDIN
    /// (never argv, so it cannot leak via ps or /proc).
    pub fn store(&self, label: &str, attrs: &[(String, String)], secret: &str) -> Result<(), SecretToolError> {
        if label.starts_with('-') || guard::has_ctrl(label) {
            return Err(SecretToolError::BadAttribute("label".into()));
        }
        let mut args = vec!["store", "--label", label];
        args.extend(Self::argv(attrs)?);
        let done = self.run(&args, Some(secret.as_bytes()))?;
        if done.success {
            return Ok(());
        }
        let said = String::from_utf8_lossy(&done.stderr).trim().to_string();
        Err(SecretToolError::Failed(if said.is_empty() { "no Secret Service?".into() } else { said }))
    }

    /// `secret-tool clear <k> <v> …`. Safe to call when nothing is stored.
    pub fn clear(&self, attrs: &[(String, String)]) -> Result<(), SecretToolError> {
        let mut args = vec!["clear"];
        args.extend(Self::argv(attrs)?);
        let done = self.run(&args, None)?;
        if done.success {
            return Ok(());
        }
        Err(SecretToolError::Failed(String::from_utf8_lossy(&done.stderr).trim().to_string()))
    }
}

/// The opt-in login-keyring backend (`SOC_SECRET_BACKEND=libsecret`): the
/// master stored in the user's keyring, unlocked when the user logs in.
///
/// Trade-off against the sealed files: those are host-bound and need no user
/// session (right for a tty1 kiosk); the keyring is user-bound and only
/// reachable while that user's keyring is unlocked (right for a desk deploy).
/// Operators choose at setup time; nothing is promoted automatically, and the
/// sealed files stay the on-disk source of truth.
///
/// The item carries the schema name and attribute the Python release stored
/// it under, so an entry written by either is found by both.
#[derive(Clone, Debug)]
pub struct Keyring {
    tool: SecretTool,
}

impl Keyring {
    const LABEL: &'static str = "SOC Wall vault master";

    fn attrs() -> Attrs {
        vec![("xdg:schema".into(), "com.soc-wall.master".into()), ("role".into(), "master".into())]
    }

    pub fn new(tool: SecretTool) -> Keyring {
        Keyring { tool }
    }

    /// True if `secret-tool` is installed (no D-Bus traffic).
    pub fn available(&self) -> bool {
        self.tool.available()
    }

    /// The stored master, `Ok(None)` if there is none.
    pub fn load(&self) -> Result<Option<Zeroizing<String>>, SecretToolError> {
        self.tool.lookup(&Self::attrs())
    }

    pub fn store(&self, master: &str) -> Result<(), SecretToolError> {
        self.tool.store(Self::LABEL, &Self::attrs(), master)
    }

    pub fn clear(&self) -> Result<(), SecretToolError> {
        self.tool.clear(&Self::attrs())
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use crate::proc::testutil::script;
    use std::path::{Path, PathBuf};

    /// A fake `secret-tool`: `lookup` prints `$dir/value` (exit 1 if absent),
    /// `store` appends its argv (unit-separated), a tab and its stdin to
    /// `$dir/rec`, `clear` removes the value. Proves what really crosses the
    /// process boundary.
    pub(crate) fn fake_secret_tool(dir: &Path) -> PathBuf {
        let body = r#"dir=$(dirname "$0")
case "$1" in
  lookup) [ -f "$dir/value" ] || exit 1; cat "$dir/value"; printf '\n' ;;
  store) { IFS=$(printf '\037'); printf '%s\t' "$*"; cat; printf '\n'; } >> "$dir/rec"
         [ ! -f "$dir/store-fails" ] || { echo "no Secret Service" >&2; exit 1; } ;;
  clear) rm -f "$dir/value" ;;
  *) exit 2 ;;
esac"#;
        script(dir, "secret-tool", body)
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::fake_secret_tool;
    use super::*;
    use crate::fsio::testdir::TestDir;
    use crate::proc::testutil::script;

    fn attrs(pairs: &[(&str, &str)]) -> Attrs {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn lookup_strips_one_trailing_newline_only() {
        let d = TestDir::new("st-lookup");
        let tool = SecretTool::at(fake_secret_tool(d.path()));
        std::fs::write(d.join("value"), "  pw with spaces  ").unwrap();
        let got = tool.lookup(&attrs(&[("service", "soc-wall")])).unwrap().unwrap();
        assert_eq!(got.as_str(), "  pw with spaces  ");
        std::fs::write(d.join("value"), "ends-in-newline\n").unwrap();
        assert_eq!(tool.lookup(&attrs(&[("a", "b")])).unwrap().unwrap().as_str(), "ends-in-newline\n");
    }

    #[test]
    fn absent_item_is_none_and_absent_tool_is_typed() {
        let d = TestDir::new("st-absent");
        let tool = SecretTool::at(fake_secret_tool(d.path()));
        assert!(tool.lookup(&attrs(&[("a", "b")])).unwrap().is_none());
        assert!(matches!(SecretTool::absent().lookup(&attrs(&[("a", "b")])), Err(SecretToolError::Missing)));
        assert!(matches!(SecretTool::at(d.join("gone")).lookup(&attrs(&[("a", "b")])), Err(SecretToolError::Missing)));
        assert!(!SecretTool::absent().available());
    }

    #[test]
    fn store_feeds_the_secret_on_stdin_never_argv() {
        let d = TestDir::new("st-store");
        let tool = SecretTool::at(fake_secret_tool(d.path()));
        tool.store("a label", &attrs(&[("service", "soc-wall"), ("account", "vault-master")]), "S3cr3t-on-stdin")
            .unwrap();
        let rec = std::fs::read_to_string(d.join("rec")).unwrap();
        let (argv, stdin) = rec.trim_end_matches('\n').split_once('\t').unwrap();
        let argv: Vec<&str> = argv.split('\u{1f}').collect();
        assert_eq!(argv, ["store", "--label", "a label", "service", "soc-wall", "account", "vault-master"]);
        assert_eq!(stdin, "S3cr3t-on-stdin");
    }

    #[test]
    fn store_failure_surfaces_the_tools_own_words() {
        let d = TestDir::new("st-fail");
        let tool = SecretTool::at(fake_secret_tool(d.path()));
        std::fs::write(d.join("store-fails"), "").unwrap();
        let err = tool.store("l", &attrs(&[("a", "b")]), "the-master").unwrap_err();
        assert!(err.to_string().contains("no Secret Service"));
        assert!(!err.to_string().contains("the-master") && !format!("{err:?}").contains("the-master"));
    }

    #[test]
    fn a_locked_wallet_times_out_instead_of_hanging() {
        let d = TestDir::new("st-slow");
        let tool =
            SecretTool::at(script(d.path(), "secret-tool", "exec sleep 30")).with_timeout(Duration::from_millis(100));
        assert!(matches!(tool.lookup(&attrs(&[("a", "b")])), Err(SecretToolError::TimedOut)));
    }

    #[test]
    fn option_shaped_attributes_never_reach_the_tool() {
        let d = TestDir::new("st-inject");
        let tool = SecretTool::at(fake_secret_tool(d.path()));
        for bad in
            [attrs(&[("--all", "x")]), attrs(&[("k", "-v")]), attrs(&[("k", "a\nb")]), attrs(&[("", "v")]), attrs(&[])]
        {
            assert!(matches!(tool.lookup(&bad), Err(SecretToolError::BadAttribute(_))), "{bad:?}");
            assert!(matches!(tool.store("l", &bad, "s"), Err(SecretToolError::BadAttribute(_))));
        }
        assert!(matches!(tool.store("--label", &attrs(&[("a", "b")]), "s"), Err(SecretToolError::BadAttribute(_))));
        assert!(!d.join("rec").exists());
    }

    #[test]
    fn non_text_values_are_an_error_not_a_panic() {
        let d = TestDir::new("st-bin");
        let tool = SecretTool::at(fake_secret_tool(d.path()));
        std::fs::write(d.join("value"), [0xff, 0xfe]).unwrap();
        assert!(matches!(tool.lookup(&attrs(&[("a", "b")])), Err(SecretToolError::Failed(_))));
    }

    #[test]
    fn keyring_uses_the_python_releases_schema_and_round_trips() {
        let d = TestDir::new("st-keyring");
        let keyring = Keyring::new(SecretTool::at(fake_secret_tool(d.path())));
        assert!(keyring.available());
        assert!(keyring.load().unwrap().is_none());
        keyring.store("kr-master").unwrap();
        let rec = std::fs::read_to_string(d.join("rec")).unwrap();
        assert!(rec.starts_with("store\u{1f}--label\u{1f}SOC Wall vault master\u{1f}xdg:schema\u{1f}com.soc-wall.master\u{1f}role\u{1f}master\t"));
        std::fs::write(d.join("value"), "kr-master").unwrap();
        assert_eq!(keyring.load().unwrap().unwrap().as_str(), "kr-master");
        keyring.clear().unwrap();
        assert!(keyring.load().unwrap().is_none());
    }
}
