//! The `litebw` command line: an `rbw`-compatible subset for the few call
//! sites (and operators) that shell out.
//!
//! ```text
//! litebw config set <email|base_url|pinentry> <value>
//! litebw login | unlock | unlocked | sync
//! litebw get [--field username|password|notes] <item>
//! litebw code <item>
//! ```
//!
//! Secrets only ever leave on stdout, value only, one line; diagnostics go to
//! stderr and never contain them. Nothing secret is accepted on argv.

use std::io::Write;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::config::{CONFIG_KEYS, LitebwConfig, default_config_path, resolve};
use crate::error::VaultError;
use crate::master::{EnvMaster, MasterSource};
use crate::session::{Session, SessionOptions};
use crate::totp;

const USAGE: &str = "\
litebw — lightweight Vaultwarden client (rbw-compatible subset)

usage:
  litebw config set <email|base_url|pinentry> <value>
  litebw login
  litebw unlock | unlocked
  litebw sync
  litebw get [--field username|password|notes] <item>
  litebw code <item>
";

/// Everything the CLI takes from its surroundings.
pub struct CliContext<'a> {
    /// Where the master password comes from (the sealed store, in production).
    pub master: &'a dyn MasterSource,
    /// The litebw config file.
    pub config_path: PathBuf,
    /// `$SOC_VAULT_EMAIL` / `$SOC_VAULT_URL`; they win over the config file.
    pub env_email: Option<String>,
    pub env_url: Option<String>,
    pub session: SessionOptions,
    /// Pin "now" (seconds since the epoch) for `code`; `None` uses the clock.
    pub unix_time: Option<u64>,
}

impl<'a> CliContext<'a> {
    /// The context this process's environment describes.
    pub fn from_env(master: &'a dyn MasterSource) -> CliContext<'a> {
        CliContext {
            master,
            config_path: default_config_path(),
            env_email: soc_core::env::env_str("SOC_VAULT_EMAIL"),
            env_url: soc_core::env::env_str("SOC_VAULT_URL"),
            session: SessionOptions::from_env(),
            unix_time: None,
        }
    }

    fn open_session(&self) -> Result<Session, VaultError> {
        let file = LitebwConfig::load(&self.config_path);
        let url = resolve(self.env_url.as_deref(), file.base_url());
        let email = resolve(self.env_email.as_deref(), file.email());
        let master = match self.master.master() {
            Ok(m) => m,
            // Let the missing URL / email be reported first, as the more basic problem.
            Err(VaultError::NoMaster(_)) if url.is_empty() || email.is_empty() => Zeroizing::new("-".to_string()),
            Err(e) => return Err(e),
        };
        Session::login(url, email, &master, &self.session)
    }
}

struct Io<'a> {
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl Io<'_> {
    /// Write a diagnostic and return `code`.
    fn fail(&mut self, code: i32, message: &str) -> i32 {
        let _ = writeln!(self.err, "{message}"); // audit-allow: best-effort: diagnostics writer failure (closed pipe) is unreportable
        code
    }
}

fn cmd_config(args: &[String], ctx: &CliContext<'_>, io: &mut Io<'_>) -> i32 {
    if args.first().map(String::as_str) != Some("set") {
        return io.fail(2, "litebw config: only 'set' is supported");
    }
    let [_, key, value, ..] = args else {
        return io.fail(2, "litebw config set <key> <value>");
    };
    if !CONFIG_KEYS.contains(&key.as_str()) {
        return io.fail(2, &format!("litebw config set: unknown key '{key}' (email|base_url|pinentry)"));
    }
    let mut file = LitebwConfig::load(&ctx.config_path);
    file.set(key, value);
    match file.save(&ctx.config_path) {
        Ok(()) => 0,
        Err(e) => io.fail(2, &format!("litebw config set: {e}")),
    }
}

fn cmd_get(args: &[String], ctx: &CliContext<'_>, io: &mut Io<'_>) -> i32 {
    let mut field = "password";
    let mut item = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--field" {
            match rest.next() {
                Some(value) => field = value,
                None => return io.fail(2, "litebw get: --field needs a value"),
            }
        } else if let Some(value) = arg.strip_prefix("--field=") {
            field = value;
        } else if item.is_none() {
            item = Some(arg.as_str());
        }
    }
    let Some(item) = item else {
        return io.fail(2, "litebw get: missing <item>");
    };
    if !matches!(field, "password" | "username" | "notes") {
        return io.fail(2, &format!("litebw get: unknown --field '{field}'"));
    }
    let found = ctx.open_session().and_then(|session| session.find(item));
    let cipher = match found {
        Ok(Some(cipher)) => cipher,
        Ok(None) => return io.fail(1, &format!("litebw get: item '{item}' not found")),
        Err(e) => return io.fail(1, &format!("litebw get: {e}")),
    };
    let value = match field {
        "password" => cipher.password(),
        "username" => cipher.username(),
        _ => cipher.notes(),
    };
    match value {
        Err(e) => io.fail(1, &format!("litebw get: {e}")),
        Ok(v) if v.is_empty() && field == "password" => {
            io.fail(1, &format!("litebw get: item '{item}' has no password"))
        }
        // username / notes: the item exists, so an empty value is still success.
        Ok(v) if v.is_empty() => 0,
        Ok(v) => {
            let _ = writeln!(io.out, "{}", v.as_str()); // audit-allow: best-effort: output writer failure (closed pipe) is unreportable
            0
        }
    }
}

fn cmd_code(args: &[String], ctx: &CliContext<'_>, io: &mut Io<'_>) -> i32 {
    let Some(item) = args.first() else {
        return io.fail(2, "litebw code: missing <item>");
    };
    let secret = ctx.open_session().and_then(|session| match session.find(item)? {
        Some(cipher) if cipher.has_totp() => cipher.totp(),
        _ => Err(VaultError::NotFound(format!("item '{item}' has no TOTP secret"))),
    });
    let code = secret.and_then(|s| totp::generate(&s, ctx.unix_time.unwrap_or_else(totp::unix_now)));
    match code {
        Ok(code) => {
            let _ = writeln!(io.out, "{code}"); // audit-allow: best-effort: output writer failure (closed pipe) is unreportable
            0
        }
        Err(e) => io.fail(1, &format!("litebw code: {e}")),
    }
}

/// Run the CLI with its surroundings injected. `args` are the words after the
/// program (or subcommand) name. Returns the process exit code: 0 success,
/// 1 a vault failure, 2 a usage error.
pub fn cli_main_with(args: &[String], ctx: &CliContext<'_>, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut io = Io { out, err };
    let Some((command, rest)) = args.split_first() else {
        let _ = io.out.write_all(USAGE.as_bytes()); // audit-allow: best-effort: output writer failure (closed pipe) is unreportable
        return 0;
    };
    match command.as_str() {
        "-h" | "--help" | "help" => {
            let _ = io.out.write_all(USAGE.as_bytes()); // audit-allow: best-effort: output writer failure (closed pipe) is unreportable
            0
        }
        "config" => cmd_config(rest, ctx, &mut io),
        // prelogin + token grant proves the credentials and reachability.
        "login" => match ctx.open_session() {
            Ok(_) => 0,
            Err(e) => io.fail(1, &format!("litebw login: {e}")),
        },
        // No agent in this client: the long-running host unlocks in process.
        "unlock" | "unlocked" => 0,
        "sync" => match ctx.open_session().and_then(|session| session.ciphers()) {
            Ok(_) => 0,
            Err(e) => io.fail(1, &format!("litebw sync: {e}")),
        },
        "get" => cmd_get(rest, ctx, &mut io),
        "code" => cmd_code(rest, ctx, &mut io),
        other => {
            let shown: String = other.chars().filter(|c| !c.is_control()).take(40).collect();
            io.fail(2, &format!("litebw: unknown command '{shown}'\n{USAGE}"))
        }
    }
}

/// Run the CLI against the process environment, with the master password
/// taken from `$SOC_VAULT_PASSWORD` (development / seeding). A binary that has
/// a sealed store should call [`cli_main_with`] and pass it as the source.
pub fn cli_main(args: &[String]) -> i32 {
    let master = EnvMaster::new();
    let ctx = CliContext::from_env(&master);
    cli_main_with(args, &ctx, &mut std::io::stdout(), &mut std::io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use crate::master::{FixedMaster, NoMaster};
    use crate::testutil::{FakeVaultwarden, TEST_EMAIL, TEST_MASTER, test_options};
    use serde_json::json;

    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    struct Fixture {
        fake: FakeVaultwarden,
        dir: TestDir,
        master: FixedMaster,
    }

    impl Fixture {
        fn new() -> Fixture {
            let fake = FakeVaultwarden::start();
            {
                let mut s = fake.state();
                let wazuh = s.add_login("wazuh", "admin", "s3cr3t");
                let (notes, totp) = (s.enc("panel notes"), s.enc(RFC_SECRET));
                s.cipher_mut(&wazuh)["notes"] = json!(notes);
                s.cipher_mut(&wazuh)["login"]["totp"] = json!(totp);
                s.add_login("nouser", "", "pw-only");
                let nopw = s.add_login("nopw", "u", "");
                let note = s.enc("just a note");
                s.cipher_mut(&nopw)["notes"] = json!(note);
                let bad = s.add_login("badtotp", "u", "p");
                let junk = s.enc("not base32 !!!");
                s.cipher_mut(&bad)["login"]["totp"] = json!(junk);
            }
            Fixture { fake, dir: TestDir::new("cli"), master: FixedMaster::new(TEST_MASTER) }
        }

        fn ctx(&self) -> CliContext<'_> {
            CliContext {
                master: &self.master,
                config_path: self.dir.path().join("litebw").join("config.json"),
                env_email: Some(TEST_EMAIL.to_string()),
                env_url: Some(self.fake.url().to_string()),
                session: test_options(),
                unix_time: Some(59),
            }
        }

        fn run(&self, args: &[&str]) -> (i32, String, String) {
            run(&self.ctx(), args)
        }
    }

    fn run(ctx: &CliContext<'_>, args: &[&str]) -> (i32, String, String) {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli_main_with(&args, ctx, &mut out, &mut err);
        (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    fn offline_ctx<'a>(dir: &TestDir, master: &'a dyn MasterSource) -> CliContext<'a> {
        CliContext {
            master,
            config_path: dir.path().join("litebw").join("config.json"),
            env_email: None,
            env_url: None,
            session: test_options(),
            unix_time: None,
        }
    }

    #[test]
    fn get_prints_only_the_requested_value() {
        let f = Fixture::new();
        assert_eq!(f.run(&["get", "wazuh"]), (0, "s3cr3t\n".into(), String::new()));
        assert_eq!(f.run(&["get", "--field", "username", "wazuh"]), (0, "admin\n".into(), String::new()));
        assert_eq!(f.run(&["get", "--field=notes", "wazuh"]), (0, "panel notes\n".into(), String::new()));
        assert_eq!(f.run(&["get", "wazuh", "--field", "password"]), (0, "s3cr3t\n".into(), String::new()));
    }

    #[test]
    fn empty_username_or_notes_is_success_with_no_output() {
        let f = Fixture::new();
        assert_eq!(f.run(&["get", "--field", "username", "nouser"]), (0, String::new(), String::new()));
        assert_eq!(f.run(&["get", "--field", "notes", "nouser"]), (0, String::new(), String::new()));
    }

    #[test]
    fn missing_items_and_passwords_exit_nonzero_with_empty_stdout() {
        let f = Fixture::new();
        let (code, out, err) = f.run(&["get", "does-not-exist"]);
        assert_eq!((code, out.as_str()), (1, ""));
        assert_eq!(err, "litebw get: item 'does-not-exist' not found\n");
        let (code, out, err) = f.run(&["get", "nopw"]);
        assert_eq!((code, out.as_str()), (1, ""));
        assert_eq!(err, "litebw get: item 'nopw' has no password\n");
    }

    #[test]
    fn get_usage_errors_exit_2_without_touching_the_vault() {
        let f = Fixture::new();
        for bad in
            [&["get"][..], &["get", "--field"], &["get", "--field", "uri", "wazuh"], &["get", "--field=x", "wazuh"]]
        {
            let (code, out, err) = f.run(bad);
            assert_eq!((code, out.as_str()), (2, ""), "{bad:?}");
            assert!(err.starts_with("litebw get: "), "{err}");
        }
        assert!(f.fake.server.requests().is_empty());
    }

    #[test]
    fn code_prints_only_the_digits() {
        let f = Fixture::new();
        assert_eq!(f.run(&["code", "wazuh"]), (0, "287082\n".into(), String::new()));
        let (code, out, err) = f.run(&["code", "nouser"]);
        assert_eq!((code, out.as_str()), (1, ""));
        assert_eq!(err, "litebw code: item 'nouser' has no TOTP secret\n");
        let (code, out, _) = f.run(&["code", "ghost"]);
        assert_eq!((code, out.as_str()), (1, ""));
        // A malformed secret is a clean failure that does not echo the secret.
        let (code, out, err) = f.run(&["code", "badtotp"]);
        assert_eq!((code, out.as_str()), (1, ""));
        assert!(err.starts_with("litebw code: ") && !err.contains("not base32"), "{err}");
        assert_eq!(f.run(&["code"]).0, 2);
    }

    #[test]
    fn login_and_sync_report_success_and_failure() {
        let f = Fixture::new();
        assert_eq!(f.run(&["login"]), (0, String::new(), String::new()));
        assert_eq!(f.run(&["sync"]), (0, String::new(), String::new()));

        let wrong = FixedMaster::new("not the master password");
        let ctx = CliContext { master: &wrong, ..f.ctx() };
        let (code, out, err) = run(&ctx, &["login"]);
        assert_eq!((code, out.as_str()), (1, ""));
        assert!(err.starts_with("litebw login: Vaultwarden rejected the login"), "{err}");
        assert!(!err.contains("not the master password"));
        assert_eq!(run(&ctx, &["get", "wazuh"]).0, 1);

        let none = NoMaster;
        let ctx = CliContext { master: &none, ..f.ctx() };
        let (code, _, err) = run(&ctx, &["sync"]);
        assert_eq!(code, 1);
        assert!(err.starts_with("litebw sync: no vault master password"), "{err}");
    }

    #[test]
    fn the_config_file_supplies_email_and_url_when_the_environment_does_not() {
        let f = Fixture::new();
        let ctx = CliContext { env_email: None, env_url: None, ..f.ctx() };
        // Nothing configured yet: the missing URL is the first thing reported.
        let (code, _, err) = run(&ctx, &["login"]);
        assert_eq!(code, 1);
        assert!(err.contains("no Vaultwarden URL"), "{err}");
        assert_eq!(run(&ctx, &["config", "set", "base_url", f.fake.url()]).0, 0);
        let (_, _, err) = run(&ctx, &["login"]);
        assert!(err.contains("no vault email"), "{err}");
        assert_eq!(run(&ctx, &["config", "set", "email", TEST_EMAIL]).0, 0);
        assert_eq!(run(&ctx, &["get", "wazuh"]), (0, "s3cr3t\n".into(), String::new()));
        // The environment overrides the file at read time.
        let ctx = CliContext { env_email: Some("someone-else@soc.local".into()), ..ctx };
        assert_eq!(run(&ctx, &["login"]).0, 1);
    }

    #[test]
    fn config_set_persists_private_json() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("cli-config");
        let ctx = offline_ctx(&dir, &NoMaster);
        assert_eq!(run(&ctx, &["config", "set", "email", "a@b.com"]), (0, String::new(), String::new()));
        assert_eq!(run(&ctx, &["config", "set", "base_url", "https://vault.local"]).0, 0);
        assert_eq!(run(&ctx, &["config", "set", "pinentry", "/usr/bin/pinentry"]).0, 0);
        let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&ctx.config_path).unwrap()).unwrap();
        assert_eq!(
            raw,
            json!({"email": "a@b.com", "base_url": "https://vault.local", "pinentry": "/usr/bin/pinentry"})
        );
        assert_eq!(std::fs::metadata(&ctx.config_path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn config_usage_errors_exit_2() {
        let dir = TestDir::new("cli-config-bad");
        let ctx = offline_ctx(&dir, &NoMaster);
        for bad in [
            &["config"][..],
            &["config", "get", "email"],
            &["config", "set"],
            &["config", "set", "email"],
            &["config", "set", "bogus", "x"],
        ] {
            let (code, out, err) = run(&ctx, bad);
            assert_eq!((code, out.as_str()), (2, ""), "{bad:?}");
            assert!(err.starts_with("litebw config"), "{err}");
        }
        assert!(!ctx.config_path.exists());
    }

    #[test]
    fn unlock_help_and_unknown_commands() {
        let dir = TestDir::new("cli-misc");
        let ctx = offline_ctx(&dir, &NoMaster);
        assert_eq!(run(&ctx, &["unlock"]), (0, String::new(), String::new()));
        assert_eq!(run(&ctx, &["unlocked"]), (0, String::new(), String::new()));
        for help in [&[][..], &["--help"], &["-h"], &["help"]] {
            let (code, out, err) = run(&ctx, help);
            assert_eq!((code, err.as_str()), (0, ""));
            assert!(out.starts_with("litebw — lightweight Vaultwarden client"));
        }
        let (code, out, err) = run(&ctx, &["frobnicate"]);
        assert_eq!((code, out.as_str()), (2, ""));
        assert!(err.starts_with("litebw: unknown command 'frobnicate'\nlitebw — "));
        let (_, _, err) = run(&ctx, &["evil\x1b[2J\ncommand"]);
        assert!(!err.contains('\x1b') && err.starts_with("litebw: unknown command 'evil[2Jcommand'"));
    }
}
