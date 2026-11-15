//! Helpers behind the binary's sealing subcommands.
//!
//! `seal` is run through pkexec so the GUI/TTY wizard can RE-SEAL the master
//! into a root-owned secret dir without being root itself. The master and PIN
//! arrive over STDIN — never argv — so they never appear on the process
//! table, and nothing plaintext is ever written: they go straight into the
//! seal. The PIN actually used is printed to stdout so the caller can show
//! the operator their one-time PIN.
//!
//! ```text
//! printf '%s' '---MASTER---\n<master>\n---PIN---\n<pin>' | pkexec soc-wall seal --dir /etc/soc-display/secret
//! ```
//!
//! (`<pin>` may be empty: a fresh PIN is generated.)

use crate::pin::{DEFAULT_PIN_DIGITS, gen_pin};
use crate::pinentry::raw_stdout;
use crate::proc::read_capped;
use crate::secret_tool::{Keyring, SecretTool};
use crate::store::SecretStore;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

const MASTER_MARK: &[u8] = b"---MASTER---\n";
const PIN_MARK: &[u8] = b"\n---PIN---\n";
/// Far more than any master + PIN.
const MAX_INPUT: usize = 64 * 1024;

/// Exit code: sealed (or stored) fine.
pub const EXIT_OK: i32 = 0;
/// Exit code: the input was well-formed but the operation failed.
pub const EXIT_FAILED: i32 = 1;
/// Exit code: malformed input; nothing was touched.
pub const EXIT_USAGE: i32 = 2;

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Split `---MASTER---\n<master>\n---PIN---\n<pin>` into its two fields.
///
/// The PIN marker is searched from the END: a PIN is one line, so the last
/// marker is the real one even if the master itself contains the marker text.
/// One trailing line ending on the PIN is dropped (`echo` adds one; sealed
/// verbatim it would make a PIN nobody can type).
fn parse(input: &[u8]) -> Result<(&str, &str), &'static str> {
    const MALFORMED: &str = "malformed STDIN (want ---MASTER---/---PIN--- markers)";
    let body = input.strip_prefix(MASTER_MARK).ok_or(MALFORMED)?;
    let split = rfind(body, PIN_MARK).ok_or(MALFORMED)?;
    let (master, pin) = (body.get(..split).ok_or(MALFORMED)?, body.get(split + PIN_MARK.len()..).ok_or(MALFORMED)?);
    let pin = pin.strip_suffix(b"\n").map_or(pin, |p| p.strip_suffix(b"\r").unwrap_or(p));
    let master = std::str::from_utf8(master).map_err(|_| "the master is not valid UTF-8 text")?; // audit-allow: Utf8Error carries a byte offset into the secret; deliberately not surfaced
    let pin = std::str::from_utf8(pin).map_err(|_| "the PIN is not valid UTF-8 text")?; // audit-allow: Utf8Error carries a byte offset into the secret; deliberately not surfaced
    if master.is_empty() {
        return Err("empty master — nothing sealed");
    }
    if pin.chars().any(char::is_control) {
        return Err("the PIN must be a single line of printable characters");
    }
    Ok((master, pin))
}

/// Read the marker-framed master + PIN from `input`, seal them into `store`
/// and print the PIN that was used (given or generated) to `out`.
///
/// [`SecretStore::seal`] proves the new seal opens — with keys derived afresh
/// on this host — before it replaces anything, so success here means the wall
/// can unseal it and failure leaves the previous seal in place.
pub fn seal_from_reader(store: &SecretStore, input: impl Read, mut out: impl Write, mut err: impl Write) -> i32 {
    let mut fail = |code: i32, why: &dyn std::fmt::Display| {
        let _ = writeln!(err, "seal: {why}"); // audit-allow: best-effort diagnostics; the exit code carries the result
        code
    };
    let Some(data) = read_capped(input, MAX_INPUT) else {
        return fail(EXIT_USAGE, &"input too large");
    };
    let (master, pin) = match parse(&data) {
        Ok(fields) => fields,
        Err(why) => return fail(EXIT_USAGE, &why),
    };
    let generated;
    let pin = if pin.is_empty() {
        generated = match gen_pin(DEFAULT_PIN_DIGITS) {
            Ok(pin) => pin,
            Err(e) => return fail(EXIT_FAILED, &e),
        };
        generated.as_str()
    } else {
        pin
    };
    if let Err(e) = store.seal(master, pin) {
        return fail(EXIT_FAILED, &e);
    }
    // The one-time PIN, for the caller to surface. One write, so it is never
    // split across a buffer boundary.
    let mut line = Zeroizing::new(Vec::with_capacity(pin.len() + 1));
    line.extend_from_slice(pin.as_bytes());
    line.push(b'\n');
    match out.write_all(&line).and_then(|()| out.flush()) {
        Ok(()) => EXIT_OK,
        Err(e) => fail(EXIT_FAILED, &format_args!("sealed, but the PIN could not be reported: {e}")),
    }
}

/// The `seal [--dir DIR]` subcommand over the real stdin/stdout/stderr.
/// `dir` overrides `$SOC_SECRET_DIR`.
pub fn seal_from_stdin(dir: Option<PathBuf>) -> i32 {
    let store = SecretStore::from_env_in(dir);
    match raw_stdout() {
        Ok(stdout) => seal_from_reader(&store, io::stdin().lock(), stdout, io::stderr()),
        Err(e) => {
            eprintln!("seal: {e}");
            EXIT_FAILED
        }
    }
}

/// Store the master read from `input` (one trailing newline dropped) in the
/// login keyring, for `SOC_SECRET_BACKEND=libsecret`.
pub fn keyring_store_from_reader(keyring: &Keyring, input: impl Read, mut err: impl Write) -> i32 {
    let Some(mut data) = read_capped(input, MAX_INPUT) else {
        let _ = writeln!(err, "keyring-store: input too large"); // audit-allow: best-effort diagnostics; the exit code carries the result
        return EXIT_USAGE;
    };
    if data.last() == Some(&b'\n') {
        data.pop();
    }
    let decoded = std::str::from_utf8(&data).ok(); // audit-allow: Utf8Error leaks an offset into the secret
    let master = match decoded {
        Some(master) if !master.is_empty() => master,
        Some(_) => {
            let _ = writeln!(err, "keyring-store: empty master — nothing stored"); // audit-allow: best-effort diagnostics; the exit code carries the result
            return EXIT_USAGE;
        }
        None => {
            let _ = writeln!(err, "keyring-store: the master is not valid UTF-8 text"); // audit-allow: best-effort diagnostics; the exit code carries the result
            return EXIT_USAGE;
        }
    };
    match keyring.store(master) {
        Ok(()) => EXIT_OK,
        Err(e) => {
            let _ = writeln!(err, "keyring-store: {e}"); // audit-allow: best-effort diagnostics; the exit code carries the result
            EXIT_FAILED
        }
    }
}

/// The `keyring-store` subcommand: master on STDIN, never argv.
pub fn keyring_store_from_stdin() -> i32 {
    keyring_store_from_reader(&Keyring::new(SecretTool::locate()), io::stdin().lock(), io::stderr())
}

/// The `keyring-clear` subcommand: remove the master from the login keyring.
pub fn keyring_clear() -> i32 {
    match Keyring::new(SecretTool::locate()).clear() {
        Ok(()) => EXIT_OK,
        Err(e) => {
            eprintln!("keyring-clear: {e}");
            EXIT_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsio::testdir::TestDir;
    use crate::secret_tool::testutil::fake_secret_tool;
    use std::path::Path;

    fn run(dir: &Path, stdin: &str) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = seal_from_reader(&SecretStore::for_unit_tests(dir), stdin.as_bytes(), &mut out, &mut err);
        (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    fn no_plaintext_anywhere(dir: &Path, secret: &str) -> bool {
        std::fs::read_dir(dir).unwrap().all(|entry| {
            let data = std::fs::read(entry.unwrap().path()).unwrap();
            !data.windows(secret.len()).any(|w| w == secret.as_bytes())
        })
    }

    #[test]
    fn round_trips_and_hides_the_plaintext() {
        let d = TestDir::new("cli");
        let sd = d.join("secret");
        let (master, pin) = ("Tr0ub4dor-&-3", "204617");
        let (code, out, err) = run(&sd, &format!("---MASTER---\n{master}\n---PIN---\n{pin}"));
        assert_eq!((code, err.as_str()), (EXIT_OK, ""));
        assert_eq!(out, "204617\n", "the one-time PIN is echoed for the caller");
        let store = SecretStore::for_unit_tests(&sd);
        assert!(store.is_sealed());
        assert_eq!(store.unseal().unwrap().as_str(), master);
        assert!(store.verify_pin(pin));
        assert!(no_plaintext_anywhere(&sd, master));
    }

    #[test]
    fn generates_a_pin_when_none_is_given() {
        let d = TestDir::new("cli-gen");
        let (code, out, _) = run(d.path(), "---MASTER---\nanother-master\n---PIN---\n");
        assert_eq!(code, EXIT_OK);
        let pin = out.trim_end_matches('\n');
        assert_eq!(pin.len(), DEFAULT_PIN_DIGITS);
        assert!(pin.bytes().all(|b| b.is_ascii_digit()));
        let store = SecretStore::for_unit_tests(d.path());
        assert_eq!(store.unseal().unwrap().as_str(), "another-master");
        assert!(store.verify_pin(pin));
    }

    #[test]
    fn refuses_malformed_input_without_touching_the_disk() {
        let d = TestDir::new("cli-bad");
        let sd = d.join("secret");
        for bad in ["no markers here", "", "---MASTER---\nm", "x---MASTER---\nm\n---PIN---\n123456"] {
            let (code, out, err) = run(&sd, bad);
            assert_eq!((code, out.as_str()), (EXIT_USAGE, ""), "{bad:?}");
            assert!(err.contains("malformed STDIN"));
        }
        assert!(!sd.exists(), "nothing sealed on malformed input");
    }

    #[test]
    fn refuses_an_empty_master_and_a_short_pin() {
        let d = TestDir::new("cli-empty");
        let (code, _, err) = run(d.path(), "---MASTER---\n\n---PIN---\n123456");
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("empty master"));
        let (code, out, err) = run(d.path(), "---MASTER---\nmaster\n---PIN---\n1234");
        assert_eq!((code, out.as_str()), (EXIT_FAILED, ""));
        assert!(err.contains("PIN too short"));
        assert!(!SecretStore::for_unit_tests(d.path()).is_sealed());
    }

    #[test]
    fn a_trailing_newline_is_not_part_of_the_pin() {
        // `echo` instead of `printf %s`: sealing "204617\n" would leave the
        // operator with a PIN that never verifies.
        for ending in ["\n", "\r\n"] {
            let d = TestDir::new("cli-nl");
            let (code, out, _) = run(d.path(), &format!("---MASTER---\nm\n---PIN---\n204617{ending}"));
            assert_eq!((code, out.as_str()), (EXIT_OK, "204617\n"));
            assert!(SecretStore::for_unit_tests(d.path()).verify_pin("204617"));
        }
        let d = TestDir::new("cli-ctl");
        let (code, _, err) = run(d.path(), "---MASTER---\nm\n---PIN---\n2046\n17");
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("single line"));
    }

    #[test]
    fn a_master_containing_the_marker_is_sealed_whole() {
        let d = TestDir::new("cli-marker");
        let master = "line one\n---PIN---\nline three";
        let (code, out, _) = run(d.path(), &format!("---MASTER---\n{master}\n---PIN---\n204617"));
        assert_eq!((code, out.as_str()), (EXIT_OK, "204617\n"));
        assert_eq!(SecretStore::for_unit_tests(d.path()).unseal().unwrap().as_str(), master);
    }

    #[test]
    fn errors_never_echo_the_master_or_pin() {
        let d = TestDir::new("cli-leak");
        let (_, out, err) = run(d.path(), "---MASTER---\nSuperSecretMaster\n---PIN---\n9a\u{7}");
        assert!(!format!("{out}{err}").contains("SuperSecretMaster") && !err.contains("9a"));
        let (_, out, err) = run(d.path(), "---MASTER---\nSuperSecretMaster\n---PIN---\n987");
        assert!(!format!("{out}{err}").contains("SuperSecretMaster") && !err.contains("987"));
    }

    #[test]
    fn oversized_and_non_text_input_is_refused() {
        let d = TestDir::new("cli-big");
        let huge = format!("---MASTER---\n{}\n---PIN---\n123456", "x".repeat(MAX_INPUT));
        assert_eq!(run(d.path(), &huge).0, EXIT_USAGE);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let binary = b"---MASTER---\n\xff\xfe\n---PIN---\n123456";
        let code = seal_from_reader(&SecretStore::for_unit_tests(d.path()), &binary[..], &mut out, &mut err);
        assert_eq!(code, EXIT_USAGE);
        assert!(std::fs::read_dir(d.path()).unwrap().next().is_none());
    }

    #[test]
    fn keyring_store_reads_stdin_and_strips_one_newline() {
        let d = TestDir::new("cli-keyring");
        let keyring = Keyring::new(SecretTool::at(fake_secret_tool(d.path())));
        let mut err = Vec::new();
        assert_eq!(keyring_store_from_reader(&keyring, &b"kr-master\n"[..], &mut err), EXIT_OK);
        let rec = std::fs::read_to_string(d.join("rec")).unwrap();
        assert!(rec.ends_with("\tkr-master\n"), "{rec:?}");
        assert_eq!(keyring_store_from_reader(&keyring, &b"\n"[..], &mut err), EXIT_USAGE);
        assert!(String::from_utf8(err).unwrap().contains("empty master"));
        let absent = Keyring::new(SecretTool::absent());
        assert_eq!(keyring_store_from_reader(&absent, &b"m"[..], &mut Vec::new()), EXIT_FAILED);
    }
}
