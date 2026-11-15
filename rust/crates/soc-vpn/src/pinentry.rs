//! The pinentry helper openfortivpn runs (`--pinentry=<program>`).
//!
//! openfortivpn executes the program with no arguments and speaks the Assuan
//! pinentry protocol over its stdin/stdout: `SETTITLE`, `SETDESC`,
//! `SETKEYINFO <hint>`, `SETPROMPT`, then `GETPIN`. The secrets arrive in our
//! environment — exported by the supervisor into the openfortivpn child only —
//! so they never appear on a command line and never touch disk.
//!
//! The `SETKEYINFO` hint says what is being asked for
//! (`<user>_<realm>_<host>_password`, `…_otp`, `…_2fa`). A token request is
//! answered with the one-time code or refused — never with the account
//! password, which a FortiGate would forward to its token backend.

use std::io::{BufRead, Write};
use std::os::unix::ffi::OsStringExt;
use zeroize::Zeroizing;

/// File name of the helper. The main binary may be installed (symlinked)
/// under this name and dispatch on it with [`is_pinentry_argv0`].
pub const PINENTRY_NAME: &str = "soc-vpn-pinentry";

/// Environment variable carrying the account password.
pub const PASSWORD_ENV: &str = "SOC_VPN_PASSWORD";
/// Environment variable carrying the one-time code.
pub const OTP_ENV: &str = "SOC_VPN_OTP";

/// Assuan "no data" as openfortivpn's own pinentry callers expect it
/// (`GPG_ERR_SOURCE_PINENTRY | GPG_ERR_CANCELED`).
const ERR_NO_SECRET: &str = "ERR 83886179";

/// Whether the process was started as the pinentry helper.
pub fn is_pinentry_argv0(argv0: &str) -> bool {
    argv0.rsplit('/').next() == Some(PINENTRY_NAME)
}

/// Whether a `SETKEYINFO` hint asks for a one-time token rather than the
/// account password.
fn wants_token(keyinfo: &str) -> bool {
    let hint = keyinfo.trim().to_ascii_lowercase();
    ["otp", "2fa"].iter().any(|kind| hint == *kind || hint.ends_with(&format!("_{kind}")))
}

/// Percent-escape a secret for an Assuan `D` line.
fn assuan_escape(secret: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(secret.len() + 8));
    for &byte in secret {
        match byte {
            b'%' => out.extend_from_slice(b"%25"),
            b'\n' => out.extend_from_slice(b"%0A"),
            b'\r' => out.extend_from_slice(b"%0D"),
            other => out.push(other),
        }
    }
    out
}

/// Run the protocol over `input`/`output`. Returns the process exit code.
///
/// An empty or missing secret is refused with an Assuan error, so
/// openfortivpn aborts instead of submitting a blank password: rapid blank
/// logins can lock the account.
pub fn serve(input: &mut dyn BufRead, output: &mut dyn Write, password: Option<&[u8]>, otp: Option<&[u8]>) -> i32 {
    fn run(
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        password: Option<&[u8]>,
        otp: Option<&[u8]>,
    ) -> std::io::Result<()> {
        output.write_all(b"OK Pleased to meet you\n")?;
        output.flush()?;
        let mut token = false;
        let mut line = Vec::new();
        loop {
            line.clear();
            if input.read_until(b'\n', &mut line)? == 0 {
                return Ok(());
            }
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end_matches(['\r', '\n']);
            if text.starts_with("GETPIN") {
                let secret = if token { otp } else { password };
                match secret.filter(|s| !s.is_empty()) {
                    Some(secret) => {
                        output.write_all(b"D ")?;
                        output.write_all(&assuan_escape(secret))?;
                        output.write_all(b"\nOK\n")?;
                    }
                    None if token => writeln!(output, "{ERR_NO_SECRET} No one-time code available")?,
                    None => writeln!(output, "{ERR_NO_SECRET} No password available")?,
                }
            } else if text.starts_with("BYE") {
                output.write_all(b"OK\n")?;
                output.flush()?;
                return Ok(());
            } else {
                if let Some(hint) = text.strip_prefix("SETKEYINFO") {
                    token = wants_token(hint);
                }
                output.write_all(b"OK\n")?;
            }
            output.flush()?;
        }
    }
    // The I/O error is dropped on purpose: it must stay opaque next to secret material.
    run(input, output, password, otp).map_or(1, |()| 0)
}

fn env_secret(name: &str) -> Option<Zeroizing<Vec<u8>>> {
    std::env::var_os(name).map(|v| Zeroizing::new(v.into_vec()))
}

/// The helper's entry point: stdin/stdout and the secrets from the
/// environment. Takes no arguments because openfortivpn passes none.
pub fn pinentry_main() -> i32 {
    let password = env_secret(PASSWORD_ENV);
    let otp = env_secret(OTP_ENV);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(
        &mut stdin.lock(),
        &mut stdout.lock(),
        password.as_ref().map(|p| p.as_slice()),
        otp.as_ref().map(|o| o.as_slice()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str, password: Option<&str>, otp: Option<&str>) -> String {
        let mut out = Vec::new();
        let rc = serve(&mut input.as_bytes(), &mut out, password.map(str::as_bytes), otp.map(str::as_bytes));
        assert_eq!(rc, 0);
        String::from_utf8(out).unwrap()
    }

    const PASSWORD_ASK: &str = "SETTITLE VPN Password\nSETDESC VPN Requires a Password\nSETKEYINFO alice_staff_gw.example_password\nSETPROMPT VPN account password: \nGETPIN\nBYE\n";

    #[test]
    fn answers_the_openfortivpn_exchange() {
        assert_eq!(
            run(PASSWORD_ASK, Some("s3cret"), None),
            "OK Pleased to meet you\nOK\nOK\nOK\nOK\nD s3cret\nOK\nOK\n"
        );
    }

    #[test]
    fn escapes_what_assuan_would_misread() {
        assert!(run("GETPIN\nBYE\n", Some("a%b"), None).contains("D a%25b\n"));
        assert!(run("GETPIN\n", Some("a\nb\rc"), None).contains("D a%0Ab%0Dc\n"));
    }

    #[test]
    fn refuses_to_submit_a_blank_password() {
        for password in [None, Some("")] {
            let out = run("GETPIN\nBYE\n", password, None);
            assert!(out.contains("ERR 83886179 "), "{out}");
            assert!(!out.contains("\nD "), "{out}");
        }
    }

    #[test]
    fn a_token_request_never_gets_the_password() {
        for hint in ["alice_staff_gw.example_otp", "alice__gw.example_2fa", "otp", "2FA"] {
            let ask = format!("SETKEYINFO {hint}\nGETPIN\nBYE\n");
            let out = run(&ask, Some("s3cret"), None);
            assert!(!out.contains("s3cret"), "{hint}: {out}");
            assert!(out.contains("ERR 83886179 No one-time code available"), "{hint}: {out}");
            assert!(run(&ask, Some("s3cret"), Some("123456")).contains("D 123456\nOK\n"), "{hint}");
        }
    }

    #[test]
    fn a_password_request_never_gets_the_token() {
        let out = run(PASSWORD_ASK, Some("s3cret"), Some("123456"));
        assert!(out.contains("D s3cret\n") && !out.contains("123456"));
        // A user literally named "…otp" does not turn a password hint into a token hint.
        let out = run("SETKEYINFO robotp_r_h_password\nGETPIN\n", Some("s3cret"), Some("123456"));
        assert!(out.contains("D s3cret\n"));
    }

    #[test]
    fn password_then_token_in_one_session() {
        let out =
            run("SETKEYINFO u_r_h_password\nGETPIN\nSETKEYINFO u_r_h_otp\nGETPIN\nBYE\n", Some("pw"), Some("654321"));
        assert_eq!(out, "OK Pleased to meet you\nOK\nD pw\nOK\nOK\nD 654321\nOK\nOK\n");
    }

    #[test]
    fn end_of_input_without_bye_is_a_clean_exit() {
        assert_eq!(run("SETTITLE x\n", Some("pw"), None), "OK Pleased to meet you\nOK\n");
        assert_eq!(run("", None, None), "OK Pleased to meet you\n");
    }

    #[test]
    fn non_utf8_passwords_pass_through_untouched() {
        let mut out = Vec::new();
        serve(&mut "GETPIN\n".as_bytes(), &mut out, Some(&[0xff, b'%', 0xfe]), None);
        assert!(out.windows(7).any(|w| w == [b'D', b' ', 0xff, b'%', b'2', b'5', 0xfe]));
    }

    #[test]
    fn argv0_dispatch() {
        assert!(is_pinentry_argv0("soc-vpn-pinentry"));
        assert!(is_pinentry_argv0("/usr/lib/soc-display/soc-vpn-pinentry"));
        assert!(!is_pinentry_argv0("soc-wall"));
        assert!(!is_pinentry_argv0("/x/soc-vpn-pinentry-old"));
    }
}
