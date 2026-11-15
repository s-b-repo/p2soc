//! An Assuan pinentry that answers with the vault master password.
//!
//! This is what lets a pinentry-driven vault client (rbw) unlock with no
//! plaintext master anywhere on disk: it is pointed at
//! `soc-wall pinentry` instead of a prompting pinentry, and `GETPIN` is
//! answered from the configured master source — the host-bound seal in
//! production.

use crate::master::MasterResolver;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use zeroize::Zeroizing;

/// Assuan caps a line at 1000 bytes; anything longer is not a command.
const MAX_LINE: u64 = 4096;
/// GPG_ERR_CANCELED from the pinentry source: what a real pinentry answers
/// when the user dismisses the prompt.
const ERR_CANCELLED: &str = "ERR 83886179 Operation cancelled <Pinentry>\n";

/// Percent-escape the three bytes Assuan cannot carry in a data line.
fn data_line(secret: &str) -> Zeroizing<Vec<u8>> {
    // Sized for the worst case up front, so the secret is never left behind
    // by a reallocation.
    let mut line = Zeroizing::new(Vec::with_capacity(2 + secret.len() * 3 + 1));
    line.extend_from_slice(b"D ");
    for &byte in secret.as_bytes() {
        match byte {
            b'%' => line.extend_from_slice(b"%25"),
            b'\n' => line.extend_from_slice(b"%0A"),
            b'\r' => line.extend_from_slice(b"%0D"),
            other => line.push(other),
        }
    }
    line.push(b'\n');
    line
}

/// Speak the pinentry side of the Assuan protocol on `input`/`output` until
/// `BYE` or end of input. `master` is asked at most once, on the first
/// `GETPIN`.
///
/// With no master to give, `GETPIN` is answered with a cancellation, not with
/// empty data: an empty answer would make the client try to log in with an
/// empty password — a failed login against the vault on every retry — and
/// then fail with an error that says nothing about why.
pub fn serve(
    input: impl Read,
    mut output: impl Write,
    master: impl FnOnce() -> Option<Zeroizing<String>>,
) -> io::Result<()> {
    let mut input = BufReader::new(input);
    let mut master = Some(master);
    let mut secret: Option<Zeroizing<String>> = None;
    output.write_all(b"OK Pleased to meet you\n")?;
    output.flush()?;
    let mut line = Vec::new();
    loop {
        line.clear();
        if (&mut input).take(MAX_LINE).read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&line);
        let command = text.trim().split(' ').next().unwrap_or("").to_ascii_uppercase();
        match command.as_str() {
            "GETPIN" => {
                if let Some(resolve) = master.take() {
                    secret = resolve().filter(|s| !s.is_empty());
                }
                match &secret {
                    Some(secret) => {
                        output.write_all(&data_line(secret))?;
                        output.write_all(b"OK\n")?;
                    }
                    None => output.write_all(ERR_CANCELLED.as_bytes())?,
                }
            }
            "BYE" => {
                output.write_all(b"OK\n")?;
                output.flush()?;
                return Ok(());
            }
            _ => output.write_all(b"OK\n")?,
        }
        output.flush()?;
    }
}

/// The process's stdout without Rust's buffering layer, so a secret written
/// to it is not also parked in a long-lived buffer.
pub(crate) fn raw_stdout() -> io::Result<File> {
    Ok(File::from(io::stdout().as_fd().try_clone_to_owned()?))
}

/// The `pinentry` subcommand: serve stdin/stdout from the master source the
/// environment configures. Returns the process exit code.
pub fn run() -> i32 {
    let resolve = || {
        // An unknown SOC_MASTER_SOURCE yields NO master. It must not fall back
        // to $SOC_VAULT_PASSWORD: that would hand a sealed production box a
        // weaker source than the one it was told to use.
        match MasterResolver::from_env() {
            Ok(resolver) => {
                let master = resolver.get_master();
                if master.is_none() {
                    // The client forwards our stderr to the journal; say why.
                    eprintln!(
                        "pinentry-vault: no usable master (secret dir {}) — the vault cannot be unlocked. \
                         If this box is new or was re-imaged, run first-run setup to seal the master \
                         password host-bound.",
                        resolver.store().dir().display()
                    );
                }
                master
            }
            Err(e) => {
                eprintln!("pinentry-vault: {e}");
                None
            }
        }
    };
    let served = raw_stdout().and_then(|stdout| serve(io::stdin().lock(), stdout, resolve));
    match served {
        Ok(()) => 0,
        // The client hanging up mid-conversation is how sessions often end.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
        Err(e) => {
            eprintln!("pinentry-vault: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsio::testdir::TestDir;
    use crate::master::MasterSource;
    use crate::store::SecretStore;
    use std::cell::Cell;

    fn talk(script: &str, master: Option<&str>) -> (String, usize) {
        let asked = Cell::new(0);
        let mut out = Vec::new();
        serve(script.as_bytes(), &mut out, || {
            asked.set(asked.get() + 1);
            master.map(|m| Zeroizing::new(m.to_string()))
        })
        .unwrap();
        (String::from_utf8(out).unwrap(), asked.get())
    }

    #[test]
    fn answers_getpin_with_the_master() {
        let (out, asked) = talk("OPTION ttyname=/dev/tty1\nSETDESC Master password\nGETPIN\nBYE\n", Some("Master-PW!"));
        assert_eq!(out, "OK Pleased to meet you\nOK\nOK\nD Master-PW!\nOK\nOK\n");
        assert_eq!(asked, 1);
    }

    #[test]
    fn resolves_once_however_often_it_is_asked() {
        let (out, asked) = talk("getpin\nGetPin extra\n  GETPIN  \n", Some("m"));
        assert_eq!(out.matches("D m\nOK\n").count(), 3);
        assert_eq!(asked, 1);
        let (_, asked) = talk("SETDESC x\nBYE\n", Some("m"));
        assert_eq!(asked, 0, "never unseals unless asked for the PIN");
    }

    #[test]
    fn escapes_what_assuan_cannot_carry() {
        let (out, _) = talk("GETPIN\n", Some("100%\nsure\r ok"));
        assert!(out.contains("D 100%25%0Asure%0D ok\nOK\n"), "{out:?}");
    }

    #[test]
    fn no_master_is_a_cancellation_not_an_empty_password() {
        for none in [None, Some("")] {
            let (out, asked) = talk("GETPIN\nGETPIN\nBYE\n", none);
            assert_eq!(out, format!("OK Pleased to meet you\n{ERR_CANCELLED}{ERR_CANCELLED}OK\n"));
            assert!(!out.contains("D "));
            assert_eq!(asked, 1);
        }
    }

    #[test]
    fn stops_at_bye_and_at_end_of_input() {
        let (out, asked) = talk("BYE\nGETPIN\n", Some("m"));
        assert_eq!(out, "OK Pleased to meet you\nOK\n");
        assert_eq!(asked, 0);
        assert_eq!(talk("", Some("m")).0, "OK Pleased to meet you\n");
        assert_eq!(talk("NOP", Some("m")).0, "OK Pleased to meet you\nOK\n");
    }

    #[test]
    fn overlong_and_binary_lines_are_survived() {
        let mut script = vec![b'x'; 10_000];
        script.extend_from_slice(b"\n\xff\xfe\nGETPIN\n");
        let mut out = Vec::new();
        serve(&script[..], &mut out, || Some(Zeroizing::new("m".into()))).unwrap();
        assert!(String::from_utf8(out).unwrap().ends_with("D m\nOK\n"));
    }

    #[test]
    fn a_sealed_wall_answers_from_the_seal_and_ignores_the_env_password() {
        let d = TestDir::new("pinentry");
        let store = SecretStore::for_unit_tests(d.path());
        let resolver = |store: SecretStore| {
            MasterResolver::new(store).with_env_password(Some(Zeroizing::new("ENV-master".to_string())))
        };
        // Dev / seeding: with nothing sealed, the env master is the fallback.
        let mut out = Vec::new();
        serve(&b"GETPIN\n"[..], &mut out, || resolver(store.clone()).get_master()).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("D ENV-master\n"));

        store.seal("SEALED-master", "12345678").unwrap();
        let mut out = Vec::new();
        serve(&b"GETPIN\n"[..], &mut out, || resolver(store.clone()).get_master()).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("D SEALED-master\n"));

        // A seal that does not open is a cancellation, never the env master.
        let wrong_host = resolver(store.with_machine_id("host-B")).with_source(MasterSource::Auto);
        let mut out = Vec::new();
        serve(&b"GETPIN\n"[..], &mut out, || wrong_host.get_master()).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("ERR ") && !out.contains("ENV-master"), "{out}");
    }
}
