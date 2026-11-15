//! This host's machine-id: what binds a seal to one physical box.
//!
//! It is NOT a secret (0644 on systemd hosts); the 0600 `host.key` is. It only
//! makes sealed files useless when copied to another machine.

use crate::error::{Result, SealError};
use std::path::Path;

const SOURCES: [&str; 2] = ["/etc/machine-id", "/var/lib/dbus/machine-id"];

/// Strip what Python's `str.strip()` strips. The trimmed bytes are KDF input,
/// so the set has to match exactly: Unicode whitespace plus the four ASCII
/// separators U+001C..U+001F that Rust's `char::is_whitespace` leaves out.
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Resolve the machine-id from an explicit override (`$SOC_MACHINE_ID`, used
/// to simulate other hosts) or the first non-empty file in `files`.
pub(crate) fn resolve(over: Option<&str>, files: &[&Path]) -> Result<Vec<u8>> {
    // A blank override falls through to the real id instead of binding the
    // seal to the empty string.
    if let Some(id) = over.map(py_strip).filter(|id| !id.is_empty()) {
        return Ok(id.as_bytes().to_vec());
    }
    for path in files {
        // Unreadable or non-text: try the next source rather than failing the
        // boot on the first.
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        let id = py_strip(&text);
        if !id.is_empty() {
            return Ok(id.as_bytes().to_vec());
        }
    }
    Err(SealError::NoMachineId)
}

/// The machine-id of this host, honouring `over` first.
pub(crate) fn machine_id(over: Option<&str>) -> Result<Vec<u8>> {
    let files: Vec<&Path> = SOURCES.iter().map(Path::new).collect();
    resolve(over, &files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsio::testdir::TestDir;

    #[test]
    fn override_wins_and_is_trimmed() {
        assert_eq!(resolve(Some("  host-A\n"), &[]).unwrap(), b"host-A");
    }

    #[test]
    fn blank_override_is_not_an_empty_binding() {
        assert!(matches!(resolve(Some(" \n"), &[]), Err(SealError::NoMachineId)));
    }

    #[test]
    fn first_non_empty_file_wins() {
        let d = TestDir::new("mid");
        std::fs::write(d.join("empty"), "\n").unwrap();
        std::fs::write(d.join("binary"), [0xff, 0xfe, 0x00]).unwrap();
        std::fs::write(d.join("real"), "0123abcd\n").unwrap();
        let (absent, empty, binary, real) = (d.join("absent"), d.join("empty"), d.join("binary"), d.join("real"));
        assert_eq!(resolve(None, &[&absent, &empty, &binary, &real]).unwrap(), b"0123abcd");
        assert!(matches!(resolve(None, &[&absent, &empty, &binary]), Err(SealError::NoMachineId)));
    }

    #[test]
    fn strips_exactly_what_python_strips() {
        assert_eq!(py_strip("\u{1c}\u{1f} id\u{a0}\t"), "id");
        assert_eq!(py_strip("a b"), "a b");
    }
}
