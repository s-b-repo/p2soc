//! OpenVPN management-socket credential injection.
//!
//! openvpn is started with `--management <sock> unix
//! --management-query-passwords --management-hold`: it waits, held, until we
//! connect, release the hold and answer its password query. The login thus
//! never appears on argv or disk.
//!
//! The session is deliberately strict about what it will do twice. openvpn
//! re-enters the hold and re-asks for the password whenever it restarts by
//! itself; answering again would resend a rejected password with no pause —
//! exactly the rapid retry that locks an account — and ignoring the hold
//! would leave openvpn waiting forever. Both end the session instead, and the
//! supervisor reconnects on its own (classified) schedule.

use crate::proc::LineSplitter;
use soc_core::Login;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use zeroize::Zeroizing;

/// Strip CR, LF and NUL before anything reaches the socket. The protocol is
/// line-oriented, so a vault value holding a newline would otherwise inject
/// management commands (`signal SIGTERM`, …) onto the control channel.
pub fn sanitize(value: &str) -> String {
    value.chars().filter(|c| !matches!(c, '\r' | '\n' | '\0')).collect()
}

/// Quote a value as one management-interface parameter. Unquoted, openvpn's
/// lexer splits at whitespace and reinterprets quotes and backslashes, so a
/// password containing a space would be silently truncated — and then sent,
/// wrong, to the server.
pub fn quote(value: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(value.len() + 2));
    out.push('"');
    for c in sanitize(value).chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// The two lines answering `>PASSWORD:Need 'Auth' username/password`.
pub fn credential_lines(login: &Login) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "username \"Auth\" {}\npassword \"Auth\" {}\n",
        quote(&login.username).as_str(),
        quote(&login.password).as_str()
    ))
}

/// What to do about one line from openvpn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Nothing,
    /// Send the username and password.
    Credentials,
    /// The server rejected the login.
    AuthFailed,
    /// openvpn restarted by itself and is waiting to be released again.
    Restarted,
}

/// Protocol state for one openvpn process.
#[derive(Debug, Default)]
pub struct Session {
    answered: bool,
    holds: u32,
}

impl Session {
    pub fn on_line(&mut self, line: &str) -> Reply {
        if line.contains("Verification Failed") {
            return Reply::AuthFailed;
        }
        if line.starts_with(">PASSWORD:Need 'Auth'") {
            if self.answered {
                return Reply::Restarted;
            }
            self.answered = true;
            return Reply::Credentials;
        }
        if line.starts_with(">HOLD:") {
            // The first hold is the one we release on connecting.
            self.holds += 1;
            if self.holds > 1 {
                return Reply::Restarted;
            }
        }
        Reply::Nothing
    }
}

/// How a management session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// openvpn closed the socket (it exited).
    Closed,
    AuthFailed,
    Restarted,
    /// We were told to stand down.
    Cancelled,
}

const READ_POLL: Duration = Duration::from_millis(300);

/// Serve one openvpn over its management socket until it closes, the login is
/// rejected, openvpn restarts itself, or `cancelled` turns true. Nothing read
/// from or written to the socket is ever logged.
pub fn serve(stream: &UnixStream, login: &Login, cancelled: &dyn Fn() -> bool) -> End {
    if stream.set_read_timeout(Some(READ_POLL)).is_err()
        || stream.set_write_timeout(Some(Duration::from_secs(5))).is_err()
    {
        // Without the poll timeout a read could block past cancellation.
        return End::Closed;
    }
    let mut stream = stream;
    if stream.write_all(b"hold release\n").is_err() {
        return End::Closed;
    }
    let mut session = Session::default();
    let mut lines = LineSplitter::default();
    let mut buf = [0u8; 4096];
    loop {
        if cancelled() {
            return End::Cancelled;
        }
        match stream.read(&mut buf) {
            Ok(0) => return End::Closed,
            Ok(n) => {
                if let Some(chunk) = buf.get(..n) {
                    lines.push(chunk);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return End::Closed, // audit-allow: opaque, socket traffic carries the login and is never reported
        }
        while let Some(raw) = lines.pop() {
            match session.on_line(String::from_utf8_lossy(&raw).trim()) {
                Reply::Nothing => {}
                Reply::Credentials => {
                    if stream.write_all(credential_lines(login).as_bytes()).is_err() {
                        return End::Closed;
                    }
                }
                Reply::AuthFailed => return End::AuthFailed,
                Reply::Restarted => return End::Restarted,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempDir;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    #[test]
    fn sanitize_strips_line_breaks() {
        assert_eq!(sanitize("alice"), "alice");
        assert_eq!(sanitize("al\nice"), "alice");
        assert_eq!(sanitize("al\r\nice"), "alice");
        assert_eq!(sanitize("user\"\nsignal SIGTERM"), "user\"signal SIGTERM");
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn quoting_keeps_spaces_quotes_and_backslashes_intact() {
        assert_eq!(quote("plain").as_str(), "\"plain\"");
        assert_eq!(quote("two words").as_str(), "\"two words\"");
        assert_eq!(quote(r#"a"b\c"#).as_str(), r#""a\"b\\c""#);
        assert_eq!(quote("p\r\nsignal SIGTERM").as_str(), "\"psignal SIGTERM\"");
    }

    #[test]
    fn session_answers_once_and_stops_on_a_restart() {
        let mut s = Session::default();
        assert_eq!(s.on_line(">INFO:OpenVPN Management Interface Version 5"), Reply::Nothing);
        assert_eq!(s.on_line(">HOLD:Waiting for hold release:0"), Reply::Nothing);
        assert_eq!(s.on_line("SUCCESS: hold release succeeded"), Reply::Nothing);
        assert_eq!(s.on_line(">PASSWORD:Need 'Auth' username/password"), Reply::Credentials);
        assert_eq!(s.on_line("SUCCESS: 'Auth' username entered, but not yet verified"), Reply::Nothing);
        assert_eq!(s.on_line(">HOLD:Waiting for hold release:5"), Reply::Restarted);
    }

    #[test]
    fn a_rejected_login_is_never_answered_again() {
        let mut s = Session::default();
        assert_eq!(s.on_line(">PASSWORD:Need 'Auth' username/password"), Reply::Credentials);
        assert_eq!(s.on_line(">PASSWORD:Verification Failed: 'Auth'"), Reply::AuthFailed);
        assert_eq!(s.on_line(">PASSWORD:Need 'Auth' username/password"), Reply::Restarted);
    }

    /// A stand-in for openvpn's side of the socket.
    fn fake_openvpn(
        script: impl FnOnce(BufReader<UnixStream>, UnixStream) + Send + 'static,
    ) -> (TempDir, UnixStream, std::thread::JoinHandle<()>) {
        let dir = TempDir::new("mgmt");
        let path = dir.path().join("ovpn.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            script(BufReader::new(conn.try_clone().unwrap()), conn);
        });
        let client = UnixStream::connect(&path).unwrap();
        (dir, client, server)
    }

    fn read_line(reader: &mut BufReader<UnixStream>) -> String {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line
    }

    #[test]
    fn credentials_cross_the_socket_as_exactly_two_clean_lines() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (_dir, client, server) = fake_openvpn(move |mut reader, mut conn| {
            conn.write_all(b">HOLD:Waiting for hold release:0\n").unwrap();
            tx.send(read_line(&mut reader)).unwrap();
            conn.write_all(b">PASSWORD:Need 'Auth' username/password\n").unwrap();
            tx.send(read_line(&mut reader)).unwrap();
            tx.send(read_line(&mut reader)).unwrap();
        });
        let login = Login::new("ad\nmin", "p w\r\nsignal SIGTERM");
        assert_eq!(serve(&client, &login, &|| false), End::Closed);
        server.join().unwrap();
        let received: Vec<String> = rx.try_iter().collect();
        assert_eq!(
            received,
            ["hold release\n", "username \"Auth\" \"admin\"\n", "password \"Auth\" \"p wsignal SIGTERM\"\n"]
        );
    }

    #[test]
    fn a_verification_failure_ends_the_session() {
        let (_dir, client, server) = fake_openvpn(|mut reader, mut conn| {
            read_line(&mut reader);
            conn.write_all(b">PASSWORD:Need 'Auth' username/password\n").unwrap();
            read_line(&mut reader);
            read_line(&mut reader);
            conn.write_all(b">PASSWORD:Verification Failed: 'Auth'\n>PASSWORD:Need 'Auth' username/password\n")
                .unwrap();
            // A second answer would be a second login with the rejected password.
            conn.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            let mut extra = String::new();
            assert_eq!(reader.read_line(&mut extra).unwrap_or(0), 0, "credentials were resent: {extra:?}");
        });
        assert_eq!(serve(&client, &Login::new("u", "p"), &|| false), End::AuthFailed);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn a_self_restart_ends_the_session() {
        let (_dir, client, server) = fake_openvpn(|mut reader, mut conn| {
            conn.write_all(b">HOLD:Waiting for hold release:0\n").unwrap();
            read_line(&mut reader);
            conn.write_all(b">HOLD:Waiting for hold release:5\n").unwrap();
            let mut rest = String::new();
            let _ = reader.read_line(&mut rest);
        });
        assert_eq!(serve(&client, &Login::new("u", "p"), &|| false), End::Restarted);
        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn cancellation_ends_a_silent_session() {
        let (_dir, client, server) = fake_openvpn(|mut reader, _conn| {
            let mut all = String::new();
            let _ = reader.read_to_string(&mut all);
        });
        let calls = std::cell::Cell::new(0);
        let end = serve(&client, &Login::new("u", "p"), &|| {
            calls.set(calls.get() + 1);
            calls.get() > 2
        });
        assert_eq!(end, End::Cancelled);
        drop(client);
        server.join().unwrap();
    }
}
