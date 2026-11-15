//! The auth state machine against an in-process mock TLS gateway: a std
//! `TcpListener` + rustls server in a thread with a self-signed cert generated
//! fresh for each run (no key material is committed to the repo).
//! Covers index -> gatewayinfo -> login -> (challenge) -> success and the
//! auth-failure path. The client uses `--insecure` (verify off) so the throwaway
//! cert needs no trust chain. Nothing here touches the real network beyond
//! 127.0.0.1.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::JoinHandle;

use rustls::pki_types::PrivateKeyDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use zeroize::Zeroizing;

use soc_inode::{Client, ClientConfig, Prompter};

/// A single response for a given request path.
type Route = (u16, &'static str, Vec<(&'static str, String)>, Vec<u8>);

fn server_config() -> ServerConfig {
    // Generate a throwaway self-signed cert + key in memory for localhost. The
    // client connects with `--insecure`, so the cert is never trust-validated;
    // this keeps any private key out of the repository entirely.
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .expect("generate self-signed cert");
    let cert_der = issued.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(issued.signing_key.serialize_der()).expect("serialize key");
    ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap()
}

/// Start a one-connection gateway that dispatches on the request path.
fn spawn_gateway<F>(routes: F) -> (String, u16, JoinHandle<()>)
where
    F: Fn(&str, &str, &[u8]) -> Route + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(server_config());
    let handle = std::thread::spawn(move || {
        let Ok((tcp, _)) = listener.accept() else { return };
        let conn = ServerConnection::new(config).unwrap();
        let mut tls = StreamOwned::new(conn, tcp);
        let mut buf: Vec<u8> = Vec::new();
        while let Some((method, path, body)) = read_request(&mut tls, &mut buf) {
            let (status, reason, headers, rbody) = routes(&method, &path, &body);
            write_response(&mut tls, status, reason, &headers, &rbody);
        }
    });
    (addr.ip().to_string(), addr.port(), handle)
}

fn read_request(tls: &mut impl Read, buf: &mut Vec<u8>) -> Option<(String, String, Vec<u8>)> {
    loop {
        if let Some(pos) = find(buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or("").to_string();
            let mut parts = request_line.split(' ');
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let mut content_length = 0usize;
            for l in lines {
                if let Some((k, v)) = l.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            buf.drain(..pos + 4);
            while buf.len() < content_length {
                let mut tmp = [0u8; 4096];
                match tls.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            let body: Vec<u8> = buf.drain(..content_length.min(buf.len())).collect();
            return Some((method, path, body));
        }
        let mut tmp = [0u8; 4096];
        match tls.read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return None,
        }
    }
}

fn write_response(tls: &mut impl Write, status: u16, reason: &str, headers: &[(&str, String)], body: &[u8]) {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let _ = tls.write_all(head.as_bytes());
    let _ = tls.write_all(body);
    let _ = tls.flush();
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

const GATEWAYINFO: &str = "<data><gatewayinfo><auth><supportPassword>true</supportPassword><supportvldimg>false</supportvldimg></auth><url><login>/login.cgi</login><challenge>/chal.cgi</challenge><logout>/logout.cgi</logout></url></gatewayinfo></data>";

fn client(host: &str, port: u16) -> Client {
    let mut config = ClientConfig::new(host, port, "alice", Zeroizing::new("hunter2".to_string()));
    config.tls.verify = false;
    Client::new(config)
}

#[test]
fn happy_path_authenticates() {
    let (host, port, handle) = spawn_gateway(|_method, path, _body| match path {
        "/svpn/index.cgi" => (
            200,
            "OK",
            vec![("Server", "SSLVPN-Gateway/7.0".to_string()), ("Set-Cookie", "svpnginfo=SESSIONTOKEN".to_string())],
            GATEWAYINFO.as_bytes().to_vec(),
        ),
        "/login.cgi" => (200, "OK", vec![], b"<data><result>Success</result></data>".to_vec()),
        _ => (404, "Not Found", vec![], Vec::new()),
    });

    let mut c = client(&host, port);
    let session = c.authenticate().expect("auth should succeed");
    assert_eq!(session.session_cookie(), "SESSIONTOKEN");
    drop(handle);
}

struct FixedPrompter;
impl Prompter for FixedPrompter {
    fn captcha(&self, _image: &[u8]) -> String {
        String::new()
    }
    fn challenge_code(&self, _ctype: &str, _message: &str) -> String {
        "246810".to_string()
    }
}

#[test]
fn challenge_then_success() {
    let (host, port, handle) = spawn_gateway(|_method, path, _body| match path {
        "/svpn/index.cgi" => (
            200,
            "OK",
            vec![("Server", "SSLVPN-Gateway/7.0".to_string()), ("Set-Cookie", "svpnginfo=TOK2".to_string())],
            GATEWAYINFO.as_bytes().to_vec(),
        ),
        "/login.cgi" => (
            200,
            "OK",
            vec![],
            b"<data><result>Challenge</result><type>SMS</type><message>code?</message></data>".to_vec(),
        ),
        "/chal.cgi" => (200, "OK", vec![], b"<data><result>Success</result></data>".to_vec()),
        _ => (404, "Not Found", vec![], Vec::new()),
    });

    let mut c = client(&host, port).with_prompter(std::rc::Rc::new(FixedPrompter));
    let session = c.authenticate().expect("challenge path should succeed");
    assert_eq!(session.session_cookie(), "TOK2");
    drop(handle);
}

#[test]
fn auth_failure_is_classifiable() {
    let (host, port, handle) = spawn_gateway(|_method, path, _body| match path {
        "/svpn/index.cgi" => {
            (200, "OK", vec![("Server", "SSLVPN-Gateway/7.0".to_string())], GATEWAYINFO.as_bytes().to_vec())
        }
        "/login.cgi" => (
            200,
            "OK",
            vec![],
            b"<data><result>Failed</result><replyMessage>incorrect username or password</replyMessage></data>".to_vec(),
        ),
        _ => (404, "Not Found", vec![], Vec::new()),
    });

    let mut c = client(&host, port);
    match c.authenticate() {
        Ok(_) => panic!("bad credentials must fail"),
        // The supervisor classifies on this exact substring.
        Err(err) => assert!(err.to_string().contains("authentication failed"), "got: {err}"),
    }
    drop(handle);
}

#[test]
fn index_non_200_fails() {
    let (host, port, handle) = spawn_gateway(|_m, _p, _b| {
        (500, "Server Error", vec![("Server", "SSLVPN-Gateway/7.0".to_string())], Vec::new())
    });
    let mut c = client(&host, port);
    assert!(c.authenticate().is_err());
    drop(handle);
}
