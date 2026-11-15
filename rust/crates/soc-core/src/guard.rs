//! Input guards.
//!
//! The single implementation shared by load-time validation and by every argv
//! builder (VPN, tunnel). Builders re-check at connect time because a
//! `config_from_vault` overlay can change a VPN entry after validation ran.
//!
//! Each guard exists to stop one concrete attack: option injection (a value
//! starting with `-` parsed as a flag by the child binary), argv smuggling via
//! whitespace, and log/request splitting via control characters.

use crate::dict::{Dict, DictExt, quote, repr, text};
use crate::url::Url;
use serde_json::Value;

/// A rejected input; the message is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardError(pub String);

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GuardError {}

type Result<T> = std::result::Result<T, GuardError>;

fn err<T>(msg: String) -> Result<T> {
    Err(GuardError(msg))
}

pub const VALID_URL_SCHEMES: [&str; 2] = ["http", "https"];
/// ssh `StrictHostKeyChecking` values an operator may select. `no` is
/// deliberately absent.
pub const VALID_HOST_KEY_CHECKING: [&str; 2] = ["yes", "accept-new"];

/// True if `s` holds a control character: the full Unicode `Cc` category — C0
/// (incl. `\n` `\r` `\t` NUL), DEL, and the C1 range U+0080..=U+009F. The C1
/// controls matter because callers reject these in URLs, hostnames and argv,
/// where an embedded C1 byte is a smuggling vector, never legitimate input.
pub fn has_ctrl(s: &str) -> bool {
    s.chars().any(char::is_control)
}

/// True if `s` holds a control character or any whitespace.
pub fn has_ctrl_or_space(s: &str) -> bool {
    has_ctrl(s) || s.chars().any(char::is_whitespace)
}

/// RFC 3986-aware check for a panel URL: an http/https scheme, a real host, a
/// well-formed port, no embedded credentials (`user:pass@host` is a
/// confusion/leak vector) and no control or whitespace character (those enable
/// scheme smuggling and request splitting).
pub fn valid_http_url(url: &str, allow_empty: bool) -> bool {
    if url.trim().is_empty() {
        return allow_empty;
    }
    // Validate the string exactly as the caller will use it. Leading/trailing
    // whitespace must be REJECTED, not trimmed away: callers load the original
    // string, browsers may strip surrounding whitespace/control themselves, and
    // `Url::split` does not trim — so trimming here accepted inputs like
    // "\n http://evil" that parse with no http scheme once actually used.
    if has_ctrl_or_space(url) {
        return false;
    }
    let Ok(parts) = Url::split(url) else {
        return false;
    };
    VALID_URL_SCHEMES.contains(&parts.scheme.as_str()) && parts.host.is_some() && !parts.netloc.contains('@')
}

/// `url` quoted for a message, with any userinfo masked: a rejected
/// `user:pass@host` URL must not leak the password it was rejected for.
pub fn url_for_msg(url: &str) -> String {
    // Mask the first `/?#`-delimited segment that holds an `@`, up to its
    // LAST `@`: a password may itself contain one (`user:p@ss@host`).
    let mut start = 0;
    let masked = loop {
        let end = url.get(start..).and_then(|t| t.find(['/', '?', '#'])).map_or(url.len(), |i| start + i);
        if let Some(at) = url.get(start..end).and_then(|seg| seg.rfind('@')) {
            let head = url.get(..start).unwrap_or("");
            let tail = url.get(start + at..).unwrap_or("");
            break format!("{head}***{tail}");
        }
        if end == url.len() {
            break url.to_string();
        }
        start = end + 1;
    };
    quote(&masked)
}

/// Validate a hostname/IP destined for an argv slot; returns it trimmed.
/// Rejects empty values, whitespace/control characters and a leading `-`.
pub fn safe_host(v: &str, what: &str) -> Result<String> {
    let s = v.trim();
    if s.is_empty() {
        return err(format!("{what} is empty"));
    }
    if has_ctrl_or_space(s) {
        return err(format!("{what} {} contains whitespace/control characters", quote(s)));
    }
    if s.starts_with('-') {
        return err(format!("{what} {} may not begin with '-' (option injection)", quote(s)));
    }
    Ok(s.to_string())
}

/// Validate a port in 1..=65535 given as an integer or a digit string. Bools
/// and floats are rejected rather than coerced.
pub fn safe_port(v: &Value, what: &str) -> Result<u16> {
    let n: Option<i64> = match v {
        Value::Number(n) if n.is_i64() || n.is_u64() => n.as_i64(),
        Value::String(s) => {
            let t = s.trim();
            if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) { t.parse().ok() } else { None }
        }
        _ => None,
    };
    let Some(p) = n else {
        return err(format!("{what} {} is not an integer", repr(v)));
    };
    if !(1..=65535).contains(&p) {
        return err(format!("{what} {p} is out of range 1..65535"));
    }
    u16::try_from(p).or_else(|e| err(format!("{what} {p} is out of range 1..65535 ({e})")))
}

/// [`safe_port`] for a digit string.
pub fn safe_port_str(v: &str, what: &str) -> Result<u16> {
    safe_port(&Value::String(v.to_string()), what)
}

/// Validate a free-text argv token (realm / path / key); returns it trimmed.
/// Rejects newlines and a leading `-`. The value is never echoed: some of
/// these (the SPA key) are sensitive.
pub fn safe_word(v: &str, what: &str) -> Result<String> {
    if v.contains('\n') || v.contains('\r') {
        return err(format!("{what} must not contain newlines"));
    }
    let s = v.trim();
    if s.starts_with('-') {
        return err(format!("{what} may not begin with '-' (option injection)"));
    }
    Ok(s.to_string())
}

/// [`safe_word`] over an optional config value (missing/null -> `""`).
pub fn safe_word_value(v: Option<&Value>, what: &str) -> Result<String> {
    match v {
        None | Some(Value::Null) => Ok(String::new()),
        Some(v) => safe_word(&text(v), what),
    }
}

/// Validate the pass-through `extra_args` list. It is operator-trusted, so a
/// leading `-` is fine (those are real flags); control characters and a
/// non-list are not.
pub fn safe_extra_args(v: Option<&Value>) -> Result<Vec<String>> {
    let items = match v {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::String(s)) if s.is_empty() => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(other) => {
            let kind = match other {
                Value::String(_) => "string",
                Value::Bool(_) => "boolean",
                Value::Number(_) => "number",
                _ => "mapping",
            };
            return err(format!("extra_args must be a list, got {kind}"));
        }
    };
    let mut out = Vec::with_capacity(items.len());
    for (i, a) in items.iter().enumerate() {
        let s = text(a);
        if has_ctrl(&s) {
            return err(format!("extra_args item #{} contains control characters", i + 1));
        }
        out.push(s);
    }
    Ok(out)
}

/// Format `host:port`, bracketing a bare IPv6 literal (two or more colons).
pub fn host_port(host: &str, port: u16) -> String {
    if !host.starts_with('[') && host.matches(':').count() >= 2 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Accept the operator-natural gateway shapes and return `(host, port)`:
///
/// | input            | result                          |
/// |------------------|---------------------------------|
/// | `gw.example`     | `("gw.example", default)`       |
/// | `gw.example:443` | `("gw.example", 443)`           |
/// | `fd00::1`        | `("fd00::1", default)`          |
/// | `[fd00::1]`      | `("fd00::1", default)`          |
/// | `[fd00::1]:443`  | `("fd00::1", 443)`              |
/// | `fd00::1:443`    | `("fd00::1:443", default)` (ambiguous: read as IPv6) |
///
/// An embedded port wins over `default_port`.
pub fn split_host_port(value: &str, default_port: &Value) -> Result<(String, u16)> {
    let s = value.trim();
    if s.is_empty() {
        return err("host is empty".into());
    }
    let (host, port): (&str, Option<&str>) = if let Some(inner) = s.strip_prefix('[') {
        let Some((h, rest)) = inner.split_once(']') else {
            return err(format!("malformed bracketed host {}", quote(s)));
        };
        match rest.strip_prefix(':') {
            Some(p) => (h, Some(p)),
            None if rest.is_empty() => (h, None),
            None => return err(format!("malformed bracketed host {}", quote(s))),
        }
    } else if s.matches(':').count() == 1 {
        let (h, p) = s.split_once(':').unwrap_or((s, ""));
        (h, Some(p))
    } else {
        (s, None)
    };
    match port {
        None => Ok((host.to_string(), safe_port(default_port, "default port")?)),
        Some("") => err(format!("{} has a ':' but no port", quote(s))),
        Some(p) => Ok((host.to_string(), safe_port_str(p, "embedded port")?)),
    }
}

/// The canonical bracketed `host:port` for `vpn.gateway` + `vpn.port`
/// (default 443).
pub fn gateway_hostport(vpn: &Dict) -> Result<String> {
    let default = match vpn.get("port") {
        Some(v) if crate::dict::truthy(v) => v.clone(),
        _ => Value::from(443),
    };
    let (host, port) = split_host_port(&vpn.text("gateway"), &default)?;
    Ok(host_port(&safe_host(&host, "vpn.gateway")?, port))
}

/// Validate a panel's `tunnel.remote_host`. A single `:` means the operator
/// wrote `host:port` here instead of using `remote_port`, which builds a
/// forward ssh rejects and autossh would then retry forever.
pub fn safe_remote_host(v: &str) -> Result<String> {
    let s = safe_host(v, "tunnel.remote_host")?;
    if s.matches(':').count() == 1 {
        return err(format!("tunnel.remote_host {} has an embedded ':port' (use a separate remote_port)", quote(&s)));
    }
    Ok(s)
}

/// The `ssh -L` spec for one `mode: tunnel` panel.
pub fn panel_forward(tunnel: &Dict) -> Result<String> {
    let null = Value::Null;
    let lp = safe_port(tunnel.get("local_port").unwrap_or(&null), "tunnel.local_port")?;
    let rp = safe_port(tunnel.get("remote_port").unwrap_or(&null), "tunnel.remote_port")?;
    let host = safe_remote_host(&tunnel.get("remote_host").map(text).unwrap_or_default())?; // audit-allow: default is the intended fallback
    Ok(format!("127.0.0.1:{lp}:{}", host_port(&host, rp)))
}

fn is_forward_host(s: &str) -> bool {
    if let Some(inner) = s.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return false;
        };
        return !inner.is_empty()
            && inner.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '%' | '_' | '-'));
    }
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Split an `ssh -L` spec on the colons that are outside `[...]`.
fn forward_fields(s: &str) -> Option<Vec<&str>> {
    let mut fields = Vec::new();
    let (mut depth, mut start) = (0u32, 0usize);
    for (i, c) in s.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.checked_sub(1)?,
            ':' if depth == 0 => {
                fields.push(s.get(start..i)?);
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    fields.push(s.get(start..)?);
    Some(fields)
}

/// Vet one `tunnel.extra_forwards` entry, returning it unchanged. It is
/// spliced straight into ssh's `-L` argument, so it must be a plain
/// `[bindaddr:]port:host:port` spec — never an option-looking token or
/// anything with whitespace.
pub fn safe_forward(entry: &str) -> Result<String> {
    if has_ctrl_or_space(entry) {
        return err(format!("extra_forward contains whitespace/control characters: {}", quote(entry)));
    }
    let shape_err = || GuardError(format!("extra_forward must be [bindaddr:]port:host:port, got {}", quote(entry)));
    let fields = forward_fields(entry).ok_or_else(shape_err)?;
    let (lport, host, rport) = match fields.as_slice() {
        [lp, h, rp] => (*lp, *h, *rp),
        [bind, lp, h, rp] if is_forward_host(bind) => (*lp, *h, *rp),
        _ => return Err(shape_err()),
    };
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if !digits(lport) || !digits(rport) || !is_forward_host(host) {
        return Err(shape_err());
    }
    safe_port_str(lport, "extra_forward port")?;
    safe_port_str(rport, "extra_forward port")?;
    Ok(entry.to_string())
}

/// The effective ssh `StrictHostKeyChecking` mode for the `tunnel:` section.
/// Default is strict `yes`: a MITM at first connect must not be able to
/// intercept the tunnel carrying the dashboards and their logins.
/// `accept-new` (TOFU) is an explicit opt-in; anything else — a typo, `no`,
/// a boolean — fails closed to `yes`.
pub fn host_key_checking(tunnel: &Dict) -> &'static str {
    let v = match tunnel.get("host_key_checking") {
        None => return "yes",
        Some(Value::Bool(true)) => "true".to_string(),
        Some(v) => text(v).trim().to_ascii_lowercase(),
    };
    VALID_HOST_KEY_CHECKING.into_iter().find(|ok| *ok == v).unwrap_or("yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn d(v: Value) -> Dict {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn http_url_validation() {
        assert!(valid_http_url("http://10.0.0.1:3000/login", false));
        assert!(valid_http_url("https://[fd00::1]/x", false));
        assert!(valid_http_url("", true));
        assert!(!valid_http_url("", false));
        assert!(!valid_http_url("ftp://h/", false));
        assert!(!valid_http_url("javascript:alert(1)", false));
        assert!(!valid_http_url("http://user:pw@h/", false));
        assert!(!valid_http_url("http://h:99999/", false));
        assert!(!valid_http_url("http://h/\njavascript:alert(1)", false));
        assert!(!valid_http_url("http://h/a b", false));
        assert!(!valid_http_url("http:///nohost", false));
        // Leading/trailing whitespace must be rejected, not trimmed: the raw
        // string is what gets loaded, and it parses with no http scheme. (Fuzz
        // regression: `valid_http_url` used to trim then accept these.)
        assert!(!valid_http_url("\n http://h", false));
        assert!(!valid_http_url(" http://h ", false));
        assert!(!valid_http_url("http://h\t", false));
        // A blank/whitespace-only value is still treated as empty.
        assert!(valid_http_url("   ", true));
        assert!(!valid_http_url("   ", false));
        // A non-ASCII C1 control char (U+0099) embedded in the host must be
        // rejected (fuzz regression: has_ctrl missed the C1 range U+0080..=009F).
        assert!(!valid_http_url("http://h\u{0099}x", false));
        assert!(has_ctrl("a\u{0099}b"));
        assert!(has_ctrl("a\u{0085}b")); // NEL, another C1 control
    }

    #[test]
    fn url_message_masks_credentials() {
        assert_eq!(url_for_msg("http://u:secret@h/x"), "'http://***@h/x'");
        assert_eq!(url_for_msg("http://h/x"), "'http://h/x'");
        assert!(!url_for_msg("u:secret@h").contains("secret"));
        // A password containing '@' must be masked in full.
        assert_eq!(url_for_msg("http://u:p@ss@h/x"), "'http://***@h/x'");
        assert_eq!(url_for_msg("http://h/a?b=c@d"), "'http://h/a?***@d'");
        // Fuzz-found pathological input (`userinfo` is `*@BBBBBBBB`): the whole
        // userinfo is masked and its characters never survive before the host.
        let shown = url_for_msg("//*@BBBBBBBB@BBBBBBBBB/@B/@@");
        assert_eq!(shown, "'//***@BBBBBBBBB/@B/@@'");
        assert!(!shown.contains("*@BBBBBBBB@"), "the credential+separator must not survive: {shown}");
        // Only the authority's userinfo is masked; an identical byte run that
        // recurs later in the path stays visible (it is path data, not a
        // credential). This is why a bare substring leak-check is wrong.
        assert_eq!(url_for_msg("http://aaaa@h/aaaa@x"), "'http://***@h/aaaa@x'");
        // A scheme-relative URL whose host is control bytes still masks the user.
        assert_eq!(url_for_msg("//333333333,@\u{0}\u{8}?x"), "'//***@\\x00\\x08?x'");
    }

    #[test]
    fn host_guard_blocks_option_injection() {
        assert_eq!(safe_host(" gw.example ", "h").unwrap(), "gw.example");
        assert!(safe_host("-oProxyCommand=x", "h").is_err());
        assert!(safe_host("a b", "h").is_err());
        assert!(safe_host("a\nb", "h").is_err());
        assert!(safe_host("", "h").is_err());
    }

    #[test]
    fn port_guard() {
        assert_eq!(safe_port(&json!(443), "p").unwrap(), 443);
        assert_eq!(safe_port(&json!("8443"), "p").unwrap(), 8443);
        for bad in [json!(0), json!(65536), json!(-1), json!(true), json!(4.0), json!("x"), json!(null), json!("")] {
            assert!(safe_port(&bad, "p").is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn word_guard_never_echoes_the_value() {
        assert_eq!(safe_word(" realm ", "vpn.realm").unwrap(), "realm");
        let e = safe_word("-secret", "vpn.spa_key").unwrap_err();
        assert!(!e.0.contains("secret"));
        assert!(safe_word("a\nb", "w").is_err());
    }

    #[test]
    fn extra_args_guard() {
        assert_eq!(safe_extra_args(Some(&json!(["-v", "--trace"]))).unwrap(), vec!["-v", "--trace"]);
        assert!(safe_extra_args(None).unwrap().is_empty());
        assert!(safe_extra_args(Some(&json!("-v"))).is_err());
        assert!(safe_extra_args(Some(&json!(["a\nb"]))).is_err());
    }

    #[test]
    fn split_host_port_shapes() {
        let def = json!(443);
        let ok = |s: &str| split_host_port(s, &def).unwrap();
        assert_eq!(ok("gw.example"), ("gw.example".into(), 443));
        assert_eq!(ok("gw.example:8443"), ("gw.example".into(), 8443));
        assert_eq!(ok("fd00::1"), ("fd00::1".into(), 443));
        assert_eq!(ok("[fd00::1]"), ("fd00::1".into(), 443));
        assert_eq!(ok("[fd00::1]:3000"), ("fd00::1".into(), 3000));
        assert_eq!(ok("fd00::1:443"), ("fd00::1:443".into(), 443));
        for bad in ["", "host:", "[::1", "[::1]x", "h:0", "h:x"] {
            assert!(split_host_port(bad, &def).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn gateway_is_bracketed_and_embedded_port_wins() {
        assert_eq!(gateway_hostport(&d(json!({"gateway": "fd00::1", "port": 10443}))).unwrap(), "[fd00::1]:10443");
        assert_eq!(gateway_hostport(&d(json!({"gateway": "gw:8443", "port": 443}))).unwrap(), "gw:8443");
        assert_eq!(gateway_hostport(&d(json!({"gateway": "gw"}))).unwrap(), "gw:443");
        assert!(gateway_hostport(&d(json!({"gateway": "-x"}))).is_err());
    }

    #[test]
    fn panel_forward_spec() {
        let t = d(json!({"local_port": 19103, "remote_host": "10.20.0.7", "remote_port": 8443}));
        assert_eq!(panel_forward(&t).unwrap(), "127.0.0.1:19103:10.20.0.7:8443");
        let t6 = d(json!({"local_port": 1, "remote_host": "fd00::7", "remote_port": 2}));
        assert_eq!(panel_forward(&t6).unwrap(), "127.0.0.1:1:[fd00::7]:2");
        assert!(panel_forward(&d(json!({"local_port": 1, "remote_host": "h:80", "remote_port": 2}))).is_err());
        assert!(panel_forward(&d(json!({"local_port": 1, "remote_host": "h"}))).is_err());
    }

    #[test]
    fn extra_forward_guard() {
        for ok in ["8080:host:80", "127.0.0.1:8080:host:80", "[::1]:8080:[fd00::1]:80", "1:a.b-c:2"] {
            assert_eq!(safe_forward(ok).unwrap(), ok);
        }
        for bad in [
            "-D 1080",
            "-D1080",
            "8080:host",
            "8080:host:80 -oProxyCommand=x",
            "x:host:80",
            "8080:fd00::1:80",
            "0:host:80",
            "8080:host:70000",
            "8080:-host:80",
            "a:b:c:d:e",
            "",
        ] {
            assert!(safe_forward(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn host_key_checking_fails_closed() {
        assert_eq!(host_key_checking(&d(json!({}))), "yes");
        assert_eq!(host_key_checking(&d(json!({"host_key_checking": "accept-new"}))), "accept-new");
        assert_eq!(host_key_checking(&d(json!({"host_key_checking": " Accept-New "}))), "accept-new");
        for bad in [json!("no"), json!(false), json!(true), json!("off"), json!("typo")] {
            assert_eq!(host_key_checking(&d(json!({"host_key_checking": bad}))), "yes");
        }
    }
}
