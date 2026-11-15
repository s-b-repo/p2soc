//! A small RFC 3986 URL splitter.
//!
//! Only what the wall needs: scheme, authority (userinfo / host / port) and the
//! remainder. It is deliberately strict where the config validators need it to
//! be (malformed ports and unbalanced IPv6 brackets are errors) and pulls in no
//! dependency.

/// The parts of a split URL. `rest` is everything after the authority
/// (path, query and fragment), verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub netloc: String,
    pub userinfo: Option<String>,
    /// Lower-cased host with IPv6 brackets removed; `None` when empty.
    pub host: Option<String>,
    pub port: Option<u16>,
    pub rest: String,
}

/// Why a URL could not be split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    BadPort,
    BadBrackets,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UrlError::BadPort => "invalid port",
            UrlError::BadBrackets => "invalid IPv6 literal",
        })
    }
}

impl std::error::Error for UrlError {}

fn is_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

impl Url {
    /// Split `input`. A string with no `scheme://` yields an empty scheme and
    /// no authority (the whole input lands in `rest`).
    pub fn split(input: &str) -> Result<Url, UrlError> {
        let (scheme, after) = match input.split_once(':') {
            Some((s, rest)) if is_scheme(s) => (s.to_ascii_lowercase(), rest),
            _ => (String::new(), input),
        };
        let Some(authority_on) = after.strip_prefix("//") else {
            return Ok(Url {
                scheme,
                netloc: String::new(),
                userinfo: None,
                host: None,
                port: None,
                rest: after.to_string(),
            });
        };
        let end = authority_on.find(['/', '?', '#']).unwrap_or(authority_on.len());
        // `end` comes from `find`/`len` on this very string, so `get` always succeeds.
        let netloc = authority_on.get(..end).unwrap_or(authority_on);
        let rest = authority_on.get(end..).unwrap_or("");
        if netloc.contains('[') != netloc.contains(']') {
            return Err(UrlError::BadBrackets);
        }
        let (userinfo, hostport) = match netloc.rsplit_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, netloc),
        };
        let (host, port_text) = if let Some(inner) = hostport.strip_prefix('[') {
            let Some((h, tail)) = inner.split_once(']') else {
                return Err(UrlError::BadBrackets);
            };
            match tail.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None if tail.is_empty() => (h, None),
                None => return Err(UrlError::BadBrackets),
            }
        } else {
            // First colon, not last: `a:b:80` is a malformed port, never a
            // host named `a:b` (an unbracketed IPv6 literal is not a valid URL).
            match hostport.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        let port = match port_text {
            None | Some("") => None,
            Some(p) => {
                if !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(UrlError::BadPort);
                }
                Some(p.parse::<u16>().map_err(|_| UrlError::BadPort)?) // audit-allow: u16 overflow of an all-digit port is exactly BadPort
            }
        };
        Ok(Url {
            scheme,
            netloc: netloc.to_string(),
            userinfo,
            host: (!host.is_empty()).then(|| host.to_ascii_lowercase()),
            port,
            rest: rest.to_string(),
        })
    }

    /// The port, falling back to the scheme's well-known one.
    pub fn port_or_default(&self) -> Option<u16> {
        self.port.or(match self.scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        })
    }

    /// `scheme://host[:port]` with a non-default port only — the origin a
    /// browser would compute. `None` without a scheme or host.
    pub fn origin(&self) -> Option<String> {
        let host = self.host.as_deref()?;
        if self.scheme.is_empty() {
            return None;
        }
        let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        let default = Url { port: None, ..self.clone() }.port_or_default();
        Some(match self.port {
            Some(p) if Some(p) != default => format!("{}://{host}:{p}", self.scheme),
            _ => format!("{}://{host}", self.scheme),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_plain_url() {
        let u = Url::split("HTTP://Example.COM:8080/a?b#c").unwrap();
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host.as_deref(), Some("example.com"));
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.rest, "/a?b#c");
        assert_eq!(u.userinfo, None);
    }

    #[test]
    fn userinfo_and_ipv6() {
        let u = Url::split("https://u:p@[fd00::1]:443/x").unwrap();
        assert_eq!(u.userinfo.as_deref(), Some("u:p"));
        assert_eq!(u.host.as_deref(), Some("fd00::1"));
        assert_eq!(u.port, Some(443));
        assert_eq!(u.origin().as_deref(), Some("https://[fd00::1]"));
    }

    #[test]
    fn rejects_bad_ports_and_brackets() {
        assert_eq!(Url::split("http://h:99999/"), Err(UrlError::BadPort));
        assert_eq!(Url::split("http://h:8x/"), Err(UrlError::BadPort));
        assert_eq!(Url::split("http://[::1/"), Err(UrlError::BadBrackets));
        assert_eq!(Url::split("http://[::1]x/"), Err(UrlError::BadBrackets));
    }

    #[test]
    fn no_authority() {
        let u = Url::split("javascript:alert(1)").unwrap();
        assert_eq!(u.scheme, "javascript");
        assert_eq!(u.host, None);
        let u = Url::split("just/a/path").unwrap();
        assert_eq!(u.scheme, "");
        assert_eq!(u.rest, "just/a/path");
    }

    #[test]
    fn empty_host_is_none() {
        assert_eq!(Url::split("http://:80/").unwrap().host, None);
        assert_eq!(Url::split("http:///x").unwrap().host, None);
    }

    #[test]
    fn origin_drops_default_port() {
        assert_eq!(Url::split("http://a:80/x").unwrap().origin().as_deref(), Some("http://a"));
        assert_eq!(Url::split("http://a:81/x").unwrap().origin().as_deref(), Some("http://a:81"));
    }
}
