//! A tiny, dependency-free XML reader for untrusted gateway responses
//! (port of `safexml.py` + just enough of ElementTree for `protocol.rs`).
//!
//! The H3C SSL VPN protocol never uses a DOCTYPE or entities, so we reject any
//! document that declares one (the "billion laughs" / XXE guard) and parse the
//! rest with a minimal hand-rolled parser. Only the read paths the protocol
//! needs are supported: `find`/`findall` for a direct child tag or a `.//a/b`
//! descendant path, element text (leading character data, ElementTree
//! semantics) and attributes.

use crate::error::{InodeError, Result};

/// One parsed element.
#[derive(Debug, Clone, Default)]
pub struct Element {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    /// Leading character data before the first child (ElementTree `.text`).
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    /// An attribute value, like ElementTree `.get(name)`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// First match of `path`: a bare tag selects a direct child; a `.//a/b`
    /// path selects any-depth `a`, then its direct child `b`.
    pub fn find(&self, path: &str) -> Option<&Element> {
        self.find_all(path).into_iter().next()
    }

    /// All matches of `path` (see [`Element::find`]).
    pub fn find_all(&self, path: &str) -> Vec<&Element> {
        if let Some(rest) = path.strip_prefix(".//") {
            let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
            let Some((first, tail)) = segs.split_first() else {
                return Vec::new();
            };
            let mut hits: Vec<&Element> = Vec::new();
            self.collect_descendants(first, &mut hits);
            // Then walk the remaining segments as direct children.
            let mut current = hits;
            for seg in tail {
                let mut next: Vec<&Element> = Vec::new();
                for el in current {
                    for child in &el.children {
                        if child.tag == *seg {
                            next.push(child);
                        }
                    }
                }
                current = next;
            }
            current
        } else {
            // A bare tag: direct children only.
            self.children.iter().filter(|c| c.tag == path).collect()
        }
    }

    /// Stripped text of a direct child `tag`, or `default`.
    pub fn child_text<'a>(&'a self, tag: &str, default: &'a str) -> &'a str {
        match self.children.iter().find(|c| c.tag == tag) {
            Some(el) => el.text.trim(),
            None => default,
        }
    }

    fn collect_descendants<'a>(&'a self, tag: &str, out: &mut Vec<&'a Element>) {
        for child in &self.children {
            if child.tag == tag {
                out.push(child);
            }
            child.collect_descendants(tag, out);
        }
    }
}

/// Reject a document that declares a DOCTYPE/ENTITY, then parse it.
pub fn fromstring(data: &str) -> Result<Element> {
    guard_no_dtd(data)?;
    parse(data)
}

fn guard_no_dtd(data: &str) -> Result<()> {
    let bytes = data.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'<' && bytes.get(i + 1) == Some(&b'!') {
            let tail = data.get(i + 2..).unwrap_or("").trim_start();
            let up: String = tail.chars().take(7).collect::<String>().to_ascii_uppercase();
            if up.starts_with("DOCTYPE") || up.starts_with("ENTITY") {
                return Err(InodeError::Protocol("XML declares a DOCTYPE/ENTITY; refusing to parse".into()));
            }
        }
        i += 1;
    }
    Ok(())
}

fn parse(data: &str) -> Result<Element> {
    let bytes = data.as_bytes();
    let mut i = 0;
    let n = bytes.len();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;

    let attach = |stack: &mut Vec<Element>, root: &mut Option<Element>, el: Element| {
        if let Some(top) = stack.last_mut() {
            top.children.push(el);
        } else {
            *root = Some(el);
        }
    };

    while i < n {
        if bytes[i] != b'<' {
            // Character data up to the next '<'.
            let start = i;
            while i < n && bytes[i] != b'<' {
                i += 1;
            }
            let raw = data.get(start..i).unwrap_or("");
            if let Some(top) = stack.last_mut() {
                if top.children.is_empty() {
                    top.text.push_str(&decode_entities(raw));
                }
            }
            continue;
        }
        // A markup token.
        match bytes.get(i + 1) {
            Some(b'?') => {
                // Processing instruction: skip to "?>".
                i = find_from(data, i + 2, "?>").map(|p| p + 2).unwrap_or(n);
            }
            Some(b'!') => {
                if data.get(i..).is_some_and(|s| s.starts_with("<![CDATA[")) {
                    let end = find_from(data, i + 9, "]]>").unwrap_or(n);
                    let raw = data.get(i + 9..end).unwrap_or("");
                    if let Some(top) = stack.last_mut() {
                        if top.children.is_empty() {
                            top.text.push_str(raw);
                        }
                    }
                    i = end.saturating_add(3).min(n);
                } else {
                    // Comment or declaration: skip to '>'.
                    i = find_from(data, i + 2, ">").map(|p| p + 1).unwrap_or(n);
                }
            }
            Some(b'/') => {
                // End tag: pop and attach to the parent.
                let end = find_from(data, i + 2, ">").unwrap_or(n);
                if let Some(el) = stack.pop() {
                    attach(&mut stack, &mut root, el);
                }
                i = end.saturating_add(1).min(n);
            }
            _ => {
                // Start tag (possibly self-closing).
                let end = find_from(data, i + 1, ">").ok_or_else(|| InodeError::Protocol("unterminated tag".into()))?;
                let inner = data.get(i + 1..end).unwrap_or("");
                let self_closing = inner.ends_with('/');
                let inner = inner.strip_suffix('/').unwrap_or(inner);
                let (tag, attrs) = parse_start_tag(inner);
                if tag.is_empty() {
                    return Err(InodeError::Protocol("empty tag name".into()));
                }
                let el = Element { tag, attrs, text: String::new(), children: Vec::new() };
                if self_closing {
                    attach(&mut stack, &mut root, el);
                } else {
                    stack.push(el);
                }
                i = end.saturating_add(1).min(n);
            }
        }
    }
    root.ok_or_else(|| InodeError::Protocol("no XML root element".into()))
}

fn parse_start_tag(inner: &str) -> (String, Vec<(String, String)>) {
    let inner = inner.trim();
    let mut parts = inner.splitn(2, |c: char| c.is_ascii_whitespace());
    let tag = parts.next().unwrap_or("").trim().to_string();
    let rest = parts.next().unwrap_or("");
    (tag, parse_attrs(rest))
}

fn parse_attrs(mut s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    loop {
        s = s.trim_start();
        let Some(eq) = s.find('=') else { break };
        let name = s.get(..eq).unwrap_or("").trim().to_string();
        let after = s.get(eq + 1..).unwrap_or("").trim_start();
        let Some(quote) = after.chars().next().filter(|&c| c == '"' || c == '\'') else {
            break;
        };
        let body = after.get(1..).unwrap_or("");
        let Some(close) = body.find(quote) else { break };
        let value = decode_entities(body.get(..close).unwrap_or(""));
        if !name.is_empty() {
            out.push((name, value));
        }
        s = body.get(close + 1..).unwrap_or("");
    }
    out
}

fn find_from(data: &str, from: usize, needle: &str) -> Option<usize> {
    data.get(from..).and_then(|s| s.find(needle)).map(|p| p + from)
}

/// Decode the five predefined entities plus numeric `&#..;` / `&#x..;`.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            if let Some(ch) = s.get(i..i + 1) {
                out.push_str(ch);
            }
            i += 1;
            continue;
        }
        let rest = s.get(i..).unwrap_or("");
        if let Some(semi) = rest.find(';').filter(|&p| p <= 10) {
            let ent = rest.get(1..semi).unwrap_or("");
            let decoded = match ent {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => numeric_entity(ent),
            };
            if let Some(c) = decoded {
                out.push(c);
                i += semi + 1;
                continue;
            }
        }
        out.push('&');
        i += 1;
    }
    out
}

fn numeric_entity(ent: &str) -> Option<char> {
    let code = if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        let dec = ent.strip_prefix('#')?;
        dec.parse::<u32>().ok()?
    };
    char::from_u32(code)
}
