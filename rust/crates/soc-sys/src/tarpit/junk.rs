//! Plausible-looking junk responses.
//!
//! A matched path gets a body whose *shape* fits what a header-only scanner
//! expects — `KEY=value` lines for a `.env`, a JSON object for an API path,
//! an HTML page for an admin login — filled with random base64. Plausible
//! enough to cost a human triage time; junk enough to be useless.
//!
//! Nothing here is secret, so the randomness is a small non-cryptographic
//! generator seeded from the OS-keyed hasher: no syscall per response and no
//! dependency.

use crate::sha256::hex_digest;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// No body is ever larger than this, whatever size is asked for: together
/// with the connection cap it bounds the tarpit's memory.
pub const MAX_BODY_SEED: usize = 32 * 1024;

/// xorshift64* — fast, tiny, good enough for junk.
#[derive(Debug, Clone)]
pub struct Rng(u64);

static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Default for Rng {
    fn default() -> Self {
        Rng::new()
    }
}

impl Rng {
    /// A generator with an unpredictable seed.
    pub fn new() -> Rng {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(SEED_COUNTER.fetch_add(1, Ordering::Relaxed));
        hasher.write_u128(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
        Rng::from_seed(hasher.finish())
    }

    pub fn from_seed(seed: u64) -> Rng {
        Rng(if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed })
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value in `lo..=hi` (`lo` when the range is empty).
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo + 1)
    }

    /// [`Rng::range`] for lengths and sizes.
    pub fn range_len(&mut self, lo: usize, hi: usize) -> usize {
        let wide = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
        usize::try_from(self.range(wide(lo), wide(hi))).unwrap_or(lo)
    }

    /// A value in `lo..=hi`, whichever way round the bounds are given.
    pub fn uniform(&mut self, lo: f64, hi: f64) -> f64 {
        let unit = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64; // audit-allow: lossless, both values are below 2^53
        lo + (hi - lo) * unit
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n + 8);
        while out.len() < n {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(n);
        out
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        let count = u64::try_from(items.len()).unwrap_or(1).max(1);
        let idx = usize::try_from(self.next_u64() % count).unwrap_or(0);
        items.get(idx).copied().unwrap_or("")
    }
}

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = u32::from(chunk.first().copied().unwrap_or(0)) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = usize::try_from(n >> (18 - 6 * i) & 63).unwrap_or(0);
                out.push(alphabet.get(idx).copied().map_or('=', char::from));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64 with padding.
pub fn base64_std(data: &[u8]) -> String {
    base64(data, STD_ALPHABET, true)
}

/// URL-safe base64 without padding.
pub fn base64_url(data: &[u8]) -> String {
    base64(data, URL_ALPHABET, false)
}

/// The shape of a junk body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    Env,
    Json,
    Html,
    Text,
}

/// `(Content-Type, body shape)` for a matched path, so a quick look reads
/// "yes, an env file" rather than "random bytes".
pub fn mime_for(path: &str) -> (&'static str, BodyKind) {
    const PLAIN: &str = "text/plain; charset=utf-8";
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| path.starts_with(p));
    let ends = |suffixes: &[&str]| suffixes.iter().any(|s| path.ends_with(s));
    if ends(&[".env", ".env.local", ".env.production"]) {
        (PLAIN, BodyKind::Env)
    } else if ends(&[".json"]) || starts(&["/api/", "/actuator/", "/jolokia/"]) {
        ("application/json", BodyKind::Json)
    } else if starts(&["/.git/", "/.htpasswd", "/.htaccess", "/.aws/", "/.ssh/"]) {
        (PLAIN, BodyKind::Text)
    } else {
        ("text/html; charset=utf-8", BodyKind::Html)
    }
}

fn junk_env(n: usize, rng: &mut Rng) -> Vec<u8> {
    const KEYS: [&str; 8] = [
        "DATABASE_URL",
        "APP_KEY",
        "MAIL_PASSWORD",
        "S3_SECRET",
        "REDIS_URL",
        "JWT_SECRET",
        "API_TOKEN",
        "DEBUG_TOKEN",
    ];
    let mut out = String::with_capacity(n + 96);
    while out.len() < n {
        let len = rng.range_len(16, 48);
        out.push_str(rng.pick(&KEYS));
        out.push('=');
        out.push_str(&base64_url(&rng.bytes(len)));
        out.push('\n');
    }
    out.into_bytes()
}

fn junk_json(n: usize, rng: &mut Rng) -> Vec<u8> {
    const KEYS: [&str; 7] = ["status", "data", "result", "token", "id", "name", "value"];
    let mut out = String::with_capacity(n + 96);
    out.push('{');
    let mut pairs = 0usize;
    while out.len() < n {
        if pairs > 0 {
            out.push_str(", ");
        }
        let len = rng.range_len(8, 32);
        out.push_str(&format!("\"{}_{pairs}\": \"{}\"", rng.pick(&KEYS), base64_url(&rng.bytes(len))));
        pairs += 1;
    }
    out.push('}');
    out.into_bytes()
}

fn junk_html(n: usize, rng: &mut Rng) -> Vec<u8> {
    // Just enough HTML chrome that a header-only scanner is satisfied.
    let filler = base64_std(&rng.bytes(n.saturating_sub(200).max(64)));
    format!("<!doctype html><html><head><title>Admin</title></head><body><h1>Login</h1><!-- {filler} --></body></html>")
        .into_bytes()
}

fn junk_text(n: usize, rng: &mut Rng) -> Vec<u8> {
    base64_url(&rng.bytes((n / 4 * 3).max(48))).into_bytes()
}

/// A junk body of roughly `n` bytes in the given shape.
pub fn junk_body(kind: BodyKind, n: usize, rng: &mut Rng) -> Vec<u8> {
    let n = n.min(MAX_BODY_SEED);
    match kind {
        BodyKind::Env => junk_env(n, rng),
        BodyKind::Json => junk_json(n, rng),
        BodyKind::Html => junk_html(n, rng),
        BodyKind::Text => junk_text(n, rng),
    }
}

/// `Thu, 01 Jan 1970 00:00:00 GMT` for a Unix timestamp (RFC 9110 IMF-fixdate).
pub fn http_date(unix_secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = unix_secs / 86_400;
    let rem = unix_secs % 86_400;
    // Civil-from-days (Howard Hinnant's algorithm), valid for the whole range.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS.get(usize::try_from(days % 7).unwrap_or(0)).copied().unwrap_or("Thu"),
        MONTHS.get(usize::try_from(month - 1).unwrap_or(0)).copied().unwrap_or("Jan"),
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// A weak ETag that is stable per (path, source, hour): a scanner retrying
/// within the hour sees the same tag, so "are these all the same response?"
/// stops being a useful fingerprint.
pub fn etag(path: &str, ip: &str, hour_bucket: u64) -> String {
    let digest = hex_digest(format!("{path}|{ip}|{hour_bucket}").as_bytes());
    format!("W/\"{}\"", digest.get(..16).unwrap_or(&digest))
}

/// ETag, Last-Modified (some time in the last 30 days) and Cache-Control, so
/// the response's header shape does not say "toy server".
pub fn plausibility_headers(path: &str, ip: &str, now_secs: u64, rng: &mut Rng) -> [(&'static str, String); 3] {
    let modified = now_secs.saturating_sub(rng.range(60, 86_400 * 30));
    [
        ("ETag", etag(path, ip, now_secs / 3600)),
        ("Last-Modified", http_date(modified)),
        ("Cache-Control", "no-store, no-cache, must-revalidate".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_std(plain.as_bytes()), encoded);
            assert_eq!(base64_url(plain.as_bytes()), encoded.trim_end_matches('='));
        }
        assert_eq!(base64_std(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64_url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn mime_picks_a_plausible_type() {
        assert_eq!(mime_for("/.env"), ("text/plain; charset=utf-8", BodyKind::Env));
        assert_eq!(mime_for("/app/.env.production").1, BodyKind::Env);
        assert_eq!(mime_for("/api/v1/foo"), ("application/json", BodyKind::Json));
        assert_eq!(mime_for("/actuator/env").0, "application/json");
        assert_eq!(mime_for("/vendor/composer.json").1, BodyKind::Json);
        assert_eq!(mime_for("/admin.php"), ("text/html; charset=utf-8", BodyKind::Html));
        assert_eq!(mime_for("/.git/HEAD"), ("text/plain; charset=utf-8", BodyKind::Text));
        assert_eq!(mime_for("/.htpasswd").1, BodyKind::Text);
    }

    #[test]
    fn junk_bodies_have_a_plausible_shape() {
        let mut rng = Rng::from_seed(7);
        let env = String::from_utf8(junk_body(BodyKind::Env, 400, &mut rng)).unwrap();
        assert!(env.len() >= 400 && env.ends_with('\n'));
        assert!(env.lines().all(|l| l.split_once('=').is_some_and(|(k, v)| !k.is_empty() && !v.is_empty())));

        let json = junk_body(BodyKind::Json, 400, &mut rng);
        let doc: serde_json::Value = serde_json::from_slice(&json).expect("the JSON junk parses");
        assert!(doc.as_object().is_some_and(|o| o.len() > 3));

        let html = String::from_utf8(junk_body(BodyKind::Html, 400, &mut rng)).unwrap();
        assert!(html.starts_with("<!doctype html") && html.ends_with("</body></html>"));

        let text = junk_body(BodyKind::Text, 400, &mut rng);
        assert!(!text.is_empty() && text.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')));
    }

    #[test]
    fn body_size_is_bounded_whatever_is_asked_for() {
        let mut rng = Rng::from_seed(1);
        for kind in [BodyKind::Env, BodyKind::Json, BodyKind::Html, BodyKind::Text] {
            let huge = junk_body(kind, usize::MAX, &mut rng);
            assert!(huge.len() <= MAX_BODY_SEED * 3 / 2, "{kind:?}: {}", huge.len());
            let tiny = junk_body(kind, 0, &mut rng);
            assert!(tiny.len() < 512, "{kind:?}: {}", tiny.len());
        }
    }

    #[test]
    fn rng_ranges_are_inclusive_and_seeds_differ() {
        let mut rng = Rng::from_seed(42);
        let draws: Vec<u64> = (0..2000).map(|_| rng.range(4, 7)).collect();
        assert!(draws.iter().all(|d| (4..=7).contains(d)));
        for want in 4..=7 {
            assert!(draws.contains(&want));
        }
        assert_eq!(rng.range(9, 9), 9);
        assert_eq!(rng.range(9, 3), 9);
        for _ in 0..1000 {
            let x = rng.uniform(0.5, 2.0);
            assert!((0.5..=2.0).contains(&x));
            let swapped = rng.uniform(2.0, 0.5);
            assert!((0.5..=2.0).contains(&swapped));
        }
        assert_ne!(Rng::new().next_u64(), Rng::new().next_u64());
        assert_eq!(rng.bytes(13).len(), 13);
        assert_ne!(Rng::from_seed(0).next_u64(), 0);
    }

    #[test]
    fn http_dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(http_date(1_730_000_000), "Sun, 27 Oct 2024 03:33:20 GMT");
        assert_eq!(http_date(4_102_444_799), "Thu, 31 Dec 2099 23:59:59 GMT");
    }

    #[test]
    fn etag_is_stable_within_the_hour_per_source_and_path() {
        let a = etag("/admin.php", "1.2.3.4", 100);
        assert_eq!(a, etag("/admin.php", "1.2.3.4", 100));
        assert_ne!(a, etag("/admin.php", "9.9.9.9", 100));
        assert_ne!(a, etag("/admin.php", "1.2.3.4", 101));
        assert_ne!(a, etag("/.env", "1.2.3.4", 100));
        assert!(a.starts_with("W/\"") && a.ends_with('"') && a.len() == 3 + 16 + 1);
    }

    #[test]
    fn plausibility_headers_are_present() {
        let mut rng = Rng::from_seed(3);
        let headers = plausibility_headers("/admin.php", "1.2.3.4", 1_730_000_000, &mut rng);
        assert_eq!(headers[0].0, "ETag");
        assert!(headers[0].1.starts_with("W/\""));
        assert!(headers[1].1.ends_with(" GMT"));
        assert!(headers[2].1.contains("no-store"));
    }
}
