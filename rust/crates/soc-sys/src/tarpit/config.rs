//! Tarpit tunables (`SOC_TARPIT_*`).
//!
//! Every value is clamped to a sane range and garbage falls back to the
//! default with a warning: a typo in `tarpit.env` must not crash-loop the
//! unit, and no setting can remove a resource bound.

use soc_core::env::{parse_float, parse_int};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct TarpitConfig {
    /// Bind address (an IPv6 literal selects an IPv6 socket).
    pub host: String,
    pub port: u16,
    /// Per-source rate: at most `burst` hits, then one per `window`.
    pub burst: u32,
    pub window: Duration,
    /// Each matched request sleeps this long before answering.
    pub drip_min: Duration,
    pub drip_max: Duration,
    /// Matched requests answered concurrently; beyond it they are dropped.
    pub max_workers: usize,
    /// Hard cap on open connections (and therefore threads) of any kind.
    pub max_conns: usize,
    /// Total time a client has to deliver its request head.
    pub conn_timeout: Duration,
    /// Extra paths, re-read on SIGHUP.
    pub paths_file: PathBuf,
    /// Sources remembered by the rate limiter and the hit counter.
    pub hit_cap: usize,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        TarpitConfig {
            host: "0.0.0.0".into(),
            port: 80,
            burst: 8,
            window: Duration::from_secs(2),
            drip_min: Duration::from_millis(500),
            drip_max: Duration::from_secs(2),
            max_workers: 64,
            max_conns: 96,
            conn_timeout: Duration::from_secs(5),
            paths_file: PathBuf::from("/etc/soc-display/tarpit-paths.list"),
            hit_cap: 4096,
        }
    }
}

impl TarpitConfig {
    /// Read the tunables through `get` (an environment lookup).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> TarpitConfig {
        let d = TarpitConfig::default();
        let int = |name: &str, default: i64, lo: i64, hi: i64| parse_int(get(name), name, default, Some(lo), Some(hi));
        let secs = |name: &str, default: Duration, lo: f64, hi: f64| {
            Duration::from_secs_f64(parse_float(get(name), name, default.as_secs_f64(), Some(lo), Some(hi)))
        };
        let max_workers = usize::try_from(int("SOC_TARPIT_MAX_WORKERS", 64, 1, 512)).unwrap_or(64);
        let drip_a = secs("SOC_TARPIT_DRIP_MIN", d.drip_min, 0.0, 60.0);
        let drip_b = secs("SOC_TARPIT_DRIP_MAX", d.drip_max, 0.0, 60.0);
        TarpitConfig {
            host: get("SOC_TARPIT_HOST").map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).unwrap_or(d.host),
            port: u16::try_from(int("SOC_TARPIT_PORT", 80, 1, 65535)).unwrap_or(80),
            burst: u32::try_from(int("SOC_TARPIT_BURST", 8, 1, 10_000)).unwrap_or(8),
            window: secs("SOC_TARPIT_WINDOW", d.window, 0.001, 3600.0),
            drip_min: drip_a.min(drip_b),
            drip_max: drip_a.max(drip_b),
            max_workers,
            // Room for clients still sending their request (or getting a 404)
            // on top of the ones being dripped.
            max_conns: usize::try_from(int(
                "SOC_TARPIT_MAX_CONNS",
                i64::try_from(max_workers).unwrap_or(64) + 32,
                1,
                1024,
            ))
            .unwrap_or(96),
            conn_timeout: secs("SOC_TARPIT_CONN_TIMEOUT", d.conn_timeout, 0.1, 60.0),
            paths_file: get("SOC_TARPIT_PATHS_FILE").filter(|p| !p.is_empty()).map_or(d.paths_file, PathBuf::from),
            hit_cap: usize::try_from(int("SOC_TARPIT_HIT_CAP", 4096, 1, 65_536)).unwrap_or(4096),
        }
    }

    pub fn from_env() -> TarpitConfig {
        TarpitConfig::from_lookup(|name| std::env::var(name).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| (*v).to_string())
    }

    #[test]
    fn defaults_match_the_documented_ones() {
        assert_eq!(TarpitConfig::from_lookup(|_| None), TarpitConfig::default());
        // an empty value means "unset", as in an env file with `KEY=`
        assert_eq!(TarpitConfig::from_lookup(lookup(&[("SOC_TARPIT_PORT", ""), ("SOC_TARPIT_HOST", " ")])).port, 80);
    }

    #[test]
    fn values_are_read_and_clamped() {
        let cfg = TarpitConfig::from_lookup(lookup(&[
            ("SOC_TARPIT_HOST", "::"),
            ("SOC_TARPIT_PORT", "8080"),
            ("SOC_TARPIT_BURST", "0"),
            ("SOC_TARPIT_WINDOW", "0"),
            ("SOC_TARPIT_DRIP_MIN", "9"),
            ("SOC_TARPIT_DRIP_MAX", "1"),
            ("SOC_TARPIT_MAX_WORKERS", "100000"),
            ("SOC_TARPIT_CONN_TIMEOUT", "86400"),
            ("SOC_TARPIT_HIT_CAP", "-5"),
            ("SOC_TARPIT_PATHS_FILE", "/tmp/p.list"),
        ]));
        assert_eq!((cfg.host.as_str(), cfg.port), ("::", 8080));
        assert_eq!(cfg.burst, 1);
        assert_eq!(cfg.window, Duration::from_millis(1));
        assert_eq!((cfg.drip_min, cfg.drip_max), (Duration::from_secs(1), Duration::from_secs(9)), "swapped bounds");
        assert_eq!((cfg.max_workers, cfg.max_conns), (512, 544));
        assert_eq!(cfg.conn_timeout, Duration::from_secs(60));
        assert_eq!(cfg.hit_cap, 1);
        assert_eq!(cfg.paths_file, PathBuf::from("/tmp/p.list"));
    }

    #[test]
    fn garbage_falls_back_instead_of_crashing() {
        let cfg = TarpitConfig::from_lookup(lookup(&[
            ("SOC_TARPIT_PORT", "eighty"),
            ("SOC_TARPIT_WINDOW", "nan"),
            ("SOC_TARPIT_DRIP_MAX", "soon"),
            ("SOC_TARPIT_MAX_WORKERS", "1e3"),
            ("SOC_TARPIT_PORT_EXTRA", "1"),
        ]));
        assert_eq!(cfg, TarpitConfig::default());
    }
}
