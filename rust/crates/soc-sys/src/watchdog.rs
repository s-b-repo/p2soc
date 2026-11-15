//! The memory watchdog's decision logic, as a pure state machine.
//!
//! On a 1 GB Pi a single leaking dashboard can OOM the box. The host samples
//! `MemAvailable` on a timer and, under sustained pressure, recycles one
//! panel — the heaviest measurable one — to reclaim memory. Two guards keep
//! it from thrashing: *hysteresis* (two consecutive low readings, so a
//! transient dip is ignored) and a *cooldown* after each successful recycle.
//!
//! The machine owns no clock and touches no panel: the caller feeds it
//! samples with a monotonic timestamp and reports back whether the recycle it
//! asked for worked. Monotonic time matters — a wall-clock step backwards
//! (NTP on a board with no RTC) must not stretch the cooldown and leave the
//! box unprotected.

use soc_core::env::parse_int;
use std::time::{Duration, Instant};

/// Tunables (`SOC_MEM_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemWatchCfg {
    /// Recycle when MemAvailable drops below this many MiB.
    pub min_avail_mb: u64,
    /// Sampling period.
    pub check_every: Duration,
    /// Minimum time between two recycles.
    pub cooldown: Duration,
}

impl Default for MemWatchCfg {
    fn default() -> Self {
        MemWatchCfg { min_avail_mb: 150, check_every: Duration::from_secs(30), cooldown: Duration::from_secs(120) }
    }
}

impl MemWatchCfg {
    /// Read the tunables through `get` (an environment lookup); garbage falls
    /// back to the default and out-of-range values are clamped.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> MemWatchCfg {
        let int = |name: &str, default: i64, lo: i64, hi: i64| {
            u64::try_from(parse_int(get(name), name, default, Some(lo), Some(hi)))
                .unwrap_or(u64::try_from(default).unwrap_or(0))
        };
        MemWatchCfg {
            min_avail_mb: int("SOC_MEM_MIN_AVAIL_MB", 150, 16, 8192),
            check_every: Duration::from_secs(int("SOC_MEM_CHECK_SEC", 30, 5, 3600)),
            cooldown: Duration::from_secs(int("SOC_MEM_RECYCLE_COOLDOWN", 120, 10, 86_400)),
        }
    }

    /// [`MemWatchCfg::from_lookup`] on the process environment.
    pub fn from_env() -> MemWatchCfg {
        MemWatchCfg::from_lookup(|name| std::env::var(name).ok())
    }
}

/// One panel as the watchdog sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelMem<'a> {
    pub id: &'a str,
    /// Summed renderer RSS in KiB; `None` when it cannot be measured (the
    /// renderer crashed, or there is no `/proc`).
    pub rss_kb: Option<u64>,
}

/// What a sample led to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Memory is fine (or unknown): the low streak is reset.
    Healthy,
    /// Low, but only once so far — could be a transient dip.
    Watching,
    /// Sustained pressure, but the last recycle was too recent.
    CoolingDown,
    /// Sustained pressure with no panel to recycle.
    NoTarget,
    /// Recycle `panels[index]`, then call [`MemWatch::recycled`] or
    /// [`MemWatch::recycle_failed`].
    Recycle { index: usize },
}

/// Index of the panel with the largest measurable RSS (the first one on a
/// tie), or `None` if none can be measured.
pub fn heaviest(panels: &[PanelMem<'_>]) -> Option<usize> {
    let mut best: Option<(usize, u64)> = None;
    for (i, p) in panels.iter().enumerate() {
        if let Some(rss) = p.rss_kb {
            if best.is_none_or(|(_, b)| rss > b) {
                best = Some((i, rss));
            }
        }
    }
    best.map(|(i, _)| i)
}

/// The watchdog state.
#[derive(Debug, Clone)]
pub struct MemWatch {
    cfg: MemWatchCfg,
    low_streak: u32,
    last_recycle: Option<Instant>,
    round_robin: usize,
}

impl MemWatch {
    pub fn new(cfg: MemWatchCfg) -> MemWatch {
        MemWatch { cfg, low_streak: 0, last_recycle: None, round_robin: 0 }
    }

    pub fn cfg(&self) -> &MemWatchCfg {
        &self.cfg
    }

    /// Consecutive low readings so far.
    pub fn low_streak(&self) -> u32 {
        self.low_streak
    }

    /// Feed one `MemAvailable` reading (MiB; `None` when unreadable) taken at
    /// `now`, with the panels' current memory.
    pub fn sample(&mut self, avail_mb: Option<u64>, now: Instant, panels: &[PanelMem<'_>]) -> Verdict {
        if !avail_mb.is_some_and(|a| a < self.cfg.min_avail_mb) {
            self.low_streak = 0;
            return Verdict::Healthy;
        }
        self.low_streak = self.low_streak.saturating_add(1);
        if self.low_streak < 2 {
            return Verdict::Watching;
        }
        if self.last_recycle.is_some_and(|last| now.saturating_duration_since(last) < self.cfg.cooldown) {
            return Verdict::CoolingDown;
        }
        match self.pick(panels) {
            Some(index) => Verdict::Recycle { index },
            None => Verdict::NoTarget,
        }
    }

    /// The heaviest panel by renderer RSS. Round-robin only when no panel can
    /// be measured at all, so the watchdog still does something.
    fn pick(&mut self, panels: &[PanelMem<'_>]) -> Option<usize> {
        if let Some(i) = heaviest(panels) {
            return Some(i);
        }
        if panels.is_empty() {
            return None;
        }
        let i = self.round_robin % panels.len();
        self.round_robin = self.round_robin.wrapping_add(1);
        Some(i)
    }

    /// The requested recycle succeeded: start the cooldown, reset hysteresis.
    pub fn recycled(&mut self, now: Instant) {
        self.last_recycle = Some(now);
        self.low_streak = 0;
    }

    /// The requested recycle failed and reclaimed nothing while memory is
    /// still critical. The cooldown is *not* consumed and the streak is kept
    /// at one, so a single further low reading retries — otherwise the
    /// watchdog would sit out a full cooldown while the box gets OOM-killed.
    pub fn recycle_failed(&mut self) {
        self.low_streak = 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panels<'a>(spec: &[(&'a str, Option<u64>)]) -> Vec<PanelMem<'a>> {
        spec.iter().map(|(id, rss_kb)| PanelMem { id, rss_kb: *rss_kb }).collect()
    }

    fn watch(cooldown_secs: u64) -> MemWatch {
        MemWatch::new(MemWatchCfg { cooldown: Duration::from_secs(cooldown_secs), ..MemWatchCfg::default() })
    }

    #[test]
    fn heaviest_panel_picks_max_rss() {
        assert_eq!(heaviest(&panels(&[("a", Some(100)), ("b", None), ("c", Some(300))])), Some(2));
        assert_eq!(heaviest(&panels(&[("b", None)])), None);
        assert_eq!(heaviest(&[]), None);
        assert_eq!(heaviest(&panels(&[("a", Some(5)), ("b", Some(5))])), Some(0), "first wins a tie");
        assert_eq!(heaviest(&panels(&[("a", Some(0))])), Some(0), "a zero reading is still a measurement");
    }

    #[test]
    fn a_single_dip_is_ignored() {
        let mut w = watch(120);
        let ps = panels(&[("a", Some(1))]);
        let t = Instant::now();
        assert_eq!(w.sample(Some(10), t, &ps), Verdict::Watching);
        assert_eq!(w.sample(Some(500), t, &ps), Verdict::Healthy);
        assert_eq!(w.sample(Some(10), t, &ps), Verdict::Watching, "the streak restarted");
        assert_eq!(w.sample(Some(10), t, &ps), Verdict::Recycle { index: 0 });
    }

    #[test]
    fn unknown_memory_is_not_pressure() {
        let mut w = watch(0);
        let ps = panels(&[("a", Some(1))]);
        let t = Instant::now();
        assert_eq!(w.sample(Some(10), t, &ps), Verdict::Watching);
        assert_eq!(w.sample(None, t, &ps), Verdict::Healthy);
        assert_eq!(w.low_streak(), 0);
    }

    #[test]
    fn the_floor_is_exclusive() {
        let mut w = watch(0);
        assert_eq!(w.sample(Some(150), Instant::now(), &[]), Verdict::Healthy);
        assert_eq!(w.sample(Some(149), Instant::now(), &[]), Verdict::Watching);
    }

    #[test]
    fn recycles_the_heaviest_panel_every_time() {
        let mut w = watch(0);
        let ps = panels(&[("a", Some(100)), ("b", Some(900)), ("c", Some(300))]);
        let t = Instant::now();
        let mut hits = [0; 3];
        w.sample(Some(10), t, &ps);
        for _ in 0..3 {
            w.recycle_failed(); // re-arm: the next low reading acts
            if let Verdict::Recycle { index } = w.sample(Some(10), t, &ps) {
                hits[index] += 1;
                w.recycled(t);
            }
        }
        assert_eq!(hits, [0, 3, 0]);
    }

    #[test]
    fn skips_a_panel_with_nothing_to_measure() {
        let mut w = watch(0);
        let ps = panels(&[("crashed", None), ("live", Some(5))]);
        let t = Instant::now();
        w.sample(Some(10), t, &ps);
        assert_eq!(w.sample(Some(10), t, &ps), Verdict::Recycle { index: 1 });
    }

    #[test]
    fn round_robin_is_only_the_no_proc_fallback() {
        let mut w = watch(0);
        let ps = panels(&[("a", None), ("b", None)]);
        let t = Instant::now();
        w.sample(Some(10), t, &ps);
        let mut order = Vec::new();
        for _ in 0..3 {
            if let Verdict::Recycle { index } = w.sample(Some(10), t, &ps) {
                order.push(index);
            }
        }
        assert_eq!(order, [0, 1, 0]);
    }

    #[test]
    fn no_panels_means_no_target() {
        let mut w = watch(0);
        let t = Instant::now();
        w.sample(Some(10), t, &[]);
        assert_eq!(w.sample(Some(10), t, &[]), Verdict::NoTarget);
    }

    #[test]
    fn cooldown_spaces_out_recycles() {
        let mut w = watch(120);
        let ps = panels(&[("a", Some(1))]);
        let t0 = Instant::now();
        w.sample(Some(10), t0, &ps);
        assert_eq!(w.sample(Some(10), t0, &ps), Verdict::Recycle { index: 0 }, "the first recycle is never delayed");
        w.recycled(t0);
        assert_eq!(w.low_streak(), 0);
        assert_eq!(w.sample(Some(10), t0 + Duration::from_secs(30), &ps), Verdict::Watching);
        assert_eq!(w.sample(Some(10), t0 + Duration::from_secs(60), &ps), Verdict::CoolingDown);
        assert_eq!(w.sample(Some(10), t0 + Duration::from_secs(119), &ps), Verdict::CoolingDown);
        assert_eq!(w.sample(Some(10), t0 + Duration::from_secs(120), &ps), Verdict::Recycle { index: 0 });
    }

    #[test]
    fn a_failed_recycle_retries_on_the_next_low_reading() {
        let mut w = watch(120);
        let ps = panels(&[("a", Some(1))]);
        let t = Instant::now();
        w.sample(Some(10), t, &ps);
        assert_eq!(w.sample(Some(10), t, &ps), Verdict::Recycle { index: 0 });
        w.recycle_failed();
        assert_eq!(w.low_streak(), 1);
        // no cooldown was consumed: one more low reading asks again
        assert_eq!(w.sample(Some(10), t + Duration::from_secs(30), &ps), Verdict::Recycle { index: 0 });
    }

    #[test]
    fn a_timestamp_before_the_last_recycle_cannot_panic_or_skip_the_cooldown() {
        let mut w = watch(120);
        let ps = panels(&[("a", Some(1))]);
        let t = Instant::now() + Duration::from_secs(1000);
        w.recycled(t);
        w.sample(Some(10), t - Duration::from_secs(500), &ps);
        assert_eq!(w.sample(Some(10), t - Duration::from_secs(500), &ps), Verdict::CoolingDown);
    }

    #[test]
    fn tunables_are_clamped_and_survive_garbage() {
        let cfg = MemWatchCfg::from_lookup(|name| match name {
            "SOC_MEM_MIN_AVAIL_MB" => Some("4".into()),
            "SOC_MEM_CHECK_SEC" => Some("soon".into()),
            "SOC_MEM_RECYCLE_COOLDOWN" => Some("1".into()),
            _ => None,
        });
        assert_eq!(cfg.min_avail_mb, 16);
        assert_eq!(cfg.check_every, Duration::from_secs(30));
        assert_eq!(cfg.cooldown, Duration::from_secs(10));
        assert_eq!(MemWatchCfg::from_lookup(|_| None), MemWatchCfg::default());
    }
}
