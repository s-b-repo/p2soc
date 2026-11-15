//! Bounded per-source bookkeeping: an LRU map, the rate limiter and the hit
//! counter built on it.
//!
//! Everything a remote peer can make the tarpit remember lives in one of
//! these, and each has a hard entry cap — a flood from a million addresses
//! keeps only the most recent few thousand, so memory is bounded forever.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A map that forgets its least-recently-written entries beyond `cap`.
///
/// Recency is tracked with a queue of `(key, stamp)` records; a record whose
/// stamp no longer matches the map's is stale and skipped. The queue is
/// compacted when stale records outnumber live ones, so both structures stay
/// proportional to `cap`.
#[derive(Debug)]
pub struct Lru<K, V> {
    map: HashMap<K, (V, u64)>,
    order: VecDeque<(K, u64)>,
    stamp: u64,
    cap: usize,
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    pub fn new(cap: usize) -> Lru<K, V> {
        Lru { map: HashMap::new(), order: VecDeque::new(), stamp: 0, cap: cap.max(1) }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Remove and return the value for `key`.
    pub fn take(&mut self, key: &K) -> Option<V> {
        self.map.remove(key).map(|(v, _)| v)
    }

    /// Insert `key` as the newest entry, evicting the oldest beyond the cap.
    pub fn put(&mut self, key: K, value: V) {
        self.stamp += 1;
        self.order.push_back((key.clone(), self.stamp));
        self.map.insert(key, (value, self.stamp));
        while self.map.len() > self.cap {
            let Some((old, stamp)) = self.order.pop_front() else { break };
            if self.map.get(&old).is_some_and(|(_, s)| *s == stamp) {
                self.map.remove(&old);
            }
        }
        if self.order.len() > self.map.len() * 2 + 64 {
            let map = &self.map;
            self.order.retain(|(k, stamp)| map.get(k).is_some_and(|(_, s)| s == stamp));
        }
    }

    /// Live entries, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.order.iter().filter_map(|(k, stamp)| self.map.get(k).filter(|(_, s)| s == stamp).map(|(v, _)| (k, v)))
    }

    #[cfg(test)]
    fn queue_len(&self) -> usize {
        self.order.len()
    }
}

/// Per-source leaky bucket: at most `burst` hits, leaking one per `window`.
///
/// Limiting per source rather than globally means one noisy scanner cannot
/// shoulder out a quiet one.
#[derive(Debug)]
pub struct RateLimiter<K> {
    buckets: Lru<K, (Instant, u32)>,
    burst: u32,
    window: Duration,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    pub fn new(burst: u32, window: Duration, cap: usize) -> RateLimiter<K> {
        RateLimiter { buckets: Lru::new(cap), burst: burst.max(1), window: window.max(Duration::from_millis(1)) }
    }

    /// Whether a hit from `key` at `now` is within its budget.
    pub fn allow_at(&mut self, key: K, now: Instant) -> bool {
        let Some((last, count)) = self.buckets.take(&key) else {
            self.buckets.put(key, (now, 1));
            return true;
        };
        let elapsed = now.saturating_duration_since(last);
        // Whole windows elapsed; a zero window drains the bucket at once.
        let leaked = elapsed.as_nanos().checked_div(self.window.as_nanos()).unwrap_or(u128::MAX);
        let remaining = u32::try_from(leaked).map_or(0, |leaked| count.saturating_sub(leaked));
        if remaining >= self.burst {
            // Re-insert without moving the window head, so the source stays
            // capped until time — not more requests — drains its bucket.
            self.buckets.put(key, (last, self.burst));
            return false;
        }
        self.buckets.put(key, (now, remaining + 1));
        true
    }

    pub fn allow(&mut self, key: K) -> bool {
        self.allow_at(key, Instant::now())
    }

    /// Sources currently remembered.
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

/// How often each source was served, for the metrics dump. Exact counts under
/// heavy load are not needed — only the top offenders.
#[derive(Debug)]
pub struct HitCounter<K> {
    counts: Lru<K, u64>,
}

impl<K: Hash + Eq + Clone> HitCounter<K> {
    pub fn new(cap: usize) -> HitCounter<K> {
        HitCounter { counts: Lru::new(cap) }
    }

    pub fn bump(&mut self, key: K) {
        let n = self.counts.take(&key).unwrap_or(0).saturating_add(1);
        self.counts.put(key, n);
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.counts.contains(key)
    }

    /// The `n` sources with the most hits, highest first.
    pub fn top(&self, n: usize) -> Vec<(K, u64)> {
        let mut all: Vec<(K, u64)> = self.counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        all.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        all.truncate(n);
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_the_oldest_write() {
        let mut lru = Lru::new(3);
        for k in ["a", "b", "c"] {
            lru.put(k, 0);
        }
        // rewriting "a" makes it the newest
        let v = lru.take(&"a").unwrap();
        lru.put("a", v + 1);
        lru.put("d", 0);
        assert_eq!(lru.len(), 3);
        assert!(!lru.contains(&"b") && lru.contains(&"a") && lru.contains(&"d"));
        assert_eq!(lru.iter().map(|(k, _)| *k).collect::<Vec<_>>(), ["c", "a", "d"]);
    }

    #[test]
    fn lru_bookkeeping_stays_bounded_under_churn() {
        let mut lru = Lru::new(8);
        for i in 0..100_000u32 {
            // hammer a few keys (stale queue records) and a stream of new ones
            lru.put(i % 4, i);
            lru.put(1000 + i, i);
        }
        assert_eq!(lru.len(), 8);
        assert!(lru.queue_len() <= 8 * 2 + 64 + 1, "{}", lru.queue_len());
    }

    #[test]
    fn a_zero_cap_still_holds_one_entry() {
        let mut lru = Lru::new(0);
        lru.put(1, ());
        lru.put(2, ());
        assert_eq!(lru.len(), 1);
    }

    #[test]
    fn limiter_caps_burst_then_leaks() {
        let mut rl = RateLimiter::new(3, Duration::from_millis(50), 4096);
        let t = Instant::now();
        let got: Vec<bool> = (0..5).map(|_| rl.allow_at("9.9.9.9", t)).collect();
        assert_eq!(got, [true, true, true, false, false]);
        // still capped just before a full window has passed
        assert!(!rl.allow_at("9.9.9.9", t + Duration::from_millis(49)));
        // one window later one token has leaked
        assert!(rl.allow_at("9.9.9.9", t + Duration::from_millis(120)));
    }

    #[test]
    fn hammering_while_capped_does_not_extend_the_ban() {
        let mut rl = RateLimiter::new(2, Duration::from_secs(1), 16);
        let t = Instant::now();
        assert!(rl.allow_at("x", t) && rl.allow_at("x", t));
        for ms in (100..1000).step_by(100) {
            assert!(!rl.allow_at("x", t + Duration::from_millis(ms)));
        }
        assert!(rl.allow_at("x", t + Duration::from_millis(1000)));
    }

    #[test]
    fn limiter_is_per_source() {
        let mut rl = RateLimiter::new(2, Duration::from_secs(1), 16);
        let t = Instant::now();
        assert!(rl.allow_at("1.1.1.1", t) && rl.allow_at("1.1.1.1", t));
        assert!(!rl.allow_at("1.1.1.1", t));
        assert!(rl.allow_at("2.2.2.2", t));
    }

    #[test]
    fn limiter_memory_is_bounded() {
        let mut rl = RateLimiter::new(1, Duration::from_secs(60), 4);
        for i in 0..20 {
            rl.allow(format!("10.0.0.{i}"));
        }
        assert!(rl.tracked() <= 4);
    }

    #[test]
    fn degenerate_limits_are_clamped() {
        let mut rl = RateLimiter::new(0, Duration::ZERO, 0);
        let t = Instant::now();
        assert!(rl.allow_at("x", t), "a zero burst still allows one hit");
        assert!(!rl.allow_at("x", t));
    }

    #[test]
    fn a_time_before_the_last_hit_does_not_panic() {
        let mut rl = RateLimiter::new(2, Duration::from_secs(1), 4);
        let t = Instant::now() + Duration::from_secs(10);
        assert!(rl.allow_at("x", t));
        assert!(rl.allow_at("x", t - Duration::from_secs(5)));
        assert!(!rl.allow_at("x", t - Duration::from_secs(5)));
    }

    #[test]
    fn hit_counter_evicts_the_oldest_source() {
        let mut hits = HitCounter::new(8);
        for i in 0..12 {
            hits.bump(format!("10.0.0.{i}"));
        }
        assert_eq!(hits.len(), 8);
        assert!(hits.contains(&"10.0.0.11".to_string()));
        assert!(!hits.contains(&"10.0.0.0".to_string()));
    }

    #[test]
    fn top_sources_come_highest_first() {
        let mut hits = HitCounter::new(4096);
        for i in 1..=30u64 {
            for _ in 0..i {
                hits.bump(format!("203.0.113.{i}"));
            }
        }
        let top = hits.top(20);
        assert_eq!(top.len(), 20);
        assert_eq!(top[0], ("203.0.113.30".to_string(), 30));
        assert!(top.windows(2).all(|w| w[0].1 >= w[1].1));
    }
}
