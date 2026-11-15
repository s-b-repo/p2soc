//! Exponential backoff.

/// `initial, initial*factor, ...` capped at `maximum` (seconds).
#[derive(Debug, Clone, PartialEq)]
pub struct Backoff {
    pub initial: f64,
    pub maximum: f64,
    pub factor: f64,
    next: f64,
}

impl Backoff {
    pub fn new(initial: f64, maximum: f64) -> Backoff {
        Backoff { initial, maximum, factor: 2.0, next: initial }
    }

    /// The delay to wait now; the following one is longer.
    pub fn next_delay(&mut self) -> f64 {
        let delay = self.next;
        self.next = (self.next * self.factor).min(self.maximum);
        delay
    }

    pub fn reset(&mut self) {
        self.next = self.initial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_caps_and_resets() {
        let mut b = Backoff::new(5.0, 60.0);
        let seen: Vec<f64> = (0..5).map(|_| b.next_delay()).collect();
        assert_eq!(seen, vec![5.0, 10.0, 20.0, 40.0, 60.0]);
        assert_eq!(b.next_delay(), 60.0);
        b.reset();
        assert_eq!(b.next_delay(), 5.0);
    }

    #[test]
    fn a_ceiling_below_the_floor_never_grows() {
        let mut b = Backoff::new(5.0, 3.0);
        assert_eq!(b.next_delay(), 5.0);
        assert_eq!(b.next_delay(), 3.0);
    }
}
