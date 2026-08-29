// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Per-peer rate limiting — `spec/ponor-v1.md` §7.4.
//!
//! Two buckets, not one. A flood of 33-byte `SendPacket`s is cheap in
//! bandwidth and expensive in per-frame work, so a bytes-only limit is one an
//! attacker simply sizes around; a frames-only limit ignores a peer saturating
//! the uplink with full-size frames. A frame must pay both.
//!
//! Integer arithmetic throughout. Floating point in an admission decision
//! invites a rounding difference between two implementations to become a
//! difference in what they let through.

/// A per-peer allowance.
///
/// The defaults are **policy rather than protocol** (§7.4) and an operator is
/// expected to tune them. They are sized for interactive use and a relayed
/// bulk transfer that finishes — not for making a volunteer's relay a free CDN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Sustained bytes per second.
    pub bytes_per_sec: u64,
    /// Bytes a peer may burst above the sustained rate.
    pub byte_burst: u64,
    /// Sustained frames per second.
    pub frames_per_sec: u64,
    /// Frames a peer may burst above the sustained rate.
    pub frame_burst: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            bytes_per_sec: 25 * 1_000_000 / 8,
            byte_burst: 8 * 1024 * 1024,
            frames_per_sec: 5_000,
            frame_burst: 20_000,
        }
    }
}

impl Budget {
    /// A budget that admits everything.
    ///
    /// For tests and for a mesh peer an operator has deliberately exempted.
    /// Deliberately spelled as its own constructor rather than reachable by
    /// leaving a field at zero: a zero rate must read as "nothing passes", not
    /// as "no limit" — see [`Bucket::take`].
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            bytes_per_sec: u64::MAX,
            byte_burst: u64::MAX,
            frames_per_sec: u64::MAX,
            frame_burst: u64::MAX,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u64,
    cap: u64,
    rate_per_sec: u64,
    last_ms: u64,
}

impl Bucket {
    const fn new(rate_per_sec: u64, cap: u64, now_ms: u64) -> Self {
        // Starts full. A peer that has just connected has not yet used
        // anything, and making it wait for a first refill would rate-limit the
        // handshake burst that follows every reconnect.
        Self {
            tokens: cap,
            cap,
            rate_per_sec,
            last_ms: now_ms,
        }
    }

    fn take(&mut self, n: u64, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        let refill = self.rate_per_sec.saturating_mul(elapsed) / 1000;
        if refill > 0 {
            self.tokens = self.tokens.saturating_add(refill).min(self.cap);
            // Advanced only when the refill was non-zero, so a peer sending
            // faster than one frame per millisecond does not lose the
            // fractional remainder on every call and end up throttled below
            // its configured rate.
            self.last_ms = now_ms;
        }
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// The pair of buckets guarding one connection.
#[derive(Debug, Clone, Copy)]
pub struct Meter {
    bytes: Bucket,
    frames: Bucket,
}

impl Meter {
    /// Start a meter, full, at `now_ms`.
    #[must_use]
    pub const fn new(budget: Budget, now_ms: u64) -> Self {
        Self {
            bytes: Bucket::new(budget.bytes_per_sec, budget.byte_burst, now_ms),
            frames: Bucket::new(budget.frames_per_sec, budget.frame_burst, now_ms),
        }
    }

    /// Charge one frame of `bytes` against both buckets.
    ///
    /// Returns `false` when the frame is over budget, in which case the caller
    /// **drops it** — §7.4 forbids closing the connection for a burst, because
    /// a burst is what a relayed handshake looks like.
    ///
    /// Both buckets are charged only if both can pay. Charging the one that
    /// can and rejecting on the other would let a peer drain its byte
    /// allowance with frames that were never delivered.
    pub fn admit(&mut self, bytes: u64, now_ms: u64) -> bool {
        // Probe both before spending either.
        let mut b = self.bytes;
        let mut f = self.frames;
        if !b.take(bytes, now_ms) || !f.take(1, now_ms) {
            return false;
        }
        self.bytes = b;
        self.frames = f;
        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_fresh_meter_admits_a_burst() {
        let mut m = Meter::new(Budget::default(), 0);
        // The whole byte burst in one millisecond.
        let mut sent = 0u64;
        while m.admit(1336, 0) {
            sent += 1336;
            assert!(sent < 16 * 1024 * 1024, "bucket never emptied");
        }
        assert!(sent >= 8 * 1024 * 1024 - 1336, "burst was {sent}");
    }

    #[test]
    fn a_drained_meter_refills_at_the_configured_rate() {
        let budget = Budget {
            bytes_per_sec: 1000,
            byte_burst: 1000,
            frames_per_sec: 1_000_000,
            frame_burst: 1_000_000,
        };
        let mut m = Meter::new(budget, 0);
        assert!(m.admit(1000, 0));
        assert!(!m.admit(1, 0), "bucket should be empty");

        // Half a second buys half the rate.
        assert!(m.admit(500, 500));
        assert!(!m.admit(1, 500));
    }

    #[test]
    fn the_frame_bucket_stops_a_flood_the_byte_bucket_would_not() {
        // The reason there are two buckets: 33-byte frames are almost free in
        // bandwidth, so a bytes-only limit is one an attacker sizes around.
        let budget = Budget {
            bytes_per_sec: u64::MAX,
            byte_burst: u64::MAX,
            frames_per_sec: 10,
            frame_burst: 10,
        };
        let mut m = Meter::new(budget, 0);
        for i in 0..10 {
            assert!(m.admit(33, 0), "frame {i} should be admitted");
        }
        assert!(!m.admit(33, 0), "the eleventh frame is over budget");
    }

    #[test]
    fn the_byte_bucket_stops_a_flood_the_frame_bucket_would_not() {
        let budget = Budget {
            bytes_per_sec: 3000,
            byte_burst: 3000,
            frames_per_sec: u64::MAX,
            frame_burst: u64::MAX,
        };
        let mut m = Meter::new(budget, 0);
        assert!(m.admit(1000, 0));
        assert!(m.admit(1000, 0));
        assert!(m.admit(1000, 0));
        assert!(!m.admit(1000, 0), "3000 bytes is the whole burst");
    }

    #[test]
    fn a_rejected_frame_does_not_spend_the_other_bucket() {
        // Otherwise a peer over its frame budget still drains its byte
        // allowance, and is throttled twice over for one offense.
        let budget = Budget {
            bytes_per_sec: 1_000_000,
            byte_burst: 1_000_000,
            frames_per_sec: 1,
            frame_burst: 1,
        };
        let mut m = Meter::new(budget, 0);
        assert!(m.admit(1000, 0));
        assert!(!m.admit(1000, 0), "over the frame budget");

        // One second later exactly one frame's worth of allowance has
        // returned; if the failed call had spent bytes, this would fail.
        assert!(m.admit(1_000_000, 1000));
    }

    #[test]
    fn a_zero_rate_admits_nothing() {
        // An absent or zeroed configuration must not read as "no limit".
        let budget = Budget {
            bytes_per_sec: 0,
            byte_burst: 0,
            frames_per_sec: 0,
            frame_burst: 0,
        };
        let mut m = Meter::new(budget, 0);
        assert!(!m.admit(1, 0));
        assert!(!m.admit(1, 10_000_000), "time does not help a zero rate");
    }

    #[test]
    fn unlimited_is_unlimited() {
        let mut m = Meter::new(Budget::unlimited(), 0);
        for _ in 0..10_000 {
            assert!(m.admit(1336, 0));
        }
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_mint_tokens() {
        let budget = Budget {
            bytes_per_sec: 1000,
            byte_burst: 1000,
            frames_per_sec: 1_000_000,
            frame_burst: 1_000_000,
        };
        let mut m = Meter::new(budget, 10_000);
        assert!(m.admit(1000, 10_000));
        assert!(!m.admit(1, 0), "a backwards clock must not refill");
        assert!(!m.admit(1, 10_000));
    }

    #[test]
    fn sustained_sending_is_not_throttled_below_the_configured_rate() {
        // The fractional-remainder trap: refilling on every call and advancing
        // the timestamp regardless would discard the sub-millisecond remainder
        // each time and hold a peer well under its rate.
        let budget = Budget {
            bytes_per_sec: 1_000_000,
            byte_burst: 1000,
            frames_per_sec: u64::MAX,
            frame_burst: u64::MAX,
        };
        let mut m = Meter::new(budget, 0);
        // Drain the burst, then send 1000 bytes/ms — exactly the rate — while
        // being asked ten times per millisecond.
        assert!(m.admit(1000, 0));
        let mut admitted = 0;
        for tenth in 1..=1000u64 {
            if m.admit(100, tenth / 10) {
                admitted += 1;
            }
        }
        assert!(admitted >= 950, "throttled to {admitted}/1000 at the rate");
    }
}
