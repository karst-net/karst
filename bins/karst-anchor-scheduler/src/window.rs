// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The duty-cycle window arithmetic — deliberately duplicated from
//! `bins/karstd/src/ephemeral_anchor_probe.rs`'s own `window_start`, not
//! shared via a crate: there is no natural shared-crate boundary between a
//! Go/Rust control server and this standalone Rust binary that would make
//! sharing it natural, the same tradeoff `bins/karst-scaler-aws/src/enroll.rs`'s
//! own doc comment accepts for "neither crate can depend on the other."
//! Each side is independently unit-tested against the same documented
//! formula instead.

/// The start of the duty-cycle window containing `now_unix_secs`.
pub(crate) fn window_start(now_unix_secs: u64, window_period_seconds: u32) -> u64 {
    if window_period_seconds == 0 {
        return now_unix_secs;
    }
    let period = u64::from(window_period_seconds);
    (now_unix_secs / period) * period
}

/// Whether `now_unix_secs` falls inside the live (reachable) span of its
/// own duty-cycle window — `[window_start, window_start + duty_cycle_seconds)`.
/// `false` whenever `duty_cycle_seconds` is `0`: nothing is ever reachable
/// with no duty cycle configured.
pub(crate) fn in_window(
    now_unix_secs: u64,
    window_period_seconds: u32,
    duty_cycle_seconds: u32,
) -> bool {
    if duty_cycle_seconds == 0 {
        return false;
    }
    let start = window_start(now_unix_secs, window_period_seconds);
    now_unix_secs < start + u64::from(duty_cycle_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_window_is_true_only_within_the_duty_cycle_span() {
        // window_period=900, duty_cycle=300: reachable for [0,300), [900,1200), ...
        assert!(in_window(0, 900, 300));
        assert!(in_window(299, 900, 300));
        assert!(!in_window(300, 900, 300));
        assert!(!in_window(899, 900, 300));
        assert!(in_window(900, 900, 300));
        assert!(in_window(1_199, 900, 300));
        assert!(!in_window(1_200, 900, 300));
    }

    #[test]
    fn in_window_is_always_false_with_no_duty_cycle_configured() {
        for now in [0u64, 900, 1_000_000] {
            assert!(!in_window(now, 900, 0));
        }
    }

    #[test]
    fn window_start_is_idempotent_within_the_same_window() {
        assert_eq!(window_start(0, 900), 0);
        assert_eq!(window_start(899, 900), 0);
        assert_eq!(window_start(900, 900), 900);
        assert_eq!(window_start(1_799, 900), 900);
    }
}
