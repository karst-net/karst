// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Noticing that this machine stopped running and started again.
//!
//! A laptop suspends. When it comes back, every UDP source address may be
//! different, every NAT binding is gone, and the paths discovery measured
//! before the lid closed are measurements of a network this node is no longer
//! on. Karst already re-probes when it notices — [`crate::disco`] on a path
//! change, and the run loop's interface scan every fifteen seconds — so the
//! requirement here is not new machinery but *promptness*: a resume should
//! trigger rediscovery at once rather than at the end of whichever timer
//! happens to fire first.
//!
//! # Why a clock gap, and not a platform notification
//!
//! The direct answer on macOS is an `IOKit` power notification, and on Linux a
//! `systemd-logind` `PrepareForSleep` signal. Both mean platform-specific code
//! on the path that recovers connectivity — an FFI dependency under ADR-0003 in
//! one case, a bus subscription in the other — and both would be a second
//! mechanism to test on a machine that has to be physically suspended to test
//! it at all.
//!
//! The run loop already ticks every hundred milliseconds. A tick that arrives
//! seconds late is a tick the machine did not run, whatever the reason, and
//! "the machine did not run for a while" is precisely the condition that
//! invalidates the measurements. So this reads the clocks the loop already has
//! and needs no platform code, no privileges, and no notification to arrive.
//!
//! **Both clocks, and the larger gap wins.** Whether a monotonic clock counts
//! time spent asleep is a platform decision: Darwin's `CLOCK_MONOTONIC` does,
//! Linux's does not (that is `CLOCK_BOOTTIME`). Reading the wall clock as well
//! covers the platform whose monotonic clock stops, and reading the monotonic
//! clock covers the case the wall clock cannot distinguish — a process starved
//! or stopped, on a host whose wall clock is being stepped by NTP at the same
//! moment.
//!
//! # What it costs to be wrong
//!
//! A false positive costs one round of probes and one `CallMeMaybe` per peer —
//! the same work the fifteen-second interface scan already does when an address
//! changes. That asymmetry is why the threshold is set where it is: missing a
//! resume costs a user their connection until a timer fires, and imagining one
//! costs a few datagrams.

use std::time::{Duration, Instant, SystemTime};

/// How late a tick must be before it reads as a resume rather than as an
/// ordinary scheduling delay.
///
/// The loop asks for a hundred milliseconds. Five seconds is fifty times that
/// — far outside anything ordinary scheduling produces, and comfortably inside
/// the fifteen-second interface scan, so a resume is always noticed sooner than
/// the scan would have noticed it.
pub const GAP: Duration = Duration::from_secs(5);

/// Watches the interval between successive ticks of the run loop.
#[derive(Debug)]
pub struct Detector {
    monotonic: Instant,
    wall: SystemTime,
    gap: Duration,
}

impl Detector {
    /// Start watching, from now.
    #[must_use]
    pub fn new() -> Self {
        Self::with_gap(Instant::now(), SystemTime::now(), GAP)
    }

    /// Start watching from explicit readings, for tests and for a caller that
    /// wants a different threshold.
    #[must_use]
    pub fn with_gap(monotonic: Instant, wall: SystemTime, gap: Duration) -> Self {
        Self {
            monotonic,
            wall,
            gap,
        }
    }

    /// Record one tick. `Some(gap)` means the machine was not running for that
    /// long and whatever discovery measured beforehand should be re-measured.
    pub fn tick(&mut self) -> Option<Duration> {
        self.observe(Instant::now(), SystemTime::now())
    }

    /// The clock arithmetic on its own, so the decision can be tested without
    /// suspending anything.
    ///
    /// A wall clock that moves *backwards* — an NTP step, or a user changing
    /// the date — yields no gap rather than a negative one, and is not a
    /// resume: `duration_since` fails, and the monotonic reading still decides.
    pub fn observe(&mut self, monotonic: Instant, wall: SystemTime) -> Option<Duration> {
        let monotonic_gap = monotonic.saturating_duration_since(self.monotonic);
        let wall_gap = wall
            .duration_since(self.wall)
            .unwrap_or(Duration::from_secs(0));
        self.monotonic = monotonic;
        self.wall = wall;
        let gap = monotonic_gap.max(wall_gap);
        (gap >= self.gap).then_some(gap)
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn start() -> (Instant, SystemTime) {
        (
            Instant::now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
    }

    #[test]
    fn an_ordinary_tick_is_not_a_resume() {
        let (monotonic, wall) = start();
        let mut detector = Detector::with_gap(monotonic, wall, GAP);
        for step in 1..50u32 {
            let elapsed = Duration::from_millis(u64::from(step) * 100);
            assert_eq!(
                detector.observe(monotonic + elapsed, wall + elapsed),
                None,
                "a tick on schedule must not read as a resume"
            );
        }
    }

    /// Darwin: the monotonic clock counts the time spent asleep, so the gap is
    /// visible in both clocks.
    #[test]
    fn a_resume_that_both_clocks_saw_is_detected() {
        let (monotonic, wall) = start();
        let mut detector = Detector::with_gap(monotonic, wall, GAP);
        let slept = Duration::from_secs(600);
        assert_eq!(
            detector.observe(monotonic + slept, wall + slept),
            Some(slept)
        );
    }

    /// Linux: `CLOCK_MONOTONIC` stops while the machine is suspended, so the
    /// monotonic reading shows an ordinary tick and only the wall clock moved.
    #[test]
    fn a_resume_only_the_wall_clock_saw_is_detected() {
        let (monotonic, wall) = start();
        let mut detector = Detector::with_gap(monotonic, wall, GAP);
        let tick = Duration::from_millis(100);
        let slept = Duration::from_secs(600);
        assert_eq!(
            detector.observe(monotonic + tick, wall + slept),
            Some(slept)
        );
    }

    /// And the other way: a process stopped and continued on a host whose wall
    /// clock is being stepped backwards by NTP at the same moment.
    #[test]
    fn a_stall_only_the_monotonic_clock_saw_is_detected() {
        let (monotonic, wall) = start();
        let mut detector = Detector::with_gap(monotonic, wall, GAP);
        let stalled = Duration::from_secs(600);
        assert_eq!(
            detector.observe(monotonic + stalled, wall - Duration::from_secs(30)),
            Some(stalled)
        );
    }

    /// A clock stepped backwards is not a resume, and must not be reported as
    /// one every tick until it catches up.
    #[test]
    fn a_wall_clock_stepped_backwards_is_not_a_resume() {
        let (monotonic, wall) = start();
        let mut detector = Detector::with_gap(monotonic, wall, GAP);
        let tick = Duration::from_millis(100);
        assert_eq!(
            detector.observe(monotonic + tick, wall - Duration::from_secs(3_600)),
            None
        );
        // And the next ordinary tick, measured against the stepped clock, is
        // still ordinary.
        assert_eq!(
            detector.observe(
                monotonic + tick + tick,
                wall - Duration::from_secs(3_600) + tick
            ),
            None
        );
    }

    /// One resume, reported once. A detector that kept reporting it would turn
    /// every subsequent tick into a full round of probes.
    #[test]
    fn a_resume_is_reported_once_and_not_again() {
        let (monotonic, wall) = start();
        let mut detector = Detector::with_gap(monotonic, wall, GAP);
        let slept = Duration::from_secs(600);
        assert!(detector.observe(monotonic + slept, wall + slept).is_some());
        let tick = Duration::from_millis(100);
        assert_eq!(
            detector.observe(monotonic + slept + tick, wall + slept + tick),
            None
        );
    }

    /// The threshold is a boundary, and boundaries are where the off-by-one
    /// lives: exactly `GAP` counts, a hair under does not.
    #[test]
    fn the_threshold_includes_its_own_boundary() {
        let (monotonic, wall) = start();
        let mut detector = Detector::with_gap(monotonic, wall, GAP);
        assert_eq!(
            detector.observe(monotonic + GAP, wall + GAP),
            Some(GAP),
            "a gap of exactly the threshold is a resume"
        );
        let just_under = GAP - Duration::from_millis(1);
        assert_eq!(
            detector.observe(monotonic + GAP + just_under, wall + GAP + just_under),
            None
        );
    }
}
