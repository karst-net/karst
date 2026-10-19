// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! ADR-0045 §4d: opt-in, staggered probing of operator-provisioned
//! ephemeral anchors — AWS Local Zone probe instances kept reachable only
//! in short, published duty-cycle windows (`bins/karst-anchor-scheduler`
//! toggles their power state; they are never a `karst-relay`, never part
//! of any pool).
//!
//! Sibling to [`crate::anchor_probe`], reusing its
//! [`probe_at_port`](crate::anchor_probe::probe_at_port)/
//! [`rtt_ms`](crate::anchor_probe::rtt_ms) helpers rather than duplicating
//! them, with one real difference in shape: `anchor_probe.rs` probes
//! fixed, always-up provider endpoints on a flat 15-minute cadence. These
//! anchors are only reachable for a short window every
//! `window_period_seconds`, so firing on a flat cadence would mostly miss
//! them. Instead each node computes its own offset within the window —
//! `process_start_unix_secs mod duty_cycle_seconds` — and sleeps until
//! that exact wall-clock instant, spreading every opted-in node's probe
//! roughly evenly across the live window instead of all firing at the
//! instant it opens (which would pile connection load onto an instance
//! that may still be finishing its own boot/health checks).
//!
//! **Zero anchors means zero probes, by construction.** If the fetched
//! [`EphemeralAnchors`] has no anchors (the fail-closed default when no
//! admin has configured any — see that type's own doc comment), or
//! `duty_cycle_seconds` is `0`, this loop never computes a wait time and
//! never calls `probe_at_port` — it just rechecks at a bounded interval,
//! exactly how `anchor_probe.rs` treats an empty allowlist.
//!
//! **Opt-in under the same `[probe] anchor_probe` flag `anchor_probe.rs`
//! uses** — see `run.rs`'s own spawn site, which starts neither thread for
//! a node that has not set it. No second flag: the ADR's own reason that
//! flag exists (a node must never gain a new outbound target silently)
//! applies identically here.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use karst_control_client::transport::pb;

use crate::anchor_probe::{probe_at_port, rtt_ms, sleep_cooperatively};
use crate::netmap::EphemeralAnchors;
use crate::run::Shutdown;

/// How often to recheck for an anchor list/schedule when there is nothing
/// to probe yet (no anchors, or no duty cycle configured) — bounded so a
/// server that configures one soon after this node started is noticed
/// promptly, not only at the next restart.
const IDLE_RECHECK: Duration = Duration::from_secs(30);

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// This node's offset within a duty-cycle window: a stable, deterministic
/// value derived from when it started, not a new source of randomness.
/// Always `< duty_cycle_seconds` (or `0` if `duty_cycle_seconds` is `0`,
/// the "nothing to probe" case callers must check separately).
fn offset_seconds(process_start_unix_secs: u64, duty_cycle_seconds: u32) -> u64 {
    if duty_cycle_seconds == 0 {
        return 0;
    }
    process_start_unix_secs % u64::from(duty_cycle_seconds)
}

/// The start of the duty-cycle window containing `now_unix_secs`.
fn window_start(now_unix_secs: u64, window_period_seconds: u32) -> u64 {
    if window_period_seconds == 0 {
        return now_unix_secs;
    }
    let period = u64::from(window_period_seconds);
    (now_unix_secs / period) * period
}

/// The next wall-clock instant, at or after `now_unix_secs`, at which this
/// node should fire its probe — `window_start + offset`, advanced to a
/// later window if that instant has already passed. Always falls within
/// `[window_start, window_start + duty_cycle_seconds)` for the window it
/// returns into, since `offset < duty_cycle_seconds` by construction in
/// [`offset_seconds`] — i.e. always inside the live window, never past it.
fn next_fire_at(now_unix_secs: u64, window_period_seconds: u32, offset: u64) -> u64 {
    let period = u64::from(window_period_seconds).max(1);
    let mut start = window_start(now_unix_secs, window_period_seconds);
    let mut fire_at = start + offset;
    while fire_at < now_unix_secs {
        start += period;
        fire_at = start + offset;
    }
    fire_at
}

/// Run until `shutdown`. Reads the live [`EphemeralAnchors`] snapshot
/// (projected by the netmap-refresh loop after each successful sync) and
/// queues measured RTTs into `rtt_out`, which that same loop drains and
/// hands to
/// [`control::Client::set_ephemeral_anchor_rtt_observations`](crate::control::Client::set_ephemeral_anchor_rtt_observations)
/// right before its next request — identical bridging to
/// [`crate::anchor_probe::run`].
///
/// A pass's results **replace** whatever `rtt_out` held, rather than
/// accumulating — the same "last locally measured" contract
/// `anchor_probe::run` documents, for the identical reason: an anchor that
/// dropped out of the list (or stopped answering) between passes must not
/// have its last known value quietly re-sent forever.
pub fn run(
    ephemeral_anchors: &Mutex<EphemeralAnchors>,
    rtt_out: &Mutex<Vec<pb::KarstEphemeralAnchorRtt>>,
    process_start_unix_secs: u64,
    shutdown: &Shutdown,
) {
    while !shutdown.requested() {
        let (has_anchors, window_period_seconds, duty_cycle_seconds) = {
            let snapshot = ephemeral_anchors
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let has_anchors = snapshot.iter().next().is_some();
            (
                has_anchors,
                snapshot.window_period_seconds(),
                snapshot.duty_cycle_seconds(),
            )
        };

        if !has_anchors || duty_cycle_seconds == 0 {
            sleep_cooperatively(IDLE_RECHECK, shutdown);
            continue;
        }

        let now = now_unix_secs();
        let offset = offset_seconds(process_start_unix_secs, duty_cycle_seconds);
        let fire_at = next_fire_at(now, window_period_seconds, offset);
        sleep_cooperatively(Duration::from_secs(fire_at.saturating_sub(now)), shutdown);
        if shutdown.requested() {
            return;
        }

        // Re-read: the anchor list or schedule may have moved while this
        // node slept.
        let targets: Vec<(String, String, u16)> = ephemeral_anchors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|a| (a.label.clone(), a.address.clone(), a.port))
            .collect();

        let mut measured = Vec::with_capacity(targets.len());
        for (label, address, port) in &targets {
            if shutdown.requested() {
                return;
            }
            if let Some(rtt) = probe_at_port(address, *port) {
                measured.push(pb::KarstEphemeralAnchorRtt {
                    label: label.clone(),
                    rtt_ms: rtt_ms(rtt),
                });
            }
        }
        *rtt_out.lock().unwrap_or_else(PoisonError::into_inner) = measured;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn offset_is_always_less_than_the_duty_cycle() {
        for start in [0, 1, 59, 900, 1_700_000_000, u64::from(u32::MAX)] {
            for duty_cycle in [1, 30, 60, 300, 900, 3_600] {
                let offset = offset_seconds(start, duty_cycle);
                assert!(
                    offset < u64::from(duty_cycle),
                    "offset {offset} not less than duty_cycle {duty_cycle} (start={start})"
                );
            }
        }
    }

    #[test]
    fn offset_is_zero_when_the_duty_cycle_is_unconfigured() {
        assert_eq!(offset_seconds(12_345, 0), 0);
    }

    #[test]
    fn offset_is_deterministic_for_the_same_start_time() {
        assert_eq!(
            offset_seconds(1_700_000_123, 300),
            offset_seconds(1_700_000_123, 300)
        );
    }

    #[test]
    fn fire_at_always_falls_within_the_live_window() {
        for now in [0u64, 1, 899, 900, 901, 1_799, 1_800, 1_700_000_000] {
            for window_period in [60u32, 300, 900] {
                for duty_cycle in [30u32, 60, 300, 900] {
                    for start in [0u64, 7, 12_345, 1_700_000_000] {
                        let offset = offset_seconds(start, duty_cycle);
                        let fire_at = next_fire_at(now, window_period, offset);
                        let start_of_window = window_start(fire_at, window_period);
                        assert!(
                            fire_at >= start_of_window && fire_at < start_of_window + u64::from(duty_cycle),
                            "fire_at={fire_at} not within [{start_of_window}, {}) \
                             (now={now}, window_period={window_period}, duty_cycle={duty_cycle}, start={start})",
                            start_of_window + u64::from(duty_cycle)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn fire_at_is_never_before_now() {
        for now in [0u64, 1, 899, 900, 1_700_000_000] {
            for window_period in [60u32, 900] {
                for offset in [0u64, 5, 59] {
                    let fire_at = next_fire_at(now, window_period, offset);
                    assert!(
                        fire_at >= now,
                        "fire_at={fire_at} is before now={now} (window_period={window_period}, offset={offset})"
                    );
                }
            }
        }
    }

    #[test]
    fn a_shutdown_mid_wait_stops_promptly() {
        let anchors = Mutex::new(EphemeralAnchors::default());
        let out = Mutex::new(Vec::new());
        let shutdown = Shutdown::default();
        shutdown.request();

        let started = std::time::Instant::now();
        run(&anchors, &out, 0, &shutdown);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// The empty-table guarantee's client-side proof: an opted-in node
    /// with no ephemeral anchors configured — `EphemeralAnchors::default()`,
    /// the fail-closed state before any admin has configured one — must
    /// never produce a measurement, across a real run of the loop (not
    /// just a pre-shutdown no-op). Every iteration with no anchors takes
    /// the idle-recheck branch, which never reaches `probe_at_port` at
    /// all; a nonempty `rtt_out` here would mean that branch was skipped.
    #[test]
    fn an_empty_anchor_list_never_measures_anything() {
        let anchors = Mutex::new(EphemeralAnchors::default());
        let out: Mutex<Vec<pb::KarstEphemeralAnchorRtt>> = Mutex::new(Vec::new());
        let shutdown = Shutdown::default();

        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(150));
                shutdown.request();
            });
            run(&anchors, &out, 0, &shutdown);
        });

        assert!(
            out.lock().unwrap().is_empty(),
            "an empty anchor list must never produce a measurement"
        );
    }
}
