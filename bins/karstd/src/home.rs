// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Choosing a home relay — `ponor-v1.md` §9.1, §9.2.
//!
//! A node keeps a connection to one relay for as long as it runs, so that peers
//! have somewhere to reach it before any direct path exists. Which relay that
//! is used to be "whichever the netmap listed first", which is a choice made by
//! the server's iteration order rather than by the network.
//!
//! **Sans-io and sans-clock**, like everything else that decides: round-trip
//! times arrive from the caller, and this says which relay to hold.
//!
//! # The hysteresis is AVEN's, deliberately
//!
//! §9.2 requires hysteresis and recommends 20 ms or 20%, sustained. That is
//! word for word `aven-v1.md` §8.2's rule for path selection, so this uses
//! `karst_disco`'s constants rather than restating them. Two copies of one
//! number are free to drift, and a reader who found them disagreeing would have
//! no way to tell which was intended.
//!
//! §9.2's reasoning is worth keeping in view because it is not the usual
//! stability argument: **the cost of flapping is not paid by the node that
//! flaps.** Every change must reach the coordination server and from there
//! every peer, so a node that tracks the instantaneous minimum spends the whole
//! aquifer's netmap churn on its own noise.

use std::collections::HashMap;

use karst_disco::consts::HYSTERESIS_SAMPLES;

use crate::relay::PING_TOKEN_LEN;

/// A relay's 32-byte id.
pub type RelayId = [u8; 32];

/// Which relay to hold a connection to.
#[derive(Debug, Default)]
pub struct Selector {
    chosen: Option<RelayId>,
    /// Most recent round-trip time per relay.
    latest: HashMap<RelayId, u64>,
    /// Consecutive rounds a challenger has beaten the incumbent by the margin.
    streak: HashMap<RelayId, u32>,
}

impl Selector {
    /// Nothing measured yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a measurement.
    ///
    /// One value per relay per round; a later measurement replaces an earlier
    /// one rather than averaging, because §9.2's stability comes from the
    /// sustained-margin rule and an average would apply it twice.
    ///
    /// Measurements are consumed by [`Self::select`], so **a relay that does
    /// not answer a round is absent from it** rather than carrying its last
    /// good number forward. Retaining it would make a relay that had stopped
    /// responding keep looking as fast as the day it died, which is the one
    /// state a home relay must not be chosen in.
    pub fn observe(&mut self, relay: RelayId, rtt_ms: u64) {
        self.latest.insert(relay, rtt_ms);
    }

    /// Forget a relay the netmap no longer lists.
    ///
    /// Including the choice itself: holding a connection to a relay the
    /// coordination server has withdrawn is holding it to somewhere peers are
    /// no longer told to look.
    pub fn retain(&mut self, present: &[RelayId]) {
        self.latest.retain(|id, _| present.contains(id));
        self.streak.retain(|id, _| present.contains(id));
        if self.chosen.is_some_and(|c| !present.contains(&c)) {
            self.chosen = None;
        }
    }

    /// The relay currently held.
    #[must_use]
    pub fn chosen(&self) -> Option<RelayId> {
        self.chosen
    }

    /// The held relay's most recent measured round trip, if it has answered
    /// at least one round since being chosen.
    ///
    /// Feeds `karst_disco`'s per-peer §8.4 comparison (`Disco::
    /// set_relay_latency`, GitHub issue #121): that mechanism needs *a*
    /// number to rank against a confirmed black-hole direct path, not a
    /// precise one, since `group()` alone already decides the comparison —
    /// the magnitude only matters for tie-breaks this single relay slot
    /// never has.
    #[must_use]
    pub fn chosen_latency_ms(&self) -> Option<u64> {
        self.latest.get(&self.chosen?).copied()
    }

    /// Adopt a relay this node is already connected to, without evidence.
    ///
    /// **A daemon holds a relay before anything has been measured** — it has to,
    /// since peers need somewhere to reach it from the moment it starts — and
    /// [`Self::select`]'s first selection is immediate precisely because there
    /// is normally nothing to defend. Left unsaid, those two facts combine into
    /// a node that takes whatever the first round happens to like best,
    /// hysteresis and all, and every restart is a coin toss whose cost is a
    /// netmap update for the whole aquifer.
    ///
    /// So the relay actually held is declared here, and from the first round on
    /// it is an incumbent like any other: it keeps its place until something
    /// beats it by §9.2's margin, sustained.
    pub fn hold(&mut self, relay: RelayId) {
        self.chosen = Some(relay);
        self.streak.clear();
    }

    /// Whether `challenger` beats `incumbent` by §9.2's margin.
    ///
    /// **"Whichever is larger" means the required improvement is the larger of
    /// the two, not that either one suffices.** Read the other way — as an
    /// `OR` — a 1 ms gain on a 3 ms path clears the 20% test and the node
    /// switches on jitter, which is precisely what §9.2 exists to stop. The
    /// first version of this function made that mistake and a test caught it.
    ///
    /// `karst_disco::margin` is the one implementation; AVEN §8.2 states the
    /// same rule for path selection and had it right already.
    #[must_use]
    pub fn beats(challenger: u64, incumbent: u64) -> bool {
        incumbent.saturating_sub(challenger) >= karst_disco::margin(incumbent)
    }

    /// Decide, given everything measured this round.
    ///
    /// Returns the relay to hold, and whether it changed.
    pub fn select(&mut self) -> (Option<RelayId>, bool) {
        let round = std::mem::take(&mut self.latest);
        let Some((&best, &best_rtt)) = round.iter().min_by_key(|(id, rtt)| (**rtt, **id)) else {
            return (self.chosen, false);
        };

        let Some(current) = self.chosen else {
            // Nothing held yet: take the fastest at once. Hysteresis defends an
            // existing choice, and there is nothing here to defend — making the
            // first selection wait three rounds would leave a starting node
            // with no relay at the moment it most needs one.
            self.chosen = Some(best);
            self.streak.clear();
            return (self.chosen, true);
        };

        // The incumbent may not have answered this round. Treating silence as
        // infinitely slow would switch away on one lost datagram, so it keeps
        // its place until something beats it on evidence.
        let Some(&current_rtt) = round.get(&current) else {
            self.streak.clear();
            return (self.chosen, false);
        };

        if best == current || !Self::beats(best_rtt, current_rtt) {
            self.streak.clear();
            return (self.chosen, false);
        }

        let streak = self.streak.entry(best).or_insert(0);
        *streak = streak.saturating_add(1);
        if *streak >= HYSTERESIS_SAMPLES {
            self.chosen = Some(best);
            self.streak.clear();
            return (self.chosen, true);
        }
        (self.chosen, false)
    }
}

/// Which alternative relay is being measured, and for how long.
///
/// **§9.2's hysteresis decides the shape of this, not the other way round.** A
/// challenger has to beat the incumbent on [`HYSTERESIS_SAMPLES`] *consecutive*
/// rounds, and [`Selector::select`] consumes each round as it goes — so a relay
/// measured once every ten minutes can never accumulate a streak at all, and a
/// rotation that visited a different candidate each round would leave every
/// alternative permanently unadoptable while looking busy.
///
/// So a candidate is measured on consecutive rounds, enough of them for the
/// hysteresis to be able to act, and then the connection is let go. One
/// candidate at a time: measuring alternatives costs a Ponor connection each —
/// TLS and an ML-DSA-65 handshake — and a node that held one to every relay in
/// the registry would be paying the cost §9.1 exists to avoid.
#[derive(Debug, Default)]
pub struct Rotation {
    /// The candidate under measurement and the rounds left after this one.
    measuring: Option<(RelayId, u32)>,
    /// Rounds left before the next candidate is taken up.
    resting: u32,
    /// Where in the registry the next candidate comes from.
    next: usize,
    /// A network change is being answered by visiting every candidate once,
    /// back to back — see [`Self::network_changed`].
    sweeping: bool,
    /// Candidates the sweep has yet to start. `None` until the first round
    /// after the change, which is when the registry is known.
    sweep_left: Option<u32>,
}

/// How many consecutive rounds one alternative is measured for.
///
/// One more than the hysteresis needs. **The extra round pays for the first
/// measurement, which is spoiled by construction**: the probe is queued on a
/// connection that is still being established, so its round trip includes a TCP
/// handshake, a TLS 1.3 exchange and an ML-DSA-65 signature. That inflation is
/// in the safe direction — it argues against switching — but without the extra
/// round it would also make a genuinely faster relay unadoptable.
pub const PROBE_ROUNDS: u32 = HYSTERESIS_SAMPLES + 1;

/// Rounds between one candidate's measurement window and the next.
///
/// With [`PROBE_INTERVAL`] at a minute this puts each candidate's turn ten
/// minutes apart. The rest is not idleness: it is the connection *not* being
/// held, which is the whole cost being managed here.
pub const REST_ROUNDS: u32 = 6;

impl Rotation {
    /// The alternative to measure this round, if any.
    ///
    /// `candidates` is the registry minus the relay this node already holds —
    /// that one is measured on its own connection every round, and a node that
    /// probed it twice would be comparing it against itself.
    pub fn round(&mut self, candidates: &[RelayId]) -> Option<RelayId> {
        if self.sweeping && self.sweep_left.is_none() {
            self.sweep_left = Some(u32::try_from(candidates.len()).unwrap_or(u32::MAX));
        }
        if let Some((id, left)) = self.measuring {
            // A candidate withdrawn from the registry mid-window, or adopted as
            // the home relay, stops being an alternative at once.
            let still_a_candidate = candidates.contains(&id);
            if still_a_candidate && left > 0 {
                self.measuring = Some((id, left - 1));
                return Some(id);
            }
            self.measuring = None;
            // A window that ran its course earns the rest that follows it. One
            // cut short by the registry does not: there is nothing being held,
            // so there is nothing to stand back from.
            if still_a_candidate {
                // A sweep goes straight on to the next candidate; the rest
                // that follows is for the sweep's end, not for each window.
                self.resting = if self.sweeping && self.sweep_left != Some(0) {
                    0
                } else {
                    REST_ROUNDS
                };
            }
        }
        if self.sweeping && (self.sweep_left == Some(0) || candidates.is_empty()) {
            self.sweeping = false;
        }
        if self.resting > 0 {
            self.resting -= 1;
            return None;
        }
        let id = *candidates.get(self.next % candidates.len().max(1))?;
        self.next = self.next.wrapping_add(1);
        if self.sweeping {
            self.sweep_left = self.sweep_left.map(|n| n.saturating_sub(1));
        }
        self.measuring = Some((id, PROBE_ROUNDS - 1));
        Some(id)
    }

    /// The network under this node changed, so what was measured no longer
    /// describes it.
    ///
    /// **Measure sooner; do not decide sooner.** Abandons the current window
    /// and any rest, and visits every candidate once, back to back, instead of
    /// one per ten minutes. §9.2's margin and sample count are untouched — a
    /// challenger still has to win [`HYSTERESIS_SAMPLES`] consecutive rounds —
    /// because the cost of flapping falls on the whole aquifer's netmap, not on
    /// the node that roamed. While [`Self::sweeping`] the caller should run
    /// rounds at [`SWEEP_INTERVAL`].
    pub fn network_changed(&mut self) {
        self.measuring = None;
        self.resting = 0;
        self.sweeping = true;
        self.sweep_left = None;
    }

    /// Whether a post-change sweep is still visiting candidates.
    #[must_use]
    pub fn sweeping(&self) -> bool {
        self.sweeping
    }

    /// How long to wait before the next round.
    #[must_use]
    pub fn interval(&self) -> std::time::Duration {
        if self.sweeping {
            SWEEP_INTERVAL
        } else {
            PROBE_INTERVAL
        }
    }

    /// The candidate under measurement, whose connection must be held.
    #[must_use]
    pub fn measuring(&self) -> Option<RelayId> {
        self.measuring.map(|(id, _)| id)
    }
}

/// How often §9.1's latency probe runs.
///
/// **Minutes, not seconds.** §9.2's hysteresis means a change needs several
/// consecutive wins, so the cadence sets how long a genuinely better relay
/// waits — three rounds at this interval. Faster would spend a Ponor frame and
/// a netmap update on noise the hysteresis is there to ignore; slower would
/// leave a node on a relay that had become the wrong one for most of an hour.
pub const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The smallest jitter window a drain notice is spread over.
///
/// A relay that announces `reconnect_in_ms = 0` is still not asking every
/// client to redial in the same instant; §7.6's reason for jitter does not
/// depend on how long the relay asked for.
pub const RESTART_JITTER_FLOOR_MS: u64 = 1_000;

/// A relay's `Restarting` notice, carried out — `ponor-v1.md` §7.6.
///
/// **Sans-clock**, like the rest of this module: the caller supplies the time
/// and the entropy. The notice does two things. It sets how long to wait before
/// redialling — `reconnect_in_ms` plus jitter, so a restart is not a
/// synchronised reconnect storm — and it opens a window, `try_for_ms` long,
/// during which a failed connect is the relay still coming back rather than
/// evidence it is dead. Without the second part the 3-attempt abandon path
/// would read a relay that was merely restarting as one to leave, and walk the
/// whole home population off it.
#[derive(Debug, Default, Clone, Copy)]
pub struct Restart {
    retry_until_ms: Option<u64>,
}

impl Restart {
    /// Take a notice received at `now_ms`; returns how long to wait before
    /// reconnecting.
    ///
    /// `entropy` is uniform random; the jitter is drawn from
    /// `[0, max(reconnect_in_ms, RESTART_JITTER_FLOOR_MS))`.
    pub fn begin(
        &mut self,
        now_ms: u64,
        reconnect_in_ms: u32,
        try_for_ms: u32,
        entropy: u64,
    ) -> u64 {
        let window = u64::from(reconnect_in_ms).max(RESTART_JITTER_FLOOR_MS);
        let wait = u64::from(reconnect_in_ms) + entropy % window;
        self.retry_until_ms = Some(
            now_ms
                .saturating_add(wait)
                .saturating_add(u64::from(try_for_ms)),
        );
        wait
    }

    /// Whether a failed connect at `now_ms` is still inside the window the
    /// relay asked for, and so must not count towards abandoning it.
    #[must_use]
    pub fn in_grace(&self, now_ms: u64) -> bool {
        self.retry_until_ms.is_some_and(|until| now_ms < until)
    }
}

/// How often a connection busy with traffic looks for a pending move.
///
/// The idle path notices a move within a tick; a connection that is never idle
/// needs a bound of its own. A second is far below anything §9.2's cadence can
/// produce — a move is decided over minutes — and far above the per-packet cost
/// of taking a lock, which is the reason it is not checked on every datagram.
pub const MOVE_CHECK_INTERVAL_MS: u64 = 1_000;

/// Rate limit on the "has the choice moved?" check, for a connection whose
/// queue never empties.
#[derive(Debug, Default, Clone, Copy)]
pub struct MoveCheck {
    last_ms: Option<u64>,
}

impl MoveCheck {
    /// Whether the check is due at `now_ms`; asking starts the next interval.
    pub fn due(&mut self, now_ms: u64) -> bool {
        let due = self
            .last_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= MOVE_CHECK_INTERVAL_MS);
        if due {
            self.last_ms = Some(now_ms);
        }
        due
    }
}

/// How often rounds run while answering a network change.
///
/// Rounds are still consecutive and still [`HYSTERESIS_SAMPLES`] wins are still
/// needed; only the gap between them shrinks. Long enough that a Ponor
/// handshake to a distant relay finishes inside it, which the first
/// measurement of a window already assumes.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Outstanding latency probes on one relay connection — `ponor-v1.md` §9.1.
///
/// **A token, not a timestamp of the last send.** A `Pong` carries back the
/// token that went out, so a round trip is attributed to the request that
/// caused it rather than to whichever ping happened most recently — which
/// matters because a lost `Pong` followed by a fast one would otherwise report
/// the slow path as fast, and §9.1's answer decides where every peer is told to
/// look for this node.
#[derive(Debug, Default)]
pub struct RttProbes {
    /// Tokens in flight and when each was sent.
    outstanding: Vec<([u8; PING_TOKEN_LEN], u64)>,
}

/// Most probes in flight at once.
///
/// A relay that never answers must not make this node allocate without bound.
/// Two is already generous: §9.1's cadence is far longer than any round trip
/// worth measuring, so a third in flight means the first two are lost.
const MAX_OUTSTANDING_PROBES: usize = 2;

impl RttProbes {
    /// Note that `token` has just gone out.
    ///
    /// Returns `false` when too many are already in flight, which the caller
    /// should treat as "do not send" rather than as an error: a relay that is
    /// not answering is measured by its silence, not by more pings.
    pub fn sent(&mut self, token: [u8; PING_TOKEN_LEN], now_ms: u64) -> bool {
        if self.outstanding.len() >= MAX_OUTSTANDING_PROBES {
            return false;
        }
        self.outstanding.push((token, now_ms));
        true
    }

    /// The round trip a `Pong` reports, if it answers a probe this node sent.
    ///
    /// `None` for a token that was never sent or has already been answered —
    /// §7.4's rule for AVEN, applied here for the same reason: a relay that
    /// replayed a `Pong` could otherwise report an arbitrarily good latency and
    /// win an election it should not.
    pub fn resolve(&mut self, token: [u8; PING_TOKEN_LEN], now_ms: u64) -> Option<u64> {
        let at = self.outstanding.iter().position(|(t, _)| *t == token)?;
        let (_, sent) = self.outstanding.remove(at);
        // Everything older is lost: a relay answers in order or not at all, so
        // holding an unanswered token past a later answer would let it be
        // resolved by a much later `Pong` and reported as a fast round trip.
        self.outstanding.retain(|(_, s)| *s > sent);
        Some(now_ms.saturating_sub(sent))
    }

    /// Forget everything in flight, on reconnection.
    pub fn reset(&mut self) {
        self.outstanding.clear();
    }

    /// Probes awaiting an answer.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.outstanding.len()
    }
}

/// Outstanding probes on every connection this node is measuring.
///
/// **Per relay, not per node.** Once alternatives are measured there is more
/// than one connection in flight at a time, and the two properties [`RttProbes`]
/// carries are both per-connection: a round trip belongs to the relay it was
/// sent to, and "two outstanding means this one is not answering" is a
/// statement about one relay's silence. Sharing one table would let a busy
/// relay's probes use up the allowance of a silent one, and would make a `Pong`
/// resolvable against a token this node sent somewhere else.
#[derive(Debug, Default)]
pub struct Probes {
    per_relay: HashMap<RelayId, RttProbes>,
}

impl Probes {
    /// Note that `token` has just gone out to `relay`.
    pub fn sent(&mut self, relay: RelayId, token: [u8; PING_TOKEN_LEN], now_ms: u64) -> bool {
        self.per_relay.entry(relay).or_default().sent(token, now_ms)
    }

    /// The round trip a `Pong` from `relay` reports, if it answers a probe this
    /// node sent *to that relay*.
    pub fn resolve(
        &mut self,
        relay: RelayId,
        token: [u8; PING_TOKEN_LEN],
        now_ms: u64,
    ) -> Option<u64> {
        self.per_relay.get_mut(&relay)?.resolve(token, now_ms)
    }

    /// Forget one relay's probes, because its connection has gone.
    ///
    /// A token sent on a connection that no longer exists can never be
    /// answered, and keeping it would spend the next connection's allowance on
    /// the last one's losses.
    pub fn reset(&mut self, relay: RelayId) {
        self.per_relay.remove(&relay);
    }

    /// Probes awaiting an answer from `relay`.
    #[must_use]
    pub fn in_flight(&self, relay: RelayId) -> usize {
        self.per_relay.get(&relay).map_or(0, RttProbes::in_flight)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn id(n: u8) -> RelayId {
        [n; 32]
    }

    #[test]
    fn a_restart_waits_the_requested_time_plus_jitter() {
        let mut r = Restart::default();
        // No entropy: exactly what the relay asked for.
        assert_eq!(r.begin(0, 2_000, 60_000, 0), 2_000);
        // Jitter is bounded by the larger of the request and the floor.
        assert_eq!(r.begin(0, 2_000, 60_000, 1_999), 3_999);
        assert_eq!(r.begin(0, 0, 60_000, 999_999), 999_999 % 1_000);
        // And the same notice spreads clients out rather than aligning them.
        let waits: std::collections::HashSet<u64> = (0..50)
            .map(|e| Restart::default().begin(0, 2_000, 60_000, e * 37))
            .collect();
        assert!(waits.len() > 1);
    }

    #[test]
    fn failures_inside_the_restart_window_are_not_evidence_of_a_dead_relay() {
        let mut r = Restart::default();
        assert!(!r.in_grace(0), "no notice, no grace");
        let wait = r.begin(10_000, 2_000, 60_000, 0);
        assert!(r.in_grace(10_000 + wait + 59_999));
        assert!(!r.in_grace(10_000 + wait + 60_000), "the window ends");
    }

    #[test]
    fn a_network_change_visits_every_candidate_without_resting() {
        let candidates = [id(1), id(2), id(3)];
        let mut r = Rotation::default();
        // Settle into the slow cycle first: a window, then its rest.
        for _ in 0..=PROBE_ROUNDS {
            r.round(&candidates);
        }
        assert!(!r.sweeping());
        assert_eq!(r.interval(), PROBE_INTERVAL);

        r.network_changed();
        assert!(r.sweeping());
        assert_eq!(r.interval(), SWEEP_INTERVAL);

        let mut seen = Vec::new();
        for _ in 0..(3 * PROBE_ROUNDS) {
            let probed = r.round(&candidates).expect("no rest inside a sweep");
            if seen.last() != Some(&probed) {
                seen.push(probed);
            }
        }
        seen.sort_unstable();
        assert_eq!(seen, candidates.to_vec(), "each candidate measured once");

        // The sweep ends and the ordinary rest follows it.
        assert_eq!(r.round(&candidates), None);
        assert!(!r.sweeping());
        assert_eq!(r.interval(), PROBE_INTERVAL);
    }

    #[test]
    fn a_sweep_keeps_the_hysteresis() {
        // Faster measurement must not become a faster decision: a challenger
        // that wins fewer than HYSTERESIS_SAMPLES rounds does not move the node.
        let mut s = Selector::new();
        s.hold(id(1));
        for _ in 0..(HYSTERESIS_SAMPLES - 1) {
            s.observe(id(1), 100);
            s.observe(id(2), 10);
            assert!(!s.select().1);
        }
        assert_eq!(s.chosen(), Some(id(1)));
    }

    #[test]
    fn a_connection_that_is_never_idle_still_checks_for_a_move() {
        // A datagram every millisecond for ten seconds: the idle branch is
        // never reached, and the check must still fire on a bounded schedule
        // without being taken per packet.
        let mut check = MoveCheck::default();
        let fired: Vec<u64> = (0..10_000).filter(|&ms| check.due(ms)).collect();
        assert_eq!(fired.len(), 10);
        assert!(fired.windows(2).all(|w| w.get(1).copied().unwrap_or(0)
            - w.first().copied().unwrap_or(0)
            == MOVE_CHECK_INTERVAL_MS));
        assert_eq!(fired.first(), Some(&0), "the first look is immediate");
    }

    #[test]
    fn a_pong_is_attributed_to_the_ping_that_caused_it() {
        // The whole reason for a token. Matching on "the last ping I sent"
        // would report a slow path as fast whenever a `Pong` was lost and the
        // next one arrived quickly — and §9.1's answer decides where every peer
        // is told to look for this node.
        let mut p = RttProbes::default();
        assert!(p.sent([1; PING_TOKEN_LEN], 0));
        assert!(p.sent([2; PING_TOKEN_LEN], 100));
        assert_eq!(p.resolve([2; PING_TOKEN_LEN], 130), Some(30));
    }

    #[test]
    fn a_token_that_was_never_sent_measures_nothing() {
        // §7.4's rule for AVEN, here for the same reason: a relay that
        // volunteered or replayed a `Pong` could otherwise report an
        // arbitrarily good latency and win an election it should not.
        let mut p = RttProbes::default();
        assert_eq!(p.resolve([9; PING_TOKEN_LEN], 10), None);
        assert!(p.sent([1; PING_TOKEN_LEN], 0));
        assert_eq!(p.resolve([1; PING_TOKEN_LEN], 5), Some(5));
        assert_eq!(
            p.resolve([1; PING_TOKEN_LEN], 6),
            None,
            "the same token answered twice"
        );
    }

    #[test]
    fn an_older_probe_cannot_be_resolved_after_a_newer_one() {
        // A relay answers in order or not at all. Keeping an unanswered token
        // past a later answer would let a much later `Pong` resolve it and
        // report a fast round trip for a path that had stalled.
        let mut p = RttProbes::default();
        assert!(p.sent([1; PING_TOKEN_LEN], 0));
        assert!(p.sent([2; PING_TOKEN_LEN], 100));
        assert_eq!(p.resolve([2; PING_TOKEN_LEN], 110), Some(10));
        assert_eq!(p.resolve([1; PING_TOKEN_LEN], 900), None);
    }

    #[test]
    fn a_silent_relay_cannot_make_this_node_allocate() {
        // Probes are state a relay's behavior causes this node to hold. One
        // that never answers is measured by its silence, not by more pings.
        let mut p = RttProbes::default();
        let mut admitted = 0;
        for n in 0..50u8 {
            if p.sent([n; PING_TOKEN_LEN], u64::from(n)) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 2, "an unanswering relay grew the probe table");
        assert_eq!(p.in_flight(), 2);
        p.reset();
        assert_eq!(p.in_flight(), 0);
    }

    #[test]
    fn the_first_selection_is_immediate() {
        // Hysteresis defends an existing choice. Making the first one wait
        // three rounds leaves a starting node without a relay at the moment
        // peers most need somewhere to reach it.
        let mut s = Selector::new();
        s.observe(id(1), 40);
        s.observe(id(2), 12);
        assert_eq!(s.select(), (Some(id(2)), true));
    }

    #[test]
    fn a_faster_relay_must_win_for_several_rounds_before_it_is_taken() {
        let mut s = Selector::new();
        s.observe(id(1), 100);
        assert_eq!(s.select(), (Some(id(1)), true));

        for round in 1..HYSTERESIS_SAMPLES {
            s.observe(id(1), 100);
            s.observe(id(2), 10);
            assert_eq!(
                s.select(),
                (Some(id(1)), false),
                "switched after only {round} round(s)"
            );
        }
        s.observe(id(1), 100);
        s.observe(id(2), 10);
        assert_eq!(s.select(), (Some(id(2)), true), "never switched");
    }

    #[test]
    fn one_good_round_does_not_carry_over() {
        // The margin has to be *sustained*. A challenger that wins, loses, then
        // wins again has not shown it is better; it has shown the path is
        // noisy, which is the case §9.2 exists for.
        let mut s = Selector::new();
        s.observe(id(1), 100);
        let _ = s.select();
        for _ in 0..10 {
            s.observe(id(1), 100);
            s.observe(id(2), 10);
            assert!(!s.select().1, "switched on an alternating pattern");
            s.observe(id(1), 100);
            s.observe(id(2), 200);
            assert!(!s.select().1);
        }
        assert_eq!(s.chosen(), Some(id(1)));
    }

    #[test]
    fn a_margin_that_is_only_noise_never_wins() {
        // 20% of a 2 ms path is 0.4 ms. Without the absolute floor a node on a
        // fast network would rewrite the whole aquifer's netmap over jitter.
        let mut s = Selector::new();
        s.observe(id(1), 2);
        let _ = s.select();
        for _ in 0..20 {
            s.observe(id(1), 2);
            s.observe(id(2), 1);
            assert!(!s.select().1, "switched on sub-millisecond jitter");
        }
    }

    #[test]
    fn the_margin_is_the_larger_of_absolute_and_proportional() {
        // Both ends of the range, which is why §9.2 states two numbers.
        assert!(Selector::beats(10, 100), "80% faster");
        assert!(
            !Selector::beats(380, 400),
            "on a 400 ms path 20% is 80 ms, and that is the larger margin — \
             reading the rule as an OR is exactly the mistake §9.2 prevents"
        );
        assert!(Selector::beats(300, 400), "100 ms clears the 80 ms margin");
        assert!(!Selector::beats(99, 100), "1 ms and 1% is neither");
        assert!(!Selector::beats(2, 3), "1 ms on a fast path is noise");
    }

    #[test]
    fn a_silent_incumbent_keeps_its_place() {
        // Treating a missed measurement as infinitely slow would move the whole
        // aquifer's view of this node on one lost datagram.
        let mut s = Selector::new();
        s.observe(id(1), 50);
        let _ = s.select();
        for _ in 0..HYSTERESIS_SAMPLES + 2 {
            s.observe(id(2), 5); // the incumbent says nothing
            assert_eq!(s.select(), (Some(id(1)), false));
        }
    }

    #[test]
    fn a_withdrawn_relay_is_released_even_if_it_was_the_choice() {
        // Holding a connection to a relay the server has withdrawn is holding
        // it to somewhere peers are no longer told to look.
        let mut s = Selector::new();
        s.observe(id(1), 10);
        assert_eq!(s.select(), (Some(id(1)), true));
        s.retain(&[id(2)]);
        assert_eq!(s.chosen(), None);
        s.observe(id(2), 90);
        assert_eq!(s.select(), (Some(id(2)), true));
    }

    /// **A relay already held is defended from the first round.** The daemon
    /// connects to one before anything has been measured, so without this the
    /// immediate first selection would be made against a choice that had
    /// already been acted on — and a single fast answer from any alternative
    /// would take it, hysteresis and all.
    #[test]
    fn a_relay_already_held_is_an_incumbent_from_the_first_round() {
        let mut s = Selector::new();
        s.hold(id(1));
        s.observe(id(1), 100);
        s.observe(id(2), 10);
        assert_eq!(
            s.select(),
            (Some(id(1)), false),
            "switched on the first round, against a relay this node was already on"
        );
    }

    // ── measuring alternatives ──────────────────────────────────────────

    /// **The point of the whole rotation.** `select` consumes a round, and a
    /// challenger absent from a round has its streak cleared — so a candidate
    /// measured once and then left alone can never reach
    /// `HYSTERESIS_SAMPLES` consecutive wins, however much faster it is.
    #[test]
    fn a_candidate_is_measured_on_consecutive_rounds() {
        let mut r = Rotation::default();
        let candidates = [id(2), id(3)];
        let first = r.round(&candidates).expect("a candidate");
        for round in 1..PROBE_ROUNDS {
            assert_eq!(
                r.round(&candidates),
                Some(first),
                "the rotation moved on after {round} round(s), so no streak can form"
            );
        }
    }

    /// The window is long enough for the hysteresis to act, proven against the
    /// selector itself rather than by comparing two constants — including the
    /// spoiled first measurement, which is why the window is one round longer
    /// than the streak.
    #[test]
    fn a_faster_alternative_is_adopted_within_one_window() {
        let mut s = Selector::new();
        let mut r = Rotation::default();
        s.observe(id(1), 90);
        assert_eq!(s.select(), (Some(id(1)), true), "the incumbent is held");

        let candidates = [id(2)];
        let mut adopted = None;
        for round in 0..PROBE_ROUNDS {
            s.observe(id(1), 90);
            if let Some(candidate) = r.round(&candidates) {
                // The first probe rides a connection still being established,
                // so its round trip carries a TCP, TLS and ML-DSA-65 handshake.
                s.observe(candidate, if round == 0 { 400 } else { 10 });
            }
            if s.select().1 {
                adopted = Some(round);
            }
        }
        assert_eq!(
            adopted,
            Some(PROBE_ROUNDS - 1),
            "a relay four times faster was not adopted in its own window"
        );
        assert_eq!(s.chosen(), Some(id(2)));
    }

    /// Each candidate gets a turn, and the connection is let go between them.
    #[test]
    fn candidates_take_turns_with_a_rest_between() {
        let mut r = Rotation::default();
        let candidates = [id(2), id(3)];
        let mut seen = Vec::new();
        let mut rests = 0;
        for _ in 0..(2 * (PROBE_ROUNDS + REST_ROUNDS)) {
            match r.round(&candidates) {
                Some(id) => {
                    if seen.last() != Some(&id) {
                        seen.push(id);
                    }
                }
                None => rests += 1,
            }
        }
        assert_eq!(seen, vec![id(2), id(3)], "a candidate never had its turn");
        assert_eq!(
            rests,
            2 * REST_ROUNDS,
            "the connection was held when nothing was being measured"
        );
    }

    /// Nothing is held while resting — that is the cost being managed.
    #[test]
    fn no_connection_is_wanted_between_windows() {
        let mut r = Rotation::default();
        let candidates = [id(2)];
        for _ in 0..PROBE_ROUNDS {
            assert!(r.round(&candidates).is_some());
        }
        assert_eq!(r.round(&candidates), None);
        assert_eq!(r.measuring(), None, "a connection was kept for nothing");
    }

    /// A relay withdrawn from the registry — or adopted as this node's home —
    /// stops being an alternative at once, rather than at the end of a window
    /// it can no longer be measured on.
    #[test]
    fn a_candidate_that_stops_being_one_is_dropped_mid_window() {
        let mut r = Rotation::default();
        assert_eq!(r.round(&[id(2)]), Some(id(2)));
        assert_eq!(r.round(&[]), None);
        assert_eq!(r.measuring(), None);
    }

    /// A node with one relay in its registry has no alternatives, and must not
    /// spend a connection discovering that every round.
    #[test]
    fn a_lone_relay_leaves_nothing_to_measure() {
        let mut r = Rotation::default();
        for _ in 0..10 {
            assert_eq!(r.round(&[]), None);
        }
    }

    /// **A `Pong` belongs to the relay it came from.** One table for the node
    /// would let a relay resolve a token this node sent somewhere else, and
    /// report whatever round trip that timing implied.
    #[test]
    fn a_probe_is_answered_only_by_the_relay_it_was_sent_to() {
        let mut p = Probes::default();
        let token = [7; PING_TOKEN_LEN];
        assert!(p.sent(id(1), token, 100));
        assert_eq!(
            p.resolve(id(2), token, 105),
            None,
            "the wrong relay answered"
        );
        assert_eq!(p.resolve(id(1), token, 130), Some(30));
    }

    /// One relay's silence must not spend another's allowance: a relay that is
    /// not answering is measured by that, and the node it is starving would
    /// otherwise stop being measured at all.
    #[test]
    fn a_silent_relay_does_not_starve_the_others() {
        let mut p = Probes::default();
        for n in 0..10u8 {
            let _ = p.sent(id(1), [n; PING_TOKEN_LEN], u64::from(n));
        }
        assert_eq!(p.in_flight(id(1)), 2);
        assert!(
            p.sent(id(2), [0xEE; PING_TOKEN_LEN], 50),
            "a second relay could not be probed at all"
        );
        assert_eq!(p.in_flight(id(2)), 1);
    }

    /// A connection that has gone takes its outstanding probes with it. They
    /// can never be answered, and keeping them would spend the next
    /// connection's allowance on the last one's losses.
    #[test]
    fn a_lost_connection_clears_only_its_own_probes() {
        let mut p = Probes::default();
        assert!(p.sent(id(1), [1; PING_TOKEN_LEN], 0));
        assert!(p.sent(id(2), [2; PING_TOKEN_LEN], 0));
        p.reset(id(1));
        assert_eq!(p.in_flight(id(1)), 0);
        assert_eq!(p.in_flight(id(2)), 1, "an unrelated relay was reset");
        assert_eq!(p.resolve(id(1), [1; PING_TOKEN_LEN], 10), None);
    }

    #[test]
    fn ties_are_broken_the_same_way_every_time() {
        // Two relays at the same RTT must not alternate: the choice is
        // published to every peer, so an arbitrary tie-break that moved would
        // be netmap churn with no benefit at all.
        let mut a = Selector::new();
        let mut b = Selector::new();
        for s in [&mut a, &mut b] {
            s.observe(id(9), 30);
            s.observe(id(3), 30);
        }
        assert_eq!(a.select().0, b.select().0);
    }
}
