// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Probe scheduling — `spec/aven-v1.md` §7.3 and §7.5.
//!
//! What to send and when. [`path::PathSet`] remembers what is known about a
//! peer; this decides what to do about it.
//!
//! Sans-io and sans-clock, like everything below it: [`Engine::poll`] takes a
//! millisecond stamp and a closure that mints transaction ids, and returns
//! intents. Nothing here opens a socket, reads a clock or draws randomness, so
//! a test can run an hour of scheduling in a loop with a counter for a CSPRNG
//! and get the same answer every time.
//!
//! # Simultaneous open
//!
//! The one piece of hole punching that lives at this layer. When a
//! `CallMeMaybe` arrives, **every candidate in it is probed at once**, without
//! waiting for the backoff schedule — because the peer received ours at nearly
//! the same moment and is doing the same thing. Both NATs then see an outbound
//! packet before either sees an inbound one, which is the entire trick. A
//! scheduler that politely staggered these would defeat it.

use std::net::SocketAddr;

use crate::consts::{ADVERTISE_MIN_INTERVAL_MS, KEEPALIVE_MS, PROBE_BACKOFF_MS, REPROBE_MS};
use crate::msg::{Endpoint, TxId};
use crate::path::{Admission, PathKind, PathSet, ProbeError};

/// Something the caller should put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a `Ping` bearing `tx` to `addr`.
    ///
    /// Already recorded against the peer's outstanding set, so the answering
    /// `Pong` will confirm `addr` — §7.1.
    Probe {
        /// Where to send.
        addr: SocketAddr,
        /// The transaction id minted for it.
        tx: TxId,
    },
    /// Send a `CallMeMaybe` over the relay, so the peer learns where to try us.
    Advertise {
        /// Our candidates, capped by the caller's encoder.
        candidates: Vec<Endpoint>,
    },
}

#[derive(Debug, Clone, Copy)]
struct Scheduled {
    addr: SocketAddr,
    /// When this candidate may next be probed.
    due_ms: u64,
    /// Probes sent since it was last confirmed. Reset on a `Pong`.
    attempts: usize,
}

/// Probe scheduling for one peer.
#[derive(Debug)]
pub struct Engine {
    paths: PathSet,
    queue: Vec<Scheduled>,
    /// Our own candidates, as last advertised.
    local: Vec<Endpoint>,
    last_advertise_ms: Option<u64>,
    /// Last authenticated candidate advertisement accepted from this peer.
    /// This is separate from `last_advertise_ms`, which limits what *we* send.
    last_remote_advertise_ms: Option<u64>,
    advertise_pending: bool,
    last_keepalive_ms: Option<u64>,
    last_reprobe_ms: Option<u64>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// A peer nothing is known about yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: PathSet::new(),
            queue: Vec::new(),
            local: Vec::new(),
            last_advertise_ms: None,
            last_remote_advertise_ms: None,
            advertise_pending: false,
            last_keepalive_ms: None,
            last_reprobe_ms: None,
        }
    }

    /// What is known about how to reach this peer.
    #[must_use]
    pub fn paths(&self) -> &PathSet {
        &self.paths
    }

    /// Mutable access, for the caller to feed `Pong`s and relay measurements in.
    pub fn paths_mut(&mut self) -> &mut PathSet {
        &mut self.paths
    }

    /// Replace our own candidate list.
    ///
    /// Advertising is scheduled only when the list actually **changed**. A node
    /// that re-enumerates its interfaces every second must not turn that into a
    /// `CallMeMaybe` every second, and comparing is cheaper than rate-limiting
    /// after the fact.
    pub fn set_local_candidates(&mut self, mut candidates: Vec<Endpoint>) {
        candidates.sort_by_key(|c| (c.0.is_ipv6(), c.0.ip().to_string(), c.0.port()));
        candidates.dedup();
        if candidates == self.local {
            return;
        }
        self.local = candidates;
        self.advertise_pending = true;
    }

    /// Learn a candidate for the peer, from a `CallMeMaybe` or elsewhere.
    ///
    /// `immediate` is what implements simultaneous open: a candidate that
    /// arrived in a `CallMeMaybe` is probed on this poll rather than on the
    /// backoff schedule, because the peer is probing ours at the same moment.
    pub fn add_peer_candidate(&mut self, addr: SocketAddr, now_ms: u64, immediate: bool) {
        if let Some(existing) = self.queue.iter_mut().find(|s| s.addr == addr) {
            if immediate {
                existing.due_ms = now_ms;
                // Restarting the backoff is deliberate: a fresh CallMeMaybe is
                // evidence the peer is present and trying, which is exactly
                // when a candidate that has already exhausted its attempts
                // deserves another go.
                existing.attempts = 0;
            }
            return;
        }

        // A peer can name sixteen addresses per CallMeMaybe indefinitely, so
        // both the schedule and the path set are bounded resources rather than
        // historical records. The bound itself lives in `PathSet`, which owns
        // the vector; this only has to keep the schedule in step with whatever
        // was displaced, so the two can never disagree about which addresses
        // exist.
        match self.paths.add_candidate(addr, PathKind::direct_for(addr)) {
            Admission::Full => return,
            Admission::Added {
                evicted: Some(evicted),
            } => self.queue.retain(|scheduled| scheduled.addr != evicted),
            Admission::Added { evicted: None } | Admission::Known => {}
        }
        self.queue.push(Scheduled {
            addr,
            due_ms: now_ms,
            attempts: 0,
        });
    }

    /// Handle an authenticated `CallMeMaybe` — §7.3.
    pub fn on_call_me_maybe(&mut self, candidates: &[Endpoint], now_ms: u64) -> bool {
        if self
            .last_remote_advertise_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < ADVERTISE_MIN_INTERVAL_MS)
        {
            return false;
        }
        self.last_remote_advertise_ms = Some(now_ms);
        for c in candidates {
            self.add_peer_candidate(c.0, now_ms, true);
        }
        true
    }

    /// Whether every candidate has been probed to the end of §7.5's schedule
    /// without answering.
    ///
    /// "Immediately, then 100/300/900, then give up" — this is *give up*, and
    /// it is the difference between "not confirmed yet" and "does not work".
    /// A caller that cannot tell those apart has to choose between dropping a
    /// working endpoint during the second of probing that follows every roster
    /// change, and never dropping one at all.
    ///
    /// **Giving up is not permanent**, and that is what makes it safe to act
    /// on. The re-probe sweep tries every queued candidate again every
    /// [`REPROBE_MS`], and a fresh `CallMeMaybe` revives one at once, so a peer
    /// that comes back is found again within thirty seconds without anything
    /// having to remember it was written off.
    ///
    /// False for a peer with no candidates at all: nothing has been given up
    /// on, there was simply never anything to try.
    #[must_use]
    pub fn exhausted(&self) -> bool {
        !self.queue.is_empty()
            && self
                .queue
                .iter()
                .all(|s| s.attempts > PROBE_BACKOFF_MS.len())
    }

    /// Note that a probe was answered, so its backoff resets.
    pub fn on_confirmed(&mut self, addr: SocketAddr) {
        if let Some(scheduled) = self.queue.iter_mut().find(|s| s.addr == addr) {
            scheduled.attempts = 0;
        }
    }

    /// Start discovery over, because everything it measured may now be false.
    ///
    /// This is for the caller that has just learned the host's network moved
    /// underneath it — a laptop waking from sleep, an interface changing, a
    /// default route replaced. Every measurement in the queue was taken through
    /// a NAT binding that no longer exists, so a candidate written off before
    /// the move deserves a fresh attempt and the one currently chosen deserves
    /// an immediate keepalive rather than the rest of its interval.
    ///
    /// The effect is deliberately identical to a `CallMeMaybe` arriving for
    /// every candidate at once: attempts reset, everything due now, and one
    /// advertisement queued, because a node whose external address just changed
    /// has to *tell* its peers as well as go looking for them.
    ///
    /// Cheap and idempotent — it queues no I/O of its own, and the next
    /// [`Engine::poll`] is what turns it into probes. Calling it on a node that
    /// has no candidates does nothing at all.
    ///
    /// The re-probe clock is set rather than cleared, because this poll is
    /// about to probe everything: leaving it due would send the sweep over the
    /// top of the probes it duplicates.
    ///
    /// The *advertise* clock is cleared instead, and the asymmetry is the
    /// point. §7.5's floor exists to stop a node that re-enumerates constantly
    /// from advertising constantly, and it is measured against a caller-supplied
    /// stamp — which on a machine that has just resumed may not have advanced
    /// at all, depending on whether its monotonic clock counts time spent
    /// asleep. Clearing the stamp makes the advertisement happen on the next
    /// poll on either kind of host, and nothing on the network can reach this
    /// call to abuse it: only the local host detecting its own resume does.
    pub fn rediscover(&mut self, now_ms: u64) {
        for scheduled in &mut self.queue {
            scheduled.attempts = 0;
            scheduled.due_ms = now_ms;
        }
        self.last_keepalive_ms = None;
        self.last_reprobe_ms = Some(now_ms);
        if !self.local.is_empty() {
            self.advertise_pending = true;
            self.last_advertise_ms = None;
        }
    }

    /// Decide what to send now.
    ///
    /// `mint` supplies transaction ids; it must draw from a CSPRNG in
    /// production, and a counter is fine in a test.
    pub fn poll(&mut self, now_ms: u64, mint: &mut impl FnMut() -> TxId) -> Vec<Action> {
        let mut out = Vec::new();

        if self.should_advertise(now_ms) {
            self.last_advertise_ms = Some(now_ms);
            self.advertise_pending = false;
            out.push(Action::Advertise {
                candidates: self.local.clone(),
            });
        }

        // Candidates on the backoff schedule.
        let due: Vec<SocketAddr> = self
            .queue
            .iter()
            // `<=`, not `<`: §7.5 is "probe immediately, then after each of
            // 100/300/900, then give up" — four probes, three backoffs.
            .filter(|s| s.attempts <= PROBE_BACKOFF_MS.len() && now_ms >= s.due_ms)
            .map(|s| s.addr)
            .collect();
        for addr in due {
            if self.emit_probe(addr, now_ms, mint, &mut out) {
                if let Some(s) = self.queue.iter_mut().find(|s| s.addr == addr) {
                    let backoff = PROBE_BACKOFF_MS.get(s.attempts).copied().unwrap_or(0);
                    s.attempts = s.attempts.saturating_add(1);
                    s.due_ms = now_ms.saturating_add(backoff);
                }
            }
        }

        // Keep the chosen path alive — §7.5.
        if let Some(chosen) = self.paths.chosen() {
            let due = self
                .last_keepalive_ms
                .is_none_or(|t| now_ms.saturating_sub(t) >= KEEPALIVE_MS);
            if due {
                self.last_keepalive_ms = Some(now_ms);
                self.emit_probe(chosen, now_ms, mint, &mut out);
            }
        }

        // Re-probe the alternatives, so a better path that appears later is
        // found rather than waited for. Without this a node that settles on a
        // relay at boot stays there until something else disturbs it.
        // The first poll starts the clock without firing: the backoff schedule
        // above has just probed everything, and re-probing it in the same poll
        // would send every candidate twice and spend the outstanding budget on
        // duplicates.
        let due = match self.last_reprobe_ms {
            None => {
                self.last_reprobe_ms = Some(now_ms);
                false
            }
            Some(t) => now_ms.saturating_sub(t) >= REPROBE_MS,
        };
        if due {
            self.last_reprobe_ms = Some(now_ms);
            let chosen = self.paths.chosen();
            let others: Vec<SocketAddr> = self
                .queue
                .iter()
                .map(|s| s.addr)
                .filter(|a| Some(*a) != chosen)
                .collect();
            for addr in others {
                self.emit_probe(addr, now_ms, mint, &mut out);
            }
        }

        out
    }

    /// Whether to put a `CallMeMaybe` on the wire this poll.
    ///
    /// Two reasons to send, and the second is not optional.
    ///
    /// **On change**, which is §7.5's rule and what stops a node that
    /// re-enumerates its interfaces every second from advertising every second.
    ///
    /// **And repeatedly, while no direct path exists.** An advertisement is a
    /// datagram and datagrams are lost: a peer that missed the one we sent —
    /// because it had not yet been given our disco key, because it restarted,
    /// because the relay was briefly down — would never hear where we are, and
    /// the pair would stay on the relay for good. That is not hypothetical; it
    /// is what a node joining an existing aquifer does, and it was observed
    /// between two real daemons before this existed.
    ///
    /// The re-probe sweep above exists for the same reason and says so:
    /// *"without this a node that settles on a relay at boot stays there until
    /// something else disturbs it"*. Telling a peer where we are and asking
    /// where it is are the two halves of one job, and only one of them was
    /// being repeated.
    ///
    /// Repetition stops once a path is chosen, so a settled pair costs nothing.
    fn should_advertise(&self, now_ms: u64) -> bool {
        if self.local.is_empty() {
            return false;
        }
        let due = self.advertise_pending || self.paths.chosen().is_none();
        if !due {
            return false;
        }
        // Changed candidates go out at §7.5's floor; a repeat for want of a
        // path waits the re-probe interval, because it is answering silence
        // rather than news.
        let wait = if self.advertise_pending {
            ADVERTISE_MIN_INTERVAL_MS
        } else {
            REPROBE_MS
        };
        self.last_advertise_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= wait)
    }

    /// Mint a transaction id, record it, and queue the probe.
    ///
    /// Returns whether it was emitted. A refusal comes from the per-peer
    /// outstanding cap (§7.1) and is not an error: it means this node is
    /// already probing as hard as it is allowed to, and the schedule will come
    /// back to it.
    fn emit_probe(
        &mut self,
        addr: SocketAddr,
        now_ms: u64,
        mint: &mut impl FnMut() -> TxId,
        out: &mut Vec<Action>,
    ) -> bool {
        let tx = mint();
        match self.paths.on_ping_sent(tx, addr, now_ms) {
            Ok(()) => {
                out.push(Action::Probe { addr, tx });
                true
            }
            Err(ProbeError::TooManyOutstanding) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::consts::{MAX_OUTSTANDING, MAX_PATHS_PER_PEER};
    use crate::path::{PongOutcome, Selection};

    fn v4(a: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, a], 51820))
    }

    fn v6(a: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, a], 51820))
    }

    /// A deterministic stand-in for a CSPRNG. Production draws real randomness;
    /// what matters here is that ids are distinct.
    fn counter() -> impl FnMut() -> TxId {
        let mut n: u64 = 0;
        move || {
            n += 1;
            let mut id = [0u8; 12];
            id[..8].copy_from_slice(&n.to_be_bytes());
            TxId(id)
        }
    }

    fn probes(actions: &[Action]) -> Vec<SocketAddr> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Probe { addr, .. } => Some(*addr),
                Action::Advertise { .. } => None,
            })
            .collect()
    }

    #[test]
    fn a_new_candidate_is_probed_at_once() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        assert_eq!(probes(&e.poll(0, &mut mint)), vec![v4(7)]);
    }

    #[test]
    fn probes_back_off_and_then_give_up() {
        // §7.5: 100 ms, 300 ms, 900 ms, then stop. A candidate that never
        // answers must not be probed forever — that is a peer's address, and
        // it may not be a peer at all.
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);

        let mut sent_at = Vec::new();
        for t in 0..2000u64 {
            if !probes(&e.poll(t, &mut mint)).is_empty() {
                sent_at.push(t);
            }
        }
        assert_eq!(sent_at, vec![0, 100, 400, 1300], "{sent_at:?}");
    }

    #[test]
    fn a_call_me_maybe_probes_everything_immediately() {
        // Simultaneous open. The peer received ours at nearly the same moment
        // and is probing now; a scheduler that staggered these would defeat
        // the entire technique.
        let mut e = Engine::new();
        let mut mint = counter();
        let cands = [Endpoint(v4(1)), Endpoint(v4(2)), Endpoint(v6(3))];
        e.on_call_me_maybe(&cands, 5_000);

        let got = probes(&e.poll(5_000, &mut mint));
        assert_eq!(got.len(), 3, "{got:?}");
        for c in cands {
            assert!(got.contains(&c.0), "{:?} was not probed", c.0);
        }
    }

    #[test]
    fn a_call_me_maybe_pre_empts_a_pending_backoff() {
        // The test that actually pins simultaneous open. The one above passes
        // whether or not `immediate` does anything, because a brand-new
        // candidate is due immediately regardless — the flag only matters for a
        // candidate already waiting out its backoff, which is the common case:
        // we probed on a stale address first, and the peer's CallMeMaybe has
        // just told us where it really is.
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        assert_eq!(probes(&e.poll(0, &mut mint)), vec![v4(7)]);
        // Mid-backoff: nothing is due until t = 100.
        assert!(probes(&e.poll(50, &mut mint)).is_empty());

        e.on_call_me_maybe(&[Endpoint(v4(7))], 50);
        assert_eq!(
            probes(&e.poll(50, &mut mint)),
            vec![v4(7)],
            "the peer said where it is and we waited out a backoff anyway"
        );
    }

    #[test]
    fn remote_candidate_advertisements_are_rate_limited() {
        let mut e = Engine::new();
        assert!(e.on_call_me_maybe(&[Endpoint(v4(7))], 0));
        assert!(!e.on_call_me_maybe(&[Endpoint(v4(8))], ADVERTISE_MIN_INTERVAL_MS - 1));
        assert!(e.on_call_me_maybe(&[Endpoint(v4(8))], ADVERTISE_MIN_INTERVAL_MS));
    }

    /// A distinct address per candidate, so a batch never collides with an
    /// earlier one and every advertisement is genuinely new state.
    fn batch(round: u16) -> Vec<Endpoint> {
        (0..crate::consts::MAX_CANDIDATES)
            .map(|n| {
                let n = u16::try_from(n).unwrap_or(0);
                Endpoint(SocketAddr::from((
                    [10, 0, 0, 1],
                    10_000 + round * u16::try_from(crate::consts::MAX_CANDIDATES).unwrap_or(1) + n,
                )))
            })
            .collect()
    }

    #[test]
    fn candidates_are_bounded_per_peer() {
        let mut e = Engine::new();
        for round in 0..5u16 {
            assert!(e.on_call_me_maybe(&batch(round), u64::from(round) * ADVERTISE_MIN_INTERVAL_MS));
        }
        assert_eq!(e.queue.len(), MAX_PATHS_PER_PEER);
        assert_eq!(e.paths().paths().len(), MAX_PATHS_PER_PEER);
    }

    /// **The test above passes whether or not confirmed paths are capped**,
    /// because nothing in it ever answers a probe. This is the case that
    /// distinguishes them: a peer that answers one `Ping` per address used to
    /// buy a permanent slot each time, because the only removal refused to
    /// touch a confirmed path.
    ///
    /// The assertion that matters is not the length — exempting confirmed
    /// paths and then *refusing* new ones bounds the length too, by locking the
    /// set to whichever sixty-four addresses answered first, which is a peer
    /// pinning us to addresses of its choosing. It is that the set still tracks
    /// the peer: the newest addresses are in it and the oldest are gone.
    #[test]
    fn confirming_a_path_does_not_buy_a_permanent_slot() {
        let mut e = Engine::new();
        let mut mint = counter();

        for round in 0..8u16 {
            let now = u64::from(round) * ADVERTISE_MIN_INTERVAL_MS;
            assert!(e.on_call_me_maybe(&batch(round), now));
            // Confirm each address in turn, which is what a peer reachable at
            // all sixteen would achieve. Driven directly rather than through
            // `poll` so the outstanding-probe cap cannot decide the outcome.
            for candidate in batch(round) {
                let tx = mint();
                if e.paths_mut().on_ping_sent(tx, candidate.0, now).is_ok() {
                    assert!(matches!(
                        e.paths_mut().on_pong(tx, now),
                        PongOutcome::Confirmed { .. }
                    ));
                }
            }
        }

        assert_eq!(
            e.paths().paths().len(),
            MAX_PATHS_PER_PEER,
            "confirmed paths grew past the cap"
        );
        assert_eq!(e.queue.len(), MAX_PATHS_PER_PEER, "the schedule drifted");

        let held = |addr: SocketAddr| e.paths().paths().iter().any(|p| p.addr == addr);
        let newest = batch(7);
        let oldest = batch(0);
        assert!(
            newest.iter().all(|c| held(c.0)),
            "the peer's current addresses were refused in favour of stale ones"
        );
        assert!(
            oldest.iter().all(|c| !held(c.0)),
            "an address confirmed eight rounds ago is still holding a slot"
        );
    }

    /// Eviction must never take the path currently carrying traffic. A peer
    /// that could displace the chosen path by naming addresses would have a
    /// disconnect primitive rather than a discovery protocol.
    #[test]
    fn the_chosen_path_is_never_evicted() {
        let mut e = Engine::new();
        let mut mint = counter();

        e.add_peer_candidate(v4(9), 0, false);
        let Some(Action::Probe { tx, .. }) = e.poll(0, &mut mint).into_iter().next() else {
            panic!("the candidate was not probed");
        };
        assert!(matches!(
            e.paths_mut().on_pong(tx, 10),
            PongOutcome::Confirmed { .. }
        ));
        assert_eq!(
            e.paths_mut().select(10),
            crate::path::Selection::Chose(v4(9))
        );

        for round in 0..8u16 {
            let now = 10 + u64::from(round) * ADVERTISE_MIN_INTERVAL_MS;
            assert!(e.on_call_me_maybe(&batch(round), now));
        }

        assert_eq!(e.paths().chosen(), Some(v4(9)));
        assert!(
            e.paths().paths().iter().any(|p| p.addr == v4(9)),
            "the chosen path was evicted to make room for a candidate"
        );
        assert_eq!(e.paths().paths().len(), MAX_PATHS_PER_PEER);
    }

    #[test]
    fn a_fresh_call_me_maybe_revives_an_exhausted_candidate() {
        // It is evidence the peer is present and trying, which is exactly when
        // a candidate that ran out of attempts deserves another go.
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        for t in 0..2000u64 {
            let _ = e.poll(t, &mut mint);
        }
        assert!(
            probes(&e.poll(3_000, &mut mint)).is_empty(),
            "still probing"
        );

        e.on_call_me_maybe(&[Endpoint(v4(7))], 3_000);
        assert_eq!(probes(&e.poll(3_000, &mut mint)), vec![v4(7)]);
    }

    #[test]
    fn the_chosen_path_is_kept_alive() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.paths_mut().set_relay(v4(200), 20, 0);
        let _ = e.paths_mut().select(0);
        assert_eq!(e.paths().chosen(), Some(v4(200)));

        // First poll sends one; then nothing until the keepalive interval.
        assert_eq!(probes(&e.poll(0, &mut mint)), vec![v4(200)]);
        assert!(probes(&e.poll(KEEPALIVE_MS - 1, &mut mint)).is_empty());
        assert_eq!(
            probes(&e.poll(KEEPALIVE_MS, &mut mint)),
            vec![v4(200)],
            "keepalive did not fire"
        );
    }

    #[test]
    fn alternatives_are_re_probed() {
        // Without this a node that settles on a relay at boot stays there
        // until something else disturbs it, and never finds the direct path
        // that came up a minute later.
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        // Exhaust the backoff schedule.
        for t in 0..2_000u64 {
            let _ = e.poll(t, &mut mint);
        }
        assert!(probes(&e.poll(2_000, &mut mint)).is_empty());

        let got = probes(&e.poll(REPROBE_MS, &mut mint));
        assert!(got.contains(&v4(7)), "alternatives were never re-probed");
    }

    #[test]
    fn local_candidates_are_advertised_once_per_change() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![Endpoint(v4(1))]);

        assert_eq!(advertisements(&e.poll(0, &mut mint)), 1);
        // Nothing changed, so nothing more is said *for a while*. A node with no
        // path does eventually repeat itself — see the test below — but not on
        // every poll, which at a 100 ms tick would be ten a second.
        for t in 1..REPROBE_MS {
            assert_eq!(
                advertisements(&e.poll(t, &mut mint)),
                0,
                "re-advertised at {t} with no change"
            );
        }
    }

    /// **A node with no direct path keeps saying where it is.**
    ///
    /// An advertisement is a datagram, and datagrams are lost. A peer that
    /// missed the only one we ever sent — because it had not been given our
    /// disco key yet, because it restarted, because the relay blinked — would
    /// never learn our address, and the pair would sit on the relay for good.
    /// Two real daemons did exactly that: one reached `direct` and the other
    /// stayed `relay`, because the advertisement it needed had been sent before
    /// it existed.
    #[test]
    fn a_node_with_no_path_keeps_saying_where_it_is() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![Endpoint(v4(1))]);

        let mut sent = 0;
        for t in 0..REPROBE_MS * 5 {
            sent += advertisements(&e.poll(t, &mut mint));
        }
        assert!(
            sent >= 4,
            "a node with no path advertised {sent} times in five re-probe \
             intervals; a peer that missed the first would never hear it"
        );
    }

    /// And it stops once there is a path, so a settled pair costs nothing.
    #[test]
    fn a_settled_pair_stops_advertising() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![Endpoint(v4(1))]);
        e.add_peer_candidate(v4(7), 0, false);

        let Some(Action::Probe { tx, .. }) = e
            .poll(0, &mut mint)
            .into_iter()
            .find(|a| matches!(a, Action::Probe { .. }))
        else {
            panic!("the candidate was not probed");
        };
        assert!(matches!(
            e.paths_mut().on_pong(tx, 10),
            PongOutcome::Confirmed { .. }
        ));
        assert_eq!(
            e.paths_mut().select(10),
            crate::path::Selection::Chose(v4(7))
        );

        // Keepalives keep the path fresh; nothing re-advertises.
        let mut sent = 0;
        for t in 11..REPROBE_MS * 3 {
            sent += advertisements(&e.poll(t, &mut mint));
        }
        assert_eq!(sent, 0, "a pair with a working path went on advertising");
    }

    fn advertisements(actions: &[Action]) -> usize {
        actions
            .iter()
            .filter(|a| matches!(a, Action::Advertise { .. }))
            .count()
    }

    #[test]
    fn re_enumerating_the_same_addresses_is_not_a_change() {
        // A node that re-reads its interfaces every second must not turn that
        // into a CallMeMaybe every second. Order must not matter either:
        // interface enumeration order is not stable across calls.
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![Endpoint(v4(1)), Endpoint(v6(2))]);
        let _ = e.poll(0, &mut mint);

        e.set_local_candidates(vec![Endpoint(v6(2)), Endpoint(v4(1))]);
        // Inside the repeat interval, so anything sent here is a response to
        // the reordering rather than to the passage of time.
        let a = e.poll(1_000, &mut mint);
        assert!(!a.iter().any(|a| matches!(a, Action::Advertise { .. })));
    }

    #[test]
    fn a_changed_address_is_advertised_again() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![Endpoint(v4(1))]);
        let _ = e.poll(0, &mut mint);

        e.set_local_candidates(vec![Endpoint(v4(1)), Endpoint(v4(2))]);
        let a = e.poll(ADVERTISE_MIN_INTERVAL_MS, &mut mint);
        assert!(a.iter().any(|a| matches!(a, Action::Advertise { .. })));
    }

    #[test]
    fn advertising_is_rate_limited() {
        // §7.5: at most one CallMeMaybe per peer per interval, however fast a
        // flapping interface changes the list.
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![Endpoint(v4(1))]);
        let _ = e.poll(0, &mut mint);

        let mut count = 0;
        for t in 1..ADVERTISE_MIN_INTERVAL_MS {
            e.set_local_candidates(vec![Endpoint(v4(u8::try_from(t % 200).unwrap_or(1)))]);
            if e.poll(t, &mut mint)
                .iter()
                .any(|a| matches!(a, Action::Advertise { .. }))
            {
                count += 1;
            }
        }
        assert_eq!(count, 0, "advertised {count} times inside the interval");
    }

    #[test]
    fn an_empty_candidate_list_is_not_advertised() {
        // §6.1 makes a zero-count CallMeMaybe malformed, so emitting one would
        // be emitting a datagram the peer must reject.
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![]);
        assert!(e.poll(0, &mut mint).is_empty());
    }

    #[test]
    fn probing_stops_at_the_outstanding_cap() {
        // §7.1's cap is per peer, and the scheduler must respect it rather
        // than emitting probes the path set has refused to record — which
        // would leave Pongs arriving for transactions nobody remembers.
        let mut e = Engine::new();
        let mut mint = counter();
        for i in 0..40u8 {
            e.add_peer_candidate(v4(i), 0, false);
        }
        let got = probes(&e.poll(0, &mut mint));
        assert_eq!(got.len(), MAX_OUTSTANDING);
        assert_eq!(e.paths().outstanding(), MAX_OUTSTANDING);
    }

    #[test]
    fn a_probe_is_recorded_before_it_is_emitted() {
        // The §7.1 association has to exist by the time the Pong can arrive.
        // Emitting first and recording afterwards is a race on a fast LAN.
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        let actions = e.poll(0, &mut mint);
        let Some(&Action::Probe { addr, tx }) = actions.first() else {
            panic!("expected a probe, got {actions:?}");
        };
        assert_eq!(
            e.paths_mut().on_pong(tx, 10),
            PongOutcome::Confirmed { addr, rtt_ms: 10 }
        );
    }

    #[test]
    fn a_confirmed_candidate_gets_its_attempts_back() {
        // Otherwise a path that answers, goes quiet, and comes back is never
        // probed again — the schedule would have spent its attempts on the
        // first outage.
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        let a = e.poll(0, &mut mint);
        let Some(&Action::Probe { tx, .. }) = a.first() else {
            panic!("expected a probe");
        };
        let _ = e.paths_mut().on_pong(tx, 10);
        e.on_confirmed(v4(7));

        // The full backoff schedule is available again.
        let mut sent = 0;
        for t in 10..3_000u64 {
            sent += probes(&e.poll(t, &mut mint)).len();
        }
        assert!(sent >= PROBE_BACKOFF_MS.len(), "only {sent} probes");
    }

    /// A laptop that suspends comes back with every NAT binding gone. §7.5's
    /// schedule would have written a candidate off long before the machine
    /// woke, and a give-up is not something the passage of sleep undoes on its
    /// own — so `rediscover` has to put every one of them back in play.
    #[test]
    fn a_resume_puts_every_written_off_candidate_back_in_play() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        e.add_peer_candidate(v6(9), 0, false);
        // Run past the end of the backoff schedule with nothing answering.
        for t in 0..2_000u64 {
            let _ = e.poll(t, &mut mint);
        }
        assert!(e.exhausted(), "the schedule must have given up first");

        e.rediscover(2_000);
        assert!(!e.exhausted());
        let mut resumed = probes(&e.poll(2_000, &mut mint));
        resumed.sort_by_key(std::string::ToString::to_string);
        assert_eq!(resumed, vec![v4(7), v6(9)]);
    }

    /// The other half: a node whose external address has just changed has to
    /// say so, not only go looking. Without the advertisement the peer keeps
    /// probing the address this node held before it slept.
    #[test]
    fn a_resume_advertises_this_nodes_candidates_again() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.set_local_candidates(vec![Endpoint(v4(1))]);
        e.add_peer_candidate(v4(7), 0, false);
        // The advertisement §7.5 already owed, so the floor below is measured
        // against a real previous send rather than against nothing.
        assert!(e
            .poll(0, &mut mint)
            .iter()
            .any(|a| matches!(a, Action::Advertise { .. })));
        assert!(
            !e.poll(1, &mut mint)
                .iter()
                .any(|a| matches!(a, Action::Advertise { .. })),
            "§7.5's floor still applies to an ordinary poll"
        );

        // Deliberately the *same* stamp: a host whose monotonic clock does not
        // count time spent asleep resumes with the clock it went to sleep with,
        // and the advertisement still has to go out.
        e.rediscover(1);
        assert!(
            e.poll(1, &mut mint)
                .iter()
                .any(|a| matches!(a, Action::Advertise { .. })),
            "a resume must re-advertise even when no time appears to have passed"
        );
    }

    /// The chosen path is the one carrying traffic, so it is the one whose
    /// silence costs most. It must be probed on the resume poll rather than
    /// at the end of whatever remained of its keepalive interval.
    #[test]
    fn a_resume_pings_the_chosen_path_immediately() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.add_peer_candidate(v4(7), 0, false);
        let tx = match e.poll(0, &mut mint).first() {
            Some(Action::Probe { tx, .. }) => *tx,
            other => panic!("expected a probe, got {other:?}"),
        };
        assert!(matches!(
            e.paths_mut().on_pong(tx, 1),
            PongOutcome::Confirmed { .. }
        ));
        e.on_confirmed(v4(7));
        assert_eq!(e.paths_mut().select(1), Selection::Chose(v4(7)));
        // Consume the keepalive this poll owes, so the next one owes nothing.
        let _ = e.poll(2, &mut mint);
        assert!(probes(&e.poll(3, &mut mint)).is_empty());

        e.rediscover(3);
        assert!(
            probes(&e.poll(3, &mut mint)).contains(&v4(7)),
            "the chosen path must be re-probed on the resume poll"
        );
    }

    /// Nothing to rediscover is not an error, and must not manufacture an
    /// advertisement out of an empty candidate list.
    #[test]
    fn rediscovering_a_peer_with_nothing_known_does_nothing() {
        let mut e = Engine::new();
        let mut mint = counter();
        e.rediscover(0);
        assert!(e.poll(0, &mut mint).is_empty());
    }
}
