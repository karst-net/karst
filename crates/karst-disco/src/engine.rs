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

use crate::consts::{
    ADVERTISE_MIN_INTERVAL_MS, KEEPALIVE_MS, MAX_PATHS_PER_PEER, PROBE_BACKOFF_MS, REPROBE_MS,
};
use crate::msg::{Endpoint, TxId};
use crate::path::{PathKind, PathSet, ProbeError};

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

        // A peer can name sixteen addresses per CallMeMaybe indefinitely. The
        // queue is therefore a bounded resource, not a historical record.
        // Evict the oldest unconfirmed candidate first; confirmed paths have
        // demonstrated reachability and remain subject to normal staleness.
        if self.queue.len() >= MAX_PATHS_PER_PEER {
            let evict = self
                .queue
                .iter()
                .position(|scheduled| {
                    self.paths
                        .paths()
                        .iter()
                        .any(|path| path.addr == scheduled.addr && path.last_pong_ms.is_none())
                })
                .unwrap_or(0);
            let evicted = self.queue.remove(evict);
            self.paths.remove_unconfirmed_candidate(evicted.addr);
        }
        self.paths.add_candidate(addr, PathKind::direct_for(addr));
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

    /// Note that a probe was answered, so its backoff resets.
    pub fn on_confirmed(&mut self, addr: SocketAddr) {
        if let Some(scheduled) = self.queue.iter_mut().find(|s| s.addr == addr) {
            scheduled.attempts = 0;
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

    fn should_advertise(&self, now_ms: u64) -> bool {
        if !self.advertise_pending || self.local.is_empty() {
            return false;
        }
        self.last_advertise_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= ADVERTISE_MIN_INTERVAL_MS)
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
    use crate::consts::MAX_OUTSTANDING;
    use crate::path::PongOutcome;

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

    #[test]
    fn candidates_are_bounded_per_peer() {
        let mut e = Engine::new();
        for batch in 0..5u16 {
            let candidates: Vec<Endpoint> = (0..crate::consts::MAX_CANDIDATES)
                .map(|n| {
                    Endpoint(SocketAddr::from((
                        [
                            10,
                            0,
                            u8::try_from(batch).unwrap_or(0),
                            u8::try_from(n).unwrap_or(0),
                        ],
                        10_000 + batch * 100 + u16::try_from(n).unwrap_or(0),
                    )))
                })
                .collect();
            assert!(e.on_call_me_maybe(&candidates, u64::from(batch) * ADVERTISE_MIN_INTERVAL_MS,));
        }
        assert_eq!(e.queue.len(), MAX_PATHS_PER_PEER);
        assert!(e.paths().paths().len() <= MAX_PATHS_PER_PEER);
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

        let first = e.poll(0, &mut mint);
        assert_eq!(
            first
                .iter()
                .filter(|a| matches!(a, Action::Advertise { .. }))
                .count(),
            1
        );
        // Nothing changed, so nothing more is said.
        for t in 1..60_000u64 {
            let a = e.poll(t, &mut mint);
            assert!(
                !a.iter().any(|a| matches!(a, Action::Advertise { .. })),
                "re-advertised at {t} with no change"
            );
        }
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
        let a = e.poll(100_000, &mut mint);
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
}
