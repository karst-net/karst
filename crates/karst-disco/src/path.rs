// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Probe bookkeeping and path selection — `spec/aven-v1.md` §7 and §8.
//!
//! Sans-io and sans-clock: every method that cares about time takes a
//! millisecond stamp. That is what makes flapping, staleness and expiry
//! testable without sleeping.
//!
//! # The rule this module exists to enforce
//!
//! §7.1: **a `Pong` confirms the endpoint its `Ping` was sent to, not the
//! address the `Pong` arrived from.** [`PathSet::on_pong`] therefore takes the
//! transaction id and nothing else — there is no parameter for the source
//! address, because an implementation that had one could be walked to any
//! address an on-path attacker liked by copying a genuine `Pong` and re-sending
//! it from somewhere else.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use crate::consts::{
    ANSWERED_WINDOW, HYSTERESIS_MS, HYSTERESIS_PERCENT, HYSTERESIS_SAMPLES, MAX_OUTSTANDING,
    MAX_PATHS_PER_PEER, PATH_STALE_MS, TX_TIMEOUT_MS,
};
use crate::msg::TxId;

/// How a path reaches a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathKind {
    /// Through a relay. Always available, always last resort.
    Relay,
    /// Straight to the peer over IPv4.
    DirectV4,
    /// Straight to the peer over IPv6.
    DirectV6,
}

impl PathKind {
    /// Classify a candidate address.
    #[must_use]
    pub const fn direct_for(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(_) => Self::DirectV4,
            SocketAddr::V6(_) => Self::DirectV6,
        }
    }

    /// Whether this path avoids a relay.
    #[must_use]
    pub const fn is_direct(self) -> bool {
        matches!(self, Self::DirectV4 | Self::DirectV6)
    }

    /// §8 rule 2, and it is a **hard** ordering: 0 for direct, 1 for relay.
    /// A relay never wins on latency, because latency is not the only axis and
    /// the operator's view of the traffic graph does not appear in one.
    const fn group(self) -> u8 {
        if self.is_direct() {
            0
        } else {
            1
        }
    }
}

/// One known way to reach a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Path {
    /// Where to send.
    pub addr: SocketAddr,
    /// What kind of path this is.
    pub kind: PathKind,
    /// Most recent round-trip time, if it has ever answered.
    pub latency_ms: Option<u64>,
    /// When it last answered.
    pub last_pong_ms: Option<u64>,
}

impl Path {
    /// §8 rule 1: a path with no `Pong` inside the staleness window is not
    /// eligible, however good its last measurement was.
    #[must_use]
    pub fn is_usable(&self, now_ms: u64) -> bool {
        match self.last_pong_ms {
            Some(t) => now_ms.saturating_sub(t) <= PATH_STALE_MS,
            None => false,
        }
    }
}

/// What the caller should do with a decoded `Pong`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PongOutcome {
    /// A probe was matched and the named path is now confirmed working.
    Confirmed {
        /// The endpoint the corresponding `Ping` was sent to.
        addr: SocketAddr,
        /// Measured round-trip time.
        rtt_ms: u64,
    },
    /// No outstanding probe carries this id: expired, already spent, or forged
    /// by somebody who nonetheless holds the disco key. Dropped.
    Unmatched,
}

/// Why a probe could not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// Too many probes are already outstanding for this peer — §7.1.
    TooManyOutstanding,
}

/// What admitting a candidate did to the bounded path set.
///
/// Returned rather than swallowed because the caller keeps a probe schedule
/// alongside these paths, and a displaced address must leave both or the
/// scheduler goes on probing something this set no longer knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The address was already known. Nothing changed.
    Known,
    /// Recorded as a new, unconfirmed candidate.
    Added {
        /// The address dropped to make room, which the caller must also forget.
        evicted: Option<SocketAddr>,
    },
    /// Refused: every slot holds a confirmed path that is still in use.
    Full,
}

/// Whether a slot could be freed for a new path, and what it cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Room {
    /// A slot is available. `evicted` names the path dropped for it, if any.
    Available {
        /// The displaced address, or `None` when there was already space.
        evicted: Option<SocketAddr>,
    },
    /// Nothing could be freed without taking the path currently in use.
    Full,
}

#[derive(Debug, Clone, Copy)]
struct Outstanding {
    addr: SocketAddr,
    sent_ms: u64,
}

/// What a node knows about how to reach one peer.
#[derive(Debug, Default)]
pub struct PathSet {
    paths: Vec<Path>,
    outstanding: HashMap<TxId, Outstanding>,
    /// Transaction ids this node has already answered — §7.4. A bounded
    /// window, oldest evicted first.
    answered: VecDeque<TxId>,
    chosen: Option<SocketAddr>,
    /// Consecutive measurements in which one challenger has beaten the chosen
    /// path by the hysteresis margin — §8.2.
    challenger: Option<(SocketAddr, u32)>,
}

impl PathSet {
    /// A peer with nothing known about it yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate, or report that it is already known.
    ///
    /// A candidate is **not** a path until it answers a probe. Adding one
    /// changes nothing about selection.
    ///
    /// **The cap lives here, in the type that owns the vector.** `§5.3`'s
    /// sixteen-candidate limit bounds one `CallMeMaybe`, not the number of
    /// distinct addresses an authenticated peer can name over a connection's
    /// lifetime — and every address that ever answered a single `Ping` used to
    /// be resident for good, because the only removal refused to touch a
    /// confirmed path. A peer holding a disco key and a /64 could therefore
    /// grow this set, and the per-tick selection scan over it, without limit.
    pub fn add_candidate(&mut self, addr: SocketAddr, kind: PathKind) -> Admission {
        if self.paths.iter().any(|p| p.addr == addr) {
            return Admission::Known;
        }
        let Room::Available { evicted } = self.make_room() else {
            return Admission::Full;
        };
        self.paths.push(Path {
            addr,
            kind,
            latency_ms: None,
            last_pong_ms: None,
        });
        Admission::Added { evicted }
    }

    /// Free a slot for a new path, and say which address paid for it.
    ///
    /// The order is the whole of the policy. An unconfirmed candidate has
    /// demonstrated nothing, so those go first and oldest-first. Only when
    /// every slot holds a confirmed path is one of *those* dropped, and then
    /// the stalest — a path that answered a minute ago is weaker evidence than
    /// one that answered a second ago. The chosen path is never a victim:
    /// dropping the path currently carrying traffic to make room for an address
    /// that has answered nothing inverts the rule this set exists to enforce.
    fn make_room(&mut self) -> Room {
        if self.paths.len() < MAX_PATHS_PER_PEER {
            return Room::Available { evicted: None };
        }
        let chosen = self.chosen;
        let victim = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, path)| Some(path.addr) != chosen)
            // `None` sorts before `Some`, so ordering on `last_pong_ms` alone
            // already puts every unconfirmed candidate ahead of every confirmed
            // path and then orders the confirmed ones stalest-first. The index
            // breaks ties among candidates, which all carry `None`.
            .min_by_key(|(index, path)| (path.last_pong_ms, *index))
            .map(|(index, _)| index);
        match victim {
            Some(victim) => Room::Available {
                evicted: Some(self.paths.remove(victim).addr),
            },
            // Only reachable if the cap is one and that one slot is in use.
            None => Room::Full,
        }
    }

    /// Record that a `Ping` bearing `tx` was sent to `addr`.
    ///
    /// The association recorded here is the whole of §7.1's protection: the
    /// answering `Pong` will confirm `addr` because that is what this call
    /// says, and not because of where the `Pong` came from.
    ///
    /// # Errors
    /// [`ProbeError::TooManyOutstanding`] once the per-peer cap is reached.
    /// Outstanding probes are state a peer's behaviour causes us to allocate,
    /// so they are counted.
    pub fn on_ping_sent(
        &mut self,
        tx: TxId,
        addr: SocketAddr,
        now_ms: u64,
    ) -> Result<(), ProbeError> {
        self.expire(now_ms);
        if self.outstanding.len() >= MAX_OUTSTANDING {
            return Err(ProbeError::TooManyOutstanding);
        }
        self.outstanding.insert(
            tx,
            Outstanding {
                addr,
                sent_ms: now_ms,
            },
        );
        Ok(())
    }

    /// Decide whether to answer an authenticated `Ping` — §7.4.
    ///
    /// Returns `false` for a transaction id already answered inside the
    /// window, in which case the caller MUST NOT emit a `Pong`.
    ///
    /// This exists because `ProVerif` said so. Draft 0.1 of the specification
    /// had no such rule, on the reasoning that a `Ping` is authenticated and so
    /// cannot be forged — which is true, and is not the same as saying a
    /// genuine one cannot be *reused*. The injective form of "the responder
    /// answers only probes the prober sent" came back false while the
    /// non-injective form came back true, which is precisely "answered a real
    /// `Ping`, more than once": a keyless reflector for anyone able to capture
    /// one datagram.
    ///
    /// The window is bounded, so this is "at most once within the window". An
    /// unbounded cache would be a memory-exhaustion vector reachable by the
    /// same replay it exists to stop.
    pub fn on_ping_received(&mut self, tx: TxId) -> bool {
        if self.answered.contains(&tx) {
            return false;
        }
        if self.answered.len() >= ANSWERED_WINDOW {
            self.answered.pop_front();
        }
        self.answered.push_back(tx);
        true
    }

    /// Match an authenticated `Pong` against an outstanding probe.
    ///
    /// Takes no source address, by design — see the module documentation.
    pub fn on_pong(&mut self, tx: TxId, now_ms: u64) -> PongOutcome {
        self.expire(now_ms);
        // Removed, not read: §7.1 accepts a `tx_id` exactly once, so a second
        // `Pong` bearing a spent id finds nothing.
        let Some(sent) = self.outstanding.remove(&tx) else {
            return PongOutcome::Unmatched;
        };
        let rtt_ms = now_ms.saturating_sub(sent.sent_ms);

        if let Some(path) = self.paths.iter_mut().find(|p| p.addr == sent.addr) {
            path.latency_ms = Some(rtt_ms);
            path.last_pong_ms = Some(now_ms);
        } else if matches!(self.make_room(), Room::Available { .. }) {
            // The candidate was evicted between probe and answer. Re-adding it
            // is right: something answered, so it works. It goes through the
            // same cap as every other admission, because a peer that names a
            // fresh address and answers one probe for each would otherwise grow
            // this set through here instead.
            self.paths.push(Path {
                addr: sent.addr,
                kind: PathKind::direct_for(sent.addr),
                latency_ms: Some(rtt_ms),
                last_pong_ms: Some(now_ms),
            });
        }

        PongOutcome::Confirmed {
            addr: sent.addr,
            rtt_ms,
        }
    }

    /// Note that the relay path is available. It is always usable and needs no
    /// probing; `ponor-v1.md` §9.1 keeps the home relay connected regardless.
    pub fn set_relay(&mut self, addr: SocketAddr, latency_ms: u64, now_ms: u64) {
        if let Some(p) = self.paths.iter_mut().find(|p| p.kind == PathKind::Relay) {
            p.addr = addr;
            p.latency_ms = Some(latency_ms);
            p.last_pong_ms = Some(now_ms);
            return;
        }
        self.paths.push(Path {
            addr,
            kind: PathKind::Relay,
            latency_ms: Some(latency_ms),
            last_pong_ms: Some(now_ms),
        });
    }

    fn expire(&mut self, now_ms: u64) {
        self.outstanding
            .retain(|_, o| now_ms.saturating_sub(o.sent_ms) <= TX_TIMEOUT_MS);
    }

    /// Probes awaiting an answer.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    /// Every path known, working or not.
    #[must_use]
    pub fn paths(&self) -> &[Path] {
        &self.paths
    }

    /// The path currently in use, if any.
    #[must_use]
    pub fn chosen(&self) -> Option<SocketAddr> {
        self.chosen
    }

    /// Re-evaluate which path to use — §8.
    ///
    /// Call after every measurement. Returns what happened, so a caller can
    /// log a transition without diffing state itself.
    pub fn select(&mut self, now_ms: u64) -> Selection {
        let best = self.best(now_ms);

        let Some(best) = best else {
            // Nothing is usable. The chosen path is cleared rather than kept:
            // continuing to send into a path that has stopped answering is
            // worse than admitting there is none.
            let had = self.chosen.take();
            self.challenger = None;
            return if had.is_some() {
                Selection::Lost
            } else {
                Selection::None
            };
        };

        let Some(current_addr) = self.chosen else {
            self.chosen = Some(best.addr);
            self.challenger = None;
            return Selection::Chose(best.addr);
        };

        let Some(current) = self
            .paths
            .iter()
            .copied()
            .find(|p| p.addr == current_addr && p.is_usable(now_ms))
        else {
            // The chosen path went stale; the best usable one replaces it at
            // once, with no hysteresis. Hysteresis exists to stop *churn*
            // between two working paths, not to delay leaving a dead one.
            self.chosen = Some(best.addr);
            self.challenger = None;
            return Selection::Switched(best.addr);
        };

        if best.addr == current.addr {
            self.challenger = None;
            return Selection::Kept(current.addr);
        }

        // §8 rule 2 is exempt from hysteresis: a direct path that starts
        // working displaces a relay immediately, because causing exactly that
        // transition is what the protocol is for.
        if best.kind.is_direct() && !current.kind.is_direct() {
            self.chosen = Some(best.addr);
            self.challenger = None;
            return Selection::Switched(best.addr);
        }

        // Otherwise a challenger must beat the incumbent by the margin, and
        // keep doing so.
        if !beats(best, current) {
            self.challenger = None;
            return Selection::Kept(current.addr);
        }
        let streak = match self.challenger {
            Some((addr, n)) if addr == best.addr => n.saturating_add(1),
            _ => 1,
        };
        if streak >= HYSTERESIS_SAMPLES {
            self.chosen = Some(best.addr);
            self.challenger = None;
            Selection::Switched(best.addr)
        } else {
            self.challenger = Some((best.addr, streak));
            Selection::Kept(current.addr)
        }
    }

    fn best(&self, now_ms: u64) -> Option<Path> {
        self.paths
            .iter()
            .copied()
            .filter(|p| p.is_usable(now_ms))
            .min_by_key(|p| score(*p))
    }
}

/// The §8.2 margin: the larger of an absolute and a proportional threshold.
///
/// 20 ms is meaningless on a 400 ms satellite path and enormous on a 2 ms LAN,
/// so neither alone is a sensible rule.
#[must_use]
pub fn margin(latency_ms: u64) -> u64 {
    HYSTERESIS_MS.max(latency_ms.saturating_mul(HYSTERESIS_PERCENT) / 100)
}

/// Order paths by §8: group first, then effective latency.
///
/// **Rule 3 is implemented as a latency credit rather than as a comparison.**
/// The specification phrases it as "IPv6 beats IPv4 when their latencies are
/// within the hysteresis margin", and a comparator written that way directly is
/// not transitive — with three paths it can rank A over B over C over A, and
/// `min_by` on a non-transitive comparator returns whichever element it
/// happened to see first. Giving IPv6 a credit of one margin produces the same
/// answer for two paths, is a total order for any number, and cannot depend on
/// iteration order.
fn score(p: Path) -> (u8, u64) {
    let latency = p.latency_ms.unwrap_or(u64::MAX);
    let effective = if p.kind == PathKind::DirectV6 {
        latency.saturating_sub(margin(latency))
    } else {
        latency
    };
    (p.kind.group(), effective)
}

/// Whether `challenger` beats `incumbent` by the §8.2 margin.
fn beats(challenger: Path, incumbent: Path) -> bool {
    let (cg, ce) = score(challenger);
    let (ig, ie) = score(incumbent);
    if cg != ig {
        return cg < ig;
    }
    if challenger.latency_ms.is_none() || incumbent.latency_ms.is_none() {
        return false;
    }
    ce.saturating_add(margin(ie)) <= ie
}

/// What [`PathSet::select`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// No usable path. The peer is unreachable until something answers.
    None,
    /// The chosen path stopped being usable and nothing replaced it.
    Lost,
    /// A path was chosen where there was none.
    Chose(SocketAddr),
    /// The chosen path is still the best one.
    Kept(SocketAddr),
    /// A different path took over.
    Switched(SocketAddr),
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;
    use crate::consts::ANSWERED_WINDOW;

    fn v4(a: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, a], 51820))
    }

    fn v6(a: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, a], 51820))
    }

    fn tx(b: u8) -> TxId {
        TxId([b; 12])
    }

    /// Probe an address and have it answer with the given RTT.
    fn confirm(s: &mut PathSet, id: u8, addr: SocketAddr, at: u64, rtt: u64) {
        s.add_candidate(addr, PathKind::direct_for(addr));
        s.on_ping_sent(tx(id), addr, at).expect("room for a probe");
        assert_eq!(
            s.on_pong(tx(id), at + rtt),
            PongOutcome::Confirmed { addr, rtt_ms: rtt }
        );
    }

    // ── §7.1, the rule the module exists for ──────────────────────────────

    #[test]
    fn a_pong_confirms_the_endpoint_the_ping_went_to() {
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 1_000, 12);
        let p = s.paths().iter().find(|p| p.addr == v4(7)).expect("path");
        assert_eq!(p.latency_ms, Some(12));
        assert!(p.is_usable(1_012));
    }

    #[test]
    fn a_transaction_id_is_spent_once() {
        // §7.1. A second Pong bearing the same id finds nothing, so a replay
        // cannot refresh a path's liveness for free.
        let mut s = PathSet::new();
        s.add_candidate(v4(7), PathKind::DirectV4);
        s.on_ping_sent(tx(1), v4(7), 0).expect("probe");
        assert!(matches!(
            s.on_pong(tx(1), 10),
            PongOutcome::Confirmed { .. }
        ));
        assert_eq!(s.on_pong(tx(1), 20), PongOutcome::Unmatched);
    }

    #[test]
    fn an_unknown_transaction_id_confirms_nothing() {
        let mut s = PathSet::new();
        s.add_candidate(v4(7), PathKind::DirectV4);
        assert_eq!(s.on_pong(tx(9), 10), PongOutcome::Unmatched);
        assert!(!s.paths()[0].is_usable(10));
    }

    #[test]
    fn an_outstanding_probe_expires() {
        let mut s = PathSet::new();
        s.on_ping_sent(tx(1), v4(7), 0).expect("probe");
        assert_eq!(s.outstanding(), 1);
        assert_eq!(s.on_pong(tx(1), TX_TIMEOUT_MS + 1), PongOutcome::Unmatched);
        assert_eq!(s.outstanding(), 0);
    }

    #[test]
    fn outstanding_probes_are_bounded() {
        // They are state a peer's behaviour causes us to allocate.
        let mut s = PathSet::new();
        for i in 0..MAX_OUTSTANDING {
            s.on_ping_sent(tx(u8::try_from(i).unwrap()), v4(1), 0)
                .expect("within the cap");
        }
        assert_eq!(
            s.on_ping_sent(tx(200), v4(1), 0),
            Err(ProbeError::TooManyOutstanding)
        );
        // And the cap is a window, not a lifetime limit.
        s.on_ping_sent(tx(201), v4(1), TX_TIMEOUT_MS + 1)
            .expect("expired probes freed room");
    }

    // ── §7.4, the flaw modelling found ────────────────────────────────────

    #[test]
    fn a_probe_is_answered_once() {
        // The reflector. A captured Ping replayed from anywhere must not
        // produce a second Pong.
        let mut s = PathSet::new();
        assert!(s.on_ping_received(tx(1)));
        assert!(!s.on_ping_received(tx(1)));
        assert!(!s.on_ping_received(tx(1)));
    }

    #[test]
    fn distinct_probes_are_each_answered() {
        // The rule must not break ordinary probing, including the
        // retransmissions §7.5 schedules — which carry fresh ids for exactly
        // this reason.
        let mut s = PathSet::new();
        for i in 0..32 {
            assert!(s.on_ping_received(tx(i)), "probe {i} was refused");
        }
    }

    #[test]
    fn the_answered_window_is_bounded() {
        // An unbounded cache would be a memory-exhaustion vector reachable by
        // the very replay it exists to stop.
        let mut s = PathSet::new();
        for i in 0..(ANSWERED_WINDOW + 8) {
            let mut id = [0u8; 12];
            id[0] = (i & 0xff) as u8;
            id[1] = (i >> 8) as u8;
            assert!(s.on_ping_received(TxId(id)));
        }
        // The oldest have been evicted, so they would be answered again. That
        // is the stated limit of the guarantee — at most once *within the
        // window* — and it is a deliberate trade, not an oversight.
        assert!(s.on_ping_received(TxId([0u8; 12])));
    }

    // ── §8, selection ─────────────────────────────────────────────────────

    #[test]
    fn a_candidate_that_has_not_answered_is_not_a_path() {
        let mut s = PathSet::new();
        s.add_candidate(v4(7), PathKind::DirectV4);
        assert_eq!(s.select(0), Selection::None);
        assert_eq!(s.chosen(), None);
    }

    #[test]
    fn the_relay_is_used_when_nothing_else_works() {
        let mut s = PathSet::new();
        s.set_relay(v4(200), 40, 0);
        assert_eq!(s.select(0), Selection::Chose(v4(200)));
    }

    #[test]
    fn a_direct_path_displaces_a_relay_immediately() {
        // §8 rule 2 is exempt from hysteresis: causing exactly this transition
        // is what the protocol is for.
        let mut s = PathSet::new();
        s.set_relay(v4(200), 10, 0);
        assert_eq!(s.select(0), Selection::Chose(v4(200)));

        confirm(&mut s, 1, v4(7), 100, 90); // direct, and much slower
        assert_eq!(s.select(200), Selection::Switched(v4(7)));
    }

    #[test]
    fn a_faster_relay_never_displaces_a_working_direct_path() {
        // Latency is not the only axis: a relay discloses the traffic graph to
        // its operator, and that does not appear in a round-trip time.
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 200);
        assert_eq!(s.select(10), Selection::Chose(v4(7)));

        s.set_relay(v4(200), 1, 10);
        for t in 0..10 {
            assert_eq!(s.select(20 + t), Selection::Kept(v4(7)));
        }
    }

    #[test]
    fn ipv6_wins_a_tie_against_ipv4() {
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 30);
        confirm(&mut s, 2, v6(1), 0, 30);
        assert_eq!(s.select(30), Selection::Chose(v6(1)));
    }

    #[test]
    fn a_much_faster_ipv4_path_still_beats_ipv6() {
        // Rule 3 applies within the hysteresis margin; rule 4 takes over
        // beyond it. Family preference is a tie-break, not an override.
        let mut s = PathSet::new();
        confirm(&mut s, 1, v6(1), 0, 300);
        assert_eq!(s.select(300), Selection::Chose(v6(1)));
        confirm(&mut s, 2, v4(7), 400, 10);
        // Three consecutive measurements, per §8.2.
        assert_eq!(s.select(500), Selection::Kept(v6(1)));
        assert_eq!(s.select(501), Selection::Kept(v6(1)));
        assert_eq!(s.select(502), Selection::Switched(v4(7)));
    }

    #[test]
    fn a_marginally_better_path_does_not_cause_a_switch() {
        // §8.2: 20 ms or 20%, whichever is larger. 48 against 50 is neither.
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 50);
        assert_eq!(s.select(50), Selection::Chose(v4(7)));
        confirm(&mut s, 2, v4(8), 100, 48);
        for t in 0..10 {
            assert_eq!(s.select(200 + t), Selection::Kept(v4(7)));
        }
    }

    #[test]
    fn a_switch_needs_three_consecutive_wins() {
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 100);
        assert_eq!(s.select(100), Selection::Chose(v4(7)));
        confirm(&mut s, 2, v4(8), 100, 10);

        assert_eq!(s.select(200), Selection::Kept(v4(7)));
        assert_eq!(s.select(201), Selection::Kept(v4(7)));
        assert_eq!(s.select(202), Selection::Switched(v4(8)));
    }

    #[test]
    fn an_interrupted_streak_starts_over() {
        // The anti-flapping property. A challenger that wins twice, loses
        // once, then wins twice must not switch: otherwise a path that
        // alternates every other sample still wins eventually.
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 100);
        assert_eq!(s.select(100), Selection::Chose(v4(7)));

        confirm(&mut s, 2, v4(8), 100, 10);
        assert_eq!(s.select(200), Selection::Kept(v4(7)));
        assert_eq!(s.select(201), Selection::Kept(v4(7)));

        // The challenger degrades — no longer beating the margin.
        confirm(&mut s, 3, v4(8), 210, 100);
        assert_eq!(s.select(320), Selection::Kept(v4(7)));

        // And recovers. The streak restarts rather than resuming at two.
        confirm(&mut s, 4, v4(8), 330, 10);
        assert_eq!(s.select(400), Selection::Kept(v4(7)));
        assert_eq!(s.select(401), Selection::Kept(v4(7)));
        assert_eq!(s.select(402), Selection::Switched(v4(8)));
    }

    #[test]
    fn a_stale_path_stops_being_eligible() {
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 10);
        assert_eq!(s.select(10), Selection::Chose(v4(7)));
        assert_eq!(s.select(10 + PATH_STALE_MS), Selection::Kept(v4(7)));
        assert_eq!(s.select(11 + PATH_STALE_MS + 10), Selection::Lost);
        assert_eq!(s.chosen(), None);
    }

    #[test]
    fn a_dying_direct_path_falls_back_to_the_relay_without_hysteresis() {
        // §8.3. Hysteresis stops churn between two working paths; it must not
        // delay leaving a dead one.
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 10);
        s.set_relay(v4(200), 40, 0);
        assert_eq!(s.select(10), Selection::Chose(v4(7)));

        // The relay keeps answering; the direct path does not.
        let later = 10 + PATH_STALE_MS + 1;
        s.set_relay(v4(200), 40, later);
        assert_eq!(s.select(later), Selection::Switched(v4(200)));
    }

    #[test]
    fn losing_everything_reports_lost_once_then_none() {
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 0, 10);
        assert_eq!(s.select(10), Selection::Chose(v4(7)));
        let dead = 11 + PATH_STALE_MS + 10;
        assert_eq!(s.select(dead), Selection::Lost);
        assert_eq!(s.select(dead + 1), Selection::None);
    }

    #[test]
    fn a_repeated_candidate_is_not_duplicated() {
        let mut s = PathSet::new();
        assert_eq!(
            s.add_candidate(v4(7), PathKind::DirectV4),
            Admission::Added { evicted: None }
        );
        assert_eq!(s.add_candidate(v4(7), PathKind::DirectV4), Admission::Known);
        assert_eq!(s.paths().len(), 1);
    }

    // ── the cap ───────────────────────────────────────────────────────────

    /// Fill the remaining slots with candidates that have never answered.
    fn fill(s: &mut PathSet) {
        for n in 0..MAX_PATHS_PER_PEER - s.paths().len() {
            let addr = SocketAddr::from(([10, 0, 0, 1], 20_000 + n as u16));
            assert_eq!(
                s.add_candidate(addr, PathKind::DirectV4),
                Admission::Added { evicted: None }
            );
        }
        assert_eq!(s.paths().len(), MAX_PATHS_PER_PEER);
    }

    #[test]
    fn an_unconfirmed_candidate_gives_way_before_a_confirmed_path() {
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 1_000, 10);
        fill(&mut s);

        let Admission::Added {
            evicted: Some(evicted),
        } = s.add_candidate(v4(9), PathKind::DirectV4)
        else {
            panic!("the candidate was refused");
        };
        assert_ne!(
            evicted,
            v4(7),
            "a confirmed path was evicted before a candidate"
        );
        assert_eq!(s.paths().len(), MAX_PATHS_PER_PEER);
    }

    /// Among confirmed paths the stalest goes, and **insertion order must not
    /// decide it**: the address that answered a minute ago is weaker evidence
    /// than the one that answered a second ago, whichever arrived first.
    #[test]
    fn the_stalest_confirmed_path_is_the_one_evicted() {
        let mut s = PathSet::new();
        // Added first, answered most recently — so index order and staleness
        // order disagree, which is the whole point of the case.
        confirm(&mut s, 1, v4(7), 90_000, 10);
        confirm(&mut s, 2, v4(8), 1_000, 10);
        for n in 0..MAX_PATHS_PER_PEER - 2 {
            let addr = SocketAddr::from(([10, 0, 0, 1], 20_000 + n as u16));
            confirm(&mut s, 100 + n as u8, addr, 50_000, 10);
        }
        assert_eq!(s.paths().len(), MAX_PATHS_PER_PEER);

        assert_eq!(
            s.add_candidate(v4(9), PathKind::DirectV4),
            Admission::Added {
                evicted: Some(v4(8))
            },
            "eviction followed insertion order rather than staleness"
        );
    }

    /// The chosen path is exempt, and the case that proves it is the one where
    /// **every other rule says it should go**: it is confirmed, so no candidate
    /// outranks it, and it is the stalest of the confirmed, so it is next in
    /// line. A peer that could displace the path currently carrying traffic by
    /// naming addresses would hold a disconnect primitive.
    #[test]
    fn the_chosen_path_is_never_the_victim() {
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 1_000, 10);
        assert_eq!(s.select(1_010), Selection::Chose(v4(7)));

        // Everything else answered far more recently, so the chosen path is
        // the stalest thing in the set.
        for n in 0..MAX_PATHS_PER_PEER - 1 {
            let addr = SocketAddr::from(([10, 0, 0, 1], 20_000 + n as u16));
            confirm(&mut s, 100 + n as u8, addr, 90_000, 10);
        }
        assert_eq!(s.paths().len(), MAX_PATHS_PER_PEER);

        let Admission::Added {
            evicted: Some(evicted),
        } = s.add_candidate(v4(9), PathKind::DirectV4)
        else {
            panic!("the candidate was refused");
        };
        assert_ne!(
            evicted,
            v4(7),
            "the path carrying traffic was evicted to admit a candidate"
        );
        assert_eq!(s.chosen(), Some(v4(7)));
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_confirm_a_path_forever() {
        // saturating_sub means a backwards step reads as zero elapsed rather
        // than as an enormous one, so staleness cannot be dodged by it.
        let mut s = PathSet::new();
        confirm(&mut s, 1, v4(7), 10_000, 10);
        assert!(s.paths()[0].is_usable(0));
        assert!(!s.paths()[0].is_usable(10_010 + PATH_STALE_MS + 1));
    }
}
