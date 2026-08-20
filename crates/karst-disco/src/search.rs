// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! §7.7's port search — reaching a symmetric NAT from a cone.
//!
//! When one peer is behind endpoint-dependent mapping and the other behind a
//! port-restricted cone, neither §7.2 nor §7.6 produces an address that works:
//! the hard side's mapping toward the reflector is a port the cone's filter
//! refuses, and its mapping toward the peer is a port nobody can predict. What
//! remains is to open many mappings on one side and try many ports on the
//! other, and let them collide.
//!
//! **Sans-io and sans-clock like the rest of the crate.** This decides how many
//! sockets should exist and which ports to try; it opens nothing and reads no
//! clock.
//!
//! # The budget is the design
//!
//! The published treatments of this technique reach about 64% in one round of
//! 256 sockets against 256 probes. They also spend eight times what
//! `aven-v1.md` §7.5 allows, in one burst, at a **single** address — and §7.5's
//! limit is what keeps "any node can point every one of its peers at a third
//! party" false. A node cannot check that a peer's advertised address belongs
//! to that peer; §1.1 allows the peer to be malicious and §7.2 already ranks
//! its claims last for exactly that reason.
//!
//! So this spends the *existing* allowance — [`ROUND_PROBES`] per
//! [`ROUND_INTERVAL_MS`], the same as sixteen candidates at four probes — on
//! one address instead of sixteen. The hard side's socket count grows each
//! round while the easy side's spend stays flat, so the per-round chance rises
//! without the traffic rising. It reaches about 91% in five and a half minutes
//! and 96% in seven.
//!
//! That is slower than a burst and correct for this protocol rather than that
//! one: §8.3 makes a relay path a *working* path, so this is an upgrade, and
//! latency-to-direct is a cost rather than a correctness property.

use core::net::SocketAddr;

use crate::msg::TxId;

/// Probes the easy side sends per round — §7.7.
///
/// Deliberately equal to `MAX_CANDIDATES` × the four probes of
/// `PROBE_BACKOFF_MS`: this is the budget §7.5 already grants for one
/// advertisement, spent on one address rather than sixteen. Raising it is a
/// change to the amplification argument, not a tuning decision.
pub const ROUND_PROBES: usize = 64;

/// How often a round runs — §7.7.
///
/// **Fifteen seconds, and the number is about NAT mapping lifetime rather than
/// about pacing.** A scratch mapping lives about as long as
/// `nf_conntrack_udp_timeout`, which is thirty seconds on Linux and commonly
/// less elsewhere. The live set is therefore one round's sockets multiplied by
/// how many rounds fit inside that lifetime — so a thirty-second round holds 64
/// mappings and a fifteen-second one holds 128, which is the difference between
/// 59% and 97% over seven minutes.
///
/// The first draft used thirty seconds and published a table for 256 sockets.
/// That count was never reachable: mappings from four rounds ago are three
/// timeouts dead. Finding 28.
pub const ROUND_INTERVAL_MS: u64 = 15_000;

/// How long a scratch mapping can be assumed to live, for the arithmetic above.
///
/// Not a tunable — it is what the environment does, and it is here so the
/// relationship between it and [`ROUND_INTERVAL_MS`] is visible in one place
/// rather than inferred from two comments.
pub const MAPPING_LIFETIME_MS: u64 = 30_000;

/// Sockets expected to be alive at once, given the two constants above.
///
/// This is the *N* in §7.7's arithmetic, and computing it rather than stating
/// it is the correction finding 28 asked for.
#[must_use]
pub const fn live_sockets() -> usize {
    let rounds = MAPPING_LIFETIME_MS / ROUND_INTERVAL_MS;
    let live = SCRATCH_PER_ROUND * rounds as usize;
    if live > SCRATCH_MAX {
        SCRATCH_MAX
    } else {
        live
    }
}

/// Scratch sockets the hard side adds per round.
pub const SCRATCH_PER_ROUND: usize = 64;

/// Most scratch sockets held for one peer at once — §7.7.
///
/// Sockets are a bounded process resource and this is what bounds them. A node
/// with many peers needs a global cap as well, which is the caller's to apply:
/// this type knows about one peer and cannot see the others.
pub const SCRATCH_MAX: usize = 256;

/// Lowest port the search will try.
///
/// Below 1024 is privileged on the platforms Karst targets, so a NAT will not
/// allocate there and a probe sent there is wasted budget.
pub const PORT_MIN: u16 = 1024;

/// One peer's search, if one is running.
///
/// Created when the ordinary backoff has failed — see
/// [`Search::should_start`] — and dropped when a path is confirmed.
#[derive(Debug, Clone)]
pub struct Search {
    /// The peer addresses being searched, rotated one per round.
    ///
    /// **Not one address.** A peer advertises its interface addresses as well
    /// as its reflexive ones (§7.2), and a node cannot tell from a candidate
    /// alone which of them a NAT will carry. Mappings earned toward an
    /// unroutable candidate are worthless — the peer's filter admits only the
    /// exact destination a mapping was made toward — so a search that picked
    /// wrong would spend every socket it has on nothing and look exactly like
    /// a technique that does not work.
    ///
    /// Rotating spends one round per candidate instead. With two or three
    /// candidates that is a small constant on a curve already measured in
    /// minutes, and it removes the need to guess.
    toward: Vec<SocketAddr>,
    /// Scratch sockets believed open.
    scratch: usize,
    /// The wall-clock round boundary the last round belonged to.
    ///
    /// **A boundary rather than an elapsed time, and that is the alignment.**
    /// Two nodes both need their rounds to happen at nearly the same moment:
    /// the hard side's mappings are only fresh for a NAT timeout, so a peer
    /// probing half a round later finds mappings that have half expired, and a
    /// peer probing a full round later finds none. Deriving the boundary from
    /// wall-clock time makes any two nodes agree without exchanging anything —
    /// no message, no negotiation, and no way for a peer to drive the rate.
    ///
    /// Clock skew of a second or two is irrelevant against a thirty-second
    /// mapping lifetime, and every Karst node already validates TLS
    /// certificates, which does not work with a badly wrong clock.
    last_boundary: Option<u64>,
    /// Rounds completed, for the caller's diagnostics.
    rounds: u32,
    /// Which port each in-flight probe went to.
    ///
    /// **Separate from `PathSet`'s outstanding table on purpose.** §7.1 caps
    /// that at `MAX_OUTSTANDING` — sixteen — because it is state an arbitrary
    /// peer's behaviour can make a node allocate. A round is sixty-four probes,
    /// so registering them there would either overflow the cap or force it up
    /// for every peer, and the cap is a security property rather than a size.
    ///
    /// This table is bounded by the round instead: it holds one round's worth,
    /// is replaced wholesale each round, and is only ever populated by probes
    /// this node chose to send. A `Pong` whose `tx` is here identifies which
    /// port answered, which is what §7.1 requires and what the address alone
    /// cannot say.
    in_flight: Vec<(TxId, SocketAddr)>,
    /// Ports already tried, so a round draws without replacement across the
    /// whole search rather than only within itself.
    ///
    /// §7.7 says "without replacement"; doing that only inside a round would
    /// re-try the same ports every thirty seconds and flatten the cumulative
    /// curve to the per-round one.
    tried: Vec<u16>,
}

/// What a round asks the caller to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// How many *more* scratch sockets to open toward each address, one
    /// datagram each. They are not expected to arrive; they exist to earn
    /// mappings.
    ///
    /// **Split across every candidate rather than rotating between them**, and
    /// the reason is freshness rather than fairness. Rotating puts all of a
    /// round's sockets on one address and returns to it two rounds later, so
    /// the mappings that matter are created half as often and are twice as old
    /// when the peer probes them. It also requires the two nodes to rotate *in
    /// step* — and they cannot, because each one's candidate list is about the
    /// other and neither list's order means anything to the peer. Splitting
    /// needs no agreement at all.
    pub scratch: Vec<(SocketAddr, usize)>,
    /// Probe the peer's host at these ports, from the socket §4 already
    /// shares with PHREATIC — **not** from a scratch socket, because the
    /// receiving filter is expecting that one source.
    pub probes: Vec<(SocketAddr, TxId)>,
}

impl Search {
    /// Whether a search should begin for a peer in this state.
    ///
    /// **Only after the ordinary backoff has failed.** §7.5's four probes are
    /// cheap and cover every topology this does not; starting a search before
    /// they have run would spend the budget on peers that were about to
    /// connect anyway.
    #[must_use]
    pub const fn should_start(exhausted: bool, have_direct_path: bool) -> bool {
        exhausted && !have_direct_path
    }

    /// Begin searching toward a peer's candidate addresses.
    #[must_use]
    pub fn new(toward: Vec<SocketAddr>) -> Self {
        Self {
            toward,
            scratch: 0,
            last_boundary: None,
            rounds: 0,
            in_flight: Vec::new(),
            tried: Vec::new(),
        }
    }

    /// Scratch sockets this search believes are open.
    #[must_use]
    pub const fn scratch(&self) -> usize {
        self.scratch
    }

    /// Rounds completed.
    #[must_use]
    pub const fn rounds(&self) -> u32 {
        self.rounds
    }

    /// The address a `Pong` confirms, if its `tx` answers a probe of this
    /// round — §7.1 applied to the search's own table.
    ///
    /// Returns `None` for a `tx` this search did not send, which is what makes
    /// a forged or replayed `Pong` unable to confirm anything.
    #[must_use]
    pub fn answered(&self, tx: &TxId) -> Option<SocketAddr> {
        self.in_flight
            .iter()
            .find(|(sent, _)| sent == tx)
            .map(|(_, addr)| *addr)
    }

    /// Replace the addresses being searched.
    ///
    /// **A search must not hold the candidate list it started with.** It begins
    /// as soon as §7.5's backoff gives up, and a reflexive address (§7.6) often
    /// arrives *after* that — it takes a `Reflect` round trip and then a
    /// `CallMeMaybe` to cross the relay. A search frozen at creation rotates
    /// for ever over whatever was known at its worst moment, which in the
    /// common hard/easy case is the peer's private address and nothing else.
    pub fn retarget(&mut self, toward: Vec<SocketAddr>) {
        if self.toward != toward {
            self.toward = toward;
        }
    }

    /// Run a round if one is due.
    ///
    /// `wall_ms` is **wall-clock** milliseconds, not a monotonic stamp. The
    /// round boundary is derived from it so that two nodes run their rounds at
    /// the same moment without coordinating; see [`Search::last_boundary`].
    ///
    /// `mint` supplies transaction ids, as [`crate::Engine::poll`] does; the
    /// probe ports are derived from them, so the search needs no randomness
    /// source of its own and a test can drive it with a counter. Each probe
    /// needs a `tx` regardless — §7.1 — so this costs nothing extra.
    pub fn poll(&mut self, wall_ms: u64, mint: &mut impl FnMut() -> TxId) -> Option<Round> {
        let boundary = wall_ms / ROUND_INTERVAL_MS;
        if self.last_boundary == Some(boundary) {
            return None;
        }
        self.last_boundary = Some(boundary);
        self.rounds = self.rounds.saturating_add(1);
        if self.toward.is_empty() {
            return None;
        }

        let budget = SCRATCH_MAX
            .saturating_sub(self.scratch)
            .min(SCRATCH_PER_ROUND);
        let hosts = self.toward.len();
        let each = budget / hosts;
        let scratch: Vec<(SocketAddr, usize)> = self
            .toward
            .iter()
            .map(|addr| (*addr, each))
            .filter(|(_, n)| *n > 0)
            .collect();
        self.scratch = self
            .scratch
            .saturating_add(scratch.iter().map(|(_, n)| *n).sum::<usize>());

        // Replaced rather than appended: a probe from a previous round has
        // had thirty seconds to be answered, which is six times §7.1's
        // five-second transaction timeout.
        self.in_flight.clear();
        let mut probes = Vec::with_capacity(ROUND_PROBES);
        // Bounded rather than looping until `ROUND_PROBES` distinct ports are
        // found: once most of the range has been tried, an unbounded loop
        // becomes a spin. Falling short of the round's quota is the correct
        // degradation — it means the search has nearly exhausted the space.
        let mut attempts = 0;
        while probes.len() < ROUND_PROBES && attempts < ROUND_PROBES * 4 {
            attempts += 1;
            let tx = mint();
            let Some(port) = port_from(&tx) else {
                continue;
            };
            if self.tried.contains(&port) {
                continue;
            }
            let Some(host) = self.toward.get(probes.len() % hosts).copied() else {
                break;
            };
            self.tried.push(port);
            self.in_flight.push((tx, SocketAddr::new(host.ip(), port)));
            probes.push((SocketAddr::new(host.ip(), port), tx));
        }

        Some(Round { scratch, probes })
    }
}

/// Derive a port in `PORT_MIN..=u16::MAX` from a transaction id.
///
/// The `tx` is already CSPRNG-drawn, so this needs no separate randomness. It
/// returns `None` only for a `tx` too short to read, which cannot happen for a
/// well-formed [`TxId`] and is handled rather than indexed past — this crate is
/// written to be panic-free throughout.
fn port_from(tx: &TxId) -> Option<u16> {
    let hi = *tx.0.first()?;
    let lo = *tx.0.get(1)?;
    let raw = u16::from_be_bytes([hi, lo]);
    let span = u16::MAX - PORT_MIN;
    Some(PORT_MIN + (raw % span))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::consts::TX_ID_LEN;

    fn peer() -> SocketAddr {
        "203.0.113.7:51820".parse().expect("addr")
    }

    fn one() -> Vec<SocketAddr> {
        vec![peer()]
    }

    /// A counter standing in for a CSPRNG, as `engine.rs`'s tests do.
    fn minter() -> impl FnMut() -> TxId {
        let mut n: u64 = 0;
        move || {
            n = n.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut id = [0u8; TX_ID_LEN];
            id[..8].copy_from_slice(&n.to_be_bytes());
            TxId(id)
        }
    }

    #[test]
    fn a_search_only_starts_once_the_cheap_probes_have_failed() {
        // §7.5's four probes cover every topology this does not, and they are
        // two orders of magnitude cheaper. Starting before they have run would
        // spend the budget on peers that were about to connect anyway.
        assert!(Search::should_start(true, false));
        assert!(!Search::should_start(false, false), "backoff still running");
        assert!(!Search::should_start(true, true), "already direct");
    }

    #[test]
    fn a_round_spends_exactly_the_budget_seven_five_already_granted() {
        // The number that must not drift. 64 is `MAX_CANDIDATES` × the four
        // probes of `PROBE_BACKOFF_MS` — the allowance §7.5 gives for one
        // advertisement, spent on one address instead of sixteen. Raising it
        // changes the amplification argument rather than a tuning constant.
        let mut m = minter();
        let mut s = Search::new(one());
        let round = s.poll(0, &mut m).expect("first round is due");
        assert_eq!(round.probes.len(), ROUND_PROBES);
        assert_eq!(ROUND_PROBES, 64);
    }

    #[test]
    fn scratch_sockets_grow_each_round_and_stop_at_the_cap() {
        let mut m = minter();
        let mut s = Search::new(one());
        let mut now = 0;
        let mut seen = Vec::new();
        for _ in 0..6 {
            let r = s.poll(now, &mut m).expect("due");
            let opened: usize = r.scratch.iter().map(|(_, n)| *n).sum();
            seen.push((opened, s.scratch()));
            now += ROUND_INTERVAL_MS;
        }
        assert_eq!(
            seen,
            vec![
                (64, 64),
                (64, 128),
                (64, 192),
                (64, 256),
                (0, 256),
                (0, 256)
            ],
            "growth should be 64 a round to the cap, then flat"
        );
        assert_eq!(s.scratch(), SCRATCH_MAX);
    }

    #[test]
    fn a_round_is_not_due_before_the_interval() {
        let mut m = minter();
        let mut s = Search::new(one());
        assert!(s.poll(0, &mut m).is_some());
        assert!(s.poll(ROUND_INTERVAL_MS - 1, &mut m).is_none());
        assert!(s.poll(ROUND_INTERVAL_MS, &mut m).is_some());
        assert_eq!(s.rounds(), 2);
    }

    #[test]
    fn ports_are_drawn_without_replacement_across_the_whole_search() {
        // §7.7 says without replacement. Doing that only *within* a round
        // would re-try the same ports every thirty seconds and flatten the
        // cumulative curve to the per-round one — the growth in the table is
        // the whole reason the slow version reaches 91%.
        // **A deliberately small source of ids.** With a full-width counter
        // the draws never collide by chance, so this test passed whether the
        // memory worked or not — which a mutation caught. Cycling over 40
        // distinct values makes duplicates certain across 8 rounds of 64, so
        // the assertion now measures the dedup rather than the minter.
        let mut n: u8 = 0;
        let mut m = || {
            n = (n + 1) % 40;
            let mut id = [0u8; TX_ID_LEN];
            id[0] = n;
            id[1] = n.wrapping_mul(7);
            TxId(id)
        };
        let mut s = Search::new(one());
        let mut all = Vec::new();
        let mut now = 0;
        for _ in 0..8 {
            let r = s.poll(now, &mut m).expect("due");
            all.extend(r.probes.iter().map(|(a, _)| a.port()));
            now += ROUND_INTERVAL_MS;
        }
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "a port was tried twice");
    }

    #[test]
    fn every_probe_targets_the_peers_host_and_never_a_privileged_port() {
        let mut m = minter();
        let mut s = Search::new(one());
        let r = s.poll(0, &mut m).expect("due");
        for (addr, _) in &r.probes {
            assert_eq!(addr.ip(), peer().ip(), "probed a different host");
            assert!(addr.port() >= PORT_MIN, "privileged port {addr}");
        }
        // And the scratch datagrams go to the addresses the peer advertised,
        // port included — those are where the easy side is reachable, and the
        // mappings must be earned toward them.
        assert!(
            r.scratch.iter().all(|(addr, _)| *addr == peer()),
            "scratch must go to the addresses the peer named"
        );
    }

    #[test]
    fn a_round_terminates_even_when_ports_keep_colliding() {
        // A minter that returns one value forever. Without the attempt bound
        // the round would spin: every port is already in `tried` after the
        // first. Falling short of the quota is the right degradation.
        let mut m = || TxId([7u8; TX_ID_LEN]);
        let mut s = Search::new(one());
        let first = s.poll(0, &mut m).expect("due");
        assert_eq!(first.probes.len(), 1, "one distinct port available");
        let second = s.poll(ROUND_INTERVAL_MS, &mut m).expect("due");
        assert!(second.probes.is_empty(), "that port was already tried");
    }

    #[test]
    fn two_nodes_run_their_rounds_in_the_same_boundary_without_coordinating() {
        // **The alignment, which is the whole point of a wall-clock boundary.**
        // The hard side's mappings live about a NAT timeout, so a peer probing
        // half a round later finds them half expired and a peer probing a full
        // round later finds none. Independent thirty-second timers give no
        // guarantee at all; a shared boundary gives one for free.
        let mut a = Search::new(one());
        let mut b = Search::new(one());
        let mut m1 = minter();
        let mut m2 = minter();

        // Two nodes whose clocks differ by a second and which poll at different
        // moments inside the same boundary.
        let base = 1_700_000_000_000u64;
        let start = base - base % ROUND_INTERVAL_MS;
        assert!(a.poll(start + 200, &mut m1).is_some(), "A runs");
        assert!(b.poll(start + 1_400, &mut m2).is_some(), "B runs");
        // Neither runs again inside the same boundary, however often polled.
        for at in [start + 2_000, start + 9_000, start + ROUND_INTERVAL_MS - 1] {
            assert!(a.poll(at, &mut m1).is_none(), "A ran twice in one boundary");
            assert!(b.poll(at, &mut m2).is_none(), "B ran twice in one boundary");
        }
        // And both run again in the next one.
        assert!(a.poll(start + ROUND_INTERVAL_MS, &mut m1).is_some());
        assert!(b.poll(start + ROUND_INTERVAL_MS + 900, &mut m2).is_some());
    }

    #[test]
    fn the_live_socket_count_is_derived_rather_than_asserted() {
        // Finding 28: the first draft published a table for 256 sockets at a
        // thirty-second round, and mappings from four rounds ago are three
        // timeouts dead. The count now follows from the two constants that
        // decide it, so it cannot drift from them again.
        assert_eq!(live_sockets(), 128);
        assert_eq!(ROUND_INTERVAL_MS, 15_000);
        assert_eq!(MAPPING_LIFETIME_MS, 30_000);
        assert!(
            live_sockets() <= SCRATCH_MAX,
            "the live set must fit the per-peer cap"
        );
    }

    #[test]
    fn a_pong_confirms_the_port_its_probe_went_to_and_nothing_else() {
        // §7.1 applied to the search's own table. The source address of a
        // `Pong` cannot say which of sixty-four ports answered — only the `tx`
        // can — and a `tx` this search never sent must confirm nothing, or a
        // replayed `Pong` would install a path that was never probed.
        let mut m = minter();
        let mut s = Search::new(one());
        let round = s.poll(0, &mut m).expect("due");
        let (addr, tx) = round.probes.first().copied().expect("a probe");
        assert_eq!(s.answered(&tx), Some(addr));
        assert_eq!(s.answered(&TxId([0xEE; TX_ID_LEN])), None, "never sent");
    }

    #[test]
    fn last_rounds_probes_stop_confirming_once_a_new_round_runs() {
        // The table is one round deep. A probe from the previous round has had
        // thirty seconds, six times §7.1's five-second transaction timeout, so
        // keeping it would grow the table without bound for no benefit.
        let mut m = minter();
        let mut s = Search::new(one());
        let first = s.poll(0, &mut m).expect("due");
        let (_, stale) = first.probes.first().copied().expect("a probe");
        assert!(s.answered(&stale).is_some());
        let _ = s.poll(ROUND_INTERVAL_MS, &mut m).expect("due");
        assert_eq!(s.answered(&stale), None, "a stale tx still confirmed");
    }

    #[test]
    fn derived_ports_span_the_range_rather_than_clustering() {
        // The arithmetic in §7.7 assumes probes are spread over the ephemeral
        // range. A derivation that clustered would make the measured 91% a
        // fiction while every test above still passed.
        let mut m = minter();
        let mut s = Search::new(one());
        let mut lo = 0;
        let mut hi = 0;
        let mut now = 0;
        for _ in 0..4 {
            for (addr, _) in s.poll(now, &mut m).expect("due").probes {
                if addr.port() < 32768 {
                    lo += 1;
                } else {
                    hi += 1;
                }
            }
            now += ROUND_INTERVAL_MS;
        }
        assert!(
            lo > 50 && hi > 50,
            "ports clustered: {lo} below 32768, {hi} above"
        );
    }
}
