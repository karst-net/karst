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

use core::net::{IpAddr, SocketAddr};

use crate::msg::TxId;

/// Probes the easy side sends per round — §7.7.
///
/// Deliberately equal to `MAX_CANDIDATES` × the four probes of
/// `PROBE_BACKOFF_MS`: this is the budget §7.5 already grants for one
/// advertisement, spent on one address rather than sixteen. Raising it is a
/// change to the amplification argument, not a tuning decision.
pub const ROUND_PROBES: usize = 64;

/// How often a round runs — §7.7, reusing §7.5's re-advertisement cadence.
pub const ROUND_INTERVAL_MS: u64 = 30_000;

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
    /// The peer address whose *host* is being searched. Its port is what the
    /// hard side aims its scratch sockets at; the search varies the port only
    /// on the probing side.
    toward: SocketAddr,
    /// Scratch sockets believed open.
    scratch: usize,
    /// When the last round ran.
    last_round_ms: Option<u64>,
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
    in_flight: Vec<(TxId, u16)>,
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
    /// Open this many *more* scratch sockets, each sending one datagram to
    /// [`Round::toward`]. They are not expected to arrive; they exist to earn
    /// mappings.
    pub open_scratch: usize,
    /// Where those scratch datagrams go.
    pub toward: SocketAddr,
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

    /// Begin searching toward a peer address.
    #[must_use]
    pub fn new(toward: SocketAddr) -> Self {
        Self {
            toward,
            scratch: 0,
            last_round_ms: None,
            rounds: 0,
            in_flight: Vec::new(),
            tried: Vec::new(),
        }
    }

    /// The peer host being searched.
    #[must_use]
    pub const fn host(&self) -> IpAddr {
        self.toward.ip()
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
            .map(|(_, port)| SocketAddr::new(self.toward.ip(), *port))
    }

    /// Run a round if one is due.
    ///
    /// `mint` supplies transaction ids, as [`crate::Engine::poll`] does; the
    /// probe ports are derived from them, so the search needs no randomness
    /// source of its own and a test can drive it with a counter. Each probe
    /// needs a `tx` regardless — §7.1 — so this costs nothing extra.
    pub fn poll(&mut self, now_ms: u64, mint: &mut impl FnMut() -> TxId) -> Option<Round> {
        if let Some(last) = self.last_round_ms {
            if now_ms.saturating_sub(last) < ROUND_INTERVAL_MS {
                return None;
            }
        }
        self.last_round_ms = Some(now_ms);
        self.rounds = self.rounds.saturating_add(1);

        let open_scratch = SCRATCH_MAX
            .saturating_sub(self.scratch)
            .min(SCRATCH_PER_ROUND);
        self.scratch = self.scratch.saturating_add(open_scratch);

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
            self.tried.push(port);
            self.in_flight.push((tx, port));
            probes.push((SocketAddr::new(self.toward.ip(), port), tx));
        }

        Some(Round {
            open_scratch,
            toward: self.toward,
            probes,
        })
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
        let mut s = Search::new(peer());
        let round = s.poll(0, &mut m).expect("first round is due");
        assert_eq!(round.probes.len(), ROUND_PROBES);
        assert_eq!(ROUND_PROBES, 64);
    }

    #[test]
    fn scratch_sockets_grow_each_round_and_stop_at_the_cap() {
        let mut m = minter();
        let mut s = Search::new(peer());
        let mut now = 0;
        let mut seen = Vec::new();
        for _ in 0..6 {
            let r = s.poll(now, &mut m).expect("due");
            seen.push((r.open_scratch, s.scratch()));
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
        let mut s = Search::new(peer());
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
        let mut s = Search::new(peer());
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
        let mut s = Search::new(peer());
        let r = s.poll(0, &mut m).expect("due");
        for (addr, _) in &r.probes {
            assert_eq!(addr.ip(), peer().ip(), "probed a different host");
            assert!(addr.port() >= PORT_MIN, "privileged port {addr}");
        }
        // And the scratch datagrams go to the address the peer advertised,
        // port included — that is the one address the easy side is reachable
        // at, and the mappings must be earned toward it.
        assert_eq!(r.toward, peer());
    }

    #[test]
    fn a_round_terminates_even_when_ports_keep_colliding() {
        // A minter that returns one value forever. Without the attempt bound
        // the round would spin: every port is already in `tried` after the
        // first. Falling short of the quota is the right degradation.
        let mut m = || TxId([7u8; TX_ID_LEN]);
        let mut s = Search::new(peer());
        let first = s.poll(0, &mut m).expect("due");
        assert_eq!(first.probes.len(), 1, "one distinct port available");
        let second = s.poll(ROUND_INTERVAL_MS, &mut m).expect("due");
        assert!(second.probes.is_empty(), "that port was already tried");
    }

    #[test]
    fn a_pong_confirms_the_port_its_probe_went_to_and_nothing_else() {
        // §7.1 applied to the search's own table. The source address of a
        // `Pong` cannot say which of sixty-four ports answered — only the `tx`
        // can — and a `tx` this search never sent must confirm nothing, or a
        // replayed `Pong` would install a path that was never probed.
        let mut m = minter();
        let mut s = Search::new(peer());
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
        let mut s = Search::new(peer());
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
        let mut s = Search::new(peer());
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
