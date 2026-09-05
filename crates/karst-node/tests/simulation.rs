// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Deterministic simulation of two peers over a lossy, reordering network.
//!
//! PLAN.md §11 asks for this in Phase 2, "before it's desperately needed". The
//! point is that a failing seed **replays exactly**: virtual clock, virtual
//! network, seeded PRNG, no threads, no sockets, no sleeping. A loss-related
//! handshake bug found here is reproducible in one command rather than being a
//! flaky CI failure nobody can pin down.
//!
//! This is what the sans-io discipline (ADR-0003) buys.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use karst_node::{Action, CloseReason, Session};
use karst_noise::handshake::{PeerPublic, ResponderRandomness, StaticKeys};
use karst_proto::reassembly::{Accept, Config as ReasmConfig, Reassembler};
use karst_proto::{consts, split_datagram};

// ── deterministic PRNG ──────────────────────────────────────────────────────

/// xorshift64*. Deterministic, seeded, and entirely adequate for choosing which
/// packets to drop — this is a scheduler, not a source of key material.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// True with probability `percent`/100.
    fn chance(&mut self, percent: u32) -> bool {
        percent > 0 && (self.next_u64() % 100) < u64::from(percent)
    }
}

// ── virtual network ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
struct Link {
    loss_percent: u32,
    /// Chance a datagram is delayed behind the next one.
    reorder_percent: u32,
    /// Chance a datagram is delivered twice.
    duplicate_percent: u32,
    latency_ms: u64,
}

#[derive(Debug)]
struct InFlight {
    deliver_at_ms: u64,
    to_responder: bool,
    bytes: Vec<u8>,
}

struct Network {
    link: Link,
    rng: Rng,
    queue: Vec<InFlight>,
    dropped: usize,
    delivered: usize,
}

impl Network {
    fn new(link: Link, seed: u64) -> Self {
        Self {
            link,
            rng: Rng::new(seed),
            queue: Vec::new(),
            dropped: 0,
            delivered: 0,
        }
    }

    fn send(&mut self, to_responder: bool, bytes: Vec<u8>, now_ms: u64) {
        // A real link cannot carry more than this. The harness must enforce it,
        // or it silently validates behavior that could never work on the wire.
        //
        // §13.6 makes the budget two-tier: an unfragmented transport datagram
        // may reach TRANSPORT_DATAGRAM_MAX, but anything with count > 1 is held
        // to the IPv6 minimum. Reading the count off the wire — rather than
        // trusting the sender — is what makes this assertion worth having.
        let budget = match karst_proto::FragmentHeader::decode(&bytes) {
            Ok(h) if h.count == 1 => consts::TRANSPORT_DATAGRAM_MAX,
            _ => consts::HANDSHAKE_DATAGRAM_MAX,
        };
        assert!(
            bytes.len() <= budget,
            "datagram of {} B exceeds the {budget} B link MTU — must be fragmented (spec §5)",
            bytes.len(),
        );
        if self.rng.chance(self.link.loss_percent) {
            self.dropped += 1;
            return;
        }
        let mut delay = self.link.latency_ms;
        if self.rng.chance(self.link.reorder_percent) {
            delay = delay.saturating_add(self.link.latency_ms.max(1) * 3);
        }
        self.queue.push(InFlight {
            deliver_at_ms: now_ms.saturating_add(delay),
            to_responder,
            bytes: bytes.clone(),
        });
        if self.rng.chance(self.link.duplicate_percent) {
            self.queue.push(InFlight {
                deliver_at_ms: now_ms.saturating_add(delay).saturating_add(1),
                to_responder,
                bytes,
            });
        }
    }

    /// Everything due at or before `now_ms`, in delivery order.
    fn deliver_due(&mut self, now_ms: u64) -> Vec<InFlight> {
        let (due, pending): (Vec<_>, Vec<_>) = core::mem::take(&mut self.queue)
            .into_iter()
            .partition(|p| p.deliver_at_ms <= now_ms);
        self.queue = pending;
        self.delivered += due.len();
        due
    }
}

// ── fixtures ────────────────────────────────────────────────────────────────

const PSK: [u8; 32] = [0x42; 32];
const SRC_INIT: karst_proto::reassembly::SourceKey = [0x11; 18];
const SRC_RESP: karst_proto::reassembly::SourceKey = [0x22; 18];

fn keys(a: u8, _b: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[a; 64]))
}
fn peer_of(k: &StaticKeys) -> PeerPublic {
    PeerPublic {
        kem_pk: k.kem_pk.clone(),

        psk: PSK,
    }
}
fn rrand() -> ResponderRandomness {
    ResponderRandomness {
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}

struct Outcome {
    established_at_ms: Option<u64>,
    closed: Option<CloseReason>,
    delivered_payloads: Vec<Vec<u8>>,
    dropped: usize,
}

/// Run one simulated connection to completion or to `horizon_ms`.
fn simulate(link: Link, seed: u64, horizon_ms: u64, step_ms: u64) -> Outcome {
    let a = keys(0xA1, 0xA2);
    let b = keys(0xB1, 0xB2);
    let b_pub = peer_of(&b);
    let a_pub = peer_of(&a);

    let mut initiator = Session::new(Arc::clone(&a), Arc::new(b_pub), 7, 1);
    // Both ends are real `Session`s. An earlier version of this harness drove
    // the responder by hand, which is precisely how the fragment-MAC keying
    // defect of §13.7 stayed hidden: the hand-rolled side used a key no real
    // responder would have used, and agreed with itself.
    //
    // Reassembly sits above the session, as it must: an inbound HandshakeInit
    // cannot be attributed to a peer until it is reassembled and decrypted.
    let mut responder = Session::new(Arc::clone(&b), Arc::new(a_pub), 7, 2);
    let mut r_reasm = Reassembler::new(ReasmConfig::default());

    let mut net = Network::new(link, seed);
    let mut out = Outcome {
        established_at_ms: None,
        closed: None,
        delivered_payloads: Vec::new(),
        dropped: 0,
    };

    let mut now = 0u64;
    for action in initiator.connect(now, [0x5A; 32]) {
        if let Action::Send(d) = action {
            net.send(true, d, now);
        }
    }

    while now < horizon_ms {
        now = now.saturating_add(step_ms);

        for pkt in net.deliver_due(now) {
            if pkt.to_responder {
                let Ok((hdr, payload)) = split_datagram(&pkt.bytes) else {
                    continue;
                };
                let Accept::Complete(msg) = r_reasm.push(SRC_INIT, true, &hdr, payload, now) else {
                    continue;
                };
                let msg = msg.to_vec();
                // A retransmitted HandshakeInit is answered again, which is
                // correct: the responder holds no state until a transport
                // message authenticates (§12.6).
                let actions = if msg.first() == Some(&0x01) {
                    responder.respond_to(&msg, &rrand(), now)
                } else {
                    responder.deliver(&msg, now)
                };
                for action in actions {
                    match action {
                        Action::Send(d) => net.send(false, d, now),
                        Action::Deliver(p) => out.delivered_payloads.push(p),
                        Action::Established | Action::Closed(_) => {}
                    }
                }
            } else {
                for action in initiator.handle(&pkt.bytes, SRC_RESP, now) {
                    match action {
                        Action::Established => {
                            if out.established_at_ms.is_none() {
                                out.established_at_ms = Some(now);
                            }
                            for d in initiator.send(b"hello over a lossy link", now).unwrap() {
                                net.send(true, d, now);
                            }
                        }
                        Action::Send(d) => net.send(true, d, now),
                        Action::Closed(r) => out.closed = Some(r),
                        Action::Deliver(_) => {}
                    }
                }
            }
        }

        for action in initiator.poll(now, [0x5A; 32]) {
            match action {
                Action::Send(d) => net.send(true, d, now),
                Action::Closed(r) => {
                    out.closed = Some(r);
                    out.dropped = net.dropped;
                    return out;
                }
                _ => {}
            }
        }

        if out.established_at_ms.is_some() && !out.delivered_payloads.is_empty() {
            break;
        }
    }
    out.dropped = net.dropped;
    out
}

// ── tests ───────────────────────────────────────────────────────────────────

#[test]
fn a_clean_link_connects_on_the_first_attempt() {
    let link = Link {
        latency_ms: 10,
        ..Link::default()
    };
    let o = simulate(link, 1, 10_000, 5);
    assert!(o.established_at_ms.is_some(), "must establish");
    assert_eq!(o.dropped, 0);
    assert_eq!(o.delivered_payloads.len(), 1, "payload must arrive");
    assert!(
        o.established_at_ms.unwrap() < 100,
        "1-RTT: established at {:?} ms",
        o.established_at_ms
    );
}

/// Bounded retries under severe per-datagram loss. Requiring three fragments
/// in each direction lowers success within the fixed retry window: the same
/// deterministic seed set completed 25/25 with the retired two-fragment suite
/// and completes 20/25 with CNSA 2.0. This records the availability cost without
/// extending the protocol's retry deadline or assuming loss guarantees delivery.
#[test]
fn the_handshake_survives_heavy_loss() {
    let link = Link {
        loss_percent: 40,
        latency_ms: 20,
        ..Link::default()
    };
    let mut established = 0;
    for seed in 1..=25u64 {
        if simulate(link, seed, 120_000, 5).established_at_ms.is_some() {
            established += 1;
        }
    }
    assert_eq!(
        established, 20,
        "three-fragment success count changed under the deterministic 40% loss schedule"
    );
}

#[test]
fn reordering_and_duplication_are_tolerated() {
    let link = Link {
        loss_percent: 10,
        reorder_percent: 30,
        duplicate_percent: 20,
        latency_ms: 15,
    };
    for seed in 1..=15u64 {
        let o = simulate(link, seed, 30_000, 5);
        assert!(
            o.established_at_ms.is_some(),
            "seed {seed} failed to establish"
        );
        // Duplicates must not surface as duplicate payloads — the replay
        // window is doing its job.
        assert!(
            o.delivered_payloads.len() <= 1,
            "seed {seed}: replay window let a duplicate through"
        );
    }
}

/// A totally black link must fail cleanly and report why, rather than hanging
/// or spinning forever.
#[test]
fn a_dead_link_gives_up_and_reports_a_timeout() {
    let link = Link {
        loss_percent: 100,
        latency_ms: 10,
        ..Link::default()
    };
    // Horizon must exceed HANDSHAKE_GIVE_UP_MS (90 s) or we would be asserting
    // that the simulation ran out of time, not that the session gave up.
    let o = simulate(link, 7, 120_000, 50);
    assert_eq!(o.closed, Some(CloseReason::HandshakeTimeout));
    assert!(o.established_at_ms.is_none());
}

/// Determinism is the whole point: the same seed must produce the same run.
#[test]
fn runs_are_reproducible_from_the_seed() {
    let link = Link {
        loss_percent: 35,
        reorder_percent: 20,
        latency_ms: 12,
        duplicate_percent: 10,
    };
    for seed in [3u64, 11, 29] {
        let a = simulate(link, seed, 30_000, 5);
        let b = simulate(link, seed, 30_000, 5);
        assert_eq!(a.established_at_ms, b.established_at_ms, "seed {seed}");
        assert_eq!(a.dropped, b.dropped, "seed {seed}");
        assert_eq!(a.delivered_payloads, b.delivered_payloads, "seed {seed}");
    }
}

/// Different seeds must actually explore different schedules, or the suite is
/// only ever testing one path.
#[test]
fn different_seeds_produce_different_schedules() {
    let link = Link {
        loss_percent: 40,
        latency_ms: 10,
        ..Link::default()
    };
    let times: Vec<_> = (1..=10u64)
        .map(|s| simulate(link, s, 30_000, 5).dropped)
        .collect();
    let distinct: std::collections::HashSet<_> = times.iter().collect();
    assert!(
        distinct.len() > 1,
        "seeds produced identical drop counts — the PRNG is not steering anything"
    );
}
