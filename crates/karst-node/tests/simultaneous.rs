// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! **Both ends dial at once.**
//!
//! `tests/rekey.rs` is deliberately asymmetric — A initiates, B answers — and
//! so is every other test of the handshake. But a pair that knows both
//! endpoints performs a *simultaneous open* every time: `connect_all` runs on
//! both nodes at startup, so each one is initiator and responder at the same
//! moment, and the order the four messages land in is a race on the wire.
//!
//! That case had no test at all, and it was broken. Adopting a responder
//! session overwrote the state holding this node's own handshake, so the peer's
//! `HandshakeResponse` arrived with nothing left to complete; the two ends then
//! settled on key sets that could not read each other, **both reporting
//! `established` while nothing decrypted**. It is the stall
//! `State::Established::initiated` documents — 9 stalls in 7.8 hours, 253–765 s
//! each — in the one place that rule does not reach, because `initiated` stops
//! two *rekeys* racing and says nothing about the first handshake.
//!
//! The rekey race then reappears through the same door: after a simultaneous
//! open both ends are initiators, so both rekey, and completing one handshake
//! must not discard the keys owed to the other.
//!
//! Every valid interleaving is enumerated rather than sampled. There are only
//! six, the ordering is exactly what a real network chooses at random, and a
//! test that picked one would have passed against the defect five times in six.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karst_crypto::{SuiteId, SuitePolicy};
use karst_node::{Action, Session};
use karst_noise::handshake::{PeerPublic, ResponderRandomness, StaticKeys};
use karst_noise::transport::REKEY_AFTER_MS;
use karst_proto::reassembly::{Accept, Config as ReasmConfig, Reassembler, SourceKey};
use karst_proto::split_datagram;

const PSK: [u8; 32] = [0x42; 32];
const SRC_A: SourceKey = [0x11; 18];
const SRC_B: SourceKey = [0x22; 18];

fn keys(a: u8, b: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[a; 64], &[b; 32]))
}

fn peer_of(k: &StaticKeys) -> Arc<PeerPublic> {
    Arc::new(PeerPublic {
        kem_pk: MlKem::public_key_from_bytes(&MlKem::public_key_bytes(&k.kem_pk)).unwrap(),
        dh_pk: k.dh_pk,
        psk: PSK,
    })
}

fn policy() -> SuitePolicy {
    SuitePolicy {
        minimum: SuiteId::KARST_1,
        supported: vec![SuiteId::KARST_1],
    }
}

fn rrand(n: u8) -> ResponderRandomness {
    ResponderRandomness {
        e_dh_seed: [n; 32],
        encap_rand_e: [n ^ 0x0F; 32],
        encap_rand_s: [n ^ 0xF0; 32],
    }
}

/// Which node an action is happening to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    A,
    B,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Two sessions wired to each other, **symmetrically**: either may initiate and
/// either may answer, which is the whole difference from `rekey.rs`'s `Pair`.
struct Both {
    a: Session,
    b: Session,
    a_reasm: Reassembler,
    b_reasm: Reassembler,
    /// Distinct responder randomness per handshake. Reusing encapsulation
    /// randomness across handshakes is a key-recovery risk, not untidiness.
    round: u8,
}

impl Both {
    fn new() -> Self {
        let ak = keys(0xA1, 0xA2);
        let bk = keys(0xB1, 0xB2);
        let (ap, bp) = (peer_of(&ak), peer_of(&bk));
        Self {
            a: Session::new(ak, bp, policy(), SuiteId::KARST_1, 7, 1),
            b: Session::new(bk, ap, policy(), SuiteId::KARST_1, 7, 2),
            a_reasm: Reassembler::new(ReasmConfig::default()),
            b_reasm: Reassembler::new(ReasmConfig::default()),
            round: 0,
        }
    }

    fn sends(actions: Vec<Action>) -> Vec<Vec<u8>> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Send(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    /// Hand `datagrams` to `side`, returning what it emits and what it decrypts.
    ///
    /// A `HandshakeInit` is answered here rather than by the caller, because
    /// that is what a daemon does: `respond_to` resolves the peer and derives
    /// the responder keys in one step.
    fn feed(
        &mut self,
        side: Side,
        datagrams: Vec<Vec<u8>>,
        now: u64,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut out = Vec::new();
        let mut delivered = Vec::new();
        for d in datagrams {
            let Ok((hdr, payload)) = split_datagram(&d) else {
                continue;
            };
            let (reasm, from) = match side {
                Side::A => (&mut self.a_reasm, SRC_B),
                Side::B => (&mut self.b_reasm, SRC_A),
            };
            let Accept::Complete(msg) = reasm.push(from, true, &hdr, payload, now) else {
                continue;
            };
            let msg = msg.to_vec();
            let is_init = msg.first() == Some(&0x01);
            if is_init {
                self.round = self.round.wrapping_add(1);
            }
            let round = self.round;
            let session = match side {
                Side::A => &mut self.a,
                Side::B => &mut self.b,
            };
            let actions = if is_init {
                session.respond_to(&msg, &rrand(round), now)
            } else {
                session.deliver(&msg, now)
            };
            for a in actions {
                match a {
                    Action::Send(d) => out.push(d),
                    Action::Deliver(p) => delivered.push(p),
                    _ => {}
                }
            }
        }
        (out, delivered)
    }

    fn session(&mut self, side: Side) -> &mut Session {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }

    /// Send a payload one way and require it to arrive.
    ///
    /// **This is the assertion the defect defeats.** Both sessions report
    /// `established` either way; the only thing that tells the two states apart
    /// is whether a byte survives the trip.
    fn assert_traffic(&mut self, from: Side, now: u64, what: &str) {
        let frags = self
            .session(from)
            .send(what.as_bytes(), now)
            .unwrap_or_else(|e| panic!("{from:?} could not send at {now} ms: {e:?}"));
        let (_, delivered) = self.feed(from.other(), frags, now);
        assert_eq!(
            delivered.len(),
            1,
            "{from:?} → {:?} carried nothing at {now} ms ({what}); \
             both ends report established and neither can decrypt",
            from.other()
        );
        assert_eq!(delivered[0].get(..what.len()), Some(what.as_bytes()));
    }

    fn assert_traffic_both_ways(&mut self, now: u64, what: &str) {
        self.assert_traffic(Side::A, now, &format!("{what}: A to B"));
        self.assert_traffic(Side::B, now + 1, &format!("{what}: B to A"));
    }
}

/// One of the four messages a simultaneous open puts on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    /// A's `HandshakeInit` reaches B, which answers.
    AInit,
    /// B's `HandshakeInit` reaches A, which answers.
    BInit,
    /// The answer to A's init reaches A.
    AResp,
    /// The answer to B's init reaches B.
    BResp,
}

/// Every order the four messages can land in.
///
/// Causality is the only constraint: a response cannot arrive before the init
/// that produced it was delivered. That leaves the six interleavings of two
/// independent two-step exchanges.
fn interleavings() -> Vec<[Step; 4]> {
    use Step::{AInit, AResp, BInit, BResp};
    vec![
        [AInit, AResp, BInit, BResp],
        [AInit, BInit, AResp, BResp],
        [AInit, BInit, BResp, AResp],
        [BInit, AInit, AResp, BResp],
        [BInit, AInit, BResp, AResp],
        [BInit, BResp, AInit, AResp],
    ]
}

/// Run a simultaneous open in the given order and return the wired-up pair.
fn open_in_order(order: [Step; 4], now: u64) -> Both {
    let mut both = Both::new();
    // Both nodes dial. Neither has heard from the other yet — this is what
    // `connect_all` does at startup on every node that knows an endpoint.
    let mut a_init = Both::sends(both.a.connect(now, [0x5A; 32]));
    let mut b_init = Both::sends(both.b.connect(now, [0xA5; 32]));
    assert!(!a_init.is_empty() && !b_init.is_empty(), "both must dial");
    let mut a_resp: Vec<Vec<u8>> = Vec::new();
    let mut b_resp: Vec<Vec<u8>> = Vec::new();

    for step in order {
        match step {
            Step::AInit => {
                let (out, _) = both.feed(Side::B, std::mem::take(&mut a_init), now);
                a_resp = out;
            }
            Step::BInit => {
                let (out, _) = both.feed(Side::A, std::mem::take(&mut b_init), now);
                b_resp = out;
            }
            Step::AResp => {
                assert!(!a_resp.is_empty(), "{order:?}: A's init was never answered");
                both.feed(Side::A, std::mem::take(&mut a_resp), now);
            }
            Step::BResp => {
                assert!(!b_resp.is_empty(), "{order:?}: B's init was never answered");
                both.feed(Side::B, std::mem::take(&mut b_resp), now);
            }
        }
    }
    assert!(both.a.established(), "{order:?}: A never established");
    assert!(both.b.established(), "{order:?}: B never established");
    both
}

/// **The defect.** Two nodes that dial each other at the same moment must end
/// up able to talk, whichever order the four messages arrive in.
#[test]
fn a_simultaneous_open_carries_traffic_in_every_order() {
    for order in interleavings() {
        let mut both = open_in_order(order, 1_000);
        both.assert_traffic_both_ways(2_000, &format!("{order:?}"));
    }
}

/// The same pair, still working a long way past the open.
///
/// Separate from the test above because "it decrypted once" and "it is a
/// working tunnel" are different claims: keys held only in the slot a rekey
/// vacates would satisfy the first and fail the second.
#[test]
fn a_simultaneously_opened_pair_keeps_working() {
    for order in interleavings() {
        let mut both = open_in_order(order, 1_000);
        for step in 1..=8 {
            let now = 2_000 + step * 5_000;
            both.assert_traffic_both_ways(now, &format!("{order:?} at {now} ms"));
        }
    }
}

/// **Both ends rekey at once**, which is not an unlucky case but the expected
/// one after a simultaneous open: both sessions were created in the same
/// millisecond, so both reach `REKEY_AFTER_TIME` in the same millisecond, and
/// after a simultaneous open both ends are initiators.
///
/// Completing one's own handshake must not discard the keys owed to the other.
#[test]
fn a_simultaneous_rekey_carries_traffic() {
    let mut both = open_in_order(interleavings()[1], 0);
    both.assert_traffic_both_ways(1_000, "before the rekey");

    // Both poll past the rekey point, and both dial.
    let at = REKEY_AFTER_MS + 10;
    let a_init = Both::sends(both.a.poll(at, [0x11; 32]));
    let b_init = Both::sends(both.b.poll(at, [0x22; 32]));
    assert!(
        !a_init.is_empty() && !b_init.is_empty(),
        "after a simultaneous open both ends are initiators, so both rekey"
    );

    // Each answers the other's init before either answer comes back — the
    // window in which a completing handshake could throw away the keys the
    // peer is about to seal with.
    let (a_resp, _) = both.feed(Side::B, a_init, at);
    let (b_resp, _) = both.feed(Side::A, b_init, at);
    both.feed(Side::A, a_resp, at + 10);
    both.feed(Side::B, b_resp, at + 10);

    both.assert_traffic_both_ways(at + 100, "after the simultaneous rekey");
    both.assert_traffic_both_ways(at + 30_000, "well after the simultaneous rekey");
}

/// The asymmetric case must be untouched: when only one end dials, the other
/// must not acquire a handshake of its own out of nowhere.
///
/// This is the control. Without it, "carry the outstanding handshake across"
/// could be implemented as "always keep a handshake in flight", which would
/// make both ends rekey forever and quietly undo what `initiated` is for.
#[test]
fn a_one_sided_dial_leaves_the_responder_passive() {
    let mut both = Both::new();
    let init = Both::sends(both.a.connect(0, [0x5A; 32]));
    let (resp, _) = both.feed(Side::B, init, 0);
    both.feed(Side::A, resp, 10);
    assert!(both.a.established() && both.b.established());

    // B answered; it never dialled, so it must not rekey.
    let b_out = Both::sends(both.b.poll(REKEY_AFTER_MS + 10, [0x22; 32]));
    assert!(
        b_out.is_empty(),
        "the responder started a rekey; that is the race `initiated` prevents"
    );
    let a_out = Both::sends(both.a.poll(REKEY_AFTER_MS + 10, [0x11; 32]));
    assert!(!a_out.is_empty(), "the initiator must rekey");
}
