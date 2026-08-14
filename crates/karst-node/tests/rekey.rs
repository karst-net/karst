// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Rekeying and session lifetime — spec §2.4, §10.
//!
//! PLAN.md's Phase 2 exit criterion asks for a 12-hour soak *with rekeying*. At
//! `REKEY_AFTER_TIME` = 120 s that is around 360 rekeys per peer, so anything
//! that stalls traffic or drops a session on each one is not a minor blemish —
//! it is the difference between a tunnel that stays up overnight and one that
//! stutters every two minutes.
//!
//! These run on a virtual clock. A real soak is a separate exercise; this pins
//! the behaviour that soak would depend on, in milliseconds rather than hours.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::wrong_self_convention
)]

use std::sync::Arc;

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karst_crypto::{SuiteId, SuitePolicy};
use karst_node::{Action, CloseReason, Session};
use karst_noise::handshake::{PeerPublic, ResponderRandomness, StaticKeys};
use karst_noise::transport::{REJECT_AFTER_MS, REKEY_AFTER_MS};
use karst_proto::reassembly::{Accept, Config as ReasmConfig, Reassembler};
use karst_proto::split_datagram;

const PSK: [u8; 32] = [0x42; 32];
const SRC_A: karst_proto::reassembly::SourceKey = [0x11; 18];
const SRC_B: karst_proto::reassembly::SourceKey = [0x22; 18];

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

/// Two sessions and the reassembly each needs, wired to hand datagrams over
/// directly. No sockets, no clock: `now` is whatever the test says it is.
struct Pair {
    a: Session,
    b: Session,
    a_reasm: Reassembler,
    b_reasm: Reassembler,
    /// Distinct responder randomness per handshake — reusing encapsulation
    /// randomness across handshakes is a key-recovery risk, not untidiness.
    round: u8,
}

impl Pair {
    fn new(
        a_keys: Arc<StaticKeys>,
        b_keys: Arc<StaticKeys>,
        a_pub: Arc<PeerPublic>,
        b_pub: Arc<PeerPublic>,
    ) -> Self {
        Self {
            a: Session::new(a_keys, b_pub, policy(), SuiteId::KARST_1, 7, 1),
            b: Session::new(b_keys, a_pub, policy(), SuiteId::KARST_1, 7, 2),
            a_reasm: Reassembler::new(ReasmConfig::default()),
            b_reasm: Reassembler::new(ReasmConfig::default()),
            round: 0,
        }
    }

    /// Give `datagrams` to B, returning what B emits.
    fn deliver_to_b(&mut self, datagrams: Vec<Vec<u8>>, now: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut out = Vec::new();
        let mut delivered = Vec::new();
        for d in datagrams {
            let Ok((hdr, payload)) = split_datagram(&d) else {
                continue;
            };
            let Accept::Complete(msg) = self.b_reasm.push(SRC_A, true, &hdr, payload, now) else {
                continue;
            };
            let msg = msg.to_vec();
            let actions = if msg.first() == Some(&0x01) {
                self.round = self.round.wrapping_add(1);
                self.b.respond_to(&msg, &rrand(self.round), now)
            } else {
                self.b.deliver(&msg, now)
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

    /// Give `datagrams` to A, returning what A emits.
    fn deliver_to_a(&mut self, datagrams: Vec<Vec<u8>>, now: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut out = Vec::new();
        let mut delivered = Vec::new();
        for d in datagrams {
            let Ok((hdr, payload)) = split_datagram(&d) else {
                continue;
            };
            let Accept::Complete(msg) = self.a_reasm.push(SRC_B, true, &hdr, payload, now) else {
                continue;
            };
            let msg = msg.to_vec();
            for a in self.a.deliver(&msg, now) {
                match a {
                    Action::Send(d) => out.push(d),
                    Action::Deliver(p) => delivered.push(p),
                    _ => {}
                }
            }
        }
        (out, delivered)
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

    /// Complete the initial handshake.
    fn establish(&mut self, now: u64) {
        let msg1 = Self::sends(self.a.connect(now, [0x5A; 32]));
        let (msg2, _) = self.deliver_to_b(msg1, now);
        self.deliver_to_a(msg2, now);
        assert!(self.a.established(), "A must establish");
        assert!(self.b.established(), "B must establish");
    }

    /// Poll A, delivering anything it emits and returning B's replies.
    fn tick(&mut self, now: u64) {
        let out = Self::sends(self.a.poll(now, [0x5A; 32]));
        if out.is_empty() {
            return;
        }
        let (reply, _) = self.deliver_to_b(out, now);
        self.deliver_to_a(reply, now);
    }

    /// Send a payload A → B and assert it arrives.
    fn assert_traffic_flows(&mut self, now: u64, what: &str) {
        let frags = self
            .a
            .send(what.as_bytes(), now)
            .unwrap_or_else(|e| panic!("send failed at {now} ms: {e:?}"));
        let (_, delivered) = self.deliver_to_b(frags, now);
        assert_eq!(delivered.len(), 1, "traffic must flow at {now} ms ({what})");
        assert_eq!(
            delivered[0].get(..what.len()),
            Some(what.as_bytes()),
            "payload must survive at {now} ms"
        );
    }
}

/// **The defect this file was written for.** A rekey must not interrupt
/// traffic. The old session stays usable from the moment the rekey starts until
/// the moment it completes — an implementation that swaps state on the *first*
/// step stalls every flow for a round trip, every two minutes.
#[test]
fn traffic_never_stalls_during_a_rekey() {
    let ak = keys(0xA1, 0xA2);
    let bk = keys(0xB1, 0xB2);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );
    p.establish(0);

    // Just before the rekey is due.
    p.assert_traffic_flows(REKEY_AFTER_MS - 1, "before");

    // Trigger the rekey but do NOT deliver its handshake yet: this is the
    // window where a naive implementation has already discarded the session.
    let in_flight = Pair::sends(p.a.poll(REKEY_AFTER_MS, [0x5A; 32]));
    assert!(!in_flight.is_empty(), "a rekey handshake must be sent");
    assert!(p.a.rekeying(), "and recorded as in flight");
    assert!(
        p.a.established(),
        "while the session it will replace stays established"
    );
    p.assert_traffic_flows(REKEY_AFTER_MS, "during the rekey");

    // Now complete it.
    let (reply, _) = p.deliver_to_b(in_flight, REKEY_AFTER_MS + 10);
    p.deliver_to_a(reply, REKEY_AFTER_MS + 20);
    assert!(!p.a.rekeying(), "the rekey must have completed");
    assert!(p.a.established());
    p.assert_traffic_flows(REKEY_AFTER_MS + 30, "after the rekey");
}

/// A session must survive well past `REJECT_AFTER_TIME` measured from process
/// start, because that is not what the limit means.
///
/// Regression: `established_ms` was hard-coded to 0, so every session appeared
/// to expire 180 s after the *daemon* began — a node could not hold a tunnel
/// open beyond three minutes of uptime, however recently the session was made.
#[test]
fn a_session_established_late_is_not_instantly_expired() {
    let ak = keys(0xC1, 0xC2);
    let bk = keys(0xD1, 0xD2);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );

    // Establish long after start-up — an hour in.
    let start = 3_600_000;
    p.establish(start);
    p.assert_traffic_flows(start + 1, "immediately after a late handshake");

    // And it must still be alive just short of its own expiry, not the
    // process's.
    p.tick(start + REJECT_AFTER_MS - 1);
    assert!(
        p.a.established(),
        "the session must live REJECT_AFTER_TIME from its own establishment"
    );
}

/// Sustained operation across many rekeys, which is what the soak exercises.
#[test]
fn traffic_survives_many_consecutive_rekeys() {
    let ak = keys(0xE1, 0xE2);
    let bk = keys(0xF1, 0xF2);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );
    p.establish(0);

    // 30 rekeys ≈ an hour of wall time at REKEY_AFTER_TIME.
    let mut now = 0u64;
    for round in 1..=30u64 {
        now = round * REKEY_AFTER_MS;
        p.tick(now);
        p.tick(now + 10);
        assert!(
            p.a.established(),
            "session lost at rekey {round} ({now} ms)"
        );
        p.assert_traffic_flows(now + 20, "after a rekey");
    }
    assert!(now >= 30 * REKEY_AFTER_MS);
}

/// A rekey that never completes must not take the working session with it.
///
/// The session remains valid until `REJECT_AFTER_TIME`; abandoning it because a
/// *replacement* failed would turn a lossy minute into a dropped tunnel.
#[test]
fn an_abandoned_rekey_leaves_the_live_session_alone() {
    let ak = keys(0x11, 0x12);
    let bk = keys(0x21, 0x22);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );
    p.establish(0);

    // Start a rekey and drop every datagram it produces.
    let _discarded = Pair::sends(p.a.poll(REKEY_AFTER_MS, [0x5A; 32]));
    assert!(p.a.rekeying());

    // Traffic keeps flowing while the rekey retries into the void.
    for t in [REKEY_AFTER_MS + 1_000, REKEY_AFTER_MS + 30_000] {
        let _ = Pair::sends(p.a.poll(t, [0x5A; 32]));
        assert!(p.a.established(), "the live session must survive at {t} ms");
        p.assert_traffic_flows(t, "while a rekey is failing");
    }

    // Past the give-up window the rekey is abandoned — and only the rekey.
    // (The session itself expires on its own schedule, tested above.)
    let _ = Pair::sends(p.a.poll(
        REKEY_AFTER_MS + karst_node::session::HANDSHAKE_GIVE_UP_MS,
        [0x5A; 32],
    ));
    assert!(
        !p.a.rekeying(),
        "the rekey must be abandoned after the give-up window"
    );
}

/// **A forged `HandshakeResponse` must not cancel a handshake.**
///
/// `frag_mac` is keyed by a public static key (§9.2), so anyone who knows a
/// node's public key can produce fragments that reach the response handler.
/// If a response that fails to authenticate destroyed the handshake, an
/// off-path attacker could stop every connection on the network from ever
/// completing — no cryptographic break required.
#[test]
fn a_forged_response_does_not_cancel_the_handshake() {
    let ak = keys(0x31, 0x32);
    let bk = keys(0x41, 0x42);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );

    let msg1 = Pair::sends(p.a.connect(0, [0x5A; 32]));

    // A well-formed HandshakeResponse of the right length whose contents are
    // garbage: it parses, and fails only at the AEAD tag.
    let mut forged = vec![0u8; karst_proto::sizes::HANDSHAKE_RESPONSE];
    forged[0] = 0x02;
    assert!(
        p.a.deliver(&forged, 1).is_empty(),
        "a forged response must produce no actions"
    );

    // The real response still completes the handshake.
    let (msg2, _) = p.deliver_to_b(msg1, 2);
    p.deliver_to_a(msg2, 3);
    assert!(
        p.a.established(),
        "the handshake must survive a forged response and still complete"
    );
}

/// Many forged responses in a row, to be sure nothing accumulates.
#[test]
fn repeated_forgeries_do_not_wear_the_handshake_down() {
    let ak = keys(0x51, 0x52);
    let bk = keys(0x61, 0x62);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );

    let msg1 = Pair::sends(p.a.connect(0, [0x5A; 32]));
    for i in 0..200u8 {
        let mut forged = vec![i; karst_proto::sizes::HANDSHAKE_RESPONSE];
        forged[0] = 0x02;
        assert!(p.a.deliver(&forged, u64::from(i)).is_empty());
    }
    let (msg2, _) = p.deliver_to_b(msg1, 300);
    p.deliver_to_a(msg2, 301);
    assert!(p.a.established(), "200 forgeries must change nothing");
}

/// Expiry still works: past `REJECT_AFTER_TIME` with no successful rekey, the
/// session closes rather than using keys it should not.
#[test]
fn a_session_still_expires_when_a_rekey_never_lands() {
    let ak = keys(0x71, 0x72);
    let bk = keys(0x81, 0x82);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );
    p.establish(0);

    // Rekeys are attempted and every datagram is dropped.
    let mut closed = None;
    for t in (REKEY_AFTER_MS..=REJECT_AFTER_MS + 1_000).step_by(1_000) {
        for action in p.a.poll(t, [0x5A; 32]) {
            if let Action::Closed(r) = action {
                closed = Some(r);
            }
        }
    }
    assert_eq!(
        closed,
        Some(CloseReason::Expired),
        "the session must close once its keys are past REJECT_AFTER_TIME"
    );
    assert!(!p.a.established());
    assert!(p.a.send(b"anything", REJECT_AFTER_MS + 2_000).is_err());
}

/// **Only the initiator rekeys.** If both sides do, they race: each starts a
/// handshake, each adopts the *other's* as responder while discarding its own,
/// and the two ends finish holding sessions derived from different handshakes.
/// Neither can then decrypt the other, and because an AEAD failure is a silent
/// drop rather than a counted error, the tunnel reports `established` while
/// carrying nothing — until `REJECT_AFTER_TIME` expires both sides.
///
/// A 7.8-hour soak found this as **9 stalls of 253–765 s, 13% of samples**.
#[test]
fn only_the_initiator_rekeys() {
    let ak = keys(0x91, 0x92);
    let bk = keys(0xA9, 0xAA);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );
    p.establish(0);

    // Past the rekey deadline, the initiator starts one…
    let out = Pair::sends(p.a.poll(REKEY_AFTER_MS, [0x5A; 32]));
    assert!(!out.is_empty(), "the initiator must rekey");
    assert!(p.a.rekeying());

    // …and the responder must not, however long it sits there. Every tick it
    // stays quiet is a handshake that cannot collide with the initiator's.
    for t in 0..8u64 {
        let now = REKEY_AFTER_MS + t * 1_000;
        assert!(
            Pair::sends(p.b.poll(now, [0xB5; 32])).is_empty(),
            "the responder must not initiate a rekey at {now} ms"
        );
        assert!(!p.b.rekeying(), "and must not have one in flight");
    }

    // The initiator's rekey still completes, and traffic still flows.
    let (reply, _) = p.deliver_to_b(out, REKEY_AFTER_MS + 10);
    p.deliver_to_a(reply, REKEY_AFTER_MS + 20);
    assert!(p.a.established());
    p.assert_traffic_flows(REKEY_AFTER_MS + 30, "after an uncontested rekey");
}

/// After a rekey the responder is *still* the responder, so it must still not
/// initiate — otherwise the race returns one rekey interval later.
#[test]
fn the_responder_stays_passive_across_successive_rekeys() {
    let ak = keys(0xC9, 0xCA);
    let bk = keys(0xD9, 0xDA);
    let (ap, bp) = (peer_of(&ak), peer_of(&bk));
    let mut p = Pair::new(
        Arc::clone(&ak),
        Arc::clone(&bk),
        Arc::clone(&ap),
        Arc::clone(&bp),
    );
    p.establish(0);

    // Each rekey resets the deadline to the *new* session's establishment, so
    // the schedule accumulates rather than landing on round * REKEY_AFTER_MS.
    let mut established_at = 0u64;
    for round in 1..=4u64 {
        let now = established_at + REKEY_AFTER_MS;
        let out = Pair::sends(p.a.poll(now, [0x5A; 32]));
        assert!(!out.is_empty(), "initiator must rekey at round {round}");
        let (reply, _) = p.deliver_to_b(out, now + 10);
        p.deliver_to_a(reply, now + 20);
        established_at = now + 20;

        assert!(
            Pair::sends(p.b.poll(established_at + 10, [0xB5; 32])).is_empty(),
            "responder must stay passive at round {round}"
        );
        p.assert_traffic_flows(established_at + 20, "after a rekey");
    }
}
