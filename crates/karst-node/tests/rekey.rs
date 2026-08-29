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
//! the behavior that soak would depend on, in milliseconds rather than hours.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::wrong_self_convention
)]

use std::sync::Arc;

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
        kem_pk: k.kem_pk.clone(),
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

/// **A retransmitted `HandshakeInit` must not wedge the pair.**
///
/// An initiator retransmits the identical message until it hears back (§10), so
/// on any path where a retransmission crosses the response — a relayed one, a
/// lossy one, a slow one — the responder is asked the same question twice.
/// Answering it afresh derives a second set of keys and discards the first, the
/// set the initiator has already completed under. Both ends then report
/// `established`, neither can decrypt the other, and neither has any reason to
/// handshake again: the tunnel is wedged until the keys expire, with every
/// datagram counted as a decryption failure at one end and nothing at all at
/// the other.
///
/// Found by an aquifer row where the relay path was slow enough to make the
/// crossing routine rather than rare.
#[test]
fn a_retransmitted_handshake_init_does_not_wedge_the_pair() {
    let a_keys = keys(0x11, 0x12);
    let b_keys = keys(0x21, 0x22);
    let mut pair = Pair::new(
        Arc::clone(&a_keys),
        Arc::clone(&b_keys),
        peer_of(&a_keys),
        peer_of(&b_keys),
    );

    // A dials, and its `HandshakeInit` is delivered twice — which is what a
    // retransmission is, byte for byte.
    let msg1 = Pair::sends(pair.a.connect(0, [0x5A; 32]));
    let (msg2, _) = pair.deliver_to_b(msg1.clone(), 0);
    pair.deliver_to_a(msg2, 0);
    assert!(pair.a.established(), "A must establish on the first answer");

    let (msg2_again, _) = pair.deliver_to_b(msg1, 300);
    assert!(
        !msg2_again.is_empty(),
        "the retransmission was ignored, so an initiator whose response was \
         lost would never establish"
    );
    // A already has a session; the repeat must not disturb it either.
    pair.deliver_to_a(msg2_again, 300);

    pair.assert_traffic_flows(400, "after the retransmission");
    pair.assert_traffic_flows(500, "and again");
}

/// Give `datagrams` to a session outside the [`Pair`], returning how many
/// payloads it delivered. One reassembler across the call, because a handshake
/// response is two fragments and a fresh one per datagram never completes it.
fn feed(
    session: &mut Session,
    reasm: &mut Reassembler,
    datagrams: Vec<Vec<u8>>,
    now: u64,
) -> usize {
    let mut delivered = 0;
    for datagram in datagrams {
        let Ok((hdr, payload)) = split_datagram(&datagram) else {
            continue;
        };
        let Accept::Complete(msg) = reasm.push(SRC_B, true, &hdr, payload, now) else {
            continue;
        };
        let msg = msg.to_vec();
        for action in session.deliver(&msg, now) {
            if matches!(action, Action::Deliver(_)) {
                delivered += 1;
            }
        }
    }
    delivered
}

/// Send a payload B → A and assert it arrives, which is the half a responder
/// that quietly re-pointed its keys still fails.
fn assert_reverse_traffic_flows(p: &mut Pair, now: u64, what: &str) {
    let frags =
        p.b.send(what.as_bytes(), now)
            .unwrap_or_else(|e| panic!("B could not send at {now} ms: {e:?}"));
    let (_, delivered) = p.deliver_to_a(frags, now);
    assert_eq!(
        delivered.len(),
        1,
        "B → A traffic must flow at {now} ms ({what})"
    );
}

/// **§12.6: emitting a `HandshakeResponse` must not tear down a working
/// session.**
///
/// A `HandshakeInit` is forgeable by design — §12.5 spells out that `k2`
/// derives from values anyone holding the responder's *public* keys can
/// compute, so any party can fabricate one. A responder that installed the keys
/// it derived in answer would therefore hand every off-path attacker a
/// one-datagram teardown of somebody else's live tunnel: no secrets, no path,
/// no way for either end to notice beyond traffic stopping.
///
/// So the derived keys wait, the session in use carries on, and nothing adopts
/// them until a transport message authenticates under them — which a forger
/// cannot produce, because it needs `ct_ss` decapsulated and `dh_se` computed.
#[test]
fn a_fresh_handshake_init_does_not_disturb_a_working_session() {
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
    p.assert_traffic_flows(1_000, "before the intruder");

    // A well-formed `HandshakeInit` that is not the one A completed under, and
    // that nothing will ever finish. §12.5 makes this constructible by anyone;
    // building it here from a second session with the same identity keeps the
    // fixture honest about *what B sees*, which is all this test is about.
    let mut stray = Session::new(
        Arc::clone(&ak),
        Arc::clone(&bp),
        policy(),
        SuiteId::KARST_1,
        7,
        9,
    );
    let intrusion = Pair::sends(stray.connect(1_100, [0x77; 32]));
    assert!(!intrusion.is_empty(), "the fixture must produce an init");
    let (answer, _) = p.deliver_to_b(intrusion, 1_100);
    assert!(
        !answer.is_empty(),
        "B must still answer — §11 keeps a discard silent, and refusing here \
         would make B an oracle for whether it already holds a session"
    );

    // The session A is using is untouched, in both directions.
    p.assert_traffic_flows(1_200, "after the intruder");
    assert_reverse_traffic_flows(&mut p, 1_300, "after the intruder");
    assert!(p.b.established(), "B must still hold its session");
}

/// **And the keys are adopted the moment they are proven.** A peer that
/// restarts really does re-handshake, and the pair must converge on the new
/// session rather than the responder clinging to keys the peer has forgotten.
///
/// The proof §12.6 asks for is the first authenticated transport message: the
/// initiator decapsulated `ct_ss` and computed `dh_se`, which is exactly what a
/// forged `HandshakeInit` cannot do.
#[test]
fn keys_a_responder_derived_are_adopted_once_a_message_proves_them() {
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
    p.assert_traffic_flows(1_000, "the first session");

    // A restarts: same identity, no memory of the session B still holds.
    let mut restarted = Session::new(
        Arc::clone(&ak),
        Arc::clone(&bp),
        policy(),
        SuiteId::KARST_1,
        7,
        1,
    );
    let mut reasm = Reassembler::new(ReasmConfig::default());
    let init = Pair::sends(restarted.connect(2_000, [0x33; 32]));
    let (response, _) = p.deliver_to_b(init, 2_000);
    feed(&mut restarted, &mut reasm, response, 2_000);
    assert!(restarted.established(), "the restarted node must establish");

    // Its first transport message is the assurance, and B must both read it and
    // start using those keys.
    let frags = restarted.send(b"after the restart", 2_100).expect("send");
    let (_, delivered) = p.deliver_to_b(frags, 2_100);
    assert_eq!(
        delivered.len(),
        1,
        "the restarted node's traffic was dropped"
    );

    let reply = p.b.send(b"and back", 2_200).expect("B sends");
    let arrived = feed(&mut restarted, &mut reasm, reply, 2_200);
    assert_eq!(
        arrived, 1,
        "B kept sending under keys the peer no longer has, so the pair is \
         wedged in the reverse direction"
    );
}

/// Keys nothing ever authenticates under are forgotten, not held for ever.
///
/// They are keys: holding them past `REJECT_AFTER_TIME` would make them usable
/// beyond the window §2.4 gives any session, and a peer that walked away mid
/// handshake would leave one behind on every attempt.
#[test]
fn keys_nothing_proves_are_dropped_when_they_expire() {
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

    let mut stray = Session::new(
        Arc::clone(&ak),
        Arc::clone(&bp),
        policy(),
        SuiteId::KARST_1,
        7,
        9,
    );
    let intrusion = Pair::sends(stray.connect(1_000, [0x77; 32]));
    let _ = p.deliver_to_b(intrusion, 1_000);

    // The unproven keys are gone with the window, and the working session is
    // still working — the whole point being that only one of the two expires.
    let _ = p.b.poll(REJECT_AFTER_MS - 1, [0x5A; 32]);
    assert!(p.b.established());
    p.assert_traffic_flows(REKEY_AFTER_MS - 1, "the session that was in use");
}

/// **A rekey must not discard the keys it replaces.**
///
/// The two ends switch at different moments, and the gap is inherent to a
/// 1-RTT rekey: the initiator seals with the new keys the instant its handshake
/// completes, while the responder keeps using the old ones until a message
/// proves the new ones (§12.6). Everything the responder sends in that window
/// — and everything either end already put on the wire — is sealed under the
/// keys being replaced. An implementation that drops them at the swap loses
/// exactly that traffic, silently, because an AEAD failure is a drop.
#[test]
fn traffic_sealed_under_the_replaced_keys_still_arrives() {
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

    // Run the rekey to completion on A's side only: A now seals with the new
    // keys, and B has answered but has seen nothing under them, so it is still
    // sending under the old ones.
    let init = Pair::sends(p.a.poll(REKEY_AFTER_MS, [0x5A; 32]));
    assert!(!init.is_empty(), "a rekey handshake must be sent");
    let (response, _) = p.deliver_to_b(init, REKEY_AFTER_MS);
    p.deliver_to_a(response, REKEY_AFTER_MS);
    assert!(!p.a.rekeying(), "the rekey must have completed on A");

    assert_reverse_traffic_flows(&mut p, REKEY_AFTER_MS + 1, "sealed under the old keys");
}

/// **And the replaced keys stop working when they expire.** They are kept for
/// the traffic still in flight, not indefinitely: §2.4 gives any session
/// `REJECT_AFTER_TIME`, and a slot that outlived it would extend that window
/// for whichever end happened to rekey.
#[test]
fn the_replaced_keys_are_refused_once_they_expire() {
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
    let init = Pair::sends(p.a.poll(REKEY_AFTER_MS, [0x5A; 32]));
    let (response, _) = p.deliver_to_b(init, REKEY_AFTER_MS);
    p.deliver_to_a(response, REKEY_AFTER_MS);

    // Sealed while the old keys are still inside their window, held back, and
    // delivered after it closes — which is what a delayed datagram is.
    let held =
        p.b.send(b"in flight", REJECT_AFTER_MS - 1)
            .expect("B seals under the keys it still holds");

    let _ = p.a.poll(REJECT_AFTER_MS + 1, [0x5A; 32]);
    let (_, delivered) = p.deliver_to_a(held, REJECT_AFTER_MS + 1);
    assert!(
        delivered.is_empty(),
        "keys past REJECT_AFTER_TIME opened a message"
    );
    // The session that replaced them is untouched: only one of the two expires.
    p.assert_traffic_flows(REJECT_AFTER_MS + 2, "the current session");
}

/// **The keys adopted are the ones that opened the message.**
///
/// The AEAD runs outside the session's lock, so between a datagram opening
/// under the waiting keys and the adoption that follows, another
/// `HandshakeInit` can land — and its timing is the attacker's to choose, since
/// forging one takes a single datagram and no secrets (§12.5).
///
/// Both ways of getting this wrong are failures with a victim. Adopting
/// whatever is waiting at that moment installs keys nothing has proven, by a
/// race, which is what §12.6 exists to prevent. Refusing to adopt anything
/// because the slot has changed drops a set that *was* proven, leaving this
/// node sealing for a peer that has already moved on — the wedge again, now
/// reachable by an attacker's timing rather than by luck.
#[test]
fn only_the_keys_a_message_proved_are_adopted() {
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

    // A peer that restarts, handshakes, and sends — the ordinary case that
    // should be adopted.
    let mut restarted = Session::new(
        Arc::clone(&ak),
        Arc::clone(&bp),
        policy(),
        SuiteId::KARST_1,
        7,
        1,
    );
    let mut reasm = Reassembler::new(ReasmConfig::default());
    let init = Pair::sends(restarted.connect(1_000, [0x33; 32]));
    let (response, _) = p.deliver_to_b(init, 1_000);
    feed(&mut restarted, &mut reasm, response, 1_000);
    let proven = restarted.send(b"proof", 1_100).expect("send");

    // Its message is opened — but before B acts on it, a stray
    // `HandshakeInit` replaces what B is holding.
    let inbound = p.b.inbound().expect("B holds a session");
    let mut opened = 0;
    for datagram in &proven {
        let Ok((hdr, payload)) = split_datagram(datagram) else {
            continue;
        };
        let Accept::Complete(msg) = p.b_reasm.push(SRC_A, true, &hdr, payload, 1_100) else {
            continue;
        };
        if inbound.open(msg, 1_100).is_ok() {
            opened += 1;
        }
    }
    assert_eq!(opened, 1, "the restarted node's message must open");

    let mut stray = Session::new(
        Arc::clone(&ak),
        Arc::clone(&bp),
        policy(),
        SuiteId::KARST_1,
        7,
        9,
    );
    let intrusion = Pair::sends(stray.connect(1_150, [0x77; 32]));
    let _ = p.deliver_to_b(intrusion, 1_150);

    // Now B acts on the message it opened. The stray's keys must not be what
    // it adopts.
    p.b.promote(&inbound);
    let reply = p.b.send(b"and back", 1_200).expect("B sends");
    let arrived = feed(&mut restarted, &mut reasm, reply, 1_200);
    assert_eq!(
        arrived, 1,
        "B adopted keys nothing had proven, so it is now sealing for a peer \
         that cannot read it"
    );
}
