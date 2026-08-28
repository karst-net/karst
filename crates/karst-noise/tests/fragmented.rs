// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A real handshake carried over the fragmentation layer — `spec/phreatic-v1.md`
//! §5, §6, §9.
//!
//! `karst-noise` produces 2378-byte messages and `karst-proto` carries 1208-byte
//! fragments. These tests join the two, which is where mismatches between the
//! specification's arithmetic and the implementation would surface.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use karst_crypto::kem::KemKind;
use karst_crypto::{SuiteId, SuitePolicy};
use karst_noise::handshake::{
    initiate, peer_id_hint, respond, InitiatorRandomness, PeerPublic, ResponderRandomness,
    SessionParams, StaticKeys, TIMESTAMP_LEN,
};
use karst_proto::consts;
use karst_proto::dos::{mac1_key, mac2_key, verify_frag_mac, CookieSecret, FragMacKey};
use karst_proto::reassembly::{Accept, Config, Reassembler, Reject, SourceKey};
use karst_proto::{fragment, split_datagram, MessageType};

const PSK: [u8; 32] = [0x42; 32];
const SRC: SourceKey = [3; 18];

fn alice() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xA1; 64], &[0xA2; 32]))
}
fn bob() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xB1; 64], &[0xB2; 32]))
}
fn peer_of(k: &StaticKeys) -> PeerPublic {
    PeerPublic {
        kem_pk: k.kem_pk.clone(),
        dh_pk: k.dh_pk,
        psk: PSK,
    }
}
fn irand() -> InitiatorRandomness {
    InitiatorRandomness {
        e_kem_seed: [0xE1; 64],
        e_dh_seed: [0xE2; 32],
        encap_rand: [0xE3; 32],
        timestamp: [1; TIMESTAMP_LEN],
    }
}
fn rrand() -> ResponderRandomness {
    ResponderRandomness {
        e_dh_seed: [0xF1; 32],
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}
fn policy() -> SuitePolicy {
    SuitePolicy {
        minimum: SuiteId::KARST_1,
        supported: vec![SuiteId::KARST_1],
    }
}
fn params() -> SessionParams {
    SessionParams {
        suite: SuiteId::KARST_1,
        psk_epoch: 7,
        sender_index: 1,
    }
}

/// Build a real `HandshakeInit` and split it into authenticated fragments.
fn init_fragments(a: &Arc<StaticKeys>, b: &StaticKeys) -> (Vec<u8>, Vec<Vec<u8>>, [u8; 64]) {
    let b_pub = peer_of(b);
    let (_, msg1) = initiate(Arc::clone(a), Arc::new(b_pub), params(), &irand()).unwrap();
    let key = mac1_key(&b.kem_pk.to_bytes());
    let frags = fragment(
        MessageType::HandshakeInit,
        0xDEAD_BEEF,
        &msg1,
        &FragMacKey::new(&key),
    )
    .unwrap();
    (msg1, frags, key)
}

/// The headline joint property: a 2378-byte handshake message survives the
/// round trip through fragmentation and reassembly byte-for-byte, and the
/// reassembled bytes still drive a working handshake.
#[test]
fn a_real_handshake_survives_fragmentation_and_reassembly() {
    let (a, b) = (alice(), bob());
    let (msg1, frags, key) = init_fragments(&a, &b);

    assert_eq!(msg1.len(), 2378, "spec §6.1");
    assert_eq!(frags.len(), 2, "spec §6.4 — two fragments");

    let mut r = Reassembler::new(Config::default());
    let mut reassembled = None;
    for datagram in &frags {
        assert!(
            datagram.len() <= consts::DATAGRAM_MAX - consts::IPV6_HEADER - consts::UDP_HEADER,
            "each datagram must fit the minimum MTU"
        );
        let (hdr, payload) = split_datagram(datagram).unwrap();

        // §9.2 — verify the MAC before the fragment may touch a buffer.
        assert!(
            verify_frag_mac(
                &key,
                MessageType::HandshakeInit as u8,
                hdr.reassembly_id,
                hdr.idx,
                hdr.count,
                &hdr.frag_mac
            ),
            "fragment MAC must verify"
        );

        if let Accept::Complete(msg) = r.push(SRC, true, &hdr, payload, 0) {
            reassembled = Some(msg.to_vec());
        }
    }

    let got = reassembled.expect("must reassemble");
    assert_eq!(got, msg1, "reassembly must be byte-exact");
    assert_eq!(r.occupied(), 0, "slot released on completion");

    // And the reassembled bytes still work as a handshake.
    let a_hint = a.hint();
    let (msg2, _, _) = respond(
        &b,
        &policy(),
        &got,
        |h, _e| (*h == a_hint).then(|| peer_of(&a)),
        &rrand(),
        2,
    )
    .unwrap();
    assert_eq!(msg2.len(), 2236, "spec §6.2");
}

/// Fragments may arrive in any order.
#[test]
fn fragments_reassemble_out_of_order() {
    let (a, b) = (alice(), bob());
    let (msg1, mut frags, _) = init_fragments(&a, &b);
    frags.reverse();

    let mut r = Reassembler::new(Config::default());
    let mut out = None;
    for datagram in &frags {
        let (hdr, payload) = split_datagram(datagram).unwrap();
        if let Accept::Complete(msg) = r.push(SRC, true, &hdr, payload, 0) {
            out = Some(msg.to_vec());
        }
    }
    assert_eq!(out.unwrap(), msg1);
}

/// **§13.8 — an altered payload passes the fragment MAC and is caught by the
/// AEAD.**
///
/// This is the property the MAC change trades away, so it is asserted rather
/// than left implicit. §9.2 never claimed message integrity — "it provides no
/// reassembly integrity […] integrity of the reassembled message comes solely
/// from the message-level AEAD tag" — and an adversary holding the recipient's
/// *public* static key could always forge a MAC over any payload. What this
/// test pins is that the AEAD really is the thing that catches it, because the
/// MAC no longer will.
#[test]
fn an_altered_payload_passes_the_mac_and_is_caught_by_the_aead() {
    let (initiator, responder) = (alice(), bob());
    let (msg1, frags, key) = init_fragments(&initiator, &responder);

    let mut bad = frags.first().unwrap().clone();
    if let Some(x) = bad.last_mut() {
        *x ^= 0x01;
    }
    let (hdr, _) = split_datagram(&bad).unwrap();
    assert!(
        verify_frag_mac(
            &key,
            MessageType::HandshakeInit as u8,
            hdr.reassembly_id,
            hdr.idx,
            hdr.count,
            &hdr.frag_mac
        ),
        "the MAC covers the header only, so a payload edit leaves it valid"
    );

    // Reassemble the tampered message and offer it to the responder. The AEAD
    // is what must refuse it.
    let mut reasm = Reassembler::new(Config::default());
    let mut tampered = None;
    for (index, datagram) in frags.iter().enumerate() {
        let source = if index == 0 { &bad } else { datagram };
        let (header, body) = split_datagram(source).unwrap();
        if let Accept::Complete(whole) = reasm.push(SRC, true, &header, body, 0) {
            tampered = Some(whole.to_vec());
        }
    }
    let tampered = tampered.expect("a tampered message still reassembles");
    assert_ne!(tampered, msg1, "the message really was altered");

    let expected_hint = peer_id_hint(&initiator.kem_pk.to_bytes());
    let outcome = respond(
        &responder,
        &policy(),
        &tampered,
        |hint, _| (*hint == expected_hint).then(|| peer_of(&initiator)),
        &rrand(),
        2,
    );
    assert!(
        outcome.is_err(),
        "the AEAD must reject a message the MAC no longer protects"
    );
}

/// §9.2 — a fragment cannot be moved to another index: `idx` is under the MAC.
#[test]
fn a_fragment_cannot_be_relocated_within_the_message() {
    let (a, b) = (alice(), bob());
    let (_, frags, key) = init_fragments(&a, &b);

    let first = frags.first().unwrap();
    let (hdr, _) = split_datagram(first).unwrap();
    // Claim it is fragment 1 rather than 0, keeping the original MAC.
    assert!(
        !verify_frag_mac(
            &key,
            MessageType::HandshakeInit as u8,
            hdr.reassembly_id,
            1,
            hdr.count,
            &hdr.frag_mac
        ),
        "index is covered by the MAC"
    );
}

/// §9.1 + §9.3 end-to-end: under load an unvalidated source is refused and
/// allocates nothing; after completing the cookie round trip it is served.
#[test]
fn under_load_a_cookie_round_trip_is_required() {
    let (a, b) = (alice(), bob());
    let (_, frags, _) = init_fragments(&a, &b);
    let first = frags.first().unwrap();
    let (hdr, payload) = split_datagram(first).unwrap();

    let cfg = Config {
        max_entries: 8,
        max_per_source: 8,
        timeout_ms: 3_000,
        load_threshold: 0, // permanently "under load"
    };
    let mut r = Reassembler::new(cfg);

    // Unvalidated: refused, and nothing is allocated.
    assert_eq!(
        r.push(SRC, false, &hdr, payload, 0),
        Accept::Rejected(Reject::CookieRequired)
    );
    assert_eq!(r.occupied(), 0, "no state for an unvalidated source");

    // The responder issues a stateless cookie; the initiator echoes it, which
    // switches the fragment MAC key to mac2 and validates the address.
    let secret = CookieSecret::new([0x5A; 32], 0, 120_000);
    let cookie = secret.issue(&SRC);
    assert!(secret.validate(&SRC, &cookie));

    let key2 = mac2_key(&cookie);
    let (_, msg1) = initiate(a, Arc::new(peer_of(&b)), params(), &irand()).unwrap();
    let frags2 = fragment(
        MessageType::HandshakeInit,
        0xFEED_FACE,
        &msg1,
        &FragMacKey::new(&key2),
    )
    .unwrap();

    let mut out = None;
    for datagram in &frags2 {
        let (hdr2, payload2) = split_datagram(datagram).unwrap();
        assert!(verify_frag_mac(
            &key2,
            MessageType::HandshakeInit as u8,
            hdr2.reassembly_id,
            hdr2.idx,
            hdr2.count,
            &hdr2.frag_mac
        ));
        if let Accept::Complete(msg) = r.push(SRC, true, &hdr2, payload2, 0) {
            out = Some(msg.to_vec());
        }
    }
    assert_eq!(out.unwrap(), msg1, "served once address-validated");
}

/// §6.4 anti-amplification, measured on the wire rather than asserted on paper:
/// what a responder emits must not exceed what it received.
#[test]
fn anti_amplification_holds_on_the_wire() {
    let (a, b) = (alice(), bob());
    let (msg1, frags, key) = init_fragments(&a, &b);

    let received: usize = frags.iter().map(Vec::len).sum();

    let a_hint = a.hint();
    let (msg2, _, _) = respond(
        &b,
        &policy(),
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(&a)),
        &rrand(),
        2,
    )
    .unwrap();
    let out_frags = fragment(
        MessageType::HandshakeResponse,
        1,
        &msg2,
        &FragMacKey::new(&key),
    )
    .unwrap();
    let emitted: usize = out_frags.iter().map(Vec::len).sum();

    assert!(
        emitted < received,
        "emitted {emitted} B must not exceed received {received} B"
    );
}

// ── KARST_2 needs three fragments — spec §6.5, ADR-0015 item 1 ──────────────

/// **The CNSA profile crosses the two-fragment line, and that is a property
/// worth a test rather than a table.** `KARST_2` carries 1 568-byte ML-KEM-1024
/// keys and ciphertexts and no X25519, giving a 3 210-byte `HandshakeInit`:
/// three fragments where `KARST_1` needs two, so three datagrams must arrive
/// for a handshake to complete instead of two.
///
/// Everything else about the fragmentation layer is unchanged — same 1 208-byte
/// payloads, same MAC, same reassembler — which is exactly what this asserts,
/// because a suite that needed a *different* fragmentation would be a different
/// protocol.
#[test]
fn a_cnsa_handshake_needs_three_fragments_and_still_reassembles() {
    let a = Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xA1; 64],
        &[0xA2; 32],
    ));
    let b = Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xB1; 64],
        &[0xB2; 32],
    ));

    let cnsa_params = SessionParams {
        suite: SuiteId::KARST_2,
        psk_epoch: 7,
        sender_index: 1,
    };
    let cnsa_policy = SuitePolicy {
        minimum: SuiteId::KARST_2,
        supported: vec![SuiteId::KARST_2],
    };

    let (_, msg1) = initiate(Arc::clone(&a), Arc::new(peer_of(&b)), cnsa_params, &irand()).unwrap();
    assert_eq!(msg1.len(), 3210, "spec §6.5");

    let key = mac1_key(&b.kem_pk.to_bytes());
    let frags = fragment(
        MessageType::HandshakeInit,
        0xC0FF_EE00,
        &msg1,
        &FragMacKey::new(&key),
    )
    .unwrap();
    assert_eq!(frags.len(), 3, "spec §6.5 — three fragments, not two");
    assert!(
        frags.len() <= consts::MAX_FRAGMENTS as usize,
        "still inside the four-fragment hard cap"
    );

    let mut r = Reassembler::new(Config::default());
    let mut reassembled = None;
    for datagram in &frags {
        assert!(
            datagram.len() <= consts::DATAGRAM_MAX - consts::IPV6_HEADER - consts::UDP_HEADER,
            "each datagram must still fit the minimum MTU"
        );
        let (hdr, payload) = split_datagram(datagram).unwrap();
        assert!(
            verify_frag_mac(
                &key,
                MessageType::HandshakeInit as u8,
                hdr.reassembly_id,
                hdr.idx,
                hdr.count,
                &hdr.frag_mac
            ),
            "the fragment MAC is suite-independent and must still verify"
        );
        if let Accept::Complete(msg) = r.push(SRC, true, &hdr, payload, 0) {
            reassembled = Some(msg.to_vec());
        }
    }

    let got = reassembled.expect("three fragments must reassemble");
    assert_eq!(got, msg1, "reassembly must be byte-exact");
    assert_eq!(r.occupied(), 0, "slot released on completion");

    let a_hint = a.hint();
    let (msg2, _, suite) = respond(
        &b,
        &cnsa_policy,
        &got,
        |h, _e| (*h == a_hint).then(|| peer_of(&a)),
        &rrand(),
        2,
    )
    .unwrap();
    assert_eq!(suite, SuiteId::KARST_2);
    assert_eq!(msg2.len(), 3164, "spec §6.5");
    assert!(
        msg1.len() > msg2.len(),
        "anti-amplification still holds, by 46 bytes"
    );
}

/// **Two fragments of a three-fragment message must not complete.** The
/// reassembler counts what the header claims, and `KARST_2` is the first suite
/// where a missing third fragment is a real operational case rather than a
/// hypothetical — three-in-three at 5% path loss is roughly 86% against 90%
/// for two (§6.5).
#[test]
fn a_cnsa_handshake_does_not_complete_on_two_of_its_three_fragments() {
    let a = Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xA1; 64],
        &[0xA2; 32],
    ));
    let b = Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xB1; 64],
        &[0xB2; 32],
    ));
    let (_, msg1) = initiate(
        Arc::clone(&a),
        Arc::new(peer_of(&b)),
        SessionParams {
            suite: SuiteId::KARST_2,
            psk_epoch: 7,
            sender_index: 1,
        },
        &irand(),
    )
    .unwrap();

    let key = mac1_key(&b.kem_pk.to_bytes());
    let frags = fragment(
        MessageType::HandshakeInit,
        0xC0FF_EE01,
        &msg1,
        &FragMacKey::new(&key),
    )
    .unwrap();

    for dropped in 0..3 {
        let mut r = Reassembler::new(Config::default());
        for (i, datagram) in frags.iter().enumerate() {
            if i == dropped {
                continue;
            }
            let (hdr, payload) = split_datagram(datagram).unwrap();
            assert!(
                !matches!(r.push(SRC, true, &hdr, payload, 0), Accept::Complete(_)),
                "completed without fragment {dropped}"
            );
        }
        assert_eq!(r.occupied(), 1, "the partial message still holds a slot");
    }
}
