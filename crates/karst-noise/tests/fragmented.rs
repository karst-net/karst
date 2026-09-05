// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A real handshake carried over the fragmentation layer — `spec/phreatic-v1.md`
//! §5, §6, §9.
//!
//! `karst-noise` produces 3210-byte messages and `karst-proto` carries 1208-byte
//! fragments. These tests join the two, which is where mismatches between the
//! specification's arithmetic and the implementation would surface.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use karst_crypto::kem::KemKind;
use karst_noise::handshake::{
    initiate, respond, InitiatorRandomness, PeerPublic, ResponderRandomness, SessionParams,
    StaticKeys, TIMESTAMP_LEN,
};
use karst_proto::consts;
use karst_proto::dos::{mac1_key, mac2_key, verify_frag_mac, CookieSecret, FragMacKey};
use karst_proto::reassembly::{Accept, Config, Reassembler, Reject, SourceKey};
use karst_proto::{fragment, split_datagram, MessageType};

const PSK: [u8; 32] = [0x42; 32];
const SRC: SourceKey = [3; 18];

fn alice() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xA1; 64]))
}
fn bob() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xB1; 64]))
}
fn peer_of(k: &StaticKeys) -> PeerPublic {
    PeerPublic {
        kem_pk: k.kem_pk.clone(),

        psk: PSK,
    }
}
fn irand() -> InitiatorRandomness {
    InitiatorRandomness {
        e_kem_seed: [0xE1; 64],

        encap_rand: [0xE3; 32],
        timestamp: [1; TIMESTAMP_LEN],
    }
}
fn rrand() -> ResponderRandomness {
    ResponderRandomness {
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}

fn params() -> SessionParams {
    SessionParams {
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

/// The headline joint property: a 3210-byte handshake message survives the
/// round trip through fragmentation and reassembly byte-for-byte, and the
/// reassembled bytes still drive a working handshake.
#[test]
fn a_real_handshake_survives_fragmentation_and_reassembly() {
    let (a, b) = (alice(), bob());
    let (msg1, frags, key) = init_fragments(&a, &b);

    assert_eq!(msg1.len(), 3210, "spec §6.1");
    assert_eq!(frags.len(), 3, "spec §6.4 — three fragments");

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
                payload,
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
    let (msg2, _) = respond(
        &b,
        &got,
        |h, _e| (*h == a_hint).then(|| peer_of(&a)),
        &rrand(),
        2,
    )
    .unwrap();
    assert_eq!(msg2.len(), 3164, "spec §6.2");
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

/// **§13.8's correction (GitHub issue #81) — a tampered handshake fragment's
/// payload is now caught by the fragment MAC itself, before reassembly ever
/// sees it.**
///
/// This used to pass the MAC and only get caught by the AEAD once reassembled
/// — see `crates/karst-proto/src/dos.rs`'s
/// `transport_and_cookie_reply_fragments_do_not_cover_the_payload` for that
/// property, which `TransportData` and `CookieReply` still have, deliberately
/// (§13.8's cost argument holds on the high-volume transport path; it did not
/// hold for `mac2`'s address validation on the bounded handshake path, which
/// is what the adversarial reading this issue answers found). A real caller
/// (`Engine::inbound`) checks `frag_mac` before a byte reaches the
/// reassembler, so a tampered fragment like this one is now discarded right
/// there and never gets the chance to reassemble into anything the AEAD would
/// need to reject.
#[test]
fn a_tampered_handshake_fragment_is_caught_by_its_own_mac() {
    let (initiator, responder) = (alice(), bob());
    let (_msg1, frags, key) = init_fragments(&initiator, &responder);

    let mut bad = frags.first().unwrap().clone();
    if let Some(x) = bad.last_mut() {
        *x ^= 0x01;
    }
    let (hdr, tampered_payload) = split_datagram(&bad).unwrap();
    assert!(
        !verify_frag_mac(
            &key,
            MessageType::HandshakeInit as u8,
            hdr.reassembly_id,
            hdr.idx,
            hdr.count,
            tampered_payload,
            &hdr.frag_mac
        ),
        "a payload edit must now invalidate a handshake fragment's own MAC"
    );

    // Confirm it isn't merely the header that changed: the *un*-tampered
    // fragment's own header, replayed against the tampered payload, must
    // still fail — it is the payload binding doing the work, not idx/count.
    let (original_hdr, _) = split_datagram(frags.first().unwrap()).unwrap();
    assert!(
        !verify_frag_mac(
            &key,
            MessageType::HandshakeInit as u8,
            original_hdr.reassembly_id,
            original_hdr.idx,
            original_hdr.count,
            tampered_payload,
            &original_hdr.frag_mac
        ),
        "the original header's MAC must not validate a substituted payload"
    );
}

/// §9.2 — a fragment cannot be moved to another index: `idx` is under the MAC.
#[test]
fn a_fragment_cannot_be_relocated_within_the_message() {
    let (a, b) = (alice(), bob());
    let (_, frags, key) = init_fragments(&a, &b);

    let first = frags.first().unwrap();
    let (hdr, payload) = split_datagram(first).unwrap();
    // Claim it is fragment 1 rather than 0, keeping the original MAC.
    assert!(
        !verify_frag_mac(
            &key,
            MessageType::HandshakeInit as u8,
            hdr.reassembly_id,
            1,
            hdr.count,
            payload,
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
            payload2,
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
    let (msg2, _) = respond(
        &b,
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

/// Every fragment is required to complete the handshake.
#[test]
fn a_cnsa_handshake_does_not_complete_on_two_of_its_three_fragments() {
    let a = Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xA1; 64],
    ));
    let b = Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xB1; 64],
    ));
    let (_, msg1) = initiate(
        Arc::clone(&a),
        Arc::new(peer_of(&b)),
        SessionParams {
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
