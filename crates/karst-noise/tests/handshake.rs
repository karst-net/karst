// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! End-to-end `PHREATIC` handshake — `spec/phreatic-v1.md` §6, §7.
//!
//! Two in-process peers complete a handshake and agree on transport keys.
//! This is the core of PLAN.md Phase 1's exit criterion.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use karst_noise::handshake::{
    initiate, respond, HandshakeError, InitiatorRandomness, PeerPublic, ResponderRandomness,
    SessionParams, StaticKeys, TIMESTAMP_LEN,
};

const PSK: [u8; 32] = [0x42; 32];
const EPOCH: u32 = 7;
const TS: [u8; TIMESTAMP_LEN] = [1; TIMESTAMP_LEN];

fn irand() -> InitiatorRandomness {
    InitiatorRandomness {
        e_kem_seed: [0xE1; 64],

        encap_rand: [0xE3; 32],
        timestamp: TS,
    }
}

fn rrand() -> ResponderRandomness {
    ResponderRandomness {
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}

fn params(epoch: u32) -> SessionParams {
    SessionParams {
        psk_epoch: epoch,
        sender_index: 1,
    }
}

// The handshake's two long-term inputs are shared by `Arc` rather than
// borrowed, so that a `Session` — and the engine above it — is not pinned to
// one owner for the life of the process. See `handshake::Initiator`.
fn alice() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xA1; 64]))
}
fn bob() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xB1; 64]))
}

fn peer_of(k: &StaticKeys, psk: [u8; 32]) -> PeerPublic {
    PeerPublic {
        kem_pk: k.kem_pk.clone(),

        psk,
    }
}

fn arc_peer(p: &PeerPublic) -> Arc<PeerPublic> {
    Arc::new(p.clone())
}

/// Both peers' four directional keys: initiator's send/recv, responder's
/// send/recv. They must agree pairwise.
type BothSidesKeys = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Drive a full handshake, returning both sides' keys.
fn run(
    a: &Arc<StaticKeys>,
    b: &Arc<StaticKeys>,
    psk_i: [u8; 32],
    psk_r: [u8; 32],
) -> Result<BothSidesKeys, HandshakeError> {
    let b_pub = peer_of(b, psk_i);
    let (init, msg1) = initiate(Arc::clone(a), arc_peer(&b_pub), params(EPOCH), &irand())?;

    let a_hint = a.hint();
    let (msg2, pending) = respond(
        b,
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(a, psk_r)),
        &rrand(),
        2,
    )?;

    let ik = init.finish(&msg2)?;
    let rk = pending.confirm();
    Ok((
        ik.initiator_to_responder.to_vec(),
        ik.responder_to_initiator.to_vec(),
        rk.initiator_to_responder.to_vec(),
        rk.responder_to_initiator.to_vec(),
    ))
}

// ── the headline property ───────────────────────────────────────────────────

#[test]
fn both_peers_derive_identical_transport_keys() {
    let (a, b) = (alice(), bob());
    let (i_send, i_recv, r_send, r_recv) = run(&a, &b, PSK, PSK).expect("handshake must succeed");

    assert_eq!(i_send, r_send, "initiator→responder keys must agree");
    assert_eq!(i_recv, r_recv, "responder→initiator keys must agree");
    assert_ne!(i_send, i_recv, "directions must use distinct keys");
}

/// The handshake is deterministic in its seeds, so a failure replays exactly.
#[test]
fn handshake_is_reproducible_from_seeds() {
    let (a, b) = (alice(), bob());
    let first = run(&a, &b, PSK, PSK).unwrap();
    let second = run(&a, &b, PSK, PSK).unwrap();
    assert_eq!(first, second);
}

// ── §6 wire sizes, verified against real bytes ──────────────────────────────

#[test]
fn messages_are_exactly_the_specified_sizes() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();
    assert_eq!(msg1.len(), 3210, "HandshakeInit — spec §6.1");

    let a_hint = a.hint();
    let (msg2, _) = respond(
        &b,
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
        &rrand(),
        2,
    )
    .unwrap();
    assert_eq!(msg2.len(), 3164, "HandshakeResponse — spec §6.2");

    // §6.4 invariant 1, on the bytes actually produced.
    assert!(msg1.len() > msg2.len(), "anti-amplification");
    assert_eq!(msg1.len() - msg2.len(), 46);
}

#[test]
fn message_type_bytes_are_correct() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();
    assert_eq!(msg1.first(), Some(&0x01));
}

// ── authentication and failure modes ────────────────────────────────────────

/// A mismatched PSK must break the handshake. If it did not, ADR-0004's
/// assumption-diversity hedge would be decorative.
#[test]
fn a_mismatched_psk_fails_authentication() {
    let (a, b) = (alice(), bob());
    let err = run(&a, &b, PSK, [0x99; 32]).unwrap_err();
    assert_eq!(err, HandshakeError::AuthenticationFailed);
}

/// The zero PSK is the lattice-only fallback (§7.3). It must be a *distinct*
/// key schedule, not equivalent to a real PSK.
#[test]
fn the_zero_psk_fallback_is_not_equivalent_to_a_real_psk() {
    let (a, b) = (alice(), bob());
    let with_real = run(&a, &b, PSK, PSK).unwrap();
    let with_zero = run(&a, &b, [0; 32], [0; 32]).unwrap();
    assert_ne!(with_real.0, with_zero.0, "zero PSK must change the keys");
    // Both still complete — the fallback preserves connectivity (§7.3).
    assert_eq!(with_zero.0, with_zero.2);
}

#[test]
fn an_unknown_peer_hint_is_rejected() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();
    let err = respond(
        &b,
        &msg1,
        |_, _| None, // netmap miss
        &rrand(),
        2,
    )
    .unwrap_err();
    assert_eq!(err, HandshakeError::UnknownPeer);
}

/// Every single-byte mutation of `HandshakeInit` must be rejected. This is the
/// transcript-binding property doing its job across the whole message.
#[test]
fn every_byte_of_handshake_init_is_authenticated() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();
    let a_hint = a.hint();

    // Sample across the message: header, each key field, and the AEAD blob.
    let probes = [
        0usize, 4, 8, 10, 14, 600, 1197, 1198, 1230, 1800, 2317, 2340, 2377,
    ];
    for &i in &probes {
        let mut bad = msg1.clone();
        if let Some(byte) = bad.get_mut(i) {
            *byte ^= 0x01;
        }
        let res = respond(
            &b,
            &bad,
            |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
            &rrand(),
            2,
        );
        assert!(res.is_err(), "flipping byte {i} must be detected");
    }
}

#[test]
fn truncated_and_extended_messages_are_rejected() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();
    let a_hint = a.hint();
    let lookup = |h: &[u8; 32], _e: u32| (*h == a_hint).then(|| peer_of(&a, PSK));

    let mut short = msg1.clone();
    short.pop();
    assert_eq!(
        respond(&b, &short, lookup, &rrand(), 2).unwrap_err(),
        HandshakeError::Malformed
    );

    let mut long = msg1.clone();
    long.push(0);
    assert_eq!(
        respond(&b, &long, lookup, &rrand(), 2).unwrap_err(),
        HandshakeError::Malformed,
        "trailing bytes must not be ignored"
    );
}

#[test]
fn an_unknown_suite_id_is_rejected() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, mut msg1) =
        initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();
    // Reject retired, reserved, and unallocated IDs before roster lookup,
    // even when the rest of the body is truncated.
    for id in [0x0000u16, 0x0001, 0x0003, 0x00ff, 0xffff] {
        msg1.get_mut(8..10)
            .unwrap()
            .copy_from_slice(&id.to_le_bytes());
        for body in [msg1.as_slice(), msg1.get(..14).unwrap()] {
            let err = respond(
                &b,
                body,
                |_, _| panic!("invalid suite reached roster lookup"),
                &rrand(),
                2,
            )
            .unwrap_err();
            assert_eq!(err, HandshakeError::UnsupportedSuite);
        }
    }
}

/// A third party must not be able to substitute itself for the responder.
#[test]
fn responding_with_the_wrong_static_key_fails() {
    let (a, b) = (alice(), bob());
    let mallory = StaticKeys::from_seed(&[0xC1; 64]);
    let b_pub = peer_of(&b, PSK);
    let (init, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();

    // Mallory cannot even decapsulate ct_s, which was sealed to Bob.
    let a_hint = a.hint();
    let res = respond(
        &mallory,
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
        &rrand(),
        2,
    );
    assert!(res.is_err(), "wrong responder must not complete");
    drop(init);
}

/// Distinct sessions must not share keys, even between the same peers.
#[test]
fn distinct_ephemerals_yield_distinct_sessions() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let a_hint = a.hint();

    let mut keys = Vec::new();
    for e in [0x01u8, 0x02] {
        let (init, msg1) = initiate(
            Arc::clone(&a),
            arc_peer(&b_pub),
            params(EPOCH),
            &InitiatorRandomness {
                e_kem_seed: [e; 64],

                encap_rand: [e; 32],
                timestamp: TS,
            },
        )
        .unwrap();
        let (msg2, _) = respond(
            &b,
            &msg1,
            |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
            &rrand(),
            2,
        )
        .unwrap();
        keys.push(init.finish(&msg2).unwrap().initiator_to_responder.to_vec());
    }
    assert_ne!(keys.first(), keys.get(1), "sessions must not share keys");
}

/// §7.3: epoch acceptance is the resolver's policy. Refusing an out-of-window
/// epoch must abort the handshake, not fall back to a zero PSK.
#[test]
fn an_out_of_window_psk_epoch_is_refused() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(99), &irand()).unwrap();
    let a_hint = a.hint();
    let err = respond(
        &b,
        &msg1,
        // Accept only epochs 7 and 6.
        |h, e| ((*h == a_hint) && (e == 7 || e == 6)).then(|| peer_of(&a, PSK)),
        &rrand(),
        2,
    )
    .unwrap_err();
    assert_eq!(err, HandshakeError::UnknownPeer);
}

// ── PLAN.md Phase 1 exit criterion ──────────────────────────────────────────

/// Two in-process peers complete a handshake **and exchange authenticated
/// data** in both directions. This is the headline Phase 1 criterion.
#[test]
fn two_peers_handshake_then_exchange_authenticated_data() {
    use karst_noise::transport::{Role, TransportError, TransportSession};

    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);

    // 1. Handshake.
    let (init, msg1) = initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &irand()).unwrap();
    let a_hint = a.hint();
    let (msg2, pending) = respond(
        &b,
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
        &rrand(),
        2,
    )
    .unwrap();
    let i_keys = init.finish(&msg2).unwrap();

    // 2. The responder must not treat sending msg2 as establishment (§12.6);
    //    reaching the keys requires an explicit confirm.
    let r_keys = pending.confirm();

    let i_sess = TransportSession::new(&i_keys, Role::Initiator, 2, 0);
    let r_sess = TransportSession::new(&r_keys, Role::Responder, 1, 0);

    // 3. Data, both directions, over keys neither side transmitted.
    let payload = b"the quick brown fox jumps over the lazy dog";
    let sealed = i_sess.seal(payload, 0).unwrap();
    let opened = r_sess.open(&sealed, 0).unwrap();
    assert_eq!(opened.get(..payload.len()), Some(&payload[..]));

    let reply = b"pack my box with five dozen liquor jugs";
    let sealed_r = r_sess.seal(reply, 0).unwrap();
    let opened_i = i_sess.open(&sealed_r, 0).unwrap();
    assert_eq!(opened_i.get(..reply.len()), Some(&reply[..]));

    // 4. Replay and forgery are rejected on the live session.
    assert_eq!(r_sess.open(&sealed, 0), Err(TransportError::Replay));
    let mut forged = i_sess.seal(payload, 0).unwrap();
    if let Some(x) = forged.last_mut() {
        *x ^= 0xFF;
    }
    assert_eq!(
        r_sess.open(&forged, 0),
        Err(TransportError::AuthenticationFailed)
    );
}

/// A session built from a *different* handshake must not open this one's
/// traffic — sessions are cryptographically independent.
#[test]
fn traffic_does_not_cross_between_sessions() {
    use karst_noise::transport::{Role, TransportError, TransportSession};

    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let a_hint = a.hint();

    let mut sessions = Vec::new();
    for e in [0x11u8, 0x22] {
        let rand = InitiatorRandomness {
            e_kem_seed: [e; 64],

            encap_rand: [e; 32],
            timestamp: TS,
        };
        let (init, msg1) =
            initiate(Arc::clone(&a), arc_peer(&b_pub), params(EPOCH), &rand).unwrap();
        let (msg2, pending) = respond(
            &b,
            &msg1,
            |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
            &rrand(),
            2,
        )
        .unwrap();
        let ik = init.finish(&msg2).unwrap();
        sessions.push((
            TransportSession::new(&ik, Role::Initiator, 2, 0),
            TransportSession::new(&pending.confirm(), Role::Responder, 1, 0),
        ));
    }

    let msg = sessions
        .get_mut(0)
        .map(|(i, _)| i.seal(b"session one only", 0).unwrap())
        .unwrap();
    let cross = sessions.get_mut(1).map(|(_, r)| r.open(&msg, 0)).unwrap();
    assert_eq!(cross, Err(TransportError::AuthenticationFailed));
}
