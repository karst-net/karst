// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! End-to-end `PHREATIC` handshake — `spec/phreatic-v1.md` §6, §7.
//!
//! Two in-process peers complete a handshake and agree on transport keys.
//! This is the core of PLAN.md Phase 1's exit criterion.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use karst_crypto::kem::KemKind;
use karst_crypto::{SuiteId, SuitePolicy};
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
        e_dh_seed: [0xE2; 32],
        encap_rand: [0xE3; 32],
        timestamp: TS,
    }
}

fn rrand() -> ResponderRandomness {
    ResponderRandomness {
        e_dh_seed: [0xF1; 32],
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}

fn params(suite: SuiteId, epoch: u32) -> SessionParams {
    SessionParams {
        suite,
        psk_epoch: epoch,
        sender_index: 1,
    }
}

/// A policy that refuses nothing, so the tests below exercise the handshake
/// rather than the floor. A real node's `supported` list is constrained by the
/// parameter set of its static key — see `Engine::new`.
fn open_policy() -> SuitePolicy {
    SuitePolicy {
        minimum: SuiteId::KARST_1,
        supported: vec![SuiteId::KARST_1, SuiteId::KARST_2, SuiteId::KARST_2],
    }
}

// The handshake's two long-term inputs are shared by `Arc` rather than
// borrowed, so that a `Session` — and the engine above it — is not pinned to
// one owner for the life of the process. See `handshake::Initiator`.
fn alice() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xA1; 64], &[0xA2; 32]))
}
fn bob() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[0xB1; 64], &[0xB2; 32]))
}

/// The same two nodes under the CNSA 2.0 profile: same seeds, ML-KEM-1024
/// static keys, and therefore different identities.
fn alice_cnsa() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xA1; 64],
        &[0xA2; 32],
    ))
}
fn bob_cnsa() -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed_of_kind(
        KemKind::MlKem1024,
        &[0xB1; 64],
        &[0xB2; 32],
    ))
}

fn peer_of(k: &StaticKeys, psk: [u8; 32]) -> PeerPublic {
    PeerPublic {
        kem_pk: k.kem_pk.clone(),
        dh_pk: k.dh_pk,
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
    suite: SuiteId,
) -> Result<BothSidesKeys, HandshakeError> {
    let b_pub = peer_of(b, psk_i);
    let (init, msg1) = initiate(
        Arc::clone(a),
        arc_peer(&b_pub),
        params(suite, EPOCH),
        &irand(),
    )?;

    let a_hint = a.hint();
    let (msg2, pending, _) = respond(
        b,
        &open_policy(),
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
    let (i_send, i_recv, r_send, r_recv) =
        run(&a, &b, PSK, PSK, SuiteId::KARST_1).expect("handshake must succeed");

    assert_eq!(i_send, r_send, "initiator→responder keys must agree");
    assert_eq!(i_recv, r_recv, "responder→initiator keys must agree");
    assert_ne!(i_send, i_recv, "directions must use distinct keys");
}

/// The handshake is deterministic in its seeds, so a failure replays exactly.
#[test]
fn handshake_is_reproducible_from_seeds() {
    let (a, b) = (alice(), bob());
    let first = run(&a, &b, PSK, PSK, SuiteId::KARST_1).unwrap();
    let second = run(&a, &b, PSK, PSK, SuiteId::KARST_1).unwrap();
    assert_eq!(first, second);
}

// ── §6 wire sizes, verified against real bytes ──────────────────────────────

#[test]
fn messages_are_exactly_the_specified_sizes() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
    assert_eq!(msg1.len(), 2378, "HandshakeInit — spec §6.1");

    let a_hint = a.hint();
    let (msg2, _, _) = respond(
        &b,
        &open_policy(),
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
        &rrand(),
        2,
    )
    .unwrap();
    assert_eq!(msg2.len(), 2236, "HandshakeResponse — spec §6.2");

    // §6.4 invariant 1, on the bytes actually produced.
    assert!(msg1.len() > msg2.len(), "anti-amplification");
    assert_eq!(msg1.len() - msg2.len(), 142);
}

#[test]
fn message_type_bytes_are_correct() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
    assert_eq!(msg1.first(), Some(&0x01));
}

// ── authentication and failure modes ────────────────────────────────────────

/// A mismatched PSK must break the handshake. If it did not, ADR-0004's
/// assumption-diversity hedge would be decorative.
#[test]
fn a_mismatched_psk_fails_authentication() {
    let (a, b) = (alice(), bob());
    let err = run(&a, &b, PSK, [0x99; 32], SuiteId::KARST_1).unwrap_err();
    assert_eq!(err, HandshakeError::AuthenticationFailed);
}

/// The zero PSK is the lattice-only fallback (§7.3). It must be a *distinct*
/// key schedule, not equivalent to a real PSK.
#[test]
fn the_zero_psk_fallback_is_not_equivalent_to_a_real_psk() {
    let (a, b) = (alice(), bob());
    let with_real = run(&a, &b, PSK, PSK, SuiteId::KARST_1).unwrap();
    let with_zero = run(&a, &b, [0; 32], [0; 32], SuiteId::KARST_1).unwrap();
    assert_ne!(with_real.0, with_zero.0, "zero PSK must change the keys");
    // Both still complete — the fallback preserves connectivity (§7.3).
    assert_eq!(with_zero.0, with_zero.2);
}

#[test]
fn an_unknown_peer_hint_is_rejected() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
    let err = respond(
        &b,
        &open_policy(),
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
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
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
            &open_policy(),
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
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
    let a_hint = a.hint();
    let lookup = |h: &[u8; 32], _e: u32| (*h == a_hint).then(|| peer_of(&a, PSK));

    let mut short = msg1.clone();
    short.pop();
    assert_eq!(
        respond(&b, &open_policy(), &short, lookup, &rrand(), 2).unwrap_err(),
        HandshakeError::Malformed
    );

    let mut long = msg1.clone();
    long.push(0);
    assert_eq!(
        respond(&b, &open_policy(), &long, lookup, &rrand(), 2).unwrap_err(),
        HandshakeError::Malformed,
        "trailing bytes must not be ignored"
    );
}

#[test]
fn an_unknown_suite_id_is_rejected() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, mut msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
    // suite_id lives at offset 8.
    if let Some(s) = msg1.get_mut(8..10) {
        s.copy_from_slice(&0x00FFu16.to_le_bytes());
    }
    let a_hint = a.hint();
    let err = respond(
        &b,
        &open_policy(),
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
        &rrand(),
        2,
    )
    .unwrap_err();
    assert_eq!(err, HandshakeError::UnsupportedSuite);
}

/// A third party must not be able to substitute itself for the responder.
#[test]
fn responding_with_the_wrong_static_key_fails() {
    let (a, b) = (alice(), bob());
    let mallory = StaticKeys::from_seed(&[0xC1; 64], &[0xC2; 32]);
    let b_pub = peer_of(&b, PSK);
    let (init, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();

    // Mallory cannot even decapsulate ct_s, which was sealed to Bob.
    let a_hint = a.hint();
    let res = respond(
        &mallory,
        &open_policy(),
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
            params(SuiteId::KARST_1, EPOCH),
            &InitiatorRandomness {
                e_kem_seed: [e; 64],
                e_dh_seed: [e; 32],
                encap_rand: [e; 32],
                timestamp: TS,
            },
        )
        .unwrap();
        let (msg2, _, _) = respond(
            &b,
            &open_policy(),
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

/// ADR-0006: the minimum-suite floor is enforced **at the node**. A peer
/// offering a suite below it gets no session, and no weaker fallback.
#[test]
fn a_suite_below_the_local_floor_is_refused() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
    let strict = SuitePolicy {
        minimum: SuiteId::KARST_2,
        supported: vec![SuiteId::KARST_2],
    };
    let a_hint = a.hint();
    let err = respond(
        &b,
        &strict,
        &msg1,
        |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
        &rrand(),
        2,
    )
    .unwrap_err();
    assert_eq!(err, HandshakeError::UnsupportedSuite);
}

/// §7.3: epoch acceptance is the resolver's policy. Refusing an out-of-window
/// epoch must abort the handshake, not fall back to a zero PSK.
#[test]
fn an_out_of_window_psk_epoch_is_refused() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, 99),
        &irand(),
    )
    .unwrap();
    let a_hint = a.hint();
    let err = respond(
        &b,
        &open_policy(),
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
    let (init, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .unwrap();
    let a_hint = a.hint();
    let (msg2, pending, _) = respond(
        &b,
        &open_policy(),
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

    let i_sess = TransportSession::for_suite(&i_keys, Role::Initiator, 2, 0, SuiteId::KARST_1);
    let r_sess = TransportSession::for_suite(&r_keys, Role::Responder, 1, 0, SuiteId::KARST_1);

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
            e_dh_seed: [e; 32],
            encap_rand: [e; 32],
            timestamp: TS,
        };
        let (init, msg1) = initiate(
            Arc::clone(&a),
            arc_peer(&b_pub),
            params(SuiteId::KARST_1, EPOCH),
            &rand,
        )
        .unwrap();
        let (msg2, pending, _) = respond(
            &b,
            &open_policy(),
            &msg1,
            |h, _e| (*h == a_hint).then(|| peer_of(&a, PSK)),
            &rrand(),
            2,
        )
        .unwrap();
        let ik = init.finish(&msg2).unwrap();
        sessions.push((
            TransportSession::for_suite(&ik, Role::Initiator, 2, 0, SuiteId::KARST_1),
            TransportSession::for_suite(
                &pending.confirm(),
                Role::Responder,
                1,
                0,
                SuiteId::KARST_1,
            ),
        ));
    }

    let msg = sessions
        .get_mut(0)
        .map(|(i, _)| i.seal(b"session one only", 0).unwrap())
        .unwrap();
    let cross = sessions.get_mut(1).map(|(_, r)| r.open(&msg, 0)).unwrap();
    assert_eq!(cross, Err(TransportError::AuthenticationFailed));
}

// ── the AEAD follows the suite ──────────────────────────────────────────────

/// **Every suite must run the AEAD its registry row names.**
///
/// AES-256-GCM was in the registry for a long time with nothing behind it:
/// `karst-noise` hardcoded ChaCha20-Poly1305 for every suite, so a session
/// could report AES-256-GCM while running something else (FINDINGS 53).
///
/// ADR-0015 item 7 then removed ChaCha20-Poly1305 altogether, which leaves one
/// AEAD and so nothing to *distinguish* — the old form of this test sealed the
/// same plaintext under each suite and asserted the ciphertexts differed, and
/// today they would not. What survives, and is the part that was ever
/// load-bearing, is that the selector's answer matches the row's own claim.
#[test]
fn every_suite_runs_the_aead_its_row_names() {
    use karst_crypto::aead::Algorithm;

    for suite in [SuiteId::KARST_1, SuiteId::KARST_2] {
        let row = suite.params();
        assert_eq!(
            Algorithm::for_suite(suite).name(),
            row.aead,
            "{}: row names {} and the selector chose otherwise",
            row.name,
            row.aead
        );
        assert_eq!(
            row.aead, "AES-256-GCM",
            "{}: no suite may name ChaCha",
            row.name
        );
    }
}

/// A full handshake under each suite, with both sides agreeing on the keys.
///
/// The suite is bound into the transcript before any secret material (§13.2),
/// so if the two ends disagreed about either algorithm the transcript would
/// diverge and the keys would not match. Each profile gets its own key class,
/// because a node's static key fixes which suite it can serve.
#[test]
fn each_suite_handshakes_and_agrees_on_both_sides() {
    for (suite, a, b) in [
        (SuiteId::KARST_1, alice(), bob()),
        (SuiteId::KARST_2, alice_cnsa(), bob_cnsa()),
    ] {
        let (i_send, i_recv, r_send, r_recv) =
            run(&a, &b, [0x77; 32], [0x77; 32], suite).expect("handshake");
        assert_eq!(
            i_send, r_send,
            "{suite:?}: initiator-to-responder disagrees"
        );
        assert_eq!(
            i_recv, r_recv,
            "{suite:?}: responder-to-initiator disagrees"
        );
    }
}

/// **Two suites' transports must not open each other's traffic.** With one AEAD
/// in the registry this no longer rests on the cipher, so it rests on the keys
/// — which is the stronger place for it to rest. The two suites hash
/// differently, so identical handshake inputs still produce different transport
/// keys (`symmetric::tests::the_two_suites_derive_different_keys_...`), and
/// here that separation is checked end to end on sealed traffic.
#[test]
fn a_transport_built_for_one_suite_cannot_open_the_others() {
    use karst_noise::transport::{Role, TransportSession};

    let (one, _, _, _) =
        run(&alice(), &bob(), [0x77; 32], [0x77; 32], SuiteId::KARST_1).expect("KARST_1 handshake");
    let (two, _, _, _) = run(
        &alice_cnsa(),
        &bob_cnsa(),
        [0x77; 32],
        [0x77; 32],
        SuiteId::KARST_2,
    )
    .expect("CNSA handshake");
    assert_ne!(one, two, "the two suites must not derive the same key");

    let mk = |bytes: &[u8], role, index, suite| {
        let mut keys = karst_noise::symmetric::TransportKeys {
            initiator_to_responder: [0u8; 32],
            responder_to_initiator: [0u8; 32],
        };
        keys.initiator_to_responder.copy_from_slice(bytes);
        keys.responder_to_initiator.copy_from_slice(bytes);
        TransportSession::for_suite(&keys, role, index, 0, suite)
    };

    let sender = mk(&one, Role::Initiator, 1, SuiteId::KARST_1);
    let other = mk(&two, Role::Responder, 2, SuiteId::KARST_2);
    let sealed = sender.seal(b"payload", 0).expect("seal");
    assert!(
        other.open(&sealed, 0).is_err(),
        "a CNSA transport opened a KARST_1 message, so the suite separates nothing"
    );
}

// ── KARST_2, the CNSA 2.0 profile (ADR-0015 item 1) ─────────────────────────

/// **The headline of item 1.** Two Category 5 nodes complete a handshake and
/// agree, over ML-KEM-1024, AES-256-GCM and SHA-384, with no X25519 anywhere in
/// the schedule. Until this passed, `KARST_2` was a registry row.
#[test]
fn a_cnsa_handshake_agrees_on_both_sides() {
    let (a, b) = (alice_cnsa(), bob_cnsa());
    let (i_send, i_recv, r_send, r_recv) =
        run(&a, &b, PSK, PSK, SuiteId::KARST_2).expect("KARST_2 handshake must succeed");
    assert_eq!(i_send, r_send, "initiator-to-responder disagrees");
    assert_eq!(i_recv, r_recv, "responder-to-initiator disagrees");
    assert_ne!(i_send, i_recv, "directions must use distinct keys");
}

/// The messages must be the sizes §6.5 tabulates — 3 210 and 3 164 — because
/// those are the numbers the three-fragment budget and the anti-amplification
/// margin were computed from. A message that came out the size of `KARST_1`
/// would mean the X25519 fields were still being written.
#[test]
fn cnsa_messages_are_the_sizes_the_spec_computes() {
    for suite in [SuiteId::KARST_1, SuiteId::KARST_2, SuiteId::KARST_2] {
        let expected = suite.params().message_sizes();
        let node = if suite == SuiteId::KARST_2 {
            alice_cnsa()
        } else {
            alice()
        };
        let peer = if suite == SuiteId::KARST_2 {
            bob_cnsa()
        } else {
            bob()
        };

        let b_pub = peer_of(&peer, PSK);
        let (_, msg1) = initiate(
            Arc::clone(&node),
            arc_peer(&b_pub),
            params(suite, EPOCH),
            &irand(),
        )
        .expect("initiate");
        assert_eq!(
            msg1.len(),
            expected.handshake_init,
            "{suite:?}: HandshakeInit"
        );

        let a_hint = node.hint();
        let (msg2, _, agreed) = respond(
            &peer,
            &open_policy(),
            &msg1,
            |h, _e| (*h == a_hint).then(|| peer_of(&node, PSK)),
            &rrand(),
            2,
        )
        .expect("respond");
        assert_eq!(agreed, suite, "the responder must report what it agreed to");
        assert_eq!(
            msg2.len(),
            expected.handshake_response,
            "{suite:?}: HandshakeResponse"
        );
        assert!(
            msg1.len() > msg2.len(),
            "{suite:?}: anti-amplification (§6.4 invariant 1)"
        );
    }
}

/// `KARST_2` carries no X25519, so a node's static DH key must not reach the
/// key schedule. Changing it and getting the same transport keys is the only
/// direct way to assert that; under `KARST_1` the same change must flip them,
/// which is what makes this a test of the suite rather than of nothing.
#[test]
fn the_x25519_keys_do_not_reach_a_cnsa_session() {
    let derive = |suite: SuiteId, dh: u8| {
        let kind = if suite == SuiteId::KARST_2 {
            KemKind::MlKem1024
        } else {
            KemKind::MlKem768
        };
        let a = Arc::new(StaticKeys::from_seed_of_kind(kind, &[0xA1; 64], &[dh; 32]));
        let b = Arc::new(StaticKeys::from_seed_of_kind(kind, &[0xB1; 64], &[dh; 32]));
        run(&a, &b, PSK, PSK, suite).expect("handshake").0
    };

    assert_eq!(
        derive(SuiteId::KARST_2, 0x01),
        derive(SuiteId::KARST_2, 0x02),
        "a KARST_2 session must not depend on the static X25519 keys"
    );
    assert_ne!(
        derive(SuiteId::KARST_1, 0x01),
        derive(SuiteId::KARST_1, 0x02),
        "a KARST_1 session must depend on them, or the check above proves nothing"
    );
}

/// **A Category 3 node and a Category 5 node do not interoperate.** That is
/// what a mandate means, and the refusal has to be an honest error rather than
/// a decapsulation failure five steps later. Both directions, and both the
/// node's own key and the peer's roster entry.
#[test]
fn a_node_refuses_a_suite_its_static_key_cannot_serve() {
    let (a3, b3) = (alice(), bob());
    let (a5, b5) = (alice_cnsa(), bob_cnsa());

    // A Category 3 node asked to initiate the CNSA suite, and the reverse.
    assert_eq!(
        run(&a3, &b3, PSK, PSK, SuiteId::KARST_2),
        Err(HandshakeError::UnsupportedSuite)
    );
    assert_eq!(
        run(&a5, &b5, PSK, PSK, SuiteId::KARST_1),
        Err(HandshakeError::UnsupportedSuite)
    );

    // Mixed: the initiator is Category 5 and the peer's netmap entry is not.
    let mismatched = peer_of(&b3, PSK);
    assert_eq!(
        initiate(
            Arc::clone(&a5),
            arc_peer(&mismatched),
            params(SuiteId::KARST_2, EPOCH),
            &irand(),
        )
        .err(),
        Some(HandshakeError::UnsupportedSuite),
        "a KARST_2 session to a peer holding a Category 3 key"
    );
}

/// A responder resolving a peer whose roster entry is the wrong category must
/// refuse rather than encapsulate to it — that would produce a `ct_ss` the
/// initiator cannot decapsulate and a tag failure nobody could explain.
#[test]
fn a_responder_refuses_a_roster_entry_of_the_wrong_category() {
    let (a, b) = (alice_cnsa(), bob_cnsa());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_2, EPOCH),
        &irand(),
    )
    .expect("initiate");

    // The lookup returns the *Category 3* Alice, whose hint differs — so first
    // confirm the hint really is different, then answer with her anyway.
    let wrong = alice();
    assert_ne!(
        a.hint(),
        wrong.hint(),
        "the two profiles are two identities"
    );

    let err = respond(
        &b,
        &open_policy(),
        &msg1,
        |_h, _e| Some(peer_of(&wrong, PSK)),
        &rrand(),
        2,
    )
    .expect_err("a Category 3 roster entry under the CNSA suite");
    assert_eq!(err, HandshakeError::UnsupportedSuite);
}

/// A `KARST_2` node whose floor is `KARST_2` refuses `KARST_1` before it reads
/// a single length-dependent field. The floor is the node's, not the peer's
/// (ADR-0006), so this is the same refusal whichever suite the sender preferred.
#[test]
fn the_floor_refuses_a_weaker_suite_before_parsing_it() {
    let (a, b) = (alice(), bob());
    let b_pub = peer_of(&b, PSK);
    let (_, msg1) = initiate(
        Arc::clone(&a),
        arc_peer(&b_pub),
        params(SuiteId::KARST_1, EPOCH),
        &irand(),
    )
    .expect("initiate");

    let cnsa_only = SuitePolicy {
        minimum: SuiteId::KARST_2,
        supported: vec![SuiteId::KARST_2],
    };
    let err = respond(
        &bob_cnsa(),
        &cnsa_only,
        &msg1,
        |_h, _e| Some(peer_of(&a, PSK)),
        &rrand(),
        2,
    )
    .expect_err("KARST_1 under a CNSA floor");
    assert_eq!(err, HandshakeError::UnsupportedSuite);
}
