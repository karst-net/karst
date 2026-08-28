// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
//! Fuzz `respond()` — the handshake parser, `spec/phreatic-v1.md` §6.1.
//!
//! This is the deepest pre-authentication surface in the system: it parses
//! thousands of attacker-controlled bytes, performs ML-KEM decapsulation and
//! X25519 on attacker-supplied values, and runs an AEAD open, all before
//! anything has been authenticated. The reassembler (fuzzed separately) only
//! ever hands it bytes; this is what interprets them.
//!
//! **Both profiles are driven from one input** (ADR-0015 item 1). The same
//! bytes go to a Category 3 responder and a Category 5 one, because the two
//! read the datagram at different field lengths and have different code paths
//! after the header — the CNSA responder expects 1568-byte keys and no
//! `e_dh_pk` at all. Fuzzing only the default profile would leave the entire
//! no-X25519 branch unexercised.
//!
//! Property: for ANY input each returns a `Result` without panicking, never
//! produces a response for input it rejected, and never emits more bytes than
//! it received.

use libfuzzer_sys::fuzz_target;

use karst_crypto::kem::KemKind;
use karst_crypto::{Profile, SuiteId};
use karst_noise::handshake::{respond, PeerPublic, ResponderRandomness, StaticKeys};

fn pair(kind: KemKind) -> (StaticKeys, StaticKeys) {
    (
        StaticKeys::from_seed_of_kind(kind, &[0xB1; 64], &[0xB2; 32]),
        StaticKeys::from_seed_of_kind(kind, &[0xA1; 64], &[0xA2; 32]),
    )
}

fn drive(kind: KemKind, data: &[u8]) {
    let (b, a) = pair(kind);
    let a_hint = a.hint();
    let policy = Profile::for_kem(kind).policy();
    let rand = ResponderRandomness {
        e_dh_seed: [0xF1; 32],
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    };

    let result = respond(
        &b,
        &policy,
        data,
        |h, _epoch| {
            (*h == a_hint).then(|| PeerPublic {
                kem_pk: a.kem_pk.clone(),
                dh_pk: a.dh_pk,
                psk: [0x42; 32],
            })
        },
        &rand,
        2,
    );

    if let Ok((msg2, _pending, suite)) = result {
        // A response may only ever be produced for a well-formed,
        // authenticated HandshakeInit — at the size that suite implies, and
        // obeying the §6.4 anti-amplification invariant.
        assert_eq!(
            msg2.len(),
            suite.params().message_sizes().handshake_response,
            "response must be exactly the size the agreed suite implies"
        );
        assert!(
            msg2.len() < data.len(),
            "emitted {} B for {} B received — anti-amplification violated",
            msg2.len(),
            data.len()
        );
        // A responder may never agree to a suite its own static key cannot
        // serve; that is what keeps one node from having two identities.
        assert_eq!(KemKind::for_suite(suite), kind);
        assert!(suite == SuiteId::KARST_2 || kind == KemKind::MlKem768);
    }
}

fuzz_target!(|data: &[u8]| {
    drive(KemKind::MlKem768, data);
    drive(KemKind::MlKem1024, data);
});
