// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
//! Fuzz `respond()` — the handshake parser, `spec/phreatic-v1.md` §6.1.
//!
//! Any input must return without panicking. A successful response must have
//! the fixed CNSA 2.0 shape and must not exceed the received message length.

use libfuzzer_sys::fuzz_target;

use karst_crypto::kem::KemKind;
use karst_crypto::message_sizes;
use karst_noise::handshake::{respond, PeerPublic, ResponderRandomness, StaticKeys};

fn pair(kind: KemKind) -> (StaticKeys, StaticKeys) {
    (
        StaticKeys::from_seed_of_kind(kind, &[0xB1; 64]),
        StaticKeys::from_seed_of_kind(kind, &[0xA1; 64]),
    )
}

fn drive(kind: KemKind, data: &[u8]) {
    let (b, a) = pair(kind);
    let a_hint = a.hint();
    let rand = ResponderRandomness {
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    };

    let result = respond(
        &b,
        data,
        |h, _epoch| {
            (*h == a_hint).then(|| PeerPublic {
                kem_pk: a.kem_pk.clone(),
                psk: [0x42; 32],
            })
        },
        &rand,
        2,
    );

    if let Ok((msg2, _pending)) = result {
        // A response may only ever be produced for a well-formed,
        // decryptable HandshakeInit — at the fixed wire size, and
        // obeying the §6.4 anti-amplification invariant.
        assert_eq!(
            msg2.len(),
            message_sizes().handshake_response,
            "response must be exactly the fixed CNSA response size"
        );
        assert!(
            msg2.len() < data.len(),
            "emitted {} B for {} B received — anti-amplification violated",
            msg2.len(),
            data.len()
        );
    }
}

fuzz_target!(|data: &[u8]| {
    drive(KemKind::MlKem1024, data);
});
