// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
//! Fuzz `respond()` — the handshake parser, `spec/phreatic-v1.md` §6.1.
//!
//! This is the deepest pre-authentication surface in the system: it parses 2378
//! attacker-controlled bytes, performs ML-KEM decapsulation and X25519 on
//! attacker-supplied values, and runs an AEAD open, all before anything has been
//! authenticated. The reassembler (fuzzed separately) only ever hands it bytes;
//! this is what interprets them.
//!
//! Property: for ANY input it returns a `Result` without panicking, and never
//! produces a response for input it rejected.

use libfuzzer_sys::fuzz_target;

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karst_crypto::{SuiteId, SuitePolicy};
use karst_noise::handshake::{respond, PeerPublic, ResponderRandomness, StaticKeys};

fn responder() -> StaticKeys {
    StaticKeys::from_seed(&[0xB1; 64], &[0xB2; 32])
}
fn initiator() -> StaticKeys {
    StaticKeys::from_seed(&[0xA1; 64], &[0xA2; 32])
}

fuzz_target!(|data: &[u8]| {
    let b = responder();
    let a = initiator();
    let a_hint = a.hint();

    let policy = SuitePolicy {
        minimum: SuiteId::KARST_1,
        supported: vec![SuiteId::KARST_1, SuiteId::KARST_2],
    };
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
                kem_pk: MlKem::public_key_from_bytes(&MlKem::public_key_bytes(&a.kem_pk))
                    .expect("round-trips"),
                dh_pk: a.dh_pk,
                psk: [0x42; 32],
            })
        },
        &rand,
        2,
    );

    if let Ok((msg2, _pending)) = result {
        // A response may only ever be produced for a well-formed, authenticated
        // HandshakeInit — and must obey the §6.4 anti-amplification invariant.
        assert_eq!(msg2.len(), 2236, "response must be exactly the spec size");
        assert!(
            msg2.len() < data.len(),
            "emitted {} B for {} B received — anti-amplification violated",
            msg2.len(),
            data.len()
        );
    }
});
