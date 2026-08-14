// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Emit genuine protocol messages as fuzzing seed corpus.
//!
//! Without this, `handshake_respond` is close to useless: random mutation will
//! never produce a structurally valid 2378-byte `HandshakeInit`, so the fuzzer
//! stalls at the length check having explored nothing. Seeding it with real
//! messages lets mutation start from a valid shape and actually reach the
//! decapsulation, DH and AEAD paths.
//!
//! Usage: `cargo run --example dump_corpus -- <out-dir>`

// A build-time corpus generator, not shipped code. It runs on trusted inputs
// only, so failing loudly here is correct — the workspace bans on `expect` are
// aimed at the pre-authentication paths this tool exists to exercise.
#![allow(clippy::expect_used)]

use std::io::Write;

use std::sync::Arc;

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karst_crypto::SuiteId;
use karst_noise::handshake::{
    initiate, InitiatorRandomness, PeerPublic, SessionParams, StaticKeys, TIMESTAMP_LEN,
};

fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    std::fs::create_dir_all(&dir)?;

    let a = Arc::new(StaticKeys::from_seed(&[0xA1; 64], &[0xA2; 32]));
    let b = StaticKeys::from_seed(&[0xB1; 64], &[0xB2; 32]);

    // Several seeds, varying the fields a fuzzer would struggle to guess.
    let variants: [(&str, SuiteId, u32, u8); 4] = [
        ("msg1-suite1-epoch7", SuiteId::KARST_1, 7, 0xE1),
        ("msg1-suite2-epoch7", SuiteId::KARST_2, 7, 0xE2),
        ("msg1-suite1-epoch0", SuiteId::KARST_1, 0, 0xE3),
        ("msg1-suite1-epochmax", SuiteId::KARST_1, u32::MAX, 0xE4),
    ];

    for (name, suite, epoch, seed) in variants {
        let peer = PeerPublic {
            kem_pk: MlKem::public_key_from_bytes(&MlKem::public_key_bytes(&b.kem_pk))
                .expect("round-trips"),
            dh_pk: b.dh_pk,
            psk: [0x42; 32],
        };
        let params = SessionParams {
            suite,
            psk_epoch: epoch,
            sender_index: 1,
        };
        let rand = InitiatorRandomness {
            e_kem_seed: [seed; 64],
            e_dh_seed: [seed; 32],
            encap_rand: [seed; 32],
            timestamp: [1; TIMESTAMP_LEN],
        };
        let (_, msg1) =
            initiate(Arc::clone(&a), Arc::new(peer), params, &rand).expect("valid parameters");
        let path = format!("{dir}/{name}.bin");
        std::fs::File::create(&path)?.write_all(&msg1)?;
        println!("{} ({} bytes)", path, msg1.len());
    }
    Ok(())
}
