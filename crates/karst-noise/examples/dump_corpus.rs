// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Emit genuine protocol messages as fuzzing seed corpus.
//!
//! Valid 3210-byte seeds let mutation reach KEM decapsulation and AEAD.
//!
//! Usage: `cargo run --example dump_corpus -- <out-dir>`

// A build-time corpus generator, not shipped code. It runs on trusted inputs
// only, so failing loudly here is correct — the workspace bans on `expect` are
// aimed at the pre-authentication paths this tool exists to exercise.
#![allow(clippy::expect_used)]

use std::io::Write;

use std::sync::Arc;

use karst_crypto::kem::KemKind;
use karst_noise::handshake::{
    initiate, InitiatorRandomness, PeerPublic, SessionParams, StaticKeys, TIMESTAMP_LEN,
};

fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    std::fs::create_dir_all(&dir)?;

    let variants: [(&str, u32, u8); 4] = [
        ("msg1-suite2-epoch7", 7, 0xE1),
        ("msg1-suite2-epoch0", 0, 0xE3),
        ("msg1-suite2-epochmax", u32::MAX, 0xE4),
        ("msg1-suite2-epoch1", 1, 0xE2),
    ];
    for (name, epoch, seed) in variants {
        let kind = KemKind::MlKem1024;
        let a = Arc::new(StaticKeys::from_seed_of_kind(kind, &[0xA1; 64]));
        let b = StaticKeys::from_seed_of_kind(kind, &[0xB1; 64]);
        let peer = PeerPublic {
            kem_pk: b.kem_pk.clone(),

            psk: [0x42; 32],
        };
        let params = SessionParams {
            psk_epoch: epoch,
            sender_index: 1,
        };
        let rand = InitiatorRandomness {
            e_kem_seed: [seed; 64],

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
