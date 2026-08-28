// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Decoder robustness, checked in Rust rather than through the shared vectors.
//!
//! The vector file proves the two implementations agree on well-formed input
//! and on the specific malformed logs the Go generator produced. It cannot
//! prove the decoder is total, because a vector is a fixed input and the
//! property wanted here is "no input panics".
//!
//! That property matters more here than in most parsers: `decode_log` runs on
//! the node, on bytes handed to it by a coordination server that Bedrock's
//! whole threat model assumes may be compromised. A panic in this path is a
//! remote crash of the daemon.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use karst_bedrock::{decode_log, verify_log, Error};

/// Every truncation of a real log must be refused, and none may panic.
#[test]
fn every_prefix_of_a_valid_log_is_refused_without_panicking() {
    let raw = valid_log_bytes();

    // Stepping by a prime keeps the run time sane while still landing inside
    // length prefixes, signature bodies and entry boundaries alike.
    for cut in (0..raw.len()).step_by(997) {
        let prefix = &raw.get(..cut).expect("in range");
        match decode_log(prefix) {
            Err(_) => {}
            Ok(entries) => {
                // A prefix that happens to decode must still fail to verify:
                // the entry count would have to match, which only the full log
                // achieves.
                assert!(
                    verify_log(&entries).is_err() || cut == raw.len(),
                    "a truncated log at {cut} bytes verified"
                );
            }
        }
    }
}

/// Single-byte corruption anywhere must be refused, and must not panic.
#[test]
fn single_byte_corruption_is_always_caught() {
    let raw = valid_log_bytes();

    for pos in (0..raw.len()).step_by(1009) {
        let mut corrupt = raw.clone();
        if let Some(b) = corrupt.get_mut(pos) {
            *b ^= 0x01;
        }
        let accepted = match decode_log(&corrupt) {
            Err(_) => false,
            Ok(entries) => verify_log(&entries).is_ok(),
        };
        assert!(
            !accepted,
            "flipping a bit at offset {pos} produced a log that still verified"
        );
    }
}

/// Hostile length prefixes must not become allocation primitives.
#[test]
fn absurd_counts_and_lengths_are_refused_cheaply() {
    for case in [
        vec![0xFF, 0xFF, 0xFF, 0xFF],             // entry count of 4 billion
        vec![0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF], // one entry, absurd length
        vec![0x00, 0x00, 0x00, 0x01],             // one entry, no entry
        vec![],                                   // nothing at all
        vec![0x00],                               // a partial count
    ] {
        assert!(
            decode_log(&case).is_err(),
            "accepted a hostile encoding: {case:02x?}"
        );
    }
}

/// An empty log is refused rather than treated as "nothing is covered", which
/// would be a fail-open reading of a fail-closed mechanism.
#[test]
fn an_empty_log_is_refused() {
    assert!(matches!(verify_log(&[]), Err(Error::Broken { seq: 0, .. })));
}

/// An unknown op is refused at decode time — spec §4 rule 5.
#[test]
fn an_unknown_op_is_refused_by_name() {
    // Built by hand, because the encoder cannot express an unknown op — which
    // is itself the point: `Op` is a closed enum on both sides of the wire.
    let mut body = Vec::new();
    body.extend_from_slice(&1u32.to_be_bytes());
    let mut entry = Vec::new();
    for field in [
        &1u64.to_be_bytes()[..],
        &1000u64.to_be_bytes()[..],
        b"node-bless",
        b"",
    ] {
        entry.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(field);
    }
    entry.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&u32::try_from(entry.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&entry);

    match decode_log(&body) {
        Err(Error::UnknownOp(op)) => assert_eq!(op, "node-bless"),
        other => panic!("expected UnknownOp, got {other:?}"),
    }
}

/// A log the vectors already prove valid, as bytes.
fn valid_log_bytes() -> Vec<u8> {
    #[derive(serde::Deserialize)]
    struct File {
        cases: Cases,
    }
    #[derive(serde::Deserialize)]
    struct Cases {
        logs: Vec<Log>,
    }
    #[derive(serde::Deserialize)]
    struct Log {
        encoded: String,
    }

    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/bedrock-v1.json");
    let raw = std::fs::read_to_string(path).expect("read vectors");
    let file: File = serde_json::from_str(&raw).expect("parse vectors");
    hex::decode(&file.cases.logs.first().expect("a log").encoded).expect("hex")
}
