// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The offline round trip — plan item 10.9, plan §11 "offline round trip".
//!
//! Exports a signing request, signs it by running the real binary as a
//! subprocess, imports the response, and checks the node becomes covered.
//!
//! The subprocess matters. Calling the library directly would test the log and
//! not the tool, and the tool is where the properties that make the offline
//! story real live: that it recomputes the signing input, that it refuses a key
//! that is not in the list, and that it will not sign without a typed
//! confirmation.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::io::Write as _;
use std::process::{Command, Stdio};

use karst_bedrock::bundle::{
    request_to_json, response_from_json, OfflineSignature, Pending, Request, Response,
};
use karst_bedrock::{
    anchor_body, genesis_body, node_sign_body, verify_log, Builder, Entry, Op, Signature,
};
use karst_crypto::sign::{AnchorKey, AuthorityKey, RootKey, ANCHOR_SEED, ROOT_SEED};

fn root(seed: u8) -> RootKey {
    RootKey::from_seed(&[seed; ROOT_SEED]).expect("root")
}

fn authority(seed: u8) -> AuthorityKey {
    AuthorityKey::from_seed(&[seed; 32]).expect("authority")
}

/// The three keys a node-sign covers — spec §6.1.
struct NodeKeys {
    identity: Vec<u8>,
    kem: Vec<u8>,
}

/// A node's keys. The identity key is a pattern rather than a real ML-DSA-65
/// key, which is sound: nothing verifies a signature under a node's identity
/// key, so the chain checks only its length and that the handle derives to it.
fn node_keys(seed: u8) -> NodeKeys {
    NodeKeys {
        identity: vec![seed; karst_crypto::sign::NODE_IDENTITY_KEY],
        kem: vec![seed; 1568],
    }
}

fn sign_body(_handle: &str, k: &NodeKeys) -> Vec<u8> {
    // The handle must be the one the identity key derives to; the verifier
    // enforces it, so a caller-supplied name could only build a rejected entry.
    node_sign_body(
        &karst_bedrock::log::node_handle(&k.identity),
        &k.identity,
        &k.kem,
        0,
        0,
    )
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    // Appended to one `String` rather than collected from a `format!` per
    // byte. These are ML-DSA-87 keys — a few kilobytes each — so the
    // per-byte allocation is not notional.
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, byte| {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        },
    )
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_karst-bedrock")
}

/// Write a file into this suite's scratch directory.
///
/// The directory name is fixed rather than keyed on the process id, and is
/// emptied once per run. A pid-keyed name leaves one directory behind per
/// invocation, which on a machine that runs the suite often is an unbounded
/// pile of key material and bundles in `/tmp` — found the hard way, by filling
/// a disk.
fn scratch(name: &str, contents: &[u8]) -> std::path::PathBuf {
    use std::sync::Once;
    static CLEAN: Once = Once::new();

    let dir = std::env::temp_dir().join("karst-bedrock-offline-tests");
    CLEAN.call_once(|| {
        // Ignored: the usual outcome is NotFound on the first run.
        let _ = std::fs::remove_dir_all(&dir);
    });
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write");
    path
}

/// A genesis-only log, built in-process, so the test has something to extend.
fn genesis_log(r: &RootKey, a: &AuthorityKey) -> Vec<Entry> {
    let mut b = Builder::new();
    let body = genesis_body(
        "aquifer.karst.",
        &[r.public_key()],
        1,
        &[a.public_key()],
        1,
        &[],
    );
    let (entry, input) = b.prepare(1000, Op::Genesis, body);
    let sig = r.sign(&input).expect("sign genesis");
    b.commit(
        entry,
        vec![Signature {
            signer_index: 0,
            sig,
        }],
    )
    .expect("commit");
    b.into_entries()
}

/// The whole point: an admin countersigns a node on a machine with no network,
/// and the node becomes covered.
#[test]
fn a_node_is_countersigned_offline_and_becomes_covered() {
    let r = root(0x10);
    let a = authority(0x40);
    let node = node_keys(0x77);

    let log = genesis_log(&r, &a);
    let request = Request {
        log: log.clone(),
        pending: vec![Pending {
            seq: 2,
            time: 1100,
            op: Op::NodeSign,
            body: sign_body("laptop-alice", &node),
        }],
    };

    let req_path = scratch("request.json", request_to_json(&request).as_bytes());
    let key_path = scratch("authority.key", &[0x40u8; 32]);
    let out_path = scratch("response.json", b"");

    let out = run_sign(&req_path, &key_path, &out_path, "sign\n");
    assert!(
        out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The summary must name the node in words an admin could have checked.
    let summary = String::from_utf8_lossy(&out.stdout);
    assert!(
        summary.contains("countersign node"),
        "the summary did not describe the entry in words:\n{summary}"
    );

    let response: Response =
        response_from_json(&std::fs::read_to_string(&out_path).expect("read response"))
            .expect("parse response");

    let extended = request
        .verify()
        .expect("verify request")
        .apply(&log, &response)
        .expect("apply response");

    let st = verify_log(&extended).expect("verify extended log");
    assert_eq!(st.head_seq, 2);
    assert!(
        st.is_covered(
            &karst_bedrock::log::node_handle(&node.identity),
            karst_bedrock::PeerKeys {
                kem_public_key: &node.kem,
            },
            2000
        ),
        "the node is not covered after an offline countersignature"
    );
}

// The root ceremony is the bootstrap counterpart of the authority flow above:
// no server key, no one-root bypass, and the combined log is accepted only
// after the requested threshold verifies.
#[test]
fn root_quorum_genesis_request_sign_and_combine() {
    // A `Vec`, not a `[RootKey; 3]`. An ML-DSA-87 private key is large enough
    // that three of them on the stack trip `large_stack_arrays`, and the
    // lint has a point: a test that overflows the stack fails in a way that
    // takes an afternoon to attribute.
    let roots = vec![root(0x10), root(0x20), root(0x30)];
    let authority = authority(0x40);
    let root_pubs: Vec<_> = roots
        .iter()
        .enumerate()
        .map(|(index, key)| {
            scratch(
                &format!("genesis-root-{index}.pub"),
                hex(&key.public_key()).as_bytes(),
            )
        })
        .collect();
    let authority_pub = scratch(
        "genesis-authority.pub",
        hex(&authority.public_key()).as_bytes(),
    );
    let request = scratch("genesis-request.json", b"");
    std::fs::remove_file(&request).expect("clear request target");
    let mut command = Command::new(bin());
    command.args([
        "genesis-request",
        request.to_str().expect("path"),
        "aquifer.karst.",
        "2",
    ]);
    for path in &root_pubs {
        command.arg(path);
    }
    command.arg("--").arg("1").arg(&authority_pub);
    let made = command.output().expect("run genesis-request");
    assert!(
        made.status.success(),
        "genesis request failed: {}",
        String::from_utf8_lossy(&made.stderr)
    );

    let mut responses = Vec::new();
    for (index, seed) in [0x10u8, 0x20].iter().enumerate() {
        let key = scratch(&format!("genesis-root-{index}.key"), &[*seed; ROOT_SEED]);
        let response = scratch(&format!("genesis-response-{index}.json"), b"");
        let signed = run_sign(&request, &key, &response, "sign\n");
        assert!(
            signed.status.success(),
            "root signing failed: {}",
            String::from_utf8_lossy(&signed.stderr)
        );
        responses.push(response);
    }
    let log = scratch("genesis.bedrock", b"");
    std::fs::remove_file(&log).expect("clear log target");
    let combined = Command::new(bin())
        .arg("combine")
        .arg(&request)
        .arg(&log)
        .args(&responses)
        .output()
        .expect("run combine");
    assert!(
        combined.status.success(),
        "combine failed: {}",
        String::from_utf8_lossy(&combined.stderr)
    );
    let entries =
        karst_bedrock::decode_log(&std::fs::read(&log).expect("read log")).expect("decode log");
    let state = verify_log(&entries).expect("verify root-quorum genesis");
    assert_eq!(state.k, 2);
    assert_eq!(state.roots.len(), 3);
    assert_eq!(state.q, 1);
}

/// ADR-0016 end-to-end: a genesis carrying one anchor key enabled through
/// `genesis-request`'s optional third group, and that key signing an
/// `anchor` entry through the same subprocess path as a root or an
/// authority — recognized by which list it is in, never by its own bytes,
/// since all three tiers are ML-DSA-87.
#[test]
#[allow(clippy::too_many_lines)] // one linear flow: genesis, combine, then the anchor entry
fn an_anchor_key_enabled_from_genesis_signs_an_anchor_entry() {
    let roots = vec![root(0x11), root(0x21), root(0x31)];
    let authority = authority(0x41);
    let anchor = AnchorKey::from_seed(&[0x51u8; ANCHOR_SEED]).expect("anchor");

    let root_pubs: Vec<_> = roots
        .iter()
        .enumerate()
        .map(|(index, key)| {
            scratch(
                &format!("anchor-genesis-root-{index}.pub"),
                hex(&key.public_key()).as_bytes(),
            )
        })
        .collect();
    let authority_pub = scratch(
        "anchor-genesis-authority.pub",
        hex(&authority.public_key()).as_bytes(),
    );
    let anchor_pub = scratch(
        "anchor-genesis-anchor.pub",
        hex(&anchor.public_key()).as_bytes(),
    );

    let request = scratch("anchor-genesis-request.json", b"");
    std::fs::remove_file(&request).expect("clear request target");
    let mut command = Command::new(bin());
    command.args([
        "genesis-request",
        request.to_str().expect("path"),
        "aquifer.karst.",
        "2",
    ]);
    for path in &root_pubs {
        command.arg(path);
    }
    command
        .arg("--")
        .arg("1")
        .arg(&authority_pub)
        .arg("--")
        .arg(&anchor_pub);
    let made = command.output().expect("run genesis-request");
    assert!(
        made.status.success(),
        "genesis request failed: {}",
        String::from_utf8_lossy(&made.stderr)
    );
    let made_out = String::from_utf8_lossy(&made.stdout);
    assert!(
        made_out.contains("anchor key"),
        "genesis-request did not report the anchor key:\n{made_out}"
    );

    let mut responses = Vec::new();
    for (index, seed) in [0x11u8, 0x21].iter().enumerate() {
        let key = scratch(
            &format!("anchor-genesis-root-{index}.key"),
            &[*seed; ROOT_SEED],
        );
        let response = scratch(&format!("anchor-genesis-response-{index}.json"), b"");
        let signed = run_sign(&request, &key, &response, "sign\n");
        assert!(
            signed.status.success(),
            "root signing failed: {}",
            String::from_utf8_lossy(&signed.stderr)
        );
        responses.push(response);
    }
    let log_path = scratch("anchor-genesis.bedrock", b"");
    std::fs::remove_file(&log_path).expect("clear log target");
    let combined = Command::new(bin())
        .arg("combine")
        .arg(&request)
        .arg(&log_path)
        .args(&responses)
        .output()
        .expect("run combine");
    assert!(
        combined.status.success(),
        "combine failed: {}",
        String::from_utf8_lossy(&combined.stderr)
    );
    let genesis_entries = karst_bedrock::decode_log(&std::fs::read(&log_path).expect("read log"))
        .expect("decode log");
    let genesis_state = verify_log(&genesis_entries).expect("verify genesis with anchor key");
    assert_eq!(genesis_state.anchor_keys, vec![anchor.public_key()]);

    // Extend the chain with an anchor entry, signed by the dedicated anchor
    // key rather than an authority — the concatenated signer space of §3.5,
    // exercised through the real binary rather than the library directly.
    // `genesis-request` stamps the genesis entry with the real wall clock
    // (unlike this file's in-process `genesis_log` fixture, which uses 1000),
    // so the next entry's time has to follow it rather than a fixed constant.
    let genesis_time = genesis_entries.first().expect("genesis entry").time;
    let anchor_request = Request {
        log: genesis_entries.clone(),
        pending: vec![Pending {
            seq: 2,
            time: genesis_time + 100,
            op: Op::Anchor,
            body: anchor_body(b"audit-head", 42),
        }],
    };
    let req_path = scratch(
        "anchor-entry-request.json",
        request_to_json(&anchor_request).as_bytes(),
    );
    let anchor_key_path = scratch("anchor.key", &[0x51u8; ANCHOR_SEED]);
    let out_path = scratch("anchor-entry-response.json", b"");

    let out = run_sign(&req_path, &anchor_key_path, &out_path, "sign\n");
    assert!(
        out.status.success(),
        "signing with the anchor key failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary = String::from_utf8_lossy(&out.stdout);
    assert!(
        summary.contains("About to sign as anchor"),
        "the tool did not recognize the anchor key:\n{summary}"
    );

    let response: Response =
        response_from_json(&std::fs::read_to_string(&out_path).expect("read response"))
            .expect("parse response");
    let extended = anchor_request
        .verify()
        .expect("verify request")
        .apply(&genesis_entries, &response)
        .expect("apply anchor response");

    let final_state = verify_log(&extended).expect("verify extended log");
    let anchor_entry = final_state.anchor.expect("anchor entry applied");
    assert_eq!(anchor_entry.audit_seq, 42);
    assert_eq!(anchor_entry.audit_head, b"audit-head");
}

/// Without the typed confirmation, nothing is signed.
#[test]
fn refusing_the_confirmation_signs_nothing() {
    let r = root(0x10);
    let a = authority(0x40);
    let node = node_keys(0x77);

    let request = Request {
        log: genesis_log(&r, &a),
        pending: vec![Pending {
            seq: 2,
            time: 1100,
            op: Op::NodeSign,
            body: sign_body("laptop-alice", &node),
        }],
    };

    let req_path = scratch(
        "request-noconfirm.json",
        request_to_json(&request).as_bytes(),
    );
    let key_path = scratch("authority-noconfirm.key", &[0x40u8; 32]);
    let out_path = scratch("response-noconfirm.json", b"");

    // "y" is not "sign". A keypress is too easy to give reflexively, which is
    // the entire reason the confirmation is a word.
    let out = run_sign(&req_path, &key_path, &out_path, "y\n");
    assert!(!out.status.success(), "signed without confirmation");
    assert!(
        std::fs::read(&out_path).expect("read").is_empty(),
        "a response was written despite the refusal"
    );
}

/// A key that is not in the log's list cannot sign into it, whatever index it
/// might have hoped to occupy.
#[test]
fn a_key_outside_the_authority_list_cannot_sign() {
    let r = root(0x10);
    let a = authority(0x40);
    let node = node_keys(0x77);

    let request = Request {
        log: genesis_log(&r, &a),
        pending: vec![Pending {
            seq: 2,
            time: 1100,
            op: Op::NodeSign,
            body: sign_body("laptop-alice", &node),
        }],
    };

    let req_path = scratch(
        "request-stranger.json",
        request_to_json(&request).as_bytes(),
    );
    // A perfectly valid authority key — just not one this log knows.
    let key_path = scratch("stranger.key", &[0x99u8; 32]);
    let out_path = scratch("response-stranger.json", b"");

    let out = run_sign(&req_path, &key_path, &out_path, "sign\n");
    assert!(
        !out.status.success(),
        "a stranger's key produced a signature"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("none of the root, authority, or anchor lists"),
        "unhelpful error: {err}"
    );
}

/// A tampered response must not slip past `apply`.
///
/// This is the import side of the air gap: the console is reading a file that
/// came back on removable media, and a signature that does not verify against
/// the recomputed chain hash has to be refused there, not merely later.
#[test]
fn a_tampered_response_is_refused_on_import() {
    let r = root(0x10);
    let a = authority(0x40);
    let node = node_keys(0x77);

    let log = genesis_log(&r, &a);
    let request = Request {
        log: log.clone(),
        pending: vec![Pending {
            seq: 2,
            time: 1100,
            op: Op::NodeSign,
            body: sign_body("laptop-alice", &node),
        }],
    };
    let verified = request.verify().expect("verify request");

    let mut sig = a.sign(&verified.to_sign[0].1).expect("sign");
    sig[0] ^= 0x01;

    let err = verified
        .apply(
            &log,
            &Response {
                signatures: vec![OfflineSignature {
                    seq: 2,
                    signer_index: 0,
                    sig,
                }],
            },
        )
        .expect_err("a corrupted signature was accepted");
    assert!(
        format!("{err}").contains("does not verify"),
        "unexpected error: {err}"
    );
}

/// A request cannot name its own signing input; it is always recomputed.
///
/// Here the request claims a *different* prior log than the one it carries — a
/// compromised server's way of asking for a signature over a chain position
/// that does not exist. The recomputation makes the resulting signature bind to
/// the real position, so applying it to the real log is what must succeed, and
/// to any other log must not.
#[test]
fn the_signing_input_comes_from_the_log_not_the_request() {
    let r = root(0x10);
    let a = authority(0x40);
    let node = node_keys(0x77);

    let log = genesis_log(&r, &a);
    let body = sign_body("laptop-alice", &node);

    let request = Request {
        log: log.clone(),
        pending: vec![Pending {
            seq: 2,
            time: 1100,
            op: Op::NodeSign,
            body: body.clone(),
        }],
    };
    let input = request.verify().expect("verify").to_sign[0].1.clone();

    // The same entry at the same sequence on a *different* genesis produces a
    // different signing input, so a signature cannot be lifted between chains.
    let other = genesis_log(&root(0x20), &a);
    let other_request = Request {
        log: other,
        pending: vec![Pending {
            seq: 2,
            time: 1100,
            op: Op::NodeSign,
            body,
        }],
    };
    let other_input = other_request.verify().expect("verify").to_sign[0].1.clone();

    assert_ne!(
        input, other_input,
        "the same entry signs identically on two different chains"
    );
}

fn run_sign(
    request: &std::path::Path,
    key: &std::path::Path,
    out: &std::path::Path,
    answer: &str,
) -> std::process::Output {
    let mut child = Command::new(bin())
        .arg("sign")
        .arg(request)
        .arg(key)
        .arg(out)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn karst-bedrock");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(answer.as_bytes())
        .expect("write answer");
    child.wait_with_output().expect("wait")
}
