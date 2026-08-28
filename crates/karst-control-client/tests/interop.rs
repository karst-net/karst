// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Cross-language interop: this Rust client against the real Go server.
//!
//! The vectors in `tests/vectors.rs` prove the two implementations agree on
//! every derivation and framing function. They cannot prove the two ends
//! actually *talk*: that needs sockets, HTTP/2, protobuf on the wire, and a
//! real ML-KEM handshake between two processes in two languages. This is that
//! test.
//!
//! It is `#[ignore]`d by default because it needs a Go toolchain and builds a
//! binary. Run it with:
//!
//! ```sh
//! cargo test -p karst-control-client --test interop -- --ignored
//! ```
//!
//! CI runs it in the `vectors` job, which already has both toolchains.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use karst_control_client::transport::{
    Connection, EncapRandomness, Error, ServerPins, Signer, Verifier,
};

// The Go server verifies with real ML-DSA-87, so this side must sign with it.
// The node's production signer will live in `karstd` alongside the rest of its
// key management; this exists so the interop test proves the handshake
// completes against a server doing real verification, not a stand-in.

struct TestServer {
    child: Child,
    pins: ServerPins,
    address: String,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("server pin is not hex")
}

/// Build and start the Go test server, and read its pins.
fn start_server() -> TestServer {
    let repo = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let bin = format!("{repo}/target/karst-testserver");

    let build = Command::new("go")
        .args([
            "build",
            "-o",
            &bin,
            "./management/internals/karst/testserver/",
        ])
        .current_dir(format!("{repo}/server"))
        .output()
        .expect("run `go build` (is the Go toolchain installed?)");
    assert!(
        build.status.success(),
        "go build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let mut child = Command::new(&bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the test server");

    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read the server's pins");

    let v: serde_json::Value = serde_json::from_str(&line).expect("pins are not JSON");
    let address = v["address"].as_str().expect("address").to_string();
    let pins = ServerPins {
        static_kem: unhex(v["static_kem"].as_str().expect("static_kem")),
        verify_key: unhex(v["verify_key"].as_str().expect("verify_key")),
        minimum_version: 1,
    };

    TestServer {
        child,
        pins,
        address,
    }
}

// ── a real ML-DSA-87 identity for the node side ─────────────────────────────

struct NodeSigner {
    signing: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>,
    public: Vec<u8>,
}

impl NodeSigner {
    fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        let signing = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(&seed.into());
        let public = signing.verifying_key().encode().to_vec();
        Self { signing, public }
    }
}

impl Signer for NodeSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>> {
        // The Go side signs with a FIPS 204 context string; both ends must use
        // the same one or the signature will not verify.
        let sig = self
            .signing
            .sign_deterministic(message, b"karst-control-v1")
            .map_err(|_| "sign failed")?;
        Ok(sig.encode().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }
}

struct NodeVerifier;

impl Verifier for NodeVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(pk) = <[u8; 2592]>::try_from(public_key) else {
            return false;
        };
        let Ok(sg) = <[u8; 4627]>::try_from(signature) else {
            return false;
        };
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&pk.into());
        let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa87>::decode(&sg.into()) else {
            return false;
        };
        vk.verify_with_context(message, b"karst-control-v1", &sig)
    }
}

fn randomness() -> EncapRandomness {
    use rand::RngCore;
    let mut r = EncapRandomness {
        statik: [0u8; 32],
        ephemeral: [0u8; 32],
    };
    rand::rngs::OsRng.fill_bytes(&mut r.statik);
    rand::rngs::OsRng.fill_bytes(&mut r.ephemeral);
    r
}

// ── the tests ───────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn rust_node_completes_a_handshake_with_the_go_server() {
    let server = start_server();
    let signer = NodeSigner::generate();

    let mut conn = Connection::open(
        format!("http://{}", server.address),
        &server.pins,
        Vec::new(),
        &signer,
        &NodeVerifier,
        true,
        &randomness(),
    )
    .await
    .expect("handshake against the Go server");

    let reply = conn.request(b"hello from rust").await.expect("request");
    assert!(
        reply.starts_with(b"echo:hello from rust"),
        "unexpected reply: {:?}",
        String::from_utf8_lossy(&reply)
    );
}

/// Many requests on one channel: the sequence counters advance on both sides
/// and a mistake shows up on the second message, not the first.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn many_requests_on_one_channel() {
    let server = start_server();
    let signer = NodeSigner::generate();

    let mut conn = Connection::open(
        format!("http://{}", server.address),
        &server.pins,
        Vec::new(),
        &signer,
        &NodeVerifier,
        true,
        &randomness(),
    )
    .await
    .expect("handshake");

    for i in 0..25u8 {
        let reply = conn.request(&[i]).await.expect("request");
        assert_eq!(&reply[..5], b"echo:");
        assert_eq!(reply[5], i, "request {i} came back wrong");
    }
}

/// A wrong pinned verification key must be refused *before* anything is sent.
/// This is the check whose absence cost forward secrecy in the first revision
/// of ADR-0011.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn wrong_pinned_verify_key_is_refused() {
    let server = start_server();
    let signer = NodeSigner::generate();

    let mut bad = server.pins.clone();
    bad.verify_key = vec![0u8; bad.verify_key.len()];

    let err = Connection::open(
        format!("http://{}", server.address),
        &bad,
        Vec::new(),
        &signer,
        &NodeVerifier,
        true,
        &randomness(),
    )
    .await
    .expect_err("a bad pin was accepted");

    assert!(
        matches!(err, Error::ServerAuth),
        "expected ServerAuth, got {err}"
    );
}

/// A wrong pinned KEM key cannot be detected at the handshake — ML-KEM
/// decapsulation of a foreign ciphertext yields an implicit-rejection secret
/// rather than an error, by design in FIPS 203 — so it must fail closed at the
/// first envelope instead.
#[tokio::test]
#[ignore = "needs a Go toolchain; run with --ignored"]
async fn wrong_pinned_kem_key_fails_closed() {
    let server = start_server();
    let signer = NodeSigner::generate();

    let mut bad = server.pins.clone();
    bad.static_kem[0] ^= 0xFF;

    match Connection::open(
        format!("http://{}", server.address),
        &bad,
        Vec::new(),
        &signer,
        &NodeVerifier,
        true,
        &randomness(),
    )
    .await
    {
        Err(_) => {} // rejected at the handshake is also acceptable
        Ok(mut conn) => {
            conn.request(b"secret")
                .await
                .expect_err("a channel built on the wrong pinned KEM key carried a request");
        }
    }
}
