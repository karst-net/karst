// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Cookie-validated handshake throughput, one core — karst-net/karst#119.
//!
//! PLAN.md's deferred Phase 2 target is "≥5,000 cookie-validated
//! handshakes/sec/core". That is a CPU cost, not a network one: §9.1's cookie
//! path (`bins/karstd/tests/cookie.rs`) exists precisely so a flooded
//! responder never allocates reassembly state for an unvalidated source, so
//! nothing about its cost depends on a NIC, a peer count on the wire, or two
//! real hosts — it depends on how many times one core can run mac1 check →
//! `CookieReply` → mac2 check → `HandshakeResponse` (ML-KEM-1024 decapsulation
//! included) per second. That is measurable in-process, deterministically,
//! the same way `cookie.rs` proves the mechanism works at all; this measures
//! how fast.
//!
//! # Design
//!
//! One server [`Engine`] with `N_CLIENTS` independent peer identities
//! pre-registered (a closed roster, same as any real Karst deployment — there
//! is no "any client may connect" mode to benchmark instead). `N_CLIENTS`
//! separate client `Engine`s, one identity each, so the server sees genuinely
//! distinct sources the way `N_CLIENTS` real machines would, not one identity
//! rekeying.
//!
//! The server's reassembler is flooded to `load_threshold` once, up front,
//! with fake unvalidated sources — exactly `cookie.rs`'s `flood` — so every
//! subsequent real client arrives into the condition §9.1 exists for. The
//! virtual clock (`NOW`) never advances: every call in this file, flood
//! included, passes the same `now_ms`. `Reassembler` entries expire at
//! `inserted_at + timeout_ms` (3 s by default — see
//! `karst_proto::reassembly::Config`), so a clock that does not move never
//! ages the flood out from under a multi-thousand-iteration loop, and nothing
//! here depends on wall-clock pacing to stay under that timeout. Only
//! [`std::time::Instant`] — outside the engines entirely — measures how long
//! the benchmark actually took.
//!
//! Only the server-side calls (`b.inbound`) are timed. A client's own cost
//! (`connect_all`, processing the `CookieReply`) is real work, but it runs on
//! a different machine's core in any real deployment and would inflate a
//! "how many can one server core validate" number if counted here.
//!
//! Randomness is fixed, as in `cookie.rs`: this measures cost, not the RNG,
//! and a deterministic run is a reproducible one.
//!
//! # Running it
//!
//! Not part of the default suite — it takes real wall-clock time and reports
//! a number rather than asserting one, per #119's own "file measured gaps
//! rather than asserting targets":
//!
//! ```text
//! cargo test --release --test handshake_rate_bench -- --ignored --nocapture
//! ```

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use karst_crypto::kem::{keypair_from_seed, KemKind};
use karst_noise::handshake::ResponderRandomness;
use karst_proto::dos::{mac1_key, FragMacKey};
use karst_proto::reassembly::{Config as ReasmConfig, Reassembler};
use karst_proto::{fragment, MessageType};
use karstd::config::{encode_hex, Config};
use karstd::engine::{Engine, Output};

/// Distinct client identities. Each is a full ML-KEM-1024 keypair plus a
/// roster entry on the server, so this also bounds setup time — picked large
/// enough to sustain several seconds of measurement at even a pessimistic
/// per-handshake cost, without the setup phase itself (excluded from the
/// timed portion, but not free) taking minutes.
const N_CLIENTS: usize = 2_000;
const SERVER_ENDPOINT: &str = "127.0.0.1:51900";
/// Frozen for the whole run — see the module doc.
const NOW: u64 = 1_000;

fn rand() -> ResponderRandomness {
    ResponderRandomness {
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}
fn seed() -> [u8; 32] {
    [0x5E; 32]
}

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("karst-hsrate-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write600(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// A 64-byte seed, distinct for every `i` up to several billion — real
/// entropy is not the point, distinctness of the resulting identity is.
fn seed_for(i: usize) -> [u8; 64] {
    let mut s = [0u8; 64];
    for (j, b) in s.iter_mut().enumerate() {
        *b = ((i as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(j as u64)
            >> 3) as u8;
    }
    s
}
fn kem_pk_hex(seed: &[u8; 64]) -> String {
    encode_hex(&keypair_from_seed(KemKind::MlKem1024, seed).1.to_bytes())
}
fn kem_pk_bytes(seed: &[u8; 64]) -> Vec<u8> {
    keypair_from_seed(KemKind::MlKem1024, seed).1.to_bytes()
}

fn server_config(server_seed: &[u8; 64], client_pks: &[String]) -> Config {
    let dir = Scratch::new("server");
    write600(&dir.join("node.key"), &encode_hex(server_seed));
    let mut toml = format!(
        "[node]\nlisten = \"{SERVER_ENDPOINT}\"\ninterface = \"karst0\"\naddresses = [\"10.240.0.1/16\"]\nprivate_key_file = \"node.key\"\n"
    );
    for (i, pk) in client_pks.iter().enumerate() {
        let a = i / 256;
        let b = i % 256;
        write!(
            toml,
            "\n[[peer]]\nname = \"c{i}\"\nkem_public_key = \"{pk}\"\nallowed_ips = [\"10.241.{a}.{b}/32\"]\n"
        )
        .unwrap();
    }
    let path = dir.join("karstd.toml");
    write600(&path, &toml);
    Config::load(&path).expect("server config must load")
}

fn client_config(i: usize, client_seed: &[u8; 64], server_pk: &str) -> Config {
    let dir = Scratch::new(&format!("client-{i}"));
    write600(&dir.join("node.key"), &encode_hex(client_seed));
    let a = i / 256;
    let b = i % 256;
    let toml = format!(
        "[node]\nlisten = \"127.0.0.1:0\"\ninterface = \"karst0\"\naddresses = [\"10.242.{a}.{b}/32\"]\nprivate_key_file = \"node.key\"\n\n\
         [[peer]]\nname = \"server\"\nkem_public_key = \"{server_pk}\"\nendpoint = \"{SERVER_ENDPOINT}\"\nallowed_ips = [\"10.240.0.1/32\"]\n"
    );
    let path = dir.join("karstd.toml");
    write600(&path, &toml);
    Config::load(&path).expect("client config must load")
}

/// Same as `cookie.rs`'s `deliver`: hand every datagram in `out` to `to`,
/// returning what it emits.
fn deliver(
    to: &Engine,
    reasm: &mut Reassembler,
    from_addr: SocketAddr,
    out: Output,
    now: u64,
) -> Output {
    let mut result = Output::default();
    for (datagram, _) in out.datagrams {
        let o = to.inbound(reasm, &datagram, from_addr, now, &rand());
        result.datagrams.extend(o.datagrams);
        result.packets.extend(o.packets);
    }
    result
}

/// `cookie.rs`'s `flood`, verbatim in spirit: occupy `count` reassembler slots
/// with fragment 0 of a fake, never-to-complete `HandshakeInit`.
fn flood(b: &Engine, reasm_b: &mut Reassembler, server_kem_pk: &[u8], count: u16, now: u64) {
    let key = FragMacKey::new(&mac1_key(server_kem_pk));
    let fake_msg = vec![0xABu8; 3210];
    for i in 0..count {
        let frags = fragment(
            MessageType::HandshakeInit,
            u32::from(i) + 1,
            &fake_msg,
            &key,
        )
        .expect("fragments");
        let first = frags.first().expect("at least one fragment").clone();
        let from: SocketAddr = format!("127.0.0.1:{}", 40_000 + i).parse().expect("addr");
        let out = b.inbound(reasm_b, &first, from, now, &rand());
        assert!(out.datagrams.is_empty());
    }
}

#[test]
#[ignore = "wall-clock benchmark, not a correctness check; run explicitly, see module docs"]
fn cookie_validated_handshakes_per_second() {
    let load_threshold = ReasmConfig::default().load_threshold;

    println!("Generating {N_CLIENTS} client identities...");
    let setup_start = Instant::now();
    let server_seed = seed_for(usize::MAX); // distinct from every client_i
    let client_seeds: Vec<[u8; 64]> = (0..N_CLIENTS).map(seed_for).collect();
    let client_pks: Vec<String> = client_seeds.iter().map(kem_pk_hex).collect();

    let server_cfg = Arc::new(server_config(&server_seed, &client_pks));
    let server_pk = kem_pk_hex(&server_seed);
    let b = Engine::new(&server_cfg);
    let mut reasm_b = Reassembler::new(ReasmConfig::default());

    let clients: Vec<Engine> = client_seeds
        .iter()
        .enumerate()
        .map(|(i, seed)| Engine::new(&Arc::new(client_config(i, seed, &server_pk))))
        .collect();
    println!(
        "Setup done in {:.1}s ({N_CLIENTS} identities + rosters)",
        setup_start.elapsed().as_secs_f64()
    );

    // Seed the cookie secret, then fill every slot with unvalidated sources —
    // once. See the module doc for why this survives the whole run.
    let _ = b.poll(NOW, seed);
    flood(
        &b,
        &mut reasm_b,
        &kem_pk_bytes(&server_seed),
        u16::try_from(load_threshold).unwrap(),
        NOW,
    );

    let mut succeeded = 0u64;
    let mut server_time = Duration::ZERO;

    for (i, client) in clients.iter().enumerate() {
        let mut reasm_c = Reassembler::new(ReasmConfig::default());
        let from: SocketAddr = format!("127.0.0.2:{}", 20_000 + (i % 40_000))
            .parse()
            .expect("addr");

        let msg1 = client.connect_all(NOW, seed);
        if msg1.datagrams.is_empty() {
            continue;
        }

        let t0 = Instant::now();
        let challenge = deliver(&b, &mut reasm_b, from, msg1, NOW);
        server_time += t0.elapsed();
        if challenge.datagrams.is_empty() {
            continue; // not under load, or already validated — should not happen here
        }

        let retry = deliver(
            client,
            &mut reasm_c,
            SERVER_ENDPOINT.parse().unwrap(),
            challenge,
            NOW,
        );
        if retry.datagrams.is_empty() {
            continue;
        }

        let t1 = Instant::now();
        let response = deliver(&b, &mut reasm_b, from, retry, NOW);
        server_time += t1.elapsed();

        let _ = deliver(
            client,
            &mut reasm_c,
            SERVER_ENDPOINT.parse().unwrap(),
            response,
            NOW,
        );

        if client.established(0) && b.established(i) {
            succeeded += 1;
        }
    }

    let rate = succeeded as f64 / server_time.as_secs_f64();
    println!(
        "\n{succeeded}/{N_CLIENTS} cookie-validated handshakes completed\n\
         server-side time: {:.3}s (client-side and setup excluded)\n\
         rate: {rate:.0} cookie-validated handshakes/sec/core",
        server_time.as_secs_f64()
    );
    assert!(
        succeeded > N_CLIENTS as u64 * 9 / 10,
        "expected nearly all {N_CLIENTS} clients to complete; only {succeeded} did \
         — the benchmark's own setup is broken, not (necessarily) the target code"
    );
}
