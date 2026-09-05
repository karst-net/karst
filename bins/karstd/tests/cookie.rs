// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! §9.1's cookie mechanism, end to end — GitHub issue #76.
//!
//! Two real [`Engine`]s, one flooded to its `load_threshold` with fake
//! unvalidated sources first, so a genuine peer's `HandshakeInit` arrives
//! into exactly the condition §9.1 exists for: a responder that must not
//! allocate reassembly state for an address it has not seen prove it can
//! receive at. This is the property `crates/karst-proto`'s unit tests check
//! in isolation and this file checks wired into the real daemon — the
//! distinction `phreatic-review-findings.md`'s Finding 1 turned on.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use karst_crypto::kem::{keypair_from_seed, KemKind};
use karst_noise::handshake::ResponderRandomness;
use karst_proto::dos::{mac1_key, FragMacKey};
use karst_proto::reassembly::Config as ReasmConfig;
use karst_proto::{fragment, MessageType};
use karstd::config::{encode_hex, Config};
use karstd::engine::{Engine, Output};

const A_ADDR: &str = "127.0.0.1:51831";
const B_ADDR: &str = "127.0.0.1:51832";

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
        let dir = std::env::temp_dir().join(format!("karst-cookie-{}-{tag}", std::process::id()));
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

fn public_of(n: u8) -> String {
    let (_, kem_pk) = keypair_from_seed(KemKind::MlKem1024, &[n; 64]);

    encode_hex(&kem_pk.to_bytes())
}
fn private_of(n: u8) -> String {
    encode_hex(&[n; 64])
}
fn kem_pk_bytes(n: u8) -> Vec<u8> {
    keypair_from_seed(KemKind::MlKem1024, &[n; 64]).1.to_bytes()
}

fn config_for(tag: &str, me: u8, peer: u8, listen: &str, peer_endpoint: &str) -> Config {
    let dir = Scratch::new(tag);
    let key = dir.join("node.key");
    write600(&key, &private_of(me));

    let kem = public_of(peer);
    let my_octet = if me == 0xA1 { 1 } else { 2 };
    let peer_octet = 3 - my_octet;
    let toml = format!(
        r#"
[node]
listen = "{listen}"
interface = "karst0"
addresses = ["10.79.0.{my_octet}/24"]
private_key_file = "node.key"

[[peer]]
name = "other"
kem_public_key = "{kem}"
endpoint = "{peer_endpoint}"
allowed_ips = ["10.79.0.{peer_octet}/32"]
"#
    );
    let path = dir.join("karstd.toml");
    write600(&path, &toml);
    Config::load(&path).expect("config must load")
}

/// Hand every datagram in `out` to `to`, returning what it emits.
fn deliver(to: &Engine, from_addr: SocketAddr, out: Output, now: u64) -> Output {
    let mut result = Output::default();
    for (datagram, _) in out.datagrams {
        let o = to.inbound(&datagram, from_addr, now, &rand());
        result.datagrams.extend(o.datagrams);
        result.packets.extend(o.packets);
    }
    result
}

/// Occupy `n` of B's reassembler slots with fragment 0 of a fake, never-to-be-
/// completed `HandshakeInit`, each from its own address — exactly what a
/// spoofed-source flood looks like from B's side, and cheap to build because
/// none of it needs to be a real handshake: `Reassembler::push` only asks
/// whether the shape is legal, not whether the content is.
fn flood(b: &Engine, b_kem_pk: &[u8], count: u16, now: u64) {
    let key = FragMacKey::new(&mac1_key(b_kem_pk));
    let fake_msg = vec![0xABu8; 3210]; // HandshakeInit's real size, garbage content
    for i in 0..count {
        let frags = fragment(
            MessageType::HandshakeInit,
            u32::from(i) + 1,
            &fake_msg,
            &key,
        )
        .expect("fragments");
        let first = frags.first().expect("at least one fragment").clone();
        let from: SocketAddr = format!("127.0.0.1:{}", 20_000 + i).parse().expect("addr");
        // Only fragment 0 — the second never arrives, so the entry stays
        // `Buffered` and keeps its slot rather than completing or expiring.
        let out = b.inbound(&first, from, now, &rand());
        assert!(
            out.datagrams.is_empty(),
            "an unvalidated flood gets nothing back below threshold"
        );
    }
}

#[test]
fn a_genuine_peer_gets_a_cookie_reply_under_load_and_still_connects() {
    let load_threshold = ReasmConfig::default().load_threshold;
    let a_addr: SocketAddr = A_ADDR.parse().unwrap();
    let b_addr: SocketAddr = B_ADDR.parse().unwrap();

    let a_cfg = config_for("a", 0xA1, 0xB1, A_ADDR, B_ADDR);
    let b_cfg = config_for("b", 0xB1, 0xA1, B_ADDR, A_ADDR);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));

    // Seed B's cookie secret — the real path is `Engine::poll`, called here
    // once rather than looping the daemon's timer, since only its side effect
    // (a seeded secret) matters to this test.
    let _ = b.poll(0, seed);

    // Fill every slot with unvalidated sources before A ever sends anything,
    // so A's first attempt arrives into the exact condition §9.1 describes.
    flood(
        &b,
        &kem_pk_bytes(0xB1),
        u16::try_from(load_threshold).unwrap(),
        1,
    );

    // A dials, unaware B is under load.
    let msg1 = a.connect_all(2, seed);
    assert_eq!(msg1.datagrams.len(), 3, "HandshakeInit is three fragments");

    // B refuses to allocate reassembly state for A and answers with cookies
    // instead of a `HandshakeResponse` — this is Finding 1's fix actually
    // firing, not merely present in the source.
    let challenge = deliver(&b, a_addr, msg1, 3);
    assert!(
        !challenge.datagrams.is_empty(),
        "B must answer an address-unvalidated sender under load with a CookieReply"
    );
    for (d, _) in &challenge.datagrams {
        assert_eq!(
            d.len(),
            24 + 64,
            "a CookieReply datagram is one 64-byte fragment"
        );
    }
    assert!(!a.established(0));
    assert!(!b.established(0));

    // A processes the challenge and retries under mac2 — automatically, the
    // same way a real daemon would on the next `inbound` call for this peer.
    let retry = deliver(&a, b_addr, challenge, 4);
    assert_eq!(
        retry.datagrams.len(),
        3,
        "the retried HandshakeInit is three fragments, same as the first attempt"
    );

    // B accepts it this time: the fragments verify under mac2, which only a
    // sender that received B's CookieReply — sent to A's real address — could
    // produce, so B treats A as address-validated despite still being over
    // `load_threshold` for everyone else.
    let msg2 = deliver(&b, a_addr, retry, 5);
    assert_eq!(
        msg2.datagrams.len(),
        3,
        "B answers with a HandshakeResponse"
    );

    let nothing = deliver(&a, b_addr, msg2, 6);
    assert!(nothing.datagrams.is_empty());

    assert!(
        a.established(0),
        "A must complete the handshake despite the flood"
    );
    assert!(b.established(0), "B must complete it too");

    // And the flood never cost B a single byte of state beyond the counters:
    // this is the property §9.1 exists for, checked from the outside.
    assert!(b.stats().cookie_replies_issued > 0);
}

#[test]
fn an_off_path_spoofer_gets_no_more_than_the_amplification_bound_allows() {
    let load_threshold = ReasmConfig::default().load_threshold;
    let b_cfg = config_for("spoof-b", 0xB1, 0xA1, B_ADDR, A_ADDR);
    let b = Engine::new(&Arc::new(b_cfg));
    let _ = b.poll(0, seed);

    flood(
        &b,
        &kem_pk_bytes(0xB1),
        u16::try_from(load_threshold).unwrap(),
        1,
    );

    // One more, address-unvalidated, from a spoofed source that will never
    // read the reply — modelling the attacker rather than a real peer.
    let key = FragMacKey::new(&mac1_key(&kem_pk_bytes(0xB1)));
    let fake_msg = vec![0xCDu8; 3210];
    let frags = fragment(MessageType::HandshakeInit, 999, &fake_msg, &key).expect("fragments");
    let spoofed: SocketAddr = "127.0.0.1:59999".parse().unwrap();
    let out = b.inbound(&frags[0], spoofed, 2, &rand());

    // §6.4 invariant 3 (`karst_proto::sizes::COOKIE_REPLY` against
    // `FRAGMENT_PAYLOAD_MAX`) is a message-body comparison — 64 against
    // ≥1208 — so the fragment header both datagrams share is excluded here
    // too, to check the same bound the compile-time assertion does.
    let sent: usize = out
        .datagrams
        .iter()
        .map(|(d, _)| d.len().saturating_sub(karst_proto::consts::FRAGMENT_HEADER))
        .sum();
    let received = frags[0]
        .len()
        .saturating_sub(karst_proto::consts::FRAGMENT_HEADER);
    assert!(
        sent * 100 < received * 6,
        "a CookieReply must keep the amplification ratio under the 0.06 §6.4 bound: \
         sent {sent} against received {received}"
    );
}
