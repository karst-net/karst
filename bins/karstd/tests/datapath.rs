// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Two engines, one virtual link.
//!
//! Drives both nodes' [`Engine`]s against each other with the sockets replaced
//! by a direct hand-off, so the whole datapath — routing, handshake, encryption,
//! reassembly, the source check — is exercised without needing `CAP_NET_ADMIN`.
//! The privileged half, where real IP packets cross real interfaces, is in
//! `tests/two_nodes.rs`.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use karst_control_client::transport::pb;
use karst_crypto::kem::{keypair_from_seed, KemKind};
use karst_noise::handshake::ResponderRandomness;
use karstd::config::{encode_hex, Config};
use karstd::engine::{Engine, Output};
use karstd::filter::PacketFilter;

const A_ADDR: &str = "127.0.0.1:51821";
const B_ADDR: &str = "127.0.0.1:51822";

fn rand() -> ResponderRandomness {
    ResponderRandomness {
        encap_rand_e: [0xF2; 32],
        encap_rand_s: [0xF3; 32],
    }
}
fn seed() -> [u8; 32] {
    [0x5A; 32]
}

/// A temporary directory that removes itself.
///
/// Fixtures here used to create one per process and never remove it, which
/// accumulated thousands of directories in `/tmp` across repeated runs.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("karst-scratch-{}-{tag}", std::process::id()));
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

/// Public keys for the node whose private seed is `n` repeated.
fn public_of(n: u8) -> String {
    let (_, kem_pk) = keypair_from_seed(KemKind::MlKem1024, &[n; 64]);

    encode_hex(&kem_pk.to_bytes())
}

/// A private key file: 64 bytes of ML-KEM-1024 seed, all `n`.
fn private_of(n: u8) -> String {
    let seed = [n; 64];

    encode_hex(&seed)
}

/// Write a config for one node of a two-node network.
fn config_for(tag: &str, me: u8, peer: u8, listen: &str, peer_endpoint: Option<&str>) -> Config {
    let dir = Scratch::new(tag);
    let key = dir.join("node.key");
    write600(&key, &private_of(me));

    let kem = public_of(peer);
    let endpoint = peer_endpoint.map_or_else(String::new, |e| format!("endpoint = \"{e}\"\n"));
    let my_octet = if me == 0xA1 { 1 } else { 2 };
    let peer_octet = 3 - my_octet;

    let toml = format!(
        r#"
[node]
listen = "{listen}"
interface = "karst0"
addresses = ["10.77.0.{my_octet}/24"]
private_key_file = "node.key"
psk_epoch = 3

[[peer]]
name = "other"
kem_public_key = "{kem}"
{endpoint}allowed_ips = ["10.77.0.{peer_octet}/32"]
"#
    );
    let path = dir.join("karstd.toml");
    write600(&path, &toml);
    Config::load(&path).expect("config must load")
}

/// A roster with two peers, for testing that they do not contend.
fn config_for_two_peers(tag: &str) -> Config {
    let dir = Scratch::new(tag);
    let key = dir.join("node.key");
    write600(&key, &private_of(0xA1));

    let kem1 = public_of(0xB1);
    let kem2 = public_of(0xC1);
    let toml = format!(
        r#"
[node]
listen = "{A_ADDR}"
interface = "karst0"
addresses = ["10.77.0.1/24"]
private_key_file = "node.key"

[[peer]]
name = "one"
kem_public_key = "{kem1}"
endpoint = "{B_ADDR}"
allowed_ips = ["10.77.0.2/32"]

[[peer]]
name = "two"
kem_public_key = "{kem2}"
endpoint = "127.0.0.1:51823"
allowed_ips = ["10.77.0.3/32"]
"#
    );
    let path = dir.join("karstd.toml");
    write600(&path, &toml);
    Config::load(&path).expect("config must load")
}

/// A minimal IPv4 packet with a correct total-length field.
fn packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    let total = u16::try_from(20 + payload.len()).expect("small");
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

/// Hand every datagram in `out` to the other engine, returning what it emits.
fn deliver(to: &Engine, from_addr: SocketAddr, out: Output, now: u64) -> Output {
    let mut result = Output::default();
    for (datagram, _) in out.datagrams {
        let o = to.inbound(&datagram, from_addr, now, &rand());
        result.datagrams.extend(o.datagrams);
        result.packets.extend(o.packets);
    }
    result
}

/// Run the handshake to completion in both directions.
fn establish(a: &Engine, b: &Engine) {
    let a_addr: SocketAddr = A_ADDR.parse().unwrap();
    let b_addr: SocketAddr = B_ADDR.parse().unwrap();

    // A initiates; B answers; A completes.
    let msg1 = a.connect_all(0, seed);
    assert_eq!(msg1.datagrams.len(), 3, "HandshakeInit is three fragments");
    let msg2 = deliver(b, a_addr, msg1, 1);
    assert_eq!(
        msg2.datagrams.len(),
        3,
        "HandshakeResponse is three fragments"
    );
    let nothing = deliver(a, b_addr, msg2, 2);
    assert!(nothing.datagrams.is_empty());
}

#[test]
fn two_nodes_complete_a_handshake_and_carry_a_packet() {
    let a_cfg = config_for("a1", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("b1", 0xB1, 0xA1, B_ADDR, None);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));

    establish(&a, &b);
    assert!(a.established(0), "initiator must be established");
    assert!(b.established(0), "responder must be established");

    // B learned where A is from the handshake, so it can reply unprompted.
    assert_eq!(b.endpoint(0), Some(A_ADDR.parse().unwrap()));

    // A packet from the host, routed to B by its destination address.
    let p = packet([10, 77, 0, 1], [10, 77, 0, 2], b"hello karst");
    let out = a.outbound(&p, 3);
    assert!(!out.datagrams.is_empty(), "a routable packet must be sent");

    let delivered = deliver(&b, A_ADDR.parse().unwrap(), out, 4);
    assert_eq!(delivered.packets.len(), 1, "one packet must reach the host");
    assert_eq!(
        delivered.packets[0], p,
        "the packet must arrive byte-identical, with §8's padding trimmed"
    );
    assert_eq!(b.stats().rx_packets, 1);
}

/// Both directions, because the responder's send path uses a different MAC key
/// from the initiator's (§13.7) and a one-way test would not notice.
#[test]
fn traffic_flows_in_both_directions() {
    let a_cfg = config_for("a2", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("b2", 0xB1, 0xA1, B_ADDR, None);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);

    let to_b = packet([10, 77, 0, 1], [10, 77, 0, 2], b"ping");
    let got = deliver(&b, A_ADDR.parse().unwrap(), a.outbound(&to_b, 3), 4);
    assert_eq!(got.packets.len(), 1);

    let to_a = packet([10, 77, 0, 2], [10, 77, 0, 1], b"pong");
    let got = deliver(&a, B_ADDR.parse().unwrap(), b.outbound(&to_a, 5), 6);
    assert_eq!(
        got.packets.len(),
        1,
        "the responder's fragments must verify"
    );
    assert_eq!(got.packets[0], to_a);
}

/// A full-MTU packet is the case §13.6 exists for: 1280 bytes in, one
/// unfragmented datagram out, 1280 bytes at the far end.
#[test]
fn a_full_mtu_packet_crosses_in_a_single_datagram() {
    let a_cfg = config_for("a3", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("b3", 0xB1, 0xA1, B_ADDR, None);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);

    let p = packet([10, 77, 0, 1], [10, 77, 0, 2], &vec![0x5A; 1260]);
    assert_eq!(p.len(), 1280, "the tunnel MTU");

    let out = a.outbound(&p, 3);
    assert_eq!(out.datagrams.len(), 1, "spec §8 — never fragmented");
    assert_eq!(
        out.datagrams[0].0.len(),
        karst_proto::consts::TRANSPORT_DATAGRAM_MAX,
        "spec §13.6"
    );

    let got = deliver(&b, A_ADDR.parse().unwrap(), out, 4);
    assert_eq!(got.packets.len(), 1);
    assert_eq!(got.packets[0].len(), 1280, "padding must be trimmed");
    assert_eq!(got.packets[0], p);
}

/// **Cryptokey routing, inbound.** An authenticated peer that claims a source
/// address it does not own must be dropped. Without this, any peer on the
/// roster can impersonate any other.
#[test]
fn a_peer_cannot_send_from_an_address_it_does_not_own() {
    let a_cfg = config_for("a4", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("b4", 0xB1, 0xA1, B_ADDR, None);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);

    // B is entitled to 10.77.0.2 only. It sends a packet claiming to be A.
    let spoofed = packet([10, 77, 0, 1], [10, 77, 0, 1], b"i am you");
    // Route it deliberately: `outbound` would refuse on the destination, so the
    // packet is sealed directly to model a malicious peer rather than a bug.
    let legit = packet([10, 77, 0, 2], [10, 77, 0, 1], b"honest");
    let out = b.outbound(&legit, 5);
    assert!(!out.datagrams.is_empty(), "the honest packet must be sent");
    let got = deliver(&a, B_ADDR.parse().unwrap(), out, 6);
    assert_eq!(got.packets.len(), 1, "an honest packet is delivered");

    // Now the spoof, through the same session.
    let out = b.outbound(&spoofed, 7);
    let before = a.stats().source_violations;
    let got = deliver(&a, B_ADDR.parse().unwrap(), out, 8);
    assert!(
        got.packets.is_empty(),
        "a peer must not be able to claim another peer's source address"
    );
    assert_eq!(
        a.stats().source_violations,
        before + 1,
        "and the drop must be counted, not silent"
    );
}

/// A packet no peer owns has nowhere to go. Dropping it is right; dropping it
/// without counting turns a configuration mistake into a mystery.
#[test]
fn an_unroutable_packet_is_dropped_and_counted() {
    let cfg = config_for("a5", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let a = Engine::new(&Arc::new(cfg));

    let p = packet([10, 77, 0, 1], [192, 168, 1, 1], b"nowhere");
    let out = a.outbound(&p, 0);
    assert!(out.datagrams.is_empty());
    assert_eq!(a.stats().unroutable, 1);

    let out = a.outbound(&[0xFF; 40], 0);
    assert!(out.datagrams.is_empty(), "garbage is not a packet");
    assert_eq!(a.stats().unroutable, 2);
}

/// The fragment MAC discards a flood before any state is allocated (§9.2), and
/// with §13.7's keying it does so with one key regardless of sender.
#[test]
fn forged_datagrams_are_discarded_by_the_fragment_mac() {
    let cfg = config_for("a6", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let a = Engine::new(&Arc::new(cfg));
    let from: SocketAddr = B_ADDR.parse().unwrap();

    for i in 0..64u8 {
        let mut junk = vec![i; 300];
        junk[4] = 0; // idx 0, count 1
        let out = a.inbound(&junk, from, 0, &rand());
        assert!(out.datagrams.is_empty() && out.packets.is_empty());
    }
    assert_eq!(
        a.stats().mac_failures,
        64,
        "every forgery must be rejected at the MAC, before reassembly"
    );
}

/// A peer with no configured endpoint is not contacted — there is nowhere to
/// send — but must still be able to contact us. That is the arrangement for a
/// node behind NAT.
#[test]
fn a_peer_without_an_endpoint_is_not_contacted_but_can_still_connect() {
    let a_cfg = config_for("a7", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("b7", 0xB1, 0xA1, B_ADDR, None);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));

    assert!(
        b.connect_all(0, seed).datagrams.is_empty(),
        "B has no endpoint for A, so it must not try"
    );
    assert_eq!(b.endpoint(0), None);

    establish(&a, &b);
    assert!(b.established(0));
    assert_eq!(
        b.endpoint(0),
        Some(A_ADDR.parse().unwrap()),
        "the endpoint must be learned from the handshake"
    );
}

/// A retransmitted `HandshakeInit` must be answered again: the responder holds
/// no state until a transport message authenticates (§12.6), so refusing the
/// retry would strand an initiator whose first response was lost.
#[test]
fn a_retransmitted_handshake_is_answered_again() {
    let a_cfg = config_for("a8", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("b8", 0xB1, 0xA1, B_ADDR, None);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    let a_addr: SocketAddr = A_ADDR.parse().unwrap();

    let msg1 = a.connect_all(0, seed);
    let first: Vec<Vec<u8>> = msg1.datagrams.iter().map(|(d, _)| d.clone()).collect();
    let r1 = deliver(&b, a_addr, msg1, 1);
    assert_eq!(r1.datagrams.len(), 3);

    let mut r2 = Output::default();
    for d in &first {
        let o = b.inbound(d, a_addr, 2, &rand());
        r2.datagrams.extend(o.datagrams);
    }
    assert_eq!(
        r2.datagrams.len(),
        3,
        "the responder must answer a retransmission rather than ignore it"
    );
}

// ── concurrency (PLAN.md §3.4) ───────────────────────────────────────────────

/// The engine must be shareable across threads **without an external lock**.
///
/// A compile-time check, because the failure mode is silent: adding a
/// non-`Sync` field would not break any test, it would force the next person to
/// wrap the engine in a mutex — which is exactly the bottleneck §3.4 measured
/// and this design removes.
#[test]
fn the_engine_is_shareable_without_an_outer_lock() {
    const fn assert_sync<T: Sync>() {}
    assert_sync::<Engine>();
}

/// Traffic for **different peers must not contend**, which is the whole point
/// of per-peer locking.
///
/// Two threads send to two peers at once. This cannot prove the absence of
/// contention — timing tests are unreliable — but it does prove the API permits
/// concurrent use, which a single `&mut self` engine did not. A regression to a
/// global lock fails to compile here rather than merely running slowly.
#[test]
fn different_peers_can_be_driven_concurrently() {
    let cfg = config_for_two_peers("conc");
    let engine = Engine::new(&Arc::new(cfg));

    let p1 = packet([10, 77, 0, 1], [10, 77, 0, 2], b"to peer one");
    let p2 = packet([10, 77, 0, 1], [10, 77, 0, 3], b"to peer two");

    std::thread::scope(|s| {
        s.spawn(|| {
            for _ in 0..200 {
                let _ = engine.outbound(&p1, 0);
            }
        });
        s.spawn(|| {
            for _ in 0..200 {
                let _ = engine.outbound(&p2, 0);
            }
        });
        // A third thread walking every peer's timers, which is what the daemon
        // does and which must not require exclusive access to the engine.
        s.spawn(|| {
            for t in 0..200 {
                let _ = engine.poll(t, seed);
            }
        });
    });

    // Neither peer has a session, so every packet is counted as dropped rather
    // than sent. What matters is that 400 concurrent calls all landed.
    let stats = engine.stats();
    assert_eq!(
        stats.tx_dropped_no_session + stats.tx_packets,
        400,
        "every concurrent send must be accounted for"
    );
}

/// Counters are atomic, so concurrent updates must not lose any.
#[test]
fn counters_do_not_lose_updates_under_concurrency() {
    let cfg = config_for("count", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let engine = Engine::new(&Arc::new(cfg));

    // Unroutable: no peer owns 192.168.1.1, so each call bumps one counter.
    let p = packet([10, 77, 0, 1], [192, 168, 1, 1], b"nowhere");
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for _ in 0..500 {
                    let _ = engine.outbound(&p, 0);
                }
            });
        }
    });
    assert_eq!(
        engine.stats().unroutable,
        2000,
        "a lost increment means the counters are not actually atomic"
    );
}

/// **A session that dies must come back.** `connect_all` runs once at startup,
/// so an expired or abandoned session returns to `Idle` and — without a re-dial
/// on the timer — stays there for the life of the process.
///
/// This is the failure that would have ended a 12-hour soak: one rekey lost to
/// packet loss expires the session at `REJECT_AFTER_TIME`, and the tunnel is
/// then permanently dead rather than down for a round trip.
#[test]
fn an_expired_session_is_re_dialled() {
    let a_cfg = config_for("redial", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("redial-b", 0xB1, 0xA1, B_ADDR, None);
    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);
    assert!(a.established(0));

    // Past REJECT_AFTER_TIME with no successful rekey the session expires, and
    // the same tick must already be re-dialling — not leaving the peer idle.
    let expired = karst_noise::transport::REJECT_AFTER_MS + 1_000;
    let out = a.poll(expired, seed);
    assert_eq!(
        out.datagrams.len(),
        3,
        "an idle peer with an endpoint must be re-dialled (HandshakeInit is three fragments)"
    );

    // And it must actually recover, end to end.
    let reply = deliver(&b, A_ADDR.parse().unwrap(), out, expired + 2);
    deliver(&a, B_ADDR.parse().unwrap(), reply, expired + 3);
    assert!(a.established(0), "the tunnel must come back on its own");
}

/// A peer with no endpoint must not be re-dialled: there is nowhere to send,
/// and a handshake storm at every tick would be the result.
#[test]
fn a_peer_without_an_endpoint_is_not_re_dialled() {
    let cfg = config_for("nodial", 0xB1, 0xA1, B_ADDR, None);
    let e = Engine::new(&Arc::new(cfg));
    for t in 0..20u64 {
        assert!(
            e.poll(t * 1_000, seed).datagrams.is_empty(),
            "a peer with no endpoint must stay silent"
        );
    }
}

// ── ACL enforcement, end to end ─────────────────────────────────────────────

/// A TCP packet with a destination port, so the ACL has something to match.
fn tcp_packet(src: [u8; 4], dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut p = packet(src, dst, &[0u8; 4]);
    p[9] = 6; // TCP
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&dst_port.to_be_bytes());
    p
}

/// Give a loaded config a compiled filter, as a netmap-sourced one would have.
fn with_filter(
    config: &mut Config,
    ingress: &[pb::KarstFilterRule],
    egress: &[pb::KarstEgressRule],
) {
    // The peer is index 0 in these two-node configs, and the filter names peers
    // by handle, so the handle list has to line up with the roster order.
    config.filter = PacketFilter::compile(ingress, egress, &[b"other".to_vec()]);
}

fn rule(srcs: &[&str], first: u32, last: u32) -> pb::KarstFilterRule {
    pb::KarstFilterRule {
        srcs: srcs.iter().map(|s| (*s).to_owned()).collect(),
        ports: vec![pb::KarstPortRange { first, last }],
    }
}

fn out_rule(dsts: &[&str], first: u32, last: u32) -> pb::KarstEgressRule {
    pb::KarstEgressRule {
        dsts: dsts.iter().map(|s| (*s).to_owned()).collect(),
        ports: vec![pb::KarstPortRange { first, last }],
    }
}

/// **The exit criterion's second half, through the real datapath.** A packet
/// the receiver's ACL forbids is decrypted, authenticated, confirmed to come
/// from an address the peer owns — and then dropped, because policy says so.
#[test]
fn the_receivers_acl_drops_a_packet_the_sender_was_willing_to_send() {
    let a_cfg = config_for("acl-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let mut b_cfg = config_for("acl-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR));
    // B accepts only SSH from its peer. A has no policy at all, so it will
    // happily send anything — which is the point: the receiver's check is what
    // stops a sender that does not enforce.
    with_filter(&mut b_cfg, &[rule(&["other"], 22, 22)], &[]);

    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);
    let a_addr: SocketAddr = A_ADDR.parse().unwrap();

    let permitted = deliver(
        &b,
        a_addr,
        a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 22), 10),
        11,
    );
    assert_eq!(permitted.packets.len(), 1, "SSH is permitted");

    let refused = deliver(
        &b,
        a_addr,
        a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 8080), 12),
        13,
    );
    assert!(
        refused.packets.is_empty(),
        "a packet the ACL forbids must not reach the host"
    );
    assert_eq!(b.stats().acl_denied_in, 1);
    assert_eq!(
        b.stats().source_violations,
        0,
        "an ACL denial is not a source violation; conflating them reads policy as an attack"
    );
    assert_eq!(
        b.stats().rx_packets,
        1,
        "only the permitted packet was delivered"
    );
}

/// The sender's own filter refuses before any cryptography runs, so a denied
/// flow costs a route lookup rather than a round trip.
#[test]
fn the_senders_acl_drops_a_packet_before_it_is_encrypted() {
    let mut a_cfg = config_for("acl-out-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("acl-out-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR));
    with_filter(&mut a_cfg, &[], &[out_rule(&["other"], 443, 443)]);

    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);

    let refused = a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 22), 10);
    assert!(refused.datagrams.is_empty(), "nothing may go on the wire");
    assert_eq!(a.stats().acl_denied_out, 1);
    assert_eq!(
        a.stats().tx_packets,
        0,
        "the packet must not be counted as sent"
    );

    let allowed = a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 443), 11);
    assert!(!allowed.datagrams.is_empty());
    assert_eq!(a.stats().tx_packets, 1);
    let _ = b; // established above so the send path is realiztic
}

/// `PeerStatus::tx_bytes`/`rx_bytes` — plans/phase-6/13-macos-status-indicators.md
/// §1's throughput plumbing. Counts must track plaintext length (what a
/// menu-bar app would want to show a user, not AEAD-padded wire size) and
/// must not move for a packet the ACL refused before encryption.
#[test]
fn peer_status_reports_bytes_sent_and_received() {
    let mut a_cfg = config_for("bytes-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("bytes-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR));
    with_filter(&mut a_cfg, &[], &[out_rule(&["other"], 443, 443)]);

    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);

    assert_eq!(a.status()[0].tx_bytes, 0, "nothing sent yet");
    assert_eq!(b.status()[0].rx_bytes, 0, "nothing received yet");

    let refused = a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 22), 10);
    assert!(
        refused.datagrams.is_empty(),
        "the sender's own ACL refuses this port"
    );
    assert_eq!(
        a.status()[0].tx_bytes,
        0,
        "a packet the ACL refused before encryption must not count as sent"
    );

    let packet = tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 443);
    let sent = a.outbound(&packet, 11);
    assert!(!sent.datagrams.is_empty());
    assert_eq!(
        a.status()[0].tx_bytes,
        packet.len() as u64,
        "tx_bytes must track the plaintext length, not the sealed wire size"
    );

    let delivered = deliver(&b, A_ADDR.parse().unwrap(), sent, 12);
    assert_eq!(delivered.packets.len(), 1);
    assert_eq!(
        b.status()[0].rx_bytes,
        delivered.packets[0].len() as u64,
        "rx_bytes must track what was actually delivered to the host"
    );
}

/// **Fragmenting must not be a way around the filter.** A non-first fragment
/// carries no transport header, so its ports cannot be read; it is denied and
/// counted apart from a policy decision, because no rule was evaluated.
#[test]
fn a_fragment_cannot_slip_past_the_filter() {
    let mut a_cfg = config_for("acl-frag-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    with_filter(&mut a_cfg, &[], &[out_rule(&["other"], 443, 443)]);
    let a = Engine::new(&Arc::new(a_cfg));

    let mut fragment = tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 443);
    fragment[6] = 0x00;
    fragment[7] = 0x02; // a non-first fragment, claiming a permitted port

    let refused = a.outbound(&fragment, 10);
    assert!(refused.datagrams.is_empty());
    assert_eq!(a.stats().acl_unclassifiable, 1);
    assert_eq!(
        a.stats().acl_denied_out,
        0,
        "this is not a policy decision — no rule could be evaluated"
    );
}

/// A roster-configured node has no policy source, and must keep working. The
/// TOML path predates ACLs entirely; denying everything because no policy was
/// supplied would break a working network on upgrade.
#[test]
fn a_roster_without_a_policy_still_carries_traffic() {
    let a_cfg = config_for("acl-none-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let b_cfg = config_for("acl-none-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR));
    assert!(!b_cfg.filter.is_enforcing());

    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);

    let out = deliver(
        &b,
        A_ADDR.parse().unwrap(),
        a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 8080), 10),
        11,
    );
    assert_eq!(out.packets.len(), 1);
    assert_eq!(b.stats().acl_denied_in, 0);
}

/// And its opposite: a netmap that shipped no rules is a policy granting
/// nothing, so the same traffic is refused. These two tests differ only in
/// which constructor built the filter, which is exactly the distinction that
/// must never collapse.
#[test]
fn an_empty_policy_denies_the_traffic_no_policy_permits() {
    let a_cfg = config_for("acl-empty-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    let mut b_cfg = config_for("acl-empty-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR));
    with_filter(&mut b_cfg, &[], &[]);
    assert!(b_cfg.filter.is_enforcing());

    let a = Engine::new(&Arc::new(a_cfg));
    let b = Engine::new(&Arc::new(b_cfg));
    establish(&a, &b);

    let out = deliver(
        &b,
        A_ADDR.parse().unwrap(),
        a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 8080), 10),
        11,
    );
    assert!(out.packets.is_empty());
    assert_eq!(b.stats().acl_denied_in, 1);
}

// ── live reconfiguration ────────────────────────────────────────────────────

/// Rebuild a config with an extra peer, keeping the first one identical.
fn config_with_two_peers(tag: &str, me: u8, first: u8, second: u8) -> Config {
    let dir = Scratch::new(tag);
    let key = dir.join("node.key");
    write600(&key, &private_of(me));

    let kem1 = public_of(first);
    let kem2 = public_of(second);
    let toml = format!(
        r#"
[node]
listen = "{A_ADDR}"
interface = "karst0"
addresses = ["10.77.0.1/24"]
private_key_file = "node.key"
psk_epoch = 3

[[peer]]
name = "other"
kem_public_key = "{kem1}"
endpoint = "{B_ADDR}"
allowed_ips = ["10.77.0.2/32"]

[[peer]]
name = "newcomer"
kem_public_key = "{kem2}"
allowed_ips = ["10.77.0.3/32"]
"#
    );
    let path = dir.join("karstd.toml");
    write600(&path, &toml);
    Config::load(&path).expect("config must load")
}

/// **The property live reconfiguration exists for.** Adding a peer must not
/// cost a rehandshake with every other one — on a large aquifer a single
/// enrollment would otherwise produce a fleet-wide reconnect, each costing two
/// ML-KEM operations and a window where traffic is dropped for want of a
/// session.
#[test]
fn adding_a_peer_leaves_the_existing_session_alone() {
    let a_cfg = Arc::new(config_for("recfg-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR)));
    let b_cfg = Arc::new(config_for("recfg-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR)));

    let a = Engine::new(&a_cfg);
    let b = Engine::new(&b_cfg);
    establish(&a, &b);
    assert!(a.established(0), "the session must be up before the change");

    let grown = Arc::new(config_with_two_peers("recfg-grow", 0xA1, 0xB1, 0xC1));
    let report = a.reconfigure(&grown);

    assert_eq!(report.added, 1, "one peer arrived");
    assert_eq!(report.kept, 1, "and one was carried over");
    assert_eq!(report.removed, 0);
    assert!(!report.epoch_rotated);

    assert!(
        a.established(0),
        "the existing peer's session must survive a netmap change about somebody else"
    );
    assert!(
        !a.established(1),
        "and the new peer must start from scratch"
    );

    // And traffic still flows on the surviving session, without a new handshake.
    let out = deliver(
        &b,
        A_ADDR.parse().unwrap(),
        a.outbound(&packet([10, 77, 0, 1], [10, 77, 0, 2], b"after"), 100),
        101,
    );
    assert_eq!(out.packets.len(), 1, "the carried session must still carry");
}

/// The learned endpoint survives too. A peer whose NAT mapping was discovered
/// by a handshake would otherwise become unreachable on the next netmap poll —
/// and the netmap does not know the mapping, so nothing would restore it.
#[test]
fn a_learned_endpoint_survives_a_reconfiguration() {
    let a_cfg = Arc::new(config_for("recfg-ep-a", 0xA1, 0xB1, A_ADDR, None));
    let b_cfg = Arc::new(config_for("recfg-ep-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR)));

    let a = Engine::new(&a_cfg);
    let b = Engine::new(&b_cfg);

    // B dials A, so A learns B's endpoint from the handshake rather than from
    // configuration — the roster gave it none.
    assert_eq!(a.endpoint(0), None, "A starts with no endpoint for B");
    let msg1 = b.connect_all(0, seed);
    let msg2 = deliver(&a, B_ADDR.parse().unwrap(), msg1, 1);
    let _ = deliver(&b, A_ADDR.parse().unwrap(), msg2, 2);
    assert_eq!(
        a.endpoint(0),
        Some(B_ADDR.parse().unwrap()),
        "A must have learned it"
    );

    let same = Arc::new(config_for("recfg-ep-a2", 0xA1, 0xB1, A_ADDR, None));
    a.reconfigure(&same);

    assert_eq!(
        a.endpoint(0),
        Some(B_ADDR.parse().unwrap()),
        "a reconfiguration must not forget where a peer was last heard from"
    );
}

/// A peer that leaves the netmap is dropped, and its address stops routing.
#[test]
fn a_removed_peer_is_dropped() {
    let grown = Arc::new(config_with_two_peers("recfg-shrink", 0xA1, 0xB1, 0xC1));
    let a = Engine::new(&grown);
    assert_eq!(a.status().len(), 2);

    let shrunk = Arc::new(config_for("recfg-shrunk", 0xA1, 0xB1, A_ADDR, Some(B_ADDR)));
    let report = a.reconfigure(&shrunk);

    assert_eq!(report.removed, 1);
    assert_eq!(report.kept, 1);
    assert_eq!(a.status().len(), 1);
    assert_eq!(
        a.peer_for("10.77.0.3".parse().unwrap()),
        None,
        "the removed peer's address must stop routing"
    );
}

/// **A peer whose key changed is a different peer.** The KEM key is what a
/// handshake authenticates, so carrying a session across a key change would
/// mean talking to somebody else on keys agreed with the original.
#[test]
fn a_peer_whose_key_changed_gets_a_fresh_session() {
    let a_cfg = Arc::new(config_for("recfg-key-a", 0xA1, 0xB1, A_ADDR, Some(B_ADDR)));
    let b_cfg = Arc::new(config_for("recfg-key-b", 0xB1, 0xA1, B_ADDR, Some(A_ADDR)));

    let a = Engine::new(&a_cfg);
    let b = Engine::new(&b_cfg);
    establish(&a, &b);
    assert!(a.established(0));

    // Same name, same address, different key.
    let rekeyed = Arc::new(config_for("recfg-key-a2", 0xA1, 0xC1, A_ADDR, Some(B_ADDR)));
    let report = a.reconfigure(&rekeyed);

    assert_eq!(report.kept, 0, "a changed key is not the same peer");
    assert_eq!(report.added, 1);
    assert_eq!(report.removed, 1);
    assert!(
        !a.established(0),
        "the session must not be carried across a key change"
    );
}

/// **§7.3: a PSK epoch rotation completes with no session interruption.**
/// Tearing sessions down on rotation would turn a routine, scheduled event into
/// a fleet-wide reconnect — the outage the two-epoch rule exists to avoid.
#[test]
fn a_psk_epoch_rotation_does_not_interrupt_a_live_session() {
    let dir = Scratch::new("recfg-epoch");
    let key = dir.join("node.key");
    write600(&key, &private_of(0xA1));
    let kem = public_of(0xB1);
    let write_epoch = |epoch: u32, name: &str| {
        let toml = format!(
            r#"
[node]
listen = "{A_ADDR}"
interface = "karst0"
addresses = ["10.77.0.1/24"]
private_key_file = "node.key"
psk_epoch = {epoch}

[[peer]]
name = "other"
kem_public_key = "{kem}"
endpoint = "{B_ADDR}"
allowed_ips = ["10.77.0.2/32"]
"#
        );
        let path = dir.join(name);
        write600(&path, &toml);
        Arc::new(Config::load(&path).expect("config must load"))
    };

    let a_cfg = write_epoch(3, "epoch3.toml");
    let b_cfg = Arc::new(config_for(
        "recfg-epoch-b",
        0xB1,
        0xA1,
        B_ADDR,
        Some(A_ADDR),
    ));
    let a = Engine::new(&a_cfg);
    let b = Engine::new(&b_cfg);
    establish(&a, &b);
    assert!(a.established(0));

    let rotated = write_epoch(4, "epoch4.toml");
    let report = a.reconfigure(&rotated);

    assert!(report.epoch_rotated);
    assert_eq!(report.kept, 1);
    assert!(
        a.established(0),
        "a rotation must not tear the session down — §7.3 requires no interruption"
    );

    // And traffic keeps flowing on the keys derived from the *old* epoch.
    let out = deliver(
        &b,
        A_ADDR.parse().unwrap(),
        a.outbound(&packet([10, 77, 0, 1], [10, 77, 0, 2], b"rotated"), 200),
        201,
    );
    assert_eq!(
        out.packets.len(),
        1,
        "the session's keys stay valid across the rotation"
    );
}

/// §7.3's actual grace period: a *fresh* handshake landing during the window
/// where one node has rotated its epoch and the other has not — GitHub issue
/// #77. The test above only ever covers an *established* session surviving a
/// rearm; this is the case #77 was filed over, where nothing is established
/// yet and the two ends' `psk_epoch` genuinely disagree.
///
/// Modelled at the responder: `b`'s current epoch is one ahead of `a`'s, with
/// `psk_previous` on `b`'s side matching what `a`'s `psk` still is — the
/// state both ends are actually in for the seconds between the coordination
/// server rotating and every node's netmap catching up.
#[derive(Clone, Copy)]
struct EpochConfig<'a> {
    name: &'a str,
    me: u8,
    peer: u8,
    listen: &'a str,
    peer_endpoint: &'a str,
    epoch: u32,
    psk: &'a str,
    psk_previous: Option<&'a str>,
}

fn config_at_epoch(dir: &Scratch, p: EpochConfig<'_>) -> Arc<Config> {
    let key = dir.join(&format!("{}.key", p.name));
    write600(&key, &private_of(p.me));
    let kem = public_of(p.peer);
    let my_octet = if p.me == 0xA1 { 1 } else { 2 };
    let peer_octet = 3 - my_octet;
    let prev_line = p
        .psk_previous
        .map_or_else(String::new, |psk| format!("psk_previous = \"{psk}\"\n"));
    let toml = format!(
        r#"
[node]
listen = "{listen}"
interface = "karst0"
addresses = ["10.78.0.{my_octet}/24"]
private_key_file = "{name}.key"
psk_epoch = {epoch}

[[peer]]
name = "other"
kem_public_key = "{kem}"
psk = "{psk}"
{prev_line}endpoint = "{peer_endpoint}"
allowed_ips = ["10.78.0.{peer_octet}/32"]
"#,
        listen = p.listen,
        name = p.name,
        epoch = p.epoch,
        psk = p.psk,
        peer_endpoint = p.peer_endpoint,
    );
    let path = dir.join(&format!("{}.toml", p.name));
    write600(&path, &toml);
    Arc::new(Config::load(&path).expect("config must load"))
}

#[test]
fn a_fresh_handshake_survives_the_responder_being_one_epoch_ahead() {
    let dir = Scratch::new("epoch-race-behind");
    let psk_n_minus_1 = "77".repeat(32);
    let psk_n = "88".repeat(32);

    // A hasn't rotated: still offering epoch n-1 with the old PSK.
    let a_cfg = config_at_epoch(
        &dir,
        EpochConfig {
            name: "a",
            me: 0xA1,
            peer: 0xB1,
            listen: A_ADDR,
            peer_endpoint: B_ADDR,
            epoch: 6,
            psk: &psk_n_minus_1,
            psk_previous: None,
        },
    );
    // B has: current epoch n, but still holds n-1's PSK as `psk_previous`,
    // matching what a real netmap push carries during the grace window.
    let b_cfg = config_at_epoch(
        &dir,
        EpochConfig {
            name: "b",
            me: 0xB1,
            peer: 0xA1,
            listen: B_ADDR,
            peer_endpoint: A_ADDR,
            epoch: 7,
            psk: &psk_n,
            psk_previous: Some(&psk_n_minus_1),
        },
    );
    let a = Engine::new(&a_cfg);
    let b = Engine::new(&b_cfg);

    establish(&a, &b);

    assert!(
        a.established(0),
        "the initiator, one epoch behind, must still complete the handshake"
    );
    assert!(
        b.established(0),
        "the responder must accept epoch n-1 per §7.3, not just n"
    );
}

#[test]
fn a_handshake_two_epochs_behind_is_still_rejected() {
    let dir = Scratch::new("epoch-race-too-far");
    let psk_n_minus_2 = "66".repeat(32);
    let psk_n = "88".repeat(32);
    let psk_n_minus_1 = "77".repeat(32);

    // A offers epoch n-2 — neither of the two epochs B will accept.
    let a_cfg = config_at_epoch(
        &dir,
        EpochConfig {
            name: "a",
            me: 0xA1,
            peer: 0xB1,
            listen: A_ADDR,
            peer_endpoint: B_ADDR,
            epoch: 5,
            psk: &psk_n_minus_2,
            psk_previous: None,
        },
    );
    let b_cfg = config_at_epoch(
        &dir,
        EpochConfig {
            name: "b",
            me: 0xB1,
            peer: 0xA1,
            listen: B_ADDR,
            peer_endpoint: A_ADDR,
            epoch: 7,
            psk: &psk_n,
            psk_previous: Some(&psk_n_minus_1),
        },
    );
    let a = Engine::new(&a_cfg);
    let b = Engine::new(&b_cfg);

    let a_addr: SocketAddr = A_ADDR.parse().unwrap();
    let msg1 = a.connect_all(0, seed);
    let msg2 = deliver(&b, a_addr, msg1, 1);

    assert!(
        msg2.datagrams.is_empty(),
        "§7.3 requires rejecting anything but n and n-1 — a HandshakeResponse here would be the MUST's silent absence going unenforced"
    );
    assert!(!b.established(0));
}

/// A reconfiguration swaps the filter with the peer set, so a rule cannot end
/// up applied against the wrong peer.
#[test]
fn reconfiguring_swaps_the_filter_with_the_roster() {
    let a_cfg = Arc::new(config_for("recfg-filter", 0xA1, 0xB1, A_ADDR, Some(B_ADDR)));
    let a = Engine::new(&a_cfg);

    let mut denied = config_for("recfg-filter2", 0xA1, 0xB1, A_ADDR, Some(B_ADDR));
    with_filter(&mut denied, &[], &[]); // an empty policy: default deny
    let denied = Arc::new(denied);

    // Before: no policy source at all, so nothing is refused.
    let _ = a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 22), 10);
    assert_eq!(
        a.stats().acl_denied_out,
        0,
        "a roster has no policy, so nothing should have been refused yet"
    );

    a.reconfigure(&denied);
    let _ = a.outbound(&tcp_packet([10, 77, 0, 1], [10, 77, 0, 2], 22), 11);
    assert_eq!(
        a.stats().acl_denied_out,
        1,
        "the new filter must take effect with the new roster"
    );
}
