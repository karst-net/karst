// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Two nodes, two chains, one lying server — `spec/bedrock-v1.md` §5 layer 3,
//! plan §11's "equivocation" row.
//!
//! A hash chain proves the coordination server did not *edit* history. It does
//! not prove the server told everyone the *same* history: a compromised server
//! can maintain two valid chains and hand a different one to each node, and
//! **every check in §4 passes on both**. Layers 1 and 2 cannot see it, because
//! each node's idea of the head comes from the party being audited.
//!
//! So this test builds exactly that. Two genuinely valid chains, signed by
//! different roots, each verifying perfectly on its own. Two nodes, each given
//! one. They complete a real PHREATIC handshake, exchange head claims over it,
//! and both must notice.
//!
//! The handshake is real and driven in-process by shuttling datagrams between
//! two engines, the same way `dual_stack.rs` does. That matters: the property
//! under test is not `compare_head` — which has its own unit tests — but that
//! the claim is actually *emitted* when a session comes up, survives the
//! transport, and is routed to the comparison rather than to the host stack.
//! Every previous bug in this workstream that unit tests could not see was in
//! exactly that kind of wiring.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::Arc;

use karst_bedrock::{genesis_body, node_sign_body, Builder, Entry, Op, Signature};
use karst_control_client::handle::handle;
use karst_crypto::sign::{AuthorityKey, RootKey, ROOT_SEED};
use karst_noise::handshake::{PeerPublic, ResponderRandomness, StaticKeys};
use karstd::bedrock::Log;
use karstd::config::{Config, Peer};
use karstd::engine::{Engine, Via};
use karstd::routing::{AllowedIps, Prefix};

fn keys(seed: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[seed; 64], &[seed; 32]))
}

fn rand() -> ResponderRandomness {
    ResponderRandomness {
        e_dh_seed: [0x21; 32],
        encap_rand_e: [0x22; 32],
        encap_rand_s: [0x23; 32],
    }
}

fn seed(byte: u8) -> impl Fn() -> [u8; 32] {
    move || [byte; 32]
}

fn peer_endpoint(byte: u8) -> SocketAddr {
    match byte {
        0x31 => "192.0.2.10:51820".parse().expect("a"),
        _ => "192.0.2.20:51820".parse().expect("b"),
    }
}

struct Node {
    engine: Engine,
    endpoint: SocketAddr,
}

fn node(own: u8, peer: u8, own_range: &str, peer_range: &'static str) -> Node {
    let prefix: Prefix = peer_range.parse().expect("peer prefix");
    let peer_keys = keys(peer);
    let peers = vec![Peer {
        name: format!("peer{peer}"),
        node_id: handle(&[peer; 2592]).into_bytes(),
        public: Arc::new(PeerPublic {
            kem_pk: peer_keys.kem_pk.clone(),
            dh_pk: peer_keys.dh_pk,
            psk: [0x77; 32],
        }),
        endpoint: Some(peer_endpoint(peer)),
        allowed_ips: vec![prefix],
        psk_is_fallback: false,
        psk_previous: None,
        disco_key: None,
        home_relay: None,
    }];

    let config = Arc::new(Config {
        relay_ca_file: None,
        keys: keys(own),
        listen: "[::]:0".parse().expect("listen"),
        port_mapping: false,
        interface: format!("karst{own}"),
        network_mode: karstd::config::NetworkMode::Tun,
        dns: karstd::config::DnsSettings::default(),
        netmap_dns: karstd::netmap::DNSConfig::default(),
        userspace_socks5_listen: None,
        userspace_publish: Vec::new(),
        nat64: None,
        addresses: vec![own_range.parse().expect("interface address")],
        psk_epoch: 1,
        route_offers: Vec::new(),
        exit_node_state_file: None,
        node_id: handle(&[own; 2592]).into_bytes(),
        relays: Vec::new(),
        turn_servers: Vec::new(),
        peers,
        routes: AllowedIps::build(vec![(prefix, 0)]).expect("no conflicts"),
        skipped: Vec::new(),
        filter: karstd::filter::PacketFilter::unrestricted(),
    });

    Node {
        engine: Engine::new(&config),
        endpoint: peer_endpoint(own),
    }
}

/// Shuttle datagrams between the two engines until nothing more is produced.
///
/// A queue rather than the two-deep nesting `dual_stack.rs` uses, because the
/// head claim is emitted *in reply to a reply*: the initiator reaches
/// `Action::Established` while processing the responder's handshake response,
/// so its claim appears in the `Output` of an `inbound` call that a
/// send-and-collect-the-answer helper discards. Getting that wrong is what made
/// this test first report the divergence on one side only.
fn pump(a: &Node, b: &Node, out: karstd::engine::Output, to_b: bool, now: u64) {
    // (destined_for_b, datagram)
    let mut queue: Vec<(bool, Vec<u8>)> = out
        .datagrams
        .into_iter()
        .filter(|(_, via)| matches!(via, Via::Direct(_)))
        .map(|(d, _)| (to_b, d))
        .collect();

    // Bounded so a pump that never quiesces fails as a test rather than hanging.
    for _ in 0..256 {
        let Some((for_b, datagram)) = queue.pop() else {
            return;
        };
        let (target, source) = if for_b { (b, a) } else { (a, b) };
        let produced = target
            .engine
            .inbound(&datagram, source.endpoint, now, &rand());
        for (datagram, via) in produced.datagrams {
            if matches!(via, Via::Direct(_)) {
                queue.push((!for_b, datagram));
            }
        }
    }
    panic!("the datagram pump did not settle");
}

/// Drive both ends to an established session, then keep pumping.
///
/// The extra rounds are the point: the head claim is emitted on
/// `Action::Established`, which happens *during* the round that completes the
/// handshake, so its datagram is still in flight when `established()` first
/// returns true. Stopping there would test that the claim was built and never
/// that it arrived.
fn establish(a: &Node, b: &Node) {
    let mut now = 0;
    for round in 0..16 {
        pump(a, b, a.engine.connect_all(now, seed(0x31)), true, now);
        pump(a, b, b.engine.connect_all(now, seed(0x32)), false, now);
        pump(a, b, a.engine.poll(now, seed(0x33)), true, now);
        pump(a, b, b.engine.poll(now, seed(0x34)), false, now);
        if a.engine.established(0) && b.engine.established(0) && round >= 2 {
            return;
        }
        now += 400 * (round + 1);
    }
    panic!(
        "no session after 16 rounds: a={} b={}",
        a.engine.established(0),
        b.engine.established(0)
    );
}

/// A complete, valid chain whose root is derived from `seed`.
///
/// Two chains built with different seeds are both perfectly valid and share no
/// entry hash at any sequence — which is exactly what a server maintaining two
/// histories produces.
fn chain(seed: u8) -> Log {
    let root = RootKey::from_seed(&[seed; ROOT_SEED]).expect("root");
    let authority = AuthorityKey::from_seed(&[seed; 32]).expect("authority");

    let mut b = Builder::new();
    let (entry, input) = b.prepare(
        1000,
        Op::Genesis,
        genesis_body(
            "aquifer.karst.",
            &[root.public_key()],
            1,
            &[authority.public_key()],
            1,
            &[],
        ),
    );
    b.commit(
        entry,
        vec![Signature {
            signer_index: 0,
            sig: root.sign(&input).expect("sign genesis"),
        }],
    )
    .expect("commit genesis");

    // One covered node, so the chains are two entries long and the comparison
    // has a common sequence above genesis to disagree at.
    // A pattern, not a real ML-DSA-87 key: nothing verifies a signature under a
    // node's identity key, so the chain checks only its length and that the
    // handle derives to it.
    let identity = vec![seed ^ 0xFF; karst_crypto::sign::NODE_IDENTITY_KEY];
    let (entry, input) = b.prepare(
        1100,
        Op::NodeSign,
        node_sign_body(
            &handle(&identity),
            &identity,
            &vec![seed; 1184],
            &[seed; 32],
            0,
            0,
        ),
    );
    b.commit(
        entry,
        vec![Signature {
            signer_index: 0,
            sig: authority.sign(&input).expect("sign node"),
        }],
    )
    .expect("commit node-sign");

    let entries: Vec<Entry> = b.into_entries();
    let mut log = Log::new();
    log.extend(entries).expect("the fixture chain must verify");
    log
}

fn pair() -> (Node, Node) {
    (
        node(0x31, 0x32, "10.60.0.1/24", "10.60.0.2/32"),
        node(0x32, 0x31, "10.60.0.2/24", "10.60.0.1/32"),
    )
}

/// **The property.** A server that served two histories is caught by the two
/// nodes talking to each other, with the server nowhere in the conversation.
#[test]
fn two_nodes_given_different_chains_both_detect_it() {
    let (a, b) = pair();

    // Each chain verifies on its own. That is what makes this equivocation
    // rather than corruption: nothing either node can check by itself is wrong.
    let chain_a = chain(0x10);
    let chain_b = chain(0x20);
    assert!(chain_a.state().is_some(), "chain A must verify");
    assert!(chain_b.state().is_some(), "chain B must verify");
    assert_ne!(
        chain_a.head(),
        chain_b.head(),
        "the fixture built the same chain twice, so this test proves nothing"
    );
    assert_eq!(chain_a.verified_seq(), chain_b.verified_seq());

    a.engine.set_bedrock(Arc::new(chain_a));
    b.engine.set_bedrock(Arc::new(chain_b));

    establish(&a, &b);

    assert!(
        a.engine.stats().bedrock_equivocation > 0,
        "node A did not detect the divergence"
    );
    assert!(
        b.engine.stats().bedrock_equivocation > 0,
        "node B did not detect the divergence"
    );
}

/// **And the session stays up.** Both nodes verified their peer against a valid
/// chain; the fault is the server's. Tearing the link down would be a
/// self-inflicted outage on exactly the network an operator needs in order to
/// investigate, so the response is a loud alarm and nothing else.
#[test]
fn a_divergence_does_not_close_the_session() {
    let (a, b) = pair();
    a.engine.set_bedrock(Arc::new(chain(0x10)));
    b.engine.set_bedrock(Arc::new(chain(0x20)));

    establish(&a, &b);
    assert!(a.engine.stats().bedrock_equivocation > 0);

    assert!(
        a.engine.established(0) && b.engine.established(0),
        "the session was closed over a divergence"
    );

    // And it still carries traffic.
    let packet = {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[9] = 1; // ICMP
        p[12..16].copy_from_slice(&[10, 60, 0, 1]);
        p[16..20].copy_from_slice(&[10, 60, 0, 2]);
        p
    };
    let before = b.engine.stats().rx_packets;
    pump(&a, &b, a.engine.outbound(&packet, 9_000), true, 9_000);
    assert!(
        b.engine.stats().rx_packets > before,
        "traffic stopped flowing after a divergence was reported"
    );
}

/// Two nodes on the **same** chain agree, and nothing is reported.
///
/// The counterpart to the test above: an alarm that fires when nothing is wrong
/// is one an operator learns to ignore, which would cost the alarm its value at
/// the moment it mattered.
#[test]
fn two_nodes_on_one_chain_agree_silently() {
    let (a, b) = pair();
    a.engine.set_bedrock(Arc::new(chain(0x10)));
    b.engine.set_bedrock(Arc::new(chain(0x10)));

    establish(&a, &b);

    assert_eq!(
        a.engine.stats().bedrock_equivocation,
        0,
        "agreement was reported as equivocation"
    );
    assert_eq!(b.engine.stats().bedrock_equivocation, 0);
    assert!(
        a.engine.stats().bedrock_head_agreed > 0 && b.engine.stats().bedrock_head_agreed > 0,
        "the head exchange did not happen at all, so neither test above proves anything"
    );
}

/// A node with no verified log says nothing and accuses nobody.
///
/// Most deployments never turn Bedrock on, so this is the common path: no
/// claim goes out, and a claim that arrives from a peer cannot be compared
/// against anything.
#[test]
fn a_node_without_a_log_neither_claims_nor_accuses() {
    let (a, b) = pair();
    a.engine.set_bedrock(Arc::new(chain(0x10)));
    // b gets nothing.

    establish(&a, &b);

    assert_eq!(b.engine.stats().bedrock_equivocation, 0);
    assert_eq!(b.engine.stats().bedrock_head_agreed, 0);
    // A hears nothing from B, so it has nothing to compare either.
    assert_eq!(a.engine.stats().bedrock_equivocation, 0);
}
