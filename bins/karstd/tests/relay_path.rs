// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Two nodes talk through a relay, then upgrade to a direct path.
//!
//! **This is the test that makes "relay fallback" mean something.** Every part
//! of the relay path had tests before this one: the Ponor codec, the handshake
//! state machines, the node-side session, the TLS listener. What none of them
//! could see is whether PHREATIC actually *uses* the relay — for a long time it
//! did not, and the relay carried discovery messages for a data plane that
//! quietly dropped every packet to a peer it had no address for.
//!
//! So this drives two [`Engine`]s and moves their datagrams between them by
//! hand. There is no relay process: the relay's job on the data path is to
//! forward opaque bytes to a named node, and `forward` here is those four lines.
//! What is under test is the two ends — that they choose the relay when there is
//! no direct path, that a handshake completes over it, that traffic flows, and
//! that a direct path displaces it without dropping the session.
//!
//! Nothing here calls `set_endpoint` to fake a path except where a test says it
//! is standing in for AVEN, which has its own end-to-end test in
//! `rendezvous.rs`.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::Arc;

use karst_control_client::handle;
use karst_noise::handshake::{ResponderRandomness, StaticKeys};
use karstd::config::{Config, Peer};
use karstd::engine::{Engine, Transport, Via};
use karstd::netmap::Relay;
use karstd::routing::{AllowedIps, Prefix};

/// Deterministic randomness. These are tests of routing and framing, not of
/// entropy, and a fixed seed makes a failure reproduce.
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

/// A node's static keys, derived from one byte so each node differs.
fn keys(byte: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[byte; 64], &[byte; 32]))
}

/// A relay registry entry. Only the node-facing fields matter here; nothing in
/// this test opens a socket.
fn relay() -> Relay {
    use sha2::{Digest as _, Sha256};
    let identity_key = vec![0x44; 1952];
    let mut h = Sha256::new();
    h.update(b"karst-relay-id-v1");
    h.update(&identity_key);
    Relay {
        address: "127.0.0.1:443".to_owned(),
        tls_server_name: "relay.test".to_owned(),
        relay_id: h.finalize().into(),
        identity_key,
        region: "test".to_owned(),
    }
}

/// One node and the peers it holds.
struct Node {
    engine: Engine,
    /// The roster the engine was built from, for driving discovery over it.
    config: Arc<Config>,
    /// This node's Ponor id, which is what the relay stamps on what it sends.
    id: [u8; 32],
}

/// One peer, as the netmap would describe it.
struct PeerSpec {
    /// Seed byte, which decides the peer's keys and its control handle.
    byte: u8,
    /// What the netmap configured. `None` is the case this file exists for: a
    /// peer known by identity with no address to reach it at.
    endpoint: Option<SocketAddr>,
    /// The range this peer owns.
    range: &'static str,
    /// The AVEN pair key, when the netmap supplies one. `None` means no
    /// discovery for this peer, ever (`aven-v1.md` §5.1).
    disco_key: Option<[u8; 32]>,
}

/// The Ponor node id a seed byte produces, for stamping a relayed datagram.
fn id_of(byte: u8) -> [u8; 32] {
    karst_control_client::handle_bytes(&handle(&[byte; 1952])).expect("a handle decodes")
}

fn node(own: u8, own_range: &str, specs: &[PeerSpec], with_relay: bool) -> Node {
    let own_handle = handle(&[own; 1952]);
    let mut peers = Vec::with_capacity(specs.len());
    let mut pairs = Vec::with_capacity(specs.len());

    for (index, spec) in specs.iter().enumerate() {
        let peer_keys = keys(spec.byte);
        let prefix: Prefix = spec.range.parse().expect("peer prefix");
        pairs.push((prefix, index));
        peers.push(Peer {
            name: format!("peer{}", spec.byte),
            node_id: handle(&[spec.byte; 1952]).into_bytes(),
            public: Arc::new(karst_noise::handshake::PeerPublic {
                kem_pk: peer_keys.kem_pk.clone(),
                dh_pk: peer_keys.dh_pk,
                psk: [0x77; 32],
            }),
            endpoint: spec.endpoint,
            allowed_ips: vec![prefix],
            psk_is_fallback: false,
            disco_key: spec.disco_key,
        });
    }

    let config = Config {
        relay_ca_file: None,
        keys: keys(own),
        listen: "0.0.0.0:0".parse().expect("listen"),
        port_mapping: true,
        interface: format!("karst{own}"),
        addresses: vec![own_range.parse().expect("interface address")],
        psk_epoch: 1,
        node_id: own_handle.clone().into_bytes(),
        relays: if with_relay {
            vec![relay()]
        } else {
            Vec::new()
        },
        peers,
        routes: AllowedIps::build(pairs).expect("no conflicts"),
        skipped: Vec::new(),
        filter: karstd::filter::PacketFilter::unrestricted(),
    };

    let config = Arc::new(config);
    Node {
        engine: Engine::new(&config),
        config,
        id: id_of(own),
    }
}

/// The common shape: one peer, no configured endpoint.
fn pair(own: u8, peer: u8, peer_range: &'static str, own_range: &str, with_relay: bool) -> Node {
    node(
        own,
        own_range,
        &[PeerSpec {
            byte: peer,
            endpoint: None,
            range: peer_range,
            disco_key: None,
        }],
        with_relay,
    )
}

/// An ICMP-shaped IPv4 packet from `src` to `dst`, big enough to be real and
/// small enough to read in a failure message.
fn packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    let total = u16::try_from(p.len()).expect("small");
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p
}

/// The relay: forward every relayed datagram to the far end, stamped with the
/// sender's node id. Returns how many it carried.
///
/// Direct datagrams are **not** carried, deliberately. A test that quietly
/// delivered them either way could not tell a working relay path from a working
/// direct one, which is the only thing this file is trying to establish.
fn forward(from: &Node, to: &Node, out: karstd::engine::Output, now: u64) -> usize {
    let mut carried = 0;
    for (datagram, via) in out.datagrams {
        let Via::Relay(destination) = via else {
            continue;
        };
        assert_eq!(destination, to.id, "the relay was asked for the wrong node");
        let reply = to
            .engine
            .inbound_from_relay(from.id, &datagram, now, &rand());
        carried += 1;
        // Whatever the far end says back travels the same way.
        for (datagram, via) in reply.datagrams {
            if let Via::Relay(back) = via {
                assert_eq!(back, from.id);
                let _ = from
                    .engine
                    .inbound_from_relay(to.id, &datagram, now, &rand());
            }
        }
    }
    carried
}

/// Run handshakes until both ends are established, or give up.
fn establish(a: &Node, b: &Node) {
    let mut now = 0;
    for round in 0..12 {
        forward(a, b, a.engine.connect_all(now, seed(0x31)), now);
        forward(b, a, b.engine.connect_all(now, seed(0x32)), now);
        forward(a, b, a.engine.poll(now, seed(0x33)), now);
        forward(b, a, b.engine.poll(now, seed(0x34)), now);
        if a.engine.established(0) && b.engine.established(0) {
            return;
        }
        now += 400 * (round + 1);
    }
    panic!(
        "no session after 12 rounds: a={} b={}",
        a.engine.established(0),
        b.engine.established(0)
    );
}

/// **A peer with no address is reached through the relay, not dropped.** This
/// is the whole of finding 12: before it, `outbound` asked for an endpoint,
/// found none, and counted the packet as undeliverable — so a peer the
/// coordination server knew about, whose keys were held, and which was online,
/// was simply unreachable.
#[test]
fn a_peer_with_no_endpoint_is_reachable_through_the_relay() {
    let a = pair(0x01, 0x02, "100.64.0.2/32", "100.64.0.1/24", true);
    let b = pair(0x02, 0x01, "100.64.0.1/32", "100.64.0.2/24", true);

    establish(&a, &b);

    let sent = a
        .engine
        .outbound(&packet([100, 64, 0, 1], [100, 64, 0, 2]), 1_000);
    assert!(!sent.datagrams.is_empty(), "the packet was dropped");
    assert!(
        sent.datagrams
            .iter()
            .all(|(_, via)| matches!(via, Via::Relay(_))),
        "a peer with no endpoint was sent something directly"
    );

    let carried = forward(&a, &b, sent, 1_000);
    assert_eq!(carried, 1);
    assert_eq!(a.engine.stats().tx_packets, 1);
    assert_eq!(
        b.engine.stats().rx_packets,
        1,
        "the relayed packet never reached the far end's host"
    );
}

/// The same node with no relay configured drops the packet, which is the
/// behaviour before this work and still correct when there is nowhere to send.
/// Without this the test above would pass on a build that relayed everything.
#[test]
fn a_peer_with_no_endpoint_and_no_relay_is_still_undeliverable() {
    let a = pair(0x01, 0x02, "100.64.0.2/32", "100.64.0.1/24", false);
    let out = a.engine.connect_all(0, seed(0x31));
    assert!(
        out.datagrams.is_empty(),
        "a node with no relay dialled a peer it has no address for"
    );

    let sent = a
        .engine
        .outbound(&packet([100, 64, 0, 1], [100, 64, 0, 2]), 0);
    assert!(sent.datagrams.is_empty());
    assert_eq!(a.engine.stats().tx_dropped_no_session, 1);
}

/// **The upgrade, and the part that has to be seamless: the session survives
/// it.** A relay→direct transition that rehandshaked would be a visible stall
/// on every path change, and path changes are exactly what AVEN produces.
#[test]
fn a_direct_path_displaces_the_relay_without_disturbing_the_session() {
    let a = pair(0x01, 0x02, "100.64.0.2/32", "100.64.0.1/24", true);
    let b = pair(0x02, 0x01, "100.64.0.1/32", "100.64.0.2/24", true);
    establish(&a, &b);

    let relayed = a
        .engine
        .outbound(&packet([100, 64, 0, 1], [100, 64, 0, 2]), 1_000);
    assert!(relayed
        .datagrams
        .iter()
        .all(|(_, via)| matches!(via, Via::Relay(_))));

    // Standing in for AVEN confirming a path — `rendezvous.rs` covers how one
    // is actually found.
    let direct: SocketAddr = "203.0.113.2:51820".parse().expect("endpoint");
    assert!(a.engine.set_endpoint(0, direct));

    assert!(
        a.engine.established(0),
        "installing a direct path tore down the session"
    );
    let after = a
        .engine
        .outbound(&packet([100, 64, 0, 1], [100, 64, 0, 2]), 1_100);
    assert!(
        after
            .datagrams
            .iter()
            .all(|(_, via)| matches!(via, Via::Direct(addr) if *addr == direct)),
        "the direct path did not displace the relay"
    );

    // And back again, which is the half that used to have no expression at all:
    // a released path must return the peer to the relay rather than to nothing.
    assert!(a.engine.release_endpoint(0, direct));
    let released = a
        .engine
        .outbound(&packet([100, 64, 0, 1], [100, 64, 0, 2]), 1_200);
    assert!(
        released
            .datagrams
            .iter()
            .all(|(_, via)| matches!(via, Via::Relay(_))),
        "releasing a direct path left the peer unreachable instead of relayed"
    );
    assert!(a.engine.established(0), "the round trip cost the session");
}

/// A relay is not trusted to say who sent something. It authenticated the
/// sender under Ponor, and this end checks that claim against the one the
/// handshake's own AEAD resolves — two independent bindings that must agree.
///
/// **The case that matters is a peer this node already holds**, not a stranger.
/// A stranger's id resolves to nothing and is refused by the lookup alone, so a
/// test using one passes with the comparison deleted. The attack is C —
/// admitted by the same relay, holding its own keys with this node — replaying
/// A's handshake under C's identity.
#[test]
fn one_peer_cannot_replay_anothers_handshake_under_its_own_identity() {
    let a = pair(0x01, 0x02, "100.64.0.2/32", "100.64.0.1/24", true);
    // B holds both A and C.
    let b = node(
        0x02,
        "100.64.0.2/24",
        &[
            PeerSpec {
                byte: 0x01,
                endpoint: None,
                range: "100.64.0.1/32",
                disco_key: None,
            },
            PeerSpec {
                byte: 0x03,
                endpoint: None,
                range: "100.64.0.3/32",
                disco_key: None,
            },
        ],
        true,
    );

    let init = a.engine.connect_all(0, seed(0x31));
    assert!(!init.datagrams.is_empty());

    // Stamped as C: the AEAD resolves A, the relay says C, so it is refused.
    for (datagram, _) in &init.datagrams {
        let _ = b
            .engine
            .inbound_from_relay(id_of(0x03), datagram, 0, &rand());
    }
    assert!(
        !b.engine.established(0) && !b.engine.established(1),
        "one peer replayed another's handshake under its own relay identity"
    );

    // A node id B holds no peer for at all, refused one step earlier.
    for (datagram, _) in &init.datagrams {
        let _ = b
            .engine
            .inbound_from_relay([0x9E; 32], datagram, 0, &rand());
    }
    assert!(!b.engine.established(0) && !b.engine.established(1));

    // And under the right source it works, so the refusals above were the
    // checks rather than a broken fixture.
    for (datagram, _) in &init.datagrams {
        let out = b.engine.inbound_from_relay(a.id, datagram, 0, &rand());
        assert!(
            out.datagrams
                .iter()
                .all(|(_, via)| matches!(via, Via::Relay(back) if *back == a.id)),
            "the response to a relayed handshake did not go back over the relay"
        );
    }
}

/// Status has to say how each peer is reached. A relayed peer works, and works
/// through a third party that sees its traffic timing (§9) — an operator
/// cannot tell that from the outside.
#[test]
fn status_reports_how_each_peer_is_reached() {
    let transport = |node: &Node| node.engine.status().first().expect("one peer").transport;

    let a = pair(0x01, 0x02, "100.64.0.2/32", "100.64.0.1/24", true);
    assert_eq!(
        transport(&a),
        Transport::Relay,
        "a peer with no direct path was not reported as relayed"
    );

    assert!(a
        .engine
        .set_endpoint(0, "203.0.113.2:51820".parse().unwrap()));
    assert_eq!(
        transport(&a),
        Transport::Direct,
        "a peer with a direct path was reported as relayed"
    );

    // **"relayed" and "no path at all" are different problems**, and the bool
    // this replaced merged the second into the healthy case. A node with no
    // relay and no address for a peer knows about it and cannot reach it, which
    // is the one an operator has to act on.
    let stranded = pair(0x01, 0x02, "100.64.0.2/32", "100.64.0.1/24", false);
    assert_eq!(transport(&stranded), Transport::Unreachable);
}

/// **Finding 15, end to end and through the real wiring.** A netmap that
/// publishes an endpoint for a peer, where that endpoint has since stopped
/// working: the node must end up on the relay rather than sending into a hole.
///
/// The path this exercises is the one that was broken — `Disco::reconcile`
/// adopting the configured endpoint, discovery giving up on it, and the
/// withdrawal reaching `Engine::via`. A test that called `add_peer_at` directly
/// would skip the adoption and pass without it, which the mutation check
/// caught.
#[test]
fn a_published_endpoint_that_has_gone_stale_falls_back_to_the_relay() {
    use karst_disco::msg::TxId;
    use karstd::disco::{Disco, PathChange};

    let stale: SocketAddr = "203.0.113.9:51820".parse().expect("endpoint");
    let node = node(
        0x01,
        "100.64.0.1/24",
        &[PeerSpec {
            byte: 0x02,
            endpoint: Some(stale),
            range: "100.64.0.2/32",
            disco_key: Some([0x5A; 32]),
        }],
        true,
    );

    // The datapath starts on the published address, which is the behaviour to
    // preserve: until discovery has evidence, the control plane is right.
    assert_eq!(node.engine.endpoint(0), Some(stale));
    assert_eq!(
        node.engine.status().first().expect("one peer").transport,
        Transport::Direct
    );

    let mut disco = Disco::new(node.config.psk_epoch);
    disco.reconcile(&node.config, 0);
    assert_eq!(disco.peer_count(), 1, "the peer's disco key was not loaded");

    // Nothing answers the probes. Walk §7.5's schedule to its end.
    let mut n = 0u8;
    let mut mint = || {
        n = n.wrapping_add(1);
        TxId([n; 12])
    };
    let mut released = None;
    for now in [0, 100, 400, 1_300, 2_000, 3_000] {
        let _ = disco.poll(now, &mut mint);
        for change in disco.path_changes() {
            if let PathChange::Release { peer, installed } = change {
                assert_eq!(peer, 0);
                assert_eq!(installed, stale);
                assert!(node.engine.release_endpoint(peer, installed));
                released = Some(now);
            }
        }
    }

    assert!(
        released.is_some(),
        "discovery never withdrew a published endpoint that answers nothing"
    );
    assert_eq!(node.engine.endpoint(0), None);
    assert_eq!(
        node.engine.status().first().expect("one peer").transport,
        Transport::Relay,
        "the peer did not fall back to the relay"
    );
}
