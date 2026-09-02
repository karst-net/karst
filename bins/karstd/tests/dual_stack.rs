// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! What a node bound to `[::]` sees, and whether it can still talk to IPv4.
//!
//! **`node.listen` decides the datapath's address family, and that is the whole
//! of Karst's IPv6 story.** §4 gives the datapath one shared socket; the
//! operator picks its family by writing an address. `0.0.0.0` is an `AF_INET`
//! socket, which cannot send to an IPv6 candidate at all — the kernel refuses
//! with `EAFNOSUPPORT` and [`dispatch`] drops the error, because a send failure
//! must not take the daemon down. So the only configuration that can use an
//! IPv6 path is `[::]`, and `aven-v1.md`'s candidate encoding carries IPv6
//! addresses precisely so that it can.
//!
//! A dual-stack socket reaches both families, but it does not report both the
//! same way: **a datagram from an IPv4 peer arrives with a v4-mapped source**,
//! `[::ffff:a.b.c.d]:port`, and Rust's `SocketAddr` has no idea that is the
//! same place as `a.b.c.d:port`. `SocketAddr::V4(x) == SocketAddr::V6(mapped)`
//! is false, always.
//!
//! That is what this file is about, and it is not a hypothetical: the engine
//! attributes a transport datagram to a peer by comparing its source address
//! against the endpoints it holds, hands the same address back as
//! `Pong.observed`, and prints it in `karst status`.
//!
//! **Two layers, because neither sees the other's half.**
//! `karst-transport`'s `a_dual_stack_socket_reports_an_ipv4_peer_at_its_ipv4_address`
//! binds real sockets and pins what the *kernel* does — that the mapped source
//! is real, and that `UdpTransport` normalizes it away. This file drives two
//! engines with no socket at all and pins what the daemon *does with* the
//! result. It models the receive path through the same
//! [`karst_transport::canonical`] the daemon calls, so removing that call fails
//! both files: the socket test because the address arrives mapped, this one
//! because the engine then records it.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use karst_control_client::handle;
use karst_noise::handshake::{ResponderRandomness, StaticKeys};
use karstd::config::{Config, Peer};
use karstd::engine::{Engine, Via};
use karstd::routing::{AllowedIps, Prefix};

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

fn keys(byte: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[byte; 64], &[byte; 32]))
}

/// How the receiving socket reports a source address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Family {
    /// An `AF_INET` socket: the source is reported exactly as it was sent.
    V4Only,
    /// An `AF_INET6` dual-stack socket, which is what `listen = "[::]:…"`
    /// produces on Linux with the default `bindv6only=0`. An IPv4 peer's
    /// datagrams arrive from `[::ffff:a.b.c.d]`.
    DualStack,
}

impl Family {
    /// The source address the daemon is handed for a datagram sent from
    /// `addr`: what the kernel reports, then what the transport layer makes
    /// of it.
    ///
    /// The second step is the daemon's own line, called here rather than
    /// reimplemented — a test that normalized addresses its own way would pass
    /// while the daemon did not.
    fn reports(self, addr: SocketAddr) -> SocketAddr {
        let from_kernel = match (self, addr.ip()) {
            (Self::DualStack, IpAddr::V4(v4)) => {
                SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), addr.port())
            }
            _ => addr,
        };
        karst_transport::canonical(from_kernel)
    }
}

struct Node {
    engine: Engine,
    /// Where this node's datagrams come *from*, as its peer's socket would see
    /// them before that socket's family is applied.
    endpoint: SocketAddr,
}

/// One node holding one peer, each with a configured IPv4 endpoint.
fn node(own: u8, peer: u8, own_range: &str, peer_range: &'static str, own_at: &str) -> Node {
    let prefix: Prefix = peer_range.parse().expect("peer prefix");
    let peer_keys = keys(peer);
    let peers = vec![Peer {
        name: format!("peer{peer}"),
        node_id: handle(&[peer; 2592]).into_bytes(),
        public: Arc::new(karst_noise::handshake::PeerPublic {
            kem_pk: peer_keys.kem_pk.clone(),
            dh_pk: peer_keys.dh_pk,
            psk: [0x77; 32],
        }),
        // The other node's IPv4 endpoint, exactly as a netmap would carry it.
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
        node_id: handle(&[own; 2592]).into_bytes(),
        relays: Vec::new(),
        peers,
        routes: AllowedIps::build(vec![(prefix, 0)]).expect("no conflicts"),
        skipped: Vec::new(),
        filter: karstd::filter::PacketFilter::unrestricted(),
    });

    Node {
        engine: Engine::new(&config),
        endpoint: own_at.parse().expect("own endpoint"),
    }
}

/// The IPv4 endpoint a seed byte owns. Two ordinary IPv4 nodes.
fn peer_endpoint(byte: u8) -> SocketAddr {
    match byte {
        0x31 => "192.0.2.10:51820".parse().expect("a"),
        _ => "192.0.2.20:51820".parse().expect("b"),
    }
}

/// Carry every *direct* datagram to the far end, reporting its source the way
/// `to`'s socket family would.
fn carry(from: &Node, to: &Node, out: karstd::engine::Output, family: Family, now: u64) -> usize {
    let mut carried = 0;
    for (datagram, via) in out.datagrams {
        let Via::Direct(_) = via else {
            continue;
        };
        let source = family.reports(from.endpoint);
        let reply = to.engine.inbound(&datagram, source, now, &rand());
        carried += 1;
        for (datagram, via) in reply.datagrams {
            if matches!(via, Via::Direct(_)) {
                let back = Family::V4Only.reports(to.endpoint);
                let _ = from.engine.inbound(&datagram, back, now, &rand());
            }
        }
    }
    carried
}

fn establish(a: &Node, b: &Node, family: Family) {
    let mut now = 0;
    for round in 0..12 {
        carry(a, b, a.engine.connect_all(now, seed(0x31)), family, now);
        carry(
            b,
            a,
            b.engine.connect_all(now, seed(0x32)),
            Family::V4Only,
            now,
        );
        carry(a, b, a.engine.poll(now, seed(0x33)), family, now);
        carry(b, a, b.engine.poll(now, seed(0x34)), Family::V4Only, now);
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

fn pair() -> (Node, Node) {
    (
        node(
            0x31,
            0x32,
            "10.60.0.1/24",
            "10.60.0.2/32",
            "192.0.2.10:51820",
        ),
        node(
            0x32,
            0x31,
            "10.60.0.2/24",
            "10.60.0.1/32",
            "192.0.2.20:51820",
        ),
    )
}

/// **The control: two IPv4 sockets, which is every other test in this tree.**
///
/// Without it the row below could fail for any reason at all — a broken helper,
/// a bad packet, a roster that does not route — and be read as evidence about
/// address families. This is the same conversation with the same helpers and
/// the only difference is how the source address is reported.
#[test]
fn two_ipv4_nodes_carry_traffic_over_a_direct_path() {
    let (a, b) = pair();
    establish(&a, &b, Family::V4Only);

    let out = a
        .engine
        .outbound(&packet([10, 60, 0, 1], [10, 60, 0, 2]), 0);
    assert_eq!(
        carry(&a, &b, out, Family::V4Only, 0),
        1,
        "the packet was not sent directly"
    );
    assert_eq!(
        b.engine.stats().rx_packets,
        1,
        "an IPv4 socket did not deliver an IPv4 peer's packet"
    );
}

/// **A dual-stack node still carries its IPv4 peers' traffic.**
///
/// `listen = "[::]:51820"` is the only configuration that can use an IPv6 path,
/// because an `AF_INET` socket cannot send to an IPv6 address at all. It is
/// therefore the configuration a dual-stack deployment writes — and every IPv4
/// peer's datagrams then arrive from `[::ffff:a.b.c.d]` rather than from
/// `a.b.c.d`.
///
/// **Delivery was expected to be where this broke, and it is not** — recorded
/// because the wrong guess is instructive. The engine attributes a transport
/// datagram by comparing its source against the endpoint it holds, and
/// `SocketAddr::V4(x) == SocketAddr::V6(mapped)` is false, so that looked like
/// a node which establishes and then drops everything. It does not, for a
/// reason that is worse rather than better: accepting the handshake *records
/// the source address as the peer's endpoint*, so the comparison is
/// mapped-against-mapped and matches. The mapped address is consistent
/// everywhere inside this node and wrong everywhere outside it — which is the
/// row below.
#[test]
fn a_dual_stack_node_carries_traffic_from_a_peer_that_arrives_v4_mapped() {
    let (a, b) = pair();
    establish(&a, &b, Family::DualStack);

    let out = a
        .engine
        .outbound(&packet([10, 60, 0, 1], [10, 60, 0, 2]), 0);
    assert_eq!(
        carry(&a, &b, out, Family::DualStack, 0),
        1,
        "the packet was not sent directly"
    );
    assert_eq!(
        b.engine.stats().rx_packets,
        1,
        "a dual-stack node dropped an IPv4 peer's packet"
    );
}

/// The session is what makes the row above worth having: it establishes either
/// way, so nothing an operator can see distinguishes the two cases.
#[test]
fn the_session_establishes_either_way_which_is_why_this_is_quiet() {
    for family in [Family::V4Only, Family::DualStack] {
        let (a, b) = pair();
        establish(&a, &b, family);
        assert!(
            a.engine.established(0) && b.engine.established(0),
            "{family:?} did not establish"
        );
    }
}

/// **The defect, and the reason it is High rather than cosmetic.**
///
/// A peer's endpoint, once learned, is not private to the node that learned it.
/// It is printed by `karst status`, compared against by `set_endpoint`, handed
/// to `add_peer_candidate` as a path — and, the one that does the damage,
/// echoed straight back as AVEN's `Pong.observed`, which is how a node is told
/// its own reflexive address (`aven-v1.md` §7.2). A node told its reflexive
/// address is `[::ffff:a.b.c.d]` advertises that to the whole aquifer, and a
/// peer whose socket is `AF_INET` cannot send to it at all: the kernel refuses
/// with `EAFNOSUPPORT` and `dispatch` drops the error, deliberately, because a
/// send failure must not take the daemon down.
///
/// So one dual-stack node in a mesh of IPv4 nodes can make an IPv4 node
/// unreachable, and every symptom of it is silence.
#[test]
fn a_peer_that_arrives_v4_mapped_is_recorded_at_its_ipv4_address() {
    let (a, b) = pair();
    establish(&a, &b, Family::DualStack);
    let endpoint = b.engine.endpoint(0).expect("b holds an endpoint for a");
    assert_eq!(
        endpoint,
        peer_endpoint(0x31),
        "b recorded its IPv4 peer at {endpoint}, which is not an address any \
         IPv4 node can reach"
    );
}
