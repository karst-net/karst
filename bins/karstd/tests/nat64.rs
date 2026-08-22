// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! What a NAT64 node tells its peers about *them*.
//!
//! On a NAT64 network every IPv4 peer is reached at `prefix::v4`, and every
//! datagram from one arrives with `prefix::v4` as its source. That address is a
//! purely local spelling: it means something on this node's network and nothing
//! anywhere else. `karst-transport` translates it away at the socket, so the
//! engine above goes on holding plain IPv4 addresses.
//!
//! **This file exists because the whole-aquifer row cannot see whether it did.**
//! `an_ipv6_only_node_behind_nat64_reaches_an_ipv4_mesh` passes with the
//! receive-side translation removed, and that is not a flaw in the row — with
//! two nodes there is nothing for the mistake to break. The synthesised address
//! is one the NAT64 node really can reach, so its own paths keep working; what
//! breaks is what it *tells other people*, and telling requires a third node.
//!
//! `aven-v1.md` §7.2: a node answering a `Ping` reports the source it arrived
//! from as `Pong.observed`, and the peer takes that as its own reflexive
//! candidate and advertises it to everybody. So a NAT64 node that skipped the
//! translation would hand an IPv4 peer an address inside its own translator's
//! prefix, that peer would publish it, and every IPv4-only node in the mesh
//! would receive a candidate it cannot send to at all. This is FINDINGS.md 45's
//! failure in its other spelling, and worse: a v4-mapped address is at least
//! *about* somewhere real, while `64:ff9b::…` names a place that exists only
//! inside one network.
//!
//! # Why a real socket
//!
//! The claim is that the socket and the discovery layer *compose*. A test that
//! called the translation itself and then fed the result to `Disco` would pass
//! whether or not `UdpTransport` ever calls it — which is exactly the trap the
//! first draft of `karst-transport`'s own NAT64 test fell into, where a
//! carefully chosen prefix let `canonical` do the work and the test could not
//! fail. So a datagram genuinely crosses a socket here, and `Disco` is given
//! whatever that socket says the source was.
//!
//! `::/96` is the prefix, for the reason that file records: it embeds `0.0.0.1`
//! as `::1`, so synthesised addresses are ones loopback already carries and no
//! translator is needed to make the round trip real.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use karst_disco::msg::{self, Message};
use karst_disco::DiscoKey;
use karst_transport::{Nat64Prefix, UdpTransport, MAX_DATAGRAM};
use karstd::disco::Disco;

const KEY: [u8; 32] = [0x5A; 32];
/// Node ids are the 32-byte handles a netmap carries; `Disco::add_peer` refuses
/// anything shorter, and a shorter one here would fail as "the peer was not
/// added" rather than as anything to do with NAT64.
const OUR_ID: &[u8] = &[0xA1; 32];
const THEIR_ID: &[u8] = &[0xB2; 32];

/// A prefix whose synthesised addresses loopback already routes — see the
/// module docs.
fn prefix() -> Nat64Prefix {
    "::/96".parse().expect("::/96 is a legal prefix")
}

/// The NAT64 node's `Disco`, holding one peer.
fn nat64_node() -> Disco {
    let mut d = Disco::new(0);
    assert!(
        d.add_peer(DiscoKey::new(KEY), OUR_ID, THEIR_ID),
        "the peer must be added for anything below to mean something"
    );
    d
}

/// **The assertion the aquifer row cannot make.**
///
/// A peer pings the NAT64 node. The node answers, and the address it reports
/// seeing the peer at must be the peer's own IPv4 address — not the spelling
/// this node's translator gave it.
#[test]
fn a_nat64_node_reports_an_ipv4_peer_at_an_address_other_nodes_can_use() {
    let Ok(node) =
        UdpTransport::bind_via_nat64(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), Some(prefix()))
    else {
        return; // IPv6 disabled outright.
    };
    let Ok(peer) = UdpTransport::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) else {
        return;
    };
    node.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // The peer sends a Ping. It is an ordinary node with no NAT64 anything; it
    // addresses the NAT64 node natively and knows nothing about prefixes.
    let key = DiscoKey::new(KEY);
    let ping = Message::Ping {
        tx: msg::TxId([0x11; 12]),
    }
    .encode(&key, &key.tag(THEIR_ID, 0), 0);
    peer.send_to(&ping, node.local_addr().unwrap())
        .expect("send the Ping");

    // What the NAT64 node's socket says the source was. Everything above the
    // socket sees only this.
    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, from) = node.recv_from(&mut buf).expect("receive the Ping");
    assert!(
        from.is_ipv4(),
        "the socket reported the peer at {from}; a NAT64 node must hand the \
         layers above it a plain IPv4 address"
    );

    let mut disco = nat64_node();
    let verdict = disco.inbound(&buf[..n], from, 1_000);
    let out = match verdict {
        karstd::disco::Verdict::Handled(out) => out,
        other @ karstd::disco::Verdict::NotAven => {
            panic!("the Ping was not handled: {other:?}")
        }
    };
    let (bytes, to) = out
        .first()
        .expect("a Ping is answered with a Pong — aven-v1.md §7.4");

    let Message::Pong { observed, .. } = msg::open(bytes, &key).expect("our own Pong") else {
        panic!("what was sent back was not a Pong");
    };

    let want = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 1), peer.local_addr().unwrap().port()));
    assert_eq!(
        observed.0, want,
        "the NAT64 node told its peer it was seen at {}, which is this \
         network's private spelling of an address. The peer will publish that \
         as its own reflexive candidate (aven-v1.md §7.2) and every IPv4-only \
         node in the mesh will be handed an endpoint it cannot send to.",
        observed.0
    );
    assert_eq!(*to, from, "the Pong went somewhere other than the sender");
}

/// The same node must leave a **native IPv6** peer exactly as it found it.
///
/// A NAT64 network still has real IPv6, and it is the path that needs no
/// translation at all. A node that rewrote those addresses too would break the
/// only peers it could reach without help.
#[test]
fn a_native_ipv6_peer_is_reported_at_its_own_address() {
    // A prefix that loopback is *not* inside, so `::1` is a genuine IPv6 peer
    // as far as this node is concerned.
    let well_known = Nat64Prefix::well_known();
    let Ok(node) =
        UdpTransport::bind_via_nat64(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), Some(well_known))
    else {
        return;
    };
    let Ok(peer) = UdpTransport::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))) else {
        return;
    };
    node.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let key = DiscoKey::new(KEY);
    let ping = Message::Ping {
        tx: msg::TxId([0x22; 12]),
    }
    .encode(&key, &key.tag(THEIR_ID, 0), 0);
    peer.send_to(&ping, node.local_addr().unwrap()).unwrap();

    let mut buf = [0u8; MAX_DATAGRAM];
    let (n, from) = node.recv_from(&mut buf).unwrap();
    assert_eq!(
        from,
        peer.local_addr().unwrap(),
        "a native IPv6 peer was rewritten"
    );

    let mut disco = nat64_node();
    let karstd::disco::Verdict::Handled(out) = disco.inbound(&buf[..n], from, 1_000) else {
        panic!("the Ping was not handled");
    };
    let Message::Pong { observed, .. } =
        msg::open(&out.first().expect("a Pong").0, &key).expect("our own Pong")
    else {
        panic!("not a Pong");
    };
    assert_eq!(observed.0, peer.local_addr().unwrap());
}

/// **What an operator actually reads on a node that cannot use IPv6.**
///
/// FINDINGS.md 51: every send path drops errors on purpose, so an `AF_INET`
/// node's sends to an IPv6 candidate were an unbroken silence — no log line, no
/// counter, no symptom but never connecting. The counter is asserted in
/// `karst-transport`; what is asserted here is that it reaches the one surface
/// an operator looks at, because a number nothing prints is the same as no
/// number.
#[test]
fn an_ipv4_node_says_in_its_status_that_ipv6_is_out_of_reach() {
    let cfg = std::sync::Arc::new(config());
    let text = karstd::run::status_report(
        &cfg,
        &karstd::engine::Engine::new(&cfg),
        karstd::run::Attachment {
            name: "karst0",
            mtu: 1280,
            sockets: None,
            unreachable_family: Some(3),
        },
        0,
    );
    assert!(
        text.contains(r#"ipv6 = "unreachable (node.listen is IPv4)""#),
        "status does not say this node cannot use IPv6:\n{text}"
    );
    assert!(
        text.contains("ipv6_candidates_refused = 3"),
        "status does not carry the count:\n{text}"
    );

    // A dual-stack node must not be told it has a problem it does not have.
    let dual = karstd::run::status_report(
        &cfg,
        &karstd::engine::Engine::new(&cfg),
        karstd::run::Attachment {
            name: "karst0",
            mtu: 1280,
            sockets: None,
            unreachable_family: None,
        },
        0,
    );
    assert!(
        !dual.contains("ipv6 ="),
        "a dual-stack node was told IPv6 is unreachable:\n{dual}"
    );
}

/// The minimum a `Config` needs to be reported on.
fn config() -> karstd::config::Config {
    karstd::config::Config {
        keys: std::sync::Arc::new(karst_noise::handshake::StaticKeys::from_seed(
            &[7u8; 64], &[7u8; 32],
        )),
        listen: "0.0.0.0:51820".parse().expect("listen"),
        port_mapping: false,
        interface: "karst0".to_owned(),
        network_mode: karstd::config::NetworkMode::default(),
        userspace_socks5_listen: None,
        userspace_publish: Vec::new(),
        nat64: None,
        addresses: Vec::new(),
        psk_epoch: 1,
        node_id: Vec::new(),
        relays: Vec::new(),
        relay_ca_file: None,
        peers: Vec::new(),
        routes: karstd::routing::AllowedIps::build(Vec::new()).expect("routes"),
        skipped: Vec::new(),
        filter: karstd::filter::PacketFilter::unrestricted(),
    }
}
