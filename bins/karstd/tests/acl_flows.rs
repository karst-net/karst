// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! A conversation, under the policy PLAN.md §4.3 uses as its own example.
//!
//! **This is the test finding 17 should have had.** Every unit test below it
//! passed while no TCP connection could complete: the filter's tests assert
//! that a rule permits and denies the packets it should, and it does; the
//! datapath's tests run with `PacketFilter::unrestricted`. Nothing exercised a
//! *reply*, because a reply only exists once something upstream is holding a
//! connection open — and two daemons carrying real traffic is what finally
//! produced one.
//!
//! So this drives two engines with a port-scoped ACL and moves a request and
//! its answer between them. Not a socket in sight; what was missing was never
//! the network.

#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use karst_control_client::transport::pb;
use karstd::config::{Config, Peer};
use karstd::engine::Engine;
use karstd::filter::{Direction, PacketFilter};
use karstd::routing::{AllowedIps, Prefix};

const A_IP: [u8; 4] = [100, 64, 0, 2];
const B_IP: [u8; 4] = [100, 64, 0, 3];
const SSH: u16 = 22;
const EPHEMERAL: u16 = 54321;

/// A TCP packet with the ports the policy cares about.
fn tcp(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    let total = u16::try_from(p.len()).expect("small");
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[9] = 6; // TCP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..22].copy_from_slice(&src_port.to_be_bytes());
    p[22..24].copy_from_slice(&dst_port.to_be_bytes());
    p
}

fn keys(byte: u8) -> Arc<karst_noise::handshake::StaticKeys> {
    Arc::new(karst_noise::handshake::StaticKeys::from_seed(
        &[byte; 64],
        &[byte; 32],
    ))
}

/// One node holding the other as its only peer.
///
/// `filter` is the compiled policy, which is the whole subject here.
fn config_for(
    own: u8,
    peer_byte: u8,
    own_range: &str,
    peer_range: &str,
    filter: PacketFilter,
) -> Arc<Config> {
    let peer_keys = keys(peer_byte);
    let prefix: Prefix = peer_range.parse().expect("peer prefix");
    let config = Config {
        keys: keys(own),
        listen: "0.0.0.0:0".parse().expect("listen"),
        port_mapping: true,
        interface: format!("karst{own}"),
        network_mode: karstd::config::NetworkMode::Tun,
        userspace_socks5_listen: None,
        addresses: vec![own_range.parse().expect("interface address")],
        psk_epoch: 1,
        node_id: Vec::new(),
        relays: Vec::new(),
        relay_ca_file: None,
        peers: vec![Peer {
            name: "peer".to_owned(),
            node_id: Vec::new(),
            public: Arc::new(karst_noise::handshake::PeerPublic {
                kem_pk: peer_keys.kem_pk.clone(),
                dh_pk: peer_keys.dh_pk,
                psk: [0x77; 32],
            }),
            endpoint: Some("203.0.113.1:51820".parse().expect("endpoint")),
            allowed_ips: vec![prefix],
            psk_is_fallback: false,
            disco_key: None,
        }],
        routes: AllowedIps::build(vec![(prefix, 0)]).expect("no conflicts"),
        skipped: Vec::new(),
        filter,
    };
    Arc::new(config)
}

fn node(own: u8, peer_byte: u8, own_range: &str, peer_range: &str, filter: PacketFilter) -> Engine {
    Engine::new(&config_for(own, peer_byte, own_range, peer_range, filter))
}

/// The compiled form of §4.3's example: *accept from anyone, to port 22*.
///
/// A **unidirectional grant**, which is the point: it says who may initiate,
/// and says nothing whatever about the answer.
fn ssh_only(peer_handle: &str) -> PacketFilter {
    let ports = vec![pb::KarstPortRange {
        first: u32::from(SSH),
        last: u32::from(SSH),
    }];
    PacketFilter::compile(
        &[pb::KarstFilterRule {
            srcs: vec![peer_handle.to_owned()],
            ports: ports.clone(),
        }],
        &[pb::KarstEgressRule {
            dsts: vec![peer_handle.to_owned()],
            ports,
        }],
        &[peer_handle.as_bytes().to_vec()],
    )
}

/// **Finding 17.** A client reaches `B:22` and the answer gets home.
///
/// Measured on the daemons that found it: A sent 7 packets, B received all 7,
/// and B's egress filter denied 12 — the SYN-ACK and its retries. Both ends
/// reported `established` and `direct` throughout. The tunnel was working
/// perfectly and carrying nothing.
#[test]
fn a_reply_to_a_permitted_request_crosses_the_acl() {
    let handle = "peer-handle";
    let client = node(
        0x01,
        0x02,
        "100.64.0.2/24",
        "100.64.0.3/32",
        ssh_only(handle),
    );
    let server = node(
        0x02,
        0x01,
        "100.64.0.3/24",
        "100.64.0.2/32",
        ssh_only(handle),
    );

    let request = tcp(A_IP, EPHEMERAL, B_IP, SSH);
    let reply = tcp(B_IP, SSH, A_IP, EPHEMERAL);

    // The request. A rule permits it at both ends.
    assert!(
        client.permits_for_test(Direction::Out, 0, &request, 1_000),
        "the policy did not permit the request it exists to permit"
    );
    assert!(server.permits_for_test(Direction::In, 0, &request, 1_000));

    // The reply. No rule mentions port 54321 anywhere.
    assert!(
        server.permits_for_test(Direction::Out, 0, &reply, 1_100),
        "the server could not answer a request the policy allowed it to receive"
    );
    assert!(
        client.permits_for_test(Direction::In, 0, &reply, 1_100),
        "the client could not receive the answer to its own request"
    );
}

/// **And the grant does not widen.** A flow permits the reverse of the packet
/// that opened it, not the peer generally — the difference between connection
/// tracking and "allow anything from port 22", which would have satisfied the
/// test above and handed a permitted peer every port on this node.
#[test]
fn a_permitted_flow_does_not_open_the_node_to_its_peer() {
    let handle = "peer-handle";
    let client = node(
        0x01,
        0x02,
        "100.64.0.2/24",
        "100.64.0.3/32",
        ssh_only(handle),
    );

    client.permits_for_test(Direction::Out, 0, &tcp(A_IP, EPHEMERAL, B_IP, SSH), 1_000);

    for (what, packet) in [
        ("another local port", tcp(B_IP, SSH, A_IP, 9999)),
        ("another remote port", tcp(B_IP, 8080, A_IP, EPHEMERAL)),
        ("an unrelated service", tcp(B_IP, 31337, A_IP, 3306)),
    ] {
        assert!(
            !client.permits_for_test(Direction::In, 0, &packet, 1_100),
            "a flow to port 22 also admitted {what}"
        );
    }
}

/// Unsolicited traffic is still refused, so the flow table has not quietly
/// become an accept-all. This is the assertion that would fail first if the
/// lookup were consulted before the rules rather than after them.
#[test]
fn an_unsolicited_packet_is_still_denied() {
    let handle = "peer-handle";
    let server = node(
        0x02,
        0x01,
        "100.64.0.3/24",
        "100.64.0.2/32",
        ssh_only(handle),
    );

    assert!(
        !server.permits_for_test(Direction::In, 0, &tcp(A_IP, EPHEMERAL, B_IP, 3306), 1_000),
        "a port the policy never mentioned was reachable"
    );
    // And a packet that merely *looks* like a reply, with no request behind it.
    assert!(
        !server.permits_for_test(Direction::Out, 0, &tcp(B_IP, SSH, A_IP, EPHEMERAL), 1_000),
        "an unrequested reply was allowed out"
    );
}

/// A flow that goes quiet stops permitting anything, so a permission granted
/// once does not last for the life of the process.
#[test]
fn a_permission_does_not_outlive_its_conversation() {
    let handle = "peer-handle";
    let client = node(
        0x01,
        0x02,
        "100.64.0.2/24",
        "100.64.0.3/32",
        ssh_only(handle),
    );
    let reply = tcp(B_IP, SSH, A_IP, EPHEMERAL);

    client.permits_for_test(Direction::Out, 0, &tcp(A_IP, EPHEMERAL, B_IP, SSH), 0);
    assert!(client.permits_for_test(Direction::In, 0, &reply, 60_000));
    assert!(
        !client.permits_for_test(Direction::In, 0, &reply, 10 * 60_000),
        "a flow permitted traffic ten minutes after it went silent"
    );
}

/// **A policy change revokes what it revoked.**
///
/// A flow is a cached permission, and sessions and endpoints are deliberately
/// carried across a reconfiguration so an unrelated netmap change does not cost
/// a rehandshake. Carrying the flow table with them would mean an ACL edit that
/// withdrew access left every connection it withdrew still working — a
/// revocation that does not revoke, which is the one failure mode §4.3's
/// "distributor of policy, not an enforcement point" argument cannot survive.
#[test]
fn a_policy_change_revokes_flows_it_opened() {
    let handle = "peer-handle";
    let client = node(
        0x01,
        0x02,
        "100.64.0.2/24",
        "100.64.0.3/32",
        ssh_only(handle),
    );
    let reply = tcp(B_IP, SSH, A_IP, EPHEMERAL);

    client.permits_for_test(Direction::Out, 0, &tcp(A_IP, EPHEMERAL, B_IP, SSH), 0);
    assert!(client.permits_for_test(Direction::In, 0, &reply, 1));

    // The new policy grants nothing at all. The peer, its keys and its session
    // are unchanged, so only the flow table decides what happens next.
    let deny_all = PacketFilter::compile(&[], &[], &[handle.as_bytes().to_vec()]);
    client.reconfigure(&config_for(
        0x01,
        0x02,
        "100.64.0.2/24",
        "100.64.0.3/32",
        deny_all,
    ));

    assert!(
        !client.permits_for_test(Direction::In, 0, &reply, 2),
        "a connection kept working after the policy that allowed it was withdrawn"
    );
}
