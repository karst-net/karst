// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Peer-to-peer file transfer, end to end — GitHub issue #212,
//! `docs/adr/0041-peer-to-peer-file-transfer.md`.
//!
//! Two real `Engine`s, a real PHREATIC handshake shuttled between them
//! in-process — the same harness `equivocation.rs` and `dual_stack.rs` use,
//! for the same reason: the property under test is not the codec (that has
//! its own unit tests in `karstd::filetransfer`) but that an offer actually
//! rides the live session, survives the transport, and is gated by the ACL
//! the two nodes were each configured with.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::net::SocketAddr;
use std::sync::Arc;

use karst_control_client::handle::handle;
use karst_control_client::transport::pb;
use karst_noise::handshake::{PeerPublic, ResponderRandomness, StaticKeys};
use karst_proto::reassembly::{Config as ReasmConfig, Reassembler};
use karstd::config::{Config, Peer};
use karstd::engine::{Engine, Via};
use karstd::filetransfer;
use karstd::filter::PacketFilter;
use karstd::routing::{AllowedIps, Prefix};

fn keys(seed: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[seed; 64]))
}

fn rand() -> ResponderRandomness {
    ResponderRandomness {
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
    reasm: RefCell<Reassembler>,
}

/// `filter` is this node's *own* policy — what its ingress/egress checks
/// enforce, exactly as a real netmap-delivered ACL would.
fn node(
    own: u8,
    peer: u8,
    own_range: &str,
    peer_range: &'static str,
    filter: PacketFilter,
) -> Node {
    let prefix: Prefix = peer_range.parse().expect("peer prefix");
    let peer_keys = keys(peer);
    let peers = vec![Peer {
        name: format!("peer{peer}"),
        node_id: handle(&[peer; 2592]).into_bytes(),
        public: Arc::new(PeerPublic {
            kem_pk: peer_keys.kem_pk.clone(),
            psk: [0x77; 32],
        }),
        endpoint: Some(peer_endpoint(peer)),
        allowed_ips: vec![prefix],
        identity_addresses: vec![prefix],
        psk_is_fallback: false,
        psk_previous: None,
        disco_key: None,
        home_relay: None,
    }];

    let config = Arc::new(Config {
        relay_ca_file: None,
        prefer_quic_relay: false,
        metrics_listen: None,
        tracing_collector: None,
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
        filter,
        ssh_filter: karstd::filter::SshFilter::absent(),
        datapath_workers: 1,
        anchor_probe_enabled: false,
    });

    Node {
        engine: Engine::new(&config),
        endpoint: peer_endpoint(own),
        reasm: RefCell::new(Reassembler::new(ReasmConfig::default())),
    }
}

/// Shuttle datagrams between the two engines until nothing more is produced
/// — used only to bring up the session. File-transfer frames are driven by
/// hand afterward (see [`deliver`]), so the test can inspect each `Output`.
fn pump(a: &Node, b: &Node, out: karstd::engine::Output, to_b: bool, now: u64) {
    let mut queue: Vec<(bool, Vec<u8>)> = out
        .datagrams
        .into_iter()
        .filter(|(_, via)| matches!(via, Via::Direct(_)))
        .map(|(d, _)| (to_b, d))
        .collect();

    for _ in 0..256 {
        let Some((for_b, datagram)) = queue.pop() else {
            return;
        };
        let (target, source) = if for_b { (b, a) } else { (a, b) };
        let produced = target.engine.inbound(
            &mut target.reasm.borrow_mut(),
            &datagram,
            source.endpoint,
            now,
            &rand(),
        );
        for (datagram, via) in produced.datagrams {
            if matches!(via, Via::Direct(_)) {
                queue.push((!for_b, datagram));
            }
        }
    }
    panic!("the datagram pump did not settle");
}

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

/// Deliver one datagram from `from` to `to` and return what `to`'s engine
/// produced in response — the hand-driven counterpart to `pump`, used once a
/// session is up so the test can inspect each step of the offer/accept flow.
fn deliver(from: &Node, to: &Node, datagram: &[u8], now: u64) -> karstd::engine::Output {
    to.engine.inbound(
        &mut to.reasm.borrow_mut(),
        datagram,
        from.endpoint,
        now,
        &rand(),
    )
}

fn only_direct_datagram(out: &karstd::engine::Output) -> &[u8] {
    let [(datagram, Via::Direct(_))] = out.datagrams.as_slice() else {
        panic!(
            "expected exactly one direct datagram, got {:?}",
            out.datagrams.iter().map(|(_, via)| via).collect::<Vec<_>>()
        );
    };
    datagram
}

fn pair(a_filter: PacketFilter, b_filter: PacketFilter) -> (Node, Node) {
    (
        node(0x31, 0x32, "10.61.0.1/24", "10.61.0.2/32", a_filter),
        node(0x32, 0x31, "10.61.0.2/24", "10.61.0.1/32", b_filter),
    )
}

/// A general-ACL rule granting file transfer to any peer on the service
/// port — exercising that this really does reuse the ordinary `acls`
/// engine rather than a parallel allow-list, per the issue's own framing.
fn permissive_filter() -> PacketFilter {
    let handles = vec![b"peer".to_vec()]; // this test's one-peer rosters
    let rule = pb::KarstFilterRule {
        srcs: vec!["peer".to_owned()],
        ports: vec![pb::KarstPortRange {
            first: u32::from(filetransfer::SERVICE_PORT),
            last: u32::from(filetransfer::SERVICE_PORT),
        }],
    };
    let egress = pb::KarstEgressRule {
        dsts: vec!["peer".to_owned()],
        ports: vec![pb::KarstPortRange {
            first: u32::from(filetransfer::SERVICE_PORT),
            last: u32::from(filetransfer::SERVICE_PORT),
        }],
        ..Default::default()
    };
    PacketFilter::compile(&[rule], &[egress], &handles)
}

/// Deny-all: a present policy that grants nothing, the state
/// `crate::filter`'s own tests call "empty is deny" — distinct from
/// [`PacketFilter::unrestricted`], which has no policy source at all.
fn deny_all_filter() -> PacketFilter {
    PacketFilter::compile(&[], &[], &[b"peer".to_vec()])
}

// ── the happy path ──────────────────────────────────────────────────────

/// **The property the issue asks for.** An offer, an accept, the bytes
/// themselves, and a verified receipt on both sides — over a real PHREATIC
/// session between two real engines, gated by the same general ACL that
/// already governs whether the two peers may talk to each other at all.
#[test]
fn two_nodes_transfer_a_file_end_to_end() {
    let (a, b) = pair(permissive_filter(), permissive_filter());
    establish(&a, &b);
    let now = 100_000;

    let data = b"the quick brown fox jumps over the lazy dog".to_vec();
    let (id, offer_out) = a
        .engine
        .offer_file(0, "fox.txt".to_owned(), data.clone(), now)
        .expect("a's own policy permits this transfer");
    let offer_frame = only_direct_datagram(&offer_out).to_vec();

    // B has not accepted anything yet: the offer must be visible to the
    // local operator/agent, and nothing must have been written anywhere.
    let b_after_offer = deliver(&a, &b, &offer_frame, now);
    assert!(b_after_offer.files_received.is_empty());
    let pending = b.engine.pending_transfers();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, 0, "peer index");
    assert_eq!(pending[0].1, id);
    assert_eq!(pending[0].2.name, "fox.txt");
    assert_eq!(pending[0].2.size, data.len() as u64);

    // B's own decision.
    let accept_out = b
        .engine
        .accept_transfer(0, id, now)
        .expect("a pending offer from a known peer");
    let accept_frame = only_direct_datagram(&accept_out).to_vec();

    // A answers Accept with every Chunk plus a trailing Complete.
    let chunks_out = deliver(&b, &a, &accept_frame, now);
    assert!(
        chunks_out.datagrams.len() >= 2,
        "at least one Chunk and the trailing Complete"
    );

    // Feed every produced datagram to B in order; the last one (Complete)
    // is what verifies the transfer and lands the file.
    let mut final_out = karstd::engine::Output::default();
    for (datagram, via) in &chunks_out.datagrams {
        assert!(matches!(via, Via::Direct(_)));
        let out = deliver(&a, &b, datagram, now);
        if !out.files_received.is_empty() || !out.datagrams.is_empty() {
            final_out = out;
        }
    }

    assert_eq!(
        final_out.files_received.len(),
        1,
        "the file must land exactly once"
    );
    let received = &final_out.files_received[0];
    assert_eq!(received.name, "fox.txt");
    assert_eq!(received.bytes, data);
    assert_eq!(received.peer_name, "peer49"); // config's `peer{own}` naming, own=0x31=49

    // B answered Complete with a Receipt; deliver it back to A so A's own
    // audit trail resolves too.
    let receipt_frame = only_direct_datagram(&final_out).to_vec();
    let _ = deliver(&b, &a, &receipt_frame, now);

    // Both sides now show exactly one completed transfer, and the stats
    // agree with the receipt log.
    assert_eq!(a.engine.stats().file_transfer_completed, 1);
    assert_eq!(b.engine.stats().file_transfer_completed, 1);
    assert!(b.engine.pending_transfers().is_empty());

    let a_receipts = a.engine.file_transfer_receipts();
    assert_eq!(a_receipts.len(), 1);
    assert_eq!(
        a_receipts[0].direction,
        filetransfer::TransferDirection::Sent
    );
    assert_eq!(a_receipts[0].outcome, filetransfer::Outcome::Completed);
    assert_eq!(a_receipts[0].name, "fox.txt");

    let b_receipts = b.engine.file_transfer_receipts();
    assert_eq!(b_receipts.len(), 1);
    assert_eq!(
        b_receipts[0].direction,
        filetransfer::TransferDirection::Received
    );
    assert_eq!(b_receipts[0].outcome, filetransfer::Outcome::Completed);
}

// ── ACL gating (issue #212's second acceptance criterion) ──────────────

/// A transfer this node's own policy does not permit is refused locally,
/// before anything reaches the wire — the fast half of the check
/// (`crate::filter`'s own reasoning for evaluating egress at all).
#[test]
fn offer_file_is_refused_locally_when_the_senders_own_policy_denies_it() {
    let (a, b) = pair(deny_all_filter(), permissive_filter());
    establish(&a, &b);
    let now = 50_000;

    let err = a
        .engine
        .offer_file(0, "secret.txt".to_owned(), b"top secret".to_vec(), now)
        .expect_err("a's own egress policy denies every peer");
    assert!(matches!(
        err,
        karstd::engine::FileTransferError::NotPermitted
    ));
    assert_eq!(a.engine.stats().file_transfer_denied, 1);

    let receipts = a.engine.file_transfer_receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, filetransfer::Outcome::DeniedByPolicy);
}

/// **The authoritative check.** Even if a peer's own client ignored its
/// egress filter and sent an `Offer` anyway, the receiving node's own
/// ingress ACL is what actually stops the transfer — nothing is admitted to
/// `pending_transfers`, no bytes are ever written, and (per §11's silent-
/// discard discipline, reused here) no reply crosses the wire to confirm to
/// the sender that a policy exists to probe.
#[test]
fn a_transfer_is_refused_when_the_receiving_peers_policy_denies_it() {
    // A's own egress is permissive so it actually sends the offer; B's
    // ingress is deny-all, which is the check that must actually stop it.
    let (a, b) = pair(permissive_filter(), deny_all_filter());
    establish(&a, &b);
    let now = 75_000;

    let (_, offer_out) = a
        .engine
        .offer_file(0, "data.bin".to_owned(), vec![1, 2, 3, 4], now)
        .expect("a's own policy permits sending it");
    let offer_frame = only_direct_datagram(&offer_out).to_vec();

    let b_out = deliver(&a, &b, &offer_frame, now);
    assert!(
        b_out.datagrams.is_empty(),
        "a policy denial must not be answered"
    );
    assert!(b_out.files_received.is_empty());
    assert!(b.engine.pending_transfers().is_empty());

    assert_eq!(b.engine.stats().file_transfer_denied, 1);
    let receipts = b.engine.file_transfer_receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].direction,
        filetransfer::TransferDirection::Received
    );
    assert_eq!(receipts[0].outcome, filetransfer::Outcome::DeniedByPolicy);
}

// ── rejection ────────────────────────────────────────────────────────────

/// The receiving user/agent saying no is a first-class outcome, distinct
/// from a policy denial: the peer is told, and both sides' audit trails
/// agree on why.
#[test]
fn a_declined_offer_is_reported_to_the_sender() {
    let (a, b) = pair(permissive_filter(), permissive_filter());
    establish(&a, &b);
    let now = 10_000;

    let (id, offer_out) = a
        .engine
        .offer_file(0, "unwanted.zip".to_owned(), vec![9; 64], now)
        .expect("permitted");
    let offer_frame = only_direct_datagram(&offer_out).to_vec();
    let _ = deliver(&a, &b, &offer_frame, now);

    let reject_out = b
        .engine
        .reject_transfer(0, id, filetransfer::RejectReason::Declined, now)
        .expect("a pending offer");
    let reject_frame = only_direct_datagram(&reject_out).to_vec();
    let _ = deliver(&b, &a, &reject_frame, now);

    assert_eq!(a.engine.stats().file_transfer_failed, 1);
    let a_receipts = a.engine.file_transfer_receipts();
    assert_eq!(a_receipts[0].outcome, filetransfer::Outcome::Declined);

    let b_receipts = b.engine.file_transfer_receipts();
    assert_eq!(b_receipts[0].outcome, filetransfer::Outcome::Declined);

    // A second accept after the reject must not resurrect the transfer.
    assert!(b.engine.accept_transfer(0, id, now).is_err());
}
