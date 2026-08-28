// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Two nodes discover a direct path to each other — `spec/aven-v1.md` §7.
//!
//! **The one test that proves discovery works rather than that its parts do.**
//! Every layer below has its own unit tests, and each passed for a long time
//! while the vertical slice did nothing at all: the scheduler produced
//! advertisements nobody carried, the relay carried datagrams nobody produced,
//! and selection ran over a candidate set that was always empty. A test that
//! exercises one layer cannot see that.
//!
//! So this runs both ends and moves the bytes between them by hand. There is no
//! socket and no relay process — the point is not the transport, it is that the
//! protocol closes: an advertisement leads to a probe, a probe to a `Pong`, and
//! a `Pong` to an endpoint the datapath is told to use.
//!
//! Every datagram is delivered through the same entry points the daemon uses.
//! Nothing here reaches inside `Disco` to set a path directly, because that
//! would be a test of the fixture.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;

use karst_disco::consts::KEY_LEN;
use karst_disco::msg::TxId;
use karst_disco::DiscoKey;
use karstd::disco::{Disco, PathChange, Verdict};

const EPOCH: u32 = 7;

/// A node id of the width the control plane produces.
fn node_id(tag: u8) -> [u8; 32] {
    let mut id = *b"karst-node-id-32-bytes-long-xxxx";
    id[31] = tag;
    id
}

/// Where each node believes it can be reached.
fn addr(host: u8, port: u16) -> SocketAddr {
    SocketAddr::from(([198, 51, 100, host], port))
}

/// Distinct transaction ids, deterministic so a failure reproduces.
fn minter(seed: u8) -> impl FnMut() -> TxId {
    let mut n = 0u8;
    move || {
        n = n.wrapping_add(1);
        TxId([seed ^ n; 12])
    }
}

/// Both ends of one pair, each holding the other.
struct Pair {
    a: Disco,
    b: Disco,
    a_id: [u8; 32],
    b_id: [u8; 32],
}

impl Pair {
    fn new() -> Self {
        // One pair key, which is what the coordination server derives for both
        // ends of the pair (`psk.Disco`, label `karst-disco-v1`).
        let key = DiscoKey::new([0x5A; KEY_LEN]);
        let (a_id, b_id) = (node_id(1), node_id(2));

        let mut a = Disco::new(EPOCH);
        let mut b = Disco::new(EPOCH);
        assert!(a.add_peer(key.clone(), &a_id, &b_id));
        assert!(b.add_peer(key, &b_id, &a_id));
        Self { a, b, a_id, b_id }
    }
}

/// What one node's poll produced, once it had been delivered.
struct Delivered {
    advertisements: usize,
    probes: usize,
}

/// Poll one node and deliver **everything** it asked for.
///
/// Both halves, deliberately. `poll` returns relayed advertisements and UDP
/// probes together because one call to it is one tick of the protocol, and a
/// caller that carried only one of the two would be a caller with a bug — the
/// first version of this fixture dropped the probes, and the symptom was one
/// node confirming a path while the other silently did not.
///
/// `via` is the address `to` sees this node's datagrams arriving from, which is
/// what it reports back in `Pong.observed` (§7.2). `source` is the node id a
/// relay stamps on a forwarded frame.
fn step(
    from: &mut Disco,
    to: &mut Disco,
    source: [u8; 32],
    via: SocketAddr,
    now: u64,
    seed: u8,
) -> Delivered {
    let out = from.poll(now, minter(seed));
    let advertisements = out.relayed.len();
    let probes = out.datagrams.len();

    for (_destination, payload) in out.relayed {
        // The relay addresses by node id and never looks inside; the receiver
        // is what checks that the stamped source and the AVEN tag agree.
        assert!(
            to.inbound_from_relay(source, &payload, now),
            "the peer refused a genuine relayed advertisement"
        );
    }
    for (datagram, _target) in out.datagrams {
        let Verdict::Handled(replies) = to.inbound(&datagram, via, now) else {
            panic!("a genuine AVEN datagram was not recognised");
        };
        for (reply, _back) in replies {
            // §7.1: what the answer confirms is the endpoint the `Ping` went
            // to, so the address it appears to arrive from is deliberately not
            // the one that matters. Delivered from somewhere else entirely to
            // keep that honest.
            assert!(matches!(
                from.inbound(&reply, addr(9, 9), now + 1),
                Verdict::Handled(_)
            ));
        }
    }
    Delivered {
        advertisements,
        probes,
    }
}

/// **The whole slice.** Two nodes that have never exchanged a packet learn each
/// other's addresses over the relay, probe them, and end up with a confirmed
/// direct path each — which is the transition Phase 4 exists to produce.
#[test]
fn two_nodes_rendezvous_over_the_relay_and_confirm_a_direct_path() {
    let mut pair = Pair::new();
    let (a_addr, b_addr) = (addr(1, 51820), addr(2, 51820));

    // Each node enumerates its own interfaces. Neither knows the other's
    // address yet, and there is no configured endpoint anywhere — the relay is
    // the only thing that connects them.
    pair.a.set_interfaces(&[a_addr.ip()], a_addr.port());
    pair.b.set_interfaces(&[b_addr.ip()], b_addr.port());

    let first = step(&mut pair.a, &mut pair.b, pair.a_id, a_addr, 0, 0x10);
    assert_eq!(first.advertisements, 1, "A never told B where it is");
    assert_eq!(
        first.probes, 0,
        "A probed before it had been told anywhere to probe"
    );

    // B answers with its own candidates *and* starts probing on the same
    // poll — a `CallMeMaybe` is probed immediately rather than on the backoff
    // schedule, which is what makes simultaneous open work: the peer received
    // ours at nearly the same moment and is doing likewise, so both NATs see an
    // outbound packet before either sees an inbound one.
    let second = step(&mut pair.b, &mut pair.a, pair.b_id, b_addr, 0, 0x20);
    assert_eq!(second.advertisements, 1, "B never told A where it is");
    assert_eq!(
        second.probes, 1,
        "B waited out a backoff instead of probing what it had just been told"
    );

    let third = step(&mut pair.a, &mut pair.b, pair.a_id, a_addr, 10, 0x30);
    assert_eq!(third.probes, 1, "A never probed the address B advertised");

    assert_eq!(
        pair.a.path_changes(),
        vec![PathChange::Install {
            peer: 0,
            endpoint: b_addr
        }],
        "A confirmed no direct path to B"
    );
    assert_eq!(
        pair.b.path_changes(),
        vec![PathChange::Install {
            peer: 0,
            endpoint: a_addr
        }],
        "B confirmed no direct path to A"
    );
}

/// The reflexive half of §7.2, end to end. A node behind a NAT never sees its
/// own mapped address; the only way it learns one is from a peer that answers
/// its probe, and the only reason to learn it is to advertise it.
#[test]
fn a_node_learns_its_mapped_address_from_its_peer_and_advertises_it() {
    let mut pair = Pair::new();
    let (a_private, b_addr) = (addr(1, 51820), addr(2, 51820));
    // What B actually sees when A's datagrams cross A's NAT.
    let a_mapped = SocketAddr::from(([203, 0, 113, 1], 40404));

    pair.a.set_interfaces(&[a_private.ip()], a_private.port());
    pair.b.set_interfaces(&[b_addr.ip()], b_addr.port());
    step(&mut pair.b, &mut pair.a, pair.b_id, b_addr, 0, 0x20);

    // A probes B; B sees the translated source and says so in its `Pong`.
    step(&mut pair.a, &mut pair.b, pair.a_id, a_mapped, 10, 0x30);

    // A now offers both: the private address, which is what it can see, and
    // the mapped one, which only B could tell it.
    let out = pair.a.poll(6_000, minter(0x50));
    let (_, payload) = out
        .relayed
        .first()
        .expect("A did not re-advertise after learning its mapped address");

    let key = DiscoKey::new([0x5A; KEY_LEN]);
    let Ok(karst_disco::msg::Message::CallMeMaybe { candidates }) =
        karst_disco::msg::open(payload, &key)
    else {
        panic!("the advertisement is not a decodable CallMeMaybe");
    };
    let offered: Vec<SocketAddr> = candidates.iter().map(|c| c.0).collect();
    assert!(
        offered.contains(&a_mapped),
        "the mapped address was not advertised: {offered:?}"
    );
    assert!(
        offered.contains(&a_private),
        "the private address was dropped: {offered:?}"
    );
    assert_eq!(
        offered.first(),
        Some(&a_private),
        "a peer's claim was offered ahead of an address this node observed itself"
    );
}

/// A relay that mislabels which node sent a datagram must not be able to move
/// candidates between peers. The AVEN tag and the relay-stamped source are two
/// independent bindings and both have to name the same peer.
///
/// **The case that matters is a peer the relay legitimately admits**, not an
/// unknown one. A stranger's id resolves to nothing and is refused by the
/// lookup alone; the attack is C — admitted, holding its own pair key with this
/// node — capturing A's authentic advertisement off the relay and replaying it
/// under C's own identity. Only comparing the two bindings catches that, and a
/// test that used a stranger would pass with the comparison deleted.
#[test]
fn one_peer_cannot_replay_anothers_advertisement_under_its_own_identity() {
    let mut pair = Pair::new();
    let a_addr = addr(1, 51820);
    pair.a.set_interfaces(&[a_addr.ip()], a_addr.port());

    // A third node B has also admitted, with its own pair key.
    let c_id = node_id(3);
    assert!(pair
        .b
        .add_peer(DiscoKey::new([0xC3; KEY_LEN]), &pair.b_id, &c_id));

    let out = pair.a.poll(0, minter(0x10));
    let (_, payload) = out.relayed.first().expect("A produced no advertisement");

    assert!(
        !pair.b.inbound_from_relay(c_id, payload, 0),
        "an admitted peer replayed another's advertisement under its own identity"
    );
    assert!(
        !pair.b.inbound_from_relay(node_id(9), payload, 0),
        "a relay-stamped source that names nobody was accepted"
    );
    assert!(
        pair.b.inbound_from_relay(pair.a_id, payload, 0),
        "the same advertisement under the right source was refused"
    );
}

/// Without an advertisement there is nothing to probe. This is the state the
/// daemon was in before candidate gathering existed, and it is worth pinning:
/// the failure was silent, and a node that discovers nothing looks exactly like
/// a node whose peers are unreachable.
#[test]
fn a_node_that_advertises_nothing_produces_no_probes() {
    let mut pair = Pair::new();
    let b_addr = addr(2, 51820);
    pair.b.set_interfaces(&[b_addr.ip()], b_addr.port());

    // A has no interfaces, so it advertises nothing and B learns no candidate.
    let delivered = step(&mut pair.a, &mut pair.b, pair.a_id, addr(1, 51820), 0, 0x10);
    assert_eq!(delivered.advertisements, 0);
    assert!(
        pair.b.poll(10, minter(0x20)).datagrams.is_empty(),
        "B probed an address it was never given"
    );
    assert!(pair.b.path_changes().is_empty());
}
