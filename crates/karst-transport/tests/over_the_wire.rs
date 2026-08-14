// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! **First packets** — a complete Karst handshake and data exchange over real
//! UDP sockets. PLAN.md Phase 2's opening milestone.
//!
//! Everything before this ran in-process or against a simulated link. Here two
//! sockets on loopback carry genuine fragmented datagrams: a 2378-byte
//! `HandshakeInit` split across two MTU-legal packets, MAC-verified,
//! reassembled, answered, and followed by authenticated data.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use std::sync::Arc;

use karst_crypto::kem::{Kem, MlKem768Backend as MlKem};
use karst_crypto::{SuiteId, SuitePolicy};
use karst_node::{Action, Session};
use karst_noise::handshake::{PeerPublic, ResponderRandomness, StaticKeys};
use karst_noise::transport::TransportSession;
use karst_proto::dos::{mac1_key, FragMacKey};
use karst_proto::reassembly::{Accept, Config as ReasmConfig, Reassembler};
use karst_proto::{fragment, split_datagram, MessageType};
use karst_transport::{source_key, UdpTransport, MAX_DATAGRAM};

const PSK: [u8; 32] = [0x42; 32];

fn peer_of(k: &StaticKeys) -> PeerPublic {
    PeerPublic {
        kem_pk: MlKem::public_key_from_bytes(&MlKem::public_key_bytes(&k.kem_pk)).unwrap(),
        dh_pk: k.dh_pk,
        psk: PSK,
    }
}
fn policy() -> SuitePolicy {
    SuitePolicy {
        minimum: SuiteId::KARST_1,
        supported: vec![SuiteId::KARST_1],
    }
}

/// Two peers, two sockets, one tunnel.
#[test]
fn a_handshake_and_data_exchange_over_real_udp() {
    let a_keys = Arc::new(StaticKeys::from_seed(&[0xA1; 64], &[0xA2; 32]));
    let b_keys = Arc::new(StaticKeys::from_seed(&[0xB1; 64], &[0xB2; 32]));
    let a_pub = peer_of(&a_keys);
    let b_pub = peer_of(&b_keys);

    let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let sock_a = UdpTransport::bind(bind).unwrap();
    let sock_b = UdpTransport::bind(bind).unwrap();
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();
    let to = Duration::from_secs(5);
    sock_a.set_read_timeout(Some(to)).unwrap();
    sock_b.set_read_timeout(Some(to)).unwrap();

    let mut initiator = Session::new(
        Arc::clone(&a_keys),
        Arc::new(b_pub),
        policy(),
        SuiteId::KARST_1,
        7,
        1,
    );

    // ── initiator: connect, transmit every fragment over the wire ──────────
    let mut sent = 0usize;
    for action in initiator.connect(0, [0x5A; 32]) {
        if let Action::Send(d) = action {
            assert!(d.len() <= MAX_DATAGRAM, "datagram must fit the link MTU");
            sock_a.send_to(&d, addr_b).unwrap();
            sent += 1;
        }
    }
    assert_eq!(sent, 2, "a 2378-byte HandshakeInit is two fragments");

    // ── responder: receive fragments, reassemble, answer ───────────────────
    // §13.7: fragments are MAC'd with the *recipient's* static key, so the
    // response to A is keyed by A's, not by the responder's own.
    let to_initiator_mac = FragMacKey::new(&mac1_key(&MlKem::public_key_bytes(&a_keys.kem_pk)));
    let mut r_reasm = Reassembler::new(ReasmConfig::default());
    let mut buf = [0u8; MAX_DATAGRAM];

    let mut msg1 = None;
    let mut from_a = addr_a;
    for _ in 0..2 {
        let (n, from) = sock_b.recv_from(&mut buf).unwrap();
        from_a = from;
        let datagram = buf.get(..n).unwrap();
        let (hdr, payload) = split_datagram(datagram).unwrap();
        if let Accept::Complete(m) = r_reasm.push(source_key(from), true, &hdr, payload, 0) {
            msg1 = Some(m.to_vec());
        }
    }
    let msg1 = msg1.expect("HandshakeInit must reassemble from two datagrams");
    assert_eq!(msg1.len(), 2378, "spec §6.1");

    let (msg2, sess) = Session::accept(
        &b_keys,
        &policy(),
        &msg1,
        &a_pub,
        &ResponderRandomness {
            e_dh_seed: [0xF1; 32],
            encap_rand_e: [0xF2; 32],
            encap_rand_s: [0xF3; 32],
        },
        2,
        0,
    )
    .expect("handshake must be accepted");
    let mut r_session: Option<TransportSession> = Some(sess);
    assert_eq!(msg2.len(), 2236, "spec §6.2");

    for f in fragment(MessageType::HandshakeResponse, 1, &msg2, &to_initiator_mac).unwrap() {
        assert!(f.len() <= MAX_DATAGRAM);
        sock_b.send_to(&f, from_a).unwrap();
    }

    // ── initiator: reassemble the response, establish ──────────────────────
    let mut established = false;
    let mut data_frags = Vec::new();
    for _ in 0..2 {
        let (n, from) = sock_a.recv_from(&mut buf).unwrap();
        let datagram = buf.get(..n).unwrap().to_vec();
        for action in initiator.handle(&datagram, source_key(from), 0) {
            if action == Action::Established {
                established = true;
                data_frags = initiator.send(b"first packets over real UDP", 0).unwrap();
            }
        }
    }
    assert!(established, "session must establish over the wire");
    assert!(initiator.established());

    // ── data ───────────────────────────────────────────────────────────────
    for f in &data_frags {
        sock_a.send_to(f, addr_b).unwrap();
    }

    let mut delivered = None;
    for _ in 0..data_frags.len() {
        let (n, from) = sock_b.recv_from(&mut buf).unwrap();
        let datagram = buf.get(..n).unwrap();
        let (hdr, payload) = split_datagram(datagram).unwrap();
        if let Accept::Complete(m) = r_reasm.push(source_key(from), true, &hdr, payload, 0) {
            delivered = r_session.as_mut().unwrap().open(m, 0).ok();
        }
    }

    let payload = delivered.expect("data must arrive and authenticate");
    assert_eq!(
        payload.get(..27),
        Some(&b"first packets over real UDP"[..]),
        "plaintext must survive the round trip"
    );
}

/// Every datagram Karst emits must fit the minimum-MTU budget. Asserting it at
/// the socket boundary catches a fragmentation regression that in-process tests
/// would not — the failure would otherwise appear only on a real network.
#[test]
fn every_emitted_datagram_fits_the_link_mtu() {
    let a_keys = Arc::new(StaticKeys::from_seed(&[0xC1; 64], &[0xC2; 32]));
    let b_keys = Arc::new(StaticKeys::from_seed(&[0xD1; 64], &[0xD2; 32]));
    let b_pub = peer_of(&b_keys);

    let mut s = Session::new(
        Arc::clone(&a_keys),
        Arc::new(b_pub),
        policy(),
        SuiteId::KARST_1,
        7,
        1,
    );
    let sock = UdpTransport::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let sink = UdpTransport::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap()
        .local_addr()
        .unwrap();

    // connect plus several retransmissions
    let mut actions = s.connect(0, [0x11; 32]);
    for t in [400u64, 1200, 2800, 6000] {
        actions.extend(s.poll(t, [0x11; 32]));
    }
    let mut count = 0;
    for a in actions {
        if let Action::Send(d) = a {
            sock.send_to(&d, sink)
                .unwrap_or_else(|e| panic!("oversized datagram escaped: {e}"));
            count += 1;
        }
    }
    assert!(
        count >= 4,
        "expected retransmissions, saw {count} datagrams"
    );
}
