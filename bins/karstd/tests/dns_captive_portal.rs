// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! §7.3's captive-portal row: **do nothing special.**
//!
//! A captive portal hijacks DNS — every question, not just the one it needs
//! to answer, gets a short-TTL response pointing at its own login page. The
//! wrong fix is a resolver that "helpfully" detects and bypasses that: the
//! failure mode it would create is a portal a user cannot log in to at all,
//! which is worse than any answer being wrong. The right behaviour, and the
//! only thing this file checks, is that `KarstDNS` does not try: the mesh zone
//! keeps answering out of the netmap regardless of what the hijacking
//! upstream says, and everything else gets forwarded unmodified — hijacked
//! answer included.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use karst_dns::{Config, MeshPeer, Resolver};

fn query(name: &str) -> Message {
    let mut request = Message::new(53, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii(name).expect("DNS name"),
        RecordType::A,
    ));
    request
}

/// A portal that answers *every* question the same way: a five-second TTL
/// and its own login-page address, regardless of what was asked. One query,
/// then it exits — this file gives each test its own portal rather than a
/// shared long-lived one, so a test can never observe a stale reply from a
/// previous case.
fn captive_portal() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("portal socket");
    let address = socket.local_addr().expect("portal address");
    std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let mut buffer = [0u8; 512];
        let Ok((length, client)) = socket.recv_from(&mut buffer) else {
            return;
        };
        let Ok(request) = karst_dns::message::decode(&buffer[..length]) else {
            return;
        };
        let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.metadata.response_code = ResponseCode::NoError;
        response.add_queries(request.queries.iter().cloned());
        let name = request
            .queries
            .first()
            .map_or_else(Name::root, |q| q.name().clone());
        // The portal's login page, and a TTL short enough that a client
        // would notice its answer expiring the moment the portal is gone —
        // exactly what a hijack looks like on the wire.
        response.add_answer(Record::from_rdata(
            name,
            5,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 200))),
        ));
        let _ = socket.send_to(&response.to_vec().expect("portal reply"), client);
    });
    address
}

/// The mesh zone is authenticated by the control channel, not by the portal —
/// it must keep answering out of the netmap even while every other question
/// on the network is being hijacked.
#[test]
fn captive_portal_leaves_mesh_names_unaffected() {
    let portal = captive_portal();
    let resolver = Resolver::new(
        Config::new(vec![portal], vec![], vec![], "aquifer.karst", true).expect("config"),
        [MeshPeer::new("atlas", [Ipv4Addr::new(100, 64, 0, 9)], [])],
    );

    let wire = query("atlas.aquifer.karst.").to_vec().expect("wire query");
    let answer = karst_dns::service::handle_wire(&resolver, &wire).expect("authoritative answer");
    let decoded = karst_dns::message::decode(&answer).expect("decode");
    assert_eq!(decoded.answers.len(), 1);
    let RData::A(A(address)) = &decoded.answers[0].data else {
        panic!("expected an A record, got {:?}", decoded.answers[0].data);
    };
    assert_eq!(
        *address,
        Ipv4Addr::new(100, 64, 0, 9),
        "the mesh answer must be the netmap's address, never the portal's login page"
    );
    // `handle_wire` returned synchronously with an authoritative answer,
    // which is the proof that the mesh name was never forwarded: nothing in
    // this test ever sent `portal` a query, so it has nothing to say about
    // this case beyond what `dns_leak.rs` already checks for the general
    // one. `portal`'s background thread simply exits on its read timeout.
}

/// Anything the mesh zone does not own is forwarded to the portal, and
/// whatever the portal says comes back **unmodified** — no portal detection,
/// no rewriting, no substituted answer. Bypassing the hijack, however
/// well-intentioned, is the failure mode that leaves a user unable to reach
/// the portal's login page at all.
#[test]
fn captive_portal_answers_pass_through_unmodified() {
    let portal = captive_portal();
    let resolver = Resolver::new(
        Config::new(vec![portal], vec![], vec![], "aquifer.karst", true).expect("config"),
        [],
    );

    let wire = query("example.com.").to_vec().expect("wire query");
    let answer = karst_dns::service::handle_wire(&resolver, &wire).expect("forwarded answer");
    let decoded = karst_dns::message::decode(&answer).expect("decode");

    assert_eq!(
        decoded.answers.len(),
        1,
        "the portal's one answer, no more and no fewer"
    );
    assert_eq!(
        decoded.answers[0].ttl, 5,
        "the hijacked TTL must survive unmodified"
    );
    let RData::A(A(address)) = &decoded.answers[0].data else {
        panic!("expected an A record, got {:?}", decoded.answers[0].data);
    };
    assert_eq!(
        *address,
        Ipv4Addr::new(192, 0, 2, 200),
        "the portal's login-page address must reach the client exactly as sent"
    );
}
