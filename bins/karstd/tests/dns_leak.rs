// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! DNS leak regressions at the daemon crate boundary.
//!
//! The upstream socket is intentionally real rather than mocked: a policy
//! decision that accidentally opens a socket is precisely the failure this
//! test is meant to catch.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use karst_dns::{Config, MeshPeer, Resolver, Route};

fn query(name: &str) -> Vec<u8> {
    let mut request = Message::new(19, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii(name).expect("DNS name"),
        RecordType::A,
    ));
    request.to_vec().expect("DNS wire query")
}

fn hostile_upstream() -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("hostile upstream");
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("timeout");
    let address = socket.local_addr().expect("address");
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        let mut packet = [0; 512];
        if let Ok((length, _)) = socket.recv_from(&mut packet) {
            let _ = sent.send(packet[..length].to_vec());
        }
    });
    (address, received)
}

#[test]
fn mesh_name_never_reaches_a_logging_upstream() {
    let (hostile, received) = hostile_upstream();
    let resolver = Resolver::new(
        Config::new(vec![hostile], vec![], vec![], "aquifer.karst", true).expect("config"),
        [MeshPeer::new("atlas", [Ipv4Addr::new(100, 64, 0, 2)], [])],
    );
    let answer = karst_dns::service::handle_wire(&resolver, &query("missing.aquifer.karst."))
        .expect("authoritative NXDOMAIN");
    assert_eq!(
        karst_dns::message::decode(&answer)
            .expect("response")
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert!(received.recv_timeout(Duration::from_millis(350)).is_err());
}

#[test]
fn failed_split_route_never_falls_back_to_a_logging_global_upstream() {
    let (hostile, received) = hostile_upstream();
    let unavailable: SocketAddr = "127.0.0.1:9".parse().expect("discard port");
    let resolver = Resolver::new(
        Config::new(
            vec![hostile],
            vec![],
            vec![Route {
                match_domain: "internal.example".to_owned(),
                resolvers: vec![unavailable],
            }],
            "aquifer.karst",
            true,
        )
        .expect("config"),
        [],
    );
    assert!(karst_dns::service::handle_wire(&resolver, &query("db.internal.example.")).is_err());
    assert!(received.recv_timeout(Duration::from_millis(350)).is_err());
}
