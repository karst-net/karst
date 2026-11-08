// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Socket adapters for the DNS wire handler.

use std::io;
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::time::Duration;

use crate::service;
use crate::Resolver;

/// Receive and answer one UDP request. Keeping one datagram at a time makes
/// this usable from both a conventional socket loop and Karst's userspace IP
/// stack, which supplies the equivalent datagram boundary itself.
pub fn serve_udp_once(socket: &UdpSocket, resolver: &Resolver) -> io::Result<()> {
    serve_udp_once_with(socket, resolver, |_, _| {})
}

/// As [`serve_udp_once`], and additionally calls `on_answered` with the
/// queried name and every A/AAAA record the response carried (ADR-0068's
/// karst-net/karst input for DNS-zone-scoped Gateway affinity) whenever the
/// response actually answered with one — never for a malformed, SERVFAIL, or
/// address-less response. Kept as a second function rather than a parameter
/// on [`serve_udp_once`] with a default: a no-op closure costs nothing extra
/// to call, and every existing caller stays unchanged.
pub fn serve_udp_once_with(
    socket: &UdpSocket,
    resolver: &Resolver,
    mut on_answered: impl FnMut(&str, &[(IpAddr, Duration)]),
) -> io::Result<()> {
    let mut request = vec![0u8; 65_535];
    let (length, client) = socket.recv_from(&mut request)?;
    let Some(request) = request.get(..length) else {
        return Ok(());
    };
    let response = match service::handle_wire(resolver, request) {
        Ok(response) => response,
        Err(_) => match service::servfail_wire(request) {
            Some(response) => response,
            None => return Ok(()), // malformed datagrams are not amplifiers
        },
    };
    report_answer(request, &response, &mut on_answered);
    socket.send_to(&response, client)?;
    Ok(())
}

/// Receive and answer one RFC 7766 length-prefixed TCP DNS request.
pub fn serve_tcp_once(listener: &TcpListener, resolver: &Resolver) -> io::Result<()> {
    serve_tcp_once_with(listener, resolver, |_, _| {})
}

/// As [`serve_tcp_once`], reporting answered addresses the same way
/// [`serve_udp_once_with`] does.
pub fn serve_tcp_once_with(
    listener: &TcpListener,
    resolver: &Resolver,
    mut on_answered: impl FnMut(&str, &[(IpAddr, Duration)]),
) -> io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    // The caller polls a non-blocking listener, and whether an accepted socket
    // inherits that flag is a platform decision POSIX declines to make: BSD and
    // macOS inherit it, Linux does not. The reads below are `read_exact`, which
    // reports `WouldBlock` as a failure rather than waiting, so on an inheriting
    // platform a request whose bytes had not all arrived by this line would be
    // dropped — intermittently, and only there. Asked for explicitly so both
    // platforms answer DNS the same way.
    stream.set_nonblocking(false)?;
    let request = crate::message::read_framed(&mut stream)?;
    let response = match service::handle_wire(resolver, &request) {
        Ok(response) => response,
        Err(_) => match service::servfail_wire(&request) {
            Some(response) => response,
            None => return Ok(()),
        },
    };
    report_answer(&request, &response, &mut on_answered);
    crate::message::write_framed(&mut stream, &response)
}

/// Shared by [`serve_udp_once_with`] and [`serve_tcp_once_with`]: decode the
/// request only far enough to name the query, extract the response's
/// addresses, and call the hook — skipped entirely when there is nothing to
/// report, so a hook never sees an empty address list.
fn report_answer(
    request: &[u8],
    response: &[u8],
    on_answered: &mut impl FnMut(&str, &[(IpAddr, Duration)]),
) {
    let addresses = service::answered_addresses(response);
    if addresses.is_empty() {
        return;
    }
    if let Ok(decoded) = crate::message::decode(request) {
        if let Some(query) = decoded.queries.first() {
            // Canonicalized the same way `crate::canonical_name` normalizes
            // every name this crate compares — including a `dns_zone`
            // binding's own stored form (`route_offer::canonical_zone`
            // matches it) — so a caller comparing this name against a zone
            // binding is comparing like with like, not a bare wire name
            // (lower-case, no trailing root dot) against one that still has
            // it.
            if let Ok(name) = crate::canonical_name(&query.name().to_ascii()) {
                on_answered(&name, &addresses);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Upstream};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::thread;

    #[test]
    fn serves_an_authoritative_udp_request() {
        let listener = UdpSocket::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let resolver = Resolver::new(
            Config::new(vec![], vec![], vec![], "aquifer.karst", true).expect("config"),
            [],
        );
        let worker = thread::spawn(move || serve_udp_once(&listener, &resolver));
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("timeout");
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("missing.aquifer.karst.").expect("name"),
            RecordType::A,
        ));
        client
            .send_to(&request.to_vec().expect("wire"), address)
            .expect("send");
        let mut response = [0u8; 512];
        let (length, _) = client.recv_from(&mut response).expect("response");
        assert_eq!(
            crate::message::decode(&response[..length])
                .expect("decode")
                .metadata
                .response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
        worker.join().expect("worker").expect("serve");
    }

    #[test]
    fn serves_an_authoritative_tcp_request() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let resolver = Resolver::new(
            Config::new(vec![], vec![], vec![], "aquifer.karst", true).expect("config"),
            [],
        );
        let worker = thread::spawn(move || serve_tcp_once(&listener, &resolver));
        let mut client = TcpStream::connect(address).expect("client");
        let mut request = Message::new(2, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("missing.aquifer.karst.").expect("name"),
            RecordType::A,
        ));
        let wire = request.to_vec().expect("wire");
        client
            .write_all(&u16::try_from(wire.len()).expect("size").to_be_bytes())
            .expect("length");
        client.write_all(&wire).expect("query");
        let mut prefix = [0u8; 2];
        client.read_exact(&mut prefix).expect("response length");
        let mut response = vec![0; usize::from(u16::from_be_bytes(prefix))];
        client.read_exact(&mut response).expect("response");
        assert_eq!(
            crate::message::decode(&response)
                .expect("decode")
                .metadata
                .response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
        worker.join().expect("worker").expect("serve");
    }

    #[test]
    fn reports_the_queried_name_and_its_addresses_on_a_successful_answer() {
        use crate::MeshPeer;
        use std::net::Ipv4Addr;
        use std::sync::{Arc, Mutex};

        type Reported = Vec<(String, Vec<(IpAddr, Duration)>)>;

        let listener = UdpSocket::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let resolver = Resolver::new(
            Config::new(vec![], vec![], vec![], "aquifer.karst", true).expect("config"),
            [MeshPeer::new(
                "alpha",
                [Ipv4Addr::new(100, 64, 0, 2)],
                [std::net::Ipv6Addr::LOCALHOST],
            )],
        );
        let reported: Arc<Mutex<Reported>> = Arc::new(Mutex::new(Vec::new()));
        let reported_worker = Arc::clone(&reported);
        let worker = thread::spawn(move || {
            serve_udp_once_with(&listener, &resolver, |name, addresses| {
                reported_worker
                    .lock()
                    .expect("lock")
                    .push((name.to_owned(), addresses.to_vec()));
            })
        });
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("timeout");
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("alpha.aquifer.karst.").expect("name"),
            RecordType::A,
        ));
        client
            .send_to(&request.to_vec().expect("wire"), address)
            .expect("send");
        let mut response = [0u8; 512];
        let _ = client.recv_from(&mut response).expect("response");
        worker.join().expect("worker").expect("serve");

        let reported = reported.lock().expect("lock");
        assert_eq!(
            *reported,
            vec![(
                "alpha.aquifer.karst".to_owned(),
                vec![(
                    IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
                    Duration::from_secs(60)
                )]
            )],
            "the reported name must be canonical (no trailing root dot), \
             matching a dns_zone binding's own stored form"
        );
    }

    #[test]
    fn an_nxdomain_answer_reports_nothing() {
        use std::sync::{Arc, Mutex};

        let listener = UdpSocket::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let resolver = Resolver::new(
            Config::new(vec![], vec![], vec![], "aquifer.karst", true).expect("config"),
            [],
        );
        let reported: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let reported_worker = Arc::clone(&reported);
        let worker = thread::spawn(move || {
            serve_udp_once_with(&listener, &resolver, |name, _| {
                reported_worker.lock().expect("lock").push(name.to_owned());
            })
        });
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .expect("timeout");
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("missing.aquifer.karst.").expect("name"),
            RecordType::A,
        ));
        client
            .send_to(&request.to_vec().expect("wire"), address)
            .expect("send");
        let mut response = [0u8; 512];
        let _ = client.recv_from(&mut response).expect("response");
        worker.join().expect("worker").expect("serve");

        assert!(
            reported.lock().expect("lock").is_empty(),
            "an NXDOMAIN answer has no addresses to report"
        );
    }

    #[test]
    fn failed_split_route_returns_servfail() {
        let listener = UdpSocket::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let resolver = Resolver::new(
            Config::new(
                vec![Upstream::plain("192.0.2.53:53".parse().expect("global"))],
                vec![],
                vec![crate::Route {
                    match_domain: "internal.example".to_owned(),
                    resolvers: vec![Upstream::plain("127.0.0.1:9".parse().expect("down"))],
                }],
                "aquifer.karst",
                true,
            )
            .expect("config"),
            [],
        );
        let worker = thread::spawn(move || serve_udp_once(&listener, &resolver));
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .expect("timeout");
        let mut request = Message::new(3, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("db.internal.example.").expect("name"),
            RecordType::A,
        ));
        client
            .send_to(&request.to_vec().expect("wire"), address)
            .expect("send");
        let mut response = [0u8; 512];
        let (length, _) = client.recv_from(&mut response).expect("SERVFAIL");
        assert_eq!(
            crate::message::decode(&response[..length])
                .expect("decode")
                .metadata
                .response_code,
            hickory_proto::op::ResponseCode::ServFail
        );
        worker.join().expect("worker").expect("serve");
    }
}
