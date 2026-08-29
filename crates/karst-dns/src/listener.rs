// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Socket adapters for the DNS wire handler.

use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};

use crate::service;
use crate::Resolver;

/// Receive and answer one UDP request. Keeping one datagram at a time makes
/// this usable from both a conventional socket loop and Karst's userspace IP
/// stack, which supplies the equivalent datagram boundary itself.
pub fn serve_udp_once(socket: &UdpSocket, resolver: &Resolver) -> io::Result<()> {
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
    socket.send_to(&response, client)?;
    Ok(())
}

/// Receive and answer one RFC 7766 length-prefixed TCP DNS request.
pub fn serve_tcp_once(listener: &TcpListener, resolver: &Resolver) -> io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    // The caller polls a non-blocking listener, and whether an accepted socket
    // inherits that flag is a platform decision POSIX declines to make: BSD and
    // macOS inherit it, Linux does not. The reads below are `read_exact`, which
    // reports `WouldBlock` as a failure rather than waiting, so on an inheriting
    // platform a request whose bytes had not all arrived by this line would be
    // dropped — intermittently, and only there. Asked for explicitly so both
    // platforms answer DNS the same way.
    stream.set_nonblocking(false)?;
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix)?;
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut request = vec![0u8; length];
    stream.read_exact(&mut request)?;
    let response = match service::handle_wire(resolver, &request) {
        Ok(response) => response,
        Err(_) => match service::servfail_wire(&request) {
            Some(response) => response,
            None => return Ok(()),
        },
    };
    let length = u16::try_from(response.len())
        .map_err(|_| io::Error::other("DNS TCP response exceeds RFC 7766 framing"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
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
    fn failed_split_route_returns_servfail() {
        let listener = UdpSocket::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let resolver = Resolver::new(
            Config::new(
                vec!["192.0.2.53:53".parse().expect("global")],
                vec![],
                vec![crate::Route {
                    match_domain: "internal.example".to_owned(),
                    resolvers: vec!["127.0.0.1:9".parse().expect("down")],
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
