// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Bounded UDP forwarding for resolver-selected upstreams.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::message;

const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_MESSAGE: usize = 65_535;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DNS query is malformed: {0}")]
    Query(String),
    #[error("DNS upstream did not return a valid matching response")]
    MismatchedResponse,
    #[error("all DNS upstreams failed: {0}")]
    Upstream(#[source] io::Error),
}

/// Send a query only to the supplied resolver set, returning the first valid
/// matching response. Callers choose this set from [`crate::service::Decision`]
/// and therefore cannot accidentally use global upstreams for a split route.
pub fn udp(query: &[u8], resolvers: &[SocketAddr]) -> Result<Vec<u8>, Error> {
    let request = message::decode(query).map_err(Error::Query)?;
    let mut last_error = None;
    for resolver in resolvers {
        match query_one(query, request.metadata.id, *resolver) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(Error::Upstream(last_error.unwrap_or_else(|| {
        io::Error::other("no DNS upstream configured")
    })))
}

fn query_one(query: &[u8], request_id: u16, resolver: SocketAddr) -> io::Result<Vec<u8>> {
    let bind = match resolver.ip() {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.send_to(query, resolver)?;
    let mut response = vec![0; MAX_MESSAGE];
    let (length, source) = socket.recv_from(&mut response)?;
    if source != resolver {
        return Err(io::Error::other(
            "DNS response source does not match upstream",
        ));
    }
    response.truncate(length);
    let decoded = message::decode(&response).map_err(io::Error::other)?;
    if decoded.metadata.id != request_id
        || decoded.metadata.message_type != hickory_proto::op::MessageType::Response
    {
        return Err(io::Error::other("DNS response does not match query"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use std::thread;

    #[test]
    fn forwards_only_to_the_requested_upstream() {
        let upstream = UdpSocket::bind("127.0.0.1:0").expect("upstream");
        let address = upstream.local_addr().expect("address");
        let worker = thread::spawn(move || {
            let mut buffer = [0; 512];
            let (length, client) = upstream.recv_from(&mut buffer).expect("query");
            let request = message::decode(&buffer[..length]).expect("decode request");
            let response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            upstream
                .send_to(&response.to_vec().expect("response"), client)
                .expect("reply");
        });
        let request = Message::new(17, MessageType::Query, OpCode::Query);
        let response = udp(&request.to_vec().expect("query"), &[address]).expect("forward");
        assert_eq!(message::decode(&response).expect("decode").metadata.id, 17);
        worker.join().expect("upstream worker");
    }
}
