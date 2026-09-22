// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! DNS-over-TLS (RFC 7858) upstream forwarding — the
//! [`Transport::Dot`](crate::Transport::Dot) leg, ADR-0034.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

use super::tls;
use crate::message;

/// Longer than plain UDP's 2s: a TLS handshake needs extra round trips.
const TIMEOUT: Duration = Duration::from_secs(4);

pub(super) fn query_one(
    query: &[u8],
    request_id: u16,
    resolver: SocketAddr,
    server_name: &str,
    pin: Option<&[u8; 32]>,
) -> io::Result<Vec<u8>> {
    let config = match pin {
        Some(pin) => tls::pinned_config(*pin)?,
        None => tls::shared_config()?,
    };
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| io::Error::other(format!("DoT: invalid TLS server name {server_name:?}")))?;
    let conn = ClientConnection::new(config, name).map_err(io::Error::other)?;

    let sock = TcpStream::connect(resolver)?;
    sock.set_read_timeout(Some(TIMEOUT))?;
    sock.set_write_timeout(Some(TIMEOUT))?;
    let mut tls = StreamOwned { conn, sock };

    // Complete the handshake — including certificate verification, whether
    // by CA chain or by pin (see `tls::pinned_config`) — before the query is
    // ever written, so a failed verification never leaks the query.
    tls.conn.complete_io(&mut tls.sock)?;

    message::write_framed(&mut tls, query)?;
    let response = message::read_framed(&mut tls)?;
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
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    /// A loopback DoT resolver: real TLS, terminated by a background thread,
    /// answering exactly one query with an empty NOERROR response.
    struct FakeResolver {
        address: SocketAddr,
        spki_pin: [u8; 32],
        received: std::sync::mpsc::Receiver<bool>,
    }

    fn start_fake_resolver(name: &str) -> FakeResolver {
        let cert = rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("cert");
        let key = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
        let leaf = CertificateDer::from(cert.cert.der().to_vec());
        let spki_pin = tls::spki_sha256(&leaf).expect("hash fixture cert");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf], key)
            .expect("server config");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            let conn = rustls::ServerConnection::new(Arc::new(server_config)).expect("conn");
            let mut tls = StreamOwned { conn, sock };
            let Ok(request) = message::read_framed(&mut tls) else {
                let _ = tx.send(false);
                return;
            };
            let _ = tx.send(true);
            let Ok(decoded) = message::decode(&request) else {
                return;
            };
            let response = Message::new(decoded.metadata.id, MessageType::Response, OpCode::Query);
            let _ = message::write_framed(&mut tls, &response.to_vec().expect("encode"));
        });
        FakeResolver {
            address,
            spki_pin,
            received: rx,
        }
    }

    fn query_bytes(id: u16) -> Vec<u8> {
        Message::new(id, MessageType::Query, OpCode::Query)
            .to_vec()
            .expect("encode")
    }

    /// An unpinned connection still runs ordinary WebPKI chain validation, so
    /// a self-signed test certificate is never trusted without a pin — this
    /// asserts that failure mode, not the pin machinery.
    #[test]
    fn an_unpinned_self_signed_resolver_is_rejected() {
        let resolver = start_fake_resolver("dot.test");
        let error = query_one(&query_bytes(1), 1, resolver.address, "dot.test", None)
            .expect_err("self-signed cert is not in the system trust store");
        assert!(!error.to_string().is_empty());
        // The handshake fails before any query bytes are sent.
        assert_eq!(resolver.received.recv(), Ok(false));
    }

    #[test]
    fn a_matching_pin_succeeds() {
        let resolver = start_fake_resolver("dot.test");
        let response = query_one(
            &query_bytes(3),
            3,
            resolver.address,
            "dot.test",
            Some(&resolver.spki_pin),
        )
        .expect("forward with correct pin");
        assert_eq!(message::decode(&response).expect("decode").metadata.id, 3);
        assert_eq!(resolver.received.recv(), Ok(true));
    }

    /// A pin still requires a server-name usable as SNI, but does not
    /// require it to match the certificate — the pin is what's trusted.
    #[test]
    fn a_pin_tolerates_a_server_name_the_certificate_does_not_carry() {
        let resolver = start_fake_resolver("dot.test");
        let response = query_one(
            &query_bytes(6),
            6,
            resolver.address,
            "not-in-the-cert.test",
            Some(&resolver.spki_pin),
        )
        .expect("pin alone is sufficient trust");
        assert_eq!(message::decode(&response).expect("decode").metadata.id, 6);
    }

    #[test]
    fn a_pin_mismatch_is_rejected_before_the_query_is_sent() {
        let resolver = start_fake_resolver("dot.test");
        let wrong_pin = [0u8; 32];
        let error = query_one(
            &query_bytes(4),
            4,
            resolver.address,
            "dot.test",
            Some(&wrong_pin),
        )
        .expect_err("pin mismatch");
        assert!(error.to_string().contains("pin"));
        assert_eq!(resolver.received.recv(), Ok(false));
    }

    #[test]
    fn an_unreachable_upstream_is_a_plain_error() {
        let unreachable: SocketAddr = "127.0.0.1:1".parse().expect("address");
        assert!(query_one(&query_bytes(5), 5, unreachable, "dot.test", None).is_err());
    }

    /// A manual sanity check against a real public DoT resolver, run once
    /// before landing ADR-0034's implementation and kept as a documented,
    /// explicitly-invoked network test — same pattern as
    /// `bins/karstd/tests/relay_live.rs`'s real-relay tests.
    #[test]
    #[ignore = "requires network access to 1.1.1.1:853"]
    fn a_real_public_resolver_answers_over_dot() {
        use hickory_proto::rr::{Name, RecordType};

        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.add_query(hickory_proto::op::Query::query(
            Name::from_ascii("example.com.").expect("name"),
            RecordType::A,
        ));
        let wire = request.to_vec().expect("encode");
        let response = query_one(
            &wire,
            1,
            "1.1.1.1:853".parse().expect("address"),
            "cloudflare-dns.com",
            None,
        )
        .expect("forward to a real public DoT resolver");
        let decoded = message::decode(&response).expect("decode");
        assert_eq!(
            decoded.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert!(!decoded.answers.is_empty());
    }
}
