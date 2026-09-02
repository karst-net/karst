// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The deliberately small **outbound** sidecar attachment for userspace mode.
//!
//! SOCKS5 is bound only where the operator configured it. It accepts literal
//! overlay IP addresses; accepting DNS names would silently make resolution a
//! host-network operation outside the Karst policy boundary.
//!
//! The other direction is [`crate::publish`]; the copy loop both use is
//! [`crate::pump`].

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use karst_tun::Userspace;

use crate::run::Shutdown;

pub(crate) fn serve(stack: &Userspace, listen: SocketAddr, shutdown: &Shutdown) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    std::thread::scope(|connections| {
        while !shutdown.requested() {
            match listener.accept() {
                Ok((stream, _)) => {
                    // **Back to blocking for the conversation itself.** BSD
                    // accepts inherit the listener's `O_NONBLOCK` and Linux
                    // accepts do not — POSIX leaves it unspecified — so without
                    // this the negotiation below runs non-blocking on macOS and
                    // blocking on Linux. It fails in the least visible way
                    // possible: SOCKS5 is a round trip, the client sends its
                    // CONNECT only after reading the method selection, and the
                    // daemon's `read_exact` for the request therefore arrives
                    // before the bytes do and returns `WouldBlock` as an error.
                    // The client sees its greeting answered and then an EOF, so
                    // userspace mode's whole outbound attachment was dead on
                    // macOS while every Linux test passed.
                    //
                    // `run.rs`'s control socket already does this, for this
                    // reason, and says so. Two other accept sites did not.
                    let _ = stream.set_nonblocking(false);
                    let stack = stack.clone();
                    connections.spawn(move || {
                        // **Reported, not discarded.** Every failure below
                        // closes the client's connection, and SOCKS5 has no
                        // reply for most of them — a client that asked for a
                        // name, or spoke HTTP, or named an overlay address the
                        // stack cannot reach, sees an EOF and nothing else. The
                        // operator debugging a sidecar that will not connect
                        // has this log and the client's silence, so the log has
                        // to carry the reason.
                        if let Err(error) = proxy(stream, &stack, shutdown) {
                            eprintln!("karstd: socks5 connection failed: {error}");
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    Ok(())
}

/// How long to wait for an overlay handshake before giving up.
///
/// The address is the client's choice, so this is a bound on what a local
/// process can make the daemon hold open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn proxy(mut client: TcpStream, stack: &Userspace, shutdown: &Shutdown) -> io::Result<()> {
    let destination = negotiate(&mut client)?;
    // The destination is in the message because it is the client's choice and
    // the most common reason this fails is that it named an address the stack
    // has no source address for — which the stack reports as "unaddressable"
    // and nothing else.
    let tunnel = stack
        .connect_tcp(destination.ip(), destination.port())
        .map_err(|e| io::Error::other(format!("overlay connection to {destination}: {e}")))?;
    // **Bounded, because the overlay address came from the client.** A SOCKS
    // client may ask for any address in the tailnet, including one nothing
    // answers at; waiting for the handshake without a deadline holds a thread
    // per such request until the daemon stops, which is a resource a local
    // process should not be able to consume by asking politely.
    //
    // **Every exit from here on releases the socket.** `pump` does it for the
    // conversation itself; the three paths that never reach a conversation do
    // it here, because a socket the stack still holds is one nothing will ever
    // free (GitHub issue [#49](https://github.com/karst-net/karst/issues/49)).
    let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    while !stack.tcp_can_send(tunnel) {
        if shutdown.requested() {
            stack.tcp_abort(tunnel);
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            // Abandoned rather than closed: nothing was established, and
            // waiting out the graceful grace period would hold exactly the
            // resource this deadline exists to bound.
            stack.tcp_abort(tunnel);
            // SOCKS5 reply 0x04: host unreachable. A closed socket would leave
            // the client guessing between "refused", "timed out" and "the proxy
            // died", which are three different things to debug.
            let _ = client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "overlay peer did not complete the handshake",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // A client that walked away between its request and this reply is an
    // ordinary event, and the overlay connection opened on its behalf has to go
    // with it.
    if let Err(e) = client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]) {
        stack.tcp_abort(tunnel);
        return Err(e);
    }
    crate::pump::pump(client, stack, tunnel, shutdown)
}

fn negotiate(client: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut hello = [0u8; 2];
    client.read_exact(&mut hello)?;
    if hello[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not SOCKS5"));
    }
    let mut methods = vec![0; usize::from(hello[1])];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS auth required",
        ));
    }
    client.write_all(&[5, 0])?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request)?;
    if request[..3] != [5, 1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only SOCKS CONNECT is supported",
        ));
    }
    let ip = match request[3] {
        1 => {
            let mut raw = [0u8; 4];
            client.read_exact(&mut raw)?;
            IpAddr::V4(Ipv4Addr::from(raw))
        }
        4 => {
            let mut raw = [0u8; 16];
            client.read_exact(&mut raw)?;
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        3 => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length)?;
            let mut ignored = vec![0; usize::from(length[0])];
            client.read_exact(&mut ignored)?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS domains are not supported",
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown SOCKS address type",
            ))
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use std::net::TcpListener;

    /// Drive `negotiate` over a real socket pair and return what it decided.
    ///
    /// A real pair rather than a cursor because `negotiate` reads *and* writes
    /// — the method-selection reply and the refusals are part of the protocol,
    /// and a one-directional fake could not observe them.
    fn negotiated(request: &[u8]) -> (io::Result<SocketAddr>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let sent = request.to_vec();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).expect("connect");
            let _ = s.write_all(&sent);
            let _ = s.flush();
            // Read whatever the server said back, then let it close.
            s.set_read_timeout(Some(Duration::from_millis(300))).ok();
            let mut out = Vec::new();
            let mut buf = [0u8; 64];
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        });
        let (mut server, _) = listener.accept().expect("accept");
        let decided = negotiate(&mut server);
        drop(server);
        (decided, client.join().expect("client thread"))
    }

    /// `05 01 00` — one method, "no authentication".
    const GREETING: &[u8] = &[5, 1, 0];

    #[test]
    fn a_connect_to_a_literal_v4_address_is_accepted() {
        let mut req = GREETING.to_vec();
        req.extend_from_slice(&[5, 1, 0, 1, 10, 0, 0, 7, 0x1f, 0x90]);
        let (decided, replies) = negotiated(&req);
        assert_eq!(
            decided.expect("accepted"),
            "10.0.0.7:8080".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(&replies[..2], &[5, 0], "method selection was not accepted");
    }

    #[test]
    fn a_connect_to_a_literal_v6_address_is_accepted() {
        let mut req = GREETING.to_vec();
        req.extend_from_slice(&[5, 1, 0, 4]);
        req.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        req.extend_from_slice(&[0, 22]);
        let (decided, _) = negotiated(&req);
        assert_eq!(
            decided.expect("accepted"),
            "[fd00::1]:22".parse::<SocketAddr>().expect("addr")
        );
    }

    #[test]
    fn a_domain_name_is_refused_and_its_bytes_are_consumed() {
        // ADR-0012 refuses names deliberately: resolving one through the host
        // resolver is an unreviewed path around Karst's packet and policy
        // boundary. The length and the name are still read, so the refusal is
        // a protocol answer rather than a desynchronised stream.
        let mut req = GREETING.to_vec();
        req.extend_from_slice(&[5, 1, 0, 3, 11]);
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        let (decided, _) = negotiated(&req);
        let err = decided.expect_err("names must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("domain"), "{err}");
    }

    #[test]
    fn a_client_offering_no_acceptable_method_is_told_so() {
        // §3 of RFC 1928: reply `05 FF`. Closing instead would leave the
        // client unable to distinguish "no shared method" from a dead proxy.
        let req = vec![5, 1, 2, 5, 1, 0, 1, 10, 0, 0, 1, 0, 80];
        let (decided, replies) = negotiated(&req);
        assert_eq!(
            decided.expect_err("refused").kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(replies, vec![5, 0xff], "the refusal was not sent");
    }

    #[test]
    fn anything_that_is_not_socks5_connect_is_refused() {
        for (label, tail) in [
            ("BIND", vec![5, 2, 0, 1, 10, 0, 0, 1, 0, 80]),
            ("UDP ASSOCIATE", vec![5, 3, 0, 1, 10, 0, 0, 1, 0, 80]),
            ("unknown address type", vec![5, 1, 0, 9, 0, 0]),
        ] {
            let mut req = GREETING.to_vec();
            req.extend_from_slice(&tail);
            let (decided, _) = negotiated(&req);
            assert!(decided.is_err(), "{label} was accepted");
        }
    }

    #[test]
    fn a_greeting_for_another_protocol_version_is_refused() {
        // A browser pointed at the wrong port speaks HTTP here. `GET ` starts
        // 0x47, which is not 5, and the refusal must be immediate rather than
        // an attempt to read a method list out of a request line.
        let (decided, _) = negotiated(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            decided.expect_err("refused").kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn every_truncation_is_refused_rather_than_read_past() {
        // The property this file most needs: it parses bytes from a local
        // process, and no prefix of a valid request may hang or panic. A short
        // read ends the connection, which `read_exact` reports as an error.
        let mut full = GREETING.to_vec();
        full.extend_from_slice(&[5, 1, 0, 1, 10, 0, 0, 7, 0x1f, 0x90]);
        for n in 0..full.len() {
            let (decided, _) = negotiated(&full[..n]);
            assert!(
                decided.is_err(),
                "a {n}-byte prefix was accepted as a complete request"
            );
        }
        assert!(negotiated(&full).0.is_ok(), "the whole request is fine");
    }
}
