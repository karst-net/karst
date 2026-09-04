// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The opt-in `[metrics] listen` HTTP surface —
//! plans/phase-6/08-observability.md §3.1/§5 W6 item 2.
//!
//! **A thin proxy in front of the control socket, not a second computation
//! of the same numbers.** Every request here dials the same local socket
//! `karst metrics` does ([`ipc::Command::Metrics`]) and returns exactly what
//! came back, byte for byte. That is what makes "the IPC verb and this
//! listener agree" true by construction — there is only one place the text
//! is ever assembled — rather than something two independent code paths
//! could drift apart on the day someone edits one and not the other.
//!
//! **Loopback-only, and already enforced by the time this file runs.**
//! [`crate::config::Config::load`] and
//! [`crate::config::Config::from_netmap_enforced`] both refuse a
//! non-loopback `[metrics] listen` address at startup, so `listen` here is
//! never anything else — this module does not re-check it.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

use crate::ipc;
use crate::run::Shutdown;

/// How long a poll-for-shutdown iteration waits before checking again —
/// mirrors the control socket's own accept loop (`run.rs`'s `TICK`); not
/// shared directly because the two listeners have nothing else in common.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Serve `GET /metrics` on `listen` until `shutdown` is requested.
///
/// # Errors
/// Binding the listener failed. A per-connection I/O error is logged and
/// does not stop the listener — one bad client must not take the scrape
/// target down for the next one.
pub(crate) fn serve(
    listen: SocketAddr,
    socket_path: &Path,
    shutdown: &Shutdown,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    // Non-blocking so this loop can also poll `shutdown`, the same reason
    // the control socket's own accept loop does.
    listener.set_nonblocking(true)?;
    while !shutdown.requested() {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                if let Err(error) = handle(stream, socket_path) {
                    tracing::debug!(%error, "metrics HTTP request failed");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => std::thread::sleep(POLL_INTERVAL),
        }
    }
    Ok(())
}

/// Handle one connection: read the request line, discard headers (nothing
/// here needs them — there is exactly one resource and no request body),
/// and answer.
fn handle(mut stream: TcpStream, socket_path: &Path) -> std::io::Result<()> {
    // Bounded so a client that connects and never sends a full request line
    // cannot hold a thread forever — the same discipline a local
    // administrative socket does not need but a network-facing one does.
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 || header == "\r\n" || header == "\n" {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method != "GET" || path != "/metrics" {
        return respond(&mut stream, "404 Not Found", "text/plain", "not found\n");
    }

    match ipc::request(socket_path, &ipc::Command::Metrics) {
        // The Prometheus text-exposition content type, version 0.0.4 — what
        // `prometheus::exporters` and every scraper this daemon is meant to
        // be found by expect.
        Ok(body) => respond(&mut stream, "200 OK", "text/plain; version=0.0.4", &body),
        Err(error) => respond(
            &mut stream,
            "502 Bad Gateway",
            "text/plain",
            &format!("karstd: could not reach the control socket: {error}\n"),
        ),
    }
}

fn respond(
    stream: &mut impl Write,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::serve;
    use crate::ipc;
    use crate::run::Shutdown;
    use crate::scratch::Scratch;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// End to end: bind the control socket, bind the HTTP listener, ask both
    /// for `metrics`, and check the bodies match — the property §6 of the
    /// observability plan requires ("byte-identical output for the same
    /// underlying state").
    #[test]
    fn the_http_listener_and_the_ipc_verb_return_the_same_bytes() {
        let dir = Scratch::new("metrics_http");
        let socket_path = dir.join("karstd.sock");
        let control = ipc::bind(&socket_path).expect("bind control socket");
        let shutdown = Shutdown::default();

        let reply_body =
            "# HELP karst_tx_packets test\n# TYPE karst_tx_packets counter\nkarst_tx_packets 1\n";

        let http_addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let probe = std::net::TcpListener::bind(http_addr).expect("bind http");
        let bound = probe.local_addr().expect("local addr");
        drop(probe); // serve() binds its own; avoid a race for the port

        std::thread::scope(|scope| {
            let control_thread = scope.spawn(|| {
                let (mut stream, _) = control.accept().expect("accept");
                ipc::serve(&mut stream, |_| reply_body.to_owned()).expect("serve")
            });
            let http_thread = scope.spawn(|| serve(bound, &socket_path, &shutdown));

            // The HTTP listener binds asynchronously in its own thread; give
            // it a moment before the client dials.
            let mut got = String::new();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match TcpStream::connect(bound) {
                    Ok(mut stream) => {
                        stream
                            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
                            .expect("write request");
                        stream.read_to_string(&mut got).expect("read response");
                        break;
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("connect: {e}"),
                }
            }

            shutdown.request();
            control_thread.join().expect("control thread");
            http_thread
                .join()
                .expect("http thread")
                .expect("http serve");

            assert!(got.contains("200 OK"), "got {got:?}");
            assert!(
                got.ends_with(reply_body),
                "HTTP body does not match the IPC reply byte for byte: {got:?}"
            );
        });
    }

    /// A request for anything but `GET /metrics` gets a 404, not the
    /// daemon's internal state — this listener serves exactly one resource.
    #[test]
    fn an_unknown_path_gets_a_404() {
        let dir = Scratch::new("metrics_http_404");
        let socket_path = dir.join("karstd.sock");
        let _control = ipc::bind(&socket_path).expect("bind control socket");
        let shutdown = Shutdown::default();

        let http_addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let probe = std::net::TcpListener::bind(http_addr).expect("bind http");
        let bound = probe.local_addr().expect("local addr");
        drop(probe);

        std::thread::scope(|scope| {
            let http_thread = scope.spawn(|| serve(bound, &socket_path, &shutdown));

            let mut got = String::new();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match TcpStream::connect(bound) {
                    Ok(mut stream) => {
                        stream
                            .write_all(b"GET /nonsense HTTP/1.1\r\nHost: x\r\n\r\n")
                            .expect("write request");
                        stream.read_to_string(&mut got).expect("read response");
                        break;
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("connect: {e}"),
                }
            }

            shutdown.request();
            http_thread
                .join()
                .expect("http thread")
                .expect("http serve");

            assert!(got.starts_with("HTTP/1.1 404"), "got {got:?}");
        });
    }
}
