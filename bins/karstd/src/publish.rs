// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The **inbound** half of userspace mode's attachment: a service on this node
//! reachable from the mesh.
//!
//! [`crate::socks5`] lets an attached workload dial the mesh. This is the
//! mirror — an overlay TCP port that the stack listens on, forwarded to a local
//! address the operator names. Together they are ADR-0012 §9's sidecar; with
//! only the first, a workload behind userspace mode could reach every peer and
//! no peer could reach it.
//!
//! **Nothing is published by default and nothing is inferred.** Each entry is
//! one line of configuration naming one overlay port and one destination, so
//! the node's entire inbound surface is a list the operator wrote. The mesh
//! side of it is still governed by the ACL: an inbound packet reaches this
//! module only after `Engine::deliver_to_host` has admitted it, so a peer no
//! rule permits cannot reach a published port at all.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use karst_tun::Userspace;

use crate::run::Shutdown;

/// How many connections one published port will carry at a time.
///
/// **This bound exists because the initiator is the mesh.** On the outbound
/// side the peer choosing to open a connection is a local process the operator
/// already trusts; here it is another node, and each connection it opens costs
/// a thread, a host socket, and 128 KiB of smoltcp buffers. In TUN mode the
/// equivalent limit is the kernel's, on a listener the daemon is not part of;
/// in userspace mode the daemon *is* the listener, so it has to have one.
///
/// At the limit no new listening socket is created, which is the same answer a
/// full accept queue gives: the peer's `SYN` goes unanswered and TCP retries.
const MAX_CONNECTIONS: usize = 64;

/// How long to wait for the backend to accept a forwarded connection.
///
/// The overlay peer is already connected by the time this is dialled, so a
/// backend that is slow to answer holds a mesh connection open. Short, because
/// the destination is a local service the operator configured.
const BACKEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Listen on one overlay port and forward what arrives to `to`.
///
/// Returns only when the daemon is shutting down or the overlay port cannot be
/// listened on at all; a backend that refuses a single connection is that
/// connection's problem, not the port's.
pub(crate) fn serve(stack: &Userspace, port: u16, to: SocketAddr, shutdown: &Shutdown) {
    let in_flight = AtomicUsize::new(0);
    let in_flight = &in_flight;
    std::thread::scope(|connections| {
        let mut announced_busy = false;
        while !shutdown.requested() {
            if in_flight.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                if !announced_busy {
                    // Once per busy episode, not once per refusal: a peer that
                    // keeps trying must not be able to write the log.
                    eprintln!(
                        "karstd: overlay port {port} is at its {MAX_CONNECTIONS}-connection \
                         limit; further connections wait"
                    );
                    announced_busy = true;
                }
                std::thread::sleep(crate::pump::IDLE_POLL);
                continue;
            }
            announced_busy = false;

            let listener = match stack.listen_tcp(port) {
                Ok(handle) => handle,
                Err(e) => {
                    eprintln!("karstd: cannot listen on overlay port {port}: {e}");
                    return;
                }
            };
            // **A listening socket becomes the connection**, so the accept loop
            // is "wait for this one to stop listening, then start another". The
            // dial to the backend happens in the spawned thread rather than
            // here, so the window in which this port has no listener at all is
            // a thread spawn rather than a TCP connect.
            //
            // **Wait for the handshake to finish, not for the socket to leave
            // LISTEN.** `is_active` is already true in `SYN-RECEIVED`, and a
            // socket in that state reports `may_recv() == false` — which is the
            // same answer it gives when the peer will never send again. Handing
            // such a socket to `pump` made it half-close the backend before the
            // request had arrived; the backend read `EOF`, closed, and the
            // daemon's write of the real request came back `EPIPE`. FINDINGS.md
            // 49, and it only ever showed on a machine slow enough to run this
            // loop inside the handshake.
            //
            // `may_recv` is the precise question — "can this connection deliver
            // bytes to me" — and it is what the first thing to touch the socket
            // is going to ask anyway.
            let mut handshaking = false;
            loop {
                if shutdown.requested() {
                    stack.tcp_release(listener);
                    return;
                }
                if stack.tcp_may_recv(listener) || stack.tcp_can_recv(listener) {
                    break;
                }
                // A handshake that started and then died — a `RST`, or a peer
                // that vanished — leaves a socket that is neither listening nor
                // ever going to be established. Reclaim it and listen again,
                // rather than waiting on it for the life of the daemon.
                let active = stack.tcp_is_active(listener);
                if handshaking && !active {
                    stack.tcp_release(listener);
                    break;
                }
                handshaking |= active;
                std::thread::sleep(crate::pump::IDLE_POLL);
            }
            if !stack.tcp_may_recv(listener) && !stack.tcp_can_recv(listener) {
                // The abandoned-handshake path above. Nothing to forward.
                continue;
            }

            let from = stack.tcp_remote(listener);
            in_flight.fetch_add(1, Ordering::Relaxed);
            let stack = stack.clone();
            connections.spawn(move || {
                if let Err(e) = forward(&stack, listener, to, shutdown) {
                    let from = from.map_or_else(|| "an overlay peer".to_owned(), |a| a.to_string());
                    eprintln!("karstd: overlay port {port} from {from}: {e}");
                }
                in_flight.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
}

/// Dial the local backend and join the two ends together.
fn forward(
    stack: &Userspace,
    tunnel: karst_tun::TcpHandle,
    to: SocketAddr,
    shutdown: &Shutdown,
) -> io::Result<()> {
    let backend = match TcpStream::connect_timeout(&to, BACKEND_TIMEOUT) {
        Ok(stream) => stream,
        Err(e) => {
            // **Reset rather than dropped.** The peer asked for a service that
            // is not answering; a reset says so now, where silence would leave
            // it retransmitting into a socket this daemon is about to reclaim.
            stack.tcp_abort(tunnel);
            return Err(io::Error::new(
                e.kind(),
                format!("the published backend {to} refused the connection: {e}"),
            ));
        }
    };
    crate::pump::pump(backend, stack, tunnel, shutdown)
}
