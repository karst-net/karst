// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The bidirectional copy that both userspace attachments are made of.
//!
//! Outbound ([`crate::socks5`]) and inbound ([`crate::publish`]) differ only in
//! who dials whom. Once there is a host socket at one end and an overlay socket
//! at the other, the work is identical — and it is not trivial work: the
//! half-close rule below is FINDINGS.md 39, and the poll schedule is the
//! difference between 1.1 Mbps and 516 Mbps measured in
//! `docs/measurements/userspace-cost-2026-08-21.md`.
//!
//! One implementation rather than two, so the second direction cannot be
//! written with the first one's bugs put back.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use karst_tun::{TcpHandle, Userspace};

use crate::run::Shutdown;

/// Most bytes buffered from the host socket while the tunnel is not draining.
///
/// One `SendPacket` is bounded by the datapath MTU; this is a few round trips'
/// worth, which is enough that an ordinary burst never stalls and small enough
/// that a fast writer cannot spend the daemon's memory.
pub(crate) const MAX_BUFFERED: usize = 256 * 1024;

/// One read from the host socket.
///
/// 4 KiB was three tunnel MTUs, which made this loop's own read the smallest
/// quantum in the path. Matched to [`MAX_BUFFERED`]'s order instead, so a
/// bulk-sending workload is limited by the tunnel rather than by this loop.
const READ_CHUNK: usize = 64 * 1024;

/// How long to wait before looking again when a pass moved no bytes at all.
///
/// **Two rates, because the two cases want opposite things.** A connection in
/// the middle of a request/response exchange is idle in exactly the interval
/// that matters — between the request going out and the reply arriving — so a
/// long sleep there is added directly to every round trip. A connection that
/// has been quiet for a while is a resource to be cheap about instead.
///
/// The measurement that settled the numbers, from `scripts/userspace-cost.sh`:
/// at a flat 2 ms the round trip was **4.1 ms**, two quanta of it, with no
/// spread across percentiles; at a flat 200 µs it was **0.545 ms** against a
/// privileged baseline of 0.161 ms. The window keeps the second figure for an
/// active connection and the first figure's idle cost for a quiet one.
pub(crate) const ACTIVE_POLL: Duration = Duration::from_micros(200);
pub(crate) const IDLE_POLL: Duration = Duration::from_millis(2);
/// How long after its last byte a connection is still treated as active.
const ACTIVE_WINDOW: Duration = Duration::from_millis(50);

/// Copy in both directions until both are finished, then give the socket back.
///
/// `tunnel` is consumed in the sense that matters: this function releases it on
/// every exit path, and the caller must not use it afterwards.
pub(crate) fn pump(
    mut local: TcpStream,
    stack: &Userspace,
    tunnel: TcpHandle,
    shutdown: &Shutdown,
) -> io::Result<()> {
    let result = copy(&mut local, stack, tunnel, shutdown);
    // **The only place a proxied socket is reclaimed.** `copy` returns early on
    // any host-socket error, and an earlier version of this code — which lived
    // inline in `socks5` — simply returned, leaving a socket and its 128 KiB of
    // buffers in the stack for the life of the daemon (FINDINGS.md 44).
    stack.tcp_release(tunnel);
    result
}

fn copy(
    local: &mut TcpStream,
    stack: &Userspace,
    tunnel: TcpHandle,
    shutdown: &Shutdown,
) -> io::Result<()> {
    local.set_nonblocking(true)?;

    let mut outgoing = Vec::new();
    let mut buf = vec![0u8; READ_CHUNK];
    // **Each direction ends on its own.** TCP is two independent half-duplex
    // streams, and "send the request, close the write half, read the reply" is
    // an ordinary client, not an exotic one — it is what `curl` does, what
    // `nc -N` does, and what any request/response protocol that ends a message
    // by closing does. An earlier version returned from this function the
    // moment the local read hit EOF, which tore down both halves at once and
    // lost every reply that had not already arrived.
    let mut local_done = false;
    let mut sent_fin = false;
    let mut told_local = false;
    let mut last_moved = std::time::Instant::now();
    while !shutdown.requested() {
        // **Sleep only when a pass moved nothing.** This loop is the whole
        // datapath for an attached workload, and an unconditional sleep put a
        // hard ceiling on it: one `READ_CHUNK` per tick, and a round trip
        // costing at least two ticks. Measured at 2 ms that was 1.1 Mbps and a
        // 4.1 ms RTT whose distribution was flat across every percentile —
        // FINDINGS.md 40, and the shape of a number that is a timer rather than
        // a cost. What remains is `ACTIVE_POLL`, and only on a pass that found
        // nothing to do.
        let mut moved = false;
        if stack.tcp_can_recv(tunnel) {
            let mut received = Vec::new();
            stack
                .tcp_recv(tunnel, &mut received)
                .map_err(|e| io::Error::other(e.to_string()))?;
            if !received.is_empty() {
                local.write_all(&received)?;
                moved = true;
            }
        }
        if !local_done {
            match if outgoing.len() >= MAX_BUFFERED {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                local.read(&mut buf)
            } {
                // This end will send no more. Its *reply* may still be on the
                // way, so this closes one direction and keeps relaying the
                // other.
                Ok(0) => local_done = true,
                // Read only while there is room. Without this a writer faster
                // than the tunnel drains grows this buffer without limit — the
                // peer then chooses how much of the daemon's memory to consume.
                Ok(n) => {
                    outgoing.extend_from_slice(buf.get(..n).unwrap_or_default());
                    moved = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if !outgoing.is_empty() && stack.tcp_can_send(tunnel) {
            let sent = stack
                .tcp_send(tunnel, &outgoing)
                .map_err(|e| io::Error::other(e.to_string()))?;
            outgoing.drain(..sent);
            moved |= sent > 0;
        }
        // The FIN goes out only once everything read locally has been handed to
        // the stack; closing with bytes still buffered here would truncate the
        // request that the reply is an answer to.
        if local_done && outgoing.is_empty() && !sent_fin {
            stack.tcp_close(tunnel);
            sent_fin = true;
        }

        // `tcp_may_recv` is false only when nothing further can ever arrive —
        // buffered bytes keep it true, so the drain above cannot be cut short.
        if !stack.tcp_may_recv(tunnel) && !stack.tcp_can_recv(tunnel) {
            if !told_local {
                // The workload learns the overlay end is finished the same way
                // it would from any other socket.
                let _ = local.shutdown(std::net::Shutdown::Write);
                told_local = true;
            }
            if local_done {
                stack.tcp_close(tunnel);
                return Ok(());
            }
        }
        if moved {
            last_moved = std::time::Instant::now();
        } else if last_moved.elapsed() < ACTIVE_WINDOW {
            std::thread::sleep(ACTIVE_POLL);
        } else {
            std::thread::sleep(IDLE_POLL);
        }
    }
    stack.tcp_close(tunnel);
    Ok(())
}
