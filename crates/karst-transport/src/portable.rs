// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The batched paths on a platform without `sendmmsg` and `recvmmsg`.
//!
//! Safe Rust throughout — this module exists precisely because it needs no
//! syscall that `std` does not already wrap, and the crate-level
//! `deny(unsafe_code)` holds here without an exception. It takes the
//! `UdpSocket` itself rather than a descriptor for the same reason: there is
//! nothing here that a raw fd would buy.
//!
//! # What this is and is not
//!
//! It is **not** an optimisation. Every datagram costs a syscall, exactly as
//! [`crate::UdpTransport::send_to`] does; what it buys is that `karstd` has
//! one datapath rather than two. The alternative — `#[cfg]` at the call site
//! in the daemon's receive loop — would mean the *unbatched* path was the one
//! macOS ran while the batched one was the only one anybody profiled or
//! tested, which is how two implementations quietly diverge.
//!
//! macOS does have `sendmsg_x`/`recvmsg_x`, which are the same idea. They are
//! not in `libc`, are not covered by Apple's stability guarantees, and are
//! worth reaching for only once there is a macOS profile saying the syscall
//! rate is the bottleneck. PLAN.md §3.4 measured that on Linux; nobody has
//! measured it here, and writing `unsafe` against an undocumented interface on
//! the strength of an assumption is the wrong order to do this in.
//!
//! # Receive semantics
//!
//! `recv_batch` returns **at most one** datagram per call. It cannot do better
//! without either putting the socket into non-blocking mode — which would
//! change the blocking contract the caller relies on for its shutdown timeout
//! — or waiting for a second datagram that may never come, which would add
//! latency to every packet in exchange for throughput nobody has asked for.
//! One datagram per call is what the unbatched path already does, and the
//! caller's loop is written to iterate over however many it is given.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use crate::{Received, BATCH};

/// Send several datagrams, one syscall each.
///
/// Returns how many were accepted. A short count is normal and the caller must
/// retry the remainder, exactly as on the batched path — treating it as an
/// error would drop packets the protocol then has to recover.
///
/// An error is reported only if the *first* datagram failed. Once some have
/// gone out, the count is the honest answer, and whatever stopped the rest
/// will be seen again on the retry.
pub(crate) fn send_batch(
    socket: &UdpSocket,
    datagrams: &[(&[u8], SocketAddr)],
) -> io::Result<usize> {
    let mut sent = 0usize;
    for (payload, to) in datagrams.iter().take(BATCH) {
        match socket.send_to(payload, to) {
            Ok(_) => sent = sent.saturating_add(1),
            Err(e) if sent == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(sent)
}

/// Receive datagrams into `buffers`, filling `out` with one entry each.
///
/// At most one per call; see the module documentation for why.
pub(crate) fn recv_batch(
    socket: &UdpSocket,
    buffers: &mut [[u8; super::MAX_DATAGRAM]],
    out: &mut Vec<Received>,
) -> io::Result<usize> {
    out.clear();
    let Some(buf) = buffers.first_mut() else {
        return Ok(0);
    };
    let (len, from) = socket.recv_from(buf)?;
    out.push(Received { len, from });
    Ok(out.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    /// The property the daemon depends on: what `send_batch` accepts,
    /// `recv_batch` delivers, with the same lengths and the right source.
    #[test]
    fn a_batch_round_trips() {
        let a = UdpSocket::bind(loopback()).unwrap();
        let b = UdpSocket::bind(loopback()).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let to = b.local_addr().unwrap();

        let first = [0xAAu8; 64];
        let second = [0xBBu8; 128];
        assert_eq!(
            send_batch(&a, &[(&first[..], to), (&second[..], to)]).unwrap(),
            2
        );

        let mut buffers = vec![[0u8; crate::MAX_DATAGRAM]; BATCH];
        let mut out = Vec::new();
        let mut lengths = Vec::new();
        for _ in 0..2 {
            recv_batch(&b, &mut buffers, &mut out).unwrap();
            let received = *out.first().expect("one datagram per call");
            assert_eq!(received.from.port(), a.local_addr().unwrap().port());
            lengths.push(received.len);
        }
        assert_eq!(lengths, vec![64, 128]);
    }

    #[test]
    fn an_empty_batch_sends_nothing_and_succeeds() {
        let a = UdpSocket::bind(loopback()).unwrap();
        assert_eq!(send_batch(&a, &[]).unwrap(), 0);
    }

    /// `BATCH` bounds the send, as it does on the syscall path — a caller that
    /// hands over more must see a short count and retry, not have the excess
    /// silently dropped.
    #[test]
    fn no_more_than_a_batch_goes_out_at_once() {
        let a = UdpSocket::bind(loopback()).unwrap();
        let b = UdpSocket::bind(loopback()).unwrap();
        let to = b.local_addr().unwrap();
        let payload = [0u8; 8];
        let datagrams: Vec<(&[u8], SocketAddr)> =
            std::iter::repeat_n((&payload[..], to), BATCH + 5).collect();
        assert_eq!(send_batch(&a, &datagrams).unwrap(), BATCH);
    }

    /// `out` is reused across calls by the daemon's receive loop. A stale entry
    /// left in it would be re-processed as though it had just arrived — the
    /// same datagram decrypted twice, which the replay window would then have
    /// to catch.
    #[test]
    fn a_reused_output_vector_carries_nothing_forward() {
        let a = UdpSocket::bind(loopback()).unwrap();
        let b = UdpSocket::bind(loopback()).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let to = b.local_addr().unwrap();

        let mut buffers = vec![[0u8; crate::MAX_DATAGRAM]; BATCH];
        let mut out = Vec::new();
        for len in [16usize, 32] {
            send_batch(&a, &[(&vec![0u8; len][..], to)]).unwrap();
            recv_batch(&b, &mut buffers, &mut out).unwrap();
            assert_eq!(out.len(), 1, "one call, one datagram");
            assert_eq!(out.first().unwrap().len, len);
        }
    }
}
