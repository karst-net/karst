// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

// ADR-0003 permits `unsafe` in this crate for the batched-I/O paths. It is
// confined to `sys`, which carries the sole `allow(unsafe_code)` and whose every
// block states its argument.
#![deny(unsafe_code)]
//! UDP transport — the first layer that touches a real socket.
//!
//! Everything below this crate is sans-io (ADR-0003). This is where that ends:
//! `karst-transport` owns the socket and nothing else does.
//!
//! # Batched I/O
//!
//! One datagram per syscall is the simple form and is still available. It is
//! also what limited the datapath: PLAN.md §3.4 measured 63% of the profile in
//! the kernel at ~46,000 packets per second per direction, with no userspace
//! hotspot above 6%. [`UdpTransport::send_batch`] and
//! [`UdpTransport::recv_batch`] amortise the syscall across up to [`BATCH`]
//! datagrams, and [`UdpTransport::send_segmented`] hands the kernel one buffer
//! to split (UDP GSO).
//!
//! **Receive-side GRO is not enabled**, and that is a considered omission
//! rather than an oversight — see the note at the foot of `sys.rs`.

#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use sys::{Received, BATCH};

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::time::Duration;

/// Largest UDP payload Karst will send or receive — `spec/phreatic-v1.md` §13.6.
///
/// This is a **transport** datagram: 1336 bytes, carrying a full 1280-byte
/// tunnel packet. Handshakes are held to the tighter [`MAX_HANDSHAKE_DATAGRAM`]
/// so the §9 denial-of-service analysis is unaffected.
pub const MAX_DATAGRAM: usize = karst_proto::consts::TRANSPORT_DATAGRAM_MAX;

/// Largest UDP payload that fits the IPv6 minimum MTU — §5.
///
/// 1280 (IPv6 minimum MTU) − 40 (IPv6 header) − 8 (UDP header). Every
/// handshake datagram, and every datagram of a fragmented message, fits this.
pub const MAX_HANDSHAKE_DATAGRAM: usize = karst_proto::consts::HANDSHAKE_DATAGRAM_MAX;

/// Opaque per-source identity for the reassembler — 16 bytes of address plus
/// 2 of port. IPv4 is encoded as IPv4-mapped IPv6 so both families share one
/// representation and cannot collide.
pub type SourceKey = [u8; 18];

/// Encode a socket address as a [`SourceKey`].
#[must_use]
pub fn source_key(addr: SocketAddr) -> SourceKey {
    let mut key = [0u8; 18];
    let octets = match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    if let Some(head) = key.get_mut(..16) {
        head.copy_from_slice(&octets);
    }
    if let Some(tail) = key.get_mut(16..18) {
        tail.copy_from_slice(&addr.port().to_be_bytes());
    }
    key
}

/// A bound UDP socket carrying Karst datagrams.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Bind to an address.
    ///
    /// # Errors
    /// Any `bind` failure.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr)?,
        })
    }

    /// The address actually bound, after any ephemeral-port assignment.
    ///
    /// # Errors
    /// Any `getsockname` failure.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Read timeout, so a receive loop cannot block forever.
    ///
    /// # Errors
    /// Any `setsockopt` failure.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)
    }

    /// Put the socket in non-blocking mode.
    ///
    /// For sockets that are polled opportunistically rather than waited on —
    /// `aven-v1.md` §7.7's scratch sockets are polled from a timer tick, and a
    /// blocking read on any one of a few hundred idle sockets would stall the
    /// datapath behind it.
    ///
    /// # Errors
    /// Any `fcntl` failure.
    pub fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.socket.set_nonblocking(on)
    }

    /// Send one datagram.
    ///
    /// Refuses anything over [`MAX_DATAGRAM`]. The fragmentation layer exists
    /// precisely so this cannot happen; an over-sized buffer arriving here is a
    /// caller bug, and letting the kernel IP-fragment it would defeat §5 and
    /// the denial-of-service analysis built on it.
    ///
    /// Note this is the *transport* budget. Whether a given datagram is
    /// entitled to exceed [`MAX_HANDSHAKE_DATAGRAM`] is decided by
    /// `FragmentHeader::decode`'s `count == 1` rule on receipt (§13.6), not
    /// here — this socket does not parse what it carries.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] if oversized; otherwise any `send`
    /// failure.
    pub fn send_to(&self, datagram: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if datagram.len() > MAX_DATAGRAM {
            return Err(oversized(datagram.len()));
        }
        self.socket.send_to(datagram, peer)
    }

    /// Receive one datagram, returning its length and source.
    ///
    /// The buffer should be [`MAX_DATAGRAM`] bytes. A larger datagram is
    /// truncated by the kernel and will then fail its fragment MAC, which is
    /// the correct outcome.
    ///
    /// # Errors
    /// Any `recv` failure, including a timeout as `WouldBlock` or `TimedOut`.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    /// Send several datagrams in **one syscall** — `sendmmsg(2)`.
    ///
    /// Returns how many the kernel accepted. A short count is normal and the
    /// caller must retry the remainder, exactly as with a short write; treating
    /// it as an error would drop packets the protocol then has to recover.
    ///
    /// Over-sized datagrams are refused before any syscall, for the reason
    /// [`Self::send_to`] gives.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] if any datagram is oversized; otherwise
    /// any `sendmmsg` failure.
    #[cfg(target_os = "linux")]
    pub fn send_batch(&self, datagrams: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        for (d, _) in datagrams {
            if d.len() > MAX_DATAGRAM {
                return Err(oversized(d.len()));
            }
        }
        sys::send_batch(self.socket.as_fd(), datagrams)
    }

    /// Receive several datagrams in **one syscall** — `recvmmsg(2)`.
    ///
    /// `buffers` is reused across calls and never reallocated; `out` is filled
    /// with one entry per datagram, in arrival order.
    ///
    /// # Errors
    /// Any `recvmmsg` failure, including a timeout as `WouldBlock`.
    #[cfg(target_os = "linux")]
    pub fn recv_batch(
        &self,
        buffers: &mut [[u8; MAX_DATAGRAM]],
        out: &mut Vec<Received>,
    ) -> io::Result<usize> {
        sys::recv_batch(self.socket.as_fd(), buffers, out)
    }

    /// Send equal-sized datagrams as one segmented write — **UDP GSO**.
    ///
    /// `payload` is the concatenation of datagrams of exactly `segment_size`
    /// bytes each, the last permitted to be shorter. One syscall emits them all.
    ///
    /// Not every path supports segmentation; a caller should fall back to
    /// [`Self::send_batch`] on error rather than treat it as fatal.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] if `segment_size` exceeds
    /// [`MAX_DATAGRAM`]; otherwise any `sendmsg` failure.
    #[cfg(target_os = "linux")]
    pub fn send_segmented(
        &self,
        payload: &[u8],
        segment_size: u16,
        to: SocketAddr,
    ) -> io::Result<usize> {
        if usize::from(segment_size) > MAX_DATAGRAM {
            return Err(oversized(usize::from(segment_size)));
        }
        sys::send_segmented(self.socket.as_fd(), payload, segment_size, to)
    }
}

/// The error every over-sized send returns, so the message is identical
/// whichever path refused it.
fn oversized(len: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "datagram of {len} B exceeds the {MAX_DATAGRAM} B limit — \
             fragment it first (spec §5)"
        ),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    #[test]
    fn datagrams_round_trip_over_a_real_socket() {
        let a = UdpTransport::bind(loopback()).unwrap();
        let b = UdpTransport::bind(loopback()).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let payload = [0xABu8; 512];
        a.send_to(&payload, b.local_addr().unwrap()).unwrap();

        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(buf.get(..n), Some(&payload[..]));
        assert_eq!(from.port(), a.local_addr().unwrap().port());
    }

    #[test]
    fn a_full_size_fragment_fits() {
        let a = UdpTransport::bind(loopback()).unwrap();
        let b = UdpTransport::bind(loopback()).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // 24-byte fragment header + 1208-byte payload = exactly MAX_DATAGRAM.
        let full = [0x5Au8; MAX_DATAGRAM];
        a.send_to(&full, b.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; MAX_DATAGRAM];
        assert_eq!(b.recv_from(&mut buf).unwrap().0, MAX_DATAGRAM);
    }

    /// Over-sized sends are refused here rather than left to the kernel: IP
    /// fragmentation would defeat §5 and the `DoS` analysis built on it.
    #[test]
    fn oversized_datagrams_are_refused_locally() {
        let a = UdpTransport::bind(loopback()).unwrap();
        let b = UdpTransport::bind(loopback()).unwrap();
        let too_big = vec![0u8; MAX_DATAGRAM + 1];
        let err = a.send_to(&too_big, b.local_addr().unwrap()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("fragment it first"));
    }

    #[test]
    fn source_keys_distinguish_address_and_port() {
        let a = source_key(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 51820)));
        let b = source_key(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 51820)));
        let c = source_key(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 51821)));
        assert_ne!(a, b, "address must matter");
        assert_ne!(a, c, "port must matter");
        assert_eq!(
            a,
            source_key(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 51820)))
        );
    }

    /// IPv4 and IPv6 share one key space, so the encoding must keep them apart.
    #[test]
    fn ipv4_and_ipv6_keys_do_not_collide() {
        let v4 = source_key(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 1234)));
        let v6 = source_key(SocketAddr::from((Ipv6Addr::LOCALHOST, 1234)));
        assert_ne!(v4, v6);
        // The IPv4-mapped prefix is what makes the two families comparable.
        assert_eq!(v4.get(10..12), Some(&[0xFF, 0xFF][..]));
    }

    #[test]
    fn a_read_timeout_returns_rather_than_hanging() {
        let s = UdpTransport::bind(loopback()).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; MAX_DATAGRAM];
        let err = s.recv_from(&mut buf).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "unexpected kind: {:?}",
            err.kind()
        );
    }
}
