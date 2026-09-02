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
//!
//! # Platforms
//!
//! `sendmmsg`, `recvmmsg` and UDP GSO are Linux interfaces with no portable
//! equivalent. The batched *API* is portable anyway: [`portable`] implements
//! the same two calls as a loop over `sendto`/`recvfrom`, so a caller writes
//! one datapath and gets the syscall amortisation where the kernel offers it.
//! Only [`UdpTransport::send_segmented`] and [`RouterSocket`] remain
//! Linux-only, because neither has a meaningful unaccelerated form — a
//! caller must fall back to `send_batch` for the first, and the second is
//! PREF64 discovery, which its caller already treats as best-effort.

mod nat64;
#[cfg(not(target_os = "linux"))]
mod portable;
#[cfg(target_os = "linux")]
mod sys;

pub use nat64::{Nat64Prefix, PrefixError, WKA, WKA2};
#[cfg(target_os = "linux")]
pub use sys::RouterSocket;

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
// Only the `sendmmsg`/`recvmmsg` paths need a raw descriptor; the portable
// ones take the socket itself.
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Datagrams per batched call.
///
/// 32 is enough to amortise a `sendmmsg` almost completely — the marginal gain
/// past it is small, and every slot costs a `sockaddr_storage` (128 B) plus an
/// `mmsghdr` in a per-thread buffer that is allocated once.
///
/// Declared here rather than in `sys`, because it is part of the API a caller
/// sizes its buffers against and not a detail of the syscall: the portable
/// path honors the same bound so that a caller's buffers are correct on
/// either platform.
pub const BATCH: usize = 32;

/// One datagram from a batched receive.
#[derive(Debug, Clone, Copy)]
pub struct Received {
    /// Payload length.
    pub len: usize,
    /// Source address.
    pub from: SocketAddr,
}

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

/// Put a received source address into the one form the rest of Karst uses.
///
/// **A dual-stack socket does not report both families the same way.**
/// `node.listen` decides the datapath's address family — §4 gives it one shared
/// socket — and an `AF_INET` socket cannot send to an IPv6 address at all, so
/// `[::]` is the only configuration that can use an IPv6 path. On that socket
/// an IPv4 peer's datagrams arrive from `[::ffff:a.b.c.d]`, and Rust's
/// `SocketAddr` does not know that is the same place as `a.b.c.d`:
/// `SocketAddr::V4(x) == SocketAddr::V6(mapped)` is false, always.
///
/// Everything above this layer compares addresses for equality — the engine
/// attributes a datagram to a peer that way, AVEN hands the source straight
/// back as `Pong.observed`, and `karst status` prints it. Normalizing here
/// rather than at each of those means there is one representation of an
/// address in the daemon, and it is the one every other node can reach: a
/// v4-mapped address advertised as a candidate is one that no IPv4-only peer
/// can send to (GitHub issue [#50](https://github.com/karst-net/karst/issues/50)).
///
/// [`source_key`] maps the other way, and deliberately: a *reassembly* key
/// wants both families in one width, and it is not an address anything sends
/// to.
#[must_use]
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // `to_ipv4_mapped`, not `to_ipv4`: the latter also unwraps the
            // deprecated IPv4-compatible form (`::a.b.c.d`), which is a
            // different and long-obsolete encoding that no socket produces.
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

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
    /// The NAT64 prefix this host reaches IPv4 through, if it is on such a
    /// network. See [`Self::bind_via_nat64`].
    nat64: Option<Nat64Prefix>,
    /// Whether this socket is `AF_INET`, and so cannot carry IPv6 at all.
    ipv4_only: bool,
    /// How many datagrams this socket has refused because their destination is
    /// in a family it cannot reach. See [`Self::unreachable_family`].
    unreachable: AtomicU64,
}

impl UdpTransport {
    /// Bind to an address.
    ///
    /// # Errors
    /// Any `bind` failure.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        Self::bind_via_nat64(addr, None)
    }

    /// Bind on a network that reaches IPv4 only through a NAT64 translator.
    ///
    /// Every IPv4 destination is sent to `prefix::v4` instead, and every source
    /// within the prefix is reported as the IPv4 address it stands for. The
    /// rest of Karst therefore goes on holding, comparing and advertising plain
    /// IPv4 addresses on a host that cannot send an IPv4 packet — which is the
    /// only arrangement that works, because a synthesised address means nothing
    /// outside this network and a node that advertised one would be telling
    /// every peer to reach it somewhere that does not exist.
    ///
    /// **The prefix is fixed for the socket's life.** Learning it again would
    /// mean re-reading DNS on a timer for a value that changes when the host
    /// moves networks, which is a restart in this daemon anyway.
    ///
    /// # Errors
    /// Any `bind` failure.
    pub fn bind_via_nat64(addr: SocketAddr, prefix: Option<Nat64Prefix>) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        // Asked of the socket rather than of `addr`, so a bind to a name or to
        // port 0 is described by what the kernel actually gave out.
        let ipv4_only = socket.local_addr().map_or(addr.is_ipv4(), |a| a.is_ipv4());
        Ok(Self {
            socket,
            nat64: prefix,
            ipv4_only,
            unreachable: AtomicU64::new(0),
        })
    }

    /// Whether this socket is `AF_INET`, and so can never send to an IPv6
    /// address.
    #[must_use]
    pub const fn is_ipv4_only(&self) -> bool {
        self.ipv4_only
    }

    /// How many datagrams have been refused for having a destination in a
    /// family this socket cannot reach.
    ///
    /// **Nonzero means a peer is unreachable and nothing else will say so.**
    /// `node.listen` decides the datapath's address family, because §4 gives it
    /// one shared socket; an `AF_INET` socket cannot send to an IPv6 address at
    /// all. Every send path drops errors on purpose — a full buffer or an
    /// unreachable host must not take the daemon down, and the protocol
    /// retransmits — so a peer that advertises only IPv6 candidates produces an
    /// unbroken silence. This is the counter that turns that silence into a
    /// number an operator can read.
    #[must_use]
    pub fn unreachable_family(&self) -> u64 {
        self.unreachable.load(Ordering::Relaxed)
    }

    /// Whether this socket could send to `peer` at all, ignoring reachability.
    ///
    /// A question about address families, not about routes: `true` here does
    /// not promise the datagram arrives.
    #[must_use]
    fn family_reachable(&self, peer: SocketAddr) -> bool {
        !(self.ipv4_only && peer.is_ipv6())
    }

    /// Refuse a datagram whose destination this socket cannot address.
    fn refuse(&self, peer: SocketAddr) -> io::Error {
        let n = self.unreachable.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
            // Once per process. A peer that keeps advertising an IPv6 candidate
            // would otherwise write the log at the probe rate, and the fact
            // does not change: it is a property of this node's configuration.
            eprintln!(
                "karstd: cannot send to {peer} — node.listen is an IPv4 address, \
                 so the datapath socket is AF_INET and no IPv6 peer or candidate \
                 is reachable from it. Set node.listen to \"[::]\" to use both \
                 families. This is reported once; `karst status` counts the rest."
            );
        }
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{peer} is IPv6 and this datapath socket is AF_INET"),
        )
    }

    /// Where this socket must actually send, to reach `peer`.
    ///
    /// The identity on any host that is not behind NAT64, which is why every
    /// send path can call it unconditionally.
    fn route(&self, peer: SocketAddr) -> SocketAddr {
        match self.nat64 {
            Some(prefix) => prefix.synthesise_socket(peer),
            None => peer,
        }
    }

    /// What the rest of Karst should call the sender of a datagram.
    fn attribute(&self, from: SocketAddr) -> SocketAddr {
        match self.nat64 {
            Some(prefix) => prefix.extract_socket(from),
            None => from,
        }
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
    /// For sockets that are polled opportunistically rather than waited on,
    /// where a blocking read would stall whatever is driving the poll.
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
        let to = self.route(peer);
        if !self.family_reachable(to) {
            return Err(self.refuse(to));
        }
        self.socket.send_to(datagram, to)
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
        let (n, from) = self.socket.recv_from(buf)?;
        Ok((n, self.attribute(canonical(from))))
    }

    /// Send several datagrams, in **one syscall** where the platform has one.
    ///
    /// That is `sendmmsg(2)` on Linux and a loop over `sendto` elsewhere; see
    /// [`portable`] for what the difference costs and why the API does not
    /// expose it. Both honor the same [`BATCH`] bound, so a caller sizes its
    /// buffers once.
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
    /// any send failure.
    pub fn send_batch(&self, datagrams: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        for (d, _) in datagrams {
            if d.len() > MAX_DATAGRAM {
                return Err(oversized(d.len()));
            }
        }
        // **The common path allocates nothing.** A host that is not behind
        // NAT64 hands the slice straight through; only one that is pays for a
        // rewritten copy, and it is the batch's own size.
        let Some(prefix) = self.nat64 else {
            return self.send_batch_raw(datagrams);
        };
        let routed: Vec<(&[u8], SocketAddr)> = datagrams
            .iter()
            .map(|(d, peer)| (*d, prefix.synthesise_socket(*peer)))
            .collect();
        self.send_batch_raw(&routed)
    }

    #[cfg(target_os = "linux")]
    fn send_batch_raw(&self, datagrams: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        sys::send_batch(self.socket.as_fd(), datagrams)
    }

    #[cfg(not(target_os = "linux"))]
    fn send_batch_raw(&self, datagrams: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
        portable::send_batch(&self.socket, datagrams)
    }

    /// Receive several datagrams, in **one syscall** where the platform has
    /// one — `recvmmsg(2)` on Linux, one `recvfrom` elsewhere.
    ///
    /// `buffers` is reused across calls and never reallocated; `out` is filled
    /// with one entry per datagram, in arrival order. A caller must iterate
    /// over what it is given rather than assume a count: the portable path
    /// yields one at a time.
    ///
    /// # Errors
    /// Any receive failure, including a timeout as `WouldBlock`.
    pub fn recv_batch(
        &self,
        buffers: &mut [[u8; MAX_DATAGRAM]],
        out: &mut Vec<Received>,
    ) -> io::Result<usize> {
        let n = self.recv_batch_raw(buffers, out)?;
        if let Some(prefix) = self.nat64 {
            for received in out.iter_mut() {
                received.from = prefix.extract_socket(received.from);
            }
        }
        Ok(n)
    }

    #[cfg(target_os = "linux")]
    fn recv_batch_raw(
        &self,
        buffers: &mut [[u8; MAX_DATAGRAM]],
        out: &mut Vec<Received>,
    ) -> io::Result<usize> {
        sys::recv_batch(self.socket.as_fd(), buffers, out)
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_batch_raw(
        &self,
        buffers: &mut [[u8; MAX_DATAGRAM]],
        out: &mut Vec<Received>,
    ) -> io::Result<usize> {
        portable::recv_batch(&self.socket, buffers, out)
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
        let to = self.route(to);
        if !self.family_reachable(to) {
            return Err(self.refuse(to));
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

    /// **The kernel's behavior, not a belief about it.**
    ///
    /// Everything `canonical` exists for rests on one claim: that a dual-stack
    /// socket reports an IPv4 peer as `[::ffff:a.b.c.d]`. That is a property of
    /// the operating system, so it is checked against a real socket pair rather
    /// than asserted — and the first assertion here is the claim itself, so a
    /// platform on which it were false would say so rather than leave the
    /// normalization looking like superstition.
    #[test]
    fn a_dual_stack_socket_reports_an_ipv4_peer_at_its_ipv4_address() {
        let Ok(dual) = UdpTransport::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))) else {
            // A host with IPv6 disabled outright. Nothing to say here.
            return;
        };
        dual.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let port = dual.local_addr().unwrap().port();
        let v4 = UdpTransport::bind(loopback()).unwrap();
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        // An `AF_INET` socket sending to a dual-stack one: the ordinary case of
        // an IPv4 node in a mesh whose peer is dual-stack.
        if v4.send_to(b"from-v4", to).is_err() {
            return; // No v4 mapping on this host either.
        }

        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, from) = dual.recv_from(&mut buf).unwrap();
        assert_eq!(buf.get(..n), Some(&b"from-v4"[..]));
        assert_eq!(
            from,
            SocketAddr::from((Ipv4Addr::LOCALHOST, v4.local_addr().unwrap().port())),
            "a dual-stack socket reported an IPv4 peer as {from}, which no \
             IPv4-only node can send to"
        );
        assert!(
            from.is_ipv4(),
            "the source is still an IPv6 address, so it will not compare equal \
             to the IPv4 endpoint a netmap carries"
        );
    }

    /// The batched receive path is a separate syscall and a separate decoder,
    /// so it gets the same requirement rather than inheriting it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_batched_path_canonicalizes_the_same_way() {
        let Ok(dual) = UdpTransport::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))) else {
            return;
        };
        dual.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let port = dual.local_addr().unwrap().port();
        let v4 = UdpTransport::bind(loopback()).unwrap();
        if v4
            .send_to(b"batched", SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .is_err()
        {
            return;
        }

        let mut buffers = vec![[0u8; MAX_DATAGRAM]; 4];
        let mut out = Vec::new();
        let count = dual.recv_batch(&mut buffers, &mut out).unwrap();
        assert_eq!(count, 1);
        let received = out.first().expect("one datagram");
        assert!(
            received.from.is_ipv4(),
            "recvmmsg reported {} — the two receive paths disagree about the \
             same address",
            received.from
        );
    }

    /// A genuine IPv6 peer is left alone: only the mapped form is rewritten.
    #[test]
    fn a_real_ipv6_address_is_not_touched() {
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 4242));
        assert_eq!(canonical(v6), v6);
        let v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 4242));
        assert_eq!(canonical(v4), v4, "an IPv4 address is already canonical");
        // The deprecated IPv4-*compatible* form is not a mapped address and is
        // not produced by any socket; unwrapping it would invent a peer.
        let compat: SocketAddr = "[::192.0.2.1]:4242".parse().unwrap();
        assert_eq!(canonical(compat), compat);
    }

    /// **An `AF_INET` socket refuses an IPv6 destination, loudly.**
    ///
    /// This used to be a silent drop, and the silence was the whole problem.
    /// `node.listen` decides the datapath's address family — §4 gives it one
    /// shared socket — so a node listening on `0.0.0.0` cannot send to an IPv6
    /// candidate at all. Every send path in the daemon drops errors on purpose,
    /// because a full buffer or an unreachable host must not take it down, so
    /// a peer reachable only over IPv6 produced no log line, no counter and no
    /// symptom other than never connecting (GitHub issue [#56](https://github.com/karst-net/karst/issues/56)).
    #[test]
    fn an_ipv4_socket_says_why_it_cannot_send_to_an_ipv6_peer() {
        let v4 = UdpTransport::bind(loopback()).unwrap();
        assert!(v4.is_ipv4_only());
        assert_eq!(v4.unreachable_family(), 0);

        let peer = SocketAddr::from((Ipv6Addr::LOCALHOST, 51820));
        let err = v4.send_to(b"unreachable", peer).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::Unsupported,
            "an IPv6 destination on an AF_INET socket is a configuration \
             mismatch, not a transient send failure: {err}"
        );
        assert!(err.to_string().contains("AF_INET"), "{err}");
        assert_eq!(
            v4.unreachable_family(),
            1,
            "the refusal must be countable, because `karst status` is the only \
             place an operator can see this"
        );
        // Counting, not just flagging: a peer that keeps advertising is worth
        // distinguishing from one that tried once.
        let _ = v4.send_to(b"again", peer);
        assert_eq!(v4.unreachable_family(), 2);

        // And an IPv4 destination on the same socket is untouched.
        assert!(v4.send_to(b"fine", v4.local_addr().unwrap()).is_ok());
        assert_eq!(v4.unreachable_family(), 2);
    }

    /// A dual-stack socket reaches both families, so the question never arises
    /// and the counter must stay at zero rather than fire on every IPv6 peer.
    #[test]
    fn a_dual_stack_socket_refuses_nothing_for_its_family() {
        let Ok(dual) = UdpTransport::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))) else {
            return; // IPv6 disabled outright.
        };
        assert!(!dual.is_ipv4_only());
        let port = dual.local_addr().unwrap().port();
        assert!(dual
            .send_to(b"v6", SocketAddr::from((Ipv6Addr::LOCALHOST, port)))
            .is_ok());
        // A v4 destination goes out v4-mapped on this socket, which is exactly
        // why `is_ipv4_only` asks the socket rather than the destination.
        let _ = dual.send_to(b"v4", SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        assert_eq!(dual.unreachable_family(), 0);
    }

    /// A NAT64 socket sends to `prefix::v4` and reports the sender as IPv4 —
    /// **over a real socket pair**, with no translator in sight.
    ///
    /// The trick is a prefix whose synthesised addresses this host already
    /// routes. `::/96` is one: it embeds `0.0.0.1` as `::1`, so a send
    /// addressed in plain IPv4 genuinely leaves through the prefix and
    /// genuinely arrives on loopback, and the source that comes back is a real
    /// `::1` that only the extraction can turn into `0.0.0.1`.
    ///
    /// **The obvious choice, `::ffff:0:0/96`, does not work and the reason is
    /// worth keeping.** Its synthesised form is the v4-mapped address, which
    /// [`canonical`] already rewrites one line earlier — so the test passes
    /// whether or not NAT64 extraction is wired to the receive path at all.
    /// This version was written first, and removing the extraction did not fail
    /// it. A test that cannot fail is not evidence.
    ///
    /// The whole-aquifer row runs this against a real translator on an IPv6-only
    /// network; what this pins is that both rewrites are wired to the socket,
    /// which is a unit-sized claim and now fails in a unit-sized way.
    #[test]
    fn a_nat64_socket_sends_through_the_prefix_and_reports_plain_ipv4() {
        let prefix: Nat64Prefix = "::/96".parse().unwrap();
        // IPv6 disabled outright: nothing here to say.
        let (Ok(a), Ok(b)) = (
            UdpTransport::bind_via_nat64(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), Some(prefix)),
            UdpTransport::bind_via_nat64(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), Some(prefix)),
        ) else {
            return;
        };
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let their_port = b.local_addr().unwrap().port();
        let our_port = a.local_addr().unwrap().port();

        // Addressed as plain IPv4, exactly as the engine would address a peer
        // out of a netmap. Nothing above the socket knows this host is on IPv6.
        let to = SocketAddr::from((Ipv4Addr::new(0, 0, 0, 1), their_port));
        a.send_to(b"through-the-prefix", to)
            .expect("the send must go through the prefix to reach ::1");

        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(buf.get(..n), Some(&b"through-the-prefix"[..]));
        assert_eq!(
            from,
            SocketAddr::from((Ipv4Addr::new(0, 0, 0, 1), our_port)),
            "the sender came back as {from}; anything but a plain IPv4 address \
             is one the engine cannot match against a netmap and would go on to \
             hand back to peers as the address they were seen at"
        );
    }

    /// The same socket must leave a genuine IPv6 peer alone. A NAT64 network
    /// still has native IPv6, and rewriting a peer that is already reachable
    /// would break the one path that needs no translation.
    #[test]
    fn a_nat64_socket_does_not_touch_a_native_ipv6_peer() {
        let prefix = Nat64Prefix::well_known();
        let Ok(a) =
            UdpTransport::bind_via_nat64(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), Some(prefix))
        else {
            return;
        };
        let Ok(b) =
            UdpTransport::bind_via_nat64(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), Some(prefix))
        else {
            return;
        };
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        a.send_to(b"native", b.local_addr().unwrap()).unwrap();

        let mut buf = [0u8; MAX_DATAGRAM];
        let (_, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(from, a.local_addr().unwrap());
        assert!(from.is_ipv6(), "a native IPv6 peer was rewritten to {from}");
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
