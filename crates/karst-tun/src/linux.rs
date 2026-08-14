// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The Linux TUN interface.
//!
//! Safe throughout — every syscall goes through [`crate::sys`], which is the
//! only module permitted `unsafe`.

use std::fs::{File, OpenOptions};
use std::io::{IoSlice, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use crate::sys;
use crate::vnet::{self, VnetHdr, VNET_HDR_LEN};
use crate::{decode_name, encode_name, validate_mtu, TunConfig, TunError};

/// Cap on segments produced by one coalesced read.
///
/// A bound rather than a guess: it is what stops a malformed or hostile
/// `gso_size` turning one read into an unbounded allocation. 64 KB of payload
/// at the smallest sane segment size stays well inside it.
const MAX_SEGMENTS: usize = 128;

const DEV_NET_TUN: &str = "/dev/net/tun";

/// An open TUN interface.
///
/// Dropping this closes the descriptor, and the kernel removes the interface —
/// TUN devices created this way are not persistent unless `TUNSETPERSIST` is
/// used, which Karst deliberately does not do: a crashed daemon should not
/// leave a dead interface routing traffic into a black hole.
#[derive(Debug)]
pub struct Tun {
    dev: File,
    name: String,
    mtu: usize,
    /// Whether reads and writes carry a `virtio_net_hdr`, and so whether the
    /// kernel may hand over coalesced segments.
    offload: bool,
    /// Netlink sequence numbers for route requests.
    ///
    /// Atomic because routes are added from the control thread while the
    /// datapath threads hold `&self`, and a reply must be matched to the
    /// request that caused it rather than assumed to be the right one.
    route_seq: std::sync::atomic::AtomicU32,
}

impl Tun {
    /// Create and configure a TUN interface.
    ///
    /// The interface is created, its MTU set, and it is brought up. Addresses
    /// are assigned separately — see [`Tun::set_ipv4`] and [`Tun::set_ipv6`] —
    /// because the control plane supplies them later than interface creation.
    ///
    /// # Errors
    /// [`TunError::InvalidName`] or [`TunError::InvalidMtu`] for a
    /// configuration that cannot work; [`TunError::OpenDevice`] if
    /// `/dev/net/tun` is unavailable; [`TunError::Ioctl`] if a step is refused,
    /// which without `CAP_NET_ADMIN` means `TUNSETIFF` failing with `EPERM`.
    pub fn create(cfg: &TunConfig) -> Result<Self, TunError> {
        let requested = encode_name(&cfg.name)?;
        validate_mtu(cfg.mtu)?;

        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        if cfg.nonblocking {
            opts.custom_flags(libc::O_NONBLOCK);
        }
        let dev = opts.open(DEV_NET_TUN).map_err(TunError::OpenDevice)?;

        // IFF_NO_PI: no 4-byte packet-information prefix, so one read is
        // exactly one IP packet with nothing to strip.
        //
        // IFF_VNET_HDR additionally prefixes a `virtio_net_hdr`, which is what
        // lets the kernel coalesce. It is requested first and retried without
        // on failure: an old kernel, or a container without the capability,
        // must still get a working interface rather than none.
        let mut offload = cfg.offload;
        let base = sys::IFF_TUN | sys::IFF_NO_PI;
        let with_vnet =
            offload.then(|| sys::set_iff(dev.as_fd(), requested, base | sys::IFF_VNET_HDR));
        let assigned = if let Some(Ok(name)) = with_vnet {
            name
        } else {
            // Either offload was not asked for, or the kernel refused the flag.
            // Fall back to a plain device rather than to no device at all.
            offload = false;
            sys::set_iff(dev.as_fd(), requested, base).map_err(|source| TunError::Ioctl {
                op: "TUNSETIFF",
                source,
            })?
        };
        let name = decode_name(&assigned);

        if offload {
            // Both of these are best-effort. If either is refused the device
            // still works — it simply returns one packet per read — so the flag
            // is lowered rather than the interface abandoned.
            let sized =
                sys::set_vnet_hdr_size(dev.as_fd(), i32::try_from(VNET_HDR_LEN).unwrap_or(10))
                    .is_ok();
            let enabled = sys::set_offload(
                dev.as_fd(),
                sys::TUN_F_CSUM | sys::TUN_F_TSO4 | sys::TUN_F_TSO6,
            )
            .is_ok();
            offload = sized && enabled;
        }

        let sock = sys::control_socket().map_err(|source| TunError::Ioctl {
            op: "socket(AF_INET)",
            source,
        })?;

        let mtu = i32::try_from(cfg.mtu).map_err(|_| TunError::InvalidMtu {
            requested: cfg.mtu,
            required: karst_proto::consts::TUNNEL_MTU,
        })?;
        sys::set_mtu(sock.as_fd(), assigned, mtu).map_err(|source| TunError::Ioctl {
            op: "SIOCSIFMTU",
            source,
        })?;
        sys::set_up(sock.as_fd(), assigned).map_err(|source| TunError::Ioctl {
            op: "SIOCSIFFLAGS",
            source,
        })?;

        Ok(Self {
            dev,
            name,
            mtu: cfg.mtu,
            offload,
            // 1 rather than 0: netlink treats sequence 0 as unsolicited, which
            // would make an ack indistinguishable from a broadcast.
            route_seq: std::sync::atomic::AtomicU32::new(1),
        })
    }

    /// Whether segmentation offload is active on this device.
    #[must_use]
    pub fn offload(&self) -> bool {
        self.offload
    }

    /// The interface name the kernel assigned.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// The raw descriptor, for registering with an event loop.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.dev.as_raw_fd()
    }

    /// Assign an IPv4 address with a prefix length.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if the assignment is refused.
    pub fn set_ipv4(&self, addr: Ipv4Addr, prefix_len: u8) -> Result<(), TunError> {
        let mask = Ipv4Addr::from(
            u32::MAX
                .checked_shl(32 - u32::from(prefix_len))
                .unwrap_or(0),
        );
        let sock = sys::control_socket().map_err(|source| TunError::Ioctl {
            op: "socket(AF_INET)",
            source,
        })?;
        sys::set_ipv4(sock.as_fd(), self.encoded_name()?, addr, mask).map_err(|source| {
            TunError::Ioctl {
                op: "SIOCSIFADDR",
                source,
            }
        })
    }

    /// Assign an IPv6 address with a prefix length.
    ///
    /// # Errors
    /// [`TunError::Ioctl`] if the assignment is refused.
    pub fn set_ipv6(&self, addr: Ipv6Addr, prefix_len: u8) -> Result<(), TunError> {
        let sock4 = sys::control_socket().map_err(|source| TunError::Ioctl {
            op: "socket(AF_INET)",
            source,
        })?;
        let sock6 = sys::control_socket_v6().map_err(|source| TunError::Ioctl {
            op: "socket(AF_INET6)",
            source,
        })?;
        sys::set_ipv6(
            sock6.as_fd(),
            sock4.as_fd(),
            self.encoded_name()?,
            addr,
            u32::from(prefix_len),
        )
        .map_err(|source| TunError::Ioctl {
            op: "SIOCSIFADDR (IPv6)",
            source,
        })
    }

    /// Assign either family.
    ///
    /// # Errors
    /// As [`Tun::set_ipv4`] and [`Tun::set_ipv6`].
    pub fn set_address(&self, addr: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        match addr {
            IpAddr::V4(a) => self.set_ipv4(a, prefix_len),
            IpAddr::V6(a) => self.set_ipv6(a, prefix_len),
        }
    }

    /// Route `dst/prefix_len` over this interface.
    ///
    /// # Why this is needed at all
    ///
    /// Assigning an address gives the kernel a connected route for that address
    /// and its on-link prefix, and nothing else. A peer inside the prefix is
    /// therefore reachable for free — but a peer outside it is not, and a subnet
    /// router advertising, say, `192.168.1.0/24` is exactly that case. Without
    /// a route the kernel never hands those packets to the tunnel: they go to
    /// the default gateway instead, which is worse than dropping them.
    ///
    /// The route is **on-link** — scope `RT_SCOPE_LINK`, no gateway. A tunnel
    /// peer is not behind a next hop; it is the far end of the interface.
    ///
    /// Adding a route that already exists succeeds rather than failing, so a
    /// daemon restart does not come up missing routes it left behind.
    ///
    /// # Errors
    /// [`TunError::Netlink`] if the kernel refuses the request. `EPERM` means
    /// the process lacks `CAP_NET_ADMIN`.
    pub fn add_route(&self, dst: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        self.route(sys::RouteOp::Add, dst, prefix_len, "RTM_NEWROUTE")
    }

    /// Stop routing `dst/prefix_len` over this interface.
    ///
    /// Used when a peer leaves the netmap. Leaving the route behind would send
    /// that peer's traffic into a tunnel that no longer has anywhere to put it
    /// — a black hole rather than the "no route to host" the host stack would
    /// otherwise report.
    ///
    /// # Errors
    /// [`TunError::Netlink`] if the kernel refuses. A route that is already
    /// absent is **not** an error: the desired state is what matters, and
    /// something else having removed it first is not a failure.
    pub fn remove_route(&self, dst: IpAddr, prefix_len: u8) -> Result<(), TunError> {
        match self.route(sys::RouteOp::Delete, dst, prefix_len, "RTM_DELROUTE") {
            Err(TunError::Netlink { source, .. }) if sys::is_absent(&source) => Ok(()),
            other => other,
        }
    }

    fn route(
        &self,
        op: sys::RouteOp,
        dst: IpAddr,
        prefix_len: u8,
        what: &'static str,
    ) -> Result<(), TunError> {
        let max = if dst.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(TunError::Netlink {
                op: what,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("prefix length /{prefix_len} exceeds /{max} for this family"),
                ),
            });
        }

        let ctl = sys::control_socket().map_err(|source| TunError::Ioctl {
            op: "socket(AF_INET)",
            source,
        })?;
        let index = sys::interface_index(ctl.as_fd(), self.encoded_name()?).map_err(|source| {
            TunError::Ioctl {
                op: "SIOCGIFINDEX",
                source,
            }
        })?;

        let nl = sys::netlink_socket().map_err(|source| TunError::Netlink {
            op: "socket(AF_NETLINK)",
            source,
        })?;
        // A per-request sequence number, so a reply can be matched to the
        // request that caused it rather than assumed to be the right one.
        let seq = self.next_seq();
        sys::route(nl.as_fd(), op, seq, dst, prefix_len, index)
            .map_err(|source| TunError::Netlink { op: what, source })
    }

    /// A fresh netlink sequence number.
    fn next_seq(&self) -> u32 {
        self.route_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Read one outbound IP packet from the host.
    ///
    /// Returns the packet length. `buf` must be at least [`Tun::mtu`] bytes: a
    /// short buffer makes the kernel truncate silently, which would corrupt
    /// traffic with no error anywhere to explain it.
    ///
    /// # Errors
    /// [`TunError::BufferTooSmall`] for an undersized buffer; [`TunError::Io`]
    /// on a read failure, including `WouldBlock` on a non-blocking device.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        if buf.len() < self.mtu {
            return Err(TunError::BufferTooSmall {
                len: buf.len(),
                mtu: self.mtu,
            });
        }
        // `&self`, not `&mut self`: a character device handles concurrent reads
        // and writes, and each syscall carries exactly one packet, so there is
        // no interleaving to protect against. A `&mut self` here would force a
        // daemon to hold a lock across a *blocking* read — which would stall
        // every inbound packet waiting to be written for as long as the host
        // sent nothing.
        if !self.offload {
            return (&self.dev).read(buf).map_err(TunError::Io);
        }
        // With offload the device prefixes a header even for a single packet,
        // so it has to be read and stripped.
        let n = (&self.dev).read(buf).map_err(TunError::Io)?;
        let hdr = VnetHdr::parse(buf.get(..n).unwrap_or_default())
            .ok_or(TunError::Io(std::io::Error::other("short virtio_net_hdr")))?;
        if hdr.is_segmented() {
            // A caller using the single-packet API cannot receive a coalesced
            // buffer; saying so is better than silently handing back something
            // that is not a packet.
            return Err(TunError::Io(std::io::Error::other(
                "coalesced segment on the single-packet path; use recv_segments",
            )));
        }
        buf.copy_within(VNET_HDR_LEN..n, 0);
        Ok(n.saturating_sub(VNET_HDR_LEN))
    }

    /// Read from the device, splitting a coalesced segment if there is one.
    ///
    /// `out` receives one entry per wire-legal packet — usually one, and many
    /// when the kernel has coalesced a TCP stream. This is the path that makes
    /// offload worth having: one syscall can yield tens of packets.
    ///
    /// # Errors
    /// [`TunError::BufferTooSmall`] if `buf` cannot hold a coalesced read;
    /// [`TunError::Io`] on a read failure or a segment that cannot be split.
    pub fn recv_segments(&self, buf: &mut [u8], out: &mut Vec<Vec<u8>>) -> Result<usize, TunError> {
        out.clear();
        if !self.offload {
            let n = self.recv(buf)?;
            out.push(buf.get(..n).unwrap_or_default().to_vec());
            return Ok(out.len());
        }
        if buf.len() < self.mtu + VNET_HDR_LEN {
            return Err(TunError::BufferTooSmall {
                len: buf.len(),
                mtu: self.mtu + VNET_HDR_LEN,
            });
        }

        let n = (&self.dev).read(buf).map_err(TunError::Io)?;
        let read = buf.get(..n).unwrap_or_default();
        let hdr = VnetHdr::parse(read)
            .ok_or_else(|| TunError::Io(std::io::Error::other("short virtio_net_hdr")))?;
        let packet = read.get(VNET_HDR_LEN..).unwrap_or_default();

        let segments = vnet::split_gso(packet, &hdr, MAX_SEGMENTS)
            .map_err(|e| TunError::Io(std::io::Error::other(format!("{e:?}"))))?;
        *out = segments;
        Ok(out.len())
    }

    /// Write one inbound IP packet to the host.
    ///
    /// Takes `&self` for the reason given on [`Tun::recv`].
    ///
    /// # Errors
    /// [`TunError::PacketTooLarge`] if the packet exceeds the MTU;
    /// [`TunError::Io`] on a write failure.
    pub fn send(&self, packet: &[u8]) -> Result<usize, TunError> {
        if packet.len() > self.mtu {
            return Err(TunError::PacketTooLarge {
                len: packet.len(),
                mtu: self.mtu,
            });
        }
        if !self.offload {
            return (&self.dev).write(packet).map_err(TunError::Io);
        }
        // With offload the device expects a header on every write. An all-zero
        // one means "one packet, no segmentation, checksum already valid",
        // which is exactly what a decrypted tunnel packet is.
        //
        // `write_vectored` rather than building a joined buffer: the kernel
        // gathers the two pieces itself, so this costs no allocation and no
        // copy per packet. It is also plain safe Rust — `IoSlice` is the
        // standard library's own wrapper over `iovec`.
        let header = VnetHdr::default().encode();
        let written = (&self.dev)
            .write_vectored(&[IoSlice::new(&header), IoSlice::new(packet)])
            .map_err(TunError::Io)?;
        Ok(written.saturating_sub(VNET_HDR_LEN))
    }

    fn encoded_name(&self) -> Result<[u8; 16], TunError> {
        encode_name(&self.name)
    }
}

impl AsFd for Tun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.dev.as_fd()
    }
}
