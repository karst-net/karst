// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Linux `ioctl` plumbing — **the only module in Karst that may use `unsafe`**
//! outside the GSO paths (ADR-0003).
//!
//! Everything here is a thin, total wrapper over one syscall. The crate denies
//! `unsafe_code`; this module carries the single `allow`, so the blast radius
//! of a memory-safety mistake is this file. Each block states its argument.
//!
//! The `ifreq` layout is declared locally rather than taken from `libc`, whose
//! union representation has changed shape across releases. A fixed 24-byte
//! payload area matches the kernel's `sizeof(struct ifreq)` of 40 on every
//! Linux ABI Karst targets, and a static assertion below holds it there.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// `IFNAMSIZ` — interface names are at most 15 bytes plus a NUL.
pub(crate) const IF_NAME_SIZE: usize = 16;

/// Payload area of `struct ifreq`, the union following the name.
const IF_REQ_DATA: usize = 24;

// `TUNSETIFF` = `_IOW('T', 202, int)`; the SIOC* codes are ABI-stable.
const TUNSETIFF: u64 = 0x4004_54ca;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFMTU: u64 = 0x8922;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCSIFNETMASK: u64 = 0x891c;
const SIOCGIFINDEX: u64 = 0x8933;
// `TUNSETOFFLOAD` = `_IOW('T', 208, unsigned int)`,
// `TUNSETVNETHDRSZ` = `_IOW('T', 216, int)`.
const TUNSETOFFLOAD: u64 = 0x4004_54d0;
const TUNSETVNETHDRSZ: u64 = 0x4004_54d8;

/// Layer-3 device: bare IP packets.
pub(crate) const IFF_TUN: i16 = 0x0001;
/// No 4-byte packet-information prefix, so a read yields exactly one IP packet.
pub(crate) const IFF_NO_PI: i16 = 0x1000;
/// Each read and write is prefixed by a `virtio_net_hdr`, which is what allows
/// the kernel to hand over coalesced segments.
pub(crate) const IFF_VNET_HDR: i16 = 0x4000;

/// Offload capabilities for `TUNSETOFFLOAD`.
pub(crate) const TUN_F_CSUM: u32 = 0x01;
pub(crate) const TUN_F_TSO4: u32 = 0x02;
pub(crate) const TUN_F_TSO6: u32 = 0x04;
/// Interface is administratively up.
const IFF_UP: i16 = 0x0001;
/// Interface is operationally running.
const IFF_RUNNING: i16 = 0x0040;

/// `struct ifreq`, as the kernel expects it.
#[repr(C)]
pub(crate) struct IfReq {
    name: [u8; IF_NAME_SIZE],
    data: [u8; IF_REQ_DATA],
}

/// The kernel reads and writes exactly this many bytes. A mismatch would mean
/// handing it a buffer smaller than it expects to fill.
const _: () = assert!(size_of::<IfReq>() == 40);

impl IfReq {
    /// A request naming `name`, with a zeroed payload area.
    pub(crate) const fn new(name: [u8; IF_NAME_SIZE]) -> Self {
        Self {
            name,
            data: [0u8; IF_REQ_DATA],
        }
    }

    /// The name field, as the kernel left it — it assigns one when the request
    /// was empty.
    pub(crate) fn name(&self) -> &[u8; IF_NAME_SIZE] {
        &self.name
    }

    fn set_flags_field(&mut self, flags: i16) {
        let bytes = flags.to_ne_bytes();
        if let Some(head) = self.data.get_mut(..2) {
            head.copy_from_slice(&bytes);
        }
    }

    fn flags_field(&self) -> i16 {
        self.data
            .first_chunk::<2>()
            .map_or(0, |b| i16::from_ne_bytes(*b))
    }

    fn set_int_field(&mut self, value: i32) {
        let bytes = value.to_ne_bytes();
        if let Some(head) = self.data.get_mut(..4) {
            head.copy_from_slice(&bytes);
        }
    }

    /// Write a `sockaddr_in` into the payload area: family, zero port, address,
    /// then eight bytes of padding that are already zero.
    fn set_sockaddr_in(&mut self, addr: Ipv4Addr) {
        #[allow(clippy::cast_possible_truncation)]
        let family = (libc::AF_INET as u16).to_ne_bytes();
        if let Some(head) = self.data.get_mut(..2) {
            head.copy_from_slice(&family);
        }
        if let Some(port) = self.data.get_mut(2..4) {
            port.copy_from_slice(&0u16.to_be_bytes());
        }
        if let Some(ip) = self.data.get_mut(4..8) {
            ip.copy_from_slice(&addr.octets());
        }
    }
}

/// Issue an `ioctl` carrying an `ifreq`.
///
/// `op` names the operation for the error message; a bare `EPERM` from an
/// unnamed `ioctl` is one of the least actionable errors in systems
/// programming.
fn ifreq_ioctl(
    fd: BorrowedFd<'_>,
    request: u64,
    req: &mut IfReq,
    op: &'static str,
) -> io::Result<()> {
    // SAFETY: `fd` is open and valid for the duration of this call, guaranteed
    // by `BorrowedFd`'s lifetime. `req` is a live, uniquely borrowed, correctly
    // sized `#[repr(C)]` `struct ifreq` — the static assertion above pins its
    // 40-byte layout — so the kernel may read and write it in place without
    // exceeding the allocation. Every `request` used with this function is one
    // whose kernel handler takes an `ifreq` pointer, so the kernel's view of the
    // buffer matches ours. `ioctl` is variadic; the pointer is the single
    // trailing argument. Errno is read immediately, with no intervening call
    // that could overwrite it.
    let rc = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            request as libc::Ioctl,
            std::ptr::from_mut(req).cast::<c_void>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("{op}: {}", io::Error::last_os_error()),
        ));
    }
    Ok(())
}

/// Register an open `/dev/net/tun` handle as a TUN interface.
///
/// Returns the name the kernel assigned, which differs from the request when
/// the caller passed an empty name.
pub(crate) fn set_iff(
    fd: BorrowedFd<'_>,
    name: [u8; IF_NAME_SIZE],
    flags: i16,
) -> io::Result<[u8; IF_NAME_SIZE]> {
    let mut req = IfReq::new(name);
    req.set_flags_field(flags);
    ifreq_ioctl(fd, TUNSETIFF, &mut req, "TUNSETIFF (needs CAP_NET_ADMIN)")?;
    Ok(*req.name())
}

/// Set the `virtio_net_hdr` size the device will use.
pub(crate) fn set_vnet_hdr_size(fd: BorrowedFd<'_>, size: i32) -> io::Result<()> {
    // SAFETY: `fd` is an open `/dev/net/tun` handle for the duration of the
    // call. `TUNSETVNETHDRSZ` reads a single `int` through the pointer, which
    // is exactly what `size` is, and it lives across the call. Nothing is
    // written back.
    let rc = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            TUNSETVNETHDRSZ as libc::Ioctl,
            std::ptr::from_ref(&size).cast::<c_void>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Enable segmentation and checksum offload.
///
/// Best-effort by design: a kernel or device that declines simply means reads
/// return one packet each, which is the unaccelerated path and still correct.
pub(crate) fn set_offload(fd: BorrowedFd<'_>, features: u32) -> io::Result<()> {
    // SAFETY: `fd` is an open `/dev/net/tun` handle for the duration of the
    // call. `TUNSETOFFLOAD` takes its argument by value in the pointer slot —
    // an `unsigned int` bit-set, not a pointer to be dereferenced — so no
    // memory is read or written through it.
    let rc = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            TUNSETOFFLOAD as libc::Ioctl,
            libc::c_ulong::from(features),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A datagram socket used only as a handle for interface `ioctl`s. The kernel
/// requires *some* socket; the family is irrelevant to the operations below,
/// and `AF_INET` is available on every Linux configuration Karst supports.
pub(crate) fn control_socket() -> io::Result<OwnedFd> {
    // SAFETY: `socket` with constant, valid arguments has no preconditions. It
    // returns either -1 or a fresh descriptor.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly created, open descriptor owned by nobody else,
    // so transferring it to `OwnedFd` gives exactly one owner and one close.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Set the interface MTU.
pub(crate) fn set_mtu(sock: BorrowedFd<'_>, name: [u8; IF_NAME_SIZE], mtu: i32) -> io::Result<()> {
    let mut req = IfReq::new(name);
    req.set_int_field(mtu);
    ifreq_ioctl(sock, SIOCSIFMTU, &mut req, "SIOCSIFMTU")
}

/// Bring the interface up, preserving flags the kernel already set.
pub(crate) fn set_up(sock: BorrowedFd<'_>, name: [u8; IF_NAME_SIZE]) -> io::Result<()> {
    let mut req = IfReq::new(name);
    ifreq_ioctl(sock, SIOCGIFFLAGS, &mut req, "SIOCGIFFLAGS")?;
    let flags = req.flags_field() | IFF_UP | IFF_RUNNING;
    let mut req = IfReq::new(name);
    req.set_flags_field(flags);
    ifreq_ioctl(sock, SIOCSIFFLAGS, &mut req, "SIOCSIFFLAGS")
}

/// Assign an IPv4 address and netmask.
pub(crate) fn set_ipv4(
    sock: BorrowedFd<'_>,
    name: [u8; IF_NAME_SIZE],
    addr: Ipv4Addr,
    netmask: Ipv4Addr,
) -> io::Result<()> {
    let mut req = IfReq::new(name);
    req.set_sockaddr_in(addr);
    ifreq_ioctl(sock, SIOCSIFADDR, &mut req, "SIOCSIFADDR")?;

    let mut req = IfReq::new(name);
    req.set_sockaddr_in(netmask);
    ifreq_ioctl(sock, SIOCSIFNETMASK, &mut req, "SIOCSIFNETMASK")
}

/// `struct in6_ifreq` — the IPv6 path takes a different structure entirely,
/// keyed by interface index rather than by name.
#[repr(C)]
struct In6IfReq {
    addr: [u8; 16],
    prefix_len: u32,
    if_index: i32,
}

const _: () = assert!(size_of::<In6IfReq>() == 24);

/// Look up an interface index by name.
fn if_index(sock: BorrowedFd<'_>, name: [u8; IF_NAME_SIZE]) -> io::Result<i32> {
    let mut req = IfReq::new(name);
    ifreq_ioctl(sock, SIOCGIFINDEX, &mut req, "SIOCGIFINDEX")?;
    Ok(req
        .data
        .first_chunk::<4>()
        .map_or(0, |b| i32::from_ne_bytes(*b)))
}

/// Assign an IPv6 address.
///
/// A separate socket family and structure from the IPv4 case; there is no
/// unified `ioctl` for both. `sock` must be an `AF_INET6` socket.
pub(crate) fn set_ipv6(
    sock6: BorrowedFd<'_>,
    sock4: BorrowedFd<'_>,
    name: [u8; IF_NAME_SIZE],
    addr: std::net::Ipv6Addr,
    prefix_len: u32,
) -> io::Result<()> {
    let mut req = In6IfReq {
        addr: addr.octets(),
        prefix_len,
        if_index: if_index(sock4, name)?,
    };
    // SAFETY: identical argument to `ifreq_ioctl` — `sock6` is open for the
    // call, and `req` is a live, uniquely borrowed `#[repr(C)]` `in6_ifreq`
    // whose 24-byte layout the static assertion above pins. `SIOCSIFADDR` on an
    // `AF_INET6` socket is the operation that takes this structure, so the
    // kernel reads exactly the bytes we provided and writes none.
    let rc = unsafe {
        libc::ioctl(
            sock6.as_raw_fd(),
            SIOCSIFADDR as libc::Ioctl,
            std::ptr::from_mut(&mut req).cast::<c_void>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!("SIOCSIFADDR (IPv6): {}", io::Error::last_os_error()),
        ));
    }
    Ok(())
}

/// An `AF_INET6` datagram socket, for the IPv6 address `ioctl`.
pub(crate) fn control_socket_v6() -> io::Result<OwnedFd> {
    // SAFETY: as `control_socket` — constant valid arguments, returns -1 or a
    // fresh descriptor which we take sole ownership of.
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is fresh, open, and owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

// ── routes, over rtnetlink ──────────────────────────────────────────────────

/// `AF_NETLINK` protocol for routing.
const NETLINK_ROUTE: i32 = 0;

/// `rtmsg.rtm_family` is one byte, so the families are narrowed once, here.
const AF_INET_U8: u8 = 2;
const AF_INET6_U8: u8 = 10;
/// The narrowing above must match what the C headers say, or every route would
/// be filed under the wrong family.
const _: () = assert!(AF_INET_U8 as i32 == libc::AF_INET);
const _: () = assert!(AF_INET6_U8 as i32 == libc::AF_INET6);

/// rtnetlink message types.
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

/// `nlmsghdr` flags.
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_REPLACE: u16 = 0x0100;
const NLM_F_CREATE: u16 = 0x0400;

/// `rtmsg` fields.
const RT_TABLE_MAIN: u8 = 254;
/// Set by boot-time configuration — the same value `ip route` uses by default,
/// so a Karst route looks like any other in `ip route show`.
const RTPROT_BOOT: u8 = 3;
/// The destination is on-link, reachable directly over the device. That is what
/// makes a gateway unnecessary: a tunnel peer is not behind a next hop, it *is*
/// the far end of the interface.
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

/// `rtattr` types.
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;

const NLMSG_ERROR: u16 = 2;
const NLMSG_HDR_LEN: usize = 16;
/// `sizeof(struct rtmsg)`. Used by the encoding tests, which navigate the
/// message by offset rather than trusting it to be the right shape.
const RTMSG_LEN: usize = 12;
const RTATTR_LEN: usize = 4;

const fn nl_align(n: usize) -> usize {
    (n + 3) & !3
}

/// Which way a route request goes.
#[derive(Clone, Copy)]
pub(crate) enum RouteOp {
    Add,
    Delete,
}

/// Build the rtnetlink request for one route.
///
/// Split out from the syscall and returning plain bytes, because this is the
/// part that is easy to get wrong and impossible to see: a mis-sized attribute
/// or a forgotten alignment byte produces `EINVAL` from the kernel with nothing
/// to say which field was wrong. Encoded here, checked by tests that need no
/// privileges.
pub(crate) fn route_message(
    op: RouteOp,
    seq: u32,
    dst: IpAddr,
    prefix_len: u8,
    if_index: u32,
) -> Vec<u8> {
    let (family, addr): (u8, Vec<u8>) = match dst {
        // The families fit in a byte; `rtm_family` is one. Written as
        // constants rather than a cast so the narrowing is checked once here
        // rather than asserted at each use.
        IpAddr::V4(a) => (AF_INET_U8, a.octets().to_vec()),
        IpAddr::V6(a) => (AF_INET6_U8, a.octets().to_vec()),
    };

    let mut msg = Vec::with_capacity(64);
    // nlmsghdr: length is filled in once the body is known.
    msg.extend_from_slice(&0u32.to_ne_bytes());
    let (kind, flags) = match op {
        // REPLACE as well as CREATE: re-adding a route a previous run left
        // behind must succeed rather than fail with EEXIST, or a daemon restart
        // would come up with no route to half its peers.
        RouteOp::Add => (
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        ),
        RouteOp::Delete => (RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK),
    };
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    // Port ID 0 asks the kernel to fill in ours.
    msg.extend_from_slice(&0u32.to_ne_bytes());

    // rtmsg.
    msg.push(family);
    msg.push(prefix_len); // rtm_dst_len
    msg.push(0); // rtm_src_len
    msg.push(0); // rtm_tos
    msg.push(RT_TABLE_MAIN);
    msg.push(RTPROT_BOOT);
    msg.push(RT_SCOPE_LINK);
    msg.push(RTN_UNICAST);
    msg.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags

    push_attr(&mut msg, RTA_DST, &addr);
    push_attr(&mut msg, RTA_OIF, &if_index.to_ne_bytes());

    let len = u32::try_from(msg.len()).unwrap_or(u32::MAX);
    if let Some(head) = msg.get_mut(..4) {
        head.copy_from_slice(&len.to_ne_bytes());
    }
    msg
}

/// Append one `rtattr`, padded to the 4-byte alignment netlink requires.
///
/// The length field counts the header *and* the unpadded payload; the padding
/// that follows is not counted. Getting that backwards is the classic netlink
/// mistake and yields `EINVAL` with no further explanation.
fn push_attr(msg: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = u16::try_from(4 + payload.len()).unwrap_or(u16::MAX);
    msg.extend_from_slice(&len.to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(payload);
    let pad = (4 - (payload.len() % 4)) % 4;
    msg.extend(std::iter::repeat_n(0u8, pad));
}

/// Read the kernel's answer to a route request.
///
/// Every request sets `NLM_F_ACK`, so exactly one `NLMSG_ERROR` comes back —
/// with `error == 0` for success. Not waiting for it would make every failure
/// silent: the route would simply not be there, and the symptom would be a peer
/// that cannot be reached for no visible reason.
pub(crate) fn route_ack(reply: &[u8], seq: u32) -> io::Result<()> {
    let short = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "netlink reply is shorter than a header",
        )
    };
    // Every read goes through `get`: this parses bytes the kernel wrote, and a
    // panic on the control path would take the daemon down over a short read.
    let kind = u16::from_ne_bytes(
        *reply
            .get(4..)
            .ok_or_else(short)?
            .first_chunk::<2>()
            .ok_or_else(short)?,
    );
    let got_seq = u32::from_ne_bytes(
        *reply
            .get(8..)
            .ok_or_else(short)?
            .first_chunk::<4>()
            .ok_or_else(short)?,
    );
    if got_seq != seq {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("netlink reply is for sequence {got_seq}, expected {seq}"),
        ));
    }
    if kind != NLMSG_ERROR {
        // An ack is the only reply a route request asks for. Anything else
        // means the kernel answered a question we did not put.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected netlink message type {kind}"),
        ));
    }
    let code = i32::from_ne_bytes(
        *reply
            .get(NLMSG_HDR_LEN..)
            .and_then(<[u8]>::first_chunk::<4>)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "netlink error message carries no code",
                )
            })?,
    );
    if code == 0 {
        return Ok(());
    }
    // The kernel reports errors as negative errno.
    Err(io::Error::from_raw_os_error(-code))
}

/// Whether a netlink error means "that route was not there".
///
/// The kernel answers a delete for a route it does not hold with `ESRCH`, and
/// occasionally `ENOENT`. Neither maps to `io::ErrorKind::NotFound` — `ESRCH`
/// arrives as `Uncategorized` — so matching on the kind silently fails to
/// recognize the one case a caller wants to tolerate. The raw errno is the only
/// reliable answer.
pub(crate) fn is_absent(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ESRCH | libc::ENOENT))
}

/// A netlink socket bound to this process.
pub(crate) fn netlink_socket() -> io::Result<OwnedFd> {
    // SAFETY: as `control_socket` — constant valid arguments, returns -1 or a
    // fresh descriptor which we take sole ownership of.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor this call owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Send one route request and wait for its acknowledgment.
pub(crate) fn route(
    sock: BorrowedFd<'_>,
    op: RouteOp,
    seq: u32,
    dst: IpAddr,
    prefix_len: u8,
    if_index: u32,
) -> io::Result<()> {
    let msg = route_message(op, seq, dst, prefix_len, if_index);
    send_netlink_request(sock, &msg, seq)
}

/// Build the rtnetlink request that adds one *secondary* address to an
/// interface.
///
/// This is additive, unlike `SIOCSIFADDR` (used by [`set_ipv4`] /
/// [`set_ipv6`]): that ioctl **replaces** whatever address the interface
/// already had, so calling it a second time for a different address —
/// exactly what a DNS stub host address needs, alongside the node's own
/// overlay address — leaves only the second one behind. `NLM_F_CREATE`
/// without `NLM_F_REPLACE` is deliberate: this must add, and only add, never
/// silently displace an address assigned another way.
pub(crate) fn new_address_message(
    seq: u32,
    addr: IpAddr,
    prefix_len: u8,
    if_index: u32,
) -> Vec<u8> {
    let (family, bytes): (u8, Vec<u8>) = match addr {
        IpAddr::V4(a) => (AF_INET_U8, a.octets().to_vec()),
        IpAddr::V6(a) => (AF_INET6_U8, a.octets().to_vec()),
    };

    let mut msg = Vec::with_capacity(NLMSG_HDR_LEN + IFADDRMSG_LEN + 16);
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&RTM_NEWADDR.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());

    // ifaddrmsg.
    msg.push(family);
    msg.push(prefix_len);
    msg.push(0); // ifa_flags — the permanent default; IFA_F_* attributes are
                 // for the kernel to report back, not for a request to set.
    msg.push(RT_SCOPE_UNIVERSE);
    msg.extend_from_slice(&if_index.to_ne_bytes());

    // IFA_LOCAL is this host's own address; IFA_ADDRESS matches it on a
    // non-point-to-point interface. Setting both is what `ip addr add`
    // itself does, and addr_batch's IFA_LOCAL-wins parsing (see
    // `read_addr_message`) means a reader agrees with what was requested.
    push_attr(&mut msg, IFA_LOCAL, &bytes);
    push_attr(&mut msg, IFA_ADDRESS, &bytes);

    let len = u32::try_from(msg.len()).unwrap_or(u32::MAX);
    if let Some(head) = msg.get_mut(..4) {
        head.copy_from_slice(&len.to_ne_bytes());
    }
    msg
}

/// Send a secondary-address request and wait for its acknowledgment.
///
/// Adding an address that is already present succeeds rather than failing —
/// the kernel treats an identical `RTM_NEWADDR` as idempotent — so a daemon
/// restart does not need to know whether a previous run already got here.
pub(crate) fn new_address(
    sock: BorrowedFd<'_>,
    seq: u32,
    addr: IpAddr,
    prefix_len: u8,
    if_index: u32,
) -> io::Result<()> {
    let msg = new_address_message(seq, addr, prefix_len, if_index);
    send_netlink_request(sock, &msg, seq)
}

/// Send one already-built netlink request and wait for its `NLMSG_ERROR` ack.
/// Shared by [`route`] and [`new_address`] — the request differs, the
/// send/receive/ack sequence around it does not.
fn send_netlink_request(sock: BorrowedFd<'_>, msg: &[u8], seq: u32) -> io::Result<()> {
    // SAFETY: `sock` is open for the call, and `msg` is a live slice of exactly
    // `msg.len()` initialized bytes. `send` reads that many and writes none.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            msg.as_ptr().cast::<c_void>(),
            msg.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut reply = [0u8; 256];
    // SAFETY: `reply` is a live, uniquely borrowed array of exactly 256 bytes,
    // and the length passed is its true size. `recv` writes at most that many
    // and returns how many it wrote.
    let got = unsafe {
        libc::recv(
            sock.as_raw_fd(),
            reply.as_mut_ptr().cast::<c_void>(),
            reply.len(),
            0,
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let got = usize::try_from(got).unwrap_or(0);
    route_ack(reply.get(..got).unwrap_or_default(), seq)
}

/// The kernel's index for a named interface.
pub(crate) fn interface_index(sock: BorrowedFd<'_>, name: [u8; IF_NAME_SIZE]) -> io::Result<u32> {
    if_index(sock, name).map(|i| u32::try_from(i).unwrap_or(0))
}

// ── enumerating the host's own addresses ───────────────────────────────────
//
// AVEN needs the set of addresses a peer might reach this node on
// (`spec/aven-v1.md` §7.3). That is a question about the *host*, not about the
// tunnel, but it needs `AF_NETLINK` and therefore `unsafe`, and ADR-0003 keeps
// every such call in this file.

/// rtnetlink address-dump message types.
const RTM_GETADDR: u16 = 22;
const RTM_NEWADDR: u16 = 20;
const RTM_GETROUTE: u16 = 26;
const NLM_F_DUMP: u16 = 0x0300;
const NLMSG_DONE: u16 = 3;

/// `sizeof(struct ifaddrmsg)`.
const IFADDRMSG_LEN: usize = 8;

/// `rtattr` types inside an `ifaddrmsg`.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

/// `ifa_scope`. Anything above universe is link-, site- or host-local, and none
/// of those is reachable by a peer.
const RT_SCOPE_UNIVERSE: u8 = 0;

/// `rtattr` types inside an `rtmsg`.
const RTA_GATEWAY: u16 = 5;

/// `ifa_flags`. A tentative address has not finished duplicate-address
/// detection and may yet be withdrawn; a deprecated one still works for
/// established flows but must not be offered for new ones. Advertising either
/// spends a peer's probe budget on an address that will not answer.
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_DEPRECATED: u32 = 0x20;

/// Ask the kernel for every address on every interface.
///
/// `AF_UNSPEC` covers both families in one dump. Split out and returning plain
/// bytes for the same reason `route_message` is: this is the part that is easy
/// to get wrong and impossible to see.
pub(crate) fn addr_dump_message(seq: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(NLMSG_HDR_LEN + IFADDRMSG_LEN);
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&RTM_GETADDR.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());

    // ifaddrmsg: family AF_UNSPEC, everything else zero for a dump.
    msg.push(0); // ifa_family
    msg.push(0); // ifa_prefixlen
    msg.push(0); // ifa_flags
    msg.push(0); // ifa_scope
    msg.extend_from_slice(&0u32.to_ne_bytes()); // ifa_index

    let len = u32::try_from(msg.len()).unwrap_or(u32::MAX);
    if let Some(head) = msg.get_mut(..4) {
        head.copy_from_slice(&len.to_ne_bytes());
    }
    msg
}

/// What one pass over a dump buffer produced.
pub(crate) struct AddrBatch {
    pub(crate) addrs: Vec<IpAddr>,
    /// Whether `NLMSG_DONE` appeared, meaning no further `recv` is needed.
    pub(crate) done: bool,
}

/// Parse one buffer of `RTM_NEWADDR` messages.
///
/// **Pure, so it can be tested without privileges or a network.** Every read
/// goes through `get`: these are bytes the kernel wrote, but a malformed or
/// truncated dump must degrade to "fewer candidates" rather than take the
/// daemon down.
///
/// Addresses the kernel reports but a peer cannot use are dropped here rather
/// than by the caller — scope, tentative and deprecated are facts about the
/// address, not policy about what to do with it. Which of the remaining ones
/// are *worth advertising* is AVEN's decision and is made in `karstd`.
pub(crate) fn parse_addr_dump(buf: &[u8]) -> AddrBatch {
    let mut addrs = Vec::new();
    let mut done = false;
    let mut rest = buf;

    while rest.len() >= NLMSG_HDR_LEN {
        let Some(len) = rest.first_chunk::<4>().map(|b| u32::from_ne_bytes(*b)) else {
            break;
        };
        let len = usize::try_from(len).unwrap_or(0);
        // A header shorter than a header, or longer than what arrived, means
        // the stream is not walkable; stopping beats guessing a stride.
        if len < NLMSG_HDR_LEN || len > rest.len() {
            break;
        }
        let Some(msg) = rest.get(..len) else { break };
        let kind = msg
            .get(4..)
            .and_then(<[u8]>::first_chunk::<2>)
            .map_or(0, |b| u16::from_ne_bytes(*b));

        if kind == NLMSG_DONE {
            done = true;
            break;
        }
        if kind == RTM_NEWADDR {
            if let Some(addr) = parse_ifaddr(msg.get(NLMSG_HDR_LEN..).unwrap_or_default()) {
                addrs.push(addr);
            }
        }

        // Messages are padded to a 4-byte boundary.
        let step = len.saturating_add(3) & !3usize;
        let Some(next) = rest.get(step..) else { break };
        rest = next;
    }

    AddrBatch { addrs, done }
}

/// One `ifaddrmsg` and its attributes, or `None` if it names nothing usable.
fn parse_ifaddr(body: &[u8]) -> Option<IpAddr> {
    let header = body.get(..IFADDRMSG_LEN)?;
    let family = *header.first()?;
    let scope = *header.get(3)?;
    let mut flags = u32::from(*header.get(2)?);

    // Only globally scoped addresses. This is what removes loopback (host
    // scope) and IPv6 link-local (link scope) without special-casing either.
    if scope != RT_SCOPE_UNIVERSE {
        return None;
    }

    let mut address = None;
    let mut local = None;
    let mut attrs = body.get(IFADDRMSG_LEN..)?;
    while attrs.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes(*attrs.first_chunk::<2>()?));
        let kind = u16::from_ne_bytes(*attrs.get(2..)?.first_chunk::<2>()?);
        if len < 4 || len > attrs.len() {
            break;
        }
        let payload = attrs.get(4..len)?;
        match kind {
            IFA_ADDRESS => address = ip_from_bytes(family, payload),
            IFA_LOCAL => local = ip_from_bytes(family, payload),
            // Newer kernels carry the full 32-bit flags here; the byte in the
            // header saturates and would hide IFA_F_TENTATIVE on some setups.
            IFA_FLAGS => {
                if let Some(b) = payload.first_chunk::<4>() {
                    flags = u32::from_ne_bytes(*b);
                }
            }
            _ => {}
        }
        let step = len.saturating_add(3) & !3usize;
        attrs = attrs.get(step..)?;
    }

    if flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED) != 0 {
        return None;
    }

    // `IFA_LOCAL` first: on a point-to-point interface `IFA_ADDRESS` holds the
    // *peer's* address, and advertising that would name somebody else's host.
    let addr = local.or(address)?;
    let usable = match addr {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified(),
    };
    usable.then_some(addr)
}

fn ip_from_bytes(family: u8, payload: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET_U8 => payload
            .first_chunk::<4>()
            .map(|b| IpAddr::V4(Ipv4Addr::from(*b))),
        AF_INET6_U8 => payload
            .first_chunk::<16>()
            .map(|b| IpAddr::V6(std::net::Ipv6Addr::from(*b))),
        _ => None,
    }
}

/// Dump every global-scope address the host holds.
pub(crate) fn local_addresses(sock: BorrowedFd<'_>, seq: u32) -> io::Result<Vec<IpAddr>> {
    let msg = addr_dump_message(seq);
    // SAFETY: as `route` — `sock` is open for the call and `msg` is a live
    // slice of exactly `msg.len()` initialized bytes, which `send` only reads.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            msg.as_ptr().cast::<c_void>(),
            msg.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    // A dump arrives in as many datagrams as it needs. The bound is a
    // backstop, not an expectation: a host with more addresses than this can
    // report is one where a truncated candidate list beats an unbounded loop.
    for _ in 0..64 {
        // SAFETY: `buf` is a live, uniquely borrowed allocation of exactly
        // `buf.len()` bytes, and that length is what is passed. `recv` writes
        // at most that many and returns how many it wrote.
        let got = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let got = usize::try_from(got).unwrap_or(0);
        if got == 0 {
            break;
        }
        let batch = parse_addr_dump(buf.get(..got).unwrap_or_default());
        out.extend(batch.addrs);
        if batch.done {
            break;
        }
    }
    Ok(out)
}

/// Ask the kernel for the main-table default route in every family.
///
/// `AF_UNSPEC` covers IPv4 and IPv6 in one dump; the parser below filters to
/// default routes with an explicit next hop.
pub(crate) fn default_route_message(seq: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(NLMSG_HDR_LEN + RTMSG_LEN);
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());

    msg.push(0); // AF_UNSPEC
    msg.push(0); // dst len: default route only
    msg.push(0); // src len
    msg.push(0); // tos
    msg.push(RT_TABLE_MAIN);
    msg.push(0); // protocol
    msg.push(0); // scope
    msg.push(0); // type
    msg.extend_from_slice(&0u32.to_ne_bytes()); // flags

    let len = u32::try_from(msg.len()).unwrap_or(0);
    if let Some(head) = msg.get_mut(..4) {
        head.copy_from_slice(&len.to_ne_bytes());
    }
    msg
}

#[derive(Default)]
pub(crate) struct RouteBatch {
    pub gateways: Vec<IpAddr>,
    pub done: bool,
}

fn parse_route(msg: &[u8]) -> Option<IpAddr> {
    let rt = msg.get(..RTMSG_LEN)?;
    let family = *rt.first()?;
    let dst_len = *rt.get(1)?;
    let table = *rt.get(4)?;
    let kind = *rt.get(7)?;
    if dst_len != 0 || table != RT_TABLE_MAIN || kind != RTN_UNICAST {
        return None;
    }

    let mut at = RTMSG_LEN;
    while let Some(head) = msg.get(at..at.checked_add(RTATTR_LEN)?) {
        let len = usize::from(u16::from_ne_bytes(*head.first_chunk::<2>()?));
        let kind = u16::from_ne_bytes(*head.get(2..4)?.first_chunk::<2>()?);
        if len < RTATTR_LEN {
            break;
        }
        let end = at.checked_add(len)?;
        let body = msg.get(at + RTATTR_LEN..end)?;
        if kind == RTA_GATEWAY {
            return match (family, body.len()) {
                (AF_INET_U8, 4) => Some(IpAddr::V4(Ipv4Addr::from(*body.first_chunk::<4>()?))),
                (AF_INET6_U8, 16) => Some(IpAddr::V6(Ipv6Addr::from(*body.first_chunk::<16>()?))),
                _ => None,
            };
        }
        at = nl_align(end);
    }
    None
}

pub(crate) fn parse_route_dump(buf: &[u8]) -> RouteBatch {
    let mut at = 0usize;
    let mut out = RouteBatch::default();
    while let Some(hdr) = buf.get(at..at.checked_add(NLMSG_HDR_LEN).unwrap_or(usize::MAX)) {
        let len = hdr
            .get(..4)
            .and_then(<[u8]>::first_chunk::<4>)
            .map(|b| u32::from_ne_bytes(*b) as usize);
        let kind = hdr
            .get(4..6)
            .and_then(<[u8]>::first_chunk::<2>)
            .map(|b| u16::from_ne_bytes(*b));
        let (Some(len), Some(kind)) = (len, kind) else {
            break;
        };
        if len < NLMSG_HDR_LEN {
            break;
        }
        let Some(end) = at.checked_add(len) else {
            break;
        };
        let Some(msg) = buf.get(at..end) else {
            break;
        };
        match kind {
            NLMSG_DONE => {
                out.done = true;
                break;
            }
            RTM_NEWROUTE => {
                if let Some(gateway) = parse_route(msg.get(NLMSG_HDR_LEN..).unwrap_or_default()) {
                    out.gateways.push(gateway);
                }
            }
            _ => {}
        }
        at = nl_align(end);
    }
    out
}

/// The next hop of the main-table default route, if there is one.
pub(crate) fn default_gateway(sock: BorrowedFd<'_>, seq: u32) -> io::Result<Option<IpAddr>> {
    let msg = default_route_message(seq);

    // SAFETY: as `route` — `sock` is open for the call and `msg` is a live
    // slice of exactly `msg.len()` initialized bytes.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            msg.as_ptr().cast::<c_void>(),
            msg.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = vec![0u8; 4096];
    for _ in 0..64 {
        // SAFETY: as `local_addresses` — `buf` is a live, uniquely borrowed
        // allocation of exactly `buf.len()` bytes.
        let got = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let got = usize::try_from(got).unwrap_or(0);
        if got == 0 {
            break;
        }
        let batch = parse_route_dump(buf.get(..got).unwrap_or_default());
        if let Some(gateway) = batch.gateways.into_iter().next() {
            return Ok(Some(gateway));
        }
        if batch.done {
            break;
        }
    }
    Ok(None)
}

#[cfg(test)]
mod route_tests {
    #![allow(clippy::indexing_slicing, clippy::panic, clippy::expect_used)]

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn u16_at(msg: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes([msg[at], msg[at + 1]])
    }
    fn u32_at(msg: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes([msg[at], msg[at + 1], msg[at + 2], msg[at + 3]])
    }

    /// **The length field must cover the whole message.** The kernel reads it to
    /// decide how much to parse; a wrong value yields `EINVAL` with nothing to
    /// say which field was at fault.
    #[test]
    fn the_declared_length_matches_the_message() {
        for (dst, prefix) in [
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8u8),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
        ] {
            let msg = route_message(RouteOp::Add, 1, dst, prefix, 7);
            assert_eq!(
                u32_at(&msg, 0) as usize,
                msg.len(),
                "nlmsg_len disagrees with the bytes actually sent"
            );
        }
    }

    /// An IPv4 route: header, `rtmsg`, a 4-byte destination and a 4-byte
    /// interface index, each in a 4-byte-aligned attribute.
    #[test]
    fn an_ipv4_route_has_the_expected_shape() {
        let msg = route_message(
            RouteOp::Add,
            42,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            24,
            9,
        );
        assert_eq!(msg.len(), NLMSG_HDR_LEN + RTMSG_LEN + 8 + 8);

        assert_eq!(u16_at(&msg, 4), RTM_NEWROUTE);
        assert_eq!(u32_at(&msg, 8), 42, "the sequence number must be carried");

        let rt = NLMSG_HDR_LEN;
        assert_eq!(msg[rt], AF_INET_U8);
        assert_eq!(msg[rt + 1], 24, "rtm_dst_len is the prefix length");
        assert_eq!(msg[rt + 4], RT_TABLE_MAIN);
        assert_eq!(
            msg[rt + 6],
            RT_SCOPE_LINK,
            "a tunnel peer is on-link, not behind a gateway"
        );
        assert_eq!(msg[rt + 7], RTN_UNICAST);

        let a1 = rt + RTMSG_LEN;
        assert_eq!(
            u16_at(&msg, a1),
            8,
            "RTA_DST length covers header + 4 bytes"
        );
        assert_eq!(u16_at(&msg, a1 + 2), RTA_DST);
        assert_eq!(&msg[a1 + 4..a1 + 8], &[192, 168, 1, 0]);

        let a2 = a1 + 8;
        assert_eq!(u16_at(&msg, a2), 8);
        assert_eq!(u16_at(&msg, a2 + 2), RTA_OIF);
        assert_eq!(u32_at(&msg, a2 + 4), 9, "the interface index");
    }

    /// A 16-byte address needs no padding, and the whole message stays aligned.
    #[test]
    fn an_ipv6_route_carries_a_sixteen_byte_destination() {
        let addr = Ipv6Addr::new(0xfd7a, 0x5ea5, 0, 0, 0, 0, 0, 0);
        let msg = route_message(RouteOp::Add, 1, IpAddr::V6(addr), 64, 3);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + RTMSG_LEN + 20 + 8);

        let a1 = NLMSG_HDR_LEN + RTMSG_LEN;
        assert_eq!(u16_at(&msg, a1), 20);
        assert_eq!(&msg[a1 + 4..a1 + 20], &addr.octets());
        assert_eq!(msg[NLMSG_HDR_LEN], AF_INET6_U8);
        assert_eq!(msg.len() % 4, 0, "netlink messages are 4-byte aligned");
    }

    /// **Adding a route that already exists must succeed**, or a daemon restart
    /// would come up missing routes it left behind and half its peers would be
    /// unreachable for no visible reason.
    #[test]
    fn an_add_replaces_rather_than_failing_on_a_duplicate() {
        let msg = route_message(RouteOp::Add, 1, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, 1);
        let flags = u16_at(&msg, 6);
        assert_ne!(flags & NLM_F_CREATE, 0);
        assert_ne!(flags & NLM_F_REPLACE, 0, "EEXIST must not be possible");
        assert_ne!(flags & NLM_F_ACK, 0, "every request must be acknowledged");
    }

    /// A delete must not carry CREATE, or a request to remove a route would
    /// add one.
    #[test]
    fn a_delete_does_not_create() {
        let msg = route_message(RouteOp::Delete, 1, IpAddr::V4(Ipv4Addr::LOCALHOST), 32, 1);
        assert_eq!(u16_at(&msg, 4), RTM_DELROUTE);
        let flags = u16_at(&msg, 6);
        assert_eq!(flags & NLM_F_CREATE, 0);
        assert_eq!(flags & NLM_F_REPLACE, 0);
        assert_ne!(flags & NLM_F_ACK, 0);
    }

    // ── the acknowledgment ─────────────────────────────────────────────────

    fn ack(seq: u32, code: i32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&36u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&code.to_ne_bytes());
        m
    }

    #[test]
    fn a_zero_error_code_is_success() {
        assert!(route_ack(&ack(5, 0), 5).is_ok());
    }

    /// **The kernel reports errors as negative errno**, and reading the sign
    /// backwards would turn every failure into a success — a route that is
    /// simply not there, with nothing to explain why.
    #[test]
    fn a_negative_code_is_the_errno() {
        let err = route_ack(&ack(5, -libc::EPERM), 5).expect_err("EPERM must surface");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));

        // ESRCH is what a delete for a route the kernel does not hold returns.
        // It does *not* map to `ErrorKind::NotFound` — it arrives as
        // `Uncategorized` — so recognizing it has to go through the raw errno.
        let err = route_ack(&ack(5, -libc::ESRCH), 5).expect_err("ESRCH must surface");
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
        assert!(
            is_absent(&err),
            "removing an absent route must be recognizable as absent"
        );
        assert!(is_absent(&std::io::Error::from_raw_os_error(libc::ENOENT)));
        assert!(
            !is_absent(&std::io::Error::from_raw_os_error(libc::EPERM)),
            "a permissions failure is not an absent route"
        );
    }

    /// A reply to somebody else's request must not be read as an answer to
    /// ours: two route operations in flight would otherwise let one succeed on
    /// the strength of the other's ack.
    #[test]
    fn a_reply_for_another_sequence_is_refused() {
        assert!(route_ack(&ack(9, 0), 5).is_err());
    }

    #[test]
    fn a_truncated_or_unexpected_reply_is_refused() {
        assert!(route_ack(&[], 1).is_err());
        assert!(route_ack(&ack(1, 0)[..10], 1).is_err());

        // A well-formed message that is not an error report.
        let mut other = ack(1, 0);
        other[4] = 3; // RTM_GETROUTE-ish; anything that is not NLMSG_ERROR
        other[5] = 0;
        assert!(route_ack(&other, 1).is_err());
    }
}

#[cfg(test)]
mod new_address_tests {
    #![allow(clippy::indexing_slicing, clippy::panic, clippy::expect_used)]

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn u16_at(msg: &[u8], at: usize) -> u16 {
        u16::from_ne_bytes([msg[at], msg[at + 1]])
    }
    fn u32_at(msg: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes([msg[at], msg[at + 1], msg[at + 2], msg[at + 3]])
    }

    #[test]
    fn the_declared_length_matches_the_message() {
        let msg = new_address_message(1, IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)), 32, 7);
        assert_eq!(u32_at(&msg, 0) as usize, msg.len());
    }

    /// **This is the whole point of the function.** A request that carries
    /// `NLM_F_REPLACE` would let the kernel treat the stub address as
    /// replacing whatever address the interface already had — the exact bug
    /// `add_secondary_address` exists to avoid. `CREATE` alone adds, and only
    /// adds.
    #[test]
    fn adding_never_carries_replace() {
        let msg = new_address_message(1, IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)), 32, 7);
        let flags = u16_at(&msg, 6);
        assert_ne!(flags & NLM_F_CREATE, 0, "must create");
        assert_eq!(flags & NLM_F_REPLACE, 0, "must never replace");
        assert_ne!(flags & NLM_F_ACK, 0, "every request must be acknowledged");
    }

    #[test]
    fn an_ipv4_secondary_address_has_the_expected_shape() {
        let msg = new_address_message(42, IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100)), 32, 9);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + IFADDRMSG_LEN + 8 + 8);
        assert_eq!(u16_at(&msg, 4), RTM_NEWADDR);
        assert_eq!(u32_at(&msg, 8), 42, "the sequence number must be carried");

        let ifa = NLMSG_HDR_LEN;
        assert_eq!(msg[ifa], AF_INET_U8);
        assert_eq!(msg[ifa + 1], 32, "ifa_prefixlen");
        assert_eq!(msg[ifa + 3], RT_SCOPE_UNIVERSE);
        assert_eq!(u32_at(&msg, ifa + 4), 9, "ifa_index");

        let a1 = ifa + IFADDRMSG_LEN;
        assert_eq!(u16_at(&msg, a1 + 2), IFA_LOCAL);
        assert_eq!(&msg[a1 + 4..a1 + 8], &[100, 100, 100, 100]);
        let a2 = a1 + 8;
        assert_eq!(u16_at(&msg, a2 + 2), IFA_ADDRESS);
        assert_eq!(&msg[a2 + 4..a2 + 8], &[100, 100, 100, 100]);
    }

    #[test]
    fn an_ipv6_secondary_address_carries_a_sixteen_byte_payload() {
        let addr = Ipv6Addr::new(0xfd7a, 0x5ea5, 0, 0, 0, 0, 0, 1);
        let msg = new_address_message(1, IpAddr::V6(addr), 128, 3);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + IFADDRMSG_LEN + 20 + 20);
        assert_eq!(msg[NLMSG_HDR_LEN], AF_INET6_U8);
        assert_eq!(msg.len() % 4, 0, "netlink messages are 4-byte aligned");
    }
}

#[cfg(test)]
mod addr_tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::cast_possible_truncation
    )]

    use super::*;
    use std::net::Ipv6Addr;

    /// Build one `RTM_NEWADDR` message the way the kernel lays it out.
    fn newaddr(family: u8, scope: u8, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![family, 24, 0, scope];
        body.extend_from_slice(&1u32.to_ne_bytes()); // ifa_index
        for (kind, payload) in attrs {
            let len = u16::try_from(4 + payload.len()).expect("small attribute");
            body.extend_from_slice(&len.to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(payload);
            body.extend(std::iter::repeat_n(0u8, (4 - (payload.len() % 4)) % 4));
        }
        let mut msg = Vec::new();
        let total = u32::try_from(NLMSG_HDR_LEN + body.len()).expect("small message");
        msg.extend_from_slice(&total.to_ne_bytes());
        msg.extend_from_slice(&RTM_NEWADDR.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    fn v4_attr(kind: u16, a: [u8; 4]) -> (u16, Vec<u8>) {
        (kind, a.to_vec())
    }

    fn done() -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&(NLMSG_HDR_LEN as u32).to_ne_bytes());
        msg.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg
    }

    fn newroute_default(family: u8, gateway: &[u8]) -> Vec<u8> {
        let attr_len = u16::try_from(RTATTR_LEN + gateway.len()).expect("small attr");
        let padded = nl_align(RTATTR_LEN + gateway.len());
        let total = u32::try_from(NLMSG_HDR_LEN + RTMSG_LEN + padded).expect("small message");
        let mut msg = Vec::new();
        msg.extend_from_slice(&total.to_ne_bytes());
        msg.extend_from_slice(&RTM_NEWROUTE.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.push(family);
        msg.push(0); // dst len = default
        msg.push(0);
        msg.push(0);
        msg.push(RT_TABLE_MAIN);
        msg.push(0);
        msg.push(0);
        msg.push(RTN_UNICAST);
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&attr_len.to_ne_bytes());
        msg.extend_from_slice(&RTA_GATEWAY.to_ne_bytes());
        msg.extend_from_slice(gateway);
        msg.extend(std::iter::repeat_n(
            0u8,
            padded - (RTATTR_LEN + gateway.len()),
        ));
        msg
    }

    #[test]
    fn the_request_asks_both_families_for_a_dump() {
        let msg = addr_dump_message(7);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + IFADDRMSG_LEN);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 24);
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_GETADDR
        );
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert_eq!(u32::from_ne_bytes(msg[8..12].try_into().unwrap()), 7);
        assert_eq!(msg[16], 0, "AF_UNSPEC, so one dump covers both families");
    }

    #[test]
    fn the_default_route_request_asks_for_a_dump() {
        let msg = default_route_message(9);
        assert_eq!(msg.len(), NLMSG_HDR_LEN + RTMSG_LEN);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 28);
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_GETROUTE
        );
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert_eq!(u32::from_ne_bytes(msg[8..12].try_into().unwrap()), 9);
        assert_eq!(msg[16], 0, "AF_UNSPEC covers IPv4 and IPv6 in one dump");
        assert_eq!(msg[17], 0, "a default route has prefix length zero");
    }

    #[test]
    fn a_default_ipv4_gateway_is_reported() {
        let msg = newroute_default(AF_INET_U8, &[192, 0, 2, 1]);
        let batch = parse_route_dump(&msg);
        assert_eq!(
            batch.gateways,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]
        );
        assert!(!batch.done);
    }

    #[test]
    fn a_default_ipv6_gateway_is_reported() {
        let gateway = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
        let msg = newroute_default(AF_INET6_U8, &gateway.octets());
        assert_eq!(parse_route_dump(&msg).gateways, vec![IpAddr::V6(gateway)]);
    }

    #[test]
    fn a_route_without_a_gateway_is_not_reported() {
        let mut msg = newroute_default(AF_INET_U8, &[192, 0, 2, 1]);
        let a1 = NLMSG_HDR_LEN + RTMSG_LEN;
        msg[a1 + 2..a1 + 4].copy_from_slice(&RTA_OIF.to_ne_bytes());
        assert!(parse_route_dump(&msg).gateways.is_empty());
    }

    #[test]
    fn a_global_ipv4_address_is_reported() {
        let msg = newaddr(
            AF_INET_U8,
            RT_SCOPE_UNIVERSE,
            &[v4_attr(IFA_LOCAL, [192, 168, 1, 20])],
        );
        let batch = parse_addr_dump(&msg);
        assert_eq!(
            batch.addrs,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))]
        );
        assert!(!batch.done);
    }

    /// **`IFA_LOCAL` wins over `IFA_ADDRESS`.** On a point-to-point interface
    /// `IFA_ADDRESS` holds the *peer's* address, and a node that advertised it
    /// would be naming somebody else's host as a way to reach itself.
    #[test]
    fn the_local_address_wins_over_the_peer_address() {
        let msg = newaddr(
            AF_INET_U8,
            RT_SCOPE_UNIVERSE,
            &[
                v4_attr(IFA_ADDRESS, [10, 9, 9, 1]),
                v4_attr(IFA_LOCAL, [10, 9, 9, 2]),
            ],
        );
        assert_eq!(
            parse_addr_dump(&msg).addrs,
            vec![IpAddr::V4(Ipv4Addr::new(10, 9, 9, 2))]
        );
    }

    /// IPv6 carries no `IFA_LOCAL`, so `IFA_ADDRESS` is the address.
    #[test]
    fn a_global_ipv6_address_is_reported() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let msg = newaddr(
            AF_INET6_U8,
            RT_SCOPE_UNIVERSE,
            &[(IFA_ADDRESS, addr.octets().to_vec())],
        );
        assert_eq!(parse_addr_dump(&msg).addrs, vec![IpAddr::V6(addr)]);
    }

    /// Scope is what removes loopback and IPv6 link-local without either being
    /// special-cased. A link-local address is reachable from the link and
    /// nowhere else, so advertising one spends a peer's probe budget for
    /// certain failure.
    #[test]
    fn a_non_global_scope_is_not_a_candidate() {
        for scope in [253u8, 254, 200] {
            let msg = newaddr(AF_INET_U8, scope, &[v4_attr(IFA_LOCAL, [127, 0, 0, 1])]);
            assert!(
                parse_addr_dump(&msg).addrs.is_empty(),
                "scope {scope} was offered as a candidate"
            );
        }
    }

    /// A tentative address has not finished duplicate-address detection and may
    /// yet be withdrawn; a deprecated one must not be offered for new flows.
    #[test]
    fn tentative_and_deprecated_addresses_are_not_candidates() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        for flag in [IFA_F_TENTATIVE, IFA_F_DEPRECATED] {
            let msg = newaddr(
                AF_INET6_U8,
                RT_SCOPE_UNIVERSE,
                &[
                    (IFA_ADDRESS, addr.octets().to_vec()),
                    (IFA_FLAGS, flag.to_ne_bytes().to_vec()),
                ],
            );
            assert!(
                parse_addr_dump(&msg).addrs.is_empty(),
                "flag {flag:#x} was offered as a candidate"
            );
        }
    }

    #[test]
    fn several_messages_in_one_buffer_are_all_read() {
        let mut buf = newaddr(
            AF_INET_U8,
            RT_SCOPE_UNIVERSE,
            &[v4_attr(IFA_LOCAL, [192, 168, 1, 20])],
        );
        buf.extend_from_slice(&newaddr(
            AF_INET_U8,
            RT_SCOPE_UNIVERSE,
            &[v4_attr(IFA_LOCAL, [10, 0, 0, 3])],
        ));
        buf.extend_from_slice(&done());

        let batch = parse_addr_dump(&buf);
        assert_eq!(
            batch.addrs,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            ]
        );
        assert!(batch.done, "NLMSG_DONE was not noticed, so the dump loops");
    }

    /// **Bytes from the kernel are still parsed defensively.** A truncated or
    /// malformed dump must cost candidates, never the daemon — this is on the
    /// control path of a process carrying traffic for a whole aquifer.
    #[test]
    fn malformed_input_is_rejected_not_panicked_on() {
        let full = {
            let mut b = newaddr(
                AF_INET_U8,
                RT_SCOPE_UNIVERSE,
                &[v4_attr(IFA_LOCAL, [192, 168, 1, 20])],
            );
            b.extend_from_slice(&done());
            b
        };
        for cut in 0..full.len() {
            let _ = parse_addr_dump(&full[..cut]);
        }
        for byte in 0u8..=255 {
            let _ = parse_addr_dump(&[byte; 64]);
        }
        // A length field claiming more than arrived, and one claiming less
        // than a header — the two that walk a parser off the end or in circles.
        let mut lying = full.clone();
        lying[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(parse_addr_dump(&lying).addrs.is_empty());
        let mut zero = full.clone();
        zero[0..4].copy_from_slice(&0u32.to_ne_bytes());
        assert!(parse_addr_dump(&zero).addrs.is_empty());
    }
}
