// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Batched socket syscalls — the second of the two modules ADR-0003 permits
//! `unsafe` in.
//!
//! `sendmmsg`, `recvmmsg` and UDP segmentation offload have no safe equivalent
//! in `std`, and the datapath is syscall-bound (PLAN.md §3.4): one `sendto` per
//! packet at ~46,000 packets per second, with 63% of the profile in the kernel.
//! These three calls are what remove that.
//!
//! Everything here is a thin wrapper over one syscall, and every block states
//! its argument. The crate denies `unsafe_code`; this module carries the only
//! `allow`, so the blast radius of a memory-safety mistake is this file.
//!
//! # The shape of the danger
//!
//! `mmsghdr` is a structure of raw pointers into buffers the caller owns. The
//! kernel writes through those pointers. Every function below therefore takes
//! the buffers by reference for exactly the duration of the call, and the
//! pointer arrays are built inside the same function so they cannot outlive
//! what they point at. Nothing here stores a pointer.

#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd};

/// Datagrams per batched syscall.
///
/// 32 is enough to amortise the syscall almost completely — the marginal gain
/// past it is small, and every slot costs a `sockaddr_storage` (128 B) plus an
/// `mmsghdr` in a per-thread buffer that is allocated once.
pub const BATCH: usize = 32;

/// `UDP_SEGMENT` — the socket option carrying a GSO segment size.
///
/// Not in `libc` for all targets, and it is a stable part of the UDP ABI.
const UDP_SEGMENT: libc::c_int = 103;

/// A control-message buffer with the alignment `cmsghdr` requires.
///
/// **A bare `[u8; N]` is not sufficient**, and the difference is undefined
/// behaviour rather than a warning: `CMSG_FIRSTHDR` returns a `*mut cmsghdr`
/// into this buffer, and writing through a pointer that is not 8-byte aligned
/// is UB on every target Karst builds for. A `[u8; 64]` happened to work in
/// release and aborted under debug assertions — which is how this was found.
#[repr(C, align(8))]
struct ControlBuf([u8; 64]);

impl ControlBuf {
    const fn new() -> Self {
        Self([0u8; 64])
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
}

/// Narrow an `AF_*` constant to the address-family field.
///
/// The constants are `c_int` and the field is `u16`; every family Karst uses is
/// a small positive number, so `try_from` cannot fail — but saying so is better
/// than an `as` cast that would silently truncate if that ever changed.
fn sa_family(af: libc::c_int) -> libc::sa_family_t {
    libc::sa_family_t::try_from(af).unwrap_or(0)
}

/// Convert a `SocketAddr` into the kernel's representation.
///
/// Returns the storage and the length the kernel expects for that family;
/// passing `size_of::<sockaddr_storage>()` instead would be accepted for
/// sending but is wrong, and `sendmsg` on some kernels validates it.
fn to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: `sockaddr_storage` is a plain-old-data C aggregate whose fields
    // are all integers and arrays; an all-zero value is a valid instance, and
    // the family field below then makes it well-formed.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: sa_family(libc::AF_INET),
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `sockaddr_storage` is defined to be large enough and
            // aligned for every socket address family, `sockaddr_in` included,
            // which is the entire purpose of the type. Both are POD, the
            // regions do not overlap, and exactly `size_of::<sockaddr_in>()`
            // bytes are written into a strictly larger destination.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::from_ref(&sin).cast::<u8>(),
                    std::ptr::from_mut(&mut storage).cast::<u8>(),
                    mem::size_of::<libc::sockaddr_in>(),
                );
            }
            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: sa_family(libc::AF_INET6),
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: as above, for `sockaddr_in6`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::from_ref(&sin6).cast::<u8>(),
                    std::ptr::from_mut(&mut storage).cast::<u8>(),
                    mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, libc::socklen_t::try_from(len).unwrap_or(0))
}

/// Convert the kernel's representation back into a `SocketAddr`.
///
/// Returns `None` for a family Karst does not use, rather than guessing — a
/// mis-parsed source address would be attributed to the wrong peer.
fn from_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
            // SAFETY: the family field says this storage holds a `sockaddr_in`.
            // Both are POD and non-overlapping, and the read is of exactly
            // `size_of::<sockaddr_in>()` bytes from a strictly larger source.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::from_ref(storage).cast::<u8>(),
                    std::ptr::from_mut(&mut sin).cast::<u8>(),
                    mem::size_of::<libc::sockaddr_in>(),
                );
            }
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let mut sin6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            // SAFETY: as above, for `sockaddr_in6`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::from_ref(storage).cast::<u8>(),
                    std::ptr::from_mut(&mut sin6).cast::<u8>(),
                    mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            // Canonicalised here as well as in `recv_from`, because these are
            // two independent receive paths into the same daemon and an address
            // that took the batched one must not be a different value from the
            // same address that took the other.
            Some(crate::canonical(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            ))))
        }
        _ => None,
    }
}

/// Send up to `BATCH` datagrams in one syscall.
///
/// Returns how many the kernel accepted. A short count is **normal**, not an
/// error: the caller must retry the remainder, exactly as with a short write.
pub(crate) fn send_batch(
    fd: BorrowedFd<'_>,
    datagrams: &[(&[u8], SocketAddr)],
) -> io::Result<usize> {
    if datagrams.is_empty() {
        return Ok(0);
    }
    let n = datagrams.len().min(BATCH);

    // Every array is local to this call, so no pointer built here can outlive
    // the buffer it addresses.
    let mut addrs = [(unsafe { mem::zeroed::<libc::sockaddr_storage>() }, 0); BATCH];
    let mut iovecs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; BATCH];
    // SAFETY: `mmsghdr` is POD; zeroed is a valid instance, and every field
    // that matters is written below.
    let mut msgs: [libc::mmsghdr; BATCH] = unsafe { mem::zeroed() };

    for i in 0..n {
        let Some((payload, addr)) = datagrams.get(i) else {
            break;
        };
        let Some(slot) = addrs.get_mut(i) else { break };
        *slot = to_sockaddr(*addr);

        let Some(iov) = iovecs.get_mut(i) else { break };
        // The cast to `*mut` is required by the C signature; `sendmsg` does not
        // write through `msg_iov` and the buffer stays borrowed as `&[u8]`.
        iov.iov_base = payload.as_ptr().cast::<libc::c_void>().cast_mut();
        iov.iov_len = payload.len();

        let (Some(msg), Some(slot), Some(iov)) =
            (msgs.get_mut(i), addrs.get_mut(i), iovecs.get_mut(i))
        else {
            break;
        };
        msg.msg_hdr.msg_name = std::ptr::from_mut(&mut slot.0).cast::<libc::c_void>();
        msg.msg_hdr.msg_namelen = slot.1;
        msg.msg_hdr.msg_iov = std::ptr::from_mut(iov);
        msg.msg_hdr.msg_iovlen = 1;
    }

    // SAFETY: `fd` is open for the call. `msgs` holds `n` initialised headers,
    // each pointing at an `iovec` and a `sockaddr_storage` in the arrays above,
    // all of which outlive this statement. The kernel reads through those
    // pointers and writes only `msg_len` back into `msgs`. `n <= BATCH` is the
    // array length, so the vlen argument cannot over-read.
    let sent = unsafe {
        libc::sendmmsg(
            fd.as_raw_fd(),
            msgs.as_mut_ptr(),
            u32::try_from(n).unwrap_or(0),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(sent).unwrap_or(0))
}

/// One received datagram: how many bytes, and from where.
#[derive(Debug, Clone, Copy)]
pub struct Received {
    /// Payload length.
    pub len: usize,
    /// Source address.
    pub from: SocketAddr,
}

/// Receive up to `BATCH` datagrams in one syscall.
///
/// `buffers` must have at least `BATCH` slots, each at least one datagram long;
/// `out` receives one entry per datagram. Returns how many arrived.
///
/// A datagram larger than its buffer is **truncated**, which is the correct
/// outcome: it will then fail its fragment MAC or its AEAD.
pub(crate) fn recv_batch(
    fd: BorrowedFd<'_>,
    buffers: &mut [[u8; super::MAX_DATAGRAM]],
    out: &mut Vec<Received>,
) -> io::Result<usize> {
    let n = buffers.len().min(BATCH);
    if n == 0 {
        return Ok(0);
    }

    let mut addrs = [(unsafe { mem::zeroed::<libc::sockaddr_storage>() }, 0u32); BATCH];
    let mut iovecs = [libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; BATCH];
    // SAFETY: `mmsghdr` is POD and zeroed is valid; the fields used are set below.
    let mut msgs: [libc::mmsghdr; BATCH] = unsafe { mem::zeroed() };

    for i in 0..n {
        let Some(buf) = buffers.get_mut(i) else { break };
        let len = buf.len();
        let base = buf.as_mut_ptr().cast::<libc::c_void>();
        let Some(iov) = iovecs.get_mut(i) else { break };
        iov.iov_base = base;
        iov.iov_len = len;

        let (Some(msg), Some(addr), Some(iov)) =
            (msgs.get_mut(i), addrs.get_mut(i), iovecs.get_mut(i))
        else {
            break;
        };
        addr.1 = u32::try_from(mem::size_of::<libc::sockaddr_storage>()).unwrap_or(0);
        msg.msg_hdr.msg_name = std::ptr::from_mut(&mut addr.0).cast::<libc::c_void>();
        msg.msg_hdr.msg_namelen = addr.1;
        msg.msg_hdr.msg_iov = std::ptr::from_mut(iov);
        msg.msg_hdr.msg_iovlen = 1;
    }

    // `MSG_WAITFORONE` is **not optional**. Without it `recvmmsg` blocks until
    // all `vlen` slots are filled, so a socket carrying anything less than a
    // full batch stalls: a ping every second against 32 slots waits for 32
    // pings. `SO_RCVTIMEO` does not rescue it either — that governs the wait
    // for the *first* datagram only.
    //
    // The failure this caused was invisible in unit tests (they eventually
    // timed out and returned what had accumulated, merely running slowly) and
    // total on a real link: the handshake completed only because
    // retransmissions eventually accumulated 32 datagrams, and no data ever
    // flowed at all. See PLAN.md §3.4.
    //
    // SAFETY: `fd` is open for the call. Each of the `n` headers points at a
    // distinct buffer from `buffers` and a distinct `sockaddr_storage`, all
    // borrowed mutably for this statement and outliving it. The kernel writes
    // at most `iov_len` bytes into each buffer — the true length of the slice —
    // and at most `msg_namelen` into each address.
    let got = unsafe {
        libc::recvmmsg(
            fd.as_raw_fd(),
            msgs.as_mut_ptr(),
            u32::try_from(n).unwrap_or(0),
            libc::MSG_WAITFORONE,
            std::ptr::null_mut(),
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let got = usize::try_from(got).unwrap_or(0).min(n);

    out.clear();
    for i in 0..got {
        let (Some(msg), Some(addr)) = (msgs.get(i), addrs.get(i)) else {
            break;
        };
        // A source family we do not use cannot be attributed to a peer, so the
        // datagram is dropped rather than guessed at.
        if let Some(from) = from_sockaddr(&addr.0) {
            out.push(Received {
                len: usize::try_from(msg.msg_len).unwrap_or(0),
                from,
            });
        }
    }
    Ok(out.len())
}

/// Send several equal-sized datagrams as one segmented write — UDP GSO.
///
/// `payload` is the concatenation of datagrams that are each exactly
/// `segment_size` bytes, except the last which may be shorter. The kernel (or
/// the NIC) splits it, so one syscall emits many datagrams.
///
/// # Errors
/// Any `sendmsg` failure. `EIO` or `ENOBUFS` typically means the path does not
/// support segmentation; callers should fall back to unsegmented sending rather
/// than treat it as fatal.
pub(crate) fn send_segmented(
    fd: BorrowedFd<'_>,
    payload: &[u8],
    segment_size: u16,
    to: SocketAddr,
) -> io::Result<usize> {
    let (mut addr, addr_len) = to_sockaddr(to);
    let mut iov = libc::iovec {
        // Cast to `*mut` for the C signature; `sendmsg` does not write here.
        iov_base: payload.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: payload.len(),
    };

    // The control message carries one `u16` segment size. `CMSG_SPACE` gives
    // the buffer size including alignment padding.
    // SAFETY: `CMSG_SPACE` is a pure arithmetic macro over its argument.
    let space = unsafe { libc::CMSG_SPACE(u32::try_from(mem::size_of::<u16>()).unwrap_or(2)) };
    let mut control = ControlBuf::new();
    if usize::try_from(space).unwrap_or(usize::MAX) > control.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control buffer too small for UDP_SEGMENT",
        ));
    }

    // SAFETY: `msghdr` is POD; zeroed is valid and every field used is set here.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = std::ptr::from_mut(&mut addr).cast::<libc::c_void>();
    msg.msg_namelen = addr_len;
    msg.msg_iov = std::ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = usize::try_from(space).unwrap_or(0);

    // SAFETY: `msg_control` points at `control`, which is at least `space`
    // bytes — checked above — so `CMSG_FIRSTHDR` returns a pointer within it or
    // null. The write below goes through that pointer only after a null check,
    // and writes exactly the two bytes `CMSG_LEN` accounts for.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::from_ref(&msg));
        if cmsg.is_null() {
            return Err(io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = usize::try_from(libc::CMSG_LEN(
            u32::try_from(mem::size_of::<u16>()).unwrap_or(2),
        ))
        .unwrap_or(0);
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(&segment_size).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            mem::size_of::<u16>(),
        );
    }

    // SAFETY: `fd` is open for the call; `msg` and everything it points at —
    // the address, the iovec, the payload and the control buffer — are borrowed
    // for this statement and outlive it. `sendmsg` reads through them and
    // writes nothing back.
    let sent = unsafe { libc::sendmsg(fd.as_raw_fd(), std::ptr::from_ref(&msg), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(sent).unwrap_or(0))
}

// ── UDP GRO is deliberately absent ──────────────────────────────────────────
//
// `UDP_GRO` is the receive-side counterpart of `UDP_SEGMENT`, and enabling it
// looks like a one-line `setsockopt`. It is not, and the difference destroys
// the datapath.
//
// With GRO on, the kernel **coalesces several datagrams into one buffer** and
// reports the original segment size in a `UDP_GRO` control message. A receiver
// that does not read that cmsg gets one oversized buffer where it expected one
// datagram, hands it to the parser, and drops everything.
//
// That is not hypothetical: it was enabled here, every unit test passed —
// loopback with light traffic never coalesces — and two real hosts went to
// **100% packet loss** the moment the tunnel came up. See PLAN.md §3.4.
//
// GRO therefore waits for `recv_batch` to request and parse control messages
// and split coalesced buffers itself. Until then the option stays off, because
// a switch that silently corrupts the datapath is worse than a missing feature.
