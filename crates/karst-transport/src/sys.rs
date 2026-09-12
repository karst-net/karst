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
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};

use crate::{Received, BATCH};

/// `UDP_SEGMENT` — the socket option carrying a GSO segment size.
///
/// Not in `libc` for all targets, and it is a stable part of the UDP ABI.
const UDP_SEGMENT: libc::c_int = 103;

/// `UDP_GRO` — the receive-side counterpart of `UDP_SEGMENT`. Same "not in
/// `libc`, stable UDP ABI" note. See the module doc's GRO section for what
/// this actually does and why enabling it needs [`recv_batch`]'s cmsg
/// handling below, not just this `setsockopt`.
const UDP_GRO: libc::c_int = 104;

/// Best-effort: turn on `UDP_GRO` for `fd`.
///
/// Callers ignore the error deliberately. An old kernel (pre-5.0) or a
/// restricted sandbox just leaves the option off, `recvmmsg` never gets a
/// `UDP_GRO` cmsg back, and every call to [`recv_batch`] falls through to
/// exactly the pre-GRO one-segment-per-slot behavior — that silence is the
/// fallback, not an error a caller needs to react to.
pub(crate) fn enable_gro(fd: BorrowedFd<'_>) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `value` points at `one`, a live local for the duration of this
    // call, and `len` is exactly `size_of_val(&one)`.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_UDP,
            UDP_GRO,
            std::ptr::from_ref(&one).cast(),
            libc::socklen_t::try_from(mem::size_of_val(&one)).unwrap_or(0),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Where in a coalesced `UDP_GRO` read each segment starts, and how long it
/// is — `segment_size` bytes each, except a shorter final one.
///
/// Pure and `unsafe`-free on purpose: this is the logic a real coalesced
/// kernel read exercises, made independently testable rather than relying on
/// a test environment actually producing one (loopback under light load
/// never does — see this module's GRO note).
///
/// `segment_size == 0` is treated as "no valid segmentation" (one segment
/// covering the whole read) rather than looping forever; a real `UDP_GRO`
/// cmsg never reports zero, but this function does not trust that a raw
/// `u16` off the wire.
fn gro_segments(total_len: usize, segment_size: usize) -> impl Iterator<Item = (usize, usize)> {
    let step = if segment_size == 0 { total_len.max(1) } else { segment_size };
    (0..total_len).step_by(step).map(move |offset| (offset, step.min(total_len - offset)))
}

/// Read `UDP_GRO`'s segment-size cmsg out of a just-completed `recvmsg`, per
/// `udp(7)`: a `u16` giving the size of every segment but (possibly) the
/// last in the buffer that call just filled.
///
/// `None` means no GRO cmsg was present — the read was one ordinary,
/// uncoalesced datagram (or the kernel doesn't support `UDP_GRO` at all),
/// and the caller should treat the whole buffer as one segment.
fn gro_segment_size(msg: &libc::msghdr) -> Option<usize> {
    // SAFETY: `msg` was just filled in by a successful `recvmmsg` on a
    // control buffer this function only reads from; `CMSG_FIRSTHDR`/
    // `CMSG_NXTHDR`/`CMSG_DATA` are the standard, bounds-respecting way to
    // walk it and never step outside `msg.msg_control`'s `msg.msg_controllen`
    // bytes.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == UDP_GRO {
                let data = libc::CMSG_DATA(cmsg);
                let mut size = [0u8; 2];
                size.copy_from_slice(std::slice::from_raw_parts(data, 2));
                return Some(u16::from_ne_bytes(size) as usize);
            }
            cmsg = libc::CMSG_NXTHDR(std::ptr::from_ref(msg).cast_mut(), cmsg);
        }
    }
    None
}

/// A control-message buffer with the alignment `cmsghdr` requires.
///
/// **A bare `[u8; N]` is not sufficient**, and the difference is undefined
/// behavior rather than a warning: `CMSG_FIRSTHDR` returns a `*mut cmsghdr`
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
            // canonicalized here as well as in `recv_from`, because these are
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

/// Bind a UDP socket with `SO_REUSEPORT` set before `bind` — karst-net/karst#118's
/// multi-reader receive scaling.
///
/// `std::net::UdpSocket::bind` has no way to reach this: the option has to be
/// set between `socket(2)` and `bind(2)`, and the standard library does both
/// in one call with no seam to hook a `setsockopt` into. Every socket that
/// binds the same port with this flag joins one reuseport group, and the
/// kernel hashes an inbound datagram across the group by its 4-tuple — which
/// in practice means by source, since the destination side is this one fixed
/// `(addr, port)` for every member. A peer's traffic therefore lands on the
/// same socket for as long as its own address does, which covers the
/// ordinary case of one NAT binding; a roaming peer whose address changes
/// mid-session may land on a different member afterward, same as it may
/// migrate `SO_REUSEPORT` groups in any other multi-reader design.
///
/// # Errors
/// Any `socket`, `setsockopt` or `bind` failure.
pub(crate) fn bind_reuseport(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let family = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: `socket` takes three integers and returns a fresh descriptor or
    // -1; no pointers are involved.
    let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor this function owns and has handed to
    // nothing else yet — exactly `from_raw_fd`'s contract. Held as `OwnedFd`
    // so an early return below closes it instead of leaking it.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let one: libc::c_int = 1;
    // SAFETY: `value` points at `one`, a live local for the duration of this
    // call, and `len` is exactly `size_of_val(&one)`, so the kernel reads no
    // more than what is there.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            std::ptr::from_ref(&one).cast(),
            libc::socklen_t::try_from(mem::size_of_val(&one)).unwrap_or(0),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // Best-effort, ignored deliberately — see `enable_gro`'s doc comment.
    let _ = enable_gro(fd.as_fd());

    let (storage, len) = to_sockaddr(addr);
    // SAFETY: `storage` is a live `sockaddr_storage` on this frame, sized and
    // aligned for every family per its own contract, and `len` is exactly what
    // `to_sockaddr` wrote into it — either a `sockaddr_in` or `sockaddr_in6`
    // prefix — so `bind` reads no further into `storage` than what is
    // actually initialized.
    let rc = unsafe { libc::bind(fd.as_raw_fd(), std::ptr::from_ref(&storage).cast(), len) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `fd` is a live, uniquely owned, now-bound UDP socket with no
    // other handle anywhere — `into_raw_fd` transfers that one ownership to
    // the `UdpSocket` this returns, which is `from_raw_fd`'s contract.
    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd.into_raw_fd()) })
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

    // SAFETY: `fd` is open for the call. `msgs` holds `n` initialized headers,
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

/// Receive up to `BATCH` datagrams in one syscall.
///
/// `buffers` must have at least `BATCH` slots, each at least one datagram long;
/// `out` receives one entry per **datagram**, which on this platform can
/// exceed `BATCH` — see [`Received`]'s doc comment on `slot`/`offset`: with
/// `UDP_GRO` enabled (best-effort, see [`enable_gro`]), one physical slot can
/// hold several coalesced datagrams from the same flow. Returns `out.len()`.
///
/// A datagram larger than its buffer is **truncated**, which is the correct
/// outcome: it will then fail its fragment MAC or its AEAD.
pub(crate) fn recv_batch(
    fd: BorrowedFd<'_>,
    buffers: &mut [[u8; super::MAX_GRO_READ]],
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
    // One control buffer per slot: `UDP_GRO`'s segment-size cmsg is
    // per-message, so `recvmmsg` needs somewhere to put each message's own,
    // not one shared buffer every slot would overwrite the last one's into.
    let mut ctrls: [ControlBuf; BATCH] = std::array::from_fn(|_| ControlBuf::new());
    // SAFETY: `mmsghdr` is POD and zeroed is valid; the fields used are set below.
    let mut msgs: [libc::mmsghdr; BATCH] = unsafe { mem::zeroed() };

    for i in 0..n {
        let Some(buf) = buffers.get_mut(i) else { break };
        let len = buf.len();
        let base = buf.as_mut_ptr().cast::<libc::c_void>();
        let Some(iov) = iovecs.get_mut(i) else { break };
        iov.iov_base = base;
        iov.iov_len = len;

        let (Some(msg), Some(addr), Some(iov), Some(ctrl)) =
            (msgs.get_mut(i), addrs.get_mut(i), iovecs.get_mut(i), ctrls.get_mut(i))
        else {
            break;
        };
        addr.1 = u32::try_from(mem::size_of::<libc::sockaddr_storage>()).unwrap_or(0);
        msg.msg_hdr.msg_name = std::ptr::from_mut(&mut addr.0).cast::<libc::c_void>();
        msg.msg_hdr.msg_namelen = addr.1;
        msg.msg_hdr.msg_iov = std::ptr::from_mut(iov);
        msg.msg_hdr.msg_iovlen = 1;
        msg.msg_hdr.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_hdr.msg_controllen = ctrl.len();
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
    // distinct buffer from `buffers`, a distinct `sockaddr_storage` and a
    // distinct `ControlBuf`, all borrowed mutably for this statement and
    // outliving it. The kernel writes at most `iov_len` bytes into each
    // buffer, at most `msg_namelen` into each address, and at most
    // `msg_controllen` into each control buffer — the true sizes of each.
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
        let Some(from) = from_sockaddr(&addr.0) else {
            continue;
        };
        let total = usize::try_from(msg.msg_len).unwrap_or(0);
        // No cmsg (`None`), or a nonsensical zero segment size: either way
        // there is exactly one segment, the whole read — `gro_segments`
        // already produces that same single-entry result for `size >= total`
        // too, so a real, undersized `size` is the only case worth a
        // distinct branch.
        match gro_segment_size(&msg.msg_hdr).filter(|&size| size > 0) {
            Some(size) => {
                for (offset, len) in gro_segments(total, size) {
                    out.push(Received { len, from, slot: i, offset });
                }
            }
            None => out.push(Received { len: total, from, slot: i, offset: 0 }),
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

// ── RFC 8781 PREF64 discovery ───────────────────────────────────────────────

/// `ICMP6_FILTER`, from RFC 3542 §3.2. Not in `libc` for every target, and it
/// is a stable part of the `ICMPv6` socket ABI.
const ICMP6_FILTER: libc::c_int = 1;
/// `ND_ROUTER_SOLICIT` and `ND_ROUTER_ADVERT` — RFC 4861 §4.1, §4.2.
const ND_ROUTER_SOLICIT: u8 = 133;
const ND_ROUTER_ADVERT: u8 = 134;
/// RFC 4861 §4: every Neighbour Discovery message is sent with a hop limit of
/// 255 and refused on receipt if it arrives with anything less. That single
/// rule is what makes these messages un-spoofable from off-link, and it is the
/// only authentication `PREF64` has.
const ND_HOP_LIMIT: libc::c_int = 255;

/// A raw `ICMPv6` socket that solicits routers and reads their advertisements.
///
/// **Opening this needs `CAP_NET_RAW`, and not having it is an ordinary
/// outcome.** `karstd` wants `CAP_NET_ADMIN` for a TUN device and nothing more,
/// and in userspace mode it runs with an empty capability set — so this is
/// opportunistic. A caller that cannot open one falls back to RFC 7050, which
/// needs no privilege at all.
#[derive(Debug)]
pub struct RouterSocket {
    fd: std::os::fd::OwnedFd,
}

impl RouterSocket {
    /// Open the socket and filter it down to Router Advertisements.
    ///
    /// # Errors
    /// [`io::ErrorKind::PermissionDenied`] without `CAP_NET_RAW`, which callers
    /// should treat as "this mechanism is unavailable" rather than as a fault.
    pub fn open() -> io::Result<Self> {
        // SAFETY: `socket` takes three integers and returns a file descriptor
        // or -1. No pointers are involved.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMPV6,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor this function owns and has not
        // handed to anything else, which is exactly `from_raw_fd`'s contract.
        let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let socket = Self { fd };

        // **Block every ICMPv6 type, then pass only Router Advertisements.**
        // Without this the socket receives every ICMPv6 message the host sees —
        // every ping, every unreachable, every neighbour solicitation — and the
        // read loop below would spend its timeout discarding them.
        //
        // **A set bit *blocks*.** RFC 3542 §3.2 defines `SETBLOCKALL` as all
        // ones and `SETPASS` as *clearing* a bit, which reads backwards to
        // anyone who assumes a filter lists what it admits. Written the other
        // way round this passed every ICMPv6 type except the one type it
        // wanted, and no unit test could see it: the option parser was correct,
        // the solicitation went out correctly, and the answer was dropped by
        // the socket before anything in this crate looked at it. GitHub issue [#57](https://github.com/karst-net/karst/issues/57).
        let mut filter = [u32::MAX; 8];
        let bit = u32::from(ND_ROUTER_ADVERT);
        if let Some(word) = filter.get_mut((bit >> 5) as usize) {
            *word &= !(1u32 << (bit & 31));
        }
        socket.set_opt(
            libc::IPPROTO_ICMPV6,
            ICMP6_FILTER,
            std::ptr::from_ref(&filter).cast(),
            std::mem::size_of_val(&filter),
        )?;

        // RFC 4861 §4.1: a Router Solicitation is sent with hop limit 255.
        let hops = ND_HOP_LIMIT;
        socket.set_opt(
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            std::ptr::from_ref(&hops).cast(),
            std::mem::size_of_val(&hops),
        )?;
        Ok(socket)
    }

    /// One `setsockopt`, with the length the caller measured.
    fn set_opt(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: *const libc::c_void,
        len: usize,
    ) -> io::Result<()> {
        // SAFETY: `value` points at a live local in the caller's frame for the
        // duration of this call, and `len` is `size_of_val` of that same local,
        // so the kernel reads exactly what is there and nothing beyond it.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                level,
                name,
                value,
                libc::socklen_t::try_from(len).unwrap_or(0),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send a Router Solicitation out of one interface — RFC 4861 §4.1.
    ///
    /// Addressed to `ff02::2`, the all-routers link-local multicast group.
    /// `interface` is a kernel interface index; a link-local destination is
    /// ambiguous without one, which is what the scope id carries.
    ///
    /// The `ICMPv6` checksum is left zero on purpose: for `IPPROTO_ICMPV6` the
    /// kernel computes it, and RFC 3542 §3.1 requires that it does.
    ///
    /// # Errors
    /// Any `sendto` failure. `ENETUNREACH` on an interface with no IPv6 is
    /// ordinary and means only that this interface has no router to ask.
    pub fn solicit(&self, interface: u32) -> io::Result<()> {
        // Type, code, checksum, then four reserved bytes. No source
        // link-layer option: it is optional (§4.1), and omitting it keeps this
        // free of any need to know the interface's hardware address.
        let message = [ND_ROUTER_SOLICIT, 0, 0, 0, 0, 0, 0, 0];
        let all_routers =
            SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2), 0, 0, interface);
        let (addr, addr_len) = to_sockaddr(SocketAddr::V6(all_routers));
        // SAFETY: `message` and `addr` are live locals for the duration of the
        // call, and both lengths are of those same locals. `sendto` reads
        // through the pointers and writes through neither.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
                std::ptr::from_ref(&addr).cast(),
                addr_len,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read one Router Advertisement, or time out.
    ///
    /// Returns the `ICMPv6` message, starting at the type byte — which is what
    /// [`crate::Nat64Prefix::from_router_advertisement`] parses. The IPv6 header
    /// is not included: `AF_INET6` raw sockets deliver the payload alone.
    ///
    /// # Errors
    /// [`io::ErrorKind::WouldBlock`] or [`io::ErrorKind::TimedOut`] when no
    /// advertisement arrives inside `timeout`; otherwise any `recv` failure.
    pub fn recv_advertisement(
        &self,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> io::Result<usize> {
        let tv = libc::timeval {
            tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
        };
        self.set_opt(
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&tv).cast(),
            std::mem::size_of_val(&tv),
        )?;
        // SAFETY: the kernel writes at most `buf.len()` bytes through this
        // pointer, and `buf` is a live mutable borrow for the whole call.
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(usize::try_from(n).unwrap_or(0))
    }
}

// ── UDP GRO ──────────────────────────────────────────────────────────────────
//
// `UDP_GRO` is the receive-side counterpart of `UDP_SEGMENT`. Enabling it
// looks like a one-line `setsockopt`, and once was exactly that here — every
// unit test passed (loopback with light traffic never coalesces) and two
// real hosts went to **100% packet loss** the moment the tunnel came up. See
// PLAN.md §3.4. The bug: with GRO on, the kernel **coalesces several
// datagrams into one buffer** and reports the original segment size in a
// `UDP_GRO` control message; a receiver that does not read that cmsg gets
// one oversized buffer where it expected one datagram, hands it to the
// parser, and drops everything.
//
// `recv_batch` above now requests that cmsg (a per-slot `ControlBuf`) and
// splits every coalesced read via `gro_segments`, so `enable_gro` is safe to
// call unconditionally — measured on the real `turing`↔`lovelace` link at
// 32% less receive-side CPU for comparable throughput versus `recvmmsg`
// alone; see `docs/measurements/udp-gro-2026-09-12.md`.

#[cfg(test)]
mod gro_tests {
    use super::gro_segments;

    #[test]
    fn an_exact_multiple_splits_evenly() {
        let segments: Vec<_> = gro_segments(300, 100).collect();
        assert_eq!(segments, vec![(0, 100), (100, 100), (200, 100)]);
    }

    #[test]
    fn a_short_final_segment_is_preserved() {
        let segments: Vec<_> = gro_segments(250, 100).collect();
        assert_eq!(segments, vec![(0, 100), (100, 100), (200, 50)]);
    }

    #[test]
    fn a_segment_size_covering_the_whole_read_is_one_segment() {
        let segments: Vec<_> = gro_segments(80, 1336).collect();
        assert_eq!(segments, vec![(0, 80)]);
    }

    #[test]
    fn a_zero_segment_size_does_not_loop_forever() {
        // A real `UDP_GRO` cmsg never reports this, but the raw `u16` off the
        // wire is not trusted to promise that.
        let segments: Vec<_> = gro_segments(80, 0).collect();
        assert_eq!(segments, vec![(0, 80)]);
    }

    #[test]
    fn an_empty_read_yields_no_segments() {
        assert_eq!(gro_segments(0, 100).count(), 0);
    }
}
