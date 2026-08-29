// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Darwin syscall plumbing — the macOS counterpart to [`crate::sys`], and
//! subject to the same discipline (ADR-0003).
//!
//! Everything here is a thin, total wrapper over one syscall. The crate denies
//! `unsafe_code`; this module carries one of the two `allow`s, so the blast
//! radius of a memory-safety mistake is this file. Each block states its
//! argument.
//!
//! # What is *not* here
//!
//! Address assignment and routing. On Linux those are `ioctl`s and rtnetlink,
//! and `sys.rs` is 1 500 lines largely because of it. On macOS they are
//! `SIOCAIFADDR` and `PF_ROUTE` sockets, which would be a second module of
//! comparable size on the critical path of a packaging-heavy phase — so
//! [`crate::macos`] shells out to `ifconfig` and `route` instead, with the
//! reasoning recorded there. Phase 7 revisits it, because the mobile port
//! needs the same code behind `NEPacketTunnelProvider` anyway.
//!
//! What remains is what has no command-line equivalent: opening the `utun`
//! control socket, and reading the host's own addresses and routes.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::macos_wire::{parse_default_gateway, RT_MSGHDR_LEN};

/// The kernel control that vends `utun` interfaces.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

/// `RT_MSGHDR_LEN` is derived by hand in `macos_wire` so that the parser can
/// be tested on any host. This is where that derivation is checked against the
/// ABI it describes: a Darwin release that ever resized `rt_msghdr` fails to
/// compile here rather than mis-parsing every dump at run time.
const _: () = assert!(mem::size_of::<libc::rt_msghdr>() == RT_MSGHDR_LEN);

/// A `PF_SYSTEM` socket, the handle every `utun` operation goes through.
///
/// Unlike Linux there is no device node to open: the interface *is* the
/// socket, created by connecting this one to the `utun` kernel control.
pub(crate) fn utun_socket() -> io::Result<OwnedFd> {
    // SAFETY: `socket` with constant, valid arguments has no preconditions. It
    // returns -1 or an owned descriptor.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly created, open descriptor owned by nobody else,
    // so transferring ownership to `OwnedFd` cannot double-close.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Resolve the numeric id of the `com.apple.net.utun_control` kernel control.
///
/// The id is not a constant: it is assigned at boot and has to be asked for.
pub(crate) fn utun_control_id(fd: BorrowedFd<'_>) -> io::Result<u32> {
    // SAFETY: `ctl_info` is POD; zeroed is a valid instance, and the only field
    // the kernel reads is written below.
    let mut info: libc::ctl_info = unsafe { mem::zeroed() };
    // `ctl_name` is a fixed 96-byte buffer and the name is 27 bytes with its
    // NUL, so this cannot truncate — but the copy is bounded by the shorter of
    // the two rather than by the name's length, so it could not overrun even
    // if that ever changed.
    for (slot, byte) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
        #[allow(clippy::cast_possible_wrap)]
        {
            *slot = *byte as libc::c_char;
        }
    }

    // SAFETY: `fd` is an open `PF_SYSTEM` socket for the duration of the call,
    // and `info` is a live, uniquely borrowed `ctl_info` of exactly the size
    // `CTLIOCGINFO` reads and writes.
    let rc = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::CTLIOCGINFO,
            std::ptr::from_mut(&mut info),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.ctl_id)
}

/// Attach the socket to a `utun` interface, creating it.
///
/// `unit` is the *`sockaddr_ctl`* unit, which is one greater than the number
/// in the interface's name: unit 4 is `utun3`. **Unit 0 asks the kernel to
/// allocate the first free one**, which is what Karst does unless the operator
/// named a specific `utunN`.
pub(crate) fn utun_connect(fd: BorrowedFd<'_>, ctl_id: u32, unit: u32) -> io::Result<()> {
    let addr = libc::sockaddr_ctl {
        #[allow(clippy::cast_possible_truncation)]
        sc_len: mem::size_of::<libc::sockaddr_ctl>() as u8,
        #[allow(clippy::cast_possible_truncation)]
        sc_family: libc::AF_SYSTEM as u8,
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: ctl_id,
        sc_unit: unit,
        sc_reserved: [0; 5],
    };

    // SAFETY: `fd` is an open `PF_SYSTEM` socket for the duration of the call.
    // `addr` is a live, fully initialized `sockaddr_ctl` and the length passed
    // is exactly its size, so the kernel reads only bytes this frame owns. The
    // cast to `*const sockaddr` is the documented calling convention for every
    // address family.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(&addr).cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_ctl>()).unwrap_or(0),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The name the kernel gave the interface — `utun3`, and so on.
///
/// **This is the only way to learn it.** macOS does not accept a requested
/// name, so nothing downstream may assume the configured one; see
/// [`crate::TunConfig::name`].
pub(crate) fn utun_name(fd: BorrowedFd<'_>) -> io::Result<String> {
    // `IFNAMSIZ` plus room for the NUL the kernel writes.
    let mut buf = [0u8; crate::MAX_NAME_LEN + 1];
    let mut len = libc::socklen_t::try_from(buf.len()).unwrap_or(0);

    // SAFETY: `fd` is an open `PF_SYSTEM` socket connected to a `utun`
    // control. `buf` is a live, uniquely borrowed array and `len` is exactly
    // its length, so the kernel writes at most that many bytes into it; it
    // then overwrites `len` with how many it wrote.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            buf.as_mut_ptr().cast::<c_void>(),
            std::ptr::from_mut(&mut len),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let len = usize::try_from(len).unwrap_or(0).min(buf.len());
    let name = buf.get(..len).unwrap_or_default();
    // The length the kernel reports includes the terminating NUL.
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    Ok(String::from_utf8_lossy(name.get(..end).unwrap_or_default()).into_owned())
}

/// Put the descriptor into non-blocking mode, for a poll-driven event loop.
///
/// Linux passes `O_NONBLOCK` when opening `/dev/net/tun`; there is no open
/// here to pass it to, so it is set afterwards.
pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: `fd` is open for the duration of both calls; `F_GETFL` and
    // `F_SETFL` take and return an int and touch no memory the caller owns.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The kernel's index for a named interface.
pub(crate) fn interface_index(name: &str) -> io::Result<u32> {
    let c_name = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "interface name contains a NUL")
    })?;
    // SAFETY: `c_name` is a live, NUL-terminated C string for the duration of
    // the call, which is the function's only requirement. It returns 0 for an
    // unknown name and touches no other memory.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

/// Every global-scope unicast address this host currently holds.
///
/// # A gap worth stating
///
/// The Linux path filters out tentative and deprecated IPv6 addresses, which
/// rtnetlink reports directly. `getifaddrs(3)` does not carry those flags —
/// reading them needs `SIOCGIFAFLAG_IN6` and an `in6_ifreq` whose layout is
/// not worth guessing without a Mac to check it against. The cost of the gap
/// is a wasted probe against an address that has not finished duplicate
/// address detection, which AVEN already tolerates; it is **not** a
/// correctness problem, because an address that does not answer is simply not
/// selected. Closing it is Phase 7 work, alongside the `SIOCAIFADDR` port.
pub(crate) fn local_addresses() -> io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes one owned pointer through `head` and returns
    // -1 on failure without doing so. Nothing else is read or written.
    if unsafe { libc::getifaddrs(std::ptr::from_mut(&mut head)) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut out = Vec::new();
    let mut node = head;
    // The list is owned by libc until `freeifaddrs`, which runs below on every
    // path out of this loop — there is no `?` inside it for that reason.
    while !node.is_null() {
        // SAFETY: `node` is non-null and was produced by `getifaddrs`, so it
        // points at a live `ifaddrs` that stays valid until `freeifaddrs`. The
        // read copies the record rather than holding a reference into it.
        let entry = unsafe { *node };
        node = entry.ifa_next;

        // A down interface's addresses are not reachable, and a loopback one's
        // are not reachable *by a peer* — both are facts about the address
        // rather than policy, so they are dropped here.
        let flags = entry.ifa_flags;
        #[allow(clippy::cast_sign_loss)]
        let up = flags & (libc::IFF_UP as u32) != 0 && flags & (libc::IFF_RUNNING as u32) != 0;
        #[allow(clippy::cast_sign_loss)]
        let loopback = flags & (libc::IFF_LOOPBACK as u32) != 0;
        if !up || loopback || entry.ifa_addr.is_null() {
            continue;
        }

        // SAFETY: `ifa_addr` is non-null and points into the same allocation,
        // valid until `freeifaddrs`. Only `sa_family` is read here, which
        // every `sockaddr` has at the same offset by definition of the ABI.
        let family = libc::c_int::from(unsafe { (*entry.ifa_addr).sa_family });
        let addr = match family {
            libc::AF_INET => {
                // SAFETY: the kernel sets `sa_family` to `AF_INET` only for a
                // `sockaddr_in`, whose `sa_len` is its own size, so the whole
                // structure is within the allocation. `copy_from_sockaddr`
                // copies bytewise rather than dereferencing a cast pointer,
                // which is what makes the alignment of `ifa_addr` irrelevant.
                let sin: libc::sockaddr_in = unsafe { copy_from_sockaddr(entry.ifa_addr) };
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                // SAFETY: as above, for `AF_INET6` and `sockaddr_in6`.
                let sin6: libc::sockaddr_in6 = unsafe { copy_from_sockaddr(entry.ifa_addr) };
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        };

        if let Some(addr) = addr.filter(is_reachable) {
            out.push(addr);
        }
    }

    // SAFETY: `head` came from a successful `getifaddrs` and has not been freed
    // or modified; the loop above advanced a copy.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Copy a `sockaddr` out of a pointer into a properly aligned `T`.
///
/// **Bytewise, not a pointer cast and dereference.** `getifaddrs` hands back a
/// `*mut sockaddr`, which is aligned to 1; reading a `sockaddr_in` through a
/// cast of it is undefined behavior if the allocation happens not to be
/// 4-aligned, whatever libc does in practice today. Copying the bytes into a
/// local of the target type sidesteps the question entirely and costs 16 or 28
/// bytes of `memcpy` per address, once per enumeration.
///
/// # Safety
///
/// `sa` must point at a live, readable allocation of at least
/// `size_of::<T>()` bytes, and `T` must be a `sockaddr` variant that is valid
/// for any bit pattern. Both hold for the two call sites, which have already
/// matched on `sa_family`: the kernel sizes each `sockaddr` at exactly the
/// width of the structure that family names.
unsafe fn copy_from_sockaddr<T>(sa: *const libc::sockaddr) -> T {
    // SAFETY: `zeroed` is a valid instance of both `sockaddr_in` and
    // `sockaddr_in6`, and every byte of it is overwritten below.
    let mut out: T = unsafe { mem::zeroed() };
    // SAFETY: the caller guarantees `sa` is readable for `size_of::<T>()`
    // bytes; `out` is a live local of exactly that size, and a `*mut u8`
    // destination has no alignment requirement. The two cannot overlap — `out`
    // is a fresh stack local.
    unsafe {
        std::ptr::copy_nonoverlapping(
            sa.cast::<u8>(),
            std::ptr::from_mut(&mut out).cast::<u8>(),
            mem::size_of::<T>(),
        );
    }
    out
}

/// Whether a peer could plausibly reach this host at `addr`.
///
/// The same rule the Linux path applies through netlink scopes: loopback,
/// link-local, unspecified and multicast addresses are not candidates, and
/// their absence is a fact about the address rather than a policy choice. The
/// caller still has to exclude its *own overlay* addresses — this reports what
/// the host has, tunnel included.
fn is_reachable(addr: &IpAddr) -> bool {
    !(addr.is_loopback() || addr.is_unspecified() || addr.is_multicast())
        && match addr {
            IpAddr::V4(a) => !a.is_link_local() && !a.is_broadcast(),
            // `is_unicast_link_local` is unstable; the prefix is fe80::/10.
            IpAddr::V6(a) => a.segments().first().is_none_or(|s| s & 0xffc0 != 0xfe80),
        }
}

/// The next hop of the default route, if this host has one.
///
/// `sysctl(NET_RT_DUMP)` rather than a `PF_ROUTE` socket: a dump is a read of
/// a snapshot, where a routing socket is a subscription that has to be drained
/// and matched. The parsing is in [`crate::macos_wire`] so that it is tested
/// on every platform rather than only on a Mac.
pub(crate) fn default_gateway() -> io::Result<Option<IpAddr>> {
    // `AF_UNSPEC` in slot 3 covers IPv4 and IPv6 in one dump, exactly as the
    // netlink path does; slot 5 is the routing-table id, and 0 is the only one
    // macOS has.
    let mut mib: [libc::c_int; 6] = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];

    // Two calls: the first sizes the answer, the second reads it. The table can
    // grow between them, which is why the second failing with `ENOMEM` is
    // retried rather than reported.
    for _ in 0..4 {
        let mut len: libc::size_t = 0;
        // SAFETY: `mib` is a live array of exactly 6 ints and the count says
        // so. A null output pointer with a live `len` is the documented way to
        // ask `sysctl` for the size it would write, and it writes only `len`.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                libc::c_uint::try_from(mib.len()).unwrap_or(0),
                std::ptr::null_mut(),
                std::ptr::from_mut(&mut len),
                std::ptr::null_mut(),
                0,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if len == 0 {
            return Ok(None);
        }

        let mut buf = vec![0u8; len];
        // SAFETY: `buf` is a live, uniquely borrowed allocation of exactly
        // `len` bytes and `len` says so, so the kernel writes no further than
        // the allocation; it then overwrites `len` with how much it wrote.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                libc::c_uint::try_from(mib.len()).unwrap_or(0),
                buf.as_mut_ptr().cast::<c_void>(),
                std::ptr::from_mut(&mut len),
                std::ptr::null_mut(),
                0,
            )
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            // The table grew between sizing and reading. Ask again.
            if error.raw_os_error() == Some(libc::ENOMEM) {
                continue;
            }
            return Err(error);
        }
        return Ok(parse_default_gateway(
            buf.get(..len.min(buf.len())).unwrap_or_default(),
        ));
    }
    // Four consecutive races is not a transient. Report no gateway rather than
    // looping: the caller treats that as "no port mapping to ask for", which
    // is the correct behavior when the routing table cannot be read.
    Ok(None)
}
