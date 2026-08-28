// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The macOS byte formats — parsed portably, and therefore tested everywhere.
//!
//! Two things macOS hands Karst are pure byte layouts: the four-byte address
//! family every `utun` frame carries, and the `PF_ROUTE` dump that
//! `sysctl(NET_RT_DUMP)` returns. Both are easy to get wrong in ways no
//! compiler catches — an endianness assumption, a `sockaddr` walked with the
//! wrong stride, a header size off by the width of a padding word — and both
//! fail silently: the first as every packet dropped by the filter, the second
//! as a host that reports no default gateway and quietly never asks its router
//! for a port mapping.
//!
//! So they live here, in a module compiled on **every** platform, rather than
//! inside `macos.rs` where they would only ever be exercised by a macOS runner.
//! The tests below run on the same Linux job that runs the rest of the suite,
//! which is what makes a mistake in either format a red build on the commit
//! that introduced it rather than one found on a Mac three weeks later.
//!
//! Nothing here calls a syscall; `sys_macos` does that, and it is the only
//! module on this path permitted `unsafe`.

// `macos.rs` and `sys_macos.rs` are the only callers, so on any other platform
// every item below is unused. That is the arrangement working as intended —
// the tests are the consumer there — and silencing the warning is what buys
// the coverage.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Bytes of address family prefixed to every `utun` frame.
pub(crate) const AF_HEADER_LEN: usize = 4;

/// macOS `AF_INET` and `AF_INET6`.
///
/// **Hardcoded rather than taken from `libc`, deliberately.** This module
/// compiles on Linux so its tests can run there, and Linux's `AF_INET6` is 10
/// where Darwin's is 30. Reading the host's constant here would make the
/// parser agree with itself on the build machine and disagree with the kernel
/// it was written for.
const AF_INET: u32 = 2;
/// See [`AF_INET`].
const AF_INET6: u32 = 30;

/// IP version nibble of the first byte of a packet.
const IP_VERSION_SHIFT: u8 = 4;

/// The four-byte header that must precede `packet` on a write to `utun`.
///
/// Returns `None` for anything that is not an IPv4 or IPv6 packet. The caller
/// must not invent a family: macOS discards a frame whose declared family does
/// not match its contents, and it does so without an error, so a guess here
/// would surface as an interface that accepts every write and delivers
/// nothing.
pub(crate) fn af_header(packet: &[u8]) -> Option<[u8; AF_HEADER_LEN]> {
    let family = match packet.first()? >> IP_VERSION_SHIFT {
        4 => AF_INET,
        6 => AF_INET6,
        _ => return None,
    };
    // Big-endian: the kernel writes and expects the family in network byte
    // order on this interface, not in the host's.
    Some(family.to_be_bytes())
}

/// Whether the address family a frame declares matches the packet it carries.
///
/// The read path takes the header and the packet in **separate** slices — a
/// vectored read scatters them, so there is no contiguous frame to split — and
/// this is the check that reunites them.
///
/// It is not defensive noise. A frame arriving here came from the host's own
/// stack, but the version nibble is what every downstream consumer parses, and
/// a disagreement between the two means one of them is being read wrong.
/// Dropping such a frame is strictly better than handing the filter a packet
/// whose family it will decide by a different rule than the kernel used — and
/// in practice a disagreement here is the signature of the header having been
/// read at the wrong offset, which is worth failing loudly for.
pub(crate) fn family_agrees(header: [u8; AF_HEADER_LEN], packet: &[u8]) -> bool {
    let family = u32::from_be_bytes(header);
    let Some(version) = packet.first().map(|b| b >> IP_VERSION_SHIFT) else {
        return false;
    };
    matches!((family, version), (AF_INET, 4) | (AF_INET6, 6))
}

// ── PF_ROUTE dumps ──────────────────────────────────────────────────────────

/// `sizeof(struct rt_msghdr)` on every 32- and 64-bit Darwin ABI.
///
/// Derived rather than guessed, because the payload starts immediately after
/// it and a wrong value walks into the middle of the first `sockaddr`:
///
/// ```text
/// u_short rtm_msglen     0..2
/// u_char  rtm_version    2
/// u_char  rtm_type       3
/// u_short rtm_index      4..6
///                        6..8    padding, to align the int that follows
/// int     rtm_flags      8..12
/// int     rtm_addrs     12..16
/// pid_t   rtm_pid       16..20
/// int     rtm_seq       20..24
/// int     rtm_errno     24..28
/// int     rtm_use       28..32
/// u_int32 rtm_inits     32..36
/// struct rt_metrics     36..92   14 × u_int32_t
/// ```
///
/// `sys_macos` holds this against `size_of::<libc::rt_msghdr>()` in a static
/// assertion, so a Darwin ABI that ever changed shape would fail to compile
/// rather than mis-parse.
pub(crate) const RT_MSGHDR_LEN: usize = 92;

/// Offsets into `rt_msghdr`, from the layout above.
const RTM_MSGLEN: usize = 0;
const RTM_VERSION_AT: usize = 2;
const RTM_TYPE: usize = 3;
const RTM_FLAGS: usize = 8;
const RTM_ADDRS: usize = 12;

/// `RTM_VERSION` — the routing socket message version Darwin emits.
const RTM_VERSION: u8 = 5;
/// `RTM_GET` — the message type a dump is made of.
const RTM_GET: u8 = 0x4;

/// `RTF_UP` and `RTF_GATEWAY`: the route is live and has a next hop.
const RTF_UP: i32 = 0x1;
/// See [`RTF_UP`].
const RTF_GATEWAY: i32 = 0x2;

/// Bits of `rtm_addrs`, in the order the `sockaddr`s follow the header.
///
/// The whole mask has to be walked in order even though only two entries are
/// wanted: the addresses are positional, so skipping a set bit rather than
/// consuming its `sockaddr` puts every later read at the wrong offset.
const RTAX_MAX: u32 = 8;
const RTA_DST: u32 = 0x1;
const RTA_GATEWAY: u32 = 0x2;

/// `sockaddr` entries in a routing message are padded to `sizeof(uint32_t)`.
///
/// Its own constant rather than a reuse of [`AF_HEADER_LEN`]: the two are both
/// four and mean entirely different things, and a reader who saw the address
/// family's width used as an alignment would reasonably wonder which one was
/// the mistake.
const SA_ALIGN: usize = 4;

/// Round a `sockaddr`'s length up to the slot it occupies.
///
/// A zero-length entry still occupies a full slot — that is the encoding of a
/// wildcard, which is exactly what the destination of a default route is.
/// Treating it as occupying nothing puts every later read four bytes early.
fn sa_roundup(len: usize) -> usize {
    if len == 0 {
        SA_ALIGN
    } else {
        len.checked_add(SA_ALIGN - 1)
            .map_or(0, |n| n & !(SA_ALIGN - 1))
    }
}

/// One `sockaddr` as an address, if it holds one of a family Karst can use.
///
/// `AF_LINK` gateways — a default route pointing straight out of an interface
/// rather than at a next hop — return `None` on purpose. There is no address
/// to speak NAT-PMP or PCP to in that case, and reporting the interface as
/// though it were a gateway would send port-mapping requests into the void.
fn sockaddr_ip(sa: &[u8]) -> Option<IpAddr> {
    let family = u32::from(*sa.get(1)?);
    match family {
        // sockaddr_in: len, family, sin_port (2), sin_addr (4).
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
            *sa.get(4..8)?.first_chunk::<4>()?,
        ))),
        // sockaddr_in6: len, family, sin6_port (2), sin6_flowinfo (4),
        // sin6_addr (16).
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
            *sa.get(8..24)?.first_chunk::<16>()?,
        ))),
        _ => None,
    }
}

/// Whether a destination `sockaddr` is the wildcard a default route carries.
///
/// Two encodings mean the same thing and both appear in real dumps: a
/// zero-length entry, and a full `sockaddr` whose address is all zeroes.
fn is_default_destination(sa: &[u8]) -> bool {
    match sockaddr_ip(sa) {
        None => sa.first().is_none_or(|&len| len == 0),
        Some(IpAddr::V4(a)) => a.is_unspecified(),
        Some(IpAddr::V6(a)) => a.is_unspecified(),
    }
}

/// The next hop of one routing message, if that message is a usable default
/// route.
fn parse_route(msg: &[u8]) -> Option<IpAddr> {
    let hdr = msg.get(..RT_MSGHDR_LEN)?;
    if *hdr.get(RTM_VERSION_AT)? != RTM_VERSION || *hdr.get(RTM_TYPE)? != RTM_GET {
        return None;
    }
    let flags = i32::from_le_bytes(*hdr.get(RTM_FLAGS..RTM_FLAGS + 4)?.first_chunk::<4>()?);
    if flags & RTF_UP == 0 || flags & RTF_GATEWAY == 0 {
        return None;
    }
    let addrs = u32::from_le_bytes(*hdr.get(RTM_ADDRS..RTM_ADDRS + 4)?.first_chunk::<4>()?);

    let mut at = RT_MSGHDR_LEN;
    let mut destination_is_default = false;
    for slot in 0..RTAX_MAX {
        let bit = 1u32.checked_shl(slot)?;
        if addrs & bit == 0 {
            continue;
        }
        let sa = msg.get(at..)?;
        let len = usize::from(*sa.first()?);
        // A `sockaddr` claiming to run past the end of the message is a
        // malformed dump; stop rather than reinterpreting the remainder.
        let body = sa.get(..len.max(1).min(sa.len()))?;
        match bit {
            RTA_DST => destination_is_default = is_default_destination(body),
            RTA_GATEWAY if destination_is_default => return sockaddr_ip(body),
            // A gateway before a destination cannot happen — the mask is
            // positional and RTA_DST is bit 0 — but returning here anyway
            // would report a host route's next hop as the default.
            _ => {}
        }
        at = at.checked_add(sa_roundup(len))?;
    }
    None
}

/// The first usable default gateway in a `NET_RT_DUMP` buffer.
///
/// Every read goes through `get`: these are bytes the kernel wrote, but a
/// truncated or unexpected dump must degrade to "no gateway found" rather than
/// take the daemon down. `None` is a legitimate answer — a host with no
/// default route, or one whose default route leaves via an interface rather
/// than a next hop.
pub(crate) fn parse_default_gateway(buf: &[u8]) -> Option<IpAddr> {
    let mut at = 0usize;
    while let Some(rest) = buf.get(at..) {
        let len = usize::from(u16::from_le_bytes(
            *rest.get(RTM_MSGLEN..RTM_MSGLEN + 2)?.first_chunk::<2>()?,
        ));
        if len < RT_MSGHDR_LEN {
            break;
        }
        let end = at.checked_add(len)?;
        let msg = buf.get(at..end)?;
        if let Some(gateway) = parse_route(msg) {
            return Some(gateway);
        }
        at = end;
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;

    fn v4_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p
    }

    fn v6_packet() -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p
    }

    // ── the utun address-family header ──────────────────────────────────────

    /// The values are Darwin's, not the build host's. This is the test that
    /// catches somebody "tidying" the constants into `libc::AF_INET6` — which
    /// would be 10 here and 30 on the machine that matters.
    #[test]
    fn the_header_carries_darwins_families_in_network_order() {
        assert_eq!(af_header(&v4_packet()), Some([0, 0, 0, 2]));
        assert_eq!(af_header(&v6_packet()), Some([0, 0, 0, 30]));
    }

    /// What the write path produces, the read path must accept. These are the
    /// two halves of the same convention and they are checked against each
    /// other rather than each against a fixture.
    #[test]
    fn a_frame_round_trips_through_the_header() {
        for packet in [v4_packet(), v6_packet()] {
            let header = af_header(&packet).expect("a family for a real packet");
            assert!(family_agrees(header, &packet));
        }
    }

    /// Neither direction may guess. A frame that is not IP has no family, and
    /// inventing one would make macOS drop every write without saying so.
    #[test]
    fn a_packet_that_is_not_ip_has_no_family() {
        assert_eq!(af_header(&[0x00]), None);
        assert_eq!(af_header(&[0x54]), None);
        assert_eq!(af_header(&[]), None);
    }

    #[test]
    fn an_empty_packet_agrees_with_nothing() {
        assert!(!family_agrees([0, 0, 0, 2], &[]));
        assert!(!family_agrees([0, 0, 0, 30], &[]));
    }

    /// The symptom this guards against is the memorable one: leave the prefix
    /// on the packet and the filter drops every one as malformed, because
    /// `0x00` is not a version nibble it knows.
    #[test]
    fn an_unstripped_frame_does_not_parse_as_a_packet() {
        let mut frame = vec![0, 0, 0, 2];
        frame.extend_from_slice(&v4_packet());
        assert!(crate::ip::version(&frame).is_none());
        assert!(crate::ip::version(&v4_packet()).is_some());
    }

    #[test]
    fn a_family_contradicting_the_packet_is_refused() {
        assert!(!family_agrees([0, 0, 0, 30], &v4_packet()));
        assert!(!family_agrees([0, 0, 0, 2], &v6_packet()));
    }

    #[test]
    fn an_unknown_family_is_refused() {
        assert!(!family_agrees([0, 0, 0, 18], &v4_packet())); // AF_LINK
        assert!(!family_agrees([0, 0, 0, 10], &v6_packet())); // Linux's AF_INET6
    }

    /// Big-endian, not host order: the header is the one field on this
    /// interface in network byte order, and writing it the other way round
    /// declares family 33 554 432 rather than 2.
    #[test]
    fn the_header_is_not_host_order() {
        assert!(!family_agrees([2, 0, 0, 0], &v4_packet()));
        assert!(!family_agrees([30, 0, 0, 0], &v6_packet()));
    }

    // ── PF_ROUTE dumps ──────────────────────────────────────────────────────

    fn sockaddr_in(addr: Ipv4Addr) -> Vec<u8> {
        let mut sa = vec![16u8, 2, 0, 0];
        sa.extend_from_slice(&addr.octets());
        sa.resize(16, 0);
        sa
    }

    fn sockaddr_in6(addr: Ipv6Addr) -> Vec<u8> {
        let mut sa = vec![28u8, 30, 0, 0];
        sa.extend_from_slice(&0u32.to_le_bytes()); // sin6_flowinfo
        sa.extend_from_slice(&addr.octets());
        sa.resize(28, 0);
        sa
    }

    /// One `RTM_GET` message, as the kernel lays it out.
    fn route_message(flags: i32, addrs: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut msg = vec![0u8; RT_MSGHDR_LEN];
        msg[RTM_VERSION_AT] = RTM_VERSION;
        msg[RTM_TYPE] = RTM_GET;
        msg[RTM_FLAGS..RTM_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        let mask: u32 = addrs.iter().map(|(bit, _)| *bit).sum();
        msg[RTM_ADDRS..RTM_ADDRS + 4].copy_from_slice(&mask.to_le_bytes());
        for (_, sa) in addrs {
            let padded = sa_roundup(sa.len());
            msg.extend_from_slice(sa);
            msg.resize(msg.len() + padded - sa.len(), 0);
        }
        let len = u16::try_from(msg.len()).unwrap();
        msg[RTM_MSGLEN..RTM_MSGLEN + 2].copy_from_slice(&len.to_le_bytes());
        msg
    }

    fn default_v4(gateway: Ipv4Addr) -> Vec<u8> {
        route_message(
            RTF_UP | RTF_GATEWAY,
            &[
                (RTA_DST, sockaddr_in(Ipv4Addr::UNSPECIFIED)),
                (RTA_GATEWAY, sockaddr_in(gateway)),
            ],
        )
    }

    #[test]
    fn a_default_route_yields_its_next_hop() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            parse_default_gateway(&default_v4(gateway)),
            Some(IpAddr::V4(gateway))
        );
    }

    #[test]
    fn an_ipv6_default_route_yields_its_next_hop() {
        let gateway: Ipv6Addr = "fe80::1".parse().unwrap();
        let dump = route_message(
            RTF_UP | RTF_GATEWAY,
            &[
                (RTA_DST, sockaddr_in6(Ipv6Addr::UNSPECIFIED)),
                (RTA_GATEWAY, sockaddr_in6(gateway)),
            ],
        );
        assert_eq!(parse_default_gateway(&dump), Some(IpAddr::V6(gateway)));
    }

    /// A wildcard destination also appears as a zero-length entry, which still
    /// occupies a padded slot. Consuming it as though it were absent puts the
    /// gateway read four bytes into the wrong place.
    #[test]
    fn a_zero_length_destination_is_still_the_default_route() {
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        let dump = route_message(
            RTF_UP | RTF_GATEWAY,
            &[(RTA_DST, vec![]), (RTA_GATEWAY, sockaddr_in(gateway))],
        );
        assert_eq!(parse_default_gateway(&dump), Some(IpAddr::V4(gateway)));
    }

    /// The commonest shape in a real dump: many host and network routes, one
    /// default. A parser that returned the first `RTA_GATEWAY` it saw would
    /// report the first of these instead.
    #[test]
    fn a_host_route_is_not_mistaken_for_the_default() {
        let mut dump = route_message(
            RTF_UP | RTF_GATEWAY,
            &[
                (RTA_DST, sockaddr_in(Ipv4Addr::new(10, 1, 0, 0))),
                (RTA_GATEWAY, sockaddr_in(Ipv4Addr::new(10, 1, 0, 254))),
            ],
        );
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        dump.extend_from_slice(&default_v4(gateway));
        assert_eq!(parse_default_gateway(&dump), Some(IpAddr::V4(gateway)));
    }

    /// A default route out of an interface rather than to a next hop has an
    /// `AF_LINK` gateway. There is nothing to send a port-mapping request to,
    /// so the honest answer is that there is no gateway.
    #[test]
    fn a_link_layer_gateway_is_not_an_address() {
        let mut sa = vec![20u8, 18];
        sa.resize(20, 0);
        let dump = route_message(
            RTF_UP | RTF_GATEWAY,
            &[
                (RTA_DST, sockaddr_in(Ipv4Addr::UNSPECIFIED)),
                (RTA_GATEWAY, sa),
            ],
        );
        assert_eq!(parse_default_gateway(&dump), None);
    }

    #[test]
    fn a_route_that_is_down_or_has_no_gateway_is_skipped() {
        for flags in [0, RTF_UP, RTF_GATEWAY] {
            let dump = route_message(
                flags,
                &[
                    (RTA_DST, sockaddr_in(Ipv4Addr::UNSPECIFIED)),
                    (RTA_GATEWAY, sockaddr_in(Ipv4Addr::new(1, 2, 3, 4))),
                ],
            );
            assert_eq!(parse_default_gateway(&dump), None, "flags {flags:#x}");
        }
    }

    /// Truncation must end the walk, not wrap it or panic. The kernel does not
    /// truncate; a short `recv` into a fixed buffer does.
    #[test]
    fn a_truncated_dump_degrades_to_no_answer() {
        let full = default_v4(Ipv4Addr::new(192, 168, 1, 1));
        for cut in 0..full.len() {
            let _ = parse_default_gateway(full.get(..cut).unwrap());
        }
    }

    /// Every byte pattern must terminate. The dump is kernel-authored, but a
    /// parser that can loop on one is a parser that can hang the daemon.
    #[test]
    fn arbitrary_bytes_terminate() {
        let mut buf = vec![0u8; 512];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).unwrap();
        }
        let _ = parse_default_gateway(&buf);
        let _ = parse_default_gateway(&[0xff; 256]);
    }
}
