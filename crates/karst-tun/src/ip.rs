// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Inner IP packet inspection.
//!
//! Just enough parsing to decide which peer a packet belongs to, and to check
//! that a packet arriving from a peer carries a source address that peer is
//! entitled to use. Nothing here interprets the payload.
//!
//! **This is an adversarial parser.** It reads bytes written by the local host
//! *and* bytes decrypted from a peer, so a malformed packet must yield `None`,
//! never a panic. No indexing, no slicing, no arithmetic that can overflow a
//! bound: every read goes through `first_chunk` or `get`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Offsets into an IPv4 header — RFC 791.
mod v4 {
    pub(super) const SRC: usize = 12;
    pub(super) const DST: usize = 16;
    pub(super) const MIN_LEN: usize = 20;
}

/// Offsets into an IPv6 header — RFC 8200.
mod v6 {
    pub(super) const SRC: usize = 8;
    pub(super) const DST: usize = 24;
    pub(super) const MIN_LEN: usize = 40;
}

/// Which IP version a packet claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// IPv4 — RFC 791.
    V4,
    /// IPv6 — RFC 8200.
    V6,
}

/// The addresses of an inner packet, and nothing else.
///
/// A TUN device in `IFF_TUN` mode hands over bare IP packets with no link
/// header, so the version nibble of the first byte is the only demultiplexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addresses {
    /// IP version, from the leading nibble.
    pub version: Version,
    /// Source address.
    pub source: IpAddr,
    /// Destination address — what peer selection keys on.
    pub destination: IpAddr,
}

/// Read the version nibble.
///
/// Returns `None` for an empty buffer or an unrecognized version. Note that a
/// version nibble is *claimed*, not proven: [`addresses`] additionally checks
/// that the buffer is long enough for the header it claims.
#[must_use]
pub fn version(packet: &[u8]) -> Option<Version> {
    match packet.first()? >> 4 {
        4 => Some(Version::V4),
        6 => Some(Version::V6),
        _ => None,
    }
}

/// Extract source and destination.
///
/// Returns `None` if the packet is truncated, of an unknown version, or —
/// for IPv4 — declares an internet header length below the 20-byte minimum.
/// Options are not parsed; the addresses sit at fixed offsets before them.
#[must_use]
pub fn addresses(packet: &[u8]) -> Option<Addresses> {
    match version(packet)? {
        Version::V4 => {
            // IHL is in 32-bit words and must cover the fixed header. A packet
            // claiming less is malformed, and accepting it would mean reading
            // addresses out of a header the sender says does not exist.
            let ihl = usize::from(packet.first()? & 0x0F) * 4;
            if ihl < v4::MIN_LEN || packet.len() < v4::MIN_LEN {
                return None;
            }
            Some(Addresses {
                version: Version::V4,
                source: IpAddr::V4(Ipv4Addr::from(*read4(packet, v4::SRC)?)),
                destination: IpAddr::V4(Ipv4Addr::from(*read4(packet, v4::DST)?)),
            })
        }
        Version::V6 => {
            if packet.len() < v6::MIN_LEN {
                return None;
            }
            Some(Addresses {
                version: Version::V6,
                source: IpAddr::V6(Ipv6Addr::from(*read16(packet, v6::SRC)?)),
                destination: IpAddr::V6(Ipv6Addr::from(*read16(packet, v6::DST)?)),
            })
        }
    }
}

/// Destination address alone — the common case, since that is what selects a
/// peer.
#[must_use]
pub fn destination(packet: &[u8]) -> Option<IpAddr> {
    addresses(packet).map(|a| a.destination)
}

// ── transport ports, for the packet filter ──────────────────────────────────

/// Protocol numbers this parser knows how to read ports out of.
mod proto {
    pub(super) const HOPOPT: u8 = 0;
    pub(super) const TCP: u8 = 6;
    pub(super) const UDP: u8 = 17;
    pub(super) const DCCP: u8 = 33;
    pub(super) const IPV6_ROUTING: u8 = 43;
    pub(super) const IPV6_FRAGMENT: u8 = 44;
    pub(super) const ESP: u8 = 50;
    pub(super) const AH: u8 = 51;
    pub(super) const IPV6_NONXT: u8 = 59;
    pub(super) const IPV6_DSTOPTS: u8 = 60;
    pub(super) const SCTP: u8 = 132;
    pub(super) const MOBILITY: u8 = 135;
    pub(super) const UDPLITE: u8 = 136;
}

/// A packet's transport-layer ports, as far as they can be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    /// The upper-layer protocol number, after any IPv6 extension headers.
    pub protocol: u8,
    /// Source port, or 0 for a protocol that has none.
    pub source: u16,
    /// Destination port, or 0 for a protocol that has none.
    pub destination: u16,
}

/// Read the transport ports of an inner packet.
///
/// # Why `None` must be treated as "deny"
///
/// This is the input to the ACL check, so the distinction between the two
/// negative answers is load-bearing:
///
/// - **A protocol with no ports** — ICMP, and anything else not listed in
///   [`proto`] — returns `Some` with both ports zero. It is classifiable, and
///   the policy language decides what to do with port 0.
/// - **A packet whose ports cannot be established** returns `None`. A caller
///   MUST deny it. The case that matters is a **non-first IP fragment**, which
///   carries no transport header at all: reading its payload as one would take
///   two arbitrary bytes as a port, and *ignoring* the ambiguity would let an
///   attacker bypass every port rule by sending traffic as fragments. Encrypted
///   ESP payloads are the same: opaque, so unclassifiable.
///
/// Options and IPv6 extension headers are walked, with a hard iteration cap —
/// a crafted chain must not become a loop on the datapath.
#[must_use]
pub fn ports(packet: &[u8]) -> Option<Ports> {
    match version(packet)? {
        Version::V4 => {
            let ihl = usize::from(packet.first()? & 0x0F) * 4;
            if ihl < v4::MIN_LEN || packet.len() < ihl {
                return None;
            }
            // Fragment offset is the low 13 bits of bytes 6-7. A non-zero
            // offset means the transport header is in another packet.
            let frag = u16::from_be_bytes(*packet.get(6..)?.first_chunk::<2>()?);
            if frag & 0x1FFF != 0 {
                return None;
            }
            let protocol = *packet.get(9)?;
            read_ports(packet.get(ihl..)?, protocol)
        }
        Version::V6 => {
            if packet.len() < v6::MIN_LEN {
                return None;
            }
            let mut next = *packet.get(6)?;
            let mut rest = packet.get(v6::MIN_LEN..)?;

            // Bounded: an extension chain is a linked list written by the peer,
            // and eight hops is already more than any legitimate packet uses.
            for _ in 0..8 {
                let advance = match next {
                    proto::HOPOPT | proto::IPV6_ROUTING | proto::IPV6_DSTOPTS | proto::MOBILITY => {
                        // Length is in 8-octet units, excluding the first 8.
                        (usize::from(*rest.get(1)?) + 1) * 8
                    }
                    proto::IPV6_FRAGMENT => {
                        // Same reasoning as IPv4: a non-first fragment has no
                        // transport header to read.
                        let off = u16::from_be_bytes(*rest.get(2..)?.first_chunk::<2>()?);
                        if off & 0xFFF8 != 0 {
                            return None;
                        }
                        8
                    }
                    // Length is in 4-octet units, excluding the first 8.
                    proto::AH => (usize::from(*rest.get(1)?) + 2) * 4,
                    // Opaque. Not classifiable, so not permitted.
                    proto::ESP => return None,
                    // "No next header": there is no upper layer at all.
                    proto::IPV6_NONXT => {
                        return Some(Ports {
                            protocol: proto::IPV6_NONXT,
                            source: 0,
                            destination: 0,
                        })
                    }
                    _ => return read_ports(rest, next),
                };
                next = *rest.first()?;
                rest = rest.get(advance..)?;
            }
            // A chain longer than the cap is either broken or hostile.
            None
        }
    }
}

/// Ports out of a transport header, given the protocol.
fn read_ports(payload: &[u8], protocol: u8) -> Option<Ports> {
    match protocol {
        proto::TCP | proto::UDP | proto::SCTP | proto::DCCP | proto::UDPLITE => Some(Ports {
            protocol,
            source: u16::from_be_bytes(*payload.first_chunk::<2>()?),
            destination: u16::from_be_bytes(*payload.get(2..)?.first_chunk::<2>()?),
        }),
        // ICMP, ICMPv6, GRE, ESP-in-anything-else: real protocols with no port
        // number. Zero is the honest answer, not a refusal — the packet is
        // perfectly classifiable, it simply has no port.
        _ => Some(Ports {
            protocol,
            source: 0,
            destination: 0,
        }),
    }
}

fn read4(packet: &[u8], at: usize) -> Option<&[u8; 4]> {
    packet.get(at..)?.first_chunk::<4>()
}

fn read16(packet: &[u8], at: usize) -> Option<&[u8; 16]> {
    packet.get(at..)?.first_chunk::<16>()
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

    /// A minimal well-formed IPv4 header: version 4, IHL 5, 10.0.0.1 → 10.0.0.2.
    fn v4_packet() -> Vec<u8> {
        let mut p = vec![0u8; v4::MIN_LEN];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p
    }

    /// A minimal well-formed IPv6 header: `fd7a::1` → `fd7a::2`.
    fn v6_packet() -> Vec<u8> {
        let mut p = vec![0u8; v6::MIN_LEN];
        p[0] = 0x60;
        p[8..24].copy_from_slice(&Ipv6Addr::new(0xfd7a, 0, 0, 0, 0, 0, 0, 1).octets());
        p[24..40].copy_from_slice(&Ipv6Addr::new(0xfd7a, 0, 0, 0, 0, 0, 0, 2).octets());
        p
    }

    #[test]
    fn parses_ipv4_addresses() {
        let a = addresses(&v4_packet()).expect("well-formed v4 header");
        assert_eq!(a.version, Version::V4);
        assert_eq!(a.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(a.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn parses_ipv6_addresses() {
        let a = addresses(&v6_packet()).expect("well-formed v6 header");
        assert_eq!(a.version, Version::V6);
        assert_eq!(
            a.destination,
            IpAddr::V6(Ipv6Addr::new(0xfd7a, 0, 0, 0, 0, 0, 0, 2))
        );
    }

    /// IPv4 options push the payload back but not the addresses, so a header
    /// with IHL > 5 must still parse.
    #[test]
    fn ipv4_options_do_not_move_the_addresses() {
        let mut p = v4_packet();
        p[0] = 0x46; // IHL 6 — one 32-bit option word
        p.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            destination(&p),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
    }

    /// An IHL below 5 claims a header shorter than the addresses it would
    /// contain. Trusting it would mean parsing fields the sender disclaims.
    #[test]
    fn rejects_an_impossible_internet_header_length() {
        let mut p = v4_packet();
        p[0] = 0x44; // IHL 4 → 16 bytes, less than the 20-byte minimum
        assert_eq!(addresses(&p), None);
    }

    #[test]
    fn rejects_unknown_versions() {
        assert_eq!(version(&[0x00]), None);
        assert_eq!(version(&[0x50]), None, "IPv5 was never deployed");
        assert_eq!(version(&[]), None);
        assert_eq!(addresses(&[0xF0; 64]), None);
    }

    #[test]
    fn rejects_truncated_headers() {
        for n in 0..v4::MIN_LEN {
            let p = &v4_packet()[..n];
            assert_eq!(addresses(p), None, "{n}-byte v4 header must not parse");
        }
        for n in 0..v6::MIN_LEN {
            let p = &v6_packet()[..n];
            assert_eq!(addresses(p), None, "{n}-byte v6 header must not parse");
        }
    }

    /// The parser runs on bytes decrypted from a peer. Whatever it is handed,
    /// it must answer rather than abort.
    #[test]
    fn never_panics_on_arbitrary_input() {
        let mut state = 0x243F_6A88_85A3_08D3u64;
        let mut buf = Vec::new();
        for len in 0..80 {
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.clear();
                buf.extend(state.to_le_bytes().iter().cycle().take(len));
                let _ = addresses(&buf);
                let _ = version(&buf);
            }
        }
    }

    // ── ports ───────────────────────────────────────────────────────────────

    fn v4_with(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = v4_packet();
        p[9] = protocol;
        p.extend_from_slice(payload);
        p
    }

    fn v6_with(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = v6_packet();
        p[6] = next;
        p.extend_from_slice(payload);
        p
    }

    /// `0x0016` is 22; `0xC000` is 49152.
    const TCP_HDR: [u8; 4] = [0xC0, 0x00, 0x00, 0x16];

    #[test]
    fn reads_tcp_and_udp_ports() {
        for proto in [6u8, 17, 132, 33, 136] {
            let got = ports(&v4_with(proto, &TCP_HDR)).expect("well-formed");
            assert_eq!(got.protocol, proto);
            assert_eq!(got.source, 49152);
            assert_eq!(got.destination, 22);
        }
        let got = ports(&v6_with(6, &TCP_HDR)).expect("well-formed v6");
        assert_eq!(got.destination, 22);
    }

    /// ICMP has no ports. That is not a parse failure — the packet is entirely
    /// classifiable, and reporting it as one would deny every ping.
    #[test]
    fn a_protocol_without_ports_reports_zero_rather_than_failing() {
        let got = ports(&v4_with(1, &[8, 0, 0, 0])).expect("icmp is classifiable");
        assert_eq!(got.protocol, 1);
        assert_eq!((got.source, got.destination), (0, 0));

        let got = ports(&v6_with(58, &[128, 0, 0, 0])).expect("icmpv6 is classifiable");
        assert_eq!(got.protocol, 58);
    }

    /// **The filter bypass this exists to stop.** A non-first fragment carries
    /// no transport header, so its "ports" are two arbitrary payload bytes.
    /// Reading them anyway would let an attacker evade every port rule by
    /// fragmenting; the only safe answer is that the ports are unknown.
    #[test]
    fn a_non_first_ipv4_fragment_has_no_readable_ports() {
        let mut p = v4_with(6, &TCP_HDR);
        p[6] = 0x00;
        p[7] = 0x01; // fragment offset 1 (8-byte units)
        assert_eq!(ports(&p), None);

        // The *first* fragment does carry the header, and must still parse —
        // denying it would break large packets rather than attacks.
        let mut first = v4_with(6, &TCP_HDR);
        first[6] = 0x20; // MF set, offset 0
        assert_eq!(ports(&first).map(|p| p.destination), Some(22));
    }

    #[test]
    fn a_non_first_ipv6_fragment_has_no_readable_ports() {
        // Fragment header: next=TCP, reserved, offset 1<<3, ident.
        let frag = [6u8, 0, 0x00, 0x08, 0, 0, 0, 1];
        let mut payload = frag.to_vec();
        payload.extend_from_slice(&TCP_HDR);
        assert_eq!(ports(&v6_with(44, &payload)), None);

        let first = [6u8, 0, 0x00, 0x01, 0, 0, 0, 1]; // offset 0, M flag set
        let mut payload = first.to_vec();
        payload.extend_from_slice(&TCP_HDR);
        assert_eq!(
            ports(&v6_with(44, &payload)).map(|p| p.destination),
            Some(22)
        );
    }

    /// IPv6 extension headers push the transport header back. A parser that
    /// read at a fixed offset would take two option bytes as a port.
    #[test]
    fn ipv6_extension_headers_are_walked() {
        // Hop-by-hop: next=TCP, len=0 (8 bytes total), then padding.
        let mut payload = vec![6u8, 0, 1, 4, 0, 0, 0, 0];
        payload.extend_from_slice(&TCP_HDR);
        let got = ports(&v6_with(0, &payload)).expect("chain must be walked");
        assert_eq!(got.protocol, 6);
        assert_eq!(got.destination, 22);
    }

    /// An ESP payload is encrypted, so its ports cannot be read at all.
    #[test]
    fn an_encrypted_payload_is_not_classifiable() {
        assert_eq!(ports(&v6_with(50, &[0u8; 32])), None);
    }

    /// A chain that never terminates must not become a loop on the datapath.
    #[test]
    fn a_long_extension_chain_is_refused_rather_than_followed() {
        // Twenty hop-by-hop headers, each pointing at the next.
        let mut payload = Vec::new();
        for _ in 0..20 {
            payload.extend_from_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0]);
        }
        payload.extend_from_slice(&TCP_HDR);
        assert_eq!(ports(&v6_with(0, &payload)), None);
    }

    #[test]
    fn a_truncated_transport_header_has_no_ports() {
        assert_eq!(ports(&v4_with(6, &[0xC0])), None);
        assert_eq!(ports(&v4_with(6, &[])), None);
        assert_eq!(ports(&v6_with(6, &[0, 1, 2])), None);
    }

    /// Same discipline as the address parser: arbitrary bytes must answer,
    /// never abort.
    #[test]
    fn port_parsing_never_panics_on_arbitrary_input() {
        let mut state = 0x1357_9BDF_2468_ACE0u64;
        let mut buf = Vec::new();
        for len in 0..120 {
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                buf.clear();
                buf.extend(state.to_le_bytes().iter().cycle().take(len));
                let _ = ports(&buf);
                // And with a forced-valid version nibble, so the deeper paths
                // are actually reached rather than rejected at the first byte.
                if let Some(b) = buf.first_mut() {
                    *b = 0x60;
                }
                let _ = ports(&buf);
            }
        }
    }

    /// Truncating a valid packet at every length must never produce a *wrong*
    /// answer — only the right one or none.
    #[test]
    fn truncation_never_yields_a_wrong_address() {
        let full = v6_packet();
        let expected = destination(&full);
        for n in 0..=full.len() {
            match destination(&full[..n]) {
                None => {}
                got => assert_eq!(got, expected, "truncation at {n} changed the answer"),
            }
        }
    }
}
