// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! NAT-PMP — RFC 6886.
//!
//! Two exchanges matter here. `PublicAddress` (opcode 0) asks the gateway what
//! its external address is; `Map` (opcodes 1 and 2) asks it to forward a port.
//! Both are fixed-size, which is most of why this file is short.
//!
//! **NAT-PMP has no transaction identifier**, and that absence shapes the
//! decoder. A client matches a response to a request by opcode alone, so two
//! outstanding requests of the same opcode are indistinguishable — the caller
//! must therefore keep at most one in flight per opcode, and this module cannot
//! enforce it. RFC 6886 §3.6 papers over the gap with idempotency: re-sending a
//! mapping request for the same ports is defined to be harmless, so a
//! misattributed response leads to a redundant mapping rather than a wrong one.
//! PCP added the nonce precisely because that is a weak guarantee, which is one
//! more reason to try PCP first.

use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;

use crate::{be16, be32, Error, Mapping, Protocol, ResultCode, Transport, RESPONSE_MAX};

/// Ask the gateway for its external address — RFC 6886 §3.2.
pub const OP_PUBLIC_ADDRESS: u8 = 0;
/// Map a UDP port — RFC 6886 §3.3.
pub const OP_MAP_UDP: u8 = 1;
/// Map a TCP port.
pub const OP_MAP_TCP: u8 = 2;

/// Set in the opcode of every response.
const RESPONSE_BIT: u8 = 0x80;

/// Wire size of a request for the gateway's external address.
pub const PUBLIC_ADDRESS_REQUEST_LEN: usize = 2;
/// Wire size of a mapping request.
pub const MAP_REQUEST_LEN: usize = 12;
/// Wire size of the gateway's external-address response.
pub const PUBLIC_ADDRESS_RESPONSE_LEN: usize = 12;
/// Wire size of a mapping response.
pub const MAP_RESPONSE_LEN: usize = 16;

/// The lifetime RFC 6886 §3.3 recommends a client request: two hours.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(7200);

/// Encode a request for the gateway's external address.
#[must_use]
pub fn encode_public_address() -> Vec<u8> {
    vec![Protocol::NatPmp.version(), OP_PUBLIC_ADDRESS]
}

/// Encode a mapping request — RFC 6886 §3.3.
///
/// A `lifetime` of zero deletes, and RFC 6886 §3.4 attaches two further rules
/// to that case which the caller owns: the external port MUST be sent as zero,
/// and a zero *internal* port deletes every mapping for the client. This
/// function enforces the first, because sending a non-zero external port with a
/// zero lifetime is a malformed deletion that some gateways answer and others
/// ignore.
#[must_use]
pub fn encode_map(
    transport: Transport,
    internal_port: u16,
    external_port: u16,
    lifetime: Duration,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAP_REQUEST_LEN);
    out.push(Protocol::NatPmp.version());
    out.push(match transport {
        Transport::Udp => OP_MAP_UDP,
        Transport::Tcp => OP_MAP_TCP,
    });
    out.extend_from_slice(&[0, 0]); // reserved
    out.extend_from_slice(&internal_port.to_be_bytes());
    let suggested = if lifetime.is_zero() { 0 } else { external_port };
    out.extend_from_slice(&suggested.to_be_bytes());
    let secs = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
    out.extend_from_slice(&secs.to_be_bytes());
    out
}

/// What a gateway said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// The gateway's external address, and its seconds-since-boot epoch.
    PublicAddress {
        /// The address the gateway forwards from.
        address: Ipv4Addr,
        /// RFC 6886 §3.2's "seconds since start of epoch".
        epoch: u32,
    },
    /// A mapping was installed, or refreshed, or deleted.
    Mapped(Mapping),
}

/// Parse a response, checking it answers the opcode that was sent.
///
/// # Errors
///
/// [`Error::TooLong`] before anything is read; [`Error::TooShort`] when the
/// message cannot hold the fields its opcode requires; [`Error::BadVersion`];
/// [`Error::NotAResponse`] when the response bit is clear;
/// [`Error::OpcodeMismatch`]; and [`Error::Refused`] carrying the gateway's own
/// code.
pub fn decode(datagram: &[u8], sent_opcode: u8) -> Result<Response, Error> {
    if datagram.len() > RESPONSE_MAX {
        return Err(Error::TooLong(datagram.len()));
    }
    // Version, opcode, result code — the four bytes every response starts with,
    // and the only ones that can be read before the opcode is known.
    let need = 4;
    let got = datagram.len();
    if got < need {
        return Err(Error::TooShort { need, got });
    }
    let version = *datagram.first().ok_or(Error::TooShort { need, got })?;
    if version != Protocol::NatPmp.version() {
        return Err(Error::BadVersion(version));
    }
    let opcode = *datagram.get(1).ok_or(Error::TooShort { need, got })?;
    if opcode & RESPONSE_BIT == 0 {
        return Err(Error::NotAResponse(opcode));
    }
    let answered = opcode & !RESPONSE_BIT;
    if answered != sent_opcode {
        return Err(Error::OpcodeMismatch {
            sent: sent_opcode,
            got: answered,
        });
    }

    // **The result code is checked before the body is parsed.** A gateway
    // refusing a request sends the fixed header and, on several
    // implementations, nothing meaningful after it — so a decoder that parsed
    // the body first would report a length error for what is really a refusal,
    // and the caller would retry something that had already been declined.
    let code = be16(datagram, 2).ok_or(Error::TooShort { need, got })?;
    if code != 0 {
        return Err(Error::Refused(ResultCode::NatPmp(code)));
    }

    match answered {
        OP_PUBLIC_ADDRESS => decode_public_address(datagram),
        OP_MAP_UDP | OP_MAP_TCP => decode_map(datagram, answered),
        // Unreachable while `sent_opcode` comes from this module's constants,
        // and refused rather than assumed away, because it does not.
        _ => Err(Error::Malformed),
    }
}

fn decode_public_address(datagram: &[u8]) -> Result<Response, Error> {
    let got = datagram.len();
    let need = PUBLIC_ADDRESS_RESPONSE_LEN;
    if got < need {
        return Err(Error::TooShort { need, got });
    }
    let epoch = be32(datagram, 4).ok_or(Error::TooShort { need, got })?;
    let raw = be32(datagram, 8).ok_or(Error::TooShort { need, got })?;
    Ok(Response::PublicAddress {
        address: Ipv4Addr::from(raw.to_be_bytes()),
        epoch,
    })
}

fn decode_map(datagram: &[u8], opcode: u8) -> Result<Response, Error> {
    let got = datagram.len();
    let need = MAP_RESPONSE_LEN;
    if got < need {
        return Err(Error::TooShort { need, got });
    }
    let transport = match opcode {
        OP_MAP_UDP => Transport::Udp,
        OP_MAP_TCP => Transport::Tcp,
        _ => return Err(Error::Malformed),
    };
    let internal_port = be16(datagram, 8).ok_or(Error::TooShort { need, got })?;
    let external_port = be16(datagram, 10).ok_or(Error::TooShort { need, got })?;
    let lifetime = be32(datagram, 12).ok_or(Error::TooShort { need, got })?;
    Ok(Response::Mapped(Mapping {
        protocol: Protocol::NatPmp,
        transport,
        internal_port,
        external_port,
        // RFC 6886 carries no address in a mapping response. Reporting the
        // gateway's own address here — the tempting fill-in, since the caller
        // has usually just asked for it — would be inventing a field the
        // gateway did not send.
        external_address: None,
        lifetime: Duration::from_secs(u64::from(lifetime)),
    }))
}

/// Whether an `epoch` jumped backwards, which means the gateway rebooted.
///
/// RFC 6886 §3.6 makes this the client's cue that **every mapping it holds is
/// gone**, because a rebooted NAT has an empty table while the client still
/// believes its mappings exist. Without this check a node keeps advertising a
/// mapped address that stopped working at the reboot, and only notices when the
/// mapping's own lifetime expires — which can be two hours later.
#[must_use]
pub const fn gateway_restarted(previous: u32, current: u32) -> bool {
    current < previous
}

/// The gateway's epoch, whether the reply was `PublicAddress` or `Map`.
///
/// Returns `None` when the datagram is too short to carry one, which is the
/// same condition [`decode`] rejects on; it is separate so a caller can run the
/// restart check on a response it is otherwise discarding.
#[must_use]
pub fn epoch(datagram: &[u8]) -> Option<u32> {
    be32(datagram, 4)
}

/// Whether an address is one a mapping response should never name.
///
/// A gateway that reports a private or unspecified external address has told
/// the node something unusable — RFC 6886 §3.2 anticipates it for a
/// double-NATed gateway. Advertising it would put an unroutable candidate into
/// every peer's probe queue, so it is refused at the boundary rather than
/// filtered later. Loopback and link-local are refused for the same reason.
///
/// **RFC 6598 shared address space is the case this was written for and did not
/// cover** (finding 37). 100.64.0.0/10 is what a carrier addresses subscriber
/// routers out of, so it is the address a *double-NATed gateway* actually
/// reports — the exact situation the paragraph above names — and
/// `Ipv4Addr::is_private` does not include it, because it is not RFC 1918.
/// Measured rather than reasoned: `miniupnpd` behind a carrier answers PCP with
/// `NO_RESOURCES` and still names its 100.64 address in the response body, and
/// a gateway that answered `SUCCESS` with the same body — which consumer
/// routers do — would have been believed.
///
/// The v6 arm carried the same gap by symmetry: a unique-local or link-local
/// address is v6's private address, and only loopback and the unspecified
/// address were refused.
///
/// Multicast and broadcast are refused last, on a different ground: they are
/// not unicast endpoints at all, so no probe sent to one can establish a path.
///
/// Documentation prefixes are deliberately **not** refused. They are ordinary
/// globally-scoped unicast as far as routing is concerned, and both this
/// crate's fixtures and `bins/karstd/tests/aquifer.rs` use routable-looking
/// addresses from that space to stand in for public ones.
#[must_use]
pub fn is_unusable_external(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            // RFC 6598 §7: 100.64.0.0/10.
            let shared = a == 100 && (64..128).contains(&b);
            v4.is_private()
                || shared
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            // RFC 4193 fc00::/7, and RFC 4291 §2.5.6 fe80::/10.
            let unique_local = (first & 0xfe00) == 0xfc00;
            let link_local = (first & 0xffc0) == 0xfe80;
            v6.is_loopback()
                || v6.is_unspecified()
                || unique_local
                || link_local
                || v6.is_multicast()
        }
    }
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

    fn map_response(opcode: u8, code: u16, internal: u16, external: u16, life: u32) -> Vec<u8> {
        let mut v = vec![0u8, opcode | RESPONSE_BIT];
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // epoch
        v.extend_from_slice(&internal.to_be_bytes());
        v.extend_from_slice(&external.to_be_bytes());
        v.extend_from_slice(&life.to_be_bytes());
        v
    }

    #[test]
    fn requests_are_the_sizes_the_rfc_gives() {
        // RFC 6886 §3.2 and §3.3. A change should read as a diff against the
        // specification rather than as drift.
        assert_eq!(encode_public_address().len(), PUBLIC_ADDRESS_REQUEST_LEN);
        assert_eq!(
            encode_map(Transport::Udp, 51820, 51820, DEFAULT_LIFETIME).len(),
            MAP_REQUEST_LEN
        );
        assert_eq!(PUBLIC_ADDRESS_REQUEST_LEN, 2);
        assert_eq!(MAP_REQUEST_LEN, 12);
    }

    #[test]
    fn a_mapping_request_says_what_the_rfc_says() {
        let wire = encode_map(Transport::Udp, 51820, 40000, Duration::from_secs(7200));
        assert_eq!(wire[0], 0, "version");
        assert_eq!(wire[1], OP_MAP_UDP);
        assert_eq!(&wire[2..4], &[0, 0], "reserved");
        assert_eq!(be16(&wire, 4), Some(51820), "internal port");
        assert_eq!(be16(&wire, 6), Some(40000), "suggested external port");
        assert_eq!(be32(&wire, 8), Some(7200), "lifetime");
    }

    #[test]
    fn a_deletion_forces_the_external_port_to_zero() {
        // RFC 6886 §3.4. Sending a suggested port with a zero lifetime is a
        // malformed deletion; some gateways honour it and others ignore it,
        // and "sometimes deletes" is the worst of the three behaviours.
        let wire = encode_map(Transport::Udp, 51820, 40000, Duration::ZERO);
        assert_eq!(be16(&wire, 4), Some(51820), "internal port is kept");
        assert_eq!(be16(&wire, 6), Some(0), "external port is forced to zero");
        assert_eq!(be32(&wire, 8), Some(0));
    }

    #[test]
    fn a_lifetime_beyond_u32_saturates_rather_than_wrapping() {
        // A wrapping cast turns "forever" into a short or zero lifetime, and a
        // zero lifetime is a *deletion* — so the arithmetic edge is a
        // functional reversal, not a cosmetic one.
        let wire = encode_map(Transport::Udp, 1, 1, Duration::from_secs(u64::MAX));
        assert_eq!(be32(&wire, 8), Some(u32::MAX));
    }

    #[test]
    fn a_mapping_response_decodes() {
        let wire = map_response(OP_MAP_UDP, 0, 51820, 40000, 3600);
        let got = decode(&wire, OP_MAP_UDP).expect("decodes");
        let Response::Mapped(m) = got else {
            panic!("expected a mapping, got {got:?}");
        };
        assert_eq!(m.protocol, Protocol::NatPmp);
        assert_eq!(m.transport, Transport::Udp);
        assert_eq!(m.internal_port, 51820);
        assert_eq!(m.external_port, 40000);
        assert_eq!(m.lifetime, Duration::from_secs(3600));
        assert_eq!(m.external_address, None, "the RFC carries no address here");
        assert_eq!(m.renew_after(), Some(Duration::from_secs(1800)));
    }

    #[test]
    fn a_public_address_response_decodes() {
        let mut wire = vec![0u8, OP_PUBLIC_ADDRESS | RESPONSE_BIT, 0, 0];
        wire.extend_from_slice(&42u32.to_be_bytes());
        wire.extend_from_slice(&[203, 0, 113, 9]);
        let got = decode(&wire, OP_PUBLIC_ADDRESS).expect("decodes");
        assert_eq!(
            got,
            Response::PublicAddress {
                address: Ipv4Addr::new(203, 0, 113, 9),
                epoch: 42,
            }
        );
    }

    #[test]
    fn a_refusal_is_reported_before_the_body_is_parsed() {
        // The header alone, with a non-zero code — which is what several
        // gateways actually send on a refusal. Parsing the body first would
        // turn this into a length complaint and the caller would retry a
        // request that has already been declined.
        let wire = vec![0u8, OP_MAP_UDP | RESPONSE_BIT, 0, 2];
        assert_eq!(
            decode(&wire, OP_MAP_UDP),
            Err(Error::Refused(ResultCode::NatPmp(2)))
        );
    }

    #[test]
    fn a_response_to_another_opcode_is_refused() {
        // NAT-PMP has no transaction id, so the opcode is the *entire* means
        // of matching a response to a request. Accepting a mismatch would let
        // an address response satisfy an outstanding mapping request.
        let wire = map_response(OP_MAP_TCP, 0, 51820, 40000, 3600);
        assert_eq!(
            decode(&wire, OP_MAP_UDP),
            Err(Error::OpcodeMismatch {
                sent: OP_MAP_UDP,
                got: OP_MAP_TCP
            })
        );
    }

    #[test]
    fn a_request_arriving_as_though_it_were_a_response_is_refused() {
        // Something on the link talking to us as though we were the gateway.
        let wire = map_response(OP_MAP_UDP, 0, 1, 1, 1);
        let mut req = wire;
        req[1] &= !RESPONSE_BIT;
        assert_eq!(
            decode(&req, OP_MAP_UDP),
            Err(Error::NotAResponse(OP_MAP_UDP))
        );
    }

    #[test]
    fn the_wrong_version_is_refused() {
        let mut wire = map_response(OP_MAP_UDP, 0, 1, 1, 1);
        wire[0] = 2; // PCP's byte, on a NAT-PMP decoder
        assert_eq!(decode(&wire, OP_MAP_UDP), Err(Error::BadVersion(2)));
    }

    #[test]
    fn every_truncation_is_refused_rather_than_read_past() {
        // The property that matters on the pre-authentication path: no prefix
        // of a valid message may panic or produce a value.
        let full = map_response(OP_MAP_UDP, 0, 51820, 40000, 3600);
        for n in 0..full.len() {
            let short = full.get(..n).expect("prefix");
            let got = decode(short, OP_MAP_UDP);
            assert!(
                matches!(got, Err(Error::TooShort { .. })),
                "prefix of {n} bytes gave {got:?}"
            );
        }
        assert!(
            decode(&full, OP_MAP_UDP).is_ok(),
            "the full message is fine"
        );
    }

    #[test]
    fn an_over_long_datagram_is_refused_before_anything_is_read() {
        let huge = vec![0u8; RESPONSE_MAX + 1];
        assert_eq!(
            decode(&huge, OP_MAP_UDP),
            Err(Error::TooLong(RESPONSE_MAX + 1))
        );
    }

    #[test]
    fn a_backwards_epoch_means_the_gateway_rebooted() {
        // RFC 6886 §3.6. Missing this is a silent failure that lasts until the
        // mapping's own lifetime runs out — up to two hours of advertising an
        // address that stopped working.
        assert!(gateway_restarted(500, 10));
        assert!(!gateway_restarted(10, 500));
        assert!(!gateway_restarted(10, 10), "no change is not a restart");
    }

    #[test]
    fn a_private_external_address_is_rejected() {
        // The double-NAT case RFC 6886 §3.2 anticipates. Advertising it puts
        // an unroutable candidate in every peer's probe queue.
        for bad in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            let addr: IpAddr = bad.parse().expect("address");
            assert!(is_unusable_external(addr), "{bad} should be rejected");
        }
        for good in ["203.0.113.9", "198.51.100.1"] {
            let addr: IpAddr = good.parse().expect("address");
            assert!(!is_unusable_external(addr), "{good} should be accepted");
        }
    }

    #[test]
    fn shared_address_space_is_rejected() {
        // **Finding 37.** RFC 6598's 100.64.0.0/10 is what a carrier addresses
        // subscriber routers out of, so it is what a gateway behind CGNAT
        // reports — the very case the check exists for — and it is not RFC
        // 1918, so `is_private` says nothing about it.
        for bad in ["100.64.0.1", "100.64.0.2", "100.100.5.6", "100.127.255.255"] {
            let addr: IpAddr = bad.parse().expect("address");
            assert!(is_unusable_external(addr), "{bad} is RFC 6598 shared space");
        }
        // The edges, in both directions. 100.64/10 is a ten-bit prefix, so the
        // second octet is what decides it, and an off-by-one here would either
        // reject public space or admit the carrier's.
        for good in ["100.63.255.255", "100.128.0.0", "100.0.0.1", "99.64.0.1"] {
            let addr: IpAddr = good.parse().expect("address");
            assert!(
                !is_unusable_external(addr),
                "{good} is outside 100.64.0.0/10 and is ordinary public space"
            );
        }
    }

    #[test]
    fn the_v6_arm_refuses_what_the_v4_arm_refuses() {
        // The two arms were asymmetric: v4 refused private and link-local, v6
        // refused neither. A unique-local address is v6's RFC 1918.
        for bad in ["fd00::1", "fc00::1", "fe80::1", "::1", "::", "ff02::1"] {
            let addr: IpAddr = bad.parse().expect("address");
            assert!(is_unusable_external(addr), "{bad} should be rejected");
        }
        for good in ["2001:db8::1", "2606:4700::1111"] {
            let addr: IpAddr = good.parse().expect("address");
            assert!(!is_unusable_external(addr), "{good} should be accepted");
        }
    }

    #[test]
    fn an_address_that_is_not_a_unicast_endpoint_is_rejected() {
        // Not "unroutable" like the ranges above — a probe to one of these
        // cannot establish a path with a peer no matter how it is routed.
        for bad in ["224.0.0.1", "239.1.2.3", "255.255.255.255"] {
            let addr: IpAddr = bad.parse().expect("address");
            assert!(is_unusable_external(addr), "{bad} should be rejected");
        }
    }
}
