// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! Explicit NAT port mapping — **NAT-PMP** (RFC 6886) and **PCP** (RFC 6887).
//!
//! A NAT that will *tell* you your external port, or better, reserve one for
//! you, removes the guessing that `karst-disco` otherwise has to do. The
//! mapping it hands back is a candidate like any other — `aven-v1.md` §7.2's
//! tiers still apply — with one distinction worth stating: it is the only
//! candidate a node holds that the NAT is keeping open **on purpose**, rather
//! than as a side effect of traffic the node happened to send.
//!
//! **Sans-io**, like every other protocol crate here: this turns bytes into
//! typed values and back and computes when the next renewal is due. It opens no
//! socket, reads no clock, and does not discover the gateway.
//!
//! # Why both protocols
//!
//! PCP supersedes NAT-PMP and they share UDP port 5351, which is not a
//! coincidence — PCP's designers made version 2 distinguishable from NAT-PMP's
//! version 0 on the wire so that one socket can speak both. A client sends PCP
//! first and falls back on an explicit version error, which is the negotiation
//! RFC 6887 §9 describes. Deployment is the reason both are here: PCP is what
//! carrier-grade NAT deploys, NAT-PMP is what a decade of consumer routers
//! shipped, and a client that speaks only one meets the other regularly.
//!
//! UPnP-IGD is deliberately **not** in this crate. It is SOAP over HTTP over
//! SSDP discovery — three protocols and an XML parser — against these two,
//! which are a single UDP exchange with fixed-size messages. It belongs in its
//! own crate if it is built at all, and putting it here would have meant this
//! crate depending on an XML parser to serve the two protocols that do not need
//! one.
//!
//! # The security posture is not the same as AVEN's
//!
//! AVEN authenticates every datagram with a per-pair key. **Nothing here is
//! authenticated at all** — NAT-PMP has no security whatever, and PCP's
//! optional authentication (RFC 7652) is not deployed and not implemented here.
//! Anything on the local link can forge a response.
//!
//! That is survivable only because of what a mapping is *used for*. A forged
//! response makes a node advertise an external address that does not work,
//! which costs its peers a few probes and nothing else — the same bound
//! `aven-v1.md` §7.2 already places on a lying peer, and the reason that
//! section forbids treating any reported address as a path. A node MUST NOT
//! draw any other conclusion from a mapping response: not that it is behind a
//! NAT of a particular kind, not that a port is safe to bind, and above all not
//! that traffic arriving at the mapped port is authentic.

pub mod natpmp;
pub mod pcp;

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::time::Duration;

/// The UDP port both protocols are served on — RFC 6886 §3.2, RFC 6887 §8.1.
pub const SERVER_PORT: u16 = 5351;

/// Largest response either protocol defines, and the cap on anything parsed.
///
/// Checked before a length is read from the wire, so no field ever sizes an
/// allocation. PCP responses are capped at 1100 bytes by RFC 6887 §7; the
/// options this crate emits do not approach it, and a response longer than this
/// is refused rather than truncated.
pub const RESPONSE_MAX: usize = 1100;

/// Which protocol a message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// RFC 6886. Version byte 0.
    NatPmp,
    /// RFC 6887. Version byte 2.
    Pcp,
}

impl Protocol {
    /// The version byte that opens every message of this protocol.
    #[must_use]
    pub const fn version(self) -> u8 {
        match self {
            Self::NatPmp => 0,
            Self::Pcp => 2,
        }
    }
}

/// Which transport a mapping covers.
///
/// Karst only ever asks for UDP — the datapath is UDP and there is nothing else
/// to map. TCP exists here because both protocols encode it and a decoder that
/// cannot name what it decodes is harder to test, not because anything requests
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// IANA protocol number 17.
    Udp,
    /// IANA protocol number 6.
    Tcp,
}

impl Transport {
    /// The IANA protocol number, which is what PCP puts on the wire.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Udp => 17,
            Self::Tcp => 6,
        }
    }

    /// Parse an IANA protocol number.
    #[must_use]
    pub const fn from_number(n: u8) -> Option<Self> {
        match n {
            17 => Some(Self::Udp),
            6 => Some(Self::Tcp),
            _ => None,
        }
    }
}

/// A mapping the gateway says it has installed.
///
/// **`lifetime` is the gateway's answer, not the client's request.** Both
/// protocols allow a shorter grant than was asked for, and RFC 6887 §11.2.1 is
/// explicit that the client renews against what it was granted. An
/// implementation that renews on its own requested interval loses the mapping
/// on any gateway that trims it — which is the same class of mistake as
/// `aven-v1.md` §7.5's reflect interval, one layer up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The protocol that produced it.
    pub protocol: Protocol,
    /// Which transport it covers.
    pub transport: Transport,
    /// The port on this host.
    pub internal_port: u16,
    /// The port the gateway will forward from.
    pub external_port: u16,
    /// The external address, when the gateway reports one.
    ///
    /// `None` for NAT-PMP, which carries no address in a mapping response — a
    /// separate `PublicAddress` request answers that, and RFC 6886 §3.2 makes
    /// it a distinct exchange rather than a field.
    pub external_address: Option<IpAddr>,
    /// How long the gateway granted, which may be shorter than requested.
    pub lifetime: Duration,
}

impl Mapping {
    /// When to renew, per RFC 6887 §11.2.1: **half the granted lifetime**.
    ///
    /// Renewing at the lifetime itself is renewing at the moment of expiry, so
    /// a single lost datagram costs the mapping. Half leaves room for a
    /// retransmission and is what the RFC specifies rather than what this
    /// implementation preferred.
    ///
    /// A zero lifetime — which is how both protocols express a *deletion* —
    /// yields `None`, because there is nothing left to renew.
    #[must_use]
    pub fn renew_after(&self) -> Option<Duration> {
        if self.lifetime.is_zero() {
            return None;
        }
        Some(self.lifetime / 2)
    }
}

/// Why a message could not be used.
///
/// Every variant is a **silent drop** at the caller: this crate is parsing
/// unauthenticated bytes from the local link, and a log line per malformed
/// datagram is a disk-filling primitive available to anything on that link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Shorter than the fixed part of the message it claims to be.
    TooShort {
        /// Bytes needed.
        need: usize,
        /// Bytes present.
        got: usize,
    },
    /// Longer than [`RESPONSE_MAX`]. Refused before anything is parsed.
    TooLong(usize),
    /// A version byte this crate does not speak.
    BadVersion(u8),
    /// The opcode is not the response to the request that was sent.
    ///
    /// Both protocols set the high bit of the opcode in a response, so a
    /// message with it clear is a *request* — which arrives when something on
    /// the link is talking to us as though we were the gateway.
    NotAResponse(u8),
    /// A response to a different opcode than the one outstanding.
    OpcodeMismatch {
        /// What was sent.
        sent: u8,
        /// What came back.
        got: u8,
    },
    /// The gateway refused, with its own code.
    Refused(ResultCode),
    /// A field held a value the protocol does not define.
    Malformed,
    /// The nonce did not match the outstanding request — PCP only.
    ///
    /// PCP's 96-bit mapping nonce is what makes an off-path forgery need a
    /// guess rather than just a well-timed datagram, so a mismatch is dropped
    /// rather than tolerated.
    NonceMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, got } => {
                write!(
                    f,
                    "message of {got} bytes is shorter than the {need} needed"
                )
            }
            Self::TooLong(n) => write!(f, "message of {n} bytes exceeds the cap"),
            Self::BadVersion(v) => write!(f, "unsupported port-mapping version {v}"),
            Self::NotAResponse(op) => write!(f, "opcode {op:#04x} is a request, not a response"),
            Self::OpcodeMismatch { sent, got } => {
                write!(f, "sent opcode {sent:#04x} and got {got:#04x}")
            }
            Self::Refused(c) => write!(f, "gateway refused: {c}"),
            Self::Malformed => f.write_str("malformed body"),
            Self::NonceMismatch => f.write_str("nonce did not match the outstanding request"),
        }
    }
}

impl core::error::Error for Error {}

/// A gateway's refusal.
///
/// The two protocols number their codes differently — NAT-PMP's 2 is "network
/// failure", PCP's 2 is "not authorized" — so they are kept apart rather than
/// merged into one enum that would silently mean different things depending on
/// where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResultCode {
    /// An RFC 6886 §3.5 code.
    NatPmp(u16),
    /// An RFC 6887 §7.4 code.
    Pcp(u8),
}

impl ResultCode {
    /// Whether retrying the same request could plausibly succeed later.
    ///
    /// **The distinction is operational rather than cosmetic.** A node that
    /// retries `UnsupportedVersion` every thirty seconds is generating traffic
    /// that cannot ever work; a node that gives up on `NoResources` never
    /// recovers when the gateway's table drains. Everything unrecognized is
    /// treated as permanent, so a code this crate has never heard of costs one
    /// attempt rather than an indefinite retry loop.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        match self {
            // 3 network failure, 4 out of resources.
            Self::NatPmp(c) => matches!(c, 3 | 4),
            // RFC 6887 §7.4: 7 NETWORK_FAILURE, 8 NO_RESOURCES,
            // 11 CANNOT_PROVIDE_EXTERNAL, 13 EXCESSIVE_REMOTE_PEERS — all of
            // which can change without the client changing anything.
            //
            // **The numbering is worth reading off the RFC rather than
            // remembering.** The first version of this listed 4 as "network
            // failure": 4 is UNSUPP_OPCODE and network failure is 7, so a
            // gateway that does not implement `MAP` would have been retried
            // indefinitely while a genuinely transient failure was given up on.
            // 12 ADDRESS_MISMATCH is deliberately *not* here — it means the
            // client sent an address that does not match its own packet
            // source, which is a bug in the client and retrying it unchanged
            // reproduces it exactly. `tests/gateway.rs` gets a real 12 out of
            // miniupnpd by mutating the encoder, which is how the mislabelling
            // was found.
            Self::Pcp(c) => matches!(c, 7 | 8 | 11 | 13),
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NatPmp(c) => write!(f, "NAT-PMP code {c}"),
            Self::Pcp(c) => write!(f, "PCP code {c}"),
        }
    }
}

/// Read a big-endian `u16` without indexing.
///
/// The whole crate is on the pre-authentication path — these are unauthenticated
/// bytes from the local link — so it is written the way `karst-disco`'s decoder
/// is: no indexing, no slicing by a length the wire supplied, no `unwrap`.
pub(crate) fn be16(b: &[u8], at: usize) -> Option<u16> {
    let hi = *b.get(at)?;
    let lo = *b.get(at.checked_add(1)?)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Read a big-endian `u32` without indexing.
pub(crate) fn be32(b: &[u8], at: usize) -> Option<u32> {
    let a = *b.get(at)?;
    let b1 = *b.get(at.checked_add(1)?)?;
    let c = *b.get(at.checked_add(2)?)?;
    let d = *b.get(at.checked_add(3)?)?;
    Some(u32::from_be_bytes([a, b1, c, d]))
}

/// Read the 16 bytes PCP uses for every address, and unmap IPv4.
///
/// RFC 6887 §5 carries every address as 16 bytes, using the
/// IPv4-mapped IPv6 form for IPv4. Returning `Ipv4Addr` for those is not
/// cosmetic: a caller that advertised `::ffff:192.0.2.1` as a candidate would
/// be naming an address no peer can parse into a UDP destination.
pub(crate) fn pcp_address(b: &[u8], at: usize) -> Option<IpAddr> {
    let end = at.checked_add(16)?;
    let raw: &[u8] = b.get(at..end)?;
    let mut octets = [0u8; 16];
    octets.copy_from_slice(raw);
    let v6 = Ipv6Addr::from(octets);
    Some(match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    })
}

/// Write an address in PCP's 16-byte form.
pub(crate) fn put_pcp_address(out: &mut Vec<u8>, addr: IpAddr) {
    let v6 = match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&v6.octets());
}

/// The unspecified IPv4 address, which both protocols use to mean "any".
pub(crate) const ANY_V4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]
    use super::*;

    #[test]
    fn version_bytes_match_the_rfcs() {
        // RFC 6886 §3.2 and RFC 6887 §7.1. PCP chose 2 so that a NAT-PMP
        // server, which rejects anything but 0, and a PCP server can share
        // port 5351 — which is the whole reason one socket can try both.
        assert_eq!(Protocol::NatPmp.version(), 0);
        assert_eq!(Protocol::Pcp.version(), 2);
        assert_ne!(Protocol::NatPmp.version(), Protocol::Pcp.version());
    }

    #[test]
    fn transport_numbers_are_ianas() {
        assert_eq!(Transport::Udp.number(), 17);
        assert_eq!(Transport::Tcp.number(), 6);
        assert_eq!(Transport::from_number(17), Some(Transport::Udp));
        assert_eq!(Transport::from_number(6), Some(Transport::Tcp));
        assert_eq!(Transport::from_number(1), None);
    }

    #[test]
    fn renewal_is_half_the_granted_lifetime_not_the_requested_one() {
        // RFC 6887 §11.2.1. The value that matters is what came back: a
        // gateway that grants 120 seconds against a request for 7200 must be
        // renewed against the 120, and renewing on the request is how a
        // mapping is lost on exactly the gateways that trim.
        let granted = Mapping {
            protocol: Protocol::Pcp,
            transport: Transport::Udp,
            internal_port: 51820,
            external_port: 40000,
            external_address: None,
            lifetime: Duration::from_secs(120),
        };
        assert_eq!(granted.renew_after(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn a_deletion_has_nothing_to_renew() {
        let deleted = Mapping {
            protocol: Protocol::Pcp,
            transport: Transport::Udp,
            internal_port: 51820,
            external_port: 0,
            external_address: None,
            lifetime: Duration::ZERO,
        };
        assert_eq!(deleted.renew_after(), None);
    }

    #[test]
    fn the_pcp_codes_are_the_rfcs_numbers_and_not_plausible_looking_ones() {
        // RFC 6887 §7.4, spelled out because getting this wrong is invisible:
        // both the right and the wrong set look reasonable in a diff.
        assert!(ResultCode::Pcp(7).is_transient(), "7 NETWORK_FAILURE");
        assert!(ResultCode::Pcp(8).is_transient(), "8 NO_RESOURCES");
        assert!(
            ResultCode::Pcp(11).is_transient(),
            "11 CANNOT_PROVIDE_EXTERNAL"
        );
        assert!(
            ResultCode::Pcp(13).is_transient(),
            "13 EXCESSIVE_REMOTE_PEERS"
        );
        assert!(
            !ResultCode::Pcp(4).is_transient(),
            "4 is UNSUPP_OPCODE — a gateway that does not implement MAP will \
             not start doing so, and retrying is traffic that cannot work"
        );
        assert!(
            !ResultCode::Pcp(12).is_transient(),
            "12 is ADDRESS_MISMATCH — the client sent an address that does not \
             match its own source, and an unchanged retry reproduces it"
        );
    }

    #[test]
    fn an_unknown_result_code_is_permanent_rather_than_retried_forever() {
        // The default matters more than the listed cases. A code nobody here
        // has heard of costs one attempt; treating unknowns as transient would
        // make any future code a retry loop against a gateway that has already
        // said no.
        assert!(!ResultCode::Pcp(200).is_transient());
        assert!(!ResultCode::NatPmp(999).is_transient());
        assert!(ResultCode::Pcp(8).is_transient());
        assert!(ResultCode::NatPmp(4).is_transient());
    }

    #[test]
    fn the_same_number_means_different_things_in_the_two_protocols() {
        // NAT-PMP 2 is "not authorized/refused" and PCP 2 is "not authorized",
        // but NAT-PMP 3 is network failure while PCP 3 is malformed request.
        // Merging the two numberings would have made this pair silently wrong,
        // which is why `ResultCode` keeps them apart.
        assert!(ResultCode::NatPmp(3).is_transient());
        assert!(!ResultCode::Pcp(3).is_transient());
    }

    #[test]
    fn an_ipv4_mapped_address_comes_back_as_ipv4() {
        // RFC 6887 §5 carries IPv4 in the mapped form. A caller that
        // advertised `::ffff:c000:0201` as a candidate would be naming
        // something no peer turns into a UDP destination.
        let mut wire = vec![0u8; 16];
        wire[10] = 0xff;
        wire[11] = 0xff;
        wire[12..16].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(
            pcp_address(&wire, 0),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
    }

    #[test]
    fn address_encoding_round_trips_both_families() {
        for addr in [
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            let mut out = Vec::new();
            put_pcp_address(&mut out, addr);
            assert_eq!(out.len(), 16);
            assert_eq!(pcp_address(&out, 0), Some(addr));
        }
    }

    #[test]
    fn readers_refuse_to_run_off_the_end() {
        let short = [1u8, 2, 3];
        assert_eq!(be16(&short, 2), None);
        assert_eq!(be32(&short, 0), None);
        assert_eq!(pcp_address(&short, 0), None);
        // And at the very edge of `usize`, where a checked_add is what stands
        // between this and a panic on the pre-authentication path.
        assert_eq!(be16(&short, usize::MAX), None);
        assert_eq!(be32(&short, usize::MAX), None);
        assert_eq!(pcp_address(&short, usize::MAX), None);
    }
}
