// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! PCP — RFC 6887.
//!
//! One exchange is needed: `MAP` (opcode 1) asks the gateway to forward a port
//! and tells us the external address as part of the same answer, which is the
//! practical improvement over NAT-PMP's two round trips.
//!
//! # The nonce is the interesting field
//!
//! Every `MAP` carries a 96-bit **mapping nonce** which the gateway echoes.
//! RFC 6887 §11.2 gives it two jobs. It matches a response to a request, which
//! NAT-PMP cannot do at all. And it is what makes an off-path forgery need a
//! guess: anything on the link can send a datagram from the gateway's address,
//! but it cannot produce a response that this client will accept without
//! knowing a value it never saw.
//!
//! **That is not authentication and this module does not pretend otherwise.**
//! Anything that can *observe* the request has the nonce. It raises the cost
//! from "send a packet" to "be on the path", which is worth having and is not
//! the same as being secure — see the crate documentation for why the
//! consequences are bounded.
//!
//! # Where the client address comes from
//!
//! The request carries the client's own internal address, and RFC 6887 §8.1
//! requires the gateway to check it against the packet's source. This module
//! takes it as a parameter rather than discovering it, because the value that
//! must go here is the address of the **socket the mapping is for** — mapping a
//! port on one interface and announcing it from another is a mapping that
//! silently covers nothing.

use core::net::IpAddr;
use core::time::Duration;

use crate::{
    be16, be32, pcp_address, put_pcp_address, Error, Mapping, Protocol, ResultCode, Transport,
    ANY_V4, RESPONSE_MAX,
};

/// Ask the gateway to forward a port — RFC 6887 §11.
pub const OP_MAP: u8 = 1;

/// Set in the opcode of every response — RFC 6887 §7.2.
const RESPONSE_BIT: u8 = 0x80;

/// Length of the mapping nonce, in bytes — RFC 6887 §11.1.
pub const NONCE_LEN: usize = 12;

/// Wire size of a `MAP` request with no options.
pub const MAP_REQUEST_LEN: usize = 60;
/// Wire size of a `MAP` response, before any options.
pub const MAP_RESPONSE_LEN: usize = 60;

/// The lifetime RFC 6887 §15 suggests for a long-lived mapping: two hours.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(7200);

/// A `MAP` request's nonce.
///
/// Held as its own type so it cannot be confused with any other twelve bytes,
/// and because the comparison on the response path must be against the exact
/// value sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce(pub [u8; NONCE_LEN]);

/// Encode a `MAP` request — RFC 6887 §11.1.
///
/// `client` is the address of the socket being mapped; see the module
/// documentation. A `lifetime` of zero deletes the mapping.
#[must_use]
pub fn encode_map(
    nonce: Nonce,
    transport: Transport,
    internal_port: u16,
    external_port: u16,
    client: IpAddr,
    lifetime: Duration,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAP_REQUEST_LEN);
    out.push(Protocol::Pcp.version());
    out.push(OP_MAP); // response bit clear: this is a request
    out.extend_from_slice(&[0, 0]); // reserved
    let secs = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
    out.extend_from_slice(&secs.to_be_bytes());
    put_pcp_address(&mut out, client);

    out.extend_from_slice(&nonce.0);
    out.push(transport.number());
    out.extend_from_slice(&[0, 0, 0]); // reserved
    out.extend_from_slice(&internal_port.to_be_bytes());
    // RFC 6887 §11.1: a suggested external port of zero asks the gateway to
    // choose. On a delete it is ignored, and zero is sent for the same reason
    // NAT-PMP forces it — a deletion that also names a port reads as a request
    // to some implementations.
    let suggested = if lifetime.is_zero() { 0 } else { external_port };
    out.extend_from_slice(&suggested.to_be_bytes());
    // The suggested external address. Unspecified means "any", which is what a
    // client wants unless it is re-requesting a mapping it already holds.
    put_pcp_address(&mut out, IpAddr::V4(ANY_V4));
    out
}

/// Parse a `MAP` response.
///
/// # Errors
///
/// [`Error::TooLong`] before anything is read; [`Error::TooShort`];
/// [`Error::BadVersion`]; [`Error::NotAResponse`]; [`Error::OpcodeMismatch`];
/// [`Error::Refused`] carrying the gateway's code; [`Error::NonceMismatch`]
/// when the echoed nonce is not the one sent; and [`Error::Malformed`] for a
/// protocol number PCP does not define.
pub fn decode_map(datagram: &[u8], sent: Nonce) -> Result<Mapping, Error> {
    if datagram.len() > RESPONSE_MAX {
        return Err(Error::TooLong(datagram.len()));
    }
    let got = datagram.len();
    // Version, opcode, reserved, result code — the fixed header, readable
    // before anything else is known about the message.
    let header = 4;
    if got < header {
        return Err(Error::TooShort { need: header, got });
    }
    let version = *datagram
        .first()
        .ok_or(Error::TooShort { need: header, got })?;
    if version != Protocol::Pcp.version() {
        return Err(Error::BadVersion(version));
    }
    let opcode = *datagram
        .get(1)
        .ok_or(Error::TooShort { need: header, got })?;
    if opcode & RESPONSE_BIT == 0 {
        return Err(Error::NotAResponse(opcode));
    }
    let answered = opcode & !RESPONSE_BIT;
    if answered != OP_MAP {
        return Err(Error::OpcodeMismatch {
            sent: OP_MAP,
            got: answered,
        });
    }

    // **Refusal before body, as in NAT-PMP and for the same reason.** RFC 6887
    // §7.2 puts the result code at byte 3 precisely so it can be read from the
    // header alone.
    let code = *datagram
        .get(3)
        .ok_or(Error::TooShort { need: header, got })?;
    if code != 0 {
        return Err(Error::Refused(ResultCode::Pcp(code)));
    }

    let need = MAP_RESPONSE_LEN;
    if got < need {
        return Err(Error::TooShort { need, got });
    }

    // **The nonce is checked before any field is believed**, so a response that
    // is not ours cannot contribute a port, an address or a lifetime even
    // transiently.
    let echoed: &[u8] = datagram.get(24..36).ok_or(Error::TooShort { need, got })?;
    if echoed != sent.0 {
        return Err(Error::NonceMismatch);
    }

    let lifetime = be32(datagram, 4).ok_or(Error::TooShort { need, got })?;
    let proto = *datagram.get(36).ok_or(Error::TooShort { need, got })?;
    let transport = Transport::from_number(proto).ok_or(Error::Malformed)?;
    let internal_port = be16(datagram, 40).ok_or(Error::TooShort { need, got })?;
    let external_port = be16(datagram, 42).ok_or(Error::TooShort { need, got })?;
    let external_address = pcp_address(datagram, 44).ok_or(Error::TooShort { need, got })?;

    Ok(Mapping {
        protocol: Protocol::Pcp,
        transport,
        internal_port,
        external_port,
        external_address: Some(external_address),
        lifetime: Duration::from_secs(u64::from(lifetime)),
    })
}

/// The gateway's epoch, for the restart check — RFC 6887 §8.5.
///
/// Returns `None` when the datagram is too short to hold one, which is the
/// same condition [`decode_map`] refuses on; it is separate so a caller can
/// run the restart check on a response it is otherwise discarding.
#[must_use]
pub fn epoch(datagram: &[u8]) -> Option<u32> {
    be32(datagram, 8)
}

/// Whether a PCP gateway's epoch indicates it lost its state — RFC 6887 §8.5.
///
/// **This is not NAT-PMP's rule and the difference is the point.** NAT-PMP says
/// any backwards step means a reboot. PCP's epoch is a free-running clock, so
/// the client also has to notice a *forward* step that is too small for the
/// wall-clock time that has passed — a gateway whose epoch advanced by 3
/// seconds while 600 seconds elapsed has restarted, even though nothing went
/// backwards. RFC 6887 §8.5 gives the tolerance used here: the epoch must have
/// advanced by at least the elapsed time less one eighth of it, plus a second
/// of slack.
#[must_use]
pub fn gateway_lost_state(previous: u32, current: u32, elapsed: Duration) -> bool {
    if current < previous {
        return true;
    }
    let advanced = u64::from(current.saturating_sub(previous));
    let secs = elapsed.as_secs();
    // The RFC's expression, in integer arithmetic: elapsed - elapsed/8 - 1.
    let expected = secs.saturating_sub(secs / 8).saturating_sub(1);
    advanced < expected
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
    use core::net::Ipv4Addr;

    const NONCE: Nonce = Nonce([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));

    fn ok_response(nonce: Nonce, life: u32, internal: u16, external: u16) -> Vec<u8> {
        let mut v = vec![Protocol::Pcp.version(), OP_MAP | RESPONSE_BIT, 0, 0];
        v.extend_from_slice(&life.to_be_bytes()); // 4..8 lifetime
        v.extend_from_slice(&7u32.to_be_bytes()); // 8..12 epoch
        v.extend_from_slice(&[0u8; 12]); // 12..24 reserved
        v.extend_from_slice(&nonce.0); // 24..36
        v.push(Transport::Udp.number()); // 36
        v.extend_from_slice(&[0, 0, 0]); // 37..40 reserved
        v.extend_from_slice(&internal.to_be_bytes()); // 40..42
        v.extend_from_slice(&external.to_be_bytes()); // 42..44
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..16].copy_from_slice(&[203, 0, 113, 4]);
        v.extend_from_slice(&mapped); // 44..60
        v
    }

    #[test]
    fn a_request_is_the_size_the_rfc_gives() {
        let wire = encode_map(NONCE, Transport::Udp, 51820, 0, CLIENT, DEFAULT_LIFETIME);
        assert_eq!(wire.len(), MAP_REQUEST_LEN);
        assert_eq!(MAP_REQUEST_LEN, 60, "RFC 6887 §11.1");
    }

    #[test]
    fn a_request_lays_out_as_the_rfc_says() {
        let wire = encode_map(
            NONCE,
            Transport::Udp,
            51820,
            40000,
            CLIENT,
            DEFAULT_LIFETIME,
        );
        assert_eq!(wire[0], 2, "version");
        assert_eq!(wire[1], OP_MAP, "opcode, response bit clear");
        assert_eq!(be32(&wire, 4), Some(7200), "requested lifetime");
        // RFC 6887 §7.1: the common request header is version, R+opcode,
        // two reserved bytes, a 32-bit lifetime, and *then* the client
        // address — so it starts at 8, not at 12. Getting this wrong shifts
        // every opcode-specific field after it by four bytes, which is what
        // the first version of this test asserted and the encoder did not do.
        assert_eq!(
            pcp_address(&wire, 8),
            Some(CLIENT),
            "the client address the gateway checks against the source"
        );
        assert_eq!(wire.get(24..36), Some(&NONCE.0[..]), "nonce");
        assert_eq!(wire[36], 17, "UDP");
        assert_eq!(be16(&wire, 40), Some(51820), "internal port");
        assert_eq!(be16(&wire, 42), Some(40000), "suggested external port");
        assert_eq!(
            pcp_address(&wire, 44),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            "any external address"
        );
    }

    #[test]
    fn a_deletion_forces_the_suggested_port_to_zero() {
        let wire = encode_map(NONCE, Transport::Udp, 51820, 40000, CLIENT, Duration::ZERO);
        assert_eq!(be32(&wire, 4), Some(0), "lifetime");
        assert_eq!(be16(&wire, 40), Some(51820), "internal port is kept");
        assert_eq!(be16(&wire, 42), Some(0), "suggested port forced to zero");
    }

    #[test]
    fn a_response_decodes_and_reports_the_external_address() {
        // The improvement over NAT-PMP that justifies trying PCP first: the
        // address arrives with the mapping instead of in a second exchange.
        let wire = ok_response(NONCE, 3600, 51820, 40000);
        let m = decode_map(&wire, NONCE).expect("decodes");
        assert_eq!(m.protocol, Protocol::Pcp);
        assert_eq!(m.transport, Transport::Udp);
        assert_eq!(m.internal_port, 51820);
        assert_eq!(m.external_port, 40000);
        assert_eq!(
            m.external_address,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4))),
            "and unmapped from ::ffff: form"
        );
        assert_eq!(m.lifetime, Duration::from_secs(3600));
    }

    #[test]
    fn a_response_carrying_someone_elses_nonce_is_refused() {
        // The property the nonce exists for. Without this check, anything that
        // can send a datagram from the gateway's address decides what external
        // port this node advertises.
        let wire = ok_response(Nonce([9; NONCE_LEN]), 3600, 51820, 40000);
        assert_eq!(decode_map(&wire, NONCE), Err(Error::NonceMismatch));
    }

    #[test]
    fn the_nonce_is_checked_before_any_field_is_believed() {
        // A wrong-nonce response that *also* carries an absurd lifetime and a
        // private external address. The nonce check must be what rejects it,
        // so that ordering is not merely conventional.
        let mut wire = ok_response(Nonce([0xAA; NONCE_LEN]), u32::MAX, 1, 1);
        wire[44..60].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
        assert_eq!(decode_map(&wire, NONCE), Err(Error::NonceMismatch));
    }

    #[test]
    fn a_refusal_is_reported_from_the_header_alone() {
        let mut wire = vec![Protocol::Pcp.version(), OP_MAP | RESPONSE_BIT, 0, 8];
        wire.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            decode_map(&wire, NONCE),
            Err(Error::Refused(ResultCode::Pcp(8)))
        );
        assert!(
            ResultCode::Pcp(8).is_transient(),
            "NO_RESOURCES is worth retrying"
        );
    }

    #[test]
    fn an_undefined_protocol_number_is_refused() {
        let mut wire = ok_response(NONCE, 3600, 51820, 40000);
        wire[36] = 132; // SCTP, which PCP allows but this crate does not name
        assert_eq!(decode_map(&wire, NONCE), Err(Error::Malformed));
    }

    #[test]
    fn the_wrong_version_is_refused() {
        let mut wire = ok_response(NONCE, 3600, 1, 1);
        wire[0] = 0; // NAT-PMP's byte on a PCP decoder
        assert_eq!(decode_map(&wire, NONCE), Err(Error::BadVersion(0)));
    }

    #[test]
    fn a_request_arriving_as_a_response_is_refused() {
        let mut wire = ok_response(NONCE, 3600, 1, 1);
        wire[1] &= !RESPONSE_BIT;
        assert_eq!(decode_map(&wire, NONCE), Err(Error::NotAResponse(OP_MAP)));
    }

    #[test]
    fn every_truncation_is_refused_rather_than_read_past() {
        let full = ok_response(NONCE, 3600, 51820, 40000);
        for n in 0..full.len() {
            let short = full.get(..n).expect("prefix");
            let got = decode_map(short, NONCE);
            assert!(
                matches!(got, Err(Error::TooShort { .. })),
                "prefix of {n} bytes gave {got:?}"
            );
        }
        assert!(decode_map(&full, NONCE).is_ok());
    }

    #[test]
    fn an_over_long_datagram_is_refused_before_anything_is_read() {
        let huge = vec![0u8; RESPONSE_MAX + 1];
        assert_eq!(
            decode_map(&huge, NONCE),
            Err(Error::TooLong(RESPONSE_MAX + 1))
        );
    }

    #[test]
    fn trailing_options_do_not_prevent_a_response_decoding() {
        // RFC 6887 §7.3 allows options after the fixed part. A decoder that
        // demanded an exact length would refuse every gateway that sends one.
        let mut wire = ok_response(NONCE, 3600, 51820, 40000);
        wire.extend_from_slice(&[3, 0, 0, 16]);
        wire.extend_from_slice(&[0u8; 16]);
        assert!(decode_map(&wire, NONCE).is_ok());
    }

    #[test]
    fn a_backwards_epoch_means_lost_state() {
        assert!(gateway_lost_state(500, 10, Duration::from_secs(60)));
    }

    #[test]
    fn an_epoch_that_advanced_too_little_also_means_lost_state() {
        // The case NAT-PMP's rule misses entirely, and the reason PCP has its
        // own: 600 seconds passed and the gateway's clock moved 3, so it
        // restarted without the counter ever going backwards.
        assert!(gateway_lost_state(1000, 1003, Duration::from_secs(600)));
    }

    #[test]
    fn a_normally_advancing_epoch_is_not_a_restart() {
        // RFC 6887 §8.5's tolerance has to absorb ordinary clock skew, or
        // every node tears down and rebuilds its mappings on a schedule.
        assert!(!gateway_lost_state(1000, 1600, Duration::from_secs(600)));
        assert!(
            !gateway_lost_state(1000, 1540, Duration::from_secs(600)),
            "10% slow is within tolerance"
        );
        assert!(
            gateway_lost_state(1000, 1400, Duration::from_secs(600)),
            "but a third of the elapsed time is not"
        );
    }

    #[test]
    fn the_epoch_reader_refuses_a_short_datagram() {
        assert_eq!(epoch(&[0u8; 4]), None);
        assert_eq!(epoch(&ok_response(NONCE, 1, 1, 1)), Some(7));
    }
}
