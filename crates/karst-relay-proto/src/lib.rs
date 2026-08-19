// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! Ponor v1 relay framing and handshake.
//!
//! Implements `spec/ponor-v1.md`. This crate is **sans-io**: it turns bytes
//! into typed values and back and drives two state machines, and does no
//! network, clock or key access. Signing and verification are supplied by the
//! caller through [`Signer`] and [`Verifier`], and roster lookup through
//! [`Roster`], so the same code runs in `karstd`, in `karst-relay`, and in a
//! test with a stub that signs nothing.
//!
//! The frame decoder is on the **pre-authentication path** — it parses
//! attacker-controlled bytes before any signature is checked — so it is written
//! to be panic-free: no indexing, no slicing, no `unwrap`. Bounds are
//! discharged by `first_chunk` and `get`, and the fixed-size arrays are then
//! destructured.

pub mod frame;
pub mod handshake;

pub use frame::{Frame, Reason, Role};
pub use handshake::{
    client_auth_signing_input, relay_auth_signing_input, Admitted, AquiferId, ClientHandshake,
    RelayEntry, RelayHandshake, Roster, RosterEntry, Signer, Verifier,
};

pub mod consts {
    //! Normative constants — `spec/ponor-v1.md` §6.

    /// Protocol version carried in every handshake frame.
    pub const VERSION: u8 = 1;

    /// Frame header: one type byte and a 24-bit big-endian length.
    pub const FRAME_HEADER: usize = 4;

    /// Hard cap on a frame payload, checked **before** anything is allocated.
    ///
    /// The 24-bit length field can express 16 MB; this is what makes a frame
    /// header safe to act on. It is the smallest power of two above the
    /// largest legal frame ([`CLIENT_AUTH_LEN`], 3375 B), and it is enforced
    /// in addition to the exact per-type lengths, not instead of them.
    pub const FRAME_PAYLOAD_MAX: usize = 4096;

    /// Node and relay identifiers: a SHA-256 digest — §5.1, §5.2.
    pub const ID_LEN: usize = 32;

    /// Handshake nonce.
    pub const RANDOM_LEN: usize = 32;

    /// ML-DSA-65 signature. Suite `KARST_1` is the only suite in v1 and the
    /// version byte implies it, so this is fixed rather than negotiated; a
    /// second signature algorithm means a second protocol version.
    pub const SIG_LEN: usize = 3309;

    /// ML-DSA-65 public key.
    pub const IDENTITY_PK_LEN: usize = 1952;

    /// Largest relayed payload: the largest datagram PHREATIC emits
    /// (`phreatic-v1.md` §13.6, `TRANSPORT_DATAGRAM_MAX`).
    ///
    /// A relay never sees a larger one because a PHREATIC transport message
    /// never fragments and the tunnel MTU cannot drop below 1280.
    pub const PAYLOAD_MAX: usize = 1336;

    /// Smallest relayed payload. Zero is rejected: it costs a frame header and
    /// delivers nothing, which makes it a pure amplification unit.
    pub const PAYLOAD_MIN: usize = 1;

    /// `RelayHello`: version, `relay_id`, `relay_random`.
    pub const RELAY_HELLO_LEN: usize = 1 + ID_LEN + RANDOM_LEN;
    /// `ClientAuth`: version, role, `peer_id`, `client_random`, signature.
    pub const CLIENT_AUTH_LEN: usize = 1 + 1 + ID_LEN + RANDOM_LEN + SIG_LEN;
    /// `RelayAuth`: version, signature.
    pub const RELAY_AUTH_LEN: usize = 1 + SIG_LEN;
    /// `PeerGone`: peer id and reason.
    pub const PEER_GONE_LEN: usize = ID_LEN + 1;
    /// `Ping` / `Pong` token.
    pub const TOKEN_LEN: usize = 8;
    /// `Restarting`: two 32-bit millisecond fields.
    pub const RESTARTING_LEN: usize = 8;

    /// An AVEN reflect key — §7.7, `aven-v1.md` §5.3.
    pub const REFLECT_KEY_LEN: usize = 32;

    /// An endpoint in `aven-v1.md` §6.2's encoding: family, address, port.
    ///
    /// Ponor carries this shape only here, and it is AVEN's rather than
    /// Ponor's — repeated as a constant instead of imported so that this crate
    /// keeps no dependency on `karst-disco`, which depends on nothing and is
    /// the layer below. `karst-relay`'s reflector tests hold the two in step.
    pub const ENDPOINT_LEN: usize = 1 + 16 + 2;

    /// `ReflectOffer`: a reflect key and the reflector's endpoint.
    pub const REFLECT_OFFER_LEN: usize = REFLECT_KEY_LEN + ENDPOINT_LEN;

    /// A relay MUST close a connection on which `ClientAuth` has not arrived
    /// within this long — §7.1. Connection slots are the scarce resource.
    pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

    /// A client SHOULD send `Ping` this often on an idle connection — §7.5.
    pub const KEEPALIVE_SECS: u64 = 30;

    /// A relay MUST close a connection from which nothing has been received
    /// for this long — three missed keepalives, §7.5.
    pub const IDLE_TIMEOUT_SECS: u64 = 90;

    /// Recommended per-destination write queue depth — §7.3.
    pub const WRITE_QUEUE_DEPTH: usize = 32;
}

/// Everything that can go wrong parsing or driving Ponor.
///
/// The relay's wire response to any variant marked *rejection* is a bare
/// connection close with no `Close` frame and no reason — `spec/ponor-v1.md`
/// §10. These variants are distinguished for the operator's metrics and logs,
/// never for the peer. `handshake::tests::rejections_are_indistinguishable` is
/// what holds that line: an unknown id, a bad signature and a wrong role all
/// produce the identical error, so the caller has nothing to key a response
/// off even if it wanted to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The frame's declared length exceeds [`consts::FRAME_PAYLOAD_MAX`].
    /// Detected before any allocation.
    FrameTooLarge(usize),
    /// The type byte is not one Ponor v1 defines. Not skippable: v1 has no
    /// forward-compatible extension point, because silently ignoring unknown
    /// frames is how a downgrade is mounted against a protocol with no other
    /// negotiation to attack.
    UnknownFrameType(u8),
    /// The payload length is not what this frame type requires.
    BadFrameLength {
        /// The frame's type byte.
        frame_type: u8,
        /// The length that arrived.
        got: usize,
    },
    /// A handshake frame carried a version this implementation does not speak.
    BadVersion(u8),
    /// The role byte is neither `CLIENT` nor `MESH`.
    BadRole(u8),
    /// A reason byte outside the defined set.
    BadReason(u8),
    /// A frame arrived that is legal in itself but not in this state — an
    /// envelope before the handshake, a second `ClientAuth`, a `SendPacket` on
    /// a mesh connection.
    OutOfOrder,
    /// *Rejection.* The peer is not admitted, or its signature did not verify.
    /// Deliberately does not say which — see the type-level note.
    Rejected,
    /// *Rejection.* The relay this client reached is not the one it intended.
    RelayIdentityMismatch,
    /// The signer refused. Never a peer's fault.
    SignerUnavailable,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FrameTooLarge(n) => write!(f, "frame length {n} exceeds the cap"),
            Self::UnknownFrameType(t) => write!(f, "unknown frame type {t:#04x}"),
            Self::BadFrameLength { frame_type, got } => {
                write!(f, "frame type {frame_type:#04x} cannot have length {got}")
            }
            Self::BadVersion(v) => write!(f, "unsupported protocol version {v}"),
            Self::BadRole(r) => write!(f, "unknown role {r:#04x}"),
            Self::BadReason(r) => write!(f, "unknown reason {r:#04x}"),
            Self::OutOfOrder => f.write_str("frame is not legal in this state"),
            Self::Rejected => f.write_str("rejected"),
            Self::RelayIdentityMismatch => f.write_str("relay is not the one expected"),
            Self::SignerUnavailable => f.write_str("signing key unavailable"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::consts::*;

    #[test]
    fn frame_lengths_match_the_spec() {
        // spec/ponor-v1.md §6.1. A change here should show up as a diff
        // against the specification rather than as drift.
        assert_eq!(RELAY_HELLO_LEN, 65);
        assert_eq!(CLIENT_AUTH_LEN, 3375);
        assert_eq!(RELAY_AUTH_LEN, 3310);
        assert_eq!(PEER_GONE_LEN, 33);
        assert_eq!(ID_LEN + PAYLOAD_MAX, 1368); // SendPacket / RecvPacket max
        assert_eq!(2 * ID_LEN + PAYLOAD_MAX, 1400); // Forward max
    }

    #[test]
    fn the_cap_admits_every_legal_frame() {
        // The cap is what makes a frame header safe to act on, so it has to be
        // above the largest legal frame — and the largest legal frame is the
        // handshake's, not the datapath's.
        let largest = CLIENT_AUTH_LEN
            .max(RELAY_AUTH_LEN)
            .max(2 * ID_LEN + PAYLOAD_MAX);
        assert!(
            largest <= FRAME_PAYLOAD_MAX,
            "{largest} > {FRAME_PAYLOAD_MAX}"
        );
    }

    #[test]
    fn handshake_costs_under_seven_kilobytes() {
        // §5.2 of karst-control-v1.md records ~12 KB to open a control
        // channel. Ponor is cheaper because it derives no keys, and the figure
        // is recorded so a future field addition is a visible cost.
        let total = 3 * FRAME_HEADER + RELAY_HELLO_LEN + CLIENT_AUTH_LEN + RELAY_AUTH_LEN;
        assert_eq!(total, 6762);
    }
}
