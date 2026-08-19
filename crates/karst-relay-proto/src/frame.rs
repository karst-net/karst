// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Ponor frames — `spec/ponor-v1.md` §6.
//!
//! Decoding borrows from the input buffer, so relaying a packet copies it once
//! into the destination's queue rather than twice.

use crate::consts::{
    CLIENT_AUTH_LEN, ENDPOINT_LEN, FRAME_HEADER, FRAME_PAYLOAD_MAX, ID_LEN, PAYLOAD_MAX,
    PAYLOAD_MIN, PEER_GONE_LEN, RANDOM_LEN, REFLECT_KEY_LEN, REFLECT_OFFER_LEN, RELAY_AUTH_LEN,
    RELAY_HELLO_LEN, RESTARTING_LEN, SIG_LEN, TOKEN_LEN, VERSION,
};
use crate::Error;

/// Which side of the protocol a connecting peer is.
///
/// Bound into both signatures (§5.5) so that a client's authentication cannot
/// be replayed as a mesh peer's, which would grant it §8's forwarding
/// privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// A node.
    Client,
    /// Another relay in the same region.
    Mesh,
}

impl Role {
    const CLIENT: u8 = 0x01;
    const MESH: u8 = 0x02;

    /// # Errors
    /// [`Error::BadRole`] for any byte outside the defined set. There is no
    /// default: an unrecognised role must not fall through to `Client`.
    pub fn from_wire(b: u8) -> Result<Self, Error> {
        match b {
            Self::CLIENT => Ok(Self::Client),
            Self::MESH => Ok(Self::Mesh),
            other => Err(Error::BadRole(other)),
        }
    }

    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Client => Self::CLIENT,
            Self::Mesh => Self::MESH,
        }
    }
}

/// Why a peer is gone, or why a connection is closing — §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// Not connected to this relay or its mesh.
    NotHere,
    /// Was here and has gone.
    Disconnected,
    /// Not in the roster, or not in this tailnet.
    NotAdmitted,
    /// A newer connection for this id has been accepted.
    Replaced,
    /// Sustained excess over the rate budget — §7.4.
    RateLimited,
    /// The relay is shutting down.
    ShuttingDown,
    /// A malformed or illegal frame.
    ProtocolError,
}

impl Reason {
    /// # Errors
    /// [`Error::BadReason`] for any byte outside the defined set.
    pub fn from_wire(b: u8) -> Result<Self, Error> {
        match b {
            0x00 => Ok(Self::NotHere),
            0x01 => Ok(Self::Disconnected),
            0x02 => Ok(Self::NotAdmitted),
            0x03 => Ok(Self::Replaced),
            0x04 => Ok(Self::RateLimited),
            0x05 => Ok(Self::ShuttingDown),
            0x06 => Ok(Self::ProtocolError),
            other => Err(Error::BadReason(other)),
        }
    }

    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::NotHere => 0x00,
            Self::Disconnected => 0x01,
            Self::NotAdmitted => 0x02,
            Self::Replaced => 0x03,
            Self::RateLimited => 0x04,
            Self::ShuttingDown => 0x05,
            Self::ProtocolError => 0x06,
        }
    }
}

/// A Ponor frame.
///
/// `Copy`: every field is a fixed-size array, a shared slice or a small scalar,
/// so a frame is a handful of words and callers should be free to match on one
/// by value rather than fighting a borrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// `0x01` relay → peer. The relay speaks first, so the peer signs over a
    /// value it has not yet seen and a captured `ClientAuth` is useless
    /// elsewhere — §7.1.
    RelayHello {
        /// `SHA-256("karst-relay-id-v1" ‖ relay_identity_pk)`.
        relay_id: [u8; ID_LEN],
        /// Freshness for the peer's signature.
        relay_random: [u8; RANDOM_LEN],
    },
    /// `0x02` peer → relay. Carries **no public key**: the relay looks the
    /// peer up in its roster, which is what makes admission structural (§5.3).
    ClientAuth {
        /// Client or mesh peer.
        role: Role,
        /// `node_id` for a client, `relay_id` for a mesh peer.
        peer_id: [u8; ID_LEN],
        /// Freshness for the relay's signature.
        client_random: [u8; RANDOM_LEN],
        /// ML-DSA-65 over §5.5.
        signature: &'a [u8],
    },
    /// `0x03` relay → peer. The peer MUST verify this before sending anything
    /// beyond `ClientAuth`.
    RelayAuth {
        /// ML-DSA-65 over §5.5.
        signature: &'a [u8],
    },
    /// `0x04` client → relay. There is no source field, so there is nothing to
    /// spoof; the relay stamps the connection's authenticated id.
    SendPacket {
        /// Destination node.
        dst_id: [u8; ID_LEN],
        /// Opaque PHREATIC datagram. The relay MUST NOT parse it.
        payload: &'a [u8],
    },
    /// `0x05` relay → client.
    RecvPacket {
        /// Source node, stamped by the relay.
        src_id: [u8; ID_LEN],
        /// Opaque PHREATIC datagram.
        payload: &'a [u8],
    },
    /// `0x06` relay → peer.
    PeerGone {
        /// The peer that is unreachable.
        peer_id: [u8; ID_LEN],
        /// Why.
        reason: Reason,
    },
    /// `0x07` either direction. Also the client's RTT measurement for
    /// home-relay selection — §7.5.
    Ping(&'a [u8; TOKEN_LEN]),
    /// `0x08` either direction. Echoes the token exactly.
    Pong(&'a [u8; TOKEN_LEN]),
    /// `0x09` relay → peer. Graceful drain; clients add jitter, or a restart
    /// becomes an outage — §7.6.
    Restarting {
        /// Wait this long before reconnecting.
        reconnect_in_ms: u32,
        /// Keep retrying for this long.
        try_for_ms: u32,
    },
    /// `0x0a` either direction.
    Close(Reason),
    /// `0x0b` mesh → mesh. This node is connected to me.
    PeerPresent {
        /// The node now reachable through the sending relay.
        node_id: [u8; ID_LEN],
    },
    /// `0x0c` mesh → mesh. One hop only: a relay MUST NOT forward a `Forward`
    /// onward, so a mesh loop is not expressible rather than merely bounded.
    Forward {
        /// Original source node.
        src_id: [u8; ID_LEN],
        /// Destination node, held by the receiving relay.
        dst_id: [u8; ID_LEN],
        /// Opaque PHREATIC datagram.
        payload: &'a [u8],
    },
    /// `0x0d` relay → client. The key and address of this relay's AVEN
    /// reflector — §7.7, `aven-v1.md` §7.6.
    ///
    /// **Optional in both directions.** A relay without a reflector never sends
    /// one; a client that never receives one degrades to `aven-v1.md` §7.2 and
    /// stays on the relay when that is not enough.
    ReflectOffer {
        /// 32 bytes from a CSPRNG, minted for this connection and forgotten
        /// when it closes. Sent only after `RelayAuth`, so a client that
        /// follows §7.1 has already authenticated whoever minted it.
        reflect_key: [u8; REFLECT_KEY_LEN],
        /// Where to send `Reflect`, in `aven-v1.md` §6.2's encoding.
        ///
        /// Carried rather than inferred from the Ponor connection: the
        /// reflector is a different socket, on a different port and possibly a
        /// different host behind a load balancer that terminates TCP and not
        /// UDP — which is the deployment §4.2 exists for.
        endpoint: [u8; ENDPOINT_LEN],
    },
}

const T_RELAY_HELLO: u8 = 0x01;
const T_CLIENT_AUTH: u8 = 0x02;
const T_RELAY_AUTH: u8 = 0x03;
const T_SEND_PACKET: u8 = 0x04;
const T_RECV_PACKET: u8 = 0x05;
const T_PEER_GONE: u8 = 0x06;
const T_PING: u8 = 0x07;
const T_PONG: u8 = 0x08;
const T_RESTARTING: u8 = 0x09;
const T_CLOSE: u8 = 0x0a;
const T_PEER_PRESENT: u8 = 0x0b;
const T_FORWARD: u8 = 0x0c;
const T_REFLECT_OFFER: u8 = 0x0d;

/// Split a fixed-size prefix off a slice without indexing.
fn take<const N: usize>(buf: &[u8]) -> Option<(&[u8; N], &[u8])> {
    Some((buf.first_chunk::<N>()?, buf.get(N..)?))
}

impl Frame<'_> {
    /// The type byte this frame encodes as.
    #[must_use]
    pub const fn frame_type(&self) -> u8 {
        match self {
            Self::RelayHello { .. } => T_RELAY_HELLO,
            Self::ClientAuth { .. } => T_CLIENT_AUTH,
            Self::RelayAuth { .. } => T_RELAY_AUTH,
            Self::SendPacket { .. } => T_SEND_PACKET,
            Self::RecvPacket { .. } => T_RECV_PACKET,
            Self::PeerGone { .. } => T_PEER_GONE,
            Self::Ping(_) => T_PING,
            Self::Pong(_) => T_PONG,
            Self::Restarting { .. } => T_RESTARTING,
            Self::Close(_) => T_CLOSE,
            Self::PeerPresent { .. } => T_PEER_PRESENT,
            Self::Forward { .. } => T_FORWARD,
            Self::ReflectOffer { .. } => T_REFLECT_OFFER,
        }
    }

    /// Append the encoded frame — header and payload — to `out`.
    ///
    /// Encoding cannot fail: every variant that carries a variable-length
    /// field is only constructible from values this crate has already
    /// length-checked on the way in, and the datapath variants are checked
    /// again here in debug builds.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&[self.frame_type(), 0, 0, 0]);

        match *self {
            Self::RelayHello {
                relay_id,
                relay_random,
            } => {
                out.push(VERSION);
                out.extend_from_slice(&relay_id);
                out.extend_from_slice(&relay_random);
            }
            Self::ClientAuth {
                role,
                peer_id,
                client_random,
                signature,
            } => {
                out.push(VERSION);
                out.push(role.to_wire());
                out.extend_from_slice(&peer_id);
                out.extend_from_slice(&client_random);
                out.extend_from_slice(signature);
            }
            Self::RelayAuth { signature } => {
                out.push(VERSION);
                out.extend_from_slice(signature);
            }
            Self::SendPacket {
                dst_id: id,
                payload,
            }
            | Self::RecvPacket {
                src_id: id,
                payload,
            } => {
                out.extend_from_slice(&id);
                out.extend_from_slice(payload);
            }
            Self::PeerGone { peer_id, reason } => {
                out.extend_from_slice(&peer_id);
                out.push(reason.to_wire());
            }
            Self::Ping(token) | Self::Pong(token) => out.extend_from_slice(token),
            Self::Restarting {
                reconnect_in_ms,
                try_for_ms,
            } => {
                out.extend_from_slice(&reconnect_in_ms.to_be_bytes());
                out.extend_from_slice(&try_for_ms.to_be_bytes());
            }
            Self::Close(reason) => out.push(reason.to_wire()),
            Self::PeerPresent { node_id } => out.extend_from_slice(&node_id),
            Self::Forward {
                src_id,
                dst_id,
                payload,
            } => {
                out.extend_from_slice(&src_id);
                out.extend_from_slice(&dst_id);
                out.extend_from_slice(payload);
            }
            Self::ReflectOffer {
                reflect_key,
                endpoint,
            } => {
                out.extend_from_slice(&reflect_key);
                out.extend_from_slice(&endpoint);
            }
        }

        // The length is written after the fact so no variant has to know its
        // own size. `saturating_sub` because a caller that handed us a
        // pre-filled buffer must not be able to make this arithmetic wrap.
        let len = out.len().saturating_sub(start).saturating_sub(FRAME_HEADER);
        debug_assert!(len <= FRAME_PAYLOAD_MAX, "encoded an over-long frame");
        #[allow(clippy::cast_possible_truncation)]
        let be = (len as u32).to_be_bytes();
        if let Some(hdr) = out.get_mut(start.saturating_add(1)..start.saturating_add(FRAME_HEADER))
        {
            hdr.copy_from_slice(be.get(1..).unwrap_or(&[0, 0, 0]));
        }
    }

    /// Encode into a fresh buffer.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Size on the wire, header included.
    ///
    /// A decoder already knows this — it is the byte count `decode` returns —
    /// but a relay charges frames it *emits* against a budget too, and
    /// re-encoding a frame to measure it would be absurd. Kept honest by
    /// `tests::encoded_len_agrees_with_encode`, which checks it against the
    /// real encoder for every variant rather than trusting two hand-written
    /// sums to stay in step.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let payload = match *self {
            Self::RelayHello { .. } => RELAY_HELLO_LEN,
            Self::ClientAuth { signature, .. } => CLIENT_AUTH_LEN - SIG_LEN + signature.len(),
            Self::RelayAuth { signature } => RELAY_AUTH_LEN - SIG_LEN + signature.len(),
            Self::SendPacket { payload, .. } | Self::RecvPacket { payload, .. } => {
                ID_LEN + payload.len()
            }
            Self::PeerGone { .. } => PEER_GONE_LEN,
            Self::Ping(_) | Self::Pong(_) => TOKEN_LEN,
            Self::Restarting { .. } => RESTARTING_LEN,
            Self::Close(_) => 1,
            Self::PeerPresent { .. } => ID_LEN,
            Self::Forward { payload, .. } => 2 * ID_LEN + payload.len(),
            Self::ReflectOffer { .. } => REFLECT_OFFER_LEN,
        };
        FRAME_HEADER + payload
    }
}

/// Decode one frame from the front of `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet hold a whole frame, and the
/// number of bytes consumed alongside the frame when it does. The caller keeps
/// the buffer; this crate holds none.
///
/// # Errors
/// Any malformed frame. `spec/ponor-v1.md` §10 requires the connection to end
/// on all of them: the transport is ordered and authenticated, so a malformed
/// frame means tampering or a bug, and there is no recovery that does not
/// weaken the connection.
pub fn decode(buf: &[u8]) -> Result<Option<(Frame<'_>, usize)>, Error> {
    let Some(&[frame_type, l0, l1, l2]) = buf.first_chunk::<FRAME_HEADER>() else {
        return Ok(None);
    };
    let len = u32::from_be_bytes([0, l0, l1, l2]) as usize;

    // Before waiting for the body, and so before anything is sized from it.
    // This is the check that makes a 24-bit length field safe to act on.
    if len > FRAME_PAYLOAD_MAX {
        return Err(Error::FrameTooLarge(len));
    }

    let total = FRAME_HEADER.saturating_add(len);
    let Some(payload) = buf.get(FRAME_HEADER..total) else {
        return Ok(None);
    };

    Ok(Some((decode_payload(frame_type, payload)?, total)))
}

fn bad_len(frame_type: u8, got: usize) -> Error {
    Error::BadFrameLength { frame_type, got }
}

/// Reject a payload whose length is legal for its type but whose relayed
/// portion is empty or over-long.
fn check_payload(frame_type: u8, payload: &[u8]) -> Result<(), Error> {
    if payload.len() < PAYLOAD_MIN || payload.len() > PAYLOAD_MAX {
        return Err(bad_len(frame_type, payload.len()));
    }
    Ok(())
}

fn check_version(b: u8) -> Result<(), Error> {
    if b == VERSION {
        Ok(())
    } else {
        Err(Error::BadVersion(b))
    }
}

#[allow(clippy::too_many_lines)]
fn decode_payload(frame_type: u8, p: &[u8]) -> Result<Frame<'_>, Error> {
    let n = p.len();
    match frame_type {
        T_RELAY_HELLO => {
            if n != RELAY_HELLO_LEN {
                return Err(bad_len(frame_type, n));
            }
            let (version, rest) = take::<1>(p).ok_or_else(|| bad_len(frame_type, n))?;
            check_version(version[0])?;
            let (relay_id, rest) = take::<ID_LEN>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            let (relay_random, _) =
                take::<RANDOM_LEN>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            Ok(Frame::RelayHello {
                relay_id: *relay_id,
                relay_random: *relay_random,
            })
        }
        T_CLIENT_AUTH => {
            if n != CLIENT_AUTH_LEN {
                return Err(bad_len(frame_type, n));
            }
            let (head, rest) = take::<2>(p).ok_or_else(|| bad_len(frame_type, n))?;
            check_version(head[0])?;
            let role = Role::from_wire(head[1])?;
            let (peer_id, rest) = take::<ID_LEN>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            let (client_random, signature) =
                take::<RANDOM_LEN>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            Ok(Frame::ClientAuth {
                role,
                peer_id: *peer_id,
                client_random: *client_random,
                signature,
            })
        }
        T_RELAY_AUTH => {
            if n != RELAY_AUTH_LEN {
                return Err(bad_len(frame_type, n));
            }
            let (version, signature) = take::<1>(p).ok_or_else(|| bad_len(frame_type, n))?;
            check_version(version[0])?;
            Ok(Frame::RelayAuth { signature })
        }
        T_SEND_PACKET | T_RECV_PACKET => {
            let (id, payload) = take::<ID_LEN>(p).ok_or_else(|| bad_len(frame_type, n))?;
            check_payload(frame_type, payload)?;
            if frame_type == T_SEND_PACKET {
                Ok(Frame::SendPacket {
                    dst_id: *id,
                    payload,
                })
            } else {
                Ok(Frame::RecvPacket {
                    src_id: *id,
                    payload,
                })
            }
        }
        T_PEER_GONE => {
            if n != PEER_GONE_LEN {
                return Err(bad_len(frame_type, n));
            }
            let (peer_id, rest) = take::<ID_LEN>(p).ok_or_else(|| bad_len(frame_type, n))?;
            let (reason, _) = take::<1>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            Ok(Frame::PeerGone {
                peer_id: *peer_id,
                reason: Reason::from_wire(reason[0])?,
            })
        }
        T_PING | T_PONG => {
            let token = p
                .first_chunk::<TOKEN_LEN>()
                .filter(|_| n == TOKEN_LEN)
                .ok_or_else(|| bad_len(frame_type, n))?;
            if frame_type == T_PING {
                Ok(Frame::Ping(token))
            } else {
                Ok(Frame::Pong(token))
            }
        }
        T_RESTARTING => {
            if n != RESTARTING_LEN {
                return Err(bad_len(frame_type, n));
            }
            let (a, rest) = take::<4>(p).ok_or_else(|| bad_len(frame_type, n))?;
            let (b, _) = take::<4>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            Ok(Frame::Restarting {
                reconnect_in_ms: u32::from_be_bytes(*a),
                try_for_ms: u32::from_be_bytes(*b),
            })
        }
        T_CLOSE => {
            let byte = p
                .first_chunk::<1>()
                .filter(|_| n == 1)
                .ok_or_else(|| bad_len(frame_type, n))?;
            Ok(Frame::Close(Reason::from_wire(byte[0])?))
        }
        T_PEER_PRESENT => {
            let node_id = p
                .first_chunk::<ID_LEN>()
                .filter(|_| n == ID_LEN)
                .ok_or_else(|| bad_len(frame_type, n))?;
            Ok(Frame::PeerPresent { node_id: *node_id })
        }
        T_FORWARD => {
            let (src_id, rest) = take::<ID_LEN>(p).ok_or_else(|| bad_len(frame_type, n))?;
            let (dst_id, payload) = take::<ID_LEN>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            check_payload(frame_type, payload)?;
            Ok(Frame::Forward {
                src_id: *src_id,
                dst_id: *dst_id,
                payload,
            })
        }
        T_REFLECT_OFFER => {
            if n != REFLECT_OFFER_LEN {
                return Err(bad_len(frame_type, n));
            }
            let (reflect_key, rest) =
                take::<REFLECT_KEY_LEN>(p).ok_or_else(|| bad_len(frame_type, n))?;
            let (endpoint, _) = take::<ENDPOINT_LEN>(rest).ok_or_else(|| bad_len(frame_type, n))?;
            Ok(Frame::ReflectOffer {
                reflect_key: *reflect_key,
                endpoint: *endpoint,
            })
        }
        other => Err(Error::UnknownFrameType(other)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const SIG: [u8; SIG_LEN] = [0x5a; SIG_LEN];

    fn id(b: u8) -> [u8; ID_LEN] {
        [b; ID_LEN]
    }

    fn roundtrip(f: &Frame<'_>) {
        let bytes = f.to_vec();
        assert_eq!(
            f.encoded_len(),
            bytes.len(),
            "encoded_len disagrees with encode"
        );
        let (decoded, used) = decode(&bytes)
            .expect("decode should succeed")
            .expect("frame should be complete");
        assert_eq!(&decoded, f);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn every_frame_round_trips() {
        let token = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = [0xab; 1200];
        for f in [
            Frame::RelayHello {
                relay_id: id(1),
                relay_random: id(2),
            },
            Frame::ClientAuth {
                role: Role::Client,
                peer_id: id(3),
                client_random: id(4),
                signature: &SIG,
            },
            Frame::ClientAuth {
                role: Role::Mesh,
                peer_id: id(3),
                client_random: id(4),
                signature: &SIG,
            },
            Frame::RelayAuth { signature: &SIG },
            Frame::SendPacket {
                dst_id: id(5),
                payload: &payload,
            },
            Frame::RecvPacket {
                src_id: id(6),
                payload: &payload,
            },
            Frame::PeerGone {
                peer_id: id(7),
                reason: Reason::NotHere,
            },
            Frame::Ping(&token),
            Frame::Pong(&token),
            Frame::Restarting {
                reconnect_in_ms: 2_500,
                try_for_ms: 60_000,
            },
            Frame::Close(Reason::ShuttingDown),
            Frame::PeerPresent { node_id: id(8) },
            Frame::Forward {
                src_id: id(9),
                dst_id: id(10),
                payload: &payload,
            },
            Frame::ReflectOffer {
                reflect_key: [0x11; REFLECT_KEY_LEN],
                endpoint: [0x22; ENDPOINT_LEN],
            },
        ] {
            roundtrip(&f);
        }
    }

    #[test]
    fn encoded_lengths_match_the_spec() {
        let f = Frame::RelayHello {
            relay_id: id(1),
            relay_random: id(2),
        };
        assert_eq!(f.to_vec().len(), FRAME_HEADER + RELAY_HELLO_LEN);
        let f = Frame::ClientAuth {
            role: Role::Client,
            peer_id: id(1),
            client_random: id(2),
            signature: &SIG,
        };
        assert_eq!(f.to_vec().len(), FRAME_HEADER + CLIENT_AUTH_LEN);
        let f = Frame::RelayAuth { signature: &SIG };
        assert_eq!(f.to_vec().len(), FRAME_HEADER + RELAY_AUTH_LEN);
        let f = Frame::ReflectOffer {
            reflect_key: [0; REFLECT_KEY_LEN],
            endpoint: [0; ENDPOINT_LEN],
        };
        assert_eq!(f.to_vec().len(), FRAME_HEADER + REFLECT_OFFER_LEN);
        // spec/ponor-v1.md §6.1 says 51. Written as a literal so a change to
        // either constant shows up as a diff against the specification.
        assert_eq!(REFLECT_OFFER_LEN, 51);
    }

    #[test]
    fn a_partial_frame_is_incomplete_rather_than_an_error() {
        let bytes = Frame::PeerPresent { node_id: id(1) }.to_vec();
        for n in 0..bytes.len() {
            let prefix = bytes.get(..n).expect("in range");
            assert_eq!(decode(prefix), Ok(None), "prefix of {n} bytes");
        }
        assert!(matches!(decode(&bytes), Ok(Some(_))));
    }

    #[test]
    fn trailing_bytes_are_left_for_the_next_frame() {
        let mut buf = Frame::Close(Reason::NotHere).to_vec();
        let second = Frame::Ping(&[9; 8]).to_vec();
        buf.extend_from_slice(&second);

        let (first, used) = decode(&buf).expect("ok").expect("complete");
        assert_eq!(first, Frame::Close(Reason::NotHere));
        let rest = buf.get(used..).expect("in range");
        assert_eq!(rest.len(), second.len());
        let (next, _) = decode(rest).expect("ok").expect("complete");
        assert_eq!(next, Frame::Ping(&[9; 8]));
    }

    #[test]
    fn an_over_long_frame_is_rejected_before_the_body_arrives() {
        // The whole point of the cap: four bytes of header are enough to
        // reject it, so nothing is sized from an attacker's length field.
        let header = [T_SEND_PACKET, 0xff, 0xff, 0xff];
        assert_eq!(decode(&header), Err(Error::FrameTooLarge(0x00ff_ffff)));
    }

    #[test]
    fn an_unknown_type_is_an_error_not_a_skip() {
        // v1 has no forward-compatible extension point on purpose.
        let bytes = [0x7f, 0, 0, 0];
        assert_eq!(decode(&bytes), Err(Error::UnknownFrameType(0x7f)));
    }

    #[test]
    fn every_wrong_length_is_rejected() {
        // Walk each fixed-length frame one byte short and one byte long.
        for (ty, len) in [
            (T_REFLECT_OFFER, REFLECT_OFFER_LEN),
            (T_RELAY_HELLO, RELAY_HELLO_LEN),
            (T_CLIENT_AUTH, CLIENT_AUTH_LEN),
            (T_RELAY_AUTH, RELAY_AUTH_LEN),
            (T_PEER_GONE, PEER_GONE_LEN),
            (T_PING, TOKEN_LEN),
            (T_PONG, TOKEN_LEN),
            (T_RESTARTING, RESTARTING_LEN),
            (T_CLOSE, 1),
            (T_PEER_PRESENT, ID_LEN),
        ] {
            for wrong in [len - 1, len + 1] {
                let mut bytes = vec![ty, 0, 0, 0];
                #[allow(clippy::cast_possible_truncation)]
                let be = (wrong as u32).to_be_bytes();
                bytes.splice(1..4, be[1..].iter().copied());
                bytes.resize(FRAME_HEADER + wrong, VERSION);
                assert!(
                    matches!(decode(&bytes), Err(Error::BadFrameLength { .. })),
                    "type {ty:#04x} accepted length {wrong}, wanted {len}"
                );
            }
        }
    }

    #[test]
    fn an_empty_payload_is_rejected() {
        // A zero-length relayed payload costs a frame header and delivers
        // nothing, which makes it a pure amplification unit — §6.1.
        for ty in [T_SEND_PACKET, T_RECV_PACKET] {
            let mut bytes = vec![ty, 0, 0, u8::try_from(ID_LEN).expect("fits")];
            bytes.extend_from_slice(&id(1));
            assert!(matches!(decode(&bytes), Err(Error::BadFrameLength { .. })));
        }
        let mut bytes = vec![T_FORWARD, 0, 0, u8::try_from(2 * ID_LEN).expect("fits")];
        bytes.extend_from_slice(&id(1));
        bytes.extend_from_slice(&id(2));
        assert!(matches!(decode(&bytes), Err(Error::BadFrameLength { .. })));
    }

    #[test]
    fn a_payload_over_the_phreatic_maximum_is_rejected() {
        // 1336 is the largest datagram PHREATIC emits. Anything larger did not
        // come from a Karst node, and accepting it would make the relay a
        // general-purpose tunnel.
        let too_big = vec![0u8; PAYLOAD_MAX + 1];
        let f = Frame::SendPacket {
            dst_id: id(1),
            payload: &too_big,
        };
        assert!(matches!(
            decode(&f.to_vec()),
            Err(Error::BadFrameLength { .. })
        ));

        let exact = vec![0u8; PAYLOAD_MAX];
        let f = Frame::SendPacket {
            dst_id: id(1),
            payload: &exact,
        };
        assert!(matches!(decode(&f.to_vec()), Ok(Some(_))));
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let mut bytes = Frame::RelayHello {
            relay_id: id(1),
            relay_random: id(2),
        }
        .to_vec();
        *bytes.get_mut(FRAME_HEADER).expect("version byte") = 0xff;
        assert_eq!(decode(&bytes), Err(Error::BadVersion(0xff)));
    }

    #[test]
    fn an_unknown_role_does_not_fall_through_to_client() {
        let mut bytes = Frame::ClientAuth {
            role: Role::Client,
            peer_id: id(1),
            client_random: id(2),
            signature: &SIG,
        }
        .to_vec();
        *bytes.get_mut(FRAME_HEADER + 1).expect("role byte") = 0x03;
        assert_eq!(decode(&bytes), Err(Error::BadRole(0x03)));
    }

    #[test]
    fn an_unknown_reason_is_rejected() {
        let mut bytes = Frame::Close(Reason::NotHere).to_vec();
        *bytes.get_mut(FRAME_HEADER).expect("reason byte") = 0x40;
        assert_eq!(decode(&bytes), Err(Error::BadReason(0x40)));
    }

    #[test]
    fn decoding_never_panics_on_arbitrary_bytes() {
        // The decoder is the pre-authentication path. Exhaustive over every
        // type byte and every length up to the cap, with the body filled from
        // a rolling pattern so field boundaries land on varied values.
        for ty in 0u8..=0x20 {
            for len in 0usize..=64 {
                let mut bytes = vec![ty, 0, 0, 0];
                #[allow(clippy::cast_possible_truncation)]
                let be = (len as u32).to_be_bytes();
                bytes.splice(1..4, be[1..].iter().copied());
                bytes.extend((0..len).map(|i| {
                    #[allow(clippy::cast_possible_truncation)]
                    let b = (i * 7 + 1) as u8;
                    b
                }));
                let _ = decode(&bytes);
            }
        }
    }
}
