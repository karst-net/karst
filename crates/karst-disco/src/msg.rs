// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! AVEN wire format — `spec/aven-v1.md` §6.
//!
//! This decoder runs on an unfiltered UDP port, before any MAC is checked, on
//! bytes chosen by whoever can reach the socket. It is written accordingly:
//! panic-free, bounded before anything is sized, and with no field whose value
//! selects how much memory to allocate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::consts::{
    DATAGRAM_MAX, ENDPOINT_LEN, HEADER, MAC_LEN, MAGIC, MAX_CANDIDATES, PING_LEN, PONG_LEN,
    REFLECTION_LEN, REFLECT_LEN, REFLECT_PAD_LEN, TAG_LEN, TX_ID_LEN, VERSION,
};
use crate::key::DiscoKey;
use crate::Error;

/// A probe transaction id — 12 bytes from a CSPRNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxId(pub [u8; TX_ID_LEN]);

/// A candidate address, as it appears on the wire — §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint(pub SocketAddr);

impl Endpoint {
    /// The nineteen bytes §6.2 defines.
    ///
    /// Public because `ponor-v1.md` §7.7's `ReflectOffer` carries an endpoint
    /// in this encoding — the one place AVEN's wire shape appears inside
    /// another protocol. Both ends of that frame must agree on it, and the
    /// agreement is better held by one function than by two hand-written
    /// layouts.
    #[must_use]
    pub fn to_wire(self) -> [u8; ENDPOINT_LEN] {
        let mut v = Vec::with_capacity(ENDPOINT_LEN);
        self.encode(&mut v);
        let mut out = [0u8; ENDPOINT_LEN];
        if let Some(chunk) = v.first_chunk::<ENDPOINT_LEN>() {
            out = *chunk;
        }
        out
    }

    /// Parse §6.2's encoding.
    ///
    /// # Errors
    /// [`Error::Malformed`] for an unknown family or a non-zero IPv4 tail —
    /// rejected rather than ignored, so there is no covert channel in the
    /// padding and no two encodings of one address.
    pub fn from_wire(buf: &[u8; ENDPOINT_LEN]) -> Result<Self, Error> {
        Self::decode(buf)
    }

    fn encode(self, out: &mut Vec<u8>) {
        match self.0.ip() {
            IpAddr::V4(v4) => {
                out.push(0x04);
                out.extend_from_slice(&v4.octets());
                // Twelve zero bytes. A receiver rejects a non-zero tail, so
                // there is no covert channel here and no second encoding of
                // the same address.
                out.extend_from_slice(&[0u8; 12]);
            }
            IpAddr::V6(v6) => {
                out.push(0x06);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&self.0.port().to_be_bytes());
    }

    fn decode(buf: &[u8; ENDPOINT_LEN]) -> Result<Self, Error> {
        let (family, rest) = buf.split_first().ok_or(Error::Malformed)?;
        let addr = rest.first_chunk::<16>().ok_or(Error::Malformed)?;
        let port = rest.last_chunk::<2>().ok_or(Error::Malformed)?;
        let port = u16::from_be_bytes(*port);

        let ip = match *family {
            0x04 => {
                let (v4, pad) = addr.split_at_checked(4).ok_or(Error::Malformed)?;
                // Rejected rather than ignored: an ignored tail is a covert
                // channel and a second spelling of one address.
                if pad.iter().any(|b| *b != 0) {
                    return Err(Error::Malformed);
                }
                let octets = v4.first_chunk::<4>().ok_or(Error::Malformed)?;
                IpAddr::V4(Ipv4Addr::from(*octets))
            }
            0x06 => IpAddr::V6(Ipv6Addr::from(*addr)),
            _ => return Err(Error::Malformed),
        };
        Ok(Self(SocketAddr::new(ip, port)))
    }
}

/// A decoded, **not yet authenticated** AVEN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `0x01` — probes one candidate.
    Ping {
        /// Matches the answering `Pong`.
        tx: TxId,
    },
    /// `0x02` — answers a `Ping`.
    Pong {
        /// The `Ping` being answered.
        tx: TxId,
        /// The source address the `Ping` appeared to arrive from.
        ///
        /// The STUN function, without a STUN server. §7.2: the receiver of a
        /// `Pong` may advertise this and MUST NOT treat it as a path.
        observed: Endpoint,
    },
    /// `0x03` — "here is where to try me", sent over the relay.
    CallMeMaybe {
        /// Between 1 and [`MAX_CANDIDATES`] addresses.
        candidates: Vec<Endpoint>,
    },
    /// `0x04` — "what address do you see me at?", sent to a relay's reflector.
    ///
    /// Keyed by a §5.3 reflect key, not a disco key. Carries nineteen zero
    /// bytes of padding so that it is exactly as large as the `Reflection` it
    /// asks for — §7.6's amplification factor is 1.0 because of that field and
    /// for no other reason.
    Reflect {
        /// Matches the answering `Reflection`.
        tx: TxId,
    },
    /// `0x05` — a reflector's answer: the source address the `Reflect` came
    /// from.
    ///
    /// This is the one message in AVEN where the source address *is* the
    /// content, which is why §7.6 has the reflector answer to it — the inverse
    /// of §7.1's rule for `Pong`, and not a contradiction of it: a `Pong`
    /// answers a question about the peer's address, a `Reflection` answers a
    /// question about the sender's own.
    Reflection {
        /// The `Reflect` being answered.
        tx: TxId,
        /// Where the reflector saw it come from.
        observed: Endpoint,
    },
}

const T_PING: u8 = 0x01;
const T_PONG: u8 = 0x02;
const T_CALL_ME_MAYBE: u8 = 0x03;
const T_REFLECT: u8 = 0x04;
const T_REFLECTION: u8 = 0x05;

/// A datagram's header fields, read before the key is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Whose datagram this claims to be — §5.2. Not a node id.
    pub tag: [u8; TAG_LEN],
    /// Which disco-key epoch it was authenticated under.
    ///
    /// Zero for the §5.3 reflect types, which name no epoch — see
    /// [`Header::is_reflect`].
    pub epoch: u32,
    msg_type: u8,
}

impl Header {
    /// Whether this datagram is keyed by a §5.3 **reflect** key rather than a
    /// per-pair disco key.
    ///
    /// The receiver needs this before it has any key to try: the two tag
    /// derivations use different labels and live in different tables, and
    /// §5.3 requires the reflect tag to be tested *before* the §5.2 peer
    /// table. This is what makes that ordering a single branch rather than two
    /// lookups whose precedence is left unstated.
    #[must_use]
    pub const fn is_reflect(&self) -> bool {
        matches!(self.msg_type, T_REFLECT | T_REFLECTION)
    }
}

impl Message {
    const fn msg_type(&self) -> u8 {
        match self {
            Self::Ping { .. } => T_PING,
            Self::Pong { .. } => T_PONG,
            Self::CallMeMaybe { .. } => T_CALL_ME_MAYBE,
            Self::Reflect { .. } => T_REFLECT,
            Self::Reflection { .. } => T_REFLECTION,
        }
    }

    /// Encode and authenticate a datagram.
    ///
    /// `tag` is what [`DiscoKey::tag`] returns for *this* node as sender.
    #[must_use]
    pub fn encode(&self, key: &DiscoKey, tag: &[u8; TAG_LEN], epoch: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(PONG_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.msg_type());
        out.extend_from_slice(tag);
        out.extend_from_slice(&epoch.to_be_bytes());

        match self {
            Self::Ping { tx } => out.extend_from_slice(&tx.0),
            // Identical bodies, deliberately merged: `Reflection` is a `Pong`
            // for the reflect key space, with the same shape and a different
            // type byte. Keeping them apart would be two copies of one layout
            // free to drift, and `msg_type` already carries the only
            // difference.
            Self::Pong { tx, observed } | Self::Reflection { tx, observed } => {
                out.extend_from_slice(&tx.0);
                observed.encode(&mut out);
            }
            Self::CallMeMaybe { candidates } => {
                // Truncation at the cap is the sender's job. §6.1 has the
                // receiver reject an over-long count rather than truncate,
                // precisely so the two ends cannot disagree about what was
                // said, which means the sender must not emit one.
                let take = candidates.len().min(MAX_CANDIDATES);
                out.push(u8::try_from(take).unwrap_or(0));
                for c in candidates.iter().take(take) {
                    c.encode(&mut out);
                }
            }
            Self::Reflect { tx } => {
                out.extend_from_slice(&tx.0);
                // §7.6. Not filler: it makes the request the same size as the
                // reply, which is the entire amplification argument. A
                // reflector answers datagrams from anyone able to replay one,
                // and a reply larger than its request is a contribution to
                // somebody else's attack.
                out.extend_from_slice(&[0u8; REFLECT_PAD_LEN]);
            }
        }

        let mac = key.mac(&out);
        out.extend_from_slice(&mac);
        out
    }
}

/// Read the header of a datagram that looks like AVEN, without authenticating.
///
/// This is the first half of a two-step receive: the caller uses
/// [`Header::tag`] to find the peer and its key, then calls [`open`] with that
/// key. Splitting it is what keeps an unmatched datagram to one map lookup
/// instead of one MAC per peer (§5.2).
///
/// # Errors
/// [`Error::NotAven`] if the magic is absent or the datagram is too short to
/// hold a header and a MAC — which is the caller's signal to try PHREATIC
/// instead. [`Error::TooLong`] before anything else is examined.
pub fn peek(datagram: &[u8]) -> Result<Header, Error> {
    // Checked first, so no later step is ever handed an unbounded length.
    if datagram.len() > DATAGRAM_MAX {
        return Err(Error::TooLong(datagram.len()));
    }
    if datagram.len() < HEADER + MAC_LEN {
        return Err(Error::NotAven);
    }
    let magic = datagram.first_chunk::<4>().ok_or(Error::NotAven)?;
    if *magic != MAGIC {
        return Err(Error::NotAven);
    }
    let version = *datagram.get(4).ok_or(Error::NotAven)?;
    if version != VERSION {
        return Err(Error::BadVersion(version));
    }
    let msg_type = *datagram.get(5).ok_or(Error::NotAven)?;
    let tag_bytes = datagram.get(6..6 + TAG_LEN).ok_or(Error::NotAven)?;
    let tag = *tag_bytes.first_chunk::<TAG_LEN>().ok_or(Error::NotAven)?;
    let epoch_bytes = datagram
        .get(6 + TAG_LEN..HEADER)
        .ok_or(Error::NotAven)?
        .first_chunk::<4>()
        .ok_or(Error::NotAven)?;

    Ok(Header {
        tag,
        epoch: u32::from_be_bytes(*epoch_bytes),
        msg_type,
    })
}

/// Verify and decode a datagram whose peer has already been resolved.
///
/// # Errors
/// [`Error::BadMac`] if authentication fails — deliberately indistinguishable
/// from an unknown tag, which the caller reports before reaching here.
/// [`Error::BadLength`], [`Error::UnknownType`] or [`Error::Malformed`] for a
/// datagram that authenticates but does not parse, which means a peer holding
/// the key sent something this version does not understand.
pub fn open(datagram: &[u8], key: &DiscoKey) -> Result<Message, Error> {
    let header = peek(datagram)?;

    let split = datagram.len().checked_sub(MAC_LEN).ok_or(Error::NotAven)?;
    let (signed, mac) = datagram.split_at_checked(split).ok_or(Error::NotAven)?;
    // Authenticated before the body is looked at, so a malformed body is only
    // ever something a key holder sent.
    if !key.verify(signed, mac) {
        return Err(Error::BadMac);
    }

    let body = signed.get(HEADER..).ok_or(Error::NotAven)?;
    decode_body(&header, body, datagram.len())
}

fn decode_body(header: &Header, body: &[u8], total: usize) -> Result<Message, Error> {
    let msg_type = header.msg_type;
    let bad_len = || Error::BadLength {
        msg_type,
        got: total,
    };
    // §6.1: the reflect types name no epoch, because a reflect key's lifetime
    // is a Ponor connection rather than a netmap version. Rejected rather than
    // ignored, so each datagram has one encoding — the same rule §6.2 applies
    // to an IPv4 tail.
    if header.is_reflect() && header.epoch != 0 {
        return Err(Error::Malformed);
    }
    match msg_type {
        T_PING => {
            if total != PING_LEN {
                return Err(bad_len());
            }
            let tx = body.first_chunk::<TX_ID_LEN>().ok_or_else(bad_len)?;
            Ok(Message::Ping { tx: TxId(*tx) })
        }
        T_PONG => {
            if total != PONG_LEN {
                return Err(bad_len());
            }
            let tx = body.first_chunk::<TX_ID_LEN>().ok_or_else(bad_len)?;
            let rest = body.get(TX_ID_LEN..).ok_or_else(bad_len)?;
            let ep = rest.first_chunk::<ENDPOINT_LEN>().ok_or_else(bad_len)?;
            Ok(Message::Pong {
                tx: TxId(*tx),
                observed: Endpoint::decode(ep)?,
            })
        }
        T_CALL_ME_MAYBE => {
            let (count, rest) = body.split_first().ok_or_else(bad_len)?;
            let count = usize::from(*count);
            // Rejected, not truncated — §6.1. A truncating receiver and a
            // non-truncating sender disagree about what was said, and the
            // disagreement is invisible to both.
            if count == 0 || count > MAX_CANDIDATES {
                return Err(Error::Malformed);
            }
            let want = count.checked_mul(ENDPOINT_LEN).ok_or(Error::Malformed)?;
            if rest.len() != want {
                return Err(bad_len());
            }
            // `count` is now known to match the bytes present, so the
            // allocation is sized by the datagram rather than by a field in
            // it.
            let mut candidates = Vec::with_capacity(count);
            for chunk in rest.chunks_exact(ENDPOINT_LEN) {
                let ep = chunk
                    .first_chunk::<ENDPOINT_LEN>()
                    .ok_or(Error::Malformed)?;
                candidates.push(Endpoint::decode(ep)?);
            }
            Ok(Message::CallMeMaybe { candidates })
        }
        T_REFLECT => {
            if total != REFLECT_LEN {
                return Err(bad_len());
            }
            let tx = body.first_chunk::<TX_ID_LEN>().ok_or_else(bad_len)?;
            let pad = body.get(TX_ID_LEN..).ok_or_else(bad_len)?;
            // Rejected rather than ignored, for the reason §6.2 gives about an
            // IPv4 tail — but with a second one specific to this field. The
            // padding exists to hold a size equality, and a receiver that
            // accepted arbitrary bytes there would let a sender fill it with
            // anything, which is the shape of a covert channel through a field
            // whose only job is to be a certain number of bytes long.
            if pad.iter().any(|b| *b != 0) {
                return Err(Error::Malformed);
            }
            Ok(Message::Reflect { tx: TxId(*tx) })
        }
        T_REFLECTION => {
            if total != REFLECTION_LEN {
                return Err(bad_len());
            }
            let tx = body.first_chunk::<TX_ID_LEN>().ok_or_else(bad_len)?;
            let rest = body.get(TX_ID_LEN..).ok_or_else(bad_len)?;
            let ep = rest.first_chunk::<ENDPOINT_LEN>().ok_or_else(bad_len)?;
            Ok(Message::Reflection {
                tx: TxId(*tx),
                observed: Endpoint::decode(ep)?,
            })
        }
        other => Err(Error::UnknownType(other)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;
    use crate::consts::KEY_LEN;

    fn key(b: u8) -> DiscoKey {
        DiscoKey::new([b; KEY_LEN])
    }

    fn tag() -> [u8; TAG_LEN] {
        [0xab; TAG_LEN]
    }

    fn v4(a: u8, port: u16) -> Endpoint {
        Endpoint(SocketAddr::from(([10, 0, 0, a], port)))
    }

    fn v6(port: u16) -> Endpoint {
        Endpoint(SocketAddr::from((
            [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port,
        )))
    }

    fn roundtrip(m: &Message) {
        let k = key(1);
        let bytes = m.encode(&k, &tag(), 7);
        let header = peek(&bytes).expect("peek");
        assert_eq!(header.tag, tag());
        assert_eq!(header.epoch, 7);
        assert_eq!(open(&bytes, &k).expect("open"), *m);
    }

    #[test]
    fn every_message_round_trips() {
        roundtrip(&Message::Ping { tx: TxId([3; 12]) });
        roundtrip(&Message::Pong {
            tx: TxId([4; 12]),
            observed: v4(7, 51820),
        });
        roundtrip(&Message::Pong {
            tx: TxId([4; 12]),
            observed: v6(51820),
        });
        roundtrip(&Message::CallMeMaybe {
            candidates: vec![v4(1, 1), v6(2)],
        });
        roundtrip(&Message::CallMeMaybe {
            candidates: (0..MAX_CANDIDATES)
                .map(|i| v4(i as u8, 1000 + i as u16))
                .collect(),
        });
    }

    /// The reflect types carry epoch 0 — §6.1 — so they need their own
    /// round-trip rather than sharing [`roundtrip`]'s epoch 7.
    fn roundtrip_reflect(m: &Message) {
        let k = key(1);
        let bytes = m.encode(&k, &tag(), 0);
        let header = peek(&bytes).expect("peek");
        assert!(header.is_reflect(), "not routed to the reflect key space");
        assert_eq!(open(&bytes, &k).expect("open"), *m);
    }

    #[test]
    fn the_reflect_pair_round_trips() {
        roundtrip_reflect(&Message::Reflect { tx: TxId([5; 12]) });
        roundtrip_reflect(&Message::Reflection {
            tx: TxId([6; 12]),
            observed: v4(9, 51820),
        });
        roundtrip_reflect(&Message::Reflection {
            tx: TxId([6; 12]),
            observed: v6(51820),
        });
    }

    #[test]
    fn a_reflect_is_exactly_as_large_as_the_reflection_it_asks_for() {
        // §7.6's amplification factor. This is the assertion the `pad` field
        // exists for: without it a 46-byte request draws a 65-byte reply and
        // every relay in a pool becomes a 1.4× amplifier for anyone who can
        // replay one datagram.
        let k = key(1);
        let request = Message::Reflect { tx: TxId([0; 12]) }.encode(&k, &tag(), 0);
        let reply = Message::Reflection {
            tx: TxId([0; 12]),
            observed: v4(1, 1),
        }
        .encode(&k, &tag(), 0);
        assert_eq!(request.len(), reply.len());
        assert_eq!(request.len(), REFLECT_LEN);
        // And the same for the larger of the two address families, which is
        // where an inequality would actually appear.
        let reply6 = Message::Reflection {
            tx: TxId([0; 12]),
            observed: v6(1),
        }
        .encode(&k, &tag(), 0);
        assert_eq!(request.len(), reply6.len());
    }

    #[test]
    fn a_reflect_with_dirty_padding_is_refused() {
        // The padding's only job is to be nineteen bytes long, so a receiver
        // that accepted arbitrary bytes there would leave a covert channel in
        // a field with no other content.
        let k = key(1);
        let mut d = Message::Reflect { tx: TxId([1; 12]) }.encode(&k, &tag(), 0);
        let at = HEADER + TX_ID_LEN;
        d[at + 3] = 0x01;
        let mac = k.mac(&d[..REFLECT_LEN - MAC_LEN]);
        d[REFLECT_LEN - MAC_LEN..].copy_from_slice(&mac);
        assert_eq!(open(&d, &k), Err(Error::Malformed));
    }

    #[test]
    fn a_reflect_type_with_a_non_zero_epoch_is_refused() {
        // §6.1. A reflect key's lifetime is a Ponor connection, so there is no
        // epoch to name; one encoding per datagram means rejecting the others.
        let k = key(1);
        for m in [
            Message::Reflect { tx: TxId([1; 12]) },
            Message::Reflection {
                tx: TxId([1; 12]),
                observed: v4(1, 1),
            },
        ] {
            let d = m.encode(&k, &tag(), 1);
            assert_eq!(open(&d, &k), Err(Error::Malformed), "{m:?}");
        }
    }

    #[test]
    fn the_reflect_tag_is_not_the_peer_tag() {
        // §5.3 has the receiver test the reflect tag before the §5.2 peer
        // table. That ordering is only meaningful because the two derivations
        // cannot produce the same value for the same key material — different
        // labels, so seeing one never reveals the other.
        let k = key(1);
        assert_ne!(k.reflect_tag(), k.tag(b"node-a", 0));
        assert_ne!(k.reflect_tag(), k.tag(b"", 0));
    }

    #[test]
    fn the_reflect_types_are_routed_to_the_reflect_key_space() {
        // A receiver has to pick a key before it can verify anything, and the
        // type byte is the only thing available at that point.
        let k = key(1);
        for (m, reflect) in [
            (Message::Ping { tx: TxId([1; 12]) }, false),
            (
                Message::Pong {
                    tx: TxId([1; 12]),
                    observed: v4(1, 1),
                },
                false,
            ),
            (
                Message::CallMeMaybe {
                    candidates: vec![v4(1, 1)],
                },
                false,
            ),
            (Message::Reflect { tx: TxId([1; 12]) }, true),
            (
                Message::Reflection {
                    tx: TxId([1; 12]),
                    observed: v4(1, 1),
                },
                true,
            ),
        ] {
            let d = m.encode(&k, &tag(), 0);
            assert_eq!(peek(&d).expect("peek").is_reflect(), reflect, "{m:?}");
        }
    }

    #[test]
    fn encoded_sizes_match_the_spec() {
        let k = key(1);
        assert_eq!(
            Message::Ping { tx: TxId([0; 12]) }
                .encode(&k, &tag(), 0)
                .len(),
            PING_LEN
        );
        assert_eq!(
            Message::Pong {
                tx: TxId([0; 12]),
                observed: v4(1, 1)
            }
            .encode(&k, &tag(), 0)
            .len(),
            PONG_LEN
        );
        let full = Message::CallMeMaybe {
            candidates: (0..MAX_CANDIDATES).map(|i| v4(i as u8, 1)).collect(),
        };
        assert_eq!(full.encode(&k, &tag(), 0).len(), DATAGRAM_MAX);
    }

    #[test]
    fn a_datagram_without_the_magic_is_not_aven() {
        // The signal to try PHREATIC instead.
        let mut bytes = Message::Ping { tx: TxId([1; 12]) }.encode(&key(1), &tag(), 0);
        bytes[0] ^= 0xff;
        assert_eq!(peek(&bytes), Err(Error::NotAven));
    }

    #[test]
    fn a_phreatic_datagram_that_collides_with_the_magic_fails_the_mac() {
        // §4: reassembly_id is CSPRNG-drawn, so one PHREATIC datagram in 2^32
        // starts with KAVN. What stops it being accepted is the MAC, not the
        // magic — and the receiver must fall through rather than drop it.
        let mut fake = Vec::new();
        fake.extend_from_slice(&MAGIC);
        fake.extend_from_slice(&[VERSION, T_PING]);
        fake.extend_from_slice(&[0u8; TAG_LEN]);
        fake.extend_from_slice(&0u32.to_be_bytes());
        fake.extend_from_slice(&[0u8; TX_ID_LEN]);
        fake.extend_from_slice(&[0u8; MAC_LEN]);
        assert_eq!(fake.len(), PING_LEN);
        // It peeks cleanly — the header is structurally fine.
        assert!(peek(&fake).is_ok());
        // And fails to open, which is the real discriminator.
        assert_eq!(open(&fake, &key(1)), Err(Error::BadMac));
    }

    #[test]
    fn an_over_long_datagram_is_rejected_before_anything_else() {
        let junk = vec![0u8; DATAGRAM_MAX + 1];
        assert_eq!(peek(&junk), Err(Error::TooLong(DATAGRAM_MAX + 1)));
    }

    #[test]
    fn a_runt_is_not_aven() {
        for n in 0..HEADER + MAC_LEN {
            let junk = vec![0u8; n];
            assert!(matches!(peek(&junk), Err(Error::NotAven)), "{n} bytes");
        }
    }

    #[test]
    fn a_wrong_version_is_refused() {
        let mut bytes = Message::Ping { tx: TxId([1; 12]) }.encode(&key(1), &tag(), 0);
        bytes[4] = 9;
        assert_eq!(peek(&bytes), Err(Error::BadVersion(9)));
    }

    #[test]
    fn a_tampered_datagram_fails_the_mac() {
        let k = key(1);
        let bytes = Message::Ping { tx: TxId([1; 12]) }.encode(&k, &tag(), 0);
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 0x01;
            // Flipping a bit either breaks the header structurally or breaks
            // the MAC. Neither may yield a decoded message.
            assert!(open(&bad, &k).is_err(), "byte {i} was not covered");
        }
    }

    #[test]
    fn the_epoch_is_authenticated() {
        // Otherwise a datagram could be replayed into a different epoch, where
        // it would be checked against a key it was never made with.
        let k = key(1);
        let mut bytes = Message::Ping { tx: TxId([1; 12]) }.encode(&k, &tag(), 7);
        bytes[HEADER - 1] ^= 0x01;
        assert_eq!(open(&bytes, &k), Err(Error::BadMac));
    }

    #[test]
    fn another_peers_key_does_not_open_it() {
        let bytes = Message::Ping { tx: TxId([1; 12]) }.encode(&key(1), &tag(), 0);
        assert_eq!(open(&bytes, &key(2)), Err(Error::BadMac));
    }

    #[test]
    fn a_wrong_length_for_the_type_is_refused() {
        // The MAC is checked first, so this is a peer that holds the key and
        // sent something malformed — a bug or a version skew, not an attack.
        let k = key(1);
        for (ty, len) in [
            (T_PING, PING_LEN),
            (T_PONG, PONG_LEN),
            (T_REFLECT, REFLECT_LEN),
            (T_REFLECTION, REFLECTION_LEN),
        ] {
            for wrong in [len - 1, len + 1] {
                let mut body = vec![0u8; wrong - HEADER - MAC_LEN];
                let mut d = Vec::new();
                d.extend_from_slice(&MAGIC);
                d.extend_from_slice(&[VERSION, ty]);
                d.extend_from_slice(&tag());
                d.extend_from_slice(&0u32.to_be_bytes());
                d.append(&mut body);
                let mac = k.mac(&d);
                d.extend_from_slice(&mac);
                assert!(
                    matches!(open(&d, &k), Err(Error::BadLength { .. })),
                    "type {ty:#04x} accepted {wrong}"
                );
            }
        }
    }

    #[test]
    fn an_unknown_type_is_refused() {
        let k = key(1);
        let mut d = Vec::new();
        d.extend_from_slice(&MAGIC);
        d.extend_from_slice(&[VERSION, 0x7f]);
        d.extend_from_slice(&tag());
        d.extend_from_slice(&0u32.to_be_bytes());
        let mac = k.mac(&d);
        d.extend_from_slice(&mac);
        assert_eq!(open(&d, &k), Err(Error::UnknownType(0x7f)));
    }

    fn call_me_maybe_with(count: u8, endpoints: &[Endpoint]) -> Vec<u8> {
        let k = key(1);
        let mut d = Vec::new();
        d.extend_from_slice(&MAGIC);
        d.extend_from_slice(&[VERSION, T_CALL_ME_MAYBE]);
        d.extend_from_slice(&tag());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.push(count);
        for e in endpoints {
            e.encode(&mut d);
        }
        let mac = k.mac(&d);
        d.extend_from_slice(&mac);
        d
    }

    #[test]
    fn a_count_of_zero_is_malformed() {
        let d = call_me_maybe_with(0, &[]);
        assert_eq!(open(&d, &key(1)), Err(Error::Malformed));
    }

    #[test]
    fn a_count_over_the_cap_is_rejected_not_truncated() {
        // §6.1. Truncating would leave sender and receiver disagreeing about
        // what was said, invisibly to both.
        let many: Vec<Endpoint> = (0..=MAX_CANDIDATES).map(|i| v4(i as u8, 1)).collect();
        let d = call_me_maybe_with(u8::try_from(many.len()).unwrap(), &many);
        assert!(open(&d, &key(1)).is_err());
    }

    #[test]
    fn a_count_that_disagrees_with_the_bytes_present_is_refused() {
        // The classic: a length field that would size an allocation larger
        // than the data behind it.
        let d = call_me_maybe_with(16, &[v4(1, 1)]);
        assert!(matches!(
            open(&d, &key(1)),
            Err(Error::BadLength { .. } | Error::Malformed)
        ));
    }

    #[test]
    fn an_ipv4_endpoint_with_a_dirty_tail_is_refused() {
        // Rejected rather than ignored: an ignored tail is a covert channel
        // and a second spelling of the same address.
        let k = key(1);
        let mut d = Vec::new();
        d.extend_from_slice(&MAGIC);
        d.extend_from_slice(&[VERSION, T_PONG]);
        d.extend_from_slice(&tag());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&[0u8; TX_ID_LEN]);
        d.push(0x04);
        d.extend_from_slice(&[10, 0, 0, 1]);
        d.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99]); // dirty
        d.extend_from_slice(&1234u16.to_be_bytes());
        let mac = k.mac(&d);
        d.extend_from_slice(&mac);
        assert_eq!(open(&d, &k), Err(Error::Malformed));
    }

    #[test]
    fn an_unknown_address_family_is_refused() {
        let k = key(1);
        let mut d = Vec::new();
        d.extend_from_slice(&MAGIC);
        d.extend_from_slice(&[VERSION, T_PONG]);
        d.extend_from_slice(&tag());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&[0u8; TX_ID_LEN]);
        d.push(0x05); // neither 4 nor 6
        d.extend_from_slice(&[0u8; 16]);
        d.extend_from_slice(&1234u16.to_be_bytes());
        let mac = k.mac(&d);
        d.extend_from_slice(&mac);
        assert_eq!(open(&d, &k), Err(Error::Malformed));
    }

    #[test]
    fn decoding_never_panics_on_arbitrary_bytes() {
        // The whole point of the module doc. Exhaustive over lengths up to a
        // full datagram, with the magic and version forced valid so the walk
        // reaches the body parsers rather than bouncing off `peek`.
        let k = key(1);
        for len in 0..=DATAGRAM_MAX {
            let mut d: Vec<u8> = (0..len).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
            if len >= 6 {
                d[0..4].copy_from_slice(&MAGIC);
                d[4] = VERSION;
            }
            let _ = peek(&d);
            let _ = open(&d, &k);
            // And with a MAC that actually verifies, so the body parsers see
            // arbitrary input rather than being short-circuited.
            if len >= HEADER + MAC_LEN {
                let split = len - MAC_LEN;
                let mac = k.mac(&d[..split]);
                d[split..].copy_from_slice(&mac);
                let _ = open(&d, &k);
            }
        }
    }
}
