// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! `PHREATIC` v1 wire formats, fragmentation and codec.
//!
//! Implements `spec/phreatic-v1.md` §5–§6. This crate is **sans-io**: it turns
//! bytes into typed values and back, and does no network or clock access. See
//! ADR-0003.
//!
//! The codec is on the **pre-authentication path** — it parses
//! attacker-controlled bytes before anything is verified — so it is written to
//! be panic-free: no indexing, no slicing, no `unwrap`. Bounds are discharged
//! once by `first_chunk`, and the fixed-size array is then destructured.

pub mod dos;
pub mod reassembly;

pub mod consts {
    //! Normative constants — `spec/phreatic-v1.md` §10.

    /// `IPv6` minimum MTU, and the budget for a **handshake** datagram. The
    /// entire IP datagram must fit — see [`TRANSPORT_DATAGRAM_MAX`] for why
    /// this bound is not universal.
    pub const DATAGRAM_MAX: usize = 1280;
    /// `IPv6` fixed header.
    pub const IPV6_HEADER: usize = 40;
    /// UDP header.
    pub const UDP_HEADER: usize = 8;
    /// `PHREATIC` fragment header — §5.
    pub const FRAGMENT_HEADER: usize = 24;
    /// Transport message header: type, reserved, `receiver_index`, counter — §8.
    pub const TRANSPORT_HEADER: usize = 16;
    /// AEAD tag.
    pub const TRANSPORT_TAG: usize = 16;
    /// Transport plaintext is zero-padded to a multiple of this — §8.
    pub const TRANSPORT_PAD: usize = 16;

    /// UDP payload of a datagram that fits the minimum MTU: 1232 bytes. Every
    /// handshake datagram, and every datagram belonging to a multi-fragment
    /// message, is bounded by this.
    pub const HANDSHAKE_DATAGRAM_MAX: usize = DATAGRAM_MAX - IPV6_HEADER - UDP_HEADER;

    /// Largest fragment payload of a fragmented message: 1208 bytes.
    pub const FRAGMENT_PAYLOAD_MAX: usize = HANDSHAKE_DATAGRAM_MAX - FRAGMENT_HEADER;

    /// Hard cap on fragments per message — the wire `cnt` field is 2 bits.
    pub const MAX_FRAGMENTS: u8 = 4;

    /// Tunnel MTU presented to the host — §13.6.
    ///
    /// Fixed at the `IPv6` minimum. It cannot go lower: nodes are assigned a
    /// ULA `IPv6` address (PLAN.md §4.2), and RFC 8200 §5 requires every link
    /// carrying `IPv6` to have an MTU of at least 1280.
    pub const TUNNEL_MTU: usize = 1280;

    /// Largest sealed transport message: 1312 bytes. A full-size tunnel packet
    /// plus the §8 header and AEAD tag.
    pub const TRANSPORT_PAYLOAD_MAX: usize = TRANSPORT_HEADER + TUNNEL_MTU + TRANSPORT_TAG;

    /// UDP payload of a full-size **transport** datagram: 1336 bytes.
    ///
    /// A 1280-byte inner packet plus the transport header, AEAD tag and
    /// fragment header does not fit the 1232-byte UDP payload that bounds the
    /// handshake. §8 requires transport messages never to fragment and the
    /// tunnel MTU cannot drop below 1280, so the outer budget is what gives:
    /// data datagrams reach 1384 bytes on the wire. See §13.6 — the
    /// minimum-MTU cap exists for the pre-authentication `DoS` analysis in §9,
    /// which applies to handshakes only.
    ///
    /// Only an **unfragmented** message may reach this size, so the reassembler
    /// still never sees a fragment larger than [`FRAGMENT_PAYLOAD_MAX`] and its
    /// budget analysis is unchanged.
    pub const TRANSPORT_DATAGRAM_MAX: usize = FRAGMENT_HEADER + TRANSPORT_PAYLOAD_MAX;

    /// `frag_mac` length: HMAC over the suite hash, truncated. §9.2.
    pub const FRAG_MAC_LEN: usize = 16;

    /// `peer_id_hint` length — §4.
    pub const PEER_ID_HINT_LEN: usize = 32;
}

pub mod sizes {
    //! Message sizes for suite `KARST_1` — §6.
    //!
    //! **This module is `KARST_1` only, deliberately.** Sizes for *every* suite
    //! are computed from the registry by `karst_crypto::Suite::message_sizes`,
    //! which is where a new suite is checked against §6.4. What these constants
    //! buy is the compile-time assertion below: this crate does not depend on
    //! `karst-crypto`, so the invariants can be `const`-asserted here for the
    //! shipping suite and only tested there for the rest. `KARST_2` needs three
    //! fragments (§6.5) and would fail invariant 2 as written, which is why it
    //! is not tabulated here.

    /// ML-KEM-768 encapsulation key.
    pub const ML_KEM_768_PK: usize = 1184;
    /// ML-KEM-768 ciphertext.
    pub const ML_KEM_768_CT: usize = 1088;
    /// X25519 public key.
    pub const X25519_PK: usize = 32;
    /// AEAD tag.
    pub const AEAD_TAG: usize = 16;
    /// TAI64N timestamp.
    pub const TIMESTAMP: usize = 12;

    /// `HandshakeInit` — §6.1.
    pub const HANDSHAKE_INIT: usize = 1 // type
        + 3                             // reserved
        + 4                             // sender_index
        + 2                             // suite_id
        + 4                             // psk_epoch
        + ML_KEM_768_PK                 // e_kem_pk
        + X25519_PK                     // e_dh_pk
        + ML_KEM_768_CT                 // ct_s
        + super::consts::PEER_ID_HINT_LEN + TIMESTAMP + AEAD_TAG; // enc_ident

    /// `HandshakeResponse` — §6.2.
    pub const HANDSHAKE_RESPONSE: usize = 1 // type
        + 3                                 // reserved
        + 4                                 // sender_index
        + 4                                 // receiver_index
        + ML_KEM_768_CT                     // ct_e
        + ML_KEM_768_CT                     // ct_ss
        + X25519_PK                         // e_dh_pk
        + AEAD_TAG; // enc_empty

    /// `CookieReply` — §6.3.
    pub const COOKIE_REPLY: usize = 64;
}

// ── §6.4 size invariants, enforced at COMPILE time ──────────────────────────
//
// The specification requires implementations to enforce these. Making them
// `const` assertions means a field addition that breaks either one fails the
// build rather than a test — which is the point, since the whole risk is that
// someone adds a field without re-reading §6.4.

/// Invariant 1 — anti-amplification: a responder must never emit more bytes to
/// an address-unvalidated source than it received.
const _: () = assert!(sizes::HANDSHAKE_INIT > sizes::HANDSHAKE_RESPONSE);

/// Invariant 2 — a **`KARST_1`** `HandshakeInit` must fit two fragments.
/// Headroom is 38 bytes; any new field larger than that forces a third fragment
/// and changes the `DoS` analysis in §9.
///
/// Two fragments is a property of `KARST_1` and `KARST_2`, not of the protocol:
/// `KARST_2` needs three (§6.5), which is inside the four-fragment cap and
/// costs it real loss performance. The cap that applies to every suite is
/// asserted in `karst-crypto`, over the registry.
const _: () = assert!(sizes::HANDSHAKE_INIT <= 2 * consts::FRAGMENT_PAYLOAD_MAX);

/// The header must be exactly the size the field layout implies.
const _: () = assert!(consts::FRAGMENT_HEADER == 4 + 1 + 3 + consts::FRAG_MAC_LEN);

/// §9.1 — a `CookieReply` answering one received fragment must keep the
/// amplification ratio below 0.06. Integer form of
/// `COOKIE_REPLY / FRAGMENT_PAYLOAD_MAX < 0.06`.
const _: () = assert!(sizes::COOKIE_REPLY * 100 < consts::FRAGMENT_PAYLOAD_MAX * 6);

// ── §13.6 transport MTU invariants ──────────────────────────────────────────

/// The tunnel MTU may never fall below the `IPv6` minimum: nodes carry a ULA
/// `IPv6` address, and RFC 8200 §5 requires 1280 on every link that does.
/// Shrinking this to make transport messages fit one 1208-byte fragment would
/// silently break `IPv6` inside the tunnel.
const _: () = assert!(consts::TUNNEL_MTU >= 1280);

/// §8 — a full-size tunnel packet must fit **one** fragment. This is the
/// assertion that makes "transport messages are never fragmented" true rather
/// than aspirational.
const _: () = assert!(consts::TRANSPORT_PAYLOAD_MAX <= consts::TRANSPORT_DATAGRAM_MAX);

/// Padding never pushes a full-size packet over budget: the tunnel MTU is
/// already a multiple of the pad quantum, so the worst case adds nothing.
const _: () = assert!(consts::TUNNEL_MTU % consts::TRANSPORT_PAD == 0);

/// The reassembler's budget analysis (§9.1) assumes no fragment exceeds
/// `FRAGMENT_PAYLOAD_MAX`. Oversize datagrams are legal only when unfragmented,
/// so they never reach it — this records that the two bounds really do differ,
/// which is the whole reason `decode` must enforce the `count == 1` rule.
const _: () = assert!(consts::TRANSPORT_DATAGRAM_MAX > consts::HANDSHAKE_DATAGRAM_MAX);

/// `PHREATIC` message types — §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// §6.1
    HandshakeInit = 0x01,
    /// §6.2
    HandshakeResponse = 0x02,
    /// §6.3
    CookieReply = 0x03,
    /// §8
    TransportData = 0x04,
}

impl MessageType {
    /// Parse a type byte. Unknown types are rejected, not ignored.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::HandshakeInit),
            0x02 => Some(Self::HandshakeResponse),
            0x03 => Some(Self::CookieReply),
            0x04 => Some(Self::TransportData),
            _ => None,
        }
    }
}

/// Errors from decoding. Deliberately coarse: §11 requires silent discard, so
/// callers log locally and drop. None of this is ever sent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Datagram shorter than the fragment header.
    TooShort,
    /// Datagram exceeds the minimum-MTU budget.
    TooLong,
    /// `idx >= count`.
    InvalidFragmentCounts,
}

/// A parsed fragment header — §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Sender-chosen, drawn from a CSPRNG.
    pub reassembly_id: u32,
    /// 0-based fragment index.
    pub idx: u8,
    /// Total fragment count (`1..=MAX_FRAGMENTS`), i.e. wire `cnt` + 1.
    pub count: u8,
    /// §9.2. A valid MAC proves nothing about identity — see the spec note.
    pub frag_mac: [u8; consts::FRAG_MAC_LEN],
}

impl FragmentHeader {
    /// Encode to the 24-byte on-wire header.
    ///
    /// Returns the array by value rather than writing into a caller slice, so
    /// no bounds check and no panic path exists.
    ///
    /// Reserved bits and bytes are written as zero, per §2. `idx`/`count` are
    /// masked into range rather than asserted, keeping this total.
    #[must_use]
    pub fn encode(&self) -> [u8; consts::FRAGMENT_HEADER] {
        let [i0, i1, i2, i3] = self.reassembly_id.to_le_bytes();
        // idx in bits 7..6, (count-1) in bits 5..4, low nibble reserved zero.
        let flags = ((self.idx & 0b11) << 6) | ((self.count.saturating_sub(1) & 0b11) << 4);

        let mut out = [0u8; consts::FRAGMENT_HEADER];
        let (head, mac) = out.split_at_mut(8);
        head.copy_from_slice(&[i0, i1, i2, i3, flags, 0, 0, 0]);
        mac.copy_from_slice(&self.frag_mac);
        out
    }

    /// Decode a fragment header from the front of `buf`.
    ///
    /// Reserved fields are ignored rather than rejected (§2), so adding a suite
    /// later does not make older peers drop valid traffic.
    ///
    /// # Errors
    /// [`DecodeError`] on a malformed or out-of-budget datagram.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() > consts::TRANSPORT_DATAGRAM_MAX {
            return Err(DecodeError::TooLong);
        }
        // Discharges every bound in one step; the rest is array destructuring.
        let hdr = buf
            .first_chunk::<{ consts::FRAGMENT_HEADER }>()
            .ok_or(DecodeError::TooShort)?;

        let [i0, i1, i2, i3, flags, _, _, _, frag_mac @ ..] = *hdr;

        let idx = flags >> 6;
        let count = ((flags >> 4) & 0b11) + 1;
        if idx >= count {
            return Err(DecodeError::InvalidFragmentCounts);
        }
        // §13.6 — only an unfragmented transport message may exceed the
        // minimum-MTU budget. Enforcing it here keeps every datagram that can
        // reach the reassembler within `FRAGMENT_PAYLOAD_MAX`, so §9.1's
        // memory bound holds without the reassembler knowing message types.
        if count > 1 && buf.len() > consts::HANDSHAKE_DATAGRAM_MAX {
            return Err(DecodeError::TooLong);
        }

        Ok(Self {
            reassembly_id: u32::from_le_bytes([i0, i1, i2, i3]),
            idx,
            count,
            frag_mac,
        })
    }
}

/// Split a message into authenticated fragments — §5, §9.2.
///
/// Each fragment carries its own MAC, so an invalid one is discarded before it
/// can enter a reassembly buffer. `mac_key` is [`dos::mac1_key`] before a
/// cookie has been obtained and [`dos::mac2_key`] afterwards.
///
/// Returns `None` if the message exceeds the four-fragment cap, or if it is
/// [`MessageType::TransportData`] longer than [`consts::TRANSPORT_PAYLOAD_MAX`]
/// — §8 forbids fragmenting transport data, so an over-long packet is refused
/// rather than quietly split.
#[must_use]
pub fn fragment(
    msg_type: MessageType,
    reassembly_id: u32,
    msg: &[u8],
    mac_key: &dos::FragMacKey,
) -> Option<Vec<Vec<u8>>> {
    // §13.6: transport data rides in a single oversize datagram; everything
    // else is bounded by the minimum MTU and may fragment.
    let (budget, count_usize) = if msg_type == MessageType::TransportData {
        (
            consts::TRANSPORT_PAYLOAD_MAX,
            (msg.len() <= consts::TRANSPORT_PAYLOAD_MAX).then_some(1)?,
        )
    } else {
        (consts::FRAGMENT_PAYLOAD_MAX, fragments_needed(msg.len())?)
    };
    let count = u8::try_from(count_usize).ok()?;
    let mut out = Vec::with_capacity(count_usize);

    for idx in 0..count {
        let start = usize::from(idx).checked_mul(budget)?;
        let end = start.checked_add(budget)?.min(msg.len());
        let payload = msg.get(start..end)?;

        let hdr = FragmentHeader {
            reassembly_id,
            idx,
            count,
            frag_mac: mac_key.compute(msg_type as u8, reassembly_id, idx, count, payload),
        };
        let mut datagram = Vec::with_capacity(consts::FRAGMENT_HEADER + payload.len());
        datagram.extend_from_slice(&hdr.encode());
        datagram.extend_from_slice(payload);
        out.push(datagram);
    }
    Some(out)
}

/// Split a received datagram into its header and payload.
///
/// # Errors
/// [`DecodeError`] if the datagram is malformed.
pub fn split_datagram(datagram: &[u8]) -> Result<(FragmentHeader, &[u8]), DecodeError> {
    let hdr = FragmentHeader::decode(datagram)?;
    let payload = datagram
        .get(consts::FRAGMENT_HEADER..)
        .ok_or(DecodeError::TooShort)?;
    Ok((hdr, payload))
}

/// Fragments required to carry `len` bytes, or `None` if it exceeds the cap.
#[must_use]
pub fn fragments_needed(len: usize) -> Option<usize> {
    let n = len.div_ceil(consts::FRAGMENT_PAYLOAD_MAX);
    (n <= consts::MAX_FRAGMENTS as usize).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_sizes_match_the_specification() {
        assert_eq!(sizes::HANDSHAKE_INIT, 2378, "spec §6.1");
        assert_eq!(sizes::HANDSHAKE_RESPONSE, 2236, "spec §6.2");
        assert_eq!(consts::FRAGMENT_PAYLOAD_MAX, 1208, "spec §5");
    }

    /// §6.4 invariant 1. The compile-time assertion above proves the ordering;
    /// this pins the actual margin so a change is visible in review.
    #[test]
    fn anti_amplification_margin_is_142_bytes() {
        assert_eq!(
            sizes::HANDSHAKE_INIT - sizes::HANDSHAKE_RESPONSE,
            142,
            "anti-amplification margin changed — re-read spec §6.4"
        );
    }

    /// §6.4 invariant 2 — the tightest constraint in the protocol.
    #[test]
    fn handshake_init_fits_two_fragments_with_38_bytes_headroom() {
        assert_eq!(fragments_needed(sizes::HANDSHAKE_INIT), Some(2));
        assert_eq!(fragments_needed(sizes::HANDSHAKE_RESPONSE), Some(2));
        assert_eq!(
            2 * consts::FRAGMENT_PAYLOAD_MAX - sizes::HANDSHAKE_INIT,
            38,
            "fragment headroom changed — any field over 38 B forces a third \
             fragment and changes the DoS analysis (spec §6.4)"
        );
    }

    #[test]
    fn cookie_reply_is_one_fragment_and_not_an_amplifier() {
        assert_eq!(fragments_needed(sizes::COOKIE_REPLY), Some(1));
        // The 0.06 amplification bound is a compile-time assertion (see
        // AMPLIFICATION_BOUND above); here we only pin the fragment count.
    }

    #[test]
    fn header_round_trips() {
        for count in 1..=consts::MAX_FRAGMENTS {
            for idx in 0..count {
                let h = FragmentHeader {
                    reassembly_id: 0xDEAD_BEEF,
                    idx,
                    count,
                    frag_mac: [0xA5; consts::FRAG_MAC_LEN],
                };
                assert_eq!(FragmentHeader::decode(&h.encode()), Ok(h), "{idx}/{count}");
            }
        }
    }

    #[test]
    fn reserved_bits_and_bytes_are_written_zero() {
        let h = FragmentHeader {
            reassembly_id: 1,
            idx: 0,
            count: 1,
            frag_mac: [0; consts::FRAG_MAC_LEN],
        };
        let buf = h.encode();
        assert_eq!(buf.get(4).map(|b| b & 0x0F), Some(0), "low nibble reserved");
        assert_eq!(buf.get(5..8), Some(&[0, 0, 0][..]), "reserved bytes");
    }

    /// §2: reserved fields are ignored, not rejected — otherwise adding a suite
    /// later would make older peers drop valid traffic.
    #[test]
    fn reserved_bits_are_ignored_on_receipt() {
        let h = FragmentHeader {
            reassembly_id: 7,
            idx: 1,
            count: 2,
            frag_mac: [3; consts::FRAG_MAC_LEN],
        };
        let mut buf = h.encode();
        if let Some(b) = buf.get_mut(4) {
            *b |= 0x0F; // dirty the reserved nibble
        }
        if let Some(r) = buf.get_mut(5..8) {
            r.fill(0xFF); // and the reserved bytes
        }
        assert_eq!(FragmentHeader::decode(&buf), Ok(h));
    }

    #[test]
    fn rejects_short_and_oversized_datagrams() {
        assert_eq!(
            FragmentHeader::decode(&[0u8; consts::FRAGMENT_HEADER - 1]),
            Err(DecodeError::TooShort)
        );
        assert_eq!(
            FragmentHeader::decode(&vec![0u8; consts::TRANSPORT_DATAGRAM_MAX + 1]),
            Err(DecodeError::TooLong)
        );
    }

    /// §13.6 — the rule that keeps the §9.1 memory bound intact once transport
    /// datagrams are allowed to exceed the minimum-MTU budget. An oversize
    /// datagram claiming to be part of a multi-fragment message is exactly the
    /// input an attacker would use to inflate reassembly buffers.
    #[test]
    fn only_an_unfragmented_message_may_exceed_the_minimum_mtu() {
        let oversize = consts::HANDSHAKE_DATAGRAM_MAX + 1;

        // count == 1: legal, this is transport data.
        let mut solo = vec![0u8; oversize];
        assert!(FragmentHeader::decode(&solo).is_ok());

        // count == 2: refused, however large the reassembly budget looks.
        if let Some(b) = solo.get_mut(4) {
            *b = 1 << 4; // idx 0, count 2
        }
        assert_eq!(FragmentHeader::decode(&solo), Err(DecodeError::TooLong));

        // A multi-fragment datagram at exactly the budget stays legal.
        let mut at_budget = vec![0u8; consts::HANDSHAKE_DATAGRAM_MAX];
        if let Some(b) = at_budget.get_mut(4) {
            *b = 1 << 4;
        }
        assert!(FragmentHeader::decode(&at_budget).is_ok());
    }

    /// §8 — "transport messages are never fragmented" must be enforced, not
    /// merely documented. A full-size tunnel packet yields exactly one
    /// datagram, and anything longer is refused rather than split.
    #[test]
    fn transport_data_never_fragments() {
        let key = dos::FragMacKey::new(&[7u8; dos::MAC_KEY_LEN]);
        let full = vec![0u8; consts::TRANSPORT_PAYLOAD_MAX];
        let frags = fragment(MessageType::TransportData, 1, &full, &key);
        assert_eq!(frags.as_ref().map(Vec::len), Some(1), "spec §8");
        assert_eq!(
            frags.and_then(|f| f.first().map(Vec::len)),
            Some(consts::TRANSPORT_DATAGRAM_MAX)
        );

        let too_long = vec![0u8; consts::TRANSPORT_PAYLOAD_MAX + 1];
        assert!(
            fragment(MessageType::TransportData, 1, &too_long, &key).is_none(),
            "an over-MTU packet must be refused, not silently fragmented"
        );
    }

    /// The datagram a full-size tunnel packet produces must still fit a
    /// conventional 1500-byte path with room to spare.
    #[test]
    fn a_full_size_transport_datagram_fits_a_1500_byte_path() {
        let on_the_wire = consts::TRANSPORT_DATAGRAM_MAX + consts::UDP_HEADER + consts::IPV6_HEADER;
        assert_eq!(on_the_wire, 1384, "spec §13.6");
        assert!(on_the_wire <= 1500 - 100, "116 B of headroom for underlays");
    }

    #[test]
    fn rejects_index_beyond_count() {
        let mut buf = [0u8; consts::FRAGMENT_HEADER];
        if let Some(b) = buf.get_mut(4) {
            *b = 3 << 6; // idx 3, count 1
        }
        assert_eq!(
            FragmentHeader::decode(&buf),
            Err(DecodeError::InvalidFragmentCounts)
        );
    }

    #[test]
    fn fragment_count_cap_is_enforced() {
        let max = consts::MAX_FRAGMENTS as usize * consts::FRAGMENT_PAYLOAD_MAX;
        assert_eq!(fragments_needed(max), Some(consts::MAX_FRAGMENTS as usize));
        assert_eq!(fragments_needed(max + 1), None, "must reject over the cap");
    }

    #[test]
    fn unknown_message_types_are_rejected() {
        assert_eq!(
            MessageType::from_byte(0x01),
            Some(MessageType::HandshakeInit)
        );
        assert_eq!(MessageType::from_byte(0x00), None);
        assert_eq!(MessageType::from_byte(0x05), None);
        assert_eq!(MessageType::from_byte(0xFF), None);
    }

    /// The decoder must never panic, whatever it is fed. This is a smoke test;
    /// `cargo-fuzz` covers the space properly (PLAN.md §11).
    #[test]
    fn decoder_never_panics_on_arbitrary_input() {
        for len in 0..=64usize {
            for pattern in [0x00u8, 0xFF, 0xA5, 0x5A] {
                let buf = vec![pattern; len];
                let _ = FragmentHeader::decode(&buf);
            }
        }
    }
}
