// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Per-pair disco keys and sender tags — `spec/aven-v1.md` §5.
//!
//! The key arrives from the netmap; this module does not derive it from a
//! master, because nodes do not hold the master. What it does derive is the
//! §5.2 tag, and it owns the lookup table that turns a tag on the wire into a
//! peer without trying every key in the roster.

use hmac::{Hmac, Mac as _};
use sha2::Sha512;
use subtle::ConstantTimeEq as _;

use crate::consts::{KEY_LEN, MAC_LEN, TAG_LEN};

type HmacSha512 = Hmac<Sha512>;

const TAG_LABEL: &[u8] = b"aven-tag-v1";
const REFLECT_TAG_LABEL: &[u8] = b"aven-reflect-v1";

/// A per-pair disco key from the netmap.
///
/// The key bytes are held and the HMAC schedule is built per call, rather than
/// pre-keyed the way `karst-proto`'s `FragMacKey` is. That optimisation was
/// worth 6% of CPU on a datapath running 50,000 packets a second (PLAN.md
/// §3.4); AVEN sends a handful of probes a second, and holding only the array
/// is what keeps the zeroize-on-drop honest — a pre-keyed `Hmac` retains
/// key-derived `ipad`/`opad` state that the crate gives no way to clear.
///
/// This is a **secret**, and a distinct one from the pair's PHREATIC PSK
/// (§5.1). Both derive from the same master, so this is blast-radius
/// containment rather than assumption diversity: a disco key rides on far more
/// packets, handled by code that runs before any session exists, and it must
/// not be the value that also gates the data plane's key schedule.
#[derive(Clone)]
pub struct DiscoKey([u8; KEY_LEN]);

// Printing a key is how it ends up in a log. The node-side leak scan
// (`bins/karstd/tests/leakscan.rs`) checks `Debug` output specifically,
// because `{:02x?}` on a key is a thoroughly plausible way to lose one.
impl core::fmt::Debug for DiscoKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DiscoKey(redacted)")
    }
}

impl Drop for DiscoKey {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
    }
}

impl DiscoKey {
    /// Wrap 32 bytes from the netmap.
    #[must_use]
    pub const fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The tag a given sender presents under this key, for this epoch — §5.2.
    ///
    /// `sender_id` is bound in so that the two directions of a pair have
    /// different tags. Without it both ends would present the same value and
    /// neither could tell its own probes from its peer's.
    #[must_use]
    pub fn tag(&self, sender_id: &[u8], epoch: u32) -> [u8; TAG_LEN] {
        let mut mac = Self::keyed(&self.0);
        mac.update(TAG_LABEL);
        mac.update(&epoch.to_be_bytes());
        mac.update(sender_id);
        let full = mac.finalize().into_bytes();
        let mut out = [0u8; TAG_LEN];
        if let Some(head) = full.get(..TAG_LEN) {
            out.copy_from_slice(head);
        }
        out
    }

    /// The tag carried by `Reflect` and `Reflection` under this key — §5.3.
    ///
    /// A **reflect key** is a different secret from a disco key with the same
    /// construction: 32 bytes, HMAC-SHA-512, truncated MACs. It is minted by a
    /// relay per Ponor connection and delivered inside TLS, so this type is
    /// reused rather than duplicated — what differs is where the bytes come
    /// from and which label derives the tag.
    ///
    /// Unlike [`DiscoKey::tag`] this binds neither a sender id nor an epoch.
    /// There is no second direction to disambiguate — only a node sends
    /// `Reflect`, only a reflector sends `Reflection`, and the type byte
    /// already separates them — and the key is per-connection and random, so it
    /// rotates whenever the connection does, which is the property the epoch
    /// buys in §5.2.
    #[must_use]
    pub fn reflect_tag(&self) -> [u8; TAG_LEN] {
        let mut mac = Self::keyed(&self.0);
        mac.update(REFLECT_TAG_LABEL);
        let full = mac.finalize().into_bytes();
        let mut out = [0u8; TAG_LEN];
        if let Some(head) = full.get(..TAG_LEN) {
            out.copy_from_slice(head);
        }
        out
    }

    /// Authenticate `bytes` — everything in the datagram before the MAC.
    #[must_use]
    pub fn mac(&self, bytes: &[u8]) -> [u8; MAC_LEN] {
        let mut mac = Self::keyed(&self.0);
        mac.update(bytes);
        let full = mac.finalize().into_bytes();
        let mut out = [0u8; MAC_LEN];
        if let Some(head) = full.get(..MAC_LEN) {
            out.copy_from_slice(head);
        }
        out
    }

    /// Verify a MAC in constant time.
    ///
    /// A variable-time comparison here would leak the correct tag one byte at
    /// a time to anyone able to send datagrams and measure, which on an
    /// unfiltered UDP port is anyone at all.
    #[must_use]
    pub fn verify(&self, bytes: &[u8], tag: &[u8]) -> bool {
        if tag.len() != MAC_LEN {
            return false;
        }
        self.mac(bytes).ct_eq(tag).into()
    }

    fn keyed(key: &[u8]) -> HmacSha512 {
        // HMAC accepts any key length; this cannot fail. Same shape as
        // `karst-proto::dos::FragMacKey::new`.
        <HmacSha512 as hmac::Mac>::new_from_slice(key).unwrap_or_else(|_| {
            <HmacSha512 as hmac::Mac>::new_from_slice(&[]).unwrap_or_else(|_| unreachable!())
        })
    }
}

/// What a tag resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerIndex(pub usize);

/// Maps a wire tag to a peer, so an unmatched datagram costs one lookup rather
/// than one MAC per peer.
///
/// Without this a receiver would try every peer's key against every datagram
/// arriving on the port, which at 200 peers is a 200× work amplifier any
/// unauthenticated source could pull — §5.2.
#[derive(Debug, Default)]
pub struct TagTable {
    by_tag: std::collections::HashMap<[u8; TAG_LEN], PeerIndex>,
}

impl TagTable {
    /// An empty table, which resolves nothing.
    ///
    /// The starting state is "no peer is discoverable", and that is correct:
    /// §5.1 makes an absent disco key mean no discovery at all, with the pair
    /// staying on the relay.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the tag `peer` will present this epoch.
    ///
    /// Returns whether the tag was already taken by a different peer. A
    /// collision is an 8-byte birthday event — around a one-in-2⁴⁰ chance at
    /// 200 peers — but a silent overwrite would make one peer undiscoverable
    /// for an epoch with nothing to show for it, so the caller is told.
    pub fn insert(&mut self, tag: [u8; TAG_LEN], peer: PeerIndex) -> bool {
        match self.by_tag.get(&tag).copied() {
            Some(previous) if previous != peer => true,
            Some(_) => false,
            None => {
                self.by_tag.insert(tag, peer);
                false
            }
        }
    }

    /// Resolve a tag seen on the wire.
    #[must_use]
    pub fn get(&self, tag: &[u8; TAG_LEN]) -> Option<PeerIndex> {
        self.by_tag.get(tag).copied()
    }

    /// Drop every registration. Used on epoch rotation, when every tag
    /// changes at once.
    pub fn clear(&mut self) {
        self.by_tag.clear();
    }

    /// Registered tags.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_tag.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn key(b: u8) -> DiscoKey {
        DiscoKey::new([b; KEY_LEN])
    }

    #[test]
    fn a_mac_verifies_under_its_own_key() {
        let k = key(1);
        let m = b"some datagram prefix";
        let tag = k.mac(m);
        assert!(k.verify(m, &tag));
    }

    #[test]
    fn a_mac_does_not_verify_under_another_key() {
        let tag = key(1).mac(b"msg");
        assert!(!key(2).verify(b"msg", &tag));
    }

    #[test]
    fn a_mac_does_not_verify_over_another_message() {
        let k = key(1);
        let tag = k.mac(b"msg");
        assert!(!k.verify(b"msh", &tag));
    }

    #[test]
    fn a_truncated_mac_is_refused() {
        // Otherwise a peer could offer a one-byte tag and get a 1-in-256
        // forgery. The length check is not cosmetic.
        let k = key(1);
        let tag = k.mac(b"msg");
        assert!(!k.verify(b"msg", &tag[..MAC_LEN - 1]));
        assert!(!k.verify(b"msg", &[]));
    }

    #[test]
    fn the_two_directions_of_a_pair_have_different_tags() {
        // sender_id is bound in for exactly this reason: without it both ends
        // present the same value and neither can tell its own probes apart.
        let k = key(1);
        assert_ne!(k.tag(b"node-a", 7), k.tag(b"node-b", 7));
    }

    #[test]
    fn a_tag_changes_with_the_epoch() {
        // What makes the tag unlinkable across epochs to an observer without
        // the key — §5.2.
        let k = key(1);
        assert_ne!(k.tag(b"node-a", 7), k.tag(b"node-a", 8));
    }

    #[test]
    fn a_tag_depends_on_the_key() {
        assert_ne!(key(1).tag(b"node-a", 7), key(2).tag(b"node-a", 7));
    }

    #[test]
    fn a_tag_is_not_a_prefix_of_the_mac() {
        // Different labels, so seeing one never reveals the other. If these
        // collided, an observer could derive a peer's tag from any datagram it
        // had already seen.
        let k = key(1);
        let t = k.tag(b"node-a", 7);
        let m = k.mac(b"node-a");
        assert_ne!(&m[..TAG_LEN], &t[..]);
    }

    #[test]
    fn a_key_does_not_print_itself() {
        let rendered = format!("{:?}", key(0xab));
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn an_empty_table_resolves_nothing() {
        // The starting state is "no peer is discoverable", which is what §5.1
        // requires: an absent disco key means the pair stays on the relay.
        let t = TagTable::new();
        assert!(t.is_empty());
        assert_eq!(t.get(&[0; TAG_LEN]), None);
    }

    #[test]
    fn a_registered_tag_resolves_to_its_peer() {
        let mut t = TagTable::new();
        let tag = key(1).tag(b"peer", 3);
        assert!(!t.insert(tag, PeerIndex(4)));
        assert_eq!(t.get(&tag), Some(PeerIndex(4)));
        assert_eq!(t.get(&[0; TAG_LEN]), None);
    }

    #[test]
    fn a_colliding_tag_is_reported_rather_than_swallowed() {
        let mut t = TagTable::new();
        let tag = [9u8; TAG_LEN];
        assert!(!t.insert(tag, PeerIndex(1)));
        assert!(t.insert(tag, PeerIndex(2)), "collision not reported");
        assert_eq!(t.get(&tag), Some(PeerIndex(1)), "collision overwrote owner");
        // Re-registering the owning peer is not a collision.
        assert!(!t.insert(tag, PeerIndex(1)));
    }

    #[test]
    fn clearing_makes_every_peer_undiscoverable_again() {
        // Epoch rotation changes every tag at once, and the failure mode of
        // getting this wrong is accepting a stale epoch's probes.
        let mut t = TagTable::new();
        t.insert([1; TAG_LEN], PeerIndex(0));
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.get(&[1; TAG_LEN]), None);
    }
}
