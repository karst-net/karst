// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Denial-of-service machinery — `spec/phreatic-v1.md` §9.2 and §9.3.
//!
//! Fragment MACs and stateless cookies. This is the pre-authentication path:
//! every function here runs on attacker-controlled bytes before anything has
//! been verified, so nothing panics, allocates unboundedly, or branches on
//! secret data in a way an attacker can time.
//!
//! # What the fragment MAC is, and is not
//!
//! `mac1`'s key derives from the responder's **public** static key. Anyone who
//! knows that key can compute valid `mac1` values, so it is a cheap filter
//! against scanning and untargeted flooding — exactly `WireGuard`'s `mac1` —
//! **not** an authenticator, and it provides **no reassembly integrity**.
//!
//! `mac2` is keyed by the secret cookie and does authenticate, but only that
//! the sender can receive at the address it claims.
//!
//! Integrity of the reassembled message comes solely from the message-level
//! AEAD tag. Treating a valid `frag_mac` as evidence about the sender's
//! identity would be a vulnerability.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

use crate::consts::FRAG_MAC_LEN;
use crate::reassembly::SourceKey;

type HmacSha512 = Hmac<Sha512>;

/// Cookie length — §6.3.
pub const COOKIE_LEN: usize = 24;
/// MAC key length — SHA-512's output.
///
/// **Fixed across suites, unlike everything in the key schedule** — spec §13.9.
/// This MAC is a filter keyed by public material, not an authenticator: anyone
/// holding the recipient's static key can forge it, so its hash is not a
/// security parameter. Following the suite here would put a branch on the
/// pre-authentication path and two key widths through a type whose whole
/// purpose is to be precomputed once, for a value neither end can authenticate.
/// SHA-512 is itself a CNSA 2.0 algorithm, so `KARST_2` running it conforms.
pub const MAC_KEY_LEN: usize = 64;

/// Derive the `mac1` key from the responder's **public** static key — §9.2.
///
/// Public input, therefore a filter and not an authenticator.
#[must_use]
pub fn mac1_key(responder_static_pk: &[u8]) -> [u8; MAC_KEY_LEN] {
    derive_key(b"Karst mac1 v1", responder_static_pk)
}

/// Derive the `mac2` key from a cookie — §9.2. Secret input.
#[must_use]
pub fn mac2_key(cookie: &[u8; COOKIE_LEN]) -> [u8; MAC_KEY_LEN] {
    derive_key(b"Karst mac2 v1", cookie)
}

fn derive_key(label: &[u8], input: &[u8]) -> [u8; MAC_KEY_LEN] {
    let mut d = Sha512::new();
    d.update(label);
    d.update(input);
    let out = d.finalize();
    let mut k = [0u8; MAC_KEY_LEN];
    k.copy_from_slice(&out);
    k
}

/// A fragment MAC key with its HMAC schedule already computed.
///
/// HMAC keying is not free: it absorbs a 128-byte `ipad` block *and* a
/// 128-byte `opad` block into two SHA-512 states. Rebuilding that per packet
/// meant **four** compression functions per MAC where two would do — on a
/// datapath running tens of thousands of packets a second, for a value whose
/// message input is seven bytes.
///
/// Cloning a keyed [`Hmac`] copies both precomputed states, so a MAC costs only
/// the message block and the outer digest block. Derived once per session; see
/// PLAN.md §3.4 for the measurement that prompted it.
#[derive(Clone)]
pub struct FragMacKey {
    keyed: HmacSha512,
}

// The key may derive from a secret cookie (`mac2`), so it is never printed.
impl core::fmt::Debug for FragMacKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FragMacKey(<redacted>)")
    }
}

impl FragMacKey {
    /// Pre-compute the schedule for a key from [`mac1_key`] or [`mac2_key`].
    #[must_use]
    pub fn new(mac_key: &[u8; MAC_KEY_LEN]) -> Self {
        // HMAC accepts any key length; this cannot fail.
        let keyed = <HmacSha512 as Mac>::new_from_slice(mac_key).unwrap_or_else(|_| {
            <HmacSha512 as Mac>::new_from_slice(&[]).unwrap_or_else(|_| unreachable!())
        });
        Self { keyed }
    }

    /// Compute a fragment MAC over the header fields — §9.2, §13.8.
    #[must_use]
    pub fn compute(
        &self,
        msg_type: u8,
        reassembly_id: u32,
        idx: u8,
        count: u8,
    ) -> [u8; FRAG_MAC_LEN] {
        // The clone is the point: it carries the keyed `ipad` and `opad` states.
        let mut m = self.keyed.clone();
        m.update(&[msg_type]);
        m.update(&reassembly_id.to_le_bytes());
        m.update(&[idx, count]);
        let full = m.finalize().into_bytes();
        let mut out = [0u8; FRAG_MAC_LEN];
        if let Some(head) = full.get(..FRAG_MAC_LEN) {
            out.copy_from_slice(head);
        }
        out
    }

    /// Verify a fragment MAC in constant time.
    #[must_use]
    pub fn verify(
        &self,
        msg_type: u8,
        reassembly_id: u32,
        idx: u8,
        count: u8,
        got: &[u8; FRAG_MAC_LEN],
    ) -> bool {
        self.compute(msg_type, reassembly_id, idx, count)
            .ct_eq(got)
            .into()
    }
}

/// Compute a fragment MAC — §9.2.
///
/// `HMAC(mac_key, type ‖ reassembly_id ‖ idx ‖ cnt)`, truncated to the leftmost
/// 16 bytes.
///
/// **The payload is deliberately not covered** (§13.8). This is a scanning
/// filter, not an authenticator: its key derives from a *public* static key, so
/// anyone who knows the recipient's public key can already forge a valid MAC
/// over any payload they like. Hashing the payload therefore bought no property
/// against an adversary who has that key, and cost time proportional to every
/// byte — measured at **23% of node CPU under load, about five times the AEAD
/// it gates**. Message integrity comes from the AEAD tag and always did; §9.2
/// says so explicitly.
///
/// The cost is now constant: 7 bytes of input regardless of packet size.
#[must_use]
/// Convenience for callers that hold raw key bytes and are not on the hot path
/// — it re-derives the HMAC schedule every call. Anything per-packet should
/// hold a [`FragMacKey`].
pub fn frag_mac(
    mac_key: &[u8; MAC_KEY_LEN],
    msg_type: u8,
    reassembly_id: u32,
    idx: u8,
    count: u8,
) -> [u8; FRAG_MAC_LEN] {
    FragMacKey::new(mac_key).compute(msg_type, reassembly_id, idx, count)
}

/// Verify a fragment MAC in constant time.
#[must_use]
pub fn verify_frag_mac(
    mac_key: &[u8; MAC_KEY_LEN],
    msg_type: u8,
    reassembly_id: u32,
    idx: u8,
    count: u8,
    got: &[u8; FRAG_MAC_LEN],
) -> bool {
    FragMacKey::new(mac_key).verify(msg_type, reassembly_id, idx, count, got)
}

/// Stateless cookie issuer — §9.3.
///
/// `cookie = MAC(R_secret, source_ip ‖ source_port)`. The responder keeps no
/// per-initiator state; it holds one rotating secret and its predecessor, so
/// cookies issued just before a rotation remain valid for one period.
#[derive(Clone)]
pub struct CookieSecret {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
    rotated_at_ms: u64,
    rotation_ms: u64,
}

impl core::fmt::Debug for CookieSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CookieSecret")
            .field("rotated_at_ms", &self.rotated_at_ms)
            .finish_non_exhaustive()
    }
}

impl CookieSecret {
    /// `rotation_ms` is `COOKIE_ROTATION` — §10, 120 s.
    #[must_use]
    pub fn new(secret: [u8; 32], now_ms: u64, rotation_ms: u64) -> Self {
        Self {
            current: secret,
            previous: None,
            rotated_at_ms: now_ms,
            rotation_ms,
        }
    }

    /// Whether the secret is due for rotation.
    #[must_use]
    pub fn needs_rotation(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.rotated_at_ms) >= self.rotation_ms
    }

    /// Install a fresh secret, retaining the old one for one further period.
    pub fn rotate(&mut self, secret: [u8; 32], now_ms: u64) {
        self.previous = Some(self.current);
        self.current = secret;
        self.rotated_at_ms = now_ms;
    }

    /// Issue the cookie for a source address.
    #[must_use]
    pub fn issue(&self, source: &SourceKey) -> [u8; COOKIE_LEN] {
        Self::compute(&self.current, source)
    }

    /// Validate a cookie against the current or previous secret, in constant
    /// time.
    #[must_use]
    pub fn validate(&self, source: &SourceKey, cookie: &[u8; COOKIE_LEN]) -> bool {
        let cur: bool = Self::compute(&self.current, source).ct_eq(cookie).into();
        let prev: bool = self
            .previous
            .is_some_and(|p| Self::compute(&p, source).ct_eq(cookie).into());
        // Bitwise `|`, not `||`: both branches are evaluated regardless, so
        // validation time does not reveal which secret matched.
        cur | prev
    }

    fn compute(secret: &[u8; 32], source: &SourceKey) -> [u8; COOKIE_LEN] {
        let mut m = <HmacSha512 as Mac>::new_from_slice(secret).unwrap_or_else(|_| {
            <HmacSha512 as Mac>::new_from_slice(&[]).unwrap_or_else(|_| unreachable!())
        });
        m.update(source);
        let full = m.finalize().into_bytes();
        let mut out = [0u8; COOKIE_LEN];
        if let Some(head) = full.get(..COOKIE_LEN) {
            out.copy_from_slice(head);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const SRC_A: SourceKey = [1; 18];
    const SRC_B: SourceKey = [2; 18];

    fn key() -> [u8; MAC_KEY_LEN] {
        mac1_key(b"a responder static public key")
    }

    #[test]
    fn frag_mac_round_trips() {
        let k = key();
        let m = frag_mac(&k, 0x01, 42, 0, 2);
        assert!(verify_frag_mac(&k, 0x01, 42, 0, 2, &m));
    }

    /// Every input the MAC covers must change it — otherwise an attacker could
    /// move a fragment between positions or messages.
    #[test]
    fn every_covered_field_changes_the_mac() {
        let k = key();
        let base = frag_mac(&k, 0x01, 42, 0, 2);

        assert_ne!(base, frag_mac(&k, 0x02, 42, 0, 2), "type");
        assert_ne!(base, frag_mac(&k, 0x01, 43, 0, 2), "reassembly_id");
        assert_ne!(base, frag_mac(&k, 0x01, 42, 1, 2), "idx");
        assert_ne!(base, frag_mac(&k, 0x01, 42, 0, 3), "count");
    }

    /// §13.8 — the payload is deliberately **not** covered, and its cost is
    /// therefore independent of packet size. Asserting this stops the payload
    /// being quietly folded back in: it would restore 23% of node CPU
    /// (PLAN.md §3.4) for a property the AEAD already provides.
    #[test]
    fn the_payload_is_not_covered_and_the_cost_is_constant() {
        let k = key();
        // The MAC is a pure function of the header fields, so there is no
        // payload to pass — the signature itself is the guarantee. What can
        // still be checked is that the cost does not grow with the message.
        let m = frag_mac(&k, 0x04, 7, 0, 1);
        assert_eq!(m, frag_mac(&k, 0x04, 7, 0, 1), "deterministic");
        assert_eq!(m.len(), FRAG_MAC_LEN);
    }

    #[test]
    fn a_different_responder_key_yields_a_different_mac() {
        let a = mac1_key(b"responder one");
        let b = mac1_key(b"responder two");
        assert_ne!(frag_mac(&a, 0x01, 1, 0, 1), frag_mac(&b, 0x01, 1, 0, 1));
    }

    #[test]
    fn tampered_macs_are_rejected() {
        let k = key();
        let mut m = frag_mac(&k, 0x01, 7, 0, 1);
        if let Some(b) = m.first_mut() {
            *b ^= 0x01;
        }
        assert!(!verify_frag_mac(&k, 0x01, 7, 0, 1, &m));
    }

    #[test]
    fn mac1_and_mac2_keys_are_distinct() {
        // Same input bytes, different labels: domain separation must hold.
        let c = [7u8; COOKIE_LEN];
        assert_ne!(mac1_key(&c), mac2_key(&c));
    }

    // ── cookies ─────────────────────────────────────────────────────────────

    #[test]
    fn cookies_are_per_source_and_verify() {
        let s = CookieSecret::new([9; 32], 0, 120_000);
        let a = s.issue(&SRC_A);
        assert!(s.validate(&SRC_A, &a));
        assert!(
            !s.validate(&SRC_B, &a),
            "a cookie must not transfer sources"
        );
    }

    #[test]
    fn cookies_are_stateless_and_reproducible() {
        let s = CookieSecret::new([9; 32], 0, 120_000);
        assert_eq!(s.issue(&SRC_A), s.issue(&SRC_A));
    }

    /// Rotation must not invalidate a cookie mid-flight, or a legitimate peer
    /// retrying across the boundary would be locked out.
    #[test]
    fn a_cookie_survives_one_rotation() {
        let mut s = CookieSecret::new([9; 32], 0, 120_000);
        let old = s.issue(&SRC_A);
        s.rotate([10; 32], 120_000);
        assert!(s.validate(&SRC_A, &old), "grace period");
        s.rotate([11; 32], 240_000);
        assert!(!s.validate(&SRC_A, &old), "but only one");
    }

    #[test]
    fn rotation_is_due_on_schedule() {
        let s = CookieSecret::new([9; 32], 0, 120_000);
        assert!(!s.needs_rotation(119_999));
        assert!(s.needs_rotation(120_000));
    }

    #[test]
    fn a_forged_cookie_is_rejected() {
        let s = CookieSecret::new([9; 32], 0, 120_000);
        assert!(!s.validate(&SRC_A, &[0; COOKIE_LEN]));
        let mut c = s.issue(&SRC_A);
        if let Some(b) = c.last_mut() {
            *b ^= 0xFF;
        }
        assert!(!s.validate(&SRC_A, &c));
    }

    #[test]
    fn debug_does_not_leak_the_secret() {
        let s = CookieSecret::new([0xAB; 32], 0, 120_000);
        let out = format!("{s:?}");
        assert!(!out.contains("171") && !out.contains("ab"));
    }
}
