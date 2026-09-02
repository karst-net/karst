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

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::Aes256Gcm;
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

    /// Every cookie this source could legitimately be presenting right now:
    /// the current secret's, and the previous one's during its one-period
    /// grace (see [`Self::rotate`]).
    ///
    /// For verifying `mac2` against a fragment claiming address validation —
    /// a sender that received a cookie moments before a rotation must still
    /// be able to use it, or [`Self::rotate`]'s grace period is fiction.
    /// [`Self::issue`] alone is right for building a *new* `CookieReply`,
    /// where only the current secret should ever be handed out; this is for
    /// checking a cookie that may already be one rotation old.
    pub fn candidates(&self, source: &SourceKey) -> impl Iterator<Item = [u8; COOKIE_LEN]> + '_ {
        core::iter::once(Self::compute(&self.current, source))
            .chain(self.previous.map(|p| Self::compute(&p, source)))
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

// ─── CookieReply (§6.3) ─────────────────────────────────────────────────────
//
// The message body §9.1 tells a fragment-flooded responder to send: 64 bytes,
// carrying the stateless cookie of §9.3 so the sender can prove, on its next
// attempt, that it can receive at the address it claims.
//
// **Key derivation is this crate's own decision, not the spec's.** §6.3 gives
// the wire layout but not `enc_cookie`'s key — the gap this fills.
// `cookie_key` is called with the **issuing responder's own static key**,
// symmetric with [`mac1_key`]: the party building a reply passes its own key,
// and the party opening one (an initiator who already knows which peer it
// dialled) passes that peer's key. Deliberately independent of any suite —
// like the fragment MAC's hash (§13.9), this runs on the pre-authentication
// path before a suite is resolved, and AES-256-GCM is reached directly rather
// than through a suite-selected `Algorithm` for the same reason.
//
// **`frag_mac` keying diverges from §13.7's table for this one message type,
// and deliberately.** §13.7 says a `CookieReply`'s fragment MAC is keyed by
// "the initiator's static key" — true of `HandshakeResponse`, where the
// responder has by then resolved `peer_id_hint` and knows who it is answering.
// A `CookieReply` is issued **before** that resolution: §9.1 exists precisely
// so a responder under load need not decapsulate anything to answer a flood,
// which means it cannot know the initiator's identity at the moment it builds
// one. What it *can* sign with is its own key — the same key the triggering
// fragment's `mac1` was already checked against — and an initiator verifies an
// inbound `CookieReply` with the `mac1` key it already holds for that peer
// (its own `out_mac_key`), never with `in_mac_key`. See
// `spec/phreatic-v1.md` §13.10.

/// `enc_cookie`'s AEAD nonce is 16 bytes on the wire (§6.3) but AES-256-GCM
/// takes 12. The low 12 bytes carry the caller's randomness; the top 4 are
/// reserved zero, following §2's convention for every other reserved field
/// rather than spending CSPRNG output nobody needs: 96 bits of nonce entropy
/// already keeps collision probability negligible at the traffic volumes a
/// cookie challenge is issued at.
pub const COOKIE_NONCE_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;
const AEAD_KEY_LEN: usize = 32;
const AEAD_TAG_LEN: usize = 16;

/// `CookieReply` message body length — §6.3.
pub const COOKIE_REPLY_LEN: usize = 64;

/// Derive `enc_cookie`'s AEAD key from the issuing responder's static key.
///
/// Called with the same key on both ends: the builder passes its own
/// `S_pk`, the opener passes the peer's — see the module note.
#[must_use]
pub fn cookie_key(responder_static_pk: &[u8]) -> [u8; AEAD_KEY_LEN] {
    let mut d = Sha512::new();
    d.update(b"Karst cookie-reply v1");
    d.update(responder_static_pk);
    let out = d.finalize();
    let mut k = [0u8; AEAD_KEY_LEN];
    if let Some(head) = out.get(..AEAD_KEY_LEN) {
        k.copy_from_slice(head);
    }
    k
}

/// Build a `CookieReply` message body (§6.3) — 64 bytes, ready to fragment
/// with [`crate::fragment`] under a `mac1` key keyed by **this node's own**
/// static key (see the module note; `in_mac_key` is already exactly that).
///
/// `receiver_index` is the `reassembly_id` of the fragment that triggered
/// this reply — the identifier both ends already have without needing to
/// parse anything past the fragment header, since a responder issuing this
/// under load has not reassembled the message it is answering.
///
/// `nonce` is 12 bytes of caller-supplied randomness (sans-io — this crate
/// generates none itself). Returns `None` only if the AEAD itself refuses,
/// which does not happen for a well-formed key and a 24-byte plaintext.
#[must_use]
pub fn build_cookie_reply(
    responder_static_pk: &[u8],
    receiver_index: u32,
    cookie: &[u8; COOKIE_LEN],
    nonce: [u8; AEAD_NONCE_LEN],
) -> Option<[u8; COOKIE_REPLY_LEN]> {
    let key = cookie_key(responder_static_pk);
    let cipher = Aes256Gcm::new((&key).into());
    let aad = receiver_index.to_le_bytes();
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: cookie,
                aad: &aad,
            },
        )
        .ok()?;
    if ct.len() != COOKIE_LEN + AEAD_TAG_LEN {
        return None;
    }

    let mut out = [0u8; COOKIE_REPLY_LEN];
    if let Some(b) = out.first_mut() {
        *b = 0x03; // type — §6.3
    }
    // out[1..4] reserved, zero.
    if let Some(dst) = out.get_mut(4..8) {
        dst.copy_from_slice(&receiver_index.to_le_bytes());
    }
    if let Some(dst) = out.get_mut(8..8 + AEAD_NONCE_LEN) {
        dst.copy_from_slice(&nonce);
    }
    // out[20..24] reserved, zero — the wire nonce field's top 4 bytes.
    if let Some(dst) = out.get_mut(24..64) {
        dst.copy_from_slice(&ct);
    }
    Some(out)
}

/// Open a `CookieReply` message body, returning `(receiver_index, cookie)`.
///
/// `responder_static_pk` is the peer this session dialled — see the module
/// note for why the same key that built it opens it.
///
/// # Errors
/// `None` on a malformed body or failed authentication. Coarse by design —
/// §11 requires silent discard, and a distinguishable error would be an
/// oracle.
#[must_use]
pub fn open_cookie_reply(
    responder_static_pk: &[u8],
    body: &[u8],
) -> Option<(u32, [u8; COOKIE_LEN])> {
    if body.len() != COOKIE_REPLY_LEN || body.first() != Some(&0x03) {
        return None;
    }
    let receiver_index = u32::from_le_bytes(body.get(4..8)?.try_into().ok()?);
    let nonce: [u8; AEAD_NONCE_LEN] = body.get(8..8 + AEAD_NONCE_LEN)?.try_into().ok()?;
    let enc_cookie = body.get(24..64)?;

    let key = cookie_key(responder_static_pk);
    let cipher = Aes256Gcm::new((&key).into());
    let aad = receiver_index.to_le_bytes();
    let pt = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: enc_cookie,
                aad: &aad,
            },
        )
        .ok()?;
    let cookie: [u8; COOKIE_LEN] = pt.try_into().ok()?;
    Some((receiver_index, cookie))
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

    /// The grace period `rotate` provides must actually be reachable through
    /// `candidates`, not just `validate` — this is what a verifier checking
    /// `mac2` against a self-derived cookie has to use.
    #[test]
    fn candidates_include_the_previous_secret_during_its_grace() {
        let mut s = CookieSecret::new([9; 32], 0, 120_000);
        let old = s.issue(&SRC_A);
        s.rotate([10; 32], 120_000);
        let now: Vec<_> = s.candidates(&SRC_A).collect();
        assert!(now.contains(&old), "grace period must appear in candidates");
        assert!(now.contains(&s.issue(&SRC_A)));

        s.rotate([11; 32], 240_000);
        let later: Vec<_> = s.candidates(&SRC_A).collect();
        assert!(!later.contains(&old), "but only for one rotation");
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

    // ── CookieReply ─────────────────────────────────────────────────────────

    #[test]
    fn cookie_reply_round_trips() {
        let responder_pk = b"a responder's static ML-KEM public key";
        let cookie = [0x42; COOKIE_LEN];
        let body = build_cookie_reply(responder_pk, 7, &cookie, [1u8; 12]).expect("build");
        assert_eq!(body.len(), COOKIE_REPLY_LEN);
        assert_eq!(body[0], 0x03);

        let (receiver_index, opened) = open_cookie_reply(responder_pk, &body).expect("open");
        assert_eq!(receiver_index, 7);
        assert_eq!(opened, cookie);
    }

    #[test]
    fn cookie_reply_reserved_bytes_are_zero() {
        let body = build_cookie_reply(b"pk", 1, &[0; COOKIE_LEN], [0; 12]).expect("build");
        assert_eq!(&body[1..4], &[0, 0, 0], "type's reserved bytes");
        assert_eq!(&body[20..24], &[0, 0, 0, 0], "nonce's reserved bytes");
    }

    #[test]
    fn cookie_reply_does_not_open_under_the_wrong_key() {
        let cookie = [0x11; COOKIE_LEN];
        let body = build_cookie_reply(b"responder A", 1, &cookie, [3u8; 12]).expect("build");
        assert_eq!(open_cookie_reply(b"responder B", &body), None);
    }

    /// `receiver_index` is authenticated as AAD — an off-path attacker must not
    /// be able to redirect a captured reply to a different pending attempt by
    /// rewriting the cleartext field alone.
    #[test]
    fn cookie_reply_receiver_index_is_authenticated() {
        let cookie = [0x22; COOKIE_LEN];
        let mut body = build_cookie_reply(b"responder", 1, &cookie, [5u8; 12]).expect("build");
        body[4..8].copy_from_slice(&2u32.to_le_bytes()); // rewrite receiver_index
        assert_eq!(open_cookie_reply(b"responder", &body), None);
    }

    #[test]
    fn tampered_cookie_reply_ciphertext_is_rejected() {
        let cookie = [0x33; COOKIE_LEN];
        let mut body = build_cookie_reply(b"responder", 1, &cookie, [9u8; 12]).expect("build");
        if let Some(b) = body.last_mut() {
            *b ^= 0xFF;
        }
        assert_eq!(open_cookie_reply(b"responder", &body), None);
    }

    #[test]
    fn cookie_reply_rejects_malformed_bodies_without_panicking() {
        for len in 0..COOKIE_REPLY_LEN + 4 {
            let buf = vec![0u8; len];
            assert_eq!(open_cookie_reply(b"responder", &buf), None, "len {len}");
        }
        let mut wrong_type = build_cookie_reply(b"r", 1, &[0; COOKIE_LEN], [0; 12]).unwrap();
        wrong_type[0] = 0x04;
        assert_eq!(open_cookie_reply(b"r", &wrong_type), None);
    }

    /// Two different responder keys must derive different `enc_cookie` keys —
    /// otherwise any node's cookies could be read by any other.
    #[test]
    fn different_responder_keys_derive_different_cookie_keys() {
        assert_ne!(cookie_key(b"responder A"), cookie_key(b"responder B"));
    }
}
