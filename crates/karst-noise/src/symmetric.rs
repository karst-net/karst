// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The `PHREATIC` symmetric state — transcript hash and chaining key.
//!
//! Implements the `MixHash` / `MixKey` / `MixKeyAndHash` primitives of
//! `spec/phreatic-v1.md` §7, in Noise style, over the suite hash.
//!
//! Two ordering properties this type exists to protect, both from §7.2:
//!
//! * `suite_id` and `psk_epoch` are bound **before any secret material**, so a
//!   downgrade attempt invalidates the transcript (§13.2).
//! * The per-pair PSK is mixed **last**, after every KEM and DH contribution,
//!   so it gates the final session key rather than seasoning an early chaining
//!   value (ADR-0004 §3).
//!
//! # Both algorithms come from the suite
//!
//! This type used to hardcode ChaCha20-Poly1305 and SHA-512. ADR-0015 item 2
//! made the AEAD a field; item 1 does the same for the hash, because the CNSA
//! suite is SHA-384. Neither is negotiated *here*: the suite id is mixed into the
//! transcript before any secret material, so two ends that disagree about
//! either algorithm diverge immediately and every subsequent tag fails.
//!
//! The chaining key and the message key stay 32 bytes under both hashes — HKDF
//! is asked for 32-byte chunks regardless of its output block size — so only
//! the transcript hash changes width. That is why [`KEY_LEN`] is still a
//! constant and the transcript is a [`Digest`] carrying its own length.

use karst_crypto::aead::{Algorithm, Cipher};
use karst_crypto::hash::{self, Digest};
use karst_crypto::SuiteId;
use zeroize::Zeroize;

/// Protocol label — §7.
pub const PROTOCOL_LABEL: &[u8] = b"Karst PHREATIC v1";

/// Chaining-key and message-key length. The same under both suite hashes.
pub const KEY_LEN: usize = 32;

/// Transport keys produced by [`SymmetricState::split`].
#[derive(Clone)]
pub struct TransportKeys {
    /// Key for data sent by the initiator.
    pub initiator_to_responder: [u8; KEY_LEN],
    /// Key for data sent by the responder.
    pub responder_to_initiator: [u8; KEY_LEN],
}

impl Drop for TransportKeys {
    fn drop(&mut self) {
        self.initiator_to_responder.zeroize();
        self.responder_to_initiator.zeroize();
    }
}

impl core::fmt::Debug for TransportKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TransportKeys(<redacted>)")
    }
}

/// AEAD failure. Carries no detail: §11 requires silent discard, and a
/// distinguishable error would be an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

/// Transcript hash plus chaining key.
#[derive(Clone)]
pub struct SymmetricState {
    ck: [u8; KEY_LEN],
    k: Option<[u8; KEY_LEN]>,
    h: Digest,
    /// The AEAD this handshake's suite selects — ADR-0015 item 2.
    aead: Algorithm,
    /// The hash this handshake's suite selects — ADR-0015 item 1.
    hash: hash::Algorithm,
}

impl core::fmt::Debug for SymmetricState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        f.debug_struct("SymmetricState")
            .field("has_key", &self.k.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        self.ck.zeroize();
        if let Some(mut k) = self.k.take() {
            k.zeroize();
        }
    }
}

impl SymmetricState {
    /// Start a transcript for a suite — §7.1 step 1.
    ///
    /// Both algorithms are fixed here, from the suite the initiator chose and
    /// the responder accepted. Nothing downstream may override them.
    #[must_use]
    pub fn for_suite(suite: SuiteId) -> Self {
        Self::with_algorithms(
            Algorithm::for_suite(suite),
            hash::Algorithm::for_suite(suite),
        )
    }

    /// A state over algorithms named directly, for tests that are exercising
    /// the mixing rules rather than a suite.
    #[must_use]
    pub fn with_algorithms(aead: Algorithm, hash: hash::Algorithm) -> Self {
        let h = hash.digest(&[PROTOCOL_LABEL]);
        let mut ck = [0u8; KEY_LEN];
        // Both hashes are longer than the chaining key, so this always fills.
        if let Some(head) = h.as_bytes().get(..KEY_LEN) {
            ck.copy_from_slice(head);
        }
        Self {
            ck,
            k: None,
            h,
            aead,
            hash,
        }
    }

    /// `h ← HASH(h ‖ data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = self.hash.digest(&[self.h.as_bytes(), data]);
    }

    /// `ck, k ← HKDF(ck, input, 2)`.
    pub fn mix_key(&mut self, input: &[u8]) {
        let mut okm = [0u8; KEY_LEN * 2];
        // HKDF-Expand only fails for absurd output lengths; 64 bytes is fine.
        if !self.hash.hkdf(&self.ck, input, &mut okm) {
            return;
        }
        let mut ck = [0u8; KEY_LEN];
        let mut k = [0u8; KEY_LEN];
        if let (Some(a), Some(b)) = (okm.get(..KEY_LEN), okm.get(KEY_LEN..)) {
            ck.copy_from_slice(a);
            k.copy_from_slice(b);
        }
        okm.zeroize();
        self.ck = ck;
        self.k = Some(k);
    }

    /// `ck, t, k ← HKDF(ck, input, 3)` then `MixHash(t)`. Used for the PSK so
    /// it contributes to the transcript as well as the key (§7.1 step 12).
    pub fn mix_key_and_hash(&mut self, input: &[u8]) {
        let mut okm = [0u8; KEY_LEN * 3];
        if !self.hash.hkdf(&self.ck, input, &mut okm) {
            return;
        }
        let mut ck = [0u8; KEY_LEN];
        let mut t = [0u8; KEY_LEN];
        let mut k = [0u8; KEY_LEN];
        if let (Some(a), Some(b), Some(c)) = (
            okm.get(..KEY_LEN),
            okm.get(KEY_LEN..KEY_LEN * 2),
            okm.get(KEY_LEN * 2..),
        ) {
            ck.copy_from_slice(a);
            t.copy_from_slice(b);
            k.copy_from_slice(c);
        }
        okm.zeroize();
        self.ck = ck;
        self.mix_hash(&t);
        t.zeroize();
        self.k = Some(k);
    }

    /// AEAD-seal `plaintext` with the transcript as associated data, then mix
    /// the ciphertext into the transcript.
    ///
    /// # Errors
    /// [`AeadError`] if no key has been established or the AEAD fails.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let k = self.k.ok_or(AeadError)?;
        let ct = Cipher::new(self.aead, &k)
            .seal(&[0u8; 12], self.h.as_bytes(), plaintext)
            .map_err(|_| AeadError)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    /// Inverse of [`Self::encrypt_and_hash`]. The transcript is mixed with the
    /// *ciphertext* either way, so both sides stay in step.
    ///
    /// # Errors
    /// [`AeadError`] if no key has been established or authentication fails.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let k = self.k.ok_or(AeadError)?;
        let pt = Cipher::new(self.aead, &k)
            .open(&[0u8; 12], self.h.as_bytes(), ciphertext)
            .map_err(|_| AeadError)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// Derive the two transport keys — §7.1 step 13.
    #[must_use]
    pub fn split(&self) -> TransportKeys {
        let mut okm = [0u8; KEY_LEN * 2];
        let mut a = [0u8; KEY_LEN];
        let mut b = [0u8; KEY_LEN];
        if self.hash.hkdf(&self.ck, &[], &mut okm) {
            if let (Some(x), Some(y)) = (okm.get(..KEY_LEN), okm.get(KEY_LEN..)) {
                a.copy_from_slice(x);
                b.copy_from_slice(y);
            }
        }
        okm.zeroize();
        TransportKeys {
            initiator_to_responder: a,
            responder_to_initiator: b,
        }
    }

    /// Current transcript hash. Exposed for tests and for binding into the
    /// fragment MAC; it is public data.
    ///
    /// Its length is the suite's, not a constant — 48 bytes under `KARST_2`.
    #[must_use]
    pub fn transcript(&self) -> Digest {
        self.h
    }

    /// The suite hash this state is using.
    #[must_use]
    pub const fn hash(&self) -> hash::Algorithm {
        self.hash
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// The shipping suite, for the tests below that are about the mixing rules
    /// rather than about which algorithms a suite picks.
    fn st() -> SymmetricState {
        SymmetricState::for_suite(SuiteId::KARST_1)
    }

    #[test]
    fn transcripts_diverge_on_any_differing_input() {
        let mut a = st();
        let mut b = st();
        assert_eq!(a.transcript(), b.transcript(), "same start");
        a.mix_hash(b"x");
        b.mix_hash(b"y");
        assert_ne!(a.transcript(), b.transcript());
    }

    #[test]
    fn mix_hash_is_order_sensitive() {
        let mut a = st();
        let mut b = st();
        a.mix_hash(b"one");
        a.mix_hash(b"two");
        b.mix_hash(b"two");
        b.mix_hash(b"one");
        assert_ne!(a.transcript(), b.transcript(), "transcript must bind order");
    }

    #[test]
    fn aead_round_trips_under_a_matching_transcript() {
        let mut a = st();
        let mut b = st();
        a.mix_key(b"shared");
        b.mix_key(b"shared");
        let ct = a.encrypt_and_hash(b"hello").expect("encrypt");
        let pt = b.decrypt_and_hash(&ct).expect("decrypt");
        assert_eq!(pt, b"hello");
        assert_eq!(a.transcript(), b.transcript(), "both mix the ciphertext");
    }

    /// The whole point of using the transcript as associated data: a peer whose
    /// view of the handshake differs cannot decrypt, even with the same key.
    #[test]
    fn differing_transcripts_fail_authentication() {
        let mut a = st();
        let mut b = st();
        a.mix_key(b"shared");
        b.mix_key(b"shared");
        b.mix_hash(b"an extra field the initiator never sent");
        let ct = a.encrypt_and_hash(b"hello").expect("encrypt");
        assert_eq!(b.decrypt_and_hash(&ct), Err(AeadError));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut a = st();
        let mut b = st();
        a.mix_key(b"shared");
        b.mix_key(b"shared");
        let mut ct = a.encrypt_and_hash(b"hello").expect("encrypt");
        if let Some(x) = ct.first_mut() {
            *x ^= 0x01;
        }
        assert_eq!(b.decrypt_and_hash(&ct), Err(AeadError));
    }

    #[test]
    fn encrypting_without_a_key_is_an_error_not_a_panic() {
        let mut s = st();
        assert_eq!(s.encrypt_and_hash(b"x"), Err(AeadError));
        assert_eq!(s.decrypt_and_hash(b"xxxxxxxxxxxxxxxxx"), Err(AeadError));
    }

    /// §7.2 / §13.2 — `suite_id` and `psk_epoch` are bound before any secret,
    /// so flipping either produces a different transcript and the handshake
    /// cannot complete. This is the downgrade defence.
    #[test]
    fn suite_and_epoch_binding_prevents_downgrade() {
        let build = |suite: u16, epoch: u32| {
            let mut s = st();
            s.mix_hash(&suite.to_le_bytes());
            s.mix_hash(&epoch.to_le_bytes());
            s.mix_key(b"same secret material");
            s
        };
        let honest = build(0x0002, 7);
        let downgraded = build(0x0001, 7);
        let epoch_flipped = build(0x0002, 8);
        assert_ne!(honest.transcript(), downgraded.transcript());
        assert_ne!(honest.transcript(), epoch_flipped.transcript());
    }

    /// The PSK must change the output. If mixing it were a no-op, the hedge in
    /// ADR-0004 would be worthless — so this test guards the property directly.
    #[test]
    fn the_psk_changes_the_derived_keys() {
        let derive = |psk: &[u8]| {
            let mut s = st();
            s.mix_key(b"kem and dh secrets");
            s.mix_key_and_hash(psk);
            s.split().initiator_to_responder
        };
        let real = derive(&[9u8; 32]);
        let zero = derive(&[0u8; 32]);
        let other = derive(&[8u8; 32]);
        assert_ne!(real, zero, "zero-PSK fallback must not match a real PSK");
        assert_ne!(real, other);
    }

    #[test]
    fn split_yields_two_distinct_directional_keys() {
        let mut s = st();
        s.mix_key(b"secret");
        let t = s.split();
        assert_ne!(t.initiator_to_responder, t.responder_to_initiator);
    }

    #[test]
    fn split_is_deterministic_for_the_same_transcript() {
        let mut a = st();
        let mut b = st();
        a.mix_key(b"secret");
        b.mix_key(b"secret");
        let (x, y) = (a.split(), b.split());
        assert_eq!(x.initiator_to_responder, y.initiator_to_responder);
        assert_eq!(x.responder_to_initiator, y.responder_to_initiator);
    }

    /// Debug output must never leak key material — diagnostics bundles and logs
    /// are a tracked leakage path (THREAT-MODEL R5).
    #[test]
    fn debug_does_not_leak_key_material() {
        let mut s = st();
        s.mix_key(b"super secret");
        let rendered = format!("{s:?} {:?}", s.split());
        assert!(!rendered.contains("super secret"));
        assert!(rendered.contains("redacted") || rendered.contains("has_key"));
    }

    // ── The suite chooses both algorithms (ADR-0015 items 1, 2 and 7) ──────

    /// Each suite's transcript must be its advertised width. A 48-byte
    /// transcript silently widened to 64 would still let both ends agree, which
    /// is precisely why this is asserted rather than assumed.
    #[test]
    fn the_transcript_is_the_suites_hash_length() {
        for (id, len) in [(SuiteId::KARST_1, 64), (SuiteId::KARST_2, 48)] {
            let mut s = SymmetricState::for_suite(id);
            assert_eq!(s.transcript().len(), len, "{}", id.params().name);
            assert_eq!(s.hash().output_len(), id.params().hash_len);
            s.mix_hash(b"more");
            assert_eq!(s.transcript().len(), len, "after mixing");
        }
    }

    /// **The two suites must not derive the same keys** from identical inputs.
    /// The suite id is mixed into the transcript before any secret material, so
    /// in a real handshake they would already have diverged — this checks the
    /// algorithms themselves also differ, so the defence does not rest on that
    /// one field alone.
    ///
    /// Note what carries the separation: the *hash*, not the AEAD. Both suites
    /// run AES-256-GCM since ADR-0015 item 7 removed ChaCha20-Poly1305, and the
    /// AEAD never reached the key schedule anyway. When there were two AEADs,
    /// `KARST_1` and `KARST_2` differed only in that and derived *identical*
    /// keys — which was correct then and is worth remembering, because it means
    /// an AEAD choice is not and never was a key-separation mechanism.
    #[test]
    fn the_two_suites_derive_different_keys_from_identical_inputs() {
        let derive = |id| {
            let mut s = SymmetricState::for_suite(id);
            s.mix_hash(b"identical transcript input");
            s.mix_key(b"identical secret material");
            s.mix_key_and_hash(&[7u8; 32]);
            s.split().initiator_to_responder
        };
        assert_ne!(
            derive(SuiteId::KARST_1),
            derive(SuiteId::KARST_2),
            "SHA-512 and SHA-384 must not agree"
        );
    }

    /// A message sealed under one suite must not open under the other. Here
    /// that rests entirely on the associated data's width, since both suites
    /// run the same AEAD — which is exactly why the transcript is the AAD.
    #[test]
    fn a_message_sealed_for_one_suite_does_not_open_under_the_other() {
        let mut a = SymmetricState::for_suite(SuiteId::KARST_1);
        let mut b = SymmetricState::for_suite(SuiteId::KARST_2);
        a.mix_key(b"shared");
        b.mix_key(b"shared");
        let ct = a.encrypt_and_hash(b"hello").expect("encrypt");
        assert_eq!(
            b.decrypt_and_hash(&ct),
            Err(AeadError),
            "the CNSA state opened a KARST_1 message"
        );
    }
}
