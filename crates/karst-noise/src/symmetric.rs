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

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Protocol label — §7.
pub const PROTOCOL_LABEL: &[u8] = b"Karst PHREATIC v1";

/// Chaining-key and message-key length.
pub const KEY_LEN: usize = 32;
/// Transcript hash length (SHA-512).
pub const HASH_LEN: usize = 64;

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
    h: [u8; HASH_LEN],
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

fn hash(parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut d = Sha512::new();
    for p in parts {
        d.update(p);
    }
    let out = d.finalize();
    let mut h = [0u8; HASH_LEN];
    h.copy_from_slice(&out);
    h
}

impl SymmetricState {
    /// Start a transcript — §7.1 step 1.
    #[must_use]
    pub fn new() -> Self {
        let h = hash(&[PROTOCOL_LABEL]);
        let mut ck = [0u8; KEY_LEN];
        if let Some(head) = h.get(..KEY_LEN) {
            ck.copy_from_slice(head);
        }
        Self { ck, k: None, h }
    }

    /// `h ← HASH(h ‖ data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash(&[&self.h, data]);
    }

    /// `ck, k ← HKDF(ck, input, 2)`.
    pub fn mix_key(&mut self, input: &[u8]) {
        let hk = Hkdf::<Sha512>::new(Some(&self.ck), input);
        let mut okm = [0u8; KEY_LEN * 2];
        // HKDF-Expand only fails for absurd output lengths; 64 bytes is fine.
        if hk.expand(&[], &mut okm).is_err() {
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
        let hk = Hkdf::<Sha512>::new(Some(&self.ck), input);
        let mut okm = [0u8; KEY_LEN * 3];
        if hk.expand(&[], &mut okm).is_err() {
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
        let cipher = ChaCha20Poly1305::new_from_slice(&k).map_err(|_| AeadError)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&[0u8; 12]),
                Payload {
                    msg: plaintext,
                    aad: &self.h,
                },
            )
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
        let cipher = ChaCha20Poly1305::new_from_slice(&k).map_err(|_| AeadError)?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&[0u8; 12]),
                Payload {
                    msg: ciphertext,
                    aad: &self.h,
                },
            )
            .map_err(|_| AeadError)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// Derive the two transport keys — §7.1 step 13.
    #[must_use]
    pub fn split(&self) -> TransportKeys {
        let hk = Hkdf::<Sha512>::new(Some(&self.ck), &[]);
        let mut okm = [0u8; KEY_LEN * 2];
        let mut a = [0u8; KEY_LEN];
        let mut b = [0u8; KEY_LEN];
        if hk.expand(&[], &mut okm).is_ok() {
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
    #[must_use]
    pub fn transcript(&self) -> [u8; HASH_LEN] {
        self.h
    }
}

impl Default for SymmetricState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn transcripts_diverge_on_any_differing_input() {
        let mut a = SymmetricState::new();
        let mut b = SymmetricState::new();
        assert_eq!(a.transcript(), b.transcript(), "same start");
        a.mix_hash(b"x");
        b.mix_hash(b"y");
        assert_ne!(a.transcript(), b.transcript());
    }

    #[test]
    fn mix_hash_is_order_sensitive() {
        let mut a = SymmetricState::new();
        let mut b = SymmetricState::new();
        a.mix_hash(b"one");
        a.mix_hash(b"two");
        b.mix_hash(b"two");
        b.mix_hash(b"one");
        assert_ne!(a.transcript(), b.transcript(), "transcript must bind order");
    }

    #[test]
    fn aead_round_trips_under_a_matching_transcript() {
        let mut a = SymmetricState::new();
        let mut b = SymmetricState::new();
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
        let mut a = SymmetricState::new();
        let mut b = SymmetricState::new();
        a.mix_key(b"shared");
        b.mix_key(b"shared");
        b.mix_hash(b"an extra field the initiator never sent");
        let ct = a.encrypt_and_hash(b"hello").expect("encrypt");
        assert_eq!(b.decrypt_and_hash(&ct), Err(AeadError));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut a = SymmetricState::new();
        let mut b = SymmetricState::new();
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
        let mut s = SymmetricState::new();
        assert_eq!(s.encrypt_and_hash(b"x"), Err(AeadError));
        assert_eq!(s.decrypt_and_hash(b"xxxxxxxxxxxxxxxxx"), Err(AeadError));
    }

    /// §7.2 / §13.2 — `suite_id` and `psk_epoch` are bound before any secret,
    /// so flipping either produces a different transcript and the handshake
    /// cannot complete. This is the downgrade defence.
    #[test]
    fn suite_and_epoch_binding_prevents_downgrade() {
        let build = |suite: u16, epoch: u32| {
            let mut s = SymmetricState::new();
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
            let mut s = SymmetricState::new();
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
        let mut s = SymmetricState::new();
        s.mix_key(b"secret");
        let t = s.split();
        assert_ne!(t.initiator_to_responder, t.responder_to_initiator);
    }

    #[test]
    fn split_is_deterministic_for_the_same_transcript() {
        let mut a = SymmetricState::new();
        let mut b = SymmetricState::new();
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
        let mut s = SymmetricState::new();
        s.mix_key(b"super secret");
        let rendered = format!("{s:?} {:?}", s.split());
        assert!(!rendered.contains("super secret"));
        assert!(rendered.contains("redacted") || rendered.contains("has_key"));
    }
}
