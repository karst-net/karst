// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Transport phase — `spec/phreatic-v1.md` §8.
//!
//! Sealed data messages under the keys a completed handshake produced, with a
//! 64-bit counter nonce and a sliding replay window.
//!
//! Sans-io: time is a parameter, so rekey deadlines are deterministic.

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use karst_crypto::aead::{Algorithm, Cipher, TAG_LEN as AEAD_TAG_LEN};
use karst_crypto::SuiteId;

use crate::symmetric::TransportKeys;

/// Replay window, in 64-bit words. 32 words = 2048 messages, satisfying §10's
/// `REPLAY_WINDOW` ≥ 2048.
const WINDOW_WORDS: usize = 32;
/// Replay window width in messages — §10.
pub const REPLAY_WINDOW: u64 = (WINDOW_WORDS as u64) * 64;

/// Rekey once this many messages have been sent — §10.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Rekey after this long — §10, 120 s.
pub const REKEY_AFTER_MS: u64 = 120_000;
/// Refuse to use a session older than this — §10, 180 s.
pub const REJECT_AFTER_MS: u64 = 180_000;
/// Force a fresh KEM handshake at least this often — §10, 600 s.
pub const PQ_REKEY_INTERVAL_MS: u64 = 600_000;

/// Transport header: type, reserved, `receiver_index`, counter — §8.
pub const HEADER_LEN: usize = 1 + 3 + 4 + 8;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Plaintext is padded up to a multiple of this — §8.
pub const PAD_TO: usize = 16;

/// Which side of the handshake this session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Transport failure. Coarse by design: §11 requires silent discard, and a
/// distinguishable error would be an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Too short, or not a transport message.
    Malformed,
    /// AEAD authentication failed.
    AuthenticationFailed,
    /// Counter already seen, or too old for the replay window.
    Replay,
    /// Session is past `REJECT_AFTER_MS`, or the counter space is exhausted.
    Expired,
}

/// Sliding replay window — §8.
#[derive(Debug)]
struct ReplayWindow {
    highest: u64,
    bits: [u64; WINDOW_WORDS],
}

impl ReplayWindow {
    const fn new() -> Self {
        Self {
            highest: 0,
            bits: [0; WINDOW_WORDS],
        }
    }

    /// Accept `counter` exactly once. Returns `false` for a replay or a
    /// counter that has fallen out of the window.
    fn accept(&mut self, counter: u64) -> bool {
        if counter > self.highest {
            // Advance, clearing the bits we slide past.
            let shift = counter - self.highest;
            if shift >= REPLAY_WINDOW {
                self.bits = [0; WINDOW_WORDS];
            } else {
                self.shift_by(shift);
            }
            self.highest = counter;
            self.set(0);
            return true;
        }
        let back = self.highest - counter;
        if back >= REPLAY_WINDOW {
            return false; // too old
        }
        let idx = usize::try_from(back).unwrap_or(usize::MAX);
        if self.get(idx) {
            return false; // already seen
        }
        self.set(idx);
        true
    }

    fn shift_by(&mut self, shift: u64) {
        let words = usize::try_from(shift / 64).unwrap_or(WINDOW_WORDS);
        let bits = u32::try_from(shift % 64).unwrap_or(0);
        let mut out = [0u64; WINDOW_WORDS];
        for i in (0..WINDOW_WORDS).rev() {
            let Some(src) = i.checked_sub(words) else {
                continue;
            };
            let Some(&v) = self.bits.get(src) else {
                continue;
            };
            let mut moved = v.checked_shl(bits).unwrap_or(0);
            if bits > 0 {
                if let Some(&lower) = src.checked_sub(1).and_then(|j| self.bits.get(j)) {
                    moved |= lower.checked_shr(64 - bits).unwrap_or(0);
                }
            }
            if let Some(slot) = out.get_mut(i) {
                *slot = moved;
            }
        }
        self.bits = out;
    }

    fn get(&self, idx: usize) -> bool {
        self.bits
            .get(idx / 64)
            .is_some_and(|w| w & (1u64 << (idx % 64)) != 0)
    }

    fn set(&mut self, idx: usize) {
        if let Some(w) = self.bits.get_mut(idx / 64) {
            *w |= 1u64 << (idx % 64);
        }
    }
}

/// An established session's send and receive halves.
pub struct TransportSession {
    /// Ciphers, keyed once at construction rather than per message.
    ///
    /// `ChaCha20Poly1305::new` was previously called on every packet, which at
    /// tens of thousands of packets a second is a key schedule rebuilt for
    /// nothing. Both zeroize their key material on drop, which is why the
    /// raw key bytes are no longer kept alongside them — two copies of a key
    /// is one more than necessary.
    send_cipher: Cipher,
    recv_cipher: Cipher,
    /// Nonce counter. Atomic rather than behind the session lock: allocating a
    /// counter is the only part of sealing that must be serial, and it costs
    /// one instruction. Holding a lock across the AEAD instead — which is what
    /// a `&mut self` API forces a caller to do — serializes every flow to a
    /// peer behind every other, and measured as a hard ~500 Mbps ceiling
    /// regardless of flow count (PLAN.md §3.4).
    send_counter: AtomicU64,
    /// The replay window is genuinely shared mutable state, so it keeps a lock —
    /// but a short one, taken *after* decryption rather than around it.
    window: Mutex<ReplayWindow>,
    established_ms: u64,
    peer_index: u32,
}

impl core::fmt::Debug for TransportSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportSession")
            .field("send_counter", &self.send_counter)
            .field("peer_index", &self.peer_index)
            .finish_non_exhaustive()
    }
}

impl TransportSession {
    /// Build a session from handshake output, under the agreed suite.
    ///
    /// The two directions use different keys, so each side sends under one and
    /// receives under the other.
    ///
    /// **There is no constructor that names an AEAD directly.** There was one,
    /// alongside a `new` that defaulted to ChaCha20-Poly1305, and the default
    /// was how a suite's choice could be quietly ignored (FINDINGS 53). Taking
    /// the suite means the AEAD is derived where it is used and cannot be
    /// chosen independently of what the handshake transcript already bound.
    #[must_use]
    pub fn for_suite(
        keys: &TransportKeys,
        role: Role,
        peer_index: u32,
        now_ms: u64,
        suite: SuiteId,
    ) -> Self {
        let aead = Algorithm::for_suite(suite);
        let (send_key, recv_key) = match role {
            Role::Initiator => (keys.initiator_to_responder, keys.responder_to_initiator),
            Role::Responder => (keys.responder_to_initiator, keys.initiator_to_responder),
        };
        Self {
            send_cipher: Cipher::new(aead, &send_key),
            recv_cipher: Cipher::new(aead, &recv_key),
            send_counter: AtomicU64::new(0),
            window: Mutex::new(ReplayWindow::new()),
            established_ms: now_ms,
            peer_index,
        }
    }

    /// Whether a rekey is due — §2.4.
    #[must_use]
    pub fn needs_rekey(&self, now_ms: u64) -> bool {
        self.send_counter.load(Ordering::Relaxed) >= REKEY_AFTER_MESSAGES
            || now_ms.saturating_sub(self.established_ms) >= REKEY_AFTER_MS
    }

    /// Whether the session must no longer be used at all — §10.
    #[must_use]
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.established_ms) >= REJECT_AFTER_MS
    }

    /// Seal a payload into a transport message.
    ///
    /// Plaintext is zero-padded to a multiple of [`PAD_TO`] (§8). **The
    /// receiver does not learn the unpadded length from this layer** — the
    /// datapath recovers it from the inner IP header's total-length field, as
    /// `WireGuard` does. Callers carrying payloads that are not self-describing
    /// must add their own framing.
    ///
    /// # Errors
    /// [`TransportError::Expired`] if the session is too old or the counter
    /// space is exhausted; [`TransportError::AuthenticationFailed`] if the
    /// AEAD fails.
    /// Takes `&self`: sealing needs no exclusive access, which is what lets a
    /// caller encrypt without holding a per-peer lock.
    pub fn seal(&self, plaintext: &[u8], now_ms: u64) -> Result<Vec<u8>, TransportError> {
        if self.expired(now_ms) {
            return Err(TransportError::Expired);
        }
        // The only serial step. `Relaxed` suffices: nothing is ordered against
        // this, and uniqueness — which is all nonce safety requires — comes from
        // the atomicity of the exchange itself.
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        if counter == u64::MAX {
            return Err(TransportError::Expired);
        }

        let pad = (PAD_TO - plaintext.len() % PAD_TO) % PAD_TO;
        let padded_len = plaintext
            .len()
            .checked_add(pad)
            .ok_or(TransportError::Malformed)?;

        // **One allocation for the whole message.** The previous form copied the
        // plaintext, allocated a ciphertext, then allocated again to prepend the
        // header — three allocations and two copies per packet. Encrypting in
        // place, detached from the tag, does it with one of each.
        let mut out = Vec::with_capacity(HEADER_LEN + padded_len + TAG_LEN);
        out.push(0x04);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&self.peer_index.to_le_bytes());
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(plaintext);
        out.resize(HEADER_LEN + padded_len, 0);

        let tag = {
            let body = out.get_mut(HEADER_LEN..).ok_or(TransportError::Malformed)?;
            self.send_cipher
                .seal_in_place(&nonce(counter), &[], body)
                .map_err(|_| TransportError::AuthenticationFailed)?
        };
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Open a transport message, enforcing the replay window.
    ///
    /// Returns the **padded** plaintext — see [`Self::seal`].
    ///
    /// # Errors
    /// [`TransportError`] on malformed input, replay, expiry, or failed
    /// authentication.
    /// Takes `&self`, for the reason [`Self::seal`] gives. The replay window is
    /// locked only to record the counter, after the AEAD has already decided.
    pub fn open(&self, msg: &[u8], now_ms: u64) -> Result<Vec<u8>, TransportError> {
        if self.expired(now_ms) {
            return Err(TransportError::Expired);
        }
        let header = msg.get(..HEADER_LEN).ok_or(TransportError::Malformed)?;
        let body = msg.get(HEADER_LEN..).ok_or(TransportError::Malformed)?;
        if header.first() != Some(&0x04) || body.len() < TAG_LEN {
            return Err(TransportError::Malformed);
        }
        let counter_bytes: [u8; 8] = header
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .ok_or(TransportError::Malformed)?;
        let counter = u64::from_le_bytes(counter_bytes);

        // Authenticate BEFORE touching the replay window: otherwise an attacker
        // could burn counter slots with forged messages and lock out the peer.
        let split = body
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(TransportError::Malformed)?;
        let ciphertext = body.get(..split).ok_or(TransportError::Malformed)?;
        let tag = body.get(split..).ok_or(TransportError::Malformed)?;

        let mut pt = ciphertext.to_vec();
        let tag: &[u8; AEAD_TAG_LEN] = tag
            .try_into()
            .map_err(|_| TransportError::AuthenticationFailed)?;
        self.recv_cipher
            .open_in_place(&nonce(counter), &[], &mut pt, tag)
            .map_err(|_| TransportError::AuthenticationFailed)?;

        // §8 — the window is touched only now, and only under a lock held for
        // the duration of a bitmap update. Recording before authenticating would
        // let an attacker burn counter slots with forgeries.
        let accepted = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accept(counter);
        if !accepted {
            return Err(TransportError::Replay);
        }
        Ok(pt)
    }
}

/// AEAD nonce for a counter — §8: `LE32(0) ‖ LE64(counter)`.
///
/// A plain array now that the cipher is chosen at runtime: both AEADs take a
/// 12-byte nonce, and the construction is the protocol's rather than any one
/// library's.
fn nonce(counter: u64) -> [u8; karst_crypto::aead::NONCE_LEN] {
    let mut n = [0u8; karst_crypto::aead::NONCE_LEN];
    if let Some(tail) = n.get_mut(4..12) {
        tail.copy_from_slice(&counter.to_le_bytes());
    }
    n
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn pair() -> (TransportSession, TransportSession) {
        let keys = TransportKeys {
            initiator_to_responder: [1u8; 32],
            responder_to_initiator: [2u8; 32],
        };
        (
            TransportSession::for_suite(&keys, Role::Initiator, 7, 0, SuiteId::KARST_1),
            TransportSession::for_suite(&keys, Role::Responder, 9, 0, SuiteId::KARST_1),
        )
    }

    #[test]
    fn data_flows_in_both_directions() {
        let (i, r) = pair();
        let a = i.seal(b"hello responder!", 0).unwrap();
        assert_eq!(r.open(&a, 0).unwrap(), b"hello responder!");
        let b = r.seal(b"hello initiator!", 0).unwrap();
        assert_eq!(i.open(&b, 0).unwrap(), b"hello initiator!");
    }

    #[test]
    fn plaintext_is_padded_to_a_multiple_of_sixteen() {
        let (i, r) = pair();
        let msg = i.seal(b"short", 0).unwrap();
        let out = r.open(&msg, 0).unwrap();
        assert_eq!(out.len() % PAD_TO, 0);
        assert_eq!(out.get(..5), Some(&b"short"[..]));
    }

    #[test]
    fn each_message_uses_a_fresh_counter() {
        let (i, r) = pair();
        let a = i.seal(b"one", 0).unwrap();
        let b = i.seal(b"one", 0).unwrap();
        assert_ne!(a, b, "identical plaintext must not produce identical bytes");
        assert!(r.open(&a, 0).is_ok());
        assert!(r.open(&b, 0).is_ok());
    }

    // ── replay ──────────────────────────────────────────────────────────────

    #[test]
    fn a_replayed_message_is_rejected() {
        let (i, r) = pair();
        let msg = i.seal(b"once only", 0).unwrap();
        assert!(r.open(&msg, 0).is_ok());
        assert_eq!(r.open(&msg, 0), Err(TransportError::Replay));
    }

    #[test]
    fn out_of_order_within_the_window_is_accepted_once_each() {
        let (i, r) = pair();
        let msgs: Vec<_> = (0..8).map(|_| i.seal(b"x", 0).unwrap()).collect();
        // Deliver in reverse.
        for m in msgs.iter().rev() {
            assert!(r.open(m, 0).is_ok(), "reordering must be tolerated");
        }
        // Every one is now a replay.
        for m in &msgs {
            assert_eq!(r.open(m, 0), Err(TransportError::Replay));
        }
    }

    #[test]
    fn messages_older_than_the_window_are_rejected() {
        let (i, r) = pair();
        let old = i.seal(b"ancient", 0).unwrap();
        // Advance well past the window.
        for _ in 0..(REPLAY_WINDOW + 16) {
            let m = i.seal(b"x", 0).unwrap();
            let _ = r.open(&m, 0);
        }
        assert_eq!(r.open(&old, 0), Err(TransportError::Replay));
    }

    #[test]
    fn a_large_counter_jump_does_not_panic_or_wrongly_accept() {
        let (i, r) = pair();
        i.send_counter.store(u64::MAX - 4, Ordering::Relaxed);
        let m = i.seal(b"far future", 0).unwrap();
        assert!(r.open(&m, 0).is_ok());
        // Anything after the jump is outside the window.
        let (i2, _) = pair();
        let early = i2.seal(b"early", 0).unwrap();
        assert_eq!(r.open(&early, 0), Err(TransportError::Replay));
    }

    // ── authentication ──────────────────────────────────────────────────────

    /// A forged message must not consume a replay-window slot. Otherwise an
    /// attacker could lock the peer out by burning counters.
    #[test]
    fn a_forged_message_does_not_burn_a_window_slot() {
        let (i, r) = pair();
        let good = i.seal(b"genuine", 0).unwrap();
        let mut forged = good.clone();
        if let Some(b) = forged.last_mut() {
            *b ^= 0xFF;
        }
        assert_eq!(
            r.open(&forged, 0),
            Err(TransportError::AuthenticationFailed)
        );
        // The genuine message with the same counter still gets through.
        assert!(
            r.open(&good, 0).is_ok(),
            "forgery must not consume the slot"
        );
    }

    #[test]
    fn tampering_with_the_counter_is_detected() {
        let (i, r) = pair();
        let mut msg = i.seal(b"genuine", 0).unwrap();
        if let Some(b) = msg.get_mut(8) {
            *b ^= 0x01;
        }
        assert_eq!(r.open(&msg, 0), Err(TransportError::AuthenticationFailed));
    }

    #[test]
    fn wrong_direction_keys_do_not_open() {
        let (i, _) = pair();
        let keys = TransportKeys {
            initiator_to_responder: [1u8; 32],
            responder_to_initiator: [2u8; 32],
        };
        let wrong = TransportSession::for_suite(&keys, Role::Initiator, 0, 0, SuiteId::KARST_1);
        let msg = i.seal(b"for the responder", 0).unwrap();
        assert_eq!(
            wrong.open(&msg, 0),
            Err(TransportError::AuthenticationFailed)
        );
    }

    #[test]
    fn malformed_messages_are_rejected_without_panicking() {
        let (_, r) = pair();
        for len in 0..(HEADER_LEN + TAG_LEN + 4) {
            let buf = vec![0x04u8; len];
            let _ = r.open(&buf, 0);
        }
        assert_eq!(r.open(&[0x01; 64], 0), Err(TransportError::Malformed));
    }

    // ── lifecycle ───────────────────────────────────────────────────────────

    #[test]
    fn rekey_is_due_after_the_time_limit() {
        let (i, _) = pair();
        assert!(!i.needs_rekey(REKEY_AFTER_MS - 1));
        assert!(i.needs_rekey(REKEY_AFTER_MS));
    }

    #[test]
    fn a_session_stops_working_after_reject_after_time() {
        let (i, r) = pair();
        let msg = i.seal(b"in time", 0).unwrap();
        assert!(r.open(&msg, REJECT_AFTER_MS - 1).is_ok());
        assert_eq!(
            i.seal(b"too late", REJECT_AFTER_MS),
            Err(TransportError::Expired)
        );
        assert_eq!(r.open(&msg, REJECT_AFTER_MS), Err(TransportError::Expired));
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let (i, _) = pair();
        let s = format!("{i:?}");
        assert!(!s.contains("send_key"));
        assert!(s.contains("send_counter"));
    }
}
