// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The KARST-CONTROL v1 key schedule and record layer.
//!
//! Mirrors `server/management/internals/karst/channel` byte for byte; the
//! agreement is pinned by `spec/vectors/karst-control-v1.json`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// Envelope format version: the construction in ADR-0011.
pub const VERSION: u32 = 1;

const LABEL_TRANSCRIPT: &[u8] = b"karst-control-v1";
const LABEL_INIT_SIG: &[u8] = b"karst-control-init-v1";
const LABEL_HELLO_SIG: &[u8] = b"karst-control-hello-v1";
const LABEL_CLIENT_KEY: &[u8] = b"karst-control-v1 node-to-server";
const LABEL_SERVER_KEY: &[u8] = b"karst-control-v1 server-to-node";

/// Key length for ChaCha20-Poly1305.
pub const KEY_LEN: usize = 32;

/// Errors from the record layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The AEAD rejected the ciphertext.
    Decrypt,
    /// A sequence number was replayed or arrived out of order.
    Replay,
    /// Key derivation failed.
    Derive,
    /// The sequence space is exhausted.
    SeqExhausted,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Decrypt => "decryption failed",
            Self::Replay => "sequence number replayed or out of order",
            Self::Derive => "key derivation failed",
            Self::SeqExhausted => "sequence space exhausted",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}

/// Append a length-prefixed field.
///
/// Every hashed concatenation is length-prefixed so that `("ab","c")` and
/// `("a","bc")` cannot hash identically. Both the transcript and the signature
/// input are built from attacker-influenced variable-length fields, so this is
/// load-bearing rather than tidiness.
fn push_field(h: &mut Sha512, field: &[u8]) {
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    h.update(len.to_be_bytes());
    h.update(field);
}

/// The byte string the server signs over its ephemeral key.
///
/// The node MUST verify this before deriving keys and before transmitting
/// anything. Skipping it costs forward secrecy against an attacker holding no
/// key material — see `spec/karst-control-v1.md` §9.
#[must_use]
pub fn hello_signing_input(server_random: &[u8], eph_kem_pk: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(LABEL_HELLO_SIG);
    push_field(&mut h, server_random);
    push_field(&mut h, eph_kem_pk);
    h.finalize().into()
}

fn transcript(
    label: &[u8],
    server_random: &[u8],
    ct_static: &[u8],
    ct_eph: &[u8],
    node_id: &[u8],
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(label);
    push_field(&mut h, server_random);
    push_field(&mut h, ct_static);
    push_field(&mut h, ct_eph);
    push_field(&mut h, node_id);
    h.finalize().into()
}

/// The byte string a node signs in `ChannelInit`.
#[must_use]
pub fn init_signing_input(
    server_random: &[u8],
    ct_static: &[u8],
    ct_eph: &[u8],
    node_id: &[u8],
) -> [u8; 64] {
    transcript(LABEL_INIT_SIG, server_random, ct_static, ct_eph, node_id)
}

/// The two directional channel keys.
#[derive(Clone)]
pub struct Keys {
    /// Node to server.
    pub c2s: [u8; KEY_LEN],
    /// Server to node.
    pub s2c: [u8; KEY_LEN],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.c2s.zeroize();
        self.s2c.zeroize();
    }
}

// Keys are secret. Printing them is how they end up in a log.
impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys(redacted)")
    }
}

/// Derive both directional keys from the two ML-KEM shared secrets.
///
/// Both encapsulations are load-bearing: `ss_static` authenticates the server
/// implicitly, `ss_eph` provides forward secrecy. Dropping either is a real
/// weakening, demonstrated by `spec/models/karst-control-nofs.pv`.
///
/// # Errors
///
/// Returns [`Error::Derive`] if HKDF expansion fails, which for these fixed
/// output lengths cannot happen in practice.
pub fn derive_keys(
    ss_static: &[u8],
    ss_eph: &[u8],
    server_random: &[u8],
    ct_static: &[u8],
    ct_eph: &[u8],
) -> Result<Keys, Error> {
    let mut secret = Vec::with_capacity(ss_static.len() + ss_eph.len());
    secret.extend_from_slice(ss_static);
    secret.extend_from_slice(ss_eph);

    let salt = transcript(LABEL_TRANSCRIPT, server_random, ct_static, ct_eph, &[]);
    let hk = Hkdf::<Sha512>::new(Some(&salt), &secret);
    secret.zeroize();

    let mut c2s = [0u8; KEY_LEN];
    let mut s2c = [0u8; KEY_LEN];
    hk.expand(LABEL_CLIENT_KEY, &mut c2s)
        .map_err(|_| Error::Derive)?;
    hk.expand(LABEL_SERVER_KEY, &mut s2c)
        .map_err(|_| Error::Derive)?;
    Ok(Keys { c2s, s2c })
}

/// Nonce is the sequence number big-endian in the low 8 bytes of 12.
fn nonce_for(seq: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    *Nonce::from_slice(&n)
}

/// Associated data binds the cleartext envelope fields to the ciphertext, so a
/// proxy cannot relabel one node's traffic as another's.
fn associated_data(node_id: &[u8], seq: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(node_id.len() + 8);
    ad.extend_from_slice(node_id);
    ad.extend_from_slice(&seq.to_be_bytes());
    ad
}

/// One direction's record layer state.
pub struct Record {
    cipher: ChaCha20Poly1305,
    send_seq: u64,
    recv_seq: u64,
}

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Record")
            .field("send_seq", &self.send_seq)
            .field("recv_seq", &self.recv_seq)
            .finish_non_exhaustive()
    }
}

impl Record {
    /// Create a record layer over a key.
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            send_seq: 0,
            recv_seq: 0,
        }
    }

    /// Seal a message, returning the sequence number used and the ciphertext.
    ///
    /// # Errors
    ///
    /// [`Error::SeqExhausted`] if the 64-bit sequence space is used up, and
    /// [`Error::Decrypt`] if the AEAD fails, which for sealing cannot happen.
    pub fn seal(&mut self, node_id: &[u8], plaintext: &[u8]) -> Result<(u64, Vec<u8>), Error> {
        let seq = self.send_seq.checked_add(1).ok_or(Error::SeqExhausted)?;
        self.send_seq = seq;
        let ad = associated_data(node_id, seq);
        let ct = self
            .cipher
            .encrypt(
                &nonce_for(seq),
                Payload {
                    msg: plaintext,
                    aad: &ad,
                },
            )
            .map_err(|_| Error::Decrypt)?;
        Ok((seq, ct))
    }

    /// Open a message.
    ///
    /// The sequence number is checked *before* the AEAD, so a replay costs a
    /// comparison rather than a decryption. `recv_seq` advances only on
    /// success, so a forged envelope cannot burn sequence numbers the real
    /// peer still intends to use.
    ///
    /// # Errors
    ///
    /// [`Error::Replay`] for a non-increasing sequence number, [`Error::Decrypt`]
    /// if authentication fails.
    pub fn open(&mut self, node_id: &[u8], seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if seq <= self.recv_seq {
            return Err(Error::Replay);
        }
        let ad = associated_data(node_id, seq);
        let pt = self
            .cipher
            .decrypt(
                &nonce_for(seq),
                Payload {
                    msg: ciphertext,
                    aad: &ad,
                },
            )
            .map_err(|_| Error::Decrypt)?;
        self.recv_seq = seq;
        Ok(pt)
    }

    /// Seal at a caller-chosen sequence number. Vector generation only; the
    /// normal path owns its counter so that it cannot be reused.
    #[doc(hidden)]
    #[must_use]
    pub fn seal_at(key: &[u8; KEY_LEN], node_id: &[u8], seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let ad = associated_data(node_id, seq);
        cipher
            .encrypt(
                &nonce_for(seq),
                Payload {
                    msg: plaintext,
                    aad: &ad,
                },
            )
            .unwrap_or_default()
    }
}
