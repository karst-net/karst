// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Encryption at rest for the on-disk netmap cache.
//!
//! Phase 3 exit criterion (PLAN.md §2.6): *"the on-disk netmap cache is
//! encrypted and unreadable without the node's sealed key."* The netmap
//! carries a per-pair PSK for every peer, so a plaintext cache is a file that
//! hands an attacker with read access the assumption-diversity hedge for the
//! whole aquifer.
//!
//! # The cache stores opaque bytes
//!
//! It seals whatever the node received, without parsing it. That is
//! deliberate: a cache that understands the netmap format is a second decoder
//! to keep in step with the first, and a second place for the two to disagree.
//! The node parses once, for use; the cache stores the bytes it was given.
//!
//! # Key custody is the caller's
//!
//! [`SealKey`] is a 32-byte key the caller supplies from an OS keystore or a
//! passphrase-derived KDF. This crate deliberately does not choose: keystore
//! integration is per-platform and a password KDF is a parameter-tuning
//! decision, neither of which belongs behind a library API that would make the
//! wrong default invisible.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroize;

/// Length of the sealing key.
pub const SEAL_KEY_LEN: usize = 32;

const NONCE_LEN: usize = 12;

/// Bound into the AEAD's associated data so a cache file cannot be replayed
/// into a different version of the format.
const CACHE_AAD: &[u8] = b"karst-netmap-cache-v1";

/// Errors from the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The file is shorter than a nonce, so it is not a cache file.
    Truncated,
    /// Authentication failed: wrong key, or the file was modified.
    ///
    /// These are deliberately the same error. A caller that could tell them
    /// apart would be tempted to treat "wrong key" as recoverable and retry,
    /// and there is nothing to retry with.
    Unreadable,
    /// Sealing failed.
    Seal,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "cache file is truncated",
            Self::Unreadable => "cache is unreadable: wrong key or modified file",
            Self::Seal => "sealing the cache failed",
        })
    }
}

impl core::error::Error for Error {}

/// A key for the on-disk cache.
pub struct SealKey([u8; SEAL_KEY_LEN]);

impl SealKey {
    /// Wrap a key obtained from an OS keystore or a passphrase KDF.
    #[must_use]
    pub fn new(key: [u8; SEAL_KEY_LEN]) -> Self {
        Self(key)
    }
}

impl Drop for SealKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// The key protects every PSK in the aquifer. It does not print.
impl core::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealKey(redacted)")
    }
}

/// Seal a netmap for storage.
///
/// `nonce` must be fresh for each write under one key. The caller supplies it
/// rather than the crate generating one, because this crate has no RNG
/// dependency and a caller that already holds one should not gain a second.
///
/// The nonce is stored in the clear ahead of the ciphertext, which is standard
/// and safe: a nonce is not a secret, only a value that must not repeat.
///
/// # Errors
///
/// [`Error::Seal`] if the AEAD fails, which cannot happen for valid inputs.
pub fn seal(key: &SealKey, nonce: &[u8; NONCE_LEN], netmap: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new((&key.0).into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: netmap,
                aad: CACHE_AAD,
            },
        )
        .map_err(|_| Error::Seal)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed netmap.
///
/// # Errors
///
/// [`Error::Truncated`] if the file is too short to contain a nonce, and
/// [`Error::Unreadable`] if authentication fails.
pub fn open(key: &SealKey, sealed: &[u8]) -> Result<Vec<u8>, Error> {
    let (nonce, ct) = sealed.split_at_checked(NONCE_LEN).ok_or(Error::Truncated)?;
    let cipher = ChaCha20Poly1305::new((&key.0).into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: CACHE_AAD,
            },
        )
        .map_err(|_| Error::Unreadable)
}
