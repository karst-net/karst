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

use karst_crypto::aead::{Algorithm, Cipher, NONCE_LEN};
use zeroize::Zeroize;

/// Length of the sealing key.
pub const SEAL_KEY_LEN: usize = 32;

const MAGIC: &[u8; 8] = b"KARSTNMC";
const SUITE_AES_256_GCM: u16 = 1;
const HEADER_LEN: usize = MAGIC.len() + size_of::<u16>();

/// Bound into the AEAD's associated data so a cache file cannot be replayed
/// into a different version of the format.
const CACHE_AAD: &[u8] = b"karst-netmap-cache-v2";

/// Errors from the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The file is shorter than the format header and nonce.
    Truncated,
    /// The file does not carry the netmap-cache format marker.
    InvalidFormat,
    /// The file names a cache cipher suite this build cannot open.
    UnsupportedSuite(u16),
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
            Self::InvalidFormat => "cache file has an invalid format marker",
            Self::UnsupportedSuite(suite) => {
                return write!(f, "cache file uses unsupported cipher suite {suite}");
            }
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
/// The output starts with a format marker and cipher-suite identifier, followed
/// by the nonce and ciphertext. The nonce is cleartext, which is standard and
/// safe: a nonce is not a secret, only a value that must not repeat.
///
/// # Errors
///
/// [`Error::Seal`] if the AEAD fails, which cannot happen for valid inputs.
pub fn seal(key: &SealKey, nonce: &[u8; NONCE_LEN], netmap: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Cipher::new(Algorithm::Aes256Gcm, &key.0);
    let ct = cipher
        .seal(nonce, CACHE_AAD, netmap)
        .map_err(|_| Error::Seal)?;

    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&SUITE_AES_256_GCM.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed netmap.
///
/// # Errors
///
/// [`Error::Truncated`] if the file is too short to contain its header and
/// nonce, [`Error::InvalidFormat`] or [`Error::UnsupportedSuite`] if its format
/// cannot be opened by this build, and [`Error::Unreadable`] if authentication
/// fails.
pub fn open(key: &SealKey, sealed: &[u8]) -> Result<Vec<u8>, Error> {
    let (header, body) = sealed
        .split_at_checked(HEADER_LEN)
        .ok_or(Error::Truncated)?;
    if header.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(Error::InvalidFormat);
    }
    let suite = u16::from_be_bytes(
        header
            .get(MAGIC.len()..)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    );
    if suite != SUITE_AES_256_GCM {
        return Err(Error::UnsupportedSuite(suite));
    }
    let (nonce, ct) = body.split_at_checked(NONCE_LEN).ok_or(Error::Truncated)?;
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Truncated)?;
    let cipher = Cipher::new(Algorithm::Aes256Gcm, &key.0);
    cipher
        .open(nonce, CACHE_AAD, ct)
        .map_err(|_| Error::Unreadable)
}
