// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Per-pair PSK derivation (PLAN.md §2.6).
//!
//! The server derives these and ships them in the netmap; a node normally
//! receives rather than computes them. This implementation exists so a node
//! can verify what it was sent, and so the two implementations can be pinned
//! against one another by `spec/vectors/karst-control-v1.json`.

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

/// PSK width, matching `phreatic-v1.md` §7.
pub const PSK_LEN: usize = 32;

const LABEL: &[u8] = b"karst-psk-v1";

/// A per-pair pre-shared key.
///
/// Deliberately does not implement `Display`, and its `Debug` redacts: a PSK
/// reaching a log line is a reportable defect, and the type is the only place
/// that can be enforced rather than remembered.
#[derive(Clone, PartialEq, Eq)]
pub struct Psk([u8; PSK_LEN]);

impl Psk {
    /// The raw bytes. Every caller of this is a place a PSK can escape.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PSK_LEN] {
        &self.0
    }

    /// The all-zero fallback used when a node holds no PSK for a peer (§2.6).
    /// Such sessions are lattice-only and must be flagged as such.
    #[must_use]
    pub fn zero() -> Self {
        Self([0u8; PSK_LEN])
    }

    /// Whether this is the fallback rather than a derived key.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().fold(0u8, |acc, b| acc | b) == 0
    }
}

impl From<[u8; PSK_LEN]> for Psk {
    fn from(v: [u8; PSK_LEN]) -> Self {
        Self(v)
    }
}

impl core::fmt::Debug for Psk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Psk(redacted)")
    }
}

impl Drop for Psk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

/// Derive the PSK shared by two node handles at an epoch.
///
/// Order-independent: the handles are sorted, so both ends derive the same key
/// without agreeing who is first. Getting this wrong produces two different
/// keys per pair and a handshake failure that looks like a key mismatch.
///
/// Returns `None` for an empty handle or a self-pair.
#[must_use]
pub fn pair(master: &[u8; PSK_LEN], a: &str, b: &str, epoch: u32) -> Option<Psk> {
    if a.is_empty() || b.is_empty() || a == b {
        return None;
    }
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };

    let mut info = Vec::with_capacity(LABEL.len() + lo.len() + hi.len() + 24);
    info.extend_from_slice(LABEL);
    push_field(&mut info, lo.as_bytes());
    push_field(&mut info, hi.as_bytes());
    push_field(&mut info, &epoch.to_be_bytes());

    let hk = Hkdf::<Sha512>::new(None, master);
    let mut out = [0u8; PSK_LEN];
    hk.expand(&info, &mut out).ok()?;
    Some(Psk(out))
}
