// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The two suite hashes, and the HKDF built on them — [ADR-0001], and
//! [ADR-0015] for why the second one exists.
//!
//! | Suite | Hash | Output |
//! |---|---|---|
//! | `KARST_1` | SHA-512 | 64 B |
//! | `KARST_2` | SHA-384 | 48 B |
//!
//! # Why the CNSA suite hashes *shorter*
//!
//! It looks like a downgrade and is not. CNSA 2.0 names SHA-384 and SHA-512
//! both, and 384 bits of output is Category 5 against Grover — the choice
//! here follows the profile's own pairing of SHA-384 with AES-256 rather than
//! any belief that 512 was insufficient. What it costs is a shorter transcript
//! hash, and what it buys is a suite an auditor can check against the published
//! profile line by line.
//!
//! # The transcript length becomes a variable
//!
//! Until [ADR-0015] item 1, `karst-noise` hashed with SHA-512 unconditionally
//! and `HASH_LEN` was a constant 64. Two suites with different output lengths
//! make that a per-session property, which is why [`Digest`] carries its own
//! length rather than being a `[u8; 64]`: a 48-byte transcript zero-padded to
//! 64 would hash the padding, and the two ends would agree on it, and nobody
//! would notice for years.
//!
//! # What is *not* suite-dependent
//!
//! Two SHA-512 uses stay fixed no matter which suite a session negotiates,
//! because both are computed before a suite is known:
//!
//! * `peer_id_hint` (spec §4) is a roster lookup label. A responder precomputes
//!   a table of them; making it suite-dependent would mean one entry per suite
//!   for no gain, since the real binding of a peer's static key into the
//!   session is `MixHash(HASH(S_r_pk))` at step 3, which *does* use the suite
//!   hash.
//! * The fragment MAC key (spec §9.2, `karst_proto::dos`) is derived from a
//!   public static key and checked on fragments that do not carry the suite
//!   field at all — only fragment 0 of a `HandshakeInit` does.
//!
//! [ADR-0001]: ../../../docs/adr/0001-cryptographic-algorithm-selection.md
//! [ADR-0015]: ../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md

use hkdf::Hkdf;
use sha2::{Digest as _, Sha384, Sha512};

use crate::SuiteId;

/// Longest output any registered suite hash produces.
///
/// [`Digest`] is sized by this, so a suite added with a longer hash fails to
/// compile here rather than silently truncating.
pub const MAX_LEN: usize = 64;

/// Which hash a suite uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha384,
    Sha512,
}

impl Algorithm {
    /// The hash a suite selects.
    ///
    /// Total, because a `SuiteId` cannot be constructed for a suite outside the
    /// registry — the same reason `SuiteId::params` is total.
    #[must_use]
    pub fn for_suite(suite: SuiteId) -> Self {
        match suite.params().hash {
            "SHA-384" => Self::Sha384,
            _ => Self::Sha512,
        }
    }

    /// The registry's name for this algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Output length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Hash the concatenation of `parts`.
    ///
    /// Takes a slice of slices rather than a single buffer because every caller
    /// is hashing a transcript prefix followed by new material, and joining
    /// those first would copy the whole transcript once per step.
    #[must_use]
    pub fn digest(self, parts: &[&[u8]]) -> Digest {
        let mut out = Digest {
            bytes: [0u8; MAX_LEN],
            len: self.output_len(),
        };
        match self {
            Self::Sha384 => {
                let mut d = Sha384::new();
                for p in parts {
                    d.update(p);
                }
                copy_prefix(&mut out.bytes, &d.finalize());
            }
            Self::Sha512 => {
                let mut d = Sha512::new();
                for p in parts {
                    d.update(p);
                }
                copy_prefix(&mut out.bytes, &d.finalize());
            }
        }
        out
    }

    /// HKDF-Extract-then-Expand with an empty `info`, filling `okm`.
    ///
    /// Returns `false` if the requested output is longer than HKDF can produce
    /// (255 hash blocks). Every caller in the tree asks for 64, 96 or 128 bytes,
    /// so this is a guard rather than a case anyone handles.
    pub fn hkdf(self, salt: &[u8], ikm: &[u8], okm: &mut [u8]) -> bool {
        match self {
            Self::Sha384 => Hkdf::<Sha384>::new(Some(salt), ikm)
                .expand(&[], okm)
                .is_ok(),
            Self::Sha512 => Hkdf::<Sha512>::new(Some(salt), ikm)
                .expand(&[], okm)
                .is_ok(),
        }
    }
}

fn copy_prefix(dst: &mut [u8; MAX_LEN], src: &[u8]) {
    let n = src.len().min(MAX_LEN);
    if let (Some(d), Some(s)) = (dst.get_mut(..n), src.get(..n)) {
        d.copy_from_slice(s);
    }
}

/// A hash output that carries its own length.
///
/// The length is the point: SHA-384 and SHA-512 outputs must never be compared,
/// concatenated or hashed as if they were the same width. Everything that reads
/// one goes through [`Digest::as_bytes`], which returns only the meaningful
/// prefix.
#[derive(Clone, Copy)]
pub struct Digest {
    bytes: [u8; MAX_LEN],
    len: usize,
}

impl Digest {
    /// The output, at its real length.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    /// Output length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the output is zero-length, which no registered hash produces.
    /// Present because a public `len` is expected to come with one.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Constant-time-ish equality is not needed — a transcript hash is public — but
/// comparing only the meaningful prefix is.
impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Digest {}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Digest(")?;
        for b in self.as_bytes().iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…, {} B)", self.len)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::SUITES;

    /// The registry is the authority. A row naming a hash with no
    /// implementation behind it is exactly the failure FINDINGS 53 recorded for
    /// the AEAD, so it is asserted here for the same reason.
    #[test]
    fn every_suite_selects_an_implemented_hash_of_the_advertised_length() {
        for s in SUITES {
            let a = Algorithm::for_suite(s.id);
            assert_eq!(a.name(), s.hash, "{} advertises {}", s.name, s.hash);
            assert_eq!(a.output_len(), s.hash_len, "{}", s.name);
            assert_eq!(a.digest(&[b"x"]).len(), s.hash_len, "{}", s.name);
        }
    }

    #[test]
    fn the_two_hashes_are_the_documented_lengths() {
        assert_eq!(Algorithm::Sha384.output_len(), 48);
        assert_eq!(Algorithm::Sha512.output_len(), 64);
        assert_eq!(Algorithm::Sha384.digest(&[b"abc"]).as_bytes().len(), 48);
        assert_eq!(Algorithm::Sha512.digest(&[b"abc"]).as_bytes().len(), 64);
    }

    /// FIPS 180-4 test vectors for `"abc"`, so the wiring is checked against the
    /// standard rather than against itself.
    #[test]
    fn the_digests_match_fips_180_4() {
        let hex = |d: Digest| {
            use core::fmt::Write as _;
            let mut out = String::new();
            for b in d.as_bytes() {
                let _ = write!(out, "{b:02x}");
            }
            out
        };
        assert_eq!(
            hex(Algorithm::Sha384.digest(&[b"abc"])),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(Algorithm::Sha512.digest(&[b"abc"])),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// Splitting the input across parts must be identical to hashing the join —
    /// the property every `mix_hash` call relies on.
    #[test]
    fn parts_concatenate() {
        for a in [Algorithm::Sha384, Algorithm::Sha512] {
            assert_eq!(a.digest(&[b"foo", b"bar"]), a.digest(&[b"foobar"]));
        }
    }

    /// Two suites at different hash lengths must never produce equal digests,
    /// including when one is a prefix of the other. `Digest` comparing only its
    /// meaningful prefix is what makes this worth asserting.
    #[test]
    fn a_shorter_digest_is_never_equal_to_a_longer_one() {
        assert_ne!(
            Algorithm::Sha384.digest(&[b"same input"]),
            Algorithm::Sha512.digest(&[b"same input"])
        );
    }

    #[test]
    fn hkdf_is_deterministic_and_hash_dependent() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let mut c = [0u8; 64];
        assert!(Algorithm::Sha512.hkdf(b"salt", b"ikm", &mut a));
        assert!(Algorithm::Sha512.hkdf(b"salt", b"ikm", &mut b));
        assert!(Algorithm::Sha384.hkdf(b"salt", b"ikm", &mut c));
        assert_eq!(a, b, "same inputs, same output");
        assert_ne!(a, c, "the hash must reach the derived key");
    }

    #[test]
    fn debug_shows_the_length_and_not_the_whole_value() {
        let rendered = format!("{:?}", Algorithm::Sha384.digest(&[b"x"]));
        assert!(rendered.contains("48 B"), "{rendered}");
        assert!(rendered.len() < 40, "{rendered}");
    }
}
