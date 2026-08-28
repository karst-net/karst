// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Signature primitives for Bedrock's trust hierarchy — [ADR-0001] parameters,
//! [ADR-0014] tiering.
//!
//! One algorithm, two tiers — ADR-0015's Option A.
//!
//! | Tier | Algorithm | pk | sig | Signs |
//! |---|---|---|---|---|
//! | Root | ML-DSA-87 | 2 592 B | 4 627 B | The authority list, a handful of times ever |
//! | Authority | ML-DSA-87 | 2 592 B | 4 627 B | One countersignature per node, replicated to every node |
//!
//! # The root was hash-based, and is not any more
//!
//! [ADR-0001] chose SLH-DSA-SHA2-192s for the root *because it is not
//! lattice-based*: a break of lattice cryptography takes ML-KEM and ML-DSA
//! together, and the ability to re-key the network was meant to survive it.
//! [ADR-0014] built the two-tier hierarchy on that property.
//!
//! CNSA 2.0 excludes SLH-DSA — "not approved for any use in NSS" — so ADR-0015
//! took ML-DSA-87 rather than the stateful LMS alternative, and recorded the
//! cost: **there is no assumption-diversity hedge above the authority tier any
//! more.** A lattice break now takes the whole hierarchy, recovery path
//! included.
//!
//! # Domain separation is not optional here
//!
//! Every signature is made under a context string, and the tier is part of it.
//! A root signature must never be a valid authority signature and vice versa,
//! **even though the algorithms differ today**, because the whole point of the
//! rotatable authority tier is that they will not always differ.
//!
//! # Signing here is deterministic, and on the control channel it is not
//!
//! `identity.go` signs control-channel messages *hedged* (randomized), because
//! a deterministic signature hands a fault-injection attacker a repeatable
//! target. Bedrock signs deterministically, and the difference is not an
//! oversight.
//!
//! A control-channel key signs continuously, on a networked server, where an
//! attacker can induce faults without ever holding the machine. A Bedrock key
//! signs a handful of times, during a deliberate ceremony, on a machine that in
//! the intended deployment has no network interface — so mounting a fault
//! attack means physical possession of the signing machine, at which point the
//! key itself is available and the fault buys nothing.
//!
//! What determinism buys in exchange is worth more than that: a second admin
//! can re-run the ceremony and get byte-identical output, which is the only
//! practical check that the bundle an admin signed is the bundle they were
//! shown. It is also what lets `spec/vectors/bedrock-v1.json` pin exact
//! signature bytes rather than merely asserting that both implementations
//! verify.
//!
//! [ADR-0001]: ../../../docs/adr/0001-cryptographic-algorithm-selection.md
//! [ADR-0014]: ../../../docs/adr/0014-bedrock-trust-hierarchy.md

use zeroize::Zeroizing;

/// ML-DSA-87 public key size.
pub const ROOT_PUBLIC_KEY: usize = 2_592;
/// ML-DSA-87 signature size.
pub const ROOT_SIGNATURE: usize = 4_627;
/// ML-DSA-87 seed size. The seed is the whole secret: ML-DSA expands it
/// deterministically and the expanded form never needs to leave the process.
pub const ROOT_SEED: usize = 32;

/// ML-DSA-87 public key size.
pub const AUTHORITY_PUBLIC_KEY: usize = 2_592;
/// ML-DSA-87 signature size.
pub const AUTHORITY_SIGNATURE: usize = 4_627;
/// ML-DSA-87 seed size.
pub const AUTHORITY_SEED: usize = 32;

/// ML-DSA-87 public key size — the node control-channel key a `node-sign`
/// covers.
///
/// Numerically equal to [`AUTHORITY_PUBLIC_KEY`] now that ADR-0015 item 5 has
/// moved node identity to Category 5 too. Kept separate because the two are
/// different things that happen to share a size, and a future tier split should
/// not have to rediscover which call sites meant which.
pub const NODE_IDENTITY_KEY: usize = 2_592;

/// Context string for signatures made by an offline root key.
pub const ROOT_CONTEXT: &[u8] = b"karst-bedrock-v1 root";
/// Context string for signatures made by an authority key.
pub const AUTHORITY_CONTEXT: &[u8] = b"karst-bedrock-v1 authority";

// ── root tier ───────────────────────────────────────────────────────────────

/// An offline root signing key.
///
/// The private key never leaves the machine that generated it; in the intended
/// deployment that machine has no network interface at all. This type exists so
/// that `karst-bedrock` (the offline signer) can hold one — nothing on the
/// coordination server or on a node ever constructs it.
pub struct RootKey {
    inner: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>,
    seed: Zeroizing<Vec<u8>>,
}

// The seed is the whole secret. Debug must not print it, and the derive would.
impl core::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RootKey").finish_non_exhaustive()
    }
}

impl RootKey {
    /// Derive a root key from its 32-byte seed.
    ///
    /// A seed rather than an RNG trait, and the reason outlived the version
    /// mismatch that first forced it: this is the key anchoring the entire
    /// network, generated during a ceremony on an offline machine, and *where
    /// the bytes came from* is the most important property of that ceremony. A
    /// trait bound hides that behind whatever the caller passed; a seed puts it
    /// at the call site where a reviewer can see it.
    ///
    /// # Errors
    ///
    /// [`SignError::KeySize`] if `seed` is not exactly [`ROOT_SEED`] bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignError> {
        let array: [u8; ROOT_SEED] = seed.try_into().map_err(|_| SignError::KeySize)?;
        Ok(Self {
            inner: ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(&array.into()),
            seed: Zeroizing::new(seed.to_vec()),
        })
    }

    /// The 32-byte seed, for writing to offline media.
    ///
    /// Returns `Zeroizing` so a caller cannot casually leave a copy on the heap;
    /// it is still the caller's job not to write it somewhere durable by
    /// mistake.
    #[must_use]
    pub fn seed(&self) -> Zeroizing<Vec<u8>> {
        self.seed.clone()
    }

    /// The 2592-byte public key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.verifying_key().encode().to_vec()
    }

    /// Sign under [`ROOT_CONTEXT`]. Deterministic — see the module docs.
    ///
    /// # Errors
    ///
    /// [`SignError::Sign`] if the signature operation fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        self.inner
            .sign_deterministic(msg, ROOT_CONTEXT)
            .map(|s| s.encode().to_vec())
            .map_err(|_| SignError::Sign)
    }
}

/// Verify a root signature under [`ROOT_CONTEXT`].
///
/// Returns `false` rather than an error on malformed input, because every
/// caller is authenticating attacker-supplied bytes and there is exactly one
/// useful outcome — the same convention as `identity.Verify` on the Go side.
#[must_use]
pub fn verify_root(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if public_key.len() != ROOT_PUBLIC_KEY || sig.len() != ROOT_SIGNATURE {
        return false;
    }
    let Ok(pk) = <[u8; ROOT_PUBLIC_KEY]>::try_from(public_key) else {
        return false;
    };
    let Ok(sg) = <[u8; ROOT_SIGNATURE]>::try_from(sig) else {
        return false;
    };
    let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&pk.into());
    let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa87>::decode(&sg.into()) else {
        return false;
    };
    vk.verify_with_context(msg, ROOT_CONTEXT, &sig)
}

// ── authority tier ──────────────────────────────────────────────────────────

/// An authority signing key. Lives on an admin device, a subset offline.
pub struct AuthorityKey {
    inner: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>,
}

impl core::fmt::Debug for AuthorityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorityKey").finish_non_exhaustive()
    }
}

impl AuthorityKey {
    /// Expand an authority key from its 32-byte seed.
    ///
    /// # Errors
    ///
    /// [`SignError::KeySize`] if the seed is not exactly 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignError> {
        let seed: [u8; AUTHORITY_SEED] = seed.try_into().map_err(|_| SignError::KeySize)?;
        Ok(Self {
            inner: ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(&seed.into()),
        })
    }

    /// The 2592-byte public key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.verifying_key().encode().to_vec()
    }

    /// Sign under [`AUTHORITY_CONTEXT`]. Deterministic — see the module docs.
    ///
    /// # Errors
    ///
    /// [`SignError::Sign`] if the signature operation fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        self.inner
            .sign_deterministic(msg, AUTHORITY_CONTEXT)
            .map(|s| s.encode().to_vec())
            .map_err(|_| SignError::Sign)
    }
}

/// Verify an authority signature under [`AUTHORITY_CONTEXT`].
#[must_use]
pub fn verify_authority(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = <[u8; AUTHORITY_PUBLIC_KEY]>::try_from(public_key) else {
        return false;
    };
    let Ok(sg) = <[u8; AUTHORITY_SIGNATURE]>::try_from(sig) else {
        return false;
    };
    let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&pk.into());
    let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa87>::decode(&sg.into()) else {
        return false;
    };
    vk.verify_with_context(msg, AUTHORITY_CONTEXT, &sig)
}

// ── errors ──────────────────────────────────────────────────────────────────

/// A signing-side failure. Verification never produces one of these: it returns
/// `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The key material was the wrong length.
    KeySize,
    /// The signature operation itself failed.
    Sign,
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeySize => f.write_str("wrong key size"),
            Self::Sign => f.write_str("signing failed"),
        }
    }
}

impl std::error::Error for SignError {}

#[cfg(test)]
mod tests {
    // Tests signal failure by panicking; the workspace bans on
    // `panic`/`expect`/`unwrap` target library code on the pre-authentication
    // path, not assertions.
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// A fixed, non-secret root key.
    fn test_root() -> RootKey {
        RootKey::from_seed(&[0x11u8; ROOT_SEED]).unwrap()
    }

    #[test]
    fn root_sizes_match_adr_0001() {
        let k = test_root();
        assert_eq!(k.public_key().len(), ROOT_PUBLIC_KEY);
        assert_eq!(k.seed().len(), ROOT_SEED);
        assert_eq!(k.sign(b"x").unwrap().len(), ROOT_SIGNATURE);
    }

    #[test]
    fn authority_sizes_match_adr_0001() {
        let k = AuthorityKey::from_seed(&[7u8; AUTHORITY_SEED]).unwrap();
        assert_eq!(k.public_key().len(), AUTHORITY_PUBLIC_KEY);
        assert_eq!(k.sign(b"x").unwrap().len(), AUTHORITY_SIGNATURE);
    }

    #[test]
    fn root_round_trip() {
        let k = test_root();
        let msg = b"the authority list";
        let sig = k.sign(msg).unwrap();
        assert!(verify_root(&k.public_key(), msg, &sig));
        assert!(!verify_root(&k.public_key(), b"a different list", &sig));
    }

    #[test]
    fn authority_round_trip() {
        let k = AuthorityKey::from_seed(&[9u8; AUTHORITY_SEED]).unwrap();
        let msg = b"a node countersignature";
        let sig = k.sign(msg).unwrap();
        assert!(verify_authority(&k.public_key(), msg, &sig));
        assert!(!verify_authority(&k.public_key(), b"another node", &sig));
    }

    /// Root signing is deterministic, which is what lets a vector pin the exact
    /// signature bytes and what lets a second admin reproduce a ceremony.
    #[test]
    fn root_signing_is_deterministic() {
        let k = test_root();
        assert_eq!(
            k.sign(b"same message").unwrap(),
            k.sign(b"same message").unwrap()
        );
    }

    #[test]
    fn root_key_survives_serialisation() {
        let k = test_root();
        let restored = RootKey::from_seed(&k.seed()).unwrap();
        assert_eq!(k.public_key(), restored.public_key());
        assert_eq!(k.sign(b"m").unwrap(), restored.sign(b"m").unwrap());
    }

    #[test]
    fn wrong_sizes_are_refused_rather_than_panicking() {
        assert!(matches!(
            RootKey::from_seed(&[0u8; 31]),
            Err(SignError::KeySize)
        ));
        assert!(matches!(
            AuthorityKey::from_seed(&[0u8; 31]),
            Err(SignError::KeySize)
        ));
        assert!(!verify_root(&[0u8; 47], b"m", &[0u8; ROOT_SIGNATURE]));
        assert!(!verify_root(&[0u8; ROOT_PUBLIC_KEY], b"m", &[0u8; 16_223]));
        assert!(!verify_authority(
            &[0u8; 1951],
            b"m",
            &[0u8; AUTHORITY_SIGNATURE]
        ));
    }

    /// The tiers must not be interchangeable. Today the algorithms differ, so
    /// this is trivially true; the test exists because ADR-0014 makes the
    /// authority tier rotatable, and the day it rotates onto a hash-based
    /// algorithm this stops being trivial and starts being load-bearing.
    #[test]
    fn tier_contexts_differ() {
        assert_ne!(ROOT_CONTEXT, AUTHORITY_CONTEXT);
    }
}
