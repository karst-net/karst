// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Control-channel cipher suites — ADR-0015 item 4.
//!
//! The mirror of `server/management/internals/karst/channel/suite.go`, which
//! carries the full reasoning. The short version:
//!
//! **One number gates both the envelope format and the algorithms.**
//! `karst-control-v1.md` §3 has always said the suite is implied by the
//! protocol version; this makes that executable, so an algorithm cannot change
//! without the version changing. ADR-0015 item 5 moved this channel from
//! ML-DSA-65 to ML-DSA-87 and nothing objected, because the version was a bare
//! constant with no registry behind it.
//!
//! **There is no negotiation, and that is deliberate.** The data plane
//! negotiates because two nodes configured by different people must agree; a
//! control channel is one operator's node talking to their own server. What
//! replaces negotiation is a floor: the server states its version, and the node
//! refuses anything below its own minimum. That is ADR-0006's rule — a
//! compromised server may raise the floor and never lower it — applied to the
//! channel ADR-0006 did not cover.

/// Everything the control channel's cryptography is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub version: u32,
    pub name: &'static str,
    /// Size of the server's static ML-KEM key, which is what a node pins.
    pub kem_public_key: usize,
    pub kem_ciphertext: usize,
    pub signature_public_key: usize,
    pub signature: usize,
    pub aead: &'static str,
    pub hash: &'static str,
    /// Whether this build can actually speak it. A known version that is not
    /// implemented is a different failure from an unknown one.
    pub implemented: bool,
}

/// The shipping suite. ML-DSA-87 rather than ADR-0011's original ML-DSA-65 —
/// ADR-0015 made CNSA 2.0 a mandate and Category 5 applies to every signature.
const V1: Suite = Suite {
    version: 1,
    name: "KARST_CONTROL_1_MLKEM768_MLDSA87_CHACHA20_SHA512",
    kem_public_key: 1184,
    kem_ciphertext: 1088,
    signature_public_key: 2592,
    signature: 4627,
    aead: "ChaCha20-Poly1305",
    hash: "SHA-512",
    implemented: true,
};

/// The CNSA 2.0 profile, reserved and not implemented.
///
/// A deployment under the mandate needs ML-KEM-1024 and AES-256-GCM here
/// (ADR-0015 items 2 and 3) — ChaCha20-Poly1305 is not a NIST algorithm at all.
/// Naming the version now makes the failure "this build does not implement
/// version 2" rather than "unknown version 2", and lets an operator set the
/// floor to it and be refused honestly.
///
/// **Both primitives now exist and this row is still not implemented**, which
/// is the honest state: `karst_crypto::aead` has AES-256-GCM and
/// `karst_crypto::kem` now dispatches between both parameter sets at run time,
/// but `channel.rs` and `transport.rs` name `MlKem768Backend` and
/// ChaCha20-Poly1305 directly, so speaking v2 is a matter of dispatching there.
/// Flipping this flag first would advertise a suite the channel does not run.
///
/// The data plane finished exactly that on 2026-08-25 (ADR-0015 item 1), and
/// item 7 then removed ChaCha20-Poly1305 from it outright. **That makes this
/// channel the only place in the tree a CNSA 2.0 or FIPS 140-3 deployment is
/// non-conformant** — `karst_crypto::aead` no longer has `ChaCha` at all, and the
/// two uses that remain (`channel.rs` and `cache.rs`) reach the algorithm
/// directly. This row is what closes that, and the netmap cache, which has no
/// suite mechanism at all, is what follows it.
const V2: Suite = Suite {
    version: 2,
    name: "KARST_CONTROL_2_MLKEM1024_MLDSA87_AES256GCM_SHA512",
    kem_public_key: 1568,
    kem_ciphertext: 1568,
    signature_public_key: 2592,
    signature: 4627,
    aead: "AES-256-GCM",
    hash: "SHA-512",
    implemented: false,
};

/// The complete registry. Adding an algorithm means adding a row; there is no
/// other way to change what the channel does.
pub static SUITES: &[Suite] = &[V1, V2];

/// Why a version was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteError {
    /// Never heard of — a peer newer than this build, or a corrupted field.
    Unknown(u32),
    /// Known, and this build cannot speak it.
    NotImplemented { version: u32, name: &'static str },
    /// Weaker than this node's configured minimum.
    BelowMinimum { offered: u32, minimum: u32 },
    /// A pinned key is the wrong size for the suite, which means the pins and
    /// the configured version disagree about the algorithm.
    PinMismatch(String),
}

impl core::fmt::Display for SuiteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown(v) => write!(f, "unknown control protocol version {v}"),
            Self::NotImplemented { version, name } => write!(
                f,
                "control protocol version {version} ({name}) is not implemented by this build"
            ),
            Self::BelowMinimum { offered, minimum } => write!(
                f,
                "the server offered control version {offered}, below this node's minimum of \
                 {minimum}; refusing rather than accepting a weaker suite"
            ),
            Self::PinMismatch(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for SuiteError {}

/// The suite a version selects.
///
/// # Errors
///
/// [`SuiteError::Unknown`] or [`SuiteError::NotImplemented`].
pub fn suite_for(version: u32) -> Result<Suite, SuiteError> {
    let Some(s) = SUITES.iter().find(|s| s.version == version) else {
        return Err(SuiteError::Unknown(version));
    };
    if !s.implemented {
        return Err(SuiteError::NotImplemented {
            version,
            name: s.name,
        });
    }
    Ok(*s)
}

/// Resolve the version a server offered against what this node will accept.
///
/// # Errors
///
/// [`SuiteError::BelowMinimum`] when the offer is under the node's floor, and
/// whatever [`suite_for`] returns otherwise.
pub fn negotiate(offered: u32, minimum: u32) -> Result<Suite, SuiteError> {
    if offered < minimum {
        return Err(SuiteError::BelowMinimum { offered, minimum });
    }
    suite_for(offered)
}

impl Suite {
    /// Check pinned server keys against this suite's algorithms.
    ///
    /// The pin lengths *are* the algorithm — a 1 184-byte key is ML-KEM-768 and
    /// nothing else — so this catches a deployment configured for one version
    /// with pins from another, at startup, naming both numbers. The alternative
    /// is a handshake failing on a signature or a decapsulation and sending
    /// somebody looking in entirely the wrong place.
    ///
    /// # Errors
    ///
    /// [`SuiteError::PinMismatch`] with a sentence naming both sizes.
    pub fn check_pins(&self, static_kem: &[u8], verify_key: &[u8]) -> Result<(), SuiteError> {
        if static_kem.len() != self.kem_public_key {
            return Err(SuiteError::PinMismatch(format!(
                "server_kem_pin is {} bytes, but control version {} ({}) uses a {}-byte key",
                static_kem.len(),
                self.version,
                self.name,
                self.kem_public_key
            )));
        }
        if verify_key.len() != self.signature_public_key {
            return Err(SuiteError::PinMismatch(format!(
                "server_verify_pin is {} bytes, but control version {} ({}) uses a {}-byte key",
                verify_key.len(),
                self.version,
                self.name,
                self.signature_public_key
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_shipping_suite_resolves() {
        let s = suite_for(1).expect("v1 is implemented");
        assert_eq!(s.kem_public_key, 1184);
        assert_eq!(s.signature_public_key, 2592);
        assert_eq!(s.signature, 4627);
    }

    /// A reserved version fails differently from an invented one. The
    /// distinction is the whole reason v2 is in the registry rather than absent
    /// from it: one error tells an operator to get a different build, the other
    /// tells them something is corrupt.
    #[test]
    fn a_reserved_version_is_distinguishable_from_an_unknown_one() {
        assert!(matches!(
            suite_for(2),
            Err(SuiteError::NotImplemented { version: 2, .. })
        ));
        assert!(matches!(suite_for(3), Err(SuiteError::Unknown(3))));
        assert!(matches!(suite_for(0), Err(SuiteError::Unknown(0))));
    }

    /// **A server may not talk a node down.** The node's floor wins even when
    /// this build could happily speak what was offered.
    #[test]
    fn a_server_cannot_offer_below_the_nodes_floor() {
        assert!(negotiate(1, 1).is_ok());
        assert!(matches!(
            negotiate(1, 2),
            Err(SuiteError::BelowMinimum {
                offered: 1,
                minimum: 2
            })
        ));
    }

    /// A floor above anything implemented refuses everything, which is correct:
    /// a node configured for a suite this build cannot speak should not fall
    /// back to one it can.
    #[test]
    fn a_floor_above_this_build_refuses_rather_than_falling_back() {
        assert!(matches!(
            negotiate(2, 2),
            Err(SuiteError::NotImplemented { version: 2, .. })
        ));
    }

    #[test]
    fn pins_are_checked_against_the_suite_not_a_constant() {
        let s = suite_for(1).expect("v1");
        assert!(s.check_pins(&[0u8; 1184], &[0u8; 2592]).is_ok());

        // A v2-sized KEM pin against v1 names both numbers.
        let err = s
            .check_pins(&[0u8; 1568], &[0u8; 2592])
            .expect_err("mismatched pin");
        let text = format!("{err}");
        assert!(text.contains("1568") && text.contains("1184"), "{text}");
    }

    /// Every registry entry must be internally consistent, so a row added later
    /// cannot quietly claim a size that no algorithm has.
    #[test]
    fn the_registry_is_well_formed() {
        let mut seen = Vec::new();
        for s in SUITES {
            assert!(
                !seen.contains(&s.version),
                "duplicate version {}",
                s.version
            );
            seen.push(s.version);
            assert!(s.version > 0, "zero is not a version");
            assert!(!s.name.is_empty());
            assert!(s.kem_public_key > 0 && s.kem_ciphertext > 0);
            assert!(s.signature_public_key > 0 && s.signature > 0);
        }
        assert!(
            SUITES.iter().any(|s| s.implemented),
            "no implemented suite: this build could not open a control channel at all"
        );
    }
}
