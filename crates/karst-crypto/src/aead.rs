// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The data-plane AEAD, selected by cipher suite — [ADR-0001], and [ADR-0015]
//! for why there is now only one.
//!
//! | Suite | AEAD |
//! |---|---|
//! | `KARST_1` | AES-256-GCM |
//! | `KARST_2` | AES-256-GCM |
//!
//! # ChaCha20-Poly1305 was here, and is gone
//!
//! It was `KARST_1`'s AEAD and the registry's default: constant-time in
//! software and fast without AES-NI, which is what the hobbyist half of the
//! audience runs. [ADR-0015] item 7 removed it. **The reason is not strength.**
//! ChaCha20-Poly1305 is RFC 8439, an IETF specification, and is not a NIST
//! algorithm — so it cannot run inside a FIPS 140-3 boundary and CNSA 2.0 does
//! not name it. Once CNSA 2.0 became a mandate rather than an option, keeping a
//! suite no mandated deployment could select bought a second code path, a
//! second set of test vectors and a second thing to get wrong, for nobody.
//!
//! The performance argument it was carrying is real and now unanswered: a node
//! without AES-NI pays for AES-256-GCM in software, where a constant-time
//! implementation is markedly slower. That cost was accepted knowingly. AES-NI
//! and `ARMv8` crypto extensions are near-universal on hardware new enough to run
//! this, and the alternative was a suite that is unusable in the deployments
//! the project is being held to.
//!
//! ChaCha20-Poly1305 still runs on the **control channel**, which has its own
//! registry (`karst-control-client::suite`) and reaches the algorithm directly
//! rather than through this module. The netmap cache now uses this module's
//! AES-256-GCM implementation and carries its own suite identifier.
//!
//! # One algorithm, and still an enum
//!
//! [`Algorithm`] has a single variant. That is deliberate: [`Algorithm::for_suite`]
//! is the mechanism that stops a registry row naming an AEAD nothing runs —
//! the defect FINDINGS 53 recorded, when AES-256-GCM was named everywhere and
//! implemented nowhere — and it has to survive having exactly one answer today.
//! Adding the next AEAD is a variant and a match arm, with no caller changed.
//!
//! [`KEY_LEN`], [`NONCE_LEN`] and [`TAG_LEN`] stay named constants for the same
//! reason. A second AEAD that agreed on 32/12/16 would slot in behind
//! [`Cipher`]; one that did not would break loudly at these, which is where it
//! should break.
//!
//! # `Cipher`'s round-key schedule is zeroized on drop, and it took a second
//! # dependency to make that true
//!
//! `aes-gcm` declares an optional `zeroize` dependency in its own manifest but
//! wires it to no feature that turns it on, and exposes nothing to reach past
//! itself into `aes`'s own `zeroize` feature — which is what actually gates
//! whether `aes`'s expanded round keys implement `Drop`. Found during Phase 6's
//! internal cryptographic review: every long-lived AEAD key schedule in the
//! data plane — every live [`Cipher`], meaning every established
//! `TransportSession`'s send and receive keys — was being freed unzeroized for
//! as long as this crate has existed, silently, because turning on `aes-gcm`'s
//! `aes` feature (needed for hardware acceleration) does not turn on `aes`'s
//! own `zeroize` feature and nothing else in the graph did either.
//!
//! The fix is `Cargo.toml`'s: an otherwise-unused direct dependency on `aes`
//! with `features = ["zeroize"]`. Cargo unifies features per resolved package,
//! not per dependent, so enabling it on a direct-but-unused edge is enough to
//! flip it on for the *same* `aes` instance `aes-gcm` links against — no code
//! here changes. `ml-kem` and `ml-dsa` had the identical gap for the same
//! reason (an upstream crate's own zeroize support sitting behind a Cargo
//! feature nothing turned on) and the fix there is the same shape, in
//! `kem.rs` and `sign.rs`'s Cargo dependency lines rather than in their
//! source.
//!
//! [ADR-0001]: ../../../docs/adr/0001-cryptographic-algorithm-selection.md
//! [ADR-0015]: ../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md

use aes_gcm::Aes256Gcm;

use aes_gcm::aead::{Aead as _, AeadInPlace as _, KeyInit as _, Payload};

// A compile-time guarantee, not a runtime one — this crate forbids
// `unsafe_code`, which rules out inspecting freed memory the way `aes`'s own
// `zeroize_works` test does. `aes_gcm::Aes256Gcm` has no `ZeroizeOnDrop` of
// its own to assert against — Rust's default drop glue is what propagates
// into its round-key field, not a marker on the outer type — so this checks
// the thing the fix actually depends on: that the `aes` package instance
// this build resolves to (the same one `aes-gcm` links against, per Cargo's
// per-package feature unification) has its `zeroize` feature active. If the
// direct `aes` dependency `Cargo.toml` carries for exactly this reason is
// ever removed, the build fails here rather than every live
// `TransportSession`'s key schedule silently going unzeroized again.
const _: () = {
    const fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroizes_on_drop::<aes::Aes256>();
};

use crate::SuiteId;

/// AEAD key length.
pub const KEY_LEN: usize = 32;
/// AEAD nonce length.
pub const NONCE_LEN: usize = 12;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;

/// Which AEAD a suite uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
}

impl Algorithm {
    /// The AEAD a suite selects.
    ///
    /// Total, because a `SuiteId` cannot be constructed for a suite outside the
    /// registry — the same reason `SuiteId::params` is total.
    ///
    /// This was a match on `suite.params().aead` until ADR-0015 item 7 left one
    /// AEAD in the registry, and it becomes one again when a second is added.
    /// The guard against a row naming an algorithm nothing runs does not live
    /// here in the meantime — it lives in
    /// `every_suite_selects_an_implemented_aead`, which compares this answer
    /// against each row's own string, and which is where it always did the
    /// work.
    #[must_use]
    pub fn for_suite(_suite: SuiteId) -> Self {
        Self::Aes256Gcm
    }

    /// The registry's name for this algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
        }
    }
}

/// Anything the AEAD refused, with no detail.
///
/// Deliberately opaque: every caller is authenticating attacker-supplied bytes,
/// and there is exactly one useful outcome. Distinguishing "bad tag" from
/// "malformed length" here would be a distinction an attacker could measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

impl core::fmt::Display for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AEAD authentication failed")
    }
}

impl std::error::Error for AeadError {}

/// A key schedule, prepared once.
///
/// Both the backend and the datapath do real work in `new`: the transport used
/// to construct a cipher per packet, which showed up as a hard throughput
/// ceiling. Keeping the prepared state is why this is a type rather than a pair
/// of free functions, and it is why it stayed a type when the second algorithm
/// went away.
pub enum Cipher {
    Aes(Box<Aes256Gcm>),
}

impl core::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The algorithm is public; the key schedule is not, and the derive
        // would print it.
        f.debug_struct("Cipher")
            .field("algorithm", &self.algorithm().name())
            .finish_non_exhaustive()
    }
}

impl Cipher {
    /// Prepare a key schedule.
    #[must_use]
    pub fn new(algorithm: Algorithm, key: &[u8; KEY_LEN]) -> Self {
        match algorithm {
            Algorithm::Aes256Gcm => Self::Aes(Box::new(Aes256Gcm::new(key.into()))),
        }
    }

    /// Which algorithm this is.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Aes(_) => Algorithm::Aes256Gcm,
        }
    }

    /// Seal, returning ciphertext with the tag appended.
    ///
    /// # Errors
    ///
    /// [`AeadError`] if the AEAD refuses.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Self::Aes(c) => c.encrypt(nonce.into(), payload),
        }
        .map_err(|_| AeadError)
    }

    /// Open a ciphertext with an appended tag.
    ///
    /// # Errors
    ///
    /// [`AeadError`] if authentication fails.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Self::Aes(c) => c.decrypt(nonce.into(), payload),
        }
        .map_err(|_| AeadError)
    }

    /// Seal in place, returning the tag separately.
    ///
    /// The datapath's form: one allocation for the whole datagram rather than
    /// three, which is what the throughput work measured.
    ///
    /// # Errors
    ///
    /// [`AeadError`] if the AEAD refuses.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG_LEN], AeadError> {
        let tag = match self {
            Self::Aes(c) => c.encrypt_in_place_detached(nonce.into(), aad, buffer),
        }
        .map_err(|_| AeadError)?;
        (*tag).try_into().map_err(|_| AeadError)
    }

    /// Open in place against a detached tag.
    ///
    /// # Errors
    ///
    /// [`AeadError`] if authentication fails. The buffer's contents are then
    /// undefined and MUST NOT be used — which is why this returns `()` rather
    /// than the plaintext: a caller cannot reach the bytes without having
    /// checked the result.
    pub fn open_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AeadError> {
        match self {
            Self::Aes(c) => c.decrypt_in_place_detached(nonce.into(), aad, buffer, tag.into()),
        }
        .map_err(|_| AeadError)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x24; NONCE_LEN];

    /// Every algorithm this module implements. One entry today; the loops below
    /// are written over it so a second one is covered the moment it is added.
    fn all() -> [Algorithm; 1] {
        [Algorithm::Aes256Gcm]
    }

    #[test]
    fn every_suite_selects_an_implemented_aead() {
        for suite in crate::SUITES {
            let a = Algorithm::for_suite(suite.id);
            assert_eq!(
                a.name(),
                suite.aead,
                "{}: the registry names {} and the selector chose {}",
                suite.name,
                suite.aead,
                a.name()
            );
        }
    }

    /// **No suite may reach a non-NIST AEAD** — ADR-0015 item 7. The registry
    /// asserts its rows say AES-256-GCM; this asserts the selector cannot
    /// produce anything else, so the two halves of the claim are independent.
    #[test]
    fn the_only_implemented_aead_is_fips_approved() {
        for a in all() {
            assert_eq!(a.name(), "AES-256-GCM");
        }
        for suite in crate::SUITES {
            assert_eq!(Algorithm::for_suite(suite.id), Algorithm::Aes256Gcm);
        }
    }

    #[test]
    fn every_algorithm_round_trips() {
        for a in all() {
            let c = Cipher::new(a, &KEY);
            let ct = c.seal(&NONCE, b"aad", b"plaintext").expect("seal");
            assert_eq!(c.open(&NONCE, b"aad", &ct).expect("open"), b"plaintext");
        }
    }

    #[test]
    fn in_place_agrees_with_the_allocating_form() {
        for a in all() {
            let c = Cipher::new(a, &KEY);
            let mut buf = b"plaintext".to_vec();
            let tag = c.seal_in_place(&NONCE, b"aad", &mut buf).expect("seal");

            let mut combined = buf.clone();
            combined.extend_from_slice(&tag);
            assert_eq!(
                c.open(&NONCE, b"aad", &combined).expect("open"),
                b"plaintext",
                "{}: the detached and appended forms disagree",
                a.name()
            );

            c.open_in_place(&NONCE, b"aad", &mut buf, &tag)
                .expect("open in place");
            assert_eq!(buf, b"plaintext");
        }
    }

    /// The associated data is authenticated, not merely carried.
    #[test]
    fn a_changed_aad_fails() {
        for a in all() {
            let c = Cipher::new(a, &KEY);
            let ct = c.seal(&NONCE, b"aad", b"plaintext").expect("seal");
            assert!(c.open(&NONCE, b"different", &ct).is_err(), "{}", a.name());
        }
    }

    #[test]
    fn a_tampered_tag_fails() {
        for a in all() {
            let c = Cipher::new(a, &KEY);
            let mut ct = c.seal(&NONCE, b"aad", b"plaintext").expect("seal");
            *ct.last_mut().expect("a sealed message is never empty") ^= 0x01;
            assert!(c.open(&NONCE, b"aad", &ct).is_err(), "{}", a.name());
        }
    }

    #[test]
    fn a_changed_nonce_fails() {
        for a in all() {
            let c = Cipher::new(a, &KEY);
            let ct = c.seal(&NONCE, b"aad", b"plaintext").expect("seal");
            let mut other = NONCE;
            other[0] ^= 0x01;
            assert!(c.open(&other, b"aad", &ct).is_err(), "{}", a.name());
        }
    }

    /// AES-256-GCM against the NIST CAVP vector for a 256-bit key, 96-bit
    /// nonce and empty plaintext and AAD. It checks this module against the
    /// standard rather than against itself — the only test here that would
    /// catch the backend being wired up to the wrong key or nonce order.
    #[test]
    fn aes_256_gcm_matches_the_nist_vector() {
        let c = Cipher::new(Algorithm::Aes256Gcm, &[0u8; KEY_LEN]);
        let ct = c.seal(&[0u8; NONCE_LEN], b"", b"").expect("seal");
        let hex: String = ct.iter().fold(String::new(), |mut s, b| {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(hex, "530f8afbc74536b9a963b4f1c4cb738b");
    }

    #[test]
    fn debug_does_not_print_the_key_schedule() {
        let rendered = format!("{:?}", Cipher::new(Algorithm::Aes256Gcm, &KEY));
        assert!(rendered.contains("AES-256-GCM"));
        assert!(!rendered.contains("42"), "{rendered}");
    }
}
