// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! KEM abstraction and the ML-KEM-768 backend.
//!
//! # Backend choice was driven by licensing, not cryptography
//!
//! [ADR-0001] names `libcrux-ml-kem` as the preferred default because it is
//! formally verified. It is **Apache-2.0 only**, and [ADR-0007] chose
//! `MIT OR Apache-2.0` for these crates specifically to keep GPLv2
//! compatibility — through the MIT arm — for the in-kernel datapath [ADR-0003]
//! wants to keep reachable. An Apache-only dependency here would forfeit that
//! for the whole datapath.
//!
//! The default is therefore `RustCrypto`'s `ml-kem` (`Apache-2.0 OR MIT`), which
//! preserves the option. `libcrux` remains available behind a feature for
//! deployments that value the verified implementation and do not need kernel
//! compatibility. See §Consequences in ADR-0001.
//!
//! [ADR-0001]: ../../../docs/adr/0001-cryptographic-algorithm-selection.md
//! [ADR-0003]: ../../../docs/adr/0003-greenfield-rust-datapath.md
//! [ADR-0007]: ../../../docs/adr/0007-licensing.md

use crate::KeyDistribution;

/// Shared-secret length for every suite in the registry.
pub const SHARED_SECRET_LEN: usize = 32;

/// A key-encapsulation mechanism.
///
/// `KEY_DISTRIBUTION` is what keeps the out-of-band-key profile of [ADR-0004]
/// expressible: a KEM whose public key never travels on the wire changes the
/// handshake codec, not the trait.
///
/// [ADR-0004]: ../../../docs/adr/0004-handshake-mtu-and-kem-selection.md
pub trait Kem {
    /// Encapsulation-key size in bytes.
    const PUBLIC_KEY_LEN: usize;
    /// Ciphertext size in bytes.
    const CIPHERTEXT_LEN: usize;
    /// Whether the public key travels in the handshake.
    const KEY_DISTRIBUTION: KeyDistribution;

    /// Decapsulation (private) key.
    type SecretKey;
    /// Encapsulation (public) key.
    type PublicKey;

    /// Derive a keypair deterministically from a 64-byte seed.
    ///
    /// Deterministic generation is what makes known-answer tests and
    /// reproducible failures possible; callers supply seeds from a CSPRNG.
    fn keypair_from_seed(seed: &[u8; 64]) -> (Self::SecretKey, Self::PublicKey);

    /// Serialise an encapsulation key for transmission or netmap storage.
    fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8>;

    /// Parse an encapsulation key. Returns `None` on the wrong length or an
    /// invalid encoding — callers discard silently (spec §11).
    fn public_key_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey>;

    /// Encapsulate deterministically from 32 bytes of caller-supplied
    /// randomness, yielding `(ciphertext, shared_secret)`.
    fn encapsulate(pk: &Self::PublicKey, m: &[u8; 32]) -> (Vec<u8>, [u8; SHARED_SECRET_LEN]);

    /// Decapsulate. Returns `None` if the ciphertext is the wrong length.
    ///
    /// Note that ML-KEM's Fujisaki–Okamoto transform makes decapsulation
    /// *implicitly rejecting*: a malformed-but-correctly-sized ciphertext
    /// yields a pseudorandom secret rather than an error. That is deliberate —
    /// it denies an attacker a decryption oracle — and it means a wrong shared
    /// secret surfaces later as an AEAD failure, not here.
    fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Option<[u8; SHARED_SECRET_LEN]>;
}

#[cfg(feature = "ml-kem-rustcrypto")]
mod rustcrypto {
    use super::{Kem, SHARED_SECRET_LEN};
    use crate::KeyDistribution;
    use ml_kem::array::Array;
    use ml_kem::kem::{Decapsulate, FromSeed, KeyExport, TryKeyInit};
    use ml_kem::{MlKem768, Seed, B32};

    /// ML-KEM-768 (FIPS 203), `RustCrypto` backend.
    #[derive(Debug, Clone, Copy)]
    pub struct MlKem768Backend;

    impl Kem for MlKem768Backend {
        const PUBLIC_KEY_LEN: usize = 1184;
        const CIPHERTEXT_LEN: usize = 1088;
        const KEY_DISTRIBUTION: KeyDistribution = KeyDistribution::InBand;

        type SecretKey = ml_kem::DecapsulationKey768;
        type PublicKey = ml_kem::EncapsulationKey768;

        fn keypair_from_seed(seed: &[u8; 64]) -> (Self::SecretKey, Self::PublicKey) {
            let s: Seed = Array(*seed);
            MlKem768::from_seed(&s)
        }

        fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8> {
            pk.to_bytes().to_vec()
        }

        fn public_key_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey> {
            <Self::PublicKey as TryKeyInit>::new_from_slice(bytes).ok()
        }

        fn encapsulate(pk: &Self::PublicKey, m: &[u8; 32]) -> (Vec<u8>, [u8; SHARED_SECRET_LEN]) {
            let msg: B32 = Array(*m);
            let (ct, ss) = pk.encapsulate_deterministic(&msg);
            (ct.to_vec(), ss.0)
        }

        fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Option<[u8; SHARED_SECRET_LEN]> {
            sk.decapsulate_slice(ct).ok().map(|ss| ss.0)
        }
    }
}

#[cfg(feature = "ml-kem-rustcrypto")]
pub use rustcrypto::MlKem768Backend;

#[cfg(test)]
#[cfg(feature = "ml-kem-rustcrypto")]
mod tests {
    // Tests signal failure by panicking; the workspace bans on `panic`/`expect`
    // target library code on the pre-authentication path, not assertions.
    #![allow(clippy::panic, clippy::expect_used)]

    use super::{Kem, MlKem768Backend as K, SHARED_SECRET_LEN};
    use crate::{KeyDistribution, SuiteId};

    fn seed(b: u8) -> [u8; 64] {
        [b; 64]
    }

    #[test]
    fn round_trip_agrees_on_the_shared_secret() {
        let (dk, ek) = K::keypair_from_seed(&seed(1));
        let (ct, ss_send) = K::encapsulate(&ek, &[7u8; 32]);
        let ss_recv = K::decapsulate(&dk, &ct).expect("well-formed ciphertext");
        assert_eq!(ss_send, ss_recv);
    }

    /// Sizes must agree with the suite registry, which in turn drives the
    /// message sizes the fragment budget depends on.
    #[test]
    fn sizes_match_the_suite_registry() {
        let p = SuiteId::KARST_1.params();
        assert_eq!(K::PUBLIC_KEY_LEN, p.kem.public_key);
        assert_eq!(K::CIPHERTEXT_LEN, p.kem.ciphertext);
        assert_eq!(K::KEY_DISTRIBUTION, KeyDistribution::InBand);

        let (_, ek) = K::keypair_from_seed(&seed(2));
        assert_eq!(K::public_key_bytes(&ek).len(), K::PUBLIC_KEY_LEN);
        let (ct, ss) = K::encapsulate(&ek, &[0u8; 32]);
        assert_eq!(ct.len(), K::CIPHERTEXT_LEN);
        assert_eq!(ss.len(), SHARED_SECRET_LEN);
    }

    #[test]
    fn keygen_is_deterministic_in_the_seed() {
        let (_, a) = K::keypair_from_seed(&seed(3));
        let (_, b) = K::keypair_from_seed(&seed(3));
        let (_, c) = K::keypair_from_seed(&seed(4));
        assert_eq!(K::public_key_bytes(&a), K::public_key_bytes(&b));
        assert_ne!(K::public_key_bytes(&a), K::public_key_bytes(&c));
    }

    #[test]
    fn encapsulation_is_deterministic_in_the_message() {
        let (_, ek) = K::keypair_from_seed(&seed(5));
        let (ct1, ss1) = K::encapsulate(&ek, &[9u8; 32]);
        let (ct2, ss2) = K::encapsulate(&ek, &[9u8; 32]);
        let (ct3, ss3) = K::encapsulate(&ek, &[8u8; 32]);
        assert_eq!((&ct1, ss1), (&ct2, ss2));
        assert_ne!((&ct1, ss1), (&ct3, ss3));
    }

    #[test]
    fn public_keys_round_trip_through_bytes() {
        let (_, ek) = K::keypair_from_seed(&seed(6));
        let bytes = K::public_key_bytes(&ek);
        let parsed = K::public_key_from_bytes(&bytes).expect("valid encoding");
        assert_eq!(K::public_key_bytes(&parsed), bytes);
    }

    #[test]
    fn malformed_public_keys_are_rejected_not_panicked_on() {
        assert!(K::public_key_from_bytes(&[]).is_none());
        assert!(K::public_key_from_bytes(&[0u8; 10]).is_none());
        assert!(K::public_key_from_bytes(&vec![0u8; K::PUBLIC_KEY_LEN - 1]).is_none());
        assert!(K::public_key_from_bytes(&vec![0u8; K::PUBLIC_KEY_LEN + 1]).is_none());
    }

    #[test]
    fn wrong_length_ciphertexts_are_rejected() {
        let (dk, _) = K::keypair_from_seed(&seed(7));
        assert!(K::decapsulate(&dk, &[]).is_none());
        assert!(K::decapsulate(&dk, &vec![0u8; K::CIPHERTEXT_LEN - 1]).is_none());
        assert!(K::decapsulate(&dk, &vec![0u8; K::CIPHERTEXT_LEN + 1]).is_none());
    }

    /// ML-KEM's FO transform rejects implicitly: a corrupted ciphertext of the
    /// right length decapsulates to a *pseudorandom* secret rather than an
    /// error, denying an attacker a decryption oracle. The mismatch surfaces
    /// later as an AEAD tag failure. This test pins that behaviour so nobody
    /// "fixes" it into an early error return.
    #[test]
    fn corrupted_ciphertext_yields_a_different_secret_not_an_error() {
        let (dk, ek) = K::keypair_from_seed(&seed(8));
        let (mut ct, ss) = K::encapsulate(&ek, &[1u8; 32]);
        if let Some(b) = ct.first_mut() {
            *b ^= 0xFF;
        }
        let got = K::decapsulate(&dk, &ct).expect("length is still valid");
        assert_ne!(got, ss, "implicit rejection must not reproduce the secret");
    }

    #[test]
    fn distinct_keypairs_do_not_interoperate() {
        let (dk_a, _) = K::keypair_from_seed(&seed(10));
        let (_, ek_b) = K::keypair_from_seed(&seed(11));
        let (ct, ss_b) = K::encapsulate(&ek_b, &[3u8; 32]);
        let got = K::decapsulate(&dk_a, &ct).expect("length is valid");
        assert_ne!(got, ss_b);
    }
}
