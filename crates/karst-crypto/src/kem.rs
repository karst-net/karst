// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! ML-KEM backends and length-checked key wrappers.
//!
//! `MlKem1024Backend` is the sole PHREATIC application-suite parameter set
//! ([ADR-0015]); `MlKem768Backend` exists only so the control channel's
//! independent ML-KEM-768 suite ([ADR-0011]) shares this crate's
//! parse/encapsulate logic instead of reimplementing it — it is deliberately
//! absent from [`KemKind`]/[`KemPublicKey`]/[`KemSecretKey`], which dispatch
//! over the application suite only.
//!
//! Secret keys zeroize on drop through the required `ml-kem/zeroize` feature.
//!
//! [ADR-0011]: ../../../docs/adr/0011-control-channel-authentication.md
//! [ADR-0015]: ../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md

use crate::KeyDistribution;

/// ML-KEM shared-secret length.
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

    /// Serialize an encapsulation key for transmission or netmap storage.
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
    use ml_kem::{MlKem1024, MlKem768, Seed, B32};

    /// The two parameter sets differ only in sizes and in the `ml-kem` types
    /// they name, so the impl is written once and instantiated twice. Writing
    /// it out twice invites the two to drift — and a KEM whose two halves
    /// disagree about, say, whether a wrong-length ciphertext is an error is
    /// exactly the kind of difference that would only show up on the suite
    /// nobody exercises.
    macro_rules! ml_kem_backend {
        (
            $backend:ident, $params:ty, $dk:ty, $ek:ty,
            $pk_len:expr, $ct_len:expr, $doc:literal
        ) => {
            #[doc = $doc]
            #[derive(Debug, Clone, Copy)]
            pub struct $backend;

            impl Kem for $backend {
                const PUBLIC_KEY_LEN: usize = $pk_len;
                const CIPHERTEXT_LEN: usize = $ct_len;
                const KEY_DISTRIBUTION: KeyDistribution = KeyDistribution::InBand;

                type SecretKey = $dk;
                type PublicKey = $ek;

                fn keypair_from_seed(seed: &[u8; 64]) -> (Self::SecretKey, Self::PublicKey) {
                    let s: Seed = Array(*seed);
                    <$params>::from_seed(&s)
                }

                fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8> {
                    pk.to_bytes().to_vec()
                }

                fn public_key_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey> {
                    <Self::PublicKey as TryKeyInit>::new_from_slice(bytes).ok()
                }

                fn encapsulate(
                    pk: &Self::PublicKey,
                    m: &[u8; 32],
                ) -> (Vec<u8>, [u8; SHARED_SECRET_LEN]) {
                    let msg: B32 = Array(*m);
                    let (ct, ss) = pk.encapsulate_deterministic(&msg);
                    (ct.to_vec(), ss.0)
                }

                fn decapsulate(sk: &Self::SecretKey, ct: &[u8]) -> Option<[u8; SHARED_SECRET_LEN]> {
                    sk.decapsulate_slice(ct).ok().map(|ss| ss.0)
                }
            }
        };
    }

    ml_kem_backend!(
        MlKem768Backend,
        MlKem768,
        ml_kem::DecapsulationKey768,
        ml_kem::EncapsulationKey768,
        1184,
        1088,
        "ML-KEM-768 (FIPS 203), `RustCrypto` backend, Category 3. Used only by the \
         control channel's independent suite (ADR-0011) — the PHREATIC application \
         suite is ML-KEM-1024 only (ADR-0015)."
    );

    ml_kem_backend!(
        MlKem1024Backend,
        MlKem1024,
        ml_kem::DecapsulationKey1024,
        ml_kem::EncapsulationKey1024,
        1568,
        1568,
        "ML-KEM-1024 (FIPS 203), `RustCrypto` backend. Category 5 — `KARST_2`, the profile \
         CNSA 2.0 mandates ([ADR-0015](../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md))."
    );

    // A compile-time guarantee, not a runtime one — this crate forbids
    // `unsafe_code`, which rules out actually inspecting freed memory the way
    // `ml-kem`'s own `zeroize_works` test does. If `Cargo.toml`'s `zeroize`
    // feature on `ml-kem` is ever dropped, or a future version of the crate
    // stops implementing this, the build fails here rather than the key
    // material silently going unzeroized again. See the module note.
    const _: () = {
        const fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroizes_on_drop::<ml_kem::DecapsulationKey768>();
        assert_zeroizes_on_drop::<ml_kem::DecapsulationKey1024>();
    };
}

#[cfg(feature = "ml-kem-rustcrypto")]
pub use rustcrypto::{MlKem1024Backend, MlKem768Backend};

#[cfg(feature = "ml-kem-rustcrypto")]
mod dispatch {
    //! Length-checked ML-KEM-1024 key wrappers.
    //!
    //! [ADR-0015]: ../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md

    use super::{Kem, MlKem1024Backend, SHARED_SECRET_LEN};

    /// Which ML-KEM parameter set, as a value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KemKind {
        /// Category 5 — `KARST_2`, the CNSA 2.0 profile.
        MlKem1024,
    }

    impl KemKind {
        /// **The parameter set an encoded key must be**, inferred from its
        /// length.
        ///
        /// ML-KEM encodings carry no type tag, so length is the only thing that
        /// distinguishes them — which makes this the entire suite-confusion
        /// defense and the reason it is written once here rather than at each
        /// caller. Returns `None` for any other length, including lengths that
        /// belong to some other KEM entirely.
        #[must_use]
        pub const fn for_public_key_len(len: usize) -> Option<Self> {
            match len {
                1568 => Some(Self::MlKem1024),
                _ => None,
            }
        }

        /// The name for this parameter set.
        #[must_use]
        pub const fn name(self) -> &'static str {
            match self {
                Self::MlKem1024 => "ML-KEM-1024",
            }
        }

        /// Encapsulation-key size in bytes.
        #[must_use]
        pub const fn public_key_len(self) -> usize {
            match self {
                Self::MlKem1024 => MlKem1024Backend::PUBLIC_KEY_LEN,
            }
        }

        /// Ciphertext size in bytes.
        #[must_use]
        pub const fn ciphertext_len(self) -> usize {
            match self {
                Self::MlKem1024 => MlKem1024Backend::CIPHERTEXT_LEN,
            }
        }

        /// NIST security category.
        #[must_use]
        pub const fn category(self) -> u8 {
            match self {
                Self::MlKem1024 => 5,
            }
        }
    }

    /// A decapsulation key whose parameter set is known at run time.
    pub enum KemSecretKey {
        MlKem1024(<MlKem1024Backend as Kem>::SecretKey),
    }

    // Hand-written and redacting. The derive would print a decapsulation key
    // into any log line or diagnostics bundle that formatted the value — a
    // tracked leakage path (THREAT-MODEL R5).
    impl core::fmt::Debug for KemSecretKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("KemSecretKey")
                .field("kind", &self.kind().name())
                .finish_non_exhaustive()
        }
    }

    impl KemSecretKey {
        /// Which parameter set this key belongs to.
        #[must_use]
        pub const fn kind(&self) -> KemKind {
            match self {
                Self::MlKem1024(_) => KemKind::MlKem1024,
            }
        }

        /// Decapsulate. Returns `None` if the ciphertext is the wrong length
        /// for *this* parameter set — see [`Kem::decapsulate`] for why a
        /// right-length but corrupt ciphertext succeeds instead.
        #[must_use]
        pub fn decapsulate(&self, ct: &[u8]) -> Option<[u8; SHARED_SECRET_LEN]> {
            match self {
                Self::MlKem1024(sk) => MlKem1024Backend::decapsulate(sk, ct),
            }
        }
    }

    /// An encapsulation key whose parameter set is known at run time.
    #[derive(Clone)]
    pub enum KemPublicKey {
        MlKem1024(<MlKem1024Backend as Kem>::PublicKey),
    }

    impl core::fmt::Debug for KemPublicKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            // Public data, but printing 1 568 bytes helps nobody.
            f.debug_struct("KemPublicKey")
                .field("kind", &self.kind().name())
                .finish_non_exhaustive()
        }
    }

    impl PartialEq for KemPublicKey {
        fn eq(&self, other: &Self) -> bool {
            self.kind() == other.kind() && self.to_bytes() == other.to_bytes()
        }
    }

    impl Eq for KemPublicKey {}

    impl KemPublicKey {
        /// Which parameter set this key belongs to.
        #[must_use]
        pub const fn kind(&self) -> KemKind {
            match self {
                Self::MlKem1024(_) => KemKind::MlKem1024,
            }
        }

        /// Serialize for transmission or netmap storage.
        #[must_use]
        pub fn to_bytes(&self) -> Vec<u8> {
            match self {
                Self::MlKem1024(pk) => MlKem1024Backend::public_key_bytes(pk),
            }
        }

        /// Parse a key **of a known parameter set**. Returns `None` on the
        /// wrong length or an invalid encoding.
        ///
        /// Use this where the suite is already fixed — a handshake that has
        /// parsed its `suite_id` knows exactly which encoding must follow, and
        /// accepting the other one there would be the suite confusion the
        /// length check exists to stop.
        #[must_use]
        pub fn from_bytes(kind: KemKind, bytes: &[u8]) -> Option<Self> {
            match kind {
                KemKind::MlKem1024 => {
                    MlKem1024Backend::public_key_from_bytes(bytes).map(Self::MlKem1024)
                }
            }
        }

        /// Parse a key whose parameter set is **implied by its length**.
        ///
        /// For netmap and configuration entries, where a peer's category is a
        /// property of that peer rather than of the local session. The length
        /// is unambiguous ([`KemKind::for_public_key_len`]), so this cannot
        /// silently accept one algorithm as another; it can only fail.
        #[must_use]
        pub fn from_bytes_by_length(bytes: &[u8]) -> Option<Self> {
            Self::from_bytes(KemKind::for_public_key_len(bytes.len())?, bytes)
        }

        /// Encapsulate deterministically from 32 bytes of caller-supplied
        /// randomness, yielding `(ciphertext, shared_secret)`.
        #[must_use]
        pub fn encapsulate(&self, m: &[u8; 32]) -> (Vec<u8>, [u8; SHARED_SECRET_LEN]) {
            match self {
                Self::MlKem1024(pk) => MlKem1024Backend::encapsulate(pk, m),
            }
        }
    }

    /// Derive a keypair of a chosen parameter set from a 64-byte seed.
    ///
    #[must_use]
    pub fn keypair_from_seed(kind: KemKind, seed: &[u8; 64]) -> (KemSecretKey, KemPublicKey) {
        match kind {
            KemKind::MlKem1024 => {
                let (sk, pk) = MlKem1024Backend::keypair_from_seed(seed);
                (KemSecretKey::MlKem1024(sk), KemPublicKey::MlKem1024(pk))
            }
        }
    }
}

#[cfg(feature = "ml-kem-rustcrypto")]
pub use dispatch::{keypair_from_seed, KemKind, KemPublicKey, KemSecretKey};

#[cfg(test)]
#[cfg(feature = "ml-kem-rustcrypto")]
mod tests {
    // Tests signal failure by panicking; the workspace bans on `panic`/`expect`
    // target library code on the pre-authentication path, not assertions.
    #![allow(clippy::panic, clippy::expect_used)]

    use super::{Kem, MlKem1024Backend, MlKem768Backend, SHARED_SECRET_LEN};
    use crate::KeyDistribution;

    fn seed(b: u8) -> [u8; 64] {
        [b; 64]
    }

    fn round_trip_agrees_on_the_shared_secret<K: Kem>() {
        let (dk, ek) = K::keypair_from_seed(&seed(1));
        let (ct, ss_send) = K::encapsulate(&ek, &[7u8; 32]);
        let ss_recv = K::decapsulate(&dk, &ct).expect("well-formed ciphertext");
        assert_eq!(ss_send, ss_recv);
    }

    fn declared_sizes_are_the_real_ones<K: Kem>() {
        assert_eq!(K::KEY_DISTRIBUTION, KeyDistribution::InBand);
        let (_, ek) = K::keypair_from_seed(&seed(2));
        assert_eq!(K::public_key_bytes(&ek).len(), K::PUBLIC_KEY_LEN);
        let (ct, ss) = K::encapsulate(&ek, &[0u8; 32]);
        assert_eq!(ct.len(), K::CIPHERTEXT_LEN);
        assert_eq!(ss.len(), SHARED_SECRET_LEN);
    }

    fn keygen_is_deterministic_in_the_seed<K: Kem>() {
        let (_, a) = K::keypair_from_seed(&seed(3));
        let (_, b) = K::keypair_from_seed(&seed(3));
        let (_, c) = K::keypair_from_seed(&seed(4));
        assert_eq!(K::public_key_bytes(&a), K::public_key_bytes(&b));
        assert_ne!(K::public_key_bytes(&a), K::public_key_bytes(&c));
    }

    fn encapsulation_is_deterministic_in_the_message<K: Kem>() {
        let (_, ek) = K::keypair_from_seed(&seed(5));
        let (ct1, ss1) = K::encapsulate(&ek, &[9u8; 32]);
        let (ct2, ss2) = K::encapsulate(&ek, &[9u8; 32]);
        let (ct3, ss3) = K::encapsulate(&ek, &[8u8; 32]);
        assert_eq!((&ct1, ss1), (&ct2, ss2));
        assert_ne!((&ct1, ss1), (&ct3, ss3));
    }

    fn public_keys_round_trip_through_bytes<K: Kem>() {
        let (_, ek) = K::keypair_from_seed(&seed(6));
        let bytes = K::public_key_bytes(&ek);
        let parsed = K::public_key_from_bytes(&bytes).expect("valid encoding");
        assert_eq!(K::public_key_bytes(&parsed), bytes);
    }

    fn malformed_public_keys_are_rejected_not_panicked_on<K: Kem>() {
        assert!(K::public_key_from_bytes(&[]).is_none());
        assert!(K::public_key_from_bytes(&[0u8; 10]).is_none());
        assert!(K::public_key_from_bytes(&vec![0u8; K::PUBLIC_KEY_LEN - 1]).is_none());
        assert!(K::public_key_from_bytes(&vec![0u8; K::PUBLIC_KEY_LEN + 1]).is_none());
    }

    fn wrong_length_ciphertexts_are_rejected<K: Kem>() {
        let (dk, _) = K::keypair_from_seed(&seed(7));
        assert!(K::decapsulate(&dk, &[]).is_none());
        assert!(K::decapsulate(&dk, &vec![0u8; K::CIPHERTEXT_LEN - 1]).is_none());
        assert!(K::decapsulate(&dk, &vec![0u8; K::CIPHERTEXT_LEN + 1]).is_none());
    }

    /// ML-KEM's FO transform rejects implicitly: a corrupted ciphertext of the
    /// right length decapsulates to a *pseudorandom* secret rather than an
    /// error, denying an attacker a decryption oracle. The mismatch surfaces
    /// later as an AEAD tag failure. This pins that behavior so nobody
    /// "fixes" it into an early error return.
    fn corrupted_ciphertext_yields_a_different_secret_not_an_error<K: Kem>() {
        let (dk, ek) = K::keypair_from_seed(&seed(8));
        let (mut ct, ss) = K::encapsulate(&ek, &[1u8; 32]);
        if let Some(b) = ct.first_mut() {
            *b ^= 0xFF;
        }
        let got = K::decapsulate(&dk, &ct).expect("length is still valid");
        assert_ne!(got, ss, "implicit rejection must not reproduce the secret");
    }

    fn distinct_keypairs_do_not_interoperate<K: Kem>() {
        let (dk_a, _) = K::keypair_from_seed(&seed(10));
        let (_, ek_b) = K::keypair_from_seed(&seed(11));
        let (ct, ss_b) = K::encapsulate(&ek_b, &[3u8; 32]);
        let got = K::decapsulate(&dk_a, &ct).expect("length is valid");
        assert_ne!(got, ss_b);
    }

    fn battery<K: Kem>() {
        round_trip_agrees_on_the_shared_secret::<K>();
        declared_sizes_are_the_real_ones::<K>();
        keygen_is_deterministic_in_the_seed::<K>();
        encapsulation_is_deterministic_in_the_message::<K>();
        public_keys_round_trip_through_bytes::<K>();
        malformed_public_keys_are_rejected_not_panicked_on::<K>();
        wrong_length_ciphertexts_are_rejected::<K>();
        corrupted_ciphertext_yields_a_different_secret_not_an_error::<K>();
        distinct_keypairs_do_not_interoperate::<K>();
    }

    #[test]
    fn ml_kem_1024_behaves() {
        battery::<MlKem1024Backend>();
    }

    #[test]
    fn ml_kem_768_behaves() {
        battery::<MlKem768Backend>();
    }

    // ── The registry ───────────────────────────────────────────────────────

    // ── Runtime dispatch (ADR-0015 item 1) ─────────────────────────────────
    //
    // These assert that the enum agrees with the trait rather than reproducing
    // it. Every variant delegates, so the behavioral battery above already
    // covers the cryptography; what can go wrong here is the *routing*.

    use super::{keypair_from_seed, KemKind, KemPublicKey};

    #[test]
    fn dispatch_round_trips_within_a_parameter_set() {
        {
            let kind = KemKind::MlKem1024;
            let (sk, pk) = keypair_from_seed(kind, &seed(30));
            assert_eq!(sk.kind(), kind);
            assert_eq!(pk.kind(), kind);
            assert_eq!(pk.to_bytes().len(), kind.public_key_len());

            let (ct, ss) = pk.encapsulate(&[5u8; 32]);
            assert_eq!(ct.len(), kind.ciphertext_len());
            assert_eq!(sk.decapsulate(&ct), Some(ss));
        }
    }

    #[test]
    fn retired_key_and_ciphertext_lengths_are_rejected() {
        assert_eq!(KemKind::for_public_key_len(1184), None);
        assert!(KemPublicKey::from_bytes_by_length(&[0; 1184]).is_none());
        let (sk, pk) = keypair_from_seed(KemKind::MlKem1024, &seed(32));
        assert!(sk.decapsulate(&[0; 1088]).is_none());
        assert_eq!(
            KemPublicKey::from_bytes_by_length(&pk.to_bytes()).expect("valid key"),
            pk
        );
    }

    #[test]
    fn debug_does_not_print_a_decapsulation_key() {
        let (sk, pk) = keypair_from_seed(KemKind::MlKem1024, &seed(34));
        let rendered = format!("{sk:?} {pk:?}");
        assert!(rendered.contains("ML-KEM-1024"), "{rendered}");
        assert!(rendered.len() < 120, "{rendered}");
    }
}
