// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! KEM abstraction and the two ML-KEM backends.
//!
//! | Parameter set | Suites | Category | pk / ct |
//! |---|---|---|---|
//! | ML-KEM-768 | `KARST_1` | 3 | 1 184 / 1 088 |
//! | ML-KEM-1024 | `KARST_2` | 5 | 1 568 / 1 568 |
//!
//! # Two ways to name a parameter set
//!
//! Unlike the AEAD — where both algorithms share a 32/12/16 shape and so can
//! hide behind one runtime [`Cipher`](crate::aead::Cipher) — the two ML-KEM
//! parameter sets have different key, ciphertext and internal sizes. They are
//! therefore two implementations of one trait, [`MlKem768Backend`] and
//! [`MlKem1024Backend`], selected at compile time.
//!
//! That was all this module offered under [ADR-0015] item 3, and it is why
//! finishing item 3 did **not** make the CNSA suite reachable: `karst-noise`
//! named `MlKem768Backend` through a type alias, so its `StaticKeys` and
//! `PeerPublic` were ML-KEM-768 by construction.
//!
//! Item 1 adds the runtime half — [`KemKind`] with [`KemSecretKey`] and
//! [`KemPublicKey`] — which is an enum over the same two impls. A handshake
//! learns its suite from a header field, so the parameter set genuinely is a
//! value at that point and no amount of generics moves the decision earlier.
//! The trait remains the definition; the enum is dispatch over it, and every
//! variant delegates rather than reimplementing, so the two cannot drift.
//!
//! **A node holds one static KEM key, and its parameter set is a deployment
//! property.** Spec §4 derives `peer_id_hint` from the static encapsulation
//! key, so a second static key would be a second identity for the same node —
//! in the netmap, the roster, the responder's lookup table and the audit trail.
//! That is an identity change, not an agility one. A deployment under CNSA 2.0
//! runs Category 5 throughout and refuses everything below it, which is exactly
//! what [ADR-0006]'s floor already expresses.
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
//! [ADR-0006]: ../../../docs/adr/0006-cryptographic-agility-layer.md
//! [ADR-0007]: ../../../docs/adr/0007-licensing.md
//! [ADR-0015]: ../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md

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
        "ML-KEM-768 (FIPS 203), `RustCrypto` backend. Category 3 — `KARST_1`."
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
}

#[cfg(feature = "ml-kem-rustcrypto")]
pub use rustcrypto::{MlKem1024Backend, MlKem768Backend};

#[cfg(feature = "ml-kem-rustcrypto")]
mod dispatch {
    //! Runtime selection between the two parameter sets — [ADR-0015] item 1.
    //!
    //! [ADR-0015]: ../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md

    use super::{Kem, MlKem1024Backend, MlKem768Backend, SHARED_SECRET_LEN};
    use crate::SuiteId;

    /// Which ML-KEM parameter set, as a value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KemKind {
        /// Category 3 — `KARST_1`, the default profile.
        MlKem768,
        /// Category 5 — `KARST_2`, the CNSA 2.0 profile.
        MlKem1024,
    }

    impl KemKind {
        /// The parameter set a suite selects.
        ///
        /// Total, because a `SuiteId` cannot be constructed for a suite outside
        /// the registry — the same reason `SuiteId::params` is total.
        #[must_use]
        pub fn for_suite(suite: SuiteId) -> Self {
            match suite.params().kem.name {
                "ML-KEM-1024" => Self::MlKem1024,
                _ => Self::MlKem768,
            }
        }

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
                1184 => Some(Self::MlKem768),
                1568 => Some(Self::MlKem1024),
                _ => None,
            }
        }

        /// The registry's name for this parameter set.
        #[must_use]
        pub const fn name(self) -> &'static str {
            match self {
                Self::MlKem768 => "ML-KEM-768",
                Self::MlKem1024 => "ML-KEM-1024",
            }
        }

        /// Encapsulation-key size in bytes.
        #[must_use]
        pub const fn public_key_len(self) -> usize {
            match self {
                Self::MlKem768 => MlKem768Backend::PUBLIC_KEY_LEN,
                Self::MlKem1024 => MlKem1024Backend::PUBLIC_KEY_LEN,
            }
        }

        /// Ciphertext size in bytes.
        #[must_use]
        pub const fn ciphertext_len(self) -> usize {
            match self {
                Self::MlKem768 => MlKem768Backend::CIPHERTEXT_LEN,
                Self::MlKem1024 => MlKem1024Backend::CIPHERTEXT_LEN,
            }
        }

        /// NIST security category — 3 or 5.
        #[must_use]
        pub const fn category(self) -> u8 {
            match self {
                Self::MlKem768 => 3,
                Self::MlKem1024 => 5,
            }
        }
    }

    /// A decapsulation key whose parameter set is known at run time.
    ///
    /// Boxed because the two variants differ by roughly a kilobyte and this
    /// type is held per node and per session; an unboxed enum would pay the
    /// larger variant everywhere.
    pub enum KemSecretKey {
        MlKem768(Box<<MlKem768Backend as Kem>::SecretKey>),
        MlKem1024(Box<<MlKem1024Backend as Kem>::SecretKey>),
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
                Self::MlKem768(_) => KemKind::MlKem768,
                Self::MlKem1024(_) => KemKind::MlKem1024,
            }
        }

        /// Decapsulate. Returns `None` if the ciphertext is the wrong length
        /// for *this* parameter set — see [`Kem::decapsulate`] for why a
        /// right-length but corrupt ciphertext succeeds instead.
        #[must_use]
        pub fn decapsulate(&self, ct: &[u8]) -> Option<[u8; SHARED_SECRET_LEN]> {
            match self {
                Self::MlKem768(sk) => MlKem768Backend::decapsulate(sk, ct),
                Self::MlKem1024(sk) => MlKem1024Backend::decapsulate(sk, ct),
            }
        }
    }

    /// An encapsulation key whose parameter set is known at run time.
    #[derive(Clone)]
    pub enum KemPublicKey {
        MlKem768(Box<<MlKem768Backend as Kem>::PublicKey>),
        MlKem1024(Box<<MlKem1024Backend as Kem>::PublicKey>),
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
                Self::MlKem768(_) => KemKind::MlKem768,
                Self::MlKem1024(_) => KemKind::MlKem1024,
            }
        }

        /// Serialize for transmission or netmap storage.
        #[must_use]
        pub fn to_bytes(&self) -> Vec<u8> {
            match self {
                Self::MlKem768(pk) => MlKem768Backend::public_key_bytes(pk),
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
                KemKind::MlKem768 => MlKem768Backend::public_key_from_bytes(bytes)
                    .map(|k| Self::MlKem768(Box::new(k))),
                KemKind::MlKem1024 => MlKem1024Backend::public_key_from_bytes(bytes)
                    .map(|k| Self::MlKem1024(Box::new(k))),
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
                Self::MlKem768(pk) => MlKem768Backend::encapsulate(pk, m),
                Self::MlKem1024(pk) => MlKem1024Backend::encapsulate(pk, m),
            }
        }
    }

    /// Derive a keypair of a chosen parameter set from a 64-byte seed.
    ///
    /// The seed is the same size for both, so a node that changes profile keeps
    /// its key file and gets a different key — which is correct: they are
    /// different keys, and therefore different `peer_id_hint`s and different
    /// identities.
    #[must_use]
    pub fn keypair_from_seed(kind: KemKind, seed: &[u8; 64]) -> (KemSecretKey, KemPublicKey) {
        match kind {
            KemKind::MlKem768 => {
                let (sk, pk) = MlKem768Backend::keypair_from_seed(seed);
                (
                    KemSecretKey::MlKem768(Box::new(sk)),
                    KemPublicKey::MlKem768(Box::new(pk)),
                )
            }
            KemKind::MlKem1024 => {
                let (sk, pk) = MlKem1024Backend::keypair_from_seed(seed);
                (
                    KemSecretKey::MlKem1024(Box::new(sk)),
                    KemPublicKey::MlKem1024(Box::new(pk)),
                )
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
    use crate::{KeyDistribution, SuiteId, SUITES};

    fn seed(b: u8) -> [u8; 64] {
        [b; 64]
    }

    // ── The battery, written once and run against both parameter sets ──────
    //
    // Both backends come from one macro, so a behavioral difference between
    // them would have to come from the library rather than from this crate.
    // Running the same assertions against both is what would catch that — and
    // it matters more than usual here, because ML-KEM-1024 is on the suite no
    // integration test exercises yet.

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
    fn ml_kem_768_behaves() {
        battery::<MlKem768Backend>();
    }

    #[test]
    fn ml_kem_1024_behaves() {
        battery::<MlKem1024Backend>();
    }

    // ── The registry ───────────────────────────────────────────────────────

    /// Every suite's KEM must be backed by an implementation, not just a name.
    ///
    /// The mirror of `aead::tests::every_suite_selects_an_implemented_aead`,
    /// and it exists for the same reason: the CNSA row named ML-KEM-1024 for a
    /// long time with nothing behind it, so the registry described an intent.
    /// Note what this does *not* claim — a suite whose sizes check out here
    /// may still be unreachable, because `karst-noise` binds the KEM at the
    /// type level. It claims the primitive exists and is the right shape,
    /// which is the part that would otherwise be silently absent.
    #[test]
    fn every_suite_names_a_kem_with_a_backend_behind_it() {
        for suite in SUITES {
            let (pk, ct) = match suite.kem.name {
                "ML-KEM-768" => (
                    MlKem768Backend::PUBLIC_KEY_LEN,
                    MlKem768Backend::CIPHERTEXT_LEN,
                ),
                "ML-KEM-1024" => (
                    MlKem1024Backend::PUBLIC_KEY_LEN,
                    MlKem1024Backend::CIPHERTEXT_LEN,
                ),
                other => panic!("{}: no backend implements {other}", suite.name),
            };
            assert_eq!(pk, suite.kem.public_key, "{}: public key", suite.name);
            assert_eq!(ct, suite.kem.ciphertext, "{}: ciphertext", suite.name);
        }
    }

    /// The suites the registry actually points at, spelled out — so that a
    /// mistyped size in a registry row cannot be "confirmed" by the loop above
    /// reading the same wrong constant from a backend nobody checked.
    #[test]
    fn the_registry_rows_have_the_fips_203_sizes() {
        let k = SuiteId::KARST_1.params().kem;
        assert_eq!(
            (k.name, k.public_key, k.ciphertext),
            ("ML-KEM-768", 1184, 1088)
        );
        let k = SuiteId::KARST_2.params().kem;
        assert_eq!(
            (k.name, k.public_key, k.ciphertext),
            ("ML-KEM-1024", 1568, 1568)
        );
    }

    /// **A Category 5 key is not a Category 3 key.** Parsing is where a suite
    /// confusion would either be caught or become a mystery, and ML-KEM's
    /// encodings are distinguished only by length — so the length check is the
    /// whole defense, and it has to be in both directions.
    #[test]
    fn the_two_parameter_sets_reject_each_others_keys() {
        let (_, ek_768) = MlKem768Backend::keypair_from_seed(&seed(20));
        let (_, ek_1024) = MlKem1024Backend::keypair_from_seed(&seed(20));
        let b_768 = MlKem768Backend::public_key_bytes(&ek_768);
        let b_1024 = MlKem1024Backend::public_key_bytes(&ek_1024);

        assert!(MlKem768Backend::public_key_from_bytes(&b_1024).is_none());
        assert!(MlKem1024Backend::public_key_from_bytes(&b_768).is_none());

        // And the same for ciphertexts, which is the case an attacker chooses:
        // a 1 088-byte ciphertext offered to a 1 024 decapsulation key.
        let (dk_1024, _) = MlKem1024Backend::keypair_from_seed(&seed(21));
        let (dk_768, _) = MlKem768Backend::keypair_from_seed(&seed(21));
        let (ct_768, _) = MlKem768Backend::encapsulate(&ek_768, &[1u8; 32]);
        let (ct_1024, _) = MlKem1024Backend::encapsulate(&ek_1024, &[1u8; 32]);

        assert!(MlKem1024Backend::decapsulate(&dk_1024, &ct_768).is_none());
        assert!(MlKem768Backend::decapsulate(&dk_768, &ct_1024).is_none());
    }

    // ── Runtime dispatch (ADR-0015 item 1) ─────────────────────────────────
    //
    // These assert that the enum agrees with the trait rather than reproducing
    // it. Every variant delegates, so the behavioral battery above already
    // covers the cryptography; what can go wrong here is the *routing*.

    use super::{keypair_from_seed, KemKind, KemPublicKey};

    #[test]
    fn every_suite_selects_an_implemented_kem_kind() {
        for suite in SUITES {
            let k = KemKind::for_suite(suite.id);
            assert_eq!(k.name(), suite.kem.name, "{}", suite.name);
            assert_eq!(k.public_key_len(), suite.kem.public_key, "{}", suite.name);
            assert_eq!(k.ciphertext_len(), suite.kem.ciphertext, "{}", suite.name);
            assert_eq!(k.category(), suite.category, "{}", suite.name);
        }
    }

    #[test]
    fn dispatch_round_trips_within_a_parameter_set() {
        for kind in [KemKind::MlKem768, KemKind::MlKem1024] {
            let (sk, pk) = keypair_from_seed(kind, &seed(30));
            assert_eq!(sk.kind(), kind);
            assert_eq!(pk.kind(), kind);
            assert_eq!(pk.to_bytes().len(), kind.public_key_len());

            let (ct, ss) = pk.encapsulate(&[5u8; 32]);
            assert_eq!(ct.len(), kind.ciphertext_len());
            assert_eq!(sk.decapsulate(&ct), Some(ss));
        }
    }

    /// The dispatched path must agree with the compile-time one byte for byte.
    /// If it did not, a node built one way could not talk to a node built the
    /// other, and the enum would be a second implementation rather than a
    /// dispatcher.
    #[test]
    fn dispatch_agrees_with_the_typed_backends() {
        let (_, dyn_768) = keypair_from_seed(KemKind::MlKem768, &seed(31));
        let (_, typed_768) = MlKem768Backend::keypair_from_seed(&seed(31));
        assert_eq!(
            dyn_768.to_bytes(),
            MlKem768Backend::public_key_bytes(&typed_768)
        );

        let (_, dyn_1024) = keypair_from_seed(KemKind::MlKem1024, &seed(31));
        let (_, typed_1024) = MlKem1024Backend::keypair_from_seed(&seed(31));
        assert_eq!(
            dyn_1024.to_bytes(),
            MlKem1024Backend::public_key_bytes(&typed_1024)
        );

        // Same seed, different parameter set, different key — so a node that
        // switches profile really does get a new identity rather than the same
        // one re-encoded.
        assert_ne!(dyn_768.to_bytes(), dyn_1024.to_bytes());
    }

    /// Length is the only thing distinguishing the two encodings, so parsing by
    /// length must be exact in both directions and must reject everything else.
    #[test]
    fn parsing_by_length_infers_the_parameter_set_and_nothing_more() {
        let (_, pk768) = keypair_from_seed(KemKind::MlKem768, &seed(32));
        let (_, pk1024) = keypair_from_seed(KemKind::MlKem1024, &seed(32));

        let parsed = KemPublicKey::from_bytes_by_length(&pk768.to_bytes()).expect("1184 is 768");
        assert_eq!(parsed.kind(), KemKind::MlKem768);
        let parsed = KemPublicKey::from_bytes_by_length(&pk1024.to_bytes()).expect("1568 is 1024");
        assert_eq!(parsed.kind(), KemKind::MlKem1024);

        assert_eq!(KemKind::for_public_key_len(0), None);
        assert_eq!(KemKind::for_public_key_len(1183), None);
        assert_eq!(KemKind::for_public_key_len(1569), None);
        // A Classic McEliece key, the one out-of-band profile ADR-0004 keeps
        // expressible. It must not be mistaken for an ML-KEM key.
        assert_eq!(KemKind::for_public_key_len(524_160), None);
        assert!(KemPublicKey::from_bytes_by_length(&[0u8; 32]).is_none());
    }

    /// **A key of one parameter set must not parse as the other**, even when
    /// the caller names a kind explicitly. This is the same defense as
    /// `the_two_parameter_sets_reject_each_others_keys`, asserted through the
    /// dispatch layer because that is what the handshake now uses.
    #[test]
    fn dispatch_refuses_a_key_of_the_wrong_parameter_set() {
        let (sk768, pk768) = keypair_from_seed(KemKind::MlKem768, &seed(33));
        let (sk1024, pk1024) = keypair_from_seed(KemKind::MlKem1024, &seed(33));

        assert!(KemPublicKey::from_bytes(KemKind::MlKem768, &pk1024.to_bytes()).is_none());
        assert!(KemPublicKey::from_bytes(KemKind::MlKem1024, &pk768.to_bytes()).is_none());

        let (ct768, _) = pk768.encapsulate(&[1u8; 32]);
        let (ct1024, _) = pk1024.encapsulate(&[1u8; 32]);
        assert!(sk1024.decapsulate(&ct768).is_none());
        assert!(sk768.decapsulate(&ct1024).is_none());
    }

    #[test]
    fn debug_does_not_print_a_decapsulation_key() {
        let (sk, pk) = keypair_from_seed(KemKind::MlKem1024, &seed(34));
        let rendered = format!("{sk:?} {pk:?}");
        assert!(rendered.contains("ML-KEM-1024"), "{rendered}");
        assert!(rendered.len() < 120, "{rendered}");
    }
}
