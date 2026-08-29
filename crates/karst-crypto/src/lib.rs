// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! Cipher-suite registry and algorithm parameters for `PHREATIC` v1.
//!
//! Implements [ADR-0006] — a **narrow, closed** agility layer, deliberately not
//! a crypto plugin system. Algorithms are selected only as complete named
//! suites drawn from a fixed allowlist compiled into this crate. There is no
//! per-primitive negotiation, no runtime-extensible registry, and no
//! operator-defined parameter set.
//!
//! That constraint is the primary defense against the failure mode that
//! produced FREAK, Logjam and JWT's `alg: none`: **an attacker cannot express a
//! weak combination because weak combinations have no wire representation.**
//!
//! # The registry was renumbered on 2026-08-25
//!
//! [ADR-0015] item 7 removed the ChaCha20-Poly1305 suite and reassigned the two
//! survivors to consecutive identifiers. There is no deployed base, so a gap in
//! a two-entry allowlist would have been a permanent monument to a suite nobody
//! ran.
//!
//! | Wire | Before | After |
//! |---|---|---|
//! | `0x0001` | `KARST_1` — ChaCha20-Poly1305 | `KARST_1` — AES-256-GCM (was `0x0002`) |
//! | `0x0002` | `KARST_2` — AES-256-GCM | `KARST_2` — the CNSA 2.0 profile (was `0x0003`) |
//! | `0x0003` | `KARST_3` — CNSA 2.0 | *unallocated* |
//!
//! **Code points were reused, which a shipped registry must never do.** It is
//! safe exactly once, before there is anything to be incompatible with, and the
//! mapping is written here and in spec §3 so that a reference to `KARST_2` in a
//! document dated before 2026-08-25 can be resolved rather than guessed at.
//!
//! [ADR-0006]: ../../../docs/adr/0006-cryptographic-agility-layer.md
//! [ADR-0015]: ../../../docs/adr/0015-cnsa-2-0-as-a-mandate.md

pub mod aead;
pub mod hash;
pub mod kem;
pub mod sign;

/// How a KEM's public key reaches the peer.
///
/// Required by [ADR-0004] so the Classic `McEliece` profile — 524 KB public keys
/// distributed by the coordination server and never sent on the wire — stays
/// expressible without being implemented. The handshake codec branches on this.
///
/// [ADR-0004]: ../../../docs/adr/0004-handshake-mtu-and-kem-selection.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDistribution {
    /// Public key travels in the handshake (ML-KEM).
    InBand,
    /// Public key is distributed out of band via the netmap (Classic `McEliece`).
    OutOfBand,
}

/// Post-quantum KEM parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KemParams {
    pub name: &'static str,
    /// Encapsulation key size in bytes.
    pub public_key: usize,
    /// Ciphertext size in bytes.
    pub ciphertext: usize,
    pub distribution: KeyDistribution,
}

/// Classical Diffie–Hellman parameters. Absent in PQ-only suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhParams {
    pub name: &'static str,
    pub public_key: usize,
}

/// A complete cipher suite. Suites are all-or-nothing: KEM, DH, signature,
/// AEAD and hash are fixed together and never negotiated separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub id: SuiteId,
    pub name: &'static str,
    pub kem: KemParams,
    /// `None` for PQ-only suites such as the CNSA 2.0 profile.
    pub dh: Option<DhParams>,
    pub signature: &'static str,
    pub aead: &'static str,
    /// AEAD tag size in bytes.
    pub aead_tag: usize,
    pub hash: &'static str,
    /// Hash output size in bytes.
    pub hash_len: usize,
    /// NIST security category.
    pub category: u8,
}

/// Wire identifier for a suite. Constructed only via [`SuiteId::from_wire`],
/// which rejects anything outside the allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuiteId(u16);

impl SuiteId {
    /// `KARST_1` — ML-KEM-768 + X25519, AES-256-GCM, SHA-512. Category 3, the
    /// default profile.
    pub const KARST_1: Self = Self(0x0001);
    /// `KARST_2` — CNSA 2.0 profile: ML-KEM-1024, AES-256-GCM, SHA-384,
    /// PQ-only. Category 5.
    pub const KARST_2: Self = Self(0x0002);

    /// Parse a suite identifier from the wire.
    ///
    /// Returns `None` for unknown or reserved values. Callers MUST discard the
    /// datagram — §11 requires silent failure, never a negotiation fallback.
    #[must_use]
    pub fn from_wire(v: u16) -> Option<Self> {
        SUITES.iter().find(|s| s.id.0 == v).map(|s| s.id)
    }

    /// The on-wire encoding.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        self.0
    }

    /// Parameters for this suite. Total, because a `SuiteId` cannot be
    /// constructed for a suite that is not in the registry.
    /// Total by construction, and exhaustive without indexing — the codec runs
    /// on the pre-authentication path and must have no panic path.
    #[must_use]
    pub fn params(self) -> &'static Suite {
        match self {
            Self::KARST_2 => &S2,
            _ => &S1,
        }
    }
}

const S1: Suite = Suite {
    id: SuiteId::KARST_1,
    name: "KARST_1_X25519_MLKEM768_MLDSA87_AES256GCM_SHA512",
    kem: KemParams {
        name: "ML-KEM-768",
        public_key: 1184,
        ciphertext: 1088,
        distribution: KeyDistribution::InBand,
    },
    dh: Some(DhParams {
        name: "X25519",
        public_key: 32,
    }),
    signature: "ML-DSA-87",
    aead: "AES-256-GCM",
    aead_tag: 16,
    hash: "SHA-512",
    hash_len: 64,
    category: 3,
};

const S2: Suite = Suite {
    id: SuiteId::KARST_2,
    name: "KARST_2_MLKEM1024_MLDSA87_AES256GCM_SHA384",
    kem: KemParams {
        name: "ML-KEM-1024",
        public_key: 1568,
        ciphertext: 1568,
        distribution: KeyDistribution::InBand,
    },
    dh: None, // CNSA 2.0 does not call for a classical hybrid.
    signature: "ML-DSA-87",
    aead: "AES-256-GCM",
    aead_tag: 16,
    hash: "SHA-384",
    hash_len: 48,
    category: 5,
};

/// The complete allowlist. **Adding an entry here is the only way to add a
/// suite** — there is no runtime registration path, by design.
pub static SUITES: &[Suite] = &[S1, S2];

/// Which set of suites a deployment runs — [ADR-0015] item 1.
///
/// **A profile is chosen once, per node, and fixes the parameter set of that
/// node's static KEM key.** It cannot be a per-session choice: `peer_id_hint`
/// is derived from the static encapsulation key (spec §4), so a node holding
/// both a Category 3 and a Category 5 key would have two identities in the
/// netmap, the roster, the responder's lookup table and the audit trail.
///
/// The consequence is deliberate and worth stating plainly: **a `Cnsa2` node
/// and a `Default` node cannot talk to each other.** CNSA 2.0 is a mandate, not
/// a preference — a deployment held to it may not fall back, and one that is
/// not held to it has no ML-KEM-1024 key to answer with. Mixed fleets are a
/// migration, planned as one, not something negotiation smooths over.
///
/// [ADR-0015]: ../../docs/adr/0015-cnsa-2-0-as-a-mandate.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// `KARST_1` — Category 3, ML-KEM-768 with an X25519 hybrid.
    #[default]
    Default,
    /// `KARST_2` — Category 5, ML-KEM-1024, AES-256-GCM, SHA-384, and no
    /// classical half.
    Cnsa2,
}

impl Profile {
    /// The name an operator writes in configuration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Cnsa2 => "cnsa2",
        }
    }

    /// Parse the name an operator writes.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "cnsa2" => Some(Self::Cnsa2),
            _ => None,
        }
    }

    /// The suite policy this profile implies.
    ///
    /// **Each profile currently holds exactly one suite**, since ADR-0015 item
    /// 7 removed the `ChaCha` alternative and left the default profile with a
    /// single Category 3 row. `SuitePolicy` keeps its floor-plus-list shape
    /// anyway: it is ADR-0006's mechanism, and collapsing it to a scalar
    /// because the list happens to be short today would have to be undone by
    /// whoever adds the next suite. `supported` is ordered most preferred last,
    /// which is what [`SuitePolicy::select`] reads.
    #[must_use]
    pub fn policy(self) -> SuitePolicy {
        match self {
            Self::Default => SuitePolicy {
                minimum: SuiteId::KARST_1,
                supported: vec![SuiteId::KARST_1],
            },
            Self::Cnsa2 => SuitePolicy {
                minimum: SuiteId::KARST_2,
                supported: vec![SuiteId::KARST_2],
            },
        }
    }

    /// **The profile a node holding this KEM parameter set runs.**
    ///
    /// The static key is the source of truth, not the configuration line that
    /// generated it: a node can only speak suites its own key can serve, so
    /// deriving the policy from the key means the two cannot come apart. The
    /// configuration chooses which key to *generate*; after that the key
    /// decides.
    #[cfg(feature = "ml-kem-rustcrypto")]
    #[must_use]
    pub fn for_kem(kind: kem::KemKind) -> Self {
        match kind {
            kem::KemKind::MlKem768 => Self::Default,
            kem::KemKind::MlKem1024 => Self::Cnsa2,
        }
    }

    /// Every profile, for enumeration in help text and tests.
    pub const ALL: &'static [Self] = &[Self::Default, Self::Cnsa2];
}

/// A node's suite policy, as distributed in the netmap.
///
/// Enforcement is **at the node**, never at the server: a compromised
/// coordination server can raise the floor but cannot lower it below what a
/// node already accepts (ADR-0006).
#[derive(Debug, Clone)]
pub struct SuitePolicy {
    /// Lowest acceptable suite. Anything below is refused outright.
    pub minimum: SuiteId,
    /// Suites this node can speak, most preferred last.
    pub supported: Vec<SuiteId>,
}

impl SuitePolicy {
    /// Select the highest suite supported by both peers and at or above the
    /// local floor.
    ///
    /// Returns `None` if no suite qualifies — the handshake is then abandoned
    /// rather than retried at a weaker setting. **There is no downgrade path.**
    #[must_use]
    pub fn select(&self, peer_supported: &[SuiteId]) -> Option<SuiteId> {
        self.supported
            .iter()
            .filter(|s| **s >= self.minimum && peer_supported.contains(s))
            .max()
            .copied()
    }

    /// Whether an offered suite is acceptable. Used on the receiving side.
    #[must_use]
    pub fn accepts(&self, offered: SuiteId) -> bool {
        offered >= self.minimum && self.supported.contains(&offered)
    }
}

/// Handshake message sizes implied by a suite — `spec/phreatic-v1.md` §6.
///
/// Computed rather than tabulated so that adding a suite cannot silently
/// violate the fragment budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSizes {
    pub handshake_init: usize,
    pub handshake_response: usize,
}

impl Suite {
    /// Size of the `peer_id_hint` — §4.
    pub const PEER_ID_HINT: usize = 32;
    /// TAI64N timestamp — §6.1.
    pub const TIMESTAMP: usize = 12;

    /// Message sizes for this suite.
    #[must_use]
    pub fn message_sizes(&self) -> MessageSizes {
        let dh_pk = self.dh.map_or(0, |d| d.public_key);

        // §6.1: type, reserved, sender_index, suite_id, psk_epoch,
        //       e_kem_pk, e_dh_pk, ct_s, enc_ident
        let handshake_init = 1
            + 3
            + 4
            + 2
            + 4
            + self.kem.public_key
            + dh_pk
            + self.kem.ciphertext
            + Self::PEER_ID_HINT
            + Self::TIMESTAMP
            + self.aead_tag;

        // §6.2: type, reserved, sender_index, receiver_index,
        //       ct_e, ct_ss, e_dh_pk, enc_empty
        let handshake_response = 1 + 3 + 4 + 4 + self.kem.ciphertext * 2 + dh_pk + self.aead_tag;

        MessageSizes {
            handshake_init,
            handshake_response,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const FRAGMENT_PAYLOAD_MAX: usize = 1208;
    const MAX_FRAGMENTS: usize = 4;

    fn fragments(len: usize) -> usize {
        len.div_ceil(FRAGMENT_PAYLOAD_MAX)
    }

    // ── registry is closed ──────────────────────────────────────────────────

    #[test]
    fn unknown_and_reserved_suites_are_rejected() {
        assert_eq!(SuiteId::from_wire(0x0001), Some(SuiteId::KARST_1));
        assert_eq!(SuiteId::from_wire(0x0002), Some(SuiteId::KARST_2));
        assert_eq!(SuiteId::from_wire(0x0000), None, "reserved");
        assert_eq!(SuiteId::from_wire(0xFFFF), None, "reserved");
        assert_eq!(
            SuiteId::from_wire(0x0003),
            None,
            "vacated by ADR-0015 item 7"
        );
        assert_eq!(SuiteId::from_wire(0x0004), None, "not allocated");
        assert_eq!(SuiteId::from_wire(0x1234), None);
    }

    /// **No suite may name ChaCha20-Poly1305** — ADR-0015 item 7. It is not a
    /// NIST algorithm, so a FIPS 140-3 or CNSA 2.0 deployment cannot run it in
    /// the approved boundary, and it had no reason to remain once every profile
    /// had an AES row. Asserted rather than left to review because a suite is
    /// one struct literal and this is the property that made removing it worth
    /// a wire-format break.
    #[test]
    fn no_suite_names_a_non_nist_aead() {
        for s in SUITES {
            assert_eq!(s.aead, "AES-256-GCM", "{}", s.name);
            assert!(
                !s.name.contains("CHACHA"),
                "{}: the name outlived the algorithm",
                s.name
            );
        }
    }

    /// Every suite must be at or above Category 3, and the registry must offer
    /// exactly one Category 5 profile. If a second Category 5 suite is ever
    /// added, `Profile::for_kem` needs revisiting before this is relaxed — it
    /// maps a KEM parameter set back to one profile.
    #[test]
    fn the_registry_offers_one_category_5_suite() {
        assert_eq!(
            SUITES.iter().filter(|s| s.category == 5).count(),
            1,
            "Profile::for_kem assumes one profile per KEM parameter set"
        );
        for s in SUITES {
            assert!(s.category >= 3, "{}", s.name);
        }
    }

    // ── profiles ────────────────────────────────────────────────────────────

    /// **The invariant the one-static-key rule rests on.** Every suite a
    /// profile offers must name the same KEM parameter set, because a node has
    /// exactly one static KEM key and `peer_id_hint` is derived from it. A
    /// profile mixing ML-KEM-768 and ML-KEM-1024 suites would be unserviceable
    /// by any single node, and the failure would surface as an unexplainable
    /// `UnsupportedSuite` mid-handshake rather than here.
    #[test]
    fn every_profile_names_one_kem_parameter_set() {
        for p in Profile::ALL {
            let policy = p.policy();
            assert!(!policy.supported.is_empty(), "{}", p.name());
            let first = policy.supported.first().expect("non-empty").params().kem;
            for s in &policy.supported {
                assert_eq!(
                    s.params().kem,
                    first,
                    "{}: {} does not share a KEM with the rest of the profile",
                    p.name(),
                    s.params().name
                );
            }
            assert!(
                policy.supported.contains(&policy.minimum),
                "{}: the floor is not itself supported",
                p.name()
            );
        }
    }

    /// The CNSA profile must be Category 5 throughout — that is the whole point
    /// of it, and a row silently added at Category 3 would pass every other
    /// test in this file.
    #[test]
    fn the_cnsa_profile_is_category_5_throughout() {
        for s in &Profile::Cnsa2.policy().supported {
            let p = s.params();
            assert_eq!(p.category, 5, "{}", p.name);
            assert_eq!(p.dh, None, "{}: CNSA 2.0 has no classical half", p.name);
            assert_eq!(p.aead, "AES-256-GCM", "{}", p.name);
        }
    }

    /// A key and the profile derived from it must round-trip, in both
    /// directions. If they did not, a node would generate one kind of key and
    /// then advertise suites it could not serve — the exact failure the
    /// derivation exists to prevent.
    #[cfg(feature = "ml-kem-rustcrypto")]
    #[test]
    fn a_profile_and_its_kem_parameter_set_agree_both_ways() {
        for p in Profile::ALL {
            let kind = kem::KemKind::for_suite(p.policy().minimum);
            assert_eq!(Profile::for_kem(kind), *p, "{}", p.name());
        }
        for kind in [kem::KemKind::MlKem768, kem::KemKind::MlKem1024] {
            let p = Profile::for_kem(kind);
            assert_eq!(kem::KemKind::for_suite(p.policy().minimum), kind);
        }
    }

    #[test]
    fn profile_names_round_trip() {
        for p in Profile::ALL {
            assert_eq!(Profile::from_name(p.name()), Some(*p));
        }
        assert_eq!(Profile::from_name("cnsa"), None);
        assert_eq!(Profile::from_name(""), None);
        assert_eq!(Profile::default(), Profile::Default);
    }

    #[test]
    fn registry_ids_are_unique_and_ordered() {
        let ids: Vec<u16> = SUITES.iter().map(|s| s.id.to_wire()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "suite IDs must be unique and ascending");
    }

    // ── §6 message sizes, derived per suite ─────────────────────────────────

    #[test]
    fn karst_1_matches_the_specification() {
        let m = SuiteId::KARST_1.params().message_sizes();
        assert_eq!(m.handshake_init, 2378, "spec §6.1");
        assert_eq!(m.handshake_response, 2236, "spec §6.2");
    }

    /// The renumbering of ADR-0015 item 7 moved suites between identifiers but
    /// changed no field of either survivor, so both keep the sizes §6 records.
    /// A size that moved with the identifier would mean a row was edited rather
    /// than relabelled.
    #[test]
    fn renumbering_did_not_change_either_suites_shape() {
        let one = SuiteId::KARST_1.params();
        assert_eq!(one.kem.name, "ML-KEM-768");
        assert_eq!(one.hash_len, 64);
        assert!(one.dh.is_some(), "the Category 3 profile keeps its hybrid");

        let two = SuiteId::KARST_2.params();
        assert_eq!(two.kem.name, "ML-KEM-1024");
        assert_eq!(two.hash_len, 48);
        assert_eq!(two.dh, None, "CNSA 2.0 has no classical half");
    }

    /// Every suite must satisfy §6.4 invariant 1.
    #[test]
    fn anti_amplification_holds_for_every_suite() {
        for s in SUITES {
            let m = s.message_sizes();
            assert!(
                m.handshake_init > m.handshake_response,
                "{}: init {} must exceed response {}",
                s.name,
                m.handshake_init,
                m.handshake_response
            );
        }
    }

    /// Every suite must stay inside the 4-fragment hard cap.
    #[test]
    fn every_suite_fits_the_fragment_cap() {
        for s in SUITES {
            let m = s.message_sizes();
            assert!(
                fragments(m.handshake_init) <= MAX_FRAGMENTS,
                "{}: init needs {} fragments",
                s.name,
                fragments(m.handshake_init)
            );
        }
    }

    /// `KARST_1` fits two fragments; **`KARST_2` does not**. The CNSA profile
    /// uses `ML-KEM-1024` (1568 B keys and ciphertexts) and needs three, which
    /// changes its loss and `DoS` behavior. Recorded in spec §6.5 so it is a
    /// known property rather than a surprise in the field.
    #[test]
    fn fragment_counts_are_as_documented() {
        assert_eq!(
            fragments(SuiteId::KARST_1.params().message_sizes().handshake_init),
            2
        );

        let cnsa = SuiteId::KARST_2.params().message_sizes();
        assert_eq!(cnsa.handshake_init, 3210);
        assert_eq!(cnsa.handshake_response, 3164);
        assert_eq!(
            fragments(cnsa.handshake_init),
            3,
            "CNSA profile needs 3 fragments"
        );
    }

    // ── downgrade protection ────────────────────────────────────────────────

    fn policy(min: SuiteId, supported: &[SuiteId]) -> SuitePolicy {
        SuitePolicy {
            minimum: min,
            supported: supported.to_vec(),
        }
    }

    #[test]
    fn selects_the_highest_mutually_supported_suite() {
        let p = policy(SuiteId::KARST_1, &[SuiteId::KARST_1, SuiteId::KARST_2]);
        assert_eq!(
            p.select(&[SuiteId::KARST_1, SuiteId::KARST_2]),
            Some(SuiteId::KARST_2)
        );
        assert_eq!(p.select(&[SuiteId::KARST_1]), Some(SuiteId::KARST_1));
    }

    #[test]
    fn refuses_anything_below_the_floor() {
        let p = policy(SuiteId::KARST_2, &[SuiteId::KARST_1, SuiteId::KARST_2]);
        // Peer offers only the weaker suite: no agreement, and no fallback.
        assert_eq!(p.select(&[SuiteId::KARST_1]), None);
        assert!(!p.accepts(SuiteId::KARST_1), "below floor must be refused");
        assert!(p.accepts(SuiteId::KARST_2));
    }

    #[test]
    fn refuses_a_suite_it_does_not_support_even_above_the_floor() {
        let p = policy(SuiteId::KARST_1, &[SuiteId::KARST_1]);
        assert!(
            !p.accepts(SuiteId::KARST_2),
            "must not accept an unsupported suite merely because it is stronger"
        );
    }

    #[test]
    fn no_common_suite_yields_none_rather_than_a_weaker_choice() {
        let p = policy(SuiteId::KARST_2, &[SuiteId::KARST_2]);
        assert_eq!(p.select(&[SuiteId::KARST_1]), None);
    }

    /// **The two shipping profiles have no suite in common**, which is the
    /// whole content of "CNSA 2.0 is a mandate, not a preference". Asserted
    /// against the real `Profile` policies rather than hand-built ones, so a
    /// future row that quietly reconnected them would fail here.
    #[test]
    fn the_two_profiles_cannot_negotiate_with_each_other() {
        let default = Profile::Default.policy();
        let cnsa = Profile::Cnsa2.policy();
        assert_eq!(default.select(&cnsa.supported), None);
        assert_eq!(cnsa.select(&default.supported), None);
    }

    // ── ADR-0004 out-of-band KEM profile stays expressible ──────────────────

    #[test]
    fn key_distribution_is_part_of_the_kem_parameters() {
        for s in SUITES {
            assert_eq!(
                s.kem.distribution,
                KeyDistribution::InBand,
                "no shipped suite uses an out-of-band KEM in v1"
            );
        }
        // The variant exists so the McEliece profile remains reachable.
        assert_ne!(KeyDistribution::OutOfBand, KeyDistribution::InBand);
    }
}
