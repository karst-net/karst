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
//! That constraint is the primary defence against the failure mode that
//! produced FREAK, Logjam and JWT's `alg: none`: **an attacker cannot express a
//! weak combination because weak combinations have no wire representation.**
//!
//! [ADR-0006]: ../../../docs/adr/0006-cryptographic-agility-layer.md

pub mod kem;

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
    /// `KARST_1` — ML-KEM-768 + X25519, `ChaCha20-Poly1305`. The default.
    pub const KARST_1: Self = Self(0x0001);
    /// `KARST_2` — as `KARST_1` with AES-256-GCM, for AES-NI hardware.
    pub const KARST_2: Self = Self(0x0002);
    /// `KARST_3` — CNSA 2.0 profile: ML-KEM-1024, PQ-only. Phase 7.
    pub const KARST_3: Self = Self(0x0003);

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
            Self::KARST_3 => &S3,
            _ => &S1,
        }
    }
}

const S1: Suite = Suite {
    id: SuiteId::KARST_1,
    name: "KARST_1_X25519_MLKEM768_MLDSA65_CHACHA20_SHA512",
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
    signature: "ML-DSA-65",
    aead: "ChaCha20-Poly1305",
    aead_tag: 16,
    hash: "SHA-512",
    hash_len: 64,
    category: 3,
};

const S2: Suite = Suite {
    id: SuiteId::KARST_2,
    name: "KARST_2_X25519_MLKEM768_MLDSA65_AES256GCM_SHA512",
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
    signature: "ML-DSA-65",
    aead: "AES-256-GCM",
    aead_tag: 16,
    hash: "SHA-512",
    hash_len: 64,
    category: 3,
};

const S3: Suite = Suite {
    id: SuiteId::KARST_3,
    name: "KARST_3_MLKEM1024_MLDSA87_AES256GCM_SHA384",
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
pub static SUITES: &[Suite] = &[S1, S2, S3];

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
        assert_eq!(SuiteId::from_wire(0x0000), None, "reserved");
        assert_eq!(SuiteId::from_wire(0xFFFF), None, "reserved");
        assert_eq!(SuiteId::from_wire(0x0004), None, "not allocated");
        assert_eq!(SuiteId::from_wire(0x1234), None);
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

    #[test]
    fn karst_2_is_size_identical_to_karst_1() {
        assert_eq!(
            SuiteId::KARST_1.params().message_sizes(),
            SuiteId::KARST_2.params().message_sizes(),
            "only the AEAD differs; sizes must match"
        );
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

    /// Suites 1 and 2 fit two fragments; **suite 3 does not**. The CNSA profile
    /// uses `ML-KEM-1024` (1568 B keys and ciphertexts) and needs three, which
    /// changes its loss and `DoS` behaviour. Recorded in spec §6.4 so it is a
    /// known property rather than a surprise in Phase 7.
    #[test]
    fn fragment_counts_are_as_documented() {
        assert_eq!(
            fragments(SuiteId::KARST_1.params().message_sizes().handshake_init),
            2
        );
        assert_eq!(
            fragments(SuiteId::KARST_2.params().message_sizes().handshake_init),
            2
        );

        let m3 = SuiteId::KARST_3.params().message_sizes();
        assert_eq!(m3.handshake_init, 3210);
        assert_eq!(m3.handshake_response, 3164);
        assert_eq!(
            fragments(m3.handshake_init),
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
            !p.accepts(SuiteId::KARST_3),
            "must not accept an unimplemented suite merely because it is stronger"
        );
    }

    #[test]
    fn no_common_suite_yields_none_rather_than_a_weaker_choice() {
        let p = policy(SuiteId::KARST_3, &[SuiteId::KARST_3]);
        assert_eq!(p.select(&[SuiteId::KARST_1, SuiteId::KARST_2]), None);
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
