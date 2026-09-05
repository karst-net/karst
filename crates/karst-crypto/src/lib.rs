// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

#![forbid(unsafe_code)]
//! Fixed CNSA 2.0 parameters for PHREATIC v1. See ADR-0018.

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

/// Sole accepted PHREATIC wire suite identifier. Retired IDs are not reused.
pub const SUITE_ID: u16 = 0x0002;
pub const SUITE_NAME: &str = "KARST_2_MLKEM1024_MLDSA87_AES256GCM_SHA384";
pub const KEM_PUBLIC_KEY: usize = 1568;
pub const KEM_CIPHERTEXT: usize = 1568;
pub const AEAD_TAG: usize = 16;
pub const HASH_LEN: usize = 48;
pub const PEER_ID_HINT: usize = 32;
pub const TIMESTAMP: usize = 12;
pub const CATEGORY: u8 = 5;

/// Reject unknown, reserved, and retired wire identifiers without fallback.
#[must_use]
pub const fn accepts_suite(id: u16) -> bool {
    id == SUITE_ID
}

/// Handshake sizes derived from the fixed wire layout (spec §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageSizes {
    pub handshake_init: usize,
    pub handshake_response: usize,
}

#[must_use]
pub const fn message_sizes() -> MessageSizes {
    MessageSizes {
        handshake_init: 14 + KEM_PUBLIC_KEY + KEM_CIPHERTEXT + PEER_ID_HINT + TIMESTAMP + AEAD_TAG,
        handshake_response: 12 + 2 * KEM_CIPHERTEXT + AEAD_TAG,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_retired_suite_ids_are_rejected() {
        for id in 0..=u16::MAX {
            assert_eq!(accepts_suite(id), id == 0x0002);
        }
    }

    #[test]
    fn wire_sizes_and_fragment_budget_match_the_specification() {
        let sizes = message_sizes();
        assert_eq!(sizes.handshake_init, 3210);
        assert_eq!(sizes.handshake_response, 3164);
        assert_eq!(sizes.handshake_init.div_ceil(1208), 3);
        assert_eq!(sizes.handshake_response.div_ceil(1208), 3);
        assert!(sizes.handshake_response <= sizes.handshake_init);
    }
}
