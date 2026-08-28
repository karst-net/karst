// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Node handles.
//!
//! A node is named on the wire by a hash of its ML-DSA-87 identity key rather
//! than by the key itself: 44 base64 characters, the width of a base64 X25519
//! key. See `spec/karst-control-v1.md` §4.3.

use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};

/// Domain label. Not decorative: the data plane also hashes public keys
/// (ADR-0005's `peer_id_hint`, over the *KEM* key), and two unlabelled hashes
/// of related material is how a correlation channel gets built by accident.
const HANDLE_CONTEXT: &[u8] = b"karst-node-handle-v1";

/// Length of a handle in characters.
pub const HANDLE_LEN: usize = 44;

/// Derive the stable handle for an ML-DSA-87 identity key.
#[must_use]
pub fn handle(identity_pk: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(HANDLE_CONTEXT);
    h.update(identity_pk);
    Base64::encode_string(&h.finalize())
}

/// Decode the 32-byte identifier represented by a control-plane handle.
///
/// KARST-CONTROL carries this value in its base64 presentation because it is
/// convenient for logs and JSON. Ponor and AVEN carry the digest itself to
/// avoid paying 12 extra bytes on every relay frame and discovery message.
/// Keeping the conversion here prevents either protocol from quietly treating
/// the display spelling as a distinct identifier.
#[must_use]
pub fn handle_bytes(handle: &str) -> Option<[u8; 32]> {
    let mut raw = [0u8; 32];
    let decoded = Base64::decode(handle, &mut raw).ok()?;
    (decoded.len() == raw.len()).then_some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_decodes_to_its_digest() {
        let key = [0x42; 2592];
        let rendered = handle(&key);
        let mut h = Sha256::new();
        h.update(HANDLE_CONTEXT);
        h.update(key);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(handle_bytes(&rendered), Some(expected));
    }

    #[test]
    fn malformed_or_wrong_sized_handles_are_not_identifiers() {
        assert_eq!(handle_bytes("not base64"), None);
        assert_eq!(handle_bytes(&Base64::encode_string(&[0u8; 31])), None);
    }
}
