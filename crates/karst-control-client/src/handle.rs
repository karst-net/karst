// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Node handles.
//!
//! A node is named on the wire by a hash of its ML-DSA-65 identity key rather
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

/// Derive the stable handle for an ML-DSA-65 identity key.
#[must_use]
pub fn handle(identity_pk: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(HANDLE_CONTEXT);
    h.update(identity_pk);
    Base64::encode_string(&h.finalize())
}
