// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Node-side halves of two Phase 3 exit criteria (PLAN.md §2.6):
//! a PSK epoch rotation that does not interrupt sessions, and an on-disk
//! netmap cache that is unreadable without the node's sealed key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use karst_control_client::{
    cache::{self, SealKey},
    netmap::{PeerPsks, PskChoice},
    psk::{pair, Psk, PSK_LEN},
};

fn psks_at(epoch: u32) -> PeerPsks {
    let master = [7u8; PSK_LEN];
    PeerPsks {
        epoch,
        current: pair(&master, "alice", "bob", epoch),
        previous: if epoch > 0 {
            pair(&master, "alice", "bob", epoch - 1)
        } else {
            None
        },
    }
}

fn bytes_of(c: &PskChoice<'_>) -> [u8; PSK_LEN] {
    c.bytes()
}

// ── §7.3: responders accept n and n-1, and reject anything else ──────────────

#[test]
fn responder_accepts_current_and_previous_epoch() {
    let p = psks_at(5);
    assert!(p.responding(5).is_some(), "current epoch was rejected");
    assert!(p.responding(4).is_some(), "previous epoch was rejected");
}

/// A peer claiming an epoch we have never held is not a peer missing a key.
/// Falling back to the zero PSK here would let an attacker choose the epoch
/// and so steer every session into the lattice-only path.
#[test]
fn responder_rejects_any_other_epoch() {
    let p = psks_at(5);
    for e in [0, 1, 3, 6, 7, u32::MAX] {
        assert!(
            p.responding(e).is_none(),
            "epoch {e} was accepted; §7.3 permits only 5 and 4"
        );
    }
}

#[test]
fn the_two_epochs_use_different_keys() {
    let p = psks_at(5);
    let now = bytes_of(&p.responding(5).unwrap());
    let then = bytes_of(&p.responding(4).unwrap());
    assert_ne!(now, then, "both epochs derived the same key");
}

/// The rotation property, from the node's side: after the epoch advances, what
/// the node uses for the *old* epoch must be exactly what it used for the
/// current one before. That is what lets it answer a peer that has not
/// refetched yet.
#[test]
fn rotation_preserves_the_previous_key() {
    let before = psks_at(5);
    let after = psks_at(6);

    let old_current = bytes_of(&before.responding(5).unwrap());
    let new_previous = bytes_of(&after.responding(5).unwrap());
    assert_eq!(
        old_current, new_previous,
        "after rotating, the node cannot answer a peer still on the old epoch"
    );
}

#[test]
fn initiating_always_uses_the_current_epoch() {
    let p = psks_at(5);
    let (epoch, choice) = p.initiating();
    assert_eq!(epoch, 5);
    assert_eq!(bytes_of(&choice), bytes_of(&p.responding(5).unwrap()));
}

#[test]
fn epoch_zero_has_no_previous() {
    let p = psks_at(0);
    assert!(p.responding(0).is_some());
    assert!(
        p.responding(u32::MAX).is_none(),
        "epoch 0 must not wrap around to u32::MAX"
    );
}

// ── §7.3: a zero PSK is never silently equivalent to a real one ──────────────

#[test]
fn a_missing_psk_is_flagged_lattice_only() {
    let p = PeerPsks {
        epoch: 3,
        current: None,
        previous: None,
    };
    let (_, choice) = p.initiating();
    assert!(
        choice.is_lattice_only(),
        "a missing PSK was not flagged as lattice-only"
    );
    assert_eq!(
        choice.bytes(),
        [0u8; PSK_LEN],
        "the fallback must be 32 zero bytes"
    );

    let responding = p.responding(3).expect("epoch 3 is still in range");
    assert!(responding.is_lattice_only());
}

#[test]
fn a_real_psk_is_not_flagged() {
    let p = psks_at(5);
    let (_, choice) = p.initiating();
    assert!(
        !choice.is_lattice_only(),
        "a derived PSK was reported as lattice-only"
    );
    assert_ne!(choice.bytes(), [0u8; PSK_LEN]);
}

/// A derived PSK must never coincide with the fallback, or the two security
/// states become indistinguishable at runtime.
#[test]
fn derived_psks_are_never_all_zero() {
    for epoch in 0..16 {
        let p = psks_at(epoch);
        assert!(!p.current.as_ref().unwrap().is_zero());
    }
    assert!(Psk::zero().is_zero());
}

// ── §2.6: the on-disk cache is unreadable without the sealed key ─────────────

#[test]
fn cache_round_trips() {
    let key = SealKey::new([9u8; 32]);
    let netmap = b"a netmap with a PSK in it".to_vec();
    let sealed = cache::seal(&key, &[1u8; 12], &netmap).expect("seal");

    assert_ne!(sealed, netmap, "the cache is not encrypted at all");
    assert!(
        !sealed.windows(netmap.len()).any(|w| w == netmap),
        "the plaintext appears verbatim in the sealed file"
    );

    let opened = cache::open(&key, &sealed).expect("open");
    assert_eq!(opened, netmap);
}

#[test]
fn cache_format_selects_aes_256_gcm() {
    let sealed = cache::seal(&SealKey::new([9u8; 32]), &[1u8; 12], b"netmap").expect("seal");

    assert_eq!(&sealed[..8], b"KARSTNMC");
    assert_eq!(u16::from_be_bytes(sealed[8..10].try_into().unwrap()), 1);
}

#[test]
fn cache_rejects_unknown_cipher_suites() {
    let key = SealKey::new([9u8; 32]);
    let mut sealed = cache::seal(&key, &[1u8; 12], b"netmap").expect("seal");
    sealed[8..10].copy_from_slice(&2u16.to_be_bytes());

    assert_eq!(
        cache::open(&key, &sealed),
        Err(cache::Error::UnsupportedSuite(2))
    );
}

#[test]
fn cache_rejects_the_legacy_unversioned_format() {
    let mut legacy_shape = vec![1u8; 12];
    legacy_shape.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        cache::open(&SealKey::new([9u8; 32]), &legacy_shape),
        Err(cache::Error::InvalidFormat)
    );
}

#[test]
fn cache_is_unreadable_without_the_key() {
    let netmap = b"secret netmap".to_vec();
    let sealed = cache::seal(&SealKey::new([9u8; 32]), &[1u8; 12], &netmap).expect("seal");

    assert_eq!(
        cache::open(&SealKey::new([10u8; 32]), &sealed),
        Err(cache::Error::Unreadable),
        "the cache opened under the wrong key"
    );
}

#[test]
fn cache_detects_tampering() {
    let key = SealKey::new([9u8; 32]);
    let sealed = cache::seal(&key, &[1u8; 12], b"netmap").expect("seal");

    // The public format and suite fields have their own parsing errors. Every
    // nonce/ciphertext bit is authenticated by AES-GCM.
    for i in 10..sealed.len() {
        let mut bad = sealed.clone();
        bad[i] ^= 0xFF;
        assert_eq!(
            cache::open(&key, &bad),
            Err(cache::Error::Unreadable),
            "a single flipped bit at offset {i} went undetected"
        );
    }
}

#[test]
fn cache_rejects_truncated_files() {
    let key = SealKey::new([9u8; 32]);
    let sealed = cache::seal(&key, &[1u8; 12], b"netmap").expect("seal");

    assert_eq!(cache::open(&key, &[]), Err(cache::Error::Truncated));
    assert_eq!(
        cache::open(&key, &sealed[..8]),
        Err(cache::Error::Truncated)
    );
    assert_eq!(
        cache::open(&key, &sealed[..14]),
        Err(cache::Error::Truncated)
    );
    // Long enough for the header and nonce but with the authentication tag cut
    // off.
    assert_eq!(
        cache::open(&key, &sealed[..24]),
        Err(cache::Error::Unreadable)
    );
}

/// Different nonces must produce different files for the same plaintext, or a
/// cache write leaks whether anything changed.
#[test]
fn cache_nonce_changes_the_ciphertext() {
    let key = SealKey::new([9u8; 32]);
    let a = cache::seal(&key, &[1u8; 12], b"netmap").expect("seal");
    let b = cache::seal(&key, &[2u8; 12], b"netmap").expect("seal");
    assert_ne!(a, b, "the nonce is not reaching the AEAD");
}

/// Neither the key nor a PSK may print.
#[test]
fn secrets_do_not_render() {
    let key = SealKey::new([9u8; 32]);
    assert!(format!("{key:?}").contains("redacted"));

    let p = pair(&[7u8; PSK_LEN], "alice", "bob", 1).unwrap();
    let rendered = format!("{p:?}");
    assert!(
        rendered.contains("redacted"),
        "psk Debug leaked: {rendered}"
    );
    assert!(!rendered.contains(&hex::encode(p.as_bytes())));
}
