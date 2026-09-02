// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `reassembly_id` must be a CSPRNG draw, not a predictable counter —
//! `spec/phreatic-v1.md` §5. GitHub issue #80: `Session` used to seed it at
//! 0 and `wrapping_add(1)` per fragmented message, so every peer pair's
//! first `HandshakeInit` carried the same value fleet-wide and every retry
//! after that was one more than the last. These tests would have caught
//! that regression; none of the existing reassembly or session tests check
//! `reassembly_id`'s distribution, only its role in demultiplexing.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use karst_crypto::{SuiteId, SuitePolicy};
use karst_node::{Action, Session};
use karst_noise::handshake::{PeerPublic, StaticKeys};
use karst_proto::split_datagram;

const PSK: [u8; 32] = [0x42; 32];

fn keys(a: u8, b: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[a; 64], &[b; 32]))
}
fn peer_of(k: &StaticKeys) -> Arc<PeerPublic> {
    Arc::new(PeerPublic {
        kem_pk: k.kem_pk.clone(),
        dh_pk: k.dh_pk,
        psk: PSK,
    })
}
fn policy() -> SuitePolicy {
    SuitePolicy {
        minimum: SuiteId::KARST_1,
        supported: vec![SuiteId::KARST_1],
    }
}

/// The `reassembly_id` fragment 0 of a set of `Send` actions carries.
fn reassembly_id_of(actions: &[Action]) -> u32 {
    actions
        .iter()
        .find_map(|act| match act {
            Action::Send(d) => split_datagram(d).ok().map(|(hdr, _)| hdr.reassembly_id),
            _ => None,
        })
        .expect("at least one HandshakeInit fragment")
}

#[test]
fn two_freshly_dialled_sessions_do_not_pick_the_same_first_reassembly_id() {
    let a_keys = keys(1, 2);
    let b_keys = keys(3, 4);

    let mut s1 = Session::new(
        Arc::clone(&a_keys),
        peer_of(&b_keys),
        policy(),
        SuiteId::KARST_1,
        7,
        1,
    );
    let mut s2 = Session::new(
        Arc::clone(&a_keys),
        peer_of(&b_keys),
        policy(),
        SuiteId::KARST_1,
        7,
        2,
    );

    let id1 = reassembly_id_of(&s1.connect(0, [0x11; 32]));
    let id2 = reassembly_id_of(&s2.connect(0, [0x22; 32]));

    // The old counter made every fresh session's first fragmented message
    // carry the same value, `1` — fleet-wide, not merely session-wide.
    assert_ne!(id1, 1, "must not be the old fixed counter's first value");
    assert_ne!(
        id1, id2,
        "two sessions given different seeds must not pick the same id"
    );
}

#[test]
fn a_handshake_retry_does_not_increment_the_previous_id_by_one() {
    let a_keys = keys(1, 2);
    let b_keys = keys(3, 4);
    let mut s = Session::new(a_keys, peer_of(&b_keys), policy(), SuiteId::KARST_1, 7, 1);

    let id1 = reassembly_id_of(&s.connect(0, [0x33; 32]));
    // `RETRY_INITIAL_MS` (300 ms) must have passed for `poll` to retransmit.
    let retry = s.poll(300, [0x44; 32]);
    assert!(
        !retry.is_empty(),
        "a retry must fire once the backoff elapses"
    );
    let id2 = reassembly_id_of(&retry);

    assert_ne!(
        id2,
        id1.wrapping_add(1),
        "a retry's id must not be a plain increment of the previous one"
    );
}
