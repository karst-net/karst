// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! `CookieReply` handling on the initiator side — spec §6.3, §9.1, §9.3.
//!
//! `Session::handle_cookie_reply` is reached from `Engine::inbound` rather
//! than `Session::handle`, because its fragment MAC is keyed by the *peer's*
//! own static key rather than this node's (§13.10) — the divergence
//! `karst_proto::dos`'s module note records. These tests drive it directly,
//! the way `Engine` does, rather than through the ordinary dispatch path.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use karst_node::{Action, Session};
use karst_noise::handshake::{PeerPublic, StaticKeys};
use karst_proto::dos::{build_cookie_reply, mac1_key, mac2_key, FragMacKey, COOKIE_LEN};
use karst_proto::{split_datagram, MessageType};

const PSK: [u8; 32] = [0x42; 32];
const TEST_SEED: [u8; 32] = [0x99; 32];

fn keys(a: u8, _b: u8) -> Arc<StaticKeys> {
    Arc::new(StaticKeys::from_seed(&[a; 64]))
}
fn peer_of(k: &StaticKeys) -> Arc<PeerPublic> {
    Arc::new(PeerPublic {
        kem_pk: k.kem_pk.clone(),

        psk: PSK,
    })
}

/// An initiator session, dialled but not yet answered — `Handshaking`.
fn dialling() -> (Session, u32) {
    let a_keys = keys(1, 2);
    let b_keys = keys(3, 4);
    let mut a = Session::new(Arc::clone(&a_keys), peer_of(&b_keys), 7, 1);
    let actions = a.connect(0, [0xAA; 32]);
    let reassembly_id = actions
        .iter()
        .find_map(|act| match act {
            Action::Send(d) => split_datagram(d).ok().map(|(hdr, _)| hdr.reassembly_id),
            _ => None,
        })
        .expect("connect emits at least one HandshakeInit fragment");
    (a, reassembly_id)
}

/// Build a `CookieReply` fragment the way `Engine::issue_cookie_reply` would:
/// signed with the **responder's own** key (`b_keys`, the session's peer),
/// per §13.10 — not the initiator's.
fn reply_fragment(b_keys: &StaticKeys, receiver_index: u32, cookie: &[u8; COOKIE_LEN]) -> Vec<u8> {
    let body = build_cookie_reply(&b_keys.kem_pk.to_bytes(), receiver_index, cookie, [7u8; 12])
        .expect("build");
    let key = FragMacKey::new(&mac1_key(&b_keys.kem_pk.to_bytes()));
    let frags = karst_proto::fragment(MessageType::CookieReply, receiver_index, &body, &key)
        .expect("fragment");
    assert_eq!(frags.len(), 1, "a CookieReply is always one fragment");
    frags.into_iter().next().expect("one fragment")
}

#[test]
fn a_valid_cookie_reply_triggers_a_retry_under_mac2() {
    let (mut a, reassembly_id) = dialling();
    let b_keys = keys(3, 4);
    let cookie = [0x11; COOKIE_LEN];
    let datagram = reply_fragment(&b_keys, reassembly_id, &cookie);
    let (hdr, payload) = split_datagram(&datagram).expect("split");

    let actions = a
        .handle_cookie_reply(payload, &hdr, TEST_SEED)
        .expect("the reply's own MAC verifies");
    assert!(!actions.is_empty(), "a valid reply must trigger a retry");

    let key = FragMacKey::new(&mac2_key(&cookie));
    for (i, action) in actions.iter().enumerate() {
        let Action::Send(d) = action else {
            panic!("expected Send, got {action:?}");
        };
        let (rhdr, rpayload) = split_datagram(d).expect("split retry");
        if i == 0 {
            // Only the first fragment's payload starts with the message-type
            // byte; the rest is a raw continuation of `msg1`'s body.
            assert_eq!(
                rpayload.first(),
                Some(&0x01),
                "the retry is the same HandshakeInit"
            );
        }
        assert!(
            key.verify(
                0x01,
                rhdr.reassembly_id,
                rhdr.idx,
                rhdr.count,
                rpayload,
                &rhdr.frag_mac
            ),
            "the retry must be signed under mac2, not mac1"
        );
    }
}

/// `None` specifically — a forged `frag_mac`, same accounting at the `Engine`
/// level as any other MAC failure (`stats.mac_failures`), never a silent
/// `Some(vec![])`.
#[test]
fn a_reply_signed_with_the_wrong_key_is_ignored() {
    let (mut a, reassembly_id) = dialling();
    let wrong_keys = keys(9, 9); // not the session's peer
    let cookie = [0x22; COOKIE_LEN];
    let datagram = reply_fragment(&wrong_keys, reassembly_id, &cookie);
    let (hdr, payload) = split_datagram(&datagram).expect("split");

    assert_eq!(
        a.handle_cookie_reply(payload, &hdr, TEST_SEED),
        None,
        "a forged frag_mac must not even reach the AEAD"
    );
}

/// The `frag_mac` verifies (correctly signed by the peer) but the correlation
/// check fails — `Some(vec![])`, not `None`: the MAC was genuine, so this is
/// not counted as a MAC failure.
#[test]
fn a_reply_for_a_different_attempt_is_ignored() {
    let (mut a, reassembly_id) = dialling();
    let b_keys = keys(3, 4);
    let cookie = [0x33; COOKIE_LEN];
    // A plausible but wrong receiver_index — an off-path attacker replaying
    // a reply captured from a different attempt, or a stale one.
    let datagram = reply_fragment(&b_keys, reassembly_id.wrapping_add(1), &cookie);
    let (hdr, payload) = split_datagram(&datagram).expect("split");

    assert_eq!(
        a.handle_cookie_reply(payload, &hdr, TEST_SEED),
        Some(Vec::new())
    );
}

#[test]
fn a_reply_with_no_outstanding_handshake_is_ignored() {
    let a_keys = keys(1, 2);
    let b_keys = keys(3, 4);
    // Idle: never dialled, so `reassembly_id` is still its initial value.
    let mut a = Session::new(a_keys, peer_of(&b_keys), 7, 1);
    let cookie = [0x44; COOKIE_LEN];
    let datagram = reply_fragment(&b_keys, 0, &cookie);
    let (hdr, payload) = split_datagram(&datagram).expect("split");

    assert_eq!(
        a.handle_cookie_reply(payload, &hdr, TEST_SEED),
        Some(Vec::new())
    );
}

#[test]
fn a_tampered_cookie_reply_body_is_ignored() {
    let (mut a, reassembly_id) = dialling();
    let b_keys = keys(3, 4);
    let cookie = [0x55; COOKIE_LEN];
    let mut datagram = reply_fragment(&b_keys, reassembly_id, &cookie);
    // Flip a byte inside the AEAD-protected body, after the fragment header.
    if let Some(b) = datagram.last_mut() {
        *b ^= 0xFF;
    }
    let (hdr, payload) = split_datagram(&datagram).expect("split");

    // The frag_mac does not cover the payload (§13.8), so this still passes
    // that check — and must be rejected by `open_cookie_reply`'s AEAD tag.
    assert_eq!(
        a.handle_cookie_reply(payload, &hdr, TEST_SEED),
        Some(Vec::new())
    );
}
