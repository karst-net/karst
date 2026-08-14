// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! Everything except the socket, driven together with real ML-DSA-65.
//!
//! The unit tests in each module use a stub signature scheme so they can be
//! exhaustive without paying for lattice arithmetic. This file exists because
//! those stubs agree with the code that calls them by construction, and the
//! things that go wrong between a spec and an implementation — a context
//! string that does not match, an identifier hashed under the wrong label, a
//! roster keyed by the wrong derivation — are invisible to a stub and fatal in
//! production.

#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

use base64ct::{Base64, Encoding as _};
use karst_relay::hub::{Config as HubConfig, ConnId, Hub};
use karst_relay::roster::FileRoster;
use karst_relay::sign::{node_id, Identity, PonorVerifier, SEED_LEN};
use karst_relay_proto::{
    frame::decode, Admitted, ClientHandshake, Error as ProtoError, Frame, RelayHandshake, Role,
    TailnetId,
};

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; SEED_LEN])
}

fn roster_for(entries: &[(&Identity, &str)], mesh: &[&Identity]) -> FileRoster {
    use std::fmt::Write as _;
    let mut text = String::new();
    for (id, tailnet) in entries {
        let _ = write!(
            text,
            "[[client]]\nidentity_pk = \"{}\"\ntailnet = \"{tailnet}\"\n\n",
            Base64::encode_string(id.public_key())
        );
    }
    for id in mesh {
        let _ = write!(
            text,
            "[[mesh]]\nidentity_pk = \"{}\"\n\n",
            Base64::encode_string(id.public_key())
        );
    }
    FileRoster::parse(&text).expect("roster parses")
}

/// Drive a complete Ponor handshake between a node and the relay.
///
/// Every message goes through the real encoder and decoder, so a field the
/// codec and the state machine disagree about shows up here.
fn handshake(
    relay: &Identity,
    node: &Identity,
    role: Role,
    peer_id: [u8; 32],
    roster: &FileRoster,
    relay_random: [u8; 32],
    client_random: [u8; 32],
) -> Result<Admitted, ProtoError> {
    let mut server = RelayHandshake::new(relay.relay_id(), relay_random);
    let mut client = ClientHandshake::new(
        role,
        peer_id,
        relay.relay_id(),
        relay.public_key().to_vec(),
        client_random,
    );

    let hello_bytes = server.hello().to_vec();
    let (hello, _) = decode(&hello_bytes)?.expect("complete");

    let auth_bytes = client.on_relay_hello(&hello, node)?;
    let (auth, _) = decode(&auth_bytes)?.expect("complete");

    let (admitted, reply_bytes) = server.on_client_auth(&auth, roster, &PonorVerifier, relay)?;
    let (reply, _) = decode(&reply_bytes)?.expect("complete");

    client.on_relay_auth(&reply, &PonorVerifier)?;
    assert!(client.may_send(), "client did not reach established");
    assert!(server.is_established());
    Ok(admitted)
}

#[test]
fn a_rostered_node_is_admitted_and_its_traffic_is_forwarded() {
    let relay = identity(0x10);
    let alice = identity(0x21);
    let bob = identity(0x22);
    let roster = roster_for(&[(&alice, "acme"), (&bob, "acme")], &[]);

    let a = handshake(
        &relay,
        &alice,
        Role::Client,
        node_id(alice.public_key()),
        &roster,
        [1; 32],
        [2; 32],
    )
    .expect("alice admitted");
    let b = handshake(
        &relay,
        &bob,
        Role::Client,
        node_id(bob.public_key()),
        &roster,
        [3; 32],
        [4; 32],
    )
    .expect("bob admitted");

    assert_eq!(
        a,
        Admitted::Client {
            node_id: node_id(alice.public_key()),
            tailnet: TailnetId("acme".to_owned()),
        }
    );

    let mut hub = Hub::new(HubConfig::default());
    hub.admit(ConnId(1), a, 0);
    hub.admit(ConnId(2), b, 0);

    let payload = [0xab; 1336]; // the largest datagram PHREATIC emits
    hub.on_frame(
        ConnId(1),
        &Frame::SendPacket {
            dst_id: node_id(bob.public_key()),
            payload: &payload,
        },
        &roster,
        0,
    )
    .expect("legal frame");

    let bytes = hub.take_outbound(ConnId(2)).expect("bob has a frame");
    let (frame, used) = decode(&bytes).expect("decodes").expect("complete");
    assert_eq!(used, bytes.len());
    assert_eq!(
        frame,
        Frame::RecvPacket {
            src_id: node_id(alice.public_key()),
            payload: &payload,
        }
    );
}

#[test]
fn a_node_absent_from_the_roster_cannot_be_admitted() {
    // spec §5.3. The node has a perfectly good key and produces a perfectly
    // good signature; there is simply no key for the relay to check it
    // against, and no code path that would accept one from the wire.
    let relay = identity(0x10);
    let alice = identity(0x21);
    let stranger = identity(0x99);
    let roster = roster_for(&[(&alice, "acme")], &[]);

    let err = handshake(
        &relay,
        &stranger,
        Role::Client,
        node_id(stranger.public_key()),
        &roster,
        [1; 32],
        [2; 32],
    )
    .expect_err("stranger must not be admitted");
    assert_eq!(err, ProtoError::Rejected);
}

#[test]
fn an_empty_roster_admits_nobody() {
    let relay = identity(0x10);
    let alice = identity(0x21);
    let roster = FileRoster::empty();

    assert_eq!(
        handshake(
            &relay,
            &alice,
            Role::Client,
            node_id(alice.public_key()),
            &roster,
            [1; 32],
            [2; 32]
        )
        .expect_err("nobody is admitted"),
        ProtoError::Rejected
    );
}

#[test]
fn a_rostered_node_cannot_authenticate_as_a_mesh_peer() {
    // §5.5's role binding and §5.2's separate identifier label, together. The
    // node signs with role = MESH and presents the id it would present as a
    // client; the mesh directory cannot contain it.
    let relay = identity(0x10);
    let alice = identity(0x21);
    let roster = roster_for(&[(&alice, "acme")], &[]);

    assert_eq!(
        handshake(
            &relay,
            &alice,
            Role::Mesh,
            node_id(alice.public_key()),
            &roster,
            [1; 32],
            [2; 32]
        )
        .expect_err("a client is not a mesh peer"),
        ProtoError::Rejected
    );
}

#[test]
fn a_configured_mesh_peer_is_admitted_as_one() {
    let relay = identity(0x10);
    let peer = identity(0x30);
    let roster = roster_for(&[], &[&peer]);

    let admitted = handshake(
        &relay,
        &peer,
        Role::Mesh,
        peer.relay_id(),
        &roster,
        [1; 32],
        [2; 32],
    )
    .expect("mesh peer admitted");
    assert_eq!(
        admitted,
        Admitted::Mesh {
            relay_id: peer.relay_id()
        }
    );
}

#[test]
fn a_client_does_not_complete_against_the_wrong_relay() {
    // §4.2: relay identity comes from the registry, not the certificate and
    // not the connection. The client here is handed the wrong relay's key.
    let real = identity(0x10);
    let impostor = identity(0x11);
    let alice = identity(0x21);
    let roster = roster_for(&[(&alice, "acme")], &[]);

    let mut server = RelayHandshake::new(impostor.relay_id(), [1; 32]);
    let mut client = ClientHandshake::new(
        Role::Client,
        node_id(alice.public_key()),
        real.relay_id(),
        real.public_key().to_vec(),
        [2; 32],
    );

    let hello_bytes = server.hello().to_vec();
    let (hello, _) = decode(&hello_bytes).expect("decodes").expect("complete");
    assert_eq!(
        client.on_relay_hello(&hello, &alice),
        Err(ProtoError::RelayIdentityMismatch)
    );
    assert!(!client.may_send());

    // And nothing was signed for the impostor to carry elsewhere.
    let _ = &mut server;
    let _ = roster;
}

#[test]
fn a_rogue_relay_cannot_replay_a_clients_authentication() {
    // The attack `spec/models/ponor-norelayid.pv` demonstrates when relay_id
    // is unbound: the rogue copies the honest relay's relay_random into its
    // own hello, so the client's signature would be valid at the honest relay.
    // Binding relay_id is what stops it, and this is that check against the
    // real signature scheme rather than the model's.
    let honest = identity(0x10);
    let rogue = identity(0x11);
    let alice = identity(0x21);
    let roster = roster_for(&[(&alice, "acme")], &[]);

    // The honest relay's hello, and so its relay_random.
    let mut honest_server = RelayHandshake::new(honest.relay_id(), [7; 32]);
    let honest_hello = honest_server.hello().to_vec();
    let (honest_hello, _) = decode(&honest_hello).expect("decodes").expect("complete");
    let Frame::RelayHello { relay_random, .. } = honest_hello else {
        panic!("expected RelayHello");
    };

    // The rogue presents its own id with the honest relay's nonce. Alice
    // legitimately pins the rogue — a community-pool relay, ADR-0008 §6.
    let mut alice_hs = ClientHandshake::new(
        Role::Client,
        node_id(alice.public_key()),
        rogue.relay_id(),
        rogue.public_key().to_vec(),
        [8; 32],
    );
    let rogue_hello = Frame::RelayHello {
        relay_id: rogue.relay_id(),
        relay_random,
    };
    let auth_bytes = alice_hs
        .on_relay_hello(&rogue_hello, &alice)
        .expect("alice signs for the relay she pinned");
    let (auth, _) = decode(&auth_bytes).expect("decodes").expect("complete");

    // The rogue forwards Alice's ClientAuth to the honest relay.
    assert_eq!(
        honest_server.on_client_auth(&auth, &roster, &PonorVerifier, &honest),
        Err(ProtoError::Rejected),
        "a rogue relay impersonated its own client"
    );
}

#[test]
fn a_captured_client_auth_does_not_replay_onto_a_second_connection() {
    let relay = identity(0x10);
    let alice = identity(0x21);
    let roster = roster_for(&[(&alice, "acme")], &[]);

    let first = RelayHandshake::new(relay.relay_id(), [1; 32]);
    let hello = first.hello().to_vec();
    let (hello, _) = decode(&hello).expect("decodes").expect("complete");
    let mut client = ClientHandshake::new(
        Role::Client,
        node_id(alice.public_key()),
        relay.relay_id(),
        relay.public_key().to_vec(),
        [2; 32],
    );
    let auth_bytes = client.on_relay_hello(&hello, &alice).expect("signs");
    let (auth, _) = decode(&auth_bytes).expect("decodes").expect("complete");

    // Same relay, a new connection, so a fresh relay_random.
    let mut second = RelayHandshake::new(relay.relay_id(), [99; 32]);
    assert_eq!(
        second.on_client_auth(&auth, &roster, &PonorVerifier, &relay),
        Err(ProtoError::Rejected)
    );
}

#[test]
fn the_relay_will_not_forward_between_tailnets() {
    // §5.4, end to end: both nodes are admitted, and traffic still does not
    // cross. Admission and authorisation are different questions.
    let relay = identity(0x10);
    let alice = identity(0x21);
    let bob = identity(0x22);
    let roster = roster_for(&[(&alice, "acme"), (&bob, "globex")], &[]);

    let a = handshake(
        &relay,
        &alice,
        Role::Client,
        node_id(alice.public_key()),
        &roster,
        [1; 32],
        [2; 32],
    )
    .expect("alice admitted");
    let b = handshake(
        &relay,
        &bob,
        Role::Client,
        node_id(bob.public_key()),
        &roster,
        [3; 32],
        [4; 32],
    )
    .expect("bob admitted");

    let mut hub = Hub::new(HubConfig::default());
    hub.admit(ConnId(1), a, 0);
    hub.admit(ConnId(2), b, 0);

    let payload = [1u8; 64];
    hub.on_frame(
        ConnId(1),
        &Frame::SendPacket {
            dst_id: node_id(bob.public_key()),
            payload: &payload,
        },
        &roster,
        0,
    )
    .expect("legal frame");

    assert!(
        hub.take_outbound(ConnId(2)).is_none(),
        "traffic crossed a tailnet boundary"
    );
}
