// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The Ponor handshake — `spec/ponor-v1.md` §5 and §7.1.
//!
//! Two state machines, one per side. Neither touches the network, a clock, or
//! a key: signing and verification arrive through [`Signer`] and [`Verifier`],
//! and the roster through [`Roster`].
//!
//! Two properties are enforced here rather than left to the caller, because
//! both are the kind of thing that is correct in the first implementation and
//! quietly wrong in the second:
//!
//! * **The client verifies before it transmits.** [`ClientHandshake`] will not
//!   report itself established until `RelayAuth` has verified, and
//!   [`ClientHandshake::may_send`] is the guard the datapath is expected to
//!   consult. `karst-control-v1.md` §9 is what happens otherwise: "the
//!   connection will fail closed" is no comfort for a message already sent.
//! * **Admission is structural.** [`RelayHandshake::on_client_auth`] obtains
//!   the peer's public key from the roster and from nowhere else. There is no
//!   argument it could be handed that would admit an unknown node, because
//!   `ClientAuth` does not carry a key.

use sha2::{Digest, Sha512};

use crate::consts::{ID_LEN, RANDOM_LEN, SIG_LEN};
use crate::frame::{Frame, Role};
use crate::Error;

const LABEL_CLIENT_AUTH: &[u8] = b"ponor-client-auth-v1";
const LABEL_RELAY_AUTH: &[u8] = b"ponor-relay-auth-v1";

/// Length-prefix every hashed component.
///
/// Every field in v1 is fixed-width, so this changes nothing today. It is here
/// because a future variable-width field would otherwise inherit an ambiguity
/// nobody re-derived — `("ab","c")` and `("a","bc")` hashing alike — and the
/// signature input is built from attacker-influenced values.
fn push_field(h: &mut Sha512, field: &[u8]) {
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    h.update(len.to_be_bytes());
    h.update(field);
}

fn transcript(
    label: &[u8],
    relay_id: &[u8; ID_LEN],
    relay_random: &[u8; RANDOM_LEN],
    client_random: &[u8; RANDOM_LEN],
    peer_id: &[u8; ID_LEN],
    role: Role,
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(label);
    push_field(&mut h, relay_id);
    push_field(&mut h, relay_random);
    push_field(&mut h, client_random);
    push_field(&mut h, peer_id);
    push_field(&mut h, &[role.to_wire()]);
    h.finalize().into()
}

/// The byte string a connecting peer signs — `spec/ponor-v1.md` §5.5.
///
/// `relay_id` is bound so that a rogue relay cannot replay the client's
/// authentication to the real one; `role` is bound so that a client's
/// authentication cannot be accepted as a mesh peer's.
#[must_use]
pub fn client_auth_signing_input(
    relay_id: &[u8; ID_LEN],
    relay_random: &[u8; RANDOM_LEN],
    client_random: &[u8; RANDOM_LEN],
    peer_id: &[u8; ID_LEN],
    role: Role,
) -> [u8; 64] {
    transcript(
        LABEL_CLIENT_AUTH,
        relay_id,
        relay_random,
        client_random,
        peer_id,
        role,
    )
}

/// The byte string the relay signs — `spec/ponor-v1.md` §5.5.
///
/// The field list is identical to the client's; the label is not, so neither
/// party's signature is ever a valid value for the other's.
#[must_use]
pub fn relay_auth_signing_input(
    relay_id: &[u8; ID_LEN],
    relay_random: &[u8; RANDOM_LEN],
    client_random: &[u8; RANDOM_LEN],
    peer_id: &[u8; ID_LEN],
    role: Role,
) -> [u8; 64] {
    transcript(
        LABEL_RELAY_AUTH,
        relay_id,
        relay_random,
        client_random,
        peer_id,
        role,
    )
}

/// Produces ML-DSA-65 signatures with this party's identity key.
///
/// Signing SHOULD be hedged (randomized). FIPS 204 permits either form, and
/// the randomized one does not hand a fault-injection attacker a repeatable
/// target.
pub trait Signer {
    /// # Errors
    /// Returns an error if the signing key is unavailable.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>>;
}

/// Verifies ML-DSA-65 signatures against a public key from the roster or the
/// relay registry.
pub trait Verifier {
    /// Must be false, not a panic, for a malformed key or signature: both
    /// arrive from the wire.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// An aquifer identifier. Forwarding is scoped by it — §5.4.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AquiferId(pub String);

/// What the roster holds about an admitted node.
#[derive(Debug, Clone)]
pub struct RosterEntry {
    /// The node's ML-DSA-65 identity key.
    pub identity_pk: Vec<u8>,
    /// The aquifer it belongs to. A relay MUST NOT forward between aquifers.
    pub aquifer: AquiferId,
}

/// What the configuration holds about a meshed relay.
#[derive(Debug, Clone)]
pub struct RelayEntry {
    /// The peer relay's ML-DSA-65 identity key.
    pub identity_pk: Vec<u8>,
}

/// The set of peers a relay will speak to.
///
/// This trait is the whole of §5.3. A relay verifies a peer's signature
/// against a key it obtains here, and `ClientAuth` carries no key, so there is
/// no code path in which an unknown peer is admitted — admitting one would
/// require a key the relay does not have.
pub trait Roster {
    /// The node's roster entry, or `None` if it is not admitted.
    fn client(&self, node_id: &[u8; ID_LEN]) -> Option<RosterEntry>;

    /// The mesh peer's entry, or `None` if it is not a configured mesh peer.
    fn mesh_peer(&self, relay_id: &[u8; ID_LEN]) -> Option<RelayEntry>;

    /// A syntactically valid ML-DSA-65 public key that verifies nothing.
    ///
    /// Used to close a timing side channel: without it, an unknown `node_id`
    /// is rejected by a map lookup while a known one with a bad signature
    /// costs a full ML-DSA verification, and the difference is a
    /// roster-membership oracle available to any unauthenticated caller.
    /// [`RelayHandshake::on_client_auth`] verifies against this on a miss so
    /// both paths do the same work.
    ///
    /// A keypair generated at relay start and never used elsewhere is the
    /// intended implementation. It is never transmitted.
    fn decoy_key(&self) -> &[u8];
}

/// Who was admitted, and as what.
///
/// Mesh peers are not clients. §8 forbids `SendPacket` on a mesh connection
/// and `Forward` on a client one, and this enum is how a connection remembers
/// which set of rules it is under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// A node.
    Client {
        /// Its 32-byte id.
        node_id: [u8; ID_LEN],
        /// Its aquifer. Forwarding is scoped to it.
        aquifer: AquiferId,
    },
    /// Another relay in the same region.
    Mesh {
        /// Its 32-byte id.
        relay_id: [u8; ID_LEN],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientState {
    AwaitingHello,
    AwaitingAuth { relay_random: [u8; RANDOM_LEN] },
    Established,
    Failed,
}

/// The connecting side of the handshake.
///
/// Used by a node dialling a relay ([`Role::Client`]) and by a relay dialling
/// a mesh peer ([`Role::Mesh`]); the two differ only in the role byte and in
/// which key directory the responder consults.
#[derive(Debug)]
pub struct ClientHandshake {
    role: Role,
    peer_id: [u8; ID_LEN],
    expected_relay_id: [u8; ID_LEN],
    relay_identity_pk: Vec<u8>,
    client_random: [u8; RANDOM_LEN],
    state: ClientState,
}

impl ClientHandshake {
    /// Start a handshake against a relay whose identity is already known.
    ///
    /// `relay_identity_pk` comes from the relay registry in the netmap, never
    /// from the connection. §4.2: a client MUST NOT treat TLS certificate
    /// validation as authentication of the relay, and there is deliberately no
    /// constructor that omits this argument.
    ///
    /// `client_random` must be 32 fresh random bytes.
    #[must_use]
    pub fn new(
        role: Role,
        peer_id: [u8; ID_LEN],
        expected_relay_id: [u8; ID_LEN],
        relay_identity_pk: Vec<u8>,
        client_random: [u8; RANDOM_LEN],
    ) -> Self {
        Self {
            role,
            peer_id,
            expected_relay_id,
            relay_identity_pk,
            client_random,
            state: ClientState::AwaitingHello,
        }
    }

    /// Consume `RelayHello` and produce the encoded `ClientAuth` to send.
    ///
    /// # Errors
    /// [`Error::OutOfOrder`] if a hello has already been seen,
    /// [`Error::RelayIdentityMismatch`] if this is not the relay the caller
    /// intended to reach, [`Error::SignerUnavailable`] if the signer refuses or
    /// returns a signature of the wrong length.
    pub fn on_relay_hello(
        &mut self,
        frame: &Frame<'_>,
        signer: &impl Signer,
    ) -> Result<Vec<u8>, Error> {
        let Frame::RelayHello {
            relay_id,
            relay_random,
        } = *frame
        else {
            return self.fail(Error::OutOfOrder);
        };
        if self.state != ClientState::AwaitingHello {
            return self.fail(Error::OutOfOrder);
        }
        // Checked before signing, not after: signing over an impostor's
        // relay_id would hand it a signature naming itself.
        if relay_id != self.expected_relay_id {
            return self.fail(Error::RelayIdentityMismatch);
        }

        let input = client_auth_signing_input(
            &relay_id,
            &relay_random,
            &self.client_random,
            &self.peer_id,
            self.role,
        );
        let signature = match signer.sign(&input) {
            Ok(sig) if sig.len() == SIG_LEN => sig,
            _ => return self.fail(Error::SignerUnavailable),
        };

        let bytes = Frame::ClientAuth {
            role: self.role,
            peer_id: self.peer_id,
            client_random: self.client_random,
            signature: &signature,
        }
        .to_vec();

        self.state = ClientState::AwaitingAuth { relay_random };
        Ok(bytes)
    }

    /// Verify `RelayAuth` and establish the connection.
    ///
    /// # Errors
    /// [`Error::OutOfOrder`] if no hello has been seen or the handshake is
    /// already finished, [`Error::Rejected`] if the signature does not verify
    /// against the registry key.
    pub fn on_relay_auth(
        &mut self,
        frame: &Frame<'_>,
        verifier: &impl Verifier,
    ) -> Result<(), Error> {
        let Frame::RelayAuth { signature } = *frame else {
            return self.fail(Error::OutOfOrder).map(|_: Vec<u8>| ());
        };
        let ClientState::AwaitingAuth { relay_random } = self.state else {
            return self.fail(Error::OutOfOrder).map(|_: Vec<u8>| ());
        };

        let input = relay_auth_signing_input(
            &self.expected_relay_id,
            &relay_random,
            &self.client_random,
            &self.peer_id,
            self.role,
        );
        if !verifier.verify(&self.relay_identity_pk, &input, signature) {
            return self.fail(Error::Rejected).map(|_: Vec<u8>| ());
        }

        self.state = ClientState::Established;
        Ok(())
    }

    /// Whether the relay has been authenticated.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == ClientState::Established
    }

    /// Whether it is legal to send anything beyond `ClientAuth`.
    ///
    /// The datapath is expected to consult this rather than assume. It is the
    /// same condition as [`Self::is_established`], named for the thing the
    /// caller is actually asking.
    #[must_use]
    pub fn may_send(&self) -> bool {
        self.is_established()
    }

    /// A failed handshake stays failed. Without this a caller that ignored one
    /// error could drive the machine forward on the next frame.
    fn fail<T>(&mut self, e: Error) -> Result<T, Error> {
        self.state = ClientState::Failed;
        Err(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayState {
    AwaitingAuth,
    Established,
    Failed,
}

/// The listening side of the handshake.
#[derive(Debug)]
pub struct RelayHandshake {
    relay_id: [u8; ID_LEN],
    relay_random: [u8; RANDOM_LEN],
    state: RelayState,
}

impl RelayHandshake {
    /// Begin a handshake. `relay_random` must be 32 fresh random bytes, per
    /// connection — it is the freshness the peer's signature is bound to.
    #[must_use]
    pub fn new(relay_id: [u8; ID_LEN], relay_random: [u8; RANDOM_LEN]) -> Self {
        Self {
            relay_id,
            relay_random,
            state: RelayState::AwaitingAuth,
        }
    }

    /// The frame to send first. The relay speaks first so that the peer signs
    /// over a value it has not yet seen — §7.1.
    #[must_use]
    pub fn hello(&self) -> Frame<'static> {
        Frame::RelayHello {
            relay_id: self.relay_id,
            relay_random: self.relay_random,
        }
    }

    /// Verify `ClientAuth`, decide admission, and produce the encoded
    /// `RelayAuth` to send.
    ///
    /// The peer's public key is obtained from `roster` and from nowhere else.
    /// On a roster miss the signature is still verified, against
    /// [`Roster::decoy_key`], so that an unknown id and a bad signature cost
    /// the same work.
    ///
    /// # Errors
    /// [`Error::Rejected`] — uniformly — for an unknown peer, a signature that
    /// does not verify, or a role whose directory does not hold the id.
    /// `spec/ponor-v1.md` §10 requires the caller to respond by closing the
    /// connection with no frame and no reason: the distinction is for the
    /// operator's logs, never for the peer.
    ///
    /// [`Error::OutOfOrder`] for a second `ClientAuth` or any other frame.
    /// [`Error::SignerUnavailable`] if this relay's signer refuses.
    pub fn on_client_auth(
        &mut self,
        frame: &Frame<'_>,
        roster: &impl Roster,
        verifier: &impl Verifier,
        signer: &impl Signer,
    ) -> Result<(Admitted, Vec<u8>), Error> {
        let Frame::ClientAuth {
            role,
            peer_id,
            client_random,
            signature,
        } = *frame
        else {
            return self.fail(Error::OutOfOrder);
        };
        if self.state != RelayState::AwaitingAuth {
            return self.fail(Error::OutOfOrder);
        }

        // Look up first, then verify unconditionally. The decoy makes the miss
        // path cost an ML-DSA verification too; see Roster::decoy_key.
        let (key, admitted) = match role {
            Role::Client => match roster.client(&peer_id) {
                Some(e) => (
                    e.identity_pk,
                    Some(Admitted::Client {
                        node_id: peer_id,
                        aquifer: e.aquifer,
                    }),
                ),
                None => (roster.decoy_key().to_vec(), None),
            },
            Role::Mesh => match roster.mesh_peer(&peer_id) {
                Some(e) => (e.identity_pk, Some(Admitted::Mesh { relay_id: peer_id })),
                None => (roster.decoy_key().to_vec(), None),
            },
        };

        let input = client_auth_signing_input(
            &self.relay_id,
            &self.relay_random,
            &client_random,
            &peer_id,
            role,
        );
        let verified = verifier.verify(&key, &input, signature);

        // The lookup result is already in hand and `verified` is already
        // computed, so testing them together cannot short-circuit past the
        // verification and undo the work the decoy just did.
        let Some(admitted) = admitted.filter(|_| verified) else {
            return self.fail(Error::Rejected);
        };

        let reply = relay_auth_signing_input(
            &self.relay_id,
            &self.relay_random,
            &client_random,
            &peer_id,
            role,
        );
        let sig = match signer.sign(&reply) {
            Ok(s) if s.len() == SIG_LEN => s,
            _ => return self.fail(Error::SignerUnavailable),
        };

        self.state = RelayState::Established;
        Ok((admitted, Frame::RelayAuth { signature: &sig }.to_vec()))
    }

    /// Whether a peer has been admitted.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == RelayState::Established
    }

    fn fail<T>(&mut self, e: Error) -> Result<T, Error> {
        self.state = RelayState::Failed;
        Err(e)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use core::cell::Cell;
    use std::collections::HashMap;

    /// A stand-in for ML-DSA-65 that is deterministic and checkable.
    ///
    /// The state machines are what is under test; substituting the real
    /// signature scheme would slow every case down and test `RustCrypto` rather
    /// than this crate. What matters is that a wrong key produces a signature
    /// that does not verify, and this does.
    struct StubKey(u8);

    impl StubKey {
        fn public(&self) -> Vec<u8> {
            vec![self.0; 1952]
        }
        fn expected(public_key: &[u8], message: &[u8]) -> Vec<u8> {
            let mut h = Sha512::new();
            h.update(public_key);
            h.update(message);
            let seed: [u8; 64] = h.finalize().into();
            seed.iter().copied().cycle().take(SIG_LEN).collect()
        }
    }

    impl Signer for StubKey {
        fn sign(
            &self,
            message: &[u8],
        ) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>> {
            Ok(Self::expected(&self.public(), message))
        }
    }

    #[derive(Default)]
    struct StubVerifier {
        calls: Cell<usize>,
    }

    impl Verifier for StubVerifier {
        fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
            self.calls.set(self.calls.get() + 1);
            StubKey::expected(public_key, message) == signature
        }
    }

    struct BrokenSigner;
    impl Signer for BrokenSigner {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error + Send + Sync>> {
            Err("no key".into())
        }
    }

    struct TestRoster {
        clients: HashMap<[u8; ID_LEN], RosterEntry>,
        mesh: HashMap<[u8; ID_LEN], RelayEntry>,
        decoy: Vec<u8>,
    }

    impl TestRoster {
        fn new() -> Self {
            Self {
                clients: HashMap::new(),
                mesh: HashMap::new(),
                decoy: StubKey(0xde).public(),
            }
        }
        fn with_client(mut self, id: [u8; ID_LEN], key: &StubKey, aquifer: &str) -> Self {
            self.clients.insert(
                id,
                RosterEntry {
                    identity_pk: key.public(),
                    aquifer: AquiferId(aquifer.to_owned()),
                },
            );
            self
        }
        fn with_mesh(mut self, id: [u8; ID_LEN], key: &StubKey) -> Self {
            self.mesh.insert(
                id,
                RelayEntry {
                    identity_pk: key.public(),
                },
            );
            self
        }
    }

    impl Roster for TestRoster {
        fn client(&self, node_id: &[u8; ID_LEN]) -> Option<RosterEntry> {
            self.clients.get(node_id).cloned()
        }
        fn mesh_peer(&self, relay_id: &[u8; ID_LEN]) -> Option<RelayEntry> {
            self.mesh.get(relay_id).cloned()
        }
        fn decoy_key(&self) -> &[u8] {
            &self.decoy
        }
    }

    fn id(b: u8) -> [u8; ID_LEN] {
        [b; ID_LEN]
    }

    struct Fixture {
        node_id: [u8; ID_LEN],
        relay_id: [u8; ID_LEN],
        node_key: StubKey,
        relay_key: StubKey,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                node_id: id(0x11),
                relay_id: id(0x22),
                node_key: StubKey(0xaa),
                relay_key: StubKey(0xbb),
            }
        }
        fn client(&self) -> ClientHandshake {
            ClientHandshake::new(
                Role::Client,
                self.node_id,
                self.relay_id,
                self.relay_key.public(),
                id(0x33),
            )
        }
        fn relay(&self) -> RelayHandshake {
            RelayHandshake::new(self.relay_id, id(0x44))
        }
        fn roster(&self) -> TestRoster {
            TestRoster::new().with_client(self.node_id, &self.node_key, "aquifer-a")
        }
    }

    /// Drive a full handshake, returning whether the client ended up
    /// established and what the relay admitted.
    fn run(f: &Fixture, roster: &TestRoster) -> Result<(bool, Admitted), Error> {
        let v = StubVerifier::default();
        let mut client = f.client();
        let mut relay = f.relay();

        let hello = relay.hello();
        let auth_bytes = client.on_relay_hello(&hello, &f.node_key)?;
        let (auth, _) = crate::frame::decode(&auth_bytes)?.expect("complete frame");

        let (admitted, reply_bytes) = relay.on_client_auth(&auth, roster, &v, &f.relay_key)?;
        let (reply, _) = crate::frame::decode(&reply_bytes)?.expect("complete frame");
        client.on_relay_auth(&reply, &v)?;

        Ok((client.may_send(), admitted))
    }

    #[test]
    fn a_rostered_node_completes_the_handshake() {
        let f = Fixture::new();
        let (may_send, admitted) = run(&f, &f.roster()).expect("handshake should succeed");
        assert!(may_send);
        assert_eq!(
            admitted,
            Admitted::Client {
                node_id: f.node_id,
                aquifer: AquiferId("aquifer-a".to_owned()),
            }
        );
    }

    #[test]
    fn an_unrostered_node_cannot_be_admitted() {
        // The point of §5.3: there is no argument that admits an unknown node,
        // because ClientAuth carries no key for the relay to fall back on.
        let f = Fixture::new();
        assert_eq!(run(&f, &TestRoster::new()), Err(Error::Rejected));
    }

    #[test]
    fn an_empty_roster_admits_nobody() {
        // An absent value must never read as permissive.
        let f = Fixture::new();
        let roster = TestRoster::new();
        assert!(roster.client(&f.node_id).is_none());
        assert_eq!(run(&f, &roster), Err(Error::Rejected));
    }

    #[test]
    fn rejections_are_indistinguishable() {
        // §10: an unauthenticated caller must not be able to tell "I am not in
        // the roster" from "my signature is wrong". Both are Error::Rejected,
        // and the caller has nothing else to key a response off.
        let f = Fixture::new();

        let unknown = run(&f, &TestRoster::new());

        // Right id, wrong key.
        let wrong_key = TestRoster::new().with_client(f.node_id, &StubKey(0xcc), "aquifer-a");
        let bad_sig = run(&f, &wrong_key);

        // Right id and key, but registered as a mesh peer rather than a client.
        let wrong_role = TestRoster::new().with_mesh(f.node_id, &f.node_key);
        let bad_role = run(&f, &wrong_role);

        assert_eq!(unknown, Err(Error::Rejected));
        assert_eq!(unknown, bad_sig);
        assert_eq!(unknown, bad_role);
    }

    #[test]
    fn an_unknown_id_still_costs_a_verification() {
        // Otherwise the roster is a membership oracle by timing: a miss would
        // return on a map lookup while a hit pays for ML-DSA.
        let f = Fixture::new();
        let v = StubVerifier::default();
        let mut client = f.client();
        let mut relay = f.relay();

        let auth_bytes = client
            .on_relay_hello(&relay.hello(), &f.node_key)
            .expect("hello accepted");
        let (auth, _) = crate::frame::decode(&auth_bytes)
            .expect("decodes")
            .expect("complete");

        let empty = TestRoster::new();
        assert_eq!(
            relay.on_client_auth(&auth, &empty, &v, &f.relay_key),
            Err(Error::Rejected)
        );
        assert_eq!(v.calls.get(), 1, "roster miss skipped the verification");
    }

    #[test]
    fn a_mesh_peer_is_admitted_as_a_mesh_peer() {
        let f = Fixture::new();
        let peer_relay_id = id(0x55);
        let peer_key = StubKey(0xdd);
        let roster = TestRoster::new().with_mesh(peer_relay_id, &peer_key);
        let v = StubVerifier::default();

        let mut client = ClientHandshake::new(
            Role::Mesh,
            peer_relay_id,
            f.relay_id,
            f.relay_key.public(),
            id(0x66),
        );
        let mut relay = f.relay();

        let auth_bytes = client
            .on_relay_hello(&relay.hello(), &peer_key)
            .expect("hello accepted");
        let (auth, _) = crate::frame::decode(&auth_bytes)
            .expect("decodes")
            .expect("complete");
        let (admitted, reply_bytes) = relay
            .on_client_auth(&auth, &roster, &v, &f.relay_key)
            .expect("mesh peer admitted");
        assert_eq!(
            admitted,
            Admitted::Mesh {
                relay_id: peer_relay_id
            }
        );

        let (reply, _) = crate::frame::decode(&reply_bytes)
            .expect("decodes")
            .expect("complete");
        client
            .on_relay_auth(&reply, &v)
            .expect("relay authenticated");
        assert!(client.is_established());
    }

    #[test]
    fn a_client_key_cannot_authenticate_as_a_mesh_peer() {
        // §5.5's role binding. Even with the same id in both directories, the
        // signature a client produced does not verify for role = MESH.
        let f = Fixture::new();
        let roster = TestRoster::new()
            .with_client(f.node_id, &f.node_key, "aquifer-a")
            .with_mesh(f.node_id, &f.node_key);
        let v = StubVerifier::default();

        let mut client = f.client(); // signs with role = CLIENT
        let auth_bytes = client
            .on_relay_hello(&f.relay().hello(), &f.node_key)
            .expect("hello accepted");
        let (auth, _) = crate::frame::decode(&auth_bytes)
            .expect("decodes")
            .expect("complete");

        // Rewrite the role byte in flight, leaving the signature untouched.
        let Frame::ClientAuth {
            peer_id,
            client_random,
            signature,
            ..
        } = auth
        else {
            panic!("expected ClientAuth")
        };
        let forged = Frame::ClientAuth {
            role: Role::Mesh,
            peer_id,
            client_random,
            signature,
        };

        let mut relay = f.relay();
        assert_eq!(
            relay.on_client_auth(&forged, &roster, &v, &f.relay_key),
            Err(Error::Rejected)
        );
    }

    #[test]
    fn a_client_will_not_sign_for_the_wrong_relay() {
        // A rogue relay must not obtain a signature naming itself, and the
        // check happens before signing rather than after.
        let f = Fixture::new();
        let mut client = f.client();
        let impostor = RelayHandshake::new(id(0x99), id(0x44));
        assert_eq!(
            client.on_relay_hello(&impostor.hello(), &f.node_key),
            Err(Error::RelayIdentityMismatch)
        );
        assert!(!client.may_send());
    }

    #[test]
    fn a_captured_client_auth_does_not_replay_onto_a_new_connection() {
        // relay_random is per connection and is signed, so a recorded
        // ClientAuth is bound to the connection that produced it.
        let f = Fixture::new();
        let roster = f.roster();
        let v = StubVerifier::default();

        let mut client = f.client();
        let first = RelayHandshake::new(f.relay_id, id(0x44));
        let auth_bytes = client
            .on_relay_hello(&first.hello(), &f.node_key)
            .expect("hello accepted");
        let (auth, _) = crate::frame::decode(&auth_bytes)
            .expect("decodes")
            .expect("complete");

        // Same relay, different connection: a fresh relay_random.
        let mut second = RelayHandshake::new(f.relay_id, id(0x77));
        assert_eq!(
            second.on_client_auth(&auth, &roster, &v, &f.relay_key),
            Err(Error::Rejected)
        );
    }

    #[test]
    fn a_captured_relay_auth_does_not_replay_onto_a_new_connection() {
        // The mirror property: client_random is signed by the relay, so the
        // relay's signature is fresh with respect to the client.
        let f = Fixture::new();
        let roster = f.roster();
        let v = StubVerifier::default();

        let mut client_a = f.client();
        let mut relay = f.relay();
        let auth_bytes = client_a
            .on_relay_hello(&relay.hello(), &f.node_key)
            .expect("hello accepted");
        let (auth, _) = crate::frame::decode(&auth_bytes)
            .expect("decodes")
            .expect("complete");
        let (_, reply_bytes) = relay
            .on_client_auth(&auth, &roster, &v, &f.relay_key)
            .expect("admitted");
        let (reply, _) = crate::frame::decode(&reply_bytes)
            .expect("decodes")
            .expect("complete");

        // A second client with a different client_random, same relay.
        let mut client_b = ClientHandshake::new(
            Role::Client,
            f.node_id,
            f.relay_id,
            f.relay_key.public(),
            id(0x88),
        );
        let _ = client_b
            .on_relay_hello(&relay.hello(), &f.node_key)
            .expect("hello accepted");
        assert_eq!(client_b.on_relay_auth(&reply, &v), Err(Error::Rejected));
        assert!(!client_b.may_send());
    }

    #[test]
    fn a_client_does_not_send_before_it_has_verified() {
        // karst-control-v1.md §9 in one assertion: "fails closed" is no
        // comfort for a message already on the wire, so the guard is checked
        // rather than the outcome.
        let f = Fixture::new();
        let mut client = f.client();
        assert!(!client.may_send());

        let relay = f.relay();
        let _ = client
            .on_relay_hello(&relay.hello(), &f.node_key)
            .expect("hello accepted");
        assert!(
            !client.may_send(),
            "ClientAuth is sent, but nothing else may be"
        );
    }

    #[test]
    fn a_forged_relay_auth_leaves_the_client_unestablished() {
        let f = Fixture::new();
        let v = StubVerifier::default();
        let mut client = f.client();
        let _ = client
            .on_relay_hello(&f.relay().hello(), &f.node_key)
            .expect("hello accepted");

        let junk = vec![0u8; SIG_LEN];
        assert_eq!(
            client.on_relay_auth(&Frame::RelayAuth { signature: &junk }, &v),
            Err(Error::Rejected)
        );
        assert!(!client.may_send());
    }

    #[test]
    fn a_failed_handshake_stays_failed() {
        // A caller that ignored one error must not be able to drive the
        // machine forward on the next frame.
        let f = Fixture::new();
        let mut client = f.client();
        let impostor = RelayHandshake::new(id(0x99), id(0x44));
        let _ = client.on_relay_hello(&impostor.hello(), &f.node_key);

        assert_eq!(
            client.on_relay_hello(&f.relay().hello(), &f.node_key),
            Err(Error::OutOfOrder)
        );
        assert!(!client.may_send());
    }

    #[test]
    fn a_second_client_auth_is_out_of_order() {
        // §10: a second ClientAuth on an established connection would reset
        // state the peer has already relied on.
        let f = Fixture::new();
        let roster = f.roster();
        let v = StubVerifier::default();
        let mut client = f.client();
        let mut relay = f.relay();

        let auth_bytes = client
            .on_relay_hello(&relay.hello(), &f.node_key)
            .expect("hello accepted");
        let (auth, _) = crate::frame::decode(&auth_bytes)
            .expect("decodes")
            .expect("complete");
        let _ = relay
            .on_client_auth(&auth, &roster, &v, &f.relay_key)
            .expect("admitted");
        assert_eq!(
            relay.on_client_auth(&auth, &roster, &v, &f.relay_key),
            Err(Error::OutOfOrder)
        );
    }

    #[test]
    fn an_envelope_before_the_handshake_is_out_of_order() {
        let f = Fixture::new();
        let roster = f.roster();
        let v = StubVerifier::default();
        let mut relay = f.relay();
        let payload = [7u8; 64];
        assert_eq!(
            relay.on_client_auth(
                &Frame::SendPacket {
                    dst_id: id(1),
                    payload: &payload
                },
                &roster,
                &v,
                &f.relay_key
            ),
            Err(Error::OutOfOrder)
        );
    }

    #[test]
    fn a_broken_signer_is_not_a_rejection() {
        // Our own key being unavailable is not the peer's fault, and must not
        // be reported as though it were.
        let f = Fixture::new();
        let mut client = f.client();
        assert_eq!(
            client.on_relay_hello(&f.relay().hello(), &BrokenSigner),
            Err(Error::SignerUnavailable)
        );
    }

    #[test]
    fn the_two_signing_inputs_differ() {
        // The field lists are identical; only the label separates them. If
        // they ever collided, either party's signature would be a valid value
        // for the other's.
        let a = client_auth_signing_input(&id(1), &id(2), &id(3), &id(4), Role::Client);
        let b = relay_auth_signing_input(&id(1), &id(2), &id(3), &id(4), Role::Client);
        assert_ne!(a, b);
    }

    #[test]
    fn the_role_changes_the_signing_input() {
        let a = client_auth_signing_input(&id(1), &id(2), &id(3), &id(4), Role::Client);
        let b = client_auth_signing_input(&id(1), &id(2), &id(3), &id(4), Role::Mesh);
        assert_ne!(a, b);
    }

    #[test]
    fn every_field_is_bound_into_the_signing_input() {
        let base = client_auth_signing_input(&id(1), &id(2), &id(3), &id(4), Role::Client);
        for changed in [
            client_auth_signing_input(&id(9), &id(2), &id(3), &id(4), Role::Client),
            client_auth_signing_input(&id(1), &id(9), &id(3), &id(4), Role::Client),
            client_auth_signing_input(&id(1), &id(2), &id(9), &id(4), Role::Client),
            client_auth_signing_input(&id(1), &id(2), &id(3), &id(9), Role::Client),
        ] {
            assert_ne!(base, changed);
        }
    }
}
