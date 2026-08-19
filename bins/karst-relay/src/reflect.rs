// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The AVEN reflector — `spec/aven-v1.md` §7.6, `spec/ponor-v1.md` §7.7.
//!
//! A UDP service that answers `Reflect` with the source address it saw. That
//! is the piece a pair of NAT-bound nodes needs before either can be probed at
//! all: each learns its own mapped address from a party that can see it, and
//! neither can see it for itself.
//!
//! **Sans-io**, like `hub`. [`Reflector::handle`] takes bytes, a source address
//! and a millisecond stamp, and returns the bytes to send back — so every rule
//! in §7.6 is unit-testable without a socket. `server` owns the socket.
//!
//! # Why this is not a STUN server
//!
//! It answers **only** datagrams authenticated under a key it minted, inside
//! TLS, for a node that completed the Ponor handshake. An open STUN service
//! answers anyone, which makes it a reflector for anyone; §7.6's amplification
//! table is the whole argument and it depends on this being closed.

use std::collections::HashMap;
use std::net::SocketAddr;

use karst_disco::consts::{REFLECT_KEY_LEN, TAG_LEN};
use karst_disco::{msg, DiscoKey, Endpoint, Message};
use karst_relay_proto::consts::ID_LEN;

use crate::limits::{Budget, Meter};

/// §7.6's recommended sustained rate, per key.
const REFLECTS_PER_SEC: u64 = 1;
/// …and the burst, which is what a node's first three probes need.
const REFLECT_BURST: u64 = 5;

/// What a node may spend at the reflector.
///
/// The frame counters carry the limit and the byte counters are left open,
/// because every legal datagram here is exactly the same size — 65 bytes, by
/// §7.6 — so counting bytes would be counting frames again in a unit that
/// obscures the rule.
fn budget() -> Budget {
    Budget {
        bytes_per_sec: u64::MAX,
        byte_burst: u64::MAX,
        frames_per_sec: REFLECTS_PER_SEC,
        frame_burst: REFLECT_BURST,
    }
}

struct Session {
    key: DiscoKey,
    node: [u8; ID_LEN],
    meter: Meter,
}

/// The reflector's state: the live keys, and what each may spend.
pub struct Reflector {
    /// Where nodes are told to send `Reflect`. Carried in `ReflectOffer`
    /// rather than inferred, because this is a different socket from the Ponor
    /// listener — see `ponor-v1.md` §7.7.
    endpoint: SocketAddr,
    by_tag: HashMap<[u8; TAG_LEN], Session>,
    by_node: HashMap<[u8; ID_LEN], [u8; TAG_LEN]>,
}

impl std::fmt::Debug for Reflector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the keys. A reflect key is a credential and `{:?}` on a
        // collection of them is a thoroughly plausible way to lose one.
        f.debug_struct("Reflector")
            .field("endpoint", &self.endpoint)
            .field("sessions", &self.by_tag.len())
            .finish_non_exhaustive()
    }
}

/// Why a datagram produced no answer.
///
/// Distinguished for the operator's metrics, **never** for the sender: §10
/// makes every AVEN failure a silent drop, and telling the two apart on the
/// wire would make the reflector an oracle for which keys it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Not AVEN, malformed, or the wrong length for its type.
    NotForUs,
    /// The tag names no live key — so, by §5.3, no live Ponor connection.
    UnknownTag,
    /// The tag resolved but the MAC did not verify.
    BadMac,
    /// A `Reflection`, or anything else only a node should receive. A
    /// reflector answers `Reflect` and nothing else.
    WrongDirection,
    /// Over §7.6's per-key rate.
    RateLimited,
}

impl Reflector {
    /// A reflector holding no keys, advertising `endpoint`.
    #[must_use]
    pub fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            by_tag: HashMap::new(),
            by_node: HashMap::new(),
        }
    }

    /// Where clients are told to send `Reflect`.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// The endpoint as `ReflectOffer` carries it — `aven-v1.md` §6.2.
    #[must_use]
    pub fn wire_endpoint(&self) -> [u8; karst_disco::consts::ENDPOINT_LEN] {
        Endpoint(self.endpoint).to_wire()
    }

    /// Mint a key for `node`, replacing any it already had.
    ///
    /// Returns the bytes to put in `ReflectOffer`. **Replacing rather than
    /// reusing** is what makes §7.7's per-connection lifetime true: a
    /// reconnecting node — the common case after a suspend or a handover —
    /// must not find its previous credential still live, because the old
    /// connection's key would then outlive the connection that authenticated
    /// it.
    ///
    /// # Errors
    /// The operating system's refusal to supply entropy, which is not a
    /// condition to paper over with a weaker key.
    pub fn mint(
        &mut self,
        node: [u8; ID_LEN],
        now_ms: u64,
    ) -> Result<[u8; REFLECT_KEY_LEN], String> {
        let mut bytes = [0u8; REFLECT_KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|e| format!("reflector: no entropy: {e}"))?;

        self.release(&node);
        let key = DiscoKey::new(bytes);
        let tag = key.reflect_tag();
        self.by_tag.insert(
            tag,
            Session {
                key,
                node,
                meter: Meter::new(budget(), now_ms),
            },
        );
        self.by_node.insert(node, tag);
        Ok(bytes)
    }

    /// Forget `node`'s key, if it has one.
    ///
    /// Called when a Ponor connection closes. §7.7 requires it: a key that
    /// outlived its connection would be a credential with no revocation and no
    /// expiry, held by a node the relay has stopped tracking.
    pub fn release(&mut self, node: &[u8; ID_LEN]) {
        if let Some(tag) = self.by_node.remove(node) {
            self.by_tag.remove(&tag);
        }
    }

    /// Live keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_tag.len()
    }

    /// Whether no key is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }

    /// Answer one datagram, or explain why not.
    ///
    /// The reply goes to `from` and to nowhere else. That is the **inverse** of
    /// §7.1's rule for `Pong` and it is not a contradiction of it: a `Pong`
    /// answers a question about the *peer's* address, where trusting the source
    /// lets an on-path attacker redirect a probe; a `Reflection` answers a
    /// question about the *sender's own* address, where the source is the
    /// entire content of the answer.
    ///
    /// # Errors
    /// [`Refused`], for the operator's metrics only. Every variant means the
    /// same thing on the wire: nothing is sent.
    pub fn handle(
        &mut self,
        datagram: &[u8],
        from: SocketAddr,
        now_ms: u64,
    ) -> Result<Vec<u8>, Refused> {
        let header = msg::peek(datagram).map_err(|_| Refused::NotForUs)?;
        // A `Reflection` arriving here is a node's answer being replayed at the
        // reflector. Refused by direction before any key is consulted, so the
        // two message types can never be confused for one another even under a
        // key that would verify both.
        if !header.is_reflect() {
            return Err(Refused::WrongDirection);
        }

        let session = self
            .by_tag
            .get_mut(&header.tag)
            .ok_or(Refused::UnknownTag)?;
        let message = msg::open(datagram, &session.key).map_err(|_| Refused::BadMac)?;
        let Message::Reflect { tx } = message else {
            return Err(Refused::WrongDirection);
        };

        // Charged after authentication, so an unauthenticated source cannot
        // spend a node's allowance — but before the answer, so a replayed
        // `Reflect` cannot. §7.6's amplification table depends on this being
        // the last gate rather than the first.
        let len = u64::try_from(datagram.len()).unwrap_or(u64::MAX);
        if !session.meter.admit(len, now_ms) {
            return Err(Refused::RateLimited);
        }

        Ok(Message::Reflection {
            tx,
            observed: Endpoint(from),
        }
        .encode(&session.key, &header.tag, 0))
    }

    /// Which node a tag belongs to — for logging and tests.
    #[must_use]
    pub fn node_for(&self, tag: &[u8; TAG_LEN]) -> Option<[u8; ID_LEN]> {
        self.by_tag.get(tag).map(|s| s.node)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation
    )]

    use super::*;
    use karst_disco::TxId;

    fn node(b: u8) -> [u8; ID_LEN] {
        [b; ID_LEN]
    }

    fn here() -> SocketAddr {
        "203.0.113.7:3478".parse().expect("addr")
    }

    fn from() -> SocketAddr {
        "198.51.100.9:51820".parse().expect("addr")
    }

    /// A node's side: mint gives it key bytes, and it builds `Reflect` from
    /// them exactly as `karstd` will.
    fn request(key_bytes: [u8; REFLECT_KEY_LEN], tx: TxId) -> Vec<u8> {
        let key = DiscoKey::new(key_bytes);
        Message::Reflect { tx }.encode(&key, &key.reflect_tag(), 0)
    }

    #[test]
    fn a_reflect_is_answered_with_the_source_address() {
        let mut r = Reflector::new(here());
        let key = r.mint(node(1), 0).expect("mint");
        let tx = TxId([7; 12]);

        let reply = r.handle(&request(key, tx), from(), 0).expect("answered");

        let decoded = msg::open(&reply, &DiscoKey::new(key)).expect("opens");
        assert_eq!(
            decoded,
            Message::Reflection {
                tx,
                observed: Endpoint(from()),
            }
        );
    }

    #[test]
    fn the_answer_is_exactly_as_large_as_the_question() {
        // §7.6's amplification factor, measured on the real pair rather than
        // asserted about the constants. A reply larger than its request makes
        // every relay in a pool a contribution to somebody else's attack.
        let mut r = Reflector::new(here());
        let key = r.mint(node(1), 0).expect("mint");
        let q = request(key, TxId([1; 12]));
        let a = r.handle(&q, from(), 0).expect("answered");
        assert_eq!(a.len(), q.len());

        // And for the wider address family, which is where an inequality
        // would actually show up.
        let mut r = Reflector::new(here());
        let key = r.mint(node(2), 0).expect("mint");
        let q = request(key, TxId([1; 12]));
        let v6: SocketAddr = "[2001:db8::1]:51820".parse().expect("addr");
        let a = r.handle(&q, v6, 0).expect("answered");
        assert_eq!(a.len(), q.len());
    }

    #[test]
    fn an_unauthenticated_datagram_gets_nothing() {
        // The property the whole amplification argument rests on: an attacker
        // without a key cannot make this service emit a single byte.
        let mut r = Reflector::new(here());
        r.mint(node(1), 0).expect("mint");

        assert_eq!(r.handle(b"", from(), 0), Err(Refused::NotForUs));
        assert_eq!(r.handle(&[0xff; 64], from(), 0), Err(Refused::NotForUs));
        // Well-formed, correctly tagged, and signed with the wrong key.
        let stranger = [0x99; REFLECT_KEY_LEN];
        assert_eq!(
            r.handle(&request(stranger, TxId([1; 12])), from(), 0),
            Err(Refused::UnknownTag)
        );
    }

    #[test]
    fn a_forged_mac_under_a_live_tag_is_refused() {
        // The tag is public once observed, so resolving one must not be the
        // same as being admitted.
        let mut r = Reflector::new(here());
        let key = r.mint(node(1), 0).expect("mint");
        let mut d = request(key, TxId([1; 12]));
        let last = d.len() - 1;
        d[last] ^= 0x01;
        assert_eq!(r.handle(&d, from(), 0), Err(Refused::BadMac));
    }

    #[test]
    fn a_reflection_replayed_at_the_reflector_is_refused() {
        // A reflector answers `Reflect` and nothing else. Without the
        // direction check, a node's own answer — authentic under the same
        // key — is a datagram the reflector holds a key for, and a service
        // that answered it would answer its own output.
        let mut r = Reflector::new(here());
        let key = r.mint(node(1), 0).expect("mint");
        let k = DiscoKey::new(key);
        let reflection = Message::Reflection {
            tx: TxId([1; 12]),
            observed: Endpoint(from()),
        }
        .encode(&k, &k.reflect_tag(), 0);
        assert_eq!(
            r.handle(&reflection, from(), 0),
            Err(Refused::WrongDirection)
        );
    }

    #[test]
    fn a_peer_space_message_is_refused_identically_whether_or_not_its_tag_is_live() {
        // A `Ping`, `Pong` or `CallMeMaybe` belongs to the §5.2 peer key
        // space, which a reflector has no part of. The type byte decides —
        // *before* the tag lookup — so the refusal cannot vary with whether
        // the reflector happens to hold that key.
        //
        // Written as an equality rather than as two `WrongDirection`
        // assertions because that is what fails when the early check is
        // removed: the `let else` below it still refuses, but it refuses
        // `UnknownTag` for a stranger and `WrongDirection` for a member, and
        // the difference is a membership oracle in the operator's metrics.
        let mut r = Reflector::new(here());
        let live = DiscoKey::new(r.mint(node(1), 0).expect("mint"));
        let stranger = DiscoKey::new([0x99; REFLECT_KEY_LEN]);

        for m in [
            Message::Ping { tx: TxId([1; 12]) },
            Message::Pong {
                tx: TxId([1; 12]),
                observed: Endpoint(from()),
            },
            Message::CallMeMaybe {
                candidates: vec![Endpoint(from())],
            },
        ] {
            let as_member = r.handle(&m.encode(&live, &live.reflect_tag(), 0), from(), 0);
            let as_stranger = r.handle(&m.encode(&stranger, &stranger.reflect_tag(), 0), from(), 0);
            assert_eq!(as_member, Err(Refused::WrongDirection), "{m:?}");
            assert_eq!(as_member, as_stranger, "{m:?} distinguishes membership");
        }
    }

    #[test]
    fn a_released_key_stops_working_immediately() {
        // §7.7: the key's lifetime is the connection. This is what makes that
        // true rather than aspirational.
        let mut r = Reflector::new(here());
        let key = r.mint(node(1), 0).expect("mint");
        assert!(r.handle(&request(key, TxId([1; 12])), from(), 0).is_ok());
        r.release(&node(1));
        assert!(r.is_empty());
        assert_eq!(
            r.handle(&request(key, TxId([2; 12])), from(), 0),
            Err(Refused::UnknownTag)
        );
    }

    #[test]
    fn reconnecting_retires_the_previous_key() {
        // A node that reconnects after a suspend must not leave its old
        // credential live: that key was authenticated by a connection that no
        // longer exists.
        let mut r = Reflector::new(here());
        let first = r.mint(node(1), 0).expect("mint");
        let second = r.mint(node(1), 0).expect("mint");
        assert_ne!(first, second);
        assert_eq!(r.len(), 1, "the old session outlived its connection");
        assert_eq!(
            r.handle(&request(first, TxId([1; 12])), from(), 0),
            Err(Refused::UnknownTag)
        );
        assert!(r.handle(&request(second, TxId([2; 12])), from(), 0).is_ok());
    }

    #[test]
    fn two_nodes_get_two_keys() {
        let mut r = Reflector::new(here());
        let a = r.mint(node(1), 0).expect("mint");
        let b = r.mint(node(2), 0).expect("mint");
        assert_ne!(a, b);
        assert_eq!(r.len(), 2);
        // And each key resolves to its own node.
        let ka = DiscoKey::new(a);
        assert_eq!(r.node_for(&ka.reflect_tag()), Some(node(1)));
    }

    #[test]
    fn a_replayed_reflect_is_bounded_by_the_rate_limit() {
        // A captured `Reflect` can be replayed forever — it is authenticated,
        // not fresh. The reply always goes to the replayer's own address, so
        // this is not a reflector at a third party; what it is is a way to
        // spend a node's allowance, and the allowance is what bounds it.
        let mut r = Reflector::new(here());
        let key = r.mint(node(1), 0).expect("mint");
        let captured = request(key, TxId([1; 12]));

        let mut answered = 0;
        for _ in 0..100 {
            if r.handle(&captured, from(), 0).is_ok() {
                answered += 1;
            }
        }
        assert_eq!(
            answered, REFLECT_BURST as usize,
            "the burst is the whole budget at t=0"
        );
        assert_eq!(
            r.handle(&captured, from(), 0),
            Err(Refused::RateLimited),
            "still spending after the burst"
        );
        // And it refills at the configured rate, not faster.
        assert!(r.handle(&captured, from(), 1_000).is_ok());
        assert_eq!(
            r.handle(&captured, from(), 1_000),
            Err(Refused::RateLimited)
        );
    }

    #[test]
    fn one_nodes_rate_limit_does_not_touch_another() {
        // Buckets are per key, so a node that spends its allowance — or an
        // attacker replaying that node's captured datagram — cannot deny the
        // service to anybody else.
        let mut r = Reflector::new(here());
        let a = r.mint(node(1), 0).expect("mint");
        let b = r.mint(node(2), 0).expect("mint");
        let qa = request(a, TxId([1; 12]));
        // Bounded rather than `while ... is_ok()`. Draining with an unbounded
        // loop makes *removing the rate limit* hang the suite instead of
        // failing it, and a test that hangs in CI is worse than one that
        // fails: the failure has no message and the run has no end.
        for _ in 0..=REFLECT_BURST {
            let _ = r.handle(&qa, from(), 0);
        }
        assert_eq!(
            r.handle(&qa, from(), 0),
            Err(Refused::RateLimited),
            "node 1 was not drained, so this proves nothing about node 2"
        );
        assert!(r.handle(&request(b, TxId([2; 12])), from(), 0).is_ok());
    }

    #[test]
    fn the_advertised_endpoint_round_trips_through_the_wire_encoding() {
        // `ReflectOffer` carries this, and a client that decoded it
        // differently would send `Reflect` into the void with nothing to
        // explain the silence.
        for a in ["203.0.113.7:3478", "[2001:db8::1]:3478"] {
            let addr: SocketAddr = a.parse().expect("addr");
            let r = Reflector::new(addr);
            let wire = r.wire_endpoint();
            assert_eq!(Endpoint::from_wire(&wire).expect("decodes").0, addr);
        }
    }

    #[test]
    fn a_key_is_not_printed_by_debug() {
        let mut r = Reflector::new(here());
        r.mint(node(1), 0).expect("mint");
        let rendered = format!("{r:?}");
        assert!(rendered.contains("sessions"), "{rendered}");
        assert!(!rendered.contains("key"), "{rendered}");
    }
}
