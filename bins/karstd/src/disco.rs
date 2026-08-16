// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! AVEN on the datapath socket — `spec/aven-v1.md` §4.
//!
//! Path discovery shares the node's UDP socket with PHREATIC, and must: a path
//! is only useful if it is the one PHREATIC will actually take, and a NAT
//! binding proven on one port says nothing about another.
//!
//! So every arriving datagram belongs to one of two protocols and something has
//! to decide which. [`Disco::inbound`] is that decision, and it sits *in front*
//! of the PHREATIC engine rather than inside it — the data plane is untouched
//! by this file, which is the smallest blast radius available for a change on
//! the receive path.
//!
//! # Why the magic is only a hint
//!
//! `phreatic-v1.md` §5 begins every datagram with `reassembly_id`, drawn from a
//! CSPRNG. So roughly one PHREATIC datagram in 2³² starts with AVEN's magic by
//! chance, and a demultiplexer that trusted the magic would drop one datagram a
//! day on a busy node — a lost fragment, a retried handshake, and nothing in
//! any log to explain it.
//!
//! Reserved bits are no better: `phreatic-v1.md` §2 makes them **ignored on
//! receipt rather than rejected**, deliberately, so no bit pattern makes a
//! datagram invalid PHREATIC.
//!
//! What actually separates the two protocols is that both are authenticated.
//! [`Verdict::NotAven`] is returned whenever AVEN cannot *authenticate* the
//! datagram, not merely when the magic is absent, and the caller then offers it
//! to PHREATIC where a genuine one will pass its own MAC.

use std::collections::HashMap;
use std::net::SocketAddr;

use karst_disco::consts::{MAGIC, TAG_LEN};
use karst_disco::key::PeerIndex;
use karst_disco::msg::{self, Endpoint, Message, TxId};
use karst_disco::path::PongOutcome;
use karst_disco::{DiscoKey, Engine, TagTable};

/// What to do with an arriving datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// AVEN authenticated it and handled it. Any reply is here.
    Handled(Vec<(Vec<u8>, SocketAddr)>),
    /// Not ours. Offer it to PHREATIC.
    ///
    /// Covers a datagram without the magic, one that fails to parse, one whose
    /// tag names no peer we hold a key for, and one whose MAC does not verify.
    /// The last two are deliberately not distinguished: `spec/aven-v1.md` §10
    /// makes every failure a silent drop, because saying which would make a
    /// node an oracle for the peers it holds keys for.
    NotAven,
}

/// One peer's discovery state.
struct Peer {
    key: DiscoKey,
    /// The tag *we* present to this peer, for the current epoch.
    our_tag: [u8; TAG_LEN],
    engine: Engine,
}

/// Path discovery for every peer this node holds a disco key for.
///
/// Peers without one are absent from here entirely, which is
/// `spec/aven-v1.md` §5.1: no disco key means no discovery, ever, and the pair
/// stays on the relay. There is deliberately no unauthenticated mode — probing
/// without a key would let an attacker tell this node where to send its
/// traffic, which is the whole of what the protocol decides.
pub struct Disco {
    peers: Vec<Peer>,
    tags: TagTable,
    epoch: u32,
}

impl std::fmt::Debug for Disco {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counts, never keys.
        f.debug_struct("Disco")
            .field("peers", &self.peers.len())
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Disco {
    /// No peers, so nothing is discoverable — the correct starting state.
    #[must_use]
    pub fn new(epoch: u32) -> Self {
        Self {
            peers: Vec::new(),
            tags: TagTable::new(),
            epoch,
        }
    }

    /// Register a peer's disco key from the netmap.
    ///
    /// `our_id` and `their_id` are the 32-byte node ids of this node and the
    /// peer. Both tags derive from the shared key, and the sender's id is bound
    /// in so the two directions differ (§5.2).
    ///
    /// Returns `false` if the peer's tag collides with one already registered —
    /// an 8-byte birthday event, reported rather than silently overwritten
    /// because the loser would be undiscoverable for a whole epoch.
    pub fn add_peer(&mut self, key: DiscoKey, our_id: &[u8], their_id: &[u8]) -> bool {
        let their_tag = key.tag(their_id, self.epoch);
        let our_tag = key.tag(our_id, self.epoch);
        let index = PeerIndex(self.peers.len());
        if self.tags.insert(their_tag, index) {
            return false;
        }
        self.peers.push(Peer {
            key,
            our_tag,
            engine: Engine::new(),
        });
        true
    }

    /// Peers this node can discover paths to.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// The scheduler for one peer, for the caller's poll loop.
    pub fn engine_mut(&mut self, peer: PeerIndex) -> Option<&mut Engine> {
        self.peers.get_mut(peer.0).map(|p| &mut p.engine)
    }

    /// Encode an AVEN message to a peer, ready for the socket.
    #[must_use]
    pub fn encode(&self, peer: PeerIndex, msg: &Message) -> Option<Vec<u8>> {
        let p = self.peers.get(peer.0)?;
        Some(msg.encode(&p.key, &p.our_tag, self.epoch))
    }

    /// Decide whether a datagram is AVEN's, and handle it if so.
    ///
    /// The two-step receive of §5.2: [`msg::peek`] reads the tag without
    /// authenticating, one map lookup finds the peer, and then exactly one MAC
    /// is verified. Trying every peer's key instead would be a work amplifier
    /// any unauthenticated source could pull — 200× at 200 peers.
    pub fn inbound(&mut self, datagram: &[u8], from: SocketAddr, now_ms: u64) -> Verdict {
        // Cheap reject first, so a PHREATIC datagram costs a four-byte compare
        // and not a parse.
        if datagram.first_chunk::<4>() != Some(&MAGIC) {
            return Verdict::NotAven;
        }
        let Ok(header) = msg::peek(datagram) else {
            return Verdict::NotAven;
        };
        // An epoch we are not holding keys for. Not an error: §12.2 leaves the
        // rotation overlap unwritten, and until it is written a mismatched
        // epoch is simply not ours.
        if header.epoch != self.epoch {
            return Verdict::NotAven;
        }
        let Some(index) = self.tags.get(&header.tag) else {
            return Verdict::NotAven;
        };
        let Some(peer) = self.peers.get_mut(index.0) else {
            return Verdict::NotAven;
        };
        let Ok(message) = msg::open(datagram, &peer.key) else {
            // Includes a MAC failure, which is where a PHREATIC datagram that
            // collided with the magic ends up. Falling through is what stops
            // that collision from being a dropped packet.
            return Verdict::NotAven;
        };

        let mut out = Vec::new();
        match message {
            Message::Ping { tx } => {
                // §7.4, the rule ProVerif produced: answer each transaction id
                // at most once, or a captured Ping replayed from anywhere makes
                // this node a reflector.
                if peer.engine.paths_mut().on_ping_received(tx) {
                    let pong = Message::Pong {
                        tx,
                        observed: Endpoint(from),
                    };
                    let bytes = pong.encode(&peer.key, &peer.our_tag, self.epoch);
                    out.push((bytes, from));
                }
            }
            Message::Pong { tx, observed } => {
                // §7.1: the endpoint confirmed is the one the Ping was sent to,
                // which `on_pong` knows and `from` does not enter into.
                let engine = &mut peer.engine;
                if let PongOutcome::Confirmed { addr, .. } = engine.paths_mut().on_pong(tx, now_ms)
                {
                    engine.on_confirmed(addr);
                    let _ = engine.paths_mut().select(now_ms);
                }
                // `observed` is ours as seen by the peer — a candidate to
                // advertise, never a path to ourselves (§7.2).
                let _ = observed;
            }
            Message::CallMeMaybe { candidates } => {
                let _ = peer.engine.on_call_me_maybe(&candidates, now_ms);
            }
        }
        Verdict::Handled(out)
    }

    /// Drive every peer's scheduler and encode what it asks for.
    pub fn poll(
        &mut self,
        now_ms: u64,
        mut mint: impl FnMut() -> TxId,
    ) -> Vec<(Vec<u8>, SocketAddr)> {
        let mut out = Vec::new();
        for peer in &mut self.peers {
            // A path can become stale without another packet arriving. Run
            // selection on every timer tick so a dead direct path is released
            // instead of being kept forever.
            let _ = peer.engine.paths_mut().select(now_ms);
            for action in peer.engine.poll(now_ms, &mut mint) {
                match action {
                    karst_disco::Action::Probe { addr, tx } => {
                        let bytes =
                            Message::Ping { tx }.encode(&peer.key, &peer.our_tag, self.epoch);
                        out.push((bytes, addr));
                    }
                    // Carried over the relay rather than the datapath socket
                    // (§7.3), so it is not a datagram this loop can send. The
                    // relay client is not wired yet; see PLAN.md Phase 4.
                    karst_disco::Action::Advertise { .. } => {}
                }
            }
        }
        out
    }

    /// Which peers have a usable direct path, for the datapath to prefer.
    #[must_use]
    pub fn chosen_paths(&self) -> HashMap<usize, SocketAddr> {
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.engine.paths().chosen().map(|a| (i, a)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::indexing_slicing
    )]

    use super::*;
    use karst_disco::consts::KEY_LEN;

    const OUR_ID: &[u8] = b"our-node-id-32-bytes-long-xxxxxx";
    const THEIR_ID: &[u8] = b"their-node-id-32-bytes-long-xxxx";

    fn addr(a: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, a], 51820))
    }

    fn with_peer() -> (Disco, DiscoKey) {
        let mut d = Disco::new(7);
        let key = DiscoKey::new([0x11; KEY_LEN]);
        assert!(d.add_peer(key.clone(), OUR_ID, THEIR_ID));
        (d, key)
    }

    /// Build a datagram as the *peer* would: their tag, our shared key.
    fn from_peer(key: &DiscoKey, msg: &Message, epoch: u32) -> Vec<u8> {
        let their_tag = key.tag(THEIR_ID, epoch);
        msg.encode(key, &their_tag, epoch)
    }

    #[test]
    fn a_ping_from_a_known_peer_is_answered() {
        let (mut d, key) = with_peer();
        let ping = from_peer(&key, &Message::Ping { tx: TxId([3; 12]) }, 7);

        let Verdict::Handled(out) = d.inbound(&ping, addr(9), 1_000) else {
            panic!("a known peer's Ping was not handled");
        };
        assert_eq!(out.len(), 1);
        let (bytes, to) = &out[0];
        assert_eq!(*to, addr(9));

        // And it is a Pong reporting the address we saw — §7.2's reflexive
        // function, which is what lets a peer learn its own mapped address.
        let decoded = msg::open(bytes, &key).expect("our own Pong decodes");
        assert_eq!(
            decoded,
            Message::Pong {
                tx: TxId([3; 12]),
                observed: Endpoint(addr(9)),
            }
        );
    }

    #[test]
    fn a_replayed_ping_is_not_answered_twice() {
        // §7.4. Without this a captured Ping replayed from any address turns
        // this node into a reflector.
        let (mut d, key) = with_peer();
        let ping = from_peer(&key, &Message::Ping { tx: TxId([3; 12]) }, 7);

        assert!(matches!(d.inbound(&ping, addr(9), 1_000), Verdict::Handled(o) if o.len() == 1));
        // Replayed from somewhere else entirely, which is the attack.
        assert!(matches!(d.inbound(&ping, addr(200), 1_100), Verdict::Handled(o) if o.is_empty()));
    }

    #[test]
    fn a_datagram_without_the_magic_goes_to_phreatic() {
        let (mut d, _) = with_peer();
        let phreatic = [0x9a; 200];
        assert_eq!(d.inbound(&phreatic, addr(9), 0), Verdict::NotAven);
    }

    #[test]
    fn a_phreatic_datagram_that_collides_with_the_magic_falls_through() {
        // The one-in-2^32 case. `reassembly_id` is CSPRNG-drawn, so this
        // happens; if the demultiplexer dropped it, a node would lose a
        // fragment roughly once a day with nothing in any log to explain it.
        let (mut d, _) = with_peer();
        let mut collided = vec![0u8; 200];
        collided[..4].copy_from_slice(&MAGIC);
        assert_eq!(d.inbound(&collided, addr(9), 0), Verdict::NotAven);
    }

    #[test]
    fn a_tag_we_hold_no_key_for_falls_through() {
        // §10: indistinguishable from a MAC failure, so a caller cannot use
        // this node as an oracle for which peers it holds keys for.
        let mut d = Disco::new(7);
        let stranger = DiscoKey::new([0x99; KEY_LEN]);
        let ping = from_peer(&stranger, &Message::Ping { tx: TxId([1; 12]) }, 7);
        assert_eq!(d.inbound(&ping, addr(9), 0), Verdict::NotAven);
    }

    #[test]
    fn another_peers_key_does_not_authenticate() {
        let (mut d, key) = with_peer();
        // Right tag, wrong key: the tag is public-ish, the MAC is not.
        let wrong = DiscoKey::new([0x22; KEY_LEN]);
        let their_tag = key.tag(THEIR_ID, 7);
        let ping = Message::Ping { tx: TxId([1; 12]) }.encode(&wrong, &their_tag, 7);
        assert_eq!(d.inbound(&ping, addr(9), 0), Verdict::NotAven);
    }

    #[test]
    fn an_empty_peer_set_discovers_nothing() {
        // §5.1: no disco key means no discovery, and the pair stays on the
        // relay. An absent value must never read as permissive.
        let mut d = Disco::new(7);
        assert_eq!(d.peer_count(), 0);
        let key = DiscoKey::new([0x11; KEY_LEN]);
        let ping = from_peer(&key, &Message::Ping { tx: TxId([1; 12]) }, 7);
        assert_eq!(d.inbound(&ping, addr(9), 0), Verdict::NotAven);
    }

    #[test]
    fn a_datagram_from_another_epoch_falls_through() {
        let (mut d, key) = with_peer();
        let ping = from_peer(&key, &Message::Ping { tx: TxId([1; 12]) }, 6);
        assert_eq!(d.inbound(&ping, addr(9), 0), Verdict::NotAven);
    }

    #[test]
    fn a_pong_confirms_the_probed_endpoint_not_its_source() {
        // §7.1, end to end through the demultiplexer. The Pong is delivered
        // from a *different* address than the one probed, and the path that
        // gets confirmed is still the one the Ping went to.
        let (mut d, key) = with_peer();
        let peer = PeerIndex(0);
        let mut n = 0u8;
        let mut mint = || {
            n += 1;
            TxId([n; 12])
        };

        d.engine_mut(peer)
            .expect("peer")
            .add_peer_candidate(addr(7), 0, false);
        let probes = d.poll(0, &mut mint);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].1, addr(7));

        let sent = msg::open(&probes[0].0, &key).expect("our Ping decodes");
        let Message::Ping { tx } = sent else {
            panic!("expected a Ping");
        };

        // The answer arrives from an address we never probed.
        let pong = from_peer(
            &key,
            &Message::Pong {
                tx,
                observed: Endpoint(addr(1)),
            },
            7,
        );
        assert!(matches!(
            d.inbound(&pong, addr(250), 20),
            Verdict::Handled(_)
        ));

        let confirmed: Vec<SocketAddr> = d.peers[0]
            .engine
            .paths()
            .paths()
            .iter()
            .filter(|p| p.is_usable(20))
            .map(|p| p.addr)
            .collect();
        assert_eq!(
            confirmed,
            vec![addr(7)],
            "the source address of the Pong was trusted"
        );
        assert_eq!(d.chosen_paths().get(&0), Some(&addr(7)));
    }

    #[test]
    fn a_tag_collision_keeps_the_existing_peer() {
        let (mut d, key) = with_peer();
        // Reusing the same key and sender id deterministically forces a tag
        // collision without needing a 64-bit preimage.
        assert!(!d.add_peer(key, OUR_ID, THEIR_ID));
        assert_eq!(d.peer_count(), 1);
    }

    #[test]
    fn a_call_me_maybe_produces_probes() {
        let (mut d, key) = with_peer();
        let cmm = from_peer(
            &key,
            &Message::CallMeMaybe {
                candidates: vec![Endpoint(addr(11)), Endpoint(addr(12))],
            },
            7,
        );
        assert!(matches!(d.inbound(&cmm, addr(9), 100), Verdict::Handled(_)));

        let mut n = 0u8;
        let probes = d.poll(100, || {
            n += 1;
            TxId([n; 12])
        });
        let targets: Vec<SocketAddr> = probes.iter().map(|(_, a)| *a).collect();
        assert!(targets.contains(&addr(11)), "{targets:?}");
        assert!(targets.contains(&addr(12)), "{targets:?}");
    }

    #[test]
    fn disco_does_not_print_its_keys() {
        let (d, _) = with_peer();
        let rendered = format!("{d:?}");
        assert!(!rendered.contains("11"), "{rendered}");
        assert!(rendered.contains("peers: 1"), "{rendered}");
    }
}
