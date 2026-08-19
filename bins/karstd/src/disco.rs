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
use karst_disco::search::Search;
use karst_disco::{DiscoKey, Engine, PathKind, TagTable};

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

/// Most reflexive addresses this node will advertise at once.
///
/// A reflexive address is whatever a peer *said* it saw (§7.2), so the set is
/// attacker-influenced and has to be bounded well below the sixteen a
/// `CallMeMaybe` can carry. Four covers the real cases — one mapping per
/// address family, plus room for a NAT that rebinds — and leaves most of the
/// message for interface addresses, which no peer gets a vote on.
const REFLEXIVE_MAX: usize = 4;

/// Most reflectors this node will talk to at once.
///
/// A reflector arrives in a `ReflectOffer` on an authenticated Ponor
/// connection, so this bounds configured relays rather than an attacker — but
/// each one is a periodic datagram and a slot in the candidate list, and
/// "however many relays the netmap names" is not a number this file should
/// discover at runtime.
const REFLECTORS_MAX: usize = 4;

/// A relay's AVEN reflector, as offered over Ponor — §7.6, `ponor-v1.md` §7.7.
struct Reflector {
    /// The §5.3 reflect key, minted by the relay for this connection.
    key: DiscoKey,
    /// What we present on `Reflect`. Derived from the key, never carried
    /// beside it, so the two cannot disagree.
    tag: [u8; TAG_LEN],
    /// Where to send `Reflect`. A **UDP** address, and not the Ponor
    /// connection's: a NAT maps TCP and UDP separately, so the address a relay
    /// sees on its TCP connection is not the one AVEN needs.
    endpoint: SocketAddr,
    /// Transaction ids sent and not yet answered, with when each went out.
    ///
    /// §7.1 applies here unchanged: a `Reflection` is accepted only against a
    /// `Reflect` this node actually sent, and each id at most once. Bounded,
    /// because these are entries a stalled reflector would otherwise
    /// accumulate one per interval forever.
    outstanding: HashMap<TxId, u64>,
    /// The address this reflector last reported seeing us at.
    observed: Option<SocketAddr>,
    /// When a `Reflect` last went out, so §7.5's interval can be kept.
    last_ms: Option<u64>,
}

/// Order addresses by how many parties reported them, dropping any this node
/// already holds as an interface address — §7.2's counting rule.
///
/// Shared by the two reflexive tiers because it is the same argument twice: a
/// node behind one NAT hears the same mapping from everyone that can see it, so
/// agreement is evidence and a single liar is outvoted. The tie-break is the
/// address itself rather than iteration order, so the list a node sends does not
/// vary between runs on identical inputs.
fn rank(votes: HashMap<SocketAddr, usize>, interfaces: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut ranked: Vec<(SocketAddr, usize)> = votes
        .into_iter()
        .filter(|(addr, _)| !interfaces.contains(addr))
        .collect();
    ranked.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.to_string().cmp(&b.0.to_string()))
    });
    ranked.into_iter().map(|(a, _)| a).collect()
}

/// One peer's discovery state.
struct Peer {
    key: DiscoKey,
    route_index: usize,
    /// The peer's Ponor node id, for addressing a relayed `CallMeMaybe`.
    their_id: [u8; 32],
    /// The tag *we* present to this peer, for the current epoch.
    our_tag: [u8; TAG_LEN],
    engine: Engine,
    /// The endpoint the datapath currently holds for this peer, as far as
    /// discovery is concerned.
    ///
    /// Seeded from the netmap at reconcile rather than left empty, because the
    /// netmap-configured endpoint *is* what the datapath is using — and a
    /// discovery layer that did not know that could never withdraw it. That was
    /// finding 15: a published address that had gone stale pre-empted the relay
    /// forever, because nothing owned it.
    installed: Option<SocketAddr>,
    /// The address this peer most recently reported seeing us at — §7.2.
    ///
    /// One slot per peer, deliberately: this is the peer's claim about us, and
    /// a peer that lies should cost one vote rather than fill the list.
    reflexive: Option<SocketAddr>,
    /// §7.7's port search, once the ordinary backoff has failed.
    ///
    /// `None` until then and again once a path is confirmed, because the search
    /// is the expensive fallback and holding one open for a peer that is
    /// already direct would keep its scratch sockets alive for nothing.
    search: Option<Search>,
}

/// What one poll of discovery wants put on the wire.
///
/// Two transports, because AVEN uses two. Probes go on the shared UDP socket,
/// which is the whole point — a NAT binding proven on one port says nothing
/// about another. Candidate advertisements go over the relay (§7.3), which is
/// what makes simultaneous open possible: both ends learn each other's
/// candidates at nearly the same moment.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outbound {
    /// AVEN datagrams for the shared UDP socket.
    pub datagrams: Vec<(Vec<u8>, SocketAddr)>,
    /// Encoded `CallMeMaybe` messages, each addressed by Ponor node id.
    pub relayed: Vec<([u8; 32], Vec<u8>)>,
    /// §7.7 scratch datagrams, each tagged with the peer's route index: every
    /// one must leave from a **fresh** socket, which is then kept open.
    ///
    /// Separate from `datagrams` because the difference is the whole mechanism.
    /// A scratch datagram exists to earn one distinct external mapping toward
    /// the peer, so sending several from one socket earns one mapping and
    /// wastes the rest — and the caller cannot tell which is which from the
    /// address alone, since every one of them goes to the same place.
    pub scratch: Vec<(usize, Vec<u8>, SocketAddr)>,
}

/// A change the datapath must make to one peer's endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChange {
    /// A direct path was confirmed. Install it.
    Install {
        /// Roster index of the peer.
        peer: usize,
        /// The confirmed endpoint.
        endpoint: SocketAddr,
    },
    /// Discovery has given up on every path to this peer. Withdraw the one the
    /// datapath holds, so it falls back to the relay.
    ///
    /// Carries what was installed because the datapath must not clobber an
    /// endpoint some other writer has since put there — see
    /// [`crate::engine::Engine::release_endpoint`].
    ///
    /// **There is no revert target, and that is the rule.** An earlier version
    /// reverted an AVEN-confirmed path to the netmap-configured endpoint, which
    /// only made sense while that endpoint was exempt from discovery. It is not:
    /// it is a candidate like any other, so by the time this fires it has been
    /// probed and given up on too. Reverting to it would hand the datapath an
    /// address discovery had just finished disproving.
    Release {
        /// Roster index of the peer.
        peer: usize,
        /// The endpoint this node installed and is now withdrawing.
        installed: SocketAddr,
    },
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
    /// Raw Ponor node ids, resolved only for relay-delivered AVEN messages.
    /// The AVEN tag finds a key cheaply; this second binding makes sure the
    /// relay-stamped source names the very same peer.
    relay_peers: HashMap<[u8; 32], PeerIndex>,
    epoch: u32,
    /// This node's own interface addresses, as last enumerated. Kept so a
    /// reflexive address learned from a `Pong` can be folded in without
    /// re-reading the host's interfaces.
    interfaces: Vec<SocketAddr>,
    /// An explicit external mapping the node's own gateway installed, when it
    /// has one.
    explicit_mapping: Option<SocketAddr>,
    /// Reflectors offered over Ponor, by relay node id — §7.6.
    ///
    /// Keyed by relay so a reconnect replaces its own entry: a relay mints a
    /// fresh key per connection (`ponor-v1.md` §7.7), and keeping the old one
    /// alongside would mean probing a reflector that has already forgotten us.
    reflectors: HashMap<[u8; 32], Reflector>,
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
            relay_peers: HashMap::new(),
            epoch,
            interfaces: Vec::new(),
            explicit_mapping: None,
            reflectors: HashMap::new(),
        }
    }

    /// Record the mapped external address this node's gateway is holding open.
    ///
    /// Unlike a reflexive address, this is not a side effect of other traffic:
    /// the gateway reserved the port for this node deliberately. It is still a
    /// candidate rather than a path — §7.2's rule is unchanged — but among the
    /// reported addresses it is the strongest evidence this node can get about
    /// itself.
    pub fn set_explicit_mapping(&mut self, mapping: Option<SocketAddr>) {
        if self.explicit_mapping == mapping {
            return;
        }
        self.explicit_mapping = mapping;
        self.republish();
    }

    /// Record the reflector a relay offered — `ponor-v1.md` §7.7.
    ///
    /// Replaces any previous offer from the same relay, because the key's
    /// lifetime is the Ponor connection and a reconnect mints a new one.
    ///
    /// Returns whether it was accepted. A node past [`REFLECTORS_MAX`] refuses
    /// further offers rather than evicting: the ones it holds are working, and
    /// swapping a live reflector for a new one on every netmap change would
    /// discard the reports §7.2's counting rule depends on.
    pub fn set_reflector(
        &mut self,
        relay_id: [u8; 32],
        key: [u8; 32],
        endpoint: SocketAddr,
    ) -> bool {
        if !self.reflectors.contains_key(&relay_id) && self.reflectors.len() >= REFLECTORS_MAX {
            return false;
        }
        let key = DiscoKey::new(key);
        let tag = key.reflect_tag();
        self.reflectors.insert(
            relay_id,
            Reflector {
                key,
                tag,
                endpoint,
                outstanding: HashMap::new(),
                observed: None,
                last_ms: None,
            },
        );
        // The address this relay used to report is gone with its key, so the
        // list may have changed even though nothing was learned yet.
        self.republish();
        true
    }

    /// Forget a relay's reflector, and any address it had reported.
    ///
    /// Called when the Ponor connection drops. The key is dead at the relay the
    /// moment that happens (`ponor-v1.md` §7.7), so continuing to send
    /// `Reflect` to it would be talking to something that will never answer —
    /// and continuing to *advertise* what it last said would be offering peers
    /// a mapping nothing is keeping alive.
    pub fn clear_reflector(&mut self, relay_id: &[u8; 32]) {
        if self.reflectors.remove(relay_id).is_some() {
            self.republish();
        }
    }

    /// How many reflectors this node currently holds a key for.
    #[must_use]
    pub fn reflectors(&self) -> usize {
        self.reflectors.len()
    }

    /// The addresses reflectors have reported, most-reported first — §7.2.
    fn reflected(&self) -> Vec<SocketAddr> {
        let mut votes: HashMap<SocketAddr, usize> = HashMap::new();
        for r in self.reflectors.values() {
            if let Some(addr) = r.observed {
                *votes.entry(addr).or_default() += 1;
            }
        }
        rank(votes, &self.interfaces)
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
        self.add_peer_at(key, our_id, their_id, self.peers.len(), None)
    }

    fn add_peer_at(
        &mut self,
        key: DiscoKey,
        our_id: &[u8],
        their_id: &[u8],
        route_index: usize,
        installed: Option<SocketAddr>,
    ) -> bool {
        // Before the tag is registered, not after: a peer rejected here must
        // leave no entry in the table, or the tag resolves to an index with no
        // peer behind it.
        let Some(id) = their_id.first_chunk::<32>().copied() else {
            return false;
        };
        let their_tag = key.tag(their_id, self.epoch);
        let our_tag = key.tag(our_id, self.epoch);
        let index = PeerIndex(self.peers.len());
        if self.tags.insert(their_tag, index) {
            return false;
        }
        // Registered here rather than by the caller, so a peer is never half
        // added: every peer that can be found by its AVEN tag can also be found
        // by the node id a relay stamps on its frames, and the two always name
        // the same slot.
        self.relay_peers.insert(id, index);
        self.peers.push(Peer {
            search: None,
            key,
            route_index,
            their_id: id,
            our_tag,
            engine: Engine::new(),
            installed,
            reflexive: None,
        });
        true
    }

    /// Replace this node's own interface addresses.
    ///
    /// `addresses` comes from [`karst_tun::local_addresses`] with the node's
    /// overlay addresses already removed — advertising a tunnel address as a
    /// way to reach the tunnel is a loop. `port` is the port the datapath
    /// socket is actually bound to, which is not always the configured one: a
    /// node listening on port 0 gets an ephemeral port, and advertising 0 would
    /// name nothing.
    pub fn set_interfaces(&mut self, addresses: &[std::net::IpAddr], port: u16) {
        let mut next: Vec<SocketAddr> = addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        next.sort_by_key(|a| (a.is_ipv6(), a.ip().to_string(), a.port()));
        next.dedup();
        if next == self.interfaces {
            return;
        }
        self.interfaces = next;
        self.republish();
    }

    /// The candidate list this node advertises, in the order it is offered.
    ///
    /// **Explicit mappings first, then interface addresses, then reflexive
    /// ones**, and the ordering is the security property rather than a
    /// preference. A mapping the gateway is holding open on purpose is the
    /// strongest evidence a node can gather about itself. An interface address
    /// is something this node observed directly. A reflexive address is what a
    /// peer *claimed* it saw (§7.2). If the weaker tiers competed with the
    /// stronger on equal terms, a peer sending sixteen fabricated `observed`
    /// values could push every real address out of the list this node sends to
    /// *everybody else*.
    ///
    /// Among reflexive addresses, the most-reported wins. A node behind one NAT
    /// hears the same mapped address from every peer that answers it, so a
    /// single peer lying is outvoted by the ones telling the truth — and where
    /// there is only one peer there is nothing to cross-check against anyway,
    /// which is why the count decides the order rather than admission.
    ///
    /// **Four tiers, which are four grades of evidence.** An explicit mapping
    /// is the node's gateway naming the port it is keeping open on purpose. An
    /// interface address is something this node observed directly. A
    /// reflector's report (§7.6) comes from a relay the netmap named and this
    /// node already trusts to carry its traffic. A peer's `Pong.observed`
    /// comes from a party §1.1 explicitly allows to be malicious. The ordering
    /// is that ranking, and nothing else decides it.
    ///
    /// A reflector's address is not listed again under the peer tier. It is one
    /// address; spending two of sixteen slots on it would cost a real
    /// candidate for no information.
    fn candidates(&self) -> Vec<Endpoint> {
        let reflected = self.reflected();

        let mut votes: HashMap<SocketAddr, usize> = HashMap::new();
        for peer in &self.peers {
            if let Some(addr) = peer.reflexive {
                *votes.entry(addr).or_default() += 1;
            }
        }
        let from_peers: Vec<SocketAddr> = rank(votes, &self.interfaces)
            .into_iter()
            // A reflector already said this, and it is the better witness.
            // Listing it twice would spend two of sixteen slots on one address.
            .filter(|a| !reflected.contains(a))
            .collect();

        let mut ordered = Vec::new();
        let mut push = |addr: SocketAddr| {
            if !ordered.contains(&addr) {
                ordered.push(addr);
            }
        };
        if let Some(mapped) = self.explicit_mapping {
            push(mapped);
        }
        for addr in self.interfaces.iter().copied() {
            push(addr);
        }
        for addr in reflected.into_iter().take(REFLEXIVE_MAX) {
            push(addr);
        }
        for addr in from_peers.into_iter().take(REFLEXIVE_MAX) {
            push(addr);
        }

        ordered
            .into_iter()
            .take(karst_disco::consts::MAX_CANDIDATES)
            .map(Endpoint)
            .collect()
    }

    /// Push the current candidate list to every peer's scheduler.
    ///
    /// `set_local_candidates` schedules an advertisement only when the list
    /// actually changed, so calling this on every recomputation is free when
    /// nothing moved — and a node that re-enumerates its interfaces every
    /// second must not turn that into a `CallMeMaybe` every second.
    fn republish(&mut self) {
        let candidates = self.candidates();
        for peer in &mut self.peers {
            peer.engine.set_local_candidates(candidates.clone());
        }
    }

    /// Withdraw every endpoint this node installed, against the roster they
    /// were installed on.
    ///
    /// A netmap replaces the roster, and a roster index names a different peer
    /// afterwards. So the releases have to be issued *before* the swap, or the
    /// alternative is a `reconcile` that silently forgets it ever installed
    /// anything and leaves the old addresses on the datapath for good — the
    /// same defect this type's transitions exist to prevent, re-entering
    /// through reconfiguration.
    pub fn release_all(&mut self) -> Vec<PathChange> {
        let mut out = Vec::new();
        for peer in &mut self.peers {
            if let Some(installed) = peer.installed.take() {
                out.push(PathChange::Release {
                    peer: peer.route_index,
                    installed,
                });
            }
        }
        out
    }

    /// Replace discovery state from the current control-plane roster.
    ///
    /// A netmap replaces pair keys and peer handles atomically, so retaining a
    /// prior candidate under a new roster would bind it to the wrong identity.
    /// Starting fresh is conservative: configured endpoints are reintroduced
    /// as unconfirmed candidates, while relay-delivered candidates arrive via
    /// `CallMeMaybe` once the relay client is connected.
    ///
    /// **A configured endpoint is adopted, not merely probed.** Discovery
    /// records it as the endpoint the datapath is already holding, which is
    /// what gives it the standing to withdraw it later. Probing an address
    /// nobody owns produces a measurement and no consequence — that was
    /// finding 15.
    pub fn reconcile(&mut self, config: &crate::config::Config, now_ms: u64) {
        self.peers.clear();
        self.tags = TagTable::new();
        self.relay_peers.clear();
        self.epoch = config.psk_epoch;
        let Some(our_id) = std::str::from_utf8(&config.node_id)
            .ok()
            .and_then(karst_control_client::handle_bytes)
        else {
            return;
        };
        for (route_index, peer) in config.peers.iter().enumerate() {
            let (Some(raw_key), false) = (peer.disco_key, peer.node_id.is_empty()) else {
                continue;
            };
            let Some(their_id) = std::str::from_utf8(&peer.node_id)
                .ok()
                .and_then(karst_control_client::handle_bytes)
            else {
                eprintln!(
                    "karstd: AVEN peer {} has an invalid control handle; discovery disabled",
                    peer.name
                );
                continue;
            };
            let key = DiscoKey::new(raw_key);
            if !self.add_peer_at(key, &our_id, &their_id, route_index, peer.endpoint) {
                eprintln!(
                    "karstd: AVEN tag collision for peer {}; discovery disabled",
                    peer.name
                );
                continue;
            }
            if let Some(endpoint) = peer.endpoint {
                let index = PeerIndex(self.peers.len() - 1);
                if let Some(engine) = self.engine_mut(index) {
                    engine.add_peer_candidate(endpoint, now_ms, true);
                }
            }
        }
        // Every peer here is new, so each starts with an empty candidate list
        // and would otherwise never advertise until this node's interfaces next
        // changed — which on a stable host is never.
        self.republish();
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
        // §5.3: the reflect tag is tested **before** the peer table. The two
        // key spaces are disjoint by construction — different labels, different
        // provenance — and the type byte says which one a datagram belongs to
        // before any key is tried.
        if header.is_reflect() {
            return self.inbound_reflection(datagram, header.tag);
        }
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
        let mut republish = false;
        match message {
            Message::Ping { tx } => {
                // **Where it came from is a candidate.** An authenticated probe
                // arriving from an address is the best evidence there is that
                // the address reaches this peer — better than a `CallMeMaybe`,
                // which is a claim, because this datagram actually made the
                // journey.
                //
                // It is a *candidate*, not a path: confirming it still takes
                // this node's own `Ping` and the `Pong` that answers it, so §7.1
                // is untouched. That distinction is the whole safety argument —
                // a peer that lies here spends probes and nothing else.
                //
                // Without this, discovery is asymmetric in a way that only two
                // real daemons showed: the node that probes first confirms a
                // path and stops advertising, and the node that answered is
                // left with no candidate to probe and no one telling it any.
                peer.engine.add_peer_candidate(from, now_ms, false);
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
                } else if let Some(addr) = peer.search.as_ref().and_then(|s| s.answered(&tx)) {
                    // §7.7. The search's sixty-four probes per round cannot live
                    // in §7.1's outstanding table — that is capped at sixteen
                    // because it is state a peer can make this node allocate —
                    // so the search keeps its own, and a `Pong` matching it
                    // confirms exactly the port that probe went to. Still §7.1's
                    // rule: the address confirmed is the one probed, and a `tx`
                    // neither table knows confirms nothing.
                    let kind = if addr.is_ipv6() {
                        PathKind::DirectV6
                    } else {
                        PathKind::DirectV4
                    };
                    engine.paths_mut().add_candidate(addr, kind);
                    if engine.paths_mut().on_ping_sent(tx, addr, now_ms).is_ok() {
                        if let PongOutcome::Confirmed { addr, .. } =
                            engine.paths_mut().on_pong(tx, now_ms)
                        {
                            engine.on_confirmed(addr);
                        }
                    }
                    let _ = engine.paths_mut().select(now_ms);
                }
                // `observed` is ours as seen by the peer — a candidate to
                // advertise, never a path to ourselves (§7.2). Recorded in the
                // peer's own slot so a peer that lies costs one vote rather
                // than a place in everybody's candidate list.
                if peer.reflexive != Some(observed.0) {
                    peer.reflexive = Some(observed.0);
                    republish = true;
                }
            }
            Message::CallMeMaybe { candidates } => {
                // §7.3: candidate advertisements arrive over the relay until
                // a direct path is already authenticated. The disco MAC proves
                // which peer authored this message; it does *not* make an
                // arbitrary UDP source a permitted delivery path for a fresh
                // endpoint list.
                if peer.engine.paths().chosen() == Some(from) {
                    let _ = peer.engine.on_call_me_maybe(&candidates, now_ms);
                }
            }
            // Unreachable: `header.is_reflect()` returned above for exactly
            // these two, and a peer key cannot open a datagram carrying a
            // reflect type without a MAC forgery. Spelled out rather than
            // caught by a wildcard, so a new message type is a compile error
            // here instead of a silent no-op.
            Message::Reflect { .. } | Message::Reflection { .. } => {}
        }
        if republish {
            self.republish();
        }
        Verdict::Handled(out)
    }

    /// Handle a datagram in the §5.3 reflect key space.
    ///
    /// Separate from the peer path because almost nothing is shared: a
    /// different key, a different tag derivation, a zero epoch, and — the part
    /// that matters — a different rule about what the source address means.
    fn inbound_reflection(&mut self, datagram: &[u8], tag: [u8; TAG_LEN]) -> Verdict {
        // Linear over at most `REFLECTORS_MAX`. A map keyed by tag would be
        // faster and would have to be rebuilt on every offer; four comparisons
        // on a datagram that already carries the AVEN magic is not a rate
        // anything can pull on.
        let Some(r) = self.reflectors.values_mut().find(|r| r.tag == tag) else {
            return Verdict::NotAven;
        };
        let Ok(message) = msg::open(datagram, &r.key) else {
            return Verdict::NotAven;
        };
        let Message::Reflection { tx, observed } = message else {
            // A `Reflect` arriving at a node is our own request replayed back
            // at us. A node is not a reflector and must not answer it.
            return Verdict::NotAven;
        };
        // §7.1, unchanged: an answer counts only against a request this node
        // actually sent, and each transaction id at most once. Without it a
        // captured `Reflection` replayed later would overwrite a current
        // mapping with a stale one.
        if r.outstanding.remove(&tx).is_none() {
            return Verdict::NotAven;
        }
        if r.observed == Some(observed.0) {
            return Verdict::Handled(Vec::new());
        }
        r.observed = Some(observed.0);
        // On change only, so this is silent on the thirty-second refresh of a
        // stable mapping and loud on a NAT that has rebound. §10's ban is on a
        // line per *datagram*; this is a line per address.
        eprintln!("karstd: reflector reports this node at {}", observed.0);
        // A new mapped address is news for every peer, not just this relay.
        self.republish();
        Verdict::Handled(Vec::new())
    }

    /// Accept a `CallMeMaybe` carried by the authenticated Ponor relay.
    ///
    /// Relay I/O uses this explicit entrypoint instead of calling
    /// [`Self::inbound`], so an untrusted UDP source cannot accidentally gain
    /// the same authority by looking like a relay-delivered datagram.
    pub fn on_relay_call_me_maybe(
        &mut self,
        peer: PeerIndex,
        candidates: &[Endpoint],
        now_ms: u64,
    ) -> bool {
        self.engine_mut(peer)
            .is_some_and(|engine| engine.on_call_me_maybe(candidates, now_ms))
    }

    /// Accept an AVEN `CallMeMaybe` forwarded by the authenticated relay.
    ///
    /// A relay stamps the source node ID in its `RecvPacket` frame. AVEN's
    /// rotating tag independently selects the pair key. Both must resolve to
    /// the same peer before candidates are accepted; otherwise one admitted
    /// peer could replay another's authentic AVEN datagram under its own
    /// relay identity.
    pub fn inbound_from_relay(
        &mut self,
        source_id: [u8; 32],
        datagram: &[u8],
        now_ms: u64,
    ) -> bool {
        if datagram.first_chunk::<4>() != Some(&MAGIC) {
            return false;
        }
        let Ok(header) = msg::peek(datagram) else {
            return false;
        };
        if header.epoch != self.epoch {
            return false;
        }
        let (Some(index), Some(expected)) = (
            self.tags.get(&header.tag),
            self.relay_peers.get(&source_id).copied(),
        ) else {
            return false;
        };
        if index != expected {
            return false;
        }
        let Some(peer) = self.peers.get_mut(index.0) else {
            return false;
        };
        let Ok(Message::CallMeMaybe { candidates }) = msg::open(datagram, &peer.key) else {
            // Probes and Pongs are direct-path messages. A relay has no reason
            // to carry them, and accepting them would collapse the source
            // provenance distinction this method exists to preserve.
            return false;
        };
        eprintln!(
            "karstd: aven received candidates from peer {}: {:?}",
            peer.route_index,
            candidates.iter().map(|c| c.0).collect::<Vec<_>>()
        );
        peer.engine.on_call_me_maybe(&candidates, now_ms)
    }

    /// Whether any peer is still without a confirmed direct path.
    ///
    /// The condition §7.5 puts on `Reflect`, and the same one it puts on
    /// repeating `CallMeMaybe`: a node with nothing left to discover should not
    /// be talking to a reflector.
    fn wants_reflection(&self) -> bool {
        self.peers
            .iter()
            .any(|p| p.engine.paths().chosen().is_none())
    }

    /// Ask each reflector where it sees us — §7.6.
    ///
    /// Sent on the **datapath socket**, which the caller guarantees by putting
    /// these in `Outbound::datagrams` alongside the probes. That is §4's rule
    /// reaching one hop further: a mapping learned from a different socket is a
    /// mapping no peer can use, and opening one for the purpose is the obvious
    /// way to write this and the wrong one.
    fn poll_reflectors(
        &mut self,
        now_ms: u64,
        mint: &mut impl FnMut() -> TxId,
    ) -> Vec<(Vec<u8>, SocketAddr)> {
        if !self.wants_reflection() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for r in self.reflectors.values_mut() {
            // Expire first, so a reflector that has stopped answering does not
            // accumulate one entry per interval for the life of the process.
            r.outstanding.retain(|_, sent| {
                now_ms.saturating_sub(*sent) < karst_disco::consts::TX_TIMEOUT_MS
            });

            let due = r.last_ms.is_none_or(|t| {
                now_ms.saturating_sub(t) >= karst_disco::consts::REFLECT_INTERVAL_MS
            });
            if !due || r.outstanding.len() >= karst_disco::consts::MAX_OUTSTANDING {
                continue;
            }
            let tx = mint();
            r.outstanding.insert(tx, now_ms);
            r.last_ms = Some(now_ms);
            out.push((
                Message::Reflect { tx }.encode(&r.key, &r.tag, 0),
                r.endpoint,
            ));
        }
        out
    }

    /// Drive every peer's scheduler and encode what it asks for.
    pub fn poll(&mut self, now_ms: u64, mut mint: impl FnMut() -> TxId) -> Outbound {
        let mut out = Outbound {
            datagrams: self.poll_reflectors(now_ms, &mut mint),
            relayed: Vec::new(),
            scratch: Vec::new(),
        };
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
                        out.datagrams.push((bytes, addr));
                    }
                    // Over the relay, not the datapath socket (§7.3). It is
                    // encoded here, where the pair key lives, and handed to the
                    // caller addressed by Ponor node id — the relay knows
                    // nothing about AVEN and must not have to.
                    // Same arm shape as `Probe`; kept separate because the
                    // destination is a node id rather than an address.
                    karst_disco::Action::Advertise { candidates } => {
                        if candidates.is_empty() {
                            continue;
                        }
                        eprintln!(
                            "karstd: aven advertising to peer {}: {:?}",
                            peer.route_index,
                            candidates.iter().map(|c| c.0).collect::<Vec<_>>()
                        );
                        let bytes = Message::CallMeMaybe { candidates }.encode(
                            &peer.key,
                            &peer.our_tag,
                            self.epoch,
                        );
                        out.relayed.push((peer.their_id, bytes));
                    }
                }
            }

            // §7.7. Started only once the ordinary backoff has failed, and
            // dropped as soon as anything is confirmed — the scratch sockets it
            // implies are a real resource and a peer that is already direct has
            // no use for them.
            let direct = peer.engine.paths().chosen().is_some();
            if direct {
                peer.search = None;
            } else if peer.search.is_none() && Search::should_start(peer.engine.exhausted(), direct)
            {
                // Search the address the peer advertised that we could not
                // reach. The stalest candidate is as good as any: they all
                // failed, and the search varies the port rather than the host.
                // The first candidate that is not the relay. They all failed —
                // that is what `exhausted` means — and the search varies the
                // port rather than the host, so any of them names the right one.
                // Every non-relay candidate, not the first. A peer advertises
                // interface addresses beside reflexive ones and nothing here
                // can tell which a NAT will carry; the search rotates rather
                // than guesses, and guessing wrong spends every socket it has
                // on an unroutable destination.
                let toward: Vec<SocketAddr> = peer
                    .engine
                    .paths()
                    .paths()
                    .iter()
                    .filter(|p| p.kind != PathKind::Relay)
                    .map(|p| p.addr)
                    .collect();
                if !toward.is_empty() {
                    // One line when a search begins, because "did it start at
                    // all" is the first question every failure asks and the
                    // answer is otherwise invisible. §7.7 runs on a
                    // thirty-second cadence, so this is not a hot path.
                    eprintln!(
                        "karstd: aven port search starting for peer {} toward {:?}",
                        peer.route_index, toward
                    );
                    peer.search = Some(Search::new(toward));
                }
            }
            if let Some(search) = peer.search.as_mut() {
                // Re-read the candidates every poll. They grow after the search
                // starts — a reflexive address needs a `Reflect` round trip and
                // then a `CallMeMaybe` over the relay — and a search holding
                // the list it began with searches the peer's private address
                // for ever.
                search.retarget(
                    peer.engine
                        .paths()
                        .paths()
                        .iter()
                        .filter(|p| p.kind != PathKind::Relay)
                        .map(|p| p.addr)
                        .collect(),
                );
                if let Some(round) = search.poll(now_ms, &mut mint) {
                    eprintln!(
                        "karstd: aven port search peer {} round {} toward {} \
                         scratch +{} probes {}",
                        peer.route_index,
                        search.rounds(),
                        round.toward,
                        round.open_scratch,
                        round.probes.len()
                    );
                    for _ in 0..round.open_scratch {
                        let bytes = Message::Ping { tx: mint() }.encode(
                            &peer.key,
                            &peer.our_tag,
                            self.epoch,
                        );
                        out.scratch.push((peer.route_index, bytes, round.toward));
                    }
                    for (addr, tx) in round.probes {
                        let bytes =
                            Message::Ping { tx }.encode(&peer.key, &peer.our_tag, self.epoch);
                        out.datagrams.push((bytes, addr));
                    }
                }
            }
        }
        out
    }

    /// What the datapath must change since this was last asked.
    ///
    /// **Transitions, not a snapshot, and the release half is why.** A snapshot
    /// of the chosen paths can only ever say "install this"; it has no way to
    /// say a path that used to be there is gone. `PathSet::select` clears the
    /// chosen path as soon as nothing is usable — deliberately, because
    /// continuing to send into a path that has stopped answering is worse than
    /// admitting there is none — and without this the datapath would keep the
    /// dead address for the lifetime of the process.
    pub fn path_changes(&mut self) -> Vec<PathChange> {
        let mut out = Vec::new();
        for peer in &mut self.peers {
            let chosen = peer.engine.paths().chosen();
            if chosen == peer.installed {
                continue;
            }
            match (peer.installed, chosen) {
                // A confirmed path, where there was none or a different one.
                (_, Some(endpoint)) => {
                    peer.installed = Some(endpoint);
                    out.push(PathChange::Install {
                        peer: peer.route_index,
                        endpoint,
                    });
                }
                // **Only once discovery has actually given up.** Before that,
                // "nothing chosen" means "not confirmed yet" — which is the
                // state every peer is in for the second of probing that follows
                // every roster change, and withdrawing there would drop a
                // working endpoint onto the relay each time the netmap moved.
                (Some(installed), None) if peer.engine.exhausted() => {
                    peer.installed = None;
                    out.push(PathChange::Release {
                        peer: peer.route_index,
                        installed,
                    });
                }
                (Some(_) | None, None) => {}
            }
        }
        out
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

    /// Drive one peer until §7.5's backoff has given up, so §7.7 may start.
    fn exhaust_backoff(d: &mut Disco, now: &mut u64) {
        let mut n = 0u8;
        let mut mint = || {
            n = n.wrapping_add(1);
            TxId([n; 12])
        };
        // Immediately, then 100/300/900 ms, then the engine gives up.
        for step in [0u64, 100, 300, 900, 1_000] {
            *now += step;
            let _ = d.poll(*now, &mut mint);
        }
    }

    #[test]
    fn the_port_search_starts_only_after_the_ordinary_probes_give_up() {
        // §7.7. The cheap four probes cover every topology the search does not
        // and cost two orders of magnitude less, so starting early would spend
        // the budget on peers that were about to connect anyway.
        let (mut d, _key) = with_peer();
        d.engine_mut(PeerIndex(0))
            .expect("peer")
            .add_peer_candidate(addr(9), 0, true);

        let mut n = 0u8;
        let mut mint = || {
            n = n.wrapping_add(1);
            TxId([n; 12])
        };
        let first = d.poll(0, &mut mint);
        assert!(
            first.scratch.is_empty(),
            "a search began before the backoff had run"
        );

        let mut now = 0;
        exhaust_backoff(&mut d, &mut now);
        now += karst_disco::search::ROUND_INTERVAL_MS;
        let out = d.poll(now, &mut mint);
        assert!(
            !out.scratch.is_empty(),
            "the search never started once the probes were exhausted"
        );
    }

    #[test]
    fn a_round_earns_one_mapping_per_scratch_datagram_and_probes_one_host() {
        // The two halves of §7.7 have different shapes and the difference is
        // the mechanism. Every scratch datagram goes to the *same* address —
        // each from its own socket, which is what earns a distinct mapping —
        // while the probes go to one host across many ports.
        let (mut d, _key) = with_peer();
        d.engine_mut(PeerIndex(0))
            .expect("peer")
            .add_peer_candidate(addr(9), 0, true);
        let mut now = 0;
        exhaust_backoff(&mut d, &mut now);

        let mut n = 0u8;
        let mut mint = || {
            n = n.wrapping_add(1);
            TxId([n; 12])
        };
        now += karst_disco::search::ROUND_INTERVAL_MS;
        let out = d.poll(now, &mut mint);

        assert!(
            out.scratch.iter().all(|(_, _, to)| *to == addr(9)),
            "scratch datagrams must all go to the one address the peer named"
        );
        let probes: Vec<_> = out
            .datagrams
            .iter()
            .filter(|(_, to)| to.ip() == addr(9).ip())
            .collect();
        assert!(
            probes.len() > 1,
            "expected a spread of probes, got {probes:?}"
        );
        let mut ports: Vec<u16> = probes.iter().map(|(_, to)| to.port()).collect();
        ports.sort_unstable();
        ports.dedup();
        assert!(ports.len() > 1, "every probe went to the same port");
    }

    /// **The bug this test was written to catch, and did.**
    ///
    /// §7.7's sixty-four probes a round cannot live in §7.1's outstanding
    /// table, which is capped at sixteen because it is state a peer can make
    /// this node allocate. The first version of the integration pushed the
    /// probes onto the wire without recording them anywhere, so a `Pong` that
    /// answered one confirmed nothing and the search could never succeed —
    /// invisible from every unit test of the scheduler, because the scheduler
    /// was right.
    #[test]
    fn a_pong_answering_a_search_probe_confirms_the_port_it_went_to() {
        let (mut d, key) = with_peer();
        d.engine_mut(PeerIndex(0))
            .expect("peer")
            .add_peer_candidate(addr(9), 0, true);
        let mut now = 0;
        exhaust_backoff(&mut d, &mut now);
        let mut n = 0u8;
        let mut mint = || {
            n = n.wrapping_add(1);
            TxId([n; 12])
        };
        now += karst_disco::search::ROUND_INTERVAL_MS;
        let round = d.poll(now, &mut mint);
        assert!(!round.scratch.is_empty(), "search running");

        // **Answer a real probe.** The transaction id is decoded out of a
        // datagram the search actually emitted rather than guessed. A guessed
        // one confirms nothing — that is exactly the property the search's own
        // table provides — so guessing would make this pass for the wrong
        // reason.
        let (bytes, to) = round
            .datagrams
            .iter()
            .find(|(_, to)| to.ip() == addr(9).ip() && to.port() != addr(9).port())
            .expect("a search probe");
        let Ok(Message::Ping { tx }) = msg::open(bytes, &key) else {
            panic!("a search probe should be a Ping");
        };

        let pong = from_peer(
            &key,
            &Message::Pong {
                tx,
                observed: Endpoint(addr(1)),
            },
            7,
        );
        let _ = d.inbound(&pong, addr(9), now);

        // The confirmed path is the **port the probe went to**, not the
        // address the `Pong` came from — §7.1 unchanged.
        let chosen = d
            .engine_mut(PeerIndex(0))
            .expect("peer")
            .paths()
            .chosen()
            .expect("the search probe should have confirmed a path");
        assert_eq!(
            chosen, *to,
            "confirmed {chosen}, but the probe went to {to}"
        );
        assert_ne!(
            chosen,
            addr(9),
            "confirmed the advertised address rather than the searched port"
        );
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
        let probes = d.poll(0, &mut mint).datagrams;
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
        assert_eq!(
            d.path_changes(),
            vec![PathChange::Install {
                peer: 0,
                endpoint: addr(7)
            }]
        );
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
    fn a_udp_call_me_maybe_before_a_direct_path_is_ignored() {
        let (mut d, key) = with_peer();
        let cmm = from_peer(
            &key,
            &Message::CallMeMaybe {
                candidates: vec![Endpoint(addr(11)), Endpoint(addr(12))],
            },
            7,
        );
        assert!(matches!(d.inbound(&cmm, addr(9), 100), Verdict::Handled(_)));

        let probes = d.poll(100, || TxId([1; 12])).datagrams;
        assert!(
            probes.is_empty(),
            "UDP candidate advertisement was accepted"
        );
    }

    #[test]
    fn a_relay_call_me_maybe_produces_probes() {
        let (mut d, _) = with_peer();
        assert!(d.on_relay_call_me_maybe(
            PeerIndex(0),
            &[Endpoint(addr(11)), Endpoint(addr(12))],
            100,
        ));
        let mut n = 0u8;
        let probes = d.poll(100, || {
            n += 1;
            TxId([n; 12])
        });
        let targets: Vec<SocketAddr> = probes.datagrams.iter().map(|(_, a)| *a).collect();
        assert!(targets.contains(&addr(11)), "{targets:?}");
        assert!(targets.contains(&addr(12)), "{targets:?}");
    }

    #[test]
    fn a_confirmed_direct_path_may_carry_a_call_me_maybe() {
        let (mut d, key) = with_peer();
        d.engine_mut(PeerIndex(0))
            .expect("peer")
            .add_peer_candidate(addr(9), 0, false);
        let probe = d.poll(0, || TxId([1; 12])).datagrams;
        let Some((bytes, _)) = probe.first() else {
            panic!("candidate was not probed");
        };
        let Message::Ping { tx } = msg::open(bytes, &key).expect("our Ping") else {
            panic!("probe was not a Ping");
        };
        let pong = from_peer(
            &key,
            &Message::Pong {
                tx,
                observed: Endpoint(addr(9)),
            },
            7,
        );
        assert!(matches!(d.inbound(&pong, addr(9), 10), Verdict::Handled(_)));
        assert_eq!(d.peers[0].engine.paths().chosen(), Some(addr(9)));

        let cmm = from_peer(
            &key,
            &Message::CallMeMaybe {
                candidates: vec![Endpoint(addr(11))],
            },
            7,
        );
        assert!(matches!(d.inbound(&cmm, addr(9), 100), Verdict::Handled(_)));
        let targets: Vec<SocketAddr> = d
            .poll(100, || TxId([2; 12]))
            .datagrams
            .into_iter()
            .map(|(_, target)| target)
            .collect();
        assert!(targets.contains(&addr(11)), "{targets:?}");
    }

    #[test]
    fn a_relay_stamped_source_must_match_the_aven_tag_owner() {
        let (mut d, key) = with_peer();
        d.relay_peers.insert([9; 32], PeerIndex(0));
        let cmm = from_peer(
            &key,
            &Message::CallMeMaybe {
                candidates: vec![Endpoint(addr(11))],
            },
            7,
        );

        assert!(d.inbound_from_relay([9; 32], &cmm, 100));
        assert!(
            !d.inbound_from_relay([8; 32], &cmm, 1_000),
            "a relay source absent from the roster was accepted"
        );
    }

    #[test]
    fn a_relay_cannot_carry_a_probe_as_a_candidate_advertisement() {
        let (mut d, key) = with_peer();
        d.relay_peers.insert([9; 32], PeerIndex(0));
        let ping = from_peer(&key, &Message::Ping { tx: TxId([4; 12]) }, 7);
        assert!(!d.inbound_from_relay([9; 32], &ping, 100));
    }

    // ── what reaches the datapath ─────────────────────────────────────────

    /// Confirm `addr` as a direct path for peer 0 and return `Disco` holding it.
    fn with_confirmed_path(configured: Option<SocketAddr>) -> (Disco, DiscoKey) {
        let mut d = Disco::new(7);
        let key = DiscoKey::new([0x11; KEY_LEN]);
        assert!(d.add_peer_at(key.clone(), OUR_ID, THEIR_ID, 0, configured));
        d.engine_mut(PeerIndex(0))
            .expect("peer")
            .add_peer_candidate(addr(9), 0, false);

        let probe = d.poll(0, || TxId([1; 12])).datagrams;
        let Some((bytes, _)) = probe.first() else {
            panic!("candidate was not probed");
        };
        let Message::Ping { tx } = msg::open(bytes, &key).expect("our Ping") else {
            panic!("probe was not a Ping");
        };
        let pong = from_peer(
            &key,
            &Message::Pong {
                tx,
                observed: Endpoint(addr(9)),
            },
            7,
        );
        assert!(matches!(d.inbound(&pong, addr(9), 10), Verdict::Handled(_)));
        (d, key)
    }

    #[test]
    fn a_confirmed_path_is_reported_once_and_not_restated() {
        // Restating it every tick would be a write to the datapath's endpoint
        // lock a hundred times a second for a value that has not moved.
        let (mut d, _) = with_confirmed_path(None);
        assert_eq!(
            d.path_changes(),
            vec![PathChange::Install {
                peer: 0,
                endpoint: addr(9)
            }]
        );
        assert!(d.path_changes().is_empty());
        let _ = d.poll(20, || TxId([2; 12]));
        assert!(d.path_changes().is_empty(), "the same path was restated");
    }

    /// **The case the datapath had no way to hear about.** `PathSet::select`
    /// clears a path that has stopped answering; before this, only installs
    /// crossed the boundary, so the dead address stayed on the datapath for the
    /// lifetime of the process.
    #[test]
    fn a_path_that_is_given_up_on_is_withdrawn() {
        let (mut d, _) = with_confirmed_path(Some(addr(1)));
        assert_eq!(
            d.path_changes(),
            vec![PathChange::Install {
                peer: 0,
                endpoint: addr(9)
            }]
        );

        // Well past PATH_STALE_MS with no further Pong, and probed to the end
        // of §7.5's schedule, so discovery has given up rather than merely not
        // yet confirmed.
        for now in [100, 300, 900, 1_500, 200_000] {
            let _ = d.poll(now, || TxId([2; 12]));
        }
        assert_eq!(
            d.path_changes(),
            vec![PathChange::Release {
                peer: 0,
                installed: addr(9),
            }]
        );
        assert!(d.path_changes().is_empty(), "the release was repeated");
    }

    /// **Finding 15.** A netmap-configured endpoint is adopted by discovery and
    /// withdrawn like any other, so a published address that has gone stale
    /// stops pre-empting the relay. Before this it was exempt — nothing owned
    /// it, so nothing could take it away.
    #[test]
    fn a_configured_endpoint_that_never_answers_is_withdrawn() {
        let mut d = Disco::new(7);
        let key = DiscoKey::new([0x11; KEY_LEN]);
        // Adopted at reconcile: the datapath is already using addr(1).
        assert!(d.add_peer_at(key, OUR_ID, THEIR_ID, 0, Some(addr(1))));
        d.engine_mut(PeerIndex(0))
            .expect("peer")
            .add_peer_candidate(addr(1), 0, true);

        // Nothing answers. Until discovery gives up, the endpoint stands.
        let mut n = 0u8;
        let mut mint = || {
            n += 1;
            TxId([n; 12])
        };
        let _ = d.poll(0, &mut mint);
        assert!(
            d.path_changes().is_empty(),
            "the endpoint was withdrawn while it was still being probed"
        );

        for now in [100, 400, 1_300, 2_000] {
            let _ = d.poll(now, &mut mint);
        }
        assert_eq!(
            d.path_changes(),
            vec![PathChange::Release {
                peer: 0,
                installed: addr(1),
            }],
            "a configured endpoint discovery gave up on was not withdrawn"
        );
    }

    /// The other half: an endpoint that answers is kept, so the withdrawal
    /// above is a response to failure and not to the passage of time.
    #[test]
    fn a_configured_endpoint_that_answers_is_kept() {
        let (mut d, _) = with_confirmed_path(Some(addr(9)));
        // `with_confirmed_path` probes and confirms addr(9); it was also the
        // adopted endpoint, so nothing should change hands at all.
        assert!(
            d.path_changes().is_empty(),
            "a confirmed endpoint was re-reported as a change"
        );
        for now in [100, 400, 1_300, 2_000] {
            let _ = d.poll(now, || TxId([9; 12]));
        }
        assert!(
            d.path_changes().is_empty(),
            "a working endpoint was withdrawn"
        );
    }

    /// A netmap replaces the roster, and a route index names a different peer
    /// afterwards. Whatever was installed has to be withdrawn before that
    /// happens, or it is never withdrawn at all.
    #[test]
    fn a_roster_replacement_withdraws_what_was_installed() {
        let (mut d, _) = with_confirmed_path(Some(addr(1)));
        assert_eq!(d.path_changes().len(), 1);

        assert_eq!(
            d.release_all(),
            vec![PathChange::Release {
                peer: 0,
                installed: addr(9),
            }]
        );
        assert!(
            d.release_all().is_empty(),
            "the same withdrawal was issued twice"
        );
    }

    // ── candidates this node offers ───────────────────────────────────────

    fn ip(a: u8) -> std::net::IpAddr {
        std::net::IpAddr::from([198, 51, 100, a])
    }

    /// Drive one peer to a confirmed path and have it report `observed`.
    fn report_reflexive(d: &mut Disco, key: &DiscoKey, peer: u8, observed: SocketAddr, at: u64) {
        let index = PeerIndex(usize::from(peer));
        d.engine_mut(index)
            .expect("peer")
            .add_peer_candidate(addr(9), at, false);
        let probes = d.poll(at, || TxId([peer + 1; 12])).datagrams;
        let Some((bytes, _)) = probes.iter().find(|(_, to)| *to == addr(9)) else {
            panic!("candidate was not probed");
        };
        let Message::Ping { tx } = msg::open(bytes, key).expect("our Ping") else {
            panic!("probe was not a Ping");
        };
        // Encoded with the peer's own tag, which is what `from_peer` builds.
        let their_tag = key.tag(THEIR_ID, 7);
        let pong = Message::Pong {
            tx,
            observed: Endpoint(observed),
        }
        .encode(key, &their_tag, 7);
        assert!(matches!(
            d.inbound(&pong, addr(9), at + 1),
            Verdict::Handled(_)
        ));
    }

    #[test]
    fn interface_addresses_become_candidates_on_the_configured_port() {
        let (mut d, _) = with_peer();
        d.set_interfaces(&[ip(4), ip(5)], 51820);
        assert_eq!(
            d.candidates(),
            vec![
                Endpoint(SocketAddr::new(ip(4), 51820)),
                Endpoint(SocketAddr::new(ip(5), 51820)),
            ]
        );
    }

    #[test]
    fn a_reflexive_address_is_advertised_after_the_interface_ones() {
        let (mut d, key) = with_peer();
        d.set_interfaces(&[ip(4)], 51820);
        let mapped = SocketAddr::from(([203, 0, 113, 7], 40000));
        report_reflexive(&mut d, &key, 0, mapped, 1_000);

        assert_eq!(
            d.candidates(),
            vec![Endpoint(SocketAddr::new(ip(4), 51820)), Endpoint(mapped)],
            "the peer's view of us was not folded into the candidate list"
        );
    }

    /// §7.2. A reflexive address is a *claim*, and this is the node that pays
    /// for believing it — the list goes to every peer, not just the one that
    /// made the claim.
    #[test]
    fn a_lying_peer_cannot_displace_this_nodes_own_addresses() {
        let mut d = Disco::new(7);
        let key = DiscoKey::new([0x11; KEY_LEN]);
        assert!(d.add_peer(key.clone(), OUR_ID, THEIR_ID));

        let interfaces: Vec<std::net::IpAddr> = (0..16).map(ip).collect();
        d.set_interfaces(&interfaces, 51820);
        report_reflexive(
            &mut d,
            &key,
            0,
            SocketAddr::from(([192, 0, 2, 66], 9)),
            1_000,
        );

        let candidates = d.candidates();
        assert_eq!(candidates.len(), karst_disco::consts::MAX_CANDIDATES);
        assert!(
            candidates.iter().all(|c| interfaces.contains(&c.0.ip())),
            "a peer's claim displaced an address this node observed itself"
        );
    }

    /// A `Disco` holding `count` peers, each with its own key and node id.
    fn peers(count: u8) -> Disco {
        let mut d = Disco::new(7);
        for n in 0..count {
            let mut their_id = *b"their-node-id-32-bytes-long-xxxx";
            their_id[31] = n;
            assert!(d.add_peer(DiscoKey::new([0x11 + n; KEY_LEN]), OUR_ID, &their_id));
        }
        d
    }

    /// **A single peer lying is outvoted.** A node behind one NAT hears the
    /// same mapped address from every peer that answers it, so agreement is
    /// evidence and disagreement is not — which is why the count decides the
    /// order rather than who reported first.
    #[test]
    fn the_most_reported_reflexive_address_is_offered_first() {
        let truth = SocketAddr::from(([203, 0, 113, 7], 40000));
        let lie = SocketAddr::from(([192, 0, 2, 66], 9));

        let mut d = peers(3);
        // Peer 1 is the liar, and it reports first — so insertion order would
        // put its claim ahead if anything but the count decided.
        d.peers[1].reflexive = Some(lie);
        d.peers[0].reflexive = Some(truth);
        d.peers[2].reflexive = Some(truth);
        d.republish();

        assert_eq!(
            d.candidates(),
            vec![Endpoint(truth), Endpoint(lie)],
            "one peer's claim outranked the two that agreed"
        );
    }

    /// And when the list is full, being outvoted means being dropped rather
    /// than merely ranked lower.
    #[test]
    fn an_outvoted_reflexive_address_is_dropped_when_the_list_is_full() {
        let truth = SocketAddr::from(([203, 0, 113, 7], 40000));
        let lie = SocketAddr::from(([192, 0, 2, 66], 9));

        let mut d = peers(3);
        d.peers[1].reflexive = Some(lie);
        d.peers[0].reflexive = Some(truth);
        d.peers[2].reflexive = Some(truth);
        // Fifteen interface addresses leaves exactly one reflexive slot.
        let interfaces: Vec<std::net::IpAddr> = (0..15).map(ip).collect();
        d.set_interfaces(&interfaces, 51820);

        let candidates = d.candidates();
        assert_eq!(candidates.len(), karst_disco::consts::MAX_CANDIDATES);
        assert_eq!(candidates.last(), Some(&Endpoint(truth)));
        assert!(!candidates.contains(&Endpoint(lie)));
    }

    #[test]
    fn a_candidate_list_does_not_depend_on_map_iteration_order() {
        // Two addresses reported once each: nothing separates them but the
        // tie-break, so a list built from raw hash order would vary run to run
        // and every rebuild would look like a change worth advertising.
        let build = || {
            let mut d = peers(4);
            d.peers[0].reflexive = Some(SocketAddr::from(([203, 0, 113, 7], 40000)));
            d.peers[1].reflexive = Some(SocketAddr::from(([203, 0, 113, 8], 40001)));
            d.peers[2].reflexive = Some(SocketAddr::from(([203, 0, 113, 9], 40002)));
            d.peers[3].reflexive = Some(SocketAddr::from(([203, 0, 113, 10], 40003)));
            d.set_interfaces(&[ip(4)], 51820);
            d.candidates()
        };
        let first = build();
        for _ in 0..16 {
            assert_eq!(build(), first);
        }
    }

    /// The whole point of the outbound half: a node with candidates and a peer
    /// produces a `CallMeMaybe` for the relay to carry, addressed by the peer's
    /// Ponor node id.
    #[test]
    fn candidates_produce_a_relayed_call_me_maybe() {
        let (mut d, key) = with_peer();
        d.set_interfaces(&[ip(4)], 51820);

        let out = d.poll(0, || TxId([1; 12]));
        let Some((destination, payload)) = out.relayed.first() else {
            panic!("no advertisement was produced, so no peer ever learns where we are");
        };
        assert_eq!(destination, THEIR_ID, "addressed to the wrong node");

        let Ok(Message::CallMeMaybe { candidates }) = msg::open(payload, &key) else {
            panic!("the advertisement is not a decodable CallMeMaybe");
        };
        assert_eq!(candidates, vec![Endpoint(SocketAddr::new(ip(4), 51820))]);
    }

    #[test]
    fn re_enumerating_the_same_interfaces_is_not_news() {
        // A node that re-reads its interfaces every second must not turn that
        // into a `CallMeMaybe` every second.
        //
        // **Inside the repeat interval, deliberately.** A node with no direct
        // path does go on advertising — §7.5 requires it, because a peer that
        // missed the first one would otherwise never hear it (finding 19) — so
        // a poll far enough in the future would see one of those and prove
        // nothing about re-enumeration.
        let (mut d, _) = with_peer();
        d.set_interfaces(&[ip(4)], 51820);
        assert_eq!(d.poll(0, || TxId([1; 12])).relayed.len(), 1);

        d.set_interfaces(&[ip(4)], 51820);
        assert!(
            d.poll(1_000, || TxId([2; 12])).relayed.is_empty(),
            "re-enumerating the same interfaces produced a second advertisement"
        );
    }

    /// And the repeat itself, at this layer: a peer that missed the first
    /// advertisement gets another one.
    #[test]
    fn a_peer_with_no_path_is_told_again() {
        let (mut d, _) = with_peer();
        d.set_interfaces(&[ip(4)], 51820);
        assert_eq!(d.poll(0, || TxId([1; 12])).relayed.len(), 1);
        assert!(
            !d.poll(60_000, || TxId([2; 12])).relayed.is_empty(),
            "a peer that never answered was never told again"
        );
    }

    #[test]
    fn a_node_with_no_candidates_advertises_nothing() {
        // Sending an empty CallMeMaybe would spend a rendezvous saying nothing.
        let (mut d, _) = with_peer();
        assert!(d.poll(0, || TxId([1; 12])).relayed.is_empty());
    }

    /// **The asymmetry two real daemons found.** A node that only ever answers
    /// probes must still end up with a path of its own: the peer that probed
    /// first confirms one and stops advertising, so nothing else will ever tell
    /// this node where that peer is.
    #[test]
    fn an_incoming_probe_is_itself_a_candidate() {
        let (mut d, key) = with_peer();
        // No candidates, no advertisement received — this node knows nothing.
        assert!(d.poll(0, || TxId([1; 12])).datagrams.is_empty());

        let ping = from_peer(&key, &Message::Ping { tx: TxId([3; 12]) }, 7);
        assert!(matches!(
            d.inbound(&ping, addr(9), 100),
            Verdict::Handled(_)
        ));

        let probes: Vec<SocketAddr> = d
            .poll(100, || TxId([2; 12]))
            .datagrams
            .into_iter()
            .map(|(_, to)| to)
            .collect();
        assert!(
            probes.contains(&addr(9)),
            "the address a probe arrived from was not probed back: {probes:?}"
        );
    }

    #[test]
    fn disco_does_not_print_its_keys() {
        let (d, _) = with_peer();
        let rendered = format!("{d:?}");
        assert!(!rendered.contains("11"), "{rendered}");
        assert!(rendered.contains("peers: 1"), "{rendered}");
    }

    // ── the reflector — §7.6 ──────────────────────────────────────────────

    const RELAY_ID: [u8; 32] = [0xaa; 32];
    const REFLECT_KEY: [u8; 32] = [0x77; 32];

    fn reflector_addr() -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 200], 3478))
    }

    fn mapped() -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], 40000))
    }

    /// Take the one `Reflect` a poll produced and answer it as the reflector
    /// would, reporting `observed`.
    fn answer_reflect(d: &mut Disco, observed: SocketAddr, at: u64) -> Verdict {
        let out = d.poll(at, || TxId([0x42; 12]));
        let (bytes, to) = out
            .datagrams
            .iter()
            .find(|(_, to)| *to == reflector_addr())
            .expect("no Reflect was sent");
        assert_eq!(*to, reflector_addr());
        let key = DiscoKey::new(REFLECT_KEY);
        let Message::Reflect { tx } = msg::open(bytes, &key).expect("our Reflect") else {
            panic!("what was sent to the reflector was not a Reflect");
        };
        let reply = Message::Reflection {
            tx,
            observed: Endpoint(observed),
        }
        .encode(&key, &key.reflect_tag(), 0);
        // Delivered from the reflector's address, which is deliberately *not*
        // what the node reads the answer out of — the body is.
        d.inbound(&reply, reflector_addr(), at + 1)
    }

    #[test]
    fn a_reflection_becomes_a_candidate_this_node_advertises() {
        // The whole point of §7.6: a node behind a NAT has no interface
        // address any peer can reach, and this is the only way it learns one.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        assert!(d.candidates().is_empty(), "nothing is known yet");

        assert!(matches!(
            answer_reflect(&mut d, mapped(), 0),
            Verdict::Handled(_)
        ));
        assert_eq!(d.candidates(), vec![Endpoint(mapped())]);
    }

    #[test]
    fn a_reflect_goes_to_the_reflector_and_nowhere_else() {
        // §7.6 requires it on the datapath socket, which is what putting it in
        // `datagrams` means — the caller sends that list on the shared socket.
        // A mapping learned from any other socket is one no peer can use.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let out = d.poll(0, || TxId([1; 12]));
        assert!(out.relayed.is_empty(), "a Reflect went over the relay");
        assert_eq!(out.datagrams.len(), 1);
        assert_eq!(out.datagrams[0].1, reflector_addr());
        assert_eq!(
            out.datagrams[0].0.len(),
            karst_disco::consts::REFLECT_LEN,
            "not a Reflect"
        );
    }

    #[test]
    fn a_reflection_answering_no_request_is_ignored() {
        // §7.1 applied to the reflect pair. Without this a captured
        // `Reflection` replayed later overwrites a current mapping with a
        // stale one, and the node advertises an address that has moved on.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let key = DiscoKey::new(REFLECT_KEY);
        let unsolicited = Message::Reflection {
            tx: TxId([0xee; 12]),
            observed: Endpoint(mapped()),
        }
        .encode(&key, &key.reflect_tag(), 0);
        assert_eq!(
            d.inbound(&unsolicited, reflector_addr(), 0),
            Verdict::NotAven
        );
        assert!(
            d.candidates().is_empty(),
            "an unsolicited answer was believed"
        );
    }

    #[test]
    fn a_reflection_is_accepted_once_for_its_transaction_id() {
        // The other half of §7.1. Replaying the *genuine* answer must not
        // re-arm anything, or a captured pair becomes a way to pin this node's
        // advertised address after it has changed.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let out = d.poll(0, || TxId([0x42; 12]));
        let (bytes, _) = &out.datagrams[0];
        let key = DiscoKey::new(REFLECT_KEY);
        let Message::Reflect { tx } = msg::open(bytes, &key).expect("Reflect") else {
            panic!("not a Reflect");
        };
        let reply = Message::Reflection {
            tx,
            observed: Endpoint(mapped()),
        }
        .encode(&key, &key.reflect_tag(), 0);

        assert!(matches!(
            d.inbound(&reply, reflector_addr(), 1),
            Verdict::Handled(_)
        ));
        assert_eq!(
            d.inbound(&reply, reflector_addr(), 2),
            Verdict::NotAven,
            "the same transaction id was accepted twice"
        );
    }

    #[test]
    fn a_reflection_under_a_key_we_do_not_hold_falls_through() {
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let stranger = DiscoKey::new([0x01; 32]);
        let forged = Message::Reflection {
            tx: TxId([1; 12]),
            observed: Endpoint(mapped()),
        }
        .encode(&stranger, &stranger.reflect_tag(), 0);
        assert_eq!(d.inbound(&forged, reflector_addr(), 0), Verdict::NotAven);
    }

    #[test]
    fn a_node_does_not_answer_a_reflect() {
        // A node is not a reflector. Its own request replayed back at it —
        // authentic under the very key it holds — must produce nothing, or
        // every node in the aquifer is a reflector for anyone who can capture
        // one datagram.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let out = d.poll(0, || TxId([0x42; 12]));
        let ours = out.datagrams[0].0.clone();
        assert_eq!(d.inbound(&ours, reflector_addr(), 1), Verdict::NotAven);
    }

    #[test]
    fn a_reflector_address_outranks_a_peers_claim() {
        // §7.2's three tiers. A relay the netmap named is better evidence than
        // a peer §1.1 explicitly allows to be malicious — and a peer that
        // disagrees must not be able to displace it.
        let peer_claim = SocketAddr::from(([192, 0, 2, 66], 9));
        let mut d = peers(1);
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        d.peers[0].reflexive = Some(peer_claim);
        assert!(matches!(
            answer_reflect(&mut d, mapped(), 0),
            Verdict::Handled(_)
        ));

        assert_eq!(
            d.candidates(),
            vec![Endpoint(mapped()), Endpoint(peer_claim)],
            "a peer's claim outranked a reflector's report"
        );
    }

    #[test]
    fn an_interface_address_still_outranks_a_reflector() {
        // The reflector tier sits below what this node observed about itself,
        // not above it. A relay is trusted more than a peer and less than
        // direct observation.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        d.set_interfaces(&[ip(4)], 51820);
        assert!(matches!(
            answer_reflect(&mut d, mapped(), 0),
            Verdict::Handled(_)
        ));
        assert_eq!(
            d.candidates(),
            vec![Endpoint(SocketAddr::new(ip(4), 51820)), Endpoint(mapped()),]
        );
    }

    #[test]
    fn an_address_a_reflector_reported_is_not_listed_twice() {
        // A peer agreeing with the reflector is agreement, not a second
        // candidate. Listing it twice spends two of sixteen slots on one
        // address.
        let mut d = peers(1);
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        d.peers[0].reflexive = Some(mapped());
        assert!(matches!(
            answer_reflect(&mut d, mapped(), 0),
            Verdict::Handled(_)
        ));
        assert_eq!(d.candidates(), vec![Endpoint(mapped())]);
    }

    #[test]
    fn a_dropped_relay_takes_its_reflector_and_its_report_with_it() {
        // §7.7: the key dies with the connection. Continuing to advertise what
        // that relay last said would offer peers a mapping nothing is keeping
        // alive — and continuing to probe it would be talking to something
        // that has already forgotten us.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        assert!(matches!(
            answer_reflect(&mut d, mapped(), 0),
            Verdict::Handled(_)
        ));
        assert_eq!(d.candidates(), vec![Endpoint(mapped())]);

        d.clear_reflector(&RELAY_ID);
        assert_eq!(d.reflectors(), 0);
        assert!(
            d.candidates().is_empty(),
            "a dead relay's report survived it"
        );
        assert!(
            d.poll(1000, || TxId([1; 12]))
                .datagrams
                .iter()
                .all(|(_, to)| *to != reflector_addr()),
            "still probing a reflector that has forgotten us"
        );
    }

    #[test]
    fn a_reconnecting_relay_replaces_its_own_reflector() {
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        assert!(d.set_reflector(RELAY_ID, [0x33; 32], reflector_addr()));
        assert_eq!(d.reflectors(), 1, "the old connection's key outlived it");
    }

    #[test]
    fn the_number_of_reflectors_is_bounded() {
        let (mut d, _) = with_peer();
        for n in 0..REFLECTORS_MAX {
            let mut id = RELAY_ID;
            id[0] = u8::try_from(n).expect("small");
            assert!(d.set_reflector(id, [0x77; 32], reflector_addr()), "{n}");
        }
        assert!(!d.set_reflector([0xff; 32], [0x77; 32], reflector_addr()));
        assert_eq!(d.reflectors(), REFLECTORS_MAX);
    }

    #[test]
    fn reflection_stops_once_every_peer_has_a_direct_path() {
        // §7.5: the purpose is served, and a node with nothing left to
        // discover should not be talking to a reflector.
        // **Both halves, because one is not evidence.** "No `Reflect` was
        // sent" holds for any number of reasons — a broken fixture, a
        // reflector that was never registered, a poll that produced nothing at
        // all — so the same node is first shown asking, and only then shown
        // stopping.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let asked = |d: &mut Disco, t: u64| {
            d.poll(t, || TxId([1; 12]))
                .datagrams
                .iter()
                .any(|(_, to)| *to == reflector_addr())
        };
        assert!(asked(&mut d, 0), "a node with no direct path did not ask");

        let (mut d, _) = with_confirmed_path(None);
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        assert!(
            !asked(&mut d, 0),
            "a node with a direct path to every peer still asked for a reflection"
        );
    }

    #[test]
    fn reflection_repeats_on_the_interval_and_not_faster() {
        // A NAT rebinds, so a mapping learned once and never refreshed becomes
        // a candidate that *used to be* true — which is worse than none, since
        // a stale address costs an advertisement slot and a peer's probes.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let sent_at = |d: &mut Disco, t: u64| {
            d.poll(t, || TxId([1; 12]))
                .datagrams
                .iter()
                .filter(|(_, to)| *to == reflector_addr())
                .count()
        };
        assert_eq!(sent_at(&mut d, 0), 1, "nothing was asked at all");
        assert_eq!(sent_at(&mut d, 1_000), 0, "asked again a second later");
        let interval = karst_disco::consts::REFLECT_INTERVAL_MS;
        assert_eq!(sent_at(&mut d, interval), 1, "never asked again");
    }

    #[test]
    fn an_unanswered_reflector_does_not_accumulate_state() {
        // Outstanding transaction ids are entries a stalled reflector would
        // otherwise add one of per interval for the life of the process.
        let (mut d, _) = with_peer();
        assert!(d.set_reflector(RELAY_ID, REFLECT_KEY, reflector_addr()));
        let interval = karst_disco::consts::REFLECT_INTERVAL_MS;
        let mut tx = 0u8;
        for n in 0..50 {
            tx = tx.wrapping_add(1);
            let _ = d.poll(n * interval, || TxId([tx; 12]));
        }
        let held = d
            .reflectors
            .values()
            .map(|r| r.outstanding.len())
            .sum::<usize>();
        assert!(held <= 1, "{held} outstanding requests accumulated");
    }
}
