// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The datapath engine.
//!
//! Owns one [`Session`] per peer and the node-level state that sits above them:
//! reassembly, endpoint learning, and the cryptokey routing decisions.
//!
//! # Why reassembly lives here
//!
//! An inbound `HandshakeInit` cannot be attributed to a peer until it has been
//! reassembled *and* decrypted — `peer_id_hint` is inside the AEAD. So
//! reassembly must happen once, above the sessions, keyed by source address
//! rather than by peer. That is also where §9.1's budget belongs: it bounds the
//! whole node, not a peer that has not been identified yet.
//!
//! Like the crates beneath it, the engine is **sans-io**: it takes datagrams,
//! packets and a clock reading and returns [`Output`]. [`crate::run`] is what
//! owns the sockets.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use karst_crypto::kem::{Kem as _, MlKem768Backend as MlKem};
use karst_crypto::{SuiteId, SuitePolicy};
use karst_node::{Action, Session};
use karst_noise::handshake::{peer_id_hint, ResponderRandomness};
use karst_proto::dos::{mac1_key, FragMacKey};
use karst_proto::reassembly::{Accept, Config as ReasmConfig, Reassembler};
use karst_proto::{fragment, split_datagram, MessageType};
use karst_transport::source_key;

use crate::config::Config;
use crate::filter::{Direction, Verdict};
use crate::routing::PeerIndex;

/// How a datagram reaches its peer.
///
/// **The engine names a destination rather than an address**, because a peer
/// with no working direct path is not unreachable — `aven-v1.md` §8.3 makes the
/// relay a path like any other, and the last resort rather than a failure
/// state. The two arms are the two transports a node has, and which one a peer
/// gets is decided in exactly one place ([`Engine::via`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Straight to the peer on the shared UDP socket.
    Direct(SocketAddr),
    /// Through a relay, addressed by the peer's Ponor node id.
    ///
    /// The relay reads the id and forwards the payload without looking inside
    /// it: what it carries is a sealed PHREATIC datagram, and `ponor-v1.md`
    /// §1.2 is explicit that no inner layer is added because there is nothing
    /// left to protect from the relay that the payload does not already cover.
    Relay {
        /// Which relay carries it. `None` is this node's own home relay —
        /// §9.1's first rule, and the connection that is always up.
        ///
        /// `Some` names the peer's **published** home relay, §9.1's second
        /// rule: a relay this node did not choose and holds a connection to
        /// only for as long as there is traffic for it.
        relay: Option<[u8; karst_relay_proto::consts::ID_LEN]>,
        /// The peer, as the relay knows it.
        destination: [u8; karst_relay_proto::consts::ID_LEN],
    },
}

/// How long this node believes its own relay when it says a peer is not there.
///
/// Five minutes. Short enough that a peer which has since arrived on this
/// node's relay — or on its mesh — stops paying for a second connection within
/// a few minutes; long enough that a peer genuinely homed elsewhere costs one
/// probing datagram every five minutes rather than one per packet.
const HOME_RELAY_RETRY_MS: u64 = 5 * 60 * 1000;

/// A full-size PHREATIC datagram must fit one Ponor frame, or the relay path
/// would need a fragmentation layer that the direct path does not have — and
/// two reassemblers for one protocol is how they drift apart.
///
/// Asserted rather than assumed: `PAYLOAD_MAX` was sized from
/// `TRANSPORT_DATAGRAM_MAX` and the two live in different crates, so nothing
/// but this would notice if either moved.
const _: () =
    assert!(karst_proto::consts::TRANSPORT_DATAGRAM_MAX <= karst_relay_proto::consts::PAYLOAD_MAX);

/// How a peer's traffic currently leaves this node, for `karst status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Straight to the peer.
    Direct,
    /// Through the relay: working, slower, and visible to a third party.
    Relay,
    /// Nowhere. No address is known and no relay is configured, so the peer is
    /// known about and cannot be sent to.
    Unreachable,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
            Self::Unreachable => "none",
        })
    }
}

/// What the engine wants done, having processed an input.
#[derive(Debug, Default)]
pub struct Output {
    /// Datagrams to send, each with the transport that carries it.
    pub datagrams: Vec<(Vec<u8>, Via)>,
    /// Plaintext IP packets to write to the TUN device.
    pub packets: Vec<Vec<u8>>,
}

impl Output {
    /// Whether there is nothing to do.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.datagrams.is_empty() && self.packets.is_empty()
    }
}

/// Counters, for `karst status` and for tests that need to assert a packet was
/// dropped rather than merely absent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Packets from the host with no peer owning the destination.
    pub unroutable: u64,
    /// Packets from a peer whose source address that peer may not use — §13.7
    /// is about MACs, this is cryptokey routing (see [`crate::routing`]).
    pub source_violations: u64,
    /// Datagrams discarded by the fragment MAC before any state was touched.
    pub mac_failures: u64,
    /// Packets encrypted and sent.
    pub tx_packets: u64,
    /// Packets decrypted and delivered to the host.
    pub rx_packets: u64,
    /// Packets dropped because no session was established yet.
    pub tx_dropped_no_session: u64,
    /// Authenticated-decryption failures on inbound transport data.
    ///
    /// **The blind spot that cost a diagnosis.** An AEAD failure is a silent
    /// drop by design (§11), and for a long time it was silent from the
    /// operator's side too: a rekey race left the two ends holding sessions
    /// from different handshakes, 13% of traffic vanished over 7.8 hours, and
    /// every counter read zero while both peers reported `established`. A drop
    /// that is invisible in the statistics is indistinguishable from a packet
    /// that never arrived.
    pub decrypt_failures: u64,
    /// Inbound datagrams that could not even be parsed as a fragment.
    ///
    /// Previously a silent `return` with no counter, which hid a real bug
    /// during the batched-I/O work: datagrams were visible on the wire, absent
    /// from every statistic, and there was no way to tell whether they had been
    /// received and rejected or never received at all.
    pub malformed: u64,
    /// Authenticated packets from a peer that the ACL refused (§4.3).
    ///
    /// Counted apart from `source_violations` because they mean opposite
    /// things: a source violation is a peer claiming an address it does not
    /// own, which is an attack or a serious misconfiguration; this is the
    /// policy working as written. An operator who cannot tell them apart will
    /// read a correctly-enforced ACL as an intrusion.
    pub acl_denied_in: u64,
    /// Packets from the host the ACL refused to send.
    pub acl_denied_out: u64,
    /// Packets denied because their ports could not be established at all — a
    /// non-first fragment or an encrypted payload.
    ///
    /// Separate from the two above because it is not a policy decision: no rule
    /// was evaluated, because none could be. A sustained rate means something
    /// is fragmenting or tunnelling, not that a policy is wrong.
    pub acl_unclassifiable: u64,
}

/// Live counters. Separate from [`Stats`], which is the snapshot type.
///
/// Atomics rather than fields behind the peer locks: a counter shared by every
/// peer would reintroduce exactly the contention this design removes, and
/// `Relaxed` is right because nothing is ordered against these — they are
/// diagnostics, not synchronisation.
#[derive(Debug, Default)]
struct Counters {
    unroutable: AtomicU64,
    source_violations: AtomicU64,
    mac_failures: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_dropped_no_session: AtomicU64,
    malformed: AtomicU64,
    decrypt_failures: AtomicU64,
    acl_denied_in: AtomicU64,
    acl_denied_out: AtomicU64,
    acl_unclassifiable: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> Stats {
        Stats {
            unroutable: self.unroutable.load(Ordering::Relaxed),
            source_violations: self.source_violations.load(Ordering::Relaxed),
            mac_failures: self.mac_failures.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_dropped_no_session: self.tx_dropped_no_session.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            decrypt_failures: self.decrypt_failures.load(Ordering::Relaxed),
            acl_denied_in: self.acl_denied_in.load(Ordering::Relaxed),
            acl_denied_out: self.acl_denied_out.load(Ordering::Relaxed),
            acl_unclassifiable: self.acl_unclassifiable.load(Ordering::Relaxed),
        }
    }
}

/// One peer's mutable state, behind its own lock.
///
/// The session and the endpoint are separate locks because they are taken on
/// different schedules: the endpoint is read on every outbound packet and
/// written only when a handshake authenticates, so folding it into the session
/// lock would make every send wait behind a crypto operation.
struct PeerSlot {
    session: Mutex<Session>,
    endpoint: RwLock<Option<SocketAddr>>,
    /// Connection tracking for this peer's ACL — see [`crate::flow`].
    ///
    /// **Per peer, like everything else here**, so the datapath keeps the
    /// property §3.4 measured: two peers never contend. The critical section is
    /// a hash lookup and is taken alongside the session lock this path already
    /// takes, rather than being a new kind of contention.
    flows: Mutex<crate::flow::Flows>,
    /// When this node's own relay last said it could not reach this peer, in
    /// engine milliseconds. Zero means it has not — §9.1's first rule still
    /// applies.
    ///
    /// **A relay will not say who it holds**, and §5.4 makes that deliberate:
    /// answering "is this node here?" for an arbitrary id is a membership
    /// oracle across tenants on a shared relay. So presence is learned the only
    /// way it can be, by addressing the peer and reading the `PeerGone` that
    /// comes back. An atomic rather than a lock because the outbound path reads
    /// it for every packet to a peer with no direct path.
    off_home: AtomicU64,
}

/// Everything a packet's handling depends on, swapped as a unit.
///
/// Held behind an `RwLock<Arc<Roster>>` and cloned out on entry to each method,
/// so the lock is held only long enough to bump a refcount. That keeps the
/// datapath's parallelism — PLAN.md §3.4 measured what a lock held *across* the
/// work costs — while making the whole peer set replaceable.
///
/// The three fields move together because they must agree: `by_hint` and the
/// filter's rules are both indexed by position in `peers`, and a swap that
/// updated one without the others would enforce the right policy against the
/// wrong peer.
struct Roster {
    config: Arc<Config>,
    /// `Arc` per slot so a new roster can carry a live session over from the
    /// old one rather than rebuilding it — which is the entire point of
    /// [`Engine::reconfigure`].
    peers: Vec<Arc<PeerSlot>>,
    /// `peer_id_hint` → index, so resolving an inbound handshake is a lookup
    /// rather than a scan of the roster (§4).
    by_hint: HashMap<[u8; 32], PeerIndex>,
    /// Each peer's Ponor node id, when it has one. `None` for a static TOML
    /// roster, which carries no server-assigned handles and therefore has no
    /// relay path — the peer is direct-only or it is nothing.
    relay_ids: Vec<Option<[u8; karst_relay_proto::consts::ID_LEN]>>,
    /// The reverse mapping, for attributing a relay-delivered datagram to the
    /// peer the relay says sent it.
    by_relay_id: HashMap<[u8; karst_relay_proto::consts::ID_LEN], PeerIndex>,
    /// Each peer's published home relay — §9.1 — **filtered to relays this node
    /// could actually dial**, which means present in the netmap's registry.
    ///
    /// A relay id alone names nothing dialable: reaching one needs its address,
    /// its TLS name and the ML-DSA-65 key its identity is pinned to, and all
    /// three come from the registry. Filtering here rather than at the point of
    /// use means the routing decision cannot produce a destination the
    /// transport will silently drop.
    home_relays: Vec<Option<[u8; karst_relay_proto::consts::ID_LEN]>>,
    /// Whether this node has a relay to send through at all. Without one a
    /// peer's node id names a destination nothing can reach.
    relay_configured: bool,
}

/// The node's datapath.
///
/// # Concurrency
///
/// Every method takes `&self`. There is deliberately **no lock around the
/// engine as a whole**: measurement (PLAN.md §3.4) showed that one is enough to
/// flatten throughput completely — four concurrent flows went no faster than
/// one while 46 of 48 cores sat idle.
///
/// Instead the state is split by what actually needs to be exclusive:
///
/// - **per-peer session locks**, so traffic for different peers never contends,
///   and the two directions of one peer contend only for the length of the
///   crypto;
/// - **atomic counters**, which would otherwise be a single point every packet
///   passes through;
/// - **the reassembler behind its own lock**, off the outbound path entirely —
///   sending a packet must not wait on inbound reassembly, which is unrelated
///   work that happens to live in the same struct.
pub struct Engine {
    /// The peer set, replaceable while the daemon runs.
    roster: RwLock<Arc<Roster>>,
    /// Node-level reassembly, bounded at construction (§9.1).
    ///
    /// Locked separately and released before any session work, so the outbound
    /// path never touches it.
    reasm: Mutex<Reassembler>,
    /// Suite policy, identical for every peer until the netmap distributes it.
    policy: SuitePolicy,
    /// The one key every inbound fragment is verified with — §13.7. Pre-keyed
    /// so the HMAC schedule is not rebuilt per packet.
    in_mac_key: FragMacKey,
    stats: Counters,
    /// The relay this node itself holds a connection to — §9.1.
    ///
    /// **Told to the engine rather than derived from the configuration**, even
    /// though today the daemon takes the first registry entry. The choice
    /// belongs to `home::Selector`, and a second place computing it is a second
    /// place that can disagree — at which point this node would route a peer
    /// onto an on-demand connection to the relay it is already sitting on.
    home_relay: RwLock<Option<[u8; karst_relay_proto::consts::ID_LEN]>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("peers", &self.roster().peers.len())
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Build an engine over a loaded configuration.
    #[must_use]
    pub fn new(config: &Arc<Config>) -> Self {
        let policy = SuitePolicy {
            minimum: SuiteId::KARST_1,
            supported: vec![SuiteId::KARST_1],
        };
        let in_mac_key = FragMacKey::new(&mac1_key(&MlKem::public_key_bytes(&config.keys.kem_pk)));
        let roster = build_roster(config, &policy, &HashMap::new());
        Self {
            roster: RwLock::new(Arc::new(roster)),
            reasm: Mutex::new(Reassembler::new(ReasmConfig::default())),
            policy,
            in_mac_key,
            stats: Counters::default(),
            home_relay: RwLock::new(None),
        }
    }

    /// Tell the engine which relay this node holds — §9.1.
    ///
    /// Routing needs it to tell the two rules apart: a peer whose published
    /// home is the relay this node is already connected to is reached on that
    /// connection, not on a second one dialled to the same address.
    pub fn set_home_relay(&self, relay_id: Option<[u8; karst_relay_proto::consts::ID_LEN]>) {
        *self
            .home_relay
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = relay_id;
    }

    /// The registry entry for a relay id, or `None` if the netmap carries none.
    ///
    /// The engine holds the current configuration and swaps it as a unit, so
    /// asking it is what keeps a dialler from working off a registry that has
    /// been replaced since the packet was routed.
    #[must_use]
    pub fn relay(
        &self,
        relay_id: [u8; karst_relay_proto::consts::ID_LEN],
    ) -> Option<crate::netmap::Relay> {
        self.roster()
            .config
            .relays
            .iter()
            .find(|r| r.relay_id == relay_id)
            .cloned()
    }

    /// The relay registry the netmap currently carries.
    ///
    /// Read from the engine rather than from the configuration the daemon
    /// started with, because a netmap refresh replaces it: a node measuring
    /// alternatives against a registry that has been withdrawn would be dialling
    /// relays its peers are no longer told about.
    #[must_use]
    pub fn relays(&self) -> Vec<crate::netmap::Relay> {
        self.roster().config.relays.clone()
    }

    /// The relay this node holds — §9.1.
    #[must_use]
    pub fn home_relay(&self) -> Option<[u8; karst_relay_proto::consts::ID_LEN]> {
        *self
            .home_relay
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record that a datagram from `peer_id` arrived on this node's own relay —
    /// §9.1's first rule, answered in the affirmative.
    ///
    /// **The peer is there, and that outranks anything it published.** A
    /// `PeerGone` is a fact with a lifetime: the peer may join this relay's
    /// mesh, or dial this very relay on demand because *this* node is the one
    /// it cannot reach directly — which is exactly what happens when two nodes
    /// end up on two relays and only one of them can dial the other's. Without
    /// this the pair would sit either side of a mark that expires in minutes,
    /// each sending to a relay the other is not on, while both were meeting on
    /// one relay the whole time.
    ///
    /// Cheap on the datapath: a relaxed load, and a store only when a mark is
    /// actually in force.
    pub fn seen_on_home_relay(&self, peer_id: [u8; karst_relay_proto::consts::ID_LEN]) {
        let roster = self.roster();
        let Some(&peer) = roster.by_relay_id.get(&peer_id) else {
            return;
        };
        let Some(slot) = roster.peers.get(peer) else {
            return;
        };
        if slot.off_home.load(Ordering::Relaxed) != 0 {
            slot.off_home.store(0, Ordering::Relaxed);
        }
    }

    /// Record that this node's own relay could not deliver to `peer_id` —
    /// §9.1's first rule, answered in the negative.
    ///
    /// Returns whether the peer now has somewhere else to be tried. `false`
    /// means the peer published no reachable home relay, so this changes
    /// nothing: the traffic keeps going to the relay that just refused it,
    /// which is right, because a peer that is simply offline will be back on
    /// that same relay when it returns.
    pub fn relay_unreachable(
        &self,
        peer_id: [u8; karst_relay_proto::consts::ID_LEN],
        now_ms: u64,
    ) -> bool {
        let roster = self.roster();
        let Some(&peer) = roster.by_relay_id.get(&peer_id) else {
            return false;
        };
        let Some(slot) = roster.peers.get(peer) else {
            return false;
        };
        // Zero is "not marked", so a mark taken in the first millisecond of the
        // process must not read as one.
        slot.off_home.store(now_ms.max(1), Ordering::Relaxed);
        let elsewhere = roster.home_relays.get(peer).copied().flatten();
        elsewhere.is_some_and(|id| Some(id) != self.home_relay())
    }

    /// A snapshot of the current peer set.
    ///
    /// The read lock is held only for the `Arc` clone, so two packets for
    /// different peers never wait on each other — and a reconfiguration in
    /// progress does not stall the datapath, it just means the next packet sees
    /// the new roster.
    fn roster(&self) -> Arc<Roster> {
        Arc::clone(
            &self
                .roster
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Replace the peer set without disturbing the sessions that survive it.
    ///
    /// # What is preserved, and why it matters
    ///
    /// A peer present in both rosters **keeps its live session and its learned
    /// endpoint**. Adding one peer must not cost a rehandshake with every
    /// other: on a large aquifer a single enrolment would otherwise produce a
    /// fleet-wide reconnect, and each reconnect is two ML-KEM operations and a
    /// window where traffic is dropped for want of a session.
    ///
    /// "The same peer" means the same **KEM public key**, since that is what
    /// `peer_id_hint` is derived from and what a handshake actually
    /// authenticates. A peer whose key changed is a different peer wearing the
    /// same name, and gets a fresh session.
    ///
    /// A changed **PSK or epoch** does *not* invalidate a session: §7.3 wants a
    /// rotation to complete with no interruption, so the running session keeps
    /// its keys and only the next handshake uses the new material. See
    /// [`Session::rearm`].
    ///
    /// Returns what changed, for the log line an operator will want.
    pub fn reconfigure(&self, config: &Arc<Config>) -> Reconfigured {
        let previous = self.roster();

        // Index the old roster by peer key, which is what identifies a peer
        // across a reconfiguration — not its position, which shifts whenever
        // anything is added or removed.
        let mut existing: HashMap<[u8; 32], (usize, Arc<PeerSlot>)> =
            HashMap::with_capacity(previous.peers.len());
        for (index, peer) in previous.config.peers.iter().enumerate() {
            if let Some(slot) = previous.peers.get(index) {
                existing.insert(
                    peer_id_hint(&MlKem::public_key_bytes(&peer.public.kem_pk)),
                    (index, Arc::clone(slot)),
                );
            }
        }

        let carried: HashMap<[u8; 32], Arc<PeerSlot>> = existing
            .iter()
            .map(|(hint, (_, slot))| (*hint, Arc::clone(slot)))
            .collect();
        let next = build_roster(config, &self.policy, &carried);

        // Count from the two rosters rather than from the builder, so the
        // report describes what actually happened.
        let mut added = 0;
        let mut kept = 0;
        for peer in &config.peers {
            let hint = peer_id_hint(&MlKem::public_key_bytes(&peer.public.kem_pk));
            if existing.contains_key(&hint) {
                kept += 1;
            } else {
                added += 1;
            }
        }
        let removed = existing.len().saturating_sub(kept);

        // Rearm the carried sessions for the epoch and PSK now in force. Done
        // after the new roster is built so a failure to build it leaves the old
        // one untouched rather than half-updated.
        if previous.config.psk_epoch != config.psk_epoch {
            for (index, peer) in config.peers.iter().enumerate() {
                let hint = peer_id_hint(&MlKem::public_key_bytes(&peer.public.kem_pk));
                if !existing.contains_key(&hint) {
                    continue;
                }
                if let Some(slot) = next.peers.get(index) {
                    Self::lock(&slot.session).rearm(Arc::clone(&peer.public), config.psk_epoch);
                }
            }
        }

        // **A flow is a cached permission, so a new policy invalidates it.**
        // Sessions and endpoints are carried across a reconfiguration on
        // purpose — a peer that did not change should not rehandshake — but
        // carrying the flow table too would mean a policy edit that revoked
        // access left every connection it revoked still working. The cache is
        // cheap to rebuild and the alternative is a revocation that does not
        // revoke.
        for slot in &next.peers {
            Self::lock(&slot.flows).clear();
        }

        *self
            .roster
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);

        Reconfigured {
            added,
            removed,
            kept,
            epoch_rotated: previous.config.psk_epoch != config.psk_epoch,
        }
    }

    /// Take a lock, recovering from poisoning.
    ///
    /// A poisoned lock means another thread panicked while holding it. Every
    /// structure here is a state machine over owned data rather than a
    /// half-written buffer, so continuing is better than taking the tunnel down
    /// for every peer because one packet caused a panic somewhere.
    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats.snapshot()
    }

    /// Whether a session with `peer` is usable right now.
    #[must_use]
    pub fn established(&self, peer: PeerIndex) -> bool {
        self.roster()
            .peers
            .get(peer)
            .is_some_and(|p| Self::lock(&p.session).established())
    }

    /// The endpoint currently believed for a peer.
    ///
    /// A read lock, not the session lock: this is consulted on every outbound
    /// packet, and making it wait behind an in-progress encryption would put the
    /// contention straight back.
    #[must_use]
    pub fn endpoint(&self, peer: PeerIndex) -> Option<SocketAddr> {
        self.roster().peers.get(peer).and_then(|p| {
            *p.endpoint
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
    }

    /// How to reach a peer right now, or `None` if there is no way at all.
    ///
    /// **This is the whole of the relay→direct upgrade, and it is a two-line
    /// rule on purpose.** A direct endpoint wins whenever there is one; the
    /// relay carries the traffic whenever there is not. Nothing else has to
    /// coordinate, because AVEN owns whether a direct endpoint exists at all:
    /// it installs one on a confirmed path and withdraws it once it has given
    /// up on every path ([`Self::set_endpoint`], [`Self::release_endpoint`]).
    /// The upgrade and the fallback are the same decision read at different
    /// moments.
    ///
    /// **That includes the endpoint the netmap supplied.** Discovery adopts it
    /// at reconcile and can withdraw it, which is what stops a published
    /// address that has gone stale from pre-empting the relay forever — it did,
    /// and it was FINDINGS.md finding 15. A peer with no disco key is untouched
    /// by any of this and keeps its configured endpoint, which is correct: no
    /// key means no discovery, ever (`aven-v1.md` §5.1), so there is nothing to
    /// learn from and nothing that could responsibly take it away.
    ///
    /// Deciding it here rather than at each call site is what keeps that true.
    /// An earlier version asked `endpoint(peer)` in four places and dropped the
    /// packet when it was `None`, and a relay path added to three of them would
    /// have been a peer that could receive but not send.
    /// **Which relay is the second half of the decision, and §9.1 orders it.**
    /// This node's own relay is tried first, because the connection is already
    /// up and the peer may well be on it or on its mesh. Only once that relay
    /// has said otherwise — `PeerGone`, recorded by [`Self::relay_unreachable`]
    /// — does the peer's published home relay come into play, and then only if
    /// it is one this node could dial and is not the relay it already holds.
    fn via(&self, roster: &Roster, peer: PeerIndex) -> Option<Via> {
        if let Some(addr) = self.endpoint(peer) {
            return Some(Via::Direct(addr));
        }
        if !roster.relay_configured {
            return None;
        }
        let destination = roster.relay_ids.get(peer).copied().flatten()?;
        let refused = roster
            .peers
            .get(peer)
            .is_some_and(|slot| slot.off_home.load(Ordering::Relaxed) != 0);
        if refused {
            if let Some(home) = roster.home_relays.get(peer).copied().flatten() {
                if Some(home) != self.home_relay() {
                    return Some(Via::Relay {
                        relay: Some(home),
                        destination,
                    });
                }
            }
        }
        Some(Via::Relay {
            relay: None,
            destination,
        })
    }

    /// Which relay carries traffic for the peer the relay knows as `peer_id`.
    ///
    /// The same decision [`Self::via`] makes, for the callers that hold a node
    /// id rather than a roster index — AVEN's rendezvous, whose advertisements
    /// must reach the peer by the same route its data does. A peer with a
    /// direct path still answers here: an advertisement is what *creates* the
    /// direct path, so it goes over the relay regardless (`aven-v1.md` §7.3).
    #[must_use]
    pub fn relay_for(
        &self,
        peer_id: [u8; karst_relay_proto::consts::ID_LEN],
    ) -> Option<[u8; karst_relay_proto::consts::ID_LEN]> {
        let roster = self.roster();
        let &peer = roster.by_relay_id.get(&peer_id)?;
        let refused = roster
            .peers
            .get(peer)
            .is_some_and(|slot| slot.off_home.load(Ordering::Relaxed) != 0);
        if !refused {
            return None;
        }
        roster
            .home_relays
            .get(peer)
            .copied()
            .flatten()
            .filter(|&home| Some(home) != self.home_relay())
    }

    /// Install an authenticated AVEN-selected endpoint for a roster peer.
    ///
    /// Unconditional: a probed and confirmed direct path is better evidence
    /// than an address learned from a handshake, and displacing the second with
    /// the first is the whole purpose of discovery.
    ///
    /// The index is bounds-checked, which is **not** the same as checking
    /// identity — see [`Self::release_endpoint`] for the caller's obligation.
    pub fn set_endpoint(&self, peer: PeerIndex, endpoint: SocketAddr) -> bool {
        let roster = self.roster();
        let Some(slot) = roster.peers.get(peer) else {
            return false;
        };
        *slot
            .endpoint
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(endpoint);
        true
    }

    /// Withdraw the direct endpoint discovery has given up on, so the peer
    /// falls back to the relay.
    ///
    /// **Conditional on `installed` still being the value in force**, and that
    /// is the point of the method. This field has a second writer — [`inbound`]
    /// learns an endpoint from a handshake that decrypted (§9.1) — and a
    /// discovery result going stale is no reason to discard an address somebody
    /// else has since established as working.
    ///
    /// Clearing it rather than keeping the dead address follows
    /// `PathSet::select`'s own rule: continuing to send into a path that has
    /// stopped answering is worse than admitting there is none. There is no
    /// revert target because there is nothing left to revert *to* — the
    /// netmap-configured endpoint is a candidate like any other, so by the time
    /// discovery says this, it has been probed and given up on as well.
    ///
    /// [`inbound`]: Self::inbound
    pub fn release_endpoint(&self, peer: PeerIndex, installed: SocketAddr) -> bool {
        let roster = self.roster();
        let Some(slot) = roster.peers.get(peer) else {
            return false;
        };
        let mut current = slot
            .endpoint
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current != Some(installed) {
            return false;
        }
        *current = None;
        true
    }

    /// Start handshakes with every peer that has a configured endpoint.
    ///
    /// A peer with no endpoint is not contacted: there is nowhere to send. It
    /// can still connect to us, which is the intended arrangement for a node
    /// behind NAT that has not yet been discovered.
    pub fn connect_all(&self, now_ms: u64, seed: impl Fn() -> [u8; 32]) -> Output {
        let mut out = Output::default();
        let roster = self.roster();
        for index in 0..roster.peers.len() {
            // A peer with neither a direct endpoint nor a relay path is not
            // dialled: there is nowhere to send, and it is expected to contact
            // us instead.
            if self.via(&roster, index).is_none() {
                continue;
            }
            let actions = roster
                .peers
                .get(index)
                .map(|p| Self::lock(&p.session).connect(now_ms, seed()))
                .unwrap_or_default();
            self.apply(&roster, index, actions, now_ms, &mut out);
        }
        out
    }

    /// Advance every session's timers.
    pub fn poll(&self, now_ms: u64, seed: impl Fn() -> [u8; 32]) -> Output {
        let mut out = Output::default();
        // One peer's lock at a time, released before the next. A timer sweep
        // must not stall the datapath for every peer while it walks the roster.
        let roster = self.roster();
        for slot in &roster.peers {
            // §9.1's first rule is retried, because a peer's absence from this
            // node's relay is a fact with a lifetime: the peer may join this
            // relay's mesh, or move onto this relay outright, and neither
            // produces a message anyone sends here. Retrying costs one datagram
            // — the one that draws the next `PeerGone` — every
            // `HOME_RELAY_RETRY`, and never retrying means a pair that could
            // share one relay hop keeps paying for two connections for as long
            // as both run.
            let marked = slot.off_home.load(Ordering::Relaxed);
            if marked != 0 && now_ms.saturating_sub(marked) >= HOME_RELAY_RETRY_MS {
                slot.off_home.store(0, Ordering::Relaxed);
            }
        }
        for index in 0..roster.peers.len() {
            // As `connect_all`: reachable by either transport is enough.
            let reconnect = self.via(&roster, index).is_some();
            let actions = roster
                .peers
                .get(index)
                .map(|p| {
                    let mut session = Self::lock(&p.session);
                    let mut actions = session.poll(now_ms, seed());
                    // **Re-dial an idle peer.** A session that expires, or whose
                    // handshake gives up, returns to `Idle` — and `connect_all`
                    // runs only at startup, so without this it would stay there
                    // for the life of the process. One rekey lost to packet loss
                    // would then end the tunnel permanently rather than costing
                    // a round trip. `connect` is a no-op unless the session is
                    // genuinely idle, and the `Handshaking` state paces the
                    // retries from there.
                    if reconnect {
                        actions.extend(session.connect(now_ms, seed()));
                    }
                    actions
                })
                .unwrap_or_default();
            self.apply(&roster, index, actions, now_ms, &mut out);
        }
        out
    }

    /// A packet arrived from the host, destined for the tunnel.
    ///
    /// Chooses a peer by longest-prefix match on the destination and encrypts.
    /// A packet nobody owns is dropped and counted: silently discarding it is
    /// correct — the kernel routed it here, and there is no peer to ask — but
    /// silently *not counting* it turns a configuration mistake into a mystery.
    pub fn outbound(&self, packet: &[u8], now_ms: u64) -> Output {
        let mut out = Output::default();
        let roster = self.roster();
        let Some(dst) = karst_tun::ip::destination(packet) else {
            self.stats.unroutable.fetch_add(1, Ordering::Relaxed);
            return out;
        };
        let Some(peer) = roster.config.routes.route(dst) else {
            self.stats.unroutable.fetch_add(1, Ordering::Relaxed);
            return out;
        };
        // **The ACL, before the endpoint and before any cryptography.** A
        // packet policy forbids should not reach a peer's crypto at all, and
        // checking here means a denied flow costs nothing beyond a route
        // lookup. The receiver checks independently — this end is the fast,
        // local answer, not the one carrying the security property.
        if !self.permit(&roster, Direction::Out, peer, packet, now_ms) {
            return out;
        }
        let Some(via) = self.via(&roster, peer) else {
            self.stats
                .tx_dropped_no_session
                .fetch_add(1, Ordering::Relaxed);
            return out;
        };
        let Some(slot) = roster.peers.get(peer) else {
            return out;
        };

        // **The lock is held only to clone two handles**, not across the
        // cryptography. Sealing needs no exclusive access — the counter is
        // atomic — so holding the session lock around it would serialise every
        // flow to this peer behind every other, which measured as a hard
        // ~500 Mbps ceiling regardless of flow count (PLAN.md §3.4).
        let handles = {
            let mut session = Self::lock(&slot.session);
            session
                .transport()
                .map(|t| (t, session.out_mac_key(), session.next_reassembly_id()))
        };
        let Some((transport, mac_key, reassembly_id)) = handles else {
            self.stats
                .tx_dropped_no_session
                .fetch_add(1, Ordering::Relaxed);
            return out;
        };

        let sealed = transport
            .seal(packet, now_ms)
            .ok()
            .and_then(|msg| fragment(MessageType::TransportData, reassembly_id, &msg, &mac_key));
        match sealed {
            Some(frags) => {
                self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                for f in frags {
                    out.datagrams.push((f, via));
                }
            }
            // No session yet. Dropping the packet is what WireGuard does too;
            // the handshake is already in flight from `connect_all`, and TCP
            // will retransmit. Queueing it here would mean buffering
            // unbounded traffic for a peer that may never answer.
            None => {
                self.stats
                    .tx_dropped_no_session
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        out
    }

    /// A datagram arrived on the UDP socket.
    pub fn inbound(
        &self,
        datagram: &[u8],
        from: SocketAddr,
        now_ms: u64,
        rand: &ResponderRandomness,
    ) -> Output {
        let mut out = Output::default();
        let roster = self.roster();
        let Ok((hdr, payload)) = split_datagram(datagram) else {
            self.stats.malformed.fetch_add(1, Ordering::Relaxed);
            return out;
        };

        // §9.2 — one key, checked before anything is allocated. The type byte is
        // only visible on fragment 0, so later fragments are checked against
        // every type they could belong to and the AEAD settles it.
        let claimed = payload.first().copied().unwrap_or(0);
        let mac_ok = [claimed, 0x01, 0x02, 0x04].iter().any(|t| {
            self.in_mac_key
                .verify(*t, hdr.reassembly_id, hdr.idx, hdr.count, &hdr.frag_mac)
        });
        if !mac_ok {
            self.stats.mac_failures.fetch_add(1, Ordering::Relaxed);
            return out;
        }

        // Address validation is `true` here because Phase 2 has a static roster
        // reachable only from configured endpoints. §9.1's under-load path,
        // where an unvalidated source must allocate nothing, arrives with
        // cookies in Phase 3.
        //
        // The reassembly lock is taken here and released immediately: the
        // message is copied out before any session work starts, so a handshake
        // — which runs ML-KEM — never blocks the next datagram's reassembly.
        let msg = {
            let mut reasm = Self::lock(&self.reasm);
            let Accept::Complete(msg) = reasm.push(source_key(from), true, &hdr, payload, now_ms)
            else {
                return out;
            };
            msg.to_vec()
        };

        if msg.first() == Some(&0x01) {
            self.accept_handshake(&roster, &msg, from, now_ms, rand, &mut out);
            return out;
        }

        // A response or transport message belongs to whichever peer is at this
        // address. Attribution by address is provisional — the AEAD is what
        // actually decides — so a wrong guess costs a dropped datagram, not a
        // security property.
        let Some(peer) = self.peer_at(from) else {
            return out;
        };
        // Transport data is the hot path and takes the same treatment as the
        // outbound one: clone the handle under the lock, decrypt outside it.
        // Anything else — a handshake response — is rare and goes through the
        // session state machine as before.
        if msg.first() == Some(&0x04) {
            let transport = roster
                .peers
                .get(peer)
                .and_then(|p| Self::lock(&p.session).transport());
            if let Some(transport) = transport {
                // Decryption happens with no lock held. A forged or replayed
                // message is rejected inside `open`, which takes the replay
                // window's own lock only after the AEAD has decided (§8).
                match transport.open(&msg, now_ms) {
                    Ok(payload) => self.deliver_to_host(&roster, peer, &payload, now_ms, &mut out),
                    // Counted, not just dropped. A replay is expected traffic;
                    // a *sustained* rate here means the two ends disagree about
                    // their keys, which is otherwise indistinguishable from the
                    // peer having gone quiet.
                    Err(_) => {
                        self.stats.decrypt_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return out;
            }
        }

        let actions = roster
            .peers
            .get(peer)
            .map(|p| Self::lock(&p.session).deliver(&msg, now_ms))
            .unwrap_or_default();
        self.apply(&roster, peer, actions, now_ms, &mut out);
        out
    }

    /// A datagram arrived over the authenticated relay.
    ///
    /// Separate from [`Self::inbound`] rather than a flag on it, because the
    /// two differ in what they may conclude from where a datagram came from:
    ///
    /// - **No endpoint is learned.** `inbound` learns one from a handshake that
    ///   decrypted, which is how a peer whose NAT mapping moved becomes
    ///   reachable again. A relay-delivered datagram carries no UDP source at
    ///   all — the address it arrived from is the *relay's*. Learning it would
    ///   point this peer's traffic at the relay's TLS port, which is not even a
    ///   PHREATIC listener.
    /// - **Attribution is by the relay-stamped source, not by address.**
    ///   `peer_at(from)` guesses from the endpoint table; here the relay has
    ///   already told us, having authenticated the sender under Ponor.
    /// - **Reassembly is keyed apart from every UDP source.** Two transports
    ///   feeding one reassembly key would let a peer interleave fragments
    ///   across them, and let one relay-delivered stream collide with a
    ///   direct one from the same peer mid-upgrade.
    ///
    /// A handshake must additionally name the same peer the relay says sent it.
    /// Both bindings are independent — the relay authenticated a Ponor identity,
    /// the AEAD resolves a `peer_id_hint` — and requiring them to agree is what
    /// stops one admitted peer from replaying another's handshake under its own
    /// relay identity.
    pub fn inbound_from_relay(
        &self,
        source_id: [u8; karst_relay_proto::consts::ID_LEN],
        datagram: &[u8],
        now_ms: u64,
        rand: &ResponderRandomness,
    ) -> Output {
        let mut out = Output::default();
        let roster = self.roster();
        let Some(peer) = roster.by_relay_id.get(&source_id).copied() else {
            return out;
        };
        let Ok((hdr, payload)) = split_datagram(datagram) else {
            self.stats.malformed.fetch_add(1, Ordering::Relaxed);
            return out;
        };

        let claimed = payload.first().copied().unwrap_or(0);
        let mac_ok = [claimed, 0x01, 0x02, 0x04].iter().any(|t| {
            self.in_mac_key
                .verify(*t, hdr.reassembly_id, hdr.idx, hdr.count, &hdr.frag_mac)
        });
        if !mac_ok {
            self.stats.mac_failures.fetch_add(1, Ordering::Relaxed);
            return out;
        }

        let msg = {
            let mut reasm = Self::lock(&self.reasm);
            let Accept::Complete(msg) =
                reasm.push(relay_source_key(&source_id), true, &hdr, payload, now_ms)
            else {
                return out;
            };
            msg.to_vec()
        };

        if msg.first() == Some(&0x01) {
            self.accept_relayed_handshake(&roster, &msg, peer, now_ms, rand, &mut out);
            return out;
        }

        if msg.first() == Some(&0x04) {
            let transport = roster
                .peers
                .get(peer)
                .and_then(|p| Self::lock(&p.session).transport());
            if let Some(transport) = transport {
                match transport.open(&msg, now_ms) {
                    Ok(payload) => self.deliver_to_host(&roster, peer, &payload, now_ms, &mut out),
                    Err(_) => {
                        self.stats.decrypt_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return out;
            }
        }

        let actions = roster
            .peers
            .get(peer)
            .map(|p| Self::lock(&p.session).deliver(&msg, now_ms))
            .unwrap_or_default();
        self.apply(&roster, peer, actions, now_ms, &mut out);
        out
    }

    /// Answer a `HandshakeInit` the relay delivered.
    ///
    /// The same work as [`Self::accept_handshake`] minus the endpoint learning,
    /// plus the check that the peer the AEAD resolves is the peer the relay
    /// named.
    fn accept_relayed_handshake(
        &self,
        roster: &Roster,
        msg: &[u8],
        expected: PeerIndex,
        now_ms: u64,
        rand: &ResponderRandomness,
        out: &mut Output,
    ) {
        // **The same `HandshakeInit` gets the same `HandshakeResponse`.** An
        // initiator retransmits the identical message until it hears back
        // (§10), and answering the retransmission afresh derives keys that
        // displace the ones the initiator has already completed under — leaving
        // a pair that both ends call `established` and neither can decrypt.
        // Checked before the ML-KEM work, so a repeat costs nothing.
        let repeated = roster
            .peers
            .get(expected)
            .and_then(|p| Self::lock(&p.session).repeat_response(msg));
        if let Some(actions) = repeated {
            self.apply(roster, expected, actions, now_ms, out);
            return;
        }

        let index = u32::try_from(expected).unwrap_or(u32::MAX).wrapping_add(1);
        let by_hint = &roster.by_hint;
        let peers = &roster.config.peers;
        let mut matched: Option<PeerIndex> = None;

        let result = karst_noise::handshake::respond(
            &roster.config.keys,
            &self.policy,
            msg,
            |hint, _epoch| {
                let index = *by_hint.get(hint)?;
                let peer = peers.get(index)?;
                matched = Some(index);
                Some((*peer.public).clone())
            },
            rand,
            index,
        );

        let (Ok((msg2, pending)), Some(peer)) = (result, matched) else {
            return;
        };
        // The two bindings must agree. Silent, like every other §11 discard:
        // saying which check failed would distinguish "not a peer" from "not
        // *that* peer", and the second is a roster-membership oracle.
        if peer != expected {
            return;
        }
        let actions = roster
            .peers
            .get(peer)
            .map(|p| Self::lock(&p.session).adopt_responder(msg, &pending.confirm(), &msg2, now_ms))
            .unwrap_or_default();
        self.apply(roster, peer, actions, now_ms, out);
    }

    /// Answer an inbound `HandshakeInit`.
    ///
    /// One call to `respond` performs **one** ML-KEM decapsulation and resolves
    /// the initiator through `peer_id_hint` — the O(1) lookup §4 exists for.
    /// Offering the message to each session in turn would instead cost a
    /// decapsulation per peer for every unrecognised handshake, so a stream of
    /// garbage from one address would consume CPU proportional to roster size.
    fn accept_handshake(
        &self,
        roster: &Roster,
        msg: &[u8],
        from: SocketAddr,
        now_ms: u64,
        rand: &ResponderRandomness,
        out: &mut Output,
    ) {
        // **The same `HandshakeInit` gets the same `HandshakeResponse`.** An
        // initiator retransmits the identical message until it hears back
        // (§10), and answering the retransmission afresh derives keys that
        // displace the ones the initiator has already completed under — leaving
        // a pair that both ends call `established` and neither can decrypt.
        // Checked before the ML-KEM work, so a repeat costs nothing.
        let repeated = self.peer_at(from).and_then(|peer| {
            roster
                .peers
                .get(peer)
                .and_then(|p| Self::lock(&p.session).repeat_response(msg))
                .map(|actions| (peer, actions))
        });
        if let Some((peer, actions)) = repeated {
            self.apply(roster, peer, actions, now_ms, out);
            return;
        }

        let index = self
            .peer_at(from)
            .map_or(0, |i| u32::try_from(i).unwrap_or(u32::MAX).wrapping_add(1));
        let by_hint = &roster.by_hint;
        let peers = &roster.config.peers;
        let mut matched: Option<PeerIndex> = None;

        let result = karst_noise::handshake::respond(
            &roster.config.keys,
            &self.policy,
            msg,
            |hint, _epoch| {
                let index = *by_hint.get(hint)?;
                let peer = peers.get(index)?;
                matched = Some(index);
                // A plain clone. This used to rebuild the key through its
                // serialisation, on the belief that `PeerPublic` could not be
                // `Clone` because the KEM key is opaque — true of an earlier
                // backend, and it had outlived it.
                Some((*peer.public).clone())
            },
            rand,
            index,
        );

        // §11: an unresolvable hint, a refused suite and a failed AEAD are all
        // silent discards, and deliberately indistinguishable — answering would
        // make this node an oracle for roster membership.
        let (Ok((msg2, pending)), Some(peer)) = (result, matched) else {
            return;
        };

        // Learn the endpoint from a handshake that decrypted, which is how a
        // peer whose NAT mapping changed becomes reachable again. It is not yet
        // proof of anything (§12.6) — the AEAD on the first transport message
        // is — but a wrong guess only costs a dropped datagram.
        if let Some(slot) = roster.peers.get(peer) {
            if let Ok(mut endpoint) = slot.endpoint.write() {
                *endpoint = Some(from);
            }
        }
        let actions = roster
            .peers
            .get(peer)
            .map(|p| Self::lock(&p.session).adopt_responder(msg, &pending.confirm(), &msg2, now_ms))
            .unwrap_or_default();
        self.apply(roster, peer, actions, now_ms, out);
    }

    /// Turn a session's actions into I/O.
    fn apply(
        &self,
        roster: &Roster,
        peer: PeerIndex,
        actions: Vec<Action>,
        now_ms: u64,
        out: &mut Output,
    ) {
        let via = self.via(roster, peer);
        for action in actions {
            match action {
                Action::Send(d) => {
                    if let Some(to) = via {
                        out.datagrams.push((d, to));
                    }
                }
                Action::Deliver(packet) => self.deliver_to_host(roster, peer, &packet, now_ms, out),
                Action::Established | Action::Closed(_) => {}
            }
        }
    }

    /// Write a decrypted packet to the host — after checking the sender is
    /// entitled to the source address it claims.
    ///
    /// This is the inbound half of cryptokey routing. Authentication proved the
    /// packet came from this peer; it did not entitle the peer to impersonate
    /// another. Without this check any peer on the roster could inject traffic
    /// appearing to come from any address in the network.
    fn deliver_to_host(
        &self,
        roster: &Roster,
        peer: PeerIndex,
        packet: &[u8],
        now_ms: u64,
        out: &mut Output,
    ) {
        let Some(addrs) = karst_tun::ip::addresses(packet) else {
            self.stats.source_violations.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if !roster.config.routes.permits(peer, addrs.source) {
            self.stats.source_violations.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // **The ACL check that carries the security property.** It runs after
        // cryptokey routing, not before: a rule about a peer means nothing
        // until the packet is known to have come from that peer and to be
        // entitled to the source address it claims.
        //
        // A compromised peer will ignore its own egress filter, so this is the
        // check that stops it — which is why the same policy is enforced at
        // both ends rather than trusted to the sender.
        if !self.permit(roster, Direction::In, peer, packet, now_ms) {
            return;
        }
        // §8: the transport layer pads and carries no length field, so the
        // unpadded length comes from the inner IP header.
        let Some(len) = ip_total_length(packet) else {
            self.stats.source_violations.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match packet.get(..len) {
            Some(trimmed) => {
                self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                out.packets.push(trimmed.to_vec());
            }
            None => {
                self.stats.source_violations.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Whether the ACL — rules *and* connection tracking — permits a packet.
    ///
    /// Exported for `tests/acl_flows.rs`, in the same spirit as
    /// [`crate::run::bug_report_for_test`]: the property under test is a
    /// conversation, and reaching the ingress check the ordinary way needs an
    /// established session, a decrypted packet and a peer to have sent it. A
    /// test that stood all that up would be testing the handshake.
    ///
    /// It has side effects, deliberately — a permitted packet opens a flow,
    /// because that is what the real path does and a hook that skipped it would
    /// not be testing the real path.
    pub fn permits_for_test(
        &self,
        direction: Direction,
        peer: PeerIndex,
        packet: &[u8],
        now_ms: u64,
    ) -> bool {
        let roster = self.roster();
        self.permit(&roster, direction, peer, packet, now_ms)
    }

    /// Evaluate the ACL and count the refusal.
    ///
    /// One function for both directions so the two can never drift into
    /// different treatments of the same verdict — in particular so that
    /// `Unclassifiable` cannot come to mean "permit" on one side.
    fn permit(
        &self,
        roster: &Roster,
        dir: Direction,
        peer: PeerIndex,
        packet: &[u8],
        now_ms: u64,
    ) -> bool {
        let verdict = match dir {
            Direction::In => roster.config.filter.ingress(peer, packet),
            Direction::Out => roster.config.filter.egress(peer, packet),
        };
        match verdict {
            Verdict::Permit => {
                // **Recorded only here**, where a *rule* said yes. That is what
                // makes a flow un-forgeable: a packet no rule permits never
                // reaches this arm, so nothing an attacker sends can open one.
                if let Some(slot) = roster.peers.get(peer) {
                    Self::lock(&slot.flows).record(dir, packet, now_ms);
                }
                return true;
            }
            Verdict::Denied => {
                // No rule permits it. **That is not the end of the question**:
                // Karst's ACLs are unidirectional grants (§4.3), so the reply
                // to a permitted request never matches a rule and would be
                // dropped here — which is finding 17, and is why no TCP
                // connection could complete before this lookup existed.
                if let Some(slot) = roster.peers.get(peer) {
                    if Self::lock(&slot.flows).permits(dir, packet, now_ms) {
                        return true;
                    }
                }
                let counter = match dir {
                    Direction::In => &self.stats.acl_denied_in,
                    Direction::Out => &self.stats.acl_denied_out,
                };
                counter.fetch_add(1, Ordering::Relaxed);
            }
            // Not offered to the flow table either. A packet whose ports cannot
            // be read cannot be attributed to a flow, and guessing at two bytes
            // would let a fragment claim any permission it liked.
            Verdict::Unclassifiable => {
                self.stats
                    .acl_unclassifiable
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        false
    }

    fn peer_at(&self, addr: SocketAddr) -> Option<PeerIndex> {
        (0..self.roster().peers.len()).find(|i| self.endpoint(*i) == Some(addr))
    }

    /// The peer that owns an address, for diagnostics.
    #[must_use]
    pub fn peer_for(&self, addr: IpAddr) -> Option<PeerIndex> {
        self.roster().config.routes.route(addr)
    }

    /// A snapshot for `karst status`.
    ///
    /// Reports names, endpoints and session state. It reports **no key
    /// material**: not the PSK, not the private key, not even a full public key
    /// — a truncated `peer_id_hint` identifies a peer without filling a
    /// terminal, and nothing here can leak a secret into a support bundle
    /// (THREAT-MODEL R5).
    #[must_use]
    pub fn status(&self) -> Vec<PeerStatus> {
        let roster = self.roster();
        roster
            .config
            .peers
            .iter()
            .enumerate()
            .map(|(index, peer)| PeerStatus {
                name: peer.name.clone(),
                hint: short_hint(&peer.public.kem_pk),
                endpoint: self.endpoint(index),
                established: self.established(index),
                rekeying: roster
                    .peers
                    .get(index)
                    .is_some_and(|p| Self::lock(&p.session).rekeying()),
                allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
                psk_is_fallback: peer.psk_is_fallback,
                transport: match self.via(&roster, index) {
                    Some(Via::Direct(_)) => Transport::Direct,
                    Some(Via::Relay { .. }) => Transport::Relay,
                    None => Transport::Unreachable,
                },
            })
            .collect()
    }
}

/// What a [`Engine::reconfigure`] actually did.
///
/// Reported rather than inferred from the peer count: an operator seeing a
/// tunnel drop needs to know whether that peer was removed, replaced, or merely
/// carried through a rotation, and the three look identical in a total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reconfigured {
    /// Peers that were not in the previous roster.
    pub added: usize,
    /// Peers dropped from it.
    pub removed: usize,
    /// Peers carried over **with their live session intact**.
    pub kept: usize,
    /// Whether the PSK epoch advanced. Carried sessions keep their keys; only
    /// the next handshake uses the new PSK (§7.3).
    pub epoch_rotated: bool,
}

/// Build a roster, reusing any slot in `carried` whose peer is unchanged.
///
/// Reuse is keyed by `peer_id_hint`, a function of the peer's KEM public key —
/// what a handshake authenticates, and so what makes two entries the *same*
/// peer rather than two peers with one name.
/// A reassembly key for a relay-delivered stream.
///
/// **Disjoint from every [`source_key`] by construction**, and that is the
/// point rather than a nicety. A `SourceKey` is an IPv6-mapped address and a
/// port, so the first byte of a UDP source is either an IPv6 prefix byte or the
/// leading zero of a mapped IPv4 address. Prefixing with a byte no address
/// encoding produces means a relayed stream and a direct stream from the same
/// peer cannot land in the same reassembly slot — which matters exactly during
/// an upgrade, when both are briefly in flight.
fn relay_source_key(id: &[u8; karst_relay_proto::consts::ID_LEN]) -> karst_transport::SourceKey {
    let mut key = [0u8; 18];
    // 0xFF cannot begin a source key: an IPv6 address starting FF00::/8 is
    // multicast, which is not a source address a datagram can arrive from.
    key[0] = 0xFF;
    if let (Some(dst), Some(src)) = (key.get_mut(1..18), id.get(..17)) {
        dst.copy_from_slice(src);
    }
    key
}

fn build_roster(
    config: &Arc<Config>,
    policy: &SuitePolicy,
    carried: &HashMap<[u8; 32], Arc<PeerSlot>>,
) -> Roster {
    let mut peers = Vec::with_capacity(config.peers.len());
    let mut by_hint = HashMap::with_capacity(config.peers.len());
    let mut relay_ids = Vec::with_capacity(config.peers.len());
    let mut by_relay_id = HashMap::with_capacity(config.peers.len());
    let mut home_relays = Vec::with_capacity(config.peers.len());

    for (index, peer) in config.peers.iter().enumerate() {
        let hint = peer_id_hint(&MlKem::public_key_bytes(&peer.public.kem_pk));
        // The control plane renders node ids in base64; Ponor carries the
        // digest. Converted once here rather than on every packet, and a handle
        // that will not decode simply leaves the peer without a relay path
        // instead of failing the whole roster — the direct path, if it has one,
        // still works.
        let relay_id = std::str::from_utf8(&peer.node_id)
            .ok()
            .and_then(karst_control_client::handle_bytes);
        if let Some(id) = relay_id {
            by_relay_id.insert(id, index);
        }
        relay_ids.push(relay_id);
        // §9.1. A published relay this node's registry does not carry is a
        // relay it has no address, TLS name or pinned key for — so it is
        // dropped here, where the peer still has every other route, rather
        // than surfacing as a destination the transport quietly discards.
        home_relays.push(peer.home_relay.filter(|id| {
            config
                .relays
                .iter()
                .any(|registered| registered.relay_id == *id)
        }));
        // The same peer as before keeps its session and its learned endpoint;
        // rebuilding would cost a rehandshake for a change that had nothing to
        // do with this peer.
        let slot = if let Some(existing) = carried.get(&hint) {
            Arc::clone(existing)
        } else {
            // The local session index is what a peer echoes back as
            // `receiver_index`; it must be non-zero and distinct per peer.
            let local_index = u32::try_from(index).unwrap_or(u32::MAX).wrapping_add(1);
            Arc::new(PeerSlot {
                session: Mutex::new(Session::new(
                    Arc::clone(&config.keys),
                    Arc::clone(&peer.public),
                    policy.clone(),
                    SuiteId::KARST_1,
                    config.psk_epoch,
                    local_index,
                )),
                endpoint: RwLock::new(peer.endpoint),
                flows: Mutex::new(crate::flow::Flows::new()),
                off_home: AtomicU64::new(0),
            })
        };
        peers.push(slot);
        by_hint.insert(hint, index);
    }

    Roster {
        relay_configured: !config.relays.is_empty(),
        config: Arc::clone(config),
        peers,
        by_hint,
        relay_ids,
        by_relay_id,
        home_relays,
    }
}

/// One peer's state, for `karst status`.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// Configured name.
    pub name: String,
    /// First bytes of the `peer_id_hint`, hex — enough to identify a peer in a
    /// bug report without disclosing a key.
    pub hint: String,
    /// Where it was last heard from.
    pub endpoint: Option<SocketAddr>,
    /// Whether traffic can flow.
    pub established: bool,
    /// Whether a rekey handshake is in flight.
    pub rekeying: bool,
    /// Ranges this peer owns.
    pub allowed_ips: Vec<String>,
    /// Whether the §7.3 zero-PSK fallback is in use.
    pub psk_is_fallback: bool,
    /// How this peer's traffic currently leaves the node.
    ///
    /// **Not decoration, and not a bool.** A relayed peer works, and works more
    /// slowly, by more hops, and through a third party that sees the timing and
    /// volume of the traffic (`aven-v1.md` §9) — an operator asking "why is
    /// this slow" cannot tell that from the outside. Neither can they tell it
    /// from a peer with *no* path at all, which is a different problem with a
    /// different fix, and which a `relayed: false` would have quietly merged
    /// with the healthy case.
    pub transport: Transport,
}

/// Eight bytes of `peer_id_hint`, hex.
fn short_hint(pk: &<MlKem as karst_crypto::kem::Kem>::PublicKey) -> String {
    let hint = peer_id_hint(&MlKem::public_key_bytes(pk));
    crate::config::encode_hex(hint.get(..8).unwrap_or_default())
}

/// Recover a packet's real length from its IP header.
///
/// Transport plaintext is padded to a 16-byte multiple and carries no length
/// field (§8), so trailing padding must be trimmed using the inner header.
/// Handing the padding to the kernel would present malformed packets to the
/// host stack.
fn ip_total_length(packet: &[u8]) -> Option<usize> {
    match karst_tun::ip::version(packet)? {
        // IPv4 total length covers header plus payload.
        karst_tun::ip::Version::V4 => {
            let b = packet.get(2..4)?.first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*b));
            (len >= 20 && len <= packet.len()).then_some(len)
        }
        // IPv6 payload length excludes the 40-byte fixed header.
        karst_tun::ip::Version::V6 => {
            let b = packet.get(4..6)?.first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*b)).checked_add(40)?;
            (len <= packet.len()).then_some(len)
        }
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

    fn v4(src: [u8; 4], dst: [u8; 4], payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; 20 + payload];
        p[0] = 0x45;
        let total = u16::try_from(20 + payload).expect("small");
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn ipv4_length_comes_from_the_header() {
        let p = v4([10, 0, 0, 1], [10, 0, 0, 2], 8);
        assert_eq!(ip_total_length(&p), Some(28));
    }

    /// The padding §8 adds must be trimmed off using the inner header, or the
    /// host stack is handed a packet longer than it claims to be.
    #[test]
    fn padding_is_trimmed_using_the_inner_header() {
        let mut p = v4([10, 0, 0, 1], [10, 0, 0, 2], 8);
        p.extend_from_slice(&[0u8; 4]); // pad to a 16-byte multiple
        assert_eq!(ip_total_length(&p), Some(28), "padding must not be counted");
    }

    /// A header claiming more than arrived is a malformed packet, not a reason
    /// to read past the buffer.
    #[test]
    fn a_length_beyond_the_buffer_is_rejected() {
        let mut p = v4([10, 0, 0, 1], [10, 0, 0, 2], 8);
        p[2..4].copy_from_slice(&9000u16.to_be_bytes());
        assert_eq!(ip_total_length(&p), None);
    }

    #[test]
    fn an_ipv4_length_below_the_header_is_rejected() {
        let mut p = v4([10, 0, 0, 1], [10, 0, 0, 2], 8);
        p[2..4].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(ip_total_length(&p), None);
    }

    #[test]
    fn ipv6_length_excludes_the_fixed_header() {
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(ip_total_length(&p), Some(48));
    }

    #[test]
    fn garbage_has_no_length() {
        assert_eq!(ip_total_length(&[]), None);
        assert_eq!(ip_total_length(&[0xFF; 64]), None);
        assert_eq!(ip_total_length(&[0x45]), None);
    }

    // ── the relay transport ───────────────────────────────────────────────

    /// **The reassembler must never confuse a relayed stream with a direct
    /// one.** Both carry PHREATIC fragments from the same peer, and during an
    /// upgrade both are briefly in flight; a shared key would let fragments
    /// from one interleave into the other's message.
    ///
    /// The property is structural rather than probabilistic: a `SourceKey`
    /// begins with the first byte of an IPv6 address, and `0xFF` there is
    /// multicast — not something a datagram can arrive *from*.
    #[test]
    fn a_relayed_stream_cannot_collide_with_any_udp_source() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let relayed = relay_source_key(&[0x11; 32]);
        assert_eq!(relayed.first(), Some(&0xFF));

        // Every address family, including the ones whose encodings are most
        // likely to collide: IPv4-mapped (leading zeros) and a v6 address
        // chosen to start as high as a unicast address can.
        let sources = [
            SocketAddr::from((Ipv4Addr::new(255, 255, 255, 255), 65535)),
            SocketAddr::from((Ipv4Addr::new(0, 0, 0, 0), 0)),
            SocketAddr::from((Ipv6Addr::from([0xFE; 16]), 51820)),
            SocketAddr::from((Ipv6Addr::from([0xFF; 16]), 51820)),
        ];
        for source in sources {
            assert_ne!(
                source_key(source),
                relayed,
                "a relayed stream collided with the UDP source {source}"
            );
        }
    }

    /// Two peers on the relay get different reassembly keys, or one peer's
    /// fragments would complete another's message.
    #[test]
    fn each_relayed_peer_has_its_own_reassembly_key() {
        let mut a = [0x11; 32];
        let mut b = [0x11; 32];
        assert_ne!(
            relay_source_key(&a),
            relay_source_key(&{
                b[0] = 0x12;
                b
            })
        );
        // And a difference beyond the truncation point is *not* distinguished,
        // which is a real limit rather than an oversight: a `SourceKey` is 18
        // bytes and a node id is 32, so the key carries the leading 17. Two ids
        // agreeing on all of those are a 136-bit collision, and the cost of
        // being wrong is one dropped message rather than a security property.
        a[31] = 0x99;
        assert_eq!(relay_source_key(&[0x11; 32]), relay_source_key(&a));
    }
}
