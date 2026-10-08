// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

//! The forwarding core — `spec/ponor-v1.md` §7.2, §7.3, §7.5, §7.6 and §8.
//!
//! Sans-io, like the protocol crates below it. The hub owns the connection
//! registry, the presence table and the per-destination write queues; it does
//! not own a socket, a clock or a task. Frames go in with a timestamp, bytes
//! come out of [`Hub::take_outbound`].
//!
//! The queues live here rather than in the I/O layer on purpose. §7.3 makes
//! the queue discipline a **correctness** requirement — bounded, drop-oldest,
//! never applying backpressure to the source — and a rule that is a property
//! of the code that touches sockets is a rule nobody can unit-test.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use karst_relay_proto::consts::{ID_LEN, TOKEN_LEN};
use karst_relay_proto::{Admitted, AquiferId, Frame, Reason, Roster};

use crate::limits::{Budget, Meter};

/// A 32-byte node or relay identifier.
pub type Id = [u8; ID_LEN];

/// The I/O layer's handle for a connection. Opaque to the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(pub u64);

/// Why a frame did not reach a destination.
///
/// Every one of these is a **drop**, never a close: §7.4 forbids ending a
/// connection over a burst, and the rest are ordinary consequences of a
/// distributed presence table that is eventually consistent by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// Over the peer's rate budget — §7.4.
    RateLimited,
    /// Over the *aquifer's* aggregate rate budget — §13 #9 / ADR-0038.
    ///
    /// Distinct from [`Dropped::RateLimited`], which is per-connection: this
    /// fires even when the sending node is well within its own allowance,
    /// because some other node sharing its aquifer has used the aquifer's
    /// share of this relay's capacity. Only reachable when
    /// [`Config::aquifer_budget`] is configured; `None` (the default) never
    /// produces this.
    AquiferRateLimited,
    /// The destination is not in the roster, or not in this aquifer — §5.4.
    NotAdmitted,
    /// Nobody here or on the mesh holds the destination.
    NotHere,
    /// A peer addressed itself.
    SelfAddressed,
    /// The destination's write queue was full — §7.3.
    QueueFull,
}

/// A frame that is legal on the wire but not on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubError {
    /// §8: a relay MUST NOT accept `SendPacket` on a mesh connection, nor
    /// `Forward` on a client one. Also covers relay→peer frames arriving from
    /// a peer, which is either a bug or a probe.
    IllegalForRole,
    /// The connection is not registered. A caller bug, not a peer's.
    UnknownConn,
}

/// Per-connection accounting for the operator — §7.4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// Frames accepted from the peer.
    pub frames_in: u64,
    /// Bytes accepted from the peer, frame headers included.
    pub bytes_in: u64,
    /// Frames queued towards the peer.
    pub frames_out: u64,
    /// Bytes queued towards the peer.
    pub bytes_out: u64,
    /// Frames refused by the per-connection rate limiter.
    pub dropped_rate: u64,
    /// Frames from this peer refused by its aquifer's aggregate rate limiter
    /// — ADR-0038. Always zero when [`Config::aquifer_budget`] is `None`.
    pub dropped_aquifer_rate: u64,
    /// Frames discarded because this peer's write queue was full.
    pub dropped_queue: u64,
    /// Frames from this peer that could not be delivered.
    pub undeliverable: u64,
}

impl ConnStats {
    /// Fold another connection's totals into these.
    ///
    /// Saturating rather than wrapping: a counter that wraps is worse than one
    /// that sticks, because a monitoring system reads the wrap as a reset and
    /// a stick as a plateau — and only one of those is a lie about the
    /// direction of travel.
    fn absorb(&mut self, other: Self) {
        self.frames_in = self.frames_in.saturating_add(other.frames_in);
        self.bytes_in = self.bytes_in.saturating_add(other.bytes_in);
        self.frames_out = self.frames_out.saturating_add(other.frames_out);
        self.bytes_out = self.bytes_out.saturating_add(other.bytes_out);
        self.dropped_rate = self.dropped_rate.saturating_add(other.dropped_rate);
        self.dropped_aquifer_rate = self
            .dropped_aquifer_rate
            .saturating_add(other.dropped_aquifer_rate);
        self.dropped_queue = self.dropped_queue.saturating_add(other.dropped_queue);
        self.undeliverable = self.undeliverable.saturating_add(other.undeliverable);
    }
}

/// How the hub is configured.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Rate allowance for a node.
    pub client_budget: Budget,
    /// Rate allowance for a meshed relay, which carries many nodes' traffic
    /// and so cannot share a node's budget.
    pub mesh_budget: Budget,
    /// Aggregate rate allowance shared by every node in one aquifer —
    /// §13 #9 / ADR-0038.
    ///
    /// `None` (the default) is fully inert: no aquifer-level accounting is
    /// done at all, and forwarding is governed by [`Self::client_budget`]
    /// alone, exactly as before this field existed. A single-tenant
    /// deployment, or an operator who has not opted in, sees no change.
    ///
    /// Configured, this caps the *total* traffic one aquifer may push
    /// through this relay, independent of how many nodes it has — the gap
    /// `ponor-v1.md` §13 #9 names: nothing today stops one aquifer with many
    /// nodes from consuming a shared relay's entire capacity within each
    /// node's own per-connection limit.
    pub aquifer_budget: Option<Budget>,
    /// Per-destination write queue depth — §7.3.
    pub queue_depth: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            client_budget: Budget::default(),
            mesh_budget: Budget::unlimited(),
            aquifer_budget: None,
            queue_depth: karst_relay_proto::consts::WRITE_QUEUE_DEPTH,
        }
    }
}

#[derive(Debug)]
struct Conn {
    peer: Admitted,
    queue: VecDeque<Vec<u8>>,
    meter: Meter,
    close_after_flush: Option<Reason>,
    stats: ConnStats,
    /// §4a's RTT probe: the token and send time of an outstanding
    /// relay-initiated `Ping`, if this connection has one out that has not
    /// yet been answered. At most one at a time — a second probe before the
    /// first resolves would leave an answering `Pong` ambiguous about which
    /// send it is timing.
    pending_ping: Option<(u64, u64)>,
    /// Strictly increasing, so a `Pong` cannot be mistaken for the answer to
    /// an earlier, abandoned probe — see [`Hub::resolve_ping`].
    ping_seq: u64,
    /// This connection's most recently measured RTT, in milliseconds —
    /// ADR-0045 §4a. `None` until the first probe answers; never reset by a
    /// probe that times out or a `Pong` that does not match, so a
    /// momentarily slow or silent peer does not fall out of the histogram
    /// entirely, it just goes stale.
    last_rtt_ms: Option<u32>,
}

impl Conn {
    fn node_id(&self) -> Option<Id> {
        match self.peer {
            Admitted::Client { node_id, .. } => Some(node_id),
            Admitted::Mesh { .. } => None,
        }
    }
    fn relay_id(&self) -> Option<Id> {
        match self.peer {
            Admitted::Mesh { relay_id } => Some(relay_id),
            Admitted::Client { .. } => None,
        }
    }
    fn aquifer(&self) -> Option<&AquiferId> {
        match &self.peer {
            Admitted::Client { aquifer, .. } => Some(aquifer),
            Admitted::Mesh { .. } => None,
        }
    }
}

/// The relay's connection registry and forwarding engine.
///
/// `BTreeMap` rather than `HashMap` for the connection table: fan-out to mesh
/// peers then happens in a deterministic order, which makes a test that
/// asserts on gossip reproducible instead of flaky.
#[derive(Debug)]
pub struct Hub {
    cfg: Config,
    conns: BTreeMap<ConnId, Conn>,
    by_node: HashMap<Id, ConnId>,
    by_mesh: HashMap<Id, ConnId>,
    /// Everything the connections that have gone accounted for.
    ///
    /// **Kept because a counter that resets is not a counter.** `ConnStats`
    /// lives on the connection and dies with it, which is right for the
    /// per-connection view an operator asks for by id — but a relay's totals
    /// must only ever go up, or every disconnect reads downstream as a restart.
    retired: ConnStats,
    /// Which meshed relay holds a node that is not connected here — §8.
    ///
    /// Advisory. A relay MUST tolerate a `Forward` for a node that has just
    /// left, and MUST NOT treat presence disagreement as an error: the state
    /// is eventually consistent by construction and anything stricter would
    /// fail on every client roam.
    presence: HashMap<Id, Id>,
    /// Aggregate meters, one per aquifer that has forwarded a frame —
    /// ADR-0038. Created lazily, on that aquifer's first charge, so an
    /// aquifer nobody uses never allocates one. Empty and never consulted
    /// when [`Config::aquifer_budget`] is `None`.
    aquifer_meters: HashMap<AquiferId, Meter>,
    /// Connections whose queue has grown since the caller last asked.
    ///
    /// The hub is pull-based, so an I/O layer needs to know *which* sockets to
    /// wake. Waking every connection after every frame would make a relay's
    /// cost quadratic in its client count; this keeps it proportional to the
    /// work actually done.
    dirty: BTreeSet<ConnId>,
}

impl Hub {
    /// An empty hub.
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            retired: ConnStats::default(),
            conns: BTreeMap::new(),
            by_node: HashMap::new(),
            by_mesh: HashMap::new(),
            presence: HashMap::new(),
            aquifer_meters: HashMap::new(),
            dirty: BTreeSet::new(),
        }
    }

    /// Connections with something new to write, cleared by the call.
    pub fn take_dirty(&mut self) -> Vec<ConnId> {
        core::mem::take(&mut self.dirty).into_iter().collect()
    }

    /// Register a connection whose handshake has completed.
    ///
    /// Returns the connection this one **replaced**, if any. §7.6: newest
    /// wins, and the caller must close the returned connection with
    /// [`Reason::Replaced`]. Refusing the new connection instead would
    /// black-hole a node whose old TCP connection is a half-open zombie the
    /// relay has not timed out — the common case after a suspend or a mobile
    /// handover. It is safe because it requires the peer's identity key.
    pub fn admit(&mut self, id: ConnId, peer: Admitted, now_ms: u64) -> Option<ConnId> {
        let (budget, replaced, announce) = match &peer {
            Admitted::Client { node_id, .. } => {
                let prev = self.by_node.insert(*node_id, id);
                // Only announce presence the mesh does not already have. A
                // replacement is not an arrival: the node never left.
                (self.cfg.client_budget, prev, prev.is_none())
            }
            Admitted::Mesh { relay_id } => {
                let prev = self.by_mesh.insert(*relay_id, id);
                (self.cfg.mesh_budget, prev, false)
            }
        };

        let is_mesh = matches!(peer, Admitted::Mesh { .. });
        self.conns.insert(
            id,
            Conn {
                peer,
                queue: VecDeque::new(),
                meter: Meter::new(budget, now_ms),
                close_after_flush: None,
                stats: ConnStats::default(),
                pending_ping: None,
                ping_seq: 0,
                last_rtt_ms: None,
            },
        );

        if announce {
            if let Some(node_id) = self.conns.get(&id).and_then(Conn::node_id) {
                self.gossip(&Frame::PeerPresent { node_id }, None);
            }
        }
        if is_mesh {
            // §8: on establishment each side sends PeerPresent for every
            // client it currently holds. Bounded by the connected count.
            let locals: Vec<Id> = self.by_node.keys().copied().collect();
            for node_id in locals {
                self.enqueue(id, &Frame::PeerPresent { node_id });
            }
        }

        // A replacement of *this same* id is not a replacement of a live
        // connection when the previous entry is the one we just wrote.
        replaced.filter(|prev| *prev != id)
    }

    /// Handle one inbound frame.
    ///
    /// # Errors
    /// [`HubError::IllegalForRole`] for a frame this connection may not send —
    /// the caller must close, per §10. [`HubError::UnknownConn`] is a caller
    /// bug.
    pub fn on_frame(
        &mut self,
        id: ConnId,
        frame: &Frame<'_>,
        roster: &impl Roster,
        now_ms: u64,
    ) -> Result<Option<Dropped>, HubError> {
        let len = frame.encoded_len() as u64;
        let conn = self.conns.get_mut(&id).ok_or(HubError::UnknownConn)?;

        // Charged before anything is done with the frame, and charged on every
        // frame rather than only on SendPacket: a Ping flood is cheap in bytes
        // and is still work.
        if !conn.meter.admit(len, now_ms) {
            conn.stats.dropped_rate += 1;
            return Ok(Some(Dropped::RateLimited));
        }
        conn.stats.frames_in += 1;
        conn.stats.bytes_in += len;

        let is_mesh = conn.relay_id().is_some();
        match (*frame, is_mesh) {
            // ── Either role ───────────────────────────────────────────────
            (Frame::Ping(token), _) => {
                // §7.5: ahead of queued RecvPacket frames. A keepalive stuck
                // behind a full queue is a keepalive that misses its deadline
                // and takes the connection down with it.
                self.enqueue_priority(id, &Frame::Pong(token));
                Ok(None)
            }
            // Answers either the peer's own keepalive probe (nothing for the
            // relay to do with that) or this relay's own §4a probe — telling
            // the two apart, and ignoring a `Pong` that answers neither, is
            // `resolve_ping`'s job.
            (Frame::Pong(token), _) => {
                self.resolve_ping(id, *token, now_ms);
                Ok(None)
            }
            (Frame::Close(_), _) => {
                self.begin_close(id, None);
                Ok(None)
            }

            // ── Client only ───────────────────────────────────────────────
            (Frame::SendPacket { dst_id, payload }, false) => {
                Ok(self.forward_from_client(id, dst_id, payload, roster, now_ms))
            }

            // ── Mesh only ─────────────────────────────────────────────────
            (
                Frame::Forward {
                    src_id,
                    dst_id,
                    payload,
                },
                true,
            ) => Ok(self.deliver_from_mesh(id, src_id, dst_id, payload, roster, now_ms)),
            (Frame::PeerPresent { node_id }, true) => {
                if let Some(relay_id) = self.conns.get(&id).and_then(Conn::relay_id) {
                    self.presence.insert(node_id, relay_id);
                }
                Ok(None)
            }
            (Frame::PeerGone { peer_id, .. }, true) => {
                // Only the relay that claimed a node may retract it.
                let owner = self.conns.get(&id).and_then(Conn::relay_id);
                if self.presence.get(&peer_id).copied() == owner {
                    self.presence.remove(&peer_id);
                }
                Ok(None)
            }

            // Everything else is either a relay→peer frame arriving from a
            // peer, or a frame for the other role. §8's role separation is
            // enforced here and nowhere else.
            _ => Err(HubError::IllegalForRole),
        }
    }

    /// §7.2. The relay stamps the connection's authenticated id as the source;
    /// `SendPacket` has no source field, so there is nothing to spoof.
    fn forward_from_client(
        &mut self,
        from: ConnId,
        dst_id: Id,
        payload: &[u8],
        roster: &impl Roster,
        now_ms: u64,
    ) -> Option<Dropped> {
        let conn = self.conns.get(&from)?;
        let (Some(src_id), Some(src_aquifer)) = (conn.node_id(), conn.aquifer().cloned()) else {
            return None;
        };

        if dst_id == src_id {
            self.count_undeliverable(from);
            return Some(Dropped::SelfAddressed);
        }

        // §5.4. "Unknown" and "in another aquifer" deliberately produce the
        // same outcome and the same NOT_ADMITTED code: distinguishing them
        // would tell one tenant whether an id exists in another, which is a
        // cross-customer membership oracle on a shared relay.
        let admitted = roster
            .client(&dst_id)
            .is_some_and(|e| e.aquifer == src_aquifer);
        if !admitted {
            self.reply(
                from,
                &Frame::PeerGone {
                    peer_id: dst_id,
                    reason: Reason::NotAdmitted,
                },
            );
            self.count_undeliverable(from);
            return Some(Dropped::NotAdmitted);
        }

        // ADR-0038: checked after admission (a rejected destination never
        // touches the aquifer's shared budget) and before delivery — a drop
        // here is silent, exactly as §7.4's per-connection limiter is,
        // because both are the same kind of fact: a burst, not an attack.
        if !self.charge_aquifer(&src_aquifer, payload.len() as u64, now_ms) {
            if let Some(conn) = self.conns.get_mut(&from) {
                conn.stats.dropped_aquifer_rate += 1;
            }
            return Some(Dropped::AquiferRateLimited);
        }

        if let Some(&to) = self.by_node.get(&dst_id) {
            return self.deliver(from, to, &Frame::RecvPacket { src_id, payload });
        }

        if let Some(to) = self
            .presence
            .get(&dst_id)
            .and_then(|relay| self.by_mesh.get(relay))
            .copied()
        {
            return self.deliver(
                from,
                to,
                &Frame::Forward {
                    src_id,
                    dst_id,
                    payload,
                },
            );
        }

        self.reply(
            from,
            &Frame::PeerGone {
                peer_id: dst_id,
                reason: Reason::NotHere,
            },
        );
        self.count_undeliverable(from);
        Some(Dropped::NotHere)
    }

    /// §8. **One hop.** A `Forward` is delivered locally or not at all; it is
    /// never forwarded onward, so a mesh loop is not expressible rather than
    /// merely bounded.
    fn deliver_from_mesh(
        &mut self,
        from: ConnId,
        src_id: Id,
        dst_id: Id,
        payload: &[u8],
        roster: &impl Roster,
        now_ms: u64,
    ) -> Option<Dropped> {
        let Some(&to) = self.by_node.get(&dst_id) else {
            // Our presence claim reached them and the node has since left.
            // Correcting the sender's table is the whole reason this is not a
            // silent drop.
            self.reply(
                from,
                &Frame::PeerGone {
                    peer_id: dst_id,
                    reason: Reason::Disconnected,
                },
            );
            self.count_undeliverable(from);
            return Some(Dropped::NotHere);
        };

        // The originating relay already checked §5.4, and we check it again
        // against our own roster. A meshed relay is other infrastructure, not
        // an oracle we have to believe: re-checking here is what stops a
        // compromised mesh peer from injecting cross-aquifer traffic, and it
        // costs one lookup we were going to do anyway.
        let dst_aquifer = match (roster.client(&src_id), roster.client(&dst_id)) {
            (Some(s), Some(d)) if s.aquifer == d.aquifer => Some(d.aquifer),
            _ => None,
        };
        let Some(dst_aquifer) = dst_aquifer else {
            self.count_undeliverable(from);
            return Some(Dropped::NotAdmitted);
        };

        // ADR-0038: a mesh-delivered frame spends the same local aquifer
        // budget a directly-connected client's would — otherwise an aquifer
        // could exceed this relay's per-aquifer share simply by routing
        // through a mesh peer instead of connecting here directly.
        if !self.charge_aquifer(&dst_aquifer, payload.len() as u64, now_ms) {
            self.count_undeliverable(from);
            return Some(Dropped::AquiferRateLimited);
        }

        self.deliver(from, to, &Frame::RecvPacket { src_id, payload })
    }

    /// Charge `bytes` against `aquifer`'s aggregate meter, creating it on
    /// first use. Always admits when [`Config::aquifer_budget`] is `None` —
    /// ADR-0038's fully-inert default.
    fn charge_aquifer(&mut self, aquifer: &AquiferId, bytes: u64, now_ms: u64) -> bool {
        let Some(budget) = self.cfg.aquifer_budget else {
            return true;
        };
        self.aquifer_meters
            .entry(aquifer.clone())
            .or_insert_with(|| Meter::new(budget, now_ms))
            .admit(bytes, now_ms)
    }

    fn deliver(&mut self, from: ConnId, to: ConnId, frame: &Frame<'_>) -> Option<Dropped> {
        if self.enqueue(to, frame) {
            None
        } else {
            self.count_undeliverable(from);
            Some(Dropped::QueueFull)
        }
    }

    /// Queue a frame towards `to`, dropping the **oldest** on overflow.
    ///
    /// Returns whether it went in without displacing anything.
    ///
    /// §7.3, and the two halves are separate requirements. *Bounded* is what
    /// stops a slow destination from being a memory-exhaustion vector.
    /// *Never blocking* is what stops it from being everyone else's problem:
    /// a relay that lets one slow peer apply backpressure to a source's read
    /// loop has made every other peer of that source hostage to the slowest.
    ///
    /// Dropping the head rather than the tail keeps the queue's contents
    /// fresh — everything in it is either a handshake retransmission or a
    /// datagram whose usefulness decays.
    fn enqueue(&mut self, to: ConnId, frame: &Frame<'_>) -> bool {
        let depth = self.cfg.queue_depth;
        let Some(conn) = self.conns.get_mut(&to) else {
            return false;
        };
        let bytes = frame.encoded_len() as u64;
        let mut clean = true;
        while conn.queue.len() >= depth {
            conn.queue.pop_front();
            conn.stats.dropped_queue += 1;
            clean = false;
        }
        conn.queue.push_back(frame.to_vec());
        conn.stats.frames_out += 1;
        conn.stats.bytes_out += bytes;
        self.dirty.insert(to);
        clean
    }

    /// Queue at the head, past whatever is waiting.
    ///
    /// For `Pong` (§7.5) and this relay's own outbound `Ping` (ADR-0045
    /// §4a) only. Anything else jumping the queue would reorder a peer's
    /// datagrams for no reason; these two are exempted for different
    /// reasons — a `Pong` is a keepalive whose deadline a full queue could
    /// miss, and a `Ping` whose own send is delayed behind other traffic
    /// would measure this relay's queueing, not the path to the peer.
    fn enqueue_priority(&mut self, to: ConnId, frame: &Frame<'_>) {
        let depth = self.cfg.queue_depth;
        let Some(conn) = self.conns.get_mut(&to) else {
            return;
        };
        let bytes = frame.encoded_len() as u64;
        while conn.queue.len() >= depth {
            conn.queue.pop_front();
            conn.stats.dropped_queue += 1;
        }
        conn.queue.push_front(frame.to_vec());
        conn.stats.frames_out += 1;
        conn.stats.bytes_out += bytes;
        self.dirty.insert(to);
    }

    fn reply(&mut self, to: ConnId, frame: &Frame<'_>) {
        self.enqueue(to, frame);
    }

    fn count_undeliverable(&mut self, id: ConnId) {
        if let Some(conn) = self.conns.get_mut(&id) {
            conn.stats.undeliverable += 1;
        }
    }

    fn gossip(&mut self, frame: &Frame<'_>, except: Option<ConnId>) {
        let peers: Vec<ConnId> = self
            .by_mesh
            .values()
            .copied()
            .filter(|c| Some(*c) != except)
            .collect();
        for peer in peers {
            self.enqueue(peer, frame);
        }
    }

    /// Ask the relay to shut this connection down once its queue has drained.
    pub fn begin_close(&mut self, id: ConnId, reason: Option<Reason>) {
        if let Some(conn) = self.conns.get_mut(&id) {
            if let Some(r) = reason {
                conn.queue.push_back(Frame::Close(r).to_vec());
            }
            conn.close_after_flush = Some(reason.unwrap_or(Reason::Disconnected));
            self.dirty.insert(id);
        }
    }

    /// Tell every directly connected client this relay is going away, then
    /// close their connections once the notice has been written — `ponor-v1.md`
    /// §7.6.
    ///
    /// **`Restarting` goes in front of the close, not instead of it.** The
    /// frame is what turns a dropped connection into a coordinated move: a
    /// client that has seen it waits `reconnect_in_ms` plus its own jitter, and
    /// one that has not treats the close as a dead relay. Mesh peers are left
    /// alone — they redial on their own schedule and have no jitter to apply.
    ///
    /// Returns how many clients were told.
    pub fn begin_restart(&mut self, reconnect_in_ms: u32, try_for_ms: u32) -> usize {
        let clients: Vec<ConnId> = self.by_node.values().copied().collect();
        for &id in &clients {
            self.enqueue_priority(
                id,
                &Frame::Restarting {
                    reconnect_in_ms,
                    try_for_ms,
                },
            );
            self.begin_close(id, None);
        }
        clients.len()
    }

    /// Forget a connection and correct the tables that referred to it.
    ///
    /// Returns the client whose mapping this actually released, which is
    /// `None` for a mesh peer and for a connection that had already been
    /// replaced. The caller needs that distinction to retire the same node's
    /// reflect key (`ponor-v1.md` §7.7) without retiring its *successor's* —
    /// and deriving it from `Admitted` at the call site would be a second copy
    /// of the ownership rule below, free to drift from it.
    pub fn disconnect(&mut self, id: ConnId) -> Option<[u8; ID_LEN]> {
        let conn = self.conns.remove(&id)?;
        self.retired.absorb(conn.stats);
        let mut released = None;

        if let Some(node_id) = conn.node_id() {
            // Only if this connection is still the one that owns the id: a
            // replaced connection closing later must not retract the mapping
            // its successor now holds, nor announce a departure that did not
            // happen.
            if self.by_node.get(&node_id) == Some(&id) {
                self.by_node.remove(&node_id);
                released = Some(node_id);
                self.gossip(
                    &Frame::PeerGone {
                        peer_id: node_id,
                        reason: Reason::Disconnected,
                    },
                    None,
                );
            }
        }

        if let Some(relay_id) = conn.relay_id() {
            if self.by_mesh.get(&relay_id) == Some(&id) {
                self.by_mesh.remove(&relay_id);
                // Every presence claim this peer made goes with it. Leaving
                // them would send Forwards into a connection that no longer
                // exists, for as long as the process runs.
                self.presence.retain(|_, owner| *owner != relay_id);
            }
        }
        released
    }

    /// The next frame to write to `id`, if any.
    pub fn take_outbound(&mut self, id: ConnId) -> Option<Vec<u8>> {
        self.conns.get_mut(&id)?.queue.pop_front()
    }

    /// Whether the caller should close `id` once its queue has drained.
    #[must_use]
    pub fn close_reason(&self, id: ConnId) -> Option<Reason> {
        self.conns.get(&id)?.close_after_flush
    }

    /// Frames waiting to be written to `id`.
    #[must_use]
    pub fn pending(&self, id: ConnId) -> usize {
        self.conns.get(&id).map_or(0, |c| c.queue.len())
    }

    /// Everything this relay has carried since it started.
    ///
    /// Live connections plus the ones that have gone, so the numbers are
    /// monotonic and a scrape can be differentiated. A sum over live
    /// connections alone would fall every time a client left.
    #[must_use]
    pub fn totals(&self) -> ConnStats {
        let mut out = self.retired;
        for conn in self.conns.values() {
            out.absorb(conn.stats);
        }
        out
    }

    /// Whether a mesh connection to this relay already exists.
    ///
    /// Asked by the dialler rather than tracked there, so there is one answer
    /// to the question instead of two that can disagree.
    #[must_use]
    pub fn has_mesh(&self, relay_id: &Id) -> bool {
        self.by_mesh.contains_key(relay_id)
    }

    /// Accounting for the operator — §7.4.
    #[must_use]
    pub fn stats(&self, id: ConnId) -> Option<ConnStats> {
        self.conns.get(&id).map(|c| c.stats)
    }

    /// Nodes connected directly to this relay.
    #[must_use]
    pub fn local_clients(&self) -> usize {
        self.by_node.len()
    }

    /// Meshed relays currently connected.
    #[must_use]
    pub fn mesh_peers(&self) -> usize {
        self.by_mesh.len()
    }

    /// Nodes reachable through a meshed relay rather than directly.
    #[must_use]
    pub fn remote_clients(&self) -> usize {
        self.presence.len()
    }

    /// Send a `Ping` to measure round-trip latency to a connection's peer —
    /// ADR-0045 §4a's demand-attribution signal.
    ///
    /// Returns whether a probe actually went out. `false` for a mesh
    /// connection (§4a's histogram is about clients, not meshed relays, and
    /// this is where that distinction is made so a caller sweeping every
    /// connection need not know it), an unknown connection, or a client
    /// that already has one outstanding.
    pub fn probe_rtt(&mut self, id: ConnId, now_ms: u64) -> bool {
        let Some(conn) = self.conns.get_mut(&id) else {
            return false;
        };
        if conn.node_id().is_none() || conn.pending_ping.is_some() {
            return false;
        }
        conn.ping_seq = conn.ping_seq.wrapping_add(1);
        let token = conn.ping_seq;
        conn.pending_ping = Some((token, now_ms));
        self.enqueue_priority(id, &Frame::Ping(&token.to_be_bytes()));
        true
    }

    /// Resolve a `Pong` against this connection's outstanding §4a probe, if
    /// it has one and `token` is the answer to it.
    ///
    /// A `Pong` that does not match — nothing was pending, or the token is
    /// someone else's — is silently ignored rather than treated as an
    /// error: it is also legitimately the peer's own §7.5 keepalive
    /// surfacing here, or the answer to a probe this relay already gave up
    /// on, and neither is a protocol violation.
    fn resolve_ping(&mut self, id: ConnId, token: [u8; TOKEN_LEN], now_ms: u64) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        let Some((expected, sent_ms)) = conn.pending_ping else {
            return;
        };
        if expected.to_be_bytes() != token {
            return;
        }
        conn.pending_ping = None;
        let rtt_ms = now_ms.saturating_sub(sent_ms);
        conn.last_rtt_ms = Some(u32::try_from(rtt_ms).unwrap_or(u32::MAX));
    }

    /// ADR-0045 §4a's bucketed RTT histogram: how many currently connected
    /// *clients* last measured under 20ms, 20–50ms, 50–100ms, and over
    /// 100ms. Meshed relays are excluded — see [`Self::probe_rtt`] — and a
    /// client never yet successfully probed contributes to none of the four
    /// buckets rather than being assumed into any particular one, including
    /// the most favorable.
    #[must_use]
    pub fn rtt_histogram(&self) -> RttHistogram {
        let mut h = RttHistogram::default();
        for conn in self.conns.values() {
            if conn.node_id().is_none() {
                continue;
            }
            if let Some(ms) = conn.last_rtt_ms {
                h.record(ms);
            }
        }
        h
    }
}

/// ADR-0045 §4a's RTT histogram — aggregate counts only, never a per-client
/// value, matching the discipline ADR-0021's existing fields already use.
/// Bucket boundaries are the ADR's own text, verbatim: "N clients under
/// 20 ms, N at 20–50 ms, N at 50–100 ms, N over 100 ms."
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttHistogram {
    pub under_20ms: u64,
    pub ms_20_to_50: u64,
    pub ms_50_to_100: u64,
    pub over_100ms: u64,
}

impl RttHistogram {
    fn record(&mut self, rtt_ms: u32) {
        match rtt_ms {
            0..=19 => self.under_20ms += 1,
            20..=49 => self.ms_20_to_50 += 1,
            50..=99 => self.ms_50_to_100 += 1,
            _ => self.over_100ms += 1,
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
    use karst_relay_proto::{RelayEntry, RosterEntry};

    struct TestRoster {
        aquifers: HashMap<Id, &'static str>,
    }

    impl TestRoster {
        fn new() -> Self {
            Self {
                aquifers: HashMap::new(),
            }
        }
        fn with(mut self, id: Id, aquifer: &'static str) -> Self {
            self.aquifers.insert(id, aquifer);
            self
        }
    }

    impl Roster for TestRoster {
        fn client(&self, node_id: &Id) -> Option<RosterEntry> {
            self.aquifers.get(node_id).map(|t| RosterEntry {
                identity_pk: vec![0; 2592],
                aquifer: AquiferId((*t).to_owned()),
            })
        }
        fn mesh_peer(&self, _: &Id) -> Option<RelayEntry> {
            None
        }
        fn decoy_key(&self) -> &[u8] {
            &[]
        }
    }

    fn id(b: u8) -> Id {
        [b; ID_LEN]
    }

    fn client(node: u8, aquifer: &str) -> Admitted {
        Admitted::Client {
            node_id: id(node),
            aquifer: AquiferId(aquifer.to_owned()),
        }
    }

    fn mesh(relay: u8) -> Admitted {
        Admitted::Mesh {
            relay_id: id(relay),
        }
    }

    /// Decode everything queued for a connection.
    fn drain(hub: &mut Hub, conn: ConnId) -> Vec<Frame<'static>> {
        let mut out = Vec::new();
        while let Some(bytes) = hub.take_outbound(conn) {
            let (f, _) = karst_relay_proto::frame::decode(&bytes)
                .expect("relay emitted an undecodable frame")
                .expect("relay emitted a truncated frame");
            // Re-encode into an owned frame so the borrow of `bytes` ends.
            out.push(match f {
                Frame::RecvPacket { src_id, payload } => Frame::RecvPacket {
                    src_id,
                    payload: Box::leak(payload.to_vec().into_boxed_slice()),
                },
                Frame::Forward {
                    src_id,
                    dst_id,
                    payload,
                } => Frame::Forward {
                    src_id,
                    dst_id,
                    payload: Box::leak(payload.to_vec().into_boxed_slice()),
                },
                // Previously collapsed into `Frame::Pong` regardless, back
                // when the relay never emitted an outbound `Ping` of its
                // own (ADR-0045 §4a) and every token-carrying frame this
                // helper ever drained was a reply. Kept distinct now that
                // both occur.
                Frame::Ping(t) => Frame::Ping(Box::leak(Box::new(*t))),
                Frame::Pong(t) => Frame::Pong(Box::leak(Box::new(*t))),
                Frame::PeerGone { peer_id, reason } => Frame::PeerGone { peer_id, reason },
                Frame::PeerPresent { node_id } => Frame::PeerPresent { node_id },
                Frame::Close(r) => Frame::Close(r),
                Frame::Restarting {
                    reconnect_in_ms,
                    try_for_ms,
                } => Frame::Restarting {
                    reconnect_in_ms,
                    try_for_ms,
                },
                other => panic!("unexpected frame {other:?}"),
            });
        }
        out
    }

    const A: ConnId = ConnId(1);
    const B: ConnId = ConnId(2);
    const M: ConnId = ConnId(3);

    fn two_clients() -> (Hub, TestRoster) {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");
        (hub, roster)
    }

    #[test]
    fn a_packet_reaches_a_local_peer_with_the_source_stamped() {
        let (mut hub, roster) = two_clients();
        let payload = [7u8; 100];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, None);

        let got = drain(&mut hub, B);
        assert_eq!(got.len(), 1);
        match got[0] {
            Frame::RecvPacket { src_id, payload: p } => {
                // The source is the connection's authenticated id, not
                // anything the sender supplied — SendPacket has no source
                // field precisely so there is nothing to spoof.
                assert_eq!(src_id, id(0xa1));
                assert_eq!(p, &[7u8; 100]);
            }
            ref other => panic!("expected RecvPacket, got {other:?}"),
        }
    }

    #[test]
    fn an_unrostered_destination_is_not_admitted() {
        let (mut hub, _) = two_clients();
        let roster = TestRoster::new().with(id(0xa1), "t1"); // B absent
        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::NotAdmitted));
        assert!(drain(&mut hub, B).is_empty());
        assert_eq!(
            drain(&mut hub, A),
            vec![Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::NotAdmitted
            }]
        );
    }

    #[test]
    fn a_relay_does_not_forward_between_aquifers() {
        // §5.4. Without this a multi-tenant relay is a general-purpose message
        // bus between any two keys it has ever been told about.
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t2"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t2");

        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::NotAdmitted));
        assert!(drain(&mut hub, B).is_empty());
    }

    #[test]
    fn a_cross_aquifer_destination_is_indistinguishable_from_an_unknown_one() {
        // Both must yield NOT_ADMITTED. Telling them apart would let one
        // tenant probe whether an id exists in another, on a shared relay.
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let payload = [1u8; 10];

        let other_aquifer = TestRoster::new().with(id(0xa1), "t1").with(id(0xff), "t2");
        hub.on_frame(
            A,
            &Frame::SendPacket {
                dst_id: id(0xff),
                payload: &payload,
            },
            &other_aquifer,
            0,
        )
        .expect("legal");
        let cross = drain(&mut hub, A);

        let unknown = TestRoster::new().with(id(0xa1), "t1");
        hub.on_frame(
            A,
            &Frame::SendPacket {
                dst_id: id(0xff),
                payload: &payload,
            },
            &unknown,
            0,
        )
        .expect("legal");
        let absent = drain(&mut hub, A);

        assert_eq!(cross, absent);
    }

    #[test]
    fn an_offline_peer_produces_not_here() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");
        let payload = [1u8; 10];

        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::NotHere));
        assert_eq!(
            drain(&mut hub, A),
            vec![Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::NotHere
            }]
        );
    }

    #[test]
    fn a_node_cannot_relay_to_itself() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xa1),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal frame");
        assert_eq!(dropped, Some(Dropped::SelfAddressed));
        assert!(drain(&mut hub, A).is_empty(), "no echo, no reflection");
    }

    // ── Roles ──────────────────────────────────────────────────────────────

    #[test]
    fn a_mesh_peer_may_not_send_a_packet() {
        // §8: SendPacket on a mesh connection is illegal. This is what the
        // role binding in the handshake (spec §5.5) protects.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        let roster = TestRoster::new();
        let payload = [1u8; 10];
        assert_eq!(
            hub.on_frame(
                M,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload
                },
                &roster,
                0
            ),
            Err(HubError::IllegalForRole)
        );
    }

    #[test]
    fn a_client_may_not_forward() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 10];
        assert_eq!(
            hub.on_frame(
                A,
                &Frame::Forward {
                    src_id: id(0xff),
                    dst_id: id(0xb2),
                    payload: &payload
                },
                &roster,
                0
            ),
            Err(HubError::IllegalForRole)
        );
    }

    #[test]
    fn a_client_may_not_announce_presence() {
        let (mut hub, roster) = two_clients();
        assert_eq!(
            hub.on_frame(A, &Frame::PeerPresent { node_id: id(0xff) }, &roster, 0),
            Err(HubError::IllegalForRole)
        );
    }

    #[test]
    fn a_peer_may_not_send_a_relay_to_peer_frame() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 10];
        for f in [
            Frame::RecvPacket {
                src_id: id(1),
                payload: &payload,
            },
            Frame::RelayHello {
                relay_id: id(1),
                relay_random: id(2),
            },
            Frame::Restarting {
                reconnect_in_ms: 1,
                try_for_ms: 2,
            },
        ] {
            assert_eq!(
                hub.on_frame(A, &f, &roster, 0),
                Err(HubError::IllegalForRole),
                "{f:?} should be illegal from a client"
            );
        }
    }

    #[test]
    fn a_restart_tells_every_client_before_closing_it() {
        let (mut hub, _roster) = two_clients();
        let _ = drain(&mut hub, A);
        let _ = drain(&mut hub, B);
        assert_eq!(hub.begin_restart(1_500, 30_000), 2);
        for conn in [A, B] {
            assert_eq!(
                drain(&mut hub, conn),
                vec![Frame::Restarting {
                    reconnect_in_ms: 1_500,
                    try_for_ms: 30_000,
                }]
            );
            assert!(
                hub.close_reason(conn).is_some(),
                "the connection closes once the notice is written"
            );
        }
    }

    // ── Mesh ───────────────────────────────────────────────────────────────

    #[test]
    fn a_new_client_is_announced_to_the_mesh() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        let _ = drain(&mut hub, M);
        hub.admit(A, client(0xa1, "t1"), 0);
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::PeerPresent { node_id: id(0xa1) }]
        );
    }

    #[test]
    fn a_new_mesh_peer_learns_every_local_client() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        hub.admit(M, mesh(0x0e), 0);
        let got = drain(&mut hub, M);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&Frame::PeerPresent { node_id: id(0xa1) }));
        assert!(got.contains(&Frame::PeerPresent { node_id: id(0xb2) }));
    }

    #[test]
    fn a_packet_for_a_remote_peer_goes_to_the_mesh_peer_holding_it() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(M, mesh(0x0e), 0);
        let _ = drain(&mut hub, M);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        hub.on_frame(M, &Frame::PeerPresent { node_id: id(0xb2) }, &roster, 0)
            .expect("legal");
        assert_eq!(hub.remote_clients(), 1);

        let payload = [3u8; 20];
        let dropped = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(dropped, None);
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::Forward {
                src_id: id(0xa1),
                dst_id: id(0xb2),
                payload: &[3u8; 20]
            }]
        );
    }

    #[test]
    fn a_forward_is_never_forwarded_onward() {
        // §8's one-hop rule, enforced by frame type: a Forward arriving from a
        // mesh peer is delivered locally or dropped. Two meshed relays and a
        // destination neither of them holds must not produce a loop.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(ConnId(4), mesh(0x0f), 0);
        let _ = drain(&mut hub, M);
        let _ = drain(&mut hub, ConnId(4));
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        // The other mesh peer claims the destination.
        hub.on_frame(
            ConnId(4),
            &Frame::PeerPresent { node_id: id(0xb2) },
            &roster,
            0,
        )
        .expect("legal");
        let _ = drain(&mut hub, ConnId(4));

        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                M,
                &Frame::Forward {
                    src_id: id(0xa1),
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");

        assert_eq!(dropped, Some(Dropped::NotHere));
        assert!(
            drain(&mut hub, ConnId(4)).is_empty(),
            "a Forward was relayed onward — mesh loop"
        );
        // And the sender's stale presence entry is corrected.
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::Disconnected
            }]
        );
    }

    #[test]
    fn a_mesh_peer_cannot_inject_cross_aquifer_traffic() {
        // The originating relay checks §5.4, and so do we. A meshed relay is
        // other infrastructure, not an oracle we have to believe.
        let mut hub = Hub::new(Config::default());
        hub.admit(B, client(0xb2, "t1"), 0);
        hub.admit(M, mesh(0x0e), 0);
        let _ = drain(&mut hub, M);
        let roster = TestRoster::new().with(id(0xb2), "t1").with(id(0xc3), "t2");

        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                M,
                &Frame::Forward {
                    src_id: id(0xc3),
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(dropped, Some(Dropped::NotAdmitted));
        assert!(drain(&mut hub, B).is_empty());
    }

    #[test]
    fn a_mesh_delivered_frame_also_spends_the_destination_aquifers_budget() {
        // ADR-0038: routing through a mesh peer must not be a way around this
        // relay's own aquifer-capacity cap.
        let cfg = Config {
            client_budget: Budget::unlimited(),
            aquifer_budget: Some(Budget {
                bytes_per_sec: 1,
                byte_burst: 1,
                frames_per_sec: 1,
                frame_burst: 1,
            }),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(B, client(0xb2, "t1"), 0);
        hub.admit(M, mesh(0x0e), 0);
        let _ = drain(&mut hub, M);
        let roster = TestRoster::new().with(id(0xb2), "t1").with(id(0xc3), "t1");

        let payload = [1u8; 10];
        let dropped = hub
            .on_frame(
                M,
                &Frame::Forward {
                    src_id: id(0xc3),
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(dropped, Some(Dropped::AquiferRateLimited));
        assert!(drain(&mut hub, B).is_empty());
    }

    #[test]
    fn only_the_claiming_relay_may_retract_a_presence_entry() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(ConnId(4), mesh(0x0f), 0);
        let roster = TestRoster::new();

        hub.on_frame(M, &Frame::PeerPresent { node_id: id(0xb2) }, &roster, 0)
            .expect("legal");
        assert_eq!(hub.remote_clients(), 1);

        // The other relay says the node is gone. It never claimed it.
        hub.on_frame(
            ConnId(4),
            &Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::Disconnected,
            },
            &roster,
            0,
        )
        .expect("legal");
        assert_eq!(hub.remote_clients(), 1, "a third party retracted a claim");

        hub.on_frame(
            M,
            &Frame::PeerGone {
                peer_id: id(0xb2),
                reason: Reason::Disconnected,
            },
            &roster,
            0,
        )
        .expect("legal");
        assert_eq!(hub.remote_clients(), 0);
    }

    #[test]
    fn losing_a_mesh_peer_drops_the_presence_it_claimed() {
        // Otherwise Forwards go into a connection that no longer exists, for
        // as long as the process runs.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        let roster = TestRoster::new();
        hub.on_frame(M, &Frame::PeerPresent { node_id: id(0xb2) }, &roster, 0)
            .expect("legal");
        assert_eq!(hub.remote_clients(), 1);

        hub.disconnect(M);
        assert_eq!(hub.remote_clients(), 0);
        assert_eq!(hub.mesh_peers(), 0);
    }

    #[test]
    fn a_departing_client_is_announced_to_the_mesh() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(A, client(0xa1, "t1"), 0);
        let _ = drain(&mut hub, M);

        hub.disconnect(A);
        assert_eq!(
            drain(&mut hub, M),
            vec![Frame::PeerGone {
                peer_id: id(0xa1),
                reason: Reason::Disconnected
            }]
        );
    }

    // ── Replacement — §7.6 ────────────────────────────────────────────────

    #[test]
    fn a_reconnecting_node_replaces_its_old_connection() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let replaced = hub.admit(B, client(0xa1, "t1"), 0);
        assert_eq!(replaced, Some(A));
        assert_eq!(hub.local_clients(), 1);

        // Traffic goes to the new connection.
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xc3), "t1");
        hub.admit(ConnId(9), client(0xc3, "t1"), 0);
        let payload = [1u8; 10];
        hub.on_frame(
            ConnId(9),
            &Frame::SendPacket {
                dst_id: id(0xa1),
                payload: &payload,
            },
            &roster,
            0,
        )
        .expect("legal");
        assert_eq!(hub.pending(B), 1);
        assert_eq!(hub.pending(A), 0);
    }

    #[test]
    fn closing_a_replaced_connection_does_not_evict_its_successor() {
        // The subtle one. The old connection is closed *after* the new one is
        // admitted, and its teardown must not remove the mapping the new one
        // now owns, nor announce a departure that did not happen.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(A, client(0xa1, "t1"), 0);
        let _ = drain(&mut hub, M);
        hub.admit(B, client(0xa1, "t1"), 0);

        hub.disconnect(A);

        assert_eq!(hub.local_clients(), 1, "successor was evicted");
        assert!(
            drain(&mut hub, M).is_empty(),
            "announced a departure that did not happen"
        );
    }

    #[test]
    fn a_replacement_is_not_announced_as_an_arrival() {
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0x0e), 0);
        hub.admit(A, client(0xa1, "t1"), 0);
        let _ = drain(&mut hub, M);

        hub.admit(B, client(0xa1, "t1"), 0);
        assert!(
            drain(&mut hub, M).is_empty(),
            "the node never left, so it never arrived"
        );
    }

    // ── Queueing — §7.3 ───────────────────────────────────────────────────

    #[test]
    fn a_full_queue_drops_the_oldest_and_never_blocks() {
        let cfg = Config {
            queue_depth: 4,
            client_budget: Budget::unlimited(),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        // B never reads. A keeps sending, and must never be told to stop.
        for n in 0u8..10 {
            let payload = [n; 8];
            let dropped = hub
                .on_frame(
                    A,
                    &Frame::SendPacket {
                        dst_id: id(0xb2),
                        payload: &payload,
                    },
                    &roster,
                    0,
                )
                .expect("legal");
            // The sender learns the queue was full, and is not stopped by it.
            assert!(dropped.is_none() || dropped == Some(Dropped::QueueFull));
        }

        assert_eq!(hub.pending(B), 4, "queue exceeded its bound");
        let got = drain(&mut hub, B);
        // Drop-oldest: what survives is the newest four.
        let last: Vec<u8> = got
            .iter()
            .map(|f| match f {
                Frame::RecvPacket { payload, .. } => payload[0],
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(last, vec![6, 7, 8, 9]);

        let stats = hub.stats(B).expect("B exists");
        assert_eq!(stats.dropped_queue, 6);
    }

    #[test]
    fn a_pong_jumps_the_queue() {
        // §7.5: ahead of queued RecvPacket frames. A keepalive stuck behind a
        // backlog is a keepalive that misses its deadline.
        let cfg = Config {
            queue_depth: 8,
            client_budget: Budget::unlimited(),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        for n in 0u8..4 {
            let payload = [n; 8];
            hub.on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        }
        let token = [9u8; 8];
        hub.on_frame(B, &Frame::Ping(&token), &roster, 0)
            .expect("legal");

        let got = drain(&mut hub, B);
        assert_eq!(got.first(), Some(&Frame::Pong(&[9u8; 8])));
        assert_eq!(got.len(), 5);
    }

    // ── §4a's RTT probe (ADR-0045) ──────────────────────────────────────────

    #[test]
    fn a_probed_client_is_pinged_and_a_matching_pong_resolves_it() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1");

        assert!(hub.probe_rtt(A, 1_000));
        let got = drain(&mut hub, A);
        let Some(Frame::Ping(token)) = got.first() else {
            panic!("expected a Ping, got {got:?}");
        };
        let token = **token;

        assert!(
            hub.rtt_histogram() == RttHistogram::default(),
            "no answer yet"
        );
        hub.on_frame(A, &Frame::Pong(&token), &roster, 1_015)
            .expect("legal");
        assert_eq!(
            hub.rtt_histogram(),
            RttHistogram {
                under_20ms: 1,
                ..RttHistogram::default()
            }
        );
    }

    #[test]
    fn a_second_probe_is_refused_while_one_is_outstanding() {
        // Sending a second would leave an answering `Pong` ambiguous about
        // which send it is timing.
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        assert!(hub.probe_rtt(A, 0));
        assert!(!hub.probe_rtt(A, 100));
    }

    #[test]
    fn a_mesh_connection_is_never_probed() {
        // §4a's histogram is about clients, not meshed relays.
        let mut hub = Hub::new(Config::default());
        hub.admit(M, mesh(0xaa), 0);
        assert!(!hub.probe_rtt(M, 0));
    }

    #[test]
    fn a_pong_with_the_wrong_token_does_not_resolve_the_probe() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1");

        assert!(hub.probe_rtt(A, 0));
        drain(&mut hub, A); // the Ping this relay sent, not a reply
        hub.on_frame(A, &Frame::Pong(&[0xffu8; TOKEN_LEN]), &roster, 50)
            .expect("legal");
        assert_eq!(
            hub.rtt_histogram(),
            RttHistogram::default(),
            "a mismatched token must not be mistaken for the answer"
        );
        // The real probe is still outstanding, so a second one is refused.
        assert!(!hub.probe_rtt(A, 50));
    }

    #[test]
    fn rtt_buckets_match_the_adrs_boundaries_exactly() {
        let mut hub = Hub::new(Config::default());
        let roster = TestRoster::new()
            .with(id(0xa1), "t1")
            .with(id(0xa2), "t1")
            .with(id(0xa3), "t1")
            .with(id(0xa4), "t1");
        for (n, rtt) in [(0xa1u8, 19u64), (0xa2, 20), (0xa3, 99), (0xa4, 100)] {
            let conn = ConnId(u64::from(n));
            hub.admit(conn, client(n, "t1"), 0);
            assert!(hub.probe_rtt(conn, 0));
            let got = drain(&mut hub, conn);
            let Some(Frame::Ping(token)) = got.first() else {
                panic!("expected a Ping");
            };
            let token = **token;
            hub.on_frame(conn, &Frame::Pong(&token), &roster, rtt)
                .expect("legal");
        }
        assert_eq!(
            hub.rtt_histogram(),
            RttHistogram {
                under_20ms: 1,
                ms_20_to_50: 1,
                ms_50_to_100: 1,
                over_100ms: 1,
            }
        );
    }

    #[test]
    fn a_client_never_probed_is_in_no_bucket() {
        let mut hub = Hub::new(Config::default());
        hub.admit(A, client(0xa1, "t1"), 0);
        assert_eq!(hub.rtt_histogram(), RttHistogram::default());
    }

    // ── Rate limiting — §7.4 ──────────────────────────────────────────────

    #[test]
    fn an_over_budget_peer_is_dropped_not_disconnected() {
        // §7.4 forbids closing for a burst: a burst is what a relayed
        // handshake looks like.
        let cfg = Config {
            client_budget: Budget {
                bytes_per_sec: 1,
                byte_burst: 1,
                frames_per_sec: 1,
                frame_burst: 1,
            },
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        let payload = [1u8; 100];
        let r = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("a rate-limited frame is still a legal frame");
        assert_eq!(r, Some(Dropped::RateLimited));
        assert!(drain(&mut hub, B).is_empty());
        assert_eq!(hub.stats(A).expect("A").dropped_rate, 1);
        assert!(hub.close_reason(A).is_none(), "closed over a burst");
    }

    // ── Aquifer capacity fairness — ADR-0038 / §13 #9 ──────────────────────

    #[test]
    fn no_aquifer_budget_configured_is_fully_inert() {
        // ADR-0038's default: `Config::default().aquifer_budget` is `None`,
        // and heavy sustained traffic must never surface
        // `Dropped::AquiferRateLimited` when it is.
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 100];
        for _ in 0..1000 {
            let r = hub
                .on_frame(
                    A,
                    &Frame::SendPacket {
                        dst_id: id(0xb2),
                        payload: &payload,
                    },
                    &roster,
                    0,
                )
                .expect("legal");
            assert_ne!(r, Some(Dropped::AquiferRateLimited));
        }
    }

    #[test]
    fn an_aquifer_over_its_aggregate_budget_is_dropped_but_the_connection_stays_open() {
        // A node well within its own per-connection allowance can still be
        // dropped because its aquifer's shared budget is spent — the whole
        // point of the aggregate cap being a second, independent limit.
        let cfg = Config {
            client_budget: Budget::unlimited(),
            aquifer_budget: Some(Budget {
                bytes_per_sec: 1,
                byte_burst: 1,
                frames_per_sec: 1,
                frame_burst: 1,
            }),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        let roster = TestRoster::new().with(id(0xa1), "t1").with(id(0xb2), "t1");

        let payload = [1u8; 100];
        let r = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(r, Some(Dropped::AquiferRateLimited));
        assert!(drain(&mut hub, B).is_empty());
        assert_eq!(hub.stats(A).expect("A").dropped_aquifer_rate, 1);
        assert!(hub.close_reason(A).is_none(), "closed over a burst");
    }

    #[test]
    fn the_aquifer_budget_is_shared_across_its_nodes_not_per_connection() {
        let cfg = Config {
            client_budget: Budget::unlimited(),
            aquifer_budget: Some(Budget {
                bytes_per_sec: 1_000_000,
                byte_burst: 150,
                frames_per_sec: 1_000_000,
                frame_burst: 1_000_000,
            }),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        hub.admit(ConnId(4), client(0xc3, "t1"), 0);
        let roster = TestRoster::new()
            .with(id(0xa1), "t1")
            .with(id(0xb2), "t1")
            .with(id(0xc3), "t1");

        let payload = [1u8; 100];
        // A spends 100 of the aquifer's 150-byte burst.
        let r1 = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(r1, None);

        // A different node in the same aquifer inherits what A already
        // spent: only 50 bytes were left, not another fresh 150.
        let r2 = hub
            .on_frame(
                ConnId(4),
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(r2, Some(Dropped::AquiferRateLimited));
    }

    #[test]
    fn two_aquifers_do_not_share_their_aggregate_budget() {
        let cfg = Config {
            client_budget: Budget::unlimited(),
            aquifer_budget: Some(Budget {
                bytes_per_sec: 1,
                byte_burst: 1,
                frames_per_sec: 1,
                frame_burst: 1,
            }),
            ..Config::default()
        };
        let mut hub = Hub::new(cfg);
        hub.admit(A, client(0xa1, "t1"), 0);
        hub.admit(B, client(0xb2, "t1"), 0);
        hub.admit(ConnId(4), client(0xc3, "t2"), 0);
        hub.admit(ConnId(5), client(0xd4, "t2"), 0);
        let roster = TestRoster::new()
            .with(id(0xa1), "t1")
            .with(id(0xb2), "t1")
            .with(id(0xc3), "t2")
            .with(id(0xd4), "t2");

        let payload = [1u8; 1];
        let r1 = hub
            .on_frame(
                A,
                &Frame::SendPacket {
                    dst_id: id(0xb2),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(r1, None, "t1's budget is fresh");

        let r2 = hub
            .on_frame(
                ConnId(4),
                &Frame::SendPacket {
                    dst_id: id(0xd4),
                    payload: &payload,
                },
                &roster,
                0,
            )
            .expect("legal");
        assert_eq!(r2, None, "t2 has its own budget, unaffected by t1's use");
    }

    #[test]
    fn accounting_survives_a_round_trip() {
        let (mut hub, roster) = two_clients();
        let payload = [1u8; 100];
        hub.on_frame(
            A,
            &Frame::SendPacket {
                dst_id: id(0xb2),
                payload: &payload,
            },
            &roster,
            0,
        )
        .expect("legal");

        let a = hub.stats(A).expect("A");
        let b = hub.stats(B).expect("B");
        assert_eq!(a.frames_in, 1);
        assert_eq!(a.bytes_in, 4 + 32 + 100);
        assert_eq!(a.frames_out, 0);
        assert_eq!(b.frames_out, 1);
        assert_eq!(b.bytes_out, 4 + 32 + 100);
        assert_eq!(b.frames_in, 0);
    }

    #[test]
    fn an_unknown_connection_is_a_caller_bug() {
        let (mut hub, roster) = two_clients();
        let token = [0u8; 8];
        assert_eq!(
            hub.on_frame(ConnId(999), &Frame::Ping(&token), &roster, 0),
            Err(HubError::UnknownConn)
        );
    }

    #[test]
    fn a_close_from_the_peer_ends_the_connection() {
        let (mut hub, roster) = two_clients();
        hub.on_frame(A, &Frame::Close(Reason::ShuttingDown), &roster, 0)
            .expect("legal");
        assert!(hub.close_reason(A).is_some());
        // And nothing is echoed: there is no reason to tell a peer that is
        // leaving why it is leaving.
        assert!(drain(&mut hub, A).is_empty());
    }
}
